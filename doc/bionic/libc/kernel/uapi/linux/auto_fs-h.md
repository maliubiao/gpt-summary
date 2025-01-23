Response:
Let's break down the thought process for answering the user's request about the `auto_fs.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `auto_fs.h` header file within the Android Bionic library. They are specifically interested in:

* **Functionality:** What does this header define?
* **Android Relevance:** How is it used in Android?
* **libc Functions:**  Explanation of any libc functions involved (though this file mainly defines structures and macros, not actual function implementations).
* **Dynamic Linker:** Relevance to the dynamic linker (less direct, but worth considering in the context of system calls).
* **Logic and Examples:**  Illustrative scenarios with inputs and outputs.
* **Usage Errors:** Common mistakes when interacting with this functionality.
* **Android Framework/NDK Integration:**  How does data reach this point?
* **Frida Hooking:**  How can these interactions be observed?

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_LINUX_AUTO_FS_H`:** This is a standard include guard, preventing multiple inclusions.
* **Includes:**  `linux/types.h`, `linux/limits.h`, `sys/ioctl.h`. These point to low-level kernel interfaces and system call definitions.
* **`AUTOFS_PROTO_VERSION`, etc.:**  Version numbers suggest a communication protocol.
* **`autofs_wqt_t`:**  A type definition likely related to wait queues, hinting at synchronization mechanisms.
* **`autofs_packet_hdr`, `autofs_packet_missing`, `autofs_packet_expire`, etc.:** These structures strongly indicate the definition of data packets used for communication. The names suggest different packet types (missing file, expiration).
* **`AUTOFS_IOCTL` and `AUTOFS_IOC_*` definitions:** This is a crucial clue. `ioctl` is a system call for device-specific control operations. The `AUTOFS_IOC_*` constants define specific commands that can be sent via `ioctl`.
* **Enums:** `autofs_notify` and the anonymous enum for `AUTOFS_IOC_*_CMD` provide categorized lists of values.
* **Unions:** `autofs_packet_union` and `autofs_v5_packet_union` suggest different ways to interpret the same memory region based on the packet type.
* **Typedefs:**  Shorthand names for more complex structures.

**3. Identifying Key Concepts:**

Based on the initial analysis, the key concepts are:

* **Autofs:**  The header relates to the automount file system feature in Linux.
* **Kernel-Userspace Communication:** The structures and ioctl commands indicate communication between a userspace process and the kernel module for autofs.
* **Protocol:** Version numbers and packet structures suggest a defined protocol for this communication.
* **`ioctl` System Call:** The primary mechanism for interacting with the autofs kernel module.

**4. Addressing the User's Questions Systematically:**

* **功能 (Functionality):** Describe the purpose of the header file – defining data structures and ioctl commands for the autofs filesystem.
* **与 Android 的关系 (Relevance to Android):**  Autofs is a standard Linux kernel feature, so Android inherits and uses it. Give an example, like mounting on demand.
* **libc 函数的功能 (libc Function Functionality):**  While this header *defines* structures and macros, the *implementation* of `ioctl` resides in the libc. Explain that `ioctl` is a syscall that allows userspace to control device drivers and kernel modules. No direct *implementation* details are in this header.
* **Dynamic Linker:** The dynamic linker is involved in loading the libc itself, which contains the `ioctl` implementation. Illustrate the shared object structure and how linking resolves symbols like `ioctl`.
* **逻辑推理 (Logical Inference):**  Create simple scenarios. For example, a process might send an `AUTOFS_IOC_READY` command to signal its readiness. Show the structure of the `ioctl` call and the data being passed.
* **用户或编程常见的使用错误 (Common Usage Errors):** Focus on incorrect `ioctl` usage: wrong command, incorrect data structure, permission issues.
* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):**  Trace the path from user interaction to the system call. Start with a user action (accessing a directory), mention the VFS layer, and how the kernel then interacts with the autofs module via the defined structures and `ioctl` calls.
* **Frida Hook 示例 (Frida Hook Example):** Provide a concrete example of hooking the `ioctl` system call to observe the commands and data related to autofs.

**5. Structuring the Answer:**

Organize the answer clearly, using headings and bullet points to make it easy to read. Address each of the user's questions explicitly.

**6. Refining and Adding Detail:**

* **Explain `ioctl` parameters:**  Mention the file descriptor, request code, and argument pointer.
* **Expand on the dynamic linker process:** Briefly describe symbol resolution and the role of the GOT and PLT.
* **Provide concrete Frida code:** Show how to filter for autofs-related `ioctl` calls.
* **Use clear and concise language.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the structures themselves.
* **Correction:** Realize the importance of `ioctl` as the *mechanism* and shift focus to how these structures are used within the context of `ioctl` calls.
* **Initial thought:**  Overcomplicate the dynamic linker explanation.
* **Correction:**  Simplify to the core concepts of symbol resolution and shared libraries.
* **Initial thought:**  Provide very generic Frida examples.
* **Correction:**  Make the Frida example specific to the `auto_fs.h` context by filtering for the `AUTOFS_IOCTL` number.

By following this structured thought process, considering the user's specific questions, and iteratively refining the answer, a comprehensive and informative response can be generated.
这个头文件 `bionic/libc/kernel/uapi/linux/auto_fs.h` 定义了 Linux 内核中 `autofs` 文件系统的用户空间 API。`autofs` 是一个自动挂载文件系统的机制，它会在访问挂载点时按需挂载文件系统，并在一段时间不使用后自动卸载。这个头文件在 Android 的 Bionic 库中，意味着 Android 系统也使用了 `autofs` 功能。

**功能列举:**

1. **定义 `autofs` 协议版本:**  定义了 `AUTOFS_PROTO_VERSION`, `AUTOFS_MIN_PROTO_VERSION`, `AUTOFS_MAX_PROTO_VERSION`, `AUTOFS_PROTO_SUBVERSION` 等宏，用于协商内核和用户空间 `autofs` 守护进程之间的通信协议版本。
2. **定义数据包结构:**  定义了用于内核和用户空间 `autofs` 守护进程之间传递消息的结构体，例如 `autofs_packet_hdr` (包头), `autofs_packet_missing` (指示缺少挂载点), `autofs_packet_expire` (指示需要卸载挂载点) 等。这些结构体定义了消息的格式和包含的数据。
3. **定义 `ioctl` 命令:**  定义了用于与 `autofs` 内核模块进行交互的 `ioctl` 命令，例如 `AUTOFS_IOC_READY` (通知内核守护进程已准备好), `AUTOFS_IOC_FAIL` (通知内核挂载失败), `AUTOFS_IOC_EXPIRE` (请求立即卸载挂载点) 等。这些 `ioctl` 命令允许用户空间控制 `autofs` 的行为。
4. **定义 `autofs` 事件类型:**  定义了 `autofs_ptype_missing`, `autofs_ptype_expire` 等常量，用于标识不同的 `autofs` 事件类型。
5. **定义挂载类型:**  定义了 `AUTOFS_TYPE_INDIRECT`, `AUTOFS_TYPE_DIRECT`, `AUTOFS_TYPE_OFFSET` 等常量，用于指定不同类型的自动挂载。
6. **定义卸载选项:**  定义了 `AUTOFS_EXP_NORMAL`, `AUTOFS_EXP_IMMEDIATE`, `AUTOFS_EXP_LEAVES`, `AUTOFS_EXP_FORCED` 等常量，用于控制卸载行为。
7. **定义通知类型:** 定义了 `NFY_NONE`, `NFY_MOUNT`, `NFY_EXPIRE` 等枚举，用于表示不同的通知事件。

**与 Android 功能的关系及举例说明:**

Android 系统利用 `autofs` 来管理某些文件系统的挂载，特别是在需要按需挂载和自动卸载的场景下。

**举例说明:**

* **USB OTG 存储:** 当用户插入 USB OTG 设备时，Android 可以使用 `autofs` 自动挂载 USB 存储。当设备拔出或一段时间不使用后，`autofs` 可以自动卸载该存储，释放资源。
* **SD 卡:** 类似于 USB OTG，Android 可以使用 `autofs` 来管理 SD 卡的挂载和卸载。
* **网络文件系统 (NFS, SMB/CIFS):**  虽然 Android 的支持可能有限，但理论上 `autofs` 可以用于按需挂载网络文件系统。例如，当用户尝试访问一个特定的网络共享目录时，`autofs` 会自动挂载该共享。
* **某些虚拟文件系统:** Android 内部可能使用 `autofs` 来管理某些虚拟文件系统的挂载点。

**libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现代码**。它只是定义了常量、宏和数据结构。真正实现与 `autofs` 交互功能的代码位于 Android 的 `system/core/ MountService` 或相关的守护进程中，这些进程会使用 `ioctl` 系统调用与内核中的 `autofs` 模块进行通信。

`ioctl` 函数是一个通用的设备控制系统调用，其签名如下：

```c
int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  要操作的文件描述符，通常是与 `autofs` 相关的控制文件，例如 `/.automount`。
* `request`:  一个与设备相关的请求代码，对应于头文件中定义的 `AUTOFS_IOC_*` 宏。
* `...`:  可选的参数，其类型和含义取决于 `request`。对于 `autofs` 来说，通常是指向前面定义的数据包结构体的指针。

**`ioctl` 的实现过程 (简述):**

1. 用户空间程序（例如 `MountService`）打开与 `autofs` 相关的设备文件。
2. 用户空间程序调用 `ioctl` 函数，传递文件描述符、`AUTOFS_IOC_*` 命令以及指向数据包结构体的指针。
3. 内核接收到 `ioctl` 调用，根据文件描述符找到对应的设备驱动程序或文件系统模块（这里是 `autofs`）。
4. 内核中的 `autofs` 模块根据 `ioctl` 的命令代码和数据包内容执行相应的操作，例如，接收到 `AUTOFS_IOC_READY` 后，可能会记录该守护进程已准备就绪。收到 `AUTOFS_IOC_EXPIRE` 后，会尝试卸载指定路径的挂载点。
5. `ioctl` 调用返回，用户空间程序根据返回值判断操作是否成功。

**涉及 dynamic linker 的功能 (几乎没有直接关系):**

这个头文件主要定义了内核接口，与 dynamic linker 的直接关系不大。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的主要职责是加载共享库，解析符号，并进行重定位。

虽然 `autofs` 相关的用户空间程序是需要链接到 libc 的，并且会使用 libc 提供的 `ioctl` 函数，但是这个头文件本身的内容并不直接影响 dynamic linker 的行为。

**SO 布局样本和链接的处理过程 (针对 `ioctl`):**

假设有一个名为 `automountd` 的守护进程，它使用了 `ioctl` 与 `autofs` 交互。

**SO 布局样本:**

```
automountd:
  INTERP                 /system/bin/linker64  // 指示使用哪个动态链接器
  LOAD                   0x...
  ...
  DYNAMIC                0x...
    NEEDED               libc.so
    ...
  .plt                   // 程序链接表
    ...
      ioctl@LIBC
    ...
  .got.plt               // 全局偏移量表
    ...
      指向 ioctl 在 libc.so 中的地址（初始可能是一个 resolver 的地址）
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器遇到 `ioctl` 函数调用时，会生成一个对 `ioctl@LIBC` 的引用。
2. **链接时:** 静态链接器会将对 `ioctl` 的引用放到 `.plt` 节中，并在 `.got.plt` 节中分配一个条目。
3. **加载时:**
   * 动态链接器 `linker64` 会加载 `automountd` 和其依赖的共享库 `libc.so`。
   * 动态链接器会处理 `.dynamic` 节中的 `NEEDED` 条目，确保 `libc.so` 被加载。
   * 对于 `.got.plt` 中的 `ioctl` 条目，初始可能指向一个 resolver 函数。
4. **第一次调用 `ioctl` 时 (延迟绑定，如果启用):**
   * 程序跳转到 `.plt` 中 `ioctl` 对应的条目。
   * `.plt` 中的代码会跳转到 `.got.plt` 中 `ioctl` 对应的地址。
   * 如果是第一次调用，`.got.plt` 中是指向 resolver 函数的。
   * resolver 函数会查找 `libc.so` 中 `ioctl` 函数的实际地址。
   * resolver 函数会将 `ioctl` 的实际地址写入 `.got.plt` 中对应的条目。
   * resolver 函数跳转到 `ioctl` 的实际地址。
5. **后续调用 `ioctl` 时:**
   * 程序跳转到 `.plt` 中 `ioctl` 对应的条目。
   * `.plt` 中的代码会直接跳转到 `.got.plt` 中已经存储的 `ioctl` 的实际地址，避免了再次查找。

**假设输入与输出 (针对 `ioctl` 调用):**

**假设输入:**

* 文件描述符 `fd`: 指向 `/.automount` 的文件描述符。
* `request`: `AUTOFS_IOC_READY`
* 参数:  指向包含守护进程信息的结构体的指针（根据实际实现而定，可能没有额外参数）。

**输出:**

* 如果 `ioctl` 调用成功，返回 0。
* 如果失败，返回 -1，并设置 `errno`。

**假设输入:**

* 文件描述符 `fd`: 指向 `/.automount` 的文件描述符。
* `request`: `AUTOFS_IOC_EXPIRE`
* 参数: 指向 `struct autofs_packet_expire` 结构体的指针，其中 `name` 字段包含了要卸载的挂载点路径，例如 "/mnt/usb_drive"。

**输出:**

* 如果卸载成功，返回 0。
* 如果卸载失败（例如，设备正在使用中），返回 -1，并设置 `errno`（例如 `EBUSY`）。

**用户或编程常见的使用错误:**

1. **错误的 `ioctl` 命令:** 使用了内核不支持的 `AUTOFS_IOC_*` 命令。
2. **错误的数据结构:** 传递给 `ioctl` 的数据包结构体的内容格式不正确，例如字段大小、类型不匹配。
3. **权限问题:** 用户空间程序没有足够的权限与 `autofs` 模块进行交互。通常需要 root 权限或特定的 capabilities。
4. **文件描述符无效:** 传递给 `ioctl` 的文件描述符不是与 `autofs` 相关的有效文件描述符。
5. **竞争条件:**  多个进程同时尝试操作同一个 `autofs` 挂载点可能导致错误。
6. **协议版本不匹配:** 用户空间守护进程和内核的 `autofs` 模块使用的协议版本不兼容。

**举例说明:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/auto_fs.h>
#include <errno.h>
#include <string.h>

int main() {
    int fd = open("/.automount", O_RDONLY);
    if (fd == -1) {
        perror("open /.automount failed");
        return 1;
    }

    // 错误的使用：尝试发送一个不存在的 ioctl 命令
    if (ioctl(fd, 0xBADCAFE, NULL) == -1) {
        perror("ioctl failed"); // 可能会输出 "Invalid argument" 或其他错误
    }

    struct autofs_packet_expire expire_packet;
    memset(&expire_packet, 0, sizeof(expire_packet));
    expire_packet.hdr.proto_version = AUTOFS_PROTO_VERSION;
    expire_packet.hdr.type = autofs_ptype_expire;
    strncpy(expire_packet.name, "/mnt/usb_drive", NAME_MAX);
    expire_packet.len = strlen(expire_packet.name);

    // 正确的使用，但可能因为权限问题失败
    if (ioctl(fd, AUTOFS_IOC_EXPIRE, &expire_packet) == -1) {
        perror("ioctl AUTOFS_IOC_EXPIRE failed"); // 如果不是 root 权限，可能输出 "Operation not permitted"
    }

    close(fd);
    return 0;
}
```

**Android Framework 或 NDK 如何一步步到达这里:**

1. **用户操作:** 用户插入 USB 设备，或者访问一个尚未挂载的网络共享目录。
2. **Vold (Volume Daemon):** Android 的 `vold` 守护进程负责管理存储设备的挂载和卸载。它会监听内核事件（例如设备插入）或来自 framework 的请求。
3. **MountService (Java Framework):**  Framework 中的 `MountService` 通过 Binder IPC 与 `vold` 进行通信，请求挂载或卸载操作。
4. **`vold` 操作:** `vold` 接收到请求后，可能会调用 `mount` 或 `umount` 系统调用，或者与 `autofs` 守护进程进行交互。
5. **`autofs` 守护进程 (可选):**  Android 系统中可能存在一个专门的 `autofs` 守护进程（具体实现可能因 Android 版本而异）。`vold` 可以通过 UNIX domain socket 或其他机制与 `autofs` 守护进程通信。
6. **`ioctl` 调用:** `autofs` 守护进程（或者 `vold` 本身）会打开 `/.automount` 文件，并使用 `ioctl` 系统调用，传递相应的 `AUTOFS_IOC_*` 命令和数据包，与内核中的 `autofs` 模块进行通信。
7. **内核 `autofs` 模块:** 内核接收到 `ioctl` 调用，执行相应的挂载或卸载操作。

**NDK 访问 (较少见):**

通常情况下，开发者不会直接使用 NDK 来调用 `autofs` 相关的 `ioctl`。Android Framework 已经提供了管理存储设备的 API。但是，如果开发者需要实现一些非常底层的存储管理功能，他们可以使用 NDK 调用 libc 的 `open` 和 `ioctl` 函数，并包含 `<linux/auto_fs.h>` 头文件。这需要非常谨慎，并且可能需要系统权限。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida Hook `ioctl` 系统调用，并过滤与 `autofs` 相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

session = frida.attach("com.android.systemui") # 或者你想要监控的进程，例如 "vold"

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function(args) {
    var fd = args[0].toInt32();
    var request = args[1].toInt32();

    // 检查是否是与 autofs 相关的 ioctl 命令 (0x93 << 8)
    if ((request >> 8) === 0x93) {
      var requestName = "";
      switch (request) {
        case 0x9360: requestName = "AUTOFS_IOC_READY"; break;
        case 0x9361: requestName = "AUTOFS_IOC_FAIL"; break;
        case 0x9362: requestName = "AUTOFS_IOC_CATATONIC"; break;
        case 0x9363: requestName = "AUTOFS_IOC_PROTOVER"; break;
        case 0x9364: requestName = "AUTOFS_IOC_SETTIMEOUT"; break;
        case 0x9365: requestName = "AUTOFS_IOC_EXPIRE"; break;
        case 0x9366: requestName = "AUTOFS_IOC_EXPIRE_MULTI"; break;
        case 0x9367: requestName = "AUTOFS_IOC_PROTOSUBVER"; break;
        case 0x9370: requestName = "AUTOFS_IOC_ASKUMOUNT"; break;
        default: requestName = "UNKNOWN_AUTOFS_IOC_" + request.toString(16);
      }
      console.log("[IOCTL] fd: " + fd + ", request: " + request.toString(16) + " (" + requestName + ")");

      // 你可以进一步解析 arg[2] 的数据，如果需要的话
      // 例如，对于 AUTOFS_IOC_EXPIRE，可以读取 struct autofs_packet_expire
      if (request === 0x9365) {
        var expireDataPtr = args[2];
        if (expireDataPtr) {
          try {
            var len = expireDataPtr.add(4).readInt(); // 读取 len 字段的偏移量
            var namePtr = expireDataPtr.add(8);      // 读取 name 字段的偏移量
            var name = namePtr.readUtf8String(len);
            console.log("  -> Expire Name: " + name);
          } catch (e) {
            console.log("  -> Error reading expire data: " + e);
          }
        }
      }
    }
  }
});
""")
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_autofs.py`。
2. 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
3. 运行 `python frida_autofs.py`。
4. 在 Android 设备上执行触发 `autofs` 操作的动作，例如插入 USB 设备或访问某个自动挂载点。
5. Frida 会打印出 `ioctl` 系统调用的相关信息，包括文件描述符、请求代码和可能的数据。

这个 Frida 脚本会 hook `ioctl` 系统调用，并过滤出与 `autofs` 相关的命令。对于 `AUTOFS_IOC_EXPIRE` 命令，它会尝试读取并打印出要卸载的挂载点名称。你可以根据需要扩展脚本来解析其他 `ioctl` 命令的数据。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/auto_fs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_AUTO_FS_H
#define _UAPI_LINUX_AUTO_FS_H
#include <linux/types.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#define AUTOFS_PROTO_VERSION 5
#define AUTOFS_MIN_PROTO_VERSION 3
#define AUTOFS_MAX_PROTO_VERSION 5
#define AUTOFS_PROTO_SUBVERSION 6
#if defined(__ia64__) || defined(__alpha__)
typedef unsigned long autofs_wqt_t;
#else
typedef unsigned int autofs_wqt_t;
#endif
#define autofs_ptype_missing 0
#define autofs_ptype_expire 1
struct autofs_packet_hdr {
  int proto_version;
  int type;
};
struct autofs_packet_missing {
  struct autofs_packet_hdr hdr;
  autofs_wqt_t wait_queue_token;
  int len;
  char name[NAME_MAX + 1];
};
struct autofs_packet_expire {
  struct autofs_packet_hdr hdr;
  int len;
  char name[NAME_MAX + 1];
};
#define AUTOFS_IOCTL 0x93
enum {
  AUTOFS_IOC_READY_CMD = 0x60,
  AUTOFS_IOC_FAIL_CMD,
  AUTOFS_IOC_CATATONIC_CMD,
  AUTOFS_IOC_PROTOVER_CMD,
  AUTOFS_IOC_SETTIMEOUT_CMD,
  AUTOFS_IOC_EXPIRE_CMD,
};
#define AUTOFS_IOC_READY _IO(AUTOFS_IOCTL, AUTOFS_IOC_READY_CMD)
#define AUTOFS_IOC_FAIL _IO(AUTOFS_IOCTL, AUTOFS_IOC_FAIL_CMD)
#define AUTOFS_IOC_CATATONIC _IO(AUTOFS_IOCTL, AUTOFS_IOC_CATATONIC_CMD)
#define AUTOFS_IOC_PROTOVER _IOR(AUTOFS_IOCTL, AUTOFS_IOC_PROTOVER_CMD, int)
#define AUTOFS_IOC_SETTIMEOUT32 _IOWR(AUTOFS_IOCTL, AUTOFS_IOC_SETTIMEOUT_CMD, compat_ulong_t)
#define AUTOFS_IOC_SETTIMEOUT _IOWR(AUTOFS_IOCTL, AUTOFS_IOC_SETTIMEOUT_CMD, unsigned long)
#define AUTOFS_IOC_EXPIRE _IOR(AUTOFS_IOCTL, AUTOFS_IOC_EXPIRE_CMD, struct autofs_packet_expire)
#define AUTOFS_EXP_NORMAL 0x00
#define AUTOFS_EXP_IMMEDIATE 0x01
#define AUTOFS_EXP_LEAVES 0x02
#define AUTOFS_EXP_FORCED 0x04
#define AUTOFS_TYPE_ANY 0U
#define AUTOFS_TYPE_INDIRECT 1U
#define AUTOFS_TYPE_DIRECT 2U
#define AUTOFS_TYPE_OFFSET 4U
enum autofs_notify {
  NFY_NONE,
  NFY_MOUNT,
  NFY_EXPIRE
};
#define autofs_ptype_expire_multi 2
#define autofs_ptype_missing_indirect 3
#define autofs_ptype_expire_indirect 4
#define autofs_ptype_missing_direct 5
#define autofs_ptype_expire_direct 6
struct autofs_packet_expire_multi {
  struct autofs_packet_hdr hdr;
  autofs_wqt_t wait_queue_token;
  int len;
  char name[NAME_MAX + 1];
};
union autofs_packet_union {
  struct autofs_packet_hdr hdr;
  struct autofs_packet_missing missing;
  struct autofs_packet_expire expire;
  struct autofs_packet_expire_multi expire_multi;
};
struct autofs_v5_packet {
  struct autofs_packet_hdr hdr;
  autofs_wqt_t wait_queue_token;
  __u32 dev;
  __u64 ino;
  __u32 uid;
  __u32 gid;
  __u32 pid;
  __u32 tgid;
  __u32 len;
  char name[NAME_MAX + 1];
};
typedef struct autofs_v5_packet autofs_packet_missing_indirect_t;
typedef struct autofs_v5_packet autofs_packet_expire_indirect_t;
typedef struct autofs_v5_packet autofs_packet_missing_direct_t;
typedef struct autofs_v5_packet autofs_packet_expire_direct_t;
union autofs_v5_packet_union {
  struct autofs_packet_hdr hdr;
  struct autofs_v5_packet v5_packet;
  autofs_packet_missing_indirect_t missing_indirect;
  autofs_packet_expire_indirect_t expire_indirect;
  autofs_packet_missing_direct_t missing_direct;
  autofs_packet_expire_direct_t expire_direct;
};
enum {
  AUTOFS_IOC_EXPIRE_MULTI_CMD = 0x66,
  AUTOFS_IOC_PROTOSUBVER_CMD,
  AUTOFS_IOC_ASKUMOUNT_CMD = 0x70,
};
#define AUTOFS_IOC_EXPIRE_MULTI _IOW(AUTOFS_IOCTL, AUTOFS_IOC_EXPIRE_MULTI_CMD, int)
#define AUTOFS_IOC_PROTOSUBVER _IOR(AUTOFS_IOCTL, AUTOFS_IOC_PROTOSUBVER_CMD, int)
#define AUTOFS_IOC_ASKUMOUNT _IOR(AUTOFS_IOCTL, AUTOFS_IOC_ASKUMOUNT_CMD, int)
#endif
```