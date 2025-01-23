Response:
Let's break down the thought process for answering the user's request about the `if_tun.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `if_tun.h`, its relationship to Android, the implementation details of related libc functions, dynamic linker aspects, common errors, and how it's used within the Android framework/NDK, including a Frida hook example. This is a multi-faceted request requiring knowledge of kernel interfaces, Android architecture, C library interaction, and debugging techniques.

**2. Initial Analysis of the Header File:**

The first step is to read and understand the content of `if_tun.h`. Key observations:

* **Auto-generated:** This suggests it's a kernel header file mirrored in the user space for system calls. Changes shouldn't be made directly.
* **`#include`s:** It includes `linux/types.h`, `linux/if_ether.h`, and `linux/filter.h`. These point to network-related structures and definitions.
* **`#define`s:**  The majority of the file consists of `#define` macros. These fall into several categories:
    * **Constants:** `TUN_READQ_SIZE`, `IFF_TUN`, `IFF_TAP`, etc. These define fixed values.
    * **Bitmasks:** `TUN_TYPE_MASK`, `IFF_NO_CARRIER`, etc. Used for setting and checking flags.
    * **IO Control Codes:** `TUNSETNOCSUM`, `TUNSETDEBUG`, etc. These are crucial for interacting with the TUN/TAP driver via `ioctl`. They follow the `_IO`, `_IOW`, `_IOR` convention.
    * **Structures:** `tun_pi`, `tun_filter`. These define the data formats used in `ioctl` calls.
* **No actual function implementations:** This is a header file, so it only contains declarations and definitions, not executable code.

**3. Connecting to the Concepts:**

Based on the header file's content, I started connecting the dots to relevant concepts:

* **TUN/TAP:** The names `TUN_TUN_DEV` and `TUN_TAP_DEV` immediately indicate that this header is related to the TUN/TAP virtual network interface driver in Linux.
* **Virtual Networks:** TUN/TAP allows user-space programs to send and receive network packets as if they were real network interfaces. This is used in VPNs, network simulators, and other networking applications.
* **`ioctl`:** The presence of numerous `_IO`, `_IOW`, and `_IOR` macros strongly suggests the use of the `ioctl` system call to configure and control the TUN/TAP interface.
* **Kernel-User Space Interaction:** The header file bridges the gap between the kernel (which implements the TUN/TAP driver) and user-space applications.

**4. Addressing Specific Parts of the Request:**

Now, I systematically addressed each point in the user's request:

* **功能 (Functionality):** I summarized the purpose of the header file and the underlying TUN/TAP driver. Key functionalities are creating virtual network interfaces, sending/receiving raw packets, and configuration.
* **与 Android 的关系 (Relationship with Android):** I highlighted that Android, being based on Linux, inherits the TUN/TAP functionality. I provided concrete examples like VPN apps, tethering, and virtualization.
* **libc 函数 (libc Functions):**  This was tricky because the header file *doesn't define libc functions*. The connection is that user-space programs (including those in Android's Bionic) use *libc functions* (like `open`, `close`, `ioctl`, `read`, `write`) to interact with the TUN/TAP device file. I explained the role of these libc functions in this context. I emphasized that `ioctl` is the primary function used with the defined macros.
* **dynamic linker:**  The header file itself has *no direct involvement* with the dynamic linker. However, applications using TUN/TAP would be linked against libc and potentially other libraries. I provided a basic SO layout example and explained the dynamic linking process in a general sense, as it relates to *any* shared library usage, rather than something specific to `if_tun.h`.
* **逻辑推理 (Logical Deduction):**  I provided examples of how the `ioctl` calls would be used with specific commands and data structures. I demonstrated setting the interface type and flags.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** I listed common mistakes, such as incorrect `ioctl` usage, permission issues, and buffer management problems.
* **Android framework or ndk 如何到达这里 (How Android Framework/NDK Reaches Here):**  I described the typical path:
    * An app or service initiates a network operation requiring a virtual interface.
    * This involves system calls, often through the NDK or higher-level Android APIs.
    * The system calls eventually interact with the kernel's TUN/TAP driver.
    * The header file's constants and structures are used in these interactions.
* **Frida hook 示例 (Frida Hook Example):** I provided a basic Frida script to hook the `ioctl` call and inspect the arguments when interacting with a TUN/TAP device. This demonstrates how to observe the usage of the constants defined in the header file.

**5. Refinement and Language:**

Throughout the process, I paid attention to using clear and concise Chinese, explaining technical terms, and organizing the information logically using headings and bullet points. I aimed to provide a comprehensive yet understandable answer to the user's detailed request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the *header file itself* as having functionality. **Correction:** Shift focus to the *underlying TUN/TAP driver* and how the header file provides the necessary definitions for interacting with it.
* **Misinterpreting "libc 函数的功能是如何实现的":**  Initially, I might have tried to explain the *internal implementation* of `open`, `ioctl`, etc. **Correction:** Realize the user likely meant how these functions are *used in the context of TUN/TAP* and focus on the interaction with the driver.
* **Overcomplicating the dynamic linker section:**  Avoid going too deep into the intricacies of the dynamic linker. **Correction:** Keep the explanation general and relevant to how any shared library is loaded, as `if_tun.h` itself doesn't directly involve linking. Focus on the standard library usage.

By following this structured thought process, breaking down the request, connecting concepts, and addressing each point methodically, I could generate a comprehensive and accurate answer.
这是一个关于Linux TUN/TAP 驱动程序用户空间接口的头文件，定义了用于配置和控制 TUN/TAP 虚拟网络接口的常量、宏和数据结构。由于它位于 `bionic/libc/kernel/uapi/linux` 目录下，说明它是 Linux 内核头文件的用户空间拷贝，供 Android 的 Bionic C 库使用。

**功能列举:**

这个头文件定义了以下功能相关的常量和宏：

1. **定义 TUN/TAP 设备类型:**
   - `TUN_TUN_DEV IFF_TUN`: 定义了 TUN 设备的类型标志。
   - `TUN_TAP_DEV IFF_TAP`: 定义了 TAP 设备的类型标志。

2. **定义 ioctl 命令:**  这些宏定义了用于配置和控制 TUN/TAP 设备的 `ioctl` 系统调用命令。例如：
   - `TUNSETNOCSUM`: 设置是否校验校验和。
   - `TUNSETDEBUG`: 设置调试模式。
   - `TUNSETIFF`: 设置接口类型和标志。
   - `TUNSETPERSIST`: 设置设备持久化。
   - `TUNSETOWNER`: 设置设备所有者。
   - `TUNSETLINK`: 设置底层链路类型。
   - `TUNSETGROUP`: 设置设备所属组。
   - `TUNGETFEATURES`: 获取设备特性。
   - `TUNSETOFFLOAD`: 设置硬件卸载功能。
   - `TUNSETTXFILTER`, `TUNGETFILTER`, `TUNATTACHFILTER`, `TUNDETACHFILTER`:  用于设置和管理数据包过滤器。
   - `TUNGETVNETHDRSZ`, `TUNSETVNETHDRSZ`, `TUNSETVNETLE`, `TUNGETVNETLE`, `TUNSETVNETBE`, `TUNGETVNETBE`: 用于控制虚拟网络报头的大小和字节序。
   - `TUNSETQUEUE`, `TUNSETIFINDEX`: 用于设置队列和接口索引。
   - `TUNSETSTEERINGEBPF`, `TUNSETFILTEREBPF`: 用于设置 eBPF 过滤器。
   - `TUNSETCARRIER`: 设置载波状态。
   - `TUNGETDEVNETNS`: 获取设备所在的网络命名空间。

3. **定义接口标志 (Interface Flags):**  以 `IFF_` 开头的宏定义了各种接口标志，用于 `TUNSETIFF` 命令：
   - `IFF_TUN`:  指定创建 TUN 设备（网络层）。
   - `IFF_TAP`:  指定创建 TAP 设备（数据链路层）。
   - `IFF_NAPI`, `IFF_NAPI_FRAGS`:  与 NAPI (New API) 相关。
   - `IFF_NO_CARRIER`:  表示无载波。
   - `IFF_NO_PI`:  表示不包含额外的协议信息头。
   - `IFF_ONE_QUEUE`, `IFF_MULTI_QUEUE`, `IFF_ATTACH_QUEUE`, `IFF_DETACH_QUEUE`:  与多队列功能相关。
   - `IFF_PERSIST`:  表示设备持久化。
   - `IFF_NOFILTER`:  禁用过滤器。
   - `IFF_VNET_HDR`:  使用虚拟网络报头。
   - `IFF_TUN_EXCL`:  独占模式。

4. **定义 TUN 特性标志:** 以 `TUN_F_` 开头的宏定义了 TUN 设备的特性标志，用于 `TUNSETOFFLOAD` 命令：
   - `TUN_F_CSUM`:  校验和卸载。
   - `TUN_F_TSO4`, `TUN_F_TSO6`, `TUN_F_TSO_ECN`:  TCP 分段卸载 (TSO) 相关。
   - `TUN_F_UFO`:  UDP Fragmentation Offload。
   - `TUN_F_USO4`, `TUN_F_USO6`:  UDP Segmentation Offload。

5. **定义数据结构:**
   - `struct tun_pi`:  定义了当 `IFF_NO_PI` 未设置时，数据包前缀的信息，包含标志和协议类型。
   - `struct tun_filter`: 定义了用于设置 MAC 地址过滤器的结构。

**与 Android 功能的关系及举例:**

TUN/TAP 设备在 Android 中被广泛用于以下功能：

1. **VPN (Virtual Private Network) 应用:** VPN 应用通常会创建一个 TUN 设备。所有通过 VPN 连接的网络流量都会被路由到这个虚拟接口。VPN 应用可以在用户空间读取和写入这个接口，从而实现加密、解密和路由功能。
   - **例子:** 当你在 Android 手机上启动一个 VPN 应用时，该应用会在后台创建一个 TUN 设备，例如 `tun0`。你的所有网络请求，例如访问网页，都会先发送到这个 `tun0` 接口。VPN 应用会截获这些数据包，进行加密，然后通过实际的网络接口发送出去。接收到的加密数据包也会通过 `tun0` 接口注入到操作系统的网络栈中。

2. **热点 (Tethering):**  Android 的热点功能可以使用 TUN/TAP 设备来转发手机的网络连接给连接的设备。
   - **例子:** 当你开启手机热点时，系统可能会创建一个 TAP 设备。连接到你热点的设备发送的数据包会通过这个 TAP 设备到达你的手机，然后你的手机会负责将这些数据包转发到互联网。

3. **虚拟化和容器化:**  在 Android 上运行虚拟机或容器时，可以使用 TUN/TAP 设备来为虚拟机或容器提供网络连接。
   - **例子:**  类似于在桌面 Linux 环境中使用 QEMU 或 Docker，Android 上的虚拟化方案也可能利用 TUN/TAP 设备来实现虚拟机或容器的网络隔离和连接。

4. **网络调试和分析工具:**  开发者可以使用 TUN/TAP 设备来创建自定义的网络环境，用于测试和分析网络协议。

**libc 函数的功能实现:**

这个头文件本身不包含任何 libc 函数的实现。它只是定义了与 TUN/TAP 设备交互时需要使用的常量和数据结构。用户空间的应用程序需要使用标准的 libc 函数，例如：

1. **`open()`:** 用于打开 `/dev/net/tun` 设备文件。这是一个字符设备，用于创建和管理 TUN/TAP 接口。
   - **实现:** `open()` 系统调用会传递到内核，内核会查找对应的设备驱动程序（这里是 `tun.ko` 模块）。驱动程序的 `open` 方法会被调用，负责分配必要的内核资源并返回一个文件描述符。

2. **`close()`:** 用于关闭与 TUN/TAP 设备关联的文件描述符，释放内核资源。
   - **实现:** `close()` 系统调用也会传递到内核，内核根据文件描述符找到对应的驱动程序，并调用其 `release` 或 `close` 方法来清理资源。

3. **`ioctl()`:**  这是与 TUN/TAP 设备交互的核心函数。应用程序使用 `ioctl()` 系统调用，并传入上面头文件中定义的 `TUNSETIFF`、`TUNSETNOCSUM` 等命令码以及相应的参数，来配置 TUN/TAP 接口。
   - **实现:** `ioctl()` 系统调用会传递到内核，内核根据文件描述符找到 TUN/TAP 驱动程序，并调用其 `ioctl` 方法。驱动程序的 `ioctl` 方法会根据传入的命令码执行相应的操作，例如创建接口、设置标志等。例如，当调用 `ioctl(fd, TUNSETIFF, &ifr)` 时，内核中的 TUN/TAP 驱动程序会根据 `ifr` 结构体中的信息创建一个新的 TUN 或 TAP 接口。

4. **`read()` 和 `write()`:**  一旦 TUN/TAP 接口被创建并配置，应用程序就可以使用 `read()` 从该接口读取接收到的网络数据包，并使用 `write()` 向该接口写入要发送的网络数据包。
   - **实现:** 当调用 `read()` 时，如果 TUN/TAP 接口有数据包到达，内核会将数据包拷贝到用户空间的缓冲区。当调用 `write()` 时，内核会接收用户空间写入的数据包，并将其注入到网络协议栈中，就像是从一个真实的物理网卡接收到的一样。

**dynamic linker 的功能 (无直接关联):**

这个头文件 `if_tun.h` 本身与 dynamic linker 没有直接的功能关联。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库 (`.so` 文件) 并解析符号引用。

然而，使用 TUN/TAP 接口的应用程序会链接到 C 库 (`libc.so`)，并可能链接到其他共享库。

**so 布局样本:**

一个使用 TUN/TAP 的 Android 应用的 SO 布局可能如下所示：

```
/system/bin/app_process64  # zygote 进程孵化出的应用进程
 |
 |-- /apex/com.android.runtime/lib64/bionic/linker64  # dynamic linker
 |
 |-- /system/lib64/libc.so  # Android 的 C 库，包含 open, close, ioctl, read, write 等函数
 |
 |-- /system/lib64/libutils.so  # 可能使用的其他 Android 系统库
 |
 |-- /data/app/com.example.myapp/lib/arm64/libnative.so # 你的应用的原生库 (如果使用了 NDK)
```

**链接的处理过程:**

1. 当应用程序启动时，操作系统会加载应用程序的可执行文件。
2. Dynamic linker (`linker64`) 会被启动。
3. Dynamic linker 解析应用程序的依赖关系，找到需要加载的共享库，例如 `libc.so`。
4. Dynamic linker 将这些共享库加载到进程的内存空间。
5. Dynamic linker 解析应用程序和加载的共享库中的符号引用，并进行符号重定位，将函数调用指向正确的内存地址。
6. 应用程序就可以调用 `libc.so` 中的 `open()`, `ioctl()` 等函数来与 TUN/TAP 设备进行交互。

**逻辑推理 (假设输入与输出):**

假设一个程序想要创建一个 TUN 设备，并设置其 IP 地址。

**假设输入:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

int main() {
    int fd;
    struct ifreq ifr;

    // 打开 TUN 设备文件
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open /dev/net/tun");
        exit(1);
    }

    // 设置接口名称和类型 (TUN)
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "mytun", IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // 创建 TUN 设备，不包含额外的协议信息头

    // 调用 ioctl 创建 TUN 设备
    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    printf("TUN device %s created with file descriptor %d\n", ifr.ifr_name, fd);

    // ... 后续可以使用 read/write 在该接口上收发数据包 ...

    close(fd);
    return 0;
}
```

**假设输出:**

```
TUN device mytun created with file descriptor 3
```

**解释:**

程序首先打开 `/dev/net/tun`。然后，填充 `ifreq` 结构体，指定接口名称为 "mytun"，类型为 TUN (`IFF_TUN`) 且不包含额外的协议信息头 (`IFF_NO_PI`)。调用 `ioctl` 函数，使用 `TUNSETIFF` 命令和 `ifreq` 结构体作为参数。内核的 TUN/TAP 驱动程序会根据这些信息创建一个名为 "mytun" 的 TUN 虚拟网络接口，并将其与文件描述符 `fd` 关联起来。

**用户或编程常见的使用错误:**

1. **忘记打开 `/dev/net/tun`:**  在使用 `ioctl` 配置 TUN/TAP 设备之前，必须先打开 `/dev/net/tun` 设备文件。
2. **权限问题:**  打开 `/dev/net/tun` 通常需要 root 权限或相应的 capabilities。普通用户可能无法创建 TUN/TAP 设备。
3. **`ioctl` 命令错误:** 使用了错误的 `ioctl` 命令码，或者传递了错误的参数结构体。例如，将 TAP 设备的标志传递给 TUN 设备。
4. **接口名称冲突:**  尝试创建的 TUN/TAP 接口名称已经存在。
5. **忘记设置必要的标志:** 例如，没有设置 `IFF_NO_PI`，导致读取到的数据包包含额外的协议信息头，应用程序需要正确处理。
6. **缓冲区大小不足:** 在 `read()` 操作中，提供的缓冲区大小不足以容纳接收到的数据包。
7. **资源泄漏:**  忘记 `close()` 打开的文件描述符。
8. **不正确的网络配置:**  创建 TUN/TAP 设备后，还需要使用 `ip` 命令或相关工具配置其 IP 地址、路由等信息，否则无法正常工作。

**Android framework or ndk 如何一步步的到达这里:**

1. **Android 应用或服务发起网络操作:**  例如，一个 VPN 应用想要建立 VPN 连接。
2. **调用 Android Framework API:**  VPN 应用会调用 Android Framework 提供的 VPN 相关 API，例如 `VpnService`。
3. **Framework 层调用 Native 代码:**  `VpnService` 的实现会调用底层的 Native 代码（通常使用 C++）。
4. **Native 代码使用 NDK API:**  Native 代码可能会使用 NDK 提供的网络相关的 API，或者直接使用 POSIX 标准的 socket 或网络接口 API。
5. **调用 `open()` 打开 `/dev/net/tun`:**  Native 代码最终会调用 `open("/dev/net/tun", O_RDWR)` 来获取 TUN 设备的文件描述符。
6. **调用 `ioctl()` 配置 TUN 设备:**  使用 `ioctl()` 系统调用和 `if_tun.h` 中定义的宏来配置 TUN 设备，例如设置接口名称、类型、持久化等。
7. **使用 `read()` 和 `write()` 收发数据包:**  Native 代码通过 `read()` 和 `write()` 函数与 TUN 设备进行数据包的收发。
8. **数据包的路由和处理:**  操作系统内核会将发送到 TUN 设备的数据包路由到实际的网络接口，接收到的数据包也会通过 TUN 设备传递给应用程序。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `open` 和 `ioctl` 系统调用来观察应用程序如何与 TUN/TAP 设备进行交互。

```javascript
// Hook open 系统调用
Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function(args) {
    const pathname = Memory.readUtf8String(args[0]);
    if (pathname.includes("/dev/net/tun")) {
      console.log("[open] Opening TUN device:", pathname);
    }
  },
  onLeave: function(retval) {
    if (retval.toInt32() > 0 && this.context) {
      const fd = retval.toInt32();
      console.log("[open] TUN device opened with fd:", fd);
    }
  }
});

// Hook ioctl 系统调用
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function(args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    // 判断是否是与 TUN/TAP 相关的 ioctl 命令
    if (request >= 0x400054c8 && request <= 0xc00454df) { // 'T' 的 ASCII 码是 0x54
      console.log("[ioctl] fd:", fd, "request:", request.toString(16));

      if (request === 0x400454ca) { // TUNSETIFF
        const ifrPtr = args[2];
        const ifrName = Memory.readCString(ifrPtr);
        const ifrFlags = Memory.readU16(ifrPtr.add(16)); // ifr_flags 偏移量

        console.log("[ioctl]   TUNSETIFF - ifr_name:", ifrName, "ifr_flags:", ifrFlags.toString(16));
      }
      // 可以根据其他的 ioctl 命令码解析相应的参数
    }
  }
});
```

**解释 Frida 脚本:**

1. **Hook `open`:**  监听 `open` 系统调用，当打开的文件路径包含 `/dev/net/tun` 时，打印日志，显示正在打开 TUN 设备。
2. **Hook `ioctl`:** 监听 `ioctl` 系统调用。通过检查 `request` 参数的值范围，可以大致判断是否是与 TUN/TAP 设备相关的 `ioctl` 命令（`_IO`, `_IOR`, `_IOW`, `_IOWR` 宏的特点）。
3. **解析 `TUNSETIFF` 参数:**  如果 `ioctl` 的 `request` 是 `TUNSETIFF` (0x400454ca)，则读取 `ifreq` 结构体中的接口名称 (`ifr_name`) 和标志 (`ifr_flags`) 并打印出来。你需要根据不同的 `ioctl` 命令码和参数结构体来解析其他参数。

通过运行这个 Frida 脚本，你可以观察到 Android 应用程序在创建和配置 TUN/TAP 设备时调用的系统调用及其参数，从而理解 `if_tun.h` 中定义的常量和宏是如何被使用的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/if_tun.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__IF_TUN_H
#define _UAPI__IF_TUN_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#define TUN_READQ_SIZE 500
#define TUN_TUN_DEV IFF_TUN
#define TUN_TAP_DEV IFF_TAP
#define TUN_TYPE_MASK 0x000f
#define TUNSETNOCSUM _IOW('T', 200, int)
#define TUNSETDEBUG _IOW('T', 201, int)
#define TUNSETIFF _IOW('T', 202, int)
#define TUNSETPERSIST _IOW('T', 203, int)
#define TUNSETOWNER _IOW('T', 204, int)
#define TUNSETLINK _IOW('T', 205, int)
#define TUNSETGROUP _IOW('T', 206, int)
#define TUNGETFEATURES _IOR('T', 207, unsigned int)
#define TUNSETOFFLOAD _IOW('T', 208, unsigned int)
#define TUNSETTXFILTER _IOW('T', 209, unsigned int)
#define TUNGETIFF _IOR('T', 210, unsigned int)
#define TUNGETSNDBUF _IOR('T', 211, int)
#define TUNSETSNDBUF _IOW('T', 212, int)
#define TUNATTACHFILTER _IOW('T', 213, struct sock_fprog)
#define TUNDETACHFILTER _IOW('T', 214, struct sock_fprog)
#define TUNGETVNETHDRSZ _IOR('T', 215, int)
#define TUNSETVNETHDRSZ _IOW('T', 216, int)
#define TUNSETQUEUE _IOW('T', 217, int)
#define TUNSETIFINDEX _IOW('T', 218, unsigned int)
#define TUNGETFILTER _IOR('T', 219, struct sock_fprog)
#define TUNSETVNETLE _IOW('T', 220, int)
#define TUNGETVNETLE _IOR('T', 221, int)
#define TUNSETVNETBE _IOW('T', 222, int)
#define TUNGETVNETBE _IOR('T', 223, int)
#define TUNSETSTEERINGEBPF _IOR('T', 224, int)
#define TUNSETFILTEREBPF _IOR('T', 225, int)
#define TUNSETCARRIER _IOW('T', 226, int)
#define TUNGETDEVNETNS _IO('T', 227)
#define IFF_TUN 0x0001
#define IFF_TAP 0x0002
#define IFF_NAPI 0x0010
#define IFF_NAPI_FRAGS 0x0020
#define IFF_NO_CARRIER 0x0040
#define IFF_NO_PI 0x1000
#define IFF_ONE_QUEUE 0x2000
#define IFF_VNET_HDR 0x4000
#define IFF_TUN_EXCL 0x8000
#define IFF_MULTI_QUEUE 0x0100
#define IFF_ATTACH_QUEUE 0x0200
#define IFF_DETACH_QUEUE 0x0400
#define IFF_PERSIST 0x0800
#define IFF_NOFILTER 0x1000
#define TUN_TX_TIMESTAMP 1
#define TUN_F_CSUM 0x01
#define TUN_F_TSO4 0x02
#define TUN_F_TSO6 0x04
#define TUN_F_TSO_ECN 0x08
#define TUN_F_UFO 0x10
#define TUN_F_USO4 0x20
#define TUN_F_USO6 0x40
#define TUN_PKT_STRIP 0x0001
struct tun_pi {
  __u16 flags;
  __be16 proto;
};
#define TUN_FLT_ALLMULTI 0x0001
struct tun_filter {
  __u16 flags;
  __u16 count;
  __u8 addr[][ETH_ALEN];
};
#endif
```