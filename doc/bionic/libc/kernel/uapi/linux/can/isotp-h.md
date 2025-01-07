Response:
Let's break down the thought process for analyzing the given C header file and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `isotp.h`, its relation to Android, how it's implemented (specifically focusing on libc and dynamic linking), common usage errors, and how it's accessed from higher Android layers. The output needs to be in Chinese.

**2. Initial Analysis of the Header File:**

* **File Location and Purpose:** The path `bionic/libc/kernel/uapi/linux/can/isotp.h` immediately tells us this is a header file defining the user-space API for the ISOTP (ISO Transport Protocol) over CAN (Controller Area Network) within the Linux kernel. The `uapi` indicates it's meant for user-space programs. The comment at the top confirms this and notes it's auto-generated.
* **Includes:** It includes `linux/types.h` and `linux/can.h`. This is crucial because it shows dependencies and where to find foundational definitions. `linux/can.h` will contain the basic CAN frame definitions.
* **Macros:** Several `#define` directives are present. These are constants and likely represent socket options or configuration flags for the ISOTP protocol. The `SOL_CAN_ISOTP` macro suggests it's a socket option level.
* **Structures:** Key structures are defined: `can_isotp_options`, `can_isotp_fc_options`, and `can_isotp_ll_options`. These likely represent different configuration parameters for the ISOTP socket.
* **Bitmasks/Flags:** A series of `#define` directives starting with `CAN_ISOTP_` followed by uppercase names strongly suggest bitmasks or flags used to configure the ISOTP socket behavior.
* **Default Values:**  Macros like `CAN_ISOTP_DEFAULT_FLAGS` define default values for the configuration options.

**3. Connecting to Android:**

* **Bionic Context:** The file is located within Bionic, Android's C library. This immediately establishes a direct connection to Android. Bionic provides the standard C library functions used by Android apps and system services.
* **CAN and Automotive:**  ISOTP over CAN is commonly used in automotive applications. This hints at potential use cases within Android's automotive stack (if it exists).

**4. Functionality Identification:**

Based on the structure definitions and macros, we can deduce the following functionalities:

* **Socket Options:**  The `SOL_CAN_ISOTP` and `CAN_ISOTP_*_OPTS` indicate this file defines options that can be set on CAN sockets using `setsockopt`.
* **ISOTP Configuration:** The structures define various ISOTP parameters like addressing (extended addressing), padding, flow control (block size, separation time), and link-layer options (MTU).
* **Operational Modes:** The flags define different modes of operation, such as listen-only, padding behavior, and handling of flow control.

**5. Addressing the Specific Requirements:**

* **功能 (Functions):**  List the identified functionalities clearly.
* **与 Android 的关系 (Relationship with Android):** Explain how Bionic integrates kernel headers and how ISOTP relates to potential automotive use cases within Android. Provide a concrete example, even if hypothetical, of an Android service using ISOTP for communication.
* **详细解释 libc 函数的功能是如何实现的 (Detailed explanation of libc functions):** This requires realizing that *this header file itself does not contain libc function implementations*. It *defines the interface* that user-space programs will use with libc's socket functions (like `socket`, `setsockopt`, `bind`, `send`, `recv`). Explain how these libc functions would interact with the kernel ISOTP implementation.
* **涉及 dynamic linker 的功能 (Dynamic linker functionality):** Recognize that this header file doesn't directly involve the dynamic linker. However, the user-space program using these definitions *will* be linked by the dynamic linker. Provide a simple example of an SO layout and explain the linking process at a high level (symbol resolution).
* **逻辑推理 (Logical deduction):**  Create a simple scenario (setting an option) and illustrate the expected input and output (no immediate output, but the socket's behavior changes).
* **用户或编程常见的使用错误 (Common user/programming errors):** Think about typical mistakes when working with sockets and options: incorrect option values, setting incompatible options, not handling errors.
* **说明 Android framework or ndk 是如何一步步的到达这里 (How Android framework/NDK reaches here):** Trace the path: NDK (C/C++) -> system calls (via Bionic) -> kernel ISOTP implementation. Provide a Frida hook example targeting `setsockopt` to demonstrate intercepting the system call related to ISOTP options.

**6. Structuring the Response:**

Organize the answer into logical sections corresponding to the prompt's requirements. Use clear headings and bullet points for readability.

**7. Providing Examples:**

Whenever possible, provide concrete examples (code snippets, SO layouts, Frida hooks) to illustrate the concepts. Even if the examples are simplified, they aid understanding.

**8. Language and Terminology:**

Use precise technical terms and explain them if necessary. Maintain the requested Chinese language throughout the response.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Focus heavily on the specific structures and flags in the header.
* **Correction:** Realize that the *header itself* doesn't implement anything. The focus should shift to how user-space programs *use* these definitions with libc and the kernel.
* **Initial thought:** Dive deep into the low-level details of the kernel ISOTP implementation.
* **Correction:**  Stay focused on the user-space perspective and how Android components interact with this API. Mention the kernel implementation but don't get bogged down in its specifics.
* **Initial thought:** Overlook the dynamic linking aspect.
* **Correction:**  Include a section explaining how a user-space program using this header would be linked and provide a basic SO layout example.

By following this structured thought process and iteratively refining the analysis, the comprehensive and accurate response can be generated. The key is to understand the *context* of the header file (user-space API for a kernel feature within Android) and address each part of the prompt directly.
这是一个定义了 ISOTP (ISO Transport Protocol) over CAN (Controller Area Network) 协议用户空间 API 的 C 头文件。它属于 Android 的 Bionic 库，位于内核头文件目录下。

**功能列举:**

这个头文件定义了以下功能，允许用户空间的应用程序配置和使用 ISOTP over CAN 协议进行通信：

1. **定义 ISOTP Socket Option Level:**  `SOL_CAN_ISOTP` 定义了一个套接字选项级别，用于设置与 ISOTP 协议相关的选项。
2. **定义 ISOTP 套接字选项常量:**
   - `CAN_ISOTP_OPTS`:  用于设置 `can_isotp_options` 结构体中的通用 ISOTP 选项。
   - `CAN_ISOTP_RECV_FC`: 用于设置 `can_isotp_fc_options` 结构体中的流控 (Flow Control) 选项。
   - `CAN_ISOTP_TX_STMIN`:  （虽然定义了，但从结构体看似乎不再使用，可能已废弃或仅用于兼容性）。
   - `CAN_ISOTP_RX_STMIN`: （虽然定义了，但从结构体看似乎不再使用，可能已废弃或仅用于兼容性）。
   - `CAN_ISOTP_LL_OPTS`: 用于设置 `can_isotp_ll_options` 结构体中的链路层 (Link Layer) 选项。
3. **定义 ISOTP 配置结构体:**
   - `can_isotp_options`: 包含通用的 ISOTP 配置选项，例如标志位、帧发送时间、扩展地址和填充字节。
   - `can_isotp_fc_options`: 包含 ISOTP 流控相关的选项，例如块大小 (BS)、最小间隔时间 (STmin) 和最大等待帧数 (WFTmax)。
   - `can_isotp_ll_options`: 包含 ISOTP 链路层相关的选项，例如最大传输单元 (MTU)、发送数据长度 (TX DL) 和发送标志位。
4. **定义 ISOTP 操作标志位:** 这些宏定义了可以设置在 `can_isotp_options` 结构体 `flags` 字段中的各种标志位，用于控制 ISOTP 的行为，例如监听模式、是否使用扩展地址、是否填充数据、半双工模式等。
5. **定义 ISOTP 默认值:**  提供了一系列宏定义，表示各种 ISOTP 选项的默认值。

**与 Android 功能的关系及举例说明:**

ISOTP over CAN 协议常用于汽车电子领域，Android 在车载信息娱乐系统 (IVI) 或与汽车电子控制单元 (ECU) 通信的场景中可能会使用到它。

**举例说明:**

假设一个 Android 应用需要与汽车的发动机控制单元 (ECU) 通信，读取发动机的转速和温度信息。通信过程可能使用 ISOTP over CAN 协议。

1. **底层 CAN 通信:** Android 系统或硬件抽象层 (HAL) 负责通过 CAN 总线发送和接收原始 CAN 帧。
2. **ISOTP 协议处理:**  用户空间的应用程序可以使用这里定义的结构体和常量，通过 Socket API 设置 ISOTP 相关的选项，指示内核按照 ISOTP 协议处理收发的 CAN 帧，将多个 CAN 帧组装成一个大的数据包，或将大的数据包拆分成多个 CAN 帧。

**例如，一个 Android 服务可能使用如下步骤与 ECU 通信:**

1. **创建 CAN Socket:** 使用 `socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP);` 创建一个 ISOTP 类型的 CAN socket。
2. **设置 ISOTP 选项:** 使用 `setsockopt()` 系统调用，并结合这里定义的常量和结构体来配置 ISOTP 选项，例如：
   ```c
   #include <sys/socket.h>
   #include <linux/can.h>
   #include <linux/can/isotp.h>

   int sock = socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP);
   if (sock < 0) {
       perror("socket");
       // ... 错误处理
   }

   struct can_isotp_options opts;
   memset(&opts, 0, sizeof(opts));
   opts.flags |= CAN_ISOTP_TX_PADDING; // 启用发送填充
   opts.txpad_content = 0xCC;         // 设置填充内容为 0xCC

   if (setsockopt(sock, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, sizeof(opts)) < 0) {
       perror("setsockopt");
       // ... 错误处理
   }
   ```
3. **绑定 CAN 接口:** 将 socket 绑定到特定的 CAN 接口。
4. **发送和接收数据:** 使用 `sendto()` 和 `recvfrom()` 发送和接收符合 ISOTP 协议的数据。内核会根据设置的选项自动处理 CAN 帧的拆分和组装。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有实现任何 libc 函数。它只是定义了数据结构和常量，供用户空间的程序在调用 libc 提供的 socket 相关函数时使用。

以下是一些相关的 libc 函数及其功能实现简述：

* **`socket(int domain, int type, int protocol)`:**
    * **功能:** 创建一个特定类型的 socket。
    * **实现:**  这是一个系统调用，最终会陷入内核。内核根据 `domain` (例如 `AF_CAN`)、`type` (例如 `SOCK_DGRAM`) 和 `protocol` (例如 `CAN_ISOTP`) 创建相应的内核数据结构来表示这个 socket，并分配相关的资源。对于 `CAN_ISOTP` 协议，内核会创建一个与 CAN 接口关联的 ISOTP 协议栈实例。
* **`setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)`:**
    * **功能:** 设置 socket 的选项。
    * **实现:** 也是一个系统调用。内核根据 `level` (例如 `SOL_CAN_ISOTP`) 和 `optname` (例如 `CAN_ISOTP_OPTS`) 找到对应的 socket 选项处理函数，并将 `optval` 指向的数据复制到内核空间，更新 socket 的配置。对于 ISOTP 选项，内核会解析 `can_isotp_options` 等结构体中的字段，配置 ISOTP 协议栈的行为，例如是否填充数据、流控参数等。
* **`bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`:**
    * **功能:** 将 socket 绑定到特定的地址和端口。对于 CAN socket，`addr` 通常是一个 `sockaddr_can` 结构体，指定了要绑定的 CAN 接口。
    * **实现:** 系统调用，内核将 socket 与指定的 CAN 接口关联起来，后续通过该 socket 发送的数据将通过该接口发送，接收的数据也将来自该接口。
* **`sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)` 和 `recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)`:**
    * **功能:** 在 socket 上发送和接收数据。
    * **实现:** 系统调用。
        * **`sendto`:**  用户空间的数据会被传递到内核的 ISOTP 协议栈，协议栈会根据配置将数据分割成 CAN 帧，并添加到 CAN 接口的发送队列中。
        * **`recvfrom`:**  当 CAN 接口接收到 CAN 帧时，内核的 ISOTP 协议栈会根据 ISOTP 协议将多个 CAN 帧重组成完整的数据包，并将其复制到用户空间的 `buf` 中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及动态链接器的功能。它只是定义了数据结构和常量，会被编译到用户空间的程序中。

但是，用户空间的程序在调用 libc 函数（如 `socket` 和 `setsockopt`）时，这些函数的实现位于 Bionic 提供的共享对象 (`.so`) 文件中，例如 `libc.so`。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:
        socket:  // socket 函数的代码
            ...
        setsockopt: // setsockopt 函数的代码
            ...
        // 其他 libc 函数的代码
    .data:
        // 全局变量
    .dynsym:
        socket  // socket 函数的符号
        setsockopt // setsockopt 函数的符号
        // 其他导出符号
    .dynstr:
        socket\0
        setsockopt\0
        // 其他字符串
```

**链接的处理过程:**

1. **编译时链接:** 编译器在编译用户程序时，遇到对 `socket` 和 `setsockopt` 等函数的调用，会生成对这些符号的未解析引用。
2. **动态链接:** 当用户程序启动时，动态链接器 (例如 `linker64` 或 `linker`) 会负责加载程序依赖的共享对象 (`libc.so`) 到内存中。
3. **符号解析:** 动态链接器会遍历已加载的共享对象的符号表 (`.dynsym`)，找到与用户程序中未解析符号匹配的符号定义。
4. **重定位:** 动态链接器会修改用户程序中的指令，将对未解析符号的引用替换为 `libc.so` 中对应函数的实际内存地址。

**假设输入与输出 (逻辑推理):**

假设用户程序尝试设置 ISOTP 的发送填充选项：

**假设输入:**

* `sockfd`:  一个已经创建的 ISOTP CAN socket 的文件描述符。
* `level`: `SOL_CAN_ISOTP`。
* `optname`: `CAN_ISOTP_OPTS`。
* `optval`: 指向一个 `can_isotp_options` 结构体的指针，其中 `flags` 字段包含 `CAN_ISOTP_TX_PADDING` 标志位，并且 `txpad_content` 字段设置为 `0xAA`。
* `optlen`: `sizeof(struct can_isotp_options)`。

**预期输出:**

* 如果 `setsockopt` 调用成功，返回值应为 0。
* 内核中与该 socket 关联的 ISOTP 协议栈配置将被更新，后续通过该 socket 发送的数据帧将会填充 `0xAA` 字节，直到达到 CAN 数据帧的最大长度。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未包含必要的头文件:**  如果忘记包含 `<linux/can.h>` 或 `<linux/can/isotp.h>`，会导致编译器无法识别相关的宏定义和结构体，产生编译错误。
   ```c
   // 编译错误，因为缺少头文件
   int sock = socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP);
   ```

2. **传递错误的 `optlen`:** `setsockopt` 的 `optlen` 参数必须是 `optval` 指向的数据的实际大小。如果传递错误的大小，可能导致读取或写入越界。
   ```c
   struct can_isotp_options opts;
   // ... 初始化 opts
   if (setsockopt(sock, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, 1) < 0) { // 错误的 optlen
       perror("setsockopt");
   }
   ```

3. **使用未初始化的结构体:**  在调用 `setsockopt` 之前，应该正确初始化 `can_isotp_options` 等结构体，否则会使用未定义的值，导致不可预测的行为。
   ```c
   struct can_isotp_options opts; // 未初始化
   if (setsockopt(sock, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, sizeof(opts)) < 0) {
       perror("setsockopt");
   }
   ```

4. **设置冲突的选项:**  某些 ISOTP 选项可能存在冲突，例如同时启用发送和接收填充但填充内容不同。内核可能会拒绝设置这样的配置或产生意外行为。

5. **在错误的 socket 上设置选项:**  尝试在非 CAN 或非 ISOTP socket 上设置 ISOTP 选项会导致错误。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 开发:**  开发者通常使用 NDK (Native Development Kit) 来编写 C/C++ 代码，这些代码可以直接调用 Linux 系统调用和使用 Bionic 库。

2. **NDK API 调用:** 在 NDK 代码中，开发者会调用 Bionic 提供的 socket 相关函数，例如 `socket()`, `setsockopt()`, `bind()`, `sendto()`, `recvfrom()`。

3. **Bionic libc:** 这些 NDK 调用的函数最终会链接到 Bionic 的 `libc.so` 中的实现。

4. **系统调用:** `libc.so` 中的 `socket()` 和 `setsockopt()` 等函数会通过 `syscall` 指令触发系统调用，陷入 Linux 内核。

5. **内核 CAN 子系统:** 内核接收到系统调用后，会根据系统调用号和参数，调用相应的内核函数来处理 CAN 和 ISOTP 协议。

6. **CAN 驱动:** 内核 CAN 子系统会与底层的 CAN 控制器驱动进行交互，通过硬件发送和接收 CAN 帧。

**Frida Hook 示例:**

可以使用 Frida 来 Hook `setsockopt` 系统调用，观察 Android Framework 或 NDK 如何设置 ISOTP 选项。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "your.android.app.package"  # 替换为你的 Android 应用包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Make sure the app is running.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
        onEnter: function(args) {
            var sockfd = args[0].toInt32();
            var level = args[1].toInt32();
            var optname = args[2].toInt32();
            var optval = ptr(args[3]);
            var optlen = args[4].toInt32();

            if (level === SOL_CAN_ISOTP) {
                console.log("================= setsockopt called for SOL_CAN_ISOTP =================");
                console.log("sockfd: " + sockfd);
                console.log("optname: " + optname);
                console.log("optlen: " + optlen);

                if (optname === CAN_ISOTP_OPTS) {
                    console.log("Option: CAN_ISOTP_OPTS");
                    var opts = Memory.readByteArray(optval, optlen);
                    console.log("can_isotp_options data: " + hexdump(opts));
                    // 可以进一步解析 opts 中的字段
                } else if (optname === CAN_ISOTP_RECV_FC) {
                    console.log("Option: CAN_ISOTP_RECV_FC");
                    var fc_opts = Memory.readByteArray(optval, optlen);
                    console.log("can_isotp_fc_options data: " + hexdump(fc_opts));
                } else if (optname === CAN_ISOTP_LL_OPTS) {
                    console.log("Option: CAN_ISOTP_LL_OPTS");
                    var ll_opts = Memory.readByteArray(optval, optlen);
                    console.log("can_isotp_ll_options data: " + hexdump(ll_opts));
                }
            }
        }
    });

    const SOL_CAN_ISOTP = 253; // 需要根据实际情况确定，可能需要动态获取
    const CAN_ISOTP_OPTS = 1;
    const CAN_ISOTP_RECV_FC = 2;
    const CAN_ISOTP_LL_OPTS = 5;
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**解释 Frida Hook 步骤:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **定义消息处理函数:** `on_message` 函数用于处理 Frida 脚本发送的消息。
3. **获取设备并附加进程:**  `frida.get_usb_device().attach(package_name)` 获取 USB 连接的 Android 设备，并附加到目标应用程序的进程。需要替换 `your.android.app.package` 为实际的应用包名。
4. **编写 Frida 脚本:**
   - 使用 `Interceptor.attach` Hook `libc.so` 中的 `setsockopt` 函数。
   - 在 `onEnter` 函数中，获取 `setsockopt` 的参数。
   - 检查 `level` 是否为 `SOL_CAN_ISOTP`，如果是，则表示正在设置 ISOTP 选项。
   - 打印相关的参数信息，包括 `sockfd`、`optname` 和 `optlen`。
   - 根据 `optname` 的值，读取 `optval` 指向的内存数据，并以十六进制格式打印出来，方便查看 `can_isotp_options`、`can_isotp_fc_options` 或 `can_isotp_ll_options` 结构体的具体内容。
   - **注意:** `SOL_CAN_ISOTP` 和 `CAN_ISOTP_*` 的值可能需要根据 Android 系统的具体版本动态获取，或者通过其他方式确定其常量值。这里为了示例方便直接使用了定义的值，实际使用中可能需要更严谨的处理。
5. **创建和加载 Frida 脚本:** 使用 `session.create_script(script_code)` 创建脚本，并使用 `script.load()` 加载脚本到目标进程。
6. **保持脚本运行:** `sys.stdin.read()` 阻止脚本立即退出，保持 Hook 状态。
7. **卸载 Frida:** `session.detach()` 在脚本结束时卸载 Frida。

通过运行这个 Frida 脚本，当目标 Android 应用调用 `setsockopt` 设置 ISOTP 选项时，你可以在 Frida 的控制台中看到相关的参数信息，从而了解 Android Framework 或 NDK 是如何一步步配置 ISOTP 协议的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/can/isotp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_CAN_ISOTP_H
#define _UAPI_CAN_ISOTP_H
#include <linux/types.h>
#include <linux/can.h>
#define SOL_CAN_ISOTP (SOL_CAN_BASE + CAN_ISOTP)
#define CAN_ISOTP_OPTS 1
#define CAN_ISOTP_RECV_FC 2
#define CAN_ISOTP_TX_STMIN 3
#define CAN_ISOTP_RX_STMIN 4
#define CAN_ISOTP_LL_OPTS 5
struct can_isotp_options {
  __u32 flags;
  __u32 frame_txtime;
  __u8 ext_address;
  __u8 txpad_content;
  __u8 rxpad_content;
  __u8 rx_ext_address;
};
struct can_isotp_fc_options {
  __u8 bs;
  __u8 stmin;
  __u8 wftmax;
};
struct can_isotp_ll_options {
  __u8 mtu;
  __u8 tx_dl;
  __u8 tx_flags;
};
#define CAN_ISOTP_LISTEN_MODE 0x0001
#define CAN_ISOTP_EXTEND_ADDR 0x0002
#define CAN_ISOTP_TX_PADDING 0x0004
#define CAN_ISOTP_RX_PADDING 0x0008
#define CAN_ISOTP_CHK_PAD_LEN 0x0010
#define CAN_ISOTP_CHK_PAD_DATA 0x0020
#define CAN_ISOTP_HALF_DUPLEX 0x0040
#define CAN_ISOTP_FORCE_TXSTMIN 0x0080
#define CAN_ISOTP_FORCE_RXSTMIN 0x0100
#define CAN_ISOTP_RX_EXT_ADDR 0x0200
#define CAN_ISOTP_WAIT_TX_DONE 0x0400
#define CAN_ISOTP_SF_BROADCAST 0x0800
#define CAN_ISOTP_CF_BROADCAST 0x1000
#define CAN_ISOTP_DYN_FC_PARMS 0x2000
#define CAN_ISOTP_DEFAULT_FLAGS 0
#define CAN_ISOTP_DEFAULT_EXT_ADDRESS 0x00
#define CAN_ISOTP_DEFAULT_PAD_CONTENT 0xCC
#define CAN_ISOTP_DEFAULT_FRAME_TXTIME 50000
#define CAN_ISOTP_DEFAULT_RECV_BS 0
#define CAN_ISOTP_DEFAULT_RECV_STMIN 0x00
#define CAN_ISOTP_DEFAULT_RECV_WFTMAX 0
#define CAN_ISOTP_DEFAULT_LL_MTU CAN_MTU
#define CAN_ISOTP_DEFAULT_LL_TX_DL CAN_MAX_DLEN
#define CAN_ISOTP_DEFAULT_LL_TX_FLAGS 0
#define CAN_ISOTP_FRAME_TXTIME_ZERO 0xFFFFFFFF
#endif

"""

```