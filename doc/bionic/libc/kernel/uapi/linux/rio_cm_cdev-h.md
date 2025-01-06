Response:
Let's break down the thought process for answering the request about `rio_cm_cdev.h`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`rio_cm_cdev.h`) and explain its functionality within the context of Android's Bionic library. The prompt specifically asks for:

* Listing functionalities.
* Connecting these functionalities to Android.
* Detailed explanations of libc functions.
* Dynamic linker considerations (if applicable).
* Logical reasoning with examples.
* Common usage errors.
* Tracing the path from Android Framework/NDK.
* Frida hook examples.

**2. Initial Analysis of the Header File:**

The first step is to examine the contents of the header file. Key observations are:

* **`#ifndef _RIO_CM_CDEV_H_` and `#define _RIO_CM_CDEV_H_`:**  This is a standard include guard, preventing multiple inclusions of the header file.
* **`#include <linux/types.h>`:** This indicates the header file interacts with the Linux kernel. The types defined here (`__u16`, `__u8`, `__u32`, `__u64`) are common in kernel interfaces.
* **Structures (`rio_cm_channel`, `rio_cm_msg`, `rio_cm_accept`):** These structures define data formats for communication. Their names suggest operations related to channels, messages, and accepting connections.
* **Macros (`RIO_CM_IOC_MAGIC`, `RIO_CM_EP_GET_LIST_SIZE`, etc.):** These macros define ioctl commands. The pattern `_IOWR`, `_IOW` strongly suggests this header is defining an interface for interacting with a character device driver. The `RIO_CM_IOC_MAGIC` likely identifies the specific device family. The names of the other macros clearly indicate different operations (getting lists, creating/closing/binding/listening/accepting/connecting/sending/receiving).

**3. Connecting to Android and Bionic:**

The prompt explicitly mentions Bionic. The fact that this header is located within `bionic/libc/kernel/uapi/linux/` confirms it's part of Bionic's interface to the Linux kernel. The "uapi" part further indicates it's a user-space API for interacting with a kernel component. The name "rio_cm" likely stands for "RapidIO Communication Management," suggesting a lower-level communication mechanism.

**4. Addressing Specific Questions:**

* **Functionalities:**  Based on the macros, the core functionalities are related to managing communication channels: creating, closing, binding, listening, accepting, connecting, sending, and receiving. There are also operations for getting lists of endpoints and mports.
* **Android Relationship:**  This is where the connection to Android becomes important. Since this is a kernel interface, it's likely used by system services or hardware abstraction layers (HALs) that need to interact with hardware using the RapidIO protocol. It's *not* typically something directly used by application developers. Examples of such services could involve inter-processor communication or specialized hardware interfaces.
* **libc Functions:** The header file itself *doesn't define* libc functions. It defines *constants* used by system calls like `ioctl()`. Therefore, the explanation focuses on how `ioctl()` is used with these constants.
* **Dynamic Linker:** This header file does *not* directly involve the dynamic linker. It's a kernel interface. Therefore, the explanation clarifies this and provides a "negative" answer.
* **Logical Reasoning:**  The example provided focuses on the `RIO_CM_CHAN_SEND` macro, illustrating how it's used within an `ioctl()` call, demonstrating the input parameters and potential output.
* **Common Usage Errors:** The focus here is on common errors when using `ioctl()`: incorrect file descriptor, wrong command, and mismatched data sizes.
* **Android Framework/NDK Path:** This requires thinking about how an Android app might indirectly trigger the use of this interface. The path is from an application using an Android API, which might call into a framework service, which in turn might use a HAL, eventually leading to a device driver interaction using `ioctl()` with these specific constants.
* **Frida Hook:** The Frida example focuses on hooking the `ioctl()` system call and filtering for calls using the `RIO_CM_IOC_MAGIC`, allowing inspection of the command and arguments.

**5. Structuring the Answer:**

Organizing the answer logically is crucial. The structure used in the provided good example is effective:

* Start with a general overview of the file's purpose.
* List the functionalities based on the macros.
* Explain the connection to Android, giving concrete (though perhaps slightly hypothetical, given the specific nature of RapidIO) examples.
* Explain the role of `ioctl()` and how the macros are used.
* Clearly state that the dynamic linker is not directly involved.
* Provide a logical reasoning example using `RIO_CM_CHAN_SEND`.
* Outline common usage errors related to `ioctl()`.
* Describe the path from the Android Framework/NDK to this kernel interface.
* Give a practical Frida hooking example.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "Are these actual function definitions?"  **Correction:** Realized these are just macro definitions for `ioctl()` commands.
* **Initial thought:** "How does the dynamic linker fit in?" **Correction:** Recognized that this header is about kernel interaction, not user-space library linking.
* **Initial thought:** "What's a very simple example of using these?" **Correction:** Focused on a single `ioctl()` call with one of the defined commands to illustrate the concept.
* **Initial thought:** "How can I make the Frida example practical?" **Correction:**  Decided to hook the generic `ioctl()` call and filter based on the magic number, as directly hooking calls involving these macros within a closed-source system would be difficult without more context.

By following this structured analysis and iterative refinement process, the comprehensive and informative answer can be generated.
```chinese
这是一个位于 Android Bionic 库中，用于描述 Linux 内核 RapidIO 连接管理 (RIO CM) 字符设备接口的头文件。简单来说，它定义了用户空间程序与内核中 RIO CM 驱动交互所需要的数据结构和 ioctl 命令。

**功能列举:**

这个头文件定义了以下与 RIO CM 设备交互的功能：

1. **获取 RIO CM 端点列表大小 (`RIO_CM_EP_GET_LIST_SIZE`)**:  允许用户空间程序查询当前可用的 RIO CM 端点数量。
2. **获取 RIO CM 端点列表 (`RIO_CM_EP_GET_LIST`)**:  允许用户空间程序获取当前可用 RIO CM 端点的详细信息。
3. **创建 RIO CM 通道 (`RIO_CM_CHAN_CREATE`)**:  请求内核创建一个新的 RIO CM 通信通道。
4. **关闭 RIO CM 通道 (`RIO_CM_CHAN_CLOSE`)**:  请求内核关闭一个已创建的 RIO CM 通信通道。
5. **绑定 RIO CM 通道 (`RIO_CM_CHAN_BIND`)**:  将一个本地 RIO CM 通道与一个特定的本地地址绑定。
6. **监听 RIO CM 通道 (`RIO_CM_CHAN_LISTEN`)**:  使一个绑定的 RIO CM 通道进入监听状态，等待远程连接请求。
7. **接受 RIO CM 连接 (`RIO_CM_CHAN_ACCEPT`)**:  接受一个在监听通道上的远程连接请求，创建一个新的连接通道。
8. **连接 RIO CM 通道 (`RIO_CM_CHAN_CONNECT`)**:  向指定的远程 RIO CM 端点发起连接请求。
9. **发送 RIO CM 消息 (`RIO_CM_CHAN_SEND`)**:  通过已连接的 RIO CM 通道发送消息。
10. **接收 RIO CM 消息 (`RIO_CM_CHAN_RECEIVE`)**: 通过已连接的 RIO CM 通道接收消息。
11. **获取 RIO CM MPORT 列表 (`RIO_CM_MPORT_GET_LIST`)**: 允许用户空间程序获取当前可用的 RIO CM MPORT (Multi-Port) 的信息。

**与 Android 功能的关系及举例:**

RapidIO 是一种高性能的互连技术，主要用于嵌入式系统和高性能计算领域。在 Android 设备中，它可能被用于以下场景（尽管不常见于主流消费级设备）：

* **硬件加速器通信:** 如果 Android 设备集成了使用 RapidIO 接口的硬件加速器（例如，用于某些特定的图像处理或信号处理任务），系统服务或 HAL (Hardware Abstraction Layer) 可能会使用这些接口与硬件加速器通信。
* **处理器间通信 (IPC):** 在某些具有多个处理器的复杂 Android 设备中，RapidIO 可以作为一种高速的处理器间通信机制。
* **外部设备连接:**  理论上，Android 设备可以通过 RapidIO 接口连接到某些外部设备。

**举例说明:**

假设一个 Android 设备中存在一个使用 RapidIO 连接的图像处理单元 (IPU)。一个负责图像处理的系统服务可能需要与 IPU 通信以执行图像处理任务。

1. **创建通道:** 系统服务可能会使用 `RIO_CM_CHAN_CREATE` 创建一个 RIO CM 通道，用于与 IPU 通信。这会调用内核的 RIO CM 驱动，驱动会分配一个内部通道 ID。
2. **绑定通道:** 系统服务可能不需要显式绑定，或者可以绑定到一个特定的本地地址（如果有需要）。
3. **连接通道:** 系统服务使用 `RIO_CM_CHAN_CONNECT` 指定 IPU 的远程端点信息 (`remote_destid`, `mport_id`)，请求建立连接。
4. **发送消息:**  一旦连接建立，系统服务就可以使用 `RIO_CM_CHAN_SEND` 将图像处理指令和数据发送到 IPU。消息内容会填充到 `rio_cm_msg` 结构体的 `msg` 字段中。
5. **接收消息:**  IPU 完成处理后，可能会通过 `RIO_CM_CHAN_SEND` （对于 IPU 来说是发送）将结果返回。系统服务使用 `RIO_CM_CHAN_RECEIVE` 接收这些结果。
6. **关闭通道:** 当通信结束后，系统服务可以使用 `RIO_CM_CHAN_CLOSE` 关闭连接。

**libc 函数的功能实现:**

这个头文件本身并没有定义任何 libc 函数。它定义的是用于 `ioctl` 系统调用的常量和数据结构。用户空间程序需要使用 libc 提供的 `ioctl` 函数与内核驱动进行交互。

`ioctl` 函数的原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  文件描述符，指向要操作的设备文件 (在本例中是 RIO CM 字符设备，例如 `/dev/rio_cm`)。
* `request`:  一个与设备相关的请求码，通常使用本头文件中定义的 `RIO_CM_...` 宏。
* `...`:  可选的参数，依赖于 `request` 的值。可以是指向数据的指针。

**例如，`RIO_CM_CHAN_CREATE` 的使用:**

用户空间程序会首先打开 RIO CM 字符设备，获得一个文件描述符 `fd`。然后，使用 `ioctl` 函数发起创建通道的请求：

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include "rio_cm_cdev.h" // 包含头文件

int main() {
  int fd = open("/dev/rio_cm", O_RDWR);
  if (fd < 0) {
    perror("打开 /dev/rio_cm 失败");
    return 1;
  }

  __u16 new_channel_id;
  if (ioctl(fd, RIO_CM_CHAN_CREATE, &new_channel_id) < 0) {
    perror("创建 RIO CM 通道失败");
    close(fd);
    return 1;
  }

  printf("成功创建 RIO CM 通道，ID: %u\n", new_channel_id);

  close(fd);
  return 0;
}
```

在这个例子中，`ioctl` 函数调用了内核的 RIO CM 驱动，并传递了 `RIO_CM_CHAN_CREATE` 请求码。驱动程序会分配一个新的通道 ID，并通过 `ioctl` 的第三个参数（指向 `new_channel_id` 的指针）返回给用户空间程序。

**涉及 dynamic linker 的功能:**

这个头文件主要定义了内核接口，与 dynamic linker 没有直接关系。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 负责在程序启动时加载和链接共享库。这个头文件中的定义会被编译到使用它的用户空间程序中，并在运行时通过系统调用与内核交互。

**如果涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

由于这个头文件不直接涉及 dynamic linker，这里无法提供相关的 so 布局样本和链接处理过程。通常，包含此类内核接口的头文件的代码会被编译成可执行文件或共享库。在编译时，编译器会处理头文件中的定义。在运行时，程序会通过 `syscall` 指令触发 `ioctl` 系统调用，进入内核空间执行相应的驱动程序代码。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入 (针对 `RIO_CM_CHAN_SEND`):**

* `fd`:  已成功连接的 RIO CM 通道的字符设备文件描述符。
* `request`: `RIO_CM_CHAN_SEND` 宏的值。
* `argp`: 指向 `rio_cm_msg` 结构体的指针，结构体内容如下：
    * `ch_num`:  目标通道号。
    * `size`:   要发送的消息大小（字节）。
    * `rxto`:   接收超时时间（可能被驱动忽略）。
    * `msg`:    指向要发送的实际数据的指针。

**假设输出 (成功发送):**

* `ioctl` 函数返回 0。
* 内核 RIO CM 驱动成功将消息发送到远程端点。

**假设输入 (针对 `RIO_CM_CHAN_RECEIVE`):**

* `fd`:  已成功连接的 RIO CM 通道的字符设备文件描述符。
* `request`: `RIO_CM_CHAN_RECEIVE` 宏的值。
* `argp`: 指向 `rio_cm_msg` 结构体的指针，其中 `msg` 指向一个用于接收数据的缓冲区。

**假设输出 (成功接收):**

* `ioctl` 函数返回 0。
* `rio_cm_msg` 结构体的 `msg` 字段指向的缓冲区中包含从远程端点接收到的数据。
* `rio_cm_msg` 结构体的 `size` 字段更新为实际接收到的数据大小。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未打开设备文件:**  在调用任何 `ioctl` 命令之前，必须先使用 `open` 函数打开 RIO CM 字符设备文件 (`/dev/rio_cm`)。如果文件打开失败，`ioctl` 调用将失败。

   ```c
   int fd;
   // 忘记打开设备文件
   if (ioctl(fd, RIO_CM_CHAN_CREATE, &channel_id) < 0) { // 错误：fd 未初始化或无效
       perror("创建通道失败");
   }
   ```

2. **使用了错误的请求码:**  为 `ioctl` 传递了错误的 `request` 值，例如将用于接收消息的宏用于发送消息。

   ```c
   // 假设要发送消息，但错误地使用了接收消息的宏
   rio_cm_msg msg;
   // ... 初始化 msg ...
   if (ioctl(fd, RIO_CM_CHAN_RECEIVE, &msg) < 0) { // 错误：应该使用 RIO_CM_CHAN_SEND
       perror("发送消息失败");
   }
   ```

3. **传递了错误的数据结构或大小:** `ioctl` 的第三个参数必须指向与请求码预期的数据结构类型和大小一致的内存区域。传递错误的数据结构或大小会导致不可预测的行为，甚至内核崩溃。

   ```c
   __u32 incorrect_data;
   if (ioctl(fd, RIO_CM_CHAN_SEND, &incorrect_data) < 0) { // 错误：应传递 rio_cm_msg 结构体
       perror("发送消息失败");
   }
   ```

4. **在未连接的通道上发送/接收数据:**  在调用 `RIO_CM_CHAN_SEND` 或 `RIO_CM_CHAN_RECEIVE` 之前，必须先使用 `RIO_CM_CHAN_CONNECT` 成功建立连接 (或者对于监听通道，使用 `RIO_CM_CHAN_ACCEPT` 接受连接)。

   ```c
   int fd = open("/dev/rio_cm", O_RDWR);
   __u16 channel_id;
   ioctl(fd, RIO_CM_CHAN_CREATE, &channel_id);
   // 忘记连接通道
   rio_cm_msg msg;
   // ... 初始化 msg ...
   if (ioctl(fd, RIO_CM_CHAN_SEND, &msg) < 0) { // 错误：通道未连接
       perror("发送消息失败");
   }
   close(fd);
   ```

5. **缓冲区溢出:** 在使用 `RIO_CM_CHAN_RECEIVE` 接收数据时，提供的缓冲区大小必须足够容纳接收到的数据。如果接收到的数据超过缓冲区大小，会导致缓冲区溢出。

   ```c
   int fd = open("/dev/rio_cm", O_RDWR);
   // ... 连接通道 ...
   rio_cm_msg msg;
   char recv_buffer[10]; // 小缓冲区
   msg.msg = (__u64)recv_buffer;
   msg.size = sizeof(recv_buffer);
   if (ioctl(fd, RIO_CM_CHAN_RECEIVE, &msg) < 0) {
       perror("接收消息失败");
   } else if (msg.size > sizeof(recv_buffer)) { // 潜在的缓冲区溢出
       printf("接收到的数据超过缓冲区大小\n");
   }
   close(fd);
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于这是一个底层的内核接口，Android Framework 或 NDK 应用通常不会直接调用这些接口。更可能的情况是，Android Framework 中的某些系统服务或底层的 HAL (Hardware Abstraction Layer) 会使用这些接口与特定的硬件进行交互。

**可能的路径：**

1. **NDK 应用 (间接):**  一个 NDK 应用可能会调用一个 Android Framework 提供的 API。
2. **Android Framework API:** 该 API 的实现可能涉及到某个系统服务。
3. **系统服务:** 系统服务需要与使用 RapidIO 的硬件进行通信。
4. **HAL (Hardware Abstraction Layer):** 系统服务可能会调用一个 HAL 模块提供的接口。HAL 模块是特定于硬件的，负责与内核驱动程序交互。
5. **内核驱动程序 (RIO CM):** HAL 模块会打开 `/dev/rio_cm` 设备文件，并使用 `ioctl` 系统调用，传入 `rio_cm_cdev.h` 中定义的宏和数据结构，与 RIO CM 驱动进行通信。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用，并过滤出与 RIO CM 相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    if pid:
        session = device.attach(pid)
    else:
        package_name = "com.example.rio_cm_app" # 替换为可能使用 RIO CM 的应用的包名
        session = device.attach(package_name)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查是否是与 RIO CM 相关的 ioctl 调用 (根据 RIO_CM_IOC_MAGIC)
            if ((request & 0xFF) === '%d'.charCodeAt(0)) {
                const requestName = getRioCmRequestName(request);
                this.rioCmData = { fd: fd, request: request, requestName: requestName };
                console.log("[IOCTL] RIO CM Call: fd=" + fd + ", request=0x" + request.toString(16) + " (" + requestName + ")");

                // 可以进一步解析参数，根据不同的 request 类型读取 args[2] 的内容
                // 例如，对于 RIO_CM_CHAN_SEND，可以读取 rio_cm_msg 结构体
                if (requestName === "RIO_CM_CHAN_SEND") {
                    const msgPtr = ptr(args[2]);
                    const ch_num = msgPtr.readU16();
                    const size = msgPtr.add(2).readU16();
                    console.log("[IOCTL]   Sending: ch_num=" + ch_num + ", size=" + size);
                    // 如果需要查看发送的数据，可以进一步读取 msg 字段指向的内存
                }
            }
        },
        onLeave: function(retval) {
            if (this.rioCmData) {
                console.log("[IOCTL] RIO CM Call Returned: " + retval);
            }
        }
    });

    function getRioCmRequestName(request) {
        const commands = {
            0xC301: "RIO_CM_EP_GET_LIST_SIZE",
            0xC302: "RIO_CM_EP_GET_LIST",
            0xC303: "RIO_CM_CHAN_CREATE",
            0xC304: "RIO_CM_CHAN_CLOSE",
            0xC305: "RIO_CM_CHAN_BIND",
            0xC306: "RIO_CM_CHAN_LISTEN",
            0xC307: "RIO_CM_CHAN_ACCEPT",
            0xC308: "RIO_CM_CHAN_CONNECT",
            0xC309: "RIO_CM_CHAN_SEND",
            0xC30A: "RIO_CM_CHAN_RECEIVE",
            0xC30B: "RIO_CM_MPORT_GET_LIST"
        };
        return commands[request] || "Unknown RIO CM Command";
    }
    """ % ord('c') # RIO_CM_IOC_MAGIC 的字符 'c'

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input("[*] Press Enter to detach from the process...\n")
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `rio_cm_hook.py`。
2. 运行目标 Android 应用（可能需要 root 权限）。
3. 运行 Frida 脚本，需要指定目标进程的 PID 或包名：
   ```bash
   frida -U -f com.example.rio_cm_app rio_cm_hook.py  # 通过包名启动并 hook
   # 或
   frida -U -p <PID> rio_cm_hook.py  # 通过 PID hook 已经运行的进程
   ```

**Frida 脚本解释:**

* **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook 了 `ioctl` 系统调用。
* **`onEnter`:**  在 `ioctl` 调用入口处执行。
* **`(request & 0xFF) === '%d'.charCodeAt(0)`:**  检查 `ioctl` 的请求码的最低字节是否与 `RIO_CM_IOC_MAGIC` 相同，以此判断是否是 RIO CM 相关的调用。
* **`getRioCmRequestName(request)`:**  一个辅助函数，将请求码转换为易读的名称。
* **解析参数:**  在 `onEnter` 中，可以根据不同的 `request` 值，进一步解析 `args[2]` 指向的数据结构的内容。例如，对于 `RIO_CM_CHAN_SEND`，读取 `rio_cm_msg` 结构体的字段。
* **`onLeave`:** 在 `ioctl` 调用返回时执行，可以查看返回值。

通过这个 Frida 脚本，你可以在 Android 设备上监控目标进程是否调用了与 RIO CM 相关的 `ioctl` 命令，并查看传递的参数，从而调试相关的步骤。你需要根据实际情况替换 `com.example.rio_cm_app` 为你想要监控的应用程序的包名。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/rio_cm_cdev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _RIO_CM_CDEV_H_
#define _RIO_CM_CDEV_H_
#include <linux/types.h>
struct rio_cm_channel {
  __u16 id;
  __u16 remote_channel;
  __u16 remote_destid;
  __u8 mport_id;
};
struct rio_cm_msg {
  __u16 ch_num;
  __u16 size;
  __u32 rxto;
  __u64 msg;
};
struct rio_cm_accept {
  __u16 ch_num;
  __u16 pad0;
  __u32 wait_to;
};
#define RIO_CM_IOC_MAGIC 'c'
#define RIO_CM_EP_GET_LIST_SIZE _IOWR(RIO_CM_IOC_MAGIC, 1, __u32)
#define RIO_CM_EP_GET_LIST _IOWR(RIO_CM_IOC_MAGIC, 2, __u32)
#define RIO_CM_CHAN_CREATE _IOWR(RIO_CM_IOC_MAGIC, 3, __u16)
#define RIO_CM_CHAN_CLOSE _IOW(RIO_CM_IOC_MAGIC, 4, __u16)
#define RIO_CM_CHAN_BIND _IOW(RIO_CM_IOC_MAGIC, 5, struct rio_cm_channel)
#define RIO_CM_CHAN_LISTEN _IOW(RIO_CM_IOC_MAGIC, 6, __u16)
#define RIO_CM_CHAN_ACCEPT _IOWR(RIO_CM_IOC_MAGIC, 7, struct rio_cm_accept)
#define RIO_CM_CHAN_CONNECT _IOW(RIO_CM_IOC_MAGIC, 8, struct rio_cm_channel)
#define RIO_CM_CHAN_SEND _IOW(RIO_CM_IOC_MAGIC, 9, struct rio_cm_msg)
#define RIO_CM_CHAN_RECEIVE _IOWR(RIO_CM_IOC_MAGIC, 10, struct rio_cm_msg)
#define RIO_CM_MPORT_GET_LIST _IOWR(RIO_CM_IOC_MAGIC, 11, __u32)
#endif

"""

```