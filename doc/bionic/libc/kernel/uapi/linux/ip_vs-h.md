Response:
Let's break down the thought process for analyzing this IPVS header file.

**1. Initial Understanding & Context:**

* **File Type:** The header comment explicitly states it's auto-generated and located within the Android Bionic library (`bionic/libc/kernel/uapi/linux/ip_vs.handroid`). This immediately tells us it's a user-space header providing definitions for interacting with the Linux kernel's IP Virtual Server (IPVS) functionality. The `.handroid` suffix likely indicates modifications or adaptations for Android.
* **Purpose:** The file defines constants, structures, and enums related to IPVS. IPVS is a kernel-level load balancer. Therefore, this header provides the interface for user-space programs to configure and monitor the IPVS kernel module.
* **"auto-generated":** This is a crucial piece of information. It means we're looking at a generated output, likely from a more abstract definition or a kernel header. Modifications here will be lost. This also suggests we should be careful about making assumptions based on the specific naming conventions, as they might be influenced by the generation process.

**2. Deconstructing the Content (Top-Down):**

* **Header Guards (`#ifndef _IP_VS_H`):** Standard practice to prevent multiple inclusions. No specific IPVS function here.
* **Includes (`#include <linux/types.h>`):**  This means IPVS relies on fundamental Linux data types like `__u16`, `__be32`, etc. This confirms its kernel-level nature.
* **Versioning (`IP_VS_VERSION_CODE`, `NVERSION`):** This is important for compatibility. User-space programs can check the kernel's IPVS version.
* **Service Flags (`IP_VS_SVC_F_*`):** These constants define various options for configuring virtual services (e.g., persistence, hashing, scheduling). These are the *verbs* for controlling IPVS behavior.
* **Destination Flags (`IP_VS_DEST_F_*`):**  Similar to service flags, but specific to backend servers (destinations).
* **State (`IP_VS_STATE_*`):** Relates to high-availability configurations (master/backup).
* **Socket Options (`IP_VS_BASE_CTL`, `IP_VS_SO_SET_*`, `IP_VS_SO_GET_*`):** This is the primary mechanism for user-space interaction. These constants define the `setsockopt` and `getsockopt` level options used to manage IPVS. The `IP_VS_BASE_CTL` suggests a structured approach to defining these options.
* **Connection Flags (`IP_VS_CONN_F_*`):**  These flags describe the characteristics of individual connections handled by IPVS (e.g., forwarding method, tunneling, synchronization).
* **Maximum Lengths (`IP_VS_SCHEDNAME_MAXLEN`, etc.):** Defines buffer sizes for string-based configuration parameters.
* **Tunneling Enum (`enum { IP_VS_CONN_F_TUNNEL_TYPE_* }`):**  Specifies different tunneling protocols used by IPVS.
* **Tunneling Flags (`IP_VS_TUNNEL_ENCAP_FLAG_*`):**  Options for tunneling encapsulation.
* **Structures (`struct ip_vs_service_user`, `struct ip_vs_dest_user`, etc.):**  These are the data structures used to pass information between user-space and the kernel via the socket options. They define the format for configuration and status retrieval.
* **Generic Netlink (`IPVS_GENL_NAME`, `IPVS_GENL_VERSION`, `enum IPVS_CMD_*`, `enum IPVS_CMD_ATTR_*`, etc.):**  This signals that IPVS also uses the newer Generic Netlink interface for control and monitoring. This is a more modern and flexible approach than just socket options. The enums define the commands and attributes for this interface.

**3. Identifying Key Functionality and Connections to Android:**

* **Load Balancing:** The core function is clearly load balancing for network traffic.
* **Android Relevance:**  Android devices, especially server-side components or those involved in network infrastructure, might utilize IPVS for managing incoming connections across multiple backend servers. This improves scalability and resilience.
* **Framework/NDK Interaction:**  Android framework or NDK applications wouldn't directly use this header. Instead, they would interact with higher-level APIs (likely through system calls interacting with netlink or socket options) that eventually translate into operations defined by these structures and constants.

**4. Addressing Specific Questions in the Prompt:**

* **Function Listing:** Summarize the core functionalities based on the defined constants and structures (managing services, destinations, timeouts, daemons, getting statistics).
* **Android Examples:**  Think of scenarios where load balancing is relevant on Android (although direct usage is less common in typical mobile apps). Emphasize the role in Android's underlying infrastructure.
* **libc Function Implementation:**  The header *defines* interfaces, not implements them. The *implementation* resides in the Linux kernel. Focus on *how* these definitions are *used* by libc (via system calls like `setsockopt`, `getsockopt`, and potentially netlink functions).
* **Dynamic Linker:** This header file is a header file. It doesn't directly involve the dynamic linker. However, user-space tools interacting with IPVS would be linked against libc. Provide a basic example of a user-space program and its dependencies.
* **Logic Reasoning:**  Where configuration or behavior is determined by flags or values, illustrate with hypothetical inputs and outputs.
* **Common Errors:** Focus on incorrect usage of socket options, incorrect data structure packing, or misunderstanding the semantics of the flags.
* **Framework/NDK to IPVS:** Describe the layered architecture, starting from the Android framework, going down to native code (NDK), then system calls, and finally reaching the kernel's IPVS module.
* **Frida Hooking:** Demonstrate hooking at the system call level (e.g., `setsockopt`) to intercept IPVS interactions. This shows how to observe the data being passed to the kernel based on these header definitions.

**5. Refinement and Structuring the Answer:**

* **Organize the answer logically:** Start with a general overview, then detail specific functionalities, address the Android connection, and finally cover the more technical aspects (libc, dynamic linker, debugging).
* **Use clear and concise language:** Avoid jargon where possible or explain it clearly.
* **Provide concrete examples:**  Illustrate abstract concepts with practical scenarios.
* **Address all parts of the prompt:** Ensure each question is answered thoroughly.

By following this structured approach, we can systematically analyze the header file, understand its purpose, and provide a comprehensive and accurate response to the prompt. The key is to move from the general context to the specific details, and then connect those details back to the broader Android ecosystem.
这个头文件 `ip_vs.h` 定义了用户空间程序与 Linux 内核中 IP Virtual Server (IPVS) 子系统交互的接口。IPVS 实现了传输层的负载均衡，也称为四层交换。它允许将客户端的请求转发到多个后端服务器，从而提高服务的可用性和可扩展性。

**主要功能:**

1. **定义 IPVS 版本信息:**
   - `IP_VS_VERSION_CODE`:  定义了 IPVS 的版本号 (0x010201)。
   - `NVERSION(version)`:  一个宏，用于从版本号中提取主要、次要和修订版本号。

2. **定义虚拟服务 (Service) 的标志位:**
   - `IP_VS_SVC_F_PERSISTENT`:  表示服务具有持久连接的特性，客户端的连接会被路由到同一个后端服务器一段时间。
   - `IP_VS_SVC_F_HASHED`:  表示服务使用哈希算法来选择后端服务器。
   - `IP_VS_SVC_F_ONEPACKET`:  表示服务只处理第一个数据包，后续的包直接转发到选定的后端服务器。
   - `IP_VS_SVC_F_SCHED1`, `IP_VS_SVC_F_SCHED2`, `IP_VS_SVC_F_SCHED3`:  表示不同的调度器类型 (例如，源地址哈希，源端口哈希)。

3. **定义后端服务器 (Destination) 的标志位:**
   - `IP_VS_DEST_F_AVAILABLE`:  表示后端服务器可用。
   - `IP_VS_DEST_F_OVERLOAD`:  表示后端服务器过载。

4. **定义同步状态:**
   - `IP_VS_STATE_NONE`:  没有同步。
   - `IP_VS_STATE_MASTER`:  主节点。
   - `IP_VS_STATE_BACKUP`:  备份节点。

5. **定义用于 `setsockopt` 和 `getsockopt` 的 socket 选项:**
   - `IP_VS_BASE_CTL`:  定义了 IPVS 控制操作的基地址。
   - `IP_VS_SO_SET_*`:  定义了用于设置 IPVS 配置的 socket 选项，例如添加、删除、编辑服务和后端服务器，设置超时时间，启动/停止守护进程等。
   - `IP_VS_SO_GET_*`:  定义了用于获取 IPVS 信息的 socket 选项，例如获取版本、基本信息、服务列表、指定服务的信息、后端服务器列表、指定后端服务器的信息、超时时间、守护进程状态等。

6. **定义连接 (Connection) 的标志位:**
   - `IP_VS_CONN_F_FWD_MASK`:  转发方法的掩码。
   - `IP_VS_CONN_F_MASQ`:  表示使用 NAT (网络地址转换) 进行转发。
   - `IP_VS_CONN_F_LOCALNODE`:  表示转发到本地节点。
   - `IP_VS_CONN_F_TUNNEL`:  表示使用隧道进行转发。
   - `IP_VS_CONN_F_DROUTE`:  表示使用直接路由进行转发。
   - 其他标志位表示连接的同步状态、哈希状态、序列号等。

7. **定义名称的最大长度:**
   - `IP_VS_SCHEDNAME_MAXLEN`:  调度器名称的最大长度。
   - `IP_VS_PENAME_MAXLEN`:  持久化引擎名称的最大长度。
   - `IP_VS_IFNAME_MAXLEN`:  接口名称的最大长度。
   - `IP_VS_PEDATA_MAXLEN`:  持久化引擎数据的最大长度。

8. **定义隧道类型枚举:**
   - `IP_VS_CONN_F_TUNNEL_TYPE_IPIP`, `IP_VS_CONN_F_TUNNEL_TYPE_GUE`, `IP_VS_CONN_F_TUNNEL_TYPE_GRE`: 定义了不同的隧道协议类型。

9. **定义隧道封装标志位:**
   - `IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM`, `IP_VS_TUNNEL_ENCAP_FLAG_CSUM`, `IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM`: 定义了隧道封装的校验和选项。

10. **定义用于与 IPVS 通信的数据结构:**
    - `ip_vs_service_user`:  用于设置或获取虚拟服务信息的结构体。
    - `ip_vs_dest_user`:  用于设置或获取后端服务器信息的结构体。
    - `ip_vs_stats_user`:  用于获取统计信息的结构体。
    - `ip_vs_getinfo`:  用于获取 IPVS 基本信息的结构体。
    - `ip_vs_service_entry`:  包含虚拟服务完整信息的结构体。
    - `ip_vs_dest_entry`:  包含后端服务器完整信息的结构体。
    - `ip_vs_get_dests`:  用于获取指定虚拟服务的后端服务器列表的结构体。
    - `ip_vs_get_services`:  用于获取所有虚拟服务列表的结构体。
    - `ip_vs_timeout_user`:  用于设置或获取超时时间的结构体。
    - `ip_vs_daemon_user`:  用于设置或获取同步守护进程信息的结构体。

11. **定义 Generic Netlink 相关的常量和枚举:**
    - `IPVS_GENL_NAME`:  Generic Netlink 族名称 ("IPVS")。
    - `IPVS_GENL_VERSION`:  Generic Netlink 版本号。
    - `ip_vs_flags`:  用于设置或获取标志位的结构体。
    - `enum IPVS_CMD_*`:  定义了用于 Generic Netlink 的命令，例如创建、设置、删除、获取服务和后端服务器，设置和获取配置信息等。
    - `enum IPVS_CMD_ATTR_*`:  定义了 Generic Netlink 命令的属性，例如服务、后端服务器、守护进程、超时时间等。
    - `enum IPVS_SVC_ATTR_*`, `enum IPVS_DEST_ATTR_*`, `enum IPVS_DAEMON_ATTR_*`, `enum IPVS_STATS_ATTR_*`, `enum IPVS_INFO_ATTR_*`: 定义了与不同实体相关的属性，例如地址、端口、权重、状态、统计信息等。

**与 Android 功能的关系举例说明:**

虽然普通 Android 应用程序不太可能直接使用这些 IPVS 的接口，但它可能在 Android 系统的一些底层网络基础设施中使用。例如：

* **Android 热点 (Tethering):** 当 Android 设备充当热点时，它可能在内部使用类似 IPVS 的机制来管理连接和路由数据包到连接的客户端。虽然不一定直接使用 IPVS 内核模块，但相关的负载均衡和连接管理概念是相似的。
* **Android 容器化或虚拟化环境:** 在一些更复杂的 Android 使用场景中，例如运行在服务器上的 Android 实例，可能需要负载均衡来分配流量到不同的容器或虚拟机。IPVS 在这种情况下可能被用到。
* **运营商级的 Android 服务:** 一些运营商可能会在其网络基础设施中使用 IPVS 或类似技术来管理流向 Android 设备的流量。

**libc 函数的功能实现 (针对此头文件):**

这个头文件本身**并没有实现任何 libc 函数**。它只是一个头文件，用于提供常量、宏、枚举和数据结构的定义。用户空间的程序会包含这个头文件，然后使用标准的 libc 函数，例如 `socket()`, `setsockopt()`, `getsockopt()`, 以及可能用于 Generic Netlink 通信的函数 (例如 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)`, `sendto()`, `recvfrom()`) 来与 IPVS 内核模块进行交互。

* **`setsockopt()` 和 `getsockopt()`:** 这些是关键的 libc 函数，用于配置和获取 IPVS 的状态。程序会创建一个 socket，然后使用 `setsockopt()` 结合 `IP_VS_SO_SET_*` 常量来设置 IPVS 的参数，使用 `getsockopt()` 结合 `IP_VS_SO_GET_*` 常量来获取 IPVS 的信息。

   **例如，添加一个虚拟服务:**

   ```c
   #include <sys/socket.h>
   #include <linux/ip_vs.h>
   #include <stdio.h>
   #include <stdlib.h>
   #include <string.h>
   #include <arpa/inet.h>

   int main() {
       int sock = socket(AF_INET, SOCK_DGRAM, 0); // IPVS 通常与 UDP 或 TCP 一起使用
       if (sock < 0) {
           perror("socket");
           return 1;
       }

       struct ip_vs_service_user svc;
       memset(&svc, 0, sizeof(svc));
       svc.protocol = IPPROTO_TCP;
       inet_pton(AF_INET, "192.168.1.100", &svc.addr);
       svc.port = htons(80);
       strncpy(svc.sched_name, "rr", sizeof(svc.sched_name) - 1); // 使用轮询调度

       if (setsockopt(sock, SOL_IPVS, IP_VS_SO_SET_ADD, &svc, sizeof(svc)) < 0) {
           perror("setsockopt IP_VS_SO_SET_ADD");
           close(sock);
           return 1;
       }

       printf("Successfully added IPVS service.\n");
       close(sock);
       return 0;
   }
   ```

* **Generic Netlink 函数:**  如果程序使用 Generic Netlink 与 IPVS 通信，它会使用 `socket()` 创建 Netlink socket，并使用 `sendto()` 和 `recvfrom()` 发送和接收包含特定 Netlink 消息的包。这些消息的结构会根据 `IPVS_GENL_NAME`, `IPVS_CMD_*` 和 `IPVS_SVC_ATTR_*` 等常量来构建。

**涉及 dynamic linker 的功能:**

这个头文件本身不直接涉及 dynamic linker 的功能。但是，任何使用此头文件的用户空间程序都需要链接到 libc 库。

**so 布局样本:**

假设我们有一个名为 `ipvs_tool` 的可执行文件，它使用了 `ip_vs.h` 中定义的接口。它的依赖关系可能如下：

```
ipvs_tool:
    NEEDED libc.so
```

**链接的处理过程:**

1. **编译:** 当编译 `ipvs_tool.c` 时，编译器会识别出对标准 libc 函数的调用 (例如 `socket`, `setsockopt`)。
2. **链接:** 链接器在链接 `ipvs_tool.o` 和其他必要的库时，会解析这些符号。由于使用了 libc 函数，链接器会将 `libc.so` 标记为 `ipvs_tool` 的依赖。
3. **加载:** 当 `ipvs_tool` 运行时，操作系统会加载 `ipvs_tool` 到内存中。动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会检查 `ipvs_tool` 的 `NEEDED` 条目，并加载 `libc.so` 到内存中。
4. **符号解析:** 动态链接器会将 `ipvs_tool` 中对 libc 函数的未定义引用 (例如 `socket`, `setsockopt`) 与 `libc.so` 中相应的函数实现进行绑定。

**假设输入与输出 (逻辑推理示例):**

假设我们使用以下代码来获取 IPVS 版本信息：

```c
#include <sys/socket.h>
#include <linux/ip_vs.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    unsigned int version;
    socklen_t version_len = sizeof(version);

    if (getsockopt(sock, SOL_IPVS, IP_VS_SO_GET_VERSION, &version, &version_len) < 0) {
        perror("getsockopt IP_VS_SO_GET_VERSION");
        close(sock);
        return 1;
    }

    printf("IPVS Version Code: 0x%08X\n", version);
    printf("IPVS Version: %d.%d.%d\n", NVERSION(version));

    close(sock);
    return 0;
}
```

**假设输入:** 运行该程序，并且 Linux 内核中 IPVS 模块的版本为 1.2.1。

**预期输出:**

```
IPVS Version Code: 0x010201
IPVS Version: 1.2.1
```

**用户或编程常见的使用错误:**

1. **忘记包含必要的头文件:** 如果没有包含 `<linux/ip_vs.h>`，编译器将无法识别 IPVS 相关的常量和结构体定义。
2. **socket 选项使用错误:** 使用了错误的 `SOL_IPVS` 参数或错误的 `IP_VS_SO_SET_*` / `IP_VS_SO_GET_*` 常量。
3. **数据结构填充错误:**  在设置 IPVS 配置时，没有正确填充 `ip_vs_service_user` 或 `ip_vs_dest_user` 等结构体的字段，例如字节序错误 (`htons`, `htonl`)，地址格式错误等。
4. **权限不足:**  修改 IPVS 配置通常需要 root 权限。普通用户尝试执行相关操作可能会失败并返回权限错误。
5. **内核模块未加载:** 如果 IPVS 内核模块没有加载，相关的 socket 选项调用将会失败。
6. **Generic Netlink 消息构建错误:** 如果使用 Generic Netlink，构建 Netlink 消息时可能出现错误，例如错误的头部信息、属性编码错误等。

**Android framework or ndk 如何一步步的到达这里:**

通常，Android Framework 或 NDK 应用**不会直接**调用 IPVS 相关的 socket 选项。相反，它们会使用更高层次的抽象接口。

一个可能的路径 (虽然不太常见直接使用 IPVS):

1. **Android Framework (Java/Kotlin):**  Framework 层级的代码可能调用 Android 系统服务来执行网络配置或管理任务。
2. **System Server (C++):** 某些系统服务 (例如 `NetworkManagementService`)  可能会处理这些请求，并调用底层的 native 代码。
3. **Native Code (C/C++ in NDK or platform code):**  在 native 代码中，可能会使用标准的 C 库函数 (libc) 来与内核交互。
4. **System Calls:**  Native 代码最终会通过系统调用 (例如 `socket`, `setsockopt`, `getsockopt`) 来与内核进行通信。
5. **IPVS Kernel Module:**  当调用涉及到 IPVS 相关的 socket 选项时，Linux 内核会识别这些调用，并将它们路由到 IPVS 内核模块进行处理。

**Frida hook 示例调试这些步骤:**

由于 Framework 通常不会直接调用 IPVS socket 选项，我们假设有一个使用 NDK 的应用或一个平台级别的守护进程可能进行这样的操作。我们可以 hook `setsockopt` 系统调用来观察是否传递了 IPVS 相关的参数。

```python
import frida
import sys

# 要 hook 的系统调用
syscall_name = "setsockopt"

# IPVS 相关的 SOL 和选项 (这是一个简化的示例，可能需要根据具体情况调整)
SOL_IPVS = 276  # 实际值可能需要通过内核头文件或调试获取
IP_VS_SO_SET_ADD = 64 + 1024 + 64 + 1  #  IP_VS_BASE_CTL + 1

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process_name or pid>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    const setsockoptPtr = Module.getExportByName(null, "setsockopt");

    Interceptor.attach(setsockoptPtr, {
        onEnter: function(args) {
            const sockfd = args[0].toInt32();
            const level = args[1].toInt32();
            const optname = args[2].toInt32();

            if (level === %d) {
                console.log("[*] setsockopt called with SOL_IPVS");
                if (optname === %d) {
                    console.log("[*] Attempting to add IPVS service (IP_VS_SO_SET_ADD)");
                    // 可以进一步解析 optval (args[3]) 的内容，但这需要知道具体的结构体布局
                } else {
                    console.log("[*] setsockopt optname:", optname);
                }
                console.log("[*] Socket FD:", sockfd);
            }
        },
        onLeave: function(retval) {
            // console.log("[*] setsockopt returned:", retval);
        }
    });
    """ % (SOL_IPVS, IP_VS_SO_SET_ADD)

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print(f"[*] Hooking 'setsockopt' in process '{target}'. Press Ctrl+C to stop...")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("[*] Stopping script...")
        session.detach()

if __name__ == '__main__':
    main()
```

**使用说明:**

1. 将上述 Python 代码保存为 `frida_hook_ipvs.py`。
2. 替换 `SOL_IPVS` 和 `IP_VS_SO_SET_ADD` 为实际的值 (可以通过查看内核源代码或使用其他调试方法获取)。
3. 运行 Frida hook 脚本，指定要监控的进程名称或 PID：
   ```bash
   python frida_hook_ipvs.py <process_name or pid>
   ```
4. 如果目标进程调用了 `setsockopt` 并且 `level` 参数是 `SOL_IPVS`，并且 `optname` 是 `IP_VS_SO_SET_ADD`，Frida 将会打印相关信息。

这个 Frida 示例提供了一个基本的框架。要更详细地分析传递给 `setsockopt` 的数据 (例如 `optval`)，你需要了解 `ip_vs_service_user` 或其他相关结构体的内存布局，并在 Frida 脚本中使用 `Memory.read*` 函数来读取和解析这些数据。

请注意，直接在 Android Framework 进程上 hook 系统调用可能需要 root 权限，并且可能会影响系统的稳定性。在进行此类调试时请谨慎。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/ip_vs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _IP_VS_H
#define _IP_VS_H
#include <linux/types.h>
#define IP_VS_VERSION_CODE 0x010201
#define NVERSION(version) (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF
#define IP_VS_SVC_F_PERSISTENT 0x0001
#define IP_VS_SVC_F_HASHED 0x0002
#define IP_VS_SVC_F_ONEPACKET 0x0004
#define IP_VS_SVC_F_SCHED1 0x0008
#define IP_VS_SVC_F_SCHED2 0x0010
#define IP_VS_SVC_F_SCHED3 0x0020
#define IP_VS_SVC_F_SCHED_SH_FALLBACK IP_VS_SVC_F_SCHED1
#define IP_VS_SVC_F_SCHED_SH_PORT IP_VS_SVC_F_SCHED2
#define IP_VS_DEST_F_AVAILABLE 0x0001
#define IP_VS_DEST_F_OVERLOAD 0x0002
#define IP_VS_STATE_NONE 0x0000
#define IP_VS_STATE_MASTER 0x0001
#define IP_VS_STATE_BACKUP 0x0002
#define IP_VS_BASE_CTL (64 + 1024 + 64)
#define IP_VS_SO_SET_NONE IP_VS_BASE_CTL
#define IP_VS_SO_SET_INSERT (IP_VS_BASE_CTL + 1)
#define IP_VS_SO_SET_ADD (IP_VS_BASE_CTL + 2)
#define IP_VS_SO_SET_EDIT (IP_VS_BASE_CTL + 3)
#define IP_VS_SO_SET_DEL (IP_VS_BASE_CTL + 4)
#define IP_VS_SO_SET_FLUSH (IP_VS_BASE_CTL + 5)
#define IP_VS_SO_SET_LIST (IP_VS_BASE_CTL + 6)
#define IP_VS_SO_SET_ADDDEST (IP_VS_BASE_CTL + 7)
#define IP_VS_SO_SET_DELDEST (IP_VS_BASE_CTL + 8)
#define IP_VS_SO_SET_EDITDEST (IP_VS_BASE_CTL + 9)
#define IP_VS_SO_SET_TIMEOUT (IP_VS_BASE_CTL + 10)
#define IP_VS_SO_SET_STARTDAEMON (IP_VS_BASE_CTL + 11)
#define IP_VS_SO_SET_STOPDAEMON (IP_VS_BASE_CTL + 12)
#define IP_VS_SO_SET_RESTORE (IP_VS_BASE_CTL + 13)
#define IP_VS_SO_SET_SAVE (IP_VS_BASE_CTL + 14)
#define IP_VS_SO_SET_ZERO (IP_VS_BASE_CTL + 15)
#define IP_VS_SO_SET_MAX IP_VS_SO_SET_ZERO
#define IP_VS_SO_GET_VERSION IP_VS_BASE_CTL
#define IP_VS_SO_GET_INFO (IP_VS_BASE_CTL + 1)
#define IP_VS_SO_GET_SERVICES (IP_VS_BASE_CTL + 2)
#define IP_VS_SO_GET_SERVICE (IP_VS_BASE_CTL + 3)
#define IP_VS_SO_GET_DESTS (IP_VS_BASE_CTL + 4)
#define IP_VS_SO_GET_DEST (IP_VS_BASE_CTL + 5)
#define IP_VS_SO_GET_TIMEOUT (IP_VS_BASE_CTL + 6)
#define IP_VS_SO_GET_DAEMON (IP_VS_BASE_CTL + 7)
#define IP_VS_SO_GET_MAX IP_VS_SO_GET_DAEMON
#define IP_VS_CONN_F_FWD_MASK 0x0007
#define IP_VS_CONN_F_MASQ 0x0000
#define IP_VS_CONN_F_LOCALNODE 0x0001
#define IP_VS_CONN_F_TUNNEL 0x0002
#define IP_VS_CONN_F_DROUTE 0x0003
#define IP_VS_CONN_F_BYPASS 0x0004
#define IP_VS_CONN_F_SYNC 0x0020
#define IP_VS_CONN_F_HASHED 0x0040
#define IP_VS_CONN_F_NOOUTPUT 0x0080
#define IP_VS_CONN_F_INACTIVE 0x0100
#define IP_VS_CONN_F_OUT_SEQ 0x0200
#define IP_VS_CONN_F_IN_SEQ 0x0400
#define IP_VS_CONN_F_SEQ_MASK 0x0600
#define IP_VS_CONN_F_NO_CPORT 0x0800
#define IP_VS_CONN_F_TEMPLATE 0x1000
#define IP_VS_CONN_F_ONE_PACKET 0x2000
#define IP_VS_CONN_F_BACKUP_MASK (IP_VS_CONN_F_FWD_MASK | IP_VS_CONN_F_NOOUTPUT | IP_VS_CONN_F_INACTIVE | IP_VS_CONN_F_SEQ_MASK | IP_VS_CONN_F_NO_CPORT | IP_VS_CONN_F_TEMPLATE)
#define IP_VS_CONN_F_BACKUP_UPD_MASK (IP_VS_CONN_F_INACTIVE | IP_VS_CONN_F_SEQ_MASK)
#define IP_VS_CONN_F_NFCT (1 << 16)
#define IP_VS_CONN_F_DEST_MASK (IP_VS_CONN_F_FWD_MASK | IP_VS_CONN_F_ONE_PACKET | IP_VS_CONN_F_NFCT | 0)
#define IP_VS_SCHEDNAME_MAXLEN 16
#define IP_VS_PENAME_MAXLEN 16
#define IP_VS_IFNAME_MAXLEN 16
#define IP_VS_PEDATA_MAXLEN 255
enum {
  IP_VS_CONN_F_TUNNEL_TYPE_IPIP = 0,
  IP_VS_CONN_F_TUNNEL_TYPE_GUE,
  IP_VS_CONN_F_TUNNEL_TYPE_GRE,
  IP_VS_CONN_F_TUNNEL_TYPE_MAX,
};
#define IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM (0)
#define IP_VS_TUNNEL_ENCAP_FLAG_CSUM (1 << 0)
#define IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM (1 << 1)
struct ip_vs_service_user {
  __u16 protocol;
  __be32 addr;
  __be16 port;
  __u32 fwmark;
  char sched_name[IP_VS_SCHEDNAME_MAXLEN];
  unsigned int flags;
  unsigned int timeout;
  __be32 netmask;
};
struct ip_vs_dest_user {
  __be32 addr;
  __be16 port;
  unsigned int conn_flags;
  int weight;
  __u32 u_threshold;
  __u32 l_threshold;
};
struct ip_vs_stats_user {
  __u32 conns;
  __u32 inpkts;
  __u32 outpkts;
  __u64 inbytes;
  __u64 outbytes;
  __u32 cps;
  __u32 inpps;
  __u32 outpps;
  __u32 inbps;
  __u32 outbps;
};
struct ip_vs_getinfo {
  unsigned int version;
  unsigned int size;
  unsigned int num_services;
};
struct ip_vs_service_entry {
  __u16 protocol;
  __be32 addr;
  __be16 port;
  __u32 fwmark;
  char sched_name[IP_VS_SCHEDNAME_MAXLEN];
  unsigned int flags;
  unsigned int timeout;
  __be32 netmask;
  unsigned int num_dests;
  struct ip_vs_stats_user stats;
};
struct ip_vs_dest_entry {
  __be32 addr;
  __be16 port;
  unsigned int conn_flags;
  int weight;
  __u32 u_threshold;
  __u32 l_threshold;
  __u32 activeconns;
  __u32 inactconns;
  __u32 persistconns;
  struct ip_vs_stats_user stats;
};
struct ip_vs_get_dests {
  __u16 protocol;
  __be32 addr;
  __be16 port;
  __u32 fwmark;
  unsigned int num_dests;
  struct ip_vs_dest_entry entrytable[];
};
struct ip_vs_get_services {
  unsigned int num_services;
  struct ip_vs_service_entry entrytable[];
};
struct ip_vs_timeout_user {
  int tcp_timeout;
  int tcp_fin_timeout;
  int udp_timeout;
};
struct ip_vs_daemon_user {
  int state;
  char mcast_ifn[IP_VS_IFNAME_MAXLEN];
  int syncid;
};
#define IPVS_GENL_NAME "IPVS"
#define IPVS_GENL_VERSION 0x1
struct ip_vs_flags {
  __u32 flags;
  __u32 mask;
};
enum {
  IPVS_CMD_UNSPEC = 0,
  IPVS_CMD_NEW_SERVICE,
  IPVS_CMD_SET_SERVICE,
  IPVS_CMD_DEL_SERVICE,
  IPVS_CMD_GET_SERVICE,
  IPVS_CMD_NEW_DEST,
  IPVS_CMD_SET_DEST,
  IPVS_CMD_DEL_DEST,
  IPVS_CMD_GET_DEST,
  IPVS_CMD_NEW_DAEMON,
  IPVS_CMD_DEL_DAEMON,
  IPVS_CMD_GET_DAEMON,
  IPVS_CMD_SET_CONFIG,
  IPVS_CMD_GET_CONFIG,
  IPVS_CMD_SET_INFO,
  IPVS_CMD_GET_INFO,
  IPVS_CMD_ZERO,
  IPVS_CMD_FLUSH,
  __IPVS_CMD_MAX,
};
#define IPVS_CMD_MAX (__IPVS_CMD_MAX - 1)
enum {
  IPVS_CMD_ATTR_UNSPEC = 0,
  IPVS_CMD_ATTR_SERVICE,
  IPVS_CMD_ATTR_DEST,
  IPVS_CMD_ATTR_DAEMON,
  IPVS_CMD_ATTR_TIMEOUT_TCP,
  IPVS_CMD_ATTR_TIMEOUT_TCP_FIN,
  IPVS_CMD_ATTR_TIMEOUT_UDP,
  __IPVS_CMD_ATTR_MAX,
};
#define IPVS_CMD_ATTR_MAX (__IPVS_CMD_ATTR_MAX - 1)
enum {
  IPVS_SVC_ATTR_UNSPEC = 0,
  IPVS_SVC_ATTR_AF,
  IPVS_SVC_ATTR_PROTOCOL,
  IPVS_SVC_ATTR_ADDR,
  IPVS_SVC_ATTR_PORT,
  IPVS_SVC_ATTR_FWMARK,
  IPVS_SVC_ATTR_SCHED_NAME,
  IPVS_SVC_ATTR_FLAGS,
  IPVS_SVC_ATTR_TIMEOUT,
  IPVS_SVC_ATTR_NETMASK,
  IPVS_SVC_ATTR_STATS,
  IPVS_SVC_ATTR_PE_NAME,
  IPVS_SVC_ATTR_STATS64,
  __IPVS_SVC_ATTR_MAX,
};
#define IPVS_SVC_ATTR_MAX (__IPVS_SVC_ATTR_MAX - 1)
enum {
  IPVS_DEST_ATTR_UNSPEC = 0,
  IPVS_DEST_ATTR_ADDR,
  IPVS_DEST_ATTR_PORT,
  IPVS_DEST_ATTR_FWD_METHOD,
  IPVS_DEST_ATTR_WEIGHT,
  IPVS_DEST_ATTR_U_THRESH,
  IPVS_DEST_ATTR_L_THRESH,
  IPVS_DEST_ATTR_ACTIVE_CONNS,
  IPVS_DEST_ATTR_INACT_CONNS,
  IPVS_DEST_ATTR_PERSIST_CONNS,
  IPVS_DEST_ATTR_STATS,
  IPVS_DEST_ATTR_ADDR_FAMILY,
  IPVS_DEST_ATTR_STATS64,
  IPVS_DEST_ATTR_TUN_TYPE,
  IPVS_DEST_ATTR_TUN_PORT,
  IPVS_DEST_ATTR_TUN_FLAGS,
  __IPVS_DEST_ATTR_MAX,
};
#define IPVS_DEST_ATTR_MAX (__IPVS_DEST_ATTR_MAX - 1)
enum {
  IPVS_DAEMON_ATTR_UNSPEC = 0,
  IPVS_DAEMON_ATTR_STATE,
  IPVS_DAEMON_ATTR_MCAST_IFN,
  IPVS_DAEMON_ATTR_SYNC_ID,
  IPVS_DAEMON_ATTR_SYNC_MAXLEN,
  IPVS_DAEMON_ATTR_MCAST_GROUP,
  IPVS_DAEMON_ATTR_MCAST_GROUP6,
  IPVS_DAEMON_ATTR_MCAST_PORT,
  IPVS_DAEMON_ATTR_MCAST_TTL,
  __IPVS_DAEMON_ATTR_MAX,
};
#define IPVS_DAEMON_ATTR_MAX (__IPVS_DAEMON_ATTR_MAX - 1)
enum {
  IPVS_STATS_ATTR_UNSPEC = 0,
  IPVS_STATS_ATTR_CONNS,
  IPVS_STATS_ATTR_INPKTS,
  IPVS_STATS_ATTR_OUTPKTS,
  IPVS_STATS_ATTR_INBYTES,
  IPVS_STATS_ATTR_OUTBYTES,
  IPVS_STATS_ATTR_CPS,
  IPVS_STATS_ATTR_INPPS,
  IPVS_STATS_ATTR_OUTPPS,
  IPVS_STATS_ATTR_INBPS,
  IPVS_STATS_ATTR_OUTBPS,
  IPVS_STATS_ATTR_PAD,
  __IPVS_STATS_ATTR_MAX,
};
#define IPVS_STATS_ATTR_MAX (__IPVS_STATS_ATTR_MAX - 1)
enum {
  IPVS_INFO_ATTR_UNSPEC = 0,
  IPVS_INFO_ATTR_VERSION,
  IPVS_INFO_ATTR_CONN_TAB_SIZE,
  __IPVS_INFO_ATTR_MAX,
};
#define IPVS_INFO_ATTR_MAX (__IPVS_INFO_ATTR_MAX - 1)
#endif

"""

```