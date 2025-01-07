Response:
Let's break down the thought process for answering the request about `inet_netof.c`.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of a specific C source file (`inet_netof.c`) from Android's Bionic libc. The key aspects to address are:

* Functionality: What does the code do?
* Android Relevance: How is this used in Android?
* Implementation Details: How does each libc function work?
* Dynamic Linking: If applicable, how does this relate to the dynamic linker?
* Logic and Examples: Provide examples of input/output.
* Common Errors: What mistakes do developers make when using this?
* Android Integration: How does the code get called from higher levels (Framework/NDK)?
* Debugging: Show a Frida hook example.

**2. Initial Code Analysis (Static Analysis):**

* **Includes:** The code includes `<netinet/in.h>` and `<arpa/inet.h>`. This immediately tells us it's dealing with network addresses, specifically IPv4.
* **Function Signature:** `in_addr_t inet_netof(struct in_addr in)`. This indicates the function takes an `in_addr` structure (representing an IPv4 address) and returns an `in_addr_t` (an unsigned 32-bit integer, likely the network number).
* **Core Logic:** The function uses bitwise operations (`&`, `>>`) and preprocessor macros (`IN_CLASSA`, `IN_CLASSB`, `IN_CLASSC`, `IN_CLASSA_NET`, etc.). This strongly suggests it's implementing the traditional IPv4 classful addressing scheme.
* **`ntohl`:** The first operation is `ntohl(in.s_addr)`. This converts the network byte order to host byte order, a crucial step when working with network data.

**3. Deeper Dive into Functionality and Implementation:**

* **IPv4 Classful Addressing:**  The `if/else if/else` structure and the class-specific macros confirm that the function extracts the network part based on the first few bits of the IP address according to the old Class A, B, and C scheme.
* **`ntohl` Explanation:** It's crucial to explain *why* `ntohl` is needed – network byte order (big-endian) vs. host byte order.
* **Macro Definitions:** Briefly explaining what the `IN_CLASSA`, `IN_CLASSB`, `IN_CLASSC`, `IN_CLASSA_NET`, `IN_CLASSB_NET`, `IN_CLASSC_NET`, `IN_CLASSA_NSHIFT`, `IN_CLASSB_NSHIFT`, and `IN_CLASSC_NSHIFT` macros do is important for clarity. Even though the code is simple, understanding the underlying concepts is key.

**4. Android Relevance and Examples:**

* **Core Networking:** Explain that this function is fundamental for network operations within Android.
* **Use Cases:**  Think about concrete examples: routing, network configuration, etc. Mention scenarios where identifying the network part of an IP address is necessary.
* **Illustrative Example:** Create a clear input/output example showing how `inet_netof` works for different IP addresses and network classes.

**5. Dynamic Linking (Careful Consideration):**

* **Is it directly involved?**  `inet_netof` itself doesn't directly interact with the dynamic linker. It's a static function within libc.
* **Indirect Relationship:** However, *libc as a whole* is a dynamically linked library. Therefore, the *concept* of dynamic linking is relevant.
* **SO Layout (General):** Provide a generic example of an SO layout (code, data, GOT, PLT). Explain these sections in the context of dynamic linking.
* **Linking Process (Simplified):** Briefly describe the steps involved in resolving symbols at runtime.
* **Distinguish:** Emphasize that while `inet_netof` is *in* a dynamically linked library, its *internal implementation* doesn't directly perform dynamic linking operations.

**6. Common Errors:**

* **Byte Order Issues (Without `ntohl`):** This is the most likely error. Explain why not using `ntohl` leads to incorrect results.
* **Misunderstanding Classful Addressing:**  Briefly mention that this function is based on an older addressing scheme and might not be suitable for all modern networking scenarios (though it's still present for compatibility).

**7. Android Framework/NDK Integration:**

* **Tracing the Call Path:** Think about how a high-level Android application might ultimately trigger a call to `inet_netof`. Start with a general networking operation (e.g., creating a socket, connecting to a host).
* **Framework Layers:** Describe the journey from the Android Framework (Java/Kotlin) through the JNI to the NDK and finally to libc.
* **Concrete API Examples:**  Mention relevant Android APIs (e.g., `java.net.InetAddress`, `NetworkInterface`) and corresponding NDK functions (e.g., socket functions).

**8. Frida Hook Example:**

* **Target Function:** Specify the function to hook (`inet_netof`).
* **Hooking Logic:** Demonstrate how to intercept the function call, access arguments (the `in_addr` structure), and potentially log or modify the behavior.
* **Clear Output:** Show what the Frida script output would look like, displaying the input and output of the hooked function.

**9. Structure and Language:**

* **Clear Headings:** Use headings and subheadings to organize the information logically.
* **Concise Explanations:** Explain concepts clearly and avoid unnecessary jargon.
* **Code Formatting:** Format code snippets correctly for readability.
* **Chinese Language:** Ensure the entire response is in Chinese as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the low-level bit manipulation.
* **Correction:** Realize the importance of explaining the *why* behind these operations (e.g., network byte order) and connecting it to broader networking concepts.
* **Initial thought:** Overcomplicate the dynamic linking aspect.
* **Correction:**  Simplify the explanation to emphasize that while `inet_netof` doesn't directly *do* dynamic linking, it resides within a dynamically linked library, and explaining the general concepts is relevant.
* **Initial thought:** Provide a very technical explanation of the Android Framework layers.
* **Correction:**  Keep the explanation at a reasonably high level, focusing on the general path from the application to the native code.

By following this structured thought process and continually refining the explanations, it's possible to create a comprehensive and informative answer that addresses all aspects of the user's request.好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/net/inet_netof.c` 这个文件。

**功能概述**

`inet_netof` 函数的主要功能是从一个 IPv4 地址中提取出网络号。它基于传统的 IPv4 分类编址方案（Class A, B, C）。

**与 Android 功能的关系及举例**

尽管现代网络更多地使用无类别域间路由 (CIDR)，但理解和处理传统的分类网络地址仍然是底层网络操作的基础。在 Android 中，这个函数可能在以下场景中使用：

1. **网络配置和管理:** 当系统需要解析或显示网络配置信息时，可能会用到这个函数来识别给定 IP 地址所属的网络。
2. **路由表操作:**  路由表通常需要区分网络地址部分和主机地址部分。`inet_netof` 可以帮助确定目标 IP 地址的网络部分，以便查找合适的路由。
3. **防火墙规则和网络策略:** 防火墙和网络策略可能基于网络地址进行过滤和控制。
4. **历史遗留代码兼容性:** 某些旧的网络协议或应用程序可能仍然依赖于分类编址的概念。

**举例说明:**

假设一个 Android 设备的 IP 地址是 `192.168.1.100`。这个地址属于 Class C 网络。`inet_netof` 函数会提取出网络号 `192.168.1`。

**libc 函数的实现细节**

`inet_netof` 函数的实现非常简洁：

```c
in_addr_t
inet_netof(struct in_addr in)
{
	in_addr_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return (((i)&IN_CLASSA_NET) >> IN_CLASSA_NSHIFT);
	else if (IN_CLASSB(i))
		return (((i)&IN_CLASSB_NET) >> IN_CLASSB_NSHIFT);
	else
		return (((i)&IN_CLASSC_NET) >> IN_CLASSC_NSHIFT);
}
```

让我们逐行解释：

1. **`in_addr_t i = ntohl(in.s_addr);`**:
   - `in` 是一个 `struct in_addr` 类型的参数，它包含了需要提取网络号的 IPv4 地址。`in.s_addr` 是一个 32 位的整数，以网络字节序（大端序）存储 IP 地址。
   - `ntohl()` 是 "network to host long" 的缩写。它将网络字节序的 32 位整数转换为主机字节序。这是因为不同架构的计算机可能使用不同的字节序来存储多字节数据。网络协议通常使用大端序，因此需要转换成本地机器的字节序才能正确处理。

2. **`if (IN_CLASSA(i))`**:
   - `IN_CLASSA(i)` 是一个宏，用于判断 IP 地址 `i` 是否属于 A 类网络。A 类网络的特点是 IP 地址的第一个字节的前一位是 0。宏的定义通常如下：
     ```c
     #define	IN_CLASSA(i)	(((uint32_t)(i) & 0x80000000) == 0)
     ```
     这里 `0x80000000` 的二进制表示是 `10000000 00000000 00000000 00000000`。与 `i` 进行按位与运算，然后判断结果是否为 0，即判断最高位是否为 0。

3. **`return (((i)&IN_CLASSA_NET) >> IN_CLASSA_NSHIFT);`**:
   - 如果 IP 地址属于 A 类网络，则执行此行代码。
   - `IN_CLASSA_NET` 是一个宏，表示 A 类网络的网络号掩码。它的定义通常如下：
     ```c
     #define	IN_CLASSA_NET	0xff000000
     ```
     其二进制表示是 `11111111 00000000 00000000 00000000`。与 `i` 进行按位与运算，可以提取出 IP 地址中的网络号部分（前 8 位）。
   - `IN_CLASSA_NSHIFT` 是一个宏，表示 A 类网络网络号的位移量。它的定义通常如下：
     ```c
     #define	IN_CLASSA_NSHIFT	24
     ```
     将按位与的结果右移 24 位，可以将网络号移动到低 8 位，得到最终的网络号。

4. **`else if (IN_CLASSB(i))`**:
   - `IN_CLASSB(i)` 是一个宏，用于判断 IP 地址 `i` 是否属于 B 类网络。B 类网络的特点是 IP 地址的第一个字节的前两位是 `10`。宏的定义通常如下：
     ```c
     #define	IN_CLASSB(i)	(((uint32_t)(i) & 0xc0000000) == 0x80000000)
     ```
     这里 `0xc0000000` 的二进制表示是 `11000000 00000000 00000000 00000000`，`0x80000000` 的二进制表示是 `10000000 00000000 00000000 00000000`。

5. **`return (((i)&IN_CLASSB_NET) >> IN_CLASSB_NSHIFT);`**:
   - 如果 IP 地址属于 B 类网络，则执行此行代码。
   - `IN_CLASSB_NET` 是 B 类网络的网络号掩码，定义通常如下：
     ```c
     #define	IN_CLASSB_NET	0xffff0000
     ```
     其二进制表示是 `11111111 11111111 00000000 00000000`。
   - `IN_CLASSB_NSHIFT` 是 B 类网络网络号的位移量，定义通常如下：
     ```c
     #define	IN_CLASSB_NSHIFT	16
     ```

6. **`else`**:
   - 如果 IP 地址既不属于 A 类也不属于 B 类，则默认为 C 类网络。C 类网络的特点是 IP 地址的第一个字节的前三位是 `110`。

7. **`return (((i)&IN_CLASSC_NET) >> IN_CLASSC_NSHIFT);`**:
   - 如果 IP 地址属于 C 类网络，则执行此行代码。
   - `IN_CLASSC_NET` 是 C 类网络的网络号掩码，定义通常如下：
     ```c
     #define	IN_CLASSC_NET	0xffffff00
     ```
     其二进制表示是 `11111111 11111111 11111111 00000000`。
   - `IN_CLASSC_NSHIFT` 是 C 类网络网络号的位移量，定义通常如下：
     ```c
     #define	IN_CLASSC_NSHIFT	8
     ```

**涉及 dynamic linker 的功能**

`inet_netof.c` 本身的代码并没有直接涉及动态链接器的功能。它是一个简单的函数，其实现完全在 `libc.so` 内部。

然而，`inet_netof` 函数存在于 `libc.so` 这个共享库中，因此它的加载和使用受到动态链接器的管理。

**so 布局样本**

一个典型的 `libc.so` 的布局可能包含以下部分：

```
libc.so:
    .text         # 存放可执行的代码
        inet_netof:  # inet_netof 函数的代码
        ...         # 其他 libc 函数的代码
    .data         # 存放已初始化的全局变量和静态变量
    .bss          # 存放未初始化的全局变量和静态变量
    .rodata       # 存放只读数据，例如字符串常量
    .dynsym       # 动态符号表，包含共享库导出的符号信息
    .dynstr       # 动态字符串表，存储符号名称等字符串
    .plt          # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
    .got.plt      # 全局偏移表 (Global Offset Table) 的 PLT 部分
    .got          # 全局偏移表，存储全局变量的地址
    ...           # 其他段
```

**链接的处理过程**

当一个应用程序（例如 Android Framework 的一个组件或一个 NDK 应用）调用 `inet_netof` 函数时，动态链接器会参与以下过程：

1. **加载 `libc.so`:** 如果 `libc.so` 尚未加载到进程的地址空间，动态链接器会负责将其加载到内存中。
2. **符号查找:** 当应用程序调用 `inet_netof` 时，如果这个调用是首次发生，动态链接器需要解析这个符号。这通常通过以下步骤完成：
   - **PLT 条目:** 应用程序的代码会跳转到 `libc.so` 的 PLT 中与 `inet_netof` 对应的条目。
   - **GOT 条目:** PLT 条目会引用 GOT 中的一个地址。首次调用时，GOT 中的这个地址通常指向 PLT 中的一段代码。
   - **动态链接器介入:** PLT 中的这段代码会调用动态链接器。
   - **符号解析:** 动态链接器在 `libc.so` 的 `.dynsym` 和 `.dynstr` 中查找 `inet_netof` 的地址。
   - **更新 GOT:** 动态链接器将 `inet_netof` 函数的实际地址写入 GOT 中对应的条目。
   - **跳转到目标函数:** 动态链接器跳转到 `inet_netof` 函数的实际地址执行。
3. **后续调用:**  一旦 `inet_netof` 的地址被解析并存储在 GOT 中，后续的调用将直接通过 GOT 跳转到 `inet_netof` 的实际地址，避免了重复的符号查找过程，这称为延迟绑定。

**逻辑推理、假设输入与输出**

假设输入一个 `struct in_addr` 结构，其 `s_addr` 成员（以网络字节序表示）为 `0xc0a80164`。

1. **`ntohl(in.s_addr)`:** `ntohl(0xc0a80164)` 将网络字节序转换为主机字节序。假设主机是小端序，则结果为 `0x6401a8c0`。
2. **`IN_CLASSA(0x6401a8c0)`:** `(0x6401a8c0 & 0x80000000) == 0`，结果为真，因为最高位是 0。
3. **返回:** `((0x6401a8c0 & 0xff000000) >> 24)`。
   - `0x6401a8c0 & 0xff000000` 的结果是 `0x64000000`。
   - `0x64000000 >> 24` 的结果是 `0x64`，即十进制的 `100`。

**更正：** 上面的假设输入有误。`0xc0a80164` 对应的 IP 地址是 `192.168.1.100`，属于 C 类网络。让我们重新计算。

假设输入一个 `struct in_addr` 结构，其 `s_addr` 成员（以网络字节序表示）为 `0xc0a80164`。

1. **`ntohl(in.s_addr)`:** `ntohl(0xc0a80164)` 结果为 `0x6401a8c0`。
2. **`IN_CLASSA(0x6401a8c0)`:**  结果为真。
3. **`IN_CLASSB(0x6401a8c0)`:** `(0x6401a8c0 & 0xc0000000) == 0x80000000`，即 `0x40000000 == 0x80000000`，结果为假。
4. **`else` 分支:** 进入 C 类网络的处理。
5. **返回:** `((0x6401a8c0 & 0xffffff00) >> 8)`。
   - `0x6401a8c0 & 0xffffff00` 的结果是 `0x6401a800`。
   - `0x6401a800 >> 8` 的结果是 `0x6401a8`。

**再次更正：**  我之前的理解有误，`inet_netof` 返回的是网络号本身，而不是 IP 地址。对于 IP 地址 `192.168.1.100`，网络号应该是 `192.168.1`。让我们再来一次。

假设输入一个 `struct in_addr` 结构，其 `s_addr` 成员（以网络字节序表示）为 `0xc0a80164` (代表 `192.168.1.100`)。

1. **`ntohl(in.s_addr)`:** `ntohl(0xc0a80164)` 结果为 `0x6401a8c0`。
2. **`IN_CLASSA(0x6401a8c0)`:** 结果为假。
3. **`IN_CLASSB(0x6401a8c0)`:** 结果为假。
4. **`else` 分支:** 进入 C 类网络的处理。
5. **返回:** `((0x6401a8c0 & IN_CLASSC_NET) >> IN_CLASSC_NSHIFT)`
   - `IN_CLASSC_NET` 是 `0xffffff00`。
   - `0x6401a8c0 & 0xffffff00` 的结果是 `0x6401a800`。
   - `IN_CLASSC_NSHIFT` 是 `8`。
   - `0x6401a800 >> 8` 的结果是 `0x6401a8`。  这仍然不是我们期望的网络号。

**最终修正：**  我意识到我混淆了主机字节序和网络字节序在计算中的位置。`inet_netof` 的返回值是以主机字节序表示的网络号。

对于 IP 地址 `192.168.1.100` (网络字节序 `0xc0a80164`)：

1. **`ntohl(in.s_addr)`:** `ntohl(0xc0a80164)` 得到主机字节序的 IP 地址，假设是小端序，结果为 `0x6401a8c0`。
2. **判断网络类别：**
   - `IN_CLASSA(0x6401a8c0)` 为假。
   - `IN_CLASSB(0x6401a8c0)` 为假。
   - 因此是 C 类网络。
3. **计算网络号：**
   - `(0x6401a8c0 & 0xffffff00)` 得到 `0x6401a800`。
   - `0x6401a800 >> 8` 得到 `0x006401a8`。

**关键在于理解 `inet_netof` 返回的是主机字节序的网络号。**  对于 C 类网络 `192.168.1.100`，网络号是 `192.168.1`。在内存中，以主机字节序（小端序）表示时，可能是 `0x01a8c0` (如果只考虑网络号的三个字节)。但是 `inet_netof` 返回的是 `in_addr_t` 类型，所以是完整的 32 位。

**假设输入：** IP 地址 `10.0.0.1` (网络字节序 `0x0a000001`)，属于 A 类网络。

1. **`ntohl(0x0a000001)`:** 假设小端序，结果为 `0x0100000a`。
2. **`IN_CLASSA(0x0100000a)`:** 为真。
3. **返回：** `((0x0100000a & 0xff000000) >> 24)`
   - `0x0100000a & 0xff000000` 得到 `0x01000000`。
   - `0x01000000 >> 24` 得到 `0x01`，即十进制的 `1`。  这是 A 类网络 `10.0.0.0/8` 的网络号。

**用户或编程常见的使用错误**

1. **字节序错误:**  忘记使用 `ntohl()` 将网络字节序转换为主机字节序，导致基于错误的 IP 地址进行网络类别判断和网络号提取。
   ```c
   struct in_addr addr;
   inet_pton(AF_INET, "192.168.1.100", &addr);
   in_addr_t net = inet_netof(addr); // 如果主机是大端序，结果可能错误
   ```
   正确的做法是：
   ```c
   struct in_addr addr;
   inet_pton(AF_INET, "192.168.1.100", &addr);
   in_addr_t net = inet_netof(addr);
   // net 中的值已经是主机字节序
   ```

2. **误解 `inet_netof` 的作用:**  认为 `inet_netof` 返回的是点分十进制的字符串表示，或者仍然是网络字节序。实际上，它返回的是主机字节序的整数表示的网络号。

3. **在现代网络环境中的误用:**  由于现代网络主要使用 CIDR，分类编址已经过时。在处理子网掩码不是默认值的情况时，`inet_netof` 的结果可能不再准确反映实际的网络划分。

**Android Framework 或 NDK 如何一步步到达这里**

1. **Android Framework (Java/Kotlin):**  应用程序通常通过 Java 网络相关的 API 进行网络操作，例如 `java.net.InetAddress`, `java.net.NetworkInterface`, `java.net.Socket` 等。

2. **JNI 调用:**  当 Java 代码需要进行底层的网络操作时，会通过 JNI (Java Native Interface) 调用到 Android 系统的 Native 层代码。

3. **NDK (Native Development Kit):**  使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic libc 提供的网络函数。例如，使用 `socket()`, `bind()`, `connect()` 等函数时，可能会涉及到 IP 地址的处理。

4. **Bionic libc:**  当 Native 代码调用 `inet_pton()` 将 IP 地址字符串转换为 `struct in_addr` 结构后，如果需要提取网络号，就可以调用 `inet_netof()`。

**Frida Hook 示例**

可以使用 Frida hook `inet_netof` 函数，观察其输入和输出：

```python
import frida
import sys

package_name = "your.target.app"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "inet_netof"), {
    onEnter: function(args) {
        var in_addr_ptr = ptr(args[0]);
        var s_addr = Memory.readU32(in_addr_ptr);
        var ip_str = "";
        var bytes = [
            (s_addr & 0xFF),
            ((s_addr >> 8) & 0xFF),
            ((s_addr >> 16) & 0xFF),
            ((s_addr >> 24) & 0xFF)
        ];
        ip_str = bytes.join(".");
        send({type: "input", ip: ip_str});
        this.ip_address = ip_str;
    },
    onLeave: function(retval) {
        send({type: "output", ip: this.ip_address, net: retval.toString()});
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print(f"[+] Frida 正在监听 '{package_name}' 的 inet_netof 调用...")
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **`Interceptor.attach()`:**  使用 Frida 的 `Interceptor` API 来拦截 `libc.so` 中的 `inet_netof` 函数。
2. **`onEnter`:** 在 `inet_netof` 函数被调用前执行。
   - `args[0]` 是指向 `struct in_addr` 结构体的指针。
   - 读取 `s_addr` 成员，并将其转换为点分十进制的 IP 地址字符串。
   - 使用 `send()` 函数将输入 IP 地址发送到 Frida 控制台。
   - 将 IP 地址保存在 `this.ip_address` 中，以便在 `onLeave` 中使用。
3. **`onLeave`:** 在 `inet_netof` 函数返回后执行。
   - `retval` 是函数的返回值（即网络号）。
   - 使用 `send()` 函数将原始 IP 地址和计算出的网络号发送到 Frida 控制台。

运行此 Frida 脚本后，每当目标应用调用 `inet_netof` 函数时，Frida 控制台将打印出调用的 IP 地址和返回的网络号。

希望这个详细的分析能够帮助你理解 `inet_netof.c` 的功能和在 Android 中的应用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/net/inet_netof.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: inet_netof.c,v 1.7 2015/01/16 16:48:51 deraadt Exp $ */
/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Return the network number from an internet
 * address; handles class a/b/c network #'s.
 */
in_addr_t
inet_netof(struct in_addr in)
{
	in_addr_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return (((i)&IN_CLASSA_NET) >> IN_CLASSA_NSHIFT);
	else if (IN_CLASSB(i))
		return (((i)&IN_CLASSB_NET) >> IN_CLASSB_NSHIFT);
	else
		return (((i)&IN_CLASSC_NET) >> IN_CLASSC_NSHIFT);
}

"""

```