Response:
Let's break down the thought process to answer the request about `bionic/libc/include/arpa/telnet.h`.

**1. Understanding the Core Request:**

The request asks for an analysis of a C header file (`telnet.h`). The key areas to address are:

* **Functionality:** What does this file *do*? What concepts does it define?
* **Android Relevance:** How does this relate to the Android operating system?
* **Libc Function Details:**  In-depth explanation of libc functions (though this file doesn't *implement* functions, it *defines* constants used by them). *Correction: Realized the request might be misinterpreting "libc functions" as "the definitions *in* this libc header file".*
* **Dynamic Linker:** How does this interact with the dynamic linker? (Again, since it's a header file, it doesn't directly participate in linking, but the constants are used by linked libraries).
* **Logic and Examples:**  Illustrative scenarios.
* **Common Mistakes:** Potential pitfalls for developers.
* **Android Framework/NDK Path:** How does a call from higher levels reach this header file?
* **Frida Hooking:**  How to intercept and inspect this in a running process.

**2. Initial Analysis of the Header File:**

* **Copyright Notice:**  Recognize the Berkeley copyright, indicating a historical connection to BSD Unix.
* **Include Guard:**  The `#ifndef _ARPA_TELNET_H_` and `#define _ARPA_TELNET_H_` pattern is a standard include guard to prevent multiple inclusions.
* **Includes:**  The inclusion of `<sys/cdefs.h>` is a common pattern in system headers, often related to compiler definitions and feature checks.
* **Macros and Constants:** The bulk of the file is a series of `#define` statements. These define symbolic names for various aspects of the Telnet protocol. Keywords like `IAC`, `DO`, `DONT`, `WILL`, `WONT`, `SB` immediately suggest Telnet protocol control codes. Further examination reveals definitions for Telnet options (like `TELOPT_ECHO`, `TELOPT_BINARY`), sub-option qualifiers, and constants related to line mode, authentication, and encryption.
* **Arrays of Strings (Optional):** The sections with `#ifdef TELCMDS` and `#ifdef TELOPTS` suggest that there *might* be arrays of human-readable strings associated with the command and option codes, but these are conditionally defined. The `extern char *telcmds[];` and `extern char *telopts[];` indicate that these arrays might be defined elsewhere.
* **"OK" Macros:**  Macros like `TELCMD_OK(x)` and `TELOPT_OK(x)` are present for validating command and option values.

**3. Connecting to Android:**

* **Bionic Path:** The path `bionic/libc/include/arpa/telnet.handroid` clearly indicates this is part of Android's C library.
* **Telnet's Role:** Telnet is a network protocol for remote terminal access. While not commonly used directly by end-user Android apps, it might be used in lower-level system utilities or debugging tools. It's also possible that parts of the Telnet protocol are used in other network protocols or services.
* **NDK Relevance:**  Developers using the NDK for low-level network programming *could* potentially interact with these definitions if they are implementing Telnet clients or servers, or if they are working with libraries that use Telnet-like mechanisms.

**4. Addressing Specific Request Points:**

* **Functionality (Header File):**  The file *doesn't* implement functions. It provides *definitions* needed for Telnet protocol handling. This is a crucial distinction. It defines constants, macros, and potentially external string arrays.
* **Libc Function Details:** Since it's just a header, direct implementation details aren't present. The explanation should focus on *how* the *definitions* are used by libc functions (e.g., `socket`, `send`, `recv`, potentially custom Telnet handling functions if they exist).
* **Dynamic Linker:** The header file itself isn't directly involved in dynamic linking. However, libraries that *use* these definitions will be linked. The example SO layout and linking process should demonstrate how a library using `telnet.h` would be structured and how symbols are resolved.
* **Logic and Examples:**  Provide concrete examples of how the constants are used in a Telnet interaction (e.g., sending an IAC WILL ECHO sequence).
* **Common Mistakes:**  Focus on incorrect usage of the constants, like using raw numeric values instead of the defined macros or misunderstanding the meaning of different control codes.
* **Android Framework/NDK Path:** Trace a hypothetical path from an application-level request (e.g., using a terminal emulator app that supports Telnet) down to the system calls and how the Telnet protocol handling might involve these definitions.
* **Frida Hooking:**  Demonstrate how to use Frida to intercept calls involving these constants or related functions. Focus on hooking functions that *use* these definitions.

**5. Structuring the Answer:**

Organize the answer according to the request's points. Use clear headings and bullet points. Provide code examples where applicable. Explain technical terms.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretation:**  The request mentioned "libc functions" within this file. Realized the file only *defines* things, not implements functions. Adjusted the explanation accordingly.
* **Dynamic Linker Nuance:**  The header isn't directly linked. Clarified that it's the *libraries using* the header that are linked.
* **Frida Focus:** Initially thought about hooking the header itself, which isn't directly possible. Shifted focus to hooking functions that *use* the definitions from the header.
* **Clarity on Conditional Definitions:** Explicitly mentioned that the `telcmds` and `telopts` arrays might not be defined in all compilation units and might be external.

By following this thought process, addressing each point systematically, and correcting any initial misunderstandings, a comprehensive and accurate answer can be constructed. The key is to understand the nature of a header file and its role in the broader software ecosystem.
好的，让我们详细分析一下 `bionic/libc/include/arpa/telnet.handroid` 这个头文件。

**功能概述**

`telnet.h` 文件定义了 Telnet 协议中使用的各种常量、宏和数据结构。它并没有实现任何实际的 Telnet 功能，而是作为其他 C/C++ 代码实现 Telnet 客户端或服务器的基础。 它的主要功能是提供：

* **Telnet 命令代码 (Telnet Commands):** 定义了如 `IAC` (解释为命令), `DO`, `DONT`, `WILL`, `WONT`, `SB` (子协商) 等 Telnet 协议的核心命令代码。
* **Telnet 选项代码 (Telnet Options):** 定义了各种 Telnet 协议支持的选项，例如 `TELOPT_BINARY` (8 位数据路径), `TELOPT_ECHO` (回显), `TELOPT_NAWS` (窗口大小协商) 等。
* **子选项限定符 (Sub-option Qualifiers):**  定义了在 Telnet 子协商中使用的限定符，如 `TELQUAL_IS`, `TELQUAL_SEND` 等。
* **LINEMODE 子选项 (LINEMODE Suboptions):**  定义了与 Telnet 行模式相关的常量，用于更精细地控制终端的行为。
* **身份验证子选项 (Authentication Suboptions):** 定义了与 Telnet 身份验证相关的常量，用于协商身份验证方式。
* **加密子选项 (Encryption Suboptions):** 定义了与 Telnet 加密相关的常量，用于协商加密方式。
* **辅助宏和类型定义:** 提供了一些辅助宏，如 `TELCMD_OK`, `TELOPT_OK`，用于校验命令或选项的有效性。

**与 Android 功能的关系及举例**

虽然 Android 设备本身通常不直接运行 Telnet 服务器，但 `telnet.h` 文件仍然包含在 Android 的 Bionic C 库中，这有几个原因：

1. **兼容性:**  Android 的 Bionic 库很大程度上参考了传统的 Unix 和 Linux 系统，包含 Telnet 相关的头文件是为了保持一定的兼容性。一些底层的网络工具或库可能依赖这些定义。

2. **NDK 开发:** 使用 Android NDK 进行 Native 开发的开发者，如果需要实现与 Telnet 协议相关的网络功能（例如，开发一个 Telnet 客户端工具），可以直接使用这个头文件中定义的常量，而无需自己去定义这些协议细节。

3. **系统工具和调试:**  Android 系统内部的一些工具或守护进程，出于调试或维护的目的，可能会使用到 Telnet 协议或其相关的概念。例如，某些嵌入式设备或测试环境可能会启用 Telnet 服务。

**举例说明:**

假设你正在使用 Android NDK 开发一个简单的 Telnet 客户端。你可以这样使用 `telnet.h` 中定义的常量：

```c++
#include <arpa/telnet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(23); // Telnet 默认端口
    // ... 设置服务器 IP 地址 ...

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // 发送 "WILL ECHO" 命令，请求服务器回显
    unsigned char will_echo[] = {IAC, WILL, TELOPT_ECHO};
    send(sockfd, will_echo, sizeof(will_echo), 0);

    std::cout << "Sent WILL ECHO command." << std::endl;

    close(sockfd);
    return 0;
}
```

在这个例子中，我们使用了 `IAC`, `WILL`, `TELOPT_ECHO` 这些在 `telnet.h` 中定义的常量来构造 Telnet 协议消息。

**详细解释每一个 libc 函数的功能是如何实现的**

需要强调的是，`telnet.h` **本身不是 libc 函数**，它是一个头文件，包含了宏定义和常量。它并不实现任何函数。  它提供的是构建网络应用所需的协议定义。

如果你想了解 **实际处理 Telnet 协议的 libc 函数** 的实现，你可能指的是与网络编程相关的函数，例如：

* **`socket()`:**  创建一个用于网络通信的套接字。它的实现涉及到内核的网络协议栈，包括分配文件描述符、创建套接字数据结构等。
* **`connect()`:**  尝试连接到远程服务器。它会发起 TCP 三次握手过程，建立网络连接。
* **`send()` 和 `recv()`:**  在已连接的套接字上发送和接收数据。它们的实现涉及将用户空间的数据拷贝到内核空间，并交给网络协议栈进行处理，或者反之。

这些函数的具体实现非常复杂，涉及到操作系统内核的细节，例如网络协议栈的实现、设备驱动等。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

`telnet.h` 本身不直接涉及动态链接器的功能。然而，如果一个动态链接库 ( `.so` 文件) 使用了 `telnet.h` 中定义的常量，那么动态链接器在加载这个 `.so` 文件时，会处理相关的符号。

**SO 布局样本 (假设一个名为 `libmytelnet.so` 的库使用了 `telnet.h`)：**

```
libmytelnet.so:
    .text          # 包含代码段
        ... 使用了 IAC, WILL, TELOPT_ECHO 等常量 ...
    .rodata        # 包含只读数据
        ...
    .data          # 包含可读写数据
        ...
    .dynamic       # 包含动态链接信息
        NEEDED libc.so  # 依赖 libc.so
        ...
    .dynsym        # 包含动态符号表
        ... IAC (UNDEF) ...
        ... WILL (UNDEF) ...
        ... TELOPT_ECHO (UNDEF) ...
        ... 其他函数符号 ...
    .rel.dyn       # 包含动态重定位信息
        ... 需要重定位 IAC 的地址 ...
        ... 需要重定位 WILL 的地址 ...
        ... 需要重定位 TELOPT_ECHO 的地址 ...
        ...
```

**链接处理过程：**

1. **加载 `.so` 文件:** 当 Android 系统加载 `libmytelnet.so` 时，动态链接器 (如 `linker64` 或 `linker`) 会将该文件加载到内存中。

2. **解析 `.dynamic` 段:** 动态链接器会解析 `.dynamic` 段，获取该库的依赖信息，例如它依赖于 `libc.so`。

3. **加载依赖库:** 动态链接器会加载所有依赖的共享库，包括 `libc.so`。

4. **符号查找 (Symbol Lookup):** 动态链接器会遍历已加载的共享库的符号表 (`.dynsym`)，查找 `libmytelnet.so` 中未定义的符号 (标记为 `UNDEF`)。  在这个例子中，`IAC`, `WILL`, `TELOPT_ECHO` 这些常量是在 `libc.so` 中定义的 (实际上是在 `telnet.h` 中定义，编译到 `libc.so` 中)。

5. **符号重定位 (Symbol Relocation):** 找到这些符号的定义后，动态链接器会根据 `.rel.dyn` 段中的信息，修改 `libmytelnet.so` 中引用这些符号的地址，使其指向 `libc.so` 中对应符号的地址。  这样，`libmytelnet.so` 就可以正确地使用 `telnet.h` 中定义的常量了。

**假设输入与输出 (逻辑推理)**

`telnet.h` 主要定义常量，本身不执行逻辑推理。逻辑推理发生在使用了这些常量的代码中。

**假设输入:**  一个 Telnet 客户端接收到来自服务器的三个字节：`{ 255, 251, 1 }`。

**输出:**

* 第一个字节 `255` (`IAC`) 表示这是一个 Telnet 命令。
* 第二个字节 `251` (`WILL`) 表示这是一个 "WILL" 命令，意味着服务器愿意启用某个选项。
* 第三个字节 `1` (`TELOPT_ECHO`) 表示服务器愿意启用 "ECHO" 选项。

因此，客户端的 Telnet 处理逻辑会解释这个输入为：服务器请求启用回显功能。客户端可能会根据自身配置和策略，回复一个 `DO ECHO` 或 `DONT ECHO` 命令。

**用户或编程常见的使用错误**

1. **直接使用数字常量:** 程序员可能会直接使用数字 `255` 而不是 `IAC`，降低代码可读性和可维护性。如果协议定义发生变化，需要修改所有硬编码的数字。

2. **误解命令或选项的含义:**  错误地理解某个 Telnet 命令或选项的作用，导致实现逻辑错误。例如，混淆 `DO` 和 `WILL` 的含义。

3. **忽略字节序问题:**  在网络编程中，需要注意字节序 (大端或小端) 的问题。虽然 Telnet 命令本身是单字节的，但如果涉及到子选项协商中的多字节数据，就需要考虑字节序转换。

4. **不完整的 Telnet 协议实现:**  只实现了部分 Telnet 命令和选项，导致与某些 Telnet 服务器的兼容性问题。

5. **安全问题:**  Telnet 协议本身是明文传输的，存在安全风险。在现代应用中，应该优先使用 SSH 等加密协议。如果必须使用 Telnet，需要注意安全加固，例如使用 `TELOPT_ENCRYPT` 选项进行加密。

**说明 Android framework or ndk 是如何一步步的到达这里**

1. **Android Framework (Java 层):**  Android Framework 本身通常不直接操作 Telnet 协议。更高层次的网络操作通常使用 HTTP、WebSocket 等更现代和安全的协议。

2. **Android NDK (Native 层):**  NDK 开发允许开发者使用 C/C++ 编写 Native 代码。如果 NDK 应用需要实现 Telnet 客户端功能，开发者会包含 `<arpa/telnet.h>` 头文件。

3. **系统调用:**  NDK 代码中，处理网络连接通常会使用标准的 POSIX socket API，例如 `socket()`, `connect()`, `send()`, `recv()`。这些函数是 libc 提供的，最终会通过系统调用与 Linux 内核交互。

4. **Bionic libc:**  `telnet.h` 是 Bionic libc 的一部分。当 NDK 代码编译时，编译器会找到并使用这个头文件。在运行时，NDK 应用链接到 Bionic libc，其中的网络函数实现会处理底层的网络操作。

**Frida hook 示例调试这些步骤**

假设我们想 hook 一个使用了 `telnet.h` 中常量的 NDK 应用，查看它发送的 Telnet 命令。

```python
import frida
import sys

package_name = "your.ndk.telnet.app" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        command_code = message['payload'][0]
        command_name = ""
        if 236 <= command_code <= 255: # 检查是否为 Telnet 命令
            # 可以根据 telnet.h 中的定义映射到命令名称
            if command_code == 255:
                command_name = "IAC"
            elif command_code == 251:
                command_name = "WILL"
            # ... 添加其他命令的映射 ...
            print(f"[*] Sending Telnet Command: {command_name} ({command_code})")
        else:
            print(f"[*] Sending data: {message['payload']}")

def main():
    try:
        device = frida.get_usb_device()
        session = device.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"Error: Process '{package_name}' not found. Is the app running?")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "send"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const buf = args[1];
            const size = args[2].toInt32();
            const data = Memory.readByteArray(buf, size);
            send({'type': 'send', 'payload': data});
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Frida script loaded. Monitoring 'send' calls...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**Frida Hook 示例解释:**

1. **导入 Frida 库:**  导入 `frida` 和 `sys` 库。
2. **定义 `on_message` 函数:**  这个函数处理从 Frida 脚本接收到的消息。我们拦截了 `send` 函数的调用，并将发送的数据发送回 Python 脚本。
3. **定义 `main` 函数:**
   - 获取 USB 设备并附加到目标 Android 应用进程。
   - 定义 Frida 脚本代码：
     - 使用 `Interceptor.attach` 钩住 `libc.so` 中的 `send` 函数。
     - 在 `onEnter` 阶段，读取 `send` 函数的参数：文件描述符、缓冲区地址和大小。
     - 使用 `Memory.readByteArray` 读取缓冲区中的数据。
     - 使用 `send()` 函数将数据发送回 Python 脚本，并标记消息类型为 `'send'`。
4. **加载 Frida 脚本:**  创建并加载 Frida 脚本。
5. **监听消息:**  设置消息监听器，将接收到的消息传递给 `on_message` 函数处理。
6. **保持运行:**  使用 `sys.stdin.read()` 使脚本保持运行状态，直到手动停止。
7. **卸载:**  在脚本结束时分离 Frida 会话。

**运行流程:**

1. 运行你的 NDK Telnet 应用。
2. 运行这个 Frida 脚本，替换 `package_name` 为你的应用包名。
3. 当你的 NDK 应用调用 `send` 函数发送数据时，Frida 脚本会拦截调用，读取发送的数据，并判断是否是 Telnet 命令。
4. 如果是 Telnet 命令，`on_message` 函数会根据 `telnet.h` 中的定义（你需要自己添加映射）打印出命令的名称和代码。
5. 如果不是 Telnet 命令，会打印出原始发送的数据。

通过这种方式，你可以监控 NDK 应用与 Telnet 服务器之间的通信，并验证是否正确使用了 `telnet.h` 中定义的常量。

希望这个详细的解答能够帮助你理解 `bionic/libc/include/arpa/telnet.handroid` 文件的作用以及它在 Android 系统中的相关性。

### 提示词
```
这是目录为bionic/libc/include/arpa/telnet.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 *
 *	@(#)telnet.h	8.2 (Berkeley) 12/15/93
 * $FreeBSD$
 */

#ifndef _ARPA_TELNET_H_
#define	_ARPA_TELNET_H_

#include <sys/cdefs.h>

/*
 * Definitions for the TELNET protocol.
 */
#define	IAC	255		/* interpret as command: */
#define	DONT	254		/* you are not to use option */
#define	DO	253		/* please, you use option */
#define	WONT	252		/* I won't use option */
#define	WILL	251		/* I will use option */
#define	SB	250		/* interpret as subnegotiation */
#define	GA	249		/* you may reverse the line */
#define	EL	248		/* erase the current line */
#define	EC	247		/* erase the current character */
#define	AYT	246		/* are you there */
#define	AO	245		/* abort output--but let prog finish */
#define	IP	244		/* interrupt process--permanently */
#define	BREAK	243		/* break */
#define	DM	242		/* data mark--for connect. cleaning */
#define	NOP	241		/* nop */
#define	SE	240		/* end sub negotiation */
#define EOR     239             /* end of record (transparent mode) */
#define	ABORT	238		/* Abort process */
#define	SUSP	237		/* Suspend process */
#define	xEOF	236		/* End of file: EOF is already used... */

#define SYNCH	242		/* for telfunc calls */

#ifdef TELCMDS
const char *telcmds[] = {
	"EOF", "SUSP", "ABORT", "EOR",
	"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
	"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC",
	0
};
#else
extern char *telcmds[];
#endif

#define	TELCMD_FIRST	xEOF
#define	TELCMD_LAST	IAC
#define	TELCMD_OK(x)	((unsigned int)(x) <= TELCMD_LAST && \
			 (unsigned int)(x) >= TELCMD_FIRST)
#define	TELCMD(x)	telcmds[(x)-TELCMD_FIRST]

/* telnet options */
#define TELOPT_BINARY	0	/* 8-bit data path */
#define TELOPT_ECHO	1	/* echo */
#define	TELOPT_RCP	2	/* prepare to reconnect */
#define	TELOPT_SGA	3	/* suppress go ahead */
#define	TELOPT_NAMS	4	/* approximate message size */
#define	TELOPT_STATUS	5	/* give status */
#define	TELOPT_TM	6	/* timing mark */
#define	TELOPT_RCTE	7	/* remote controlled transmission and echo */
#define TELOPT_NAOL 	8	/* negotiate about output line width */
#define TELOPT_NAOP 	9	/* negotiate about output page size */
#define TELOPT_NAOCRD	10	/* negotiate about CR disposition */
#define TELOPT_NAOHTS	11	/* negotiate about horizontal tabstops */
#define TELOPT_NAOHTD	12	/* negotiate about horizontal tab disposition */
#define TELOPT_NAOFFD	13	/* negotiate about formfeed disposition */
#define TELOPT_NAOVTS	14	/* negotiate about vertical tab stops */
#define TELOPT_NAOVTD	15	/* negotiate about vertical tab disposition */
#define TELOPT_NAOLFD	16	/* negotiate about output LF disposition */
#define TELOPT_XASCII	17	/* extended ascic character set */
#define	TELOPT_LOGOUT	18	/* force logout */
#define	TELOPT_BM	19	/* byte macro */
#define	TELOPT_DET	20	/* data entry terminal */
#define	TELOPT_SUPDUP	21	/* supdup protocol */
#define	TELOPT_SUPDUPOUTPUT 22	/* supdup output */
#define	TELOPT_SNDLOC	23	/* send location */
#define	TELOPT_TTYPE	24	/* terminal type */
#define	TELOPT_EOR	25	/* end or record */
#define	TELOPT_TUID	26	/* TACACS user identification */
#define	TELOPT_OUTMRK	27	/* output marking */
#define	TELOPT_TTYLOC	28	/* terminal location number */
#define	TELOPT_3270REGIME 29	/* 3270 regime */
#define	TELOPT_X3PAD	30	/* X.3 PAD */
#define	TELOPT_NAWS	31	/* window size */
#define	TELOPT_TSPEED	32	/* terminal speed */
#define	TELOPT_LFLOW	33	/* remote flow control */
#define TELOPT_LINEMODE	34	/* Linemode option */
#define TELOPT_XDISPLOC	35	/* X Display Location */
#define TELOPT_OLD_ENVIRON 36	/* Old - Environment variables */
#define	TELOPT_AUTHENTICATION 37/* Authenticate */
#define	TELOPT_ENCRYPT	38	/* Encryption option */
#define TELOPT_NEW_ENVIRON 39	/* New - Environment variables */
#define	TELOPT_TN3270E	40	/* RFC2355 - TN3270 Enhancements */
#define	TELOPT_CHARSET	42	/* RFC2066 - Charset */
#define	TELOPT_COMPORT	44	/* RFC2217 - Com Port Control */
#define	TELOPT_KERMIT	47	/* RFC2840 - Kermit */
#define	TELOPT_EXOPL	255	/* extended-options-list */


#define	NTELOPTS	(1+TELOPT_KERMIT)
#ifdef TELOPTS
const char *telopts[NTELOPTS+1] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
	"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
	"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
	"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
	"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
	"TACACS UID", "OUTPUT MARKING", "TTYLOC",
	"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
	"LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
	"ENCRYPT", "NEW-ENVIRON", "TN3270E", "XAUTH", "CHARSET",
	"RSP", "COM-PORT", "SLE", "STARTTLS", "KERMIT",
	0
};
#define	TELOPT_FIRST	TELOPT_BINARY
#define	TELOPT_LAST	TELOPT_KERMIT
#define	TELOPT_OK(x)	((unsigned int)(x) <= TELOPT_LAST)
#define	TELOPT(x)	telopts[(x)-TELOPT_FIRST]
#endif

/* sub-option qualifiers */
#define	TELQUAL_IS	0	/* option is... */
#define	TELQUAL_SEND	1	/* send option */
#define	TELQUAL_INFO	2	/* ENVIRON: informational version of IS */
#define	TELQUAL_REPLY	2	/* AUTHENTICATION: client version of IS */
#define	TELQUAL_NAME	3	/* AUTHENTICATION: client version of IS */

#define	LFLOW_OFF		0	/* Disable remote flow control */
#define	LFLOW_ON		1	/* Enable remote flow control */
#define	LFLOW_RESTART_ANY	2	/* Restart output on any char */
#define	LFLOW_RESTART_XON	3	/* Restart output only on XON */

/*
 * LINEMODE suboptions
 */

#define	LM_MODE		1
#define	LM_FORWARDMASK	2
#define	LM_SLC		3

#define	MODE_EDIT	0x01
#define	MODE_TRAPSIG	0x02
#define	MODE_ACK	0x04
#define MODE_SOFT_TAB	0x08
#define MODE_LIT_ECHO	0x10

#define	MODE_MASK	0x1f

/* Not part of protocol, but needed to simplify things... */
#define MODE_FLOW		0x0100
#define MODE_ECHO		0x0200
#define MODE_INBIN		0x0400
#define MODE_OUTBIN		0x0800
#define MODE_FORCE		0x1000

#define	SLC_SYNCH	1
#define	SLC_BRK		2
#define	SLC_IP		3
#define	SLC_AO		4
#define	SLC_AYT		5
#define	SLC_EOR		6
#define	SLC_ABORT	7
#define	SLC_EOF		8
#define	SLC_SUSP	9
#define	SLC_EC		10
#define	SLC_EL		11
#define	SLC_EW		12
#define	SLC_RP		13
#define	SLC_LNEXT	14
#define	SLC_XON		15
#define	SLC_XOFF	16
#define	SLC_FORW1	17
#define	SLC_FORW2	18
#define SLC_MCL         19
#define SLC_MCR         20
#define SLC_MCWL        21
#define SLC_MCWR        22
#define SLC_MCBOL       23
#define SLC_MCEOL       24
#define SLC_INSRT       25
#define SLC_OVER        26
#define SLC_ECR         27
#define SLC_EWR         28
#define SLC_EBOL        29
#define SLC_EEOL        30

#define	NSLC		30

/*
 * For backwards compatibility, we define SLC_NAMES to be the
 * list of names if SLC_NAMES is not defined.
 */
#define	SLC_NAMELIST	"0", "SYNCH", "BRK", "IP", "AO", "AYT", "EOR",	\
			"ABORT", "EOF", "SUSP", "EC", "EL", "EW", "RP",	\
			"LNEXT", "XON", "XOFF", "FORW1", "FORW2",	\
			"MCL", "MCR", "MCWL", "MCWR", "MCBOL",		\
			"MCEOL", "INSRT", "OVER", "ECR", "EWR",		\
			"EBOL", "EEOL",					\
			0

#ifdef	SLC_NAMES
const char *slc_names[] = {
	SLC_NAMELIST
};
#else
extern char *slc_names[];
#define	SLC_NAMES SLC_NAMELIST
#endif

#define	SLC_NAME_OK(x)	((unsigned int)(x) <= NSLC)
#define SLC_NAME(x)	slc_names[x]

#define	SLC_NOSUPPORT	0
#define	SLC_CANTCHANGE	1
#define	SLC_VARIABLE	2
#define	SLC_DEFAULT	3
#define	SLC_LEVELBITS	0x03

#define	SLC_FUNC	0
#define	SLC_FLAGS	1
#define	SLC_VALUE	2

#define	SLC_ACK		0x80
#define	SLC_FLUSHIN	0x40
#define	SLC_FLUSHOUT	0x20

#define	OLD_ENV_VAR	1
#define	OLD_ENV_VALUE	0
#define	NEW_ENV_VAR	0
#define	NEW_ENV_VALUE	1
#define	ENV_ESC		2
#define ENV_USERVAR	3

/*
 * AUTHENTICATION suboptions
 */

/*
 * Who is authenticating who ...
 */
#define	AUTH_WHO_CLIENT		0	/* Client authenticating server */
#define	AUTH_WHO_SERVER		1	/* Server authenticating client */
#define	AUTH_WHO_MASK		1

/*
 * amount of authentication done
 */
#define	AUTH_HOW_ONE_WAY	0
#define	AUTH_HOW_MUTUAL		2
#define	AUTH_HOW_MASK		2

#define	AUTHTYPE_NULL		0
#define	AUTHTYPE_KERBEROS_V4	1
#define	AUTHTYPE_KERBEROS_V5	2
#define	AUTHTYPE_SPX		3
#define	AUTHTYPE_MINK		4
#define	AUTHTYPE_SRA		6
#define	AUTHTYPE_CNT		7

#define	AUTHTYPE_TEST		99

#ifdef	AUTH_NAMES
const char *authtype_names[] = {
	"NULL", "KERBEROS_V4", "KERBEROS_V5", "SPX", "MINK", NULL, "SRA",
	0
};
#else
extern char *authtype_names[];
#endif

#define	AUTHTYPE_NAME_OK(x)	((unsigned int)(x) < AUTHTYPE_CNT)
#define	AUTHTYPE_NAME(x)	authtype_names[x]

/*
 * ENCRYPTion suboptions
 */
#define	ENCRYPT_IS		0	/* I pick encryption type ... */
#define	ENCRYPT_SUPPORT		1	/* I support encryption types ... */
#define	ENCRYPT_REPLY		2	/* Initial setup response */
#define	ENCRYPT_START		3	/* Am starting to send encrypted */
#define	ENCRYPT_END		4	/* Am ending encrypted */
#define	ENCRYPT_REQSTART	5	/* Request you start encrypting */
#define	ENCRYPT_REQEND		6	/* Request you end encrypting */
#define	ENCRYPT_ENC_KEYID	7
#define	ENCRYPT_DEC_KEYID	8
#define	ENCRYPT_CNT		9

#define	ENCTYPE_ANY		0
#define	ENCTYPE_DES_CFB64	1
#define	ENCTYPE_DES_OFB64	2
#define	ENCTYPE_CNT		3

#ifdef	ENCRYPT_NAMES
const char *encrypt_names[] = {
	"IS", "SUPPORT", "REPLY", "START", "END",
	"REQUEST-START", "REQUEST-END", "ENC-KEYID", "DEC-KEYID",
	0
};
const char *enctype_names[] = {
	"ANY", "DES_CFB64",  "DES_OFB64",
	0
};
#else
extern char *encrypt_names[];
extern char *enctype_names[];
#endif


#define	ENCRYPT_NAME_OK(x)	((unsigned int)(x) < ENCRYPT_CNT)
#define	ENCRYPT_NAME(x)		encrypt_names[x]

#define	ENCTYPE_NAME_OK(x)	((unsigned int)(x) < ENCTYPE_CNT)
#define	ENCTYPE_NAME(x)		enctype_names[x]

#endif /* !_TELNET_H_ */
```