Response:
Let's break down the thought process to address the user's request. The user has provided a C header file and asked for a comprehensive analysis within the context of Android.

**1. Initial Understanding and Keyword Extraction:**

The first step is to read the code and the prompt carefully, identifying key elements.

* **File Path:** `bionic/libc/kernel/uapi/linux/isdn/capicmd.h` -  This tells us it's a header file related to the kernel's ISDN (Integrated Services Digital Network) subsystem, specifically the CAPI (Common ISDN API) commands. The "uapi" signifies user-space facing kernel headers. The location within `bionic/libc` indicates it's part of Android's C library.
* **Content:** The file mainly defines macros related to CAPI commands and their structure.
* **Keywords in Prompt:** "功能", "android的功能", "举例说明", "libc函数", "实现", "dynamic linker", "so布局", "链接过程", "逻辑推理", "假设输入与输出", "使用错误", "android framework or ndk", "frida hook", "调试步骤".

**2. Deconstructing the Request:**

The prompt asks for a multi-faceted analysis. I'll address each part systematically:

* **Functionality:** What does this header file *do*?  It defines constants for CAPI commands used in ISDN communication.
* **Relationship to Android:** How does ISDN and its CAPI relate to Android?  This requires thinking about Android's functionalities. While ISDN isn't a core feature of typical Android phones today, it might be relevant for specific hardware or embedded Android use cases.
* **libc Functions:** The prompt specifically asks about libc functions. *This is a trick question!* The provided file *only contains macros and doesn't define any functions*. Recognizing this is crucial. If there were functions, the request would then require explaining their implementations within the bionic libc.
* **Dynamic Linker:** How does this relate to the dynamic linker? Header files define interfaces. While not directly involved in *linking*,  these definitions are used by code that *will be linked*. I need to explain how symbols defined here are used by shared libraries.
* **SO Layout & Linking:** How would an SO using these definitions look? And how would the linker resolve symbols? I need to illustrate this with a conceptual example, even though the provided file isn't a shared library itself.
* **Logical Reasoning (Hypothetical Input/Output):** Since the file defines constants, the "input" would be these constants being used in a program, and the "output" would be actions based on the specific CAPI command.
* **User Errors:** How might a developer misuse these definitions? Common errors include using incorrect command codes or improperly structuring data.
* **Android Framework/NDK and Frida:** How does a request get from the Android framework down to using these definitions? This involves tracing the potential call path, even if it's not a common path. I need to think about the layers involved and how a CAPI call might be triggered. Frida examples should demonstrate how to intercept calls related to these definitions (even if those calls aren't directly to functions *in this header*).

**3. Pre-computation and Pre-analysis (Internal "Sandbox"):**

Before generating the final response, I'll do some internal processing:

* **ISDN/CAPI Background:**  Briefly recall what ISDN and CAPI are for context. It's a digital communication standard. CAPI provides a standardized way for applications to interact with ISDN hardware.
* **Android Relevance:**  Consider *why* these headers exist in Android. Even if not widely used on phones, they might be for:
    * Legacy support.
    * Specialized hardware (e.g., industrial devices).
    * Potential for future use.
* **libc Functions - The Key Insight:** The file *doesn't contain function definitions*. This is the most important point for this part of the request.
* **Dynamic Linking - Abstraction:** Focus on the concept of how these *definitions* are used in dynamically linked libraries. The actual linking of these *macros* is trivial (compile-time substitution). The linking happens with the functions that *use* these macros.
* **Frida Hooking - Targeting Usage:**  Since there are no functions in this header, Frida hooks will need to target *functions that use these defined constants*.

**4. Structuring the Response:**

Organize the answer clearly, following the structure of the prompt:

* **功能 (Functionality):** Start with a concise explanation of the header file's purpose.
* **与Android的关系 (Relationship to Android):** Explain the potential relevance to Android, acknowledging it's not a mainstream feature. Provide plausible examples.
* **libc函数的功能 (Functionality of libc functions):**  Address this by explicitly stating that *this header file doesn't contain libc function definitions*.
* **Dynamic Linker:** Explain the role of the dynamic linker in resolving symbols and how these definitions are used. Provide a simple SO layout example (even if conceptual). Explain the linking process.
* **逻辑推理 (Logical Reasoning):**  Give simple examples of how the defined constants would be used and the expected "output" in terms of ISDN actions.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** List typical mistakes related to using these definitions.
* **Android Framework/NDK and Frida:**  Describe a plausible path from the framework/NDK to the usage of these definitions (even if it's a less common path). Provide concrete Frida hooking examples targeting functions that *might use* these constants.

**5. Refinement and Language:**

* **Use clear and concise Chinese.**
* **Explain technical terms simply.**
* **Be accurate and avoid making definitive statements where there's uncertainty (e.g., about the exact usage in Android).**
* **Emphasize the distinction between the header file (definitions) and actual function implementations.**

By following this systematic thought process, I can generate a comprehensive and accurate response that addresses all aspects of the user's request, even the potentially tricky parts like the libc function question. The focus shifts from the *content* of the header to its *purpose* and *how it might be used* within the broader Android ecosystem.
这个头文件 `capicmd.h` 定义了用于与 ISDN (Integrated Services Digital Network) 设备的 CAPI (Common ISDN API) 协议进行通信的命令和常量。由于其位于 `bionic/libc/kernel/uapi/linux/isdn/` 目录下，可以推断这是 Linux 内核提供给用户空间的 CAPI 命令定义。

**功能列举:**

这个头文件的主要功能是定义了一系列用于构造和解析 CAPI 消息的常量。这些常量代表了不同的 CAPI 命令和子命令，以及与这些命令相关的消息长度。具体来说，它定义了：

1. **基本常量:**
   - `CAPI_MSG_BASELEN`: CAPI 消息的基本长度。
   - `CAPI_DATA_B3_REQ_LEN`, `CAPI_DATA_B3_RESP_LEN`, `CAPI_DISCONNECT_B3_RESP_LEN`: 特定 CAPI 命令请求和响应消息的长度。

2. **CAPI 命令代码:**
   - `CAPI_ALERT`, `CAPI_CONNECT`, `CAPI_CONNECT_ACTIVE`, `CAPI_CONNECT_B3_ACTIVE`, `CAPI_CONNECT_B3`, `CAPI_CONNECT_B3_T90_ACTIVE`, `CAPI_DATA_B3`, `CAPI_DISCONNECT_B3`, `CAPI_DISCONNECT`, `CAPI_FACILITY`, `CAPI_INFO`, `CAPI_LISTEN`, `CAPI_MANUFACTURER`, `CAPI_RESET_B3`, `CAPI_SELECT_B_PROTOCOL`:  这些常量代表了不同的 CAPI 命令，例如呼叫建立、数据传输、断开连接等。

3. **CAPI 子命令代码:**
   - `CAPI_REQ`, `CAPI_CONF`, `CAPI_IND`, `CAPI_RESP`: 这些常量代表了 CAPI 消息的类型，分别是请求 (Request)、确认 (Confirm)、指示 (Indication) 和响应 (Response)。

4. **组合的 CAPI 命令:**
   - 使用 `CAPICMD(cmd, subcmd)` 宏将命令代码和子命令代码组合成一个完整的 CAPI 命令字，例如 `CAPI_DISCONNECT_REQ` 代表断开连接请求。  文件中定义了大量的组合命令，涵盖了各种 CAPI 操作的请求、确认、指示和响应。

**与 Android 功能的关系及举例说明:**

虽然 ISDN 技术在现代移动设备中并不常见，但它可能在以下 Android 场景中出现：

* **特定的工业或嵌入式设备:**  一些特定的工业设备或嵌入式系统可能仍然使用 ISDN 进行数据传输或通信。Android 作为一个通用的操作系统，可能需要支持这些硬件。
* **旧的硬件兼容性:** 尽管不常见，某些特定的 Android 设备可能需要与旧的 ISDN 设备进行交互。
* **测试和开发:**  在某些开发和测试环境中，可能需要模拟或与 ISDN 系统进行交互。

**举例说明:**

假设一个 Android 应用需要通过 ISDN 网络发送数据。该应用可能会使用底层的 C 库函数来构建 CAPI 消息。例如，要发送一个数据块，应用可能需要构建一个 `CAPI_DATA_B3_REQ` 消息。这个头文件中定义的 `CAPI_DATA_B3_REQ` 常量 (其值为 `CAPICMD(CAPI_DATA_B3, CAPI_REQ)`) 可以用来识别这是一个数据传输请求。  `CAPI_DATA_B3_REQ_LEN` 常量则可以帮助确定消息的长度，以便正确地分配内存或进行数据包的构建。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并没有定义任何 libc 函数。** 它仅仅定义了一些宏常量。这些常量会被其他使用 CAPI 的 C/C++ 代码使用，而这些代码可能会调用 libc 提供的系统调用或其他函数来最终实现与 ISDN 设备的交互。

例如，如果有一个函数需要发送一个 CAPI `DISCONNECT_B3_REQ` 消息，它可能会使用 `write()` 系统调用来将构造好的消息发送到与 ISDN 驱动程序关联的文件描述符。 `write()` 函数是 libc 提供的，其实现涉及到将用户空间的数据复制到内核空间，并触发内核中相应的驱动程序操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然这个头文件本身不直接涉及动态链接，但如果有一个共享库 (`.so`) 使用了这些定义的常量，那么动态链接器就会参与其中。

**SO 布局样本:**

假设有一个名为 `libisdn.so` 的共享库，它使用了 `capicmd.h` 中定义的常量：

```c
// libisdn.c
#include <linux/isdn/capicmd.h>
#include <stdio.h>

void send_disconnect_request() {
  unsigned char buffer[100]; // 假设足够大的缓冲区
  // ... 构造 CAPI_DISCONNECT_REQ 消息到 buffer 中 ...
  printf("Sending disconnect request: 0x%x\n", CAPI_DISCONNECT_REQ);
  // ... 使用系统调用 (如 write()) 发送 buffer ...
}
```

编译成共享库：

```bash
gcc -shared -fPIC libisdn.c -o libisdn.so
```

**`libisdn.so` 的布局可能如下：**

| 区域         | 内容                               |
|--------------|------------------------------------|
| .text        | `send_disconnect_request` 函数的代码 |
| .rodata      |  可能包含字符串常量等              |
| .data        |  可能包含已初始化的全局变量          |
| .bss         |  可能包含未初始化的全局变量          |
| .symtab      |  符号表，包含 `send_disconnect_request` 的符号信息 |
| .strtab      |  字符串表，包含符号名称等字符串     |
| .rel.dyn     |  动态重定位信息                   |
| .dynsym      |  动态符号表                       |
| .dynstr      |  动态字符串表                     |
| ...          |  其他段                           |

**链接的处理过程:**

1. **编译时:** 当编译 `libisdn.c` 时，编译器会读取 `capicmd.h`，并将 `CAPI_DISCONNECT_REQ` 宏替换为其对应的数值。由于这些是宏定义，它们在编译时就被替换，不会产生需要动态链接的符号。

2. **运行时:** 如果另一个可执行文件或共享库想要使用 `libisdn.so` 中的 `send_disconnect_request` 函数，动态链接器会执行以下步骤：
   - **加载:** 将 `libisdn.so` 加载到内存中。
   - **重定位:**  如果 `libisdn.so` 中有需要重定位的符号（例如，调用了其他共享库的函数），动态链接器会根据 `.rel.dyn` 段中的信息修改代码或数据段中的地址。在这个例子中，由于 `capicmd.h` 中都是宏，所以 `libisdn.so` 内部直接使用了常量值，可能不需要针对 `capicmd.h` 中的符号进行动态链接。
   - **符号解析:**  如果 `libisdn.so` 导出了 `send_disconnect_request` 符号，其他模块可以通过动态链接器找到并调用这个函数。

**注意:**  这个例子中，`capicmd.h` 中的常量在编译时就被替换了，因此动态链接器不会直接处理这些常量。动态链接器主要处理函数和全局变量的符号。

**如果做了逻辑推理，请给出假设输入与输出:**

假设有一个程序尝试发送一个断开连接的请求：

**假设输入:**

* 程序调用了一个发送 CAPI 消息的函数，并指定要发送 `CAPI_DISCONNECT_REQ` 消息。
* 相关的 ISDN 设备和驱动程序已正确初始化。

**输出:**

* 程序构建了一个包含 `CAPI_DISCONNECT_REQ` 命令字的消息。
* 这个消息被发送到 ISDN 驱动程序。
* ISDN 驱动程序会解释这个消息，并执行断开连接的操作。
* 可能会收到来自 ISDN 网络的响应，表明断开连接是否成功。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的命令代码:**  开发者可能错误地使用了 `CAPI_CONNECT_REQ` 而不是 `CAPI_DISCONNECT_REQ` 来尝试断开连接。这会导致 ISDN 设备执行错误的操作。

2. **消息长度计算错误:**  开发者可能没有正确使用 `CAPI_MSG_BASELEN` 和其他长度常量来构建消息，导致消息结构不正确，无法被 ISDN 驱动程序解析。例如，发送 `CAPI_DATA_B3_REQ` 时，数据部分的长度没有正确计算，导致数据丢失或解析错误。

3. **字节序问题:**  CAPI 协议可能对字节序有要求。如果开发者没有正确处理字节序，发送到 ISDN 设备的命令字和参数可能会被错误解释。

4. **状态机错误:**  CAPI 通信通常涉及一个状态机。开发者可能在错误的状态下发送了不合适的命令，例如在连接尚未建立时发送数据。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 ISDN 不是 Android 核心的网络技术，Android Framework 或 NDK 直接使用 CAPI 命令的情况非常罕见。更可能的情况是：

1. **第三方硬件或驱动:**  某个特定的 Android 设备可能集成了 ISDN 硬件，并提供了一个 vendor HAL (Hardware Abstraction Layer) 或内核驱动程序来处理 ISDN 通信。
2. **NDK 开发:**  一个使用 NDK 开发的应用程序可能需要与这个特定的 ISDN 硬件进行交互。

**可能的路径:**

1. **NDK 应用:** 使用 NDK 编写的应用想要进行 ISDN 通信。
2. **自定义库:** 该应用可能链接到一个自定义的共享库 (`.so`)，这个库封装了与 ISDN 驱动程序交互的逻辑。
3. **系统调用:** 这个自定义库可能会使用标准 C 库函数（如 `open()`, `read()`, `write()`, `ioctl()`) 与内核中的 ISDN 驱动程序进行通信。
4. **内核驱动程序:** 内核中的 ISDN 驱动程序接收到来自用户空间的请求，并会解析和处理 CAPI 消息。驱动程序会使用 `capicmd.h` 中定义的常量来识别不同的 CAPI 命令。

**Frida Hook 示例:**

假设我们要 hook 一个自定义库中发送 CAPI 消息的函数（例如，名为 `send_capi_message` 的函数）。

```python
import frida
import sys

# 目标进程名称
package_name = "com.example.isdn_app"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received message:", message['payload'])

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libisdn.so", "send_capi_message"), {
    onEnter: function(args) {
        console.log("[*] Calling send_capi_message");
        // 假设第一个参数是指向 CAPI 消息缓冲区的指针
        var capi_buffer = ptr(args[0]);
        // 假设消息长度在第二个参数
        var message_length = args[1].toInt();
        console.log("[*] Message Length:", message_length);

        // 读取并打印部分消息内容 (假设前 4 字节是命令字)
        if (message_length >= 4) {
            var command = capi_buffer.readU32();
            console.log("[*] CAPI Command: 0x" + command.toString(16));
            // 可以根据命令字判断具体的操作
            if (command === 0x0480) { // 假设 CAPI_DISCONNECT_REQ 的值为 0x0480
                console.log("[*] Detected CAPI_DISCONNECT_REQ");
            }
        }
    },
    onLeave: function(retval) {
        console.log("[*] send_capi_message returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 进程。
2. **`Module.findExportByName("libisdn.so", "send_capi_message")`:** 找到 `libisdn.so` 中导出的 `send_capi_message` 函数的地址。你需要知道实际的库名称和函数名称。
3. **`Interceptor.attach(...)`:**  在 `send_capi_message` 函数的入口和出口处设置 hook。
4. **`onEnter`:**  在函数调用前执行：
   - 打印日志表明函数被调用。
   - 读取函数参数，例如 CAPI 消息缓冲区的指针和消息长度。
   - 读取缓冲区中的数据，并解析 CAPI 命令字。
   - 根据命令字判断具体的 CAPI 操作。
5. **`onLeave`:** 在函数返回后执行，打印返回值。

通过这种方式，你可以使用 Frida 动态地分析 Android 应用与 ISDN 硬件的交互过程，观察发送的 CAPI 命令，并进行调试。 请注意，这需要对目标应用的内部实现有一定的了解，才能确定要 hook 的库和函数名称，以及参数的含义。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/isdn/capicmd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __CAPICMD_H__
#define __CAPICMD_H__
#define CAPI_MSG_BASELEN 8
#define CAPI_DATA_B3_REQ_LEN (CAPI_MSG_BASELEN + 4 + 4 + 2 + 2 + 2)
#define CAPI_DATA_B3_RESP_LEN (CAPI_MSG_BASELEN + 4 + 2)
#define CAPI_DISCONNECT_B3_RESP_LEN (CAPI_MSG_BASELEN + 4)
#define CAPI_ALERT 0x01
#define CAPI_CONNECT 0x02
#define CAPI_CONNECT_ACTIVE 0x03
#define CAPI_CONNECT_B3_ACTIVE 0x83
#define CAPI_CONNECT_B3 0x82
#define CAPI_CONNECT_B3_T90_ACTIVE 0x88
#define CAPI_DATA_B3 0x86
#define CAPI_DISCONNECT_B3 0x84
#define CAPI_DISCONNECT 0x04
#define CAPI_FACILITY 0x80
#define CAPI_INFO 0x08
#define CAPI_LISTEN 0x05
#define CAPI_MANUFACTURER 0xff
#define CAPI_RESET_B3 0x87
#define CAPI_SELECT_B_PROTOCOL 0x41
#define CAPI_REQ 0x80
#define CAPI_CONF 0x81
#define CAPI_IND 0x82
#define CAPI_RESP 0x83
#define CAPICMD(cmd,subcmd) (((cmd) << 8) | (subcmd))
#define CAPI_DISCONNECT_REQ CAPICMD(CAPI_DISCONNECT, CAPI_REQ)
#define CAPI_DISCONNECT_CONF CAPICMD(CAPI_DISCONNECT, CAPI_CONF)
#define CAPI_DISCONNECT_IND CAPICMD(CAPI_DISCONNECT, CAPI_IND)
#define CAPI_DISCONNECT_RESP CAPICMD(CAPI_DISCONNECT, CAPI_RESP)
#define CAPI_ALERT_REQ CAPICMD(CAPI_ALERT, CAPI_REQ)
#define CAPI_ALERT_CONF CAPICMD(CAPI_ALERT, CAPI_CONF)
#define CAPI_CONNECT_REQ CAPICMD(CAPI_CONNECT, CAPI_REQ)
#define CAPI_CONNECT_CONF CAPICMD(CAPI_CONNECT, CAPI_CONF)
#define CAPI_CONNECT_IND CAPICMD(CAPI_CONNECT, CAPI_IND)
#define CAPI_CONNECT_RESP CAPICMD(CAPI_CONNECT, CAPI_RESP)
#define CAPI_CONNECT_ACTIVE_REQ CAPICMD(CAPI_CONNECT_ACTIVE, CAPI_REQ)
#define CAPI_CONNECT_ACTIVE_CONF CAPICMD(CAPI_CONNECT_ACTIVE, CAPI_CONF)
#define CAPI_CONNECT_ACTIVE_IND CAPICMD(CAPI_CONNECT_ACTIVE, CAPI_IND)
#define CAPI_CONNECT_ACTIVE_RESP CAPICMD(CAPI_CONNECT_ACTIVE, CAPI_RESP)
#define CAPI_SELECT_B_PROTOCOL_REQ CAPICMD(CAPI_SELECT_B_PROTOCOL, CAPI_REQ)
#define CAPI_SELECT_B_PROTOCOL_CONF CAPICMD(CAPI_SELECT_B_PROTOCOL, CAPI_CONF)
#define CAPI_CONNECT_B3_ACTIVE_REQ CAPICMD(CAPI_CONNECT_B3_ACTIVE, CAPI_REQ)
#define CAPI_CONNECT_B3_ACTIVE_CONF CAPICMD(CAPI_CONNECT_B3_ACTIVE, CAPI_CONF)
#define CAPI_CONNECT_B3_ACTIVE_IND CAPICMD(CAPI_CONNECT_B3_ACTIVE, CAPI_IND)
#define CAPI_CONNECT_B3_ACTIVE_RESP CAPICMD(CAPI_CONNECT_B3_ACTIVE, CAPI_RESP)
#define CAPI_CONNECT_B3_REQ CAPICMD(CAPI_CONNECT_B3, CAPI_REQ)
#define CAPI_CONNECT_B3_CONF CAPICMD(CAPI_CONNECT_B3, CAPI_CONF)
#define CAPI_CONNECT_B3_IND CAPICMD(CAPI_CONNECT_B3, CAPI_IND)
#define CAPI_CONNECT_B3_RESP CAPICMD(CAPI_CONNECT_B3, CAPI_RESP)
#define CAPI_CONNECT_B3_T90_ACTIVE_IND CAPICMD(CAPI_CONNECT_B3_T90_ACTIVE, CAPI_IND)
#define CAPI_CONNECT_B3_T90_ACTIVE_RESP CAPICMD(CAPI_CONNECT_B3_T90_ACTIVE, CAPI_RESP)
#define CAPI_DATA_B3_REQ CAPICMD(CAPI_DATA_B3, CAPI_REQ)
#define CAPI_DATA_B3_CONF CAPICMD(CAPI_DATA_B3, CAPI_CONF)
#define CAPI_DATA_B3_IND CAPICMD(CAPI_DATA_B3, CAPI_IND)
#define CAPI_DATA_B3_RESP CAPICMD(CAPI_DATA_B3, CAPI_RESP)
#define CAPI_DISCONNECT_B3_REQ CAPICMD(CAPI_DISCONNECT_B3, CAPI_REQ)
#define CAPI_DISCONNECT_B3_CONF CAPICMD(CAPI_DISCONNECT_B3, CAPI_CONF)
#define CAPI_DISCONNECT_B3_IND CAPICMD(CAPI_DISCONNECT_B3, CAPI_IND)
#define CAPI_DISCONNECT_B3_RESP CAPICMD(CAPI_DISCONNECT_B3, CAPI_RESP)
#define CAPI_RESET_B3_REQ CAPICMD(CAPI_RESET_B3, CAPI_REQ)
#define CAPI_RESET_B3_CONF CAPICMD(CAPI_RESET_B3, CAPI_CONF)
#define CAPI_RESET_B3_IND CAPICMD(CAPI_RESET_B3, CAPI_IND)
#define CAPI_RESET_B3_RESP CAPICMD(CAPI_RESET_B3, CAPI_RESP)
#define CAPI_LISTEN_REQ CAPICMD(CAPI_LISTEN, CAPI_REQ)
#define CAPI_LISTEN_CONF CAPICMD(CAPI_LISTEN, CAPI_CONF)
#define CAPI_MANUFACTURER_REQ CAPICMD(CAPI_MANUFACTURER, CAPI_REQ)
#define CAPI_MANUFACTURER_CONF CAPICMD(CAPI_MANUFACTURER, CAPI_CONF)
#define CAPI_MANUFACTURER_IND CAPICMD(CAPI_MANUFACTURER, CAPI_IND)
#define CAPI_MANUFACTURER_RESP CAPICMD(CAPI_MANUFACTURER, CAPI_RESP)
#define CAPI_FACILITY_REQ CAPICMD(CAPI_FACILITY, CAPI_REQ)
#define CAPI_FACILITY_CONF CAPICMD(CAPI_FACILITY, CAPI_CONF)
#define CAPI_FACILITY_IND CAPICMD(CAPI_FACILITY, CAPI_IND)
#define CAPI_FACILITY_RESP CAPICMD(CAPI_FACILITY, CAPI_RESP)
#define CAPI_INFO_REQ CAPICMD(CAPI_INFO, CAPI_REQ)
#define CAPI_INFO_CONF CAPICMD(CAPI_INFO, CAPI_CONF)
#define CAPI_INFO_IND CAPICMD(CAPI_INFO, CAPI_IND)
#define CAPI_INFO_RESP CAPICMD(CAPI_INFO, CAPI_RESP)
#endif
```