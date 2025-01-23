Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/netinet_ether.cpp`.

**1. Understanding the Core Request:**

The central goal is to analyze the provided C++ code snippet and explain its functionality, its relevance to Android, how it's implemented, its connection to the dynamic linker (if any), potential errors, and how Android reaches this code. The format needs to be in Chinese.

**2. Initial Code Analysis (Identifying the Functions):**

The first step is to look at the function signatures. We see four functions:

* `ether_aton_r(const char* asc, ether_addr* addr)`
* `ether_aton(const char* asc)`
* `ether_ntoa_r(const ether_addr* addr, char* buf)`
* `ether_ntoa(const ether_addr* addr)`

**3. Deducing Functionality (Name and Logic):**

The function names themselves provide strong clues:

* `aton`:  Likely "ASCII to network address" or similar. The `_r` suffix often indicates a reentrant version (though in this case, the reentrancy is primarily about the output buffer).
* `ntoa`: Likely "network address to ASCII". Again, the `_r` suffix points to reentrancy considerations.

Looking at the code:

* `ether_aton_r`: Uses `sscanf` to parse a colon-separated hexadecimal string. It validates the number of components and their values. It writes the parsed bytes into the provided `ether_addr` structure.
* `ether_aton`:  A convenience wrapper around `ether_aton_r` that uses a static buffer for the `ether_addr`. This makes it non-thread-safe.
* `ether_ntoa_r`:  Uses `snprintf` to format the byte array from the `ether_addr` structure into a colon-separated hexadecimal string. The result is written to the provided buffer.
* `ether_ntoa`:  A convenience wrapper around `ether_ntoa_r` that uses a static buffer. Also non-thread-safe.

Therefore, the core functionality is converting MAC addresses between string representation (e.g., "00:11:22:33:44:55") and a binary structure.

**4. Connecting to Android:**

Since this code resides in `bionic/libc`, it's part of Android's fundamental C library. MAC addresses are crucial for network communication. Therefore, any Android component dealing with network interfaces or low-level networking will likely use these functions (or functions that rely on them). Examples include:

* **Network configuration tools:**  Setting or displaying MAC addresses.
* **DHCP clients:**  Identifying devices on the network.
* **Wi-Fi and Bluetooth stacks:**  Device identification and communication.
* **Socket programming:**  While usually working at higher levels, the underlying network stack uses MAC addresses.

**5. Detailed Explanation of `libc` Functions:**

* **`sscanf`:**  The core of the string-to-binary conversion. Explain how it parses the input string according to the format specifier. Highlight the validation steps (number of items parsed, end-of-string check, range check).
* **`snprintf`:**  The core of the binary-to-string conversion. Explain how it formats the output string according to the format specifier. Emphasize the buffer size parameter to prevent buffer overflows.

**6. Dynamic Linker Considerations:**

Examine the code for direct calls to dynamic linker functions. In this snippet, there are none. Therefore, the explanation should focus on *how* these functions are used within the broader context of Android's dynamic linking:

* These functions are compiled into `libc.so`.
* Other Android components (like system services or apps) will *link* against `libc.so`.
* When these components are loaded, the dynamic linker resolves the symbols (`ether_aton`, `ether_ntoa`, etc.) to their addresses within the loaded `libc.so`.

A simple `libc.so` layout example is helpful to visualize this. The linking process involves the dynamic linker reading metadata from the ELF files and resolving symbols.

**7. Logic Inference and Examples:**

Provide simple input/output examples to illustrate how the functions work:

* `ether_aton("00:11:22:33:44:55")` -> `ether_addr` structure with the corresponding bytes.
* `ether_ntoa(&my_ether_addr)` -> "00:11:22:33:44:55".
* Illustrate invalid inputs and the expected `NULL` return for `ether_aton`.

**8. Common Usage Errors:**

Focus on the dangers of the non-reentrant versions (`ether_aton` and `ether_ntoa`):

* Race conditions in multithreaded environments due to the use of static buffers.
* Buffer overflows if the provided buffer to `ether_ntoa_r` is too small (though `snprintf` mitigates this if used correctly).
* Incorrect format strings passed to `sscanf` or `snprintf`.

**9. Android Framework/NDK Path and Frida Hooking:**

This requires tracing the execution flow. A hypothetical example would involve:

* **Framework:** A system service like `ConnectivityService` or a HAL interacting with network devices.
* **NDK:** An app using network APIs that eventually call down to native code and then to `libc`.

The Frida hook example needs to target these functions directly. Show how to intercept the calls, examine arguments, and potentially modify the return value. It's important to demonstrate how Frida can be used to understand the execution flow.

**10. Structuring the Answer:**

Organize the information logically with clear headings and bullet points for readability. Use precise technical terms but explain them clearly. Ensure the language is natural Chinese.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Should I explain the underlying network protocols?  **Correction:** Stick to the scope of the provided code and its immediate context. Mentioning network protocols briefly is okay, but deep dives are unnecessary.
* **Initial thought:**  Focus heavily on the `_r` suffixes and reentrancy. **Correction:**  While important, the primary practical difference here is the static buffer. Emphasize the thread-safety implications more directly.
* **Initial thought:**  Provide very complex Frida examples. **Correction:** Keep the Frida examples simple and focused on demonstrating the basic hooking mechanism for these functions. Overly complex examples can be confusing.
* **Ensure all parts of the prompt are addressed:** Double-check that each question in the prompt has been answered adequately.

By following these steps and constantly refining the approach, a comprehensive and accurate answer to the user's request can be generated.
好的，让我们详细分析一下 `bionic/libc/bionic/netinet_ether.cpp` 这个文件。

**功能概述:**

这个文件定义了用于处理以太网地址（MAC地址）的几个实用函数。这些函数主要用于在以太网地址的二进制表示和可读的ASCII字符串表示之间进行转换。具体来说，它提供了以下四个函数：

1. **`ether_aton_r(const char* asc, ether_addr* addr)`**: 将以冒号分隔的十六进制字符串表示的以太网地址转换为二进制的 `ether_addr` 结构体，并将结果存储在用户提供的 `addr` 指针指向的内存中。这是一个线程安全（可重入）的版本。
2. **`ether_aton(const char* asc)`**:  功能与 `ether_aton_r` 类似，将字符串转换为 `ether_addr`。但是，它使用一个静态的内部缓冲区来存储结果，因此不是线程安全的。
3. **`ether_ntoa_r(const ether_addr* addr, char* buf)`**: 将二进制的 `ether_addr` 结构体转换为以冒号分隔的十六进制字符串表示，并将结果存储在用户提供的 `buf` 缓冲区中。这是一个线程安全（可重入）的版本。
4. **`ether_ntoa(const ether_addr* addr)`**: 功能与 `ether_ntoa_r` 类似，将 `ether_addr` 转换为字符串。但是，它使用一个静态的内部缓冲区来存储结果，因此不是线程安全的。

**与 Android 功能的关系及举例说明:**

以太网地址是网络通信的基础，几乎所有涉及网络操作的 Android 功能都会间接或直接地使用到这些函数。以下是一些例子：

* **网络配置 (Network Configuration):** Android 系统在配置网络接口时，需要读取和设置设备的 MAC 地址。例如，在 Wi-Fi 连接或者以太网连接的设置中，设备的 MAC 地址会被显示出来。这些显示可能就使用了 `ether_ntoa` 将二进制 MAC 地址转换为可读的字符串。
* **DHCP 客户端 (DHCP Client):** 当 Android 设备连接到网络时，DHCP 客户端会发送请求获取 IP 地址等信息。在 DHCP 交互过程中，设备的 MAC 地址会被用来唯一标识设备。网络协议栈可能会使用 `ether_aton` 将配置中或者接收到的 MAC 地址字符串转换为二进制格式进行处理。
* **蓝牙 (Bluetooth):** 蓝牙地址与以太网地址类似，也需要进行字符串和二进制之间的转换。尽管这个文件主要处理以太网地址，但相关的转换逻辑思想是相似的，在蓝牙相关的代码中可能会有类似的功能实现。
* **网络监控工具 (Network Monitoring Tools):**  一些 Android 上的网络监控工具可能会捕获网络数据包，并需要将数据包中的 MAC 地址显示出来，这时就会用到 `ether_ntoa`。

**libc 函数的实现细节:**

1. **`ether_aton_r(const char* asc, ether_addr* addr)`:**
   - **`sscanf(asc, "%x:%x:%x:%x:%x:%x%n", ...)`**:  这是核心部分。`sscanf` 是 C 标准库函数，用于从字符串 `asc` 中读取格式化的输入。
     - `"%x:%x:%x:%x:%x:%x"`:  指定了输入字符串的格式，即六个十六进制数，每个数之间用冒号分隔。
     - `&bytes[0]`, `&bytes[1]`, ...:  提供存储读取到的十六进制数值的地址。`bytes` 是一个包含 6 个 `int` 的数组。
     - `%n`:  一个特殊的格式说明符，它将到目前为止成功读取的字符数写入到 `end` 变量中。
   - **错误检查:**
     - `n != ETHER_ADDR_LEN`: 检查 `sscanf` 是否成功读取了 6 个十六进制数。`ETHER_ADDR_LEN` 通常定义为 6。
     - `asc[end] != '\0'`: 检查在读取完 6 个十六进制数后，字符串是否已经结束。如果后面还有其他字符，则说明输入格式不正确。
   - **范围检查:**
     - 循环遍历读取到的每个字节，检查其值是否在 0 到 0xff 之间，因为以太网地址的每个字节的取值范围是 0-255。
   - **赋值:**
     - 如果所有检查都通过，则将读取到的字节值赋值给 `addr->ether_addr_octet` 数组的相应元素。`ether_addr_octet` 是 `ether_addr` 结构体中用于存储 6 个字节的 MAC 地址的数组。

2. **`ether_aton(const char* asc)`:**
   - 这个函数很简单，它声明了一个静态的 `ether_addr` 变量 `addr`。
   - 然后调用 `ether_aton_r(asc, &addr)`，将转换结果存储到这个静态变量中。
   - 最后返回静态变量 `addr` 的地址。由于使用了静态变量，这个函数不是线程安全的，因为多个线程可能同时修改这个静态变量。

3. **`ether_ntoa_r(const ether_addr* addr, char* buf)`:**
   - **`snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", ...)`**: 这是核心部分。`snprintf` 是 C 标准库函数，用于格式化输出到字符串缓冲区 `buf` 中。
     - `buf`:  指向用于存储格式化后的字符串的缓冲区。
     - `18`:  指定缓冲区的大小，包括结尾的空字符。以太网地址的字符串表示 "xx:xx:xx:xx:xx:xx" 需要 17 个字符加上结尾的空字符。
     - `"%02x:%02x:%02x:%02x:%02x:%02x"`:  指定了输出格式，即六个两位的十六进制数，每个数之间用冒号分隔。`02x` 表示以两位十六进制形式输出，不足两位时补零。
     - `addr->ether_addr_octet[0]`, `addr->ether_addr_octet[1]`, ...:  提供要格式化的字节值，这些值来自 `addr` 指向的 `ether_addr` 结构体。
   - 返回指向 `buf` 的指针。

4. **`ether_ntoa(const ether_addr* addr)`:**
   - 这个函数也很简单，它声明了一个静态的字符数组 `buf`，大小为 18。
   - 然后调用 `ether_ntoa_r(addr, buf)`，将转换结果存储到这个静态缓冲区中。
   - 最后返回静态缓冲区 `buf` 的地址。同样，由于使用了静态缓冲区，这个函数不是线程安全的。

**涉及 dynamic linker 的功能:**

这个源文件本身并不直接涉及 dynamic linker 的功能。它定义的是一些普通的 C 函数，编译后会成为 `libc.so` 的一部分。其他需要使用这些功能的模块（例如，系统服务、应用程序）会在运行时通过 dynamic linker 加载 `libc.so` 并解析这些函数的地址。

**so 布局样本和链接的处理过程:**

假设 `libc.so` 的布局简化如下：

```
libc.so:
  .text:  // 包含可执行代码
    ...
    ether_aton_r:  // ether_aton_r 函数的代码
      ...
    ether_aton:    // ether_aton 函数的代码
      ...
    ether_ntoa_r:  // ether_ntoa_r 函数的代码
      ...
    ether_ntoa:    // ether_ntoa 函数的代码
      ...
  .rodata: // 包含只读数据
    ...
  .data:   // 包含可读写数据
    ...
```

当一个 Android 进程（比如一个应用）需要使用 `ether_aton` 函数时，链接过程如下：

1. **编译时链接 (Compile-time Linking):**  编译器在编译应用程序的代码时，如果遇到了 `ether_aton` 等函数调用，会生成一个对该符号的未解析引用。
2. **加载时链接 (Load-time Linking):** 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
3. **符号解析 (Symbol Resolution):** dynamic linker 会读取应用程序 ELF 文件中的动态链接信息，找到对 `ether_aton` 的未解析引用。然后，它会在已经加载的共享库（如 `libc.so`）的符号表（symbol table）中查找名为 `ether_aton` 的符号。
4. **地址重定位 (Address Relocation):**  一旦找到 `ether_aton` 的定义，dynamic linker 会将应用程序中对 `ether_aton` 的调用地址重定向到 `libc.so` 中 `ether_aton` 函数的实际地址。

**假设输入与输出 (逻辑推理):**

**`ether_aton_r`:**

* **假设输入:** `asc = "00:1A:2B:3C:4D:5E"`, `addr` 指向一个 `ether_addr` 结构体。
* **输出:** `addr->ether_addr_octet` 将会是 `{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}`，函数返回 `addr`。
* **假设输入 (错误):** `asc = "00:1A:2B:3C:4D"`, `addr` 指向一个 `ether_addr` 结构体。
* **输出:** 函数返回 `NULL`，因为输入的冒号分隔的十六进制数少于 6 个。
* **假设输入 (错误):** `asc = "00:1A:2B:3C:4D:GG"`, `addr` 指向一个 `ether_addr` 结构体。
* **输出:** 函数返回 `NULL`，因为 "GG" 不是有效的十六进制数。

**`ether_ntoa_r`:**

* **假设输入:** `addr->ether_addr_octet = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}`, `buf` 指向一个至少 18 字节的缓冲区。
* **输出:** `buf` 中将会存储字符串 `"00:1a:2b:3c:4d:5e"`，函数返回 `buf`。

**用户或编程常见的使用错误:**

1. **使用非线程安全版本 ( `ether_aton`, `ether_ntoa` ) 在多线程环境中:**  由于这些函数使用静态缓冲区，多个线程同时调用可能会导致数据竞争和未定义的行为。应该优先使用 `ether_aton_r` 和 `ether_ntoa_r`。

   ```c
   #include <stdio.h>
   #include <pthread.h>
   #include <netinet/ether.h>

   void* thread_func(void* arg) {
       const char* mac_str = "AA:BB:CC:DD:EE:FF";
       struct ether_addr* addr = ether_aton(mac_str); // 错误用法！
       if (addr) {
           printf("Thread ID: %lu, MAC: %s\n", pthread_self(), ether_ntoa(addr)); // 错误用法！
       }
       return NULL;
   }

   int main() {
       pthread_t threads[2];
       for (int i = 0; i < 2; ++i) {
           pthread_create(&threads[i], NULL, thread_func, NULL);
       }
       for (int i = 0; i < 2; ++i) {
           pthread_join(threads[i], NULL);
       }
       return 0;
   }
   ```
   在这个例子中，两个线程同时调用 `ether_aton` 和 `ether_ntoa`，它们都使用静态缓冲区，可能导致输出的 MAC 地址不一致或错误。

2. **`ether_ntoa_r` 提供的缓冲区过小:**  如果传递给 `ether_ntoa_r` 的缓冲区小于 18 字节，将会发生缓冲区溢出。

   ```c
   #include <stdio.h>
   #include <netinet/ether.h>

   int main() {
       struct ether_addr addr = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
       char buf[10]; // 缓冲区太小
       ether_ntoa_r(&addr, buf); // 潜在的缓冲区溢出
       printf("MAC: %s\n", buf);
       return 0;
   }
   ```

3. **`ether_aton_r` 输入字符串格式错误:**  如果输入的字符串不是正确的冒号分隔的十六进制格式，`ether_aton_r` 将返回 `NULL`，但如果调用者没有检查返回值，就会导致空指针解引用等错误。

   ```c
   #include <stdio.h>
   #include <netinet/ether.h>
   #include <stdlib.h>

   int main() {
       const char* mac_str = "00-11-22-33-44-55"; // 错误的格式
       struct ether_addr addr;
       ether_addr* result = ether_aton_r(mac_str, &addr);
       if (result == NULL) {
           fprintf(stderr, "Error: Invalid MAC address format.\n");
           return 1;
       }
       // 如果没有检查 result，这里可能会导致错误
       printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
              addr.ether_addr_octet[0], addr.ether_addr_octet[1],
              addr.ether_addr_octet[2], addr.ether_addr_octet[3],
              addr.ether_addr_octet[4], addr.ether_addr_octet[5]);
       return 0;
   }
   ```

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework:**
   - 很多系统服务（例如 `ConnectivityService`，负责处理网络连接）需要获取和处理设备的 MAC 地址。
   - 当 Framework 需要获取网络接口的信息时，可能会调用底层的 HAL (Hardware Abstraction Layer) 层。
   - HAL 层会调用 Linux 内核的 Netlink 接口或者 ioctl 系统调用来获取网络接口信息，其中包括 MAC 地址。
   - 内核返回的 MAC 地址通常是二进制格式。
   - Framework 中的 Java 代码（通过 JNI 调用 Native 代码）或者 Native 系统服务可能会调用 `ether_ntoa` 或 `ether_ntoa_r` 将二进制 MAC 地址转换为字符串，以便在 UI 上显示或者进行其他处理。

2. **Android NDK:**
   - 使用 NDK 开发的应用程序可以直接调用 C 标准库函数，包括 `ether_aton` 和 `ether_ntoa`。
   - 例如，一个需要监控网络流量或者进行底层网络操作的 NDK 应用可能会使用这些函数来解析或格式化 MAC 地址。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook 调试 `ether_aton` 函数的示例：

```python
import frida
import sys

# 要 hook 的进程名称或 PID
package_name = "com.example.myapp"  # 替换为你的应用包名

# Frida script
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ether_aton"), {
    onEnter: function(args) {
        console.log("[+] ether_aton called");
        console.log("    Argument (asc): " + Memory.readUtf8String(args[0]));
    },
    onLeave: function(retval) {
        if (retval.isNull()) {
            console.log("    Return value: NULL");
        } else {
            var mac_addr = "";
            for (var i = 0; i < 6; i++) {
                mac_addr += ("0" + Memory.readU8(retval.add(i)).toString(16)).slice(-2);
                if (i < 5) {
                    mac_addr += ":";
                }
            }
            console.log("    Return value (ether_addr*): " + mac_addr);
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # Keep the script running
except frida.ProcessNotFoundError:
    print(f"Error: Process with name '{package_name}' not found.")
except Exception as e:
    print(e)
```

**步骤说明:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定目标进程:** 将 `package_name` 替换为你想要调试的 Android 应用的包名。
3. **编写 Frida 脚本:**
   - `Module.findExportByName("libc.so", "ether_aton")`: 找到 `libc.so` 中导出的 `ether_aton` 函数。
   - `Interceptor.attach(...)`:  拦截对 `ether_aton` 函数的调用。
   - `onEnter`: 在函数执行前调用。
     - `args[0]`:  获取 `ether_aton` 的第一个参数，即指向 MAC 地址字符串的指针。
     - `Memory.readUtf8String(args[0])`: 读取该字符串并打印。
   - `onLeave`: 在函数执行后调用。
     - `retval`: 获取 `ether_aton` 的返回值，即指向 `ether_addr` 结构体的指针。
     - 读取 `ether_addr` 结构体中的 6 个字节，并将其格式化为 MAC 地址字符串并打印。
4. **创建 Frida Session 和 Script:**
   - `frida.get_usb_device().attach(package_name)`: 连接到 USB 设备上的目标进程。
   - `session.create_script(script_code)`: 创建 Frida 脚本。
   - `script.on('message', on_message)`: 设置消息处理函数，用于接收脚本中的 `console.log` 输出。
   - `script.load()`: 加载并执行脚本。
5. **保持脚本运行:** `sys.stdin.read()` 阻止脚本立即退出。
6. **运行你的 Android 应用:** 当你的应用调用到 `ether_aton` 函数时，Frida 脚本将会拦截并打印相关信息。

你可以使用类似的 `Interceptor.attach` 方法来 hook `ether_aton_r`, `ether_ntoa`, 和 `ether_ntoa_r` 函数，以观察它们的参数和返回值，从而理解 Android Framework 或 NDK 如何一步步地调用到这些函数。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是目录为bionic/libc/bionic/netinet_ether.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2010 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <netinet/ether.h>

#include <stdio.h>

ether_addr* ether_aton_r(const char* asc, ether_addr* addr) {
  int bytes[ETHER_ADDR_LEN], end;
  int n = sscanf(asc, "%x:%x:%x:%x:%x:%x%n",
                 &bytes[0], &bytes[1], &bytes[2],
                 &bytes[3], &bytes[4], &bytes[5], &end);
  if (n != ETHER_ADDR_LEN || asc[end] != '\0') return NULL;
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    if (bytes[i] > 0xff) return NULL;
    addr->ether_addr_octet[i] = bytes[i];
  }
  return addr;
}

struct ether_addr* ether_aton(const char* asc) {
  static ether_addr addr;
  return ether_aton_r(asc, &addr);
}

char* ether_ntoa_r(const ether_addr* addr, char* buf) {
  snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
           addr->ether_addr_octet[0], addr->ether_addr_octet[1],
           addr->ether_addr_octet[2], addr->ether_addr_octet[3],
           addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
  return buf;
}

char* ether_ntoa(const ether_addr* addr) {
  static char buf[18];
  return ether_ntoa_r(addr, buf);
}
```