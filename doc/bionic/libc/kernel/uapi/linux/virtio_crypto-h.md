Response:
Let's break down the thought process for answering the user's request about the `virtio_crypto.h` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this header file, its relationship to Android, details about its implementation (especially libc functions and the dynamic linker), common usage errors, and how Android components reach this low-level code. They also requested a Frida hook example.

**2. Initial Analysis of the Header File:**

The first step is to scan the header file for key indicators of its purpose. I noticed:

* **`#ifndef _VIRTIO_CRYPTO_H`:**  Standard header guard, indicating this file defines a set of structures and constants.
* **`#include <linux/types.h>`, `#include <linux/virtio_types.h>`, etc.:** This immediately tells me it's related to the Linux kernel and the VirtIO framework. VirtIO is a standardized way for virtual machines to interact with their host operating system.
* **`VIRTIO_CRYPTO_SERVICE_CIPHER`, `VIRTIO_CRYPTO_SERVICE_HASH`, etc.:** These constants suggest different cryptographic services are being defined.
* **`struct virtio_crypto_ctrl_header`, `struct virtio_crypto_cipher_session_para`, etc.:**  The file defines various structures. The naming convention strongly suggests they are used to send control commands and data related to cryptographic operations. "Session" implies the concept of establishing and managing cryptographic contexts.
* **`VIRTIO_CRYPTO_CIPHER_CREATE_SESSION`, `VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION`, etc.:** These macros define specific opcodes for controlling cryptographic sessions.
* **Endianness:** The use of `__le32` and `__le64` indicates little-endian byte order, common in embedded systems and hardware interfaces.
* **Comments:** The comment at the beginning explicitly mentions that the file is auto-generated and located within the Bionic library.

**3. Connecting to Android:**

Given that the file is in `bionic/libc/kernel/uapi/linux/`, the connection to Android is clear. Bionic is Android's C library. The `kernel/uapi` part signifies that this is a header file exposing kernel-level interfaces to userspace. This means Android applications or system services *could* potentially interact with these interfaces, although it's typically through higher-level abstractions.

**4. Deducing Functionality:**

Based on the names and structure definitions, I could deduce the core functionality:

* **Cryptographic Services:**  The file defines interfaces for cipher operations (encryption/decryption), hashing, message authentication codes (MACs), authenticated encryption with associated data (AEAD), and asymmetric key cryptography.
* **Session Management:** The "create session" and "destroy session" opcodes and associated structures indicate a mechanism for establishing and tearing down cryptographic contexts. This is essential for managing cryptographic state.
* **Operation Requests:** The "op_data_req" structures are clearly used to send requests for performing cryptographic operations (encrypt, decrypt, hash, sign, verify).
* **VirtIO Interface:** The "virtio_" prefix strongly suggests this is part of the VirtIO framework, enabling communication with a virtualized cryptographic device.

**5. Addressing Specific User Questions:**

* **List of Functions:** I translated the identified functionalities into a list.
* **Relationship to Android:**  I explained that this provides a low-level interface for hardware-accelerated or virtualized cryptography within Android. I provided examples of how this *might* be used indirectly by higher-level Android components.
* **libc Function Implementation:**  This was a tricky part. The header file *defines* structures and constants, it doesn't *implement* libc functions. I clarified this, explaining that the *implementation* would reside in the kernel driver associated with the VirtIO crypto device.
* **Dynamic Linker:**  Again, this header file doesn't directly involve the dynamic linker. I explained that it's a *definition* file. I provided a general explanation of how shared libraries are structured and linked in Android. I created a hypothetical scenario illustrating library linking and function calls to a hypothetical library that *uses* this header.
* **Logical Inference:** I provided examples of how the opcode macros are constructed and how different structures relate to specific cryptographic operations.
* **Common Usage Errors:** I focused on common programming errors related to memory management, incorrect parameter usage, and session management, as these are typical pitfalls when working with low-level APIs.
* **Android Framework/NDK to This Point:** This required a more detailed explanation of the Android software stack. I described the path from user applications, through the Framework (Java and native layers), potentially using the NDK for native cryptographic libraries, which could then interact with the kernel through the VirtIO interface defined in this header.
* **Frida Hook Example:**  I provided a basic Frida script demonstrating how to hook one of the core functions (like creating a session) to observe the parameters being passed. I chose a relevant function and showed how to log the `opcode` value.

**6. Structuring the Answer:**

I organized the answer logically, addressing each of the user's points in turn. I used clear headings and bullet points to improve readability. I tried to explain complex concepts in a way that is understandable to someone who may not be deeply familiar with kernel internals or VirtIO.

**7. Iterative Refinement (Self-Correction):**

While writing, I double-checked my understanding of the terms and concepts involved. For instance, I made sure to emphasize the difference between *defining* an interface (the header file) and *implementing* it (the kernel driver). I also considered the level of detail appropriate for each point, trying to be informative without being overly technical. I recognized that the user's request about libc function implementation was slightly misdirected, and I clarified that the *kernel driver* would be responsible. Similarly, for the dynamic linker, I focused on the *potential* connection through hypothetical libraries using the defined interface.
这是一个定义 Linux 内核中 VirtIO 框架下加密设备接口的头文件。它为用户空间程序（比如 Android 系统服务或 NDK 应用）提供了一种与虚拟化或硬件加速的加密设备进行通信的方式。

**它的功能:**

1. **定义了与 VirtIO 加密设备通信的数据结构：**  该文件定义了用于控制和数据传输的各种结构体，例如：
    * `virtio_crypto_ctrl_header`:  用于发送控制命令，如创建或销毁加密会话。
    * `virtio_crypto_cipher_session_para`:  定义了密码会话的参数，例如算法、密钥长度和操作类型（加密/解密）。
    * `virtio_crypto_hash_session_para`: 定义了哈希会话的参数，例如哈希算法和结果长度。
    * `virtio_crypto_op_data_req`: 用于发送实际的加密操作请求。
2. **定义了加密服务的类型：**  通过 `VIRTIO_CRYPTO_SERVICE_*` 系列宏定义了不同的加密服务，如对称加密（CIPHER）、哈希（HASH）、消息认证码（MAC）、认证加密（AEAD）和非对称加密（AKCIPHER）。
3. **定义了各种加密算法的标识符：**  例如 `VIRTIO_CRYPTO_CIPHER_AES_CBC`、`VIRTIO_CRYPTO_HASH_SHA256` 等，用于指定具体的加密算法。
4. **定义了操作码（Opcode）：** 通过 `VIRTIO_CRYPTO_OPCODE` 宏和一系列的 `VIRTIO_CRYPTO_*_*` 宏定义了各种操作的唯一标识符，例如创建密码会话、执行加密操作等。
5. **定义了状态码和配置信息：**  定义了操作成功或失败的状态码（如 `VIRTIO_CRYPTO_OK`, `VIRTIO_CRYPTO_ERR`）以及设备的配置信息结构体 `virtio_crypto_config`。

**与 Android 功能的关系及举例说明:**

该头文件定义的是 Linux 内核接口，Android 作为基于 Linux 内核的操作系统，其底层加密框架可能会使用到这个接口。虽然开发者通常不会直接使用这个头文件中定义的结构体，但 Android Framework 或 NDK 中的加密库（例如 Java Cryptography Architecture (JCA) 的 Provider 实现，或者 OpenSSL 等 Native 加密库）可能会在底层利用这种 VirtIO 加密设备来加速加密操作。

**举例说明:**

假设 Android 系统运行在一个虚拟机上，宿主机提供了硬件加速的加密功能，并通过 VirtIO 暴露给虚拟机。Android Framework 中的一个应用程序需要执行 AES 加密操作：

1. **应用程序调用 Framework 层的加密 API:**  比如 `javax.crypto.Cipher`。
2. **Framework 层选择合适的 Provider:**  根据配置，可能会选择一个利用硬件加速的 Provider。
3. **Provider 与 Native 层交互:** 该 Provider 的 Native 实现（可能是通过 JNI 调用）可能会使用 NDK 提供的加密库（如 Conscrypt，它也可能使用 OpenSSL）。
4. **Native 加密库与内核交互:**  Native 加密库如果检测到有 VirtIO 加密设备可用，可能会构造 `virtio_crypto_op_ctrl_req` 和 `virtio_crypto_op_data_req` 结构体，通过 VirtIO 通道发送给内核驱动。这些结构体的定义就来源于 `virtio_crypto.h`。
5. **内核驱动处理请求:**  内核中的 VirtIO 加密设备驱动接收到请求后，会调用底层的硬件加速功能完成加密操作，并将结果返回给用户空间。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是定义了数据结构和常量。  `virtio_crypto.h` 是一个内核头文件，用于定义用户空间与内核 VirtIO 加密驱动交互的接口。

用户空间程序（包括 Android 的库）会使用标准的 Linux 系统调用（例如 `open`, `ioctl`, `read`, `write`, `mmap` 等）来与 VirtIO 设备进行交互。 这些系统调用是 libc 提供的，它们的实现位于 Bionic 的内核接口部分。

**例如，一个程序可能需要创建 VirtIO 设备文件描述符，并使用 `ioctl` 系统调用来发送控制命令，例如创建加密会话。**  `ioctl` 函数的实现会涉及到 Bionic 将用户空间的请求转换为内核能够理解的格式，并触发相应的内核操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`virtio_crypto.h` 本身并不直接涉及 dynamic linker。 它定义的是内核接口，而 dynamic linker 主要负责链接和加载用户空间的共享库（.so 文件）。

**但是，如果用户空间的加密库（例如上面提到的 Conscrypt 或 OpenSSL 的 .so 文件）需要使用 VirtIO 加密设备，那么 dynamic linker 会参与加载这些库，并且这些库内部可能会包含与内核 VirtIO 设备交互的代码。**

**so 布局样本 (假设一个名为 `libmycrypto.so` 的库使用了 VirtIO 加密):**

```
libmycrypto.so:
    .text          # 包含代码段
        my_encrypt_function:
            # ... 调用内部函数与 VirtIO 设备通信 ...
    .data          # 包含初始化数据
    .rodata        # 包含只读数据
    .bss           # 包含未初始化数据
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # Procedure Linkage Table (PLT)
    .got.plt       # Global Offset Table (GOT) for PLT
    .rela.dyn      # 重定位表 (dynamic)
    .rela.plt      # 重定位表 (PLT)
```

**链接的处理过程:**

1. **编译时链接:**  当编译使用 `libmycrypto.so` 的应用程序时，编译器会记录下需要链接的共享库。
2. **加载时链接:** 当应用程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库。
3. **查找依赖:** dynamic linker 会解析应用程序的 ELF 头，找到需要的共享库列表。
4. **加载共享库:** dynamic linker 会在预定义的路径中查找共享库文件，并将其加载到内存中。
5. **符号解析和重定位:**
   * **PLT 和 GOT:**  `libmycrypto.so` 中可能调用了操作系统提供的与 VirtIO 设备交互的函数（例如 `open`, `ioctl`）。这些外部函数的地址在编译时是未知的。
   * **PLT 条目:** 对于每个外部函数调用，编译器会在 PLT 中生成一个条目。
   * **GOT 条目:**  每个 PLT 条目对应一个 GOT 条目，初始时 GOT 条目包含 PLT 条目的地址。
   * **首次调用:** 当第一次调用外部函数时，会跳转到 PLT 条目。PLT 条目中的代码会调用 dynamic linker 辅助函数。
   * **dynamic linker 解析:** dynamic linker 会在已加载的共享库（例如 Bionic libc）中查找该函数的地址。
   * **更新 GOT:**  dynamic linker 将找到的函数地址写入对应的 GOT 条目。
   * **后续调用:**  后续对该函数的调用会直接通过 GOT 条目跳转到正确的函数地址，避免了重复的解析过程。

**假设输入与输出 (逻辑推理):**

假设一个用户空间程序想要创建一个用于 AES-CBC 加密的 VirtIO 会话：

**假设输入 (构造 `virtio_crypto_op_ctrl_req` 结构体):**

```c
struct virtio_crypto_op_ctrl_req ctrl_req;

ctrl_req.header.opcode = VIRTIO_CRYPTO_CIPHER_CREATE_SESSION;
ctrl_req.header.algo = VIRTIO_CRYPTO_CIPHER_AES_CBC;
ctrl_req.header.flag = 0; // 没有特殊标志
ctrl_req.header.queue_id = 0; // 使用默认队列

ctrl_req.u.sym_create_session.op_type = VIRTIO_CRYPTO_SYM_OP_CIPHER;
ctrl_req.u.sym_create_session.u.cipher.para.algo = VIRTIO_CRYPTO_CIPHER_AES_CBC;
ctrl_req.u.sym_create_session.u.cipher.para.keylen = 16; // 128-bit 密钥
ctrl_req.u.sym_create_session.u.cipher.para.op = VIRTIO_CRYPTO_OP_ENCRYPT; // 或者 VIRTIO_CRYPTO_OP_DECRYPT
ctrl_req.u.sym_create_session.u.cipher.para.padding = 0;
// ... 其他字段设置为默认值或根据需要设置 ...
```

**假设输出 (内核返回的响应):**

如果创建会话成功，内核可能会通过 VirtIO 通道返回一个 `virtio_crypto_session_input` 结构体：

```c
struct virtio_crypto_session_input session_input;

session_input.session_id = 12345; // 新创建的会话 ID
session_input.status = VIRTIO_CRYPTO_OK;
```

如果创建失败，`session_input.status` 可能会是 `VIRTIO_CRYPTO_NOTSUPP`（如果不支持 AES-CBC）或其他错误码。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确设置结构体字段:**  例如，忘记设置 `keylen` 或者设置了错误的算法 ID。这会导致内核无法正确创建会话或执行操作。
2. **内存管理错误:**  在构造请求结构体时，如果内存分配不足或者使用了已释放的内存，会导致程序崩溃或数据损坏。
3. **会话管理错误:**  例如，尝试使用一个已经销毁的会话 ID，或者在没有创建会话的情况下尝试执行加密操作。这会导致内核返回 `VIRTIO_CRYPTO_INVSESS` 错误。
4. **缓冲区溢出:**  在加密或解密时，提供的输出缓冲区可能小于实际需要的长度，导致数据溢出。
5. **竞争条件:**  如果多个线程同时尝试访问同一个 VirtIO 设备或会话，可能会导致数据竞争和不可预测的结果。需要使用适当的同步机制（例如互斥锁）来保护共享资源。
6. **字节序问题:**  结构体中的字段使用了 `__le32` 和 `__le64` 表示小端字节序。如果用户空间的程序运行在大端字节序的架构上，需要进行字节序转换，否则发送给内核的数据可能无法被正确解析。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**路径示例：Android Framework 到 VirtIO 加密设备**

1. **Android 应用层:** 应用调用 `javax.crypto.Cipher` 类进行加密操作。
2. **Java Framework (`android.security.keystore` 等):** Framework 层的加密 API 会选择合适的 Provider 实现。
3. **Native Framework (JNI 调用):**  如果选择了使用硬件加速的 Provider，Framework 可能会通过 JNI 调用 Native 层的加密库。例如，Android 的 Conscrypt 库。
4. **NDK 加密库 (例如 Conscrypt, OpenSSL):**  这些库内部会包含与底层加密设备交互的代码。
5. **VirtIO 用户空间库 (如果存在):**  某些实现可能会有一个中间层库来封装与 VirtIO 设备的交互。
6. **系统调用 (ioctl):**  最终，用户空间的库会使用 `ioctl` 系统调用向内核的 VirtIO 加密设备驱动发送控制和数据请求，请求的结构体定义在 `virtio_crypto.h` 中。
7. **Linux Kernel (VirtIO 加密设备驱动):** 内核驱动接收请求，与虚拟化或硬件加密设备通信，完成加密操作，并将结果返回给用户空间。

**Frida Hook 示例**

我们可以使用 Frida Hook `ioctl` 系统调用，并检查传递给它的参数，来观察与 VirtIO 加密设备的交互。

**假设我们想观察创建 VirtIO 加密会话的过程，即 `VIRTIO_CRYPTO_CIPHER_CREATE_SESSION` 操作。**

```python
import frida
import sys

# 要 Hook 的进程名称
package_name = "com.example.myapp"  # 替换为你的应用包名

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 假设 VirtIO 加密设备的文件描述符范围
        // 你可能需要根据实际情况调整这个范围
        if (fd > 3 && fd < 100) {
            // 检查是否是 VirtIO 控制命令 (可能需要进一步判断)
            if ((request & 0xFF) == 0xCA) { // 假设 VirtIO 魔数是 0xCA
                console.log("ioctl called with fd:", fd, "request:", request.toString(16));

                // 检查是否是创建会话的请求码
                if (request == 0xCA02) { // 假设创建会话的 ioctl 请求码
                    console.log("Potential VirtIO crypto CREATE_SESSION command!");

                    // 读取 virtio_crypto_op_ctrl_req 结构体
                    const ctrl_req_ptr = argp;
                    const opcode = ctrl_req_ptr.readU32();
                    const algo = ctrl_req_ptr.add(4).readU32();

                    console.log("Opcode:", opcode.toString(16));
                    console.log("Algorithm:", algo.toString(16));
                }
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval.toInt32());
    }
});
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[!] {message}")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 示例:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 应用程序。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 系统调用。`Module.findExportByName(null, "ioctl")` 会在所有已加载的模块中查找 `ioctl` 函数的地址。
3. **`onEnter` 函数:**  在 `ioctl` 函数被调用之前执行。
4. **`args` 参数:**  包含了传递给 `ioctl` 的参数。`args[0]` 是文件描述符，`args[1]` 是请求码，`args[2]` 是指向参数的指针。
5. **文件描述符判断:**  我们简单地假设 VirtIO 加密设备的文件描述符在一个特定的范围内。你需要根据实际情况调整这个范围。
6. **请求码判断:**  我们假设 VirtIO 的控制命令有特定的魔数（例如 `0xCA`）。你需要根据实际的 VirtIO 实现来确定。
7. **读取结构体:**  如果判断是创建会话的请求，我们从 `argp` 指针读取 `virtio_crypto_op_ctrl_req` 结构体的 `opcode` 和 `algo` 字段。
8. **`onLeave` 函数:** 在 `ioctl` 函数返回之后执行（本例中注释掉了）。
9. **`script.on('message', on_message)`:**  设置消息处理函数，用于接收来自 Frida 脚本的日志输出。

**使用步骤:**

1. 将以上 Python 代码保存为 `hook_virtio.py`。
2. 确保你的 Android 设备已 Root，并且安装了 Frida 服务端。
3. 运行目标 Android 应用程序。
4. 在 PC 上运行 `python hook_virtio.py`，将 `com.example.myapp` 替换为你的应用包名。
5. 当应用程序尝试创建 VirtIO 加密会话时，Frida 脚本会在终端输出相关的 `ioctl` 调用信息，包括 `opcode` 和算法。

**注意:**  这只是一个简单的示例。实际的 VirtIO 加密设备交互可能更复杂，你需要根据具体的 Android 版本和硬件实现进行更深入的分析。你需要根据实际的请求码和结构体布局来调整 Frida 脚本。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/virtio_crypto.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _VIRTIO_CRYPTO_H
#define _VIRTIO_CRYPTO_H
#include <linux/types.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#define VIRTIO_CRYPTO_SERVICE_CIPHER 0
#define VIRTIO_CRYPTO_SERVICE_HASH 1
#define VIRTIO_CRYPTO_SERVICE_MAC 2
#define VIRTIO_CRYPTO_SERVICE_AEAD 3
#define VIRTIO_CRYPTO_SERVICE_AKCIPHER 4
#define VIRTIO_CRYPTO_OPCODE(service,op) (((service) << 8) | (op))
struct virtio_crypto_ctrl_header {
#define VIRTIO_CRYPTO_CIPHER_CREATE_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x02)
#define VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x03)
#define VIRTIO_CRYPTO_HASH_CREATE_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x02)
#define VIRTIO_CRYPTO_HASH_DESTROY_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x03)
#define VIRTIO_CRYPTO_MAC_CREATE_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x02)
#define VIRTIO_CRYPTO_MAC_DESTROY_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x03)
#define VIRTIO_CRYPTO_AEAD_CREATE_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x02)
#define VIRTIO_CRYPTO_AEAD_DESTROY_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x03)
#define VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x04)
#define VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x05)
  __le32 opcode;
  __le32 algo;
  __le32 flag;
  __le32 queue_id;
};
struct virtio_crypto_cipher_session_para {
#define VIRTIO_CRYPTO_NO_CIPHER 0
#define VIRTIO_CRYPTO_CIPHER_ARC4 1
#define VIRTIO_CRYPTO_CIPHER_AES_ECB 2
#define VIRTIO_CRYPTO_CIPHER_AES_CBC 3
#define VIRTIO_CRYPTO_CIPHER_AES_CTR 4
#define VIRTIO_CRYPTO_CIPHER_DES_ECB 5
#define VIRTIO_CRYPTO_CIPHER_DES_CBC 6
#define VIRTIO_CRYPTO_CIPHER_3DES_ECB 7
#define VIRTIO_CRYPTO_CIPHER_3DES_CBC 8
#define VIRTIO_CRYPTO_CIPHER_3DES_CTR 9
#define VIRTIO_CRYPTO_CIPHER_KASUMI_F8 10
#define VIRTIO_CRYPTO_CIPHER_SNOW3G_UEA2 11
#define VIRTIO_CRYPTO_CIPHER_AES_F8 12
#define VIRTIO_CRYPTO_CIPHER_AES_XTS 13
#define VIRTIO_CRYPTO_CIPHER_ZUC_EEA3 14
  __le32 algo;
  __le32 keylen;
#define VIRTIO_CRYPTO_OP_ENCRYPT 1
#define VIRTIO_CRYPTO_OP_DECRYPT 2
  __le32 op;
  __le32 padding;
};
struct virtio_crypto_session_input {
  __le64 session_id;
  __le32 status;
  __le32 padding;
};
struct virtio_crypto_cipher_session_req {
  struct virtio_crypto_cipher_session_para para;
  __u8 padding[32];
};
struct virtio_crypto_hash_session_para {
#define VIRTIO_CRYPTO_NO_HASH 0
#define VIRTIO_CRYPTO_HASH_MD5 1
#define VIRTIO_CRYPTO_HASH_SHA1 2
#define VIRTIO_CRYPTO_HASH_SHA_224 3
#define VIRTIO_CRYPTO_HASH_SHA_256 4
#define VIRTIO_CRYPTO_HASH_SHA_384 5
#define VIRTIO_CRYPTO_HASH_SHA_512 6
#define VIRTIO_CRYPTO_HASH_SHA3_224 7
#define VIRTIO_CRYPTO_HASH_SHA3_256 8
#define VIRTIO_CRYPTO_HASH_SHA3_384 9
#define VIRTIO_CRYPTO_HASH_SHA3_512 10
#define VIRTIO_CRYPTO_HASH_SHA3_SHAKE128 11
#define VIRTIO_CRYPTO_HASH_SHA3_SHAKE256 12
  __le32 algo;
  __le32 hash_result_len;
  __u8 padding[8];
};
struct virtio_crypto_hash_create_session_req {
  struct virtio_crypto_hash_session_para para;
  __u8 padding[40];
};
struct virtio_crypto_mac_session_para {
#define VIRTIO_CRYPTO_NO_MAC 0
#define VIRTIO_CRYPTO_MAC_HMAC_MD5 1
#define VIRTIO_CRYPTO_MAC_HMAC_SHA1 2
#define VIRTIO_CRYPTO_MAC_HMAC_SHA_224 3
#define VIRTIO_CRYPTO_MAC_HMAC_SHA_256 4
#define VIRTIO_CRYPTO_MAC_HMAC_SHA_384 5
#define VIRTIO_CRYPTO_MAC_HMAC_SHA_512 6
#define VIRTIO_CRYPTO_MAC_CMAC_3DES 25
#define VIRTIO_CRYPTO_MAC_CMAC_AES 26
#define VIRTIO_CRYPTO_MAC_KASUMI_F9 27
#define VIRTIO_CRYPTO_MAC_SNOW3G_UIA2 28
#define VIRTIO_CRYPTO_MAC_GMAC_AES 41
#define VIRTIO_CRYPTO_MAC_GMAC_TWOFISH 42
#define VIRTIO_CRYPTO_MAC_CBCMAC_AES 49
#define VIRTIO_CRYPTO_MAC_CBCMAC_KASUMI_F9 50
#define VIRTIO_CRYPTO_MAC_XCBC_AES 53
  __le32 algo;
  __le32 hash_result_len;
  __le32 auth_key_len;
  __le32 padding;
};
struct virtio_crypto_mac_create_session_req {
  struct virtio_crypto_mac_session_para para;
  __u8 padding[40];
};
struct virtio_crypto_aead_session_para {
#define VIRTIO_CRYPTO_NO_AEAD 0
#define VIRTIO_CRYPTO_AEAD_GCM 1
#define VIRTIO_CRYPTO_AEAD_CCM 2
#define VIRTIO_CRYPTO_AEAD_CHACHA20_POLY1305 3
  __le32 algo;
  __le32 key_len;
  __le32 hash_result_len;
  __le32 aad_len;
  __le32 op;
  __le32 padding;
};
struct virtio_crypto_aead_create_session_req {
  struct virtio_crypto_aead_session_para para;
  __u8 padding[32];
};
struct virtio_crypto_rsa_session_para {
#define VIRTIO_CRYPTO_RSA_RAW_PADDING 0
#define VIRTIO_CRYPTO_RSA_PKCS1_PADDING 1
  __le32 padding_algo;
#define VIRTIO_CRYPTO_RSA_NO_HASH 0
#define VIRTIO_CRYPTO_RSA_MD2 1
#define VIRTIO_CRYPTO_RSA_MD3 2
#define VIRTIO_CRYPTO_RSA_MD4 3
#define VIRTIO_CRYPTO_RSA_MD5 4
#define VIRTIO_CRYPTO_RSA_SHA1 5
#define VIRTIO_CRYPTO_RSA_SHA256 6
#define VIRTIO_CRYPTO_RSA_SHA384 7
#define VIRTIO_CRYPTO_RSA_SHA512 8
#define VIRTIO_CRYPTO_RSA_SHA224 9
  __le32 hash_algo;
};
struct virtio_crypto_ecdsa_session_para {
#define VIRTIO_CRYPTO_CURVE_UNKNOWN 0
#define VIRTIO_CRYPTO_CURVE_NIST_P192 1
#define VIRTIO_CRYPTO_CURVE_NIST_P224 2
#define VIRTIO_CRYPTO_CURVE_NIST_P256 3
#define VIRTIO_CRYPTO_CURVE_NIST_P384 4
#define VIRTIO_CRYPTO_CURVE_NIST_P521 5
  __le32 curve_id;
  __le32 padding;
};
struct virtio_crypto_akcipher_session_para {
#define VIRTIO_CRYPTO_NO_AKCIPHER 0
#define VIRTIO_CRYPTO_AKCIPHER_RSA 1
#define VIRTIO_CRYPTO_AKCIPHER_DSA 2
#define VIRTIO_CRYPTO_AKCIPHER_ECDSA 3
  __le32 algo;
#define VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PUBLIC 1
#define VIRTIO_CRYPTO_AKCIPHER_KEY_TYPE_PRIVATE 2
  __le32 keytype;
  __le32 keylen;
  union {
    struct virtio_crypto_rsa_session_para rsa;
    struct virtio_crypto_ecdsa_session_para ecdsa;
  } u;
};
struct virtio_crypto_akcipher_create_session_req {
  struct virtio_crypto_akcipher_session_para para;
  __u8 padding[36];
};
struct virtio_crypto_alg_chain_session_para {
#define VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER 1
#define VIRTIO_CRYPTO_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH 2
  __le32 alg_chain_order;
#define VIRTIO_CRYPTO_SYM_HASH_MODE_PLAIN 1
#define VIRTIO_CRYPTO_SYM_HASH_MODE_AUTH 2
#define VIRTIO_CRYPTO_SYM_HASH_MODE_NESTED 3
  __le32 hash_mode;
  struct virtio_crypto_cipher_session_para cipher_param;
  union {
    struct virtio_crypto_hash_session_para hash_param;
    struct virtio_crypto_mac_session_para mac_param;
    __u8 padding[16];
  } u;
  __le32 aad_len;
  __le32 padding;
};
struct virtio_crypto_alg_chain_session_req {
  struct virtio_crypto_alg_chain_session_para para;
};
struct virtio_crypto_sym_create_session_req {
  union {
    struct virtio_crypto_cipher_session_req cipher;
    struct virtio_crypto_alg_chain_session_req chain;
    __u8 padding[48];
  } u;
#define VIRTIO_CRYPTO_SYM_OP_NONE 0
#define VIRTIO_CRYPTO_SYM_OP_CIPHER 1
#define VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING 2
  __le32 op_type;
  __le32 padding;
};
struct virtio_crypto_destroy_session_req {
  __le64 session_id;
  __u8 padding[48];
};
struct virtio_crypto_op_ctrl_req {
  struct virtio_crypto_ctrl_header header;
  union {
    struct virtio_crypto_sym_create_session_req sym_create_session;
    struct virtio_crypto_hash_create_session_req hash_create_session;
    struct virtio_crypto_mac_create_session_req mac_create_session;
    struct virtio_crypto_aead_create_session_req aead_create_session;
    struct virtio_crypto_akcipher_create_session_req akcipher_create_session;
    struct virtio_crypto_destroy_session_req destroy_session;
    __u8 padding[56];
  } u;
};
struct virtio_crypto_op_header {
#define VIRTIO_CRYPTO_CIPHER_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x00)
#define VIRTIO_CRYPTO_CIPHER_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_CIPHER, 0x01)
#define VIRTIO_CRYPTO_HASH VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_HASH, 0x00)
#define VIRTIO_CRYPTO_MAC VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_MAC, 0x00)
#define VIRTIO_CRYPTO_AEAD_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x00)
#define VIRTIO_CRYPTO_AEAD_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AEAD, 0x01)
#define VIRTIO_CRYPTO_AKCIPHER_ENCRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x00)
#define VIRTIO_CRYPTO_AKCIPHER_DECRYPT VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x01)
#define VIRTIO_CRYPTO_AKCIPHER_SIGN VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x02)
#define VIRTIO_CRYPTO_AKCIPHER_VERIFY VIRTIO_CRYPTO_OPCODE(VIRTIO_CRYPTO_SERVICE_AKCIPHER, 0x03)
  __le32 opcode;
  __le32 algo;
  __le64 session_id;
  __le32 flag;
  __le32 padding;
};
struct virtio_crypto_cipher_para {
  __le32 iv_len;
  __le32 src_data_len;
  __le32 dst_data_len;
  __le32 padding;
};
struct virtio_crypto_hash_para {
  __le32 src_data_len;
  __le32 hash_result_len;
};
struct virtio_crypto_mac_para {
  struct virtio_crypto_hash_para hash;
};
struct virtio_crypto_aead_para {
  __le32 iv_len;
  __le32 aad_len;
  __le32 src_data_len;
  __le32 dst_data_len;
};
struct virtio_crypto_cipher_data_req {
  struct virtio_crypto_cipher_para para;
  __u8 padding[24];
};
struct virtio_crypto_hash_data_req {
  struct virtio_crypto_hash_para para;
  __u8 padding[40];
};
struct virtio_crypto_mac_data_req {
  struct virtio_crypto_mac_para para;
  __u8 padding[40];
};
struct virtio_crypto_alg_chain_data_para {
  __le32 iv_len;
  __le32 src_data_len;
  __le32 dst_data_len;
  __le32 cipher_start_src_offset;
  __le32 len_to_cipher;
  __le32 hash_start_src_offset;
  __le32 len_to_hash;
  __le32 aad_len;
  __le32 hash_result_len;
  __le32 reserved;
};
struct virtio_crypto_alg_chain_data_req {
  struct virtio_crypto_alg_chain_data_para para;
};
struct virtio_crypto_sym_data_req {
  union {
    struct virtio_crypto_cipher_data_req cipher;
    struct virtio_crypto_alg_chain_data_req chain;
    __u8 padding[40];
  } u;
  __le32 op_type;
  __le32 padding;
};
struct virtio_crypto_aead_data_req {
  struct virtio_crypto_aead_para para;
  __u8 padding[32];
};
struct virtio_crypto_akcipher_para {
  __le32 src_data_len;
  __le32 dst_data_len;
};
struct virtio_crypto_akcipher_data_req {
  struct virtio_crypto_akcipher_para para;
  __u8 padding[40];
};
struct virtio_crypto_op_data_req {
  struct virtio_crypto_op_header header;
  union {
    struct virtio_crypto_sym_data_req sym_req;
    struct virtio_crypto_hash_data_req hash_req;
    struct virtio_crypto_mac_data_req mac_req;
    struct virtio_crypto_aead_data_req aead_req;
    struct virtio_crypto_akcipher_data_req akcipher_req;
    __u8 padding[48];
  } u;
};
#define VIRTIO_CRYPTO_OK 0
#define VIRTIO_CRYPTO_ERR 1
#define VIRTIO_CRYPTO_BADMSG 2
#define VIRTIO_CRYPTO_NOTSUPP 3
#define VIRTIO_CRYPTO_INVSESS 4
#define VIRTIO_CRYPTO_NOSPC 5
#define VIRTIO_CRYPTO_KEY_REJECTED 6
#define VIRTIO_CRYPTO_S_HW_READY (1 << 0)
struct virtio_crypto_config {
  __le32 status;
  __le32 max_dataqueues;
  __le32 crypto_services;
  __le32 cipher_algo_l;
  __le32 cipher_algo_h;
  __le32 hash_algo;
  __le32 mac_algo_l;
  __le32 mac_algo_h;
  __le32 aead_algo;
  __le32 max_cipher_key_len;
  __le32 max_auth_key_len;
  __le32 akcipher_algo;
  __le64 max_size;
};
struct virtio_crypto_inhdr {
  __u8 status;
};
#endif

"""

```