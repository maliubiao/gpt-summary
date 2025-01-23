Response:
Let's break down the thought process for answering the user's request about `cryptouser.h`.

**1. Understanding the Core Request:**

The user has provided a header file (`cryptouser.h`) and wants to understand its purpose and how it relates to Android. Key aspects they are interested in include: functionality, relationship to Android, implementation details (specifically libc functions and dynamic linking), potential errors, and how Android reaches this code (including debugging).

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_LINUX_CRYPTOUSER_H`:**  This is a standard include guard, meaning this file defines structures and constants related to a crypto user interface within the Linux kernel's UAPI (User API) layer. The `uapi` strongly suggests it's for communication between user-space applications and the kernel.
* **`enum`s (CRYPTO_MSG_BASE, crypto_attr_type_t):** These define sets of constants. The `CRYPTO_MSG_` constants likely represent different types of messages passed between user-space and the kernel's crypto subsystem. `crypto_attr_type_t` likely describes attributes or categories of crypto algorithms or reports.
* **`struct crypto_user_alg`:** This structure probably describes a cryptographic algorithm that a user-space application wants to interact with. It contains names (algorithm, driver, module), type, mask, reference count, and flags.
* **`struct crypto_stat_*`:** These structures seem to hold statistics about the usage of different cryptographic algorithms (AEAD, AKCipher, Cipher, etc.). They track things like encryption/decryption counts, data lengths, and error counts.
* **`struct crypto_report_*`:** These structures appear to provide information *about* different cryptographic algorithms. For example, `crypto_report_hash` has `blocksize` and `digestsize`.
* **`#define CRYPTO_REPORT_MAXSIZE`:** This defines a maximum size, likely for a buffer used to receive report information.

**3. Connecting to Android:**

Given that this is in `bionic/libc/kernel/uapi/linux/`, it's clear this is part of Android's adaptation of the Linux kernel headers for its C library. The presence of "crypto" strongly implies it's related to Android's cryptographic capabilities. Android applications often need to perform cryptographic operations (encryption, decryption, hashing, signing, etc.).

**4. Addressing Specific User Questions:**

* **Functionality:** Summarize the purpose of the header file – defining the interface for user-space programs to interact with the kernel's crypto API. List the main categories of information provided (algorithm definitions, statistics, reports).
* **Relationship to Android:** Explain that Android applications use this interface indirectly. The Android framework and NDK provide higher-level APIs that eventually translate into interactions with the kernel crypto subsystem defined here. Provide concrete examples like encryption/decryption for secure storage or network communication.
* **libc Function Implementation:** This is a trickier question. This header *defines* the interface, it doesn't *implement* the libc functions that *use* this interface. The *implementation* would be in the kernel itself or in other parts of `bionic`. It's crucial to distinguish between definition and implementation. Explain that system calls (like `ioctl`) are likely involved.
* **Dynamic Linker:** The header file itself *doesn't* directly involve the dynamic linker. However, the *libraries* that use these definitions (likely within `bionic`) *will* be dynamically linked. Provide a simplified SO layout example and explain the linking process (symbol resolution, relocation).
* **Logical Reasoning (Hypothetical Input/Output):**  Illustrate how a user-space program might use these structures. Imagine sending a `CRYPTO_MSG_NEWALG` message with a populated `crypto_user_alg` structure to register a new algorithm. Conversely, receiving a `CRYPTO_MSG_GETSTAT` might return a populated `crypto_stat_hash` structure.
* **User/Programming Errors:** Think about common mistakes when interacting with such a low-level interface: incorrect sizes, invalid message types, not checking return codes, buffer overflows.
* **Android Framework/NDK Path:**  Trace the likely path from a high-level Android API (e.g., `Cipher` in Java or the NDK's cryptographic functions) down to the system call level that interacts with the kernel's crypto API defined here.
* **Frida Hook Example:**  Provide a simple Frida script to hook a hypothetical system call related to crypto (like `ioctl`) to observe interactions with these structures. Focus on demonstrating how to read the relevant data structures.

**5. Structuring the Answer:**

Organize the answer logically, following the user's questions. Use clear headings and bullet points to improve readability. Provide code examples where appropriate.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus too much on the header file itself as the "implementation."  Realization: This is the *interface* definition. The implementation is elsewhere.
* **Considering the Dynamic Linker:**  Acknowledge that while this specific header isn't the focus of the dynamic linker, the libraries using it *are*. Provide a relevant explanation of SO layout and linking.
* **Frida Hook Detail:** Keep the Frida example relatively simple, focusing on the core idea of intercepting system calls and inspecting data structures. Don't get bogged down in overly complex hooking scenarios.

By following this structured approach, combining analysis of the code with understanding the user's questions, and performing some self-correction, a comprehensive and accurate answer can be generated.
这是一个定义了 Linux 内核中用于与加密子系统用户空间接口交互的头文件。它并不直接包含 libc 函数的实现或动态链接器的功能，但定义了用户空间程序与内核加密模块通信所需的数据结构和常量。

**功能列举:**

1. **定义加密消息类型:**  定义了用户空间程序可以发送给内核加密子系统的各种消息类型，例如：
    * `CRYPTO_MSG_NEWALG`:  请求注册一个新的加密算法。
    * `CRYPTO_MSG_DELALG`: 请求删除一个已注册的加密算法。
    * `CRYPTO_MSG_UPDATEALG`: 请求更新一个已注册的加密算法。
    * `CRYPTO_MSG_GETALG`: 请求获取一个已注册的加密算法的信息。
    * `CRYPTO_MSG_DELRNG`: 请求删除一个随机数生成器。
    * `CRYPTO_MSG_GETSTAT`: 请求获取加密算法的统计信息。

2. **定义加密属性类型:**  定义了用于描述加密算法属性的类型，例如不同类型的报告和统计信息。

3. **定义数据结构:** 定义了用于在用户空间和内核空间之间传递信息的结构体：
    * `crypto_user_alg`: 描述一个加密算法的属性，包括名称、驱动名称、模块名称、类型、掩码、引用计数和标志。
    * `crypto_stat_*`:  用于报告各种加密操作的统计信息，例如加密、解密、哈希、压缩、随机数生成等操作的次数和数据量，以及错误计数。例如，`crypto_stat_aead` 记录 AEAD (Authenticated Encryption with Associated Data) 算法的加密、解密次数和数据长度。
    * `crypto_report_*`:  用于报告各种加密算法的详细信息，例如块大小、密钥大小、摘要大小等。例如，`crypto_report_hash` 报告哈希算法的块大小和摘要大小。

**与 Android 功能的关系及举例说明:**

Android 依赖 Linux 内核的加密子系统来提供各种安全功能。这个头文件中定义的接口是 Android 框架和应用程序与内核加密模块交互的基础。

**举例说明:**

* **文件系统加密 (File-Based Encryption, FBE) 和 全盘加密 (Full-Disk Encryption, FDE):**  Android 使用内核的加密功能来加密存储在设备上的数据。当 Android 需要使用特定的加密算法（例如 AES）来加密或解密数据时，框架或底层库会通过系统调用与内核进行通信。这个头文件中定义的 `CRYPTO_MSG_NEWALG` 可能在系统启动时用于注册加密算法。
* **HTTPS 连接:**  当 Android 应用发起 HTTPS 连接时，TLS/SSL 协议会使用各种加密算法来保护通信安全。Android 的网络库会使用底层的加密库，最终可能通过内核的加密接口来执行加密和解密操作。例如，`crypto_stat_cipher` 可以记录用于 HTTPS 连接的对称加密算法的使用统计。
* **Android Keystore 系统:**  Android Keystore 系统允许应用安全地存储加密密钥。当应用需要使用 Keystore 中的密钥进行加密或签名操作时，可能会涉及到与内核加密模块的交互。
* **VPN 连接:**  VPN 应用在建立安全隧道时也会使用各种加密算法。

**libc 函数的功能实现:**

这个头文件本身并没有定义或实现任何 libc 函数。它只是定义了数据结构和常量。用户空间程序通常不会直接包含这个头文件并使用其中的结构体。 相反，Android 的 Bionic libc 中会包含一些封装了与内核加密子系统交互的函数，这些函数会使用到这里定义的数据结构。

与内核交互通常通过 **系统调用 (system call)** 来完成，例如 `ioctl`。用户空间的 libc 函数会调用 `ioctl` 系统调用，并将适当的命令（例如 `CRYPTO_MSG_NEWALG`）和数据结构传递给内核。内核接收到系统调用后，会根据命令和数据执行相应的操作。

**例如，一个可能的 libc 函数（并非实际存在于 libc 中，仅为说明概念）:**

```c
#include <sys/ioctl.h>
#include <linux/cryptouser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int register_crypto_algorithm(const char *name, const char *driver_name) {
    int fd = open("/dev/crypto", O_RDWR); // 假设内核提供一个 /dev/crypto 设备
    if (fd < 0) {
        perror("open /dev/crypto failed");
        return -1;
    }

    struct crypto_user_alg alg;
    memset(&alg, 0, sizeof(alg));
    strncpy(alg.cru_name, name, sizeof(alg.cru_name) - 1);
    strncpy(alg.cru_driver_name, driver_name, sizeof(alg.cru_driver_name) - 1);
    alg.cru_type = 1; // 假设类型为 1
    alg.cru_mask = 1; // 假设掩码为 1

    if (ioctl(fd, CRYPTO_MSG_NEWALG, &alg) < 0) {
        perror("ioctl CRYPTO_MSG_NEWALG failed");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}
```

这个 `register_crypto_algorithm` 函数演示了如何使用 `ioctl` 系统调用和 `CRYPTO_MSG_NEWALG` 消息类型以及 `crypto_user_alg` 结构体来向内核注册一个新的加密算法。

**涉及 dynamic linker 的功能:**

这个头文件本身与 dynamic linker 没有直接关系。然而，任何使用内核加密功能的库（包括 Android Framework 的库或者 NDK 中的加密库）都需要被动态链接。

**SO 布局样本:**

假设一个名为 `libcrypto_wrapper.so` 的共享库封装了对内核加密功能的调用：

```
libcrypto_wrapper.so:
    ADDRESS           SIZE      OFFSET    LOAD ALIGN PERM  SEGMENT
    0000000000000000  0000001f8  00000000  load 0x000 0x1000 r--  LOAD
    0000000000001000  000000130  00001000  load 0x000 0x1000 r-x  LOAD
    0000000000002000  000000008  00002000  load 0x000 0x1000 r--  LOAD
    0000000000003000  000000008  00003000  load 0x000 0x1000 rw-  LOAD

    DYNAMIC Section:
     ...
         0x0000000000000001 (NEEDED)             Shared library: libc.so
         0x000000000000000c (INIT)               0x1000
         0x000000000000000d (FINI)               0x1128
         0x0000000000000019 (INIT_ARRAY)         0x3000
         0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
         0x000000000000001a (FINI_ARRAY)         0x3008
         0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
     ...
    SYMTAB:          0000000000000040
    STRTAB:          00000000000001b8
    ...
```

**链接的处理过程:**

1. **加载:** 当一个应用程序需要使用 `libcrypto_wrapper.so` 时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载这个共享库到内存中。
2. **符号解析:**  `libcrypto_wrapper.so` 可能依赖于其他共享库，例如 `libc.so`。dynamic linker 会读取 `libcrypto_wrapper.so` 的 `DYNAMIC` 段，找到 `NEEDED` 条目，并加载所需的依赖库。
3. **重定位:**  共享库中的代码和数据通常使用相对于加载地址的偏移量。由于共享库的加载地址在运行时可能不同，dynamic linker 需要根据实际的加载地址调整代码和数据中的地址引用，这个过程称为重定位。例如，如果 `libcrypto_wrapper.so` 中调用了 `libc.so` 中的 `open` 函数，dynamic linker 需要将该调用指令的目标地址修改为 `open` 函数在 `libc.so` 中的实际地址。
4. **初始化:** 加载和重定位完成后，dynamic linker 会执行共享库的初始化代码，通常由 `INIT` 和 `INIT_ARRAY` 指定。

**逻辑推理 (假设输入与输出):**

假设用户空间程序想要获取 AES 算法的统计信息。

**假设输入:**

* 用户空间程序打开 `/dev/crypto` 设备。
* 用户空间程序构造一个消息，指定要获取 AES 算法的统计信息，并将消息类型设置为 `CRYPTO_MSG_GETSTAT`，并将要查询的算法名称设置为 "aes"。

**可能的输出:**

* 内核接收到消息后，会查找名为 "aes" 的算法的统计信息。
* 内核会将统计信息填充到 `crypto_stat_cipher` 结构体中，例如：
  ```
  struct crypto_stat_cipher stat;
  strcpy(stat.type, "aes");
  stat.stat_encrypt_cnt = 12345;
  stat.stat_encrypt_tlen = 1024 * 1024 * 10; // 10MB
  stat.stat_decrypt_cnt = 54321;
  stat.stat_decrypt_tlen = 1024 * 1024 * 15; // 15MB
  stat.stat_err_cnt = 10;
  ```
* 内核将包含统计信息的结构体返回给用户空间程序。

**用户或编程常见的使用错误:**

1. **缓冲区溢出:**  在填充 `cru_name`，`cru_driver_name` 等字符数组时，没有正确处理字符串长度，可能导致缓冲区溢出。
   ```c
   struct crypto_user_alg alg;
   char long_name[100];
   memset(long_name, 'A', sizeof(long_name));
   strcpy(alg.cru_name, long_name); // 错误：可能溢出
   ```
2. **使用错误的 message type:**  向内核发送了不支持或错误的 `CRYPTO_MSG_*` 值。
3. **传递不正确的数据结构:**  `ioctl` 的第三个参数指向的数据结构类型与期望的不符。
4. **权限问题:**  访问 `/dev/crypto` 设备可能需要特定的权限。
5. **忘记检查系统调用返回值:**  `ioctl` 调用失败时没有检查返回值并处理错误。
6. **假设算法一定存在:**  尝试获取一个不存在的算法的统计信息。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 层):** 例如，`javax.crypto.Cipher` 类提供了加密和解密的功能。
2. **JNI 调用:** `Cipher` 类的底层实现会通过 Java Native Interface (JNI) 调用到 Android 的 Native 代码。
3. **Android NDK 库:**  NDK 中可能包含一些封装了加密功能的库，例如 `libcrypto.so` (虽然 Android 现在更倾向于使用 Conscrypt)。
4. **Conscrypt 或 OpenSSL (或其他加密库):** 这些库会实现各种加密算法，并可能使用到内核提供的加密加速功能。
5. **Bionic libc:** 底层的加密库会调用 Bionic libc 提供的系统调用封装函数，例如 `ioctl`。
6. **系统调用:**  libc 函数会发起 `ioctl` 系统调用，并将命令和数据传递给内核。
7. **Linux 内核加密子系统:** 内核接收到系统调用后，会根据消息类型和数据执行相应的操作，例如注册算法、获取统计信息等。

**Frida Hook 示例调试步骤:**

假设我们想 hook 获取 AES 算法统计信息的 `ioctl` 调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
session = device.attach(pid)
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
  onEnter: function(args) {
    var req = args[1].toInt36();
    if (req == 0x80404305) { // 假设 CRYPTO_MSG_GETSTAT 对应的 ioctl 请求码
      send("[*] ioctl called with CRYPTO_MSG_GETSTAT");
      var argp = ptr(args[2]);
      send("[*] argp: " + argp);

      // 读取 crypto_user_alg 结构体 (假设大小)
      var alg_name = argp.readCString();
      send("[*] Algorithm Name: " + alg_name);

      // 如果是获取统计信息，可以尝试读取 crypto_stat_cipher 结构体
      if (alg_name === "aes") {
          send("[*] Attempting to read crypto_stat_cipher");
          var encrypt_cnt = argp.add(offsetof(crypto_stat_cipher, 'stat_encrypt_cnt')).readU64();
          send("[*] Encrypt Count: " + encrypt_cnt);
          // ... 读取其他字段
      }
    }
  },
  onLeave: function(retval) {
    send("[*] ioctl returned: " + retval);
  }
});

function offsetof(struct, member) {
  // 简单的模拟 offsetof，实际需要根据结构体定义计算
  const layout = {
    'crypto_stat_cipher': {
      'type': 0,
      'stat_encrypt_cnt': 64, // 假设偏移
      // ... 其他成员的偏移
    }
  };
  return layout[struct][member];
}
""");
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**说明:**

1. **找到 `ioctl` 函数:**  使用 `Module.findExportByName` 找到 `libc.so` 中的 `ioctl` 函数。
2. **Hook `ioctl`:** 使用 `Interceptor.attach` hook `ioctl` 函数的入口和出口。
3. **检查 `ioctl` 命令:**  在 `onEnter` 中，检查 `args[1]` (第二个参数) 是否是 `CRYPTO_MSG_GETSTAT` 对应的 `ioctl` 请求码。你需要查找或推断这个请求码。
4. **读取数据结构:**  如果命令匹配，读取 `args[2]` (第三个参数) 指向的内存，尝试解析 `crypto_user_alg` 或 `crypto_stat_cipher` 结构体的内容。  你需要根据头文件中的定义来计算结构体成员的偏移量。
5. **打印信息:** 使用 `send` 函数将读取到的信息发送到 Frida 客户端。

**注意:**

* Frida hook 代码需要根据实际的 Android 版本和设备进行调整。
* 你需要知道 `CRYPTO_MSG_GETSTAT` 对应的实际 `ioctl` 请求码。这通常可以在内核源码中找到。
* 结构体成员的偏移量需要根据实际的结构体定义来计算。上面的 `offsetof` 函数只是一个简单的示例。

总而言之，`cryptouser.h` 是一个定义了 Linux 内核加密子系统用户空间接口的重要头文件，它定义了用户空间程序与内核进行加密操作交互的规范。虽然它本身不包含 libc 函数的实现或动态链接器的功能，但它是 Android 安全框架的基础组成部分，并被底层的加密库所使用。通过 Frida 可以 hook 相关的系统调用来调试和分析这些交互过程。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/cryptouser.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_CRYPTOUSER_H
#define _UAPI_LINUX_CRYPTOUSER_H
#include <linux/types.h>
enum {
  CRYPTO_MSG_BASE = 0x10,
  CRYPTO_MSG_NEWALG = 0x10,
  CRYPTO_MSG_DELALG,
  CRYPTO_MSG_UPDATEALG,
  CRYPTO_MSG_GETALG,
  CRYPTO_MSG_DELRNG,
  CRYPTO_MSG_GETSTAT,
  __CRYPTO_MSG_MAX
};
#define CRYPTO_MSG_MAX (__CRYPTO_MSG_MAX - 1)
#define CRYPTO_NR_MSGTYPES (CRYPTO_MSG_MAX + 1 - CRYPTO_MSG_BASE)
#define CRYPTO_MAX_NAME 64
enum crypto_attr_type_t {
  CRYPTOCFGA_UNSPEC,
  CRYPTOCFGA_PRIORITY_VAL,
  CRYPTOCFGA_REPORT_LARVAL,
  CRYPTOCFGA_REPORT_HASH,
  CRYPTOCFGA_REPORT_BLKCIPHER,
  CRYPTOCFGA_REPORT_AEAD,
  CRYPTOCFGA_REPORT_COMPRESS,
  CRYPTOCFGA_REPORT_RNG,
  CRYPTOCFGA_REPORT_CIPHER,
  CRYPTOCFGA_REPORT_AKCIPHER,
  CRYPTOCFGA_REPORT_KPP,
  CRYPTOCFGA_REPORT_ACOMP,
  CRYPTOCFGA_STAT_LARVAL,
  CRYPTOCFGA_STAT_HASH,
  CRYPTOCFGA_STAT_BLKCIPHER,
  CRYPTOCFGA_STAT_AEAD,
  CRYPTOCFGA_STAT_COMPRESS,
  CRYPTOCFGA_STAT_RNG,
  CRYPTOCFGA_STAT_CIPHER,
  CRYPTOCFGA_STAT_AKCIPHER,
  CRYPTOCFGA_STAT_KPP,
  CRYPTOCFGA_STAT_ACOMP,
  __CRYPTOCFGA_MAX
#define CRYPTOCFGA_MAX (__CRYPTOCFGA_MAX - 1)
};
struct crypto_user_alg {
  char cru_name[CRYPTO_MAX_NAME];
  char cru_driver_name[CRYPTO_MAX_NAME];
  char cru_module_name[CRYPTO_MAX_NAME];
  __u32 cru_type;
  __u32 cru_mask;
  __u32 cru_refcnt;
  __u32 cru_flags;
};
struct crypto_stat_aead {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_encrypt_cnt;
  __u64 stat_encrypt_tlen;
  __u64 stat_decrypt_cnt;
  __u64 stat_decrypt_tlen;
  __u64 stat_err_cnt;
};
struct crypto_stat_akcipher {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_encrypt_cnt;
  __u64 stat_encrypt_tlen;
  __u64 stat_decrypt_cnt;
  __u64 stat_decrypt_tlen;
  __u64 stat_verify_cnt;
  __u64 stat_sign_cnt;
  __u64 stat_err_cnt;
};
struct crypto_stat_cipher {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_encrypt_cnt;
  __u64 stat_encrypt_tlen;
  __u64 stat_decrypt_cnt;
  __u64 stat_decrypt_tlen;
  __u64 stat_err_cnt;
};
struct crypto_stat_compress {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_compress_cnt;
  __u64 stat_compress_tlen;
  __u64 stat_decompress_cnt;
  __u64 stat_decompress_tlen;
  __u64 stat_err_cnt;
};
struct crypto_stat_hash {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_hash_cnt;
  __u64 stat_hash_tlen;
  __u64 stat_err_cnt;
};
struct crypto_stat_kpp {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_setsecret_cnt;
  __u64 stat_generate_public_key_cnt;
  __u64 stat_compute_shared_secret_cnt;
  __u64 stat_err_cnt;
};
struct crypto_stat_rng {
  char type[CRYPTO_MAX_NAME];
  __u64 stat_generate_cnt;
  __u64 stat_generate_tlen;
  __u64 stat_seed_cnt;
  __u64 stat_err_cnt;
};
struct crypto_stat_larval {
  char type[CRYPTO_MAX_NAME];
};
struct crypto_report_larval {
  char type[CRYPTO_MAX_NAME];
};
struct crypto_report_hash {
  char type[CRYPTO_MAX_NAME];
  unsigned int blocksize;
  unsigned int digestsize;
};
struct crypto_report_cipher {
  char type[CRYPTO_MAX_NAME];
  unsigned int blocksize;
  unsigned int min_keysize;
  unsigned int max_keysize;
};
struct crypto_report_blkcipher {
  char type[CRYPTO_MAX_NAME];
  char geniv[CRYPTO_MAX_NAME];
  unsigned int blocksize;
  unsigned int min_keysize;
  unsigned int max_keysize;
  unsigned int ivsize;
};
struct crypto_report_aead {
  char type[CRYPTO_MAX_NAME];
  char geniv[CRYPTO_MAX_NAME];
  unsigned int blocksize;
  unsigned int maxauthsize;
  unsigned int ivsize;
};
struct crypto_report_comp {
  char type[CRYPTO_MAX_NAME];
};
struct crypto_report_rng {
  char type[CRYPTO_MAX_NAME];
  unsigned int seedsize;
};
struct crypto_report_akcipher {
  char type[CRYPTO_MAX_NAME];
};
struct crypto_report_kpp {
  char type[CRYPTO_MAX_NAME];
};
struct crypto_report_acomp {
  char type[CRYPTO_MAX_NAME];
};
#define CRYPTO_REPORT_MAXSIZE (sizeof(struct crypto_user_alg) + sizeof(struct crypto_report_blkcipher))
#endif
```