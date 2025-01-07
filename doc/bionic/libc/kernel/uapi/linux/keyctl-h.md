Response:
Let's break down the thought process for analyzing this header file.

1. **Identify the Core Subject:** The filename `keyctl.h` and the presence of macros starting with `KEYCTL_` immediately tell us this file is about the Linux kernel's key management facility (keyrings). The `bionic` path indicates this is the Android-specific version.

2. **High-Level Purpose:**  The comment at the top stating "auto-generated" and referencing the bionic repository suggests this isn't manually written for Android, but rather derived from the upstream Linux kernel. This implies its primary purpose is to expose kernel key management functionality to userspace within Android.

3. **Categorize the Content:** Scan through the definitions and group them logically:
    * **Key Specification Macros (`KEY_SPEC_*`):** These define special identifiers for different types of keyrings (thread, process, session, etc.).
    * **Request Key Default Macros (`KEY_REQKEY_DEFL_*`):**  These specify defaults for where to search for keys.
    * **Key Control Operation Macros (`KEYCTL_*`):** These are the core commands you can send to the kernel to manipulate keys (get keyring ID, join session, update, revoke, etc.). This is the most significant part.
    * **Structures (`keyctl_dh_params`, `keyctl_kdf_params`, `keyctl_pkey_query`, `keyctl_pkey_params`):** These define data structures used as arguments for specific `KEYCTL_` operations, likely related to Diffie-Hellman, key derivation, and public-key cryptography.
    * **Support Flags (`KEYCTL_SUPPORTS_*`):** These seem related to querying the capabilities of public keys.
    * **Move Flags (`KEYCTL_MOVE_EXCL`):**  Options for the `KEYCTL_MOVE` operation.
    * **Capability Flags (`KEYCTL_CAPS*_*`):** Features the kernel's key management system supports.

4. **Explain the Functionality (General):** Based on the categorization, I can now describe the general purpose: providing an interface to manage keys and keyrings within the kernel. This includes operations for creating, updating, searching, linking, unlinking, and controlling access to keys.

5. **Connect to Android (If Applicable):**  The prompt specifically asks about Android relevance. While this is a kernel-level interface, Android uses it. I need to consider *where* and *how*. Key use cases in Android include:
    * **Credential Management:** Storing things like Wi-Fi passwords, VPN credentials.
    * **Inter-Process Communication:**  Although less common than other mechanisms, keyrings *could* be used for secure IPC.
    * **DRM:**  Keys are crucial for managing digital rights.
    * **Keystore/Keymaster:** This is the most prominent example. The Android Keystore system leverages the kernel keyring functionality.

6. **Explain `libc` Functions (Implementation Details):**  The header file *itself* doesn't contain `libc` function implementations. It only *declares* the constants and structures used by those functions. The actual `libc` functions (like `syscall`) would be in a separate `.c` file. The core idea is that `libc` provides wrapper functions around the `syscall` instruction to interact with the kernel's key management system. The `KEYCTL_*` macros become the `cmd` argument to the `syscall(SYS_keyctl, ...)` function.

7. **Address Dynamic Linker (If Applicable):** This header file doesn't directly involve the dynamic linker. The linker is concerned with resolving symbols and loading shared libraries. While the *libc* that *uses* this header is a shared library, the header itself defines constants for kernel interaction. Therefore, a typical SO layout example and linking process explanation isn't directly relevant to *this specific file*. I should acknowledge this and state that the relevant dynamic linking occurs when *libc* itself is loaded.

8. **Consider Logic and Examples:**
    * **Assumptions:** The primary assumption is that the user has the necessary permissions to perform the requested key operations.
    * **Input/Output:**  For functions like `keyctl_search`, the input would be the keyring ID to search within, the key type, and a description. The output would be the key ID of the found key (or an error).
    * **Usage Errors:**  Common errors include trying to access a non-existent key, lacking permissions, or providing incorrect data formats.

9. **Android Framework/NDK Path:** Trace the path from a high-level Android component to the kernel:
    * **Java Framework:**  `KeyStore` class interacts with `KeyStore` service.
    * **Native Code (via JNI):**  `KeyStore` service (often in C++) calls into `libkeystore` or a similar native library.
    * **`libc`:** The native library uses `libc` functions (like a wrapper around `syscall(SYS_keyctl, ...)`) that utilize the constants defined in `keyctl.h`.
    * **Kernel:** The `syscall` triggers the kernel's key management code.

10. **Frida Hooking:** Demonstrate how to intercept the `syscall` related to key management using Frida. This requires finding the `syscall` number (or the wrapper function) and hooking it, then logging the arguments (especially the `cmd` corresponding to the `KEYCTL_*` macros).

11. **Structure and Language:** Organize the information logically with clear headings. Use precise and technical language while also explaining concepts clearly for a general audience. Ensure the response is in Chinese as requested.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This file defines functions for key management."  **Correction:** The file defines *constants and structures* used by functions, not the functions themselves. The functions reside in `libc`.
* **Considering Dynamic Linking:** Initially, I might think about how a user application links against `libc`. **Refinement:** While relevant to the bigger picture, this header file's direct involvement with dynamic linking is limited. The crucial dynamic linking is *libc* itself.
* **Framing the Android Connection:** Instead of just saying "Android uses this," it's better to provide specific examples like Keystore/Keymaster to illustrate *how* it's used.

By following this detailed thought process, breaking down the problem into smaller pieces, and continuously refining the understanding, we can generate a comprehensive and accurate explanation of the provided header file.
这是一个定义了Linux内核keyrings接口的头文件，主要用于管理内核中的密钥。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，可以断定这是Android Bionic C库为了兼容Linux内核API而提供的接口。

**功能列举:**

这个头文件定义了以下功能相关的宏和结构体：

1. **密钥环 (Keyring) 特殊ID:**
   - `KEY_SPEC_THREAD_KEYRING`：当前线程的密钥环。
   - `KEY_SPEC_PROCESS_KEYRING`：当前进程的密钥环。
   - `KEY_SPEC_SESSION_KEYRING`：当前会话的密钥环。
   - `KEY_SPEC_USER_KEYRING`：当前用户的密钥环。
   - `KEY_SPEC_USER_SESSION_KEYRING`：当前用户会话的密钥环。
   - `KEY_SPEC_GROUP_KEYRING`：当前组的密钥环。
   - `KEY_SPEC_REQKEY_AUTH_KEY`：请求密钥认证密钥。
   - `KEY_SPEC_REQUESTOR_KEYRING`：请求者的密钥环。
   这些宏定义了用于指代特定密钥环的特殊数值，方便在 `keyctl` 系统调用中使用。

2. **请求密钥默认值 (Request Key Defaults):**
   - `KEY_REQKEY_DEFL_NO_CHANGE`：不改变当前的请求密钥默认值。
   - `KEY_REQKEY_DEFL_DEFAULT`：使用系统默认的请求密钥默认值。
   - `KEY_REQKEY_DEFL_THREAD_KEYRING` 到 `KEY_REQKEY_DEFL_REQUESTOR_KEYRING`：指定在请求密钥时默认搜索的密钥环。
   这些宏用于设置当需要一个密钥但未明确指定时，系统应该在哪些密钥环中查找。

3. **密钥控制操作 (Key Control Operations):**
   - `KEYCTL_GET_KEYRING_ID`：获取指定密钥环的ID。
   - `KEYCTL_JOIN_SESSION_KEYRING`：加入或创建一个新的会话密钥环。
   - `KEYCTL_UPDATE`：更新密钥的值。
   - `KEYCTL_REVOKE`：撤销密钥。
   - `KEYCTL_CHOWN`：更改密钥的所有者。
   - `KEYCTL_SETPERM`：设置密钥的权限。
   - `KEYCTL_DESCRIBE`：获取密钥的描述信息。
   - `KEYCTL_CLEAR`：清除密钥环中的所有密钥。
   - `KEYCTL_LINK`：将一个密钥链接到密钥环。
   - `KEYCTL_UNLINK`：从密钥环中取消链接密钥。
   - `KEYCTL_SEARCH`：在密钥环中搜索密钥。
   - `KEYCTL_READ`：读取密钥的值。
   - `KEYCTL_INSTANTIATE`：实例化一个未实例化的密钥。
   - `KEYCTL_NEGATE`：否定一个密钥请求。
   - `KEYCTL_SET_REQKEY_KEYRING`：设置请求密钥时使用的密钥环。
   - `KEYCTL_SET_TIMEOUT`：设置密钥的超时时间。
   - `KEYCTL_ASSUME_AUTHORITY`：假设拥有特定权限。
   - `KEYCTL_GET_SECURITY`：获取密钥的安全上下文。
   - `KEYCTL_SESSION_TO_PARENT`：将会话密钥环移动到父会话。
   - `KEYCTL_REJECT`：拒绝一个密钥。
   - `KEYCTL_INSTANTIATE_IOV`：使用IO向量实例化密钥。
   - `KEYCTL_INVALIDATE`：使密钥失效。
   - `KEYCTL_GET_PERSISTENT`：获取持久密钥环的ID。
   - `KEYCTL_DH_COMPUTE`：执行Diffie-Hellman密钥交换计算。
   - `KEYCTL_PKEY_QUERY`：查询公钥的属性。
   - `KEYCTL_PKEY_ENCRYPT`：使用公钥加密数据。
   - `KEYCTL_PKEY_DECRYPT`：使用私钥解密数据。
   - `KEYCTL_PKEY_SIGN`：使用私钥签名数据。
   - `KEYCTL_PKEY_VERIFY`：使用公钥验证签名。
   - `KEYCTL_RESTRICT_KEYRING`：限制密钥环。
   - `KEYCTL_MOVE`：将密钥移动到另一个密钥环。
   - `KEYCTL_CAPABILITIES`：查询内核密钥管理功能。
   - `KEYCTL_WATCH_KEY`：监视密钥的状态变化。
   这些宏定义了可以对密钥和密钥环执行的各种操作，是与内核密钥管理功能交互的核心。

4. **数据结构:**
   - `struct keyctl_dh_params`：用于 `KEYCTL_DH_COMPUTE` 操作，包含Diffie-Hellman密钥交换的参数（私钥、素数、基数）。
   - `struct keyctl_kdf_params`：可能用于密钥派生功能 (虽然在这个头文件中没有直接的使用，但结构体的存在暗示了相关功能)，包含哈希算法名称和额外信息。
   - `struct keyctl_pkey_query`：用于 `KEYCTL_PKEY_QUERY` 操作，存储查询到的公钥属性，如支持的操作、密钥大小、最大数据/签名/加密/解密大小。
   - `struct keyctl_pkey_params`：用于 `KEYCTL_PKEY_ENCRYPT`、`KEYCTL_PKEY_DECRYPT`、`KEYCTL_PKEY_SIGN`、`KEYCTL_PKEY_VERIFY` 操作，包含密钥ID、输入/输出长度等参数。

5. **标志位:**
   - `KEYCTL_SUPPORTS_ENCRYPT`, `KEYCTL_SUPPORTS_DECRYPT`, `KEYCTL_SUPPORTS_SIGN`, `KEYCTL_SUPPORTS_VERIFY`：用于 `KEYCTL_PKEY_QUERY` 结构体，表示公钥支持的操作。
   - `KEYCTL_MOVE_EXCL`：用于 `KEYCTL_MOVE` 操作，表示排他移动。
   - `KEYCTL_CAPS0_*`, `KEYCTL_CAPS1_*`：用于 `KEYCTL_CAPABILITIES` 操作，表示内核支持的密钥管理功能，例如持久密钥环、Diffie-Hellman、公钥支持等。

**与Android功能的关系及举例说明:**

Android 使用 Linux 内核的 keyrings 功能来管理各种安全相关的凭据和密钥。以下是一些例子：

* **Keystore/Keymaster:** Android 的 Keystore 系统和 Keymaster HAL (硬件抽象层)  广泛使用了内核的 keyrings 功能来安全地存储和管理加密密钥。例如，当你使用 Android 的 Keystore API 生成或存储一个密钥时，该密钥最终可能会存储在一个内核密钥环中，并受到内核的安全机制保护。`KEYCTL_UPDATE`, `KEYCTL_SEARCH`, `KEYCTL_READ`, `KEYCTL_SET_PERM` 等操作会被用到管理这些密钥的生命周期和访问权限。

* **Wi-Fi 密码管理:**  Android 系统可能会使用 keyrings 来存储已连接 Wi-Fi 网络的密码。当系统需要连接到已知的 Wi-Fi 网络时，它可能会使用 `KEYCTL_SEARCH` 来查找相应的密码。

* **VPN 凭据管理:** 类似于 Wi-Fi 密码，VPN 的用户名和密码等凭据也可能存储在 keyrings 中。

* **SELinux 策略:** 虽然不是直接使用这些 `KEYCTL_*` 操作，但 SELinux 的一些策略可能与内核 keyrings 的访问控制机制集成。

**libc 函数的实现 (基于推测，因为此文件是头文件):**

这个头文件本身不包含 libc 函数的实现。它只是定义了与内核交互时使用的常量和结构体。实际的 libc 函数 (例如 `keyctl()`) 会在 bionic 的其他源文件中实现。

`keyctl()` 函数是访问内核 keyrings 功能的主要接口。它是一个系统调用包装函数，其实现大致如下：

```c
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/keyctl.h> // 包含此头文件
#include <stdarg.h>
#include <errno.h>

// ...

long keyctl(int operation, ...) {
  va_list args;
  long ret;

  va_start(args, operation);

  switch (operation) {
    case KEYCTL_GET_KEYRING_ID: {
      key_serial_t id = va_arg(args, key_serial_t);
      int create = va_arg(args, int);
      ret = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
      break;
    }
    // ... 其他 KEYCTL_* 操作的实现
    case KEYCTL_UPDATE: {
      key_serial_t id = va_arg(args, key_serial_t);
      const char *description = va_arg(args, const char *);
      const void *payload = va_arg(args, const void *);
      size_t payload_len = va_arg(args, size_t);
      ret = syscall(__NR_keyctl, KEYCTL_UPDATE, id, description, payload, payload_len);
      break;
    }
    // ...
    default:
      errno = EINVAL;
      ret = -1;
      break;
  }

  va_end(args);
  return ret;
}
```

**解释:**

1. `keyctl()` 函数接收一个 `operation` 参数，对应于头文件中定义的 `KEYCTL_*` 宏。
2. 使用可变参数 `...` 来接收不同操作所需的参数。
3. `syscall(__NR_keyctl, ...)` 是实际的系统调用，其中 `__NR_keyctl` 是 `keyctl` 系统调用的编号。不同的 `KEYCTL_*` 宏会被作为 `syscall` 的第一个参数传递，指示内核执行相应的操作。
4. `va_arg` 用于从可变参数列表中提取与当前操作相关的参数。
5. 返回值通常是操作成功与否的指示，失败时会设置 `errno`。

**涉及 dynamic linker 的功能:**

这个头文件本身不直接涉及 dynamic linker 的功能。dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责在程序启动时加载共享库，并解析符号引用。

然而，`keyctl()` 函数本身存在于 `libc.so` 中，这是一个由 dynamic linker 加载的共享库。

**so 布局样本:**

`libc.so` 的布局非常复杂，包含了各种标准 C 库函数以及 Android 特定的功能。与 `keyctl()` 相关的部分可能如下所示：

```
libc.so:
    ...
    .text:
        ...
        keyctl:  ; keyctl 函数的指令
            ...
        __keyctl: ; 实际执行 syscall 的函数 (可能)
            ...
        ...
    .rodata:
        ...
        一些字符串常量，可能用于错误消息或内部逻辑
        ...
    .data:
        ...
        全局变量
        ...
    ...
```

**链接的处理过程:**

1. 当一个应用程序调用 `keyctl()` 函数时，编译器会生成一个对该符号的未解析引用。
2. 在链接阶段，静态链接器会记录这些未解析的引用，并标记该程序需要链接 `libc.so`。
3. 当程序启动时，dynamic linker 会加载 `libc.so` 到内存中。
4. dynamic linker 会遍历程序中未解析的符号引用，并在 `libc.so` 的符号表 (symbol table) 中查找 `keyctl` 的地址。
5. 找到 `keyctl` 的地址后，dynamic linker 会更新程序中的引用，使其指向 `libc.so` 中 `keyctl` 函数的实际地址。
6. 这样，当程序执行到调用 `keyctl()` 的代码时，就能正确跳转到 `libc.so` 中对应的函数执行。

**逻辑推理和假设输入/输出:**

假设我们想获取当前用户会话密钥环的 ID：

**假设输入:**
- `operation`: `KEYCTL_GET_KEYRING_ID`
- `id`: `KEY_SPEC_USER_SESSION_KEYRING`
- `create`: 0 (不创建，如果不存在则失败)

**预期输出:**
- 如果用户会话密钥环存在，则返回其正数的 ID (例如，12345)。
- 如果用户会话密钥环不存在，则返回 -1，并且 `errno` 设置为相应的错误码 (例如，ENOENT)。

假设我们想更新一个已存在密钥的值：

**假设输入:**
- `operation`: `KEYCTL_UPDATE`
- `id`:  一个已存在密钥的 ID (例如，54321)
- `description`: "my_secret_key"
- `payload`: 指向新密钥数据的指针 (例如，"new_value")
- `payload_len`: 新密钥数据的长度 (例如，strlen("new_value"))

**预期输出:**
- 如果更新成功，则返回 0。
- 如果密钥不存在或没有权限更新，则返回 -1，并且 `errno` 设置为相应的错误码 (例如，EACCES, ENOKEY)。

**用户或编程常见的使用错误:**

1. **权限不足:** 尝试访问或操作没有足够权限的密钥或密钥环。例如，尝试读取属于其他用户的密钥。
2. **密钥或密钥环不存在:** 尝试操作不存在的密钥或密钥环。
3. **错误的密钥类型或格式:**  在创建或更新密钥时，使用了内核不支持的类型或格式。
4. **内存管理错误:** 在传递密钥数据时，没有正确分配或释放内存。
5. **忘记检查返回值和 `errno`:** 没有检查 `keyctl()` 的返回值，导致未能处理错误情况。
6. **混淆密钥环 ID 和密钥 ID:**  错误地将密钥环的 ID 当作密钥的 ID 使用，或者反之。
7. **不正确的参数顺序或类型:**  调用 `keyctl()` 时，传递了错误顺序或类型的参数。

**Frida Hook 示例调试步骤:**

假设我们想观察 Android 系统中对 `KEYCTL_UPDATE` 操作的调用。

**Frida Hook 代码 (JavaScript):**

```javascript
// 获取 keyctl 函数的地址
const keyctlPtr = Module.findExportByName("libc.so", "keyctl");

if (keyctlPtr) {
  Interceptor.attach(keyctlPtr, {
    onEnter: function(args) {
      const operation = args[0].toInt32();
      if (operation === 2) { // KEYCTL_UPDATE 的值
        console.log("Keyctl called with KEYCTL_UPDATE");
        console.log("  Key ID:", args[1].toInt32());
        console.log("  Description:", Memory.readUtf8String(args[2]));
        const payloadPtr = ptr(args[3]);
        const payloadLen = args[4].toInt32();
        if (payloadLen > 0) {
          console.log("  Payload (first 32 bytes):", payloadPtr.readByteArray(Math.min(payloadLen, 32)));
        } else {
          console.log("  Payload: (empty)");
        }
      }
    },
    onLeave: function(retval) {
      if (this.operation === 2) {
        console.log("Keyctl returned:", retval.toInt32());
      }
    }
  });
} else {
  console.error("Could not find keyctl function in libc.so");
}
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在你的电脑上安装了 Frida 客户端。
2. **找到目标进程:** 确定你想要监控的 Android 进程的进程名或 PID。例如，可能是某个系统服务或应用进程。
3. **运行 Frida Hook:** 使用 Frida 客户端连接到目标进程并执行上面的 JavaScript 代码。例如：
   ```bash
   frida -U -n com.android.systemui -l your_script.js
   ```
   将 `com.android.systemui` 替换为你想要监控的进程名，`your_script.js` 替换为保存的 Frida 脚本文件名。
4. **触发相关操作:** 在 Android 设备上执行可能会调用 `KEYCTL_UPDATE` 的操作。例如，修改 Wi-Fi 密码、VPN 设置、或者执行某些使用 Keystore 的操作。
5. **查看 Frida 输出:** 在 Frida 客户端的控制台中，你将看到捕获到的 `keyctl` 调用信息，包括操作类型、密钥 ID、描述信息和部分有效载荷。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 例如，当你使用 `java.security.KeyStore` 类来存储或更新密钥时。
   - `KeyStore` 类的方法会调用底层的 `KeyStore` 系统服务。

2. **System Server (Java/Native 混合):**
   - `KeyStore` 系统服务 (通常在 `system_server` 进程中运行) 接收到来自 Framework 的请求。
   - `KeyStore` 服务的实现会调用原生的 Keymaster HAL 或软件实现。

3. **Keymaster HAL (C++):**
   - Keymaster HAL 的实现 (例如，`libkeymaster.so`) 会处理密钥的生成、存储和访问。
   - 在存储或更新密钥时，Keymaster HAL 的实现会调用 `libc.so` 中的 `keyctl()` 函数。

4. **NDK (Native 代码):**
   - 如果一个使用 NDK 开发的应用程序需要直接与内核 keyrings 交互，它可以直接调用 `libc.so` 中的 `keyctl()` 函数，并使用头文件中定义的常量。

**流程示例 (使用 Keystore):**

```
[Android App (Java)] --> [KeyStore.store()]
                      |
                      v
[KeyStore Service (Java)] --> JNI 调用到 native 代码
                              |
                              v
[KeyStore Service (Native C++)] --> 调用 Keymaster HAL
                                    |
                                    v
[Keymaster HAL Implementation (C++)] --> 调用 libc 的 keyctl() 函数 (例如, KEYCTL_UPDATE)
                                         |
                                         v
[Linux Kernel (keyrings 子系统)]
```

总而言之，这个头文件定义了 Android 系统中与 Linux 内核密钥管理功能交互的基础常量和结构体。无论是 Android Framework 还是 NDK 开发的应用，最终都可能通过 `libc` 的 `keyctl()` 函数，并利用这里定义的宏，来操作内核的密钥环，实现安全凭据和密钥的管理。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/keyctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_KEYCTL_H
#define _LINUX_KEYCTL_H
#include <linux/types.h>
#define KEY_SPEC_THREAD_KEYRING - 1
#define KEY_SPEC_PROCESS_KEYRING - 2
#define KEY_SPEC_SESSION_KEYRING - 3
#define KEY_SPEC_USER_KEYRING - 4
#define KEY_SPEC_USER_SESSION_KEYRING - 5
#define KEY_SPEC_GROUP_KEYRING - 6
#define KEY_SPEC_REQKEY_AUTH_KEY - 7
#define KEY_SPEC_REQUESTOR_KEYRING - 8
#define KEY_REQKEY_DEFL_NO_CHANGE - 1
#define KEY_REQKEY_DEFL_DEFAULT 0
#define KEY_REQKEY_DEFL_THREAD_KEYRING 1
#define KEY_REQKEY_DEFL_PROCESS_KEYRING 2
#define KEY_REQKEY_DEFL_SESSION_KEYRING 3
#define KEY_REQKEY_DEFL_USER_KEYRING 4
#define KEY_REQKEY_DEFL_USER_SESSION_KEYRING 5
#define KEY_REQKEY_DEFL_GROUP_KEYRING 6
#define KEY_REQKEY_DEFL_REQUESTOR_KEYRING 7
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_CHOWN 4
#define KEYCTL_SETPERM 5
#define KEYCTL_DESCRIBE 6
#define KEYCTL_CLEAR 7
#define KEYCTL_LINK 8
#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_INSTANTIATE 12
#define KEYCTL_NEGATE 13
#define KEYCTL_SET_REQKEY_KEYRING 14
#define KEYCTL_SET_TIMEOUT 15
#define KEYCTL_ASSUME_AUTHORITY 16
#define KEYCTL_GET_SECURITY 17
#define KEYCTL_SESSION_TO_PARENT 18
#define KEYCTL_REJECT 19
#define KEYCTL_INSTANTIATE_IOV 20
#define KEYCTL_INVALIDATE 21
#define KEYCTL_GET_PERSISTENT 22
#define KEYCTL_DH_COMPUTE 23
#define KEYCTL_PKEY_QUERY 24
#define KEYCTL_PKEY_ENCRYPT 25
#define KEYCTL_PKEY_DECRYPT 26
#define KEYCTL_PKEY_SIGN 27
#define KEYCTL_PKEY_VERIFY 28
#define KEYCTL_RESTRICT_KEYRING 29
#define KEYCTL_MOVE 30
#define KEYCTL_CAPABILITIES 31
#define KEYCTL_WATCH_KEY 32
struct keyctl_dh_params {
  union {
#ifndef __cplusplus
    __s32 __linux_private;
#endif
    __s32 priv;
  };
  __s32 prime;
  __s32 base;
};
struct keyctl_kdf_params {
  char  * hashname;
  char  * otherinfo;
  __u32 otherinfolen;
  __u32 __spare[8];
};
#define KEYCTL_SUPPORTS_ENCRYPT 0x01
#define KEYCTL_SUPPORTS_DECRYPT 0x02
#define KEYCTL_SUPPORTS_SIGN 0x04
#define KEYCTL_SUPPORTS_VERIFY 0x08
struct keyctl_pkey_query {
  __u32 supported_ops;
  __u32 key_size;
  __u16 max_data_size;
  __u16 max_sig_size;
  __u16 max_enc_size;
  __u16 max_dec_size;
  __u32 __spare[10];
};
struct keyctl_pkey_params {
  __s32 key_id;
  __u32 in_len;
  union {
    __u32 out_len;
    __u32 in2_len;
  };
  __u32 __spare[7];
};
#define KEYCTL_MOVE_EXCL 0x00000001
#define KEYCTL_CAPS0_CAPABILITIES 0x01
#define KEYCTL_CAPS0_PERSISTENT_KEYRINGS 0x02
#define KEYCTL_CAPS0_DIFFIE_HELLMAN 0x04
#define KEYCTL_CAPS0_PUBLIC_KEY 0x08
#define KEYCTL_CAPS0_BIG_KEY 0x10
#define KEYCTL_CAPS0_INVALIDATE 0x20
#define KEYCTL_CAPS0_RESTRICT_KEYRING 0x40
#define KEYCTL_CAPS0_MOVE 0x80
#define KEYCTL_CAPS1_NS_KEYRING_NAME 0x01
#define KEYCTL_CAPS1_NS_KEY_TAG 0x02
#define KEYCTL_CAPS1_NOTIFICATIONS 0x04
#endif

"""

```