Response:
Let's break down the thought process for answering the user's request about the `fscrypt.h` header file.

**1. Understanding the Core Request:**

The user provided a header file path (`bionic/libc/kernel/uapi/linux/fscrypt.handroid`) and wants to understand its functionalities, its relation to Android, implementation details (especially for libc functions), dynamic linking aspects, potential usage errors, and how Android framework/NDK interacts with it. The request also includes a demand for Frida hooking examples.

**2. Initial Analysis of the Header File:**

The first step is to read and understand the contents of `fscrypt.h`. Key observations:

* **Auto-generated:** The comment at the top is crucial. It tells us this file isn't manually written but generated, likely from the upstream Linux kernel headers. This implies its primary function is to define the *interface* between user-space (Android apps and libraries) and the kernel's filesystem encryption subsystem (fscrypt).
* **Includes:**  The inclusion of `linux/ioctl.h` and `linux/types.h` strongly suggests that this file defines structures and constants used for interacting with kernel drivers via `ioctl` system calls.
* **Constants and Macros:** A large portion of the file defines constants (`#define`) related to policy flags, encryption modes, key sizes, and prefixes. These represent the different options and configurations available for filesystem encryption.
* **Structures:** The file defines several structures (e.g., `fscrypt_policy_v1`, `fscrypt_key`, `fscrypt_add_key_arg`). These structures are used to pass data between user-space and the kernel during `ioctl` calls. They represent the data format for setting policies, adding keys, removing keys, etc.
* **`ioctl` Definitions:** The `#define FS_IOC_*` lines define the `ioctl` command codes. These are crucial for invoking specific fscrypt operations in the kernel.
* **Type Definitions:** The `typedef` (or implicit typedef through `#define`) like `fscrypt_policy fscrypt_policy_v1` suggests versioning or aliasing of structures.

**3. Addressing Each Point of the Request:**

Now, systematically address each part of the user's query:

* **功能 (Functionality):** The core functionality is providing the *interface* for filesystem encryption operations. This translates to:
    * Defining data structures for policies and keys.
    * Defining constants for encryption algorithms and options.
    * Defining `ioctl` commands to interact with the kernel.

* **与 Android 的关系 (Relationship to Android):**  Since this file is within the Bionic library and specifically the `uapi` (user API) section related to the kernel, it's a direct bridge between Android user-space and the Linux kernel's fscrypt implementation. Examples include encrypting user data, app data, or adoptable storage.

* **详细解释 libc 函数的功能是如何实现的 (Detailed explanation of libc function implementation):**  This is a **critical point of clarification**. The header file *itself* doesn't contain the *implementation* of any libc functions. It only defines the *interface*. The actual implementation of functions that *use* these definitions (like `ioctl`) resides in other parts of the C library. The answer needs to explicitly state this distinction. The `ioctl` system call is the key libc function to discuss in this context. Explain its purpose (sending control commands to device drivers) and how it uses the structures defined in the header file.

* **涉及 dynamic linker 的功能 (Dynamic linker related functionality):**  This header file doesn't directly involve the dynamic linker. It defines data structures and constants, not code that gets linked. The answer needs to clarify this. The *use* of these definitions by other libraries would involve the dynamic linker, but the header file itself doesn't.

* **逻辑推理，假设输入与输出 (Logical reasoning, assumed input and output):**  For the `ioctl` system call, a logical flow can be described: an application prepares the `fscrypt_*` structures, fills them with data, and then calls `ioctl` with the appropriate `FS_IOC_*` command. The kernel processes this data, and the `ioctl` call returns success/failure or potentially modifies the input structure to provide output. Example scenarios (setting a policy, adding a key) are helpful here.

* **用户或者编程常见的使用错误 (Common user/programming errors):** Common errors relate to misinterpreting flags, providing incorrect key sizes, using the wrong `ioctl` command, or handling errors from `ioctl` incorrectly. Examples are crucial for understanding.

* **说明 android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK reaches here):**  Trace the path from a high-level Android operation (like setting a file encryption policy) down to the system call level. This involves the Framework (Java/Kotlin), potentially NDK (C/C++), Bionic libc, and finally the `ioctl` system call using the definitions from `fscrypt.h`.

* **给出 frida hook 示例调试这些步骤 (Frida hook examples):** Provide practical Frida examples for hooking the `ioctl` system call, specifically when the relevant `FS_IOC_*` constants are used. This demonstrates how to inspect the data being passed to the kernel.

**4. Structuring the Answer:**

Organize the answer logically, addressing each point clearly and concisely. Use headings and bullet points to improve readability. Start with a high-level overview and then delve into specifics. Emphasize the distinction between interface definition and implementation.

**5. Refinement and Language:**

Ensure the language is clear, precise, and uses appropriate technical terms. The request was in Chinese, so the answer needs to be in Chinese as well. Double-check the accuracy of the technical details.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Might be tempted to explain the implementation details of encryption algorithms. **Correction:** The header file doesn't contain this. Focus on the interface and how to *use* the encryption mechanisms, not the mechanisms themselves.
* **Overemphasis on libc functions:**  Realized that the file *defines* data structures, it doesn't *implement* libc functions. The focus should be on the `ioctl` system call and how it leverages these definitions.
* **Dynamic linker connection:**  Initially considered how libraries using this might be linked. **Correction:**  The header file itself isn't linked; it's included during compilation. The link happens with the code that uses these definitions.

By following this structured thought process and constantly refining the understanding of the request and the content of the header file, a comprehensive and accurate answer can be constructed.
这是一个定义 Linux 文件系统加密 (fscrypt) 用户空间 API 的头文件。它位于 Android 的 Bionic C 库中，这意味着 Android 系统使用它来与 Linux 内核的文件系统加密功能进行交互。

**功能列举:**

这个头文件定义了以下功能：

1. **定义了用于配置和管理文件系统加密策略的数据结构:**
   - `fscrypt_policy_v1`, `fscrypt_policy_v2`:  定义了不同版本的加密策略结构，包括加密算法、密钥描述符/标识符、以及一些标志位。
   - `fscrypt_get_policy_ex_arg`: 用于获取文件或目录的加密策略。
   - `fscrypt_key`:  定义了密钥的结构，包括密钥模式、原始密钥数据和大小。
   - `fscrypt_key_specifier`:  用于指定要操作的密钥，通过描述符或标识符。
   - `fscrypt_provisioning_key_payload`:  可能用于密钥提供的载荷信息（具体用途未在代码中直接体现）。
   - `fscrypt_add_key_arg`: 用于向内核添加加密密钥。
   - `fscrypt_remove_key_arg`: 用于从内核移除加密密钥。
   - `fscrypt_get_key_status_arg`: 用于获取密钥的状态信息。

2. **定义了控制文件系统加密操作的常量和标志位:**
   - `FSCRYPT_POLICY_FLAGS_PAD_*`:  定义了加密策略中的填充标志，用于调整加密块的大小。
   - `FSCRYPT_POLICY_FLAG_DIRECT_KEY`:  指示使用直接提供的密钥。
   - `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64`, `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32`:  定义了初始化向量 (IV) 的生成方式。
   - `FSCRYPT_MODE_AES_256_XTS`, `FSCRYPT_MODE_AES_256_CTS`, 等:  定义了支持的加密算法模式。
   - `FSCRYPT_POLICY_V1`, `FSCRYPT_POLICY_V2`:  定义了加密策略的版本。
   - `FSCRYPT_KEY_DESCRIPTOR_SIZE`, `FSCRYPT_KEY_IDENTIFIER_SIZE`, `FSCRYPT_MAX_KEY_SIZE`: 定义了密钥描述符、标识符和最大密钥的大小。
   - `FSCRYPT_KEY_DESC_PREFIX`: 定义了密钥描述符的前缀。
   - `FSCRYPT_KEY_STATUS_*`: 定义了密钥的状态常量。
   - `__FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED`: 定义了添加密钥时的硬件包裹标志。
   - `FSCRYPT_KEY_REMOVAL_STATUS_FLAG_*`: 定义了密钥移除状态的标志。

3. **定义了用于执行文件系统加密操作的 ioctl 命令:**
   - `FS_IOC_SET_ENCRYPTION_POLICY`:  用于设置文件或目录的加密策略。
   - `FS_IOC_GET_ENCRYPTION_PWSALT`:  用于获取加密盐值（password salt）。
   - `FS_IOC_GET_ENCRYPTION_POLICY`:  用于获取文件或目录的加密策略。
   - `FS_IOC_GET_ENCRYPTION_POLICY_EX`: 用于获取扩展的加密策略信息。
   - `FS_IOC_ADD_ENCRYPTION_KEY`:  用于向内核添加加密密钥。
   - `FS_IOC_REMOVE_ENCRYPTION_KEY`:  用于从内核移除加密密钥。
   - `FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS`:  用于移除所有用户的加密密钥。
   - `FS_IOC_GET_ENCRYPTION_KEY_STATUS`:  用于获取加密密钥的状态。
   - `FS_IOC_GET_ENCRYPTION_NONCE`:  用于获取加密 nonce（随机数）。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 文件系统加密功能的核心组成部分。Android 使用 fscrypt 来保护用户数据和应用程序数据。

* **用户数据加密:** Android 设备的 `/data/user` 分区通常使用 fscrypt 加密。当用户设置锁屏密码时，Android 系统会使用该密码派生出加密密钥，并通过这个头文件中定义的 `ioctl` 命令和数据结构，将密钥添加到内核，并设置 `/data/user` 分区的加密策略。这样，只有在设备解锁后，内核才能访问加密的数据。

* **应用数据加密:** Android 可以对单个应用程序的数据目录进行加密。开发者可以使用 Android Framework 提供的 API (例如 `StorageManager.createApp будущемKey(...)`)，最终会调用到 Bionic 库中的相关函数，这些函数会使用此头文件中定义的结构和 `ioctl` 命令来管理应用程序的加密密钥和策略。

* **可移动存储加密 (Adoptable Storage):** 当用户将 SD 卡设置为内部存储时，Android 也会使用 fscrypt 对其进行加密。过程类似于用户数据加密。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了与 Linux 内核交互的接口（数据结构和常量）。实际的 libc 函数（例如 `ioctl`）的实现位于 Bionic 库的其他源文件中。

**`ioctl` 函数的实现简述:**

`ioctl` 是一个系统调用，允许用户空间程序向设备驱动程序发送控制命令。

1. **参数准备:** 当 Android Framework 或 NDK 需要执行文件系统加密操作时，例如设置加密策略，它会填充此头文件中定义的结构体（例如 `fscrypt_policy_v1`）。

2. **`ioctl` 调用:**  程序调用 `ioctl` 函数，传入以下参数：
   - 文件描述符 (file descriptor):  通常是需要操作的文件或目录的文件描述符。
   - 命令码 (request code):  例如 `FS_IOC_SET_ENCRYPTION_POLICY`，指示要执行的操作。
   - 参数 (argument): 指向填充好的结构体的指针。

3. **系统调用处理:**  内核接收到 `ioctl` 系统调用后，会根据文件描述符找到对应的文件系统驱动程序，并根据命令码调用驱动程序中相应的处理函数。

4. **驱动程序处理:** 文件系统驱动程序（例如 ext4）的 fscrypt 相关代码会解析传入的结构体数据，执行相应的加密操作，例如设置加密策略、添加或移除密钥等。

5. **返回结果:**  `ioctl` 系统调用返回操作结果，成功或失败。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及动态链接器的功能**。它定义的是数据结构和常量，在编译时会被包含到需要使用 fscrypt 功能的 C/C++ 代码中。

**动态链接器的作用:**

动态链接器负责在程序运行时加载共享库 (`.so` 文件)，并解析和重定位库中的符号。

**使用 `fscrypt.h` 的 `.so` 布局样本 (假设一个名为 `libfscrypt_wrapper.so` 的库使用了这个头文件):**

```
libfscrypt_wrapper.so:
    .text          # 代码段，包含使用 fscrypt.h 中定义的 ioctl 命令的函数
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表
    .got.plt       # 全局偏移量表 (PLT 部分)
    ...           # 其他段
```

**链接处理过程:**

1. **编译时:** 当编译 `libfscrypt_wrapper.so` 的源代码时，编译器会处理 `#include <linux/fscrypt.h>` 指令，将头文件中定义的结构体和常量信息包含到编译单元中。

2. **链接时:**  链接器将各个编译单元的目标文件链接在一起，生成 `libfscrypt_wrapper.so` 文件。虽然 `fscrypt.h` 本身没有需要链接的代码，但 `libfscrypt_wrapper.so` 中调用 `ioctl` 的代码是链接到 Bionic C 库中的 `ioctl` 函数实现的。动态链接器会在运行时负责加载 Bionic C 库。

3. **运行时:** 当一个应用程序（例如 Android System Server）加载 `libfscrypt_wrapper.so` 时，动态链接器会：
   - 加载 `libfscrypt_wrapper.so` 到内存中。
   - 检查 `libfscrypt_wrapper.so` 的依赖项，例如 Bionic C 库 (`libc.so`)。
   - 如果依赖项尚未加载，则加载它们。
   - 解析 `libfscrypt_wrapper.so` 中的动态符号表，找到对 `ioctl` 函数的引用。
   - 在 Bionic C 库中找到 `ioctl` 函数的地址。
   - 更新 `libfscrypt_wrapper.so` 中的全局偏移量表 (GOT)，使其指向 `ioctl` 函数的实际地址。
   - 当 `libfscrypt_wrapper.so` 中的代码调用 `ioctl` 时，会通过 GOT 跳转到 Bionic C 库中的实现。

**如果做了逻辑推理，请给出假设输入与输出:**

**场景: 设置文件加密策略**

**假设输入:**

* 文件描述符 `fd`:  指向一个需要加密的目录。
* `policy`: 一个 `fscrypt_policy_v1` 结构体，包含以下信息:
    * `version`: `FSCRYPT_POLICY_V1` (0)
    * `contents_encryption_mode`: `FSCRYPT_MODE_AES_256_XTS` (1)
    * `filenames_encryption_mode`:  假设也为某种模式 (例如，文件名加密通常不开启)
    * `flags`: 0
    * `master_key_descriptor`: 一个 8 字节的密钥描述符，例如 `fscrypt:xxxxxxxxxxxxxxxx` (十六进制表示)。

**逻辑推理:**

1. 程序会使用上述输入填充 `fscrypt_policy_v1` 结构体。
2. 调用 `ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy)`。

**假设输出:**

* 如果操作成功，`ioctl` 返回 0。
* 如果操作失败（例如，权限不足，密钥无效等），`ioctl` 返回 -1，并设置 `errno` 来指示错误类型。

**场景: 添加加密密钥**

**假设输入:**

* 文件描述符 `fd`:  可以是任意有效的文件描述符。
* `add_key_arg`: 一个 `fscrypt_add_key_arg` 结构体，包含以下信息:
    * `key_spec.type`: `FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR` (1)
    * `key_spec.u.descriptor`:  与之前设置策略时相同的密钥描述符。
    * `raw_size`: 32 (假设密钥是 256 位的 AES 密钥)
    * `raw`:  32 字节的原始密钥数据。

**逻辑推理:**

1. 程序会使用上述输入填充 `fscrypt_add_key_arg` 结构体。
2. 调用 `ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, &add_key_arg)`。

**假设输出:**

* 如果操作成功，`ioctl` 返回 0。
* 如果操作失败（例如，密钥格式错误，密钥已存在等），`ioctl` 返回 -1，并设置 `errno`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **密钥描述符错误:**
   - **错误:** 传递了格式不正确的密钥描述符，例如缺少 `fscrypt:` 前缀或长度不对。
   - **后果:** `ioctl` 调用 `FS_IOC_SET_ENCRYPTION_POLICY` 或 `FS_IOC_ADD_ENCRYPTION_KEY` 会失败，返回 `EINVAL` 错误。

2. **密钥大小错误:**
   - **错误:** 提供的密钥数据长度与预期不符。例如，对于 AES-256 XTS，密钥应为 64 字节。
   - **后果:** `ioctl` 调用 `FS_IOC_ADD_ENCRYPTION_KEY` 会失败，返回 `EINVAL` 错误。

3. **权限不足:**
   - **错误:**  尝试设置或获取加密策略，但当前用户没有足够的权限。
   - **后果:** `ioctl` 调用会失败，返回 `EACCES` 或 `EPERM` 错误。

4. **在未加密的文件上设置策略:**
   - **错误:**  尝试在一个已经包含数据的未加密文件上设置加密策略。
   - **后果:**  `ioctl` 调用可能会失败，或者可能导致数据损坏，具体取决于文件系统实现。通常，需要在文件为空时设置加密策略。

5. **忘记添加密钥:**
   - **错误:**  在设置了加密策略后，忘记使用 `FS_IOC_ADD_ENCRYPTION_KEY` 添加相应的密钥。
   - **后果:**  尝试访问加密文件时会失败，返回权限错误或其他指示无法解密的错误。

6. **使用了错误的 ioctl 命令:**
   - **错误:**  例如，错误地使用了 `FS_IOC_GET_ENCRYPTION_POLICY` 来尝试设置加密策略。
   - **后果:** `ioctl` 调用会失败，返回 `EINVAL` 错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `fscrypt.h` 的路径:**

1. **用户操作或 Framework API 调用:**  例如，用户在“设置”中启用设备加密，或者应用程序调用 `StorageManager.createApp будущемKey(...)`。

2. **System Server (Java/Kotlin):** Android Framework 的核心组件 System Server 处理这些请求。相关的代码位于 `android.os` 和 `android.security` 等包中。

3. **Storage Service (Java/Kotlin):**  System Server 中的 Storage Service 负责管理存储相关的操作，包括文件系统加密。

4. **Native Daemon (C++):** Storage Service 通常会通过 Binder IPC 调用一个 Native Daemon，例如 `vold` (Volume Daemon)。 `vold` 是一个 C++ 守护进程，负责执行底层的存储管理操作。

5. **Bionic libc 函数调用 (C++):** `vold` 中的代码会调用 Bionic C 库中的函数，例如 `open()`, `ioctl()`。 当需要执行文件系统加密操作时，会调用 `ioctl()`，并使用 `fscrypt.h` 中定义的 `FS_IOC_*` 命令和数据结构。

6. **Linux Kernel:** `ioctl()` 系统调用最终会到达 Linux 内核的文件系统层，由文件系统驱动程序（例如 ext4）的 fscrypt 相关代码处理。

**NDK 到 `fscrypt.h` 的路径:**

1. **NDK 应用调用:**  NDK 应用可以直接使用 POSIX API，包括 `open()` 和 `ioctl()`.

2. **Bionic libc 函数调用 (C/C++):** NDK 应用调用 `ioctl()` 函数。

3. **Linux Kernel:**  类似于 Framework 的路径，`ioctl()` 系统调用最终到达内核的文件系统层。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `ioctl` 系统调用的示例，用于调试文件系统加密相关的操作：

```javascript
// frida 脚本

function hook_ioctl() {
    const ioctlPtr = Module.findExportByName("libc.so", "ioctl");
    if (ioctlPtr) {
        Interceptor.attach(ioctlPtr, {
            onEnter: function (args) {
                const fd = args[0].toInt32();
                const request = args[1].toInt32();
                const argp = args[2];

                console.log(`ioctl called with fd: ${fd}, request: ${request}`);

                // 检查是否是 fscrypt 相关的 ioctl 命令
                if (request === 0xc0086613) { // FS_IOC_SET_ENCRYPTION_POLICY
                    console.log("  -> FS_IOC_SET_ENCRYPTION_POLICY");
                    // 可以进一步解析 argp 指向的 fscrypt_policy_v1 结构体
                } else if (request === 0xc0186617) { // FS_IOC_ADD_ENCRYPTION_KEY
                    console.log("  -> FS_IOC_ADD_ENCRYPTION_KEY");
                    // 可以进一步解析 argp 指向的 fscrypt_add_key_arg 结构体
                } else if (request === 0xc0106614) { // FS_IOC_GET_ENCRYPTION_POLICY
                    console.log("  -> FS_IOC_GET_ENCRYPTION_POLICY");
                    // 可以进一步解析 argp 指向的 fscrypt_policy_v1 结构体
                }
                // ... 可以添加其他 fscrypt 相关的 ioctl 命令的 hook

                // 如果需要查看参数的具体内容，可以使用 Memory.read* 函数
                // 例如，对于 FS_IOC_SET_ENCRYPTION_POLICY:
                // if (request === 0xc0086613) {
                //     const policy = Memory.readByteArray(argp, 8); // fscrypt_policy_v1 大小
                //     console.log("  Policy data:", hexdump(policy));
                // }
            },
            onLeave: function (retval) {
                console.log(`ioctl returned: ${retval}`);
            }
        });
        console.log("ioctl hook installed");
    } else {
        console.error("Failed to find ioctl in libc.so");
    }
}

setImmediate(hook_ioctl);
```

**使用方法:**

1. 将上述代码保存为 `.js` 文件（例如 `fscrypt_hook.js`）。
2. 使用 Frida 连接到 Android 设备上的目标进程 (例如 System Server 或你的 NDK 应用)：
   ```bash
   frida -U -f system_server -l fscrypt_hook.js --no-pause
   # 或者连接到正在运行的进程
   frida -U com.example.myapp -l fscrypt_hook.js
   ```
3. 当目标进程执行 fscrypt 相关的操作时，Frida 会拦截 `ioctl` 调用并在控制台上打印相关信息，包括文件描述符、ioctl 命令码以及可能的参数数据。

**注意:**

* 上述 Frida 脚本中的 ioctl 命令码 (例如 `0xc0086613`) 是根据 `_IO*` 宏计算出来的，可能需要根据具体的 Android 版本和内核版本进行调整。你可以查看头文件中的定义来确定正确的数值。
* 解析结构体数据需要了解其内存布局。`Memory.readByteArray` 和 `hexdump` 可以帮助你查看原始字节数据，然后你需要根据 `fscrypt.h` 中的结构体定义来解释这些数据。

通过 Frida Hook，你可以动态地观察 Android Framework 或 NDK 应用与 Linux 内核文件系统加密功能的交互过程，从而更好地理解其工作原理和调试相关问题。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/fscrypt.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_FSCRYPT_H
#define _UAPI_LINUX_FSCRYPT_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define FSCRYPT_POLICY_FLAGS_PAD_4 0x00
#define FSCRYPT_POLICY_FLAGS_PAD_8 0x01
#define FSCRYPT_POLICY_FLAGS_PAD_16 0x02
#define FSCRYPT_POLICY_FLAGS_PAD_32 0x03
#define FSCRYPT_POLICY_FLAGS_PAD_MASK 0x03
#define FSCRYPT_POLICY_FLAG_DIRECT_KEY 0x04
#define FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 0x08
#define FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 0x10
#define FSCRYPT_MODE_AES_256_XTS 1
#define FSCRYPT_MODE_AES_256_CTS 4
#define FSCRYPT_MODE_AES_128_CBC 5
#define FSCRYPT_MODE_AES_128_CTS 6
#define FSCRYPT_MODE_SM4_XTS 7
#define FSCRYPT_MODE_SM4_CTS 8
#define FSCRYPT_MODE_ADIANTUM 9
#define FSCRYPT_MODE_AES_256_HCTR2 10
#define FSCRYPT_POLICY_V1 0
#define FSCRYPT_KEY_DESCRIPTOR_SIZE 8
struct fscrypt_policy_v1 {
  __u8 version;
  __u8 contents_encryption_mode;
  __u8 filenames_encryption_mode;
  __u8 flags;
  __u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
};
#define FSCRYPT_KEY_DESC_PREFIX "fscrypt:"
#define FSCRYPT_KEY_DESC_PREFIX_SIZE 8
#define FSCRYPT_MAX_KEY_SIZE 64
struct fscrypt_key {
  __u32 mode;
  __u8 raw[FSCRYPT_MAX_KEY_SIZE];
  __u32 size;
};
#define FSCRYPT_POLICY_V2 2
#define FSCRYPT_KEY_IDENTIFIER_SIZE 16
struct fscrypt_policy_v2 {
  __u8 version;
  __u8 contents_encryption_mode;
  __u8 filenames_encryption_mode;
  __u8 flags;
  __u8 log2_data_unit_size;
  __u8 __reserved[3];
  __u8 master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
};
struct fscrypt_get_policy_ex_arg {
  __u64 policy_size;
  union {
    __u8 version;
    struct fscrypt_policy_v1 v1;
    struct fscrypt_policy_v2 v2;
  } policy;
};
#define FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR 1
#define FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER 2
struct fscrypt_key_specifier {
  __u32 type;
  __u32 __reserved;
  union {
    __u8 __reserved[32];
    __u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
    __u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
  } u;
};
struct fscrypt_provisioning_key_payload {
  __u32 type;
  __u32 __reserved;
  __u8 raw[];
};
struct fscrypt_add_key_arg {
  struct fscrypt_key_specifier key_spec;
  __u32 raw_size;
  __u32 key_id;
  __u32 __reserved[7];
#define __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED 0x00000001
  __u32 __flags;
  __u8 raw[];
};
struct fscrypt_remove_key_arg {
  struct fscrypt_key_specifier key_spec;
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY 0x00000001
#define FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS 0x00000002
  __u32 removal_status_flags;
  __u32 __reserved[5];
};
struct fscrypt_get_key_status_arg {
  struct fscrypt_key_specifier key_spec;
  __u32 __reserved[6];
#define FSCRYPT_KEY_STATUS_ABSENT 1
#define FSCRYPT_KEY_STATUS_PRESENT 2
#define FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED 3
  __u32 status;
#define FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF 0x00000001
  __u32 status_flags;
  __u32 user_count;
  __u32 __out_reserved[13];
};
#define FS_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct fscrypt_policy_v1)
#define FS_IOC_GET_ENCRYPTION_PWSALT _IOW('f', 20, __u8[16])
#define FS_IOC_GET_ENCRYPTION_POLICY _IOW('f', 21, struct fscrypt_policy_v1)
#define FS_IOC_GET_ENCRYPTION_POLICY_EX _IOWR('f', 22, __u8[9])
#define FS_IOC_ADD_ENCRYPTION_KEY _IOWR('f', 23, struct fscrypt_add_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY _IOWR('f', 24, struct fscrypt_remove_key_arg)
#define FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS _IOWR('f', 25, struct fscrypt_remove_key_arg)
#define FS_IOC_GET_ENCRYPTION_KEY_STATUS _IOWR('f', 26, struct fscrypt_get_key_status_arg)
#define FS_IOC_GET_ENCRYPTION_NONCE _IOR('f', 27, __u8[16])
#define fscrypt_policy fscrypt_policy_v1
#define FS_KEY_DESCRIPTOR_SIZE FSCRYPT_KEY_DESCRIPTOR_SIZE
#define FS_POLICY_FLAGS_PAD_4 FSCRYPT_POLICY_FLAGS_PAD_4
#define FS_POLICY_FLAGS_PAD_8 FSCRYPT_POLICY_FLAGS_PAD_8
#define FS_POLICY_FLAGS_PAD_16 FSCRYPT_POLICY_FLAGS_PAD_16
#define FS_POLICY_FLAGS_PAD_32 FSCRYPT_POLICY_FLAGS_PAD_32
#define FS_POLICY_FLAGS_PAD_MASK FSCRYPT_POLICY_FLAGS_PAD_MASK
#define FS_POLICY_FLAG_DIRECT_KEY FSCRYPT_POLICY_FLAG_DIRECT_KEY
#define FS_POLICY_FLAGS_VALID 0x07
#define FS_ENCRYPTION_MODE_INVALID 0
#define FS_ENCRYPTION_MODE_AES_256_XTS FSCRYPT_MODE_AES_256_XTS
#define FS_ENCRYPTION_MODE_AES_256_GCM 2
#define FS_ENCRYPTION_MODE_AES_256_CBC 3
#define FS_ENCRYPTION_MODE_AES_256_CTS FSCRYPT_MODE_AES_256_CTS
#define FS_ENCRYPTION_MODE_AES_128_CBC FSCRYPT_MODE_AES_128_CBC
#define FS_ENCRYPTION_MODE_AES_128_CTS FSCRYPT_MODE_AES_128_CTS
#define FS_ENCRYPTION_MODE_ADIANTUM FSCRYPT_MODE_ADIANTUM
#define FS_KEY_DESC_PREFIX FSCRYPT_KEY_DESC_PREFIX
#define FS_KEY_DESC_PREFIX_SIZE FSCRYPT_KEY_DESC_PREFIX_SIZE
#define FS_MAX_KEY_SIZE FSCRYPT_MAX_KEY_SIZE
#endif

"""

```