Response:
Let's break down the thought process for answering the request about the `nfs4.h` file.

**1. Understanding the Core Request:**

The central task is to analyze the provided C header file (`nfs4.h`) and explain its purpose, relationship to Android, its contents, and how Android interacts with it. The user also requests examples of usage, debugging with Frida, and common errors.

**2. Initial Assessment of the File:**

* **Header File Nature:** The `#ifndef _UAPI_LINUX_NFS4_H` and `#define _UAPI_LINUX_NFS4_H` clearly indicate it's a header file designed to prevent multiple inclusions.
* **`linux/nfs4.h` Path:** The path `bionic/libc/kernel/uapi/linux/nfs4.handroid` is crucial. This tells us:
    * `bionic`: It's part of Android's core C library.
    * `libc`:  Specifically related to the C library functionalities.
    * `kernel`: It's defining interfaces related to the Linux kernel.
    * `uapi`: Stands for "user-space API," meaning it defines how user-space programs interact with the kernel.
    * `linux/nfs4.h`: It's defining structures and constants related to the NFSv4 (Network File System version 4) protocol within the Linux kernel.
    * `.handroid`:  This suffix suggests Android-specific modifications or customizations.

**3. Identifying Key Information within the File:**

The file primarily consists of:

* **Macros Defining Sizes:** `NFS4_BITMAP_SIZE`, `NFS4_VERIFIER_SIZE`, `NFS4_STATEID_SIZE`, `NFS4_FHSIZE`, etc. These define the sizes of data structures used in the NFSv4 protocol.
* **Macros Defining Access Rights:** `NFS4_ACCESS_READ`, `NFS4_ACCESS_WRITE`, `NFS4_ACCESS_EXECUTE`, etc. These define bitmasks representing different permissions for accessing files over NFS.
* **Macros Defining Flags and Options:**  A large number of macros like `NFS4_FH_PERSISTENT`, `NFS4_OPEN_RESULT_CONFIRM`, `NFS4_SHARE_ACCESS_READ`, `NFS4_ACE_FILE_INHERIT_ACE`, `EXCHGID4_FLAG_SUPP_MOVED_REFER`, and `SEQ4_STATUS_CB_PATH_DOWN`. These define various options, flags, and status codes used in NFSv4 operations.
* **A Few General Definitions:** `NFS4_MAXPATHLEN`, `NFS4_MAXNAMLEN`, `NFS4_OPAQUE_LIMIT`, `NFS4_MAX_UINT64`, `NFS4_MAX_OPS`, `NFS4_MAX_BACK_CHANNEL_OPS`.

**4. Relating to Android:**

The "handroid" suffix is a strong indicator that this is a version of the standard Linux NFSv4 header adapted for Android. The key connection is that Android devices might act as NFS clients or servers, requiring them to interact with NFSv4.

* **Examples:**  Accessing files on a network storage device via NFS, sharing files from an Android device to a network.

**5. Addressing Specific Questions:**

* **Functionality:** The file doesn't contain *functions*. It defines *constants and macros*. Its primary function is to provide definitions for interacting with the NFSv4 protocol at a low level.
* **libc Functions:**  Since it's just definitions, there are no specific *libc functions* defined within this header file. It's used *by* libc (or code linked against libc) when making NFS-related system calls. The actual implementation of those system calls resides in the kernel.
* **Dynamic Linker:**  This header file itself doesn't directly involve the dynamic linker. However, if Android applications or libraries use NFS functionality, they would link against libc, which might internally use these definitions.
    * **SO Layout:**  The header file wouldn't dictate the layout of a `.so` file. The `.so` would contain the *implementation* of NFS-related functions, potentially using these definitions.
    * **Linking Process:** When an application uses NFS, the linker resolves the necessary symbols from libc.
* **Logic Reasoning (Hypothetical):** Since it's mostly definitions, there's limited logic to reason about directly within the file. We can hypothesize about how these definitions would be used in system calls, but that's not contained within the file itself.
* **User Errors:**  Incorrectly using the defined constants (e.g., passing the wrong access flags to an NFS system call) would be a common error.
* **Android Framework/NDK:**  The Android Framework or NDK wouldn't directly include this header. Instead, higher-level Java or C/C++ APIs would provide abstractions over NFS functionality, eventually leading to system calls that utilize these definitions.

**6. Frida Hook Example:**

To hook NFS-related system calls, one would target functions like `open`, `read`, `write`, or more specific NFS system calls (if they exist and are exposed). The hook would need to examine the arguments to see if they relate to NFS operations (e.g., checking file paths or specific flags). Since this header defines *constants*, you could potentially hook a function that uses these constants as arguments, and check if the passed argument matches a specific constant defined in this header.

**7. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request:

* Start with a summary of the file's purpose.
* Explain its relationship to Android.
* Detail the functionality (primarily defining constants).
* Clarify the lack of libc functions within the header itself.
* Explain the indirect involvement with the dynamic linker.
* Provide a basic Frida hook example.
* Mention potential user errors.
* Briefly describe how the Android Framework/NDK interacts indirectly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe there are some inline functions or structs in the file. *Correction:*  A closer look reveals only `#define` macros and `#include`.
* **Initial thought:** Focus heavily on the dynamic linker. *Correction:* The file's direct relationship to the dynamic linker is weak. Emphasize the indirect link through libc.
* **Initial thought:** Provide very specific Frida hook code. *Correction:*  Since we don't know the exact system calls being used, a more general example of hooking system calls related to file access is more appropriate. Mentioning how to check for NFS-specific arguments adds further value.

By following these steps and iterating on the understanding of the file and the request, a comprehensive and accurate answer can be constructed.
这个文件 `bionic/libc/kernel/uapi/linux/nfs4.handroid` 是 Android Bionic C 库中用于定义与 NFSv4 (Network File System version 4) 协议相关的用户空间 API 的头文件。它来源于 Linux 内核的 UAPI (User API) 部分，并可能经过 Android 特定的修改（通过 `.handroid` 后缀体现）。

**功能列举:**

该文件主要定义了用于与 Linux 内核中 NFSv4 实现进行交互的常量、宏定义和数据结构。具体功能包括：

1. **定义 NFSv4 协议中使用的常量和宏:**
   - **大小定义:**  例如 `NFS4_BITMAP_SIZE`, `NFS4_VERIFIER_SIZE`, `NFS4_STATEID_SIZE`, `NFS4_FHSIZE` 等，定义了各种 NFSv4 数据结构的大小。
   - **访问权限:** 例如 `NFS4_ACCESS_READ`, `NFS4_ACCESS_WRITE`, `NFS4_ACCESS_EXECUTE` 等，定义了不同的文件访问权限。
   - **标志位和选项:**  例如 `NFS4_FH_PERSISTENT`, `NFS4_OPEN_RESULT_CONFIRM`, `NFS4_SHARE_ACCESS_READ`,  `NFS4_ACE_FILE_INHERIT_ACE`, `EXCHGID4_FLAG_SUPP_MOVED_REFER`, `SEQ4_STATUS_CB_PATH_DOWN` 等，定义了 NFSv4 操作中可以使用的各种标志和选项。
   - **最大值限制:** 例如 `NFS4_MAXPATHLEN`, `NFS4_MAXNAMLEN`, `NFS4_OPAQUE_LIMIT`, `NFS4_MAX_SESSIONID_LEN`, `NFS4_MAX_UINT64`, `NFS4_MAX_OPS`, `NFS4_MAX_BACK_CHANNEL_OPS` 等，定义了各种参数的最大值。
   - **ACE (Access Control Entry) 相关定义:**  例如 `NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE`, `NFS4_ACE_FILE_INHERIT_ACE`, `NFS4_ACE_READ_DATA` 等，定义了 NFSv4 ACL（访问控制列表）中使用的各种类型和权限。
   - **会话和状态相关定义:** 例如 `EXCHGID4_FLAG_*`, `SEQ4_STATUS_*` 等，定义了与 NFSv4 会话建立和状态管理相关的标志位。

2. **为用户空间程序提供与 NFSv4 内核模块交互的接口:**  通过这些定义，用户空间的程序可以使用标准 C 库的系统调用（例如 `open()`, `read()`, `write()`, `ioctl()` 等）与内核中的 NFSv4 客户端实现进行通信。

**与 Android 功能的关系及举例:**

虽然 Android 设备通常不直接作为 NFS 服务器，但它们可以作为 NFS 客户端来挂载和访问网络上的共享文件系统。这个头文件中的定义使得 Android 系统能够与 NFSv4 服务器进行交互。

**举例:**

- Android 设备上的文件管理器应用可能允许用户添加 NFS 网络存储位置。当用户尝试访问这些位置上的文件时，系统底层会使用 NFSv4 协议与服务器通信。这个头文件中的 `NFS4_ACCESS_READ`, `NFS4_ACCESS_WRITE` 等常量会被用来构造相应的 NFSv4 请求，以请求读取或写入文件的权限。
- 某些 Android 应用可能需要访问存储在 NFS 服务器上的配置文件或数据文件。这些应用会间接地使用到这个头文件中定义的常量和结构。
- 在 Android 系统中，一些后台服务或守护进程可能会使用 NFS 来进行文件同步或备份等操作。

**libc 函数的实现解释:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只定义了常量和宏。 这些常量和宏会被 Bionic C 库中的 NFS 相关系统调用包装函数所使用。

例如，当一个 Android 应用调用 `open()` 函数尝试打开一个 NFS 文件时，Bionic C 库会将这个调用转换为相应的内核系统调用。在内核处理这个系统调用时，可能会用到这个头文件中定义的常量，比如文件访问权限标志。

**涉及 dynamic linker 的功能:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。Dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 负责在程序运行时加载和链接共享库。

但是，如果 Android 应用程序使用了与 NFS 相关的库（例如，如果存在一个专门处理 NFS 交互的共享库，尽管在 Android 中这种情况比较少见，因为 NFS 支持通常集成在内核和 libc 中），那么 dynamic linker 会负责加载这些库。

**so 布局样本和链接处理过程 (假设存在一个 NFS 相关的共享库):**

假设存在一个名为 `libnfsclient.so` 的共享库，它封装了与 NFS 交互的功能。

**`libnfsclient.so` 布局样本 (简化):**

```assembly
.text:
    nfs_open:  // 封装了 open 系统调用，可能使用了 nfs4.h 中的常量
        ...
        mov     r0, #NFS4_ACCESS_READ  // 使用了 nfs4.h 中的常量
        svc     #SYS_openat          // 发起系统调用
        ...
    nfs_read:
        ...
.data:
    g_nfs_version: .word 4
.dynamic:
    ... (符号表，重定位表等)
```

**链接处理过程:**

1. **编译时:** 应用程序的代码在编译时会包含对 `libnfsclient.so` 中函数的调用。编译器会生成相应的符号引用。
2. **链接时:** 链接器（在 Android 中通常是 `ld`）会将应用程序的目标文件与 `libnfsclient.so` 链接在一起。链接器会解析应用程序中对 `libnfsclient.so` 中符号的引用，并生成最终的可执行文件。可执行文件中会记录需要加载的共享库的信息。
3. **运行时:** 当应用程序启动时，dynamic linker 会被内核调用。
4. **加载共享库:** Dynamic linker 会读取可执行文件的头部信息，找到需要加载的共享库列表（包括 `libnfsclient.so`）。
5. **加载到内存:** Dynamic linker 会将 `libnfsclient.so` 加载到内存中的特定地址。
6. **符号解析和重定位:** Dynamic linker 会解析应用程序和 `libnfsclient.so` 之间的符号引用，并根据加载地址修正代码中的地址。例如，如果 `nfs_open` 函数中使用了 `NFS4_ACCESS_READ` 常量，那么这个常量的值会在编译时确定，并在运行时通过链接过程进行关联。

**由于 `nfs4.h` 主要定义常量，它对 dynamic linker 的影响是间接的：它提供的常量会被可能与 NFS 交互的共享库所使用。**

**逻辑推理 (假设输入与输出):**

由于此文件是头文件，主要定义常量，不存在直接的逻辑推理过程。逻辑推理发生在使用了这些常量的代码中。

**假设场景:**  一个程序尝试以只读模式打开一个 NFS 文件。

**假设输入:**  调用 `open()` 函数，传入包含 NFS 文件路径的字符串，以及标志 `O_RDONLY`。

**使用 `nfs4.h` 中的信息:**  在内核的 NFS 客户端实现中，会将 `O_RDONLY` 转换为 NFSv4 协议中相应的访问权限标志，即 `NFS4_ACCESS_READ`。

**假设输出:**  内核会构造一个包含 `NFS4_ACCESS_READ` 权限信息的 NFSv4 请求发送给服务器。如果服务器允许读取，则 `open()` 系统调用成功返回文件描述符；否则返回错误。

**用户或编程常见的使用错误:**

1. **不理解访问权限标志:**  错误地组合或使用 `NFS4_ACCESS_*` 常量可能导致权限不足或操作失败。例如，尝试使用 `NFS4_ACCESS_WRITE` 打开一个只读挂载的文件。
2. **错误地配置 NFS 客户端:**  例如，NFS 服务器未正确导出文件系统，或者客户端的配置（例如挂载选项）不正确，导致连接失败或操作异常。这与 `nfs4.h` 本身关系不大，但与之定义的协议相关。
3. **假设本地文件系统语义:**  NFS 具有网络延迟和状态管理的复杂性，与本地文件系统的语义有所不同。例如，文件锁的行为可能不同。程序员可能错误地假设 NFS 的行为与本地文件系统完全一致。
4. **忽略错误处理:**  与 NFS 服务器的通信可能因为网络问题或其他原因失败。不进行充分的错误处理可能导致程序崩溃或数据丢失.

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

**路径:**

1. **Java 代码 (Android Framework):** 用户在文件管理器或应用中尝试访问 NFS 文件。
2. **System Services (Android Framework):** Framework 会调用相应的系统服务（例如 `StorageManagerService`）。
3. **Native 代码 (Android Runtime/Bionic):** 系统服务会通过 JNI (Java Native Interface) 调用到 Native 代码，最终可能涉及 Bionic C 库中的函数。
4. **系统调用 (Bionic C Library):** Bionic C 库中的函数（例如 `open()`, `mount()` 等）会被调用。当操作涉及 NFS 时，这些函数会构建相应的系统调用。
5. **Linux 内核:** 内核接收到系统调用，NFS 客户端模块会处理这些调用，并根据 `nfs4.h` 中定义的常量和结构，构造 NFSv4 协议消息与服务器通信。

**Frida Hook 示例:**

假设我们想观察在尝试打开 NFS 文件时，`open()` 系统调用中使用的访问标志。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.android.documentsui"]) # 假设是文件管理器进程
    session = device.attach(pid)
    script = session.create_script("""
        // 定义 nfs4.h 中相关的常量 (需要手动复制)
        const NFS4_ACCESS_READ = 0x0001;
        const NFS4_ACCESS_WRITE = 0x0004;
        const NFS4_ACCESS_EXECUTE = 0x0020;

        Interceptor.attach(Module.findExportByName("libc.so", "open"), {
            onEnter: function(args) {
                const pathname = args[0].readUtf8String();
                const flags = args[1].toInt();
                if (pathname.startsWith("/mnt/nfs/")) { // 假设 NFS 挂载点
                    this.nfs_file = true;
                    send({ type: "nfs_open_enter", pathname: pathname, flags: flags });
                } else {
                    this.nfs_file = false;
                }
            },
            onLeave: function(retval) {
                if (this.nfs_file) {
                    send({ type: "nfs_open_leave", retval: retval.toInt() });
                }
            }
        });

        // 你可以添加更多 hook 来观察其他 NFS 相关的系统调用，例如 mount

    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except Exception as e:
    print(e)
```

**解释:**

1. **连接到设备和进程:** 代码使用 Frida 连接到 USB 设备，并附加到文件管理器进程 (`com.android.documentsui`)。你需要根据实际情况修改进程名称。
2. **创建 Frida 脚本:**
   - **复制常量:**  由于 Frida 脚本无法直接包含头文件，你需要手动将 `nfs4.h` 中你关心的常量定义复制到脚本中。
   - **Hook `open()` 系统调用:** `Interceptor.attach` 用于 hook `libc.so` 中的 `open()` 函数。
   - **`onEnter`:** 在 `open()` 函数被调用之前执行。
     - 获取 `pathname` 和 `flags` 参数。
     - 检查 `pathname` 是否以 `/mnt/nfs/` 开头（假设这是 NFS 挂载点）。
     - 如果是 NFS 文件，则发送包含路径和标志的消息。
   - **`onLeave`:** 在 `open()` 函数返回之后执行。
     - 如果是 NFS 文件，则发送包含返回值的消息.
3. **加载和运行脚本:** 脚本被加载并运行，开始监控 `open()` 函数的调用。
4. **操作文件管理器:** 在 Android 设备上，尝试通过文件管理器访问 NFS 共享的文件。
5. **查看输出:** Frida 会在控制台上打印出捕获到的 `open()` 调用信息，包括尝试打开的 NFS 文件路径和使用的标志。你可以分析这些标志，看它们是否与 `nfs4.h` 中定义的常量一致。

**注意:**

- 你需要根据你想要调试的具体场景选择合适的进程和系统调用进行 hook。
- 对于更底层的 NFS 交互，可能需要 hook 更底层的系统调用，例如 `mount()` 或专门的 NFS 系统调用 (如果存在并被使用)。
- 分析系统调用的参数和返回值需要一定的内核和 NFS 协议知识。

这个 `nfs4.handroid` 头文件是 Android 系统与 NFSv4 协议交互的基础，虽然用户空间的应用程序通常不会直接包含它，但它定义的常量和结构体在系统底层发挥着关键作用。 通过 Frida 等工具，我们可以观察到这些定义如何在系统调用的参数中体现出来，从而更好地理解 Android 如何与网络文件系统进行交互。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/nfs4.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_NFS4_H
#define _UAPI_LINUX_NFS4_H
#include <linux/types.h>
#define NFS4_BITMAP_SIZE 3
#define NFS4_VERIFIER_SIZE 8
#define NFS4_STATEID_SEQID_SIZE 4
#define NFS4_STATEID_OTHER_SIZE 12
#define NFS4_STATEID_SIZE (NFS4_STATEID_SEQID_SIZE + NFS4_STATEID_OTHER_SIZE)
#define NFS4_FHSIZE 128
#define NFS4_MAXPATHLEN PATH_MAX
#define NFS4_MAXNAMLEN NAME_MAX
#define NFS4_OPAQUE_LIMIT 1024
#define NFS4_MAX_SESSIONID_LEN 16
#define NFS4_ACCESS_READ 0x0001
#define NFS4_ACCESS_LOOKUP 0x0002
#define NFS4_ACCESS_MODIFY 0x0004
#define NFS4_ACCESS_EXTEND 0x0008
#define NFS4_ACCESS_DELETE 0x0010
#define NFS4_ACCESS_EXECUTE 0x0020
#define NFS4_ACCESS_XAREAD 0x0040
#define NFS4_ACCESS_XAWRITE 0x0080
#define NFS4_ACCESS_XALIST 0x0100
#define NFS4_FH_PERSISTENT 0x0000
#define NFS4_FH_NOEXPIRE_WITH_OPEN 0x0001
#define NFS4_FH_VOLATILE_ANY 0x0002
#define NFS4_FH_VOL_MIGRATION 0x0004
#define NFS4_FH_VOL_RENAME 0x0008
#define NFS4_OPEN_RESULT_CONFIRM 0x0002
#define NFS4_OPEN_RESULT_LOCKTYPE_POSIX 0x0004
#define NFS4_OPEN_RESULT_PRESERVE_UNLINKED 0x0008
#define NFS4_OPEN_RESULT_NO_OPEN_STATEID 0x0010
#define NFS4_OPEN_RESULT_MAY_NOTIFY_LOCK 0x0020
#define NFS4_SHARE_ACCESS_MASK 0x000F
#define NFS4_SHARE_ACCESS_READ 0x0001
#define NFS4_SHARE_ACCESS_WRITE 0x0002
#define NFS4_SHARE_ACCESS_BOTH 0x0003
#define NFS4_SHARE_DENY_READ 0x0001
#define NFS4_SHARE_DENY_WRITE 0x0002
#define NFS4_SHARE_DENY_BOTH 0x0003
#define NFS4_SHARE_WANT_MASK 0xFF00
#define NFS4_SHARE_WANT_NO_PREFERENCE 0x0000
#define NFS4_SHARE_WANT_READ_DELEG 0x0100
#define NFS4_SHARE_WANT_WRITE_DELEG 0x0200
#define NFS4_SHARE_WANT_ANY_DELEG 0x0300
#define NFS4_SHARE_WANT_NO_DELEG 0x0400
#define NFS4_SHARE_WANT_CANCEL 0x0500
#define NFS4_SHARE_WHEN_MASK 0xF0000
#define NFS4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL 0x10000
#define NFS4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED 0x20000
#define NFS4_SHARE_WANT_DELEG_TIMESTAMPS 0x100000
#define NFS4_SHARE_WANT_OPEN_XOR_DELEGATION 0x200000
#define NFS4_CDFC4_FORE 0x1
#define NFS4_CDFC4_BACK 0x2
#define NFS4_CDFC4_BOTH 0x3
#define NFS4_CDFC4_FORE_OR_BOTH 0x3
#define NFS4_CDFC4_BACK_OR_BOTH 0x7
#define NFS4_CDFS4_FORE 0x1
#define NFS4_CDFS4_BACK 0x2
#define NFS4_CDFS4_BOTH 0x3
#define NFS4_SET_TO_SERVER_TIME 0
#define NFS4_SET_TO_CLIENT_TIME 1
#define NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE 0
#define NFS4_ACE_ACCESS_DENIED_ACE_TYPE 1
#define NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE 2
#define NFS4_ACE_SYSTEM_ALARM_ACE_TYPE 3
#define ACL4_SUPPORT_ALLOW_ACL 0x01
#define ACL4_SUPPORT_DENY_ACL 0x02
#define ACL4_SUPPORT_AUDIT_ACL 0x04
#define ACL4_SUPPORT_ALARM_ACL 0x08
#define NFS4_ACL_AUTO_INHERIT 0x00000001
#define NFS4_ACL_PROTECTED 0x00000002
#define NFS4_ACL_DEFAULTED 0x00000004
#define NFS4_ACE_FILE_INHERIT_ACE 0x00000001
#define NFS4_ACE_DIRECTORY_INHERIT_ACE 0x00000002
#define NFS4_ACE_NO_PROPAGATE_INHERIT_ACE 0x00000004
#define NFS4_ACE_INHERIT_ONLY_ACE 0x00000008
#define NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG 0x00000010
#define NFS4_ACE_FAILED_ACCESS_ACE_FLAG 0x00000020
#define NFS4_ACE_IDENTIFIER_GROUP 0x00000040
#define NFS4_ACE_INHERITED_ACE 0x00000080
#define NFS4_ACE_READ_DATA 0x00000001
#define NFS4_ACE_LIST_DIRECTORY 0x00000001
#define NFS4_ACE_WRITE_DATA 0x00000002
#define NFS4_ACE_ADD_FILE 0x00000002
#define NFS4_ACE_APPEND_DATA 0x00000004
#define NFS4_ACE_ADD_SUBDIRECTORY 0x00000004
#define NFS4_ACE_READ_NAMED_ATTRS 0x00000008
#define NFS4_ACE_WRITE_NAMED_ATTRS 0x00000010
#define NFS4_ACE_EXECUTE 0x00000020
#define NFS4_ACE_DELETE_CHILD 0x00000040
#define NFS4_ACE_READ_ATTRIBUTES 0x00000080
#define NFS4_ACE_WRITE_ATTRIBUTES 0x00000100
#define NFS4_ACE_WRITE_RETENTION 0x00000200
#define NFS4_ACE_WRITE_RETENTION_HOLD 0x00000400
#define NFS4_ACE_DELETE 0x00010000
#define NFS4_ACE_READ_ACL 0x00020000
#define NFS4_ACE_WRITE_ACL 0x00040000
#define NFS4_ACE_WRITE_OWNER 0x00080000
#define NFS4_ACE_SYNCHRONIZE 0x00100000
#define NFS4_ACE_GENERIC_READ 0x00120081
#define NFS4_ACE_GENERIC_WRITE 0x00160106
#define NFS4_ACE_GENERIC_EXECUTE 0x001200A0
#define NFS4_ACE_MASK_ALL 0x001F01FF
#define EXCHGID4_FLAG_SUPP_MOVED_REFER 0x00000001
#define EXCHGID4_FLAG_SUPP_MOVED_MIGR 0x00000002
#define EXCHGID4_FLAG_BIND_PRINC_STATEID 0x00000100
#define EXCHGID4_FLAG_USE_NON_PNFS 0x00010000
#define EXCHGID4_FLAG_USE_PNFS_MDS 0x00020000
#define EXCHGID4_FLAG_USE_PNFS_DS 0x00040000
#define EXCHGID4_FLAG_MASK_PNFS 0x00070000
#define EXCHGID4_FLAG_UPD_CONFIRMED_REC_A 0x40000000
#define EXCHGID4_FLAG_CONFIRMED_R 0x80000000
#define EXCHGID4_FLAG_SUPP_FENCE_OPS 0x00000004
#define EXCHGID4_FLAG_MASK_A 0x40070103
#define EXCHGID4_FLAG_MASK_R 0x80070103
#define EXCHGID4_2_FLAG_MASK_R 0x80070107
#define SEQ4_STATUS_CB_PATH_DOWN 0x00000001
#define SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING 0x00000002
#define SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED 0x00000004
#define SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED 0x00000008
#define SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED 0x00000010
#define SEQ4_STATUS_ADMIN_STATE_REVOKED 0x00000020
#define SEQ4_STATUS_RECALLABLE_STATE_REVOKED 0x00000040
#define SEQ4_STATUS_LEASE_MOVED 0x00000080
#define SEQ4_STATUS_RESTART_RECLAIM_NEEDED 0x00000100
#define SEQ4_STATUS_CB_PATH_DOWN_SESSION 0x00000200
#define SEQ4_STATUS_BACKCHANNEL_FAULT 0x00000400
#define NFS4_SECINFO_STYLE4_CURRENT_FH 0
#define NFS4_SECINFO_STYLE4_PARENT 1
#define NFS4_MAX_UINT64 (~(__u64) 0)
#define NFS4_MAX_OPS 8
#define NFS4_MAX_BACK_CHANNEL_OPS 2
#endif

"""

```