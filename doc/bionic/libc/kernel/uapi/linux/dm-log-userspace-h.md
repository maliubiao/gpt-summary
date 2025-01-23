Response:
Let's break down the thought process to answer the request about `dm-log-userspace.h`.

**1. Understanding the Context:**

The first and most crucial step is to understand what this file represents. The path `bionic/libc/kernel/uapi/linux/dm-log-userspace.h` immediately provides key information:

* **`bionic`:** This points to Android's core C library, indicating the file is related to low-level system functionalities.
* **`libc`:** Confirms it's part of the C library, suggesting it defines system-level interfaces.
* **`kernel`:** Implies interaction with the Linux kernel.
* **`uapi`:**  Stands for "user API". This is a critical clue:  this header defines structures and constants meant for user-space programs to interact with the kernel.
* **`linux`:**  Specifies it's a Linux-specific header.
* **`dm-log-userspace.h`:** The filename itself gives a strong hint about its purpose: it's related to logging within the Device Mapper (DM) subsystem, specifically for user-space interaction.

**2. Analyzing the File Contents:**

With the context established, the next step is to meticulously go through the file's content:

* **`#ifndef __DM_LOG_USERSPACE_H__ ... #define __DM_LOG_USERSPACE_H__ ... #endif`:**  This is a standard header guard, preventing multiple inclusions. Not a functional aspect, but good to note.
* **`#include <linux/types.h>` and `#include <linux/dm-ioctl.h>`:**  These include directives are crucial. They tell us that `dm-log-userspace.h` relies on definitions from these other kernel headers. `linux/types.h` defines fundamental data types, and `linux/dm-ioctl.h` is specific to Device Mapper and likely contains the definitions for the `DM_UUID_LEN` used later.
* **`#define DM_ULOG_CTR 1`, `#define DM_ULOG_DTR 2`, ... `#define DM_ULOG_STATUS_TABLE 16`, `#define DM_ULOG_IS_REMOTE_RECOVERING 17`:** These are preprocessor macros defining integer constants. The `DM_ULOG_` prefix strongly suggests these represent different types of user-space log requests to the Device Mapper. The names themselves (CTR, DTR, PRESUSPEND, etc.) give clues about their potential meaning.
* **`#define DM_ULOG_REQUEST_MASK 0xFF`:**  Another macro, likely used for bitwise operations related to request types.
* **`#define DM_ULOG_REQUEST_TYPE(request_type) (DM_ULOG_REQUEST_MASK & (request_type))`:**  A macro defining how to extract the core request type from a larger value (though in this case, it's just masking, implying the request type *is* the relevant information).
* **`#define DM_ULOG_REQUEST_VERSION 3`:**  Indicates a version number for the request structure.
* **`struct dm_ulog_request { ... }`:** This is the central structure definition. Each member needs to be examined:
    * `__u64 luid`: Likely a logical unit ID.
    * `char uuid[DM_UUID_LEN]`:  A UUID (Universally Unique Identifier), essential for identifying DM components.
    * `char padding[3]`:  Padding for alignment purposes, common in structures.
    * `__u32 version`:  Matches the earlier `DM_ULOG_REQUEST_VERSION` macro.
    * `__s32 error`: An error code returned by the kernel.
    * `__u32 seq`: A sequence number, useful for ordering events.
    * `__u32 request_type`:  Connects back to the `DM_ULOG_` constants, identifying the specific request.
    * `__u32 data_size`:  The size of the accompanying data.
    * `char data[]`: A flexible array member (often the last member of a structure) to hold variable-sized data associated with the request.

**3. Answering the Specific Questions:**

Now, with a solid understanding of the file, I can address each point in the original request:

* **功能列举:**  This is a straightforward summary of the identified elements: defining request types and the structure for communication.
* **与 Android 功能的关系和举例:** This requires connecting the dots. Device Mapper is a core part of Android's storage management (e.g., for logical volumes, encryption, snapshots). The log mechanism likely aids in debugging and monitoring these operations. Examples like file system checks, encryption state changes, and snapshot creation are relevant.
* **libc 函数功能解释:** This is a trick question! The file *doesn't* define libc functions. It defines kernel-related structures and constants. The explanation needs to clarify this distinction and mention the *use* of these definitions by user-space programs (which *would* use libc functions to interact with the kernel). System calls like `ioctl` are the key here.
* **Dynamic Linker 功能:**  Again, this file doesn't directly involve the dynamic linker. The explanation needs to state this. However, the *programs using* this header would be linked by the dynamic linker. A basic shared library layout example and a simplified linking explanation can be provided to illustrate the *context*, even if the file itself isn't a dynamic library.
* **逻辑推理 (假设输入/输出):**  This involves creating a hypothetical scenario. Choosing a concrete `DM_ULOG_` constant (like `DM_ULOG_GET_REGION_SIZE`) and outlining how a user-space program might construct and send such a request, and how the kernel might respond, is a good way to illustrate the data flow.
* **用户或编程常见错误:**  Focus on errors related to incorrect usage of the structure or understanding of the request types. Incorrect sizes, wrong request types, and misinterpreting error codes are good examples.
* **Android Framework/NDK 到达这里的步骤:** This requires tracing the call flow. Start with a high-level action (like a file operation), show how it might trigger a storage-related operation, which in turn might use the Device Mapper. Mentioning the `ioctl` system call as the bridge between user-space and kernel is crucial. A Frida hook example targeting the `ioctl` system call with relevant arguments can demonstrate observation of this interaction.

**4. Language and Formatting:**

Finally, ensure the response is in clear, concise Chinese, using appropriate terminology and formatting (e.g., code blocks, bullet points) for readability.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this file defines some helper functions in libc for DM logging. **Correction:**  The `uapi` designation means it's for *user* API, primarily defining structures and constants, not function implementations.
* **Initial thought:**  Focus heavily on the `dm-ioctl.h` include. **Refinement:** While important, emphasize that *this* file's main contribution is the specific logging-related definitions.
* **Initial thought:** Provide a very detailed explanation of the dynamic linker. **Refinement:** Keep the dynamic linker explanation concise and focus on its relevance to *programs using* this header, not the header itself.
* **Consideration:** Should I explain Device Mapper in detail? **Decision:** Keep the DM explanation at a high level, focusing on its role in storage management within Android, to avoid getting too sidetracked.

By following this structured thought process, combining domain knowledge with careful analysis of the provided code, a comprehensive and accurate answer can be generated.
这个头文件 `dm-log-userspace.handroid` 定义了用户空间程序与内核中的 Device Mapper (DM) 子系统进行日志交互的接口。Device Mapper 是 Linux 内核中一个通用的块设备映射框架，它允许将一个或多个底层块设备组合成新的虚拟块设备，并提供诸如快照、加密、精简配置等功能。

由于这个文件位于 `bionic/libc/kernel/uapi/linux/`，它属于 Android 的 Bionic C 库的一部分，并且是内核提供的用户空间 API (uapi)。这意味着它定义了用户空间程序可以直接使用的结构体和宏，以便与内核中的 DM 日志功能进行通信。

**功能列举:**

这个头文件定义了以下功能：

1. **定义了不同的用户空间日志请求类型 (Macros):**
   - `DM_ULOG_CTR`:  可能表示构造函数 (Constructor) 或创建事件。
   - `DM_ULOG_DTR`:  可能表示析构函数 (Destructor) 或销毁事件。
   - `DM_ULOG_PRESUSPEND`:  在挂起 (Suspend) 操作之前的事件。
   - `DM_ULOG_POSTSUSPEND`: 在挂起操作之后的事件。
   - `DM_ULOG_RESUME`: 在恢复 (Resume) 操作时的事件。
   - `DM_ULOG_GET_REGION_SIZE`: 请求获取日志区域的大小。
   - `DM_ULOG_IS_CLEAN`: 请求检查日志是否干净 (没有未完成的操作)。
   - `DM_ULOG_IN_SYNC`: 请求检查日志是否同步。
   - `DM_ULOG_FLUSH`: 请求刷新日志。
   - `DM_ULOG_MARK_REGION`: 请求标记一个日志区域。
   - `DM_ULOG_CLEAR_REGION`: 请求清除一个日志区域。
   - `DM_ULOG_GET_RESYNC_WORK`: 请求获取重新同步的工作信息。
   - `DM_ULOG_SET_REGION_SYNC`: 请求设置日志区域的同步状态。
   - `DM_ULOG_GET_SYNC_COUNT`: 请求获取同步计数。
   - `DM_ULOG_STATUS_INFO`: 请求获取状态信息。
   - `DM_ULOG_STATUS_TABLE`: 请求获取状态表。
   - `DM_ULOG_IS_REMOTE_RECOVERING`: 请求检查是否正在进行远程恢复。

2. **定义了请求掩码和类型提取宏:**
   - `DM_ULOG_REQUEST_MASK`: 用于提取请求类型的掩码。
   - `DM_ULOG_REQUEST_TYPE(request_type)`:  使用掩码提取请求类型的宏。

3. **定义了请求版本号:**
   - `DM_ULOG_REQUEST_VERSION`:  指示请求结构体的版本。

4. **定义了用户空间日志请求结构体 `dm_ulog_request`:**
   - `luid`:  逻辑单元 ID (Logical Unit ID)。
   - `uuid`:  通用唯一标识符 (Universally Unique Identifier)，用于标识 DM 设备。
   - `padding`:  填充字节，用于结构体对齐。
   - `version`:  请求结构体的版本号。
   - `error`:  内核返回的错误代码。
   - `seq`:  序列号，用于跟踪请求。
   - `request_type`:  请求类型，对应上面定义的 `DM_ULOG_` 宏。
   - `data_size`:  `data` 字段的大小。
   - `data[]`:  变长数组，用于携带请求的附加数据。

**与 Android 功能的关系及举例说明:**

Device Mapper 在 Android 系统中被广泛使用，例如：

* **Logical Volume Management (LVM):** Android 可以使用 LVM 来管理存储，Device Mapper 是 LVM 的基础。这个日志机制可以用于跟踪 LVM 操作的状态和事件。
* **Disk Encryption (dm-crypt):** Android 的磁盘加密功能通常基于 Device Mapper 的 `dm-crypt` 模块。这里的日志可以记录加密设备的创建、挂载、卸载等事件。
* **Snapshotting:** Device Mapper 允许创建存储设备的快照。日志可以记录快照的创建、删除和回滚等操作。
* **Verified Boot (dm-verity):** Android 的 Verified Boot 功能使用 `dm-verity` 模块来验证系统分区的完整性。日志可能记录验证过程中的错误或事件。
* **轻量级存储虚拟化 (e.g., for containers):**  在某些 Android 环境中，Device Mapper 可能被用于创建隔离的存储层。日志可以跟踪这些虚拟存储设备的生命周期。

**举例说明:**

假设 Android 系统正在创建一个新的加密分区。内核中的 `dm-crypt` 模块可能会发送一个日志消息，指示加密设备的创建。用户空间的监控工具可以通过读取 DM 日志来了解这个过程的状态，例如，它可以接收到 `DM_ULOG_CTR` 类型的请求，其中包含新创建的加密设备的 UUID 和其他相关信息。

又比如，当 Android 系统进行 OTA 更新时，可能需要进行 A/B 分区切换。在切换分区之前或之后，Device Mapper 可能会发送 `DM_ULOG_PRESUSPEND` 和 `DM_ULOG_POSTSUSPEND` 类型的日志，以表明相关的 DM 设备正在被挂起或恢复。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义任何 libc 函数的实现。它只是定义了用户空间和内核空间之间通信的数据结构和常量。用户空间程序会使用标准的 libc 函数（如 `open`, `close`, `ioctl` 等）与内核的 Device Mapper 驱动程序进行交互。

要发送一个日志请求，用户空间程序通常会执行以下步骤：

1. **打开 Device Mapper 控制设备:**  通常是 `/dev/mapper/control`。
2. **构造 `dm_ulog_request` 结构体:** 填充请求类型、UUID、数据等信息。
3. **使用 `ioctl` 系统调用发送请求:**  `ioctl` 函数允许用户空间程序向设备驱动程序发送控制命令和数据。对于 Device Mapper 日志，可能有一个特定的 `ioctl` 命令码用于发送日志请求。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件定义的是内核 UAPI，它不会直接涉及动态链接器。动态链接器 (例如 Android 的 `linker64` 或 `linker`) 的作用是在程序启动时加载共享库 (`.so` 文件) 并解析符号依赖关系。

然而，如果用户空间程序使用了这个头文件中定义的结构体和宏，那么这些程序本身会被动态链接。

**so 布局样本 (非常简化):**

```
libmylogger.so:
    .text         # 代码段
        my_log_function:  # 使用 dm_ulog_request 结构体的函数
            ...
            // 构造 dm_ulog_request 结构体
            struct dm_ulog_request req;
            req.request_type = DM_ULOG_FLUSH;
            ...
            // 使用 ioctl 发送请求
            ioctl(fd, DM_IOCTL, &dm_ioctl_struct); // DM_IOCTL 包含日志相关的命令
            ...
    .rodata       # 只读数据段
        log_message: "Flushing DM log"
    .data         # 可读写数据段
        ...
    .dynamic      # 动态链接信息
        NEEDED libandroid.so
        SONAME libmylogger.so
        ...
    .symtab       # 符号表
        my_log_function
    .strtab       # 字符串表
        my_log_function
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译 `libmylogger.so` 时，编译器会知道它需要使用内核提供的 `dm_ulog_request` 结构体和相关的宏定义。这些定义来源于包含的头文件。编译器会生成对这些符号的引用。
2. **运行时链接:** 当一个可执行文件或另一个共享库加载了 `libmylogger.so` 时，动态链接器会执行以下操作：
   - **加载共享库:** 将 `libmylogger.so` 加载到内存中。
   - **解析依赖:** 检查 `.dynamic` 段的 `NEEDED` 条目，例如 `libandroid.so`。如果依赖的库尚未加载，则先加载它们。
   - **符号解析 (重定位):**  动态链接器会查找 `libmylogger.so` 中未定义的符号，并在已加载的共享库中找到它们的地址，然后更新 `libmylogger.so` 中的相应地址。
   - **应用重定位:**  将解析得到的地址填入代码段和数据段中，使得函数调用和数据访问能够正确进行。

在这个特定的场景下，`dm-log-userspace.h` 定义的是内核 UAPI，它不是一个共享库。用户空间程序会直接包含这个头文件，并在编译时将相关的结构体定义编译到程序中。与内核的交互主要通过系统调用（如 `ioctl`）完成，而不是通过动态链接到内核库。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要刷新一个名为 "mydisk" 的 DM 设备的日志。

**假设输入:**

* DM 设备名称: "mydisk"
* 请求类型: `DM_ULOG_FLUSH`

**逻辑推理过程:**

1. 程序需要找到 "mydisk" 对应的 UUID。这可能需要通过读取 `/dev/mapper/mydisk` 或使用 Device Mapper 提供的用户空间工具 (如 `dmsetup`) 来获取。 假设 UUID 为 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"。
2. 程序构造 `dm_ulog_request` 结构体：
   - `luid`:  可能设置为 0 或一个特定的逻辑单元 ID。
   - `uuid`:  设置为 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"。
   - `version`: 设置为 `DM_ULOG_REQUEST_VERSION` (3)。
   - `error`: 初始化为 0。
   - `seq`:  可以是一个递增的序列号。
   - `request_type`: 设置为 `DM_ULOG_FLUSH` (9)。
   - `data_size`: 设置为 0，因为刷新操作通常不需要额外的数据。
3. 程序打开 `/dev/mapper/control` 设备文件。
4. 程序构造一个 `dm_ioctl` 结构体 (这个结构体在 `linux/dm-ioctl.h` 中定义，用于与 DM 驱动通信)，其中包含 `dm_ulog_request` 结构体的指针和相关的控制信息。
5. 程序调用 `ioctl` 系统调用，将 `dm_ioctl` 结构体传递给内核。

**预期输出:**

* **内核行为:** 内核的 Device Mapper 驱动程序接收到 `ioctl` 请求，解析 `dm_ulog_request` 结构体，识别出 `DM_ULOG_FLUSH` 请求，并对 "mydisk" 设备执行日志刷新操作。
* **ioctl 返回值:** `ioctl` 系统调用通常会返回 0 表示成功，返回 -1 并设置 `errno` 表示失败。
* **日志记录 (内核内部):**  内核可能会记录本次刷新操作的事件。
* **用户空间感知:** 用户空间程序可能不会直接收到任何数据输出，但可以通过检查 `ioctl` 的返回值来判断操作是否成功。如果失败，`errno` 会指示具体的错误原因。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的请求类型:**  使用了不正确的 `DM_ULOG_` 宏，导致内核无法正确识别请求意图。例如，尝试使用 `DM_ULOG_GET_REGION_SIZE` 来执行刷新操作。
2. **错误的 UUID:**  提供了不正确的 DM 设备 UUID，导致请求作用于错误的设备或找不到目标设备。
3. **`data_size` 与 `data` 不匹配:**  设置了非零的 `data_size`，但 `data` 字段没有填充相应的数据，或者 `data_size` 与实际 `data` 的大小不符，可能导致数据读取错误或内核崩溃。
4. **未正确初始化结构体:**  `dm_ulog_request` 结构体中的某些字段（如 `version`）如果未正确初始化，可能导致内核拒绝处理该请求。
5. **权限问题:**  用户空间程序可能没有足够的权限访问 `/dev/mapper/control` 设备，导致 `open` 或 `ioctl` 调用失败。
6. **并发问题:**  多个进程或线程同时尝试修改同一个 DM 设备的日志可能会导致竞争条件和数据不一致。
7. **误解日志请求的含义:**  错误地理解不同日志请求类型的含义和适用场景，导致发送了不合适的请求。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

到达 `dm-log-userspace.h` 中定义的接口通常需要通过以下步骤：

1. **Android Framework 层 (Java/Kotlin):**  Android Framework 中的某些操作可能会间接地触发对 Device Mapper 的调用。例如，当进行文件系统检查 (`fsck`)、磁盘加密操作、或者管理存储卷时。Framework 层会调用底层的 Native 代码。
2. **Native 代码 (C/C++):** Framework 层会通过 JNI (Java Native Interface) 调用到 Native 代码，这些 Native 代码通常位于 Android 的系统服务或 HAL (Hardware Abstraction Layer) 中。
3. **Device Mapper 用户空间工具库 (libdm):**  Android 中通常会有一个 `libdm.so` 库，它封装了与 Device Mapper 交互的 API。Native 代码可能会使用 `libdm` 提供的函数来操作 DM 设备，例如创建、删除、修改 DM 设备。这些 `libdm` 函数内部会构造 `dm_ioctl` 结构体，并使用 `ioctl` 系统调用与内核进行通信。
4. **系统调用 (ioctl):**  `libdm` 或 Native 代码会调用 `ioctl` 系统调用，并将构造好的 `dm_ioctl` 结构体传递给内核。`dm_ioctl` 结构体中会包含指向 `dm_ulog_request` 结构体的指针，如果这次 `ioctl` 调用涉及到日志操作。
5. **内核 Device Mapper 驱动:** 内核接收到 `ioctl` 调用后，Device Mapper 驱动程序会解析 `dm_ioctl` 结构体，提取出 `dm_ulog_request` 结构体，并根据 `request_type` 执行相应的日志操作。

**Frida Hook 示例:**

可以使用 Frida 来 hook `ioctl` 系统调用，并检查其参数，以观察是否涉及到与 DM 日志相关的操作。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"]) # 替换为你的应用进程
    session = device.attach(pid)
except frida.TimedOutError:
    print("[-] Device not found or busy.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print("[-] Process not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 假设 DM_IOCTL 的值已知，需要根据实际情况替换
        const DM_IOCTL = 0xC0444D00; // 示例值，实际值需要查看内核头文件

        if (request === DM_IOCTL) {
            console.log("[*] ioctl called with DM_IOCTL");
            console.log("    File Descriptor:", fd);
            console.log("    Request Code:", request);

            // 读取 dm_ioctl 结构体 (需要根据 dm_ioctl 的定义进行解析)
            const dmIoctlPtr = ptr(argp);
            const dataPtrPtr = dmIoctlPtr.add(8); // 假设 data 字段是指向 dm_ulog_request 的指针

            try {
                const dataPtr = Memory.readPointer(dataPtrPtr);
                if (dataPtr.isNull()) {
                    console.log("    Data pointer is null.");
                    return;
                }

                console.log("    Data Pointer:", dataPtr);

                // 读取 dm_ulog_request 结构体
                const luid = dataPtr.readU64();
                const uuid = dataPtr.add(8).readUtf8String(36); // 假设 UUID 长度为 36
                const version = dataPtr.add(48).readU32();
                const error = dataPtr.add(52).readS32();
                const seq = dataPtr.add(56).readU32();
                const request_type = dataPtr.add(60).readU32();
                const data_size = dataPtr.add(64).readU32();

                console.log("    dm_ulog_request:");
                console.log("        luid:", luid.toString());
                console.log("        uuid:", uuid);
                console.log("        version:", version);
                console.log("        error:", error);
                console.log("        seq:", seq);
                console.log("        request_type:", request_type);
                console.log("        data_size:", data_size);

                // 可以进一步读取 data 字段的内容
                if (data_size > 0) {
                    const data = dataPtr.add(68).readByteArray(data_size);
                    console.log("        data:", hexdump(data));
                }

            } catch (e) {
                console.error("    Error reading dm_ulog_request:", e);
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **连接到目标进程:**  代码首先尝试连接到指定的 Android 应用进程。
2. **Hook `ioctl` 系统调用:**  使用 `Interceptor.attach` 拦截 `ioctl` 函数的调用。
3. **检查 `request` 参数:**  在 `onEnter` 函数中，检查 `ioctl` 的第二个参数（`request`），看它是否等于我们预期的 Device Mapper 控制命令 (`DM_IOCTL`)。你需要根据你的 Android 内核源码或者实际调试中观察到的值来替换 `DM_IOCTL` 的示例值。
4. **读取 `dm_ioctl` 结构体:** 如果 `request` 是 `DM_IOCTL`，则尝试读取 `ioctl` 的第三个参数 (`argp`)，它指向传递给内核的 `dm_ioctl` 结构体。你需要了解 `dm_ioctl` 结构体的布局，以便正确读取其中的成员。
5. **读取 `dm_ulog_request` 结构体:**  从 `dm_ioctl` 结构体中找到指向 `dm_ulog_request` 结构体的指针，并读取其各个字段，例如 `request_type`，以判断是否是与日志相关的操作。
6. **打印信息:**  将读取到的信息打印到控制台，方便调试和分析。

通过这个 Frida 脚本，你可以在应用运行时动态地观察 `ioctl` 调用，并分析传递给内核的 DM 日志请求，从而了解 Android Framework 或 NDK 是如何一步步地使用这些接口的。请注意，你需要根据实际的 Android 版本和内核配置来调整脚本中的常量和结构体偏移量。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/dm-log-userspace.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __DM_LOG_USERSPACE_H__
#define __DM_LOG_USERSPACE_H__
#include <linux/types.h>
#include <linux/dm-ioctl.h>
#define DM_ULOG_CTR 1
#define DM_ULOG_DTR 2
#define DM_ULOG_PRESUSPEND 3
#define DM_ULOG_POSTSUSPEND 4
#define DM_ULOG_RESUME 5
#define DM_ULOG_GET_REGION_SIZE 6
#define DM_ULOG_IS_CLEAN 7
#define DM_ULOG_IN_SYNC 8
#define DM_ULOG_FLUSH 9
#define DM_ULOG_MARK_REGION 10
#define DM_ULOG_CLEAR_REGION 11
#define DM_ULOG_GET_RESYNC_WORK 12
#define DM_ULOG_SET_REGION_SYNC 13
#define DM_ULOG_GET_SYNC_COUNT 14
#define DM_ULOG_STATUS_INFO 15
#define DM_ULOG_STATUS_TABLE 16
#define DM_ULOG_IS_REMOTE_RECOVERING 17
#define DM_ULOG_REQUEST_MASK 0xFF
#define DM_ULOG_REQUEST_TYPE(request_type) (DM_ULOG_REQUEST_MASK & (request_type))
#define DM_ULOG_REQUEST_VERSION 3
struct dm_ulog_request {
  __u64 luid;
  char uuid[DM_UUID_LEN];
  char padding[3];
  __u32 version;
  __s32 error;
  __u32 seq;
  __u32 request_type;
  __u32 data_size;
  char data[];
};
#endif
```