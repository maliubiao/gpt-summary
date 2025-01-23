Response:
My thought process to answer the request went something like this:

1. **Understand the Core Request:** The user wants a comprehensive analysis of the provided `binder.h` header file. This includes its purpose, relationship to Android, details about specific functions (though there aren't really "functions" in a header like this, so I need to interpret this as data structures and enums), dynamic linker implications, error scenarios, and how Android frameworks use this.

2. **Break Down the Task:**  I mentally divided the request into manageable chunks:
    * **Purpose:** What is this file for?
    * **Android Relation:** How does Binder fit into Android?
    * **"libc Function" Explanation:**  Since it's a header, this means explaining the *structures*, *enums*, and *macros*.
    * **Dynamic Linker:**  How does this relate to shared libraries? (This will be a less direct connection as this header defines the *interface* to the Binder kernel driver, not the implementation itself).
    * **Logic/Examples:**  Provide concrete scenarios.
    * **Common Errors:** What mistakes do developers make?
    * **Android Framework/NDK Usage:** Trace the path from high-level to this low-level definition.
    * **Frida Hook:**  Show how to inspect this in action.

3. **Initial Analysis of the Header:** I quickly scanned the header file, identifying key elements:
    * **Auto-generated:** This means direct modification is discouraged.
    * **`#ifndef _UAPI_LINUX_BINDER_H`:** Standard header guard.
    * **Includes `<linux/types.h>` and `<linux/ioctl.h>`:**  Indicates this is related to kernel interfaces and ioctl system calls.
    * **`B_PACK_CHARS` macro:**  For packing character codes.
    * **`BINDER_TYPE_*` enums:** Defines different types of Binder objects.
    * **`flat_binder_object_flags` enum:** Defines flags for Binder objects.
    * **`binder_size_t`, `binder_uintptr_t`:** Platform-specific size types.
    * **Various `struct binder_*` structures:** Represents data passed between processes.
    * **`BINDER_*` enums for ioctl commands:** Defines the operations that can be performed on the Binder driver.
    * **`transaction_flags` enum:** Flags related to Binder transactions.
    * **`binder_driver_return_protocol` and `binder_driver_command_protocol` enums:**  Define the communication protocol between user-space and the kernel driver.

4. **Address Each Breakdown Point:**

    * **Purpose:** Clearly state that it defines the interface to the Binder inter-process communication (IPC) mechanism at the kernel level.

    * **Android Relation:** Explain that Binder is the cornerstone of Android's component communication system. Provide concrete examples like Activities, Services, and Content Providers.

    * **"libc Function" Explanation (Interpreted as Structure/Enum Explanation):** For each major structure and enum, provide a description of its purpose and the meaning of its members. Focus on how they represent data being exchanged through Binder. For example, explain the `flat_binder_object` and its `binder`/`handle` union, or the `binder_transaction_data` structure which carries the actual data.

    * **Dynamic Linker:**  Acknowledge that while not directly a *dynamic linking* file, Binder relies on shared libraries. Explain that the *implementation* of Binder (in `libbinder.so`, etc.) is linked dynamically. Provide a simple `libbinder.so` layout example (though this is simplified, as the actual layout is more complex). Explain how the dynamic linker resolves symbols and loads dependencies.

    * **Logic/Examples:** For things like `B_PACK_CHARS`, show the input and output. For the `flat_binder_object` flags, illustrate how they control behavior.

    * **Common Errors:**  Focus on mistakes related to managing Binder objects (strong/weak references), data serialization/deserialization, and improper use of file descriptors.

    * **Android Framework/NDK Usage:**  Outline the call stack: Starting from an AIDL definition, going through the Stub/Proxy classes in Java/Kotlin, the JNI bridge, down to the native Binder library (`libbinder.so`), and finally to the kernel driver interaction (ioctl calls using the structures defined in this header).

    * **Frida Hook:** Provide practical Frida code snippets to intercept ioctl calls related to Binder, demonstrating how to inspect the data being exchanged. Focus on hooking the `ioctl` function and filtering for Binder-related commands (using the `BINDER_*` constants).

5. **Refine and Organize:**  Structure the answer logically with clear headings and subheadings. Use bullet points and code blocks for readability. Ensure the language is clear and concise, avoiding overly technical jargon where possible, but being precise when necessary.

6. **Review and Improve:**  Read through the entire answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, I made sure to clarify that the header defines the *interface* and the *implementation* resides elsewhere. I also emphasized the role of `ioctl`.

By following these steps, I could generate a comprehensive and informative answer that addresses all aspects of the user's request. The key was to break down the complex topic into smaller, manageable parts and address each part systematically.
这是一个描述 Linux Binder 机制用户空间接口的头文件 (`binder.h`)。它定义了用户空间程序与 Binder 驱动程序交互时使用的数据结构、常量和 ioctl 命令。Binder 是 Android 系统中进程间通信 (IPC) 的核心机制。

**文件功能:**

1. **定义 Binder 对象类型:**  定义了各种 Binder 对象的类型，如本地 Binder 对象、弱引用 Binder 对象、Binder 句柄、弱引用 Binder 句柄、文件描述符等。这些类型用于标识在进程间传递的不同类型的实体。
    * `BINDER_TYPE_BINDER`: 表示一个本地 Binder 对象，即服务提供者的实体。
    * `BINDER_TYPE_WEAK_BINDER`: 表示一个本地 Binder 对象的弱引用。
    * `BINDER_TYPE_HANDLE`: 表示一个 Binder 句柄，即客户端持有的远程 Binder 对象的引用。
    * `BINDER_TYPE_WEAK_HANDLE`: 表示一个 Binder 句柄的弱引用。
    * `BINDER_TYPE_FD`: 表示一个文件描述符。
    * `BINDER_TYPE_FDA`: 表示一个文件描述符数组。
    * `BINDER_TYPE_PTR`: 表示一个原始指针（通常不建议直接使用）。

2. **定义 Binder 对象标志:**  定义了用于描述 Binder 对象属性的标志，例如是否接受文件描述符、调度策略等。
    * `FLAT_BINDER_FLAG_ACCEPTS_FDS`:  指示 Binder 对象是否可以接收传递的文件描述符。

3. **定义数据结构用于进程间通信:** 定义了用于在进程间传递数据的结构体，例如 `flat_binder_object`、`binder_buffer_object`、`binder_transaction_data` 等。
    * `flat_binder_object`: 用于描述传递的 Binder 对象，包含类型、标志、binder/handle 和 cookie。
    * `binder_buffer_object`: 用于描述传递的缓冲区。
    * `binder_transaction_data`: 用于描述一个 Binder 事务，包含目标、代码、标志、发送者信息以及数据和偏移量。

4. **定义 ioctl 命令:**  定义了用户空间程序通过 `ioctl` 系统调用与 Binder 驱动程序进行交互的命令。这些命令用于执行各种操作，例如发送和接收数据、注册服务、获取 Binder 信息等。
    * `BINDER_WRITE_READ`:  用于向 Binder 驱动程序写入数据并从中读取响应。
    * `BINDER_SET_CONTEXT_MGR`:  用于设置 Binder 上下文管理器 (servicemanager)。
    * `BINDER_TRANSACTION`:  用于发送一个 Binder 事务。
    * `BINDER_REPLY`:  用于回复一个 Binder 事务。

5. **定义 Binder 驱动程序返回协议和命令协议:** 定义了 Binder 驱动程序返回给用户空间程序的事件类型以及用户空间程序发送给驱动程序的命令类型。

**与 Android 功能的关系及举例说明:**

Binder 是 Android 系统的基石，几乎所有的系统服务和应用程序之间的通信都依赖于 Binder。

* **ActivityManagerService (AMS) 的启动:** 当系统启动时，`system_server` 进程会启动 `ActivityManagerService`。AMS 需要注册到 `servicemanager`，以便其他进程可以访问它。这个注册过程就使用了 Binder IPC。`ActivityManagerService` 会创建一个本地 Binder 对象，并将其句柄（通过 `BINDER_SET_CONTEXT_MGR` 或其他相关 ioctl）传递给 `servicemanager`。

* **启动一个 Activity:** 当一个应用想要启动一个新的 Activity 时，它会通过 `Context.startActivity()` 发起请求。这个请求最终会通过 Binder IPC 发送到 `ActivityManagerService`。客户端进程（应用进程）会创建一个 `binder_transaction_data` 结构，其中包含启动 Activity 的相关信息（Intent 等），并通过 `BC_TRANSACTION` ioctl 发送给 Binder 驱动程序，最终到达 `system_server` 进程中的 `ActivityManagerService`。

* **访问系统服务:** 应用程序通常需要访问各种系统服务，例如 LocationManager、WindowManager 等。它们通过 `ServiceManager.getService()` 获取服务的代理对象。这个过程涉及向 `servicemanager` 发送 Binder 请求，`servicemanager` 返回对应服务的 Binder 句柄。应用程序随后就可以使用这个句柄与服务进行通信。

**libc 函数的功能实现 (这里主要指头文件中定义的结构体和宏):**

由于这是一个头文件，它本身不包含任何 C 语言函数的实现。它定义的是数据结构和常量，用于在用户空间和内核空间的 Binder 驱动程序之间传递信息。`bionic` 是 Android 的 C 库，它提供了与 Binder 交互的 API，这些 API 的实现会使用到这里定义的结构体。

* **`B_PACK_CHARS(c1, c2, c3, c4)`:**  这是一个宏，用于将四个字符打包成一个 32 位的整数。这常用于创建具有特定标识的常量，例如 Binder 对象的类型。
    * **实现:** 通过位移操作将每个字符放置到整数的不同字节位置。
    * **假设输入:** `B_PACK_CHARS('s', 'b', '*', 0x85)`
    * **输出:** `0x73622a85` (假设字符编码为 ASCII)

* **`flat_binder_object` 结构体:**  描述了一个扁平化的 Binder 对象，用于在进程间传递。
    * **功能:**  它包含了 Binder 对象的类型 (`hdr.type`)，标志 (`flags`)，以及实际的 Binder 指针或句柄 (`binder` 或 `handle`)，以及一个关联的 cookie 值。
    * **`hdr.type`:**  标识 Binder 对象的类型，例如 `BINDER_TYPE_BINDER` 或 `BINDER_TYPE_HANDLE`。
    * **`flags`:**  包含对象的属性标志，例如 `FLAT_BINDER_FLAG_ACCEPTS_FDS`。
    * **`union { binder_uintptr_t binder; __u32 handle; }`:**  如果是在服务提供者进程中，`binder` 字段指向实际的 Binder 对象在内存中的地址。如果是在客户端进程中，`handle` 字段存储着远程 Binder 对象的句柄。
    * **`cookie`:**  一个与 Binder 对象关联的任意值，可以用于调试或识别目的。

* **`binder_transaction_data` 结构体:**  描述了一个 Binder 事务，这是进程间通信的基本单元。
    * **功能:**  包含了发送事务的目标（Binder 句柄或指针）、事务代码、标志、发送者信息以及传递的数据。
    * **`target`:**  指定事务的目标，可以是 Binder 句柄（客户端到服务）或 Binder 指针（服务到客户端的回复）。
    * **`code`:**  一个 32 位整数，用于标识要调用的方法或操作。
    * **`flags`:**  包含事务的属性标志，例如 `TF_ONE_WAY`（单向调用）。
    * **`sender_pid` 和 `sender_euid`:**  发送进程的 PID 和 EUID。
    * **`data_size` 和 `offsets_size`:**  分别表示传递的数据和偏移量的大小。
    * **`data`:**  一个联合体，包含了指向数据缓冲区和偏移量缓冲区的指针 (`ptr`)，或者直接包含 8 字节的数据 (`buf`)，用于小型事务优化。

* **ioctl 命令宏 (例如 `_IOWR`, `_IOW`, `_IOR`, `_IO`):**  这些宏用于生成 `ioctl` 系统调用所需的命令值。它们将幻数、类型、序列号和数据大小编码到一个整数中。例如，`BINDER_WRITE_READ` 的定义使用了 `_IOWR('b', 1, struct binder_write_read)`，表示这是一个读写操作，幻数为 'b'，序列号为 1，并且需要传递 `struct binder_write_read` 结构体。

**dynamic linker 的功能及 so 布局样本和链接处理过程:**

虽然 `binder.h` 文件本身不直接涉及 dynamic linker 的功能，但 Android 的 Binder 机制的实现（例如在 `libbinder.so` 中）是通过 dynamic linker 加载和链接的。

**so 布局样本 (`libbinder.so` 的简化示例):**

```
libbinder.so:
  .text         # 代码段
    binder_open
    binder_ioctl
    Parcel::readInt32
    Parcel::writeInt32
    ...
  .data         # 数据段
    gBinderServiceName
    ...
  .rodata       # 只读数据段
    BINDER_VERSION_STRING
    ...
  .dynsym       # 动态符号表
    binder_open (GLOBAL DEFAULT)
    binder_ioctl (GLOBAL DEFAULT)
    Parcel::readInt32 (GLOBAL DEFAULT)
    Parcel::writeInt32 (GLOBAL DEFAULT)
    ...
  .dynstr       # 动态字符串表
    binder_open
    binder_ioctl
    Parcel::readInt32
    Parcel::writeInt32
    ...
  .rel.dyn      # 重定位表 (用于数据段)
  .rel.plt      # 重定位表 (用于过程链接表)
```

**链接处理过程:**

1. **加载:** 当一个进程需要使用 Binder 功能时（例如，通过调用 `android::ProcessState::self()->getContextObject(NULL)`），dynamic linker（通常是 `/system/bin/linker64` 或 `/system/bin/linker`）会负责加载 `libbinder.so` 到进程的地址空间。

2. **符号解析:** 在加载过程中，dynamic linker 会解析 `libbinder.so` 中的动态符号引用。如果 `libbinder.so` 依赖于其他共享库（例如 `libc.so`），dynamic linker 也会加载这些依赖库。

3. **重定位:**  由于共享库被加载到进程的哪个地址是运行时决定的，dynamic linker 需要修改代码和数据段中的地址引用，使其指向正确的内存位置。这通过 `.rel.dyn` 和 `.rel.plt` 段中存储的重定位信息完成。

4. **链接到 Binder 驱动程序:**  `libbinder.so` 中的代码（例如 `binder_open` 和 `binder_ioctl` 函数）会使用 `open("/dev/binder")` 打开 Binder 驱动程序的文件描述符，并使用 `ioctl` 系统调用与驱动程序进行交互。

**假设输入与输出 (逻辑推理示例):**

假设用户空间程序想要向一个 Binder 服务发送一个整数数据。

* **假设输入:**
    * 目标 Binder 句柄: `target_handle = 10`
    * 事务代码: `code = 1001`
    * 要发送的整数: `data = 12345`

* **用户空间操作:**
    1. 创建 `binder_transaction_data` 结构体。
    2. 设置 `target.handle = target_handle;`
    3. 设置 `code = code;`
    4. 分配一个缓冲区，并将 `data` 写入缓冲区。
    5. 设置 `data_size` 和 `data.ptr.buffer` 指向该缓冲区。
    6. 调用 `ioctl(binder_fd, BINDER_WRITE_READ, &bwr)`，其中 `bwr.write_buffer` 指向包含 `binder_transaction_data` 和数据缓冲区的内存。

* **Binder 驱动程序处理:**
    1. 接收到 `BINDER_WRITE_READ` ioctl。
    2. 解析 `binder_transaction_data` 结构体。
    3. 根据 `target_handle` 找到对应的 Binder 对象。
    4. 将事务传递给目标服务进程。

* **目标服务进程处理:**
    1. 接收到 Binder 事务。
    2. 解析 `binder_transaction_data` 结构体。
    3. 读取 `code` 和数据。
    4. 执行相应的操作 (根据 `code` 的定义)。

**用户或编程常见的使用错误举例:**

1. **忘记释放 Binder 引用:**  如果客户端获取了 Binder 对象的引用（例如，通过 `IBinder::linkToDeath()`），但忘记在不再需要时释放引用（通过 `IBinder::unlinkToDeath()`），可能导致内存泄漏或资源无法回收。

2. **在错误的线程调用 Binder 方法:**  某些 Binder 操作必须在特定的线程执行（例如，主线程）。在错误的线程调用可能导致程序崩溃或死锁。

3. **序列化/反序列化错误:**  在进程间传递数据时，需要将数据序列化为字节流。如果序列化或反序列化的过程不正确，会导致数据损坏或程序崩溃。例如，尝试读取超出缓冲区大小的数据。

4. **忘记处理 Binder 死亡:**  如果一个进程持有的远程 Binder 对象对应的进程意外终止，客户端需要处理 Binder 死亡事件，避免访问无效的 Binder 对象。

5. **不正确地管理文件描述符:**  通过 Binder 传递文件描述符时，需要确保文件描述符的所有权和生命周期管理正确，避免文件描述符泄漏或被意外关闭。

**Android framework 或 ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `binder.h` 的路径:**

1. **AIDL 定义:**  开发者通常会定义一个 AIDL (Android Interface Definition Language) 文件来描述进程间通信的接口。

2. **AIDL 编译器:**  AIDL 编译器 (`aidl`) 会根据 AIDL 文件生成 Java 或 Kotlin 接口和 Stub/Proxy 类。

3. **Java/Kotlin Stub 和 Proxy:**
   * **Stub (在服务端):** 继承自 `Binder` 类，负责处理来自客户端的 Binder 调用。
   * **Proxy (在客户端):**  实现了 AIDL 定义的接口，负责将方法调用转换为 Binder 事务并发送给服务端。

4. **`android.os.Binder` 类 (Java Framework):**  `Stub` 类会继承自 `android.os.Binder`。`Binder` 类提供了与 Binder 驱动程序交互的 Java API。

5. **Native Binder 代码 (`libbinder.so`):**  `android.os.Binder` 类的方法最终会调用到 Android 运行时 (ART) 中的 JNI 代码，这些 JNI 代码会调用到 native 的 Binder 库 (`libbinder.so`) 中的函数，例如 `IPCThreadState::self()->transact()`。

6. **Binder 系统调用:**  `libbinder.so` 中的函数会构建 `binder_transaction_data` 结构体，并使用 `ioctl` 系统调用 (使用 `BINDER_WRITE_READ` 等命令) 与内核中的 Binder 驱动程序 (`/dev/binder`) 进行交互。这就是 `bionic/libc/kernel/uapi/linux/android/binder.h` 中定义的结构体和常量发挥作用的地方。

**Android NDK 到 `binder.h` 的路径:**

1. **NDK AIBinder:** NDK 提供了 `android/binder_interface.h` 和 `android/binder_ibinder.h` 等头文件，用于在 C++ 代码中使用 Binder。

2. **C++ Binder 类:** NDK 中也有类似的 Stub 和 Proxy 模式，使用 C++ 类来表示 Binder 接口。

3. **Libbinder (C++ 实现):** NDK 中的 Binder 代码最终也会链接到 `libbinder.so`，使用相同的底层机制与 Binder 驱动程序交互。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `ioctl` 系统调用来观察 Binder 交互的示例：

```javascript
function hookBinder() {
  const ioctlPtr = Module.getExportByName(null, "ioctl");
  const binderIoctl = 0x40186201; // BINDER_WRITE_READ 的值，不同架构可能不同，需要查找

  Interceptor.attach(ioctlPtr, {
    onEnter: function (args) {
      const fd = args[0].toInt32();
      const request = args[1].toInt32();

      // 判断是否是 Binder 相关的 ioctl
      if (request === binderIoctl) {
        console.log("ioctl called with BINDER_WRITE_READ");
        const bwrPtr = args[2];
        const writeSize = bwrPtr.readUSize();
        const writeConsumed = bwrPtr.add(Process.pointerSize).readUSize();
        const writeBuffer = bwrPtr.add(Process.pointerSize * 2).readPointer();

        console.log("  fd:", fd);
        console.log("  writeSize:", writeSize);
        console.log("  writeConsumed:", writeConsumed);
        console.log("  writeBuffer:", writeBuffer);

        if (writeBuffer.isNull() === false && writeSize > 0) {
          // 读取 binder_write_read 结构体指向的数据
          const transactionDataPtr = writeBuffer;
          const targetHandle = transactionDataPtr.readU32();
          const code = transactionDataPtr.add(Process.pointerSize * 2).readU32(); // 假设 64 位
          console.log("  Target Handle:", targetHandle);
          console.log("  Transaction Code:", code);
          // 可以进一步解析数据缓冲区
        }
      }
    },
    onLeave: function (retval) {
      // console.log("ioctl returned:", retval);
    },
  });
}

setImmediate(hookBinder);
```

**解释:**

1. **`Module.getExportByName(null, "ioctl")`:** 获取 `ioctl` 函数的地址。
2. **`binderIoctl = 0x40186201;`:**  `BINDER_WRITE_READ` 常量的值。需要根据目标 Android 版本的架构（32位或64位）查找正确的数值。可以使用 `grep BINDER_WRITE_READ /usr/include/linux/android/binder.h` 或类似的命令在 SDK 中找到。
3. **`Interceptor.attach(ioctlPtr, ...)`:**  Hook `ioctl` 函数。
4. **`onEnter`:**  在 `ioctl` 函数调用之前执行。
5. **检查 `request`:** 判断当前的 `ioctl` 调用是否是 `BINDER_WRITE_READ`。
6. **读取 `binder_write_read` 结构体:** 从 `args[2]` 中读取 `binder_write_read` 结构体的成员。
7. **读取 `binder_transaction_data`:** 如果 `writeBuffer` 不为空，则尝试将其解析为 `binder_transaction_data` 结构体，并打印目标句柄和事务代码。

**使用 Frida 运行:**

1. 将上述 JavaScript 代码保存为 `binder_hook.js`。
2. 找到目标 Android 进程的进程 ID (PID)。
3. 使用 Frida 连接到目标进程并运行脚本：
   ```bash
   frida -U -f <package_name> -l binder_hook.js --no-pause
   # 或者连接到正在运行的进程
   frida -U <process_name_or_pid> -l binder_hook.js
   ```

这个 Frida 脚本会打印出所有通过 `BINDER_WRITE_READ` ioctl 发送的 Binder 事务的相关信息，帮助你理解 Android Framework 或 NDK 是如何一步步地使用 Binder 机制的。你可以根据需要修改脚本来 hook 其他 Binder 相关的 ioctl 命令或解析更详细的数据。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/android/binder.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_BINDER_H
#define _UAPI_LINUX_BINDER_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define B_PACK_CHARS(c1,c2,c3,c4) ((((c1) << 24)) | (((c2) << 16)) | (((c3) << 8)) | (c4))
#define B_TYPE_LARGE 0x85
enum {
  BINDER_TYPE_BINDER = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
  BINDER_TYPE_WEAK_BINDER = B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
  BINDER_TYPE_HANDLE = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
  BINDER_TYPE_WEAK_HANDLE = B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
  BINDER_TYPE_FD = B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
  BINDER_TYPE_FDA = B_PACK_CHARS('f', 'd', 'a', B_TYPE_LARGE),
  BINDER_TYPE_PTR = B_PACK_CHARS('p', 't', '*', B_TYPE_LARGE),
};
enum flat_binder_object_shifts {
  FLAT_BINDER_FLAG_SCHED_POLICY_SHIFT = 9,
};
enum flat_binder_object_flags {
  FLAT_BINDER_FLAG_PRIORITY_MASK = 0xff,
  FLAT_BINDER_FLAG_ACCEPTS_FDS = 0x100,
  FLAT_BINDER_FLAG_SCHED_POLICY_MASK = 3U << FLAT_BINDER_FLAG_SCHED_POLICY_SHIFT,
  FLAT_BINDER_FLAG_INHERIT_RT = 0x800,
  FLAT_BINDER_FLAG_TXN_SECURITY_CTX = 0x1000,
};
#ifdef BINDER_IPC_32BIT
typedef __u32 binder_size_t;
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
#endif
struct binder_object_header {
  __u32 type;
};
struct flat_binder_object {
  struct binder_object_header hdr;
  __u32 flags;
  union {
    binder_uintptr_t binder;
    __u32 handle;
  };
  binder_uintptr_t cookie;
};
struct binder_fd_object {
  struct binder_object_header hdr;
  __u32 pad_flags;
  union {
    binder_uintptr_t pad_binder;
    __u32 fd;
  };
  binder_uintptr_t cookie;
};
struct binder_buffer_object {
  struct binder_object_header hdr;
  __u32 flags;
  binder_uintptr_t buffer;
  binder_size_t length;
  binder_size_t parent;
  binder_size_t parent_offset;
};
enum {
  BINDER_BUFFER_FLAG_HAS_PARENT = 0x01,
};
struct binder_fd_array_object {
  struct binder_object_header hdr;
  __u32 pad;
  binder_size_t num_fds;
  binder_size_t parent;
  binder_size_t parent_offset;
};
struct binder_write_read {
  binder_size_t write_size;
  binder_size_t write_consumed;
  binder_uintptr_t write_buffer;
  binder_size_t read_size;
  binder_size_t read_consumed;
  binder_uintptr_t read_buffer;
};
struct binder_version {
  __s32 protocol_version;
};
#ifdef BINDER_IPC_32BIT
#define BINDER_CURRENT_PROTOCOL_VERSION 7
#else
#define BINDER_CURRENT_PROTOCOL_VERSION 8
#endif
struct binder_node_debug_info {
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
  __u32 has_strong_ref;
  __u32 has_weak_ref;
};
struct binder_node_info_for_ref {
  __u32 handle;
  __u32 strong_count;
  __u32 weak_count;
  __u32 reserved1;
  __u32 reserved2;
  __u32 reserved3;
};
struct binder_freeze_info {
  __u32 pid;
  __u32 enable;
  __u32 timeout_ms;
};
struct binder_frozen_status_info {
  __u32 pid;
  __u32 sync_recv;
  __u32 async_recv;
};
struct binder_frozen_state_info {
  binder_uintptr_t cookie;
  __u32 is_frozen;
  __u32 reserved;
};
struct binder_extended_error {
  __u32 id;
  __u32 command;
  __s32 param;
};
enum {
  BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read),
  BINDER_SET_IDLE_TIMEOUT = _IOW('b', 3, __s64),
  BINDER_SET_MAX_THREADS = _IOW('b', 5, __u32),
  BINDER_SET_IDLE_PRIORITY = _IOW('b', 6, __s32),
  BINDER_SET_CONTEXT_MGR = _IOW('b', 7, __s32),
  BINDER_THREAD_EXIT = _IOW('b', 8, __s32),
  BINDER_VERSION = _IOWR('b', 9, struct binder_version),
  BINDER_GET_NODE_DEBUG_INFO = _IOWR('b', 11, struct binder_node_debug_info),
  BINDER_GET_NODE_INFO_FOR_REF = _IOWR('b', 12, struct binder_node_info_for_ref),
  BINDER_SET_CONTEXT_MGR_EXT = _IOW('b', 13, struct flat_binder_object),
  BINDER_FREEZE = _IOW('b', 14, struct binder_freeze_info),
  BINDER_GET_FROZEN_INFO = _IOWR('b', 15, struct binder_frozen_status_info),
  BINDER_ENABLE_ONEWAY_SPAM_DETECTION = _IOW('b', 16, __u32),
  BINDER_GET_EXTENDED_ERROR = _IOWR('b', 17, struct binder_extended_error),
};
enum transaction_flags {
  TF_ONE_WAY = 0x01,
  TF_ROOT_OBJECT = 0x04,
  TF_STATUS_CODE = 0x08,
  TF_ACCEPT_FDS = 0x10,
  TF_CLEAR_BUF = 0x20,
  TF_UPDATE_TXN = 0x40,
};
struct binder_transaction_data {
  union {
    __u32 handle;
    binder_uintptr_t ptr;
  } target;
  binder_uintptr_t cookie;
  __u32 code;
  __u32 flags;
  __kernel_pid_t sender_pid;
  __kernel_uid32_t sender_euid;
  binder_size_t data_size;
  binder_size_t offsets_size;
  union {
    struct {
      binder_uintptr_t buffer;
      binder_uintptr_t offsets;
    } ptr;
    __u8 buf[8];
  } data;
};
struct binder_transaction_data_secctx {
  struct binder_transaction_data transaction_data;
  binder_uintptr_t secctx;
};
struct binder_transaction_data_sg {
  struct binder_transaction_data transaction_data;
  binder_size_t buffers_size;
};
struct binder_ptr_cookie {
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
};
struct binder_handle_cookie {
  __u32 handle;
  binder_uintptr_t cookie;
} __attribute__((__packed__));
struct binder_pri_desc {
  __s32 priority;
  __u32 desc;
};
struct binder_pri_ptr_cookie {
  __s32 priority;
  binder_uintptr_t ptr;
  binder_uintptr_t cookie;
};
enum binder_driver_return_protocol {
  BR_ERROR = _IOR('r', 0, __s32),
  BR_OK = _IO('r', 1),
  BR_TRANSACTION_SEC_CTX = _IOR('r', 2, struct binder_transaction_data_secctx),
  BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
  BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
  BR_ACQUIRE_RESULT = _IOR('r', 4, __s32),
  BR_DEAD_REPLY = _IO('r', 5),
  BR_TRANSACTION_COMPLETE = _IO('r', 6),
  BR_INCREFS = _IOR('r', 7, struct binder_ptr_cookie),
  BR_ACQUIRE = _IOR('r', 8, struct binder_ptr_cookie),
  BR_RELEASE = _IOR('r', 9, struct binder_ptr_cookie),
  BR_DECREFS = _IOR('r', 10, struct binder_ptr_cookie),
  BR_ATTEMPT_ACQUIRE = _IOR('r', 11, struct binder_pri_ptr_cookie),
  BR_NOOP = _IO('r', 12),
  BR_SPAWN_LOOPER = _IO('r', 13),
  BR_FINISHED = _IO('r', 14),
  BR_DEAD_BINDER = _IOR('r', 15, binder_uintptr_t),
  BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR('r', 16, binder_uintptr_t),
  BR_FAILED_REPLY = _IO('r', 17),
  BR_FROZEN_REPLY = _IO('r', 18),
  BR_ONEWAY_SPAM_SUSPECT = _IO('r', 19),
  BR_TRANSACTION_PENDING_FROZEN = _IO('r', 20),
  BR_FROZEN_BINDER = _IOR('r', 21, struct binder_frozen_state_info),
  BR_CLEAR_FREEZE_NOTIFICATION_DONE = _IOR('r', 22, binder_uintptr_t),
};
enum binder_driver_command_protocol {
  BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
  BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
  BC_ACQUIRE_RESULT = _IOW('c', 2, __s32),
  BC_FREE_BUFFER = _IOW('c', 3, binder_uintptr_t),
  BC_INCREFS = _IOW('c', 4, __u32),
  BC_ACQUIRE = _IOW('c', 5, __u32),
  BC_RELEASE = _IOW('c', 6, __u32),
  BC_DECREFS = _IOW('c', 7, __u32),
  BC_INCREFS_DONE = _IOW('c', 8, struct binder_ptr_cookie),
  BC_ACQUIRE_DONE = _IOW('c', 9, struct binder_ptr_cookie),
  BC_ATTEMPT_ACQUIRE = _IOW('c', 10, struct binder_pri_desc),
  BC_REGISTER_LOOPER = _IO('c', 11),
  BC_ENTER_LOOPER = _IO('c', 12),
  BC_EXIT_LOOPER = _IO('c', 13),
  BC_REQUEST_DEATH_NOTIFICATION = _IOW('c', 14, struct binder_handle_cookie),
  BC_CLEAR_DEATH_NOTIFICATION = _IOW('c', 15, struct binder_handle_cookie),
  BC_DEAD_BINDER_DONE = _IOW('c', 16, binder_uintptr_t),
  BC_TRANSACTION_SG = _IOW('c', 17, struct binder_transaction_data_sg),
  BC_REPLY_SG = _IOW('c', 18, struct binder_transaction_data_sg),
  BC_REQUEST_FREEZE_NOTIFICATION = _IOW('c', 19, struct binder_handle_cookie),
  BC_CLEAR_FREEZE_NOTIFICATION = _IOW('c', 20, struct binder_handle_cookie),
  BC_FREEZE_NOTIFICATION_DONE = _IOW('c', 21, binder_uintptr_t),
};
#endif
```