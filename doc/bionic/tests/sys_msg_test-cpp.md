Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The primary goal is to analyze the `sys_msg_test.cpp` file from Android's Bionic library and explain its purpose, the functions it tests, and how these relate to Android and its underlying mechanisms. The request also specifically asks for details about libc functions, the dynamic linker, error scenarios, and how the code is reached from higher levels of the Android stack. Finally, it wants a Frida hook example.

**2. Initial Code Scan and Identifying Key Components:**

The first step is to quickly scan the code and identify the key elements:

* **`#include <gtest/gtest.h>`:** This indicates it's a unit test file using Google Test.
* **`#include <errno.h>` and `<sys/msg.h>`:** These headers are crucial. They tell us the code is testing System V message queues, a classic inter-process communication (IPC) mechanism.
* **`#include <android-base/file.h>`:** This suggests the test uses Android-specific utilities, likely for creating temporary files/directories.
* **`TEST(sys_msg, ...)` blocks:** These are the individual test cases. Looking at the names (`smoke`, `msgctl_failure`, etc.) provides a high-level idea of what's being tested.
* **`msgctl`, `msgget`, `msgsnd`, `msgrcv`:**  These are the core System V message queue functions being tested.
* **`IPC_CREAT`, `IPC_STAT`, `IPC_RMID`:** These are flags used with `msgctl`.
* **`TemporaryDir`:**  Used for generating a unique key for the message queue.
* **`ASSERT_*` macros:** These are Google Test assertions used to verify expected outcomes.

**3. Addressing the "Functionality" Question:**

Based on the identified components, the primary function of this test file is to verify the correctness and behavior of the System V message queue implementation in Bionic. It aims to test both successful operations (creating, sending, receiving, deleting messages) and failure scenarios (invalid arguments, lack of system support).

**4. Connecting to Android Functionality:**

The next step is to explain *why* this is relevant to Android. The key point here is that System V message queues are an IPC mechanism. While not the *most* commonly used IPC on modern Android (Binder is dominant), it's still a valid and potentially used method, particularly in legacy code or for specific use cases where its simpler nature might be preferred. The examples of system services or native daemons using it are good illustrative points.

**5. Explaining libc Function Implementations:**

This requires more in-depth knowledge of operating systems and how libc functions are generally implemented. The thought process here is to provide a conceptual overview, focusing on the key interactions:

* **System Calls:** Emphasize that these libc functions are wrappers around system calls.
* **Kernel Involvement:** Explain that the actual message queue management happens within the kernel.
* **Data Structures:** Mention the kernel likely uses internal data structures to maintain message queues, message data, and metadata.
* **Error Handling:**  Explain how the functions set `errno` on failure.

Since the request specifically asked for *how* they are implemented, a disclaimer acknowledging the complexity and OS-specific nature is important. Avoid getting bogged down in OS kernel source code details unless explicitly requested.

**6. Addressing Dynamic Linker Functionality:**

The crucial realization here is that **this specific test file *doesn't directly exercise dynamic linking* features.**  The message queue functions are *system calls*, handled by the kernel. The dynamic linker comes into play when *loading libraries* that might *use* these functions.

Therefore, the explanation should focus on:

* **Indirect Relationship:**  The test *depends* on the dynamic linker to load the test executable and potentially any required libraries (like `libc.so`).
* **Illustrative SO Layout:**  Provide a basic example of how an SO (like `libc.so`) might be laid out in memory.
* **Linking Process:** Describe the dynamic linker's role in resolving symbols (like `msgget`) and relocating code.
* **Hypothetical Example:**  Construct a scenario where a separate SO *uses* message queue functions and explain how it would be linked. This helps clarify the dynamic linking aspect in the context of the system calls being tested.

**7. Identifying Common Usage Errors:**

This involves thinking about how a programmer might misuse these message queue functions:

* **Incorrect Key Generation:**  Problems with `ftok`.
* **Permissions:** Issues with the mode argument to `msgget`.
* **Message Size Mismatch:** Sending and receiving with incorrect sizes.
* **Blocking/Non-blocking Behavior:** Misunderstanding the flags in `msgrcv` and `msgsnd`.
* **Resource Leaks:** Forgetting to remove message queues.

**8. Tracing the Path from Framework/NDK:**

This requires knowledge of the Android architecture. The thought process is to move from the highest level down:

* **Framework:**  Start with a scenario where an Android app might indirectly trigger message queue usage (though it's less common). A system service is a more plausible example.
* **NDK:** Explain how native code using the NDK can directly call these libc functions.
* **System Calls:**  Highlight the transition from the userspace (app/native code) to the kernel via system calls.
* **Bionic:** Emphasize that Bionic's libc provides the implementation of these functions, wrapping the system calls.

**9. Providing a Frida Hook Example:**

The goal here is to demonstrate how to intercept calls to the message queue functions. The Frida script should:

* **Target the Process:**  Use `Process.getModuleByName()` or similar to target the process where the message queue functions are being called.
* **Hook the Function:**  Use `Interceptor.attach()` to intercept calls to functions like `msgget`.
* **Log Information:**  Print relevant details about the function calls (arguments, return values).

The example should be simple and illustrative. Hooking `msgget` is a good starting point because it's involved in queue creation.

**10. Review and Refine:**

After drafting the initial response, it's crucial to review and refine it for clarity, accuracy, and completeness. Ensure all parts of the original request have been addressed. Check for any technical inaccuracies or confusing explanations. Use clear and concise language.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the internal implementation details of the kernel's message queue management. However, the prompt asks for the *libc function implementation*. So, I would adjust to focus on the libc wrapper aspect and the system call interface, keeping the kernel details more high-level. Similarly, realizing that direct dynamic linking isn't *explicitly* demonstrated by this test file, shifting the focus to the indirect dependency and a hypothetical example is crucial for a correct and nuanced answer.
好的，让我们详细分析一下 `bionic/tests/sys_msg_test.cpp` 这个文件。

**功能概述**

这个 C++ 文件是一个单元测试文件，它使用 Google Test 框架来测试 Android Bionic 库中关于 System V 消息队列 (System V message queues) 的实现。具体来说，它测试了以下几个与消息队列相关的系统调用：

* **`msgget()`**:  创建或访问一个消息队列。
* **`msgctl()`**:  对消息队列执行各种控制操作，例如获取状态信息、删除消息队列等。
* **`msgsnd()`**:  向消息队列发送消息。
* **`msgrcv()`**:  从消息队列接收消息。

**与 Android 功能的关系及举例**

System V 消息队列是一种进程间通信 (IPC) 机制。虽然在现代 Android 中，Binder 机制是主要的 IPC 手段，但消息队列仍然可以在某些场景下使用，尤其是一些历史遗留的或者对实时性要求不高的系统服务或者原生守护进程可能会使用。

**举例说明：**

想象一个场景，一个底层的 Android 系统服务需要定期向另一个服务发送简单的状态更新信息。使用消息队列可以实现这种单向的、异步的通信。

* **发送服务：**  可以使用 `msgget()` 创建一个消息队列，然后使用 `msgsnd()` 将状态信息打包成消息发送到队列中。
* **接收服务：**  可以使用相同的 `msgget()` 获取到消息队列的 ID，然后使用 `msgrcv()` 等待并接收消息。

**libc 函数的实现详解**

这些 `msg*` 函数都是 libc 提供的封装，它们最终会调用 Linux 内核提供的相应的系统调用。

1. **`msgget(key_t key, int msgflg)`**:
   * **功能:**  根据给定的 `key` 创建一个新的消息队列，或者返回与该 `key` 关联的现有消息队列的标识符。
   * **实现:**
      * 这个函数会调用内核的 `sys_msgget()` 系统调用。
      * **`key` 参数:**  可以是一个特定的值，也可以使用 `IPC_PRIVATE` 创建一个私有的消息队列。通常使用 `ftok()` 函数根据文件路径和项目 ID 生成一个唯一的 `key`。
      * **`msgflg` 参数:**  指定创建消息队列的标志和权限。例如，`IPC_CREAT` 表示如果消息队列不存在则创建，`0666` 指定了消息队列的权限。
      * **内核处理:**  内核会在内部维护一个消息队列的数据结构，如果需要创建新的消息队列，内核会分配相应的资源，并返回一个消息队列的标识符（通常是一个整数）。如果消息队列已经存在，并且权限允许，则返回现有的标识符。
      * **错误处理:**  如果创建失败（例如，没有权限，资源耗尽），内核会设置 `errno` 并返回 -1。

2. **`msgctl(int msqid, int cmd, struct msqid_ds *buf)`**:
   * **功能:**  对由 `msqid` 标识的消息队列执行各种控制操作。
   * **实现:**
      * 这个函数会调用内核的 `sys_msgctl()` 系统调用。
      * **`msqid` 参数:**  消息队列的标识符。
      * **`cmd` 参数:**  指定要执行的操作，例如：
         * `IPC_STAT`: 获取消息队列的状态信息，并将信息存储到 `buf` 指向的 `msqid_ds` 结构体中。
         * `IPC_SET`:  设置消息队列的某些属性（需要 root 权限）。
         * `IPC_RMID`:  删除消息队列。
      * **`buf` 参数:**  指向用于存储或设置消息队列信息的结构体指针。如果是 `IPC_STAT`，内核会将信息写入 `buf`。如果是 `IPC_SET`，内核会根据 `buf` 中的信息修改消息队列的属性。对于 `IPC_RMID`，这个参数可以为 `nullptr`。
      * **内核处理:**  内核根据 `cmd` 执行相应的操作。例如，对于 `IPC_STAT`，内核会查找 `msqid` 对应的消息队列，读取其状态信息，并复制到用户空间的 `buf`。对于 `IPC_RMID`，内核会释放与该消息队列相关的资源。
      * **错误处理:**  如果操作失败（例如，无效的 `msqid`，权限不足），内核会设置 `errno` 并返回 -1。

3. **`msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)`**:
   * **功能:**  向由 `msqid` 标识的消息队列发送一条消息。
   * **实现:**
      * 这个函数会调用内核的 `sys_msgsnd()` 系统调用。
      * **`msqid` 参数:**  目标消息队列的标识符。
      * **`msgp` 参数:**  指向要发送的消息的指针。消息的结构通常包含一个 `long` 类型的消息类型和一个数据部分。
      * **`msgsz` 参数:**  要发送的消息数据部分的长度（不包括消息类型）。
      * **`msgflg` 参数:**  控制发送操作的行为，例如：
         * `0`: 阻塞发送，直到消息可以被放入队列。
         * `IPC_NOWAIT`: 非阻塞发送，如果队列已满则立即返回错误。
      * **内核处理:**  内核会将 `msgp` 指向的消息数据复制到内核空间的消息队列中。如果队列已满且 `msgflg` 没有指定 `IPC_NOWAIT`，则发送进程会被阻塞，直到队列有空间。
      * **错误处理:**  如果发送失败（例如，无效的 `msqid`，队列已满且指定了 `IPC_NOWAIT`），内核会设置 `errno` 并返回 -1。

4. **`msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)`**:
   * **功能:**  从由 `msqid` 标识的消息队列接收一条消息。
   * **实现:**
      * 这个函数会调用内核的 `sys_msgrcv()` 系统调用。
      * **`msqid` 参数:**  源消息队列的标识符。
      * **`msgp` 参数:**  指向用于接收消息的缓冲区的指针。
      * **`msgsz` 参数:**  接收缓冲区的大小。
      * **`msgtyp` 参数:**  指定要接收的消息类型。
         * `0`:  接收队列中的第一条消息。
         * 大于 0:  接收队列中类型为 `msgtyp` 的第一条消息。
         * 小于 0:  接收队列中类型小于等于 `abs(msgtyp)` 的最小类型的消息。
      * **`msgflg` 参数:**  控制接收操作的行为，例如：
         * `0`: 阻塞接收，直到队列中有符合条件的消息。
         * `IPC_NOWAIT`: 非阻塞接收，如果队列中没有符合条件的消息则立即返回错误。
         * `MSG_NOERROR`: 如果接收到的消息大小大于 `msgsz`，则截断消息而不返回错误。
      * **内核处理:**  内核会从消息队列中找到符合条件的消息，并将其复制到用户空间的 `msgp` 指向的缓冲区。如果队列中没有符合条件的消息且 `msgflg` 没有指定 `IPC_NOWAIT`，则接收进程会被阻塞，直到有消息到达。
      * **错误处理:**  如果接收失败（例如，无效的 `msqid`，队列为空且指定了 `IPC_NOWAIT`），内核会设置 `errno` 并返回 -1。

**涉及 dynamic linker 的功能**

这个测试文件本身并没有直接涉及到动态链接器的核心功能。它主要测试的是系统调用。动态链接器 (e.g., `linker64` 或 `linker`) 的作用是在程序启动时加载程序依赖的共享库 (`.so` 文件），并将程序中的符号引用解析到这些共享库中的实际地址。

**但是，这个测试文件依赖于 `libc.so`，因为 `msgget`、`msgctl` 等函数都在 `libc.so` 中实现。**

**so 布局样本 (对于 `libc.so`)**

一个典型的 `libc.so` 的内存布局可能如下所示（简化）：

```
[加载地址]
+----------------------+
| .text (代码段)        |  <-- 包含 msgget, msgctl, msgsnd, msgrcv 等函数的代码
+----------------------+
| .rodata (只读数据段) |  <-- 包含一些常量字符串等
+----------------------+
| .data (已初始化数据段)|  <-- 包含全局变量等
+----------------------+
| .bss (未初始化数据段) |  <-- 包含未初始化的全局变量
+----------------------+
| .dynamic (动态链接信息)|  <-- 包含动态链接器需要的信息，如符号表、重定位表等
+----------------------+
| .got (全局偏移表)     |  <-- 用于存储外部函数的地址，在运行时被动态链接器填充
+----------------------+
| .plt (过程链接表)     |  <-- 用于调用外部函数的跳转代码
+----------------------+
```

**链接的处理过程**

1. **编译时链接:**  编译器在编译 `sys_msg_test.cpp` 时，会识别出对 `msgget` 等函数的调用。由于这些函数在标准库中，编译器会生成对这些函数的未解析引用。
2. **链接时链接:**  链接器（通常是 `ld`）会将编译生成的目标文件 (`.o`) 与所需的库 (`libc.so`) 链接在一起。链接器会查找 `libc.so` 中的符号表，找到 `msgget` 等函数的定义，并将程序中的符号引用指向 `libc.so` 中相应的入口地址。然而，对于共享库，这里的链接是“部分链接”，真正的地址需要在运行时由动态链接器确定。
3. **运行时链接:**
   * 当运行 `sys_msg_test` 可执行文件时，Android 的 `zygote` 进程会 `fork` 出新的进程。
   * 新进程启动后，内核会将程序加载到内存中。
   * 动态链接器会被加载并执行。
   * 动态链接器会解析 `sys_msg_test` 依赖的共享库 (`libc.so`)。
   * 动态链接器会查看 `sys_msg_test` 的 `.dynamic` 段，找到需要重定位的符号（例如，`msgget`）。
   * 动态链接器会查看 `libc.so` 的符号表，找到 `msgget` 的实际地址。
   * 动态链接器会将 `sys_msg_test` 的 `.got` (全局偏移表) 中对应 `msgget` 的条目更新为 `libc.so` 中 `msgget` 的实际内存地址。
   * 之后，当 `sys_msg_test` 执行到调用 `msgget` 的代码时，它会通过 `.plt` (过程链接表) 跳转到 `.got` 中存储的 `libc.so` 中 `msgget` 的地址，从而实现对 `libc.so` 中函数的调用。

**逻辑推理和假设输入/输出**

在 `sys_msg_test.cpp` 中，每个 `TEST` 都是一个独立的测试用例，包含了逻辑推理和假设输入/输出。

**例如 `smoke` 测试:**

* **假设输入:**  一个空的系统。
* **逻辑推理:**
    1. 使用 `ftok` 和 `msgget` 创建一个消息队列。期望创建成功，返回有效的消息队列 ID。
    2. 使用 `msgctl` 获取消息队列的状态，期望队列为空 (`msg_qnum` 为 0，`msg_cbytes` 为 0)。
    3. 使用 `msgsnd` 发送一条消息。期望发送成功。
    4. 再次使用 `msgctl` 获取状态，期望队列非空 (`msg_qnum` 为 1，`msg_cbytes` 为消息大小)。
    5. 使用 `msgrcv` 接收消息。期望接收到之前发送的消息，并且消息内容正确。
    6. 使用 `msgctl` 删除消息队列。期望删除成功。
* **预期输出:**  所有 `ASSERT_*` 宏都应该为真，测试用例执行成功。

**用户或编程常见的使用错误**

1. **忘记删除消息队列:** 创建了消息队列但程序退出时没有使用 `msgctl(id, IPC_RMID, nullptr)` 删除，导致资源泄漏。
   ```c++
   int id = msgget(key, IPC_CREAT | 0666);
   // ... 使用消息队列 ...
   // 忘记删除
   ```

2. **使用错误的 `key`:**  在不同的进程中使用不同的 `ftok` 参数或者硬编码的 `key`，导致无法访问同一个消息队列。
   ```c++
   // 进程 1
   key_t key1 = ftok("/tmp/file1", 1);
   int id1 = msgget(key1, IPC_CREAT | 0666);

   // 进程 2
   key_t key2 = ftok("/tmp/file2", 1); // 错误：使用了不同的文件路径
   int id2 = msgget(key2, 0); // 尝试连接，但 key 不同会失败
   ```

3. **消息大小不匹配:**  发送的消息大小和接收缓冲区的大小不一致，可能导致数据丢失或缓冲区溢出（虽然 `msgrcv` 可以通过 `MSG_NOERROR` 标志截断消息，但通常不是期望的行为）。
   ```c++
   // 发送端
   struct { long type; char data[64]; } send_msg;
   msgsnd(id, &send_msg, sizeof(send_msg.data), 0);

   // 接收端
   struct { long type; char data[32]; } recv_msg; // 缓冲区太小
   msgrcv(id, &recv_msg, sizeof(recv_msg.data), 0, 0); // 可能丢失数据
   ```

4. **权限问题:**  创建消息队列时使用了不合适的权限，导致其他进程无法访问。
   ```c++
   // 创建者
   int id = msgget(key, IPC_CREAT | 0400); // 只有所有者有读权限

   // 其他进程
   int other_id = msgget(key, 0); // 会因为权限不足而失败
   ```

5. **阻塞调用导致程序无响应:**  如果在单线程程序中使用了阻塞的 `msgsnd` 或 `msgrcv`，并且没有相应的接收或发送者，会导致程序一直等待。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework:**
   * 在 Java 层，Android Framework 并没有直接提供 System V 消息队列的 API。
   * 如果某个系统服务或者应用需要使用消息队列，它通常会通过 JNI (Java Native Interface) 调用 NDK 提供的 C/C++ 代码。

2. **Android NDK:**
   * NDK 允许开发者编写原生 C/C++ 代码。
   * 在 NDK 代码中，可以直接包含 `<sys/msg.h>` 头文件，并调用 `msgget`、`msgctl`、`msgsnd`、`msgrcv` 等 libc 函数。
   * 当 NDK 代码调用这些函数时，会链接到 Bionic 库 (`libc.so`) 中的实现。
   * Bionic 库中的这些函数最终会通过系统调用 (syscall) 进入 Linux 内核。

**步骤流程:**

```
[Android Java Framework] --> (JNI 调用) --> [NDK C/C++ 代码] --> #include <sys/msg.h> --> msgget/msgctl/msgsnd/msgrcv (Bionic libc.so) --> 系统调用 (syscall) --> [Linux Kernel] (消息队列管理)
```

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook 这些 libc 函数，以观察它们的调用情况和参数。

**假设我们想 hook `msgget` 函数：**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在你的开发机上安装了 Frida Python 模块。

2. **编写 Frida 脚本 (JavaScript):**

   ```javascript
   if (Process.platform === 'android') {
     const libc = Process.getModuleByName("libc.so");
     const msggetPtr = libc.getExportByName("msgget");

     if (msggetPtr) {
       Interceptor.attach(msggetPtr, {
         onEnter: function(args) {
           console.log("[msgget] Called");
           console.log("  key:", args[0].toInt());
           console.log("  msgflg:", args[1].toInt());
         },
         onLeave: function(retval) {
           console.log("  Return value:", retval.toInt());
           if (retval.toInt() === -1) {
             const errnoPtr = libc.getExportByName("__errno_location");
             if (errnoPtr) {
               const errnoVal = Memory.readS32(errnoPtr());
               console.log("  errno:", errnoVal);
             }
           }
         }
       });
     } else {
       console.log("Failed to find msgget in libc.so");
     }
   } else {
     console.log("This script is for Android.");
   }
   ```

3. **运行 Frida 脚本:**

   * 找到你想要调试的目标进程的进程 ID (PID)。可以使用 `adb shell ps | grep your_process_name` 命令。
   * 在你的开发机上运行 Frida 命令：
     ```bash
     frida -U -f your.package.name -l your_script.js --no-pause
     ```
     或者如果已经知道 PID：
     ```bash
     frida -U your_pid -l your_script.js
     ```
     将 `your.package.name` 替换为你的应用程序的包名，`your_pid` 替换为进程 ID， `your_script.js` 替换为你的 Frida 脚本文件名。

4. **执行目标操作:**  在你的 Android 应用或服务中执行会调用 `msgget` 的操作。

5. **查看 Frida 输出:**  Frida 会在你的终端上输出 `msgget` 函数被调用时的参数和返回值，以及 `errno` 的值（如果调用失败）。

**其他可以 hook 的函数:**

你可以使用类似的方法 hook `msgctl`, `msgsnd`, 和 `msgrcv`，以观察它们的操作和参数。例如，hook `msgsnd` 可以查看发送的消息内容，hook `msgrcv` 可以查看接收到的消息内容。

希望这个详细的解释能够帮助你理解 `bionic/tests/sys_msg_test.cpp` 文件以及相关的 Android 技术。

### 提示词
```
这是目录为bionic/tests/sys_msg_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <errno.h>
#include <sys/msg.h>

#include <android-base/file.h>

TEST(sys_msg, smoke) {
  if (msgctl(-1, IPC_STAT, nullptr) == -1 && errno == ENOSYS) {
    GTEST_SKIP() << "no <sys/msg.h> support in this kernel";
  }

  // Create a queue.
  TemporaryDir dir;
  key_t key = ftok(dir.path, 1);
  int id = msgget(key, IPC_CREAT|0666);
  ASSERT_NE(id, -1);

  // Queue should be empty.
  msqid_ds ds = {};
  ASSERT_EQ(0, msgctl(id, IPC_STAT, &ds));
  ASSERT_EQ(0U, ds.msg_qnum);
  ASSERT_EQ(0U, ds.msg_cbytes);

  // Send a message.
  struct {
    long type;
    char data[32];
  } msg = { 1, "hello world" };
  ASSERT_EQ(0, msgsnd(id, &msg, sizeof(msg.data), 0));

  // Queue should be non-empty.
  ASSERT_EQ(0, msgctl(id, IPC_STAT, &ds));
  ASSERT_EQ(1U, ds.msg_qnum);
  ASSERT_EQ(sizeof(msg.data), ds.msg_cbytes);

  // Read the message.
  msg = {};
  ASSERT_EQ(static_cast<ssize_t>(sizeof(msg.data)),
            msgrcv(id, &msg, sizeof(msg.data), 0, 0));
  ASSERT_EQ(1, msg.type);
  ASSERT_STREQ("hello world", msg.data);

  // Destroy the queue.
  ASSERT_EQ(0, msgctl(id, IPC_RMID, nullptr));
}

TEST(sys_msg, msgctl_failure) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(-1, msgctl(-1, IPC_STAT, nullptr));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
#pragma clang diagnostic pop
}

TEST(sys_msg, msgget_failure) {
  errno = 0;
  ASSERT_EQ(-1, msgget(-1, 0));
  ASSERT_TRUE(errno == ENOENT || errno == ENOSYS);
}

TEST(sys_msg, msgrcv_failure) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(-1, msgrcv(-1, nullptr, 0, 0, 0));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
#pragma clang diagnostic pop
}

TEST(sys_msg, msgsnd_failure) {
  struct {
    long type;
    char data[1];
  } msg = { 1, "" };
  errno = 0;
  ASSERT_EQ(-1, msgsnd(-1, &msg, sizeof(msg.data), 0));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
}
```