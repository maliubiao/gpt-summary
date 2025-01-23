Response:
Let's break down the thought process to answer the request about `bionic/tests/headers/posix/sys_msg_h.c`.

**1. Understanding the Core Purpose of the File:**

The file name and content immediately suggest it's a header check file. The `#include <sys/msg.h>` and the `TYPE()` and `MACRO()` calls are strong indicators. The surrounding `#if defined(__BIONIC__)` confirms this is specific to the Bionic library. The copyright notice reinforces it's an Android Open Source Project file.

**Core Conclusion #1:** This file isn't about *implementing* message queues; it's about *testing* the presence and correctness of declarations in the `sys/msg.h` header file within Bionic.

**2. Analyzing the Code Structure:**

The code defines a single function `sys_msg_h()`. Inside this function, it uses several macros:

* `TYPE(type_name)`:  This checks if the given type is defined in `sys/msg.h`.
* `MACRO(macro_name)`: This checks if the given macro is defined.
* `TYPE(struct msqid_ds)`: Checks for the existence of the `msqid_ds` structure.
* `STRUCT_MEMBER(struct_name, member_type, member_name)`:  Crucially, this verifies that specific members with the correct types exist within the `msqid_ds` structure. This is a key part of ensuring ABI compatibility.
* `FUNCTION(function_name, function_signature)`:  This checks if functions like `msgctl`, `msgget`, `msgrcv`, and `msgsnd` are declared with the expected signatures.

**Core Conclusion #2:** The code systematically checks for the presence and correct definition of types, macros, structures, and functions related to POSIX message queues.

**3. Connecting to Android and Bionic:**

Knowing Bionic is Android's C library is crucial. This test file is part of ensuring that the Bionic implementation of POSIX message queues (declared in `sys/msg.h`) conforms to the standards and provides the necessary interfaces for Android developers.

**Android Relevance Example:**  An Android app using the NDK might use the `msgsnd` function to send data between processes. This test ensures that the `msgsnd` function is indeed available and has the correct signature in Bionic.

**4. Detailed Explanation of Libc Functions:**

The prompt specifically asks for explanations of the libc functions. Even though this *test file* doesn't implement them, it *checks for their existence*. Therefore, I need to explain what these functions *do*:

* `msgctl()`:  Control message queue operations.
* `msgget()`:  Get a message queue identifier.
* `msgrcv()`:  Receive a message from a queue.
* `msgsnd()`:  Send a message to a queue.

For each, I need to provide a brief description of its purpose and key arguments. Since this is about the *interface*, the implementation details within the kernel are less relevant here.

**5. Dynamic Linker Aspects:**

This particular test file doesn't directly interact with the dynamic linker. It's checking header definitions, not the linking process. Therefore, the answer should state this and explain that the *implementation* of the message queue functions would reside in a shared library (like `libc.so`) that the dynamic linker would handle.

**Example SO Layout and Linking (Conceptual):**

Even though the test isn't about linking, providing an example of how the `msgsnd` function would be in `libc.so` and how an application would link to it is helpful for demonstrating understanding. This involves the GOT, PLT, and the dynamic linker's role in resolving symbols.

**6. Logical Reasoning, Assumptions, and Errors:**

Since this is a test file, the "logic" is in the testing framework. The assumptions are that the build environment has Bionic set up correctly and that the headers should contain the expected definitions.

**Common Errors:**  I need to consider what could go wrong when *using* message queues: incorrect permissions, invalid queue IDs, buffer overflows, etc.

**7. Android Framework/NDK Path and Frida Hook:**

This is where the understanding of the Android stack comes in. An application (Java/Kotlin) might use the NDK to call the C message queue functions. I need to outline the steps:

* Java code uses `System.loadLibrary()` to load a native library.
* Native code (C++) uses the `<sys/msg.h>` header.
* The C++ code calls functions like `msgsnd`.
* Bionic's `libc.so` provides the implementation.
* The kernel handles the actual message queue operations.

**Frida Hook Example:** I need to show how to intercept calls to `msgsnd` using Frida, demonstrating how to inspect arguments and potentially modify behavior. This requires basic Frida syntax for attaching to a process and hooking a function.

**8. Language and Formatting:**

The request specifies Chinese output. Care must be taken to use accurate translations for technical terms. Clear formatting with headings and bullet points is essential for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the implementation of message queues. **Correction:** Realize the file is about *header checks*, so the focus should be on the declarations and interfaces.
* **Initial thought:** Provide very detailed explanations of the kernel's message queue implementation. **Correction:** Keep the explanation focused on the libc functions' purpose and signatures as seen from the user's perspective.
* **Initial thought:** Overcomplicate the dynamic linker section. **Correction:**  Keep it concise, emphasizing that the test isn't *directly* about linking, but showing an example clarifies the bigger picture.

By following this structured thought process, breaking down the problem into smaller parts, and constantly referring back to the original request, I can construct a comprehensive and accurate answer.
这个文件 `bionic/tests/headers/posix/sys_msg_h.c` 的主要功能是**测试 Android Bionic 库中 `sys/msg.h` 头文件的正确性**。 它并不直接实现任何消息队列的功能，而是验证该头文件中定义的类型、宏、结构体成员和函数声明是否符合 POSIX 标准以及 Android Bionic 的预期。

以下是针对你提出的问题的详细解答：

**1. 功能列举:**

* **类型检查 (`TYPE` 宏):**  验证 `sys/msg.h` 中定义的类型，如 `msgqnum_t` (消息队列中的消息数量类型) 和 `msglen_t` (消息长度类型) 是否存在。
* **宏检查 (`MACRO` 宏):** 验证 `sys/msg.h` 中定义的宏，如 `MSG_NOERROR` (指示 `msgrcv` 函数在没有消息时立即返回) 是否存在。
* **结构体成员检查 (`STRUCT_MEMBER` 宏):** 验证 `sys/msg.h` 中定义的结构体 `msqid_ds` (消息队列的描述符) 的成员变量及其类型是否正确。例如，检查是否存在 `msg_perm` (消息队列的权限信息), `msg_qnum` (当前队列中的消息数量), `msg_qbytes` (队列的最大字节数) 等成员。  需要注意的是，代码中根据 `__LP64__` 宏 (是否为 64 位系统) 来判断 `msg_stime`, `msg_rtime`, `msg_ctime` 成员的类型，这反映了 Android 在不同架构上的兼容性考虑。
* **函数声明检查 (`FUNCTION` 宏):** 验证 `sys/msg.h` 中声明的消息队列相关函数是否存在，并且其参数和返回值类型是否符合预期。检查的函数包括 `msgctl` (消息队列控制), `msgget` (获取消息队列 ID), `msgrcv` (接收消息), 和 `msgsnd` (发送消息)。

**2. 与 Android 功能的关系及举例:**

`sys/msg.h` 中定义的接口是 POSIX 标准中进程间通信 (IPC) 的一种方式——消息队列。Android 作为基于 Linux 内核的操作系统，也支持这种 IPC 机制。

* **Android 进程间通信 (IPC):**  Android 系统中的不同应用程序 (或同一个应用程序的不同进程) 经常需要相互通信。消息队列提供了一种异步的通信方式，发送者将消息放入队列，接收者从队列中取出消息。
* **NDK 开发:**  Android NDK (Native Development Kit) 允许开发者使用 C 或 C++ 编写应用程序的某些部分。通过包含 `<sys/msg.h>` 头文件，NDK 开发者可以在他们的本地代码中使用消息队列进行进程间通信。

**举例说明:**

假设一个 Android 应用包含两个服务进程：一个负责传感器数据采集，另一个负责数据处理和显示。采集服务可以使用 `msgsnd` 将采集到的传感器数据封装成消息发送到一个消息队列，而处理服务可以使用 `msgrcv` 从同一个消息队列接收这些数据进行处理和显示。

**3. libc 函数功能实现详解:**

这个测试文件本身 **不实现** 这些 libc 函数的功能，它只是检查这些函数是否被正确声明。 这些函数的具体实现位于 Android Bionic 库 (`libc.so`) 中，更底层的实现则在 Linux 内核中。

以下是这些函数的功能简述：

* **`msgctl(int msqid, int cmd, struct msqid_ds *buf)`:**
    * **功能:**  对消息队列执行各种控制操作。
    * **参数:**
        * `msqid`:  要操作的消息队列的 ID。
        * `cmd`:  要执行的命令，例如 `IPC_STAT` (获取消息队列的状态信息), `IPC_SET` (设置消息队列的属性), `IPC_RMID` (删除消息队列) 等。
        * `buf`:  一个指向 `msqid_ds` 结构体的指针，用于存储或设置消息队列的状态信息。
    * **实现:**  `msgctl` 系统调用最终会陷入内核，由内核中的消息队列管理模块执行相应的操作。

* **`msgget(key_t key, int msgflg)`:**
    * **功能:**  获取一个消息队列的 ID。
    * **参数:**
        * `key`:  一个用于标识消息队列的键值 (通常使用 `ftok` 函数生成)。
        * `msgflg`:  一组标志位，用于指定创建或访问消息队列的方式，例如 `IPC_CREAT` (如果队列不存在则创建), `IPC_EXCL` (与 `IPC_CREAT` 一起使用，表示如果队列已存在则返回错误),  以及权限标志 (例如 `0666`)。
    * **实现:**  `msgget` 系统调用会陷入内核，内核会根据 `key` 查找现有的消息队列，如果找到则返回其 ID。如果没有找到且指定了 `IPC_CREAT` 标志，内核会创建一个新的消息队列并返回其 ID。

* **`msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)`:**
    * **功能:**  从消息队列接收一条消息。
    * **参数:**
        * `msqid`:  要接收消息的消息队列的 ID。
        * `msgp`:  一个指向缓冲区的指针，用于存储接收到的消息。
        * `msgsz`:  缓冲区的最大大小 (不包括消息类型的大小)。
        * `msgtyp`:  指定要接收的消息类型。如果为 0，则接收队列中的第一个消息。如果大于 0，则接收类型为 `msgtyp` 的第一个消息。如果小于 0，则接收类型小于等于 `abs(msgtyp)` 的最小类型消息。
        * `msgflg`:  一组标志位，例如 `IPC_NOWAIT` (如果队列为空则立即返回错误), `MSG_NOERROR` (如果消息长度超过 `msgsz` 则截断消息)。
    * **实现:**  `msgrcv` 系统调用会陷入内核，内核会从指定的队列中找到符合条件的消息，将其复制到用户空间的缓冲区。如果队列中没有符合条件的消息，进程可能会阻塞，直到有消息到达 (除非指定了 `IPC_NOWAIT`)。

* **`msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)`:**
    * **功能:**  向消息队列发送一条消息。
    * **参数:**
        * `msqid`:  要发送消息的消息队列的 ID。
        * `msgp`:  一个指向要发送的消息的指针。消息结构体的第一个成员必须是 `long` 类型的消息类型。
        * `msgsz`:  要发送的消息的长度 (不包括消息类型的大小)。
        * `msgflg`:  一组标志位，例如 `IPC_NOWAIT` (如果队列已满则立即返回错误)。
    * **实现:**  `msgsnd` 系统调用会陷入内核，内核会将用户空间的消息数据复制到内核空间的消息队列中。如果队列已满，进程可能会阻塞，直到队列有空间 (除非指定了 `IPC_NOWAIT`)。

**4. 涉及 dynamic linker 的功能，so 布局样本及链接处理过程:**

这个测试文件本身并不直接涉及 dynamic linker 的功能。它只是静态地检查头文件的定义。

然而，当一个 Android 应用使用消息队列相关的函数时，dynamic linker (在 Android 中是 `linker64` 或 `linker`) 会发挥作用。

**SO 布局样本 (`libc.so`):**

```
libc.so:
    ...
    .text:  // 代码段
        ...
        msgsnd:  // msgsnd 函数的实现代码
            ...
        msgrcv:  // msgrcv 函数的实现代码
            ...
        msgget:  // msgget 函数的实现代码
            ...
        msgctl:  // msgctl 函数的实现代码
            ...
    .data:  // 数据段
        ...
    .dynamic: // 动态链接信息
        ...
        NEEDED libc.so  // 通常指向自身，表明它是动态链接库
        SONAME libc.so
        ...
        SYMTAB  // 符号表，包含导出的符号信息 (如 msgsnd, msgrcv 等)
        STRTAB  // 字符串表，包含符号名称等字符串
        ...
    .plt:    // Procedure Linkage Table (过程链接表)
        ...
        条目指向 msgsnd 的链接过程
        条目指向 msgrcv 的链接过程
        ...
    .got:    // Global Offset Table (全局偏移表)
        ...
        msgsnd 的地址 (初始为 dynamic linker 的某个入口)
        msgrcv 的地址 (初始为 dynamic linker 的某个入口)
        ...
```

**链接处理过程:**

1. **编译链接时:** 当应用程序的代码调用 `msgsnd` 等函数时，编译器会在生成的目标文件中记录下对这些外部符号的引用。这些引用会指向一个占位符地址，通常位于 `.plt` 段。
2. **加载时:** 当 Android 系统加载应用程序时，dynamic linker 会被启动。
3. **符号解析:** dynamic linker 会解析应用程序依赖的共享库 (`libc.so`) 中的符号。它会查找 `libc.so` 的符号表 (`.symtab`)，找到 `msgsnd`, `msgrcv` 等函数的实际地址。
4. **重定位:** dynamic linker 会更新应用程序的全局偏移表 (`.got`) 中的条目，将占位符地址替换为 `libc.so` 中对应函数的实际地址。
5. **第一次调用:** 当应用程序第一次调用 `msgsnd` 时，会跳转到 `.plt` 中对应的条目。`.plt` 中的代码会先跳转到 `.got` 中对应的条目。由于 `.got` 中的地址已经被 dynamic linker 更新为 `msgsnd` 的实际地址，所以程序会成功跳转到 `libc.so` 中的 `msgsnd` 函数执行。后续的调用将直接跳转到 `.got` 中存储的地址，避免重复的解析过程。

**5. 逻辑推理、假设输入与输出:**

这个测试文件主要进行静态检查，没有复杂的逻辑推理。它的“逻辑”在于断言各种定义的存在性和正确性。

**假设输入:**  Bionic 库的 `sys/msg.h` 头文件。

**输出:**  如果所有检查都通过，则测试通过 (通常不产生可见的输出，或者输出表示成功的消息)。如果任何检查失败，则测试会报告错误，指出哪个类型、宏、结构体成员或函数声明不符合预期。

**6. 用户或编程常见的使用错误:**

* **忘记包含头文件:** 如果使用消息队列相关函数但忘记 `#include <sys/msg.h>`，会导致编译错误，因为相关的类型和函数声明不可见。
* **`msgget` 使用不当:**
    * 使用相同的 `key` 但不同的 `msgflg` 可能导致意外的行为。
    * 没有正确处理 `msgget` 的返回值 (可能返回 -1 表示错误，并设置 `errno`)。
* **`msgsnd` 发送的消息格式错误:** 发送的消息的第一个成员必须是 `long` 类型的消息类型，否则 `msgrcv` 接收时可能无法正确过滤。
* **`msgrcv` 缓冲区大小不足:** 如果接收缓冲区的大小小于实际接收到的消息大小，且没有指定 `MSG_NOERROR`，则 `msgrcv` 会返回错误。如果指定了 `MSG_NOERROR`，消息会被截断，可能导致数据丢失。
* **权限问题:**  消息队列的权限设置不当可能导致其他进程无法访问。
* **资源泄漏:**  创建了消息队列但没有在不再使用时删除 (`msgctl` 与 `IPC_RMID`)，可能导致系统资源泄漏。

**示例 (C 代码):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>

#define MSG_TYPE 1

struct msg_buffer {
    long msg_type;
    char msg_text[100];
};

int main() {
    key_t key;
    int msgid;
    struct msg_buffer message;

    // 常见错误：忘记处理 msgget 的返回值
    key = ftok("my_program", 'B');
    if (key == -1) {
        perror("ftok");
        exit(EXIT_FAILURE);
    }

    msgid = msgget(key, 0666 | IPC_CREAT);
    if (msgid == -1) {
        perror("msgget");
        exit(EXIT_FAILURE);
    }

    // 发送消息
    message.msg_type = MSG_TYPE;
    strcpy(message.msg_text, "Hello from sender!");
    if (msgsnd(msgid, &message, sizeof(message.msg_text), 0) == -1) {
        perror("msgsnd");
    }

    // 接收消息（假设有另一个进程在接收）

    // 清理资源
    if (msgctl(msgid, IPC_RMID, NULL) == -1) {
        perror("msgctl");
        // 注意：如果其他进程还在使用队列，删除可能会失败
    }

    return 0;
}
```

**7. Android Framework 或 NDK 如何到达这里，Frida Hook 示例:**

1. **Android Framework (Java/Kotlin):** Android Framework 本身通常不直接使用 POSIX 消息队列进行进程间通信。Framework 更倾向于使用 Binder 机制。
2. **NDK (C/C++):**  NDK 开发的应用可以直接使用 `<sys/msg.h>` 中定义的函数。

**步骤示例：NDK 应用使用消息队列:**

1. **Java 代码:**  创建一个 Native 方法，该方法将在 C/C++ 代码中调用消息队列函数。
   ```java
   public class MessageQueueUtil {
       static {
           System.loadLibrary("native-lib"); // 加载 NDK 库
       }

       public native int sendMessage(String message);
   }
   ```

2. **NDK 代码 (C++):**
   ```c++
   #include <jni.h>
   #include <string>
   #include <sys/types.h>
   #include <sys/ipc.h>
   #include <sys/msg.h>
   #include <cstring>
   #include <unistd.h>

   extern "C" JNIEXPORT jint JNICALL
   Java_com_example_myapp_MessageQueueUtil_sendMessage(JNIEnv* env, jobject /* this */, jstring message) {
       key_t key;
       int msgid;
       struct {
           long mtype;
           char mtext[256];
       } msg;

       key = ftok("/tmp/mymsgq", 'R'); // 使用一个固定的路径和 ID
       if (key == -1) return -1;

       msgid = msgget(key, 0666 | IPC_CREAT);
       if (msgid == -1) return -1;

       const char* nativeMessage = env->GetStringUTFChars(message, 0);
       msg.mtype = 1;
       strncpy(msg.mtext, nativeMessage, sizeof(msg.mtext) - 1);
       msg.mtext[sizeof(msg.mtext) - 1] = '\0';
       env->ReleaseStringUTFChars(message, nativeMessage);

       if (msgsnd(msgid, &msg, sizeof(msg.mtext), 0) == -1) return -1;

       return 0;
   }
   ```

**Frida Hook 示例 (Hook `msgsnd`):**

假设你要 Hook 上述 NDK 代码中的 `msgsnd` 函数。

```python
import frida
import sys

package_name = "com.example.myapp" # 你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "msgsnd"), {
    onEnter: function(args) {
        console.log("[*] msgsnd called");
        console.log("    msqid: " + args[0]);
        console.log("    msgp: " + args[1]);
        console.log("    msgsz: " + args[2]);
        console.log("    msgflg: " + args[3]);

        // 读取消息内容 (假设消息结构体的第一个成员是 long 类型，之后是 char 数组)
        var msqid = parseInt(args[0]);
        var msgp = ptr(args[1]);
        var msgsz = parseInt(args[2]);

        var messageType = msgp.readLong();
        var messageText = msgp.add(Process.pointerSize).readUtf8String(msgsz);

        console.log("    Message Type: " + messageType);
        console.log("    Message Text: " + messageText);
    },
    onLeave: function(retval) {
        console.log("[*] msgsnd returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 解释:**

1. **导入 Frida 库:**  导入 `frida` 和 `sys` 库。
2. **连接到目标应用:** 使用 `frida.get_usb_device().attach(package_name)` 连接到正在运行的目标 Android 应用进程。
3. **定义 `on_message` 函数:**  用于处理 Frida 脚本发送回来的消息。
4. **编写 Frida 脚本:**
   * `Interceptor.attach`:  拦截 `libc.so` 中的 `msgsnd` 函数。
   * `onEnter`:  在 `msgsnd` 函数被调用前执行：
     * 打印调用信息和参数值。
     * 读取消息结构体的内容（需要根据消息结构体的定义来解析）。
   * `onLeave`: 在 `msgsnd` 函数返回后执行，打印返回值。
5. **创建和加载脚本:**  使用 `session.create_script(script_code)` 创建 Frida 脚本，并使用 `script.load()` 加载到目标进程中。
6. **保持脚本运行:** `sys.stdin.read()` 阻止脚本退出，以便持续监听 `msgsnd` 的调用。

通过运行这个 Frida 脚本，当你的 NDK 应用调用 `msgsnd` 发送消息时，你将在 Frida 控制台中看到拦截到的调用信息，包括参数和消息内容。

总结来说，`bionic/tests/headers/posix/sys_msg_h.c` 是一个测试文件，用于确保 Android Bionic 库中 `sys/msg.h` 头文件的定义正确，从而保证 NDK 开发者可以使用标准的 POSIX 消息队列 API 进行进程间通信。理解这个文件的作用有助于理解 Android 系统中本地代码与系统库的交互方式。

### 提示词
```
这是目录为bionic/tests/headers/posix/sys_msg_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#if defined(__BIONIC__)

#include <sys/msg.h>

#include "header_checks.h"

static void sys_msg_h() {
  TYPE(msgqnum_t);
  TYPE(msglen_t);

  MACRO(MSG_NOERROR);

  TYPE(struct msqid_ds);
  STRUCT_MEMBER(struct msqid_ds, struct ipc_perm, msg_perm);
  STRUCT_MEMBER(struct msqid_ds, msgqnum_t, msg_qnum);
  STRUCT_MEMBER(struct msqid_ds, msglen_t, msg_qbytes);
  STRUCT_MEMBER(struct msqid_ds, pid_t, msg_lspid);
  STRUCT_MEMBER(struct msqid_ds, pid_t, msg_lrpid);
#if defined(__LP64__)
  STRUCT_MEMBER(struct msqid_ds, time_t, msg_stime);
  STRUCT_MEMBER(struct msqid_ds, time_t, msg_rtime);
  STRUCT_MEMBER(struct msqid_ds, time_t, msg_ctime);
#else
  // Starting at kernel v4.19, 32 bit changed these to unsigned values.
  STRUCT_MEMBER(struct msqid_ds, unsigned long, msg_stime);
  STRUCT_MEMBER(struct msqid_ds, unsigned long, msg_rtime);
  STRUCT_MEMBER(struct msqid_ds, unsigned long, msg_ctime);
#endif

  TYPE(pid_t);
  TYPE(size_t);
  TYPE(ssize_t);
  TYPE(time_t);

  FUNCTION(msgctl, int (*f)(int, int, struct msqid_ds*));
  FUNCTION(msgget, int (*f)(key_t, int));
  FUNCTION(msgrcv, ssize_t (*f)(int, void*, size_t, long, int));
  FUNCTION(msgsnd, int (*f)(int, const void*, size_t, int));
}
#endif
```