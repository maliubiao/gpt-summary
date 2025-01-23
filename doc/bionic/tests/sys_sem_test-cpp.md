Response:
Let's break down the thought process for answering the user's request about `bionic/tests/sys_sem_test.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided C++ test file. Key aspects to address are:

* **What does the code test?** (Functionality)
* **How does it relate to Android?** (Android integration)
* **How are the libc functions implemented?** (Internal implementation)
* **How does it interact with the dynamic linker?** (Dynamic linking)
* **What are possible errors?** (Common mistakes)
* **How does the Android framework/NDK reach this code?** (Call path)
* **How can I debug it?** (Frida example)

**2. Initial Code Scan and Keyword Spotting:**

I quickly scanned the code for keywords and function names to get a high-level overview:

* **`#include <sys/sem.h>`:**  This immediately signals that the code is about System V semaphores.
* **`TEST(sys_sem, ...)`:** This indicates Google Test framework usage, meaning these are unit tests.
* **`semget`, `semctl`, `semop`, `semtimedop`:** These are the core System V semaphore functions being tested.
* **`IPC_CREAT`, `IPC_RMID`, `IPC_STAT`, `GETVAL`:** These are constants used with `semctl`.
* **`TemporaryDir`:**  Likely a helper class for creating temporary directories, probably used with `ftok`.
* **`ASSERT_*` macros:**  Assertions from Google Test to check for expected outcomes.
* **`errno`:**  Indicates error handling.
* **`GTEST_SKIP()`:**  A way to skip tests under certain conditions.

**3. Analyzing Each Test Case:**

I went through each `TEST` function individually to understand its purpose:

* **`smoke`:**  This seems to be the main test, covering the basic lifecycle of a semaphore: creation, getting info, incrementing, testing timeouts, decrementing, and destroying.
* **`semget_failure`, `semctl_failure`, `semop_failure`, `semtimedop_failure`:** These tests specifically check for error conditions and ensure the functions return -1 and set `errno` correctly when invalid arguments are provided.
* **`union_semun`:** This test addresses a specific issue related to the `semun` union, which has historical baggage and is handled differently across systems.

**4. Addressing Each Part of the User's Request (Mental Checklist):**

* **功能 (Functionality):**  The tests exercise the core System V semaphore API in Android's Bionic library. I need to list the tested functions and their basic purposes.
* **与 Android 的关系 (Relationship with Android):** Semaphores are a fundamental IPC mechanism used in Android for process and thread synchronization. I should provide an example, such as inter-process communication between an app and a system service.
* **libc 函数实现 (libc function implementation):** I need to explain what each of the `semget`, `semctl`, `semop`, and `semtimedop` functions *conceptually* do. Since this is a *test* file, the actual implementation details are in the Bionic library itself. I'll focus on the system calls they likely wrap.
* **dynamic linker 的功能 (Dynamic linker functionality):** The test code itself *doesn't directly interact* with the dynamic linker. However, the `libutils.so` mentioned hints at dynamic linking. I need to explain that the semaphore functions are *part of* libc.so, which is dynamically linked. I should provide a basic SO layout and the linking process (finding symbols, resolving dependencies).
* **逻辑推理 (Logical reasoning):** The tests use assertions, implicitly demonstrating expected input and output. I can explicitly state these for the `smoke` test (e.g., creating a semaphore should result in a positive ID).
* **常见的使用错误 (Common usage errors):**  I should think about typical programming mistakes when using semaphores, like forgetting to initialize, race conditions due to improper usage, and not handling errors.
* **Android framework/NDK 如何到达这里 (How Android reaches here):** I need to trace the path. An NDK app using the semaphore API will call the corresponding functions in libc.so. The Android framework itself might use semaphores internally for various synchronization tasks.
* **Frida hook 示例 (Frida hook example):** I should provide a basic Frida script that intercepts one of the semaphore functions (e.g., `semop`) to demonstrate how to observe its behavior.

**5. Structuring the Answer:**

I decided to structure the answer based on the user's specific questions to make it clear and organized:

* Start with a general summary of the file's purpose.
* Address each function (`semget`, `semctl`, etc.) individually, explaining its purpose and relating it to Android.
* Dedicate a section to dynamic linking, explaining the role of `libc.so`.
* Provide clear examples for logical reasoning, common errors, and the Frida hook.
* Explain the call path from the NDK/framework.

**6. Refining the Content:**

During the writing process, I made sure to:

* Use precise language.
* Explain technical terms clearly.
* Provide concrete examples.
* Maintain a logical flow.
* Emphasize the distinction between the *test code* and the *underlying implementation* in Bionic.

**Self-Correction/Refinement Example:**

Initially, I might have focused too heavily on the *specifics* of how the kernel implements semaphores. However, the user's request is about the *test file* and its context within Android. Therefore, I shifted the focus to the API level and the user-space perspective, explaining how Android developers would use these functions. I also realized that while the test uses `ftok`, which involves file system paths, the core functionality of semaphores is OS-level and doesn't inherently require files in a production scenario. This nuance needed to be addressed. Similarly, for dynamic linking, I initially thought about going into more detail about relocation, but decided to keep it at a high level of finding and resolving symbols within `libc.so`.

By following this structured approach, I could address all aspects of the user's request comprehensively and accurately.
这个 `bionic/tests/sys_sem_test.cpp` 文件是 Android Bionic 库中用于测试 System V 信号量 (semaphore) 相关功能的单元测试代码。Bionic 是 Android 系统的 C 库，提供了 POSIX 标准的接口以及 Android 特有的功能。这个测试文件验证了 Bionic 中 `sys/sem.h` 头文件中定义的信号量相关函数的正确性。

**功能列举:**

这个测试文件主要测试了以下 System V 信号量相关的 libc 函数：

1. **`semget()`:**  用于创建或获取一个信号量集。
2. **`semctl()`:**  用于对信号量集执行各种控制操作，例如获取状态、设置值、删除信号量集。
3. **`semop()`:**  用于对信号量集中的信号量执行原子操作（增加或减少）。
4. **`semtimedop()`:**  与 `semop()` 类似，但可以设置超时时间。

此外，它还测试了一些边缘情况和错误处理，以及与 `union semun` 结构体相关的兼容性问题。

**与 Android 功能的关系及举例说明:**

System V 信号量是一种进程间通信 (IPC) 机制，用于同步不同进程或线程之间的操作。在 Android 中，它可能被用于：

* **进程同步:**  不同的 Android 进程可能需要同步对共享资源的访问。例如，一个媒体服务器进程和一个客户端进程可能需要通过信号量来协调对共享内存缓冲区的读写操作。
* **资源管理:** 系统服务可以使用信号量来管理有限的资源，例如线程池的大小或可用的硬件资源。
* **驱动程序和用户空间通信:**  某些底层的驱动程序可能会使用信号量来与用户空间的进程进行同步。

**举例说明:** 假设一个 Android 应用需要使用一个后台服务来处理一些耗时的任务。

1. **服务创建信号量:** 后台服务启动时，可以使用 `semget()` 创建一个初始值为 0 的信号量。
2. **应用请求任务:** 应用向服务发送一个任务请求。
3. **服务处理任务:** 服务开始处理任务。
4. **服务完成任务后释放信号量:** 任务完成后，服务使用 `semop()` 对信号量执行加 1 操作，表示任务已完成。
5. **应用等待信号量:** 应用可以使用 `semop()` 对信号量执行减 1 操作，但设置了阻塞标志。如果信号量的值为 0，应用会被阻塞，直到服务释放信号量。

**详细解释每一个 libc 函数的功能是如何实现的:**

这些 libc 函数实际上是对 Linux 内核提供的系统调用的封装。

1. **`semget(key_t key, int nsems, int semflg)`:**
   * **功能:** 创建一个新的信号量集或返回一个已存在的信号量集的标识符。
   * **实现:**
     * 将参数传递给内核的 `sys_semget` 系统调用。
     * 内核会检查是否存在与给定 `key` 关联的信号量集。
     * 如果 `IPC_CREAT` 标志被设置，且不存在这样的信号量集，内核会创建一个包含 `nsems` 个信号量的新集合，并返回其标识符。
     * 如果 `IPC_CREAT` 未设置，且不存在这样的集合，或者发生其他错误（如权限问题），则返回 -1 并设置 `errno`。
     * `key` 通常通过 `ftok()` 函数生成，以确保不同进程使用相同的键能访问同一个信号量集。

2. **`semctl(int semid, int semnum, int cmd, ...)`:**
   * **功能:** 对由 `semid` 标识的信号量集执行各种控制操作。
   * **实现:**
     * 将参数传递给内核的 `sys_semctl` 系统调用。
     * `cmd` 参数指定要执行的操作，例如：
       * **`IPC_STAT`:** 获取信号量集的状态信息 (存储在 `semid_ds` 结构体中)。
       * **`IPC_SET`:** 设置信号量集的某些属性（例如，所有者）。
       * **`IPC_RMID`:** 删除信号量集。
       * **`GETVAL`:** 获取信号量集中指定信号量 `semnum` 的当前值。
       * **`SETVAL`:** 设置信号量集中指定信号量 `semnum` 的当前值。
       * **`GETALL`:** 获取信号量集中所有信号量的当前值。
       * **`SETALL`:** 设置信号量集中所有信号量的当前值。
     * 内核根据 `cmd` 执行相应的操作，并返回结果或错误码。

3. **`semop(int semid, struct sembuf *sops, unsigned nsops)`:**
   * **功能:** 对由 `semid` 标识的信号量集执行一个或多个原子操作。
   * **实现:**
     * 将参数传递给内核的 `sys_semop` 系统调用。
     * `sops` 是一个指向 `sembuf` 结构体数组的指针，每个结构体描述一个操作。
     * `sembuf` 结构体包含：
       * `sem_num`: 要操作的信号量在集合中的索引。
       * `sem_op`: 要执行的操作，正数表示增加信号量的值（释放），负数表示减少信号量的值（获取），零表示等待信号量的值变为零。
       * `sem_flg`: 操作标志，例如 `IPC_NOWAIT` (非阻塞操作) 或 0 (阻塞操作)。
     * 内核会原子地执行所有指定的操作。如果任何一个操作由于信号量的值不足而无法立即完成，并且没有设置 `IPC_NOWAIT`，调用进程会被阻塞直到条件满足。

4. **`semtimedop(int semid, struct sembuf *sops, unsigned nsops, const struct timespec *timeout)`:**
   * **功能:** 与 `semop()` 类似，但可以指定一个超时时间。
   * **实现:**
     * 将参数传递给内核的 `sys_semtimedop` 系统调用。
     * 如果在指定的 `timeout` 时间内，所有操作无法完成，则调用失败并返回 `EAGAIN` 错误。
     * 其余实现与 `semop()` 类似。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

在这个测试代码本身，并没有直接涉及到动态链接器的功能。测试代码运行在一个独立的进程中，它调用的 `semget`、`semctl` 等函数是 libc 提供的。但是，libc 本身是一个动态链接库 (`libc.so`)。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:  // 代码段，包含 semget, semctl, semop, semtimedop 等函数的实现
        semget:
            ... // semget 的汇编代码
        semctl:
            ... // semctl 的汇编代码
        semop:
            ... // semop 的汇编代码
        semtimedop:
            ... // semtimedop 的汇编代码
    .data:  // 初始化数据段
        ...
    .bss:   // 未初始化数据段
        ...
    .dynsym: // 动态符号表，包含导出的符号（例如 semget, semctl）
        semget
        semctl
        semop
        semtimedop
    .dynstr: // 动态字符串表，存储符号名称
        "semget"
        "semctl"
        "semop"
        "semtimedop"
    .plt:    // 程序链接表，用于延迟绑定
        semget@plt:
            ...
        semctl@plt:
            ...
        semop@plt:
            ...
        semtimedop@plt:
            ...
    .got.plt: // 全局偏移表，存储动态链接器解析后的函数地址
        semget@got.plt: 0x...
        semctl@got.plt: 0x...
        semop@got.plt: 0x...
        semtimedop@got.plt: 0x...
```

**链接的处理过程:**

1. **加载:** 当测试程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载测试程序的可执行文件以及其依赖的动态链接库，包括 `libc.so`。
2. **符号查找:** 当测试程序调用 `semget` 等函数时，最初会跳转到 `.plt` 段中对应的条目（例如 `semget@plt`）。
3. **延迟绑定:** `.plt` 中的代码会跳转到动态链接器的例程。动态链接器会查找 `libc.so` 的 `.dynsym` 表，找到 `semget` 符号的定义。
4. **地址解析:** 动态链接器找到 `semget` 在 `libc.so` 中的实际地址。
5. **更新 GOT:** 动态链接器将 `semget` 的实际地址写入 `.got.plt` 段中 `semget@got.plt` 对应的条目。
6. **跳转执行:**  之后再次调用 `semget` 时，会直接跳转到 `.got.plt` 中存储的实际地址，从而执行 `libc.so` 中 `semget` 的代码。

**如果做了逻辑推理，请给出假设输入与输出:**

在 `smoke` 测试用例中，可以看到一些逻辑推理和断言：

**假设输入与输出 (基于 `smoke` 测试):**

1. **`semget(key, 1, IPC_CREAT|0666)`:**
   * **假设输入:**
     * `key`: 通过 `ftok()` 生成的唯一键值 (例如，假设 `key` 为 `12345`).
     * `nsems`: 1 (创建一个包含 1 个信号量的集合).
     * `semflg`: `IPC_CREAT|0666` (如果不存在则创建，并设置权限为 0666).
   * **预期输出:** 返回一个非负的信号量集 ID (例如，假设返回 `10`). 如果创建失败，则返回 -1。

2. **`semctl(id, 0, IPC_STAT, &ds)`:**
   * **假设输入:**
     * `id`: 上一步 `semget` 返回的 ID (假设为 `10`).
     * `semnum`: 0 (操作集合中的第一个信号量).
     * `cmd`: `IPC_STAT` (获取状态).
     * `&ds`: 指向 `semid_ds` 结构体的指针。
   * **预期输出:** 返回 0 (表示成功)，并且 `ds.sem_nsems` 的值为 1。

3. **`semctl(id, 0, GETVAL)`:**
   * **假设输入:**
     * `id`: `10`.
     * `semnum`: 0.
     * `cmd`: `GETVAL` (获取值).
   * **预期输出:** 返回 0 (因为信号量刚创建时初始值为 0)。

4. **`semop(id, ops, 1)` (increment):**
   * **假设输入:**
     * `id`: `10`.
     * `ops`:  `{{ .sem_num = 0, .sem_op = 1, .sem_flg = 0 }}` (对第一个信号量加 1).
     * `nsops`: 1.
   * **预期输出:** 返回 0 (表示成功)。

5. **`semctl(id, 0, GETVAL)` (after increment):**
   * **假设输入:** 同上.
   * **预期输出:** 返回 1。

6. **`semtimedop(id, ops, 1, &ts)` (timeout):**
   * **假设输入:**
     * `id`: `10`.
     * `ops`: `{{ .sem_num = 0, .sem_op = 0, .sem_flg = 0 }}` (等待第一个信号量变为 0，当前值为 1).
     * `ts`: `{ .tv_sec = 0, .tv_nsec = 100 }` (超时时间为 100 纳秒).
   * **预期输出:** 返回 -1，并且 `errno` 被设置为 `EAGAIN` (表示超时)。

7. **`semop(id, ops, 1)` (decrement):**
   * **假设输入:**
     * `id`: `10`.
     * `ops`: `{{ .sem_num = 0, .sem_op = -1, .sem_flg = 0 }}` (对第一个信号量减 1).
   * **预期输出:** 返回 0。

8. **`semctl(id, 0, IPC_RMID)`:**
   * **假设输入:**
     * `id`: `10`.
     * `semnum`: 0.
     * `cmd`: `IPC_RMID` (删除信号量集).
   * **预期输出:** 返回 0。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记初始化信号量:** 创建信号量后，如果没有使用 `semctl` 的 `SETVAL` 或 `SETALL` 命令设置初始值，信号量的行为将不可预测。

   ```c
   int id = semget(key, 1, IPC_CREAT | 0666);
   // 错误：忘记初始化
   sembuf ops = {0, -1, 0};
   if (semop(id, &ops, 1) == -1) {
       perror("semop"); // 可能因为信号量值为 0 而阻塞
   }
   ```

2. **死锁:** 多个进程或线程互相等待对方释放信号量，导致所有进程都无法继续执行。

   ```c
   // 进程 A
   semop(semid1, acquire_sem1, 1);
   // ... 执行某些操作 ...
   semop(semid2, acquire_sem2, 1); // 等待进程 B 释放 semid2
   // ...

   // 进程 B
   semop(semid2, acquire_sem2, 1);
   // ... 执行某些操作 ...
   semop(semid1, acquire_sem1, 1); // 等待进程 A 释放 semid1
   // ...
   ```

3. **信号量泄漏:**  创建了信号量但忘记在不再需要时使用 `semctl` 的 `IPC_RMID` 命令删除，导致系统资源泄漏。

   ```c
   int id = semget(key, 1, IPC_CREAT | 0666);
   // ... 使用信号量 ...
   // 错误：忘记删除信号量
   ```

4. **错误的信号量操作数:** 对信号量执行加或减操作时，没有考虑信号量的当前值，可能导致信号量的值变为负数 (虽然 System V 信号量允许负值，但通常表示逻辑错误)。

   ```c
   int id = semget(key, 1, IPC_CREAT | 0666);
   semctl(id, 0, SETVAL, 0); // 初始化为 0
   sembuf ops = {0, -2, 0}; // 错误：尝试减 2
   semop(id, &ops, 1);
   ```

5. **不正确的 `sem_num` 值:** 在操作信号量集时，使用了超出范围的 `sem_num` 值，会导致错误。

   ```c
   int id = semget(key, 2, IPC_CREAT | 0666); // 创建包含 2 个信号量的集合
   sembuf ops = {2, 1, 0}; // 错误：访问索引为 2 的信号量（索引从 0 开始）
   semop(id, &ops, 1);
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 或 NDK 到达 `sys_sem` 的步骤:**

1. **NDK 应用:**
   * NDK 应用开发者使用 C/C++ 代码，包含 `<sys/sem.h>` 头文件。
   * 调用 `semget`, `semctl`, `semop`, `semtimedop` 等函数。
   * 这些函数是 Bionic libc 提供的接口。
   * 当 NDK 应用被编译时，链接器会将这些函数调用链接到 `libc.so` 动态库。
   * 在运行时，当应用调用这些函数时，会通过动态链接器跳转到 `libc.so` 中对应的实现。

2. **Android Framework:**
   * Android Framework 的某些组件（通常是 Native 组件，例如 system server 的一部分）可能也会直接使用 System V 信号量进行进程间或线程间同步。
   * 这些组件的代码同样会调用 `semget` 等 libc 函数。

**Frida Hook 示例:**

可以使用 Frida 来拦截和观察这些函数的调用。以下是一个简单的 Frida 脚本示例，用于 hook `semop` 函数：

```javascript
if (Process.platform === 'android') {
  var libc = Process.getModuleByName("libc.so");
  var semopPtr = libc.getExportByName("semop");

  if (semopPtr) {
    Interceptor.attach(semopPtr, {
      onEnter: function (args) {
        console.log("[semop] Entered");
        console.log("  semid:", args[0]);
        console.log("  sops:", args[1]);
        console.log("  nsops:", args[2]);

        // 读取 sembuf 结构体的内容 (需要根据目标架构调整)
        var sopsPtr = ptr(args[1]);
        var nsops = parseInt(args[2]);
        for (let i = 0; i < nsops; i++) {
          var semNum = sopsPtr.add(i * 12).readU16(); // 假设 sembuf 大小为 12 字节
          var semOp = sopsPtr.add(i * 12 + 2).readShort();
          var semFlg = sopsPtr.add(i * 12 + 4).readShort();
          console.log(`  sops[${i}]: sem_num=${semNum}, sem_op=${semOp}, sem_flg=${semFlg}`);
        }
      },
      onLeave: function (retval) {
        console.log("[semop] Leaving, return value:", retval);
        if (retval.toInt32() === -1) {
          var errnoPtr = libc.getExportByName("__errno_location");
          if (errnoPtr) {
            var errnoVal = ptr(errnoPtr()).readS32();
            console.log("  errno:", errnoVal);
          }
        }
      }
    });
    console.log("semop hooked!");
  } else {
    console.log("Failed to find semop in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `semop_hook.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l semop_hook.js --no-pause
   # 或者连接到正在运行的进程
   frida -U <进程名或PID> -l semop_hook.js
   ```
   将 `<包名>` 替换为你要监控的应用的包名，或者 `<进程名或PID>` 替换为进程名或 PID。

**调试步骤:**

当目标应用调用 `semop` 函数时，Frida 脚本会拦截该调用并打印相关信息，包括：

* 函数入口和出口。
* `semid` (信号量集 ID)。
* `sops` 指针和 `nsops` (操作数组及其大小)。
* 解析出的 `sembuf` 结构体内容 (信号量编号、操作类型、标志)。
* `semop` 函数的返回值。
* 如果返回值是 -1，还会尝试获取并打印 `errno` 的值。

通过这种方式，可以观察 Android 应用或 Framework 如何使用 System V 信号量，以及可能出现的错误。你可以根据需要修改 Frida 脚本来 hook 其他信号量相关的函数，或者添加更详细的日志信息。

### 提示词
```
这是目录为bionic/tests/sys_sem_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <sys/sem.h>

#include <android-base/file.h>

#include "utils.h"

TEST(sys_sem, smoke) {
  if (semctl(-1, 0, IPC_RMID) == -1 && errno == ENOSYS) {
    GTEST_SKIP() << "no <sys/sem.h> support in this kernel";
  }

  // Create a semaphore.
  TemporaryDir dir;
  key_t key = ftok(dir.path, 1);
  int id = semget(key, 1, IPC_CREAT|0666);
  ASSERT_NE(id, -1);

  // Check semaphore info.
  semid_ds ds = {};
  ASSERT_EQ(0, semctl(id, 0, IPC_STAT, &ds));
  ASSERT_EQ(1U, ds.sem_nsems);

  ASSERT_EQ(0, semctl(id, 0, GETVAL));

  // Increment.
  sembuf ops[] = {{ .sem_num = 0, .sem_op = 1, .sem_flg = 0 }};
  ASSERT_EQ(0, semop(id, ops, 1));
  ASSERT_EQ(1, semctl(id, 0, GETVAL));

  // Test timeouts.
  timespec ts = { .tv_sec = 0, .tv_nsec = 100 };
  ops[0] = { .sem_num = 0, .sem_op = 0, .sem_flg = 0 };
  errno = 0;
  ASSERT_EQ(-1, semtimedop(id, ops, 1, &ts));
  ASSERT_ERRNO(EAGAIN);
  ASSERT_EQ(1, semctl(id, 0, GETVAL));

  // Decrement.
  ops[0] = { .sem_num = 0, .sem_op = -1, .sem_flg = 0 };
  ASSERT_EQ(0, semop(id, ops, 1));
  ASSERT_EQ(0, semctl(id, 0, GETVAL));

  // Destroy the semaphore.
  ASSERT_EQ(0, semctl(id, 0, IPC_RMID));
}

TEST(sys_sem, semget_failure) {
  errno = 0;
  ASSERT_EQ(-1, semget(-1, -1, 0));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
}

TEST(sys_sem, semctl_failure) {
  errno = 0;
  ASSERT_EQ(-1, semctl(-1, 0, IPC_RMID));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
}

TEST(sys_sem, semop_failure) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(-1, semop(-1, nullptr, 0));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
#pragma clang diagnostic pop
}

TEST(sys_sem, semtimedop_failure) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(-1, semtimedop(-1, nullptr, 0, nullptr));
  ASSERT_TRUE(errno == EINVAL || errno == ENOSYS);
#pragma clang diagnostic pop
}

TEST(sys_sem, union_semun) {
  // https://github.com/android-ndk/ndk/issues/400
#if defined(__BIONIC__)
  semun arg;
  semid_ds i1;
  seminfo i2;
  unsigned short a[] = { 1u, 2u };
  arg.val = 123;
  arg.buf = &i1;
  arg.array = a;
  arg.__buf = &i2;
#else
  // glibc already mostly removed this cruft (although it's still in <linux/sem.h>).
#endif
}
```