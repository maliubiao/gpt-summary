Response:
Let's break down the thought process for answering the request about `futex.h`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`futex.h`) within the context of Android's Bionic library. The request specifically asks about:

* **Functionality:** What does this file define?
* **Android Relationship:** How does it connect to Android?
* **libc Function Implementation:**  A detailed explanation of how each libc *function* is implemented (tricky, as it's a header, not implementation).
* **Dynamic Linker:** Aspects related to dynamic linking (again, the header is declarations, not linking logic directly).
* **Logical Reasoning:**  Input/output examples (applicable to functions, less so to constant definitions).
* **Common Usage Errors:**  Typical mistakes developers might make.
* **Android Framework/NDK Path:** How does a call from a higher level reach this header?
* **Frida Hooking:**  Demonstrating how to intercept calls related to this.

**2. Initial Analysis of the Header File:**

The first step is to recognize that `futex.h` is a **header file**. This is crucial because header files primarily contain:

* **Macros and Constants:**  Definitions using `#define`.
* **Type Definitions:**  Structures (`struct`), unions (`union`), and typedefs.
* **Function Declarations:** Prototypes of functions (but *not* the actual function implementations).

This immediately tells us that we won't find *implementation details* of libc functions *within this file*. The actual implementation of the `futex` syscall and related functions resides in the Linux kernel.

**3. Identifying Key Elements and Grouping:**

Scan the header file and categorize the content:

* **FUTEX Command Macros:** `FUTEX_WAIT`, `FUTEX_WAKE`, etc. These represent the different operations that can be performed with the `futex` system call.
* **FUTEX Flag Macros:** `FUTEX_PRIVATE_FLAG`, `FUTEX_CLOCK_REALTIME`. These modify the behavior of the `futex` operation.
* **Combined Flag Macros:**  Combinations like `FUTEX_WAIT_PRIVATE`.
* **FUTEX2 Macros:**  Constants related to a potentially newer or alternative `futex` mechanism.
* **Structure Definitions:** `futex_waitv`, `robust_list`, `robust_list_head`. These define the data structures used with `futex`.
* **Bit Manipulation Macros:** `FUTEX_WAITERS`, `FUTEX_OWNER_DIED`, `FUTEX_TID_MASK`.
* **Operation Composition Macro:** `FUTEX_OP`. This is a utility for constructing the `op` argument for `FUTEX_WAKE_OP`.

**4. Connecting to Android:**

Recognize that `futex` is a fundamental Linux kernel mechanism for synchronization. Android, being built on the Linux kernel, directly utilizes this. The `bionic/libc/kernel/uapi/linux/futex.h` path indicates this is the kernel's API definition as seen by the userspace (uapi).

* **Example:**  Think about how threads synchronize in Java or C++ on Android. Mechanisms like `synchronized` blocks in Java or mutexes in C++ often rely on `futex` under the hood for efficient waiting and waking.

**5. Addressing Specific Questions (and Identifying Misconceptions in the Request):**

* **Functionality:**  Focus on the *purpose* of the defined elements. It's about defining constants and structures for interacting with the `futex` syscall.
* **Android Relationship:**  Provide concrete examples of where `futex` is used (thread synchronization, inter-process communication).
* **libc Function Implementation:**  **Crucially, state that this header *doesn't* contain the implementations.** Explain that the actual implementation is in the kernel, and libc provides wrappers (like the `syscall()` function) to invoke the kernel functionality. Mention the glibc wrapper function `futex()`.
* **Dynamic Linker:**  While this header isn't directly involved in dynamic linking, explain that synchronization primitives are essential for managing shared resources in dynamically linked libraries. Give an example of a race condition that could occur without proper synchronization. The SO layout example illustrates the shared nature of code and data. Explain that the dynamic linker itself might use `futex` internally for its own synchronization.
* **Logical Reasoning:**  Since it's a header, the "inputs" are the arguments passed to the *syscall*, and the "outputs" are the kernel's actions and return values. Give examples related to `FUTEX_WAIT` and `FUTEX_WAKE`.
* **Common Usage Errors:** Focus on the pitfalls of using low-level synchronization primitives, such as deadlocks, spurious wakeups, and incorrect flag usage.
* **Android Framework/NDK Path:**  Trace a typical path: Java `synchronized` -> ART VM internals -> potentially `pthread_mutex` in native code -> `futex` syscall. For the NDK, it's more direct: C/C++ synchronization primitives map to `futex`.
* **Frida Hooking:** Show how to hook the `syscall` function (since `futex` is a syscall) and filter for the `SYS_futex` number.

**6. Structuring the Answer:**

Organize the response clearly, addressing each part of the request. Use headings and bullet points for readability. Start with a general overview, then delve into specifics. Be explicit about the limitations of the header file (no implementation details).

**7. Refinement and Language:**

Use clear and concise language. Explain technical terms. Ensure the response is in Chinese, as requested. Double-check for accuracy and consistency. For instance, when talking about libc functions, clarify that you're referring to the *concept* and their relationship to the `futex` syscall, rather than implementations *within this specific header file*.

By following these steps, the resulting answer accurately reflects the content of the header file, its role in Android, and addresses the various aspects of the request, even when the request contains slight misconceptions about where certain functionality resides.
这个目录 `bionic/libc/kernel/uapi/linux/futex.handroid` 下的 `futex.h` 文件是 Linux 内核提供给用户空间的 futex (fast userspace mutex) 接口的头文件。这个文件定义了与 futex 系统调用相关的常量、宏和数据结构。由于它位于 `bionic` 的路径下，因此是 Android C 库 (Bionic) 中用于与 futex 机制交互的接口定义。

**它的功能:**

这个头文件定义了以下内容，用于用户空间程序使用 futex 系统调用：

1. **Futex 操作码 (Opcode):** 定义了 futex 系统调用可以执行的不同操作，例如等待、唤醒、重新排队等。
   - `FUTEX_WAIT`:  等待一个 futex 上的特定值。
   - `FUTEX_WAKE`: 唤醒等待在 futex 上的一个或多个线程。
   - `FUTEX_REQUEUE`:  唤醒一些线程并将其转移到另一个 futex 上等待。
   - `FUTEX_CMP_REQUEUE`: 只有当 futex 的当前值与预期值匹配时，才唤醒并重新排队线程。
   - `FUTEX_WAKE_OP`:  唤醒一些线程，并对另一个 futex 执行原子操作。
   - `FUTEX_LOCK_PI`, `FUTEX_UNLOCK_PI`, `FUTEX_TRYLOCK_PI`:  用于实现优先级继承锁 (Priority Inheritance Locks)。
   - `FUTEX_WAIT_BITSET`, `FUTEX_WAKE_BITSET`:  允许使用位掩码进行更精细的等待和唤醒控制。
   - `FUTEX_WAIT_REQUEUE_PI`, `FUTEX_CMP_REQUEUE_PI`, `FUTEX_LOCK_PI2`: 优先级继承锁的变种。

2. **Futex 标志 (Flags):**  定义了 futex 操作的各种修饰符。
   - `FUTEX_PRIVATE_FLAG`: 指示 futex 是否仅在进程内部可见（进程私有）还是跨进程共享。
   - `FUTEX_CLOCK_REALTIME`:  指示等待操作使用实时时钟，而不是单调时钟。

3. **Futex 结构体:** 定义了与 futex 操作相关的数据结构。
   - `struct futex_waitv`: 用于 `FUTEX_WAITV` (虽然这个宏在文件中没有直接定义，但结构体暗示了它的存在，可能在其他相关的头文件中)。它允许多个等待条件。
   - `struct robust_list`, `struct robust_list_head`:  用于实现健壮的互斥锁 (robust mutexes)。当持有互斥锁的线程异常终止时，其他等待线程可以被通知到。

4. **Futex 相关的常量和宏:**  定义了其他辅助常量，例如掩码、位定义等。
   - `FUTEX_CMD_MASK`: 用于提取 futex 命令中的操作码。
   - `FUTEX_WAITERS`, `FUTEX_OWNER_DIED`, `FUTEX_TID_MASK`:  用于检查 futex 的状态。
   - `FUTEX_BITSET_MATCH_ANY`: 用于匹配任何位。
   - `FUTEX_OP_*`:  定义了 `FUTEX_WAKE_OP` 中可以执行的原子操作类型。
   - `FUTEX_OP`:  一个宏，用于组合 `FUTEX_WAKE_OP` 的参数。

**与 Android 功能的关系举例:**

Futex 是 Android 系统中实现线程同步和互斥的关键机制。许多 Android 的高级并发原语，例如 Java 的 `synchronized` 关键字、`java.util.concurrent` 包中的锁和条件变量，以及 C/C++ 的 `pthread` 库中的互斥锁、条件变量等，在底层都可能使用 futex 来实现高效的等待和唤醒操作。

**举例说明:**

假设一个 Java 应用程序使用了 `synchronized` 关键字来保护一段临界区：

```java
public class Counter {
    private int count = 0;

    public synchronized void increment() {
        count++;
    }

    public int getCount() {
        return count;
    }
}
```

当多个线程同时调用 `increment()` 方法时，JVM 会使用底层的同步机制来确保只有一个线程可以进入 `synchronized` 代码块。在 Android 的 Dalvik 或 ART 虚拟机中，`synchronized` 关键字的实现很可能会涉及到使用 futex。

当一个线程尝试进入已被其他线程持有的 `synchronized` 块时，它会被阻塞。这个阻塞操作在底层很可能通过 `FUTEX_WAIT` 系统调用来实现。当持有锁的线程退出 `synchronized` 块时，它会唤醒等待的线程，这通常通过 `FUTEX_WAKE` 系统调用来实现。

**详细解释每一个 libc 函数的功能是如何实现的:**

需要注意的是，`futex.h` 并不是 libc 函数的实现，它只是定义了与 `futex` 系统调用交互所需的常量和数据结构。真正的 `futex` 功能实现在 Linux 内核中。

在 Bionic libc 中，会有一个名为 `futex` 的系统调用包装函数 (wrapper function)。这个函数负责将用户空间的请求转换为内核能够理解的格式，并调用底层的 `syscall` 指令来执行 `futex` 系统调用。

**libc 中 `futex` 函数的实现 (简化描述):**

```c
// 这是一个概念性的简化代码，并非 Bionic libc 的真实实现

#include <syscall.h>
#include <linux/futex.h> // 包含上面提供的 futex.h

int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3) {
  return syscall(__NR_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}
```

- `syscall(__NR_futex, ...)`:  `syscall` 是一个通用的系统调用函数，它接受系统调用号 (`__NR_futex`) 以及系统调用所需的参数。
- `__NR_futex`:  这是一个定义在其他头文件中的宏，表示 `futex` 系统调用的编号。
- `uaddr`:  指向用户空间 futex 变量的地址。
- `futex_op`:  指定要执行的 futex 操作，例如 `FUTEX_WAIT` 或 `FUTEX_WAKE`。
- `val`:  对于 `FUTEX_WAIT`，表示希望 futex 变量达到的值。
- `timeout`:  一个可选的超时时间结构体。
- `uaddr2`, `val3`:  用于某些 futex 操作，例如 `FUTEX_REQUEUE` 和 `FUTEX_WAKE_OP`。

当用户空间的程序调用 Bionic libc 提供的 `futex` 函数时，该函数会通过 `syscall` 指令陷入内核，内核中的 `futex` 系统调用处理程序会根据传入的参数执行相应的操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

Futex 本身主要是用于线程同步，虽然 dynamic linker (动态链接器) 在加载和链接共享库的过程中也需要进行同步操作，但 `futex.h` 文件本身并不直接涉及 dynamic linker 的链接过程。

然而，dynamic linker 在实现自己的同步机制时可能会使用 futex。例如，在加载共享库时，多个线程可能同时尝试加载同一个库，这时需要互斥锁来保护加载过程。

**SO 布局样本:**

假设有一个名为 `libexample.so` 的共享库：

```
libexample.so:
    .text         # 代码段
        function1:
            ...
        function2:
            ...
    .data         # 已初始化数据段
        global_var: 0
    .bss          # 未初始化数据段
        shared_buffer: (uninitialized)
    .dynamic      # 动态链接信息
        ...
    .symtab       # 符号表
        ...
    .strtab       # 字符串表
        ...
    .rel.dyn      # 动态重定位表
        ...
    .rel.plt      # PLT 重定位表
        ...
```

**链接的处理过程 (简化):**

1. **加载 SO:** 当程序需要使用 `libexample.so` 中的函数时，dynamic linker 会找到该 SO 文件并将其加载到内存中。
2. **解析 ELF 头:** dynamic linker 会解析 SO 文件的 ELF 头，获取各个段的加载地址和大小等信息。
3. **映射段:** dynamic linker 将 SO 文件的各个段 (如 `.text`, `.data`, `.bss`) 映射到进程的地址空间。
4. **符号解析:** dynamic linker 会查找 SO 文件的符号表 (`.symtab`)，以解析程序中引用的来自该 SO 的符号 (函数、全局变量)。
5. **重定位:**  由于 SO 文件在编译时并不知道最终的加载地址，因此需要进行重定位。dynamic linker 会根据重定位表 (`.rel.dyn`, `.rel.plt`) 修改代码和数据中的地址引用，使其指向正确的内存位置。
6. **同步:** 在加载和链接的过程中，dynamic linker 需要确保线程安全，例如在更新全局数据结构或执行重定位操作时，可能会使用互斥锁来防止竞争条件。这些互斥锁的底层实现可能使用了 futex。

**逻辑推理，假设输入与输出:**

假设一个场景：两个线程尝试同时增加一个受互斥锁保护的全局计数器。

**假设输入:**

- 线程 1 和线程 2 同时尝试获取同一个互斥锁。
- 互斥锁的底层实现使用了 futex。
- 假设互斥锁当前未被任何线程持有 (futex 变量的值表示未锁定状态，例如 0)。

**逻辑推理:**

1. **线程 1 尝试获取锁:** 线程 1 执行原子操作 (例如 compare-and-swap) 尝试将 futex 变量的值从 0 修改为 1 (表示锁定状态)。如果成功，线程 1 获得锁，并继续执行临界区代码。
2. **线程 2 尝试获取锁:** 线程 2 也执行相同的原子操作尝试获取锁。由于线程 1 已经成功获取锁，futex 变量的值为 1，线程 2 的原子操作会失败。
3. **线程 2 进入等待:** 线程 2 发现锁已被占用，会调用 `futex(..., FUTEX_WAIT, 1, ...)` 系统调用，在 futex 变量上等待值为 1 的状态变为其他值 (通常是 0，表示解锁)。线程 2 进入睡眠状态，释放 CPU。
4. **线程 1 释放锁:** 线程 1 完成临界区代码的执行，释放锁。它会执行原子操作将 futex 变量的值从 1 修改回 0，并调用 `futex(..., FUTEX_WAKE, 1, ...)` 系统调用，唤醒一个等待在该 futex 上的线程。
5. **线程 2 被唤醒:** 内核唤醒线程 2。
6. **线程 2 再次尝试获取锁:** 线程 2 被唤醒后，会再次尝试获取锁 (原子操作)。此时 futex 变量的值为 0，线程 2 可以成功获取锁。

**假设输出:**

- 最终，只有一个线程能够成功进入临界区并增加计数器，保证了数据的一致性。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **死锁 (Deadlock):** 两个或多个线程相互等待对方释放锁，导致所有线程都无法继续执行。
   - **例子:** 线程 A 持有锁 L1，尝试获取锁 L2；线程 B 持有锁 L2，尝试获取锁 L1。
   - **如何导致 futex 相关问题:** 如果 L1 和 L2 的底层实现都使用了 futex，那么死锁会导致相关 futex 上的线程一直处于等待状态。

2. **活锁 (Livelock):** 线程不断地尝试获取锁，但由于某些条件始终无法满足，导致它们不断重复尝试和退避，但没有实质性的进展。
   - **例子:** 两个线程在尝试获取同一个锁时，如果发现锁被占用，都选择退避一段时间后重试，但退避的时间不合适可能导致它们永远无法同时获得锁。

3. **条件竞争 (Race Condition):** 程序的行为取决于多个线程执行的相对顺序，导致不可预测的结果。
   - **例子:** 多个线程同时修改同一个共享变量，但没有使用适当的同步机制。
   - **如何导致 futex 相关问题:**  如果同步机制使用不当，例如忘记加锁或解锁，就可能导致条件竞争。

4. **忘记解锁:** 线程获取了互斥锁，但在某些情况下 (例如异常退出) 没有释放锁，导致其他线程永远无法获取该锁。
   - **与 `FUTEX_WAITERS` 相关:**  可以通过检查 futex 的 `FUTEX_WAITERS` 标志来诊断是否有线程在等待。

5. **Spurious Wakeup (虚假唤醒):** 线程在没有被明确唤醒的情况下从 `FUTEX_WAIT` 返回。这是可能发生的，应用程序需要处理这种情况，通常是在循环中检查等待条件。

6. **优先级反转 (Priority Inversion):** 低优先级线程持有高优先级线程需要的锁，导致高优先级线程被阻塞。 Futex 提供了优先级继承锁 (`FUTEX_LOCK_PI`) 来解决这个问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 Futex 的路径 (示例: Java `synchronized`)**

1. **Java 代码:** Android Framework 或应用程序使用 Java 的 `synchronized` 关键字或 `java.util.concurrent` 包中的锁。
   ```java
   public class MyClass {
       private final Object lock = new Object();
       public void myMethod() {
           synchronized (lock) {
               // 临界区代码
           }
       }
   }
   ```

2. **ART (Android Runtime):** 当 JVM 执行到 `synchronized` 块的入口时，ART 虚拟机需要获取与 `lock` 对象关联的监视器锁 (monitor lock)。

3. **Monitor 实现:** ART 的监视器锁通常在底层使用本地代码实现。获取锁的过程可能涉及原子操作 (例如 CAS) 和 futex 系统调用。

4. **`pthread` 互斥锁 (可能):** 在某些情况下，Java 的 `synchronized` 可能会映射到基于 `pthread` 互斥锁的实现。 `pthread_mutex_lock` 函数在底层会调用 `futex` 系统调用。

5. **Bionic libc:** `pthread_mutex_lock` 是 Bionic libc 提供的函数，它会调用 `syscall` 来执行 `futex` 系统调用。

6. **Linux Kernel:** 内核接收到 `futex` 系统调用，根据操作码执行相应的操作 (例如，如果锁已被占用，则将当前线程放入等待队列)。

**NDK 到 Futex 的路径 (示例: C++ `std::mutex`)**

1. **NDK 代码:** NDK 开发人员使用 C++ 的 `std::mutex` 或 `pthread` 库提供的互斥锁。
   ```cpp
   #include <mutex>
   std::mutex m;
   void myNativeFunction() {
       std::lock_guard<std::mutex> lock(m);
       // 临界区代码
   }
   ```

2. **`std::mutex` 实现:** `std::mutex` 通常在底层使用 `pthread_mutex_t` 来实现。

3. **`pthread` 库:**  NDK 中使用的 `pthread` 库是 Bionic libc 的一部分。

4. **Bionic libc:** 调用 `pthread_mutex_lock` 函数，最终调用 `futex` 系统调用。

5. **Linux Kernel:**  同上。

**Frida Hook 示例:**

可以使用 Frida Hook `syscall` 函数，并过滤出 `futex` 系统调用来观察其行为。

```javascript
// frida 脚本

function hook_futex() {
    const syscallPtr = Module.getExportByName(null, "syscall");
    Interceptor.attach(syscallPtr, {
        onEnter: function(args) {
            const syscallNumber = args[0].toInt32();
            const SYS_futex = 202; // __NR_futex 的值，可能因架构而异，需要确认

            if (syscallNumber === SYS_futex) {
                console.log("Futex syscall detected!");
                console.log("  Operation:", args[1].toInt32()); // futex_op
                console.log("  Address:", args[2]);          // uaddr
                console.log("  Value:", args[3].toInt32());    // val
                // ... 可以打印更多参数
            }
        }
    });
}

setImmediate(hook_futex);
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_futex.js`。
2. 运行 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l hook_futex.js --no-pause
   ```
   或者连接到正在运行的进程：
   ```bash
   frida -U <进程名或 PID> -l hook_futex.js
   ```

当目标应用程序执行涉及 futex 的操作时，Frida 会拦截 `syscall` 函数，并打印出 `futex` 系统调用的相关信息，例如操作类型、futex 地址和期望值等。这可以帮助调试同步相关的行为。

**注意:** `SYS_futex` 的值可能因 Android 版本和 CPU 架构而异。你可能需要查找目标设备的 `unistd_32.h` 或 `unistd_64.h` 文件来确定正确的系统调用号。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/futex.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_FUTEX_H
#define _UAPI_LINUX_FUTEX_H
#include <linux/compiler.h>
#include <linux/types.h>
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_LOCK_PI2 13
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_CMD_MASK ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_REQUEUE_PRIVATE (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_OP_PRIVATE (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#define FUTEX_LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_LOCK_PI2_PRIVATE (FUTEX_LOCK_PI2 | FUTEX_PRIVATE_FLAG)
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX2_SIZE_U8 0x00
#define FUTEX2_SIZE_U16 0x01
#define FUTEX2_SIZE_U32 0x02
#define FUTEX2_SIZE_U64 0x03
#define FUTEX2_NUMA 0x04
#define FUTEX2_PRIVATE FUTEX_PRIVATE_FLAG
#define FUTEX2_SIZE_MASK 0x03
#define FUTEX_32 FUTEX2_SIZE_U32
#define FUTEX_WAITV_MAX 128
struct futex_waitv {
  __u64 val;
  __u64 uaddr;
  __u32 flags;
  __u32 __reserved;
};
struct robust_list {
  struct robust_list  * next;
};
struct robust_list_head {
  struct robust_list list;
  long futex_offset;
  struct robust_list  * list_op_pending;
};
#define FUTEX_WAITERS 0x80000000
#define FUTEX_OWNER_DIED 0x40000000
#define FUTEX_TID_MASK 0x3fffffff
#define ROBUST_LIST_LIMIT 2048
#define FUTEX_BITSET_MATCH_ANY 0xffffffff
#define FUTEX_OP_SET 0
#define FUTEX_OP_ADD 1
#define FUTEX_OP_OR 2
#define FUTEX_OP_ANDN 3
#define FUTEX_OP_XOR 4
#define FUTEX_OP_OPARG_SHIFT 8
#define FUTEX_OP_CMP_EQ 0
#define FUTEX_OP_CMP_NE 1
#define FUTEX_OP_CMP_LT 2
#define FUTEX_OP_CMP_LE 3
#define FUTEX_OP_CMP_GT 4
#define FUTEX_OP_CMP_GE 5
#define FUTEX_OP(op,oparg,cmp,cmparg) (((op & 0xf) << 28) | ((cmp & 0xf) << 24) | ((oparg & 0xfff) << 12) | (cmparg & 0xfff))
#endif
```