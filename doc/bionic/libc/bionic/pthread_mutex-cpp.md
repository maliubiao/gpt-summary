Response:
Let's break down the thought process for summarizing the provided C++ code snippet.

1. **Identify the Core Purpose:** The first thing to do is read the initial comments and `#include` directives. The comments explicitly state this is the `pthread_mutex.cpp` file for Android's Bionic library. This immediately tells us the file deals with mutexes, a fundamental synchronization primitive in multithreaded programming. The includes (`pthread.h`, `errno.h`, etc.) confirm this and hint at the functionality provided.

2. **High-Level Structure Scan:** Quickly skim through the code, noting the defined functions (starting with `pthread_mutexattr_`). This immediately suggests the code handles mutex attributes as well as the mutexes themselves.

3. **Categorize Functionality:**  As you skim, try to group related functions. You'll see blocks of code for:
    * Mutex attribute initialization, destruction, getting/setting type, getting/setting process-shared status, getting/setting protocol.
    *  An internal `PIMutex` structure and related functions (`PIMutexTryLock`, `PIMutexTimedLock`, `PIMutexUnlock`, `PIMutexDestroy`). The "PI" likely stands for Priority Inheritance.
    *  Conditional compilation blocks (`#if !defined(__LP64__)`) suggesting different implementations for 32-bit and 64-bit architectures. The `PIMutexAllocator` namespace is a key element within the 32-bit conditional.
    *  Macros defining bit fields and states related to mutex implementation (e.g., `MUTEX_STATE_MASK`, `MUTEX_TYPE_MASK`).
    *  The `pthread_mutex_internal_t` structure, which appears to be the internal representation of a `pthread_mutex_t`.
    *  The core `pthread_mutex_init`, `pthread_mutex_lock`, `pthread_mutex_trylock`, `pthread_mutex_timedlock`, and `pthread_mutex_unlock` functions.
    *  A `NonPI` namespace encapsulating logic for non-priority-inheritance mutexes.

4. **Focus on Key Concepts:**  Identify the major concepts being implemented:
    * **Mutex Attributes:**  How mutexes are configured (type, shared, protocol).
    * **Priority Inheritance Mutexes:** A special type of mutex to prevent priority inversion.
    * **Regular Mutexes:** The standard mutex implementation.
    * **Locking and Unlocking:** The core operations of a mutex.
    * **TryLock and TimedLock:** Non-blocking and time-limited locking attempts.
    * **Internal State Management:** How the mutex keeps track of its lock status, owner, etc. (using bitfields and atomic operations).
    * **Architecture-Specific Implementations:**  The 32-bit vs. 64-bit differences, particularly the `PIMutexAllocator`.

5. **Synthesize a Summary:**  Combine the identified categories and concepts into a concise summary. Start with the most general description and then become more specific.

    * *Initial Thought:* "This file implements mutexes."  (Too simple)
    * *Refinement 1:* "This file implements POSIX mutexes for Android's Bionic library, including attribute handling and lock/unlock operations." (Better)
    * *Refinement 2 (Adding detail):* "This file provides the implementation for POSIX mutex functions in Android's Bionic library. It handles mutex attributes (type, shared status, priority inheritance), and implements different types of mutexes including normal, recursive, error-checking, and priority inheritance mutexes. It manages the internal state of mutexes, including locking, unlocking, and handling contention. The code also includes architecture-specific optimizations and considerations, particularly for 32-bit systems." (Getting there)
    * *Final Refinement (Adding more key details and structure):*  Emphasize the separation of concerns and the different mutex types more clearly. Mention the internal representation.

6. **Review and Refine:** Read the summary to ensure it's accurate, comprehensive (given the first part limitation), and easy to understand. Check for any missing key features or inaccurate statements. Ensure the language is clear and avoids jargon where possible. For example, explicitly mentioning the use of atomic operations is important.

By following these steps, we move from a basic understanding of the file's location to a more detailed and structured overview of its functionality. The process involves identification, categorization, concept extraction, and iterative refinement of the summary. The awareness of the "Part 1" constraint helps to focus on the core functionality related to mutex initialization, attribute handling, and the basic locking mechanisms, rather than going deep into the lock/unlock implementation details, which likely come in Part 2.
这是目录为 `bionic/libc/bionic/pthread_mutex.cpp` 的 Android Bionic 源代码文件，它主要负责实现 POSIX 线程互斥锁（mutex）的相关功能。

**功能归纳:**

总而言之，该文件的主要功能是提供 Android Bionic 库中线程互斥锁的实现，包括属性管理、初始化、销毁、加锁、解锁以及尝试加锁等操作。它支持不同类型的互斥锁，并针对性能和特定场景（如进程共享和优先级继承）进行了考虑。

**详细功能列表:**

1. **互斥锁属性管理:**
   - 提供函数用于初始化、销毁、获取和设置互斥锁的属性 (`pthread_mutexattr_init`, `pthread_mutexattr_destroy`, `pthread_mutexattr_gettype`, `pthread_mutexattr_settype`, `pthread_mutexattr_getpshared`, `pthread_mutexattr_setpshared`, `pthread_mutexattr_getprotocol`, `pthread_mutexattr_setprotocol`)。
   - 定义了互斥锁属性的内部表示，包括类型、进程共享标志和协议类型。

2. **互斥锁初始化与销毁:**
   - 提供函数用于初始化互斥锁对象 (`pthread_mutex_init`)，可以指定互斥锁的属性。
   - 提供函数用于销毁互斥锁对象 (`pthread_mutex_destroy`)。

3. **互斥锁加锁操作:**
   - 提供阻塞式加锁函数 (`pthread_mutex_lock`)，当互斥锁被其他线程持有的时候，调用线程会进入等待状态。
   - 提供非阻塞式加锁函数 (`pthread_mutex_trylock`)，如果互斥锁当前未被持有，则加锁成功并立即返回；否则立即返回错误。
   - 提供带有超时功能的加锁函数 (`pthread_mutex_timedlock`)，如果在指定的时间内未能成功获取锁，则返回错误。

4. **互斥锁解锁操作:**
   - 提供解锁函数 (`pthread_mutex_unlock`)，释放互斥锁的持有权。

5. **支持多种互斥锁类型:**
   - **普通锁 (PTHREAD_MUTEX_NORMAL):**  基本的互斥锁，不允许同一线程重复加锁，否则会导致死锁。
   - **递归锁 (PTHREAD_MUTEX_RECURSIVE):** 允许同一线程多次加锁，每次加锁都需要对应一次解锁。
   - **错误检查锁 (PTHREAD_MUTEX_ERRORCHECK):**  与普通锁类似，但会进行额外的错误检查，例如检测同一线程重复加锁的情况，并返回 `EDEADLK` 错误。
   - **优先级继承锁 (Priority Inheritance Mutex):** 一种特殊的互斥锁，用于解决优先级反转问题。当低优先级线程持有该锁时，如果高优先级线程尝试获取该锁而被阻塞，低优先级线程的优先级会被临时提升到高优先级线程的优先级，以尽快释放锁。

6. **进程共享互斥锁:**
   - 支持进程间共享的互斥锁 (`PTHREAD_PROCESS_SHARED`)，允许不同进程的线程通过共享内存来同步。

7. **内部状态管理:**
   - 使用原子操作 (`std::atomic`) 来管理互斥锁的内部状态，保证线程安全。
   - 定义了互斥锁状态的位域表示，包括锁状态（解锁、已锁定无等待者、已锁定有等待者）、计数器（用于递归锁）和类型等信息。

8. **优先级继承互斥锁的特殊处理:**
   - 使用单独的 `PIMutex` 结构体来管理优先级继承互斥锁的状态。
   - 在 32 位系统上，由于 `pthread_mutex_t` 的大小限制，优先级继承互斥锁的状态信息需要通过 `PIMutexAllocator` 进行动态分配和管理。

9. **与 `futex` 系统调用的交互:**
   - 互斥锁的底层实现依赖于 Linux 的 `futex` (fast userspace mutexes) 系统调用来实现线程的等待和唤醒。

**与 Android 功能的关系举例说明:**

- **SurfaceFlinger 和 AudioFlinger 使用共享互斥锁:** 代码注释中提到，`surfaceflinger` 和 `audioflinger` 这两个核心的 Android 系统服务使用了进程共享的互斥锁，这允许它们在不同的进程之间同步对共享资源的访问，例如帧缓冲区和音频缓冲区。
- **Android Framework 中多线程组件的同步:** Android Framework 中很多组件都是多线程的，例如 ActivityManagerService、WindowManagerService 等。这些组件内部会使用互斥锁来保护共享数据结构，防止数据竞争和保证数据的一致性。
- **NDK 开发中线程同步:**  NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的 native 代码。开发者可以使用 `pthread` 库提供的互斥锁功能来实现 native 代码中的线程同步。

**libc 函数的功能实现解释 (部分):**

由于这是第一部分，我们主要关注属性管理和初始化，以及部分加锁的初步实现。

- **`pthread_mutexattr_init(pthread_mutexattr_t *attr)`:**
    - 功能：初始化互斥锁属性对象。
    - 实现：将传入的 `attr` 指向的内存区域设置为默认值 `PTHREAD_MUTEX_DEFAULT`。在代码中，`PTHREAD_MUTEX_DEFAULT` 实际上是一个整数，其低 4 位用于表示互斥锁类型，默认通常是 `PTHREAD_MUTEX_NORMAL`。

- **`pthread_mutexattr_destroy(pthread_mutexattr_t *attr)`:**
    - 功能：销毁互斥锁属性对象。
    - 实现：将传入的 `attr` 指向的内存区域设置为 `-1`，表示该属性对象不再有效。这并不会释放任何资源，因为互斥锁属性通常是值类型。

- **`pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type_p)`:**
    - 功能：获取互斥锁属性对象的类型。
    - 实现：通过位运算 `(*attr & MUTEXATTR_TYPE_MASK)` 从属性值中提取出类型信息，并检查其有效性。然后将提取出的类型值存储到 `type_p` 指向的内存。

- **`pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)`:**
    - 功能：设置互斥锁属性对象的类型。
    - 实现：首先检查传入的 `type` 是否是有效的互斥锁类型。然后使用位运算 `(*attr & ~MUTEXATTR_TYPE_MASK) | type` 来更新属性值，保留其他属性位不变，只修改类型相关的位。

- **`pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int  pshared)`:**
    - 功能：设置互斥锁属性对象的进程共享属性。
    - 实现：根据传入的 `pshared` 值（`PTHREAD_PROCESS_PRIVATE` 或 `PTHREAD_PROCESS_SHARED`），使用位运算设置或清除 `MUTEXATTR_SHARED_MASK` 位。

- **`pthread_mutex_init(pthread_mutex_t* mutex_interface, const pthread_mutexattr_t* attr)`:**
    - 功能：初始化互斥锁对象。
    - 实现：
        1. 将传入的 `mutex_interface` 指针转换为内部表示 `pthread_mutex_internal_t* mutex`。
        2. 将 `mutex` 指向的内存区域清零。
        3. 如果 `attr` 为空，则设置为默认的普通锁类型。
        4. 如果 `attr` 不为空，则根据属性值设置 `mutex` 的内部状态，包括是否进程共享以及互斥锁类型。
        5. 对于优先级继承锁，在 32 位系统上，会调用 `PIMutexAllocator::AllocId()` 分配一个 ID 来管理其状态。

- **`PIMutexTryLock(PIMutex& mutex)`:**
    - 功能：尝试获取优先级继承互斥锁。
    - 实现：
        1. 获取当前线程 ID (`tid`).
        2. 使用原子操作 `atomic_compare_exchange_strong_explicit` 尝试将 `mutex.owner_tid` 从 0 修改为当前线程 ID。这是最常见的情况，如果成功则立即返回 0。
        3. 如果当前线程已经持有该锁（递归锁的情况），根据互斥锁类型进行处理，例如对于普通锁返回 `EBUSY`，对于错误检查锁返回 `EDEADLK`，对于递归锁增加计数器。
        4. 如果互斥锁被其他线程持有，返回 `EBUSY`。

**Dynamic Linker 功能和 SO 布局 (目前代码片段中未直接涉及):**

目前的代码片段主要关注互斥锁的实现逻辑，没有直接涉及到 dynamic linker 的功能。Dynamic linker (如 `linker64` 或 `linker`) 负责在程序启动或动态加载共享库时解析和链接符号。互斥锁的实现会被编译成 libpthread.so 共享库，当应用程序需要使用互斥锁时，dynamic linker 会将对 `pthread_mutex_lock` 等函数的调用链接到 libpthread.so 中的对应实现。

**假设输入与输出 (部分):**

- **假设输入 `pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE)`:**
    - 输出：如果 `attr` 是一个有效的互斥锁属性对象，且操作成功，则返回 0，并且 `attr` 的内部表示会更新，使其类型为递归锁。

- **假设输入 `pthread_mutex_init(&mutex, NULL)`:**
    - 输出：如果 `mutex` 是一个有效的 `pthread_mutex_t` 对象，且操作成功，则返回 0，并且 `mutex` 被初始化为普通锁类型，未被任何线程持有。

- **假设输入 `pthread_mutex_lock(&mutex)`，且 `mutex` 当前未被持有:**
    - 输出：调用线程成功获取锁，函数返回 0。

- **假设输入 `pthread_mutex_lock(&mutex)`，且 `mutex` 当前已被其他线程持有:**
    - 输出：调用线程进入阻塞等待状态，直到持有锁的线程解锁。

**用户或编程常见的使用错误举例说明:**

- **死锁 (Deadlock):**
    - 错误示例：线程 A 持有锁 1，尝试获取锁 2；线程 B 持有锁 2，尝试获取锁 1。
    ```c++
    // 线程 A
    pthread_mutex_lock(&mutex1);
    pthread_mutex_lock(&mutex2); // 线程 A 等待 mutex2
    // ...
    pthread_mutex_unlock(&mutex2);
    pthread_mutex_unlock(&mutex1);

    // 线程 B
    pthread_mutex_lock(&mutex2);
    pthread_mutex_lock(&mutex1); // 线程 B 等待 mutex1
    // ...
    pthread_mutex_unlock(&mutex1);
    pthread_mutex_unlock(&mutex2);
    ```
    - 说明：两个或多个线程相互等待对方释放资源，导致所有线程都无法继续执行。

- **重复解锁 (Double Unlock):**
    - 错误示例：
    ```c++
    pthread_mutex_lock(&mutex);
    // ...
    pthread_mutex_unlock(&mutex);
    pthread_mutex_unlock(&mutex); // 错误：重复解锁
    ```
    - 说明：对同一个互斥锁解锁两次或多次，可能导致未定义的行为，例如破坏互斥锁的内部状态或唤醒错误的线程。

- **在未加锁的情况下解锁:**
    - 错误示例：
    ```c++
    pthread_mutex_unlock(&mutex); // 错误：未加锁就解锁
    ```
    - 说明：尝试解锁一个当前未被任何线程持有的互斥锁，会导致未定义的行为。

- **忘记解锁:**
    - 错误示例：
    ```c++
    void some_function() {
        pthread_mutex_lock(&mutex);
        // ... 做一些操作 ...
        // 忘记解锁
    }
    ```
    - 说明：如果一个线程加锁后忘记解锁，会导致其他线程永远无法获取该锁，造成程序卡死。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例调试步骤 (简要说明):**

1. **Android Framework 使用:**
   - Android Framework 中的 Java 代码通常通过 JNI (Java Native Interface) 调用到底层的 native 代码。
   - 例如，`synchronized` 关键字在某些情况下会映射到 native 的互斥锁实现。
   - Framework 层的线程管理和同步机制最终会调用到 Bionic 库提供的 `pthread` 函数。

2. **NDK 开发使用:**
   - NDK 开发者可以直接在 C/C++ 代码中使用 `pthread` 库提供的互斥锁函数。
   - 当应用运行到这些互斥锁操作时，会调用到 `bionic/libc/bionic/pthread_mutex.cpp` 中的实现。

3. **Frida Hook 示例调试步骤:**

   可以使用 Frida 来 hook `pthread_mutex_lock` 函数，观察其调用过程和参数。

   ```python
   import frida, sys

   package_name = "your.app.package.name"  # 替换为你的应用包名

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {}: {}".format(message['payload']['tag'], message['payload']['content']))
       else:
           print(message)

   try:
       session = frida.attach(package_name)
   except frida.ProcessNotFoundError:
       print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
       sys.exit()

   script_code = """
   // 获取 pthread_mutex_lock 函数的地址
   var pthread_mutex_lock_ptr = Module.findExportByName("libpthread.so", "pthread_mutex_lock");

   if (pthread_mutex_lock_ptr) {
       Interceptor.attach(pthread_mutex_lock_ptr, {
           onEnter: function(args) {
               var mutex_ptr = args[0];
               console.log("[pthread_mutex_lock] 调用, mutex 地址:", mutex_ptr);
               // 你可以在这里读取 mutex 指向的内存，查看其内部状态
               // 例如： console.log("Mutex state:", Memory.readU16(mutex_ptr));
           },
           onLeave: function(retval) {
               console.log("[pthread_mutex_lock] 返回值:", retval);
           }
       });
       send({"tag": "Frida", "content": "pthread_mutex_lock hook 成功"});
   } else {
       send({"tag": "Frida", "content": "pthread_mutex_lock hook 失败，函数未找到"});
   }
   """

   script = session.create_script(script_code)
   script.on('message', on_message)
   script.load()
   sys.stdin.read()
   ```

   **说明:**

   - 上述 Frida 脚本会尝试 hook `libpthread.so` 中的 `pthread_mutex_lock` 函数。
   - `onEnter` 函数会在 `pthread_mutex_lock` 被调用时执行，你可以访问函数的参数（例如互斥锁的地址）。
   - `onLeave` 函数会在 `pthread_mutex_lock` 返回时执行，你可以查看返回值。
   - 你可以根据需要修改脚本来 hook 其他互斥锁相关的函数，并读取互斥锁内存来分析其状态变化。

这部分内容是对 `bionic/libc/bionic/pthread_mutex.cpp` 文件功能的归纳总结，涵盖了其提供的核心互斥锁功能以及与 Android 系统和 NDK 开发的关联。后续部分会深入探讨更细节的实现和机制。

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_mutex.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <pthread.h>

#include <errno.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pthread_internal.h"

#include "private/bionic_constants.h"
#include "private/bionic_fortify.h"
#include "private/bionic_futex.h"
#include "private/bionic_systrace.h"
#include "private/bionic_time_conversions.h"
#include "private/bionic_tls.h"

/* a mutex attribute holds the following fields
 *
 * bits:     name       description
 * 0-3       type       type of mutex
 * 4         shared     process-shared flag
 * 5         protocol   whether it is a priority inherit mutex.
 */
#define  MUTEXATTR_TYPE_MASK   0x000f
#define  MUTEXATTR_SHARED_MASK 0x0010
#define MUTEXATTR_PROTOCOL_MASK 0x0020

#define MUTEXATTR_PROTOCOL_SHIFT 5

int pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
    *attr = PTHREAD_MUTEX_DEFAULT;
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
    *attr = -1;
    return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type_p)
{
    int type = (*attr & MUTEXATTR_TYPE_MASK);

    if (type < PTHREAD_MUTEX_NORMAL || type > PTHREAD_MUTEX_ERRORCHECK) {
        return EINVAL;
    }

    *type_p = type;
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)
{
    if (type < PTHREAD_MUTEX_NORMAL || type > PTHREAD_MUTEX_ERRORCHECK ) {
        return EINVAL;
    }

    *attr = (*attr & ~MUTEXATTR_TYPE_MASK) | type;
    return 0;
}

/* process-shared mutexes are not supported at the moment */

int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int  pshared)
{
    switch (pshared) {
    case PTHREAD_PROCESS_PRIVATE:
        *attr &= ~MUTEXATTR_SHARED_MASK;
        return 0;

    case PTHREAD_PROCESS_SHARED:
        /* our current implementation of pthread actually supports shared
         * mutexes but won't cleanup if a process dies with the mutex held.
         * Nevertheless, it's better than nothing. Shared mutexes are used
         * by surfaceflinger and audioflinger.
         */
        *attr |= MUTEXATTR_SHARED_MASK;
        return 0;
    }
    return EINVAL;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t* attr, int* pshared) {
    *pshared = (*attr & MUTEXATTR_SHARED_MASK) ? PTHREAD_PROCESS_SHARED : PTHREAD_PROCESS_PRIVATE;
    return 0;
}

int pthread_mutexattr_setprotocol(pthread_mutexattr_t* attr, int protocol) {
    if (protocol != PTHREAD_PRIO_NONE && protocol != PTHREAD_PRIO_INHERIT) {
        return EINVAL;
    }
    *attr = (*attr & ~MUTEXATTR_PROTOCOL_MASK) | (protocol << MUTEXATTR_PROTOCOL_SHIFT);
    return 0;
}

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t* attr, int* protocol) {
    *protocol = (*attr & MUTEXATTR_PROTOCOL_MASK) >> MUTEXATTR_PROTOCOL_SHIFT;
    return 0;
}

// Priority Inheritance mutex implementation
struct PIMutex {
  // mutex type, can be 0 (normal), 1 (recursive), 2 (errorcheck), constant during lifetime
  uint8_t type;
  // process-shared flag, constant during lifetime
  bool shared;
  // <number of times a thread holding a recursive PI mutex> - 1
  uint16_t counter;
  // owner_tid is read/written by both userspace code and kernel code. It includes three fields:
  // FUTEX_WAITERS, FUTEX_OWNER_DIED and FUTEX_TID_MASK.
  atomic_int owner_tid;
};

static inline __always_inline int PIMutexTryLock(PIMutex& mutex) {
    pid_t tid = __get_thread()->tid;
    // Handle common case first.
    int old_owner = 0;
    if (__predict_true(atomic_compare_exchange_strong_explicit(&mutex.owner_tid,
                                                               &old_owner, tid,
                                                               memory_order_acquire,
                                                               memory_order_relaxed))) {
        return 0;
    }
    if (tid == (old_owner & FUTEX_TID_MASK)) {
        // We already own this mutex.
        if (mutex.type == PTHREAD_MUTEX_NORMAL) {
            return EBUSY;
        }
        if (mutex.type == PTHREAD_MUTEX_ERRORCHECK) {
            return EDEADLK;
        }
        if (mutex.counter == 0xffff) {
            return EAGAIN;
        }
        mutex.counter++;
        return 0;
    }
    return EBUSY;
}

// Inlining this function in pthread_mutex_lock() adds the cost of stack frame instructions on
// ARM/ARM64, which increases at most 20 percent overhead. So make it noinline.
static int  __attribute__((noinline)) PIMutexTimedLock(PIMutex& mutex,
                                                       bool use_realtime_clock,
                                                       const timespec* abs_timeout) {
    int ret = PIMutexTryLock(mutex);
    if (__predict_true(ret == 0)) {
        return 0;
    }
    if (ret == EBUSY) {
        char trace_msg[64];
        const pid_t owner = atomic_load_explicit(&mutex.owner_tid, memory_order_relaxed)
                & FUTEX_TID_MASK;
        snprintf(trace_msg, sizeof(trace_msg),
                 "Contending for pthread mutex owned by tid: %d", owner);
        ScopedTrace trace(trace_msg);
        ret = -__futex_pi_lock_ex(&mutex.owner_tid, mutex.shared, use_realtime_clock, abs_timeout);
    }
    return ret;
}

static int PIMutexUnlock(PIMutex& mutex) {
    pid_t tid = __get_thread()->tid;
    int old_owner = tid;
    // Handle common case first.
    if (__predict_true(mutex.type == PTHREAD_MUTEX_NORMAL)) {
        if (__predict_true(atomic_compare_exchange_strong_explicit(&mutex.owner_tid,
                                                                   &old_owner, 0,
                                                                   memory_order_release,
                                                                   memory_order_relaxed))) {
            return 0;
        }
    } else {
        old_owner = atomic_load_explicit(&mutex.owner_tid, memory_order_relaxed);
    }

    if (tid != (old_owner & FUTEX_TID_MASK)) {
        // The mutex can only be unlocked by the thread who owns it.
        return EPERM;
    }
    if (mutex.type == PTHREAD_MUTEX_RECURSIVE) {
        if (mutex.counter != 0u) {
            --mutex.counter;
            return 0;
        }
    }
    if (old_owner == tid) {
        // No thread is waiting.
        if (__predict_true(atomic_compare_exchange_strong_explicit(&mutex.owner_tid,
                                                                   &old_owner, 0,
                                                                   memory_order_release,
                                                                   memory_order_relaxed))) {
            return 0;
        }
    }
    return -__futex_pi_unlock(&mutex.owner_tid, mutex.shared);
}

static int PIMutexDestroy(PIMutex& mutex) {
    // The mutex should be in unlocked state (owner_tid == 0) when destroyed.
    // Store 0xffffffff to make the mutex unusable.
    int old_owner = 0;
    if (atomic_compare_exchange_strong_explicit(&mutex.owner_tid, &old_owner, 0xffffffff,
                                                memory_order_relaxed, memory_order_relaxed)) {
        return 0;
    }
    return EBUSY;
}

#if !defined(__LP64__)

namespace PIMutexAllocator {
// pthread_mutex_t has only 4 bytes in 32-bit programs, which are not enough to hold PIMutex.
// So we use malloc to allocate PIMutexes and use 16-bit of pthread_mutex_t as indexes to find
// the allocated PIMutexes. This allows at most 65536 PI mutexes.
// When calling operations like pthread_mutex_lock/unlock, the 16-bit index is mapped to the
// corresponding PIMutex. To make the map operation fast, we use a lockless mapping method:
//   Once a PIMutex is allocated, all the data used to map index to the PIMutex isn't changed until
//   it is destroyed.
// Below are the data structures:
//   // struct Node contains a PIMutex.
//   typedef Node NodeArray[256];
//   typedef NodeArray* NodeArrayP;
//   NodeArrayP nodes[256];
//
// A 16-bit index is mapped to Node as below:
//   (*nodes[index >> 8])[index & 0xff]
//
// Also use a free list to allow O(1) finding recycled PIMutexes.

union Node {
    PIMutex mutex;
    int next_free_id;  // If not -1, refer to the next node in the free PIMutex list.
};
typedef Node NodeArray[256];
typedef NodeArray* NodeArrayP;

// lock_ protects below items.
static Lock lock;
static NodeArrayP* nodes;
static int next_to_alloc_id;
static int first_free_id = -1;  // If not -1, refer to the first node in the free PIMutex list.

static inline __always_inline Node& IdToNode(int id) {
    return (*nodes[id >> 8])[id & 0xff];
}

static inline __always_inline PIMutex& IdToPIMutex(int id) {
    return IdToNode(id).mutex;
}

static int AllocIdLocked() {
    if (first_free_id != -1) {
        int result = first_free_id;
        first_free_id = IdToNode(result).next_free_id;
        return result;
    }
    if (next_to_alloc_id >= 0x10000) {
        return -1;
    }
    int array_pos = next_to_alloc_id >> 8;
    int node_pos = next_to_alloc_id & 0xff;
    if (node_pos == 0) {
        if (array_pos == 0) {
            nodes = static_cast<NodeArray**>(calloc(256, sizeof(NodeArray*)));
            if (nodes == nullptr) {
                return -1;
            }
        }
        nodes[array_pos] = static_cast<NodeArray*>(malloc(sizeof(NodeArray)));
        if (nodes[array_pos] == nullptr) {
            return -1;
        }
    }
    return next_to_alloc_id++;
}

// If succeed, return an id referring to a PIMutex, otherwise return -1.
// A valid id is in range [0, 0xffff].
static int AllocId() {
    lock.lock();
    int result = AllocIdLocked();
    lock.unlock();
    if (result != -1) {
        memset(&IdToPIMutex(result), 0, sizeof(PIMutex));
    }
    return result;
}

static void FreeId(int id) {
    lock.lock();
    IdToNode(id).next_free_id = first_free_id;
    first_free_id = id;
    lock.unlock();
}

}  // namespace PIMutexAllocator

#endif  // !defined(__LP64__)


/* Convenience macro, creates a mask of 'bits' bits that starts from
 * the 'shift'-th least significant bit in a 32-bit word.
 *
 * Examples: FIELD_MASK(0,4)  -> 0xf
 *           FIELD_MASK(16,9) -> 0x1ff0000
 */
#define  FIELD_MASK(shift,bits)           (((1 << (bits))-1) << (shift))

/* This one is used to create a bit pattern from a given field value */
#define  FIELD_TO_BITS(val,shift,bits)    (((val) & ((1 << (bits))-1)) << (shift))

/* And this one does the opposite, i.e. extract a field's value from a bit pattern */
#define  FIELD_FROM_BITS(val,shift,bits)  (((val) >> (shift)) & ((1 << (bits))-1))

/* Convenience macros.
 *
 * These are used to form or modify the bit pattern of a given mutex value
 */

/* Mutex state:
 *
 * 0 for unlocked
 * 1 for locked, no waiters
 * 2 for locked, maybe waiters
 */
#define  MUTEX_STATE_SHIFT      0
#define  MUTEX_STATE_LEN        2

#define  MUTEX_STATE_MASK           FIELD_MASK(MUTEX_STATE_SHIFT, MUTEX_STATE_LEN)
#define  MUTEX_STATE_FROM_BITS(v)   FIELD_FROM_BITS(v, MUTEX_STATE_SHIFT, MUTEX_STATE_LEN)
#define  MUTEX_STATE_TO_BITS(v)     FIELD_TO_BITS(v, MUTEX_STATE_SHIFT, MUTEX_STATE_LEN)

#define  MUTEX_STATE_UNLOCKED            0   /* must be 0 to match PTHREAD_MUTEX_INITIALIZER */
#define  MUTEX_STATE_LOCKED_UNCONTENDED  1   /* must be 1 due to atomic dec in unlock operation */
#define  MUTEX_STATE_LOCKED_CONTENDED    2   /* must be 1 + LOCKED_UNCONTENDED due to atomic dec */

#define  MUTEX_STATE_BITS_UNLOCKED            MUTEX_STATE_TO_BITS(MUTEX_STATE_UNLOCKED)
#define  MUTEX_STATE_BITS_LOCKED_UNCONTENDED  MUTEX_STATE_TO_BITS(MUTEX_STATE_LOCKED_UNCONTENDED)
#define  MUTEX_STATE_BITS_LOCKED_CONTENDED    MUTEX_STATE_TO_BITS(MUTEX_STATE_LOCKED_CONTENDED)

// Return true iff the mutex is unlocked.
#define MUTEX_STATE_BITS_IS_UNLOCKED(v) (((v) & MUTEX_STATE_MASK) == MUTEX_STATE_BITS_UNLOCKED)

// Return true iff the mutex is locked with no waiters.
#define MUTEX_STATE_BITS_IS_LOCKED_UNCONTENDED(v)  (((v) & MUTEX_STATE_MASK) == MUTEX_STATE_BITS_LOCKED_UNCONTENDED)

// return true iff the mutex is locked with maybe waiters.
#define MUTEX_STATE_BITS_IS_LOCKED_CONTENDED(v)   (((v) & MUTEX_STATE_MASK) == MUTEX_STATE_BITS_LOCKED_CONTENDED)

/* used to flip from LOCKED_UNCONTENDED to LOCKED_CONTENDED */
#define  MUTEX_STATE_BITS_FLIP_CONTENTION(v)      ((v) ^ (MUTEX_STATE_BITS_LOCKED_CONTENDED ^ MUTEX_STATE_BITS_LOCKED_UNCONTENDED))

/* Mutex counter:
 *
 * We need to check for overflow before incrementing, and we also need to
 * detect when the counter is 0
 */
#define  MUTEX_COUNTER_SHIFT         2
#define  MUTEX_COUNTER_LEN           11
#define  MUTEX_COUNTER_MASK          FIELD_MASK(MUTEX_COUNTER_SHIFT, MUTEX_COUNTER_LEN)

#define  MUTEX_COUNTER_BITS_WILL_OVERFLOW(v)    (((v) & MUTEX_COUNTER_MASK) == MUTEX_COUNTER_MASK)
#define  MUTEX_COUNTER_BITS_IS_ZERO(v)          (((v) & MUTEX_COUNTER_MASK) == 0)

/* Used to increment the counter directly after overflow has been checked */
#define  MUTEX_COUNTER_BITS_ONE      FIELD_TO_BITS(1, MUTEX_COUNTER_SHIFT,MUTEX_COUNTER_LEN)

/* Mutex shared bit flag
 *
 * This flag is set to indicate that the mutex is shared among processes.
 * This changes the futex opcode we use for futex wait/wake operations
 * (non-shared operations are much faster).
 */
#define  MUTEX_SHARED_SHIFT    13
#define  MUTEX_SHARED_MASK     FIELD_MASK(MUTEX_SHARED_SHIFT,1)

/* Mutex type:
 * We support normal, recursive and errorcheck mutexes.
 */
#define  MUTEX_TYPE_SHIFT      14
#define  MUTEX_TYPE_LEN        2
#define  MUTEX_TYPE_MASK       FIELD_MASK(MUTEX_TYPE_SHIFT,MUTEX_TYPE_LEN)

#define  MUTEX_TYPE_TO_BITS(t)       FIELD_TO_BITS(t, MUTEX_TYPE_SHIFT, MUTEX_TYPE_LEN)

#define  MUTEX_TYPE_BITS_NORMAL      MUTEX_TYPE_TO_BITS(PTHREAD_MUTEX_NORMAL)
#define  MUTEX_TYPE_BITS_RECURSIVE   MUTEX_TYPE_TO_BITS(PTHREAD_MUTEX_RECURSIVE)
#define  MUTEX_TYPE_BITS_ERRORCHECK  MUTEX_TYPE_TO_BITS(PTHREAD_MUTEX_ERRORCHECK)
// Use a special mutex type to mark priority inheritance mutexes.
#define  PI_MUTEX_STATE     MUTEX_TYPE_TO_BITS(3)

// For a PI mutex, it includes below fields:
//   Atomic(uint16_t) state;
//   PIMutex pi_mutex;  // uint16_t pi_mutex_id in 32-bit programs
//
//   state holds the following fields:
//
//   bits:   name    description
//   15-14   type    mutex type, should be 3
//   13-0    padding should be 0
//
//   pi_mutex holds the state of a PI mutex.
//   pi_mutex_id holds an integer to find the state of a PI mutex.
//
// For a Non-PI mutex, it includes below fields:
//   Atomic(uint16_t) state;
//   atomic_int owner_tid;  // Atomic(uint16_t) in 32-bit programs
//
//   state holds the following fields:
//
//   bits:     name     description
//   15-14     type     mutex type, can be 0 (normal), 1 (recursive), 2 (errorcheck)
//   13        shared   process-shared flag
//   12-2      counter  <number of times a thread holding a recursive Non-PI mutex> - 1
//   1-0       state    lock state (0, 1 or 2)
//
//   bits 15-13 are constant during the lifetime of the mutex.
//
//   owner_tid is used only in recursive and errorcheck Non-PI mutexes to hold the mutex owner
//   thread id.
//
// PI mutexes and Non-PI mutexes are distinguished by checking type field in state.
#if defined(__LP64__)
struct pthread_mutex_internal_t {
    _Atomic(uint16_t) state;
    uint16_t __pad;
    union {
        atomic_int owner_tid;
        PIMutex pi_mutex;
    };
    char __reserved[28];

    PIMutex& ToPIMutex() {
        return pi_mutex;
    }

    void FreePIMutex() {
    }
} __attribute__((aligned(4)));

#else
struct pthread_mutex_internal_t {
    _Atomic(uint16_t) state;
    union {
        _Atomic(uint16_t) owner_tid;
        uint16_t pi_mutex_id;
    };

    PIMutex& ToPIMutex() {
        return PIMutexAllocator::IdToPIMutex(pi_mutex_id);
    }

    void FreePIMutex() {
        PIMutexAllocator::FreeId(pi_mutex_id);
    }
} __attribute__((aligned(4)));
#endif

static_assert(sizeof(pthread_mutex_t) == sizeof(pthread_mutex_internal_t),
              "pthread_mutex_t should actually be pthread_mutex_internal_t in implementation.");

// For binary compatibility with old version of pthread_mutex_t, we can't use more strict alignment
// than 4-byte alignment.
static_assert(alignof(pthread_mutex_t) == 4,
              "pthread_mutex_t should fulfill the alignment of pthread_mutex_internal_t.");

static inline pthread_mutex_internal_t* __get_internal_mutex(pthread_mutex_t* mutex_interface) {
  return reinterpret_cast<pthread_mutex_internal_t*>(mutex_interface);
}

int pthread_mutex_init(pthread_mutex_t* mutex_interface, const pthread_mutexattr_t* attr) {
    pthread_mutex_internal_t* mutex = __get_internal_mutex(mutex_interface);

    memset(mutex, 0, sizeof(pthread_mutex_internal_t));

    if (__predict_true(attr == nullptr)) {
      atomic_store_explicit(&mutex->state, MUTEX_TYPE_BITS_NORMAL, memory_order_relaxed);
      return 0;
    }

    uint16_t state = 0;
    if ((*attr & MUTEXATTR_SHARED_MASK) != 0) {
        state |= MUTEX_SHARED_MASK;
    }

    switch (*attr & MUTEXATTR_TYPE_MASK) {
    case PTHREAD_MUTEX_NORMAL:
      state |= MUTEX_TYPE_BITS_NORMAL;
      break;
    case PTHREAD_MUTEX_RECURSIVE:
      state |= MUTEX_TYPE_BITS_RECURSIVE;
      break;
    case PTHREAD_MUTEX_ERRORCHECK:
      state |= MUTEX_TYPE_BITS_ERRORCHECK;
      break;
    default:
        return EINVAL;
    }

    if (((*attr & MUTEXATTR_PROTOCOL_MASK) >> MUTEXATTR_PROTOCOL_SHIFT) == PTHREAD_PRIO_INHERIT) {
#if !defined(__LP64__)
        if (state & MUTEX_SHARED_MASK) {
            return EINVAL;
        }
        int id = PIMutexAllocator::AllocId();
        if (id == -1) {
            return ENOMEM;
        }
        mutex->pi_mutex_id = id;
#endif
        atomic_store_explicit(&mutex->state, PI_MUTEX_STATE, memory_order_relaxed);
        PIMutex& pi_mutex = mutex->ToPIMutex();
        pi_mutex.type = *attr & MUTEXATTR_TYPE_MASK;
        pi_mutex.shared = (*attr & MUTEXATTR_SHARED_MASK) != 0;
    } else {
      atomic_store_explicit(&mutex->state, state, memory_order_relaxed);
      atomic_store_explicit(&mutex->owner_tid, 0, memory_order_relaxed);
    }
    return 0;
}

// namespace for Non-PI mutex routines.
namespace NonPI {

static inline __always_inline int NormalMutexTryLock(pthread_mutex_internal_t* mutex,
                                                     uint16_t shared) {
    const uint16_t unlocked           = shared | MUTEX_STATE_BITS_UNLOCKED;
    const uint16_t locked_uncontended = shared | MUTEX_STATE_BITS_LOCKED_UNCONTENDED;

    uint16_t old_state = unlocked;
    if (__predict_true(atomic_compare_exchange_strong_explicit(&mutex->state, &old_state,
                         locked_uncontended, memory_order_acquire, memory_order_relaxed))) {
        return 0;
    }
    return EBUSY;
}

/*
 * Lock a normal Non-PI mutex.
 *
 * As noted above, there are three states:
 *   0 (unlocked, no contention)
 *   1 (locked, no contention)
 *   2 (locked, contention)
 *
 * Non-recursive mutexes don't use the thread-id or counter fields, and the
 * "type" value is zero, so the only bits that will be set are the ones in
 * the lock state field.
 */
static inline __always_inline int NormalMutexLock(pthread_mutex_internal_t* mutex,
                                                  uint16_t shared,
                                                  bool use_realtime_clock,
                                                  const timespec* abs_timeout_or_null) {
    if (__predict_true(NormalMutexTryLock(mutex, shared) == 0)) {
        return 0;
    }
    int result = check_timespec(abs_timeout_or_null, true);
    if (result != 0) {
        return result;
    }

    ScopedTrace trace("Contending for pthread mutex");

    const uint16_t unlocked           = shared | MUTEX_STATE_BITS_UNLOCKED;
    const uint16_t locked_contended = shared | MUTEX_STATE_BITS_LOCKED_CONTENDED;

    // We want to go to sleep until the mutex is available, which requires
    // promoting it to locked_contended. We need to swap in the new state
    // and then wait until somebody wakes us up.
    // An atomic_exchange is used to compete with other threads for the lock.
    // If it returns unlocked, we have acquired the lock, otherwise another
    // thread still holds the lock and we should wait again.
    // If lock is acquired, an acquire fence is needed to make all memory accesses
    // made by other threads visible to the current CPU.
    while (atomic_exchange_explicit(&mutex->state, locked_contended,
                                    memory_order_acquire) != unlocked) {
        if (__futex_wait_ex(&mutex->state, shared, locked_contended, use_realtime_clock,
                            abs_timeout_or_null) == -ETIMEDOUT) {
            return ETIMEDOUT;
        }
    }
    return 0;
}

/*
 * Release a normal Non-PI mutex.  The caller is responsible for determining
 * that we are in fact the owner of this lock.
 */
static inline __always_inline void NormalMutexUnlock(pthread_mutex_internal_t* mutex,
                                                     uint16_t shared) {
    const uint16_t unlocked         = shared | MUTEX_STATE_BITS_UNLOCKED;
    const uint16_t locked_contended = shared | MUTEX_STATE_BITS_LOCKED_CONTENDED;

    // We use an atomic_exchange to release the lock. If locked_contended state
    // is returned, some threads is waiting for the lock and we need to wake up
    // one of them.
    // A release fence is required to make previous stores visible to next
    // lock owner threads.
    if (atomic_exchange_explicit(&mutex->state, unlocked,
                                 memory_order_release) == locked_contended) {
        // Wake up one waiting thread. We don't know which thread will be
        // woken or when it'll start executing -- futexes make no guarantees
        // here. There may not even be a thread waiting.
        //
        // The newly-woken thread will replace the unlocked state we just set above
        // with locked_contended state, which means that when it eventually releases
        // the mutex it will also call FUTEX_WAKE. This results in one extra wake
        // call whenever a lock is contended, but let us avoid forgetting anyone
        // without requiring us to track the number of sleepers.
        //
        // It's possible for another thread to sneak in and grab the lock between
        // the exchange above and the wake call below. If the new thread is "slow"
        // and holds the lock for a while, we'll wake up a sleeper, which will swap
        // in locked_uncontended state and then go back to sleep since the lock is
        // still held. If the new thread is "fast", running to completion before
        // we call wake, the thread we eventually wake will find an unlocked mutex
        // and will execute. Either way we have correct behavior and nobody is
        // orphaned on the wait queue.
        //
        // The pthread_mutex_internal_t object may have been deallocated between the
        // atomic exchange and the wake call. In that case, this wake call could
        // target unmapped memory or memory used by an otherwise unrelated futex
        // operation. Even if the kernel avoids spurious futex wakeups from its
        // point of view, this wake call could trigger a spurious wakeup in any
        // futex accessible from this process. References:
        //  - https://lkml.org/lkml/2014/11/27/472
        //  - http://austingroupbugs.net/view.php?id=811#c2267
        __futex_wake_ex(&mutex->state, shared, 1);
    }
}

/* This common inlined function is used to increment the counter of a recursive Non-PI mutex.
 *
 * If the counter overflows, it will return EAGAIN.
 * Otherwise, it atomically increments the counter and returns 0.
 *
 */
static inline __always_inline int RecursiveIncrement(pthread_mutex_internal_t* mutex,
                                                     uint16_t old_state) {
    // Detect recursive lock overflow and return EAGAIN.
    // This is safe because only the owner thread can modify the
    // counter bits in the mutex value.
    if (MUTEX_COUNTER_BITS_WILL_OVERFLOW(old_state)) {
        return EAGAIN;
    }

    // Other threads are able to change the lower bits (e.g. promoting it to "contended"),
    // but the mutex counter will not overflow. So we use atomic_fetch_add operation here.
    // The mutex is already locked by current thread, so we don't need an acquire fence.
    atomic_fetch_add_explicit(&mutex->state, MUTEX_COUNTER_BITS_ONE, memory_order_relaxed);
    return 0;
}

// Wait on a recursive or errorcheck Non-PI mutex.
static inline __always_inline int RecursiveOrErrorcheckMutexWait(pthread_mutex_internal_t* mutex,
                                                                 uint16_t shared,
                                                                 uint16_t old_state,
                                                                 bool use_realtime_clock,
                                                                 const timespec* abs_timeout) {
// __futex_wait always waits on a 32-bit value. But state is 16-bit. For a normal mutex, the owner_tid
// field in mutex is not used. On 64-bit devices, the __pad field in mutex is not used.
// But when a recursive or errorcheck mutex is used on 32-bit devices, we need to add the
// owner_tid value in the value argument for __futex_wait, otherwise we may always get EAGAIN error.

#if defined(__LP64__)
  return __futex_wait_ex(&mutex->state, shared, old_state, use_realtime_clock, abs_timeout);

#else
  // This implementation works only when the layout of pthread_mutex_internal_t matches below expectation.
  // And it is based on the assumption that Android is always in little-endian devices.
  static_assert(offsetof(pthread_mutex_internal_t, state) == 0, "");
  static_assert(offsetof(pthread_mutex_internal_t, owner_tid) == 2, "");

  uint32_t owner_tid = atomic_load_explicit(&mutex->owner_tid, memory_order_relaxed);
  return __futex_wait_ex(&mutex->state, shared, (owner_tid << 16) | old_state,
                         use_realtime_clock, abs_timeout);
#endif
}

// Lock a Non-PI mutex.
static int MutexLockWithTimeout(pthread_mutex_internal_t* mutex, bool use_realtime_clock,
                                const timespec* abs_timeout_or_null) {
    uint16_t old_state = atomic_load_explicit(&mutex->state, memory_order_relaxed);
    uint16_t mtype = (old_state & MUTEX_TYPE_MASK);
    uint16_t shared = (old_state & MUTEX_SHARED_MASK);

    // Handle common case first.
    if ( __predict_true(mtype == MUTEX_TYPE_BITS_NORMAL) ) {
        return NormalMutexLock(mutex, shared, use_realtime_clock, abs_timeout_or_null);
    }

    // Do we already own this recursive or error-check mutex?
    pid_t tid = __get_thread()->tid;
    if (tid == atomic_load_explicit(&mutex->owner_tid, memory_order_relaxed)) {
        if (mtype == MUTEX_TYPE_BITS_ERRORCHECK) {
            return EDEADLK;
        }
        return RecursiveIncrement(mutex, old_state);
    }

    const uint16_t unlocked           = mtype | shared | MUTEX_STATE_BITS_UNLOCKED;
    const uint16_t locked_uncontended = mtype | shared | MUTEX_STATE_BITS_LOCKED_UNCONTENDED;
    const uint16_t locked_contended   = mtype | shared | MUTEX_STATE_BITS_LOCKED_CONTENDED;

    // First, if the mutex is unlocked, try to quickly acquire it.
    // In the optimistic case where this works, set the state to locked_uncontended.
    if (old_state == unlocked) {
        // If exchanged successfully, an acquire fence is required to make
        // all memory accesses made by other threads visible to the current CPU.
        if (__predict_true(atomic_compare_exchange_strong_explicit(&mutex->state, &old_state,
                             locked_uncontended, memory_order_acquire, memory_order_relaxed))) {
            atomic_store_explicit(&mutex->owner_tid, tid, memory_order_relaxed);
            return 0;
        }
    }

    ScopedTrace trace("Contending for pthread mutex");

    while (true) {
        if (old_state == unlocked) {
            // NOTE: We put the state to locked_contended since we _know_ there
            // is contention when we are in this loop. This ensures all waiters
            // will be unlocked.

            // If exchanged successfully, an acquire fence is required to make
            // all memory accesses made by other threads visible to the current CPU.
            if (__predict_true(atomic_compare_exchange_weak_explicit(&mutex->state,
                                                                     &old_state, locked_contended,
                                                                     memory_order_acquire,
                                                                     memory_order_relaxed))) {
                atomic_store_explicit(&mutex->owner_tid, tid, memory_order_relaxed);
                return 0;
            }
            continue;
        } else if (MUTEX_STATE_BITS_IS_LOCKED_UNCONTENDED(old_state)) {
            // We should set it to locked_contended beforing going to sleep. This can make
            // sure waiters will be woken up eventually.

            int new_state = MUTEX_STATE_BITS_FLIP_CONTENTION(old_state);
            if (__predict_false(!atomic_compare_exchange_weak_explicit(&mutex->state,
                                                                       &old_state, new_state,
                                                                       memory_order_relaxed,
                                                                       memory_order_relaxed))) {
                continue;
            }
            old_state = new_state;
        }

        int result = check_timespec(abs_timeout_or_null, true);
        if (result != 0) {
            return result;
        }
        // We are in locked_contended state, sleep until someone wakes us up.
        if (RecursiveOrErrorcheckMutexWait(mutex, shared, old_state, use_realtime_clock,
                                           abs_timeout_or_null) == -ETIMEDOUT) {
            return ETIMEDOUT;
        }
        old_state = atomic_load_explicit(&mutex->state, memory_order_relaxed);
    }
}

}  // namespace NonPI

static inline __always_inline bool IsMutexDestroyed(uint16_t mutex_state) {
    return mutex_state == 0xffff;
}

// Inlining this function in pthread_mutex_lock() adds the cost of stack frame instructions on
// ARM64. So make it noinline.
static int __attribute__((noinline)) HandleUsingDestroyedMutex(pthread_mutex_t* mutex,
                                                               const char* function_name) {
    if (android_get_application_target_sdk_version() >= 28) {
        __fortify_fatal("%s called on a destroyed mutex (%p)", function_name, mutex);
    }
    return EBUSY;
}

int pthread_mutex_lock(pthread_mutex_t* mutex_interface) {
#if !defined(__LP64__)
    // Some apps depend on being able to pass NULL as a mutex and get EINVAL
    // back. Don't need to worry about it for LP64 since the ABI is brand new,
    // but keep compatibility for LP32. http://b/19995172.
    if (mutex_interface == nullptr) {
        return EINVAL;
    }
#endif

    pthread_mutex_internal_t* mutex = __get_internal_mutex(mutex_interface);
    uint16_t old_state = atomic_load_explicit(&mutex->state, memory_order_relaxed);
    uint16_t mtype = (old_state & MUTEX_TYPE_MASK)
"""


```