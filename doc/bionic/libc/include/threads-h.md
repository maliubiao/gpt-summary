Response:
Let's break down the thought process to answer the request about `bionic/libc/include/threads.handroid`.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`threads.h`) within the context of Android's Bionic library. The request has several specific sub-questions:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it relate to Android's features?
* **Implementation Details:** How are the libc functions implemented?
* **Dynamic Linker:**  What's the connection to the dynamic linker, and examples?
* **Logic and Examples:** If there's logic, show input/output. Provide examples of common errors.
* **Android Framework/NDK Integration:** How does the code get used in Android? Provide Frida hook examples.

**2. Initial Analysis of the Header File:**

* **Copyright and License:**  Standard open-source license information. Not directly functional, but good to note.
* **Includes:**  `<sys/cdefs.h>`, `<pthread.h>`, `<time.h>`. This immediately tells us the file is *wrapping* or providing an interface to POSIX threads (`pthread`).
* **Typedefs:**  `cnd_t`, `thrd_t`, `tss_t`, `mtx_t`. These are just renaming `pthread` types, likely for C11 compatibility or internal consistency.
* **Defines:** `ONCE_FLAG_INIT`, `TSS_DTOR_ITERATIONS`. These are also direct mappings to `pthread` constants.
* **Enums:** `mtx_plain`, `mtx_recursive`, `mtx_timed` and `thrd_success`, `thrd_busy`, etc. These define constants related to mutex types and thread status.
* **`thread_local` Macro:** A conditional definition for `thread_local` to handle C11's `_Thread_local`.
* **Function Declarations:** The bulk of the file. These are function declarations for thread management (`thrd_*`), mutexes (`mtx_*`), condition variables (`cnd_*`), thread-specific storage (`tss_*`), and `call_once`.
* **`__INTRODUCED_IN(30)`:** This is a crucial indicator. It signifies that these functions are only available from Android API level 30 onwards. This means the *primary* function of this header for older Android versions is the *inlines* provided in the included `<android/legacy_threads_inlines.h>`.
* **Include of `android/legacy_threads_inlines.h`:**  This is key. It suggests that before API level 30, the functionality was likely provided through inline functions for backwards compatibility or performance reasons.

**3. Answering the Sub-Questions - Iterative Process:**

* **Functionality:** Based on the function declarations and the inclusion of `pthread.h`, the file provides a C11-style threading API on top of POSIX threads. It offers mechanisms for thread creation, joining, exiting, mutex locking, condition variable signaling, thread-local storage, and running a function once.

* **Android Relevance:**  Threading is fundamental to modern operating systems, and Android is no exception. This file provides the standard C11 threading interface for Android developers. Examples include any concurrent task: UI updates separate from background processing, network requests, data processing, etc. The API level restriction is a significant point for Android developers to consider for backward compatibility.

* **Implementation Details:**  The *declarations* in this header file *don't* contain the implementation. The implementations would be in the corresponding `.c` files within Bionic. However, the API level comment is a strong hint:  Before API 30, the implementations are likely inline functions wrapping `pthread` calls directly. After API 30, these are likely separate function calls within the Bionic library. It's important to state that the header *declares* the interface, while the implementation is elsewhere.

* **Dynamic Linker:**  The connection here isn't *direct*. These functions are part of `libc.so`, which is dynamically linked by every Android process. The dynamic linker resolves the symbols (like `thrd_create`) to their addresses in the loaded `libc.so` library. A simple `libc.so` layout example can be given, but detailed linker workings are beyond the scope of analyzing *this specific header file*. The linking process involves symbol lookup in the dynamic symbol table of `libc.so`.

* **Logic and Examples:** The logic is within the *implementations* of the functions. However, we can describe the *expected behavior*. For example, with `call_once`, the input is a `once_flag` and a function. The output is that the function is executed *exactly once*, regardless of how many times `call_once` is called with the same flag. Common errors include using uninitialized mutexes or condition variables, or forgetting to unlock a mutex.

* **Android Framework/NDK Integration:** This is about tracing the call stack. An Android app using the NDK can directly call these functions. The Android Framework (written in Java/Kotlin) indirectly uses these through the underlying native libraries. A Frida hook example would target one of these functions in `libc.so`. We'd need to identify a relevant process and hook the function.

**4. Structuring the Answer:**

Organize the answer to address each sub-question clearly. Use headings and bullet points for readability. Emphasize the key takeaway about the API level dependency and the role of `legacy_threads_inlines.h`.

**5. Refining and Adding Detail:**

* Explicitly mention the wrapping of POSIX threads.
* Elaborate on the API level constraint.
* Give concrete examples of Android features that use threading.
* Provide a simplified explanation of dynamic linking.
* Offer specific examples of usage errors.
* Create a basic Frida hook example targeting `thrd_create`.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the function *declarations* without emphasizing that the *implementation* isn't here. The API level comment is a strong clue about how the implementation differs across Android versions.
* It's important to avoid over-explaining the dynamic linker. Focus on the connection to `libc.so` and symbol resolution.
*  The Frida hook example should be kept simple and illustrative. No need for complex scenarios.

By following this thought process, breaking down the request, and focusing on the key information in the header file, we can construct a comprehensive and accurate answer.
这是目录为 `bionic/libc/include/threads.handroid` 的源代码文件，它位于 Android 的 Bionic 库中。这个文件定义了与 C11 标准线程相关的接口。

**功能列举:**

该头文件主要提供以下功能，用于在 Android 系统中进行多线程编程：

1. **线程管理:**
   - **创建线程 (`thrd_create`):**  允许创建新的执行线程。
   - **获取当前线程 (`thrd_current`):**  返回当前正在执行的线程的标识符。
   - **分离线程 (`thrd_detach`):**  将线程与创建它的线程分离，使其在退出后自动释放资源。
   - **比较线程 (`thrd_equal`):**  检查两个线程标识符是否代表同一个线程。
   - **线程退出 (`thrd_exit`):**  终止当前线程的执行，并可以传递一个退出状态码。
   - **等待线程结束 (`thrd_join`):**  阻塞调用线程，直到指定的线程执行结束。
   - **线程休眠 (`thrd_sleep`):**  使当前线程休眠指定的时间。
   - **线程让步 (`thrd_yield`):**  建议操作系统调度其他线程运行。

2. **互斥锁 (Mutexes):**
   - **创建互斥锁 (`mtx_init`):**  初始化一个互斥锁，可以指定互斥锁的类型（普通、递归、定时）。
   - **销毁互斥锁 (`mtx_destroy`):**  释放互斥锁占用的资源。
   - **加锁 (`mtx_lock`):**  尝试获取互斥锁，如果锁已被其他线程持有，则阻塞当前线程直到获取锁。
   - **定时加锁 (`mtx_timedlock`):**  尝试获取互斥锁，如果在指定时间内无法获取，则返回错误。
   - **尝试加锁 (`mtx_trylock`):**  尝试获取互斥锁，如果锁已被其他线程持有，则立即返回错误，不会阻塞。
   - **解锁 (`mtx_unlock`):**  释放已持有的互斥锁。

3. **条件变量 (Condition Variables):**
   - **创建条件变量 (`cnd_init`):**  初始化一个条件变量。
   - **销毁条件变量 (`cnd_destroy`):**  释放条件变量占用的资源。
   - **广播 (`cnd_broadcast`):**  唤醒所有等待在该条件变量上的线程。
   - **发送信号 (`cnd_signal`):**  唤醒一个等待在该条件变量上的线程。
   - **定时等待 (`cnd_timedwait`):**  原子地解锁互斥锁并等待条件变量被信号通知，如果在指定时间内未收到信号，则返回错误。
   - **等待 (`cnd_wait`):**  原子地解锁互斥锁并等待条件变量被信号通知。

4. **线程特定存储 (Thread-Specific Storage, TSS):**
   - **创建 TSS 键 (`tss_create`):**  创建一个用于线程特定存储的键，可以关联一个析构函数。
   - **删除 TSS 键 (`tss_delete`):**  删除一个线程特定存储的键。
   - **获取 TSS 值 (`tss_get`):**  获取当前线程与指定 TSS 键关联的值。
   - **设置 TSS 值 (`tss_set`):**  设置当前线程与指定 TSS 键关联的值。

5. **一次性初始化 (`call_once`):**
   - **执行一次函数 (`call_once`):**  确保指定的函数只被调用一次，即使在多个线程中同时调用。

**与 Android 功能的关系及举例说明:**

这些功能是 Android 多线程编程的基础，广泛应用于 Android Framework 和 NDK 开发中。

* **Android Framework:** Android Framework 中许多组件和服务都是多线程的，例如：
    * **UI 线程 (Main Thread):** 处理用户交互和 UI 更新。
    * **后台服务 (Background Services):** 执行诸如网络请求、数据同步等后台任务。
    * **异步任务 (AsyncTask):**  简化后台任务的处理，并允许将结果发布到 UI 线程。

    例如，当一个应用需要从网络下载数据并在 UI 上显示时，通常会创建一个新的线程来执行下载操作，避免阻塞 UI 线程，从而保持应用的响应性。`thrd_create` 可以用来创建这个下载线程，而互斥锁和条件变量可以用于线程间的同步和通信，例如在下载完成时通知 UI 线程更新界面。

* **NDK 开发:** 使用 NDK 开发的 native 代码可以直接使用这些线程相关的函数。例如，一个游戏引擎可能会使用多个线程来处理渲染、物理模拟和用户输入。`mtx_lock` 和 `mtx_unlock` 可以用来保护共享资源，防止竞态条件。

**libc 函数的实现原理:**

这个头文件本身只是定义了接口，具体的实现位于 Bionic 库的源代码中。 这些 C11 线程函数实际上是对 POSIX 线程 (pthread) 的一层封装。

* **`thrd_create`:**  内部会调用 `pthread_create` 创建一个 POSIX 线程。它需要一个指向 `pthread_t` 变量的指针来存储新线程的 ID，一个 `pthread_attr_t` 结构体（通常为 NULL 使用默认属性），一个线程启动函数指针，以及传递给启动函数的参数。

* **`mtx_init`:**  内部会调用 `pthread_mutex_init` 来初始化一个 POSIX 互斥锁。它可以接收一个 `pthread_mutexattr_t` 结构体来指定互斥锁的属性，例如类型（普通、递归等）。

* **`cnd_wait`:**  内部会调用 `pthread_cond_wait`，它需要一个指向 `pthread_cond_t` 条件变量的指针和一个指向 `pthread_mutex_t` 互斥锁的指针。调用 `pthread_cond_wait` 会原子地释放互斥锁并使线程进入休眠状态，直到条件变量被信号通知。

* **`tss_create`:**  内部会调用 `pthread_key_create` 创建一个线程特定存储的键，并可以指定一个析构函数，当线程结束时，与该键关联的值会被传递给析构函数。

* **`call_once`:**  通常使用 `pthread_once` 实现。它需要一个 `pthread_once_t` 类型的标志和一个函数指针。`pthread_once` 保证传递的函数只会被执行一次，即使在多个线程中同时调用。

**涉及 dynamic linker 的功能及处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的具体操作，但它定义的函数是 `libc.so` 的一部分，而 `libc.so` 是 Android 系统中所有进程都会动态链接的共享库。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:  // 代码段
        thrd_create: ... // thrd_create 函数的机器码
        mtx_lock: ...   // mtx_lock 函数的机器码
        ...
    .data:  // 初始化数据段
        ...
    .bss:   // 未初始化数据段
        ...
    .dynamic: // 动态链接信息
        SONAME: libc.so
        NEEDED: libm.so // 可能依赖的其他库
        SYMTAB: ...    // 符号表 (包含 thrd_create, mtx_lock 等符号)
        STRTAB: ...    // 字符串表
        ...
```

**链接的处理过程:**

1. **加载:** 当一个 Android 应用启动时，zygote 进程会 fork 出新的进程。在进程启动过程中，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。

2. **查找依赖:** Dynamic linker 会读取可执行文件的头部信息，找到其依赖的共享库列表，其中包括 `libc.so`。

3. **加载共享库:** Dynamic linker 会在预定义的路径（如 `/system/lib64`, `/system/lib`) 中查找 `libc.so`，并将其加载到进程的内存空间。

4. **符号解析:** 当程序代码调用 `thrd_create` 等函数时，编译器和链接器会在可执行文件中生成对这些符号的引用。Dynamic linker 会在 `libc.so` 的符号表 (`SYMTAB`) 中查找这些符号的地址，并将程序代码中的符号引用替换为实际的内存地址。这个过程称为符号解析或重定位。

5. **执行:** 一旦所有的依赖库都被加载，并且符号解析完成，程序就可以开始执行，调用 `libc.so` 中提供的线程相关函数。

**逻辑推理、假设输入与输出:**

以 `call_once` 为例：

**假设输入:**

```c
#include <threads.h>
#include <stdio.h>

once_flag flag = ONCE_FLAG_INIT;

void init() {
    printf("Initialization done.\n");
}

int main() {
    call_once(&flag, init);
    call_once(&flag, init);
    return 0;
}
```

**逻辑推理:** `call_once` 保证 `init` 函数只会被调用一次。第一次调用 `call_once` 时，`flag` 尚未被标记为已初始化，因此 `init` 函数会被执行。第二次调用 `call_once` 时，`flag` 已经被标记，所以 `init` 函数不会再次执行。

**预期输出:**

```
Initialization done.
```

**用户或编程常见的使用错误:**

1. **未初始化互斥锁或条件变量:** 在使用互斥锁或条件变量之前，必须先使用 `mtx_init` 或 `cnd_init` 进行初始化。否则，会导致未定义行为，可能崩溃。

   ```c
   mtx_t my_mutex; // 未初始化
   mtx_lock(&my_mutex); // 错误！
   ```

2. **死锁:** 当多个线程相互等待对方释放锁时，会发生死锁。

   ```c
   mtx_t mutex1, mutex2;
   mtx_init(&mutex1, mtx_plain);
   mtx_init(&mutex2, mtx_plain);

   // 线程 1
   mtx_lock(&mutex1);
   // ...
   mtx_lock(&mutex2); // 等待线程 2 释放 mutex2
   // ...
   mtx_unlock(&mutex2);
   mtx_unlock(&mutex1);

   // 线程 2
   mtx_lock(&mutex2);
   // ...
   mtx_lock(&mutex1); // 等待线程 1 释放 mutex1
   // ...
   mtx_unlock(&mutex1);
   mtx_unlock(&mutex2);
   ```

3. **忘记解锁互斥锁:** 如果线程获取了互斥锁但忘记释放，会导致其他线程永久阻塞。

   ```c
   mtx_t my_mutex;
   mtx_init(&my_mutex, mtx_plain);
   mtx_lock(&my_mutex);
   // ... 忘记调用 mtx_unlock(&my_mutex);
   ```

4. **在未持有互斥锁的情况下调用 `cnd_wait` 或 `cnd_signal`:**  条件变量总是与互斥锁一起使用，以避免竞争条件。

   ```c
   cnd_t my_cond;
   mtx_t my_mutex;
   cnd_init(&my_cond);
   mtx_init(&my_mutex, mtx_plain);

   cnd_wait(&my_cond, &my_mutex); // 错误！应该先持有 mutex
   ```

5. **错误地使用线程特定存储:** 例如，在 `tss_create` 时提供了析构函数，但线程退出时没有设置 TSS 值，可能导致析构函数被传递一个无效的指针。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例:**

**Android Framework 的调用路径 (简化):**

1. **Java 代码:** Android Framework 的上层代码（Java 或 Kotlin）可能会使用 `java.lang.Thread` 或 `java.util.concurrent` 包中的类来进行多线程操作。

2. **VM 内部调用:** Java 虚拟机会将这些高级线程操作转换为底层的 native 调用。例如，`java.lang.Thread.start()` 方法最终会调用 native 方法。

3. **NDK Bridge:** 如果涉及 NDK 代码，Java 代码可以通过 JNI (Java Native Interface) 调用 native 函数。

4. **Bionic 库:** NDK 代码中直接调用 `<threads.h>` 中声明的函数，这些函数最终会调用 Bionic 库中的实现（通常是对 POSIX 线程的封装）。

**NDK 的调用路径:**

1. **C/C++ 代码:** NDK 开发者直接在 C/C++ 代码中 `#include <threads.h>` 并调用相应的函数，例如 `thrd_create`。

2. **编译和链接:**  NDK 构建系统会将 C/C++ 代码编译成 native 库 (`.so` 文件)，并链接到 Bionic 库 (`libc.so`)。

3. **运行时加载:** 当 Android 应用加载包含 NDK 代码的 native 库时，dynamic linker 会解析对 `libc.so` 中函数的引用。

**Frida Hook 示例 (Hook `thrd_create`):**

假设我们想要监控应用中线程的创建情况。可以使用 Frida Hook `thrd_create` 函数：

```javascript
// frida script

// 获取 libc.so 的基地址
const libc = Process.getModuleByName("libc.so");
const thrd_create_addr = libc.getExportByName("thrd_create");

if (thrd_create_addr) {
  Interceptor.attach(thrd_create_addr, {
    onEnter: function(args) {
      console.log("[thrd_create] Entered");
      const threadPtr = args[0];
      const startFuncPtr = args[1];
      const argPtr = args[2];

      console.log("  Thread pointer:", threadPtr);
      console.log("  Start function:", startFuncPtr);
      console.log("  Argument:", argPtr);
    },
    onLeave: function(retval) {
      console.log("[thrd_create] Left, return value:", retval);
      if (retval === 0) {
        console.log("  Thread creation successful.");
      } else {
        console.log("  Thread creation failed.");
      }
    }
  });
} else {
  console.log("Failed to find thrd_create in libc.so");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_threads.js`。
2. 运行 Frida，指定要 hook 的 Android 应用进程：
   ```bash
   frida -U -f <package_name> -l hook_threads.js --no-pause
   ```
   或者 attach 到正在运行的进程：
   ```bash
   frida -U <process_id> -l hook_threads.js
   ```

**预期输出 (当应用创建新线程时):**

```
[thrd_create] Entered
  Thread pointer: 0x...
  Start function: 0x...
  Argument: 0x...
[thrd_create] Left, return value: 0
  Thread creation successful.
```

这个 Frida 脚本会在 `thrd_create` 函数被调用时打印相关信息，包括传递给函数的参数和返回值，从而帮助我们理解应用如何使用线程。

总结来说，`bionic/libc/include/threads.handroid` 定义了 Android 系统中进行多线程编程的关键接口，它基于 POSIX 线程，并被 Android Framework 和 NDK 广泛使用。理解这些接口的功能和使用方法对于开发高效且稳定的 Android 应用至关重要。

Prompt: 
```
这是目录为bionic/libc/include/threads.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

/**
 * @file threads.h
 * @brief C11 threads.
 */

#include <sys/cdefs.h>

#include <pthread.h>
#include <time.h>

#define ONCE_FLAG_INIT PTHREAD_ONCE_INIT
#define TSS_DTOR_ITERATIONS PTHREAD_DESTRUCTOR_ITERATIONS

/** The type for a condition variable. */
typedef pthread_cond_t cnd_t;
/** The type for a thread. */
typedef pthread_t thrd_t;
/** The type for a thread-specific storage key. */
typedef pthread_key_t tss_t;
/** The type for a mutex. */
typedef pthread_mutex_t mtx_t;

/** The type for a thread-specific storage destructor. */
typedef void (*tss_dtor_t)(void* _Nullable);
/** The type of the function passed to thrd_create() to create a new thread. */
typedef int (*thrd_start_t)(void* _Nullable);

/** The type used by call_once(). */
typedef pthread_once_t once_flag;

enum {
  mtx_plain = 0x1,
  mtx_recursive = 0x2,
  mtx_timed = 0x4,
};

enum {
  thrd_success = 0,
  thrd_busy = 1,
  thrd_error = 2,
  thrd_nomem = 3,
  thrd_timedout = 4,
};

/* `thread_local` is a keyword in C++11 and C23; C11 had `_Thread_local` instead. */
#if !defined(__cplusplus) && (__STDC_VERSION__ >= 201112L && __STDC_VERSION__ < 202311L)
# undef thread_local
# define thread_local _Thread_local
#endif

__BEGIN_DECLS

#if __ANDROID_API__ >= 30
// This file is implemented as static inlines before API level 30.

/** Uses `__flag` to ensure that `__function` is called exactly once. */
void call_once(once_flag* _Nonnull __flag, void (* _Nonnull __function)(void)) __INTRODUCED_IN(30);



/**
 * Unblocks all threads blocked on `__cond`.
 */
int cnd_broadcast(cnd_t* _Nonnull __cond) __INTRODUCED_IN(30);

/**
 * Destroys a condition variable.
 */
void cnd_destroy(cnd_t* _Nonnull __cond) __INTRODUCED_IN(30);

/**
 * Creates a condition variable.
 */
int cnd_init(cnd_t* _Nonnull __cond) __INTRODUCED_IN(30);

/**
 * Unblocks one thread blocked on `__cond`.
 */
int cnd_signal(cnd_t* _Nonnull __cond) __INTRODUCED_IN(30);

/**
 * Unlocks `__mutex` and blocks until `__cond` is signaled or `__timeout` occurs.
 */
int cnd_timedwait(cnd_t* _Nonnull __cond, mtx_t* _Nonnull __mutex, const struct timespec* _Nonnull __timeout)
    __INTRODUCED_IN(30);

/**
 * Unlocks `__mutex` and blocks until `__cond` is signaled.
 */
int cnd_wait(cnd_t* _Nonnull __cond, mtx_t* _Nonnull __mutex) __INTRODUCED_IN(30);



/**
 * Destroys a mutex.
 */
void mtx_destroy(mtx_t* _Nonnull __mutex) __INTRODUCED_IN(30);

/**
 * Creates a mutex.
 */
int mtx_init(mtx_t* _Nonnull __mutex, int __type) __INTRODUCED_IN(30);

/**
 * Blocks until `__mutex` is acquired.
 */
int mtx_lock(mtx_t* _Nonnull __mutex) __INTRODUCED_IN(30);

/**
 * Blocks until `__mutex` is acquired or `__timeout` expires.
 */
int mtx_timedlock(mtx_t* _Nonnull __mutex, const struct timespec* _Nonnull __timeout) __INTRODUCED_IN(30);

/**
 * Acquires `__mutex` or returns `thrd_busy`.
 */
int mtx_trylock(mtx_t* _Nonnull __mutex) __INTRODUCED_IN(30);

/**
 * Unlocks `__mutex`.
 */
int mtx_unlock(mtx_t* _Nonnull __mutex) __INTRODUCED_IN(30);



/**
 * Creates a new thread running `__function(__arg)`, and sets `*__thrd` to
 * the new thread.
 */
int thrd_create(thrd_t* _Nonnull __thrd, thrd_start_t _Nonnull __function, void* _Nullable __arg) __INTRODUCED_IN(30);

/**
 * Returns the `thrd_t` corresponding to the caller.
 */
thrd_t thrd_current(void) __INTRODUCED_IN(30);

/**
 * Tells the OS to automatically dispose of `__thrd` when it exits.
 */
int thrd_detach(thrd_t __thrd) __INTRODUCED_IN(30);

/**
 * Tests whether two threads are the same thread.
 */
int thrd_equal(thrd_t __lhs, thrd_t __rhs) __INTRODUCED_IN(30);

/**
 * Terminates the calling thread, setting its result to `__result`.
 */
void thrd_exit(int __result) __noreturn __INTRODUCED_IN(30);

/**
 * Blocks until `__thrd` terminates. If `__result` is not null, `*__result`
 * is set to the exiting thread's result.
 */
int thrd_join(thrd_t __thrd, int* _Nullable __result) __INTRODUCED_IN(30);

/**
 * Blocks the caller for at least `__duration` unless a signal is delivered.
 * If a signal causes the sleep to end early and `__remaining` is not null,
 * `*__remaining` is set to the time remaining.
 *
 * Returns 0 on success, or -1 if a signal was delivered.
 */
int thrd_sleep(const struct timespec* _Nonnull __duration, struct timespec* _Nullable __remaining) __INTRODUCED_IN(30);

/**
 * Request that other threads should be scheduled.
 */
void thrd_yield(void) __INTRODUCED_IN(30);



/**
 * Creates a thread-specific storage key with the associated destructor (which
 * may be null).
 */
int tss_create(tss_t* _Nonnull __key, tss_dtor_t _Nullable __dtor) __INTRODUCED_IN(30);

/**
 * Destroys a thread-specific storage key.
 */
void tss_delete(tss_t __key) __INTRODUCED_IN(30);

/**
 * Returns the value for the current thread held in the thread-specific storage
 * identified by `__key`.
 */
void* _Nullable tss_get(tss_t __key) __INTRODUCED_IN(30);

/**
 * Sets the current thread's value for the thread-specific storage identified
 * by `__key` to `__value`.
 */
int tss_set(tss_t __key, void* _Nonnull __value) __INTRODUCED_IN(30);

#endif

__END_DECLS

#include <android/legacy_threads_inlines.h>

"""

```