Response:
Let's break down the thought process for analyzing the provided C++ benchmark code and generating the detailed response.

**1. Understanding the Goal:**

The core request is to analyze the `pthread_benchmark.cpp` file within the Android Bionic library. This involves identifying its purpose, explaining the functions it uses, connecting them to Android, detailing internal implementations (where possible), explaining dynamic linking concepts, highlighting potential errors, and tracing the execution path from Android frameworks.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code. I immediately notice the `#include <pthread.h>` and the `benchmark/benchmark.h` includes. This signals that the code is using POSIX threads and the Google Benchmark library. The presence of functions like `BM_pthread_self`, `BM_pthread_mutex_lock`, etc., clearly indicates that this file is designed to measure the performance of various `pthread` functions.

**3. Identifying Functionality (Instruction 1):**

Based on the naming convention of the benchmark functions (e.g., `BM_pthread_self`), I can directly infer the functionality. Each `BM_` prefixed function tests the performance of the corresponding `pthread_` function. This leads to the list of tested functionalities: `pthread_self`, `pthread_getspecific`, `pthread_setspecific`, `pthread_once`, `pthread_mutex_lock` (various types), `pthread_rwlock_read`, `pthread_rwlock_write`, `pthread_create`, `pthread_exit`, `pthread_key_create`, and `pthread_key_delete`.

**4. Connecting to Android Functionality (Instruction 2):**

Since Bionic *is* Android's C library, all the `pthread` functions are fundamental to Android's multithreading capabilities. I need to provide concrete examples of how these functions are used in Android. My thinking goes like this:

* **`pthread_self`:** Every thread in an Android process has a thread ID. Useful for logging, debugging, and thread-local storage.
* **`pthread_getspecific`/`pthread_setspecific`:**  Thread-local storage is crucial for managing thread-specific data without global variables. Think about per-thread resources or contexts.
* **`pthread_once`:** Initialization routines that should only run once, like initializing a singleton or a global resource.
* **Mutexes (`pthread_mutex_lock`):**  Protecting shared resources from race conditions is essential in concurrent programming. Think about accessing shared data structures.
* **Read-Write Locks (`pthread_rwlock_read`/`pthread_rwlock_write`):** Optimize for scenarios where reads are frequent and writes are less so. Good for managing data that's often read but occasionally updated.
* **`pthread_create`:** Starting new threads for concurrent tasks, background processing, etc. Core to Android's application execution model.
* **`pthread_exit`/`pthread_join`:**  Managing the lifecycle of threads.
* **Thread-Specific Data (`pthread_key_create`/`pthread_key_delete`):**  Another way to implement thread-local storage.

**5. Detailed Explanation of Libc Functions (Instruction 3):**

This is where deeper knowledge of operating systems and the implementation of threading primitives comes in. I consider the underlying mechanisms for each function:

* **`pthread_self`:**  Likely reading a thread-local variable or accessing a field in the thread's control block.
* **Thread-Specific Data (`pthread_getspecific`/`pthread_setspecific`, `pthread_key_create`/`pthread_key_delete`):**  Requires a mechanism to associate data with a thread and a key. This often involves a thread-local storage array or a hash map.
* **`pthread_once`:**  Needs an atomic flag to ensure the initialization function runs only once.
* **Mutexes (`pthread_mutex_lock`/`pthread_mutex_unlock`):** Involve operating system primitives like futexes or semaphores to implement locking and waiting. Different mutex types (normal, errorcheck, recursive, priority inheritance) have different semantics and implementations.
* **Read-Write Locks (`pthread_rwlock_rdlock`/`pthread_rwlock_wrlock`/`pthread_rwlock_unlock`):**  More complex than mutexes. They need to track the number of readers and manage writer access. Often implemented using semaphores and counters.
* **`pthread_create`:**  A system call to create a new thread (e.g., `clone` on Linux). This involves allocating resources for the new thread, setting up its stack, and starting its execution.
* **`pthread_exit`:**  Terminates the calling thread. Involves cleaning up thread-local storage and notifying the joining thread (if any).
* **`pthread_join`:**  Waits for a specific thread to terminate. Typically involves waiting on a synchronization object (like a semaphore) associated with the target thread.

**6. Dynamic Linker Functionality (Instruction 4):**

This requires understanding how shared libraries (`.so` files) are loaded and linked in Android.

* **SO Layout Sample:** I need to represent the basic structure of a shared library, including the ELF header, program headers (loadable segments), dynamic section, symbol tables, and relocation tables.
* **Symbol Handling:**  Distinguish between different types of symbols (defined, undefined, global, local). Explain how the dynamic linker resolves undefined symbols by searching through the symbol tables of loaded libraries. Mention PLT (Procedure Linkage Table) and GOT (Global Offset Table) for lazy symbol resolution.

**7. Logical Reasoning (Instruction 5):**

Since the code is primarily benchmarks, direct logical reasoning about input/output is limited. However, for functions like `pthread_getspecific` and `pthread_setspecific`, I can devise a simple scenario: set a value using `pthread_setspecific` and then retrieve it using `pthread_getspecific` within the same thread.

**8. Common Usage Errors (Instruction 6):**

Think about common pitfalls when working with threads:

* **Deadlocks:** Circular dependencies in lock acquisition.
* **Race Conditions:**  Unpredictable behavior due to interleaved access to shared resources without proper synchronization.
* **Memory Corruption:**  Accessing shared memory without synchronization.
* **Forgetting to join threads:**  Can lead to resource leaks.
* **Incorrect mutex usage:**  Double locking, unlocking the wrong mutex, etc.
* **Misunderstanding thread-local storage:**  Thinking data is shared when it's thread-local, or vice versa.

**9. Android Framework and NDK (Instruction 7):**

Trace the execution path from a high-level Android component down to the `pthread` calls:

* **Android Framework:**  UI operations, service management, etc., often happen on different threads. Examples: `AsyncTask`, `HandlerThread`, `IntentService`.
* **NDK:**  Native code directly uses `pthread` functions. JNI calls often involve thread management.
* **Bionic:**  The underlying implementation of `pthread` functions.

**Self-Correction/Refinement during the Process:**

* **Initially, I might focus too much on the *benchmark* aspect.**  I need to remember that the core request is about the `pthread` functions themselves.
* **For the dynamic linker section, I need to be careful to explain the concepts clearly without going into excessive technical detail.** The goal is understanding, not a deep dive into ELF internals.
* **When explaining libc function implementations, I should avoid making definitive statements about the *exact* implementation details, as they can vary across Bionic versions.**  Focus on the general mechanisms.
* **Make sure the examples for Android usage and common errors are clear and relevant.**

By following these steps and constantly reviewing the original request, I can generate a comprehensive and accurate answer. The key is to break down the problem into smaller, manageable parts and address each aspect systematically.
好的，我们来详细分析一下 `bionic/benchmarks/pthread_benchmark.cpp` 这个文件。

**1. 文件功能概览**

`pthread_benchmark.cpp` 的主要功能是**对 Android Bionic 库中 `pthread` 相关的函数进行性能基准测试 (benchmark)**。  它使用 Google Benchmark 框架来测量这些函数在不同场景下的执行时间，从而评估 Bionic 中线程操作的效率。

**2. 测试的功能列表及其与 Android 功能的关系**

该文件测试了以下 `pthread` 相关的功能：

* **`pthread_self()`**:  获取当前线程的 ID。
    * **Android 关系:**  在 Android 中，每个线程都有唯一的 ID。这对于调试、日志记录以及实现某些线程局部存储机制非常重要。例如，在 Native 代码中，你可以使用 `pthread_self()` 来区分不同的工作线程。
* **`pthread_getspecific()` / `pthread_setspecific()`**:  获取或设置线程特定数据 (Thread-Specific Data, TSD)。
    * **Android 关系:**  TSD 允许每个线程拥有其独立的全局变量副本。这在多线程环境下避免了数据竞争。例如，在 Android 的 `libc` 中，错误号 `errno` 就是通过 TSD 实现的，每个线程都有自己的 `errno` 副本。
* **`pthread_once()`**:  确保某个初始化函数只被调用一次，即使在多个线程中同时调用。
    * **Android 关系:**  用于执行只需要初始化一次的操作，例如初始化全局数据结构或单例模式的实例。在 Android 系统服务或 Native 库的初始化过程中经常用到。
* **`pthread_mutex_lock()` / `pthread_mutex_unlock()`**:  互斥锁的加锁和解锁操作，用于保护共享资源免受并发访问的影响。
    * **Android 关系:**  这是多线程同步的基本机制。Android 的许多组件，包括 Framework 层和 Native 层，都使用互斥锁来保护关键数据结构和代码段。例如，在 `SurfaceFlinger` 中，互斥锁用于保护图形缓冲区的访问。
* **`pthread_mutex_lock()` (不同类型):**  测试了普通互斥锁 (`PTHREAD_MUTEX_INITIALIZER`)、错误检查互斥锁 (`PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP`) 和递归互斥锁 (`PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP`)。
    * **Android 关系:**  不同类型的互斥锁提供了不同的错误检测和使用场景。例如，错误检查互斥锁可以检测到重复加锁的情况，有助于调试并发问题。递归互斥锁允许同一个线程多次加锁，适用于某些特定的设计模式。
* **`pthread_mutex_lock()` (带优先级继承):** 测试了带优先级继承的互斥锁。
    * **Android 关系:**  优先级继承用于解决优先级反转问题，即低优先级线程持有高优先级线程需要的锁，导致高优先级线程被阻塞。这在实时性要求高的系统中很重要，Android 某些低延迟音频路径可能会用到。
* **`pthread_rwlock_rdlock()` / `pthread_rwlock_wrlock()` / `pthread_rwlock_unlock()`**:  读写锁的获取读锁、获取写锁和解锁操作。读写锁允许多个线程同时读取共享资源，但只允许一个线程写入。
    * **Android 关系:**  适用于读操作远多于写操作的场景，例如缓存管理、配置信息的读取等。在 Android 的文件系统访问或某些系统服务的状态管理中可能会使用。
* **`pthread_create()` / `pthread_join()`**:  创建新线程和等待线程结束的操作。
    * **Android 关系:**  这是 Android 中创建并发执行任务的基本方式。无论是 Java 层的 `Thread` 或 `AsyncTask`，还是 Native 层的 `pthread_create`，最终都会调用到 Bionic 的 `pthread_create` 实现。
* **`pthread_exit()`**:  线程主动退出。
    * **Android 关系:**  用于结束一个线程的执行。在 Android 的线程模型中，线程可以主动退出，也可以被其他线程取消。
* **`pthread_key_create()` / `pthread_key_delete()`**:  创建和删除线程特定数据键。
    * **Android 关系:**  与 `pthread_getspecific` 和 `pthread_setspecific` 配合使用，用于管理线程特定数据的键。

**3. 详细解释每个 libc 函数的功能是如何实现的**

由于 `pthread` 函数的具体实现细节非常复杂，涉及到操作系统内核的调度和同步机制，这里只能给出大致的原理性解释：

* **`pthread_self()`**:  通常通过读取线程本地存储 (Thread Local Storage, TLS) 中的一个特定值来实现，这个值在线程创建时被设置。在 Linux 内核中，这个值可能存储在 `task_struct` 结构体中。
* **`pthread_getspecific(key)` / `pthread_setspecific(key, value)`**:
    * **`pthread_key_create()`**: 创建一个新的 TSD 键。这通常涉及到分配一个全局唯一的 ID，并可能需要维护一个全局的 TSD 键管理结构。
    * **`pthread_getspecific(key)`**:  每个线程都有一个关联的 TSD 数组或哈希表，其中存储了键值对。`pthread_getspecific` 根据提供的键，在当前线程的 TSD 结构中查找对应的值。
    * **`pthread_setspecific(key, value)`**: 将给定的值与键关联起来，存储到当前线程的 TSD 结构中。
* **`pthread_once(pthread_once_t *once_control, void (*init_routine)(void))`**:
    * `pthread_once_t` 通常包含一个状态标志。
    * 函数内部会检查 `once_control` 的状态。如果状态指示初始化尚未完成，则尝试使用原子操作（如 CAS - Compare and Swap）将状态更新为正在初始化。
    * 只有一个线程能够成功更新状态并执行 `init_routine`。其他线程会阻塞直到初始化完成。
* **`pthread_mutex_lock(pthread_mutex_t *mutex)` / `pthread_mutex_unlock(pthread_mutex_t *mutex)`**:
    * `pthread_mutex_t` 通常包含一个状态标志（指示锁是否被持有）以及一个等待队列。
    * **`pthread_mutex_lock()`**: 如果锁未被持有，则当前线程尝试获取锁（通常使用原子操作）。如果锁已被持有，则当前线程会被放入锁的等待队列中，并进入休眠状态。
    * **`pthread_mutex_unlock()`**: 释放锁。如果等待队列中有线程，则唤醒其中一个或多个线程，使其尝试获取锁。
    * **不同类型的互斥锁**:
        * **普通互斥锁**: 最基本的互斥锁。
        * **错误检查互斥锁**: 会检查重复加锁或解锁非自己持有的锁等错误。
        * **递归互斥锁**: 允许同一个线程多次加锁，需要在解锁时对应地解锁相同次数。
        * **优先级继承互斥锁**: 当高优先级线程等待低优先级线程持有的锁时，会临时提升低优先级线程的优先级，以避免优先级反转。
* **`pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)` / `pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)` / `pthread_rwlock_unlock(pthread_rwlock_t *rwlock)`**:
    * `pthread_rwlock_t` 通常包含读计数器、写标志和等待队列。
    * **`pthread_rwlock_rdlock()`**: 如果没有线程持有写锁，则增加读计数器。如果有写锁，则将当前线程加入读等待队列。
    * **`pthread_rwlock_wrlock()`**: 如果没有线程持有读锁或写锁，则设置写标志。否则，将当前线程加入写等待队列。
    * **`pthread_rwlock_unlock()`**: 如果释放的是读锁，则减少读计数器。如果释放的是写锁，则清除写标志。释放锁后，会根据等待队列的情况唤醒等待的读线程或写线程。
* **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`**:
    * 这是创建一个新线程的系统调用包装器。在 Linux 上，通常会调用 `clone()` 系统调用。
    * `clone()` 会创建一个新的执行上下文，包括独立的栈空间、寄存器状态等。
    * `start_routine` 是新线程执行的入口函数。
* **`pthread_exit(void *retval)`**:
    * 终止当前线程的执行。
    * 会清理线程相关的资源，例如线程本地存储。
    * `retval` 是线程的返回值，可以被 `pthread_join` 获取。
* **`pthread_join(pthread_t thread, void **retval)`**:
    * 调用线程会阻塞，直到指定的线程 `thread` 终止。
    * 如果 `retval` 不为空，则会将目标线程的返回值存储到 `retval` 指向的内存位置。
* **`pthread_key_create(pthread_key_t *key, void (*destructor)(void *))`**:
    * 分配一个新的线程特定数据键。
    * `destructor` 是一个可选的回调函数，当线程退出时，如果该键关联了数据，则会调用 `destructor` 来释放资源。
* **`pthread_key_delete(pthread_key_t key)`**:
    * 删除一个线程特定数据键。注意，这不会影响已经存在的线程的 TSD 值，只有新创建的线程不会再分配这个键。

**4. Dynamic Linker 的功能**

Dynamic Linker（在 Android 中主要是 `linker` 或 `linker64`）负责在程序运行时加载共享库（.so 文件）并将它们链接到可执行文件。其主要功能包括：

* **加载共享库:**  根据可执行文件或已加载库的依赖关系，找到并加载需要的共享库到内存中。这涉及到解析 ELF 文件头，确定加载地址，分配内存空间等。
* **符号解析 (Symbol Resolution):**  当程序或库引用了外部函数或变量时，Dynamic Linker 需要找到这些符号在哪个已加载的共享库中定义，并将引用地址重定向到实际的符号地址。
* **重定位 (Relocation):**  由于共享库被加载到内存中的地址可能不是编译时的地址，Dynamic Linker 需要修改代码和数据段中的某些地址引用，使其指向正确的运行时地址。
* **初始化:**  执行共享库中的初始化代码（例如，C++ 的全局对象的构造函数，使用 `__attribute__((constructor))` 标记的函数）。

**SO 布局样本:**

一个典型的 `.so` 文件的内存布局（简化版）可能如下：

```
+----------------------+  <- 加载基址
| ELF Header           |
+----------------------+
| Program Headers      |
+----------------------+
| .text (代码段)       |  <- 包含可执行指令
+----------------------+
| .rodata (只读数据段) |  <- 包含常量字符串等
+----------------------+
| .data (已初始化数据段)|  <- 包含已初始化的全局变量
+----------------------+
| .bss (未初始化数据段)|  <- 包含未初始化的全局变量
+----------------------+
| .dynamic (动态链接段)|  <- 包含动态链接器需要的信息，如依赖库列表、符号表位置等
+----------------------+
| .symtab (符号表)      |  <- 包含库中定义的符号信息
+----------------------+
| .strtab (字符串表)    |  <- 符号表中符号名称的字符串
+----------------------+
| .rel.dyn (动态重定位表)|  <- 数据段的重定位信息
+----------------------+
| .rel.plt (PLT重定位表)|  <- 函数调用的重定位信息
+----------------------+
| ...                  |
+----------------------+
```

**每种符号的处理过程:**

* **已定义全局符号 (Defined Global Symbols):**  在 `.symtab` 中有对应的条目，指示了符号的名称和地址。Dynamic Linker 会将这些符号的地址记录下来，供其他库解析引用时使用。
* **未定义全局符号 (Undefined Global Symbols):**  在 `.symtab` 中标记为未定义，表示该库引用了外部的符号。Dynamic Linker 会在加载其他共享库时查找这些符号的定义。
* **局部符号 (Local Symbols):**  在 `.symtab` 中标记为局部，通常只在定义它们的库内部可见。Dynamic Linker 主要在库内部处理这些符号，不会暴露给其他库。

**符号解析过程:**

1. **遇到外部符号引用:** 当程序或库执行到需要调用外部函数或访问外部变量时，会触发符号解析。
2. **查找符号表:** Dynamic Linker 会在已加载的共享库的符号表中搜索匹配的符号。搜索顺序通常是按照依赖关系进行的。
3. **重定位:** 找到符号定义后，Dynamic Linker 会更新程序或库中引用该符号的地址，使其指向符号在内存中的实际地址。
4. **延迟绑定 (Lazy Binding):** 为了提高启动速度，Android 默认使用延迟绑定。对于函数调用，Dynamic Linker 只在第一次调用时才进行符号解析和重定位。这通过 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 实现。首次调用时，会跳转到 PLT 中的一段代码，该代码会调用 Dynamic Linker 来解析符号，并将解析后的地址写入 GOT。后续调用将直接跳转到 GOT 中已解析的地址。

**5. 逻辑推理：假设输入与输出**

由于这个文件主要是性能测试，没有明显的输入和输出的逻辑处理。但我们可以针对某些测试的函数进行简单的逻辑推理：

* **`BM_pthread_getspecific` / `BM_pthread_setspecific`:**
    * **假设输入:**  一个已创建的 `pthread_key_t` 键，以及要设置的特定值。
    * **预期输出:** `pthread_setspecific` 应该成功将值与键关联，`pthread_getspecific` 应该能够返回之前设置的值。
* **`BM_pthread_once`:**
    * **假设输入:** 一个 `pthread_once_t` 变量和一个初始化函数。
    * **预期输出:** 初始化函数只会被执行一次，即使 `pthread_once` 被多次调用。

**6. 用户或编程常见的使用错误**

* **死锁 (Deadlock):**  多个线程互相等待对方释放资源，导致所有线程都无法继续执行。
    * **例子:** 线程 A 持有锁 1，尝试获取锁 2；线程 B 持有锁 2，尝试获取锁 1。
* **竞争条件 (Race Condition):**  程序的行为取决于多个线程执行的相对顺序，导致结果不可预测。
    * **例子:** 多个线程同时增加一个共享计数器，由于没有适当的同步机制，最终的计数值可能不正确。
* **忘记解锁互斥锁:**  导致其他需要访问相同资源的线程永久阻塞。
    * **例子:** 在一个函数中 `pthread_mutex_lock` 后，在某些错误处理路径上忘记调用 `pthread_mutex_unlock`。
* **对未初始化的互斥锁或读写锁进行操作:**  可能导致程序崩溃或未定义行为。
* **在信号处理程序中使用非异步信号安全的函数:**  `pthread` 中的许多函数不是异步信号安全的，在信号处理程序中调用可能导致问题。
* **错误地使用线程特定数据:**  例如，在线程退出后尝试访问其线程特定数据，或者在不同的线程中错误地共享线程特定数据的键。
* **资源泄漏:**  例如，创建了线程但忘记 `pthread_join`，可能导致线程资源无法回收。

**7. Android Framework 或 NDK 如何到达这里，作为调试线索**

作为调试线索，了解 Android Framework 或 NDK 如何使用 `pthread` 可以帮助定位问题。

* **Android Framework (Java 层):**
    1. **`java.lang.Thread`:**  当在 Java 代码中创建一个新的 `Thread` 对象并调用 `start()` 方法时，Android Runtime (ART) 会创建一个 native 线程。
    2. **`AsyncTask`:**  虽然 `AsyncTask` 内部使用了线程池，但最终执行任务仍然是在后台线程中进行的。
    3. **`HandlerThread`:**  一个带有消息循环的线程，常用于在后台执行特定的任务。
    4. **`IntentService`:**  在后台处理异步请求的服务，内部使用一个工作线程。
    5. **Binder 线程池:**  Android 的进程间通信 (IPC) 机制 Binder 使用线程池来处理来自其他进程的请求。
    6. **系统服务:**  许多 Android 系统服务都在独立的线程中运行。
    7. **Native 方法调用 (JNI):**  Java 代码可以通过 JNI 调用 Native 代码。Native 代码可以直接使用 `pthread` 函数。

* **Android NDK (Native 层):**
    1. **直接使用 `pthread` API:**  Native 代码可以直接包含 `<pthread.h>` 并调用 `pthread_create` 等函数来创建和管理线程。
    2. **C++ 标准库的线程:**  C++11 引入了 `<thread>` 库，其底层实现通常也是基于 `pthread`。
    3. **第三方 Native 库:**  许多第三方 Native 库也使用 `pthread` 来实现并发。

**调试线索:**

1. **分析堆栈信息 (Stack Trace):** 当程序崩溃或出现问题时，查看堆栈信息可以了解当前线程的执行路径。如果堆栈中包含 `pthread` 相关的函数，则表明问题可能与线程同步或管理有关。
2. **使用调试器 (Debugger):**  例如 `gdb` 或 Android Studio 的调试器，可以单步执行代码，查看线程的状态、锁的持有情况、变量的值等。
3. **使用性能分析工具:**  例如 Systrace、Perfetto 等，可以分析线程的执行情况、锁的争用情况，帮助识别性能瓶颈或死锁。
4. **日志记录:**  在关键的代码段添加日志，记录线程 ID、锁的状态等信息，可以帮助追踪线程的执行流程。
5. **静态分析工具:**  一些静态分析工具可以检测潜在的并发问题，例如死锁、竞争条件等。

总而言之，`bionic/benchmarks/pthread_benchmark.cpp` 是一个用于测试 Android Bionic 库中 `pthread` 函数性能的工具，它涵盖了线程创建、同步、线程特定数据等多个方面，这些功能是 Android 系统多线程编程的基础。理解这些函数的实现原理和使用场景，以及可能出现的错误，对于开发高效稳定的 Android 应用至关重要。

### 提示词
```
这是目录为bionic/benchmarks/pthread_benchmark.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pthread.h>

#include <benchmark/benchmark.h>
#include "util.h"

// Stop GCC optimizing out our pure function.
/* Must not be static! */ pthread_t (*pthread_self_fp)() = pthread_self;

static void BM_pthread_self(benchmark::State& state) {
  while (state.KeepRunning()) {
    pthread_self_fp();
  }
}
BIONIC_BENCHMARK(BM_pthread_self);

static void BM_pthread_getspecific(benchmark::State& state) {
  pthread_key_t key;
  pthread_key_create(&key, nullptr);

  while (state.KeepRunning()) {
    pthread_getspecific(key);
  }

  pthread_key_delete(key);
}
BIONIC_BENCHMARK(BM_pthread_getspecific);

static void BM_pthread_setspecific(benchmark::State& state) {
  pthread_key_t key;
  pthread_key_create(&key, nullptr);

  while (state.KeepRunning()) {
    pthread_setspecific(key, nullptr);
  }

  pthread_key_delete(key);
}
BIONIC_BENCHMARK(BM_pthread_setspecific);

static void NoOpPthreadOnceInitFunction() {}

static void BM_pthread_once(benchmark::State& state) {
  static pthread_once_t once = PTHREAD_ONCE_INIT;
  pthread_once(&once, NoOpPthreadOnceInitFunction);

  while (state.KeepRunning()) {
    pthread_once(&once, NoOpPthreadOnceInitFunction);
  }
}
BIONIC_BENCHMARK(BM_pthread_once);

static void BM_pthread_mutex_lock(benchmark::State& state) {
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

  while (state.KeepRunning()) {
    pthread_mutex_lock(&mutex);
    pthread_mutex_unlock(&mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock);

#if !defined(ANDROID_HOST_MUSL)
static void BM_pthread_mutex_lock_ERRORCHECK(benchmark::State& state) {
  pthread_mutex_t mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

  while (state.KeepRunning()) {
    pthread_mutex_lock(&mutex);
    pthread_mutex_unlock(&mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock_ERRORCHECK);
#endif

#if !defined(ANDROID_HOST_MUSL)
static void BM_pthread_mutex_lock_RECURSIVE(benchmark::State& state) {
  pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

  while (state.KeepRunning()) {
    pthread_mutex_lock(&mutex);
    pthread_mutex_unlock(&mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock_RECURSIVE);
#endif

namespace {
struct PIMutex {
  pthread_mutex_t mutex;

  explicit PIMutex(int type) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, type);
    pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&mutex, &attr);
    pthread_mutexattr_destroy(&attr);
  }

  ~PIMutex() {
    pthread_mutex_destroy(&mutex);
  }
};
}

static void BM_pthread_mutex_lock_PI(benchmark::State& state) {
  PIMutex m(PTHREAD_MUTEX_NORMAL);

  while (state.KeepRunning()) {
    pthread_mutex_lock(&m.mutex);
    pthread_mutex_unlock(&m.mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock_PI);

static void BM_pthread_mutex_lock_ERRORCHECK_PI(benchmark::State& state) {
  PIMutex m(PTHREAD_MUTEX_ERRORCHECK);

  while (state.KeepRunning()) {
    pthread_mutex_lock(&m.mutex);
    pthread_mutex_unlock(&m.mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock_ERRORCHECK_PI);

static void BM_pthread_mutex_lock_RECURSIVE_PI(benchmark::State& state) {
  PIMutex m(PTHREAD_MUTEX_RECURSIVE);

  while (state.KeepRunning()) {
    pthread_mutex_lock(&m.mutex);
    pthread_mutex_unlock(&m.mutex);
  }
}
BIONIC_BENCHMARK(BM_pthread_mutex_lock_RECURSIVE_PI);

static void BM_pthread_rwlock_read(benchmark::State& state) {
  pthread_rwlock_t lock;
  pthread_rwlock_init(&lock, nullptr);

  while (state.KeepRunning()) {
    pthread_rwlock_rdlock(&lock);
    pthread_rwlock_unlock(&lock);
  }

  pthread_rwlock_destroy(&lock);
}
BIONIC_BENCHMARK(BM_pthread_rwlock_read);

static void BM_pthread_rwlock_write(benchmark::State& state) {
  pthread_rwlock_t lock;
  pthread_rwlock_init(&lock, nullptr);

  while (state.KeepRunning()) {
    pthread_rwlock_wrlock(&lock);
    pthread_rwlock_unlock(&lock);
  }

  pthread_rwlock_destroy(&lock);
}
BIONIC_BENCHMARK(BM_pthread_rwlock_write);

static void* IdleThread(void*) {
  return nullptr;
}

static void BM_pthread_create(benchmark::State& state) {
  while (state.KeepRunning()) {
    pthread_t thread;
    pthread_create(&thread, nullptr, IdleThread, nullptr);
    state.PauseTiming();
    pthread_join(thread, nullptr);
    state.ResumeTiming();
  }
}
BIONIC_BENCHMARK(BM_pthread_create);

static void* RunThread(void*) {
  return nullptr;
}

static void BM_pthread_create_and_run(benchmark::State& state) {
  while (state.KeepRunning()) {
    pthread_t thread;
    pthread_create(&thread, nullptr, RunThread, &state);
    pthread_join(thread, nullptr);
  }
}
BIONIC_BENCHMARK(BM_pthread_create_and_run);

static void* ExitThread(void*) {
  pthread_exit(nullptr);
}

static void BM_pthread_exit_and_join(benchmark::State& state) {
  while (state.KeepRunning()) {
    pthread_t thread;
    pthread_create(&thread, nullptr, ExitThread, nullptr);
    pthread_join(thread, nullptr);
  }
}
BIONIC_BENCHMARK(BM_pthread_exit_and_join);

static void BM_pthread_key_create(benchmark::State& state) {
  while (state.KeepRunning()) {
    pthread_key_t key;
    pthread_key_create(&key, nullptr);

    state.PauseTiming();
    pthread_key_delete(key);
    state.ResumeTiming();
  }
}
BIONIC_BENCHMARK(BM_pthread_key_create);

static void BM_pthread_key_delete(benchmark::State& state) {
  while (state.KeepRunning()) {
    state.PauseTiming();
    pthread_key_t key;
    pthread_key_create(&key, nullptr);
    state.ResumeTiming();

    pthread_key_delete(key);
  }
}
BIONIC_BENCHMARK(BM_pthread_key_delete);
```