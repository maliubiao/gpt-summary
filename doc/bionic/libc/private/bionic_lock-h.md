Response:
Let's break down the thought process for analyzing this C++ header file and generating the detailed Chinese response.

**1. Understanding the Request:**

The core request is to analyze the provided C++ code snippet from Android's Bionic library, specifically the `bionic_lock.handroid`. The analysis should cover its functionality, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's used within the Android framework/NDK, including a Frida hook example.

**2. Initial Code Scan and Identification of Key Elements:**

First, I scanned the code for the main components:

* **`class Lock`:**  This is clearly the central entity, representing a lock.
* **`enum LockState`:** Defines the possible states of the lock (Unlocked, LockedWithoutWaiter, LockedWithWaiter).
* **`_Atomic(LockState) state`:**  Indicates this is an atomic variable used for managing the lock state, crucial for thread safety.
* **`bool process_shared`:**  Suggests the lock can be used for inter-process synchronization.
* **`init()`, `trylock()`, `lock()`, `unlock()`:** These are the standard lock operations.
* **`__futex_wait_ex()`, `__futex_wake_ex()`:**  These clearly indicate the use of futex system calls, a low-level mechanism for synchronization in Linux (and Android).
* **`class LockGuard`:**  This is a RAII (Resource Acquisition Is Initialization) wrapper for `Lock`, ensuring the lock is automatically released when the `LockGuard` object goes out of scope.
* **`BIONIC_DISALLOW_COPY_AND_ASSIGN(LockGuard)`:**  Prevents accidental copying of `LockGuard` objects, maintaining the intended ownership semantics.

**3. Deconstructing the Functionality of `Lock`:**

I then analyzed each member function of the `Lock` class:

* **`init()`:** Straightforward initialization, setting the initial state to `Unlocked`. The `process_shared` flag is stored.
* **`trylock()`:**  A non-blocking attempt to acquire the lock. The key is the `atomic_compare_exchange_strong_explicit`. I focused on what this atomic operation does: try to change the state from `Unlocked` to `LockedWithoutWaiter` *only if* the current state is `Unlocked`.
* **`lock()`:**  A blocking attempt to acquire the lock. This is more complex:
    * It first tries a quick, non-blocking acquisition like `trylock()`.
    * If that fails, it enters a loop.
    * Inside the loop, it atomically sets the state to `LockedWithWaiter`.
    * If the previous state was `Unlocked`, the lock is acquired.
    * Otherwise, it calls `__futex_wait_ex()` to put the thread to sleep until the lock is released.
* **`unlock()`:** Releases the lock. Crucially, it checks if there were waiters (`LockedWithWaiter`). If so, it calls `__futex_wake_ex()` to wake up one of the waiting threads. The comment about potential deallocation is important and needs to be included in the explanation.

**4. Deconstructing the Functionality of `LockGuard`:**

This is simpler. It's a classic RAII pattern: acquire the lock in the constructor, release it in the destructor. This simplifies lock management and prevents forgetting to unlock.

**5. Identifying Relationships with Android Features:**

The key relationship is with thread synchronization. I connected it to `pthread_rwlock_t` (mentioned in the comment) and general mutex-like behavior. The `process_shared` flag immediately points to inter-process communication and shared memory.

**6. Dynamic Linking Aspects:**

The code itself doesn't *directly* involve dynamic linking. However, the fact that it's part of Bionic, the C library, means it's *used* by dynamically linked libraries. Therefore, the explanation needed to cover:

* How this code would be present in `libc.so`.
* A simple example of a dynamically linked library using this lock.
* The linking process where the dynamic linker resolves the symbols for the lock operations.

**7. Potential User Errors:**

The most obvious error is forgetting to unlock a mutex. `LockGuard` helps prevent this. Other errors include deadlock situations and using the lock incorrectly in multi-threaded contexts.

**8. Android Framework/NDK Usage and Frida Hooking:**

This required thinking about how this low-level lock is used by higher-level Android components. The path goes from Java framework (e.g., `synchronized` blocks) down to native code using NDK, which eventually relies on Bionic's primitives. A concrete example, like accessing shared preferences concurrently, was necessary.

The Frida hook example needed to target the `lock()` and `unlock()` functions to demonstrate how to observe their behavior.

**9. Structuring the Response:**

I decided on a structured approach for clarity:

* **功能列举:**  A concise summary of the class functionalities.
* **与 Android 功能的关系:**  Explaining the connection to threading and IPC.
* **libc 函数实现:**  Detailed explanations of `lock()`, `trylock()`, and `unlock()`.
* **Dynamic Linker 功能:**  Illustrating the dynamic linking aspect with a simple scenario and explaining the linking process.
* **逻辑推理 (假设输入与输出):** Providing a simple multi-threaded example demonstrating the lock's behavior.
* **用户或编程常见错误:**  Listing common pitfalls.
* **Android Framework/NDK 到达路径:**  Tracing the usage from Java to native code.
* **Frida Hook 示例:**  Providing a practical Frida script.

**10. Refinement and Language:**

Throughout the process, I focused on clear and concise Chinese explanations. I paid attention to terminology related to concurrency and system programming. I also made sure to address all the specific points in the original request.

This systematic approach, from initial code comprehension to detailed analysis and example creation, allowed me to generate a comprehensive and accurate response to the user's request.
这个 `bionic/libc/private/bionic_lock.handroid` 文件定义了两个 C++ 类：`Lock` 和 `LockGuard`，它们提供了一种基础的互斥锁（mutex）实现。由于它位于 Bionic 库的私有目录中，这表明它很可能是 Bionic 内部使用的，而不是直接暴露给 Android NDK 开发者的公共 API。

**`Lock` 类的功能:**

`Lock` 类实现了一个简单的互斥锁，其主要功能包括：

1. **初始化 (`init`)**:  允许初始化锁对象，可以指定该锁是否为进程共享。进程共享的锁可以用于不同进程之间的同步。
2. **尝试加锁 (`trylock`)**: 尝试获取锁，如果锁当前未被占用，则立即获取并返回 `true`；如果锁已被占用，则立即返回 `false`，不会阻塞。
3. **加锁 (`lock`)**: 尝试获取锁。如果锁当前未被占用，则获取锁并返回。如果锁已被占用，则当前线程会阻塞，直到锁被释放。
4. **解锁 (`unlock`)**: 释放当前线程持有的锁。如果存在等待该锁的线程，则会唤醒其中一个等待的线程。

**`LockGuard` 类的功能:**

`LockGuard` 类是一个 RAII (Resource Acquisition Is Initialization) 风格的锁管理助手。它的功能是：

1. **构造函数**:  在 `LockGuard` 对象创建时，自动调用关联的 `Lock` 对象的 `lock()` 方法，获取锁。
2. **析构函数**:  在 `LockGuard` 对象销毁时，自动调用关联的 `Lock` 对象的 `unlock()` 方法，释放锁。

这种设计模式确保了锁的获取和释放总是成对出现，即使在发生异常的情况下，锁也能被正确释放，从而避免死锁。

**与 Android 功能的关系及举例说明:**

由于 `Lock` 类是 Bionic 库内部使用的，它直接支持了 Android 系统中各种需要同步的场景。以下是一些例子：

* **`pthread_rwlock_t` 的实现**:  代码中的注释提到 `Lock` 被用于像 `pthread_rwlock_t` 这样的结构中。`pthread_rwlock_t` 是 POSIX 线程库中的读写锁，允许多个线程同时读取共享资源，但只允许一个线程写入。Bionic 的 `pthread_rwlock_t` 内部很可能使用了 `Lock` 来保护其内部状态。
* **Binder 机制**: Android 的 Binder 机制用于进程间通信 (IPC)。在 Binder 驱动和库的实现中，为了保证数据的一致性和避免竞态条件，会使用锁来同步对共享资源的访问。`Lock` 类可能被用于保护 Binder 节点、引用计数等关键数据结构。
* **Zygote 进程**: Zygote 是 Android 系统中所有应用进程的父进程。当 Zygote fork 新的应用进程时，需要确保共享资源的同步。`Lock` 类可能被用于保护 Zygote 进程中的某些共享数据结构，防止在 fork 期间发生问题。
* **Android Runtime (ART) 的内部同步**: ART 是 Android 的运行时环境。在 ART 的内部实现中，例如在垃圾回收、对象分配等关键操作中，需要使用锁来保证线程安全。`Lock` 类可能被用作这些同步原语的基础构建块。

**libc 函数的实现细节:**

`Lock` 类本身并不是 libc 的标准函数，而是 Bionic 库自定义的同步原语。它使用了以下机制来实现锁的功能：

* **原子操作 (`std::atomic`)**: `state` 成员变量是一个原子变量，这保证了对 `state` 的读写操作是原子性的，不会发生数据竞争。代码中使用了 `atomic_compare_exchange_strong_explicit` 和 `atomic_exchange_explicit` 等原子操作。
    * **`atomic_compare_exchange_strong_explicit(&state, &old_state, new_state, success_memorder, failure_memorder)`**:  这是一个比较并交换操作。它原子地比较 `state` 的当前值是否等于 `old_state`。如果是，则将 `state` 的值设置为 `new_state`，并返回 `true`。否则，将 `old_state` 的值更新为 `state` 的当前值，并返回 `false`。`memory_order` 参数指定了内存排序约束。
    * **`atomic_exchange_explicit(&state, new_state, memory_order)`**: 原子地将 `state` 的值设置为 `new_state`，并返回 `state` 的旧值。
* **Futex (`__futex_wait_ex`, `__futex_wake_ex`)**:  Futex (fast userspace mutex) 是 Linux 提供的一种轻量级同步机制。
    * **`__futex_wait_ex(&state, process_shared, LockedWithWaiter)`**: 当线程尝试获取锁但锁已被占用时，会调用 `__futex_wait_ex` 将线程放入等待队列并休眠。只有当 `state` 的值等于 `LockedWithWaiter` 时才会进入休眠。`process_shared` 参数指定该 futex 是否为进程共享。
    * **`__futex_wake_ex(&state, shared, 1)`**: 当持有锁的线程释放锁时，如果存在等待的线程，会调用 `__futex_wake_ex` 唤醒等待队列中的一个线程。`shared` 参数与 `__futex_wait_ex` 中的 `process_shared` 对应。

**`lock()` 函数的实现逻辑:**

1. 首先尝试使用原子操作 `atomic_compare_exchange_strong_explicit` 将 `state` 从 `Unlocked` 状态切换到 `LockedWithoutWaiter` 状态。如果成功，则表示成功获取了锁，直接返回。这是一个快速路径，避免了系统调用。
2. 如果第一步失败（锁已被占用），则进入一个循环。
3. 在循环中，使用 `atomic_exchange_explicit` 原子地将 `state` 设置为 `LockedWithWaiter`。
4. 检查 `atomic_exchange_explicit` 的返回值。如果返回值是 `Unlocked`，这意味着在当前线程尝试将状态设置为 `LockedWithWaiter` 的同时，另一个线程释放了锁，并且当前线程成功抢到了锁，循环结束。
5. 如果 `atomic_exchange_explicit` 的返回值不是 `Unlocked`，则调用 `__futex_wait_ex` 将当前线程放入等待队列并休眠，等待锁被释放。
6. 当锁被释放并且当前线程被唤醒后，循环继续，直到成功获取锁。

**`unlock()` 函数的实现逻辑:**

1. 使用 `atomic_exchange_explicit` 原子地将 `state` 设置回 `Unlocked` 状态，并获取 `state` 的旧值。
2. 如果旧值是 `LockedWithWaiter`，表示在解锁之前有线程在等待该锁，因此调用 `__futex_wake_ex` 唤醒一个等待的线程。
3. 代码中特别提到了一个潜在的问题：在原子交换和 futex 唤醒之间，`Lock` 对象可能已被释放。为了避免访问已释放的内存，`__futex_wake_ex` 的第一个参数直接使用了 `&state`，而没有访问 `Lock` 对象的其他成员。

**Dynamic Linker 的功能与处理过程:**

这个源代码文件本身并没有直接涉及 dynamic linker 的功能，因为它定义的是一个锁的实现，而不是一个可以被动态链接的库。然而，`Lock` 类所在的 Bionic 库 (`libc.so`) 本身就是一个会被动态链接的共享库。

**so 布局样本:**

假设有一个名为 `libmylib.so` 的共享库，它使用了 `bionic_lock.handroid` 中定义的 `Lock` 类（尽管实际上开发者不会直接使用私有 API）。

```
libmylib.so:
    .text
        my_function:
            ; ... 使用 Lock 进行同步的代码 ...
            call    _ZN4Lock4lockEv  // 调用 Lock::lock()
            ; ... 临界区 ...
            call    _ZN4Lock6unlockEv // 调用 Lock::unlock()
            ret

    .data
        my_lock:
            .zero   sizeof(Lock)     // Lock 对象

    .dynamic
        ...
        NEEDED      libc.so          // 依赖 libc.so
        ...
        SYMTAB
        STRTAB
        ...
```

**链接的处理过程:**

1. **编译时**: 当 `libmylib.so` 被编译时，如果代码中使用了 `Lock` 类，编译器会生成对 `Lock::lock()` 和 `Lock::unlock()` 等方法的符号引用（例如 `_ZN4Lock4lockEv`，这是 C++ mangled name）。由于 `Lock` 类是在 Bionic 的私有头文件中定义的，直接使用通常会导致编译错误。但假设我们能够访问到这些定义。
2. **链接时**: 链接器在链接 `libmylib.so` 时，会解析这些符号引用。由于 `Lock` 类的实现位于 `libc.so` 中，链接器会将 `libmylib.so` 标记为依赖于 `libc.so`。
3. **运行时**: 当 Android 系统加载 `libmylib.so` 时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
    * **加载依赖库**: 首先加载 `libmylib.so` 依赖的 `libc.so`。
    * **符号解析 (Symbol Resolution)**: 动态链接器会在 `libc.so` 的符号表（`.symtab`）中查找 `libmylib.so` 中未解析的符号，例如 `Lock::lock()` 和 `Lock::unlock()`。
    * **重定位 (Relocation)**: 找到这些符号的地址后，动态链接器会更新 `libmylib.so` 中调用这些函数的指令，将占位符地址替换为 `libc.so` 中实际函数的地址。这样，在 `libmylib.so` 运行时，调用 `Lock::lock()` 就会跳转到 `libc.so` 中 `Lock::lock()` 的实现代码。

**逻辑推理 (假设输入与输出):**

假设有两个线程 A 和 B 尝试访问受 `Lock` 对象 `my_lock` 保护的临界区。

**场景:**

1. **线程 A 首先执行 `my_lock.lock()`**:
   - 假设 `my_lock` 的初始状态是 `Unlocked`。
   - `atomic_compare_exchange_strong_explicit` 会成功将 `state` 从 `Unlocked` 变为 `LockedWithoutWaiter`。
   - `my_lock.lock()` 返回，线程 A 进入临界区。

2. **线程 B 接着执行 `my_lock.lock()`**:
   - `atomic_compare_exchange_strong_explicit` 失败，因为 `state` 已经是 `LockedWithoutWaiter`。
   - 线程 B 进入循环，并将 `state` 原子地设置为 `LockedWithWaiter`。
   - 由于之前的状态不是 `Unlocked`，线程 B 调用 `__futex_wait_ex` 进入休眠状态。

3. **线程 A 执行完毕，调用 `my_lock.unlock()`**:
   - `atomic_exchange_explicit` 将 `state` 设置回 `Unlocked`，并返回旧值 `LockedWithWaiter`。
   - 由于旧值是 `LockedWithWaiter`，`__futex_wake_ex` 被调用，唤醒线程 B。

4. **线程 B 被唤醒，继续执行 `my_lock.lock()`**:
   - 线程 B 从 `__futex_wait_ex` 返回。
   - 循环继续，此时 `state` 是 `Unlocked`。
   - `atomic_compare_exchange_strong_explicit` 会成功将 `state` 从 `Unlocked` 变为 `LockedWithoutWaiter`。
   - 线程 B 进入临界区。

**涉及用户或者编程常见的使用错误:**

1. **忘记解锁**: 如果在持有锁的情况下，由于逻辑错误或异常导致 `unlock()` 没有被调用，就会发生死锁。其他线程将永远无法获取该锁。
   ```c++
   void some_function(Lock& lock) {
       lock.lock();
       // ... 访问共享资源 ...
       if (some_error_condition) {
           return; // 忘记 unlock
       }
       lock.unlock();
   }
   ```
   `LockGuard` 可以帮助避免这种错误：
   ```c++
   void some_function(Lock& lock) {
       LockGuard guard(lock);
       // ... 访问共享资源 ...
       if (some_error_condition) {
           return; // 即使提前返回，guard 的析构函数也会解锁
       }
   }
   ```

2. **死锁**: 当多个线程互相持有对方需要的锁时，就会发生死锁。例如：
   ```c++
   Lock lock1, lock2;

   void thread1_func() {
       lock1.lock();
       // ...
       lock2.lock(); // 线程 1 尝试获取 lock2
       // ...
       lock2.unlock();
       lock1.unlock();
   }

   void thread2_func() {
       lock2.lock();
       // ...
       lock1.lock(); // 线程 2 尝试获取 lock1
       // ...
       lock1.unlock();
       lock2.unlock();
   }
   ```
   如果线程 1 持有 `lock1`，线程 2 持有 `lock2`，它们会互相等待对方释放锁，导致死锁。

3. **在中断上下文中使用**: 通常，锁的实现可能会导致线程休眠等待，这在中断上下文中是不允许的。

4. **过度使用锁**:  如果锁的粒度过大，会导致并发性降低，因为即使某些操作不需要同步，也会因为持有锁而被阻塞。

**Android Framework or NDK 是如何一步步的到达这里:**

虽然 `bionic_lock.handroid` 是一个私有头文件，NDK 开发者通常不会直接使用它。但是，Android Framework 和 NDK 提供的更高级的同步机制最终会依赖于像 `Lock` 这样的底层原语。以下是一个可能的路径：

1. **Android Framework (Java)**:
   - 开发者在 Java 代码中使用 `synchronized` 关键字或者 `java.util.concurrent` 包中的类（如 `ReentrantLock`）。
   ```java
   public class MyClass {
       private final Object myLock = new Object();

       public void myMethod() {
           synchronized (myLock) {
               // 访问共享资源
           }
       }
   }
   ```
2. **ART (Android Runtime)**:
   - 当 Java 代码执行到 `synchronized` 块时，ART 会调用底层的 native 方法来获取和释放锁。`java.util.concurrent` 中的锁通常也是基于 native 代码实现的。
3. **Native Libraries (NDK)**:
   - NDK 开发者可以使用 POSIX 线程 API，例如 `pthread_mutex_t`。
   ```c++
   #include <pthread.h>

   pthread_mutex_t my_mutex = PTHREAD_MUTEX_INITIALIZER;

   void my_native_function() {
       pthread_mutex_lock(&my_mutex);
       // 访问共享资源
       pthread_mutex_unlock(&my_mutex);
   }
   ```
4. **Bionic Library (`libc.so`)**:
   - Bionic 库提供了 `pthread_mutex_t` 等 POSIX 线程 API 的实现。`pthread_mutex_lock` 等函数内部会使用更底层的同步原语，例如 `futex`。
   - 正如代码注释所示，`bionic_lock.handroid` 中定义的 `Lock` 类很可能被用于实现 `pthread_mutex_t` 或其他同步结构。

**Frida Hook 示例调试步骤:**

假设我们想要观察某个使用 `Lock` 类的 native 库（例如，假设某个系统服务内部使用了这个私有 API）。

**目标**: Hook `Lock::lock()` 和 `Lock::unlock()` 方法。

**假设**: 目标进程中加载了使用 `Lock` 类的库，并且我们知道 `Lock` 类在内存中的布局（可以通过调试或分析获取）。

**Frida Script:**

```javascript
// 假设目标进程中 Lock 类的地址可以通过某种方式找到，例如符号表或内存扫描
// 这里使用一个占位符地址
const lock_addr = Module.findExportByName("libc.so", "_ZN4Lock4lockEv");
const unlock_addr = Module.findExportByName("libc.so", "_ZN4Lock6unlockEv");

if (lock_addr) {
  Interceptor.attach(lock_addr, {
    onEnter: function(args) {
      console.log("[Lock::lock] Thread ID:", Process.getCurrentThreadId());
      // 'this' 指向 Lock 对象实例
      console.log("[Lock::lock] Lock object address:", this.toString());
    }
  });
} else {
  console.error("Could not find Lock::lock");
}

if (unlock_addr) {
  Interceptor.attach(unlock_addr, {
    onEnter: function(args) {
      console.log("[Lock::unlock] Thread ID:", Process.getCurrentThreadId());
      // 'this' 指向 Lock 对象实例
      console.log("[Lock::unlock] Lock object address:", this.toString());
    }
  });
} else {
  console.error("Could not find Lock::unlock");
}
```

**调试步骤:**

1. **找到目标进程**: 使用 `frida -U -f <package_name>` 或 `frida -U <process_name_or_pid>` 连接到目标进程。
2. **加载 Frida 脚本**: 将上面的 JavaScript 代码保存为 `.js` 文件，然后使用 `frida -U -l your_script.js <process_name_or_pid>` 运行脚本。
3. **触发锁操作**: 在目标应用中执行会导致使用 `Lock` 类的操作。
4. **观察输出**: Frida 会在控制台输出 `Lock::lock()` 和 `Lock::unlock()` 被调用时的信息，包括线程 ID 和 `Lock` 对象的地址。

**更精细的 Hook (如果需要查看 `Lock` 对象的成员变量):**

```javascript
const lock_addr = Module.findExportByName("libc.so", "_ZN4Lock4lockEv");
const unlock_addr = Module.findExportByName("libc.so", "_ZN4Lock6unlockEv");

// 假设我们知道 LockState enum 的值：Unlocked = 0, LockedWithoutWaiter = 1, LockedWithWaiter = 2
const LockState = {
  Unlocked: 0,
  LockedWithoutWaiter: 1,
  LockedWithWaiter: 2
};

if (lock_addr) {
  Interceptor.attach(lock_addr, {
    onEnter: function(args) {
      const lockObj = this.context.r0; // 假设 'this' 指针在 ARM64 架构的 r0 寄存器中
      const statePtr = lockObj.add(0); // 'state' 成员通常在 Lock 对象的起始位置
      const state = Memory.readU32(statePtr);
      const processSharedPtr = lockObj.add(4); // 假设 'process_shared' 在 'state' 之后
      const processShared = Memory.readU8(processSharedPtr);

      console.log("[Lock::lock] Thread ID:", Process.getCurrentThreadId());
      console.log("[Lock::lock] Lock object address:", lockObj);
      console.log("[Lock::lock] State:", state, `(${Object.keys(LockState).find(key => LockState[key] === state)})`);
      console.log("[Lock::lock] Process Shared:", processShared);
    }
  });
}

// ... 类似的 hook unlock 函数 ...
```

**注意**: 上面的 Frida 示例需要根据目标架构和编译器的具体实现进行调整，例如 `this` 指针的位置和成员变量的偏移量。通常需要通过调试信息或反汇编来确定这些细节。由于 `bionic_lock.handroid` 是私有 API，直接 hook 可能会比较困难，因为符号可能不会被导出，或者名称可能会被混淆。

Prompt: 
```
这是目录为bionic/libc/private/bionic_lock.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdatomic.h>
#include "private/bionic_futex.h"
#include "platform/bionic/macros.h"

// Lock is used in places like pthread_rwlock_t, which can be initialized without calling
// an initialization function. So make sure Lock can be initialized by setting its memory to 0.
class Lock {
 private:
  enum LockState {
    Unlocked = 0,
    LockedWithoutWaiter,
    LockedWithWaiter,
  };
  _Atomic(LockState) state;
  bool process_shared;

 public:
  void init(bool process_shared) {
    atomic_store_explicit(&state, Unlocked, memory_order_relaxed);
    this->process_shared = process_shared;
  }

  bool trylock() {
    LockState old_state = Unlocked;
    return __predict_true(atomic_compare_exchange_strong_explicit(&state, &old_state,
                        LockedWithoutWaiter, memory_order_acquire, memory_order_relaxed));
  }

  void lock() {
    LockState old_state = Unlocked;
    if (__predict_true(atomic_compare_exchange_strong_explicit(&state, &old_state,
                         LockedWithoutWaiter, memory_order_acquire, memory_order_relaxed))) {
      return;
    }
    while (atomic_exchange_explicit(&state, LockedWithWaiter, memory_order_acquire) != Unlocked) {
      // TODO: As the critical section is brief, it is a better choice to spin a few times befor sleeping.
      __futex_wait_ex(&state, process_shared, LockedWithWaiter);
    }
    return;
  }

  void unlock() {
    bool shared = process_shared; /* cache to local variable */
    if (atomic_exchange_explicit(&state, Unlocked, memory_order_release) == LockedWithWaiter) {
      // The Lock object may have been deallocated between the atomic exchange and the futex wake
      // call, so avoid accessing any fields of Lock here. In that case, the wake call may target
      // unmapped memory or trigger a spurious futex wakeup. The same situation happens with
      // pthread mutexes. References:
      //  - https://lkml.org/lkml/2014/11/27/472
      //  - http://austingroupbugs.net/view.php?id=811#c2267
      __futex_wake_ex(&state, shared, 1);
    }
  }
};

class LockGuard {
 public:
  explicit LockGuard(Lock& lock) : lock_(lock) {
    lock_.lock();
  }
  ~LockGuard() {
    lock_.unlock();
  }

  BIONIC_DISALLOW_COPY_AND_ASSIGN(LockGuard);

 private:
  Lock& lock_;
};

"""

```