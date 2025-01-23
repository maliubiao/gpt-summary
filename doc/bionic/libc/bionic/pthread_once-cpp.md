Response:
Let's break down the thought process for analyzing the `pthread_once.cpp` code and generating the comprehensive response.

**1. Understanding the Core Function:**

The first and most crucial step is to understand the purpose of `pthread_once`. The name itself is a big clue: it's about executing a function *once*, even if called by multiple threads concurrently. This immediately brings threading synchronization and atomicity to mind.

**2. Analyzing the Code Structure and Key Components:**

Next, I would dissect the code itself, focusing on:

* **Includes:** `pthread.h`, `stdatomic.h`, `private/bionic_futex.h`. These tell us the function is related to threading, uses atomic operations for thread safety, and interacts with the kernel through `futex`.

* **Macros:** `ONCE_INITIALIZATION_NOT_YET_STARTED`, `ONCE_INITIALIZATION_UNDERWAY`, `ONCE_INITIALIZATION_COMPLETE`. These define the states of the `pthread_once_t` variable and are critical for the function's logic.

* **`static_assert`:**  This confirms that `pthread_once_t` is treated as an atomic integer. This is essential for ensuring thread-safe updates to its state.

* **Type Casting:** The code explicitly casts `pthread_once_t*` to `atomic_int*`. The comment explaining this choice is important for understanding the design decisions.

* **The `while (true)` loop:** This suggests a potential for contention and waiting.

* **`atomic_load_explicit`:**  This is the initial check for whether initialization is already done. The `memory_order_acquire` is important for visibility of previous operations.

* **`atomic_compare_exchange_weak_explicit`:** This is the core atomic operation for attempting to transition to the "underway" state. The loop around it handles potential spurious failures. The different memory orderings (`acquire` for both success and failure) are crucial.

* **`init_routine()` call:** This is the actual function being executed once.

* **`atomic_store_explicit`:**  This marks the initialization as complete, using `memory_order_release` to ensure visibility to other threads.

* **`__futex_wake_ex`:**  This signals to waiting threads that the initialization is done.

* **`__futex_wait_ex`:** This is how threads wait for the initialization to complete if another thread is already doing it.

**3. Inferring the Functionality:**

Based on the code analysis, I can deduce the main functionalities:

* **Ensuring Single Execution:** The primary goal is to run the `init_routine` only once.
* **Thread Safety:** Atomic operations and futexes are used to manage concurrent access and prevent race conditions.
* **Waiting Mechanism:** Threads that call `pthread_once` while initialization is in progress will wait.

**4. Connecting to Android:**

Since this is part of Android's Bionic library, it's fundamental to the Android platform. I would think about where one-time initialization is important in Android:

* **Library Initialization:**  Shared libraries often need to initialize internal state only once.
* **System Services:** Certain system components might have one-time setup routines.
* **NDK Development:** NDK developers can directly use `pthread_once` in their native code.

**5. Explaining Libc Functions:**

For each libc function used, a detailed explanation is necessary:

* **`pthread_once`:**  Explain its overall purpose (single execution of a function).
* **`atomic_load_explicit`:** Explain its purpose (reading atomically), and the meaning of `memory_order_acquire`.
* **`atomic_compare_exchange_weak_explicit`:**  Explain the compare-and-swap operation, the "weak" aspect, and the different memory orderings.
* **`atomic_store_explicit`:** Explain atomic writing and `memory_order_release`.
* **`__futex_wake_ex` and `__futex_wait_ex`:** Explain the fundamental purpose of futexes for inter-process/thread synchronization at the kernel level.

**6. Dynamic Linker Aspects:**

The "dynamic linker" part of the prompt requires thinking about when `pthread_once` might be relevant during the linking process. Library initialization using `pthread_once` often happens after a library is loaded by the dynamic linker.

* **SO Layout:**  A simple example of a library using `pthread_once` would involve a global `pthread_once_t` variable and an initialization function.
* **Linking Process:** Explain that the dynamic linker loads the SO, and during the library's initialization code, `pthread_once` might be called to ensure some setup happens only once.

**7. Logical Reasoning and Examples:**

Consider different scenarios:

* **First call:**  Initialization should happen.
* **Subsequent calls:**  Initialization should be skipped.
* **Concurrent calls:** Only one thread should execute the initialization.

**8. Common Usage Errors:**

Think about how developers might misuse `pthread_once`:

* **Forgetting Initialization:** Not initializing the `pthread_once_t` variable.
* **Race Conditions in `init_routine`:** The `init_routine` itself needs to be thread-safe if it accesses shared resources.
* **Deadlocks:**  If the `init_routine` attempts to acquire a lock held by a thread waiting in `pthread_once`, a deadlock can occur.

**9. Android Framework/NDK Path and Frida Hooking:**

Trace the call flow:

* **Android Framework:**  A system service might use a native library that uses `pthread_once`.
* **NDK:**  Native code directly calls `pthread_once`.

For Frida hooking, identify the function to hook (`pthread_once`) and demonstrate how to intercept calls, examine arguments, and potentially modify behavior.

**10. Structuring the Response:**

Finally, organize the information logically, using headings and bullet points for clarity. Use clear and concise language, explaining technical terms where necessary. The goal is to provide a comprehensive yet understandable explanation of the code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on just the atomic operations. Realization: the futex part is equally important for the waiting mechanism.
* **Clarifying Memory Ordering:** Ensuring I correctly explain `acquire` and `release` semantics.
* **Adding Practical Examples:**  Thinking of concrete scenarios in Android where `pthread_once` would be used makes the explanation more tangible.
* **Reviewing for Completeness:**  Making sure all parts of the prompt are addressed, especially the dynamic linker and Frida aspects.
好的，让我们深入分析一下 `bionic/libc/bionic/pthread_once.cpp` 这个文件。

**功能列举:**

`pthread_once` 函数的主要功能是**确保一个指定的函数（`init_routine`）在多线程环境中只被执行一次**。即使多个线程同时调用 `pthread_once` 并传入相同的 `once_control`，`init_routine` 也只会执行一次。 这对于初始化全局资源、单例模式或其他只需要执行一次的操作非常有用。

**与 Android 功能的关系及举例:**

`pthread_once` 是 Android Bionic libc 库的一部分，因此它被广泛应用于 Android 系统和应用程序的各个层面，以实现线程安全的初始化。

**举例：**

1. **共享库的初始化:** 当一个共享库 (.so 文件) 被加载到进程时，可能需要在首次加载时执行一些初始化操作。`pthread_once` 可以确保这些初始化代码只运行一次，即使多个线程同时加载或使用该库。例如，一个图形库可能使用 `pthread_once` 来初始化 OpenGL 上下文或加载必要的驱动程序。

2. **单例模式:**  在 Android 的各种系统服务和应用程序中，单例模式非常常见。`pthread_once` 可以用于实现线程安全的单例初始化。以下是一个简化的例子：

   ```c++
   #include <pthread.h>

   class MySingleton {
   public:
       static MySingleton* getInstance() {
           pthread_once(&once_control_, &MySingleton::init);
           return instance_;
       }

   private:
       MySingleton() {}
       static void init() {
           instance_ = new MySingleton();
           // 进行其他初始化操作
       }
       static pthread_once_t once_control_;
       static MySingleton* instance_;
   };

   pthread_once_t MySingleton::once_control_ = PTHREAD_ONCE_INIT;
   MySingleton* MySingleton::instance_ = nullptr;
   ```
   在这个例子中，`getInstance()` 函数使用 `pthread_once` 来确保 `init()` 函数只被调用一次，从而保证 `instance_` 指针只被初始化一次。

3. **Bionic 内部使用:** Bionic 自身也使用 `pthread_once` 来初始化其内部的一些全局数据结构或执行一次性的设置。例如，某些区域设置 (locale) 或内存管理器的初始化可能就使用了 `pthread_once`。

**libc 函数的实现细节:**

让我们逐行分析 `pthread_once` 函数的实现：

1. **`static_assert(sizeof(atomic_int) == sizeof(pthread_once_t), ...)`:**
   - 这是一个编译时断言，用于确保 `pthread_once_t` 的大小与 `atomic_int` 的大小相同。
   - **目的:**  `pthread_once_t` 实际上在实现中被当做原子整型来使用，以便进行线程安全的更新。这个断言确保了类型兼容性。

2. **`atomic_int* once_control_ptr = reinterpret_cast<atomic_int*>(once_control);`:**
   - 将 `pthread_once_t*` 指针强制转换为 `atomic_int*` 指针。
   - **目的:**  直接将 `pthread_once_t` 声明为 `atomic_int` 会污染 `pthread.h` 头文件，可能导致与 libc++ 等其他库的编译冲突。这种转换是一种更干净的实现方式。

3. **`int old_value = atomic_load_explicit(once_control_ptr, memory_order_acquire);`:**
   - 使用原子加载操作读取 `once_control_ptr` 指向的值，并将结果存储在 `old_value` 中。
   - **`atomic_load_explicit` 的功能:**  从内存中原子地读取一个值。原子性保证了读取操作不会被其他线程的写入操作打断，从而避免了数据竞争。
   - **`memory_order_acquire`:**  这是一个内存排序约束。它确保当前线程中所有后续的内存访问操作（指代码顺序上的后续）都能够看到其他线程在初始化完成之前的所有写入操作。这对于确保初始化函数所做的修改对所有线程可见至关重要。

4. **`while (true)` 循环:**
   -  一个无限循环，用于处理可能出现的竞争情况。

5. **`if (__predict_true(old_value == ONCE_INITIALIZATION_COMPLETE))`:**
   -  如果 `old_value` 等于 `ONCE_INITIALIZATION_COMPLETE` (值为 2)，表示初始化已经完成，直接返回 0。
   - **`__predict_true`:**  这是一个编译器提示，告诉编译器这个条件很可能是真的。这可以帮助编译器进行优化。

6. **`if (!atomic_compare_exchange_weak_explicit(once_control_ptr, &old_value, ONCE_INITIALIZATION_UNDERWAY, memory_order_acquire, memory_order_acquire))`:**
   -  尝试原子地将 `once_control_ptr` 指向的值从 `old_value` 修改为 `ONCE_INITIALIZATION_UNDERWAY` (值为 1)。
   - **`atomic_compare_exchange_weak_explicit` 的功能:**  这是一个原子比较并交换操作。它执行以下步骤：
     - 比较 `*once_control_ptr` 的当前值是否等于 `old_value`。
     - 如果相等，则将 `*once_control_ptr` 的值设置为 `ONCE_INITIALIZATION_UNDERWAY`。
     - 如果不相等，则将 `old_value` 更新为 `*once_control_ptr` 的当前值（以便下次循环重试）。
     - 函数返回一个布尔值，表示是否成功进行了交换。
   - **"weak" 的含义:**  `compare_exchange_weak` 允许在即使当前值与预期值相等的情况下也可能失败（所谓的“虚假失败”，spurious failure）。这通常发生在某些多处理器架构上，由于缓存一致性等问题。因此，通常需要在循环中调用 `compare_exchange_weak`。
   - **`memory_order_acquire` (成功时):**  与前面的 `atomic_load_explicit` 类似，确保初始化完成前的写入操作对当前线程可见。
   - **`memory_order_acquire` (失败时):**  确保加载到 `old_value` 的新值是最新的，以便下次循环可以正确重试。

7. **`continue;`:**
   - 如果 compare-and-swap 操作失败，则继续下一次循环，重新尝试。

8. **`if (old_value == ONCE_INITIALIZATION_NOT_YET_STARTED)`:**
   -  如果 compare-and-swap 成功，并且 `old_value` 是 `ONCE_INITIALIZATION_NOT_YET_STARTED` (值为 0)，表示当前线程是第一个尝试初始化的线程。

9. **`(*init_routine)();`:**
   -  调用用户提供的初始化函数。**重要提示:** 代码注释中提到，这个实现不支持 `init_routine` 抛出 C++ 异常或调用 `fork()`。这涉及到进程状态和线程安全的一些复杂性。

10. **`atomic_store_explicit(once_control_ptr, ONCE_INITIALIZATION_COMPLETE, memory_order_release);`:**
    -  将 `once_control_ptr` 指向的值原子地设置为 `ONCE_INITIALIZATION_COMPLETE` (值为 2)，表示初始化完成。
    - **`atomic_store_explicit` 的功能:**  原子地将一个值写入内存。
    - **`memory_order_release`:**  这是一个内存排序约束。它保证当前线程中所有先前的内存写入操作（指代码顺序上的先前）在这次存储操作完成之后，对其他线程都是可见的。这与 `memory_order_acquire` 形成配对，确保初始化函数中的所有修改在其他线程读取 `once_control` 时都能被看到。

11. **`__futex_wake_ex(once_control_ptr, 0, INT_MAX);`:**
    -  唤醒可能正在等待 `once_control_ptr` 的其他线程。
    - **`__futex_wake_ex` 的功能:**  这是一个与内核交互的系统调用，用于唤醒等待在特定地址（在本例中是 `once_control_ptr`）上的线程。
    - **参数:**
        - `once_control_ptr`:  等待的地址。
        - `0`:  标志，通常为 0。
        - `INT_MAX`:  最多唤醒的线程数。这里使用 `INT_MAX` 表示唤醒所有等待的线程。

12. **`return 0;`:**
    -  返回 0，表示成功完成初始化。

13. **`__futex_wait_ex(once_control_ptr, 0, old_value, false, nullptr);`:**
    -  如果 compare-and-swap 成功，但 `old_value` 不是 `ONCE_INITIALIZATION_NOT_YET_STARTED`，则表示有其他线程正在进行初始化，当前线程需要等待。
    - **`__futex_wait_ex` 的功能:**  这是一个与内核交互的系统调用，用于使当前线程休眠，直到指定的地址上的值发生变化。
    - **参数:**
        - `once_control_ptr`:  等待的地址。
        - `0`:  标志，通常为 0。
        - `old_value`:  期望的当前值。只有当 `once_control_ptr` 的值仍然等于 `old_value` 时，线程才会进入休眠。这是一种避免惊群效应的优化。
        - `false`:  不使用超时。
        - `nullptr`:  超时时间结构，由于不使用超时，所以为 `nullptr`。

14. **`old_value = atomic_load_explicit(once_control_ptr, memory_order_acquire);`:**
    -  当被唤醒后，重新加载 `once_control_ptr` 的值。

**Dynamic Linker 功能:**

虽然 `pthread_once.cpp` 本身的代码没有直接涉及动态链接器的操作，但 `pthread_once` 的使用场景与动态链接密切相关。

**SO 布局样本:**

假设我们有一个名为 `libexample.so` 的共享库，它使用 `pthread_once` 来初始化一个全局单例：

```c++
// libexample.cpp
#include <pthread.h>
#include <iostream>

class MySingleton {
public:
    static MySingleton* getInstance() {
        pthread_once(&once_control_, &MySingleton::init);
        return instance_;
    }

    void doSomething() {
        std::cout << "Singleton doing something." << std::endl;
    }

private:
    MySingleton() {
        std::cout << "Singleton initialized." << std::endl;
    }
    static void init() {
        instance_ = new MySingleton();
    }
    static pthread_once_t once_control_;
    static MySingleton* instance_;
};

pthread_once_t MySingleton::once_control_ = PTHREAD_ONCE_INIT;
MySingleton* MySingleton::instance_ = nullptr;

extern "C" void exampleFunction() {
    MySingleton::getInstance()->doSomething();
}
```

**链接的处理过程:**

1. **加载 SO:** 当应用程序需要使用 `libexample.so` 中的函数（如 `exampleFunction`）时，Android 的动态链接器 (linker，通常是 `linker64` 或 `linker`) 会负责加载该 SO 到进程的内存空间。

2. **符号解析:** 链接器会解析 SO 中定义的符号（如 `exampleFunction`），并将其地址链接到应用程序的调用位置。

3. **初始化段:**  在 SO 加载后，链接器会执行 SO 中的初始化段 (`.init_array` 或 `.ctors`) 中的代码。 这段代码通常包含全局对象的构造函数和其他需要在加载时执行的代码。

4. **`pthread_once` 的首次调用:** 当应用程序的某个线程首次调用 `exampleFunction` 时，`MySingleton::getInstance()` 会被调用。由于这是第一次调用，`pthread_once` 会检测到 `once_control_` 尚未初始化，因此会执行 `MySingleton::init()` 函数，创建单例对象。

5. **后续调用:**  后续任何线程调用 `exampleFunction` 或直接调用 `MySingleton::getInstance()` 时，`pthread_once` 会检测到 `once_control_` 已经处于完成状态，因此会直接返回，而不会再次执行 `init()` 函数。

**SO 布局样本（简化）：**

```
libexample.so:
    .text:
        exampleFunction: ...
        MySingleton::getInstance(): ...
        MySingleton::init(): ...
        ...
    .data:
        MySingleton::once_control_:  // 存储 pthread_once_t 的状态
        MySingleton::instance_:      // 存储单例对象的指针
        ...
```

**逻辑推理、假设输入与输出:**

**假设输入:**

- 线程 A 调用 `pthread_once(&my_once, init_func)`。
- 线程 B 同时调用 `pthread_once(&my_once, init_func)`。

**输出:**

- `init_func` 只会被其中一个线程执行一次。
- 假设线程 A 成功将 `my_once` 的状态设置为 `ONCE_INITIALIZATION_UNDERWAY` 并执行了 `init_func`。
- 线程 B 在执行 `atomic_compare_exchange_weak_explicit` 时会发现 `my_once` 的值不是 `ONCE_INITIALIZATION_NOT_YET_STARTED`，它会等待 `my_once` 的值变为 `ONCE_INITIALIZATION_COMPLETE`。
- 当线程 A 执行完 `init_func` 并调用 `atomic_store_explicit` 和 `__futex_wake_ex` 后，线程 B 会被唤醒并返回。

**常见的使用错误:**

1. **未正确初始化 `pthread_once_t`:**  必须将 `pthread_once_t` 变量初始化为 `PTHREAD_ONCE_INIT`。如果未初始化，其值可能是随机的，导致不可预测的行为。

   ```c++
   pthread_once_t my_once; // 错误：未初始化
   pthread_once(&my_once, init_func);
   ```

2. **`init_routine` 不是线程安全的:** 即使 `pthread_once` 保证 `init_routine` 只执行一次，但 `init_routine` 内部的操作仍然需要是线程安全的，特别是当它访问共享资源时。

3. **在 `init_routine` 中调用可能导致死锁的操作:** 如果 `init_routine` 尝试获取一个已经被调用 `pthread_once` 的线程持有的锁，可能会导致死锁。

4. **错误地重用 `pthread_once_t` 变量:**  一个 `pthread_once_t` 变量设计为用于控制一个特定的初始化过程。不应该将其用于控制多个不同的初始化过程。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例:**

**Android Framework:**

1. **Java 代码调用 JNI:** Android Framework 的 Java 代码可能需要调用 Native 代码执行某些操作。这通常通过 JNI (Java Native Interface) 来实现。

2. **Native 代码调用 libc 函数:** JNI 调用的 Native 代码（通常是 C/C++ 代码）可能会使用 POSIX 线程相关的函数，包括 `pthread_once`。

3. **libc 库的链接:**  Native 代码在编译时会链接到 Bionic libc 库，其中包含了 `pthread_once` 的实现。

**NDK:**

NDK 开发者可以直接在他们的 Native 代码中使用 `pthread_once` 来实现线程安全的初始化。

**Frida Hook 示例:**

我们可以使用 Frida 来 Hook `pthread_once` 函数，观察其调用情况和参数。

```javascript
// Frida 脚本
Interceptor.attach(Module.findExportByName("libc.so", "pthread_once"), {
  onEnter: function(args) {
    console.log("pthread_once called!");
    const once_control = ptr(args[0]);
    const init_routine = ptr(args[1]);
    console.log("  once_control:", once_control);
    console.log("  init_routine:", init_routine);

    // 可以读取 once_control 的当前状态
    const state = Memory.readInt(once_control);
    console.log("  Current state:", state);
  },
  onLeave: function(retval) {
    console.log("pthread_once returned:", retval);
  }
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_pthread_once.js`）。
2. 运行 Frida 命令，将脚本附加到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_pthread_once.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_pthread_once.js
   ```
3. 当目标应用程序执行到 `pthread_once` 函数时，Frida 会拦截调用并打印相关信息。

**调试步骤示例:**

假设你想调试一个使用了 `pthread_once` 的 Native 库：

1. **找到目标 SO 文件:** 确定包含你想调试的代码的 SO 文件的路径。
2. **编写 Frida Hook 脚本:**  使用上面的示例脚本，或者根据需要进行修改，例如添加条件判断，只 Hook 特定的 `once_control` 地址。
3. **运行 Frida 并附加到进程:**  使用 Frida 命令启动或附加到目标 Android 进程。
4. **触发 `pthread_once` 的调用:**  在应用程序中执行导致 `pthread_once` 被调用的操作。
5. **查看 Frida 输出:**  Frida 会在控制台中打印出 `pthread_once` 的调用信息，包括 `once_control` 的地址、`init_routine` 的地址以及 `once_control` 的当前状态。
6. **分析输出:**  根据 Frida 的输出，你可以了解 `pthread_once` 是否被调用，以及 `init_routine` 是否被执行。如果遇到问题，例如 `init_routine` 被多次调用，或者出现死锁，Frida 的输出可以帮助你定位问题。

希望这个详细的分析能够帮助你理解 `pthread_once.cpp` 的功能和实现细节，以及它在 Android 系统中的应用。

### 提示词
```
这是目录为bionic/libc/bionic/pthread_once.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <stdatomic.h>

#include "private/bionic_futex.h"

#define ONCE_INITIALIZATION_NOT_YET_STARTED   0
#define ONCE_INITIALIZATION_UNDERWAY          1
#define ONCE_INITIALIZATION_COMPLETE          2

/* NOTE: this implementation doesn't support a init function that throws a C++ exception
 *       or calls fork()
 */
int pthread_once(pthread_once_t* once_control, void (*init_routine)(void)) {
  static_assert(sizeof(atomic_int) == sizeof(pthread_once_t),
                "pthread_once_t should actually be atomic_int in implementation.");

  // We prefer casting to atomic_int instead of declaring pthread_once_t to be atomic_int directly.
  // Because using the second method pollutes pthread.h, and causes an error when compiling libcxx.
  atomic_int* once_control_ptr = reinterpret_cast<atomic_int*>(once_control);

  // First check if the once is already initialized. This will be the common
  // case and we want to make this as fast as possible. Note that this still
  // requires a load_acquire operation here to ensure that all the
  // stores performed by the initialization function are observable on
  // this CPU after we exit.
  int old_value = atomic_load_explicit(once_control_ptr, memory_order_acquire);

  while (true) {
    if (__predict_true(old_value == ONCE_INITIALIZATION_COMPLETE)) {
      return 0;
    }

    // Try to atomically set the initialization underway flag. This requires a compare exchange
    // in a loop, and we may need to exit prematurely if the initialization is complete.
    if (!atomic_compare_exchange_weak_explicit(once_control_ptr, &old_value,
                                               ONCE_INITIALIZATION_UNDERWAY,
                                               memory_order_acquire, memory_order_acquire)) {
      continue;
    }

    if (old_value == ONCE_INITIALIZATION_NOT_YET_STARTED) {
      // We got here first, we can handle the initialization.
      (*init_routine)();

      // Do a store_release indicating that initialization is complete.
      atomic_store_explicit(once_control_ptr, ONCE_INITIALIZATION_COMPLETE, memory_order_release);

      // Wake up any waiters, if any.
      __futex_wake_ex(once_control_ptr, 0, INT_MAX);
      return 0;
    }

    // The initialization is underway, wait for its finish.
    __futex_wait_ex(once_control_ptr, 0, old_value, false, nullptr);
    old_value = atomic_load_explicit(once_control_ptr, memory_order_acquire);
  }
}
```