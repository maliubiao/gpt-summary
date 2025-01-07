Response:
Let's break down the thought process for analyzing the `__cxa_guard.cpp` file and answering the prompt.

**1. Understanding the Core Purpose:**

The initial comments are crucial. They explicitly state the file's purpose: handling one-time constructors in C++, particularly focusing on the differences between ARM and Itanium/x86 ABIs. This immediately tells me the core functionality is related to ensuring that static initialization happens only once, even in multithreaded environments.

**2. Identifying Key Data Structures:**

The `_guard_t` union is central. It holds the state of the constructor. The conditional compilation (`#if defined(__arm__)`) highlights the ABI difference in alignment and size. The `atomic_int` member signifies the need for thread-safe access.

**3. Analyzing Each Function:**

* **`__cxa_guard_acquire`:** The name suggests acquiring a lock or permission to proceed. The code inside the `while(true)` loop implements a spinlock-like mechanism with futexes for waiting. The different state values (`CONSTRUCTION_NOT_YET_STARTED`, `CONSTRUCTION_UNDERWAY_...`, `CONSTRUCTION_COMPLETE`) are the key to understanding the state transitions. The use of `atomic_compare_exchange_weak_explicit` and `atomic_load_explicit` with memory ordering (`memory_order_acquire`) confirms the concurrency control aspect. The return value of 0 or 1 signals whether the caller should proceed with construction.

* **`__cxa_guard_release`:** This function is clearly responsible for marking the constructor as finished. The `atomic_exchange_explicit` with `memory_order_release` is used to ensure visibility of the constructor's effects. The conditional `__futex_wake_ex` indicates that waiting threads are notified.

* **`__cxa_guard_abort`:** This handles the case where the constructor fails. It resets the state and potentially wakes up waiting threads. The use of `memory_order_release` is consistent with the other functions.

**4. Connecting to Android and Dynamic Linking:**

The file resides in `bionic/libc/bionic`, placing it squarely within Android's core C library. This implies it's a fundamental part of the runtime environment. The one-time constructor mechanism is vital for initializing static objects and global variables in shared libraries (SOs). This immediately brings dynamic linking into the picture.

**5. Considering Potential Issues and Usage:**

The locking mechanism and potential for blocking suggest possible deadlocks or performance bottlenecks if not handled correctly. The initial comments about ABI differences highlight the importance of compiler and linker compatibility. The possibility of constructor failures leading to `__cxa_guard_abort` needs to be mentioned.

**6. Tracing the Execution Flow (Android Framework/NDK):**

Think about where static initialization occurs. When an Android app (either Java/Kotlin or native using the NDK) loads a shared library, the dynamic linker is involved. The linker walks through the SO's initialization sections, which include calls to initialize static objects. This is where the compiler-generated code interacting with `__cxa_guard_*` comes into play.

**7. Developing the Frida Hook Example:**

To debug these steps, a Frida hook needs to intercept the `__cxa_guard_*` functions. The hook should log the arguments (the guard variable's address) and potentially the state changes to observe the locking behavior.

**8. Structuring the Answer:**

Organize the information logically:

* **功能概述:** Start with a high-level summary of the file's purpose.
* **与 Android 的关系:** Explain how it fits into the Android ecosystem, specifically mentioning dynamic linking and the Bionic library.
* **函数详解:** Detail each function's purpose and implementation, highlighting key concepts like atomics, memory ordering, and futexes.
* **动态链接:** Describe the interaction with the dynamic linker and provide a sample SO layout. Explain the linking process in the context of static initialization.
* **逻辑推理 (Implicit):** The state transitions within the functions are a form of logical reasoning. Explain the conditions and effects of each state change.
* **用户错误:**  Discuss common pitfalls like deadlocks and constructor failures.
* **Android 框架/NDK 调用路径:** Describe the path from app loading to these functions.
* **Frida Hook 示例:** Provide concrete code to demonstrate debugging.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the low-level details of futexes.**  While important, the core function of the guard needs to be emphasized first.
* **I could forget to explicitly mention the compiler's role.** The compiler generates the code that calls these functions, which is a crucial link.
* **The explanation of memory ordering needs to be clear and concise.** Avoid overly technical jargon without explanation. Focus on why it's necessary for correctness in concurrent scenarios.
* **The SO layout example should be simple but illustrative.**  Including details like `.init_array` is important.
* **Ensure the Frida hook example is practical and easy to understand.**

By following this structured thought process and continually refining the explanation, the final answer becomes comprehensive, accurate, and addresses all aspects of the prompt.
好的，让我们详细分析一下 `bionic/libc/bionic/__cxa_guard.cpp` 这个文件。

**功能概述**

`__cxa_guard.cpp` 文件定义了 C++ ABI (Application Binary Interface) 中用于实现 **一次性构造 (One-Time Construction)** 的支持函数。  一次性构造是指保证某个全局或静态局部对象只被构造一次，即使在多线程环境下也是如此。 这些函数用于控制对需要进行一次性初始化的对象的构造过程的并发访问。

**具体功能：**

1. **`__cxa_guard_acquire(_guard_t* gv)`:**
   - 尝试获取对与给定 guard 变量 `gv` 关联的构造过程的控制权。
   - 如果构造尚未开始，则将 guard 变量的状态标记为正在进行，并返回 1，表示调用者可以继续构造对象。
   - 如果构造已经在其他线程中进行，则当前线程会等待，直到构造完成或中止。
   - 如果构造已经完成，则立即返回 0，表示无需进行任何操作。

2. **`__cxa_guard_release(_guard_t* gv)`:**
   - 当对象的构造完成后，调用此函数来释放 guard 变量 `gv`。
   - 将 guard 变量的状态标记为已完成，并唤醒所有等待该 guard 变量的线程。

3. **`__cxa_guard_abort(_guard_t* gv)`:**
   - 如果对象的构造过程中发生异常或失败，可以调用此函数来中止构造过程。
   - 将 guard 变量的状态重置为未开始状态，并唤醒所有等待该 guard 变量的线程。

**与 Android 功能的关系及举例说明**

这个文件是 Android Bionic C 库的一部分，因此它的功能直接支撑着 Android 运行时环境的正常运行。  C++ 中使用静态局部变量或全局变量时，经常需要进行一次性初始化。  Android 系统中的许多组件，包括 Framework 层和 Native 层，都使用 C++ 开发，因此这些函数对于保证这些组件的正确初始化至关重要。

**举例说明：**

假设有一个全局单例类 `MySingleton`：

```c++
// MySingleton.h
#ifndef MYSINGLETON_H
#define MYSINGLETON_H

class MySingleton {
public:
    static MySingleton& getInstance();
    void doSomething();

private:
    MySingleton() {
        // 初始化单例对象
        initialize();
    }
    void initialize();
    static MySingleton instance;
};

#endif
```

```c++
// MySingleton.cpp
#include "MySingleton.h"
#include <iostream>

void MySingleton::initialize() {
    std::cout << "MySingleton initialized." << std::endl;
    // 执行一些初始化操作
}

MySingleton& MySingleton::getInstance() {
    return instance;
}

void MySingleton::doSomething() {
    std::cout << "MySingleton is doing something." << std::endl;
}

MySingleton MySingleton::instance; // 静态成员变量，需要一次性构造
```

当程序首次访问 `MySingleton::getInstance()` 时，编译器会生成类似下面的代码来确保 `MySingleton::instance` 只被构造一次：

```c++
MySingleton& MySingleton::getInstance() {
    static _guard_t guard;
    if (__cxa_guard_acquire(&guard)) {
        instance = MySingleton();
        __cxa_guard_release(&guard);
    }
    return instance;
}
```

在多线程环境下，如果没有 `__cxa_guard_acquire` 和 `__cxa_guard_release`，多个线程可能同时尝试构造 `instance`，导致未定义的行为。 `__cxa_guard_*` 函数保证只有一个线程能够成功构造 `instance`。

**详细解释每个 libc 函数的功能是如何实现的**

1. **`__cxa_guard_acquire`:**
   - **原子加载 (Atomic Load):** 首先使用 `atomic_load_explicit(&gv->state, memory_order_acquire)` 原子地读取 guard 变量 `gv` 的状态。 `memory_order_acquire` 确保在该加载操作之后的所有内存访问都发生在加载的值之后。
   - **状态判断和处理:**
     - 如果状态是 `CONSTRUCTION_COMPLETE` (构造已完成)，则直接返回 0。
     - 如果状态是 `CONSTRUCTION_NOT_YET_STARTED` (构造尚未开始)，尝试使用 `atomic_compare_exchange_weak_explicit` 原子地将状态从 `CONSTRUCTION_NOT_YET_STARTED` 修改为 `CONSTRUCTION_UNDERWAY_WITHOUT_WAITER`。 `memory_order_acquire` 用于获取锁。如果修改成功，则返回 1。如果修改失败（说明有其他线程抢先一步），则循环重试。
     - 如果状态是 `CONSTRUCTION_UNDERWAY_WITHOUT_WAITER` (构造正在进行，没有等待者)，尝试使用 `atomic_compare_exchange_weak_explicit` 原子地将状态修改为 `CONSTRUCTION_UNDERWAY_WITH_WAITER`。 这表示当前线程也希望参与等待。
     - 如果状态是 `CONSTRUCTION_UNDERWAY_WITH_WAITER` (构造正在进行，有等待者)，则调用 `__futex_wait_ex` 进入睡眠状态，等待其他线程完成构造并唤醒。
   - **Futex 等待:** `__futex_wait_ex(&gv->state, false, CONSTRUCTION_UNDERWAY_WITH_WAITER)` 是一个用户空间的快速互斥锁 (Fast Userspace Mutex)。它允许线程在 guard 变量的状态为 `CONSTRUCTION_UNDERWAY_WITH_WAITER` 时进入睡眠状态，避免忙等待，提高 CPU 利用率。

2. **`__cxa_guard_release`:**
   - **原子交换 (Atomic Exchange):** 使用 `atomic_exchange_explicit(&gv->state, CONSTRUCTION_COMPLETE, memory_order_release)` 原子地将 guard 变量 `gv` 的状态设置为 `CONSTRUCTION_COMPLETE`。 `memory_order_release` 确保在该交换操作之前的所有内存写入都对其他线程可见。
   - **Futex 唤醒:** 如果之前的状态是 `CONSTRUCTION_UNDERWAY_WITH_WAITER`，表示有其他线程在等待，则调用 `__futex_wake_ex(&gv->state, false, INT_MAX)` 唤醒所有等待该 guard 变量的线程。

3. **`__cxa_guard_abort`:**
   - **原子交换 (Atomic Exchange):** 使用 `atomic_exchange_explicit(&gv->state, CONSTRUCTION_NOT_YET_STARTED, memory_order_release)` 原子地将 guard 变量 `gv` 的状态重置为 `CONSTRUCTION_NOT_YET_STARTED`。
   - **Futex 唤醒:** 如果之前的状态是 `CONSTRUCTION_UNDERWAY_WITH_WAITER`，则调用 `__futex_wake_ex` 唤醒所有等待线程，告知构造已中止。

**涉及 dynamic linker 的功能、so 布局样本以及链接的处理过程**

当程序加载一个包含需要进行一次性初始化的静态变量的共享库 (SO) 时，dynamic linker (在 Android 上是 `linker64` 或 `linker`) 会参与到这个过程中。

**SO 布局样本：**

一个典型的包含需要一次性初始化的静态变量的 SO 的布局可能如下所示（简化）：

```
ELF Header
Program Headers
Section Headers
...
.data              # 已初始化全局和静态变量
.bss               # 未初始化全局和静态变量
.init_array        # 包含指向初始化函数的指针数组
.fini_array        # 包含指向清理函数的指针数组
.rodata            # 只读数据
.text              # 代码段
...
```

**链接的处理过程：**

1. **加载 SO:** 当系统需要使用 SO 中的代码时，dynamic linker 会加载 SO 到内存中。
2. **处理 `.init_array`:** dynamic linker 会遍历 SO 的 `.init_array` 段。这个段包含了一系列函数指针，这些函数需要在 SO 加载时执行，通常用于初始化静态变量。
3. **调用初始化函数:** 对于需要进行一次性初始化的静态变量，编译器会生成一个包装函数，这个函数内部会调用 `__cxa_guard_acquire`、构造函数以及 `__cxa_guard_release`。 这个包装函数的地址会被放入 `.init_array` 中。
4. **`__cxa_guard_*` 的作用:** 当 dynamic linker 执行 `.init_array` 中的初始化函数时，`__cxa_guard_acquire` 会确保只有一个线程能够成功执行构造函数。其他尝试同时进行初始化的线程会被阻塞在 `__cxa_guard_acquire` 中。
5. **完成初始化:** 构造完成后，`__cxa_guard_release` 会释放 guard 变量，允许其他等待的线程继续执行，但此时构造已经完成，它们会立即返回。

**逻辑推理和假设输入与输出**

假设有两个线程 T1 和 T2 同时尝试访问需要一次性初始化的静态变量 `MySingleton::instance`：

**T1:** 调用 `MySingleton::getInstance()`
**T2:** 调用 `MySingleton::getInstance()`

**Guard 变量 `guard` 的初始状态：** `CONSTRUCTION_NOT_YET_STARTED` (0)

**T1 执行 `__cxa_guard_acquire(&guard)`：**
- 读取 `guard` 的状态，为 0。
- 尝试将 `guard` 的状态修改为 `CONSTRUCTION_UNDERWAY_WITHOUT_WAITER`。 假设 T1 成功。
- `__cxa_guard_acquire` 返回 1。
- T1 执行 `instance = MySingleton()`，构造对象。
- T1 执行 `__cxa_guard_release(&guard)`。
- `__cxa_guard_release` 将 `guard` 的状态修改为 `CONSTRUCTION_COMPLETE` (1)，并唤醒可能等待的线程。

**T2 执行 `__cxa_guard_acquire(&guard)`：**
- 读取 `guard` 的状态。 由于 T1 已经成功修改，状态可能为 `CONSTRUCTION_UNDERWAY_WITHOUT_WAITER` 或 `CONSTRUCTION_UNDERWAY_WITH_WAITER` （如果 T2 在 T1 修改状态之后到达）。
- 如果状态是 `CONSTRUCTION_UNDERWAY_WITHOUT_WAITER`，T2 会尝试修改为 `CONSTRUCTION_UNDERWAY_WITH_WAITER`，然后调用 `__futex_wait_ex` 进入等待。
- 最终，当 T1 执行 `__cxa_guard_release` 后，T2 被唤醒。
- T2 再次读取 `guard` 的状态，此时为 `CONSTRUCTION_COMPLETE`。
- `__cxa_guard_acquire` 返回 0。
- T2 不会再次构造对象，直接返回已构造的 `instance`。

**用户或编程常见的使用错误**

1. **死锁 (Deadlock):** 如果一次性初始化的对象 A 的构造依赖于另一个需要一次性初始化的对象 B，并且对象 B 的构造又依赖于对象 A，可能会发生死锁。  例如：

   ```c++
   // a.cpp
   #include "b.h"
   class A {
   public:
       A() { B::getInstance(); }
       static A& getInstance() {
           static A instance;
           return instance;
       }
   };

   // b.cpp
   #include "a.h"
   class B {
   public:
       B() { A::getInstance(); }
       static B& getInstance() {
           static B instance;
           return instance;
       }
   };
   ```

   在这种情况下，当尝试初始化 `A::instance` 时，会尝试获取 `A` 的 guard 锁，然后尝试调用 `B::getInstance()`，这会尝试获取 `B` 的 guard 锁。 同时，如果另一个线程尝试初始化 `B::instance`，则会尝试获取 `B` 的 guard 锁，然后尝试调用 `A::getInstance()`，这会尝试获取 `A` 的 guard 锁。 两个线程相互等待对方释放锁，从而导致死锁。

2. **构造函数抛出异常:** 如果在一次性构造函数的执行过程中抛出异常，`__cxa_guard_release` 不会被调用，guard 变量的状态可能不会被正确更新，导致后续的访问行为未定义。 应该使用 `__cxa_guard_abort` 来处理异常情况。

3. **不正确的 guard 变量使用:** 开发者不应该手动操作 guard 变量的值，这些变量应该由编译器自动生成和管理。

**Android Framework 或 NDK 如何一步步地到达这里**

1. **编写 C++ 代码:** Android Framework 的 Native 层或 NDK 开发的 Native 代码中使用了包含静态局部变量或全局变量的 C++ 类。

2. **编译和链接:** 使用 Android NDK 的编译器 (clang++) 编译这些 C++ 代码。编译器会自动生成与 `__cxa_guard_*` 函数交互的代码，用于管理一次性初始化。链接器会将这些代码与 Bionic C 库链接。

3. **加载 SO 或可执行文件:** 当 Android 系统启动应用程序或加载包含 Native 代码的 SO 库时，dynamic linker 会负责加载这些模块到内存中。

4. **执行初始化代码:** dynamic linker 会执行 `.init_array` 中的函数指针。对于包含一次性初始化的静态变量，`.init_array` 中的函数会调用 `__cxa_guard_acquire`，然后执行构造函数，最后调用 `__cxa_guard_release`。

5. **Framework 或 NDK 使用:** Framework 或 NDK 的代码就可以安全地访问这些已初始化的一次性构造对象。

**Frida Hook 示例调试这些步骤**

可以使用 Frida hook 这些 `__cxa_guard_*` 函数来观察它们的执行过程和 guard 变量的状态变化。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: The process '{package_name}' was not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__cxa_guard_acquire"), {
    onEnter: function(args) {
        var guard_ptr = ptr(args[0]);
        var state = guard_ptr.readU32();
        console.log("[__cxa_guard_acquire] Guard address: " + guard_ptr + ", Current State: " + state);
    },
    onLeave: function(retval) {
        console.log("[__cxa_guard_acquire] Return value: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__cxa_guard_release"), {
    onEnter: function(args) {
        var guard_ptr = ptr(args[0]);
        var state = guard_ptr.readU32();
        console.log("[__cxa_guard_release] Guard address: " + guard_ptr + ", Current State: " + state);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__cxa_guard_abort"), {
    onEnter: function(args) {
        var guard_ptr = ptr(args[0]);
        var state = guard_ptr.readU32();
        console.log("[__cxa_guard_abort] Guard address: " + guard_ptr + ", Current State: " + state);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print(f"[*] Script loaded. Attaching to '{package_name}'...")
sys.stdin.read()
session.detach()
```

**使用方法：**

1. 将 `your.app.package.name` 替换为你想要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 ADB 授权。
3. 运行 Frida script。
4. 在你的 Android 应用中执行触发一次性初始化的操作。
5. Frida console 会打印出 `__cxa_guard_acquire`, `__cxa_guard_release`, 和 `__cxa_guard_abort` 的调用信息，包括 guard 变量的地址和状态。

通过 Frida hook，你可以观察到 guard 变量的状态变化，以及这些函数在多线程环境下的行为，从而更好地理解 Android 如何管理一次性构造。

希望这个详细的解释能够帮助你理解 `__cxa_guard.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/__cxa_guard.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2006 The Android Open Source Project
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

#include <endian.h>
#include <limits.h>
#include <stdatomic.h>
#include <stddef.h>

#include "private/bionic_futex.h"

// This file contains C++ ABI support functions for one time
// constructors as defined in the "Run-time ABI for the ARM Architecture"
// section 4.4.2
//
// ARM C++ ABI and Itanium/x86 C++ ABI has different definition for
// one time construction:
//
//    ARM C++ ABI defines the LSB of guard variable should be tested
//    by compiler-generated code before calling __cxa_guard_acquire et al.
//
//    The Itanium/x86 C++ ABI defines the low-order _byte_ should be
//    tested instead.
//
//    Meanwhile, guard variable are 32bit aligned for ARM, and 64bit
//    aligned for x86.
//
// Reference documentation:
//
//    section 3.2.3 of ARM IHI 0041C (for ARM)
//    section 3.3.2 of the Itanium C++ ABI specification v1.83 (for x86).
//
// There is no C++ ABI available for other ARCH. But the gcc source
// shows all other ARCH follow the definition of Itanium/x86 C++ ABI.

#if defined(__arm__)
// The ARM C++ ABI mandates that guard variables are 32-bit aligned, 32-bit
// values. The LSB is tested by the compiler-generated code before calling
// __cxa_guard_acquire.
union _guard_t {
  atomic_int state;
  int32_t aligner;
};

#else
// The Itanium/x86 C++ ABI (used by all other architectures) mandates that
// guard variables are 64-bit aligned, 64-bit values. The LSB is tested by
// the compiler-generated code before calling __cxa_guard_acquire.
union _guard_t {
  atomic_int state;
  int64_t aligner;
};

#endif

// Set construction state values according to reference documentation.
// 0 is the initialization value.
// Arm requires ((*gv & 1) == 1) after __cxa_guard_release, ((*gv & 3) == 0) after __cxa_guard_abort.
// X86 requires first byte not modified by __cxa_guard_acquire, first byte is non-zero after
// __cxa_guard_release.

#define CONSTRUCTION_NOT_YET_STARTED                0
#define CONSTRUCTION_COMPLETE                       1
#define CONSTRUCTION_UNDERWAY_WITHOUT_WAITER    0x100
#define CONSTRUCTION_UNDERWAY_WITH_WAITER       0x200

extern "C" int __cxa_guard_acquire(_guard_t* gv) {
  int old_value = atomic_load_explicit(&gv->state, memory_order_acquire);
  // In the common CONSTRUCTION_COMPLETE case we have to ensure that all the stores performed by
  // the construction function are observable on this CPU after we exit. A similar constraint may
  // apply in the CONSTRUCTION_NOT_YET_STARTED case with a prior abort.

  while (true) {
    if (old_value == CONSTRUCTION_COMPLETE) {
      return 0;
    } else if (old_value == CONSTRUCTION_NOT_YET_STARTED) {
      if (!atomic_compare_exchange_weak_explicit(&gv->state, &old_value,
                                                  CONSTRUCTION_UNDERWAY_WITHOUT_WAITER,
                                                  memory_order_acquire /* or relaxed in C++17 */,
                                                  memory_order_acquire)) {
        continue;
      }
      return 1;
    } else if (old_value == CONSTRUCTION_UNDERWAY_WITHOUT_WAITER) {
      if (!atomic_compare_exchange_weak_explicit(&gv->state, &old_value,
                                                 CONSTRUCTION_UNDERWAY_WITH_WAITER,
                                                 memory_order_acquire /* or relaxed in C++17 */,
                                                 memory_order_acquire)) {
        continue;
      }
    }

    __futex_wait_ex(&gv->state, false, CONSTRUCTION_UNDERWAY_WITH_WAITER);
    old_value = atomic_load_explicit(&gv->state, memory_order_acquire);
  }
}

extern "C" void __cxa_guard_release(_guard_t* gv) {
  // Release fence is used to make all stores performed by the construction function
  // visible in other threads.
  int old_value = atomic_exchange_explicit(&gv->state, CONSTRUCTION_COMPLETE, memory_order_release);
  if (old_value == CONSTRUCTION_UNDERWAY_WITH_WAITER) {
    __futex_wake_ex(&gv->state, false, INT_MAX);
  }
}

extern "C" void __cxa_guard_abort(_guard_t* gv) {
  // Release fence is used to make all stores performed by the construction function
  // visible in other threads.
  int old_value = atomic_exchange_explicit(&gv->state, CONSTRUCTION_NOT_YET_STARTED, memory_order_release);
  if (old_value == CONSTRUCTION_UNDERWAY_WITH_WAITER) {
    __futex_wake_ex(&gv->state, false, INT_MAX);
  }
}

"""

```