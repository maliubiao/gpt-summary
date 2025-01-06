Response:
Let's break down the thought process for analyzing this `pthread_atfork.cpp` file.

**1. Understanding the Core Functionality:**

The first step is to identify the primary purpose of the code. The filename itself, `pthread_atfork.cpp`, and the included header `<pthread.h>` strongly suggest that this code is related to the `pthread_atfork` family of functions. Reading the copyright notice and the surrounding comments confirms this. The code manages a list of handlers to be called during the `fork()` process.

**2. Dissecting the Data Structures:**

Next, we need to understand the data structures involved:

* **`atfork_t`:** This struct clearly holds the three handler functions (`prepare`, `child`, `parent`) and a `dso_handle`. The `next` and `prev` pointers indicate it's part of a linked list. The `dso_handle` is a key clue for understanding its interaction with dynamic linking.

* **`atfork_list_t`:** This class encapsulates the linked list of `atfork_t` structures. Its methods (`walk_forward`, `walk_backwards`, `push_back`, `remove_if`, `remove`) provide the core logic for managing the list. The constructor and the `BIONIC_DISALLOW_COPY_AND_ASSIGN` macro indicate careful memory management.

* **`g_atfork_list_mutex` and `g_atfork_list`:** These are global variables – a mutex to protect the list from race conditions and the actual list instance.

**3. Analyzing the Functions:**

Now, let's go through each function and understand its role:

* **`__bionic_atfork_run_prepare()`:**  This function locks the mutex, iterates backward through the list, and calls the `prepare` handlers. The backward iteration is important and needs to be noted as per POSIX requirements.

* **`__bionic_atfork_run_child()`:** This function re-initializes the mutex (important for the child process) and then iterates forward, calling the `child` handlers.

* **`__bionic_atfork_run_parent()`:** This function iterates forward and calls the `parent` handlers, then unlocks the mutex.

* **`__register_atfork()`:** This is the crucial function for *registering* the handlers. It allocates memory for a new `atfork_t` entry, populates it with the provided handlers and DSO handle, locks the mutex, adds the entry to the list, and unlocks the mutex. The `dso` parameter is significant – it connects the handlers to a specific shared object.

* **`__unregister_atfork()`:** This function removes the handlers associated with a specific DSO. It locks the mutex, iterates through the list using `remove_if`, and unlocks the mutex.

**4. Connecting to Android and Dynamic Linking:**

The `dso_handle` is the key to understanding the connection to Android's dynamic linker. Shared libraries (DSOs) often need to perform cleanup or setup when a `fork()` occurs. The `pthread_atfork` mechanism allows them to register these actions. When a new shared library is loaded, it can register its handlers using `__register_atfork`. When it's unloaded, it can unregister them.

**5. Identifying Potential Issues and Use Cases:**

Thinking about how this code might be used helps to identify potential problems:

* **Use Cases:**  Resource cleanup (closing files, releasing locks), state synchronization, custom memory management.
* **Common Errors:** Forgetting to unregister handlers, race conditions if the mutex isn't held correctly (though the code seems to handle this), and issues related to the order of handler execution.

**6. Explaining the `libc` Function Implementation:**

The implementation is relatively straightforward: a linked list protected by a mutex. The key is the separate `prepare`, `child`, and `parent` handlers and their specific order of execution.

**7. Addressing Dynamic Linker Aspects:**

* **SO Layout:**  A basic understanding of SO structure is needed (code, data, GOT, PLT).
* **Linking Process:**  Focus on how the dynamic linker resolves symbols and loads SOs. The key connection is that the dynamic linker itself (or code within a loaded SO) calls `__register_atfork`.

**8. Developing Examples:**

Concrete examples are crucial for understanding:

* **Hypothetical Input/Output:**  Show how registering and unregistering handlers affects the list.
* **User Errors:** Demonstrate forgetting to unregister or potential race conditions in *user code* that interacts with `fork()`.
* **Android Framework/NDK:**  Trace the path from a high-level `fork()` call down to the execution of these handlers within Bionic.

**9. Frida Hooking:**

Consider how to observe this in action using Frida. Hooking the registration and execution functions (`__register_atfork`, `__bionic_atfork_run_prepare`, etc.) would provide valuable insights.

**10. Structuring the Response:**

Finally, organize the information logically, starting with a high-level overview, then diving into details, and providing clear examples. Use headings and bullet points to improve readability. Ensure all the questions in the prompt are addressed.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this is just about basic thread management.
* **Correction:** The "atfork" in the name and the `fork()` discussion strongly suggest it's related to process forking, not just threads.
* **Initial thought:** The `dso_handle` might be some generic identifier.
* **Correction:** Connecting it to dynamic linking and shared objects makes much more sense given the context of a C library in an operating system.
* **Initial thought:**  Just list the functions.
* **Refinement:**  Explain *how* the linked list is managed, the importance of the mutex, and the order of handler execution.

By following this structured approach and continuously refining understanding, we can generate a comprehensive and accurate analysis of the provided code.
好的，让我们来详细分析一下 `bionic/libc/bionic/pthread_atfork.cpp` 这个文件。

**文件功能概述**

`pthread_atfork.cpp` 实现了 `pthread_atfork` 系列函数，这些函数允许应用程序在 `fork()` 系统调用发生前后注册回调函数。这些回调函数在 `fork()` 过程中特定的时间点被调用，以帮助应用程序安全地处理 `fork()` 操作，特别是涉及到多线程环境下的资源管理和状态同步。

**具体功能分解**

1. **注册 atfork 处理器 (`__register_atfork`)**:
   - 允许动态链接库 (DSO，即 `.so` 文件) 或应用程序注册三个函数指针：`prepare`、`parent` 和 `child`。
   - `prepare` 函数在 `fork()` 开始执行，创建子进程之前，在父进程中被调用。它的主要目的是获取所有线程共享的锁，以避免子进程继承到处于不一致状态的锁。
   - `parent` 函数在 `fork()` 完成，子进程创建之后，在父进程中被调用。它的主要目的是释放 `prepare` 阶段获取的锁。
   - `child` 函数在 `fork()` 完成之后，在新创建的子进程中被调用。它的主要目的是重新初始化子进程中父进程持有但子进程不应该持有的资源，例如互斥锁、条件变量等。
   - `dso` 参数用于标识注册这些处理器的动态链接库，以便后续可以取消注册。
   - 内部实现：
     - 分配一个 `atfork_t` 结构体来存储这些函数指针和 DSO 句柄。
     - 获取全局互斥锁 `g_atfork_list_mutex`，以保护全局的 atfork 处理器列表。
     - 将新创建的 `atfork_t` 结构体添加到全局链表 `g_atfork_list` 的末尾。
     - 释放全局互斥锁。

2. **取消注册 atfork 处理器 (`__unregister_atfork`)**:
   - 允许动态链接库取消注册之前使用 `__register_atfork` 注册的处理器。
   - 通过提供的 `dso` 句柄，在全局链表 `g_atfork_list` 中查找并移除相关的 `atfork_t` 结构体。
   - 内部实现：
     - 获取全局互斥锁 `g_atfork_list_mutex`。
     - 使用 `remove_if` 遍历 `g_atfork_list`，根据 `dso_handle` 匹配需要移除的条目。
     - 对于匹配到的条目，调用私有的 `remove` 函数释放 `atfork_t` 结构体的内存，并将其从链表中移除。
     - 释放全局互斥锁。

3. **运行 prepare 处理器 (`__bionic_atfork_run_prepare`)**:
   - 在 `fork()` 系统调用开始执行时，父进程会调用此函数。
   - 它的作用是遍历全局 atfork 处理器列表，并调用每个处理器注册的 `prepare` 函数。
   - 调用顺序是逆序的，即最后注册的 `prepare` 函数先被调用。这是 POSIX 标准的要求。
   - 内部实现：
     - 获取全局互斥锁 `g_atfork_list_mutex`。
     - 使用 `walk_backwards` 遍历 `g_atfork_list`，并调用每个 `atfork_t` 结构体中的 `prepare` 函数（如果存在）。

4. **运行 child 处理器 (`__bionic_atfork_run_child`)**:
   - 在 `fork()` 系统调用完成，子进程创建之后，子进程会调用此函数。
   - 它的作用是遍历全局 atfork 处理器列表，并调用每个处理器注册的 `child` 函数。
   - 调用顺序是正序的，即最先注册的 `child` 函数先被调用。
   - 内部实现：
     - **重要**: 重新初始化全局互斥锁 `g_atfork_list_mutex`。这是因为子进程继承了父进程的内存空间，包括互斥锁的状态。为了避免父子进程对同一个锁产生竞争，子进程需要重新初始化这个锁。
     - 获取重新初始化后的全局互斥锁 `g_atfork_list_mutex`。
     - 使用 `walk_forward` 遍历 `g_atfork_list`，并调用每个 `atfork_t` 结构体中的 `child` 函数（如果存在）。
     - 释放全局互斥锁。

5. **运行 parent 处理器 (`__bionic_atfork_run_parent`)**:
   - 在 `fork()` 系统调用完成，子进程创建之后，父进程会调用此函数。
   - 它的作用是遍历全局 atfork 处理器列表，并调用每个处理器注册的 `parent` 函数。
   - 调用顺序是正序的，即最先注册的 `parent` 函数先被调用。
   - 内部实现：
     - 使用 `walk_forward` 遍历 `g_atfork_list`，并调用每个 `atfork_t` 结构体中的 `parent` 函数（如果存在）。
     - 释放全局互斥锁 `g_atfork_list_mutex`。

**与 Android 功能的关系和举例说明**

`pthread_atfork` 对于 Android 系统的稳定性和可靠性至关重要，尤其是在多进程和多线程环境下。

**举例说明：**

假设一个 Android 应用使用 SQLite 数据库。SQLite 内部使用了互斥锁来保护数据库的完整性。

1. **注册 `prepare` 处理器：** 当 SQLite 库被加载时，它会注册一个 `prepare` 处理器。这个处理器在 `fork()` 之前尝试获取 SQLite 内部的互斥锁。这样可以防止 `fork()` 发生在数据库操作的中间状态，避免子进程继承到一个可能处于不一致状态的数据库锁。

2. **注册 `parent` 处理器：** SQLite 还会注册一个 `parent` 处理器，在父进程的 `fork()` 完成后被调用，用于释放 `prepare` 阶段获取的 SQLite 互斥锁。

3. **注册 `child` 处理器：** SQLite 还会注册一个 `child` 处理器，在子进程的 `fork()` 完成后被调用。这个处理器会重新初始化子进程中的 SQLite 连接和锁，因为子进程不应该继续持有父进程的锁。

**libc 函数的实现细节**

- **`malloc` 和 `free`**: 用于 `__register_atfork` 分配 `atfork_t` 结构体的内存，以及在 `__unregister_atfork` 中释放内存。
- **`pthread_mutex_lock` 和 `pthread_mutex_unlock`**: 用于保护全局 atfork 处理器列表 `g_atfork_list` 免受并发访问的影响，确保在注册、取消注册和遍历列表时的线程安全。
- **`pthread_mutex_t g_atfork_list_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;`**:  初始化一个递归互斥锁。递归互斥锁允许同一个线程多次获取同一个锁而不会造成死锁。这里使用递归锁可能是为了处理某些复杂的嵌套调用场景，虽然在这个代码中直接的递归调用并不明显。
- **`walk_forward` 和 `walk_backwards`**: 这是 `atfork_list_t` 类的模板成员函数，用于遍历链表并对每个节点执行给定的函数对象。
- **`push_back`**: `atfork_list_t` 类的成员函数，用于将新的 `atfork_t` 节点添加到链表的末尾。
- **`remove_if`**: `atfork_list_t` 类的模板成员函数，用于遍历链表并移除满足特定条件的节点。
- **`remove`**: `atfork_list_t` 类的私有成员函数，用于从链表中移除指定的 `atfork_t` 节点并释放其内存。

**涉及 dynamic linker 的功能**

`__register_atfork` 函数的 `dso` 参数就是与 dynamic linker 交互的关键。当一个共享库被加载时，它可以通过 dynamic linker 获取自身的句柄，并将其传递给 `__register_atfork`。这样，当需要取消注册时，dynamic linker 可以使用这个句柄来找到对应的 atfork 处理器。

**SO 布局样本**

```
my_library.so:
    .text:
        my_init_function:
            # ... 初始化代码 ...
            mov     r0, pc  // 获取当前 DSO 的加载地址（近似）
            bl      __register_atfork
            # ... 其他初始化 ...

        my_prepare_handler:
            # ... prepare 处理逻辑 ...

        my_parent_handler:
            # ... parent 处理逻辑 ...

        my_child_handler:
            # ... child 处理逻辑 ...

    .data:
        # ... 数据段 ...

    .dynamic:
        # ... 动态链接信息 ...
```

**链接的处理过程**

1. **加载 SO:** Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 在加载 `my_library.so` 时，会执行其 `.init` 部分的代码（或者由 `__attribute__((constructor))` 标记的函数）。

2. **注册 atfork 处理器:** 在 `my_init_function` 中，`__register_atfork` 被调用。
   - `prepare`, `parent`, `child` 参数指向 `my_prepare_handler`, `my_parent_handler`, `my_child_handler` 函数在 `.text` 段中的地址。
   - `dso` 参数会指向 `my_library.so` 的某个内部数据结构，可以唯一标识这个 SO。具体实现可能依赖于 linker 的内部机制，通常可以通过一些技巧（比如获取当前 PC 指针）来近似获取 DSO 的加载地址或相关信息。

3. **fork() 调用:** 当应用程序调用 `fork()` 时：
   - **父进程:**
     - Bionic 的 `fork()` 实现会调用 `__bionic_atfork_run_prepare()`，遍历并执行所有已注册的 `prepare` 处理器（包括 `my_prepare_handler`）。
     - `fork()` 系统调用创建子进程。
     - Bionic 的 `fork()` 实现会调用 `__bionic_atfork_run_parent()`，遍历并执行所有已注册的 `parent` 处理器（包括 `my_parent_handler`）。
   - **子进程:**
     - Bionic 的 `fork()` 实现会调用 `__bionic_atfork_run_child()`，遍历并执行所有已注册的 `child` 处理器（包括 `my_child_handler`）。

4. **卸载 SO:** 当 `my_library.so` 被卸载时，dynamic linker 会执行其 `.fini` 部分的代码（或者由 `__attribute__((destructor))` 标记的函数）。在这个过程中，可能会调用 `__unregister_atfork`，使用之前注册时使用的 `dso` 句柄来移除相关的 atfork 处理器。

**假设输入与输出**

假设我们有以下操作序列：

1. 动态链接库 `libA.so` 加载，注册了 `prepareA`, `parentA`, `childA`。
2. 动态链接库 `libB.so` 加载，注册了 `prepareB`, `parentB`, `childB`。
3. 调用 `fork()`。

**输出：**

- **父进程 (prepare 阶段):** 先执行 `prepareB`，后执行 `prepareA` (逆序)。
- **子进程 (child 阶段):** 先执行 `childA`，后执行 `childB` (正序)。
- **父进程 (parent 阶段):** 先执行 `parentA`，后执行 `parentB` (正序)。

**用户或编程常见的使用错误**

1. **忘记取消注册:** 如果一个动态链接库注册了 atfork 处理器，但在卸载时忘记取消注册，可能会导致这些处理器在后续的 `fork()` 调用中仍然被执行，产生不可预测的行为，尤其是在 DSO 已经被卸载，其代码和数据不再有效的情况下。

2. **在 prepare 处理器中进行耗时操作:** `prepare` 处理器在 `fork()` 过程中被调用，会阻塞子进程的创建。如果 `prepare` 处理器执行时间过长，会影响系统的响应性能。

3. **在子进程中访问父进程的资源而不进行适当的同步:** 子进程继承了父进程的内存空间，但父子进程是独立的进程。如果不使用进程间通信机制（例如管道、共享内存）或者在 `child` 处理器中进行适当的资源重置，子进程直接访问父进程的资源可能会导致竞争条件和数据不一致。

4. **在 `child` 处理器中持有锁:**  `child` 处理器应该避免持有父进程遗留下来的锁，否则可能导致死锁。通常需要在 `child` 处理器中释放或重新初始化这些锁。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:** NDK 开发的应用可以直接调用标准的 POSIX `fork()` 函数。当 Bionic 的 `fork()` 实现被调用时，就会触发 atfork 机制。

2. **Android Framework:** Android Framework 的某些底层组件或服务也可能调用 `fork()` 来创建新的进程。例如，`Zygote` 进程通过 `fork()` 来孵化新的应用进程。

3. **系统库:** 许多 Android 系统库（如 `libbinder.so`, `libsqlite.so` 等）在初始化时可能会注册 `pthread_atfork` 处理器来管理它们内部的资源。

**Frida Hook 示例**

可以使用 Frida hook 这些关键函数来观察其执行过程：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const register_atfork = Module.findExportByName(null, "__register_atfork");
    const unregister_atfork = Module.findExportByName(null, "__unregister_atfork");
    const run_prepare = Module.findExportByName(null, "__bionic_atfork_run_prepare");
    const run_parent = Module.findExportByName(null, "__bionic_atfork_run_parent");
    const run_child = Module.findExportByName(null, "__bionic_atfork_run_child");

    if (register_atfork) {
        Interceptor.attach(register_atfork, {
            onEnter: function (args) {
                console.log("[__register_atfork] prepare:", args[0], "parent:", args[1], "child:", args[2], "dso:", args[3]);
            }
        });
    }

    if (unregister_atfork) {
        Interceptor.attach(unregister_atfork, {
            onEnter: function (args) {
                console.log("[__unregister_atfork] dso:", args[0]);
            }
        });
    }

    if (run_prepare) {
        Interceptor.attach(run_prepare, {
            onEnter: function (args) {
                console.log("[__bionic_atfork_run_prepare]");
            }
        });
    }

    if (run_parent) {
        Interceptor.attach(run_parent, {
            onEnter: function (args) {
                console.log("[__bionic_atfork_run_parent]");
            }
        });
    }

    if (run_child) {
        Interceptor.attach(run_child, {
            onEnter: function (args) {
                console.log("[__bionic_atfork_run_child]");
            }
        });
    }
} else {
    console.log("Frida hook not implemented for this architecture.");
}
```

这个 Frida 脚本会 hook `__register_atfork`, `__unregister_atfork`, `__bionic_atfork_run_prepare`, `__bionic_atfork_run_parent`, 和 `__bionic_atfork_run_child` 函数，并在它们被调用时打印相关信息，帮助你理解 atfork 机制的执行流程。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/pthread_atfork.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_atfork.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include "platform/bionic/macros.h"

struct atfork_t {
  atfork_t* next;
  atfork_t* prev;

  void (*prepare)(void);
  void (*child)(void);
  void (*parent)(void);

  void* dso_handle;
};

class atfork_list_t {
 public:
  constexpr atfork_list_t() : first_(nullptr), last_(nullptr) {}

  template<typename F>
  void walk_forward(F f) {
    for (atfork_t* it = first_; it != nullptr; it = it->next) {
      f(it);
    }
  }

  template<typename F>
  void walk_backwards(F f) {
    for (atfork_t* it = last_; it != nullptr; it = it->prev) {
      f(it);
    }
  }

  void push_back(atfork_t* entry) {
    entry->next = nullptr;
    entry->prev = last_;
    if (entry->prev != nullptr) {
      entry->prev->next = entry;
    }
    if (first_ == nullptr) {
      first_ = entry;
    }
    last_ = entry;
  }

  template<typename F>
  void remove_if(F predicate) {
    atfork_t* it = first_;
    while (it != nullptr) {
      if (predicate(it)) {
        atfork_t* entry = it;
        it = it->next;
        remove(entry);
      } else {
        it = it->next;
      }
    }
  }

 private:
  void remove(atfork_t* entry) {
    if (entry->prev != nullptr) {
      entry->prev->next = entry->next;
    } else {
      first_ = entry->next;
    }

    if (entry->next != nullptr) {
      entry->next->prev = entry->prev;
    } else {
      last_ = entry->prev;
    }

    free(entry);
  }

  atfork_t* first_;
  atfork_t* last_;

  BIONIC_DISALLOW_COPY_AND_ASSIGN(atfork_list_t);
};

static pthread_mutex_t g_atfork_list_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static atfork_list_t g_atfork_list;

void __bionic_atfork_run_prepare() {
  // We lock the atfork list here, unlock it in the parent, and reset it in the child.
  // This ensures that nobody can modify the handler array between the calls
  // to the prepare and parent/child handlers.
  pthread_mutex_lock(&g_atfork_list_mutex);

  // Call pthread_atfork() prepare handlers. POSIX states that the prepare
  // handlers should be called in the reverse order of the parent/child
  // handlers, so we iterate backwards.
  g_atfork_list.walk_backwards([](atfork_t* it) {
    if (it->prepare != nullptr) {
      it->prepare();
    }
  });
}

void __bionic_atfork_run_child() {
  g_atfork_list_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

  pthread_mutex_lock(&g_atfork_list_mutex);
  g_atfork_list.walk_forward([](atfork_t* it) {
    if (it->child != nullptr) {
      it->child();
    }
  });
  pthread_mutex_unlock(&g_atfork_list_mutex);
}

void __bionic_atfork_run_parent() {
  g_atfork_list.walk_forward([](atfork_t* it) {
    if (it->parent != nullptr) {
      it->parent();
    }
  });

  pthread_mutex_unlock(&g_atfork_list_mutex);
}

// __register_atfork is the name used by glibc
extern "C" int __register_atfork(void (*prepare)(void), void (*parent)(void),
                                 void(*child)(void), void* dso) {
  atfork_t* entry = reinterpret_cast<atfork_t*>(malloc(sizeof(atfork_t)));
  if (entry == nullptr) {
    return ENOMEM;
  }

  entry->prepare = prepare;
  entry->parent = parent;
  entry->child = child;
  entry->dso_handle = dso;

  pthread_mutex_lock(&g_atfork_list_mutex);

  g_atfork_list.push_back(entry);

  pthread_mutex_unlock(&g_atfork_list_mutex);

  return 0;
}

extern "C" __LIBC_HIDDEN__ void __unregister_atfork(void* dso) {
  pthread_mutex_lock(&g_atfork_list_mutex);
  g_atfork_list.remove_if([&](const atfork_t* entry) {
    return entry->dso_handle == dso;
  });
  pthread_mutex_unlock(&g_atfork_list_mutex);
}

"""

```