Response:
Let's break down the thought process for analyzing this `atexit.cpp` file. The initial request is quite comprehensive, asking for function, Android relevance, implementation details, dynamic linking aspects, error cases, and tracing. Here's a step-by-step approach:

1. **Understand the Core Functionality:** The file name `atexit.cpp` and the presence of `__cxa_atexit` and `__cxa_finalize` immediately suggest this file handles functions to be executed upon program exit or shared library unloading. The comments confirm this.

2. **High-Level Function Breakdown:**
    * **`__cxa_atexit`:**  Register a function to be called on exit. The key parameters are the function pointer, its argument, and the DSO handle (for shared libraries).
    * **`__cxa_finalize`:** Execute the registered functions. It takes an optional DSO handle to only finalize functions associated with that library.
    * **`AtexitArray`:**  This class is the data structure holding the registered functions. It needs methods to add, remove, and manage the array.

3. **Deep Dive into `AtexitArray`:** This class is central, so understanding its implementation is crucial.
    * **Data Structures:**  `array_`, `size_`, `extracted_count_`, `capacity_`, `total_appends_`. Figure out what each represents.
    * **Key Methods:**
        * **`append_entry`:** How is a new function added?  Consider memory allocation and protection.
        * **`extract_entry`:** How is a function removed for execution? What happens to the array?
        * **`recompact`:** Why is this needed? How does it optimize memory?
        * **`set_writable`:** Why is `mprotect` used? What security implications are there?
        * **`expand_capacity`:** How does the array grow?  What happens if allocation fails? `mremap` is a key detail here.
        * **`next_capacity`:** How is the new capacity calculated? Look for potential overflow issues.

4. **Android Relevance:**
    * **NDK:**  C/C++ code in Android apps uses `atexit` and `__cxa_atexit`.
    * **Shared Libraries:**  Android apps rely heavily on shared libraries (`.so` files). The DSO handle in `__cxa_atexit` is crucial for library unloading.
    * **Process Termination:**  When an Android app exits, these functions are executed to perform cleanup.

5. **Dynamic Linking Aspects:**
    * **DSO Handle:** Understand the role of the `dso` parameter. How does the linker provide this?
    * **Unloading Libraries:** How does `__cxa_finalize` with a DSO handle clean up only the functions associated with that library?
    * **`.so` Layout:**  Think about the structure of a shared library and where the linker might store the DSO handle.

6. **Error Cases and Common Mistakes:**
    * **Registering `nullptr`:**  The code explicitly checks for this.
    * **Recursive Calls to `__cxa_finalize`:**  The `call_depth` variable addresses this.
    * **Memory Allocation Failures:**  What happens if `mmap` or `mremap` fails?
    * **Concurrency:** The mutex `g_atexit_lock` is crucial for thread safety.

7. **Tracing and Debugging:**
    * **Frida:**  This is explicitly requested. Think about how to hook `__cxa_atexit` and `__cxa_finalize` to observe their behavior and parameters.

8. **Structure the Answer:**  Organize the information logically. Start with a summary of functionality, then delve into details for each function/class. Address each aspect of the original request systematically.

9. **Refine and Elaborate:**  Once the initial draft is done, review and add more details. For example, explain the purpose of `madvise`, the implications of `PROT_READ` and `PROT_WRITE`, and the role of `prctl`. Ensure the explanations are clear and accurate.

10. **Consider Hypothetical Input/Output:**  While not strictly input/output in the traditional sense, think about the *sequence* of calls. What happens when multiple libraries register exit handlers?  What's the order of execution?

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the `AtexitArray` is just a simple vector. **Correction:** The code uses `mmap` and `mremap`, suggesting a more involved memory management scheme, likely for efficiency and potential memory protection.
* **Initial thought:** The lock is just for basic thread safety. **Refinement:** Consider the interaction between `__cxa_atexit` and `__cxa_finalize` and how the lock prevents race conditions during registration and execution. The `total_appends_` and `restart` logic are key to handling modifications during finalization.
* **Initial thought:**  The DSO handle is just an identifier. **Refinement:** Realize that it's a pointer within the shared library, likely to a specific data structure managed by the dynamic linker.

By following these steps and continually refining understanding, a comprehensive and accurate answer can be constructed. The key is to break down the problem, understand the individual components, and then connect them to the broader Android system and dynamic linking concepts.
好的，我们来详细分析一下 `bionic/libc/bionic/atexit.cpp` 这个文件。

**功能概述**

`atexit.cpp` 文件实现了 C 标准库中的 `atexit` 函数以及 C++ 异常处理相关的 `__cxa_atexit` 和 `__cxa_finalize` 函数。这些函数的主要功能是：

1. **注册退出处理函数 (`atexit`, `__cxa_atexit`)**: 允许程序在正常退出时（例如，通过调用 `exit()` 或 `return` 从 `main()` 函数返回）或者在共享库被卸载时执行一些清理工作。
2. **执行退出处理函数 (`__cxa_finalize`)**:  负责在程序退出或共享库卸载时，按照注册的顺序（后进先出）调用这些清理函数。

**与 Android 功能的关系及举例说明**

这个文件是 Android Bionic C 库的核心组成部分，对于 Android 应用程序和系统库的正常运行至关重要。

* **应用程序退出清理:** 当一个 Android 应用程序正常退出时，`atexit` 或 `__cxa_atexit` 注册的函数会被调用，用于释放资源、关闭文件、刷新缓冲区等。例如，一个应用程序可能会使用 `atexit` 注册一个函数来确保在退出时将所有未保存的数据写入磁盘。

```c++
#include <cstdlib>
#include <cstdio>

void cleanup() {
  printf("程序即将退出，执行清理工作。\n");
  // 关闭文件，释放内存等操作
}

int main() {
  atexit(cleanup);
  printf("程序开始运行。\n");
  return 0;
}
```

* **共享库卸载清理:** 在 Android 系统中，动态链接库（.so 文件）可以在运行时加载和卸载。当一个共享库被卸载时，`__cxa_atexit` 注册的与该库相关的函数会被 `__cxa_finalize` 调用。这对于 C++ 对象的析构函数非常重要，确保在库卸载时，其对象能够被正确销毁，防止内存泄漏或其他资源泄漏。

```c++
// 在一个共享库中
#include <cstdlib>
#include <new>

class MyClass {
public:
  MyClass() { printf("MyClass 构造函数\n"); }
  ~MyClass() { printf("MyClass 析构函数\n"); }
};

void cleanup_myclass(void* p) {
  delete static_cast<MyClass*>(p);
  printf("清理 MyClass 实例\n");
}

static MyClass* global_object = nullptr;

__attribute__((constructor)) void on_load() {
  global_object = new MyClass();
  if (std::atexit(cleanup_myclass, global_object) != 0) {
    // 处理注册失败的情况
  }
}

__attribute__((destructor)) void on_unload() {
  // 通常不需要在这里手动调用，__cxa_finalize 会处理
  printf("共享库即将卸载\n");
}
```

* **Framework 和 NDK 的使用:** Android Framework 和 NDK 开发的应用程序都会间接地使用这些函数。Framework 中的 Java 代码最终会调用 Native 代码，而 Native 代码可能会使用 `atexit` 或 `__cxa_atexit` 来管理资源。NDK 开发的 C/C++ 应用程序直接使用这些函数进行清理。

**libc 函数实现详解**

1. **`__cxa_atexit(void (*func)(void*), void* arg, void* dso)`**:
   - **功能:** 注册一个函数 `func`，该函数将在程序退出或与 `dso` 关联的共享库卸载时被调用。`arg` 是传递给 `func` 的参数，`dso` 是共享模块的句柄。
   - **实现:**
     - 使用一个全局的 `AtexitArray` 对象 `g_array` 来存储注册的函数信息（`AtexitEntry` 结构体包含函数指针 `fn`、参数 `arg` 和 DSO 句柄 `dso`）。
     - 使用一个互斥锁 `g_atexit_lock` 来保证线程安全，因为 `atexit` 可能在多线程环境中被调用。
     - `append_entry` 方法将新的 `AtexitEntry` 添加到 `g_array` 中。
     - `AtexitArray` 使用动态分配的数组来存储条目，并且会根据需要扩展容量（通过 `expand_capacity`，使用 `mmap` 或 `mremap`）。
     - 为了防止意外或恶意修改，`AtexitArray` 使用 `mprotect` 来设置内存页的读写权限，通常情况下是只读的，只有在添加或修改条目时才设置为可写。
   - **假设输入与输出:**
     - **输入:** `func` 指向一个清理函数，`arg` 是传递给 `func` 的数据指针，`dso` 是共享库的句柄（如果与共享库关联，否则为 `nullptr`）。
     - **输出:** 成功返回 0，失败返回 -1。成功会将函数信息添加到 `g_array` 中。

2. **`__cxa_finalize(void* dso)`**:
   - **功能:** 执行先前通过 `__cxa_atexit` 注册的函数。如果 `dso` 不为 `nullptr`，则只执行与该共享库关联的函数；如果 `dso` 为 `nullptr`，则执行所有注册的函数（通常在程序退出时调用）。
   - **实现:**
     - 获取 `g_atexit_lock` 互斥锁。
     - 遍历 `g_array`，从后向前查找需要执行的函数。
     - 如果找到需要执行的函数（`g_array[i].fn != nullptr` 且 `dso` 匹配或者 `dso == nullptr`），则调用该函数 `entry.fn(entry.arg)`。
     - 在调用函数之前，使用 `extract_entry` 将该条目从数组中移除，以避免重复执行，特别是在 `__cxa_finalize` 递归调用的情况下。
     - 为了处理在执行清理函数过程中又有新的函数通过 `__cxa_atexit` 注册的情况，代码使用了 `total_appends_` 计数器。如果在执行过程中发现有新的条目被添加，则会重新开始遍历（`goto restart`）。
     - 在执行完与特定 DSO 相关的函数后，会调用 `__unregister_atfork(dso)`，这部分涉及到 `fork` 相关的清理，超出了 `atexit` 的直接范围。
     - 如果 `dso` 为 `nullptr`（程序退出），则还会调用 `__libc_stdio_cleanup()` 来刷新标准 I/O 缓冲区。
     - 为了优化内存使用，`__cxa_finalize` 在非递归调用且不是程序退出的情况下，会调用 `g_array.recompact()` 来整理数组，移除已执行的条目留下的空洞。`recompact` 使用 `madvise` 来提示内核可以回收不再使用的内存页。
   - **假设输入与输出:**
     - **输入:** `dso` 是要卸载的共享库句柄（如果卸载库），或者 `nullptr`（如果程序退出）。
     - **输出:** 无返回值。执行所有需要执行的已注册的清理函数。

**涉及 dynamic linker 的功能**

`__cxa_atexit` 和 `__cxa_finalize` 与 dynamic linker 紧密相关，特别是在处理共享库的加载和卸载时。

* **DSO 句柄:**  `dso` 参数（Dynamic Shared Object）是由 dynamic linker 提供的，用于标识一个特定的共享库。当使用 `dlopen` 加载一个共享库时，dynamic linker 会返回一个 `dso` 句柄。当库被卸载时（通过 `dlclose`），dynamic linker 会调用 `__cxa_finalize` 并传递该库的 `dso` 句柄，以便执行与该库相关的清理函数。

* **`.so` 布局样本:**

```
加载地址: 0xb4000000
  ...
  .dynamic 段:
    ...
    SONAME              libmylib.so
    INIT                0xb4001000  // 初始化函数地址
    FINI                0xb4005000  // 终止函数地址 (通常指向 __cxa_finalize)
    INIT_ARRAY          0xb4008000  // 初始化函数指针数组
    FINI_ARRAY          0xb4008010  // 终止函数指针数组 (包含通过 __cxa_atexit 注册的函数)
    ...
  ...
  __dso_handle 变量地址: 0xb400A000  // 这是一个隐藏的变量，用于标识该 DSO
  ...
  代码段
  数据段
  ...
```

* **链接的处理过程:**
    1. **加载时:** 当 dynamic linker 加载一个共享库时，它会遍历库的 `.init_array` 段，并执行其中的初始化函数。对于 C++ 库，这通常会包含全局对象的构造函数。
    2. **`__cxa_atexit` 注册:** 在共享库的代码中，如果使用了 `std::atexit`（最终会调用 `__cxa_atexit`），dynamic linker 会将注册的函数信息（函数指针、参数、以及该库的 `__dso_handle` 地址作为 `dso`）存储在一个全局的 `atexit` 列表中。
    3. **卸载时:** 当调用 `dlclose` 卸载共享库时，dynamic linker 会执行以下操作：
        - 调用该库的 `FINI` 条目指向的函数，通常是 `__cxa_finalize`，并将该库的 `__dso_handle` 地址作为参数传递给它。
        - `__cxa_finalize` 遍历全局的 `atexit` 列表，找到 `dso` 匹配的条目，并执行相应的清理函数（例如，调用 C++ 全局对象的析构函数）。
        - 执行完与该库相关的清理函数后，dynamic linker 可能会执行其他的卸载操作，例如解除内存映射。

**逻辑推理：假设输入与输出**

假设我们有以下场景：

1. 一个名为 `libtest.so` 的共享库被加载。
2. 在 `libtest.so` 中，通过 `__cxa_atexit` 注册了两个清理函数 `cleanup1` 和 `cleanup2`，它们都与 `libtest.so` 的 `__dso_handle` 关联。
3. 主程序调用 `dlclose` 卸载 `libtest.so`。

**预期输出:**

当 `dlclose` 被调用时，dynamic linker 会调用 `__cxa_finalize` 并传入 `libtest.so` 的 `__dso_handle`。`__cxa_finalize` 会找到与该 `dso` 关联的 `cleanup2` 和 `cleanup1` 函数，并按照 **后进先出** 的顺序执行它们：

1. `cleanup2` 被调用。
2. `cleanup1` 被调用。

**用户或编程常见的使用错误**

1. **在清理函数中调用可能导致死锁的操作:**  如果在 `atexit` 注册的函数中尝试获取已经被持有的锁，可能会导致死锁。
2. **在清理函数中访问已释放的资源:**  清理函数的执行顺序不完全可控，如果一个清理函数依赖于另一个清理函数释放的资源，可能会导致访问无效内存。
3. **注册过多的清理函数:**  虽然技术上可行，但注册过多的清理函数会增加程序退出的时间。
4. **在共享库的清理函数中访问主程序的资源:**  当共享库被卸载时，主程序的某些资源可能已经被释放或失效，访问这些资源可能导致崩溃。
5. **忘记注册清理函数导致资源泄漏:**  对于需要手动释放的资源（例如，`malloc` 分配的内存，打开的文件），如果没有注册相应的清理函数，会导致资源泄漏。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:**
   - NDK 开发的 C/C++ 代码可以直接调用 `atexit` 或使用 C++ 的全局对象，其析构函数注册机制最终会调用 `__cxa_atexit`。
   - 当 NDK 应用退出或动态链接库被卸载时，Bionic 的 `libc.so` 中的 `__cxa_finalize` 会被调用。

2. **Android Framework:**
   - Android Framework 的许多组件是用 Java 编写的，但底层仍然依赖于 Native 代码（C/C++）。
   - Framework 中的 Native 组件（例如，SurfaceFlinger，MediaServer）可能会使用 `atexit` 或 `__cxa_atexit` 来管理其资源。
   - 当 Framework 进程退出或其内部的共享库被卸载时，也会触发 `__cxa_finalize` 的调用。

**Frida Hook 示例调试步骤**

我们可以使用 Frida 来 hook `__cxa_atexit` 和 `__cxa_finalize` 函数，以观察其调用情况和参数。

**Frida Hook 代码示例:**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName('libc.so');
  const cxa_atexit = libc.getExportByName('__cxa_atexit');
  const cxa_finalize = libc.getExportByName('__cxa_finalize');

  if (cxa_atexit) {
    Interceptor.attach(cxa_atexit, {
      onEnter: function (args) {
        const func = args[0];
        const arg = args[1];
        const dso = args[2];
        console.log('[__cxa_atexit] Called');
        console.log('  Function:', func);
        console.log('  Argument:', arg);
        console.log('  DSO:', dso);
        if (dso.isNull()) {
          console.log('  DSO: NULL (Program exit handler)');
        } else {
          const dsoName = Memory.readCString(Module.findNameForAddress(dso));
          console.log('  DSO Name:', dsoName);
        }
      }
    });
  } else {
    console.error('Error: __cxa_atexit not found.');
  }

  if (cxa_finalize) {
    Interceptor.attach(cxa_finalize, {
      onEnter: function (args) {
        const dso = args[0];
        console.log('[__cxa_finalize] Called');
        console.log('  DSO:', dso);
        if (dso.isNull()) {
          console.log('  DSO: NULL (Program exit)');
        } else {
          const dsoName = Module.findNameForAddress(dso);
          console.log('  DSO Name:', dsoName);
        }
      }
    });
  } else {
    console.error('Error: __cxa_finalize not found.');
  }
} else {
  console.log('This script is designed for Android.');
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_atexit.js`。
3. **运行 Frida:** 使用 Frida 命令将脚本注入到目标进程。你需要知道目标进程的名称或 PID。

   ```bash
   frida -U -f <package_name> -l hook_atexit.js --no-pause
   # 或者，如果进程已经在运行
   frida -U <package_name> -l hook_atexit.js
   # 或者使用 PID
   frida -p <pid> -l hook_atexit.js
   ```

   将 `<package_name>` 替换为你要调试的 Android 应用的包名。

4. **观察输出:** 当目标应用退出或其共享库被卸载时，Frida 会在控制台上打印出 `__cxa_atexit` 和 `__cxa_finalize` 的调用信息，包括注册的函数地址、参数和相关的 DSO 句柄。

通过 Frida Hook，你可以清晰地观察到哪些函数被注册为退出处理程序，以及它们在何时被执行，这对于理解 Android 系统和应用程序的生命周期管理以及调试资源泄漏等问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/bionic/atexit.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include "atexit.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>

#include <async_safe/CHECK.h>
#include <async_safe/log.h>

#include "platform/bionic/page.h"

extern "C" void __libc_stdio_cleanup();
extern "C" void __unregister_atfork(void* dso);

namespace {

struct AtexitEntry {
  void (*fn)(void*);  // the __cxa_atexit callback
  void* arg;          // argument for `fn` callback
  void* dso;          // shared module handle
};

class AtexitArray {
 public:
  size_t size() const { return size_; }
  uint64_t total_appends() const { return total_appends_; }
  const AtexitEntry& operator[](size_t idx) const { return array_[idx]; }

  bool append_entry(const AtexitEntry& entry);
  AtexitEntry extract_entry(size_t idx);
  void recompact();

 private:
  AtexitEntry* array_;
  size_t size_;
  size_t extracted_count_;
  size_t capacity_;

  // An entry can be appended by a __cxa_finalize callback. Track the number of appends so we
  // restart concurrent __cxa_finalize passes.
  uint64_t total_appends_;

  static size_t page_start_of_index(size_t idx) { return page_start(idx * sizeof(AtexitEntry)); }
  static size_t page_end_of_index(size_t idx) { return page_end(idx * sizeof(AtexitEntry)); }

  // Recompact the array if it will save at least one page of memory at the end.
  bool needs_recompaction() const {
    return page_end_of_index(size_ - extracted_count_) < page_end_of_index(size_);
  }

  void set_writable(bool writable, size_t start_idx, size_t num_entries);
  static bool next_capacity(size_t capacity, size_t* result);
  bool expand_capacity();
};

}  // anonymous namespace

bool AtexitArray::append_entry(const AtexitEntry& entry) {
  if (size_ >= capacity_ && !expand_capacity()) return false;

  size_t idx = size_++;

  set_writable(true, idx, 1);
  array_[idx] = entry;
  ++total_appends_;
  set_writable(false, idx, 1);

  return true;
}

// Extract an entry and return it.
AtexitEntry AtexitArray::extract_entry(size_t idx) {
  AtexitEntry result = array_[idx];

  set_writable(true, idx, 1);
  array_[idx] = {};
  ++extracted_count_;
  set_writable(false, idx, 1);

  return result;
}

void AtexitArray::recompact() {
  if (!needs_recompaction()) return;

  set_writable(true, 0, size_);

  // Optimization: quickly skip over the initial non-null entries.
  size_t src = 0, dst = 0;
  while (src < size_ && array_[src].fn != nullptr) {
    ++src;
    ++dst;
  }

  // Shift the non-null entries forward, and zero out the removed entries at the end of the array.
  for (; src < size_; ++src) {
    const AtexitEntry entry = array_[src];
    array_[src] = {};
    if (entry.fn != nullptr) {
      array_[dst++] = entry;
    }
  }

  // If the table uses fewer pages, clean the pages at the end.
  size_t old_bytes = page_end_of_index(size_);
  size_t new_bytes = page_end_of_index(dst);
  if (new_bytes < old_bytes) {
    madvise(reinterpret_cast<char*>(array_) + new_bytes, old_bytes - new_bytes, MADV_DONTNEED);
  }

  set_writable(false, 0, size_);

  size_ = dst;
  extracted_count_ = 0;
}

// Use mprotect to make the array writable or read-only. Returns true on success. Making the array
// read-only could protect against either unintentional or malicious corruption of the array.
void AtexitArray::set_writable(bool writable, size_t start_idx, size_t num_entries) {
  if (array_ == nullptr) return;

  const size_t start_byte = page_start_of_index(start_idx);
  const size_t stop_byte = page_end_of_index(start_idx + num_entries);
  const size_t byte_len = stop_byte - start_byte;

  const int prot = PROT_READ | (writable ? PROT_WRITE : 0);
  if (mprotect(reinterpret_cast<char*>(array_) + start_byte, byte_len, prot) != 0) {
    async_safe_fatal("mprotect failed on atexit array: %m");
  }
}

// Approximately double the capacity. Returns true if successful (no overflow). AtexitEntry is
// smaller than a page, but this function should still be correct even if AtexitEntry were larger
// than one.
bool AtexitArray::next_capacity(size_t capacity, size_t* result) {
  if (capacity == 0) {
    *result = page_end(sizeof(AtexitEntry)) / sizeof(AtexitEntry);
    return true;
  }
  size_t num_bytes;
  if (__builtin_mul_overflow(page_end_of_index(capacity), 2, &num_bytes)) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "__cxa_atexit: capacity calculation overflow");
    return false;
  }
  *result = num_bytes / sizeof(AtexitEntry);
  return true;
}

bool AtexitArray::expand_capacity() {
  size_t new_capacity;
  if (!next_capacity(capacity_, &new_capacity)) return false;
  const size_t new_capacity_bytes = page_end_of_index(new_capacity);

  set_writable(true, 0, capacity_);

  bool result = false;
  void* new_pages;
  if (array_ == nullptr) {
    new_pages = mmap(nullptr, new_capacity_bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  } else {
    // mremap fails if the source buffer crosses a boundary between two VMAs. When a single array
    // element is modified, the kernel should split then rejoin the buffer's VMA.
    new_pages = mremap(array_, page_end_of_index(capacity_), new_capacity_bytes, MREMAP_MAYMOVE);
  }
  if (new_pages == MAP_FAILED) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "__cxa_atexit: mmap/mremap failed to allocate %zu bytes: %m",
                          new_capacity_bytes);
  } else {
    result = true;
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, new_pages, new_capacity_bytes, "atexit handlers");
    array_ = static_cast<AtexitEntry*>(new_pages);
    capacity_ = new_capacity;
  }
  set_writable(false, 0, capacity_);
  return result;
}

static AtexitArray g_array;
static pthread_mutex_t g_atexit_lock = PTHREAD_MUTEX_INITIALIZER;

static inline void atexit_lock() {
  pthread_mutex_lock(&g_atexit_lock);
}

static inline void atexit_unlock() {
  pthread_mutex_unlock(&g_atexit_lock);
}

// Register a function to be called either when a library is unloaded (dso != nullptr), or when the
// program exits (dso == nullptr). The `dso` argument is typically the address of a hidden
// __dso_handle variable. This function is also used as the backend for the atexit function.
//
// See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#dso-dtor.
//
int __cxa_atexit(void (*func)(void*), void* arg, void* dso) {
  int result = -1;

  if (func != nullptr) {
    atexit_lock();
    if (g_array.append_entry({.fn = func, .arg = arg, .dso = dso})) {
      result = 0;
    }
    atexit_unlock();
  }

  return result;
}

void __cxa_finalize(void* dso) {
  atexit_lock();

  static uint32_t call_depth = 0;
  ++call_depth;

restart:
  const uint64_t total_appends = g_array.total_appends();

  for (ssize_t i = g_array.size() - 1; i >= 0; --i) {
    if (g_array[i].fn == nullptr || (dso != nullptr && g_array[i].dso != dso)) continue;

    // Clear the entry in the array because its DSO handle will become invalid, and to avoid calling
    // an entry again if __cxa_finalize is called recursively.
    const AtexitEntry entry = g_array.extract_entry(i);

    atexit_unlock();
    entry.fn(entry.arg);
    atexit_lock();

    if (g_array.total_appends() != total_appends) goto restart;
  }

  // Avoid recompaction on recursive calls because it's unnecessary and would require earlier,
  // concurrent __cxa_finalize calls to restart. Skip recompaction on program exit too
  // (dso == nullptr), because the memory will be reclaimed soon anyway.
  --call_depth;
  if (call_depth == 0 && dso != nullptr) {
    g_array.recompact();
  }

  atexit_unlock();

  if (dso != nullptr) {
    __unregister_atfork(dso);
  } else {
    // If called via exit(), flush output of all open files.
    __libc_stdio_cleanup();
  }
}
```