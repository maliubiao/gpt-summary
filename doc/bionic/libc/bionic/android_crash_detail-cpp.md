Response:
Let's break down the thought process for analyzing the `android_crash_detail.cpp` file.

**1. Understanding the Goal:** The request asks for a comprehensive analysis of the provided C++ code. This includes functionality, relationship to Android, implementation details, dynamic linking aspects, error handling, usage in the Android ecosystem, and debugging techniques. The output should be in Chinese.

**2. Initial Code Scan & Keyword Identification:**  First, I'd quickly scan the code, looking for key elements:

* **Includes:** `android/crash_detail.h`, `async_safe/log.h`, `bionic/crash_detail_internal.h`, standard C/C++ headers (`bits/stdatomic.h`, `pthread.h`, etc.), and private bionic headers. This gives a high-level idea of the dependencies and the domain.
* **Function Names:** `android_crash_detail_register`, `android_crash_detail_unregister`, `android_crash_detail_replace_data`, `android_crash_detail_replace_name`. These are the core functionalities.
* **Data Structures:** `crash_detail_t`, `crash_detail_page_t`. Understanding these structures is crucial.
* **Global Variables:** `free_head`, `__libc_shared_globals()->crash_detail_page`, `__libc_shared_globals()->crash_detail_page_lock`. These suggest memory management and synchronization.
* **Key System Calls/APIs:** `mmap`, `prctl`, atomic operations (`atomic_load`, `atomic_compare_exchange_strong`), mutex locking (`ScopedPthreadMutexLocker`). These indicate interaction with the operating system and concurrency control.
* **Macros/Attributes:** `__BIONIC_WEAK_FOR_NATIVE_BRIDGE`. This points to how the functions are exposed and used in different contexts.

**3. Deconstructing Each Function:**  I'd analyze each function individually:

* **`android_crash_detail_register`:**
    * **Purpose:**  Registers crash-related details (name and data).
    * **Fast Path:**  Recognize the atomic operations on `free_head` as an optimization for quick allocation and deallocation. This hints at a stack-like or freelist approach.
    * **Slow Path:**  Identify the mutex (`__libc_shared_globals()->crash_detail_page_lock`) and the `crash_detail_page_t` structure. The use of `mmap` for allocating pages and `prctl` for naming the memory region is important. The logic of allocating new pages when the current one is full is clear.
    * **Connection to Android:** The function name itself strongly suggests Android involvement. The purpose relates to debugging and crash reporting, a core Android feature.
* **`android_crash_detail_unregister`:**
    * **Purpose:** Releases a registered `crash_detail_t`.
    * **Freelist Implementation:** Recognize the logic of adding the released object back to the `free_head` list using atomic operations. The check `crash_detail->prev_free` prevents double-freeing.
    * **Connection to Android:**  Essential for managing the resources allocated in `register`.
* **`android_crash_detail_replace_data` and `android_crash_detail_replace_name`:**
    * **Purpose:**  Allow modifying the data and name associated with a registered detail.
    * **Simple Implementation:** These are straightforward assignments.
    * **Connection to Android:** Provide flexibility in updating crash information.

**4. Identifying Key Concepts and Relationships:**

* **Crash Reporting:**  The function names and the purpose of storing "name" and "data" clearly link to crash reporting and debugging. This is a fundamental aspect of Android.
* **Memory Management:** The use of `mmap` and the freelist mechanism shows how memory is managed for storing crash details. The two-path approach (fast atomic path and slower mutex-protected path) highlights optimization strategies.
* **Concurrency Control:** The mutex and atomic operations are essential for thread safety, as multiple threads might be registering or unregistering crash details.
* **Dynamic Linking:** The `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` attribute signifies the function's visibility to the native bridge, which is a key component of the Android runtime.

**5. Addressing Specific Requirements:**

* **Libc Function Details:** Explain `mmap`, `prctl`, mutex operations, and atomic operations, relating them to memory management, security, and concurrency.
* **Dynamic Linker:**  Explain the role of `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` and provide a basic SO layout example. Describe the linking process conceptually.
* **Logical Reasoning (Input/Output):** While the code doesn't involve complex logic, illustrate the registration and unregistration process with hypothetical inputs and outputs.
* **User/Programming Errors:**  Focus on common mistakes like double-unregistering or not unregistering, leading to memory leaks.
* **Android Framework/NDK Usage:**  Describe the typical crash reporting flow, starting from a crash signal, going through the signal handler, and how `android_crash_detail_register` might be called to add contextual information.
* **Frida Hooking:**  Provide concrete Frida examples for intercepting the key functions and inspecting their arguments and return values.

**6. Structuring the Output (in Chinese):**

* **功能列表:** Start with a high-level overview of the file's purpose and the functions it provides.
* **与 Android 的关系:** Explicitly connect the functionality to Android's crash reporting and debugging mechanisms. Provide concrete examples.
* **Libc 函数详解:** Detail the implementation of `mmap`, `prctl`, mutexes, and atomics.
* **动态链接器功能:** Explain the role of `__BIONIC_WEAK_FOR_NATIVE_BRIDGE`, provide the SO layout, and describe the linking process.
* **逻辑推理 (假设输入与输出):** Illustrate the registration and unregistration flow.
* **用户或编程常见错误:**  Give examples of common mistakes.
* **Android Framework/NDK 如何到达这里:** Explain the crash reporting flow from a high level.
* **Frida Hook 示例:** Provide practical Frida code snippets.

**7. Iteration and Refinement:**  Review the generated output for clarity, accuracy, and completeness. Ensure all aspects of the original request are addressed. For example, initially, I might not have explicitly mentioned the purpose of the fast path optimization, but on review, I'd add that detail. I'd also ensure the Chinese is natural and easy to understand.

This detailed, step-by-step approach ensures a thorough analysis of the code and a comprehensive response to the user's request. The key is to break down the problem into smaller, manageable parts and then synthesize the findings into a cohesive explanation.
好的，让我们详细分析一下 `bionic/libc/bionic/android_crash_detail.cpp` 这个文件。

**功能列表**

这个文件定义了用于注册和管理崩溃细节的函数，主要功能包括：

1. **`android_crash_detail_register`**: 注册一个崩溃细节，允许在崩溃报告中包含额外的名称和数据。
2. **`android_crash_detail_unregister`**: 取消注册一个已注册的崩溃细节，释放相关资源。
3. **`android_crash_detail_replace_data`**: 替换已注册崩溃细节中的数据部分。
4. **`android_crash_detail_replace_name`**: 替换已注册崩溃细节中的名称部分。

**与 Android 功能的关系及举例说明**

这个文件直接关系到 Android 平台的崩溃报告机制。当应用或 Native 代码发生崩溃时，Android 系统会生成崩溃报告。这些报告对于开发者调试和修复问题至关重要。

`android_crash_detail.cpp` 提供的功能允许在崩溃发生前，或者在崩溃处理过程中，向崩溃报告中添加自定义的上下文信息。

**举例说明:**

假设你的 Native 代码中有一个复杂的算法，你希望在崩溃报告中包含算法执行到哪个阶段的关键信息。你可以在算法的关键步骤中使用 `android_crash_detail_register` 来记录这些信息。如果程序崩溃，这些信息就会包含在崩溃报告中，帮助你定位问题。

例如：

```c++
#include <android/crash_detail.h>
#include <string>

void complex_algorithm() {
  std::string step1_data = "Data at step 1";
  crash_detail_t* detail = android_crash_detail_register("algorithm_step", strlen("algorithm_step"),
                                                        step1_data.c_str(), step1_data.size());
  // ... 执行算法的第一步 ...

  if (/* 发生错误需要记录更多信息 */) {
    std::string step2_data = "Error occurred at step 2 with some crucial values";
    android_crash_detail_replace_data(detail, step2_data.c_str(), step2_data.size());
  }

  // ... 如果不再需要这个 detail 了 ...
  android_crash_detail_unregister(detail);
}
```

在这个例子中，`android_crash_detail_register` 用于标记当前执行到算法的哪个步骤，并将相关数据添加到崩溃报告中。如果之后发生错误，可以使用 `android_crash_detail_replace_data` 更新数据。

**详细解释每一个 libc 函数的功能是如何实现的**

这个文件中涉及到的 libc 函数主要是内存管理和线程同步相关的：

1. **`mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)`**:
   - **功能:** 在进程的地址空间中创建一个新的内存映射。
   - **实现:**
     - `nullptr`:  表示由系统选择映射的起始地址。
     - `size`:  指定映射的长度，这里是 `sizeof(crash_detail_page_t)`。
     - `PROT_READ | PROT_WRITE`:  设置内存保护属性为可读写。
     - `MAP_ANON | MAP_PRIVATE`:
       - `MAP_ANON`:  表示创建的是匿名映射，即不与任何文件关联。
       - `MAP_PRIVATE`: 表示创建的是私有映射，对这块内存的修改不会影响到其他进程或文件。
     - `-1`:  文件描述符，对于匿名映射通常设置为 -1。
     - `0`:  文件偏移量，对于匿名映射设置为 0。
   - **在这个文件中的作用:** 用于分配 `crash_detail_page_t` 结构体的内存页，这些页用于存储 `crash_detail_t` 对象。

2. **`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, map, size, "crash details")`**:
   - **功能:**  对进程或线程的行为进行控制。这里用于设置匿名内存区域的名称。
   - **实现:** 这是一个系统调用，其具体实现依赖于 Linux 内核。
     - `PR_SET_VMA`:  指定要执行的操作是设置虚拟内存区域的属性。
     - `PR_SET_VMA_ANON_NAME`:  指定要设置的是匿名内存区域的名称。
     - `map`:  指向要命名的内存区域的起始地址。
     - `size`:  内存区域的大小。
     - `"crash details"`:  要设置的名称。
   - **在这个文件中的作用:** 方便在调试工具（如 `/proc/<pid>/maps`）中识别这些用于存储崩溃细节的内存区域。

3. **原子操作 (`atomic_load`, `atomic_compare_exchange_strong`)**:
   - **功能:**  提供线程安全的访问和修改共享变量的机制。
   - **实现:**  这些通常由编译器和硬件共同实现，利用原子指令来保证操作的不可分割性。
     - `atomic_load(&free_head)`: 原子地读取 `free_head` 的值。
     - `atomic_compare_exchange_strong(&free_head, &head, head->prev_free)`: 原子地比较 `free_head` 的当前值是否等于 `head`，如果相等，则将其设置为 `head->prev_free`。这是一个实现无锁数据结构的关键操作。
   - **在这个文件中的作用:**  用于管理空闲的 `crash_detail_t` 对象链表 (`free_head`)，实现快速的注册和取消注册，而无需每次都获取互斥锁。

4. **`pthread_mutex_t` 和 `ScopedPthreadMutexLocker`**:
   - **功能:** 提供互斥锁，用于保护共享资源，防止多线程并发访问导致的数据竞争。
   - **实现:**  互斥锁通常由操作系统内核实现，通过系统调用来实现加锁和解锁操作。
   - **`ScopedPthreadMutexLocker locker(&__libc_shared_globals()->crash_detail_page_lock)`**: 这是一个 RAII (Resource Acquisition Is Initialization) 风格的互斥锁管理类。当 `locker` 对象创建时，它会自动尝试获取互斥锁；当对象销毁时（例如，离开作用域），它会自动释放互斥锁。
   - **在这个文件中的作用:**  保护 `crash_detail_page` 全局变量，确保在分配新的 `crash_detail_t` 对象时，不会发生多线程冲突。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程**

这个文件中使用了 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 宏修饰了这四个函数。这个宏表明这些函数在 Native Bridge 上是弱符号。

**SO 布局样本:**

假设 `libc.so` 是 Bionic 的主要库文件，其中包含了这些函数的定义。一个简单的 `libc.so` 的布局可能如下：

```
.text     # 存放代码段
  ...
  android_crash_detail_register:  # 函数的指令
    ...
  android_crash_detail_unregister:
    ...
  android_crash_detail_replace_data:
    ...
  android_crash_detail_replace_name:
    ...
  ...

.data     # 存放已初始化的全局变量
  free_head: ...
  __libc_shared_globals: ...
  ...

.bss      # 存放未初始化的全局变量

.symtab   # 符号表
  ...
  android_crash_detail_register  WEAK ...
  android_crash_detail_unregister WEAK ...
  android_crash_detail_replace_data WEAK ...
  android_crash_detail_replace_name WEAK ...
  ...
```

**链接的处理过程:**

1. **编译时:** 当 NDK 代码调用这些函数时，链接器会查找这些符号。由于这些符号被标记为 `WEAK`，如果链接器在其他库中找到了同名的强符号，它会优先链接到那个强符号。
2. **运行时 (Native Bridge):** Native Bridge 是 Android 用于兼容 32 位应用的机制。当一个 32 位应用在 64 位系统上运行时，Native Bridge 会介入。
3. **弱符号的作用:** `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 使得这些函数在 Native Bridge 的上下文中可以被替换或覆盖。这意味着 Native Bridge 可以提供自己的实现，或者在 32 位和 64 位环境中提供不同的实现。
4. **查找过程:** 当 Native 代码调用 `android_crash_detail_register` 时，动态链接器会按照一定的顺序查找符号。如果当前进程运行在 Native Bridge 下，链接器可能会先检查 Native Bridge 提供的符号表。如果找不到，则会继续在标准的 `libc.so` 中查找。

**逻辑推理，假设输入与输出**

**假设输入:**

1. 线程 A 调用 `android_crash_detail_register("my_feature", 10, "some data", 9)`。
2. 线程 B 调用 `android_crash_detail_register("another_info", 12, "more data", 9)`。
3. 线程 A 调用 `android_crash_detail_unregister` 之前注册的 detail。

**输出:**

1. `android_crash_detail_register` 在线程 A 中会返回一个指向新分配的 `crash_detail_t` 结构的指针，该结构的 `name` 指向 "my_feature"，`name_size` 为 10，`data` 指向 "some data"，`data_size` 为 9。
2. `android_crash_detail_register` 在线程 B 中也会返回一个指向新分配的 `crash_detail_t` 结构的指针，内容类似。 由于使用了互斥锁或原子操作，两个线程的分配操作是线程安全的，不会出现数据竞争。
3. `android_crash_detail_unregister` 在线程 A 中会将之前分配的 `crash_detail_t` 对象添加到空闲链表 `free_head` 中，以便后续的注册操作可以重用该内存。

**更详细的输出情景:**

* **首次注册 (空闲链表为空):** `android_crash_detail_register` 会尝试从空闲链表 `free_head` 中获取空闲的结构体，如果为空，则会分配新的内存页 (`crash_detail_page_t`) 并从中分配一个 `crash_detail_t`。
* **后续注册 (空闲链表有空闲项):** `android_crash_detail_register` 会尝试从 `free_head` 中取出一个空闲的 `crash_detail_t`，并更新其内容。
* **取消注册:** `android_crash_detail_unregister` 会将指定的 `crash_detail_t` 添加回 `free_head` 链表。

**涉及用户或者编程常见的使用错误，请举例说明**

1. **忘记取消注册 (`android_crash_detail_unregister`)**:
   - **错误:**  在注册了崩溃细节后，如果没有及时调用 `android_crash_detail_unregister` 释放资源，会导致内存泄漏。虽然这里的内存是通过 `mmap` 分配的，最终会被进程回收，但在进程运行期间会占用额外的内存。
   - **示例:**
     ```c++
     void some_function() {
       crash_detail_t* detail = android_crash_detail_register("temp", 4, "data", 4);
       // ... 使用 detail，但是忘记 unregister ...
     } // detail 指针丢失，但内存未释放
     ```

2. **重复取消注册**:
   - **错误:** 对同一个 `crash_detail_t` 指针调用 `android_crash_detail_unregister` 多次，可能导致空闲链表的混乱，甚至程序崩溃。代码中已经有检查 `crash_detail->prev_free` 来避免这种情况。
   - **示例:**
     ```c++
     crash_detail_t* detail = android_crash_detail_register("test", 4, "data", 4);
     android_crash_detail_unregister(detail);
     android_crash_detail_unregister(detail); // 错误：重复 unregister
     ```

3. **在 `crash_detail_t` 对象分配的内存之外进行读写**:
   - **错误:**  虽然用户不太可能直接操作 `crash_detail_t` 的内存，但是如果错误地计算 `name_size` 或 `data_size`，可能会导致越界读写。

4. **多线程竞争未保护的 `crash_detail_t` 对象**:
   - **错误:** 如果多个线程同时修改同一个已注册的 `crash_detail_t` 对象的内容，可能会导致数据竞争。虽然 `register` 和 `unregister` 操作是线程安全的，但对已注册对象的 `replace_data` 或 `replace_name` 操作如果不是原子性的，就需要外部同步。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 如何到达这里:**

1. **Native 代码中的调用:**  NDK 开发的应用在其 Native 代码中可以直接调用 `android_crash_detail_register` 等函数。
2. **Android Framework 的使用 (间接):**  虽然 Framework 层通常不直接调用这些函数，但 Framework 可能会调用底层的 Native 代码，而这些 Native 代码会使用这些崩溃细节功能。例如，系统服务或者某些库在遇到错误时，可能会注册一些上下文信息。
3. **崩溃处理流程:**
   - 当 Native 代码发生崩溃（如 SIGSEGV），系统会捕获这个信号。
   - 系统会创建一个崩溃信息的数据结构，其中会包含崩溃时的上下文信息（寄存器、堆栈等）。
   - 在崩溃处理的过程中，可能会遍历已注册的 `crash_detail_t` 对象，并将它们的信息添加到崩溃报告中。
   - 这部分通常发生在 `/system/bin/app_process*` 或相关进程中，涉及到信号处理机制和崩溃报告生成逻辑。

**Frida Hook 示例调试这些步骤:**

你可以使用 Frida 来 hook 这些函数，观察它们的调用时机和参数。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_crash_detail_register"), {
    onEnter: function(args) {
        console.log("[+] android_crash_detail_register called");
        console.log("    name:", Memory.readUtf8String(args[0]));
        console.log("    name_size:", args[1]);
        console.log("    data:", Memory.readUtf8String(args[2]));
        console.log("    data_size:", args[3]);
        this.name = Memory.readUtf8String(args[0]);
    },
    onLeave: function(retval) {
        console.log("[+] android_crash_detail_register returned:", retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "android_crash_detail_unregister"), {
    onEnter: function(args) {
        console.log("[+] android_crash_detail_unregister called");
        console.log("    crash_detail:", args[0]);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "android_crash_detail_replace_data"), {
    onEnter: function(args) {
        console.log("[+] android_crash_detail_replace_data called");
        console.log("    crash_detail:", args[0]);
        console.log("    data:", Memory.readUtf8String(args[1]));
        console.log("    data_size:", args[2]);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "android_crash_detail_replace_name"), {
    onEnter: function(args) {
        console.log("[+] android_crash_detail_replace_name called");
        console.log("    crash_detail:", args[0]);
        console.log("    name:", Memory.readUtf8String(args[1]));
        console.log("    name_size:", args[2]);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上面的 Python 代码保存为 `hook_crash_detail.py`。
2. 确保你的 Android 设备已连接并通过 `adb devices` 可以识别。
3. 替换 `package_name` 为你要调试的应用的包名。
4. 运行应用。
5. 运行 Frida 脚本：`frida -U -f <你的应用包名> hook_crash_detail.py` （或者先运行应用，然后使用 `frida -U -n <你的应用包名> hook_crash_detail.py`）。
6. 在应用中触发可能调用这些函数的代码路径，或者让应用发生崩溃。
7. Frida 的输出会显示这些函数的调用情况，包括参数值。

通过 Frida，你可以观察到何时调用了这些函数，传递了哪些名称和数据，从而更好地理解崩溃细节的注册和管理过程。

希望这个详细的分析对你有所帮助！

### 提示词
```
这是目录为bionic/libc/bionic/android_crash_detail.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2024 The Android Open Source Project
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

#include <android/crash_detail.h>

#include <async_safe/log.h>
#include <bionic/crash_detail_internal.h>

#include <bits/stdatomic.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "private/ScopedPthreadMutexLocker.h"
#include "private/bionic_defs.h"
#include "private/bionic_globals.h"

static _Atomic(crash_detail_t*) free_head = nullptr;

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
crash_detail_t* android_crash_detail_register(const void* name, size_t name_size, const void* data,
                                              size_t data_size) {
  auto populate_crash_detail = [&](crash_detail_t* result) {
    result->name = reinterpret_cast<const char*>(name);
    result->name_size = name_size;
    result->data = reinterpret_cast<const char*>(data);
    result->data_size = data_size;
  };
  // This is a atomic fast-path for RAII use-cases where the app keeps creating and deleting
  // crash details for short periods of time to capture detailed scopes.
  if (crash_detail_t* head = atomic_load(&free_head)) {
    while (head != nullptr && !atomic_compare_exchange_strong(&free_head, &head, head->prev_free)) {
      // intentionally left blank.
    }
    if (head) {
      head->prev_free = nullptr;
      populate_crash_detail(head);
      return head;
    }
  }
  ScopedPthreadMutexLocker locker(&__libc_shared_globals()->crash_detail_page_lock);
  struct crash_detail_page_t* prev = nullptr;
  struct crash_detail_page_t* page = __libc_shared_globals()->crash_detail_page;
  if (page != nullptr && page->used == kNumCrashDetails) {
    prev = page;
    page = nullptr;
  }
  if (page == nullptr) {
    size_t size = sizeof(crash_detail_page_t);
    void* map = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (map == MAP_FAILED) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to allocate crash_detail_page: %m");
      return nullptr;
    }
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, map, size, "crash details");
    page = reinterpret_cast<struct crash_detail_page_t*>(map);
    page->prev = prev;
    __libc_shared_globals()->crash_detail_page = page;
  }
  crash_detail_t* result = &page->crash_details[page->used];
  populate_crash_detail(result);
  page->used++;
  return result;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void android_crash_detail_unregister(crash_detail_t* crash_detail) {
  if (crash_detail) {
    if (crash_detail->prev_free) {
      // removing already removed would mess up the free-list by creating a circle.
      return;
    }
    crash_detail->data = nullptr;
    crash_detail->name = nullptr;
    crash_detail_t* prev = atomic_load(&free_head);
    do {
      crash_detail->prev_free = prev;
    } while (!atomic_compare_exchange_strong(&free_head, &prev, crash_detail));
  }
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void android_crash_detail_replace_data(crash_detail_t* crash_detail, const void* data,
                                       size_t data_size) {
  crash_detail->data = reinterpret_cast<const char*>(data);
  crash_detail->data_size = data_size;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void android_crash_detail_replace_name(crash_detail_t* crash_detail, const void* name,
                                       size_t name_size) {
  crash_detail->name = reinterpret_cast<const char*>(name);
  crash_detail->name_size = name_size;
}
```