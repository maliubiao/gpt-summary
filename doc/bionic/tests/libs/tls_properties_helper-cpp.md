Response:
Let's break down the thought process for analyzing the C++ code and generating the comprehensive response.

1. **Understanding the Goal:** The request asks for a detailed analysis of the `tls_properties_helper.cpp` file in Android's Bionic library. The key is to identify its purpose, explain its functions, relate it to Android, dissect the libc and dynamic linker interactions, and provide examples (including potential errors and debugging).

2. **Initial Code Scan and High-Level Purpose:** I first scanned the code for keywords and structure. The `#if defined(__BIONIC__)` immediately tells me this code is specific to the Bionic environment. The inclusion of `<sys/thread_properties.h>` and function names like `__libc_get_static_tls_bounds` and `__libc_iterate_dynamic_tls` strongly suggest this code is about testing or demonstrating Bionic's thread-local storage (TLS) mechanisms. The comments also confirm this.

3. **Analyzing Each Function:** I then examined each function individually:

    * **`test_static_tls_bounds()`:**  The name itself is self-explanatory. It declares a thread-local variable `local_var` and then calls `__libc_get_static_tls_bounds`. The assertions check if the address of `local_var` falls within the returned bounds. This clearly tests the ability to retrieve the memory region allocated for static TLS.

    * **`test_iter_tls()`:**  This function `dlopen`s a shared library (`libtest_elftls_dynamic.so`). It then accesses a thread-local variable (`large_tls_var`) defined *within* that shared library. The call to `__libc_iterate_dynamic_tls` with a lambda callback aims to verify that this dynamic TLS region can be enumerated. The `found_count` acts as a flag.

    * **`test_iterate_another_thread_tls()`:** This is the most complex function. It forks a child process. In the parent, it stores the address of `large_tls_var`. The child attaches to the parent using `ptrace` and then calls `__libc_iterate_dynamic_tls` *on the parent's PID*. This demonstrates the ability to inspect the TLS of another thread/process.

4. **Identifying Key Libc and Dynamic Linker Functions:** As I analyzed the functions, I noted the critical libc functions being used:

    * `__libc_get_static_tls_bounds`:  Directly related to Bionic's TLS implementation.
    * `__libc_iterate_dynamic_tls`:  Another Bionic-specific function for iterating over dynamic TLS.
    * `dlopen`:  A standard libc function, but crucial here for loading the shared library and triggering dynamic TLS allocation.
    * `fork`, `wait`, `gettid`, `getppid`, `ptrace`, `waitpid`: Standard process management functions used in the multi-process test.

5. **Connecting to Android:**  The header `#include <sys/thread_properties.h>` is a strong indicator of Android-specific functionality. I considered how TLS is used in Android: for thread-specific data, often accessed via NDK APIs or indirectly within the framework. The example of `Looper` came to mind as a common Android framework component that likely uses TLS.

6. **Explaining Libc Function Implementations:**  For the key Bionic-specific functions, I outlined a simplified explanation of what they *likely* do internally. This involves concepts like thread control blocks (TCBs) and the dynamic linker's role in allocating TLS during library loading. I emphasized that the *exact* implementation is complex and internal to Bionic. For standard libc functions, I provided a more general explanation.

7. **Dynamic Linker Interaction:** `dlopen` was the primary interaction point. I described the process of the dynamic linker allocating memory for dynamic TLS when a shared library with `__thread` variables is loaded. I then constructed a sample `so` layout and explained how the linker resolves TLS addresses.

8. **Assumptions and Outputs:** For the multi-process test, I laid out the expected behavior: the child process successfully attaching and finding the parent's TLS region.

9. **Common Errors:** I thought about typical mistakes developers make when dealing with threads and shared memory, such as race conditions, incorrect `dlopen` flags, and assuming TLS works across processes without explicit mechanisms like `ptrace`.

10. **Android Framework/NDK Path:** I traced the path from the Android framework down to the NDK and how a developer might end up indirectly using these Bionic TLS functions (e.g., through `pthread_key_create` or directly using NDK thread-local storage).

11. **Frida Hooking:** I focused on how to hook the key Bionic functions to observe their behavior. The examples provided how to intercept the input arguments (PID, callbacks) and potentially the output (TLS bounds).

12. **Structuring the Response:** Finally, I organized the information logically with clear headings and subheadings to make it easy to read and understand. I ensured the language was clear and concise, avoiding overly technical jargon where possible while still maintaining accuracy. I double-checked that all aspects of the original prompt were addressed.

**Self-Correction/Refinement:**

* **Initial thought:**  Maybe focus heavily on the specific assembly instructions of TLS access.
* **Correction:**  Realized a higher-level conceptual explanation of the Bionic functions and dynamic linker interactions would be more beneficial and understandable for a broader audience. The assembly details are implementation-specific and can change.
* **Initial thought:**  Just list the libc functions.
* **Correction:**  Decided to provide a brief explanation of the *purpose* of each libc function within the context of the code, and then a more detailed explanation of the crucial Bionic-specific functions.
* **Initial thought:**  Give a very basic Frida example.
* **Correction:** Expanded the Frida examples to be more practical, showing how to hook both the `__libc_get_static_tls_bounds` and `__libc_iterate_dynamic_tls` functions and inspect their arguments.

By following this systematic approach, breaking down the problem, and iteratively refining the explanation, I was able to generate the comprehensive and informative response.
这个文件 `bionic/tests/libs/tls_properties_helper.cpp` 是 Android Bionic 库中的一个测试文件。它的主要功能是**测试与线程本地存储 (Thread-Local Storage, TLS) 相关的 Bionic 内部接口**。

具体来说，它测试了以下几个方面：

1. **获取静态 TLS 区域的边界 (`__libc_get_static_tls_bounds`)**: 测试是否能够正确获取当前线程的静态 TLS 区域的起始和结束地址。
2. **迭代动态 TLS 块 (`__libc_iterate_dynamic_tls`)**: 测试是否能够遍历当前线程或指定线程的动态 TLS 块，例如由 `dlopen` 加载的共享库中的 `__thread` 变量所分配的内存。

**与 Android 功能的关系及举例说明:**

TLS 是一个重要的概念，它允许每个线程拥有自己的全局变量副本。这对于编写多线程程序至关重要，可以避免竞态条件和简化并发编程。Android 系统和应用程序广泛使用了 TLS。

* **Android Framework**:  Android Framework 的某些部分会使用 TLS 来存储线程特定的数据。例如，`Looper` 类 (用于处理消息队列) 通常使用 TLS 来保存当前线程的 `Looper` 实例。
* **NDK 开发**: 使用 NDK 进行原生开发的应用程序可以使用 `__thread` 关键字声明线程局部变量，这些变量的存储就是通过 TLS 实现的。
* **Bionic 库内部**: Bionic 库自身也使用 TLS 来管理一些线程相关的数据结构。

**举例说明:**

假设一个 NDK 应用加载了一个共享库，这个共享库定义了一个线程局部变量：

```c++
// libmy.so
#include <pthread.h>

__thread int my_thread_local_data = 0;

void set_data(int value) {
  my_thread_local_data = value;
}

int get_data() {
  return my_thread_local_data;
}
```

当应用主线程调用 `dlopen("libmy.so", ...)` 加载这个共享库时，动态链接器会为 `my_thread_local_data` 在主线程的动态 TLS 区域分配空间。  `tls_properties_helper.cpp` 中的 `test_iter_tls()` 函数就是模拟这种情况，验证 Bionic 是否能正确找到这个动态分配的 TLS 块。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件主要使用了以下几个 libc 函数（其中 `__libc_get_static_tls_bounds` 和 `__libc_iterate_dynamic_tls` 是 Bionic 特有的）：

1. **`__libc_get_static_tls_bounds(void** start_addr, void** end_addr)`**:
   * **功能**: 获取当前线程静态 TLS 区域的起始地址和结束地址。静态 TLS 区域是在线程创建时分配的，用于存储在主程序或静态链接的库中声明的 `thread_local` 或 `__thread` 变量。
   * **实现**:  Bionic 内部维护了每个线程的线程控制块 (Thread Control Block, TCB)。TCB 中包含了指向线程的静态 TLS 区域的起始和结束地址的指针。这个函数会访问当前线程的 TCB，并返回这些指针的值。具体的实现细节涉及操作系统和架构相关的 TLS 实现方式。在 Linux 上，通常是通过 `pthread` 库的内部机制来实现的。

2. **`__libc_iterate_dynamic_tls(pid_t tid, void (*callback)(void*, void*, size_t, void*), void* arg)`**:
   * **功能**: 迭代指定线程 (由 `tid` 指定) 的动态 TLS 块。动态 TLS 块是在运行时由动态链接器分配的，通常用于存储由 `dlopen` 加载的共享库中的 `__thread` 变量。
   * **实现**:  Bionic 的动态链接器 (linker) 维护了每个进程加载的共享库的 TLS 信息，包括每个库的 TLS 模板大小和偏移量。当调用 `dlopen` 加载一个包含 `__thread` 变量的共享库时，动态链接器会在加载线程的动态 TLS 区域中分配一块内存。`__libc_iterate_dynamic_tls` 函数会访问指定线程的 TLS 信息，并遍历所有已分配的动态 TLS 块。对于每个块，它会调用用户提供的 `callback` 函数，并将该块的起始地址、结束地址、所属的动态库 ID (`dso_id`) 和用户提供的参数 `arg` 传递给回调函数。

3. **`dlopen(const char* filename, int flag)`**:
   * **功能**: 打开并加载指定的动态链接库 (共享对象)。
   * **实现**:  这是一个标准的 POSIX 函数。其实现涉及复杂的步骤，包括：查找共享库文件、解析 ELF 文件头、加载代码段和数据段、解析重定位信息、以及执行初始化函数等。对于 TLS 相关的处理，当加载的共享库包含 `__thread` 变量时，`dlopen` 会通知动态链接器为当前线程分配相应的动态 TLS 空间。

4. **`assert(expression)`**:
   * **功能**:  如果 `expression` 的值为假 (0)，则终止程序并打印错误信息。
   * **实现**:  这是一个宏，通常在 Debug 模式下启用。它的基本实现是检查表达式的值，如果为假则调用 `abort()` 或类似的函数来终止程序。

5. **`dlfcn.h` 中其他的函数 (例如，虽然代码中没有直接调用，但 `dlopen` 依赖于 `dlfcn.h` 中定义的类型和常量)`**:  `dlfcn.h` 定义了动态链接相关的函数，例如 `dlclose` (卸载共享库)、`dlsym` (查找符号地址) 等。

6. **`elf.h`**: 定义了 ELF (Executable and Linkable Format) 文件格式的相关结构体和常量，动态链接器需要解析 ELF 文件。

7. **`err.h`**: 提供了类似 `perror` 但更方便的错误处理函数，例如 `err` 和 `warn`。

8. **`errno.h`**: 定义了错误代码的宏，例如 `ENOENT` (文件不存在)。

9. **`fcntl.h`**: 定义了文件控制相关的常量和函数，例如 `open`。

10. **`sched.h`**: 定义了进程调度相关的函数，例如 `sched_getcpu` (虽然这个文件没有直接使用，但可能在 Bionic 内部的 TLS 实现中使用)。

11. **`stdio.h`**: 标准输入输出库，包含 `printf` 等函数。

12. **`string.h`**: 字符串处理函数，例如 `strcmp`, `strcpy`。

13. **`sys/prctl.h`**: 进程控制相关的函数，例如 `prctl` (设置进程属性)。

14. **`sys/ptrace.h`**:  ptrace 系统调用相关的定义，用于进程跟踪和调试。

15. **`sys/uio.h`**: 定义了 `iovec` 结构体，用于分散/聚集 I/O 操作。

16. **`sys/user.h`**:  定义了用户空间访问内核数据结构的接口 (例如 `user_regs_struct`)，通常与 `ptrace` 一起使用。

17. **`sys/wait.h`**:  进程等待相关的函数，例如 `wait` 和 `waitpid`。

18. **`unistd.h`**:  POSIX 标准的系统调用接口，例如 `fork`, `getpid`, `sleep`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**so 布局样本 (`libtest_elftls_dynamic.so`):**

```
ELF Header:
  ...
Program Headers:
  ...
  LOAD           0x00000000 0x00000000 0x00001000 R E   0x1000
  LOAD           0x00001000 0x00001000 0x00001000 RW    0x1000
  ...
Dynamic Section:
  ...
  NEEDED               Shared library: libc.so
  ...
Thread-Local Storage Section (.tdata and .tbss):
  .tdata:  Contains initialized TLS variables (e.g., `large_tls_var`)
  .tbss:   Contains uninitialized TLS variables
Symbol Table:
  ...
  00001000 g     O .tdata 00001000 large_tls_var
  ...
```

在这个简化的例子中：

* **LOAD 段**: 定义了需要加载到内存的区域，包括代码段 (R E) 和数据段 (RW)。
* **Dynamic Section**: 包含动态链接器需要的信息，例如依赖的库 (`NEEDED`)。
* **Thread-Local Storage Section (.tdata 和 .tbss)**:  这是关键部分。
    * `.tdata` 存储已初始化的线程局部变量，例如 `__thread char large_tls_var[4 * 1024 * 1024];` 的初始值（如果它有初始值）。
    * `.tbss` 存储未初始化的线程局部变量，链接器会在运行时为其分配清零的内存。
* **Symbol Table**: 包含了导出的符号信息，包括 `large_tls_var` 的地址和大小。

**链接的处理过程:**

1. **加载时**: 当主程序调用 `dlopen("libtest_elftls_dynamic.so", ...)` 时，动态链接器会执行以下操作：
   * **解析 ELF 头**: 读取 ELF 文件头信息，确定文件类型、目标架构等。
   * **加载 Program Headers**: 根据 LOAD 段的信息，将代码段和数据段加载到内存中的合适位置。
   * **处理 Dynamic Section**:
     * **加载依赖库**:  如果 `NEEDED` 项指定了其他依赖库 (例如 `libc.so`)，则递归地加载这些库。
     * **处理 TLS**: 动态链接器会识别 `.tdata` 和 `.tbss` 段，并计算出此共享库需要的 TLS 空间大小。
   * **分配 TLS 空间**:  动态链接器会在调用 `dlopen` 的线程的动态 TLS 区域中分配一块足够大的内存来容纳 `libtest_elftls_dynamic.so` 的 TLS 数据。
   * **初始化 TLS 数据**: 将 `.tdata` 段的内容复制到新分配的 TLS 空间中。`.tbss` 对应的空间会被清零。
   * **重定位**:  如果共享库中的代码引用了其他共享库中的符号 (包括 TLS 变量)，动态链接器会更新这些引用，使其指向正确的内存地址。对于 TLS 变量，通常使用一种特殊的重定位类型，例如 `R_TLS_DTPMOD64` 和 `R_TLS_DTPOFF64` (对于 64 位架构)，来计算 TLS 变量的地址。

2. **运行时访问 TLS 变量**: 当代码访问 `large_tls_var` 时，编译器会生成特殊的指令来访问线程的 TLS 区域。这些指令通常会使用寄存器 (例如在 x86-64 架构上是 `FS` 或 `GS` 寄存器) 来指向当前线程的 TLS 基地址，然后加上一个偏移量来访问特定的 TLS 变量。这个偏移量是在链接时计算出来的。

**如果做了逻辑推理，请给出假设输入与输出:**

在 `test_iterate_another_thread_tls()` 函数中，假设父进程的 PID 为 12345。

**假设输入:**

* 父进程 PID: 12345
* 父进程中 `large_tls_var` 的地址 (例如): 0x7fff12345000

**逻辑推理:**

1. 子进程通过 `ptrace(PTRACE_ATTACH, 12345)` 附加到父进程。
2. 子进程调用 `__libc_iterate_dynamic_tls(12345, cb, nullptr)`，要求 Bionic 遍历父进程的动态 TLS 块。
3. 回调函数 `cb` 会检查父进程的动态 TLS 块的起始和结束地址，判断 `parent_addr` (父进程中 `large_tls_var` 的地址) 是否在这个范围内。

**预期输出:**

* 回调函数 `cb` 会被调用至少一次，并且其中一个动态 TLS 块的范围会包含 `0x7fff12345000`。
* `found_count` 的值最终会是 1，因为 `large_tls_var` 应该只在一个动态 TLS 块中。
* 子进程会打印 "done_iterate_another_thread_tls"。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **在多线程环境中使用全局变量而不是 TLS 变量**: 如果多个线程访问和修改同一个全局变量，可能会导致竞态条件和数据不一致。应该使用 TLS 变量来存储线程特定的数据。

   ```c++
   // 错误示例
   int global_counter = 0; // 多个线程会竞争修改

   void increment_counter() {
       global_counter++;
   }

   // 正确示例
   __thread int thread_local_counter = 0;

   void increment_local_counter() {
       thread_local_counter++;
   }
   ```

2. **假设 TLS 变量可以在不同的进程之间共享**: TLS 是线程本地的，不适用于进程间通信。如果需要在不同进程之间共享数据，应该使用其他的 IPC (Inter-Process Communication) 机制，例如共享内存、管道、Socket 等。

3. **在没有加载共享库的情况下访问其 TLS 变量**: 如果尝试访问一个尚未通过 `dlopen` 加载的共享库中的 `__thread` 变量，会导致未定义的行为，通常是程序崩溃。

4. **不正确地使用 `dlopen` 的标志**: 例如，如果使用了 `RTLD_LOCAL` 标志加载共享库，那么该库中定义的全局符号 (包括 TLS 变量) 不会暴露给后续加载的库，这可能会导致链接错误。

5. **忘记在子线程中初始化 TLS 变量**: 对于动态加载的共享库中的 TLS 变量，每个线程都会有自己的一份副本。如果子线程没有显式地初始化这些变量，它们的值可能是未定义的。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 TLS 相关 Bionic 代码的路径：**

1. **Android Framework**:
   * **Java 代码使用 ThreadLocal**: Android Framework 中的 Java 代码可以使用 `java.lang.ThreadLocal` 类来创建线程局部变量。
   * **JNI 调用**: 当 Java 代码访问 `ThreadLocal` 变量时，最终会通过 JNI (Java Native Interface) 调用到 Native 代码。
   * **Native 代码中的 pthread 或 Bionic 内部机制**: 在 Native 代码中，`java.lang.ThreadLocal` 的实现通常会依赖于 `pthread_key_create` 等 POSIX 线程 API，而 Bionic 的 `pthread` 库内部会使用到 TLS 相关的系统调用和内部接口，例如 `__pthread_getspecific` 和 `__pthread_setspecific`，这些接口可能会间接使用到 `__libc_get_static_tls_bounds` 或类似的机制来管理线程特定的数据。

2. **NDK 开发**:
   * **C/C++ 代码使用 `__thread`**: NDK 开发者可以直接在 C/C++ 代码中使用 `__thread` 关键字声明线程局部变量。
   * **编译器和链接器处理**: 编译器会将 `__thread` 变量标记为需要存储在 TLS 中。链接器在加载共享库时会分配相应的 TLS 空间。
   * **Bionic 库的支持**: 当程序运行时，Bionic 库 (libc.so 和 linker) 负责管理 TLS 的分配、初始化和访问。访问 `__thread` 变量的代码最终会通过 Bionic 提供的机制来定位和访问 TLS 内存。

**Frida Hook 示例：**

可以使用 Frida hook `__libc_get_static_tls_bounds` 和 `__libc_iterate_dynamic_tls` 函数来观察它们的行为。

**示例 1: Hook `__libc_get_static_tls_bounds`**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload'], data))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(['/system/bin/app_process64', '/system/bin']) # 替换为你想要附加的进程
session = device.attach(pid)
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "__libc_get_static_tls_bounds"), {
    onEnter: function(args) {
        console.log("[*] __libc_get_static_tls_bounds called");
        this.start_addr_ptr = args[0];
        this.end_addr_ptr = args[1];
    },
    onLeave: function(retval) {
        var start_addr = this.start_addr_ptr.readPointer();
        var end_addr = this.end_addr_ptr.readPointer();
        console.log("[*] Static TLS bounds: start =", start_addr, ", end =", end_addr);
    }
});
""")
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**示例 2: Hook `__libc_iterate_dynamic_tls`**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload'], data))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(['/system/bin/app_process64', '/system/bin']) # 替换为你想要附加的进程
session = device.attach(pid)
script = session.create_script("""
const iterate_dynamic_tls = Module.findExportByName("libc.so", "__libc_iterate_dynamic_tls");

Interceptor.attach(iterate_dynamic_tls, {
    onEnter: function(args) {
        console.log("[*] __libc_iterate_dynamic_tls called");
        this.tid = args[0].toInt32();
        this.callback = args[1];
        this.arg = args[2];

        const callback = new NativeCallback(this.callback, 'void', ['pointer', 'pointer', 'ulong', 'pointer']);
        this.wrapped_callback = function(dtls_begin, dtls_end, dso_id, arg) {
            console.log("[*] Dynamic TLS block: start =", dtls_begin, ", end =", dtls_end, ", dso_id =", dso_id);
            callback(dtls_begin, dtls_end, dso_id, arg);
        };
        arguments[1] = new NativeFunction(this.wrapped_callback, 'void', ['pointer', 'pointer', 'ulong', 'pointer']);
    },
    onLeave: function(retval) {
        console.log("[*] __libc_iterate_dynamic_tls returned:", retval);
    }
});
""")
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**使用说明:**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. 将上面的 Python 代码保存为 `.py` 文件 (例如 `hook_tls.py`).
3. 将 `/system/bin/app_process64` 替换为你想要调试的 Android 进程的路径和名称。
4. 运行 `python hook_tls.py`。

这些 Frida 脚本会拦截对 `__libc_get_static_tls_bounds` 和 `__libc_iterate_dynamic_tls` 的调用，并在控制台上打印相关的参数和返回值，帮助你理解 TLS 的分配和管理过程。对于 `__libc_iterate_dynamic_tls`，我们还 hook 了传递给它的回调函数，以便查看每个动态 TLS 块的信息。

Prompt: 
```
这是目录为bionic/tests/libs/tls_properties_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

// Prevent tests from being compiled with glibc because thread_properties.h
// only exists in Bionic.
#if defined(__BIONIC__)

#include <sys/thread_properties.h>

#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// Helper binary to use TLS-related functions in thread_properties

// Tests __get_static_tls_bound.
thread_local int local_var;
void test_static_tls_bounds() {
  local_var = 123;
  void* start_addr = nullptr;
  void* end_addr = nullptr;

  __libc_get_static_tls_bounds(reinterpret_cast<void**>(&start_addr),
                               reinterpret_cast<void**>(&end_addr));
  assert(start_addr != nullptr);
  assert(end_addr != nullptr);

  assert(&local_var >= start_addr && &local_var < end_addr);

  printf("done_get_static_tls_bounds\n");
}

// Tests iterate_dynamic tls chunks.
// Export a var from the shared so.
__thread char large_tls_var[4 * 1024 * 1024];
// found_count  has to be Global variable so that the non-capturing lambda
// can access it.
int found_count = 0;
void test_iter_tls() {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  large_tls_var[1025] = 'a';
  auto cb = +[](void* dtls_begin, void* dtls_end, size_t dso_id, void* arg) {
    if (&large_tls_var >= dtls_begin && &large_tls_var < dtls_end) ++found_count;
  };
  __libc_iterate_dynamic_tls(gettid(), cb, nullptr);

  // It should be found exactly once.
  assert(found_count == 1);
  printf("done_iterate_dynamic_tls\n");
}

void* parent_addr = nullptr;
void test_iterate_another_thread_tls() {
  large_tls_var[1025] = 'b';
  parent_addr = &large_tls_var;
  found_count = 0;

  pid_t pid = fork();
  assert(pid != -1);
  int status;
  if (pid) {
    // Parent.
    assert(pid == wait(&status));
    assert(0 == status);
  } else {
    // Child.
    pid_t parent_pid = getppid();
    assert(0 == ptrace(PTRACE_ATTACH, parent_pid));
    assert(parent_pid == waitpid(parent_pid, &status, 0));

    auto cb = +[](void* dtls_begin, void* dtls_end, size_t dso_id, void* arg) {
      if (parent_addr >= dtls_begin && parent_addr < dtls_end) ++found_count;
    };
    __libc_iterate_dynamic_tls(parent_pid, cb, nullptr);
    // It should be found exactly once.
    assert(found_count == 1);
    printf("done_iterate_another_thread_tls\n");
  }
}
int main() {
  test_static_tls_bounds();
  test_iter_tls();
  test_iterate_another_thread_tls();
  return 0;
}

#else
int main() {
  return 0;
}
#endif  // __BIONIC__

"""

```