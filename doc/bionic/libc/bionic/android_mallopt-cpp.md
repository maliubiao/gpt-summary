Response:
Let's break down the thought process for answering the request about `android_mallopt.cpp`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the `android_mallopt.cpp` file in Android's Bionic libc. The key points are:

* **Functionality:** What does this file *do*?
* **Android Integration:** How does it connect with the broader Android system?
* **Libc Function Implementation:**  Details about the specific functions within.
* **Dynamic Linker Interaction:** How does it relate to SOs and linking?
* **Logic and I/O:**  Understanding the flow and potential data.
* **Common Errors:**  Pitfalls for users and programmers.
* **Framework/NDK Path:** How does the execution reach this code?
* **Debugging:**  Frida examples for observing behavior.

**2. Initial Code Scan and Keyword Identification:**

The first step is to read the code and identify key elements. I looked for:

* **Function Definition:** The central `android_mallopt` function is the obvious starting point.
* **`opcode`:**  The `switch`-like structure based on `opcode` suggests different functionalities. I noted the `M_` prefixes, implying a set of predefined options.
* **Conditional Compilation:** `#if !defined(LIBC_STATIC)` and `#ifdef LIBC_STATIC` indicate different behavior depending on whether the libc is statically or dynamically linked. This is crucial.
* **Included Headers:**  `<errno.h>`, `<stdatomic.h>`, `<platform/bionic/malloc.h>`, etc., provide clues about the types of operations involved (error handling, atomics, memory management).
* **Global Variables:** `gZygoteChild`, `gZygoteChildProfileable`, and `__libc_globals` are important for understanding state.
* **Function Calls:** `EnableGwpAsan`, `LimitEnable`, `HeapprofdInitZygoteChildProfiling`, `WriteMallocLeakInfo`, `GetMallocLeakInfo`, `FreeMallocLeakInfo`, and `HeapprofdMallopt` point to interactions with other parts of the system.
* **Memory Operations:**  The manipulation of pointers (`void* arg`) and sizes (`size_t arg_size`) suggests memory-related actions.

**3. Analyzing Functionality Based on `opcode`:**

I systematically went through each `opcode` and deduced its purpose:

* **`M_GET_DECAY_TIME_ENABLED`:**  Retrieving a boolean value related to memory decay.
* **`M_INITIALIZE_GWP_ASAN`:**  Enabling GWP-ASan (Guard Whale Protection - AddressSanitizer), a memory safety feature.
* **`M_MEMTAG_STACK_IS_ON`:**  Checking if memory tagging for stacks is enabled (hardware-assisted memory safety).
* **`M_SET_ALLOCATION_LIMIT_BYTES`:**  Setting limits on memory allocation.
* **`M_SET_ZYGOTE_CHILD`:**  Marking the process as a Zygote child (important for Android's process forking).
* **`M_INIT_ZYGOTE_CHILD_PROFILING`:**  Initiating profiling for Zygote children.
* **`M_GET_PROCESS_PROFILEABLE`:**  Determining if a process can be profiled.
* **`M_WRITE_MALLOC_LEAK_INFO_TO_FILE`:**  Dumping memory leak information to a file.
* **`M_GET_MALLOC_LEAK_INFO`:**  Retrieving memory leak information into a structure.
* **`M_FREE_MALLOC_LEAK_INFO`:**  Releasing memory associated with leak information.

**4. Connecting to Android Functionality:**

For each identified functionality, I considered its relevance to Android:

* **Memory Management:** All the memory-related `opcodes` are core to how Android manages resources and prevents issues like crashes and security vulnerabilities.
* **Zygote:** The `Zygote` related `opcodes` are directly tied to Android's process creation mechanism, which is a fundamental aspect of the OS.
* **Profiling:**  The profiling options are important for performance analysis and debugging in Android apps and the system itself.
* **Memory Safety:** GWP-ASan and memory tagging are critical security features in modern Android versions.

**5. Delving into Libc Function Implementations:**

I focused on understanding *how* each `opcode` is handled. The code provides some clues:

* **Atomic Operations:**  `atomic_load` and `atomic_store_explicit` indicate thread-safe access to shared variables.
* **Pointer Casting:** The use of `reinterpret_cast` shows how data is passed and interpreted.
* **External Function Calls:** The calls to functions like `EnableGwpAsan`, `LimitEnable`, and the `Heapprofd` functions suggest delegation of the actual implementation. I acknowledged that this code is more of a dispatcher.

**6. Addressing the Dynamic Linker Aspect:**

This required understanding the implications of `#if !defined(LIBC_STATIC)`:

* **Shared Objects (SOs):** Dynamic linking means the libc is a shared library (`.so` file). I needed to illustrate a typical SO layout.
* **Linking Process:**  I described how the dynamic linker resolves symbols at runtime. The `android_mallopt` function itself is a symbol that can be called by other SOs.

**7. Logic, Input, and Output:**

For simpler `opcodes`, I could deduce the logic. For example, `M_GET_DECAY_TIME_ENABLED` takes a pointer and writes a boolean value. I provided simple input/output examples.

**8. Identifying Common Errors:**

By looking at the argument checks (`arg == nullptr || arg_size != sizeof(...)`), I identified common mistakes like passing incorrect arguments (null pointers, wrong sizes).

**9. Tracing the Framework/NDK Path:**

This required a higher-level understanding of how Android apps and native code interact with the system:

* **System Calls:**  Apps eventually make system calls. `android_mallopt` itself isn't a direct system call, but it's part of the libc, which provides wrappers for them.
* **NDK:** Native code in apps can directly call `android_mallopt`.
* **Framework:**  The Android framework (Java code) can indirectly trigger calls to `android_mallopt` through its memory management and profiling subsystems.

**10. Crafting Frida Hooks:**

I aimed for practical Frida examples demonstrating how to intercept calls to `android_mallopt` and observe its behavior, focusing on logging the `opcode` and arguments.

**11. Structuring the Response:**

Finally, I organized the information logically, following the structure of the request, and used clear, concise language. I made sure to explain technical terms and provide context. I also used formatting (like bolding) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps get bogged down in the details of each external function call.
* **Correction:** Realized the focus should be on what *this* file does, acknowledging the delegation to other components.
* **Initial thought:**  Maybe provide very low-level details about memory allocation.
* **Correction:** Focused on the specific functionality of `android_mallopt` and its immediate context within the libc.
* **Initial thought:**  Overcomplicate the dynamic linking explanation.
* **Correction:**  Provided a simplified but accurate overview relevant to this specific function.
好的，让我们来详细分析一下 `bionic/libc/bionic/android_mallopt.cpp` 这个文件。

**功能概述**

`android_mallopt.cpp` 文件定义了一个名为 `android_mallopt` 的函数，这个函数是 Android Bionic libc 库提供的一个平台内部的 `mallopt` 变体。`mallopt` 通常用于控制内存分配器的行为。Android 的 `android_mallopt` 扩展了标准 `mallopt` 的功能，提供了更多特定于 Android 平台的内存管理和调试选项。

**与 Android 功能的关系及举例说明**

`android_mallopt` 提供的功能直接关系到 Android 平台的内存管理、性能分析、安全性和调试。以下是一些具体的功能及其与 Android 的关联：

1. **`M_GET_DECAY_TIME_ENABLED`**:  获取内存衰减（decay time）是否启用。
   * **Android 关联:** 内存衰减是一种优化策略，用于在内存压力不高时延迟释放某些内存，期望稍后可以重用，从而提高性能。这在 Android 系统服务和应用中都有应用。
   * **举例:** 系统服务可能会调用此选项来检查当前的内存衰减策略是否激活。

2. **`M_INITIALIZE_GWP_ASAN`**: 初始化 GWP-ASan (Guard Whale Protection - AddressSanitizer)。
   * **Android 关联:** GWP-ASan 是一种用于检测内存安全错误的采样工具，尤其是在生产环境中。Android 使用它来提高系统的安全性。
   * **举例:**  Android 系统框架或某些关键的系统组件可能会在启动时调用此选项来启用 GWP-ASan，以监控内存安全问题。

3. **`M_MEMTAG_STACK_IS_ON`**:  检查内存标签（memtag）是否在栈上启用。
   * **Android 关联:** 内存标签是一种硬件辅助的内存安全功能，用于检测内存访问错误。在较新的 Android 设备上，可以启用此功能以增强安全性。
   * **举例:** Android 系统可能会在运行时查询此选项，以了解当前的内存保护状态。

4. **`M_SET_ALLOCATION_LIMIT_BYTES`**: 设置内存分配的字节数限制。
   * **Android 关联:**  Android 可能会使用此选项来限制特定进程或组件的内存使用，防止它们占用过多资源。
   * **举例:**  Android 的资源管理器可能会使用此选项来限制后台应用的内存使用。

5. **`M_SET_ZYGOTE_CHILD`**:  标记当前进程为 Zygote 子进程。
   * **Android 关联:** Zygote 是 Android 中所有应用进程的父进程。当 Zygote fork 出新的应用进程时，新的子进程会调用此选项来标记自己。
   * **举例:**  Zygote 完成 fork 操作后，新创建的应用进程会调用 `android_mallopt(M_SET_ZYGOTE_CHILD, nullptr, 0)`。

6. **`M_INIT_ZYGOTE_CHILD_PROFILING`**:  初始化 Zygote 子进程的性能分析。
   * **Android 关联:**  允许在 Zygote 子进程中启动性能分析，例如使用 `heapprofd` 进行堆内存分析。
   * **举例:** 当开发者想要分析应用启动时的内存分配情况时，可以使用此选项。

7. **`M_GET_PROCESS_PROFILEABLE`**: 获取进程是否可以被性能分析。
   * **Android 关联:**  确定进程是否允许被性能分析工具（如 `simpleperf` 或 `heapprofd`）监控。Zygote 子进程只有在被标记为可分析时才返回 true。
   * **举例:** 性能分析工具在尝试连接到目标进程前，可能会调用此选项来检查是否允许进行分析。

8. **`M_WRITE_MALLOC_LEAK_INFO_TO_FILE`**: 将内存泄漏信息写入文件。
   * **Android 关联:**  用于诊断内存泄漏问题。可以将详细的内存分配信息写入文件进行分析。
   * **举例:**  开发者或自动化测试可以使用此选项来捕获内存泄漏报告。

9. **`M_GET_MALLOC_LEAK_INFO`**: 获取内存泄漏信息。
   * **Android 关联:**  以结构体的形式返回内存泄漏信息，方便程序进行处理。
   * **举例:**  内存监控工具可以使用此选项来定期检查并报告内存泄漏情况。

10. **`M_FREE_MALLOC_LEAK_INFO`**: 释放通过 `M_GET_MALLOC_LEAK_INFO` 获取的内存泄漏信息。
    * **Android 关联:**  配套使用，防止内存泄漏。

**Libc 函数的功能实现**

下面详细解释 `android_mallopt` 中处理的每个 `opcode` 的实现方式：

* **`M_GET_DECAY_TIME_ENABLED`**:
    *  检查 `arg` 是否为有效的 `bool` 指针且大小正确。
    *  使用原子操作 `atomic_load` 读取全局变量 `__libc_globals->decay_time_enabled` 的值。这个全局变量可能在其他地方被设置，控制内存衰减的启用状态。
    *  将读取的值写入到 `arg` 指向的内存。

* **`M_INITIALIZE_GWP_ASAN`**:
    *  检查 `arg` 是否为指向 `android_mallopt_gwp_asan_options_t` 结构体的有效指针且大小正确。
    *  调用 `EnableGwpAsan` 函数，并将 `arg` 中包含的选项传递给它。`EnableGwpAsan` 的具体实现可能在其他源文件中，它负责初始化 GWP-ASan 机制。

* **`M_MEMTAG_STACK_IS_ON`**:
    *  检查 `arg` 是否为有效的 `bool` 指针且大小正确。
    *  使用原子操作 `atomic_load` 读取全局变量 `__libc_memtag_stack` 的值。这个全局变量指示栈内存标签是否已启用。
    *  将读取的值写入到 `arg` 指向的内存。

* **`M_SET_ALLOCATION_LIMIT_BYTES`**:
    *  直接调用 `LimitEnable` 函数，并将 `arg` 和 `arg_size` 传递给它。`LimitEnable` 的实现可能在 `malloc_limit.h` 相关的源文件中，负责设置内存分配限制。

* **`M_SET_ZYGOTE_CHILD`**:
    *  检查 `arg` 是否为 `nullptr` 且 `arg_size` 是否为 0。
    *  将全局布尔变量 `gZygoteChild` 设置为 `true`。这个变量用于标识当前进程是否为 Zygote 的子进程。

* **`M_INIT_ZYGOTE_CHILD_PROFILING`**:
    *  检查 `arg` 是否为 `nullptr` 且 `arg_size` 是否为 0。
    *  使用原子操作 `atomic_store_explicit` 将全局变量 `gZygoteChildProfileable` 设置为 `true`，并使用 `memory_order_release` 确保内存顺序。
    *  调用 `HeapprofdInitZygoteChildProfiling` 函数，该函数负责初始化 `heapprofd`（Android 的堆内存分析器）在 Zygote 子进程中的分析。

* **`M_GET_PROCESS_PROFILEABLE`**:
    *  检查 `arg` 是否为有效的 `bool` 指针且大小正确。
    *  读取全局变量 `gZygoteChild` 和 `gZygoteChildProfileable` 的值。
    *  如果不是 Zygote 子进程 (`!gZygoteChild`)，则认为是可以进行性能分析的。
    *  如果是 Zygote 子进程，则只有当 `gZygoteChildProfileable` 为 `true` 时才认为可以进行性能分析。使用 `memory_order_acquire` 确保内存顺序。
    *  将结果写入到 `arg` 指向的内存。

* **`M_WRITE_MALLOC_LEAK_INFO_TO_FILE`**:
    *  检查 `arg` 是否为指向 `FILE` 结构体的有效指针且大小正确。
    *  调用 `WriteMallocLeakInfo` 函数，并将文件指针传递给它。`WriteMallocLeakInfo` 的实现会遍历内存分配信息并将其写入到指定的文件中。

* **`M_GET_MALLOC_LEAK_INFO`**:
    *  检查 `arg` 是否为指向 `android_mallopt_leak_info_t` 结构体的有效指针且大小正确。
    *  调用 `GetMallocLeakInfo` 函数，并将结构体指针传递给它。`GetMallocLeakInfo` 的实现会收集内存泄漏信息并填充到提供的结构体中。

* **`M_FREE_MALLOC_LEAK_INFO`**:
    *  检查 `arg` 是否为指向 `android_mallopt_leak_info_t` 结构体的有效指针且大小正确。
    *  调用 `FreeMallocLeakInfo` 函数，并将结构体指针传递给它。`FreeMallocLeakInfo` 的实现会释放之前通过 `M_GET_MALLOC_LEAK_INFO` 获取的内存。

* **其他情况 (非静态链接库)**:
    * 如果 `opcode` 不匹配上述任何情况，并且当前是动态链接的库 (`!defined(LIBC_STATIC)`），则会调用 `HeapprofdMallopt` 函数。这表明 `heapprofd` 模块也可能处理一些 `mallopt` 的操作码。

**动态链接器功能及 SO 布局样本和链接过程**

`android_mallopt` 函数本身是 `libc.so` 库导出的一个符号。当其他动态链接库或可执行文件需要调用 `android_mallopt` 时，动态链接器负责解析这个符号的地址。

**SO 布局样本 (libc.so):**

```
libc.so:
    ...
    .text:
        ...
        android_mallopt:  // android_mallopt 函数的代码
            <android_mallopt 函数的指令>
        ...
    .dynsym:           // 动态符号表
        ...
        SYMBOL android_mallopt  // 包含 android_mallopt 的符号信息
        ...
    .dynstr:           // 动态字符串表
        ...
        android_mallopt\0
        ...
```

**链接处理过程:**

1. **加载 SO:** 当一个进程启动或使用 `dlopen` 加载 `libc.so` 时，动态链接器会将 `libc.so` 加载到进程的地址空间。
2. **符号解析:** 当代码中调用 `android_mallopt` 时，如果该调用发生在其他 SO 或可执行文件中，动态链接器需要找到 `android_mallopt` 的地址。
3. **查找符号表:** 动态链接器会在 `libc.so` 的 `.dynsym` 节中查找名为 "android_mallopt" 的符号。
4. **获取地址:** 找到符号后，动态链接器会从符号表中获取 `android_mallopt` 函数的入口地址。
5. **重定位:**  动态链接器可能会进行重定位操作，以确保函数地址在当前进程的地址空间中是正确的。
6. **调用:**  程序最终通过解析得到的地址来调用 `android_mallopt` 函数。

**逻辑推理、假设输入与输出**

以 `M_GET_DECAY_TIME_ENABLED` 为例：

* **假设输入:**
    * `opcode = M_GET_DECAY_TIME_ENABLED`
    * `arg` 是一个指向未初始化的 `bool` 变量的有效指针。
    * `arg_size = sizeof(bool)`
* **内部逻辑:** 函数会读取全局变量 `__libc_globals->decay_time_enabled` 的当前值（假设为 `true`）。
* **输出:** `arg` 指向的 `bool` 变量的值将被设置为 `true`，函数返回 `true`。

**用户或编程常见的使用错误**

1. **传递错误的 `opcode` 值:**  使用未定义的或错误的 `opcode` 值会导致函数进入未预期的分支，或者在静态链接时返回错误。
   ```c++
   android_mallopt(999, nullptr, 0); // 假设 999 不是有效的 opcode
   ```

2. **`arg` 指针为空或大小不匹配:** 对于需要传递数据的 `opcode`，如果 `arg` 是空指针或者 `arg_size` 与预期大小不符，会导致 `errno` 设置为 `EINVAL` 并返回 `false`。
   ```c++
   bool decay_enabled;
   android_mallopt(M_GET_DECAY_TIME_ENABLED, nullptr, sizeof(bool)); // arg 为空
   android_mallopt(M_GET_DECAY_TIME_ENABLED, &decay_enabled, sizeof(int)); // arg_size 错误
   ```

3. **在不适用的上下文中调用:** 例如，在静态链接的程序中调用只有在动态链接时才有的 `opcode`。
   ```c++
   // 假设程序是静态链接的
   android_mallopt(M_SET_ZYGOTE_CHILD, nullptr, 0); // 会返回错误，因为此功能在静态链接时不可用
   ```

4. **忘记释放内存:** 对于 `M_GET_MALLOC_LEAK_INFO`，用户需要记得调用 `M_FREE_MALLOC_LEAK_INFO` 来释放返回的内存，否则会导致内存泄漏。
   ```c++
   android_mallopt_leak_info_t leak_info;
   if (android_mallopt(M_GET_MALLOC_LEAK_INFO, &leak_info, sizeof(leak_info))) {
       // 处理 leak_info
       // ... 但是忘记调用 M_FREE_MALLOC_LEAK_INFO
   }
   ```

**Android Framework 或 NDK 如何到达这里**

1. **NDK (Native Development Kit):**
   * 使用 NDK 开发的 C/C++ 代码可以直接调用 `android_mallopt` 函数，因为它是由 Bionic libc 提供的。
   * 例如，一个使用 NDK 的游戏引擎可能需要查询或设置一些内存管理选项。
   ```c++
   #include <malloc.h> // 包含 android_mallopt 的声明

   void some_native_function() {
       bool decay_enabled;
       if (android_mallopt(M_GET_DECAY_TIME_ENABLED, &decay_enabled, sizeof(decay_enabled))) {
           // ...
       }
   }
   ```

2. **Android Framework:**
   * Android Framework 的某些组件，特别是那些与内存管理、进程管理或性能分析相关的组件，可能会间接地调用 `android_mallopt`。
   * 例如，`Zygote` 进程在创建新的应用进程时会调用 `android_mallopt(M_SET_ZYGOTE_CHILD, nullptr, 0)`。
   * 系统服务（如 `ActivityManagerService`）可能在进行内存管理决策时查询或设置某些 `mallopt` 选项。
   * 性能分析工具（如 `heapprofd`）的控制逻辑可能会调用 `android_mallopt` 来启用或配置分析。

**Frida Hook 示例调试步骤**

假设我们想 hook `android_mallopt` 函数，查看哪些 `opcode` 被调用以及参数是什么。

**Frida Hook 脚本:**

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: The process '{package_name}' was not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_mallopt"), {
    onEnter: function(args) {
        var opcode = args[0].toInt32();
        var arg = args[1];
        var arg_size = args[2].toInt32();
        var opcode_name = "UNKNOWN";

        const opcodes = {
            0: "M_GET_DECAY_TIME_ENABLED",
            1: "M_INITIALIZE_GWP_ASAN",
            // ... 添加其他 opcode 的映射
            10: "M_SET_ZYGOTE_CHILD",
            11: "M_INIT_ZYGOTE_CHILD_PROFILING",
            12: "M_GET_PROCESS_PROFILEABLE",
            13: "M_WRITE_MALLOC_LEAK_INFO_TO_FILE",
            14: "M_GET_MALLOC_LEAK_INFO",
            15: "M_FREE_MALLOC_LEAK_INFO"
        };

        if (opcodes[opcode]) {
            opcode_name = opcodes[opcode];
        }

        console.log("\\n[*] android_mallopt called");
        console.log("[*]   Opcode: " + opcode + " (" + opcode_name + ")");
        console.log("[*]   arg: " + arg);
        console.log("[*]   arg_size: " + arg_size);

        if (opcode === 0) { // 假设 opcode 0 是 M_GET_DECAY_TIME_ENABLED
            this.decay_ptr = arg;
        } else if (opcode === 14) { // 假设 opcode 14 是 M_GET_MALLOC_LEAK_INFO
            this.leak_info_ptr = arg;
        }
    },
    onLeave: function(retval) {
        console.log("[*] android_mallopt returned: " + retval);
        if (this.decay_ptr) {
            console.log("[*]   Decay Time Enabled: " + Memory.readU8(this.decay_ptr));
            this.decay_ptr = null;
        } else if (this.leak_info_ptr) {
            // 可以读取 leak_info_ptr 指向的内存来查看泄漏信息
            this.leak_info_ptr = null;
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **准备环境:** 确保安装了 Frida，并能连接到你的 Android 设备或模拟器。你的目标应用需要正在运行。
2. **替换包名:** 将 `package_name` 变量替换为你想要监控的应用的包名。
3. **运行 Frida 脚本:** 运行上述 Python 脚本。
4. **触发 `android_mallopt` 调用:** 在你的目标应用中执行某些操作，这些操作可能会导致调用 `android_mallopt`。例如，启动应用，进行内存分配，或者触发垃圾回收。
5. **查看输出:** Frida 脚本会在控制台中打印出 `android_mallopt` 被调用时的 `opcode` 和参数值，以及返回值。你可以根据 `opcode` 的值来推断调用的功能。

这个 Frida 脚本提供了一个基本的框架，你可以根据需要扩展它，例如打印更多关于参数的信息，或者只 hook 特定的 `opcode`。

希望这个详细的解答能够帮助你理解 `android_mallopt.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/android_mallopt.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2009 The Android Open Source Project
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
#include <stdatomic.h>

#include <platform/bionic/malloc.h>
#include <private/bionic_globals.h>

#include "gwp_asan_wrappers.h"
#include "malloc_limit.h"

#if !defined(LIBC_STATIC)
#include <stdio.h>

#include <private/bionic_defs.h>

#include "malloc_heapprofd.h"

extern bool gZygoteChild;
extern _Atomic bool gZygoteChildProfileable;

bool WriteMallocLeakInfo(FILE* fp);
bool GetMallocLeakInfo(android_mallopt_leak_info_t* leak_info);
bool FreeMallocLeakInfo(android_mallopt_leak_info_t* leak_info);
#endif

// =============================================================================
// Platform-internal mallopt variant.
// =============================================================================
#if !defined(LIBC_STATIC)
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
#endif
extern "C" bool android_mallopt(int opcode, void* arg, size_t arg_size) {
  // Functionality available in both static and dynamic libc.
  if (opcode == M_GET_DECAY_TIME_ENABLED) {
    if (arg == nullptr || arg_size != sizeof(bool)) {
      errno = EINVAL;
      return false;
    }
    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_globals->decay_time_enabled);
    return true;
  }
  if (opcode == M_INITIALIZE_GWP_ASAN) {
    if (arg == nullptr || arg_size != sizeof(android_mallopt_gwp_asan_options_t)) {
      errno = EINVAL;
      return false;
    }

    return EnableGwpAsan(*reinterpret_cast<android_mallopt_gwp_asan_options_t*>(arg));
  }
  if (opcode == M_MEMTAG_STACK_IS_ON) {
    if (arg == nullptr || arg_size != sizeof(bool)) {
      errno = EINVAL;
      return false;
    }
    *reinterpret_cast<bool*>(arg) = atomic_load(&__libc_memtag_stack);
    return true;
  }
  if (opcode == M_SET_ALLOCATION_LIMIT_BYTES) {
    return LimitEnable(arg, arg_size);
  }

#if defined(LIBC_STATIC)
  errno = ENOTSUP;
  return false;
#else
  if (opcode == M_SET_ZYGOTE_CHILD) {
    if (arg != nullptr || arg_size != 0) {
      errno = EINVAL;
      return false;
    }
    gZygoteChild = true;
    return true;
  }
  if (opcode == M_INIT_ZYGOTE_CHILD_PROFILING) {
    if (arg != nullptr || arg_size != 0) {
      errno = EINVAL;
      return false;
    }
    atomic_store_explicit(&gZygoteChildProfileable, true, memory_order_release);
    // Also check if heapprofd should start profiling from app startup.
    HeapprofdInitZygoteChildProfiling();
    return true;
  }
  if (opcode == M_GET_PROCESS_PROFILEABLE) {
    if (arg == nullptr || arg_size != sizeof(bool)) {
      errno = EINVAL;
      return false;
    }
    // Native processes are considered profileable. Zygote children are considered
    // profileable only when appropriately tagged.
    *reinterpret_cast<bool*>(arg) =
        !gZygoteChild || atomic_load_explicit(&gZygoteChildProfileable, memory_order_acquire);
    return true;
  }
  if (opcode == M_WRITE_MALLOC_LEAK_INFO_TO_FILE) {
    if (arg == nullptr || arg_size != sizeof(FILE*)) {
      errno = EINVAL;
      return false;
    }
    return WriteMallocLeakInfo(reinterpret_cast<FILE*>(arg));
  }
  if (opcode == M_GET_MALLOC_LEAK_INFO) {
    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
      errno = EINVAL;
      return false;
    }
    return GetMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
  }
  if (opcode == M_FREE_MALLOC_LEAK_INFO) {
    if (arg == nullptr || arg_size != sizeof(android_mallopt_leak_info_t)) {
      errno = EINVAL;
      return false;
    }
    return FreeMallocLeakInfo(reinterpret_cast<android_mallopt_leak_info_t*>(arg));
  }
  // Try heapprofd's mallopt, as it handles options not covered here.
  return HeapprofdMallopt(opcode, arg, arg_size);
#endif
}

"""

```