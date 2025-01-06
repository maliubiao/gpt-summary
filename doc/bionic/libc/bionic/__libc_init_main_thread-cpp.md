Response:
我的目标是对给定的 C++ 源代码文件 `__libc_init_main_thread.cpp` 进行详细分析，并涵盖用户提出的所有要求。以下是逐步思考和分解过程：

1. **理解文件定位和作用:**  首先，我注意到文件路径 `bionic/libc/bionic/__libc_init_main_thread.cpp` 和描述 "bionic is Android's C library, math library, and dynamic linker." 这告诉我这个文件是 Android 系统库 `bionic` 的一部分，并且专注于主线程的初始化。

2. **识别主要功能:** 我需要浏览代码并识别出主要的函数和它们的作用。初步观察，我看到了 `__libc_init_main_thread_early`, `__init_tcb`, `__init_tcb_dtv`, `android_reset_stack_guards`, `__libc_init_main_thread_late`, 和 `__libc_init_main_thread_final` 这些关键函数。

3. **功能描述和与 Android 的关系:**  对于每个识别出的函数，我需要解释其功能，并联系 Android 的特性。
    * `__libc_init_main_thread_early`: 在动态链接器加载 libc 之前执行，负责早期的 TLS 和辅助向量设置。这直接关系到 Android 应用程序的启动过程。
    * `__init_tcb`: 初始化线程控制块 (TCB)，这是线程本地存储的关键数据结构。这对于 Android 的多线程支持至关重要。
    * `__init_tcb_dtv`: 初始化动态 TLS 向量 (DTV)。DTV 用于访问动态加载的共享库中的线程局部变量，这在 Android 应用中使用 NDK 时很常见。
    * `android_reset_stack_guards`: 重新设置栈保护金丝雀值，增强安全性，防止栈溢出攻击。Android 系统非常重视安全性。
    * `__libc_init_main_thread_late`: 完成主线程的初始化，包括设置 TID 地址和线程属性。
    * `__libc_init_main_thread_final`: 在所有模块加载后，分配主线程的最终静态 TLS 内存。

4. **libc 函数实现细节:** 对于像 `__init_tcb` 和 `__init_tcb_dtv` 这样的 libc 内部函数，我需要解释它们如何操作 TCB 的成员，以及 DTV 的初始化方式。  我需要解释 TLS 槽位的概念，以及零 DTV 的作用。

5. **动态链接器相关功能:**  `__libc_init_main_thread_early` 的注释明确提到了它在动态链接器加载 libc 之前被调用。我需要解释这个阶段的特殊性，例如全局变量访问的限制。  我需要构造一个简单的 SO 布局样本，并描述动态链接器如何处理链接过程，包括重定位。

6. **逻辑推理、假设输入输出:**  对于一些涉及到设置或者初始化的函数，例如 `android_reset_stack_guards`，我可以假设一个场景，比如栈保护值未初始化，然后函数执行后，该值被随机化。

7. **常见用户错误:**  思考用户在编程时可能遇到的与这些初始化过程相关的问题。 例如，过早地访问线程局部变量，或者在栈保护机制尚未完全建立时发生栈溢出。

8. **Android Framework/NDK 到达这里的路径:**  这是一个比较复杂的问题。我需要描述 Android 应用的启动流程，从 zygote 进程 fork 出应用进程，到加载 `app_process`，再到动态链接器加载 libc.so，最终调用到这些初始化函数。  NDK 应用的启动流程类似，只是最终执行的是 NDK 编译出的 native 代码。

9. **Frida Hook 示例:**  为关键的初始化函数提供 Frida hook 示例，展示如何监控这些函数的调用和参数。例如，hook `__libc_init_main_thread_early` 可以查看传入的 `KernelArgumentBlock`。

10. **组织和语言:**  最后，我需要将所有信息组织成清晰易懂的中文回复，确保涵盖所有要求。使用清晰的标题和段落，使回复易于阅读。

**预先思考和避免的陷阱：**

* **过度细节:**  避免陷入过于底层的实现细节，保持解释的清晰度和重点。
* **假设读者知识:** 假设读者对操作系统和链接器有一定的了解，但也要避免使用过于专业的术语而不加解释。
* **代码细节的重复:**  避免对同一段代码的功能进行重复解释。
* **忽略 "弱符号":**  注意到 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 宏，这表明这些函数可能在某些情况下被覆盖或不使用，需要在解释中提及。
* **遗漏关键概念:** 确保解释了 TLS、DTV、栈保护等关键概念。

通过以上步骤，我可以系统地分析给定的源代码，并生成满足用户所有要求的详细回复。  在实际编写过程中，我可能会多次迭代和修改，以确保信息的准确性和完整性。

好的，让我们详细分析一下 `bionic/libc/bionic/__libc_init_main_thread.cpp` 这个文件。

**文件功能概述**

这个文件主要负责 Android 系统中主线程的初始化工作。由于主线程是所有其他线程的起点，并且在进程生命周期中扮演着核心角色，因此其初始化过程至关重要。该文件中的函数在进程启动的不同阶段被调用，以完成主线程的各种设置，包括：

* **早期 TLS (Thread Local Storage) 设置:** 在动态链接器加载 libc 之前进行，为主线程建立基本的线程局部存储。
* **线程控制块 (TCB) 初始化:** 创建和初始化与主线程关联的 `pthread_internal_t` 结构，用于管理线程的内部状态。
* **栈保护 (Stack Protector) 设置:** 初始化栈保护机制，防止栈溢出攻击。
* **设置内核线程 ID:** 通知内核主线程的 tid。
* **线程属性初始化:** 设置主线程的默认属性，如调度策略和栈大小。
* **最终 TLS 分配:** 在所有 ELF 模块加载完成后，分配主线程的最终静态 TLS 内存。

**与 Android 功能的关系及举例**

这个文件直接关系到 Android 应用程序的启动和运行。没有正确的主线程初始化，应用程序将无法正常启动。以下是一些具体的例子：

* **应用程序启动:** 当 Android 系统启动一个新的应用程序进程时，`zygote` 进程会 `fork` 出一个新的进程。在这个新进程中，动态链接器会首先加载必要的共享库，包括 `libc.so`。在加载 `libc.so` 的过程中，会调用到这个文件中的函数来初始化主线程。
* **NDK 开发:** 使用 Android NDK 开发原生 C/C++ 代码时，你的 `main` 函数实际上是在主线程中运行的。这个文件中的初始化工作确保了 NDK 代码运行所需的线程环境。
* **线程本地存储 (TLS):** Android 系统和应用程序广泛使用 TLS 来存储线程特定的数据。这个文件中的代码负责建立主线程的 TLS 区域，使得应用程序能够安全地访问线程局部变量。例如，在 NDK 中，你可以使用 `__thread` 关键字声明线程局部变量，这些变量的存储就依赖于这里建立的 TLS。
* **栈溢出保护:**  `android_reset_stack_guards` 函数初始化栈保护机制，这是一种重要的安全特性，可以防止恶意代码通过栈溢出攻击应用程序。

**libc 函数功能实现详解**

让我们详细解释一下代码中的关键函数：

1. **`__libc_init_main_thread_early(const KernelArgumentBlock& args, bionic_tcb* temp_tcb)`:**
   * **功能:** 这是在动态链接器将 `libc.so` 映射到内存之前调用的。它的主要任务是进行最早期的主线程初始化。由于此时 libc 还没有完全加载，所以只能进行非常基本的操作，避免访问未重定位的全局变量或调用复杂的函数。
   * **实现:**
     * `__libc_shared_globals()->auxv = args.auxv;`: 将内核传递的辅助向量 (auxiliary vector) 存储到全局变量中。辅助向量包含了系统信息，如页面大小、硬件能力等。
     * `#if defined(__i386__) __libc_init_sysinfo(); #endif`: 在 x86 架构上初始化系统信息，可能使用辅助向量中的 `AT_SYSINFO` 条目。
     * `__init_tcb(temp_tcb, &main_thread);`: 初始化一个临时的线程控制块 (`bionic_tcb`)。`temp_tcb` 是一个在早期阶段使用的临时 TCB。`main_thread` 是一个静态分配的 `pthread_internal_t` 结构，代表主线程。
     * `__init_tcb_dtv(temp_tcb);`: 初始化临时 TCB 的动态 TLS 向量 (DTV)。DTV 用于管理动态加载的共享库的线程局部存储。
     * `__set_tls(&temp_tcb->tls_slot(0));`: 设置线程局部存储指针，使其指向临时 TCB 的第一个 TLS 槽位。在某些架构上，第一个槽位指向 TCB 本身。
     * `main_thread.tid = __getpid();`: 获取当前进程的 PID，并将其设置为主线程的线程 ID。在 Linux 中，主线程的线程 ID 与进程 ID 相同。
     * `main_thread.set_cached_pid(main_thread.tid);`: 缓存主线程的 PID。
     * `main_thread.stack_top = reinterpret_cast<uintptr_t>(args.argv);`: 将参数列表的起始地址设置为主线程的栈顶。这只是一个临时的值，在后续会进行更精确的设置。
   * **假设输入与输出:** 假设 `args.auxv` 包含了有效的辅助向量数据，`temp_tcb` 指向一块可写的内存区域。输出是 `temp_tcb` 和 `main_thread` 结构的部分字段被初始化。

2. **`__init_tcb(bionic_tcb* tcb, pthread_internal_t* thread)`:**
   * **功能:** 初始化线程控制块 (`bionic_tcb`) 的一部分。
   * **实现:**
     * `#ifdef TLS_SLOT_SELF tcb->tls_slot(TLS_SLOT_SELF) = &tcb->tls_slot(TLS_SLOT_SELF); #endif`: 在某些架构（如 x86）上，将 TCB 的第一个 TLS 槽位设置为指向自身，以便代码可以通过固定的偏移量访问 TCB。
     * `tcb->tls_slot(TLS_SLOT_THREAD_ID) = thread;`: 将 TCB 中用于存储线程 ID 的 TLS 槽位指向 `pthread_internal_t` 结构。这使得可以通过 TLS 方便地获取线程的内部信息。

3. **`__init_tcb_dtv(bionic_tcb* tcb)`:**
   * **功能:** 初始化线程控制块的动态 TLS 向量 (DTV)。
   * **实现:**
     * `static const TlsDtv zero_dtv = {};`: 定义一个静态的空 DTV。
     * `__set_tcb_dtv(tcb, const_cast<TlsDtv*>(&zero_dtv));`: 将 TCB 的 DTV 指针设置为指向这个空的 DTV。当线程首次访问动态 TLS 变量时，会分配真正的 DTV。

4. **`android_reset_stack_guards()`:**
   * **功能:** 重新设置栈保护金丝雀值 (stack guard)。
   * **实现:**
     * `__libc_safe_arc4random_buf(&__stack_chk_guard, sizeof(__stack_chk_guard));`: 使用安全的随机数生成器生成一个新的金丝雀值，并将其存储到全局变量 `__stack_chk_guard` 中。
     * `__init_tcb_stack_guard(__get_bionic_tcb());`: 将新的金丝雀值设置到当前线程的 TCB 中。
   * **用户或编程常见的使用错误:**  理论上，用户不应该直接调用这个函数。如果用户在不了解其作用的情况下调用，可能会导致栈保护失效或出现意外行为。

5. **`__libc_init_main_thread_late()`:**
   * **功能:** 在 libc 基本功能初始化完成后，进一步初始化主线程。
   * **实现:**
     * `__init_bionic_tls_ptrs(__get_bionic_tcb(), __allocate_temp_bionic_tls());`: 初始化 TCB 和 `bionic_tls` 结构中的 TLS 指针。
     * `__set_tid_address(&main_thread.tid);`: 调用内核系统调用 `set_tid_address`，告诉内核在主线程退出时清除 `main_thread.tid` 的值。这使得主线程的行为更像普通的 `pthread` 创建的线程。
     * `pthread_attr_init(&main_thread.attr);`: 初始化主线程的线程属性结构。
     * `pthread_attr_setinheritsched(&main_thread.attr, PTHREAD_INHERIT_SCHED);`: 设置主线程继承创建它的父进程的调度策略。
     * `pthread_attr_setguardsize(&main_thread.attr, 0);`: 设置主线程没有保护页。
     * `pthread_attr_setstacksize(&main_thread.attr, 0);`: 设置主线程的栈大小为 0，表示使用默认大小。
     * `android_reset_stack_guards();`: 再次设置栈保护金丝雀值。
     * `__init_thread(&main_thread);`: 执行更深层次的线程初始化，例如将主线程添加到线程列表中。
     * `__init_additional_stacks(&main_thread);`: 初始化额外的栈空间（如果有）。

6. **`__libc_init_main_thread_final()`:**
   * **功能:** 在所有 ELF 模块加载完成后，分配主线程的最终静态 TLS 内存。
   * **实现:**
     * `bionic_tcb* temp_tcb = __get_bionic_tcb();`: 获取临时的 TCB。
     * `bionic_tls* temp_tls = &__get_bionic_tls();`: 获取临时的 TLS 结构。
     * `ThreadMapping mapping = __allocate_thread_mapping(0, PTHREAD_GUARD_SIZE);`: 分配一块内存区域用于主线程的静态 TLS。
     * `if (mapping.mmap_base == nullptr) { async_safe_fatal("failed to mmap main thread static TLS: %m"); }`: 检查内存分配是否成功。
     * `const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;`: 获取静态 TLS 的布局信息。
     * `auto new_tcb = reinterpret_cast<bionic_tcb*>(mapping.static_tls + layout.offset_bionic_tcb());`: 计算新的 TCB 在分配的内存中的地址。
     * `auto new_tls = reinterpret_cast<bionic_tls*>(mapping.static_tls + layout.offset_bionic_tls());`: 计算新的 TLS 结构在分配的内存中的地址。
     * `__init_static_tls(mapping.static_tls);`: 初始化静态 TLS 区域。
     * `new_tcb->copy_from_bootstrap(temp_tcb);`: 将临时 TCB 的内容复制到新的 TCB。
     * `new_tls->copy_from_bootstrap(temp_tls);`: 将临时 TLS 结构的内容复制到新的 TLS 结构。
     * `__init_tcb(new_tcb, &main_thread);`: 使用新的 TCB 重新初始化主线程。
     * `__init_bionic_tls_ptrs(new_tcb, new_tls);`: 更新 TCB 和 TLS 结构中的 TLS 指针，指向新分配的内存。
     * 更新 `main_thread` 结构中的 `mmap_base` 和 `mmap_size` 等字段，记录分配的内存区域信息。
     * `__set_tls(&new_tcb->tls_slot(0));`: 将线程局部存储指针设置为指向新 TCB 的第一个槽位。
     * `__set_stack_and_tls_vma_name(true);`: 设置栈和 TLS 内存区域的 VMA 名称，方便调试。
     * `__free_temp_bionic_tls(temp_tls);`: 释放临时的 TLS 结构。

**涉及 dynamic linker 的功能**

`__libc_init_main_thread_early` 函数是与动态链接器交互的关键点。在动态链接器加载 `libc.so` 之前调用这个函数，意味着：

* **有限的功能:** 此时，libc 的许多功能还不可用，例如标准库函数。因此，这个函数中的代码必须非常谨慎，只能调用链接器提供的基本功能或直接进行内存操作。
* **全局变量的特殊性:** 对全局变量的写入会影响链接器私有的副本，而不是最终加载的 libc 中的副本。这是因为链接器在重定位之前运行代码。

**SO 布局样本和链接处理过程**

假设我们有一个简单的 Android 应用程序，它链接了 `libc.so` 和一个自定义的共享库 `libmy.so`。

**SO 布局样本:**

```
Memory Address Space:

[加载器/链接器代码]
[libc.so]
    .text   (代码段)
    .rodata (只读数据段)
    .data   (已初始化数据段)
    .bss    (未初始化数据段)
    .plt    (过程链接表)
    .got    (全局偏移量表)
    ...
    __libc_init_main_thread_early  (位于 .text 段)
    ...
[libmy.so]
    .text
    .rodata
    .data
    .bss
    .plt
    .got
    ...
[应用程序代码]
    .text
    ...
[栈]
[堆]
```

**链接的处理过程 (简化):**

1. **加载器/链接器启动:**  当操作系统启动应用程序时，内核会加载应用程序的可执行文件，并将控制权交给动态链接器（通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
2. **加载依赖库:** 动态链接器解析应用程序的依赖关系，并加载所需的共享库，包括 `libc.so` 和 `libmy.so`。
3. **映射共享库:** 动态链接器将这些共享库映射到进程的地址空间中的不同区域。
4. **重定位:**  由于共享库被加载到内存中的随机地址，链接器需要修改代码和数据中的地址引用，使其指向正确的内存位置。这包括：
   * **代码重定位:** 修改指令中引用的全局变量和函数地址。
   * **数据重定位:** 修改全局变量的初始值。
5. **解析符号:** 链接器解析共享库之间的符号引用，例如，如果 `libmy.so` 调用了 `libc.so` 中的函数，链接器会确保调用指向 `libc.so` 中该函数的地址。
6. **调用初始化函数:** 对于每个共享库，链接器会查找并调用其初始化函数 (例如，`.init` 段中的代码或使用 `__attribute__((constructor))` 声明的函数)。对于 `libc.so`，`__libc_init_main_thread_early` 就是在这个早期阶段被链接器调用的。
7. **执行应用程序代码:**  完成链接和初始化后，链接器将控制权交给应用程序的入口点 (`_start` 函数，通常由 `libc` 提供)。

**逻辑推理、假设输入与输出**

在 `__libc_init_main_thread_early` 中：

* **假设输入:** `args` 包含有效的内核参数块，例如 `argv` 指向参数字符串数组，`auxv` 包含系统信息。`temp_tcb` 指向一块预先分配好的 `bionic_tcb` 结构。
* **输出:**  `temp_tcb` 结构的某些字段被初始化，例如指向 `main_thread`，DTV 被设置为初始状态，TLS 指针被设置。`main_thread` 结构的 `tid` 和临时的 `stack_top` 被设置。

**用户或编程常见的使用错误**

* **在早期初始化阶段访问 libc 功能:**  如果在动态链接器加载 `libc.so` 之前（或者在 `__libc_init_main_thread_early` 执行期间）尝试使用 libc 的标准库函数，会导致程序崩溃或未定义的行为。因为此时这些函数可能还没有被正确加载和初始化。
* **错误的 TLS 使用:**  如果在多线程编程中不正确地使用线程局部存储，例如，在没有正确初始化 TLS 的情况下访问线程局部变量，可能会导致数据竞争或段错误。
* **栈溢出:**  尽管栈保护机制存在，但如果程序员编写了不安全的代码，仍然可能发生栈溢出。例如，使用 `strcpy` 复制过长的字符串到固定大小的缓冲区。

**Android Framework 或 NDK 如何到达这里**

1. **应用程序启动 (Framework):**
   * Android 系统启动应用程序时，首先会启动 `zygote` 进程。
   * `zygote` 进程 `fork` 出新的应用程序进程。
   * 在新的应用程序进程中，内核执行 `app_process` (或 `app_process64`)。
   * `app_process` 负责创建虚拟机实例并加载应用程序代码。
   * 在加载过程中，动态链接器会加载应用程序依赖的共享库，包括 `libc.so`。
   * 动态链接器在加载 `libc.so` 的早期阶段调用 `__libc_init_main_thread_early`。
   * 随后的 `__libc_init_main_thread_late` 和 `__libc_init_main_thread_final` 在 libc 初始化过程中被调用。

2. **NDK 应用程序启动:**
   * 过程类似，但最终执行的是 NDK 编译出的原生代码。
   * 当应用程序启动时，动态链接器加载应用程序依赖的共享库，包括 `libc.so`。
   * `__libc_init_main_thread_early` 等函数会被调用以初始化主线程环境。
   * NDK 应用程序的 `main` 函数会在初始化完成后的主线程中执行。

**Frida Hook 示例**

以下是一些使用 Frida hook 来调试这些步骤的示例：

```javascript
// Hook __libc_init_main_thread_early
Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_main_thread_early"), {
  onEnter: function (args) {
    console.log("[__libc_init_main_thread_early] called");
    // 打印 KernelArgumentBlock 的内容 (需要进一步解析内存结构)
    console.log("  KernelArgumentBlock:", args[0]);
    // 打印 bionic_tcb 指针
    console.log("  bionic_tcb*:", args[1]);
  },
  onLeave: function (retval) {
    console.log("[__libc_init_main_thread_early] returned");
  }
});

// Hook __init_tcb
Interceptor.attach(Module.findExportByName("libc.so", "__init_tcb"), {
  onEnter: function (args) {
    console.log("[__init_tcb] called");
    // 打印 bionic_tcb 指针
    console.log("  bionic_tcb*:", args[0]);
    // 打印 pthread_internal_t 指针
    console.log("  pthread_internal_t*:", args[1]);
  }
});

// Hook android_reset_stack_guards
Interceptor.attach(Module.findExportByName("libc.so", "android_reset_stack_guards"), {
  onEnter: function () {
    console.log("[android_reset_stack_guards] called");
    // 读取当前的 __stack_chk_guard 值
    var stack_chk_guard = Process.findModuleByName("libc.so").getExportByName("__stack_chk_guard");
    console.log("  Current __stack_chk_guard:", stack_chk_guard.readUInt());
  },
  onLeave: function () {
    console.log("[android_reset_stack_guards] returned");
    // 读取更新后的 __stack_chk_guard 值
    var stack_chk_guard = Process.findModuleByName("libc.so").getExportByName("__stack_chk_guard");
    console.log("  New __stack_chk_guard:", stack_chk_guard.readUInt());
  }
});

// Hook __libc_init_main_thread_late
Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_main_thread_late"), {
  onEnter: function () {
    console.log("[__libc_init_main_thread_late] called");
  },
  onLeave: function () {
    console.log("[__libc_init_main_thread_late] returned");
  }
});

// Hook __libc_init_main_thread_final
Interceptor.attach(Module.findExportByName("libc.so", "__libc_init_main_thread_final"), {
  onEnter: function () {
    console.log("[__libc_init_main_thread_final] called");
  },
  onLeave: function () {
    console.log("[__libc_init_main_thread_final] returned");
  }
});
```

要使用这些 Frida 脚本，你需要将它们保存为 `.js` 文件，然后使用 Frida 命令行工具附加到目标 Android 进程：

```bash
frida -U -f <your_app_package_name> -l your_script.js --no-pause
```

将 `<your_app_package_name>` 替换为你的应用程序的包名，`your_script.js` 替换为你的 Frida 脚本文件名。

希望这个详细的解释能够帮助你理解 `__libc_init_main_thread.cpp` 文件的功能和作用。

Prompt: 
```
这是目录为bionic/libc/bionic/__libc_init_main_thread.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "libc_init_common.h"

#include <async_safe/log.h>

#include "private/KernelArgumentBlock.h"
#include "private/bionic_arc4random.h"
#include "private/bionic_defs.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "private/bionic_ssp.h"
#include "pthread_internal.h"

extern "C" pid_t __getpid();
extern "C" int __set_tid_address(int* tid_address);

// Declared in "private/bionic_ssp.h".
uintptr_t __stack_chk_guard = 0;

BIONIC_USED_BEFORE_LINKER_RELOCATES static pthread_internal_t main_thread;

// Setup for the main thread. For dynamic executables, this is called by the
// linker _before_ libc is mapped in memory. This means that all writes to
// globals from this function will apply to linker-private copies and will not
// be visible from libc later on.
//
// Note: this function creates a pthread_internal_t for the initial thread and
// stores the pointer in TLS, but does not add it to pthread's thread list. This
// has to be done later from libc itself (see __libc_init_common).
//
// This is in a file by itself because it needs to be built with
// -fno-stack-protector because it's responsible for setting up the main
// thread's TLS (which stack protector relies on). It's also built with
// -ffreestanding because the early init function runs in the linker before
// ifunc resolvers have run.

// Do enough setup to:
//  - Let the dynamic linker invoke system calls (and access errno)
//  - Ensure that TLS access functions (__get_{tls,thread}) never return NULL
//  - Allow the stack protector to work (with a zero cookie)
// Avoid doing much more because, when this code is called within the dynamic
// linker, the linker binary hasn't been relocated yet, so certain kinds of code
// are hazardous, such as accessing non-hidden global variables or calling
// string.h functions.
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
extern "C" void __libc_init_main_thread_early(const KernelArgumentBlock& args,
                                              bionic_tcb* temp_tcb) {
  __libc_shared_globals()->auxv = args.auxv;
#if defined(__i386__)
  __libc_init_sysinfo(); // uses AT_SYSINFO auxv entry
#endif
  __init_tcb(temp_tcb, &main_thread);
  __init_tcb_dtv(temp_tcb);
  __set_tls(&temp_tcb->tls_slot(0));
  main_thread.tid = __getpid();
  main_thread.set_cached_pid(main_thread.tid);
  main_thread.stack_top = reinterpret_cast<uintptr_t>(args.argv);
}

// This code is used both by each new pthread and the code that initializes the main thread.
void __init_tcb(bionic_tcb* tcb, pthread_internal_t* thread) {
#ifdef TLS_SLOT_SELF
  // On x86, slot 0 must point to itself so code can read the thread pointer by
  // loading %fs:0 or %gs:0.
  tcb->tls_slot(TLS_SLOT_SELF) = &tcb->tls_slot(TLS_SLOT_SELF);
#endif
  tcb->tls_slot(TLS_SLOT_THREAD_ID) = thread;
}

void __init_tcb_dtv(bionic_tcb* tcb) {
  // Initialize the DTV slot to a statically-allocated empty DTV. The first
  // access to a dynamic TLS variable allocates a new DTV.
  static const TlsDtv zero_dtv = {};
  __set_tcb_dtv(tcb, const_cast<TlsDtv*>(&zero_dtv));
}

// This is public so that the zygote can call it too. It is not expected
// to be useful otherwise.
//
// Note in particular that it is not possible to return from any existing
// stack frame with stack protector enabled after this function is called.
extern "C" void android_reset_stack_guards() {
  // The TLS stack guard is set from the global, so ensure that we've initialized the global
  // before we initialize the TLS. Dynamic executables will initialize their copy of the global
  // stack protector from the one in the main thread's TLS.
  __libc_safe_arc4random_buf(&__stack_chk_guard, sizeof(__stack_chk_guard));
  __init_tcb_stack_guard(__get_bionic_tcb());
}

// Finish initializing the main thread.
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
extern "C" void __libc_init_main_thread_late() {
  __init_bionic_tls_ptrs(__get_bionic_tcb(), __allocate_temp_bionic_tls());

  // Tell the kernel to clear our tid field when we exit, so we're like any other pthread.
  // For threads created by pthread_create, this setup happens during the clone syscall (i.e.
  // CLONE_CHILD_CLEARTID).
  __set_tid_address(&main_thread.tid);

  pthread_attr_init(&main_thread.attr);
  // We don't want to explicitly set the main thread's scheduler attributes (http://b/68328561).
  pthread_attr_setinheritsched(&main_thread.attr, PTHREAD_INHERIT_SCHED);
  // The main thread has no guard page.
  pthread_attr_setguardsize(&main_thread.attr, 0);
  // User code should never see this; we'll compute it when asked.
  pthread_attr_setstacksize(&main_thread.attr, 0);

  android_reset_stack_guards();

  __init_thread(&main_thread);

  __init_additional_stacks(&main_thread);
}

// Once all ELF modules are loaded, allocate the final copy of the main thread's
// static TLS memory.
__BIONIC_WEAK_FOR_NATIVE_BRIDGE
extern "C" void __libc_init_main_thread_final() {
  bionic_tcb* temp_tcb = __get_bionic_tcb();
  bionic_tls* temp_tls = &__get_bionic_tls();

  // Allocate the main thread's static TLS. (This mapping doesn't include a
  // stack.)
  ThreadMapping mapping = __allocate_thread_mapping(0, PTHREAD_GUARD_SIZE);
  if (mapping.mmap_base == nullptr) {
    async_safe_fatal("failed to mmap main thread static TLS: %m");
  }

  const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  auto new_tcb = reinterpret_cast<bionic_tcb*>(mapping.static_tls + layout.offset_bionic_tcb());
  auto new_tls = reinterpret_cast<bionic_tls*>(mapping.static_tls + layout.offset_bionic_tls());

  __init_static_tls(mapping.static_tls);
  new_tcb->copy_from_bootstrap(temp_tcb);
  new_tls->copy_from_bootstrap(temp_tls);
  __init_tcb(new_tcb, &main_thread);
  __init_bionic_tls_ptrs(new_tcb, new_tls);

  main_thread.mmap_base = mapping.mmap_base;
  main_thread.mmap_size = mapping.mmap_size;
  main_thread.mmap_base_unguarded = mapping.mmap_base_unguarded;
  main_thread.mmap_size_unguarded = mapping.mmap_size_unguarded;

  __set_tls(&new_tcb->tls_slot(0));

  __set_stack_and_tls_vma_name(true);
  __free_temp_bionic_tls(temp_tls);
}

"""

```