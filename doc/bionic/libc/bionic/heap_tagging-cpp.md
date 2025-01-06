Response:
我的目标是对给定的 C++ 源代码文件 `heap_tagging.cpp` 进行深入分析和解释。以下是我的思考过程，以确保覆盖所有要求：

1. **理解文件目标和上下文:**  首先，我注意到文件路径 `bionic/libc/bionic/heap_tagging.cpp` 和说明 "bionic is Android's C library, math library, and dynamic linker" 表明这个文件是 Android 系统库 `bionic` 的一部分，专门负责堆内存标记（heap tagging）功能。 关键词 "heap tagging" 告诉我，这个文件很可能与内存安全和调试有关。

2. **列举功能:** 我需要浏览代码并识别其主要功能。以下是我在第一次阅读时注意到的关键点：
    * 设置和获取堆标记级别 (`SetHeapTaggingLevel`, `SetDefaultHeapTaggingLevel`)
    * 处理默认的堆标记级别 (`SetDefaultHeapTaggingLevel`)
    * 与内存标记相关的全局变量 (`heap_tagging_level`)
    * 与 Scudo 内存分配器的交互 (`scudo_malloc_disable_memory_tagging`, `scudo_malloc_set_track_allocation_stacks`)
    * 在所有线程上设置 MTE (Memory Tagging Extension) 配置 (`set_tcf_on_all_threads`)
    * 处理 `longjmp` 调用 (`memtag_handle_longjmp`)
    * 涉及 AArch64 特定的操作和宏 (`__aarch64__`)
    * 与 HWASan (Hardware-assisted AddressSanitizer) 的集成 (`__has_feature(hwaddress_sanitizer)`, `__hwasan_handle_longjmp`)

3. **关联 Android 功能:**  考虑到这个文件属于 Android 的 `bionic` 库，我需要解释这些功能如何与 Android 的整体运行相关联。
    * **内存安全:**  堆标记是一种提高内存安全性的技术，可以帮助检测和防止内存错误，例如 use-after-free 和 double-free。这对于 Android 这样的复杂系统至关重要。
    * **调试和诊断:** 堆标记可以为开发者提供更详细的内存分配和释放信息，有助于调试内存相关的问题。
    * **性能影响:**  内存标记可能会带来性能开销，因此 Android 允许配置不同的标记级别，以便在安全性和性能之间进行权衡。
    * **系统服务和应用程序:**  堆标记功能影响到所有使用 `bionic` 库的 Android 组件，包括系统服务和应用程序。

4. **详细解释 libc 函数实现:**  我需要深入了解代码中使用的 libc 函数以及它们的作用。
    * `prctl`:  用于设置和获取进程属性，这里用于配置 MTE 的线程控制标志 (TCF)。
    * `pthread_mutex_t`: 用于线程同步，保护全局变量 `heap_tagging_level`。
    * `atomic_store`: 原子操作，用于安全地更新共享变量，例如 `__libc_memtag_stack` 和 `globals->memtag`。
    * `android_run_on_all_threads`:  Android 特有的函数，用于在所有线程上执行给定的函数。
    * `async_safe_fatal`:  在异步信号处理程序中安全地终止进程。

5. **Dynamic Linker 的功能:** 代码中并没有直接涉及 dynamic linker 的具体操作，但提到了一些与内存地址相关的全局变量，这暗示了 dynamic linker 可能在初始化这些变量时起作用。  我需要在解释中提到这一点，并提供一个典型的 SO (Shared Object) 布局示例，并说明链接过程如何将这些变量地址解析到 SO 中。

6. **逻辑推理、假设输入与输出:**  对于像 `SetHeapTaggingLevel` 这样的函数，我可以考虑不同的输入（不同的标记级别）并推断其行为。例如，如果输入 `M_HEAP_TAGGING_LEVEL_TBI`，代码会设置 `globals->heap_pointer_tag`。我需要给出这样的例子，并解释预期的输出（例如，指针的标记方式）。

7. **常见使用错误:**  我需要考虑开发者在使用堆标记功能时可能犯的错误。例如，在不支持堆标记的设备上启用它可能会导致问题。或者，不正确地处理 `longjmp` 可能会导致内存错误。

8. **Android Framework/NDK 到达这里的路径:**  我需要解释 Android 应用程序或 framework 如何最终调用到 `heap_tagging.cpp` 中的函数。这涉及到以下步骤：
    * NDK 应用程序调用 `malloc` 或 `free`。
    * `malloc` 和 `free` 的实现位于 `bionic` 库中。
    * `bionic` 的内存分配器（例如 Scudo）可能会利用堆标记功能。
    * Framework 中的某些操作也可能直接或间接地触发内存分配，从而涉及到堆标记。

9. **Frida Hook 示例:**  为了进行调试，我需要提供 Frida hook 的示例代码，以便在运行时拦截和检查 `heap_tagging.cpp` 中的函数调用和变量值。

10. **组织和语言:** 最后，我需要用清晰的中文组织我的回答，确保易于理解。我需要使用代码块来展示代码片段，并使用适当的术语来解释概念。

**自我纠正和补充:**

* **Scudo 的角色:** 我需要更详细地解释 Scudo 内存分配器在堆标记中的作用。Scudo 是 Android 上的默认分配器，它集成了 MTE 支持。
* **MTE (Memory Tagging Extension):** 需要解释 MTE 是 ARMv8.5-A 架构引入的硬件特性，用于内存标记。
* **TCF (Tag Check Faults):**  解释 TCF 是 MTE 的一部分，用于配置如何处理标记不匹配的情况。
* **`longjmp` 的内存清理:**  重点解释 `memtag_handle_longjmp` 如何在 `longjmp` 发生时清理目标堆栈上的标记，以避免标记不一致。
* **更具体的 Frida Hook 示例:** 提供更具体的 Frida 代码，例如 hook `SetHeapTaggingLevel` 并打印参数。

通过以上思考过程，我能够更全面地理解 `heap_tagging.cpp` 的功能，并按照要求进行详细的解释和说明。 我的目标是提供一个既准确又易于理解的答案，帮助读者深入了解 Android 的堆内存标记机制。

这是一个关于 Android Bionic 库中 `heap_tagging.cpp` 文件的分析。这个文件主要负责管理 Android 系统中的堆内存标记（Heap Tagging）功能，这是一项利用 ARMv8.5-A 内存标记扩展（MTE）来增强内存安全性的技术。

**功能列举:**

1. **设置和获取堆标记级别:**  文件定义了 `SetHeapTaggingLevel` 和 `SetDefaultHeapTaggingLevel` 函数，用于设置和初始化系统的堆标记级别。堆标记级别决定了系统如何使用 MTE 来保护堆内存。可能的级别包括：
    * `M_HEAP_TAGGING_LEVEL_NONE`:  禁用堆标记。
    * `M_HEAP_TAGGING_LEVEL_TBI`:  仅使用 Top Byte Ignore (TBI)，一种简化的标记形式。
    * `M_HEAP_TAGGING_LEVEL_ASYNC`:  异步地检查内存标记，性能开销较低。
    * `M_HEAP_TAGGING_LEVEL_SYNC`:  同步地检查内存标记，能更早地发现错误，但性能开销较高。

2. **与 Scudo 内存分配器的集成:**  Scudo 是 Android 的默认内存分配器。这个文件中的代码会根据堆标记级别来配置 Scudo 的行为，例如禁用内存标记或启用分配栈跟踪。

3. **在所有线程上设置 MTE 配置:**  `set_tcf_on_all_threads` 函数使用 `prctl` 系统调用在所有线程上设置内存标记的线程控制标志 (TCF)。TCF 决定了当发生标记不匹配时，系统应该如何处理（例如，产生一个异常）。

4. **处理 `longjmp`:**  `memtag_handle_longjmp` 函数处理 `longjmp` 调用，这是一个非本地跳转操作。由于 `longjmp` 会改变程序的执行流程和栈状态，需要确保在跳转后栈上的内存标记仍然有效。这个函数会清理目标栈上的标记，以避免标记不一致。

5. **全局锁保护:** 使用 `g_heap_tagging_lock` 互斥锁来保护对全局变量 `heap_tagging_level` 的访问，确保线程安全。

**与 Android 功能的关系及举例说明:**

堆标记是 Android 系统安全性的重要组成部分。它可以帮助检测和预防各种内存错误，例如：

* **Use-after-free (释放后使用):**  如果一个指针指向已经被释放的内存，并且程序尝试访问这块内存，MTE 可以检测到标记不匹配，并抛出异常。
    * **例子:**  一个 Service 持有一个指向 Activity 分配的内存的指针。当 Activity 销毁并释放内存后，Service 仍然尝试访问这块内存。开启堆标记后，系统会检测到这个错误。

* **Double-free (重复释放):**  如果同一块内存被释放两次，MTE 也可以检测到。
    * **例子:**  一个 Bug 在代码中导致 `free()` 函数被调用了两次在同一个内存地址上。堆标记可以阻止第二次释放并报告错误。

* **Heap buffer overflow (堆缓冲区溢出):**  虽然 MTE 不是专门为检测缓冲区溢出设计的，但在某些情况下，溢出可能会破坏相邻内存块的标记，从而被 MTE 检测到。

**libc 函数的实现解释:**

* **`prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0)` 和 `prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0)`:**
    * `prctl` 是一个 Linux 系统调用，用于对进程的行为进行各种控制。
    * `PR_SET_TAGGED_ADDR_CTRL` 用于设置与内存标记相关的进程属性，例如线程控制标志 (TCF)。`tagged_addr_ctrl` 参数指定了 MTE 的行为，例如是否启用标记检查以及如何处理标记不匹配。
    * `PR_GET_TAGGED_ADDR_CTRL` 用于获取当前的 MTE 配置。
    * **实现:**  `prctl` 的实现位于内核中。当用户空间程序调用 `prctl` 时，会发生系统调用，内核会根据传入的参数修改进程的相应属性。

* **`pthread_mutex_t g_heap_tagging_lock = PTHREAD_MUTEX_INITIALIZER;` 和 `pthread_mutex_lock(&g_heap_tagging_lock);` / `pthread_mutex_unlock(&g_heap_tagging_lock);`:**
    * `pthread_mutex_t` 定义了一个互斥锁，用于保护共享资源，防止并发访问导致的数据竞争。
    * `pthread_mutex_lock` 尝试获取互斥锁。如果锁已经被其他线程持有，调用线程将被阻塞，直到锁被释放。
    * `pthread_mutex_unlock` 释放互斥锁，允许其他等待的线程获取锁。
    * **实现:** 这些函数由 Bionic 库实现，基于底层的内核同步机制（如 futex）。

* **`atomic_store(&__libc_memtag_stack, ...)` 和 `atomic_load(&__libc_memtag_stack)`:**
    * 这些是原子操作，用于安全地读写共享变量，避免多线程环境下的数据竞争。原子操作保证了操作的完整性，不会被其他线程打断。
    * `atomic_store` 原子地将一个值存储到指定的内存位置。
    * `atomic_load` 原子地从指定的内存位置加载一个值。
    * **实现:** 这些操作通常通过 CPU 提供的原子指令来实现，确保操作的原子性。

* **`android_run_on_all_threads(..., &tcf)`:**
    * 这是一个 Android 特有的函数，用于在进程中的所有线程上执行指定的函数。
    * **实现:**  这个函数的实现会遍历当前进程的所有线程，并为每个线程调用传入的回调函数。这通常涉及到访问进程的线程管理数据结构。

* **`async_safe_fatal(...)`:**
    * 这是一个在异步信号处理程序中安全地终止进程的函数。由于信号处理程序可能在任何时候被调用，因此只能执行非常有限的安全操作。
    * **实现:**  `async_safe_fatal` 通常会调用 `_exit()` 系统调用，这是一个保证安全的进程终止方式，不会调用任何用户空间的清理代码。

* **`untag_memory(void* from, void* to)`:**
    * 这是一个内联汇编函数，专门用于 AArch64 架构。它的作用是移除指定内存范围内的内存标记。这通常在处理 `longjmp` 时使用，以确保栈上的标记与新的栈状态一致。
    * **实现:**  它使用 ARMv8.5-A 的 MTE 指令 `stg` (store tag) 来将标记清零。

**Dynamic Linker 的功能:**

虽然 `heap_tagging.cpp` 本身不直接实现 dynamic linker 的功能，但它依赖于 dynamic linker 来定位和访问一些全局变量和外部函数，例如：

* `__libc_shared_globals()`:  这是一个由 dynamic linker 在加载时解析的全局符号，指向 libc 的共享全局数据结构。
* `scudo_malloc_disable_memory_tagging()` 和 `scudo_malloc_set_track_allocation_stacks()`: 这些是 Scudo 库中的函数，dynamic linker 负责在程序启动时将这些符号链接到正确的地址。
* `__scudo_get_stack_depot_addr()`, `__scudo_get_ring_buffer_addr()` 等: 这些也是 Scudo 提供的用于获取内部数据结构地址的函数，需要 dynamic linker 进行链接。

**SO 布局样本:**

假设一个使用了堆标记功能的 Android 应用程序 `my_app`，它链接了 `libc.so` 和 `libscudo.so`。

```
Memory Map:

    Address Range         Permissions    Mapping
    --------------------- -------------- ------------------
    0xAAAA00000000 - 0xAAAA00001000    r-x p          /system/bin/linker64
    0xAAAA00001000 - 0xAAAA00002000    r-- p          /system/bin/linker64
    0xAAAA00002000 - 0xAAAA00003000    rw- p          /system/bin/linker64
    ...
    0xBBBB00000000 - 0xBBBB00100000    r-x p          /system/lib64/libc.so  <-- libc 加载地址
    0xBBBB00100000 - 0xBBBB00200000    r-- p          /system/lib64/libc.so
    0xBBBB00200000 - 0xBBBB00280000    rw- p          /system/lib64/libc.so  <-- __libc_shared_globals() 位于此区域
    ...
    0xCCCC00000000 - 0xCCCC00080000    r-x p          /system/lib64/libscudo.so  <-- libscudo 加载地址
    0xCCCC00080000 - 0xCCCC000A0000    r-- p          /system/lib64/libscudo.so
    0xCCCC000A0000 - 0xCCCC000B0000    rw- p          /system/lib64/libscudo.so  <-- scudo 函数位于此区域
    ...
    0xDDDD00000000 - 0xDDDD00010000    r-x p          /data/app/com.example.myapp/lib/arm64/my_app  <-- 应用程序加载地址
    ...
```

**链接的处理过程:**

1. **加载:** 当 `my_app` 启动时，Android 的 `linker64` (dynamic linker) 会被首先调用。
2. **依赖解析:** `linker64` 读取 `my_app` 的 ELF 头，找到其依赖的共享库，例如 `libc.so` 和 `libscudo.so`。
3. **加载共享库:** `linker64` 将这些共享库加载到内存中的可用地址空间。
4. **符号解析:** `linker64` 遍历 `my_app` 和其依赖库的符号表和重定位表。
5. **重定位:** 对于在 `heap_tagging.cpp` 中使用的外部符号，例如 `__libc_shared_globals` 和 Scudo 的函数，`linker64` 会将这些符号引用替换为它们在内存中的实际地址。例如，对 `__libc_shared_globals()` 的调用会被修改为指向 `libc.so` 中 `__libc_shared_globals` 变量的地址。同样，对 `scudo_malloc_disable_memory_tagging()` 的调用会被修改为指向 `libscudo.so` 中该函数的地址。

**假设输入与输出:**

假设调用 `SetHeapTaggingLevel(M_HEAP_TAGGING_LEVEL_SYNC)`:

* **输入:** `tag_level = M_HEAP_TAGGING_LEVEL_SYNC`
* **逻辑推理:**
    1. 代码会检查 `tag_level` 是否等于当前的 `heap_tagging_level`。如果不同，则进入 switch 语句。
    2. 由于 `tag_level` 是 `M_HEAP_TAGGING_LEVEL_SYNC`，代码会执行相应的 case。
    3. 如果当前 `heap_tagging_level` 是 `M_HEAP_TAGGING_LEVEL_NONE`，则会输出错误日志并返回 `false`。
    4. 否则，`set_tcf_on_all_threads(PR_MTE_TCF_SYNC)` 会被调用，尝试在所有线程上设置同步标记检查。
    5. 如果使用了 Scudo 且没有启用 HWASan，则会调用 `scudo_malloc_set_track_allocation_stacks(1)`，启用 Scudo 的分配栈跟踪。
    6. Scudo 的环形缓冲区和栈仓库的地址和大小会被获取并存储到 `__libc_shared_globals()` 中。
    7. `heap_tagging_level` 被更新为 `M_HEAP_TAGGING_LEVEL_SYNC`。
    8. 输出信息日志，指示标记级别已设置。
* **输出:**  如果一切顺利，函数返回 `true`，并且系统的堆标记级别被设置为同步检查。如果设置 TCF 失败，函数返回 `false` 并输出错误日志。

**用户或编程常见的使用错误:**

1. **在不支持 MTE 的设备上启用堆标记:**  如果在不支持 ARMv8.5-A MTE 的设备上尝试启用 `M_HEAP_TAGGING_LEVEL_SYNC` 或 `M_HEAP_TAGGING_LEVEL_ASYNC`，`prctl` 调用会失败，导致堆标记功能无法正常工作。
    * **错误示例:**  开发者硬编码设置堆标记级别为 `SYNC`，但在旧设备上运行应用程序。

2. **在禁用堆标记后尝试重新启用:** 代码中有检查，如果堆标记被禁用 (`NONE`) 后尝试重新启用 (`TBI`, `ASYNC`, 或 `SYNC`)，`SetHeapTaggingLevel` 会返回 `false`，并输出错误日志。这是因为重新启用可能会导致一些状态不一致的问题。
    * **错误示例:**  应用程序先调用 `SetHeapTaggingLevel(NONE)` 禁用堆标记，然后在稍后的某个时刻又调用 `SetHeapTaggingLevel(SYNC)`。

3. **在 TBI 和 ASYNC/SYNC 之间切换:**  代码不允许在 `M_HEAP_TAGGING_LEVEL_TBI` 和 `M_HEAP_TAGGING_LEVEL_ASYNC`/`M_HEAP_TAGGING_LEVEL_SYNC` 之间直接切换。必须先设置为 `NONE` 才能切换到另一种模式。
    * **错误示例:**  应用程序先设置堆标记级别为 `TBI`，然后直接尝试设置为 `SYNC`。

4. **不正确的 `longjmp` 使用:** 如果代码中使用了 `longjmp`，但没有调用 `setjmp` 进行正确的配对，或者跳转的目标栈帧已经被销毁，即使有 `memtag_handle_longjmp` 的处理，也可能导致未定义的行为和内存错误。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 应用调用 `malloc` 或 `free`:**  当一个使用 NDK 开发的 C/C++ 应用调用标准库的内存分配函数（如 `malloc`, `free`, `new`, `delete`）时，这些调用最终会路由到 Bionic 库中的实现。

2. **Bionic 的内存分配器 (Scudo):**  Bionic 使用 Scudo 作为默认的内存分配器。Scudo 在分配和释放内存时，会考虑当前的堆标记级别。

3. **系统属性或环境变量:** Android 系统可以通过系统属性或环境变量来配置默认的堆标记级别。例如，`libc.debug.malloc.tag_level` 属性可以设置初始的堆标记级别。

4. **`SetDefaultHeapTaggingLevel` 的调用:**  在 Bionic 的初始化过程中，`SetDefaultHeapTaggingLevel` 函数会被调用，根据系统配置设置初始的堆标记级别。这通常发生在 `libc.so` 加载时。

5. **Framework 的内存操作:**  Android Framework 中的各种组件和服务在运行时也会进行大量的内存分配和释放。这些操作也会使用 Bionic 提供的内存分配器，从而受到堆标记设置的影响。

6. **开发者显式调用 `SetHeapTaggingLevel` (不常见):**  虽然不常见，但开发者也可以通过 JNI 调用到 Bionic 库，并显式地调用 `SetHeapTaggingLevel` 来动态调整堆标记级别。这通常用于调试或性能测试。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `SetHeapTaggingLevel` 函数调用的示例：

```javascript
if (Process.arch === 'arm64') {
  const SetHeapTaggingLevel = Module.findExportByName("libc.so", "SetHeapTaggingLevel");
  if (SetHeapTaggingLevel) {
    Interceptor.attach(SetHeapTaggingLevel, {
      onEnter: function (args) {
        const tagLevel = args[0].toInt();
        console.log("SetHeapTaggingLevel called with tagLevel:", tagLevel);
        // 可以进一步检查 tagLevel 的值，例如打印其枚举值
        if (tagLevel === 0) {
          console.log("Heap tagging level is being set to NONE");
        } else if (tagLevel === 1) {
          console.log("Heap tagging level is being set to TBI");
        } else if (tagLevel === 2) {
          console.log("Heap tagging level is being set to ASYNC");
        } else if (tagLevel === 3) {
          console.log("Heap tagging level is being set to SYNC");
        }
      },
      onLeave: function (retval) {
        console.log("SetHeapTaggingLevel returned:", retval);
      }
    });
  } else {
    console.error("Could not find SetHeapTaggingLevel function");
  }
} else {
  console.warn("Heap tagging is only relevant for arm64 architecture.");
}
```

**解释:**

1. **`if (Process.arch === 'arm64')`:**  堆标记功能主要在 ARM64 架构上使用，因此先检查架构。
2. **`Module.findExportByName("libc.so", "SetHeapTaggingLevel")`:**  在 `libc.so` 库中查找 `SetHeapTaggingLevel` 函数的地址。
3. **`Interceptor.attach(...)`:** 使用 Frida 的 `Interceptor` API 来拦截对 `SetHeapTaggingLevel` 函数的调用。
4. **`onEnter: function (args)`:**  在函数入口处执行的函数。`args` 数组包含了函数的参数。这里 `args[0]` 是 `HeapTaggingLevel` 枚举值。
5. **`args[0].toInt()`:** 将 Frida 的 NativePointer 对象转换为整数。
6. **`console.log(...)`:** 打印函数的参数和返回值，方便调试。
7. **`onLeave: function (retval)`:** 在函数返回时执行的函数。`retval` 是函数的返回值。

这个 Frida 脚本可以帮助开发者在运行时观察堆标记级别的设置情况，从而更好地理解系统的内存管理行为。可以通过类似的方法 hook 其他相关的函数，例如 `prctl` 调用，来深入分析堆标记的实现细节。

Prompt: 
```
这是目录为bionic/libc/bionic/heap_tagging.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "heap_tagging.h"
#include "malloc_common.h"
#include "malloc_tagged_pointers.h"

#include <bionic/pthread_internal.h>
#include <platform/bionic/malloc.h>
#include <sanitizer/hwasan_interface.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

extern "C" void scudo_malloc_disable_memory_tagging();
extern "C" void scudo_malloc_set_track_allocation_stacks(int);

extern "C" const char* __scudo_get_stack_depot_addr();
extern "C" const char* __scudo_get_ring_buffer_addr();
extern "C" size_t __scudo_get_ring_buffer_size();
extern "C" size_t __scudo_get_stack_depot_size();

// Protected by `g_heap_tagging_lock`.
static HeapTaggingLevel heap_tagging_level = M_HEAP_TAGGING_LEVEL_NONE;

void SetDefaultHeapTaggingLevel() {
#if defined(__aarch64__)
#if !__has_feature(hwaddress_sanitizer)
  heap_tagging_level = __libc_shared_globals()->initial_heap_tagging_level;
#endif

  __libc_memtag_stack_abi = __libc_shared_globals()->initial_memtag_stack_abi;

  __libc_globals.mutate([](libc_globals* globals) {
    switch (heap_tagging_level) {
      case M_HEAP_TAGGING_LEVEL_TBI:
        // Arrange for us to set pointer tags to POINTER_TAG, check tags on
        // deallocation and untag when passing pointers to the allocator.
        globals->heap_pointer_tag = (reinterpret_cast<uintptr_t>(POINTER_TAG) << TAG_SHIFT) |
                                    (0xffull << CHECK_SHIFT) | (0xffull << UNTAG_SHIFT);
        break;
      case M_HEAP_TAGGING_LEVEL_SYNC:
      case M_HEAP_TAGGING_LEVEL_ASYNC:
        atomic_store(&globals->memtag, true);
        atomic_store(&__libc_memtag_stack, __libc_shared_globals()->initial_memtag_stack);
        break;
      default:
        break;
    };
  });

#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
  switch (heap_tagging_level) {
    case M_HEAP_TAGGING_LEVEL_TBI:
    case M_HEAP_TAGGING_LEVEL_NONE:
      scudo_malloc_disable_memory_tagging();
      break;
    case M_HEAP_TAGGING_LEVEL_SYNC:
      scudo_malloc_set_track_allocation_stacks(1);
      break;
    default:
      break;
  }
#endif  // USE_SCUDO
#endif  // aarch64
}

static bool set_tcf_on_all_threads(int tcf) {
  return android_run_on_all_threads(
      [](void* arg) {
        int tcf = *reinterpret_cast<int*>(arg);
        int tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
        if (tagged_addr_ctrl < 0) {
          return false;
        }

        tagged_addr_ctrl = (tagged_addr_ctrl & ~PR_MTE_TCF_MASK) | tcf;
        return prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0) >= 0;
      },
      &tcf);
}

pthread_mutex_t g_heap_tagging_lock = PTHREAD_MUTEX_INITIALIZER;

// Requires `g_heap_tagging_lock` to be held.
bool SetHeapTaggingLevel(HeapTaggingLevel tag_level) {
  if (tag_level == heap_tagging_level) {
    return true;
  }

  switch (tag_level) {
    case M_HEAP_TAGGING_LEVEL_NONE:
      __libc_globals.mutate([](libc_globals* globals) {
        if (heap_tagging_level == M_HEAP_TAGGING_LEVEL_TBI) {
          // Preserve the untag mask (we still want to untag pointers when passing them to the
          // allocator), but clear the fixed tag and the check mask, so that pointers are no longer
          // tagged and checks no longer happen.
          globals->heap_pointer_tag = static_cast<uintptr_t>(0xffull << UNTAG_SHIFT);
        }
        atomic_store(&__libc_memtag_stack, false);
        atomic_store(&globals->memtag, false);
      });

      if (heap_tagging_level != M_HEAP_TAGGING_LEVEL_TBI) {
        if (!set_tcf_on_all_threads(PR_MTE_TCF_NONE)) {
          error_log("SetHeapTaggingLevel: set_tcf_on_all_threads failed");
          return false;
        }
      }
#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
      scudo_malloc_disable_memory_tagging();
#endif
      break;
    case M_HEAP_TAGGING_LEVEL_TBI:
    case M_HEAP_TAGGING_LEVEL_ASYNC:
    case M_HEAP_TAGGING_LEVEL_SYNC:
      if (heap_tagging_level == M_HEAP_TAGGING_LEVEL_NONE) {
#if !__has_feature(hwaddress_sanitizer)
        // Suppress the error message in HWASan builds. Apps can try to enable TBI (or even MTE
        // modes) being unaware of HWASan, fail them silently.
        error_log(
            "SetHeapTaggingLevel: re-enabling tagging after it was disabled is not supported");
#endif
        return false;
      } else if (tag_level == M_HEAP_TAGGING_LEVEL_TBI ||
                 heap_tagging_level == M_HEAP_TAGGING_LEVEL_TBI) {
        error_log("SetHeapTaggingLevel: switching between TBI and ASYNC/SYNC is not supported");
        return false;
      }

      if (tag_level == M_HEAP_TAGGING_LEVEL_ASYNC) {
        // When entering ASYNC mode, specify that we want to allow upgrading to SYNC by OR'ing in
        // the SYNC flag. But if the kernel doesn't support specifying multiple TCF modes, fall back
        // to specifying a single mode.
        if (!set_tcf_on_all_threads(PR_MTE_TCF_ASYNC | PR_MTE_TCF_SYNC)) {
          set_tcf_on_all_threads(PR_MTE_TCF_ASYNC);
        }
#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
        scudo_malloc_set_track_allocation_stacks(0);
#endif
      } else if (tag_level == M_HEAP_TAGGING_LEVEL_SYNC) {
        set_tcf_on_all_threads(PR_MTE_TCF_SYNC);
#if defined(USE_SCUDO) && !__has_feature(hwaddress_sanitizer)
        scudo_malloc_set_track_allocation_stacks(1);
        __libc_shared_globals()->scudo_ring_buffer = __scudo_get_ring_buffer_addr();
        __libc_shared_globals()->scudo_ring_buffer_size = __scudo_get_ring_buffer_size();
        __libc_shared_globals()->scudo_stack_depot = __scudo_get_stack_depot_addr();
        __libc_shared_globals()->scudo_stack_depot_size = __scudo_get_stack_depot_size();
#endif
      }
      break;
    default:
      error_log("SetHeapTaggingLevel: unknown tagging level");
      return false;
  }

  heap_tagging_level = tag_level;
  info_log("SetHeapTaggingLevel: tag level set to %d", tag_level);

  return true;
}

#ifdef __aarch64__
static inline __attribute__((no_sanitize("memtag"))) void untag_memory(void* from, void* to) {
  if (from == to) {
    return;
  }
  __asm__ __volatile__(
      ".arch_extension mte\n"
      "1:\n"
      "stg %[Ptr], [%[Ptr]], #16\n"
      "cmp %[Ptr], %[End]\n"
      "b.lt 1b\n"
      : [Ptr] "+&r"(from)
      : [End] "r"(to)
      : "memory");
}
#endif

#ifdef __aarch64__
// 128Mb of stack should be enough for anybody.
static constexpr size_t kUntagLimit = 128 * 1024 * 1024;
#endif  // __aarch64__

extern "C" __LIBC_HIDDEN__ __attribute__((no_sanitize("memtag"))) void memtag_handle_longjmp(
    void* sp_dst __unused, void* sp_src __unused) {
  // A usual longjmp looks like this, where sp_dst was the LR in the call to setlongjmp (i.e.
  // the SP of the frame calling setlongjmp).
  // ┌─────────────────────┐                  │
  // │                     │                  │
  // ├─────────────────────┤◄──────── sp_dst  │ stack
  // │         ...         │                  │ grows
  // ├─────────────────────┤                  │ to lower
  // │         ...         │                  │ addresses
  // ├─────────────────────┤◄──────── sp_src  │
  // │siglongjmp           │                  │
  // ├─────────────────────┤                  │
  // │memtag_handle_longjmp│                  │
  // └─────────────────────┘                  ▼
#ifdef __aarch64__
  if (atomic_load(&__libc_memtag_stack)) {
    size_t distance = reinterpret_cast<uintptr_t>(sp_dst) - reinterpret_cast<uintptr_t>(sp_src);
    if (distance > kUntagLimit) {
      async_safe_fatal(
          "memtag_handle_longjmp: stack adjustment too large! %p -> %p, distance %zx > %zx\n",
          sp_src, sp_dst, distance, kUntagLimit);
    } else {
      untag_memory(sp_src, sp_dst);
    }
  }
#endif  // __aarch64__

  // We can use __has_feature here rather than __hwasan_handle_longjmp as a
  // weak symbol because this is part of libc which is always sanitized for a
  // hwasan enabled process.
#if __has_feature(hwaddress_sanitizer)
  __hwasan_handle_longjmp(sp_dst);
#endif  // __has_feature(hwaddress_sanitizer)
}

"""

```