Response:
Let's break down the thought process for analyzing this C++ header file and generating the detailed explanation.

**1. Understanding the Goal:**

The core request is to analyze a C++ header file (`WriteProtected.handroid`) within the Android Bionic library. The focus is on understanding its functionality, its relation to Android, the implementation details of any involved libc functions, its interaction with the dynamic linker (if applicable), potential usage errors, and how it's reached within the Android ecosystem (framework/NDK). Finally, Frida hooking examples are needed.

**2. Initial Code Scan and Key Observations:**

* **`#pragma once`:** Standard header guard.
* **Includes:** `errno.h`, `string.h`, `sys/cdefs.h`, `sys/mman.h`, `sys/user.h`, `async_safe/log.h`,  `platform/bionic/macros.h`, `platform/bionic/page.h`. These immediately suggest interaction with low-level system calls, memory management, and potentially Android-specific features.
* **`WriteProtectedContents` Union:**  A union holding a value of type `T` and padding. The `__attribute__((aligned(max_android_page_size())))` is a major clue—it forces page alignment. The disallowed copy/assignment confirms it's designed for specific memory management.
* **`WriteProtected` Class Template:** This is the main actor. It holds a `WriteProtectedContents` instance. The `static_assert` confirms a size constraint. Disallowed copy/assignment again reinforces specific usage.
* **`initialize()`:** Sets the memory to zero and makes it read-only using `mprotect`.
* **`operator->()` and `operator*()`:**  Provide access to the underlying value.
* **`mutate()`:**  Temporarily makes the memory writable using `mprotect`, allows a function (`Mutator`) to modify the value, and then sets it back to read-only.
* **`contents_addr()`:** Returns the address of the contents. The inline assembly (`__asm__ __volatile__("" : "+r"(addr));`) is intriguing and suggests a compiler optimization workaround related to alignment.
* **`set_protection()`:** The core function using `mprotect` to change memory permissions. The `__has_feature(hwaddress_sanitizer)` check hints at dealing with tagged pointers, likely for memory safety.

**3. Deeper Analysis - Function by Function and Concept:**

* **`WriteProtectedContents`:**  The purpose of the union and the alignment becomes clear: to allocate a page-aligned block of memory, ensuring that the `value` resides within a page boundary. The padding ensures the entire page is used.
* **`WriteProtected` Class:** The class acts as a wrapper around the `WriteProtectedContents`, providing controlled access. The key idea is *write protection*.
* **`initialize()` and `set_protection()`:** The use of `mprotect` is central. This system call is the mechanism for changing the memory protection of a region. Understanding `PROT_READ` and `PROT_WRITE` is essential.
* **`mutate()`:** This is the *only* way to modify the protected data, enforcing a controlled mutation pattern.
* **Inline Assembly in `contents_addr()`:**  This warrants closer examination. The comment suggests it's preventing the compiler from making assumptions about alignment beyond the guaranteed minimum. This points to a potential optimization issue if the compiler incorrectly assumes a smaller alignment for the `contents` member.
* **Hardware Address Sanitizer (`hwaddress_sanitizer`):** Recognizing this feature helps understand the `untag_address` function's purpose. HWASan adds tags to pointers for memory safety debugging, and system calls might not expect tagged pointers.

**4. Connecting to Android:**

* **Bionic:** The file's location directly indicates its importance within Android's core C library.
* **Memory Safety:** The write protection mechanism strongly suggests a focus on memory safety and preventing accidental or malicious modifications of critical data.
* **Dynamic Linker:**  While the code itself doesn't directly interact with the dynamic linker, the concept of protecting data is relevant to the linker's internal structures. The linker itself might use similar techniques to protect its own metadata.
* **Framework/NDK:**  The question of *how* this code is reached requires thinking about higher-level Android components that need to store and protect data. System services, core libraries, or even parts of the ART runtime could use this.

**5. Predicting Usage and Errors:**

* **Common Mistakes:**  Trying to directly assign to or modify the protected data without using `mutate` would be a primary error. Initializing multiple times is also flagged in the code.

**6. Crafting the Explanation:**

* **Structure:** Organize the explanation logically: introduction, function-by-function breakdown, Android relevance, dynamic linker connections, usage errors, and finally, the Frida hooking example.
* **Clarity:** Use clear and concise language. Define technical terms like `mprotect`, `PROT_READ`, `PROT_WRITE`, and page alignment.
* **Examples:**  Provide concrete examples (even if hypothetical) to illustrate the concepts and potential errors.
* **Dynamic Linker Example:**  While the code doesn't directly manipulate the linker, create a plausible scenario where the linker might use such a mechanism for its internal data structures. The SO layout and linking process description should be simplified but accurate.
* **Frida Example:**  Choose relevant functions to hook (like `initialize` and `mutate`) to demonstrate the behavior of the `WriteProtected` class.
* **Assumptions and Reasoning:** Explicitly state any assumptions made (like the linker example being hypothetical).

**7. Review and Refinement:**

* **Accuracy:** Double-check the explanations of `mprotect`, the inline assembly, and the HWASan part.
* **Completeness:** Ensure all aspects of the prompt are addressed.
* **Readability:**  Make sure the explanation is easy to understand, even for someone with some, but not necessarily expert, knowledge of C++ and operating systems.

By following this methodical approach, starting with a high-level understanding and then diving into the details, it's possible to construct a comprehensive and accurate explanation of the provided C++ header file. The key is to connect the individual code elements to the broader context of the Android operating system and its security mechanisms.
好的，我们来详细分析一下 `bionic/libc/private/WriteProtected.handroid` 这个头文件。

**文件功能总览:**

这个头文件定义了一个名为 `WriteProtected` 的 C++ 模板类。这个类的主要功能是提供一种机制来**安全地存储和访问数据，确保数据在正常情况下是只读的，只能通过特定的 `mutate` 方法进行修改**。它通过利用操作系统提供的内存保护机制（`mprotect` 系统调用）来实现这一目标。

**具体功能分解:**

1. **`WriteProtectedContents` Union:**
   -  这是一个联合体，包含一个类型为 `T` 的成员 `value` 和一个 `padding` 数组。
   -  `padding` 数组的大小被设置为 `max_android_page_size()`，这意味着联合体的大小将至少是一个页面的大小（通常是 4KB 或 64KB，取决于架构）。
   -  `__attribute__((aligned(max_android_page_size())))`：这是一个 GCC 扩展属性，强制该联合体的实例在内存中按照页面大小对齐。这对于 `mprotect` 系统调用至关重要，因为 `mprotect` 只能操作以页为单位的内存区域。
   -  `BIONIC_DISALLOW_COPY_AND_ASSIGN(WriteProtectedContents)`：这是一个宏，通常用于禁用类的拷贝构造函数和拷贝赋值运算符。这表明 `WriteProtectedContents` 实例不应该被复制，以避免多个实例指向同一块受保护的内存区域。

2. **`WriteProtected` Class Template:**
   -  这是一个模板类，可以用于保护任意类型 `T` 的数据。
   -  `static_assert(sizeof(T) < max_android_page_size(), ...)`：这是一个静态断言，用于在编译时检查要保护的数据类型 `T` 的大小是否小于一个页面的大小。这是因为整个页面都会被设置为相同的保护属性。
   -  **`initialize()`:**
     -  使用 `memset` 将 `contents` 内存区域初始化为零。虽然不是严格必需，但可以帮助检测意外的多次初始化。
     -  调用 `set_protection(PROT_READ)` 将内存区域设置为只读。`PROT_READ` 是 `mprotect` 系统调用中的一个标志，表示允许读取。
   -  **`operator->()`:**
     -  重载了指针运算符 `->`，允许像访问结构体指针一样访问受保护的 `value` 成员。
     -  返回指向 `contents_addr()->value` 的指针。
   -  **`operator*()`:**
     -  重载了解引用运算符 `*`，允许像访问结构体引用一样访问受保护的 `value` 成员。
     -  返回 `contents_addr()->value` 的引用。
   -  **`mutate(Mutator mutator)`:**
     -  这是修改受保护数据的唯一入口点。
     -  `set_protection(PROT_READ | PROT_WRITE)`：首先，将内存区域设置为可读写。`PROT_WRITE` 是 `mprotect` 系统调用中的一个标志，表示允许写入。
     -  `mutator(&contents_addr()->value)`：调用传入的 `Mutator` 函数对象（通常是一个 lambda 表达式或函数指针），并将指向受保护 `value` 的指针传递给它。`Mutator` 负责执行实际的修改操作。
     -  `set_protection(PROT_READ)`：修改完成后，立即将内存区域恢复为只读。
   -  **`contents`:**
     -  `WriteProtectedContents<T> contents;`：这是存储实际受保护数据的成员变量。
   -  **`contents_addr()`:**
     -  返回指向 `contents` 成员的指针。
     -  `__asm__ __volatile__("" : "+r"(addr));`：这段内联汇编代码的作用是防止编译器过度优化。它指示编译器不要假设 `addr` 的对齐方式，即使 `contents` 成员保证了页面对齐。如果不这样做，编译器可能会生成假设 64KB 对齐的代码，即使变量只保证了 4KB 对齐。这在某些情况下可能会导致问题。
   -  **`set_protection(int prot)`:**
     -  这是设置内存保护属性的核心函数。
     -  `auto addr = contents_addr();`：获取 `contents` 的地址。
     -  `#if __has_feature(hwaddress_sanitizer)` ... `#endif`：这部分代码是针对启用了硬件地址消毒器 (HWAddress Sanitizer, HWASan) 的情况。HWASan 会给指针打标签以进行内存安全检查。`mprotect` 系统调用可能不处理这些标签，因此需要使用 `untag_address` 函数移除标签。
     -  `if (mprotect(reinterpret_cast<void*>(addr), max_android_page_size(), prot) == -1)`：调用 `mprotect` 系统调用。
        -  `reinterpret_cast<void*>(addr)`：将 `contents` 的地址转换为 `void*`，`mprotect` 接受 `void*` 类型的地址。
        -  `max_android_page_size()`：指定要修改保护属性的内存区域的大小，即一个页面的大小。
        -  `prot`：指定新的内存保护属性（例如 `PROT_READ` 或 `PROT_READ | PROT_WRITE`）。
        -  如果 `mprotect` 调用失败（返回 -1），则调用 `async_safe_fatal` 函数记录错误并终止程序。`strerror(errno)` 用于获取错误码对应的错误信息。

**与 Android 功能的关系及举例:**

`WriteProtected` 类是 Bionic 库的一部分，而 Bionic 是 Android 的核心 C 库。这种写保护机制在 Android 中有多种应用场景，主要用于提高系统的稳定性和安全性：

1. **保护关键数据结构:** Android 框架或运行时系统可能使用 `WriteProtected` 来保护其内部的关键数据结构，防止意外或恶意修改导致系统崩溃或安全漏洞。

   **举例:** 假设 Android 的某个系统服务需要维护一个配置信息，这个配置信息很少更改，但对系统的正常运行至关重要。可以使用 `WriteProtected` 来保护这个配置信息，确保只有授权的代码才能修改它。

   ```c++
   // 假设的配置结构体
   struct SystemConfig {
       int max_connections;
       bool logging_enabled;
   };

   WriteProtected<SystemConfig> g_system_config;

   void initialize_config() {
       g_system_config.initialize();
       g_system_config.mutate([](SystemConfig* config) {
           config->max_connections = 100;
           config->logging_enabled = true;
       });
   }

   void print_config() {
       ALOGI("Max connections: %d", g_system_config->max_connections);
       ALOGI("Logging enabled: %s", g_system_config->logging_enabled ? "true" : "false");
   }

   void update_config(int new_max_connections) {
       g_system_config.mutate([new_max_connections](SystemConfig* config) {
           config->max_connections = new_max_connections;
       });
   }
   ```

2. **防止竞态条件:** 在多线程环境下，对共享数据的并发访问可能导致竞态条件。使用 `WriteProtected` 可以限制对共享数据的修改，并强制使用 `mutate` 方法，这可以作为一种粗粒度的同步机制，确保数据在修改时具有原子性。

3. **增强安全性:** 通过将敏感数据标记为只读，可以防止潜在的缓冲区溢出或其他写入漏洞意外修改这些数据。即使攻击者能够控制程序中的某些指针，他们也无法直接修改受 `WriteProtected` 保护的内存区域。

**libc 函数的实现:**

1. **`memset(void* s, int c, size_t n)`:**
   -  `memset` 是 C 标准库中的函数，用于将一段内存区域设置为指定的值。
   -  它通常由汇编语言或高度优化的 C 代码实现，直接操作内存地址，将从 `s` 开始的 `n` 个字节设置为字符 `c` 的值。

2. **`mprotect(void* addr, size_t len, int prot)`:**
   -  `mprotect` 是 POSIX 标准中定义的系统调用，用于修改调用进程的虚拟地址空间中页面的访问权限。
   -  **实现原理:** 当进程调用 `mprotect` 时，内核会检查指定的内存区域（从 `addr` 开始的 `len` 字节，必须是页对齐和页大小的整数倍）是否属于该进程的地址空间。
   -  如果有效，内核会更新页表项中与这些页面对应的权限位。页表是操作系统用于管理虚拟地址到物理地址映射的数据结构。
   -  `prot` 参数是一个位掩码，用于指定新的保护属性，例如：
     -  `PROT_READ`: 允许读取。
     -  `PROT_WRITE`: 允许写入。
     -  `PROT_EXEC`: 允许执行。
     -  `PROT_NONE`: 禁止访问。
   -  当程序尝试以不符合页表项中权限的方式访问内存时（例如，尝试写入只读页面），CPU 的内存管理单元 (MMU) 会触发一个异常（通常是 `SIGSEGV` 信号），操作系统会捕获这个异常并采取相应的措施，通常是终止程序。

3. **`strerror(int errnum)`:**
   -  `strerror` 也是 C 标准库中的函数，用于将给定的错误码 `errnum` 转换为对应的错误描述字符串。
   -  它通常维护一个错误码到错误消息的映射表。当调用 `strerror` 时，它会查找与 `errnum` 匹配的错误消息并返回指向该消息的指针。

**dynamic linker 的功能及 SO 布局样本和链接过程:**

虽然 `WriteProtected.handroid` 本身不直接涉及 dynamic linker 的功能，但 dynamic linker 在加载和链接共享库时，也可能需要保护其内部的一些关键数据结构，以防止被恶意修改。

**SO 布局样本:**

```
加载地址: 0xb4000000

.text   (代码段, 可读可执行)   : 0xb4001000 - 0xb4005000
.rodata (只读数据段)        : 0xb4005000 - 0xb4007000
.data   (可读写数据段)      : 0xb4007000 - 0xb4008000
.bss    (未初始化数据段)    : 0xb4008000 - 0xb4009000
```

**链接的处理过程 (简化描述):**

1. **加载共享库:** 当程序需要使用一个共享库时，操作系统会调用 dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。Dynamic linker 将共享库的代码和数据段加载到内存中的某个地址空间。
2. **符号解析:**  共享库中可能包含对其他共享库或可执行文件中定义的符号的引用（例如函数调用或全局变量访问）。Dynamic linker 需要找到这些符号的定义位置。
3. **重定位:** 由于共享库被加载到内存的哪个地址是不确定的（地址空间布局随机化 ASLR），因此共享库中的一些地址（例如全局变量的地址）需要在加载时进行调整。这个过程称为重定位。Dynamic linker 会修改代码和数据段中的地址，使其指向正确的内存位置。
4. **绑定:**  在重定位之后，对外部符号的引用需要被绑定到实际的内存地址。这通常发生在程序首次调用到共享库的函数时（延迟绑定）。
5. **初始化:**  共享库可能包含一些初始化代码（例如全局对象的构造函数）。Dynamic linker 会在完成链接后执行这些初始化代码。

**Dynamic Linker 与 `WriteProtected` 的潜在联系 (假设):**

Dynamic linker 可能会使用类似 `WriteProtected` 的机制来保护其内部的数据结构，例如：

- **已加载的共享库列表:** 维护当前已加载的共享库的信息。
- **符号表:** 存储已解析的符号及其地址。
- **重定位表:** 记录需要进行重定位的条目。

使用写保护可以防止恶意代码篡改这些关键数据，例如修改已加载的共享库列表，从而劫持函数调用或执行恶意代码。

**假设输入与输出 (逻辑推理):**

假设我们使用 `WriteProtected` 保护一个整数变量：

**假设输入:**

```c++
WriteProtected<int> protected_int;
protected_int.initialize(); // 初始化并设置为只读

// 尝试直接修改 (这会触发错误)
//*protected_int = 10; // 编译错误，因为 operator* 返回的是 const 引用

// 使用 mutate 方法修改
protected_int.mutate([](int* value) {
    *value = 10;
});

int value = *protected_int; // 读取值
```

**输出:**

- 尝试直接修改会导致编译错误，因为 `operator*` 返回的是 `const T&`，不允许修改。
- 使用 `mutate` 方法可以成功修改 `protected_int` 的值。
- `value` 将被赋值为 10。

**用户或编程常见的使用错误:**

1. **直接修改受保护的数据:**  这是最常见的错误。由于 `operator->` 和 `operator*` 返回的是 `const T*` 和 `const T&`，直接尝试通过这些操作符修改数据会导致编译错误。

   ```c++
   WriteProtected<int> protected_value;
   protected_value.initialize();

   // 错误：编译失败，尝试修改 const int&
   //*protected_value = 5;

   // 错误：编译失败，尝试修改 const int*
   //*protected_value.operator->() = 5;
   ```

2. **忘记调用 `mutate` 进行修改:**  如果不使用 `mutate` 方法，就无法修改受保护的数据。

   ```c++
   WriteProtected<int> protected_value;
   protected_value.initialize();

   // 错误：无法修改
   // int* ptr = const_cast<int*>(&(*protected_value)); // 即使尝试使用 const_cast 绕过，在运行时也会因为内存保护而崩溃
   // *ptr = 5;
   ```

3. **在 `mutate` 回调函数之外尝试持有指向受保护数据的指针:**  `mutate` 方法执行完毕后，内存会立即恢复为只读。如果在 `mutate` 调用期间获取了指向受保护数据的指针，并在 `mutate` 调用结束后尝试通过该指针修改数据，将会触发内存保护错误。

   ```c++
   WriteProtected<int> protected_value;
   protected_value.initialize();
   int* ptr = nullptr;

   protected_value.mutate([&ptr](int* value) {
       ptr = value; // 获取指向 value 的指针
       *ptr = 10;   // 在 mutate 内部修改是允许的
   });

   // 错误：在 mutate 外部通过 ptr 修改会导致运行时崩溃 (SIGSEGV)
   // *ptr = 20;
   ```

4. **多次初始化:** 虽然 `initialize` 方法内部有 `memset` 操作，但多次调用 `initialize` 可能会导致意外的重置。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例:**

要追踪 Android Framework 或 NDK 如何使用 `WriteProtected`，需要进行更深入的源码分析和调试。这里提供一个思路和 Frida Hook 示例：

**思路:**

1. **识别潜在的使用场景:**  在 Android Framework 的关键组件（例如 SystemServer、各种系统服务）或 NDK 库中，查找可能需要保护其内部状态或配置信息的地方。搜索包含 `WriteProtected` 关键字的源码。
2. **使用源码交叉引用工具:** 利用 IDE 或在线代码搜索工具（如 Android Code Search）查找 `WriteProtected` 的使用位置。
3. **运行时调试:** 使用调试器（例如 GDB）或日志记录来跟踪程序的执行流程，观察何时以及如何访问受 `WriteProtected` 保护的数据。

**Frida Hook 示例:**

假设我们想观察某个使用了 `WriteProtected<int>` 的全局变量 `g_protected_counter` 的初始化和修改过程。

**C++ 代码 (假设):**

```c++
// 某个全局变量
WriteProtected<int> g_protected_counter;

void some_function() {
    g_protected_counter.initialize();
    ALOGI("Initial counter value: %d", *g_protected_counter);

    // 稍后修改
    g_protected_counter.mutate([](int* value) {
        (*value)++;
        (*value)++;
    });
    ALOGI("Updated counter value: %d", *g_protected_counter);
}
```

**Frida Hook 脚本 (JavaScript):**

```javascript
rpc.exports = {
  hookWriteProtected: function() {
    const WriteProtectedInitialize = Module.findExportByName(null, "_ZN14WriteProtectedIiE10initializeEv"); // 替换为实际的符号
    const WriteProtectedMutate = Module.findExportByName(null, "_ZN14WriteProtectedIiE6mutateIRAFviEEvT_"); // 替换为实际的符号

    if (WriteProtectedInitialize) {
      Interceptor.attach(WriteProtectedInitialize, {
        onEnter: function(args) {
          console.log("[+] WriteProtected<int>::initialize() called");
        }
      });
    } else {
      console.log("[-] WriteProtected<int>::initialize() not found");
    }

    if (WriteProtectedMutate) {
      Interceptor.attach(WriteProtectedMutate, {
        onEnter: function(args) {
          console.log("[+] WriteProtected<int>::mutate() called");
        },
        onLeave: function(retval) {
          console.log("[+] WriteProtected<int>::mutate() finished");
        }
      });
    } else {
      console.log("[-] WriteProtected<int>::mutate() not found");
    }
  }
};
```

**使用方法:**

1. 将 Frida Hook 脚本保存为 `.js` 文件（例如 `hook_writeprotected.js`）。
2. 运行 Android 应用或进程。
3. 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l hook_writeprotected.js --no-pause` 或 `frida -p <process_id> -l hook_writeprotected.js`.
4. 在 Frida 控制台中调用 `rpc.exports.hookWriteProtected()`。

**Frida Hook 说明:**

- `Module.findExportByName(null, "_ZN14WriteProtectedIiE10initializeEv")`: 尝试查找 `WriteProtected<int>::initialize()` 函数的符号。你需要根据实际的编译结果调整符号名称（可以使用 `adb shell "grep WriteProtected.*initialize /proc/<pid>/maps"` 等命令辅助查找）。
- `Interceptor.attach()`: 用于拦截函数的调用。
- `onEnter`: 在函数入口处执行的代码。
- `onLeave`: 在函数退出时执行的代码。
- 通过 Hook `initialize` 和 `mutate` 方法，可以观察到何时创建并初始化了受保护的变量，以及何时进行了修改。

要 Hook 更具体的场景，例如访问 `g_protected_counter` 的值，可能需要 Hook `operator*` 或直接读取内存。这需要更深入的分析和对目标代码的理解。

希望以上详细的分析和示例能够帮助你理解 `bionic/libc/private/WriteProtected.handroid` 的功能和在 Android 中的应用。

Prompt: 
```
这是目录为bionic/libc/private/WriteProtected.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

#include <errno.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <async_safe/log.h>

#include "platform/bionic/macros.h"
#include "platform/bionic/page.h"

template <typename T>
union WriteProtectedContents {
  T value;
  char padding[max_android_page_size()];

  WriteProtectedContents() = default;
  BIONIC_DISALLOW_COPY_AND_ASSIGN(WriteProtectedContents);
} __attribute__((aligned(max_android_page_size())));

// Write protected wrapper class that aligns its contents to a page boundary,
// and sets the memory protection to be non-writable, except when being modified
// explicitly.
template <typename T>
class WriteProtected {
 public:
  static_assert(sizeof(T) < max_android_page_size(),
                "WriteProtected only supports contents up to max_android_page_size()");

  WriteProtected() = default;
  BIONIC_DISALLOW_COPY_AND_ASSIGN(WriteProtected);

  void initialize() {
    // Not strictly necessary, but this will hopefully segfault if we initialize
    // multiple times by accident.
    memset(contents_addr(), 0, sizeof(contents));
    set_protection(PROT_READ);
  }

  const T* operator->() {
    return &contents_addr()->value;
  }

  const T& operator*() {
    return contents_addr()->value;
  }

  template <typename Mutator>
  void mutate(Mutator mutator) {
    set_protection(PROT_READ | PROT_WRITE);
    mutator(&contents_addr()->value);
    set_protection(PROT_READ);
  }

 private:
  WriteProtectedContents<T> contents;

  WriteProtectedContents<T>* contents_addr() {
    auto addr = &contents;
    // Hide the fact that we're returning the address of contents from the compiler.
    // Otherwise it may generate code assuming alignment of 64KB even though the
    // variable is only guaranteed to have 4KB alignment.
    __asm__ __volatile__("" : "+r"(addr));
    return addr;
  }

  void set_protection(int prot) {
    auto addr = contents_addr();
#if __has_feature(hwaddress_sanitizer)
    // The mprotect system call does not currently untag pointers, so do it
    // ourselves.
    addr = untag_address(addr);
#endif
    if (mprotect(reinterpret_cast<void*>(addr), max_android_page_size(), prot) == -1) {
      async_safe_fatal("WriteProtected mprotect %x failed: %s", prot, strerror(errno));
    }
  }
};

"""

```