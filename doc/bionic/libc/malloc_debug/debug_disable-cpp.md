Response:
Let's break down the thought process to generate the comprehensive answer for the `debug_disable.cpp` file.

**1. Understanding the Request:**

The request asks for a detailed analysis of a specific C++ source file within Android's Bionic library. Key requirements include:

* **Functionality:** What does the code do?
* **Android Relevance:** How does this relate to Android's operation?
* **Libc Function Details:**  Explain the implementation of used libc functions.
* **Dynamic Linking:** Address any dynamic linker aspects (although this file doesn't directly involve it, it's a standard request when analyzing Bionic code, so it needs to be considered).
* **Logic/Assumptions:**  Analyze the control flow and potential inputs/outputs.
* **Common Errors:**  Identify potential usage issues.
* **Android Integration:** Explain how the code is reached from higher levels (framework/NDK).
* **Frida Hooking:** Provide a practical debugging example.

**2. Initial Code Analysis (Skimming and Keyword Spotting):**

* **Includes:**  `pthread.h`, "DebugData.h", "debug_disable.h", "debug_log.h". This immediately suggests the code deals with thread-local storage (pthreads) and some kind of debugging mechanism.
* **Global Variable:** `pthread_key_t g_disable_key;`. Confirms the use of thread-local storage.
* **Functions:** `DebugCallsDisabled()`, `DebugDisableInitialize()`, `DebugDisableFinalize()`, `DebugDisableSet()`. These names are very descriptive and hint at the module's purpose: enabling/disabling debug calls.

**3. Deeper Dive into Each Function:**

* **`DebugCallsDisabled()`:**
    * Checks if `g_debug` is null OR if a thread-specific value is set for `g_disable_key`.
    * Returns `true` if debugging is disabled, `false` otherwise.
    * *Inference:* The `g_debug` global (likely defined elsewhere) acts as a global on/off switch for debugging. The thread-specific check allows for disabling debugging on a per-thread basis.

* **`DebugDisableInitialize()`:**
    * Calls `pthread_key_create()` to create a thread-local storage key.
    * Calls `pthread_setspecific()` to initialize the thread-specific value to `nullptr`.
    * *Inference:* This function sets up the thread-local storage mechanism. The initialization to `nullptr` means debugging is initially enabled for all threads.

* **`DebugDisableFinalize()`:**
    * Calls `pthread_key_delete()` to clean up the thread-local storage key.
    * *Inference:*  Releases the resources allocated in `DebugDisableInitialize()`. Good practice for resource management.

* **`DebugDisableSet(bool disable)`:**
    * If `disable` is `true`, sets the thread-specific value to `reinterpret_cast<void*>(1)`.
    * If `disable` is `false`, sets the thread-specific value to `nullptr`.
    * *Inference:* This function provides the mechanism to enable or disable debugging for the current thread. The choice of `1` and `nullptr` is arbitrary but serves as a flag.

**4. Connecting to Android Functionality:**

* **Memory Allocation Debugging:** The file is located in `bionic/libc/malloc_debug/`. This strongly suggests it's related to debugging memory allocation within the C library.
* **Per-Thread Control:** The use of pthreads enables fine-grained control over debugging, potentially useful for isolating issues in multithreaded applications.

**5. Explaining Libc Functions:**

* **`pthread_key_create()`:** Explained its purpose: creating a thread-local storage key and its parameters (key pointer, destructor). Crucial to explain the concept of thread-local storage.
* **`pthread_getspecific()`:** Explained how it retrieves the thread-specific value associated with a key.
* **`pthread_setspecific()`:** Explained how it sets the thread-specific value associated with a key.
* **`pthread_key_delete()`:** Explained how it destroys a thread-local storage key and potentially calls the destructor.
* **`strerror()`:** Briefly explained its purpose: converting an error number to a human-readable string.

**6. Addressing Dynamic Linking (Even if not directly relevant):**

Although this specific file doesn't directly manipulate the dynamic linker, it's part of Bionic, which heavily relies on dynamic linking. So, a standard explanation of SO layout and the linking process is necessary to provide context.

**7. Logic, Assumptions, and Input/Output:**

* **Assumptions:** The existence of a global `g_debug` variable controlling global debugging.
* **Input/Output:** Focused on the `DebugDisableSet()` function and how it affects `DebugCallsDisabled()`.

**8. Common Errors:**

Focused on the misuse of thread-local storage, specifically the risk of resource leaks if `pthread_key_delete()` is not called.

**9. Android Framework/NDK Integration:**

This is where higher-level understanding is crucial.

* **Framework:** Explained how the Android framework, through system services and native libraries, eventually calls into Bionic functions. Mentioned the possibility of system properties influencing debugging.
* **NDK:** Explained how NDK developers directly use Bionic functions, potentially including those related to memory allocation, which might trigger these debugging mechanisms.

**10. Frida Hooking Example:**

Designed a practical Frida script targeting the `DebugCallsDisabled` and `DebugDisableSet` functions to demonstrate how to observe and manipulate their behavior. Included clear comments and explanations of the Frida API used.

**11. Structure and Language:**

* **Use clear headings and bullet points** to organize the information.
* **Explain technical terms** like "thread-local storage" and "dynamic linker" clearly.
* **Provide code snippets** where relevant (Frida script).
* **Use Chinese as requested.**
* **Review and refine** for clarity and accuracy.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe this file is directly involved in turning on/off malloc debugging globally.
* **Correction:** The use of `pthread_key_t` clearly indicates *thread-local* control, not global. This significantly refines the understanding of the functionality.
* **Realization:**  The dynamic linker aspect isn't directly present in this code, but it's essential background for understanding Bionic. So, include a general explanation.
* **Emphasis:**  Highlight the importance of resource management when using pthreads (calling `pthread_key_delete`).

By following this structured approach, breaking down the code, connecting it to broader Android concepts, and anticipating the different aspects of the request, a comprehensive and accurate answer can be generated.
这个文件 `bionic/libc/malloc_debug/debug_disable.cpp` 的主要功能是提供一种**按线程禁用内存分配调试**的机制。 换句话说，它允许在某些特定的线程中临时关闭内存分配的调试功能，而在其他线程中仍然保持启用。

下面是对其功能的详细解释：

**核心功能:**

1. **线程局部存储 (Thread-Local Storage):**  它利用 POSIX 线程库中的线程局部存储（TLS）机制来实现按线程的控制。 具体来说，它使用了一个全局的 `pthread_key_t` 类型的变量 `g_disable_key`。这个键可以用来在每个线程中存储一个特定的值。

2. **禁用状态指示:**  每个线程可以通过 `g_disable_key` 关联一个值来指示是否禁用了调试功能。 如果一个线程与 `g_disable_key` 关联的值不是 `nullptr`，则认为该线程的调试功能被禁用。

3. **查询禁用状态 (`DebugCallsDisabled()`):**  `DebugCallsDisabled()` 函数用于查询当前线程是否禁用了调试功能。它会检查两个条件：
    * `g_debug == nullptr`:  这可能是全局的调试开关，如果 `g_debug` 为空，则表示全局调试被禁用。
    * `pthread_getspecific(g_disable_key) != nullptr`:  如果当前线程通过 `g_disable_key` 关联了一个非空的值，则表示该线程禁用了调试。
    只要满足其中一个条件，该函数就返回 `true`，表示调试被禁用。

4. **初始化 (`DebugDisableInitialize()`):**  `DebugDisableInitialize()` 函数负责初始化线程局部存储的键 `g_disable_key`。它调用 `pthread_key_create()` 创建一个新的键。 初始状态下，所有线程与这个键关联的值都是 `nullptr`，意味着调试功能默认是启用的。

5. **清理 (`DebugDisableFinalize()`):**  `DebugDisableFinalize()` 函数用于清理 `g_disable_key` 占用的资源，调用 `pthread_key_delete()` 销毁该键。 这通常在程序退出时调用。

6. **设置禁用状态 (`DebugDisableSet()`):**  `DebugDisableSet()` 函数允许设置当前线程的调试禁用状态。
    * 如果传入 `disable` 为 `true`，则调用 `pthread_setspecific(g_disable_key, reinterpret_cast<void*>(1))`，将当前线程与 `g_disable_key` 关联的值设置为非空（这里是 `1`）。这表示在该线程中禁用调试。
    * 如果传入 `disable` 为 `false`，则调用 `pthread_setspecific(g_disable_key, nullptr)`，将当前线程与 `g_disable_key` 关联的值设置为 `nullptr`。这表示在该线程中启用调试。

**与 Android 功能的关系及举例说明:**

这个文件是 Android Bionic 库的一部分，而 Bionic 是 Android 系统底层的 C 库，提供了诸如内存分配、线程管理等核心功能。 `debug_disable.cpp` 所在的 `malloc_debug` 目录表明它与内存分配的调试功能相关。

**示例：**

假设 Android 系统在进行内存分配时，如果启用了调试功能，可能会进行额外的检查，例如检测内存泄漏、double free 等错误。  在某些特定的场景下，为了性能考虑或者避免某些已知的问题，可能需要在特定的线程中临时关闭这些调试检查。

例如，在处理图形渲染的线程中，频繁的内存操作可能对性能非常敏感。  在这种情况下，Android 系统可能会调用 `DebugDisableSet(true)` 来禁用该线程的内存分配调试，以提高渲染效率。  当该线程完成其关键任务后，可能会调用 `DebugDisableSet(false)` 重新启用调试。

**详细解释 libc 函数的功能实现:**

* **`pthread_key_create(pthread_key_t *key, void (*destructor)(void*))`:**
    * **功能:** 创建一个线程局部存储的键。每个线程可以使用这个键来关联一个特定的值。
    * **实现:**  操作系统会分配一个唯一的标识符给新的键，并将其存储在 `key` 指向的内存位置。 `destructor` 是一个可选的函数指针，当一个线程退出并且其关联的键值非空时，系统会调用这个析构函数来释放资源。 在 `DebugDisableInitialize` 中，析构函数被设置为 `nullptr`，意味着不需要额外的清理操作。
    * **假设输入与输出:**
        * **输入:**  `key` 指向未初始化的 `pthread_key_t` 变量的地址， `destructor` 为 `nullptr`。
        * **输出:**  如果成功，`key` 指向的变量会被赋值为一个新创建的键的标识符，函数返回 0。 如果失败（例如，达到系统限制），则返回一个非零的错误码。

* **`pthread_getspecific(pthread_key_t key)`:**
    * **功能:** 获取当前线程与指定键关联的值。
    * **实现:**  操作系统会维护一个数据结构，用于存储每个线程与每个键关联的值。 `pthread_getspecific` 会查找当前线程和给定键的对应关系，并返回存储的值。
    * **假设输入与输出:**
        * **输入:**  一个已经创建的 `pthread_key_t` 键。
        * **输出:**  返回当前线程与该键关联的值。 如果当前线程没有与该键关联任何值，则返回 `nullptr`。

* **`pthread_setspecific(pthread_key_t key, const void *value)`:**
    * **功能:** 设置当前线程与指定键关联的值。
    * **实现:**  操作系统会更新内部数据结构，将当前线程与给定键关联的值设置为 `value`。
    * **假设输入与输出:**
        * **输入:**  一个已经创建的 `pthread_key_t` 键和一个要关联的值 `value`。
        * **输出:**  如果成功，返回 0。 如果失败（例如，键无效），则返回一个非零的错误码。

* **`pthread_key_delete(pthread_key_t key)`:**
    * **功能:** 删除一个线程局部存储的键。
    * **实现:**  操作系统会释放与该键相关的资源。  如果存在已创建但尚未退出的线程且其与该键关联的值非空，并且在 `pthread_key_create` 时指定了析构函数，则系统会为这些线程调用析构函数。 在 `debug_disable.cpp` 中，析构函数为 `nullptr`，所以这里主要就是释放键本身占用的资源。
    * **假设输入与输出:**
        * **输入:**  一个要删除的 `pthread_key_t` 键。
        * **输出:**  如果成功，返回 0。 如果失败（例如，键无效），则返回一个非零的错误码。

* **`strerror(int errnum)`:**
    * **功能:** 将错误码转换为对应的错误信息字符串。
    * **实现:**  libc 维护一个错误码到错误消息的映射表。 `strerror` 根据传入的错误码 `errnum` 在表中查找对应的错误消息，并返回指向该消息字符串的指针。
    * **假设输入与输出:**
        * **输入:**  一个表示错误码的整数，例如 `errno` 的值。
        * **输出:**  返回一个指向描述该错误的字符串的指针。

**涉及 dynamic linker 的功能:**

这个文件本身并没有直接涉及 dynamic linker 的功能。 它主要依赖于 POSIX 线程库 (pthread)，而 pthread 通常是作为 libc 的一部分提供的。

**SO 布局样本及链接的处理过程（通常与动态库相关，这里关联不大）：**

由于此文件不直接涉及 dynamic linker，这里只做一个简要说明，以便理解 Android 中动态库的运作方式。

假设有一个动态库 `libexample.so`，它的布局可能如下：

```
libexample.so:
    .text      (代码段)
    .rodata    (只读数据段，例如字符串常量)
    .data      (已初始化的全局变量)
    .bss       (未初始化的全局变量)
    .dynsym    (动态符号表，包含导出的符号)
    .dynstr    (动态字符串表，包含符号名)
    .plt       (过程链接表，用于延迟绑定)
    .got       (全局偏移表，用于访问全局变量和函数)
    ...
```

**链接处理过程：**

1. **加载：** 当 Android 系统需要使用 `libexample.so` 中的代码时，dynamic linker (通常是 `linker64` 或 `linker`) 会将该 SO 文件加载到内存中。
2. **符号解析：** 如果 `libexample.so` 依赖于其他动态库，dynamic linker 会递归加载这些依赖。 然后，它会解析 SO 文件中引用的外部符号（函数和全局变量），在依赖库中找到这些符号的地址。
3. **重定位：**  由于动态库加载到内存的地址可能不是编译时的地址，dynamic linker 需要修改代码和数据段中的地址，使其指向正确的内存位置。  GOT 和 PLT 表在此过程中起关键作用。
4. **绑定：**  对于延迟绑定的符号，在第一次调用时，PLT 中的代码会跳转到 dynamic linker，dynamic linker 会解析符号并更新 GOT 表，后续调用将直接通过 GOT 表跳转到目标地址。

**逻辑推理、假设输入与输出:**

**函数：`DebugCallsDisabled()`**

* **假设输入 1:** `g_debug` 指向非空内存，当前线程没有通过 `DebugDisableSet(true)` 设置禁用。
* **预期输出 1:** `false` (调试未禁用)

* **假设输入 2:** `g_debug` 为 `nullptr`。
* **预期输出 2:** `true` (全局调试已禁用)

* **假设输入 3:** `g_debug` 指向非空内存，当前线程之前调用过 `DebugDisableSet(true)`。
* **预期输出 3:** `true` (当前线程已禁用调试)

**函数：`DebugDisableSet(bool disable)`**

* **假设输入 1:** `disable` 为 `true`。
* **预期输出 1:**  调用后，在当前线程中调用 `DebugCallsDisabled()` 将返回 `true`。

* **假设输入 2:** `disable` 为 `false`。
* **预期输出 2:** 调用后，在当前线程中调用 `DebugCallsDisabled()` 将返回 `false` (除非 `g_debug` 为空)。

**涉及用户或者编程常见的使用错误:**

1. **忘记调用 `DebugDisableFinalize()`:**  虽然在这个简单的例子中，`pthread_key_delete` 并不会造成严重的资源泄漏（因为没有设置析构函数），但在更复杂的场景中，如果线程局部存储关联了需要释放的资源，忘记调用对应的清理函数会导致内存泄漏或其他资源泄漏。

2. **在错误的线程中设置/查询禁用状态:**  线程局部存储是线程私有的，在一个线程中设置的值不会影响其他线程。 如果开发者误解了这一点，可能会在错误的线程中调用 `DebugDisableSet` 或 `DebugCallsDisabled`，导致意外的行为。

3. **与全局调试开关 `g_debug` 的混淆:**  `DebugCallsDisabled` 同时检查全局开关 `g_debug` 和线程局部设置。 如果开发者只关注线程局部设置，可能会忽略全局开关的状态，导致调试行为不符合预期。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `debug_disable.cpp` 的路径 (理论推测):**

1. **Framework 层的内存分配请求:**  Android Framework 中很多组件（例如，ActivityManagerService, PackageManagerService 等）在运行时会进行内存分配。这些分配最终会调用到 Bionic 库提供的 `malloc`, `calloc`, `realloc`, `free` 等函数。

2. **`malloc_debug` 介入:**  当启用了内存分配调试功能时（通常通过系统属性或开发者选项配置），Bionic 的内存分配函数会调用 `malloc_debug` 目录下的相关代码。

3. **检查调试禁用状态:**  在 `malloc_debug` 的实现中，很可能会调用 `DebugCallsDisabled()` 来检查当前线程是否禁用了调试。 如果禁用了，则跳过调试相关的检查和记录，直接进行实际的内存分配操作。

4. **设置/清除禁用状态:**  Android Framework 或其底层的 native 代码可能会在某些特定场景下调用 `DebugDisableSet()` 来临时禁用或启用特定线程的内存分配调试。  这可能发生在性能敏感的代码路径中，或者在已知某些代码逻辑不会导致内存错误的情况下。

**NDK 到达 `debug_disable.cpp` 的路径:**

1. **NDK 代码的内存分配:**  使用 NDK 开发的应用程序可以直接调用 Bionic 库提供的标准 C/C++ 库函数，包括内存分配函数。

2. **与 Framework 类似的处理:**  当 NDK 应用调用 `malloc` 等函数时，如果启用了内存分配调试，也会经过 `malloc_debug` 目录下的代码，并可能调用 `DebugCallsDisabled()`。

3. **NDK 代码显式调用:**  理论上，NDK 开发者也可以直接调用 `debug_disable.h` 中声明的函数，例如 `DebugDisableSet()`，来控制其应用中特定线程的内存分配调试行为。  但这通常不是常见的做法，因为内存分配调试通常由系统统一控制。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 监听和修改 `DebugCallsDisabled` 和 `DebugDisableSet` 函数行为的示例：

```javascript
// attach 到目标进程
Java.perform(function() {
    // 假设目标进程已经运行，可以使用进程名或 PID
    // const targetProcess = Process.getProcessByName("com.example.myapp");
    // if (targetProcess) {
    //     Process.attach(targetProcess.pid);
    // }

    const DebugCallsDisabled = Module.findExportByName("libc.so", "_Z18DebugCallsDisabledEv"); // 函数名可能需要 demangle
    const DebugDisableSet = Module.findExportByName("libc.so", "_Z15DebugDisableSetb"); // 函数名可能需要 demangle

    if (DebugCallsDisabled) {
        Interceptor.attach(DebugCallsDisabled, {
            onEnter: function(args) {
                console.log("[DebugCallsDisabled] Called");
            },
            onLeave: function(retval) {
                console.log("[DebugCallsDisabled] Returning: " + retval);
            }
        });
    } else {
        console.log("[DebugCallsDisabled] Not found");
    }

    if (DebugDisableSet) {
        Interceptor.attach(DebugDisableSet, {
            onEnter: function(args) {
                const disable = args[0].toInt() !== 0;
                console.log("[DebugDisableSet] disable=" + disable);
                // 可以修改参数，强制启用或禁用调试
                // args[0] = ptr(0); // 强制启用
            },
            onLeave: function(retval) {
                console.log("[DebugDisableSet] Returned");
            }
        });
    } else {
        console.log("[DebugDisableSet] Not found");
    }
});
```

**说明:**

1. **`Java.perform(function() { ... });`:**  这是 Frida 的标准用法，确保代码在目标进程的上下文中执行。
2. **`Module.findExportByName("libc.so", "_Z18DebugCallsDisabledEv");`:**  使用函数符号名在 `libc.so` 中查找函数的地址。  C++ 函数名需要进行 demangle (可以使用 `c++filt` 工具)。
3. **`Interceptor.attach(address, { onEnter: ..., onLeave: ... });`:**  在找到的函数地址上设置 Hook。
    * `onEnter`: 在函数执行前调用，可以访问和修改函数参数 (`args`)。
    * `onLeave`: 在函数执行后调用，可以访问和修改返回值 (`retval`)。
4. **日志输出:**  在 `onEnter` 和 `onLeave` 中打印日志，可以观察函数的调用情况和参数返回值。
5. **修改参数 (示例):**  在 `DebugDisableSet` 的 `onEnter` 中，可以将 `args[0]` 修改为 `ptr(0)` 来强制启用调试，即使原始调用是禁用。

**使用 Frida 调试这些步骤的流程:**

1. **准备环境:**  确保安装了 Frida 和 Frida-tools，并且你的 Android 设备或模拟器已 root 并运行了 Frida server。
2. **编写 Frida 脚本:**  将上面的 JavaScript 代码保存到一个文件中，例如 `debug_disable_hook.js`。
3. **运行 Frida 命令:**  使用 `frida -U -f <包名> -l debug_disable_hook.js --no-pause` 命令来启动目标应用并注入 Hook。  将 `<包名>` 替换为你要调试的 Android 应用的包名。
4. **观察日志:**  Frida 会在终端输出 Hook 到的函数调用信息，你可以根据这些信息来理解 Android Framework 或 NDK 是如何与 `debug_disable.cpp` 中的函数交互的。
5. **根据需要修改脚本:**  你可以根据需要修改 Frida 脚本，例如添加更多的 Hook 点，修改参数返回值，以进行更深入的调试分析。

通过 Frida Hook，你可以动态地观察和操纵这些底层函数的行为，从而更好地理解 Android 系统的内存分配调试机制。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/debug_disable.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "DebugData.h"
#include "debug_disable.h"
#include "debug_log.h"

pthread_key_t g_disable_key;

bool DebugCallsDisabled() {
  if (g_debug == nullptr || pthread_getspecific(g_disable_key) != nullptr) {
    return true;
  }
  return false;
}

bool DebugDisableInitialize() {
  int error = pthread_key_create(&g_disable_key, nullptr);
  if (error != 0) {
    error_log("pthread_key_create failed: %s", strerror(error));
    return false;
  }
  pthread_setspecific(g_disable_key, nullptr);

  return true;
}

void DebugDisableFinalize() {
  pthread_key_delete(g_disable_key);
}

void DebugDisableSet(bool disable) {
  if (disable) {
    pthread_setspecific(g_disable_key, reinterpret_cast<void*>(1));
  } else {
    pthread_setspecific(g_disable_key, nullptr);
  }
}

"""

```