Response:
Let's break down the thought process to generate the comprehensive answer.

1. **Understanding the Core Request:** The primary goal is to analyze the provided C++ code (`NetdClient.cpp`) from Android's Bionic library and explain its functionality, its interaction with the Android framework, and related low-level concepts like `libc` functions and the dynamic linker. The request also asks for practical examples like Frida hooks and common errors.

2. **Initial Code Scan & Keyword Identification:**  I first read through the code, identifying key elements and functions:
    * `#ifdef LIBC_STATIC`:  Indicates conditional compilation based on whether `libc` is built statically.
    * `#include`:  Standard C++ includes, notably `<dlfcn.h>` (for dynamic linking), `<pthread.h>` (for thread synchronization), and `<unistd.h>` (for POSIX system calls).
    * `template <typename FunctionType> static void netdClientInitFunction(...)`: A template function for initializing function pointers.
    * `static void netdClientInitImpl()`: The core initialization logic.
    * `dlopen("libnetd_client.so", RTLD_NOW)`:  Dynamic loading of `libnetd_client.so`. This is a crucial point.
    * `dlsym(handle, symbol)`:  Retrieving symbols (function pointers) from the loaded library.
    * `__netdClientDispatch`: A global structure likely containing function pointers.
    * `static pthread_once_t netdClientInitOnce = PTHREAD_ONCE_INIT`:  Ensuring initialization happens only once.
    * `extern "C" __LIBC_HIDDEN__ void netdClientInit()`: The public initialization function.
    * `async_safe_format_log`:  For logging, ensuring thread safety.
    * `getuid()`, `basename(getprogname())`:  Functions to get the user ID and the program name.

3. **High-Level Functionality Identification:** Based on the identified keywords, I could infer the main purpose: **Dynamic loading of `libnetd_client.so` and initializing function pointers within it.**  This strongly suggests that `NetdClient.cpp` is providing a mechanism to use optimized or specialized network functions from a separate library.

4. **Detailed Analysis of Key Functions:**

    * **`netdClientInitImpl()`:** This function is central. I analyzed its steps:
        * Check if the current process is `netd` itself to avoid a loop.
        * Attempt to `dlopen("libnetd_client.so", RTLD_NOW)`. The `RTLD_NOW` flag is important – it means symbols are resolved immediately. I noted the error handling (or lack thereof for `dlopen` failure, which is by design).
        * Call `netdClientInitFunction` multiple times to initialize function pointers in `__netdClientDispatch`. This is where the actual hooking/redirection happens.

    * **`netdClientInitFunction()`:** This template function is a helper for `netdClientInitImpl()`. It performs the `dlsym` call and initializes the provided function pointer. I focused on understanding how it safely handles cases where the symbol might not exist (the `if (initFunction != nullptr)` check).

    * **`netdClientInit()`:** This is the entry point that uses `pthread_once` to ensure thread-safe, single initialization.

5. **Connecting to Android Functionality:** The filename `NetdClient.cpp` and the dependency on `libnetd_client.so` strongly suggest interaction with the `netd` daemon. `netd` is responsible for network management in Android. Therefore, this code likely provides a way for other parts of the system (through `libc`) to communicate with and utilize `netd`'s capabilities. The specific functions being initialized (e.g., `accept4`, `connect`, `sendmmsg`, `socket`, `netIdForResolv`, `dnsOpenProxy`) confirmed this connection to networking operations.

6. **Explaining `libc` Functions:**  I systematically explained the purpose and general implementation of each `libc` function used: `dlopen`, `dlsym`, `pthread_once`, `getuid`, `strcmp`, `basename`, and `getprogname`. For `dlopen` and `dlsym`, I emphasized their role in dynamic linking. For `pthread_once`, I highlighted its thread-safety. For the others, I described their basic function in process identification and string manipulation.

7. **Addressing Dynamic Linking:** This was a crucial part of the request. I explained the concepts of shared libraries, the role of the dynamic linker, and how `dlopen` and `dlsym` are used. I provided a conceptual `.so` layout example showing the GOT and PLT, and described the linking process at runtime, mentioning lazy binding (though `RTLD_NOW` bypasses it here).

8. **Logic Reasoning and Examples:** I considered potential scenarios and provided examples:
    * **Skipping initialization:**  When the process *is* `netd`.
    * **Dynamic linking failure:** What happens if `libnetd_client.so` isn't found.

9. **Common Errors:** I thought about typical programming mistakes related to dynamic linking, such as incorrect library paths, missing symbols, and versioning issues.

10. **Android Framework/NDK Interaction:** I traced the path from a typical app using socket functions to how it might end up calling the wrapped functions initialized by `NetdClient.cpp`. I explained the role of system calls and the indirection provided by `libc`.

11. **Frida Hook Example:** I created a Frida script to demonstrate how to intercept the `connect` function, showing how to inspect arguments and potentially modify behavior. I focused on hooking the function *after* the redirection by `NetdClient.cpp`.

12. **Structuring the Answer:** I organized the information logically with clear headings and subheadings to make it easier to read and understand. I used formatting like bold text and code blocks to highlight important information. I made sure to answer each part of the original prompt.

13. **Review and Refinement:**  Finally, I reviewed the entire answer to ensure accuracy, completeness, and clarity. I double-checked the explanations and examples.

This iterative process of analyzing the code, connecting it to broader concepts, providing specific examples, and structuring the information effectively allowed me to create the detailed and comprehensive answer you provided.
好的，让我们深入分析 `bionic/libc/bionic/NetdClient.cpp` 这个文件。

**功能概述**

`NetdClient.cpp` 的主要功能是 **动态加载 `libnetd_client.so` 库，并初始化其中提供的网络相关函数的指针**。这是一种延迟加载和功能扩展的机制，允许 Bionic libc 在运行时根据 `libnetd_client.so` 的存在与否，选择性地使用更高级或定制化的网络功能。

简单来说，它就像一个“桥梁”，连接了 Bionic libc 提供的基础网络 API 和 `libnetd_client.so` 中可能提供的更高级或经过优化的实现。

**与 Android 功能的关系及举例说明**

`NetdClient.cpp` 紧密关联着 Android 的网络管理功能。`netd` 是 Android 系统中负责网络管理的核心守护进程。`libnetd_client.so` 库通常由 `netd` 提供，其中包含了与 `netd` 守护进程交互的客户端实现，以及一些可能由 `netd` 提供的特定网络功能优化。

以下是几个具体的例子：

* **网络命名空间支持:** Android 支持网络命名空间，允许进程拥有独立的网络配置。`libnetd_client.so` 可能包含处理网络命名空间相关操作的函数，例如在特定网络命名空间中创建 socket 连接。
* **防火墙和网络策略:** `netd` 负责管理防火墙规则和网络策略。`libnetd_client.so` 中的函数可能允许应用通过 `libc` 间接地与 `netd` 交互，执行需要提升权限的网络操作。
* **DNS 解析:**  `netd` 可能提供定制化的 DNS 解析功能。`libnetd_client.so` 可以包含与 `netd` 的 DNS 解析服务交互的函数，例如 `netIdForResolv` 和 `dnsOpenProxy` 所暗示的功能。
* **Socket 操作优化:**  `libnetd_client.so` 可能包含对标准 socket 操作（如 `connect`, `send`, `recv` 等）的优化实现，例如针对特定网络环境或硬件的加速。

**详细解释每一个 libc 函数的功能是如何实现的**

`NetdClient.cpp` 本身并没有实现 `libc` 函数的功能，而是 **使用** 了 `libc` 提供的函数来实现其自身的功能。让我们逐个分析它使用的 `libc` 函数：

1. **`dlopen(const char *filename, int flag)`:**
   - **功能:**  `dlopen` 用于 **打开一个动态链接库**（通常是 `.so` 文件）。它将库加载到进程的地址空间，并返回一个指向库句柄的指针。如果加载失败，则返回 `nullptr`。
   - **实现:** `dlopen` 的实现高度依赖于操作系统的动态链接器。在 Android 中，这个动态链接器是 Bionic 的一部分。它的主要步骤包括：
     - **查找库文件:** 根据 `filename` 和系统配置的库路径（例如 `LD_LIBRARY_PATH`）查找要加载的 `.so` 文件。
     - **加载库到内存:** 将库的代码段、数据段等加载到进程的虚拟地址空间中。
     - **符号解析和重定位:**  解析库中未定义的符号（例如，依赖的其他库的函数），并根据加载地址调整库中的地址引用。`flag` 参数（这里是 `RTLD_NOW`）决定了符号解析的时机。`RTLD_NOW` 表示立即解析所有符号。
     - **执行初始化代码:**  如果库中有初始化函数（通常使用 `__attribute__((constructor))` 声明），则执行这些函数。

2. **`dlsym(void *handle, const char *symbol)`:**
   - **功能:** `dlsym` 用于在 **已加载的动态链接库中查找指定的符号**（通常是函数或全局变量）。它接收由 `dlopen` 返回的库句柄和符号名称作为参数，并返回该符号的地址。如果找不到符号，则返回 `nullptr`。
   - **实现:**
     - **查找符号表:** `dlsym` 在由 `handle` 指向的动态链接库的符号表中查找与 `symbol` 匹配的条目。
     - **返回地址:** 如果找到匹配的符号，则返回该符号在内存中的地址。

3. **`pthread_once(pthread_once_t *once_control, void (*init_routine)(void))`:**
   - **功能:** `pthread_once` 用于 **确保一个初始化函数 `init_routine` 在多线程环境中只被执行一次**。
   - **实现:**
     - **内部状态:** `pthread_once_t` 结构通常包含一个标志位，用于指示初始化函数是否已经执行过。
     - **原子操作:** `pthread_once` 使用原子操作来检查和更新这个标志位，以保证线程安全。
     - **首次执行:** 只有当 `pthread_once` 首次被调用且 `once_control` 指示初始化尚未完成时，它才会调用 `init_routine`。后续对 `pthread_once` 的调用将直接返回，不会再次执行初始化函数。

4. **`getuid()`:**
   - **功能:** `getuid` 返回 **调用进程的实际用户 ID (UID)**。
   - **实现:** 这是一个系统调用。内核维护着每个进程的 UID。`getuid` 系统调用只是简单地从内核中获取并返回这个值。

5. **`strcmp(const char *s1, const char *s2)`:**
   - **功能:** `strcmp` 用于 **比较两个字符串 `s1` 和 `s2`**。
   - **实现:** `strcmp` 从两个字符串的第一个字符开始逐个比较，直到遇到不同的字符或字符串的结尾。
     - 如果两个字符串相等，则返回 0。
     - 如果 `s1` 的字符在字典序上小于 `s2` 的字符，则返回负值。
     - 如果 `s1` 的字符在字典序上大于 `s2` 的字符，则返回正值。

6. **`basename(const char *path)`:**
   - **功能:** `basename` 返回 **路径名 `path` 的最后一部分**。
   - **实现:** `basename` 在 `path` 字符串中查找最后一个斜杠 `/`。
     - 如果找到斜杠，则返回斜杠后面的子字符串。
     - 如果没有找到斜杠，则返回整个 `path` 字符串。
     - 需要注意的是，某些 `basename` 的实现可能会修改传入的 `path` 字符串（例如，通过将其中的斜杠替换为 null 字符）。

7. **`getprogname()`:**
   - **功能:** `getprogname` 返回 **当前程序的程序名**。
   - **实现:** 不同的系统可能以不同的方式存储程序名。在某些系统中，程序名会作为命令行参数的一部分传递给 `execve` 系统调用，并由内核存储。`getprogname` 可能会直接访问存储在全局变量中的程序名，或者通过读取 `/proc/self/comm` 等方式获取。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

`NetdClient.cpp` 的核心功能就是动态链接。当 `dlopen("libnetd_client.so", RTLD_NOW)` 被调用时，动态链接器会执行以下关键步骤：

**`libnetd_client.so` 布局样本 (简化)**

```
.so 文件: libnetd_client.so

---------------------------------
| ELF Header                     |  (包含魔数、架构信息、入口点等)
---------------------------------
| Program Headers               |  (描述各个段的加载地址、权限等)
---------------------------------
| .text (代码段)                |  (包含可执行的代码)
|   - netdClientInitAccept4     |
|   - netdClientInitConnect     |
|   - ...                       |
---------------------------------
| .rodata (只读数据段)           |  (包含字符串常量、只读数据等)
---------------------------------
| .data (已初始化数据段)        |  (包含已初始化的全局变量、静态变量)
---------------------------------
| .bss (未初始化数据段)         |  (包含未初始化的全局变量、静态变量)
---------------------------------
| .dynamic (动态链接信息段)    |  (包含动态链接所需的各种信息)
|   - DT_NEEDED: 依赖的其他 .so |
|   - DT_SYMTAB: 符号表地址     |
|   - DT_STRTAB: 字符串表地址   |
|   - ...                       |
---------------------------------
| .symtab (符号表)              |  (包含库中定义的符号及其地址)
|   - netdClientInitAccept4     |  (类型: 函数, 地址: ...)
|   - netdClientInitConnect     |  (类型: 函数, 地址: ...)
|   - ...                       |
---------------------------------
| .strtab (字符串表)            |  (包含符号表中使用的字符串)
|   - "netdClientInitAccept4"   |
|   - "netdClientInitConnect"   |
|   - ...                       |
---------------------------------
| .plt (过程链接表)             |  (用于延迟绑定)
---------------------------------
| .got (全局偏移表)             |  (存储全局变量和函数的最终地址)
---------------------------------
```

**链接处理过程 (当 `RTLD_NOW` 被使用时)**

1. **加载 `libnetd_client.so`:** 动态链接器根据 `dlopen` 的请求，将 `libnetd_client.so` 加载到进程的地址空间。
2. **符号解析 (Eager Binding):** 由于使用了 `RTLD_NOW` 标志，动态链接器会立即解析 `libnetd_client.so` 中所有未定义的符号。
   - **查找依赖库:** 如果 `libnetd_client.so` 依赖于其他共享库（通过 `.dynamic` 段中的 `DT_NEEDED` 条目指定），动态链接器会先加载这些依赖库。
   - **解析符号:** 对于 `libnetd_client.so` 中定义的符号（例如 `netdClientInitAccept4`），动态链接器会在其符号表 (`.symtab`) 中找到对应的条目，并确定其在内存中的地址。
   - **重定位:** 动态链接器会修改 `libnetd_client.so` 的代码和数据段中对这些符号的引用，将其指向实际的内存地址。这通常涉及到修改全局偏移表 (`.got`) 中的条目。
3. **`dlsym` 的使用:** 当 `netdClientInitFunction` 调用 `dlsym(handle, "netdClientInitAccept4")` 时：
   - `dlsym` 接收 `dlopen` 返回的 `handle` (指向 `libnetd_client.so` 的加载基址) 和符号名称 `"netdClientInitAccept4"`。
   - `dlsym` 在 `libnetd_client.so` 的符号表中查找 `"netdClientInitAccept4"`。
   - 因为使用了 `RTLD_NOW`，该符号的地址在 `dlopen` 阶段已经被解析和重定位，`dlsym` 可以直接返回其在内存中的地址。
4. **函数指针初始化:** `netdClientInitFunction` 将 `dlsym` 返回的地址转换为函数指针，并赋值给 `__netdClientDispatch.accept4` 等成员。

**如果做了逻辑推理，请给出假设输入与输出**

**假设输入:**

* 程序以 root 权限运行 (`getuid() == 0`)。
* 程序的名称是 "my_app" (`basename(getprogname())` 返回 "my_app")。
* 系统中存在 `libnetd_client.so` 文件，并且其中定义了 "netdClientInitAccept4" 等符号。

**逻辑推理和输出:**

1. **`getuid() == 0` 为真。**
2. **`strcmp(basename(getprogname()), "netd") == 0` 为假**，因为程序名是 "my_app"。
3. **因此，不会跳过 `libnetd_client` 的初始化。**
4. **`dlopen("libnetd_client.so", RTLD_NOW)` 成功**，返回一个非空的 `handle`。
5. **`netdClientInitFunction` 会被多次调用。** 例如，对于 "netdClientInitAccept4"：
   - `dlsym(handle, "netdClientInitAccept4")` 会返回 `libnetd_client.so` 中 `netdClientInitAccept4` 函数的地址 (假设查找成功)。
   - 如果 `initFunction` 不为 `nullptr`，则会调用 `initFunction(&__netdClientDispatch.accept4)`。这通常意味着 `libnetd_client.so` 中的 `netdClientInitAccept4` 函数会将 `__netdClientDispatch.accept4` 指向它自己提供的 `accept4` 实现。
6. **最终，`__netdClientDispatch` 结构体中的函数指针会被 `libnetd_client.so` 中的函数地址填充。**

**假设输入 (另一种情况):**

* 程序的名称是 "netd" (`basename(getprogname())` 返回 "netd")。

**逻辑推理和输出:**

1. **`getuid() == 0` (假设 netd 通常以 root 权限运行)。**
2. **`strcmp(basename(getprogname()), "netd") == 0` 为真。**
3. **会执行条件判断中的 `async_safe_format_log` 打印日志 "Skipping libnetd_client init since *we* are netd"。**
4. **函数直接返回，不会尝试加载 `libnetd_client.so`。** 这避免了 `netd` 进程加载它自己提供的客户端库，防止潜在的循环依赖或资源竞争。

**如果涉及用户或者编程常见的使用错误，请举例说明**

1. **缺少 `libnetd_client.so`:**
   - **错误:** 如果系统缺少 `libnetd_client.so` 文件，`dlopen` 将返回 `nullptr`。
   - **后果:** `netdClientInitFunction` 不会被执行，`__netdClientDispatch` 中的函数指针将保持其默认值（可能是空指针或者 Bionic libc 自身的实现）。这可能导致程序使用默认的网络功能，或者在尝试调用这些函数时崩溃（如果默认值是空指针且没有进行空指针检查）。
   - **常见原因:** 系统配置错误、精简版 Android 系统未包含该库。

2. **`libnetd_client.so` 中缺少指定的符号:**
   - **错误:** 如果 `libnetd_client.so` 存在，但其中没有定义 `dlsym` 尝试查找的符号 (例如，拼写错误或库版本不兼容)。
   - **后果:** `dlsym` 将返回 `nullptr`，`initFunction` 不会被调用，对应的 `__netdClientDispatch` 中的函数指针不会被初始化。
   - **常见原因:** `libnetd_client.so` 版本不匹配、开发或构建错误。

3. **线程安全问题 (虽然 `pthread_once` 解决了此文件中的初始化问题):**
   - **潜在错误 (如果初始化逻辑更复杂):** 如果 `netdClientInitImpl` 中有多个步骤，且这些步骤不是原子操作，在多线程环境下可能出现竞争条件，导致初始化不完整或状态不一致。但此代码中使用了 `pthread_once`，已经规避了这个问题。
   - **常见原因:** 并发编程中的经典问题，需要仔细设计共享资源的访问。

4. **错误地假设 `libnetd_client.so` 总是存在:**
   - **错误:** 一些开发者可能会假设 `libnetd_client.so` 始终存在并提供增强的功能。
   - **后果:** 如果没有检查 `dlopen` 的返回值，并且直接使用 `__netdClientDispatch` 中的函数指针，当 `libnetd_client.so` 不存在时会导致程序崩溃或行为异常。
   - **良好实践:** 始终进行错误检查，并提供回退机制或使用默认实现。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **用户空间程序 (Framework 或 NDK):**
   - 一个 Android 应用 (Java 或 Native) 通过 Android Framework 或 NDK 调用网络相关的 API，例如创建 socket 连接、发送数据等。

2. **System Calls (syscall):**
   - 这些 API 最终会转化为系统调用，例如 `socket()`, `connect()`, `sendto()` 等。

3. **Bionic libc:**
   - 用户空间程序链接到 Bionic libc。当程序执行网络相关的系统调用时，libc 中的包装函数会被调用。
   - **`NetdClient.cpp` 的介入点:** 在 Bionic libc 的某些网络函数实现中（例如 `connect`, `accept4`, `sendto`, `socket` 等），会间接地调用 `netdClientInit()` 函数，以确保 `libnetd_client.so` 的初始化已经完成。
   - **`__netdClientDispatch` 的使用:**  libc 中的网络函数实现可能会检查 `__netdClientDispatch` 中的函数指针。如果这些指针已经被 `libnetd_client.so` 中的函数地址覆盖，那么 libc 的实现会调用 `libnetd_client.so` 提供的版本，而不是其自身的默认实现。

4. **`libnetd_client.so` (如果存在):**
   - 如果 `libnetd_client.so` 被成功加载，并且 `__netdClientDispatch` 中的函数指针被初始化，那么系统调用会被路由到 `libnetd_client.so` 中提供的实现。
   - `libnetd_client.so` 内部可能会与 `netd` 守护进程进行 IPC 通信，以完成网络操作。

**Frida Hook 示例**

我们可以使用 Frida hook `connect` 函数，观察 Bionic libc 如何调用或不调用 `libnetd_client.so` 中的实现。

```javascript
// Frida 脚本

// Hook Bionic libc 的 connect 函数
Interceptor.attach(Module.findExportByName("libc.so", "connect"), {
  onEnter: function (args) {
    console.log("[connect] Entering connect");
    this.sockfd = args[0];
    this.addr = args[1];
    this.addrlen = args[2];

    // 尝试获取 __netdClientDispatch.connect 的地址
    const netdClientDispatch = Module.findBaseAddress("libc.so").add( /* 偏移量，需要根据实际 libc 版本确定 */ );
    const connectPtr = netdClientDispatch.readPointer(); // 假设 connect 是 __netdClientDispatch 的第一个成员

    console.log("[connect] __netdClientDispatch.connect address:", connectPtr);

    // 你可以进一步检查 connectPtr 是否指向 libnetd_client.so 中的地址
    const libnetdClientBase = Module.findBaseAddress("libnetd_client.so");
    if (libnetdClientBase && connectPtr.compare(libnetdClientBase) >= 0 && connectPtr.compare(libnetdClientBase.add(Process.getModuleByName("libnetd_client.so").size)) < 0) {
      console.log("[connect] Calling libnetd_client.so's connect implementation");
    } else {
      console.log("[connect] Calling Bionic libc's default connect implementation");
    }
  },
  onLeave: function (retval) {
    console.log("[connect] Leaving connect, retval:", retval);
  },
});

// 你可能还需要 hook netdClientInit 函数来观察其执行
Interceptor.attach(Module.findExportByName("libc.so", "_ZN12_GLOBAL__N_114netdClientInitEv"), { // 函数名可能需要根据实际 mangled name 调整
  onEnter: function (args) {
    console.log("[netdClientInit] Entering netdClientInit");
  },
  onLeave: function (retval) {
    console.log("[netdClientInit] Leaving netdClientInit");
  },
});
```

**调试步骤：**

1. 将 Frida 脚本保存为 `.js` 文件。
2. 找到目标 Android 进程的 PID。
3. 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l your_script.js --no-pause` 或 `frida -p <pid> -l your_script.js`。
4. 在目标应用中触发网络连接操作。
5. 查看 Frida 的输出，观察 `connect` 函数的调用，以及 `__netdClientDispatch.connect` 指向的地址，从而判断是否使用了 `libnetd_client.so` 中的实现。
6. 观察 `netdClientInit` 的执行情况，确认初始化逻辑是否被调用。

**注意：**

* 查找 `__netdClientDispatch` 的偏移量以及 `netdClientInit` 的函数名可能需要根据具体的 Android 版本和 Bionic libc 的实现进行调整。可以使用 `readelf` 或其他工具查看 `libc.so` 的符号表。
* Hook 系统级别的函数需要 root 权限或特殊的 Frida 配置。

希望以上详细的分析能够帮助你理解 `NetdClient.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/NetdClient.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#ifdef LIBC_STATIC
#error NetdClient.cpp should NOT be included in static libc builds.
#endif

#include <async_safe/log.h>

#include "private/NetdClientDispatch.h"

#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

template <typename FunctionType>
static void netdClientInitFunction(void* handle, const char* symbol, FunctionType* function) {
    typedef void (*InitFunctionType)(FunctionType*);
    InitFunctionType initFunction = reinterpret_cast<InitFunctionType>(dlsym(handle, symbol));
    if (initFunction != nullptr) {
        initFunction(function);
    }
}

static void netdClientInitImpl() {
    // Prevent netd from looping back fwmarkd connections to itself. It would work, but it's
    // a deadlock hazard and unnecessary overhead for the resolver.
    if (getuid() == 0 && strcmp(basename(getprogname()), "netd") == 0) {
        async_safe_format_log(ANDROID_LOG_INFO, "netdClient",
                              "Skipping libnetd_client init since *we* are netd");
        return;
    }

    void* handle = dlopen("libnetd_client.so", RTLD_NOW);
    if (handle == nullptr) {
        // If the library is not available, it's not an error. We'll just use
        // default implementations of functions that it would've overridden.
        return;
    }

    netdClientInitFunction(handle, "netdClientInitAccept4", &__netdClientDispatch.accept4);
    netdClientInitFunction(handle, "netdClientInitConnect", &__netdClientDispatch.connect);
    netdClientInitFunction(handle, "netdClientInitSendmmsg", &__netdClientDispatch.sendmmsg);
    netdClientInitFunction(handle, "netdClientInitSendmsg", &__netdClientDispatch.sendmsg);
    netdClientInitFunction(handle, "netdClientInitSendto", &__netdClientDispatch.sendto);
    netdClientInitFunction(handle, "netdClientInitSocket", &__netdClientDispatch.socket);

    netdClientInitFunction(handle, "netdClientInitNetIdForResolv",
                           &__netdClientDispatch.netIdForResolv);
    netdClientInitFunction(handle, "netdClientInitDnsOpenProxy",
                           &__netdClientDispatch.dnsOpenProxy);
}

static pthread_once_t netdClientInitOnce = PTHREAD_ONCE_INIT;

extern "C" __LIBC_HIDDEN__ void netdClientInit() {
    if (pthread_once(&netdClientInitOnce, netdClientInitImpl)) {
        async_safe_format_log(ANDROID_LOG_ERROR, "netdClient", "Failed to initialize libnetd_client");
    }
}

"""

```