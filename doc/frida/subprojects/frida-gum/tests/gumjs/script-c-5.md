Response:
The user wants a summary of the functionalities of the provided C code file, which is part of the Frida dynamic instrumentation tool. I need to go through each `TESTCASE` in the code and extract its purpose. For each functionality, I should consider the following aspects if relevant:

1. **Relationship with reverse engineering:** How this functionality can be used in the context of reverse engineering.
2. **Involvement of low-level details:** Whether the functionality interacts with binary data, the Linux/Android kernel, or frameworks.
3. **Logical reasoning:**  If the test case demonstrates a logical flow or decision-making process, I should provide an example with input and output.
4. **Common user errors:** Potential mistakes users might make when using the functionality.
5. **Debugging context:** How a user would reach this point in a debugging session.

This is the 6th part of 11, so I need to make sure the summary focuses on the code provided and doesn't repeat information from previous parts (although I don't have access to those parts).

Here's a breakdown of the `TESTCASE` blocks and their functionalities:

*   `process_malloc_ranges_can_be_enumerated`: Enumerates memory ranges allocated with `malloc`.
*   `process_malloc_ranges_can_be_enumerated_legacy_style`:  Enumerates `malloc` ranges using an older API style.
*   `process_can_run_on_thread_with_success`: Executes a function on a specific thread.
*   `process_can_run_on_thread_with_failure`: Handles errors when executing a function on a specific thread.
*   `process_system_ranges_can_be_enumerated`: Enumerates system-level memory ranges.
*   `module_imports_can_be_enumerated`: Enumerates imported functions in a module.
*   `module_imports_can_be_enumerated_legacy_style`: Enumerates module imports using an older API.
*   `module_exports_can_be_enumerated`: Enumerates exported functions in a module.
*   `module_exports_can_be_enumerated_legacy_style`: Enumerates module exports using an older API.
*   `module_exports_enumeration_performance`:  Tests the performance of enumerating module exports.
*   `module_symbols_can_be_enumerated`: Enumerates symbols in a module (functions, variables, etc.).
*   `module_symbols_can_be_enumerated_legacy_style`: Enumerates module symbols using an older API.
*   `module_ranges_can_be_enumerated`: Enumerates memory ranges within a module based on permissions.
*   `module_ranges_can_be_enumerated_legacy_style`: Enumerates module ranges using an older API.
*   `module_sections_can_be_enumerated`: Enumerates sections within a module's binary.
*   `module_dependencies_can_be_enumerated`: Enumerates the dependencies (shared libraries) of a module.
*   `module_base_address_can_be_found`:  Finds the base address of a loaded module.
*   `module_export_can_be_found_by_name`: Finds the address of a specific exported function in a module.
*   `module_can_be_loaded`: Loads a module into the process.
*   `module_can_be_forcibly_initialized`: Forces the initialization of a module.
*   `module_map_values_should_have_module_prototype`: Checks the type of values in a ModuleMap.
*   `api_resolver_can_be_used_to_find_functions`: Uses an API resolver to find functions based on patterns.
*   `api_resolver_can_be_used_to_find_functions_legacy_style`:  Uses the API resolver with an older API.
*   `api_resolver_can_be_used_to_find_sections`: Uses the API resolver to find module sections.
*   `invalid_script_should_return_null`: Tests handling of invalid JavaScript code.
*   `strict_mode_should_be_enforced`: Verifies that JavaScript strict mode is active.
*   `array_buffer_can_be_created`: Tests the creation of ArrayBuffer objects.
*   `method_can_be_called_sync`: Tests synchronous Remote Procedure Calls (RPC).
*   `method_can_be_called_async`: Tests asynchronous RPC.
*   `method_can_throw_sync`: Tests synchronous RPC calls that throw exceptions.
*   `method_can_throw_async`: Tests asynchronous RPC calls that throw exceptions.
*   `method_can_return_null`: Tests RPC returning null values.
*   `method_can_receive_binary_data`: Tests RPC receiving binary data.
*   `method_can_return_binary_data`: Tests RPC returning binary data.
*   `method_can_return_value_and_binary_data`: Tests RPC returning both values and binary data.
*   `method_list_can_be_queried`: Tests retrieving a list of available RPC methods.
*   `calling_inexistent_method_should_throw_error`: Tests calling non-existent RPC methods.
*   `message_can_be_sent`: Tests sending messages from the Frida script.
*   `message_can_be_sent_with_data`: Tests sending messages with binary data.
*   `message_can_be_received`: Tests receiving messages in the Frida script.
*   `recv_wait_in_an_application_thread_should_not_deadlock`: Tests waiting for messages in application threads without causing deadlocks.
*   `message_can_be_received_with_data`: Tests receiving messages with binary data.
*   `recv_may_specify_desired_message_type`: Tests filtering received messages by type.
*   `recv_can_be_waited_for_from_an_application_thread`: Tests blocking for a specific message in an application thread.
*   `recv_can_be_waited_for_from_two_application_threads`: Tests blocking for messages in multiple application threads.
*   `recv_can_be_waited_for_from_our_js_thread`: Tests blocking for a message in the main Frida script thread.
*   `recv_wait_in_an_application_thread_should_throw_on_unload`: Tests how message waiting behaves when the script is unloaded.
*   `recv_wait_in_our_js_thread_should_throw_on_unload`: Tests message waiting during script unload in the main thread.
*   `recv_wait_should_not_leak`: Tests for memory leaks when waiting for messages.
*   `message_can_be_logged`: Tests the console logging functionality within the script.
*   `thread_can_be_forced_to_sleep`: Tests pausing the execution of the script.
*   `thread_backtrace_can_be_captured_with_limit`: Tests capturing the call stack of a thread.
*   `hardware_breakpoint_can_be_set`: Tests setting hardware breakpoints for debugging.
*   `hardware_watchpoint_can_be_set`: Tests setting hardware watchpoints to monitor memory access.
*   `timeout_can_be_scheduled`: Tests scheduling code to run after a delay.

Now I can organize these functionalities into a coherent summary.
这个C源代码文件是Frida工具中`gumjs`组件的测试文件，专门测试JavaScript脚本的各种功能。作为第6部分，它主要涵盖了**进程和模块的枚举、查找、加载以及与远程过程调用（RPC）和消息传递相关的功能**。

以下是该文件功能的详细列表和说明：

**进程相关的操作:**

*   **枚举进程的 `malloc` 分配的内存范围 (`process_malloc_ranges_can_be_enumerated`, `process_malloc_ranges_can_be_enumerated_legacy_style`)**:
    *   **功能**: 允许JavaScript脚本获取目标进程中通过 `malloc` 或类似方式动态分配的内存区域的信息。这包括起始地址和大小。
    *   **与逆向的关系**: 在逆向分析中，了解进程的内存布局对于分析恶意代码、查找敏感数据或理解程序的动态行为至关重要。通过枚举 `malloc` 区域，逆向工程师可以找到程序运行时动态分配的数据结构和缓冲区。
        *   **举例说明**: 假设一个加壳的程序在运行时解密代码并将其存储在动态分配的内存中。通过枚举 `malloc` 范围，Frida脚本可以找到这块解密后的代码区域，并进一步进行分析或提取。
    *   **涉及的底层知识**: 这涉及到对目标进程的内存管理机制的理解，可能需要读取进程的内存映射信息 (如 `/proc/[pid]/maps` 在Linux上)。
*   **在指定线程上运行 JavaScript 代码 (`process_can_run_on_thread_with_success`, `process_can_run_on_thread_with_failure`)**:
    *   **功能**:  允许Frida脚本在目标进程的特定线程上下文中执行代码。这对于访问线程局部变量或在特定线程的执行流程中插入代码非常有用。
    *   **与逆向的关系**:  有些操作可能需要在特定的线程上下文中进行，例如，访问线程本地存储（TLS）或在图形渲染线程中进行操作。
        *   **举例说明**:  某个恶意软件可能在特定的工作线程中解密配置信息。逆向工程师可以使用此功能在那个线程中执行JavaScript代码来读取解密后的配置。
    *   **涉及的底层知识**: 这需要Frida能够控制目标进程的线程执行，涉及到线程ID的管理和上下文切换。
*   **枚举系统级别的内存范围 (`process_system_ranges_can_be_enumerated`)**:
    *   **功能**: 允许Frida脚本获取操作系统内核和共享库等系统级别的内存区域信息.
    *   **与逆向的关系**: 了解系统的内存布局可以帮助识别加载的库，系统调用入口点等。
        *   **举例说明**: 可以用来识别操作系统的核心库加载到了哪些地址，这对于理解系统行为或者绕过地址空间布局随机化(ASLR)有一定的帮助。
    *   **涉及的底层知识**: 需要访问操作系统提供的接口来获取系统内存映射信息.

**模块相关的操作:**

*   **枚举模块的导入导出表 (`module_imports_can_be_enumerated`, `module_imports_can_be_enumerated_legacy_style`, `module_exports_can_be_enumerated`, `module_exports_can_be_enumerated_legacy_style`, `module_exports_enumeration_performance`)**:
    *   **功能**:  允许Frida脚本获取指定模块（例如，动态链接库或可执行文件）的导入函数列表和导出函数列表。
    *   **与逆向的关系**:  导入导出表是理解程序模块间依赖关系和功能接口的关键。通过分析导入表，可以了解模块使用了哪些外部库的功能；通过分析导出表，可以了解模块对外提供的功能。
        *   **举例说明**: 逆向分析一个恶意软件的DLL时，可以通过枚举其导入表来了解它使用了哪些Windows API，从而推断其恶意行为。
    *   **涉及的二进制底层知识**: 这涉及到解析PE文件（Windows）或ELF文件（Linux, Android）的结构，读取其导入目录和导出目录。
*   **枚举模块的符号 (`module_symbols_can_be_enumerated`, `module_symbols_can_be_enumerated_legacy_style`)**:
    *   **功能**: 允许Frida脚本获取模块中定义的各种符号，包括函数、全局变量等。
    *   **与逆向的关系**: 符号信息提供了更详细的程序结构信息，尤其是在有调试符号的情况下，可以获取函数名、变量名等。
        *   **举例说明**:  可以用来查找特定函数的地址，即使该函数没有被导出。
    *   **涉及的二进制底层知识**: 这需要解析模块的符号表，例如在ELF文件中是 `.symtab` 和 `.strtab` 段。
*   **枚举模块的内存范围 (`module_ranges_can_be_enumerated`, `module_ranges_can_be_enumerated_legacy_style`)**:
    *   **功能**: 允许Frida脚本获取模块内部不同权限的内存区域，例如代码段（可执行）、数据段（可读写）等。
    *   **与逆向的关系**:  有助于理解模块的内存布局，区分代码和数据区域，对于代码注入检测或权限绕过分析有用。
        *   **举例说明**:  可以用来找到模块的代码段的起始和结束地址，从而对代码进行扫描或hook。
    *   **涉及的二进制底层知识**:  需要读取PE或ELF文件的段信息。
*   **枚举模块的节 (`module_sections_can_be_enumerated`)**:
    *   **功能**: 允许Frida脚本获取模块的节（section）信息，例如 `.text` (代码段), `.data` (数据段), `.rodata` (只读数据段) 等。
    *   **与逆向的关系**: 节是组织模块内部数据和代码的基本单元。了解节信息有助于进行静态分析和理解模块的结构。
        *   **举例说明**: 可以用来定位存储字符串常量的 `.rodata` 节。
    *   **涉及的二进制底层知识**: 需要解析PE或ELF文件的节头表。
*   **枚举模块的依赖 (`module_dependencies_can_be_enumerated`)**:
    *   **功能**: 允许Frida脚本获取模块所依赖的其他模块列表。
    *   **与逆向的关系**:  了解模块的依赖关系有助于构建程序的模块调用图，理解程序的架构。
        *   **举例说明**:  可以用来确定一个库依赖于哪些其他的系统库或第三方库。
    *   **涉及的操作系统和二进制底层知识**:  需要读取PE文件的导入表或ELF文件的动态链接信息。
*   **查找模块的基址 (`module_base_address_can_be_found`)**:
    *   **功能**:  允许Frida脚本根据模块名称查找其在内存中的加载地址。
    *   **与逆向的关系**: 基址是进行动态分析的基础，许多操作（如 hook 函数）都需要知道模块的加载地址。
        *   **举例说明**: 在进行函数 hook 时，需要计算目标函数的绝对地址，这通常需要模块的基址。
    *   **涉及的操作系统知识**:  依赖于操作系统提供的API来获取已加载模块的信息。
*   **根据名称查找模块的导出函数 (`module_export_can_be_found_by_name`)**:
    *   **功能**:  允许Frida脚本根据模块名称和导出函数名称查找该函数在内存中的地址。
    *   **与逆向的关系**: 这是进行函数 hook 的常用方法。
        *   **举例说明**:  要 hook `kernel32.dll` 中的 `CreateFileW` 函数，需要先通过此功能找到该函数的地址。
    *   **涉及的操作系统和二进制底层知识**: 依赖于操作系统提供的API以及模块的导出表信息。
*   **加载模块 (`module_can_be_loaded`)**:
    *   **功能**:  允许Frida脚本动态地将指定的模块加载到目标进程中。
    *   **与逆向的关系**:  可以用于注入自定义的 DLL 或 SO 库到目标进程中，从而扩展其功能或进行更深入的分析。
        *   **举例说明**:  可以将一个包含自定义 hook 函数的 DLL 注入到目标进程中。
    *   **涉及的操作系统底层知识**: 依赖于操作系统提供的动态链接加载器 API (如 `LoadLibrary` 在 Windows 上，`dlopen` 在 Linux/Android 上)。
*   **强制模块初始化 (`module_can_be_forcibly_initialized`)**:
    *   **功能**: 允许Frida脚本强制执行尚未初始化的模块的初始化代码。
    *   **与逆向的关系**:  有时需要在模块被正常使用之前就执行其初始化代码，以便尽早地 hook 其内部函数或修改其状态。
        *   **举例说明**:  某个库的初始化过程可能会注册一些重要的回调函数，在这些回调函数被调用之前强制初始化可以提前 hook 它们。

**API 解析器 (`api_resolver_can_be_used_to_find_functions`, `api_resolver_can_be_used_to_find_functions_legacy_style`, `api_resolver_can_be_used_to_find_sections`)**:

*   **功能**: 允许Frida脚本使用模式匹配来查找模块中的函数或节。
*   **与逆向的关系**:  当不完全知道函数名称时，可以使用模式匹配来查找目标函数。
    *   **举例说明**:  可以查找所有以 `_open` 结尾的导出函数。

**脚本执行和错误处理:**

*   **处理无效脚本 (`invalid_script_should_return_null`)**: 测试Frida如何处理语法错误的JavaScript代码。
*   **强制执行严格模式 (`strict_mode_should_be_enforced`)**:  确保JavaScript代码在严格模式下运行，这有助于避免一些常见的编程错误。

**数据处理:**

*   **创建 ArrayBuffer (`array_buffer_can_be_created`)**:  测试创建二进制数据缓冲区的功能。

**远程过程调用 (RPC):**

*   **同步和异步方法调用 (`method_can_be_called_sync`, `method_can_be_called_async`)**: 测试从Frida客户端调用脚本中定义的同步和异步函数。
*   **同步和异步方法抛出异常 (`method_can_throw_sync`, `method_can_throw_async`)**: 测试客户端调用脚本函数时如何处理异常。
*   **返回 null 值 (`method_can_return_null`)**: 测试脚本函数返回 null 值的情况。
*   **接收和返回二进制数据 (`method_can_receive_binary_data`, `method_can_return_binary_data`, `method_can_return_value_and_binary_data`)**: 测试客户端和脚本之间如何传递二进制数据。
*   **查询可用的方法 (`method_list_can_be_queried`)**: 测试客户端如何获取脚本中可调用的函数列表。
*   **调用不存在的方法 (`calling_inexistent_method_should_throw_error`)**: 测试调用脚本中未定义函数时的错误处理。

**消息传递:**

*   **发送消息 (`message_can_be_sent`, `message_can_be_sent_with_data`)**: 测试从Frida脚本向客户端发送消息的功能，包括发送二进制数据。
*   **接收消息 (`message_can_be_received`, `message_can_be_received_with_data`, `recv_may_specify_desired_message_type`)**: 测试Frida脚本接收客户端发送的消息的功能，包括接收二进制数据和根据消息类型过滤。
*   **在应用线程中等待消息 (`recv_wait_in_an_application_thread_should_not_deadlock`, `recv_can_be_waited_for_from_an_application_thread`, `recv_can_be_waited_for_from_two_application_threads`, `recv_can_be_waited_for_from_our_js_thread`)**: 测试在目标进程的线程中阻塞等待特定消息的功能，并确保不会造成死锁。
*   **脚本卸载时取消等待 (`recv_wait_in_an_application_thread_should_throw_on_unload`, `recv_wait_in_our_js_thread_should_throw_on_unload`)**: 测试当Frida脚本被卸载时，正在等待消息的线程如何处理。
*   **等待消息不应导致内存泄漏 (`recv_wait_should_not_leak`)**: 进行压力测试，确保在频繁等待和接收消息时不会发生内存泄漏。

**日志记录 (`message_can_be_logged`)**:

*   **功能**: 测试在Frida脚本中使用 `console.log`, `console.warn`, `console.error` 等方法进行日志输出的功能。
*   **与逆向的关系**:  在调试 Frida 脚本时，日志记录是重要的辅助手段，可以帮助开发者了解脚本的执行状态和变量值。

**线程控制 (`thread_can_be_forced_to_sleep`)**:

*   **功能**: 测试在 Frida 脚本中暂停线程执行的功能。
*   **与逆向的关系**:  有时需要在特定的时间点暂停程序的执行，以便进行更详细的分析或观察其状态变化。

**获取线程回溯 (`thread_backtrace_can_be_captured_with_limit`)**:

*   **功能**:  允许 Frida 脚本获取当前线程的调用堆栈信息。
*   **与逆向的关系**:  回溯信息对于理解程序的执行流程和定位代码执行位置至关重要。
    *   **举例说明**:  在 hook 一个函数后，可以获取调用该函数的堆栈信息，了解调用来源。

**硬件断点和观察点 (`hardware_breakpoint_can_be_set`, `hardware_watchpoint_can_be_set`)**:

*   **功能**: 测试在目标进程中设置硬件断点和硬件观察点的功能。
*   **与逆向的关系**: 硬件断点和观察点是非常强大的调试工具，允许在特定的内存地址被访问或执行时中断程序，这对于分析难以通过软件断点调试的代码非常有用。
    *   **硬件断点举例**: 可以设置硬件断点在某个关键函数的入口，当程序执行到该函数时中断。
    *   **硬件观察点举例**: 可以设置硬件观察点在一个全局变量的地址，当该变量被写入时中断。
    *   **涉及的内核和硬件知识**: 这需要 Frida 与操作系统内核交互，设置 CPU 的调试寄存器。

**定时器 (`timeout_can_be_scheduled`)**:

*   **功能**: 测试在 Frida 脚本中设置定时器延时执行代码的功能。
*   **与逆向的关系**:  可以用于在未来的某个时间点执行特定的操作，例如，在程序运行一段时间后 dump 内存或执行 hook。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida JavaScript 脚本**: 用户首先会编写一个 Frida 脚本，利用 Frida 提供的 API 来进行动态分析或修改目标进程的行为。
2. **用户使用 Frida 客户端加载脚本**: 用户会使用 Frida 的命令行工具 (`frida`, `frida-trace` 等) 或者通过编程方式（使用 Python 或其他语言的 Frida 绑定）将编写的 JavaScript 脚本加载到目标进程中。
3. **Frida GumJS 引擎执行脚本**: Frida 的 GumJS 引擎会解析并执行用户提供的 JavaScript 代码。在执行过程中，用户脚本可能会调用 `Process`, `Module`, `Interceptor`, `send`, `recv`, `rpc.exports` 等 Frida 提供的全局对象和函数。
4. **测试文件模拟用户脚本行为**:  `script.c` 中的测试用例会模拟用户脚本的各种操作，例如调用 `Process.enumerateMallocRanges()`, `Module.findExportByName()`, `send()`, `recv()` 等。
5. **断言验证结果**:  测试用例会使用 `EXPECT_SEND_MESSAGE_WITH` 等断言宏来验证 Frida API 的行为是否符合预期，例如，调用 `Process.enumerateMallocRanges()` 后是否收到了预期的消息。
6. **错误发生或行为不符合预期**: 如果测试用例中的断言失败，则表明 Frida 的相关功能存在问题，需要开发人员进行调试。

**常见的使用错误举例说明:**

*   **模块名或导出函数名错误**:  用户在使用 `Module.findExportByName("invalid_module", "invalid_export")` 时，如果模块名或导出函数名不存在，会导致找不到目标，可能抛出异常或返回 `null`。
*   **在错误的线程上下文执行代码**: 用户尝试在主线程中访问只有特定子线程才有的资源，可能会导致程序崩溃或行为异常。`Process.runOnThread` 可以帮助用户在正确的线程上下文执行代码，但如果线程 ID 错误，也会导致失败。
*   **不正确的消息类型**:  如果用户使用 `recv('expected_type', ...)` 监听特定类型的消息，但客户端发送了其他类型的消息，则回调函数不会被触发，可能导致程序逻辑错误。
*   **在同步上下文中执行异步操作**:  例如，在 `Interceptor.onEnter` 回调中直接调用 `recv().wait()` 可能会导致阻塞，影响程序性能。应该考虑使用异步方式处理。
*   **忘记处理异常**:  在进行 RPC 调用或执行可能出错的操作时，用户应该使用 `try...catch` 语句来捕获并处理可能出现的异常，避免程序崩溃。

**归纳一下它的功能:**

总而言之，`frida/subprojects/frida-gum/tests/gumjs/script.c` 这个测试文件旨在全面测试 Frida 的 GumJS 引擎提供的核心功能，特别是与**进程和模块信息获取、动态加载、远程过程调用以及消息传递**相关的 API 的正确性和稳定性。它通过模拟各种用户脚本可能执行的操作，确保 Frida 能够可靠地完成动态 instrumentation 的任务。这些测试覆盖了底层的二进制和操作系统知识，同时也模拟了用户常见的操作和可能遇到的错误场景。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共11部分，请归纳一下它的功能

"""
urn;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Process.enumerateMallocRanges();"
      "send(ranges.length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (process_malloc_ranges_can_be_enumerated_legacy_style)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "Process.enumerateMallocRanges({"
        "onMatch(range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "send(Process.enumerateMallocRangesSync().length > 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#endif

TESTCASE (process_can_run_on_thread_with_success)
{
  GThread * thread;
  GumThreadId thread_id;
  gboolean done = FALSE;

  thread = create_sleeping_dummy_thread_sync (&done, &thread_id);

  COMPILE_AND_LOAD_SCRIPT (
      "const getLocalThreadStringValue = new NativeFunction(" GUM_PTR_CONST ", "
        "'pointer', []);"
      "Process.runOnThread(0x%" G_GSIZE_MODIFIER "x, () => {"
      "  return getLocalThreadStringValue().readUtf8String();"
      "})"
      ".then(str => { send(str); });",
      get_local_thread_string_value,
      thread_id);

  EXPECT_SEND_MESSAGE_WITH ("\"53Cr3t\"");

  done = TRUE;
  g_thread_join (thread);

  EXPECT_NO_MESSAGES ();
}

TESTCASE (process_can_run_on_thread_with_failure)
{
  GThread * thread;
  GumThreadId thread_id;
  gboolean done = FALSE;

  thread = create_sleeping_dummy_thread_sync (&done, &thread_id);

  COMPILE_AND_LOAD_SCRIPT (
      "Process.runOnThread(0x%" G_GSIZE_MODIFIER "x, () => {"
      "  throw new Error('epic fail');"
      "})"
      ".catch(e => { send(e.message); });",
      thread_id);

  EXPECT_SEND_MESSAGE_WITH ("\"epic fail\"");

  done = TRUE;
  g_thread_join (thread);

  EXPECT_NO_MESSAGES ();
}

static GThread *
create_sleeping_dummy_thread_sync (gboolean * done,
                                   GumThreadId * thread_id)
{
  TestRunOnThreadSyncContext sync_data;
  GThread * thread;

  g_mutex_init (&sync_data.mutex);
  g_cond_init (&sync_data.cond);
  sync_data.started = FALSE;
  sync_data.thread_id = 0;
  sync_data.done = done;

  g_mutex_lock (&sync_data.mutex);

  thread = g_thread_new ("gumjs-test-sleeping-dummy-func", sleeping_dummy_func,
      &sync_data);

  while (!sync_data.started)
    g_cond_wait (&sync_data.cond, &sync_data.mutex);

  if (thread_id != NULL)
    *thread_id = sync_data.thread_id;

  g_mutex_unlock (&sync_data.mutex);

  g_cond_clear (&sync_data.cond);
  g_mutex_clear (&sync_data.mutex);

  return thread;
}

static gpointer
sleeping_dummy_func (gpointer data)
{
  TestRunOnThreadSyncContext * sync_data = data;
  gboolean * done = sync_data->done;

  g_private_replace (&target_thread_string_value, g_strdup ("53Cr3t"));

  g_mutex_lock (&sync_data->mutex);
  sync_data->started = TRUE;
  sync_data->thread_id = gum_process_get_current_thread_id ();
  g_cond_signal (&sync_data->cond);
  g_mutex_unlock (&sync_data->mutex);

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

static const gchar *
get_local_thread_string_value (void)
{
  return g_private_get (&target_thread_string_value);
}

TESTCASE (process_system_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Process.enumerateSystemRanges();"
      "console.log(JSON.stringify(ranges, null, 2));");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (module_imports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const imports = Process.getModuleByName('%s').enumerateImports();"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_imports_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const imports = Module.enumerateImports('%s');"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateImports('%s', {"
        "onMatch(imp) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const imports = Module.enumerateImportsSync('%s');"
      "send(imports.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const exports = Process.getModuleByName('%s').enumerateExports();"
      "send(exports.length > 0);"
      "const e = exports[0];"
      "send(typeof e.type === 'string');"
      "send(typeof e.name === 'string');"
      "send(e.address instanceof NativePointer);"
      "send(JSON.stringify(e) !== \"{}\");",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const exports = Module.enumerateExports('%s');"
      "send(exports.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateExports('%s', {"
        "onMatch(exp) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const exports = Module.enumerateExportsSync('%s');"
      "send(exports.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_exports_enumeration_performance)
{
  TestScriptMessageItem * item;
  gint duration;

  COMPILE_AND_LOAD_SCRIPT (
      "const module = Process.getModuleByName('%s');"
      "const start = Date.now();"
      "module.enumerateExports();"
      "send(Date.now() - start);",
      SYSTEM_MODULE_NAME);
  item = test_script_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
  g_print ("<%d ms> ", duration);
  test_script_message_item_free (item);
}

TESTCASE (module_symbols_can_be_enumerated)
{
#ifndef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "const symbols = Process.getModuleByName('%s').enumerateSymbols();"
      "send(symbols.length > 0);"
      "const s = symbols[0];"
      "send(typeof s.isGlobal === 'boolean');"
      "send(typeof s.type === 'string');"
      "send(typeof s.name === 'string');"
      "send(s.address instanceof NativePointer);"
      "send(JSON.stringify(s) !== \"{}\");",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#else
  g_print ("<skipping on this platform> ");
#endif
}

TESTCASE (module_symbols_can_be_enumerated_legacy_style)
{
#ifndef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "const symbols = Module.enumerateSymbols('%s');"
      "send(symbols.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateSymbols('%s', {"
        "onMatch(sym) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const symbols = Module.enumerateSymbolsSync('%s');"
      "send(symbols.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
#else
  g_print ("<skipping on this platform> ");
#endif
}

TESTCASE (module_ranges_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Process.getModuleByName('%s').enumerateRanges('--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_ranges_can_be_enumerated_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Module.enumerateRanges('%s', '--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");

  COMPILE_AND_LOAD_SCRIPT (
      "Module.enumerateRanges('%s', '--x', {"
        "onMatch(range) {"
        "  send('onMatch');"
        "  return 'stop';"
        "},"
        "onComplete() {"
        "  send('onComplete');"
        "}"
      "});",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const ranges = Module.enumerateRangesSync('%s', '--x');"
      "send(ranges.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_sections_can_be_enumerated)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  COMPILE_AND_LOAD_SCRIPT (
      "const sections = Process.getModuleByName('%s').enumerateSections();"
      "send(sections.length > 0);",
      SYSTEM_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
}

TESTCASE (module_dependencies_can_be_enumerated)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  COMPILE_AND_LOAD_SCRIPT (
      "const deps = Process.getModuleByName('%s').enumerateDependencies();"
      "send(deps.length > 0);",
      GUM_TESTS_MODULE_NAME);
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
}

TESTCASE (module_base_address_can_be_found)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const sysModuleName = '%s';"
      "const badModuleName = 'nope_' + sysModuleName;"

      "const base = Module.findBaseAddress(sysModuleName);"
      "send(base !== null);"

      "send(Module.findBaseAddress(badModuleName) === null);"

      "try {"
          "send(Module.getBaseAddress(sysModuleName).equals(base));"

          "Module.getBaseAddress(badModuleName);"
          "send('should not get here');"
      "} catch (e) {"
          "send(/unable to find module/.test(e.message));"
      "}",
      SYSTEM_MODULE_NAME);

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (module_export_can_be_found_by_name)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const sysModuleName = '%s';"
      "const sysModuleExport = '%s';"
      "const badModuleName = 'nope_' + sysModuleName;"
      "const badModuleExport = sysModuleExport + '_does_not_exist';"

      "const impl = Module.findExportByName(sysModuleName, sysModuleExport);"
      "send(impl !== null);"

      "send(Module.findExportByName(badModuleName, badModuleExport) === null);"

      "try {"
          "send(Module.getExportByName(sysModuleName, sysModuleExport)"
              ".equals(impl));"

          "Module.getExportByName(badModuleName, badModuleExport);"
          "send('should not get here');"
      "} catch (e) {"
          "send(/unable to find export/.test(e.message));"
      "}",
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

#ifdef HAVE_WINDOWS
  HMODULE mod;
  gpointer actual_address;
  char actual_address_str[32];

  mod = GetModuleHandle (_T ("kernel32.dll"));
  g_assert_nonnull (mod);
  actual_address = GetProcAddress (mod, "Sleep");
  g_assert_nonnull (actual_address);
  sprintf_s (actual_address_str, sizeof (actual_address_str),
      "\"%" G_GSIZE_MODIFIER "x\"", GPOINTER_TO_SIZE (actual_address));

  COMPILE_AND_LOAD_SCRIPT (
      "send(Module.findExportByName('kernel32.dll', 'Sleep').toString(16));");
  EXPECT_SEND_MESSAGE_WITH (actual_address_str);
#endif
}

TESTCASE (module_can_be_loaded)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const moduleName = '%s';"
      "const moduleExport = '%s';"
      "const m = Module.load(moduleName);"
      "send(m.getExportByName(moduleExport).equals("
          "Module.getExportByName(moduleName, moduleExport)));"
      "try {"
      "  Module.load(moduleName + '_nope');"
      "  send('success');"
      "} catch (e) {"
      "  send('error');"
      "}",
      SYSTEM_MODULE_NAME, SYSTEM_MODULE_EXPORT);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"error\"");
}

TESTCASE (module_can_be_forcibly_initialized)
{
  COMPILE_AND_LOAD_SCRIPT ("Module.ensureInitialized('%s');",
      SYSTEM_MODULE_NAME);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "Module.ensureInitialized('DefinitelyNotAValidModuleName');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: unable to find module 'DefinitelyNotAValidModuleName'");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (module_map_values_should_have_module_prototype)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const map = new ModuleMap();"
      "send(map.values()[0] instanceof Module);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

#ifdef HAVE_WINDOWS
# define API_RESOLVER_TEST_QUERY "exports:*!_open*"
#else
# define API_RESOLVER_TEST_QUERY "exports:*!open*"
#endif

TESTCASE (api_resolver_can_be_used_to_find_functions)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const resolver = new ApiResolver('module');"
      "const matches = resolver.enumerateMatches('%s');"
      "send(matches.length > 0);"
      "const m = matches[0];"
      "send(typeof m.name);"
      "send(m.address instanceof NativePointer);"
      "send(typeof m.size);",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

TESTCASE (api_resolver_can_be_used_to_find_functions_legacy_style)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const resolver = new ApiResolver('module');"
      "resolver.enumerateMatches('%s', {"
      "  onMatch(match) {"
      "    send('onMatch');"
      "    return 'stop';"
      "  },"
      "  onComplete() {"
      "    send('onComplete');"
      "  }"
      "});",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("\"onMatch\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onComplete\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const resolver = new ApiResolver('module');"
      "const matches = resolver.enumerateMatchesSync('%s');"
      "send(matches.length > 0);",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (api_resolver_can_be_used_to_find_sections)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  COMPILE_AND_LOAD_SCRIPT (
      "const resolver = new ApiResolver('module');"
      "const matches = resolver.enumerateMatches('sections:*!*data*');"
      "send(matches.length > 0);"
      "const m = matches[0];"
      "send(typeof m.name);"
      "send(m.address instanceof NativePointer);"
      "send(typeof m.size);",
      API_RESOLVER_TEST_QUERY);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
#endif
}

TESTCASE (invalid_script_should_return_null)
{
  GError * err = NULL;

  g_assert_null (gum_script_backend_create_sync (fixture->backend, "testcase",
      "'", NULL, NULL, NULL));

  g_assert_null (gum_script_backend_create_sync (fixture->backend, "testcase",
      "'", NULL, NULL, &err));
  g_assert_nonnull (err);
  g_assert_true (g_str_has_prefix (err->message,
      "Script(line 1): SyntaxError: "));
}

TESTCASE (strict_mode_should_be_enforced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "function run() {"
      "  oops = 1337;"
      "}"
      "run();");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "ReferenceError: 'oops' is not defined"
      : "ReferenceError: oops is not defined");
}

TESTCASE (array_buffer_can_be_created)
{
  COMPILE_AND_LOAD_SCRIPT ("new ArrayBuffer(16);");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (method_can_be_called_sync)
{
  COMPILE_AND_LOAD_SCRIPT ("rpc.exports.add = (a, b) => a + b;");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"add\",[1,2]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"ok\",3]");
}

TESTCASE (method_can_be_called_async)
{
  COMPILE_AND_LOAD_SCRIPT ("rpc.exports.add = async (a, b) => a + b;");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"add\",[1,2]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"ok\",3]");
}

TESTCASE (method_can_throw_sync)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.raise = () => { throw new Error('no'); }");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"raise\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",42,\"error\",\"no\",");
}

TESTCASE (method_can_throw_async)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.raise = async () => { throw new Error('no'); }");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"raise\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PREFIX ("[\"frida:rpc\",42,\"error\",\"no\",");
}

TESTCASE (method_can_return_null)
{
  COMPILE_AND_LOAD_SCRIPT ("rpc.exports.returnNull = () => null;");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"returnNull\",[]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"ok\",null]");
}

TESTCASE (method_can_receive_binary_data)
{
  const guint8 data_to_send[2] = { 0x13, 0x37 };
  GBytes * bytes;

  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.eat = (str, data) => {"
          "send(str, data);"
      "}");

  bytes = g_bytes_new_static (data_to_send, sizeof (data_to_send));
  gum_script_post (fixture->script,
      "[\"frida:rpc\",42,\"call\",\"eat\",[\"yoghurt\"]]", bytes);
  g_bytes_unref (bytes);

  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"yoghurt\"", "13 37");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"ok\",null]");
}

TESTCASE (method_can_return_binary_data)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.read = () => {"
          "const buf = Memory.allocUtf8String(\"Yo\");"
          "return buf.readByteArray(2);"
      "};");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"read\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("[\"frida:rpc\",42,\"ok\",null]",
      "59 6f");
}

TESTCASE (method_can_return_value_and_binary_data)
{
  COMPILE_AND_LOAD_SCRIPT (
      "rpc.exports.read = () => {"
          "const buf = Memory.allocUtf8String(\"Yo\");"
          "return [{meta: 'data'}, buf.readByteArray(2)];"
      "};");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"read\",[]]");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA (
      "[\"frida:rpc\",42,\"ok\",null,{\"meta\":\"data\"}]",
      "59 6f");
}

TESTCASE (method_list_can_be_queried)
{
  COMPILE_AND_LOAD_SCRIPT ("rpc.exports = { a() {}, b() {}, c() {} };");
  POST_MESSAGE ("[\"frida:rpc\",42,\"list\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"ok\",[\"a\",\"b\",\"c\"]]");
}

TESTCASE (calling_inexistent_method_should_throw_error)
{
  COMPILE_AND_LOAD_SCRIPT ("");
  POST_MESSAGE ("[\"frida:rpc\",42,\"call\",\"banana\",[]]");
  EXPECT_SEND_MESSAGE_WITH ("[\"frida:rpc\",42,\"error\","
      "\"unable to find method 'banana'\"]");
}

TESTCASE (message_can_be_sent)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234);");
  EXPECT_SEND_MESSAGE_WITH ("1234");
}

TESTCASE (message_can_be_sent_with_data)
{
  COMPILE_AND_LOAD_SCRIPT ("send(1234, [0x13, 0x37]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1234", "13 37");
}

TESTCASE (message_can_be_received)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv(message => {"
      "  if (message.type === 'ping')"
      "    send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

TESTCASE (recv_wait_in_an_application_thread_should_not_deadlock)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;
  guint i;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(arg => {"
      "  let timeToRecv;"
      "  let shouldExit = false;"
      "  while (true) {"
      "    recv(message => {"
      "       if (message.type === 'stop')"
      "         shouldExit = true;"
      "       else if (message.type === 'wait-until')"
      "         timeToRecv = message.time;"
      "       else"
      "         throw new Error(`unexpected message: ${message.type}`);"
      "    }).wait();"
      "    if (shouldExit)"
      "      return 0;"
      "    while (Date.now() < timeToRecv) {}"
      "    recv(message => {"
      "      if (message.type !== 'ping')"
      "        throw new Error(`unexpected message: ${message.type}`);"
      "    }).wait();"
      "    send('pong');"
      "  }"
      "}, 'int', ['int']));", target_function_int);

  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  for (i = 0; i != 100; i++)
  {
    gint64 time_now, time_to_schedule_recv, time_to_post;
    gchar * msg;

    time_now = g_get_real_time ();
    time_to_schedule_recv = time_now - (time_now % (20 * 1000)) + (50 * 1000);
    time_to_post = time_to_schedule_recv + i;

    msg = g_strdup_printf (
        "{\"type\":\"wait-until\",\"time\":%" G_GINT64_FORMAT "}",
        time_to_schedule_recv / 1000);
    POST_MESSAGE (msg);
    g_free (msg);

    while (g_get_real_time () < time_to_post)
      ;
    POST_MESSAGE ("{\"type\":\"ping\"}");
    EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
  }

  POST_MESSAGE ("{\"type\":\"stop\"}");

  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
}

TESTCASE (message_can_be_received_with_data)
{
  const guint8 data_to_send[2] = { 0x13, 0x37 };
  GBytes * bytes;

  COMPILE_AND_LOAD_SCRIPT (
      "recv((message, data) => {"
      "  if (message.type === 'ping')"
      "    send('pong', data);"
      "});");
  EXPECT_NO_MESSAGES ();

  bytes = g_bytes_new_static (data_to_send, sizeof (data_to_send));
  gum_script_post (fixture->script, "{\"type\":\"ping\"}", bytes);
  g_bytes_unref (bytes);

  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("\"pong\"", "13 37");
}

TESTCASE (recv_may_specify_desired_message_type)
{
  COMPILE_AND_LOAD_SCRIPT (
      "recv('wobble', message => {"
      "  send('wibble');"
      "});"
      "recv('ping', message => {"
      "  send('pong');"
      "});");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"ping\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pong\"");
}

TESTCASE (recv_can_be_waited_for_from_an_application_thread)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    const op = recv('poke', pokeMessage => {"
      "      send('pokeBack');"
      "    });"
      "    op.wait();"
      "    send('pokeReceived');"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_can_be_waited_for_from_two_application_threads)
{
  GThread * worker_thread1, * worker_thread2;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    const op = recv('poke', pokeMessage => {"
      "      send('pokeBack');"
      "    });"
      "    op.wait();"
      "    send('pokeReceived');"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread1 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  g_usleep (G_USEC_PER_SEC / 25);
  worker_thread2 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started != 2)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread1);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"poke\"}");
  g_thread_join (worker_thread2);
  g_assert_cmpint (ctx.finished, ==, 2);
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_can_be_waited_for_from_our_js_thread)
{
  /*
   * We do the wait() in a setTimeout() as our test fixture loads the
   * script synchronously...
   */
  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(() => {"
      "  const op = recv('poke', pokeMessage => {"
      "    send('pokeBack');"
      "  });"
      "  op.wait();"
      "  send('pokeReceived');"
      "}, 0);");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"poke\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeBack\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pokeReceived\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_wait_in_an_application_thread_should_throw_on_unload)
{
  GThread * worker_thread;
  GumInvokeTargetContext ctx;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    const op = recv('poke', pokeMessage => {"
      "      send('pokeBack');"
      "    });"
      "    try {"
      "      op.wait();"
      "      send('pokeReceived');"
      "    } catch (e) {"
      "      send('oops: ' + e.message);"
      "    }"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();

  ctx.script = fixture->script;
  ctx.repeat_duration = 0;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);
  while (ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  g_usleep (G_USEC_PER_SEC / 25);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (ctx.finished, ==, 0);

  UNLOAD_SCRIPT ();
  g_thread_join (worker_thread);
  g_assert_cmpint (ctx.finished, ==, 1);
  EXPECT_SEND_MESSAGE_WITH ("\"oops: script is unloading\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_wait_in_our_js_thread_should_throw_on_unload)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.pin();"
      "setTimeout(() => {"
      "  Script.unpin();"
      "  const op = recv('poke', pokeMessage => {"
      "    send('pokeBack');"
      "  });"
      "  try {"
      "    op.wait();"
      "    send('pokeReceived');"
      "  } catch (e) {"
      "    send('oops: ' + e.message);"
      "  }"
      "}, 0);");
  EXPECT_NO_MESSAGES ();

  UNLOAD_SCRIPT ();
  EXPECT_SEND_MESSAGE_WITH ("\"oops: script is unloading\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (recv_wait_should_not_leak)
{
  GThread * worker_thread;
  guint initial_heap_size;
  GumInvokeTargetContext ctx;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    const op = recv('input', onInput);"
      "    send('request-input');"
      "    op.wait();"
      "  }"
      "});"
      "function onInput() {"
      "}", target_function_int);
  EXPECT_NO_MESSAGES ();

  initial_heap_size = gum_peek_private_memory_usage ();

  ctx.script = fixture->script;
  ctx.repeat_duration = 3000;
  ctx.started = 0;
  ctx.finished = 0;
  worker_thread = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &ctx);

  do
  {
    TestScriptMessageItem * item;

    item = test_script_fixture_try_pop_message (fixture, 10);
    if (item != NULL)
    {
      const guint size = 1024 * 1024;
      gpointer dummy_data;
      GBytes * dummy_bytes;

      dummy_data = g_malloc (size);
      memset (dummy_data, g_random_int_range (0, G_MAXUINT8), size);
      dummy_bytes = g_bytes_new_take (dummy_data, size);

      gum_script_post (fixture->script, "{\"type\":\"input\"}", dummy_bytes);

      g_bytes_unref (dummy_bytes);

      test_script_message_item_free (item);
    }

    g_assert_cmpuint (gum_peek_private_memory_usage () / initial_heap_size,
        <, 1000);
  }
  while (!ctx.finished);

  g_thread_join (worker_thread);
}

static gpointer
invoke_target_function_int_worker (gpointer data)
{
  GumInvokeTargetContext * ctx = (GumInvokeTargetContext *) data;

  g_atomic_int_inc (&ctx->started);

  if (ctx->repeat_duration == 0)
  {
    target_function_int (42);
  }
  else
  {
    gdouble repeat_duration_in_seconds;
    GTimer * timer;

    repeat_duration_in_seconds = (gdouble) ctx->repeat_duration / 1000.0;
    timer = g_timer_new ();

    do
    {
      target_function_int (42);
    }
    while (g_timer_elapsed (timer, NULL) < repeat_duration_in_seconds);

    g_timer_destroy (timer);
  }

  g_atomic_int_inc (&ctx->finished);

  return NULL;
}

TESTCASE (message_can_be_logged)
{
  DISABLE_LOG_MESSAGE_HANDLING ();

  COMPILE_AND_LOAD_SCRIPT ("console.log('Hello', undefined, null, 1337, "
      "'world', true, { color: 'pink' });");
  EXPECT_LOG_MESSAGE_WITH ("info", "Hello undefined null 1337 world "
      "true [object Object]");

  COMPILE_AND_LOAD_SCRIPT ("console.warn('Trouble is coming');");
  EXPECT_LOG_MESSAGE_WITH ("warning", "Trouble is coming");

  COMPILE_AND_LOAD_SCRIPT ("console.error('Oh noes');");
  EXPECT_LOG_MESSAGE_WITH ("error", "Oh noes");
}

TESTCASE (thread_can_be_forced_to_sleep)
{
  GTimer * timer = g_timer_new ();
  COMPILE_AND_LOAD_SCRIPT ("Thread.sleep(0.25);");
  g_assert_cmpfloat (g_timer_elapsed (timer, NULL), >=, 0.2f);
  EXPECT_NO_MESSAGES ();
  g_timer_destroy (timer);
}

TESTCASE (thread_backtrace_can_be_captured_with_limit)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(Thread.backtrace(null, { limit: 2 }).length);");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (hardware_breakpoint_can_be_set)
{
#if defined (HAVE_FREEBSD) || defined (HAVE_QNX)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const threads = Process.enumerateThreads();\n"
      "Process.setExceptionHandler(e => {\n"
      "  if (!['breakpoint', 'single-step'].includes(e.type))\n"
      "    return false;\n"
      "  send('trapped');\n"
      "  threads.forEach(t => t.unsetHardwareBreakpoint(0));\n"
      "  return true;\n"
      "});\n"
      "threads.forEach(t => t.setHardwareBreakpoint(0, " GUM_PTR_CONST "));",
      target_function_int);
  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("\"trapped\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (hardware_watchpoint_can_be_set)
{
  guint32 val = 42;

#if defined (HAVE_FREEBSD) || defined (HAVE_QNX)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const threads = Process.enumerateThreads();\n"
      "Process.setExceptionHandler(e => {\n"
      "  if (!['breakpoint', 'single-step'].includes(e.type))\n"
      "    return false;\n"
      "  send('trapped');\n"
      "  threads.forEach(t => t.unsetHardwareWatchpoint(0));\n"
      "  return true;\n"
      "});\n"
      "threads.forEach(t => t.setHardwareWatchpoint(0, " GUM_PTR_CONST ", 4,"
        "'w'));",
      &val);
  EXPECT_NO_MESSAGES ();

  val = 1337;
  EXPECT_SEND_MESSAGE_WITH ("\"trapped\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (timeout_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(() => {"
      "  send(1337);"
      "}, 20);");
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(value => {"
      "  send(value);"
      "}, uint64(20), 1338);");
  EXPECT_NO_
"""


```