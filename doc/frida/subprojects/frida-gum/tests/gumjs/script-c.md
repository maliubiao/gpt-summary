Response:
Let's break down the thought process for analyzing this Frida script source code.

**1. Initial Understanding and Context:**

* **Goal:** Understand the functionality of `script.c` in the context of Frida.
* **Keywords:** Frida, dynamic instrumentation, `script.c`, tests, `gumjs`.
* **Core Idea:** This file contains test cases for the JavaScript engine (`gumjs`) within Frida. These tests verify the core functionalities exposed to the JavaScript environment.

**2. Deconstructing the File Content:**

* **Copyright Notices:**  Recognize these as standard legal boilerplate, indicating the authors and licensing. Not directly functional but good for attribution.
* **`#include "script-fixture.c"`:**  This is a crucial inclusion. It likely sets up the testing environment (script loading, execution, message handling, etc.). We don't have its content here, but its presence is important context.
* **`TESTLIST_BEGIN (script)` and `TESTLIST_END ()`:** This strongly suggests a testing framework. Each `TESTENTRY` represents an individual test case. The structure and naming convention are very telling.
* **`TESTGROUP_BEGIN ("...")` and `TESTGROUP_END ()`:** These further categorize the tests, making the code more organized and easier to understand. The group names are highly informative about the area being tested.
* **Individual `TESTENTRY` lines:** The names of these entries are the *primary* source of information about the functionality being tested. They are designed to be descriptive.

**3. Inferring Functionality from Test Case Names:**

This is the core of the analysis. Go through each `TESTENTRY` and interpret its meaning:

* **Basic Scripting:**  `invalid_script_should_return_null`, `strict_mode_should_be_enforced` - These test basic script loading and execution properties.
* **Messaging:** `message_can_be_sent`, `message_can_be_received` - Tests the communication mechanism between the Frida script and the host process.
* **Timers:** `timeout_can_be_scheduled`, `interval_can_be_scheduled` -  Tests the ability to schedule asynchronous tasks.
* **Threads:** `thread_can_be_forced_to_sleep`, `thread_backtrace_can_be_captured` - Tests thread manipulation and inspection capabilities.
* **RPC:** `method_can_be_called_sync`, `method_can_throw_async` - Tests the Remote Procedure Call functionality, allowing JavaScript to invoke native code.
* **Weak References:** `weak_ref_api_should_be_supported` - Tests memory management features.
* **Interceptor:**  A large section dedicated to `Interceptor` tests (reading/writing arguments, return values, registers, replacing functions, probing instructions). This highlights the core dynamic instrumentation capability of Frida.
* **Memory:** Tests for reading/writing memory, allocation, protection, scanning, and monitoring.
* **Process:**  Tests for accessing process information (architecture, platform, memory layout, threads, modules).
* **Module:** Tests for inspecting loaded modules (imports, exports, symbols, dependencies).
* **ApiResolver:** Tests for finding functions and sections by name.
* **Socket/Stream:** Tests for network communication.
* **Hexdump:** Tests a utility function for displaying memory content.
* **NativePointer/ArrayBuffer/UInt64/Int64:** Tests for working with low-level data types.
* **NativeFunction/SystemFunction/NativeCallback:** Tests for interacting with native code from JavaScript (calling, intercepting, defining callbacks).
* **DebugSymbol:** Tests for resolving addresses to symbols.
* **CModule:** Tests for loading and using compiled C code within the Frida environment.
* **Instruction/CodeWriter/CodeRelocator:** Tests for low-level code manipulation and analysis.
* **File:** Tests for file system access.
* **Checksum:** Tests for calculating checksums of data.
* **Database:** Tests for interacting with SQLite databases.
* **MatchPattern:** Tests for pattern matching functionality.
* **Stalker:** Tests for code tracing and dynamic analysis.
* **ESM/Dynamic/Worker:** Tests for advanced JavaScript features (ECMAScript Modules, dynamic script loading, workers).
* **General Script Properties:** `script_can_be_compiled_to_bytecode`, `script_memory_usage`, etc.

**4. Connecting to Reverse Engineering Concepts:**

While the file itself *tests* Frida's capabilities, those capabilities are *directly used* in reverse engineering.

* **Interception:** The `Interceptor` tests directly relate to hooking functions to analyze their behavior, arguments, and return values – a fundamental reverse engineering technique.
* **Memory Manipulation:** The `Memory` tests demonstrate the ability to read, write, and patch memory, crucial for modifying program behavior.
* **Code Tracing (Stalker):**  The `Stalker` tests show how Frida can be used to trace the execution flow of a program, essential for understanding its logic.
* **Module Inspection:**  The `Module` tests highlight the ability to analyze loaded libraries and their functions.
* **RPC:** The `RPC` tests demonstrate how to interact with native code, enabling interaction with internal program functions.

**5. Relating to Binary/Kernel/Framework Knowledge:**

* **Binary Level:** The `Instruction`, `CodeWriter`, `CodeRelocator`, and `Memory` tests directly deal with manipulating and understanding binary code. Concepts like opcodes, registers, and memory addresses are implicit.
* **Linux/Android Kernel:**  While not explicitly testing kernel interactions *in this file*, the *functionality being tested* relies on underlying OS mechanisms. For example, `thread_backtrace_can_be_captured` relies on OS-level thread information. On Android, interacting with the Java framework (tested by `java_api_is_embedded`) involves understanding the Android runtime environment (ART/Dalvik).
* **Frameworks:** The `objc_api_is_embedded` and `java_api_is_embedded` tests specifically check the integration with Objective-C (iOS/macOS) and Java (Android) frameworks, which are high-level abstractions built on top of the OS.

**6. Logical Reasoning (Hypothetical Inputs/Outputs):**

For a test like `message_can_be_sent_with_data`:

* **Hypothetical Input (in the test setup, not shown in this snippet):**  A JavaScript call to `send("hello", [1, 2, 3])`.
* **Expected Output (assertion within the test):** The test will verify that the host process receives a message with the content "hello" and binary data representing the array `[1, 2, 3]`.

**7. User/Programming Errors:**

* **`invalid_script_should_return_null`:**  A common user error is providing syntactically incorrect JavaScript code. Frida should handle this gracefully.
* **Incorrect API Usage:**  Tests like those in the `Interceptor` section implicitly check for correct API usage. For example, trying to attach an interceptor without providing callbacks (`interceptor_should_refuse_to_attach_without_any_callbacks`) is a user error.
* **Memory Access Issues:** Tests involving `Memory.read*` and `Memory.write*` check for errors when accessing invalid memory addresses.

**8. User Operation to Reach This Code (Debugging Clues):**

A developer working on Frida or using Frida and encountering a bug in the JavaScript engine might end up here:

1. **User runs a Frida script:**  The user executes a Frida script targeting a process.
2. **Script interacts with Frida APIs:** The script uses functions like `Interceptor.attach`, `Memory.read*`, `send`, etc.
3. **Potential bug:**  If something goes wrong (e.g., a message isn't sent correctly, interception fails, memory read crashes), the developer might suspect an issue in the Frida JavaScript engine.
4. **Debugging Frida:**  A Frida developer would then look at the C++ source code for the `gumjs` component. The `tests/gumjs/script.c` file is a natural place to look because it contains comprehensive tests for the JavaScript API.
5. **Running specific tests:** The developer might run specific test cases from `script.c` to isolate the bug or to verify a fix.

**9. Summarizing the Functionality (for Part 1):**

Based on the analysis of the first part (up to `TESTENTRY (timer_cancellation_apis_should_be_forgiving)`), the core functionality covered is:

* **Basic Script Execution and Error Handling:** Loading and running JavaScript code, including handling invalid scripts and enforcing strict mode.
* **Inter-Process Communication:** Sending and receiving messages between the Frida script and the host process, including the ability to send and receive binary data.
* **Asynchronous Operations:** Scheduling timeouts and intervals.
* **Basic Callbacks:** Scheduling simple callbacks for later execution.
* **Robustness of Timer APIs:** Ensuring that cancellation of timers is handled gracefully even if the timer has already fired or doesn't exist.

This detailed breakdown illustrates the step-by-step process of understanding the functionality of a complex code file by analyzing its structure, naming conventions, and individual components, and then connecting it to broader concepts in reverse engineering and software development.
Let's break down the functionality of the provided `script.c` file, which is part of the Frida dynamic instrumentation tool's test suite for its JavaScript engine (`gumjs`).

**Core Functionality:**

This `script.c` file contains a comprehensive suite of unit tests for the JavaScript runtime environment provided by Frida's `gumjs` library. These tests verify various features and APIs exposed to Frida scripts. The primary goal is to ensure the stability and correctness of the JavaScript environment used for dynamic instrumentation.

**Detailed Breakdown of Functionality (Based on Test Names):**

Here's a summary of the functionalities being tested, grouped by category:

**1. Basic Script Execution and Control:**

* **`invalid_script_should_return_null`:** Checks that attempting to load an invalid JavaScript script results in a null return value, indicating failure.
* **`strict_mode_should_be_enforced`:** Verifies that JavaScript's strict mode is correctly enforced within the Frida script environment, catching potential errors.

**2. Data Handling and Communication:**

* **`array_buffer_can_be_created`:** Tests the ability to create and manipulate ArrayBuffer objects in JavaScript, which are used for handling raw binary data.
* **`message_can_be_sent`:** Checks if Frida scripts can send basic text messages back to the host process.
* **`message_can_be_sent_with_data`:**  Verifies the ability to send messages along with binary data (using ArrayBuffers or other data structures).
* **`message_can_be_received`:** Tests if Frida scripts can receive messages sent from the host process.
* **`message_can_be_received_with_data`:** Checks the ability to receive messages containing binary data.
* **`recv_may_specify_desired_message_type`:** Verifies that scripts can filter incoming messages based on their type.
* **`recv_can_be_waited_for_from_an_application_thread`:** Tests if application threads can synchronously wait for messages from the Frida script.
* **`recv_can_be_waited_for_from_two_application_threads`:** Checks if multiple application threads can wait for messages concurrently without issues.
* **`recv_wait_in_an_application_thread_should_not_deadlock`:** Ensures that waiting for messages from an application thread doesn't lead to deadlocks.
* **`recv_can_be_waited_for_from_our_js_thread`:** Tests if the Frida's own JavaScript thread can wait for messages.
* **`recv_wait_in_an_application_thread_should_throw_on_unload`:** Verifies that waiting for messages from an application thread throws an error when the Frida script is unloaded.
* **`recv_wait_in_our_js_thread_should_throw_on_unload`:** Similar to the above, but for the Frida's JavaScript thread.
* **`recv_wait_should_not_leak`:** Checks for memory leaks when waiting for messages.
* **`message_can_be_logged`:** Tests if Frida scripts can use a logging mechanism to output information.

**3. Time and Asynchronous Operations:**

* **`timeout_can_be_scheduled`:** Verifies the ability to schedule code execution after a specified delay using `setTimeout`.
* **`timeout_can_be_cancelled`:** Checks if scheduled timeouts can be successfully cancelled using `clearTimeout`.
* **`interval_can_be_scheduled`:** Tests the ability to schedule code execution repeatedly at a fixed interval using `setInterval`.
* **`interval_can_be_cancelled`:** Verifies that scheduled intervals can be cancelled using `clearInterval`.
* **`callback_can_be_scheduled`:** Tests the ability to schedule callbacks to be executed asynchronously.
* **`callback_can_be_scheduled_from_a_scheduled_callback`:** Checks if callbacks can be scheduled from within other scheduled callbacks.
* **`callback_can_be_cancelled`:** Verifies that scheduled callbacks can be cancelled.
* **`callback_can_be_scheduled_on_next_tick`:** Tests the ability to schedule callbacks to run as soon as possible after the current operation, using mechanisms like `process.nextTick`.
* **`timer_cancellation_apis_should_be_forgiving`:** Ensures that attempting to cancel non-existent timers or already fired timers doesn't cause errors.

**Relationship to Reverse Engineering:**

Many of these tested functionalities are directly used in reverse engineering with Frida:

* **Script Execution:** The foundation of any Frida script.
* **Data Handling (ArrayBuffers):** Essential for inspecting and manipulating binary data structures in the target process's memory.
* **Inter-Process Communication:**  Crucial for getting information back from the target process to the user's Frida script, such as function arguments, return values, or memory contents.
* **Asynchronous Operations (Timeouts, Intervals, Callbacks):** Useful for delaying actions, periodically checking for conditions, or handling events asynchronously within the target process.

**Examples of Reverse Engineering Applications (Related to the First Part):**

* **`message_can_be_sent_with_data`:** A Frida script could hook a function, read a complex data structure from memory, serialize it into an ArrayBuffer, and send it back to the user's script for analysis.
* **`message_can_be_received`:** The user's script could send commands or configuration parameters to the Frida script running in the target process, influencing its behavior.
* **`timeout_can_be_scheduled`:** A Frida script could be used to monitor a specific condition in the target process. If the condition isn't met within a certain timeframe, the script could perform an action (e.g., dump memory, log an event).
* **`interval_can_be_scheduled`:** A Frida script could periodically poll a memory location or check the status of a specific component in the target process.

**Binary Underlying, Linux/Android Kernel, and Frameworks:**

While this specific file primarily tests the JavaScript API, the underlying implementation of these features heavily relies on:

* **Binary Level:** Operations like memory reading and writing, function hooking, and code tracing directly interact with the target process's binary code.
* **Operating System (Linux/Android):**
    * **Process Management:** Frida needs to interact with the OS to inject code into the target process, manage threads, and handle signals.
    * **Memory Management:**  Reading, writing, and allocating memory in the target process relies on OS-level memory management mechanisms.
    * **Threading:**  The tests involving `recv` from application threads highlight the interaction between Frida's threads and the target process's threads.
* **Frameworks (Android):** When targeting Android, Frida often interacts with the Android Runtime (ART) and system services. The ability to access Java objects and methods relies on understanding the Android framework.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `message_can_be_sent_with_data` test:

* **Hypothetical Input (in the test setup, not directly visible in this snippet):** The C code likely executes a Frida script that calls something like `send("data", [1, 2, 3]);`.
* **Expected Output (assertion in the test):** The C code will verify that the host process receives a message with the type "data" and the associated data is a representation of the array `[1, 2, 3]`. This might involve checking the message type and the contents of the data buffer.

**User or Programming Common Usage Errors (and how these tests might catch them):**

* **Incorrectly formatted messages:** Tests ensure that the message sending and receiving mechanisms are robust enough to handle different data types and structures.
* **Deadlocks when waiting for messages:** The `recv_wait_in_an_application_thread_should_not_deadlock` test specifically targets this potential issue, which can occur if synchronization primitives are not used correctly.
* **Memory leaks when handling asynchronous operations:** Tests like `recv_wait_should_not_leak` verify that resources are properly released after waiting for messages.
* **Errors when cancelling timers:** The `timer_cancellation_apis_should_be_forgiving` test handles cases where users might try to cancel timers that don't exist or have already fired.

**User Operation to Reach This Code (Debugging Lineage):**

1. **A Frida developer writes or modifies code in the `gumjs` JavaScript engine.**
2. **To ensure the changes are correct and don't introduce regressions, they run the unit tests.**
3. **The testing framework executes the tests in `script.c`.**
4. **If a test fails, it indicates a problem in the JavaScript engine's implementation.**
5. **The developer examines the failing test case and the corresponding code in `gumjs` to identify and fix the bug.**

Alternatively, if a user encounters a bug while using Frida:

1. **A user runs a Frida script targeting a process.**
2. **The script uses one of the JavaScript APIs tested in `script.c` (e.g., `send`, `setTimeout`).**
3. **An unexpected behavior or error occurs.**
4. **The user or a Frida developer might
### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 * Copyright (C) 2020-2021 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2020 Marcus Mengs <mame8282@googlemail.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 * Copyright (C) 2024 Hillel Pinto <hillelpinto3@gmail.com>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2024 Simon Zuckerbraun <Simon_Zuckerbraun@trendmicro.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "script-fixture.c"

TESTLIST_BEGIN (script)
  TESTENTRY (invalid_script_should_return_null)
  TESTENTRY (strict_mode_should_be_enforced)
  TESTENTRY (array_buffer_can_be_created)
  TESTENTRY (message_can_be_sent)
  TESTENTRY (message_can_be_sent_with_data)
  TESTENTRY (message_can_be_received)
  TESTENTRY (message_can_be_received_with_data)
  TESTENTRY (recv_may_specify_desired_message_type)
  TESTENTRY (recv_can_be_waited_for_from_an_application_thread)
  TESTENTRY (recv_can_be_waited_for_from_two_application_threads)
  TESTENTRY (recv_wait_in_an_application_thread_should_not_deadlock)
  TESTENTRY (recv_can_be_waited_for_from_our_js_thread)
  TESTENTRY (recv_wait_in_an_application_thread_should_throw_on_unload)
  TESTENTRY (recv_wait_in_our_js_thread_should_throw_on_unload)
  TESTENTRY (recv_wait_should_not_leak)
  TESTENTRY (message_can_be_logged)
  TESTENTRY (timeout_can_be_scheduled)
  TESTENTRY (timeout_can_be_cancelled)
  TESTENTRY (interval_can_be_scheduled)
  TESTENTRY (interval_can_be_cancelled)
  TESTENTRY (callback_can_be_scheduled)
  TESTENTRY (callback_can_be_scheduled_from_a_scheduled_callback)
  TESTENTRY (callback_can_be_cancelled)
  TESTENTRY (callback_can_be_scheduled_on_next_tick)
  TESTENTRY (timer_cancellation_apis_should_be_forgiving)
#ifndef HAVE_WINDOWS
  TESTENTRY (crash_on_thread_holding_js_lock_should_not_deadlock)
#endif

  TESTGROUP_BEGIN ("Thread")
    TESTENTRY (thread_can_be_forced_to_sleep)
    TESTENTRY (thread_backtrace_can_be_captured_with_limit)
    TESTENTRY (hardware_breakpoint_can_be_set)
    TESTENTRY (hardware_watchpoint_can_be_set)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("RPC")
    TESTENTRY (method_can_be_called_sync)
    TESTENTRY (method_can_be_called_async)
    TESTENTRY (method_can_throw_sync)
    TESTENTRY (method_can_throw_async)
    TESTENTRY (method_can_return_null)
    TESTENTRY (method_can_receive_binary_data)
    TESTENTRY (method_can_return_binary_data)
    TESTENTRY (method_can_return_value_and_binary_data)
    TESTENTRY (method_list_can_be_queried)
    TESTENTRY (calling_inexistent_method_should_throw_error)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("WeakRef")
    TESTENTRY (weak_ref_api_should_be_supported)
    TESTENTRY (weak_callback_is_triggered_on_gc)
    TESTENTRY (weak_callback_is_triggered_on_unload)
    TESTENTRY (weak_callback_is_triggered_on_unbind)
    TESTENTRY (weak_callback_should_not_be_exclusive)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Interceptor")
    TESTENTRY (argument_can_be_read)
    TESTENTRY (argument_can_be_replaced)
    TESTENTRY (return_value_can_be_read)
    TESTENTRY (return_value_can_be_replaced)
    TESTENTRY (return_address_can_be_read)
    TESTENTRY (general_purpose_register_can_be_read)
    TESTENTRY (general_purpose_register_can_be_written)
    TESTENTRY (vector_register_can_be_read)
    TESTENTRY (double_register_can_be_read)
    TESTENTRY (float_register_can_be_read)
    TESTENTRY (status_register_can_be_read)
    TESTENTRY (system_error_can_be_read_from_interceptor_listener)
    TESTENTRY (system_error_can_be_read_from_replacement_function)
    TESTENTRY (system_error_can_be_replaced_from_interceptor_listener)
    TESTENTRY (system_error_can_be_replaced_from_replacement_function)
    TESTENTRY (system_error_unaffected_by_replacement_if_set_to_original_value)
    TESTENTRY (system_error_unaffected_by_replacement_if_untouched)
    TESTENTRY (invocations_are_bound_on_tls_object)
    TESTENTRY (invocations_provide_thread_id)
    TESTENTRY (invocations_provide_call_depth)
#ifndef HAVE_MIPS
    TESTENTRY (invocations_provide_context_for_backtrace)
#endif
    TESTENTRY (invocations_provide_context_serializable_to_json)
    TESTENTRY (listener_can_be_detached)
    TESTENTRY (listener_can_be_detached_by_destruction_mid_call)
    TESTENTRY (all_listeners_can_be_detached)
    TESTENTRY (function_can_be_replaced)
    TESTENTRY (function_can_be_replaced_and_called_immediately)
    TESTENTRY (function_can_be_reverted)
    TESTENTRY (replaced_function_should_have_invocation_context)
    TESTENTRY (instructions_can_be_probed)
    TESTENTRY (interceptor_should_support_native_pointer_values)
    TESTENTRY (interceptor_should_handle_bad_pointers)
    TESTENTRY (interceptor_should_refuse_to_attach_without_any_callbacks)
#ifdef HAVE_DARWIN
    TESTENTRY (interceptor_and_js_should_not_deadlock)
#endif
  TESTGROUP_END ()
  TESTGROUP_BEGIN ("Interceptor/Fast")
    TESTENTRY (function_can_be_replaced_fast)
    TESTENTRY (function_can_be_replaced_fast_and_called_immediately)
    TESTENTRY (function_can_be_reverted_fast)
    TESTENTRY (interceptor_should_support_native_pointer_values_fast)
    TESTENTRY (interceptor_should_handle_bad_pointers_fast)
    TESTENTRY (function_can_be_replaced_and_call_original_fast)
    TESTENTRY (function_can_be_replaced_fast_performance)
    TESTENTRY (function_can_be_replaced_and_call_original_fast_performance)
  TESTGROUP_END ()
  TESTGROUP_BEGIN ("Interceptor/Performance")
    TESTENTRY (interceptor_on_enter_performance)
    TESTENTRY (interceptor_on_leave_performance)
    TESTENTRY (interceptor_on_enter_and_leave_performance)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Memory")
    TESTENTRY (pointer_can_be_read)
    TESTENTRY (pointer_can_be_read_legacy_style)
    TESTENTRY (pointer_can_be_written)
    TESTENTRY (pointer_can_be_written_legacy_style)
    TESTENTRY (memory_can_be_allocated_with_byte_granularity)
    TESTENTRY (memory_can_be_allocated_with_page_granularity)
    TESTENTRY (memory_can_be_allocated_near_address)
    TESTENTRY (memory_can_be_copied)
    TESTENTRY (memory_can_be_duped)
    TESTENTRY (memory_can_be_protected)
    TESTENTRY (memory_protection_can_be_queried)
    TESTENTRY (code_can_be_patched)
    TESTENTRY (s8_can_be_read)
    TESTENTRY (s8_can_be_written)
    TESTENTRY (u8_can_be_read)
    TESTENTRY (u8_can_be_written)
    TESTENTRY (s16_can_be_read)
    TESTENTRY (s16_can_be_written)
    TESTENTRY (u16_can_be_read)
    TESTENTRY (u16_can_be_written)
    TESTENTRY (s32_can_be_read)
    TESTENTRY (s32_can_be_written)
    TESTENTRY (u32_can_be_read)
    TESTENTRY (u32_can_be_written)
    TESTENTRY (s64_can_be_read)
    TESTENTRY (s64_can_be_written)
    TESTENTRY (u64_can_be_read)
    TESTENTRY (u64_can_be_written)
    TESTENTRY (short_can_be_read)
    TESTENTRY (short_can_be_written)
    TESTENTRY (ushort_can_be_read)
    TESTENTRY (ushort_can_be_written)
    TESTENTRY (int_can_be_read)
    TESTENTRY (int_can_be_written)
    TESTENTRY (uint_can_be_read)
    TESTENTRY (uint_can_be_written)
    TESTENTRY (long_can_be_read)
    TESTENTRY (long_can_be_written)
    TESTENTRY (ulong_can_be_read)
    TESTENTRY (ulong_can_be_written)
    TESTENTRY (float_can_be_read)
    TESTENTRY (float_can_be_written)
    TESTENTRY (double_can_be_read)
    TESTENTRY (double_can_be_written)
    TESTENTRY (byte_array_can_be_read)
    TESTENTRY (byte_array_can_be_written)
    TESTENTRY (c_string_can_be_read)
    TESTENTRY (utf8_string_can_be_read)
    TESTENTRY (utf8_string_can_be_written)
    TESTENTRY (utf8_string_can_be_allocated)
    TESTENTRY (utf16_string_can_be_read)
    TESTENTRY (utf16_string_can_be_written)
    TESTENTRY (utf16_string_can_be_allocated)
#ifdef HAVE_WINDOWS
    TESTENTRY (ansi_string_can_be_read_in_code_page_936)
    TESTENTRY (ansi_string_can_be_read_in_code_page_1252)
    TESTENTRY (ansi_string_can_be_written_in_code_page_936)
    TESTENTRY (ansi_string_can_be_written_in_code_page_1252)
    TESTENTRY (ansi_string_can_be_allocated_in_code_page_936)
    TESTENTRY (ansi_string_can_be_allocated_in_code_page_1252)
#endif
    TESTENTRY (invalid_read_results_in_exception)
    TESTENTRY (invalid_write_results_in_exception)
    TESTENTRY (invalid_read_write_execute_results_in_exception)
    TESTENTRY (memory_can_be_scanned_with_pattern_string)
    TESTENTRY (memory_can_be_scanned_with_match_pattern_object)
    TESTENTRY (memory_can_be_scanned_synchronously)
    TESTENTRY (memory_can_be_scanned_asynchronously)
    TESTENTRY (memory_scan_should_be_interruptible)
    TESTENTRY (memory_scan_handles_unreadable_memory)
    TESTENTRY (memory_scan_handles_bad_arguments)
    TESTENTRY (memory_access_can_be_monitored)
    TESTENTRY (memory_access_can_be_monitored_one_range)
  TESTGROUP_END ()

  TESTENTRY (frida_version_is_available)
  TESTENTRY (frida_heap_size_can_be_queried)

  TESTGROUP_BEGIN ("Process")
    TESTENTRY (process_arch_is_available)
    TESTENTRY (process_platform_is_available)
    TESTENTRY (process_page_size_is_available)
    TESTENTRY (process_pointer_size_is_available)
    TESTENTRY (process_should_support_nested_signal_handling)
    TESTENTRY (process_current_dir_can_be_queried)
    TESTENTRY (process_home_dir_can_be_queried)
    TESTENTRY (process_tmp_dir_can_be_queried)
    TESTENTRY (process_debugger_status_is_available)
    TESTENTRY (process_id_is_available)
    TESTENTRY (process_current_thread_id_is_available)
    TESTENTRY (process_threads_can_be_enumerated)
    TESTENTRY (process_threads_can_be_enumerated_legacy_style)
    TESTENTRY (process_threads_have_names)
    TESTENTRY (process_modules_can_be_enumerated)
    TESTENTRY (process_modules_can_be_enumerated_legacy_style)
    TESTENTRY (process_module_can_be_looked_up_from_address)
    TESTENTRY (process_module_can_be_looked_up_from_name)
    TESTENTRY (process_ranges_can_be_enumerated)
    TESTENTRY (process_ranges_can_be_enumerated_legacy_style)
    TESTENTRY (process_ranges_can_be_enumerated_with_neighbors_coalesced)
    TESTENTRY (process_range_can_be_looked_up_from_address)
    TESTENTRY (process_system_ranges_can_be_enumerated)
#ifdef HAVE_DARWIN
    TESTENTRY (process_malloc_ranges_can_be_enumerated)
    TESTENTRY (process_malloc_ranges_can_be_enumerated_legacy_style)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("RunOnThread")
    TESTENTRY (process_can_run_on_thread_with_success)
    TESTENTRY (process_can_run_on_thread_with_failure)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Module")
    TESTENTRY (module_imports_can_be_enumerated)
    TESTENTRY (module_imports_can_be_enumerated_legacy_style)
    TESTENTRY (module_exports_can_be_enumerated)
    TESTENTRY (module_exports_can_be_enumerated_legacy_style)
    TESTENTRY (module_exports_enumeration_performance)
    TESTENTRY (module_symbols_can_be_enumerated)
    TESTENTRY (module_symbols_can_be_enumerated_legacy_style)
    TESTENTRY (module_ranges_can_be_enumerated)
    TESTENTRY (module_ranges_can_be_enumerated_legacy_style)
    TESTENTRY (module_sections_can_be_enumerated)
    TESTENTRY (module_dependencies_can_be_enumerated)
    TESTENTRY (module_base_address_can_be_found)
    TESTENTRY (module_export_can_be_found_by_name)
    TESTENTRY (module_can_be_loaded)
    TESTENTRY (module_can_be_forcibly_initialized)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ModuleMap")
    TESTENTRY (module_map_values_should_have_module_prototype)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ApiResolver")
    TESTENTRY (api_resolver_can_be_used_to_find_functions)
    TESTENTRY (api_resolver_can_be_used_to_find_functions_legacy_style)
    TESTENTRY (api_resolver_can_be_used_to_find_sections)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Socket")
    TESTENTRY (socket_connection_can_be_established)
    TESTENTRY (socket_connection_can_be_established_with_tls)
    TESTENTRY (socket_connection_should_not_leak_on_error)
    TESTENTRY (socket_type_can_be_inspected)
    TESTENTRY (socket_endpoints_can_be_inspected)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Stream")
#ifdef G_OS_UNIX
    TESTENTRY (unix_fd_can_be_read_from)
    TESTENTRY (unix_fd_can_be_written_to)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Hexdump")
    TESTENTRY (basic_hexdump_functionality_is_available)
    TESTENTRY (hexdump_supports_native_pointer_conforming_object)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativePointer")
    TESTENTRY (native_pointer_provides_is_null)
    TESTENTRY (native_pointer_provides_arithmetic_operations)
    TESTENTRY (native_pointer_provides_uint32_conversion_functionality)
    TESTENTRY (native_pointer_provides_ptrauth_functionality)
    TESTENTRY (native_pointer_provides_arm_tbi_functionality)
    TESTENTRY (native_pointer_to_match_pattern)
    TESTENTRY (native_pointer_can_be_constructed_from_64bit_value)
    TESTENTRY (native_pointer_should_be_serializable_to_json)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ArrayBuffer")
    TESTENTRY (array_buffer_can_wrap_memory_region)
    TESTENTRY (array_buffer_can_be_unwrapped)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("UInt64")
    TESTENTRY (uint64_provides_arithmetic_operations)
    TESTENTRY (uint64_can_be_constructed_from_a_large_number)
    TESTENTRY (uint64_can_be_converted_to_a_large_number)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Int64")
    TESTENTRY (int64_provides_arithmetic_operations)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativeFunction")
    TESTENTRY (native_function_can_be_invoked)
    TESTENTRY (native_function_can_be_invoked_with_size_t)
    TESTENTRY (native_function_can_be_intercepted_when_thread_is_ignored)
    TESTENTRY (native_function_can_not_be_intercepted_when_traps_are_none)
    TESTENTRY (native_function_should_implement_call_and_apply)
    TESTENTRY (native_function_crash_results_in_exception)
    TESTENTRY (nested_native_function_crash_is_handled_gracefully)
    TESTENTRY (variadic_native_function_can_be_invoked)
    TESTENTRY (
        variadic_native_function_args_smaller_than_int_should_be_promoted)
    TESTENTRY (variadic_native_function_float_args_should_be_promoted_to_double)
#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 4
    TESTENTRY (native_function_should_support_fastcall)
    TESTENTRY (native_function_should_support_stdcall)
#endif
    TESTENTRY (native_function_is_a_native_pointer)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("SystemFunction")
    TESTENTRY (system_function_can_be_invoked)
    TESTENTRY (system_function_should_implement_call_and_apply)
    TESTENTRY (system_function_is_a_native_pointer)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("NativeCallback")
    TESTENTRY (native_callback_can_be_invoked)
    TESTENTRY (native_callback_should_provide_access_to_system_error)
    TESTENTRY (native_callback_is_a_native_pointer)
    TESTENTRY (native_callback_memory_should_be_eagerly_reclaimed)
    TESTENTRY (native_callback_should_be_kept_alive_during_calls)
#ifdef HAVE_WINDOWS
# if GLIB_SIZEOF_VOID_P == 4
    TESTENTRY (native_callback_should_support_fastcall)
    TESTENTRY (native_callback_should_support_stdcall)
# endif
    TESTENTRY (native_callback_should_get_accurate_backtraces)
#endif
#ifdef HAVE_DARWIN
    TESTENTRY (native_callback_should_get_accurate_backtraces)
    TESTENTRY (native_callback_should_get_accurate_backtraces_2)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("DebugSymbol")
    TESTENTRY (address_can_be_resolved_to_symbol)
    TESTENTRY (name_can_be_resolved_to_symbol)
    TESTENTRY (function_can_be_found_by_name)
    TESTENTRY (functions_can_be_found_by_name)
    TESTENTRY (functions_can_be_found_by_matching)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("CModule")
#ifdef HAVE_TINYCC
    TESTENTRY (cmodule_can_be_defined)
    TESTENTRY (cmodule_can_be_defined_with_toolchain)
    TESTENTRY (cmodule_can_be_created_from_prebuilt_binary)
    TESTENTRY (cmodule_symbols_can_be_provided)
    TESTENTRY (cmodule_should_report_parsing_errors)
    TESTENTRY (cmodule_should_report_linking_errors)
    TESTENTRY (cmodule_should_provide_lifecycle_hooks)
    TESTENTRY (cmodule_can_be_used_with_interceptor_attach)
    TESTENTRY (cmodule_can_be_used_with_interceptor_replace)
    TESTENTRY (cmodule_can_be_used_with_stalker_events)
    TESTENTRY (cmodule_can_be_used_with_stalker_transform)
    TESTENTRY (cmodule_can_be_used_with_stalker_callout)
    TESTENTRY (cmodule_can_be_used_with_stalker_call_probe)
    TESTENTRY (cmodule_can_be_used_with_module_map)
    TESTENTRY (cmodule_should_provide_some_builtin_string_functions)
    TESTENTRY (cmodule_should_provide_memory_access_apis)
    TESTENTRY (cmodule_should_support_memory_builtins)
    TESTENTRY (cmodule_should_support_arithmetic_builtins)
    TESTENTRY (cmodule_should_support_floating_point)
    TESTENTRY (cmodule_should_support_varargs)
    TESTENTRY (cmodule_should_support_global_callbacks)
    TESTENTRY (cmodule_should_provide_access_to_cpu_registers)
    TESTENTRY (cmodule_should_provide_access_to_system_error)
    TESTENTRY (system_error_unaffected_by_native_callback_from_cmodule)
#else
    TESTENTRY (cmodule_constructor_should_throw_not_available)
#endif
    TESTENTRY (cmodule_builtins_can_be_retrieved)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Instruction")
    TESTENTRY (instruction_can_be_parsed)
    TESTENTRY (instruction_can_be_generated)
    TESTENTRY (instruction_can_be_relocated)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("CodeWriter")
    TESTENTRY (code_writer_should_not_flush_on_gc)
    TESTENTRY (code_writer_should_flush_on_reset)
    TESTENTRY (code_writer_should_flush_on_dispose)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("CodeRelocator")
    TESTENTRY (code_relocator_should_expose_input_instruction)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("File")
    TESTENTRY (whole_file_can_be_read_as_bytes)
    TESTENTRY (whole_file_can_be_read_as_text)
    TESTENTRY (whole_file_can_be_read_as_text_with_validation)
    TESTENTRY (whole_file_can_be_written_from_bytes)
    TESTENTRY (whole_file_can_be_written_from_text)
    TESTENTRY (file_can_be_read_as_bytes_in_one_go)
    TESTENTRY (file_can_be_read_as_bytes_in_chunks)
    TESTENTRY (file_can_be_read_as_text_in_one_go)
    TESTENTRY (file_can_be_read_as_text_in_chunks)
    TESTENTRY (file_can_be_read_as_text_with_validation)
    TESTENTRY (file_can_be_read_line_by_line)
    TESTENTRY (file_can_be_read_line_by_line_with_validation)
    TESTENTRY (file_position_can_be_queried)
    TESTENTRY (file_position_can_be_updated_to_absolute_position_implicitly)
    TESTENTRY (file_position_can_be_updated_to_absolute_position_explicitly)
    TESTENTRY (file_position_can_be_updated_to_relative_position_from_current)
    TESTENTRY (file_position_can_be_updated_to_relative_position_from_end)
    TESTENTRY (file_can_be_written_to)
#ifndef HAVE_QNX
    TESTENTRY (file_apis_can_not_trigger_interceptor)
#endif
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Checksum")
    TESTENTRY (md5_can_be_computed_for_stream)
    TESTENTRY (md5_can_be_computed_for_string)
    TESTENTRY (md5_can_be_computed_for_bytes)
    TESTENTRY (sha1_can_be_computed_for_string)
    TESTENTRY (sha256_can_be_computed_for_string)
    TESTENTRY (sha384_can_be_computed_for_string)
    TESTENTRY (sha512_can_be_computed_for_string)
    TESTENTRY (requesting_unknown_checksum_for_string_should_throw)
  TESTGROUP_END ()

#ifdef HAVE_SQLITE
  TESTGROUP_BEGIN ("Database")
    TESTENTRY (inline_sqlite_database_can_be_queried)
    TESTENTRY (external_sqlite_database_can_be_queried)
    TESTENTRY (external_sqlite_database_can_be_opened_with_flags)
# if !defined (HAVE_WINDOWS) && !defined (HAVE_QNX)
    TESTENTRY (sqlite_apis_can_not_trigger_interceptor)
# endif
  TESTGROUP_END ()
#endif

  TESTGROUP_BEGIN ("MatchPattern")
    TESTENTRY (match_pattern_can_be_constructed_from_string)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Stalker")
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
    TESTENTRY (execution_can_be_traced)
    TESTENTRY (execution_can_be_traced_with_custom_transformer)
    TESTENTRY (execution_can_be_traced_with_faulty_transformer)
    TESTENTRY (execution_can_be_traced_during_immediate_native_function_call)
    TESTENTRY (execution_can_be_traced_during_scheduled_native_function_call)
    TESTENTRY (execution_can_be_traced_after_native_function_call_from_hook)
    TESTENTRY (basic_block_can_be_invalidated_for_current_thread)
    TESTENTRY (basic_block_can_be_invalidated_for_specific_thread)
#endif
#if defined (HAVE_I386) || defined (HAVE_ARM64)
    TESTENTRY (call_can_be_probed)
#endif
    TESTENTRY (stalker_events_can_be_parsed)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("ESM")
    TESTENTRY (esm_in_root_should_be_supported)
    TESTENTRY (esm_in_subdir_should_be_supported)
    TESTENTRY (esm_referencing_subdir_should_be_supported)
    TESTENTRY (esm_referencing_parent_should_be_supported)
    TESTENTRY (esm_throwing_on_load_should_emit_error)
    TESTENTRY (esm_throwing_after_toplevel_await_should_emit_error)
    TESTENTRY (esm_referencing_missing_module_should_fail_to_load)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Dynamic")
    TESTENTRY (dynamic_script_evaluation_should_be_supported)
    TESTENTRY (dynamic_script_evaluation_should_throw_on_syntax_error)
    TESTENTRY (dynamic_script_evaluation_should_throw_on_runtime_error)
    TESTENTRY (dynamic_script_loading_should_be_supported)
    TESTENTRY (dynamic_script_loading_should_throw_on_syntax_error)
    TESTENTRY (dynamic_script_loading_should_throw_on_runtime_error)
    TESTENTRY (dynamic_script_loading_should_throw_on_error_with_toplevel_await)
    TESTENTRY (dynamic_script_loading_should_throw_on_dupe_load_attempt)
    TESTENTRY (dynamic_script_should_support_imports_from_parent)
    TESTENTRY (dynamic_script_should_support_imports_from_other_dynamic_scripts)
    TESTENTRY (dynamic_script_evaluated_should_support_inline_source_map)
    TESTENTRY (dynamic_script_loaded_should_support_inline_source_map)
    TESTENTRY (dynamic_script_loaded_should_support_separate_source_map)
  TESTGROUP_END ()

  TESTGROUP_BEGIN ("Worker")
    TESTENTRY (worker_basics_should_be_supported)
    TESTENTRY (worker_rpc_should_be_supported)
    TESTENTRY (worker_termination_should_be_supported)
  TESTGROUP_END ()

  TESTENTRY (script_can_be_compiled_to_bytecode)
  TESTENTRY (script_should_not_leak_if_destroyed_before_load)
  TESTENTRY (script_memory_usage)
  TESTENTRY (source_maps_should_be_supported_for_our_runtime)
  TESTENTRY (source_maps_should_be_supported_for_user_scripts)
  TESTENTRY (types_handle_invalid_construction)
  TESTENTRY (globals_can_be_dynamically_generated)
  TESTENTRY (exceptions_can_be_handled)
  TESTENTRY (debugger_can_be_enabled)
  TESTENTRY (objc_api_is_embedded)
  TESTENTRY (java_api_is_embedded)
  TESTENTRY (cloaked_items_can_be_queried_added_and_removed)
TESTLIST_END ()

typedef int (* TargetFunctionInt) (int arg);
typedef struct _GumInvokeTargetContext GumInvokeTargetContext;
typedef struct _GumNamedSleeperContext GumNamedSleeperContext;
typedef struct _TestRunOnThreadSyncContext TestRunOnThreadSyncContext;
typedef struct _GumCrashExceptorContext GumCrashExceptorContext;
typedef struct _TestTrigger TestTrigger;

struct _GumInvokeTargetContext
{
  GumScript * script;
  guint repeat_duration;
  volatile gint started;
  volatile gint finished;
};

struct _GumNamedSleeperContext
{
  GAsyncQueue * controller_messages;
  GAsyncQueue * sleeper_messages;
};

struct _TestRunOnThreadSyncContext
{
  GMutex mutex;
  GCond cond;
  gboolean started;
  GumThreadId thread_id;
  gboolean * done;
};

struct _GumCrashExceptorContext
{
  gboolean called;
  GumScriptBackend * backend;
};

struct _TestTrigger
{
  volatile gboolean ready;
  volatile gboolean fired;
  GMutex mutex;
  GCond cond;
};

static size_t gum_get_size_max (void);
static gboolean gum_test_size_max (size_t sz);
static size_t gum_add_size (size_t sz);
static size_t gum_pass_size (size_t u64);
#ifndef _MSC_VER
static size_t gum_pass_ssize (ssize_t ssz);
#endif

static gboolean ignore_thread (GumInterceptor * interceptor);
static gboolean unignore_thread (GumInterceptor * interceptor);

static gint gum_assert_variadic_uint8_values_are_sane (gpointer a, gpointer b,
    gpointer c, gpointer d, ...);
static gint gum_clobber_system_error (gint value);
static gint gum_get_answer_to_life_universe_and_everything (void);
static gint gum_toupper (gchar * str, gint limit);
static gint64 gum_classify_timestamp (gint64 timestamp);
static guint64 gum_square (guint64 value);
static gint gum_sum (gint count, ...);
static gint gum_add_pointers_and_float_fixed (gpointer a, gpointer b, float c);
static gint gum_add_pointers_and_float_variadic (gpointer a, ...);

static gboolean on_incoming_connection (GSocketService * service,
    GSocketConnection * connection, GObject * source_object,
    gpointer user_data);
static void on_read_ready (GObject * source_object, GAsyncResult * res,
    gpointer user_data);

#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
static gpointer run_stalked_through_hooked_function (gpointer data);
static gpointer run_stalked_through_block_invalidated_in_callout (
    gpointer data);
static gpointer run_stalked_through_block_invalidated_by_request (
    gpointer data);
static gpointer run_stalked_through_target_function (gpointer data);
#endif

static gpointer sleeping_dummy (gpointer data);
G_GNUC_UNUSED static gpointer named_sleeper (gpointer data);
static GThread * create_sleeping_dummy_thread_sync (gboolean * done,
    GumThreadId * thread_id);
static gpointer sleeping_dummy_func (gpointer data);
static const gchar * get_local_thread_string_value (void);

static gpointer invoke_target_function_int_worker (gpointer data);
static gpointer invoke_target_function_trigger (gpointer data);

#ifndef HAVE_WINDOWS
static void exit_on_sigsegv (int sig, siginfo_t * info, void * context);
static gboolean on_exceptor_called (GumExceptionDetails * details,
    gpointer user_data);
#ifdef HAVE_DARWIN
static gpointer simulate_crash_handler (gpointer user_data);
static gboolean suspend_all_threads (const GumThreadDetails * details,
    gpointer user_data);
static gboolean resume_all_threads (const GumThreadDetails * details,
    gpointer user_data);
#endif
#endif

static int target_function_int_replacement (int arg);

static void measure_target_function_int_overhead (void);
static int compare_measurements (gconstpointer element_a,
    gconstpointer element_b);

static gboolean check_exception_handling_testable (void);

static void on_script_message (const gchar * message, GBytes * data,
    gpointer user_data);
static void on_incoming_debug_message (GumInspectorServer * server,
    const gchar * message, gpointer user_data);
static void on_outgoing_debug_message (const gchar * message,
    gpointer user_data);

#ifdef HAVE_DARWIN
static gpointer interceptor_attacher_worker (gpointer data);
static void empty_invocation_callback (GumInvocationContext * context,
    gpointer user_data);
#endif

static int target_function_int (int arg);
G_GNUC_UNUSED static float target_function_float (float arg);
G_GNUC_UNUSED static double target_function_double (double arg);
static const guint8 * target_function_base_plus_offset (const guint8 * base,
    int offset);
static const gchar * target_function_string (const gchar * arg);
static void target_function_callbacks (const gint value,
    void (* first) (const gint * value), void (* second) (const gint * value));
static void target_function_trigger (TestTrigger * trigger);
static int target_function_nested_a (int arg);
static int target_function_nested_b (int arg);
static int target_function_nested_c (int arg);

static TargetFunctionInt target_function_original = NULL;
static GPrivate target_thread_string_value = G_PRIVATE_INIT (g_free);

gint gum_script_dummy_global_to_trick_optimizer = 0;

TESTCASE (instruction_can_be_parsed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const first = Instruction.parse(" GUM_PTR_CONST ");"
      "const second = Instruction.parse(first.next);"
      "send(typeof first.toString());"
      "send(typeof second.toString());"
      "send(!second.toString().startsWith('[object'));"
      "send(first.address.toInt32() !== 0);"
      "send(first.size > 0);"
      "send(typeof first.mnemonic);"
      "send(typeof first.opStr);"
      "send(JSON.stringify(first) !== \"{}\");",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  if (!gum_process_is_debugger_attached () && !RUNNING_ON_VALGRIND)
  {
    COMPILE_AND_LOAD_SCRIPT ("Instruction.parse(ptr(\"0x42\"));");
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "Error: access violation accessing 0x42");
  }

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(Process.pageSize);"

      "const cw = new X86Writer(code, { pc: ptr(0x1000) });"
      "send(cw.pc);"
      "send(cw.offset);"
      "cw.putU8(0xab);" /* stosd */
      "send(cw.pc);"
      "send(cw.offset);"
      "send(cw.code.equals(cw.base.add(1)));"
      "cw.putMovRegU32('eax', 42);"
      "cw.putCallRegOffsetPtr('rax', 12);"
      "cw.flush();"

      "const stosd = Instruction.parse(code);"
      "send(stosd.mnemonic);"
      "send(stosd.regsAccessed.read);"
      "send(stosd.regsAccessed.written);"
      "send(stosd.regsRead);"
      "send(stosd.regsWritten);"
      "send(stosd.groups);"

      "const mov = Instruction.parse(stosd.next);"
      "send(mov.mnemonic);"
      "let operands = mov.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[0].size);"
      "send(operands[0].access);"
      "send(operands[1].type);"
      "send(operands[1].value);"
      "send(operands[1].size);"
      "send(operands[1].access);"
      "send(mov.regsAccessed.read);"
      "send(mov.regsAccessed.written);"
      "send(mov.regsRead);"
      "send(mov.regsWritten);"
      "send(mov.groups);"

      "const call = Instruction.parse(mov.next);"
      "send(call.mnemonic);"
      "operands = call.operands;"
      "send(operands[0].type);"
      "const memProps = Object.keys(operands[0].value);"
      "memProps.sort();"
      "send(memProps);"
      "send(operands[0].value.base);"
      "send(operands[0].value.scale);"
      "send(operands[0].value.disp);"
      "send(call.groups);");

  EXPECT_SEND_MESSAGE_WITH ("\"0x1000\"");
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("\"0x1001\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"stosd\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"eax\",\"rdi\",\"rflags\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"rdi\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"eax\",\"rdi\",\"rflags\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"rdi\"]");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  EXPECT_SEND_MESSAGE_WITH ("\"mov\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"eax\"");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("\"w\"");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("\"42\"");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("\"\"");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_SEND_MESSAGE_WITH ("[\"eax\"]");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_SEND_MESSAGE_WITH ("[]");
  EXPECT_SEND_MESSAGE_WITH ("[]");

  EXPECT_SEND_MESSAGE_WITH ("\"call\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"base\",\"disp\",\"scale\"]");
  EXPECT_SEND_MESSAGE_WITH ("\"rax\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("12");
  EXPECT_SEND_MESSAGE_WITH ("[\"call\",\"mode64\"]");
#elif defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(Process.pageSize);"

      "const tw = new ThumbWriter(code);"
      "tw.putLdrRegU32('r0', 42);"
      "tw.putBlImm(code.add(64));"
      /* sxtb.w r3, r7, ror 16 */
      "tw.putInstruction(0xfa4f); tw.putInstruction(0xf3a7);"
      /* vdup.8 d3, d7[1] */
      "tw.putInstruction(0xffb3); tw.putInstruction(0x3c07);"
      "tw.flush();"

      "const ldr = Instruction.parse(code.or(1));"
      "send(ldr.mnemonic);"
      "let operands = ldr.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[0].access);"
      "send(operands[1].type);"
      "send(operands[1].value.base);"
      "send(operands[1].value.scal
```