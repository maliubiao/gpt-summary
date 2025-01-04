Response:
The user wants a detailed analysis of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. The analysis should cover:

1. **Functionality:** What does this specific code do?
2. **Relationship to Reversing:** How can this code be used in reverse engineering? Provide examples.
3. **Low-Level/Kernel/Framework Knowledge:** Does it interact with low-level aspects of operating systems like Linux or Android? Explain.
4. **Logical Reasoning:** Are there any conditional branches or logical deductions? What are the inputs and outputs?
5. **Common User Errors:** What mistakes might a user make when using this code?
6. **User Operation to Reach Here:** How does a user end up executing this code during a Frida session?
7. **Summary of Functionality:** A concise recap of what the code does.

Let's break down the code step by step and address each of these points.

**Code Analysis:**

The provided code consists of several test cases within a larger C file for Frida's GumJS component. Each `TESTCASE` macro likely defines an independent test function. These test cases exercise different functionalities of the `CModule` feature in Frida, which allows embedding and interacting with native C code from JavaScript.

* **`TESTCASE (cmodule_should_support_gum_memory_api)`:** This test case demonstrates how to use Gum's memory scanning API from within a `CModule`. It defines a C function `store_match` which gets called when a match is found during a memory scan initiated from the JavaScript side.

* **`TESTCASE (cmodule_should_support_memory_builtins)`:** This test verifies that basic C memory layout and struct operations work correctly within a `CModule`. It defines structs and performs assignments.

* **`TESTCASE (cmodule_should_support_arithmetic_builtins)`:** This test checks if standard C arithmetic operators (division and modulo) function as expected for different integer types within a `CModule`.

* **`TESTCASE (cmodule_should_support_floating_point)`:**  This confirms that floating-point numbers can be used and returned from functions within a `CModule`.

* **`TESTCASE (cmodule_should_support_varargs)`:** This is a more complex test involving variable arguments (`...`) in C functions within a `CModule`. It demonstrates how to pass different types and structures to these varargs functions and how to handle them. It also utilizes `NativeCallback` to bridge C code back to JavaScript.

* **`TESTCASE (cmodule_should_support_global_callbacks)`:**  This test showcases how to use `NativeCallback` to pass JavaScript functions as callbacks to C functions within a `CModule`. It covers both direct function pointers and pointers stored in memory.

* **`TESTCASE (cmodule_should_provide_access_to_cpu_registers)`:** This test demonstrates the ability to access CPU registers from within a `CModule` using Frida's `GumInvocationContext`. This is a powerful feature for low-level instrumentation. The specific register accessed depends on the architecture.

* **`TESTCASE (cmodule_should_provide_access_to_system_error)`:** This test shows how to interact with the system's error number (errno on Linux/macOS, last error on Windows) from within a `CModule`.

* **`TESTCASE (system_error_unaffected_by_native_callback_from_cmodule)`:** This test ensures that calling a JavaScript `NativeCallback` from within a `CModule` doesn't unintentionally modify the system error number.

* **`TESTCASE (cmodule_constructor_should_throw_not_available)`:** This test checks if the `CModule` constructor throws an error when an unsupported toolchain (like 'internal') is specified. This is related to build configurations of Frida.

* **`TESTCASE (cmodule_builtins_can_be_retrieved)`:** This test verifies that you can access built-in functionalities like defines and headers from the `CModule` object in JavaScript.

* **`TESTCASE (script_can_be_compiled_to_bytecode)`:** This test focuses on Frida's ability to compile JavaScript code into bytecode for potential performance improvements. It tests both successful and failing compilation scenarios.

* **`TESTCASE (script_should_not_leak_if_destroyed_before_load)`:** This test checks for memory leaks in Frida's internal structures when a `GumScript` object is destroyed before being loaded.

* **`TESTCASE (script_memory_usage)`:** This test measures the memory usage associated with creating, loading, and unloading a Frida script. It's a performance-related test.

* **`TESTCASE (esm_...)`:**  These test cases deal with ECMAScript Modules (ESM) support in Frida, covering various scenarios like importing modules from different locations and handling errors during module loading.

* **`TESTCASE (dynamic_script_evaluation_...)`:** These tests cover the `Script.evaluate()` function, which allows executing JavaScript code dynamically. They test for successful evaluation, syntax errors, and runtime errors.

* **`TESTCASE (dynamic_script_loading_...)`:** These tests focus on the `Script.load()` function, which allows loading and executing external JavaScript files dynamically. They cover various scenarios including error handling and module imports.

* **`TESTCASE (dynamic_script_evaluated_should_support_inline_source_map)` and `TESTCASE (dynamic_script_loaded_should_support_inline_source_map)` and `TESTCASE (dynamic_script_loaded_should_support_separate_source_map)`:** These test the integration of source maps with dynamically evaluated and loaded scripts, enabling better debugging experiences.

* **`TESTCASE (worker_basics_should_be_supported)`:** This test verifies basic functionality of Web Workers within Frida's JavaScript environment.

Now, let's address each of the user's requirements systematically.
Let's break down the functionality of this code snippet from `frida/subprojects/frida-gum/tests/gumjs/script.c`. This file appears to contain a series of test cases for the `CModule` and `Script` functionalities within Frida's GumJS engine.

**Functionality of the Code:**

This code tests various aspects of how Frida allows JavaScript to interact with native C code and manage JavaScript execution environments. Here's a breakdown of the key functionalities being tested:

1. **`CModule` Functionality:**
    *   **Embedding and Calling Native C Code:** The tests demonstrate creating `CModule` instances from C source code strings. This allows embedding native code directly into Frida scripts.
    *   **Calling C Functions:**  The tests show how to obtain pointers to functions defined within the `CModule` and call them from JavaScript using `NativeFunction`.
    *   **Memory Operations in C:**  Tests verify that basic memory operations like struct creation, assignment, and accessing members work correctly in the embedded C code.
    *   **Arithmetic Operations in C:** Tests ensure that standard C arithmetic operators function as expected for different integer types.
    *   **Floating-Point Support:**  A test confirms that floating-point numbers can be used and returned from C functions.
    *   **Variable Arguments (Varargs):**  Tests demonstrate calling C functions with variable numbers of arguments from JavaScript. This includes passing different data types and structures.
    *   **Global Callbacks:** Tests show how to pass JavaScript functions as callbacks to C functions within the `CModule` using `NativeCallback`. This enables communication from C back to the JavaScript environment.
    *   **Accessing CPU Registers:**  A crucial test shows how to access CPU registers (like arguments passed to functions) from within a `CModule` during interception.
    *   **Accessing System Error Numbers:** Tests verify the ability to get and set the system's error number (e.g., `errno` on Linux, `GetLastError` on Windows) from the C code.
    *   **System Error Isolation:** A test ensures that calling JavaScript callbacks from C doesn't unintentionally modify the system error number.
    *   **Built-in Access:** Tests confirm access to `CModule.builtins` which provides information about the C compilation environment.

2. **`Script` Functionality:**
    *   **Compiling to Bytecode:**  Tests verify Frida's ability to compile JavaScript code into bytecode for potential performance benefits.
    *   **Dynamic Script Evaluation (`Script.evaluate`)**: Tests how to execute JavaScript code dynamically within a running Frida session.
    *   **Dynamic Script Loading (`Script.load`)**: Tests how to load and execute external JavaScript files dynamically.
    *   **ECMAScript Modules (ESM) Support:**  Several tests explore how Frida handles modern JavaScript modules, including imports from different locations and error handling during loading.
    *   **Source Map Integration:** Tests demonstrate the ability to use source maps (both inline and separate) with dynamically evaluated and loaded scripts, which improves debugging by mapping back to the original source code.
    *   **Web Workers:** A test checks the basic functionality of Web Workers, allowing for parallel execution of JavaScript code within Frida.

**Relationship to Reversing Methods:**

This code is directly related to reverse engineering because it provides the building blocks for Frida's powerful dynamic instrumentation capabilities. Here are some examples:

*   **Hooking Native Functions with Custom Logic:** The `CModule` functionality allows reverse engineers to write custom C code that gets injected into a target process. This C code can then hook or replace native functions. For example, the test case `cmodule_should_provide_access_to_cpu_registers` demonstrates accessing function arguments, which is essential for understanding function behavior during reverse engineering. You could use this to log function arguments, modify return values, or even change the control flow of a program.

    *   **Example:** A reverse engineer could use a `CModule` to hook a function responsible for license validation. By accessing the function's arguments and return value, they could understand how the validation works and potentially bypass it.

*   **Interacting with Native Data Structures:** The ability to define and manipulate C structs within a `CModule` allows reverse engineers to directly interact with the target process's memory and data structures.

    *   **Example:** Imagine reversing a game where player information is stored in a specific struct. A Frida script with a `CModule` could define the same struct and read/modify the player's health, score, or other attributes.

*   **Dynamic Code Injection and Execution:**  The `Script.evaluate` and `Script.load` functionalities are crucial for injecting and executing custom JavaScript code on the fly. This allows for dynamic analysis and modification of the target process's behavior without restarting it.

    *   **Example:**  A reverse engineer might use `Script.load` to load a large script containing hooks for various interesting functions. Or they could use `Script.evaluate` for quick, interactive code execution and exploration.

*   **Tracing and Logging:** The `send()` function used throughout the tests demonstrates how to send data back from the injected C code to the Frida client. This is fundamental for tracing function calls, logging data, and observing the target process's behavior.

**Binary Underlying, Linux, Android Kernel, and Framework Knowledge:**

This code touches upon several low-level concepts:

*   **Binary Structure and Memory Layout:** The `CModule` functionality inherently deals with how code and data are organized in memory. Understanding binary formats (like ELF on Linux or Mach-O on macOS) is helpful when working with native code injection.
*   **CPU Registers and Calling Conventions:** The test case accessing CPU registers directly interacts with the processor's architecture. Understanding calling conventions (how arguments are passed to functions) is essential for interpreting the register values. This differs between architectures (x86, ARM, etc.).
*   **System Calls and Error Handling:** The tests related to system errors (errno, GetLastError) touch upon the interface between user-space programs and the operating system kernel. Understanding how system calls work and how errors are reported is important.
*   **Memory Management:**  The `g_memdup` function used in one of the test cases is a GLib function for memory duplication. Understanding memory allocation and deallocation is crucial to avoid crashes and leaks when working with native code.
*   **Dynamic Linking and Loading:** Frida relies on dynamic linking to inject its agent into the target process. Understanding how shared libraries are loaded and how function addresses are resolved is relevant.
*   **Operating System Concepts:**  Concepts like processes, threads, and memory spaces are fundamental to how Frida operates.
*   **Android's Framework (if targeting Android):** When targeting Android, knowledge of the Android Runtime (ART), Dalvik bytecode, and the Android framework APIs becomes relevant for more advanced instrumentation.

**Logical Reasoning, Assumptions, Inputs, and Outputs:**

Each test case involves a logical flow:

*   **Assumption:** The Frida environment is set up correctly, and the target process is running or can be executed.
*   **Input (in the test code):**  C source code strings, JavaScript code strings, data values passed to functions.
*   **Process:**
    *   Create a `CModule` (compiling C code).
    *   Get function pointers from the `CModule`.
    *   Call these functions with specific arguments from JavaScript or C.
    *   Use Frida's interception mechanisms to hook functions.
    *   Send messages back to the test framework using `send()`.
    *   Perform assertions (`g_assert_*`) to verify expected behavior.
*   **Output (from the target process/Frida):** Values returned from C functions, messages sent back using `send()`, modifications to memory or registers (implicitly tested through assertions).

**Example (from `cmodule_should_support_gum_memory_api`):**

*   **Assumption:** The memory scan functionality in Gum is working correctly.
*   **Input:** A byte array (`haystack`), a JavaScript function to initiate the scan, and a C callback function (`store_match`).
*   **Process:**
    *   The JavaScript code creates a `CModule` with the `store_match` function.
    *   It defines a JavaScript function (`m.scan`) that internally uses Gum's memory scanning.
    *   It calls `m.scan` with a target address (`haystack`).
    *   If a match is found, the `store_match` C function is called.
*   **Output:** The `store_match` function allocates memory and copies the matched bytes into `*match`. The test then asserts that the correct bytes were found. The `send(m.scan)` likely triggers the execution and the result of the scan (likely success/failure) is sent back.

**Common User or Programming Errors:**

When using `CModule` and `Script`, users can make several mistakes:

*   **C Compilation Errors:**  Incorrect C syntax, missing headers, or linking issues within the `CModule` source code will prevent it from compiling correctly. Frida will usually report these errors.
*   **Memory Management Issues in C:**  Failing to `free()` allocated memory in the `CModule` can lead to memory leaks in the target process.
*   **Incorrect Function Signatures:**  When using `NativeFunction`, the JavaScript signature must exactly match the C function signature (argument types and return type). Mismatches can lead to crashes or undefined behavior.
*   **Type Mismatches:**  Passing incorrect data types between JavaScript and C (e.g., passing a string where an integer is expected) can cause errors.
*   **Null Pointer Dereferences in C:**  Accessing memory through a null pointer in the `CModule` will cause a crash.
*   **Security Vulnerabilities:**  Carelessly written C code within a `CModule` could introduce security vulnerabilities into the target process.
*   **Incorrect ESM Syntax:**  Errors in `import` or `export` statements in JavaScript modules will prevent them from loading correctly.
*   **Path Errors in Dynamic Loading:**  Providing incorrect paths to `Script.load` can lead to module loading failures.
*   **Asynchronous Issues:**  When dealing with `async`/`await` and dynamic loading, not handling promises correctly can lead to unexpected behavior.

**User Operations to Reach This Code (as a Debugging Clue):**

A user would typically arrive at this code while:

1. **Developing a Frida Script Using `CModule`:** A user might be writing a Frida script that needs to interact deeply with the target process's native code. They would use the `CModule` constructor to embed C code and `NativeFunction` or `NativeCallback` to communicate between JavaScript and C.
2. **Debugging Issues with `CModule`:** If a Frida script using `CModule` is crashing or behaving unexpectedly, a developer might examine Frida's internal code (like this test file) to understand how `CModule` is implemented and how different features are intended to work.
3. **Investigating Frida's Internals:** A developer contributing to Frida or wanting a deeper understanding of its architecture might browse the source code, including these test files, to see how different components are tested and how they interact.
4. **Reporting Bugs or Issues:** If a user encounters a bug related to `CModule` or dynamic scripting, they might look at the test cases to see if similar scenarios are covered and if the expected behavior matches what they are observing. This can help in providing more detailed bug reports.

**Summary of Functionality (of this code snippet):**

This code snippet provides a comprehensive set of test cases that validate the core functionalities of Frida's `CModule` and dynamic JavaScript execution capabilities. It ensures that embedding native C code, calling C functions from JavaScript, handling various data types, using callbacks, accessing low-level system information, and dynamically managing JavaScript code all function as expected within the Frida instrumentation framework. The tests also cover error handling and the behavior of modern JavaScript modules.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共11部分，请归纳一下它的功能

"""
store_match (GumAddress address,\\n"
      "             gsize size,\\n"
      "             gpointer user_data)\\n"
      "{\\n"
      "  guint8 ** match = user_data;\\n"
      "  *match = g_memdup (GSIZE_TO_POINTER (address), size);\\n"
      "  return FALSE;\\n"
      "}\\n"
      "`);"
      "send(m.scan);");

  scan = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (scan);

  g_assert_false (scan (GSIZE_TO_POINTER (42), &match));
  g_assert_null (match);

  g_assert_true (scan (haystack, &match));
  g_assert_nonnull (match);
  g_assert_cmphex (match[0], ==, 0x13);
  g_assert_cmphex (match[1], ==, 0x37);
  g_assert_cmphex (match[2], ==, 0x44);
  g_assert_cmphex (match[3], ==, 0x42);
  g_free (match);
}

TESTCASE (cmodule_should_support_memory_builtins)
{
  int (* f) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule(`"
      "struct Pos1 { char x; char y; };\n"
      "struct Pos4 { int x; int y; };\n"
      "struct Pos8 { double x; double y; };\n"
      "\n"
      "int\n"
      "f (void)\n"
      "{\n"
      "  struct Pos1 a = { 0, }, b;\n"
      "  struct Pos4 c = { 0, }, d;\n"
      "  struct Pos8 e = { 0, }, f;\n"
      "  b = a;\n"
      "  d = c;\n"
      "  f = e;\n"
      "  return a.x + a.y + b.x + d.x + f.x;\n"
      "}\n"
      "`);"
      "send(m.f);");

  f = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (f);
  g_assert_cmpint (f (), ==, 0);
}

TESTCASE (cmodule_should_support_arithmetic_builtins)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule(`"
      "#include <stdint.h>\n"
      "\n"
      "int\n"
      "test_int_ops (int a,\n"
      "              int b)\n"
      "{\n"
      "  return (a / b) + (a %% b);\n"
      "}\n"
      "\n"
      "unsigned\n"
      "test_unsigned_ops (unsigned a,\n"
      "                   unsigned b)\n"
      "{\n"
      "  return (a / b) + (a %% b);\n"
      "}\n"
      "\n"
      "int64_t\n"
      "test_int64_ops (int64_t a,\n"
      "                int64_t b)\n"
      "{\n"
      "  return (a / b) + (a %% b);\n"
      "}\n"
      "`);"
      "send(m.test_int_ops);"
      "send(m.test_unsigned_ops);"
      "send(m.test_int64_ops);");

  {
    int (* test_int_ops) (int a, int b);

    test_int_ops = EXPECT_SEND_MESSAGE_WITH_POINTER ();
    g_assert_nonnull (test_int_ops);
    g_assert_cmpint (test_int_ops (16, 3), ==, 6);
  }

  {
    unsigned (* test_unsigned_ops) (unsigned a, unsigned b);

    test_unsigned_ops = EXPECT_SEND_MESSAGE_WITH_POINTER ();
    g_assert_nonnull (test_unsigned_ops);
    g_assert_cmpint (test_unsigned_ops (16, 3), ==, 6);
  }

  {
    gint64 (* test_int64_ops) (gint64 a, gint64 b);

    test_int64_ops = EXPECT_SEND_MESSAGE_WITH_POINTER ();
    g_assert_nonnull (test_int64_ops);
    g_assert_cmpint (test_int64_ops (16, 3), ==, 6);
  }
}

TESTCASE (cmodule_should_support_floating_point)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule([\n"
      "  '#include <glib.h>',\n"
      "  '',\n"
      "  'gdouble',\n"
      "  'measure (void)',\n"
      "  '{',\n"
      "  '  return 42.0;',\n"
      "  '}',\n"
      "].join('\\n'));\n"
      "\n"
      "const measure = new NativeFunction(m.measure, 'double', []);\n"
      "send(measure().toFixed(0));\n");
  EXPECT_SEND_MESSAGE_WITH ("\"42\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_support_varargs)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule([\n"
      "  '#include <glib.h>',\n"
      "  '#include <stdio.h>',\n"
      "  '',\n"
      "  'typedef struct _MediumObj MediumObj;',\n"
      "  'typedef struct _LargeObj LargeObj;',\n"
      "  '',\n"
      "  'struct _MediumObj',\n"
      "  '{',\n"
      "  '  guint64 a;',\n"
      "  '  guint64 b;',\n"
      "  '};',\n"
      "  '',\n"
      "  'struct _LargeObj',\n"
      "  '{',\n"
      "  '  guint64 a;',\n"
      "  '  guint64 b;',\n"
      "  '  guint8 c;',\n"
      "  '};',\n"
      "  '',\n"
      "  'extern void deliver (const gchar * m1, const gchar * m2);',\n"
      "  '',\n"
      "  'static void log_generic (guint8 a1, guint16 a2, guint8 a3,',\n"
      "  '    guint8 a4, guint8 a5, guint8 a6, guint8 a7, guint8 a8,',\n"
      "  '    guint8 a9, guint8 a10, const gchar * format, ...);',\n"
      "  'static void log_special (const gchar * format, ...);',\n"
      "  '',\n"
      "  'void',\n"
      "  'sayHello (const gchar * name,',\n"
      "  '          guint8 x,',\n"
      "  '          guint8 y)',\n"
      "  '{',\n"
      "  '  // printf (\"Hello %%s, x=%%u, y=%%u\\\\n\", name, x, y);',\n"
      "  '  log_generic (201, 202, 203, 204, 205, 206, 207, 208, 209,',\n"
      "  '      210, \"Hello %%s, x=%%u, y=%%u\", name, x, y);',\n"
      "  '  {',\n"
      "  '    MediumObj m = { 100, 101 };',\n"
      "  '    LargeObj l = { 150, 151, 152 };',\n"
      "  '    log_special (\"slsm\", (guint8) 42, l, (guint8) 24, m);',\n"
      "  '  }',\n"
      "  '}',\n"
      "  '',\n"
      "  'static void',\n"
      "  'log_generic (guint8 a1,',\n"
      "  '             guint16 a2,',\n"
      "  '             guint8 a3,',\n"
      "  '             guint8 a4,',\n"
      "  '             guint8 a5,',\n"
      "  '             guint8 a6,',\n"
      "  '             guint8 a7,',\n"
      "  '             guint8 a8,',\n"
      "  '             guint8 a9,',\n"
      "  '             guint8 a10,',\n"
      "  '             const gchar * format,',\n"
      "  '             ...)',\n"
      "  '{',\n"
      "  '  gchar * m1, * m2;',\n"
      "  '  va_list args;',\n"
      "  '',\n"
      "  '  m1 = g_strdup_printf (\"%%u %%u %%u %%u %%u %%u %%u %%u %%u %%u\","
          "',\n"
      "  '      a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);',\n"
      "  '',\n"
      "  '  va_start (args, format);',\n"
      "  '  m2 = g_strdup_vprintf (format, args);',\n"
      "  '  va_end (args);',\n"
      "  '',\n"
      "  '  deliver (m1, m2);',\n"
      "  '',\n"
      "  '  g_free (m2);',\n"
      "  '  g_free (m1);',\n"
      "  '}',\n"
      "  '',\n"
      "  'static void',\n"
      "  'log_special (const gchar * format,',\n"
      "  '             ...)',\n"
      "  '{',\n"
      "  '  GString * message;',\n"
      "  '  va_list args;',\n"
      "  '  const gchar * p;',\n"
      "  '',\n"
      "  '  message = g_string_new (\"Yo\");',\n"
      "  '',\n"
      "  '  va_start (args, format);',\n"
      "  '',\n"
      "  '  p = format;',\n"
      "  '  while (*p != \\'\\\\0\\')',\n"
      "  '  {',\n"
      "  '    g_string_append_c (message, \\' \\');',\n"
      "  '',\n"
      "  '    switch (*p)',\n"
      "  '    {',\n"
      "  '      case \\'s\\':',\n"
      "  '      {',\n"
      "  '        unsigned int v = va_arg (args, unsigned int);',\n"
      "  '        g_string_append_printf (message, \"%%u\", v);',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      case \\'m\\':',\n"
      "  '      {',\n"
      "  '        MediumObj v = va_arg (args, MediumObj);',\n"
      "  '        g_string_append_printf (message, \"(%%\" G_GINT64_MODIFIER',"
      "  '            \"u, %%\" G_GINT64_MODIFIER \"u)\", v.a, v.b);',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      case \\'l\\':',\n"
      "  '      {',\n"
      "  '        LargeObj v = va_arg (args, LargeObj);',\n"
      "  '        g_string_append_printf (message, \"(%%\" G_GINT64_MODIFIER',"
      "  '            \"u, %%\" G_GINT64_MODIFIER \"u, %%u)\", v.a, v.b, v.c);"
          "',\n"
      "  '        break;',\n"
      "  '      }',\n"
      "  '      default:',\n"
      "  '        printf (\"Oops!\\\\n\");',\n"
      "  '        break;',\n"
      "  '    }',\n"
      "  '',\n"
      "  '    p++;',\n"
      "  '  }',\n"
      "  '',\n"
      "  '  va_end (args);',\n"
      "  '',\n"
      "  '  deliver (\"Also\", message->str);',\n"
      "  '',\n"
      "  '  g_string_free (message, TRUE);',\n"
      "  '}',\n"
      "].join('\\n'), {\n"
      "  deliver: new NativeCallback((m1, m2) => {\n"
      "    send([m1.readUtf8String(), m2.readUtf8String()]);\n"
      "  }, 'void', ['pointer', 'pointer'])\n"
      "});\n"
      "\n"
      "const sayHello = new NativeFunction(m.sayHello, 'void',\n"
      "    ['pointer', 'uint8', 'uint8']);\n"
      "sayHello(Memory.allocUtf8String('World'), 42, 24);\n");

  EXPECT_SEND_MESSAGE_WITH ("[\"201 202 203 204 205 206 207 208 209 210\","
      "\"Hello World, x=42, y=24\"]");
  EXPECT_SEND_MESSAGE_WITH ("[\"Also\",\"Yo 42 (150, 151, 152) 24 (100, 101)"
      "\"]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_support_global_callbacks)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback(n => { send(n); }, 'void', ['int']);"
      "const cbPtr = Memory.alloc(Process.pointerSize);"
      "cbPtr.writePointer(cb);"
      ""
      "const m = new CModule('"
      "\\n"
      "extern void notify1 (int n);\\n"
      "extern void (* notify2) (int n);\\n"
      "extern void (* notify3) (int n);\\n"
      "\\n"
      "static void notify3_impl (int n);\\n"
      "\\n"
      "void\\n"
      "init (void)\\n"
      "{\\n"
      "  notify1 (42);\\n"
      "  notify2 (43);\\n"
      "  notify3 = notify3_impl;\\n"
      "  notify3 (44);\\n"
      "}\\n"
      "\\n"
      "static void\\n"
      "notify3_impl (int n)\\n"
      "{\\n"
      "  notify1 (n);\\n"
      "}\\n"
      "\\n"
      "', {"
      "  notify1: cb,"
      "  notify2: cbPtr,"
      "  notify3: Memory.alloc(Process.pointerSize)"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("43");
  EXPECT_SEND_MESSAGE_WITH ("44");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (cmodule_should_provide_access_to_cpu_registers)
{
  int seen_value = -1;
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_IC_GET_FIRST_ARG(ic) *((int *) ((ic)->cpu_context->esp + 4))
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# ifdef HAVE_WINDOWS
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->rcx
# else
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->rdi
# endif
#elif defined (HAVE_ARM)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->r[0]
#elif defined (HAVE_ARM64)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->x[0]
#elif defined (HAVE_MIPS)
# define GUM_IC_GET_FIRST_ARG(ic) (ic)->cpu_context->a0
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const cm = new CModule('"
      "  #include <gum/guminterceptor.h>\\n"
      "\\n"
      "  extern int seenValue;\\n"
      ""
      "  void\\n"
      "  onEnter (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    seenValue = " G_STRINGIFY (GUM_IC_GET_FIRST_ARG (ic)) ";\\n"
      "  }\\n"
      "\\n"
      "', { seenValue: " GUM_PTR_CONST "});"
      "Interceptor.attach(" GUM_PTR_CONST ", cm);",
      &seen_value,
      target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  g_assert_cmpint (seen_value, ==, 42);
}

TESTCASE (cmodule_should_provide_access_to_system_error)
{
  void (* bump_impl) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "const m = new CModule('"
      "#include <gum/gumprocess.h>\\n"
      ""
      "void\\n"
      "bump (void)\\n"
      "{\\n"
      "  gum_thread_set_system_error (gum_thread_get_system_error () + 1);\\n"
      "}"
      "');"
      "send(m.bump);");

  bump_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (bump_impl);

  gum_thread_set_system_error (1);
  bump_impl ();
  g_assert_cmpint (gum_thread_get_system_error (), ==, 2);
}

TESTCASE (system_error_unaffected_by_native_callback_from_cmodule)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const cm = new CModule(`\\n"
      "  #include <gum/guminterceptor.h>\\n"
      "\\n"
      "  extern void nativeCallback (void);\\n"
      "\\n"
      "  void\\n"
      "  replacement (GumInvocationContext * ic)\\n"
      "  {\\n"
      "    nativeCallback ();\\n"
      "  }\\n"
      "`, {\n"
      "  nativeCallback: new NativeCallback(() => {}, 'void', [])\n"
      "});\n"
      "Interceptor.replace(" GUM_PTR_CONST ", cm.replacement);",
      target_function_int);

#ifdef HAVE_WINDOWS
  SetLastError (1337);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  errno = 1337;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

#else /* !HAVE_TINYCC */

TESTCASE (cmodule_constructor_should_throw_not_available)
{
  COMPILE_AND_LOAD_SCRIPT ("new CModule('', {}, { toolchain: 'internal' });");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: internal toolchain is not available in this build configuration");
}

#endif

TESTCASE (cmodule_builtins_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const { builtins } = CModule;"
      "send(typeof builtins);"
      "send(typeof builtins.defines);"
      "send(typeof builtins.headers);");
  EXPECT_SEND_MESSAGE_WITH ("\"object\"");
  EXPECT_SEND_MESSAGE_WITH ("\"object\"");
  EXPECT_SEND_MESSAGE_WITH ("\"object\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (script_can_be_compiled_to_bytecode)
{
  GError * error;
  GBytes * code;
  GumScript * script;

  error = NULL;
  code = gum_script_backend_compile_sync (fixture->backend, "testcase",
      "send(1337);\noops;", NULL, &error);
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (code);
    g_assert_no_error (error);

    g_assert_null (gum_script_backend_compile_sync (fixture->backend,
        "failcase1", "'", NULL, NULL));

    g_assert_null (gum_script_backend_compile_sync (fixture->backend,
        "failcase2", "'", NULL, &error));
    g_assert_nonnull (error);
    g_assert_true (g_str_has_prefix (error->message,
        "Script(line 1): SyntaxError: "));
    g_clear_error (&error);
  }
  else
  {
    g_assert_null (code);
    g_assert_nonnull (error);
    g_assert_cmpstr (error->message, ==,
        "compilation to bytecode is not supported by the V8 runtime");
    g_clear_error (&error);

    code = g_bytes_new (NULL, 0);
  }

  script = gum_script_backend_create_from_bytes_sync (fixture->backend, code,
      NULL, NULL, &error);
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    TestScriptMessageItem * item;

    g_assert_nonnull (script);
    g_assert_no_error (error);

    gum_script_set_message_handler (script, test_script_fixture_store_message,
        fixture, NULL);

    gum_script_load_sync (script, NULL);

    EXPECT_SEND_MESSAGE_WITH ("1337");

    item = test_script_fixture_pop_message (fixture);
    g_assert_nonnull (strstr (item->message, "ReferenceError"));
    g_assert_null (strstr (item->message, "agent.js"));
    g_assert_nonnull (strstr (item->message, "testcase.js"));
    test_script_message_item_free (item);

    EXPECT_NO_MESSAGES ();

    g_object_unref (script);
  }
  else
  {
    g_assert_null (script);
    g_assert_nonnull (error);
    g_assert_cmpstr (error->message, ==,
        "script creation from bytecode is not supported by the V8 runtime");
    g_clear_error (&error);
  }

  g_bytes_unref (code);
}

TESTCASE (script_should_not_leak_if_destroyed_before_load)
{
  GumExceptor * held_instance;
  guint ref_count_before;
  GumScript * script;

  held_instance = gum_exceptor_obtain ();
  ref_count_before = G_OBJECT (held_instance)->ref_count;

  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "console.log('Hello World');", NULL, NULL, NULL);
  g_object_unref (script);

  g_assert_cmpuint (G_OBJECT (held_instance)->ref_count, ==, ref_count_before);
  g_object_unref (held_instance);
}

TESTCASE (script_memory_usage)
{
  GumScript * script;
  GTimer * timer;
  guint before, after;

  if (!GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<skipped due to runtime> ");
    return;
  }

  /* Warm up */
  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "const foo = 42;", NULL, NULL, NULL);
  gum_script_load_sync (script, NULL);
  gum_script_unload_sync (script, NULL);
  g_object_unref (script);

  timer = g_timer_new ();

  before = gum_peek_private_memory_usage ();

  g_timer_reset (timer);
  script = gum_script_backend_create_sync (fixture->backend, "testcase",
      "const foo = 42;", NULL, NULL, NULL);
  g_print ("created in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  g_timer_reset (timer);
  gum_script_load_sync (script, NULL);
  g_print ("loaded in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  after = gum_peek_private_memory_usage ();
  g_print ("memory usage: %u bytes\n", after - before);

  g_timer_reset (timer);
  gum_script_unload_sync (script, NULL);
  g_print ("unloaded in %u ms\n",
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));

  g_object_unref (script);
}

TESTCASE (esm_in_root_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "57 /main.js\n"
      "27 /dependency.js\n"
      "✄\n"
      "import { value } from './dependency.js';\n"
      "send({ value });\n"
      "✄\n"
      "export const value = 1337;\n");
  EXPECT_SEND_MESSAGE_WITH ("{\"value\":1337}");
}

TESTCASE (esm_in_subdir_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "57 /lib/main.js\n"
      "27 /lib/dependency.js\n"
      "✄\n"
      "import { value } from './dependency.js';\n"
      "send({ value });\n"
      "✄\n"
      "export const value = 1337;\n");
  EXPECT_SEND_MESSAGE_WITH ("{\"value\":1337}");
}

TESTCASE (esm_referencing_subdir_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "61 /main.js\n"
      "27 /lib/dependency.js\n"
      "✄\n"
      "import { value } from './lib/dependency.js';\n"
      "send({ value });\n"
      "✄\n"
      "export const value = 1337;\n");
  EXPECT_SEND_MESSAGE_WITH ("{\"value\":1337}");
}

TESTCASE (esm_referencing_parent_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "58 /lib/main.js\n"
      "27 /dependency.js\n"
      "✄\n"
      "import { value } from '../dependency.js';\n"
      "send({ value });\n"
      "✄\n"
      "export const value = 1337;\n");
  EXPECT_SEND_MESSAGE_WITH ("{\"value\":1337}");
}

TESTCASE (esm_throwing_on_load_should_emit_error)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "6 /main.js\n"
      "✄\n"
      "oops;\n");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "ReferenceError: 'oops' is not defined"
        : "ReferenceError: oops is not defined");
}

TESTCASE (esm_throwing_after_toplevel_await_should_emit_error)
{
  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "122 /main.js\n"
      "✄\n"
      "await sleep(10);\n"
      "oops;\n"
      "\n"
      "function sleep(duration) {\n"
      "  return new Promise(resolve => { setTimeout(resolve, duration); });\n"
      "}\n");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "ReferenceError: 'oops' is not defined"
        : "ReferenceError: oops is not defined");
}

TESTCASE (esm_referencing_missing_module_should_fail_to_load)
{
  const gchar * source =
      "📦\n"
      "41 /main.js\n"
      "✄\n"
      "import { value } from './dependency.js';\n";
  GError * error = NULL;

  g_assert_null (gum_script_backend_create_sync (fixture->backend,
      "testcase", source, NULL, NULL, &error));
  g_assert_nonnull (error);
  g_assert_cmpstr (error->message, ==,
      "Could not load module '/dependency.js'");
  g_error_free (error);
}

TESTCASE (dynamic_script_evaluation_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const result = Script.evaluate('/x.js', 'const x = 42; 1337;');"
      "send([result, x]);");
  EXPECT_SEND_MESSAGE_WITH ("[1337,42]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (dynamic_script_evaluation_should_throw_on_syntax_error)
{
  COMPILE_AND_LOAD_SCRIPT ("Script.evaluate('/x.js', 'const x = \\'');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "Error: could not parse '/x.js' line 1: unexpected end of string"
        : "Error: could not parse '/x.js' line 1: Invalid or unexpected token");
}

TESTCASE (dynamic_script_evaluation_should_throw_on_runtime_error)
{
  COMPILE_AND_LOAD_SCRIPT ("Script.evaluate('/x.js', 'x');");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "ReferenceError: 'x' is not defined"
        : "ReferenceError: x is not defined");
}

TESTCASE (dynamic_script_loading_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "async function main() {"
        "const m = await Script.load('/x.js',"
            "'export const x = 42; send(\\'A\\');');"
        "send(typeof x);"
        "send(m.x);"
      "}"
      "main().catch(e => send(e.stack));");
  EXPECT_SEND_MESSAGE_WITH ("\"A\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (dynamic_script_loading_should_throw_on_syntax_error)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.load('/x.js', 'const x = \\'')"
          ".catch(e => { send(e.message); });");
  EXPECT_SEND_MESSAGE_WITH (
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "\"could not parse '/x.js' line 1: unexpected end of string\""
        : "\"could not parse '/x.js' line 1: Invalid or unexpected token\"");
}

TESTCASE (dynamic_script_loading_should_throw_on_runtime_error)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.load('/x.js', 'x')"
          ".catch(e => { send(e.message); });");
  EXPECT_SEND_MESSAGE_WITH (
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "\"'x' is not defined\""
        : "\"x is not defined\"");
}

TESTCASE (dynamic_script_loading_should_throw_on_error_with_toplevel_await)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.load('/x.js',"
          "`"
            "await sleep(10);\n"
            "x;\n"
            "\n"
            "function sleep(duration) {\n"
              "return new Promise(resolve => {\n"
                "setTimeout(resolve, duration);\n"
              "});\n"
            "}\n"
          "`)"
          ".catch(e => { send(e.message); });");
  EXPECT_SEND_MESSAGE_WITH (
      GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
        ? "\"'x' is not defined\""
        : "\"x is not defined\"");
}

TESTCASE (dynamic_script_loading_should_throw_on_dupe_load_attempt)
{
  COMPILE_AND_LOAD_SCRIPT (
      "async function main() {"
        "await Script.load('/x.js', 'true');"
        "Script.load('/x.js', 'true').catch(e => { send(e.message); });"
      "}"
      "main().catch(e => { Script.nextTick(() => { throw e; }); });");
  EXPECT_SEND_MESSAGE_WITH ("\"module '/x.js' already exists\"");
}

TESTCASE (dynamic_script_should_support_imports_from_parent)
{
  const gchar * source =
      "export const value = 1337;"

      "async function main() {"
        "await Script.load('/plugin.js', `"
          "import { value } from '/main.js';"
          "send(value);"
        "`);"
      "}"

      "main().catch(e => send(e.stack));";

  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "%u /main.js\n"
      "✄\n"
      "%s",
      (guint) strlen (source),
      source);
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (dynamic_script_should_support_imports_from_other_dynamic_scripts)
{
  COMPILE_AND_LOAD_SCRIPT (
      "async function main() {"
        "await Script.load('/dependency.js', 'export const value = 1337;');"
        "await Script.load('/main.js', `"
          "import { value } from './dependency.js';"
          "send(value);"
        "`);"
      "}"
      "main().catch(e => send(e.stack));");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (dynamic_script_evaluated_should_support_inline_source_map)
{
  TestScriptMessageItem * item;

  /*
   * agent/index.ts
   * --------
   * 01 import * as math from "./math";
   * 02
   * 03 try {
   * 04     math.add(3, 4);
   * 05 } catch (e) {
   * 06     send((e as Error).stack);
   * 07 }
   *
   * agent/math.ts
   * -------
   * 01 export function add(a: number, b: number): number {
   * 02     throw new Error("not yet implemented");
   * 03 }
   */
  COMPILE_AND_LOAD_SCRIPT (
      "Script.evaluate('/user.js', `(function(){function r(e,n,t){function o(i,"
        "f){if(!n[i]){if(!e[i]){var c=\"function\"==typeof require&&require;if("
        "!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error(\"Cannot find"
        " module '\"+i+\"'\");throw a.code=\"MODULE_NOT_FOUND\",a}var p=n[i]={e"
        "xports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return "
        "o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u=\"function"
        "\"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return"
        " r})()({1:[function(require,module,exports){\n"
        "\"use strict\";\n"
        "Object.defineProperty(exports, \"__esModule\", { value: true });\n"
        "const math = require(\"./math\");\n"
        "try {\n"
        "    math.add(3, 4);\n"
        "}\n"
        "catch (e) {\n"
        "    send(e.stack);\n"
        "}\n"
        "\n"
        "},{\"./math\":2}],2:[function(require,module,exports){\n"
        "\"use strict\";\n"
        "Object.defineProperty(exports, \"__esModule\", { value: true });\n"
        "exports.add = void 0;\n"
        "function add(a, b) {\n"
        "    throw new Error(\"not yet implemented\");\n"
        "}\n"
        "exports.add = add;\n"
        "\n"
        "},{}]},{},[1])\n"
        "//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZX"
        "JzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1"
        "ZGUuanMiLCJhZ2VudC9pbmRleC50cyIsImFnZW50L21hdGgudHMiXSwibmFtZXMiOltdLC"
        "JtYXBwaW5ncyI6IkFBQUE7OztBQ0FBLCtCQUErQjtBQUUvQixJQUFJO0lBQ0EsSUFBSSxD"
        "QUFDLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUM7Q0FDbEI7QUFBQyxPQU"
        "FPLENBQUMsRUFBRTtJQUNSLElBQUksQ0FBRSxDQUFXLENBQUMsS0FBSyxDQUFDLENBQUM7"
        "Q0FDNUI7Ozs7OztBQ05ELFNBQWdCLEdBQUcsQ0FBQyxDQUFTLEVBQUUsQ0FBUztJQUNwQy"
        "xNQUFNLElBQUksS0FBSyxDQUFDLHFCQUFxQixDQUFDLENBQUM7QUFDM0MsQ0FBQztBQUZE"
        "LGtCQUVDIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==\n"
      "`);");

  item = test_script_fixture_pop_message (fixture);
  g_assert_nonnull (strstr (item->message, "\"type\":\"send\""));
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at add (agent/math.ts:2)\\n"
        "    at <anonymous> (agent/index.ts:4)\\n"
        "    at call (native)\\n"
        "    at o (node_modules/browser-pack/_prelude.js:1)\\n"
        "    at r (node_modules/browser-pack/_prelude.js:1)\\n"
        "    at <eval> (/user.js:21)"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at Object.add (agent/math.ts:2:11)\\n"
        "    at Object.1../math (agent/index.ts:4:10)\\n"
        "    at o (node_modules/browser-pack/_prelude.js:1:1)\\n"
        "    at r (node_modules/browser-pack/_prelude.js:1:1)\\n"
        "    at node_modules/browser-pack/_prelude.js:1:1"));
  }
  test_script_message_item_free (item);
}

TESTCASE (dynamic_script_loaded_should_support_inline_source_map)
{
  TestScriptMessageItem * item;

  /*
   * agent/index.ts
   * --------
   * 01 import * as math from "./math.js";
   * 02
   * 03 try {
   * 04     math.add(3, 4);
   * 05 } catch (e) {
   * 06     send((e as Error).stack);
   * 07 }
   *
   * agent/math.ts
   * -------
   * 01 export function add(a: number, b: number): number {
   * 02     throw new Error("not yet implemented");
   * 03 }
   */
  COMPILE_AND_LOAD_SCRIPT (
      "async function main() {"
        "await Script.load('/agent/math.js', `"
          "export function add(a, b) {\n"
          "    throw new Error(\"not yet implemented\");\n"
          "}\n"
          "//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2"
          "ZXJzaW9uIjozLCJmaWxlIjoibWF0aC5qcyIsInNvdXJjZVJvb3QiOiIvVXNlcnMvb2xl"
          "YXZyL3NyYy9mcmlkYS1hZ2VudC1leGFtcGxlLyIsInNvdXJjZXMiOlsiYWdlbnQvbWF0"
          "aC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxNQUFNLFVBQVUsR0FBRyxD"
          "QUFDLENBQVMsRUFBRSxDQUFTO0lBQ3BDLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFC"
          "LENBQUMsQ0FBQztBQUMzQyxDQUFDIn0=\n"
        "`);"
        "await Script.load('/agent/index.js', `"
          "import * as math from \"./math.js\";\n"
          "try {\n"
          "    math.add(3, 4);\n"
          "}\n"
          "catch (e) {\n"
          "    send(e.stack);\n"
          "}\n"
          "//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2"
          "ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiL1VzZXJzL29s"
          "ZWF2ci9zcmMvZnJpZGEtYWdlbnQtZXhhbXBsZS8iLCJzb3VyY2VzIjpbImFnZW50L2lu"
          "ZGV4LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE9BQU8sS0FBSyxJQUFJ"
          "LE1BQU0sV0FBVyxDQUFDO0FBRWxDLElBQUk7SUFDQSxJQUFJLENBQUMsR0FBRyxDQUFD"
          "LENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztDQUNsQjtBQUFDLE9BQU8sQ0FBQyxFQUFF"
          "O0lBQ1IsSUFBSSxDQUFFLENBQVcsQ0FBQyxLQUFLLENBQUMsQ0FBQztDQUM1QiJ9\n"
        "`);"
      "}"
      "main().catch(e => send(e.stack));");

  item = test_script_fixture_pop_message (fixture);
  g_assert_nonnull (strstr (item->message, "\"type\":\"send\""));
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at add (agent/math.ts:2)\\n"
        "    at <anonymous> (agent/index.ts:4)"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at Module.add (agent/math.ts:2:11)\\n"
        "    at agent/index.ts:4:10"));
  }
  test_script_message_item_free (item);
}

TESTCASE (dynamic_script_loaded_should_support_separate_source_map)
{
  TestScriptMessageItem * item;

  /*
   * agent/index.ts
   * --------
   * 01 import * as math from "./math.js";
   * 02
   * 03 try {
   * 04     math.add(3, 4);
   * 05 } catch (e) {
   * 06     send((e as Error).stack);
   * 07 }
   *
   * agent/math.ts
   * -------
   * 01 export function add(a: number, b: number): number {
   * 02     throw new Error("not yet implemented");
   * 03 }
   */
  COMPILE_AND_LOAD_SCRIPT (
      "async function main() {"
        "Script.registerSourceMap('/agent/math.js', `{\"version\":3,\"file\":\""
          "math.js\",\"sourceRoot\":\"/Users/oleavr/src/frida-agent-example/\","
          "\"sources\":[\"agent/math.ts\"],\"names\":[],\"mappings\":\"AAAA,MAA"
          "M,UAAU,GAAG,CAAC,CAAS,EAAE,CAAS;IACpC,MAAM,IAAI,KAAK,CAAC,qBAAqB,CAA"
          "C,CAAC;AAC3C,CAAC\"}`);"
        "await Script.load('/agent/math.js', `"
          "export function add(a, b) {\n"
          "    throw new Error(\"not yet implemented\");\n"
          "}\n`);"
        "Script.registerSourceMap('/agent/index.js', `{\"version\":3,\"file\":"
          "\"index.js\",\"sourceRoot\":\"/Users/oleavr/src/frida-agent-example/"
          "\",\"sources\":[\"agent/index.ts\"],\"names\":[],\"mappings\":\"AAAA"
          ",OAAO,KAAK,IAAI,MAAM,WAAW,CAAC;AAElC,IAAI;IACA,IAAI,CAAC,GAAG,CAAC,C"
          "AAC,EAAE,CAAC,CAAC,CAAC;CAClB;AAAC,OAAO,CAAC,EAAE;IACR,IAAI,CAAE,CAA"
          "W,CAAC,KAAK,CAAC,CAAC;CAC5B\"}`);"
        "await Script.load('/agent/index.js', `"
          "import * as math from \"./math.js\";\n"
          "try {\n"
          "    math.add(3, 4);\n"
          "}\n"
          "catch (e) {\n"
          "    send(e.stack);\n"
          "}\n`);"
      "}"
      "main().catch(e => send(e.stack));");

  item = test_script_fixture_pop_message (fixture);
  g_assert_nonnull (strstr (item->message, "\"type\":\"send\""));
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at add (agent/math.ts:2)\\n"
        "    at <anonymous> (agent/index.ts:4)"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at Module.add (agent/math.ts:2:11)\\n"
        "    at agent/index.ts:4:10"));
  }
  test_script_message_item_free (item);
}

TESTCASE (worker_basics_should_be_supported)
{
  if (!GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<only available on QuickJS for now> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "202 /main.js\n"
      "126 /worker.js\n"
      "92 /wrangler.js\n"
      "✄\n"
      "import { url as workerUrl } from './worker.js';\n"
      "const w = new Worker(workerUrl, {\n"
      "    onMessage(message) {\n"
      "        send(`onMessage got: ${JSON.stringify(message)}`);\n"
      "    }\n"
      "});\n"
      "w.post(
"""


```