Response:
The user wants a detailed analysis of a specific C source code file related to Frida, a dynamic instrumentation tool. They've provided a code snippet and are asking for its functionalities, relation to reverse engineering, interaction with low-level systems, logical deductions, potential user errors, debugging clues, and a summary of its purpose within a larger context.

Here's a breakdown of how to approach each point:

1. **Functionalities:** Analyze the code for the different test cases defined using `TESTCASE`. Each `TESTCASE` block represents a specific functionality being tested. Look for keywords like `COMPILE_AND_LOAD_SCRIPT`, `NativeFunction`, `NativeCallback`, `SystemFunction`, `send`, `EXPECT_SEND_MESSAGE_WITH`, etc., to understand what actions are being performed and verified.

2. **Relation to Reverse Engineering:**  Consider how the tested functionalities are relevant to reverse engineering. Concepts like interacting with native functions (`NativeFunction`), creating callbacks (`NativeCallback`), and dealing with system calls (`SystemFunction`) are core to dynamic analysis and reverse engineering. Look for examples where the code interacts with specific memory addresses or function calls.

3. **Binary/Kernel/Framework Knowledge:** Identify parts of the code that interact with low-level concepts. This includes dealing with memory addresses (pointers), calling native code (potentially involving ABIs like `fastcall` and `stdcall`), handling system errors (errno/GetLastError), and potentially interacting with OS-specific features (like Unix file descriptors). Note any Android or Linux kernel-related aspects.

4. **Logical Deduction (Input/Output):**  For each `TESTCASE`, analyze the script being loaded and the expected output (using `EXPECT_SEND_MESSAGE_WITH`). Formulate a hypothesis about what the script does and how it leads to the expected output. For example, if a `NativeFunction` is created to a C function that adds two numbers, the input would be the arguments to the `NativeFunction` call, and the output would be the sum.

5. **User/Programming Errors:**  Think about common mistakes a user might make when using these features. This could include incorrect function signatures in `NativeFunction` or `NativeCallback`, memory management issues, incorrect usage of APIs, or assumptions about data types.

6. **User Operation to Reach This Code:** Consider the typical workflow of using Frida. A user would write a JavaScript script that utilizes Frida's API to interact with a target process. This C code file contains *tests* for the JavaScript API, so the user's actions lead to this code indirectly by testing the implementation of those API calls. The debugging aspect arises when something in the user's script (or Frida itself) doesn't work as expected, leading developers to investigate the test suite.

7. **Summary of Functionality:**  Based on the individual functionalities identified in step 1, provide a concise overview of the overall purpose of this specific code file within the Frida project.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the C code itself. It's crucial to remember that this is a *test* file for the *JavaScript* API of Frida's Gum engine. The functionalities are about how JavaScript interacts with native code through Gum.
* I need to be careful about making assumptions about the underlying C functions being called. The test cases are designed to be self-contained, so the behavior can be inferred from the script and the expected output.
* For "logical deduction," ensure the assumptions about the underlying C functions align with the test case's intent. The test names often provide hints.
* When discussing user errors, focus on mistakes related to the *Frida API* as exposed in JavaScript, rather than generic C programming errors.
* The "debugging clue" is that this is a *test* file. If a user's Frida script fails, these tests help verify if the core functionalities are working correctly.

By following these steps and considering the self-correction points, I can generate a comprehensive and accurate response to the user's request.
好的，让我们来分析一下 `frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的第 3 部分代码的功能。

**功能列举:**

这部分代码主要测试 Frida Gum JavaScript 绑定的一些核心功能，特别是关于与 Native 代码交互的部分。 具体的测试点包括：

* **NativeFunction 的异常处理:**
    * 测试当调用的 NativeFunction 内部发生崩溃（如访问违例）时，Frida Gum 能否捕获并以 JavaScript 异常的形式抛出，而不是导致整个进程崩溃。
    * 测试嵌套的 NativeFunction 调用中，如果内部的回调函数发生崩溃，异常能否被正确处理。
* **可变参数 NativeFunction 的调用:**
    * 测试能否正确调用参数数量可变的 NativeFunction。
    * 测试当可变参数的类型小于 `int` 时，是否会被提升为 `int` 类型传递。
    * 测试可变参数中 `float` 类型是否会被提升为 `double` 类型传递。
* **特定调用约定 (Calling Convention) 的 NativeFunction:**
    * 测试在 Windows x86 平台下，能否支持 `fastcall` 和 `stdcall` 调用约定的 NativeFunction。
* **NativeFunction 作为 NativePointer 的特性:**
    * 测试 `NativeFunction` 的实例是否也是 `NativePointer` 的实例。
    * 测试 `NativeFunction` 实例的字符串表示是否与其指向的内存地址一致。
* **SystemFunction 的调用:**
    * 测试能否调用系统函数，并获取其返回值以及系统错误码 (`errno` 或 `GetLastError`)。
    * 测试 `SystemFunction` 是否实现了 `call` 和 `apply` 方法。
* **SystemFunction 作为 NativePointer 的特性:**
    * 测试 `SystemFunction` 的实例是否也是 `NativePointer` 的实例。
    * 测试 `SystemFunction` 实例的字符串表示是否与其指向的内存地址一致。
* **NativeCallback 的调用:**
    * 测试能否在 JavaScript 中创建回调函数，并将其转换为可被 Native 代码调用的函数指针。
    * 测试 `NativeCallback` 是否能访问和修改系统错误码 (`errno` 或 `GetLastError`)。
* **NativeCallback 作为 NativePointer 的特性:**
    * 测试 `NativeCallback` 的实例是否也是 `NativePointer` 的实例。
* **NativeCallback 的内存管理:**
    * 测试 `NativeCallback` 占用的内存是否能被及时回收，防止内存泄漏。
    * 测试在 Native 代码调用 `NativeCallback` 的过程中，该回调函数对象不会被垃圾回收。
* **特定调用约定的 NativeCallback:**
    * 测试在 Windows x86 平台下，能否支持 `fastcall` 和 `stdcall` 调用约定的 `NativeCallback`。
* **NativeCallback 的准确调用栈回溯:**
    * 测试在 Native 代码调用 `NativeCallback` 时，能否获取到准确的 JavaScript 调用栈信息 (返回地址)。这在 macOS 平台下有专门的测试用例，并涉及到 Objective-C 的方法调用。
* **Unix 文件描述符的读写:**
    * 测试 `UnixInputStream` 和 `UnixOutputStream` 类，用于在 JavaScript 中操作 Unix 文件描述符进行异步读写。
* **hexdump 功能:**
    * 测试 `hexdump` 函数的基本功能，可以将内存区域以十六进制形式打印出来。
    * 测试 `hexdump` 可以接受 `NativePointer` 类型的对象。
* **NativePointer 的属性和操作:**
    * 测试 `NativePointer` 的 `isNull()` 方法，用于判断指针是否为空。
    * 测试 `NativePointer` 的算术运算方法，如 `add()`, `sub()`, `and()`, `or()`, `xor()`, `shr()`, `shl()`, `not()`。
    * 测试 `NativePointer` 的类型转换方法，如 `toUInt32()`。
    * 测试 `NativePointer` 的 `ptrauth` 相关功能（在支持 ptrauth 的架构上）。
    * 测试 `NativePointer` 的 ARM TBI (Top Byte Ignore) 相关功能（在 Android ARM64 上）。
    * 测试 `NativePointer` 的 `toMatchPattern()` 方法，用于生成可以用于内存搜索的字节模式。
    * 测试能否从 64 位数值创建 `NativePointer` 对象。
    * 测试 `NativePointer` 对象能否被序列化为 JSON 格式。
* **ArrayBuffer 包装内存区域:**
    * (代码片段不完整，推测是测试 `ArrayBuffer.wrap()` 方法，允许将一段 Native 内存包装成 JavaScript 的 `ArrayBuffer` 对象)

**与逆向方法的关系及举例说明:**

这部分测试代码直接关系到 Frida 作为动态 instrumentation 工具的核心逆向能力。以下是一些例子：

* **Hooking Native 函数:** `NativeFunction` 的测试确保了可以可靠地获取 Native 函数的地址，并从 JavaScript 中调用它们。这正是 Frida Hook 技术的基础。例如，逆向工程师可以使用 `NativeFunction` 来调用目标进程中的某个函数，观察其行为或修改其参数和返回值。
* **创建 Native 回调:** `NativeCallback` 的测试保证了可以在 JavaScript 中定义逻辑，然后让目标进程的 Native 代码来执行这些逻辑。这对于在特定事件发生时注入自定义行为非常有用。例如，可以创建一个 `NativeCallback` 来记录某个关键函数的调用参数。
* **处理 Native 异常:** 测试 Native 崩溃的捕获能力，对于在不破坏目标进程的情况下进行更深入的分析至关重要。例如，当 Hook 的函数内部发生异常时，Frida 可以捕获并通知逆向工程师，而不是让目标进程直接崩溃。
* **模拟系统调用:** `SystemFunction` 的测试使得可以模拟目标进程执行系统调用，或者在 Hook 系统调用时，能够方便地调用原始的系统调用。
* **内存操作:** `NativePointer` 的各种操作，如地址计算、位运算、以及 `hexdump` 功能，是进行内存分析和数据检查的基础工具。例如，可以使用 `hexdump` 来查看某个内存地址的内容，或者使用指针运算来访问结构体成员。
* **调用约定:**  对不同调用约定的支持，使得 Frida 能够 Hook 和调用各种 Native 函数，即使它们的参数传递方式不同。这在逆向 Windows 程序时尤其重要。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **内存地址和指针:** `NativePointer` 及其各种操作直接涉及内存地址的表示和运算。测试用例中使用了十六进制地址字符串，并进行了加减、位运算等操作。
    * **调用约定 (ABI):**  `fastcall` 和 `stdcall` 是 x86 平台的特定函数调用约定，涉及到参数如何通过寄存器和栈传递，以及调用者和被调用者如何清理栈。
    * **数据类型:** 测试用例中涉及到不同大小的整数 (`uint8`, `int`) 和浮点数 (`float`)，以及它们在 Native 函数调用时的类型提升。
* **Linux/Unix:**
    * **文件描述符:** `UnixInputStream` 和 `UnixOutputStream` 直接操作 Linux/Unix 的文件描述符，这是操作系统管理文件和网络连接的基础。`socketpair` 函数用于创建一对连接的 socket 文件描述符。
    * **信号 (`SIGPIPE`):**  在测试 `UnixOutputStream` 的写入错误处理时，涉及到 `SIGPIPE` 信号，当向已关闭的管道或 socket 写入数据时，操作系统会发送此信号。
    * **`errno`:**  `SystemFunction` 和 `NativeCallback` 的测试中涉及到 `errno`，它是 Linux 系统中用于指示系统调用错误的全局变量。
* **Android 内核及框架:**
    * **ARM64 TBI (Top Byte Ignore):**  `NativePointer` 的 TBI 测试是针对 ARM64 架构的特性，某些内存地址的高字节可能被忽略。
* **macOS 框架 (Objective-C):**
    * **Objective-C 方法调用:**  在 macOS 上的 `native_callback_should_get_accurate_backtraces` 测试用例中，涉及到 `ObjC.classes` 和 `Interceptor.attach`，表明 Frida 能够 Hook Objective-C 的方法调用，并获取其调用栈信息。

**逻辑推理、假设输入与输出:**

让我们以 `variadic_native_function_can_be_invoked` 这个测试用例为例：

**假设输入:**

* JavaScript 代码创建了一个名为 `sum` 的 `NativeFunction`，它对应于 C 代码中的 `gum_sum` 函数。
* `gum_sum` 函数接受一个 `int` 参数，后面跟着可变数量的 `int` 参数，并返回所有参数的和。
* JavaScript 代码分别使用 `sum(0)`, `sum(1, 1)`, `sum(3, 1, 2, 3)` 进行调用。

**预期输出:**

* `send(sum(0))` 应该发送字符串 `"0"`。
* `send(sum(1, 1))` 应该发送字符串 `"2"`。
* `send(sum(3, 1, 2, 3))` 应该发送字符串 `"9"`。

**逻辑推理:**  Frida Gum 应该能够正确地将 JavaScript 中的可变数量的参数传递给 Native 函数 `gum_sum`，并且 `gum_sum` 函数的返回值应该被正确地返回到 JavaScript 并通过 `send` 函数发送出来。

**用户或编程常见的使用错误及举例说明:**

* **`NativeFunction` 的签名错误:** 用户在创建 `NativeFunction` 时，提供的返回值类型或参数类型与实际的 Native 函数不符。例如：
  ```javascript
  // 假设 gum_sum 实际返回 int，但用户错误地写成 'void'
  const sum = new NativeFunction(address, 'void', ['int', '...']);
  ```
  这可能导致类型不匹配的错误，或者程序崩溃。
* **`NativeCallback` 的参数类型不匹配:**  用户创建的 `NativeCallback` 的参数类型与 Native 代码期望的类型不一致。例如：
  ```javascript
  // Native 代码期望接收一个 int，但 Callback 接收的是 string
  const callback = new NativeCallback((value) => { ... }, 'void', ['string']);
  ```
  这会导致 Native 代码读取到错误的数据，可能引发不可预测的行为。
* **忘记处理 `SystemFunction` 的错误:** 用户调用 `SystemFunction` 后，没有检查 `result.lastError` (Windows) 或 `result.errno` (非 Windows) 来判断系统调用是否成功。这可能导致用户在错误发生后仍然按照成功的逻辑执行，从而产生错误。
* **`NativeCallback` 的内存管理错误 (虽然 Frida 做了很多自动化):** 在早期的 Frida 版本或更复杂的场景下，如果对 `NativeCallback` 的生命周期管理不当，可能会导致回调函数被提前回收，从而在 Native 代码尝试调用时发生错误。 虽然现在的测试用例着重测试 Frida 的自动内存管理，但理解潜在的风险仍然重要。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida JavaScript 脚本:**  用户开始使用 Frida，编写 JavaScript 脚本来对目标进程进行动态分析或修改。
2. **脚本中使用 Frida API:**  用户的脚本中使用了 `NativeFunction`, `NativeCallback`, `SystemFunction`, `ptr`, `hexdump` 等 Frida 提供的 JavaScript API。
3. **脚本执行异常或行为不符合预期:**  用户的脚本在执行过程中遇到了问题，例如调用 Native 函数失败、回调没有被正确执行、内存操作结果不正确等。
4. **开发者进行 Frida 内部调试:**  当用户报告问题或者开发者在开发 Frida 新功能时，可能需要深入 Frida 的 Gum 引擎进行调试。
5. **查看测试用例:**  为了验证 Frida Gum 引擎的特定功能是否正常工作，开发者会查看或运行相关的测试用例。例如，如果用户报告 `NativeFunction` 调用崩溃的问题，开发者可能会查看 `nested_native_function_crash_is_handled_gracefully` 这样的测试用例，来确认 Frida 的异常处理机制是否正常。
6. **定位到 `script.c` 文件:**  如果问题涉及到 Gum 引擎的 JavaScript 绑定部分，开发者可能会逐步定位到 `frida/subprojects/frida-gum/tests/gumjs/script.c` 这个文件，找到相关的测试代码进行分析和调试。
7. **分析具体的测试用例:**  开发者会仔细分析出错功能对应的测试用例，例如查看脚本代码、预期的输出、以及相关的 C 代码实现，来找出问题的根源。

**归纳一下它的功能 (第 3 部分):**

`frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的第 3 部分主要**测试 Frida Gum 引擎提供的用于 JavaScript 与 Native 代码交互的核心功能**，包括：**调用 Native 函数 (支持可变参数和特定调用约定)、创建 Native 回调 (支持特定调用约定和准确的调用栈回溯)、调用系统函数、以及对内存地址和文件描述符的操作**。 此外，它也测试了 Frida 的**异常处理机制**以及对 `NativeFunction` 和 `NativeCallback` 的**内存管理**。 这些测试用例旨在确保 Frida 作为动态 instrumentation 工具的关键功能能够稳定可靠地工作。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共11部分，请归纳一下它的功能

"""
ing(NULL);"
      "} catch (e) {"
      "  send(e.type);"
      "}",
      target_function_string);
  EXPECT_SEND_MESSAGE_WITH ("\"access-violation\"");
}

TESTCASE (nested_native_function_crash_is_handled_gracefully)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "const targetWithCallback = new NativeFunction(" GUM_PTR_CONST ", "
          "'pointer', ['int', 'pointer', 'pointer']);"
      "const callback = new NativeCallback(value => {"
      "  send(value.readInt());"
      "}, 'void', ['pointer']);"
      "try {"
      "  targetWithCallback(42, callback, NULL);"
      "} catch (e) {"
      "  send(e.type);"
      "}",
      target_function_callbacks);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("\"access-violation\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (variadic_native_function_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['int', '...', 'int']);"
      "send(sum(0));"
      "send(sum(1, 1));"
      "send(sum(3, 1, 2, 3));",
      gum_sum);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("6");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (variadic_native_function_args_smaller_than_int_should_be_promoted)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'int', "
          "['pointer', 'pointer', 'pointer', 'pointer', '...', "
          "'uint8', 'pointer', 'uint8']);"
      "const val = NULL.not();"
      "send(f(val, val, val, val, 13, val, 37));",
      gum_assert_variadic_uint8_values_are_sane);
  EXPECT_SEND_MESSAGE_WITH ("42");
}

static gint
gum_assert_variadic_uint8_values_are_sane (gpointer a,
                                           gpointer b,
                                           gpointer c,
                                           gpointer d,
                                           ...)
{
  va_list args;
  gint e;
  gint g;

  va_start (args, d);
  e = va_arg (args, gint);
  va_arg (args, gpointer);
  g = va_arg (args, gint);
  va_end (args);

  g_assert_cmphex (e, ==, 13);
  g_assert_cmphex (g, ==, 37);

  return 42;
}

TESTCASE (variadic_native_function_float_args_should_be_promoted_to_double)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', '...', 'pointer', 'float']);"
      "send(sum(ptr(3), NULL));"
      "send(sum(ptr(3), ptr(4), 42.0, NULL));"
      "send(sum(ptr(3), ptr(4), 42.0, ptr(100), 200.0, NULL));",
      gum_add_pointers_and_float_variadic);
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("49");
  EXPECT_SEND_MESSAGE_WITH ("349");
  EXPECT_NO_MESSAGES ();
}

#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 4

static int __fastcall gum_sum_three_fastcall (int a, int b, int c);
static int __stdcall gum_divide_by_two_stdcall (int n);

TESTCASE (native_function_should_support_fastcall)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['int', 'int', 'int'], "
          "{ abi: 'fastcall', exceptions: 'propagate' });"
      "send(f(10, 20, 12));",
      gum_sum_three_fastcall);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_should_support_stdcall)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int'], "
          "{ abi: 'stdcall', exceptions: 'propagate' });"
      "send(f(42));",
      gum_divide_by_two_stdcall);
  EXPECT_SEND_MESSAGE_WITH ("21");
  EXPECT_NO_MESSAGES ();
}

static int __fastcall
gum_sum_three_fastcall (int a,
                        int b,
                        int c)
{
  return a + b + c;
}

static int __stdcall
gum_divide_by_two_stdcall (int n)
{
  return n / 2;
}

#endif

TESTCASE (native_function_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "send(toupper instanceof NativePointer);"
      "send(toupper.toString() === " GUM_PTR_CONST ".toString());",
      gum_toupper, gum_toupper);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (system_function_can_be_invoked)
{
#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new SystemFunction(" GUM_PTR_CONST ", 'int', ['int']);"

      "let result = f(13);"
      "send(result.value);"
      "send(result.lastError);"

      "result = f(37);"
      "send(result.value);"
      "send(result.lastError);", gum_clobber_system_error);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new SystemFunction(" GUM_PTR_CONST ", 'int', ['int']);"

      "let result = f(13);"
      "send(result.value);"
      "send(result.errno);"

      "result = f(37);"
      "send(result.value);"
      "send(result.errno);", gum_clobber_system_error);
#endif

  EXPECT_SEND_MESSAGE_WITH ("26");
  EXPECT_SEND_MESSAGE_WITH ("13");

  EXPECT_SEND_MESSAGE_WITH ("74");
  EXPECT_SEND_MESSAGE_WITH ("37");

  EXPECT_NO_MESSAGES ();
}

TESTCASE (system_function_should_implement_call_and_apply)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new SystemFunction(" GUM_PTR_CONST ", 'int', []);"
      "send(f.call().value);"
      "send(f.call(f).value);"
      "send(f.apply(f).value);"
      "send(f.apply(f, undefined).value);"
      "send(f.apply(f, null).value);"
      "send(f.apply(f, []).value);",
      gum_get_answer_to_life_universe_and_everything);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const f = new SystemFunction(" GUM_PTR_CONST ", 'int', ['int']);"
      "send(SystemFunction.prototype.call(f, 42).value);"
      "send(SystemFunction.prototype.apply(f, [42]).value);"
      "send(f.call(undefined, 42).value);"
      "send(f.apply(undefined, [42]).value);"
      "send(f.call(null, 42).value);"
      "send(f.apply(null, [42]).value);"
      "send(f.call(f, 42).value);"
      "send(f.apply(f, [42]).value);"
      "send(f.call(ptr(" GUM_PTR_CONST "), 42).value);"
      "send(f.apply(ptr(" GUM_PTR_CONST "), [42]).value);",
      target_function_int, target_function_nested_a, target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const f = new SystemFunction(" GUM_PTR_CONST ", 'pointer', "
      "    ['pointer', 'int']);"
      "send(f.call(null, ptr(4), 3).value);"
      "send(f.apply(null, [ptr(4), 3]).value);",
      target_function_base_plus_offset);
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (system_function_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new SystemFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "send(toupper instanceof NativePointer);"
      "send(toupper.toString() === " GUM_PTR_CONST ".toString());",
      gum_toupper, gum_toupper);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

static gint
gum_clobber_system_error (gint value)
{
#ifdef HAVE_WINDOWS
  SetLastError (value);
#else
  errno = value;
#endif

  return value * 2;
}

TESTCASE (native_callback_can_be_invoked)
{
  gint (* toupper_impl) (gchar * str, gint limit);
  gchar str[7];

  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new NativeCallback((str, limit) => {"
      "  let count = 0;"
      "  while (count < limit || limit === -1) {"
      "    const p = str.add(count);"
      "    const b = p.readU8();"
      "    if (b === 0)"
      "      break;"
      "    p.writeU8(String.fromCharCode(b).toUpperCase().charCodeAt(0));"
      "    count++;"
      "  }"
      "  return (limit === -1) ? -count : count;"
      "}, 'int', ['pointer', 'int']);"
      "gc();"
      "send(toupper);");

  toupper_impl = EXPECT_SEND_MESSAGE_WITH_POINTER ();
  g_assert_nonnull (toupper_impl);

  strcpy (str, "badger");
  g_assert_cmpint (toupper_impl (str, 3), ==, 3);
  g_assert_cmpstr (str, ==, "BADger");
  g_assert_cmpint (toupper_impl (str, -1), ==, -6);
  g_assert_cmpstr (str, ==, "BADGER");
}

TESTCASE (native_callback_should_provide_access_to_system_error)
{
  void (* callback) (void);

#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback(function () {"
      "  send(this.lastError);"
      "  this.lastError = this.lastError + 37;"
      "  return 0;"
      "}, 'void', []);"
      GUM_PTR_CONST ".writePointer(cb);", &callback);
  EXPECT_NO_MESSAGES ();

  SetLastError (1300);
  callback ();
  g_assert_cmpuint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback(function () {"
      "  send(this.errno);"
      "  this.errno = this.errno + 37;"
      "  return 0;"
      "}, 'void', []);"
      GUM_PTR_CONST ".writePointer(cb);", &callback);
  EXPECT_NO_MESSAGES ();

  errno = 1300;
  callback ();
  g_assert_cmpuint (errno, ==, 1337);
#endif

  EXPECT_SEND_MESSAGE_WITH ("1300");
}

TESTCASE (native_callback_is_a_native_pointer)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback(() => {}, 'void', []);"
      "send(cb instanceof NativePointer);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (native_callback_memory_should_be_eagerly_reclaimed)
{
  guint usage_before, usage_after;
  gboolean difference_is_less_than_2x;

  COMPILE_AND_LOAD_SCRIPT (
      "let iterationsRemaining = null;"
      "recv('start', onStartRequest);"
      "function onStartRequest(message) {"
      "  iterationsRemaining = message.iterations;"
      "  processNext();"
      "}"
      "function processNext() {"
      "  const cb = new NativeCallback(() => {}, 'void', []);"
      "  if (--iterationsRemaining === 0) {"
      "    recv('start', onStartRequest);"
      "    gc();"
      "    send('done');"
      "  } else {"
      "    setTimeout(processNext, 0);"
      "  }"
      "}");
  EXPECT_NO_MESSAGES ();

  PUSH_TIMEOUT (20000);

  POST_MESSAGE ("{\"type\":\"start\",\"iterations\":5000}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();

  usage_before = gum_peek_private_memory_usage ();

  POST_MESSAGE ("{\"type\":\"start\",\"iterations\":5000}");
  EXPECT_SEND_MESSAGE_WITH ("\"done\"");
  EXPECT_NO_MESSAGES ();

  usage_after = gum_peek_private_memory_usage ();

  POP_TIMEOUT ();

  difference_is_less_than_2x = usage_after < usage_before * 2;
  if (!difference_is_less_than_2x)
  {
    g_printerr ("\n\n"
        "Oops, memory usage is not looking good:\n"
        "\tusage before: %u\n"
        "\t    vs after: %u\n\n",
        usage_before, usage_after);
    g_assert_true (difference_is_less_than_2x);
  }
}

TESTCASE (native_callback_should_be_kept_alive_during_calls)
{
  void (* cb) (void);

  COMPILE_AND_LOAD_SCRIPT (
      "let cb = new NativeCallback(() => {"
        "cb = null;"
        "gc();"
        "send('returning');"
      "}, 'void', []);"
      "Script.bindWeak(cb, () => { send('dead'); });"
      GUM_PTR_CONST ".writePointer(cb);",
      &cb);
  EXPECT_NO_MESSAGES ();

  cb ();
  EXPECT_SEND_MESSAGE_WITH ("\"returning\"");
  EXPECT_SEND_MESSAGE_WITH ("\"dead\"");
  EXPECT_NO_MESSAGES ();
}

#ifdef HAVE_WINDOWS

# if GLIB_SIZEOF_VOID_P == 4

TESTCASE (native_callback_should_support_fastcall)
{
  int (__fastcall * cb) (int, int, int);

  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback((a, b, c) => {"
              "send([a, b, c]);"
              "return a + b + c;"
          "}, 'int', ['int', 'int', 'int'], 'fastcall');"
      GUM_PTR_CONST ".writePointer(cb);",
      &cb);
  EXPECT_NO_MESSAGES ();

  g_assert_cmpint (cb (10, 20, 12), ==, 42);
  EXPECT_SEND_MESSAGE_WITH ("[10,20,12]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_callback_should_support_stdcall)
{
  int (__stdcall * cb) (int);

  COMPILE_AND_LOAD_SCRIPT (
      "const cb = new NativeCallback(n => { send(n); return n / 2; }, 'int', "
          "['int'], 'stdcall');"
      GUM_PTR_CONST ".writePointer(cb);",
      &cb);
  EXPECT_NO_MESSAGES ();

  g_assert_cmpint (cb (42), ==, 21);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();
}

# endif

GUM_NOINLINE static void *
sample_return_address (void)
{
# ifdef _MSC_VER
  return _ReturnAddress ();
# else
  return __builtin_return_address (0);
# endif
}

TESTCASE (native_callback_should_get_accurate_backtraces)
{
  void (* cb) (void);
  void * ret_address = sample_return_address ();

  COMPILE_AND_LOAD_SCRIPT (
      "const min = " GUM_PTR_CONST ";"
      "const max = min.add(128);"
      "const cb = new NativeCallback(function () {"
      "  if (this.returnAddress.compare(min) > 0 &&"
      "      this.returnAddress.compare(max) < 0) {"
      "    send('return address ok');"
      "  } else {"
      "    send('return address error');"
      "  }"
      "}, 'void', []);"
      GUM_PTR_CONST ".writePointer(cb);",
      ret_address, &cb);
  EXPECT_NO_MESSAGES ();

  cb ();
  EXPECT_SEND_MESSAGE_WITH ("\"return address ok\"");
  EXPECT_NO_MESSAGES ();
}

#endif

#ifdef HAVE_DARWIN

TESTCASE (native_callback_should_get_accurate_backtraces)
{
  COMPILE_AND_LOAD_SCRIPT (
    "const {"
    "  __NSCFBoolean,"
    "  NSAutoreleasePool,"
    "  NSData,"
    "  NSJSONSerialization,"
    "} = ObjC.classes;"

    "const pool = NSAutoreleasePool.alloc().init();"
    "let reference = null;"
    "let sample = null;"
    "let referenceRet = null;"
    "let sampleRet = null;"

    "try {"
    "  const jsonString = '{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":' +"
    "     '{\"h\":{\"i\":{\"j\":{\"k\":{\"l\":{\"m\":{\"n\":{\"o\":{\"p\":' +"
    "     '{\"q\":{},\"cool\":true}}}}}}}}}}}}}}}}}';"
    "  const bytes = Memory.allocUtf8String(jsonString);"
    "  const data = NSData.dataWithBytes_length_(bytes, jsonString.length);"
    "  const jsonObject = NSJSONSerialization"
    "      .JSONObjectWithData_options_error_(data, 0, NULL);"

    "  const method = __NSCFBoolean['- boolValue'];"
    "  const listener = Interceptor.attach(method.implementation, {"
    "    onEnter() {"
    "      listener.detach();"
    "      if (reference === null) {"
    "        reference = Thread.backtrace(this.context, Backtracer.ACCURATE);"
    "        referenceRet = this.returnAddress;"
    "      }"
    "    }"
    "  });"

    "  NSJSONSerialization"
    "      .dataWithJSONObject_options_error_(jsonObject, 0, NULL);"

    "  const origImpl = method.implementation;"
    "  method.implementation = ObjC.implement(method,"
    "      function (handle, selector) {"
    "        if (sample === null) {"
    "          sample = Thread.backtrace(this.context, Backtracer.ACCURATE);"
    "          sampleRet = this.returnAddress;"
    "          send('returnAddress ' +"
    "              (sample[0].equals(sampleRet) ? 'ok' : 'error'));"
    "        }"
    "        return origImpl(handle, selector);"
    "      });"

    "  NSJSONSerialization"
    "      .dataWithJSONObject_options_error_(jsonObject, 0, NULL);"

    "  method.implementation = origImpl;"
    "} finally {"
    "  pool.release();"
    "}"

    "let backtraceMatches = true;"
    "for (let i = 0; i !== reference.length; i++) {"
    "  try {"
    "    if (!reference[i].equals(sample[i])) {"
    "      backtraceMatches = false;"
    "      break;"
    "    }"
    "  } catch (e) {"
    "    backtraceMatches = false;"
    "    break;"
    "  }"
    "}"

    "send(backtraceMatches ? 'backtrace ok' : 'backtrace error');"

    "if (referenceRet.equals(sampleRet)) {"
    "  send('returnAddress consistent');"
    "} else {"
    "  send('returnAddress inconsistent: ' + referenceRet +"
    "      ' got ' + sampleRet);"
    "}"
  );

  EXPECT_SEND_MESSAGE_WITH ("\"returnAddress ok\"");
  EXPECT_SEND_MESSAGE_WITH ("\"backtrace ok\"");
  EXPECT_SEND_MESSAGE_WITH ("\"returnAddress consistent\"");
}

TESTCASE (native_callback_should_get_accurate_backtraces_2)
{
  COMPILE_AND_LOAD_SCRIPT (
    "const {"
    "  NSAutoreleasePool,"
    "  NSDataDetector,"
    "  NSDateCheckingResult,"
    "  NSString"
    "} = ObjC.classes;"

    "const pool = NSAutoreleasePool.alloc().init();"

    "let reference = null;"
    "let sample = null;"
    "let referenceRet = null;"
    "let sampleRet = null;"
    "const textWithTime = 'is scheduled for tomorrow night' +"
    "    'from 9 PM PST to 5 AM EST if i remember correctly';"

    "try {"
    "  const testString = NSString.stringWithString_(textWithTime);"
    "  const range = [0, textWithTime.length];"
    "  const detector = NSDataDetector"
    "      .dataDetectorWithTypes_error_(0xffffffff, NULL);"
    "  const methodName = '- initWithRange:date:timeZone:duration:' +"
    "      'referenceDate:underlyingResult:timeIsSignificant:' +"
    "      'timeIsApproximate:timeIsPast:leadingText:trailingText:';"
    "  const method = NSDateCheckingResult[methodName];"

    "  const listener = Interceptor.attach(method.implementation, {"
    "    onEnter() {"
    "      listener.detach();"
    "      if (reference === null) {"
    "        reference = Thread.backtrace(this.context, Backtracer.ACCURATE);"
    "        referenceRet = this.returnAddress;"
    "      }"
    "    }"
    "  });"

    "  const interceptHere = detector['- matchesInString:options:range:'];"
    "  Interceptor.attach(interceptHere.implementation, {"
    "    onEnter() {}"
    "  });"

    "  detector.matchesInString_options_range_(testString, 0, range);"

    "  const origImpl = method.implementation;"
    "  method.implementation = ObjC.implement(method,"
    "    function (handle, selector, ...args) {"
    "      if (sample === null) {"
    "        if (!this.context.pc.isNull()) {"
    "          send('returnAddress error');"
    "        } else {"
    "          sample = Thread.backtrace(this.context, Backtracer.ACCURATE);"
    "          sampleRet = this.returnAddress;"
    "          send('returnAddress ' +"
    "              (sample[0].equals(sampleRet) ? 'ok' : 'error'));"
    "        }"
    "      }"
    "      return origImpl(handle, selector, ...args);"
    "    });"

    "  detector.matchesInString_options_range_(testString, 0, range);"
    "  method.implementation = origImpl;"
    "} finally {"
    "  pool.release();"
    "}"

    "let backtraceEquals = true;"
    "for (let i = 0; i !== reference.length; i++) {"
    "  try {"
    "    if (!reference[i].equals(sample[i])) {"
    "      backtraceEquals = false;"
    "      break;"
    "    }"
    "  } catch (e) {"
    "    backtraceEquals = false;"
    "    break;"
    "  }"
    "}"

    "send(backtraceEquals ? 'backtrace ok' : 'backtrace error');"

    "if (referenceRet.equals(sampleRet))"
    "  send('returnAddress consistent');"
    "else"
    "  send('returnAddress inconsistent: ' + referenceRet);"
  );

  EXPECT_SEND_MESSAGE_WITH ("\"returnAddress ok\"");
  EXPECT_SEND_MESSAGE_WITH ("\"backtrace ok\"");
  EXPECT_SEND_MESSAGE_WITH ("\"returnAddress consistent\"");
}

#endif

#ifdef G_OS_UNIX

#define GUM_TEMP_FAILURE_RETRY(expression) \
    ({ \
      gssize __result; \
      \
      do __result = (gssize) (expression); \
      while (__result == -EINTR); \
      \
      __result; \
    })

TESTCASE (unix_fd_can_be_read_from)
{
  gint fds[2];
  const guint8 message[7] = { 0x13, 0x37, 0xca, 0xfe, 0xba, 0xbe, 0xff };
  gssize res;

  g_assert_cmpint (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixInputStream(%d, { autoClose: false });"
      "    const buf = await stream.read(1337);"
      "    send(buf.byteLength, buf);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 1));
  g_assert_cmpint (res, ==, 1);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1", "13");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixInputStream(%d, { autoClose: false });"
      "    const buf = await stream.readAll(7);"
      "    send(buf.byteLength, buf);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 4));
  g_assert_cmpint (res, ==, 4);
  g_usleep (G_USEC_PER_SEC / 20);
  EXPECT_NO_MESSAGES ();
  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message + 4, 3));
  g_assert_cmpint (res, ==, 3);
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("7", "13 37 ca fe ba be ff");
  EXPECT_NO_MESSAGES ();

  res = GUM_TEMP_FAILURE_RETRY (write (fds[1], message, 2));
  g_assert_cmpint (res, ==, 2);
  close (fds[1]);
  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixInputStream(%d, { autoClose: false });"
      "    await stream.readAll(7);"
      "  } catch (e) {"
      "    send(e.toString(), e.partialData);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("\"Error: short read\"", "13 37");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixInputStream(%d, { autoClose: false });"
      "    const success = await stream.close();"
      "    send(success);"
      "    await stream.read(1337);"
      "  } catch (e) {"
      "    send(e.toString());"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"Error: stream is already closed\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixInputStream(%d, { autoClose: false });"
      "    let success = await stream.close();"
      "    send(success);"
      "    success = await stream.close();"
      "    send(success);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  close (fds[0]);
}

TESTCASE (unix_fd_can_be_written_to)
{
  gint fds[2];
  guint8 buffer[8];
  sig_t original_sigpipe_handler;

  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return;
  }

  original_sigpipe_handler = signal (SIGPIPE, SIG_IGN);

  g_assert_cmpint (socketpair (AF_UNIX, SOCK_STREAM, 0, fds), ==, 0);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixOutputStream(%d, { autoClose: false });"
      "    const size = await stream.write([0x13]);"
      "    send(size);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (read (fds[1], buffer, sizeof (buffer)), ==, 1);
  g_assert_cmphex (buffer[0], ==, 0x13);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixOutputStream(%d, { autoClose: false });"
      "    const size = await stream.writeAll(["
      "        0x13, 0x37,"
      "        0xca, 0xfe, 0xba, 0xbe,"
      "        0xff"
      "    ]);"
      "    send(size);"
      "  } catch (e) {"
      "    send(`oops: ${e.stack}`);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (read (fds[1], buffer, sizeof (buffer)), ==, 7);
  g_assert_cmphex (buffer[0], ==, 0x13);
  g_assert_cmphex (buffer[1], ==, 0x37);
  g_assert_cmphex (buffer[2], ==, 0xca);
  g_assert_cmphex (buffer[3], ==, 0xfe);
  g_assert_cmphex (buffer[4], ==, 0xba);
  g_assert_cmphex (buffer[5], ==, 0xbe);
  g_assert_cmphex (buffer[6], ==, 0xff);

  close (fds[1]);

  COMPILE_AND_LOAD_SCRIPT (
      "async function run() {"
      "  try {"
      "    const stream = new UnixOutputStream(%d, { autoClose: false });"
      "    await stream.writeAll(["
      "        0x13, 0x37,"
      "        0xca, 0xfe, 0xba, 0xbe,"
      "        0xff"
      "    ]);"
      "  } catch (e) {"
      "    send(e.partialSize);"
      "  }"
      "}"
      "run();",
      fds[0]);
  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_NO_MESSAGES ();

  close (fds[0]);

  signal (SIGPIPE, original_sigpipe_handler);
}

#endif

TESTCASE (basic_hexdump_functionality_is_available)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const str = Memory.allocUtf8String(\"Hello hex world! w00t\");"
      "const buf = str.readByteArray(22);"
      "send(hexdump(buf));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\\n"
      "00000010  20 77 30 30 74 00                                "
          " w00t.\"");

  COMPILE_AND_LOAD_SCRIPT (
      "const str = Memory.allocUtf8String(\"Hello hex world! w00t\");"
      "send(hexdump(str, { address: uint64('0x100000000'), length: 22 }));");
  EXPECT_SEND_MESSAGE_WITH ("\""
      "            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "100000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\\n"
      "100000010  20 77 30 30 74 00                                "
          " w00t.\"");
}

TESTCASE (hexdump_supports_native_pointer_conforming_object)
{
  const gchar * message = "Hello hex world!";

  COMPILE_AND_LOAD_SCRIPT (
      "const obj = { handle: " GUM_PTR_CONST "  };"
      "send(hexdump(obj, { address: NULL, length: 16 }));", message);
  EXPECT_SEND_MESSAGE_WITH ("\""
      "           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  "
          "0123456789ABCDEF\\n"
      "00000000  48 65 6c 6c 6f 20 68 65 78 20 77 6f 72 6c 64 21  "
          "Hello hex world!\"");
}

TESTCASE (native_pointer_provides_is_null)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0\").isNull());"
      "send(ptr(\"1337\").isNull());");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (native_pointer_provides_arithmetic_operations)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(3).add(4).toInt32());"
      "send(ptr(7).sub(4).toInt32());"
      "send(ptr(6).and(3).toInt32());"
      "send(ptr(6).or(3).toInt32());"
      "send(ptr(6).xor(3).toInt32());"
      "send(ptr(63).shr(4).toInt32());"
      "send(ptr(1).shl(3).toInt32());"
      "send(ptr(0).not().toInt32());");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("-1");
}

TESTCASE (native_pointer_provides_uint32_conversion_functionality)
{
  COMPILE_AND_LOAD_SCRIPT ("send(ptr(1).toUInt32());");
  EXPECT_SEND_MESSAGE_WITH ("1");
}

TESTCASE (native_pointer_provides_ptrauth_functionality)
{
#ifdef HAVE_PTRAUTH
  COMPILE_AND_LOAD_SCRIPT (
      "const original = ptr(1);"

      "const a = original.sign();"
      "send(a.equals(original));"
      "send(a.strip().equals(original));"

      "send(original.sign('ia').equals(a));"
      "send(original.sign('ib').equals(a));"
      "send(original.sign('da').equals(a));"
      "send(original.sign('db').equals(a));"

      "const b = original.sign('ia', ptr(1337));"
      "send(b.equals(a));"
      "const c = original.sign('ia', 1337);"
      "send(c.equals(b));"
      "const d = original.sign('ia', ptr(1337).blend(42));"
      "send(d.equals(b));"

      "try {"
          "original.sign('x');"
      "} catch (e) {"
          "send(e.message);"
      "}");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("\"invalid key\"");
#else
  COMPILE_AND_LOAD_SCRIPT (
      "const original = ptr(1);"
      "send(original.sign() === original);"
      "send(original.strip() === original);"
      "send(original.blend(42) === original);");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif

  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_pointer_provides_arm_tbi_functionality)
{
#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)
  void * block = malloc (1);

  if (GUM_ADDRESS (block) >> 56 != 0)
  {
    COMPILE_AND_LOAD_SCRIPT (
        "const original = " GUM_PTR_CONST ";"
        "const expected = original.and(ptr(0xff).shl(56).not());"
        "send(original.strip().equals(expected));",
        block);
    EXPECT_SEND_MESSAGE_WITH ("true");
    EXPECT_NO_MESSAGES ();
  }
  else
  {
    g_print ("<skipping on this device> ");
  }

  free (block);
#else
  g_print ("<skipping on this platform> ");
#endif
}

TESTCASE (native_pointer_to_match_pattern)
{
  const gchar * extra_checks;

#if GLIB_SIZEOF_VOID_P == 4
  extra_checks = "";
#else
  extra_checks = "send(ptr(\"0xa1b2c3d4e5f6a7b8\").toMatchPattern());";
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(\"0x0\").toMatchPattern());"
      "send(ptr(\"0xa\").toMatchPattern());"
      "send(ptr(\"0xa1b\").toMatchPattern());"
      "send(ptr(\"0xa1b2\").toMatchPattern());"
      "send(ptr(\"0xa1b2c3\").toMatchPattern());"
      "send(ptr(\"0xa1b2c3d4\").toMatchPattern());"
      "%s",
      extra_checks);

#if GLIB_SIZEOF_VOID_P == 4
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b 0a 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2 a1 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3 b2 a1 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4 c3 b2 a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 0a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 0a 1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 a1 b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 a1 b2 c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1 b2 c3 d4\"");
# endif
#else
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0a 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1b 0a 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b2 a1 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"c3 b2 a1 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"d4 c3 b2 a1 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"b8 a7 f6 e5 d4 c3 b2 a1\"");
# else
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 00\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 00 0a\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 0a 1b\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 00 a1 b2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 00 a1 b2 c3\"");
  EXPECT_SEND_MESSAGE_WITH ("\"00 00 00 00 a1 b2 c3 d4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"a1 b2 c3 d4 e5 f6 a7 b8\"");
# endif
#endif
}

TESTCASE (native_pointer_can_be_constructed_from_64bit_value)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(uint64(0x1ffffffff)).equals(ptr(0x1ffffffff)));"
      "send(ptr(int64(0x2ffffffff)).equals(ptr(0x2ffffffff)));");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

#if GLIB_SIZEOF_VOID_P == 4
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(int64(-150450112)).equals(ptr('0xf7085040')));");
  EXPECT_SEND_MESSAGE_WITH ("true");
#elif GLIB_SIZEOF_VOID_P == 8
  COMPILE_AND_LOAD_SCRIPT (
      "send(ptr(int64(-1)).equals(ptr('0xffffffffffffffff')));");
  EXPECT_SEND_MESSAGE_WITH ("true");
#endif
}

TESTCASE (native_pointer_should_be_serializable_to_json)
{
  COMPILE_AND_LOAD_SCRIPT ("send(ptr(1).toJSON());");
  EXPECT_SEND_MESSAGE_WITH ("\"0x1\"");
}

TESTCASE (array_buffer_can_wrap_memory_region)
{
  guint8 val[2] = { 13, 37 };

  COMPILE_AND_LOAD_SCR
"""


```