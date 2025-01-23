Response:
Let's break down the thought process for analyzing this Frida script test file.

**1. Initial Understanding - What is this?**

The first thing is to recognize the context: `frida/subprojects/frida-gum/tests/gumjs/script.c`. This tells us:

* **Frida:** This is related to the Frida dynamic instrumentation toolkit.
* **gumjs:** This suggests it's testing the JavaScript runtime environment *within* Frida (Gum is Frida's core).
* **script.c:**  A C file likely containing test cases for the JavaScript scripting functionality. The `.c` extension implies this is the *test harness*, not the actual JavaScript runtime code itself.
* **tests:** This confirms it's for testing purposes.

**2. High-Level Functionality - What does it *do*?**

Scanning the code, we see keywords like `TESTCASE`, `COMPILE_AND_LOAD_SCRIPT`, `EXPECT_SEND_MESSAGE_WITH`, `EXPECT_NO_MESSAGES`, `send()`, `recv()`, `rpc.exports`, `Worker`, `setTimeout`, `NativePointer`, `NativeFunction`, `NativeCallback`, `WeakRef`, `Script.bindWeak`, `Script.unbindWeak`, `Script.setGlobalAccessHandler`, `Process.setExceptionHandler`, `ObjC.available`, `Java.available`, `Cloak`. These keywords hint at the capabilities being tested:

* **Script Execution:** Loading and running JavaScript code within Frida's environment.
* **Message Passing:** Communication between the Frida script and the test harness (`send`, `recv`).
* **RPC:** Remote Procedure Calls between scripts, possibly involving workers.
* **Workers:** Testing multi-threading or isolated script execution.
* **Timers:**  `setTimeout` functionality.
* **Native Interop:** Interacting with native code using `NativePointer`, `NativeFunction`, `NativeCallback`.
* **Weak References/Callbacks:** Memory management and lifecycle events.
* **Global Variable Handling:**  Customizing how global variables are accessed.
* **Exception Handling:** Intercepting and handling errors within scripts.
* **Debugging:**  Testing the integration with debuggers.
* **Platform-Specific APIs:** Accessing ObjC (macOS/iOS) and Java (Android) APIs.
* **Cloaking:**  Hiding or obscuring memory regions, threads, and file descriptors.

**3. Detailed Analysis - Examining Individual Test Cases:**

Now, we go through each `TESTCASE` block and try to understand the specific functionality being tested:

* **`ping_pong_should_work`:** Basic communication.
* **`worker_ping_pong_should_work`:** Communication involving a worker thread.
* **`worker_rpc_should_be_supported`:**  Remote procedure calls to a worker.
* **`worker_termination_should_be_supported`:**  Testing the ability to terminate workers.
* **`source_maps_should_be_supported_for_our_runtime` and `source_maps_should_be_supported_for_user_scripts`:** Ensuring source maps work for debugging.
* **`types_handle_invalid_construction`:** Checking for correct error handling when creating certain Frida types incorrectly.
* **`weak_ref_api_should_be_supported`:**  Testing weak reference functionality for garbage collection.
* **`weak_callback_is_triggered_on_gc`, `weak_callback_is_triggered_on_unload`, `weak_callback_is_triggered_on_unbind`, `weak_callback_should_not_be_exclusive`:**  Testing the various scenarios for weak callbacks.
* **`globals_can_be_dynamically_generated`:** Testing the `Script.setGlobalAccessHandler` API.
* **`exceptions_can_be_handled`:** Testing `Process.setExceptionHandler`.
* **`debugger_can_be_enabled`:**  Testing the debugging integration (often skipped in non-slow tests).
* **`objc_api_is_embedded` and `java_api_is_embedded`:** Checking for the presence of ObjC and Java APIs.
* **`cloaked_items_can_be_queried_added_and_removed`:** Testing the cloaking functionality.

**4. Connecting to Reverse Engineering and System Knowledge:**

As we analyze each test case, we think about how it relates to reverse engineering and low-level concepts:

* **Native Interop:** Essential for interacting with the target process's memory, functions, and data structures. This is *core* to dynamic instrumentation.
* **Workers/Threads:** Important for understanding concurrent execution in the target process.
* **Memory Management (Weak References):** Relevant for tracking objects without preventing their deallocation.
* **Exception Handling:** Understanding how errors are handled is crucial for robust instrumentation.
* **Debugging:**  A fundamental part of reverse engineering and Frida's workflow.
* **Platform-Specific APIs (ObjC, Java):** Needed for interacting with applications built on these platforms.
* **Cloaking:**  A technique used to hide instrumentation from detection.

**5. Inferring User Actions and Debugging:**

Consider how a user might reach these test scenarios:

* **Basic Scripting:** A user might write a Frida script using `send` and `recv` for basic interaction.
* **Advanced Scripting:** They might use workers for more complex tasks.
* **Native Function Hooking:** They would use `NativePointer`, `NativeFunction`, `NativeCallback` to intercept native function calls.
* **Memory Analysis:** They might use `NativePointer` to examine memory regions.
* **Debugging a Crash:** They might use `Process.setExceptionHandler` to intercept crashes.
* **Platform-Specific Hooking:** They would use `ObjC` or `Java` APIs to hook into specific platform features.
* **Anti-Detection:** They might use the `Cloak` API to hide their instrumentation.

**6. Summarization (Instruction #11):**

Finally, we synthesize the information into a concise summary of the file's overall purpose.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretations:**  Initially, one might think `script.c` *implements* the scripting engine. However, closer examination reveals it's a *test file*.
* **Focusing on Keywords:** The keywords and function names are critical clues. If something is unclear, searching for Frida documentation on those terms is the next step.
* **Understanding Test Structure:** Recognizing the `TESTCASE`, `COMPILE_AND_LOAD_SCRIPT`, `EXPECT_*` pattern is important for understanding how the tests are organized and how they assert the expected behavior.
* **Considering Different Runtimes:** Noticing the `GUM_QUICK_IS_SCRIPT_BACKEND` checks reminds us that Frida might support multiple JavaScript engines, and the tests might have variations for each.

By following this structured approach, we can effectively analyze even relatively complex test files and understand their purpose and implications within the larger Frida ecosystem.
这个C文件 `script.c` 是 Frida (一个动态代码插桩工具) 的一部分，位于 `frida/subprojects/frida-gum/tests/gumjs/` 目录下。从文件名和目录结构来看，它主要用于测试 Frida 的 GumJS 组件，即 Frida 中用于执行 JavaScript 代码的引擎。

下面是对该文件功能的详细列举，并结合逆向、底层、用户错误和调试线索进行说明：

**1. 功能列举:**

* **测试 JavaScript 代码执行:** 该文件包含了多个测试用例 (`TESTCASE`)，每个用例都会编译并加载一段 JavaScript 代码 (`COMPILE_AND_LOAD_SCRIPT`)，然后在 Frida 的 GumJS 环境中执行。
* **测试 JavaScript 与 Frida Core 的交互:**  测试用例中会使用 Frida 提供的全局对象和函数，例如 `send()`, `recv()`, `rpc.exports`, `Worker`, `NativePointer`, `NativeFunction`, `NativeCallback`, `Script`, `Process`, `ObjC`, `Java`, `Cloak` 等，来验证 JavaScript 代码能否正确地与 Frida 的核心功能进行交互。
* **测试异步操作和消息传递:** 包含了对 `setTimeout`, `Worker` 以及 `send`, `recv` 消息传递机制的测试，确保 JavaScript 代码能够进行异步操作并与其他部分进行通信。
* **测试错误处理和异常:**  用例中使用了 `try...catch` 结构，并通过 `EXPECT_SEND_MESSAGE_WITH` 和 `EXPECT_ERROR_MESSAGE_WITH` 来验证 JavaScript 代码的错误处理机制和 Frida 的错误报告功能。
* **测试 Source Maps 支持:**  验证 Frida 是否正确处理 JavaScript 的 Source Maps，以便在调试时能够映射回原始源代码。
* **测试 Native 互操作性:**  测试了 `NativePointer`, `NativeFunction`, `NativeCallback` 等 API，用于在 JavaScript 中与原生代码进行交互，包括调用原生函数和创建原生回调。
* **测试 Weak References 和 Weak Callbacks:**  验证了 JavaScript 中 WeakRef 的使用以及 Frida 提供的 `Script.bindWeak` 和 `Script.unbindWeak` 功能，用于处理对象生命周期和垃圾回收。
* **测试全局变量访问控制:**  通过 `Script.setGlobalAccessHandler` 测试了动态生成和控制全局变量访问的能力。
* **测试异常处理钩子:**  使用 `Process.setExceptionHandler` 测试了捕获和处理进程中异常的能力。
* **测试调试器集成:**  虽然该测试用例在非慢速模式下通常被跳过，但它旨在测试 Frida 的调试器集成功能。
* **测试平台特定 API:**  验证了 `ObjC.available` 和 `Java.available` 的存在，表明 Frida 能够检测到目标进程是否包含 Objective-C 或 Java 运行时。
* **测试 Cloaking 功能:**  测试了 `Cloak` API，用于隐藏内存区域、线程和文件描述符，这在反检测和高级插桩场景中非常重要。

**2. 与逆向方法的关系及举例:**

Frida 本身就是一个强大的逆向工程工具，而这个测试文件验证了 Frida 的核心 JavaScript 插桩能力。以下是一些例子：

* **动态修改函数行为:**  测试用例中会使用 `NativeFunction` 和 `NativeCallback` 来创建指向原生函数的 JavaScript 包装器，这正是 Frida 用于 hook 函数的基础。例如，用户可以使用 `NativeFunction` 获取目标函数的地址，然后使用 `Interceptor.replace` 或 `Interceptor.attach` 来修改其行为。
* **内存读写和分析:** `NativePointer` 的测试表明 Frida 能够在 JavaScript 中直接操作进程内存。逆向工程师可以使用 `ptr(address).read*()` 和 `ptr(address).write*()` 等方法来读取和修改目标进程的内存，分析数据结构或修改程序行为。
* **消息传递和通信分析:**  `send()` 和 `recv()` 的测试展示了 Frida 脚本与 Frida Core 之间的通信机制。在逆向分析中，这可以用于将目标进程的信息发送回控制端，或从控制端接收指令。
* **处理异步操作:**  `setTimeout` 和 `Worker` 的测试反映了目标程序可能存在的异步操作。逆向工程师需要理解这些异步流程，以便在正确的时间点进行插桩和分析。
* **平台特定 API 的使用:**  `ObjC` 和 `Java` API 的测试表明 Frida 能够深入到特定平台的运行时环境。逆向工程师可以利用这些 API 来 hook Objective-C 的方法调用或 Java 的类方法，从而分析 iOS 和 Android 应用的行为。
* **反检测技术的测试:** `Cloak` API 的测试与逆向工程中的反检测技术相关。恶意软件可能会尝试检测和阻止调试器或插桩工具，而 Frida 提供的 cloaking 功能可以帮助逆向工程师隐藏他们的存在。

**3. 涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

* **内存地址操作:** `NativePointer` 涉及到直接操作内存地址，这需要对目标进程的内存布局有一定的了解。在 Linux/Android 中，这涉及到虚拟地址空间、堆栈、代码段、数据段等概念。
* **函数调用约定 (ABI):**  `NativeFunction` 和 `NativeCallback` 的使用需要了解不同平台和架构的函数调用约定，例如参数传递方式、返回值处理等。
* **进程和线程管理:** `Worker` 的测试涉及到进程中线程的创建和管理。在 Linux/Android 中，这与 `pthread` 库或 Android 的 `Thread` 类相关。
* **文件描述符:** `Cloak.addFileDescriptor` 涉及到 Linux/Android 的文件描述符概念，用于访问打开的文件或其他 I/O 资源。
* **异常处理机制:** `Process.setExceptionHandler` 涉及到操作系统底层的异常处理机制，例如 Linux 的信号 (signals) 或 Windows 的异常处理结构 (SEH)。
* **Objective-C 和 Java 运行时:** `ObjC.available` 和 `Java.available` 的测试需要了解 iOS 的 Objective-C 运行时和 Android 的 Dalvik/ART 虚拟机。

**4. 逻辑推理、假设输入与输出:**

以下是一些基于测试用例的逻辑推理：

* **`ping_pong_should_work`:**
    * **假设输入:** Frida 加载并执行包含 `send({ type: 'ping' });` 的脚本。
    * **预期输出:** 测试程序接收到类型为 "pong" 的消息，并打印 `"onMessage got: {\"type\":\"pong\"}"`。
* **`worker_rpc_should_be_supported`:**
    * **假设输入:** Frida 加载包含主脚本和 worker 脚本的代码，主脚本创建 worker 并调用 `w.exports.add(2, 3)`。
    * **预期输出:** 测试程序接收到消息 "5"，因为 worker 执行了 `rpc.exports.add = (a, b) => a + b;` 并返回了结果。
* **`weak_ref_api_should_be_supported`:**
    * **假设输入:** Frida 加载使用 `WeakRef` 的脚本。
    * **预期输出:** 首先接收到 "true"，表示 `r.deref() === val`；然后在垃圾回收后接收到 `"undefined"`，表示弱引用指向的对象已被回收。

**5. 涉及用户或编程常见的使用错误及举例:**

* **错误的 NativePointer 初始化:** `types_handle_invalid_construction` 测试了 `NativePointer("0x1234")` 这种不正确的初始化方式。用户应该使用 `ptr("0x1234")` 或 `new NativePointer(ptr("0x1234"))`。
* **忘记使用 `new` 关键字:** 该测试用例还检查了创建 `NativeFunction`, `NativeCallback`, `File` 等对象时是否忘记使用 `new` 关键字。
* **在 worker 中未导出 RPC 方法:** 如果在 `worker_rpc_should_be_supported` 的 worker 脚本中没有定义 `rpc.exports.add`，主脚本调用 `w.exports.add` 将会失败。
* **不理解异步操作:** 用户可能会在 `worker_termination_should_be_supported` 中错误地认为 `send(await w.exports.simulateSlowRequest())` 会在 worker 终止前完成，导致程序行为不符合预期。

**6. 用户操作如何一步步到达这里，作为调试线索:**

当 Frida 的开发者或贡献者在开发 GumJS 或相关功能时，他们会编写像 `script.c` 这样的测试用例来验证新功能或修复的 bug。用户在正常使用 Frida 时，不会直接执行这个 C 文件。但是，如果用户在使用 Frida 的 JavaScript API 时遇到了问题，例如：

1. **编写的 Frida 脚本无法正常工作:** 用户可能会发现自己的脚本在某些情况下无法按照预期的方式 hook 函数、读写内存或进行消息传递。
2. **遇到 Frida 自身的错误或崩溃:**  虽然比较少见，但 Frida 自身也可能存在 bug。
3. **尝试使用新的 Frida API 功能:** 用户可能会尝试使用 Frida 的新功能，但不确定其使用方法或行为。

在这些情况下，开发者或高级用户可能会查看 Frida 的源代码，包括像 `script.c` 这样的测试文件，来理解特定 API 的预期行为、查找潜在的 bug，或者学习如何正确使用 API。`script.c` 中的测试用例可以作为参考示例，帮助用户理解 Frida 的内部工作原理和 API 的正确用法。

**7. 归纳其功能 (第 11 部分):**

总而言之，`frida/subprojects/frida-gum/tests/gumjs/script.c` 文件的主要功能是 **作为 Frida 中 GumJS (JavaScript 引擎) 的集成测试套件**。它通过编写和执行各种 JavaScript 代码片段，并断言其行为和输出，来确保 GumJS 组件的正确性、稳定性和与 Frida Core 功能的兼容性。  这个文件对于 Frida 的开发和维护至关重要，它提供了一种系统化的方法来验证 JavaScript 插桩功能的各个方面，并帮助开发者发现和修复潜在的问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
{ type: 'ping' });\n"
      "\n"
      "✄\n"
      "import * as wrangler from './wrangler.js';\n"
      "export const url = import.meta.url;\n"
      "export function run() {\n"
      "    wrangler.init();\n"
      "}\n"
      "\n"
      "✄\n"
      "export function init() {\n"
      "    recv('ping', () => {\n"
      "        send({ type: 'pong' });\n"
      "    });\n"
      "}\n");
  EXPECT_SEND_MESSAGE_WITH ("\"onMessage got: {\\\"type\\\":\\\"pong\\\"}\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (worker_rpc_should_be_supported)
{
  if (!GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<only available on QuickJS for now> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "247 /main.js\n"
      "101 /worker.js\n"
      "✄\n"
      "import { url as workerUrl } from './worker.js';\n"
      "async function main() {\n"
      "    try {\n"
      "        const w = new Worker(workerUrl);\n"
      "        send(await w.exports.add(2, 3));\n"
      "    }\n"
      "    catch (e) {\n"
      "        Script.nextTick(() => { throw e; });\n"
      "    }\n"
      "}\n"
      "main();\n"
      "\n"
      "✄\n"
      "export const url = import.meta.url;\n"
      "export function run() {\n"
      "    rpc.exports.add = (a, b) => a + b;\n"
      "}\n");
  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (worker_termination_should_be_supported)
{
  if (!GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<only available on QuickJS for now> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "📦\n"
      "290 /main.js\n"
      "221 /worker.js\n"
      "✄\n"
      "import { url as workerUrl } from './worker.js';\n"
      "async function main() {\n"
      "    try {\n"
      "        const w = new Worker(workerUrl);\n"
      "        setTimeout(() => { w.terminate(); }, 100);\n"
      "        send(await w.exports.simulateSlowRequest());\n"
      "    }\n"
      "    catch (e) {\n"
      "        send(e.message);\n"
      "    }\n"
      "}\n"
      "main();\n"
      "\n"
      "✄\n"
      "export const url = import.meta.url;\n"
      "export function run() {\n"
      "    rpc.exports.simulateSlowRequest = () => {\n"
      "        return new Promise(resolve => {\n"
      "            setTimeout(() => { resolve(42); }, 5000);\n"
      "        });\n"
      "    };\n"
      "}\n");
  EXPECT_SEND_MESSAGE_WITH ("\"worker terminated\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (source_maps_should_be_supported_for_our_runtime)
{
  TestScriptMessageItem * item;

  COMPILE_AND_LOAD_SCRIPT ("hexdump(null);");

  item = test_script_fixture_pop_message (fixture);
  g_assert_nonnull (strstr (item->message, " (frida/runtime/hexdump.js:"));
  test_script_message_item_free (item);

  EXPECT_NO_MESSAGES ();
}

TESTCASE (source_maps_should_be_supported_for_user_scripts)
{
  TestScriptMessageItem * item;

  /*
   * index.js
   * --------
   * 01 'use strict';
   * 02
   * 03 var math = require('./math');
   * 04
   * 05 try {
   * 06   math.add(5, 2);
   * 07 } catch (e) {
   * 08   send(e.stack);
   * 09 }
   * 10
   * 11 setTimeout(function () {
   * 12   throw new Error('Oops!');
   * 13 }, 0);
   *
   * math.js
   * -------
   * 01 'use strict';
   * 02
   * 03 module.exports = {
   * 04   add: function (a, b) {
   * 05     throw new Error('not yet implemented');
   * 06   }
   * 07 };
   */

  COMPILE_AND_LOAD_SCRIPT (
      "(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof requ"
      "ire==\"function\"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);v"
      "ar f=new Error(\"Cannot find module '\"+o+\"'\");throw f.code=\"MODULE_N"
      "OT_FOUND\",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){"
      "var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].expor"
      "ts}var i=typeof require==\"function\"&&require;for(var o=0;o<r.length;o+"
      "+)s(r[o]);return s})({1:[function(require,module,exports){"          "\n"
      "'use strict';"                                                       "\n"
      ""                                                                    "\n"
      "var math = require('./math');"                                       "\n"
      ""                                                                    "\n"
      "try {"                                                               "\n"
      /* testcase.js:7 => index.js:6 */
      "  math.add(5, 2);"                                                   "\n"
      "} catch (e) {"                                                       "\n"
      "  send(e.stack);"                                                    "\n"
      "}"                                                                   "\n"
      ""                                                                    "\n"
      "setTimeout(function () {"                                            "\n"
      /* testcase.js:13 => index.js:12 */
      "  throw new Error('Oops!');"                                         "\n"
      "}, 0);"                                                              "\n"
      ""                                                                    "\n"
      "},{\"./math\":2}],2:[function(require,module,exports){"              "\n"
      "'use strict';"                                                       "\n"
      ""                                                                    "\n"
      "module.exports = {"                                                  "\n"
      "  add: function (a, b) {"                                            "\n"
      /* testcase.js:21 => math.js:5 */
      "    throw new Error('not yet implemented');"                         "\n"
      "  }"                                                                 "\n"
      "};"                                                                  "\n"
      ""                                                                    "\n"
      "},{}]},{},[1])"                                                      "\n"
      "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3"
      "VyY2VzIjpbIm5vZGVfbW9kdWxlcy9mcmlkYS9ub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2"
      "RlX21vZHVsZXMvYnJvd3Nlci1wYWNrL19wcmVsdWRlLmpzIiwiaW5kZXguanMiLCJtYXRoLm"
      "pzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QU"
      "FDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQT"
      "tBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC"
      "5qcyIsInNvdXJjZVJvb3QiOiIifQ=="                                      "\n"
      "// And potentially some trailing code..."                            "\n"
  );

  item = test_script_fixture_pop_message (fixture);
  if (!GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
    g_assert_null (strstr (item->message, "testcase.js"));
  g_assert_nonnull (strstr (item->message, "\"type\":\"send\""));
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at add (math.js:5)\\n"
        "    at <anonymous> (index.js:6)\\n"
        "    at call (native)\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1)\\n"
        "    at <eval> (/testcase.js:25)"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message,
        "\"payload\":\"Error: not yet implemented\\n"
        "    at Object.add (math.js:5:1)\\n"
        "    at Object.1../math (index.js:6:1)\\n"
        "    at s (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at e (node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1)\\n"
        "    at node_modules/frida/node_modules/browserify/node_modules/"
            "browser-pack/_prelude.js:1:1\""));
  }
  test_script_message_item_free (item);

  item = test_script_fixture_pop_message (fixture);
  g_assert_null (strstr (item->message, "testcase.js"));
  g_assert_nonnull (strstr (item->message, "\"type\":\"error\""));
  g_assert_nonnull (strstr (item->message, "\"description\":\"Error: Oops!\""));
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_assert_nonnull (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at <anonymous> (index.js:12)\\n"));
  }
  else
  {
    g_assert_nonnull (strstr (item->message, "\"stack\":\"Error: Oops!\\n"
        "    at index.js:12:1\\n"));
  }
  g_assert_nonnull (strstr (item->message, "\"fileName\":\"index.js\""));
  g_assert_nonnull (strstr (item->message, "\"lineNumber\":12"));
  g_assert_nonnull (strstr (item->message, "\"columnNumber\":1"));
  test_script_message_item_free (item);
}

TESTCASE (types_handle_invalid_construction)
{
  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativePointer(\"0x1234\")"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "\"must be called with new\""
      : "\"use `new NativePointer()` to create a new instance, or use one of "
      "the two shorthands: `ptr()` and `NULL`\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeFunction(ptr(\"0x1234\"), 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "\"must be called with new\""
      : "\"use `new NativeFunction()` to create a new instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  NativeCallback(() => {}, 'void', []);"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "\"must be called with new\""
      : "\"use `new NativeCallback()` to create a new instance\"");

  COMPILE_AND_LOAD_SCRIPT (
      "try {"
      "  File(\"/foo\", \"r\");"
      "} catch (e) {"
      "  send(e.message);"
      "}");
  EXPECT_SEND_MESSAGE_WITH (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend)
      ? "\"must be called with new\""
      : "\"use `new File()` to create a new instance\"");
}

TESTCASE (weak_ref_api_should_be_supported)
{
  COMPILE_AND_LOAD_SCRIPT (
      "let r = null;"
      "(() => {"
      "  const val = { name: 'Joe' };"
      "  r = new WeakRef(val);"
      "  send(r.deref() === val);"
      "})();"
      "setImmediate(() => {"
      "  gc();"
      "  send(typeof r.deref());"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (weak_callback_is_triggered_on_gc)
{
  COMPILE_AND_LOAD_SCRIPT (
      "(() => {"
      "  const val = {};"
      "  Script.bindWeak(val, onWeakNotify);"
      "})();"
      "function onWeakNotify() {"
      "  send(\"weak notify\");"
      "}"
      "gc();");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (weak_callback_is_triggered_on_unload)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const val = {};"
      "Script.bindWeak(val, () => {"
      "  send(\"weak notify\");"
      "});");
  EXPECT_NO_MESSAGES ();
  gum_script_unload_sync (fixture->script, NULL);
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (weak_callback_is_triggered_on_unbind)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const val = {};"
      "const id = Script.bindWeak(val, () => {"
      "  send(\"weak notify\");"
      "});"
      "Script.unbindWeak(id);");
  EXPECT_SEND_MESSAGE_WITH ("\"weak notify\"");
}

TESTCASE (weak_callback_should_not_be_exclusive)
{
  COMPILE_AND_LOAD_SCRIPT (
      "let val = {};"
      "const w1 = Script.bindWeak(val, onWeakNotify.bind(null, 'w1'));"
      "const w2 = Script.bindWeak(val, onWeakNotify.bind(null, 'w2'));"
      "recv(onMessage);"
      "function onMessage(message) {"
      "  switch (message.type) {"
      "    case 'unbind':"
      "      Script.unbindWeak(w1);"
      "      break;"
      "    case 'destroy':"
      "      val = null;"
      "      gc();"
      "  }"
      "  recv(onMessage);"
      "}"
      "function onWeakNotify(id) {"
      "  send(id);"
      "}");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"unbind\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"w1\"");
  EXPECT_NO_MESSAGES ();

  POST_MESSAGE ("{\"type\":\"destroy\"}");
  EXPECT_SEND_MESSAGE_WITH ("\"w2\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (globals_can_be_dynamically_generated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.setGlobalAccessHandler({"
      "  get(property) {"
      "    if (property === 'badger')"
      "      return 1337 + mushroom;"
      "    else if (property === 'mushroom')"
      "      return 3;"
      "  },"
      "});"
      "send(badger);"
      "send(typeof badger);"
      "send(snake);");
  EXPECT_SEND_MESSAGE_WITH ("1340");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "ReferenceError: 'snake' is not defined");
  }
  else
  {
    EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
        "ReferenceError: snake is not defined");
  }
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "Script.setGlobalAccessHandler({"
      "  get(property) {"
      "  },"
      "});"
      "(1, eval)('mushroom = 42;');"
      "send(mushroom);");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (exceptions_can_be_handled)
{
  gpointer page;
  gboolean exception_on_read, exception_on_write;

  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "Process.setExceptionHandler(ex => {"
      "  send('w00t');"
      "});");

  EXPECT_NO_MESSAGES ();

  page = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_mprotect (page, gum_query_page_size (), GUM_PAGE_NO_ACCESS);
  gum_try_read_and_write_at (page, 0, &exception_on_read, &exception_on_write);
  g_assert_true (exception_on_read);
  g_assert_true (exception_on_write);
  gum_free_pages (page);

  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_SEND_MESSAGE_WITH ("\"w00t\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (debugger_can_be_enabled)
{
  GumInspectorServer * server;
  GumScript * script;
  GError * error;

  if (GUM_QUICK_IS_SCRIPT_BACKEND (fixture->backend))
  {
    g_print ("<not available on QuickJS> ");
    return;
  }

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  server = gum_inspector_server_new ();
  g_signal_connect (server, "message", G_CALLBACK (on_incoming_debug_message),
      fixture);

  script = gum_script_backend_create_sync (fixture->backend, "script",
      "const scriptTimer = setInterval(() => {\n"
      "  send('hello');\n"
      "}, 1000);", NULL, NULL, NULL);
  fixture->script = script;
  gum_script_set_message_handler (script, on_script_message, "script", NULL);
  gum_script_set_debug_message_handler (script, on_outgoing_debug_message,
      server, NULL);
  gum_script_load_sync (script, NULL);

  error = NULL;
  if (gum_inspector_server_start (server, &error))
  {
    guint port;
    GMainLoop * loop;

    g_object_get (server, "port", &port, NULL);
    g_print ("Inspector server running on port %u.\n", port);

    loop = g_main_loop_new (g_main_context_get_thread_default (), FALSE);
    g_main_loop_run (loop);
    g_main_loop_unref (loop);
  }
  else
  {
    g_printerr ("Inspector server failed to start: %s\n", error->message);

    g_error_free (error);
  }

  g_object_unref (server);
}

TESTCASE (objc_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof ObjC.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

TESTCASE (java_api_is_embedded)
{
  COMPILE_AND_LOAD_SCRIPT ("send(typeof Java.available);");
  EXPECT_SEND_MESSAGE_WITH ("\"boolean\"");
}

TESTCASE (cloaked_items_can_be_queried_added_and_removed)
{
  void * buffer = malloc (64);

#ifdef HAVE_ANDROID
  COMPILE_AND_LOAD_SCRIPT (
      "const testRange = { base: " GUM_PTR_CONST ", size: 64 };"
      "send(Cloak.hasRangeContaining(testRange.base) === false);"
      "send(Process.findRangeByAddress(testRange.base) !== null);"
      "send(Cloak.clipRange(testRange) === null);"
      "Cloak.addRange(testRange);"
      "send(Cloak.hasRangeContaining(testRange.base));"
      "send(Process.findRangeByAddress(testRange.base) === null);"
      "send(Cloak.clipRange(testRange).length === 0);"
      "Cloak.removeRange(testRange);"

      "send(Cloak.hasCurrentThread() === false);"
      "const threadId = Process.getCurrentThreadId();"
      "send(Cloak.hasThread(threadId) === false);"
      "Cloak.addThread(threadId);"
      "send(!Process.enumerateThreads().map(x => x.id).includes(threadId));"
      "send(Cloak.hasCurrentThread() === true);"
      "Cloak.removeThread(threadId);"
      "send(true);"

      "const fd = 1;"
      "Cloak.addFileDescriptor(fd);"
      "send(Cloak.hasFileDescriptor(fd));"
      "Cloak.removeFileDescriptor(fd);"
      "send(!Cloak.hasFileDescriptor(fd));",
      buffer
  );
#else
  COMPILE_AND_LOAD_SCRIPT (
      "const testRange = { base: " GUM_PTR_CONST ", size: 64 };"
      "send(Cloak.hasRangeContaining(testRange.base) === false);"
      "send(Process.findRangeByAddress(testRange.base) !== null);"
      "send(Cloak.clipRange(testRange) === null);"
      "Cloak.addRange(testRange);"
      "send(Cloak.hasRangeContaining(testRange.base));"
      "send(Process.findRangeByAddress(testRange.base) === null);"
      "send(Cloak.clipRange(testRange).length === 0);"
      "Cloak.removeRange(testRange);"

      "send(Cloak.hasCurrentThread() === false);"
      "const threadId = Process.getCurrentThreadId();"
      "send(Cloak.hasThread(threadId) === false);"
      "Cloak.addThread(threadId);"
      "send(!Process.enumerateThreads().map(x => x.id).includes(threadId));"
      "send(Cloak.hasCurrentThread() === true);"
      "Cloak.removeThread(threadId);"
      "send(Process.enumerateThreads().map(x => x.id).includes(threadId));"

      "const fd = 1;"
      "Cloak.addFileDescriptor(fd);"
      "send(Cloak.hasFileDescriptor(fd));"
      "Cloak.removeFileDescriptor(fd);"
      "send(!Cloak.hasFileDescriptor(fd));",
      buffer
  );
#endif
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  free (buffer);
}

static gboolean
check_exception_handling_testable (void)
{
  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return FALSE;
  }

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return FALSE;
  }

  return TRUE;
}

static void
on_script_message (const gchar * message,
                   GBytes * data,
                   gpointer user_data)
{
  gchar * sender = user_data;
  g_print ("Message from %s: %s\n", sender, message);
}

static void
on_incoming_debug_message (GumInspectorServer * server,
                           const gchar * message,
                           gpointer user_data)
{
  TestScriptFixture * fixture = user_data;

  gum_script_post_debug_message (fixture->script, message);
}

static void
on_outgoing_debug_message (const gchar * message,
                           gpointer user_data)
{
  GumInspectorServer * server = user_data;

  gum_inspector_server_post_message (server, message);
}

GUM_NOINLINE static int
target_function_int (int arg)
{
  int result = 0;
  int i;

  /*
   * Pad the early part of the function so the loop doesn't branch back to the
   * first part, as we may need to overwrite quite a bit if we're unlucky.
   */
  gum_script_dummy_global_to_trick_optimizer += 1337;

  for (i = 0; i != 10; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  /*
   * Throw in a dummy call to an external function so the platform's default ABI
   * is used at call-sites. Because this function is static there is otherwise
   * a chance that the compiler will invent its own calling convention, and any
   * JS-defined replacement function (NativeCallback) will be prone to clobber
   * registers used by the custom calling convention.
   */
  fflush (stdout);

  return result;
}

GUM_NOINLINE static float
target_function_float (float arg)
{
  float result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  fflush (stdout);

  return result;
}

GUM_NOINLINE static double
target_function_double (double arg)
{
  double result = 0;
  int i;

  for (i = 0; i != 10; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  fflush (stdout);

  return result;
}

GUM_NOINLINE static const guint8 *
target_function_base_plus_offset (const guint8 * base,
                                  int offset)
{
  gum_script_dummy_global_to_trick_optimizer += offset;

  fflush (stdout);

  return base + offset;
}

GUM_NOINLINE static const gchar *
target_function_string (const gchar * arg)
{
  int i;

  for (i = 0; i != 10; i++)
    gum_script_dummy_global_to_trick_optimizer += i * arg[0];

  /* Prevent optimizer from assuming what the return value is. */
  if (gum_script_dummy_global_to_trick_optimizer == 0)
    return NULL;

  return arg;
}

GUM_NOINLINE static void
target_function_callbacks (const gint value,
                           void (* first) (const gint * value),
                           void (* second) (const gint * value))
{
  int i;

  for (i = 0; i != 10; i++)
    gum_script_dummy_global_to_trick_optimizer += i * value;

  first (&value);

  second (&value);
}

GUM_NOINLINE static void
target_function_trigger (TestTrigger * trigger)
{
  g_mutex_lock (&trigger->mutex);
  trigger->ready = TRUE;
  g_cond_signal (&trigger->cond);
  g_mutex_unlock (&trigger->mutex);

  g_mutex_lock (&trigger->mutex);
  while (!trigger->fired)
    g_cond_wait (&trigger->cond, &trigger->mutex);
  g_mutex_unlock (&trigger->mutex);
}

GUM_NOINLINE static int
target_function_nested_a (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 7; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return target_function_nested_b (result);
}

GUM_NOINLINE static int
target_function_nested_b (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 14; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return target_function_nested_c (result);
}

GUM_NOINLINE static int
target_function_nested_c (int arg)
{
  int result = 0;
  int i;

  for (i = 0; i != 21; i++)
    result += i * arg;

  gum_script_dummy_global_to_trick_optimizer += result;

  return result;
}
```