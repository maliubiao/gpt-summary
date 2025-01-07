Response:
Let's break down the thought process for analyzing the given C++ code.

1. **Understand the Goal:** The first step is to understand the high-level purpose of the code. The directory name `v8/tools/v8windbg/test/` strongly suggests this is a test file for a tool named `v8windbg`. The inclusion of `<windows.h>`-related headers (even though not directly included in this snippet, the comments mention WinDbg) and COM hints at interaction with the Windows debugging environment.

2. **Identify Key Components:**  Look for the major building blocks and their roles.

    * **`LoadExtensionScope`:**  The name and comments clearly indicate this class manages loading and unloading a WinDbg extension (`v8windbg.dll`). The constructor loads it, and the destructor unloads it. The "HACK" comment is interesting and suggests a workaround for the loading process.
    * **`ComScope`:**  This class handles COM initialization and uninitialization. The comments link to official documentation, emphasizing the importance of balanced `CoInitializeEx` and `CoUninitialize` calls.
    * **`SetBreakpoint` and `SetBreakpointInV8OrD8`:** These functions are responsible for setting breakpoints within the debugged process (d8.exe or v8.dll). The latter tries different module names to accommodate various build configurations.
    * **`RunAndCheckOutput`:** This function executes a debugger command, captures the output, and verifies that the output contains expected substrings. This is a core testing utility.
    * **`RunTests`:** This is the main test function, orchestrating the setup, execution, and verification of the tests. It involves launching a process, attaching a debugger, setting breakpoints, running commands, and checking outputs.

3. **Trace the Execution Flow (of `RunTests`):**  Go through the `RunTests` function step-by-step to understand the sequence of operations.

    * **COM Initialization:** `ComScope` initializes COM.
    * **Module Path Retrieval:**  The code gets the directory where the test executable is located. This is important because it needs to find `d8.exe` and `v8windbg.dll`.
    * **Debug Client Creation:**  It creates a `IDebugClient5` interface, the primary entry point for interacting with the debugger engine.
    * **Symbol Handling:** It obtains `IDebugSymbols3` and sets the symbol path. This is crucial for the debugger to resolve function names to memory addresses.
    * **Event Callbacks:**  A custom event callback (`MyCallback`) is registered. Although the definition isn't in this snippet, we can infer it handles debugger events (like breakpoints).
    * **Process Launch:** `d8.exe` (the V8 JavaScript shell) is launched under the debugger. The script `v8windbg-test-script.js` is passed as an argument.
    * **Initial Break:** The debugger waits for the initial breakpoint after process attachment.
    * **Second Break:** It sets an engine option for another break after modules are loaded.
    * **Breakpoint Setting (C++):** A breakpoint is set in the `v8::internal::JsonStringify` function within the V8 engine. This means the test intends to inspect the V8 runtime during JavaScript execution.
    * **Execution and Break:** The debugged process is resumed (`DEBUG_STATUS_GO`) and the debugger waits for the breakpoint to be hit.
    * **Extension Loading:** The `LoadExtensionScope` loads `v8windbg.dll`.
    * **Output Capture:** `MyOutput` (again, definition not shown, but likely captures debugger output) is initialized.
    * **Stepping Mode:** The debugger is set to source-level stepping.
    * **Test Execution:**  `RunAndCheckOutput` is called multiple times to execute debugger commands (`dx`) and verify the output. These commands are clearly targeting internal V8 data structures (e.g., `replacer.Value.shared_function_info.flags`, `object.Value.@\"in-object properties\"`). The tests cover various aspects of V8 object representation.
    * **`@$curisolate()` Test:**  This tests a specific feature of the `v8windbg` extension – the ability to access the current V8 isolate.
    * **Detachment:** The debugger detaches from the process.

4. **Infer Functionality:** Based on the components and execution flow, we can deduce the purpose of `v8windbg-test.cc`:

    * **It's a test suite for the `v8windbg` WinDbg extension.**
    * **It automates debugging sessions of `d8.exe` to verify the functionality of `v8windbg`.**
    * **It sets breakpoints in V8 C++ code and uses debugger commands to inspect V8's internal state.**
    * **It checks if `v8windbg` can correctly display information about V8 objects, properties, the JavaScript stack, and other runtime details.**

5. **Address Specific Questions:** Now, we can address the specific questions raised in the prompt:

    * **Functionality:**  As described above.
    * **`.tq` extension:** The code is C++, so it's not a Torque file.
    * **Relationship to JavaScript:**  The tests debug JavaScript execution within `d8.exe` and inspect V8 internals related to JavaScript objects and execution.
    * **JavaScript Example:**  A simple JavaScript code snippet that would trigger the breakpoint in `JsonStringify` is `JSON.stringify({a: 1});`.
    * **Code Logic Reasoning (Input/Output):** `RunAndCheckOutput` provides examples. For instance, when examining `replacer.Value.shared_function_info.flags`, it expects to find "kNamedExpression" in the output. The input is the debugger command, and the output is the debugger's response.
    * **Common Programming Errors:** The example of incorrect symbol path illustrates a common debugging setup issue.

6. **Refine and Organize:** Finally, organize the findings into a clear and concise explanation, as provided in the initial good answer. Use headings, bullet points, and examples to enhance readability. Pay attention to details like the purpose of each class and function.
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <exception>
#include <vector>

#include "src/base/logging.h"
#include "tools/v8windbg/test/debug-callbacks.h"

// See the docs at
// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/using-the-debugger-engine-api

namespace v8 {
namespace internal {
namespace v8windbg_test {

namespace {

// Loads a named extension library upon construction and unloads it upon
// destruction.
class V8_NODISCARD LoadExtensionScope {
 public:
  LoadExtensionScope(WRL::ComPtr<IDebugControl4> p_debug_control,
                     std::wstring extension_path)
      : p_debug_control_(p_debug_control),
        extension_path_(std::move(extension_path)) {
    p_debug_control->AddExtensionWide(extension_path_.c_str(), 0, &ext_handle_);
    // HACK: Below fails, but is required for the extension to actually
    // initialize. Just the AddExtension call doesn't actually load and
    // initialize it.
    p_debug_control->CallExtension(ext_handle_, "Foo", "Bar");
  }
  ~LoadExtensionScope() {
    // Let the extension uninitialize so it can deallocate memory, meaning any
    // reported memory leaks should be real bugs.
    p_debug_control_->RemoveExtension(ext_handle_);
  }

 private:
  LoadExtensionScope(const LoadExtensionScope&) = delete;
  LoadExtensionScope& operator=(const LoadExtensionScope&) = delete;
  WRL::ComPtr<IDebugControl4> p_debug_control_;
  ULONG64 ext_handle_;
  // This string is part of the heap snapshot when the extension loads, so keep
  // it alive until after the extension unloads and checks for any heap changes.
  std::wstring extension_path_;
};

// Initializes COM upon construction and uninitializes it upon destruction.
class V8_NODISCARD ComScope {
 public:
  ComScope() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
  ~ComScope() {
    // "To close the COM library gracefully on a thread, each successful call to
    // CoInitialize or CoInitializeEx, including any call that returns S_FALSE,
    // must be balanced by a corresponding call to CoUninitialize."
    // https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
    if (SUCCEEDED(hr_)) {
      CoUninitialize();
    }
  }
  HRESULT hr() { return hr_; }

 private:
  HRESULT hr_;
};

// Sets a breakpoint. Returns S_OK if the function name resolved successfully
// and the breakpoint is in a non-deferred state.
HRESULT SetBreakpoint(WRL::ComPtr<IDebugControl4> p_debug_control,
                      const char* function_name) {
  WRL::ComPtr<IDebugBreakpoint> bp;
  HRESULT hr =
      p_debug_control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
  if (FAILED(hr)) return hr;
  hr = bp->SetOffsetExpression(function_name);
  if (FAILED(hr)) return hr;
  hr = bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);
  if (FAILED(hr)) return hr;

  // Check whether the symbol could be found.
  uint64_t offset;
  hr = bp->GetOffset(&offset);
  return hr;
}

// Sets a breakpoint. Depending on the build configuration, the function might
// be in the v8 or d8 module, so this function tries to set both.
HRESULT SetBreakpointInV8OrD8(WRL::ComPtr<IDebugControl4> p_debug_control,
                              const std::string& function_name) {
  // Component builds call the V8 module "v8". Try this first, because there is
  // also a module named "d8" or "d8_exe" where we should avoid attempting to
  // set a breakpoint.
  HRESULT hr = SetBreakpoint(p_debug_control, ("v8!" + function_name).c_str());
  if (SUCCEEDED(hr)) return hr;

  // x64 release builds call it "d8".
  hr = SetBreakpoint(p_debug_control, ("d8!" + function_name).c_str());
  if (SUCCEEDED(hr)) return hr;

  // x86 release builds call it "d8_exe".
  return SetBreakpoint(p_debug_control, ("d8_exe!" + function_name).c_str());
}

void RunAndCheckOutput(const char* friendly_name, const char* command,
                       std::vector<const char*> expected_substrings,
                       MyOutput* output, IDebugControl4* p_debug_control) {
  output->ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command,
                                           DEBUG_EXECUTE_ECHO)));
  for (const char* expected : expected_substrings) {
    CHECK(output->GetLog().find(expected) != std::string::npos);
  }
}

}  // namespace

void RunTests() {
  // Initialize COM... Though it doesn't seem to matter if you don't!
  ComScope com_scope;
  CHECK(SUCCEEDED(com_scope.hr()));

  // Get the file path of the module containing this test function. It should be
  // in the output directory alongside the data dependencies required by this
  // test (d8.exe, v8windbg.dll, and v8windbg-test-script.js).
  HMODULE module = nullptr;
  bool success =
      GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(&RunTests), &module);
  CHECK(success);
  wchar_t this_module_path[MAX_PATH];
  DWORD path_size = GetModuleFileName(module, this_module_path, MAX_PATH);
  CHECK(path_size != 0);
  HRESULT hr = PathCchRemoveFileSpec(this_module_path, MAX_PATH);
  CHECK(SUCCEEDED(hr));

  // Get the Debug client
  WRL::ComPtr<IDebugClient5> p_client;
  hr = DebugCreate(__uuidof(IDebugClient5), &p_client);
  CHECK(SUCCEEDED(hr));

  WRL::ComPtr<IDebugSymbols3> p_symbols;
  hr = p_client->QueryInterface(__uuidof(IDebugSymbols3), &p_symbols);
  CHECK(SUCCEEDED(hr));

  // Symbol loading fails if the pdb is in the same folder as the exe, but it's
  // not on the path.
  hr = p_symbols->SetSymbolPathWide(this_module_path);
  CHECK(SUCCEEDED(hr));

  // Set the event callbacks
  MyCallback callback;
  hr = p_client->SetEventCallbacks(&callback);
  CHECK(SUCCEEDED(hr));

  // Launch the process with the debugger attached
  std::wstring command_line =
      std::wstring(L"\"") + this_module_path + L"\\d8.exe\" \"" +
      this_module_path + L"\\obj\\tools\\v8windbg\\v8windbg-test-script.js\"";
  DEBUG_CREATE_PROCESS_OPTIONS proc_options;
  proc_options.CreateFlags = DEBUG_PROCESS;
  proc_options.EngCreateFlags = 0;
  proc_options.VerifierFlags = 0;
  proc_options.Reserved = 0;
  hr = p_client->CreateProcessWide(
      0, const_cast<wchar_t*>(command_line.c_str()), DEBUG_PROCESS);
  CHECK(SUCCEEDED(hr));

  // Wait for the attach event
  WRL::ComPtr<IDebugControl4> p_debug_control;
  hr = p_client->QueryInterface(__uuidof(IDebugControl4), &p_debug_control);
  CHECK(SUCCEEDED(hr));
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  // Break again after non-delay-load modules are loaded.
  hr = p_debug_control->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
  CHECK(SUCCEEDED(hr));
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  // Set a breakpoint in a C++ function called by the script.
  hr = SetBreakpointInV8OrD8(p_debug_control, "v8::internal::JsonStringify");
  CHECK(SUCCEEDED(hr));

  hr = p_debug_control->SetExecutionStatus(DEBUG_STATUS_GO);
  CHECK(SUCCEEDED(hr));

  // Wait for the breakpoint.
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  ULONG type, proc_id, thread_id, desc_used;
  uint8_t desc[1024];
  hr = p_debug_control->GetLastEventInformation(
      &type, &proc_id, &thread_id, nullptr, 0, nullptr,
      reinterpret_cast<PSTR>(desc), 1024, &desc_used);
  CHECK(SUCCEEDED(hr));

  LoadExtensionScope extension_loaded(
      p_debug_control, this_module_path + std::wstring(L"\\v8windbg.dll"));

  // Set the output callbacks after the extension is loaded, so it gets
  // destroyed before the extension unloads. This avoids reporting incorrectly
  // reporting that the output buffer was leaked during extension teardown.
  MyOutput output(p_client);

  // Set stepping mode.
  hr = p_debug_control->SetCodeLevel(DEBUG_LEVEL_SOURCE);
  CHECK(SUCCEEDED(hr));

  // Do some actual testing
  RunAndCheckOutput("bitfields",
                    "p;dx replacer.Value.shared_function_info.flags",
                    {"kNamedExpression"}, &output, p_debug_control.Get());

  RunAndCheckOutput("in-object properties",
                    "dx object.Value.@\"in-object properties\"[1]",
                    {"NullValue", "Oddball"}, &output, p_debug_control.Get());

  RunAndCheckOutput(
      "arrays of structs",
      "dx object.Value.map.instance_descriptors.descriptors[1].key",
      {"\"secondProp\"", "SeqOneByteString"}, &output, p_debug_control.Get());

  // TODO(v8:11527): enable this when symbol information for the in-Isolate
  // builtins is available.
  // RunAndCheckOutput(
  //     "local variables",
  //     "dx -r1 @$curthread.Stack.Frames.Where(f => "
  //     "f.ToDisplayString().Contains(\"InterpreterEntryTrampoline\")).Skip(1)."
  //     "First().LocalVariables.@\"memory interpreted as Objects\"",
  //     {"\"hello\""}, &output, p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[0].function_name",
                    {"\"a\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[1].function_name",
                    {"\"b\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[2].function_name",
                    {"empty_string \"\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  // Test for @$curisolate(). This should have the same output with
  // `dx v8::internal::g_current_isolate_`.
  output.ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(
      DEBUG_OUTCTL_ALL_CLIENTS, "dx v8::internal::g_current_isolate_",
      DEBUG_EXECUTE_ECHO)));
  size_t addr_pos = output.GetLog().find("0x");
  CHECK(addr_pos != std::string::npos);
  std::string expected_output = output.GetLog().substr(addr_pos);

  output.ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(
      DEBUG_OUTCTL_ALL_CLIENTS, "dx @$curisolate()", DEBUG_EXECUTE_ECHO)));
  CHECK_EQ(output.GetLog().substr(output.GetLog().find("0x")), expected_output);

  // Detach before exiting
  hr = p_client->DetachProcesses();
  CHECK(SUCCEEDED(hr));
}

}  // namespace v8windbg_test
}  // namespace internal
}  // namespace v8
```

### 功能列表

`v8/tools/v8windbg/test/v8windbg-test.cc` 是一个 C++ 源代码文件，用于测试 `v8windbg` 这个 V8 的 WinDbg 扩展的功能。它的主要功能是：

1. **加载和卸载 `v8windbg.dll` 扩展:**  通过 `LoadExtensionScope` 类来管理 `v8windbg.dll` 的加载和卸载，确保在测试期间扩展被加载，并在测试结束后卸载。
2. **启动带有调试器附加的 V8 (d8.exe) 进程:**  使用 Windows Debugging API (`DebugCreate`, `CreateProcessWide`) 启动 `d8.exe` 进程，并将其置于调试模式下。
3. **设置断点:**  在 V8 的 C++ 源代码中设置断点，例如 `v8::internal::JsonStringify` 函数。这允许测试在特定的 V8 代码执行点暂停，以便检查其状态。
4. **执行调试器命令并检查输出:** 使用 `IDebugControl4::Execute` 方法执行 WinDbg 的调试器命令（例如 `dx` 命令用于显示表达式的值）。然后，它会检查命令的输出是否包含预期的子字符串，以此验证 `v8windbg` 扩展的功能是否正常。
5. **测试 `v8windbg` 提供的功能:**  通过执行特定的调试器命令，测试 `v8windbg` 扩展提供的自定义功能，例如：
    * 查看对象的位域 (`bitfields` 测试)。
    * 查看对象的内联属性 (`in-object properties` 测试)。
    * 查看结构体数组 (`arrays of structs` 测试)。
    * 查看 JavaScript 栈帧 (`js stack` 测试)。
    * 测试访问当前 Isolate 的功能 (`@$curisolate()` 测试)。
6. **COM 初始化和清理:** 使用 `ComScope` 类来初始化和清理 COM 库，这是 Windows 调试 API 所需的。
7. **符号加载:**  设置符号路径，以便调试器可以解析函数名和变量名。
8. **事件回调:**  设置调试事件回调 (`MyCallback`)，虽然这段代码中没有展示 `MyCallback` 的具体实现，但它用于处理调试事件。

### 关于文件扩展名和 Torque

如果 `v8/tools/v8windbg/test/v8windbg-test.cc` 以 `.tq` 结尾，那么它确实会是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。但是，根据提供的代码内容和 `.cc` 扩展名，它是一个 **C++** 文件，而不是 Torque 文件。

### 与 JavaScript 的关系及示例

`v8/tools/v8windbg/test/v8windbg-test.cc` 与 JavaScript 的功能有密切关系，因为它测试的是用于调试 V8 JavaScript 引擎的工具。测试代码会启动 `d8.exe`（V8 的 JavaScript shell），执行一个 JavaScript 脚本 (`v8windbg-test-script.js`)，并在 V8 的 C++ 代码执行过程中设置断点，检查 V8 内部状态。

**JavaScript 示例:**

假设 `v8windbg-test-script.js` 中包含以下 JavaScript 代码：

```javascript
function a(x) {
  return b(x + 1);
}

function b(y) {
  return JSON.stringify({ value: y });
}

a(5);
```

当测试运行时，`v8windbg-test.cc` 会在 `v8::internal::JsonStringify` 函数中设置断点。当 JavaScript 代码执行到 `JSON.stringify({ value: y })` 时，断点会被触发，允许测试代码检查此时 V8 的内部状态，例如局部变量 `y` 的值，或者传递给 `JSON.stringify` 的对象的结构。

### 代码逻辑推理及假设输入与输出

**示例：`RunAndCheckOutput("bitfields", "p;dx replacer.Value.shared_function_info.flags", {"kNamedExpression"}, &output, p_debug_control.Get());`**

* **假设输入:**
    * 调试器已经附加到 `d8.exe` 进程，并且执行已经暂停在某个状态。
    * `replacer.Value` 是一个 V8 内部对象，具有 `shared_function_info` 属性，该属性又有一个 `flags` 成员，它是一个位域。
* **执行的调试器命令:** `p;dx replacer.Value.shared_function_info.flags`
    * `p` 是一个 WinDbg 命令，通常用于打印某些信息，在这里可能用于刷新上下文或执行一些准备工作（具体取决于调试器扩展的实现）。
    * `dx` 是 WinDbg 的 "display expression" 命令，用于显示 C++ 表达式的值。
* **预期输出:** 输出的日志中包含字符串 `"kNamedExpression"`。 这意味着 `v8windbg` 能够正确地解析并显示 `shared_function_info.flags` 位域的值，并且其中一个标志是 `kNamedExpression`。

**推理:** 这个测试的目标是验证 `v8windbg` 扩展能够正确地访问和显示 V8 内部对象的位域成员。如果输出中找到了 `"kNamedExpression"`，则表明扩展工作正常。

### 涉及用户常见的编程错误

虽然 `v8windbg-test.cc` 本身是测试代码，它的目的是验证调试工具的功能，但它也间接涉及了在调试 V8 或其他 C++ 项目时用户可能遇到的常见编程错误，特别是与调试器配置和符号加载相关的问题：

1. **符号加载失败:** 代码中注释提到 "Symbol loading fails if the pdb is in the same folder as the exe, but it's not on the path."  这是一个常见的调试错误。如果调试器的符号文件（.pdb）没有正确加载，你就无法查看函数名、变量名等符号信息，只能看到内存地址，这使得调试非常困难。`v8windbg-test.cc` 通过 `p_symbols->SetSymbolPathWide(this_module_path);` 来确保符号路径被正确设置。

   **示例:** 用户在 WinDbg 中调试 `d8.exe`，但没有设置正确的符号路径，或者符号文件缺失或版本不匹配，会导致 `dx` 命令无法显示有意义的类型信息，只能看到原始的内存数据。

2. **扩展加载失败或初始化问题:** `LoadExtensionScope` 类中的 "HACK" 注释表明，仅仅调用 `AddExtensionWide` 可能不足以完全初始化扩展，可能需要额外的步骤（例如调用一个虚拟的扩展函数）。这反映了用户在使用 WinDbg 扩展时可能遇到的加载和初始化问题。

   **示例:** 用户尝试加载一个 WinDbg 扩展，但发现扩展的命令无法使用或者行为异常，这可能是由于扩展加载不完整或者初始化失败导致的。

3. **不正确的调试器命令或表达式:**  `RunAndCheckOutput` 函数通过执行 `dx` 命令来检查 V8 的内部状态。如果用户在 WinDbg 中使用了错误的命令语法或表达式，他们将无法获取所需的信息，或者会得到错误的结果。`v8windbg-test.cc` 通过预定义的命令和期望的输出来验证这些命令的正确性。

   **示例:** 用户可能错误地拼写了 V8 内部的变量名或属性名，导致 `dx` 命令无法找到该符号。

总而言之，`v8/tools/v8windbg/test/v8windbg-test.cc` 是一个至关重要的测试文件，它确保了 `v8windbg` 扩展的正确性和可靠性，从而帮助 V8 开发者有效地调试 V8 JavaScript 引擎。它通过模拟真实的调试场景，并验证调试器命令的输出，来达到测试目的。

Prompt: 
```
这是目录为v8/tools/v8windbg/test/v8windbg-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/tools/v8windbg/test/v8windbg-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdio>
#include <exception>
#include <vector>

#include "src/base/logging.h"
#include "tools/v8windbg/test/debug-callbacks.h"

// See the docs at
// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/using-the-debugger-engine-api

namespace v8 {
namespace internal {
namespace v8windbg_test {

namespace {

// Loads a named extension library upon construction and unloads it upon
// destruction.
class V8_NODISCARD LoadExtensionScope {
 public:
  LoadExtensionScope(WRL::ComPtr<IDebugControl4> p_debug_control,
                     std::wstring extension_path)
      : p_debug_control_(p_debug_control),
        extension_path_(std::move(extension_path)) {
    p_debug_control->AddExtensionWide(extension_path_.c_str(), 0, &ext_handle_);
    // HACK: Below fails, but is required for the extension to actually
    // initialize. Just the AddExtension call doesn't actually load and
    // initialize it.
    p_debug_control->CallExtension(ext_handle_, "Foo", "Bar");
  }
  ~LoadExtensionScope() {
    // Let the extension uninitialize so it can deallocate memory, meaning any
    // reported memory leaks should be real bugs.
    p_debug_control_->RemoveExtension(ext_handle_);
  }

 private:
  LoadExtensionScope(const LoadExtensionScope&) = delete;
  LoadExtensionScope& operator=(const LoadExtensionScope&) = delete;
  WRL::ComPtr<IDebugControl4> p_debug_control_;
  ULONG64 ext_handle_;
  // This string is part of the heap snapshot when the extension loads, so keep
  // it alive until after the extension unloads and checks for any heap changes.
  std::wstring extension_path_;
};

// Initializes COM upon construction and uninitializes it upon destruction.
class V8_NODISCARD ComScope {
 public:
  ComScope() { hr_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
  ~ComScope() {
    // "To close the COM library gracefully on a thread, each successful call to
    // CoInitialize or CoInitializeEx, including any call that returns S_FALSE,
    // must be balanced by a corresponding call to CoUninitialize."
    // https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
    if (SUCCEEDED(hr_)) {
      CoUninitialize();
    }
  }
  HRESULT hr() { return hr_; }

 private:
  HRESULT hr_;
};

// Sets a breakpoint. Returns S_OK if the function name resolved successfully
// and the breakpoint is in a non-deferred state.
HRESULT SetBreakpoint(WRL::ComPtr<IDebugControl4> p_debug_control,
                      const char* function_name) {
  WRL::ComPtr<IDebugBreakpoint> bp;
  HRESULT hr =
      p_debug_control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp);
  if (FAILED(hr)) return hr;
  hr = bp->SetOffsetExpression(function_name);
  if (FAILED(hr)) return hr;
  hr = bp->AddFlags(DEBUG_BREAKPOINT_ENABLED);
  if (FAILED(hr)) return hr;

  // Check whether the symbol could be found.
  uint64_t offset;
  hr = bp->GetOffset(&offset);
  return hr;
}

// Sets a breakpoint. Depending on the build configuration, the function might
// be in the v8 or d8 module, so this function tries to set both.
HRESULT SetBreakpointInV8OrD8(WRL::ComPtr<IDebugControl4> p_debug_control,
                              const std::string& function_name) {
  // Component builds call the V8 module "v8". Try this first, because there is
  // also a module named "d8" or "d8_exe" where we should avoid attempting to
  // set a breakpoint.
  HRESULT hr = SetBreakpoint(p_debug_control, ("v8!" + function_name).c_str());
  if (SUCCEEDED(hr)) return hr;

  // x64 release builds call it "d8".
  hr = SetBreakpoint(p_debug_control, ("d8!" + function_name).c_str());
  if (SUCCEEDED(hr)) return hr;

  // x86 release builds call it "d8_exe".
  return SetBreakpoint(p_debug_control, ("d8_exe!" + function_name).c_str());
}

void RunAndCheckOutput(const char* friendly_name, const char* command,
                       std::vector<const char*> expected_substrings,
                       MyOutput* output, IDebugControl4* p_debug_control) {
  output->ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, command,
                                           DEBUG_EXECUTE_ECHO)));
  for (const char* expected : expected_substrings) {
    CHECK(output->GetLog().find(expected) != std::string::npos);
  }
}

}  // namespace

void RunTests() {
  // Initialize COM... Though it doesn't seem to matter if you don't!
  ComScope com_scope;
  CHECK(SUCCEEDED(com_scope.hr()));

  // Get the file path of the module containing this test function. It should be
  // in the output directory alongside the data dependencies required by this
  // test (d8.exe, v8windbg.dll, and v8windbg-test-script.js).
  HMODULE module = nullptr;
  bool success =
      GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(&RunTests), &module);
  CHECK(success);
  wchar_t this_module_path[MAX_PATH];
  DWORD path_size = GetModuleFileName(module, this_module_path, MAX_PATH);
  CHECK(path_size != 0);
  HRESULT hr = PathCchRemoveFileSpec(this_module_path, MAX_PATH);
  CHECK(SUCCEEDED(hr));

  // Get the Debug client
  WRL::ComPtr<IDebugClient5> p_client;
  hr = DebugCreate(__uuidof(IDebugClient5), &p_client);
  CHECK(SUCCEEDED(hr));

  WRL::ComPtr<IDebugSymbols3> p_symbols;
  hr = p_client->QueryInterface(__uuidof(IDebugSymbols3), &p_symbols);
  CHECK(SUCCEEDED(hr));

  // Symbol loading fails if the pdb is in the same folder as the exe, but it's
  // not on the path.
  hr = p_symbols->SetSymbolPathWide(this_module_path);
  CHECK(SUCCEEDED(hr));

  // Set the event callbacks
  MyCallback callback;
  hr = p_client->SetEventCallbacks(&callback);
  CHECK(SUCCEEDED(hr));

  // Launch the process with the debugger attached
  std::wstring command_line =
      std::wstring(L"\"") + this_module_path + L"\\d8.exe\" \"" +
      this_module_path + L"\\obj\\tools\\v8windbg\\v8windbg-test-script.js\"";
  DEBUG_CREATE_PROCESS_OPTIONS proc_options;
  proc_options.CreateFlags = DEBUG_PROCESS;
  proc_options.EngCreateFlags = 0;
  proc_options.VerifierFlags = 0;
  proc_options.Reserved = 0;
  hr = p_client->CreateProcessWide(
      0, const_cast<wchar_t*>(command_line.c_str()), DEBUG_PROCESS);
  CHECK(SUCCEEDED(hr));

  // Wait for the attach event
  WRL::ComPtr<IDebugControl4> p_debug_control;
  hr = p_client->QueryInterface(__uuidof(IDebugControl4), &p_debug_control);
  CHECK(SUCCEEDED(hr));
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  // Break again after non-delay-load modules are loaded.
  hr = p_debug_control->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
  CHECK(SUCCEEDED(hr));
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  // Set a breakpoint in a C++ function called by the script.
  hr = SetBreakpointInV8OrD8(p_debug_control, "v8::internal::JsonStringify");
  CHECK(SUCCEEDED(hr));

  hr = p_debug_control->SetExecutionStatus(DEBUG_STATUS_GO);
  CHECK(SUCCEEDED(hr));

  // Wait for the breakpoint.
  hr = p_debug_control->WaitForEvent(0, INFINITE);
  CHECK(SUCCEEDED(hr));

  ULONG type, proc_id, thread_id, desc_used;
  uint8_t desc[1024];
  hr = p_debug_control->GetLastEventInformation(
      &type, &proc_id, &thread_id, nullptr, 0, nullptr,
      reinterpret_cast<PSTR>(desc), 1024, &desc_used);
  CHECK(SUCCEEDED(hr));

  LoadExtensionScope extension_loaded(
      p_debug_control, this_module_path + std::wstring(L"\\v8windbg.dll"));

  // Set the output callbacks after the extension is loaded, so it gets
  // destroyed before the extension unloads. This avoids reporting incorrectly
  // reporting that the output buffer was leaked during extension teardown.
  MyOutput output(p_client);

  // Set stepping mode.
  hr = p_debug_control->SetCodeLevel(DEBUG_LEVEL_SOURCE);
  CHECK(SUCCEEDED(hr));

  // Do some actual testing
  RunAndCheckOutput("bitfields",
                    "p;dx replacer.Value.shared_function_info.flags",
                    {"kNamedExpression"}, &output, p_debug_control.Get());

  RunAndCheckOutput("in-object properties",
                    "dx object.Value.@\"in-object properties\"[1]",
                    {"NullValue", "Oddball"}, &output, p_debug_control.Get());

  RunAndCheckOutput(
      "arrays of structs",
      "dx object.Value.map.instance_descriptors.descriptors[1].key",
      {"\"secondProp\"", "SeqOneByteString"}, &output, p_debug_control.Get());

  // TODO(v8:11527): enable this when symbol information for the in-Isolate
  // builtins is available.
  // RunAndCheckOutput(
  //     "local variables",
  //     "dx -r1 @$curthread.Stack.Frames.Where(f => "
  //     "f.ToDisplayString().Contains(\"InterpreterEntryTrampoline\")).Skip(1)."
  //     "First().LocalVariables.@\"memory interpreted as Objects\"",
  //     {"\"hello\""}, &output, p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[0].function_name",
                    {"\"a\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[1].function_name",
                    {"\"b\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  RunAndCheckOutput("js stack", "dx @$jsstack()[2].function_name",
                    {"empty_string \"\"", "SeqOneByteString"}, &output,
                    p_debug_control.Get());

  // Test for @$curisolate(). This should have the same output with
  // `dx v8::internal::g_current_isolate_`.
  output.ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(
      DEBUG_OUTCTL_ALL_CLIENTS, "dx v8::internal::g_current_isolate_",
      DEBUG_EXECUTE_ECHO)));
  size_t addr_pos = output.GetLog().find("0x");
  CHECK(addr_pos != std::string::npos);
  std::string expected_output = output.GetLog().substr(addr_pos);

  output.ClearLog();
  CHECK(SUCCEEDED(p_debug_control->Execute(
      DEBUG_OUTCTL_ALL_CLIENTS, "dx @$curisolate()", DEBUG_EXECUTE_ECHO)));
  CHECK_EQ(output.GetLog().substr(output.GetLog().find("0x")), expected_output);

  // Detach before exiting
  hr = p_client->DetachProcesses();
  CHECK(SUCCEEDED(hr));
}

}  // namespace v8windbg_test
}  // namespace internal
}  // namespace v8

"""

```