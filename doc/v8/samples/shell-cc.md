Response:
Let's break down the thought process for analyzing the `v8/samples/shell.cc` code.

**1. Initial Scan and High-Level Understanding:**

The first step is to quickly read through the code, paying attention to comments, function names, and included headers. Keywords like "shell," "javascript," "context," "isolate," "compile," and "execute" jump out. The copyright notice also confirms it's a V8 project example. The initial comment clearly states its purpose: a simple JavaScript shell based on V8.

**2. Identifying Key Functions:**

Next, focus on the functions declared at the top. These are likely the core building blocks of the shell. Functions like `CreateShellContext`, `RunShell`, `RunMain`, `ExecuteString`, `Print`, `Read`, `Load`, `Quit`, and `Version` all seem directly related to the shell's functionality.

**3. Understanding the `main` Function:**

The `main` function is the entry point, so it's crucial to understand its flow:

* **Initialization:** It initializes V8 using `InitializeICUDefaultLocation`, `InitializeExternalStartupData`, `InitializePlatform`, and `Initialize`. It also handles command-line flags.
* **Isolate Creation:** It creates a V8 isolate, which is an isolated instance of the V8 engine.
* **Context Creation:**  It calls `CreateShellContext` to set up the JavaScript execution environment.
* **Running Code:** It calls `RunMain` to handle command-line arguments and execute scripts.
* **Interactive Shell (Optional):** If no command-line arguments are provided (meaning `argc == 1`), it calls `RunShell` for an interactive REPL.
* **Cleanup:** It disposes of the isolate and V8.

**4. Deconstructing Key Function Functionality:**

Now, analyze the purpose of the key functions identified earlier:

* **`CreateShellContext`:** Creates a V8 context, which is the environment in which JavaScript code executes. Crucially, it also binds global functions like `print`, `read`, `load`, `quit`, and `version` to their C++ implementations. This is how the C++ shell provides built-in functionality to JavaScript.
* **`RunShell`:** Implements the interactive read-eval-print loop (REPL). It prompts the user for input, reads a line, executes it using `ExecuteString`, and prints the result.
* **`RunMain`:** Processes command-line arguments. It handles options like `--shell`, `-e` (execute a string), and treats other arguments as file paths to load and execute.
* **`ExecuteString`:** The heart of the execution process. It takes a JavaScript source string, compiles it into a script, runs the script, and handles potential errors (compilation and runtime). It also manages printing the result if needed.
* **`Print`, `Read`, `Load`, `Quit`, `Version`:** These are the C++ implementations of the JavaScript global functions. Their names clearly indicate their purpose. `Read` reads a file, `Load` executes a file, `Quit` exits the shell, and `Version` returns the V8 version.

**5. Identifying JavaScript Interaction:**

The connection to JavaScript is evident in how the C++ code interacts with the V8 API:

* **Creating Contexts:** `v8::Context::New`.
* **Compiling Scripts:** `v8::Script::Compile`.
* **Running Scripts:** `v8::Script::Run`.
* **Handling Exceptions:** `v8::TryCatch`.
* **Setting Global Functions:** `global->Set(isolate, "print", ...)`.
* **Converting Between C++ and JavaScript Types:** `v8::String::NewFromUtf8`, `v8::String::Utf8Value`, `info[i]`.

**6. Considering Edge Cases and Potential Errors:**

Think about what could go wrong and how the code handles it:

* **File Not Found:** The `ReadFile` and `Load` functions check for null file pointers and throw errors.
* **Syntax Errors:** `ExecuteString` uses `v8::TryCatch` to catch compilation errors.
* **Runtime Errors:** `ExecuteString` also uses `v8::TryCatch` to catch runtime errors during script execution.
* **Invalid Input:** The `Read` function checks for the correct number of arguments.
* **Command-Line Argument Errors:** `RunMain` prints a warning for unknown flags.

**7. Formulating Examples:**

Based on the functionality, create concrete examples in JavaScript to illustrate how the shell works. This involves showing how to use the built-in functions and how the shell executes code.

**8. Checking for Torque:**

The prompt specifically mentions `.tq` files. A quick scan reveals no mention of `.tq` or Torque-related keywords. Therefore, the conclusion is that this file is not a Torque source file.

**9. Review and Refine:**

Finally, review the entire analysis for clarity, accuracy, and completeness. Ensure all aspects of the prompt have been addressed. For example, make sure the explanation of the command-line argument processing is clear and that the explanations of error handling are present.

This systematic approach, starting with a high-level overview and progressively digging deeper into the code's components and their interactions, allows for a thorough and accurate analysis of the `v8/samples/shell.cc` file. The emphasis on understanding the core functionality, how it relates to JavaScript, and how it handles potential issues is key to a good explanation.
`v8/samples/shell.cc` 是一个 V8 引擎的示例程序，实现了一个简单的 JavaScript 命令行解释器（shell）。它的主要功能是：

**主要功能:**

1. **初始化 V8 引擎:**  设置 V8 的运行环境，包括 ICU (用于国际化支持)、外部启动数据等。
2. **创建 V8 隔离区 (Isolate):**  V8 使用隔离区来提供独立的 JavaScript 执行环境。
3. **创建 V8 上下文 (Context):**  在隔离区内创建上下文，这是 JavaScript 代码实际运行的地方。
4. **注册全局函数:**  在创建的上下文中注册一些内置的全局函数，例如 `print`、`read`、`load`、`quit` 和 `version`，这些函数允许 JavaScript 代码与 shell 交互。
5. **处理命令行参数:**  解析命令行参数，例如 `--shell`（进入交互模式）、`-e`（执行一段 JavaScript 代码）以及指定要加载和执行的 JavaScript 文件。
6. **执行 JavaScript 代码:**
   -  **从命令行参数执行:**  如果提供了 `-e` 参数，则直接执行其后的 JavaScript 代码。
   -  **加载并执行文件:**  如果提供了文件名作为参数，则读取文件内容，编译并执行其中的 JavaScript 代码。
   -  **交互式执行:**  如果以交互模式运行，则读取用户输入的每一行，编译并执行。
7. **提供内置函数:**
   - **`print()`:**  将参数输出到标准输出。
   - **`read()`:**  读取指定文件的内容并返回一个字符串。
   - **`load()`:**  加载、编译并执行指定的 JavaScript 文件。
   - **`quit()`:**  退出 shell 程序，可以指定退出码。
   - **`version()`:** 返回当前 V8 引擎的版本号。
8. **错误处理:**  捕获并报告 JavaScript 代码执行期间的异常，包括编译错误和运行时错误，并提供错误发生的文件名、行号、错误信息和堆栈跟踪。
9. **交互式 REPL (Read-Eval-Print Loop):**  如果以交互模式运行，则提供一个提示符 (`> `)，用户可以输入 JavaScript 代码，shell 会执行并打印结果。

**关于文件扩展名和 Torque:**

如果 `v8/samples/shell.cc` 的文件名以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的运行时代码。然而，根据您提供的信息，文件名是 `shell.cc`，这意味着它是一个 C++ 源代码文件。

**与 JavaScript 功能的关系及示例:**

`v8/samples/shell.cc` 的核心功能就是执行 JavaScript 代码。它通过 V8 提供的 C++ API 来实现这一点。以下是一些 JavaScript 示例，展示了 shell 提供的功能：

```javascript
// 使用 print() 函数输出
print("Hello, world!");
print(1 + 2);

// 使用 read() 函数读取文件内容
let fileContent = read("my_script.js");
print(fileContent);

// 使用 load() 函数执行另一个 JavaScript 文件
load("another_script.js");

// 使用 version() 函数获取 V8 版本
print("V8 Version: " + version());

// 使用 quit() 函数退出 shell
// quit(0); // 正常退出
// quit(1); // 以错误码退出
```

**代码逻辑推理及假设输入与输出:**

假设我们以以下命令运行 `v8/samples/shell.cc` 编译后的可执行文件：

```bash
./shell my_script.js -e "print('Inline script executed');"
```

**假设输入:**

- **命令行参数:** `my_script.js`, `-e`, `"print('Inline script executed');"`
- **`my_script.js` 文件内容:**
  ```javascript
  print("Executing from my_script.js");
  let x = 10;
  let y = 20;
  print("Sum:", x + y);
  ```

**代码逻辑推理:**

1. `main` 函数初始化 V8 引擎。
2. `RunMain` 函数开始处理命令行参数。
3. 首先遇到 `my_script.js`，`RunMain` 会调用 `ReadFile` 读取其内容。
4. 然后，`RunMain` 调用 `ExecuteString` 编译并执行 `my_script.js` 中的代码。这将导致输出：
   ```
   Executing from my_script.js
   Sum: 30
   ```
5. 接着处理 `-e "print('Inline script executed');"` 参数。
6. `RunMain` 调用 `ExecuteString` 编译并执行 `"print('Inline script executed');"` 这段代码。这将导致输出：
   ```
   Inline script executed
   ```

**假设输出 (标准输出):**

```
Executing from my_script.js
Sum: 30
Inline script executed
```

**用户常见的编程错误及示例:**

使用 `v8/samples/shell.cc` 时，用户可能会遇到以下常见的 JavaScript 编程错误：

1. **语法错误:** 在 JavaScript 代码中存在拼写错误、缺少分号、括号不匹配等问题。

   ```javascript
   // 错误示例：缺少分号
   print("Hello")
   print("World")
   ```

   **错误输出 (stderr):**
   ```
   (shell):2: Unexpected identifier
   print("World")
   ^
   ```

2. **运行时错误:** 在代码执行过程中发生的错误，例如访问未定义的变量、调用不存在的函数、类型错误等。

   ```javascript
   // 错误示例：访问未定义的变量
   print(unknownVariable);
   ```

   **错误输出 (stderr):**
   ```
   (shell):1: ReferenceError: unknownVariable is not defined
   print(unknownVariable);
         ^
   ```

3. **文件操作错误:**  在使用 `read()` 或 `load()` 函数时，指定的文件不存在或没有读取权限。

   ```javascript
   // 错误示例：尝试读取不存在的文件
   let content = read("non_existent_file.txt");
   ```

   **错误输出 (stderr):**
   ```
   Error loading file
   ```

4. **`load()` 循环依赖:** 如果多个脚本之间存在相互 `load()` 的情况，可能会导致无限循环或栈溢出。

   **script1.js:**
   ```javascript
   load("script2.js");
   print("script1");
   ```

   **script2.js:**
   ```javascript
   load("script1.js");
   print("script2");
   ```

   运行 `load("script1.js")` 可能会导致错误，具体取决于 V8 的实现和栈大小限制。

`v8/samples/shell.cc` 通过 `v8::TryCatch` 来捕获这些错误，并使用 `ReportException` 函数将详细的错误信息输出到标准错误流，帮助用户调试他们的 JavaScript 代码。

Prompt: 
```
这是目录为v8/samples/shell.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/samples/shell.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <assert.h>
#include <fcntl.h>
#include <include/libplatform/libplatform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/v8-context.h"
#include "include/v8-exception.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-script.h"
#include "include/v8-template.h"

/**
 * This sample program shows how to implement a simple javascript shell
 * based on V8.  This includes initializing V8 with command line options,
 * creating global functions, compiling and executing strings.
 *
 * For a more sophisticated shell, consider using the debug shell D8.
 */

v8::Global<v8::Context> CreateShellContext(v8::Isolate* isolate);
void RunShell(v8::Isolate* isolate, const v8::Global<v8::Context>& context,
              v8::Platform* platform);
int RunMain(v8::Isolate* isolate, const v8::Global<v8::Context>& context,
            v8::Platform* platform, int argc, char* argv[]);
bool ExecuteString(v8::Isolate* isolate, v8::Local<v8::String> source,
                   v8::Local<v8::Value> name, bool print_result,
                   bool report_exceptions);
void Print(const v8::FunctionCallbackInfo<v8::Value>& info);
void Read(const v8::FunctionCallbackInfo<v8::Value>& info);
void Load(const v8::FunctionCallbackInfo<v8::Value>& info);
void Quit(const v8::FunctionCallbackInfo<v8::Value>& info);
void Version(const v8::FunctionCallbackInfo<v8::Value>& info);
v8::MaybeLocal<v8::String> ReadFile(v8::Isolate* isolate, const char* name);
void ReportException(v8::Isolate* isolate, v8::TryCatch* handler);

static bool run_shell;

int main(int argc, char* argv[]) {
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
  v8::V8::Initialize();
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  run_shell = (argc == 1);
  int result;
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::Global<v8::Context> context = CreateShellContext(isolate);
    if (context.IsEmpty()) {
      fprintf(stderr, "Error creating context\n");
      return 1;
    }
    result = RunMain(isolate, context, platform.get(), argc, argv);
    if (run_shell) RunShell(isolate, context, platform.get());
  }
  isolate->Dispose();
  v8::V8::Dispose();
  v8::V8::DisposePlatform();
  delete create_params.array_buffer_allocator;
  return result;
}

// Extracts a C string from a V8 Utf8Value.
const char* ToCString(const v8::String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

// Creates a new execution environment containing the built-in
// functions.
v8::Global<v8::Context> CreateShellContext(v8::Isolate* isolate) {
  v8::HandleScope handle_scope(isolate);
  // Create a template for the global object.
  v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
  // Bind the global 'print' function to the C++ Print callback.
  global->Set(isolate, "print", v8::FunctionTemplate::New(isolate, Print));
  // Bind the global 'read' function to the C++ Read callback.
  global->Set(isolate, "read", v8::FunctionTemplate::New(isolate, Read));
  // Bind the global 'load' function to the C++ Load callback.
  global->Set(isolate, "load", v8::FunctionTemplate::New(isolate, Load));
  // Bind the 'quit' function
  global->Set(isolate, "quit", v8::FunctionTemplate::New(isolate, Quit));
  // Bind the 'version' function
  global->Set(isolate, "version", v8::FunctionTemplate::New(isolate, Version));
  // Return the context.
  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
  return v8::Global<v8::Context>(isolate, context);
}

// The callback that is invoked by v8 whenever the JavaScript 'print'
// function is called.  Prints its arguments on stdout separated by
// spaces and ending with a newline.
void Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
  bool first = true;
  for (int i = 0; i < info.Length(); i++) {
    v8::HandleScope handle_scope(info.GetIsolate());
    if (first) {
      first = false;
    } else {
      printf(" ");
    }
    v8::String::Utf8Value str(info.GetIsolate(), info[i]);
    const char* cstr = ToCString(str);
    printf("%s", cstr);
  }
  printf("\n");
  fflush(stdout);
}

// The callback that is invoked by v8 whenever the JavaScript 'read'
// function is called.  This function loads the content of the file named in
// the argument into a JavaScript string.
void Read(const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() != 1) {
    info.GetIsolate()->ThrowError("Bad parameters");
    return;
  }
  v8::String::Utf8Value file(info.GetIsolate(), info[0]);
  if (*file == nullptr) {
    info.GetIsolate()->ThrowError("Error loading file");
    return;
  }
  v8::Local<v8::String> source;
  if (!ReadFile(info.GetIsolate(), *file).ToLocal(&source)) {
    info.GetIsolate()->ThrowError("Error loading file");
    return;
  }

  info.GetReturnValue().Set(source);
}

// The callback that is invoked by v8 whenever the JavaScript 'load'
// function is called.  Loads, compiles and executes its argument
// JavaScript file.
void Load(const v8::FunctionCallbackInfo<v8::Value>& info) {
  for (int i = 0; i < info.Length(); i++) {
    v8::HandleScope handle_scope(info.GetIsolate());
    v8::String::Utf8Value file(info.GetIsolate(), info[i]);
    if (*file == nullptr) {
      info.GetIsolate()->ThrowError("Error loading file");
      return;
    }
    v8::Local<v8::String> source;
    if (!ReadFile(info.GetIsolate(), *file).ToLocal(&source)) {
      info.GetIsolate()->ThrowError("Error loading file");
      return;
    }
    if (!ExecuteString(info.GetIsolate(), source, info[i], false, false)) {
      info.GetIsolate()->ThrowError("Error executing file");
      return;
    }
  }
}

// The callback that is invoked by v8 whenever the JavaScript 'quit'
// function is called.  Quits.
void Quit(const v8::FunctionCallbackInfo<v8::Value>& info) {
  // If not arguments are given info[0] will yield undefined which
  // converts to the integer value 0.
  int exit_code =
      info[0]->Int32Value(info.GetIsolate()->GetCurrentContext()).FromMaybe(0);
  fflush(stdout);
  fflush(stderr);
  exit(exit_code);
}

// The callback that is invoked by v8 whenever the JavaScript 'version'
// function is called.  Returns a string containing the current V8 version.
void Version(const v8::FunctionCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(
      v8::String::NewFromUtf8(info.GetIsolate(), v8::V8::GetVersion())
          .ToLocalChecked());
}

// Reads a file into a v8 string.
v8::MaybeLocal<v8::String> ReadFile(v8::Isolate* isolate, const char* name) {
  FILE* file = fopen(name, "rb");
  if (file == nullptr) return {};

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  rewind(file);

  char* chars = new char[size + 1];
  chars[size] = '\0';
  for (size_t i = 0; i < size;) {
    i += fread(&chars[i], 1, size - i, file);
    if (ferror(file)) {
      fclose(file);
      return {};
    }
  }
  fclose(file);
  v8::MaybeLocal<v8::String> result = v8::String::NewFromUtf8(
      isolate, chars, v8::NewStringType::kNormal, static_cast<int>(size));
  delete[] chars;
  return result;
}

// Process remaining command line arguments and execute files
int RunMain(v8::Isolate* isolate, const v8::Global<v8::Context>& context,
            v8::Platform* platform, int argc, char* argv[]) {
  for (int i = 1; i < argc; i++) {
    const char* str = argv[i];
    if (strcmp(str, "--shell") == 0) {
      run_shell = true;
    } else if (strcmp(str, "-f") == 0) {
      // Ignore any -f flags for compatibility with the other stand-
      // alone JavaScript engines.
      continue;
    } else if (strncmp(str, "--", 2) == 0) {
      fprintf(stderr,
              "Warning: unknown flag %s.\nTry --help for options\n", str);
    } else if (strcmp(str, "-e") == 0 && i + 1 < argc) {
      // Execute argument given to -e option directly.
      bool success;
      {
        // Enter the execution environment before evaluating any code.
        v8::HandleScope handle_scope(isolate);
        v8::Context::Scope context_scope(context.Get(isolate));
        v8::Local<v8::String> file_name =
            v8::String::NewFromUtf8Literal(isolate, "unnamed");
        v8::Local<v8::String> source;
        if (!v8::String::NewFromUtf8(isolate, argv[++i]).ToLocal(&source)) {
          return 1;
        }
        success = ExecuteString(isolate, source, file_name, false, true);
      }
      // It is important not to pump the message loop when there are v8::Local
      // handles on the stack, as this may trigger a stackless GC.
      while (v8::platform::PumpMessageLoop(platform, isolate)) continue;
      if (!success) return 1;
    } else {
      // Use all other arguments as names of files to load and run.
      bool success;
      {
        // Enter the execution environment before evaluating any code.
        v8::HandleScope handle_scope(isolate);
        v8::Context::Scope context_scope(context.Get(isolate));
        v8::Local<v8::String> file_name =
            v8::String::NewFromUtf8(isolate, str).ToLocalChecked();
        v8::Local<v8::String> source;
        if (!ReadFile(isolate, str).ToLocal(&source)) {
          fprintf(stderr, "Error reading '%s'\n", str);
          continue;
        }
        success = ExecuteString(isolate, source, file_name, false, true);
      }
      // It is important not to pump the message loop when there are v8::Local
      // handles on the stack, as this may trigger a stackless GC.
      while (v8::platform::PumpMessageLoop(platform, isolate)) continue;
      if (!success) return 1;
    }
  }
  return 0;
}

// The read-eval-execute loop of the shell.
void RunShell(v8::Isolate* isolate, const v8::Global<v8::Context>& context,
              v8::Platform* platform) {
  fprintf(stderr, "V8 version %s [sample shell]\n", v8::V8::GetVersion());
  static const int kBufferSize = 256;
  while (true) {
    char buffer[kBufferSize];
    fprintf(stderr, "> ");
    char* str = fgets(buffer, kBufferSize, stdin);
    if (str == nullptr) break;
    {
      // Enter the execution environment before evaluating any code.
      v8::HandleScope handle_scope(isolate);
      v8::Context::Scope context_scope(context.Get(isolate));
      v8::Local<v8::String> name(
          v8::String::NewFromUtf8Literal(isolate, "(shell)"));
      ExecuteString(isolate,
                    v8::String::NewFromUtf8(isolate, str).ToLocalChecked(),
                    name, true, true);
    }
    // It is important not to pump the message loop when there are v8::Local
    // handles on the stack, as this may trigger a stackless GC.
    while (v8::platform::PumpMessageLoop(platform, isolate)) continue;
  }
  fprintf(stderr, "\n");
}

// Executes a string within the current v8 context.
bool ExecuteString(v8::Isolate* isolate, v8::Local<v8::String> source,
                   v8::Local<v8::Value> name, bool print_result,
                   bool report_exceptions) {
  v8::HandleScope handle_scope(isolate);
  v8::TryCatch try_catch(isolate);
  v8::ScriptOrigin origin(name);
  v8::Local<v8::Context> context(isolate->GetCurrentContext());
  v8::Local<v8::Script> script;
  if (!v8::Script::Compile(context, source, &origin).ToLocal(&script)) {
    // Print errors that happened during compilation.
    if (report_exceptions)
      ReportException(isolate, &try_catch);
    return false;
  } else {
    v8::Local<v8::Value> result;
    if (!script->Run(context).ToLocal(&result)) {
      assert(try_catch.HasCaught());
      // Print errors that happened during execution.
      if (report_exceptions)
        ReportException(isolate, &try_catch);
      return false;
    } else {
      assert(!try_catch.HasCaught());
      if (print_result && !result->IsUndefined()) {
        // If all went well and the result wasn't undefined then print
        // the returned value.
        v8::String::Utf8Value str(isolate, result);
        const char* cstr = ToCString(str);
        printf("%s\n", cstr);
      }
      return true;
    }
  }
}

void ReportException(v8::Isolate* isolate, v8::TryCatch* try_catch) {
  v8::HandleScope handle_scope(isolate);
  v8::String::Utf8Value exception(isolate, try_catch->Exception());
  const char* exception_string = ToCString(exception);
  v8::Local<v8::Message> message = try_catch->Message();
  if (message.IsEmpty()) {
    // V8 didn't provide any extra information about this error; just
    // print the exception.
    fprintf(stderr, "%s\n", exception_string);
  } else {
    // Print (filename):(line number): (message).
    v8::String::Utf8Value filename(isolate,
                                   message->GetScriptOrigin().ResourceName());
    v8::Local<v8::Context> context(isolate->GetCurrentContext());
    const char* filename_string = ToCString(filename);
    int linenum = message->GetLineNumber(context).FromJust();
    fprintf(stderr, "%s:%i: %s\n", filename_string, linenum, exception_string);
    // Print line of source code.
    v8::String::Utf8Value sourceline(
        isolate, message->GetSourceLine(context).ToLocalChecked());
    const char* sourceline_string = ToCString(sourceline);
    fprintf(stderr, "%s\n", sourceline_string);
    // Print wavy underline (GetUnderline is deprecated).
    int start = message->GetStartColumn(context).FromJust();
    for (int i = 0; i < start; i++) {
      fprintf(stderr, " ");
    }
    int end = message->GetEndColumn(context).FromJust();
    for (int i = start; i < end; i++) {
      fprintf(stderr, "^");
    }
    fprintf(stderr, "\n");
    v8::Local<v8::Value> stack_trace_string;
    if (try_catch->StackTrace(context).ToLocal(&stack_trace_string) &&
        stack_trace_string->IsString() &&
        stack_trace_string.As<v8::String>()->Length() > 0) {
      v8::String::Utf8Value stack_trace(isolate, stack_trace_string);
      const char* err = ToCString(stack_trace);
      fprintf(stderr, "%s\n", err);
    }
  }
}

"""

```