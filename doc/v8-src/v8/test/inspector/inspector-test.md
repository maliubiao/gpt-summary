Response: Let's break down the thought process for analyzing this C++ file and relating it to JavaScript.

1. **Understand the Goal:** The primary goal is to understand what this C++ code does, specifically concerning its interaction with JavaScript. The filename `inspector-test.cc` hints at testing the V8 Inspector.

2. **Initial Scan for Keywords:** Look for obvious keywords and patterns:
    * `#include`:  These lines include headers, giving clues about the libraries and functionalities being used. `v8.h`, `v8-inspector.h`, and anything with "test/inspector" are strong indicators.
    * `namespace v8`: This confirms we're dealing with V8's internal code.
    * Class names like `UtilsExtension`, `ConsoleExtension`, `InspectorExtension`: These suggest modules or components that extend V8's functionality for testing purposes.
    * Function names within these classes, especially those with names that sound like JavaScript functions (e.g., `Print`, `Quit`, `load`, `schedulePauseOnNextStatement`).
    * Strings like `"utils"`, `"console"`, `"inspector"` being used as names for objects.
    * Usage of `v8::Local`, `v8::ObjectTemplate`, `v8::FunctionTemplate`: These are core V8 API elements for interacting with JavaScript objects and functions from C++.

3. **Focus on the Extensions:** The `UtilsExtension`, `ConsoleExtension`, and `InspectorExtension` classes appear to be the core of this file's functionality. Each has a `Run` method that sets up globals in the V8 JavaScript environment.

4. **Analyze Each Extension:**

    * **`UtilsExtension`:** This extension seems to provide utility functions accessible from JavaScript. The names of the registered functions (`print`, `quit`, `setlocale`, `read`, `load`, etc.) are very indicative of what they do. The presence of functions related to debugging (`schedulePauseOnNextStatement`, `cancelPauseOnNextStatement`, `waitForDebugger`) reinforces the "inspector test" idea. The `connectSession` and `disconnectSession` functions strongly point towards testing the inspector's connection mechanisms.

    * **`ConsoleExtension`:** This one is straightforward. It makes the standard JavaScript `console` object available in the test environment. It likely reuses or wraps V8's existing console implementation.

    * **`InspectorExtension`:** This extension offers functionalities specifically for testing the inspector. Functions like `fireContextCreated`, `fireContextDestroyed`, `breakProgram`, `addInspectedObject`, `setMaxAsyncTaskStacks` directly relate to inspector features and events.

5. **Identify the JavaScript Connection:** The `Run` methods in the extension classes are key. They use the V8 API (`v8::ObjectTemplate::New`, `Set`) to create JavaScript objects and functions, and then associate C++ implementations with those JavaScript functions. This is the fundamental mechanism for exposing C++ functionality to JavaScript within the V8 environment.

6. **Relate C++ Functions to JavaScript Equivalents:**  For each function registered in the extensions, think about how a developer would use a similar feature in JavaScript. For example:

    * `UtilsExtension::Print` maps directly to `console.log()` or similar printing in JavaScript.
    * `UtilsExtension::Quit` corresponds to stopping the execution environment.
    * `UtilsExtension::load('filename.js')` is the equivalent of `<script src="filename.js"></script>` or a dynamic `import()` in JavaScript.
    * Functions in `InspectorExtension` directly control inspector behavior, which developers might interact with via browser developer tools or programmatically using the DevTools Protocol.

7. **Construct JavaScript Examples:** Based on the C++ function names and their likely purpose, create simple JavaScript code snippets that demonstrate how a user would call these functions. This makes the connection between the C++ implementation and the JavaScript API clear.

8. **Summarize the Overall Functionality:** Combine the understanding of the individual extensions to describe the overarching purpose of the file. Emphasize that it's a testing framework for V8's inspector, providing tools to simulate inspector behavior and test its features.

9. **Refine and Organize:** Review the generated summary and examples for clarity and accuracy. Group related functions together. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this is just about setting up test environments."  **Correction:** While that's part of it, the specific function names and the "inspector" in the filename strongly suggest it's focused on *inspector* testing.
* **Realization:** Some functions in `UtilsExtension` (like `createContextGroup`, `connectSession`) seem more complex than simple utilities. **Refinement:** Recognize that these are about simulating inspector session management and context creation, which are necessary for testing inspector features.
* **Question:** How does the C++ code actually *execute* the JavaScript? **Answer:** The `ExecuteStringTask` class (mentioned in `Load` and `CompileAndRunWithOrigin`) is responsible for taking a JavaScript string and running it within a V8 context. The `TaskRunner` manages the execution of these tasks.
* **Clarity Improvement:** Initially, the explanation of the connection between C++ and JavaScript might be too technical. **Refinement:** Emphasize the practical outcome: C++ functions are made available as global functions or methods on specific objects in the JavaScript environment.

By following this structured approach, combining code analysis with an understanding of V8 and web development concepts, we can effectively understand the purpose and functionality of this C++ file and its relationship to JavaScript.
这个C++源代码文件 `inspector-test.cc` 的主要功能是为 V8 JavaScript 引擎的 Inspector（调试器和性能分析工具）提供**测试环境和辅助功能**。它不是 V8 Inspector 的核心实现，而是为编写和运行 Inspector 功能的集成测试而设计的。

以下是其主要功能的归纳：

**1. 提供测试用的全局 JavaScript 对象和函数：**

   - **`utils` 对象:**  包含一系列实用工具函数，这些函数可以在 JavaScript 测试代码中调用，用于控制测试环境、与后端通信等。例如：
     - `print()`:  在测试输出中打印信息。
     - `quit()`:  终止测试。
     - `load(filename)`: 加载并执行 JavaScript 文件。
     - `sendMessageToBackend(sessionId, message)`: 向 Inspector 后端发送消息。
     - `schedulePauseOnNextStatement()` / `cancelPauseOnNextStatement()`: 控制断点行为。
     - `createContextGroup()` / `createContext()`: 创建和管理 JavaScript 上下文组和上下文。
     - `connectSession()` / `disconnectSession()`: 模拟 Inspector 会话的连接和断开。
   - **`console` 对象:** 提供标准的 JavaScript `console` API（例如 `console.log`），用于在测试中输出日志信息。
   - **`inspector` 对象:**  提供与 Inspector 功能直接相关的函数，用于模拟 Inspector 的行为或触发特定事件：
     - `fireContextCreated()` / `fireContextDestroyed()`: 模拟 JavaScript 上下文的创建和销毁事件。
     - `breakProgram()`: 模拟在 JavaScript 代码中设置断点。
     - `addInspectedObject()`:  向 Inspector 添加被检查的对象。
     - `setMaxAsyncTaskStacks()`: 设置异步任务堆栈的最大深度。
     - `storeCurrentStackTrace()` / `externalAsyncTaskStarted()` / `externalAsyncTaskFinished()` / `scheduleWithAsyncStack()`: 用于测试异步操作和堆栈跟踪。

**2. 搭建测试框架：**

   - **`TaskRunner`:**  用于管理前端（执行 JavaScript 测试代码）和后端（模拟 Inspector 后端）的任务执行。这允许异步地执行测试和模拟 Inspector 的行为。
   - **`FrontendChannelImpl`:**  用于模拟 Inspector 前端与后端之间的通信通道。
   - **`InspectorIsolateData`:**  存储与每个 V8 Isolate 相关的 Inspector 测试数据。

**3. 模拟 Inspector 后端行为：**

   - 该文件本身不直接实现 Inspector 后端，但它创建了一个独立的 V8 Isolate 作为“后端”，并提供了一些工具函数，允许 JavaScript 测试代码向这个后端发送消息，从而模拟 Inspector 前端的行为。
   - 通过 `UtilsExtension` 中的函数，测试代码可以控制后端的一些行为，例如设置时间、内存信息等。

**与 JavaScript 功能的关系以及 JavaScript 示例：**

这个 C++ 文件中的代码直接影响着 JavaScript 代码的执行和行为，因为它向 JavaScript 环境中注入了特殊的全局对象和函数。  测试代码会利用这些对象和函数来驱动测试流程并验证 Inspector 的行为。

**JavaScript 示例：**

假设我们有一个需要测试 Inspector 断点功能的 JavaScript 文件 `breakpoint_test.js`：

```javascript
utils.print("Starting breakpoint test");

function myFunction() {
  debugger; // 期望 Inspector 在这里暂停
  utils.print("Inside myFunction");
}

myFunction();

utils.print("Breakpoint test finished");
```

为了测试 Inspector 是否能在 `debugger` 语句处暂停，我们可能会编写一个使用 `inspector-test.cc` 中提供的功能的测试脚本：

```javascript
// 这是一个模拟 Inspector 前端行为的 JavaScript 测试脚本

// 模拟连接 Inspector 会话
let sessionId = utils.connectSession(0, "", function(message) {
  utils.print("Received message from backend: " + message);
  // 在这里解析消息，验证是否收到了断点暂停事件
  if (JSON.parse(message).method === "Debugger.paused") {
    utils.print("Successfully paused at breakpoint!");
    // 发送恢复执行的消息
    utils.sendMessageToBackend(sessionId, JSON.stringify({
      id: 1,
      method: "Debugger.resume",
      params: {}
    }));
  }
});

// 加载并执行包含断点的 JavaScript 代码
utils.load("breakpoint_test.js");

// 模拟断开 Inspector 会话
// 理论上，在测试完成后应该断开连接
// utils.disconnectSession(sessionId);
```

在这个 JavaScript 例子中：

- `utils.connectSession()` 被用来模拟 Inspector 前端连接到后端的行为，并注册一个回调函数来接收后端发送的消息（例如，断点暂停事件）。
- `utils.load("breakpoint_test.js")`  加载并执行了包含 `debugger` 语句的 JavaScript 代码。
- 测试脚本期望从后端收到 `Debugger.paused` 消息，这表明 Inspector 在 `debugger` 处暂停了。
- 收到暂停消息后，测试脚本会使用 `utils.sendMessageToBackend()` 向后端发送 `Debugger.resume` 消息，以恢复代码执行。

**总结:**

`inspector-test.cc` 就像一个为 V8 Inspector 功能测试搭建的舞台，它提供了一系列特殊的 JavaScript API，允许测试代码控制测试流程、模拟 Inspector 的行为、并验证 Inspector 的各种功能是否正常工作。它对于确保 V8 Inspector 的稳定性和正确性至关重要。

Prompt: 
```
这是目录为v8/test/inspector/inspector-test.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <locale.h>

#include <optional>
#include <string>
#include <vector>

#include "include/libplatform/libplatform.h"
#include "include/v8-exception.h"
#include "include/v8-initialization.h"
#include "include/v8-local-handle.h"
#include "include/v8-snapshot.h"
#include "src/base/platform/platform.h"
#include "src/base/small-vector.h"
#include "src/flags/flags.h"
#include "src/utils/utils.h"
#include "test/inspector/frontend-channel.h"
#include "test/inspector/isolate-data.h"
#include "test/inspector/task-runner.h"
#include "test/inspector/tasks.h"
#include "test/inspector/utils.h"

#if !defined(V8_OS_WIN)
#include <unistd.h>
#endif  // !defined(V8_OS_WIN)

namespace v8 {
namespace internal {

extern void DisableEmbeddedBlobRefcounting();
extern void FreeCurrentEmbeddedBlob();

extern v8::StartupData CreateSnapshotDataBlobInternalForInspectorTest(
    v8::SnapshotCreator::FunctionCodeHandling function_code_handling,
    const char* embedded_source);

namespace {

base::SmallVector<TaskRunner*, 2> task_runners;

class UtilsExtension : public InspectorIsolateData::SetupGlobalTask {
 public:
  ~UtilsExtension() override = default;
  void Run(v8::Isolate* isolate,
           v8::Local<v8::ObjectTemplate> global) override {
    v8::Local<v8::ObjectTemplate> utils = v8::ObjectTemplate::New(isolate);
    utils->Set(isolate, "print",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Print));
    utils->Set(isolate, "quit",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Quit));
    utils->Set(isolate, "setlocale",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Setlocale));
    utils->Set(isolate, "read",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Read));
    utils->Set(isolate, "load",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Load));
    utils->Set(isolate, "compileAndRunWithOrigin",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::CompileAndRunWithOrigin));
    utils->Set(isolate, "setCurrentTimeMSForTest",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SetCurrentTimeMSForTest));
    utils->Set(isolate, "setMemoryInfoForTest",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SetMemoryInfoForTest));
    utils->Set(isolate, "schedulePauseOnNextStatement",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SchedulePauseOnNextStatement));
    utils->Set(isolate, "cancelPauseOnNextStatement",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::CancelPauseOnNextStatement));
    utils->Set(isolate, "stop",
               v8::FunctionTemplate::New(isolate, &UtilsExtension::Stop));
    utils->Set(isolate, "setLogConsoleApiMessageCalls",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SetLogConsoleApiMessageCalls));
    utils->Set(isolate, "setAdditionalConsoleApi",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SetAdditionalConsoleApi));
    utils->Set(
        isolate, "setLogMaxAsyncCallStackDepthChanged",
        v8::FunctionTemplate::New(
            isolate, &UtilsExtension::SetLogMaxAsyncCallStackDepthChanged));
    utils->Set(isolate, "createContextGroup",
               v8::FunctionTemplate::New(isolate,
                                         &UtilsExtension::CreateContextGroup));
    utils->Set(
        isolate, "createContext",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::CreateContext));
    utils->Set(
        isolate, "resetContextGroup",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::ResetContextGroup));
    utils->Set(
        isolate, "connectSession",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::ConnectSession));
    utils->Set(
        isolate, "disconnectSession",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::DisconnectSession));
    utils->Set(isolate, "sendMessageToBackend",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::SendMessageToBackend));
    utils->Set(isolate, "interruptForMessages",
               v8::FunctionTemplate::New(
                   isolate, &UtilsExtension::InterruptForMessages));
    utils->Set(
        isolate, "waitForDebugger",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::WaitForDebugger));
    global->Set(isolate, "utils", utils);
  }

  static void set_backend_task_runner(TaskRunner* runner) {
    backend_runner_ = runner;
  }

 private:
  static TaskRunner* backend_runner_;

  static void Print(const v8::FunctionCallbackInfo<v8::Value>& info) {
    for (int i = 0; i < info.Length(); i++) {
      v8::HandleScope handle_scope(info.GetIsolate());
      if (i != 0) {
        printf(" ");
      }

      // Explicitly catch potential exceptions in toString().
      v8::TryCatch try_catch(info.GetIsolate());
      v8::Local<v8::Value> arg = info[i];
      v8::Local<v8::String> str_obj;

      if (arg->IsSymbol()) {
        arg = v8::Local<v8::Symbol>::Cast(arg)->Description(info.GetIsolate());
      }
      if (!arg->ToString(info.GetIsolate()->GetCurrentContext())
               .ToLocal(&str_obj)) {
        try_catch.ReThrow();
        return;
      }

      v8::String::Utf8Value str(info.GetIsolate(), str_obj);
      size_t n = fwrite(*str, sizeof(**str), str.length(), stdout);
      if (n != str.length()) {
        FATAL("Error in fwrite\n");
      }
    }
    printf("\n");
    fflush(stdout);
  }

  static void Quit(const v8::FunctionCallbackInfo<v8::Value>& info) {
    fflush(stdout);
    fflush(stderr);
    // Only terminate, so not join the threads here, since joining concurrently
    // from multiple threads can be undefined behaviour (see pthread_join).
    for (TaskRunner* task_runner : task_runners) task_runner->Terminate();
  }

  static void Setlocale(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: setlocale get one string argument.");
    }

    v8::String::Utf8Value str(info.GetIsolate(), info[1]);
    setlocale(LC_NUMERIC, *str);
  }

  static bool ReadFile(v8::Isolate* isolate, v8::Local<v8::Value> name,
                       std::string* chars) {
    v8::String::Utf8Value str(isolate, name);
    bool exists = false;
    std::string filename(*str, str.length());
    *chars = v8::internal::ReadFile(filename.c_str(), &exists);
    if (!exists) {
      isolate->ThrowError("Error reading file");
      return false;
    }
    return true;
  }

  static void Read(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: read gets one string argument.");
    }
    std::string chars;
    v8::Isolate* isolate = info.GetIsolate();
    if (ReadFile(isolate, info[0], &chars)) {
      info.GetReturnValue().Set(ToV8String(isolate, chars));
    }
  }

  static void Load(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: load gets one string argument.");
    }
    std::string chars;
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    int context_group_id = data->GetContextGroupId(context);
    if (ReadFile(isolate, info[0], &chars)) {
      ExecuteStringTask(chars, context_group_id).Run(data);
    }
  }

  static void CompileAndRunWithOrigin(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 6 || !info[0]->IsInt32() || !info[1]->IsString() ||
        !info[2]->IsString() || !info[3]->IsInt32() || !info[4]->IsInt32() ||
        !info[5]->IsBoolean()) {
      FATAL(
          "Internal error: compileAndRunWithOrigin(context_group_id, source, "
          "name, line, column, is_module).");
    }

    backend_runner_->Append(std::make_unique<ExecuteStringTask>(
        info.GetIsolate(), info[0].As<v8::Int32>()->Value(),
        ToVector(info.GetIsolate(), info[1].As<v8::String>()),
        info[2].As<v8::String>(), info[3].As<v8::Int32>(),
        info[4].As<v8::Int32>(), info[5].As<v8::Boolean>()));
  }

  static void SetCurrentTimeMSForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsNumber()) {
      FATAL("Internal error: setCurrentTimeMSForTest(time).");
    }
    backend_runner_->data()->SetCurrentTimeMS(
        info[0].As<v8::Number>()->Value());
  }

  static void SetMemoryInfoForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1) {
      FATAL("Internal error: setMemoryInfoForTest(value).");
    }
    backend_runner_->data()->SetMemoryInfo(info[0]);
  }

  static void SchedulePauseOnNextStatement(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 3 || !info[0]->IsInt32() || !info[1]->IsString() ||
        !info[2]->IsString()) {
      FATAL(
          "Internal error: schedulePauseOnNextStatement(context_group_id, "
          "'reason', 'details').");
    }
    std::vector<uint16_t> reason =
        ToVector(info.GetIsolate(), info[1].As<v8::String>());
    std::vector<uint16_t> details =
        ToVector(info.GetIsolate(), info[2].As<v8::String>());
    int context_group_id = info[0].As<v8::Int32>()->Value();
    RunSyncTask(backend_runner_,
                [&context_group_id, &reason,
                 &details](InspectorIsolateData* data) {
                  data->SchedulePauseOnNextStatement(
                      context_group_id,
                      v8_inspector::StringView(reason.data(), reason.size()),
                      v8_inspector::StringView(details.data(), details.size()));
                });
  }

  static void CancelPauseOnNextStatement(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      FATAL("Internal error: cancelPauseOnNextStatement(context_group_id).");
    }
    int context_group_id = info[0].As<v8::Int32>()->Value();
    RunSyncTask(backend_runner_,
                [&context_group_id](InspectorIsolateData* data) {
                  data->CancelPauseOnNextStatement(context_group_id);
                });
  }

  static void Stop(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      FATAL("Internal error: stop(session_id).");
    }
    int session_id = info[0].As<v8::Int32>()->Value();
    RunSyncTask(backend_runner_, [&session_id](InspectorIsolateData* data) {
      data->Stop(session_id);
    });
  }

  static void SetLogConsoleApiMessageCalls(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsBoolean()) {
      FATAL("Internal error: setLogConsoleApiMessageCalls(bool).");
    }
    backend_runner_->data()->SetLogConsoleApiMessageCalls(
        info[0].As<v8::Boolean>()->Value());
  }

  static void SetLogMaxAsyncCallStackDepthChanged(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsBoolean()) {
      FATAL("Internal error: setLogMaxAsyncCallStackDepthChanged(bool).");
    }
    backend_runner_->data()->SetLogMaxAsyncCallStackDepthChanged(
        info[0].As<v8::Boolean>()->Value());
  }

  static void SetAdditionalConsoleApi(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: SetAdditionalConsoleApi(string).");
    }
    std::vector<uint16_t> script =
        ToVector(info.GetIsolate(), info[0].As<v8::String>());
    RunSyncTask(backend_runner_, [&script](InspectorIsolateData* data) {
      data->SetAdditionalConsoleApi(
          v8_inspector::StringView(script.data(), script.size()));
    });
  }

  static void CreateContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 0) {
      FATAL("Internal error: createContextGroup().");
    }
    int context_group_id = 0;
    RunSyncTask(backend_runner_,
                [&context_group_id](InspectorIsolateData* data) {
                  context_group_id = data->CreateContextGroup();
                });
    info.GetReturnValue().Set(
        v8::Int32::New(info.GetIsolate(), context_group_id));
  }

  static void CreateContext(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2) {
      FATAL("Internal error: createContext(context, name).");
    }
    int context_group_id = info[0].As<v8::Int32>()->Value();
    std::vector<uint16_t> name =
        ToVector(info.GetIsolate(), info[1].As<v8::String>());

    RunSyncTask(backend_runner_, [&context_group_id,
                                  name](InspectorIsolateData* data) {
      CHECK(data->CreateContext(
          context_group_id,
          v8_inspector::StringView(name.data(), name.size())));
    });
  }

  static void ResetContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      FATAL("Internal error: resetContextGroup(context_group_id).");
    }
    int context_group_id = info[0].As<v8::Int32>()->Value();
    RunSyncTask(backend_runner_,
                [&context_group_id](InspectorIsolateData* data) {
                  data->ResetContextGroup(context_group_id);
                });
  }

  static bool IsValidConnectSessionArgs(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 3 || info.Length() > 4) return false;
    if (!info[0]->IsInt32() || !info[1]->IsString() || !info[2]->IsFunction()) {
      return false;
    }
    return info.Length() == 3 || info[3]->IsBoolean();
  }

  static void ConnectSession(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (!IsValidConnectSessionArgs(info)) {
      FATAL(
          "Internal error: connectionSession(context_group_id, state, "
          "dispatch, is_fully_trusted).");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    std::unique_ptr<FrontendChannelImpl> channel =
        std::make_unique<FrontendChannelImpl>(
            InspectorIsolateData::FromContext(context)->task_runner(),
            InspectorIsolateData::FromContext(context)->GetContextGroupId(
                context),
            info.GetIsolate(), info[2].As<v8::Function>());

    std::vector<uint8_t> state =
        ToBytes(info.GetIsolate(), info[1].As<v8::String>());
    int context_group_id = info[0].As<v8::Int32>()->Value();
    bool is_fully_trusted =
        info.Length() == 3 || info[3].As<v8::Boolean>()->Value();
    std::optional<int> session_id;
    RunSyncTask(backend_runner_,
                [context_group_id, &session_id, &channel, &state,
                 is_fully_trusted](InspectorIsolateData* data) {
                  session_id = data->ConnectSession(
                      context_group_id,
                      v8_inspector::StringView(state.data(), state.size()),
                      std::move(channel), is_fully_trusted);
                });

    CHECK(session_id.has_value());
    info.GetReturnValue().Set(v8::Int32::New(info.GetIsolate(), *session_id));
  }

  static void DisconnectSession(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      FATAL("Internal error: disconnectionSession(session_id).");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    TaskRunner* context_task_runner =
        InspectorIsolateData::FromContext(context)->task_runner();
    int session_id = info[0].As<v8::Int32>()->Value();
    std::vector<uint8_t> state;
    RunSyncTask(backend_runner_, [&session_id, &context_task_runner,
                                  &state](InspectorIsolateData* data) {
      state = data->DisconnectSession(session_id, context_task_runner);
    });

    info.GetReturnValue().Set(ToV8String(info.GetIsolate(), state));
  }

  static void SendMessageToBackend(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2 || !info[0]->IsInt32() || !info[1]->IsString()) {
      FATAL("Internal error: sendMessageToBackend(session_id, message).");
    }
    backend_runner_->Append(std::make_unique<SendMessageToBackendTask>(
        info[0].As<v8::Int32>()->Value(),
        ToVector(info.GetIsolate(), info[1].As<v8::String>())));
  }

  static void InterruptForMessages(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    backend_runner_->InterruptForMessages();
  }

  static void WaitForDebugger(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2 || !info[0]->IsInt32() || !info[1]->IsFunction()) {
      FATAL("Internal error: waitForDebugger(context_group_id, callback).");
    }
    int context_group_id = info[0].As<v8::Int32>()->Value();
    RunSimpleAsyncTask(
        backend_runner_,
        [context_group_id](InspectorIsolateData* data) {
          data->WaitForDebugger(context_group_id);
        },
        info[1].As<v8::Function>());
  }
};

TaskRunner* UtilsExtension::backend_runner_ = nullptr;

bool StrictAccessCheck(v8::Local<v8::Context> accessing_context,
                       v8::Local<v8::Object> accessed_object,
                       v8::Local<v8::Value> data) {
  CHECK(accessing_context.IsEmpty());
  return accessing_context.IsEmpty();
}

class ConsoleExtension : public InspectorIsolateData::SetupGlobalTask {
 public:
  ~ConsoleExtension() override = default;
  void Run(v8::Isolate* isolate,
           v8::Local<v8::ObjectTemplate> global) override {
    v8::Local<v8::String> name =
        v8::String::NewFromUtf8Literal(isolate, "console");
    global->SetNativeDataProperty(name, &ConsoleGetterCallback, nullptr, {},
                                  v8::DontEnum);
  }

 private:
  static void ConsoleGetterCallback(
      v8::Local<v8::Name>, const v8::PropertyCallbackInfo<v8::Value>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    v8::HandleScope scope(isolate);
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    v8::Local<v8::String> name =
        v8::String::NewFromUtf8Literal(isolate, "console");
    v8::Local<v8::Object> console = context->GetExtrasBindingObject()
                                        ->Get(context, name)
                                        .ToLocalChecked()
                                        .As<v8::Object>();
    info.GetReturnValue().Set(console);
  }
};

class InspectorExtension : public InspectorIsolateData::SetupGlobalTask {
 public:
  ~InspectorExtension() override = default;
  void Run(v8::Isolate* isolate,
           v8::Local<v8::ObjectTemplate> global) override {
    v8::Local<v8::ObjectTemplate> inspector = v8::ObjectTemplate::New(isolate);
    inspector->Set(isolate, "fireContextCreated",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::FireContextCreated));
    inspector->Set(isolate, "fireContextDestroyed",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::FireContextDestroyed));
    inspector->Set(
        isolate, "freeContext",
        v8::FunctionTemplate::New(isolate, &InspectorExtension::FreeContext));
    inspector->Set(isolate, "addInspectedObject",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::AddInspectedObject));
    inspector->Set(isolate, "setMaxAsyncTaskStacks",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::SetMaxAsyncTaskStacks));
    inspector->Set(
        isolate, "dumpAsyncTaskStacksStateForTest",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::DumpAsyncTaskStacksStateForTest));
    inspector->Set(
        isolate, "breakProgram",
        v8::FunctionTemplate::New(isolate, &InspectorExtension::BreakProgram));
    inspector->Set(
        isolate, "createObjectWithStrictCheck",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::CreateObjectWithStrictCheck));
    inspector->Set(isolate, "callWithScheduledBreak",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::CallWithScheduledBreak));
    inspector->Set(
        isolate, "markObjectAsNotInspectable",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::MarkObjectAsNotInspectable));
    inspector->Set(
        isolate, "createObjectWithNativeDataProperty",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::CreateObjectWithNativeDataProperty));
    inspector->Set(isolate, "storeCurrentStackTrace",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::StoreCurrentStackTrace));
    inspector->Set(isolate, "externalAsyncTaskStarted",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::ExternalAsyncTaskStarted));
    inspector->Set(
        isolate, "externalAsyncTaskFinished",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::ExternalAsyncTaskFinished));
    inspector->Set(isolate, "scheduleWithAsyncStack",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::ScheduleWithAsyncStack));
    inspector->Set(
        isolate, "setAllowCodeGenerationFromStrings",
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::SetAllowCodeGenerationFromStrings));
    inspector->Set(isolate, "setResourceNamePrefix",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::SetResourceNamePrefix));
    inspector->Set(isolate, "newExceptionWithMetaData",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::newExceptionWithMetaData));
    inspector->Set(isolate, "callbackForTests",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::CallbackForTests));
    inspector->Set(isolate, "runNestedMessageLoop",
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::RunNestedMessageLoop));
    global->Set(isolate, "inspector", inspector);
  }

 private:
  static void FireContextCreated(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FireContextCreated(context, data->GetContextGroupId(context),
                             v8_inspector::StringView());
  }

  static void FireContextDestroyed(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FireContextDestroyed(context);
  }

  static void FreeContext(const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FreeContext(context);
  }

  static void AddInspectedObject(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2 || !info[0]->IsInt32()) {
      FATAL("Internal error: addInspectedObject(session_id, object).");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->AddInspectedObject(info[0].As<v8::Int32>()->Value(), info[1]);
  }

  static void SetMaxAsyncTaskStacks(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      FATAL("Internal error: setMaxAsyncTaskStacks(max).");
    }
    InspectorIsolateData::FromContext(info.GetIsolate()->GetCurrentContext())
        ->SetMaxAsyncTaskStacksForTest(info[0].As<v8::Int32>()->Value());
  }

  static void DumpAsyncTaskStacksStateForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 0) {
      FATAL("Internal error: dumpAsyncTaskStacksStateForTest().");
    }
    InspectorIsolateData::FromContext(info.GetIsolate()->GetCurrentContext())
        ->DumpAsyncTaskStacksStateForTest();
  }

  static void BreakProgram(const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2 || !info[0]->IsString() || !info[1]->IsString()) {
      FATAL("Internal error: breakProgram('reason', 'details').");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    std::vector<uint16_t> reason =
        ToVector(info.GetIsolate(), info[0].As<v8::String>());
    v8_inspector::StringView reason_view(reason.data(), reason.size());
    std::vector<uint16_t> details =
        ToVector(info.GetIsolate(), info[1].As<v8::String>());
    v8_inspector::StringView details_view(details.data(), details.size());
    data->BreakProgram(data->GetContextGroupId(context), reason_view,
                       details_view);
  }

  static void CreateObjectWithStrictCheck(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 0) {
      FATAL("Internal error: createObjectWithStrictCheck().");
    }
    v8::Local<v8::ObjectTemplate> templ =
        v8::ObjectTemplate::New(info.GetIsolate());
    templ->SetAccessCheckCallback(&StrictAccessCheck);
    info.GetReturnValue().Set(
        templ->NewInstance(info.GetIsolate()->GetCurrentContext())
            .ToLocalChecked());
  }

  static void CallWithScheduledBreak(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 3 || !info[0]->IsFunction() || !info[1]->IsString() ||
        !info[2]->IsString()) {
      FATAL("Internal error: callWithScheduledBreak('reason', 'details').");
    }
    std::vector<uint16_t> reason =
        ToVector(info.GetIsolate(), info[1].As<v8::String>());
    v8_inspector::StringView reason_view(reason.data(), reason.size());
    std::vector<uint16_t> details =
        ToVector(info.GetIsolate(), info[2].As<v8::String>());
    v8_inspector::StringView details_view(details.data(), details.size());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    int context_group_id = data->GetContextGroupId(context);
    data->SchedulePauseOnNextStatement(context_group_id, reason_view,
                                       details_view);
    v8::MaybeLocal<v8::Value> result;
    result = info[0].As<v8::Function>()->Call(context, context->Global(), 0,
                                              nullptr);
    data->CancelPauseOnNextStatement(context_group_id);
  }

  static void MarkObjectAsNotInspectable(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsObject()) {
      FATAL("Internal error: markObjectAsNotInspectable(object).");
    }
    v8::Local<v8::Object> object = info[0].As<v8::Object>();
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Private> notInspectablePrivate =
        v8::Private::ForApi(isolate, ToV8String(isolate, "notInspectable"));
    object
        ->SetPrivate(isolate->GetCurrentContext(), notInspectablePrivate,
                     v8::True(isolate))
        .ToChecked();
  }

  static void CreateObjectWithNativeDataProperty(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 2 || !info[0]->IsString() || !info[1]->IsBoolean()) {
      FATAL(
          "Internal error: createObjectWithNativeDataProperty('accessor name', "
          "hasSetter)\n");
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
    if (info[1].As<v8::Boolean>()->Value()) {
      templ->SetNativeDataProperty(v8::Local<v8::String>::Cast(info[0]),
                                   AccessorGetter, AccessorSetter);
    } else {
      templ->SetNativeDataProperty(v8::Local<v8::String>::Cast(info[0]),
                                   AccessorGetter);
    }
    info.GetReturnValue().Set(
        templ->NewInstance(isolate->GetCurrentContext()).ToLocalChecked());
  }

  static void AccessorGetter(v8::Local<v8::Name> property,
                             const v8::PropertyCallbackInfo<v8::Value>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    isolate->ThrowError("Getter is called");
  }

  static void AccessorSetter(v8::Local<v8::Name> property,
                             v8::Local<v8::Value> value,
                             const v8::PropertyCallbackInfo<void>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    isolate->ThrowError("Setter is called");
  }

  static void StoreCurrentStackTrace(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: storeCurrentStackTrace('description')\n");
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    std::vector<uint16_t> description =
        ToVector(isolate, info[0].As<v8::String>());
    v8_inspector::StringView description_view(description.data(),
                                              description.size());
    v8_inspector::V8StackTraceId id =
        data->StoreCurrentStackTrace(description_view);
    v8::Local<v8::ArrayBuffer> buffer =
        v8::ArrayBuffer::New(isolate, sizeof(id));
    *static_cast<v8_inspector::V8StackTraceId*>(
        buffer->GetBackingStore()->Data()) = id;
    info.GetReturnValue().Set(buffer);
  }

  static void ExternalAsyncTaskStarted(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsArrayBuffer()) {
      FATAL("Internal error: externalAsyncTaskStarted(id)\n");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    v8_inspector::V8StackTraceId* id =
        static_cast<v8_inspector::V8StackTraceId*>(
            info[0].As<v8::ArrayBuffer>()->GetBackingStore()->Data());
    data->ExternalAsyncTaskStarted(*id);
  }

  static void ExternalAsyncTaskFinished(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsArrayBuffer()) {
      FATAL("Internal error: externalAsyncTaskFinished(id)\n");
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    v8_inspector::V8StackTraceId* id =
        static_cast<v8_inspector::V8StackTraceId*>(
            info[0].As<v8::ArrayBuffer>()->GetBackingStore()->Data());
    data->ExternalAsyncTaskFinished(*id);
  }

  static void ScheduleWithAsyncStack(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 3 || !info[0]->IsFunction() || !info[1]->IsString() ||
        !info[2]->IsBoolean()) {
      FATAL(
          "Internal error: scheduleWithAsyncStack(function, 'task-name', "
          "with_empty_stack).");
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    int context_group_id = data->GetContextGroupId(context);
    bool with_empty_stack = info[2].As<v8::Boolean>()->Value();
    if (with_empty_stack) context->Exit();

    std::vector<uint16_t> task_name =
        ToVector(isolate, info[1].As<v8::String>());
    v8_inspector::StringView task_name_view(task_name.data(), task_name.size());

    RunAsyncTask(
        data->task_runner(), task_name_view,
        std::make_unique<SetTimeoutTask>(
            context_group_id, isolate, v8::Local<v8::Function>::Cast(info[0])));
    if (with_empty_stack) context->Enter();
  }

  static void SetAllowCodeGenerationFromStrings(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsBoolean()) {
      FATAL("Internal error: setAllowCodeGenerationFromStrings(allow).");
    }
    info.GetIsolate()->GetCurrentContext()->AllowCodeGenerationFromStrings(
        info[0].As<v8::Boolean>()->Value());
  }
  static void SetResourceNamePrefix(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsString()) {
      FATAL("Internal error: setResourceNamePrefix('prefix').");
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->SetResourceNamePrefix(v8::Local<v8::String>::Cast(info[0]));
  }

  static void newExceptionWithMetaData(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 3 || !info[0]->IsString() || !info[1]->IsString() ||
        !info[2]->IsString()) {
      FATAL(
          "Internal error: newExceptionWithMetaData('message', 'key', "
          "'value').");
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);

    auto error = v8::Exception::Error(info[0].As<v8::String>());
    CHECK(data->AssociateExceptionData(error, info[1].As<v8::String>(),
                                       info[2].As<v8::String>()));
    info.GetReturnValue().Set(error);
  }

  static void CallbackForTests(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() != 1 || !info[0]->IsFunction()) {
      FATAL("Internal error: callbackForTests(function).");
    }

    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(info[0]);
    v8::Local<v8::Value> result;
    if (callback->Call(context, v8::Undefined(isolate), 0, nullptr)
            .ToLocal(&result)) {
      info.GetReturnValue().Set(result);
    }
  }

  static void RunNestedMessageLoop(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);

    data->task_runner()->RunMessageLoop(true);
  }
};

int InspectorTestMain(int argc, char* argv[]) {
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  std::unique_ptr<Platform> platform(platform::NewDefaultPlatform());
  v8::V8::InitializePlatform(platform.get());
  v8_flags.abort_on_contradictory_flags = true;
  v8::V8::SetFlagsFromCommandLine(&argc, argv, true);
  v8::V8::InitializeExternalStartupData(argv[0]);
  v8::V8::Initialize();
  i::DisableEmbeddedBlobRefcounting();

  base::Semaphore ready_semaphore(0);

  StartupData startup_data = {nullptr, 0};
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--embed") == 0) {
      argv[i++] = nullptr;
      printf("Embedding script '%s'\n", argv[i]);
      startup_data = i::CreateSnapshotDataBlobInternalForInspectorTest(
          SnapshotCreator::FunctionCodeHandling::kClear, argv[i]);
      argv[i] = nullptr;
    }
  }

  {
    InspectorIsolateData::SetupGlobalTasks frontend_extensions;
    frontend_extensions.emplace_back(new UtilsExtension());
    frontend_extensions.emplace_back(new ConsoleExtension());
    TaskRunner frontend_runner(std::move(frontend_extensions),
                               kFailOnUncaughtExceptions, &ready_semaphore,
                               startup_data.data ? &startup_data : nullptr,
                               kNoInspector);
    ready_semaphore.Wait();

    int frontend_context_group_id = 0;
    RunSyncTask(&frontend_runner,
                [&frontend_context_group_id](InspectorIsolateData* data) {
                  frontend_context_group_id = data->CreateContextGroup();
                });

    InspectorIsolateData::SetupGlobalTasks backend_extensions;
    backend_extensions.emplace_back(new SetTimeoutExtension());
    backend_extensions.emplace_back(new ConsoleExtension());
    backend_extensions.emplace_back(new InspectorExtension());
    TaskRunner backend_runner(
        std::move(backend_extensions), kStandardPropagateUncaughtExceptions,
        &ready_semaphore, startup_data.data ? &startup_data : nullptr,
        kWithInspector);
    ready_semaphore.Wait();
    UtilsExtension::set_backend_task_runner(&backend_runner);

    task_runners = {&frontend_runner, &backend_runner};

    for (int i = 1; i < argc; ++i) {
      // Ignore unknown flags.
      if (argv[i] == nullptr || argv[i][0] == '-') continue;

      bool exists = false;
      std::string chars = ReadFile(argv[i], &exists, true);
      if (!exists) {
        FATAL("Internal error: script file doesn't exists: %s\n", argv[i]);
      }
      frontend_runner.Append(std::make_unique<ExecuteStringTask>(
          chars, frontend_context_group_id));
    }

    frontend_runner.Join();
    backend_runner.Join();

    delete[] startup_data.data;

    // TaskRunners go out of scope here, which causes Isolate teardown and all
    // running background tasks to be properly joined.
  }

  i::FreeCurrentEmbeddedBlob();
  return 0;
}
}  //  namespace

}  // namespace internal
}  // namespace v8

int main(int argc, char* argv[]) {
  return v8::internal::InspectorTestMain(argc, argv);
}

"""

```