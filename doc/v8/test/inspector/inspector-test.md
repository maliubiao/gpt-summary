Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/inspector/inspector-test.cc`.

Here's a breakdown of how to address the request:

1. **Identify the file type:** The file ends in `.cc`, indicating it's a C++ source file, not a Torque file (`.tq`).

2. **Determine the main purpose:** The file is located within the `v8/test/inspector` directory, suggesting it's related to testing the V8 inspector functionality.

3. **Analyze the included headers:** The includes reveal dependencies on V8's core functionalities (`v8.h`), platform utilities (`libplatform`), and specific testing infrastructure within the `test/inspector` directory.

4. **Examine the defined classes:** The code defines several classes (`UtilsExtension`, `ConsoleExtension`, `InspectorExtension`). Each of these likely adds specific testing capabilities.

5. **Focus on `UtilsExtension`:** This class seems to provide a set of utility functions accessible from JavaScript within the test environment. The `Run` method registers these functions with the global object. List these functions and their apparent purpose based on their names (e.g., `print`, `quit`, `load`, `connectSession`).

6. **Focus on `ConsoleExtension`:** This class seems to provide access to the `console` object within the test environment.

7. **Focus on `InspectorExtension`:** This class appears to expose functions that directly interact with the V8 inspector internals for testing purposes (e.g., `fireContextCreated`, `breakProgram`, `addInspectedObject`).

8. **Relate to JavaScript:** Since the exposed functions are designed to be called from a JavaScript testing environment, provide JavaScript examples demonstrating how to use some of the key functions from `UtilsExtension` and `InspectorExtension`.

9. **Code Logic Reasoning:**  For functions with more complex logic, such as `ConnectSession` or `SchedulePauseOnNextStatement`, illustrate the flow with hypothetical inputs and outputs.

10. **Common Programming Errors:**  Think about how the exposed functions might be misused or lead to common errors in a testing context. For example, incorrect argument types or counts when calling the utility functions.

11. **Summarize the functionality:**  Consolidate the findings into a concise summary highlighting the purpose of the file as a test harness for the V8 inspector, providing utilities and direct access to inspector functionalities.

12. **Address specific instructions:** Make sure to explicitly state that it's not a Torque file, provide JavaScript examples, illustrate code logic, and give examples of common errors.
```cpp
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
    // ... implementation of Print ...
  }

  static void Quit(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of Quit ...
  }

  static void Setlocale(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of Setlocale ...
  }

  static bool ReadFile(v8::Isolate* isolate, v8::Local<v8::Value> name,
                       std::string* chars) {
    // ... implementation of ReadFile ...
  }

  static void Read(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of Read ...
  }

  static void Load(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of Load ...
  }

  static void CompileAndRunWithOrigin(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CompileAndRunWithOrigin ...
  }

  static void SetCurrentTimeMSForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetCurrentTimeMSForTest ...
  }

  static void SetMemoryInfoForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetMemoryInfoForTest ...
  }

  static void SchedulePauseOnNextStatement(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SchedulePauseOnNextStatement ...
  }

  static void CancelPauseOnNextStatement(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CancelPauseOnNextStatement ...
  }

  static void Stop(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of Stop ...
  }

  static void SetLogConsoleApiMessageCalls(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetLogConsoleApiMessageCalls ...
  }

  static void SetLogMaxAsyncCallStackDepthChanged(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetLogMaxAsyncCallStackDepthChanged ...
  }

  static void SetAdditionalConsoleApi(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetAdditionalConsoleApi ...
  }

  static void CreateContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CreateContextGroup ...
  }

  static void CreateContext(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CreateContext ...
  }

  static void ResetContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of ResetContextGroup ...
  }

  static bool IsValidConnectSessionArgs(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of IsValidConnectSessionArgs ...
  }

  static void ConnectSession(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of ConnectSession ...
  }

  static void DisconnectSession(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of DisconnectSession ...
  }

  static void SendMessageToBackend(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SendMessageToBackend ...
  }

  static void InterruptForMessages(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of InterruptForMessages ...
  }

  static void WaitForDebugger(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of WaitForDebugger ...
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
    // ... implementation of ConsoleGetterCallback ...
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
    // ... implementation of FireContextCreated ...
  }

  static void FireContextDestroyed(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of FireContextDestroyed ...
  }

  static void FreeContext(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of FreeContext ...
  }

  static void AddInspectedObject(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of AddInspectedObject ...
  }

  static void SetMaxAsyncTaskStacks(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetMaxAsyncTaskStacks ...
  }

  static void DumpAsyncTaskStacksStateForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of DumpAsyncTaskStacksStateForTest ...
  }

  static void BreakProgram(const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of BreakProgram ...
  }

  static void CreateObjectWithStrictCheck(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CreateObjectWithStrictCheck ...
  }

  static void CallWithScheduledBreak(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CallWithScheduledBreak ...
  }

  static void MarkObjectAsNotInspectable(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of MarkObjectAsNotInspectable ...
  }

  static void CreateObjectWithNativeDataProperty(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CreateObjectWithNativeDataProperty ...
  }

  static void AccessorGetter(v8::Local<v8::Name> property,
                             const v8::PropertyCallbackInfo<v8::Value>& info) {
    // ... implementation of AccessorGetter ...
  }

  static void AccessorSetter(v8::Local<v8::Name> property,
                             v8::Local<v8::Value> value,
                             const v8::PropertyCallbackInfo<void>& info) {
    // ... implementation of AccessorSetter ...
  }

  static void StoreCurrentStackTrace(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of StoreCurrentStackTrace ...
  }

  static void ExternalAsyncTaskStarted(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of ExternalAsyncTaskStarted ...
  }

  static void ExternalAsyncTaskFinished(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of ExternalAsyncTaskFinished ...
  }

  static void ScheduleWithAsyncStack(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of ScheduleWithAsyncStack ...
  }

  static void SetAllowCodeGenerationFromStrings(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetAllowCodeGenerationFromStrings ...
  }

  static void SetResourceNamePrefix(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of SetResourceNamePrefix ...
  }

  static void newExceptionWithMetaData(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of newExceptionWithMetaData ...
  }

  static void CallbackForTests(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of CallbackForTests ...
  }

  static void RunNestedMessageLoop(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    // ... implementation of RunNestedMessageLoop ...
  }
};

}  // namespace

void InitializeInspectorTest(v8::Isolate* isolate, TaskRunner* backend_runner) {
  UtilsExtension::set_backend_task_runner(backend_runner);
  InspectorIsolateData::Initialize(isolate);
  new InspectorIsolateData(isolate, backend_runner, nullptr);
  task_runners.push_back(backend_runner);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  InspectorIsolateData::RunSetupGlobalTasks(isolate, global_template);
  v8::Local<v8::Context> context =
      v8::Context::New(isolate, nullptr, global_template);
  context->Enter();
}

void InitializeInspectorTestWithGlobal(v8::Isolate* isolate,
                                       TaskRunner* backend_runner,
                                       v8::Local<v8::ObjectTemplate> global) {
  UtilsExtension::set_backend_task_runner(backend_runner);
  InspectorIsolateData::Initialize(isolate);
  new InspectorIsolateData(isolate, backend_runner, nullptr);
  task_runners.push_back(backend_runner);
  InspectorIsolateData::RunSetupGlobalTasks(isolate, global);
  v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
  context->Enter();
}

void InitializeInspectorTestWithSnapshot(v8::Isolate* isolate,
                                         TaskRunner* backend_runner,
                                         const char* embedded_source) {
  UtilsExtension::set_backend_task_runner(backend_runner);
  DisableEmbeddedBlobRefcounting();
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::InitializeICUDefault();
  v8::V8::Initialize();
  v8::StartupData blob = CreateSnapshotDataBlobInternalForInspectorTest(
      v8::SnapshotCreator::FunctionCodeHandling::kClear, embedded_source);
  isolate->SetSnapshotBlob(&blob);
  new InspectorIsolateData(isolate, backend_runner, nullptr);
  task_runners.push_back(backend_runner);
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  InspectorIsolateData::RunSetupGlobalTasks(isolate, global_template);
  v8::Local<v8::Context> context =
      v8::Context::New(isolate, nullptr, global_template);
  context->Enter();
  FreeCurrentEmbeddedBlob();
}

void TearDownInspectorTest(v8::Isolate* isolate) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  context->Exit();
  InspectorIsolateData::TearDown(isolate);
  v8::V8::Dispose();
  v8::V8::ShutdownPlatform();
}

}  // namespace internal
}  // namespace v8
```

## 功能列举

`v8/test/inspector/inspector-test.cc` 是一个 V8 源代码文件，**它是一个 C++ 文件**，用于**测试 V8 的 Inspector (调试器) 功能**。 它主要做了以下几件事：

1. **提供测试环境的辅助工具 (UtilsExtension):**
   - 注册了一些全局 JavaScript 函数，这些函数可以用来控制测试流程、模拟环境行为以及与 Inspector 后端进行交互。
   - 这些函数包括 `print` (打印输出), `quit` (退出测试), `load` (加载并执行 JavaScript 文件), `connectSession` (连接 Inspector 会话), `sendMessageToBackend` (向 Inspector 后端发送消息) 等。

2. **模拟 `console` 对象 (ConsoleExtension):**
   - 在测试环境中创建一个 `console` 对象，以便测试代码可以使用 `console.log`, `console.error` 等方法。

3. **提供直接操作 Inspector 功能的接口 (InspectorExtension):**
   - 注册了一些全局 JavaScript 函数，可以直接触发 Inspector 的某些行为，例如创建和销毁上下文 (`fireContextCreated`, `fireContextDestroyed`), 手动触发断点 (`breakProgram`), 添加被检查的对象 (`addInspectedObject`) 等。

4. **初始化和清理测试环境:**
   - `InitializeInspectorTest` 和 `TearDownInspectorTest` 函数负责创建和销毁 V8 隔离区 (Isolate)，并设置测试所需的全局对象和上下文。
   - 它还处理了使用快照 (snapshot) 进行初始化的场景 (`InitializeInspectorTestWithSnapshot`).

5. **管理 Inspector 后端任务:**
   - 通过 `TaskRunner` 来管理发送给 Inspector 后端的任务，例如执行 JavaScript 代码或发送调试命令。

**关于文件类型：**

你提到 "如果 `v8/test/inspector/inspector-test.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码"。  这是不正确的。该文件以 `.cc` 结尾，**明确表明它是一个 C++ 源代码文件**。 Torque 文件的扩展名是 `.tq`。

## 与 JavaScript 的关系及举例

`v8/test/inspector/inspector-test.cc` 的主要目的是**测试与 JavaScript 代码交互的 Inspector 功能**。  它通过在 C++ 中创建 V8 运行时环境，并注入一些特殊的全局函数，使得测试脚本（通常是 JavaScript 文件）能够控制 Inspector 的行为并验证其正确性。

以下是一些 `UtilsExtension` 和 `InspectorExtension` 中定义的函数以及如何在 JavaScript 中使用它们的例子：

**UtilsExtension 的例子：**

```javascript
// 使用 utils.print 打印消息
utils.print("Hello, Inspector Test!");

// 使用 utils.load 加载并执行一个 JavaScript 文件
utils.load("my_test_script.js");

// 创建一个新的上下文组
let groupId = utils.createContextGroup();

// 在指定的上下文组中创建一个新的上下文
utils.createContext(groupId, "myContext");

// 连接到 Inspector 会话，并提供一个消息分发函数
let sessionId = utils.connectSession(groupId, "", function(message) {
  utils.print("Received message from backend: " + message);
});

// 向 Inspector 后端发送消息
utils.sendMessageToBackend(sessionId, '{"method": "Debugger.pause"}');

// 安排在下一条语句暂停
utils.schedulePauseOnNextStatement(groupId, "debuggerStatement", "Paused by test");
debugger; // 这将触发暂停

// 断开 Inspector 会话
let finalState = utils.disconnectSession(sessionId);

// 设置当前时间（用于测试时间相关的 Inspector 功能）
utils.setCurrentTimeMSForTest(Date.now());
```

**InspectorExtension 的例子：**

```javascript
// 触发上下文创建事件
inspector.fireContextCreated();

// 手动触发断点
inspector.breakProgram("testReason", "testDetails");

// 创建一个对象并将其添加到 Inspector 的检查对象列表中
let obj = { a: 1 };
inspector.addInspectedObject(sessionId, obj);

// 创建一个具有严格访问检查的对象
let strictObj = inspector.createObjectWithStrictCheck();

// 安排在调用函数时暂停
inspector.callWithScheduledBreak(function() {
  utils.print("Inside the function with scheduled break.");
}, "pauseReason", "pauseDetails");
```

## 代码逻辑推理

**假设输入与输出 (以 `UtilsExtension::connectSession` 为例):**

**假设输入 (JavaScript 调用):**

```javascript
let groupId = 123;
let initialState = "someState";
function dispatch(message) {
  utils.print("Backend message: " + message);
}
let isTrusted = true;
let sessionId = utils.connectSession(groupId, initialState, dispatch, isTrusted);
```

**C++ 端处理 (`UtilsExtension::ConnectSession`):**

1. `IsValidConnectSessionArgs` 会检查参数的类型和数量是否正确。
2. 创建一个 `FrontendChannelImpl` 实例，用于向前端发送消息。
3. 将 `initialState` 从 JavaScript 字符串转换为 C++ 的字节向量。
4. 调用 Inspector 后端的 `ConnectSession` 方法，传入 `groupId`, `initialState`, `channel` 和 `isTrusted`。
5. 后端会创建一个新的 Inspector 会话，并返回一个 `session_id`。

**假设输出 (JavaScript 端):**

如果连接成功，`utils.connectSession` 将返回一个表示新会话 ID 的整数，例如 `456`。

**代码逻辑推理 (以 `InspectorExtension::breakProgram` 为例):**

**假设输入 (JavaScript 调用):**

```javascript
inspector.breakProgram("user requested", "testing breakpoint");
```

**C++ 端处理 (`InspectorExtension::BreakProgram`):**

1. 从 JavaScript 接收 reason ("user requested") 和 details ("testing breakpoint") 字符串。
2. 将 JavaScript 字符串转换为 C++ 的 UTF-16 向量。
3. 获取当前上下文的上下文组 ID。
4. 调用 `InspectorIsolateData::BreakProgram` 方法，将上下文组 ID、reason 和 details 传递给 Inspector 后端。
5. Inspector 后端会暂停 JavaScript 执行，并通知调试器前端。

**输出:**

在调试器前端（如 Chrome DevTools）中，JavaScript 执行会暂停，并显示 "user requested" 作为暂停原因，"testing breakpoint" 作为详细信息。

## 用户常见的编程错误

使用这些测试辅助函数时，用户可能会犯以下编程错误：

1. **参数类型或数量错误:** 调用这些函数时，传递了错误类型的参数或参数数量不匹配。例如：
   ```javascript
   // 错误：connectSession 期望一个函数作为第三个参数
   utils.connectSession(123, "state", "not a function");

   // 错误：print 接受任意数量的参数，但 setlocale 只接受一个字符串
   utils.setlocale("en_US", "extra argument");
   ```

2. **未定义或错误的上下文组 ID 或会话 ID:** 在操作上下文或会话时，使用了无效的 ID。例如：
   ```javascript
   let invalidGroupId = 999;
   // 错误：该上下文组可能不存在
   utils.createContext(invalidGroupId, "anotherContext");

   let invalidSessionId = 888;
   // 错误：该会话可能已断开或从未创建
   utils.sendMessageToBackend(invalidSessionId, '{"method": "Runtime.evaluate", "params": { "expression": "1+1" }}');
   ```

3. **在错误的上下文中调用函数:** 某些函数可能需要在特定的上下文中调用才能生效。

4. **异步操作的误解:**  与 Inspector 的交互通常是异步的。用户可能没有正确处理异步操作的结果或时序。例如，在 `connectSession` 后立即发送消息，而会话可能尚未完全建立。

5. **对 Inspector 协议的错误理解:**  在使用 `sendMessageToBackend` 时，发送的 JSON 消息格式不符合 Inspector 协议的要求。

## 功能归纳

`v8/test/inspector/inspector-test.cc` 的主要功能是**为 V8 Inspector 功能的自动化测试提供一个底层的 C++ 基础设施**。 它通过以下方式实现：

- **搭建测试环境:** 创建和管理 V8 隔离区和上下文。
- **提供控制接口:** 暴露一系列 JavaScript 可调用的函数，允许测试脚本控制测试流程和模拟各种场景。
- **模拟 Inspector 行为:** 提供触发 Inspector 特定事件和操作的能力。
- **辅助测试断言:**  虽然代码本身不包含断言，但它提供的工具可以帮助测试脚本更容易地验证 Inspector 的行为是否符合预期。

总而言之，这个 C++ 文件是构建 V8 Inspector 测试套件的关键组成部分，它为编写针对 Inspector 功能的自动化测试用例提供了必要的工具和环境。

### 提示词
```
这是目录为v8/test/inspector/inspector-test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/inspector/inspector-test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
      FATAL("Internal error: setAllowCodeGenerationFr
```