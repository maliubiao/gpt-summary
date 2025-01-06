Response: The user wants to understand the functionality of the C++ code provided, specifically how it relates to JavaScript. I need to:

1. **Analyze the C++ code:** Identify the main purpose of the code by examining the classes, methods, and included headers.
2. **Summarize the functionality:** Describe what the code does in a concise and understandable way.
3. **Explain the connection to JavaScript:** Determine how the C++ code interacts with or influences JavaScript execution within the V8 engine.
4. **Provide JavaScript examples:** Illustrate the interaction between the C++ code and JavaScript by showing how the functions defined in C++ can be called or observed from JavaScript.

**Analysis of the C++ code:**

- The code defines two main extension classes: `UtilsExtension` and `InspectorExtension`.
- `UtilsExtension` exposes utility functions to JavaScript, such as:
    - `quit`: Terminates the V8 isolate.
    - `compileAndRunWithOrigin`: Compiles and runs JavaScript code with a specified origin.
    - Debugger control functions: `schedulePauseOnNextStatement`, `cancelPauseOnNextStatement`.
    - Context management functions: `createContextGroup`, `resetContextGroup`.
    - Inspector session management functions: `connectSession`, `disconnectSession`, `sendMessageToBackend`.
- `InspectorExtension` exposes functions related to the V8 Inspector, such as:
    - Context lifecycle management: `fireContextCreated`, `fireContextDestroyed`, `freeContext`.
    - Object inspection: `addInspectedObject`, `markObjectAsNotInspectable`.
    - Debugging features: `setMaxAsyncTaskStacks`, `breakProgram`, `callWithScheduledBreak`.
    - Advanced features: `createObjectWithStrictCheck`, `createObjectWithNativeDataProperty`, `storeCurrentStackTrace`, `externalAsyncTaskStarted`, `externalAsyncTaskFinished`, `scheduleWithAsyncStack`, `setAllowCodeGenerationFromStrings`, `setResourceNamePrefix`.
- The `FuzzInspector` function is the entry point for the fuzzer. It sets up two V8 isolates (frontend and backend) with these extensions, feeds the input data as a JavaScript string to the frontend, and runs it.
- The code uses `TaskRunner` to manage tasks on different isolates, indicating an asynchronous nature.
- The inclusion of `<locale.h>`, `<optional>`, `<string>`, `<vector>`, V8 headers (`v8-isolate.h`, `v8-local-handle.h`, etc.), and internal V8 headers suggests that this code interacts deeply with the V8 engine's internals.

**Connection to JavaScript:**

The C++ code acts as an interface between the fuzzer and the V8 engine's Inspector. It defines native functions that can be called from JavaScript within the fuzzer's environment. These functions allow the fuzzer to:

- Control the execution of JavaScript code.
- Simulate Inspector actions and events.
- Trigger specific scenarios within the V8 engine to uncover potential bugs.

**JavaScript Examples:**

I need to provide JavaScript code snippets that demonstrate the usage of the functions exposed by `UtilsExtension` and `InspectorExtension`.

**Refinement and Final Plan:**

1. State that the file is a C++ source file for a fuzzer that tests the V8 Inspector.
2. Explain that it registers native C++ functions that can be called from JavaScript.
3. Group the functions by their purpose (utilities, inspector actions).
4. Provide clear and concise JavaScript examples for representative functions from each group, showing how to call them.
5. Emphasize that this code is part of V8's internal testing infrastructure and not directly used in typical JavaScript development.
这个C++源代码文件 `v8/test/fuzzer/inspector-fuzzer.cc` 的功能是**为一个模糊测试器（fuzzer）提供与 V8 Inspector 交互的能力**。

具体来说，它通过注册一些 **C++ 扩展**，使得在模糊测试运行的 JavaScript 环境中可以调用特定的原生函数，从而模拟和控制 Inspector 的行为，并发送 Inspector 协议消息。这有助于发现 V8 Inspector 实现中的潜在 bug 和安全漏洞。

**与 JavaScript 的功能关系：**

这个文件直接扩展了 JavaScript 的功能，因为它向 JavaScript 环境中注入了新的全局对象 `utils` 和 `inspector`，并在这些对象上定义了一些方法，这些方法实际上是由 C++ 代码实现的。

**JavaScript 示例：**

以下是一些 JavaScript 代码示例，说明了如何使用 `inspector-fuzzer.cc` 中定义的 C++ 扩展提供的功能：

**1. 使用 `utils` 对象中的方法：**

```javascript
// 退出 fuzzer
utils.quit();

// 编译并运行一段 JavaScript 代码，指定其来源信息
utils.compileAndRunWithOrigin(
  0, // contextGroupId
  "console.log('Hello from fuzzer!');", // 代码字符串
  "fuzzer.js", // 资源名称
  0, // 偏移量
  0, // 列号
  false // 是否是 module
);

// 安排在下一条语句暂停执行，模拟断点
utils.schedulePauseOnNextStatement(0, "debugger", "Pause on next statement");

// 取消安排的暂停
utils.cancelPauseOnNextStatement(0);

// 创建一个新的上下文组
let newContextGroupId = utils.createContextGroup();
console.log("New context group ID:", newContextGroupId);

// 重置一个上下文组
utils.resetContextGroup(newContextGroupId);

// 连接到一个 Inspector 会话
let sessionId = utils.connectSession(
  0, // contextGroupId
  "", // 可选的会话状态
  function(message) { // 接收后端消息的回调函数
    console.log("Received message from backend:", message);
  },
  true // 是否完全信任
);
console.log("Session ID:", sessionId);

// 断开一个 Inspector 会话
let disconnectState = utils.disconnectSession(sessionId);
console.log("Disconnect state:", disconnectState);

// 向后端发送 Inspector 协议消息
utils.sendMessageToBackend(sessionId, JSON.stringify({
  "id": 1,
  "method": "Runtime.evaluate",
  "params": { "expression": "1 + 1" }
}));
```

**2. 使用 `inspector` 对象中的方法：**

```javascript
// 触发一个上下文创建事件
inspector.fireContextCreated();

// 触发一个上下文销毁事件
inspector.fireContextDestroyed();

// 释放一个上下文
// inspector.freeContext(); // 通常不需要手动调用

// 添加一个被检查的对象
inspector.addInspectedObject(1, { name: "inspectedObject" });

// 设置异步任务堆栈的最大数量
inspector.setMaxAsyncTaskStacks(10);

// 中断程序执行
inspector.breakProgram("debugger", "人为中断");

// 创建一个具有严格访问检查的对象
let strictObject = inspector.createObjectWithStrictCheck();

// 调用一个函数并在其中安排断点
inspector.callWithScheduledBreak(function() {
  console.log("Inside the function with scheduled break.");
}, "debugger", "Break inside function");

// 将一个对象标记为不可检查
let notInspectable = {};
inspector.markObjectAsNotInspectable(notInspectable);

// 创建一个具有原生数据属性的对象
let nativeDataObj = inspector.createObjectWithNativeDataProperty("myProperty", true);

// 存储当前堆栈跟踪
let stackTraceIdBuffer = inspector.storeCurrentStackTrace("My Custom Stack Trace");
console.log("Stack trace ID buffer:", stackTraceIdBuffer);

// 标记一个外部异步任务开始
inspector.externalAsyncTaskStarted(stackTraceIdBuffer);

// 标记一个外部异步任务结束
inspector.externalAsyncTaskFinished(stackTraceIdBuffer);

// 使用异步堆栈调度一个任务
inspector.scheduleWithAsyncStack(function() {
  console.log("Async task executed.");
}, "MyAsyncTask", false);

// 允许从字符串生成代码
inspector.setAllowCodeGenerationFromStrings(true);

// 设置资源名称前缀
inspector.setResourceNamePrefix("fuzzer://");
```

**总结：**

`inspector-fuzzer.cc` 文件通过提供 C++ 扩展，增强了 JavaScript 环境的功能，使其能够模拟和控制 V8 Inspector 的行为。这对于 V8 引擎的内部测试和发现潜在问题至关重要。在正常的 JavaScript 开发中，我们不会直接使用这些 `utils` 和 `inspector` 对象，它们是为特定的模糊测试环境设计的。

Prompt: 
```
这是目录为v8/test/fuzzer/inspector-fuzzer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <locale.h>

#include <optional>
#include <string>
#include <vector>

#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-primitive.h"
#include "include/v8-template.h"
#include "src/api/api.h"
#include "src/base/platform/platform.h"
#include "src/base/platform/time.h"
#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "test/inspector/frontend-channel.h"
#include "test/inspector/isolate-data.h"
#include "test/inspector/task-runner.h"
#include "test/inspector/tasks.h"

#if !defined(V8_OS_WIN)
#include <unistd.h>
#endif  // !defined(V8_OS_WIN)

namespace v8 {
namespace internal {
namespace {

base::SmallVector<TaskRunner*, 2> task_runners;

class UtilsExtension : public InspectorIsolateData::SetupGlobalTask {
 public:
  ~UtilsExtension() override = default;
  void Run(v8::Isolate* isolate,
           v8::Local<v8::ObjectTemplate> global) override {
    v8::Local<v8::ObjectTemplate> utils = v8::ObjectTemplate::New(isolate);
    auto Set = [isolate](v8::Local<v8::ObjectTemplate> tmpl, const char* str,
                         v8::Local<v8::Data> value) {
      // Do not set {ReadOnly}, because fuzzer inputs might overwrite individual
      // methods, or the whole "utils" global. See the
      // `testing/libfuzzer/fuzzers/generate_v8_inspector_fuzzer_corpus.py` file
      // in chromium.
      tmpl->Set(ToV8String(isolate, str), value,
                static_cast<v8::PropertyAttribute>(
                    v8::PropertyAttribute::DontDelete));
    };
    Set(utils, "quit",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::Quit));
    Set(utils, "compileAndRunWithOrigin",
        v8::FunctionTemplate::New(isolate,
                                  &UtilsExtension::CompileAndRunWithOrigin));
    Set(utils, "schedulePauseOnNextStatement",
        v8::FunctionTemplate::New(
            isolate, &UtilsExtension::SchedulePauseOnNextStatement));
    Set(utils, "cancelPauseOnNextStatement",
        v8::FunctionTemplate::New(isolate,
                                  &UtilsExtension::CancelPauseOnNextStatement));
    Set(utils, "createContextGroup",
        v8::FunctionTemplate::New(isolate,
                                  &UtilsExtension::CreateContextGroup));
    Set(utils, "resetContextGroup",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::ResetContextGroup));
    Set(utils, "connectSession",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::ConnectSession));
    Set(utils, "disconnectSession",
        v8::FunctionTemplate::New(isolate, &UtilsExtension::DisconnectSession));
    Set(utils, "sendMessageToBackend",
        v8::FunctionTemplate::New(isolate,
                                  &UtilsExtension::SendMessageToBackend));
    Set(global, "utils", utils);
  }

  static void set_backend_task_runner(TaskRunner* runner) {
    backend_runner_ = runner;
  }

 private:
  static TaskRunner* backend_runner_;

  static void Quit(const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    // Only terminate, so not join the threads here, since joining concurrently
    // from multiple threads can be undefined behaviour (see pthread_join).
    for (TaskRunner* task_runner : task_runners) task_runner->Terminate();
  }

  static void CompileAndRunWithOrigin(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 6 || !info[0]->IsInt32() || !info[1]->IsString() ||
        !info[2]->IsString() || !info[3]->IsInt32() || !info[4]->IsInt32() ||
        !info[5]->IsBoolean()) {
      return;
    }

    backend_runner_->Append(std::make_unique<ExecuteStringTask>(
        info.GetIsolate(), info[0].As<v8::Int32>()->Value(),
        ToVector(info.GetIsolate(), info[1].As<v8::String>()),
        info[2].As<v8::String>(), info[3].As<v8::Int32>(),
        info[4].As<v8::Int32>(), info[5].As<v8::Boolean>()));
  }

  static void SchedulePauseOnNextStatement(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 3 || !info[0]->IsInt32() || !info[1]->IsString() ||
        !info[2]->IsString()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      return;
    }
    int context_group_id = info[0].As<v8::Int32>()->Value();
    RunSyncTask(backend_runner_,
                [&context_group_id](InspectorIsolateData* data) {
                  data->CancelPauseOnNextStatement(context_group_id);
                });
  }

  static void CreateContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 0) {
      return;
    }
    int context_group_id = 0;
    RunSyncTask(backend_runner_,
                [&context_group_id](InspectorIsolateData* data) {
                  context_group_id = data->CreateContextGroup();
                });
    info.GetReturnValue().Set(
        v8::Int32::New(info.GetIsolate(), context_group_id));
  }

  static void ResetContextGroup(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (!IsValidConnectSessionArgs(info)) return;
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

    if (session_id.has_value()) {
      info.GetReturnValue().Set(v8::Int32::New(info.GetIsolate(), *session_id));
    } else {
      info.GetIsolate()->ThrowError("Unable to connect to context group");
    }
  }

  static void DisconnectSession(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      return;
    }
    int session_id = info[0].As<v8::Int32>()->Value();
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    TaskRunner* context_task_runner =
        InspectorIsolateData::FromContext(context)->task_runner();
    std::vector<uint8_t> state;
    RunSyncTask(backend_runner_, [&session_id, &context_task_runner,
                                  &state](InspectorIsolateData* data) {
      state = data->DisconnectSession(session_id, context_task_runner);
    });

    info.GetReturnValue().Set(ToV8String(info.GetIsolate(), state));
  }

  static void SendMessageToBackend(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 2 || !info[0]->IsInt32() || !info[1]->IsString()) {
      return;
    }
    backend_runner_->Append(std::make_unique<SendMessageToBackendTask>(
        info[0].As<v8::Int32>()->Value(),
        ToVector(info.GetIsolate(), info[1].As<v8::String>())));
  }
};

TaskRunner* UtilsExtension::backend_runner_ = nullptr;

bool StrictAccessCheck(v8::Local<v8::Context> accessing_context,
                       v8::Local<v8::Object> accessed_object,
                       v8::Local<v8::Value> data) {
  CHECK(accessing_context.IsEmpty());
  return accessing_context.IsEmpty();
}

class InspectorExtension : public InspectorIsolateData::SetupGlobalTask {
 public:
  ~InspectorExtension() override = default;
  void Run(v8::Isolate* isolate,
           v8::Local<v8::ObjectTemplate> global) override {
    v8::Local<v8::ObjectTemplate> inspector = v8::ObjectTemplate::New(isolate);
    inspector->Set(ToV8String(isolate, "fireContextCreated"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::FireContextCreated));
    inspector->Set(ToV8String(isolate, "fireContextDestroyed"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::FireContextDestroyed));
    inspector->Set(
        ToV8String(isolate, "freeContext"),
        v8::FunctionTemplate::New(isolate, &InspectorExtension::FreeContext));
    inspector->Set(ToV8String(isolate, "addInspectedObject"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::AddInspectedObject));
    inspector->Set(ToV8String(isolate, "setMaxAsyncTaskStacks"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::SetMaxAsyncTaskStacks));
    inspector->Set(
        ToV8String(isolate, "breakProgram"),
        v8::FunctionTemplate::New(isolate, &InspectorExtension::BreakProgram));
    inspector->Set(
        ToV8String(isolate, "createObjectWithStrictCheck"),
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::CreateObjectWithStrictCheck));
    inspector->Set(ToV8String(isolate, "callWithScheduledBreak"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::CallWithScheduledBreak));
    inspector->Set(
        ToV8String(isolate, "markObjectAsNotInspectable"),
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::MarkObjectAsNotInspectable));
    inspector->Set(
        ToV8String(isolate, "createObjectWithNativeDataProperty"),
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::CreateObjectWithNativeDataProperty));
    inspector->Set(ToV8String(isolate, "storeCurrentStackTrace"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::StoreCurrentStackTrace));
    inspector->Set(ToV8String(isolate, "externalAsyncTaskStarted"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::ExternalAsyncTaskStarted));
    inspector->Set(
        ToV8String(isolate, "externalAsyncTaskFinished"),
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::ExternalAsyncTaskFinished));
    inspector->Set(ToV8String(isolate, "scheduleWithAsyncStack"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::ScheduleWithAsyncStack));
    inspector->Set(
        ToV8String(isolate, "setAllowCodeGenerationFromStrings"),
        v8::FunctionTemplate::New(
            isolate, &InspectorExtension::SetAllowCodeGenerationFromStrings));
    inspector->Set(ToV8String(isolate, "setResourceNamePrefix"),
                   v8::FunctionTemplate::New(
                       isolate, &InspectorExtension::SetResourceNamePrefix));
    global->Set(ToV8String(isolate, "inspector"), inspector);
  }

 private:
  static void FireContextCreated(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FireContextCreated(context, data->GetContextGroupId(context),
                             v8_inspector::StringView());
  }

  static void FireContextDestroyed(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FireContextDestroyed(context);
  }

  static void FreeContext(const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->FreeContext(context);
  }

  static void AddInspectedObject(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 2 || !info[0]->IsInt32()) {
      return;
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->AddInspectedObject(info[0].As<v8::Int32>()->Value(), info[1]);
  }

  static void SetMaxAsyncTaskStacks(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsInt32()) {
      return;
    }
    InspectorIsolateData::FromContext(info.GetIsolate()->GetCurrentContext())
        ->SetMaxAsyncTaskStacksForTest(info[0].As<v8::Int32>()->Value());
  }

  static void DumpAsyncTaskStacksStateForTest(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 0) {
      return;
    }
    InspectorIsolateData::FromContext(info.GetIsolate()->GetCurrentContext())
        ->DumpAsyncTaskStacksStateForTest();
  }

  static void BreakProgram(const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 2 || !info[0]->IsString() || !info[1]->IsString()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 0) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 3 || !info[0]->IsFunction() || !info[1]->IsString() ||
        !info[2]->IsString()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsObject()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 2 || !info[0]->IsString() || !info[1]->IsBoolean()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsString()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsArrayBuffer()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsArrayBuffer()) {
      return;
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
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 3 || !info[0]->IsFunction() || !info[1]->IsString() ||
        !info[2]->IsBoolean()) {
      return;
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
      return;
    }
    info.GetIsolate()->GetCurrentContext()->AllowCodeGenerationFromStrings(
        info[0].As<v8::Boolean>()->Value());
  }

  static void SetResourceNamePrefix(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    DCHECK(ValidateCallbackInfo(info));
    if (info.Length() != 1 || !info[0]->IsString()) {
      return;
    }
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
    data->SetResourceNamePrefix(v8::Local<v8::String>::Cast(info[0]));
  }
};

using CharVector = v8::base::Vector<const char>;

constexpr auto kMaxExecutionSeconds = v8::base::TimeDelta::FromSeconds(2);

class Watchdog final : public base::Thread {
 public:
  explicit Watchdog(base::Semaphore* semaphore)
      : base::Thread(base::Thread::Options("InspectorFuzzerWatchdog")),
        semaphore_(semaphore) {
    CHECK(Start());
  }

 private:
  void Run() override {
    if (semaphore_->WaitFor(kMaxExecutionSeconds)) return;
    for (TaskRunner* task_runner : task_runners) task_runner->Terminate();
  }

  base::Semaphore* const semaphore_;
};

void FuzzInspector(const uint8_t* data, size_t size) {
  base::Semaphore ready_semaphore(0);

  InspectorIsolateData::SetupGlobalTasks frontend_extensions;
  frontend_extensions.emplace_back(new UtilsExtension());
  TaskRunner frontend_runner(std::move(frontend_extensions),
                             kSuppressUncaughtExceptions, &ready_semaphore,
                             nullptr, kNoInspector);
  ready_semaphore.Wait();

  int frontend_context_group_id = 0;
  RunSyncTask(&frontend_runner,
              [&frontend_context_group_id](InspectorIsolateData* data) {
                frontend_context_group_id = data->CreateContextGroup();
              });

  InspectorIsolateData::SetupGlobalTasks backend_extensions;
  backend_extensions.emplace_back(new SetTimeoutExtension());
  backend_extensions.emplace_back(new InspectorExtension());
  TaskRunner backend_runner(std::move(backend_extensions),
                            kSuppressUncaughtExceptions, &ready_semaphore,
                            nullptr, kWithInspector);
  ready_semaphore.Wait();
  UtilsExtension::set_backend_task_runner(&backend_runner);

  task_runners = {&frontend_runner, &backend_runner};

  Watchdog watchdog(&ready_semaphore);

  frontend_runner.Append(std::make_unique<ExecuteStringTask>(
      std::string{reinterpret_cast<const char*>(data), size},
      frontend_context_group_id));

  frontend_runner.Join();
  backend_runner.Join();

  ready_semaphore.Signal();
  watchdog.Join();

  // TaskRunners go out of scope here, which causes Isolate teardown and all
  // running background tasks to be properly joined.
}

}  // namespace
}  // namespace internal
}  // namespace v8

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  v8::internal::FuzzInspector(data, size);
  return 0;
}

"""

```