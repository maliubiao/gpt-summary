Response: The user wants to understand the functionality of the C++ code in `v8/test/inspector/isolate-data.cc`. I need to analyze the code and summarize its purpose. Since the filename mentions "inspector", it's likely related to the debugging and profiling features of V8. The code seems to manage the lifecycle and interactions of isolates and inspector sessions.

Here's a breakdown of the key aspects and how they might relate to JavaScript:

1. **Isolate Management:** The code manages the creation and destruction of V8 isolates. An isolate is essentially an independent instance of the V8 JavaScript engine.
2. **Context Groups:** It handles the concept of context groups, which are collections of JavaScript execution contexts within an isolate.
3. **Inspector Sessions:**  The core purpose appears to be managing inspector sessions. These sessions allow external tools (like Chrome DevTools) to connect and interact with the JavaScript runtime for debugging.
4. **Communication with Inspector Frontend:** The code deals with sending messages to and receiving messages from the inspector frontend.
5. **Event Handling:**  It handles events like exceptions, promise rejections, and console API calls, forwarding them to the inspector.
6. **Breakpoints and Pausing:** The code includes mechanisms for programmatically pausing JavaScript execution.
7. **Asynchronous Tasks:** It tracks and reports on asynchronous tasks for debugging purposes.

To illustrate the connection with JavaScript, I can provide examples of JavaScript code that would trigger the functionalities exposed by this C++ code, especially related to debugging and inspector interactions.
这个 C++ 代码文件 `v8/test/inspector/isolate-data.cc` 的主要功能是 **为 V8 引擎的 Inspector (调试器) 提供测试环境和基础设施**。 它封装了与 V8 Isolate 和 Inspector 会话相关的操作，使得测试代码能够方便地创建和管理用于调试的 JavaScript 执行环境，并模拟 Inspector 前端与 V8 引擎的交互。

更具体地说，它的功能包括：

1. **Isolate 的创建和管理:**
   - 创建新的 V8 Isolate 实例。
   - 设置 Isolate 的参数，例如 ArrayBuffer 分配器和快照数据。
   - 维护 Isolate 的生命周期。

2. **Context Group 的创建和管理:**
   - 创建和管理 JavaScript 上下文组 (Context Group)。
   - 一个 Isolate 可以包含多个 Context Group。
   - 为每个 Context Group 创建默认的 JavaScript 上下文 (Context)。

3. **Inspector 会话 (Session) 的管理:**
   - 建立和断开 Inspector 会话。
   - 将 Inspector 会话与特定的 Context Group 关联。
   - 管理 Inspector 会话的状态。

4. **与 Inspector 前端的通信:**
   - 接收来自 Inspector 前端的消息。
   - 将消息分发到相应的 Inspector 会话。
   - 向 Inspector 前端发送事件通知，例如上下文创建、异常抛出等。

5. **JavaScript 代码的执行和调试支持:**
   - 在创建的上下文中执行 JavaScript 代码模块。
   - 处理 JavaScript 异常和 Promise 拒绝，并将信息传递给 Inspector。
   - 支持设置断点和暂停 JavaScript 执行。
   - 跟踪异步任务的开始和结束。

6. **测试辅助功能:**
   - 提供设置最大异步调用堆栈深度的接口，用于测试。
   - 提供倾倒异步调用堆栈状态的接口，用于测试。
   - 允许设置模拟的当前时间，用于测试时间相关的 Inspector 功能。

**它与 JavaScript 的功能有密切关系。**  `InspectorIsolateData` 提供的功能是为了支持 JavaScript 代码的调试和检查。  当你在 Chrome DevTools 中调试 JavaScript 代码时，DevTools (Inspector 前端) 与 V8 引擎之间进行的通信和交互，很大一部分就涉及到 `InspectorIsolateData` 中实现的功能。

**JavaScript 举例说明:**

假设我们有以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  debugger; // 设置断点
  return a + b;
}

console.log(add(5, 3));

Promise.reject(new Error("Something went wrong")).catch(error => {
  console.error(error);
});

setTimeout(() => {
  console.log("Async task finished");
}, 1000);
```

当 V8 引擎执行这段代码时，`InspectorIsolateData` 的相关功能会被触发：

1. **`debugger;` 语句:** 当执行到 `debugger;` 语句时，`InspectorIsolateData` 会调用 `breakProgram` 或 `schedulePauseOnNextStatement` 等方法，通知 Inspector 前端，程序执行已暂停，等待调试操作。

2. **`console.log` 和 `console.error`:** 当执行到 `console.log` 或 `console.error` 时，`InspectorIsolateData` 会调用 `consoleAPIMessage` 方法，将日志信息、URL、行号等信息发送给 Inspector 前端，以便在 DevTools 的控制台中显示。

3. **`Promise.reject`:** 当 Promise 被拒绝时，`InspectorIsolateData` 的 `PromiseRejectHandler` 会被调用，将拒绝的原因和堆栈信息传递给 Inspector 前端，以便在 DevTools 中显示未处理的 Promise 拒绝。

4. **`setTimeout`:** 当使用 `setTimeout` 创建异步任务时，`InspectorIsolateData` 可能会调用 `asyncTaskScheduled` 方法，通知 Inspector 前端有新的异步任务被调度。当异步任务开始和结束时，会调用 `asyncTaskStarted` 和 `asyncTaskFinished` 方法，以便在 DevTools 的 "Performance" 或 "Sources" 面板中跟踪异步任务的执行情况。

**总结来说，`v8/test/inspector/isolate-data.cc` 是 V8 Inspector 功能测试的核心组件，它模拟了 Inspector 的后端行为，使得 V8 团队能够有效地测试 Inspector 的各种功能，并确保其与 JavaScript 代码的正确交互。**  它并不直接参与用户运行的 JavaScript 代码的执行，而是服务于调试和检查这个执行过程。

Prompt: 
```
这是目录为v8/test/inspector/isolate-data.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/inspector/isolate-data.h"

#include <optional>

#include "include/v8-context.h"
#include "include/v8-exception.h"
#include "include/v8-microtask-queue.h"
#include "include/v8-template.h"
#include "src/execution/isolate.h"
#include "src/heap/heap.h"
#include "src/init/v8.h"
#include "src/inspector/test-interface.h"
#include "test/inspector/frontend-channel.h"
#include "test/inspector/task-runner.h"
#include "test/inspector/utils.h"

namespace v8 {
namespace internal {

namespace {

const int kIsolateDataIndex = 2;
const int kContextGroupIdIndex = 3;

void Print(v8::Isolate* isolate, const v8_inspector::StringView& string) {
  v8::Local<v8::String> v8_string = ToV8String(isolate, string);
  v8::String::Utf8Value utf8_string(isolate, v8_string);
  fwrite(*utf8_string, sizeof(**utf8_string), utf8_string.length(), stdout);
}

class Inspectable : public v8_inspector::V8InspectorSession::Inspectable {
 public:
  Inspectable(v8::Isolate* isolate, v8::Local<v8::Value> object)
      : object_(isolate, object) {}
  ~Inspectable() override = default;
  v8::Local<v8::Value> get(v8::Local<v8::Context> context) override {
    return object_.Get(context->GetIsolate());
  }

 private:
  v8::Global<v8::Value> object_;
};

}  //  namespace

InspectorIsolateData::InspectorIsolateData(
    TaskRunner* task_runner,
    InspectorIsolateData::SetupGlobalTasks setup_global_tasks,
    v8::StartupData* startup_data, WithInspector with_inspector)
    : task_runner_(task_runner),
      setup_global_tasks_(std::move(setup_global_tasks)) {
  v8::Isolate::CreateParams params;
  array_buffer_allocator_.reset(
      v8::ArrayBuffer::Allocator::NewDefaultAllocator());
  params.array_buffer_allocator = array_buffer_allocator_.get();
  params.snapshot_blob = startup_data;
  isolate_.reset(v8::Isolate::New(params));
  v8::Isolate::Scope isolate_scope(isolate_.get());
  isolate_->SetMicrotasksPolicy(v8::MicrotasksPolicy::kScoped);
  if (with_inspector) {
    isolate_->AddMessageListener(&InspectorIsolateData::MessageHandler);
    isolate_->SetPromiseRejectCallback(
        &InspectorIsolateData::PromiseRejectHandler);
    inspector_ = v8_inspector::V8Inspector::create(isolate_.get(), this);
  }
  v8::HandleScope handle_scope(isolate_.get());
  not_inspectable_private_.Reset(
      isolate_.get(),
      v8::Private::ForApi(
          isolate_.get(),
          v8::String::NewFromUtf8Literal(isolate_.get(), "notInspectable")));
}

InspectorIsolateData* InspectorIsolateData::FromContext(
    v8::Local<v8::Context> context) {
  return static_cast<InspectorIsolateData*>(
      context->GetAlignedPointerFromEmbedderData(kIsolateDataIndex));
}

InspectorIsolateData::~InspectorIsolateData() {
  // Enter the isolate before destructing this InspectorIsolateData, so that
  // destructors that run before the Isolate's destructor still see it as
  // entered. Use a v8::Locker, in case the thread destroying the isolate is
  // not the last one that entered it.
  locker_.emplace(isolate());
  isolate()->Enter();

  // Sessions need to be deleted before channels can be cleaned up, and channels
  // must be deleted before the isolate gets cleaned up. This means we first
  // clean up all the sessions and immedatly after all the channels used by
  // those sessions.
  for (const auto& pair : sessions_) {
    session_ids_for_cleanup_.insert(pair.first);
  }

  context_group_by_session_.clear();
  sessions_.clear();

  for (int session_id : session_ids_for_cleanup_) {
    ChannelHolder::RemoveChannel(session_id);
  }
}

int InspectorIsolateData::CreateContextGroup() {
  int context_group_id = ++last_context_group_id_;
  if (!CreateContext(context_group_id, v8_inspector::StringView())) {
    DCHECK(isolate_->IsExecutionTerminating());
    return -1;
  }
  return context_group_id;
}

bool InspectorIsolateData::CreateContext(int context_group_id,
                                         v8_inspector::StringView name) {
  v8::HandleScope handle_scope(isolate_.get());
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate_.get());
  for (auto it = setup_global_tasks_.begin(); it != setup_global_tasks_.end();
       ++it) {
    (*it)->Run(isolate_.get(), global_template);
  }
  v8::Local<v8::Context> context =
      v8::Context::New(isolate_.get(), nullptr, global_template);
  if (context.IsEmpty()) return false;
  context->SetAlignedPointerInEmbedderData(kIsolateDataIndex, this);
  // Should be 2-byte aligned.
  context->SetAlignedPointerInEmbedderData(
      kContextGroupIdIndex, reinterpret_cast<void*>(context_group_id * 2));
  contexts_[context_group_id].emplace_back(isolate_.get(), context);
  if (inspector_) FireContextCreated(context, context_group_id, name);
  return true;
}

v8::Local<v8::Context> InspectorIsolateData::GetDefaultContext(
    int context_group_id) {
  return contexts_[context_group_id].begin()->Get(isolate_.get());
}

void InspectorIsolateData::ResetContextGroup(int context_group_id) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->resetContextGroup(context_group_id);
}

int InspectorIsolateData::GetContextGroupId(v8::Local<v8::Context> context) {
  return static_cast<int>(
      reinterpret_cast<intptr_t>(
          context->GetAlignedPointerFromEmbedderData(kContextGroupIdIndex)) /
      2);
}

void InspectorIsolateData::RegisterModule(v8::Local<v8::Context> context,
                                          std::vector<uint16_t> name,
                                          v8::ScriptCompiler::Source* source) {
  v8::Local<v8::Module> module;
  if (!v8::ScriptCompiler::CompileModule(isolate(), source).ToLocal(&module))
    return;
  if (!module
           ->InstantiateModule(context,
                               &InspectorIsolateData::ModuleResolveCallback)
           .FromMaybe(false)) {
    return;
  }
  v8::Local<v8::Value> result;
  if (!module->Evaluate(context).ToLocal(&result)) return;
  modules_[name] = v8::Global<v8::Module>(isolate_.get(), module);
}

// static
v8::MaybeLocal<v8::Module> InspectorIsolateData::ModuleResolveCallback(
    v8::Local<v8::Context> context, v8::Local<v8::String> specifier,
    v8::Local<v8::FixedArray> import_attributes,
    v8::Local<v8::Module> referrer) {
  // TODO(v8:11189) Consider JSON modules support in the InspectorClient
  InspectorIsolateData* data = InspectorIsolateData::FromContext(context);
  std::string str = *v8::String::Utf8Value(data->isolate(), specifier);
  v8::MaybeLocal<v8::Module> maybe_module =
      data->modules_[ToVector(data->isolate(), specifier)].Get(data->isolate());
  if (maybe_module.IsEmpty()) {
    data->isolate()->ThrowError(v8::String::Concat(
        data->isolate(),
        ToV8String(data->isolate(), "Failed to resolve module: "), specifier));
  }
  return maybe_module;
}

std::optional<int> InspectorIsolateData::ConnectSession(
    int context_group_id, const v8_inspector::StringView& state,
    std::unique_ptr<FrontendChannelImpl> channel, bool is_fully_trusted) {
  if (contexts_.find(context_group_id) == contexts_.end()) return std::nullopt;

  v8::SealHandleScope seal_handle_scope(isolate());
  int session_id = ++last_session_id_;
  // It's important that we register the channel before the `connect` as the
  // inspector will already send notifications.
  auto* c = channel.get();
  ChannelHolder::AddChannel(session_id, std::move(channel));
  sessions_[session_id] = inspector_->connect(
      context_group_id, c, state,
      is_fully_trusted ? v8_inspector::V8Inspector::kFullyTrusted
                       : v8_inspector::V8Inspector::kUntrusted,
      waiting_for_debugger_
          ? v8_inspector::V8Inspector::kWaitingForDebugger
          : v8_inspector::V8Inspector::kNotWaitingForDebugger);
  context_group_by_session_[sessions_[session_id].get()] = context_group_id;
  return session_id;
}

namespace {

class RemoveChannelTask : public TaskRunner::Task {
 public:
  explicit RemoveChannelTask(int session_id) : session_id_(session_id) {}
  ~RemoveChannelTask() override = default;
  bool is_priority_task() final { return false; }

 private:
  void Run(InspectorIsolateData* data) override {
    ChannelHolder::RemoveChannel(session_id_);
  }
  int session_id_;
};

}  // namespace

std::vector<uint8_t> InspectorIsolateData::DisconnectSession(
    int session_id, TaskRunner* context_task_runner) {
  v8::SealHandleScope seal_handle_scope(isolate());
  auto it = sessions_.find(session_id);
  CHECK(it != sessions_.end());
  context_group_by_session_.erase(it->second.get());
  std::vector<uint8_t> result = it->second->state();
  sessions_.erase(it);

  // The InspectorSession destructor does cleanup work like disabling agents.
  // This could send some more notifications. We'll delay removing the channel
  // so notification tasks have time to get sent.
  // Note: This only works for tasks scheduled immediately by the desctructor.
  //       Any task scheduled in turn by one of the "cleanup tasks" will run
  //       AFTER the channel was removed.
  context_task_runner->Append(std::make_unique<RemoveChannelTask>(session_id));

  // In case we shutdown the test runner before the above task can run, we
  // let the desctructor clean up the channel.
  session_ids_for_cleanup_.insert(session_id);
  return result;
}

void InspectorIsolateData::SendMessage(
    int session_id, const v8_inspector::StringView& message) {
  v8::SealHandleScope seal_handle_scope(isolate());
  auto it = sessions_.find(session_id);
  if (it != sessions_.end()) it->second->dispatchProtocolMessage(message);
}

void InspectorIsolateData::BreakProgram(
    int context_group_id, const v8_inspector::StringView& reason,
    const v8_inspector::StringView& details) {
  v8::SealHandleScope seal_handle_scope(isolate());
  for (int session_id : GetSessionIds(context_group_id)) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) it->second->breakProgram(reason, details);
  }
}

void InspectorIsolateData::Stop(int session_id) {
  v8::SealHandleScope seal_handle_scope(isolate());
  auto it = sessions_.find(session_id);
  if (it != sessions_.end()) it->second->stop();
}

void InspectorIsolateData::SchedulePauseOnNextStatement(
    int context_group_id, const v8_inspector::StringView& reason,
    const v8_inspector::StringView& details) {
  v8::SealHandleScope seal_handle_scope(isolate());
  for (int session_id : GetSessionIds(context_group_id)) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end())
      it->second->schedulePauseOnNextStatement(reason, details);
  }
}

void InspectorIsolateData::CancelPauseOnNextStatement(int context_group_id) {
  v8::SealHandleScope seal_handle_scope(isolate());
  for (int session_id : GetSessionIds(context_group_id)) {
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) it->second->cancelPauseOnNextStatement();
  }
}

void InspectorIsolateData::AsyncTaskScheduled(
    const v8_inspector::StringView& name, void* task, bool recurring) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->asyncTaskScheduled(name, task, recurring);
}

void InspectorIsolateData::AsyncTaskStarted(void* task) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->asyncTaskStarted(task);
}

void InspectorIsolateData::AsyncTaskFinished(void* task) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->asyncTaskFinished(task);
}

v8_inspector::V8StackTraceId InspectorIsolateData::StoreCurrentStackTrace(
    const v8_inspector::StringView& description) {
  v8::SealHandleScope seal_handle_scope(isolate());
  return inspector_->storeCurrentStackTrace(description);
}

void InspectorIsolateData::ExternalAsyncTaskStarted(
    const v8_inspector::V8StackTraceId& parent) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->externalAsyncTaskStarted(parent);
}

void InspectorIsolateData::ExternalAsyncTaskFinished(
    const v8_inspector::V8StackTraceId& parent) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->externalAsyncTaskFinished(parent);
}

void InspectorIsolateData::AddInspectedObject(int session_id,
                                              v8::Local<v8::Value> object) {
  v8::SealHandleScope seal_handle_scope(isolate());
  auto it = sessions_.find(session_id);
  if (it == sessions_.end()) return;
  std::unique_ptr<Inspectable> inspectable(
      new Inspectable(isolate_.get(), object));
  it->second->addInspectedObject(std::move(inspectable));
}

void InspectorIsolateData::SetMaxAsyncTaskStacksForTest(int limit) {
  v8::SealHandleScope seal_handle_scope(isolate());
  v8_inspector::SetMaxAsyncTaskStacksForTest(inspector_.get(), limit);
}

void InspectorIsolateData::DumpAsyncTaskStacksStateForTest() {
  v8::SealHandleScope seal_handle_scope(isolate());
  v8_inspector::DumpAsyncTaskStacksStateForTest(inspector_.get());
}

// static
int InspectorIsolateData::HandleMessage(v8::Local<v8::Message> message,
                                        v8::Local<v8::Value> exception) {
  v8::Isolate* isolate = message->GetIsolate();
  v8::Local<v8::Context> context = isolate->GetEnteredOrMicrotaskContext();
  if (context.IsEmpty()) return 0;
  v8_inspector::V8Inspector* inspector =
      InspectorIsolateData::FromContext(context)->inspector_.get();

  v8::Local<v8::StackTrace> stack = message->GetStackTrace();
  int script_id = message->GetScriptOrigin().ScriptId();
  if (!stack.IsEmpty() && stack->GetFrameCount() > 0) {
    int top_script_id = stack->GetFrame(isolate, 0)->GetScriptId();
    if (top_script_id == script_id) script_id = 0;
  }
  int line_number = message->GetLineNumber(context).FromMaybe(0);
  int column_number = 0;
  if (message->GetStartColumn(context).IsJust())
    column_number = message->GetStartColumn(context).FromJust() + 1;

  v8_inspector::StringView detailed_message;
  std::vector<uint16_t> message_text_string = ToVector(isolate, message->Get());
  v8_inspector::StringView message_text(message_text_string.data(),
                                        message_text_string.size());
  std::vector<uint16_t> url_string;
  if (message->GetScriptOrigin().ResourceName()->IsString()) {
    url_string = ToVector(
        isolate, message->GetScriptOrigin().ResourceName().As<v8::String>());
  }
  v8_inspector::StringView url(url_string.data(), url_string.size());

  v8::SealHandleScope seal_handle_scope(isolate);
  return inspector->exceptionThrown(
      context, message_text, exception, detailed_message, url, line_number,
      column_number, inspector->createStackTrace(stack), script_id);
}

// static
void InspectorIsolateData::MessageHandler(v8::Local<v8::Message> message,
                                          v8::Local<v8::Value> exception) {
  HandleMessage(message, exception);
}

// static
void InspectorIsolateData::PromiseRejectHandler(v8::PromiseRejectMessage data) {
  v8::Isolate* isolate = data.GetPromise()->GetIsolate();
  v8::Local<v8::Context> context = isolate->GetEnteredOrMicrotaskContext();
  if (context.IsEmpty()) return;
  v8::Local<v8::Promise> promise = data.GetPromise();
  v8::Local<v8::Private> id_private = v8::Private::ForApi(
      isolate, v8::String::NewFromUtf8Literal(isolate, "id"));

  if (data.GetEvent() == v8::kPromiseHandlerAddedAfterReject) {
    v8::Local<v8::Value> id;
    if (!promise->GetPrivate(context, id_private).ToLocal(&id)) return;
    if (!id->IsInt32()) return;
    v8_inspector::V8Inspector* inspector =
        InspectorIsolateData::FromContext(context)->inspector_.get();
    v8::SealHandleScope seal_handle_scope(isolate);
    const char* reason_str = "Handler added to rejected promise";
    inspector->exceptionRevoked(
        context, id.As<v8::Int32>()->Value(),
        v8_inspector::StringView(reinterpret_cast<const uint8_t*>(reason_str),
                                 strlen(reason_str)));
    return;
  } else if (data.GetEvent() == v8::kPromiseRejectAfterResolved ||
             data.GetEvent() == v8::kPromiseResolveAfterResolved) {
    // Ignore reject/resolve after resolved, like the blink handler.
    return;
  }

  v8::Local<v8::Value> exception = data.GetValue();
  int exception_id = HandleMessage(
      v8::Exception::CreateMessage(isolate, exception), exception);
  if (exception_id) {
    if (promise
            ->SetPrivate(isolate->GetCurrentContext(), id_private,
                         v8::Int32::New(isolate, exception_id))
            .IsNothing()) {
      // Handling the |message| above calls back into JavaScript (by reporting
      // it via CDP) in case of `inspector-test`, and can lead to terminating
      // execution on the |isolate|, in which case the API call above will
      // return immediately.
      DCHECK(isolate->IsExecutionTerminating());
    }
  }
}

void InspectorIsolateData::FireContextCreated(v8::Local<v8::Context> context,
                                              int context_group_id,
                                              v8_inspector::StringView name) {
  v8_inspector::V8ContextInfo info(context, context_group_id, name);
  info.hasMemoryOnConsole = true;
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->contextCreated(info);
}

void InspectorIsolateData::FireContextDestroyed(
    v8::Local<v8::Context> context) {
  v8::SealHandleScope seal_handle_scope(isolate());
  inspector_->contextDestroyed(context);
}

void InspectorIsolateData::FreeContext(v8::Local<v8::Context> context) {
  int context_group_id = GetContextGroupId(context);
  auto it = contexts_.find(context_group_id);
  if (it == contexts_.end()) return;
  contexts_.erase(it);
}

std::vector<int> InspectorIsolateData::GetSessionIds(int context_group_id) {
  std::vector<int> result;
  for (auto& it : sessions_) {
    if (context_group_by_session_[it.second.get()] == context_group_id)
      result.push_back(it.first);
  }
  return result;
}

bool InspectorIsolateData::isInspectableHeapObject(
    v8::Local<v8::Object> object) {
  v8::Local<v8::Context> context = isolate()->GetCurrentContext();
  v8::MicrotasksScope microtasks_scope(
      context, v8::MicrotasksScope::kDoNotRunMicrotasks);
  return !object->HasPrivate(context, not_inspectable_private_.Get(isolate()))
              .FromMaybe(false);
}

v8::Local<v8::Context> InspectorIsolateData::ensureDefaultContextInGroup(
    int context_group_id) {
  return GetDefaultContext(context_group_id);
}

void InspectorIsolateData::SetCurrentTimeMS(double time) {
  current_time_ = time;
  current_time_set_ = true;
}

double InspectorIsolateData::currentTimeMS() {
  if (current_time_set_) return current_time_;
  return V8::GetCurrentPlatform()->CurrentClockTimeMillisecondsHighResolution();
}

void InspectorIsolateData::SetMemoryInfo(v8::Local<v8::Value> memory_info) {
  memory_info_.Reset(isolate_.get(), memory_info);
}

void InspectorIsolateData::SetLogConsoleApiMessageCalls(bool log) {
  log_console_api_message_calls_ = log;
}

void InspectorIsolateData::SetLogMaxAsyncCallStackDepthChanged(bool log) {
  log_max_async_call_stack_depth_changed_ = log;
}

void InspectorIsolateData::SetAdditionalConsoleApi(
    v8_inspector::StringView api_script) {
  v8::HandleScope handle_scope(isolate());
  additional_console_api_.Reset(isolate(), ToV8String(isolate(), api_script));
}

v8::MaybeLocal<v8::Value> InspectorIsolateData::memoryInfo(
    v8::Isolate* isolate, v8::Local<v8::Context>) {
  if (memory_info_.IsEmpty()) return v8::MaybeLocal<v8::Value>();
  return memory_info_.Get(isolate);
}

void InspectorIsolateData::runMessageLoopOnPause(int) {
  v8::SealHandleScope seal_handle_scope(isolate());
  // Pumping the message loop below may trigger the execution of a stackless
  // GC. We need to override the embedder stack state, to force scanning the
  // stack, if this happens.
  i::Heap* heap =
      reinterpret_cast<i::Isolate*>(task_runner_->isolate())->heap();
  i::EmbedderStackStateScope scope(
      heap, i::EmbedderStackStateOrigin::kExplicitInvocation,
      StackState::kMayContainHeapPointers);
  task_runner_->RunMessageLoop(true);
}

void InspectorIsolateData::runIfWaitingForDebugger(int) {
  quitMessageLoopOnPause();
}

void InspectorIsolateData::quitMessageLoopOnPause() {
  v8::SealHandleScope seal_handle_scope(isolate());
  task_runner_->QuitMessageLoop();
}

void InspectorIsolateData::installAdditionalCommandLineAPI(
    v8::Local<v8::Context> context, v8::Local<v8::Object> object) {
  if (additional_console_api_.IsEmpty()) return;
  CHECK(context->GetIsolate() == isolate());
  v8::HandleScope handle_scope(isolate());
  v8::Context::Scope context_scope(context);
  v8::ScriptOrigin origin(
      v8::String::NewFromUtf8Literal(isolate(), "internal-console-api"));
  v8::ScriptCompiler::Source scriptSource(
      additional_console_api_.Get(isolate()), origin);
  v8::MaybeLocal<v8::Script> script =
      v8::ScriptCompiler::Compile(context, &scriptSource);
  CHECK(!script.ToLocalChecked()->Run(context).IsEmpty());
}

void InspectorIsolateData::consoleAPIMessage(
    int contextGroupId, v8::Isolate::MessageErrorLevel level,
    const v8_inspector::StringView& message,
    const v8_inspector::StringView& url, unsigned lineNumber,
    unsigned columnNumber, v8_inspector::V8StackTrace* stack) {
  if (!log_console_api_message_calls_) return;
  switch (level) {
    case v8::Isolate::kMessageLog:
      fprintf(stdout, "log: ");
      break;
    case v8::Isolate::kMessageDebug:
      fprintf(stdout, "debug: ");
      break;
    case v8::Isolate::kMessageInfo:
      fprintf(stdout, "info: ");
      break;
    case v8::Isolate::kMessageError:
      fprintf(stdout, "error: ");
      break;
    case v8::Isolate::kMessageWarning:
      fprintf(stdout, "warning: ");
      break;
    case v8::Isolate::kMessageAll:
      break;
  }
  Print(isolate_.get(), message);
  fprintf(stdout, " (");
  Print(isolate_.get(), url);
  fprintf(stdout, ":%d:%d)", lineNumber, columnNumber);
  Print(isolate_.get(), stack->toString()->string());
  fprintf(stdout, "\n");
}

void InspectorIsolateData::maxAsyncCallStackDepthChanged(int depth) {
  if (!log_max_async_call_stack_depth_changed_) return;
  fprintf(stdout, "maxAsyncCallStackDepthChanged: %d\n", depth);
}

void InspectorIsolateData::SetResourceNamePrefix(v8::Local<v8::String> prefix) {
  resource_name_prefix_.Reset(isolate(), prefix);
}

bool InspectorIsolateData::AssociateExceptionData(
    v8::Local<v8::Value> exception, v8::Local<v8::Name> key,
    v8::Local<v8::Value> value) {
  return inspector_->associateExceptionData(
      this->isolate()->GetCurrentContext(), exception, key, value);
}

void InspectorIsolateData::WaitForDebugger(int context_group_id) {
  DCHECK(!waiting_for_debugger_);
  waiting_for_debugger_ = true;
  runMessageLoopOnPause(context_group_id);
  waiting_for_debugger_ = false;
}

namespace {
class StringBufferImpl : public v8_inspector::StringBuffer {
 public:
  StringBufferImpl(v8::Isolate* isolate, v8::Local<v8::String> string)
      : data_(ToVector(isolate, string)) {}

  v8_inspector::StringView string() const override {
    return v8_inspector::StringView(data_.data(), data_.size());
  }

 private:
  std::vector<uint16_t> data_;
};
}  // anonymous namespace

std::unique_ptr<v8_inspector::StringBuffer>
InspectorIsolateData::resourceNameToUrl(
    const v8_inspector::StringView& resourceName) {
  if (resource_name_prefix_.IsEmpty()) return nullptr;
  v8::HandleScope handle_scope(isolate());
  v8::Local<v8::String> name = ToV8String(isolate(), resourceName);
  v8::Local<v8::String> prefix = resource_name_prefix_.Get(isolate());
  v8::Local<v8::String> url = v8::String::Concat(isolate(), prefix, name);
  return std::make_unique<StringBufferImpl>(isolate(), url);
}

int64_t InspectorIsolateData::generateUniqueId() {
  static int64_t last_unique_id = 0L;
  // Keep it not too random for tests.
  return ++last_unique_id;
}

// static
void ChannelHolder::AddChannel(int session_id,
                               std::unique_ptr<FrontendChannelImpl> channel) {
  CHECK_NE(channel.get(), nullptr);
  channel->set_session_id(session_id);
  channels_[session_id] = std::move(channel);
}

// static
FrontendChannelImpl* ChannelHolder::GetChannel(int session_id) {
  auto it = channels_.find(session_id);
  return it != channels_.end() ? it->second.get() : nullptr;
}

// static
void ChannelHolder::RemoveChannel(int session_id) {
  channels_.erase(session_id);
}

// static
std::map<int, std::unique_ptr<FrontendChannelImpl>> ChannelHolder::channels_;

}  // namespace internal
}  // namespace v8

"""

```