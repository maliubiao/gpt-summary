Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The core request is to analyze the functionality of the `inspector-fuzzer.cc` file. The file path `v8/test/fuzzer/` immediately suggests its purpose: it's a fuzzer for the V8 inspector. Fuzzers are used to find bugs by feeding semi-random or mutated inputs to a program.

2. **Initial Scan for Keywords and Structures:**  Quickly scan the code for important keywords and structural elements:
    * `#include`:  This tells us what external libraries and V8 components are being used. Look for things related to `v8-inspector.h`, `v8.h`, threading (`pthread`, though not explicitly here, but the concept of `TaskRunner`), and general utilities.
    * `namespace v8::internal`:  This confirms we are within V8's internal implementation.
    * `class UtilsExtension`, `class InspectorExtension`: These classes clearly define extensions to the V8 environment for the fuzzer. They are likely providing functions accessible from the fuzzed JavaScript.
    * `FuzzInspector` function: This is the main entry point for the fuzzer, taking the input data as a byte array.
    * `LLVMFuzzerTestOneInput`: This is the standard entry point for libFuzzer, confirming the file's role in fuzzing.
    * Function names within the extension classes (e.g., `Quit`, `CompileAndRunWithOrigin`, `FireContextCreated`). These are the specific functionalities being exposed to the fuzzer.

3. **Analyze `UtilsExtension`:**  This extension seems to provide utilities for controlling the fuzzer environment and interacting with the backend inspector. Go through each function:
    * `Quit`: Terminates the task runners. Essential for ending a fuzzing run.
    * `CompileAndRunWithOrigin`: Executes a string of JavaScript code within a specific context. This is a core fuzzing action.
    * `SchedulePauseOnNextStatement`, `CancelPauseOnNextStatement`: Controls debugger breakpoints. Useful for testing debugging scenarios.
    * `CreateContextGroup`, `ResetContextGroup`: Manages different V8 contexts for isolation.
    * `ConnectSession`, `DisconnectSession`: Simulates connecting and disconnecting inspector sessions.
    * `SendMessageToBackend`: Sends raw inspector protocol messages. This is key for exercising the inspector's message handling logic.

4. **Analyze `InspectorExtension`:** This extension provides functions that directly interact with the V8 inspector's internal state and behavior.
    * `FireContextCreated`, `FireContextDestroyed`, `FreeContext`: Simulate context creation and destruction events that the inspector observes.
    * `AddInspectedObject`: Makes objects available in the inspector's "scope."
    * `SetMaxAsyncTaskStacks`: Configures inspector settings related to async stack traces.
    * `BreakProgram`: Triggers a debugger breakpoint.
    * Functions related to access checks (`CreateObjectWithStrictCheck`), native data properties (`CreateObjectWithNativeDataProperty`), and object inspectability (`MarkObjectAsNotInspectable`). These are for testing specific inspector features and edge cases.
    * Functions for testing asynchronous operations and stack traces (`StoreCurrentStackTrace`, `ExternalAsyncTaskStarted`, `ExternalAsyncTaskFinished`, `ScheduleWithAsyncStack`). Important for testing how the inspector handles asynchronous code.
    * `SetAllowCodeGenerationFromStrings`, `SetResourceNamePrefix`:  Control V8 settings that can affect code execution and inspector behavior.

5. **Identify the Fuzzing Workflow:**  The `FuzzInspector` function orchestrates the fuzzing process:
    * It sets up two `TaskRunner` instances: one for the "frontend" (where the fuzzer script runs) and one for the "backend" (the V8 instance being inspected). This separation is important for managing asynchronous operations and avoiding deadlocks.
    * It creates context groups in both runners.
    * It initializes the extensions.
    * It starts a `Watchdog` thread to prevent the fuzzer from running indefinitely if a bug causes a hang.
    * It executes the fuzzer input (`data`) as a JavaScript string in the frontend context.
    * It waits for the task runners to finish.

6. **Address the Specific Questions:** Now, go back to the original prompt and answer each question based on the understanding gained:
    * **Functionality:** Summarize the roles of the two extensions and the overall fuzzing process.
    * **Torque:** Check the file extension (`.cc`). It's C++, not Torque.
    * **JavaScript Relation:** Identify the functions in the extensions that directly relate to JavaScript execution and inspector features. Provide concrete JavaScript examples that would call these functions.
    * **Code Logic Inference:** Choose a function with clear logic (e.g., `CompileAndRunWithOrigin`) and demonstrate how it would work with example inputs and outputs.
    * **Common Programming Errors:** Think about how a user might misuse the exposed functions, leading to errors (e.g., incorrect argument types in `CompileAndRunWithOrigin`).

7. **Refine and Organize:**  Structure the answer clearly with headings and bullet points. Use precise language and avoid jargon where possible. Ensure the JavaScript examples are valid and easy to understand. Double-check the code for details and make sure the explanations are accurate. For example, note the role of `TaskRunner` and the synchronization mechanisms used.

Self-Correction Example During the Process:

* **Initial thought:** "Maybe `UtilsExtension` is just for basic utilities."
* **Correction:**  On closer inspection, `ConnectSession` and `SendMessageToBackend` are clearly related to inspector communication, not just basic utilities. This understanding is crucial for accurately describing the file's functionality. The separation of frontend and backend runners also highlights the structure of the inspector interaction.

By following this structured analysis, we can effectively understand the purpose and functionality of complex code like the V8 inspector fuzzer.
The file `v8/test/fuzzer/inspector-fuzzer.cc` is a **C++ source file** that implements a **fuzzer** specifically designed to test the **V8 Inspector**.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Fuzzing the V8 Inspector:** The primary goal is to generate potentially malformed or unexpected input for the V8 Inspector to uncover bugs, crashes, or security vulnerabilities.
* **Simulating Inspector Interactions:** The fuzzer sets up a controlled V8 environment and provides JavaScript functions that mimic interactions with the Inspector protocol. This allows the fuzzer to send various commands and data to the Inspector.
* **Providing Utility Functions:** It exposes a set of utility functions via a global `utils` object in the fuzzed JavaScript environment. These functions allow the fuzzer to control the execution environment (e.g., quit, compile and run code), manage contexts, and interact with the Inspector backend.
* **Providing Inspector-Specific Functions:**  It exposes a set of functions via a global `inspector` object that directly interacts with the V8 Inspector's internal mechanisms (e.g., triggering context creation/destruction events, setting breakpoints, managing inspected objects).
* **Managing Multiple Contexts:** The fuzzer can create and manage multiple V8 contexts to test Inspector behavior in multi-context scenarios.
* **Asynchronous Operations:** It handles asynchronous operations and allows testing of Inspector features related to asynchronous JavaScript execution.
* **Watchdog Timer:** A watchdog timer is implemented to prevent the fuzzer from running indefinitely in case of hangs or infinite loops.

**Specific Functionalities Exposed via JavaScript:**

The code defines two main extension classes that expose functions to the fuzzed JavaScript environment: `UtilsExtension` and `InspectorExtension`.

**`UtilsExtension` Functions:**

* **`quit()`:** Terminates the fuzzer execution.
* **`compileAndRunWithOrigin(contextGroupId, source, originName, originLine, originColumn, isWasm)`:** Compiles and runs a JavaScript or WebAssembly string within a specific context group, allowing the fuzzer to execute arbitrary code.
* **`schedulePauseOnNextStatement(contextGroupId, reason, detail)`:**  Schedules a debugger pause on the next JavaScript statement in a specific context.
* **`cancelPauseOnNextStatement(contextGroupId)`:** Cancels a previously scheduled debugger pause.
* **`createContextGroup()`:** Creates a new V8 context group.
* **`resetContextGroup(contextGroupId)`:** Resets a specific context group.
* **`connectSession(contextGroupId, state, messageCallback, isFullyTrusted)`:** Simulates connecting an Inspector session to a context group.
* **`disconnectSession(sessionId)`:** Simulates disconnecting an Inspector session.
* **`sendMessageToBackend(sessionId, message)`:** Sends a raw Inspector protocol message to the backend.

**`InspectorExtension` Functions:**

* **`fireContextCreated()`:** Simulates the creation of a new JavaScript context, notifying the Inspector.
* **`fireContextDestroyed()`:** Simulates the destruction of a JavaScript context.
* **`freeContext()`:** Explicitly frees a JavaScript context.
* **`addInspectedObject(objectId, object)`:** Adds an object to the Inspector's list of inspected objects.
* **`setMaxAsyncTaskStacks(max)`:** Sets the maximum number of asynchronous task stack traces the Inspector should retain.
* **`breakProgram(reason, detail)`:** Triggers a debugger breakpoint.
* **`createObjectWithStrictCheck()`:** Creates an object with a strict access check, useful for testing Inspector access control.
* **`callWithScheduledBreak(func, reason, detail)`:** Calls a function after scheduling a breakpoint.
* **`markObjectAsNotInspectable(object)`:** Marks an object as not inspectable by the Inspector.
* **`createObjectWithNativeDataProperty(name, withSetter)`:** Creates an object with a native data property (with or without a setter), useful for testing Inspector handling of native properties.
* **`storeCurrentStackTrace(description)`:** Stores the current stack trace with a given description.
* **`externalAsyncTaskStarted(stackTraceId)`:** Notifies the Inspector that an external asynchronous task has started.
* **`externalAsyncTaskFinished(stackTraceId)`:** Notifies the Inspector that an external asynchronous task has finished.
* **`scheduleWithAsyncStack(func, taskName, withEmptyStack)`:** Schedules a task to be executed asynchronously, capturing the current stack or an empty stack.
* **`setAllowCodeGenerationFromStrings(allow)`:** Controls whether code generation from strings is allowed in the current context.
* **`setResourceNamePrefix(prefix)`:** Sets a prefix for resource names reported by the Inspector.

**Is it a Torque file?**

No, `v8/test/fuzzer/inspector-fuzzer.cc` ends with `.cc`, which signifies a **C++ source file**, not a Torque file (which would end in `.tq`).

**Relationship with JavaScript and Examples:**

This file heavily relates to JavaScript as it's designed to fuzz the V8 Inspector, which is a debugging and profiling tool for JavaScript execution within V8. The exposed functions are directly callable from JavaScript within the fuzzer's environment.

Here are some JavaScript examples of how these functions might be used in a fuzzer input:

```javascript
// Example using utils extension
utils.quit();

utils.compileAndRunWithOrigin(0, 'console.log("Hello from fuzzer!");', 'fuzzer.js', 1, 1, false);

utils.schedulePauseOnNextStatement(0, 'Fuzzer Break', 'Testing breakpoint');

utils.createContextGroup();

// Example using inspector extension
inspector.fireContextCreated();

inspector.breakProgram('Fuzzer Break', 'Intentional breakpoint from fuzzer');

let obj = inspector.createObjectWithStrictCheck();
try {
  obj.someProperty; // This would trigger the strict access check
} catch (e) {}

function asyncTask() {
  console.log("Async task running");
  inspector.externalAsyncTaskFinished(stackIdBuffer);
}

let stackIdBuffer = inspector.storeCurrentStackTrace("Before async task");
inspector.externalAsyncTaskStarted(stackIdBuffer);
setTimeout(asyncTask, 100);
```

**Code Logic Inference with Hypothetical Input and Output:**

Let's consider the `CompileAndRunWithOrigin` function.

**Hypothetical Input (within the fuzzer's data):**

The fuzzer might generate data that, when interpreted as a JavaScript string to be executed, looks like this:

```javascript
utils.compileAndRunWithOrigin(0, 'let a = 10; let b = a * 2; console.log(b);', 'test.js', 1, 1, false);
```

**Assumptions:**

* A context group with ID `0` exists.
* The V8 isolate is running correctly.

**Expected Output:**

* The JavaScript code `'let a = 10; let b = a * 2; console.log(b);'` would be compiled and executed within the context group `0`.
* The `console.log(b)` statement would print `20` to the console output of the V8 isolate running the backend.

**User Common Programming Errors and Examples:**

Fuzzers often expose APIs that, if used incorrectly, can lead to errors. Here are some common programming errors a user writing a fuzzer using these APIs might make:

* **Incorrect Argument Types:**
  ```javascript
  // Error: Passing a number as the contextGroupId string
  utils.compileAndRunWithOrigin("0", 'console.log("Error");', 'err.js', 1, 1, false);
  ```
  The `compileAndRunWithOrigin` function expects an integer for `contextGroupId`, but a string is provided. This would likely cause an error or unexpected behavior in the C++ code.

* **Invalid Context Group ID:**
  ```javascript
  // Error: Trying to use a non-existent context group
  utils.schedulePauseOnNextStatement(999, 'Break', 'Invalid context');
  ```
  If a context group with ID `999` hasn't been created, this call would likely fail or have no effect.

* **Malformed Inspector Messages:**
  ```javascript
  // Error: Sending an invalid JSON string as an Inspector message
  utils.sendMessageToBackend(0, '{"invalid":}');
  ```
  The `sendMessageToBackend` function expects a valid JSON string conforming to the Inspector protocol. Providing malformed JSON will likely cause parsing errors on the backend.

* **Forgetting to Connect a Session:**
  ```javascript
  // Error: Trying to send a message without an active session
  utils.sendMessageToBackend(0, '{"method": "Debugger.pause"}');
  ```
  If an Inspector session hasn't been established using `connectSession` with the corresponding `sessionId`, sending messages might fail.

* **Mixing up Context Groups:**
  ```javascript
  // Error: Creating a session in one group and trying to execute code in another
  let groupId1 = utils.createContextGroup();
  let groupId2 = utils.createContextGroup();
  utils.connectSession(groupId1, '', function(msg) { console.log(msg); });
  utils.compileAndRunWithOrigin(groupId2, 'debugger;', 'debug.js', 1, 1, false);
  ```
  The debugger might not pause as expected if the session and the code execution are happening in different context groups.

In summary, `v8/test/fuzzer/inspector-fuzzer.cc` is a crucial component for testing the robustness and reliability of the V8 Inspector by programmatically generating and executing various scenarios and inputs. It exposes a rich set of C++ functions accessible from JavaScript to control the fuzzer's environment and interact deeply with the Inspector's functionalities.

### 提示词
```
这是目录为v8/test/fuzzer/inspector-fuzzer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/fuzzer/inspector-fuzzer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```