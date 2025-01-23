Response:
Let's break down the thought process for analyzing this `session.cc` file.

1. **Understand the Goal:** The request asks for the functionality of this specific file, its relation to reverse engineering, its interaction with low-level details, any logical reasoning within, common user errors, and how users might reach this code.

2. **Initial Scan for Keywords and Structure:** Quickly skim the code looking for:
    * Class names (`Session`, `Operation`, `Script`, etc.)
    * Method names (`Detach`, `Resume`, `CreateScript`, etc.)
    * Namespaces (`frida`)
    * Include statements (`#include`)
    * Data types from external libraries (e.g., `GBytes`, `FridaSession`, `Local<Object>`)
    * Macros (`SESSION_DATA_CONSTRUCTOR`)
    * Comments (though there aren't many here)

3. **Identify the Core Class:** The central class is `Session`. The file is named `session.cc`, and most of the functions are methods of this class. This suggests the file is primarily responsible for managing Frida sessions.

4. **Analyze Class Members and Constructor:**
    * The constructor takes a `FridaSession* handle` and a `Runtime* runtime`. This indicates that a `Session` object wraps a lower-level Frida session and interacts with a runtime environment.
    * The destructor unrefs the `handle_`, suggesting resource management.

5. **Examine `Init` Function:** This static function is crucial for understanding how the `Session` class is exposed to JavaScript.
    * It creates a V8 template for the `Session` object.
    * It defines accessors (getters) for properties like `isDetached`, `persistTimeout`, and `pid`.
    * It sets up prototype methods like `detach`, `resume`, `createScript`, etc. These are the JavaScript methods that users will call.
    * It stores the constructor function in the `runtime` for later use.

6. **Analyze Public Methods (JavaScript-facing):** Go through each `NAN_METHOD` (Node.js Native Abstraction for methods) and infer its purpose based on its name and the Frida C API calls it makes. For example:
    * `Detach`: Calls `frida_session_detach`.
    * `Resume`: Calls `frida_session_resume`.
    * `CreateScript`: Calls `frida_session_create_script`.
    * `CompileScript`: Calls `frida_session_compile_script`.
    * And so on.

7. **Identify Underlying Frida C API Usage:** Notice the consistent pattern of calling functions prefixed with `frida_session_`. This points to the file's role as a bridge between the Node.js world and the core Frida library. Understanding the purpose of these Frida C API functions is key to understanding the functionality.

8. **Look for `Operation` Classes:** The code uses a pattern with nested `Operation` classes. These likely encapsulate the asynchronous nature of many Frida operations. Analyze the `Begin` and `End` methods within these classes to see the underlying Frida C API calls and their "finish" counterparts.

9. **Analyze Helper Functions:**  Functions like `ParseScriptOptions` and `ParseSnapshotOptions` are used to process arguments passed from JavaScript and convert them into the data structures expected by the Frida C API.

10. **Connect to Reverse Engineering Concepts:** Consider how the exposed methods relate to common reverse engineering tasks:
    * Attaching to a process (`Session` creation implies this).
    * Detaching from a process (`Detach`).
    * Injecting code (`CreateScript`, `CreateScriptFromBytes`).
    * Manipulating process state (`Resume`).
    * Intercepting function calls (implicitly through scripts).

11. **Identify Binary/Low-Level Interactions:** Look for:
    * Usage of `GBytes` (GLib's byte array) which represents raw binary data.
    * Handling of buffers (`node::Buffer`).
    * Interactions with process IDs (`pid`).
    * Concepts like snapshots and compiled scripts, which deal with binary representations of code.

12. **Consider Linux/Android Kernel and Framework Aspects:**  Frida operates at this level. While this specific file doesn't directly interact with kernel code, its functions enable actions that *do* interact with the kernel (e.g., injecting code, receiving signals about process crashes). The `enableChildGating` and `disableChildGating` methods directly relate to process creation, a kernel-level concern.

13. **Logical Reasoning:** Look for conditional statements and data transformations. The parsing functions involve logical checks on the types of arguments provided.

14. **User Errors:** Think about how a user might misuse the API:
    * Passing the wrong type of argument (string instead of buffer, etc.).
    * Providing incorrect parameters (missing required arguments).
    * Calling methods in an inappropriate order.

15. **Trace User Operations (Debugging Clues):**  Imagine a developer using the Frida Node.js API. How would they end up calling these methods?  Start with attaching to a process, then consider creating and running scripts, detaching, etc. The `Init` function and the constructor are the entry points for the `Session` object's lifecycle.

16. **Structure the Answer:** Organize the findings into the requested categories: functionality, reverse engineering relevance, low-level details, logical reasoning, user errors, and debugging. Provide concrete examples for each point.

17. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any logical gaps or areas where more detail could be added. For instance, explicitly mentioning the asynchronous nature of the operations is important.

This structured approach, combining code analysis with an understanding of Frida's purpose and common programming practices, allows for a comprehensive explanation of the `session.cc` file.This is the source code for the `Session` class in the Frida Node.js binding. Let's break down its functionality based on your request:

**Functionality of `session.cc`:**

This file defines the JavaScript interface for interacting with a Frida session. A Frida session represents a connection to a target process or device that Frida is instrumenting. The `Session` class provides methods to:

* **Manage the Session Lifecycle:**
    * **Creation:**  The constructor (`Session::Session`) is called when a new session object is created in JavaScript, usually after attaching to a process or device.
    * **Detachment:** The `Detach` method allows the user to disconnect Frida from the target process.
    * **Resuming:** The `Resume` method allows the user to resume the execution of a process after it has been paused by Frida.
* **Control Child Process Gating:**
    * **`enableChildGating`:**  This method enables Frida to intercept and control the creation of new child processes by the target application.
    * **`disableChildGating`:** This method disables the interception of child process creation.
* **Work with Scripts:**
    * **`createScript`:**  Allows the user to inject and execute a JavaScript script within the target process.
    * **`createScriptFromBytes`:** Similar to `createScript`, but takes pre-compiled bytecode as input.
    * **`compileScript`:**  Compiles a JavaScript script into bytecode without immediately executing it.
    * **`snapshotScript`:**  Creates a snapshot of a script, potentially including its state, for faster future execution.
* **Establish Peer-to-Peer Connections:**
    * **`setupPeerConnection`:**  Facilitates setting up a peer-to-peer connection, likely for inter-process communication or remote control scenarios.
* **Join Portals:**
    * **`joinPortal`:**  Allows the Frida session to join a Frida Portal, which is a mechanism for secure, remote access and collaboration.
* **Provide Session Information:**
    * **`isDetached` (property):**  Indicates whether the session is currently detached.
    * **`persistTimeout` (property):**  Provides the timeout for session persistence.
    * **`pid` (property):**  Returns the process ID of the target process.
* **Signal Handling:** The code sets up signal handling (`Signals::New`) to receive events from the Frida core, such as when the session is detached.

**Relationship to Reverse Engineering:**

This file is **deeply connected** to reverse engineering methods. Here are some examples:

* **Dynamic Analysis:** Frida is a dynamic instrumentation tool. This entire `session.cc` file is about enabling dynamic analysis. By creating a session and injecting scripts, reverse engineers can observe and manipulate the behavior of a running program in real-time.
    * **Example:** A reverse engineer might use `createScript` to inject a script that hooks a specific function in the target process. This allows them to examine the function's arguments, return value, and side effects as the program executes.
* **Code Injection:** The `createScript` and `createScriptFromBytes` methods are direct implementations of code injection techniques. Reverse engineers use these to insert their own logic into the target process.
    * **Example:**  A reverse engineer could inject a script to bypass authentication checks by modifying the return value of a login function.
* **API Hooking:**  While not explicitly implemented in this file, the ability to inject scripts allows reverse engineers to perform API hooking. They can intercept calls to system libraries or application-specific functions to understand their usage and potentially modify their behavior.
    * **Example:** A reverse engineer could hook the `open` system call to track which files a program is accessing.
* **Process Monitoring and Control:** Methods like `resume`, `enableChildGating`, and `disableChildGating` provide control over the target process's execution and child process creation, which are essential for debugging and understanding program flow.
    * **Example:** By enabling child gating, a reverse engineer can inspect the arguments passed to `fork` or `execve` and potentially prevent malicious child processes from being created.
* **Memory Inspection and Manipulation (Indirectly):** Although not directly in this file, the injected scripts have access to the target process's memory, allowing reverse engineers to inspect and modify data structures, variables, and even code.

**Involvement of Binary 底层, Linux, Android 内核及框架 Knowledge:**

This file bridges the gap between high-level JavaScript and the lower levels of the operating system. Here's how:

* **Binary 底层 (Binary Underpinnings):**
    * **`GBytes`:** This GLib object is used to represent raw byte arrays. Methods like `createScriptFromBytes`, `compileScript`, and `snapshotScript` directly deal with binary data representing compiled code or snapshots of memory. This requires understanding of executable formats and potentially virtual machine bytecode.
    * **Memory Layout:** While not directly manipulating memory in this file, the very concept of injecting scripts implies understanding how code and data are organized in the target process's memory.
* **Linux/Android Kernel:**
    * **Process Management:**  The `pid` property and methods like `detach`, `resume`, `enableChildGating`, and `disableChildGating` directly interact with operating system primitives for managing processes. On Linux and Android, these operations ultimately involve system calls to the kernel.
    * **Child Process Creation:** The child gating feature is tightly linked to how the kernel handles the `fork`, `execve`, and related system calls. Frida intercepts these calls at a low level.
    * **Signals:** The signal handling mechanism (`Signals::New`) deals with operating system signals, which are a fundamental way for the kernel to communicate events to processes (e.g., process termination, crashes). The `TransformSignal` function specifically handles the "detached" signal, potentially providing crash information.
* **Framework (Likely Android):**
    * While not explicitly stated as Android-specific in this code, Frida is heavily used in Android reverse engineering. The concepts of process attachment, code injection, and the ability to intercept function calls are crucial for analyzing Android applications and frameworks. The peer connection and portal features might be used in more complex, distributed instrumentation scenarios, potentially involving Android devices.

**Logical Reasoning (Assumptions and Outputs):**

The code employs logical reasoning primarily in argument validation and in the asynchronous operation handling.

* **Assumption:** When `CreateScript` is called, the `source_value` should be a JavaScript string containing the script to be injected.
    * **Input:** `info[0]` (the first argument) is a JavaScript string like `"console.log('Hello from Frida!');"`
    * **Output:** The `g_strdup(*val)` function will create a C-style string containing the same content. If the input is not a string, `g_strdup` might return `NULL`, leading to an error.
* **Assumption:** When `CreateScriptFromBytes` is called, the `bytes_value` should be a Node.js Buffer containing the compiled script bytecode.
    * **Input:** `info[0]` is a Node.js Buffer object containing bytecode.
    * **Output:** `g_bytes_new` will create a `GBytes` object from the buffer's data. If the input is not a Buffer, `node::Buffer::HasInstance` will return `false`, leading to an error.
* **Asynchronous Operations:** The `Operation` template class encapsulates the logic for performing asynchronous operations. It assumes that Frida's C API provides asynchronous functions (ending with `_async`) and corresponding finish functions (ending with `_finish`).
    * **Input:** A call to a method like `Detach`.
    * **Output:** The `DetachOperation` will initiate the asynchronous detach process using `frida_session_detach_async`. When the operation completes (either successfully or with an error), the `OnReady` callback will be invoked, and the `End` method (`frida_session_detach_finish`) will process the result. A Promise is returned to the JavaScript side to handle the eventual outcome.

**User and Programming Common Usage Errors:**

This file includes checks to prevent common user errors:

* **Incorrect Argument Types:**
    * **Example:** Calling `createScript` with a number instead of a string for the script source will trigger the `Nan::ThrowTypeError("Bad argument, 'source' must be a string");` error.
    * **Example:** Calling `createScriptFromBytes` with a string instead of a Buffer for the bytecode will trigger `Nan::ThrowTypeError("Bad argument, 'bytes' must be a Buffer");`.
* **Missing Arguments:**
    * **Example:** Calling `createScript` with fewer than 4 arguments will trigger `Nan::ThrowTypeError("Missing one or more arguments");`.
* **Incorrect Usage of `new` Keyword:**
    * The constructor (`Session::New`) checks if it's called with `new`. Calling it as a regular function will result in `Nan::ThrowError("Use the \`new\` keyword to create a new instance");`.
* **Passing Raw Handles Directly (Generally):** While the constructor *does* expect an external handle, this is an internal detail. Users shouldn't be manually creating `FridaSession` handles and passing them around. The Frida API should manage this.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user interacting with the Frida Node.js API would reach this code through the following general steps:

1. **Install the `frida` Node.js module:** `npm install frida` or `yarn add frida`.
2. **Import the `frida` module in their JavaScript code:** `const frida = require('frida');`.
3. **Attach to a target process:**
   * Using `frida.attach(processNameOrPid)` or `frida.getDevice('local').attach(processNameOrPid)`. This operation, typically implemented in other parts of the Frida Node.js binding (not this specific file), would eventually create a `FridaSession` object in the underlying Frida core library.
4. **Receive a `Session` object:** The `attach` operation returns a Promise that resolves with a `Session` object. This is where the `Session::New` constructor in this file is invoked (via the `SESSION_DATA_CONSTRUCTOR`).
5. **Call methods on the `Session` object:** The user would then call methods defined in this `session.cc` file, such as:
   * `session.createScript(scriptSource, options)` to inject a script.
   * `session.detach()` to disconnect from the target.
   * `session.resume()` to continue process execution.
   * `session.enableChildGating()` to intercept child process creation.

**As a debugging线索 (debugging clue):** If a user encounters an error related to Frida sessions, the stack trace or error message might point to functions within this `session.cc` file. For instance:

* **`TypeError: Bad argument, 'source' must be a string`:**  Indicates the user passed the wrong type of argument to `createScript`.
* **`Error: Use the \`new\` keyword to create a new instance`:**  Indicates incorrect instantiation of the `Session` object (though users typically don't create these directly).
* **Unhandled Promise Rejection:** If an asynchronous operation within this file (like `detach` or `createScript`) fails in the underlying Frida core, the returned Promise will be rejected. Examining the rejection reason can provide clues about the failure.

In summary, `session.cc` is a critical component of the Frida Node.js binding, responsible for exposing the core functionality of Frida sessions to JavaScript users, enabling a wide range of dynamic analysis and reverse engineering tasks. It interacts with low-level operating system concepts and performs logical validation to prevent common user errors.

### 提示词
```
这是目录为frida/subprojects/frida-node/src/session.cc的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "session.h"

#include "crash.h"
#include "operation.h"
#include "portal_membership.h"
#include "relay.h"
#include "script.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define SESSION_DATA_CONSTRUCTOR "session:ctor"

using std::strcmp;
using v8::Array;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Uint32;
using v8::Value;

namespace frida {

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> snapshot_value, Local<Value> runtime_value);
static FridaSnapshotOptions* ParseSnapshotOptions(
    Local<Value> warmup_script_value, Local<Value> runtime_value);
static void UnrefGBytes(char* data, void* hint);

Session::Session(FridaSession* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Session::~Session() {
  frida_unref(handle_);
}

void Session::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Session").ToLocalChecked();
  auto tpl = CreateTemplate(name, Session::New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isDetached").ToLocalChecked(),
      IsDetached, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("persistTimeout").ToLocalChecked(),
      GetPersistTimeout, 0, data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("pid").ToLocalChecked(), GetPid, 0,
      data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "detach", Detach);
  Nan::SetPrototypeMethod(tpl, "resume", Resume);
  Nan::SetPrototypeMethod(tpl, "enableChildGating", EnableChildGating);
  Nan::SetPrototypeMethod(tpl, "disableChildGating", DisableChildGating);
  Nan::SetPrototypeMethod(tpl, "createScript", CreateScript);
  Nan::SetPrototypeMethod(tpl, "createScriptFromBytes", CreateScriptFromBytes);
  Nan::SetPrototypeMethod(tpl, "compileScript", CompileScript);
  Nan::SetPrototypeMethod(tpl, "snapshotScript", SnapshotScript);
  Nan::SetPrototypeMethod(tpl, "setupPeerConnection", SetupPeerConnection);
  Nan::SetPrototypeMethod(tpl, "joinPortal", JoinPortal);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SESSION_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Session::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
    *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SESSION_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Session::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaSession*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Session(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime, TransformSignal, runtime));

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Session::GetPid) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(Nan::New<Uint32>(
      frida_session_get_pid(handle)));
}

NAN_PROPERTY_GETTER(Session::GetPersistTimeout) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(Nan::New<Uint32>(
      frida_session_get_persist_timeout(handle)));
}

NAN_PROPERTY_GETTER(Session::IsDetached) {
  auto handle = ObjectWrap::Unwrap<Session>(
      info.Holder())->GetHandle<FridaSession>();

  info.GetReturnValue().Set(
      Nan::New(static_cast<bool>(frida_session_is_detached(handle))));
}

namespace {

class DetachOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_detach(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_detach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::Detach) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new DetachOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class ResumeOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_resume(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_resume_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::Resume) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new ResumeOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnableChildGatingOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_enable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_enable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::EnableChildGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new EnableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableChildGatingOperation : public Operation<FridaSession> {
 protected:
  void Begin() {
    frida_session_disable_child_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_disable_child_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Session::DisableChildGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  auto operation = new DisableChildGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptOperation : public Operation<FridaSession> {
 public:
  CreateScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CreateScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

 protected:
  void Begin() {
    frida_session_create_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

 private:
  gchar* source_;
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}


NAN_METHOD(Session::CreateScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto snapshot_value = info[2];
  auto runtime_value = info[3];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, snapshot_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CreateScriptFromBytesOperation : public Operation<FridaSession> {
 public:
  CreateScriptFromBytesOperation(GBytes* bytes, FridaScriptOptions* options)
    : bytes_(bytes),
      options_(options) {
  }

  ~CreateScriptFromBytesOperation() {
    g_object_unref(options_);
    g_bytes_unref(bytes_);
  }

 protected:
  void Begin() {
    frida_session_create_script_from_bytes(handle_, bytes_, options_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    script_ = frida_session_create_script_from_bytes_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Script::New(script_, runtime_);
    g_object_unref(script_);
    return wrapper;
  }

 private:
  GBytes* bytes_;
  FridaScriptOptions* options_;
  FridaScript* script_;
};

}

NAN_METHOD(Session::CreateScriptFromBytes) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto bytes_value = info[0];
  auto name_value = info[1];
  auto snapshot_value = info[2];
  auto runtime_value = info[3];

  bool valid = true;

  GBytes* bytes = NULL;
  if (node::Buffer::HasInstance(bytes_value)) {
    bytes = g_bytes_new(node::Buffer::Data(bytes_value),
        node::Buffer::Length(bytes_value));
  } else {
    Nan::ThrowTypeError("Bad argument, 'bytes' must be a Buffer");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, snapshot_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_bytes_unref(bytes);
    g_clear_object(&options);
    return;
  }

  auto operation = new CreateScriptFromBytesOperation(bytes, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class CompileScriptOperation : public Operation<FridaSession> {
 public:
  CompileScriptOperation(gchar* source, FridaScriptOptions* options)
    : source_(source),
      options_(options) {
  }

  ~CompileScriptOperation() {
    g_object_unref(options_);
    g_free(source_);
  }

 protected:
  void Begin() {
    frida_session_compile_script(handle_, source_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_compile_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

 private:
  gchar* source_;
  FridaScriptOptions* options_;
  GBytes* bytes_;
};

}

NAN_METHOD(Session::CompileScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto source_value = info[0];
  auto name_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* source;
  Nan::Utf8String val(source_value);
  source = g_strdup(*val);
  if (source == NULL) {
    Nan::ThrowTypeError("Bad argument, 'source' must be a string");
    valid = false;
  }

  FridaScriptOptions* options = NULL;
  if (valid) {
    options = ParseScriptOptions(name_value, Nan::Null(), runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(source);
    g_clear_object(&options);
    return;
  }

  auto operation = new CompileScriptOperation(source, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static FridaScriptOptions* ParseScriptOptions(Local<Value> name_value,
    Local<Value> snapshot_value, Local<Value> runtime_value) {
  auto options = frida_script_options_new();
  bool valid = true;

  if (!name_value->IsNull()) {
    Nan::Utf8String val(name_value);
    const gchar* name = *val;
    if (name != NULL) {
      frida_script_options_set_name(options, name);
    } else {
      Nan::ThrowTypeError("Bad argument, 'name' must be a string");
      valid = false;
    }
  }

  if (valid && !snapshot_value->IsNull()) {
    if (node::Buffer::HasInstance(snapshot_value)) {
      auto snapshot = g_bytes_new(node::Buffer::Data(snapshot_value),
          node::Buffer::Length(snapshot_value));
      frida_script_options_set_snapshot(options, snapshot);
      g_bytes_unref(snapshot);
    } else {
      Nan::ThrowTypeError("Bad argument, 'snapshot' must be a Buffer");
      valid = false;
    }
  }

  if (valid && !runtime_value->IsNull()) {
    FridaScriptRuntime runtime;
    valid = Runtime::ValueToEnum(runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME,
        &runtime);
    if (valid) {
      frida_script_options_set_runtime(options, runtime);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return NULL;
  }

  return options;
}

namespace {

class SnapshotScriptOperation : public Operation<FridaSession> {
 public:
  SnapshotScriptOperation(gchar* embed_script, FridaSnapshotOptions* options)
    : embed_script_(embed_script),
      options_(options) {
  }

  ~SnapshotScriptOperation() {
    g_object_unref(options_);
    g_free(embed_script_);
  }

 protected:
  void Begin() {
    frida_session_snapshot_script(handle_, embed_script_, options_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    bytes_ = frida_session_snapshot_script_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    gsize size;
    auto data = g_bytes_get_data(bytes_, &size);
    return Nan::NewBuffer(static_cast<char*>(const_cast<void*>(data)), size,
        UnrefGBytes, bytes_).ToLocalChecked();
  }

 private:
  gchar* embed_script_;
  FridaSnapshotOptions* options_;
  GBytes* bytes_;
};

}

NAN_METHOD(Session::SnapshotScript) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto embed_script_value = info[0];
  auto warmup_script_value = info[1];
  auto runtime_value = info[2];

  bool valid = true;

  gchar* embed_script;
  Nan::Utf8String val(embed_script_value);
  embed_script = g_strdup(*val);
  if (embed_script == NULL) {
    Nan::ThrowTypeError("Bad argument, 'embedScript' must be a string");
    valid = false;
  }

  FridaSnapshotOptions* options = NULL;
  if (valid) {
    options = ParseSnapshotOptions(warmup_script_value, runtime_value);
    valid = options != NULL;
  }

  if (!valid) {
    g_free(embed_script);
    g_clear_object(&options);
    return;
  }

  auto operation = new SnapshotScriptOperation(embed_script, options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

static FridaSnapshotOptions* ParseSnapshotOptions(
    Local<Value> warmup_script_value, Local<Value> runtime_value) {
  auto options = frida_snapshot_options_new();
  bool valid = true;

  if (!warmup_script_value->IsNull()) {
    Nan::Utf8String val(warmup_script_value);
    const gchar* warmup_script = *val;
    if (warmup_script != NULL) {
      frida_snapshot_options_set_warmup_script(options, warmup_script);
    } else {
      Nan::ThrowTypeError("Bad argument, 'warmupScript' must be a string");
      valid = false;
    }
  }

  if (valid && !runtime_value->IsNull()) {
    FridaScriptRuntime runtime;
    valid = Runtime::ValueToEnum(runtime_value, FRIDA_TYPE_SCRIPT_RUNTIME,
        &runtime);
    if (valid) {
      frida_snapshot_options_set_runtime(options, runtime);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return NULL;
  }

  return options;
}

namespace {

class SetupPeerConnectionOperation : public Operation<FridaSession> {
 public:
  SetupPeerConnectionOperation(FridaPeerOptions* options) : options_(options) {
  }

  ~SetupPeerConnectionOperation() {
    g_object_unref(options_);
  }

 protected:
  void Begin() {
    frida_session_setup_peer_connection(handle_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_session_setup_peer_connection_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  FridaPeerOptions* options_;
};

}

NAN_METHOD(Session::SetupPeerConnection) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto stun_server_value = info[0];
  auto relays_value = info[1];

  auto options = frida_peer_options_new();
  bool valid = true;

  if (!stun_server_value->IsNull()) {
    if (stun_server_value->IsString()) {
      Nan::Utf8String stun_server(stun_server_value);
      frida_peer_options_set_stun_server(options, *stun_server);
    } else {
      Nan::ThrowTypeError("Bad argument, 'stunServer' must be a string");
      valid = false;
    }
  }

  if (valid) {
    if (relays_value->IsArray()) {
      auto array = Local<Array>::Cast(relays_value);

      uint32_t n = array->Length();

      for (uint32_t i = 0; i != n; i++) {
        auto element_value = Nan::Get(array, i).ToLocalChecked();
        FridaRelay* relay = Relay::TryParse(element_value, wrapper->runtime_);
        if (relay == NULL) {
          Nan::ThrowTypeError("Bad argument, 'relays' element type mismatch");
          valid = false;
          break;
        }
        frida_peer_options_add_relay(options, relay);
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'relays' must be an array");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new SetupPeerConnectionOperation(options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class JoinPortalOperation : public Operation<FridaSession> {
 public:
  JoinPortalOperation(gchar* address, FridaPortalOptions* options)
    : address_(address),
      options_(options) {
  }

  ~JoinPortalOperation() {
    g_object_unref(options_);
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_session_join_portal(handle_, address_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    membership_ = frida_session_join_portal_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = PortalMembership::New(membership_, runtime_);
    g_object_unref(membership_);
    return wrapper;
  }

 private:
  gchar* address_;
  FridaPortalOptions* options_;
  FridaPortalMembership* membership_;
};

}

NAN_METHOD(Session::JoinPortal) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Session>(info.Holder());

  if (info.Length() < 4) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto address_value = info[0];
  auto certificate_value = info[1];
  auto token_value = info[2];
  auto acl_value = info[3];

  if (!address_value->IsString()) {
    Nan::ThrowTypeError("Bad argument, 'address' must be a string");
    return;
  }
  Nan::Utf8String address(address_value);

  auto options = frida_portal_options_new();
  bool valid = true;

  if (!certificate_value->IsNull()) {
    GTlsCertificate* certificate;
    valid = Runtime::ValueToCertificate(certificate_value, &certificate);
    if (valid) {
      frida_portal_options_set_certificate(options, certificate);
      g_object_unref(certificate);
    }
  }

  if (valid && !token_value->IsNull()) {
    if (token_value->IsString()) {
      Nan::Utf8String token(token_value);
      frida_portal_options_set_token(options, *token);
    } else {
      Nan::ThrowTypeError("Bad argument, 'token' must be a string");
      valid = false;
    }
  }

  if (valid && !acl_value->IsNull()) {
    gchar** acl;
    gint acl_length;
    valid = Runtime::ValueToEnvp(acl_value, &acl, &acl_length);
    if (valid) {
      frida_portal_options_set_acl(options, acl, acl_length);
      g_strfreev(acl);
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new JoinPortalOperation(g_strdup(*address), options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Session::TransformSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);

  if (index == 1 && strcmp(name, "detached") == 0) {
    auto crash = g_value_get_object(value);
    if (crash == NULL)
      return Nan::Null();
    return Crash::New(crash, runtime);
  }

  return Local<Value>();
}

static void UnrefGBytes(char* data, void* hint) {
  g_bytes_unref(static_cast<GBytes*>(hint));
}

}
```