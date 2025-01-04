Response:
Let's break down the thought process for analyzing this `script.cc` file. The goal is to extract functionality, relate it to reverse engineering, identify low-level interactions, understand its logic, and point out potential user errors and debugging paths.

**1. Initial Skim and Overall Purpose:**

The first step is to quickly read through the code, paying attention to class names, method names, and included headers. Keywords like `Script`, `load`, `unload`, `post`, `enableDebugger`, `disableDebugger`, and includes like `frida.h` and `node::Buffer` immediately suggest this file is part of Frida and handles the execution and management of scripts injected into target processes. The `node::` prefix points to interaction with Node.js.

**2. Deconstructing the Core Class: `Script`:**

* **Constructor/Destructor (`Script::Script`, `Script::~Script`):**  The constructor takes a `FridaScript*` and a `Runtime*`. The destructor calls `frida_unref`. This indicates the `Script` class wraps a Frida-specific `FridaScript` object and manages its lifecycle. The `g_object_ref` and `frida_unref` point to GLib object management, common in Frida's C core.

* **Initialization (`Script::Init`):** This method is crucial for understanding how the `Script` class is exposed to JavaScript. It uses Nan (Native Abstractions for Node.js) to create a JavaScript class named "Script" and define its prototype methods (`load`, `unload`, etc.). The `SCRIPT_DATA_CONSTRUCTOR` hints at a pattern for creating new `Script` objects from the native side.

* **Static Factory (`Script::New`):** There are *two* `Script::New` methods. The first one (taking `gpointer handle, Runtime*`) is a static factory to create native `Script` objects. The second one (taking `NAN_METHOD_ARGS_INFO`) is the JavaScript constructor. This separation is typical in Node.js native addons.

* **Instance Methods:** Each of the `NAN_METHOD` functions (`Load`, `Unload`, `Eternalize`, `Post`, `EnableDebugger`, `DisableDebugger`) corresponds to a JavaScript method callable on `Script` instances. Their implementations involve calling Frida C API functions (e.g., `frida_script_load`, `frida_script_post`). The use of `Operation` templates suggests an asynchronous pattern.

* **Signals:** The `Signals::New` call and `TransformMessageSignal` function suggest a mechanism for receiving events from the injected script.

**3. Identifying Functionality and Reverse Engineering Relevance:**

For each method, consider its purpose in a reverse engineering context:

* **`load`:**  Essential for injecting and starting a script. Directly related to code injection, a core RE technique.
* **`unload`:**  Removing the injected script. Useful for cleanup or when dynamic analysis is complete.
* **`eternalize`:**  Making the script persistent, even if the application tries to unload it. Powerful for persistent hooks or monitoring.
* **`post`:**  Sending messages from the Frida script back to the controlling application. Crucial for communication and reporting results.
* **`enableDebugger`, `disableDebugger`:**  Enabling/disabling debugging of the injected script, allowing deeper inspection and control flow analysis.

**4. Pinpointing Low-Level Interactions:**

Look for interactions with operating system primitives, kernel concepts, and Frida's core:

* **Includes:**  `<cstring>`, and the Frida headers themselves (`script.h`, `operation.h`, `signals.h`, `usage_monitor.h`) indicate low-level C/C++ operations.
* **GLib:**  The use of `GObject`, `GBytes`, `GAsyncResult`, `GCancellable` points to Frida's reliance on the GLib library, which provides cross-platform system-level abstractions.
* **Asynchronous Operations:** The `Operation` template and the `_async` suffixes in Frida C API functions (e.g., `frida_script_load_async`) highlight asynchronous behavior, common in systems programming for non-blocking operations.
* **`node::Buffer`:** Interaction with Node.js buffers in the `Post` method reveals how binary data is transferred between the script and the controller.
* **Kernel/Framework (Implicit):**  While not explicitly coded here, the actions of loading, unloading, and debugging scripts *necessarily* involve interacting with the target process's memory space, potentially using system calls or platform-specific APIs (e.g., `ptrace` on Linux, debugging APIs on Windows/Android). Frida handles these complexities, but the `script.cc` acts as a bridge.

**5. Analyzing Logic and Potential Inputs/Outputs:**

For methods with non-trivial logic (even if it mostly calls into Frida's C API), think about what inputs are expected and what the expected outcome is:

* **`Load`:** Input: None (implicitly the script code is already associated with the `FridaScript` object). Output: A Promise that resolves when the script is loaded.
* **`Post`:** Input: A JavaScript value (the message) and an optional Node.js Buffer (the data). Output: None (the message is sent asynchronously).
* **`EnableDebugger`:** Input: A port number. Output: A Promise that resolves when the debugger is enabled.

**6. Identifying Potential User Errors:**

Examine the code for explicit error checking and think about common mistakes:

* **`Script::New` (JavaScript constructor):** Expects to be called with `new` and a raw handle. Forgetting `new` or passing the wrong argument type will throw an error.
* **`Post`:**  Requires at least two arguments (message and potentially data). The data, if provided, must be a Node.js Buffer.
* **`EnableDebugger`:**  Requires a numeric port argument within the valid range (0-65535).

**7. Tracing User Actions to the Code:**

Think about the typical Frida workflow:

1. **User writes a Frida script (JavaScript).**
2. **User uses the Frida API (likely via Node.js) to connect to a target process.**
3. **User calls a method to create a `Script` object, often passing the script code.** This part is handled by other Frida components. The `Script::New` in `script.cc` is called internally by Frida's core when a new script is created.
4. **User calls `script.load()`.** This is where the `NAN_METHOD(Script::Load)` function in `script.cc` gets invoked.
5. **User might call `script.post()`, `script.enableDebugger()`, etc.** These correspond to the respective `NAN_METHOD` functions.

By following these steps systematically, we can dissect the code and answer the prompt's questions effectively. The key is to combine code reading with knowledge of Frida's architecture, Node.js native addons, and general systems programming concepts.
好的，让我们来分析一下 `frida/subprojects/frida-node/src/script.cc` 这个文件，它是 Frida Dynamic Instrumentation 工具中负责脚本管理的源代码文件。

**文件功能概览:**

这个 `script.cc` 文件的主要职责是封装 Frida C 核心库提供的脚本功能，并将其暴露给 Node.js 环境使用。它定义了一个名为 `Script` 的 C++ 类，这个类是对 Frida C API 中 `FridaScript` 对象的封装。通过这个类，Node.js 可以创建、加载、卸载、持久化、发送消息以及控制脚本的调试功能。

具体来说，`script.cc` 实现了以下功能：

1. **脚本的创建和销毁:**  `Script` 类的构造函数接收一个 `FridaScript` 的句柄，并持有它。析构函数负责释放这个句柄。
2. **脚本的加载和卸载:** 提供了 `load` 和 `unload` 方法，分别对应 Frida C API 中的 `frida_script_load` 和 `frida_script_unload` 函数，用于将脚本加载到目标进程并执行或将其卸载。
3. **脚本的持久化:** `eternalize` 方法对应 `frida_script_eternalize`，用于使脚本在某些情况下（例如目标进程尝试卸载时）仍然保持运行状态。
4. **脚本间通信:** `post` 方法允许从 Frida 控制端（Node.js）向注入到目标进程中的脚本发送消息。
5. **脚本调试:**  `enableDebugger` 和 `disableDebugger` 方法用于启用和禁用注入脚本的调试功能，允许使用调试器连接到脚本的运行环境。
6. **信号处理:**  监听来自 Frida C 核心的信号（例如 "message" 信号），并将这些信号转换成 Node.js 事件。

**与逆向方法的关联及举例:**

Frida 本身就是一个强大的动态逆向工具，而 `script.cc` 中定义的功能直接支持各种逆向分析方法：

* **代码注入与执行:** `load` 方法是代码注入的核心。逆向工程师编写 JavaScript 代码（Frida 脚本）来 hook 目标进程的函数、修改内存数据、追踪函数调用等。`load` 方法将这些脚本注入到目标进程并开始执行。
    * **例子:**  逆向工程师想要跟踪某个函数 `evil_function` 的调用，可以编写如下 Frida 脚本：
      ```javascript
      Interceptor.attach(Module.findExportByName(null, "evil_function"), {
        onEnter: function(args) {
          console.log("evil_function called with args: " + args);
        }
      });
      ```
      然后通过 Node.js 调用 `script.load()` 将此脚本注入目标进程。

* **动态 hook 和修改:**  注入的脚本可以利用 Frida 提供的 API（例如 `Interceptor.attach`）动态地 hook 目标进程的函数，并在函数执行前后执行自定义的 JavaScript 代码，从而修改函数的行为或记录函数的参数和返回值。
    * **例子:**  逆向工程师想要绕过一个简单的密码校验，可以 hook 校验函数，并强制其返回 true。

* **内存数据的读取和修改:**  Frida 脚本可以使用 `Memory` API 读取和修改目标进程的内存数据。这对于分析数据结构、查找敏感信息或者进行漏洞利用非常有用。
    * **例子:**  逆向工程师想要查看某个全局变量的值，可以使用 `Memory.read*` 函数读取其内存地址的内容。

* **函数调用跟踪:**  通过 hook 函数的入口和出口，逆向工程师可以跟踪函数的调用链，理解程序的执行流程。

* **通信和交互:** `post` 方法允许注入的脚本将信息发送回控制端。这使得逆向工程师可以在脚本中收集信息，并在控制端进行分析和展示。
    * **例子:**  注入的脚本可以 hook 网络请求函数，并将请求的 URL 和数据通过 `send()` 函数发送回 Node.js 控制端。

* **调试:** `enableDebugger` 方法允许使用 JavaScript 调试器（例如 Chrome DevTools）连接到注入的脚本，进行断点调试、单步执行等，更深入地理解脚本的运行情况。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

`script.cc` 本身是对 Frida C API 的封装，而 Frida C API 底层涉及大量的二进制操作、操作系统内核和框架知识：

* **进程内存管理:**  加载和卸载脚本涉及到在目标进程的内存空间中分配、写入和释放内存。这需要理解操作系统如何管理进程内存（例如 Linux 的 `mmap`、`munmap` 等系统调用）。
* **动态链接和符号解析:**  Hook 函数通常需要查找目标函数的地址，这涉及到动态链接器如何加载共享库以及如何解析符号。Frida 内部使用了类似 `dlopen`、`dlsym` 的机制。
* **指令集架构:**  Frida 需要理解目标进程的指令集架构（例如 ARM、x86），才能正确地进行代码注入和 hook 操作。
* **操作系统 API:**  Frida 的 hook 机制可能涉及到操作系统提供的调试 API（例如 Linux 的 `ptrace`），或者平台特定的 API。
* **Android 运行时 (ART) 和 Dalvik:**  在 Android 环境下，Frida 需要与 ART 或 Dalvik 虚拟机交互，进行方法 hook 和内存操作。这需要理解 Android 的运行时机制和内部结构。
    * **例子:**  在 Android 逆向中，经常需要 hook Java 层的方法。Frida 能够通过 ART/Dalvik 的 API 实现这一点，例如使用 `Java.use` 和 `method.implementation` 来 hook Java 方法。

* **Linux 内核知识:**  Frida 的一些高级功能，例如内核模块注入或者内核 hook，需要深入理解 Linux 内核的结构和机制。

**逻辑推理、假设输入与输出:**

`script.cc` 中的逻辑主要集中在调用 Frida C API 并处理异步操作。让我们以 `Load` 方法为例：

* **假设输入:**  当用户在 Node.js 中调用 `script.load()` 时，没有显式的输入参数传递到 `NAN_METHOD(Script::Load)` 函数中，因为脚本的代码是在创建 `Script` 对象时就已经关联的。
* **逻辑推理:**
    1. `NAN_METHOD(Script::Load)` 获取到 `Script` 对象的 C++ 包装器。
    2. 创建一个 `LoadOperation` 对象，这是一个用于执行异步操作的辅助类。
    3. 调用 `operation->Schedule(isolate, wrapper, info)`，将加载操作调度到 Frida 的异步执行队列中。
    4. `LoadOperation::Begin()` 方法最终会调用 `frida_script_load(handle_, cancellable_, OnReady, this)`。
    5. Frida C 核心会异步地加载脚本到目标进程。
    6. 当加载完成时，Frida C 核心会调用 `OnReady` 回调函数。
    7. `OnReady` 回调会调用 `LoadOperation::End()`，完成异步操作的处理。
    8. `NAN_METHOD(Script::Load)` 返回一个 Promise 对象，该 Promise 会在脚本加载完成后 resolve。
* **假设输出:**  `script.load()` 方法返回一个 Promise。如果脚本加载成功，Promise 会 resolve 为 `undefined`。如果加载失败，Promise 会 reject 并带有错误信息。

**用户或编程常见的使用错误及举例:**

1. **忘记调用 `load()` 方法:**  创建 `Script` 对象后，脚本代码并不会立即执行，需要显式调用 `load()` 方法。
   ```javascript
   const session = await frida.attach('...');
   const source = 'console.log("Hello from Frida!");';
   const script = await session.createScript(source);
   // 错误：忘记调用 script.load()
   // script.load();
   ```

2. **在 `post()` 方法中传递错误的参数类型:** `post()` 方法期望第一个参数是消息内容（可以转换为 JSON 的 JavaScript 值），第二个参数是可选的二进制数据 (Node.js `Buffer`)。传递错误的类型会导致错误。
   ```javascript
   // 正确
   script.post({ type: 'log', message: 'Something happened' });
   script.post({ type: 'data' }, Buffer.from([0x01, 0x02]));

   // 错误
   script.post('message', 'not a buffer'); // 第二个参数应该是 Buffer
   ```

3. **在 `enableDebugger()` 中传递无效的端口号:**  端口号必须是 0 到 65535 之间的整数。
   ```javascript
   // 正确
   script.enableDebugger(9229);

   // 错误
   script.enableDebugger(-1);
   script.enableDebugger(65536);
   script.enableDebugger('not a number');
   ```

4. **尝试在脚本卸载后调用其方法:**  一旦脚本被卸载 (`unload()` 被调用)，就不能再对其调用 `post()` 等方法。
   ```javascript
   const session = await frida.attach('...');
   const script = await session.createScript('...');
   await script.load();
   await script.unload();
   // 错误：脚本已卸载
   script.post('message');
   ```

**用户操作如何一步步到达这里，作为调试线索:**

当开发者在使用 Frida 进行逆向分析时，他们通常会执行以下步骤，最终会触发 `script.cc` 中的代码：

1. **编写 Frida 脚本 (JavaScript):**  这是逆向工程师进行动态分析的核心。脚本定义了要 hook 的函数、要修改的内存、以及要发送回控制端的信息。
2. **使用 Frida API 连接到目标进程:**  开发者使用 Frida 提供的 Node.js API (例如 `frida.attach()`) 连接到目标进程。
   ```javascript
   const frida = require('frida');
   async function main() {
     const session = await frida.attach('com.example.app'); // 连接到 Android 应用
     // 或者
     const session = await frida.spawn('/path/to/executable'); // 启动并连接到进程
     // ... 后续步骤
   }
   main();
   ```
3. **创建脚本对象:**  一旦连接成功，开发者会使用 `session.createScript()` 方法创建一个脚本对象。这个方法在 Frida 的 Node.js 绑定层会将脚本代码传递到 Frida C 核心，并最终创建一个 `FridaScript` 对象，然后通过 `script.cc` 中的 `Script::New` 方法封装成一个 JavaScript 的 `Script` 对象。
   ```javascript
   const source = 'console.log("Hello from Frida!");';
   const script = await session.createScript(source); // 这里会调用 Script::New
   ```
4. **加载脚本:**  调用 `script.load()` 方法，这会触发 `script.cc` 中的 `NAN_METHOD(Script::Load)` 函数，将脚本注入到目标进程并执行。
   ```javascript
   await script.load(); // 触发 NAN_METHOD(Script::Load)
   ```
5. **与脚本交互 (可选):**  开发者可能会使用 `script.post()` 从控制端向脚本发送消息，或者在脚本中使用 `send()` 将消息发送回控制端。
   ```javascript
   script.post({ command: 'doSomething' }); // 触发 NAN_METHOD(Script::Post)
   ```
6. **控制脚本调试 (可选):**  开发者可以使用 `script.enableDebugger()` 启用脚本的调试功能。
   ```javascript
   await script.enableDebugger(9229); // 触发 NAN_METHOD(Script::EnableDebugger)
   ```
7. **卸载脚本 (可选):**  分析完成后，开发者可能会调用 `script.unload()` 来卸载脚本。
   ```javascript
   await script.unload(); // 触发 NAN_METHOD(Script::Unload)
   ```

**调试线索:**

当开发者在使用 Frida 遇到问题时，理解 `script.cc` 的功能可以帮助他们更好地进行调试：

* **脚本加载失败:** 如果 `script.load()` 返回 rejected 的 Promise，错误信息通常会指示加载失败的原因。可以检查脚本代码是否有语法错误，或者目标进程的环境是否阻止了脚本的加载。
* **`post()` 方法不起作用:** 检查 `post()` 方法的参数类型是否正确，以及注入的脚本中是否有对应的消息处理逻辑。
* **调试器连接失败:** 检查 `enableDebugger()` 中指定的端口是否可用，以及调试器配置是否正确。
* **脚本行为异常:** 可以通过 `enableDebugger()` 连接到脚本进行断点调试，查看脚本的执行流程和变量状态。

总而言之，`script.cc` 是 Frida Node.js 绑定的核心组件之一，它桥接了 Frida C 核心的脚本管理功能和 Node.js 环境，使得开发者可以使用 JavaScript 方便地进行动态逆向分析。理解其功能和工作原理对于有效地使用 Frida 和解决相关问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/src/script.cc的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "script.h"

#include "operation.h"
#include "signals.h"
#include "usage_monitor.h"

#include <cstring>

#define SCRIPT_DATA_CONSTRUCTOR "script:ctor"

using std::strcmp;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Value;

namespace frida {

Script::Script(FridaScript* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Script::~Script() {
  frida_unref(handle_);
}

void Script::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Script").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isDestroyed").ToLocalChecked(),
      IsDestroyed, 0, data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "load", Load);
  Nan::SetPrototypeMethod(tpl, "unload", Unload);
  Nan::SetPrototypeMethod(tpl, "eternalize", Eternalize);
  Nan::SetPrototypeMethod(tpl, "post", Post);
  Nan::SetPrototypeMethod(tpl, "enableDebugger", EnableDebugger);
  Nan::SetPrototypeMethod(tpl, "disableDebugger", DisableDebugger);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(SCRIPT_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Script::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(SCRIPT_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Script::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaScript*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Script(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  Nan::Set(obj, Nan::New("signals").ToLocalChecked(),
      Signals::New(handle, runtime, TransformMessageSignal, runtime));

  auto monitor =
      new UsageMonitor<FridaScript>(frida_script_is_destroyed, "destroyed");
  monitor->Enable(wrapper);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Script::IsDestroyed) {
  auto handle = ObjectWrap::Unwrap<Script>(
      info.Holder())->GetHandle<FridaScript>();

  info.GetReturnValue().Set(
      Nan::New(static_cast<bool>(frida_script_is_destroyed(handle))));
}

namespace {

class LoadOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_load(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_load_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Load) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new LoadOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class UnloadOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_unload(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_unload_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Unload) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new UnloadOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EternalizeOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_eternalize(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_eternalize_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::Eternalize) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new EternalizeOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

NAN_METHOD(Script::Post) {
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto num_args = info.Length();
  if (num_args < 2) {
    Nan::ThrowTypeError("Expected message and data");
    return;
  }

  Nan::Utf8String message(wrapper->runtime_->ValueToJson(info[0]));

  GBytes* data = NULL;
  auto buffer = info[1];
  if (!buffer->IsNull()) {
    if (!node::Buffer::HasInstance(buffer)) {
      Nan::ThrowTypeError("Expected a buffer");
      return;
    }
    data = g_bytes_new(node::Buffer::Data(buffer),
        node::Buffer::Length(buffer));
  }

  frida_script_post(wrapper->GetHandle<FridaScript>(), *message, data);

  g_bytes_unref(data);
}

namespace {

class EnableDebuggerOperation : public Operation<FridaScript> {
 public:
  EnableDebuggerOperation(guint16 port) : port_(port) {
  }

 protected:
  void Begin() {
    frida_script_enable_debugger(handle_, port_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_enable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  guint16 port_;
};

}

NAN_METHOD(Script::EnableDebugger) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected port number");
    return;
  }
  auto port = Nan::To<int32_t>(info[0]).FromMaybe(-1);
  if (port < 0 || port >= 65536) {
    Nan::ThrowTypeError("Bad argument, expected port number");
    return;
  }

  auto operation = new EnableDebuggerOperation(static_cast<guint16>(port));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableDebuggerOperation : public Operation<FridaScript> {
 protected:
  void Begin() {
    frida_script_disable_debugger(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_script_disable_debugger_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Script::DisableDebugger) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Script>(info.Holder());

  auto operation = new DisableDebuggerOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

Local<Value> Script::TransformMessageSignal(const gchar* name, guint index,
    const GValue* value, gpointer user_data) {
  if (index != 0 || strcmp(name, "message") != 0)
    return Local<Value>();
  auto runtime = static_cast<Runtime*>(user_data);
  auto json = Nan::New(g_value_get_string(value)).ToLocalChecked();
  return runtime->ValueFromJson(json);
}

}

"""

```