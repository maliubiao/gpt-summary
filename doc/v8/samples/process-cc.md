Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Initial Scan and Objective Identification:**

The first step is a quick scan to understand the general structure and purpose. I look for keywords and patterns that indicate the code's role. Immediately, the `v8::` namespace jumps out, confirming this is V8-related code. The filenames `process.cc` and the presence of `HttpRequest`, `HttpRequestProcessor`, and `JsHttpRequestProcessor` suggest this code deals with processing HTTP requests. The "scriptable using JavaScript" comment further clarifies the goal: to integrate JavaScript with HTTP request processing.

**2. Identifying Key Classes and Their Relationships:**

I start identifying the main classes and their relationships. This helps build a mental model of the code's architecture.

*   `HttpRequest`:  A simple class representing an HTTP request. It's an interface (abstract class).
*   `HttpRequestProcessor`: An abstract base class for processing requests. It has `Initialize` and `Process` methods.
*   `JsHttpRequestProcessor`:  Crucially, this class *inherits* from `HttpRequestProcessor`. This tells me it's a specialized processor, and the name strongly suggests JavaScript is involved.

**3. Focusing on the Core Functionality of `JsHttpRequestProcessor`:**

Since the request mentions JavaScript interaction, I focus on `JsHttpRequestProcessor`. I examine its methods:

*   Constructor: Takes an `Isolate*` and a JavaScript `String`. This indicates it's associated with a specific V8 isolate and script.
*   `Initialize`:  This is likely where the JavaScript environment is set up. I see it creates a V8 context, installs global functions (like `log`), makes `options` and `output` maps available to JavaScript, and executes the provided script.
*   `Process`: This method takes an `HttpRequest*`, wraps it in a JavaScript object, and then calls a JavaScript function named "Process". This confirms the core interaction point.
*   `ExecuteScript`: Compiles and runs the provided JavaScript code within the V8 context.
*   `InstallMaps`: Makes the C++ `std::map` objects accessible as JavaScript objects.
*   `MakeRequestTemplate`, `MakeMapTemplate`: These methods seem responsible for creating object templates that represent C++ objects in JavaScript. The `Get...` and `MapGet`/`MapSet` functions are clearly accessors and setters for these templates.
*   `WrapMap`, `UnwrapMap`, `WrapRequest`, `UnwrapRequest`: These utility functions are vital for bridging the gap between C++ and JavaScript objects. They likely involve V8's external data mechanism.

**4. Analyzing JavaScript Integration Points:**

I look for how the C++ code interacts with JavaScript:

*   Passing C++ data to JavaScript: The `InstallMaps` method and the `WrapRequest` function are key. The use of `External::New` is a strong indicator of how C++ data is made available within the V8 environment.
*   Calling JavaScript functions from C++: The `Process` method of `JsHttpRequestProcessor` does this by fetching the "Process" function from the global object and calling it.
*   Calling C++ functions from JavaScript: The `LogCallback` function demonstrates this. It's registered as a global function named "log" in the JavaScript environment.

**5. Inferring the Purpose and Workflow:**

Based on the analysis so far, I can deduce the primary function:  The `process.cc` file provides a way to process HTTP requests using a user-defined JavaScript script. The C++ code sets up the V8 environment, exposes the request data to the script, executes the script, and then potentially acts upon the results.

**6. Addressing Specific Questions in the Prompt:**

Now, I go through each question in the prompt:

*   **Functionality:** Summarize the deduced purpose.
*   **.tq extension:** Explain that `.tq` signifies Torque code (a lower-level V8 language) and that `process.cc` is C++.
*   **JavaScript Relationship and Example:**  Illustrate the interaction using a simple JavaScript example that accesses the `request` object's properties and potentially the `options` and `output` maps.
*   **Code Logic Inference (Hypothetical Input/Output):**  Create a plausible scenario with example HTTP request data and a simple JavaScript script to show how data flows and how the script might modify the `output` map.
*   **Common Programming Errors:**  Consider typical issues when integrating C++ and JavaScript using V8, such as incorrect handle usage, type mismatches, and errors in the JavaScript code itself.

**7. Refining and Structuring the Answer:**

Finally, I organize my findings into a clear and concise answer, addressing each point in the prompt directly. I use clear language and provide examples to illustrate the concepts. I pay attention to terminology (e.g., "Isolate," "Context," "HandleScope").

**Self-Correction/Refinement During the Process:**

*   Initially, I might have overlooked the `InstallMaps` function and focused only on the request object. However, closer inspection reveals the `options` and `output` maps and their importance in the interaction.
*   I might have initially assumed that the JavaScript `Process` function *returns* a value that influences the C++ code. While possible, the provided code doesn't explicitly show that. I stick to what the code demonstrably does.
*   I consider the target audience and try to explain V8-specific concepts in a way that's understandable even without deep V8 knowledge.

By following these steps, I can systematically analyze the provided C++ code and address all the points raised in the prompt, resulting in a comprehensive and accurate explanation.
`v8/samples/process.cc` 是一个 V8 引擎的示例代码，它展示了如何在 C++ 应用程序中嵌入 V8 引擎，并允许通过 JavaScript 脚本处理特定的任务，在这个例子中，是处理 HTTP 请求。

**功能列举:**

1. **嵌入 V8 引擎:**  代码包含了必要的 V8 头文件，如 `v8-isolate.h`, `v8-context.h`, `v8-script.h` 等，表明它正在使用 V8 引擎的功能。
2. **定义 HTTP 请求和处理器抽象:** 它定义了 `HttpRequest` 接口和 `HttpRequestProcessor` 抽象类，用于模拟处理 HTTP 请求的场景。
3. **实现基于 JavaScript 的 HTTP 请求处理器 (`JsHttpRequestProcessor`):**  这是一个关键的类，它继承自 `HttpRequestProcessor`，并允许使用 JavaScript 代码来处理 HTTP 请求。
4. **加载和执行 JavaScript 代码:** `JsHttpRequestProcessor` 可以加载一个 JavaScript 脚本，并在 V8 引擎中编译和执行它。
5. **将 C++ 对象暴露给 JavaScript:**  代码使用了 V8 的 API（如 `ObjectTemplate`, `SetInternalField`, `SetNativeDataProperty`）来将 C++ 的 `HttpRequest` 对象和 `std::map` 类型的 `options` 和 `output` 对象包装成 JavaScript 对象，从而可以在 JavaScript 代码中访问和操作这些 C++ 对象的数据。
6. **从 JavaScript 调用 C++ 函数:**  通过 `FunctionTemplate::New` 创建了一个名为 "log" 的全局 JavaScript 函数，它实际上调用了 C++ 的 `HttpRequestProcessor::Log` 函数。
7. **在 JavaScript 中处理请求:**  JavaScript 代码可以通过访问包装后的 `request` 对象（`HttpRequest` 实例）的属性（如 `path`, `referrer`, `host`, `userAgent`）来获取请求信息。
8. **JavaScript 修改 C++ 数据:**  通过将 C++ 的 `std::map` 包装成 JavaScript 对象，JavaScript 代码可以读取和修改 `options` 和 `output` 这两个映射的内容。
9. **示例主函数 (`main`)**:  `main` 函数演示了如何初始化 V8 引擎，加载 JavaScript 文件，创建 `JsHttpRequestProcessor` 实例，并使用一些模拟的 HTTP 请求来测试处理流程。

**关于 `.tq` 结尾:**

如果 `v8/samples/process.cc` 以 `.tq` 结尾，那么它的确是一个 **V8 Torque 源代码**。Torque 是 V8 用来定义内置函数和运行时函数的领域特定语言。 然而，根据您提供的代码内容，这个文件明显是 C++ 源代码 (`.cc`)。

**与 JavaScript 的关系及示例:**

`v8/samples/process.cc` 的核心功能就是 **将 JavaScript 代码集成到 C++ HTTP 请求处理流程中**。

**JavaScript 示例:**

假设 `process.cc` 加载了一个名为 `process_request.js` 的 JavaScript 文件，其内容可能如下：

```javascript
// process_request.js

// 可以访问 C++ 传递过来的 options 对象
log("Options received: " + JSON.stringify(options));

// 可以访问 C++ 包装的 request 对象
log("Processing request for path: " + request.path);
log("User Agent: " + request.userAgent);

// 可以访问和修改 C++ 传递过来的 output 对象
output.processed_path = request.path;
output.user_agent_type = (request.userAgent.includes("firefox")) ? "Firefox" : "Other";

// 定义处理逻辑的函数，C++ 代码会调用这个函数
function Process(request) {
  log("JavaScript Process function called for path: " + request.path);
  if (request.path === "/special") {
    output.special_request_handled = true;
    return true; // 返回值会被 C++ 代码忽略，但可以用于复杂的交互
  }
  return true;
}
```

**解释:**

*   `log(...)`:  调用了 C++ 中注册的 `LogCallback` 函数，会将消息打印到控制台。
*   `options`:  一个 JavaScript 对象，其内容映射了 C++ 中 `JsHttpRequestProcessor::Initialize` 函数传入的 `options` map。
*   `request`: 一个 JavaScript 对象，包装了 C++ 的 `HttpRequest` 实例。可以通过属性访问请求的各种信息。
*   `output`: 一个 JavaScript 对象，其内容映射了 C++ 中 `JsHttpRequestProcessor::Initialize` 函数传入的 `output` map。JavaScript 代码可以修改这个对象，这些修改会反映到 C++ 的 `output` map 中。
*   `Process(request)`:  这是 C++ 代码 (`JsHttpRequestProcessor::Process`) 会调用的 JavaScript 函数。它接收包装后的 `request` 对象作为参数，并可以执行自定义的请求处理逻辑。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**

*   **C++ 代码配置:**
    *   加载的 JavaScript 文件内容如上面的 `process_request.js` 所示。
    *   `options` map 在 C++ 中初始化为 `{"debug": "true", "timeout": "10"}`。
*   **JavaScript 执行前的 `output` map:** 空。
*   **处理的 `HttpRequest` 对象:**  一个 `StringHttpRequest` 实例，其属性为：
    *   `Path()` 返回 "/api/users"
    *   `Referrer()` 返回 "https://example.com"
    *   `Host()` 返回 "api.myservice.com"
    *   `UserAgent()` 返回 "Chrome/100.0.4896.75"

**推理过程:**

1. C++ 代码创建 `JsHttpRequestProcessor` 并加载 `process_request.js`。
2. `JsHttpRequestProcessor::Initialize` 被调用，创建 V8 上下文，将 `options` 和 `output` 包装成 JavaScript 对象，并在全局作用域中命名为 `options` 和 `output`。
3. `process_request.js` 被执行：
    *   `log` 函数会被调用，将 `options` 的 JSON 表示打印到控制台。
    *   创建 `StringHttpRequest` 实例，并被包装成 JavaScript 的 `request` 对象。
    *   `log` 函数会被调用，打印 `request.path` 和 `request.userAgent`。
    *   `output.processed_path` 被设置为 "/api/users"。
    *   `output.user_agent_type` 被设置为 "Other" (因为 UserAgent 不包含 "firefox")。
4. `JsHttpRequestProcessor::Process` 被调用，将 `StringHttpRequest` 实例包装成 `request` 对象，并调用 JavaScript 的 `Process` 函数。
5. JavaScript 的 `Process` 函数被执行：
    *   `log` 函数会被调用，打印 "JavaScript Process function called for path: /api/users"。
    *   由于 `request.path` 不是 "/special"，函数返回 `true`。

**预期输出:**

*   **控制台输出 (来自 `HttpRequestProcessor::Log`):**
    ```
    Logged: {"debug":"true","timeout":"10"}
    Logged: Processing request for path: /api/users
    Logged: User Agent: Chrome/100.0.4896.75
    Logged: JavaScript Process function called for path: /api/users
    ```
*   **C++ 代码中 `output` map 的最终状态:**
    ```
    {
      "processed_path": "/api/users",
      "user_agent_type": "Other"
    }
    ```

**用户常见的编程错误举例:**

1. **忘记初始化 V8 引擎:**  在使用 V8 API 之前，必须调用 `v8::V8::InitializePlatform` 和 `v8::V8::Initialize`。忘记初始化会导致程序崩溃或未定义的行为。

    ```c++
    // 错误示例：忘记初始化
    int main() {
      v8::Isolate::CreateParams create_params;
      create_params.array_buffer_allocator = v8::ArrayBuffer::Allocator::NewDefaultAllocator();
      v8::Isolate* isolate = v8::Isolate::New(create_params);
      // ... 使用 isolate，但 V8 引擎本身没有被初始化
    }
    ```

2. **不正确地管理 V8 的 HandleScope:**  V8 使用 HandleScope 来管理对象的生命周期。如果 HandleScope 使用不当，可能会导致内存泄漏或访问已释放的内存。

    ```c++
    v8::Local<v8::String> CreateString(v8::Isolate* isolate, const char* str) {
      // 错误示例：在 HandleScope 之外返回 Local
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::String> result = v8::String::NewFromUtf8(isolate, str).ToLocalChecked();
      return result; // result 指向的内存可能在 handle_scope 结束时被释放
    }
    ```

3. **在错误的上下文中操作 V8 对象:**  V8 对象与特定的 Context 关联。尝试在一个 Context 中创建的对象在另一个 Context 中使用会导致错误。

    ```c++
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Local<v8::Context> context1 = v8::Context::New(isolate);
    v8::Local<v8::Context> context2 = v8::Context::New(isolate);

    {
      v8::Context::Scope scope1(context1);
      v8::Local<v8::String> str = v8::String::NewFromUtf8Literal(isolate, "hello");
      // ...
    }

    {
      v8::Context::Scope scope2(context2);
      // 错误示例：尝试在 context2 中使用 context1 中创建的 str
      // context2->Global()->Set(context2, v8::String::NewFromUtf8Literal(isolate, "message"), str);
    }
    ```

4. **类型不匹配导致 V8 异常:**  当 JavaScript 代码尝试访问 C++ 对象中不存在的属性或以错误的方式操作属性时，V8 会抛出异常。C++ 代码需要适当地处理这些异常。

    ```javascript
    // 假设 C++ 的 HttpRequest 对象没有 'size' 属性
    log("Request size: " + request.size); // 会导致 JavaScript 错误
    ```

5. **忘记处理 JavaScript 异常:**  在 C++ 中调用 JavaScript 代码时，JavaScript 代码可能会抛出异常。C++ 代码应该使用 `v8::TryCatch` 来捕获和处理这些异常，否则程序可能会崩溃。

    ```c++
    v8::TryCatch try_catch(isolate);
    if (!script->Run(context).ToLocal(&result)) {
      v8::String::Utf8Value error(isolate, try_catch.Exception());
      HttpRequestProcessor::Log(*error);
      // ... 处理错误 ...
    }
    ```

6. **不正确地包装和解包 C++ 对象:**  将 C++ 对象暴露给 JavaScript 需要使用 `v8::External` 和 `SetInternalField`。如果包装或解包的逻辑不正确，会导致 JavaScript 代码无法正确访问 C++ 对象的数据。

    ```c++
    // 错误示例：忘记设置 InternalFieldCount
    v8::Local<v8::ObjectTemplate> MakeRequestTemplate(v8::Isolate* isolate) {
      v8::Local<v8::ObjectTemplate> result = v8::ObjectTemplate::New(isolate);
      // 忘记设置 result->SetInternalFieldCount(1);
      // ...
      return result;
    }
    ```

理解这些常见的错误可以帮助开发者更有效地使用 V8 引擎，并避免在 C++ 和 JavaScript 集成时遇到问题。

Prompt: 
```
这是目录为v8/samples/process.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/samples/process.cc以.tq结尾，那它是个v8 torque源代码，
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

#include <stdlib.h>
#include <string.h>

#include <map>
#include <string>

#include "include/libplatform/libplatform.h"
#include "include/v8-array-buffer.h"
#include "include/v8-context.h"
#include "include/v8-exception.h"
#include "include/v8-external.h"
#include "include/v8-function.h"
#include "include/v8-initialization.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-persistent-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "include/v8-snapshot.h"
#include "include/v8-template.h"
#include "include/v8-value.h"

using std::map;
using std::pair;
using std::string;

using v8::Context;
using v8::EscapableHandleScope;
using v8::External;
using v8::Function;
using v8::FunctionTemplate;
using v8::Global;
using v8::HandleScope;
using v8::Isolate;
using v8::Local;
using v8::MaybeLocal;
using v8::Name;
using v8::NamedPropertyHandlerConfiguration;
using v8::NewStringType;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyCallbackInfo;
using v8::Script;
using v8::String;
using v8::TryCatch;
using v8::Value;

// These interfaces represent an existing request processing interface.
// The idea is to imagine a real application that uses these interfaces
// and then add scripting capabilities that allow you to interact with
// the objects through JavaScript.

/**
 * A simplified http request.
 */
class HttpRequest {
 public:
  virtual ~HttpRequest() { }
  virtual const string& Path() = 0;
  virtual const string& Referrer() = 0;
  virtual const string& Host() = 0;
  virtual const string& UserAgent() = 0;
};


/**
 * The abstract superclass of http request processors.
 */
class HttpRequestProcessor {
 public:
  virtual ~HttpRequestProcessor() { }

  // Initialize this processor.  The map contains options that control
  // how requests should be processed.
  virtual bool Initialize(map<string, string>* options,
                          map<string, string>* output) = 0;

  // Process a single request.
  virtual bool Process(HttpRequest* req) = 0;

  static void Log(const char* event);
};


/**
 * An http request processor that is scriptable using JavaScript.
 */
class JsHttpRequestProcessor : public HttpRequestProcessor {
 public:
  // Creates a new processor that processes requests by invoking the
  // Process function of the JavaScript script given as an argument.
  JsHttpRequestProcessor(Isolate* isolate, Local<String> script)
      : isolate_(isolate), script_(script) {}
  virtual ~JsHttpRequestProcessor();

  virtual bool Initialize(map<string, string>* opts,
                          map<string, string>* output);
  virtual bool Process(HttpRequest* req);

 private:
  // Execute the script associated with this processor and extract the
  // Process function.  Returns true if this succeeded, otherwise false.
  bool ExecuteScript(Local<String> script);

  // Wrap the options and output map in a JavaScript objects and
  // install it in the global namespace as 'options' and 'output'.
  bool InstallMaps(map<string, string>* opts, map<string, string>* output);

  // Constructs the template that describes the JavaScript wrapper
  // type for requests.
  static Local<ObjectTemplate> MakeRequestTemplate(Isolate* isolate);
  static Local<ObjectTemplate> MakeMapTemplate(Isolate* isolate);

  // Callbacks that access the individual fields of request objects.
  static void GetPath(Local<Name> name,
                      const PropertyCallbackInfo<Value>& info);
  static void GetReferrer(Local<Name> name,
                          const PropertyCallbackInfo<Value>& info);
  static void GetHost(Local<Name> name,
                      const PropertyCallbackInfo<Value>& info);
  static void GetUserAgent(Local<Name> name,
                           const PropertyCallbackInfo<Value>& info);

  // Callbacks that access maps
  static v8::Intercepted MapGet(Local<Name> name,
                                const PropertyCallbackInfo<Value>& info);
  static v8::Intercepted MapSet(Local<Name> name, Local<Value> value,
                                const PropertyCallbackInfo<void>& info);

  // Utility methods for wrapping C++ objects as JavaScript objects,
  // and going back again.
  Local<Object> WrapMap(map<string, string>* obj);
  static map<string, string>* UnwrapMap(Local<Object> obj);
  Local<Object> WrapRequest(HttpRequest* obj);
  static HttpRequest* UnwrapRequest(Local<Object> obj);

  Isolate* GetIsolate() { return isolate_; }

  Isolate* isolate_;
  Local<String> script_;
  Global<Context> context_;
  Global<Function> process_;
  static Global<ObjectTemplate> request_template_;
  static Global<ObjectTemplate> map_template_;
};


// -------------------------
// --- P r o c e s s o r ---
// -------------------------

static void LogCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 1) return;
  Isolate* isolate = info.GetIsolate();
  HandleScope scope(isolate);
  Local<Value> arg = info[0];
  String::Utf8Value value(isolate, arg);
  HttpRequestProcessor::Log(*value);
}

// Execute the script and fetch the Process method.
bool JsHttpRequestProcessor::Initialize(map<string, string>* opts,
                                        map<string, string>* output) {
  // Create a handle scope to hold the temporary references.
  HandleScope handle_scope(GetIsolate());

  // Create a template for the global object where we set the
  // built-in global functions.
  Local<ObjectTemplate> global = ObjectTemplate::New(GetIsolate());
  global->Set(GetIsolate(), "log",
              FunctionTemplate::New(GetIsolate(), LogCallback));

  // Each processor gets its own context so different processors don't
  // affect each other. Context::New returns a persistent handle which
  // is what we need for the reference to remain after we return from
  // this method. That persistent handle has to be disposed in the
  // destructor.
  v8::Local<v8::Context> context = Context::New(GetIsolate(), NULL, global);
  context_.Reset(GetIsolate(), context);

  // Enter the new context so all the following operations take place
  // within it.
  Context::Scope context_scope(context);

  // Make the options mapping available within the context
  if (!InstallMaps(opts, output))
    return false;

  // Compile and run the script
  if (!ExecuteScript(script_))
    return false;

  // The script compiled and ran correctly.  Now we fetch out the
  // Process function from the global object.
  Local<String> process_name =
      String::NewFromUtf8Literal(GetIsolate(), "Process");
  Local<Value> process_val;
  // If there is no Process function, or if it is not a function,
  // bail out
  if (!context->Global()->Get(context, process_name).ToLocal(&process_val) ||
      !process_val->IsFunction()) {
    return false;
  }

  // It is a function; cast it to a Function
  Local<Function> process_fun = process_val.As<Function>();

  // Store the function in a Global handle, since we also want
  // that to remain after this call returns
  process_.Reset(GetIsolate(), process_fun);

  // All done; all went well
  return true;
}


bool JsHttpRequestProcessor::ExecuteScript(Local<String> script) {
  HandleScope handle_scope(GetIsolate());

  // We're just about to compile the script; set up an error handler to
  // catch any exceptions the script might throw.
  TryCatch try_catch(GetIsolate());

  Local<Context> context(GetIsolate()->GetCurrentContext());

  // Compile the script and check for errors.
  Local<Script> compiled_script;
  if (!Script::Compile(context, script).ToLocal(&compiled_script)) {
    String::Utf8Value error(GetIsolate(), try_catch.Exception());
    Log(*error);
    // The script failed to compile; bail out.
    return false;
  }

  // Run the script!
  Local<Value> result;
  if (!compiled_script->Run(context).ToLocal(&result)) {
    // The TryCatch above is still in effect and will have caught the error.
    String::Utf8Value error(GetIsolate(), try_catch.Exception());
    Log(*error);
    // Running the script failed; bail out.
    return false;
  }

  return true;
}


bool JsHttpRequestProcessor::InstallMaps(map<string, string>* opts,
                                         map<string, string>* output) {
  HandleScope handle_scope(GetIsolate());

  // Wrap the map object in a JavaScript wrapper
  Local<Object> opts_obj = WrapMap(opts);

  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(GetIsolate(), context_);

  // Set the options object as a property on the global object.
  context->Global()
      ->Set(context, String::NewFromUtf8Literal(GetIsolate(), "options"),
            opts_obj)
      .FromJust();

  Local<Object> output_obj = WrapMap(output);
  context->Global()
      ->Set(context, String::NewFromUtf8Literal(GetIsolate(), "output"),
            output_obj)
      .FromJust();

  return true;
}


bool JsHttpRequestProcessor::Process(HttpRequest* request) {
  // Create a handle scope to keep the temporary object references.
  HandleScope handle_scope(GetIsolate());

  v8::Local<v8::Context> context =
      v8::Local<v8::Context>::New(GetIsolate(), context_);

  // Enter this processor's context so all the remaining operations
  // take place there
  Context::Scope context_scope(context);

  // Wrap the C++ request object in a JavaScript wrapper
  Local<Object> request_obj = WrapRequest(request);

  // Set up an exception handler before calling the Process function
  TryCatch try_catch(GetIsolate());

  // Invoke the process function, giving the global object as 'this'
  // and one argument, the request.
  const int argc = 1;
  Local<Value> argv[argc] = {request_obj};
  v8::Local<v8::Function> process =
      v8::Local<v8::Function>::New(GetIsolate(), process_);
  Local<Value> result;
  if (!process->Call(context, context->Global(), argc, argv).ToLocal(&result)) {
    String::Utf8Value error(GetIsolate(), try_catch.Exception());
    Log(*error);
    return false;
  }
  return true;
}


JsHttpRequestProcessor::~JsHttpRequestProcessor() {
  // Dispose the persistent handles.  When no one else has any
  // references to the objects stored in the handles they will be
  // automatically reclaimed.
  context_.Reset();
  process_.Reset();
}


Global<ObjectTemplate> JsHttpRequestProcessor::request_template_;
Global<ObjectTemplate> JsHttpRequestProcessor::map_template_;


// -----------------------------------
// --- A c c e s s i n g   M a p s ---
// -----------------------------------

// Utility function that wraps a C++ http request object in a
// JavaScript object.
Local<Object> JsHttpRequestProcessor::WrapMap(map<string, string>* obj) {
  // Local scope for temporary handles.
  EscapableHandleScope handle_scope(GetIsolate());

  // Fetch the template for creating JavaScript map wrappers.
  // It only has to be created once, which we do on demand.
  if (map_template_.IsEmpty()) {
    Local<ObjectTemplate> raw_template = MakeMapTemplate(GetIsolate());
    map_template_.Reset(GetIsolate(), raw_template);
  }
  Local<ObjectTemplate> templ =
      Local<ObjectTemplate>::New(GetIsolate(), map_template_);

  // Create an empty map wrapper.
  Local<Object> result =
      templ->NewInstance(GetIsolate()->GetCurrentContext()).ToLocalChecked();

  // Wrap the raw C++ pointer in an External so it can be referenced
  // from within JavaScript.
  Local<External> map_ptr = External::New(GetIsolate(), obj);

  // Store the map pointer in the JavaScript wrapper.
  result->SetInternalField(0, map_ptr);

  // Return the result through the current handle scope.  Since each
  // of these handles will go away when the handle scope is deleted
  // we need to call Close to let one, the result, escape into the
  // outer handle scope.
  return handle_scope.Escape(result);
}


// Utility function that extracts the C++ map pointer from a wrapper
// object.
map<string, string>* JsHttpRequestProcessor::UnwrapMap(Local<Object> obj) {
  Local<External> field = obj->GetInternalField(0).As<Value>().As<External>();
  void* ptr = field->Value();
  return static_cast<map<string, string>*>(ptr);
}


// Convert a JavaScript string to a std::string.  To not bother too
// much with string encodings we just use ascii.
string ObjectToString(v8::Isolate* isolate, Local<Value> value) {
  String::Utf8Value utf8_value(isolate, value);
  return string(*utf8_value);
}

v8::Intercepted JsHttpRequestProcessor::MapGet(
    Local<Name> name, const PropertyCallbackInfo<Value>& info) {
  if (name->IsSymbol()) return v8::Intercepted::kNo;

  // Fetch the map wrapped by this object.
  map<string, string>* obj = UnwrapMap(info.HolderV2());

  // Convert the JavaScript string to a std::string.
  string key = ObjectToString(info.GetIsolate(), name.As<String>());

  // Look up the value if it exists using the standard STL ideom.
  map<string, string>::iterator iter = obj->find(key);

  // If the key is not present return an empty handle as signal
  if (iter == obj->end()) return v8::Intercepted::kNo;

  // Otherwise fetch the value and wrap it in a JavaScript string
  const string& value = (*iter).second;
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), value.c_str(),
                          NewStringType::kNormal,
                          static_cast<int>(value.length())).ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted JsHttpRequestProcessor::MapSet(
    Local<Name> name, Local<Value> value_obj,
    const PropertyCallbackInfo<void>& info) {
  if (name->IsSymbol()) return v8::Intercepted::kNo;

  // Fetch the map wrapped by this object.
  map<string, string>* obj = UnwrapMap(info.HolderV2());

  // Convert the key and value to std::strings.
  string key = ObjectToString(info.GetIsolate(), name.As<String>());
  string value = ObjectToString(info.GetIsolate(), value_obj);

  // Update the map.
  (*obj)[key] = value;
  return v8::Intercepted::kYes;
}

Local<ObjectTemplate> JsHttpRequestProcessor::MakeMapTemplate(
    Isolate* isolate) {
  EscapableHandleScope handle_scope(isolate);

  Local<ObjectTemplate> result = ObjectTemplate::New(isolate);
  result->SetInternalFieldCount(1);
  result->SetHandler(NamedPropertyHandlerConfiguration(MapGet, MapSet));

  // Again, return the result through the current handle scope.
  return handle_scope.Escape(result);
}


// -------------------------------------------
// --- A c c e s s i n g   R e q u e s t s ---
// -------------------------------------------

/**
 * Utility function that wraps a C++ http request object in a
 * JavaScript object.
 */
Local<Object> JsHttpRequestProcessor::WrapRequest(HttpRequest* request) {
  // Local scope for temporary handles.
  EscapableHandleScope handle_scope(GetIsolate());

  // Fetch the template for creating JavaScript http request wrappers.
  // It only has to be created once, which we do on demand.
  if (request_template_.IsEmpty()) {
    Local<ObjectTemplate> raw_template = MakeRequestTemplate(GetIsolate());
    request_template_.Reset(GetIsolate(), raw_template);
  }
  Local<ObjectTemplate> templ =
      Local<ObjectTemplate>::New(GetIsolate(), request_template_);

  // Create an empty http request wrapper.
  Local<Object> result =
      templ->NewInstance(GetIsolate()->GetCurrentContext()).ToLocalChecked();

  // Wrap the raw C++ pointer in an External so it can be referenced
  // from within JavaScript.
  Local<External> request_ptr = External::New(GetIsolate(), request);

  // Store the request pointer in the JavaScript wrapper.
  result->SetInternalField(0, request_ptr);

  // Return the result through the current handle scope.  Since each
  // of these handles will go away when the handle scope is deleted
  // we need to call Close to let one, the result, escape into the
  // outer handle scope.
  return handle_scope.Escape(result);
}


/**
 * Utility function that extracts the C++ http request object from a
 * wrapper object.
 */
HttpRequest* JsHttpRequestProcessor::UnwrapRequest(Local<Object> obj) {
  Local<External> field = obj->GetInternalField(0).As<Value>().As<External>();
  void* ptr = field->Value();
  return static_cast<HttpRequest*>(ptr);
}

void JsHttpRequestProcessor::GetPath(Local<Name> name,
                                     const PropertyCallbackInfo<Value>& info) {
  // Extract the C++ request object from the JavaScript wrapper.
  HttpRequest* request = UnwrapRequest(info.HolderV2());

  // Fetch the path.
  const string& path = request->Path();

  // Wrap the result in a JavaScript string and return it.
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), path.c_str(),
                          NewStringType::kNormal,
                          static_cast<int>(path.length())).ToLocalChecked());
}

void JsHttpRequestProcessor::GetReferrer(
    Local<Name> name, const PropertyCallbackInfo<Value>& info) {
  HttpRequest* request = UnwrapRequest(info.HolderV2());
  const string& path = request->Referrer();
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), path.c_str(),
                          NewStringType::kNormal,
                          static_cast<int>(path.length())).ToLocalChecked());
}

void JsHttpRequestProcessor::GetHost(Local<Name> name,
                                     const PropertyCallbackInfo<Value>& info) {
  HttpRequest* request = UnwrapRequest(info.HolderV2());
  const string& path = request->Host();
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), path.c_str(),
                          NewStringType::kNormal,
                          static_cast<int>(path.length())).ToLocalChecked());
}

void JsHttpRequestProcessor::GetUserAgent(
    Local<Name> name, const PropertyCallbackInfo<Value>& info) {
  HttpRequest* request = UnwrapRequest(info.HolderV2());
  const string& path = request->UserAgent();
  info.GetReturnValue().Set(
      String::NewFromUtf8(info.GetIsolate(), path.c_str(),
                          NewStringType::kNormal,
                          static_cast<int>(path.length())).ToLocalChecked());
}

Local<ObjectTemplate> JsHttpRequestProcessor::MakeRequestTemplate(
    Isolate* isolate) {
  EscapableHandleScope handle_scope(isolate);

  Local<ObjectTemplate> result = ObjectTemplate::New(isolate);
  result->SetInternalFieldCount(1);

  // Add accessors for each of the fields of the request.
  result->SetNativeDataProperty(
      String::NewFromUtf8Literal(isolate, "path", NewStringType::kInternalized),
      GetPath);
  result->SetNativeDataProperty(
      String::NewFromUtf8Literal(isolate, "referrer",
                                 NewStringType::kInternalized),
      GetReferrer);
  result->SetNativeDataProperty(
      String::NewFromUtf8Literal(isolate, "host", NewStringType::kInternalized),
      GetHost);
  result->SetNativeDataProperty(
      String::NewFromUtf8Literal(isolate, "userAgent",
                                 NewStringType::kInternalized),
      GetUserAgent);

  // Again, return the result through the current handle scope.
  return handle_scope.Escape(result);
}


// --- Test ---


void HttpRequestProcessor::Log(const char* event) {
  printf("Logged: %s\n", event);
}


/**
 * A simplified http request.
 */
class StringHttpRequest : public HttpRequest {
 public:
  StringHttpRequest(const string& path,
                    const string& referrer,
                    const string& host,
                    const string& user_agent);
  virtual const string& Path() { return path_; }
  virtual const string& Referrer() { return referrer_; }
  virtual const string& Host() { return host_; }
  virtual const string& UserAgent() { return user_agent_; }
 private:
  string path_;
  string referrer_;
  string host_;
  string user_agent_;
};


StringHttpRequest::StringHttpRequest(const string& path,
                                     const string& referrer,
                                     const string& host,
                                     const string& user_agent)
    : path_(path),
      referrer_(referrer),
      host_(host),
      user_agent_(user_agent) { }


void ParseOptions(int argc,
                  char* argv[],
                  map<string, string>* options,
                  string* file) {
  for (int i = 1; i < argc; i++) {
    string arg = argv[i];
    size_t index = arg.find('=', 0);
    if (index == string::npos) {
      *file = arg;
    } else {
      string key = arg.substr(0, index);
      string value = arg.substr(index+1);
      (*options)[key] = value;
    }
  }
}


// Reads a file into a v8 string.
MaybeLocal<String> ReadFile(Isolate* isolate, const string& name) {
  FILE* file = fopen(name.c_str(), "rb");
  if (file == NULL) return MaybeLocal<String>();

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  rewind(file);

  std::unique_ptr<char[]> chars(new char[size + 1]);
  chars.get()[size] = '\0';
  for (size_t i = 0; i < size;) {
    i += fread(&chars.get()[i], 1, size - i, file);
    if (ferror(file)) {
      fclose(file);
      return MaybeLocal<String>();
    }
  }
  fclose(file);
  MaybeLocal<String> result = String::NewFromUtf8(
      isolate, chars.get(), NewStringType::kNormal, static_cast<int>(size));
  return result;
}


const int kSampleSize = 6;
StringHttpRequest kSampleRequests[kSampleSize] = {
  StringHttpRequest("/process.cc", "localhost", "google.com", "firefox"),
  StringHttpRequest("/", "localhost", "google.net", "firefox"),
  StringHttpRequest("/", "localhost", "google.org", "safari"),
  StringHttpRequest("/", "localhost", "yahoo.com", "ie"),
  StringHttpRequest("/", "localhost", "yahoo.com", "safari"),
  StringHttpRequest("/", "localhost", "yahoo.com", "firefox")
};

bool ProcessEntries(v8::Isolate* isolate, v8::Platform* platform,
                    HttpRequestProcessor* processor, int count,
                    StringHttpRequest* reqs) {
  for (int i = 0; i < count; i++) {
    bool result = processor->Process(&reqs[i]);
    while (v8::platform::PumpMessageLoop(platform, isolate)) continue;
    if (!result) return false;
  }
  return true;
}

void PrintMap(map<string, string>* m) {
  for (map<string, string>::iterator i = m->begin(); i != m->end(); i++) {
    pair<string, string> entry = *i;
    printf("%s: %s\n", entry.first.c_str(), entry.second.c_str());
  }
}


int main(int argc, char* argv[]) {
  v8::V8::InitializeICUDefaultLocation(argv[0]);
  v8::V8::InitializeExternalStartupData(argv[0]);
  std::unique_ptr<v8::Platform> platform = v8::platform::NewDefaultPlatform();
  v8::V8::InitializePlatform(platform.get());
  v8::V8::Initialize();
  map<string, string> options;
  string file;
  ParseOptions(argc, argv, &options, &file);
  if (file.empty()) {
    fprintf(stderr, "No script was specified.\n");
    return 1;
  }
  Isolate::CreateParams create_params;
  create_params.array_buffer_allocator =
      v8::ArrayBuffer::Allocator::NewDefaultAllocator();
  Isolate* isolate = Isolate::New(create_params);
  Isolate::Scope isolate_scope(isolate);
  HandleScope scope(isolate);
  Local<String> source;
  if (!ReadFile(isolate, file).ToLocal(&source)) {
    fprintf(stderr, "Error reading '%s'.\n", file.c_str());
    return 1;
  }
  JsHttpRequestProcessor processor(isolate, source);
  map<string, string> output;
  if (!processor.Initialize(&options, &output)) {
    fprintf(stderr, "Error initializing processor.\n");
    return 1;
  }
  if (!ProcessEntries(isolate, platform.get(), &processor, kSampleSize,
                      kSampleRequests)) {
    return 1;
  }
  PrintMap(&output);
}

"""

```