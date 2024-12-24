Response: Let's break down the thought process to understand and explain this C++ code.

1. **Identify the Core Goal:** The file is named `process.cc` and resides in a `samples` directory within the V8 project. This strongly suggests it's a demonstration of some V8 functionality related to processing. The copyright header confirms it's a V8 example.

2. **Scan for Key V8 Concepts:** Quickly look for V8 API elements. Seeing `#include "include/v8-*.h"` is a dead giveaway. Keywords like `Isolate`, `Context`, `Script`, `ObjectTemplate`, `FunctionTemplate`, `HandleScope`, `Local`, `Global`, `PropertyCallbackInfo`, etc., are crucial. These indicate interaction with the V8 JavaScript engine.

3. **Look for Business Logic:**  Beyond V8, search for custom classes and their responsibilities. `HttpRequest` and `HttpRequestProcessor` stand out. The comments describe them as representing an "existing request processing interface." This implies the example integrates JavaScript with an existing C++ system.

4. **Focus on the Integration Point:** The `JsHttpRequestProcessor` class inherits from `HttpRequestProcessor`. Its constructor takes an `Isolate*` and a `Local<String> script`. This strongly hints that this class is the bridge between C++ and JavaScript. It takes JavaScript code as input.

5. **Analyze `JsHttpRequestProcessor` Methods:**
    * `Initialize`:  This method likely sets up the JavaScript environment. The comments mention creating a `Context`, installing global functions (`log`), and making `options` and `output` available as JavaScript objects. The call to `ExecuteScript` confirms that the provided script is being run.
    * `Process`: This is where the actual request processing happens. The comment mentions invoking the "Process function of the JavaScript script."  The code wraps the C++ `HttpRequest` object and passes it as an argument to the JavaScript `Process` function.
    * `ExecuteScript`:  This clearly compiles and runs the JavaScript code using V8's `Script::Compile` and `Script::Run`.
    * `InstallMaps`: This explains how C++ `std::map` objects are exposed to JavaScript.
    * `MakeRequestTemplate` and related `Get...` methods: These define how JavaScript code can access properties of the C++ `HttpRequest` object. The "template" terminology is a key V8 concept for creating JavaScript objects based on C++ structures.
    * `Wrap...` and `Unwrap...`:  These are utility functions for converting between C++ objects and their JavaScript representations.

6. **Trace the Execution Flow in `main`:**
    * Initialize V8.
    * Parse command-line arguments to get a script file.
    * Create a V8 `Isolate`.
    * Read the JavaScript file.
    * Instantiate `JsHttpRequestProcessor`.
    * Call `Initialize` to set up the JavaScript environment and run the script.
    * Call `ProcessEntries` repeatedly, simulating processing multiple requests.
    * Print the contents of the `output` map.

7. **Formulate a Summary:** Combine the observations. The core functionality is to allow a C++ application to process HTTP requests using logic defined in a JavaScript file. The `JsHttpRequestProcessor` is the central component that bridges the two worlds.

8. **Construct JavaScript Examples:** Based on the C++ code, especially the `InstallMaps` and `MakeRequestTemplate` parts, create JavaScript examples that demonstrate:
    * Accessing the `options` and `output` maps.
    * Accessing properties of the `request` object passed to the `Process` function.
    * Using the `log` function.
    * Modifying the `output` map.

9. **Refine and Organize:**  Structure the explanation clearly with headings. Explain the purpose of each major class and method. Use clear and concise language. Ensure the JavaScript examples directly relate to the C++ code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just about running JavaScript?  **Correction:** The `HttpRequest` and `HttpRequestProcessor` classes indicate a deeper integration with an existing system.
* **Stuck on details:**  Don't get bogged down in every line of V8 API initially. Focus on the overall flow and purpose. Return to the details once the high-level understanding is clear.
* **JavaScript examples unclear:** Make sure the examples directly demonstrate the interaction points identified in the C++ code. For instance, explicitly show accessing `request.path`, `options.key`, and modifying `output.result`.
* **Missing the "why":**  Emphasize *why* this example is useful. It shows how to embed a scripting language (JavaScript) into a C++ application to extend its functionality dynamically.

By following these steps and constantly asking "What is this doing?" and "How does this relate to V8 and JavaScript?", we can effectively understand and explain the functionality of this C++ code.
这个 C++ 源代码文件 `process.cc` 是一个 V8 引擎的示例，展示了如何在 C++ 应用程序中嵌入和使用 JavaScript 脚本来处理 HTTP 请求。其主要功能可以归纳为：

**主要功能：**

1. **定义了 HTTP 请求和处理器接口：**  文件中定义了 `HttpRequest` 和 `HttpRequestProcessor` 抽象类，模拟了一个简化的 HTTP 请求处理系统。

2. **实现了基于 JavaScript 的请求处理器：**  核心类是 `JsHttpRequestProcessor`，它继承自 `HttpRequestProcessor`，允许使用 JavaScript 脚本来定义请求处理逻辑。

3. **将 C++ 对象桥接到 JavaScript：**  `JsHttpRequestProcessor` 能够将 C++ 的 `HttpRequest` 对象和 `std::map` 对象（用于选项和输出）包装成 JavaScript 对象，使得 JavaScript 代码可以访问和操作这些 C++ 对象的数据。

4. **执行 JavaScript 脚本：**  `JsHttpRequestProcessor` 接收一个 JavaScript 脚本作为参数，并在其上下文中执行该脚本。

5. **调用 JavaScript 函数处理请求：**  JavaScript 脚本中需要定义一个名为 `Process` 的函数。当 `JsHttpRequestProcessor` 的 `Process` 方法被调用时，它会调用 JavaScript 脚本中的 `Process` 函数，并将包装后的 `HttpRequest` 对象作为参数传递给它。

6. **提供 C++ 到 JavaScript 的日志功能：**  通过在 JavaScript 全局对象中注入一个名为 `log` 的函数，JavaScript 代码可以调用这个函数来向 C++ 应用程序输出日志。

7. **演示了 V8 引擎的嵌入和使用：**  该示例代码展示了如何初始化 V8 引擎，创建隔离的上下文，编译和运行 JavaScript 代码，以及如何在 C++ 和 JavaScript 之间传递数据。

**与 JavaScript 的关系及示例：**

该 C++ 代码通过 V8 引擎直接与 JavaScript 交互。它允许 C++ 代码执行 JavaScript 代码，并且 JavaScript 代码可以访问和操作由 C++ 代码提供的对象。

以下是一些 JavaScript 代码示例，展示了如何在 `JsHttpRequestProcessor` 的上下文中与 C++ 代码进行交互：

**示例 1: 访问 HttpRequest 对象属性**

```javascript
function Process(request) {
  log("处理请求: " + request.path);
  log("来源页面: " + request.referrer);
  log("主机: " + request.host);
  log("用户代理: " + request.userAgent);

  if (request.path === "/special") {
    log("这是一个特殊请求！");
  }
  return true;
}
```

在这个例子中，`Process` 函数接收一个名为 `request` 的参数。这个 `request` 对象实际上是由 C++ 的 `JsHttpRequestProcessor` 包装的 `HttpRequest` 对象。JavaScript 代码可以直接访问 `request` 对象的 `path`、`referrer`、`host` 和 `userAgent` 属性，这些属性对应于 C++ `HttpRequest` 类的成员方法。

**示例 2: 访问和修改 options 和 output 对象**

```javascript
function Process(request) {
  log("选项 'debug' 的值: " + options.debug);

  if (request.host === "google.com") {
    output.result = "允许访问 Google";
  } else {
    output.result = "拒绝访问";
  }

  output.processedCount = (output.processedCount || 0) + 1;

  return true;
}
```

在这个例子中，`options` 和 `output` 是在 C++ 代码中创建的 `std::map<string, string>` 对象，并被 `JsHttpRequestProcessor` 注入到 JavaScript 的全局作用域中。JavaScript 代码可以像操作普通 JavaScript 对象一样访问和修改它们的属性（键值对）。

**示例 3: 使用 log 函数**

```javascript
function Process(request) {
  log("开始处理请求");
  // ... 一些处理逻辑 ...
  log("请求处理完成");
  return true;
}
```

这里 `log` 函数是在 C++ 的 `JsHttpRequestProcessor::Initialize` 方法中，通过 `global->Set(GetIsolate(), "log", FunctionTemplate::New(GetIsolate(), LogCallback));`  注入到 JavaScript 全局作用域的。JavaScript 代码调用 `log()` 函数时，实际上会调用 C++ 的 `LogCallback` 函数，从而在 C++ 端输出日志。

**总结：**

`v8/samples/process.cc` 演示了如何利用 V8 引擎，在 C++ 应用程序中嵌入 JavaScript 脚本来处理特定的任务（在这个例子中是 HTTP 请求）。它通过定义接口、包装 C++ 对象、提供全局函数等方式，实现了 C++ 和 JavaScript 之间的双向通信和协作，使得开发者可以使用 JavaScript 的灵活性来扩展 C++ 应用程序的功能。

Prompt: 
```
这是目录为v8/samples/process.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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