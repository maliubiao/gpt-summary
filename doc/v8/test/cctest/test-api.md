Response: The user wants me to analyze a C++ source code file, specifically `v8/test/cctest/test-api.cc`, and summarize its functionality. Since this is part 1 of 18, the summary should focus on the content of this specific part. I also need to identify any relationships to JavaScript and provide illustrative examples in JavaScript if applicable.

Based on the included headers and the overall structure of the code, it seems like this file contains tests for the V8 JavaScript engine's C++ API. It utilizes the `cctest` framework for testing.

Here's a breakdown of the functionality in this part:

1. **Includes:**  Various V8 headers (`v8-date.h`, `v8-extension.h`, etc.) indicating tests for different API components. Standard C++ library headers are also included.
2. **Macros and Typedefs:**  Defines `THREADED_PROFILED_TEST` and `RunWithProfiler`, suggesting tests involving profiling. It also uses `v8::...` types extensively, indicating interaction with the V8 API.
3. **Basic Handle and Context Tests:**  Tests the creation and usage of `v8::HandleScope` and `v8::Context`.
4. **Isolate Tests:**  Checks the `GetIsolate()` functionality of contexts.
5. **Signature Callback Tests:**  Includes tests for function signatures and how they affect callback behavior. This is strongly related to how V8 handles `this` and arguments in JavaScript function calls.
6. **Receiver Signature Tests:**  More detailed tests around function signatures, inheritance, and how they relate to the receiver (`this`) in JavaScript.
7. **Regression Test:** Contains a test named `Regress1188563`, indicating a fix for a specific bug.
8. **Basic Value Access Tests:** Tests getting and setting properties on JavaScript objects.
9. **Script Compilation and Execution:** Tests the `v8::Script::Compile` and `v8::Script::Run` APIs.
10. **External String Resource Tests:**  Significant portion dedicated to testing how V8 handles strings backed by external resources. This is a performance optimization technique.
11. **String Manipulation Tests:**  Includes a test for string concatenation.
12. **Global Property Tests:**  Tests setting and getting properties on the global object.
13. **Function Template Tests:**  Tests the creation and usage of `v8::FunctionTemplate`, a key API for creating native functions callable from JavaScript. This includes tests for callbacks, constructors, accessors, and length.
14. **External Data Wrapping:**  Tests how to associate external C++ data with JavaScript objects and functions using `v8::External`.
15. **Prototype Chain Tests:**  Tests the `FindInstanceInPrototypeChain` method, demonstrating how V8 navigates JavaScript's prototype inheritance.
16. **Integer Creation Tests:** Tests the creation of various types of integers (`v8::Integer`).

The relationship with JavaScript is evident in nearly every test. These C++ tests are verifying that the V8 C++ API behaves as expected when interacting with JavaScript concepts.

For example, the "Receiver Signature" tests are directly related to how `this` works in JavaScript, especially in the context of prototypes and inheritance. The "Function Template" tests demonstrate how to expose native C++ functions to JavaScript.

I will now formulate the summary and JavaScript examples.
This C++ source code file, `test-api.cc`, is part of the V8 JavaScript engine's test suite. Specifically, this part (part 1 of 18) focuses on testing various aspects of the V8 C++ API. Its primary function is to verify the correctness and behavior of core V8 API components.

Here's a breakdown of the functionalities covered in this section:

*   **Basic API Interaction:** It tests the fundamental use of `v8::Isolate`, `v8::HandleScope`, and `v8::Context` for creating and managing the JavaScript environment.
*   **Script Compilation and Execution:** It verifies the ability to compile and run JavaScript code snippets using `v8::Script::Compile` and `v8::Script::Run`.
*   **Object and Property Access:** It tests the API for getting and setting properties on JavaScript objects (`v8::Object::Get`, `v8::Object::Set`).
*   **Function Templates and Callbacks:** It extensively tests `v8::FunctionTemplate`, a crucial part of the API for creating native C++ functions that can be called from JavaScript. This includes setting callback functions, handling `this` (the receiver), and managing function signatures.
*   **External String Resources:** It covers testing the usage of external string resources (`v8::String::NewExternalTwoByte`, `v8::String::NewExternalOneByte`, `v8::String::MakeExternal`) for optimizing string storage and memory management.
*   **String Manipulation:** It includes basic tests for string operations like concatenation (`v8::String::Concat`).
*   **Global Object Interaction:** It tests setting and getting properties on the global JavaScript object.
*   **Integer Creation:** It verifies the creation of different integer types using `v8::Integer::New` and `v8::Integer::NewFromUnsigned`.
*   **Prototype Chain Inspection:** It tests the `v8::Object::FindInstanceInPrototypeChain` method, which allows examining the prototype inheritance of JavaScript objects.
*   **Regression Testing:** It includes specific tests like `Regress1188563`, indicating fixes for previously identified bugs in the API.

**Relationship with JavaScript and Examples:**

This C++ code directly tests the underlying mechanisms that make JavaScript features work in V8. Here are some examples illustrating the connection:

1. **Function Templates and Callbacks:**  The C++ code tests how to create native functions callable from JavaScript.

    **C++ (within `test-api.cc`):**

    ```c++
    static void handle_callback(const v8::FunctionCallbackInfo<Value>& info) {
      info.GetReturnValue().Set(v8_num(102));
    }

    TEST(FunctionTemplateInitializer) {
      // ...
      Local<v8::FunctionTemplate> fun_templ =
          v8::FunctionTemplate::New(isolate, handle_callback);
      Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
      CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
      Local<Script> script = v8_compile("obj()");
      CHECK_EQ(102, v8_run_int32value(script));
      // ...
    }
    ```

    **JavaScript:**

    ```javascript
    // After the C++ code has run, the 'obj' function is available in JavaScript
    obj(); // This will call the C++ handle_callback function, returning 102
    ```

2. **Receiver Signature:** The C++ code tests how function signatures affect the `this` value in JavaScript function calls.

    **C++ (within `test-api.cc`):**

    ```c++
    static v8::Global<Value> signature_expected_receiver_global;
    static void IncrementingSignatureCallback(
        const v8::FunctionCallbackInfo<v8::Value>& info) {
      // ...
      v8::Local<Value> signature_expected_receiver =
          signature_expected_receiver_global.Get(isolate);
      CHECK(signature_expected_receiver
                ->Equals(isolate->GetCurrentContext(),
                         info.HolderSoonToBeDeprecated())
                .FromJust());
      CHECK(signature_expected_receiver
                ->Equals(isolate->GetCurrentContext(), info.This())
                .FromJust());
      // ...
    }

    TEST(ReceiverSignature) {
      // ...
      v8::Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(isolate);
      v8::Local<v8::Signature> sig = v8::Signature::New(isolate, fun);
      v8::Local<v8::FunctionTemplate> callback_sig = v8::FunctionTemplate::New(
          isolate, IncrementingSignatureCallback, Local<Value>(), sig);
      // ...
    }
    ```

    **JavaScript:**

    ```javascript
    function Fun() {
      this.value = 42;
    }

    Fun.prototype.prop_sig = function() {
      console.log(this.value); // 'this' will be an instance of Fun
    };

    let instance = new Fun();
    instance.prop_sig(); // This will call the C++ IncrementingSignatureCallback
                         // and the C++ code will verify that 'this' in the
                         // callback corresponds to the 'instance' object.
    ```

3. **Object and Property Access:** The C++ tests directly mirror how you interact with objects in JavaScript.

    **C++ (within `test-api.cc`):**

    ```c++
    TEST(Access) {
      // ...
      Local<v8::Object> obj = v8::Object::New(isolate);
      Local<Value> foo_before =
          obj->Get(env.local(), v8_str("foo")).ToLocalChecked();
      CHECK(foo_before->IsUndefined());
      Local<String> bar_str = v8_str("bar");
      CHECK(obj->Set(env.local(), v8_str("foo"), bar_str).FromJust());
      Local<Value> foo_after =
          obj->Get(env.local(), v8_str("foo")).ToLocalChecked();
      CHECK(bar_str->Equals(env.local(), foo_after).FromJust());
      // ...
    }
    ```

    **JavaScript:**

    ```javascript
    let obj = {};
    console.log(obj.foo); // undefined
    obj.foo = "bar";
    console.log(obj.foo); // "bar"
    ```

In summary, this part of the `test-api.cc` file acts as a fundamental validation layer for the V8 C++ API, ensuring that the core building blocks for embedding and extending the JavaScript engine function correctly. It directly reflects and tests the behaviors that JavaScript developers rely on.

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共18部分，请归纳一下它的功能
```

### 源代码
```
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

#include "test/cctest/test-api.h"

#include <climits>
#include <csignal>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

#include "test/cctest/cctest.h"

#if V8_OS_POSIX
#include <unistd.h>
#endif

#include "include/v8-date.h"
#include "include/v8-extension.h"
#include "include/v8-fast-api-calls.h"
#include "include/v8-function.h"
#include "include/v8-initialization.h"
#include "include/v8-json.h"
#include "include/v8-locker.h"
#include "include/v8-primitive-object.h"
#include "include/v8-regexp.h"
#include "include/v8-util.h"
#include "src/api/api-inl.h"
#include "src/base/bounds.h"
#include "src/base/overflowing-math.h"
#include "src/base/platform/platform.h"
#include "src/base/strings.h"
#include "src/codegen/compilation-cache.h"
#include "src/common/globals.h"
#include "src/compiler/globals.h"
#include "src/execution/execution.h"
#include "src/execution/futex-emulation.h"
#include "src/execution/protectors-inl.h"
#include "src/handles/global-handles.h"
#include "src/heap/heap-inl.h"
#include "src/heap/incremental-marking.h"
#include "src/logging/metrics.h"
#include "src/objects/feedback-vector-inl.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-promise-inl.h"
#include "src/objects/lookup.h"
#include "src/objects/map-updater.h"
#include "src/objects/objects-inl.h"
#include "src/objects/string-inl.h"
#include "src/objects/synthetic-module-inl.h"
#include "src/profiler/cpu-profiler.h"
#include "src/utils/utils.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/common/flag-utils.h"
#include "test/common/streaming-helper.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-engine.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"
#endif  // V8_ENABLE_WEBASSEMBLY

static const bool kLogThreading = false;

using ::v8::Array;
using ::v8::Boolean;
using ::v8::BooleanObject;
using ::v8::Context;
using ::v8::Extension;
using ::v8::External;
using ::v8::FixedArray;
using ::v8::Function;
using ::v8::FunctionTemplate;
using ::v8::HandleScope;
using ::v8::Local;
using ::v8::Maybe;
using ::v8::Message;
using ::v8::MessageCallback;
using ::v8::Module;
using ::v8::Name;
using ::v8::None;
using ::v8::Object;
using ::v8::ObjectTemplate;
using ::v8::Persistent;
using ::v8::PropertyAttribute;
using ::v8::Script;
using ::v8::String;
using ::v8::Symbol;
using ::v8::TryCatch;
using ::v8::Undefined;
using ::v8::V8;
using ::v8::Value;


#define THREADED_PROFILED_TEST(Name)                                 \
  static void Test##Name();                                          \
  TEST(Name##WithProfiler) {                                         \
    RunWithProfiler(&Test##Name);                                    \
  }                                                                  \
  THREADED_TEST(Name)

void RunWithProfiler(void (*test)()) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::String> profile_name = v8_str("my_profile1");
  v8::CpuProfiler* cpu_profiler = v8::CpuProfiler::New(env->GetIsolate());
  cpu_profiler->StartProfiling(profile_name);
  (*test)();
  reinterpret_cast<i::CpuProfiler*>(cpu_profiler)->DeleteAllProfiles();
  cpu_profiler->Dispose();
}


static int signature_callback_count;
static v8::Global<Value> signature_expected_receiver_global;
static void IncrementingSignatureCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  signature_callback_count++;
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<Value> signature_expected_receiver =
      signature_expected_receiver_global.Get(isolate);
  CHECK(signature_expected_receiver
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  CHECK(signature_expected_receiver
            ->Equals(isolate->GetCurrentContext(), info.This())
            .FromJust());
  v8::Local<v8::Array> result = v8::Array::New(isolate, info.Length());
  for (int i = 0; i < info.Length(); i++) {
    CHECK(result
              ->Set(isolate->GetCurrentContext(), v8::Integer::New(isolate, i),
                    info[i])
              .FromJust());
  }
  info.GetReturnValue().Set(result);
}

static void Returns42(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(42);
}

THREADED_TEST(Handles) {
  v8::HandleScope scope(CcTest::isolate());
  Local<Context> local_env;
  {
    LocalContext env;
    local_env = env.local();
  }

  // Local context should still be live.
  CHECK(!local_env.IsEmpty());
  local_env->Enter();

  v8::Local<v8::Primitive> undef = v8::Undefined(CcTest::isolate());
  CHECK(!undef.IsEmpty());
  CHECK(undef->IsUndefined());

  const char* source = "1 + 2 + 3";
  Local<Script> script = v8_compile(source);
  CHECK_EQ(6, v8_run_int32value(script));

  local_env->Exit();
}


THREADED_TEST(IsolateOfContext) {
  v8::HandleScope scope(CcTest::isolate());
  v8::Local<Context> env = Context::New(CcTest::isolate());

  CHECK(!env->GetIsolate()->InContext());
  CHECK(env->GetIsolate() == CcTest::isolate());
  env->Enter();
  CHECK(env->GetIsolate()->InContext());
  CHECK(env->GetIsolate() == CcTest::isolate());
  env->Exit();
  CHECK(!env->GetIsolate()->InContext());
  CHECK(env->GetIsolate() == CcTest::isolate());
}

static void TestSignatureLooped(const char* operation, Local<Value> receiver,
                                v8::Isolate* isolate) {
  v8::base::ScopedVector<char> source(200);
  v8::base::SNPrintF(source,
                     "for (var i = 0; i < 10; i++) {"
                     "  %s"
                     "}",
                     operation);
  signature_callback_count = 0;
  signature_expected_receiver_global.Reset(isolate, receiver);
  bool expected_to_throw = receiver.IsEmpty();
  v8::TryCatch try_catch(isolate);
  CompileRun(source.begin());
  CHECK_EQ(expected_to_throw, try_catch.HasCaught());
  if (!expected_to_throw) {
    CHECK_EQ(10, signature_callback_count);
  } else {
    CHECK(v8_str("TypeError: Illegal invocation")
              ->Equals(isolate->GetCurrentContext(),
                       try_catch.Exception()
                           ->ToString(isolate->GetCurrentContext())
                           .ToLocalChecked())
              .FromJust());
  }
  signature_expected_receiver_global.Reset();
}

static void TestSignatureOptimized(const char* operation, Local<Value> receiver,
                                   v8::Isolate* isolate) {
  v8::base::ScopedVector<char> source(200);
  v8::base::SNPrintF(source,
                     "function test() {"
                     "  %s"
                     "};"
                     "%%PrepareFunctionForOptimization(test);"
                     "try { test() } catch(e) {}"
                     "try { test() } catch(e) {}"
                     "%%OptimizeFunctionOnNextCall(test);"
                     "test()",
                     operation);
  signature_callback_count = 0;
  signature_expected_receiver_global.Reset(isolate, receiver);
  bool expected_to_throw = receiver.IsEmpty();
  v8::TryCatch try_catch(isolate);
  CompileRun(source.begin());
  CHECK_EQ(expected_to_throw, try_catch.HasCaught());
  if (!expected_to_throw) {
    CHECK_EQ(3, signature_callback_count);
  } else {
    CHECK(v8_str("TypeError: Illegal invocation")
              ->Equals(isolate->GetCurrentContext(),
                       try_catch.Exception()
                           ->ToString(isolate->GetCurrentContext())
                           .ToLocalChecked())
              .FromJust());
  }
  signature_expected_receiver_global.Reset();
}

static void TestSignature(const char* operation, Local<Value> receiver,
                          v8::Isolate* isolate) {
  TestSignatureLooped(operation, receiver, isolate);
  TestSignatureOptimized(operation, receiver, isolate);
}

THREADED_TEST(ReceiverSignature) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  // Setup templates.
  v8::Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::Signature> sig = v8::Signature::New(isolate, fun);
  v8::Local<v8::FunctionTemplate> callback_sig = v8::FunctionTemplate::New(
      isolate, IncrementingSignatureCallback, Local<Value>(), sig);
  v8::Local<v8::FunctionTemplate> callback =
      v8::FunctionTemplate::New(isolate, IncrementingSignatureCallback);
  v8::Local<v8::FunctionTemplate> sub_fun = v8::FunctionTemplate::New(isolate);
  sub_fun->Inherit(fun);
  v8::Local<v8::FunctionTemplate> direct_sub_fun =
      v8::FunctionTemplate::New(isolate);
  direct_sub_fun->Inherit(fun);
  v8::Local<v8::FunctionTemplate> unrel_fun =
      v8::FunctionTemplate::New(isolate);
  // Install properties.
  v8::Local<v8::ObjectTemplate> fun_proto = fun->PrototypeTemplate();
  fun_proto->Set(isolate, "prop_sig", callback_sig);
  fun_proto->Set(isolate, "prop", callback);
  fun_proto->SetAccessorProperty(
      v8_str("accessor_sig"), callback_sig, callback_sig);
  fun_proto->SetAccessorProperty(v8_str("accessor"), callback, callback);
  // Instantiate templates.
  Local<Value> fun_instance =
      fun->InstanceTemplate()->NewInstance(env.local()).ToLocalChecked();
  Local<Value> sub_fun_instance =
      sub_fun->InstanceTemplate()->NewInstance(env.local()).ToLocalChecked();
  // Instance template with properties.
  v8::Local<v8::ObjectTemplate> direct_instance_templ =
      direct_sub_fun->InstanceTemplate();
  direct_instance_templ->Set(isolate, "prop_sig", callback_sig);
  direct_instance_templ->Set(isolate, "prop", callback);
  direct_instance_templ->SetAccessorProperty(v8_str("accessor_sig"),
                                             callback_sig, callback_sig);
  direct_instance_templ->SetAccessorProperty(v8_str("accessor"), callback,
                                             callback);
  Local<Value> direct_instance =
      direct_instance_templ->NewInstance(env.local()).ToLocalChecked();
  // Setup global variables.
  CHECK(env->Global()
            ->Set(env.local(), v8_str("Fun"),
                  fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("UnrelFun"),
                  unrel_fun->GetFunction(env.local()).ToLocalChecked())
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("fun_instance"), fun_instance)
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("sub_fun_instance"), sub_fun_instance)
            .FromJust());
  CHECK(env->Global()
            ->Set(env.local(), v8_str("direct_instance"), direct_instance)
            .FromJust());
  CompileRun(
      "var accessor_sig_key = 'accessor_sig';"
      "var accessor_key = 'accessor';"
      "var prop_sig_key = 'prop_sig';"
      "var prop_key = 'prop';"
      ""
      "function copy_props(obj) {"
      "  var keys = [accessor_sig_key, accessor_key, prop_sig_key, prop_key];"
      "  var source = Fun.prototype;"
      "  for (var i in keys) {"
      "    var key = keys[i];"
      "    var desc = Object.getOwnPropertyDescriptor(source, key);"
      "    Object.defineProperty(obj, key, desc);"
      "  }"
      "}"
      ""
      "var plain = {};"
      "copy_props(plain);"
      "var unrelated = new UnrelFun();"
      "copy_props(unrelated);"
      "var inherited = { __proto__: fun_instance };"
      "var inherited_direct = { __proto__: direct_instance };");
  // Test with and without ICs
  const char* test_objects[] = {
      "fun_instance", "sub_fun_instance", "direct_instance", "plain",
      "unrelated",    "inherited",        "inherited_direct"};
  unsigned bad_signature_start_offset = 3;
  for (unsigned i = 0; i < arraysize(test_objects); i++) {
    v8::base::ScopedVector<char> source(200);
    v8::base::SNPrintF(source, "var test_object = %s; test_object",
                       test_objects[i]);
    Local<Value> test_object = CompileRun(source.begin());
    TestSignature("test_object.prop();", test_object, isolate);
    TestSignature("test_object.accessor;", test_object, isolate);
    TestSignature("test_object[accessor_key];", test_object, isolate);
    TestSignature("test_object.accessor = 1;", test_object, isolate);
    TestSignature("test_object[accessor_key] = 1;", test_object, isolate);
    if (i >= bad_signature_start_offset) test_object = Local<Value>();
    TestSignature("test_object.prop_sig();", test_object, isolate);
    TestSignature("test_object.accessor_sig;", test_object, isolate);
    TestSignature("test_object[accessor_sig_key];", test_object, isolate);
    TestSignature("test_object.accessor_sig = 1;", test_object, isolate);
    TestSignature("test_object[accessor_sig_key] = 1;", test_object, isolate);
  }
}

namespace {

void DoNothingCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
}

}  // namespace

// Regression test for issue chromium:1188563.
THREADED_TEST(Regress1188563) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  // Set up some data for function template.
  v8::Local<v8::FunctionTemplate> data_constructor_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<Function> data_constructor =
      data_constructor_templ->GetFunction(env.local()).ToLocalChecked();
  v8::Local<v8::Object> data =
      data_constructor->NewInstance(env.local()).ToLocalChecked();

  // Setup templates and instance with accessor property.
  v8::Local<v8::FunctionTemplate> fun = v8::FunctionTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> callback =
      v8::FunctionTemplate::New(isolate, DoNothingCallback, data);
  v8::Local<v8::ObjectTemplate> instance_templ = fun->InstanceTemplate();
  instance_templ->SetAccessorProperty(v8_str("accessor"), callback, callback);
  Local<Value> test_object =
      instance_templ->NewInstance(env.local()).ToLocalChecked();
  // Setup global variables.
  CHECK(env->Global()
            ->Set(env.local(), v8_str("test_object"), test_object)
            .FromJust());
  CompileRun(
      "function test() {"
      "  test_object.accessor;"
      "};"
      "%PrepareFunctionForOptimization(test);"
      "try { test() } catch(e) {}"
      "try { test() } catch(e) {}"
      "%OptimizeFunctionOnNextCall(test);"
      "test()");
}

THREADED_TEST(HulIgennem) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Primitive> undef = v8::Undefined(isolate);
  Local<String> undef_str = undef->ToString(env.local()).ToLocalChecked();
  size_t buffer_size = undef_str->Utf8LengthV2(isolate) + 1;
  char* value = i::NewArray<char>(buffer_size);
  undef_str->WriteUtf8V2(isolate, value, buffer_size,
                         String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp(value, "undefined"));
  i::DeleteArray(value);
}


THREADED_TEST(Access) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::Object> obj = v8::Object::New(isolate);
  Local<Value> foo_before =
      obj->Get(env.local(), v8_str("foo")).ToLocalChecked();
  CHECK(foo_before->IsUndefined());
  Local<String> bar_str = v8_str("bar");
  CHECK(obj->Set(env.local(), v8_str("foo"), bar_str).FromJust());
  Local<Value> foo_after =
      obj->Get(env.local(), v8_str("foo")).ToLocalChecked();
  CHECK(!foo_after->IsUndefined());
  CHECK(foo_after->IsString());
  CHECK(bar_str->Equals(env.local(), foo_after).FromJust());

  CHECK(obj->Set(env.local(), v8_str("foo"), bar_str).ToChecked());
  bool result;
  CHECK(obj->Set(env.local(), v8_str("foo"), bar_str).To(&result));
  CHECK(result);
}

THREADED_TEST(AccessWithReceiver) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::Object> a = CompileRun(R"(
  ({
    get prop() { return this },
    set prop(v) { this.got = v },
    val: 42,
  })
  )")
                            .As<v8::Object>();
  Local<v8::Object> b = v8::Object::New(isolate);

  CHECK(a->Get(env.local(), v8_str("missing")).ToLocalChecked()->IsUndefined());
  CHECK(a->Get(env.local(), v8_str("missing"), a)
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(a->Get(env.local(), v8_str("missing"), b)
            .ToLocalChecked()
            ->IsUndefined());

  CHECK(a->Get(env.local(), v8_str("val"))
            .ToLocalChecked()
            ->StrictEquals(v8_int(42)));
  CHECK(a->Get(env.local(), v8_str("val"), a)
            .ToLocalChecked()
            ->StrictEquals(v8_int(42)));
  CHECK(a->Get(env.local(), v8_str("val"), b)
            .ToLocalChecked()
            ->StrictEquals(v8_int(42)));

  CHECK(a->Get(env.local(), v8_str("prop")).ToLocalChecked()->StrictEquals(a));
  CHECK(
      a->Get(env.local(), v8_str("prop"), a).ToLocalChecked()->StrictEquals(a));
  CHECK(
      a->Get(env.local(), v8_str("prop"), b).ToLocalChecked()->StrictEquals(b));

  CHECK(a->Set(env.local(), v8_str("prop"), v8_int(10)).ToChecked());
  CHECK(a->Get(env.local(), v8_str("got"))
            .ToLocalChecked()
            ->StrictEquals(v8_int(10)));
  CHECK(b->Get(env.local(), v8_str("got")).ToLocalChecked()->IsUndefined());
  a->Delete(env.local(), v8_str("got")).ToChecked();

  CHECK(a->Set(env.local(), v8_str("prop"), v8_int(10), b).ToChecked());
  CHECK(a->Get(env.local(), v8_str("got")).ToLocalChecked()->IsUndefined());
  CHECK(b->Get(env.local(), v8_str("got"))
            .ToLocalChecked()
            ->StrictEquals(v8_int(10)));
}

THREADED_TEST(AccessElement) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::Object> obj = v8::Object::New(env->GetIsolate());
  Local<Value> before = obj->Get(env.local(), 1).ToLocalChecked();
  CHECK(before->IsUndefined());
  Local<String> bar_str = v8_str("bar");
  CHECK(obj->Set(env.local(), 1, bar_str).FromJust());
  Local<Value> after = obj->Get(env.local(), 1).ToLocalChecked();
  CHECK(!after->IsUndefined());
  CHECK(after->IsString());
  CHECK(bar_str->Equals(env.local(), after).FromJust());

  Local<v8::Array> value = CompileRun("[\"a\", \"b\"]").As<v8::Array>();
  CHECK(v8_str("a")
            ->Equals(env.local(), value->Get(env.local(), 0).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("b")
            ->Equals(env.local(), value->Get(env.local(), 1).ToLocalChecked())
            .FromJust());
}


THREADED_TEST(Script) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  const char* source = "1 + 2 + 3";
  Local<Script> script = v8_compile(source);
  CHECK_EQ(6, v8_run_int32value(script));
}


class TestResource: public String::ExternalStringResource {
 public:
  explicit TestResource(uint16_t* data, int* counter = nullptr,
                        bool owning_data = true)
      : data_(data), length_(0), counter_(counter), owning_data_(owning_data) {
    while (data[length_]) ++length_;
  }

  ~TestResource() override {
    if (owning_data_) i::DeleteArray(data_);
    if (counter_ != nullptr) ++*counter_;
  }

  const uint16_t* data() const override { return data_; }

  size_t length() const override { return length_; }

 private:
  uint16_t* data_;
  size_t length_;
  int* counter_;
  bool owning_data_;
};


class TestOneByteResource : public String::ExternalOneByteStringResource {
 public:
  explicit TestOneByteResource(const char* data, int* counter = nullptr,
                               size_t offset = 0)
      : orig_data_(data),
        data_(data + offset),
        length_(strlen(data) - offset),
        counter_(counter) {}

  ~TestOneByteResource() override {
    i::DeleteArray(orig_data_);
    if (counter_ != nullptr) ++*counter_;
  }

  const char* data() const override { return data_; }

  size_t length() const override { return length_; }

 private:
  const char* orig_data_;
  const char* data_;
  size_t length_;
  int* counter_;
};

TEST(ScriptUsingStringResource) {
  int dispose_count = 0;
  const char* c_source = "1 + 2 * 3";
  uint16_t* two_byte_source = AsciiToTwoByteString(c_source);
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    TestResource* resource = new TestResource(two_byte_source, &dispose_count);
    Local<String> source =
        String::NewExternalTwoByte(env->GetIsolate(), resource)
            .ToLocalChecked();
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    CHECK(source->IsExternalTwoByte());
    CHECK(source->IsExternal());
    CHECK_EQ(resource,
             static_cast<TestResource*>(source->GetExternalStringResource()));
    String::Encoding encoding = String::UNKNOWN_ENCODING;
    CHECK_EQ(static_cast<const String::ExternalStringResourceBase*>(resource),
             source->GetExternalStringResourceBase(&encoding));
    CHECK_EQ(String::TWO_BYTE_ENCODING, encoding);
    i::heap::InvokeMajorGC(CcTest::heap());
    CHECK_EQ(0, dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(ScriptUsingOneByteStringResource) {
  int dispose_count = 0;
  const char* c_source = "1 + 2 * 3";
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    TestOneByteResource* resource =
        new TestOneByteResource(i::StrDup(c_source), &dispose_count);
    Local<String> source =
        String::NewExternalOneByte(env->GetIsolate(), resource)
            .ToLocalChecked();
    CHECK(source->IsExternalOneByte());
    CHECK(source->IsExternal());
    CHECK(!source->IsExternalTwoByte());
    CHECK_EQ(static_cast<const String::ExternalStringResourceBase*>(resource),
             source->GetExternalOneByteStringResource());
    String::Encoding encoding = String::UNKNOWN_ENCODING;
    CHECK_EQ(static_cast<const String::ExternalStringResourceBase*>(resource),
             source->GetExternalStringResourceBase(&encoding));
    CHECK_EQ(String::ONE_BYTE_ENCODING, encoding);
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMajorGC(CcTest::heap());
    CHECK_EQ(0, dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(ScriptMakingExternalString) {
  int dispose_count = 0;
  uint16_t* two_byte_source = AsciiToTwoByteString(u"1 + 2 * 3 /* π */");
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source =
        String::NewFromTwoByte(env->GetIsolate(), two_byte_source)
            .ToLocalChecked();
    // Trigger GCs so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    CHECK(!source->IsExternalTwoByte());
    CHECK(!source->IsExternalOneByte());
    CHECK(!source->IsExternal());
    String::Encoding encoding = String::UNKNOWN_ENCODING;
    CHECK(!source->GetExternalStringResourceBase(&encoding));
    CHECK_EQ(String::TWO_BYTE_ENCODING, encoding);
    bool success = source->MakeExternal(
        env->GetIsolate(), new TestResource(two_byte_source, &dispose_count));
    CHECK(success);
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMajorGC(CcTest::heap());
    CHECK_EQ(0, dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(ScriptMakingExternalOneByteString) {
  int dispose_count = 0;
  const char* c_source = "1 + 2 * 3";
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source = v8_str(c_source);
    // Trigger GCs so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    bool success = source->MakeExternal(
        env->GetIsolate(),
        new TestOneByteResource(i::StrDup(c_source), &dispose_count));
    CHECK(success);
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMajorGC(CcTest::heap());
    CHECK_EQ(0, dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(MakingExternalStringConditions) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  if (!i::v8_flags.single_generation) {
    // Free some space in the new space so that we can check freshness.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
  }

  Local<String> tiny_local_string = v8_str("\xCF\x80");
  Local<String> local_string = v8_str("s1234\xCF\x80");

  CHECK(!tiny_local_string->IsOneByte());
  CHECK(!local_string->IsOneByte());

  if (!i::v8_flags.single_generation) {
    // We should refuse to externalize new space strings.
    CHECK(!local_string->CanMakeExternal(String::Encoding::TWO_BYTE_ENCODING));
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
  }
  // Old space strings should be accepted.
  CHECK(local_string->CanMakeExternal(String::Encoding::TWO_BYTE_ENCODING));

  // Tiny strings are not in-place externalizable when pointer compression is
  // enabled, but they are if the sandbox is enabled.
  CHECK_EQ(
      V8_ENABLE_SANDBOX_BOOL || i::kTaggedSize == i::kSystemPointerSize,
      tiny_local_string->CanMakeExternal(String::Encoding::TWO_BYTE_ENCODING));

  // Change of representation is not allowed.
  CHECK(!local_string->CanMakeExternal(String::Encoding::ONE_BYTE_ENCODING));
}


TEST(MakingExternalOneByteStringConditions) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  if (!i::v8_flags.single_generation) {
    // Free some space in the new space so that we can check freshness.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
  }

  Local<String> tiny_local_string = v8_str("s");
  Local<String> local_string = v8_str("s1234");

  CHECK(tiny_local_string->IsOneByte());
  CHECK(local_string->IsOneByte());

  // Single-character strings should not be externalized because they
  // are always in the RO-space.
  CHECK(
      !tiny_local_string->CanMakeExternal(String::Encoding::ONE_BYTE_ENCODING));
  if (!i::v8_flags.single_generation) {
    // We should refuse to externalize new space strings.
    CHECK(!local_string->CanMakeExternal(String::Encoding::ONE_BYTE_ENCODING));
    // Trigger GC so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    CHECK(!tiny_local_string->CanMakeExternal(
        String::Encoding::ONE_BYTE_ENCODING));
  }
  // Old space strings should be accepted.
  CHECK(local_string->CanMakeExternal(String::Encoding::ONE_BYTE_ENCODING));

  // Change of representation is not allowed.
  CHECK(!local_string->CanMakeExternal(String::Encoding::TWO_BYTE_ENCODING));
}


TEST(MakingExternalUnalignedOneByteString) {
  i::v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  CompileRun("function cons(a, b) { return a + b; }"
             "function slice(a) { return a.substring(1); }");
  // Create a cons string that will land in old pointer space.
  Local<String> cons = Local<String>::Cast(CompileRun(
      "cons('abcdefghijklm', 'nopqrstuvwxyz');"));
  // Create a sliced string that will land in old pointer space.
  Local<String> slice = Local<String>::Cast(CompileRun(
      "slice('abcdefghijklmnopqrstuvwxyz');"));

  // Trigger GCs so that the newly allocated string moves to old gen.
  i::heap::EmptyNewSpaceUsingGC(CcTest::heap());

  // Turn into external string with unaligned resource data.
  const char* c_cons = "_abcdefghijklmnopqrstuvwxyz";
  bool success = cons->MakeExternal(
      env->GetIsolate(),
      new TestOneByteResource(i::StrDup(c_cons), nullptr, 1));
  CHECK(success);
  const char* c_slice = "_bcdefghijklmnopqrstuvwxyz";
  success = slice->MakeExternal(
      env->GetIsolate(),
      new TestOneByteResource(i::StrDup(c_slice), nullptr, 1));
  CHECK(success);

  // Trigger GCs and force evacuation.
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap(), i::GCFlag::kReduceMemoryFootprint);
}

THREADED_TEST(UsingExternalString) {
  i::Factory* factory = CcTest::i_isolate()->factory();
  {
    v8::HandleScope scope(CcTest::isolate());
    uint16_t* two_byte_string = AsciiToTwoByteString("test string");
    Local<String> string =
        String::NewExternalTwoByte(CcTest::isolate(),
                                   new TestResource(two_byte_string))
            .ToLocalChecked();
    i::Handle<i::String> istring = v8::Utils::OpenHandle(*string);
    // Trigger GCs so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    i::DirectHandle<i::String> isymbol = factory->InternalizeString(istring);
    CHECK(IsInternalizedString(*isymbol));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}


THREADED_TEST(UsingExternalOneByteString) {
  i::Factory* factory = CcTest::i_isolate()->factory();
  {
    v8::HandleScope scope(CcTest::isolate());
    const char* one_byte_string = "test string";
    Local<String> string =
        String::NewExternalOneByte(
            CcTest::isolate(),
            new TestOneByteResource(i::StrDup(one_byte_string)))
            .ToLocalChecked();
    i::Handle<i::String> istring = v8::Utils::OpenHandle(*string);
    // Trigger GCs so that the newly allocated string moves to old gen.
    i::heap::EmptyNewSpaceUsingGC(CcTest::heap());
    i::DirectHandle<i::String> isymbol = factory->InternalizeString(istring);
    CHECK(IsInternalizedString(*isymbol));
  }
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}


class RandomLengthResource : public v8::String::ExternalStringResource {
 public:
  explicit RandomLengthResource(int length) : length_(length) {}
  const uint16_t* data() const override { return string_; }
  size_t length() const override { return length_; }

 private:
  uint16_t string_[10];
  int length_;
};


class RandomLengthOneByteResource
    : public v8::String::ExternalOneByteStringResource {
 public:
  explicit RandomLengthOneByteResource(int length) : length_(length) {}
  const char* data() const override { return string_; }
  size_t length() const override { return length_; }

 private:
  char string_[10];
  int length_;
};


THREADED_TEST(NewExternalForVeryLongString) {
  auto isolate = CcTest::isolate();
  {
    v8::HandleScope scope(isolate);
    v8::TryCatch try_catch(isolate);
    RandomLengthOneByteResource r(1 << 30);
    v8::MaybeLocal<v8::String> maybe_str =
        v8::String::NewExternalOneByte(isolate, &r);
    CHECK(maybe_str.IsEmpty());
    CHECK(!try_catch.HasCaught());
  }

  {
    v8::HandleScope scope(isolate);
    v8::TryCatch try_catch(isolate);
    RandomLengthResource r(1 << 30);
    v8::MaybeLocal<v8::String> maybe_str =
        v8::String::NewExternalTwoByte(isolate, &r);
    CHECK(maybe_str.IsEmpty());
    CHECK(!try_catch.HasCaught());
  }
}

TEST(ScavengeExternalString) {
  i::ManualGCScope manual_gc_scope;
  i::v8_flags.stress_compaction = false;
  i::v8_flags.gc_global = false;

  int dispose_count = 0;
  bool in_young_generation = false;
  {
    v8::HandleScope scope(CcTest::isolate());
    uint16_t* two_byte_string = AsciiToTwoByteString("test string");
    Local<String> string =
        String::NewExternalTwoByte(
            CcTest::isolate(),
            new TestResource(two_byte_string, &dispose_count))
            .ToLocalChecked();
    i::DirectHandle<i::String> istring = v8::Utils::OpenDirectHandle(*string);
    i::heap::InvokeMinorGC(CcTest::heap());
    in_young_generation = i::HeapLayout::InYoungGeneration(*istring);
    CHECK_IMPLIES(!in_young_generation,
                  CcTest::heap()->old_space()->Contains(*istring));
    CHECK_EQ(0, dispose_count);
  }
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    in_young_generation ? i::heap::InvokeMinorGC(CcTest::heap())
                        : i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}

TEST(ScavengeExternalOneByteString) {
  i::ManualGCScope manual_gc_scope;
  i::v8_flags.stress_compaction = false;
  i::v8_flags.gc_global = false;

  int dispose_count = 0;
  bool in_young_generation = false;
  {
    v8::HandleScope scope(CcTest::isolate());
    const char* one_byte_string = "test string";
    Local<String> string =
        String::NewExternalOneByte(
            CcTest::isolate(),
            new TestOneByteResource(i::StrDup(one_byte_string), &dispose_count))
            .ToLocalChecked();
    i::DirectHandle<i::String> istring = v8::Utils::OpenDirectHandle(*string);
    i::heap::InvokeMinorGC(CcTest::heap());
    in_young_generation = i::HeapLayout::InYoungGeneration(*istring);
    CHECK_IMPLIES(!in_young_generation,
                  CcTest::heap()->old_space()->Contains(*istring));
    CHECK_EQ(0, dispose_count);
  }
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    in_young_generation ? i::heap::InvokeMinorGC(CcTest::heap())
                        : i::heap::InvokeMajorGC(CcTest::heap());
  }
  CHECK_EQ(1, dispose_count);
}


class TestOneByteResourceWithDisposeControl : public TestOneByteResource {
 public:
  // Only used by non-threaded tests, so it can use static fields.
  static int dispose_calls;
  static int dispose_count;

  TestOneByteResourceWithDisposeControl(const char* data, bool dispose)
      : TestOneByteResource(data, &dispose_count), dispose_(dispose) {}

  void Dispose() override {
    ++dispose_calls;
    if (dispose_) delete this;
  }
 private:
  bool dispose_;
};


int TestOneByteResourceWithDisposeControl::dispose_count = 0;
int TestOneByteResourceWithDisposeControl::dispose_calls = 0;


TEST(ExternalStringWithDisposeHandling) {
  const char* c_source = "1 + 2 * 3";

  // Use a stack allocated external string resource allocated object.
  TestOneByteResourceWithDisposeControl::dispose_count = 0;
  TestOneByteResourceWithDisposeControl::dispose_calls = 0;
  TestOneByteResourceWithDisposeControl res_stack(i::StrDup(c_source), false);
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source =
        String::NewExternalOneByte(env->GetIsolate(), &res_stack)
            .ToLocalChecked();
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
    CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_calls);
  CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);

  // Use a heap allocated external string resource allocated object.
  TestOneByteResourceWithDisposeControl::dispose_count = 0;
  TestOneByteResourceWithDisposeControl::dispose_calls = 0;
  TestOneByteResource* res_heap =
      new TestOneByteResourceWithDisposeControl(i::StrDup(c_source), true);
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    Local<String> source =
        String::NewExternalOneByte(env->GetIsolate(), res_heap)
            .ToLocalChecked();
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(7, value->Int32Value(env.local()).FromJust());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
    CHECK_EQ(0, TestOneByteResourceWithDisposeControl::dispose_count);
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_calls);
  CHECK_EQ(1, TestOneByteResourceWithDisposeControl::dispose_count);
}


THREADED_TEST(StringConcat) {
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);
    const char* one_byte_string_1 = "function a_times_t";
    const char* two_byte_string_1 = "wo_plus_b(a, b) {return ";
    const char* one_byte_extern_1 = "a * 2 + b;} a_times_two_plus_b(4, 8) + ";
    const char* two_byte_extern_1 = "a_times_two_plus_b(4, 8) + ";
    const char* one_byte_string_2 = "a_times_two_plus_b(4, 8) + ";
    const char* two_byte_string_2 = "a_times_two_plus_b(4, 8) + ";
    const char* two_byte_extern_2 = "a_times_two_plus_b(1, 2);";
    Local<String> left = v8_str(one_byte_string_1);

    uint16_t* two_byte_source = AsciiToTwoByteString(two_byte_string_1);
    Local<String> right =
        String::NewFromTwoByte(env->GetIsolate(), two_byte_source)
            .ToLocalChecked();
    i::DeleteArray(two_byte_source);

    Local<String> source = String::Concat(isolate, left, right);
    right = String::NewExternalOneByte(
                env->GetIsolate(),
                new TestOneByteResource(i::StrDup(one_byte_extern_1)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    right = String::NewExternalTwoByte(
                env->GetIsolate(),
                new TestResource(AsciiToTwoByteString(two_byte_extern_1)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    right = v8_str(one_byte_string_2);
    source = String::Concat(isolate, source, right);

    two_byte_source = AsciiToTwoByteString(two_byte_string_2);
    right = String::NewFromTwoByte(env->GetIsolate(), two_byte_source)
                .ToLocalChecked();
    i::DeleteArray(two_byte_source);

    source = String::Concat(isolate, source, right);
    right = String::NewExternalTwoByte(
                env->GetIsolate(),
                new TestResource(AsciiToTwoByteString(two_byte_extern_2)))
                .ToLocalChecked();
    source = String::Concat(isolate, source, right);
    Local<Script> script = v8_compile(source);
    Local<Value> value = script->Run(env.local()).ToLocalChecked();
    CHECK(value->IsNumber());
    CHECK_EQ(68, value->Int32Value(env.local()).FromJust());
  }
  CcTest::i_isolate()->compilation_cache()->Clear();
  i::heap::InvokeMajorGC(CcTest::heap());
  i::heap::InvokeMajorGC(CcTest::heap());
}


THREADED_TEST(GlobalProperties) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::Object> global = env->Global();
  CHECK(global->Set(env.local(), v8_str("pi"), v8_num(3.1415926)).FromJust());
  Local<Value> pi = global->Get(env.local(), v8_str("pi")).ToLocalChecked();
  CHECK_EQ(3.1415926, pi->NumberValue(env.local()).FromJust());
}


static void handle_callback_impl(const v8::FunctionCallbackInfo<Value>& info,
                                 i::Address callback) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CHECK(i::ValidateCallbackInfo(info));
  CheckReturnValue(info, callback);
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(102));
}


static void handle_callback(const v8::FunctionCallbackInfo<Value>& info) {
  return handle_callback_impl(info, FUNCTION_ADDR(handle_callback));
}


static void handle_callback_2(const v8::FunctionCallbackInfo<Value>& info) {
  return handle_callback_impl(info, FUNCTION_ADDR(handle_callback_2));
}

static void construct_callback(
    const v8::FunctionCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(construct_callback));
  CHECK(
      info.This()
          ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("x"), v8_num(1))
          .FromJust());
  CHECK(
      info.This()
          ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("y"), v8_num(2))
          .FromJust());
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(info.This());
}

static void Return239Callback(Local<Name> name,
                              const v8::PropertyCallbackInfo<Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(Return239Callback));
  info.GetReturnValue().Set(v8_str("bad value"));
  info.GetReturnValue().Set(v8_num(239));
}

template<typename Handler>
static void TestFunctionTemplateInitializer(Handler handler,
                                            Handler handler_2) {
  // Test constructor calls.
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);

    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handler);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj()");
    for (int i = 0; i < 30; i++) {
      CHECK_EQ(102, v8_run_int32value(script));
    }
  }
  // Use SetCallHandler to initialize a function template, should work like
  // the previous one.
  {
    LocalContext env;
    v8::Isolate* isolate = env->GetIsolate();
    v8::HandleScope scope(isolate);

    Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
    fun_templ->SetCallHandler(handler_2);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj()");
    for (int i = 0; i < 30; i++) {
      CHECK_EQ(102, v8_run_int32value(script));
    }
  }
}

template<typename Constructor, typename Accessor>
static void TestFunctionTemplateAccessor(Constructor constructor,
                                         Accessor accessor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate, constructor);
  fun_templ->PrototypeTemplate()->Set(
      v8::Symbol::GetToStringTag(isolate), v8_str("funky"),
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));
  fun_templ->InstanceTemplate()->SetNativeDataProperty(v8_str("m"), accessor);

  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
  Local<Value> result = CompileRun("(new obj()).toString()");
  CHECK(v8_str("[object funky]")->Equals(env.local(), result).FromJust());
  CompileRun("var obj_instance = new obj();");

  Local<Script> script = v8_compile("obj_instance.x");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(1, v8_run_int32value(script));
  }
  script = v8_compile("obj_instance.m");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(239, v8_run_int32value(script));
  }
}


THREADED_PROFILED_TEST(FunctionTemplate) {
  TestFunctionTemplateInitializer(handle_callback, handle_callback_2);
  TestFunctionTemplateAccessor(construct_callback, Return239Callback);
}

static void FunctionCallbackForProxyTest(
    const v8::FunctionCallbackInfo<Value>& info) {
  info.GetReturnValue().Set(info.This());
}

THREADED_TEST(FunctionTemplateWithProxy) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(isolate, FunctionCallbackForProxyTest);
  v8::Local<v8::Function> function =
      function_template->GetFunction(env.local()).ToLocalChecked();
  CHECK((*env)->Global()->Set(env.local(), v8_str("f"), function).FromJust());
  v8::Local<v8::Value> proxy =
      CompileRun("var proxy = new Proxy({}, {}); proxy");
  CHECK(proxy->IsProxy());

  v8::Local<v8::Value> result = CompileRun("f(proxy)");
  CHECK(result->Equals(env.local(), (*env)->Global()).FromJust());

  result = CompileRun("f.call(proxy)");
  CHECK(result->Equals(env.local(), proxy).FromJust());

  result = CompileRun("Reflect.apply(f, proxy, [1])");
  CHECK(result->Equals(env.local(), proxy).FromJust());
}

static void SimpleCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(SimpleCallback));
  info.GetReturnValue().Set(v8_num(51423 + info.Length()));
}


template<typename Callback>
static void TestSimpleCallback(Callback callback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->Set(isolate, "callback",
                       v8::FunctionTemplate::New(isolate, callback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  CHECK((*env)
            ->Global()
            ->Set(env.local(), v8_str("callback_object"), object)
            .FromJust());
  v8::Local<v8::Script> script;
  script = v8_compile("callback_object.callback(17)");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(51424, v8_run_int32value(script));
  }
  script = v8_compile("callback_object.callback(17, 24)");
  for (int i = 0; i < 30; i++) {
    CHECK_EQ(51425, v8_run_int32value(script));
  }
}


THREADED_PROFILED_TEST(SimpleCallback) {
  TestSimpleCallback(SimpleCallback);
}


template<typename T>
void FastReturnValueCallback(const v8::FunctionCallbackInfo<v8::Value>& info);

// constant return values
static int32_t fast_return_value_int32 = 471;
static uint32_t fast_return_value_uint32 = 571;
static const double kFastReturnValueDouble = 2.7;
// variable return values
static bool fast_return_value_bool = false;
enum ReturnValueOddball {
  kNullReturnValue,
  kUndefinedReturnValue,
  kEmptyStringReturnValue
};
static ReturnValueOddball fast_return_value_void;
static bool fast_return_value_object_is_empty = false;

// Helper function to avoid compiler error: insufficient contextual information
// to determine type when applying FUNCTION_ADDR to a template function.
static i::Address address_of(v8::FunctionCallback callback) {
  return FUNCTION_ADDR(callback);
}

template<>
void FastReturnValueCallback<int32_t>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<int32_t>));
  info.GetReturnValue().Set(fast_return_value_int32);
}

template<>
void FastReturnValueCallback<uint32_t>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<uint32_t>));
  info.GetReturnValue().Set(fast_return_value_uint32);
}

template<>
void FastReturnValueCallback<double>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<double>));
  info.GetReturnValue().Set(kFastReturnValueDouble);
}

template<>
void FastReturnValueCallback<bool>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<bool>));
  info.GetReturnValue().Set(fast_return_value_bool);
}

template<>
void FastReturnValueCallback<void>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CheckReturnValue(info, address_of(FastReturnValueCallback<void>));
  switch (fast_return_value_void) {
    case kNullReturnValue:
      // Ensure that setting return value to empty handle does not break
      // static roots optimization.
      info.GetReturnValue().Set(v8::Local<v8::Value>{});
      info.GetReturnValue().SetNull();
      break;
    case kUndefinedReturnValue: {
      // Ensure that setting return value to Smi handle does not break
      // static roots optimization.
      info.GetReturnValue().Set(v8::Integer::New(info.GetIsolate(), 153));
      info.GetReturnValue().SetUndefined();
      break;
    }
    case kEmptyStringReturnValue:
      // Ensure that setting return value to Smi does not break
      // static roots optimization.
      info.GetReturnValue().Set(142);
      info.GetReturnValue().SetEmptyString();
      break;
  }
}

template<>
void FastReturnValueCallback<Object>(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Object> object;
  if (!fast_return_value_object_is_empty) {
    object = Object::New(info.GetIsolate());
  }
  info.GetReturnValue().Set(object);
}

template <typename T>
Local<Value> TestFastReturnValues() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::EscapableHandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  v8::FunctionCallback callback = &FastReturnValueCallback<T>;
  object_template->Set(isolate, "callback",
                       v8::FunctionTemplate::New(isolate, callback));
  v8::Local<v8::Object> object =
      object_template->NewInstance(env.local()).ToLocalChecked();
  CHECK((*env)
            ->Global()
            ->Set(env.local(), v8_str("callback_object"), object)
            .FromJust());
  return scope.Escape(CompileRun("callback_object.callback()"));
}


THREADED_PROFILED_TEST(FastReturnValues) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> value;
  // check int32_t and uint32_t
  int32_t int_values[] = {
      0, 234, -723,
      i::Smi::kMinValue, i::Smi::kMaxValue
  };
  for (size_t i = 0; i < arraysize(int_values); i++) {
    for (int modifier = -1; modifier <= 1; modifier++) {
      int int_value = v8::base::AddWithWraparound(int_values[i], modifier);
      // check int32_t
      fast_return_value_int32 = int_value;
      value = TestFastReturnValues<int32_t>();
      CHECK(value->IsInt32());
      CHECK_EQ(fast_return_value_int32,
               value->Int32Value(env.local()).FromJust());
      // check uint32_t
      fast_return_value_uint32 = static_cast<uint32_t>(int_value);
      value = TestFastReturnValues<uint32_t>();
      CHECK(value->IsUint32());
      CHECK_EQ(fast_return_value_uint32,
               value->Uint32Value(env.local()).FromJust());
    }
  }
  // check double
  value = TestFastReturnValues<double>();
  CHECK(value->IsNumber());
  CHECK_EQ(kFastReturnValueDouble,
           value->ToNumber(env.local()).ToLocalChecked()->Value());
  // check bool values
  for (int i = 0; i < 2; i++) {
    fast_return_value_bool = i == 0;
    value = TestFastReturnValues<bool>();
    CHECK(value->IsBoolean());
    CHECK_EQ(fast_return_value_bool, value->BooleanValue(isolate));
  }
  // check oddballs
  ReturnValueOddball oddballs[] = {
      kNullReturnValue,
      kUndefinedReturnValue,
      kEmptyStringReturnValue
  };
  for (size_t i = 0; i < arraysize(oddballs); i++) {
    fast_return_value_void = oddballs[i];
    value = TestFastReturnValues<void>();
    switch (fast_return_value_void) {
      case kNullReturnValue:
        CHECK(value->IsNull());
        break;
      case kUndefinedReturnValue:
        CHECK(value->IsUndefined());
        break;
      case kEmptyStringReturnValue:
        CHECK(value->IsString());
        CHECK_EQ(0, v8::String::Cast(*value)->Length());
        break;
    }
  }
  // check handles
  fast_return_value_object_is_empty = false;
  value = TestFastReturnValues<Object>();
  CHECK(value->IsObject());
  fast_return_value_object_is_empty = true;
  value = TestFastReturnValues<Object>();
  CHECK(value->IsUndefined());
}


THREADED_TEST(FunctionTemplateSetLength) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  {
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback, Local<v8::Value>(),
                                  Local<v8::Signature>(), 23);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(23, v8_run_int32value(script));
  }
  {
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback);
    fun_templ->SetLength(22);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(22, v8_run_int32value(script));
  }
  {
    // Without setting length it defaults to 0.
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(isolate, handle_callback);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()->Set(env.local(), v8_str("obj"), fun).FromJust());
    Local<Script> script = v8_compile("obj.length");
    CHECK_EQ(0, v8_run_int32value(script));
  }
}


static void* expected_ptr;
static void callback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  void* ptr = v8::External::Cast(*args.Data())->Value();
  CHECK_EQ(expected_ptr, ptr);
  args.GetReturnValue().Set(true);
}


static void TestExternalPointerWrapping() {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  int* ptr = new int;
  expected_ptr = ptr;

  v8::Local<v8::Value> data = v8::External::New(isolate, expected_ptr);

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  CHECK(obj->Set(env.local(), v8_str("func"),
                 v8::FunctionTemplate::New(isolate, callback, data)
                     ->GetFunction(env.local())
                     .ToLocalChecked())
            .FromJust());
  CHECK(env->Global()->Set(env.local(), v8_str("obj"), obj).FromJust());

  CHECK(CompileRun("function foo() {\n"
                   "  for (var i = 0; i < 13; i++) obj.func();\n"
                   "}\n"
                   "foo(), true")
            ->BooleanValue(isolate));

  delete ptr;
}


THREADED_TEST(ExternalWrap) {
  // Check heap allocated object.
  int* ptr = new int;
  expected_ptr = ptr;
  TestExternalPointerWrapping();
  delete ptr;

  // Check stack allocated object.
  int foo;
  expected_ptr = &foo;
  TestExternalPointerWrapping();

  // Check not aligned addresses.
  const int n = 100;
  char* s = new char[n];
  for (int i = 0; i < n; i++) {
    expected_ptr = s + i;
    TestExternalPointerWrapping();
  }

  delete[] s;

  // Check several invalid addresses.
  expected_ptr = reinterpret_cast<void*>(1);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEF);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEF + 1);
  TestExternalPointerWrapping();

#if defined(V8_HOST_ARCH_X64)
  // Check a value with a leading 1 bit in x64 Smi encoding.
  expected_ptr = reinterpret_cast<void*>(0x400000000);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEFDEADBEEF);
  TestExternalPointerWrapping();

  expected_ptr = reinterpret_cast<void*>(0xDEADBEEFDEADBEEF + 1);
  TestExternalPointerWrapping();
#endif
}


THREADED_TEST(FindInstanceInPrototypeChain) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> base = v8::FunctionTemplate::New(isolate);
  Local<v8::FunctionTemplate> derived = v8::FunctionTemplate::New(isolate);
  Local<v8::FunctionTemplate> other = v8::FunctionTemplate::New(isolate);
  derived->Inherit(base);

  Local<v8::Function> base_function =
      base->GetFunction(env.local()).ToLocalChecked();
  Local<v8::Function> derived_function =
      derived->GetFunction(env.local()).ToLocalChecked();
  Local<v8::Function> other_function =
      other->GetFunction(env.local()).ToLocalChecked();

  Local<v8::Object> base_instance =
      base_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> derived_instance =
      derived_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> derived_instance2 =
      derived_function->NewInstance(env.local()).ToLocalChecked();
  Local<v8::Object> other_instance =
      other_function->NewInstance(env.local()).ToLocalChecked();
  CHECK(
      derived_instance2->Set(env.local(), v8_str("__proto__"), derived_instance)
          .FromJust());
  CHECK(other_instance->Set(env.local(), v8_str("__proto__"), derived_instance2)
            .FromJust());

  // base_instance is only an instance of base.
  CHECK(base_instance->Equals(env.local(),
                              base_instance->FindInstanceInPrototypeChain(base))
            .FromJust());
  CHECK(base_instance->FindInstanceInPrototypeChain(derived).IsEmpty());
  CHECK(base_instance->FindInstanceInPrototypeChain(other).IsEmpty());

  // derived_instance is an instance of base and derived.
  CHECK(derived_instance->Equals(env.local(),
                                 derived_instance->FindInstanceInPrototypeChain(
                                     base))
            .FromJust());
  CHECK(derived_instance->Equals(env.local(),
                                 derived_instance->FindInstanceInPrototypeChain(
                                     derived))
            .FromJust());
  CHECK(derived_instance->FindInstanceInPrototypeChain(other).IsEmpty());

  // other_instance is an instance of other and its immediate
  // prototype derived_instance2 is an instance of base and derived.
  // Note, derived_instance is an instance of base and derived too,
  // but it comes after derived_instance2 in the prototype chain of
  // other_instance.
  CHECK(derived_instance2->Equals(
                             env.local(),
                             other_instance->FindInstanceInPrototypeChain(base))
            .FromJust());
  CHECK(derived_instance2->Equals(env.local(),
                                  other_instance->FindInstanceInPrototypeChain(
                                      derived))
            .FromJust());
  CHECK(other_instance->Equals(
                          env.local(),
                          other_instance->FindInstanceInPrototypeChain(other))
            .FromJust());
}

THREADED_TEST(FindInstanceInPrototypeChainWithProxy) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::Object> proxy =
      CompileRun("var proxy = new Proxy({}, {}); proxy").As<Object>();
  CHECK(proxy->FindInstanceInPrototypeChain(function_template).IsEmpty());
}

THREADED_TEST(TinyInteger) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  int32_t value = 239;
  Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigSmiInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  int32_t value = i::Smi::kMaxValue;
  // We cannot add one to a Smi::kMaxValue without wrapping.
  if (i::SmiValuesAre31Bits()) {
    CHECK(i::Smi::IsValid(value));
    CHECK(!i::Smi::IsValid(value + 1));

    Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
    CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
  }
}


THREADED_TEST(BigInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  // We cannot add one to a Smi::kMaxValue without wrapping.
  if (i::SmiValuesAre31Bits()) {
    // The casts allow this to compile, even if Smi::kMaxValue is 2^31-1.
    // The code will not be run in that case, due to the "if" guard.
    int32_t value =
        static_cast<int32_t>(static_cast<uint32_t>(i::Smi::kMaxValue) + 1);
    CHECK_GT(value, i::Smi::kMaxValue);
    CHECK(!i::Smi::IsValid(value));

    Local<v8::Integer> value_obj = v8::Integer::New(isolate, value);
    CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
  }
}


THREADED_TEST(TinyUnsignedInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = 239;

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigUnsignedSmiInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = static_cast<uint32_t>(i::Smi::kMaxValue);
  CHECK(i::Smi::IsValid(value));
  CHECK(!i::Smi::IsValid(value + 1));

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(BigUnsignedInteger) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Isolate* isolate = CcTest::isolate();

  uint32_t value = static_cast<uint32_t>(i::Smi::kMaxValue) + 1;
  CHECK(value > static_cast<uint32_t>(i::Smi::kMaxValue));
  CHECK(!i::Smi::IsValid(value));

  Local<v8::Integer> value_obj = v8::Integer::NewFromUnsigned(isolate, value);
  CHECK_EQ(static_cast<int64_t>(value), value_obj->Value());
}


THREADED_TEST(OutOfSignedRangeUnsignedInteger) {
  LocalContext env;
  v8::HandleSco
```