Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. They are also asking for clarification on several aspects related to V8 development:

1. **General Functionality:** What does this specific part of the test file do?
2. **Torque Source:** How to identify if a file is a V8 Torque source.
3. **JavaScript Relationship:** If the code relates to JavaScript features, provide JavaScript examples.
4. **Code Logic Reasoning:** If there's logical flow, give hypothetical input and output.
5. **Common Programming Errors:** Point out potential mistakes developers might make when using the tested API.
6. **Summary:** A concise summary of the code's purpose.

Let's break down the provided C++ code:

* **Includes:** The file includes various V8 headers (`v8-date.h`, `v8-extension.h`, etc.) and internal V8 headers (`api-inl.h`, `heap-inl.h`, etc.). This immediately suggests it's testing V8's C++ API.
* **Test Macros:** The `TEST()` and `THREADED_TEST()` macros indicate this is a unit test file within the V8 project.
* **`RunWithProfiler` function:** This function seems to set up and tear down the V8 CPU profiler around a given test function.
* **`IncrementingSignatureCallback`:** This function is a V8 FunctionCallback that increments a counter and checks the receiver of the call. This suggests it's testing function signatures and how they enforce receiver types.
* **Various `THREADED_TEST` functions:** These test different aspects of the V8 API, including:
    * `Handles`: Basic handle and context manipulation.
    * `IsolateOfContext`: Testing the relationship between isolates and contexts.
    * `ReceiverSignature`:  Testing how function signatures restrict valid receivers.
    * `Regress1188563`: A regression test for a specific bug.
    * `HulIgennem`:  Likely a simple test related to undefined values.
    * `Access`, `AccessWithReceiver`, `AccessElement`: Testing object property access (get/set).
    * `Script`: Basic script compilation and execution.
    * `ScriptUsingStringResource`, `ScriptUsingOneByteStringResource`, `ScriptMakingExternalString`, `ScriptMakingExternalOneByteString`, `MakingExternalStringConditions`, `MakingExternalOneByteStringConditions`, `MakingExternalUnalignedOneByteString`, `UsingExternalString`, `UsingExternalOneByteString`: Tests related to creating and using external strings.

**Plan:**

1. **Identify the core function:** The file `test-api.cc` clearly tests the V8 C++ API.
2. **Torque Check:** Explain the `.tq` extension.
3. **JavaScript Connection:** Show JavaScript equivalents for the tested C++ API functionalities.
4. **Logic Reasoning:** For a simple test like `Handles`, demonstrate input/output.
5. **Common Errors:**  Provide examples of mistakes when using V8's API.
6. **Summarize:**  Combine the findings into a concise summary.
好的，让我们来分析一下 `v8/test/cctest/test-api.cc` 这个文件的功能。

**文件功能归纳：**

`v8/test/cctest/test-api.cc` 是 V8 JavaScript 引擎的一个测试文件，专注于测试 **V8 C++ API 的各种功能和特性**。  它通过编写一系列的 C++ 测试用例，来验证 V8 提供的 C++ 接口是否按照预期工作。 这些测试涵盖了 V8 API 的多个方面，包括：

* **基本概念：**  `Isolate`（隔离区）, `Context`（上下文）, `Handle`（句柄） 的创建和使用。
* **脚本执行：**  编译和运行 JavaScript 代码。
* **对象操作：**  创建、访问和修改 JavaScript 对象和属性。
* **函数调用：**  创建和调用 JavaScript 函数，包括带有签名的函数。
* **字符串处理：**  创建和使用不同类型的字符串，特别是外部字符串资源。
* **模板和实例：**  使用 `FunctionTemplate` 和 `ObjectTemplate` 创建对象和函数。
* **异常处理：**  通过 `TryCatch` 捕获 JavaScript 执行时的异常。
* **内存管理：**  涉及垃圾回收 (`InvokeMajorGC`) 和字符串外部化。
* **性能分析：**  使用 `CpuProfiler` 进行性能分析。
* **其他特性：**  例如，测试特定的回归错误 (`Regress1188563`)。

**关于 .tq 结尾的文件：**

如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。 Torque 是 V8 使用的一种领域特定语言，用于定义 V8 内部的运行时函数和内置对象。  这个文件目前的名称是 `.cc`，所以它是 C++ 源代码。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/test/cctest/test-api.cc` 中测试的 C++ API 都是 V8 引擎暴露给外部使用的接口，用于将 V8 集成到其他应用程序中。  这些 API 的功能直接对应于 JavaScript 的各种语言特性。

以下是一些 JavaScript 功能以及它们在 `test-api.cc` 中可能测试的 C++ API 的对应示例：

1. **JavaScript 变量和作用域：**

   ```javascript
   var x = 10;
   console.log(x);
   ```

   对应的 C++ API 测试可能会涉及到 `v8::Context` 的创建，在上下文中创建变量，并获取变量的值。例如，`THREADED_TEST(Handles)` 中就展示了 `Local<Context>` 的使用。

2. **JavaScript 对象和属性访问：**

   ```javascript
   const obj = { name: "Alice", age: 30 };
   console.log(obj.name);
   obj.age = 31;
   ```

   对应的 C++ API 测试会使用 `v8::Object::New()`, `v8::Object::Set()`, `v8::Object::Get()` 等方法。  `THREADED_TEST(Access)` 和 `THREADED_TEST(AccessElement)` 就演示了这些 API 的用法。

3. **JavaScript 函数定义和调用：**

   ```javascript
   function greet(name) {
     return "Hello, " + name;
   }
   console.log(greet("Bob"));
   ```

   对应的 C++ API 测试会使用 `v8::FunctionTemplate`, `v8::Function::NewInstance()`, `v8::Function::Call()` 等。`THREADED_TEST(ReceiverSignature)` 和 `IncrementingSignatureCallback` 就涉及了函数模板和回调。

4. **JavaScript 字符串：**

   ```javascript
   const message = "Hello";
   console.log(message.length);
   ```

   对应的 C++ API 测试会使用 `v8::String::NewFromUtf8()`, `v8::String::Length()`, 以及 `v8::String::NewExternal()` 来测试外部字符串资源，如 `TEST(ScriptUsingStringResource)` 所示。

5. **JavaScript 异常处理：**

   ```javascript
   try {
     throw new Error("Something went wrong");
   } catch (e) {
     console.error(e.message);
   }
   ```

   对应的 C++ API 测试会使用 `v8::TryCatch` 来捕获 JavaScript 抛出的异常，例如在 `TestSignatureLooped` 和 `TestSignatureOptimized` 中就使用了 `v8::TryCatch`。

**代码逻辑推理及假设输入与输出：**

让我们以 `THREADED_TEST(Handles)` 为例进行代码逻辑推理：

**假设输入：** 无明显的外部输入，主要是 V8 内部状态。

**代码逻辑：**

1. 创建一个 `v8::HandleScope`，用于管理 V8 对象的生命周期。
2. 创建一个 `Local<Context>` 类型的 `local_env`。
3. 在一个临时的 `LocalContext env` 中初始化 `local_env`。
4. 检查 `local_env` 是否仍然有效（非空）。
5. 进入 `local_env` 上下文。
6. 创建一个 `v8::Local<v8::Primitive>` 类型的 `undef`，表示 JavaScript 的 `undefined` 值。
7. 检查 `undef` 是否有效和是否是 `undefined`。
8. 定义一个 JavaScript 源代码字符串 `"1 + 2 + 3"`。
9. 使用 `v8_compile` 编译源代码得到 `Local<Script>`。
10. 使用 `v8_run_int32value` 运行脚本，并检查结果是否为 6。
11. 退出 `local_env` 上下文。

**预期输出：**  如果所有断言 (`CHECK`) 都通过，则测试成功。 具体来说：

* `!local_env.IsEmpty()` 应该为 `true`。
* `!undef.IsEmpty()` 应该为 `true`。
* `undef->IsUndefined()` 应该为 `true`。
* `v8_run_int32value(script)` 的返回值应该等于 `6`。

**用户常见的编程错误示例：**

当使用 V8 C++ API 时，开发者可能会犯以下常见的编程错误，而 `test-api.cc` 中的测试可能旨在预防或检测这些错误：

1. **忘记使用 `HandleScope`：**  V8 的对象由句柄管理。如果忘记创建 `HandleScope`，可能会导致内存泄漏或对象过早释放。

   ```c++
   // 错误示例：忘记使用 HandleScope
   v8::Isolate* isolate = CcTest::isolate();
   v8::Local<v8::String> str = v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked();
   // 如果 str 超出作用域，但没有 HandleScope，可能导致问题。
   ```

2. **不正确地管理 `Local` 句柄的生命周期：** `Local` 句柄在超出其作用域后会自动释放。如果在一个函数中创建了 `Local` 句柄并希望在函数外部使用，需要将其转换为 `Persistent` 句柄，并手动管理其生命周期。

   ```c++
   // 错误示例：在函数外部使用局部句柄
   v8::Local<v8::String> createString(v8::Isolate* isolate) {
     v8::HandleScope scope(isolate);
     return v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked();
   }

   // 在其他地方调用：
   v8::Isolate* isolate = CcTest::isolate();
   v8::Local<v8::String> myString = createString(isolate);
   // myString 可能已经失效，因为 createString 函数的 HandleScope 已经结束。
   ```

3. **在错误的 `Context` 中操作对象：**  V8 的对象属于特定的 `Context`。尝试在一个 `Context` 中创建的对象在另一个 `Context` 中使用可能会导致错误。

   ```c++
   // 错误示例：在错误的 Context 中操作对象
   LocalContext env1;
   v8::Local<v8::Object> obj1 = v8::Object::New(env1->GetIsolate());

   LocalContext env2;
   // 尝试在 env2 中使用 obj1，可能会出错。
   env2->Global()->Set(env2.local(), v8_str("myObj"), obj1);
   ```

4. **不检查 API 调用的返回值：**  许多 V8 API 方法返回 `MaybeLocal` 或 `Maybe` 类型，表示操作可能失败。不检查返回值可能导致程序崩溃或行为异常。

   ```c++
   // 错误示例：不检查返回值
   LocalContext env;
   v8::Local<v8::Value> value;
   env->Global()->Get(env.local(), v8_str("nonExistentVariable")); // 应该使用 ToLocalChecked() 或 IsEmpty() 检查
   if (value->IsUndefined()) {
       // ...
   }
   ```

5. **在没有进入 `Context` 的 `Isolate` 上操作：**  许多 V8 操作需要在 `Context` 中进行。尝试在没有活动的 `Context` 的 `Isolate` 上执行这些操作会导致错误。

   ```c++
   // 错误示例：在没有 Context 的 Isolate 上操作
   v8::Isolate* isolate = CcTest::isolate();
   v8::Local<v8::String> str = v8::String::NewFromUtf8(isolate, "hello").ToLocalChecked(); // 可能会失败
   ```

**总结一下第 1 部分的功能：**

`v8/test/cctest/test-api.cc` 的第 1 部分（以及后续部分）的主要功能是 **系统地测试 V8 JavaScript 引擎的 C++ API 的正确性和稳定性**。 它涵盖了 API 的核心概念、对象操作、脚本执行、字符串处理、函数调用、异常处理等方面，并提供了一些关于如何正确使用 V8 API 以及避免常见编程错误的示例。  这些测试是确保 V8 引擎质量的关键组成部分。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共36部分，请归纳一下它的功能

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
            new TestOneByteResource(i::StrDup(
"""


```