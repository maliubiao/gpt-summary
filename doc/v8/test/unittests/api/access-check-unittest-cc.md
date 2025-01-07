Response:
Let's break down the thought process to analyze the C++ code and generate the explanation.

1. **Understand the Goal:** The request asks for the functionality of the `access-check-unittest.cc` file, whether it's Torque, its relation to JavaScript, examples, logic, and common errors.

2. **Initial Scan and Identification of Key Elements:**
   - The `#include` directives at the beginning point to V8 API headers (`v8-context.h`, `v8-function.h`, etc.) and testing frameworks (`gtest`, `gmock`). This immediately suggests it's a C++ unit test for V8's API related to access checks.
   - The `namespace v8 {` confirms it's V8-specific code.
   - The `class AccessCheckTest : public TestWithIsolate {` and `TEST_F(AccessCheckTest, ...)` structure strongly indicate the use of Google Test for unit testing.
   - The class name `AccessCheckTest` and the function names like `CheckCanRunScriptInContext`, `CheckCrossContextAccess`, `AccessCheck` (a function), and `SetAccessCheckCallbackAndHandler` are strong clues about the feature being tested.

3. **Infer the Core Functionality:** Based on the keywords and structure, the primary functionality being tested is **access checks** in V8. This likely involves scenarios where code in one context tries to access objects or properties in another context and how V8's access control mechanisms work.

4. **Detailed Examination of Test Cases:**  Now, go through each `TEST_F` function to understand the specific scenarios being tested:
   - `GetOwnPropertyDescriptor`: Tests how access checks interact with `Object.getOwnPropertyDescriptor` and calling the getter/setter in another context.
   - `InstantiatedLazyAccessorPairsHaveCorrectNativeContext`: Focuses on the native context of accessor pairs when they are lazily instantiated in different contexts, particularly in debug mode. This hints at a potential bug fix or subtle behavior related to contexts.
   - `AccessCheckWithInterceptor`: Tests the use of interceptors (`NamedGetter`, `NamedSetter`, etc.) in conjunction with access checks. This is a key part of V8's access control API.
   - `CallFunctionWithRemoteContextReceiver`:  Tests calling a function on an object from a "remote context."
   - `AccessCheckWithExceptionThrowingInterceptor`: Checks what happens when access check interceptors throw exceptions.
   - `NewRemoteContext`: Explores the functionality of `Context::NewRemoteContext` and how it interacts with access checks.
   - `NewRemoteInstance`: Tests the `NewRemoteInstance` method and access checks.

5. **Analyze Helper Functions and Classes:**
   - `AccessCheckTest`: The base class provides common setup and assertion helper functions like `CheckCanRunScriptInContext` and `CheckCrossContextAccess`.
   - `g_cross_context_int`: A global variable likely used for communication or tracking state across contexts during tests.
   - `AccessCheck(Local<Context> accessing_context, Local<Object> accessed_object, Local<Value> data)`: This function is a core part of the access check mechanism. It returns `false`, meaning access is denied. This is used to trigger the "failed access check" behavior.
   - `CompileRun`: A utility function to compile and run JavaScript code within a given context.
   - `NamedGetter`, `NamedSetter`, `IndexedGetter`, `IndexedSetter`, etc.: These are the interceptor functions that define custom behavior when properties are accessed. They demonstrate how developers can customize access control.

6. **Determine JavaScript Relevance and Provide Examples:** Many tests involve running JavaScript code (`RunJS`, `TryRunJS`). The core concept of access checks directly relates to JavaScript's security model and how scripts in different contexts can interact. Provide JavaScript examples that illustrate:
   - Basic cross-context access (failure without custom access checks).
   - How interceptors can allow specific cross-context access.
   - Scenarios that trigger access check failures.

7. **Identify Potential Torque Usage:** The prompt mentions `.tq` files. After examining the code, there's no direct indication of Torque being used *in this specific file*. The code is standard C++ using the V8 API. State that it's not a Torque file based on the `.cc` extension.

8. **Infer Logic and Provide Examples with Inputs and Outputs:** Focus on the `CheckCrossContextAccess` and `CheckCrossContextAccessWithException` functions. Explain the setup (two contexts, an object in one accessible from the other). Provide simple JavaScript code snippets that illustrate what happens (access denied, specific properties accessible via interceptors, exceptions being thrown). Since the `AccessCheck` function always returns `false`, the standard expectation is access denial unless an interceptor allows it.

9. **Identify Common Programming Errors:** Think about the implications of incorrect access check setup. Common errors include:
   - Forgetting to set up the access check callback.
   - Incorrectly implementing interceptors (not handling all necessary cases).
   - Assuming cross-context access will "just work."
   - Not understanding the difference between direct property access and access through interceptors.

10. **Structure the Explanation:** Organize the information logically with clear headings and concise explanations for each aspect of the request. Use bullet points and code blocks to improve readability.

11. **Review and Refine:**  Read through the entire explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where more detail might be helpful. For instance, explicitly mentioning the purpose of the `g_expect_interceptor_call` flag would be beneficial.

By following these steps, you can systematically analyze the provided C++ code and generate a comprehensive and accurate explanation that addresses all aspects of the user's request. The key is to start with a high-level understanding and then progressively drill down into the details of the code and its functionality.
好的，让我们来分析一下 `v8/test/unittests/api/access-check-unittest.cc` 这个 V8 源代码文件的功能。

**主要功能:**

`v8/test/unittests/api/access-check-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 **访问检查 (Access Check)** 机制。访问检查是 V8 中一项重要的安全特性，用于控制不同 JavaScript 上下文 (Context) 之间对象的访问权限。

具体来说，这个文件测试了以下几个方面的功能：

1. **基本的跨上下文访问控制:** 测试当一个上下文尝试访问另一个上下文中对象的属性时，如果没有设置访问检查，默认情况下访问会被阻止。
2. **`SetAccessCheckCallback` 和 `SetAccessCheckCallbackAndHandler`:** 测试如何使用这两个 API 函数来设置自定义的访问检查回调函数。
3. **访问检查回调函数的行为:** 测试自定义的访问检查回调函数如何决定是否允许跨上下文的属性访问。测试了当回调函数返回 `true` (允许访问) 和 `false` (拒绝访问) 时的行为。
4. **属性拦截器 (Property Interceptors) 与访问检查的交互:** 测试当目标对象设置了属性拦截器（Getter、Setter、Query、Deleter、Enumerator）时，访问检查回调函数如何与这些拦截器协同工作。
5. **`Context::NewRemoteContext` 和 `ObjectTemplate::NewRemoteInstance`:** 测试创建“远程上下文”和“远程实例”的功能，以及访问检查如何应用于这些远程对象。远程对象允许在不完全暴露对象的情况下进行一定程度的交互。
6. **异常处理:** 测试当访问检查失败时，是否会抛出预期的异常。
7. **调试场景下的行为:**  测试在调试模式下，访问检查相关的机制是否正常工作，例如测试了懒加载的访问器属性在不同上下文中的行为。
8. **不同类型的属性访问:** 测试对命名属性 (named properties) 和索引属性 (indexed properties) 的访问检查。

**关于文件类型:**

`v8/test/unittests/api/access-check-unittest.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**。因此，它不是一个 Torque 源代码文件（Torque 文件的扩展名通常是 `.tq`）。

**与 JavaScript 的关系及示例:**

这个 C++ 文件测试的是 V8 引擎提供的 API，这些 API 直接影响 JavaScript 代码的执行行为，特别是涉及到跨上下文交互时。

以下 JavaScript 例子可以说明访问检查的功能：

```javascript
// 创建两个独立的上下文
const context1 = v8.Context.New(isolate);
const context2 = v8.Context.New(isolate);

// 在 context1 中创建一个对象
const global1 = context1.Global();
global1.Set(context1, v8.String::NewFromUtf8(isolate, "myObject").ToLocalChecked(), v8::Object::New(isolate));

// 尝试在 context2 中访问 context1 的对象 (默认情况下会被阻止)
context2.Global().Set(context2, v8.String::NewFromUtf8(isolate, "otherContextObject").ToLocalChecked(), global1);

// 在 context2 中执行代码
const source = 'otherContextObject.myObject.someProperty = 42;';
const script = v8::Script::Compile(context2, v8::String::NewFromUtf8(isolate, source).ToLocalChecked()).ToLocalChecked();

// 运行脚本，这将会因为访问检查失败而报错 (如果没有设置访问检查回调)
const result = script->Run(context2);
if (result.IsEmpty()) {
  const exception = isolate->GetException();
  console.error("访问被拒绝:", v8::String::Utf8Value(isolate, exception).out());
}

// --- 使用访问检查回调的例子 (需要在 C++ 代码中设置) ---
// 假设在 C++ 代码中，我们为 context1 的 global 对象设置了访问检查回调，
// 并且该回调允许访问 'myObject' 属性。

// 那么在 context2 中访问 context1 的对象将会成功：
// (假设 C++ 端的访问检查逻辑允许访问)
const sourceWithAccess = 'otherContextObject.myObject.someOtherProperty = 100;';
const scriptWithAccess = v8::Script::Compile(context2, v8::String::NewFromUtf8(isolate, sourceWithAccess).ToLocalChecked()).ToLocalChecked();
const resultWithAccess = scriptWithAccess->Run(context2);
if (!resultWithAccess.IsEmpty()) {
  console.log("访问成功");
}
```

**代码逻辑推理和假设输入/输出:**

让我们以 `CheckCrossContextAccess` 函数为例进行代码逻辑推理：

**假设输入:**

* `accessing_context`: 一个 V8 上下文对象，代表尝试访问的上下文。
* `accessed_object`: 一个 V8 对象，代表被访问的上下文中的对象。

**代码逻辑:**

1. 在 `accessing_context` 的全局对象上设置一个名为 "other" 的属性，其值为 `accessed_object`。
2. 设置一个全局变量 `g_expect_interceptor_call` 为 `true`，表明我们期望属性拦截器被调用。
3. 设置一个全局变量 `g_cross_context_int` 为 23。
4. 尝试在 `accessing_context` 中运行 JavaScript 代码 `this.other.foo` 和 `this.other[23]`。由于没有设置允许跨上下文访问的访问检查回调，并且假设 `accessed_object` 没有针对 "foo" 或索引 23 的拦截器，这两个操作应该会因为访问检查失败而抛出异常，被 `TryCatch` 捕获。 `TryRunJS` 返回空值，`CHECK(TryRunJS(...).IsEmpty())` 断言成功。
5. 运行 JavaScript 代码 `this.other.cross_context_int`。由于 `accessed_object` (即 `context0` 的全局对象) 设置了名为 "cross_context_int" 的命名属性拦截器，并且该拦截器返回了 `g_cross_context_int` 的值，所以这个操作应该成功，并返回 23。 `EXPECT_THAT(RunJS(...), IsInt32(23))` 断言成功。
6. 运行 JavaScript 代码 `this.other.cross_context_int = 42`。由于设置了命名属性 setter 拦截器，该拦截器会更新 `g_cross_context_int` 的值。
7. 运行 JavaScript 代码 `this.other[7]`。由于设置了索引属性 getter 拦截器，该拦截器返回 `g_cross_context_int` 的值（此时为 42）。`EXPECT_THAT(RunJS(...), IsInt32(42))` 断言成功。
8. 运行 JavaScript 代码 `JSON.stringify(Object.getOwnPropertyNames(this.other))`。由于设置了命名和索引属性的枚举器拦截器，返回的属性名称应该包含 "7" 和 "cross_context_int"。`EXPECT_THAT(RunJS(...), IsString("[\"7\",\"cross_context_int\"]"))` 断言成功。

**预期输出 (基于断言):**

所有 `CHECK` 和 `EXPECT_THAT` 断言都应该成功，表明跨上下文的访问行为符合预期，即默认拒绝访问，但可以通过属性拦截器允许特定属性的访问。

**用户常见的编程错误:**

1. **忘记设置访问检查回调函数:**  开发者可能期望在创建了多个上下文后，可以直接互相访问对象，但默认情况下这是不允许的。必须显式地使用 `SetAccessCheckCallback` 或 `SetAccessCheckCallbackAndHandler` 来启用和配置跨上下文访问。

   ```javascript
   // 错误示例：期望直接访问另一个上下文的对象
   const context1 = v8.Context.New(isolate);
   const context2 = v8.Context.New(isolate);
   context2.Global().Set(context2, v8::String::NewFromUtf8(isolate, "otherContextObject").ToLocalChecked(), context1.Global());
   // 尝试访问会失败
   ```

2. **回调函数逻辑错误:**  自定义的访问检查回调函数可能编写不当，导致意外地允许或拒绝访问。例如，没有正确检查访问的属性名或访问的上下文。

   ```c++
   // 错误示例：一个总是允许访问的访问检查回调（可能不是期望的行为）
   bool MyAccessCheckCallback(Local<Context> accessing_context,
                            Local<Object> accessed_object, Local<Value> data) {
     return true; // 错误：总是允许访问
   }
   ```

3. **没有考虑到属性拦截器:** 开发者可能只关注访问检查回调，而忽略了属性拦截器也会影响属性的访问行为。如果目标对象设置了拦截器，即使访问检查回调拒绝访问，拦截器仍然可能被调用并处理访问请求。

   ```c++
   // C++ 端设置了拦截器
   global_template->SetAccessorProperty(NewString("myProperty"), myGetter, mySetter);

   // JavaScript 端尝试访问，即使访问检查回调可能拒绝，拦截器仍然会被触发
   // context2 中的代码：otherContextObject.myProperty
   ```

4. **对远程上下文和远程实例的理解不足:**  开发者可能不清楚 `NewRemoteContext` 和 `NewRemoteInstance` 的作用，以及它们与访问检查的关系。远程对象提供了一种受限的跨上下文交互方式，需要正确理解其行为。

总而言之，`v8/test/unittests/api/access-check-unittest.cc` 通过一系列细致的测试用例，验证了 V8 引擎中访问检查机制的正确性和各种边界情况的处理，对于理解 V8 的安全模型和跨上下文编程至关重要。

Prompt: 
```
这是目录为v8/test/unittests/api/access-check-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/api/access-check-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "include/v8-script.h"
#include "include/v8-template.h"
#include "src/debug/debug.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {

using testing::IsInt32;
using testing::IsString;

int32_t g_cross_context_int = 0;

bool g_expect_interceptor_call = false;

class AccessCheckTest : public TestWithIsolate {
 public:
  void CheckCanRunScriptInContext(Local<Context> context) {
    HandleScope handle_scope(isolate());
    Context::Scope context_scope(context);

    g_expect_interceptor_call = false;
    g_cross_context_int = 0;

    // Running script in this context should work.
    RunJS("this.foo = 42; this[23] = true;");
    RunJS("this.cross_context_int = 23");
    CHECK_EQ(g_cross_context_int, 23);
    EXPECT_THAT(RunJS("this.cross_context_int"), IsInt32(23));
  }

  void CheckCrossContextAccess(Local<Context> accessing_context,
                               Local<Object> accessed_object) {
    HandleScope handle_scope(isolate());
    accessing_context->Global()
        ->Set(accessing_context, NewString("other"), accessed_object)
        .FromJust();
    Context::Scope context_scope(accessing_context);

    g_expect_interceptor_call = true;
    g_cross_context_int = 23;

    {
      TryCatch try_catch(isolate());
      CHECK(TryRunJS("this.other.foo").IsEmpty());
    }
    {
      TryCatch try_catch(isolate());
      CHECK(TryRunJS("this.other[23]").IsEmpty());
    }

    // Intercepted properties are accessible, however.
    EXPECT_THAT(RunJS("this.other.cross_context_int"), IsInt32(23));
    RunJS("this.other.cross_context_int = 42");
    EXPECT_THAT(RunJS("this.other[7]"), IsInt32(42));
    EXPECT_THAT(RunJS("JSON.stringify(Object.getOwnPropertyNames(this.other))"),
                IsString("[\"7\",\"cross_context_int\"]"));
  }

  void CheckCrossContextAccessWithException(Local<Context> accessing_context,
                                            Local<Object> accessed_object) {
    HandleScope handle_scope(isolate());
    accessing_context->Global()
        ->Set(accessing_context, NewString("other"), accessed_object)
        .FromJust();
    Context::Scope context_scope(accessing_context);

    {
      TryCatch try_catch(isolate());
      TryRunJS("this.other.should_throw");
      CHECK(try_catch.HasCaught());
      CHECK(try_catch.Exception()->IsString());
      CHECK(NewString("exception")
                ->Equals(accessing_context, try_catch.Exception())
                .FromJust());
    }

    {
      TryCatch try_catch(isolate());
      TryRunJS("this.other.should_throw = 8");
      CHECK(try_catch.HasCaught());
      CHECK(try_catch.Exception()->IsString());
      CHECK(NewString("exception")
                ->Equals(accessing_context, try_catch.Exception())
                .FromJust());
    }

    {
      TryCatch try_catch(isolate());
      TryRunJS("this.other[42]");
      CHECK(try_catch.HasCaught());
      CHECK(try_catch.Exception()->IsString());
      CHECK(NewString("exception")
                ->Equals(accessing_context, try_catch.Exception())
                .FromJust());
    }

    {
      TryCatch try_catch(isolate());
      TryRunJS("this.other[42] = 8");
      CHECK(try_catch.HasCaught());
      CHECK(try_catch.Exception()->IsString());
      CHECK(NewString("exception")
                ->Equals(accessing_context, try_catch.Exception())
                .FromJust());
    }
  }
};

namespace {

inline v8::Local<v8::String> v8_str(const char* x) {
  return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), x).ToLocalChecked();
}

inline v8::Local<v8::String> v8_str(v8::Isolate* isolate, const char* x) {
  return v8::String::NewFromUtf8(isolate, x).ToLocalChecked();
}

bool AccessCheck(Local<Context> accessing_context,
                 Local<Object> accessed_object, Local<Value> data) {
  return false;
}

MaybeLocal<Value> CompileRun(Isolate* isolate, const char* source) {
  Local<String> source_string = v8_str(isolate, source);
  Local<Context> context = isolate->GetCurrentContext();
  Local<Script> script =
      Script::Compile(context, source_string).ToLocalChecked();
  return script->Run(context);
}

}  // namespace

TEST_F(AccessCheckTest, GetOwnPropertyDescriptor) {
  isolate()->SetFailedAccessCheckCallbackFunction(
      [](v8::Local<v8::Object> host, v8::AccessType type,
         v8::Local<v8::Value> data) {});
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate());
  global_template->SetAccessCheckCallback(AccessCheck);

  Local<FunctionTemplate> getter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<Value>& info) { FAIL(); });
  getter_template->SetAcceptAnyReceiver(false);
  Local<FunctionTemplate> setter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<v8::Value>& info) { FAIL(); });
  setter_template->SetAcceptAnyReceiver(false);
  global_template->SetAccessorProperty(NewString("property"), getter_template,
                                       setter_template);

  Local<Context> target_context =
      Context::New(isolate(), nullptr, global_template);
  Local<Context> accessing_context =
      Context::New(isolate(), nullptr, global_template);

  accessing_context->Global()
      ->Set(accessing_context, NewString("other"), target_context->Global())
      .FromJust();

  Context::Scope context_scope(accessing_context);
  Local<String> no_access_str = NewString("no access");
  Local<Value> result;
  result = CompileRun(isolate(),
                      "var m = null; "
                      "try {"
                      "  Object.getOwnPropertyDescriptor(this, 'property')"
                      "      .get.call(other);"
                      "} catch(e) {"
                      "  m = e.message;"
                      "};"
                      "m")
               .ToLocalChecked();
  EXPECT_TRUE(no_access_str->Equals(accessing_context, result).FromJust());

  result = CompileRun(isolate(),
                      "var m = null; "
                      "try {"
                      "  Object.getOwnPropertyDescriptor(this, 'property')"
                      "      .set.call(other, 42);"
                      "} catch(e) {"
                      "  m = e.message;"
                      "};"
                      "m")
               .ToLocalChecked();
  EXPECT_TRUE(no_access_str->Equals(accessing_context, result).FromJust());
}

class AccessRegressionTest : public AccessCheckTest {
 protected:
  i::Handle<i::JSFunction> RetrieveFunctionFrom(Local<Context> context,
                                                const char* script) {
    Context::Scope context_scope(context);
    Local<Value> getter = CompileRun(isolate(), script).ToLocalChecked();
    EXPECT_TRUE(getter->IsFunction());

    i::Handle<i::JSReceiver> r =
        Utils::OpenHandle(*Local<Function>::Cast(getter));
    EXPECT_TRUE(IsJSFunction(*r));
    return i::Cast<i::JSFunction>(r);
  }
};

TEST_F(AccessRegressionTest,
       InstantiatedLazyAccessorPairsHaveCorrectNativeContext) {
  // The setup creates two contexts and sets an object created
  // in context 1 on the global of context 2.
  // The object has an accessor pair {property}. Accessing the
  // property descriptor of {property} causes instantiation of the
  // accessor pair. The test checks that the access pair has the
  // correct native context.
  Local<FunctionTemplate> getter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<Value>&) { FAIL(); });
  Local<FunctionTemplate> setter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<v8::Value>&) { FAIL(); });

  Local<ObjectTemplate> object_template = ObjectTemplate::New(isolate());
  object_template->SetAccessorProperty(NewString("property"), getter_template,
                                       setter_template);

  Local<Context> context1 = Context::New(isolate(), nullptr);
  Local<Context> context2 = Context::New(isolate(), nullptr);

  Local<Object> object =
      object_template->NewInstance(context1).ToLocalChecked();
  context2->Global()
      ->Set(context2, NewString("object_from_context1"), object)
      .Check();

  i::DirectHandle<i::JSFunction> getter = RetrieveFunctionFrom(
      context2,
      "Object.getOwnPropertyDescriptor(object_from_context1, 'property').get");

  ASSERT_EQ(getter->native_context(), *Utils::OpenDirectHandle(*context1));
}

// Regression test for https://crbug.com/986063.
TEST_F(AccessRegressionTest,
       InstantiatedLazyAccessorPairsHaveCorrectNativeContextDebug) {
  // The setup creates two contexts and installs an object "object"
  // on the global this for each context.
  // The object consists of:
  //    - an accessor pair "property".
  //    - a normal function "breakfn".
  //
  // The test sets a break point on {object.breakfn} in the first context.
  // This forces instantation of the JSFunction for the {object.property}
  // accessor pair. The test verifies afterwards that the respective
  // JSFunction of the getter have the correct native context.

  Local<FunctionTemplate> getter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<Value>&) { FAIL(); });
  Local<FunctionTemplate> setter_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<v8::Value>&) { FAIL(); });
  Local<FunctionTemplate> break_template = FunctionTemplate::New(
      isolate(), [](const FunctionCallbackInfo<v8::Value>&) { FAIL(); });

  Local<Context> context1 = Context::New(isolate(), nullptr);
  Local<Context> context2 = Context::New(isolate(), nullptr);

  Local<ObjectTemplate> object_template = ObjectTemplate::New(isolate());
  object_template->Set(isolate(), "breakfn", break_template);
  object_template->SetAccessorProperty(NewString("property"), getter_template,
                                       setter_template);

  Local<Object> object1 =
      object_template->NewInstance(context1).ToLocalChecked();
  EXPECT_TRUE(
      context1->Global()->Set(context1, NewString("object"), object1).IsJust());

  Local<Object> object2 =
      object_template->NewInstance(context2).ToLocalChecked();
  EXPECT_TRUE(
      context2->Global()->Set(context2, NewString("object"), object2).IsJust());

  // Force instantiation of the JSFunction for the getter and setter
  // of {object.property} by setting a break point on {object.breakfn}
  {
    Context::Scope context_scope(context1);
    i::Isolate* iso = reinterpret_cast<i::Isolate*>(isolate());
    i::DirectHandle<i::JSFunction> break_fn =
        RetrieveFunctionFrom(context1, "object.breakfn");

    int id;
    iso->debug()->SetBreakpointForFunction(i::handle(break_fn->shared(), iso),
                                           iso->factory()->empty_string(), &id);
  }

  i::DirectHandle<i::JSFunction> getter_c1 = RetrieveFunctionFrom(
      context1, "Object.getOwnPropertyDescriptor(object, 'property').get");
  i::DirectHandle<i::JSFunction> getter_c2 = RetrieveFunctionFrom(
      context2, "Object.getOwnPropertyDescriptor(object, 'property').get");

  ASSERT_EQ(getter_c1->native_context(), *Utils::OpenDirectHandle(*context1));
  ASSERT_EQ(getter_c2->native_context(), *Utils::OpenDirectHandle(*context2));
}

v8::Intercepted NamedGetter(Local<Name> property,
                            const PropertyCallbackInfo<Value>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (!property->Equals(context, v8_str("cross_context_int")).FromJust()) {
    return v8::Intercepted::kNo;
  }
  info.GetReturnValue().Set(g_cross_context_int);
  return v8::Intercepted::kYes;
}

v8::Intercepted NamedSetter(Local<Name> property, Local<Value> value,
                            const PropertyCallbackInfo<void>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (!property->Equals(context, v8_str("cross_context_int")).FromJust()) {
    return v8::Intercepted::kNo;
  }
  if (value->IsInt32()) {
    g_cross_context_int = value->ToInt32(context).ToLocalChecked()->Value();
  }
  return v8::Intercepted::kYes;
}

v8::Intercepted NamedQuery(Local<Name> property,
                           const PropertyCallbackInfo<Integer>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (!property->Equals(context, v8_str("cross_context_int")).FromJust()) {
    return v8::Intercepted::kNo;
  }
  info.GetReturnValue().Set(DontDelete);
  return v8::Intercepted::kYes;
}

v8::Intercepted NamedDeleter(Local<Name> property,
                             const PropertyCallbackInfo<Boolean>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (!property->Equals(context, v8_str("cross_context_int")).FromJust()) {
    return v8::Intercepted::kNo;
  }
  info.GetReturnValue().Set(false);
  return v8::Intercepted::kYes;
}

void NamedEnumerator(const PropertyCallbackInfo<Array>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Array> names = Array::New(isolate, 1);
  names->Set(context, 0, v8_str("cross_context_int")).FromJust();
  info.GetReturnValue().Set(names);
}

v8::Intercepted IndexedGetter(uint32_t index,
                              const PropertyCallbackInfo<Value>& info) {
  CHECK(g_expect_interceptor_call);
  if (index == 7) {
    info.GetReturnValue().Set(g_cross_context_int);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexedSetter(uint32_t index, Local<Value> value,
                              const PropertyCallbackInfo<void>& info) {
  CHECK(g_expect_interceptor_call);
  if (index == 7) {
    Isolate* isolate = info.GetIsolate();
    Local<Context> context = isolate->GetCurrentContext();
    if (value->IsInt32()) {
      g_cross_context_int = value->ToInt32(context).ToLocalChecked()->Value();
    }
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexedQuery(uint32_t index,
                             const PropertyCallbackInfo<Integer>& info) {
  CHECK(g_expect_interceptor_call);
  if (index == 7) {
    info.GetReturnValue().Set(DontDelete);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexedDeleter(uint32_t index,
                               const PropertyCallbackInfo<Boolean>& info) {
  CHECK(g_expect_interceptor_call);
  if (index == 7) {
    info.GetReturnValue().Set(false);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void IndexedEnumerator(const PropertyCallbackInfo<Array>& info) {
  CHECK(g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  Local<Array> names = Array::New(isolate, 1);
  names->Set(context, 0, v8_str(isolate, "7")).FromJust();
  info.GetReturnValue().Set(names);
}

v8::Intercepted MethodGetter(Local<Name> property,
                             const PropertyCallbackInfo<Value>& info) {
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();

  Local<External> data = info.Data().As<External>();
  Local<FunctionTemplate>& function_template =
      *reinterpret_cast<Local<FunctionTemplate>*>(data->Value());

  info.GetReturnValue().Set(
      function_template->GetFunction(context).ToLocalChecked());
  return v8::Intercepted::kYes;
}

void MethodCallback(const FunctionCallbackInfo<Value>& info) {
  info.GetReturnValue().Set(8);
}

v8::Intercepted NamedGetterThrowsException(
    Local<Name> property, const PropertyCallbackInfo<Value>& info) {
  Isolate* isolate = info.GetIsolate();
  isolate->ThrowException(v8_str(isolate, "exception"));
  return v8::Intercepted::kYes;
}

v8::Intercepted NamedSetterThrowsException(
    Local<Name> property, Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Isolate* isolate = info.GetIsolate();
  isolate->ThrowException(v8_str(isolate, "exception"));
  return v8::Intercepted::kYes;
}

v8::Intercepted IndexedGetterThrowsException(
    uint32_t index, const PropertyCallbackInfo<Value>& info) {
  Isolate* isolate = info.GetIsolate();
  isolate->ThrowException(v8_str(isolate, "exception"));
  return v8::Intercepted::kYes;
}

v8::Intercepted IndexedSetterThrowsException(
    uint32_t index, Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Isolate* isolate = info.GetIsolate();
  isolate->ThrowException(v8_str(isolate, "exception"));
  return v8::Intercepted::kYes;
}

void GetCrossContextInt(Local<Name> property,
                        const PropertyCallbackInfo<Value>& info) {
  CHECK(!g_expect_interceptor_call);
  info.GetReturnValue().Set(g_cross_context_int);
}

void SetCrossContextInt(Local<Name> property, Local<Value> value,
                        const PropertyCallbackInfo<void>& info) {
  CHECK(!g_expect_interceptor_call);
  Isolate* isolate = info.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  if (value->IsInt32()) {
    g_cross_context_int = value->ToInt32(context).ToLocalChecked()->Value();
  }
}

void Return42(Local<String> property, const PropertyCallbackInfo<Value>& info) {
  info.GetReturnValue().Set(42);
}

void Ctor(const FunctionCallbackInfo<Value>& info) {
  CHECK(info.IsConstructCall());
}

TEST_F(AccessCheckTest, AccessCheckWithInterceptor) {
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate());
  global_template->SetAccessCheckCallbackAndHandler(
      AccessCheck,
      NamedPropertyHandlerConfiguration(NamedGetter, NamedSetter, NamedQuery,
                                        NamedDeleter, NamedEnumerator),
      IndexedPropertyHandlerConfiguration(IndexedGetter, IndexedSetter,
                                          IndexedQuery, IndexedDeleter,
                                          IndexedEnumerator));
  global_template->SetNativeDataProperty(
      NewString("cross_context_int"), GetCrossContextInt, SetCrossContextInt);

  Local<Context> context0 = Context::New(isolate(), nullptr, global_template);
  CheckCanRunScriptInContext(context0);

  // Create another context.
  Local<Context> context1 = Context::New(isolate(), nullptr, global_template);
  CheckCrossContextAccess(context1, context0->Global());
}

TEST_F(AccessCheckTest, CallFunctionWithRemoteContextReceiver) {
  HandleScope scope(isolate());
  Local<FunctionTemplate> global_template = FunctionTemplate::New(isolate());

  Local<Signature> signature = Signature::New(isolate(), global_template);
  Local<FunctionTemplate> function_template = FunctionTemplate::New(
      isolate(), MethodCallback, External::New(isolate(), &function_template),
      signature);

  global_template->InstanceTemplate()->SetAccessCheckCallbackAndHandler(
      AccessCheck,
      NamedPropertyHandlerConfiguration(
          MethodGetter, nullptr, nullptr, nullptr, nullptr,
          External::New(isolate(), &function_template)),
      IndexedPropertyHandlerConfiguration());

  Local<Object> accessed_object =
      Context::NewRemoteContext(isolate(), global_template->InstanceTemplate())
          .ToLocalChecked();
  Local<Context> accessing_context =
      Context::New(isolate(), nullptr, global_template->InstanceTemplate());

  HandleScope handle_scope(isolate());
  accessing_context->Global()
      ->Set(accessing_context, NewString("other"), accessed_object)
      .FromJust();
  Context::Scope context_scope(accessing_context);

  {
    TryCatch try_catch(isolate());
    EXPECT_THAT(RunJS("this.other.method()"), IsInt32(8));
    CHECK(!try_catch.HasCaught());
  }
}

TEST_F(AccessCheckTest, AccessCheckWithExceptionThrowingInterceptor) {
  isolate()->SetFailedAccessCheckCallbackFunction(
      [](Local<Object> target, AccessType type, Local<Value> data) {
        UNREACHABLE();  // This should never be called.
      });

  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate());
  global_template->SetAccessCheckCallbackAndHandler(
      AccessCheck,
      NamedPropertyHandlerConfiguration(NamedGetterThrowsException,
                                        NamedSetterThrowsException),
      IndexedPropertyHandlerConfiguration(IndexedGetterThrowsException,
                                          IndexedSetterThrowsException));

  // Create two contexts.
  Local<Context> context0 = Context::New(isolate(), nullptr, global_template);
  Local<Context> context1 = Context::New(isolate(), nullptr, global_template);

  CheckCrossContextAccessWithException(context1, context0->Global());
}

TEST_F(AccessCheckTest, NewRemoteContext) {
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate());
  global_template->SetAccessCheckCallbackAndHandler(
      AccessCheck,
      NamedPropertyHandlerConfiguration(NamedGetter, NamedSetter, NamedQuery,
                                        NamedDeleter, NamedEnumerator),
      IndexedPropertyHandlerConfiguration(IndexedGetter, IndexedSetter,
                                          IndexedQuery, IndexedDeleter,
                                          IndexedEnumerator));
  global_template->SetNativeDataProperty(
      NewString("cross_context_int"), GetCrossContextInt, SetCrossContextInt);

  Local<Object> global0 =
      Context::NewRemoteContext(isolate(), global_template).ToLocalChecked();

  // Create a real context.
  {
    HandleScope other_scope(isolate());
    Local<Context> context1 = Context::New(isolate(), nullptr, global_template);

    CheckCrossContextAccess(context1, global0);
  }

  // Create a context using the detached global.
  {
    HandleScope other_scope(isolate());
    Local<Context> context2 =
        Context::New(isolate(), nullptr, global_template, global0);

    CheckCanRunScriptInContext(context2);
  }

  // Turn a regular context into a remote context.
  {
    HandleScope other_scope(isolate());
    Local<Context> context3 = Context::New(isolate(), nullptr, global_template);

    CheckCanRunScriptInContext(context3);

    // Turn the global object into a remote context, and try to access it.
    Local<Object> context3_global = context3->Global();
    context3->DetachGlobal();
    Local<Object> global3 =
        Context::NewRemoteContext(isolate(), global_template, context3_global)
            .ToLocalChecked();
    Local<Context> context4 = Context::New(isolate(), nullptr, global_template);

    CheckCrossContextAccess(context4, global3);

    // Turn it back into a regular context.
    Local<Context> context5 =
        Context::New(isolate(), nullptr, global_template, global3);

    CheckCanRunScriptInContext(context5);
  }
}

TEST_F(AccessCheckTest, NewRemoteInstance) {
  Local<FunctionTemplate> tmpl = FunctionTemplate::New(isolate(), Ctor);
  Local<ObjectTemplate> instance = tmpl->InstanceTemplate();
  instance->SetAccessCheckCallbackAndHandler(
      AccessCheck,
      NamedPropertyHandlerConfiguration(NamedGetter, NamedSetter, NamedQuery,
                                        NamedDeleter, NamedEnumerator),
      IndexedPropertyHandlerConfiguration(IndexedGetter, IndexedSetter,
                                          IndexedQuery, IndexedDeleter,
                                          IndexedEnumerator));
  Local<Object> obj = tmpl->NewRemoteInstance().ToLocalChecked();

  Local<Context> context = Context::New(isolate());
  CheckCrossContextAccess(context, obj);
}

}  // namespace v8

"""

```