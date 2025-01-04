Response: My thought process to analyze the C++ code and generate the summary and JavaScript examples went through these steps:

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and JavaScript examples illustrating its relation to JavaScript features. The file path `v8/test/unittests/api/accessor-unittest.cc` immediately suggests it's testing the V8 API related to accessors.

2. **Initial Code Scan and Keyword Spotting:** I quickly scanned the code, looking for keywords and patterns related to accessors in the V8 API. I noticed:
    * `v8::ObjectTemplate::SetAccessorProperty`
    * `v8::Object::SetPrivate`
    * `v8::Object::SetNativeDataProperty`
    * `v8::Object::SetLazyDataProperty`
    * `v8::FunctionTemplate::NewWithCache`
    * `v8::PropertyCallbackInfo` (Getter/Setter callbacks)
    * `v8::SideEffectType`
    * Test names like `CachedAccessor`, `RedeclareAccessor`, `AccessorsWithSideEffects`, etc.

3. **Group Tests by Feature:**  Based on the keywords and test names, I started mentally grouping the tests by the V8 accessor features they were examining:
    * **Cached Accessors:** Tests involving `NewWithCache` and private properties.
    * **Side Effects:** Tests involving `SideEffectType` and checking for side-effect-free operations using `v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect`.
    * **Native Accessors:** Tests using `SetNativeDataProperty` and custom getter/setter callbacks.
    * **Lazy Accessors:** Tests using `SetLazyDataProperty`.
    * **Accessors on Global Objects:** Specific tests targeting the global object.
    * **Redeclaration of Accessors:** Testing the behavior when trying to redefine accessors.
    * **Accessors in `Function.prototype.bind`:** Investigating how accessors interact with `bind`.
    * **Accessors in Shadow Realms:** Tests related to the newer ShadowRealm feature.

4. **Analyze Individual Tests:** I then examined individual tests more closely to understand the specific scenarios being tested. For example:
    * **`CachedAccessor`:**  The core idea is to optimize access to properties backed by private symbols. The "UnreachableCallback" is a key element – it should *not* be called under normal cached access.
    * **`AccessorsWithSideEffects`:** These tests aim to verify that V8 correctly identifies and handles (or doesn't handle, in the side-effect-free case) accessors that have side effects. The `v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect` is crucial here.
    * **`RedeclareAccessor`:**  This confirms that you can't re-declare an accessor as a normal function if it's non-configurable.

5. **Identify the JavaScript Equivalents:**  For each group of C++ tests, I thought about the corresponding JavaScript concepts:
    * **Cached Accessors/Private Properties:** This maps directly to the concept of private class fields (`#`) in modern JavaScript, though the underlying mechanism is different. The example shows how accessing a private field works.
    * **Getters and Setters:**  The native accessors and side-effect tests directly relate to JavaScript's `get` and `set` syntax within object literals or classes. The examples demonstrate defining and using getters and setters, and highlighting the side-effect behavior.
    * **Lazy Properties:** This concept is less explicitly exposed in standard JavaScript but can be implemented using techniques like closures or the `defineProperty` method with a getter that initializes the value on first access. The example uses `defineProperty` to simulate lazy initialization.
    * **Global Object Accessors:**  This is straightforward – accessors defined directly on the global object.
    * **Redeclaration:**  This relates to JavaScript's rules about redefining properties, particularly non-configurable ones.
    * **`Function.prototype.bind`:**  The C++ tests check how accessors on functions behave when `bind` is used. The JavaScript example shows a similar scenario, though the error handling might differ.
    * **Shadow Realms:**  This maps directly to the JavaScript ShadowRealm API.

6. **Construct JavaScript Examples:** I created concise JavaScript code snippets that illustrated the functionality being tested in the C++ code. The goal was to provide clear and understandable examples that a JavaScript developer could easily grasp. I focused on demonstrating the core behavior rather than perfectly replicating the internal V8 implementation.

7. **Refine and Organize:** I reviewed the summary and examples to ensure clarity, accuracy, and proper organization. I made sure the JavaScript examples directly related to the C++ features being tested. I also added introductory and concluding sentences to provide context.

Essentially, I worked from the low-level C++ V8 API details to the higher-level JavaScript concepts, trying to bridge the gap and explain the purpose of the C++ tests in terms of familiar JavaScript features. The key was understanding the intent behind each test case in the C++ code.
这个C++源代码文件 `accessor-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用来测试 V8 API 中关于 **属性访问器 (accessors)** 的功能。

以下是该文件主要功能的归纳：

**核心功能：测试 V8 API 中定义和使用属性访问器的各种场景。**

具体来说，它测试了以下方面：

1. **缓存的访问器 (Cached Accessor):**
   - 测试 `v8::FunctionTemplate::NewWithCache` 创建的访问器，这种访问器可以利用缓存来提高性能。
   - 验证缓存访问器在访问私有属性时的行为，包括初始状态和设置私有属性后的访问。
   - 测试在启用 TurboFan (V8 的优化编译器) 的情况下缓存访问器的行为。
   - 测试在全局对象上使用缓存访问器的情况。

2. **带副作用的访问器 (Accessors with Side Effects):**
   - 测试如何通过 `v8::Object::SetAccessorProperty` 和 `v8::ObjectTemplate::SetAccessorProperty` 定义带有副作用的访问器（getter 和 setter）。
   - 测试 V8 如何识别和处理带有副作用的访问器，特别是在进行 side-effect free evaluation 时。
   - 测试本地 (native) 访问器（通过 `v8::Object::SetNativeDataProperty` 和 `v8::ObjectTemplate::SetNativeDataProperty` 定义）的副作用。
   - 测试如何将访问器标记为无副作用，以便在 side-effect free evaluation 中被允许。
   - 测试 `SetNativeDataProperty` 和 `SetLazyDataProperty` 如何影响访问器的副作用属性。

3. **访问器的重定义 (Redeclare Accessor):**
   - 测试尝试重新声明一个已经存在的访问器（特别是不可配置的访问器）时是否会抛出异常。

4. **在 `Function.prototype.bind` 中使用访问器:**
   - 测试当在 `Function.prototype.bind` 返回的函数上访问属性时，getter 是否会被调用。

5. **在 ShadowRealm 中使用访问器:**
   - 测试在新的 ShadowRealm 环境中创建的对象上使用访问器的情况。

**与 JavaScript 的关系及 JavaScript 示例:**

这个 C++ 文件测试的是 V8 引擎的底层 API，这些 API 最终会暴露给 JavaScript 开发者，让他们能够创建和使用具有特定行为的对象属性。

以下是用 JavaScript 举例说明其中一些测试场景：

**1. 缓存的访问器 (对应 `CachedAccessor` 测试):**

在 JavaScript 中，虽然没有直接的 "缓存访问器" 的概念，但我们可以使用闭包和私有变量来模拟类似的行为，或者使用 ES6 的私有字段（`#`）。

```javascript
class Foo {
  #draftValue;

  constructor() {
    this.#draftValue = undefined;
  }

  get draft() {
    return this.#draftValue;
  }

  set draft(value) {
    this.#draftValue = value;
  }
}

const obj = new Foo();
console.log(obj.draft); // 输出 undefined

obj.draft = "Shhh, I'm private!";
console.log(obj.draft); // 输出 "Shhh, I'm private!"
```

在这个 JavaScript 例子中，`draft` 的 getter 和 setter 方法类似于 C++ 代码中测试的缓存访问器，尽管实现机制不同。C++ 代码中 `SetAccessorProperty` 关联的 `UnreachableCallback` 永远不会被直接调用，因为访问器会尝试从缓存中获取值 (在设置私有属性后)。

**2. 带副作用的访问器 (对应 `AccessorsWithSideEffects` 等测试):**

JavaScript 中使用 `get` 和 `set` 关键字定义的访问器可以具有副作用。

```javascript
let counter = 0;
const obj = {
  get value() {
    counter++;
    return "some value";
  },
  set value(newValue) {
    counter++;
    console.log("Setting value to:", newValue);
  }
};

console.log(obj.value); // 输出 "some value"， counter 变为 1
obj.value = "new value"; // 输出 "Setting value to: new value"， counter 变为 2
```

C++ 测试中的 `SideEffectType` 枚举和 `v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect` 用于验证 V8 引擎是否正确识别这些副作用。在 JavaScript 中，直接执行代码就可以观察到副作用。

**3. 访问器的重定义 (对应 `RedeclareAccessor` 测试):**

在 JavaScript 中，如果一个属性被定义为不可配置 (non-configurable)，则尝试重新定义它会抛出 `TypeError`。

```javascript
const obj = {};
Object.defineProperty(obj, 'foo', {
  get: function() { return 1; },
  configurable: false
});

// 尝试将 'foo' 重新定义为一个普通函数会抛出 TypeError
try {
  Object.defineProperty(obj, 'foo', { value: function() {} });
} catch (e) {
  console.error(e); // 输出 TypeError
}
```

C++ 测试模拟了这种场景，验证 V8 引擎是否遵循相同的规则。

**4. 在 `Function.prototype.bind` 中使用访问器 (对应 `BindFunctionTemplateSetNativeDataProperty` 测试):**

```javascript
function myFunc() {
  console.log("myFunc called");
}

Object.defineProperty(myFunc, 'name', {
  get: function() {
    console.log("Getting function name");
    return "customName";
  }
});

const boundFunc = myFunc.bind(null);
console.log(boundFunc.name); // 输出 "Getting function name" 和 "customName"
```

C++ 测试验证了即使通过 `bind` 创建了新的函数，访问其属性（例如 `name` 或 `length`，它们在 `Function.prototype` 上有特殊的 getter）时，定义的访问器仍然会被触发。

总而言之，`accessor-unittest.cc` 是 V8 引擎中非常重要的测试文件，它确保了 V8 在处理属性访问器时的正确性和各种边界情况的处理，而这些访问器功能是 JavaScript 语言中非常核心的一部分。 理解这些测试有助于更深入地理解 JavaScript 引擎的工作原理。

Prompt: 
```
这是目录为v8/test/unittests/api/accessor-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "include/v8-context.h"
#include "include/v8-function.h"
#include "include/v8-isolate.h"
#include "include/v8-local-handle.h"
#include "include/v8-object.h"
#include "include/v8-template.h"
#include "src/api/api-inl.h"
#include "src/debug/debug.h"
#include "src/execution/isolate.h"
#include "src/objects/objects-inl.h"
#include "test/unittests/test-utils.h"
#include "testing/gmock-support.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace i = v8::internal;

using testing::IsInt32;
using testing::IsString;
using testing::IsUndefined;

using AccessorTest = v8::TestWithContext;

// The goal is to avoid the callback.
static void UnreachableCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  UNREACHABLE();
}

TEST_F(AccessorTest, CachedAccessor) {
  // TurboFan support for fast accessors is not implemented; turbofanned
  // code uses the slow accessor which breaks this test's expectations.
  i::v8_flags.always_turbofan = false;
  v8::Isolate* isolate = context()->GetIsolate();
  v8::HandleScope scope(isolate);

  // Create 'foo' class, with a hidden property.
  v8::Local<v8::ObjectTemplate> foo = v8::ObjectTemplate::New(isolate);

  v8::Local<v8::Private> priv =
      v8::Private::ForApi(isolate, NewString("Foo#draft"));

  foo->SetAccessorProperty(
      NewString("draft"),
      v8::FunctionTemplate::NewWithCache(isolate, UnreachableCallback, priv,
                                         v8::Local<v8::Value>()));

  // Create 'obj', instance of 'foo'.
  v8::Local<v8::Object> obj = foo->NewInstance(context()).ToLocalChecked();

  // Install the private property on the instance.
  CHECK(obj->SetPrivate(isolate->GetCurrentContext(), priv,
                        v8::Undefined(isolate))
            .FromJust());

  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  // Access cached accessor.
  EXPECT_THAT(RunJS("obj.draft"), IsUndefined());

  // Set hidden property.
  CHECK(obj->SetPrivate(isolate->GetCurrentContext(), priv,
                        NewString("Shhh, I'm private!"))
            .FromJust());

  EXPECT_THAT(RunJS("obj.draft"), IsString("Shhh, I'm private!"));

  // Stress the accessor to use the IC.
  EXPECT_THAT(RunJS("var result = '';"
                    "for (var i = 0; i < 10; ++i) { "
                    "  result = obj.draft; "
                    "} "
                    "result; "),
              IsString("Shhh, I'm private!"));
}

TEST_F(AccessorTest, CachedAccessorTurboFan) {
  i::v8_flags.allow_natives_syntax = true;
  // i::v8_flags.always_turbofan = false;
  v8::Isolate* isolate = context()->GetIsolate();
  v8::HandleScope scope(isolate);

  // Create 'foo' class, with a hidden property.
  v8::Local<v8::ObjectTemplate> foo = v8::ObjectTemplate::New(isolate);
  v8::Local<v8::Private> priv =
      v8::Private::ForApi(isolate, NewString("Foo#draft"));

  // Install the private property on the template.
  // foo->SetPrivate(priv, v8::Undefined(isolate));

  foo->SetAccessorProperty(
      NewString("draft"),
      v8::FunctionTemplate::NewWithCache(isolate, UnreachableCallback, priv,
                                         v8::Local<v8::Value>()));

  // Create 'obj', instance of 'foo'.
  v8::Local<v8::Object> obj = foo->NewInstance(context()).ToLocalChecked();

  // Install the private property on the instance.
  CHECK(obj->SetPrivate(isolate->GetCurrentContext(), priv,
                        v8::Undefined(isolate))
            .FromJust());

  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  // Access surrogate accessor.
  EXPECT_THAT(RunJS("obj.draft"), IsUndefined());

  // Set hidden property.
  CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate, 123))
            .FromJust());

  // Test ICs.
  RunJS(
      "function f() {"
      "  var x;"
      "  for (var i = 0; i < 100; i++) {"
      "    x = obj.draft;"
      "  }"
      "  return x;"
      "};"
      "%PrepareFunctionForOptimization(f);");

  EXPECT_THAT(RunJS("f()"), IsInt32(123));

  // Reset hidden property.
  CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate, 456))
            .FromJust());

  // Test TurboFan.
  RunJS("%OptimizeFunctionOnNextCall(f);");

  EXPECT_THAT(RunJS("f()"), IsInt32(456));

  CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate, 456))
            .FromJust());
  // Test non-global ICs.
  RunJS(
      "function g() {"
      "  var x = obj;"
      "  var r = 0;"
      "  for (var i = 0; i < 100; i++) {"
      "    r = x.draft;"
      "  }"
      "  return r;"
      "};"
      "%PrepareFunctionForOptimization(g);");

  EXPECT_THAT(RunJS("g()"), IsInt32(456));

  // Reset hidden property.
  CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate, 789))
            .FromJust());

  // Test non-global access in TurboFan.
  RunJS("%OptimizeFunctionOnNextCall(g);");

  EXPECT_THAT(RunJS("g()"), IsInt32(789));
}

TEST_F(AccessorTest, CachedAccessorOnGlobalObject) {
  i::v8_flags.allow_natives_syntax = true;
  v8::HandleScope scope(isolate());

  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate());
  v8::Local<v8::ObjectTemplate> object_template = templ->InstanceTemplate();
  v8::Local<v8::Private> priv =
      v8::Private::ForApi(isolate(), NewString("Foo#draft"));

  object_template->SetAccessorProperty(
      NewString("draft"),
      v8::FunctionTemplate::NewWithCache(isolate(), UnreachableCallback, priv,
                                         v8::Local<v8::Value>()));

  v8::Local<v8::Context> ctx =
      v8::Context::New(isolate(), nullptr, object_template);
  v8::Local<v8::Object> obj = ctx->Global();

  // Install the private property on the instance.
  CHECK(obj->SetPrivate(isolate()->GetCurrentContext(), priv,
                        v8::Undefined(isolate()))
            .FromJust());

  {
    v8::Context::Scope context_scope(ctx);

    // Access surrogate accessor.
    EXPECT_THAT(RunJS("draft"), IsUndefined());

    // Set hidden property.
    CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate(), 123))
              .FromJust());

    // Test ICs.
    RunJS(
        "function f() {"
        "  var x;"
        "  for (var i = 0; i < 100; i++) {"
        "    x = draft;"
        "  }"
        "  return x;"
        "}"
        "%PrepareFunctionForOptimization(f);");

    EXPECT_THAT(RunJS("f()"), IsInt32(123));

    // Reset hidden property.
    CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate(), 456))
              .FromJust());

    // Test TurboFan.
    RunJS("%OptimizeFunctionOnNextCall(f);");

    EXPECT_THAT(RunJS("f()"), IsInt32(456));

    CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate(), 456))
              .FromJust());
    // Test non-global ICs.
    RunJS(
        "var x = this;"
        "function g() {"
        "  var r = 0;"
        "  for (var i = 0; i < 100; i++) {"
        "    r = x.draft;"
        "  }"
        "  return r;"
        "}"
        "%PrepareFunctionForOptimization(g);");

    EXPECT_THAT(RunJS("g()"), IsInt32(456));

    // Reset hidden property.
    CHECK(obj->SetPrivate(context(), priv, v8::Integer::New(isolate(), 789))
              .FromJust());

    // Test non-global access in TurboFan.
    RunJS("%OptimizeFunctionOnNextCall(g);");

    EXPECT_THAT(RunJS("g()"), IsInt32(789));
  }
}

namespace {

// Getter return value should be non-null to trigger lazy property paths.
void Getter(v8::Local<v8::Name> name,
            const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(
      v8::String::NewFromUtf8(info.GetIsolate(), "return value")
          .ToLocalChecked());
}

void StringGetter(v8::Local<v8::Name> name,
                  const v8::PropertyCallbackInfo<v8::Value>& info) {}

int set_accessor_call_count = 0;

void Setter(v8::Local<v8::Name> name, v8::Local<v8::Value> value,
            const v8::PropertyCallbackInfo<void>& info) {
  set_accessor_call_count++;
}

void EmptyCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {}

}  // namespace

// Re-declaration of non-configurable accessors should throw.
TEST_F(AccessorTest, RedeclareAccessor) {
  v8::HandleScope scope(isolate());

  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate());

  v8::Local<v8::ObjectTemplate> object_template = templ->InstanceTemplate();
  object_template->SetNativeDataProperty(NewString("foo"), nullptr, Setter,
                                         v8::Local<v8::Value>(),
                                         v8::PropertyAttribute::DontDelete);

  v8::Local<v8::Context> ctx =
      v8::Context::New(isolate(), nullptr, object_template);

  // Declare function.
  v8::Local<v8::String> code = NewString("function foo() {};");

  v8::TryCatch try_catch(isolate());
  v8::Script::Compile(ctx, code).ToLocalChecked()->Run(ctx).IsEmpty();
  CHECK(try_catch.HasCaught());
}

class NoopDelegate : public v8::debug::DebugDelegate {};

static void CheckSideEffectFreeAccesses(v8::Isolate* isolate,
                                        v8::Local<v8::String> call_getter,
                                        v8::Local<v8::String> call_setter) {
  const int kIterationsCountForICProgression = 20;
  v8::Local<v8::Context> context = isolate->GetCurrentContext();

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);
  v8::Local<v8::Script> func =
      v8::Script::Compile(context, call_getter).ToLocalChecked();
  // Check getter. Run enough number of times to ensure IC creates data handler.
  for (int i = 0; i < kIterationsCountForICProgression; i++) {
    v8::TryCatch try_catch(isolate);
    CHECK(EvaluateGlobal(
              isolate, call_getter,
              v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect,
              true)
              .IsEmpty());

    CHECK(try_catch.HasCaught());

    // Ensure that IC state progresses.
    CHECK(!func->Run(context).IsEmpty());
  }

  func = v8::Script::Compile(context, call_setter).ToLocalChecked();
  // Check setter. Run enough number of times to ensure IC creates data handler.
  for (int i = 0; i < kIterationsCountForICProgression; i++) {
    v8::TryCatch try_catch(isolate);
    CHECK(EvaluateGlobal(
              isolate, call_setter,
              v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect,
              true)
              .IsEmpty());

    CHECK(try_catch.HasCaught());

    // Ensure that IC state progresses.
    CHECK(!func->Run(context).IsEmpty());
  }
}

TEST_F(AccessorTest, AccessorsWithSideEffects) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  v8::Local<v8::FunctionTemplate> templ_with_sideffect =
      v8::FunctionTemplate::New(
          isolate(), EmptyCallback, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kAllow,
          v8::SideEffectType::kHasSideEffect);
  v8::Local<v8::FunctionTemplate> templ_no_sideffect =
      v8::FunctionTemplate::New(
          isolate(), EmptyCallback, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kAllow,
          v8::SideEffectType::kHasNoSideEffect);

  // Install non-native properties with side effects
  obj->SetAccessorProperty(
      NewString("get"),
      templ_with_sideffect->GetFunction(context()).ToLocalChecked(), {},
      v8::PropertyAttribute::None);

  obj->SetAccessorProperty(
      NewString("set"),
      templ_no_sideffect->GetFunction(context()).ToLocalChecked(),
      templ_with_sideffect->GetFunction(context()).ToLocalChecked(),
      v8::PropertyAttribute::None);

  RunJS(
      "function callGetter() { obj.get; }"
      "function callSetter() { obj.set = 123; }");
  CheckSideEffectFreeAccesses(isolate(), NewString("callGetter()"),
                              NewString("callSetter()"));
}

TEST_F(AccessorTest, TemplateAccessorsWithSideEffects) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::FunctionTemplate> templ_with_sideffect =
      v8::FunctionTemplate::New(
          isolate(), EmptyCallback, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kAllow,
          v8::SideEffectType::kHasSideEffect);
  v8::Local<v8::FunctionTemplate> templ_no_sideffect =
      v8::FunctionTemplate::New(
          isolate(), EmptyCallback, v8::Local<v8::Value>(),
          v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kAllow,
          v8::SideEffectType::kHasNoSideEffect);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  templ->SetAccessorProperty(NewString("get"), templ_with_sideffect);
  templ->SetAccessorProperty(NewString("set"), templ_no_sideffect,
                             templ_with_sideffect);
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  RunJS(
      "function callGetter() { obj.get; }"
      "function callSetter() { obj.set = 123; }");
  CheckSideEffectFreeAccesses(isolate(), NewString("callGetter()"),
                              NewString("callSetter()"));
}

TEST_F(AccessorTest, NativeTemplateAccessorWithSideEffects) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  templ->SetNativeDataProperty(
      NewString("get"), Getter, nullptr, v8::Local<v8::Value>(),
      v8::PropertyAttribute::None, v8::SideEffectType::kHasSideEffect);
  templ->SetNativeDataProperty(
      NewString("set"), Getter, Setter, v8::Local<v8::Value>(),
      v8::PropertyAttribute::None, v8::SideEffectType::kHasNoSideEffect,
      v8::SideEffectType::kHasSideEffect);

  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  RunJS(
      "function callGetter() { obj.get; }"
      "function callSetter() { obj.set = 123; }");
  CheckSideEffectFreeAccesses(isolate(), NewString("callGetter()"),
                              NewString("callSetter()"));
}

TEST_F(AccessorTest, NativeAccessorsWithSideEffects) {
  v8::HandleScope scope(isolate());

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  // Install native data property with side effects.
  obj->SetNativeDataProperty(context(), NewString("get"), Getter, nullptr, {},
                             v8::PropertyAttribute::None,
                             v8::SideEffectType::kHasSideEffect)
      .ToChecked();
  obj->SetNativeDataProperty(context(), NewString("set"), Getter, Setter, {},
                             v8::PropertyAttribute::None,
                             v8::SideEffectType::kHasNoSideEffect,
                             v8::SideEffectType::kHasSideEffect)
      .ToChecked();

  RunJS(
      "function callGetter() { obj.get; }"
      "function callSetter() { obj.set = 123; }");
  CheckSideEffectFreeAccesses(isolate(), NewString("callGetter()"),
                              NewString("callSetter()"));
}

// Accessors can be allowlisted as side-effect-free via SetNativeDataProperty.
TEST_F(AccessorTest, AccessorSetHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());
  obj->SetNativeDataProperty(context(), NewString("foo"), Getter).ToChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  obj->SetNativeDataProperty(context(), NewString("foo"), Getter, nullptr, {},
                             v8::PropertyAttribute::None,
                             v8::SideEffectType::kHasNoSideEffect)
      .ToChecked();
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
  CHECK_EQ(0, set_accessor_call_count);
}

// Set accessors can be allowlisted as side-effect-free via
// SetNativeDataProperty.
TEST_F(AccessorTest, SetNativeDataPropertySetSideEffectReceiverCheck1) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());
  obj->SetNativeDataProperty(context(), NewString("foo"), Getter, Setter, {},
                             v8::PropertyAttribute::None,
                             v8::SideEffectType::kHasNoSideEffect,
                             v8::SideEffectType::kHasSideEffectToReceiver)
      .ToChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .ToLocalChecked()
            ->Equals(context(), NewString("return value"))
            .FromJust());
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_EQ(0, set_accessor_call_count);
}

static void ConstructCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
}

TEST_F(AccessorTest, SetNativeDataPropertySetSideEffectReceiverCheck2) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(
      isolate(), ConstructCallback, v8::Local<v8::Value>(),
      v8::Local<v8::Signature>(), 0, v8::ConstructorBehavior::kAllow,
      v8::SideEffectType::kHasNoSideEffect);
  templ->InstanceTemplate()->SetNativeDataProperty(
      NewString("bar"), Getter, Setter, v8::Local<v8::Value>(),
      v8::PropertyAttribute::None, v8::SideEffectType::kHasSideEffectToReceiver,
      v8::SideEffectType::kHasSideEffectToReceiver);
  CHECK(context()
            ->Global()
            ->Set(context(), NewString("f"),
                  templ->GetFunction(context()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("new f().bar"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .ToLocalChecked()
            ->Equals(context(), NewString("return value"))
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate(), NewString("new f().bar = 1"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  CHECK_EQ(1, set_accessor_call_count);
}

// Accessors can be allowlisted as side-effect-free via SetNativeDataProperty.
TEST_F(AccessorTest, AccessorSetNativeDataPropertyHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());
  obj->SetNativeDataProperty(context(), NewString("foo"), Getter).ToChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  obj->SetNativeDataProperty(
         context(), NewString("foo"), Getter, nullptr, v8::Local<v8::Value>(),
         v8::PropertyAttribute::None, v8::SideEffectType::kHasNoSideEffect)
      .ToChecked();
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
}

// Accessors can be allowlisted as side-effect-free via SetLazyDataProperty.
TEST_F(AccessorTest, AccessorSetLazyDataPropertyHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());
  obj->SetLazyDataProperty(context(), NewString("foo"), Getter).ToChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  obj->SetLazyDataProperty(context(), NewString("foo"), Getter,
                           v8::Local<v8::Value>(), v8::PropertyAttribute::None,
                           v8::SideEffectType::kHasNoSideEffect)
      .ToChecked();
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
}

TEST_F(AccessorTest, ObjectTemplateSetNativeDataPropertyHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  templ->SetNativeDataProperty(NewString("foo"), StringGetter);
  templ->SetNativeDataProperty(
      NewString("foo2"), StringGetter, nullptr, v8::Local<v8::Value>(),
      v8::PropertyAttribute::None, v8::SideEffectType::kHasNoSideEffect);
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo2"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo2 = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo2"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
}

TEST_F(AccessorTest, ObjectTemplateSetNativePropertyHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  templ->SetNativeDataProperty(NewString("foo"), Getter);
  templ->SetNativeDataProperty(NewString("foo2"), Getter, nullptr, {},
                               v8::PropertyAttribute::None,
                               v8::SideEffectType::kHasNoSideEffect);
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo2"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo2 = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo2"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
}

TEST_F(AccessorTest, ObjectTemplateSetLazyPropertyHasNoSideEffect) {
  v8::HandleScope scope(isolate());

  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate());
  NoopDelegate delegate;
  i_isolate->debug()->SetDebugDelegate(&delegate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate());
  templ->SetLazyDataProperty(NewString("foo"), Getter);
  templ->SetLazyDataProperty(NewString("foo2"), Getter, v8::Local<v8::Value>(),
                             v8::PropertyAttribute::None,
                             v8::SideEffectType::kHasNoSideEffect);
  v8::Local<v8::Object> obj = templ->NewInstance(context()).ToLocalChecked();
  CHECK(context()->Global()->Set(context(), NewString("obj"), obj).FromJust());

  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  v8::debug::EvaluateGlobal(
      isolate(), NewString("obj.foo2"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that setter is not allowlisted.
  v8::TryCatch try_catch(isolate());
  CHECK(v8::debug::EvaluateGlobal(
            isolate(), NewString("obj.foo2 = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(try_catch.HasCaught());
  CHECK_NE(1, v8::debug::EvaluateGlobal(isolate(), NewString("obj.foo2"),
                                        v8::debug::EvaluateGlobalMode::kDefault)
                  .ToLocalChecked()
                  ->Int32Value(context())
                  .FromJust());
}

namespace {
void FunctionNativeGetter(v8::Local<v8::Name> property,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetIsolate()->ThrowError(
      v8::String::NewFromUtf8(info.GetIsolate(), "side effect in getter")
          .ToLocalChecked());
}
}  // namespace

TEST_F(AccessorTest, BindFunctionTemplateSetNativeDataProperty) {
  v8::HandleScope scope(isolate());

  // Check that getter is called on Function.prototype.bind.
  {
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(isolate());
    templ->SetNativeDataProperty(NewString("name"), FunctionNativeGetter);
    v8::Local<v8::Function> func =
        templ->GetFunction(context()).ToLocalChecked();
    CHECK(context()
              ->Global()
              ->Set(context(), NewString("func"), func)
              .FromJust());

    v8::TryCatch try_catch(isolate());
    CHECK(TryRunJS("func.bind()").IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  // Check that getter is called on Function.prototype.bind.
  {
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(isolate());
    templ->SetNativeDataProperty(NewString("length"), FunctionNativeGetter);
    v8::Local<v8::Function> func =
        templ->GetFunction(context()).ToLocalChecked();
    CHECK(context()
              ->Global()
              ->Set(context(), NewString("func"), func)
              .FromJust());

    v8::TryCatch try_catch(isolate());
    CHECK(TryRunJS("func.bind()").IsEmpty());
    CHECK(try_catch.HasCaught());
  }
}

namespace {
v8::MaybeLocal<v8::Context> TestHostCreateShadowRealmContextCallback(
    v8::Local<v8::Context> initiator_context) {
  v8::Isolate* isolate = initiator_context->GetIsolate();
  v8::Local<v8::FunctionTemplate> global_constructor =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::ObjectTemplate> global_template =
      global_constructor->InstanceTemplate();

  // Check that getter is called on Function.prototype.bind.
  global_template->SetNativeDataProperty(
      v8::String::NewFromUtf8(isolate, "func1").ToLocalChecked(),
      [](v8::Local<v8::Name> property,
         const v8::PropertyCallbackInfo<v8::Value>& info) {
        v8::Isolate* isolate = info.GetIsolate();
        v8::Local<v8::FunctionTemplate> templ =
            v8::FunctionTemplate::New(isolate);
        templ->SetNativeDataProperty(
            v8::String::NewFromUtf8(isolate, "name").ToLocalChecked(),
            FunctionNativeGetter);
        info.GetReturnValue().Set(
            templ->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());
      });

  // Check that getter is called on Function.prototype.bind.
  global_template->SetNativeDataProperty(
      v8::String::NewFromUtf8(isolate, "func2").ToLocalChecked(),
      [](v8::Local<v8::Name> property,
         const v8::PropertyCallbackInfo<v8::Value>& info) {
        v8::Isolate* isolate = info.GetIsolate();
        v8::Local<v8::FunctionTemplate> templ =
            v8::FunctionTemplate::New(isolate);
        templ->SetNativeDataProperty(
            v8::String::NewFromUtf8(isolate, "length").ToLocalChecked(),
            FunctionNativeGetter);
        info.GetReturnValue().Set(
            templ->GetFunction(isolate->GetCurrentContext()).ToLocalChecked());
      });

  return v8::Context::New(isolate, nullptr, global_template);
}
}  // namespace

TEST_F(AccessorTest, WrapFunctionTemplateSetNativeDataProperty) {
  i::v8_flags.harmony_shadow_realm = true;
  isolate()->SetHostCreateShadowRealmContextCallback(
      TestHostCreateShadowRealmContextCallback);

  v8::HandleScope scope(isolate());
  // Check that getter is called on WrappedFunctionCreate.
  {
    v8::TryCatch try_catch(isolate());
    CHECK(TryRunJS("new ShadowRealm().evaluate('globalThis.func1')").IsEmpty());
    CHECK(try_catch.HasCaught());
  }
  // Check that getter is called on WrappedFunctionCreate.
  {
    v8::TryCatch try_catch(isolate());
    CHECK(TryRunJS("new ShadowRealm().evaluate('globalThis.func2')").IsEmpty());
    CHECK(try_catch.HasCaught());
  }
}

"""

```