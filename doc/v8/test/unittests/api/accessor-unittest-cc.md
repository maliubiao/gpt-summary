Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Identify the Core Purpose:**  The file name `accessor-unittest.cc` and the namespace `AccessorTest` immediately suggest that this code is testing the functionality of accessors in V8's API. Unit tests aim to verify specific, isolated behaviors.

2. **Scan for Key V8 API Elements:** Look for common V8 API classes and methods being used. Keywords like `v8::Isolate`, `v8::Context`, `v8::ObjectTemplate`, `v8::FunctionTemplate`, `v8::Private`, `v8::Object`, `SetAccessorProperty`, `SetNativeDataProperty`, `SetLazyDataProperty`, `GetFunction`, `SetPrivate`, `GetReturnValue`, and related test macros like `TEST_F`, `EXPECT_THAT`, `CHECK` are strong indicators.

3. **Recognize Test Structure:**  The `TEST_F(AccessorTest, ...)` structure signifies Google Test framework usage. Each `TEST_F` block represents an individual test case focusing on a particular aspect of accessors.

4. **Analyze Individual Test Cases (Iterative Process):**  Go through each `TEST_F` block and try to understand its specific goal.

    * **`CachedAccessor` and `CachedAccessorTurboFan`:** The names suggest testing a "cached accessor." The code creates an object with an accessor property (`draft`) that retrieves a hidden private property. The `UnreachableCallback` is a red herring; the test relies on the caching mechanism. `CachedAccessorTurboFan` seems to explore how TurboFan (V8's optimizing compiler) interacts with these cached accessors, using `%PrepareFunctionForOptimization` and `%OptimizeFunctionOnNextCall`.

    * **`CachedAccessorOnGlobalObject`:** Similar to the previous cached accessor tests, but this time the accessor is placed on the global object. This tests the behavior of accessors in the global scope.

    * **`RedeclareAccessor`:** The name is self-explanatory. This test verifies that attempting to redefine a non-configurable accessor throws an error. It uses `v8::TryCatch` to check for the expected exception.

    * **`AccessorsWithSideEffects`, `TemplateAccessorsWithSideEffects`, `NativeTemplateAccessorWithSideEffects`, `NativeAccessorsWithSideEffects`:**  These tests focus on the concept of "side effects" associated with accessors. They use `SetAccessorProperty` and `SetNativeDataProperty` with different `SideEffectType` flags. The `CheckSideEffectFreeAccesses` helper function and the `v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect` flag are crucial for verifying that accessors marked as side-effect-free behave as such.

    * **Tests involving `SetNativeDataProperty` and `SetLazyDataProperty` with `kHasNoSideEffect`:** These tests specifically check the behavior when accessors are explicitly marked as having no side effects. They verify that accessing these properties doesn't trigger side-effect checks during debugging evaluation.

    * **`BindFunctionTemplateSetNativeDataProperty`:** This test explores how accessors defined on function templates interact with the `bind()` method. It checks if accessing properties like `name` or `length` on a bound function triggers the accessor.

    * **`TestHostCreateShadowRealmContextCallback`:** This test seems to be examining accessors within the context of "Shadow Realms," a newer JavaScript feature for creating isolated execution environments.

5. **Identify Common Themes and Functionality:** Group related tests to understand the broader capabilities being tested:

    * **Basic Accessor Functionality:** Setting up getters and setters, accessing properties via accessors.
    * **Caching of Accessors:** How V8 optimizes repeated access to accessor properties.
    * **Interaction with TurboFan:**  Ensuring accessors work correctly with V8's optimizing compiler.
    * **Side Effects of Accessors:**  Controlling and verifying whether accessing or setting an accessor property has side effects.
    * **Accessors on Templates:** Defining accessors on object and function templates.
    * **Accessors on the Global Object:** Specific behavior of accessors in the global scope.
    * **Error Handling:**  Testing scenarios where accessor definitions lead to errors (e.g., redeclaration).
    * **Integration with Debugger:**  Using debugger flags to verify side-effect behavior.
    * **Accessors and Function `bind()`:**  Specific interaction with the `bind()` method.
    * **Accessors in Shadow Realms:** (Likely an emerging area of testing).

6. **Infer JavaScript Equivalents and Potential Errors:**  Based on the V8 API usage, consider how these concepts translate to JavaScript and what common mistakes developers might make. For example, misunderstanding how private properties work with accessors, or not being aware of the performance implications of non-cached accessors. The side-effect tests directly relate to optimizations the JavaScript engine can perform if it knows an operation is side-effect-free.

7. **Synthesize a Summary:** Combine the understanding of individual tests and common themes to create a concise summary of the file's functionality. Emphasize the core purpose of testing accessor behavior in various scenarios.

8. **Address Specific Constraints:**  Review the original request and ensure all points are covered:

    * **Functionality Listing:** Explicitly list the tested features.
    * **`.tq` Check:**  Verify the file extension and explain its meaning if it were `.tq`.
    * **JavaScript Examples:** Provide relevant JavaScript code demonstrating the concepts.
    * **Logic Inference/Input-Output:**  For tests involving specific logic (like caching), outline the expected behavior.
    * **Common Programming Errors:**  Give examples of mistakes related to accessors.
    * **Overall Summary:** Provide a high-level overview.

This iterative process of code scanning, individual test analysis, theme identification, and relating the C++ code to JavaScript concepts allows for a comprehensive understanding of the `accessor-unittest.cc` file.
```cpp
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
  obj->Set
### 提示词
```
这是目录为v8/test/unittests/api/accessor-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/api/accessor-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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

  return v8::Context::New(isolate
```