Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. I need to go through the code, identify the different test cases, and describe what each test is verifying. I should also check if any of the tests are related to JavaScript functionality and provide examples if so. The prompt also asks about `.tq` files (which is not the case here), code logic reasoning, common programming errors, and to remember this is part 14 of 36.

Here's a breakdown of the code and its functionality:

1. **`ReturnThisSloppy` and `ReturnThisStrict` Tests**: Checks how `this` is bound in sloppy and strict mode when calling functions with different receiver values.
2. **`CallableObject` Test**: Verifies the `IsCallable()` method for different object types (objects with and without `CallAsFunctionHandler`, functions).
3. **`Regress567998` Test**: Tests the behavior of an "undetectable" object (marked as such using `MarkAsUndetectable`) in various JavaScript operations (typeof, boolean contexts, logical operators, equality).
4. **`HandleIteration` Test**: Checks the correct counting of handles created within different `HandleScope`s.
5. **`CallICFastApi_DirectCall_GCMoveStub` Test**: Tests that direct calls to API functions still work after a garbage collection that might move the stub.
6. **`CallICFastApi_DirectCall_Throw` Test**: Checks that exceptions thrown from directly called API functions are caught correctly.
7. **`LoadICFastApi_DirectCall_GCMoveStub` Test**: Similar to the function call test, but for property getters. It verifies that direct calls to getters work after GC.
8. **`LoadICFastApi_DirectCall_Throw` Test**: Checks that exceptions thrown from directly called getter API functions are caught correctly.
9. **`InterceptorCallICFastApi_TrivialSignature` Test**: Tests property access interception and calling a fast API function from within the interceptor.
10. **`CallICFastApi_TrivialSignature` Test**: Tests calling a fast API function.
11. **`VariousGetPropertiesAndThrowingCallbacks` Test**: Checks how various `Get` operations behave when native getters throw exceptions.
12. **`GetRealNamedPropertyAttributes_With_Proxy` Test**: Tests how `GetRealNamedPropertyAttributes` handles exceptions thrown by proxy handlers.
13. **`ExceptionsDoNotPropagatePastTryCatch` Test**: Verifies that exceptions caught by a `TryCatch` block in a C++ callback do not propagate further.
14. **`Overriding` Test**: Checks how native property getters are overridden in inheritance scenarios.
15. **`AccessorShouldThrowOnError` Test**: Tests the `ShouldThrowOnError` flag for native accessors in sloppy and strict mode.
16. **`ShouldThrowOnError` Tests (with Interceptors)**:  Similar to the accessor test, but using interceptors to check `ShouldThrowOnError` for getters, setters, property queries, and deleters.

Now I can formulate the response based on these observations.
`v8/test/cctest/test-api.cc` 是一个 V8 源代码文件，它包含了大量的 C++ 单元测试，用于测试 V8 JavaScript 引擎的 C++ API 的各种功能。 这段代码是该文件的一部分，主要关注以下几个方面的测试：

**功能列表:**

1. **测试函数调用的 `this` 绑定行为:**  测试在非严格模式和严格模式下，使用 `CallAsFunction` 调用函数时，不同的接收者（receiver）值如何影响 `this` 的绑定。
2. **测试对象的可调用性 (`IsCallable`)**: 验证不同类型的对象（包括有 `CallAsFunctionHandler` 的对象和普通对象）是否被正确地识别为可调用的。
3. **测试不可检测对象的行为 (`MarkAsUndetectable`)**:  验证使用 `MarkAsUndetectable` 标记的对象在 JavaScript 中的各种操作（例如 `typeof`、布尔值转换、逻辑运算符、相等性比较）下的行为是否符合预期。
4. **测试 HandleScope 的使用和句柄计数:** 验证 `HandleScope` 的嵌套使用以及句柄的正确创建和释放。
5. **测试快速 API 调用的直接调用优化和垃圾回收:**  验证在垃圾回收可能移动代码的情况下，直接调用 C++ API 函数是否仍然能正常工作。
6. **测试快速 API 调用的直接调用和异常处理:** 验证从直接调用的 C++ API 函数中抛出的异常是否能被正确捕获。
7. **测试快速 API getter 的直接调用优化和垃圾回收:**  类似于函数调用，测试在垃圾回收可能移动代码的情况下，直接调用 C++ API getter 是否仍然能正常工作。
8. **测试快速 API getter 的直接调用和异常处理:** 验证从直接调用的 C++ API getter 中抛出的异常是否能被正确捕获。
9. **测试带有拦截器的快速 API 调用:**  验证当属性访问被拦截器处理时，调用快速 API 函数的行为。
10. **测试快速 API 函数的调用:**  验证直接调用快速 API 函数的功能。
11. **测试各种属性获取操作和抛出异常的回调:** 验证在 native getter 抛出异常的情况下，各种获取属性的操作（如 `GetRealNamedProperty`）的行为。
12. **测试带有 Proxy 的 `GetRealNamedPropertyAttributes`:**  验证 `GetRealNamedPropertyAttributes` 方法在处理 Proxy 对象时，如果 Proxy 的 handler 抛出异常时的行为。
13. **测试异常不会跨越 `TryCatch` 传播:**  验证在 C++ 回调函数中使用 `TryCatch` 捕获的异常不会传播到 JavaScript 代码中。
14. **测试 native getter 的覆盖 (Overriding):** 验证子类模板如何覆盖父类模板中定义的 native getter。
15. **测试 Accessor 的 `ShouldThrowOnError` 标志:**  验证在非严格模式和严格模式下，native accessor 的 `ShouldThrowOnError` 标志的行为。
16. **测试带有拦截器的 `ShouldThrowOnError` 标志:** 类似于上面的 accessor 测试，使用拦截器来验证 getter、setter、query 和 deleter 的 `ShouldThrowOnError` 标志的行为。

**关于 .tq 结尾的文件:**

代码段提供的文件路径是 `v8/test/cctest/test-api.cc`，它以 `.cc` 结尾，表明这是一个 C++ 源代码文件。 如果文件以 `.tq` 结尾，那么它将是 V8 Torque 源代码文件，Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。

**与 JavaScript 功能的关系及示例:**

这段 C++ 代码直接测试了 V8 引擎提供的 JavaScript 功能的底层实现。  例如，`ReturnThisSloppy` 和 `ReturnThisStrict` 测试了 JavaScript 中函数调用时 `this` 关键字的行为，这直接关系到 JavaScript 的核心语法。

**JavaScript 示例:**

```javascript
// 对应 ReturnThisSloppy 和 ReturnThisStrict 的测试
function ReturnThisSloppy() {
  return this;
}

function ReturnThisStrict() {
  'use strict';
  return this;
}

console.log(ReturnThisSloppy()); // 在浏览器中或 Node.js 中通常输出 globalThis (或 window)
console.log(ReturnThisSloppy.call(null)); // 输出 globalThis
console.log(ReturnThisSloppy.call(42)); // 输出 Number 包装对象
console.log(ReturnThisStrict()); // 输出 undefined
console.log(ReturnThisStrict.call(null)); // 输出 null
console.log(ReturnThisStrict.call(42)); // 输出 42
```

**代码逻辑推理及假设输入输出:**

**示例：`ReturnThisStrict` 测试**

*   **假设输入:**  一个在 V8 环境中定义的 JavaScript 函数 `ReturnThisStrict`，其内部使用了严格模式并返回 `this`。然后使用 `CallAsFunction` 方法以不同的接收者值调用该函数。
*   **代码逻辑:**  `CallAsFunction` 方法模拟 JavaScript 的函数调用。在严格模式下，`this` 的值直接取决于传递给 `call`、`apply` 或 `bind` 的第一个参数，如果没有传递，则为 `undefined`。
*   **预期输出:**
    *   当接收者是 `v8::Undefined(isolate)` 时，`this` 应该绑定到 `undefined`。
    *   当接收者是 `v8::Null(isolate)` 时，`this` 应该绑定到 `null`。
    *   当接收者是数字、字符串或布尔值时，`this` 应该直接绑定到该原始值。

**用户常见的编程错误及示例:**

与这段代码相关的常见编程错误通常发生在理解 JavaScript 中 `this` 的绑定规则时，特别是在非严格模式下。

**示例：错误的 `this` 绑定**

```javascript
function MyClass() {
  this.value = 42;
  setTimeout(function() {
    console.log(this.value); // 错误：这里的 this 通常不是 MyClass 的实例
  }, 100);
}

const instance = new MyClass();
```

在这个例子中，`setTimeout` 内部的回调函数中的 `this` 通常指向全局对象（在浏览器中是 `window`，在 Node.js 中是 `global`），而不是 `MyClass` 的实例。 解决这个问题的方法包括使用箭头函数（箭头函数会捕获其定义时的 `this` 值）或者使用 `bind`、`call` 或 `apply` 来显式地绑定 `this`。

**归纳功能 (第 14 部分，共 36 部分):**

作为 `v8/test/cctest/test-api.cc` 文件的第 14 部分，这段代码主要集中在 **测试 V8 引擎处理函数调用、对象可调用性、特殊对象行为（如不可检测对象）、HandleScope 管理、以及 C++ API 和 JavaScript 之间的互操作性，特别是涉及到直接调用优化和异常处理** 的能力。  它深入测试了 V8 的底层机制，确保引擎在各种场景下都能正确地执行 JavaScript 代码并与 C++ 代码进行交互。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
loppy"))
            .ToLocalChecked());
    Local<Function> ReturnThisStrict = Local<Function>::Cast(
        context->Global()
            ->Get(context.local(), v8_str("ReturnThisStrict"))
            .ToLocalChecked());

    Local<v8::Value> a1 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::Undefined(isolate), 0,
                             nullptr)
            .ToLocalChecked();
    CHECK(a1->StrictEquals(context->Global()));
    Local<v8::Value> a2 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::Null(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a2->StrictEquals(context->Global()));
    Local<v8::Value> a3 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8_num(42), 0, nullptr)
            .ToLocalChecked();
    CHECK(a3->IsNumberObject());
    CHECK_EQ(42.0, a3.As<v8::NumberObject>()->ValueOf());
    Local<v8::Value> a4 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8_str("hello"), 0, nullptr)
            .ToLocalChecked();
    CHECK(a4->IsStringObject());
    CHECK(a4.As<v8::StringObject>()->ValueOf()->StrictEquals(v8_str("hello")));
    Local<v8::Value> a5 =
        ReturnThisSloppy
            ->CallAsFunction(context.local(), v8::True(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a5->IsBooleanObject());
    CHECK(a5.As<v8::BooleanObject>()->ValueOf());

    Local<v8::Value> a6 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::Undefined(isolate), 0,
                             nullptr)
            .ToLocalChecked();
    CHECK(a6->IsUndefined());
    Local<v8::Value> a7 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::Null(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a7->IsNull());
    Local<v8::Value> a8 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8_num(42), 0, nullptr)
            .ToLocalChecked();
    CHECK(a8->StrictEquals(v8_num(42)));
    Local<v8::Value> a9 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8_str("hello"), 0, nullptr)
            .ToLocalChecked();
    CHECK(a9->StrictEquals(v8_str("hello")));
    Local<v8::Value> a10 =
        ReturnThisStrict
            ->CallAsFunction(context.local(), v8::True(isolate), 0, nullptr)
            .ToLocalChecked();
    CHECK(a10->StrictEquals(v8::True(isolate)));
  }
}


// Check whether a non-function object is callable.
THREADED_TEST(CallableObject) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  {
    Local<ObjectTemplate> instance_template = ObjectTemplate::New(isolate);
    instance_template->SetCallAsFunctionHandler(call_as_function);
    Local<Object> instance =
        instance_template->NewInstance(context.local()).ToLocalChecked();
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<ObjectTemplate> instance_template = ObjectTemplate::New(isolate);
    Local<Object> instance =
        instance_template->NewInstance(context.local()).ToLocalChecked();
    v8::TryCatch try_catch(isolate);

    CHECK(!instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<FunctionTemplate> function_template =
        FunctionTemplate::New(isolate, call_as_function);
    Local<Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();
    Local<Object> instance = function;
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }

  {
    Local<FunctionTemplate> function_template = FunctionTemplate::New(isolate);
    Local<Function> function =
        function_template->GetFunction(context.local()).ToLocalChecked();
    Local<Object> instance = function;
    v8::TryCatch try_catch(isolate);

    CHECK(instance->IsCallable());
    CHECK(!try_catch.HasCaught());
  }
}


THREADED_TEST(Regress567998) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());

  Local<v8::FunctionTemplate> desc =
      v8::FunctionTemplate::New(env->GetIsolate());
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  ExpectString("undetectable.toString()", "[object Object]");
  ExpectString("typeof undetectable", "undefined");
  ExpectString("typeof(undetectable)", "undefined");
  ExpectBoolean("typeof undetectable == 'undefined'", true);
  ExpectBoolean("typeof undetectable == 'object'", false);
  ExpectBoolean("if (undetectable) { true; } else { false; }", false);
  ExpectBoolean("!undetectable", true);

  ExpectObject("true&&undetectable", obj);
  ExpectBoolean("false&&undetectable", false);
  ExpectBoolean("true||undetectable", true);
  ExpectObject("false||undetectable", obj);

  ExpectObject("undetectable&&true", obj);
  ExpectObject("undetectable&&false", obj);
  ExpectBoolean("undetectable||true", true);
  ExpectBoolean("undetectable||false", false);

  ExpectBoolean("undetectable==null", true);
  ExpectBoolean("null==undetectable", true);
  ExpectBoolean("undetectable==undefined", true);
  ExpectBoolean("undefined==undetectable", true);
  ExpectBoolean("undetectable==undetectable", true);

  ExpectBoolean("undetectable===null", false);
  ExpectBoolean("null===undetectable", false);
  ExpectBoolean("undetectable===undefined", false);
  ExpectBoolean("undefined===undetectable", false);
  ExpectBoolean("undetectable===undetectable", true);
}


static int Recurse(v8::Isolate* isolate, int depth, int iterations) {
  v8::HandleScope scope(isolate);
  if (depth == 0) return v8::HandleScope::NumberOfHandles(isolate);
  for (int i = 0; i < iterations; i++) {
    Local<v8::Number> n(v8::Integer::New(isolate, 42));
  }
  return Recurse(isolate, depth - 1, iterations);
}


THREADED_TEST(HandleIteration) {
  static const int kIterations = 500;
  static const int kNesting = 200;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope0(isolate);
  CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
  {
    v8::HandleScope scope1(isolate);
    CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
    for (int i = 0; i < kIterations; i++) {
      Local<v8::Number> n(v8::Integer::New(CcTest::isolate(), 42));
      CHECK_EQ(i + 1, v8::HandleScope::NumberOfHandles(isolate));
    }

    CHECK_EQ(kIterations, v8::HandleScope::NumberOfHandles(isolate));
    {
      v8::HandleScope scope2(CcTest::isolate());
      for (int j = 0; j < kIterations; j++) {
        Local<v8::Number> n(v8::Integer::New(CcTest::isolate(), 42));
        CHECK_EQ(j + 1 + kIterations,
                 v8::HandleScope::NumberOfHandles(isolate));
      }
    }
    CHECK_EQ(kIterations, v8::HandleScope::NumberOfHandles(isolate));
  }
  CHECK_EQ(0, v8::HandleScope::NumberOfHandles(isolate));
  CHECK_EQ(kNesting * kIterations, Recurse(isolate, kNesting, kIterations));
}

namespace {
v8::Intercepted InterceptorCallICFastApi(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  CheckReturnValue(info, FUNCTION_ADDR(InterceptorCallICFastApi));
  int* call_count =
      reinterpret_cast<int*>(v8::External::Cast(*info.Data())->Value());
  ++(*call_count);
  if ((*call_count) % 20 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
  }
  return v8::Intercepted::kNo;
}

void FastApiCallback_TrivialSignature(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(FastApiCallback_TrivialSignature));
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(info.This()
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  CHECK(info.Data()
            ->Equals(isolate->GetCurrentContext(), v8_str("method_data"))
            .FromJust());
  info.GetReturnValue().Set(
      info[0]->Int32Value(isolate->GetCurrentContext()).FromJust() + 1);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

void FastApiCallback_SimpleSignature(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CheckReturnValue(info, FUNCTION_ADDR(FastApiCallback_SimpleSignature));
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CHECK(info.This()
            ->GetPrototype()
            ->Equals(isolate->GetCurrentContext(),
                     info.HolderSoonToBeDeprecated())
            .FromJust());
  CHECK(info.Data()
            ->Equals(isolate->GetCurrentContext(), v8_str("method_data"))
            .FromJust());
  // Note, we're using HasRealNamedProperty instead of Has to avoid
  // invoking the interceptor again.
  CHECK(info.HolderSoonToBeDeprecated()
            ->HasRealNamedProperty(isolate->GetCurrentContext(), v8_str("foo"))
            .FromJust());
  info.GetReturnValue().Set(
      info[0]->Int32Value(isolate->GetCurrentContext()).FromJust() + 1);
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

// Helper to maximize the odds of object moving.
void GenerateSomeGarbage() {
  CompileRun(
      "var garbage;"
      "for (var i = 0; i < 1000; i++) {"
      "  garbage = [1/i, \"garbage\" + i, garbage, {foo: garbage}];"
      "}"
      "garbage = undefined;");
}

void DirectApiCallback(const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  static int count = 0;
  if (count++ % 3 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
    // This should move the stub
    GenerateSomeGarbage();  // This should ensure the old stub memory is flushed
  }
}
}  // namespace

THREADED_TEST(CallICFastApi_DirectCall_GCMoveStub) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> nativeobject_templ =
      v8::ObjectTemplate::New(isolate);
  nativeobject_templ->Set(isolate, "callback",
                          v8::FunctionTemplate::New(isolate,
                                                    DirectApiCallback));
  v8::Local<v8::Object> nativeobject_obj =
      nativeobject_templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("nativeobject"), nativeobject_obj)
            .FromJust());
  // call the api function multiple times to ensure direct call stub creation.
  CompileRun(
      "function f() {"
      "  for (var i = 1; i <= 30; i++) {"
      "    nativeobject.callback();"
      "  }"
      "}"
      "f();");
}

void ThrowingDirectApiCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  args.GetIsolate()->ThrowException(v8_str("g"));
}

THREADED_TEST(CallICFastApi_DirectCall_Throw) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> nativeobject_templ =
      v8::ObjectTemplate::New(isolate);
  nativeobject_templ->Set(
      isolate, "callback",
      v8::FunctionTemplate::New(isolate, ThrowingDirectApiCallback));
  v8::Local<v8::Object> nativeobject_obj =
      nativeobject_templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("nativeobject"), nativeobject_obj)
            .FromJust());
  // call the api function multiple times to ensure direct call stub creation.
  v8::Local<Value> result = CompileRun(
      "var result = '';"
      "function f() {"
      "  for (var i = 1; i <= 5; i++) {"
      "    try { nativeobject.callback(); } catch (e) { result += e; }"
      "  }"
      "}"
      "f(); result;");
  CHECK(v8_str("ggggg")->Equals(context.local(), result).FromJust());
}

namespace {
int p_getter_count_3;

Local<Value> DoDirectGetter() {
  if (++p_getter_count_3 % 3 == 0) {
    i::heap::InvokeMajorGC(CcTest::heap());
    GenerateSomeGarbage();
  }
  return v8_str("Direct Getter Result");
}

void DirectGetterCallback(Local<Name> name,
                          const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CheckReturnValue(info, FUNCTION_ADDR(DirectGetterCallback));
  info.GetReturnValue().Set(DoDirectGetter());
}

template <typename Accessor>
void LoadICFastApi_DirectCall_GCMoveStub(Accessor accessor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = v8::ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), accessor);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  p_getter_count_3 = 0;
  v8::Local<v8::Value> result = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 30; i++) o1.p1;"
      "  return o1.p1"
      "}"
      "f();");
  CHECK(v8_str("Direct Getter Result")
            ->Equals(context.local(), result)
            .FromJust());
  CHECK_EQ(31, p_getter_count_3);
}
}  // namespace

THREADED_PROFILED_TEST(LoadICFastApi_DirectCall_GCMoveStub) {
  LoadICFastApi_DirectCall_GCMoveStub(DirectGetterCallback);
}

void ThrowingDirectGetterCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetIsolate()->ThrowException(v8_str("g"));
}

THREADED_TEST(LoadICFastApi_DirectCall_Throw) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = v8::ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), ThrowingDirectGetterCallback);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<Value> result = CompileRun(
      "var result = '';"
      "for (var i = 0; i < 5; i++) {"
      "    try { o1.p1; } catch (e) { result += e; }"
      "}"
      "result;");
  CHECK(v8_str("ggggg")->Equals(context.local(), result).FromJust());
}

THREADED_PROFILED_TEST(InterceptorCallICFastApi_TrivialSignature) {
  int interceptor_call_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> method_templ = v8::FunctionTemplate::New(
      isolate, FastApiCallback_TrivialSignature, v8_str("method_data"),
      v8::Local<v8::Signature>());
  v8::Local<v8::ObjectTemplate> proto_templ = fun_templ->PrototypeTemplate();
  proto_templ->Set(isolate, "method", method_templ);
  v8::Local<v8::ObjectTemplate> templ = fun_templ->InstanceTemplate();
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      InterceptorCallICFastApi, nullptr, nullptr, nullptr, nullptr,
      v8::External::New(isolate, &interceptor_call_count)));
  LocalContext context;
  v8::Local<v8::Function> fun =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  GenerateSomeGarbage();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  fun->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 100; i++) {"
      "  result = o.method(41);"
      "}");
  CHECK_EQ(42, context->Global()
                   ->Get(context.local(), v8_str("result"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(100, interceptor_call_count);
}

THREADED_PROFILED_TEST(CallICFastApi_TrivialSignature) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::FunctionTemplate> method_templ = v8::FunctionTemplate::New(
      isolate, FastApiCallback_TrivialSignature, v8_str("method_data"),
      v8::Local<v8::Signature>());
  v8::Local<v8::ObjectTemplate> proto_templ = fun_templ->PrototypeTemplate();
  proto_templ->Set(isolate, "method", method_templ);
  v8::Local<v8::ObjectTemplate> templ(fun_templ->InstanceTemplate());
  USE(templ);
  LocalContext context;
  v8::Local<v8::Function> fun =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  GenerateSomeGarbage();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  fun->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 100; i++) {"
      "  result = o.method(41);"
      "}");

  CHECK_EQ(42, context->Global()
                   ->Get(context.local(), v8_str("result"))
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
}

static void ThrowingGetter(Local<Name> name,
                           const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetIsolate()->ThrowException(Local<Value>());
  info.GetReturnValue().SetUndefined();
}

THREADED_TEST(VariousGetPropertiesAndThrowingCallbacks) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  Local<ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetNativeDataProperty(v8_str("f"), ThrowingGetter);

  Local<Object> instance = templ->GetFunction(context.local())
                               .ToLocalChecked()
                               ->NewInstance(context.local())
                               .ToLocalChecked();

  Local<Object> another = Object::New(context->GetIsolate());
  CHECK(another->SetPrototypeV2(context.local(), instance).FromJust());

  Local<Object> with_js_getter = CompileRun(
      "o = {};\n"
      "o.__defineGetter__('f', function() { throw undefined; });\n"
      "o\n").As<Object>();
  CHECK(!with_js_getter.IsEmpty());

  TryCatch try_catch(context->GetIsolate());

  v8::MaybeLocal<Value> result =
      instance->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  Maybe<PropertyAttribute> attr =
      instance->GetRealNamedPropertyAttributes(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = another->GetRealNamedPropertyAttributes(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->GetRealNamedPropertyInPrototypeChain(context.local(),
                                                         v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = another->GetRealNamedPropertyAttributesInPrototypeChain(
      context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = another->Get(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  result = with_js_getter->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  attr = with_js_getter->GetRealNamedPropertyAttributes(context.local(),
                                                        v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(Just(None) == attr);

  result = with_js_getter->Get(context.local(), v8_str("f"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(result.IsEmpty());

  Local<Object> target = CompileRun("({})").As<Object>();
  Local<Object> handler = CompileRun("({})").As<Object>();
  Local<v8::Proxy> proxy =
      v8::Proxy::New(context.local(), target, handler).ToLocalChecked();

  result = target->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(result.IsEmpty());

  result = proxy->GetRealNamedProperty(context.local(), v8_str("f"));
  CHECK(!try_catch.HasCaught());
  CHECK(result.IsEmpty());
}

THREADED_TEST(GetRealNamedPropertyAttributes_With_Proxy) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  {
    Local<Object> proxy =
        CompileRun(
            "new Proxy({ p: 1 }, { getOwnPropertyDescriptor: _ => { "
            "  throw new Error('xyz'); } });")
            .As<Object>();
    TryCatch try_catch(context->GetIsolate());
    v8::Maybe<v8::PropertyAttribute> result =
        proxy->GetRealNamedPropertyAttributes(context.local(), v8_str("p"));
    CHECK(result.IsNothing());
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()
              .As<Object>()
              ->Get(context.local(), v8_str("message"))
              .ToLocalChecked()
              ->StrictEquals(v8_str("xyz")));
  }

  {
    Local<Object> proxy =
        CompileRun(
            "Object.create("
            "  new Proxy({ p: 1 }, { getOwnPropertyDescriptor: _ => { "
            "    throw new Error('abc'); } }))")
            .As<Object>();
    TryCatch try_catch(context->GetIsolate());
    v8::Maybe<v8::PropertyAttribute> result =
        proxy->GetRealNamedPropertyAttributesInPrototypeChain(context.local(),
                                                              v8_str("p"));
    CHECK(result.IsNothing());
    CHECK(try_catch.HasCaught());
    CHECK(try_catch.Exception()
              .As<Object>()
              ->Get(context.local(), v8_str("message"))
              .ToLocalChecked()
              ->StrictEquals(v8_str("abc")));
  }
}

static void ThrowingCallbackWithTryCatch(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  TryCatch try_catch(args.GetIsolate());
  // Verboseness is important: it triggers message delivery which can call into
  // external code.
  try_catch.SetVerbose(true);
  CompileRun("throw 'from JS';");
  CHECK(try_catch.HasCaught());
}


static int call_depth;


static void WithTryCatch(Local<Message> message, Local<Value> data) {
  TryCatch try_catch(CcTest::isolate());
}


static void ThrowFromJS(Local<Message> message, Local<Value> data) {
  if (--call_depth) CompileRun("throw 'ThrowInJS';");
}


static void ThrowViaApi(Local<Message> message, Local<Value> data) {
  if (--call_depth) CcTest::isolate()->ThrowException(v8_str("ThrowViaApi"));
}


static void WebKitLike(Local<Message> message, Local<Value> data) {
  Local<String> errorMessageString = message->Get();
  CHECK(!errorMessageString.IsEmpty());
  message->GetStackTrace();
  message->GetScriptOrigin().ResourceName();
}


THREADED_TEST(ExceptionsDoNotPropagatePastTryCatch) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  HandleScope scope(isolate);

  Local<Function> func =
      FunctionTemplate::New(isolate, ThrowingCallbackWithTryCatch)
          ->GetFunction(context.local())
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("func"), func).FromJust());

  MessageCallback callbacks[] = {nullptr, WebKitLike, ThrowViaApi, ThrowFromJS,
                                 WithTryCatch};
  for (unsigned i = 0; i < sizeof(callbacks)/sizeof(callbacks[0]); i++) {
    MessageCallback callback = callbacks[i];
    if (callback != nullptr) {
      isolate->AddMessageListener(callback);
    }
    // Some small number to control number of times message handler should
    // throw an exception.
    call_depth = 5;
    ExpectFalse(
        "var thrown = false;\n"
        "try { func(); } catch(e) { thrown = true; }\n"
        "thrown\n");
    if (callback != nullptr) {
      isolate->RemoveMessageListeners(callback);
    }
  }
}

static void ParentGetter(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(1));
}

static void ChildGetter(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(v8_num(42));
}

THREADED_TEST(Overriding) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Parent template.
  Local<v8::FunctionTemplate> parent_templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> parent_instance_templ =
      parent_templ->InstanceTemplate();
  parent_instance_templ->SetNativeDataProperty(v8_str("f"), ParentGetter);

  // Template that inherits from the parent template.
  Local<v8::FunctionTemplate> child_templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> child_instance_templ =
      child_templ->InstanceTemplate();
  child_templ->Inherit(parent_templ);
  // Override 'f'.  The child version of 'f' should get called for child
  // instances.
  child_instance_templ->SetNativeDataProperty(v8_str("f"), ChildGetter);
  // Add 'g' twice.  The 'g' added last should get called for instances.
  child_instance_templ->SetNativeDataProperty(v8_str("g"), ParentGetter);
  child_instance_templ->SetNativeDataProperty(v8_str("g"), ChildGetter);

  // Add 'h' as an accessor to the proto template with ReadOnly attributes
  // so 'h' can be shadowed on the instance object.
  Local<ObjectTemplate> child_proto_templ = child_templ->PrototypeTemplate();
  child_proto_templ->SetNativeDataProperty(v8_str("h"), ParentGetter, nullptr,
                                           v8::Local<Value>(), v8::ReadOnly);

  // Add 'i' as an accessor to the instance template with ReadOnly attributes
  // but the attribute does not have effect because it is duplicated with
  // nullptr setter.
  child_instance_templ->SetNativeDataProperty(v8_str("i"), ChildGetter, nullptr,
                                              v8::Local<Value>(), v8::ReadOnly);

  // Instantiate the child template.
  Local<v8::Object> instance = child_templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();

  // Check that the child function overrides the parent one.
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"), instance)
            .FromJust());
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  // Check that the 'g' that was added last is hit.
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
  value = v8_compile("o.g")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());

  // Check that 'h' cannot be shadowed.
  value = v8_compile("o.h = 3; o.h")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(1, value->Int32Value(context.local()).FromJust());

  // Check that 'i' cannot be shadowed or changed.
  value = v8_compile("o.i = 3; o.i")->Run(context.local()).ToLocalChecked();
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
}

namespace {
void ShouldThrowOnErrorAccessorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<Boolean> should_throw_on_error =
      Boolean::New(isolate, info.ShouldThrowOnError());
  info.GetReturnValue().Set(should_throw_on_error);
}

void ShouldThrowOnErrorAccessorSetter(
    Local<Name> name, Local<v8::Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_setter"),
                  should_throw_on_error_value)
            .FromJust());
}
}  // namespace

THREADED_TEST(AccessorShouldThrowOnError) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  Local<ObjectTemplate> instance_templ = templ->InstanceTemplate();
  instance_templ->SetNativeDataProperty(v8_str("f"),
                                        ShouldThrowOnErrorAccessorGetter,
                                        ShouldThrowOnErrorAccessorSetter);

  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();

  CHECK(global->Set(context.local(), v8_str("o"), instance).FromJust());

  // SLOPPY mode
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  // STRICT mode
  value = v8_compile("'use strict';o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("'use strict'; o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());
}

namespace {
v8::Intercepted ShouldThrowOnErrorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<Boolean> should_throw_on_error =
      Boolean::New(isolate, info.ShouldThrowOnError());
  info.GetReturnValue().Set(should_throw_on_error);
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorSetter(
    Local<Name> name, Local<v8::Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_setter"),
                  should_throw_on_error_value)
            .FromJust());
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorQuery(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::None);

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_query"),
                  should_throw_on_error_value)
            .FromJust());
  return v8::Intercepted::kYes;
}

v8::Intercepted ShouldThrowOnErrorDeleter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  info.GetReturnValue().Set(v8::True(isolate));

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(), v8_str("should_throw_deleter"),
                  should_throw_on_error_value)
```