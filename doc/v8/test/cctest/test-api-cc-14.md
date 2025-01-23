Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of how to analyze the code:

1. **Identify Core Functionality:** Look for the main test cases and the C++ functions they call. The `TEST` and `THREADED_TEST` macros indicate individual tests.

2. **Analyze Test Names:** Test names like `InterceptorShouldThrowOnError`, `CallHandlerHasNoSideEffect`, `FunctionTemplateNewHasNoSideEffect`, `ObjectProtoToString`, and `ObjectGetConstructorName` give strong hints about what each test verifies.

3. **Examine C++ Functions:** Pay attention to functions like `ShouldThrowOnErrorGetter`, `ShouldThrowOnErrorSetter`, `EmptyHandler`, `DefaultConstructHandler`, `IsConstructHandler`, and `NewTargetHandler`. These functions define the behavior being tested.

4. **Look for JavaScript Interactions:** The tests frequently use `v8_compile` and `CompileRun` to execute JavaScript code within the C++ tests. Analyze the JavaScript strings to understand how the C++ APIs are being used.

5. **Infer Purpose from JavaScript:**  The JavaScript code often sets up scenarios (like defining objects with interceptors or calling functions) to trigger the C++ code under test.

6. **Identify Potential Errors:**  Some tests explicitly check for error conditions or side effects, which can reveal common programming mistakes.

7. **Pay Attention to "Side Effect" Tests:**  Several tests focus on verifying that certain V8 API calls do or do not have side effects, especially in contexts where side effects are undesirable.

8. **Analyze `ApiTestFuzzer`:**  The presence of `ApiTestFuzzer` and related methods like `Fuzz`, `NextThread`, and `Run` indicates a focus on thread safety and concurrent execution testing.

**High-Level Plan:**

* For each test, determine the V8 API being tested and its intended behavior.
* If JavaScript is involved, provide an example illustrating the concept.
* Identify potential error scenarios highlighted by the tests.
* Summarize the overall purpose of the code snippet.
目录 `v8/test/cctest/test-api.cc` 的第 15 部分主要关注 V8 C++ API 的以下功能：

**主要功能归纳：**

1. **属性拦截器 (`Interceptor`) 的 `ShouldThrowOnError` 行为：**  测试在严格模式和非严格模式下，通过属性拦截器（`NamedPropertyHandlerConfiguration`）进行的属性访问（get, set, delete, enumerate）操作，当发生错误时，`ShouldThrowOnError` 方法的返回值是否符合预期。

2. **函数调用处理器的副作用分析 (`CallHandlerHasNoSideEffect` 等)：**  测试不同的函数创建和调用方式（通过 `FunctionTemplate`、`Function::New` 等），以及设置 `SideEffectType` 属性，是否会影响 V8 的副作用分析机制。这对于性能优化和安全上下文（如禁用副作用的调试评估）很重要。

3. **`IsConstructCall` API：** 测试在函数调用处理器中，如何通过 `args.IsConstructCall()` 判断函数是否是通过 `new` 关键字调用的。

4. **`NewTarget` API：** 测试在函数调用处理器中，如何通过 `args.NewTarget()` 获取到 `new` 关键字的目标构造函数。这在类继承等场景中非常有用。

5. **`ObjectProtoToString` API：** 测试 `Object::ObjectProtoToString` 方法的功能，该方法用于获取对象的 `[[Prototype]].toString()` 的结果，并且不受用户自定义的 `Object.prototype.toString` 方法的影响。同时，也测试了 ES6 中 `Symbol.toStringTag` 对该方法的影响。

6. **`Object::GetConstructorName` API：** 测试 `Object::GetConstructorName()` 方法，用于获取对象的构造函数名称。

7. **多线程测试框架 (`ApiTestFuzzer`) 的初始化和基本运行逻辑：** 这部分代码包含了 `ApiTestFuzzer` 类的部分实现，用于进行并发测试。它负责设置、启动和调度多个测试线程。

**具体功能及 JavaScript 示例：**

1. **属性拦截器的 `ShouldThrowOnError` 行为**

   * **功能：**  验证当使用属性拦截器处理属性访问时，`ShouldThrowOnError` 方法能够正确反映当前执行上下文是否为严格模式。
   * **JavaScript 示例：**

     ```javascript
     // 假设 C++ 代码中已经创建了名为 'o' 的对象，并设置了相应的拦截器

     // 非严格模式
     o.f;        // 不会抛出错误，即使拦截器返回 false
     o.f = 153;  // 不会抛出错误，即使拦截器返回 false
     delete o.f; // 不会抛出错误，即使拦截器返回 false
     Object.getOwnPropertyNames(o); // 枚举时，即使拦截器返回错误，也不会终止

     // 严格模式
     'use strict';
     o.f;        // 不会抛出错误，即使拦截器返回 false
     o.f = 153;  // 如果拦截器设置了 ShouldThrowOnError，这里会抛出 TypeError
     delete o.f; // 如果拦截器设置了 ShouldThrowOnError，这里会抛出 TypeError
     Object.getOwnPropertyNames(o); // 枚举时，即使拦截器返回错误，也不会终止
     ```

   * **代码逻辑推理（假设输入与输出）：**
      * **输入：**  在非严格模式下访问对象 `o` 的属性 `f`，拦截器的 `ShouldThrowOnErrorGetter` 返回 `false`。
      * **输出：**  JavaScript 代码 `o.f` 执行成功，返回 `false`。
      * **输入：**  在严格模式下设置对象 `o` 的属性 `f` 为 `153`，拦截器的 `ShouldThrowOnErrorSetter` 返回 `true`。
      * **输出：**  JavaScript 代码 `o.f = 153` 抛出 `TypeError` 异常。

   * **用户常见的编程错误：**  不了解严格模式下属性拦截器的 `ShouldThrowOnError` 行为，可能导致在严格模式下本应抛出的错误被忽略。

2. **函数调用处理器的副作用分析**

   * **功能：** 验证 V8 能够根据 `SideEffectType` 的设置，判断函数调用是否会产生副作用。这用于优化代码，例如在调试模式下可以安全地跳过无副作用的函数调用。
   * **JavaScript 示例：**

     ```javascript
     // 假设 C++ 代码中创建了函数 f 和 f2

     function f() { /* 一些可能有副作用的代码 */ }
     function f2() { /* 明确声明没有副作用的代码 */ }

     // 在禁用副作用检查的模式下评估
     // f() 的评估会被阻止，因为没有声明无副作用
     // f2() 的评估会被允许，因为它声明了无副作用

     new f(); // 在禁用副作用检查的模式下评估会被阻止
     new f2(); // 在禁用副作用检查的模式下评估会被允许
     ```

   * **代码逻辑推理：**
      * **输入：**  执行 `v8::debug::EvaluateGlobal` 并设置 `kDisableBreaksAndThrowOnSideEffect` 模式，调用未声明为无副作用的函数 `f`。
      * **输出：**  `EvaluateGlobal` 返回空（`IsEmpty()` 为 true）。
      * **输入：**  执行 `v8::debug::EvaluateGlobal` 并设置 `kDisableBreaksAndThrowOnSideEffect` 模式，调用声明为无副作用的函数 `f2`。
      * **输出：**  `EvaluateGlobal` 执行成功。

   * **用户常见的编程错误：**  在需要保证无副作用的场景（例如性能关键代码或安全上下文）下，没有正确设置 `SideEffectType`，导致不必要的副作用或潜在的安全问题。

3. **`IsConstructCall` API**

   * **功能：**  允许在函数调用处理器中判断函数是否通过 `new` 关键字调用。
   * **JavaScript 示例：**

     ```javascript
     function MyFunction() {
       if (new.target) {
         console.log("通过 new 调用");
       } else {
         console.log("作为普通函数调用");
       }
     }

     MyFunction(); // 输出 "作为普通函数调用"
     new MyFunction(); // 输出 "通过 new 调用"
     ```

   * **代码逻辑推理：**
      * **输入：**  通过 `f()` 调用在 C++ 中设置了 `IsConstructHandler` 的函数。
      * **输出：**  `IsConstructHandler` 中的 `args.IsConstructCall()` 返回 `false`。
      * **输入：**  通过 `new f()` 调用在 C++ 中设置了 `IsConstructHandler` 的函数。
      * **输出：**  `IsConstructHandler` 中的 `args.IsConstructCall()` 返回 `true`。

4. **`NewTarget` API**

   * **功能：**  允许在函数调用处理器中获取 `new` 关键字的目标构造函数。
   * **JavaScript 示例：**

     ```javascript
     function MyFunction() {
       console.log(new.target);
     }

     MyFunction(); // 输出 undefined
     new MyFunction(); // 输出 function MyFunction() { ... }
     class MyClass extends MyFunction {}
     new MyClass(); // 输出 class MyClass extends MyFunction {}
     ```

   * **代码逻辑推理：**
      * **输入：**  通过 `f()` 调用在 C++ 中设置了 `NewTargetHandler` 的函数。
      * **输出：**  `NewTargetHandler` 中的 `args.NewTarget()` 返回 `undefined`。
      * **输入：**  通过 `new f()` 调用在 C++ 中设置了 `NewTargetHandler` 的函数，`f` 是一个函数对象。
      * **输出：**  `NewTargetHandler` 中的 `args.NewTarget()` 返回与 `f` 相同的函数对象。
      * **输入：**  通过 `new g()` 调用在 C++ 中设置了 `NewTargetHandler` 的函数，`g` 是继承自 `f` 的类。
      * **输出：**  `NewTargetHandler` 中的 `args.NewTarget()` 返回与 `g` 相同的类构造函数。

5. **`ObjectProtoToString` API**

   * **功能：** 提供了一种获取对象默认 `toString` 结果的方式，不受用户修改 `Object.prototype.toString` 的影响。同时，遵循 ES6 的 `Symbol.toStringTag` 规范。
   * **JavaScript 示例：**

     ```javascript
     function MyClass() {}
     const instance = new MyClass();

     Object.prototype.toString = function() { return "custom"; };

     console.log(instance.toString()); // 输出 "custom" (如果 Object.prototype.toString 被修改)
     // ObjectProtoToString 总是返回默认的字符串表示
     // (取决于 Symbol.toStringTag)

     // ES6 Symbol.toStringTag
     const obj = {};
     obj[Symbol.toStringTag] = 'MyCustomTag';
     console.log(Object.prototype.toString.call(obj)); // 输出 "[object MyCustomTag]"
     ```

   * **代码逻辑推理：**
      * **输入：**  调用一个普通对象的 `ObjectProtoToString` 方法。
      * **输出：**  返回字符串 `"[object Object]"`。
      * **输入：**  调用一个设置了 `Symbol.toStringTag` 属性的对象的 `ObjectProtoToString` 方法，例如 `obj[Symbol.toStringTag] = 'Test'`。
      * **输出：**  返回字符串 `"[object Test]"`。

6. **`Object::GetConstructorName` API**

   * **功能：** 获取对象的构造函数名称。
   * **JavaScript 示例：**

     ```javascript
     function Parent() {}
     function Child() {}
     Child.prototype = new Parent();
     const child = new Child();
     console.log(child.constructor.name); // 输出 "Child"
     ```

   * **代码逻辑推理：**
      * **输入：**  一个通过 `new Parent()` 创建的对象。
      * **输出：**  `GetConstructorName` 返回字符串 `"Parent"`。
      * **输入：**  一个通过 `new Child()` 创建的对象，`Child` 继承自 `Parent`。
      * **输出：**  `GetConstructorName` 返回字符串 `"Child"`。

7. **多线程测试框架 (`ApiTestFuzzer`)**

   * **功能：**  用于并发地运行 V8 API 的测试用例，以检测潜在的线程安全问题。
   * **用户常见的编程错误：**  在编写 V8 扩展或嵌入代码时，没有考虑多线程环境下的数据竞争和同步问题。

**总结：**

这段代码主要测试了 V8 C++ API 中关于属性拦截、函数调用处理器、对象类型判断以及对象信息获取等方面的功能，并初步展示了 V8 的多线程测试框架的用法。这些测试用例旨在确保 V8 API 的行为符合预期，并且在多线程环境下能够正确运行。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第15部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
.FromJust());
  return v8::Intercepted::kYes;
}

void ShouldThrowOnErrorPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  Local<v8::Array> names = v8::Array::New(isolate, 1);
  CHECK(names->Set(isolate->GetCurrentContext(), names, v8_num(1)).FromJust());
  info.GetReturnValue().Set(names);

  auto context = isolate->GetCurrentContext();
  Local<Boolean> should_throw_on_error_value =
      Boolean::New(isolate, info.ShouldThrowOnError());
  CHECK(context->Global()
            ->Set(isolate->GetCurrentContext(),
                  v8_str("should_throw_enumerator"),
                  should_throw_on_error_value)
            .FromJust());
}
}  // namespace

THREADED_TEST(InterceptorShouldThrowOnError) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration handler(
      ShouldThrowOnErrorGetter, ShouldThrowOnErrorSetter,
      ShouldThrowOnErrorQuery, ShouldThrowOnErrorDeleter,
      ShouldThrowOnErrorPropertyEnumerator);
  interceptor_templ->SetHandler(handler);

  Local<v8::Object> instance =
      interceptor_templ->NewInstance(context.local()).ToLocalChecked();

  CHECK(global->Set(context.local(), v8_str("o"), instance).FromJust());

  // SLOPPY mode
  Local<Value> value = v8_compile("o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  v8_compile("delete o.f")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_deleter"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  v8_compile("Object.getOwnPropertyNames(o)")
      ->Run(context.local())
      .ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_enumerator"))
              .ToLocalChecked();
  CHECK(value->IsFalse());

  // STRICT mode
  value = v8_compile("'use strict';o.f")->Run(context.local()).ToLocalChecked();
  CHECK(value->IsFalse());
  v8_compile("'use strict'; o.f = 153")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_setter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());

  v8_compile("'use strict'; delete o.f")->Run(context.local()).ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_deleter"))
              .ToLocalChecked();
  CHECK(value->IsTrue());

  v8_compile("'use strict'; Object.getOwnPropertyNames(o)")
      ->Run(context.local())
      .ToLocalChecked();
  value = global->Get(context.local(), v8_str("should_throw_enumerator"))
              .ToLocalChecked();
  CHECK(value->IsFalse());
}

static void EmptyHandler(const v8::FunctionCallbackInfo<v8::Value>& args) {}

TEST(CallHandlerHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(EmptyHandler);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::New(isolate);
  templ2->SetCallHandler(EmptyHandler, v8::Local<Value>(),
                         v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionTemplateNewHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(isolate, EmptyHandler);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::New(
      isolate, EmptyHandler, v8::Local<Value>(), v8::Local<v8::Signature>(), 0,
      v8::ConstructorBehavior::kAllow, v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionTemplateNewWithCacheHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;
  v8::Local<v8::Private> priv =
      v8::Private::ForApi(isolate, v8_str("Foo#draft"));

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::NewWithCache(isolate, EmptyHandler, priv);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<v8::FunctionTemplate> templ2 = v8::FunctionTemplate::NewWithCache(
      isolate, EmptyHandler, priv, v8::Local<Value>(),
      v8::Local<v8::Signature>(), 0, v8::SideEffectType::kHasNoSideEffect);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f2"),
                  templ2->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

TEST(FunctionNewHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Function with side-effect.
  Local<Function> func =
      Function::New(context.local(), EmptyHandler).ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("new f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<Function> func2 =
      Function::New(context.local(), EmptyHandler, Local<Value>(), 0,
                    v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f2"), func2).FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  v8::debug::EvaluateGlobal(
      isolate, v8_str("new f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

// These handlers instantiate a function the embedder considers safe in some
// cases (e.g. "building object wrappers"), but those functions themselves were
// not explicitly marked as side-effect-free.
static void DefaultConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  v8::MaybeLocal<v8::Object> instance = Function::New(context, EmptyHandler)
                                            .ToLocalChecked()
                                            ->NewInstance(context, 0, nullptr);
  USE(instance);
}

static void NoSideEffectConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  v8::MaybeLocal<v8::Object> instance =
      Function::New(context, EmptyHandler)
          .ToLocalChecked()
          ->NewInstanceWithSideEffectType(context, 0, nullptr,
                                          v8::SideEffectType::kHasNoSideEffect);
  USE(instance);
}

static void NoSideEffectAndSideEffectConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Context::Scope context_scope(context);
  // Constructs an instance in a side-effect-free way, followed by another with
  // side effects.
  v8::MaybeLocal<v8::Object> instance =
      Function::New(context, EmptyHandler)
          .ToLocalChecked()
          ->NewInstanceWithSideEffectType(context, 0, nullptr,
                                          v8::SideEffectType::kHasNoSideEffect);
  v8::MaybeLocal<v8::Object> instance2 = Function::New(context, EmptyHandler)
                                             .ToLocalChecked()
                                             ->NewInstance(context, 0, nullptr);
  USE(instance);
  USE(instance2);
}

TEST(FunctionNewInstanceHasNoSideEffect) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // An allowlisted function that creates a new object with both side-effect
  // free/full instantiations. Should throw.
  Local<Function> func0 =
      Function::New(context.local(), NoSideEffectAndSideEffectConstructHandler,
                    Local<Value>(), 0, v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func0).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // An allowlisted function that creates a new object. Should throw.
  Local<Function> func =
      Function::New(context.local(), DefaultConstructHandler, Local<Value>(), 0,
                    v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("f"), func).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // An allowlisted function that creates a new object with explicit intent to
  // have no side-effects (e.g. building an "object wrapper"). Should not throw.
  Local<Function> func2 =
      Function::New(context.local(), NoSideEffectConstructHandler,
                    Local<Value>(), 0, v8::ConstructorBehavior::kAllow,
                    v8::SideEffectType::kHasNoSideEffect)
          .ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f2"), func2).FromJust());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("f2()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();

  // Check that side effect skipping did not leak outside to future evaluations.
  Local<Function> func3 =
      Function::New(context.local(), EmptyHandler).ToLocalChecked();
  CHECK(
      context->Global()->Set(context.local(), v8_str("f3"), func3).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("f3()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Check that using side effect free NewInstance works in normal evaluation
  // (without throwOnSideEffect).
  v8::debug::EvaluateGlobal(isolate, v8_str("f2()"),
                            v8::debug::EvaluateGlobalMode::kDefault)
      .ToLocalChecked();
}

TEST(CallHandlerAsFunctionHasNoSideEffectNotSupported) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  // Object template with call as function handler.
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetCallAsFunctionHandler(EmptyHandler);
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version is not supported.
  i::Tagged<i::FunctionTemplateInfo> cons = i::Cast<i::FunctionTemplateInfo>(
      v8::Utils::OpenDirectHandle(*templ)->constructor());

  i::Tagged<i::FunctionTemplateInfo> handler =
      i::Cast<i::FunctionTemplateInfo>(cons->GetInstanceCallHandler());
  CHECK(handler->is_object_template_call_handler());
  CHECK(handler->has_side_effects());

  handler->set_has_side_effects(false);
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
}

static void IsConstructHandler(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(args.IsConstructCall());
}


THREADED_TEST(IsConstructCall) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(IsConstructHandler);

  LocalContext context;

  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());
  Local<Value> value = v8_compile("f()")->Run(context.local()).ToLocalChecked();
  CHECK(!value->BooleanValue(isolate));
  value = v8_compile("new f()")->Run(context.local()).ToLocalChecked();
  CHECK(value->BooleanValue(isolate));
}

static void NewTargetHandler(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(args.NewTarget());
}

THREADED_TEST(NewTargetHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Function template with call handler.
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetCallHandler(NewTargetHandler);

  LocalContext context;

  Local<Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"), function)
            .FromJust());
  Local<Value> value = CompileRun("f()");
  CHECK(value->IsUndefined());
  value = CompileRun("new f()");
  CHECK(value->IsFunction());
  CHECK(value == function);
  Local<Value> subclass = CompileRun("var g = class extends f { }; g");
  CHECK(subclass->IsFunction());
  value = CompileRun("new g()");
  CHECK(value->IsFunction());
  CHECK(value == subclass);
  value = CompileRun("Reflect.construct(f, [], Array)");
  CHECK(value->IsFunction());
  CHECK(value ==
        context->Global()
            ->Get(context.local(), v8_str("Array"))
            .ToLocalChecked());
}

THREADED_TEST(ObjectProtoToString) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("MyClass"));


  Local<String> customized_tostring = v8_str("customized toString");

  // Replace Object.prototype.toString
  CompileRun(R"(
      Object.prototype.toString = function() {
        return 'customized toString';
      })");

  // Normal ToString call should call replaced Object.prototype.toString
  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();
  Local<String> value = instance->ToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), customized_tostring).FromJust());

  // ObjectProtoToString should not call replace toString function. It should
  // not look at the class name either.
  value = instance->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());

  // Check global
  value =
      context->Global()->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());

  // Check ordinary object
  Local<Value> object = CompileRun("new Object()");
  value = object.As<v8::Object>()
              ->ObjectProtoToString(context.local())
              .ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object Object]")).FromJust());
}


TEST(ObjectProtoToStringES6) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Check that ES6 semantics using @@toStringTag work.
  Local<v8::Symbol> toStringTag = v8::Symbol::GetToStringTag(isolate);

  Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->SetClassName(v8_str("MyClass"));
  templ->PrototypeTemplate()->Set(
      toStringTag, v8_str("MyClassToStringTag"),
      static_cast<v8::PropertyAttribute>(v8::ReadOnly | v8::DontEnum));

  Local<String> customized_tostring = v8_str("customized toString");

  // Replace Object.prototype.toString
  CompileRun(R"(
      Object.prototype.toString = function() {
        return 'customized toString';
      })");

  // Normal ToString call should call replaced Object.prototype.toString
  Local<v8::Object> instance = templ->GetFunction(context.local())
                                   .ToLocalChecked()
                                   ->NewInstance(context.local())
                                   .ToLocalChecked();
  Local<String> value = instance->ToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), customized_tostring).FromJust());

  // ObjectProtoToString should not call replace toString function. Instead it
  // should look at the @@toStringTag property.
  value = instance->ObjectProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString() &&
        value->Equals(context.local(), v8_str("[object MyClassToStringTag]"))
            .FromJust());

  Local<Value> object;

#define TEST_TOSTRINGTAG(type, tag, expected)                              \
  do {                                                                     \
    object = CompileRun("new " #type "()");                                \
    CHECK(object.As<v8::Object>()                                          \
              ->Set(context.local(), toStringTag, v8_str(#tag))            \
              .FromJust());                                                \
    value = object.As<v8::Object>()                                        \
                ->ObjectProtoToString(context.local())                     \
                .ToLocalChecked();                                         \
    CHECK(value->IsString() &&                                             \
          value->Equals(context.local(), v8_str("[object " #expected "]")) \
              .FromJust());                                                \
  } while (false)

  TEST_TOSTRINGTAG(Array, Object, Object);
  TEST_TOSTRINGTAG(Object, Arguments, Arguments);
  TEST_TOSTRINGTAG(Object, Array, Array);
  TEST_TOSTRINGTAG(Object, Boolean, Boolean);
  TEST_TOSTRINGTAG(Object, Date, Date);
  TEST_TOSTRINGTAG(Object, Error, Error);
  TEST_TOSTRINGTAG(Object, Function, Function);
  TEST_TOSTRINGTAG(Object, Number, Number);
  TEST_TOSTRINGTAG(Object, RegExp, RegExp);
  TEST_TOSTRINGTAG(Object, String, String);
  TEST_TOSTRINGTAG(Object, Foo, Foo);

#undef TEST_TOSTRINGTAG

  Local<v8::RegExp> valueRegExp =
      v8::RegExp::New(context.local(), v8_str("^$"), v8::RegExp::kNone)
          .ToLocalChecked();
  Local<Value> valueNumber = v8_num(123);
  Local<v8::Symbol> valueSymbol = v8_symbol("TestSymbol");
  Local<v8::Function> valueFunction =
      CompileRun("(function fn() {})").As<v8::Function>();
  Local<v8::Object> valueObject = v8::Object::New(isolate);
  Local<v8::Primitive> valueNull = v8::Null(isolate);
  Local<v8::Primitive> valueUndef = v8::Undefined(isolate);

#define TEST_TOSTRINGTAG(type, tagValue, expected)                         \
  do {                                                                     \
    object = CompileRun("new " #type "()");                                \
    CHECK(object.As<v8::Object>()                                          \
              ->Set(context.local(), toStringTag, tagValue)                \
              .FromJust());                                                \
    value = object.As<v8::Object>()                                        \
                ->ObjectProtoToString(context.local())                     \
                .ToLocalChecked();                                         \
    CHECK(value->IsString() &&                                             \
          value->Equals(context.local(), v8_str("[object " #expected "]")) \
              .FromJust());                                                \
  } while (false)

#define TEST_TOSTRINGTAG_TYPES(tagValue)                    \
  TEST_TOSTRINGTAG(Array, tagValue, Array);                 \
  TEST_TOSTRINGTAG(Object, tagValue, Object);               \
  TEST_TOSTRINGTAG(Function, tagValue, Function);           \
  TEST_TOSTRINGTAG(Date, tagValue, Date);                   \
  TEST_TOSTRINGTAG(RegExp, tagValue, RegExp);               \
  TEST_TOSTRINGTAG(Error, tagValue, Error);                 \

  // Test non-String-valued @@toStringTag
  TEST_TOSTRINGTAG_TYPES(valueRegExp);
  TEST_TOSTRINGTAG_TYPES(valueNumber);
  TEST_TOSTRINGTAG_TYPES(valueSymbol);
  TEST_TOSTRINGTAG_TYPES(valueFunction);
  TEST_TOSTRINGTAG_TYPES(valueObject);
  TEST_TOSTRINGTAG_TYPES(valueNull);
  TEST_TOSTRINGTAG_TYPES(valueUndef);

#undef TEST_TOSTRINGTAG
#undef TEST_TOSTRINGTAG_TYPES

  // @@toStringTag getter throws
  Local<Value> obj = v8::Object::New(isolate);
  obj.As<v8::Object>()
      ->SetNativeDataProperty(context.local(), toStringTag,
                              ThrowingSymbolAccessorGetter)
      .FromJust();
  {
    TryCatch try_catch(isolate);
    CHECK(obj.As<v8::Object>()->ObjectProtoToString(context.local()).IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  // @@toStringTag getter does not throw
  obj = v8::Object::New(isolate);
  obj.As<v8::Object>()
      ->SetNativeDataProperty(context.local(), toStringTag,
                              SymbolAccessorGetterReturnsDefault, nullptr,
                              v8_str("Test"))
      .FromJust();
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  // JS @@toStringTag value
  obj = CompileRun("obj = {}; obj[Symbol.toStringTag] = 'Test'; obj");
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  // JS @@toStringTag getter throws
  obj = CompileRun(
      "obj = {}; Object.defineProperty(obj, Symbol.toStringTag, {"
      "  get: function() { throw 'Test'; }"
      "}); obj");
  {
    TryCatch try_catch(isolate);
    CHECK(obj.As<v8::Object>()->ObjectProtoToString(context.local()).IsEmpty());
    CHECK(try_catch.HasCaught());
  }

  // JS @@toStringTag getter does not throw
  obj = CompileRun(
      "obj = {}; Object.defineProperty(obj, Symbol.toStringTag, {"
      "  get: function() { return 'Test'; }"
      "}); obj");
  {
    TryCatch try_catch(isolate);
    value = obj.As<v8::Object>()
                ->ObjectProtoToString(context.local())
                .ToLocalChecked();
    CHECK(value->IsString() &&
          value->Equals(context.local(), v8_str("[object Test]")).FromJust());
    CHECK(!try_catch.HasCaught());
  }
}

namespace {

void CheckGetConstructorNameOfVar(LocalContext& context, const char* var_name,
                                  const char* constructor_name) {
  Local<v8::Value> var = context->Global()
                             ->Get(context.local(), v8_str(var_name))
                             .ToLocalChecked();
  CHECK(var->IsObject() &&
        var->ToObject(context.local())
            .ToLocalChecked()
            ->GetConstructorName()
            ->Equals(context.local(), v8_str(constructor_name))
            .FromJust());
}

}  // namespace

THREADED_TEST(ObjectGetConstructorName) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext context;
  v8::HandleScope scope(isolate);
  v8_compile(
      "function Parent() {};"
      "function Child() {};"
      "Child.prototype = new Parent();"
      "Child.prototype.constructor = Child;"
      "var outer = { inner: (0, function() { }) };"
      "var p = new Parent();"
      "var c = new Child();"
      "var x = new outer.inner();"
      "var proto = Child.prototype;")
      ->Run(context.local())
      .ToLocalChecked();

  CheckGetConstructorNameOfVar(context, "p", "Parent");
  CheckGetConstructorNameOfVar(context, "c", "Child");
  CheckGetConstructorNameOfVar(context, "x", "outer.inner");
  CheckGetConstructorNameOfVar(context, "proto", "Parent");
}


THREADED_TEST(SubclassGetConstructorName) {
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext context;
  v8::HandleScope scope(isolate);
  v8_compile(
      "\"use strict\";"
      "class Parent {}"
      "class Child extends Parent {}"
      "var p = new Parent();"
      "var c = new Child();")
      ->Run(context.local())
      .ToLocalChecked();

  CheckGetConstructorNameOfVar(context, "p", "Parent");
  CheckGetConstructorNameOfVar(context, "c", "Child");
}

UNINITIALIZED_TEST(SharedObjectGetConstructorName) {
  if (!V8_CAN_CREATE_SHARED_HEAP_BOOL) return;
  // In multi-cage mode we create one cage per isolate
  // and we don't share objects between cages.
  if (COMPRESS_POINTERS_IN_MULTIPLE_CAGES_BOOL) return;

  i::v8_flags.shared_string_table = true;
  i::v8_flags.harmony_struct = true;
  i::FlagList::EnforceFlagImplications();

  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope scope(isolate);
    LocalContext context(isolate);

    v8_compile(
        "var s = new (new SharedStructType(['foo']));"
        "var a = new SharedArray(1);"
        "var m = new Atomics.Mutex;"
        "var c = new Atomics.Condition;")
        ->Run(context.local())
        .ToLocalChecked();

    CheckGetConstructorNameOfVar(context, "s", "SharedStruct");
    CheckGetConstructorNameOfVar(context, "a", "SharedArray");
    CheckGetConstructorNameOfVar(context, "m", "Atomics.Mutex");
    CheckGetConstructorNameOfVar(context, "c", "Atomics.Condition");
  }
  isolate->Dispose();
}

unsigned ApiTestFuzzer::linear_congruential_generator;
std::vector<std::unique_ptr<ApiTestFuzzer>> ApiTestFuzzer::fuzzers_;
bool ApiTestFuzzer::fuzzing_ = false;
v8::base::Semaphore ApiTestFuzzer::all_tests_done_(0);
int ApiTestFuzzer::tests_being_run_;
int ApiTestFuzzer::active_tests_;
int ApiTestFuzzer::current_fuzzer_;

// We are in a callback and want to switch to another thread (if we
// are currently running the thread fuzzing test).
void ApiTestFuzzer::Fuzz() {
  // Emulate context switch which might cause side effects as well.
  // This is mostly to ensure that the callbacks in the tests do not cause
  // side effects when they don't intercept the operation.
  CcTest::i_isolate()->IncrementJavascriptExecutionCounter();

  if (!fuzzing_) return;
  fuzzers_[current_fuzzer_]->ContextSwitch();
}


// Let the next thread go.  Since it is also waiting on the V8 lock it may
// not start immediately.
bool ApiTestFuzzer::NextThread() {
  int next_fuzzer = GetNextFuzzer();
  if (next_fuzzer == current_fuzzer_) {
    if (kLogThreading) {
      int current_number = fuzzers_[current_fuzzer_]->test_number_;
      printf("Stay with %s #%d\n",
             RegisterThreadedTest::nth(current_number)->name(), current_number);
    }
    return false;
  }
  if (kLogThreading) {
    int current_number =
        current_fuzzer_ >= 0 ? fuzzers_[current_fuzzer_]->test_number_ : -1;
    int next_number = fuzzers_[next_fuzzer]->test_number_;
    printf("Switch from %s #%d to %s #%d\n",
           current_number >= 0
               ? RegisterThreadedTest::nth(current_number)->name()
               : "<none>",
           current_number, RegisterThreadedTest::nth(next_number)->name(),
           next_number);
  }
  current_fuzzer_ = next_fuzzer;
  fuzzers_[current_fuzzer_]->gate_.Signal();
  return true;
}

void ApiTestFuzzer::Run() {
  // Wait until it is our turn.
  gate_.Wait();
  {
    // Get the V8 lock.
    v8::Locker locker(CcTest::isolate());
    // Start running the test, which will enter the isolate and exit it when it
    // finishes.
    CallTest();
  }
  // This test finished.
  active_ = false;
  active_tests_--;
  // If it was the last then signal that fact.
  if (active_tests_ == 0) {
    all_tests_done_.Signal();
  } else {
    // Otherwise select a new test and start that.
    NextThread();
  }
}

void ApiTestFuzzer::SetUp(PartOfTest part) {
  linear_congruential_generator = i::v8_flags.testing_prng_seed;
  fuzzing_ = true;
  int count = RegisterThreadedTest::count();
  int start =  count * part / (LAST_PART + 1);
  int end = (count * (part + 1) / (LAST_PART + 1)) - 1;
  active_tests_ = tests_being_run_ = end - start + 1;
  fuzzers_.clear();
  for (int i = 0; i < tests_being_run_; i++) {
    fuzzers_.push_back(
        std::unique_ptr<ApiTestFuzzer>(new ApiTestFuzzer(i + start)));
  }
  for (const auto& fuzzer : fuzzers_) {
    CHECK(fuzzer->Start());
  }
}

void ApiTestFuzzer::RunAllTests() {
  // This method is called when running each THREADING
```