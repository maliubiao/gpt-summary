Response:
Let's break down the thought process for analyzing this V8 test file.

**1. Initial Scan and Keywords:**

First, I quickly scanned the code for obvious patterns and keywords. Things that jumped out:

* `TEST(...)`:  This immediately signals that it's a testing file.
* `RequestInterruptTest...`:  A recurring theme, suggesting the core functionality being tested is related to interrupting JavaScript execution.
* `ShouldContinueCallback`:  Appears frequently, likely a mechanism to control the continuation of a loop or operation.
* `CompileRun(...)`:  Indicates execution of JavaScript code within the test.
* `Function::New`, `FunctionTemplate::New`, `Object::New`:  API calls for creating JavaScript objects and functions from C++.
* `SetAccessorProperty`, `SetNativeDataProperty`:  Ways to define properties on JavaScript objects.
* `while (...)`:  Loops are being used in the JavaScript code under test.
* `i::v8_flags.allow_natives_syntax = true/false`:  Indicates the use of V8-specific syntax for optimization hints.
* `v8::Isolate::RequestInterrupt`:  The key API call for triggering interrupts.
* `LocalContext`, `HandleScope`: Standard V8 API for managing the JavaScript environment.
* `TryCatch`: Used for handling exceptions during JavaScript execution.
* `Signature`:  Related to function call validation based on object types.
* `EventLogger`:  Suggests testing of event logging mechanisms.

**2. Identifying Core Functionality (The "Interrupt" Theme):**

The prevalence of "RequestInterruptTest" clearly points to the central theme. The tests appear to be validating how V8 handles interrupts requested from the embedder (the C++ code). The different variations of "RequestInterruptTest" (with function call, method call, accessor, native accessor, etc.) suggest testing different scenarios where an interrupt might occur during JavaScript execution.

**3. Understanding the Interrupt Mechanism:**

The `RequestInterruptTestBase` and its nested `InterruptThread` provide crucial clues. The thread seems to be responsible for requesting the interrupt. The `ShouldContinue()` method and its associated callbacks appear to be the mechanism by which the JavaScript code checks if it should continue executing after a potential interrupt. The `sem_.Wait()` suggests synchronization to ensure the interrupt is requested at the right time.

**4. Deconstructing Individual Test Cases:**

I then started looking at individual `TEST(...)` blocks to understand the specific scenarios being tested:

* **`RequestInterruptTestWith...` variations:** These test interrupts occurring during different kinds of JavaScript operations (function calls, method calls, property access).
* **`RequestInterruptTestWithMathAbs`:**  This one is interesting because it involves a built-in function (`Math.abs`) and optimization. It seems to be checking if interrupts can occur reliably even during optimized code execution.
* **`RequestMultipleInterrupts`:** This explicitly tests handling multiple interrupt requests.
* **`RequestInterruptSmallScripts`:** Checks if interrupts work correctly even for very short JavaScript snippets.
* **`FunctionNew`:** Focuses on the behavior of `Function::New` and its interaction with data and caching.
* **`ObjectNew`:** Tests various ways to create JavaScript objects with different prototypes and properties.
* **`EscapableHandleScope`:** Tests the behavior of a specific V8 API for managing object lifetimes.
* **`Regress239669`:**  Indicates a regression test, likely for a specific bug fix related to setters and `this`/`Holder`.
* **`FunctionCallOptimization` and `FunctionCallOptimizationMultipleArgs`:**  Tests if function call optimization works correctly in the presence of API callbacks.
* **`ApiCallbackCanReturnSymbols`:** Verifies that API callbacks can return Symbol values.
* **`EmptyApiCallback`:** Tests the behavior of API callbacks that don't explicitly return a value.
* **`SimpleSignatureCheck` and `ChainSignatureCheck`:** Tests the mechanism of function signatures for validating the type of the receiver object.
* **`EventLogging`:**  Tests the V8's event logging functionality.

**5. Identifying JavaScript Relevance and Examples:**

For each test case, I asked myself: "What JavaScript feature is being exercised here?" This led to the JavaScript examples. For instance, the `RequestInterruptTestWithFunctionCall` clearly relates to calling JavaScript functions, so a simple `while` loop calling a defined function was a relevant example.

**6. Code Logic Inference and Input/Output:**

For the interrupt tests, the logic is fairly straightforward: set a flag that the JavaScript code checks, and have the interrupt mechanism flip that flag. The input is implicitly the state of the `should_continue_` variable when the interrupt is requested. The output is whether the JavaScript loop terminates as expected.

**7. Common Programming Errors:**

The `Regress239669` test directly points to a potential confusion between `this` and `Holder` in API callbacks. I generalized this to the broader category of "misunderstanding `this` in JavaScript callbacks."

**8. Constraint: .tq Files:**

I checked the file extension (".cc") and noted that it's not a Torque file.

**9. Constraint: Part 25 of 36:**

This emphasizes the importance of summarizing the *overall* functionality of this specific part, while keeping in mind that it's part of a larger test suite.

**10. Structuring the Output:**

Finally, I organized the information into logical sections as requested by the prompt: Functionality, Torque, JavaScript Examples, Logic Inference, Common Errors, and Summary. I tried to be concise yet informative.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the details of each individual test. I realized I needed to step back and identify the overarching purpose: testing the interrupt mechanism and related API features.
* I made sure to connect the C++ test code with the equivalent JavaScript concepts and potential pitfalls.
* I double-checked the prompt to ensure I addressed all the specific requirements (Torque files, JavaScript examples, etc.).
好的，让我们来分析一下这段 V8 源代码 `v8/test/cctest/test-api.cc` 的第 25 部分。

**功能列举:**

这段代码主要测试 V8 的 C++ API 的以下功能，尤其关注在 JavaScript 执行过程中请求中断的能力：

1. **请求中断 (Request Interrupt):**  核心功能是测试 `v8::Isolate::RequestInterrupt` API，允许从 V8 引擎外部（通常是另一个线程）请求中断 JavaScript 的执行。

2. **中断回调 (Interrupt Callback):** 测试在收到中断请求后执行的回调函数 (`SmallScriptsInterruptCallback`, `OnInterrupt`)。

3. **在不同 JavaScript 上下文中的中断:**  测试在不同的 JavaScript 代码结构中请求中断的效果，包括：
    * **函数调用 (`RequestInterruptTestWithFunctionCall`)**
    * **方法调用 (`RequestInterruptTestWithMethodCall`)**
    * **属性访问器 (`RequestInterruptTestWithAccessor`, `RequestInterruptTestWithNativeAccessor`)**
    * **带有拦截器的属性访问 (`RequestInterruptTestWithMethodCallAndInterceptor`)**
    * **在内置函数调用中 (`RequestInterruptTestWithMathAbs`)**

4. **多次中断请求 (`RequestMultipleInterrupts`):** 测试 V8 引擎处理多个并发中断请求的能力。

5. **`Function::New` API:** 测试使用 `Function::New` 创建 JavaScript 函数，并验证其数据关联和缓存行为。

6. **`Object::New` API:** 测试使用 `Object::New` 创建 JavaScript 对象，包括设置原型和属性，以及处理重复属性名和数组索引的情况。

7. **`EscapableHandleScope`:** 测试 `EscapableHandleScope` 的使用，允许将局部句柄提升到外部作用域。

8. **原生数据属性的 Setter 和 `this`/`Holder` (`Regress239669`):** 测试原生数据属性的 setter 回调中 `this` 和 `Holder` 的区别，以及确保在特定场景下它们不相等。

9. **函数调用优化和 API 回调 (`ApiCallOptimizationChecker`, `FunctionCallOptimization`, `FunctionCallOptimizationMultipleArgs`):** 测试 V8 的函数调用优化机制在涉及 API 回调时的行为，包括签名检查。

10. **API 回调返回 Symbol 类型 (`ApiCallbackCanReturnSymbols`):** 测试 API 回调函数是否可以返回 JavaScript 的 Symbol 类型。

11. **空的 API 回调 (`EmptyApiCallback`):** 测试当 API 回调函数没有显式返回值时 V8 的处理方式。

12. **函数签名检查 (`SimpleSignatureCheck`, `ChainSignatureCheck`):** 测试使用 `v8::Signature` 对函数调用进行类型检查的功能。

13. **事件日志记录 (`EventLogging`):** 测试 V8 的事件日志记录功能，包括设置事件记录器回调。

**Torque 源代码判断:**

`v8/test/cctest/test-api.cc` 的文件扩展名是 `.cc`，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 功能的关系和示例:**

这段 C++ 代码测试了许多与 JavaScript 密切相关的功能。以下是一些与 JavaScript 功能对应的示例：

* **请求中断:**  想象一个长时间运行的 JavaScript 循环，你希望用户能够点击一个 "停止" 按钮来中断它。V8 的 `RequestInterrupt` API 允许你的 C++ 应用在用户点击按钮时通知 V8 引擎，从而中断循环的执行。

   ```javascript
   // JavaScript 代码 (可能导致长时间运行)
   let i = 0;
   while (true) {
     console.log(i++);
     // ... 执行一些耗时操作 ...
   }
   ```

   C++ 代码可以在另一个线程中调用 `isolate->RequestInterrupt(...)` 来尝试中断这个循环。

* **函数调用、方法调用、属性访问器:** 这些测试确保在 JavaScript 执行这些基本操作时，中断机制仍然有效。

   ```javascript
   // 函数调用
   function myFunction() { /* ... */ }
   while (true) { myFunction(); }

   // 方法调用
   const obj = { myMethod() { /* ... */ } };
   while (true) { obj.myMethod(); }

   // 属性访问器
   const obj2 = { get myProperty() { /* ... */ } };
   while (true) { obj2.myProperty; }
   ```

* **`Function::New`:**  当你需要在 C++ 中创建可以从 JavaScript 调用的函数时，你会使用 `Function::New`。

   ```javascript
   // JavaScript 可以调用在 C++ 中创建的 'myNativeFunction'
   myNativeFunction();
   ```

* **`Object::New`:**  类似地，你可以在 C++ 中创建 JavaScript 对象。

   ```javascript
   // JavaScript 可以使用在 C++ 中创建的 'myNativeObject'
   console.log(myNativeObject.someProperty);
   ```

* **函数签名检查:**  用于限制 API 函数的调用方式，例如只能在特定类型的对象上调用。

   ```javascript
   function MyObject() {}
   MyObject.prototype.myMethod = function() {};

   function apiFunction(arg) { /* ... */ }

   // 如果 apiFunction 有签名检查，可能只允许在 MyObject 的实例上调用
   const obj = new MyObject();
   apiFunction.call(obj); // 允许
   apiFunction.call({});    // 不允许 (可能抛出异常)
   ```

**代码逻辑推理和假设输入/输出:**

大多数测试都遵循以下模式：

1. **设置环境:** 创建一个 V8 Isolate 和 Context。
2. **定义中断条件:** 使用 `should_continue_` 标志或回调函数来控制 JavaScript 代码的执行。
3. **启动 JavaScript 代码:** 运行一个 `while` 循环或其他长时间运行的代码片段。
4. **在另一个线程中请求中断:**  `InterruptThread` 负责在适当的时机调用 `isolate->RequestInterrupt(...)`。
5. **验证中断效果:** 检查 JavaScript 代码是否在预期的时间点停止执行，或者中断回调是否被正确调用。

**假设输入/输出 (以 `RequestInterruptTestWithFunctionCall` 为例):**

* **假设输入:**
    * JavaScript 代码进入 `while (ShouldContinue()) { }` 循环。
    * `ShouldContinue()` 函数最初返回 `true`。
    * `InterruptThread` 在某个时刻调用 `isolate->RequestInterrupt(...)`。
    * 中断回调函数 `ShouldContinueCallback` 被执行，并且它会设置 `should_continue_` 为 `false`。

* **预期输出:**
    * JavaScript 循环最终会因为 `ShouldContinue()` 返回 `false` 而终止。
    * 测试通过，因为中断机制成功地影响了 JavaScript 代码的执行。

**用户常见的编程错误:**

* **在 API 回调中混淆 `this` 和 `Holder`:**  用户可能错误地认为 `this` 总是指向持有属性的对象。但对于原生属性访问器，`Holder` 指向定义属性的对象，而 `this` 指向接收属性访问的对象，它们可能不同。`Regress239669` 就是测试这种情况。

   ```javascript
   // C++ 代码定义了一个带有 setter 的对象模板
   templ->SetNativeDataProperty(v8_str("x"), nullptr, SetterCallback);

   // JavaScript 代码
   function C1() { this.x = 23; }
   C1.prototype = P; // P 是用上面的模板创建的实例

   const obj = new C1(); // 在 SetterCallback 中，'this' 指向 obj，'Holder' 指向 P
   ```

* **不正确地管理 V8 的句柄:**  忘记使用 `HandleScope` 或 `EscapableHandleScope` 可能导致内存泄漏或野指针。

* **在 API 回调中执行耗时操作:**  API 回调应该快速执行，避免阻塞 V8 引擎的主线程。

* **不理解函数签名的作用:**  尝试在不符合签名的对象上调用 API 函数会导致错误。

**功能归纳 (针对第 25 部分):**

这段代码的核心功能是 **全面测试 V8 的中断机制和相关的 C++ API 功能**。它涵盖了在各种 JavaScript 代码结构中请求中断的能力，以及对 `Function::New`、`Object::New`、句柄作用域、函数签名检查和事件日志记录等关键 API 的测试。  第 25 部分特别关注了中断在不同 JavaScript 上下文中的表现以及与函数调用优化的交互。通过这些测试，V8 开发者可以确保引擎的稳定性和可靠性，尤其是在需要外部控制 JavaScript 执行的情况下。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第25部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
tinue_ = false;
    }

   private:
     RequestInterruptTestBase* test_;
  };

  InterruptThread i_thread;
};


class RequestInterruptTestWithFunctionCall
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    Local<Function> func = Function::New(env_.local(), ShouldContinueCallback,
                                         v8::External::New(isolate_, this))
                               .ToLocalChecked();
    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("ShouldContinue"), func)
              .FromJust());

    CompileRun("while (ShouldContinue()) { }");
  }
};


class RequestInterruptTestWithMethodCall
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate_);
    v8::Local<v8::Template> proto = t->PrototypeTemplate();
    proto->Set(isolate_, "shouldContinue",
               FunctionTemplate::New(isolate_, ShouldContinueCallback,
                                     v8::External::New(isolate_, this)));
    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("Klass"),
                    t->GetFunction(env_.local()).ToLocalChecked())
              .FromJust());

    CompileRun("var obj = new Klass; while (obj.shouldContinue()) { }");
  }
};


class RequestInterruptTestWithAccessor
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate_);
    v8::Local<v8::Template> proto = t->PrototypeTemplate();
    proto->SetAccessorProperty(v8_str("shouldContinue"), FunctionTemplate::New(
        isolate_, ShouldContinueCallback, v8::External::New(isolate_, this)));
    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("Klass"),
                    t->GetFunction(env_.local()).ToLocalChecked())
              .FromJust());

    CompileRun("var obj = new Klass; while (obj.shouldContinue) { }");
  }
};


class RequestInterruptTestWithNativeAccessor
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate_);
    t->InstanceTemplate()->SetNativeDataProperty(
        v8_str("shouldContinue"), &ShouldContinueNativeGetter, nullptr,
        v8::External::New(isolate_, this));
    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("Klass"),
                    t->GetFunction(env_.local()).ToLocalChecked())
              .FromJust());

    CompileRun("var obj = new Klass; while (obj.shouldContinue) { }");
  }

 private:
  static void ShouldContinueNativeGetter(
      Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    RequestInterruptTestBase* test =
        reinterpret_cast<RequestInterruptTestBase*>(
            info.Data().As<v8::External>()->Value());
    info.GetReturnValue().Set(test->ShouldContinue());
  }
};


class RequestInterruptTestWithMethodCallAndInterceptor
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate_);
    v8::Local<v8::Template> proto = t->PrototypeTemplate();
    proto->Set(isolate_, "shouldContinue",
               FunctionTemplate::New(isolate_, ShouldContinueCallback,
                                     v8::External::New(isolate_, this)));
    v8::Local<v8::ObjectTemplate> instance_template = t->InstanceTemplate();
    instance_template->SetHandler(
        v8::NamedPropertyHandlerConfiguration(EmptyInterceptor));

    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("Klass"),
                    t->GetFunction(env_.local()).ToLocalChecked())
              .FromJust());

    CompileRun("var obj = new Klass; while (obj.shouldContinue()) { }");
  }

 private:
  static v8::Intercepted EmptyInterceptor(
      Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    return v8::Intercepted::kNo;
  }
};


class RequestInterruptTestWithMathAbs
    : public RequestInterruptTestBaseWithSimpleInterrupt {
 public:
  void TestBody() override {
    env_->Global()
        ->Set(env_.local(), v8_str("WakeUpInterruptor"),
              Function::New(env_.local(), WakeUpInterruptorCallback,
                            v8::External::New(isolate_, this))
                  .ToLocalChecked())
        .FromJust();

    env_->Global()
        ->Set(env_.local(), v8_str("ShouldContinue"),
              Function::New(env_.local(), ShouldContinueCallback,
                            v8::External::New(isolate_, this))
                  .ToLocalChecked())
        .FromJust();

    i::v8_flags.allow_natives_syntax = true;
    CompileRun(
        "function loopish(o) {"
        "  var pre = 10;"
        "  while (o.abs(1) > 0) {"
        "    if (o.abs(1) >= 0 && !ShouldContinue()) break;"
        "    if (pre > 0) {"
        "      if (--pre === 0) WakeUpInterruptor(o === Math);"
        "    }"
        "  }"
        "};"
        "%PrepareFunctionForOptimization(loopish);"
        "var i = 50;"
        "var obj = {abs: function () { return i-- }, x: null};"
        "delete obj.x;"
        "loopish(obj);"
        "%OptimizeFunctionOnNextCall(loopish);"
        "loopish(Math);");

    i::v8_flags.allow_natives_syntax = false;
  }

 private:
  static void WakeUpInterruptorCallback(
      const v8::FunctionCallbackInfo<Value>& info) {
    if (!info[0]->BooleanValue(info.GetIsolate())) {
      return;
    }

    RequestInterruptTestBase* test =
        reinterpret_cast<RequestInterruptTestBase*>(
            info.Data().As<v8::External>()->Value());
    test->WakeUpInterruptor();
  }

  static void ShouldContinueCallback(
      const v8::FunctionCallbackInfo<Value>& info) {
    RequestInterruptTestBase* test =
        reinterpret_cast<RequestInterruptTestBase*>(
            info.Data().As<v8::External>()->Value());
    info.GetReturnValue().Set(test->should_continue());
  }
};

TEST(RequestInterruptTestWithFunctionCall) {
  RequestInterruptTestWithFunctionCall().RunTest();
}


TEST(RequestInterruptTestWithMethodCall) {
  RequestInterruptTestWithMethodCall().RunTest();
}


TEST(RequestInterruptTestWithAccessor) {
  RequestInterruptTestWithAccessor().RunTest();
}


TEST(RequestInterruptTestWithNativeAccessor) {
  RequestInterruptTestWithNativeAccessor().RunTest();
}


TEST(RequestInterruptTestWithMethodCallAndInterceptor) {
  RequestInterruptTestWithMethodCallAndInterceptor().RunTest();
}


TEST(RequestInterruptTestWithMathAbs) {
  RequestInterruptTestWithMathAbs().RunTest();
}

class RequestMultipleInterrupts : public RequestInterruptTestBase {
 public:
  RequestMultipleInterrupts() : i_thread(this), counter_(0) {}

  void StartInterruptThread() override { CHECK(i_thread.Start()); }

  void TestBody() override {
    Local<Function> func = Function::New(env_.local(), ShouldContinueCallback,
                                         v8::External::New(isolate_, this))
                               .ToLocalChecked();
    CHECK(env_->Global()
              ->Set(env_.local(), v8_str("ShouldContinue"), func)
              .FromJust());

    CompileRun("while (ShouldContinue()) { }");
  }

 private:
  class InterruptThread : public v8::base::Thread {
   public:
    enum { NUM_INTERRUPTS = 10 };
    explicit InterruptThread(RequestMultipleInterrupts* test)
        : Thread(Options("RequestInterruptTest")), test_(test) {}

    void Run() override {
      test_->sem_.Wait();
      for (int i = 0; i < NUM_INTERRUPTS; i++) {
        test_->isolate_->RequestInterrupt(&OnInterrupt, test_);
      }
    }

    static void OnInterrupt(v8::Isolate* isolate, void* data) {
      RequestMultipleInterrupts* test =
          reinterpret_cast<RequestMultipleInterrupts*>(data);
      test->should_continue_ = ++test->counter_ < NUM_INTERRUPTS;
    }

   private:
    RequestMultipleInterrupts* test_;
  };

  InterruptThread i_thread;
  int counter_;
};


TEST(RequestMultipleInterrupts) { RequestMultipleInterrupts().RunTest(); }


static bool interrupt_was_called = false;


void SmallScriptsInterruptCallback(v8::Isolate* isolate, void* data) {
  interrupt_was_called = true;
}


TEST(RequestInterruptSmallScripts) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  interrupt_was_called = false;
  isolate->RequestInterrupt(&SmallScriptsInterruptCallback, nullptr);
  CompileRun("(function(x){return x;})(1);");
  CHECK(interrupt_was_called);
}

static v8::Global<Value> function_new_expected_env_global;
static void FunctionNewCallback(const v8::FunctionCallbackInfo<Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  CHECK(function_new_expected_env_global.Get(isolate)
            ->Equals(isolate->GetCurrentContext(), info.Data())
            .FromJust());
  info.GetReturnValue().Set(17);
}


THREADED_TEST(FunctionNew) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> data = v8::Object::New(isolate);
  function_new_expected_env_global.Reset(isolate, data);
  Local<Function> func =
      Function::New(env.local(), FunctionNewCallback, data).ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("func"), func).FromJust());
  Local<Value> result = CompileRun("func();");
  CHECK(v8::Integer::New(isolate, 17)->Equals(env.local(), result).FromJust());
  // Serial number should be invalid => should not be cached.
  auto serial_number = i::Cast<i::JSFunction>(v8::Utils::OpenHandle(*func))
                           ->shared()
                           ->api_func_data()
                           ->serial_number();
  CHECK_EQ(i::TemplateInfo::kDoNotCache, serial_number);

  // Verify that each Function::New creates a new function instance
  Local<Object> data2 = v8::Object::New(isolate);
  function_new_expected_env_global.Reset(isolate, data2);
  Local<Function> func2 =
      Function::New(env.local(), FunctionNewCallback, data2).ToLocalChecked();
  CHECK(!func2->IsNull());
  CHECK(!func->Equals(env.local(), func2).FromJust());
  CHECK(env->Global()->Set(env.local(), v8_str("func2"), func2).FromJust());
  Local<Value> result2 = CompileRun("func2();");
  CHECK(v8::Integer::New(isolate, 17)->Equals(env.local(), result2).FromJust());

  function_new_expected_env_global.Reset();
}

namespace {

void Verify(v8::Isolate* isolate, Local<v8::Object> obj) {
#if VERIFY_HEAP
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  i::DirectHandle<i::JSReceiver> i_obj = v8::Utils::OpenDirectHandle(*obj);
  i::Object::ObjectVerify(*i_obj, i_isolate);
#endif
}

}  // namespace

THREADED_TEST(ObjectNew) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  {
    // Verify that Object::New(null) produces an object with a null
    // [[Prototype]].
    Local<v8::Object> obj =
        v8::Object::New(isolate, v8::Null(isolate), nullptr, nullptr, 0);
    CHECK(obj->GetPrototypeV2()->IsNull());
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(0, keys->Length());
  }
  {
    // Verify that Object::New(proto) produces an object with
    // proto as it's [[Prototype]].
    Local<v8::Object> proto = v8::Object::New(isolate);
    Local<v8::Object> obj =
        v8::Object::New(isolate, proto, nullptr, nullptr, 0);
    Verify(isolate, obj);
    CHECK(obj->GetPrototypeV2()->SameValue(proto));
  }
  {
    // Verify that the properties are installed correctly.
    Local<v8::Name> names[3] = {v8_str("a"), v8_str("b"), v8_str("c")};
    Local<v8::Value> values[3] = {v8_num(1), v8_num(2), v8_num(3)};
    Local<v8::Object> obj = v8::Object::New(isolate, v8::Null(isolate), names,
                                            values, arraysize(values));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(arraysize(names), keys->Length());
    for (uint32_t i = 0; i < arraysize(names); ++i) {
      CHECK(names[i]->SameValue(keys->Get(env.local(), i).ToLocalChecked()));
      CHECK(values[i]->SameValue(
          obj->Get(env.local(), names[i]).ToLocalChecked()));
    }
  }
  {
    // Same as above, but with non-null prototype.
    Local<v8::Object> proto = v8::Object::New(isolate);
    Local<v8::Name> names[3] = {v8_str("x"), v8_str("y"), v8_str("z")};
    Local<v8::Value> values[3] = {v8_num(1), v8_num(2), v8_num(3)};
    Local<v8::Object> obj =
        v8::Object::New(isolate, proto, names, values, arraysize(values));
    CHECK(obj->GetPrototypeV2()->SameValue(proto));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(arraysize(names), keys->Length());
    for (uint32_t i = 0; i < arraysize(names); ++i) {
      CHECK(names[i]->SameValue(keys->Get(env.local(), i).ToLocalChecked()));
      CHECK(values[i]->SameValue(
          obj->Get(env.local(), names[i]).ToLocalChecked()));
    }
  }
  {
    // This has to work with duplicate names too.
    Local<v8::Name> names[3] = {v8_str("a"), v8_str("a"), v8_str("a")};
    Local<v8::Value> values[3] = {v8_num(1), v8_num(2), v8_num(3)};
    Local<v8::Object> obj = v8::Object::New(isolate, v8::Null(isolate), names,
                                            values, arraysize(values));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(1, keys->Length());
    CHECK(v8_str("a")->SameValue(keys->Get(env.local(), 0).ToLocalChecked()));
    CHECK(v8_num(3)->SameValue(
        obj->Get(env.local(), v8_str("a")).ToLocalChecked()));
  }
  {
    // This has to work with array indices too.
    Local<v8::Name> names[2] = {v8_str("0"), v8_str("1")};
    Local<v8::Value> values[2] = {v8_num(0), v8_num(1)};
    Local<v8::Object> obj = v8::Object::New(isolate, v8::Null(isolate), names,
                                            values, arraysize(values));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(arraysize(names), keys->Length());
    for (uint32_t i = 0; i < arraysize(names); ++i) {
      CHECK(v8::Number::New(isolate, i)
                ->SameValue(keys->Get(env.local(), i).ToLocalChecked()));
      CHECK(values[i]->SameValue(obj->Get(env.local(), i).ToLocalChecked()));
    }
  }
  {
    // This has to work with mixed array indices / property names too.
    Local<v8::Name> names[2] = {v8_str("0"), v8_str("x")};
    Local<v8::Value> values[2] = {v8_num(42), v8_num(24)};
    Local<v8::Object> obj = v8::Object::New(isolate, v8::Null(isolate), names,
                                            values, arraysize(values));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(arraysize(names), keys->Length());
    // 0 -> 42
    CHECK(v8_num(0)->SameValue(keys->Get(env.local(), 0).ToLocalChecked()));
    CHECK(
        values[0]->SameValue(obj->Get(env.local(), names[0]).ToLocalChecked()));
    // "x" -> 24
    CHECK(v8_str("x")->SameValue(keys->Get(env.local(), 1).ToLocalChecked()));
    CHECK(
        values[1]->SameValue(obj->Get(env.local(), names[1]).ToLocalChecked()));
  }
  {
    // Verify that this also works for a couple thousand properties.
    size_t const kLength = 10 * 1024;
    Local<v8::Name> names[kLength];
    Local<v8::Value> values[kLength];
    for (size_t i = 0; i < arraysize(names); ++i) {
      std::ostringstream ost;
      ost << "a" << i;
      names[i] = v8_str(ost.str().c_str());
      values[i] = v8_num(static_cast<double>(i));
    }
    Local<v8::Object> obj = v8::Object::New(isolate, v8::Null(isolate), names,
                                            values, arraysize(names));
    Verify(isolate, obj);
    Local<Array> keys = obj->GetOwnPropertyNames(env.local()).ToLocalChecked();
    CHECK_EQ(arraysize(names), keys->Length());
    for (uint32_t i = 0; i < arraysize(names); ++i) {
      CHECK(names[i]->SameValue(keys->Get(env.local(), i).ToLocalChecked()));
      CHECK(values[i]->SameValue(
          obj->Get(env.local(), names[i]).ToLocalChecked()));
    }
  }
}

TEST(EscapableHandleScope) {
  HandleScope outer_scope(CcTest::isolate());
  LocalContext context;
  const int runs = 10;
  Local<String> values[runs];
  for (int i = 0; i < runs; i++) {
    v8::EscapableHandleScope inner_scope(CcTest::isolate());
    Local<String> value;
    if (i != 0) value = v8_str("escape value");
    if (i < runs / 2) {
      values[i] = inner_scope.Escape(value);
    } else {
      values[i] = inner_scope.EscapeMaybe(v8::MaybeLocal<String>(value))
                      .ToLocalChecked();
    }
  }
  for (int i = 0; i < runs; i++) {
    if (i != 0) {
      CHECK(v8_str("escape value")
                ->Equals(context.local(), values[i])
                .FromJust());
    } else {
      CHECK(values[i].IsEmpty());
    }
  }
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

static void SetterWhichExpectsThisAndHolderToDiffer(
    Local<Name>, Local<Value>, const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(info.Holder() != info.This());
  CHECK(info.HolderV2() != info.This());
}

// Allow usages of v8::PropertyCallbackInfo<T>::Holder() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

TEST(Regress239669) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), nullptr,
                               SetterWhichExpectsThisAndHolderToDiffer);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("P"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
      "function C1() {"
      "  this.x = 23;"
      "};"
      "C1.prototype = P;"
      "for (var i = 0; i < 4; i++ ) {"
      "  new C1();"
      "}");
}


class ApiCallOptimizationChecker {
 private:
  static v8::Global<Object> data;
  static v8::Global<Object> receiver;
  static v8::Global<Object> holder;
  static v8::Global<Object> callee;
  static int count;

  static void OptimizationCallback(
      const v8::FunctionCallbackInfo<v8::Value>& info) {
    CHECK(i::ValidateCallbackInfo(info));
    CHECK_EQ(data, info.Data());
    CHECK_EQ(receiver, info.This());
    if (info.Length() == 1) {
      CHECK(v8_num(1)
                ->Equals(info.GetIsolate()->GetCurrentContext(), info[0])
                .FromJust());
    }
    CHECK_EQ(holder, info.HolderSoonToBeDeprecated());
    count++;
    Local<Value> return_value = info.GetReturnValue().Get();
    CHECK(return_value->IsUndefined());
    info.GetReturnValue().Set(v8_str("returned"));
  }

 public:
  enum SignatureType {
    kNoSignature,
    kSignatureOnReceiver,
    kSignatureOnPrototype
  };

  void RunAll() {
    SignatureType signature_types[] =
      {kNoSignature, kSignatureOnReceiver, kSignatureOnPrototype};
    for (unsigned i = 0; i < arraysize(signature_types); i++) {
      SignatureType signature_type = signature_types[i];
      for (int j = 0; j < 2; j++) {
        bool global = j == 0;
        int key = signature_type +
            arraysize(signature_types) * (global ? 1 : 0);
        Run(signature_type, global, key);
      }
    }
  }

  // Allow usages of v8::Object::GetPrototype() for now.
  // TODO(https://crbug.com/333672197): remove.
  START_ALLOW_USE_DEPRECATED()

  void Run(SignatureType signature_type, bool global, int key) {
    v8::Isolate* isolate = CcTest::isolate();
    v8::HandleScope scope(isolate);
    // Build a template for signature checks.
    Local<v8::ObjectTemplate> signature_template;
    Local<v8::Signature> signature;
    {
      Local<v8::FunctionTemplate> parent_template =
        FunctionTemplate::New(isolate);
      Local<v8::FunctionTemplate> function_template
          = FunctionTemplate::New(isolate);
      function_template->Inherit(parent_template);
      switch (signature_type) {
        case kNoSignature:
          break;
        case kSignatureOnReceiver:
          signature = v8::Signature::New(isolate, function_template);
          break;
        case kSignatureOnPrototype:
          signature = v8::Signature::New(isolate, parent_template);
          break;
      }
      signature_template = function_template->InstanceTemplate();
    }
    // Global object must pass checks.
    Local<v8::Context> context =
        v8::Context::New(isolate, nullptr, signature_template);
    v8::Context::Scope context_scope(context);
    // Install regular object that can pass signature checks.
    Local<Object> function_receiver =
        signature_template->NewInstance(context).ToLocalChecked();
    CHECK(context->Global()
              ->Set(context, v8_str("function_receiver"), function_receiver)
              .FromJust());
    // Get the holder objects.
    Local<Object> inner_global =
        Local<Object>::Cast(context->Global()->GetPrototype());
    Local<Object> new_object = Object::New(isolate);
    data.Reset(isolate, new_object);
    Local<FunctionTemplate> function_template = FunctionTemplate::New(
        isolate, OptimizationCallback, new_object, signature);
    Local<Function> function =
        function_template->GetFunction(context).ToLocalChecked();
    Local<Object> global_holder = inner_global;
    Local<Object> function_holder = function_receiver;
    if (signature_type == kSignatureOnPrototype) {
      function_holder = Local<Object>::Cast(function_holder->GetPrototype());
      global_holder = Local<Object>::Cast(global_holder->GetPrototype());
    }
    global_holder->Set(context, v8_str("g_f"), function).FromJust();
    global_holder->SetAccessorProperty(v8_str("g_acc"), function, function);
    function_holder->Set(context, v8_str("f"), function).FromJust();
    function_holder->SetAccessorProperty(v8_str("acc"), function, function);
    // Initialize expected values.
    callee.Reset(isolate, function);
    count = 0;
    if (global) {
      receiver.Reset(isolate, context->Global());
      holder.Reset(isolate, inner_global);
    } else {
      holder.Reset(isolate, function_receiver);
      // If not using a signature, add something else to the prototype chain
      // to test the case that holder != receiver
      if (signature_type == kNoSignature) {
        receiver.Reset(isolate,
                       Local<Object>::Cast(CompileRun(
                           "var receiver_subclass = {};\n"
                           "receiver_subclass.__proto__ = function_receiver;\n"
                           "receiver_subclass")));
      } else {
        receiver.Reset(isolate,
                       Local<Object>::Cast(CompileRun(
                           "var receiver_subclass = function_receiver;\n"
                           "receiver_subclass")));
      }
    }
    // With no signature, the holder is not set.
    if (signature_type == kNoSignature) {
      holder.Reset(isolate, receiver);
    }
    // build wrap_function
    v8::base::ScopedVector<char> wrap_function(200);
    if (global) {
      v8::base::SNPrintF(wrap_function,
                         "function wrap_f_%d() { var f = g_f; return f(); }\n"
                         "function wrap_get_%d() { return this.g_acc; }\n"
                         "function wrap_set_%d() { return this.g_acc = 1; }\n",
                         key, key, key);
    } else {
      v8::base::SNPrintF(
          wrap_function,
          "function wrap_f_%d() { return receiver_subclass.f(); }\n"
          "function wrap_get_%d() { return receiver_subclass.acc; }\n"
          "function wrap_set_%d() { return receiver_subclass.acc = 1; }\n",
          key, key, key);
    }
    // build source string
    v8::base::ScopedVector<char> source(1000);
    v8::base::SNPrintF(source,
                       "%s\n"  // wrap functions
                       "function wrap_f() { return wrap_f_%d(); }\n"
                       "function wrap_get() { return wrap_get_%d(); }\n"
                       "function wrap_set() { return wrap_set_%d(); }\n"
                       "check = function(returned) {\n"
                       "  if (returned !== 'returned') { throw returned; }\n"
                       "};\n"
                       "\n"
                       "%%PrepareFunctionForOptimization(wrap_f_%d);"
                       "check(wrap_f());\n"
                       "check(wrap_f());\n"
                       "%%OptimizeFunctionOnNextCall(wrap_f_%d);\n"
                       "check(wrap_f());\n"
                       "\n"
                       "%%PrepareFunctionForOptimization(wrap_get_%d);"
                       "check(wrap_get());\n"
                       "check(wrap_get());\n"
                       "%%OptimizeFunctionOnNextCall(wrap_get_%d);\n"
                       "check(wrap_get());\n"
                       "\n"
                       "check = function(returned) {\n"
                       "  if (returned !== 1) { throw returned; }\n"
                       "};\n"
                       "%%PrepareFunctionForOptimization(wrap_set_%d);"
                       "check(wrap_set());\n"
                       "check(wrap_set());\n"
                       "%%OptimizeFunctionOnNextCall(wrap_set_%d);\n"
                       "check(wrap_set());\n",
                       wrap_function.begin(), key, key, key, key, key, key, key,
                       key, key);
    v8::TryCatch try_catch(isolate);
    CompileRun(source.begin());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(9, count);

    data.Reset();
    receiver.Reset();
    holder.Reset();
    callee.Reset();
  }

  // Allow usages of v8::Object::GetPrototype() for now.
  // TODO(https://crbug.com/333672197): remove.
  END_ALLOW_USE_DEPRECATED()
};

v8::Global<Object> ApiCallOptimizationChecker::data;
v8::Global<Object> ApiCallOptimizationChecker::receiver;
v8::Global<Object> ApiCallOptimizationChecker::holder;
v8::Global<Object> ApiCallOptimizationChecker::callee;
int ApiCallOptimizationChecker::count = 0;


TEST(FunctionCallOptimization) {
  i::v8_flags.allow_natives_syntax = true;
  ApiCallOptimizationChecker checker;
  checker.RunAll();
}


TEST(FunctionCallOptimizationMultipleArgs) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();
  Local<v8::Function> function =
      Function::New(context.local(), Returns42).ToLocalChecked();
  global->Set(context.local(), v8_str("x"), function).FromJust();
  CompileRun(
      "function x_wrap() {\n"
      "  for (var i = 0; i < 5; i++) {\n"
      "    x(1,2,3);\n"
      "  }\n"
      "}\n"
      "%PrepareFunctionForOptimization(x_wrap);\n"
      "x_wrap();\n"
      "%OptimizeFunctionOnNextCall(x_wrap);"
      "x_wrap();\n");
}


static void ReturnsSymbolCallback(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8::Symbol::New(info.GetIsolate()));
}


TEST(ApiCallbackCanReturnSymbols) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();
  Local<v8::Function> function =
      Function::New(context.local(), ReturnsSymbolCallback).ToLocalChecked();
  global->Set(context.local(), v8_str("x"), function).FromJust();
  CompileRun(
      "function x_wrap() {\n"
      "  for (var i = 0; i < 5; i++) {\n"
      "    x();\n"
      "  }\n"
      "}\n"
      "%PrepareFunctionForOptimization(x_wrap);\n"
      "x_wrap();\n"
      "%OptimizeFunctionOnNextCall(x_wrap);"
      "x_wrap();\n");
}


TEST(EmptyApiCallback) {
  LocalContext context;
  auto isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  auto global = context->Global();
  auto function = FunctionTemplate::New(isolate)
                      ->GetFunction(context.local())
                      .ToLocalChecked();
  global->Set(context.local(), v8_str("x"), function).FromJust();

  auto result = CompileRun("x()");
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*result)));

  result = CompileRun("x(1,2,3)");
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*result)));

  result = CompileRun("x.call(undefined)");
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*result)));

  result = CompileRun("x.call(null)");
  CHECK(IsJSGlobalProxy(*v8::Utils::OpenDirectHandle(*result)));

  result = CompileRun("7 + x.call(3) + 11");
  CHECK(result->IsInt32());
  CHECK_EQ(21, result->Int32Value(context.local()).FromJust());

  result = CompileRun("7 + x.call(3, 101, 102, 103, 104) + 11");
  CHECK(result->IsInt32());
  CHECK_EQ(21, result->Int32Value(context.local()).FromJust());

  result = CompileRun("var y = []; x.call(y)");
  CHECK(result->IsArray());

  result = CompileRun("x.call(y, 1, 2, 3, 4)");
  CHECK(result->IsArray());
}


TEST(SimpleSignatureCheck) {
  LocalContext context;
  auto isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  auto global = context->Global();
  auto sig_obj = FunctionTemplate::New(isolate);
  auto sig = v8::Signature::New(isolate, sig_obj);
  auto x = FunctionTemplate::New(isolate, Returns42, Local<Value>(), sig);
  global->Set(context.local(), v8_str("sig_obj"),
              sig_obj->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  global->Set(context.local(), v8_str("x"),
              x->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun("var s = new sig_obj();");
  {
    TryCatch try_catch(isolate);
    CompileRun("x()");
    CHECK(try_catch.HasCaught());
  }
  {
    TryCatch try_catch(isolate);
    CompileRun("x.call(1)");
    CHECK(try_catch.HasCaught());
  }
  {
    TryCatch try_catch(isolate);
    auto result = CompileRun("s.x = x; s.x()");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(42, result->Int32Value(context.local()).FromJust());
  }
  {
    TryCatch try_catch(isolate);
    auto result = CompileRun("x.call(s)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(42, result->Int32Value(context.local()).FromJust());
  }
}


TEST(ChainSignatureCheck) {
  LocalContext context;
  auto isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  auto global = context->Global();
  auto sig_obj = FunctionTemplate::New(isolate);
  auto sig = v8::Signature::New(isolate, sig_obj);
  for (int i = 0; i < 4; ++i) {
    auto temp = FunctionTemplate::New(isolate);
    temp->Inherit(sig_obj);
    sig_obj = temp;
  }
  auto x = FunctionTemplate::New(isolate, Returns42, Local<Value>(), sig);
  global->Set(context.local(), v8_str("sig_obj"),
              sig_obj->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  global->Set(context.local(), v8_str("x"),
              x->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun("var s = new sig_obj();");
  {
    TryCatch try_catch(isolate);
    CompileRun("x()");
    CHECK(try_catch.HasCaught());
  }
  {
    TryCatch try_catch(isolate);
    CompileRun("x.call(1)");
    CHECK(try_catch.HasCaught());
  }
  {
    TryCatch try_catch(isolate);
    auto result = CompileRun("s.x = x; s.x()");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(42, result->Int32Value(context.local()).FromJust());
  }
  {
    TryCatch try_catch(isolate);
    auto result = CompileRun("x.call(s)");
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(42, result->Int32Value(context.local()).FromJust());
  }
}


static const char* last_event_message;
// See v8::LogEventStatus
static v8::LogEventStatus last_event_status;
static int event_count = 0;
void StoringEventLoggerCallback(const char* message, int status) {
    last_event_message = message;
    last_event_status = static_cast<v8::LogEventStatus>(status);
    event_count++;
}


TEST(EventLogging) {
    i::v8_flags.log_timer_events = true;
    v8::Isolate* isolate = CcTest::isolate();
    isolate->SetEventLogger(StoringEventLoggerCallback);
    i::NestedTimedHistogram histogram(
        "V8.Test", 0, 10000, i::TimedHistogramResolution::MILLISECOND, 50,
        reinterpret_cast<i::Isolate*>(isolate)->counters());
    event_count = 0;
    int count = 0;
    {
    CHECK_EQ(0, event_count);
    {
      CHECK_EQ(0, e
```