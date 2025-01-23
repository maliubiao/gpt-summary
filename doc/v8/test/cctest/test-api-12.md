Response: My thinking process for summarizing the C++ code involved several steps:

1. **Understanding the Context:** The prompt explicitly states that this is part 13 of 18 of the `v8/test/cctest/test-api.cc` file. This immediately tells me the primary purpose is *testing the V8 JavaScript engine's C++ API*. The "cctest" part reinforces this, likely meaning "C++ tests".

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code looking for recurring patterns, class names, and function names. Keywords like `TEST`, `CHECK`, `CompileRun`, `LocalContext`, `v8::`, and class names like `RequestInterruptTestBase`, `FunctionNew`, `ObjectNew`, `Promise`, `Script` stand out.

3. **Identifying Core Functionality Blocks:** I noticed groups of tests related to specific API features. The naming conventions of the test classes and functions were very helpful here. I grouped them mentally:
    * **Interrupts:**  `RequestInterruptTest...` classes clearly deal with testing how external threads can interrupt JavaScript execution.
    * **Function Creation:**  The `FunctionNew` test focuses on the `Function::New` API.
    * **Object Creation:** The `ObjectNew` test examines `Object::New`.
    * **Handle Scopes:**  `EscapableHandleScope` is a clear indicator of testing handle management.
    * **Callbacks and Signatures:** Tests like `Regress239669`, `FunctionCallOptimization`, `SimpleSignatureCheck`, and `ChainSignatureCheck` relate to how C++ functions interact with JavaScript, including optimization and type checking.
    * **Event Logging:** `EventLogging` tests the engine's event logging capabilities.
    * **Property Descriptors:** `PropertyDescriptor` directly tests the `v8::PropertyDescriptor` API.
    * **Promises:** The `Promises`, `PromiseThen`, etc., tests are explicitly about the V8 Promise API.
    * **Script Handling:**  `ScriptNameAndLineNumber`, `ScriptPositionInfo`, and `ScriptPositionInfoWithLineEnds` deal with how V8 tracks script information.

4. **Deep Dive into Representative Examples:** For each identified block, I picked a few representative test cases to understand the *specifics* of what's being tested. For instance, within the "Interrupts" section, I saw tests using function calls, method calls, accessors, and even native accessors to trigger interruptions. This gave me a clearer picture of the breadth of the interrupt testing.

5. **Inferring Purpose from Test Structure:** I paid attention to the structure of the tests. The pattern of setting up a JavaScript environment (`LocalContext`), creating C++ objects that interact with JavaScript, running JavaScript code (`CompileRun`), and then using `CHECK` to verify expected behavior is a consistent pattern throughout the file. This confirms the "testing API functionality" conclusion.

6. **Connecting to JavaScript:**  The prompt specifically asks about the relationship to JavaScript. The `CompileRun` calls with JavaScript code snippets provide the direct link. I looked for examples of how the C++ API interacts with JavaScript constructs (functions, objects, prototypes, promises, etc.). This allowed me to generate the JavaScript examples illustrating the C++ functionality.

7. **Summarization and Refinement:** I started writing the summary by listing the major functional areas I had identified. I then refined the descriptions to be more concise and informative, using terminology relevant to both C++ and JavaScript (where applicable). I made sure to explicitly mention the testing aspect.

8. **Addressing the "Part 13 of 18" Information:** I included this detail in the summary, as it suggests the file is part of a larger suite of API tests.

9. **Generating JavaScript Examples:** For each major functional area related to JavaScript interaction, I created simple, illustrative JavaScript examples. My goal was to demonstrate the *effect* of the C++ API calls in the JavaScript environment. For example, showing how `RequestInterrupt` can stop an infinite loop or how `Function::New` creates callable functions.

10. **Review and Verification:** I reread the summary and the JavaScript examples to ensure they were accurate and clearly explained the functionality of the C++ code. I double-checked that the JavaScript examples were relevant to the C++ code they were intended to illustrate.

By following these steps, I could systematically analyze the C++ code and produce a comprehensive summary that addressed all aspects of the prompt, including the connection to JavaScript.
这个C++源代码文件 `v8/test/cctest/test-api.cc` 是V8 JavaScript引擎的C++ API的测试套件的一部分。 **第13部分** 主要关注以下功能的测试：

**核心功能归纳：**

1. **请求中断 (Request Interrupt):**
   - 测试了在JavaScript执行过程中从C++代码请求中断的能力。
   - 涵盖了各种JavaScript代码结构下的中断测试，例如：
     - 函数调用 (`RequestInterruptTestWithFunctionCall`)
     - 方法调用 (`RequestInterruptTestWithMethodCall`)
     - 访问器属性 (`RequestInterruptTestWithAccessor`, `RequestInterruptTestWithNativeAccessor`)
     - 带有拦截器的方法调用 (`RequestInterruptTestWithMethodCallAndInterceptor`)
     - 在`Math.abs`等内置函数调用中的中断 (`RequestInterruptTestWithMathAbs`)
   - 测试了请求多个中断的情况 (`RequestMultipleInterrupts`)
   - 测试了在执行小脚本时请求中断 (`RequestInterruptSmallScripts`)

2. **函数创建 (Function Creation):**
   - 测试了使用 `Function::New` API 从C++创建JavaScript函数的能力，并验证了回调函数的执行和数据传递 (`FunctionNew`).
   - 强调了每次 `Function::New` 都会创建一个新的函数实例，并且API函数数据不会被缓存。

3. **对象创建 (Object Creation):**
   - 测试了使用 `Object::New` API 从C++创建JavaScript对象的能力。
   - 涵盖了创建带有不同原型、属性的对象，包括重复属性名和数组索引的情况 (`ObjectNew`).

4. **作用域管理 (Scope Management):**
   - 测试了 `EscapableHandleScope` 的功能，用于在局部作用域中创建可以逃逸到外部作用域的对象句柄 (`EscapableHandleScope`).

5. **回调函数 (Callbacks):**
   - 测试了在属性设置器中使用回调函数时，`this` 和 `Holder` 的区别 (`Regress239669`).
   - 测试了API回调函数的优化情况，包括不同类型的签名 (有无签名，签名在接收者或原型上) (`ApiCallOptimizationChecker`, `FunctionCallOptimization`).
   - 测试了API回调函数可以返回 Symbol 类型的值 (`ApiCallbackCanReturnSymbols`).
   - 测试了空的API回调函数的行为 (`EmptyApiCallback`).

6. **签名检查 (Signature Check):**
   - 测试了函数模板的签名机制，用于限制可以调用该函数的对象类型 (`SimpleSignatureCheck`, `ChainSignatureCheck`).

7. **事件日志 (Event Logging):**
   - 测试了V8的事件日志功能，包括记录定时器事件的开始和结束 (`EventLogging`).

8. **属性描述符 (Property Descriptor):**
   - 测试了 `v8::PropertyDescriptor` 类的功能，用于定义对象属性的特性（值、getter、setter、可枚举、可配置、可写） (`PropertyDescriptor`).

9. **Promise API:**
   - 测试了 V8 的 Promise API，包括 Promise 的创建、状态转换 (resolve, reject)、`then` 和 `catch` 方法的使用，以及获取 Promise 的状态和值 (`Promises`, `PromiseThen`, `PromiseThen2`, `PromiseCatchCallsBuiltin`, `PromiseStateAndValue`, `ResolvedPromiseReFulfill`, `RejectedPromiseReFulfill`).

10. **JavaScript执行控制:**
    - 测试了禁止和允许JavaScript执行的作用域 (`DisallowJavascriptExecutionScope`, `AllowJavascriptExecutionScope`, `ThrowOnJavascriptExecution`, `DumpOnJavascriptExecution`).

11. **访问检查 (Access Check):**
    - 测试了访问检查回调函数在访问对象原型链上的属性时的行为 (`Regress354123`).

12. **脚本信息 (Script Information):**
    - 测试了获取脚本的名称和行号信息 (`ScriptNameAndLineNumber`).
    - 测试了获取脚本的位置信息，包括行号、列号以及代码行的起始和结束位置 (`ScriptPositionInfo`, `ScriptPositionInfoWithLineEnds`).
    - 测试了从源代码中解析 SourceURL 和 SourceMappingURL 的能力 (`CheckMagicComments`, `SourceURLHelper`).

**与 JavaScript 的关系及示例：**

这个文件中的所有测试都与 JavaScript 的功能密切相关，因为它测试的是 V8 引擎提供的用于在 C++ 中操作 JavaScript 运行时环境的 API。

**JavaScript 示例：**

以下是一些与测试用例相关的 JavaScript 示例：

* **请求中断 (Request Interrupt):**

```javascript
// C++ 代码可以请求中断来暂停或终止这段无限循环
while (true) {
  // ... 一些计算 ...
}
```

* **函数创建 (Function Creation):**

```javascript
// C++ 代码创建了一个名为 'myFunction' 的 JavaScript 函数
// 该函数在被调用时会执行 C++ 中定义的回调函数
myFunction();
```

* **对象创建 (Object Creation):**

```javascript
// C++ 代码创建了一个 JavaScript 对象，并设置了属性 'name' 和 'age'
const myObject = { name: "John", age: 30 };
```

* **作用域管理 (Scope Management):**

```javascript
function outerFunction() {
  let outerVar = "outer";
  // C++ 代码可能在某个内部作用域中创建了一个可以访问 outerVar 的对象
  // 并将该对象传递到 outerFunction 的外部
  return escapedObject;
}
```

* **回调函数 (Callbacks):**

```javascript
const myObject = {};
// C++ 代码为 myObject 的 'value' 属性定义了一个 setter
// 当执行 myObject.value = 10; 时，会调用 C++ 中定义的回调函数
myObject.value = 10;
```

* **签名检查 (Signature Check):**

```javascript
function MyClass() {}
const obj = new MyClass();

function apiFunction() { /* ... */ }

// C++ 代码可能会定义 apiFunction 只能被 MyClass 的实例调用
apiFunction.call(obj); // 成功
apiFunction.call({}); // 可能会抛出异常，因为 {} 不是 MyClass 的实例
```

* **Promise API:**

```javascript
const promise = new Promise((resolve, reject) => {
  // 异步操作
  setTimeout(() => {
    resolve("操作完成");
  }, 1000);
});

promise.then(result => {
  console.log(result); // "操作完成"
});
```

* **脚本信息 (Script Information):**

```javascript
// 当 JavaScript 引擎执行这段代码时，它可以记录脚本的 URL 和行号
// 方便调试和错误报告
console.log("Hello from my-script.js, line 5");
```

**总结来说，这个测试文件的第13部分专注于验证 V8 引擎 C++ API 中用于控制 JavaScript 执行、创建和操作 JavaScript 对象和函数、处理异步操作 (Promises) 以及获取脚本元数据等核心功能是否正常工作。** 它通过各种细致的测试用例来确保这些 API 的稳定性和正确性。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第13部分，共18部分，请归纳一下它的功能
```

### 源代码
```
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
      CHECK_EQ(0, event_count);
      i::NestedTimedHistogramScope scope0(&histogram);
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
      CHECK_EQ(++count, event_count);
    }
    CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
    CHECK_EQ(++count, event_count);

    i::NestedTimedHistogramScope scope1(&histogram);
    CHECK_EQ(0, strcmp("V8.Test", last_event_message));
    CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
    CHECK_EQ(++count, event_count);
    {
      CHECK_EQ(count, event_count);
      i::NestedTimedHistogramScope scope2(&histogram);
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
      CHECK_EQ(++count, event_count);
      {
        CHECK_EQ(count, event_count);
        i::NestedTimedHistogramScope scope3(&histogram);
        CHECK_EQ(++count, event_count);
        i::PauseNestedTimedHistogramScope scope4(&histogram);
        // The outer timer scope is just paused, no event is emited yet.
        CHECK_EQ(count, event_count);
        {
          CHECK_EQ(count, event_count);
          i::NestedTimedHistogramScope scope5(&histogram);
          i::NestedTimedHistogramScope scope5_1(&histogram);
          CHECK_EQ(0, strcmp("V8.Test", last_event_message));
          CHECK_EQ(v8::LogEventStatus::kStart, last_event_status);
          count++;
          CHECK_EQ(++count, event_count);
        }
        CHECK_EQ(0, strcmp("V8.Test", last_event_message));
        CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
        count++;
        CHECK_EQ(++count, event_count);
      }
      CHECK_EQ(0, strcmp("V8.Test", last_event_message));
      CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
      CHECK_EQ(++count, event_count);
      i::PauseNestedTimedHistogramScope scope6(&histogram);
      // The outer timer scope is just paused, no event is emited yet.
      CHECK_EQ(count, event_count);
      {
        i::PauseNestedTimedHistogramScope scope7(&histogram);
        CHECK_EQ(count, event_count);
      }
      CHECK_EQ(count, event_count);
    }
    CHECK_EQ(0, strcmp("V8.Test", last_event_message));
    CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
    CHECK_EQ(++count, event_count);
    }
  CHECK_EQ(0, strcmp("V8.Test", last_event_message));
  CHECK_EQ(v8::LogEventStatus::kEnd, last_event_status);
  CHECK_EQ(++count, event_count);
}

TEST(PropertyDescriptor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  {  // empty descriptor
    v8::PropertyDescriptor desc;
    CHECK(!desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_enumerable(false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_enumerable());
    CHECK(!desc.enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_configurable(true);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_configurable());
    CHECK(desc.configurable());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42));
    desc.set_configurable(false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8_num(42), false);
    CHECK(desc.value() == v8_num(42));
    CHECK(desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(desc.has_writable());
    CHECK(!desc.writable());
  }
  {
    // data descriptor
    v8::PropertyDescriptor desc(v8::Local<v8::Value>(), true);
    CHECK(!desc.has_value());
    CHECK(!desc.has_set());
    CHECK(!desc.has_get());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(desc.has_writable());
    CHECK(desc.writable());
  }
  {
    // accessor descriptor
    CompileRun("var set = function() {return 43;};");

    v8::Local<v8::Function> set =
        v8::Local<v8::Function>::Cast(context->Global()
                                          ->Get(context.local(), v8_str("set"))
                                          .ToLocalChecked());
    v8::PropertyDescriptor desc(v8::Undefined(isolate), set);
    desc.set_configurable(false);
    CHECK(!desc.has_value());
    CHECK(desc.has_get());
    CHECK(desc.get() == v8::Undefined(isolate));
    CHECK(desc.has_set());
    CHECK(desc.set() == set);
    CHECK(!desc.has_enumerable());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_writable());
  }
  {
    // accessor descriptor with Proxy
    CompileRun(
        "var set = new Proxy(function() {}, {});"
        "var get = undefined;");

    v8::Local<v8::Value> get =
        v8::Local<v8::Value>::Cast(context->Global()
                                       ->Get(context.local(), v8_str("get"))
                                       .ToLocalChecked());
    v8::Local<v8::Function> set =
        v8::Local<v8::Function>::Cast(context->Global()
                                          ->Get(context.local(), v8_str("set"))
                                          .ToLocalChecked());
    v8::PropertyDescriptor desc(get, set);
    desc.set_configurable(false);
    CHECK(!desc.has_value());
    CHECK(desc.get() == v8::Undefined(isolate));
    CHECK(desc.has_get());
    CHECK(desc.set() == set);
    CHECK(desc.has_set());
    CHECK(!desc.has_enumerable());
    CHECK(desc.has_configurable());
    CHECK(!desc.configurable());
    CHECK(!desc.has_writable());
  }
  {
    // accessor descriptor with empty function handle
    v8::Local<v8::Function> get = v8::Local<v8::Function>();
    v8::PropertyDescriptor desc(get, get);
    CHECK(!desc.has_value());
    CHECK(!desc.has_get());
    CHECK(!desc.has_set());
    CHECK(!desc.has_enumerable());
    CHECK(!desc.has_configurable());
    CHECK(!desc.has_writable());
  }
}

TEST(Promises) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise::Resolver> rr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();
  Local<v8::Promise> r = rr->GetPromise();

  // IsPromise predicate.
  CHECK(p->IsPromise());
  CHECK(r->IsPromise());
  Local<Value> o = v8::Object::New(isolate);
  CHECK(!o->IsPromise());

  // Resolution and rejection.
  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();
  CHECK(p->IsPromise());
  rr->Reject(context.local(), v8::Integer::New(isolate, 2)).FromJust();
  CHECK(r->IsPromise());
}

// Promise.Then(on_fulfilled)
TEST(PromiseThen) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise::Resolver> qr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();
  Local<v8::Promise> q = qr->GetPromise();

  CHECK(p->IsPromise());
  CHECK(q->IsPromise());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();
  qr->Resolve(context.local(), p).FromJust();

  // Chaining non-pending promises.
  CompileRun(
      "var x1 = 0;\n"
      "var x2 = 0;\n"
      "function f1(x) { x1 = x; return x+1 };\n"
      "function f2(x) { x2 = x; return x+1 };\n");
  Local<Function> f1 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f1")).ToLocalChecked());
  Local<Function> f2 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f2")).ToLocalChecked());

  // Then
  CompileRun("x1 = x2 = 0;");
  q->Then(context.local(), f1).ToLocalChecked();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  // Then
  CompileRun("x1 = x2 = 0;");
  pr = v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  qr = v8::Promise::Resolver::New(context.local()).ToLocalChecked();

  qr->Resolve(context.local(), pr).FromJust();
  qr->GetPromise()
      ->Then(context.local(), f1)
      .ToLocalChecked()
      ->Then(context.local(), f2)
      .ToLocalChecked();

  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 3)).FromJust();

  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(3, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(4, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
}

// Promise.Then(on_fulfilled, on_rejected)
TEST(PromiseThen2) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  // Creation.
  Local<v8::Promise::Resolver> pr =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  Local<v8::Promise> p = pr->GetPromise();

  CHECK(p->IsPromise());

  pr->Resolve(context.local(), v8::Integer::New(isolate, 1)).FromJust();

  // Chaining non-pending promises.
  CompileRun(
      "var x1 = 0;\n"
      "var x2 = 0;\n"
      "function f1(x) { x1 = x; return x+1 };\n"
      "function f2(x) { x2 = x; return x+1 };\n"
      "function f3(x) { throw x + 100 };\n");
  Local<Function> f1 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f1")).ToLocalChecked());
  Local<Function> f2 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f2")).ToLocalChecked());
  Local<Function> f3 = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f3")).ToLocalChecked());

  // Then
  CompileRun("x1 = x2 = 0;");
  Local<v8::Promise> a = p->Then(context.local(), f1, f2).ToLocalChecked();
  CHECK_EQ(0, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  Local<v8::Promise> b = a->Then(context.local(), f3, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(0, global->Get(context.local(), v8_str("x2"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());

  Local<v8::Promise> c = b->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> d = c->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> e = d->Then(context.local(), f3, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  v8::Local<v8::Promise> f = e->Then(context.local(), f1, f3).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(102, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());

  f->Then(context.local(), f1, f2).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(103, global->Get(context.local(), v8_str("x1"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  CHECK_EQ(304, global->Get(context.local(), v8_str("x2"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
}

TEST(PromiseCatchCallsBuiltin) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> global = context->Global();

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();

  resolver->Reject(context.local(), v8::Integer::New(isolate, 1)).FromJust();

  CompileRun(
      "var x1 = 0;\n"
      "function f(x) { x1 = x; }\n"
      "Promise.prototype.then = function () { throw 'unreachable'; };\n");
  Local<Function> f = Local<Function>::Cast(
      global->Get(context.local(), v8_str("f")).ToLocalChecked());

  // Catch should not call monkey-patched Promise.prototype.then.
  promise->Catch(context.local(), f).ToLocalChecked();
  isolate->PerformMicrotaskCheckpoint();
  CHECK_EQ(1, global->Get(context.local(), v8_str("x1"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
}

TEST(PromiseStateAndValue) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var resolver;"
      "new Promise((res, rej) => { resolver = res; })");
  v8::Local<v8::Promise> promise = v8::Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  CompileRun("resolver('fulfilled')");
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK(v8_str("fulfilled")->SameValue(promise->Result()));

  result = CompileRun("Promise.reject('rejected')");
  promise = v8::Local<v8::Promise>::Cast(result);
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK(v8_str("rejected")->SameValue(promise->Result()));
}

TEST(ResolvedPromiseReFulfill) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> value1 = v8::String::NewFromUtf8Literal(isolate, "foo");
  v8::Local<v8::String> value2 = v8::String::NewFromUtf8Literal(isolate, "bar");

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  resolver->Resolve(context.local(), value1).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Resolve(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Reject(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kFulfilled);
  CHECK_EQ(promise->Result(), value1);
}

TEST(RejectedPromiseReFulfill) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> value1 = v8::String::NewFromUtf8Literal(isolate, "foo");
  v8::Local<v8::String> value2 = v8::String::NewFromUtf8Literal(isolate, "bar");

  v8::Local<v8::Promise::Resolver> resolver =
      v8::Promise::Resolver::New(context.local()).ToLocalChecked();
  v8::Local<v8::Promise> promise = resolver->GetPromise();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kPending);

  resolver->Reject(context.local(), value1).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Reject(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);

  // This should be a no-op.
  resolver->Resolve(context.local(), value2).ToChecked();
  CHECK_EQ(promise->State(), v8::Promise::PromiseState::kRejected);
  CHECK_EQ(promise->Result(), value1);
}

TEST(DisallowJavascriptExecutionScope) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope no_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::CRASH_ON_FAILURE);
  CompileRun("2+2");
}

TEST(AllowJavascriptExecutionScope) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope no_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::CRASH_ON_FAILURE);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  { v8::Isolate::AllowJavascriptExecutionScope yes_js(isolate);
    CompileRun("1+1");
  }
}

TEST(ThrowOnJavascriptExecution) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::THROW_ON_FAILURE);
  CompileRun("1+1");
  CHECK(try_catch.HasCaught());
}

namespace {

class MockPlatform final : public TestPlatform {
 public:
  bool dump_without_crashing_called() const {
    return dump_without_crashing_called_;
  }

  void DumpWithoutCrashing() override { dump_without_crashing_called_ = true; }

 private:
  bool dump_without_crashing_called_ = false;
};

}  // namespace

TEST_WITH_PLATFORM(DumpOnJavascriptExecution, MockPlatform) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Isolate::DisallowJavascriptExecutionScope throw_js(
      isolate, v8::Isolate::DisallowJavascriptExecutionScope::DUMP_ON_FAILURE);
  CHECK(!platform.dump_without_crashing_called());
  CompileRun("1+1");
  CHECK(platform.dump_without_crashing_called());
}

TEST(Regress354123) {
  LocalContext current;
  v8::Isolate* isolate = current->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessCounter);
  CHECK(current->Global()
            ->Set(current.local(), v8_str("friend"),
                  templ->NewInstance(current.local()).ToLocalChecked())
            .FromJust());

  // Test access using __proto__ from the prototype chain.
  access_count = 0;
  CompileRun("friend.__proto__ = {};");
  CHECK_EQ(2, access_count);
  CompileRun("friend.__proto__;");
  CHECK_EQ(4, access_count);

  // Test access using __proto__ as a hijacked function (A).
  access_count = 0;
  CompileRun("var p = Object.prototype;"
             "var f = Object.getOwnPropertyDescriptor(p, '__proto__').set;"
             "f.call(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("var p = Object.prototype;"
             "var f = Object.getOwnPropertyDescriptor(p, '__proto__').get;"
             "f.call(friend);");
  CHECK_EQ(2, access_count);

  // Test access using __proto__ as a hijacked function (B).
  access_count = 0;
  CompileRun("var f = Object.prototype.__lookupSetter__('__proto__');"
             "f.call(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("var f = Object.prototype.__lookupGetter__('__proto__');"
             "f.call(friend);");
  CHECK_EQ(2, access_count);

  // Test access using Object.setPrototypeOf reflective method.
  access_count = 0;
  CompileRun("Object.setPrototypeOf(friend, {});");
  CHECK_EQ(1, access_count);
  CompileRun("Object.getPrototypeOf(friend);");
  CHECK_EQ(2, access_count);
}


namespace {
bool ValueEqualsString(v8::Isolate* isolate, Local<Value> lhs,
                       const char* rhs) {
  CHECK(!lhs.IsEmpty());
  CHECK(lhs->IsString());
  String::Utf8Value utf8_lhs(isolate, lhs);
  return strcmp(rhs, *utf8_lhs) == 0;
}
}  // namespace

TEST(ScriptNameAndLineNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;"), origin);

  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();
  CHECK(ValueEqualsString(isolate, script->GetUnboundScript()->GetScriptName(),
                          url));

  int line_number = script->GetUnboundScript()->GetLineNumber(0);
  CHECK_EQ(13, line_number);
}

TEST(ScriptPositionInfo) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;\n"
                                                  "var bar;\n"
                                                  "var fisk = foo + bar;\n"),
                                           origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();

  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*script->GetUnboundScript()));
  CHECK(IsScript(obj->script()));

  i::DirectHandle<i::Script> script1(i::Cast<i::Script>(obj->script()),
                                     i_isolate);

  i::Script::PositionInfo info;

  for (int i = 0; i < 2; ++i) {
    // With offset.

    // Behave as if 0 was passed if position is negative.
    CHECK(script1->GetPositionInfo(-1, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(0, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(8, &info));
    CHECK_EQ(13, info.line);
    CHECK_EQ(8, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(9, &info));
    CHECK_EQ(14, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(9, info.line_start);
    CHECK_EQ(17, info.line_end);

    // Fail when position is larger than script size.
    CHECK(!script1->GetPositionInfo(220384, &info));

    // Without offset.

    // Behave as if 0 was passed if position is negative.
    CHECK(
        script1->GetPositionInfo(-1, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(0, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(8, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(0, info.line);
    CHECK_EQ(8, info.column);
    CHECK_EQ(0, info.line_start);
    CHECK_EQ(8, info.line_end);

    CHECK(script1->GetPositionInfo(9, &info, i::Script::OffsetFlag::kNoOffset));
    CHECK_EQ(1, info.line);
    CHECK_EQ(0, info.column);
    CHECK_EQ(9, info.line_start);
    CHECK_EQ(17, info.line_end);

    // Fail when position is larger than script size.
    CHECK(!script1->GetPositionInfo(220384, &info,
                                    i::Script::OffsetFlag::kNoOffset));

    i::Script::InitLineEnds(i_isolate, script1);
  }
}

TEST(ScriptPositionInfoWithLineEnds) {
  // Same as ScriptPositionInfo, but using out-of-heap cached line ends
  // information. In this case we do not need the two passes (with heap cached)
  // line information and without it that were required in ScriptPositionInfo.
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);
  const char* url = "http://www.foo.com/foo.js";
  v8::ScriptOrigin origin(v8_str(url), 13, 0);
  v8::ScriptCompiler::Source script_source(v8_str("var foo;\n"
                                                  "var bar;\n"
                                                  "var fisk = foo + bar;\n"),
                                           origin);
  Local<Script> script =
      v8::ScriptCompiler::Compile(env.local(), &script_source).ToLocalChecked();

  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*script->GetUnboundScript()));
  CHECK(IsScript(obj->script()));

  i::DirectHandle<i::Script> script1(i::Cast<i::Script>(obj->script()),
                                     i_isolate);

  i::String::LineEndsVector line_ends =
      i::Script::GetLineEnds(i_isolate, script1);

  i::Script::PositionInfo info;

  // Behave as if 0 was passed if position is negative.
  CHECK(script1->GetPositionInfoWithLineEnds(-1, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(0, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(8, &info, line_ends));
  CHECK_EQ(13, info.line);
  CHECK_EQ(8, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(9, &info, line_ends));
  CHECK_EQ(14, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(9, info.line_start);
  CHECK_EQ(17, info.line_end);

  // Fail when position is larger than script size.
  CHECK(!script1->GetPositionInfoWithLineEnds(220384, &info, line_ends));

  // Without offset.

  // Behave as if 0 was passed if position is negative.
  CHECK(script1->GetPositionInfoWithLineEnds(-1, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(0, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(8, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(0, info.line);
  CHECK_EQ(8, info.column);
  CHECK_EQ(0, info.line_start);
  CHECK_EQ(8, info.line_end);

  CHECK(script1->GetPositionInfoWithLineEnds(9, &info, line_ends,
                                             i::Script::OffsetFlag::kNoOffset));
  CHECK_EQ(1, info.line);
  CHECK_EQ(0, info.column);
  CHECK_EQ(9, info.line_start);
  CHECK_EQ(17, info.line_end);

  // Fail when position is larger than script size.
  CHECK(!script1->GetPositionInfoWithLineEnds(
      220384, &info, line_ends, i::Script::OffsetFlag::kNoOffset));
}

template <typename T>
void CheckMagicComments(v8::Isolate* isolate, Local<T> unbound_script,
                        const char* expected_source_url,
                        const char* expected_source_mapping_url) {
  if (expected_source_url != nullptr) {
    v8::String::Utf8Value url(isolate, unbound_script->GetSourceURL());
    CHECK_EQ(0, strcmp(expected_source_url, *url));
  } else {
    CHECK(unbound_script->GetSourceURL()->IsUndefined());
  }
  if (expected_source_mapping_url != nullptr) {
    v8::String::Utf8Value url(isolate, unbound_script->GetSourceMappingURL());
    CHECK_EQ(0, strcmp(expected_source_mapping_url, *url));
  } else {
    CHECK(unbound_script->GetSourceMappingURL()->IsUndefined());
  }
}

void SourceURLHelper(v8::Isolate* isolate, const char* source_text,
                     const char* expected_source_url,
                     const char* expected_source_mapping_url) {
  // Check scripts
  {
    Local<Script> script = v8_compile(source_text);
    CheckMagicComments(isolate, script->GetUnboundScript(), expected_source_url,
                       expected_source_mapping_url);
  }

  // Check modules
  {
    Local<v8::String> source_str = v8_str(source_text);
    // Set a different resource name with the case above to invalidate the
    // cache.
    v8::ScriptOrigin origin(v8_str("module.js"),  // resource name
                            0,                    // line offset
                            0,                    // column offset
                            true,                 // is cross origin
                            -1,                   // script id
                            Local<Value>(),       // source map URL
                            false,                // is opaque
                            false,                // is WASM
                            true);                // is ES Module
    v8::ScriptCompiler::Source source(source_str, origin, nullptr);
```