Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's test suite.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file is named `test-api.cc`, suggesting it tests various aspects of V8's C++ API.

2. **Examine individual tests:** Each `TEST` or `THREADED_TEST` block represents a specific test case. Analyze what each test is doing.

3. **Look for patterns and themes:** Group similar tests to find common functionalities being tested.

4. **Connect to JavaScript concepts:** If a test relates to JavaScript behavior, provide a JavaScript example to illustrate it.

5. **Consider potential errors:** If a test seems to target a common mistake, illustrate it with a JavaScript example.

6. **Address specific instructions:** Ensure all user prompts (e.g., `.tq` check, JavaScript examples, input/output, common errors) are addressed.

7. **Summarize:** Combine the identified functionalities into a concise summary, keeping in mind this is part 21 of 36.

**Detailed Analysis of the Code Snippet:**

* **Script IDs:** Tests retrieving script IDs from functions created in different scopes.
* **`Function.bind()`:** Tests the `getBoundFunction()` API for functions created using `bind()`.
* **`Function.prototype.toString()`:** Tests that `FunctionProtoToString()` retrieves the original source code, even if the `toString` method is overridden.
* **Property Callbacks (Getters/Setters):** Tests setting native data properties with getter and setter callbacks on object templates and their interaction with prototypes.
* **Interceptors:** Tests using interceptors (named property handlers) on object templates and their interaction with prototypes.
* **Constructor Prototypes:**  Several tests focus on how properties and interceptors defined on constructor prototypes behave when instances are created. This includes cases with simple object prototypes and API object prototypes.
* **Compilation Cache:** Tests how the compilation cache interacts with prototypes that change between compilations.
* **Garbage Collection Callbacks:** Tests adding and removing GC prologue and epilogue callbacks, with and without associated data.
* **String Representation (`ContainsOnlyOneByte`):** Tests the `ContainsOnlyOneByte()` API for strings, including external two-byte strings and cons strings. It checks various scenarios, including concatenation.
* **Failed Access Check Callback and GC:** Tests what happens when a failed access check callback triggers garbage collection. It covers various operations that can trigger access checks (getting/setting properties/elements, deleting, defining accessors, etc.).
* **Isolate Creation and Disposal:** Tests creating and disposing of V8 isolates. It also tests attempting to dispose of an isolate while it is still in use, which should result in an error.
* **Array Prototype Guarantees:** Tests scenarios that can break V8's assumptions about array prototypes, potentially leading to performance optimizations being disabled.
* **Multiple Isolates:** Tests running code in multiple isolates on a single thread and on different threads. It verifies proper isolation of contexts and variables.

**Addressing User Prompts:**

* **`.tq` check:** The file ends with `.cc`, so it's not a Torque file.
* **JavaScript relationship:** Many tests directly correspond to JavaScript features like function binding, `toString`, prototypes, getters/setters, etc.
* **Code logic inference:**  The tests involve setting up specific scenarios (e.g., prototypes, accessors) and then running JavaScript code to verify the expected behavior.
* **Common programming errors:** The tests on constructor prototypes and the compilation cache touch upon potential misunderstandings of how prototypes work in JavaScript. The failed access check test highlights security considerations when working with different contexts.

**Summarization (Part 21 of 36):**

This section of the V8 API test suite focuses on testing the behavior of **functions, object properties (including getters, setters, and interceptors), prototypes, garbage collection callbacks, string representation, isolate management, and interactions between different isolates**. It ensures that the C++ API correctly reflects and controls the corresponding JavaScript semantics. A significant portion of the tests in this section deal with the intricacies of how prototypes and accessors function, particularly in scenarios involving constructor functions and the compilation cache. It also verifies the robustness of V8's security model when interacting with objects across different contexts and tests the lifecycle of V8 isolates.
这是 V8 JavaScript 引擎源代码 `v8/test/cctest/test-api.cc` 的第 21 部分，共 36 部分。根据代码内容，我们可以归纳出以下功能：

**主要功能：测试 V8 C++ API 的各种功能，特别是与以下方面相关的 API：**

1. **脚本和函数信息获取:**
   - 测试获取函数关联的脚本 ID (`GetScriptId`)，包括通过 `bind()` 创建的绑定函数。

2. **函数绑定 (`Function.bind()`):**
   - 测试 `GetBoundFunction()` API，以验证是否能获取绑定函数的原始函数。
   - 检查原始函数和绑定函数的名称、行号和列号是否一致。
   - **JavaScript 举例:**
     ```javascript
     function originalFunction() { return this.value; }
     let obj = { value: 10 };
     let boundFunction = originalFunction.bind(obj);
     console.log(boundFunction()); // 输出 10
     ```

3. **自定义 `Function.prototype.toString()`:**
   - 测试即使 `Function.prototype.toString` 被自定义修改后，`FunctionProtoToString()` API 仍然能获取函数的原始源代码。
   - **JavaScript 举例:**
     ```javascript
     Function.prototype.toString = function() { return 'customized'; };
     function myFunction() { return 42; }
     console.log(myFunction.toString()); // 输出 "customized"
     // V8 内部的 FunctionProtoToString 应该能获取 "function myFunction() { return 42; }"
     ```

4. **属性访问回调 (Getters 和 Setters):**
   - 测试使用 `SetNativeDataProperty` 设置原生数据属性，并定义 Getter 和 Setter 回调函数。
   - 验证 Getter 和 Setter 回调函数的参数信息是否正确。
   - **JavaScript 举例:**
     ```javascript
     let obj = {};
     Object.defineProperty(obj, 'x', {
       get: function() { return 42; },
       set: function(value) { this.y = 23; }
     });
     console.log(obj.x); // 输出 42
     obj.x = 10;
     console.log(obj.y); // 输出 23
     ```
   - **假设输入与输出:**
     - 假设 JavaScript 代码 `new C1()` 被执行，并且 `C1.prototype` 上定义了带有 Getter (`GetterWhichReturns42`) 和 Setter (`SetterWhichSetsYOnThisTo23`) 的属性 `x`。
     - **输入:** 执行 `c1.x = 23;`
     - **输出:** Getter `GetterWhichReturns42` 会返回 `42` (但这个返回值会被赋值覆盖)，Setter `SetterWhichSetsYOnThisTo23` 会将 `c1.y` 设置为 `23`。

5. **拦截器 (Interceptors):**
   - 测试使用 `SetHandler` 设置命名属性拦截器，包括 Getter 和 Setter 拦截器。
   - 验证拦截器的执行逻辑和参数信息。
   - **JavaScript 举例:**
     ```javascript
     let obj = {};
     let handler = {
       get: function(target, prop, receiver) {
         if (prop === 'foo') {
           return 42;
         }
         return target[prop];
       },
       set: function(target, prop, value, receiver) {
         if (prop === 'foo') {
           target.y = 23;
           return true;
         }
         target[prop] = value;
         return true;
       }
     };
     let proxy = new Proxy(obj, handler);
     console.log(proxy.foo); // 输出 42
     proxy.foo = 10;
     console.log(proxy.y); // 输出 23
     ```

6. **构造函数原型上的 Setter 和拦截器:**
   - 测试在构造函数的 `prototype` 上设置带有 Setter 和拦截器的属性，以及创建实例后这些 Setter 和拦截器的行为。
   - 这部分测试了原型链的继承和属性查找机制。

7. **回归测试 (Regress618):**
   - 针对特定 Bug (618) 的回归测试，验证在构造函数原型改变后，编译缓存是否能正确处理。
   - **代码逻辑推理:**
     - **假设输入:**  先使用一个简单的对象作为 `C1.prototype` 并编译运行 `new C1()` 多次。然后，将 `C1.prototype` 替换为一个带有原生 Setter 的 API 对象，再次编译运行 `new C1()`。
     - **输出:**  第一次循环创建的 `c1` 实例的 `y` 属性应该能通过原型链访问到。第二次循环创建的 `c1` 实例在设置 `x` 时，会触发原生 Setter，导致 `y` 被设置为 `0` (因为 `SetterWhichSetsYOnThisTo23` 是在当前对象上设置 `y`)。
   - **用户常见的编程错误:**  容易混淆原型链的查找顺序和直接在实例上设置属性的区别。

8. **垃圾回收回调 (GC Callbacks):**
   - 测试添加和移除垃圾回收的 Prologue (开始前) 和 Epilogue (结束后) 回调函数。
   - 验证回调函数的调用次数和参数是否正确。
   - 测试带有额外数据的回调函数。

9. **字符串 `ContainsOnlyOneByte()`:**
   - 测试字符串是否只包含单字节字符的 API (`ContainsOnlyOneByte()`).
   - 涵盖了不同类型的字符串，包括外部双字节字符串和拼接字符串 (Cons Strings)。
   - **用户常见的编程错误:**  在处理字符串编码时，错误地假设所有字符都是单字节的。

10. **失败的访问检查回调 (Failed Access Check Callback) 中的垃圾回收:**
    - 测试当跨上下文访问被拒绝，且失败的访问检查回调函数中执行垃圾回收时，V8 的行为是否正确。
    - **用户常见的编程错误:**  在跨上下文操作时，没有正确处理访问权限问题。

11. **Isolate 的创建和销毁:**
    - 测试创建新的 Isolate (`v8::Isolate::New`) 和销毁 Isolate (`isolate->Dispose()`) 的功能。
    - 测试在 Isolate 正在使用时尝试销毁它，预期会失败。

12. **打破数组原型保证 (Break Array Guarantees):**
    - 测试一些操作，这些操作可能会破坏 V8 对数组原型的假设，从而影响性能优化。这些操作包括修改 `__proto__`、添加元素到 `Object.prototype`、修改 `Array.prototype` 的属性等。

13. **在单线程上运行多个 Isolate:**
    - 测试在同一个线程上创建和运行多个独立的 Isolate。
    - 验证不同 Isolate 之间的上下文隔离。

14. **在不同线程上运行多个 Isolate:**
    - 测试在不同的线程上创建和运行多个独立的 Isolate。
    - 使用 Fibonacci 数列计算作为示例，验证多线程 Isolate 的独立性。

15. **Isolate 中不同的 Context:**
    - 这部分代码片段被截断，但可以推测它会测试在同一个 Isolate 中创建和使用多个不同的 Context，以及它们之间的隔离性。

**总结第 21 部分的功能:**

这部分 `test-api.cc` 主要测试了 V8 C++ API 中与**函数操作、属性访问控制（包括 Getter/Setter 和拦截器）、原型链、垃圾回收机制、字符串处理以及多 Isolate 管理**相关的核心功能。它通过各种测试用例验证了 API 的正确性和健壮性，并覆盖了一些可能导致问题的常见编程错误场景。  由于是测试代码，它通过 `CHECK` 宏来断言各种条件是否成立，以确保 V8 引擎的行为符合预期。

如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那它将是一个 V8 Torque 源代码，Torque 是一种用于定义 V8 内部函数的领域特定语言。然而，当前的文件名以 `.cc` 结尾，表明它是 C++ 代码。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第21部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
pt()->GetId(), foo->ScriptId());
  CHECK_EQ(script->GetUnboundScript()->GetId(), bar->ScriptId());
}


THREADED_TEST(FunctionGetBoundFunction) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"));
  v8::Local<v8::String> script = v8_str(
      "var a = new Object();\n"
      "a.x = 1;\n"
      "function f () { return this.x };\n"
      "var g = f.bind(a);\n"
      "var b = g();");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("g")).ToLocalChecked());
  CHECK(g->GetBoundFunction()->IsFunction());
  Local<v8::Function> original_function = Local<v8::Function>::Cast(
      g->GetBoundFunction());
  CHECK(f->GetName()
            ->Equals(env.local(), original_function->GetName())
            .FromJust());
  CHECK_EQ(f->GetScriptLineNumber(), original_function->GetScriptLineNumber());
  CHECK_EQ(f->GetScriptColumnNumber(),
           original_function->GetScriptColumnNumber());
}

THREADED_TEST(FunctionProtoToString) {
  LocalContext context;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Replace Function.prototype.toString.
  CompileRun(R"(
      Function.prototype.toString = function() {
        return 'customized toString';
      })");

  constexpr char kTestFunction[] = "function testFunction() { return 7; }";
  std::string wrapped_function("(");
  wrapped_function.append(kTestFunction).append(")");
  Local<Function> function =
      CompileRun(wrapped_function.c_str()).As<Function>();

  Local<String> value = function->ToString(context.local()).ToLocalChecked();
  CHECK(value->IsString());
  CHECK(
      value->Equals(context.local(), v8_str("customized toString")).FromJust());

  // FunctionProtoToString() should not call the replaced toString function.
  value = function->FunctionProtoToString(context.local()).ToLocalChecked();
  CHECK(value->IsString());
  CHECK(value->Equals(context.local(), v8_str(kTestFunction)).FromJust());
}

static void GetterWhichReturns42(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.This())));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.HolderV2())));
  info.GetReturnValue().Set(v8_num(42));
}

static void SetterWhichSetsYOnThisTo23(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.This())));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.HolderV2())));
  info.This()
      .As<Object>()
      ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("y"), v8_num(23))
      .FromJust();
}

v8::Intercepted FooGetInterceptor(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.This())));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.HolderV2())));
  if (!name->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
           .FromJust()) {
    return v8::Intercepted::kNo;
  }
  info.GetReturnValue().Set(v8_num(42));
  return v8::Intercepted::kYes;
}

v8::Intercepted FooSetInterceptor(Local<Name> name, Local<Value> value,
                                  const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.This())));
  CHECK(IsJSObject(*v8::Utils::OpenDirectHandle(*info.HolderV2())));
  if (!name->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
           .FromJust()) {
    return v8::Intercepted::kNo;
  }
  info.This()
      .As<Object>()
      ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("y"), v8_num(23))
      .FromJust();
  return v8::Intercepted::kYes;
}

TEST(SetterOnConstructorPrototype) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("P"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("function C1() {"
             "  this.x = 23;"
             "};"
             "C1.prototype = P;"
             "function C2() {"
             "  this.x = 23"
             "};"
             "C2.prototype = { };"
             "C2.prototype.__proto__ = P;");

  v8::Local<v8::Script> script;
  script = v8_compile("new C1();");
  for (int i = 0; i < 10; i++) {
    v8::Local<v8::Object> c1 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c1->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(0, c1->Get(context.local(), v8_str("y"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  }

  script = v8_compile("new C2();");
  for (int i = 0; i < 10; i++) {
    v8::Local<v8::Object> c2 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c2->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(0, c2->Get(context.local(), v8_str("y"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  }
}

namespace {
v8::Intercepted NamedPropertySetterWhichSetsYOnThisTo23(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (name->Equals(context, v8_str("x")).FromJust()) {
    info.This().As<Object>()->Set(context, v8_str("y"), v8_num(23)).FromJust();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(InterceptorOnConstructorPrototype) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      NamedPropertyGetterWhichReturns42,
      NamedPropertySetterWhichSetsYOnThisTo23));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("P"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("function C1() {"
             "  this.x = 23;"
             "};"
             "C1.prototype = P;"
             "function C2() {"
             "  this.x = 23"
             "};"
             "C2.prototype = { };"
             "C2.prototype.__proto__ = P;");

  v8::Local<v8::Script> script;
  script = v8_compile("new C1();");
  for (int i = 0; i < 10; i++) {
    v8::Local<v8::Object> c1 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c1->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(42, c1->Get(context.local(), v8_str("y"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  }

  script = v8_compile("new C2();");
  for (int i = 0; i < 10; i++) {
    v8::Local<v8::Object> c2 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c2->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(42, c2->Get(context.local(), v8_str("y"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  }
}


TEST(Regress618) {
  const char* source = "function C1() {"
                       "  this.x = 23;"
                       "};"
                       "C1.prototype = P;";

  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Script> script;

  // Use a simple object as prototype.
  v8::Local<v8::Object> prototype = v8::Object::New(isolate);
  prototype->Set(context.local(), v8_str("y"), v8_num(42)).FromJust();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("P"), prototype)
            .FromJust());

  // This compile will add the code to the compilation cache.
  CompileRun(source);

  script = v8_compile("new C1();");
  // Allow enough iterations for the inobject slack tracking logic
  // to finalize instance size and install the fast construct stub.
  for (int i = 0; i < 256; i++) {
    v8::Local<v8::Object> c1 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c1->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(42, c1->Get(context.local(), v8_str("y"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  }

  // Use an API object with accessors as prototype.
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("P"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // This compile will get the code from the compilation cache.
  CompileRun(source);

  script = v8_compile("new C1();");
  for (int i = 0; i < 10; i++) {
    v8::Local<v8::Object> c1 = v8::Local<v8::Object>::Cast(
        script->Run(context.local()).ToLocalChecked());
    CHECK_EQ(23, c1->Get(context.local(), v8_str("x"))
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
    CHECK_EQ(0, c1->Get(context.local(), v8_str("y"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
  }
}

v8::Isolate* gc_callbacks_isolate = nullptr;
int prologue_call_count = 0;
int epilogue_call_count = 0;
int prologue_call_count_second = 0;
int epilogue_call_count_second = 0;
int prologue_call_count_alloc = 0;
int epilogue_call_count_alloc = 0;

void PrologueCallback(v8::Isolate* isolate,
                      v8::GCType,
                      v8::GCCallbackFlags flags) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++prologue_call_count;
}

void EpilogueCallback(v8::Isolate* isolate,
                      v8::GCType,
                      v8::GCCallbackFlags flags) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++epilogue_call_count;
}


void PrologueCallbackSecond(v8::Isolate* isolate,
                            v8::GCType,
                            v8::GCCallbackFlags flags) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++prologue_call_count_second;
}


void EpilogueCallbackSecond(v8::Isolate* isolate,
                            v8::GCType,
                            v8::GCCallbackFlags flags) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++epilogue_call_count_second;
}

void PrologueCallbackNew(v8::Isolate* isolate, v8::GCType,
                         v8::GCCallbackFlags flags, void* data) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++*static_cast<int*>(data);
}

void EpilogueCallbackNew(v8::Isolate* isolate, v8::GCType,
                         v8::GCCallbackFlags flags, void* data) {
  CHECK_EQ(flags, v8::kNoGCCallbackFlags);
  CHECK_EQ(gc_callbacks_isolate, isolate);
  ++*static_cast<int*>(data);
}

TEST(GCCallbacksOld) {
  LocalContext context;

  gc_callbacks_isolate = context->GetIsolate();

  context->GetIsolate()->AddGCPrologueCallback(PrologueCallback);
  context->GetIsolate()->AddGCEpilogueCallback(EpilogueCallback);
  CHECK_EQ(0, prologue_call_count);
  CHECK_EQ(0, epilogue_call_count);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(1, prologue_call_count);
  CHECK_EQ(1, epilogue_call_count);
  context->GetIsolate()->AddGCPrologueCallback(PrologueCallbackSecond);
  context->GetIsolate()->AddGCEpilogueCallback(EpilogueCallbackSecond);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue_call_count);
  CHECK_EQ(2, epilogue_call_count);
  CHECK_EQ(1, prologue_call_count_second);
  CHECK_EQ(1, epilogue_call_count_second);
  context->GetIsolate()->RemoveGCPrologueCallback(PrologueCallback);
  context->GetIsolate()->RemoveGCEpilogueCallback(EpilogueCallback);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue_call_count);
  CHECK_EQ(2, epilogue_call_count);
  CHECK_EQ(2, prologue_call_count_second);
  CHECK_EQ(2, epilogue_call_count_second);
  context->GetIsolate()->RemoveGCPrologueCallback(PrologueCallbackSecond);
  context->GetIsolate()->RemoveGCEpilogueCallback(EpilogueCallbackSecond);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue_call_count);
  CHECK_EQ(2, epilogue_call_count);
  CHECK_EQ(2, prologue_call_count_second);
  CHECK_EQ(2, epilogue_call_count_second);
}

TEST(GCCallbacksWithData) {
  LocalContext context;

  gc_callbacks_isolate = context->GetIsolate();
  int prologue1 = 0;
  int epilogue1 = 0;
  int prologue2 = 0;
  int epilogue2 = 0;

  context->GetIsolate()->AddGCPrologueCallback(PrologueCallbackNew, &prologue1);
  context->GetIsolate()->AddGCEpilogueCallback(EpilogueCallbackNew, &epilogue1);
  CHECK_EQ(0, prologue1);
  CHECK_EQ(0, epilogue1);
  CHECK_EQ(0, prologue2);
  CHECK_EQ(0, epilogue2);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(1, prologue1);
  CHECK_EQ(1, epilogue1);
  CHECK_EQ(0, prologue2);
  CHECK_EQ(0, epilogue2);
  context->GetIsolate()->AddGCPrologueCallback(PrologueCallbackNew, &prologue2);
  context->GetIsolate()->AddGCEpilogueCallback(EpilogueCallbackNew, &epilogue2);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue1);
  CHECK_EQ(2, epilogue1);
  CHECK_EQ(1, prologue2);
  CHECK_EQ(1, epilogue2);
  context->GetIsolate()->RemoveGCPrologueCallback(PrologueCallbackNew,
                                                  &prologue1);
  context->GetIsolate()->RemoveGCEpilogueCallback(EpilogueCallbackNew,
                                                  &epilogue1);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue1);
  CHECK_EQ(2, epilogue1);
  CHECK_EQ(2, prologue2);
  CHECK_EQ(2, epilogue2);
  context->GetIsolate()->RemoveGCPrologueCallback(PrologueCallbackNew,
                                                  &prologue2);
  context->GetIsolate()->RemoveGCEpilogueCallback(EpilogueCallbackNew,
                                                  &epilogue2);
  i::heap::InvokeMajorGC(CcTest::heap());
  CHECK_EQ(2, prologue1);
  CHECK_EQ(2, epilogue1);
  CHECK_EQ(2, prologue2);
  CHECK_EQ(2, epilogue2);
}

TEST(ContainsOnlyOneByte) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  // Make a buffer long enough that it won't automatically be converted.
  const int length = 512;
  // Ensure word aligned assignment.
  const int aligned_length = length*sizeof(uintptr_t)/sizeof(uint16_t);
  std::unique_ptr<uintptr_t[]> aligned_contents(new uintptr_t[aligned_length]);
  uint16_t* string_contents =
      reinterpret_cast<uint16_t*>(aligned_contents.get());
  // Set to contain only one byte.
  for (int i = 0; i < length-1; i++) {
    string_contents[i] = 0x41;
  }
  string_contents[length-1] = 0;
  // Simple case.
  Local<String> string =
      String::NewExternalTwoByte(
          isolate, new TestResource(string_contents, nullptr, false))
          .ToLocalChecked();
  CHECK(!string->IsOneByte() && string->ContainsOnlyOneByte());
  // Counter example.
  string = String::NewFromTwoByte(isolate, string_contents).ToLocalChecked();
  CHECK(string->IsOneByte() && string->ContainsOnlyOneByte());
  // Test left right and balanced cons strings.
  Local<String> base = v8_str("a");
  Local<String> left = base;
  Local<String> right = base;
  for (int i = 0; i < 1000; i++) {
    left = String::Concat(isolate, base, left);
    right = String::Concat(isolate, right, base);
  }
  Local<String> balanced = String::Concat(isolate, left, base);
  balanced = String::Concat(isolate, balanced, right);
  Local<String> cons_strings[] = {left, balanced, right};
  Local<String> two_byte =
      String::NewExternalTwoByte(
          isolate, new TestResource(string_contents, nullptr, false))
          .ToLocalChecked();
  USE(two_byte); USE(cons_strings);
  for (size_t i = 0; i < arraysize(cons_strings); i++) {
    // Base assumptions.
    string = cons_strings[i];
    CHECK(string->IsOneByte() && string->ContainsOnlyOneByte());
    // Test left and right concatentation.
    string = String::Concat(isolate, two_byte, cons_strings[i]);
    CHECK(!string->IsOneByte() && string->ContainsOnlyOneByte());
    string = String::Concat(isolate, cons_strings[i], two_byte);
    CHECK(!string->IsOneByte() && string->ContainsOnlyOneByte());
  }
  // Set bits in different positions
  // for strings of different lengths and alignments.
  for (int alignment = 0; alignment < 7; alignment++) {
    for (int size = 2; alignment + size < length; size *= 2) {
      int zero_offset = size + alignment;
      string_contents[zero_offset] = 0;
      for (int i = 0; i < size; i++) {
        int shift = 8 + (i % 7);
        string_contents[alignment + i] = 1 << shift;
        string = String::NewExternalTwoByte(
                     isolate, new TestResource(string_contents + alignment,
                                               nullptr, false))
                     .ToLocalChecked();
        CHECK_EQ(size, string->Length());
        CHECK(!string->ContainsOnlyOneByte());
        string_contents[alignment + i] = 0x41;
      }
      string_contents[zero_offset] = 0x41;
    }
  }
}

// Failed access check callback that performs a GC on each invocation.
void FailedAccessCheckCallbackGC(Local<v8::Object> target,
                                 v8::AccessType type,
                                 Local<v8::Value> data) {
  i::heap::InvokeMajorGC(CcTest::heap());
  CcTest::isolate()->ThrowException(
      v8::Exception::Error(v8_str("cross context")));
}


TEST(GCInFailedAccessCheckCallback) {
  // Install a failed access check callback that performs a GC on each
  // invocation. Then force the callback to be called from va
  v8::Isolate* isolate = CcTest::isolate();

  isolate->SetFailedAccessCheckCallbackFunction(&FailedAccessCheckCallbackGC);

  v8::HandleScope scope(isolate);

  // Create an ObjectTemplate for global objects and install access
  // check callbacks that will block access.
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(AccessAlwaysBlocked);

  // Create a context and set an x property on it's global object.
  LocalContext context0(nullptr, global_template);
  CHECK(context0->Global()
            ->Set(context0.local(), v8_str("x"), v8_num(42))
            .FromJust());
  v8::Local<v8::Object> global0 = context0->Global();

  // Create a context with a different security token so that the
  // failed access check callback will be called on each access.
  LocalContext context1(nullptr, global_template);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("other"), global0)
            .FromJust());

  v8::TryCatch try_catch(isolate);

  // Get property with failed access check.
  CHECK(CompileRun("other.x").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Get element with failed access check.
  CHECK(CompileRun("other[0]").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Set property with failed access check.
  CHECK(CompileRun("other.x = new Object()").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Set element with failed access check.
  CHECK(CompileRun("other[0] = new Object()").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Get property attribute with failed access check.
  CHECK(CompileRun("\'x\' in other").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Get property attribute for element with failed access check.
  CHECK(CompileRun("0 in other").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Delete property.
  CHECK(CompileRun("delete other.x").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Delete element.
  CHECK(global0->Delete(context1.local(), 0).IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // DefineAccessor.
  CHECK(global0
            ->SetNativeDataProperty(context1.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("x"))
            .IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Define JavaScript accessor.
  CHECK(CompileRun(
            "Object.prototype.__defineGetter__.call("
            "    other, \'x\', function() { return 42; })").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // LookupAccessor.
  CHECK(CompileRun(
            "Object.prototype.__lookupGetter__.call("
            "    other, \'x\')").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // HasOwnElement.
  CHECK(CompileRun(
            "Object.prototype.hasOwnProperty.call("
            "other, \'0\')").IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(global0->HasRealIndexedProperty(context1.local(), 0).IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(
      global0->HasRealNamedProperty(context1.local(), v8_str("x")).IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(global0->HasRealNamedCallbackProperty(context1.local(), v8_str("x"))
            .IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  // Reset the failed access check callback so it does not influence
  // the other tests.
  isolate->SetFailedAccessCheckCallbackFunction(nullptr);
}


TEST(IsolateNewDispose) {
  v8::Isolate* current_isolate = CcTest::isolate();
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  CHECK_NOT_NULL(isolate);
  CHECK(current_isolate != isolate);
  CHECK(current_isolate == CcTest::isolate());
  CHECK(isolate->GetArrayBufferAllocator() == CcTest::array_buffer_allocator());

  isolate->SetFatalErrorHandler(StoringErrorCallback);
  last_location = last_message = nullptr;
  isolate->Dispose();
  CHECK(!last_location);
  CHECK(!last_message);
}


UNINITIALIZED_TEST(DisposeIsolateWhenInUse) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope scope(isolate);
    LocalContext context(isolate);
    // Run something in this isolate.
    ExpectTrue("true");
    isolate->SetFatalErrorHandler(StoringErrorCallback);
    last_location = last_message = nullptr;
    // Still entered, should fail.
    isolate->Dispose();
    CHECK(last_location);
    CHECK(last_message);
  }
  isolate->Dispose();
}


static void BreakArrayGuarantees(const char* script) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);
  isolate1->Enter();
  v8::Persistent<v8::Context> context1;
  {
    v8::HandleScope scope(isolate1);
    context1.Reset(isolate1, Context::New(isolate1));
  }

  {
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate1, context1);
    v8::Context::Scope context_scope(context);
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate1);
    CHECK(i::Protectors::IsNoElementsIntact(i_isolate));
    // Run something in new isolate.
    CompileRun(script);
    CHECK(!i::Protectors::IsNoElementsIntact(i_isolate));
  }
  isolate1->Exit();
  isolate1->Dispose();
}


TEST(VerifyArrayPrototypeGuarantees) {
  // Break fast array hole handling by element changes.
  BreakArrayGuarantees("[].__proto__[1] = 3;");
  BreakArrayGuarantees("Object.prototype[3] = 'three';");
  BreakArrayGuarantees("Array.prototype.push(1);");
  BreakArrayGuarantees("Array.prototype.unshift(1);");
  // Break fast array hole handling by changing length.
  BreakArrayGuarantees("Array.prototype.length = 30;");
  // Break fast array hole handling by prototype structure changes.
  BreakArrayGuarantees("[].__proto__.__proto__ = { funny: true };");
  // By sending elements to dictionary mode.
  BreakArrayGuarantees(
      "Object.defineProperty(Array.prototype, 0, {"
      "  get: function() { return 3; }});");
  BreakArrayGuarantees(
      "Object.defineProperty(Object.prototype, 0, {"
      "  get: function() { return 3; }});");
}


TEST(RunTwoIsolatesOnSingleThread) {
  // Run isolate 1.
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate1 = v8::Isolate::New(create_params);

  CHECK(CcTest::isolate()->IsCurrent());
  CHECK(!isolate1->IsCurrent());

  isolate1->Enter();
  CHECK(!CcTest::isolate()->IsCurrent());
  CHECK(isolate1->IsCurrent());

  CHECK_EQ(isolate1, v8::Isolate::GetCurrent());
  CHECK_EQ(isolate1, v8::Isolate::TryGetCurrent());

  v8::Persistent<v8::Context> context1;
  {
    v8::HandleScope scope(isolate1);
    context1.Reset(isolate1, Context::New(isolate1));
  }

  {
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate1, context1);
    v8::Context::Scope context_scope(context);
    // Run something in new isolate.
    CompileRun("var foo = 'isolate 1';");
    ExpectString("function f() { return foo; }; f()", "isolate 1");
  }

  // Run isolate 2.
  v8::Isolate* isolate2 = v8::Isolate::New(create_params);
  v8::Persistent<v8::Context> context2;

  CHECK(!CcTest::isolate()->IsCurrent());
  CHECK(isolate1->IsCurrent());
  CHECK(!isolate2->IsCurrent());
  {
    v8::Isolate::Scope iscope(isolate2);
    CHECK(!isolate1->IsCurrent());
    CHECK(isolate2->IsCurrent());
    CHECK_EQ(isolate2, v8::Isolate::GetCurrent());
    CHECK_EQ(isolate2, v8::Isolate::TryGetCurrent());

    v8::HandleScope scope(isolate2);
    context2.Reset(isolate2, Context::New(isolate2));
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate2, context2);
    v8::Context::Scope context_scope(context);

    // Run something in new isolate.
    CompileRun("var foo = 'isolate 2';");
    ExpectString("function f() { return foo; }; f()", "isolate 2");
  }

  CHECK(!CcTest::isolate()->IsCurrent());
  CHECK(isolate1->IsCurrent());
  CHECK(!isolate2->IsCurrent());

  {
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate1, context1);
    v8::Context::Scope context_scope(context);
    // Now again in isolate 1
    ExpectString("function f() { return foo; }; f()", "isolate 1");
  }

  isolate1->Exit();
  CHECK(CcTest::isolate()->IsCurrent());
  CHECK(!isolate1->IsCurrent());
  CHECK(!isolate2->IsCurrent());

  // Run some stuff in default isolate.
  v8::Persistent<v8::Context> context_default;
  {
    v8::Isolate* isolate = CcTest::isolate();
    CHECK_EQ(isolate, v8::Isolate::GetCurrent());
    CHECK_EQ(isolate, v8::Isolate::TryGetCurrent());
    v8::Isolate::Scope iscope(isolate);
    v8::HandleScope scope(isolate);
    context_default.Reset(isolate, Context::New(isolate));
  }

  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(CcTest::isolate(), context_default);
    v8::Context::Scope context_scope(context);
    // Variables in other isolates should be not available, verify there
    // is an exception.
    ExpectTrue("function f() {"
               "  try {"
               "    foo;"
               "    return false;"
               "  } catch(e) {"
               "    return true;"
               "  }"
               "};"
               "var isDefaultIsolate = true;"
               "f()");
  }

  isolate1->Enter();

  {
    v8::Isolate::Scope iscope(isolate2);
    v8::HandleScope scope(isolate2);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate2, context2);
    v8::Context::Scope context_scope(context);
    ExpectString("function f() { return foo; }; f()", "isolate 2");
  }

  {
    v8::HandleScope scope(isolate1);
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(isolate1, context1);
    v8::Context::Scope context_scope(context);
    ExpectString("function f() { return foo; }; f()", "isolate 1");
  }

  {
    v8::Isolate::Scope iscope(isolate2);
    context2.Reset();
  }

  context1.Reset();
  isolate1->Exit();

  isolate2->SetFatalErrorHandler(StoringErrorCallback);
  last_location = last_message = nullptr;

  isolate1->Dispose();
  CHECK(!last_location);
  CHECK(!last_message);

  isolate2->Dispose();
  CHECK(!last_location);
  CHECK(!last_message);

  // Check that default isolate still runs.
  {
    v8::HandleScope scope(CcTest::isolate());
    v8::Local<v8::Context> context =
        v8::Local<v8::Context>::New(CcTest::isolate(), context_default);
    v8::Context::Scope context_scope(context);
    ExpectTrue("function f() { return isDefaultIsolate; }; f()");
  }
}


static int CalcFibonacci(v8::Isolate* isolate, int limit) {
  v8::Isolate::Scope isolate_scope(isolate);
  v8::HandleScope scope(isolate);
  LocalContext context(isolate);
  v8::base::ScopedVector<char> code(1024);
  v8::base::SNPrintF(code,
                     "function fib(n) {"
                     "  if (n <= 2) return 1;"
                     "  return fib(n-1) + fib(n-2);"
                     "}"
                     "fib(%d)",
                     limit);
  Local<Value> value = CompileRun(code.begin());
  CHECK(value->IsNumber());
  return static_cast<int>(value->NumberValue(context.local()).FromJust());
}

class IsolateThread : public v8::base::Thread {
 public:
  explicit IsolateThread(int fib_limit)
      : Thread(Options("IsolateThread")), fib_limit_(fib_limit), result_(0) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    result_ = CalcFibonacci(isolate, fib_limit_);
    isolate->Dispose();
  }

  int result() { return result_; }

 private:
  int fib_limit_;
  int result_;
};


TEST(MultipleIsolatesOnIndividualThreads) {
  IsolateThread thread1(21);
  IsolateThread thread2(12);

  // Compute some fibonacci numbers on 3 threads in 3 isolates.
  CHECK(thread1.Start());
  CHECK(thread2.Start());

  int result1 = CalcFibonacci(CcTest::isolate(), 21);
  int result2 = CalcFibonacci(CcTest::isolate(), 12);

  thread1.Join();
  thread2.Join();

  // Compare results. The actual fibonacci numbers for 12 and 21 are taken
  // (I'm lazy!) from http://en.wikipedia.org/wiki/Fibonacci_number
  CHECK_EQ(result1, 10946);
  CHECK_EQ(result2, 144);
  CHECK_EQ(result1, thread1.result());
  CHECK_EQ(result2, thread2.result());
}


TEST(IsolateDifferentContexts) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  Local<v8::Context> context;
  {
    v8::Iso
```