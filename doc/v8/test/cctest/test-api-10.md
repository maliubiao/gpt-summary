Response: The user wants me to summarize the functionality of the C++ code provided, which is a part of the V8 JavaScript engine's test suite. I should identify the features being tested and if they relate to JavaScript, illustrate with JavaScript examples. The user also points out this is part 11 of 18, which might suggest that there are similar tests in other parts focusing on different API aspects.

My plan is to go through each `TEST` and `THREADED_TEST` block, determine the V8 API being tested, and if applicable, provide a corresponding JavaScript example that would utilize that API or demonstrate the JavaScript feature that the C++ code is verifying.
这个C++代码文件 `v8/test/cctest/test-api.cc` 的第11部分主要测试了V8 JavaScript引擎的以下API功能和行为：

1. **`Function::GetBoundFunction()`**:  测试获取由 `bind()` 方法创建的绑定函数原始函数的能力。
   ```javascript
   var a = { x: 1 };
   function f() { return this.x; }
   var g = f.bind(a); // g 是 f 绑定到 a 的新函数
   console.log(g.prototype === undefined); // 绑定函数没有 prototype 属性
   ```

2. **`Function::FunctionProtoToString()`**: 测试在 `Function.prototype.toString` 被自定义修改后，仍然能够获取函数原始定义的字符串表示。这确保了V8内部获取函数字符串表示时不依赖于用户可修改的 `toString` 方法。
   ```javascript
   Function.prototype.toString = function() { return 'customized toString'; };
   function testFunction() { return 7; }
   console.log(testFunction.toString()); // 输出 "customized toString"
   // V8 内部的 FunctionProtoToString 仍然能获取 "function testFunction() { return 7; }"
   ```

3. **`ObjectTemplate::SetNativeDataProperty()` 和属性访问回调 (getter/setter)**：测试在构造函数原型上使用 `SetNativeDataProperty` 设置原生属性，并定义 getter 和 setter 回调函数。验证当通过原型链访问这些属性时，getter 和 setter 的行为是否符合预期。
   ```javascript
   function C1() {
     this.x = 23; // 触发原型上的 setter
   }
   // 假设原型 P 是通过 C++ API 创建的，并设置了 x 的 getter 和 setter
   C1.prototype = P;
   var c1 = new C1();
   console.log(c1.x); // 触发原型上的 getter
   console.log(c1.y); // setter 可能会修改 this 对象的 y 属性
   ```

4. **`ObjectTemplate::SetHandler()` 和命名属性拦截器 (getter/setter)**：测试在构造函数原型上使用 `SetHandler` 设置命名属性拦截器，定义 getter 和 setter 拦截函数。验证当访问这些属性时，拦截器的行为是否符合预期。
   ```javascript
   function C1() {
     this.x = 23; // 触发原型上的 setter 拦截器
   }
   // 假设原型 P 是通过 C++ API 创建的，并设置了 x 的 getter 和 setter 拦截器
   C1.prototype = P;
   var c1 = new C1();
   console.log(c1.x); // 触发原型上的 getter 拦截器
   console.log(c1.y); // setter 拦截器可能会修改 this 对象的 y 属性
   ```

5. **回归测试 (Regress618)**：测试当构造函数的原型在首次编译后被修改为具有访问器属性的对象时，实例的属性访问是否仍然正确。这涉及到 V8 的编译缓存和对象布局优化。
   ```javascript
   function C1() {
     this.x = 23;
   }
   // 首次使用简单对象作为原型
   C1.prototype = { y: 42 };
   var c1_1 = new C1();
   console.log(c1_1.x);
   console.log(c1_1.y);

   // 之后使用具有访问器属性的对象作为原型
   // 假设 P 是通过 C++ API 创建的，并设置了 x 的 getter 和 setter
   C1.prototype = P;
   var c1_2 = new C1();
   console.log(c1_2.x); // 应该触发 P 上的 getter
   console.log(c1_2.y); // 应该触发 P 上的 setter 并可能修改 c1_2 的 y
   ```

6. **垃圾回收回调 (GCCallbacksOld, GCCallbacksWithData)**：测试在垃圾回收的不同阶段注册和移除回调函数的功能，包括携带额外数据的回调。
   ```javascript
   // 无法直接在 JavaScript 中设置 V8 的垃圾回收回调
   // 这是 V8 引擎内部的机制，C++ API 提供了管理这些回调的能力
   ```

7. **字符串 `ContainsOnlyOneByte()`**: 测试字符串是否只包含单字节字符的能力。这与 V8 内部的字符串表示优化有关。
   ```javascript
   var str1 = "hello"; // 通常是单字节字符串
   var str2 = "你好";  // 通常是双字节字符串
   // V8 内部会判断字符串是否只包含单字节字符以进行优化
   ```

8. **失败访问检查回调中的垃圾回收 (GCInFailedAccessCheckCallback)**：测试在跨上下文访问受限对象时，失败的访问检查回调函数中执行垃圾回收是否会导致问题。
   ```javascript
   // 这涉及到 V8 的安全模型和跨上下文访问控制
   // 无法直接通过 JavaScript 模拟，需要在 C++ 中设置访问检查
   ```

9. **`Isolate::New()` 和 `Isolate::Dispose()`**: 测试创建和销毁 V8 隔离环境的功能。每个隔离环境都有其独立的堆和执行状态。
   ```javascript
   // 无法直接在 JavaScript 中创建和销毁 V8 隔离环境
   // 这是 V8 引擎的顶层概念，通过 C++ API 进行管理
   ```

10. **在使用的隔离环境上调用 `DisposeIsolateWhenInUse`**: 测试在隔离环境正在执行代码时尝试销毁它是否会产生错误。
    ```javascript
    // 同样，无法直接在 JavaScript 中控制隔离环境的生命周期
    ```

11. **破坏数组原型保证 (VerifyArrayPrototypeGuarantees)**：测试修改 `Array.prototype` 的各种方式是否会破坏 V8 引擎对数组的优化假设。
    ```javascript
    Array.prototype[1] = 3; // 修改 Array.prototype
    Object.prototype[3] = 'three'; // 修改 Object.prototype
    Array.prototype.push(1); // 修改 Array.prototype
    Array.prototype.length = 30; // 修改 Array.prototype 的 length 属性
    // 这些操作可能会影响 V8 引擎对数组的优化
    ```

12. **在单线程上运行两个隔离环境 (RunTwoIsolatesOnSingleThread)**：测试在同一个线程上创建和运行多个独立的 V8 隔离环境，确保它们之间的状态隔离。
    ```javascript
    // JavaScript 本身运行在一个 V8 隔离环境中
    // 在 JavaScript 中无法直接创建和管理多个隔离环境
    ```

13. **多线程上运行多个隔离环境 (MultipleIsolatesOnIndividualThreads)**：测试在不同的线程上创建和运行独立的 V8 隔离环境，验证多线程环境下的隔离性。
    ```javascript
    // 同样，JavaScript 无法直接控制 V8 的线程和隔离环境
    ```

14. **不同隔离环境的不同上下文 (IsolateDifferentContexts)**：测试在同一个隔离环境中创建多个上下文，并确保它们之间的状态隔离。
    ```javascript
    // JavaScript 代码在一个上下文中执行
    // 可以通过 C++ API 在同一个隔离环境中创建多个上下文
    ```

15. **在辅助线程上初始化默认隔离环境 (InitializeDefaultIsolateOnSecondaryThread_...)**: 测试在非主线程上初始化 V8 默认隔离环境时设置某些配置项是否安全。
    ```javascript
    // 涉及到 V8 引擎的初始化和线程安全
    ```

16. **跨多个上下文的字符串、数字、布尔值检查 (StringCheckMultipleContexts, NumberCheckMultipleContexts, BooleanCheckMultipleContexts)**：测试在不同的上下文中修改内置对象的原型后，代码的执行是否会受到影响，确保 V8 正确处理跨上下文的对象和原型链。
    ```javascript
    // 上下文 1
    String.prototype.charAt = function() { return "a"; };
    "test".charAt(0); // 输出 "a"

    // 上下文 2
    String.prototype.charAt = function() { return "b"; };
    "test".charAt(0); // 输出 "b"
    ```

17. **不删除单元格的加载 IC (DontDeleteCellLoadIC)**：测试对于标记为不可删除的全局变量，其加载 IC (Inline Cache) 的行为是否正确。
    ```javascript
    var cell = "first";
    delete cell; // 返回 false，cell 不可删除
    function readCell() { return cell; }
    readCell(); // 返回 "first"
    ```

18. **包装器类 ID (WrapperClassId)**：测试为 V8 对象设置和获取包装器类 ID 的功能。这通常用于区分不同类型的 C++ 绑定对象。
    ```javascript
    // JavaScript 对象可以通过 C++ API 关联一个包装器类 ID
    // 这个 ID 在 JavaScript 中不可直接访问
    ```

19. **正则表达式 (RegExp)**：测试 `v8::RegExp` 类的各种功能，包括创建、获取源字符串和标志等。
    ```javascript
    var re1 = /foo/;
    var re2 = new RegExp("bar", "i");
    console.log(re1.source); // "foo"
    console.log(re2.flags);  // "i"
    ```

20. **`Value::Equals()`**: 测试 V8 中 `Value` 对象的相等性比较，包括严格相等和非严格相等。
    ```javascript
    var global1 = this;
    var global2 = globalThis;
    console.log(global1 === global2); // true (严格相等)
    console.log(global1 == global2);  // true (非严格相等)
    ```

21. **命名属性枚举器和 `for...in` 循环 (NamedEnumeratorAndForIn)**：测试通过 C++ API 定义命名属性枚举器后，`for...in` 循环的行为是否符合预期。
    ```javascript
    // 假设 o 是通过 C++ API 创建的对象，并设置了命名属性枚举器
    for (var k in o) {
      console.log(k); // 应该只输出枚举器返回的属性
    }
    ```

22. **脱离上下文后定义属性 (DefinePropertyPostDetach)**：测试在全局上下文脱离当前作用域后，是否仍然可以向全局对象定义属性。
    ```javascript
    // 涉及到 V8 的上下文管理和全局对象的生命周期
    ```

23. **创建上下文 (CreationContext)**：测试如何获取 V8 对象的创建上下文。
    ```javascript
    // JavaScript 对象在创建时会关联一个创建上下文
    // 可以通过 C++ API 获取这个上下文
    ```

24. **JavaScript 函数的创建上下文 (CreationContextOfJsFunction)**：测试如何获取 JavaScript 函数的创建上下文。
    ```javascript
    function foo() {} // 在当前上下文中创建
    // 可以通过 C++ API 获取函数 foo 的创建上下文
    ```

25. **JavaScript 绑定函数的创建上下文 (CreationContextOfJsBoundFunction)**：测试如何获取 JavaScript 绑定函数的创建上下文。
    ```javascript
    function foo() {}
    var boundFoo = foo.bind(null); // 在当前上下文中创建绑定函数
    // 可以通过 C++ API 获取 boundFoo 的创建上下文
    ```

26. **`Object::HasOwnProperty()` 和属性拦截器/回调**: 测试 `HasOwnProperty` 方法在存在属性拦截器和访问器回调时的行为。
    ```javascript
    var obj = { foo: 1 };
    console.log(obj.hasOwnProperty('foo')); // true

    // 假设 obj 通过 C++ API 设置了属性拦截器或回调
    console.log(obj.hasOwnProperty('bar')); // 可能受拦截器影响
    ```

27. **带有字符串原型的索引拦截器 (IndexedInterceptorWithStringProto)**：测试当对象的原型是字符串对象时，索引属性拦截器的行为。
    ```javascript
    var obj = {};
    obj.__proto__ = new String("foobar");
    // 假设 obj 通过 C++ API 设置了索引属性拦截器
    console.log(42 in obj); // 可能被拦截器处理
    console.log(0 in obj);  // 应该访问字符串原型
    ```

28. **允许/禁止从字符串生成代码 (AllowCodeGenFromStrings)**：测试控制 `eval` 和 `Function` 构造函数是否可用的功能。
    ```javascript
    eval("2 + 2"); // 默认允许
    var f = new Function("return 2 + 2"); // 默认允许

    // 通过 C++ API 禁止后
    // eval("2 + 2"); // 抛出异常
    // var f = new Function("return 2 + 2"); // 抛出异常
    ```

总而言之，这部分代码主要关注 V8 引擎中关于函数、对象属性（包括原生属性和拦截器）、垃圾回收、隔离环境、上下文、字符串处理、正则表达式以及代码生成控制等方面的 C++ API 测试。这些测试确保了 V8 引擎的各项核心功能能够按照预期工作，并且在各种复杂场景下保持稳定和安全。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第11部分，共18部分，请归纳一下它的功能
```

### 源代码
```
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
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("2");
    CHECK(v->IsNumber());
    CHECK_EQ(2, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    context = v8::Context::New(isolate);
    v8::Context::Scope context_scope(context);
    Local<Value> v = CompileRun("22");
    CHECK(v->IsNumber());
    CHECK_EQ(22, static_cast<int>(v->NumberValue(context).FromJust()));
  }
  isolate->Dispose();
}

class InitDefaultIsolateThread : public v8::base::Thread {
 public:
  enum TestCase {
    SetFatalHandler,
    SetCounterFunction,
    SetCreateHistogramFunction,
    SetAddHistogramSampleFunction
  };

  explicit InitDefaultIsolateThread(TestCase testCase)
      : Thread(Options("InitDefaultIsolateThread")),
        testCase_(testCase),
        result_(false) {}

  void Run() override {
    v8::Isolate::CreateParams create_params;
    create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
    v8::Isolate* isolate = v8::Isolate::New(create_params);
    isolate->Enter();
    switch (testCase_) {
      case SetFatalHandler:
        isolate->SetFatalErrorHandler(nullptr);
        break;

      case SetCounterFunction:
        CcTest::isolate()->SetCounterFunction(nullptr);
        break;

      case SetCreateHistogramFunction:
        CcTest::isolate()->SetCreateHistogramFunction(nullptr);
        break;

      case SetAddHistogramSampleFunction:
        CcTest::isolate()->SetAddHistogramSampleFunction(nullptr);
        break;
    }
    isolate->Exit();
    isolate->Dispose();
    result_ = true;
  }

  bool result() { return result_; }

 private:
  TestCase testCase_;
  bool result_;
};


static void InitializeTestHelper(InitDefaultIsolateThread::TestCase testCase) {
  InitDefaultIsolateThread thread(testCase);
  CHECK(thread.Start());
  thread.Join();
  CHECK(thread.result());
}

TEST(InitializeDefaultIsolateOnSecondaryThread_FatalHandler) {
  InitializeTestHelper(InitDefaultIsolateThread::SetFatalHandler);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CounterFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCounterFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_CreateHistogramFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetCreateHistogramFunction);
}

TEST(InitializeDefaultIsolateOnSecondaryThread_AddHistogramSampleFunction) {
  InitializeTestHelper(InitDefaultIsolateThread::SetAddHistogramSampleFunction);
}


TEST(StringCheckMultipleContexts) {
  const char* code =
      "(function() { return \"a\".charAt(0); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "a");
    ExpectString(code, "a");
  }

  {
    // Change the String.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("String.prototype.charAt = function() { return \"not a\"; }");
    ExpectString(code, "not a");
  }
}


TEST(NumberCheckMultipleContexts) {
  const char* code =
      "(function() { return (42).toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "42");
    ExpectString(code, "42");
  }

  {
    // Change the Number.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Number.prototype.toString = function() { return \"not 42\"; }");
    ExpectString(code, "not 42");
  }
}


TEST(BooleanCheckMultipleContexts) {
  const char* code =
      "(function() { return true.toString(); })()";

  {
    // Run the code twice in the first context to initialize the call IC.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    ExpectString(code, "true");
    ExpectString(code, "true");
  }

  {
    // Change the Boolean.prototype in the second context and check
    // that the right function gets called.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("Boolean.prototype.toString = function() { return \"\"; }");
    ExpectString(code, "");
  }
}


TEST(DontDeleteCellLoadIC) {
  const char* function_code =
      "function readCell() { while (true) { return cell; } }";

  {
    // Run the code twice in the first context to initialize the load
    // IC for a don't delete cell.
    LocalContext context1;
    v8::HandleScope scope(context1->GetIsolate());
    CompileRun("var cell = \"first\";");
    ExpectBoolean("delete cell", false);
    CompileRun(function_code);
    ExpectString("readCell()", "first");
    ExpectString("readCell()", "first");
  }

  {
    // Use a deletable cell in the second context.
    LocalContext context2;
    v8::HandleScope scope(context2->GetIsolate());
    CompileRun("cell = \"second\";");
    CompileRun(function_code);
    ExpectString("readCell()", "second");
    ExpectBoolean("delete cell", true);
    ExpectString("(function() {"
                 "  try {"
                 "    return readCell();"
                 "  } catch(e) {"
                 "    return e.toString();"
                 "  }"
                 "})()",
                 "ReferenceError: cell is not defined");
    CompileRun("cell = \"new_second\";");
    i::heap::InvokeMajorGC(CcTest::heap());
    ExpectString("readCell()", "new_second");
    ExpectString("readCell()", "new_second");
  }
}

TEST(WrapperClassId) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Persistent<v8::Object> object(isolate, v8::Object::New(isolate));
  CHECK_EQ(0, object.WrapperClassId());
  object.SetWrapperClassId(65535);
  CHECK_EQ(65535, object.WrapperClassId());
  object.Reset();
}

TEST(RegExp) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  v8::Local<v8::RegExp> re =
      v8::RegExp::New(context.local(), v8_str("foo"), v8::RegExp::kNone)
          .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foo")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foo/bar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foo\\/bar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("bar"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kGlobal))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("bar")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kGlobal,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  re = v8::RegExp::New(context.local(), v8_str("baz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kUnicode |
                                                      v8::RegExp::kSticky))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("baz")).FromJust());
  CHECK_EQ(v8::RegExp::kUnicode | v8::RegExp::kSticky,
           static_cast<int>(re->GetFlags()));

  re = CompileRun("/quux/").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("RegExp('qu/ux')").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("qu\\/ux")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = CompileRun("/quux/gm").As<v8::RegExp>();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("quux")).FromJust());
  CHECK_EQ(v8::RegExp::kGlobal | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  // Override the RegExp constructor and check the API constructor
  // still works.
  CompileRun("RegExp = function() {}");

  re = v8::RegExp::New(context.local(), v8_str("foobar"), v8::RegExp::kNone)
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(re->GetSource()->Equals(context.local(), v8_str("foobar")).FromJust());
  CHECK_EQ(v8::RegExp::kNone, re->GetFlags());

  re = v8::RegExp::New(context.local(), v8_str("foobarbaz"),
                       static_cast<v8::RegExp::Flags>(v8::RegExp::kIgnoreCase |
                                                      v8::RegExp::kMultiline))
           .ToLocalChecked();
  CHECK(re->IsRegExp());
  CHECK(
      re->GetSource()->Equals(context.local(), v8_str("foobarbaz")).FromJust());
  CHECK_EQ(v8::RegExp::kIgnoreCase | v8::RegExp::kMultiline,
           static_cast<int>(re->GetFlags()));

  CHECK(context->Global()->Set(context.local(), v8_str("re"), re).FromJust());
  ExpectTrue("re.test('FoobarbaZ')");

  // RegExps are objects on which you can set properties.
  re->Set(context.local(), v8_str("property"),
          v8::Integer::New(context->GetIsolate(), 32))
      .FromJust();
  v8::Local<v8::Value> value(CompileRun("re.property"));
  CHECK_EQ(32, value->Int32Value(context.local()).FromJust());

  {
    v8::TryCatch try_catch(context->GetIsolate());
    CHECK(v8::RegExp::New(context.local(), v8_str("foo["), v8::RegExp::kNone)
              .IsEmpty());
    CHECK(try_catch.HasCaught());
    CHECK(context->Global()
              ->Set(context.local(), v8_str("ex"), try_catch.Exception())
              .FromJust());
    ExpectTrue("ex instanceof SyntaxError");
  }

  // RegExp::Exec.
  {
    v8::Local<v8::RegExp> regexp =
        v8::RegExp::New(context.local(), v8_str("a.c"), {}).ToLocalChecked();
    v8::Local<v8::Object> result0 =
        regexp->Exec(context.local(), v8_str("abc")).ToLocalChecked();
    CHECK(result0->IsArray());
    v8::Local<v8::Object> result1 =
        regexp->Exec(context.local(), v8_str("abd")).ToLocalChecked();
    CHECK(result1->IsNull());
  }
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
START_ALLOW_USE_DEPRECATED()

THREADED_TEST(Equals) {
  LocalContext localContext;
  v8::HandleScope handleScope(localContext->GetIsolate());

  v8::Local<v8::Object> globalProxy = localContext->Global();
  v8::Local<Value> global = globalProxy->GetPrototype();

  CHECK(global->StrictEquals(global));
  CHECK(!global->StrictEquals(globalProxy));
  CHECK(!globalProxy->StrictEquals(global));
  CHECK(globalProxy->StrictEquals(globalProxy));

  CHECK(global->Equals(localContext.local(), global).FromJust());
  CHECK(!global->Equals(localContext.local(), globalProxy).FromJust());
  CHECK(!globalProxy->Equals(localContext.local(), global).FromJust());
  CHECK(globalProxy->Equals(localContext.local(), globalProxy).FromJust());
}

// Allow usages of v8::Object::GetPrototype() for now.
// TODO(https://crbug.com/333672197): remove.
END_ALLOW_USE_DEPRECATED()

namespace {
v8::Intercepted Getter(v8::Local<v8::Name> property,
                       const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("42!"));
  return v8::Intercepted::kYes;
}

void Enumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate());
  result->Set(info.GetIsolate()->GetCurrentContext(), 0,
              v8_str("universalAnswer"))
      .FromJust();
  info.GetReturnValue().Set(result);
}
}  // namespace

TEST(NamedEnumeratorAndForIn) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope handle_scope(isolate);
  v8::Context::Scope context_scope(context.local());

  v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
  tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Getter, nullptr, nullptr, nullptr, Enumerator));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  tmpl->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Array> result = v8::Local<v8::Array>::Cast(
      CompileRun("var result = []; for (var k in o) result.push(k); result"));
  CHECK_EQ(1u, result->Length());
  CHECK(v8_str("universalAnswer")
            ->Equals(context.local(),
                     result->Get(context.local(), 0).ToLocalChecked())
            .FromJust());
}


TEST(DefinePropertyPostDetach) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::Object> proxy = context->Global();
  v8::Local<v8::Function> define_property =
      CompileRun(
          "(function() {"
          "  Object.defineProperty("
          "    this,"
          "    1,"
          "    { configurable: true, enumerable: true, value: 3 });"
          "})")
          .As<Function>();
  context->DetachGlobal();
  CHECK(define_property->Call(context.local(), proxy, 0, nullptr).IsEmpty());
}


static void InstallContextId(v8::Local<Context> context, int id) {
  Context::Scope scope(context);
  CHECK(CompileRun("Object.prototype")
            .As<Object>()
            ->Set(context, v8_str("context_id"),
                  v8::Integer::New(context->GetIsolate(), id))
            .FromJust());
}


static void CheckContextId(v8::Local<Object> object, int expected) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_EQ(expected, object->Get(context, v8_str("context_id"))
                         .ToLocalChecked()
                         ->Int32Value(context)
                         .FromJust());
}


THREADED_TEST(CreationContext) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope handle_scope(isolate);
  Local<Context> context1 = Context::New(isolate);
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(isolate);
  InstallContextId(context2, 2);
  Local<Context> context3 = Context::New(isolate);
  InstallContextId(context3, 3);

  Local<v8::FunctionTemplate> tmpl = v8::FunctionTemplate::New(isolate);

  Local<Object> object1;
  Local<Function> func1;
  {
    Context::Scope scope(context1);
    object1 = Object::New(isolate);
    func1 = tmpl->GetFunction(context1).ToLocalChecked();
  }

  Local<Object> object2;
  Local<Function> func2;
  {
    Context::Scope scope(context2);
    object2 = Object::New(isolate);
    func2 = tmpl->GetFunction(context2).ToLocalChecked();
  }

  Local<Object> instance1;
  Local<Object> instance2;

  {
    Context::Scope scope(context3);
    instance1 = func1->NewInstance(context3).ToLocalChecked();
    instance2 = func2->NewInstance(context3).ToLocalChecked();
  }

  {
    Local<Context> other_context = Context::New(isolate);
    Context::Scope scope(other_context);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(object1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(object1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(func1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(func1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked() == context1);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance1->GetCreationContext(isolate).ToLocalChecked() == context1);
    CHECK(instance1->GetCreationContextChecked(isolate) == context1);
    CheckContextId(instance1, 1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(object2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(object2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(object2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(func2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(func2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(func2, 2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked() == context2);
    END_ALLOW_USE_DEPRECATED();
    CHECK(instance2->GetCreationContext(isolate).ToLocalChecked() == context2);
    CHECK(instance2->GetCreationContextChecked(isolate) == context2);
    CheckContextId(instance2, 2);
  }

  {
    Context::Scope scope(context1);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }

  {
    Context::Scope scope(context2);
    START_ALLOW_USE_DEPRECATED();
    CHECK(object1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(object1, 1);
    CHECK(func1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(func1, 1);
    CHECK(instance1->GetCreationContext().ToLocalChecked() == context1);
    CheckContextId(instance1, 1);
    CHECK(object2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(object2, 2);
    CHECK(func2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(func2, 2);
    CHECK(instance2->GetCreationContext().ToLocalChecked() == context2);
    CheckContextId(instance2, 2);
    END_ALLOW_USE_DEPRECATED();
  }
}


THREADED_TEST(CreationContextOfJsFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context = Context::New(CcTest::isolate());
  InstallContextId(context, 1);

  Local<Object> function;
  {
    Context::Scope scope(context);
    function = CompileRun("function foo() {}; foo").As<Object>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(function->GetCreationContext().ToLocalChecked() == context);
  END_ALLOW_USE_DEPRECATED();
  CheckContextId(function, 1);
}


THREADED_TEST(CreationContextOfJsBoundFunction) {
  HandleScope handle_scope(CcTest::isolate());
  Local<Context> context1 = Context::New(CcTest::isolate());
  InstallContextId(context1, 1);
  Local<Context> context2 = Context::New(CcTest::isolate());
  InstallContextId(context2, 2);

  Local<Function> target_function;
  {
    Context::Scope scope(context1);
    target_function = CompileRun("function foo() {}; foo").As<Function>();
  }

  Local<Function> bound_function1, bound_function2;
  {
    Context::Scope scope(context2);
    CHECK(context2->Global()
              ->Set(context2, v8_str("foo"), target_function)
              .FromJust());
    bound_function1 = CompileRun("foo.bind(1)").As<Function>();
    bound_function2 =
        CompileRun("Function.prototype.bind.call(foo, 2)").As<Function>();
  }

  Local<Context> other_context = Context::New(CcTest::isolate());
  Context::Scope scope(other_context);
  START_ALLOW_USE_DEPRECATED();
  CHECK(bound_function1->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function1, 1);
  CHECK(bound_function2->GetCreationContext().ToLocalChecked() == context1);
  CheckContextId(bound_function2, 1);
  END_ALLOW_USE_DEPRECATED();
}

v8::Intercepted HasOwnPropertyIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8_str("yes"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyIndexedPropertyQuery(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (index == 42) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted HasOwnPropertyNamedPropertyQuery2(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  if (property->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("bar"))
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void HasOwnPropertyAccessorGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
}

v8::Intercepted HasOwnPropertyAccessorNameGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(v8_str("yes"));
  return v8::Intercepted::kYes;
}

TEST(HasOwnProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  { // Check normal properties and defined getters.
    Local<Value> value = CompileRun(
        "function Foo() {"
        "    this.foo = 11;"
        "    this.__defineGetter__('baz', function() { return 1; });"
        "};"
        "function Bar() { "
        "    this.bar = 13;"
        "    this.__defineGetter__('bla', function() { return 2; });"
        "};"
        "Bar.prototype = new Foo();"
        "new Bar();");
    CHECK(value->IsObject());
    Local<Object> object = value->ToObject(env.local()).ToLocalChecked();
    CHECK(object->Has(env.local(), v8_str("foo")).FromJust());
    CHECK(!object->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(object->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
    CHECK(object->Has(env.local(), v8_str("baz")).FromJust());
    CHECK(!object->HasOwnProperty(env.local(), v8_str("baz")).FromJust());
    CHECK(object->HasOwnProperty(env.local(), v8_str("bla")).FromJust());
  }
  { // Check named getter interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyNamedPropertyGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check indexed getter interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
        HasOwnPropertyIndexedPropertyGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("43")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 43).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
  }
  { // Check named query interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, HasOwnPropertyNamedPropertyQuery));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check indexed query interceptors.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
        nullptr, nullptr, HasOwnPropertyIndexedPropertyQuery));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("42")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), 42).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("41")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), 41).FromJust());
  }
  { // Check callbacks.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetNativeDataProperty(v8_str("foo"), HasOwnPropertyAccessorGetter);
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  { // Check that query wins on disagreement.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyNamedPropertyGetter, nullptr,
        HasOwnPropertyNamedPropertyQuery2));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    CHECK(!instance->HasOwnProperty(env.local(), v8_str("foo")).FromJust());
    CHECK(instance->HasOwnProperty(env.local(), v8_str("bar")).FromJust());
  }
  {  // Check that non-internalized keys are handled correctly.
    Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
        HasOwnPropertyAccessorNameGetter));
    Local<Object> instance = templ->NewInstance(env.local()).ToLocalChecked();
    env->Global()->Set(env.local(), v8_str("obj"), instance).FromJust();
    const char* src =
        "var dyn_string = 'this string ';"
        "dyn_string += 'does not exist elsewhere';"
        "({}).hasOwnProperty.call(obj, dyn_string)";
    CHECK(CompileRun(src)->BooleanValue(isolate));
  }
}


TEST(IndexedInterceptorWithStringProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      nullptr, nullptr, HasOwnPropertyIndexedPropertyQuery));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("var s = new String('foobar'); obj.__proto__ = s;");
  // These should be intercepted.
  CHECK(CompileRun("42 in obj")->BooleanValue(isolate));
  CHECK(CompileRun("'42' in obj")->BooleanValue(isolate));
  // These should fall through to the String prototype.
  CHECK(CompileRun("0 in obj")->BooleanValue(isolate));
  CHECK(CompileRun("'0' in obj")->BooleanValue(isolate));
  // And these should both fail.
  CHECK(!CompileRun("32 in obj")->BooleanValue(isolate));
  CHECK(!CompileRun("'32' in obj")->BooleanValue(isolate));
}


void CheckCodeGenerationAllowed() {
  Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  Local<Value> result = CompileRun("eval('42')");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
  result = CompileRun("(function(e) { return e('42'); })(eval)");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
  result = CompileRun("var f = new Function('return 42'); f()");
  CHECK_EQ(42, result->Int32Value(context).FromJust());
}


void CheckCodeGenerationDisallowed() {
  TryCatch try_catch(CcTest::isolate());

  Local<Value> result = CompileRun("eval('42')");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("(function(e) { return e('42'); })(eval)");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("var f = new Function('return 42'); f()");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
}

char first_fourty_bytes[41];

v8::ModifyCodeGenerationFromStringsResult CodeGenerationAllowed(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  String::Utf8Value str(CcTest::isolate(), source);
  size_t len = std::min(sizeof(first_fourty_bytes) - 1,
                        static_cast<size_t>(str.length()));
  strncpy(first_fourty_bytes, *str, len);
  first_fourty_bytes[len] = 0;
  ApiTestFuzzer::Fuzz();
  return {true, {}};
}

v8::ModifyCodeGenerationFromStringsResult CodeGenerationDisallowed(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  ApiTestFuzzer::Fuzz();
  return {false, {}};
}

v8::ModifyCodeGenerationFromStringsResult ModifyCodeGeneration(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  // Allow (passthrough, unmodified) all objects that are not strings.
  if (!source->IsString()) {
    return {/* codegen_allowed= */ true, v8::MaybeLocal<String>()};
  }

  String::Utf8Value utf8(context->GetIsolate(), source);
  DCHECK_GT(utf8.length(), 0);

  // Allow (unmodified) all strings that contain "44".
  if (strstr(*utf8, "44") != nullptr) {
    return {/* codegen_allowed= */ true, v8::MaybeLocal<String>()};
  }

  // Deny all odd-length strings.
  if (utf8.length() == 0 || utf8.length() % 2 != 0) {
    return {/* codegen_allowed= */ false, v8::MaybeLocal<String>()};
  }

  // Allow even-length strings and modify them by replacing all '2' with '3'.
  for (char* i = *utf8; *i != '\0'; i++) {
    if (*i == '2') *i = '3';
  }
  return {/* codegen_allowed= */ true,
          String::NewFromUtf8(context->GetIsolate(), *utf8).ToLocalChecked()};
}

THREADED_TEST(AllowCodeGenFromStrings) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // eval and the Function constructor allowed by default.
  CHECK(context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationAllowed();

  // Disallow eval and the Function constructor.
  context->AllowCodeGenerationFromStrings(false);
  CHECK(!context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationDisallowed();

  // Allow again.
  context->AllowCodeGenerationFromStrings(true);
  CheckCodeGenerationAllowed();

  // Disallow but setting a global callback that will allow the calls.
  context->AllowCodeGenerationFromStrings(false);
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &CodeGenerationAllo
```