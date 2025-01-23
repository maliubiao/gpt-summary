Response: The user wants me to summarize the functionality of the C++ code snippet provided. I need to identify the main purpose of the code. The code seems to be testing the V8 JavaScript engine's C++ API. Specifically, it's testing various features related to:

1. **Object Templates and Native Properties:** How to define objects with native data and accessors.
2. **Context Management:** How different JavaScript contexts interact and how security tokens are applied.
3. **Prototype Chains Across Contexts:**  Ensuring that prototype modifications in one context don't leak to others.
4. **Undetectable Objects:** Testing the behavior of objects marked as undetectable in JavaScript.
5. **Void Literal:** Verifying the behavior of the `void 0` literal.
6. **Extensibility of Undetectable Objects:** Checking if properties can be added to and removed from undetectable objects.
7. **Constructor Calls with Undetectable Objects:**  Confirming that undetectable objects cannot be used as constructors.
8. **Function Templates and Constructors:** Testing how to create JavaScript constructors using function templates.
9. **Persistent Handles:** Demonstrating the basic usage of persistent handles for V8 objects.
10. **Global Object Templates:**  Testing the creation of contexts with custom global object templates.
11. **Extensions:**  Exploring different ways to register and use V8 extensions (with source code, without source code, with syntax errors, with exceptions, with native calls, with native functions).
12. **Extension Dependencies:**  Testing how extension loading order and dependencies work.
13. **Function Lookup in Extensions:**  Verifying how native functions declared in extensions are looked up.
14. **Construct Calls to Native Functions in Extensions:** Testing the ability to use native functions in extensions as constructors.
15. **Error Reporting:**  Testing V8's error handling mechanisms for circular extension dependencies.
16. **Dcheck Error Handler:** Demonstrating the usage of the DCHECK error handler.
17. **Error with Missing Script Info:** Testing error reporting when script information is not available.
18. **Weak Handles:**  Testing the behavior of weak handles and their callbacks under various GC scenarios.
19. **Arguments Object:**  Verifying the behavior of the `arguments` object in JavaScript functions.
20. **Property Getters and Holders:** Testing how property getters and their holders work in the prototype chain.
21. **Object Instantiation:**  Testing the creation of new object instances from templates.
22. **String Encoding and Decoding:**  Testing the `WriteUtf8` and `Write` methods for V8 strings, including handling of multi-byte characters and surrogate pairs.

This is the 5th part of 18 parts, suggesting that this file likely focuses on a specific subset of the V8 API. Based on the content, this section seems to heavily focus on **Contexts, Extensions, and Object Templates with Native Properties and Callbacks.**

For the JavaScript example, I can focus on the `SetNativeDataProperty` part, as that directly links C++ to JavaScript functionality.
这个C++代码文件（`v8/test/cctest/test-api.cc` 的第 5 部分，共 18 部分）主要用于测试 **V8 JavaScript 引擎的 C++ API** 中关于 **Context（上下文）、Extension（扩展）以及 Object Template（对象模板）和 Native Properties（原生属性）** 的功能。

具体来说，这部分代码测试了以下功能：

* **使用 `SetNativeDataProperty` 创建带有原生数据属性的对象:**  测试如何使用 C++ 代码在 JavaScript 对象上定义一个属性，该属性的行为由 C++ 函数控制。这包括设置 getter 函数，并在属性被访问或修改时执行 C++ 代码。

* **测试没有访问器的原生数据属性:** 验证当只设置了原生数据属性，而没有设置 getter/setter 时，该属性的行为。

* **多上下文环境的创建和隔离:** 测试在同一个 Isolate（V8 隔离区）中创建多个独立的 JavaScript 上下文，以及它们之间的隔离性，例如全局对象的独立性和安全令牌的作用。

* **跨上下文的函数原型隔离:**  确保在一个上下文中修改函数原型 (`__proto__`) 不会影响到其他上下文中的函数原型。

* **跨上下文的对象和数组字面量隔离:** 验证在不同上下文中创建的对象和数组字面量，它们的原型不会相互影响。

* **不可检测对象 (`MarkAsUndetectable`) 的行为:** 测试使用 `MarkAsUndetectable` 标记的对象在 JavaScript 中的各种行为，例如 `typeof` 操作符、条件判断、与 `null` 和 `undefined` 的比较等。

* **`void 0` 字面量的行为:** 验证 `void 0` 在 JavaScript 中的行为，并与不可检测对象进行比较。

* **不可检测对象的扩展性:**  测试是否可以向不可检测对象添加或删除属性。

* **使用不可检测对象进行构造函数调用:** 验证尝试将不可检测对象作为构造函数调用时会抛出 `TypeError`。

* **`SetCallAsFunctionHandler` 用于构造函数:**  测试如何使用 `SetCallAsFunctionHandler` 来定义一个可以作为构造函数调用的 C++ 函数。

* **持久句柄 (`Persistent`) 的基本使用:**  简单演示了持久句柄的创建和释放。

* **全局对象模板 (`GlobalObjectTemplate`) 的使用:** 测试使用自定义全局对象模板创建上下文。

* **V8 扩展 (`Extension`) 的注册和使用:**  测试了多种 V8 扩展的使用方式：
    * 包含 JavaScript 源代码的扩展。
    * 没有 JavaScript 源代码的扩展。
    * 扩展中抛出异常或包含语法错误时的行为。
    * 扩展中调用 V8 内部运行时函数的例子。
    * 声明原生函数的扩展。

* **扩展的依赖关系:** 测试 V8 如何处理扩展之间的依赖关系和加载顺序。

* **原生函数查找:**  验证 V8 如何在扩展中查找和调用原生函数。

* **原生函数的构造函数调用:** 测试在扩展中声明的原生函数是否可以作为构造函数使用。

* **错误报告:** 测试 V8 的错误报告机制，例如在出现循环依赖的扩展配置时如何处理。

* **Dcheck 错误处理:**  演示了 Dcheck 错误处理器的使用。

* **缺少脚本信息的错误处理:** 测试在缺少脚本信息的情况下 V8 如何处理错误。

* **弱句柄 (`Weak`) 的使用:** 测试弱句柄在垃圾回收过程中的行为以及回调函数的执行时机。

* **函数调用参数 (`Arguments`) 的测试:**  验证 JavaScript 函数调用时，C++ 端如何获取参数。

* **属性 Getter 的 Holder 测试:** 测试属性 Getter 函数的 `Holder()` 方法返回的对象是否符合预期，尤其是在原型链上查找属性时。

* **对象实例化:** 测试使用对象模板创建多个对象实例，并验证它们的原型是否相同。

* **字符串写入 (`String::WriteUtf8` 和 `String::Write`) 的测试:** 测试将 V8 字符串写入 C++ 缓冲区的功能，包括处理 UTF-8 编码、UTF-16 编码、代理对以及各种写入标志。

**与 JavaScript 的关系和示例:**

这部分 C++ 代码直接测试了 V8 引擎提供的 C++ API，这些 API 用于在 C++ 环境中与 JavaScript 代码进行交互。

例如，代码中使用了 `SetNativeDataProperty` 来创建一个具有原生行为的 JavaScript 属性。以下是一个与之对应的 JavaScript 例子：

```javascript
// 这是在 C++ 代码中创建的对象模板
// al<ObjectTemplate> templ = ObjectTemplate::New(isolate);
// templ->SetNativeDataProperty(v8_str("x"), nullptr, SetXValue, v8_str("donut"));

// 在 JavaScript 中使用该对象
let obj = { }; // 假设 C++ 创建的对象实例赋值给了 obj
console.log(obj.x); // 这会触发 C++ 中的 SetXValue 函数 (getter)
obj.x = 4;       // 这会触发 C++ 中的 SetXValue 函数 (setter)
console.log(obj.x); // 再次触发 C++ 中的 SetXValue 函数 (getter)
```

在这个例子中，JavaScript 代码尝试访问和修改 `obj.x` 属性，而这个属性的行为是在 C++ 代码中使用 `SetNativeDataProperty` 定义的。当 JavaScript 引擎执行到这些代码时，它会调用 C++ 中注册的 `SetXValue` 函数来处理属性的读取和写入。

总而言之，这部分 C++ 代码是 V8 引擎的测试代码，它旨在确保 C++ API 的各种功能按照预期工作，并且能够正确地与 JavaScript 代码进行交互。这对于保证 V8 引擎的稳定性和正确性至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共18部分，请归纳一下它的功能
```

### 源代码
```
al<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), nullptr, SetXValue,
                               v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x = 4; obj.x");
  for (int i = 0; i < 10; i++) {
    CHECK(xValue.IsEmpty());
    script->Run(context.local()).ToLocalChecked();
    CHECK(v8_num(4)
              ->Equals(context.local(),
                       Local<Value>::New(CcTest::isolate(), xValue))
              .FromJust());
    xValue.Reset();
  }
}


THREADED_TEST(NoAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(
      v8_str("x"), static_cast<v8::AccessorNameGetterCallback>(nullptr),
      nullptr, v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x = 4; obj.x");
  for (int i = 0; i < 10; i++) {
    script->Run(context.local()).ToLocalChecked();
  }
}


THREADED_TEST(MultiContexts) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "dummy",
             v8::FunctionTemplate::New(isolate, DummyCallHandler));

  Local<String> password = v8_str("Password");

  // Create an environment
  LocalContext context0(nullptr, templ);
  context0->SetSecurityToken(password);
  v8::Local<v8::Object> global0 = context0->Global();
  CHECK(global0->Set(context0.local(), v8_str("custom"), v8_num(1234))
            .FromJust());
  CHECK_EQ(1234, global0->Get(context0.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context0.local())
                     .FromJust());

  // Create an independent environment
  LocalContext context1(nullptr, templ);
  context1->SetSecurityToken(password);
  v8::Local<v8::Object> global1 = context1->Global();
  CHECK(global1->Set(context1.local(), v8_str("custom"), v8_num(1234))
            .FromJust());
  CHECK(!global0->Equals(context1.local(), global1).FromJust());
  CHECK_EQ(1234, global0->Get(context1.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context0.local())
                     .FromJust());
  CHECK_EQ(1234, global1->Get(context1.local(), v8_str("custom"))
                     .ToLocalChecked()
                     ->Int32Value(context1.local())
                     .FromJust());

  // Now create a new context with the old global
  LocalContext context2(nullptr, templ, global1);
  context2->SetSecurityToken(password);
  v8::Local<v8::Object> global2 = context2->Global();
  CHECK(global1->Equals(context2.local(), global2).FromJust());
  CHECK_EQ(0, global1->Get(context2.local(), v8_str("custom"))
                  .ToLocalChecked()
                  ->Int32Value(context1.local())
                  .FromJust());
  CHECK_EQ(0, global2->Get(context2.local(), v8_str("custom"))
                  .ToLocalChecked()
                  ->Int32Value(context2.local())
                  .FromJust());
}


THREADED_TEST(FunctionPrototypeAcrossContexts) {
  // Make sure that functions created by cloning boilerplates cannot
  // communicate through their __proto__ field.

  v8::HandleScope scope(CcTest::isolate());

  LocalContext env0;
  v8::Local<v8::Object> global0 = env0->Global();
  v8::Local<v8::Object> object0 = global0->Get(env0.local(), v8_str("Object"))
                                      .ToLocalChecked()
                                      .As<v8::Object>();
  v8::Local<v8::Object> tostring0 =
      object0->Get(env0.local(), v8_str("toString"))
          .ToLocalChecked()
          .As<v8::Object>();
  v8::Local<v8::Object> proto0 =
      tostring0->Get(env0.local(), v8_str("__proto__"))
          .ToLocalChecked()
          .As<v8::Object>();
  CHECK(proto0->Set(env0.local(), v8_str("custom"), v8_num(1234)).FromJust());

  LocalContext env1;
  v8::Local<v8::Object> global1 = env1->Global();
  v8::Local<v8::Object> object1 = global1->Get(env1.local(), v8_str("Object"))
                                      .ToLocalChecked()
                                      .As<v8::Object>();
  v8::Local<v8::Object> tostring1 =
      object1->Get(env1.local(), v8_str("toString"))
          .ToLocalChecked()
          .As<v8::Object>();
  v8::Local<v8::Object> proto1 =
      tostring1->Get(env1.local(), v8_str("__proto__"))
          .ToLocalChecked()
          .As<v8::Object>();
  CHECK(!proto1->Has(env1.local(), v8_str("custom")).FromJust());
}


THREADED_TEST(Regress892105) {
  // Make sure that object and array literals created by cloning
  // boilerplates cannot communicate through their __proto__
  // field. This is rather difficult to check, but we try to add stuff
  // to Object.prototype and Array.prototype and create a new
  // environment. This should succeed.

  v8::HandleScope scope(CcTest::isolate());

  Local<String> source = v8_str(
      "Object.prototype.obj = 1234;"
      "Array.prototype.arr = 4567;"
      "8901");

  LocalContext env0;
  Local<Script> script0 = v8_compile(source);
  CHECK_EQ(8901.0, script0->Run(env0.local())
                       .ToLocalChecked()
                       ->NumberValue(env0.local())
                       .FromJust());

  LocalContext env1;
  Local<Script> script1 = v8_compile(source);
  CHECK_EQ(8901.0, script1->Run(env1.local())
                       .ToLocalChecked()
                       ->NumberValue(env1.local())
                       .FromJust());
}

static void ReturnThis(const v8::FunctionCallbackInfo<v8::Value>& args) {
  args.GetReturnValue().Set(args.This());
}

THREADED_TEST(UndetectableObject) {
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

  CHECK(obj->IsUndetectable());

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


THREADED_TEST(VoidLiteral) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  ExpectBoolean("undefined == void 0", true);
  ExpectBoolean("undetectable == void 0", true);
  ExpectBoolean("null == void 0", true);
  ExpectBoolean("undefined === void 0", true);
  ExpectBoolean("undetectable === void 0", false);
  ExpectBoolean("null === void 0", false);

  ExpectBoolean("void 0 == undefined", true);
  ExpectBoolean("void 0 == undetectable", true);
  ExpectBoolean("void 0 == null", true);
  ExpectBoolean("void 0 === undefined", true);
  ExpectBoolean("void 0 === undetectable", false);
  ExpectBoolean("void 0 === null", false);

  ExpectString(
      "(function() {"
      "  try {"
      "    return x === void 0;"
      "  } catch(e) {"
      "    return e.toString();"
      "  }"
      "})()",
      "ReferenceError: x is not defined");
  ExpectString(
      "(function() {"
      "  try {"
      "    return void 0 === x;"
      "  } catch(e) {"
      "    return e.toString();"
      "  }"
      "})()",
      "ReferenceError: x is not defined");
}


THREADED_TEST(ExtensibleOnUndetectable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  Local<String> source = v8_str(
      "undetectable.x = 42;"
      "undetectable.x");

  Local<Script> script = v8_compile(source);

  CHECK(v8::Integer::New(isolate, 42)
            ->Equals(env.local(), script->Run(env.local()).ToLocalChecked())
            .FromJust());

  ExpectBoolean("Object.isExtensible(undetectable)", true);

  source = v8_str("Object.preventExtensions(undetectable);");
  script = v8_compile(source);
  script->Run(env.local()).ToLocalChecked();
  ExpectBoolean("Object.isExtensible(undetectable)", false);

  source = v8_str("undetectable.y = 2000;");
  script = v8_compile(source);
  script->Run(env.local()).ToLocalChecked();
  ExpectBoolean("undetectable.y == undefined", true);
}

THREADED_TEST(ConstructCallWithUndetectable) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->MarkAsUndetectable();  // undetectable
  desc->InstanceTemplate()->SetCallAsFunctionHandler(ReturnThis);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(
      env->Global()->Set(env.local(), v8_str("undetectable"), obj).FromJust());

  // Undetectable object cannot be called as constructor.
  v8::TryCatch try_catch(env->GetIsolate());
  CHECK(CompileRun("new undetectable()").IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(env->GetIsolate(), try_catch.Exception());
  CHECK_EQ(0, strcmp("TypeError: undetectable is not a constructor",
                     *exception_value));
}

static int increment_callback_counter = 0;

static void IncrementCounterConstructCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  increment_callback_counter++;
  CHECK(Local<Object>::Cast(args.NewTarget())
            ->Set(args.GetIsolate()->GetCurrentContext(), v8_str("counter"),
                  v8_num(increment_callback_counter))
            .FromJust());
  args.GetReturnValue().Set(args.NewTarget());
}

THREADED_TEST(SetCallAsFunctionHandlerConstructor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->SetCallAsFunctionHandler(
      IncrementCounterConstructCallback);  // callable

  Local<v8::Object> obj = desc->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  CHECK(env->Global()->Set(env.local(), v8_str("Counter"), obj).FromJust());

  ExpectInt32("(new Counter()).counter", 1);
  CHECK_EQ(1, increment_callback_counter);
  ExpectInt32("(new Counter()).counter", 2);
  CHECK_EQ(2, increment_callback_counter);
}
// The point of this test is type checking. We run it only so compilers
// don't complain about an unused function.
TEST(PersistentHandles) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<String> str = v8_str("foo");
  v8::Persistent<String> p_str(isolate, str);
  p_str.Reset();
  Local<Script> scr = v8_compile("");
  v8::Persistent<Script> p_scr(isolate, scr);
  p_scr.Reset();
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  v8::Persistent<ObjectTemplate> p_templ(isolate, templ);
  p_templ.Reset();
}


static void HandleLogDelegator(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
}


THREADED_TEST(GlobalObjectTemplate) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
  global_template->Set(isolate, "JSNI_Log",
                       v8::FunctionTemplate::New(isolate, HandleLogDelegator));
  v8::Local<Context> context = Context::New(isolate, nullptr, global_template);
  Context::Scope context_scope(context);
  CompileRun("JSNI_Log('LOG')");
}


static const char* kSimpleExtensionSource =
    "function Foo() {"
    "  return 4;"
    "}";


TEST(SimpleExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("simpletest", kSimpleExtensionSource));
  const char* extension_names[] = {"simpletest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("Foo()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}


static const char* kStackTraceFromExtensionSource =
    "function foo() {"
    "  throw new Error();"
    "}"
    "function bar() {"
    "  foo();"
    "}";


TEST(StackTraceInExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>(
      "stacktracetest", kStackTraceFromExtensionSource));
  const char* extension_names[] = {"stacktracetest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  CompileRun(
      "function user() { bar(); }"
      "var error;"
      "try{ user(); } catch (e) { error = e; }");
  CHECK_EQ(-1, v8_run_int32value(v8_compile("error.stack.indexOf('foo')")));
  CHECK_EQ(-1, v8_run_int32value(v8_compile("error.stack.indexOf('bar')")));
  CHECK_NE(-1, v8_run_int32value(v8_compile("error.stack.indexOf('user')")));
}


TEST(NullExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>("nulltest", nullptr));
  const char* extension_names[] = {"nulltest"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("1+3");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}

static const char* kEmbeddedExtensionSource =
    "function Ret54321(){return 54321;}~~@@$"
    "$%% THIS IS A SERIES OF NON-nullptr-TERMINATED STRINGS.";
static const int kEmbeddedExtensionSourceValidLen = 34;


TEST(ExtensionMissingSourceLength) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("srclentest_fail", kEmbeddedExtensionSource));
  const char* extension_names[] = {"srclentest_fail"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


TEST(ExtensionWithSourceLength) {
  for (int source_len = kEmbeddedExtensionSourceValidLen - 1;
       source_len <= kEmbeddedExtensionSourceValidLen + 1; ++source_len) {
    v8::HandleScope handle_scope(CcTest::isolate());
    v8::base::ScopedVector<char> extension_name(32);
    v8::base::SNPrintF(extension_name, "ext #%d", source_len);
    v8::RegisterExtension(std::make_unique<Extension>(extension_name.begin(),
                                                      kEmbeddedExtensionSource,
                                                      0, nullptr, source_len));
    const char* extension_names[1] = {extension_name.begin()};
    v8::ExtensionConfiguration extensions(1, extension_names);
    v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
    if (source_len == kEmbeddedExtensionSourceValidLen) {
      Context::Scope lock(context);
      v8::Local<Value> result = CompileRun("Ret54321()");
      CHECK(v8::Integer::New(CcTest::isolate(), 54321)
                ->Equals(context, result)
                .FromJust());
    } else {
      // Anything but exactly the right length should fail to compile.
      CHECK(context.IsEmpty());
    }
  }
}


static const char* kEvalExtensionSource1 =
    "function UseEval1() {"
    "  var x = 42;"
    "  return eval('x');"
    "}";


static const char* kEvalExtensionSource2 =
    "(function() {"
    "  var x = 42;"
    "  function e() {"
    "    return eval('x');"
    "  }"
    "  this.UseEval2 = e;"
    "})()";


TEST(UseEvalFromExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("evaltest1", kEvalExtensionSource1));
  v8::RegisterExtension(
      std::make_unique<Extension>("evaltest2", kEvalExtensionSource2));
  const char* extension_names[] = {"evaltest1", "evaltest2"};
  v8::ExtensionConfiguration extensions(2, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("UseEval1()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
  result = CompileRun("UseEval2()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
}


static const char* kWithExtensionSource1 =
    "function UseWith1() {"
    "  var x = 42;"
    "  with({x:87}) { return x; }"
    "}";


static const char* kWithExtensionSource2 =
    "(function() {"
    "  var x = 42;"
    "  function e() {"
    "    with ({x:87}) { return x; }"
    "  }"
    "  this.UseWith2 = e;"
    "})()";


TEST(UseWithFromExtension) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("withtest1", kWithExtensionSource1));
  v8::RegisterExtension(
      std::make_unique<Extension>("withtest2", kWithExtensionSource2));
  const char* extension_names[] = {"withtest1", "withtest2"};
  v8::ExtensionConfiguration extensions(2, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("UseWith1()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 87))
            .FromJust());
  result = CompileRun("UseWith2()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 87))
            .FromJust());
}


TEST(AutoExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  auto extension =
      std::make_unique<Extension>("autotest", kSimpleExtensionSource);
  extension->set_auto_enable(true);
  v8::RegisterExtension(std::move(extension));
  v8::Local<Context> context = Context::New(CcTest::isolate());
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("Foo()");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 4))
            .FromJust());
}


static const char* kSyntaxErrorInExtensionSource = "[";


// Test that a syntax error in an extension does not cause a fatal
// error but results in an empty context.
TEST(SyntaxErrorExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(std::make_unique<Extension>(
      "syntaxerror", kSyntaxErrorInExtensionSource));
  const char* extension_names[] = {"syntaxerror"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


static const char* kExceptionInExtensionSource = "throw 42";


// Test that an exception when installing an extension does not cause
// a fatal error but results in an empty context.
TEST(ExceptionExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("exception", kExceptionInExtensionSource));
  const char* extension_names[] = {"exception"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}

static const char* kNativeCallInExtensionSource =
    "function call_runtime_last_index_of(x) {"
    "  return %StringLastIndexOf(x, 'bob');"
    "}";

static const char* kNativeCallTest =
    "call_runtime_last_index_of('bobbobboellebobboellebobbob');";

// Test that a native runtime calls are supported in extensions.
TEST(NativeCallInExtensions) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::RegisterExtension(
      std::make_unique<Extension>("nativecall", kNativeCallInExtensionSource));
  const char* extension_names[] = {"nativecall"};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun(kNativeCallTest);
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 24))
            .FromJust());
}


class NativeFunctionExtension : public Extension {
 public:
  NativeFunctionExtension(const char* name, const char* source,
                          v8::FunctionCallback fun = &Echo)
      : Extension(name, source), function_(fun) {}

  v8::Local<v8::FunctionTemplate> GetNativeFunctionTemplate(
      v8::Isolate* isolate, v8::Local<v8::String> name) override {
    return v8::FunctionTemplate::New(isolate, function_);
  }

  static void Echo(const v8::FunctionCallbackInfo<v8::Value>& args) {
    if (args.Length() >= 1) args.GetReturnValue().Set(args[0]);
  }

 private:
  v8::FunctionCallback function_;
};


TEST(NativeFunctionDeclaration) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedecl";
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "native function foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  Context::Scope lock(context);
  v8::Local<Value> result = CompileRun("foo(42);");
  CHECK(result->Equals(context, v8::Integer::New(CcTest::isolate(), 42))
            .FromJust());
}


TEST(NativeFunctionDeclarationError) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedeclerr";
  // Syntax error in extension code.
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "native\nfunction foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


TEST(NativeFunctionDeclarationErrorEscape) {
  v8::HandleScope handle_scope(CcTest::isolate());
  const char* name = "nativedeclerresc";
  // Syntax error in extension code - escape code in "native" means that
  // it's not treated as a keyword.
  v8::RegisterExtension(std::make_unique<NativeFunctionExtension>(
      name, "nativ\\u0065 function foo();"));
  const char* extension_names[] = {name};
  v8::ExtensionConfiguration extensions(1, extension_names);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &extensions);
  CHECK(context.IsEmpty());
}


static void CheckDependencies(const char* name, const char* expected) {
  v8::HandleScope handle_scope(CcTest::isolate());
  v8::ExtensionConfiguration config(1, &name);
  LocalContext context(&config);
  CHECK(
      v8_str(expected)
          ->Equals(context.local(), context->Global()
                                        ->Get(context.local(), v8_str("loaded"))
                                        .ToLocalChecked())
          .FromJust());
}


/*
 * Configuration:
 *
 *     /-- B <--\
 * A <-          -- D <-- E
 *     \-- C <--/
 */
THREADED_TEST(ExtensionDependency) {
  static const char* kEDeps[] = {"D"};
  v8::RegisterExtension(
      std::make_unique<Extension>("E", "this.loaded += 'E';", 1, kEDeps));
  static const char* kDDeps[] = {"B", "C"};
  v8::RegisterExtension(
      std::make_unique<Extension>("D", "this.loaded += 'D';", 2, kDDeps));
  static const char* kBCDeps[] = {"A"};
  v8::RegisterExtension(
      std::make_unique<Extension>("B", "this.loaded += 'B';", 1, kBCDeps));
  v8::RegisterExtension(
      std::make_unique<Extension>("C", "this.loaded += 'C';", 1, kBCDeps));
  v8::RegisterExtension(
      std::make_unique<Extension>("A", "this.loaded += 'A';"));
  CheckDependencies("A", "undefinedA");
  CheckDependencies("B", "undefinedAB");
  CheckDependencies("C", "undefinedAC");
  CheckDependencies("D", "undefinedABCD");
  CheckDependencies("E", "undefinedABCDE");
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[2] = {"C", "E"};
  v8::ExtensionConfiguration config(2, exts);
  LocalContext context(&config);
  CHECK(
      v8_str("undefinedACBDE")
          ->Equals(context.local(), context->Global()
                                        ->Get(context.local(), v8_str("loaded"))
                                        .ToLocalChecked())
          .FromJust());
}


static const char* kExtensionTestScript =
    "native function A();"
    "native function B();"
    "native function C();"
    "function Foo(i) {"
    "  if (i == 0) return A();"
    "  if (i == 1) return B();"
    "  if (i == 2) return C();"
    "}";


static void CallFun(const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  if (args.IsConstructCall()) {
    CHECK(args.This()
              ->Set(args.GetIsolate()->GetCurrentContext(), v8_str("data"),
                    args.Data())
              .FromJust());
    args.GetReturnValue().SetNull();
    return;
  }
  args.GetReturnValue().Set(args.Data());
}


class FunctionExtension : public Extension {
 public:
  FunctionExtension() : Extension("functiontest", kExtensionTestScript) {}
  v8::Local<v8::FunctionTemplate> GetNativeFunctionTemplate(
      v8::Isolate* isolate, v8::Local<String> name) override;
};


static int lookup_count = 0;
v8::Local<v8::FunctionTemplate> FunctionExtension::GetNativeFunctionTemplate(
    v8::Isolate* isolate, v8::Local<String> name) {
  lookup_count++;
  if (name->StrictEquals(v8_str("A"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 8));
  } else if (name->StrictEquals(v8_str("B"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 7));
  } else if (name->StrictEquals(v8_str("C"))) {
    return v8::FunctionTemplate::New(isolate, CallFun,
                                     v8::Integer::New(isolate, 6));
  } else {
    return v8::Local<v8::FunctionTemplate>();
  }
}


THREADED_TEST(FunctionLookup) {
  v8::RegisterExtension(std::make_unique<FunctionExtension>());
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[1] = {"functiontest"};
  v8::ExtensionConfiguration config(1, exts);
  LocalContext context(&config);
  CHECK_EQ(3, lookup_count);
  CHECK(v8::Integer::New(CcTest::isolate(), 8)
            ->Equals(context.local(), CompileRun("Foo(0)"))
            .FromJust());
  CHECK(v8::Integer::New(CcTest::isolate(), 7)
            ->Equals(context.local(), CompileRun("Foo(1)"))
            .FromJust());
  CHECK(v8::Integer::New(CcTest::isolate(), 6)
            ->Equals(context.local(), CompileRun("Foo(2)"))
            .FromJust());
}


THREADED_TEST(NativeFunctionConstructCall) {
  v8::RegisterExtension(std::make_unique<FunctionExtension>());
  v8::HandleScope handle_scope(CcTest::isolate());
  static const char* exts[1] = {"functiontest"};
  v8::ExtensionConfiguration config(1, exts);
  LocalContext context(&config);
  for (int i = 0; i < 10; i++) {
    // Run a few times to ensure that allocation of objects doesn't
    // change behavior of a constructor function.
    CHECK(v8::Integer::New(CcTest::isolate(), 8)
              ->Equals(context.local(), CompileRun("(new A()).data"))
              .FromJust());
    CHECK(v8::Integer::New(CcTest::isolate(), 7)
              ->Equals(context.local(), CompileRun("(new B()).data"))
              .FromJust());
    CHECK(v8::Integer::New(CcTest::isolate(), 6)
              ->Equals(context.local(), CompileRun("(new C()).data"))
              .FromJust());
  }
}


static const char* last_location;
static const char* last_message;
void StoringErrorCallback(const char* location, const char* message) {
  if (last_location == nullptr) {
    last_location = location;
    last_message = message;
  }
}


// ErrorReporting creates a circular extensions configuration and
// tests that the fatal error handler gets called.  This renders V8
// unusable and therefore this test cannot be run in parallel.
TEST(ErrorReporting) {
  CcTest::isolate()->SetFatalErrorHandler(StoringErrorCallback);
  static const char* aDeps[] = {"B"};
  v8::RegisterExtension(std::make_unique<Extension>("A", "", 1, aDeps));
  static const char* bDeps[] = {"A"};
  v8::RegisterExtension(std::make_unique<Extension>("B", "", 1, bDeps));
  last_location = nullptr;
  v8::ExtensionConfiguration config(1, bDeps);
  v8::Local<Context> context = Context::New(CcTest::isolate(), &config);
  CHECK(context.IsEmpty());
  CHECK(last_location);
}

static size_t dcheck_count;
void DcheckErrorCallback(const char* file, int line, const char* message) {
  last_message = message;
  ++dcheck_count;
}

TEST(DcheckErrorHandler) {
  V8::SetDcheckErrorHandler(DcheckErrorCallback);

  last_message = nullptr;
  dcheck_count = 0;

  DCHECK(false && "w00t");
#ifdef DEBUG
  CHECK_EQ(dcheck_count, 1);
  CHECK(last_message);
  CHECK(std::string(last_message).find("w00t") != std::string::npos);
#else
  // The DCHECK should be a noop in non-DEBUG builds.
  CHECK_EQ(dcheck_count, 0);
#endif
}

static void MissingScriptInfoMessageListener(v8::Local<v8::Message> message,
                                             v8::Local<Value> data) {
  v8::Isolate* isolate = CcTest::isolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK(message->GetScriptOrigin().ResourceName()->IsUndefined());
  CHECK(v8::Undefined(isolate)
            ->Equals(context, message->GetScriptOrigin().ResourceName())
            .FromJust());
  message->GetLineNumber(context).FromJust();
  message->GetSourceLine(context).ToLocalChecked();
}


THREADED_TEST(ErrorWithMissingScriptInfo) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->AddMessageListener(MissingScriptInfoMessageListener);
  CompileRun("throw Error()");
  context->GetIsolate()->RemoveMessageListeners(
      MissingScriptInfoMessageListener);
}


struct FlagAndPersistent {
  bool flag;
  v8::Global<v8::Object> handle;
};

static void SetFlag(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  data.GetParameter()->handle.Reset();
}

static void IndependentWeakHandle(bool global_gc, bool interlinked) {
  i::ManualGCScope manual_gc_scope;
  // Parallel scavenge introduces too much fragmentation.
  i::v8_flags.parallel_scavenge = false;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  size_t big_heap_size = 0;
  size_t big_array_size = 0;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (interlinked) {
      a->Set(context, v8_str("x"), b).FromJust();
      b->Set(context, v8_str("x"), a).FromJust();
    }
    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
    v8::Local<Value> big_array = v8::Array::New(CcTest::isolate(), 5000);
    // Verify that we created an array where the space was reserved up front.
    big_array_size =
        i::Cast<i::JSArray>(*v8::Utils::OpenDirectHandle(*big_array))
            ->elements()
            ->Size();
    CHECK_LE(20000, big_array_size);
    a->Set(context, v8_str("y"), big_array).FromJust();
    big_heap_size = CcTest::heap()->SizeOfObjects();
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &SetFlag,
                          v8::WeakCallbackType::kParameter);
  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  // A single GC should be enough to reclaim the memory, since we are using
  // phantom handles.
  CHECK_GT(big_heap_size - big_array_size, CcTest::heap()->SizeOfObjects());
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(IndependentWeakHandle) {
  IndependentWeakHandle(false, false);
  IndependentWeakHandle(false, true);
  IndependentWeakHandle(true, false);
  IndependentWeakHandle(true, true);
}

class Trivial {
 public:
  explicit Trivial(int x) : x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

 private:
  int x_;
};


class Trivial2 {
 public:
  Trivial2(int x, int y) : y_(y), x_(x) {}

  int x() { return x_; }
  void set_x(int x) { x_ = x; }

  int y() { return y_; }
  void set_y(int y) { y_ = y; }

 private:
  int y_;
  int x_;
};

void CheckInternalFields(
    const v8::WeakCallbackInfo<v8::Persistent<v8::Object>>& data) {
  v8::Persistent<v8::Object>* handle = data.GetParameter();
  handle->Reset();
  Trivial* t1 = reinterpret_cast<Trivial*>(data.GetInternalField(0));
  Trivial2* t2 = reinterpret_cast<Trivial2*>(data.GetInternalField(1));
  CHECK_EQ(42, t1->x());
  CHECK_EQ(103, t2->x());
  t1->set_x(1729);
  t2->set_x(33550336);
}

void InternalFieldCallback(bool global_gc) {
  // Manual GC scope as --stress-incremental-marking starts marking early and
  // setting internal pointer fields mark the object for a heap layout change,
  // which prevents it from being reclaimed and the callbacks from being
  // executed.
  i::ManualGCScope manual_gc_scope;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  Trivial* t1;
  Trivial2* t2;
  v8::Persistent<v8::Object> handle;
  {
    Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
    Local<v8::ObjectTemplate> instance_templ = templ->InstanceTemplate();
    instance_templ->SetInternalFieldCount(2);

    v8::HandleScope inner_scope(isolate);
    Local<v8::Object> obj = templ->GetFunction(env.local())
                                .ToLocalChecked()
                                ->NewInstance(env.local())
                                .ToLocalChecked();
    handle.Reset(isolate, obj);
    CHECK_EQ(2, obj->InternalFieldCount());
    CHECK(obj->GetInternalField(0).As<v8::Value>()->IsUndefined());
    t1 = new Trivial(42);
    t2 = new Trivial2(103, 9);

    obj->SetAlignedPointerInInternalField(0, t1);
    t1 = reinterpret_cast<Trivial*>(obj->GetAlignedPointerFromInternalField(0));
    CHECK_EQ(42, t1->x());

    obj->SetAlignedPointerInInternalField(1, t2);
    t2 =
        reinterpret_cast<Trivial2*>(obj->GetAlignedPointerFromInternalField(1));
    CHECK_EQ(103, t2->x());

    handle.SetWeak<v8::Persistent<v8::Object>>(
        &handle, CheckInternalFields, v8::WeakCallbackType::kInternalFields);
  }

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (i::v8_flags.single_generation || global_gc) {
      i::heap::InvokeMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  CHECK_EQ(1729, t1->x());
  CHECK_EQ(33550336, t2->x());

  delete t1;
  delete t2;
}

TEST(InternalFieldCallback) {
  InternalFieldCallback(false);
  InternalFieldCallback(true);
}

static void ResetUseValueAndSetFlag(
    const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  // Blink will reset the handle, and then use the other handle, so they
  // can't use the same backing slot.
  data.GetParameter()->handle.Reset();
  data.GetParameter()->flag = true;
}

void i::heap::HeapTester::ResetWeakHandle(bool global_gc) {
  if (v8_flags.stress_incremental_marking) return;
  using v8::Context;
  using v8::Local;
  using v8::Object;

  v8::Isolate* iso = CcTest::isolate();
  v8::HandleScope scope(iso);

  FlagAndPersistent object_a, object_b;

  {
    v8::Local<Context> context = Context::New(iso);
    Context::Scope context_scope(context);
    v8::HandleScope handle_scope(iso);
    Local<Object> a(v8::Object::New(iso));
    Local<Object> b(v8::Object::New(iso));
    object_a.handle.Reset(iso, a);
    object_b.handle.Reset(iso, b);
    if (global_gc || v8_flags.single_generation) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }

  object_a.flag = false;
  object_b.flag = false;
  object_a.handle.SetWeak(&object_a, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);
  object_b.handle.SetWeak(&object_b, &ResetUseValueAndSetFlag,
                          v8::WeakCallbackType::kParameter);

  {
    // We need to invoke GC without stack, otherwise the weak references may not
    // be cleared because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());

    if (global_gc || v8_flags.single_generation || v8_flags.sticky_mark_bits) {
      i::heap::InvokeAtomicMajorGC(CcTest::heap());
    } else {
      i::heap::InvokeMinorGC(CcTest::heap());
    }
  }
  CHECK(object_a.flag);
  CHECK(object_b.flag);
}

TEST(ResetWeakHandle) {
  i::heap::HeapTester::ResetWeakHandle(false);
  i::heap::HeapTester::ResetWeakHandle(true);
}

static void ForceMinorGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMinorGC(CcTest::heap());
}

static void ForceMinorGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceMinorGC2);
}

static void ForceFullGC2(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->flag = true;
  i::heap::InvokeMajorGC(CcTest::heap());
}

static void ForceFullGC1(const v8::WeakCallbackInfo<FlagAndPersistent>& data) {
  data.GetParameter()->handle.Reset();
  data.SetSecondPassCallback(ForceFullGC2);
}

TEST(GCFromWeakCallbacks) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::Locker locker(CcTest::isolate());
  LocalContext env;

  // In this test, we need to invoke GC without stack, otherwise the weak
  // references may not be cleared because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  if (i::v8_flags.single_generation) {
    FlagAndPersistent object;
    {
      v8::HandleScope handle_scope(isolate);
      object.handle.Reset(isolate, v8::Object::New(isolate));
    }
    object.flag = false;
    object.handle.SetWeak(&object, &ForceFullGC1,
                          v8::WeakCallbackType::kParameter);
    i::heap::InvokeMajorGC(CcTest::heap());
    EmptyMessageQueues(isolate);
    CHECK(object.flag);
    return;
  }

  static const int kNumberOfGCTypes = 2;
  using Callback = v8::WeakCallbackInfo<FlagAndPersistent>::Callback;
  Callback gc_forcing_callback[kNumberOfGCTypes] = {&ForceMinorGC1,
                                                    &ForceFullGC1};

  using GCInvoker = void (*)();

  GCInvoker invoke_gc[kNumberOfGCTypes] = {
      []() { i::heap::InvokeMinorGC(CcTest::heap()); },
      []() { i::heap::InvokeMajorGC(CcTest::heap()); }};

  for (int outer_gc = 0; outer_gc < kNumberOfGCTypes; outer_gc++) {
    for (int inner_gc = 0; inner_gc < kNumberOfGCTypes; inner_gc++) {
      FlagAndPersistent object;
      {
        v8::HandleScope handle_scope(isolate);
        object.handle.Reset(isolate, v8::Object::New(isolate));
      }
      object.flag = false;
      object.handle.SetWeak(&object, gc_forcing_callback[inner_gc],
                            v8::WeakCallbackType::kParameter);
      invoke_gc[outer_gc]();
      EmptyMessageQueues(isolate);
      CHECK(object.flag);
    }
  }
}

static void ArgumentsTestCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  CHECK_EQ(3, args.Length());
  CHECK(v8::Integer::New(isolate, 1)->Equals(context, args[0]).FromJust());
  CHECK(v8::Integer::New(isolate, 2)->Equals(context, args[1]).FromJust());
  CHECK(v8::Integer::New(isolate, 3)->Equals(context, args[2]).FromJust());
  CHECK(v8::Undefined(isolate)->Equals(context, args[3]).FromJust());
  v8::HandleScope scope(args.GetIsolate());
  i::heap::InvokeMajorGC(CcTest::heap());
}


THREADED_TEST(Arguments) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "f",
              v8::FunctionTemplate::New(isolate, ArgumentsTestCallback));
  LocalContext context(nullptr, global);
  v8_compile("f(1, 2, 3)")->Run(context.local()).ToLocalChecked();
}

namespace {
int p_getter_count;
int p_getter_count2;

void PGetter(Local<Name> name,
             const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count++;
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
}

void RunHolderTest(v8::Local<v8::ObjectTemplate> obj) {
  ApiTestFuzzer::Fuzz();
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o1"),
                  obj->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun(
    "o1.__proto__ = { };"
    "var o2 = { __proto__: o1 };"
    "var o3 = { __proto__: o2 };"
    "var o4 = { __proto__: o3 };"
    "for (var i = 0; i < 10; i++) o4.p4;"
    "for (var i = 0; i < 10; i++) o3.p3;"
    "for (var i = 0; i < 10; i++) o2.p2;"
    "for (var i = 0; i < 10; i++) o1.p1;");
}

v8::Intercepted PGetter2(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  p_getter_count2++;
  v8::Isolate* isolate = info.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> global = context->Global();
  CHECK(
      info.HolderV2()
          ->Equals(context, global->Get(context, v8_str("o1")).ToLocalChecked())
          .FromJust());
  if (name->Equals(context, v8_str("p1")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o1")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p2")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o2")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p3")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o3")).ToLocalChecked())
              .FromJust());
  } else if (name->Equals(context, v8_str("p4")).FromJust()) {
    CHECK(info.This()
              ->Equals(context,
                       global->Get(context, v8_str("o4")).ToLocalChecked())
              .FromJust());
  }
  // Return something to indicate that the operation was intercepted.
  info.GetReturnValue().Set(True(isolate));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(GetterHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetNativeDataProperty(v8_str("p1"), PGetter);
  obj->SetNativeDataProperty(v8_str("p2"), PGetter);
  obj->SetNativeDataProperty(v8_str("p3"), PGetter);
  obj->SetNativeDataProperty(v8_str("p4"), PGetter);
  p_getter_count = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count);
}


THREADED_TEST(PreInterceptorHolders) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(PGetter2));
  p_getter_count2 = 0;
  RunHolderTest(obj);
  CHECK_EQ(40, p_getter_count2);
}


THREADED_TEST(ObjectInstantiation) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("t"), PGetter);
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("o"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  for (int i = 0; i < 100; i++) {
    v8::HandleScope inner_scope(CcTest::isolate());
    v8::Local<v8::Object> obj =
        templ->NewInstance(context.local()).ToLocalChecked();
    CHECK(!obj->Equals(context.local(), context->Global()
                                            ->Get(context.local(), v8_str("o"))
                                            .ToLocalChecked())
               .FromJust());
    CHECK(
        context->Global()->Set(context.local(), v8_str("o2"), obj).FromJust());
    v8::Local<Value> value = CompileRun("o.__proto__ === o2.__proto__");
    CHECK(v8::True(isolate)->Equals(context.local(), value).FromJust());
    CHECK(context->Global()->Set(context.local(), v8_str("o"), obj).FromJust());
  }
}


static int StrCmp16(uint16_t* a, uint16_t* b) {
  while (true) {
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}


static int StrNCmp16(uint16_t* a, uint16_t* b, int n) {
  while (true) {
    if (n-- == 0) return 0;
    if (*a == 0 && *b == 0) return 0;
    if (*a != *b) return 0 + *a - *b;
    a++;
    b++;
  }
}

THREADED_TEST(StringWrite) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<String> str = v8_str("abcde");
  // abc<Icelandic eth><Unicode snowman>.
  v8::Local<String> str2 = v8_str("abc\xC3\xB0\xE2\x98\x83");
  v8::Local<String> str3 =
      v8::String::NewFromUtf8Literal(context->GetIsolate(), "abc\0def");
  // "ab" + lead surrogate + "wx" + trail surrogate + "yz"
  uint16_t orphans[8] = {0x61, 0x62, 0xD800, 0x77, 0x78, 0xDC00, 0x79, 0x7A};
  v8::Local<String> orphans_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), orphans,
                                 v8::NewStringType::kNormal, 8)
          .ToLocalChecked();
  // single lead surrogate
  uint16_t lead[1] = {0xD800};
  v8::Local<String> lead_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), lead,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // single trail surrogate
  uint16_t trail[1] = {0xDC00};
  v8::Local<String> trail_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), trail,
                                 v8::NewStringType::kNormal, 1)
          .ToLocalChecked();
  // surrogate pair
  uint16_t pair[2] = {0xD800, 0xDC00};
  v8::Local<String> pair_str =
      v8::String::NewFromTwoByte(context->GetIsolate(), pair,
                                 v8::NewStringType::kNormal, 2)
          .ToLocalChecked();
  const int kStride = 4;  // Must match stride in for loops in JS below.
  CompileRun(
      "var left = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  left = left + String.fromCharCode(i);"
      "}");
  CompileRun(
      "var right = '';"
      "for (var i = 0; i < 0xD800; i += 4) {"
      "  right = String.fromCharCode(i) + right;"
      "}");
  v8::Local<v8::Object> global = context->Global();
  Local<String> left_tree = global->Get(context.local(), v8_str("left"))
                                .ToLocalChecked()
                                .As<String>();
  Local<String> right_tree = global->Get(context.local(), v8_str("right"))
                                 .ToLocalChecked()
                                 .As<String>();

  CHECK_EQ(5, str2->Length());
  CHECK_EQ(0xD800 / kStride, left_tree->Length());
  CHECK_EQ(0xD800 / kStride, right_tree->Length());

  char buf[100];
  char utf8buf[0xD800 * 3];
  uint16_t wbuf[100];
  size_t len;

  memset(utf8buf, 0x1, 1000);
  len = v8::String::Empty(isolate)->WriteUtf8V2(
      isolate, utf8buf, sizeof(utf8buf), String::WriteFlags::kNullTerminate);
  CHECK_EQ(1, len);
  CHECK_EQ(0, strcmp(utf8buf, ""));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(9, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 8);
  CHECK_EQ(8, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83\x01", 9));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 7);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 6);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 5);
  CHECK_EQ(5, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\x01", 5));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 3);
  CHECK_EQ(3, len);
  CHECK_EQ(0, strncmp(utf8buf, "abc\x01", 4));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 2);
  CHECK_EQ(2, len);
  CHECK_EQ(0, strncmp(utf8buf, "ab\x01", 3));

  // always write a null terminator if requested, even if there isn't enough
  // space for all characters of the string
  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 4,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 5,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc"));

  memset(utf8buf, 0x1, 1000);
  len = str2->WriteUtf8V2(isolate, utf8buf, 6,
                          String::WriteFlags::kNullTerminate);
  CHECK_EQ(6, len);
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0"));

  // allow orphan surrogates by default
  memset(utf8buf, 0x1, 1000);
  len = orphans_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                                 String::WriteFlags::kNullTerminate);
  CHECK_EQ(13, len);
  CHECK_EQ(0, strcmp(utf8buf, "ab\xED\xA0\x80wx\xED\xB0\x80yz"));

  // replace orphan surrogates with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = orphans_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                                 String::WriteFlags::kNullTerminate |
                                     String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(13, len);
  CHECK_EQ(0, strcmp(utf8buf, "ab\xEF\xBF\xBDwx\xEF\xBF\xBDyz"));

  // replace single lead surrogate with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = lead_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                              String::WriteFlags::kNullTerminate |
                                  String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "\xEF\xBF\xBD"));

  // replace single trail surrogate with Unicode replacement character
  memset(utf8buf, 0x1, 1000);
  len = trail_str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf),
                               String::WriteFlags::kNullTerminate |
                                   String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(4, len);
  CHECK_EQ(0, strcmp(utf8buf, "\xEF\xBF\xBD"));

  // do not replace / write anything if surrogate pair does not fit the buffer
  // space
  memset(utf8buf, 0x1, 1000);
  len = pair_str->WriteUtf8V2(isolate, utf8buf, 3,
                              String::WriteFlags::kReplaceInvalidUtf8);
  CHECK_EQ(0, len);

  memset(utf8buf, 0x1, sizeof(utf8buf));
  len = left_tree->Utf8LengthV2(isolate);
  int utf8_expected =
      (0x80 + (0x800 - 0x80) * 2 + (0xD800 - 0x800) * 3) / kStride;
  CHECK_EQ(utf8_expected, len);
  len = left_tree->WriteUtf8V2(isolate, utf8buf, utf8_expected);
  CHECK_EQ(utf8_expected, len);
  CHECK_EQ(0xED, static_cast<unsigned char>(utf8buf[utf8_expected - 3]));
  CHECK_EQ(0x9F, static_cast<unsigned char>(utf8buf[utf8_expected - 2]));
  CHECK_EQ(0xC0 - kStride,
           static_cast<unsigned char>(utf8buf[utf8_expected - 1]));
  CHECK_EQ(1, utf8buf[utf8_expected]);

  memset(utf8buf, 0x1, sizeof(utf8buf));
  len = right_tree->Utf8LengthV2(isolate);
  CHECK_EQ(utf8_expected, len);
  len = right_tree->WriteUtf8V2(isolate, utf8buf, utf8_expected);
  CHECK_EQ(utf8_expected, len);
  CHECK_EQ(0xED, static_cast<unsigned char>(utf8buf[0]));
  CHECK_EQ(0x9F, static_cast<unsigned char>(utf8buf[1]));
  CHECK_EQ(0xC0 - kStride, static_cast<unsigned char>(utf8buf[2]));
  CHECK_EQ(1, utf8buf[utf8_expected]);

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, str->Length(),
                      reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 0, str->Length(), wbuf,
               String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abcde", buf));
  uint16_t answer1[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer1, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 4, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 0, 4, wbuf);
  CHECK_EQ(0, strncmp("abcd\x01", buf, 5));
  uint16_t answer2[] = {'a', 'b', 'c', 'd', 0x101};
  CHECK_EQ(0, StrNCmp16(answer2, wbuf, 5));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 0, 5, wbuf);
  CHECK_EQ(0, strncmp("abcde\x01", buf, 6));
  uint16_t answer3[] = {'a', 'b', 'c', 'd', 'e', 0x101};
  CHECK_EQ(0, StrNCmp16(answer3, wbuf, 6));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 0, 5, wbuf, String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abcde", buf));
  uint16_t answer4[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer4, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 4, 1, reinterpret_cast<uint8_t*>(buf),
                      String::WriteFlags::kNullTerminate);
  str->WriteV2(isolate, 4, 1, wbuf, String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("e", buf));
  uint16_t answer5[] = {'e', '\0'};
  CHECK_EQ(0, StrCmp16(answer5, wbuf));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 4, 1, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 4, 1, wbuf);
  CHECK_EQ(0, strncmp("e\x01", buf, 2));
  uint16_t answer6[] = {'e', 0x101};
  CHECK_EQ(0, StrNCmp16(answer6, wbuf, 2));

  memset(buf, 0x1, sizeof(buf));
  memset(wbuf, 0x1, sizeof(wbuf));
  str->WriteOneByteV2(isolate, 3, 1, reinterpret_cast<uint8_t*>(buf));
  str->WriteV2(isolate, 3, 1, wbuf);
  CHECK_EQ(0, strncmp("d\x01", buf, 2));
  uint16_t answer7[] = {'d', 0x101};
  CHECK_EQ(0, StrNCmp16(answer7, wbuf, 2));

  memset(wbuf, 0x1, sizeof(wbuf));
  wbuf[5] = 'X';
  str->WriteV2(isolate, 0, 5, wbuf);
  CHECK_EQ('X', wbuf[5]);
  uint16_t answer8a[] = {'a', 'b', 'c', 'd', 'e'};
  uint16_t answer8b[] = {'a', 'b', 'c', 'd', 'e', '\0'};
  CHECK_EQ(0, StrNCmp16(answer8a, wbuf, 5));
  CHECK_NE(0, StrCmp16(answer8b, wbuf));
  wbuf[5] = '\0';
  CHECK_EQ(0, StrCmp16(answer8b, wbuf));

  memset(buf, 0x1, sizeof(buf));
  buf[5] = 'X';
  str->WriteOneByteV2(isolate, 0, 5, reinterpret_cast<uint8_t*>(buf));
  CHECK_EQ('X', buf[5]);
  CHECK_EQ(0, strncmp("abcde", buf, 5));
  CHECK_NE(0, strcmp("abcde", buf));
  buf[5] = '\0';
  CHECK_EQ(0, strcmp("abcde", buf));

  memset(utf8buf, 0x1, sizeof(utf8buf));
  utf8buf[8] = 'X';
  str2->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf));
  CHECK_EQ('X', utf8buf[8]);
  CHECK_EQ(0, strncmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83", 8));
  CHECK_NE(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));
  utf8buf[8] = '\0';
  CHECK_EQ(0, strcmp(utf8buf, "abc\xC3\xB0\xE2\x98\x83"));

  memset(utf8buf, 0x1, sizeof(utf8buf));
  utf8buf[5] = 'X';
  len = str->WriteUtf8V2(isolate, utf8buf, sizeof(utf8buf));
  CHECK_EQ(5, len);
  CHECK_EQ('X', utf8buf[5]);  // Test that the sixth character is untouched.
  utf8buf[5] = '\0';
  CHECK_EQ(0, strcmp(utf8buf, "abcde"));

  memset(buf, 0x1, sizeof(buf));
  str3->WriteOneByteV2(isolate, 0, str3->Length(),
                       reinterpret_cast<uint8_t*>(buf),
                       String::WriteFlags::kNullTerminate);
  CHECK_EQ(0, strcmp("abc", buf));
  CHECK_EQ(0, buf[3]);
  CHECK_EQ(0, strcmp("def", buf + 4));

  str->WriteOneByteV2(isolate, 0, 0, nullptr);
  str->WriteV2(isolate, 0, 0, nullptr);
  len = str->WriteUtf8V2(isolate, nullptr, 0);
  CHECK_EQ(0, len);
}

static void Utf16Helper(LocalContext& context, const char* name,
                        const char* lengths_name, int len) {
  Local<v8::Array> a = Local<v8::Array>::Cast(
      context->Global()->Get(context.local(), v8_str(name)).ToLocalChecked());
  Local<v8::Array> alens =
      Local<v8::Array>::Cast(context->Global()
                                 ->Get(context.local(), v8_str(lengths_name))
                                 .ToLocalChecked());
  for (int i = 0; i < len; i++) {
    Local<v8::String> string =
        Local<v8::String>::Cast(a->Get(context.local(), i).ToLocalChecked());
    Local<v8::Number> expected_len = Local<v8::Number>::Cast(
        alens->Get(context.local(), i).ToLocalChecked());
    size_t length = string->Utf8LengthV2(context->GetIsolate());
    CHECK_EQ(expected_len->Value(), length);
  }
}

void TestUtf8DecodingAgainstReference(
    v8::Isolate* isolate, const char* cases[],
    const std::vector<std::vector<uint16_t>>& unicode_expected) {
  for (size_t test_ix = 0; test_ix < unicode_expected.size(); ++test_ix) {
    v8::Local<String> str = v8_str(cases[test_ix]);
    CHECK_EQ(unicode_expected[test_ix].size(), str->Length());

    uint32_t length = str->Length();
    std::unique_ptr<uint16_t[]> buffer(new uint16_t[length]);
    str->WriteV2(isolate, 0, length, buffer.get());

    for (size_t i = 0; i < unicode_expected[test_ix].size(); ++i) {
      CHECK_EQ(unicode_expected[test_ix][i], buffer[i]);
    }
  }
}

THREADED_TEST(OverlongSequencesAndSurrogates) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char* cases[] = {
      // Overlong 2-byte sequence.
      "X\xc0\xbfY\0",
      // Another overlong 2-byte sequence.
      "X\xc1\xbfY\0",
      // Overlong 3-byte sequence.
      "X\xe0\x9f\xbfY\0",
      // Overlong 4-byte sequence.
      "X\xf0\x89\xbf\xbfY\0",
      // Invalid 3-byte sequence (reserved for surrogates).
      "X\xed\xa0\x80Y\0",
      // Invalid 4-bytes sequence (value out of range).
      "X\xf4\x90\x80\x80Y\0",

      // Start of an overlong 3-byte sequence but not enough continuation bytes.
      "X\xe0\x9fY\0",
      // Start of an overlong 4-byte sequence but not enough continuation bytes.
      "X\xf0\x89\xbfY\0",
      // Start of an invalid 3-byte sequence (reserved for surrogates) but not
      // enough continuation bytes.
      "X\xed\xa0Y\0",
      // Start of an invalid 4-bytes sequence (value out of range) but not
      // enough continuation bytes.
      "X\xf4\x90\x80Y\0",
  };
  const std::vector<std::vector<uint16_t>> unicode_expected = {
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
  };
  CHECK_EQ(unicode_expected.size(), arraysize(cases));
  TestUtf8DecodingAgainstReference(context->GetIsolate(), cases,
                                   unicode_expected);
}

THREADED_TEST(Utf16) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  CompileRun(
      "var pad = '01234567890123456789';"
      "var p = [];"
      "var plens = [20, 3, 3];"
      "p.push('01234567890123456789');"
      "var lead = 0xD800;"
      "var trail = 0xDC00;"
      "p.push(String.fromCharCode(0xD800));"
      "p.push(String.fromCharCode(0xDC00));"
      "var a = [];"
      "var b = [];"
      "var c = [];"
      "var alens = [];"
      "for (var i = 0; i < 3; i++) {"
      "  p[1] = String.fromCharCode(lead++);"
      "  for (var j = 0; j < 3; j++) {"
      "    p[2] = String.fromCharCode(trail++);"
      "    a.push(p[i] + p[j]);"
      "    b.push(p[i] + p[j]);"
      "    c.push(p[i] + p[j]);"
      "    alens.push(plens[i] + plens[j]);"
      "  }"
      "}"
      "alens
```