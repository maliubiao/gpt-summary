Response: The user wants me to summarize the functionality of the C++ code provided, which is part 2 of a 4-part file. I also need to illustrate any connection to JavaScript functionality using JavaScript examples.

The code appears to be a series of C++ unit tests for V8's API related to interceptors. Interceptors are a mechanism in V8 that allows developers to hook into property access and modification on JavaScript objects.

Based on the test names and the code within each test, the functionality being tested in this part includes:

1. **Interaction of interceptors with read-only properties:**  Testing whether interceptors correctly handle scenarios where a prototype has a read-only property.
2. **Behavior of empty interceptors:** Examining how interceptors that don't intercept any properties behave in various situations, such as accessing accessors, storing to globals, and their effect on property transitions.
3. **Interceptor visibility of symbols:** Distinguishing between "legacy" interceptors (string-only) and "generic" interceptors (which can see symbols).
4. **Named property handler getters:**  Testing the `NamedPropertyHandlerConfiguration` and how it handles property access.
5. **Property definer callbacks:** Investigating callbacks triggered during `Object.defineProperty`, including different scenarios of interception and descriptor properties.
6. **Property descriptor callbacks:**  Testing callbacks for `Object.getOwnPropertyDescriptor`.
7. **Indexed property handler getters:** Similar to named property handlers, but for indexed properties.
8. **Property handlers in prototypes:**  Verifying that property handlers work correctly in prototype chains.
9. **Pre-property handlers:**  Testing handlers that execute *before* the default property access logic.
10. **Interaction of empty interceptors with accessors:** Ensuring empty interceptors don't interfere with JavaScript and API accessors.
11. **Interceptor effects on JavaScript properties:** Checking that empty interceptors don't unintentionally shadow regular JavaScript properties.
12. **Switching between interceptors and accessors/properties:** Testing how V8 handles transitions between using interceptors and using regular accessors or properties, including inheritance scenarios.
13. **Interactions with hidden properties:**  Verifying that interceptors don't get invoked for hidden properties.
14. **Named interceptor property reads:** Testing basic read operations with named interceptors.
15. **Named interceptors and dictionary mode:**  Ensuring interceptors function correctly when objects are in "dictionary" property storage mode.
16. **Named interceptors in multiple contexts:** Testing interceptor behavior when objects are moved between different V8 contexts.
17. **Map transitions and interceptors:** Making sure map transitions don't break interceptor lookup.
18. **Indexed interceptors with indexed accessors:** Testing the interaction between indexed interceptors and indexed accessors defined using `__defineGetter__` and `__defineSetter__`.
19. **Indexed interceptors and unboxed doubles:** Testing how interceptors handle arrays backed by unboxed double values during enumeration.

For the JavaScript examples, I can pick a few representative scenarios and show how the C++ tests relate to JavaScript behavior.
这个C++源代码文件（第2部分）主要测试了 **V8引擎中关于属性拦截器 (interceptors) 的各种功能和行为**。 它是对 `v8/test/cctest/test-api-interceptors.cc` 的一部分，因此延续了对V8 API中拦截器特性的测试。

具体来说，这部分测试涵盖了以下几个方面的拦截器功能：

* **拦截器与只读属性的交互:** 测试当原型链上存在只读属性时，拦截器如何影响属性的设置和访问。
* **空拦截器的行为:**  测试当拦截器没有实际拦截任何属性时，其对属性访问、设置、继承以及全局对象的影响。
* **拦截器对Symbol的可见性:** 区分了旧的只处理字符串的拦截器和新的可以处理Symbol的拦截器。
* **具名属性处理器 (NamedPropertyHandler) 的 Getter:** 测试了使用 `NamedPropertyHandlerConfiguration` 配置的处理器如何拦截属性的读取操作。
* **属性定义拦截回调 (PropertyDefinerCallback):**  测试了在调用 `Object.defineProperty` 时触发的回调，以及拦截器如何影响属性的定义过程，包括对属性描述符的检查。
* **属性描述符拦截回调 (PropertyDescriptorCallback):** 测试了在调用 `Object.getOwnPropertyDescriptor` 时触发的回调，以及拦截器如何返回自定义的属性描述符。
* **索引属性处理器 (IndexedPropertyHandler) 的 Getter:** 类似于具名属性处理器，但针对数组索引。
* **原型链上的属性处理器:** 测试了当属性处理器定义在原型链上时，其如何工作。
* **前置属性处理器 (PrePropertyHandler):** 测试了在默认属性访问逻辑之前执行的属性处理器。
* **空拦截器与访问器的交互:** 确保空拦截器不会影响JavaScript定义的访问器属性和API定义的访问器属性。
* **空拦截器对普通JavaScript属性的影响:**  确认空拦截器不会意外地屏蔽或影响普通的JavaScript属性。
* **拦截器与访问器之间的切换:** 测试了V8如何在拦截器和访问器（包括C++ API访问器和JavaScript访问器）之间进行动态切换。
* **拦截器与属性之间的切换:** 测试了V8如何在拦截器和普通属性之间进行动态切换。
* **无副作用的属性处理器:** 测试了标记为无副作用的属性处理器在调试和代码分析中的行为。
* **拦截器与隐藏属性:**  验证了拦截器不会被用于访问对象的隐藏属性 (Private Symbols)。
* **具名拦截器属性读取:** 测试了基本的具名拦截器如何拦截属性读取操作。
* **具名拦截器与字典模式:** 测试了当对象处于字典模式 (dictionary mode) 时，具名拦截器的行为。
* **具名拦截器在多上下文环境:** 测试了在不同的V8上下文中，具名拦截器的行为。
* **Map 转换与拦截器:** 确保Map转换不会干扰拦截器的查找。
* **索引拦截器与索引访问器:** 测试了索引拦截器与使用 `__defineGetter__` 和 `__defineSetter__` 定义的索引访问器之间的交互。
* **索引拦截器与非装箱的双精度浮点数:** 测试了在处理存储非装箱双精度浮点数的数组时，索引拦截器的行为。

**与JavaScript的功能关系以及示例:**

这个C++文件测试的都是直接与JavaScript的动态特性相关的底层机制，特别是对象属性的访问和修改。 属性拦截器允许在JavaScript层面自定义属性访问的行为。

以下是一些与测试用例相关的JavaScript示例：

**1. 拦截器与只读属性的交互:**

```javascript
let o = {};
let p = {};
Object.defineProperty(p, 'x', { value: 153, writable: false });
o.__proto__ = p;

let r = Object.create(o); // r的原型是o，o的原型是p
try {
  r.x = 10; // 尝试设置继承来的只读属性
} catch (e) {
  console.log("设置只读属性失败");
}
console.log(r.x); // 输出 153
```

**2. 空拦截器的行为:**

```javascript
function Child() {
  // 假设Child构造函数在C++中注册了空拦截器
}
Child.prototype.__defineGetter__('age', function() { return this._age; });
Child.prototype.__defineSetter__('age', function(v) { this._age = v; });

let child = new Child();
child.age = 20;
console.log(child.age); // 输出 20
```

**3. 拦截器对Symbol的可见性 (GenericInterceptorDoesSeeSymbols):**

```javascript
const ageSym = Symbol('age');

function Child() {
  this[ageSym] = 30; // 假设 Child 构造函数在 C++ 中注册了通用拦截器
}
Child.prototype.__defineGetter__(ageSym, function() { return this["_sym_" + ageSym.description]; });
Child.prototype.__defineSetter__(ageSym, function(v) { this["_sym_" + ageSym.description] = v; });

let child = new Child();
child[ageSym] = 35;
console.log(child[ageSym]); // 输出 35
console.log(child._sym_age); //  通用拦截器可能会将 Symbol 属性映射到类似这样的字符串属性
```

**4. 属性定义拦截回调 (PropertyDefinerCallback):**

```javascript
let obj = {};
// 假设 obj 的原型或自身在 C++ 中注册了 PropertyDefinerCallback
Object.defineProperty(obj, 'y', { value: 42 }); // 触发 PropertyDefinerCallback
console.log(obj.y);
```

**总结:**

这部分C++代码通过大量的单元测试，确保了V8引擎的属性拦截器功能的稳定性和正确性。 这些拦截器是JavaScript元编程的重要组成部分，允许开发者更精细地控制对象属性的行为，对于实现一些高级特性（如代理对象）至关重要。 开发者可以通过V8的C++ API注册和配置这些拦截器，从而影响JavaScript代码的执行。

### 提示词
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
"let p = {};"
                     "Object.defineProperty(p, 'x', "
                     "                      {value: 153, writable: false});"
                     "o.__proto__ = p;"
                     "let result = 0;"
                     "let r;"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  try {"
                     "    r.x = i;"
                     "  } catch (e) {"
                     "    result++;"
                     "  }"
                     "}"
                     "result",
                     20);
}

THREADED_TEST(InterceptorShadowsReadOnlyProperty) {
  // Interceptor claims that it has a writable property 'x', so the existence
  // of the readonly property 'x' on the prototype should not cause exceptions.
  CheckInterceptorIC(InterceptorLoadXICGetter,
                     nullptr,  // query callback
                     "'use strict';"
                     "let p = {};"
                     "Object.defineProperty(p, 'x', "
                     "                      {value: 153, writable: false});"
                     "o.__proto__ = p;"
                     "let result = 0;"
                     "let r;"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  try {"
                     "    r.x = i;"
                     "    result++;"
                     "  } catch (e) {}"
                     "}"
                     "result",
                     20);
}

THREADED_TEST(EmptyInterceptorDoesNotShadowAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddAccessor(isolate, parent, v8_str("age"), SimpleGetterCallback,
              SimpleSetterCallback);
  AddInterceptor(child, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "child.age = 10;");
  ExpectBoolean("child.hasOwnProperty('age')", false);
  ExpectInt32("child.age", 10);
  ExpectInt32("child.accessor_age", 10);
}

THREADED_TEST(EmptyInterceptorVsStoreGlobalICs) {
  // In sloppy mode storing to global must succeed.
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "globalThis.__proto__ = o;"
                     "let result = 0;"
                     "for (var i = 0; i < 20; i++) {"
                     "  try {"
                     "    x = i;"
                     "    result++;"
                     "  } catch (e) {}"
                     "}"
                     "result + x",
                     20 + 19);

  // In strict mode storing to global must throw.
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "'use strict';"
                     "globalThis.__proto__ = o;"
                     "let result = 0;"
                     "for (var i = 0; i < 20; i++) {"
                     "  try {"
                     "    x = i;"
                     "  } catch (e) {"
                     "    result++;"
                     "  }"
                     "}"
                     "result + (typeof(x) === 'undefined' ? 100 : 0)",
                     120);
}

THREADED_TEST(LegacyInterceptorDoesNotSeeSymbols) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  v8::Local<v8::Symbol> age = v8::Symbol::New(isolate, v8_str("age"));

  child->Inherit(parent);
  AddAccessor(isolate, parent, age, SymbolGetterCallback, SymbolSetterCallback);
  AddStringOnlyInterceptor(child, InterceptorGetter, InterceptorSetter);

  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  env->Global()->Set(env.local(), v8_str("age"), age).FromJust();
  CompileRun(
      "var child = new Child;"
      "child[age] = 10;");
  ExpectInt32("child[age]", 10);
  ExpectBoolean("child.hasOwnProperty('age')", false);
  ExpectBoolean("child.hasOwnProperty('accessor_age')", true);
}


THREADED_TEST(GenericInterceptorDoesSeeSymbols) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  v8::Local<v8::Symbol> age = v8::Symbol::New(isolate, v8_str("age"));
  v8::Local<v8::Symbol> anon = v8::Symbol::New(isolate);

  child->Inherit(parent);
  AddAccessor(isolate, parent, age, SymbolGetterCallback, SymbolSetterCallback);
  AddInterceptor(child, GenericInterceptorGetter, GenericInterceptorSetter);

  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  env->Global()->Set(env.local(), v8_str("age"), age).FromJust();
  env->Global()->Set(env.local(), v8_str("anon"), anon).FromJust();
  CompileRun(
      "var child = new Child;"
      "child[age] = 10;");
  ExpectInt32("child[age]", 10);
  ExpectInt32("child._sym_age", 10);

  // Check that it also sees strings.
  CompileRun("child.foo = 47");
  ExpectInt32("child.foo", 47);
  ExpectInt32("child._str_foo", 47);

  // Check that the interceptor can punt (in this case, on anonymous symbols).
  CompileRun("child[anon] = 31337");
  ExpectInt32("child[anon]", 31337);
}


THREADED_TEST(NamedPropertyHandlerGetter) {
  echo_named_call_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      EchoNamedProperty, nullptr, nullptr, nullptr, nullptr, v8_str("data")));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  CHECK_EQ(0, echo_named_call_count);
  v8_compile("obj.x")->Run(env.local()).ToLocalChecked();
  CHECK_EQ(1, echo_named_call_count);
  const char* code = "var str = 'oddle'; obj[str] + obj.poddle;";
  v8::Local<Value> str = CompileRun(code);
  String::Utf8Value value(isolate, str);
  CHECK_EQ(0, strcmp(*value, "oddlepoddle"));
  // Check default behavior
  CHECK_EQ(10, v8_compile("obj.flob = 10;")
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
  CHECK(v8_compile("'myProperty' in obj")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
  CHECK(v8_compile("delete obj.myProperty")
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
}

namespace {
v8::Intercepted NotInterceptingPropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptingPropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kYes;
}

v8::Intercepted CheckDescriptorInDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(!desc.has_writable());
  CHECK(!desc.has_value());
  CHECK(!desc.has_enumerable());
  CHECK(desc.has_configurable());
  CHECK(!desc.configurable());
  CHECK(desc.has_get());
  CHECK(desc.get()->IsFunction());
  CHECK(desc.has_set());
  CHECK(desc.set()->IsUndefined());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallback) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  {  // Intercept defineProperty()
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, nullptr, nullptr, nullptr,
        NotInterceptingPropertyDefineCallback));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj.x = 17; "
        "Object.defineProperty(obj, 'x', {value: 42});"
        "obj.x;";
    CHECK_EQ(42, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }

  {  // Intercept defineProperty() for correct accessor descriptor
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, nullptr, nullptr, nullptr,
        CheckDescriptorInDefineCallback));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj.x = 17; "
        "Object.defineProperty(obj, 'x', {"
        "get: function(){ return 42; }, "
        "set: undefined,"
        "configurable: 0"
        "});"
        "obj.x;";
    CHECK_EQ(17, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }

  {  // Do not intercept defineProperty()
    v8::Local<v8::FunctionTemplate> templ2 =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ2->InstanceTemplate()->SetHandler(
        v8::NamedPropertyHandlerConfiguration(
            nullptr, nullptr, nullptr, nullptr, nullptr,
            InterceptingPropertyDefineCallback));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ2->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();

    const char* code =
        "obj.x = 17; "
        "Object.defineProperty(obj, 'x', {value: 42});"
        "obj.x;";
    CHECK_EQ(17, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
}

namespace {
v8::Intercepted NotInterceptingPropertyDefineCallbackIndexed(
    uint32_t index, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptingPropertyDefineCallbackIndexed(
    uint32_t index, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  return v8::Intercepted::kYes;
}

v8::Intercepted CheckDescriptorInDefineCallbackIndexed(
    uint32_t index, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(!desc.has_writable());
  CHECK(!desc.has_value());
  CHECK(desc.has_enumerable());
  CHECK(desc.enumerable());
  CHECK(!desc.has_configurable());
  CHECK(desc.has_get());
  CHECK(desc.get()->IsFunction());
  CHECK(desc.has_set());
  CHECK(desc.set()->IsUndefined());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackIndexed) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  {  // Intercept defineProperty()
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(
        v8::IndexedPropertyHandlerConfiguration(
            nullptr, nullptr, nullptr, nullptr, nullptr,
            NotInterceptingPropertyDefineCallbackIndexed));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj[2] = 17; "
        "Object.defineProperty(obj, 2, {value: 42});"
        "obj[2];";
    CHECK_EQ(42, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }

  {  // Intercept defineProperty() for correct accessor descriptor
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(
        v8::IndexedPropertyHandlerConfiguration(
            nullptr, nullptr, nullptr, nullptr, nullptr,
            CheckDescriptorInDefineCallbackIndexed));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj[2] = 17; "
        "Object.defineProperty(obj, 2, {"
        "get: function(){ return 42; }, "
        "set: undefined,"
        "enumerable: true"
        "});"
        "obj[2];";
    CHECK_EQ(17, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }

  {  // Do not intercept defineProperty()
    v8::Local<v8::FunctionTemplate> templ2 =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ2->InstanceTemplate()->SetHandler(
        v8::IndexedPropertyHandlerConfiguration(
            nullptr, nullptr, nullptr, nullptr, nullptr,
            InterceptingPropertyDefineCallbackIndexed));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ2->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();

    const char* code =
        "obj[2] = 17; "
        "Object.defineProperty(obj, 2, {value: 42});"
        "obj[2];";
    CHECK_EQ(17, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
}

// Test that freeze() is intercepted.
THREADED_TEST(PropertyDefinerCallbackForFreeze) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      InterceptingPropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "obj.x = 17; "
      "Object.freeze(obj.x); "
      "Object.isFrozen(obj.x);";

  CHECK(v8_compile(code)
            ->Run(env.local())
            .ToLocalChecked()
            ->BooleanValue(isolate));
}

// Check that the descriptor passed to the callback is enumerable.
namespace {
v8::Intercepted CheckEnumerablePropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(desc.has_value());
  CHECK_EQ(42, desc.value()
                   ->Int32Value(info.GetIsolate()->GetCurrentContext())
                   .FromJust());
  CHECK(desc.has_enumerable());
  CHECK(desc.enumerable());
  CHECK(!desc.has_writable());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackEnumerable) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      CheckEnumerablePropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "obj.x = 17; "
      "Object.defineProperty(obj, 'x', {value: 42, enumerable: true});"
      "obj.x;";
  CHECK_EQ(17, v8_compile(code)
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}

// Check that the descriptor passed to the callback is configurable.
namespace {
v8::Intercepted CheckConfigurablePropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(desc.has_value());
  CHECK_EQ(42, desc.value()
                   ->Int32Value(info.GetIsolate()->GetCurrentContext())
                   .FromJust());
  CHECK(desc.has_configurable());
  CHECK(desc.configurable());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackConfigurable) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      CheckConfigurablePropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "obj.x = 17; "
      "Object.defineProperty(obj, 'x', {value: 42, configurable: true});"
      "obj.x;";
  CHECK_EQ(17, v8_compile(code)
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}

// Check that the descriptor passed to the callback is writable.
namespace {
v8::Intercepted CheckWritablePropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(desc.has_writable());
  CHECK(desc.writable());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackWritable) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      CheckWritablePropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "obj.x = 17; "
      "Object.defineProperty(obj, 'x', {value: 42, writable: true});"
      "obj.x;";
  CHECK_EQ(17, v8_compile(code)
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}

// Check that the descriptor passed to the callback has a getter.
namespace {
v8::Intercepted CheckGetterPropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(desc.has_get());
  CHECK(!desc.has_set());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackWithGetter) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      CheckGetterPropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "obj.x = 17;"
      "Object.defineProperty(obj, 'x', {get: function() {return 42;}});"
      "obj.x;";
  CHECK_EQ(17, v8_compile(code)
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}

// Check that the descriptor passed to the callback has a setter.
namespace {
v8::Intercepted CheckSetterPropertyDefineCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  CHECK(desc.has_set());
  CHECK(!desc.has_get());
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDefinerCallbackWithSetter) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;
  v8::Local<v8::FunctionTemplate> templ =
      v8::FunctionTemplate::New(CcTest::isolate());
  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, nullptr, nullptr, nullptr, nullptr,
      CheckSetterPropertyDefineCallback));
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  const char* code =
      "Object.defineProperty(obj, 'x', {set: function() {return 42;}});"
      "obj.x = 17;";
  CHECK_EQ(17, v8_compile(code)
                   ->Run(env.local())
                   .ToLocalChecked()
                   ->Int32Value(env.local())
                   .FromJust());
}

namespace {
std::vector<std::string> definer_calls;
v8::Intercepted LogDefinerCallsAndContinueCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  String::Utf8Value utf8(info.GetIsolate(), name);
  definer_calls.push_back(*utf8);
  return v8::Intercepted::kNo;
}
v8::Intercepted LogDefinerCallsAndStopCallback(
    Local<Name> name, const v8::PropertyDescriptor& desc,
    const v8::PropertyCallbackInfo<void>& info) {
  String::Utf8Value utf8(info.GetIsolate(), name);
  definer_calls.push_back(*utf8);
  return v8::Intercepted::kYes;
}

struct DefineNamedOwnICInterceptorConfig {
  std::string code;
  std::vector<std::string> intercepted_defines;
};

std::vector<DefineNamedOwnICInterceptorConfig> configs{
    {
        R"(
          class ClassWithNormalField extends Base {
            field = (() => {
              Object.defineProperty(
                this,
                'normalField',
                { writable: true, configurable: true, value: 'initial'}
              );
              return 1;
            })();
            normalField = 'written';
            constructor(arg) {
              super(arg);
            }
          }
          new ClassWithNormalField(obj);
          stop ? (obj.field === undefined && obj.normalField === undefined)
            : (obj.field === 1 && obj.normalField === 'written'))",
        {"normalField", "field", "normalField"},  // intercepted defines
    },
    {
        R"(
            let setterCalled = false;
            class ClassWithSetterField extends Base {
              field = (() => {
                Object.defineProperty(
                  this,
                  'setterField',
                  { configurable: true, set(val) { setterCalled = true; } }
                );
                return 1;
              })();
              setterField = 'written';
              constructor(arg) {
                super(arg);
              }
            }
            new ClassWithSetterField(obj);
            !setterCalled &&
              (stop ? (obj.field === undefined && obj.setterField === undefined)
                : (obj.field === 1 && obj.setterField === 'written')))",
        {"setterField", "field", "setterField"},  // intercepted defines
    },
    {
        R"(
          class ClassWithReadOnlyField extends Base {
            field = (() => {
              Object.defineProperty(
                this,
                'readOnlyField',
                { writable: false, configurable: true, value: 'initial'}
              );
              return 1;
            })();
            readOnlyField = 'written';
            constructor(arg) {
              super(arg);
            }
          }
          new ClassWithReadOnlyField(obj);
          stop ? (obj.field === undefined && obj.readOnlyField === undefined)
            : (obj.field === 1 && obj.readOnlyField === 'written'))",
        {"readOnlyField", "field", "readOnlyField"},  // intercepted defines
    },
    {
        R"(
          class ClassWithNonConfigurableField extends Base {
            field = (() => {
              Object.defineProperty(
                this,
                'nonConfigurableField',
                { writable: false, configurable: false, value: 'initial'}
              );
              return 1;
            })();
            nonConfigurableField = 'configured';
            constructor(arg) {
              super(arg);
            }
          }
          let nonConfigurableThrown = false;
          try { new ClassWithNonConfigurableField(obj); }
          catch { nonConfigurableThrown = true; }
          stop ? (!nonConfigurableThrown && obj.field === undefined
                  && obj.nonConfigurableField === undefined)
              : (nonConfigurableThrown && obj.field === 1
                && obj.nonConfigurableField === 'initial'))",
        // intercepted defines
        {"nonConfigurableField", "field", "nonConfigurableField"}}
    // We don't test non-extensible objects here because objects with
    // interceptors cannot prevent extensions.
};
}  // namespace

void CheckPropertyDefinerCallbackInDefineNamedOwnIC(Local<Context> context,
                                                    bool stop) {
  v8_compile(R"(
    class Base {
      constructor(arg) {
        return arg;
      }
    })")
      ->Run(context)
      .ToLocalChecked();

  v8_compile(stop ? "var stop = true;" : "var stop = false;")
      ->Run(context)
      .ToLocalChecked();

  for (auto& config : configs) {
    printf("stop = %s, running...\n%s\n", stop ? "true" : "false",
           config.code.c_str());

    definer_calls.clear();

    // Create the object with interceptors.
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, nullptr, nullptr, nullptr,
        stop ? LogDefinerCallsAndStopCallback
             : LogDefinerCallsAndContinueCallback,
        nullptr));
    Local<Object> obj = templ->GetFunction(context)
                            .ToLocalChecked()
                            ->NewInstance(context)
                            .ToLocalChecked();
    context->Global()->Set(context, v8_str("obj"), obj).FromJust();

    CHECK(v8_compile(config.code.c_str())
              ->Run(context)
              .ToLocalChecked()
              ->IsTrue());
    for (size_t i = 0; i < definer_calls.size(); ++i) {
      printf("define %s\n", definer_calls[i].c_str());
    }

    CHECK_EQ(config.intercepted_defines.size(), definer_calls.size());
    for (size_t i = 0; i < config.intercepted_defines.size(); ++i) {
      CHECK_EQ(config.intercepted_defines[i], definer_calls[i]);
    }
  }
}

THREADED_TEST(PropertyDefinerCallbackInDefineNamedOwnIC) {
  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    CheckPropertyDefinerCallbackInDefineNamedOwnIC(env.local(), true);
  }

  {
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    CheckPropertyDefinerCallbackInDefineNamedOwnIC(env.local(), false);
  }

  {
    i::v8_flags.lazy_feedback_allocation = false;
    i::FlagList::EnforceFlagImplications();
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    CheckPropertyDefinerCallbackInDefineNamedOwnIC(env.local(), true);
  }

  {
    i::v8_flags.lazy_feedback_allocation = false;
    i::FlagList::EnforceFlagImplications();
    LocalContext env;
    v8::HandleScope scope(env->GetIsolate());
    CheckPropertyDefinerCallbackInDefineNamedOwnIC(env.local(), false);
  }
}

namespace {
v8::Intercepted EmptyPropertyDescriptorCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptingPropertyDescriptorCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Intercept the operation and return some descriptor.
  const char* code =
      "var desc = {value: 42};"
      "desc;";
  Local<Value> descriptor = v8_compile(code)
                                ->Run(info.GetIsolate()->GetCurrentContext())
                                .ToLocalChecked();
  info.GetReturnValue().Set(descriptor);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(PropertyDescriptorCallback) {
  v8::HandleScope scope(CcTest::isolate());
  LocalContext env;

  {  // Normal behavior of getOwnPropertyDescriptor() with empty callback.
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, EmptyPropertyDescriptorCallback, nullptr, nullptr,
        nullptr));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj.x = 17; "
        "var desc = Object.getOwnPropertyDescriptor(obj, 'x');"
        "desc.value;";
    CHECK_EQ(17, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }

  {  // Intercept getOwnPropertyDescriptor().
    v8::Local<v8::FunctionTemplate> templ =
        v8::FunctionTemplate::New(CcTest::isolate());
    templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
        nullptr, nullptr, InterceptingPropertyDescriptorCallback, nullptr,
        nullptr, nullptr));
    env->Global()
        ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                              .ToLocalChecked()
                                              ->NewInstance(env.local())
                                              .ToLocalChecked())
        .FromJust();
    const char* code =
        "obj.x = 17; "
        "var desc = Object.getOwnPropertyDescriptor(obj, 'x');"
        "desc.value;";
    CHECK_EQ(42, v8_compile(code)
                     ->Run(env.local())
                     .ToLocalChecked()
                     ->Int32Value(env.local())
                     .FromJust());
  }
}

namespace {
int echo_indexed_call_count = 0;

v8::Intercepted EchoIndexedProperty(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_num(637)
            ->Equals(info.GetIsolate()->GetCurrentContext(), info.Data())
            .FromJust());
  echo_indexed_call_count++;
  info.GetReturnValue().Set(v8_num(index));
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(IndexedPropertyHandlerGetter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      EchoIndexedProperty, nullptr, nullptr, nullptr, nullptr, v8_num(637)));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  Local<Script> script = v8_compile("obj[900]");
  CHECK_EQ(900, script->Run(env.local())
                    .ToLocalChecked()
                    ->Int32Value(env.local())
                    .FromJust());
}


THREADED_TEST(PropertyHandlerInPrototype) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      CheckThisIndexedPropertyHandler, CheckThisIndexedPropertySetter,
      CheckThisIndexedPropertyQuery, CheckThisIndexedPropertyDeleter,
      CheckThisIndexedPropertyEnumerator));

  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      CheckThisNamedPropertyHandler, CheckThisNamedPropertySetter,
      CheckThisNamedPropertyQuery, CheckThisNamedPropertyDeleter,
      CheckThisNamedPropertyEnumerator));

  Local<v8::Object> bottom = templ->GetFunction(env.local())
                                 .ToLocalChecked()
                                 ->NewInstance(env.local())
                                 .ToLocalChecked();
  bottom_global.Reset(isolate, bottom);
  Local<v8::Object> top = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  Local<v8::Object> middle = templ->GetFunction(env.local())
                                 .ToLocalChecked()
                                 ->NewInstance(env.local())
                                 .ToLocalChecked();

  bottom->SetPrototypeV2(env.local(), middle).FromJust();
  middle->SetPrototypeV2(env.local(), top).FromJust();
  env->Global()->Set(env.local(), v8_str("obj"), bottom).FromJust();

  // Indexed and named get.
  CompileRun("obj[0]");
  CompileRun("obj.x");

  // Indexed and named set.
  CompileRun("obj[1] = 42");
  CompileRun("obj.y = 42");

  // Indexed and named query.
  CompileRun("0 in obj");
  CompileRun("'x' in obj");

  // Indexed and named deleter.
  CompileRun("delete obj[0]");
  CompileRun("delete obj.x");

  // Enumerators.
  CompileRun("for (var p in obj) ;");

  bottom_global.Reset();
}

TEST(PropertyHandlerInPrototypeWithDefine) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      CheckThisIndexedPropertyHandler, CheckThisIndexedPropertySetter,
      CheckThisIndexedPropertyDescriptor, CheckThisIndexedPropertyDeleter,
      CheckThisIndexedPropertyEnumerator, CheckThisIndexedPropertyDefiner));

  templ->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      CheckThisNamedPropertyHandler, CheckThisNamedPropertySetter,
      CheckThisNamedPropertyDescriptor, CheckThisNamedPropertyDeleter,
      CheckThisNamedPropertyEnumerator, CheckThisNamedPropertyDefiner));

  Local<v8::Object> bottom = templ->GetFunction(env.local())
                                 .ToLocalChecked()
                                 ->NewInstance(env.local())
                                 .ToLocalChecked();
  bottom_global.Reset(isolate, bottom);
  Local<v8::Object> top = templ->GetFunction(env.local())
                              .ToLocalChecked()
                              ->NewInstance(env.local())
                              .ToLocalChecked();
  Local<v8::Object> middle = templ->GetFunction(env.local())
                                 .ToLocalChecked()
                                 ->NewInstance(env.local())
                                 .ToLocalChecked();

  bottom->SetPrototypeV2(env.local(), middle).FromJust();
  middle->SetPrototypeV2(env.local(), top).FromJust();
  env->Global()->Set(env.local(), v8_str("obj"), bottom).FromJust();

  // Indexed and named get.
  CompileRun("obj[0]");
  CompileRun("obj.x");

  // Indexed and named set.
  CompileRun("obj[1] = 42");
  CompileRun("obj.y = 42");

  // Indexed and named deleter.
  CompileRun("delete obj[0]");
  CompileRun("delete obj.x");

  // Enumerators.
  CompileRun("for (var p in obj) ;");

  // Indexed and named definer.
  CompileRun("Object.defineProperty(obj, 2, {});");
  CompileRun("Object.defineProperty(obj, 'z', {});");

  // Indexed and named propertyDescriptor.
  CompileRun("Object.getOwnPropertyDescriptor(obj, 2);");
  CompileRun("Object.getOwnPropertyDescriptor(obj, 'z');");

  bottom_global.Reset();
}

namespace {
bool is_bootstrapping = false;
v8::Intercepted PrePropertyHandlerGet(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (!is_bootstrapping &&
      v8_str("pre")
          ->Equals(info.GetIsolate()->GetCurrentContext(), key)
          .FromJust()) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(v8_str("PrePropertyHandler: pre"));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted PrePropertyHandlerQuery(
    Local<Name> key, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  if (!is_bootstrapping &&
      v8_str("pre")
          ->Equals(info.GetIsolate()->GetCurrentContext(), key)
          .FromJust()) {
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(PrePropertyHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> desc = v8::FunctionTemplate::New(isolate);
  desc->InstanceTemplate()->SetHandler(v8::NamedPropertyHandlerConfiguration(
      PrePropertyHandlerGet, nullptr, PrePropertyHandlerQuery));
  is_bootstrapping = true;
  LocalContext env(nullptr, desc->InstanceTemplate());
  is_bootstrapping = false;
  CompileRun("var pre = 'Object: pre'; var on = 'Object: on';");
  v8::Local<Value> result_pre = CompileRun("pre");
  CHECK(v8_str("PrePropertyHandler: pre")
            ->Equals(env.local(), result_pre)
            .FromJust());
  v8::Local<Value> result_on = CompileRun("on");
  CHECK(v8_str("Object: on")->Equals(env.local(), result_on).FromJust());
  v8::Local<Value> result_post = CompileRun("post");
  CHECK(result_post.IsEmpty());
}


THREADED_TEST(EmptyInterceptorBreakTransitions) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(CcTest::isolate());
  AddInterceptor(templ, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Constructor"),
            templ->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var o1 = new Constructor;"
      "o1.a = 1;"  // Ensure a and x share the descriptor array.
      "Object.defineProperty(o1, 'x', {value: 10});");
  CompileRun(
      "var o2 = new Constructor;"
      "o2.a = 1;"
      "Object.defineProperty(o2, 'x', {value: 10});");
}


THREADED_TEST(EmptyInterceptorDoesNotShadowJSAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddInterceptor(child, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "var parent = child.__proto__;"
      "Object.defineProperty(parent, 'age', "
      "  {get: function(){ return this.accessor_age; }, "
      "   set: function(v){ this.accessor_age = v; }, "
      "   enumerable: true, configurable: true});"
      "child.age = 10;");
  ExpectBoolean("child.hasOwnProperty('age')", false);
  ExpectInt32("child.age", 10);
  ExpectInt32("child.accessor_age", 10);
}


THREADED_TEST(EmptyInterceptorDoesNotShadowApiAccessors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  auto returns_42 = FunctionTemplate::New(isolate, Returns42);
  parent->PrototypeTemplate()->SetAccessorProperty(v8_str("age"), returns_42);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddInterceptor(child, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "var parent = child.__proto__;");
  ExpectBoolean("child.hasOwnProperty('age')", false);
  ExpectInt32("child.age", 42);
  // Check interceptor followup.
  ExpectInt32(
      "var result;"
      "for (var i = 0; i < 4; ++i) {"
      "  result = child.age;"
      "}"
      "result",
      42);
}


THREADED_TEST(EmptyInterceptorDoesNotAffectJSProperties) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddInterceptor(child, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "var parent = child.__proto__;"
      "parent.name = 'Alice';");
  ExpectBoolean("child.hasOwnProperty('name')", false);
  ExpectString("child.name", "Alice");
  CompileRun("child.name = 'Bob';");
  ExpectString("child.name", "Bob");
  ExpectBoolean("child.hasOwnProperty('name')", true);
  ExpectString("parent.name", "Alice");
}


THREADED_TEST(SwitchFromInterceptorToAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> templ = FunctionTemplate::New(isolate);
  AddAccessor(isolate, templ, v8_str("age"), SimpleGetterCallback,
              SimpleSetterCallback);
  AddInterceptor(templ, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Obj"),
            templ->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var obj = new Obj;"
      "function setAge(i){ obj.age = i; };"
      "for(var i = 0; i <= 10000; i++) setAge(i);");
  // All i < 10000 go to the interceptor.
  ExpectInt32("obj.interceptor_age", 9999);
  // The last i goes to the accessor.
  ExpectInt32("obj.accessor_age", 10000);
}


THREADED_TEST(SwitchFromAccessorToInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> templ = FunctionTemplate::New(isolate);
  AddAccessor(isolate, templ, v8_str("age"), SimpleGetterCallback,
              SimpleSetterCallback);
  AddInterceptor(templ, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Obj"),
            templ->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var obj = new Obj;"
      "function setAge(i){ obj.age = i; };"
      "for(var i = 20000; i >= 9999; i--) setAge(i);");
  // All i >= 10000 go to the accessor.
  ExpectInt32("obj.accessor_age", 10000);
  // The last i goes to the interceptor.
  ExpectInt32("obj.interceptor_age", 9999);
}


THREADED_TEST(SwitchFromInterceptorToAccessorWithInheritance) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddAccessor(isolate, parent, v8_str("age"), SimpleGetterCallback,
              SimpleSetterCallback);
  AddInterceptor(child, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "function setAge(i){ child.age = i; };"
      "for(var i = 0; i <= 10000; i++) setAge(i);");
  // All i < 10000 go to the interceptor.
  ExpectInt32("child.interceptor_age", 9999);
  // The last i goes to the accessor.
  ExpectInt32("child.accessor_age", 10000);
}


THREADED_TEST(SwitchFromAccessorToInterceptorWithInheritance) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> parent = FunctionTemplate::New(isolate);
  Local<FunctionTemplate> child = FunctionTemplate::New(isolate);
  child->Inherit(parent);
  AddAccessor(isolate, parent, v8_str("age"), SimpleGetterCallback,
              SimpleSetterCallback);
  AddInterceptor(child, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "function setAge(i){ child.age = i; };"
      "for(var i = 20000; i >= 9999; i--) setAge(i);");
  // All i >= 10000 go to the accessor.
  ExpectInt32("child.accessor_age", 10000);
  // The last i goes to the interceptor.
  ExpectInt32("child.interceptor_age", 9999);
}


THREADED_TEST(SwitchFromInterceptorToJSAccessor) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(CcTest::isolate());
  AddInterceptor(templ, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Obj"),
            templ->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var obj = new Obj;"
      "function setter(i) { this.accessor_age = i; };"
      "function getter() { return this.accessor_age; };"
      "function setAge(i) { obj.age = i; };"
      "Object.defineProperty(obj, 'age', { get:getter, set:setter });"
      "for(var i = 0; i <= 10000; i++) setAge(i);");
  // All i < 10000 go to the interceptor.
  ExpectInt32("obj.interceptor_age", 9999);
  // The last i goes to the JavaScript accessor.
  ExpectInt32("obj.accessor_age", 10000);
  // The installed JavaScript getter is still intact.
  // This last part is a regression test for issue 1651 and relies on the fact
  // that both interceptor and accessor are being installed on the same object.
  ExpectInt32("obj.age", 10000);
  ExpectBoolean("obj.hasOwnProperty('age')", true);
  ExpectUndefined("Object.getOwnPropertyDescriptor(obj, 'age').value");
}


THREADED_TEST(SwitchFromJSAccessorToInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(CcTest::isolate());
  AddInterceptor(templ, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Obj"),
            templ->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var obj = new Obj;"
      "function setter(i) { this.accessor_age = i; };"
      "function getter() { return this.accessor_age; };"
      "function setAge(i) { obj.age = i; };"
      "Object.defineProperty(obj, 'age', { get:getter, set:setter });"
      "for(var i = 20000; i >= 9999; i--) setAge(i);");
  // All i >= 10000 go to the accessor.
  ExpectInt32("obj.accessor_age", 10000);
  // The last i goes to the interceptor.
  ExpectInt32("obj.interceptor_age", 9999);
  // The installed JavaScript getter is still intact.
  // This last part is a regression test for issue 1651 and relies on the fact
  // that both interceptor and accessor are being installed on the same object.
  ExpectInt32("obj.age", 10000);
  ExpectBoolean("obj.hasOwnProperty('age')", true);
  ExpectUndefined("Object.getOwnPropertyDescriptor(obj, 'age').value");
}


THREADED_TEST(SwitchFromInterceptorToProperty) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> parent = FunctionTemplate::New(CcTest::isolate());
  Local<FunctionTemplate> child = FunctionTemplate::New(CcTest::isolate());
  child->Inherit(parent);
  AddInterceptor(child, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "function setAge(i){ child.age = i; };"
      "for(var i = 0; i <= 10000; i++) setAge(i);");
  // All i < 10000 go to the interceptor.
  ExpectInt32("child.interceptor_age", 9999);
  // The last i goes to child's own property.
  ExpectInt32("child.age", 10000);
}


THREADED_TEST(SwitchFromPropertyToInterceptor) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> parent = FunctionTemplate::New(CcTest::isolate());
  Local<FunctionTemplate> child = FunctionTemplate::New(CcTest::isolate());
  child->Inherit(parent);
  AddInterceptor(child, InterceptorGetter, InterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Child"),
            child->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var child = new Child;"
      "function setAge(i){ child.age = i; };"
      "for(var i = 20000; i >= 9999; i--) setAge(i);");
  // All i >= 10000 go to child's own property.
  ExpectInt32("child.age", 10000);
  // The last i goes to the interceptor.
  ExpectInt32("child.interceptor_age", 9999);
}

namespace {
bool interceptor_for_hidden_properties_called;
v8::Intercepted InterceptorForHiddenProperties(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  interceptor_for_hidden_properties_called = true;
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(NoSideEffectPropertyHandler) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;

  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      EmptyInterceptorGetter, EmptyInterceptorSetter, EmptyInterceptorQuery,
      EmptyInterceptorDeleter, EmptyInterceptorEnumerator));
  v8::Local<v8::Object> object =
      templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), object).FromJust();

  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj.x"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj.x = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("'x' in obj"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("delete obj.x"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  // Wrap the variable declaration since declaring globals is a side effect.
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("(function() { for (var p in obj) ; })()"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());

  // Side-effect-free version.
  Local<ObjectTemplate> templ2 = ObjectTemplate::New(isolate);
  templ2->SetHandler(v8::NamedPropertyHandlerConfiguration(
      EmptyInterceptorGetter, EmptyInterceptorSetter, EmptyInterceptorQuery,
      EmptyInterceptorDeleter, EmptyInterceptorEnumerator,
      v8::Local<v8::Value>(), v8::PropertyHandlerFlags::kHasNoSideEffect));
  v8::Local<v8::Object> object2 =
      templ2->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj2"), object2).FromJust();

  v8::debug::EvaluateGlobal(
      isolate, v8_str("obj2.x"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("obj2.x = 1"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("'x' in obj2"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
  CHECK(v8::debug::EvaluateGlobal(
            isolate, v8_str("delete obj2.x"),
            v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
            .IsEmpty());
  v8::debug::EvaluateGlobal(
      isolate, v8_str("(function() { for (var p in obj2) ; })()"),
      v8::debug::EvaluateGlobalMode::kDisableBreaksAndThrowOnSideEffect)
      .ToLocalChecked();
}

THREADED_TEST(HiddenPropertiesWithInterceptors) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);

  interceptor_for_hidden_properties_called = false;

  v8::Local<v8::Private> key =
      v8::Private::New(isolate, v8_str("api-test::hidden-key"));

  // Associate an interceptor with an object and start setting hidden values.
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = fun_templ->InstanceTemplate();
  instance_templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorForHiddenProperties));
  Local<v8::Function> function =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  Local<v8::Object> obj =
      function->NewInstance(context.local()).ToLocalChecked();
  CHECK(obj->SetPrivate(context.local(), key, v8::Integer::New(isolate, 2302))
            .FromJust());
  CHECK_EQ(2302, obj->GetPrivate(context.local(), key)
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  CHECK(!interceptor_for_hidden_properties_called);
}

namespace {
v8::Intercepted XPropertyGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(info.Data()->IsUndefined());
  info.GetReturnValue().Set(property);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(NamedInterceptorPropertyRead) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(XPropertyGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  Local<Script> script = v8_compile("obj.x");
  for (int i = 0; i < 10; i++) {
    Local<Value> result = script->Run(context.local()).ToLocalChecked();
    CHECK(result->Equals(context.local(), v8_str("x")).FromJust());
  }
}


THREADED_TEST(NamedInterceptorDictionaryIC) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(XPropertyGetter));
  LocalContext context;
  // Create an object with a named interceptor.
  context->Global()
      ->Set(context.local(), v8_str("interceptor_obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  Local<Script> script = v8_compile("interceptor_obj.x");
  for (int i = 0; i < 10; i++) {
    Local<Value> result = script->Run(context.local()).ToLocalChecked();
    CHECK(result->Equals(context.local(), v8_str("x")).FromJust());
  }
  // Create a slow case object and a function accessing a property in
  // that slow case object (with dictionary probing in generated
  // code). Then force object with a named interceptor into slow-case,
  // pass it to the function, and check that the interceptor is called
  // instead of accessing the local property.
  Local<Value> result = CompileRun(
      "function get_x(o) { return o.x; };"
      "var obj = { x : 42, y : 0 };"
      "delete obj.y;"
      "for (var i = 0; i < 10; i++) get_x(obj);"
      "interceptor_obj.x = 42;"
      "interceptor_obj.y = 10;"
      "delete interceptor_obj.y;"
      "get_x(interceptor_obj)");
  CHECK(result->Equals(context.local(), v8_str("x")).FromJust());
}


THREADED_TEST(NamedInterceptorDictionaryICMultipleContext) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<Context> context1 = Context::New(isolate);

  context1->Enter();
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(XPropertyGetter));
  // Create an object with a named interceptor.
  v8::Local<v8::Object> object = templ->NewInstance(context1).ToLocalChecked();
  context1->Global()
      ->Set(context1, v8_str("interceptor_obj"), object)
      .FromJust();

  // Force the object into the slow case.
  CompileRun(
      "interceptor_obj.y = 0;"
      "delete interceptor_obj.y;");
  context1->Exit();

  {
    // Introduce the object into a different context.
    // Repeat named loads to exercise ICs.
    LocalContext context2;
    context2->Global()
        ->Set(context2.local(), v8_str("interceptor_obj"), object)
        .FromJust();
    Local<Value> result = CompileRun(
        "function get_x(o) { return o.x; }"
        "interceptor_obj.x = 42;"
        "for (var i=0; i != 10; i++) {"
        "  get_x(interceptor_obj);"
        "}"
        "get_x(interceptor_obj)");
    // Check that the interceptor was actually invoked.
    CHECK(result->Equals(context2.local(), v8_str("x")).FromJust());
  }

  // Return to the original context and force some object to the slow case
  // to cause the NormalizedMapCache to verify.
  context1->Enter();
  CompileRun("var obj = { x : 0 }; delete obj.x;");
  context1->Exit();
}

namespace {
v8::Intercepted SetXOnPrototypeGetter(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // Set x on the prototype object and do not handle the get request.
  v8::Local<v8::Value> proto = info.HolderV2()->GetPrototypeV2();
  proto.As<v8::Object>()
      ->Set(info.GetIsolate()->GetCurrentContext(), v8_str("x"),
            v8::Integer::New(info.GetIsolate(), 23))
      .FromJust();
  return v8::Intercepted::kNo;
}
}  // namespace

// This is a regression test for http://crbug.com/20104. Map
// transitions should not interfere with post interceptor lookup.
THREADED_TEST(NamedInterceptorMapTransitionRead) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> function_template =
      v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_template =
      function_template->InstanceTemplate();
  instance_template->SetHandler(
      v8::NamedPropertyHandlerConfiguration(SetXOnPrototypeGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("F"),
            function_template->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  // Create an instance of F and introduce a map transition for x.
  CompileRun("var o = new F(); o.x = 23;");
  // Create an instance of F and invoke the getter. The result should be 23.
  Local<Value> result = CompileRun("o = new F(); o.x");
  CHECK_EQ(23, result->Int32Value(context.local()).FromJust());
}

namespace {
v8::Intercepted IndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (index == 37) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(v8_num(625));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexedPropertySetter(
    uint32_t index, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  if (index == 39) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

THREADED_TEST(IndexedInterceptorWithIndexedAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      IndexedPropertyGetter, IndexedPropertySetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  Local<Script> getter_script =
      v8_compile("obj.__defineGetter__(\"3\", function(){return 5;});obj[3];");
  Local<Script> setter_script = v8_compile(
      "obj.__defineSetter__(\"17\", function(val){this.foo = val;});"
      "obj[17] = 23;"
      "obj.foo;");
  Local<Script> interceptor_setter_script = v8_compile(
      "obj.__defineSetter__(\"39\", function(val){this.foo = \"hit\";});"
      "obj[39] = 47;"
      "obj.foo;");  // This setter should not run, due to the interceptor.
  Local<Script> interceptor_getter_script = v8_compile("obj[37];");
  Local<Value> result = getter_script->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(5)->Equals(context.local(), result).FromJust());
  result = setter_script->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(23)->Equals(context.local(), result).FromJust());
  result = interceptor_setter_script->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(23)->Equals(context.local(), result).FromJust());
  result = interceptor_getter_script->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(625)->Equals(context.local(), result).FromJust());
}

namespace {
v8::Intercepted UnboxedDoubleIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (index < 25) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(v8_num(index));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted UnboxedDoubleIndexedPropertySetter(
    uint32_t index, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  if (index < 25) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

void UnboxedDoubleIndexedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  // Force the list of returned keys to be stored in a FastDoubleArray.
  Local<Script> indexed_property_names_script = v8_compile(
      "keys = new Array(); keys[125000] = 1;"
      "for(i = 0; i < 80000; i++) { keys[i] = i; };"
      "keys.length = 25; keys;");
  Local<Value> result =
      indexed_property_names_script->Run(info.GetIsolate()->GetCurrentContext())
          .ToLocalChecked();
  info.GetReturnValue().Set(result.As<v8::Array>());
}
}  // namespace

// Make sure that the the interceptor code in the runtime properly handles
// merging property name lists for double-array-backed arrays.
THREADED_TEST(IndexedInterceptorUnboxed
```