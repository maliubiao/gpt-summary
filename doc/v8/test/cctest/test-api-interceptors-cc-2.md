Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api-interceptors.cc`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename `test-api-interceptors.cc` and the content containing `THREADED_TEST` macros strongly suggest this file contains unit tests for V8's API interceptor functionality. Interceptors allow custom JavaScript behavior when accessing or modifying object properties.

2. **Analyze Individual Tests:**  Go through each `THREADED_TEST` block and understand what aspect of interceptors it's testing. Look for key API calls like `AddInterceptor`, `SetHandler` with `NamedPropertyHandlerConfiguration` or `IndexedPropertyHandlerConfiguration`, and the JavaScript code being executed within each test.

3. **Group Tests by Functionality:** Notice patterns and group tests that focus on the same interceptor behavior. For example, multiple tests cover shadowing read-only properties, empty interceptors, interceptors interacting with symbols, and different aspects of property definer callbacks.

4. **Relate C++ Concepts to JavaScript:** Connect the C++ API elements (like `InterceptorGetter`, `InterceptorSetter`, `NamedPropertyHandlerConfiguration`) to their corresponding JavaScript concepts (property access, assignment, `Object.defineProperty`, `Object.freeze`, `Object.getOwnPropertyDescriptor`).

5. **Provide Concrete JavaScript Examples:**  For functionalities that have a direct JavaScript equivalent, create concise examples that demonstrate the behavior being tested in the C++ code. This makes the explanation more accessible to those familiar with JavaScript.

6. **Identify Potential Programming Errors:**  Based on the test cases, infer common mistakes developers might make when working with interceptors or related JavaScript features. For example, confusion about how interceptors interact with read-only properties or accessors.

7. **Address Specific Instructions:** Ensure all the user's specific requests are addressed:
    * Confirm it's C++ and not Torque.
    * Provide JavaScript examples where applicable.
    * Explain code logic with assumptions and outputs.
    * Illustrate common programming errors.
    * Clearly state that this is part 3 of 8 and summarize the overall functionality of *this* part.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  Focus solely on listing each test case's purpose.
* **Refinement:** Realize that grouping related tests provides a more coherent understanding of the overall functionality.
* **Initial Thought:** Simply describe the C++ API calls.
* **Refinement:** Emphasize the *JavaScript behavior* that these API calls influence, making the explanation more relevant to the user's likely context (understanding V8 internals and their effect on JavaScript).
* **Initial Thought:**  Provide generic programming error examples.
* **Refinement:** Tailor the error examples to the specific scenarios tested in the code (e.g., assuming an interceptor will prevent writing to a read-only prototype property).

By following these steps and iteratively refining the explanation, a comprehensive and informative summary of the code's functionality can be generated.
`v8/test/cctest/test-api-interceptors.cc` 是一个 V8 的 C++ 源代码文件，它包含了一系列的单元测试，用于测试 V8 引擎中 **API 拦截器 (API interceptors)** 的功能。

**功能归纳（第 3 部分）:**

这部分代码主要测试了以下关于 API 拦截器的功能：

* **拦截器与只读原型属性的交互:** 验证了当对象原型链上存在只读属性时，拦截器如何影响属性的写入操作。
* **空拦截器 (Empty Interceptor) 的行为:** 测试了当使用没有自定义行为的空拦截器时，对于属性访问和全局对象的影响。
* **传统拦截器 (Legacy Interceptor) 与 Symbol 的交互:**  验证了较旧版本的拦截器是否能看到 Symbol 类型的属性。
* **通用拦截器 (Generic Interceptor) 与 Symbol 的交互:** 测试了新的通用拦截器能够处理 Symbol 类型的属性，并能区分 String 类型的属性和 Symbol 类型的属性。
* **命名属性处理器 (Named Property Handler) 的 Getter:** 测试了使用命名属性处理器配置的 `get` 拦截器，并验证了其调用次数和返回值。
* **属性定义拦截回调 (Property Definer Callback):**  这是本部分的核心内容，测试了当使用 `Object.defineProperty()` 定义属性时，V8 提供的拦截回调机制。 具体测试了：
    * 拦截 `defineProperty` 操作本身。
    * 拦截时传入的属性描述符 (PropertyDescriptor) 的正确性，包括 `writable`, `value`, `enumerable`, `configurable`, `get`, `set` 等属性。
    * 拦截器是否能阻止 `defineProperty` 的操作。
    * 针对索引属性的 `defineProperty` 拦截。
    * 拦截 `Object.freeze()` 操作。
    * 传递给回调的描述符中 `enumerable`, `configurable`, `writable` 属性的正确性。
    * 传递给回调的描述符中是否包含 `get` 或 `set` 函数。
    * 在类字段初始化过程中，`defineProperty` 的拦截行为。
* **属性描述符回调 (Property Descriptor Callback):** 测试了 `Object.getOwnPropertyDescriptor()` 的拦截机制，验证了拦截器是否能影响该方法的返回值。

**关于文件类型:**

`v8/test/cctest/test-api-interceptors.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**与 JavaScript 功能的关系及示例:**

API 拦截器允许 C++ 代码介入 JavaScript 对象的属性访问和修改过程，从而实现自定义的行为。

**1. 拦截器与只读原型属性:**

```javascript
let p = {};
Object.defineProperty(p, 'x', { value: 153, writable: false });
let o = {};
o.__proto__ = p;
let r = { __proto__: o };

try {
  r.x = 10; // 尝试写入继承自原型的只读属性
} catch (e) {
  console.error(e); // TypeError: Cannot set property x of #<Object> which has only a getter
}
```

在 `InterceptorShadowsReadOnlyProperty` 测试中，拦截器声称拥有可写属性 'x'，即使原型链上有只读属性，写入操作也不会抛出异常。这展示了拦截器可以覆盖默认的属性查找行为。

**2. 空拦截器:**

```javascript
globalThis.__proto__ = {}; // 设置全局对象的原型
x = 10; // 在非严格模式下，会创建全局变量 x
console.log(x); // 10
```

`EmptyInterceptorVsStoreGlobalICs` 测试了空拦截器在严格模式和非严格模式下对全局变量赋值的影响。在严格模式下，对未声明的变量赋值会抛出 `ReferenceError`，而空拦截器不会阻止这个行为。

**3. 通用拦截器与 Symbol:**

```javascript
const ageSymbol = Symbol('age');
let obj = {};
obj[ageSymbol] = 25;
console.log(obj[ageSymbol]); // 25
```

`GenericInterceptorDoesSeeSymbols` 测试了通用拦截器可以拦截对 Symbol 类型属性的访问。

**4. 属性定义拦截回调:**

```javascript
let obj = {};
Object.defineProperty(obj, 'y', { value: 42, writable: false });
console.log(Object.getOwnPropertyDescriptor(obj, 'y'));
// 输出: { value: 42, writable: false, enumerable: false, configurable: false }
```

`PropertyDefinerCallback` 系列测试模拟了当 JavaScript 代码调用 `Object.defineProperty` 时，V8 如何调用 C++ 中设置的拦截回调，并传递相关的属性描述符信息。

**代码逻辑推理和假设输入/输出:**

**示例： `InterceptorDoesNotThrowOnReadOnlyPrototype` 测试**

**假设输入:**

* 创建一个空对象 `o`。
* 创建一个对象 `p`，并在其上定义一个只读属性 `x`，值为 153。
* 将 `o` 的原型设置为 `p`。
* 循环 20 次，每次创建一个新对象 `r`，并将 `r` 的原型设置为 `o`。
* 尝试给 `r.x` 赋值不同的值。

**代码逻辑:**

由于 `r` 的原型链上有只读属性 `x`，并且没有拦截器干预，尝试给 `r.x` 赋值会抛出 `TypeError` 异常。`try...catch` 块会捕获这些异常，并递增 `result` 计数器。

**预期输出:**

`result` 的值为 20，因为循环了 20 次，每次赋值都会抛出异常。

**用户常见的编程错误:**

* **假设拦截器会阻止所有属性操作:** 开发者可能会错误地认为设置了拦截器后，某些操作（如写入只读属性）会自动被阻止。然而，拦截器需要显式地处理这些情况，否则 V8 引擎的默认行为仍然会生效。
    ```javascript
    // 错误示例：假设拦截器会阻止写入只读属性
    let obj = {};
    Object.defineProperty(obj, 'readOnlyProp', { value: 10, writable: false });

    // 设置一个可能没有处理写入只读属性情况的拦截器
    // ...

    obj.readOnlyProp = 20; // 仍然会抛出 TypeError，因为拦截器可能没有阻止
    ```

* **不理解属性描述符:** 在使用属性定义拦截回调时，开发者可能不理解 `PropertyDescriptor` 中各个属性的含义和作用，导致拦截逻辑出现错误。

* **混淆不同类型的拦截器:**  传统拦截器和通用拦截器在处理 Symbol 类型的属性时有差异，开发者可能没有意识到这一点。

**总结:**

这部分 `test-api-interceptors.cc` 主要关注于测试 V8 引擎 API 拦截器的各种核心功能，特别是它们与原型链、只读属性、Symbol 以及 `Object.defineProperty` 的交互。通过这些测试，可以确保 V8 的拦截器机制能够按照预期工作，并为开发者提供灵活的 JavaScript 行为定制能力。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
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
        "var desc = Object.getOwnPro
"""


```