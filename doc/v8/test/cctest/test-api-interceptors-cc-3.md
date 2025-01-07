Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api-interceptors.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename and the code itself clearly indicate that this file is testing the V8 API related to "interceptors".

2. **Analyze individual tests:**  Each `THREADED_TEST` or `TEST` macro defines a separate test case. Examine what each test is doing. Look for patterns in the setup and assertions.

3. **Categorize test functionalities:** Group similar tests together based on the feature they are testing. For example, tests involving `NamedPropertyHandlerConfiguration` are related to named property interceptors, and those with `IndexedPropertyHandlerConfiguration` are for indexed property interceptors.

4. **Look for JavaScript interactions:** The code often uses `v8_compile` and `Run` to execute JavaScript code within the test. Identify these parts and understand how the JavaScript interacts with the C++ interceptor setup.

5. **Address specific instructions:**  The prompt asks about `.tq` files (not applicable here), JavaScript examples, logic reasoning (input/output), common programming errors, and the current part number.

6. **Synthesize a summary:** Combine the categorized functionalities into a concise overview of what the code tests.

**Mental Walkthrough of the Code:**

* **Basic Interceptor Functionality:**  Several tests (`NamedPropertyHandlerGetter`, `IndexedPropertyHandlerGetter`) set up interceptors and then execute JavaScript code that triggers them. The checks verify that the interceptors are called and behave as expected.
* **Interceptor Context:** The `PropertyHandlerData` test checks if data passed to the interceptor is correctly received.
* **Interceptors in Prototypes:** Tests like `PropertyHandlerInPrototype` and `PropertyHandlerInPrototypeWithDefine` investigate how interceptors work in the prototype chain.
* **Pre- and Post- Interceptors:** The `PrePropertyHandler` test examines the behavior of pre-property handlers.
* **Interaction with Other V8 Features:**  Several tests focus on how interceptors interact with accessors (both API and JavaScript defined), regular properties, and map transitions. These tests often involve setting up both interceptors and other property mechanisms and observing the order of execution or shadowing.
* **Empty Interceptors:** Tests with `EmptyInterceptorGetter` and `EmptyInterceptorSetter` likely explore scenarios where interceptors exist but don't actively handle the property access.
* **Side Effects:** The `NoSideEffectPropertyHandler` test checks if interceptors can be marked as having no side effects for optimizations.
* **Hidden Properties:** The `HiddenPropertiesWithInterceptors` test confirms that interceptors are not called for private (hidden) properties.
* **IC (Inline Cache) Behavior:** Tests like `NamedInterceptorDictionaryIC` and `NamedInterceptorDictionaryICMultipleContext` ensure that interceptors work correctly with V8's optimization mechanisms.

**Considering the Specific Instructions:**

* **`.tq` check:**  The code ends in `.cc`, so this isn't a Torque file.
* **JavaScript examples:**  The `v8_compile` and `Run` calls provide direct JavaScript examples within the tests.
* **Logic reasoning:** The tests are designed to have predictable outcomes based on the interceptor setup and JavaScript execution. We can infer input (JavaScript code) and expected output (assertions).
* **Common programming errors:**  The tests themselves implicitly highlight potential errors when working with interceptors, such as incorrect data passing, unexpected shadowing, or issues with prototype inheritance.

**Final Summary Construction:** Based on this analysis, construct a summary that covers these key areas.
这是提供的 `v8/test/cctest/test-api-interceptors.cc` 源代码的第 4 部分，总共 8 部分。根据代码内容，我们可以归纳一下这部分的功能是 **测试 V8 引擎中属性拦截器 (property interceptors) 的各种特性和行为**。

具体来说，这部分测试了以下几个方面：

**1. 基础的命名和索引属性拦截器的 getter 功能:**
   - `NamedPropertyHandlerGetter`: 测试为一个对象设置命名属性拦截器，并在 JavaScript 中访问该属性时，拦截器能够正确返回预设的值。
   - `IndexedPropertyHandlerGetter`: 测试为一个对象设置索引属性拦截器，并在 JavaScript 中通过索引访问该属性时，拦截器能够正确返回基于索引的值。

**2. 属性拦截器在原型链上的行为:**
   - `PropertyHandlerInPrototype`: 测试当属性拦截器定义在对象的原型链上时，get、set、query (in 操作符)、delete 和枚举 (for...in) 等操作是否能够正确触发拦截器。
   - `PropertyHandlerInPrototypeWithDefine`:  与上一个测试类似，但增加了对 `Object.defineProperty` 和 `Object.getOwnPropertyDescriptor` 的测试，验证拦截器是否能与属性描述符的定义和获取正确交互。

**3. 前置属性拦截器 (PrePropertyHandler):**
   - `PrePropertyHandler`: 测试在属性查找之前执行的拦截器，它可以提前处理属性访问请求，阻止后续的默认属性查找。

**4. 空拦截器 (EmptyInterceptor) 的行为:**
   - `EmptyInterceptorBreakTransitions`: 测试空拦截器是否会影响对象的内部结构和属性存储方式 (map transitions)。
   - `EmptyInterceptorDoesNotShadowJSAccessors`:  测试空拦截器不会影响 JavaScript 定义的访问器属性 (getters/setters)。
   - `EmptyInterceptorDoesNotShadowApiAccessors`: 测试空拦截器不会影响通过 C++ API 定义的访问器属性。
   - `EmptyInterceptorDoesNotAffectJSProperties`: 测试空拦截器不会影响对象自身的 JavaScript 属性。

**5. 拦截器与访问器 (Accessors) 之间的切换:**
   - `SwitchFromInterceptorToAccessor`: 测试当先通过拦截器处理属性访问，然后定义访问器属性后，属性访问会切换到访问器。
   - `SwitchFromAccessorToInterceptor`: 测试当先通过访问器处理属性访问，然后添加拦截器后，属性访问会切换到拦截器。
   -  `SwitchFromInterceptorToAccessorWithInheritance` 和 `SwitchFromAccessorToInterceptorWithInheritance`:  与上述测试类似，但考虑了继承的情况。
   - `SwitchFromInterceptorToJSAccessor` 和 `SwitchFromJSAccessorToInterceptor`: 测试拦截器与 JavaScript 定义的访问器属性之间的切换。

**6. 拦截器与普通属性之间的切换:**
   - `SwitchFromInterceptorToProperty`: 测试当先通过拦截器处理属性访问，然后直接在对象上设置属性后，属性访问会切换到直接访问对象属性。
   - `SwitchFromPropertyToInterceptor`: 测试当先直接访问对象属性，然后添加拦截器后，属性访问会切换到拦截器。

**7. 无副作用的属性处理函数 (NoSideEffectPropertyHandler):**
   - `NoSideEffectPropertyHandler`: 测试可以标记为无副作用的属性处理函数，这允许 V8 进行某些优化，例如在调试模式下跳过这些处理函数以避免不必要的副作用。

**8. 拦截器与隐藏属性 (Hidden Properties) 的交互:**
   - `HiddenPropertiesWithInterceptors`: 测试属性拦截器不会被用于访问对象的隐藏属性（通过 `v8::Private` 创建）。

**9. 命名拦截器的属性读取和内联缓存 (Inline Cache, IC):**
   - `NamedInterceptorPropertyRead`: 测试命名拦截器在属性读取时的基本功能。
   - `NamedInterceptorDictionaryIC`: 测试命名拦截器在对象属性存储为字典模式时的内联缓存行为。
   - `NamedInterceptorDictionaryICMultipleContext`: 测试命名拦截器在跨多个 V8 上下文时的内联缓存行为。

**10. 命名拦截器和 Map 转换 (Map Transition):**
    - `NamedInterceptorMapTransitionRead`: 测试命名拦截器不会干扰 V8 的内部对象布局优化 (map transitions)。

**11. 索引拦截器与索引访问器 (Indexed Accessors) 的交互:**
    - `IndexedInterceptorWithIndexedAccessor`: 测试索引拦截器与通过 `__defineGetter__` 和 `__defineSetter__` 定义的索引访问器之间的优先级和交互。

**12. 索引拦截器和非装箱双精度数组 (Unboxed Double Array):**
    - `IndexedInterceptorUnboxed`: 测试索引拦截器在处理存储非装箱双精度浮点数的数组时的行为，并确保枚举器能够正确处理这种情况。

**这个文件不是 Torque 源代码。** 因为它的后缀是 `.cc`，而不是 `.tq`。

**与 JavaScript 的功能关系及举例:**

属性拦截器允许 C++ 代码拦截和自定义 JavaScript 对象的属性访问行为。这为 V8 的嵌入器提供了强大的能力，可以实现一些高级特性，例如：

```javascript
// 假设在 C++ 中为名为 'myObj' 的对象设置了命名属性拦截器

console.log(myObj.someProperty); // 访问 'someProperty' 时，会先调用 C++ 的拦截器

myObj.anotherProperty = 42; // 设置 'anotherProperty' 的值时，也会先调用 C++ 的拦截器

'dynamicProperty' in myObj; // 使用 'in' 操作符查询属性是否存在时，也会调用 C++ 的拦截器

delete myObj.deletableProperty; // 删除属性时，同样会调用 C++ 的拦截器

for (let key in myObj) {
  console.log(key); // 枚举属性时，C++ 的拦截器可以影响枚举结果
}

Object.defineProperty(myObj, 'configurableProp', {
  value: 10,
  configurable: true
}); // 定义属性时，相关的拦截器也会被调用
```

**代码逻辑推理及假设输入与输出:**

以 `NamedPropertyHandlerGetter` 测试为例：

**假设输入 (C++ 代码设置):**

- 创建一个对象模板 `templ`。
- 为 `templ` 设置一个命名属性处理配置，其中 getter 函数是 `Return42`.
- 创建一个上下文 `env`。
- 在全局对象中创建一个名为 "obj" 的对象，该对象是 `templ` 的实例。

**假设输入 (JavaScript 代码):**

- `obj.x`

**代码逻辑推理:**

1. 当 JavaScript 执行 `obj.x` 时，V8 引擎会尝试查找 "obj" 对象的 "x" 属性。
2. 由于 "obj" 对象设置了命名属性拦截器，V8 会调用配置的 getter 函数 `Return42`。
3. `Return42` 函数返回一个值为 42 的 `v8::Integer`。
4. JavaScript 的属性访问操作最终得到值 42。

**预期输出:**

- `CHECK_EQ(42, v8_compile(code) ...)` 断言会成功，因为 JavaScript 代码 `obj.x` 的执行结果是 42。

**涉及用户常见的编程错误:**

- **忘记在 C++ 拦截器中正确设置返回值:**  如果拦截器的 getter 函数没有调用 `info.GetReturnValue().Set(...)`，JavaScript 代码尝试访问该属性时会得到 `undefined`，这可能不是预期的行为。
  ```c++
  // 错误的示例：忘记设置返回值
  v8::Intercepted MyGetter(
      Local<Name> property, const v8::PropertyCallbackInfo<v8::Value>& info) {
    // ... 一些处理逻辑 ...
    return v8::Intercepted::kYes;
  }

  // JavaScript 中访问该属性会得到 undefined
  // console.log(myObj.someProperty); // 输出 undefined
  ```

- **在拦截器中执行过于耗时的操作:** 属性拦截器会在 JavaScript 引擎执行期间被同步调用，如果拦截器中的逻辑过于复杂或耗时，可能会导致 JavaScript 代码执行缓慢甚至卡顿。

- **对 `info.This()` 和 `info.Holder()` 的理解不正确:** `info.This()` 返回的是属性访问的接收者对象（在原型链查找中可能是原型对象），而 `info.Holder()` 返回的是设置了拦截器的对象。在继承场景下，理解它们的区别至关重要。

**总结一下它的功能:**

总而言之，`v8/test/cctest/test-api-interceptors.cc` 的这一部分专注于 **全面测试 V8 引擎提供的属性拦截器 API 的各种功能、行为和边界情况**，包括基本操作、与原型链的交互、与其他 V8 特性（如访问器、普通属性、隐藏属性）的协作、以及在不同优化场景下的表现，从而确保该 API 的稳定性和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共8部分，请归纳一下它的功能

"""
pertyDescriptor(obj, 'x');"
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
"""


```