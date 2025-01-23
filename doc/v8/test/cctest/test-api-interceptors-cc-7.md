Response:
The user wants a summary of the C++ code provided, which is a V8 test file.

Here's a breakdown of how to approach this:

1. **High-Level Understanding:**  The filename `test-api-interceptors.cc` strongly suggests the code tests the API for intercepting property access (get, set, enumerate, etc.) in JavaScript objects.

2. **Identify Key Components:** Look for patterns and recurring elements. In this code, the repeated use of `ObjectTemplate::SetHandler` with various configurations (getters, setters, query, enumeration) stands out. Also, the `Expect...` functions indicate assertions about JavaScript behavior.

3. **Categorize Tests:**  Notice different test functions (`THREADED_TEST`, `TEST`). Try to group them based on the specific aspect of interceptors they are testing (e.g., named properties, indexed properties, enumeration behavior, interaction with `for...in`, specific bug regressions).

4. **Explain Interceptor Concepts:**  Briefly define what property interceptors are in V8 and their purpose.

5. **Illustrate with JavaScript:** For each category of tests, provide a corresponding JavaScript example to demonstrate the functionality being tested. This will bridge the gap between the C++ implementation and user-facing behavior.

6. **Infer Logic and Examples:** Analyze the `Expect...` calls to understand the intended behavior and create simple JavaScript snippets that would lead to similar outcomes. Pay attention to enumerable vs. non-enumerable properties.

7. **Identify Potential Errors:** Think about common mistakes developers might make when working with JavaScript properties and how the tested interceptor features could be involved.

8. **Address Specific Instructions:** Check if the filename ends with `.tq` (it doesn't), so no need to discuss Torque. Confirm that the code relates to JavaScript functionality (it does).

9. **Final Summary:**  Synthesize the key takeaways from the different test cases into a concise overview of the file's purpose.

**Pre-computation/Pre-analysis (Mental Walkthrough):**

* **Named Property Interceptors:** The `ConcatNamedPropertyGetter` suggests a getter that concatenates the property name. The `RestrictiveNamedQuery` likely filters which properties are visible during enumeration.
* **Indexed Property Interceptors:** Similar to named properties, but for array indices.
* **Enumeration:**  Focus on how different interceptors influence the results of `Object.keys()`, `Object.values()`, `Object.entries()`, and `for...in` loops. The `enumerable` attribute is key here.
* **Bug Regressions:**  These tests specifically target and fix known issues. Understand the scenario being tested in each regression to provide relevant context.

By following these steps, the aim is to create a comprehensive and informative summary that addresses all the user's requests.
这是一个V8源代码文件，用于测试 V8 JavaScript 引擎中 API 拦截器 (API Interceptors) 的功能。API 拦截器允许 C++ 代码介入到 JavaScript 对象的属性访问、设置、查询和枚举等操作中，从而自定义这些行为。

**功能归纳:**

此文件中的测试用例主要验证了以下 API 拦截器的功能：

1. **命名属性拦截器 (Named Property Handlers):**
   - **Getter 拦截器 (`ConcatNamedPropertyGetter`):**  当 JavaScript 代码尝试读取对象的命名属性时被调用。此示例中的 `ConcatNamedPropertyGetter` 返回属性名自身拼接两次的结果。
   - **Query 拦截器 (`RestrictiveNamedQuery`, `QueryInterceptorForFoo`):** 当 JavaScript 代码尝试查询对象的属性（例如使用 `in` 运算符或 `Object.getOwnPropertyDescriptor`）时被调用。它可以控制属性是否被认为存在以及其属性描述符（如 `enumerable`）。
   - **枚举拦截器 (`EnumCallbackWithNames`, `NamedEnum`):** 当 JavaScript 代码尝试枚举对象的命名属性（例如使用 `for...in` 循环或 `Object.keys` 等方法）时被调用。它可以控制哪些属性会被包含在枚举结果中。
   - **Setter 拦截器 (`nullptr` 在多个测试中表示没有设置 setter):** 当 JavaScript 代码尝试设置对象的命名属性时被调用。

2. **索引属性拦截器 (Indexed Property Handlers):**
   - **Getter 拦截器 (`ConcatIndexedPropertyGetter`):** 当 JavaScript 代码尝试读取对象的索引属性时被调用。此示例中的 `ConcatIndexedPropertyGetter` 返回索引值乘以 2 的结果。
   - **Query 拦截器 (`RestrictiveIndexedQuery`):** 当 JavaScript 代码尝试查询对象的索引属性时被调用，类似于命名属性的 Query 拦截器。
   - **枚举拦截器 (`EnumCallbackWithIndices`, `SloppyArgsIndexedPropertyEnumerator`):** 当 JavaScript 代码尝试枚举对象的索引属性时被调用。
   - **Setter 拦截器 (`nullptr` 在多个测试中表示没有设置 setter):** 当 JavaScript 代码尝试设置对象的索引属性时被调用。

3. **其他拦截器特性测试:**
   - **`kNonMasking` 标志:** 测试 `kNonMasking` 标志对拦截器的影响，特别是当属性在原型链上存在时，拦截器是否会被调用。
   - **接收者 (Receiver) 检查:** 测试拦截器 `info` 参数中 `This()` 方法返回的接收者对象是否正确。
   - **`Object.defineProperty` 的拦截:** 测试当使用 `Object.defineProperty` 定义属性时，拦截器是否会被触发 (getter, setter, definer)。
   - **副作用 (Side Effects) 的处理:**  测试拦截器中允许的副作用。

**JavaScript 功能关系与示例:**

这些 C++ 测试直接关联到 JavaScript 中操作对象属性的功能。以下是一些 JavaScript 示例，展示了这些功能以及拦截器如何影响它们的行为：

```javascript
// 假设一个由 C++ 代码创建并设置了拦截器的对象 obj

// 命名属性访问 (触发 Getter 拦截器)
console.log(obj.foo); // 输出 "foofoo" (如果 ConcatNamedPropertyGetter 被设置)

// 查询属性是否存在 (触发 Query 拦截器)
console.log('foo' in obj); // 根据 RestrictiveNamedQuery 的实现，可能为 true 或 false
console.log(Object.getOwnPropertyDescriptor(obj, 'baz')); // 根据 RestrictiveNamedQuery 的实现，可能返回 undefined 或一个描述符

// 枚举属性 (触发枚举拦截器)
for (let key in obj) {
  console.log(key); // 根据 EnumCallbackWithNames 或 NamedEnum 的实现，可能只输出 "foo"
}
console.log(Object.keys(obj)); // 根据枚举拦截器的实现，可能只输出 ["foo"]
console.log(Object.getOwnPropertyNames(obj)); // 会包含所有自身属性名，受 Query 拦截器影响

// 索引属性访问 (触发索引 Getter 拦截器)
console.log(obj[10]); // 输出 20 (如果 ConcatIndexedPropertyGetter 被设置)

// 查询索引属性是否存在 (触发索引 Query 拦截器)
console.log(12 in obj); // 根据 RestrictiveIndexedQuery 的实现，可能为 true 或 false

// 枚举索引属性 (触发索引枚举拦截器)
for (let key in obj) {
  console.log(key); // 根据 EnumCallbackWithIndices 或 SloppyArgsIndexedPropertyEnumerator 的实现输出
}
```

**代码逻辑推理与假设输入/输出:**

**示例 1: `EnumeratorsAndUnenumerableNamedProperties` 测试**

**假设输入:**  C++ 代码创建了一个对象模板，设置了 `ConcatNamedPropertyGetter` 作为 getter，`RestrictiveNamedQuery` 作为 query 拦截器，`EnumCallbackWithNames` 作为枚举拦截器。`RestrictiveNamedQuery` 的逻辑是只有当属性名为 "foo" 或数字时才返回属性描述符，且 "foo" 是可枚举的，其他数字属性不可枚举。`EnumCallbackWithNames` 返回一个包含 "foo", "baz", "10" 的数组。

**逻辑推理:**

1. `Object.getOwnPropertyNames(obj)` 会调用枚举拦截器 (`EnumCallbackWithNames`)，返回所有自身属性名: `["foo", "baz", "10"]`.
2. `Object.getOwnPropertyDescriptor(obj, 'foo').enumerable` 会调用 query 拦截器 (`RestrictiveNamedQuery`)，因为属性名为 "foo"，返回的描述符中 `enumerable` 为 `true`。
3. `Object.getOwnPropertyDescriptor(obj, 'baz').enumerable` 会调用 query 拦截器，虽然 `EnumCallbackWithNames` 返回了 "baz"，但 `RestrictiveNamedQuery` 可能会将其设置为不可枚举。
4. `Object.entries(obj)` 和 `Object.keys(obj)` 只会返回可枚举的属性。由于只有 "foo" 是可枚举的，所以结果会是 `[["foo", "foofoo"]]` 和 `["foo"]`。
5. `Object.values(obj)` 只会返回可枚举属性的值，所以结果是 `["foofoo"]`。

**假设输出 (基于 `Expect...` 语句):**

```
Object.getOwnPropertyNames(obj).length  -> 3
Object.getOwnPropertyNames(obj)[0]     -> "foo"
Object.getOwnPropertyNames(obj)[1]     -> "baz"
Object.getOwnPropertyNames(obj)[2]     -> "10"
Object.getOwnPropertyDescriptor(obj, 'foo').enumerable -> true
Object.getOwnPropertyDescriptor(obj, 'baz').enumerable -> false
Object.entries(obj).length              -> 1
Object.entries(obj)[0][0]             -> "foo"
Object.entries(obj)[0][1]             -> "foofoo"
Object.keys(obj).length                 -> 1
Object.keys(obj)[0]                    -> "foo"
Object.values(obj).length               -> 1
Object.values(obj)[0]                  -> "foofoo"
```

**用户常见的编程错误:**

1. **误解枚举行为:** 开发者可能期望 `for...in` 或 `Object.keys` 能够枚举所有添加到对象的属性，但如果没有正确设置枚举拦截器或属性的 `enumerable` 属性，某些属性可能不会被枚举。

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'secret', { value: 42, enumerable: false });
   obj.visible = 10;

   for (let key in obj) {
     console.log(key); // 只会输出 "visible"
   }

   console.log(Object.keys(obj)); // 输出 ["visible"]
   ```

2. **忘记拦截器只影响特定对象:**  设置在对象模板上的拦截器只对通过该模板创建的对象生效。直接在对象实例上添加属性不会触发这些拦截器。

   ```javascript
   // 假设 MyClass 通过一个设置了拦截器的模板创建
   const instance = new MyClass();
   instance.dynamicProp = 'value'; // 不会触发 MyClass 的拦截器
   ```

3. **对 `getOwnPropertyNames` 的理解不足:** 开发者可能认为 `Object.getOwnPropertyNames` 只会返回可枚举的属性，但实际上它返回对象自身定义的所有属性名，包括不可枚举的。拦截器的 Query 部分会影响其结果。

**总结 (第 8 部分):**

`v8/test/cctest/test-api-interceptors.cc`  是 V8 引擎中一个关键的测试文件，专门用于验证 JavaScript API 拦截器的各项功能。它通过创建具有不同拦截器配置的对象，并在 JavaScript 环境中执行各种属性操作（访问、查询、枚举、设置），来确保拦截器按照预期工作。 这些测试覆盖了命名属性和索引属性的拦截，并针对枚举行为、`kNonMasking` 标志以及与 `Object.defineProperty` 的交互进行了详细的验证。通过这些测试，V8 引擎的开发者可以保证 API 拦截器功能的正确性和稳定性，这对于那些需要深度定制 JavaScript 对象行为的嵌入式或扩展 V8 的场景至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ncatNamedPropertyGetter, nullptr, RestrictiveNamedQuery, nullptr,
      EnumCallbackWithNames));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "baz");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "10");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");
  ExpectFalse("Object.getOwnPropertyDescriptor(obj, 'baz').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "foo");
  ExpectString("Object.entries(obj)[0][1]", "foofoo");

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "foo");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectString("Object.values(obj)[0]", "foofoo");
}

namespace {
v8::Intercepted QueryInterceptorForFoo(
    Local<Name> property, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  // Don't intercept anything except "foo."
  if (!v8_str("foo")
           ->Equals(info.GetIsolate()->GetCurrentContext(), property)
           .FromJust()) {
    return v8::Intercepted::kNo;
  }
  // "foo" is enumerable.
  info.GetReturnValue().Set(v8::PropertyAttribute::None);
  return v8::Intercepted::kYes;
}
}  // namespace

// Test that calls to the query interceptor are independent of each
// other.
THREADED_TEST(EnumeratorsAndUnenumerableNamedPropertiesWithoutSet) {
  // The enumerator interceptor returns a list
  // of items which are filtered according to the
  // properties defined in the query interceptor.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      ConcatNamedPropertyGetter, nullptr, QueryInterceptorForFoo, nullptr,
      EnumCallbackWithNames));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "baz");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "10");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");
  ExpectInt32("Object.keys(obj).length", 1);
}

THREADED_TEST(EnumeratorsAndUnenumerableIndexedPropertiesArgumentsElements) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      ConcatIndexedPropertyGetter, nullptr, RestrictiveIndexedQuery, nullptr,
      SloppyArgsIndexedPropertyEnumerator));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 4);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "0");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "1");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "2");
  ExpectString("Object.getOwnPropertyNames(obj)[3]", "3");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, '2').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "2");
  ExpectInt32("Object.entries(obj)[0][1]", 4);

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "2");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectInt32("Object.values(obj)[0]", 4);
}

THREADED_TEST(EnumeratorsAndUnenumerableIndexedProperties) {
  // The enumerator interceptor returns a list
  // of items which are filtered according to the
  // properties defined in the query interceptor.
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      ConcatIndexedPropertyGetter, nullptr, RestrictiveIndexedQuery, nullptr,
      EnumCallbackWithIndices));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "10");
  ExpectString("Object.getOwnPropertyNames(obj)[1]", "12");
  ExpectString("Object.getOwnPropertyNames(obj)[2]", "14");

  ExpectFalse("Object.getOwnPropertyDescriptor(obj, '10').enumerable");
  ExpectTrue("Object.getOwnPropertyDescriptor(obj, '12').enumerable");

  ExpectInt32("Object.entries(obj).length", 1);
  ExpectString("Object.entries(obj)[0][0]", "12");
  ExpectInt32("Object.entries(obj)[0][1]", 24);

  ExpectInt32("Object.keys(obj).length", 1);
  ExpectString("Object.keys(obj)[0]", "12");

  ExpectInt32("Object.values(obj).length", 1);
  ExpectInt32("Object.values(obj)[0]", 24);
}

THREADED_TEST(EnumeratorsAndForIn) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      ConcatNamedPropertyGetter, nullptr, RestrictiveNamedQuery, nullptr,
      NamedEnum));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  ExpectInt32("Object.getOwnPropertyNames(obj).length", 3);
  ExpectString("Object.getOwnPropertyNames(obj)[0]", "foo");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj, 'foo').enumerable");

  CompileRun(
      "let concat = '';"
      "for(var prop in obj) {"
      "  concat += `key:${prop}:value:${obj[prop]}`;"
      "}");

  // Check that for...in only iterates over enumerable properties.
  ExpectString("concat", "key:foo:value:foofoo");
}

namespace {

v8::Intercepted DatabaseGetter(Local<Name> name,
                               const v8::PropertyCallbackInfo<Value>& info) {
  auto context = info.GetIsolate()->GetCurrentContext();
  v8::MaybeLocal<Value> maybe_db =
      info.HolderV2()->GetRealNamedProperty(context, v8_str("db"));
  if (maybe_db.IsEmpty()) return v8::Intercepted::kNo;
  Local<v8::Object> db = maybe_db.ToLocalChecked().As<v8::Object>();
  if (!db->Has(context, name).FromJust()) return v8::Intercepted::kNo;

  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  info.GetReturnValue().Set(db->Get(context, name).ToLocalChecked());
  return v8::Intercepted::kYes;
}

v8::Intercepted DatabaseSetter(Local<Name> name, Local<Value> value,
                               const v8::PropertyCallbackInfo<void>& info) {
  auto context = info.GetIsolate()->GetCurrentContext();
  if (name->Equals(context, v8_str("db")).FromJust())
    return v8::Intercepted::kNo;

  // Side effects are allowed only when the property is present or throws.
  ApiTestFuzzer::Fuzz();
  Local<v8::Object> db = info.HolderV2()
                             ->GetRealNamedProperty(context, v8_str("db"))
                             .ToLocalChecked()
                             .As<v8::Object>();
  db->Set(context, name, value).FromJust();
  return v8::Intercepted::kYes;
}

}  // namespace


THREADED_TEST(NonMaskingInterceptorGlobalEvalRegression) {
  auto isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  LocalContext context;

  auto interceptor_templ = v8::ObjectTemplate::New(isolate);
  v8::NamedPropertyHandlerConfiguration conf(DatabaseGetter, DatabaseSetter);
  conf.flags = v8::PropertyHandlerFlags::kNonMasking;
  interceptor_templ->SetHandler(conf);

  context->Global()
      ->Set(context.local(), v8_str("intercepted_1"),
            interceptor_templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("intercepted_2"),
            interceptor_templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Init dbs.
  CompileRun(
      "intercepted_1.db = {};"
      "intercepted_2.db = {};");

  ExpectInt32(
      "var obj = intercepted_1;"
      "obj.x = 4;"
      "eval('obj.x');"
      "eval('obj.x');"
      "eval('obj.x');"
      "obj = intercepted_2;"
      "obj.x = 9;"
      "eval('obj.x');",
      9);
}

namespace {
v8::Intercepted CheckReceiver(Local<Name> name,
                              const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(info.This()->IsObject());
  return v8::Intercepted::kNo;
}
}  // namespace

TEST(Regress609134Interceptor) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  auto fun_templ = v8::FunctionTemplate::New(isolate);
  fun_templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(CheckReceiver));

  CHECK(env->Global()
            ->Set(env.local(), v8_str("Fun"),
                  fun_templ->GetFunction(env.local()).ToLocalChecked())
            .FromJust());

  CompileRun(
      "var f = new Fun();"
      "Number.prototype.__proto__ = f;"
      "var a = 42;"
      "for (var i = 0; i<3; i++) { a.foo; }");
}

namespace {

v8::Intercepted Regress42204611_Getter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("getter");
  return v8::Intercepted::kNo;
}
v8::Intercepted Regress42204611_Setter(
    Local<Name> name, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("setter");
  return v8::Intercepted::kNo;
}
v8::Intercepted Regress42204611_Definer(
    Local<Name> name, const v8::PropertyDescriptor& descriptor,
    const v8::PropertyCallbackInfo<void>& info) {
  std::vector<std::string>* calls = reinterpret_cast<std::vector<std::string>*>(
      info.Data().As<v8::External>()->Value());

  calls->push_back("definer");
  return v8::Intercepted::kNo;
}

}  // namespace

// Regression test for crbug.com/42204611
THREADED_TEST(Regress42204611) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  std::vector<std::string> calls;
  Local<v8::External> calls_ext = v8::External::New(CcTest::isolate(), &calls);

  v8::Local<v8::ObjectTemplate> object_template =
      v8::ObjectTemplate::New(isolate);
  object_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      Regress42204611_Getter, Regress42204611_Setter, nullptr, nullptr, nullptr,
      Regress42204611_Definer, calls_ext,
      static_cast<v8::PropertyHandlerFlags>(
          static_cast<int>(v8::PropertyHandlerFlags::kNonMasking) |
          static_cast<int>(v8::PropertyHandlerFlags::kHasNoSideEffect))));

  v8::Local<v8::Context> ctx =
      v8::Context::New(CcTest::isolate(), nullptr, object_template);

  {
    v8::Context::Scope scope(ctx);
    CompileRun(
        "Object.defineProperty(globalThis, 'key', {"
        "  value: 9, enumerable: true, configurable: true, writable: true"
        "})");
  }

  // We should intercept:
  //   1. The getter when getting the current property attributes,
  //   2. The definer when trying to intercept the define itself,
  //   3. The setter when applying the property descriptor.
  CHECK_EQ(calls, std::vector<std::string>({"getter", "definer", "setter"}));
}
```