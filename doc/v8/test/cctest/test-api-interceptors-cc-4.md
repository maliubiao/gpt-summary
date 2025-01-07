Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a V8 test file (`test-api-interceptors.cc`) and deals with API interceptors.

Here's a breakdown of how to approach this:

1. **Identify the core concept:** The filename and the frequent use of `ObjectTemplate::SetHandler` with configurations like `NamedPropertyHandlerConfiguration` and `IndexedPropertyHandlerConfiguration` clearly indicate that the code is testing V8's API interceptors.

2. **Analyze individual test cases:**  Each `THREADED_TEST` function likely tests a specific aspect or interaction of the interceptor API. Look for patterns in how the handlers are configured and the JavaScript code being executed.

3. **Categorize the functionalities:** Group the tests based on the interceptor type (named vs. indexed), the operations being intercepted (get, set, delete, enumerate), and any special scenarios being tested (e.g., access checks, megamorphism, prototype interaction, IC integration).

4. **Explain with JavaScript examples:** Where the C++ test code interacts with JavaScript, provide equivalent JavaScript examples to illustrate the behavior.

5. **Look for code logic and infer inputs/outputs:** Some tests involve setting up specific conditions and then checking the result of JavaScript execution. Identify the setup (inputs) and the expected outcome (outputs).

6. **Identify potential user errors:** Based on the test scenarios, think about common mistakes developers might make when using interceptors.

7. **Summarize the overall functionality:** Combine the individual functionalities into a concise summary.
```
功能：
```
这段 C++ 代码是 V8 JavaScript 引擎的测试文件，专门测试 API 拦截器（API Interceptors）的功能，特别是针对**索引属性（Indexed Properties）**的拦截器。

主要功能可以归纳为以下几点：

1. **测试索引属性的 getter 和 setter 拦截器:**  验证通过 `IndexedPropertyHandlerConfiguration` 设置的 getter 和 setter 拦截器是否能正确地拦截对对象索引属性的访问和修改。

2. **测试非盒装 Double 数组的索引访问:**  检查当对象的索引属性存储在非盒装的 Double 数组中时，拦截器是否仍然能够正常工作。

3. **测试 `arguments` 对象的索引属性枚举:**  验证当使用 `arguments` 对象作为索引属性枚举的返回结果时，拦截器是否能够正确处理。

4. **测试 `Object.getOwnPropertyDescriptor` 与索引拦截器的交互:**  确保当对象上设置了索引拦截器时，`Object.getOwnPropertyDescriptor` 能够正确地返回属性描述符。

5. **测试只设置 getter 拦截器的情况:**  验证当只设置了索引属性的 getter 拦截器而没有 setter 时，尝试设置属性会发生什么，并确保 getter 仍然能被调用。

6. **测试索引拦截器与访问检查回调函数的交互:**  检查当同时设置了索引拦截器和访问检查回调函数时，访问检查回调函数是否能够阻止对属性的访问。

7. **测试使用不同索引值的索引拦截器:**  验证索引拦截器是否能够处理不同的索引值，包括连续的数字索引。

8. **测试使用负数索引的索引拦截器:**  检查索引拦截器在处理负数索引时的行为（通常会被转换为字符串或返回 undefined）。

9. **测试使用非数字索引的索引拦截器:**  验证索引拦截器在处理非数字索引时的行为（通常会返回 undefined）。

10. **测试索引拦截器的多态性（Megamorphic）:**  模拟在循环中改变对象类型的情况，验证索引拦截器是否能够正确处理这种多态性。

11. **测试接收者（Receiver）变为 Smi 的情况:**  验证当尝试访问索引属性时，接收者对象突然变成一个 Smi（Small Integer）时会发生什么。

12. **测试原型链上的索引拦截器:**  检查当索引拦截器设置在对象的原型上时，是否能够正确地拦截对子对象索引属性的访问。

13. **测试索引拦截器与内联缓存（IC）的集成:**  验证索引拦截器如何与 V8 的内联缓存机制协同工作，特别是针对 `in` 操作符的优化。

14. **测试索引属性的删除拦截器:** 验证通过 `IndexedPropertyHandlerConfiguration` 设置的删除拦截器是否能正确地拦截对对象索引属性的删除操作。

15. **测试拦截器中的副作用:** 验证在 getter 拦截器中执行副作用代码是否按预期工作。

16. **测试索引属性的枚举拦截器:** 验证通过 `IndexedPropertyHandlerConfiguration` 设置的枚举拦截器是否能正确地控制 `for...in` 循环返回的索引属性。

17. **测试拦截器与函数调用内联缓存（Call IC）的集成:** 验证当拦截器返回一个函数时，函数调用内联缓存如何工作。

18. **测试拦截器不提供值时的情况:** 验证当索引拦截器没有返回一个值时，V8 如何尝试获取其他值（例如，对象自身的属性）。

19. **测试当拦截器提供函数时，即使存在缓存的阴影变体，拦截器的函数也会被调用。**

20. **测试当拦截器的查找结果被缓存后又失效的情况。**

21. **测试当拦截器不提供函数时，缓存的常量函数是否被使用。**

```

**如果 `v8/test/cctest/test-api-interceptors.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

目前给出的代码是以 `.cc` 结尾的 C++ 代码，所以不是 Torque 源代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明。**

以下是一些与代码中的测试相关的 JavaScript 例子：

**1. 测试索引属性的 getter 和 setter 拦截器:**

```javascript
let obj = {};
let handler = {
  get: function(target, prop, receiver) {
    console.log(`Getting index: ${prop}`);
    return prop * 2;
  },
  set: function(target, prop, value, receiver) {
    console.log(`Setting index: ${prop} with value: ${value}`);
    target[prop] = value + 10;
    return true;
  }
};
let proxyObj = new Proxy(obj, handler);

console.log(proxyObj[5]); // 输出: Getting index: 5, 然后输出: 10
proxyObj[3] = 7;        // 输出: Setting index: 3 with value: 7
console.log(proxyObj[3]); // 输出: Getting index: 3, 然后输出: 6 (因为没有实际存储，getter 返回 3 * 2)
console.log(obj[3]);       // 输出: 17 (setter 拦截器修改了实际存储的值)
```

**解释:** 虽然 JavaScript 的 Proxy 与 V8 的 API 拦截器在实现细节上有所不同，但概念是相似的。上面的例子展示了如何使用 Proxy 拦截对对象索引属性的读取和设置操作。V8 的 API 拦截器允许 C++ 代码定义类似的行为。

**2. 测试 `Object.getOwnPropertyDescriptor` 与索引拦截器的交互:**

```javascript
let obj = {};
Object.defineProperty(obj, '0', {
  get: function() { return 10; },
  configurable: true,
  enumerable: true
});

console.log(Object.getOwnPropertyDescriptor(obj, '0'));
// 输出: { value: 10, writable: undefined, enumerable: true, configurable: true }
```

**解释:**  V8 的测试用例会验证，当 C++ 代码使用 API 拦截器为对象定义了索引属性的 getter 时，`Object.getOwnPropertyDescriptor` 能够正确反映这些定义。

**3. 测试只设置 getter 拦截器的情况:**

```javascript
let obj = {
  get '0'() {
    console.log("Getter called for index 0");
    return 5;
  }
};

console.log(obj[0]); // 输出: Getter called for index 0, 然后输出: 5
obj[0] = 10;         // 在严格模式下会抛出 TypeError，非严格模式下静默失败
console.log(obj[0]); // 输出: Getter called for index 0, 然后输出: 5 (值没有被设置，getter 仍然返回原始值)
```

**解释:**  这个例子演示了当对象只有 getter 而没有 setter 时，尝试设置属性的行为。V8 的测试用例会验证当 C++ 代码只设置了索引属性的 getter 拦截器时，尝试设置属性是否会按预期工作。

**如果有代码逻辑推理，请给出假设输入与输出。**

**测试用例 `DoubleWithIndexedAccessor` 的代码逻辑推理：**

**假设输入:** 创建一个空对象，并为其设置索引属性的 getter 和 setter 拦截器 (`UnboxedDoubleIndexedPropertyGetter`, `UnboxedDoubleIndexedPropertySetter`)，这些拦截器被设计用于处理存储在非盒装 Double 数组中的数据。

**代码逻辑:**

1. 创建一个对象模板，并设置索引属性处理器。
2. 创建一个对象实例 `obj`。
3. 执行一段 JavaScript 代码：
   - `obj[125000] = 1;`:  尝试设置一个较大的索引值，这可能会触发 V8 将底层存储结构优化为非盒装 Double 数组。
   - `for(i = 0; i < 80000; i+=2) { obj[i] = i; }`:  循环设置一系列偶数索引的值。由于 setter 拦截器的存在，这些值可能会被修改。
   - `key_count = 0; for (x in obj) {key_count++;};`: 统计对象中可枚举的属性数量。

**预期输出:**

- `CHECK(result->ToObject(context.local()).ToLocalChecked()->HasRealIndexedProperty(context.local(), 2000).FromJust());`: 验证对象是否确实在索引 2000 处有一个实际的索引属性（意味着之前的设置操作生效了）。
- `CHECK(v8_num(40013)->Equals(context.local(), result).FromJust());`: 验证枚举出的属性数量是否为 40013。 这是因为循环设置了 40000 / 2 = 20000 个偶数索引，加上初始设置的索引 125000，以及可能的拦截器引入的其他属性（需要具体查看 `UnboxedDoubleIndexedPropertyEnumerator` 的实现）。 **注意：这里给出的预期输出 40013 需要根据拦截器的具体实现来确认，目前代码中没有直接显示枚举器的实现。**

**测试用例 `IndexedInterceptorSloppyArgsWithIndexedAccessor` 的代码逻辑推理：**

**假设输入:** 创建一个空对象，并为其设置索引属性的 getter 拦截器 (`SloppyIndexedPropertyGetter`) 和枚举器 (`SloppyArgsIndexedPropertyEnumerator`)。

**代码逻辑:**

1. 创建一个对象模板，并设置索引属性处理器。
2. 创建一个对象实例 `obj`。
3. 执行一段 JavaScript 代码：
   - `var key_count = 0; for (x in obj) {key_count++;} key_count;`:  循环枚举对象 `obj` 的属性，并统计数量。枚举器 `SloppyArgsIndexedPropertyEnumerator` 的作用是返回一个 `arguments` 对象作为属性名列表。

**预期输出:**

- `CHECK(v8_num(4)->Equals(context.local(), result).FromJust());`: 验证枚举出的属性数量是否为 4。 这是因为 `SloppyArgsIndexedPropertyEnumerator` 内部创建了一个包含 4 个元素的 `arguments` 对象。

**如果涉及用户常见的编程错误，请举例说明。**

**1. 忘记在拦截器中返回 `v8::Intercepted::kYes` 或 `v8::Intercepted::kNo`:**

用户在编写拦截器回调函数时，必须返回 `v8::Intercepted::kYes` 表示拦截了该操作并提供了结果，或者 `v8::Intercepted::kNo` 表示没有拦截，应该由 V8 引擎继续处理。忘记返回会导致未定义的行为。

```c++
v8::Intercepted MyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (index == 0) {
    info.GetReturnValue().Set(v8::Number::New(info.GetIsolate(), 10));
    // 错误：忘记返回 v8::Intercepted::kYes
  }
  return v8::Intercepted::kNo;
}
```

**2. 在 getter 拦截器中修改对象的状态，导致意外的副作用:**

虽然拦截器可以执行任意代码，但在 getter 拦截器中修改对象的状态可能会导致难以预测的行为，尤其是在 V8 引擎进行优化时。

```c++
v8::Intercepted MyGetterWithSideEffect(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  Local<Object> obj = info.Holder();
  if (index == 0) {
    obj->Set(info.GetIsolate()->GetCurrentContext(),
             v8_str("internal_state"),
             v8::Number::New(info.GetIsolate(), 10));
    info.GetReturnValue().Set(v8::Number::New(info.GetIsolate(), 5));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
```

**JavaScript 示例 (模拟副作用):**

```javascript
let obj = {
  get 0() {
    this.internalState = 10;
    return 5;
  }
};

console.log(obj[0]); // 输出 5，并且设置了 obj.internalState
console.log(obj.internalState); // 输出 10
```

**3. 在 setter 拦截器中没有正确地设置属性值:**

setter 拦截器的目的是控制属性的设置过程。如果拦截器没有正确地将传入的值设置到对象上，那么属性可能不会被修改。

```c++
v8::Intercepted MySetter(
    uint32_t index, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  // 错误：忘记设置属性值
  return v8::Intercepted::kYes;
}
```

**JavaScript 示例 (模拟未正确设置):**

```javascript
let obj = {
  set 0(value) {
    console.log("Setter called, but not actually setting the value");
  }
};

obj[0] = 10;
console.log(obj[0]); // 输出 undefined (因为没有默认的 getter，也没有实际设置值)
```

**这是第 5 部分，共 8 部分，请归纳一下它的功能**

作为第 5 部分，这段代码主要关注 **索引属性拦截器** 的各种功能和边缘情况的测试，包括：

- **基本的 getter 和 setter 拦截。**
- **与不同类型的索引属性存储结构的交互 (例如，非盒装 Double 数组)。**
- **与 `arguments` 对象和属性枚举的交互。**
- **与 V8 引擎的其他机制的集成，如 `Object.getOwnPropertyDescriptor`、访问检查和内联缓存。**
- **各种索引类型 (正数、负数、非数字) 的处理。**
- **在对象状态变化时的行为 (多态和接收者类型改变)。**
- **原型链上的拦截器。**
- **属性删除拦截器。**
- **属性枚举拦截器。**
- **函数调用拦截器。**

总而言之，这部分测试旨在确保 V8 的索引属性拦截器功能稳定可靠，能够处理各种复杂的场景，并与引擎的其他部分良好地协同工作。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共8部分，请归纳一下它的功能

"""
DoubleWithIndexedAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      UnboxedDoubleIndexedPropertyGetter, UnboxedDoubleIndexedPropertySetter,
      nullptr, nullptr, UnboxedDoubleIndexedPropertyEnumerator));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  // When obj is created, force it to be Stored in a FastDoubleArray.
  Local<Script> create_unboxed_double_script = v8_compile(
      "obj[125000] = 1; for(i = 0; i < 80000; i+=2) { obj[i] = i; } "
      "key_count = 0; "
      "for (x in obj) {key_count++;};"
      "obj;");
  Local<Value> result =
      create_unboxed_double_script->Run(context.local()).ToLocalChecked();
  CHECK(result->ToObject(context.local())
            .ToLocalChecked()
            ->HasRealIndexedProperty(context.local(), 2000)
            .FromJust());
  Local<Script> key_count_check = v8_compile("key_count;");
  result = key_count_check->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(40013)->Equals(context.local(), result).FromJust());
}

namespace {
void SloppyArgsIndexedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  // Force the list of returned keys to be stored in a Arguments object.
  Local<Script> indexed_property_names_script = v8_compile(
      "function f(w,x) {"
      " return arguments;"
      "}"
      "keys = f(0, 1, 2, 3);"
      "keys;");
  Local<Object> result =
      indexed_property_names_script->Run(info.GetIsolate()->GetCurrentContext())
          .ToLocalChecked()
          .As<Object>();
  // Have to populate the handle manually, as it's not Cast-able.
  i::DirectHandle<i::JSReceiver> o =
      v8::Utils::OpenDirectHandle<Object, i::JSReceiver>(result);
  i::Handle<i::JSArray> array(i::UncheckedCast<i::JSArray>(*o),
                              o->GetIsolate());
  info.GetReturnValue().Set(v8::Utils::ToLocal(array));
}

v8::Intercepted SloppyIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  if (index < 4) {
    info.GetReturnValue().Set(v8_num(index));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// Make sure that the the interceptor code in the runtime properly handles
// merging property name lists for non-string arguments arrays.
THREADED_TEST(IndexedInterceptorSloppyArgsWithIndexedAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      SloppyIndexedPropertyGetter, nullptr, nullptr, nullptr,
      SloppyArgsIndexedPropertyEnumerator));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  Local<Script> create_args_script = v8_compile(
      "var key_count = 0;"
      "for (x in obj) {key_count++;} key_count;");
  Local<Value> result =
      create_args_script->Run(context.local()).ToLocalChecked();
  CHECK(v8_num(4)->Equals(context.local(), result).FromJust());
}

namespace {
v8::Intercepted IdentityIndexedPropertyGetter(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Value>& info) {
  info.GetReturnValue().Set(index);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(IndexedInterceptorWithGetOwnPropertyDescriptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Check fast object case.
  const char* fast_case_code =
      "Object.getOwnPropertyDescriptor(obj, 0).value.toString()";
  ExpectString(fast_case_code, "0");

  // Check slow case.
  const char* slow_case_code =
      "obj.x = 1; delete obj.x;"
      "Object.getOwnPropertyDescriptor(obj, 1).value.toString()";
  ExpectString(slow_case_code, "1");
}


THREADED_TEST(IndexedInterceptorWithNoSetter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("obj"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  const char* code =
      "try {"
      "  obj[0] = 239;"
      "  for (var i = 0; i < 100; i++) {"
      "    var v = obj[0];"
      "    if (v != 0) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}

static bool AccessAlwaysBlocked(Local<v8::Context> accessing_context,
                                Local<v8::Object> accessed_object,
                                Local<v8::Value> data) {
  return false;
}


THREADED_TEST(IndexedInterceptorWithAccessorCheck) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  templ->SetAccessCheckCallback(AccessAlwaysBlocked);

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "var result = 'PASSED';"
      "for (var i = 0; i < 100; i++) {"
      "  try {"
      "    var v = obj[0];"
      "    result = 'Wrong value ' + v + ' at iteration ' + i;"
      "    break;"
      "  } catch (e) {"
      "    /* pass */"
      "  }"
      "}"
      "result";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorWithDifferentIndices) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var v = obj[i];"
      "    if (v != i) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorWithNegativeIndices) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var expected = i;"
      "    var key = i;"
      "    if (i == 25) {"
      "       key = -1;"
      "       expected = undefined;"
      "    }"
      "    if (i == 50) {"
      "       /* probe minimal Smi number on 32-bit platforms */"
      "       key = -(1 << 30);"
      "       expected = undefined;"
      "    }"
      "    if (i == 75) {"
      "       /* probe minimal Smi number on 64-bit platforms */"
      "       key = 1 << 31;"
      "       expected = undefined;"
      "    }"
      "    var v = obj[key];"
      "    if (v != expected) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorWithNotSmiLookup) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var expected = i;"
      "    var key = i;"
      "    if (i == 50) {"
      "       key = 'foobar';"
      "       expected = undefined;"
      "    }"
      "    var v = obj[key];"
      "    if (v != expected) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorGoingMegamorphic) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "var original = obj;"
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var expected = i;"
      "    if (i == 50) {"
      "       obj = {50: 'foobar'};"
      "       expected = 'foobar';"
      "    }"
      "    var v = obj[i];"
      "    if (v != expected) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "    if (i == 50) obj = original;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorReceiverTurningSmi) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "var original = obj;"
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var expected = i;"
      "    if (i == 5) {"
      "       obj = 239;"
      "       expected = undefined;"
      "    }"
      "    var v = obj[i];"
      "    if (v != expected) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "    if (i == 5) obj = original;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}


THREADED_TEST(IndexedInterceptorOnProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::IndexedPropertyHandlerConfiguration(IdentityIndexedPropertyGetter));

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();

  const char* code =
      "var o = {__proto__: obj};"
      "try {"
      "  for (var i = 0; i < 100; i++) {"
      "    var v = o[i];"
      "    if (v != i) throw 'Wrong value ' + v + ' at iteration ' + i;"
      "  }"
      "  'PASSED'"
      "} catch(e) {"
      "  e"
      "}";
  ExpectString(code, "PASSED");
}

namespace {

void CheckIndexedInterceptorHasIC(v8::IndexedPropertyGetterCallbackV2 getter,
                                  v8::IndexedPropertyQueryCallbackV2 query,
                                  const char* source, int expected) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      getter, nullptr, query, nullptr, nullptr, v8_str("data")));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(source);
  CHECK_EQ(expected, value->Int32Value(context.local()).FromJust());
}

int indexed_query_counter = 0;
v8::Intercepted IndexedQueryCallback(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  indexed_query_counter++;
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexHasICQueryAbsent(
    uint32_t index, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  // The request is not intercepted so don't call ApiTestFuzzer::Fuzz() here.
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  // TODO(ishell): the PropertyAttributes::ABSENT is not exposed in the Api,
  // so it can't be officially returned. We should fix the tests instead.
  info.GetReturnValue().Set(v8::internal::ABSENT);
  return v8::Intercepted::kNo;
}

}  // namespace

THREADED_TEST(IndexedInterceptorHasIC) {
  indexed_query_counter = 0;
  CheckIndexedInterceptorHasIC(nullptr, IndexedQueryCallback,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  i in o;"
                               "}",
                               0);
  CHECK_EQ(1000, indexed_query_counter);
}

THREADED_TEST(IndexedInterceptorHasICQueryAbsent) {
  CheckIndexedInterceptorHasIC(nullptr,
                               // HasICQuery<uint32_t, v8::internal::ABSENT>,
                               IndexHasICQueryAbsent,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  if (i in o) ++result;"
                               "}",
                               0);
}

THREADED_TEST(IndexedInterceptorHasICQueryNone) {
  CheckIndexedInterceptorHasIC(nullptr,
                               HasICQuery<uint32_t, v8::internal::NONE>,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  if (i in o) ++result;"
                               "}",
                               1000);
}

THREADED_TEST(IndexedInterceptorHasICGetter) {
  CheckIndexedInterceptorHasIC(IdentityIndexedPropertyGetter, nullptr,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  if (i in o) ++result;"
                               "}",
                               1000);
}

THREADED_TEST(IndexedInterceptorHasICQueryGetter) {
  CheckIndexedInterceptorHasIC(IdentityIndexedPropertyGetter,
                               HasICQuery<uint32_t, v8::internal::ABSENT>,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  if (i in o) ++result;"
                               "}",
                               0);
}

THREADED_TEST(IndexedInterceptorHasICQueryToggle) {
  CheckIndexedInterceptorHasIC(IdentityIndexedPropertyGetter,
                               HasICQueryToggle<uint32_t>,
                               "var result = 0;"
                               "for (var i = 0; i < 1000; i++) {"
                               "  if (i in o) ++result;"
                               "}",
                               500);
}

namespace {
v8::Intercepted NoBlockGetterX(Local<Name> name,
                               const v8::PropertyCallbackInfo<v8::Value>&) {
  return v8::Intercepted::kNo;
}

v8::Intercepted NoBlockGetterI(uint32_t index,
                               const v8::PropertyCallbackInfo<v8::Value>&) {
  return v8::Intercepted::kNo;
}

v8::Intercepted PDeleter(Local<Name> name,
                         const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  if (!name->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("foo"))
           .FromJust()) {
    return v8::Intercepted::kNo;
  }

  // Intercepted, but property deletion failed.
  info.GetReturnValue().Set(false);
  return v8::Intercepted::kYes;
}

v8::Intercepted IDeleter(uint32_t index,
                         const v8::PropertyCallbackInfo<v8::Boolean>& info) {
  if (index != 2) {
    return v8::Intercepted::kNo;
  }

  // Intercepted, but property deletion failed.
  info.GetReturnValue().Set(false);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(Deleter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(
      NoBlockGetterX, nullptr, nullptr, PDeleter, nullptr));
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      NoBlockGetterI, nullptr, nullptr, IDeleter, nullptr));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("k"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "k.foo = 'foo';"
      "k.bar = 'bar';"
      "k[2] = 2;"
      "k[4] = 4;");
  CHECK(v8_compile("delete k.foo")
            ->Run(context.local())
            .ToLocalChecked()
            ->IsFalse());
  CHECK(v8_compile("delete k.bar")
            ->Run(context.local())
            .ToLocalChecked()
            ->IsTrue());

  CHECK(v8_compile("k.foo")
            ->Run(context.local())
            .ToLocalChecked()
            ->Equals(context.local(), v8_str("foo"))
            .FromJust());
  CHECK(v8_compile("k.bar")
            ->Run(context.local())
            .ToLocalChecked()
            ->IsUndefined());

  CHECK(v8_compile("delete k[2]")
            ->Run(context.local())
            .ToLocalChecked()
            ->IsFalse());
  CHECK(v8_compile("delete k[4]")
            ->Run(context.local())
            .ToLocalChecked()
            ->IsTrue());

  CHECK(v8_compile("k[2]")
            ->Run(context.local())
            .ToLocalChecked()
            ->Equals(context.local(), v8_num(2))
            .FromJust());
  CHECK(
      v8_compile("k[4]")->Run(context.local()).ToLocalChecked()->IsUndefined());
}

namespace {
v8::Intercepted GetK(Local<Name> name,
                     const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  if (name->Equals(context, v8_str("foo")).FromJust() ||
      name->Equals(context, v8_str("bar")).FromJust() ||
      name->Equals(context, v8_str("baz")).FromJust()) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().SetUndefined();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted IndexedGetK(uint32_t index,
                            const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (index == 0 || index == 1) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().SetUndefined();
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

static void NamedEnum(const v8::PropertyCallbackInfo<v8::Array>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 3);
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 0), v8_str("foo"))
          .FromJust());
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 1), v8_str("bar"))
          .FromJust());
  CHECK(
      result
          ->Set(context, v8::Integer::New(info.GetIsolate(), 2), v8_str("baz"))
          .FromJust());
  info.GetReturnValue().Set(result);
}


static void IndexedEnum(const v8::PropertyCallbackInfo<v8::Array>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 2);
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(
      result->Set(context, v8::Integer::New(info.GetIsolate(), 0), v8_str("0"))
          .FromJust());
  CHECK(
      result->Set(context, v8::Integer::New(info.GetIsolate(), 1), v8_str("1"))
          .FromJust());
  info.GetReturnValue().Set(result);
}


THREADED_TEST(Enumerators) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> obj = ObjectTemplate::New(isolate);
  obj->SetHandler(v8::NamedPropertyHandlerConfiguration(GetK, nullptr, nullptr,
                                                        nullptr, NamedEnum));
  obj->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      IndexedGetK, nullptr, nullptr, nullptr, IndexedEnum));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("k"),
            obj->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<v8::Array> result = CompileRun(
                                    "k[10] = 0;"
                                    "k.a = 0;"
                                    "k[5] = 0;"
                                    "k.b = 0;"
                                    "k[4294967294] = 0;"
                                    "k.c = 0;"
                                    "k[4294967295] = 0;"
                                    "k.d = 0;"
                                    "k[140000] = 0;"
                                    "k.e = 0;"
                                    "k[30000000000] = 0;"
                                    "k.f = 0;"
                                    "var result = [];"
                                    "for (var prop in k) {"
                                    "  result.push(prop);"
                                    "}"
                                    "result")
                                    .As<v8::Array>();
  // Check that we get all the property names returned including the
  // ones from the enumerators in the right order: indexed properties
  // in numerical order, indexed interceptor properties, named
  // properties in insertion order, named interceptor properties.
  // This order is not mandated by the spec, so this test is just
  // documenting our behavior.
  CHECK_EQ(17u, result->Length());
  // Indexed properties.
  CHECK(v8_str("5")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 0))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("10")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 1))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("140000")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 2))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("4294967294")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 3))
                         .ToLocalChecked())
            .FromJust());
  // Indexed Interceptor properties
  CHECK(v8_str("0")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 4))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("1")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 5))
                         .ToLocalChecked())
            .FromJust());
  // Named properties in insertion order.
  CHECK(v8_str("a")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 6))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("b")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 7))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("c")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 8))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("4294967295")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 9))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("d")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 10))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("e")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 11))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("30000000000")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 12))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("f")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 13))
                         .ToLocalChecked())
            .FromJust());
  // Named interceptor properties.
  CHECK(v8_str("foo")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 14))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("bar")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 15))
                         .ToLocalChecked())
            .FromJust());
  CHECK(v8_str("baz")
            ->Equals(context.local(),
                     result->Get(context.local(), v8::Integer::New(isolate, 16))
                         .ToLocalChecked())
            .FromJust());
}

namespace {
v8::Global<Value> call_ic_function_global;
v8::Global<Value> call_ic_function2_global;
v8::Global<Value> call_ic_function3_global;

v8::Intercepted InterceptorCallICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("x")
            ->Equals(info.GetIsolate()->GetCurrentContext(), name)
            .FromJust());
  info.GetReturnValue().Set(call_ic_function_global);
  return v8::Intercepted::kYes;
}
}  // namespace

// This test should hit the call IC for the interceptor case.
THREADED_TEST(InterceptorCallIC) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorCallICGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  Local<Value> call_ic_function =
      v8_compile("function f(x) { return x + 1; }; f")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function_global.Reset(isolate, call_ic_function);
  v8::Local<Value> value = CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result = o.x(41);"
      "}");
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
  call_ic_function_global.Reset();
}


// This test checks that if interceptor doesn't provide
// a value, we can fetch regular value.
THREADED_TEST(InterceptorCallICSeesOthers) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "o.x = function f(x) { return x + 1; };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = o.x(41);"
      "}");
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
}

namespace {
v8::Global<Value> call_ic_function4_global;
v8::Intercepted InterceptorCallICGetter4(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("x")
            ->Equals(info.GetIsolate()->GetCurrentContext(), name)
            .FromJust());
  info.GetReturnValue().Set(call_ic_function4_global);
  return v8::Intercepted::kYes;
}
}  // namespace

// This test checks that if interceptor provides a function,
// even if we cached shadowed variant, interceptor's function
// is invoked
THREADED_TEST(InterceptorCallICCacheableNotNeeded) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorCallICGetter4));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> call_ic_function4 =
      v8_compile("function f(x) { return x - 1; }; f")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function4_global.Reset(isolate, call_ic_function4);
  v8::Local<Value> value = CompileRun(
      "Object.getPrototypeOf(o).x = function(x) { return x + 1; };"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result = o.x(42);"
      "}");
  CHECK_EQ(41, value->Int32Value(context.local()).FromJust());
  call_ic_function4_global.Reset();
}


// Test the case when we stored cacheable lookup into
// a stub, but it got invalidated later on
THREADED_TEST(InterceptorCallICInvalidatedCacheable) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "proto1 = new Object();"
      "proto2 = new Object();"
      "o.__proto__ = proto1;"
      "proto1.__proto__ = proto2;"
      "proto2.y = function(x) { return x + 1; };"
      // Invoke it many times to compile a stub
      "for (var i = 0; i < 7; i++) {"
      "  o.y(42);"
      "}"
      "proto1.y = function(x) { return x - 1; };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result += o.y(42);"
      "}");
  CHECK_EQ(41 * 7, value->Int32Value(context.local()).FromJust());
}


// This test checks that if interceptor doesn't provide a function,
// cached constant function is used
THREADED_TEST(InterceptorCallICConstantFunctionUsed) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "function inc(x) { return x + 1; };"
      "inc(1);"
      "o.x = inc;"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result = o.x(42);"
      "}");
  CHECK_EQ(43, value->Int32Value(context.local()).FromJust());
}

namespace {
v8::Global<Value> call_ic_function5_global;
v8::Intercepted InterceptorCallICGetter5(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    info.GetReturnValue().Se
"""


```