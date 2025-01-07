Response: The user wants a summary of the C++ code in the provided file, specifically focusing on its functionality and its relation to JavaScript.

This is the third part of a four-part file. This implies that the overall functionality is likely split across these four parts.

The code heavily uses the V8 API for embedding and testing. Key V8 concepts involved are:

*   `v8::Isolate`: Represents an isolated instance of the V8 engine.
*   `v8::HandleScope`: Manages the lifetime of V8 objects.
*   `v8::Local`: A smart pointer for V8 objects.
*   `v8::ObjectTemplate`: A blueprint for creating JavaScript objects.
*   `v8::Context`:  A sandboxed execution environment for JavaScript code.
*   `v8::Script`: Represents compiled JavaScript code.
*   `v8::IndexedPropertyHandlerConfiguration`:  Configures handlers for accessing object properties using numeric indices.
*   `v8::NamedPropertyHandlerConfiguration`: Configures handlers for accessing object properties using string or symbol names.
*   `v8::PropertyCallbackInfo`:  Provides information about property access operations.
*   `v8::Intercepted`: An enum indicating whether a property access was intercepted.

The code defines various test cases (`THREADED_TEST`) that demonstrate how indexed property interceptors work. These tests cover scenarios like:

*   Getting and setting indexed properties.
*   Enumerating indexed properties.
*   Interactions with `Object.getOwnPropertyDescriptor`.
*   Cases where setters are not defined.
*   Access checks.
*   Handling different index types (negative, non-SMI).
*   Polymorphism and megamorphism.
*   Interactions with prototypes.
*   Impact on Inline Caches (ICs).
*   Property deletion.
*   Interactions with the `in` operator.
*   Interactions with function calls (Call ICs).
*   Handling exceptions thrown by interceptors.
*   Null interceptors.
*   Interactions with optimized code (TurboFan).
*   Interactions with `Object.getOwnPropertyNames` and `Object.getOwnPropertySymbols`.

To explain the JavaScript relationship, I need to illustrate how the C++ interceptor logic affects JavaScript behavior when accessing properties of objects created using templates with these interceptors.

I will go through the provided code and summarize each test case, then provide a JavaScript example that corresponds to one of the simpler tests.
这是 `v8/test/cctest/test-api-interceptors.cc` 文件的一部分，专门测试 V8 引擎中**索引属性拦截器 (indexed property interceptors)** 的功能。

**主要功能归纳：**

这个代码片段主要测试了当 JavaScript 代码尝试访问对象的**数字索引属性**时，V8 引擎如何与 C++ 中定义的拦截器进行交互。拦截器允许 C++ 代码自定义当 JavaScript 试图读取、写入、查询、删除或枚举对象的数字索引属性时发生的行为。

**具体测试的功能点包括：**

*   **基本的 Getter 和 Setter:** 测试当 JavaScript 代码读取或设置对象的数字索引属性时，自定义的 C++ Getter 和 Setter 如何被调用并影响结果。
*   **属性枚举:** 测试自定义的 C++ 枚举器如何影响 `for...in` 循环以及 `Object.getOwnPropertyNames` 和 `Object.getOwnPropertySymbols` 的行为。
*   **`Object.getOwnPropertyDescriptor`:** 测试索引属性拦截器如何与 `Object.getOwnPropertyDescriptor` 交互，返回自定义的属性描述符。
*   **无 Setter 情况:** 测试当只定义了 Getter 而没有 Setter 时，尝试设置索引属性的行为。
*   **访问检查:** 测试访问检查回调函数如何与索引属性拦截器协同工作，控制属性的访问权限。
*   **不同的索引类型:** 测试拦截器如何处理不同类型的索引，包括正数、负数、非整数等。
*   **性能优化 (IC - Inline Cache):**  测试索引属性拦截器如何影响 V8 的性能优化机制，例如内联缓存。测试了在不同场景下，IC 的命中、未命中以及失效的情况。
*   **原型链:** 测试当通过原型链访问索引属性时，拦截器如何工作。
*   **属性删除:** 测试自定义的 C++ 删除器如何拦截并影响 `delete` 操作。
*   **异常处理:** 测试当拦截器抛出异常时，V8 引擎如何处理。
*   **与优化编译器的交互 (TurboFan):** 测试索引属性拦截器在经过优化编译器处理的代码中的行为。

**与 JavaScript 的关系及示例：**

索引属性拦截器允许 C++ 代码在 JavaScript 对象上实现类似于“代理 (Proxy)”的功能，但专门针对数字索引的属性访问。

**JavaScript 示例：**

以下 JavaScript 代码展示了与 `DoubleWithIndexedAccessor` 测试用例相关的概念：

```javascript
// 假设在 C++ 中已经创建了一个带有索引属性拦截器的对象模板 'templ'

// 在 JavaScript 中创建一个基于该模板的对象
let obj = new globalThis.obj(); // globalThis.obj 是 C++ 中设置的全局对象

// 强制 obj 使用 FastDoubleArray 存储
obj[125000] = 1;
for(let i = 0; i < 80000; i+=2) {
  obj[i] = i;
}

let key_count = 0;
for (let x in obj) {
  key_count++;
}

console.log(obj[2000]); // 这会触发 C++ 中定义的 UnboxedDoubleIndexedPropertyGetter
console.log(key_count); // 这会受到 C++ 中定义的 UnboxedDoubleIndexedPropertyEnumerator 的影响
```

**解释：**

1. 在 C++ 代码中，`DoubleWithIndexedAccessor` 测试用例创建了一个 `ObjectTemplate`，并使用 `IndexedPropertyHandlerConfiguration` 配置了针对数字索引属性的自定义 Getter (`UnboxedDoubleIndexedPropertyGetter`)、Setter (`UnboxedDoubleIndexedPropertySetter`) 和枚举器 (`UnboxedDoubleIndexedPropertyEnumerator`)。
2. 在 JavaScript 中，我们基于这个模板创建了一个对象 `obj`。
3. 通过 `obj[125000] = 1` 和循环赋值的操作，V8 可能会将 `obj` 的内部存储优化为 `FastDoubleArray` 以提高性能，特别是当存储的都是数字时。
4. 当 JavaScript 代码尝试访问 `obj[2000]` 时，由于我们设置了索引属性拦截器，V8 不会直接访问对象内部的属性，而是会调用 C++ 中定义的 `UnboxedDoubleIndexedPropertyGetter` 函数。这个函数可以自定义返回的值。
5. `for...in` 循环会触发 C++ 中定义的 `UnboxedDoubleIndexedPropertyEnumerator` 函数，该函数决定了哪些索引会被枚举出来。在测试用例中，它被设计为返回特定的键集合，因此 `key_count` 的值会是 40013。

总之，这个代码片段是 V8 引擎测试框架的一部分，用于确保索引属性拦截器功能按照预期工作，允许 C++ 代码深度定制 JavaScript 对象的行为，特别是在处理数字索引属性时。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

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
    info.GetReturnValue().Set(call_ic_function5_global);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// This test checks that if interceptor provides a function,
// even if we cached constant function, interceptor's function
// is invoked
THREADED_TEST(InterceptorCallICConstantFunctionNotNeeded) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorCallICGetter5));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> call_ic_function5 =
      v8_compile("function f(x) { return x - 1; }; f")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function5_global.Reset(isolate, call_ic_function5);
  v8::Local<Value> value = CompileRun(
      "function inc(x) { return x + 1; };"
      "inc(1);"
      "o.x = inc;"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result = o.x(42);"
      "}");
  CHECK_EQ(41, value->Int32Value(context.local()).FromJust());
  call_ic_function5_global.Reset();
}

namespace {
v8::Global<Value> call_ic_function6_global;
v8::Intercepted InterceptorCallICGetter6(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    info.GetReturnValue().Set(call_ic_function6_global);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// Same test as above, except the code is wrapped in a function
// to test the optimized compiler.
THREADED_TEST(InterceptorCallICConstantFunctionNotNeededWrapped) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorCallICGetter6));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> call_ic_function6 =
      v8_compile("function f(x) { return x - 1; }; f")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function6_global.Reset(isolate, call_ic_function6);
  v8::Local<Value> value = CompileRun(
      "function inc(x) { return x + 1; };"
      "inc(1);"
      "o.x = inc;"
      "function test() {"
      "  var result = 0;"
      "  for (var i = 0; i < 1000; i++) {"
      "    result = o.x(42);"
      "  }"
      "  return result;"
      "};"
      "%PrepareFunctionForOptimization(test);"
      "test();"
      "test();"
      "test();"
      "%OptimizeFunctionOnNextCall(test);"
      "test()");
  CHECK_EQ(41, value->Int32Value(context.local()).FromJust());
  call_ic_function6_global.Reset();
}


// Test the case when we stored constant function into
// a stub, but it got invalidated later on
THREADED_TEST(InterceptorCallICInvalidatedConstantFunction) {
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
      "proto1 = new Object();"
      "proto2 = new Object();"
      "o.__proto__ = proto1;"
      "proto1.__proto__ = proto2;"
      "proto2.y = inc;"
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


// Test the case when we stored constant function into
// a stub, but it got invalidated later on due to override on
// global object which is between interceptor and constant function' holders.
THREADED_TEST(InterceptorCallICInvalidatedConstantFunctionViaGlobal) {
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
      "o.__proto__ = this;"
      "this.__proto__.y = inc;"
      // Invoke it many times to compile a stub
      "for (var i = 0; i < 7; i++) {"
      "  if (o.y(42) != 43) throw 'oops: ' + o.y(42);"
      "}"
      "this.y = function(x) { return x - 1; };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result += o.y(42);"
      "}");
  CHECK_EQ(41 * 7, value->Int32Value(context.local()).FromJust());
}


// Test the case when actual function to call sits on global object.
THREADED_TEST(InterceptorCallICCachedFromGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "try {"
      "  o.__proto__ = this;"
      "  for (var i = 0; i < 10; i++) {"
      "    var v = o.parseFloat('239');"
      "    if (v != 239) throw v;"
      // Now it should be ICed and keep a reference to parseFloat.
      "  }"
      "  var result = 0;"
      "  for (var i = 0; i < 10; i++) {"
      "    result += o.parseFloat('239');"
      "  }"
      "  result"
      "} catch(e) {"
      "  e"
      "};");
  CHECK_EQ(239 * 10, value->Int32Value(context.local()).FromJust());
}

namespace {
v8::Global<Value> keyed_call_ic_function_global;

v8::Intercepted InterceptorKeyedCallICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  if (v8_str("x")
          ->Equals(info.GetIsolate()->GetCurrentContext(), name)
          .FromJust()) {
    info.GetReturnValue().Set(keyed_call_ic_function_global);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// Test the case when we stored cacheable lookup into
// a stub, but the function name changed (to another cacheable function).
THREADED_TEST(InterceptorKeyedCallICKeyChange1) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "proto = new Object();"
      "proto.y = function(x) { return x + 1; };"
      "proto.z = function(x) { return x - 1; };"
      "o.__proto__ = proto;"
      "var result = 0;"
      "var method = 'y';"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) { method = 'z'; };"
      "  result += o[method](41);"
      "}");
  CHECK_EQ(42 * 5 + 40 * 5, context->Global()
                                ->Get(context.local(), v8_str("result"))
                                .ToLocalChecked()
                                ->Int32Value(context.local())
                                .FromJust());
}


// Test the case when we stored cacheable lookup into
// a stub, but the function name changed (and the new function is present
// both before and after the interceptor in the prototype chain).
THREADED_TEST(InterceptorKeyedCallICKeyChange2) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorKeyedCallICGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("proto1"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<v8::Value> keyed_call_ic_function =
      v8_compile("function f(x) { return x - 1; }; f")
          ->Run(context.local())
          .ToLocalChecked();
  keyed_call_ic_function_global.Reset(isolate, keyed_call_ic_function);
  CompileRun(
      "o = new Object();"
      "proto2 = new Object();"
      "o.y = function(x) { return x + 1; };"
      "proto2.y = function(x) { return x + 2; };"
      "o.__proto__ = proto1;"
      "proto1.__proto__ = proto2;"
      "var result = 0;"
      "var method = 'x';"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) { method = 'y'; };"
      "  result += o[method](41);"
      "}");
  CHECK_EQ(42 * 5 + 40 * 5, context->Global()
                                ->Get(context.local(), v8_str("result"))
                                .ToLocalChecked()
                                ->Int32Value(context.local())
                                .FromJust());
  keyed_call_ic_function_global.Reset();
}


// Same as InterceptorKeyedCallICKeyChange1 only the cacheable function sit
// on the global object.
THREADED_TEST(InterceptorKeyedCallICKeyChangeOnGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "function inc(x) { return x + 1; };"
      "inc(1);"
      "function dec(x) { return x - 1; };"
      "dec(1);"
      "o.__proto__ = this;"
      "this.__proto__.x = inc;"
      "this.__proto__.y = dec;"
      "var result = 0;"
      "var method = 'x';"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) { method = 'y'; };"
      "  result += o[method](41);"
      "}");
  CHECK_EQ(42 * 5 + 40 * 5, context->Global()
                                ->Get(context.local(), v8_str("result"))
                                .ToLocalChecked()
                                ->Int32Value(context.local())
                                .FromJust());
}


// Test the case when actual function to call sits on global object.
THREADED_TEST(InterceptorKeyedCallICFromGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  CompileRun(
      "function len(x) { return x.length; };"
      "o.__proto__ = this;"
      "var m = 'parseFloat';"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) {"
      "    m = 'len';"
      "    saved_result = result;"
      "  };"
      "  result = o[m]('239');"
      "}");
  CHECK_EQ(3, context->Global()
                  ->Get(context.local(), v8_str("result"))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK_EQ(239, context->Global()
                    ->Get(context.local(), v8_str("saved_result"))
                    .ToLocalChecked()
                    ->Int32Value(context.local())
                    .FromJust());
}


// Test the map transition before the interceptor.
THREADED_TEST(InterceptorKeyedCallICMapChangeBefore) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("proto"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  CompileRun(
      "var o = new Object();"
      "o.__proto__ = proto;"
      "o.method = function(x) { return x + 1; };"
      "var m = 'method';"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) { o.method = function(x) { return x - 1; }; };"
      "  result += o[m](41);"
      "}");
  CHECK_EQ(42 * 5 + 40 * 5, context->Global()
                                ->Get(context.local(), v8_str("result"))
                                .ToLocalChecked()
                                ->Int32Value(context.local())
                                .FromJust());
}


// Test the map transition after the interceptor.
THREADED_TEST(InterceptorKeyedCallICMapChangeAfter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(v8::NamedPropertyHandlerConfiguration(NoBlockGetterX));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  CompileRun(
      "var proto = new Object();"
      "o.__proto__ = proto;"
      "proto.method = function(x) { return x + 1; };"
      "var m = 'method';"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  if (i == 5) { proto.method = function(x) { return x - 1; }; };"
      "  result += o[m](41);"
      "}");
  CHECK_EQ(42 * 5 + 40 * 5, context->Global()
                                ->Get(context.local(), v8_str("result"))
                                .ToLocalChecked()
                                ->Int32Value(context.local())
                                .FromJust());
}

namespace {
int interceptor_call_count = 0;

v8::Intercepted InterceptorICRefErrorGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (!is_bootstrapping &&
      v8_str("x")
          ->Equals(info.GetIsolate()->GetCurrentContext(), name)
          .FromJust() &&
      interceptor_call_count++ < 20) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(call_ic_function2_global);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// This test should hit load and call ICs for the interceptor case.
// Once in a while, the interceptor will reply that a property was not
// found in which case we should get a reference error.
THREADED_TEST(InterceptorICReferenceErrors) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorICRefErrorGetter));
  is_bootstrapping = true;
  LocalContext context(nullptr, templ, v8::Local<Value>());
  is_bootstrapping = false;
  v8::Local<Value> call_ic_function2 =
      v8_compile("function h(x) { return x; }; h")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function2_global.Reset(isolate, call_ic_function2);
  v8::Local<Value> value = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 1000; i++) {"
      "    try { x; } catch(e) { return true; }"
      "  }"
      "  return false;"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
  interceptor_call_count = 0;
  value = CompileRun(
      "function g() {"
      "  for (var i = 0; i < 1000; i++) {"
      "    try { x(42); } catch(e) { return true; }"
      "  }"
      "  return false;"
      "};"
      "g();");
  CHECK(value->BooleanValue(isolate));
  call_ic_function2_global.Reset();
}

namespace {
int interceptor_ic_exception_get_count = 0;

v8::Intercepted InterceptorICExceptionGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  if (is_bootstrapping) return v8::Intercepted::kNo;
  if (v8_str("x")
          ->Equals(info.GetIsolate()->GetCurrentContext(), name)
          .FromJust() &&
      ++interceptor_ic_exception_get_count < 20) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(call_ic_function3_global);
  }
  if (interceptor_ic_exception_get_count == 20) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetIsolate()->ThrowException(v8_num(42));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// Test interceptor load/call IC where the interceptor throws an
// exception once in a while.
THREADED_TEST(InterceptorICGetterExceptions) {
  interceptor_ic_exception_get_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorICExceptionGetter));
  is_bootstrapping = true;
  LocalContext context(nullptr, templ, v8::Local<Value>());
  is_bootstrapping = false;
  v8::Local<Value> call_ic_function3 =
      v8_compile("function h(x) { return x; }; h")
          ->Run(context.local())
          .ToLocalChecked();
  call_ic_function3_global.Reset(isolate, call_ic_function3);
  v8::Local<Value> value = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 100; i++) {"
      "    try { x; } catch(e) { return true; }"
      "  }"
      "  return false;"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
  interceptor_ic_exception_get_count = 0;
  value = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 100; i++) {"
      "    try { x(42); } catch(e) { return true; }"
      "  }"
      "  return false;"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
  call_ic_function3_global.Reset();
}

namespace {
int interceptor_ic_exception_set_count = 0;

v8::Intercepted InterceptorICExceptionSetter(
    Local<Name> key, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  if (++interceptor_ic_exception_set_count > 20) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetIsolate()->ThrowException(v8_num(42));
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}
}  // namespace

// Test interceptor store IC where the interceptor throws an exception
// once in a while.
THREADED_TEST(InterceptorICSetterExceptions) {
  interceptor_ic_exception_set_count = 0;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      nullptr, InterceptorICExceptionSetter));
  LocalContext context(nullptr, templ, v8::Local<Value>());
  v8::Local<Value> value = CompileRun(
      "function f() {"
      "  for (var i = 0; i < 100; i++) {"
      "    try { x = 42; } catch(e) { return true; }"
      "  }"
      "  return false;"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
}


// Test that we ignore null interceptors.
THREADED_TEST(NullNamedInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      static_cast<v8::NamedPropertyGetterCallback>(nullptr)));
  LocalContext context;
  templ->Set(CcTest::isolate(), "x", v8_num(42));
  v8::Local<v8::Object> obj =
      templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();
  v8::Local<Value> value = CompileRun("obj.x");
  CHECK(value->IsInt32());
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
}


// Test that we ignore null interceptors.
THREADED_TEST(NullIndexedInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      static_cast<v8::IndexedPropertyGetterCallbackV2>(nullptr)));
  LocalContext context;
  templ->Set(CcTest::isolate(), "42", v8_num(42));
  v8::Local<v8::Object> obj =
      templ->NewInstance(context.local()).ToLocalChecked();
  context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust();
  v8::Local<Value> value = CompileRun("obj[42]");
  CHECK(value->IsInt32());
  CHECK_EQ(42, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(NamedPropertyHandlerGetterAttributes) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::FunctionTemplate> templ = v8::FunctionTemplate::New(isolate);
  templ->InstanceTemplate()->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
                                            .ToLocalChecked()
                                            ->NewInstance(env.local())
                                            .ToLocalChecked())
      .FromJust();
  ExpectTrue("obj.x === 42");
  ExpectTrue("!obj.propertyIsEnumerable('x')");
}


THREADED_TEST(Regress256330) {
  if (!i::v8_flags.turbofan) return;
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  AddInterceptor(templ, InterceptorGetter, InterceptorSetter);
  context->Global()
      ->Set(context.local(), v8_str("Bug"),
            templ->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "\"use strict\"; var o = new Bug;"
      "function f(o) { o.x = 10; };"
      "%PrepareFunctionForOptimization(f);"
      "f(o); f(o); f(o);"
      "%OptimizeFunctionOnNextCall(f);"
      "f(o);");
  int status = v8_run_int32value(v8_compile("%GetOptimizationStatus(f)"));
  int mask = static_cast<int>(i::OptimizationStatus::kIsFunction) |
             static_cast<int>(i::OptimizationStatus::kOptimized);
  CHECK_EQ(mask, status & mask);
}

THREADED_TEST(OptimizedInterceptorSetter) {
  i::v8_flags.allow_natives_syntax = true;
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
      // Initialize fields to avoid transitions later.
      "obj.age = 0;"
      "obj.accessor_age = 42;"
      "function setter(i) { this.accessor_age = i; };"
      "function getter() { return this.accessor_age; };"
      "function setAge(i) { obj.age = i; };"
      "Object.defineProperty(obj, 'age', { get:getter, set:setter });"
      "%PrepareFunctionForOptimization(setAge);"
      "setAge(1);"
      "setAge(2);"
      "setAge(3);"
      "%OptimizeFunctionOnNextCall(setAge);"
      "setAge(4);");
  // All stores went through the interceptor.
  ExpectInt32("obj.interceptor_age", 4);
  ExpectInt32("obj.accessor_age", 42);
}

THREADED_TEST(OptimizedInterceptorGetter) {
  i::v8_flags.allow_natives_syntax = true;
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
      // Initialize fields to avoid transitions later.
      "obj.age = 1;"
      "obj.accessor_age = 42;"
      "function getter() { return this.accessor_age; };"
      "function getAge() { return obj.interceptor_age; };"
      "Object.defineProperty(obj, 'interceptor_age', { get:getter });"
      "%PrepareFunctionForOptimization(getAge);"
      "getAge();"
      "getAge();"
      "getAge();"
      "%OptimizeFunctionOnNextCall(getAge);");
  // Access through interceptor.
  ExpectInt32("getAge()", 1);
}

THREADED_TEST(OptimizedInterceptorFieldRead) {
  i::v8_flags.allow_natives_syntax = true;
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
      "obj.__proto__.interceptor_age = 42;"
      "obj.age = 100;"
      "function getAge() { return obj.interceptor_age; };"
      "%PrepareFunctionForOptimization(getAge);");
  ExpectInt32("getAge();", 100);
  ExpectInt32("getAge();", 100);
  ExpectInt32("getAge();", 100);
  CompileRun("%OptimizeFunctionOnNextCall(getAge);");
  // Access through interceptor.
  ExpectInt32("getAge();", 100);
}

THREADED_TEST(OptimizedInterceptorFieldWrite) {
  i::v8_flags.allow_natives_syntax = true;
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
      "obj.age = 100000;"
      "function setAge(i) { obj.age = i };"
      "%PrepareFunctionForOptimization(setAge);"
      "setAge(100);"
      "setAge(101);"
      "setAge(102);"
      "%OptimizeFunctionOnNextCall(setAge);"
      "setAge(103);");
  ExpectInt32("obj.age", 100000);
  ExpectInt32("obj.interceptor_age", 103);
}


THREADED_TEST(Regress149912) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  AddInterceptor(templ, EmptyInterceptorGetter, EmptyInterceptorSetter);
  context->Global()
      ->Set(context.local(), v8_str("Bug"),
            templ->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun("Number.prototype.__proto__ = new Bug; var x = 0; x.foo();");
}

THREADED_TEST(Regress625155) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  AddInterceptor(templ, EmptyInterceptorGetter, EmptyInterceptorSetter);
  context->Global()
      ->Set(context.local(), v8_str("Bug"),
            templ->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "Number.prototype.__proto__ = new Bug;"
      "var x;"
      "x = 0xDEAD;"
      "x.boom = 0;"
      "x = 's';"
      "x.boom = 0;"
      "x = 1.5;"
      "x.boom = 0;");
}

THREADED_TEST(Regress125988) {
  v8::HandleScope scope(CcTest::isolate());
  Local<FunctionTemplate> intercept = FunctionTemplate::New(CcTest::isolate());
  AddInterceptor(intercept, EmptyInterceptorGetter, EmptyInterceptorSetter);
  LocalContext env;
  env->Global()
      ->Set(env.local(), v8_str("Intercept"),
            intercept->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "var a = new Object();"
      "var b = new Intercept();"
      "var c = new Object();"
      "c.__proto__ = b;"
      "b.__proto__ = a;"
      "a.x = 23;"
      "for (var i = 0; i < 3; i++) c.x;");
  ExpectBoolean("c.hasOwnProperty('x')", false);
  ExpectInt32("c.x", 23);
  CompileRun(
      "a.y = 42;"
      "for (var i = 0; i < 3; i++) c.x;");
  ExpectBoolean("c.hasOwnProperty('x')", false);
  ExpectInt32("c.x", 23);
  ExpectBoolean("c.hasOwnProperty('y')", false);
  ExpectInt32("c.y", 42);
}

namespace {
void IndexedPropertyEnumerator(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 1);
  result->Set(info.GetIsolate()->GetCurrentContext(), 0,
              v8::Integer::New(info.GetIsolate(), 7))
      .FromJust();
  info.GetReturnValue().Set(result);
}

void NamedPropertyEnumerator(const v8::PropertyCallbackInfo<v8::Array>& info) {
  v8::Local<v8::Array> result = v8::Array::New(info.GetIsolate(), 2);
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  result->Set(context, 0, v8_str("x")).FromJust();
  result->Set(context, 1, v8::Symbol::GetIterator(info.GetIsolate()))
      .FromJust();
  info.GetReturnValue().Set(result);
}
}  // namespace

THREADED_TEST(GetOwnPropertyNamesWithInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);

  obj_template->Set(isolate, "7", v8::Integer::New(isolate, 7));
  obj_template->Set(isolate, "x", v8::Integer::New(isolate, 42));
  obj_template->SetHandler(v8::IndexedPropertyHandlerConfiguration(
      static_cast<v8::IndexedPropertyGetterCallbackV2>(nullptr), nullptr,
      nullptr, nullptr, IndexedPropertyEnumerator));
  obj_template->SetHandler(v8::NamedPropertyHandlerConfiguration(
      static_cast<v8::NamedPropertyGetterCallback>(nullptr), nullptr, nullptr,
      nullptr, NamedPropertyEnumerator));

  LocalContext context;
  v8::Local<v8::Object> global = context->Global();
  global->Set(context.local(), v8_str("object"),
              obj_template->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<v8::Value> result =
      CompileRun("Object.getOwnPropertyNames(object)");
  CHECK(result->IsArray());
  v8::Local<v8::Array> result_array = result.As<v8::Array>();
  CHECK_EQ(2u, result_array->Length());
  CHECK(result_array->Get(context.local(), 0).ToLocalChecked()->IsString());
  CHECK(result_array->Get(context.local(), 1).ToLocalChecked()->IsString());
  CHECK(v8_str("7")
            ->Equals(context.local(),
                     result_array->Get(context.local(), 0).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("x")
            ->Equals(context.local(),
                     result_array->Get(context.local(), 1).ToLocalChecked())
            .FromJust());

  result = CompileRun("var ret = []; for (var k in object) ret.push(k); ret");
  CHECK(result->IsArray());
  result_array = result.As<v8::Array>();
  CHECK_EQ(2u, result_array->Length());
  CHECK(result_array->Get(context.local(), 0).ToLocalChecked()->IsString());
  CHECK(result_array->Get(context.local(), 1).ToLocalChecked()->IsString());
  CHECK(v8_str("7")
            ->Equals(context.local(),
                     result_array->Get(context.local(), 0).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("x")
            ->Equals(context.local(),
                     result_array->Get(context.local(), 1).ToLocalChecked())
            .FromJust());

  result = CompileRun("Object.getOwnPropertySymbols(object)");
  CHECK(result->IsArray());
  result_array = result.As<v8::Array>();
  CHECK_EQ(1u, result_array->Length());
  CHECK(result_array->Get(context.local(), 0)
            .ToLocalChecked()
            ->Equals(context.local(), v8::Symbol::GetIterator(isolate))
            .FromJust());
}

namespace {
void IndexedPropertyEnumeratorException(
    const v8::PropertyCallbackInfo<v8::Array>& info) {
  info.GetIsolate()->ThrowException(v8_num(42));
}
}  // namespace

THREADED_TEST(GetOwnPropertyNamesWithIndexedInterceptorExceptions_regress4026) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope handle_scope(isolate);
  v8::Local<v8::ObjectTemplate> obj_template = v8::ObjectTemplate::New(isolate);

  obj_template->Set(isolate, "7", v8::Integer::New(isolate, 7));
  obj_template->
"""


```