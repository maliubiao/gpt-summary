Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from the V8 JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name and the code itself clearly indicate that it's testing the "API interceptors" feature in V8. Interceptors allow developers to hook into property access (get, set, has, define) and modify or control that access.

2. **Analyze the code structure:** The code consists of multiple `THREADED_TEST` functions. Each test likely focuses on a specific scenario or edge case related to interceptors. Helper functions like `CheckInterceptorIC`, `CheckInterceptorLoadIC`, and callback functions (e.g., `InterceptorLoadICGetter`) are used to set up and verify the behavior.

3. **Categorize the tests:**  Group the tests by the aspect of interceptors they are verifying. This helps in summarizing the overall functionality. Looking at the test names, some categories emerge:
    * Load IC (Instruction Cache) with interceptors
    * Has IC with interceptors
    * Store IC with interceptors
    * Define IC with interceptors
    * Interactions with prototypes and inheritance
    * Interactions with global objects
    * Side effects within interceptor callbacks

4. **Explain key concepts:** Define what interceptors are and why they are important.

5. **Illustrate with JavaScript examples:**  Demonstrate how these interceptor behaviors would manifest in JavaScript. This is crucial for understanding the practical implications.

6. **Infer potential programming errors:** Based on the tests, identify common mistakes developers might make when using interceptors or when interacting with code that uses them.

7. **Address specific instructions:**  Ensure all parts of the prompt are answered, such as checking for `.tq` files.

**Mental Walkthrough and Refinement:**

* Initially, I might think of simply listing all the tests. However, that's not a good summary. Grouping them by functionality is key.
* The prompt asks about `.tq` files. I need to explicitly state that this file is `.cc` and thus not a Torque file.
* The request for JavaScript examples is crucial. I need to choose simple, clear examples that directly relate to the C++ test cases.
*  For code logic, I need to select a representative test and provide a clear input and expected output.
* The "common programming errors" part requires thinking about the potential pitfalls of using interceptors, like unintended side effects or confusion about the order of operations.

By following this thought process, I can construct a comprehensive and informative summary of the provided C++ code.
这是 V8 源代码文件 `v8/test/cctest/test-api-interceptors.cc` 的第二部分，主要关注 V8 的 API 拦截器 (interceptors) 的功能测试，特别是针对属性加载 (load) 和存在性检查 (has) 的场景。它通过一系列的 C++ 测试用例来验证当对象上设置了属性拦截器时，V8 引擎在执行 JavaScript 代码时的行为是否符合预期。

**功能归纳 (基于提供的第二部分代码):**

这一部分主要测试了**属性加载 (LoadIC)** 和 **属性存在性检查 (HasIC)** 在有拦截器存在的情况下的优化和行为。具体来说，它测试了以下方面：

1. **基础的 LoadIC 拦截器调用:** 验证当访问对象的属性时，如果存在拦截器，LoadIC (Load Inline Cache) 机制能够正确调用拦截器。
2. **LoadIC 拦截器与持有者 (holder) 上的字段:** 测试当拦截器对象本身持有某个字段时，LoadIC 的行为。
3. **LoadIC 拦截器与被替换的原型链:** 验证当对象的原型链被替换后，LoadIC 和拦截器如何协同工作。
4. **LoadIC 拦截器与原型上的属性:** 测试当要访问的属性定义在对象的原型上时，拦截器和 LoadIC 的交互。
5. **LoadIC 拦截器返回 undefined 的情况:** 验证拦截器不处理该属性访问时，LoadIC 的行为。
6. **LoadIC 拦截器与属性覆盖:** 测试原型链中属性被覆盖的情况，以及拦截器如何影响属性查找。
7. **LoadIC 拦截器与已存储但不需要的字段:**  测试 LoadIC 可能缓存了来自原型的属性，但在有拦截器的情况下，仍然会调用拦截器的情况。
8. **LoadIC 拦截器与失效的字段:** 测试 LoadIC 缓存了来自原型的属性，但原型上的属性失效后，LoadIC 的行为。
9. **LoadIC 拦截器与后拦截器查找:** 测试拦截器不处理属性访问时，后续原型链查找的行为。
10. **LoadIC 拦截器与通过全局对象失效的字段:** 测试原型链中包含全局对象时，全局对象上的属性变更如何影响拦截器和 LoadIC。
11. **LoadIC 拦截器与持有者上的回调:** 验证当属性由持有者上的回调函数提供时，拦截器和 LoadIC 的交互。
12. **LoadIC 拦截器与原型上的回调:** 测试当属性由原型上的回调函数提供时，拦截器和 LoadIC 的交互。
13. **LoadIC 拦截器与回调的覆盖:** 验证原型链中回调函数被覆盖的情况，以及拦截器如何影响属性查找。
14. **LoadIC 拦截器回调不需要的情况:** 测试 LoadIC 缓存了来自原型的回调，但在有拦截器的情况下，仍然会调用拦截器的情况。
15. **LoadIC 拦截器回调失效的情况:** 测试 LoadIC 缓存了来自原型的回调，但原型上的回调失效后，LoadIC 的行为。
16. **LoadIC 拦截器回调通过全局对象失效的情况:** 测试原型链中包含全局对象时，全局对象上的回调变更如何影响拦截器和 LoadIC。
17. **LoadIC 拦截器在全局对象上的测试:** 验证当全局对象设置了拦截器时，访问不存在的全局变量的行为。
18. **HasIC 拦截器测试:** 验证属性存在性检查操作 (`in` 运算符) 在有拦截器存在的情况下的行为。包括拦截器不处理、返回存在、返回不存在等情况。
19. **HasIC 拦截器与 Getter 的交互:** 测试当同时存在拦截器和 Getter 时，`in` 运算符的行为。
20. **HasIC 拦截器和副作用回调:** 测试在 `in` 运算符的拦截器回调中执行有副作用的代码。

**关于文件类型和 JavaScript 关系:**

* `v8/test/cctest/test-api-interceptors.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque (`.tq`) 文件。
* 这个文件 **与 JavaScript 的功能有直接关系**，因为它测试了 V8 引擎执行 JavaScript 代码时，关于 API 拦截器的行为。

**JavaScript 举例说明 (对应 LoadIC 和 HasIC 的部分功能):**

```javascript
// 模拟 C++ 代码中 InterceptorLoadICGetter 的行为
function interceptorGetter(obj, prop) {
  if (prop === 'x') {
    console.log('Interceptor called for property "x"');
    return 42;
  }
  return undefined; // 拦截器不处理其他属性
}

function MyClass() {
  // ...
}

// 设置拦截器
Object.defineProperty(MyClass.prototype, '__lookupGetter__', { // 注意：__lookupGetter__ 是非标准的，这里仅为示例
  value: function(name) {
    return interceptorGetter;
  },
  enumerable: false,
  configurable: true
});

const obj = new MyClass();

// 当访问 obj.x 时，拦截器会被调用
console.log(obj.x); // 输出: Interceptor called for property "x", 42

// 当访问 obj.y 时，拦截器不处理，返回 undefined
console.log(obj.y); // 输出: undefined

// 模拟 C++ 代码中 NamedQueryCallback 的行为
function interceptorHas(obj, prop) {
  console.log(`Interceptor called for 'in' operator on property "${prop}"`);
  return false; // 假设拦截器总是返回 false
}

Object.defineProperty(MyClass.prototype, '__has__', { // 注意：__has__ 是非标准的，这里仅为示例
  value: interceptorHas,
  enumerable: false,
  configurable: true
});

// 当使用 'x' in obj 时，拦截器会被调用
console.log('x' in obj); // 输出: Interceptor called for 'in' operator on property "x", false
```

**代码逻辑推理和假设输入输出 (以 `InterceptorLoadIC` 测试为例):**

**假设输入:**

1. 创建一个 JavaScript 函数模板 `fun_templ`。
2. 为该模板的实例模板设置一个命名属性处理器，使用 `InterceptorHasOwnPropertyGetterGC` 作为 Getter。
3. 创建一个由该模板生成的函数 `constructor`。
4. 将 `constructor` 函数设置为全局对象的属性 "constructor"。
5. 执行一些 JavaScript 代码进行 GC (模拟内存压力)。
6. 执行 JavaScript 代码：
   ```javascript
   var o = new constructor();
   o.__proto__ = new String(x);
   o.hasOwnProperty('ostehaps');
   ```

**代码逻辑推理:**

* 创建的对象 `o` 的原型被设置为一个字符串对象。
* 调用 `o.hasOwnProperty('ostehaps')` 会检查 `o` 自身是否具有名为 'ostehaps' 的属性。由于 `o` 自身没有定义任何属性，并且其原型 (字符串对象) 上也没有名为 'ostehaps' 的属性，因此应该返回 `false`。
* `InterceptorHasOwnPropertyGetterGC` 的存在可能会影响 `hasOwnProperty` 的查找过程，但在这个特定的测试中，由于属性不存在于对象自身或其原型链上，拦截器应该不会改变最终结果。

**假设输出:**

`CHECK(!value->BooleanValue(isolate));`  这行代码表示断言 `o.hasOwnProperty('ostehaps')` 的返回值在转换为布尔值后为 `false`。

**用户常见的编程错误 (与拦截器相关):**

1. **未预料到的副作用:** 在拦截器回调函数中执行了意想不到的副作用，导致程序状态难以预测。例如，在 Getter 拦截器中修改了其他对象的属性。
   ```javascript
   let globalCounter = 0;
   function badGetter(obj, prop) {
     globalCounter++; // 不良实践：在 Getter 中修改全局状态
     return obj['_' + prop];
   }
   ```
2. **拦截器逻辑不严谨:** 拦截器回调函数的逻辑考虑不全面，导致某些属性访问没有被正确处理，或者处理方式不符合预期。
   ```javascript
   function incompleteGetter(obj, prop) {
     if (prop === 'importantValue') {
       return calculateImportantValue();
     }
     // 忘记处理其他属性的访问
   }
   ```
3. **过度使用拦截器:** 对所有属性都设置拦截器，即使很多属性的访问不需要特殊处理，这会降低性能。
4. **混淆拦截器和 Proxy:** 虽然拦截器和 Proxy 都可以用于拦截属性访问，但它们的使用场景和 API 有所不同。混淆两者可能导致代码错误。
5. **忽略性能影响:** 拦截器会增加属性访问的开销，如果使用不当，可能会显著影响性能。

总而言之，`v8/test/cctest/test-api-interceptors.cc` 的第二部分专注于测试 V8 引擎在处理带有拦截器的对象的属性加载和存在性检查时的内部机制，确保这些机制在各种情况下都能正确高效地工作。

### 提示词
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::FunctionTemplate> fun_templ = v8::FunctionTemplate::New(isolate);
  Local<v8::ObjectTemplate> instance_templ = fun_templ->InstanceTemplate();
  instance_templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorHasOwnPropertyGetterGC));
  Local<Function> function =
      fun_templ->GetFunction(context.local()).ToLocalChecked();
  context->Global()
      ->Set(context.local(), v8_str("constructor"), function)
      .FromJust();
  // Let's first make some stuff so we can be sure to get a good GC.
  CompileRun(
      "function makestr(size) {"
      "  switch (size) {"
      "    case 1: return 'f';"
      "    case 2: return 'fo';"
      "    case 3: return 'foo';"
      "  }"
      "  return makestr(size >> 1) + makestr((size + 1) >> 1);"
      "}"
      "var x = makestr(12345);"
      "x = makestr(31415);"
      "x = makestr(23456);");
  v8::Local<Value> value = CompileRun(
      "var o = new constructor();"
      "o.__proto__ = new String(x);"
      "o.hasOwnProperty('ostehaps');");
  CHECK(!value->BooleanValue(isolate));
}

namespace {

void CheckInterceptorIC(v8::NamedPropertyGetterCallback getter,
                        v8::NamedPropertySetterCallback setter,
                        v8::NamedPropertyQueryCallback query,
                        v8::NamedPropertyDefinerCallback definer,
                        v8::PropertyHandlerFlags flags, const char* source,
                        std::optional<int> expected) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      getter, setter, query, nullptr /* deleter */, nullptr /* enumerator */,
      definer, nullptr /* descriptor */, v8_str("data"), flags));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(source);
  if (expected) {
    CHECK_EQ(*expected, value->Int32Value(context.local()).FromJust());
  } else {
    CHECK(value.IsEmpty());
  }
}

void CheckInterceptorIC(v8::NamedPropertyGetterCallback getter,
                        v8::NamedPropertyQueryCallback query,
                        const char* source, std::optional<int> expected) {
  CheckInterceptorIC(getter, nullptr, query, nullptr,
                     v8::PropertyHandlerFlags::kNone, source, expected);
}

void CheckInterceptorLoadIC(v8::NamedPropertyGetterCallback getter,
                            const char* source, int expected) {
  CheckInterceptorIC(getter, nullptr, nullptr, nullptr,
                     v8::PropertyHandlerFlags::kNone, source, expected);
}

v8::Intercepted InterceptorLoadICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK(v8_str("data")->Equals(context, info.Data()).FromJust());
  CHECK(v8_str("x")->Equals(context, name).FromJust());
  info.GetReturnValue().Set(v8::Integer::New(isolate, 42));
  return v8::Intercepted::kYes;
}

}  // namespace

// This test should hit the load IC for the interceptor case.
THREADED_TEST(InterceptorLoadIC) {
  CheckInterceptorLoadIC(InterceptorLoadICGetter,
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.x;"
                         "}",
                         42);
}


// Below go several tests which verify that JITing for various
// configurations of interceptor and explicit fields works fine
// (those cases are special cased to get better performance).

namespace {

v8::Intercepted InterceptorLoadXICGetter(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(42);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

v8::Intercepted InterceptorLoadXICGetterWithSideEffects(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  // TODO(ishell): figure out what is the test supposed to do regarding
  // producing side effects but claiming that the interceptor hasn't
  // intercepted the operation. Is it about restarting the lookup iterator?
  ApiTestFuzzer::Fuzz();
  CompileRun("interceptor_getter_side_effect()");
  v8::Isolate* isolate = info.GetIsolate();
  if (v8_str("x")->Equals(isolate->GetCurrentContext(), name).FromJust()) {
    info.GetReturnValue().Set(42);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

}  // namespace

THREADED_TEST(InterceptorLoadICWithFieldOnHolder) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.y = 239;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y;"
                         "}",
                         239);
}


THREADED_TEST(InterceptorLoadICWithSubstitutedProto) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.__proto__ = { 'y': 239 };"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y + o.x;"
                         "}",
                         239 + 42);
}


THREADED_TEST(InterceptorLoadICWithPropertyOnProto) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "o.__proto__.y = 239;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = o.y + o.x;"
                         "}",
                         239 + 42);
}


THREADED_TEST(InterceptorLoadICUndefined) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = (o.y == undefined) ? 239 : 42;"
                         "}",
                         239);
}


THREADED_TEST(InterceptorLoadICWithOverride) {
  CheckInterceptorLoadIC(InterceptorLoadXICGetter,
                         "fst = new Object();  fst.__proto__ = o;"
                         "snd = new Object();  snd.__proto__ = fst;"
                         "var result1 = 0;"
                         "for (var i = 0; i < 1000;  i++) {"
                         "  result1 = snd.x;"
                         "}"
                         "fst.x = 239;"
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result = snd.x;"
                         "}"
                         "result + result1",
                         239 + 42);
}


// Test the case when we stored field into
// a stub, but interceptor produced value on its own.
THREADED_TEST(InterceptorLoadICFieldNotNeeded) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "proto = new Object();"
      "o.__proto__ = proto;"
      "proto.x = 239;"
      "for (var i = 0; i < 1000; i++) {"
      "  o.x;"
      // Now it should be ICed and keep a reference to x defined on proto
      "}"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result += o.x;"
      "}"
      "result;",
      42 * 1000);
}


// Test the case when we stored field into
// a stub, but it got invalidated later on.
THREADED_TEST(InterceptorLoadICInvalidatedField) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "proto1 = new Object();"
      "proto2 = new Object();"
      "o.__proto__ = proto1;"
      "proto1.__proto__ = proto2;"
      "proto2.y = 239;"
      "for (var i = 0; i < 1000; i++) {"
      "  o.y;"
      // Now it should be ICed and keep a reference to y defined on proto2
      "}"
      "proto1.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 1000; i++) {"
      "  result += o.y;"
      "}"
      "result;",
      42 * 1000);
}

namespace {

int interceptor_load_not_handled_calls = 0;
v8::Intercepted InterceptorLoadNotHandled(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ++interceptor_load_not_handled_calls;
  return v8::Intercepted::kNo;
}
}  // namespace

// Test how post-interceptor lookups are done in the non-cacheable
// case: the interceptor should not be invoked during this lookup.
THREADED_TEST(InterceptorLoadICPostInterceptor) {
  interceptor_load_not_handled_calls = 0;
  CheckInterceptorLoadIC(InterceptorLoadNotHandled,
                         "receiver = new Object();"
                         "receiver.__proto__ = o;"
                         "proto = new Object();"
                         "/* Make proto a slow-case object. */"
                         "for (var i = 0; i < 1000; i++) {"
                         "  proto[\"xxxxxxxx\" + i] = [];"
                         "}"
                         "proto.x = 17;"
                         "o.__proto__ = proto;"
                         "var result = 0;"
                         "for (var i = 0; i < 1000; i++) {"
                         "  result += receiver.x;"
                         "}"
                         "result;",
                         17 * 1000);
  CHECK_EQ(1000, interceptor_load_not_handled_calls);
}


// Test the case when we stored field into
// a stub, but it got invalidated later on due to override on
// global object which is between interceptor and fields' holders.
THREADED_TEST(InterceptorLoadICInvalidatedFieldViaGlobal) {
  CheckInterceptorLoadIC(
      InterceptorLoadXICGetter,
      "o.__proto__ = this;"  // set a global to be a proto of o.
      "this.__proto__.y = 239;"
      "for (var i = 0; i < 10; i++) {"
      "  if (o.y != 239) throw 'oops: ' + o.y;"
      // Now it should be ICed and keep a reference to y defined on
      // field_holder.
      "}"
      "this.y = 42;"  // Assign on a global.
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result;",
      42 * 10);
}

static void SetOnThis(Local<Name> name, Local<Value> value,
                      const v8::PropertyCallbackInfo<void>& info) {
  info.This()
      .As<Object>()
      ->CreateDataProperty(info.GetIsolate()->GetCurrentContext(), name, value)
      .FromJust();
}

THREADED_TEST(InterceptorLoadICWithCallbackOnHolder) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  templ->SetNativeDataProperty(v8_str("y"), Return239Callback);
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Check the case when receiver and interceptor's holder
  // are the same objects.
  v8::Local<Value> value = CompileRun(
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = o.y;"
      "}");
  CHECK_EQ(239, value->Int32Value(context.local()).FromJust());

  // Check the case when interceptor's holder is in proto chain
  // of receiver.
  value = CompileRun(
      "r = { __proto__: o };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = r.y;"
      "}");
  CHECK_EQ(239, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(InterceptorLoadICWithCallbackOnProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  // Check the case when receiver and interceptor's holder
  // are the same objects.
  v8::Local<Value> value = CompileRun(
      "o.__proto__ = p;"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = o.x + o.y;"
      "}");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());

  // Check the case when interceptor's holder is in proto chain
  // of receiver.
  value = CompileRun(
      "r = { __proto__: o };"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = r.x + r.y;"
      "}");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}


THREADED_TEST(InterceptorLoadICForCallbackWithOverride) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  templ->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "fst = new Object();  fst.__proto__ = o;"
      "snd = new Object();  snd.__proto__ = fst;"
      "var result1 = 0;"
      "for (var i = 0; i < 7;  i++) {"
      "  result1 = snd.x;"
      "}"
      "fst.x = 239;"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result = snd.x;"
      "}"
      "result + result1");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but interceptor produced value on its own.
THREADED_TEST(InterceptorLoadICCallbackNotNeeded) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "o.__proto__ = p;"
      "for (var i = 0; i < 7; i++) {"
      "  o.x;"
      // Now it should be ICed and keep a reference to x defined on p
      "}"
      "var result = 0;"
      "for (var i = 0; i < 7; i++) {"
      "  result += o.x;"
      "}"
      "result");
  CHECK_EQ(42 * 7, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but it got invalidated later on.
THREADED_TEST(InterceptorLoadICInvalidatedCallback) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback, SetOnThis);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "inbetween = new Object();"
      "o.__proto__ = inbetween;"
      "inbetween.__proto__ = p;"
      "for (var i = 0; i < 10; i++) {"
      "  o.y;"
      // Now it should be ICed and keep a reference to y defined on p
      "}"
      "inbetween.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result");
  CHECK_EQ(42 * 10, value->Int32Value(context.local()).FromJust());
}


// Test the case when we stored callback into
// a stub, but it got invalidated later on due to override on
// global object which is between interceptor and callbacks' holders.
THREADED_TEST(InterceptorLoadICInvalidatedCallbackViaGlobal) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_o = ObjectTemplate::New(isolate);
  templ_o->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  v8::Local<v8::ObjectTemplate> templ_p = ObjectTemplate::New(isolate);
  templ_p->SetNativeDataProperty(v8_str("y"), Return239Callback, SetOnThis);

  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ_o->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  context->Global()
      ->Set(context.local(), v8_str("p"),
            templ_p->NewInstance(context.local()).ToLocalChecked())
      .FromJust();

  v8::Local<Value> value = CompileRun(
      "o.__proto__ = this;"
      "this.__proto__ = p;"
      "for (var i = 0; i < 10; i++) {"
      "  if (o.y != 239) throw 'oops: ' + o.y;"
      // Now it should be ICed and keep a reference to y defined on p
      "}"
      "this.y = 42;"
      "var result = 0;"
      "for (var i = 0; i < 10; i++) {"
      "  result += o.y;"
      "}"
      "result");
  CHECK_EQ(42 * 10, value->Int32Value(context.local()).FromJust());
}

// Test load of a non-existing global when a global object has an interceptor.
THREADED_TEST(InterceptorLoadGlobalICGlobalWithInterceptor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_global = v8::ObjectTemplate::New(isolate);
  templ_global->SetHandler(v8::NamedPropertyHandlerConfiguration(
      EmptyInterceptorGetter, EmptyInterceptorSetter));

  LocalContext context(nullptr, templ_global);
  i::DirectHandle<i::JSReceiver> global_proxy =
      v8::Utils::OpenDirectHandle<Object, i::JSReceiver>(context->Global());
  CHECK(IsJSGlobalProxy(*global_proxy));
  i::DirectHandle<i::JSGlobalObject> global(
      i::Cast<i::JSGlobalObject>(global_proxy->map()->prototype()),
      global_proxy->GetIsolate());
  CHECK(global->map()->has_named_interceptor());

  v8::Local<Value> value = CompileRun(
      "var f = function() { "
      "  try {"
      "    x1;"
      "  } catch(e) {"
      "  }"
      "  return typeof x1 === 'undefined';"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));

  value = CompileRun(
      "var f = function() { "
      "  try {"
      "    x2;"
      "    return false;"
      "  } catch(e) {"
      "    return true;"
      "  }"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));

  value = CompileRun(
      "var f = function() { "
      "  try {"
      "    typeof(x3);"
      "    return true;"
      "  } catch(e) {"
      "    return false;"
      "  }"
      "};"
      "for (var i = 0; i < 10; i++) {"
      "  f();"
      "};"
      "f();");
  CHECK(value->BooleanValue(isolate));
}

// Test load of a non-existing global through prototype chain when a global
// object has an interceptor.
THREADED_TEST(InterceptorLoadICGlobalWithInterceptor) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ_global = v8::ObjectTemplate::New(isolate);
  templ_global->SetHandler(v8::NamedPropertyHandlerConfiguration(
      GenericInterceptorGetter, GenericInterceptorSetter));

  LocalContext context(nullptr, templ_global);
  i::DirectHandle<i::JSReceiver> global_proxy =
      v8::Utils::OpenDirectHandle<Object, i::JSReceiver>(context->Global());
  CHECK(IsJSGlobalProxy(*global_proxy));
  i::DirectHandle<i::JSGlobalObject> global(
      i::Cast<i::JSGlobalObject>(global_proxy->map()->prototype()),
      global_proxy->GetIsolate());
  CHECK(global->map()->has_named_interceptor());

  ExpectInt32(
      "(function() {"
      "  var f = function(obj) { "
      "    return obj.foo;"
      "  };"
      "  var obj = { __proto__: this, _str_foo: 42 };"
      "  for (var i = 0; i < 1500; i++) obj['p' + i] = 0;"
      "  /* Ensure that |obj| is in dictionary mode. */"
      "  if (%HasFastProperties(obj)) return -1;"
      "  for (var i = 0; i < 3; i++) {"
      "    f(obj);"
      "  };"
      "  return f(obj);"
      "})();",
      42);
}

namespace {
v8::Intercepted InterceptorLoadICGetter0(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
  ApiTestFuzzer::Fuzz();
  CHECK(v8_str("x")
            ->Equals(info.GetIsolate()->GetCurrentContext(), name)
            .FromJust());
  info.GetReturnValue().Set(0);
  return v8::Intercepted::kYes;
}
}  // namespace

THREADED_TEST(InterceptorReturningZero) {
  CheckInterceptorLoadIC(InterceptorLoadICGetter0, "o.x == undefined ? 1 : 0",
                         0);
}

namespace {

template <typename TKey, v8::internal::PropertyAttributes attribute>
v8::Intercepted HasICQuery(TKey name,
                           const v8::PropertyCallbackInfo<v8::Integer>& info) {
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  if (attribute != v8::internal::ABSENT) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(attribute);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

template <typename TKey>
v8::Intercepted HasICQueryToggle(
    TKey name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  static bool is_absent = false;
  is_absent = !is_absent;
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  if (!is_absent) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
    info.GetReturnValue().Set(v8::None);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

template <typename TKey, v8::internal::PropertyAttributes attribute>
v8::Intercepted HasICQuerySideEffect(
    TKey name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  if (attribute != v8::internal::ABSENT) {
    // Side effects are allowed only when the property is present or throws.
    ApiTestFuzzer::Fuzz();
  }
  v8::Isolate* isolate = CcTest::isolate();
  CHECK_EQ(isolate, info.GetIsolate());
  CompileRun("interceptor_query_side_effect()");
  if (attribute != v8::internal::ABSENT) {
    info.GetReturnValue().Set(attribute);
    return v8::Intercepted::kYes;
  }
  return v8::Intercepted::kNo;
}

int named_query_counter = 0;
v8::Intercepted NamedQueryCallback(
    Local<Name> name, const v8::PropertyCallbackInfo<v8::Integer>& info) {
  named_query_counter++;
  return v8::Intercepted::kNo;
}

}  // namespace

THREADED_TEST(InterceptorHasIC) {
  named_query_counter = 0;
  CheckInterceptorIC(nullptr, NamedQueryCallback,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  'x' in o;"
                     "}",
                     0);
  CHECK_EQ(1000, named_query_counter);
}

THREADED_TEST(InterceptorHasICQueryAbsent) {
  CheckInterceptorIC(nullptr, HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     0);
}

THREADED_TEST(InterceptorHasICQueryNone) {
  CheckInterceptorIC(nullptr, HasICQuery<Local<Name>, v8::internal::NONE>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     1000);
}

THREADED_TEST(InterceptorHasICGetter) {
  CheckInterceptorIC(InterceptorLoadICGetter, nullptr,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     1000);
}

THREADED_TEST(InterceptorHasICQueryGetter) {
  CheckInterceptorIC(InterceptorLoadICGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     0);
}

THREADED_TEST(InterceptorHasICQueryToggle) {
  CheckInterceptorIC(InterceptorLoadICGetter, HasICQueryToggle<Local<Name>>,
                     "var result = 0;"
                     "for (var i = 0; i < 1000; i++) {"
                     "  if ('x' in o) ++result;"
                     "}",
                     500);
}

THREADED_TEST(InterceptorStoreICWithSideEffectfulCallbacks1) {
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuerySideEffect<Local<Name>, v8::internal::NONE>,
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_query_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.x = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.x = i;"
                     "}",
                     19);
}

TEST(Crash_InterceptorStoreICWithSideEffectfulCallbacks1) {
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuerySideEffect<Local<Name>, v8::internal::ABSENT>,
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_query_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.x = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.x = i;"
                     "}",
                     19);
}

TEST(Crash_InterceptorStoreICWithSideEffectfulCallbacks2) {
  CheckInterceptorIC(InterceptorLoadXICGetterWithSideEffects,
                     nullptr,  // query callback is not provided
                     "let r;"
                     "let inside_side_effect = false;"
                     "let interceptor_getter_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    r.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "};"
                     "for (var i = 0; i < 20; i++) {"
                     "  r = { __proto__: o };"
                     "  r.y = i;"
                     "}",
                     19);
}

THREADED_TEST(InterceptorDefineICWithSideEffectfulCallbacks) {
  CheckInterceptorIC(EmptyInterceptorGetter, EmptyInterceptorSetter,
                     EmptyInterceptorQuery,
                     EmptyInterceptorDefinerWithSideEffect,
                     v8::PropertyHandlerFlags::kNonMasking,
                     "let inside_side_effect = false;"
                     "let interceptor_definer_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    o.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "  return true;"  // Accept the request.
                     "};"
                     "class Base {"
                     "  constructor(arg) {"
                     "    return arg;"
                     "  }"
                     "}"
                     "class ClassWithField extends Base {"
                     "  y = (() => {"
                     "    return 42;"
                     "  })();"
                     "  constructor(arg) {"
                     "    super(arg);"
                     "  }"
                     "}"
                     "new ClassWithField(o);"
                     "o.y",
                     153);
}

TEST(Crash_InterceptorDefineICWithSideEffectfulCallbacks) {
  CheckInterceptorIC(EmptyInterceptorGetter, EmptyInterceptorSetter,
                     EmptyInterceptorQuery,
                     EmptyInterceptorDefinerWithSideEffect,
                     v8::PropertyHandlerFlags::kNonMasking,
                     "let inside_side_effect = false;"
                     "let interceptor_definer_side_effect = function() {"
                     "  if (!inside_side_effect) {"
                     "    inside_side_effect = true;"
                     "    o.y = 153;"
                     "    inside_side_effect = false;"
                     "  }"
                     "  return null;"  // Decline the request.
                     "};"
                     "class Base {"
                     "  constructor(arg) {"
                     "    return arg;"
                     "  }"
                     "}"
                     "class ClassWithField extends Base {"
                     "  y = (() => {"
                     "    return 42;"
                     "  })();"
                     "  constructor(arg) {"
                     "    super(arg);"
                     "  }"
                     "}"
                     "new ClassWithField(o);"
                     "o.y",
                     42);
}

namespace {
v8::Intercepted InterceptorStoreICSetter(
    Local<Name> key, Local<Value> value,
    const v8::PropertyCallbackInfo<void>& info) {
  v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(v8_str("x")->Equals(context, key).FromJust());
  CHECK_EQ(42, value->Int32Value(context).FromJust());
  return v8::Intercepted::kYes;
}
}  // namespace

// This test should hit the store IC for the interceptor case.
THREADED_TEST(InterceptorStoreIC) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(v8::NamedPropertyHandlerConfiguration(
      InterceptorLoadICGetter, InterceptorStoreICSetter, nullptr, nullptr,
      nullptr, v8_str("data")));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  CompileRun(
      "for (var i = 0; i < 1000; i++) {"
      "  o.x = 42;"
      "}");
}


THREADED_TEST(InterceptorStoreICWithNoSetter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetHandler(
      v8::NamedPropertyHandlerConfiguration(InterceptorLoadXICGetter));
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("o"),
            templ->NewInstance(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<Value> value = CompileRun(
      "for (var i = 0; i < 1000; i++) {"
      "  o.y = 239;"
      "}"
      "42 + o.y");
  CHECK_EQ(239 + 42, value->Int32Value(context.local()).FromJust());
}

THREADED_TEST(EmptyInterceptorDoesNotShadowReadOnlyProperty) {
  // Interceptor should not shadow readonly property 'x' on the prototype, and
  // attempt to store to 'x' must throw.
  CheckInterceptorIC(EmptyInterceptorGetter,
                     HasICQuery<Local<Name>, v8::internal::ABSENT>,
                     "'use strict';"
```