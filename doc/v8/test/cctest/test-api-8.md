Response: The user wants a summary of the C++ source code file `v8/test/cctest/test-api.cc`, specifically section 9 of 18. The summary should focus on the functionality demonstrated in this section and its relation to JavaScript. I need to go through the code snippets provided, understand what each test does, and then relate it to corresponding JavaScript concepts.

Here's a breakdown of the code snippets and their potential JavaScript connections:

- **`THREADED_TEST(TryCatchSourceInfo)`**:  Tests how V8 records source code location information when an error occurs within compiled JavaScript. This is directly related to JavaScript's `try...catch` mechanism and how error messages provide context.
- **`THREADED_TEST(TryCatchSourceInfoForEOSError)`**: Specifically checks source information for a parsing error. This also relates to JavaScript's error handling.
- **`THREADED_TEST(CompilationCache)`**: Examines V8's ability to cache compiled JavaScript code. This is an optimization that's transparent to JavaScript developers but affects performance.
- **`static void FunctionNameCallback(...)` and `THREADED_TEST(CallbackFunctionName)`**:  Demonstrates how the name of a C++ callback function, when exposed to JavaScript, can be accessed from JavaScript. This relates to the `.name` property of functions in JavaScript.
- **`THREADED_TEST(DateAccess)`**: Shows how to create and access `Date` objects from the C++ API. This directly mirrors JavaScript's `Date` object.
- **`CheckIsSymbolAt`, `CheckStringArray`, `CheckProperties`, `CheckOwnProperties`, `THREADED_TEST(PropertyEnumeration)`, `THREADED_TEST(PropertyEnumeration2)`, `THREADED_TEST(GetPropertyNames)`, `THREADED_TEST(ProxyGetPropertyNames)`, `THREADED_TEST(ProxyGetPropertyNamesWithOwnKeysTrap)`**: These tests are all about how V8 handles property enumeration and retrieval, including inherited properties, own properties, and the behavior of Proxies in JavaScript. These relate to JavaScript's `for...in` loop, `Object.keys()`, `Object.getOwnPropertyNames()`, and the reflection capabilities of Proxies.
- **`THREADED_TEST(AccessChecksReenabledCorrectly)`**: Likely tests V8's access control mechanisms, though the provided snippet is more about setting up the scenario. This relates to JavaScript's property access and potentially security considerations.
- **`THREADED_TEST(DictionaryICLoadedFunction)`**: This test seems to focus on V8's internal optimization strategies for accessing properties, specifically in cases where objects behave like dictionaries. It touches on how V8 handles function calls in such scenarios.
- **`THREADED_TEST(CrossContextNew)`**:  Examines how object creation (`new` keyword) works when calling a constructor from a different JavaScript context. This relates to the concept of realms or sandboxing in JavaScript environments.
- **`TEST(ObjectClone)`**: Tests V8's API for creating shallow copies of JavaScript objects. This directly corresponds to the concept of object cloning in JavaScript, although JavaScript doesn't have a built-in shallow clone method like this (it often requires techniques like the spread syntax or `Object.assign`).
- **`class OneByteVectorResource`, `class UC16VectorResource`, `static void MorphAString(...)`, `THREADED_TEST(MorphCompositeStringTest)`, `TEST(CompileExternalTwoByteSource)`**: These sections deal with how V8 handles string representations internally (one-byte vs. two-byte) and how it optimizes string concatenation and compilation of strings from external sources. This is mostly an internal V8 concern, but it can have subtle performance implications in JavaScript.
- **`TEST(ReadOnlyPropertyInGlobalProto)`**:  Checks how V8 handles attempts to modify read-only properties in the prototype chain of the global object. This relates to JavaScript's property attributes and the behavior of `Object.defineProperty`.
- **`TEST(CreateDataProperty)`, `TEST(DefineOwnProperty)`, `TEST(DefineProperty)`**: These tests directly cover V8's implementation of JavaScript's mechanisms for adding and modifying object properties, including setting attributes like writability, enumerability, and configurability. They correspond to `Object.defineProperty` and simple property assignments in JavaScript.
- **`THREADED_TEST(GetCurrentContextWhenNotInContext)`**:  Tests the behavior of V8's API when trying to get the current context outside of any active JavaScript context. This is more about API robustness.
- **`THREADED_TEST(InitGlobalVarInProtoChain)`**: Examines how variable declarations in global scope interact with properties in the prototype chain. This relates to JavaScript's variable hoisting and scope resolution rules.
- **`THREADED_TEST(ReplaceConstantFunction)`**:  Tests a specific edge case related to object cloning and function properties, ensuring that changes to the original object don't unexpectedly affect the clone.
- **`THREADED_TEST(ScriptContextDependence)`**: Demonstrates how compiled JavaScript code can be either context-dependent or independent, relating to the concept of bound and unbound scripts in V8.
- **`#if V8_ENABLE_WEBASSEMBLY ... TEST(AsmJsWarning)`**: This test is specific to WebAssembly and how V8 handles warnings during the validation of asm.js code (a subset of JavaScript designed to be easily compilable to WebAssembly).
- **`static int error_level_message_count ... TEST(ErrorLevelWarning)`**:  Tests V8's ability to report messages with different error levels. This is related to how V8 communicates warnings and errors to developers.
- **`v8::PromiseRejectEvent reject_event ... void PromiseRejectCallback(...) ... TEST(PromiseRejectCallback)`**:  This section tests V8's handling of Promise rejections, including different rejection scenarios and the information provided in the `PromiseRejectMessage`. This directly relates to JavaScript's `Promise` API and its error handling mechanisms.

Based on this analysis, I can now formulate the summary.
这个C++源代码文件（第 9 部分，共 18 部分）主要涵盖了 V8 JavaScript 引擎 API 的以下功能测试：

**1. 错误处理和源码信息 (`TryCatchSourceInfo`, `TryCatchSourceInfoForEOSError`):**

* **功能:**  测试 V8 在执行 JavaScript 代码发生错误时，如何记录和提供源码信息，例如文件名和行号。这对于调试 JavaScript 代码至关重要。
* **JavaScript 示例:**  这与 JavaScript 的 `try...catch` 语句块以及错误对象的属性（如 `stack`，其中包含源码信息）密切相关。

```javascript
try {
  // 一些可能抛出错误的代码
  throw new Error("Something went wrong");
} catch (e) {
  console.error("捕获到错误:", e.message);
  console.error("错误堆栈:", e.stack);
}
```

**2. 编译缓存 (`CompilationCache`):**

* **功能:**  测试 V8 的编译缓存机制，即对于相同的 JavaScript 代码，V8 可以缓存编译结果，避免重复编译，提高性能。
* **JavaScript 示例:**  虽然 JavaScript 代码本身不直接控制编译缓存，但理解这个机制有助于理解 V8 的性能优化。

**3. C++ 回调函数名称 (`CallbackFunctionName`):**

* **功能:**  测试如何从 JavaScript 中获取通过 C++ API 注册的回调函数的名称。
* **JavaScript 示例:**  这与 JavaScript 函数的 `name` 属性有关。

```javascript
function myCallback() {
  // ...
}

console.log(myCallback.name); // 输出 "myCallback"
```

**4. Date 对象访问 (`DateAccess`):**

* **功能:**  测试通过 C++ API 创建和访问 JavaScript 的 `Date` 对象。
* **JavaScript 示例:**  这直接对应 JavaScript 中的 `Date` 对象及其方法。

```javascript
const now = new Date();
console.log(now.getTime()); // 获取时间戳
```

**5. 属性枚举和访问 (`PropertyEnumeration`, `PropertyEnumeration2`, `GetPropertyNames`, `ProxyGetPropertyNames`, `ProxyGetPropertyNamesWithOwnKeysTrap`):**

* **功能:**  测试 V8 如何处理 JavaScript 对象的属性枚举，包括可枚举属性、自有属性、继承属性以及 Symbol 属性。还测试了 Proxy 对象对属性枚举的影响。
* **JavaScript 示例:**  这与 JavaScript 的多种属性访问和枚举方法相关：

```javascript
const obj = { a: 1, b: 2 };
const arr = [1, 2, 3];

// for...in 循环遍历可枚举属性（包括继承的）
for (let key in obj) {
  console.log(key); // 输出 "a", "b"
}

// Object.keys() 返回对象自身可枚举属性的数组
console.log(Object.keys(obj)); // 输出 ["a", "b"]

// Object.getOwnPropertyNames() 返回对象自身所有属性的数组（包括不可枚举的）
console.log(Object.getOwnPropertyNames(obj)); // 输出 ["a", "b"]

// Object.getOwnPropertySymbols() 返回对象自身所有 Symbol 属性的数组

// Proxy 可以拦截属性访问和枚举操作
const proxy = new Proxy(obj, {
  ownKeys(target) {
    console.log("ownKeys called");
    return Reflect.ownKeys(target);
  },
});
for (let key in proxy) {
  // ...
}
```

**6. 访问检查 (`AccessChecksReenabledCorrectly`):**

* **功能:**  测试 V8 的访问检查机制，可能与对象模板和访问控制有关。
* **JavaScript 示例:**  虽然 JavaScript 本身没有直接的访问检查概念，但可以理解为 V8 内部用于实现某些安全或控制访问的机制。

**7. 字典模式的内联缓存 (`DictionaryICLoadedFunction`):**

* **功能:**  测试 V8 在处理类似字典的对象（动态添加属性的对象）时的内联缓存优化，以及如何处理在不同上下文中加载函数的情况。
* **JavaScript 示例:**  这与 V8 内部的优化策略相关，对 JavaScript 开发者来说是透明的。

**8. 跨上下文对象创建 (`CrossContextNew`):**

* **功能:**  测试在一个 JavaScript 上下文中调用另一个上下文中定义的构造函数来创建对象。
* **JavaScript 示例:**  这与 V8 的上下文隔离机制有关，在某些嵌入式场景中比较重要。

**9. 对象克隆 (`ObjectClone`):**

* **功能:**  测试通过 C++ API 克隆 JavaScript 对象的功能。
* **JavaScript 示例:**  JavaScript 中可以通过多种方式实现对象克隆，例如使用扩展运算符或 `Object.assign()`。

```javascript
const original = { a: 1, b: 2 };
const clone = { ...original }; // 使用扩展运算符进行浅拷贝
const anotherClone = Object.assign({}, original); // 使用 Object.assign() 进行浅拷贝
```

**10. 字符串处理和编译 (`MorphCompositeStringTest`, `CompileExternalTwoByteSource`):**

* **功能:**  测试 V8 如何处理不同编码的字符串 (UTF-8, UTF-16) 以及从外部资源编译 JavaScript 代码。
* **JavaScript 示例:**  JavaScript 内部使用 Unicode 编码处理字符串。

**11. 全局原型链上的只读属性 (`ReadOnlyPropertyInGlobalProto`):**

* **功能:**  测试当全局对象的原型链上存在只读属性时，尝试在全局作用域中声明同名变量的行为。
* **JavaScript 示例:**  这与 JavaScript 的作用域和属性特性有关。

```javascript
// 假设全局原型链上有只读属性 x
function test() {
  x = 5; // 如果 x 是只读的，这里会报错或赋值失败
  console.log(x);
}
```

**12. 数据属性的创建和定义 (`CreateDataProperty`, `DefineOwnProperty`, `DefineProperty`):**

* **功能:**  测试通过 C++ API 创建和定义 JavaScript 对象的数据属性，包括设置属性的特性（可写、可枚举、可配置）。
* **JavaScript 示例:**  这与 JavaScript 的 `Object.defineProperty()` 方法直接对应。

```javascript
const obj = {};
Object.defineProperty(obj, 'myProperty', {
  value: 42,
  writable: false,
  enumerable: true,
  configurable: false
});
```

**13. 获取当前上下文 (`GetCurrentContextWhenNotInContext`):**

* **功能:**  测试在没有活动 JavaScript 上下文时，尝试获取当前上下文的行为。

**14. 原型链上的变量初始化 (`InitGlobalVarInProtoChain`):**

* **功能:**  测试在全局作用域中声明变量时，如果原型链上存在同名属性，变量声明的行为。
* **JavaScript 示例:**  与 JavaScript 的变量提升和作用域链有关。

**15. 替换常量函数 (`ReplaceConstantFunction`):**

* **功能:**  测试当对象上存在常量函数属性时，克隆对象后替换原始对象的该属性是否会影响克隆对象。

**16. 脚本上下文依赖 (`ScriptContextDependence`):**

* **功能:**  测试编译后的 JavaScript 脚本是否依赖于编译时的上下文。

**17. WebAssembly 警告 (`AsmJsWarning`):**

* **功能:**  测试 V8 对 asm.js 代码的警告机制 (只有在启用了 WebAssembly 的情况下)。
* **JavaScript 示例:**  asm.js 是 JavaScript 的一个严格子集，旨在优化为 WebAssembly。

**18. 错误级别消息 (`ErrorLevelWarning`):**

* **功能:**  测试 V8 报告不同错误级别消息的功能。

**19. Promise 拒绝处理 (`PromiseRejectCallback`):**

* **功能:**  测试 V8 如何处理 Promise 的拒绝，以及提供相关的拒绝信息。
* **JavaScript 示例:**  这直接关系到 JavaScript 的 `Promise` API 及其 `.catch()` 方法或者 `unhandledrejection` 事件。

```javascript
const myPromise = new Promise((resolve, reject) => {
  reject("Promise rejected!");
});

myPromise.catch(error => {
  console.error("Promise 拒绝:", error);
});

window.addEventListener('unhandledrejection', (event) => {
  console.error("未处理的 Promise 拒绝:", event.reason, event.promise);
});
```

总而言之，这个代码片段是 V8 引擎 API 的一个测试套件的一部分，它细致地测试了引擎的各种功能，从基本的 JavaScript 语法和对象操作，到更高级的特性如 Promise、Proxy 以及引擎内部的优化机制。 通过这些测试，可以确保 V8 引擎的正确性和稳定性。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第9部分，共18部分，请归纳一下它的功能
```

### 源代码
```
= context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> source = v8_str(
      "function Foo() {\n"
      "  return Bar();\n"
      "}\n"
      "\n"
      "function Bar() {\n"
      "  return Baz();\n"
      "}\n"
      "\n"
      "function Baz() {\n"
      "  throw 'nirk';\n"
      "}\n"
      "\n"
      "Foo();\n");

  const char* resource_name;
  v8::Local<v8::Script> script;
  resource_name = "test.js";
  script = CompileWithOrigin(source, resource_name, false);
  CheckTryCatchSourceInfo(script, resource_name, 0);

  resource_name = "test1.js";
  v8::ScriptOrigin origin1(v8_str(resource_name), 0, 0);
  script =
      v8::Script::Compile(context.local(), source, &origin1).ToLocalChecked();
  CheckTryCatchSourceInfo(script, resource_name, 0);

  resource_name = "test2.js";
  v8::ScriptOrigin origin2(v8_str(resource_name), 7, 0);
  script =
      v8::Script::Compile(context.local(), source, &origin2).ToLocalChecked();
  CheckTryCatchSourceInfo(script, resource_name, 7);
}


THREADED_TEST(TryCatchSourceInfoForEOSError) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CHECK(v8::Script::Compile(context.local(), v8_str("!\n")).IsEmpty());
  CHECK(try_catch.HasCaught());
  v8::Local<v8::Message> message = try_catch.Message();
  CHECK_EQ(2, message->GetLineNumber(context.local()).FromJust());
  CHECK_EQ(0, message->GetStartColumn(context.local()).FromJust());
}


THREADED_TEST(CompilationCache) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::String> source0 = v8_str("1234");
  v8::Local<v8::String> source1 = v8_str("1234");
  v8::Local<v8::Script> script0 = CompileWithOrigin(source0, "test.js", false);
  v8::Local<v8::Script> script1 = CompileWithOrigin(source1, "test.js", false);
  v8::Local<v8::Script> script2 = v8::Script::Compile(context.local(), source0)
                                      .ToLocalChecked();  // different origin
  CHECK_EQ(1234, script0->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  CHECK_EQ(1234, script1->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
  CHECK_EQ(1234, script2->Run(context.local())
                     .ToLocalChecked()
                     ->Int32Value(context.local())
                     .FromJust());
}


static void FunctionNameCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  ApiTestFuzzer::Fuzz();
  args.GetReturnValue().Set(v8_num(42));
}


THREADED_TEST(CallbackFunctionName) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> t = ObjectTemplate::New(isolate);
  t->Set(isolate, "asdf",
         v8::FunctionTemplate::New(isolate, FunctionNameCallback));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  t->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  v8::Local<v8::Value> value = CompileRun("obj.asdf.name");
  CHECK(value->IsString());
  v8::String::Utf8Value name(isolate, value);
  CHECK_EQ(0, strcmp("asdf", *name));
}


THREADED_TEST(DateAccess) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::Local<v8::Value> date =
      v8::Date::New(context.local(), 1224744689038.0).ToLocalChecked();
  CHECK(date->IsDate());
  CHECK_EQ(1224744689038.0, date.As<v8::Date>()->ValueOf());
}

void CheckIsSymbolAt(v8::Isolate* isolate, v8::Local<v8::Array> properties,
                     unsigned index, const char* name) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Value> value =
      properties->Get(context, v8::Integer::New(isolate, index))
          .ToLocalChecked();
  CHECK(value->IsSymbol());
  v8::String::Utf8Value symbol_name(
      isolate, Local<Symbol>::Cast(value)->Description(isolate));
  if (strcmp(name, *symbol_name) != 0) {
    GRACEFUL_FATAL("properties[%u] was Symbol('%s') instead of Symbol('%s').",
                   index, name, *symbol_name);
  }
}

void CheckStringArray(v8::Isolate* isolate, v8::Local<v8::Array> properties,
                      unsigned length, const char* names[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK_EQ(length, properties->Length());
  for (unsigned i = 0; i < length; i++) {
    v8::Local<v8::Value> value =
        properties->Get(context, v8::Integer::New(isolate, i)).ToLocalChecked();
    if (names[i] == nullptr) {
      DCHECK(value->IsSymbol());
    } else {
      v8::String::Utf8Value elm(isolate, value);
      if (strcmp(names[i], *elm) != 0) {
        GRACEFUL_FATAL("properties[%u] was '%s' instead of '%s'.", i, *elm,
                       names[i]);
      }
    }
  }
}

void CheckProperties(v8::Isolate* isolate, v8::Local<v8::Value> val,
                     unsigned length, const char* names[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> obj = val.As<v8::Object>();
  v8::Local<v8::Array> props = obj->GetPropertyNames(context).ToLocalChecked();
  CheckStringArray(isolate, props, length, names);
}


void CheckOwnProperties(v8::Isolate* isolate, v8::Local<v8::Value> val,
                        unsigned elmc, const char* elmv[]) {
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::Local<v8::Object> obj = val.As<v8::Object>();
  v8::Local<v8::Array> props =
      obj->GetOwnPropertyNames(context).ToLocalChecked();
  CHECK_EQ(elmc, props->Length());
  for (unsigned i = 0; i < elmc; i++) {
    v8::String::Utf8Value elm(
        isolate,
        props->Get(context, v8::Integer::New(isolate, i)).ToLocalChecked());
    CHECK_EQ(0, strcmp(elmv[i], *elm));
  }
}


THREADED_TEST(PropertyEnumeration) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> obj = CompileRun(
      "var result = [];"
      "result[0] = {};"
      "result[1] = {a: 1, b: 2};"
      "result[2] = [1, 2, 3];"
      "var proto = {x: 1, y: 2, z: 3};"
      "var x = { __proto__: proto, w: 0, z: 1 };"
      "result[3] = x;"
      "result[4] = {21350:1};"
      "x = Object.create(null);"
      "x.a = 1; x[12345678] = 1;"
      "result[5] = x;"
      "result;");
  v8::Local<v8::Array> elms = obj.As<v8::Array>();
  CHECK_EQ(6u, elms->Length());
  int elmc0 = 0;
  const char** elmv0 = nullptr;
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);
  int elmc1 = 2;
  const char* elmv1[] = {"a", "b"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 1)).ToLocalChecked(),
      elmc1, elmv1);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 1)).ToLocalChecked(),
      elmc1, elmv1);
  int elmc2 = 3;
  const char* elmv2[] = {"0", "1", "2"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 2)).ToLocalChecked(),
      elmc2, elmv2);
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 2)).ToLocalChecked(),
      elmc2, elmv2);
  int elmc3 = 4;
  const char* elmv3[] = {"w", "z", "x", "y"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 3)).ToLocalChecked(),
      elmc3, elmv3);
  int elmc4 = 2;
  const char* elmv4[] = {"w", "z"};
  CheckOwnProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 3)).ToLocalChecked(),
      elmc4, elmv4);
  // Dictionary elements.
  int elmc5 = 1;
  const char* elmv5[] = {"21350"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 4)).ToLocalChecked(),
      elmc5, elmv5);
  // Dictionary properties.
  int elmc6 = 2;
  const char* elmv6[] = {"12345678", "a"};
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 5)).ToLocalChecked(),
      elmc6, elmv6);
}


THREADED_TEST(PropertyEnumeration2) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> obj = CompileRun(
      "var result = [];"
      "result[0] = {};"
      "result[1] = {a: 1, b: 2};"
      "result[2] = [1, 2, 3];"
      "var proto = {x: 1, y: 2, z: 3};"
      "var x = { __proto__: proto, w: 0, z: 1 };"
      "result[3] = x;"
      "result;");
  v8::Local<v8::Array> elms = obj.As<v8::Array>();
  CHECK_EQ(4u, elms->Length());
  int elmc0 = 0;
  const char** elmv0 = nullptr;
  CheckProperties(
      isolate,
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked(),
      elmc0, elmv0);

  v8::Local<v8::Value> val =
      elms->Get(context.local(), v8::Integer::New(isolate, 0)).ToLocalChecked();
  v8::Local<v8::Array> props =
      val.As<v8::Object>()->GetPropertyNames(context.local()).ToLocalChecked();
  CHECK_EQ(0u, props->Length());
  for (uint32_t i = 0; i < props->Length(); i++) {
    printf("p[%u]\n", i);
  }
}

THREADED_TEST(GetPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var result = {0: 0, 1: 1, a: 2, b: 3};"
      "result[2**32] = '4294967296';"
      "result[2**32-1] = '4294967295';"
      "result[2**32-2] = '4294967294';"
      "result[Symbol('symbol')] = true;"
      "result.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295",
  };
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(ProxyGetPropertyNames) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var target = {0: 0, 1: 1, a: 2, b: 3};"
      "target[2**32] = '4294967296';"
      "target[2**32-1] = '4294967295';"
      "target[2**32-2] = '4294967294';"
      "target[Symbol('symbol')] = true;"
      "target.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "var result = new Proxy(target, {});"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(ProxyGetPropertyNamesWithOwnKeysTrap) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Value> result = CompileRun(
      "var target = {0: 0, 1: 1, a: 2, b: 3};"
      "target[2**32] = '4294967296';"
      "target[2**32-1] = '4294967295';"
      "target[2**32-2] = '4294967294';"
      "target[Symbol('symbol')] = true;"
      "target.__proto__ = {__proto__:null, 2: 4, 3: 5, c: 6, d: 7};"
      "var result = new Proxy(target, { ownKeys: (t) => Reflect.ownKeys(t) });"
      "result;");
  v8::Local<v8::Object> object = result.As<v8::Object>();
  v8::PropertyFilter default_filter =
      static_cast<v8::PropertyFilter>(v8::ONLY_ENUMERABLE | v8::SKIP_SYMBOLS);
  v8::PropertyFilter include_symbols_filter = v8::ONLY_ENUMERABLE;

  v8::Local<v8::Array> properties =
      object->GetPropertyNames(context.local()).ToLocalChecked();
  const char* expected_properties1[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295", "2",
                                        "3", "c",          "d"};
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  CheckStringArray(isolate, properties, 11, expected_properties1);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties1_1[] = {
      "0",          "1",     "4294967294", "a", "b", "4294967296",
      "4294967295", nullptr, "2",          "3", "c", "d"};
  CheckStringArray(isolate, properties, 12, expected_properties1_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(),
                             v8::KeyCollectionMode::kIncludePrototypes,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties2[] = {"a",          "b", "4294967296",
                                        "4294967295", "c", "d"};
  CheckStringArray(isolate, properties, 6, expected_properties2);

  properties = object
                   ->GetPropertyNames(context.local(),
                                      v8::KeyCollectionMode::kIncludePrototypes,
                                      include_symbols_filter,
                                      v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties2_1[] = {
      "a", "b", "4294967296", "4294967295", nullptr, "c", "d"};
  CheckStringArray(isolate, properties, 7, expected_properties2_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kIncludeIndices)
          .ToLocalChecked();
  const char* expected_properties3[] = {"0", "1",          "4294967294", "a",
                                        "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 7, expected_properties3);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kIncludeIndices)
                   .ToLocalChecked();
  const char* expected_properties3_1[] = {
      "0", "1", "4294967294", "a", "b", "4294967296", "4294967295", nullptr};
  CheckStringArray(isolate, properties, 8, expected_properties3_1);
  CheckIsSymbolAt(isolate, properties, 7, "symbol");

  properties =
      object
          ->GetPropertyNames(context.local(), v8::KeyCollectionMode::kOwnOnly,
                             default_filter, v8::IndexFilter::kSkipIndices)
          .ToLocalChecked();
  const char* expected_properties4[] = {"a", "b", "4294967296", "4294967295"};
  CheckStringArray(isolate, properties, 4, expected_properties4);

  properties = object
                   ->GetPropertyNames(
                       context.local(), v8::KeyCollectionMode::kOwnOnly,
                       include_symbols_filter, v8::IndexFilter::kSkipIndices)
                   .ToLocalChecked();
  const char* expected_properties4_1[] = {"a", "b", "4294967296", "4294967295",
                                          nullptr};
  CheckStringArray(isolate, properties, 5, expected_properties4_1);
  CheckIsSymbolAt(isolate, properties, 4, "symbol");
}

THREADED_TEST(AccessChecksReenabledCorrectly) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  templ->Set(isolate, "a", v8_str("a"));
  // Add more than 8 (see kMaxFastProperties) properties
  // so that the constructor will force copying map.
  // Cannot sprintf, gcc complains unsafety.
  char buf[4];
  for (char i = '0'; i <= '9' ; i++) {
    buf[0] = i;
    for (char j = '0'; j <= '9'; j++) {
      buf[1] = j;
      for (char k = '0'; k <= '9'; k++) {
        buf[2] = k;
        buf[3] = 0;
        templ->Set(v8_str(buf), v8::Number::New(isolate, k));
      }
    }
  }

  Local<v8::Object> instance_1 =
      templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj_1"), instance_1)
            .FromJust());

  Local<Value> value_1 = CompileRun("obj_1.a");
  CHECK(value_1.IsEmpty());

  Local<v8::Object> instance_2 =
      templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj_2"), instance_2)
            .FromJust());

  Local<Value> value_2 = CompileRun("obj_2.a");
  CHECK(value_2.IsEmpty());
}


// This tests that we do not allow dictionary load/call inline caches
// to use functions that have not yet been compiled.  The potential
// problem of loading a function that has not yet been compiled can
// arise because we share code between contexts via the compilation
// cache.
THREADED_TEST(DictionaryICLoadedFunction) {
  v8::HandleScope scope(CcTest::isolate());
  // Test LoadIC.
  for (int i = 0; i < 2; i++) {
    LocalContext context;
    CHECK(context->Global()
              ->Set(context.local(), v8_str("tmp"), v8::True(CcTest::isolate()))
              .FromJust());
    context->Global()->Delete(context.local(), v8_str("tmp")).FromJust();
    CompileRun("for (var j = 0; j < 10; j++) new RegExp('');");
  }
  // Test CallIC.
  for (int i = 0; i < 2; i++) {
    LocalContext context;
    CHECK(context->Global()
              ->Set(context.local(), v8_str("tmp"), v8::True(CcTest::isolate()))
              .FromJust());
    context->Global()->Delete(context.local(), v8_str("tmp")).FromJust();
    CompileRun("for (var j = 0; j < 10; j++) RegExp('')");
  }
}


// Test that cross-context new calls use the context of the callee to
// create the new JavaScript object.
THREADED_TEST(CrossContextNew) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<Context> context0 = Context::New(isolate);
  v8::Local<Context> context1 = Context::New(isolate);

  // Allow cross-domain access.
  Local<String> token = v8_str("<security token>");
  context0->SetSecurityToken(token);
  context1->SetSecurityToken(token);

  // Set an 'x' property on the Object prototype and define a
  // constructor function in context0.
  context0->Enter();
  CompileRun("Object.prototype.x = 42; function C() {};");
  context0->Exit();

  // Call the constructor function from context0 and check that the
  // result has the 'x' property.
  context1->Enter();
  CHECK(context1->Global()
            ->Set(context1, v8_str("other"), context0->Global())
            .FromJust());
  Local<Value> value = CompileRun("var instance = new other.C(); instance.x");
  CHECK(value->IsInt32());
  CHECK_EQ(42, value->Int32Value(context1).FromJust());
  context1->Exit();
}


// Verify that we can clone an object
TEST(ObjectClone) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  const char* sample =
    "var rv = {};"      \
    "rv.alpha = 'hello';" \
    "rv.beta = 123;"     \
    "rv;";

  // Create an object, verify basics.
  Local<Value> val = CompileRun(sample);
  CHECK(val->IsObject());
  Local<v8::Object> obj = val.As<v8::Object>();
  obj->Set(env.local(), v8_str("gamma"), v8_str("cloneme")).FromJust();

  CHECK(v8_str("hello")
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("alpha")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("cloneme")
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("gamma")).ToLocalChecked())
            .FromJust());

  // Clone it.
  Local<v8::Object> clone = obj->Clone();
  CHECK(v8_str("hello")
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("alpha")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8_str("cloneme")
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("gamma")).ToLocalChecked())
            .FromJust());

  // Set a property on the clone, verify each object.
  CHECK(clone->Set(env.local(), v8_str("beta"), v8::Integer::New(isolate, 456))
            .FromJust());
  CHECK(v8::Integer::New(isolate, 123)
            ->Equals(env.local(),
                     obj->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
  CHECK(v8::Integer::New(isolate, 456)
            ->Equals(env.local(),
                     clone->Get(env.local(), v8_str("beta")).ToLocalChecked())
            .FromJust());
}


class OneByteVectorResource : public v8::String::ExternalOneByteStringResource {
 public:
  explicit OneByteVectorResource(v8::base::Vector<const char> vector)
      : data_(vector) {}
  ~OneByteVectorResource() override = default;
  size_t length() const override { return data_.length(); }
  const char* data() const override { return data_.begin(); }
  void Dispose() override {}

 private:
  v8::base::Vector<const char> data_;
};


class UC16VectorResource : public v8::String::ExternalStringResource {
 public:
  explicit UC16VectorResource(v8::base::Vector<const v8::base::uc16> vector)
      : data_(vector) {}
  ~UC16VectorResource() override = default;
  size_t length() const override { return data_.length(); }
  const v8::base::uc16* data() const override { return data_.begin(); }
  void Dispose() override {}

 private:
  v8::base::Vector<const v8::base::uc16> data_;
};

static void MorphAString(i::Tagged<i::String> string,
                         OneByteVectorResource* one_byte_resource,
                         UC16VectorResource* uc16_resource) {
  i::Isolate* isolate = CcTest::i_isolate();
  CHECK(i::StringShape(string).IsExternal());
  i::ReadOnlyRoots roots(CcTest::heap());
  if (string->IsOneByteRepresentation()) {
    // Check old map is not internalized or long.
    CHECK(string->map() == roots.external_one_byte_string_map());
    // Morph external string to be TwoByte string.
    string->set_map(isolate, roots.external_two_byte_string_map());
    i::Tagged<i::ExternalTwoByteString> morphed =
        i::Cast<i::ExternalTwoByteString>(string);
    CcTest::heap()->UpdateExternalString(morphed, string->length(), 0);
    morphed->SetResource(isolate, uc16_resource);
  } else {
    // Check old map is not internalized or long.
    CHECK(string->map() == roots.external_two_byte_string_map());
    // Morph external string to be one-byte string.
    string->set_map(isolate, roots.external_one_byte_string_map());
    i::Tagged<i::ExternalOneByteString> morphed =
        i::Cast<i::ExternalOneByteString>(string);
    CcTest::heap()->UpdateExternalString(morphed, string->length(), 0);
    morphed->SetResource(isolate, one_byte_resource);
  }
}

// Test that we can still flatten a string if the components it is built up
// from have been turned into 16 bit strings in the mean time.
THREADED_TEST(MorphCompositeStringTest) {
  char utf_buffer[129];
  const char* c_string = "Now is the time for all good men"
                         " to come to the aid of the party";
  uint16_t* two_byte_string = AsciiToTwoByteString(c_string);
  {
    LocalContext env;
    i::Factory* factory = CcTest::i_isolate()->factory();
    v8::Isolate* isolate = env->GetIsolate();
    i::Isolate* i_isolate = CcTest::i_isolate();
    v8::HandleScope scope(isolate);
    OneByteVectorResource one_byte_resource(
        v8::base::Vector<const char>(c_string, strlen(c_string)));
    UC16VectorResource uc16_resource(
        v8::base::Vector<const uint16_t>(two_byte_string, strlen(c_string)));

    Local<String> lhs(v8::Utils::ToLocal(
        factory->NewExternalStringFromOneByte(&one_byte_resource)
            .ToHandleChecked()));
    Local<String> rhs(v8::Utils::ToLocal(
        factory->NewExternalStringFromOneByte(&one_byte_resource)
            .ToHandleChecked()));

    CHECK(env->Global()->Set(env.local(), v8_str("lhs"), lhs).FromJust());
    CHECK(env->Global()->Set(env.local(), v8_str("rhs"), rhs).FromJust());

    CompileRun(
        "var cons = lhs + rhs;"
        "var slice = lhs.substring(1, lhs.length - 1);"
        "var slice_on_cons = (lhs + rhs).substring(1, lhs.length *2 - 1);");

    CHECK(lhs->IsOneByte());
    CHECK(rhs->IsOneByte());

    i::DirectHandle<i::String> ilhs = v8::Utils::OpenDirectHandle(*lhs);
    i::DirectHandle<i::String> irhs = v8::Utils::OpenDirectHandle(*rhs);
    MorphAString(*ilhs, &one_byte_resource, &uc16_resource);
    MorphAString(*irhs, &one_byte_resource, &uc16_resource);

    // This should UTF-8 without flattening, since everything is ASCII.
    Local<String> cons =
        v8_compile("cons")->Run(env.local()).ToLocalChecked().As<String>();
    CHECK_EQ(128, cons->Utf8LengthV2(isolate));
    CHECK_EQ(129, cons->WriteUtf8V2(isolate, utf_buffer, sizeof(utf_buffer),
                                    String::WriteFlags::kNullTerminate));
    CHECK_EQ(0, strcmp(
        utf_buffer,
        "Now is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the party"));

    // Now do some stuff to make sure the strings are flattened, etc.
    CompileRun(
        "/[^a-z]/.test(cons);"
        "/[^a-z]/.test(slice);"
        "/[^a-z]/.test(slice_on_cons);");
    const char* expected_cons =
        "Now is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the party";
    const char* expected_slice =
        "ow is the time for all good men to come to the aid of the part";
    const char* expected_slice_on_cons =
        "ow is the time for all good men to come to the aid of the party"
        "Now is the time for all good men to come to the aid of the part";
    CHECK(v8_str(expected_cons)
              ->Equals(env.local(), env->Global()
                                        ->Get(env.local(), v8_str("cons"))
                                        .ToLocalChecked())
              .FromJust());
    CHECK(v8_str(expected_slice)
              ->Equals(env.local(), env->Global()
                                        ->Get(env.local(), v8_str("slice"))
                                        .ToLocalChecked())
              .FromJust());
    CHECK(v8_str(expected_slice_on_cons)
              ->Equals(env.local(),
                       env->Global()
                           ->Get(env.local(), v8_str("slice_on_cons"))
                           .ToLocalChecked())
              .FromJust());

    // This avoids the GC from trying to free a stack allocated resource.
    if (IsExternalOneByteString(*ilhs))
      i::Cast<i::ExternalOneByteString>(*ilhs)->SetResource(i_isolate, nullptr);
    else
      i::Cast<i::ExternalTwoByteString>(*ilhs)->SetResource(i_isolate, nullptr);
    if (IsExternalOneByteString(*irhs))
      i::Cast<i::ExternalOneByteString>(*irhs)->SetResource(i_isolate, nullptr);
    else
      i::Cast<i::ExternalTwoByteString>(*irhs)->SetResource(i_isolate, nullptr);
  }
  i::DeleteArray(two_byte_string);
}


TEST(CompileExternalTwoByteSource) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // This is a very short list of sources, which currently is to check for a
  // regression caused by r2703.
  const char* one_byte_sources[] = {
      "0.5",
      "-0.5",   // This mainly testes PushBack in the Scanner.
      "--0.5",  // This mainly testes PushBack in the Scanner.
      nullptr};

  // Compile the sources as external two byte strings.
  for (int i = 0; one_byte_sources[i] != nullptr; i++) {
    uint16_t* two_byte_string = AsciiToTwoByteString(one_byte_sources[i]);
    TestResource* uc16_resource = new TestResource(two_byte_string);
    v8::Local<v8::String> source =
        v8::String::NewExternalTwoByte(context->GetIsolate(), uc16_resource)
            .ToLocalChecked();
    v8::Script::Compile(context.local(), source).FromMaybe(Local<Script>());
  }
}

// Test that we cannot set a property on the global object if there
// is a read-only property in the prototype chain.
TEST(ReadOnlyPropertyInGlobalProto) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  LocalContext context(nullptr, templ);
  v8::Local<v8::Object> global = context->Global();
  v8::Local<v8::Object> global_proto = v8::Local<v8::Object>::Cast(
      global->Get(context.local(), v8_str("__proto__")).ToLocalChecked());
  global_proto->DefineOwnProperty(context.local(), v8_str("x"),
                                  v8::Integer::New(isolate, 0), v8::ReadOnly)
      .FromJust();
  global_proto->DefineOwnProperty(context.local(), v8_str("y"),
                                  v8::Integer::New(isolate, 0), v8::ReadOnly)
      .FromJust();
  // Check without 'eval' or 'with'.
  v8::Local<v8::Value> res =
      CompileRun("function f() { x = 42; return x; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
  // Check with 'eval'.
  res = CompileRun("function f() { eval('1'); y = 43; return y; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
  // Check with 'with'.
  res = CompileRun("function f() { with (this) { y = 44 }; return y; }; f()");
  CHECK(v8::Integer::New(isolate, 0)->Equals(context.local(), res).FromJust());
}


TEST(CreateDataProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'foo', {value: 23});"
      "Object.defineProperty(a, 'bar', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());
  {
    // Can't change a non-configurable properties.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->CreateDataProperty(env.local(), v8_str("foo"),
                                   v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK(obj->CreateDataProperty(env.local(), v8_str("bar"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("bar")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a regular property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->CreateDataProperty(env.local(), v8_str("blub"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("blub")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->CreateDataProperty(env.local(), v8_str("1"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Special cases for arrays.
    v8::TryCatch try_catch(isolate);
    CHECK(!arr->CreateDataProperty(env.local(), v8_str("length"),
                                   v8::Integer::New(isolate, 1)).FromJust());
    CHECK(!try_catch.HasCaught());
  }
  {
    // Special cases for arrays: index exceeds the array's length
    v8::TryCatch try_catch(isolate);
    CHECK(arr->CreateDataProperty(env.local(), 1, v8::Integer::New(isolate, 23))
              .FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(2U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->CreateDataProperty(env.local(), 0, v8::Integer::New(isolate, 42))
              .FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  CompileRun("Object.freeze(a);");
  {
    // Can't change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->CreateDataProperty(env.local(), v8_str("baz"),
                                   v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->CreateDataProperty(env.local(), v8_str("foo"),
                                             v8::Integer::New(isolate, 42))
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}


TEST(DefineOwnProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'foo', {value: 23});"
      "Object.defineProperty(a, 'bar', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());
  {
    // Can't change a non-configurable properties.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineOwnProperty(env.local(), v8_str("foo"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("bar"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("bar")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a regular property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("blub"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("blub")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("1"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Special cases for arrays.
    v8::TryCatch try_catch(isolate);
    CHECK(!arr->DefineOwnProperty(env.local(), v8_str("length"),
                                  v8::Integer::New(isolate, 1)).FromJust());
    CHECK(!try_catch.HasCaught());
  }
  {
    // Special cases for arrays: index exceeds the array's length
    v8::TryCatch try_catch(isolate);
    CHECK(arr->DefineOwnProperty(env.local(), v8_str("1"),
                                 v8::Integer::New(isolate, 23)).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(2U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->DefineOwnProperty(env.local(), v8_str("0"),
                                 v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set a non-writable property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineOwnProperty(env.local(), v8_str("lala"),
                                 v8::Integer::New(isolate, 42),
                                 v8::ReadOnly).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val =
        obj->Get(env.local(), v8_str("lala")).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK_EQ(v8::ReadOnly, obj->GetPropertyAttributes(
                                    env.local(), v8_str("lala")).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  CompileRun("Object.freeze(a);");
  {
    // Can't change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineOwnProperty(env.local(), v8_str("baz"),
                                  v8::Integer::New(isolate, 42)).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->DefineOwnProperty(env.local(), v8_str("foo"),
                                            v8::Integer::New(isolate, 42))
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}

TEST(DefineProperty) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope handle_scope(isolate);

  v8::Local<v8::Name> p;

  CompileRun(
      "var a = {};"
      "var b = [];"
      "Object.defineProperty(a, 'v1', {value: 23});"
      "Object.defineProperty(a, 'v2', {value: 23, configurable: true});");

  v8::Local<v8::Object> obj = v8::Local<v8::Object>::Cast(
      env->Global()->Get(env.local(), v8_str("a")).ToLocalChecked());
  v8::Local<v8::Array> arr = v8::Local<v8::Array>::Cast(
      env->Global()->Get(env.local(), v8_str("b")).ToLocalChecked());

  v8::PropertyDescriptor desc(v8_num(42));
  {
    // Use a data descriptor.

    // Cannot change a non-configurable property.
    p = v8_str("v1");
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(23.0, val->NumberValue(env.local()).FromJust());

    // Change a configurable property.
    p = v8_str("v2");
    obj->DefineProperty(env.local(), p, desc).FromJust();
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());

    // Check that missing writable has default value false.
    p = v8_str("v12");
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    v8::PropertyDescriptor desc2(v8_num(43));
    CHECK(!obj->DefineProperty(env.local(), p, desc2).FromJust());
    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Set a regular property.
    p = v8_str("v3");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Set an indexed property.
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), v8_str("1"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), 1).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // No special case when changing array length.
    v8::TryCatch try_catch(isolate);
    // Use a writable descriptor, otherwise the next test, that changes
    // the array length will fail.
    v8::PropertyDescriptor desc_writable(v8_num(42), true);
    CHECK(arr->DefineProperty(env.local(), v8_str("length"), desc_writable)
              .FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Special cases for arrays: index exceeds the array's length.
    v8::TryCatch try_catch(isolate);
    CHECK(arr->DefineProperty(env.local(), v8_str("100"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    CHECK_EQ(101U, arr->Length());
    v8::Local<v8::Value> val = arr->Get(env.local(), 100).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());

    // Set an existing entry.
    CHECK(arr->DefineProperty(env.local(), v8_str("0"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
    val = arr->Get(env.local(), 0).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
  }

  {
    // Use a generic descriptor.
    v8::PropertyDescriptor desc_generic;

    p = v8_str("v4");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_generic).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());

    obj->Set(env.local(), p, v8_num(1)).FromJust();
    CHECK(!try_catch.HasCaught());

    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use a data descriptor with undefined value.
    v8::PropertyDescriptor desc_empty(v8::Undefined(isolate));

    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use a descriptor with attribute == v8::ReadOnly.
    v8::PropertyDescriptor desc_read_only(v8_num(42), false);
    desc_read_only.set_enumerable(true);
    desc_read_only.set_configurable(true);

    p = v8_str("v5");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_read_only).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(42.0, val->NumberValue(env.local()).FromJust());
    CHECK_EQ(v8::ReadOnly,
             obj->GetPropertyAttributes(env.local(), p).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use an accessor descriptor with empty handles.
    v8::PropertyDescriptor desc_empty(v8::Undefined(isolate),
                                      v8::Undefined(isolate));

    p = v8_str("v6");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());
    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsUndefined());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Use an accessor descriptor.
    CompileRun(
        "var set = function(x) {this.val = 2*x;};"
        "var get = function() {return this.val || 0;};");

    v8::Local<v8::Function> get = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("get")).ToLocalChecked());
    v8::Local<v8::Function> set = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("set")).ToLocalChecked());
    v8::PropertyDescriptor desc_getter_setter(get, set);

    p = v8_str("v7");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc_getter_setter).FromJust());
    CHECK(!try_catch.HasCaught());

    v8::Local<v8::Value> val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(0.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());

    obj->Set(env.local(), p, v8_num(7)).FromJust();
    CHECK(!try_catch.HasCaught());

    val = obj->Get(env.local(), p).ToLocalChecked();
    CHECK(val->IsNumber());
    CHECK_EQ(14.0, val->NumberValue(env.local()).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Redefine an existing property.

    // desc = {value: 42, enumerable: true}
    v8::PropertyDescriptor desc42(v8_num(42));
    desc42.set_enumerable(true);

    p = v8_str("v8");
    v8::TryCatch try_catch(isolate);
    CHECK(obj->DefineProperty(env.local(), p, desc42).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {enumerable: true}
    v8::PropertyDescriptor desc_true((v8::Local<v8::Value>()));
    desc_true.set_enumerable(true);

    // Successful redefinition because all present attributes have the same
    // value as the current descriptor.
    CHECK(obj->DefineProperty(env.local(), p, desc_true).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {}
    v8::PropertyDescriptor desc_empty;
    // Successful redefinition because no attributes are overwritten in the
    // current descriptor.
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {enumerable: false}
    v8::PropertyDescriptor desc_false((v8::Local<v8::Value>()));
    desc_false.set_enumerable(false);
    // Not successful because we cannot define a different value for enumerable.
    CHECK(!obj->DefineProperty(env.local(), p, desc_false).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  {
    // Redefine a property that has a getter.
    CompileRun("var get = function() {};");
    v8::Local<v8::Function> get = v8::Local<v8::Function>::Cast(
        env->Global()->Get(env.local(), v8_str("get")).ToLocalChecked());

    // desc = {get: function() {}}
    v8::PropertyDescriptor desc_getter(get, v8::Local<v8::Function>());
    v8::TryCatch try_catch(isolate);

    p = v8_str("v9");
    CHECK(obj->DefineProperty(env.local(), p, desc_getter).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc_empty = {}
    // Successful because we are not redefining the current getter.
    v8::PropertyDescriptor desc_empty;
    CHECK(obj->DefineProperty(env.local(), p, desc_empty).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {get: function() {}}
    // Successful because we redefine the getter with its current value.
    CHECK(obj->DefineProperty(env.local(), p, desc_getter).FromJust());
    CHECK(!try_catch.HasCaught());

    // desc = {get: undefined}
    v8::PropertyDescriptor desc_undefined(v8::Undefined(isolate),
                                          v8::Local<v8::Function>());
    // Not successful because we cannot redefine with the current value of get
    // with undefined.
    CHECK(!obj->DefineProperty(env.local(), p, desc_undefined).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  CompileRun("Object.freeze(a);");
  {
    // We cannot change non-extensible objects.
    v8::TryCatch try_catch(isolate);
    CHECK(!obj->DefineProperty(env.local(), v8_str("v10"), desc).FromJust());
    CHECK(!try_catch.HasCaught());
  }

  v8::Local<v8::ObjectTemplate> templ = v8::ObjectTemplate::New(isolate);
  templ->SetAccessCheckCallback(AccessAlwaysBlocked);
  v8::Local<v8::Object> access_checked =
      templ->NewInstance(env.local()).ToLocalChecked();
  {
    v8::TryCatch try_catch(isolate);
    CHECK(access_checked->DefineProperty(env.local(), v8_str("v11"), desc)
              .IsNothing());
    CHECK(try_catch.HasCaught());
  }
}

THREADED_TEST(GetCurrentContextWhenNotInContext) {
  i::Isolate* isolate = CcTest::i_isolate();
  CHECK_NOT_NULL(isolate);
  CHECK(isolate->context().is_null());
  v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);
  v8::HandleScope scope(v8_isolate);
  // The following should not crash, but return an empty handle.
  v8::Local<v8::Context> current = v8_isolate->GetCurrentContext();
  CHECK(current.IsEmpty());
}


// Check that a variable declaration with no explicit initialization
// value does shadow an existing property in the prototype chain.
THREADED_TEST(InitGlobalVarInProtoChain) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  // Introduce a variable in the prototype chain.
  CompileRun("__proto__.x = 42");
  v8::Local<v8::Value> result = CompileRun("var x = 43; x");
  CHECK(!result->IsUndefined());
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());
}


// Regression test for issue 398.
// If a function is added to an object, creating a constant function
// field, and the result is cloned, replacing the constant function on the
// original should not affect the clone.
// See http://code.google.com/p/v8/issues/detail?id=398
THREADED_TEST(ReplaceConstantFunction) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  v8::Local<v8::FunctionTemplate> func_templ =
      v8::FunctionTemplate::New(isolate);
  v8::Local<v8::String> foo_string = v8_str("foo");
  obj->Set(context.local(), foo_string,
           func_templ->GetFunction(context.local()).ToLocalChecked())
      .FromJust();
  v8::Local<v8::Object> obj_clone = obj->Clone();
  obj_clone->Set(context.local(), foo_string, v8_str("Hello")).FromJust();
  CHECK(!obj->Get(context.local(), foo_string).ToLocalChecked()->IsUndefined());
}

THREADED_TEST(ScriptContextDependence) {
  LocalContext c1;
  v8::HandleScope scope(c1->GetIsolate());
  const char source[] = "foo";
  v8::Local<v8::Script> dep = v8_compile(source);
  v8::ScriptCompiler::Source script_source(
      v8::String::NewFromUtf8Literal(c1->GetIsolate(), source));
  v8::Local<v8::UnboundScript> indep =
      v8::ScriptCompiler::CompileUnboundScript(c1->GetIsolate(), &script_source)
          .ToLocalChecked();
  c1->Global()
      ->Set(c1.local(), v8::String::NewFromUtf8Literal(c1->GetIsolate(), "foo"),
            v8::Integer::New(c1->GetIsolate(), 100))
      .FromJust();
  CHECK_EQ(
      dep->Run(c1.local()).ToLocalChecked()->Int32Value(c1.local()).FromJust(),
      100);
  CHECK_EQ(indep->BindToCurrentContext()
               ->Run(c1.local())
               .ToLocalChecked()
               ->Int32Value(c1.local())
               .FromJust(),
           100);
  LocalContext c2;
  c2->Global()
      ->Set(c2.local(), v8::String::NewFromUtf8Literal(c2->GetIsolate(), "foo"),
            v8::Integer::New(c2->GetIsolate(), 101))
      .FromJust();
  CHECK_EQ(
      dep->Run(c2.local()).ToLocalChecked()->Int32Value(c2.local()).FromJust(),
      100);
  CHECK_EQ(indep->BindToCurrentContext()
               ->Run(c2.local())
               .ToLocalChecked()
               ->Int32Value(c2.local())
               .FromJust(),
           101);
}

#if V8_ENABLE_WEBASSEMBLY
static int asm_warning_triggered = 0;

static void AsmJsWarningListener(v8::Local<v8::Message> message,
                                 v8::Local<Value>) {
  CHECK_EQ(v8::Isolate::kMessageWarning, message->ErrorLevel());
  asm_warning_triggered = 1;
}

TEST(AsmJsWarning) {
  i::v8_flags.validate_asm = true;
  if (i::v8_flags.suppress_asm_messages) return;

  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  asm_warning_triggered = 0;
  isolate->AddMessageListenerWithErrorLevel(AsmJsWarningListener,
                                            v8::Isolate::kMessageAll);
  CompileRun(
      "function module() {\n"
      "  'use asm';\n"
      "  var x = 'hi';\n"
      "  return {};\n"
      "}\n"
      "module();");
  int kExpectedWarnings = 1;
  CHECK_EQ(kExpectedWarnings, asm_warning_triggered);
  isolate->RemoveMessageListeners(AsmJsWarningListener);
}
#endif  // V8_ENABLE_WEBASSEMBLY

static int error_level_message_count = 0;
static int expected_error_level = 0;

static void ErrorLevelListener(v8::Local<v8::Message> message,
                               v8::Local<Value>) {
  DCHECK_EQ(expected_error_level, message->ErrorLevel());
  ++error_level_message_count;
}

TEST(ErrorLevelWarning) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  v8::HandleScope scope(isolate);

  const char* source = "fake = 1;";
  v8::Local<v8::Script> lscript = CompileWithOrigin(source, "test", false);
  i::DirectHandle<i::SharedFunctionInfo> obj = i::Cast<i::SharedFunctionInfo>(
      v8::Utils::OpenDirectHandle(*lscript->GetUnboundScript()));
  CHECK(IsScript(obj->script()));
  i::Handle<i::Script> script(i::Cast<i::Script>(obj->script()), i_isolate);

  int levels[] = {
      v8::Isolate::kMessageLog, v8::Isolate::kMessageInfo,
      v8::Isolate::kMessageDebug, v8::Isolate::kMessageWarning,
  };
  error_level_message_count = 0;
  isolate->AddMessageListenerWithErrorLevel(ErrorLevelListener,
                                            v8::Isolate::kMessageAll);
  for (size_t i = 0; i < arraysize(levels); i++) {
    i::MessageLocation location(script, 0, 0);
    i::DirectHandle<i::String> msg(i_isolate->factory()->InternalizeString(
        v8::base::StaticCharVector("test")));
    i::DirectHandle<i::JSMessageObject> message =
        i::MessageHandler::MakeMessageObject(
            i_isolate, i::MessageTemplate::kAsmJsInvalid, &location, msg);
    message->set_error_level(levels[i]);
    expected_error_level = levels[i];
    i::MessageHandler::ReportMessage(i_isolate, &location, message);
  }
  isolate->RemoveMessageListeners(ErrorLevelListener);
  DCHECK_EQ(arraysize(levels), error_level_message_count);
}

v8::PromiseRejectEvent reject_event = v8::kPromiseRejectWithNoHandler;
int promise_reject_counter = 0;
int promise_revoke_counter = 0;
int promise_reject_after_resolved_counter = 0;
int promise_resolve_after_resolved_counter = 0;
int promise_reject_msg_line_number = -1;
int promise_reject_msg_column_number = -1;
int promise_reject_line_number = -1;
int promise_reject_column_number = -1;
int promise_reject_frame_count = -1;
bool promise_reject_is_shared_cross_origin = false;

void PromiseRejectCallback(v8::PromiseRejectMessage reject_message) {
  v8::Local<v8::Object> global = CcTest::global();
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_NE(v8::Promise::PromiseState::kPending,
           reject_message.GetPromise()->State());
  switch (reject_message.GetEvent()) {
    case v8::kPromiseRejectWithNoHandler: {
      promise_reject_counter++;
      global->Set(context, v8_str("rejected"), reject_message.GetPromise())
          .FromJust();
      global->Set(context, v8_str("value"), reject_message.GetValue())
          .FromJust();
      v8::Local<v8::Message> message = v8::Exception::CreateMessage(
          CcTest::isolate(), reject_message.GetValue());
      v8::Local<v8::StackTrace> stack_trace = message->GetStackTrace();

      promise_reject_msg_line_number =
          message->GetLineNumber(context).FromJust();
      promise_reject_msg_column_number =
          message->GetStartColumn(context).FromJust() + 1;
      promise_reject_is_shared_cross_origin =
          message->IsSharedCrossOrigin();

      if (!stack_trace.IsEmpty()) {
        promise_reject_frame_count = stack_trace->GetFrameCount();
        if (promise_reject_frame_count > 0) {
          CHECK(stack_trace->GetFrame(CcTest::isolate(), 0)
                    ->GetScriptName()
                    ->Equals(context, v8_str("pro"))
                    .FromJust());
          promise_reject_line_number =
              stack_trace->GetFrame(CcTest::isolate(), 0)->GetLineNumber();
          promise_reject_column_number =
              sta
```