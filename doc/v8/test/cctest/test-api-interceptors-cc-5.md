Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze a V8 test file (`test-api-interceptors.cc`) and explain its functionality, relating it to JavaScript concepts where possible. The request also includes specific instructions about handling `.tq` files, providing JavaScript examples, code logic, common errors, and summarizing the functionality of this specific part (part 6 of 8).

2. **Initial Scan and File Type Identification:**  I first scanned the file name and the provided content. The file name `test-api-interceptors.cc` clearly indicates it's a C++ file, specifically a test file for V8's API interceptors. The content confirms this with the presence of C++ code, V8 API calls (like `v8::Isolate`, `v8::ObjectTemplate`, etc.), and test-related macros (`THREADED_TEST`). The request mentions checking for `.tq` extension, but this file has `.cc`, so it's not a Torque file.

3. **Identify Key Concepts:**  The file name itself points to the core concept: "API interceptors". I know from my V8 knowledge that interceptors are a mechanism in V8 that allows C++ code to intercept property access (get, set, delete, enumeration) on JavaScript objects. This is the central theme I'll focus on.

4. **Analyze Test Cases (THREADED_TEST):** I then examined each `THREADED_TEST` block. Each block represents a specific scenario being tested related to interceptors. I looked for patterns and the purpose of each test. For example:

    * Tests like `InterceptorCallICConstantFunctionNotNeeded` and `InterceptorCallICConstantFunctionNotNeededWrapped` deal with how interceptors interact with cached function calls (Inline Caches - ICs). They check if the interceptor's logic is executed even when V8 might have optimized and cached a direct function call.
    * Tests like `InterceptorCallICInvalidatedConstantFunction` and `InterceptorCallICInvalidatedConstantFunctionViaGlobal` explore scenarios where cached function calls become invalid due to changes in the prototype chain or global object.
    * Tests with names containing "KeyedCallIC" focus on interceptors in the context of dynamic property access (using bracket notation like `o[method]()`). They test how V8 handles interceptors when the property name being accessed changes.
    * Tests involving "ReferenceErrors" and "Exceptions" investigate how interceptors behave when they intentionally cause errors or throw exceptions.
    * Tests with "NullNamedInterceptor" and "NullIndexedInterceptor" verify the behavior when null interceptor handlers are provided.
    * Tests with "OptimizedInterceptorSetter", "OptimizedInterceptorGetter", "OptimizedInterceptorFieldRead", and "OptimizedInterceptorFieldWrite" are explicitly testing how interceptors work with V8's optimizing compiler (Turbofan).
    * Tests with "Regress" in the name usually indicate regression tests, designed to prevent previously fixed bugs from reappearing.

5. **Relate to JavaScript:**  For each test case, I thought about the corresponding JavaScript behavior. Interceptors are inherently linked to JavaScript object property access. I considered how these C++ tests would translate to JavaScript scenarios. For instance:

    * Setting a handler using `templ->SetHandler()` is analogous to defining custom property behavior in JavaScript (though not directly expressible in standard JS). It's more about how the V8 engine itself handles property lookups.
    * The concept of prototype chains and how changes there affect property access is fundamental to JavaScript.
    * Dynamic property access using bracket notation is a common JavaScript feature.
    * Exceptions and `try...catch` blocks are standard JavaScript constructs.
    * The interaction with the optimizing compiler relates to JavaScript performance and how V8 optimizes frequently executed code.

6. **Provide JavaScript Examples (Where Applicable):**  I focused on providing JavaScript examples that illustrate the *effects* of the interceptor behavior being tested, even though the interceptor itself is C++ code. The examples show how property access might behave differently due to the presence of an interceptor.

7. **Code Logic and Assumptions:** For tests with more involved logic (like loops and conditional changes), I tried to infer the expected input and output based on the code. For example, in tests that change the prototype chain mid-execution, the initial property access might behave differently than later accesses.

8. **Common Programming Errors:** I considered common JavaScript errors that might be related to interceptors, such as unexpected behavior when relying on specific property access patterns, especially when external C++ code is involved via interceptors.

9. **Summarize Functionality (Part 6):**  Based on the analysis of the individual test cases within this specific part of the file, I synthesized a summary that captures the main themes and functionalities covered. Since this is part 6, I focused on the aspects present in *this* segment.

10. **Iterative Refinement:** After the initial analysis, I reviewed my understanding and explanations to ensure clarity, accuracy, and completeness, addressing all parts of the request. I double-checked if the JavaScript examples accurately reflected the tested behavior.

Essentially, I approached this by dissecting the C++ test code into its logical components (the individual tests), understanding the V8 API calls and their purpose, mapping these to corresponding JavaScript concepts, and then synthesizing a comprehensive explanation. The knowledge of V8 internals, JavaScript behavior, and testing methodologies was crucial for this process.
好的，让我们来分析一下 `v8/test/cctest/test-api-interceptors.cc` 这个文件的第 6 部分的功能。

**文件类型判断：**

`v8/test/cctest/test-api-interceptors.cc` 的后缀是 `.cc`，这表明它是一个 C++ 源代码文件，而不是 Torque (`.tq`) 文件。

**文件功能概述：**

这个文件主要测试 V8 中 **API 拦截器 (API Interceptors)** 的功能。API 拦截器允许 C++ 代码拦截对 JavaScript 对象的属性进行访问 (读取、写入、删除等) 的操作，并自定义这些操作的行为。

**第 6 部分功能归纳：**

这部分代码主要集中在测试以下与 API 拦截器和函数调用 (特别是通过 Inline Caches - ICs) 相关的场景：

1. **拦截器提供函数，即使函数被缓存：**  测试当拦截器提供一个属性对应的函数时，即使 V8 已经缓存了该函数，拦截器提供的函数仍然会被调用。这确保了拦截器的优先级。

2. **拦截器与优化的编译器：** 测试在经过 V8 优化编译器 (如 Turbofan) 优化后的代码中，拦截器是否仍然能正常工作，包括函数调用。

3. **缓存的函数失效：**  测试当 V8 缓存了一个通过拦截器获取的函数，但之后该函数由于原型链的改变或其他原因而失效时，V8 能否正确处理，并重新查找或通过拦截器获取新的函数。

4. **全局对象上的函数调用：** 测试当要调用的函数位于全局对象上时，拦截器能否正确工作并路由到全局函数。

5. **Keyed Call ICs (键控调用 ICs)：**  测试当使用动态属性访问 (例如 `o[method]()`) 调用函数时，拦截器如何与 ICs 交互，特别是当方法名发生变化时。

6. **ReferenceError 和异常处理：** 测试拦截器在某些情况下返回“属性未找到”或抛出异常时，V8 的行为是否符合预期。

7. **Null 拦截器：** 测试当设置了 `null` 拦截器时，V8 是否能正确忽略它们，并按照默认的属性访问行为进行。

8. **属性特性 (Attributes)：** 测试通过拦截器提供的属性是否能正确设置和反映属性的特性，例如是否可枚举。

9. **与优化的 Setters/Getters 的交互：**  测试拦截器与 JavaScript 对象上定义的 `setter` 和 `getter` 的交互，特别是在代码被优化后。

10. **回归测试 (Regress):**  包含了一些回归测试，用于确保之前修复的 bug 不会再次出现。

**JavaScript 举例说明（与函数调用相关）：**

考虑 `THREADED_TEST(InterceptorCallICConstantFunctionNotNeeded)` 这个测试。它的目的是验证即使 V8 认为某个属性会返回一个固定的函数，但如果存在拦截器，拦截器仍然有机会介入并提供不同的函数。

```javascript
// 假设在 C++ 层面，我们创建了一个对象模板，并为属性 'x' 设置了一个拦截器。
// 该拦截器在第一次被调用时，会返回一个函数，但在后续的调用中，可能会返回不同的函数。

let o = {}; // JavaScript 对象

// 这是 C++ 拦截器可能返回的函数
function subtractOne(x) {
  return x - 1;
}

function addOne(x) {
  return x + 1;
}

// 模拟第一次访问 o.x，拦截器返回 subtractOne
// 假设 V8 内部可能缓存了 o.x 指向 subtractOne

// 后续的访问 o.x 仍然会触发拦截器

// 实际执行：
o.x = addOne; // 通过赋值，我们改变了 o.x 的值

let result = o.x(42); // 期望 result 为 43，而不是 41 (如果缓存未失效)
console.log(result);
```

**代码逻辑推理（以 `InterceptorCallICConstantFunctionNotNeeded` 为例）：**

**假设输入：**

1. 创建一个 JavaScript 对象 `o`。
2. 为 `o` 的属性 `x` 设置一个 C++ 拦截器 `InterceptorCallICGetter5`。
3. `InterceptorCallICGetter5` 在被调用时，会将全局变量 `call_ic_function5_global` 指向的函数 (一个减 1 的函数) 设置为属性 `x` 的值。
4. JavaScript 代码先将一个加 1 的函数赋值给 `o.x`。
5. 然后在一个循环中多次调用 `o.x(42)`。

**预期输出：**

循环中 `o.x(42)` 的结果应该是 41 (因为拦截器最终提供了减 1 的函数)，而不是最初赋值的加 1 的结果。

**涉及用户常见的编程错误：**

1. **假设对象属性是静态的：**  程序员可能会假设一旦对象属性被赋值，它的值就不会改变，而忽略了拦截器可能会动态地提供属性值。这在涉及到外部 C++ 代码或者框架时尤其需要注意。

   ```javascript
   let obj = {};
   // 假设某个框架在 C++ 层面为 obj 的 'value' 属性设置了拦截器

   obj.value = 10;
   console.log(obj.value); // 预期输出 10，但拦截器可能会返回其他值

   // 后续的操作可能基于错误的假设
   if (obj.value > 5) {
       // ...
   }
   ```

2. **不理解拦截器的副作用：**  拦截器中的 C++ 代码可以执行任意操作，包括修改其他对象的状态、调用外部服务等。如果程序员不了解这些潜在的副作用，可能会导致难以调试的问题。

**总结第 6 部分的功能：**

这部分 `test-api-interceptors.cc` 专注于测试 V8 的 API 拦截器在与函数调用和优化编译器交互时的各种复杂场景。它涵盖了拦截器如何影响函数查找、缓存、失效以及异常处理等关键方面。通过这些测试，V8 开发者可以确保拦截器功能的稳定性和正确性，即使在经过高度优化的代码中也能按预期工作。这些测试对于理解 V8 如何处理动态属性访问和与外部 C++ 代码交互至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-api-interceptors.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api-interceptors.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
t(call_ic_function5_global);
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