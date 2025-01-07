Response: The user wants a summary of the functionality of the C++ source code file `v8/test/cctest/test-api.cc`, specifically part 4 of 18. I need to analyze the code snippets provided and identify the main features being tested. The user also wants to see how these C++ features relate to JavaScript, with examples.

Looking at the code, I see a lot of `THREADED_TEST` macros, which suggests this file contains unit tests for the V8 API. The tests cover various aspects:

- **Exception Handling:** Tests involving `TryCatch`, throwing exceptions from C++ (`ThrowFromC`), and catching them in JavaScript and vice-versa. Custom error handling and message listeners are also covered.
- **Array Creation:** Testing different ways to create JavaScript arrays from C++, including empty arrays, arrays with a specific length, and arrays from vectors and callbacks.
- **Function Calls:** Testing calling JavaScript functions from C++ with different numbers of arguments and checking the `this` binding in strict and sloppy modes.
- **Object Construction:** Testing the creation of JavaScript objects using the `new` operator from C++.
- **Type Conversions:** Testing the `ToNumber`, `ToInt32`, `ToUint32` methods for converting JavaScript values to C++ number types, and checking the `IsInt32`, `IsUint32` type checks.
- **Equality Checks:** Testing different equality operators like `Equals`, `StrictEquals`, and `SameValue`.
- **`typeof` and `instanceof` Operators:**  Testing the C++ API equivalents of these JavaScript operators.
- **Property Accessors:** Testing how to define and interact with JavaScript properties that are backed by C++ getter and setter functions.

To provide JavaScript examples, I'll focus on demonstrating the JavaScript equivalents of the C++ API calls being tested.
这个C++源代码文件 (`v8/test/cctest/test-api.cc`) 的第4部分主要集中在测试 **V8 API 中与异常处理、数组操作、函数调用、对象构造、类型转换以及属性访问相关的 C++ 接口功能**。  它通过一系列的单元测试来验证这些 API 的行为是否符合预期，并且测试了 C++ 和 JavaScript 之间的互操作性，特别是异常的抛出和捕获。

以下是更详细的功能归纳：

1. **异常处理 (Exception Handling):**
    *   测试了 `v8::TryCatch` 的基本用法，包括捕获 JavaScript 中抛出的异常。
    *   测试了在 C++ 中抛出异常 (`isolate->ThrowException`) 并在 JavaScript 中捕获的能力。
    *   测试了自定义错误对象的 `toString` 方法对异常消息的影响。
    *   测试了在消息监听器中处理异常以及在 verbose 的 `TryCatch` 中重新抛出异常的情况。
    *   测试了来自外部脚本的异常处理。
    *   测试了在 C++ 回调函数中抛出异常并被 JavaScript 代码捕获的情况。
    *   测试了可以抛出和捕获各种 JavaScript 值作为异常。
    *   测试了 `try...catch` 和 `try...finally` 语句在异常处理中的作用，包括 `finally` 块如何影响异常的传播。

2. **数组操作 (Array Operations):**
    *   测试了使用 `v8::Array::New` 创建新的 JavaScript 数组，包括创建空数组、指定长度的数组以及从 C++ `std::vector` 创建数组。
    *   测试了使用回调函数动态创建数组元素的功能。
    *   测试了访问和设置数组元素的方法 (`Get`, `Set`)。

3. **函数调用 (Function Calls):**
    *   测试了使用 `Function->Call` 从 C++ 调用 JavaScript 函数，并传递不同数量的参数。
    *   测试了函数调用中 `this` 关键字在严格模式和非严格模式下的行为。

4. **对象构造 (Object Construction):**
    *   测试了使用 `Function->NewInstance` 从 C++ 创建 JavaScript 对象的实例，并传递不同数量的参数。

5. **类型转换 (Type Conversions):**
    *   测试了将 JavaScript 值转换为 C++ 数值类型的方法，如 `ToNumber`, `ToInt32`, `ToUint32`，并验证了不同 JavaScript 数值的转换结果。
    *   测试了判断 JavaScript 值类型的 API，如 `IsInt32`, `IsUint32`。
    *   测试了 `ToInteger` 方法的转换行为。
    *   测试了当 JavaScript 对象的 `toString` 等方法抛出异常时，类型转换 API 的行为。

6. **属性访问 (Property Access):**
    *   测试了使用 `SetNativeDataProperty` 在 JavaScript 对象上定义由 C++ 代码提供 getter 和 setter 的属性。
    *   测试了 API 属性的读取和写入操作。
    *   测试了在 API 属性上使用 `Object.defineProperty` 重新定义属性的行为，包括可配置性 (`configurable`) 的影响。
    *   测试了对数组元素的 API 访问器。

与 JavaScript 的功能关系和示例：

这个 C++ 文件中的测试直接对应了 V8 引擎提供的 JavaScript 功能。以下是一些 JavaScript 示例，说明了 C++ 代码正在测试的 JavaScript 特性：

**异常处理:**

```javascript
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error("Caught an error:", e.message);
} finally {
  console.log("Finally block executed.");
}

function throwError() {
  throw "This is a string exception.";
}

try {
  throwError();
} catch (e) {
  console.error("Caught a string exception:", e);
}
```

**数组操作:**

```javascript
const emptyArray = [];
const arrayWithLength = new Array(5); // Length is 5, elements are empty slots
const filledArray = [1, 2, 3];

console.log(emptyArray.length); // 0
console.log(filledArray[0]);    // 1

const dynamicArray = [];
for (let i = 0; i < 7; i++) {
  dynamicArray.push(i + 1);
}
console.log(dynamicArray); // [1, 2, 3, 4, 5, 6, 7]
```

**函数调用:**

```javascript
function myFunction(a, b) {
  console.log("Arguments:", arguments);
  console.log("this:", this);
  return a + b;
}

myFunction(10, 20); // Arguments: [Arguments] { '0': 10, '1': 20 }, this: [object global]

const myObject = {
  value: 100,
  myMethod: function(a) {
    console.log("this in method:", this); // this: { value: 100, myMethod: [Function: myMethod] }
    return this.value + a;
  }
};

myObject.myMethod(5);
```

**对象构造:**

```javascript
function MyClass(value) {
  this.myProperty = value;
}

const instance = new MyClass(42);
console.log(instance.myProperty); // 42
```

**类型转换:**

```javascript
let str = "42";
let num = Number(str); // Explicit conversion to number
console.log(typeof num, num); // number 42

let val = "3.14";
console.log(parseInt(val));   // 3
console.log(parseFloat(val)); // 3.14

let nonNumber = "hello";
console.log(Number(nonNumber)); // NaN

console.log(typeof undefined); // "undefined"
console.log(typeof null);      // "object"
```

**属性访问:**

```javascript
const myObj = {
  x: "hello",
  getY: function() { return this.x + " world"; }
};

console.log(myObj.x);    // "hello"
console.log(myObj.getY()); // "hello world"

Object.defineProperty(myObj, 'z', {
  get: function() { return "custom getter"; },
  configurable: false
});

console.log(myObj.z); // "custom getter"

try {
  Object.defineProperty(myObj, 'z', { value: 'new value' }); // Error, configurable is false
} catch (e) {
  console.error(e);
}
```

总而言之，这个 C++ 文件是 V8 引擎测试套件的一部分，专门用来验证 V8 提供的 C++ API 在处理异常、数组、函数、对象和类型等核心 JavaScript 特性时的正确性和稳定性。这些测试确保了 C++ 代码能够有效地与 JavaScript 代码进行交互。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共18部分，请归纳一下它的功能

"""
EQ(0, strcmp("exception", *exception_value));
  CHECK(context->GetIsolate()->HasPendingException());
  try_catch.Reset();
  CHECK(!context->GetIsolate()->HasPendingException());
}

void ExpectArrayValues(std::vector<int> expected_values,
                       v8::Local<v8::Context> context,
                       v8::Local<v8::Array> array) {
  for (auto i = 0u; i < expected_values.size(); i++) {
    CHECK_EQ(expected_values[i], array->Get(context, i)
                                     .ToLocalChecked()
                                     ->Int32Value(context)
                                     .FromJust());
  }
}

THREADED_TEST(Array_New_Basic) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<v8::Array> array = v8::Array::New(context->GetIsolate());
  CHECK_EQ(0u, array->Length());
  CHECK(array->Get(context.local(), 0).ToLocalChecked()->IsUndefined());
  CHECK(!array->Has(context.local(), 0).FromJust());
  CHECK(array->Get(context.local(), 100).ToLocalChecked()->IsUndefined());
  CHECK(!array->Has(context.local(), 100).FromJust());
  CHECK(array->Set(context.local(), 2, v8_num(7)).FromJust());
  CHECK_EQ(3u, array->Length());
  CHECK(!array->Has(context.local(), 0).FromJust());
  CHECK(!array->Has(context.local(), 1).FromJust());
  CHECK(array->Has(context.local(), 2).FromJust());
  CHECK_EQ(7, array->Get(context.local(), 2)
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  Local<Value> obj = CompileRun("[1, 2, 3]");
  Local<v8::Array> arr = obj.As<v8::Array>();
  CHECK_EQ(3u, arr->Length());
  ExpectArrayValues({1, 2, 3}, context.local(), arr);
  array = v8::Array::New(context->GetIsolate(), 27);
  CHECK_EQ(27u, array->Length());
  array = v8::Array::New(context->GetIsolate(), -27);
  CHECK_EQ(0u, array->Length());
}

THREADED_TEST(Array_New_FromVector) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<v8::Array> array;
  auto numbers = v8::to_array<Local<Value>>({v8_num(1), v8_num(2), v8_num(3)});
  array = v8::Array::New(context->GetIsolate(), numbers.data(), numbers.size());
  CHECK_EQ(numbers.size(), array->Length());
  ExpectArrayValues({1, 2, 3}, context.local(), array);
}

struct CreateElementFactory {
  static void Prepare(size_t abort_index_value = static_cast<size_t>(-1)) {
    abort_index = abort_index_value;
    current_index = 0;
  }

  static v8::MaybeLocal<v8::Value> CreateElement() {
    if (current_index == abort_index) {
      fprintf(stderr, "THROWING!\n");
      CcTest::isolate()->ThrowException(v8_str("CreateElement exception"));
      return {};
    }
    return v8_num(current_index++ + 1);
  }

  static size_t abort_index;
  static size_t current_index;
};

// static
size_t CreateElementFactory::abort_index = static_cast<size_t>(-1);
size_t CreateElementFactory::current_index = 0;

THREADED_TEST(Array_New_FromCallback_Success) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::MaybeLocal<v8::Array> maybe_array;
  v8::Local<v8::Array> array;
  CreateElementFactory::Prepare();
  maybe_array =
      v8::Array::New(context.local(), 7, CreateElementFactory::CreateElement);
  CHECK(maybe_array.ToLocal(&array));
  CHECK_EQ(7u, array->Length());
  ExpectArrayValues({1, 2, 3, 4, 5, 6, 7}, context.local(), array);
}

THREADED_TEST(Array_New_FromCallback_Exception) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::MaybeLocal<v8::Array> maybe_array;
  v8::Local<v8::Array> array;
  CreateElementFactory::Prepare(17);
  v8::TryCatch try_catch(context->GetIsolate());
  maybe_array =
      v8::Array::New(context.local(), 23, CreateElementFactory::CreateElement);
  CHECK(!maybe_array.ToLocal(&array));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
}

void HandleF(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  v8::EscapableHandleScope scope(args.GetIsolate());
  ApiTestFuzzer::Fuzz();
  Local<v8::Array> result = v8::Array::New(args.GetIsolate(), args.Length());
  for (int i = 0; i < args.Length(); i++) {
    CHECK(result->Set(CcTest::isolate()->GetCurrentContext(), i, args[i])
              .FromJust());
  }
  args.GetReturnValue().Set(scope.Escape(result));
}


THREADED_TEST(Vector) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> global = ObjectTemplate::New(isolate);
  global->Set(isolate, "f", v8::FunctionTemplate::New(isolate, HandleF));
  LocalContext context(nullptr, global);

  const char* fun = "f()";
  Local<v8::Array> a0 = CompileRun(fun).As<v8::Array>();
  CHECK_EQ(0u, a0->Length());

  const char* fun2 = "f(11)";
  Local<v8::Array> a1 = CompileRun(fun2).As<v8::Array>();
  CHECK_EQ(1u, a1->Length());
  CHECK_EQ(11, a1->Get(context.local(), 0)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());

  const char* fun3 = "f(12, 13)";
  Local<v8::Array> a2 = CompileRun(fun3).As<v8::Array>();
  CHECK_EQ(2u, a2->Length());
  CHECK_EQ(12, a2->Get(context.local(), 0)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(13, a2->Get(context.local(), 1)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());

  const char* fun4 = "f(14, 15, 16)";
  Local<v8::Array> a3 = CompileRun(fun4).As<v8::Array>();
  CHECK_EQ(3u, a3->Length());
  CHECK_EQ(14, a3->Get(context.local(), 0)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(15, a3->Get(context.local(), 1)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(16, a3->Get(context.local(), 2)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());

  const char* fun5 = "f(17, 18, 19, 20)";
  Local<v8::Array> a4 = CompileRun(fun5).As<v8::Array>();
  CHECK_EQ(4u, a4->Length());
  CHECK_EQ(17, a4->Get(context.local(), 0)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(18, a4->Get(context.local(), 1)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(19, a4->Get(context.local(), 2)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
  CHECK_EQ(20, a4->Get(context.local(), 3)
                   .ToLocalChecked()
                   ->Int32Value(context.local())
                   .FromJust());
}


THREADED_TEST(FunctionCall) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  CompileRun(
      "function Foo() {"
      "  var result = [];"
      "  for (var i = 0; i < arguments.length; i++) {"
      "    result.push(arguments[i]);"
      "  }"
      "  return result;"
      "}"
      "function ReturnThisSloppy() {"
      "  return this;"
      "}"
      "function ReturnThisStrict() {"
      "  'use strict';"
      "  return this;"
      "}");
  Local<Function> Foo = Local<Function>::Cast(
      context->Global()->Get(context.local(), v8_str("Foo")).ToLocalChecked());
  Local<Function> ReturnThisSloppy = Local<Function>::Cast(
      context->Global()
          ->Get(context.local(), v8_str("ReturnThisSloppy"))
          .ToLocalChecked());
  Local<Function> ReturnThisStrict = Local<Function>::Cast(
      context->Global()
          ->Get(context.local(), v8_str("ReturnThisStrict"))
          .ToLocalChecked());

  v8::Local<Value>* args0 = nullptr;
  Local<v8::Array> a0 = Local<v8::Array>::Cast(
      Foo->Call(context.local(), Foo, 0, args0).ToLocalChecked());
  CHECK_EQ(0u, a0->Length());

  v8::Local<Value> args1[] = {v8_num(1.1)};
  Local<v8::Array> a1 = Local<v8::Array>::Cast(
      Foo->Call(context.local(), Foo, 1, args1).ToLocalChecked());
  CHECK_EQ(1u, a1->Length());
  CHECK_EQ(1.1, a1->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args2[] = {v8_num(2.2), v8_num(3.3)};
  Local<v8::Array> a2 = Local<v8::Array>::Cast(
      Foo->Call(context.local(), Foo, 2, args2).ToLocalChecked());
  CHECK_EQ(2u, a2->Length());
  CHECK_EQ(2.2, a2->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(3.3, a2->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args3[] = {v8_num(4.4), v8_num(5.5), v8_num(6.6)};
  Local<v8::Array> a3 = Local<v8::Array>::Cast(
      Foo->Call(context.local(), Foo, 3, args3).ToLocalChecked());
  CHECK_EQ(3u, a3->Length());
  CHECK_EQ(4.4, a3->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(5.5, a3->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(6.6, a3->Get(context.local(), v8::Integer::New(isolate, 2))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args4[] = {v8_num(7.7), v8_num(8.8), v8_num(9.9),
                              v8_num(10.11)};
  Local<v8::Array> a4 = Local<v8::Array>::Cast(
      Foo->Call(context.local(), Foo, 4, args4).ToLocalChecked());
  CHECK_EQ(4u, a4->Length());
  CHECK_EQ(7.7, a4->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(8.8, a4->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(9.9, a4->Get(context.local(), v8::Integer::New(isolate, 2))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(10.11, a4->Get(context.local(), v8::Integer::New(isolate, 3))
                      .ToLocalChecked()
                      ->NumberValue(context.local())
                      .FromJust());

  Local<v8::Value> r1 =
      ReturnThisSloppy
          ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r1->StrictEquals(context->Global()));
  Local<v8::Value> r2 =
      ReturnThisSloppy->Call(context.local(), v8::Null(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r2->StrictEquals(context->Global()));
  Local<v8::Value> r3 =
      ReturnThisSloppy->Call(context.local(), v8_num(42), 0, nullptr)
          .ToLocalChecked();
  CHECK(r3->IsNumberObject());
  CHECK_EQ(42.0, r3.As<v8::NumberObject>()->ValueOf());
  Local<v8::Value> r4 =
      ReturnThisSloppy->Call(context.local(), v8_str("hello"), 0, nullptr)
          .ToLocalChecked();
  CHECK(r4->IsStringObject());
  CHECK(r4.As<v8::StringObject>()->ValueOf()->StrictEquals(v8_str("hello")));
  Local<v8::Value> r5 =
      ReturnThisSloppy->Call(context.local(), v8::True(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r5->IsBooleanObject());
  CHECK(r5.As<v8::BooleanObject>()->ValueOf());

  Local<v8::Value> r6 =
      ReturnThisStrict
          ->Call(context.local(), v8::Undefined(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r6->IsUndefined());
  Local<v8::Value> r7 =
      ReturnThisStrict->Call(context.local(), v8::Null(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r7->IsNull());
  Local<v8::Value> r8 =
      ReturnThisStrict->Call(context.local(), v8_num(42), 0, nullptr)
          .ToLocalChecked();
  CHECK(r8->StrictEquals(v8_num(42)));
  Local<v8::Value> r9 =
      ReturnThisStrict->Call(context.local(), v8_str("hello"), 0, nullptr)
          .ToLocalChecked();
  CHECK(r9->StrictEquals(v8_str("hello")));
  Local<v8::Value> r10 =
      ReturnThisStrict->Call(context.local(), v8::True(isolate), 0, nullptr)
          .ToLocalChecked();
  CHECK(r10->StrictEquals(v8::True(isolate)));
}


THREADED_TEST(ConstructCall) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  CompileRun(
      "function Foo() {"
      "  var result = [];"
      "  for (var i = 0; i < arguments.length; i++) {"
      "    result.push(arguments[i]);"
      "  }"
      "  return result;"
      "}");
  Local<Function> Foo = Local<Function>::Cast(
      context->Global()->Get(context.local(), v8_str("Foo")).ToLocalChecked());

  v8::Local<Value>* args0 = nullptr;
  Local<v8::Array> a0 = Local<v8::Array>::Cast(
      Foo->NewInstance(context.local(), 0, args0).ToLocalChecked());
  CHECK_EQ(0u, a0->Length());

  v8::Local<Value> args1[] = {v8_num(1.1)};
  Local<v8::Array> a1 = Local<v8::Array>::Cast(
      Foo->NewInstance(context.local(), 1, args1).ToLocalChecked());
  CHECK_EQ(1u, a1->Length());
  CHECK_EQ(1.1, a1->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args2[] = {v8_num(2.2), v8_num(3.3)};
  Local<v8::Array> a2 = Local<v8::Array>::Cast(
      Foo->NewInstance(context.local(), 2, args2).ToLocalChecked());
  CHECK_EQ(2u, a2->Length());
  CHECK_EQ(2.2, a2->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(3.3, a2->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args3[] = {v8_num(4.4), v8_num(5.5), v8_num(6.6)};
  Local<v8::Array> a3 = Local<v8::Array>::Cast(
      Foo->NewInstance(context.local(), 3, args3).ToLocalChecked());
  CHECK_EQ(3u, a3->Length());
  CHECK_EQ(4.4, a3->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(5.5, a3->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(6.6, a3->Get(context.local(), v8::Integer::New(isolate, 2))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());

  v8::Local<Value> args4[] = {v8_num(7.7), v8_num(8.8), v8_num(9.9),
                              v8_num(10.11)};
  Local<v8::Array> a4 = Local<v8::Array>::Cast(
      Foo->NewInstance(context.local(), 4, args4).ToLocalChecked());
  CHECK_EQ(4u, a4->Length());
  CHECK_EQ(7.7, a4->Get(context.local(), v8::Integer::New(isolate, 0))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(8.8, a4->Get(context.local(), v8::Integer::New(isolate, 1))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(9.9, a4->Get(context.local(), v8::Integer::New(isolate, 2))
                    .ToLocalChecked()
                    ->NumberValue(context.local())
                    .FromJust());
  CHECK_EQ(10.11, a4->Get(context.local(), v8::Integer::New(isolate, 3))
                      .ToLocalChecked()
                      ->NumberValue(context.local())
                      .FromJust());
}


THREADED_TEST(ConversionNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  // Very large number.
  CompileRun("var obj = Math.pow(2,32) * 1237;");
  Local<Value> obj =
      env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(5312874545152.0,
           obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(0, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(0, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Large number.
  CompileRun("var obj = -1234567890123;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(-1234567890123.0,
           obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(-1912276171, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(2382691125, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Small positive integer.
  CompileRun("var obj = 42;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(42.0, obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(42, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(42, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Negative integer.
  CompileRun("var obj = -37;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(-37.0, obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(-37, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(4294967259, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Positive non-int32 integer.
  CompileRun("var obj = 0x81234567;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(2166572391.0, obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(-2128394905, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(2166572391, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Fraction.
  CompileRun("var obj = 42.3;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(42.3, obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(42, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(42, obj->ToUint32(env.local()).ToLocalChecked()->Value());
  // Large negative fraction.
  CompileRun("var obj = -5726623061.75;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK_EQ(-5726623061.75,
           obj->ToNumber(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(-1431655765, obj->ToInt32(env.local()).ToLocalChecked()->Value());
  CHECK_EQ(2863311531, obj->ToUint32(env.local()).ToLocalChecked()->Value());
}


THREADED_TEST(isNumberType) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  // Very large number.
  CompileRun("var obj = Math.pow(2,32) * 1237;");
  Local<Value> obj =
      env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(!obj->IsUint32());
  // Large negative number.
  CompileRun("var obj = -1234567890123;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(!obj->IsUint32());
  // Small positive integer.
  CompileRun("var obj = 42;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(obj->IsInt32());
  CHECK(obj->IsUint32());
  // Negative integer.
  CompileRun("var obj = -37;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(obj->IsInt32());
  CHECK(!obj->IsUint32());
  // Positive non-int32 integer.
  CompileRun("var obj = 0x81234567;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(obj->IsUint32());
  // Fraction.
  CompileRun("var obj = 42.3;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(!obj->IsUint32());
  // Large negative fraction.
  CompileRun("var obj = -5726623061.75;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(!obj->IsUint32());
  // Positive zero
  CompileRun("var obj = 0.0;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(obj->IsInt32());
  CHECK(obj->IsUint32());
  // Negative zero
  CompileRun("var obj = -0.0;");
  obj = env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();
  CHECK(!obj->IsInt32());
  CHECK(!obj->IsUint32());
}

THREADED_TEST(IntegerType) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<Value> result;

  // Small positive integer
  result = CompileRun("42;");
  CHECK(result->IsNumber());
  CHECK_EQ(42, result.As<v8::Integer>()->Value());
  // Small negative integer
  result = CompileRun("-42;");
  CHECK(result->IsNumber());
  CHECK_EQ(-42, result.As<v8::Integer>()->Value());
  // Positive non-int32 integer
  result = CompileRun("1099511627776;");
  CHECK(result->IsNumber());
  CHECK_EQ(1099511627776, result.As<v8::Integer>()->Value());
  // Negative non-int32 integer
  result = CompileRun("-1099511627776;");
  CHECK(result->IsNumber());
  CHECK_EQ(-1099511627776, result.As<v8::Integer>()->Value());
  // Positive non-integer
  result = CompileRun("3.14;");
  CHECK(result->IsNumber());
  CHECK_EQ(3, result.As<v8::Integer>()->Value());
  // Negative non-integer
  result = CompileRun("-3.14;");
  CHECK(result->IsNumber());
  CHECK_EQ(-3, result.As<v8::Integer>()->Value());
}

static void CheckUncle(v8::Isolate* isolate, v8::TryCatch* try_catch) {
  CHECK(try_catch->HasCaught());
  CHECK(isolate->HasPendingException());
  String::Utf8Value str_value(isolate, try_catch->Exception());
  CHECK_EQ(0, strcmp(*str_value, "uncle?"));
  try_catch->Reset();
  CHECK(!isolate->HasPendingException());
}

THREADED_TEST(ConversionException) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  CompileRun(
      "function TestClass() { };"
      "TestClass.prototype.toString = function () { throw 'uncle?'; };"
      "var obj = new TestClass();");
  Local<Value> obj =
      env->Global()->Get(env.local(), v8_str("obj")).ToLocalChecked();

  v8::TryCatch try_catch(isolate);

  CHECK(obj->ToString(env.local()).IsEmpty());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->ToNumber(env.local()).IsEmpty());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->ToInteger(env.local()).IsEmpty());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->ToUint32(env.local()).IsEmpty());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->ToInt32(env.local()).IsEmpty());
  CheckUncle(isolate, &try_catch);

  CHECK(v8::Undefined(isolate)->ToObject(env.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(obj->Int32Value(env.local()).IsNothing());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->Uint32Value(env.local()).IsNothing());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->NumberValue(env.local()).IsNothing());
  CheckUncle(isolate, &try_catch);

  CHECK(obj->IntegerValue(env.local()).IsNothing());
  CheckUncle(isolate, &try_catch);
}


void ThrowFromC(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  args.GetIsolate()->ThrowException(v8_str("konto"));
}

THREADED_TEST(APICatch) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "ThrowFromC",
             v8::FunctionTemplate::New(isolate, ThrowFromC));
  LocalContext context(nullptr, templ);
  CompileRun(
      "var thrown = false;"
      "try {"
      "  ThrowFromC();"
      "} catch (e) {"
      "  thrown = true;"
      "}");
  Local<Value> thrown = context->Global()
                            ->Get(context.local(), v8_str("thrown"))
                            .ToLocalChecked();
  CHECK(thrown->BooleanValue(isolate));
}


THREADED_TEST(APIThrowTryCatch) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "ThrowFromC",
             v8::FunctionTemplate::New(isolate, ThrowFromC));
  LocalContext context(nullptr, templ);
  v8::TryCatch try_catch(isolate);
  CompileRun("ThrowFromC();");
  CHECK(try_catch.HasCaught());
}

static void check_custom_error_tostring(v8::Local<v8::Message> message,
                                        v8::Local<v8::Value> data) {
  const char* uncaught_error = "Uncaught MyError toString";
  CHECK(message->Get()
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8_str(uncaught_error))
            .FromJust());
}


TEST(CustomErrorToString) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->AddMessageListener(check_custom_error_tostring);
  CompileRun(
      "function MyError(name, message) {                   "
      "  this.name = name;                                 "
      "  this.message = message;                           "
      "}                                                   "
      "MyError.prototype = Object.create(Error.prototype); "
      "MyError.prototype.toString = function() {           "
      "  return 'MyError toString';                        "
      "};                                                  "
      "throw new MyError('my name', 'my message');         ");
  context->GetIsolate()->RemoveMessageListeners(check_custom_error_tostring);
}


static void check_custom_error_message(v8::Local<v8::Message> message,
                                       v8::Local<v8::Value> data) {
  const char* uncaught_error = "Uncaught MyError: my message";
  printf("%s\n", *v8::String::Utf8Value(CcTest::isolate(), message->Get()));
  CHECK(message->Get()
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8_str(uncaught_error))
            .FromJust());
}


TEST(CustomErrorMessage) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->AddMessageListener(check_custom_error_message);

  // Handlebars.
  CompileRun(
      "function MyError(msg) {                             "
      "  this.name = 'MyError';                            "
      "  this.message = msg;                               "
      "}                                                   "
      "MyError.prototype = new Error();                    "
      "throw new MyError('my message');                    ");

  // Closure.
  CompileRun(
      "function MyError(msg) {                             "
      "  this.name = 'MyError';                            "
      "  this.message = msg;                               "
      "}                                                   "
      "inherits = function(childCtor, parentCtor) {        "
      "    function tempCtor() {};                         "
      "    tempCtor.prototype = parentCtor.prototype;      "
      "    childCtor.superClass_ = parentCtor.prototype;   "
      "    childCtor.prototype = new tempCtor();           "
      "    childCtor.prototype.constructor = childCtor;    "
      "};                                                  "
      "inherits(MyError, Error);                           "
      "throw new MyError('my message');                    ");

  // Object.create.
  CompileRun(
      "function MyError(msg) {                             "
      "  this.name = 'MyError';                            "
      "  this.message = msg;                               "
      "}                                                   "
      "MyError.prototype = Object.create(Error.prototype); "
      "throw new MyError('my message');                    ");

  context->GetIsolate()->RemoveMessageListeners(check_custom_error_message);
}


static void check_custom_rethrowing_message(v8::Local<v8::Message> message,
                                            v8::Local<v8::Value> data) {
  CHECK(data->IsExternal());
  int* callcount = static_cast<int*>(data.As<v8::External>()->Value());
  ++*callcount;

  const char* uncaught_error = "Uncaught exception";
  CHECK(message->Get()
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8_str(uncaught_error))
            .FromJust());
  // Test that compiling code inside a message handler works.
  CHECK(CompileRunChecked(CcTest::isolate(), "(function(a) { return a; })(42)")
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8::Integer::NewFromUnsigned(CcTest::isolate(), 42))
            .FromJust());
}


TEST(CustomErrorRethrowsOnToString) {
  int callcount = 0;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  context->GetIsolate()->AddMessageListener(
      check_custom_rethrowing_message, v8::External::New(isolate, &callcount));

  CompileRun(
      "var e = { toString: function() { throw e; } };"
      "try { throw e; } finally {}");

  CHECK_EQ(callcount, 1);
  context->GetIsolate()->RemoveMessageListeners(
      check_custom_rethrowing_message);
}

TEST(CustomErrorRethrowsOnToStringInsideVerboseTryCatch) {
  int callcount = 0;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);
  context->GetIsolate()->AddMessageListener(
      check_custom_rethrowing_message, v8::External::New(isolate, &callcount));

  CompileRun(
      "var e = { toString: function() { throw e; } };"
      "try { throw e; } finally {}");

  CHECK_EQ(callcount, 1);
  context->GetIsolate()->RemoveMessageListeners(
      check_custom_rethrowing_message);
}


static void receive_message(v8::Local<v8::Message> message,
                            v8::Local<v8::Value> data) {
  message->Get();
  message_received = true;
}


TEST(APIThrowMessage) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(receive_message);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "ThrowFromC",
             v8::FunctionTemplate::New(isolate, ThrowFromC));
  LocalContext context(nullptr, templ);
  CompileRun("ThrowFromC();");
  CHECK(message_received);
  isolate->RemoveMessageListeners(receive_message);
}


TEST(APIThrowMessageAndVerboseTryCatch) {
  message_received = false;
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListener(receive_message);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "ThrowFromC",
             v8::FunctionTemplate::New(isolate, ThrowFromC));
  LocalContext context(nullptr, templ);
  v8::TryCatch try_catch(isolate);
  try_catch.SetVerbose(true);
  Local<Value> result = CompileRun("ThrowFromC();");
  CHECK(try_catch.HasCaught());
  CHECK(result.IsEmpty());
  CHECK(message_received);
  isolate->RemoveMessageListeners(receive_message);
}


TEST(APIStackOverflowAndVerboseTryCatch) {
  message_received = false;
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->AddMessageListener(receive_message);
  v8::TryCatch try_catch(context->GetIsolate());
  try_catch.SetVerbose(true);
  Local<Value> result = CompileRun("function foo() { foo(); } foo();");
  CHECK(try_catch.HasCaught());
  CHECK(result.IsEmpty());
  CHECK(message_received);
  context->GetIsolate()->RemoveMessageListeners(receive_message);
}


THREADED_TEST(ExternalScriptException) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "ThrowFromC",
             v8::FunctionTemplate::New(isolate, ThrowFromC));
  LocalContext context(nullptr, templ);

  v8::TryCatch try_catch(isolate);
  Local<Value> result = CompileRun("ThrowFromC(); throw 'panama';");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(isolate, try_catch.Exception());
  CHECK_EQ(0, strcmp("konto", *exception_value));
}


void CThrowCountDown(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  CHECK_EQ(4, args.Length());
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  int count = args[0]->Int32Value(context).FromJust();
  int cInterval = args[2]->Int32Value(context).FromJust();
  int expected = args[3]->Int32Value(context).FromJust();
  CHECK(!isolate->HasPendingException());
  if (count == 0) {
    isolate->ThrowException(v8_str("FromC"));
    CHECK(isolate->HasPendingException());
    return;
  } else {
    Local<v8::Object> global = context->Global();
    Local<Value> fun =
        global->Get(context, v8_str("JSThrowCountDown")).ToLocalChecked();
    v8::Local<Value> argv[] = {v8_num(count - 1), args[1], args[2], args[3]};
    if (count % cInterval == 0) {
      v8::TryCatch try_catch(isolate);
      Local<Value> result = fun.As<Function>()
                                ->Call(context, global, 4, argv)
                                .FromMaybe(Local<Value>());
      CHECK_EQ(isolate->HasPendingException(), try_catch.HasCaught());
      if (try_catch.HasCaught()) {
        CHECK_EQ(expected, count);
        CHECK(result.IsEmpty());
      } else {
        CHECK_NE(expected, count);
      }
      args.GetReturnValue().Set(result);
      return;
    } else {
      args.GetReturnValue().Set(fun.As<Function>()
                                    ->Call(context, global, 4, argv)
                                    .FromMaybe(v8::Local<v8::Value>()));
      bool exception_is_caught_by_callee = count >= expected;
      CHECK_EQ(exception_is_caught_by_callee, !isolate->HasPendingException());
      return;
    }
  }
}


void JSCheck(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  CHECK_EQ(3, args.Length());
  v8::Isolate* isolate = args.GetIsolate();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  bool equality = args[0]->BooleanValue(isolate);
  int count = args[1]->Int32Value(context).FromJust();
  int expected = args[2]->Int32Value(context).FromJust();
  if (equality) {
    CHECK_EQ(count, expected);
  } else {
    CHECK_NE(count, expected);
  }
}


THREADED_TEST(EvalInTryFinally) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(
      "(function() {"
      "  try {"
      "    eval('asldkf (*&^&*^');"
      "  } finally {"
      "    return;"
      "  }"
      "})()");
  CHECK(!try_catch.HasCaught());
}


// This test works by making a stack of alternating JavaScript and C
// activations.  These activations set up exception handlers with regular
// intervals, one interval for C activations and another for JavaScript
// activations.  When enough activations have been created an exception is
// thrown and we check that the right activation catches the exception and that
// no other activations do.  The right activation is always the topmost one with
// a handler, regardless of whether it is in JavaScript or C.
//
// The notation used to describe a test case looks like this:
//
//    *JS[4] *C[3] @JS[2] C[1] JS[0]
//
// Each entry is an activation, either JS or C.  The index is the count at that
// level.  Stars identify activations with exception handlers, the @ identifies
// the exception handler that should catch the exception.
THREADED_TEST(ExceptionOrder) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "check", v8::FunctionTemplate::New(isolate, JSCheck));
  templ->Set(isolate, "CThrowCountDown",
             v8::FunctionTemplate::New(isolate, CThrowCountDown));
  LocalContext context(nullptr, templ);
  CompileRun(
      "function JSThrowCountDown(count, jsInterval, cInterval, expected) {"
      "  if (count == 0) throw 'FromJS';"
      "  if (count % jsInterval == 0) {"
      "    try {"
      "      var value = CThrowCountDown(count - 1,"
      "                                  jsInterval,"
      "                                  cInterval,"
      "                                  expected);"
      "      check(false, count, expected);"
      "      return value;"
      "    } catch (e) {"
      "      check(true, count, expected);"
      "    }"
      "  } else {"
      "    return CThrowCountDown(count - 1, jsInterval, cInterval, expected);"
      "  }"
      "}");
  Local<Function> fun = Local<Function>::Cast(
      context->Global()
          ->Get(context.local(), v8_str("JSThrowCountDown"))
          .ToLocalChecked());

  const int argc = 4;
  //                             count      jsInterval cInterval  expected

  // *JS[4] *C[3] @JS[2] C[1] JS[0]
  v8::Local<Value> a0[argc] = {v8_num(4), v8_num(2), v8_num(3), v8_num(2)};
  fun->Call(context.local(), fun, argc, a0).ToLocalChecked();

  // JS[5] *C[4] JS[3] @C[2] JS[1] C[0]
  v8::Local<Value> a1[argc] = {v8_num(5), v8_num(6), v8_num(1), v8_num(2)};
  fun->Call(context.local(), fun, argc, a1).ToLocalChecked();

  // JS[6] @C[5] JS[4] C[3] JS[2] C[1] JS[0]
  v8::Local<Value> a2[argc] = {v8_num(6), v8_num(7), v8_num(5), v8_num(5)};
  fun->Call(context.local(), fun, argc, a2).ToLocalChecked();

  // @JS[6] C[5] JS[4] C[3] JS[2] C[1] JS[0]
  v8::Local<Value> a3[argc] = {v8_num(6), v8_num(6), v8_num(7), v8_num(6)};
  fun->Call(context.local(), fun, argc, a3).ToLocalChecked();

  // JS[6] *C[5] @JS[4] C[3] JS[2] C[1] JS[0]
  v8::Local<Value> a4[argc] = {v8_num(6), v8_num(4), v8_num(5), v8_num(4)};
  fun->Call(context.local(), fun, argc, a4).ToLocalChecked();

  // JS[6] C[5] *JS[4] @C[3] JS[2] C[1] JS[0]
  v8::Local<Value> a5[argc] = {v8_num(6), v8_num(4), v8_num(3), v8_num(3)};
  fun->Call(context.local(), fun, argc, a5).ToLocalChecked();
}

void ThrowValue(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  CHECK_EQ(1, args.Length());
  args.GetIsolate()->ThrowException(args[0]);
}


THREADED_TEST(ThrowValues) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "Throw", v8::FunctionTemplate::New(isolate, ThrowValue));
  LocalContext context(nullptr, templ);
  v8::Local<v8::Array> result = v8::Local<v8::Array>::Cast(
      CompileRun("function Run(obj) {"
                 "  try {"
                 "    Throw(obj);"
                 "  } catch (e) {"
                 "    return e;"
                 "  }"
                 "  return 'no exception';"
                 "}"
                 "[Run('str'), Run(1), Run(0), Run(null), Run(void 0)];"));
  CHECK_EQ(5u, result->Length());
  CHECK(result->Get(context.local(), v8::Integer::New(isolate, 0))
            .ToLocalChecked()
            ->IsString());
  CHECK(result->Get(context.local(), v8::Integer::New(isolate, 1))
            .ToLocalChecked()
            ->IsNumber());
  CHECK_EQ(1, result->Get(context.local(), v8::Integer::New(isolate, 1))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(result->Get(context.local(), v8::Integer::New(isolate, 2))
            .ToLocalChecked()
            ->IsNumber());
  CHECK_EQ(0, result->Get(context.local(), v8::Integer::New(isolate, 2))
                  .ToLocalChecked()
                  ->Int32Value(context.local())
                  .FromJust());
  CHECK(result->Get(context.local(), v8::Integer::New(isolate, 3))
            .ToLocalChecked()
            ->IsNull());
  CHECK(result->Get(context.local(), v8::Integer::New(isolate, 4))
            .ToLocalChecked()
            ->IsUndefined());
}


THREADED_TEST(CatchZero) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CHECK(!try_catch.HasCaught());
  CompileRun("throw 10");
  CHECK(try_catch.HasCaught());
  CHECK_EQ(10, try_catch.Exception()->Int32Value(context.local()).FromJust());
  try_catch.Reset();
  CHECK(!try_catch.HasCaught());
  CompileRun("throw 0");
  CHECK(try_catch.HasCaught());
  CHECK_EQ(0, try_catch.Exception()->Int32Value(context.local()).FromJust());
}


THREADED_TEST(CatchExceptionFromWith) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CHECK(!try_catch.HasCaught());
  CompileRun("var o = {}; with (o) { throw 42; }");
  CHECK(try_catch.HasCaught());
}


THREADED_TEST(TryCatchAndFinallyHidingException) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  v8::TryCatch try_catch(context->GetIsolate());
  CHECK(!try_catch.HasCaught());
  CompileRun("function f(k) { try { this[k]; } finally { return 0; } };");
  CompileRun("f({toString: function() { throw 42; }});");
  CHECK(!try_catch.HasCaught());
}


void WithTryCatch(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  v8::TryCatch try_catch(args.GetIsolate());
}


THREADED_TEST(TryCatchAndFinally) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("native_with_try_catch"),
                  v8::FunctionTemplate::New(isolate, WithTryCatch)
                      ->GetFunction(context.local())
                      .ToLocalChecked())
            .FromJust());
  v8::TryCatch try_catch(isolate);
  CHECK(!try_catch.HasCaught());
  CompileRun(
      "try {\n"
      "  throw new Error('a');\n"
      "} finally {\n"
      "  native_with_try_catch();\n"
      "}\n");
  CHECK(try_catch.HasCaught());
}

void TryCatchMixedNestingCheck(v8::TryCatch* try_catch) {
  CHECK(try_catch->HasCaught());
  Local<Message> message = try_catch->Message();
  Local<Value> resource = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(
      0, strcmp(*v8::String::Utf8Value(CcTest::isolate(), resource), "inner"));
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(CcTest::isolate(), message->Get()),
                     "Uncaught Error: a"));
  CHECK_EQ(1, message->GetLineNumber(CcTest::isolate()->GetCurrentContext())
                  .FromJust());
  CHECK_EQ(0, message->GetStartColumn(CcTest::isolate()->GetCurrentContext())
                  .FromJust());
}


void TryCatchMixedNestingHelper(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  v8::TryCatch try_catch(args.GetIsolate());
  CompileRunWithOrigin("throw new Error('a');\n", "inner", 0, 0);
  CHECK(try_catch.HasCaught());
  TryCatchMixedNestingCheck(&try_catch);
  CHECK(args.GetIsolate()->HasPendingException());
  try_catch.ReThrow();
  CHECK(args.GetIsolate()->HasPendingException());
}


// This test ensures that an outer TryCatch in the following situation:
//   C++/TryCatch -> JS -> C++/TryCatch -> JS w/ SyntaxError
// does not clobber the Message object generated for the inner TryCatch.
// This exercises the ability of TryCatch.ReThrow() to restore the
// inner pending Message before throwing the exception again.
TEST(TryCatchMixedNesting) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "TryCatchMixedNestingHelper",
             v8::FunctionTemplate::New(isolate, TryCatchMixedNestingHelper));
  LocalContext context(nullptr, templ);
  CompileRunWithOrigin("TryCatchMixedNestingHelper();\n", "outer", 1, 1);
  TryCatchMixedNestingCheck(&try_catch);
}


void TryCatchNativeHelper(const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  v8::TryCatch try_catch(args.GetIsolate());
  args.GetIsolate()->ThrowException(v8_str("boom"));
  CHECK(try_catch.HasCaught());
}


TEST(TryCatchNative) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "TryCatchNativeHelper",
             v8::FunctionTemplate::New(isolate, TryCatchNativeHelper));
  LocalContext context(nullptr, templ);
  CompileRun("TryCatchNativeHelper();");
  CHECK(!try_catch.HasCaught());
}


void TryCatchNativeResetHelper(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  CHECK(i::ValidateCallbackInfo(args));
  ApiTestFuzzer::Fuzz();
  v8::TryCatch try_catch(args.GetIsolate());
  args.GetIsolate()->ThrowException(v8_str("boom"));
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
  CHECK(!try_catch.HasCaught());
}


TEST(TryCatchNativeReset) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->Set(isolate, "TryCatchNativeResetHelper",
             v8::FunctionTemplate::New(isolate, TryCatchNativeResetHelper));
  LocalContext context(nullptr, templ);
  CompileRun("TryCatchNativeResetHelper();");
  CHECK(!try_catch.HasCaught());
}


THREADED_TEST(Equality) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(context->GetIsolate());
  // Check that equality works at all before relying on CHECK_EQ
  CHECK(v8_str("a")->Equals(context.local(), v8_str("a")).FromJust());
  CHECK(!v8_str("a")->Equals(context.local(), v8_str("b")).FromJust());

  CHECK(v8_str("a")->Equals(context.local(), v8_str("a")).FromJust());
  CHECK(!v8_str("a")->Equals(context.local(), v8_str("b")).FromJust());
  CHECK(v8_num(1)->Equals(context.local(), v8_num(1)).FromJust());
  CHECK(v8_num(1.00)->Equals(context.local(), v8_num(1)).FromJust());
  CHECK(!v8_num(1)->Equals(context.local(), v8_num(2)).FromJust());

  // Assume String is not internalized.
  CHECK(v8_str("a")->StrictEquals(v8_str("a")));
  CHECK(!v8_str("a")->StrictEquals(v8_str("b")));
  CHECK(!v8_str("5")->StrictEquals(v8_num(5)));
  CHECK(v8_num(1)->StrictEquals(v8_num(1)));
  CHECK(!v8_num(1)->StrictEquals(v8_num(2)));
  CHECK(v8_num(0.0)->StrictEquals(v8_num(-0.0)));
  Local<Value> not_a_number = v8_num(std::numeric_limits<double>::quiet_NaN());
  CHECK(!not_a_number->StrictEquals(not_a_number));
  CHECK(v8::False(isolate)->StrictEquals(v8::False(isolate)));
  CHECK(!v8::False(isolate)->StrictEquals(v8::Undefined(isolate)));

  v8::Local<v8::Object> obj = v8::Object::New(isolate);
  v8::Persistent<v8::Object> alias(isolate, obj);
  CHECK(v8::Local<v8::Object>::New(isolate, alias)->StrictEquals(obj));
  alias.Reset();

  CHECK(v8_str("a")->SameValue(v8_str("a")));
  CHECK(!v8_str("a")->SameValue(v8_str("b")));
  CHECK(!v8_str("5")->SameValue(v8_num(5)));
  CHECK(v8_num(1)->SameValue(v8_num(1)));
  CHECK(!v8_num(1)->SameValue(v8_num(2)));
  CHECK(!v8_num(0.0)->SameValue(v8_num(-0.0)));
  CHECK(not_a_number->SameValue(not_a_number));
  CHECK(v8::False(isolate)->SameValue(v8::False(isolate)));
  CHECK(!v8::False(isolate)->SameValue(v8::Undefined(isolate)));
}

THREADED_TEST(TypeOf) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(context->GetIsolate());

  Local<v8::FunctionTemplate> t1 = v8::FunctionTemplate::New(isolate);
  Local<v8::Function> fun = t1->GetFunction(context.local()).ToLocalChecked();

  CHECK(v8::Undefined(isolate)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("undefined"))
            .FromJust());
  CHECK(v8::Null(isolate)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("object"))
            .FromJust());
  CHECK(v8_str("str")
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("string"))
            .FromJust());
  CHECK(v8_num(0.0)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("number"))
            .FromJust());
  CHECK(v8_num(1)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("number"))
            .FromJust());
  CHECK(v8::Object::New(isolate)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("object"))
            .FromJust());
  CHECK(v8::Boolean::New(isolate, true)
            ->TypeOf(isolate)
            ->Equals(context.local(), v8_str("boolean"))
            .FromJust());
  CHECK(fun->TypeOf(isolate)
            ->Equals(context.local(), v8_str("function"))
            .FromJust());
}

THREADED_TEST(InstanceOf) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  CompileRun(
      "var A = {};"
      "var B = {};"
      "var C = {};"
      "B.__proto__ = A;"
      "C.__proto__ = B;"
      "function F() {}"
      "F.prototype = A;"
      "var G = { [Symbol.hasInstance] : null};"
      "var H = { [Symbol.hasInstance] : () => { throw new Error(); } };"
      "var J = { [Symbol.hasInstance] : () => true };"
      "class K {}"
      "var D = new K;"
      "class L extends K {}"
      "var E = new L");

  v8::Local<v8::Object> f = v8::Local<v8::Object>::Cast(CompileRun("F"));
  v8::Local<v8::Object> g = v8::Local<v8::Object>::Cast(CompileRun("G"));
  v8::Local<v8::Object> h = v8::Local<v8::Object>::Cast(CompileRun("H"));
  v8::Local<v8::Object> j = v8::Local<v8::Object>::Cast(CompileRun("J"));
  v8::Local<v8::Object> k = v8::Local<v8::Object>::Cast(CompileRun("K"));
  v8::Local<v8::Object> l = v8::Local<v8::Object>::Cast(CompileRun("L"));
  v8::Local<v8::Value> a = v8::Local<v8::Value>::Cast(CompileRun("A"));
  v8::Local<v8::Value> b = v8::Local<v8::Value>::Cast(CompileRun("B"));
  v8::Local<v8::Value> c = v8::Local<v8::Value>::Cast(CompileRun("C"));
  v8::Local<v8::Value> d = v8::Local<v8::Value>::Cast(CompileRun("D"));
  v8::Local<v8::Value> e = v8::Local<v8::Value>::Cast(CompileRun("E"));

  v8::TryCatch try_catch(env->GetIsolate());
  CHECK(!a->InstanceOf(env.local(), f).ToChecked());
  CHECK(b->InstanceOf(env.local(), f).ToChecked());
  CHECK(c->InstanceOf(env.local(), f).ToChecked());
  CHECK(!d->InstanceOf(env.local(), f).ToChecked());
  CHECK(!e->InstanceOf(env.local(), f).ToChecked());
  CHECK(!try_catch.HasCaught());

  CHECK(a->InstanceOf(env.local(), g).IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(b->InstanceOf(env.local(), h).IsNothing());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  CHECK(v8_num(1)->InstanceOf(env.local(), j).ToChecked());
  CHECK(!try_catch.HasCaught());

  CHECK(d->InstanceOf(env.local(), k).ToChecked());
  CHECK(e->InstanceOf(env.local(), k).ToChecked());
  CHECK(!d->InstanceOf(env.local(), l).ToChecked());
  CHECK(e->InstanceOf(env.local(), l).ToChecked());
  CHECK(!try_catch.HasCaught());
}

THREADED_TEST(MultiRun) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<Script> script = v8_compile("x");
  for (int i = 0; i < 10; i++) {
    script->Run(context.local()).IsEmpty();
  }
}


static void GetXValue(Local<Name> name,
                      const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CHECK(info.Data()
            ->Equals(CcTest::isolate()->GetCurrentContext(), v8_str("donut"))
            .FromJust());
  CHECK(name->Equals(CcTest::isolate()->GetCurrentContext(), v8_str("x"))
            .FromJust());
  info.GetReturnValue().Set(name);
}


THREADED_TEST(SimplePropertyRead) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetXValue, nullptr,
                               v8_str("donut"));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x");
  for (int i = 0; i < 10; i++) {
    Local<Value> result = script->Run(context.local()).ToLocalChecked();
    CHECK(result->Equals(context.local(), v8_str("x")).FromJust());
  }
}


THREADED_TEST(DefinePropertyOnAPIAccessor) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetXValue, nullptr,
                               v8_str("donut"));
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // Uses getOwnPropertyDescriptor to check the configurable status
  Local<Script> script_desc = v8_compile(
      "var prop = Object.getOwnPropertyDescriptor( "
      "obj, 'x');"
      "prop.configurable;");
  Local<Value> result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(result->BooleanValue(isolate));

  // Redefine get - but still configurable
  Local<Script> script_define = v8_compile(
      "var desc = { get: function(){return 42; },"
      "            configurable: true };"
      "Object.defineProperty(obj, 'x', desc);"
      "obj.x");
  result = script_define->Run(context.local()).ToLocalChecked();
  CHECK(result->Equals(context.local(), v8_num(42)).FromJust());

  // Check that the accessor is still configurable
  result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(result->BooleanValue(isolate));

  // Redefine to a non-configurable
  script_define = v8_compile(
      "var desc = { get: function(){return 43; },"
      "             configurable: false };"
      "Object.defineProperty(obj, 'x', desc);"
      "obj.x");
  result = script_define->Run(context.local()).ToLocalChecked();
  CHECK(result->Equals(context.local(), v8_num(43)).FromJust());
  result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(!result->BooleanValue(isolate));

  // Make sure that it is not possible to redefine again
  v8::TryCatch try_catch(isolate);
  CHECK(script_define->Run(context.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(isolate, try_catch.Exception());
  CHECK_EQ(0,
           strcmp(*exception_value, "TypeError: Cannot redefine property: x"));
}


THREADED_TEST(DefinePropertyOnDefineGetterSetter) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetXValue, nullptr,
                               v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  Local<Script> script_desc = v8_compile(
      "var prop ="
      "Object.getOwnPropertyDescriptor( "
      "obj, 'x');"
      "prop.configurable;");
  Local<Value> result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(result->BooleanValue(isolate));

  Local<Script> script_define = v8_compile(
      "var desc = {get: function(){return 42; },"
      "            configurable: true };"
      "Object.defineProperty(obj, 'x', desc);"
      "obj.x");
  result = script_define->Run(context.local()).ToLocalChecked();
  CHECK(result->Equals(context.local(), v8_num(42)).FromJust());

  result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(result->BooleanValue(isolate));

  script_define = v8_compile(
      "var desc = {get: function(){return 43; },"
      "            configurable: false };"
      "Object.defineProperty(obj, 'x', desc);"
      "obj.x");
  result = script_define->Run(context.local()).ToLocalChecked();
  CHECK(result->Equals(context.local(), v8_num(43)).FromJust());

  result = script_desc->Run(context.local()).ToLocalChecked();
  CHECK(!result->BooleanValue(isolate));

  v8::TryCatch try_catch(isolate);
  CHECK(script_define->Run(context.local()).IsEmpty());
  CHECK(try_catch.HasCaught());
  String::Utf8Value exception_value(isolate, try_catch.Exception());
  CHECK_EQ(0,
           strcmp(*exception_value, "TypeError: Cannot redefine property: x"));
}


static v8::Local<v8::Object> GetGlobalProperty(LocalContext* context,
                                               char const* name) {
  return v8::Local<v8::Object>::Cast(
      (*context)
          ->Global()
          ->Get(CcTest::isolate()->GetCurrentContext(), v8_str(name))
          .ToLocalChecked());
}


THREADED_TEST(DefineAPIAccessorOnObject) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  LocalContext context;

  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj1"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("var obj2 = {};");

  CHECK(CompileRun("obj1.x")->IsUndefined());
  CHECK(CompileRun("obj2.x")->IsUndefined());

  CHECK(GetGlobalProperty(&context, "obj1")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"))
            .FromJust());

  ExpectString("obj1.x", "x");
  CHECK(CompileRun("obj2.x")->IsUndefined());

  CHECK(GetGlobalProperty(&context, "obj2")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"))
            .FromJust());

  ExpectString("obj1.x", "x");
  ExpectString("obj2.x", "x");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj1, 'x').configurable");
  ExpectTrue("Object.getOwnPropertyDescriptor(obj2, 'x').configurable");

  CompileRun(
      "Object.defineProperty(obj1, 'x',"
      "{ get: function() { return 'y'; }, configurable: true })");

  ExpectString("obj1.x", "y");
  ExpectString("obj2.x", "x");

  CompileRun(
      "Object.defineProperty(obj2, 'x',"
      "{ get: function() { return 'y'; }, configurable: true })");

  ExpectString("obj1.x", "y");
  ExpectString("obj2.x", "y");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj1, 'x').configurable");
  ExpectTrue("Object.getOwnPropertyDescriptor(obj2, 'x').configurable");

  CHECK(GetGlobalProperty(&context, "obj1")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"))
            .FromJust());
  CHECK(GetGlobalProperty(&context, "obj2")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"))
            .FromJust());

  ExpectString("obj1.x", "x");
  ExpectString("obj2.x", "x");

  ExpectTrue("Object.getOwnPropertyDescriptor(obj1, 'x').configurable");
  ExpectTrue("Object.getOwnPropertyDescriptor(obj2, 'x').configurable");

  // Define getters/setters, but now make them not configurable.
  CompileRun(
      "Object.defineProperty(obj1, 'x',"
      "{ get: function() { return 'z'; }, configurable: false })");
  CompileRun(
      "Object.defineProperty(obj2, 'x',"
      "{ get: function() { return 'z'; }, configurable: false })");
  ExpectTrue("!Object.getOwnPropertyDescriptor(obj1, 'x').configurable");
  ExpectTrue("!Object.getOwnPropertyDescriptor(obj2, 'x').configurable");

  ExpectString("obj1.x", "z");
  ExpectString("obj2.x", "z");

  CHECK(!GetGlobalProperty(&context, "obj1")
             ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                     nullptr, v8_str("donut"))
             .FromJust());
  CHECK(!GetGlobalProperty(&context, "obj2")
             ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                     nullptr, v8_str("donut"))
             .FromJust());

  ExpectString("obj1.x", "z");
  ExpectString("obj2.x", "z");
}


THREADED_TEST(DontDeleteAPIAccessorsCannotBeOverriden) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  LocalContext context;

  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj1"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("var obj2 = {};");

  CHECK(GetGlobalProperty(&context, "obj1")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"), v8::DontDelete)
            .FromJust());
  CHECK(GetGlobalProperty(&context, "obj2")
            ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                    nullptr, v8_str("donut"), v8::DontDelete)
            .FromJust());

  ExpectString("obj1.x", "x");
  ExpectString("obj2.x", "x");

  ExpectTrue("!Object.getOwnPropertyDescriptor(obj1, 'x').configurable");
  ExpectTrue("!Object.getOwnPropertyDescriptor(obj2, 'x').configurable");

  CHECK(!GetGlobalProperty(&context, "obj1")
             ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                     nullptr, v8_str("donut"))
             .FromJust());
  CHECK(!GetGlobalProperty(&context, "obj2")
             ->SetNativeDataProperty(context.local(), v8_str("x"), GetXValue,
                                     nullptr, v8_str("donut"))
             .FromJust());

  {
    v8::TryCatch try_catch(isolate);
    CompileRun(
        "Object.defineProperty(obj1, 'x',"
        "{get: function() { return 'func'; }})");
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value(isolate, try_catch.Exception());
    CHECK_EQ(
        0, strcmp(*exception_value, "TypeError: Cannot redefine property: x"));
  }
  {
    v8::TryCatch try_catch(isolate);
    CompileRun(
        "Object.defineProperty(obj2, 'x',"
        "{get: function() { return 'func'; }})");
    CHECK(try_catch.HasCaught());
    String::Utf8Value exception_value(isolate, try_catch.Exception());
    CHECK_EQ(
        0, strcmp(*exception_value, "TypeError: Cannot redefine property: x"));
  }
}


static void Get239Value(Local<Name> name,
                        const v8::PropertyCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  ApiTestFuzzer::Fuzz();
  CHECK(info.Data()
            ->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("donut"))
            .FromJust());
  CHECK(name->Equals(info.GetIsolate()->GetCurrentContext(), v8_str("239"))
            .FromJust());
  info.GetReturnValue().Set(name);
}


THREADED_TEST(ElementAPIAccessor) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  LocalContext context;

  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj1"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  CompileRun("var obj2 = {};");

  CHECK(GetGlobalProperty(&context, "obj1")
            ->SetNativeDataProperty(context.local(), v8_str("239"), Get239Value,
                                    nullptr, v8_str("donut"))
            .FromJust());
  CHECK(GetGlobalProperty(&context, "obj2")
            ->SetNativeDataProperty(context.local(), v8_str("239"), Get239Value,
                                    nullptr, v8_str("donut"))
            .FromJust());

  ExpectString("obj1[239]", "239");
  ExpectString("obj2[239]", "239");
  ExpectString("obj1['239']", "239");
  ExpectString("obj2['239']", "239");
}


v8::Persistent<Value> xValue;


static void SetXValue(Local<Name> name, Local<Value> value,
                      const v8::PropertyCallbackInfo<void>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  Local<Context> context = info.GetIsolate()->GetCurrentContext();
  CHECK(value->Equals(context, v8_num(4)).FromJust());
  CHECK(info.Data()->Equals(context, v8_str("donut")).FromJust());
  CHECK(name->Equals(context, v8_str("x")).FromJust());
  CHECK(xValue.IsEmpty());
  xValue.Reset(info.GetIsolate(), value);
}


THREADED_TEST(SimplePropertyWrite) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("x"), GetXValue, SetXValue,
                               v8_str("donut"));
  LocalContext context;
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());
  Local<Script> script = v8_compile("obj.x = 4");
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


THREADED_TEST(SetterOnly) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Loc
"""


```