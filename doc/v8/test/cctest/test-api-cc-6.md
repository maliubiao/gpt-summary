Response:
The user wants a summary of the functionality of the provided C++ code, which is a part of the V8 JavaScript engine's test suite.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Purpose:** The file `v8/test/cctest/test-api.cc` suggests it's testing the C++ API of V8. The `test` directory further reinforces that this is for testing.

2. **Scan for Key V8 API Elements:** Look for common V8 API classes and methods being used. Keywords like `Isolate`, `Context`, `HandleScope`, `Local`, `Value`, `ObjectTemplate`, `FunctionTemplate`, `Array`, `Function`, `TryCatch`, `MessageListener` are strong indicators.

3. **Categorize Test Scenarios:**  Group the individual `THREADED_TEST` and `TEST` blocks by their apparent function. This involves reading the test names and the code within each block. Common patterns emerge:
    * **Array Creation:** Tests involving `v8::Array::New`.
    * **Function Calls:** Tests using `Function->Call` and `Function->NewInstance`.
    * **Type Conversions:** Tests involving `ToNumber`, `ToInt32`, `ToUint32`, `ToString`.
    * **Exception Handling:** Tests using `TryCatch`, `ThrowException`, and custom error handling.
    * **Message Handling:** Tests involving `AddMessageListener`.

4. **Illustrate with JavaScript (if applicable):** For tests that clearly relate to JavaScript features, provide corresponding JavaScript code snippets. For example, the array creation tests directly map to JavaScript array literals and the `new Array()` constructor. Function calls in C++ mirror JavaScript function invocation.

5. **Demonstrate Code Logic with Examples:** For tests that involve specific input and output behavior, create simple example scenarios. For array creation, show how providing a size or initial values results in a specific array. For function calls, demonstrate passing arguments and receiving return values.

6. **Highlight Common Programming Errors:** Identify test cases that simulate or check for conditions that could lead to common errors in JavaScript or when using the V8 API. Type conversion issues (e.g., implicit conversions), exception handling (or lack thereof), and incorrect function calls are good candidates.

7. **Address Specific Instructions:**
    * **`.tq` check:** Explicitly state that this file is `.cc` and not `.tq`.
    * **Part Number:** Acknowledge that this is part 7 of 36.

8. **Synthesize the Summary:**  Combine the categorized functionalities into a concise overview. Emphasize that the code tests the V8 C++ API by interacting with JavaScript constructs.

9. **Refine and Organize:**  Structure the answer logically with clear headings for each functionality. Use bullet points for better readability. Ensure the JavaScript examples and code logic examples are easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Just list the tests. **Correction:** Grouping by functionality provides a much better understanding.
* **Initial thought:** Simply state that array creation is tested. **Correction:** Show concrete examples of different `New` methods and their JavaScript equivalents.
* **Initial thought:** Focus only on the successful execution paths. **Correction:** Include exception handling and error scenarios as they are significant parts of the testing.
* **Initial thought:**  Assume the user has deep V8 knowledge. **Correction:** Provide explanations and simple examples that are accessible to someone with a general understanding of JavaScript and C++.
`v8/test/cctest/test-api.cc` 是一个 V8 源代码文件，它不是以 `.tq` 结尾，因此它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。

这个文件的主要功能是 **测试 V8 JavaScript 引擎的 C++ API 的各种功能**。它通过编写 C++ 代码来调用 V8 的 C++ API，并断言（`CHECK_EQ`, `CHECK`, `CHECK(!...)`) 返回的结果是否符合预期，以此来验证 API 的正确性。

以下是该代码片段中列举的功能归纳：

**1. 异常处理 (Exception Handling):**

* **测试捕获 JavaScript 异常:** `ExpectException` 函数验证了当执行一段 JavaScript 代码抛出异常时，C++ 代码能够捕获到该异常，并且异常的值是预期的。
    * **JavaScript 示例:**
      ```javascript
      throw "exception";
      ```
    * **代码逻辑推理:** 假设执行的 JavaScript 代码是 `throw "exception";`，那么 `exception_value` 应该指向字符串 "exception"，并且 V8 引擎会标记有一个未处理的异常。`try_catch.Reset()` 后，异常状态应该被清除。
    * **常见编程错误:**  忘记在 C++ 中使用 `v8::TryCatch` 来捕获 JavaScript 异常，会导致程序崩溃或行为异常。

**2. 数组操作 (Array Operations):**

* **测试创建新数组的各种方式:** `Array_New_Basic`, `Array_New_FromVector`, `Array_New_FromCallback_Success`, `Array_New_FromCallback_Exception` 等测试了使用 `v8::Array::New` 创建数组的不同方法，包括：
    * 创建空数组。
    * 创建指定长度的数组。
    * 使用 `std::vector` 中的元素创建数组。
    * 使用回调函数动态创建数组元素。
* **测试数组的基本属性和方法:**  例如，检查数组的长度 (`Length()`)，访问元素 (`Get()`)，判断是否存在指定索引的元素 (`Has()`)，设置元素 (`Set()`)。
    * **JavaScript 示例:**
      ```javascript
      const arr1 = [];
      const arr2 = new Array(5);
      const arr3 = [1, 2, 3];
      arr1[2] = 7;
      console.log(arr1.length); // 输出 3
      console.log(arr3[1]);    // 输出 2
      console.log(2 in arr3);   // 输出 true
      ```
    * **代码逻辑推理:** `ExpectArrayValues` 函数用于比较 C++ 创建的 V8 数组和期望的整数值序列是否一致。例如，如果使用 `v8::Array::New(context->GetIsolate(), numbers.data(), numbers.size())` 创建数组，其中 `numbers` 是包含 `{v8_num(1), v8_num(2), v8_num(3)}` 的 vector，那么 `ExpectArrayValues` 应该验证数组的元素分别是 1, 2, 3。
    * **常见编程错误:**  在 C++ 中操作 V8 数组时，忘记使用 `ToLocalChecked()` 来获取 `MaybeLocal` 的值，或者忘记在操作 V8 对象时使用正确的 `v8::Context`。

**3. 函数调用 (Function Calls):**

* **测试调用 JavaScript 函数:** `Vector`, `FunctionCall` 测试了使用 C++ 代码调用 JavaScript 函数的不同方式，包括传递不同数量的参数，以及 `this` 绑定的行为。
    * **JavaScript 示例:**
      ```javascript
      function f(a, b) {
        return [a, b];
      }
      f(1, 2); // 调用函数 f，传入参数 1 和 2
      ```
    * **代码逻辑推理:** `HandleF` 函数是一个 C++ 函数，它作为 JavaScript 函数 `f` 的实现。当在 JavaScript 中调用 `f(11, 12)` 时，`HandleF` 会被执行，并创建一个包含参数的 V8 数组返回。测试代码会断言返回数组的长度和元素值是否正确。
    * **常见编程错误:**  在 C++ 中调用 JavaScript 函数时，参数的类型和数量不匹配，或者 `v8::Context` 不正确。

**4. 构造函数调用 (Constructor Calls):**

* **测试调用 JavaScript 构造函数:** `ConstructCall` 测试了使用 C++ 代码通过 `NewInstance` 方法调用 JavaScript 构造函数创建对象。
    * **JavaScript 示例:**
      ```javascript
      function Foo(a, b) {
        this.data = [a, b];
      }
      const obj = new Foo(1, 2);
      ```
    * **代码逻辑推理:**  `ConstructCall` 测试了使用 `Foo->NewInstance` 创建 `Foo` 的实例，并验证了实例的属性（在这个例子中，是返回的数组的长度和元素）。
    * **常见编程错误:**  类似于函数调用，构造函数调用的参数类型和数量也需要匹配。

**5. 类型转换 (Type Conversions):**

* **测试 JavaScript 值到 C++ 数值的转换:** `ConversionNumber` 测试了将 JavaScript 数值转换为 C++ 的 `int32_t`, `uint32_t`, `double` 等类型的行为，包括大数、小数和负数。
    * **JavaScript 示例:**
      ```javascript
      const num = 42.3;
      ```
    * **代码逻辑推理:**  测试代码会执行 JavaScript 代码定义一个数值变量，然后使用 V8 API 的 `ToNumber`, `ToInt32`, `ToUint32` 等方法将其转换为 C++ 的数值类型，并断言转换后的值是否符合预期。
    * **常见编程错误:**  没有理解 JavaScript 的动态类型和 C++ 的静态类型之间的差异，导致类型转换时出现意想不到的结果。例如，将一个 JavaScript 浮点数强制转换为 C++ 的 `int` 会丢失精度。
* **测试 JavaScript 值的类型判断:** `isNumberType` 测试了使用 `IsInt32()`, `IsUint32()` 等方法判断 JavaScript 值的类型。
* **测试将 JavaScript 值转换为 Integer 对象:** `IntegerType` 测试了将 JavaScript 值转换为 `v8::Integer` 对象的行为。
* **测试类型转换过程中抛出异常的情况:** `ConversionException` 测试了当 JavaScript 对象的 `toString` 等方法抛出异常时，C++ 的类型转换 API 如何处理。
    * **JavaScript 示例:**
      ```javascript
      const obj = {
        toString: function() {
          throw "uncle?";
        }
      };
      String(obj); // 会抛出异常
      ```
    * **代码逻辑推理:** 当调用 `obj->ToString(env.local())` 时，由于 JavaScript 的 `toString` 方法抛出了异常，`ToString` 方法会返回一个空的 `MaybeLocal<v8::String>`。测试代码使用 `IsEmpty()` 来判断是否发生了异常，并使用 `TryCatch` 来捕获和检查异常信息。

**6. C++ 抛出异常并被 JavaScript 捕获 (Throwing Exceptions from C++):**

* **测试 C++ 代码抛出的异常可以在 JavaScript 中被捕获:** `APICatch`, `APIThrowTryCatch` 测试了使用 `args.GetIsolate()->ThrowException()` 从 C++ 代码中抛出异常，然后在 JavaScript 的 `try...catch` 块中捕获。
    * **JavaScript 示例:**
      ```javascript
      try {
        ThrowFromC(); // 调用一个会抛出异常的 C++ 函数
      } catch (e) {
        // 处理异常
      }
      ```
    * **代码逻辑推理:** `ThrowFromC` 函数会抛出一个 JavaScript 异常。测试代码先在 JavaScript 中定义了一个 `try...catch` 块，然后调用 `ThrowFromC`。如果异常被成功捕获，则 `thrown` 变量会被设置为 `true`。

**7. 自定义错误类型 (Custom Error Types):**

* **测试自定义错误对象的 `toString` 和 `message` 属性:** `CustomErrorToString`, `CustomErrorMessage` 测试了自定义 JavaScript 错误对象的行为，特别是其 `toString` 和 `message` 属性在被抛出和捕获时的表现。
    * **JavaScript 示例:**
      ```javascript
      function MyError(message) {
        this.name = 'MyError';
        this.message = message;
      }
      MyError.prototype = Object.create(Error.prototype);
      MyError.prototype.toString = function() {
        return 'MyError toString';
      };
      throw new MyError('my message');
      ```
    * **代码逻辑推理:** 测试代码定义了 `MyError` 构造函数，并重写了 `toString` 方法。然后抛出 `MyError` 的实例。通过注册消息监听器，测试代码可以检查 V8 报告的错误消息是否符合自定义的 `toString` 或默认的 `message` 格式。

**8. 消息处理 (Message Handling):**

* **测试消息监听器在异常发生时的行为:** `APIThrowMessage`, `APIThrowMessageAndVerboseTryCatch`, `APIStackOverflowAndVerboseTryCatch`, `CustomErrorRethrowsOnToString`, `CustomErrorRethrowsOnToStringInsideVerboseTryCatch` 测试了当 JavaScript 代码抛出异常时，通过 `Isolate::AddMessageListener` 注册的消息监听器是否会被调用，以及接收到的消息内容。
    * **JavaScript 示例:**  这些测试通常涉及到抛出异常的情况，例如调用会抛出异常的 C++ 函数或 JavaScript 代码本身抛出异常。
    * **代码逻辑推理:** 测试代码注册了一个消息监听器 `receive_message`，当 JavaScript 代码抛出异常时，这个监听器会被调用，并将 `message_received` 标志设置为 `true`。某些测试还涉及到 `v8::TryCatch` 的 verbose 模式对消息处理的影响。

**9. 外部脚本异常 (External Script Exception):**

* **测试在执行外部脚本时抛出的异常:** `ExternalScriptException` 测试了当 C++ 代码执行一段 JavaScript 代码，而该代码又调用了一个会抛出异常的 C++ 函数时，异常是如何被处理的。

**10. 回调函数中的异常处理 (Exception Handling in Callbacks):**

* **测试 C++ 回调函数抛出的异常如何被 JavaScript 代码处理:** `CThrowCountDown` (虽然代码片段不完整) 的命名暗示了它可能测试了 C++ 回调函数抛出异常的情况。

**总结:**

这段代码是 V8 引擎测试套件的一部分，专注于测试 V8 C++ API 的各种功能，特别是与 JavaScript 对象的创建、操作、函数调用、类型转换以及异常处理相关的 API。它通过编写 C++ 测试用例，模拟各种 JavaScript 场景，并使用断言来验证 V8 API 的行为是否符合预期，从而确保 V8 引擎的稳定性和正确性。 这些测试覆盖了 V8 API 的常见用法和边界情况，帮助开发者在使用 V8 C++ API 时避免常见的编程错误。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  int cInterval = args[2]->Int32Value(
```