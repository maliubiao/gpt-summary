Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`. I need to analyze the code and explain its purpose.

Here's a breakdown of how to approach this:

1. **Identify the main components:** Look for test functions (using `THREADED_TEST` or `TEST`), helper functions, and V8 API calls.
2. **Analyze each test function:** Determine what each test is verifying. This often involves setting up a V8 environment, running JavaScript code, and then asserting certain conditions.
3. **Analyze helper functions:** Understand the purpose of functions like `CThrowCountDown`, `JSCheck`, `ThrowValue`, `WithTryCatch`, `TryCatchMixedNestingHelper`, `TryCatchNativeHelper`, `TryCatchNativeResetHelper`, `GetXValue`, `SetXValue`, and `GetGlobalProperty`.
4. **Relate to JavaScript functionality:**  If the C++ code interacts with JavaScript (by running scripts or defining native functions), illustrate the corresponding JavaScript behavior with examples.
5. **Look for code logic and edge cases:** Identify any non-trivial logic within the C++ or JavaScript code and consider potential input/output scenarios. Pay attention to error handling and exception scenarios.
6. **Identify common programming errors:**  See if the tests target situations that often lead to mistakes in JavaScript or when using the V8 API.
7. **Consider the file name and location:**  The file name `test-api.cc` and its location in the `v8/test/cctest` directory suggest that this file contains tests for the V8 C++ API.
8. **Synthesize the findings:** Combine the analysis of individual parts to form a concise summary of the code's overall functionality.这是一个V8源代码文件 `v8/test/cctest/test-api.cc` 的一部分，它包含了一系列用于测试 V8 C++ API 功能的单元测试。这些测试覆盖了异常处理、属性访问、类型检查等多个方面。

**功能归纳:**

这个代码片段主要测试了 V8 C++ API 中与以下功能相关的特性：

* **异常处理 (`v8::TryCatch`, `isolate->ThrowException`)**:  测试了如何在 C++ 代码中捕获和处理 JavaScript 抛出的异常，以及如何在 C++ 中抛出异常并在 JavaScript 中捕获。
* **函数回调 (`v8::FunctionCallbackInfo`)**: 测试了 C++ 函数如何作为 JavaScript 函数的回调被调用，以及如何在回调函数中访问和操作 JavaScript 的值。
* **属性访问 (`v8::ObjectTemplate::Set`, `v8::Object::Get`, `v8::Object::Set`, `v8::Object::SetNativeDataProperty`)**:  测试了如何通过 C++ API 定义和访问 JavaScript 对象的属性，包括使用原生数据属性（native data properties）的情况。
* **类型检查 (`value->IsString()`, `value->IsNumber()`, `value->IsNull()`, `value->IsUndefined()`, `value->BooleanValue()`, `value->Int32Value()`, `value->Equals()`, `value->StrictEquals()`, `value->SameValue()`, `value->TypeOf()`, `value->InstanceOf()`)**:  测试了 V8 API 提供的各种类型检查方法。
* **脚本编译和运行 (`v8::Script::Compile`, `v8::Script::Run`)**: 测试了如何在 C++ 中编译和执行 JavaScript 代码。
* **对象模板 (`v8::ObjectTemplate`)**:  测试了如何使用对象模板创建 JavaScript 对象并定义其属性。

**关于文件扩展名 `.tq`:**

如果 `v8/test/cctest/test-api.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。Torque 是一种用于定义 V8 内部函数和内置对象的领域特定语言。  **但根据提供的文件路径和扩展名 `.cc`，这个文件是 C++ 源代码，而不是 Torque 源代码。**

**与 JavaScript 功能的关系及示例:**

这些 C++ 测试代码直接测试了 V8 引擎提供的 JavaScript 功能。以下是一些与代码片段相关的 JavaScript 功能示例：

1. **异常处理 (`try...catch`, `throw`)**:

   ```javascript
   function jsThrow() {
     throw "Error from JavaScript";
   }

   try {
     jsThrow();
   } catch (e) {
     console.log("Caught:", e); // 输出: Caught: Error from JavaScript
   }
   ```

   C++ 代码中的 `THREADED_TEST(ExceptionOrder)` 和 `THREADED_TEST(ThrowValues)` 就是测试 C++ 和 JavaScript 之间异常传递和捕获的机制。

2. **函数回调**:

   ```javascript
   // 假设 C++ 中定义了一个名为 'nativeFunction' 的函数，
   // 并且在 C++ 中通过模板将其暴露给 JavaScript

   function jsFunction(callback) {
     callback("Hello from JavaScript");
   }

   // 当在 C++ 中调用 jsFunction 并传入一个 C++ 函数作为回调时，
   // C++ 函数会接收到 "Hello from JavaScript" 这个字符串。
   ```

   C++ 代码中的 `CThrowCountDown` 函数就是一个可以通过 JavaScript 调用的 C++ 函数。

3. **属性访问**:

   ```javascript
   const obj = { x: 10 };
   console.log(obj.x); // 输出: 10
   obj.y = 20;
   console.log(obj.y); // 输出: 20
   ```

   C++ 代码中的 `THREADED_TEST(SimplePropertyRead)` 和相关的 `GetXValue` 函数测试了如何通过 C++ API 读取 JavaScript 对象的属性。`THREADED_TEST(SimplePropertyWrite)` 和 `SetXValue` 测试了属性写入。

4. **类型检查**:

   ```javascript
   console.log(typeof undefined); // 输出: undefined
   console.log(typeof null);      // 输出: object
   console.log(typeof "hello");    // 输出: string
   console.log(typeof 123);      // 输出: number
   console.log(typeof {});       // 输出: object
   console.log(typeof true);      // 输出: boolean
   console.log(typeof function() {}); // 输出: function

   console.log(null instanceof Object); // 输出: false (注意：这是一个特例)
   console.log({} instanceof Object);   // 输出: true
   ```

   C++ 代码中的 `THREADED_TEST(TypeOf)` 和 `THREADED_TEST(InstanceOf)` 测试了 V8 API 提供的与 JavaScript `typeof` 和 `instanceof` 操作符等价的功能。

**代码逻辑推理及假设输入与输出:**

让我们以 `CThrowCountDown` 函数为例进行逻辑推理：

**假设输入:**

* `args[0]` (count): 一个整数，表示剩余的调用次数。
* `args[1]` (jsInterval): 一个整数，表示 JavaScript 异常处理器的触发间隔。
* `args[2]` (cInterval): 一个整数，表示 C++ 异常处理器的触发间隔。
* `args[3]` (expected): 一个整数，表示期望捕获异常时的 `count` 值。

**代码逻辑:**

* 如果 `count` 为 0，则在 C++ 中抛出一个异常 "FromC"。
* 否则，调用 JavaScript 函数 `JSThrowCountDown`，并传递 `count - 1` 作为新的 `count` 值。
* 如果 `count` 是 `cInterval` 的倍数，则在 C++ 中使用 `v8::TryCatch` 包裹对 `JSThrowCountDown` 的调用。
    * 如果 JavaScript 抛出了异常，则检查期望值 `expected` 是否等于当前的 `count`，并返回一个空值。
    * 如果 JavaScript 没有抛出异常，则检查期望值 `expected` 是否不等于当前的 `count`，并返回 JavaScript 函数的返回值。
* 否则，直接调用 `JSThrowCountDown`，并检查 JavaScript 代码是否按预期抛出或未抛出异常。

**假设输入与输出示例:**

假设我们从 JavaScript 调用 `CThrowCountDown(3, 2, 3, 2)`：

1. **C++ 调用:** `CThrowCountDown` 被调用，`count` 是 3，`jsInterval` 是 2，`cInterval` 是 3，`expected` 是 2。
2. **调用 JavaScript:** 因为 `count` (3) 是 `cInterval` (3) 的倍数，所以 C++ 会使用 `TryCatch` 调用 `JSThrowCountDown(2, 2, 3, 2)`。
3. **JavaScript 调用:** `JSThrowCountDown` 被调用，`count` 是 2。因为 `count` (2) 是 `jsInterval` (2) 的倍数，JavaScript 会尝试调用 `CThrowCountDown(1, 2, 3, 2)` 并用 `try...catch` 包裹。
4. **C++ 调用:** `CThrowCountDown` 被调用，`count` 是 1。
5. **调用 JavaScript:** `JSThrowCountDown(0, 2, 3, 2)` 被调用。
6. **JavaScript 抛出异常:** `JSThrowCountDown` 中 `count` 为 0，抛出 "FromJS" 异常。
7. **C++ 捕获异常:** JavaScript 抛出的异常被第三步中的 JavaScript 的 `try...catch` 捕获。`check(true, 2, 2)` 会被执行，因为期望 `count` 是 2，当前的 `count` 也是 2。
8. **C++ 返回:**  由于第三步的 JavaScript `try...catch` 捕获了异常，`CThrowCountDown` 在第二步的调用中不会捕获到异常，并且会返回 JavaScript 函数的返回值（在本例中，由于异常被捕获，可能返回 `undefined` 或其他值）。

**用户常见的编程错误举例:**

1. **忘记处理异常:** 在 C++ 调用 JavaScript 代码时，如果没有使用 `v8::TryCatch` 包裹，JavaScript 中抛出的异常会导致程序崩溃。`THREADED_TEST(EvalInTryFinally)` 测试了 `eval` 抛出异常的情况。
2. **类型不匹配:**  在 C++ 和 JavaScript 之间传递数据时，如果类型不匹配，可能会导致错误。例如，尝试将一个 JavaScript 字符串作为 C++ 的整数使用。V8 的类型检查方法 (`IsString`, `IsNumber` 等) 可以帮助避免这类错误.
3. **错误地理解 `TryCatch` 的作用域:**  `v8::TryCatch` 只捕获其作用域内的异常。如果异常在 `TryCatch` 作用域之外抛出，将不会被捕获。`THREADED_TEST(TryCatchAndFinally)` 演示了在 `finally` 块中调用 native 函数并捕获异常的情况。
4. **混淆 `Equals`, `StrictEquals`, 和 `SameValue`:**  这些方法在比较 JavaScript 值时有细微的区别，错误地使用可能会导致意想不到的结果。`THREADED_TEST(Equality)` 详细测试了这些方法的不同行为。

**总结第8部分的功能:**

这个代码片段是 V8 单元测试套件的一部分，专门测试了 V8 C++ API 中关于 **异常处理、C++ 与 JavaScript 函数调用交互、属性访问和定义、以及类型检查** 的功能。它通过构造不同的场景，包括 C++ 和 JavaScript 之间的相互调用和异常传递，来验证 API 的正确性和健壮性。 这些测试有助于确保 V8 引擎在处理异常、调用原生函数、访问属性和进行类型判断时的行为符合预期。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共36部分，请归纳一下它的功能

"""
context).FromJust();
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