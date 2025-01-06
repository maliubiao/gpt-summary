Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-api.cc`.

Here's a breakdown of the code's functionality, addressing the user's requirements:

1. **General Functionality**: The code tests various V8 C++ API functionalities related to code generation from strings, callbacks, microtasks, and object properties.

2. **`.tq` check**:  The filename doesn't end with `.tq`, so it's not Torque code.

3. **JavaScript Relationship**:  The code heavily relies on evaluating JavaScript code using `CompileRun` and interacting with JavaScript concepts like `eval`, `Function`, `this`, and microtasks. I need to provide JavaScript examples.

4. **Code Logic Inference**:  The tests often set up conditions and then use `CHECK` macros to verify expected outcomes. I'll demonstrate this with an example of modifying code generation.

5. **Common Programming Errors**:  The tests involving `TryCatch` and error handling point towards common errors in dynamic code execution.

6. **Part of a Larger Set**: This is part 23 of 36, suggesting it covers a specific subset of V8 API testing.

**Mental Sandbox Simulation**:

* I'll go through each `TEST` block and identify its core purpose.
* For code generation tests, I'll illustrate the behavior with JavaScript `eval` and `Function` calls.
* For callback and microtask tests, I'll demonstrate the sequencing and behavior using simple JavaScript snippets.
* I need to carefully extract assumptions and outputs for the code logic example.
* I'll consider common errors when using `eval` and `Function` in JavaScript.
* Finally, I'll synthesize a summary based on these individual test functionalities.

**Constraint Checklist & Confidence Score**:

1. List functionality? Yes.
2. `.tq` check? Yes.
3. JavaScript relationship and examples? Yes.
4. Code logic and examples? Yes.
5. Common programming errors? Yes.
6. Summarize functionality as part 23/36? Yes.

Confidence Score: 5/5

Strategizing complete. I will now generate the response by summarizing the functionality of each test case and providing relevant JavaScript examples.
这是一个V8源代码文件，位于 `v8/test/cctest/test-api.cc`，因此它是一个 **V8 C++ 测试文件**，用于测试 V8 JavaScript 引擎的 C++ API 的各种功能。

**功能列表:**

这个文件主要测试了以下 V8 API 的功能：

1. **控制从字符串生成代码的能力 (Code Generation from Strings):**
   - 测试允许或禁止从字符串动态生成代码（如 `eval()` 和 `Function()` 构造函数）。
   - 测试修改代码生成行为的回调函数 (`SetModifyCodeGenerationFromStringsCallback`).
   - 测试在禁止代码生成时设置自定义错误消息。
   - 测试捕获用于代码生成的源代码。

2. **在非对象上调用 API 函数 (Call API Function on Non-Object):**
   - 测试当在非对象（例如原始值）上调用函数时，V8 的行为。

3. **只读索引属性 (Read-Only Indexed Properties):**
   - 测试定义对象的索引属性为只读时的行为，确保不能通过 `Set` 方法修改。

4. **Map 缓存 (Map Cache):**
   - 测试 V8 的内部 Map 缓存机制，以及垃圾回收如何影响缓存中的 Map 对象。

5. **跨上下文调用函数 (Foreign Function Receiver):**
   - 测试在一个上下文中创建的函数在另一个上下文中被调用时，`this` 关键字的绑定行为。

6. **调用完成回调 (Call Completed Callback):**
   - 测试在 JavaScript 代码执行完成后执行的回调函数机制。
   - 测试添加和移除这些回调函数。
   - 测试在回调函数执行期间发生异常的情况。

7. **微任务 (Microtasks):**
   - 测试微任务的入队和执行机制。
   - 测试在微任务执行期间抛出异常的处理方式。
   - 测试显式和自动运行微任务策略。
   - 测试在没有进入上下文的情况下运行微任务。
   - 测试作用域微任务（Scoped Microtasks）。

**关于文件后缀和 Torque:**

`v8/test/cctest/test-api.cc` 的后缀是 `.cc`，所以它是一个 **C++** 源文件，而不是 Torque 源文件。如果文件以 `.tq` 结尾，那它才是 V8 Torque 源代码。

**与 JavaScript 功能的关系及示例:**

这个 C++ 测试文件直接测试了与 JavaScript 密切相关的功能。以下是一些与代码功能对应的 JavaScript 示例：

1. **控制从字符串生成代码的能力:**

   ```javascript
   // 允许代码生成
   eval('1 + 1'); // 结果为 2
   new Function('return 1 + 1')(); // 结果为 2

   // 禁止代码生成 (假设在 C++ 中已设置禁止回调)
   try {
     eval('1 + 1'); // 抛出 EvalError 或类似错误
   } catch (e) {
     console.error(e);
   }

   try {
     new Function('return 1 + 1')(); // 抛出 TypeError 或类似错误
   } catch (e) {
     console.error(e);
   }
   ```

2. **在非对象上调用 API 函数:**

   ```javascript
   function myFunction() {
     return this;
   }

   myFunction.call(2); // this 的值为 2 (会被包装成 Number 对象)
   ```

3. **只读索引属性:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 1, { value: 'initial', writable: false });
   obj[1] = 'attempted change'; // 严格模式下会抛出 TypeError，非严格模式下修改无效
   console.log(obj[1]); // 输出 "initial"
   ```

4. **微任务:**

   ```javascript
   console.log('开始');

   Promise.resolve().then(() => {
     console.log('Promise 微任务执行');
   });

   queueMicrotask(() => {
     console.log('queueMicrotask 微任务执行');
   });

   console.log('结束');
   // 输出顺序可能为：
   // 开始
   // 结束
   // Promise 微任务执行
   // queueMicrotask 微任务执行
   ```

**代码逻辑推理 (假设输入与输出):**

考虑 `TEST(ModifyCodeGenFromStrings)` 这个测试。

**假设输入:**

- V8 引擎初始化完成。
- `ModifyCodeGeneration` 回调函数被设置为将字符串形式的代码中的数字加 1。

**代码逻辑:**

1. 执行 `eval('42')`。由于设置了 `ModifyCodeGeneration` 回调，字符串 `'42'` 会被处理，数字 `42` 加 1 变成 `43`，然后被求值。
2. 执行 `(function(e) { return e('42'); })(eval)`。间接 `eval` 也会触发回调。
3. 执行 `var f = new Function('return 42;'); f()`。`Function` 构造函数也会触发回调。
4. 执行 `eval(43)`。这里传入的是数字，回调逻辑可能允许通过。
5. 执行 `var f = new Function('return 44;'); f();`。同上。
6. 执行 `eval('123')`，但此时 `ModifyCodeGeneration` 可能在某些情况下返回禁止执行，导致 `TryCatch` 捕获异常。
7. 执行 `new Function('a', 'return 42;')(123)`，同样可能因为 `ModifyCodeGeneration` 返回禁止执行而被捕获。

**预期输出:**

- 前五个 `CompileRun` 的结果的整数值都比字符串中表示的数字大 1 (例如，`eval('42')` 返回 `43`)。
- 后两个 `CompileRun` 会导致 `try_catch.HasCaught()` 为 `true`，表明代码执行过程中发生了异常。

**用户常见的编程错误:**

1. **滥用 `eval()`:**  用户可能会不小心使用 `eval()` 执行不受信任的字符串，导致安全漏洞或意外行为。V8 的这些测试确保了可以控制 `eval()` 的行为，例如禁止执行。

   ```javascript
   let userInput = "alert('小心！')";
   // 如果没有适当的检查，这可能执行恶意代码
   // eval(userInput);
   ```

2. **不理解 `Function()` 构造函数的风险:** 类似于 `eval()`，使用 `Function()` 构造函数动态创建函数也存在安全风险。

   ```javascript
   let userFunctionCode = "return userSuppliedValue;";
   // 同样存在风险
   // new Function('userSuppliedValue', userFunctionCode)(someValue);
   ```

3. **在跨上下文操作中对 `this` 的误解:**  当在不同的 V8 上下文中传递和调用函数时，`this` 的绑定可能会出乎意料，导致错误。

   ```javascript
   // 假设 contextA 和 contextB 是不同的 V8 上下文
   // 在 contextA 中创建的函数
   const funcA = function() { console.log(this); };

   // 尝试在 contextB 中调用 funcA，'this' 可能不是预期的对象
   // （具体的行为取决于 V8 的实现和调用方式）
   ```

4. **不正确地处理微任务:** 用户可能没有意识到微任务的执行时机，导致代码执行顺序的困惑。例如，期望在同步代码之后立即执行某些操作，但这些操作被放入了微任务队列。

   ```javascript
   console.log('同步操作');
   Promise.resolve().then(() => console.log('微任务'));
   console.log('更多同步操作');
   // 用户可能错误地认为 "微任务" 会在 "更多同步操作" 之前输出
   ```

**归纳功能 (作为第 23 部分 / 共 36 部分):**

作为测试套件的第 23 部分，这个文件主要集中在 **V8 C++ API 中与代码动态生成、跨上下文调用以及异步操作（通过微任务）相关的核心功能测试**。它验证了 V8 提供的用于控制代码执行环境、处理不同执行上下文以及管理异步任务的机制的正确性和健壮性。这部分测试对于确保 V8 引擎的安全性和可靠性至关重要，特别是涉及到动态代码执行和复杂的 JavaScript 特性时。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第23部分，共36部分，请归纳一下它的功能

"""
wed);
  CHECK(!context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationAllowed();

  // Set a callback that disallows the code generation.
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &CodeGenerationDisallowed);
  CHECK(!context->IsCodeGenerationFromStringsAllowed());
  CheckCodeGenerationDisallowed();
}

TEST(ModifyCodeGenFromStrings) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->AllowCodeGenerationFromStrings(false);
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &ModifyCodeGeneration);

  // Test 'allowed' case in different modes (direct eval, indirect eval,
  // Function constructor, Function constructor with arguments).
  Local<Value> result = CompileRun("eval('42')");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());

  result = CompileRun("(function(e) { return e('42'); })(eval)");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());

  result = CompileRun("var f = new Function('return 42;'); f()");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());

  result = CompileRun("eval(43)");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());

  result = CompileRun("var f = new Function('return 44;'); f();");
  CHECK_EQ(44, result->Int32Value(context.local()).FromJust());

  // Test 'disallowed' cases.
  TryCatch try_catch(CcTest::isolate());
  result = CompileRun("eval('123')");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("new Function('a', 'return 42;')(123)");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();
}

v8::ModifyCodeGenerationFromStringsResult RejectStringsIncrementNumbers(
    Local<Context> context, Local<Value> source, bool is_code_like) {
  if (source->IsString()) {
    return {false, v8::MaybeLocal<String>()};
  }

  Local<v8::Number> number;
  if (!source->ToNumber(context).ToLocal(&number)) {
    return {true, v8::MaybeLocal<String>()};
  }

  Local<v8::String> incremented =
      String::NewFromUtf8(context->GetIsolate(),
                          std::to_string(number->Value() + 1).c_str(),
                          v8::NewStringType::kNormal)
          .ToLocalChecked();

  return {true, incremented};
}

TEST(AllowFromStringsOrModifyCodegen) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &RejectStringsIncrementNumbers);

  context->AllowCodeGenerationFromStrings(false);

  TryCatch try_catch(CcTest::isolate());
  Local<Value> result = CompileRun("eval('40+2')");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  try_catch.Reset();

  result = CompileRun("eval(42)");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());

  context->AllowCodeGenerationFromStrings(true);

  result = CompileRun("eval('40+2')");
  CHECK_EQ(42, result->Int32Value(context.local()).FromJust());

  result = CompileRun("eval(42)");
  CHECK_EQ(43, result->Int32Value(context.local()).FromJust());
}

TEST(SetErrorMessageForCodeGenFromStrings) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  TryCatch try_catch(context->GetIsolate());

  Local<String> message = v8_str("Message");
  Local<String> expected_message = v8_str("Uncaught EvalError: Message");
  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &CodeGenerationDisallowed);
  context->AllowCodeGenerationFromStrings(false);
  context->SetErrorMessageForCodeGenerationFromStrings(message);
  Local<Value> result = CompileRun("eval('42')");
  CHECK(result.IsEmpty());
  CHECK(try_catch.HasCaught());
  Local<String> actual_message = try_catch.Message()->Get();
  CHECK(expected_message->Equals(context.local(), actual_message).FromJust());
}

TEST(CaptureSourceForCodeGenFromStrings) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  TryCatch try_catch(context->GetIsolate());

  context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(
      &CodeGenerationAllowed);
  context->AllowCodeGenerationFromStrings(false);
  CompileRun("eval('42')");
  CHECK(!strcmp(first_fourty_bytes, "42"));
}

static void NonObjectThis(const v8::FunctionCallbackInfo<v8::Value>& args) {
}


THREADED_TEST(CallAPIFunctionOnNonObject) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> templ =
      v8::FunctionTemplate::New(isolate, NonObjectThis);
  Local<Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"), function)
            .FromJust());
  TryCatch try_catch(isolate);
  CompileRun("f.call(2)");
}


// Regression test for issue 1470.
THREADED_TEST(ReadOnlyIndexedProperties) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);

  LocalContext context;
  Local<v8::Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  CHECK(context->Global()->Set(context.local(), v8_str("obj"), obj).FromJust());
  obj->DefineOwnProperty(context.local(), v8_str("1"), v8_str("DONT_CHANGE"),
                         v8::ReadOnly)
      .FromJust();
  obj->Set(context.local(), v8_str("1"), v8_str("foobar")).FromJust();
  CHECK(v8_str("DONT_CHANGE")
            ->Equals(context.local(),
                     obj->Get(context.local(), v8_str("1")).ToLocalChecked())
            .FromJust());
  obj->DefineOwnProperty(context.local(), v8_str("2"), v8_str("DONT_CHANGE"),
                         v8::ReadOnly)
      .FromJust();
  obj->Set(context.local(), v8_num(2), v8_str("foobar")).FromJust();
  CHECK(v8_str("DONT_CHANGE")
            ->Equals(context.local(),
                     obj->Get(context.local(), v8_num(2)).ToLocalChecked())
            .FromJust());

  // Test non-smi case.
  obj->DefineOwnProperty(context.local(), v8_str("2000000000"),
                         v8_str("DONT_CHANGE"), v8::ReadOnly)
      .FromJust();
  obj->Set(context.local(), v8_str("2000000000"), v8_str("foobar")).FromJust();
  CHECK(v8_str("DONT_CHANGE")
            ->Equals(context.local(),
                     obj->Get(context.local(), v8_str("2000000000"))
                         .ToLocalChecked())
            .FromJust());
}

static int CountLiveMapsInMapCache(i::Tagged<i::Context> context) {
  i::Tagged<i::WeakFixedArray> map_cache =
      i::Cast<i::WeakFixedArray>(context->map_cache());
  int length = map_cache->length();
  int count = 0;
  for (int i = 0; i < length; i++) {
    if (map_cache->get(i).IsWeak()) count++;
  }
  return count;
}

TEST(Regress1516) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Object with 20 properties is not a common case, so it should be removed
  // from the cache after GC.
  { v8::HandleScope temp_scope(context->GetIsolate());
    CompileRun(
        "({"
        "'a00': 0, 'a01': 0, 'a02': 0, 'a03': 0, 'a04': 0, "
        "'a05': 0, 'a06': 0, 'a07': 0, 'a08': 0, 'a09': 0, "
        "'a10': 0, 'a11': 0, 'a12': 0, 'a13': 0, 'a14': 0, "
        "'a15': 0, 'a16': 0, 'a17': 0, 'a18': 0, 'a19': 0, "
        "})");
  }

  int elements = CountLiveMapsInMapCache(CcTest::i_isolate()->context());
  CHECK_LE(1, elements);

  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    // We have to abort incremental marking here to abandon black pages.
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
  }

  CHECK_GT(elements, CountLiveMapsInMapCache(CcTest::i_isolate()->context()));
}

static void TestReceiver(Local<Value> expected_result,
                         Local<Value> expected_receiver,
                         const char* code) {
  Local<Value> result = CompileRun(code);
  Local<Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK(result->IsObject());
  CHECK(expected_receiver
            ->Equals(context,
                     result.As<v8::Object>()->Get(context, 1).ToLocalChecked())
            .FromJust());
  CHECK(expected_result
            ->Equals(context,
                     result.As<v8::Object>()->Get(context, 0).ToLocalChecked())
            .FromJust());
}


THREADED_TEST(ForeignFunctionReceiver) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope scope(isolate);

  // Create two contexts with different "id" properties ('i' and 'o').
  // Call a function both from its own context and from a the foreign
  // context, and see what "this" is bound to (returning both "this"
  // and "this.id" for comparison).

  Local<Context> foreign_context = v8::Context::New(isolate);
  foreign_context->Enter();
  Local<Value> foreign_function =
    CompileRun("function func() { return { 0: this.id, "
               "                           1: this, "
               "                           toString: function() { "
               "                               return this[0];"
               "                           }"
               "                         };"
               "}"
               "var id = 'i';"
               "func;");
  CHECK(foreign_function->IsFunction());
  foreign_context->Exit();

  LocalContext context;

  Local<String> password = v8_str("Password");
  // Don't get hit by security checks when accessing foreign_context's
  // global receiver (aka. global proxy).
  context->SetSecurityToken(password);
  foreign_context->SetSecurityToken(password);

  Local<String> i = v8_str("i");
  Local<String> o = v8_str("o");
  Local<String> id = v8_str("id");

  CompileRun("function ownfunc() { return { 0: this.id, "
             "                              1: this, "
             "                              toString: function() { "
             "                                  return this[0];"
             "                              }"
             "                             };"
             "}"
             "var id = 'o';"
             "ownfunc");
  CHECK(context->Global()
            ->Set(context.local(), v8_str("func"), foreign_function)
            .FromJust());

  // Sanity check the contexts.
  CHECK(
      i->Equals(
           context.local(),
           foreign_context->Global()->Get(context.local(), id).ToLocalChecked())
          .FromJust());
  CHECK(o->Equals(context.local(),
                  context->Global()->Get(context.local(), id).ToLocalChecked())
            .FromJust());

  // Checking local function's receiver.
  // Calling function using its call/apply methods.
  TestReceiver(o, context->Global(), "ownfunc.call()");
  TestReceiver(o, context->Global(), "ownfunc.apply()");
  // Making calls through built-in functions.
  TestReceiver(o, context->Global(), "[1].map(ownfunc)[0]");
  CHECK(
      o->Equals(context.local(), CompileRun("'abcbd'.replace(/b/,ownfunc)[1]"))
          .FromJust());
  CHECK(
      o->Equals(context.local(), CompileRun("'abcbd'.replace(/b/g,ownfunc)[1]"))
          .FromJust());
  CHECK(
      o->Equals(context.local(), CompileRun("'abcbd'.replace(/b/g,ownfunc)[3]"))
          .FromJust());
  // Calling with environment record as base.
  TestReceiver(o, context->Global(), "ownfunc()");
  // Calling with no base.
  TestReceiver(o, context->Global(), "(1,ownfunc)()");

  // Checking foreign function return value.
  // Calling function using its call/apply methods.
  TestReceiver(i, foreign_context->Global(), "func.call()");
  TestReceiver(i, foreign_context->Global(), "func.apply()");
  // Calling function using another context's call/apply methods.
  TestReceiver(i, foreign_context->Global(),
               "Function.prototype.call.call(func)");
  TestReceiver(i, foreign_context->Global(),
               "Function.prototype.call.apply(func)");
  TestReceiver(i, foreign_context->Global(),
               "Function.prototype.apply.call(func)");
  TestReceiver(i, foreign_context->Global(),
               "Function.prototype.apply.apply(func)");
  // Making calls through built-in functions.
  TestReceiver(i, foreign_context->Global(), "[1].map(func)[0]");
  // ToString(func()) is func()[0], i.e., the returned this.id.
  CHECK(i->Equals(context.local(), CompileRun("'abcbd'.replace(/b/,func)[1]"))
            .FromJust());
  CHECK(i->Equals(context.local(), CompileRun("'abcbd'.replace(/b/g,func)[1]"))
            .FromJust());
  CHECK(i->Equals(context.local(), CompileRun("'abcbd'.replace(/b/g,func)[3]"))
            .FromJust());

  // Calling with environment record as base.
  TestReceiver(i, foreign_context->Global(), "func()");
  // Calling with no base.
  TestReceiver(i, foreign_context->Global(), "(1,func)()");
}


uint8_t callback_fired = 0;
uint8_t before_call_entered_callback_count1 = 0;
uint8_t before_call_entered_callback_count2 = 0;


void CallCompletedCallback1(v8::Isolate*) {
  v8::base::OS::Print("Firing callback 1.\n");
  callback_fired ^= 1;  // Toggle first bit.
}


void CallCompletedCallback2(v8::Isolate*) {
  v8::base::OS::Print("Firing callback 2.\n");
  callback_fired ^= 2;  // Toggle second bit.
}


void BeforeCallEnteredCallback1(v8::Isolate*) {
  v8::base::OS::Print("Firing before call entered callback 1.\n");
  before_call_entered_callback_count1++;
}


void BeforeCallEnteredCallback2(v8::Isolate*) {
  v8::base::OS::Print("Firing before call entered callback 2.\n");
  before_call_entered_callback_count2++;
}


void RecursiveCall(const v8::FunctionCallbackInfo<v8::Value>& args) {
  int32_t level =
      args[0]->Int32Value(args.GetIsolate()->GetCurrentContext()).FromJust();
  if (level < 3) {
    level++;
    v8::base::OS::Print("Entering recursion level %d.\n", level);
    char script[64];
    v8::base::Vector<char> script_vector(script, sizeof(script));
    v8::base::SNPrintF(script_vector, "recursion(%d)", level);
    CompileRun(script_vector.begin());
    v8::base::OS::Print("Leaving recursion level %d.\n", level);
    CHECK_EQ(0, callback_fired);
  } else {
    v8::base::OS::Print("Recursion ends.\n");
    CHECK_EQ(0, callback_fired);
  }
}


TEST(CallCompletedCallback) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  v8::Local<v8::FunctionTemplate> recursive_runtime =
      v8::FunctionTemplate::New(env->GetIsolate(), RecursiveCall);
  env->Global()
      ->Set(env.local(), v8_str("recursion"),
            recursive_runtime->GetFunction(env.local()).ToLocalChecked())
      .FromJust();
  // Adding the same callback a second time has no effect.
  env->GetIsolate()->AddCallCompletedCallback(CallCompletedCallback1);
  env->GetIsolate()->AddCallCompletedCallback(CallCompletedCallback1);
  env->GetIsolate()->AddCallCompletedCallback(CallCompletedCallback2);
  env->GetIsolate()->AddBeforeCallEnteredCallback(BeforeCallEnteredCallback1);
  env->GetIsolate()->AddBeforeCallEnteredCallback(BeforeCallEnteredCallback2);
  env->GetIsolate()->AddBeforeCallEnteredCallback(BeforeCallEnteredCallback1);
  v8::base::OS::Print("--- Script (1) ---\n");
  callback_fired = 0;
  before_call_entered_callback_count1 = 0;
  before_call_entered_callback_count2 = 0;
  Local<Script> script =
      v8::Script::Compile(env.local(), v8_str("recursion(0)")).ToLocalChecked();
  script->Run(env.local()).ToLocalChecked();
  CHECK_EQ(3, callback_fired);
  CHECK_EQ(4, before_call_entered_callback_count1);
  CHECK_EQ(4, before_call_entered_callback_count2);

  v8::base::OS::Print("\n--- Script (2) ---\n");
  callback_fired = 0;
  before_call_entered_callback_count1 = 0;
  before_call_entered_callback_count2 = 0;
  env->GetIsolate()->RemoveCallCompletedCallback(CallCompletedCallback1);
  env->GetIsolate()->RemoveBeforeCallEnteredCallback(
      BeforeCallEnteredCallback1);
  script->Run(env.local()).ToLocalChecked();
  CHECK_EQ(2, callback_fired);
  CHECK_EQ(0, before_call_entered_callback_count1);
  CHECK_EQ(4, before_call_entered_callback_count2);

  v8::base::OS::Print("\n--- Function ---\n");
  callback_fired = 0;
  before_call_entered_callback_count1 = 0;
  before_call_entered_callback_count2 = 0;
  Local<Function> recursive_function = Local<Function>::Cast(
      env->Global()->Get(env.local(), v8_str("recursion")).ToLocalChecked());
  v8::Local<Value> args[] = {v8_num(0)};
  recursive_function->Call(env.local(), env->Global(), 1, args)
      .ToLocalChecked();
  CHECK_EQ(2, callback_fired);
  CHECK_EQ(0, before_call_entered_callback_count1);
  CHECK_EQ(4, before_call_entered_callback_count2);
}


void CallCompletedCallbackNoException(v8::Isolate*) {
  v8::HandleScope scope(CcTest::isolate());
  CompileRun("1+1;");
}


void CallCompletedCallbackException(v8::Isolate*) {
  v8::HandleScope scope(CcTest::isolate());
  CompileRun("throw 'second exception';");
}


TEST(CallCompletedCallbackOneException) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  env->GetIsolate()->AddCallCompletedCallback(CallCompletedCallbackNoException);
  CompileRun("throw 'exception';");
}


TEST(CallCompletedCallbackTwoExceptions) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  env->GetIsolate()->AddCallCompletedCallback(CallCompletedCallbackException);
  CompileRun("throw 'first exception';");
}


static void MicrotaskOne(const v8::FunctionCallbackInfo<Value>& info) {
  CHECK(v8::MicrotasksScope::IsRunningMicrotasks(info.GetIsolate()));
  v8::HandleScope scope(info.GetIsolate());
  v8::MicrotasksScope microtasks(info.GetIsolate()->GetCurrentContext(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
  CompileRun("ext1Calls++;");
}


static void MicrotaskTwo(const v8::FunctionCallbackInfo<Value>& info) {
  CHECK(v8::MicrotasksScope::IsRunningMicrotasks(info.GetIsolate()));
  v8::HandleScope scope(info.GetIsolate());
  v8::MicrotasksScope microtasks(info.GetIsolate()->GetCurrentContext(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
  CompileRun("ext2Calls++;");
}

void* g_passed_to_three = nullptr;

static void MicrotaskThree(void* data) {
  g_passed_to_three = data;
}


TEST(EnqueueMicrotask) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  CHECK(!v8::MicrotasksScope::IsRunningMicrotasks(env->GetIsolate()));
  CompileRun(
      "var ext1Calls = 0;"
      "var ext2Calls = 0;");
  CompileRun("1+1;");
  CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  g_passed_to_three = nullptr;
  env->GetIsolate()->EnqueueMicrotask(MicrotaskThree);
  CompileRun("1+1;");
  CHECK(!g_passed_to_three);
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());

  int dummy;
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  env->GetIsolate()->EnqueueMicrotask(MicrotaskThree, &dummy);
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(&dummy, g_passed_to_three);
  CHECK_EQ(3, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  g_passed_to_three = nullptr;
}


static void MicrotaskExceptionOne(
    const v8::FunctionCallbackInfo<Value>& info) {
  v8::HandleScope scope(info.GetIsolate());
  CompileRun("exception1Calls++;");
  info.GetIsolate()->ThrowException(
      v8::Exception::Error(v8_str("first")));
}


static void MicrotaskExceptionTwo(
    const v8::FunctionCallbackInfo<Value>& info) {
  v8::HandleScope scope(info.GetIsolate());
  CompileRun("exception2Calls++;");
  info.GetIsolate()->ThrowException(
      v8::Exception::Error(v8_str("second")));
}

int handler_call_count = 0;
static void MicrotaskExceptionHandler(Local<Message> message,
                                      Local<Value> exception) {
  CHECK(exception->IsNativeError());
  Local<Context> context = message->GetIsolate()->GetCurrentContext();
  Local<String> str = exception->ToString(context).ToLocalChecked();
  switch (handler_call_count++) {
    case 0:
      CHECK(str->StrictEquals(v8_str("Error: first")));
      break;
    case 1:
      CHECK(str->StrictEquals(v8_str("Error: second")));
      break;
    default:
      UNREACHABLE();
  }
}

TEST(RunMicrotasksIgnoresThrownExceptions) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  isolate->AddMessageListenerWithErrorLevel(MicrotaskExceptionHandler,
                                            v8::Isolate::kMessageAll);
  CompileRun(
      "var exception1Calls = 0;"
      "var exception2Calls = 0;");
  isolate->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskExceptionOne).ToLocalChecked());
  isolate->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskExceptionTwo).ToLocalChecked());
  TryCatch try_catch(isolate);
  CompileRun("1+1;");
  CHECK(!try_catch.HasCaught());
  CHECK_EQ(handler_call_count, 2);
  CHECK_EQ(1,
           CompileRun("exception1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(1,
           CompileRun("exception2Calls")->Int32Value(env.local()).FromJust());
}

static void ThrowExceptionMicrotask(void* data) {
  CcTest::isolate()->ThrowException(v8_str("exception"));
}

int microtask_callback_count = 0;

static void IncrementCounterMicrotask(void* data) {
  microtask_callback_count++;
}

TEST(RunMicrotasksIgnoresThrownExceptionsFromApi) {
  LocalContext env;
  v8::Isolate* isolate = CcTest::isolate();
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  {
    CHECK(!isolate->IsExecutionTerminating());
    isolate->EnqueueMicrotask(ThrowExceptionMicrotask);
    isolate->EnqueueMicrotask(IncrementCounterMicrotask);
    isolate->PerformMicrotaskCheckpoint();
    CHECK_EQ(1, microtask_callback_count);
    CHECK(!try_catch.HasCaught());
  }
}

uint8_t microtasks_completed_callback_count = 0;

static void MicrotasksCompletedCallback(v8::Isolate* isolate, void*) {
  ++microtasks_completed_callback_count;
}

static void MicrotasksCompletedCallbackCallScript(v8::Isolate* isolate, void*) {
  CompileRun("1+1;");
}

TEST(SetAutorunMicrotasks) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  env->GetIsolate()->AddMicrotasksCompletedCallback(
      &MicrotasksCompletedCallback);

  // If the policy is auto, there's a microtask checkpoint at the end of every
  // zero-depth API call.
  CompileRun(
      "var ext1Calls = 0;"
      "var ext2Calls = 0;");
  CompileRun("1+1;");
  CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(4u, microtasks_completed_callback_count);

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(7u, microtasks_completed_callback_count);

  // If the policy is explicit, microtask checkpoints are explicitly invoked.
  env->GetIsolate()->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(7u, microtasks_completed_callback_count);

  env->GetIsolate()->PerformMicrotaskCheckpoint();
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(8u, microtasks_completed_callback_count);

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(8u, microtasks_completed_callback_count);

  env->GetIsolate()->PerformMicrotaskCheckpoint();
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(9u, microtasks_completed_callback_count);

  env->GetIsolate()->SetMicrotasksPolicy(v8::MicrotasksPolicy::kAuto);
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(12u, microtasks_completed_callback_count);

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  {
    v8::Isolate::SuppressMicrotaskExecutionScope suppress(env->GetIsolate());
    CompileRun("1+1;");
    CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(12u, microtasks_completed_callback_count);
  }

  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(4, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(15u, microtasks_completed_callback_count);

  // A callback which calls script should not cause nested microtask execution
  // and a nested invocation of the microtasks completed callback.
  env->GetIsolate()->AddMicrotasksCompletedCallback(
      &MicrotasksCompletedCallbackCallScript);
  CompileRun("1+1;");
  CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(4, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(18u, microtasks_completed_callback_count);
  env->GetIsolate()->RemoveMicrotasksCompletedCallback(
      &MicrotasksCompletedCallbackCallScript);

  env->GetIsolate()->RemoveMicrotasksCompletedCallback(
      &MicrotasksCompletedCallback);
  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  CompileRun("1+1;");
  CHECK_EQ(3, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(4, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  CHECK_EQ(18u, microtasks_completed_callback_count);
}


TEST(RunMicrotasksWithoutEnteringContext) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope handle_scope(isolate);
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
  Local<Context> context = Context::New(isolate);
  {
    Context::Scope context_scope(context);
    CompileRun("var ext1Calls = 0;");
    isolate->EnqueueMicrotask(
        Function::New(context, MicrotaskOne).ToLocalChecked());
  }
  isolate->PerformMicrotaskCheckpoint();
  {
    Context::Scope context_scope(context);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(context).FromJust());
  }
  isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kAuto);
}

static void Regress808911_MicrotaskCallback(void* data) {
  // So here we expect "current context" to be context1 and
  // "entered or microtask context" to be context2.
  v8::Isolate* isolate = static_cast<v8::Isolate*>(data);
  CHECK(isolate->GetCurrentContext() !=
        isolate->GetEnteredOrMicrotaskContext());
}

static void Regress808911_CurrentContextWrapper(
    const v8::FunctionCallbackInfo<Value>& info) {
  // So here we expect "current context" to be context1 and
  // "entered or microtask context" to be context2.
  v8::Isolate* isolate = info.GetIsolate();
  CHECK(isolate->GetCurrentContext() !=
        isolate->GetEnteredOrMicrotaskContext());
  isolate->EnqueueMicrotask(Regress808911_MicrotaskCallback, isolate);
  isolate->PerformMicrotaskCheckpoint();
}

THREADED_TEST(Regress808911) {
  v8::Isolate* isolate = CcTest::isolate();
  HandleScope handle_scope(isolate);
  Local<Context> context1 = Context::New(isolate);
  Local<Function> function;
  {
    Context::Scope context_scope(context1);
    function = Function::New(context1, Regress808911_CurrentContextWrapper)
                   .ToLocalChecked();
  }
  Local<Context> context2 = Context::New(isolate);
  Context::Scope context_scope(context2);
  function->CallAsFunction(context2, v8::Undefined(isolate), 0, nullptr)
      .ToLocalChecked();
}

TEST(ScopedMicrotasks) {
  LocalContext env;
  v8::HandleScope handles(env->GetIsolate());
  env->GetIsolate()->SetMicrotasksPolicy(v8::MicrotasksPolicy::kScoped);
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    CompileRun("var ext1Calls = 0;");
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    ExpectInt32("ext1Calls", 1);
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    CompileRun("throw new Error()");
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    ExpectInt32("ext1Calls", 2);
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    v8::TryCatch try_catch(env->GetIsolate());
    CompileRun("throw new Error()");
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    ExpectInt32("ext1Calls", 3);
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    env->GetIsolate()->TerminateExecution();
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kRunMicrotasks);
      env->GetIsolate()->EnqueueMicrotask(
          Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    }
  }
  env->GetIsolate()->CancelTerminateExecution();
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    ExpectInt32("ext1Calls", 3);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  }
  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);

    ExpectInt32("ext1Calls", 4);
  }

  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kDoNotRunMicrotasks);
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskOne).ToLocalChecked());
    CompileRun(
        "var ext1Calls = 0;"
        "var ext2Cal
"""


```