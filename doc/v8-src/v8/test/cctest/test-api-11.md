Response: The user wants me to summarize the functionality of the C++ source code file `v8/test/cctest/test-api.cc`, specifically focusing on the section provided (part 12 of 18). I also need to identify any relationship to JavaScript features and illustrate with JavaScript examples.

Based on the provided code, it appears to be a test suite for the V8 JavaScript engine's C++ API. This particular section seems to focus on testing various API functionalities related to:

1. **Code Generation from Strings:**  Testing how V8 handles code generation via `eval()` and the `Function` constructor, including allowing, disallowing, and modifying the source.
2. **Callbacks:** Testing callbacks related to call completion, before-call entry, and microtasks.
3. **Microtasks:** Testing the enqueueing, running, and handling of exceptions within microtasks, as well as different microtask policies (auto, explicit, scoped).
4. **Object Properties and Accessors:** Testing interactions with object properties, including read-only properties, native accessors, and interceptors.
5. **Contexts:**  Testing the behavior of functions called across different contexts and the binding of `this`.
6. **JSON Parsing and Stringification:** Testing the `v8::JSON::Parse` and `v8::JSON::Stringify` API functions, including handling different data types and access checks.
7. **Isolate Data:** Testing the setting and retrieval of data slots associated with a V8 isolate.
8. **Templates:** Testing the concept of leaf templates for API objects.
9. **Error Handling:** Testing how V8 handles exceptions thrown during failed access checks.
10. **Concurrency:** Testing interrupt handling in V8 using `RequestInterrupt`.

For the JavaScript examples, I will focus on the functionalities directly tested by the C++ code, such as `eval()`, `Function`, `Promise.resolve().then()`, `JSON.parse()`, and `JSON.stringify()`.
这个C++源代码文件 `v8/test/cctest/test-api.cc` 的第12部分主要测试了V8引擎C++ API中与以下功能相关的特性：

**1. 控制从字符串生成代码的能力 (Code Generation from Strings):**

*   测试了 `AllowCodeGenerationFromStrings` 和 `IsCodeGenerationFromStringsAllowed` API，用于允许或禁止从字符串（如 `eval()` 或 `Function` 构造函数）生成代码。
*   测试了 `SetModifyCodeGenerationFromStringsCallback` API，允许注册一个回调函数来修改或拒绝从字符串生成的代码。
*   测试了 `SetErrorMessageForCodeGenerationFromStrings` API，当禁止从字符串生成代码时，可以设置自定义的错误消息。
*   测试了在允许和禁止代码生成的情况下，`eval()` 和 `Function` 构造函数的行为。

**JavaScript 示例:**

```javascript
// 与 AllowCodeGenerationFromStrings(true/false) 相关
// 默认情况下，可以从字符串生成代码
eval('console.log("Hello from eval");'); // 输出 "Hello from eval"

// 如果 C++ 代码中设置不允许从字符串生成代码
// context->AllowCodeGenerationFromStrings(false);
try {
  eval('console.log("This should fail");');
} catch (e) {
  console.error("Eval failed:", e); // 捕获错误
}

// 与 SetModifyCodeGenerationFromStringsCallback 相关
// 假设 C++ 代码中设置了如下回调 (简化示例):
// v8::ModifyCodeGenerationFromStringsResult ModifyCodeGeneration(
//     Local<Context> context, Local<Value> source, bool is_code_like) {
//   if (source->IsString() && v8::String::Utf8Value(context->GetIsolate(), source.As<v8::String>()).get()[0] === '4') {
//     // 修改以 '4' 开头的字符串
//     v8::Local<v8::String> modifiedSource = v8::String::NewFromUtf8(context->GetIsolate(), "1+1", v8::NewStringType::kNormal).ToLocalChecked();
//     return {true, modifiedSource};
//   }
//   return {true, source.As<v8::String>()};
// }
// context->GetIsolate()->SetModifyCodeGenerationFromStringsCallback(&ModifyCodeGeneration);

let result1 = eval('42'); // 由于回调，实际执行的是 '1+1'，结果为 2
console.log(result1); // 输出 2

let result2 = new Function('"use strict"; return 42;')(); // 正常执行
console.log(result2); // 输出 42
```

**2. 调用完成回调 (Call Completed Callback) 和 调用进入前回调 (Before Call Entered Callback):**

*   测试了 `AddCallCompletedCallback` 和 `RemoveCallCompletedCallback` API，用于在 JavaScript 函数调用完成后注册和移除回调函数。
*   测试了 `AddBeforeCallEnteredCallback` 和 `RemoveBeforeCallEnteredCallback` API，用于在 JavaScript 函数调用开始前注册和移除回调函数。
*   测试了回调函数在递归调用和抛出异常时的行为。

**3. 微任务 (Microtasks):**

*   测试了 `EnqueueMicrotask` API，用于将微任务添加到微任务队列中。
*   测试了微任务的执行顺序和时机。
*   测试了微任务中抛出异常的处理方式（不会导致程序崩溃，而是通过消息监听器报告）。
*   测试了不同的微任务策略 (`SetMicrotasksPolicy`): `kAuto` (自动执行), `kExplicit` (显式执行), `kScoped` (作用域内执行)。
*   测试了 `PerformMicrotaskCheckpoint` API，用于显式地运行微任务。
*   测试了 `SuppressMicrotaskExecutionScope`，用于临时禁止微任务的执行。
*   测试了 `AddMicrotasksCompletedCallback` 和 `RemoveMicrotasksCompletedCallback` API，用于在微任务队列为空时注册和移除回调函数。

**JavaScript 示例:**

```javascript
// 与 EnqueueMicrotask 相关
Promise.resolve().then(() => {
  console.log("Microtask executed");
});
console.log("Synchronous code");
// 输出顺序可能是:
// Synchronous code
// Microtask executed

// 与微任务策略相关 (假设 C++ 设置为显式执行)
// isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kExplicit);
Promise.resolve().then(() => {
  console.log("Microtask 1");
});
Promise.resolve().then(() => {
  console.log("Microtask 2");
});
console.log("Before checkpoint");
// 在没有显式调用 PerformMicrotaskCheckpoint 的情况下，微任务不会执行

// 如果 C++ 代码中调用了 PerformMicrotaskCheckpoint
// isolate->PerformMicrotaskCheckpoint();
// console.log("After checkpoint");
// 输出顺序可能是:
// Before checkpoint
// Microtask 1
// Microtask 2
// After checkpoint
```

**4. 非对象上的 API 函数调用 (Call API Function on Non-Object):**

*   测试了在非对象上使用 `call` 方法调用 API 函数时的行为。

**5. 只读索引属性 (Read-Only Indexed Properties):**

*   测试了使用 `DefineOwnProperty` 定义只读索引属性，并尝试修改时的行为。

**6. Map 缓存 (Map Cache):**

*   测试了 V8 的 Map 缓存机制，包括对象的 Map 如何被缓存和回收。

**7. 外部函数接收者 (Foreign Function Receiver):**

*   测试了在不同上下文中调用函数时，`this` 的绑定情况。

**8. 静态 Getter (Static Getters):**

*   测试了获取 V8 内置的静态值，如 `undefined`, `null`, `true`, `false`。

**9. Isolate 嵌入数据 (Isolate Embedder Data):**

*   测试了 `SetData` 和 `GetData` API，用于在 V8 Isolate 中存储和检索嵌入器特定的数据。

**10. 空字符串 (String Empty):**

*   测试了获取 V8 内置的空字符串。

**11. API 对象的叶子模板检查 (CheckIsLeafTemplateForApiObject):**

*   测试了 `IsLeafTemplateForApiObject` API，用于检查一个对象是否是给定函数模板的直接实例。

**12. 属性访问器 (Property Accessors) 和 拦截器 (Interceptors):**

*   测试了原生属性访问器（Getter 和 Setter）和属性拦截器在不同的优化场景下的行为，包括多态和删除属性。

**13. JSON 解析和字符串化 (JSON Parse and Stringify):**

*   测试了 `v8::JSON::Parse` API，用于将 JSON 字符串解析为 JavaScript 对象，并验证解析后的数组元素的类型。
*   测试了 `v8::JSON::Stringify` API，用于将 JavaScript 对象转换为 JSON 字符串，包括使用缩进。
*   测试了在启用访问检查的情况下，`JSON.stringify` 的行为。

**14. 访问检查 (Access Check):**

*   测试了在跨上下文访问对象时，访问检查回调函数的行为，以及如何抛出异常。

**15. 请求中断 (Request Interrupt):**

*   测试了 `RequestInterrupt` API，用于在 JavaScript 执行过程中请求中断并执行指定的回调函数。

总而言之，这个代码片段是 V8 引擎 C++ API 功能的详细测试，涵盖了代码生成、回调、微任务、对象属性、上下文、JSON 处理、安全性和并发控制等多个核心方面。 通过这些测试，可以确保 V8 API 的正确性和稳定性。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第12部分，共18部分，请归纳一下它的功能

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
        "var ext2Calls = 0;");
    CompileRun("1+1;");
    CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kRunMicrotasks);
      CompileRun("1+1;");
      CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
      CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
      {
        v8::MicrotasksScope scope3(env.local(),
                                   v8::MicrotasksScope::kRunMicrotasks);
        CompileRun("1+1;");
        CHECK_EQ(0,
                 CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
        CHECK_EQ(0,
                 CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
      }
      CHECK_EQ(0, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
      CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    }
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    CompileRun("1+1;");
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kDoNotRunMicrotasks);
    }
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(0, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  {
    v8::Isolate::SuppressMicrotaskExecutionScope scope1(env->GetIsolate());
    {
      v8::MicrotasksScope scope2(env.local(),
                                 v8::MicrotasksScope::kRunMicrotasks);
    }
    v8::MicrotasksScope scope3(env.local(),
                               v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope1(env.local(),
                               v8::MicrotasksScope::kRunMicrotasks);
    v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(1, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(2, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
    env->GetIsolate()->EnqueueMicrotask(
        Function::New(env.local(), MicrotaskTwo).ToLocalChecked());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  env->GetIsolate()->EnqueueMicrotask(
      Function::New(env.local(), MicrotaskOne).ToLocalChecked());
  {
    v8::Isolate::SuppressMicrotaskExecutionScope scope1(env->GetIsolate());
    v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());
    v8::MicrotasksScope scope2(env.local(),
                               v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(1, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  v8::MicrotasksScope::PerformCheckpoint(env->GetIsolate());

  {
    v8::MicrotasksScope scope(env.local(),
                              v8::MicrotasksScope::kDoNotRunMicrotasks);
    CHECK_EQ(2, CompileRun("ext1Calls")->Int32Value(env.local()).FromJust());
    CHECK_EQ(3, CompileRun("ext2Calls")->Int32Value(env.local()).FromJust());
  }

  env->GetIsolate()->SetMicrotasksPolicy(v8::MicrotasksPolicy::kAuto);
}

namespace {

void AssertCowElements(bool expected, const char* source) {
  Local<Value> object = CompileRun(source);
  i::DirectHandle<i::JSObject> array =
      i::Cast<i::JSObject>(v8::Utils::OpenDirectHandle(*object.As<Object>()));
  CHECK_EQ(expected, array->elements()->IsCowArray());
}

}  // namespace

TEST(CheckCOWArraysCreatedRuntimeCounter) {
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  AssertCowElements(true, "[1, 2, 3]");
  AssertCowElements(false, "[[1], 2, 3]");
  AssertCowElements(true, "[[1], 2, 3][0]");
  AssertCowElements(true, "({foo: [4, 5, 6], bar: [3, 0]}.foo)");
  AssertCowElements(true, "({foo: [4, 5, 6], bar: [3, 0]}.bar)");
  AssertCowElements(false, "({foo: [1, 2, 3, [4, 5, 6]], bar: 'hi'}.foo)");
  AssertCowElements(true, "({foo: [1, 2, 3, [4, 5, 6]], bar: 'hi'}.foo[3])");
}


TEST(StaticGetters) {
  LocalContext context;
  i::Factory* factory = CcTest::i_isolate()->factory();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  i::DirectHandle<i::Object> undefined_value = factory->undefined_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::Undefined(isolate)) ==
        *undefined_value);
  i::DirectHandle<i::Object> null_value = factory->null_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::Null(isolate)) == *null_value);
  i::DirectHandle<i::Object> true_value = factory->true_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::True(isolate)) == *true_value);
  i::DirectHandle<i::Object> false_value = factory->false_value();
  CHECK(*v8::Utils::OpenDirectHandle(*v8::False(isolate)) == *false_value);
}

UNINITIALIZED_TEST(IsolateEmbedderData) {
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  isolate->Enter();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    CHECK(!isolate->GetData(slot));
    CHECK(!i_isolate->GetData(slot));
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xACCE55ED + slot);
    isolate->SetData(slot, data);
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xACCE55ED + slot);
    CHECK_EQ(data, isolate->GetData(slot));
    CHECK_EQ(data, i_isolate->GetData(slot));
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xDECEA5ED + slot);
    isolate->SetData(slot, data);
  }
  for (uint32_t slot = 0; slot < v8::Isolate::GetNumberOfDataSlots(); ++slot) {
    void* data = reinterpret_cast<void*>(0xDECEA5ED + slot);
    CHECK_EQ(data, isolate->GetData(slot));
    CHECK_EQ(data, i_isolate->GetData(slot));
  }
  isolate->Exit();
  isolate->Dispose();
}

TEST(StringEmpty) {
  LocalContext context;
  i::Factory* factory = CcTest::i_isolate()->factory();
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  i::DirectHandle<i::Object> empty_string = factory->empty_string();
  CHECK_EQ(*v8::Utils::OpenDirectHandle(*v8::String::Empty(isolate)),
           *empty_string);
}

THREADED_TEST(CheckIsLeafTemplateForApiObject) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  Local<FunctionTemplate> templ = FunctionTemplate::New(context->GetIsolate());
  CHECK(context->Global()
            ->Set(context.local(), v8_str("f"),
                  templ->GetFunction(context.local()).ToLocalChecked())
            .FromJust());

  printf("Testing positive ...\n");
  CompileRun("var obj = new f();");
  CHECK(templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  printf("Testing negative ...\n");
  CompileRun(
      "var obj = {};"
      "obj.__proto__ = new f();");
  CHECK(!templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  printf("Testing positive with modified prototype chain ...\n");
  CompileRun(
      "var obj = new f();"
      "var pro = {};"
      "pro.__proto__ = obj.__proto__;"
      "obj.__proto__ = pro;");
  CHECK(templ->IsLeafTemplateForApiObject(
      context->Global()->Get(context.local(), v8_str("obj")).ToLocalChecked()));

  Local<FunctionTemplate> child_templ =
      FunctionTemplate::New(context->GetIsolate());
  child_templ->Inherit(templ);
  Local<Object> instance = child_templ->GetFunction(context.local())
                               .ToLocalChecked()
                               ->NewInstance(context.local())
                               .ToLocalChecked();

  printf("Testing positive for child ...\n");
  CHECK(child_templ->IsLeafTemplateForApiObject(instance));
  printf("Testing negative for parent ...\n");
  CHECK(!templ->IsLeafTemplateForApiObject(instance));
}

static void Helper137002(bool do_store,
                         bool polymorphic,
                         bool remove_accessor,
                         bool interceptor) {
  LocalContext context;
  Local<ObjectTemplate> templ = ObjectTemplate::New(context->GetIsolate());
  if (interceptor) {
    templ->SetHandler(v8::NamedPropertyHandlerConfiguration(FooGetInterceptor,
                                                            FooSetInterceptor));
  } else {
    templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                                 SetterWhichSetsYOnThisTo23);
  }
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // Turn monomorphic on slow object with native accessor, then turn
  // polymorphic, finally optimize to create negative lookup and fail.
  CompileRun(do_store ?
             "function f(x) { x.foo = void 0; }" :
             "function f(x) { return x.foo; }");
  CompileRun("%PrepareFunctionForOptimization(f);");
  CompileRun("obj.y = void 0;");
  if (!interceptor) {
    CompileRun("%OptimizeObjectForAddingMultipleProperties(obj, 1);");
  }
  CompileRun("obj.__proto__ = null;"
             "f(obj); f(obj); f(obj);");
  if (polymorphic) {
    CompileRun("f({});");
  }
  CompileRun("obj.y = void 0;"
             "%OptimizeFunctionOnNextCall(f);");
  if (remove_accessor) {
    CompileRun("delete obj.foo;");
  }
  CompileRun("var result = f(obj);");
  if (do_store) {
    CompileRun("result = obj.y;");
  }
  if (remove_accessor && !interceptor) {
    CHECK(context->Global()
              ->Get(context.local(), v8_str("result"))
              .ToLocalChecked()
              ->IsUndefined());
  } else {
    CHECK_EQ(do_store ? 23 : 42, context->Global()
                                     ->Get(context.local(), v8_str("result"))
                                     .ToLocalChecked()
                                     ->Int32Value(context.local())
                                     .FromJust());
  }
}


THREADED_TEST(Regress137002a) {
  i::v8_flags.allow_natives_syntax = true;
  i::v8_flags.compilation_cache = false;
  v8::HandleScope scope(CcTest::isolate());
  for (int i = 0; i < 16; i++) {
    Helper137002(i & 8, i & 4, i & 2, i & 1);
  }
}


THREADED_TEST(Regress137002b) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  // Turn monomorphic on slow object with native accessor, then just
  // delete the property and fail.
  CompileRun("function load(x) { return x.foo; }"
             "function store(x) { x.foo = void 0; }"
             "function keyed_load(x, key) { return x[key]; }"
             // Second version of function has a different source (add void 0)
             // so that it does not share code with the first version.  This
             // ensures that the ICs are monomorphic.
             "function load2(x) { void 0; return x.foo; }"
             "function store2(x) { void 0; x.foo = void 0; }"
             "function keyed_load2(x, key) { void 0; return x[key]; }"

             "obj.y = void 0;"
             "obj.__proto__ = null;"
             "var subobj = {};"
             "subobj.y = void 0;"
             "subobj.__proto__ = obj;"
             "%OptimizeObjectForAddingMultipleProperties(obj, 1);"

             // Make the ICs monomorphic.
             "load(obj); load(obj);"
             "load2(subobj); load2(subobj);"
             "store(obj); store(obj);"
             "store2(subobj); store2(subobj);"
             "keyed_load(obj, 'foo'); keyed_load(obj, 'foo');"
             "keyed_load2(subobj, 'foo'); keyed_load2(subobj, 'foo');"

             // Actually test the shiny new ICs and better not crash. This
             // serves as a regression test for issue 142088 as well.
             "load(obj);"
             "load2(subobj);"
             "store(obj);"
             "store2(subobj);"
             "keyed_load(obj, 'foo');"
             "keyed_load2(subobj, 'foo');"

             // Delete the accessor.  It better not be called any more now.
             "delete obj.foo;"
             "obj.y = void 0;"
             "subobj.y = void 0;"

             "var load_result = load(obj);"
             "var load_result2 = load2(subobj);"
             "var keyed_load_result = keyed_load(obj, 'foo');"
             "var keyed_load_result2 = keyed_load2(subobj, 'foo');"
             "store(obj);"
             "store2(subobj);"
             "var y_from_obj = obj.y;"
             "var y_from_subobj = subobj.y;");
  CHECK(context->Global()
            ->Get(context.local(), v8_str("load_result"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("load_result2"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("keyed_load_result"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("keyed_load_result2"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("y_from_obj"))
            .ToLocalChecked()
            ->IsUndefined());
  CHECK(context->Global()
            ->Get(context.local(), v8_str("y_from_subobj"))
            .ToLocalChecked()
            ->IsUndefined());
}


THREADED_TEST(Regress142088) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  templ->SetNativeDataProperty(v8_str("foo"), GetterWhichReturns42,
                               SetterWhichSetsYOnThisTo23);
  CHECK(context->Global()
            ->Set(context.local(), v8_str("obj"),
                  templ->NewInstance(context.local()).ToLocalChecked())
            .FromJust());

  CompileRun("function load(x) { return x.foo; }"
             "var o = Object.create(obj);"
             "%OptimizeObjectForAddingMultipleProperties(obj, 1);"
             "load(o); load(o); load(o); load(o);");
}


THREADED_TEST(Regress137496) {
  i::v8_flags.expose_gc = true;
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  // Compile a try-finally clause where the finally block causes a GC
  // while there still is a message pending for external reporting.
  TryCatch try_catch(context->GetIsolate());
  try_catch.SetVerbose(true);
  CompileRun("try { throw new Error(); } finally { gc(); }");
  CHECK(try_catch.HasCaught());
}


THREADED_TEST(Regress157124) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<ObjectTemplate> templ = ObjectTemplate::New(isolate);
  Local<Object> obj = templ->NewInstance(context.local()).ToLocalChecked();
  obj->GetIdentityHash();
  obj->DeletePrivate(context.local(),
                     v8::Private::ForApi(isolate, v8_str("Bug")))
      .FromJust();
}


THREADED_TEST(Regress2535) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());
  Local<Value> set_value = CompileRun("new Set();");
  Local<Object> set_object(Local<Object>::Cast(set_value));
  CHECK_EQ(0, set_object->InternalFieldCount());
  Local<Value> map_value = CompileRun("new Map();");
  Local<Object> map_object(Local<Object>::Cast(map_value));
  CHECK_EQ(0, map_object->InternalFieldCount());
}


THREADED_TEST(Regress2746) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<Object> obj = Object::New(isolate);
  Local<v8::Private> key = v8::Private::New(isolate, v8_str("key"));
  CHECK(
      obj->SetPrivate(context.local(), key, v8::Undefined(isolate)).FromJust());
  Local<Value> value = obj->GetPrivate(context.local(), key).ToLocalChecked();
  CHECK(!value.IsEmpty());
  CHECK(value->IsUndefined());
}


THREADED_TEST(Regress260106) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<FunctionTemplate> templ = FunctionTemplate::New(isolate,
                                                        DummyCallHandler);
  CompileRun("for (var i = 0; i < 128; i++) Object.prototype[i] = 0;");
  Local<Function> function =
      templ->GetFunction(context.local()).ToLocalChecked();
  CHECK(!function.IsEmpty());
  CHECK(function->IsFunction());
}

THREADED_TEST(JSONParseObject) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> obj =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", "{\"x\":42}");
}

THREADED_TEST(JSONParseNumber) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> obj =
      v8::JSON::Parse(context.local(), v8_str("42")).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", "42");
}

namespace {
void TestJSONParseArray(Local<Context> context, const char* input_str,
                        const char* expected_output_str,
                        i::ElementsKind expected_elements_kind) {
  Local<Value> obj =
      v8::JSON::Parse(context, v8_str(input_str)).ToLocalChecked();

  i::DirectHandle<i::JSArray> a =
      i::Cast<i::JSArray>(v8::Utils::OpenDirectHandle(*obj));
  CHECK_EQ(expected_elements_kind, a->GetElementsKind());

  Local<Object> global = context->Global();
  global->Set(context, v8_str("obj"), obj).FromJust();
  ExpectString("JSON.stringify(obj)", expected_output_str);
}
}  // namespace

THREADED_TEST(JSONParseArray) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());

  TestJSONParseArray(context.local(), "[0, 1, 2]", "[0,1,2]",
                     i::PACKED_SMI_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, 1.2, 2]", "[0,1.2,2]",
                     i::PACKED_DOUBLE_ELEMENTS);
  TestJSONParseArray(context.local(), "[0.2, 1, 2]", "[0.2,1,2]",
                     i::PACKED_DOUBLE_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, \"a\", 2]", "[0,\"a\",2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[\"a\", 1, 2]", "[\"a\",1,2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[\"a\", 1.2, 2]", "[\"a\",1.2,2]",
                     i::PACKED_ELEMENTS);
  TestJSONParseArray(context.local(), "[0, 1.2, \"a\"]", "[0,1.2,\"a\"]",
                     i::PACKED_ELEMENTS);
}

THREADED_TEST(JSONStringifyObject) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> value =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> obj = value->ToObject(context.local()).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  Local<String> json =
      v8::JSON::Stringify(context.local(), obj).ToLocalChecked();
  v8::String::Utf8Value utf8(context->GetIsolate(), json);
  ExpectString("JSON.stringify(obj)", *utf8);
}

THREADED_TEST(JSONStringifyObjectWithGap) {
  LocalContext context;
  HandleScope scope(context->GetIsolate());
  Local<Value> value =
      v8::JSON::Parse(context.local(), v8_str("{\"x\":42}")).ToLocalChecked();
  Local<Object> obj = value->ToObject(context.local()).ToLocalChecked();
  Local<Object> global = context->Global();
  global->Set(context.local(), v8_str("obj"), obj).FromJust();
  Local<String> json =
      v8::JSON::Stringify(context.local(), obj, v8_str("*")).ToLocalChecked();
  v8::String::Utf8Value utf8(context->GetIsolate(), json);
  ExpectString("JSON.stringify(obj, null,  '*')", *utf8);
}

#if V8_OS_POSIX
class ThreadInterruptTest {
 public:
  ThreadInterruptTest() : sem_(0), sem_value_(0) { }
  ~ThreadInterruptTest() = default;

  void RunTest() {
    InterruptThread i_thread(this);
    CHECK(i_thread.Start());

    sem_.Wait();
    CHECK_EQ(kExpectedValue, sem_value_);
  }

 private:
  static const int kExpectedValue = 1;

  class InterruptThread : public v8::base::Thread {
   public:
    explicit InterruptThread(ThreadInterruptTest* test)
        : Thread(Options("InterruptThread")), test_(test) {}

    void Run() override {
      struct sigaction action;

      // Ensure that we'll enter waiting condition
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));

      // Setup signal handler
      memset(&action, 0, sizeof(action));
      action.sa_handler = SignalHandler;
      sigaction(SIGCHLD, &action, nullptr);

      // Send signal
      kill(getpid(), SIGCHLD);

      // Ensure that if wait has returned because of error
      v8::base::OS::Sleep(v8::base::TimeDelta::FromMilliseconds(100));

      // Set value and signal semaphore
      test_->sem_value_ = 1;
      test_->sem_.Signal();
    }

    static void SignalHandler(int signal) {
    }

   private:
     ThreadInterruptTest* test_;
  };

  v8::base::Semaphore sem_;
  volatile int sem_value_;
};


THREADED_TEST(SemaphoreInterruption) {
  ThreadInterruptTest().RunTest();
}


#endif  // V8_OS_POSIX


void UnreachableCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  UNREACHABLE();
}

TEST(JSONStringifyAccessCheck) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);

  // Create an ObjectTemplate for global objects and install access
  // check callbacks that will block access.
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(AccessAlwaysBlocked);

  // Create a context and set an x property on it's global object.
  LocalContext context0(nullptr, global_template);
  v8::Local<v8::Object> global0 = context0->Global();
  global0->Set(context0.local(), v8_str("x"), v8_num(42)).FromJust();
  ExpectString("JSON.stringify(this)", "{\"x\":42}");

  for (int i = 0; i < 2; i++) {
    if (i == 1) {
      // Install a toJSON function on the second run.
      v8::Local<v8::FunctionTemplate> toJSON =
          v8::FunctionTemplate::New(isolate, UnreachableCallback);

      global0->Set(context0.local(), v8_str("toJSON"),
                   toJSON->GetFunction(context0.local()).ToLocalChecked())
          .FromJust();
    }
    // Create a context with a different security token so that the
    // failed access check callback will be called on each access.
    LocalContext context1(nullptr, global_template);
    CHECK(context1->Global()
              ->Set(context1.local(), v8_str("other"), global0)
              .FromJust());

    CHECK(CompileRun("JSON.stringify(other)").IsEmpty());
    CHECK(CompileRun("JSON.stringify({ 'a' : other, 'b' : ['c'] })").IsEmpty());
    CHECK(CompileRun("JSON.stringify([other, 'b', 'c'])").IsEmpty());
  }
}

bool access_check_fail_thrown = false;
bool catch_callback_called = false;


// Failed access check callback that performs a GC on each invocation.
void FailedAccessCheckThrows(Local<v8::Object> target,
                             v8::AccessType type,
                             Local<v8::Value> data) {
  access_check_fail_thrown = true;
  i::PrintF("Access check failed. Error thrown.\n");
  CcTest::isolate()->ThrowException(
      v8::Exception::Error(v8_str("cross context")));
}


void CatcherCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  for (int i = 0; i < args.Length(); i++) {
    i::PrintF("%s\n", *String::Utf8Value(args.GetIsolate(), args[i]));
  }
  catch_callback_called = true;
}


void HasOwnPropertyCallback(const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
  CHECK(
      args[0]
          ->ToObject(context)
          .ToLocalChecked()
          ->HasOwnProperty(context, args[1]->ToString(context).ToLocalChecked())
          .IsNothing());
}


void CheckCorrectThrow(const char* script) {
  // Test that the script, when wrapped into a try-catch, triggers the catch
  // clause due to failed access check throwing an exception.
  // The subsequent try-catch should run without any exception.
  access_check_fail_thrown = false;
  catch_callback_called = false;
  v8::base::ScopedVector<char> source(1024);
  v8::base::SNPrintF(source, "try { %s; } catch (e) { catcher(e); }", script);
  CompileRun(source.begin());
  CHECK(access_check_fail_thrown);
  CHECK(catch_callback_called);

  access_check_fail_thrown = false;
  catch_callback_called = false;
  CompileRun("try { [1, 2, 3].sort(); } catch (e) { catcher(e) };");
  CHECK(!access_check_fail_thrown);
  CHECK(!catch_callback_called);
}


TEST(AccessCheckThrows) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  isolate->SetFailedAccessCheckCallbackFunction(&FailedAccessCheckThrows);
  v8::HandleScope scope(isolate);

  // Create an ObjectTemplate for global objects and install access
  // check callbacks that will block access.
  v8::Local<v8::ObjectTemplate> global_template =
      v8::ObjectTemplate::New(isolate);
  global_template->SetAccessCheckCallback(AccessAlwaysBlocked);

  // Create a context and set an x property on it's global object.
  LocalContext context0(nullptr, global_template);
  v8::Local<v8::Object> global0 = context0->Global();
  CHECK(global0->Set(context0.local(), v8_str("x"), global0).FromJust());

  // Create a context with a different security token so that the
  // failed access check callback will be called on each access.
  LocalContext context1(nullptr, global_template);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("other"), global0)
            .FromJust());

  v8::Local<v8::FunctionTemplate> catcher_fun =
      v8::FunctionTemplate::New(isolate, CatcherCallback);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("catcher"),
                  catcher_fun->GetFunction(context1.local()).ToLocalChecked())
            .FromJust());

  v8::Local<v8::FunctionTemplate> has_own_property_fun =
      v8::FunctionTemplate::New(isolate, HasOwnPropertyCallback);
  CHECK(context1->Global()
            ->Set(context1.local(), v8_str("has_own_property"),
                  has_own_property_fun->GetFunction(context1.local())
                      .ToLocalChecked())
            .FromJust());

  {
    v8::TryCatch try_catch(isolate);
    access_check_fail_thrown = false;
    CompileRun("other.x;");
    CHECK(access_check_fail_thrown);
    CHECK(try_catch.HasCaught());
  }

  CheckCorrectThrow("other.x");
  CheckCorrectThrow("other[1]");
  CheckCorrectThrow("JSON.stringify(other)");
  CheckCorrectThrow("has_own_property(other, 'x')");
  CheckCorrectThrow("%GetProperty(other, 'x')");
  CheckCorrectThrow("%SetKeyedProperty(other, 'x', 'foo')");
  CheckCorrectThrow("%SetNamedProperty(other, 'y', 'foo')");
  static_assert(static_cast<int>(i::LanguageMode::kSloppy) == 0);
  static_assert(static_cast<int>(i::LanguageMode::kStrict) == 1);
  CheckCorrectThrow("%DeleteProperty(other, 'x', 0)");  // 0 == SLOPPY
  CheckCorrectThrow("%DeleteProperty(other, 'x', 1)");  // 1 == STRICT
  CheckCorrectThrow("%DeleteProperty(other, '1', 0)");
  CheckCorrectThrow("%DeleteProperty(other, '1', 1)");
  CheckCorrectThrow("Object.prototype.hasOwnProperty.call(other, 'x')");
  CheckCorrectThrow("%HasProperty(other, 'x')");
  CheckCorrectThrow("Object.prototype.propertyIsEnumerable(other, 'x')");
  // PROPERTY_ATTRIBUTES_NONE = 0
  CheckCorrectThrow("%DefineAccessorPropertyUnchecked("
                        "other, 'x', null, null, 1)");

  // Reset the failed access check callback so it does not influence
  // the other tests.
  isolate->SetFailedAccessCheckCallbackFunction(nullptr);
}

class RequestInterruptTestBase {
 public:
  RequestInterruptTestBase()
      : env_(),
        isolate_(env_->GetIsolate()),
        sem_(0),
        warmup_(20000),
        should_continue_(true) {
  }

  virtual ~RequestInterruptTestBase() = default;

  virtual void StartInterruptThread() = 0;

  virtual void TestBody() = 0;

  void RunTest() {
    StartInterruptThread();

    v8::HandleScope handle_scope(isolate_);

    TestBody();

    // Verify we arrived here because interruptor was called
    // not due to a bug causing us to exit the loop too early.
    CHECK(!should_continue());
  }

  void WakeUpInterruptor() {
    sem_.Signal();
  }

  bool should_continue() const { return should_continue_; }

  bool ShouldContinue() {
    if (warmup_ > 0) {
      if (--warmup_ == 0) {
        WakeUpInterruptor();
      }
    }

    return should_continue_;
  }

  static void ShouldContinueCallback(
      const v8::FunctionCallbackInfo<Value>& info) {
    RequestInterruptTestBase* test =
        reinterpret_cast<RequestInterruptTestBase*>(
            info.Data().As<v8::External>()->Value());
    info.GetReturnValue().Set(test->ShouldContinue());
  }

  LocalContext env_;
  v8::Isolate* isolate_;
  v8::base::Semaphore sem_;
  int warmup_;
  bool should_continue_;
};


class RequestInterruptTestBaseWithSimpleInterrupt
    : public RequestInterruptTestBase {
 public:
  RequestInterruptTestBaseWithSimpleInterrupt() : i_thread(this) { }

  void StartInterruptThread() override { CHECK(i_thread.Start()); }

 private:
  class InterruptThread : public v8::base::Thread {
   public:
    explicit InterruptThread(RequestInterruptTestBase* test)
        : Thread(Options("RequestInterruptTest")), test_(test) {}

    void Run() override {
      test_->sem_.Wait();
      test_->isolate_->RequestInterrupt(&OnInterrupt, test_);
    }

    static void OnInterrupt(v8::Isolate* isolate, void* data) {
      reinterpret_cast<RequestInterruptTestBase*>(data)->
          should_con
"""


```