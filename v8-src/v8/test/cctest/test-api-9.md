Response: The user wants a summary of the C++ code provided in the file `v8/test/cctest/test-api.cc`.
The code seems to be testing various V8 API functionalities, particularly those related to:
- Promises (rejection callbacks, hooks, states)
- Error handling and stack traces
- Heap statistics
- External strings
- Script origins and function properties (inferred name, debug name, script position, line number, column number, script ID)

Since the user asked about the relationship with JavaScript, I need to find examples within the code that demonstrate how these C++ API features are related to JavaScript constructs.

**Plan:**
1. Summarize the main functionalities tested in the code.
2. Identify the sections related to promises and provide a JavaScript example illustrating the `PromiseRejectCallback`.
3. Identify sections related to script origins and function properties and provide a JavaScript example illustrating how `GetScriptLineNumber` and `GetScriptColumnNumber` in C++ relate to the source code in JavaScript.
这个C++代码文件 `v8/test/cctest/test-api.cc` 的主要功能是**测试 V8 JavaScript 引擎提供的各种 C++ API 的功能**。 由于这是一个测试文件，它的目的是验证 V8 的 API 是否按照预期工作，涵盖了 V8 引擎的多个核心特性。

从代码片段中可以看出，它主要测试了以下几个方面的功能：

1. **Promise 相关的 API：**
   - 测试了 `PromiseRejectCallback` 的工作机制，包括 Promise 被拒绝的不同状态（例如，没有 handler，handler 添加在 reject 之后等）下回调函数的触发情况，以及回调函数中可以获取的信息（例如，拒绝的值，拒绝的 Promise 对象）。
   - 测试了 `PromiseHook`，用于在 Promise 的生命周期中的不同阶段（初始化、解决、执行前、执行后）接收通知，以便进行调试和监控。
   - 测试了 `Promise::MarkAsHandled` 的功能，用于标记一个被拒绝的 Promise 已被处理，从而避免触发 `PromiseRejectCallback`。

2. **错误处理和调用栈相关的 API：**
   - 测试了当 Promise 在构造函数中抛出错误或者在 `then/catch` 中抛出错误时，`PromiseRejectCallback` 如何获取错误信息，包括错误发生的行号和列号。
   - 测试了 `Isolate::SetCaptureStackTraceForUncaughtExceptions` 的影响，以及如何在 Promise 拒绝回调中获取更详细的调用栈信息。
   - 测试了 `v8::TryCatch` 的使用，以及如何通过 `Message` 对象获取更详细的错误信息，包括 `GetScriptOrigin().ResourceName()`（通常是 sourceURL）。

3. **堆统计相关的 API：**
   - 测试了 `Isolate::GetHeapStatistics` 和 `Isolate::GetHeapSpaceStatistics`，用于获取 V8 堆的各种统计信息，例如总堆大小、已用堆大小、本地上下文的数量、分离上下文的数量等。

4. **外部字符串相关的 API：**
   - 测试了如何创建和管理外部字符串（`v8::String::NewExternalOneByte`， `MakeExternal`），这些字符串的数据存储在 V8 堆外，可以用于优化内存使用。
   - 测试了外部字符串在垃圾回收时的生命周期管理。

5. **脚本和函数相关的 API：**
   - 测试了 `v8::ScriptOrigin` 的使用，它允许指定脚本的来源信息，例如资源名称（URL）、行偏移、列偏移等。
   - 测试了 `v8::Function::GetScriptOrigin()`，用于获取函数定义所在的脚本的来源信息。
   - 测试了 `v8::Function::GetScriptLineNumber()` 和 `v8::Function::GetScriptColumnNumber()`，用于获取函数定义在脚本中的行号和列号。
   - 测试了 `v8::Function::GetInferredName()` 和 `v8::Function::GetDebugName()`，用于获取函数的推断名称和调试名称。
   - 测试了 `v8::Function::GetScriptId()`，用于获取函数所在脚本的 ID。

6. **其他 API：**
   - 测试了 `Isolate::SetStackLimit()`，用于设置 JavaScript 调用的堆栈大小限制。
   - 测试了 `v8::Value::ToString()` 在 `TryCatch` 中的异常处理。

**与 JavaScript 的关系及举例说明：**

这个 C++ 测试文件直接测试了 V8 引擎暴露给 C++ 的 API。这些 API 是 JavaScript 功能的底层实现。例如，Promise 是 JavaScript 的核心异步编程概念，而 `PromiseRejectCallback` 和 `PromiseHook` 等 C++ API 允许开发者在 V8 引擎层面监控和干预 Promise 的行为。

**PromiseRejectCallback 的 JavaScript 例子：**

在 JavaScript 中，当一个 Promise 被拒绝且没有提供拒绝处理程序（例如 `catch` 方法）时，V8 引擎会触发 `PromiseRejectCallback`。

```javascript
// 在 C++ 测试代码中，我们通过 JavaScript 代码来触发 Promise 的拒绝：
// CompileRun("reject('ppp');");

// 在 JavaScript 中，一个 Promise 被拒绝的例子：
let myPromise = new Promise((resolve, reject) => {
  // 模拟一个异步操作失败
  setTimeout(() => {
    reject("Something went wrong!");
  }, 100);
});

// 如果没有提供 catch 处理拒绝，V8 引擎的 PromiseRejectCallback 会被调用。
// myPromise.then(() => { /* 成功处理 */ });
```

在 C++ 的 `PromiseRejectCallback` 中，你可以获取到 "Something went wrong!" 这个拒绝的值。

**ScriptOrigin 和函数属性的 JavaScript 例子：**

C++ 代码中测试了如何通过 `GetScriptLineNumber()` 和 `GetScriptColumnNumber()` 获取函数在脚本中的位置。这直接对应于 JavaScript 代码的结构。

```javascript
// C++ 测试代码中编译并运行了以下 JavaScript 代码：
// v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");

function f() { // 第 1 行
  // ...
}

function g() { // 第 3 行
  // ...
}

// 在 C++ 的测试中，当获取函数 f 和 g 的 ScriptLineNumber 时，
// 应该分别得到 0 和 2（因为行号是从 0 开始的）。

// C++ 中获取 ScriptColumnNumber 测试的 JavaScript 代码：
// v8::Local<v8::String> script =
//     v8_str("function foo() {}\n\n     function bar() {}");

function foo() { // 第 1 行，"function foo" 从第 0 列开始，函数体 "{" 从第 14 列开始
  // ...
}

     function bar() { // 第 3 行，"function bar" 前面有 5 个空格，所以 "function bar" 从第 5 列开始，函数体 "{" 从第 17 列开始
  // ...
}

// 在 C++ 的测试中，当获取函数 foo 和 bar 的 ScriptColumnNumber 时，
// 应该分别得到 14 和 17。
```

总结来说，这个 C++ 测试文件是 V8 引擎内部测试框架的一部分，用于确保其 C++ API 的正确性和稳定性，而这些 API 直接支撑着 JavaScript 的各种功能和特性。第 10 部分，共 18 部分，意味着这是 V8 引擎 API 测试的一个模块，涵盖了特定范围的功能测试。

Prompt: 
```
这是目录为v8/test/cctest/test-api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第10部分，共18部分，请归纳一下它的功能

"""
ck_trace->GetFrame(CcTest::isolate(), 0)->GetColumn();
        } else {
          promise_reject_line_number = -1;
          promise_reject_column_number = -1;
        }
      }
      break;
    }
    case v8::kPromiseHandlerAddedAfterReject: {
      promise_revoke_counter++;
      global->Set(context, v8_str("revoked"), reject_message.GetPromise())
          .FromJust();
      CHECK(reject_message.GetValue().IsEmpty());
      break;
    }
    case v8::kPromiseRejectAfterResolved: {
      promise_reject_after_resolved_counter++;
      break;
    }
    case v8::kPromiseResolveAfterResolved: {
      promise_resolve_after_resolved_counter++;
      break;
    }
  }
}


v8::Local<v8::Promise> GetPromise(const char* name) {
  return v8::Local<v8::Promise>::Cast(
      CcTest::global()
          ->Get(CcTest::isolate()->GetCurrentContext(), v8_str(name))
          .ToLocalChecked());
}


v8::Local<v8::Value> RejectValue() {
  return CcTest::global()
      ->Get(CcTest::isolate()->GetCurrentContext(), v8_str("value"))
      .ToLocalChecked();
}


void ResetPromiseStates() {
  promise_reject_counter = 0;
  promise_revoke_counter = 0;
  promise_reject_after_resolved_counter = 0;
  promise_resolve_after_resolved_counter = 0;
  promise_reject_msg_line_number = -1;
  promise_reject_msg_column_number = -1;
  promise_reject_line_number = -1;
  promise_reject_column_number = -1;
  promise_reject_frame_count = -1;

  v8::Local<v8::Object> global = CcTest::global();
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  global->Set(context, v8_str("rejected"), v8_str("")).FromJust();
  global->Set(context, v8_str("value"), v8_str("")).FromJust();
  global->Set(context, v8_str("revoked"), v8_str("")).FromJust();
}


TEST(PromiseRejectCallback) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPromiseRejectCallback(PromiseRejectCallback);

  ResetPromiseStates();

  // Create promise p0.
  CompileRun(
      "var reject;            \n"
      "var p0 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reject = rej;      \n"
      "  }                    \n"
      ");                     \n");
  CHECK(!GetPromise("p0")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Add resolve handler (and default reject handler) to p0.
  CompileRun("var p1 = p0.then(function(){});");
  CHECK(GetPromise("p0")->HasHandler());
  CHECK(!GetPromise("p1")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Reject p0.
  CompileRun("reject('ppp');");
  CHECK(GetPromise("p0")->HasHandler());
  CHECK(!GetPromise("p1")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(v8::kPromiseRejectWithNoHandler, reject_event);
  CHECK(
      GetPromise("rejected")->Equals(env.local(), GetPromise("p1")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("ppp")).FromJust());

  // Reject p0 again. Callback is not triggered again.
  CompileRun("reject();");
  CHECK(GetPromise("p0")->HasHandler());
  CHECK(!GetPromise("p1")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Add resolve handler to p1.
  CompileRun("var p2 = p1.then(function(){});");
  CHECK(GetPromise("p0")->HasHandler());
  CHECK(GetPromise("p1")->HasHandler());
  CHECK(!GetPromise("p2")->HasHandler());
  CHECK_EQ(2, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);
  CHECK(
      GetPromise("rejected")->Equals(env.local(), GetPromise("p2")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("ppp")).FromJust());
  CHECK(
      GetPromise("revoked")->Equals(env.local(), GetPromise("p1")).FromJust());

  ResetPromiseStates();

  // Create promise q0.
  CompileRun(
      "var q0 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reject = rej;      \n"
      "  }                    \n"
      ");                     \n");
  CHECK(!GetPromise("q0")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Add reject handler to q0.
  CompileRun("var q1 = q0.catch(function() {});");
  CHECK(GetPromise("q0")->HasHandler());
  CHECK(!GetPromise("q1")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Reject q0.
  CompileRun("reject('qq')");
  CHECK(GetPromise("q0")->HasHandler());
  CHECK(!GetPromise("q1")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Add a new reject handler, which rejects by returning Promise.reject().
  // The returned promise q_ triggers a reject callback at first, only to
  // revoke it when returning it causes q2 to be rejected.
  CompileRun(
      "var q_;"
      "var q2 = q0.catch(               \n"
      "   function() {                  \n"
      "     q_ = Promise.reject('qqq'); \n"
      "     return q_;                  \n"
      "   }                             \n"
      ");                               \n");
  CHECK(GetPromise("q0")->HasHandler());
  CHECK(!GetPromise("q1")->HasHandler());
  CHECK(!GetPromise("q2")->HasHandler());
  CHECK(GetPromise("q_")->HasHandler());
  CHECK_EQ(2, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);
  CHECK(
      GetPromise("rejected")->Equals(env.local(), GetPromise("q2")).FromJust());
  CHECK(
      GetPromise("revoked")->Equals(env.local(), GetPromise("q_")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("qqq")).FromJust());

  // Add a reject handler to the resolved q1, which rejects by throwing.
  CompileRun(
      "var q3 = q1.then(  \n"
      "   function() {    \n"
      "     throw 'qqqq'; \n"
      "   }               \n"
      ");                 \n");
  CHECK(GetPromise("q0")->HasHandler());
  CHECK(GetPromise("q1")->HasHandler());
  CHECK(!GetPromise("q2")->HasHandler());
  CHECK(!GetPromise("q3")->HasHandler());
  CHECK_EQ(3, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);
  CHECK(
      GetPromise("rejected")->Equals(env.local(), GetPromise("q3")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("qqqq")).FromJust());

  ResetPromiseStates();

  // Create promise r0, which has three handlers, two of which handle rejects.
  CompileRun(
      "var r0 = new Promise(             \n"
      "  function(res, rej) {            \n"
      "    reject = rej;                 \n"
      "  }                               \n"
      ");                                \n"
      "var r1 = r0.catch(function() {}); \n"
      "var r2 = r0.then(function() {});  \n"
      "var r3 = r0.then(function() {},   \n"
      "                 function() {});  \n");
  CHECK(GetPromise("r0")->HasHandler());
  CHECK(!GetPromise("r1")->HasHandler());
  CHECK(!GetPromise("r2")->HasHandler());
  CHECK(!GetPromise("r3")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Reject r0.
  CompileRun("reject('rrr')");
  CHECK(GetPromise("r0")->HasHandler());
  CHECK(!GetPromise("r1")->HasHandler());
  CHECK(!GetPromise("r2")->HasHandler());
  CHECK(!GetPromise("r3")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK(
      GetPromise("rejected")->Equals(env.local(), GetPromise("r2")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("rrr")).FromJust());

  // Add reject handler to r2.
  CompileRun("var r4 = r2.catch(function() {});");
  CHECK(GetPromise("r0")->HasHandler());
  CHECK(!GetPromise("r1")->HasHandler());
  CHECK(GetPromise("r2")->HasHandler());
  CHECK(!GetPromise("r3")->HasHandler());
  CHECK(!GetPromise("r4")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);
  CHECK(
      GetPromise("revoked")->Equals(env.local(), GetPromise("r2")).FromJust());
  CHECK(RejectValue()->Equals(env.local(), v8_str("rrr")).FromJust());

  // Add reject handlers to r4.
  CompileRun("var r5 = r4.then(function() {}, function() {});");
  CHECK(GetPromise("r0")->HasHandler());
  CHECK(!GetPromise("r1")->HasHandler());
  CHECK(GetPromise("r2")->HasHandler());
  CHECK(!GetPromise("r3")->HasHandler());
  CHECK(GetPromise("r4")->HasHandler());
  CHECK(!GetPromise("r5")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);

  ResetPromiseStates();

  // Create promise s0, which has three handlers, none of which handle rejects.
  CompileRun(
      "var s0 = new Promise(            \n"
      "  function(res, rej) {           \n"
      "    reject = rej;                \n"
      "  }                              \n"
      ");                               \n"
      "var s1 = s0.then(function() {}); \n"
      "var s2 = s0.then(function() {}); \n"
      "var s3 = s0.then(function() {}); \n");
  CHECK(GetPromise("s0")->HasHandler());
  CHECK(!GetPromise("s1")->HasHandler());
  CHECK(!GetPromise("s2")->HasHandler());
  CHECK(!GetPromise("s3")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Reject s0.
  CompileRun("reject('sss')");
  CHECK(GetPromise("s0")->HasHandler());
  CHECK(!GetPromise("s1")->HasHandler());
  CHECK(!GetPromise("s2")->HasHandler());
  CHECK(!GetPromise("s3")->HasHandler());
  CHECK_EQ(3, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK(RejectValue()->Equals(env.local(), v8_str("sss")).FromJust());

  ResetPromiseStates();

  // Swallowed exceptions in the Promise constructor.
  CompileRun(
      "var v0 = new Promise(\n"
      "  function(res, rej) {\n"
      "    res(1);\n"
      "    throw new Error();\n"
      "  }\n"
      ");\n");
  CHECK(!GetPromise("v0")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(1, promise_reject_after_resolved_counter);
  CHECK_EQ(0, promise_resolve_after_resolved_counter);

  ResetPromiseStates();

  // Duplication resolve.
  CompileRun(
      "var r;\n"
      "var y0 = new Promise(\n"
      "  function(res, rej) {\n"
      "    r = res;\n"
      "    throw new Error();\n"
      "  }\n"
      ");\n"
      "r(1);\n");
  CHECK(!GetPromise("y0")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(0, promise_reject_after_resolved_counter);
  CHECK_EQ(1, promise_resolve_after_resolved_counter);

  // Test stack frames.
  env->GetIsolate()->SetCaptureStackTraceForUncaughtExceptions(true);

  ResetPromiseStates();

  // Create promise t0, which is rejected in the constructor with an error.
  CompileRunWithOrigin(
      "var t0 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reference_error;   \n"
      "  }                    \n"
      ");                     \n",
      "pro", 0, 0);
  CHECK(!GetPromise("t0")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(2, promise_reject_frame_count);
  CHECK_EQ(3, promise_reject_line_number);
  CHECK_EQ(5, promise_reject_column_number);
  CHECK_EQ(3, promise_reject_msg_line_number);
  CHECK_EQ(5, promise_reject_msg_column_number);

  ResetPromiseStates();

  // Create promise u0 and chain u1 to it, which is rejected via throw.
  CompileRunWithOrigin(
      "var u0 = Promise.resolve();        \n"
      "var u1 = u0.then(                  \n"
      "           function() {            \n"
      "             (function() {         \n"
      "                throw new Error(); \n"
      "              })();                \n"
      "           }                       \n"
      "         );                        \n",
      "pro", 0, 0);
  CHECK(GetPromise("u0")->HasHandler());
  CHECK(!GetPromise("u1")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(2, promise_reject_frame_count);
  CHECK_EQ(5, promise_reject_line_number);
  CHECK_EQ(23, promise_reject_column_number);
  CHECK_EQ(5, promise_reject_msg_line_number);
  CHECK_EQ(23, promise_reject_msg_column_number);

  // Throw in u3, which handles u1's rejection.
  CompileRunWithOrigin(
      "function f() {                \n"
      "  return (function() {        \n"
      "    return new Error();       \n"
      "  })();                       \n"
      "}                             \n"
      "var u2 = Promise.reject(f()); \n"
      "var u3 = u1.catch(            \n"
      "           function() {       \n"
      "             return u2;       \n"
      "           }                  \n"
      "         );                   \n",
      "pro", 0, 0);
  CHECK(GetPromise("u0")->HasHandler());
  CHECK(GetPromise("u1")->HasHandler());
  CHECK(GetPromise("u2")->HasHandler());
  CHECK(!GetPromise("u3")->HasHandler());
  CHECK_EQ(3, promise_reject_counter);
  CHECK_EQ(2, promise_revoke_counter);
  CHECK_EQ(3, promise_reject_frame_count);
  CHECK_EQ(3, promise_reject_line_number);
  CHECK_EQ(12, promise_reject_column_number);
  CHECK_EQ(3, promise_reject_msg_line_number);
  CHECK_EQ(12, promise_reject_msg_column_number);

  ResetPromiseStates();

  // Create promise rejected promise v0, which is incorrectly handled by v1
  // via chaining cycle.
  CompileRunWithOrigin(
      "var v0 = Promise.reject(); \n"
      "var v1 = v0.catch(         \n"
      "           function() {    \n"
      "             return v1;    \n"
      "           }               \n"
      "         );                \n",
      "pro", 0, 0);
  CHECK(GetPromise("v0")->HasHandler());
  CHECK(!GetPromise("v1")->HasHandler());
  CHECK_EQ(2, promise_reject_counter);
  CHECK_EQ(1, promise_revoke_counter);
  CHECK_EQ(0, promise_reject_frame_count);
  CHECK_EQ(-1, promise_reject_line_number);
  CHECK_EQ(-1, promise_reject_column_number);

  ResetPromiseStates();

  // Create promise t1, which rejects by throwing syntax error from eval.
  CompileRunWithOrigin(
      "var t1 = new Promise(   \n"
      "  function(res, rej) {  \n"
      "    var content = '\\n\\\n"
      "      }';               \n"
      "    eval(content);      \n"
      "  }                     \n"
      ");                      \n",
      "pro", 0, 0);
  CHECK(!GetPromise("t1")->HasHandler());
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  CHECK_EQ(2, promise_reject_frame_count);
  CHECK_EQ(5, promise_reject_line_number);
  CHECK_EQ(10, promise_reject_column_number);
  CHECK_EQ(2, promise_reject_msg_line_number);
  CHECK_EQ(7, promise_reject_msg_column_number);
}

TEST(PromiseRejectIsSharedCrossOrigin) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPromiseRejectCallback(PromiseRejectCallback);

  ResetPromiseStates();

  // Create promise p0.
  CompileRun(
      "var reject;            \n"
      "var p0 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reject = rej;      \n"
      "  }                    \n"
      ");                     \n");
  CHECK(!GetPromise("p0")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  // Not set because it's not yet rejected.
  CHECK(!promise_reject_is_shared_cross_origin);

  // Reject p0.
  CompileRun("reject('ppp');");
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  // Not set because the ScriptOriginOptions is from the script.
  CHECK(!promise_reject_is_shared_cross_origin);

  ResetPromiseStates();

  // Create promise p1
  CompileRun(
      "var reject;            \n"
      "var p1 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reject = rej;      \n"
      "  }                    \n"
      ");                     \n");
  CHECK(!GetPromise("p1")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  // Not set because it's not yet rejected.
  CHECK(!promise_reject_is_shared_cross_origin);

  // Add resolve handler (and default reject handler) to p1.
  CompileRun("var p2 = p1.then(function(){});");
  CHECK(GetPromise("p1")->HasHandler());
  CHECK(!GetPromise("p2")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);

  // Reject p1.
  CompileRun("reject('ppp');");
  CHECK_EQ(1, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  // Set because the event is from an empty script.
  CHECK(promise_reject_is_shared_cross_origin);
}

TEST(PromiseRejectMarkAsHandled) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPromiseRejectCallback(PromiseRejectCallback);

  ResetPromiseStates();

  // Create promise p0.
  CompileRun(
      "var reject;            \n"
      "var p0 = new Promise(  \n"
      "  function(res, rej) { \n"
      "    reject = rej;      \n"
      "  }                    \n"
      ");                     \n");
  CHECK(!GetPromise("p0")->HasHandler());
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
  GetPromise("p0")->MarkAsHandled();

  // Reject p0. promise_reject_counter shouldn't be incremented because
  // it's marked as handled.
  CompileRun("reject('ppp');");
  CHECK_EQ(0, promise_reject_counter);
  CHECK_EQ(0, promise_revoke_counter);
}
void PromiseRejectCallbackConstructError(
    v8::PromiseRejectMessage reject_message) {
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  CHECK_EQ(v8::Promise::PromiseState::kRejected,
           reject_message.GetPromise()->State());
  USE(v8::Script::Compile(context, v8_str("new Error('test')"))
          .ToLocalChecked()
          ->Run(context));
}

TEST(PromiseRejectCallbackConstructError) {
  i::v8_flags.allow_natives_syntax = true;
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  isolate->SetPromiseRejectCallback(PromiseRejectCallbackConstructError);

  ResetPromiseStates();
  CompileRun(
      "function f(p) {"
      "    p.catch(() => {});"
      "};"
      "%PrepareFunctionForOptimization(f);"
      "f(Promise.reject());"
      "f(Promise.reject());"
      "%OptimizeFunctionOnNextCall(f);"
      "let p = Promise.reject();"
      "f(p);");
}

void SetPromise(const char* name, v8::Local<v8::Promise> promise) {
  CcTest::global()
      ->Set(CcTest::isolate()->GetCurrentContext(), v8_str(name), promise)
      .FromJust();
}

class PromiseHookData {
 public:
  int before_hook_count = 0;
  int after_hook_count = 0;
  int promise_hook_count = 0;
  int parent_promise_count = 0;
  bool check_value = true;
  std::string promise_hook_value;

  void Reset() {
    before_hook_count = 0;
    after_hook_count = 0;
    promise_hook_count = 0;
    parent_promise_count = 0;
    check_value = true;
    promise_hook_value = "";
  }
};

PromiseHookData* promise_hook_data;

void CustomPromiseHook(v8::PromiseHookType type, v8::Local<v8::Promise> promise,
                       v8::Local<v8::Value> parentPromise) {
  promise_hook_data->promise_hook_count++;
  switch (type) {
    case v8::PromiseHookType::kInit:
      SetPromise("init", promise);

      if (!parentPromise->IsUndefined()) {
        promise_hook_data->parent_promise_count++;
        SetPromise("parent", v8::Local<v8::Promise>::Cast(parentPromise));
      }

      break;
    case v8::PromiseHookType::kResolve:
      SetPromise("resolve", promise);
      break;
    case v8::PromiseHookType::kBefore:
      promise_hook_data->before_hook_count++;
      CHECK(promise_hook_data->before_hook_count >
            promise_hook_data->after_hook_count);
      CHECK(CcTest::global()
                ->Get(CcTest::isolate()->GetCurrentContext(), v8_str("value"))
                .ToLocalChecked()
                ->Equals(CcTest::isolate()->GetCurrentContext(), v8_str(""))
                .FromJust());
      SetPromise("before", promise);
      break;
    case v8::PromiseHookType::kAfter:
      promise_hook_data->after_hook_count++;
      CHECK(promise_hook_data->after_hook_count <=
            promise_hook_data->before_hook_count);
      if (promise_hook_data->check_value) {
        CHECK(
            CcTest::global()
                ->Get(CcTest::isolate()->GetCurrentContext(), v8_str("value"))
                .ToLocalChecked()
                ->Equals(CcTest::isolate()->GetCurrentContext(),
                         v8_str(promise_hook_data->promise_hook_value.c_str()))
                .FromJust());
      }
      SetPromise("after", promise);
      break;
  }
}

TEST(PromiseHook) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);

  v8::Local<v8::Object> global = CcTest::global();
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();

  promise_hook_data = new PromiseHookData();
  isolate->SetPromiseHook(CustomPromiseHook);

  // Test that an initialized promise is passed to init. Other hooks
  // can not have un initialized promise.
  promise_hook_data->check_value = false;
  CompileRun("var p = new Promise(() => {});");

  auto init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  auto init_promise_obj = v8::Local<v8::Promise>::Cast(init_promise);
  CHECK_EQ(init_promise_obj->State(), v8::Promise::PromiseState::kPending);
  CHECK(!init_promise_obj->HasHandler());

  promise_hook_data->Reset();
  promise_hook_data->promise_hook_value = "fulfilled";
  const char* source =
      "var resolve, value = ''; \n"
      "var p = new Promise(r => resolve = r); \n";

  CompileRun(source);
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  CHECK_EQ(1, promise_hook_data->promise_hook_count);
  CHECK_EQ(0, promise_hook_data->parent_promise_count);

  CompileRun("var p1 = p.then(() => { value = 'fulfilled'; }); \n");
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  auto parent_promise = global->Get(context, v8_str("parent")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), init_promise).FromJust());
  CHECK(GetPromise("p")->Equals(env.local(), parent_promise).FromJust());
  CHECK_EQ(2, promise_hook_data->promise_hook_count);
  CHECK_EQ(1, promise_hook_data->parent_promise_count);

  CompileRun("resolve(); \n");
  auto resolve_promise =
      global->Get(context, v8_str("resolve")).ToLocalChecked();
  auto before_promise = global->Get(context, v8_str("before")).ToLocalChecked();
  auto after_promise = global->Get(context, v8_str("after")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), before_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), after_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  CHECK_EQ(6, promise_hook_data->promise_hook_count);

  CompileRun("value = ''; var p2 = p1.then(() => { value = 'fulfilled' }); \n");
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  parent_promise = global->Get(context, v8_str("parent")).ToLocalChecked();
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  before_promise = global->Get(context, v8_str("before")).ToLocalChecked();
  after_promise = global->Get(context, v8_str("after")).ToLocalChecked();
  CHECK(GetPromise("p2")->Equals(env.local(), init_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), parent_promise).FromJust());
  CHECK(GetPromise("p2")->Equals(env.local(), before_promise).FromJust());
  CHECK(GetPromise("p2")->Equals(env.local(), after_promise).FromJust());
  CHECK(GetPromise("p2")->Equals(env.local(), resolve_promise).FromJust());
  CHECK_EQ(10, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  promise_hook_data->promise_hook_value = "rejected";
  source =
      "var reject, value = ''; \n"
      "var p = new Promise((_, r) => reject = r); \n";

  CompileRun(source);
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  CHECK_EQ(1, promise_hook_data->promise_hook_count);
  CHECK_EQ(0, promise_hook_data->parent_promise_count);

  CompileRun("var p1 = p.catch(() => { value = 'rejected'; }); \n");
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  parent_promise = global->Get(context, v8_str("parent")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), init_promise).FromJust());
  CHECK(GetPromise("p")->Equals(env.local(), parent_promise).FromJust());
  CHECK_EQ(2, promise_hook_data->promise_hook_count);
  CHECK_EQ(1, promise_hook_data->parent_promise_count);

  CompileRun("reject(); \n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  before_promise = global->Get(context, v8_str("before")).ToLocalChecked();
  after_promise = global->Get(context, v8_str("after")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), before_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), after_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  CHECK_EQ(6, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  promise_hook_data->promise_hook_value = "Promise.resolve";
  source =
      "var value = ''; \n"
      "var p = Promise.resolve('Promise.resolve'); \n";

  CompileRun(source);
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  // init hook and resolve hook
  CHECK_EQ(2, promise_hook_data->promise_hook_count);
  CHECK_EQ(0, promise_hook_data->parent_promise_count);
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), resolve_promise).FromJust());

  CompileRun("var p1 = p.then((v) => { value = v; }); \n");
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  parent_promise = global->Get(context, v8_str("parent")).ToLocalChecked();
  before_promise = global->Get(context, v8_str("before")).ToLocalChecked();
  after_promise = global->Get(context, v8_str("after")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), init_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  CHECK(GetPromise("p")->Equals(env.local(), parent_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), before_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), after_promise).FromJust());
  CHECK_EQ(6, promise_hook_data->promise_hook_count);
  CHECK_EQ(1, promise_hook_data->parent_promise_count);

  promise_hook_data->Reset();
  source =
      "var resolve, value = ''; \n"
      "var p = new Promise((_, r) => resolve = r); \n";

  CompileRun(source);
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  CHECK_EQ(1, promise_hook_data->promise_hook_count);
  CHECK_EQ(0, promise_hook_data->parent_promise_count);

  CompileRun("resolve(); \n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), resolve_promise).FromJust());
  CHECK_EQ(2, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  source =
      "var reject, value = ''; \n"
      "var p = new Promise((_, r) => reject = r); \n";

  CompileRun(source);
  init_promise = global->Get(context, v8_str("init")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), init_promise).FromJust());
  CHECK_EQ(1, promise_hook_data->promise_hook_count);
  CHECK_EQ(0, promise_hook_data->parent_promise_count);

  CompileRun("reject(); \n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  CHECK(GetPromise("p")->Equals(env.local(), resolve_promise).FromJust());
  CHECK_EQ(2, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  // This test triggers after callbacks right after each other, so
  // lets just check the value at the end.
  promise_hook_data->check_value = false;
  promise_hook_data->promise_hook_value = "Promise.all";
  source =
      "var resolve, value = ''; \n"
      "var tempPromise = new Promise(r => resolve = r); \n"
      "var p = Promise.all([tempPromise]);\n "
      "var p1 = p.then(v => value = v[0]); \n";

  CompileRun(source);
  // 1) init hook (tempPromise)
  // 2) init hook (p)
  // 3) init hook (throwaway Promise in Promise.all, p)
  // 4) init hook (p1, p)
  CHECK_EQ(4, promise_hook_data->promise_hook_count);
  CHECK_EQ(2, promise_hook_data->parent_promise_count);

  promise_hook_data->promise_hook_value = "Promise.all";
  CompileRun("resolve('Promise.all'); \n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  // 5) resolve hook (tempPromise)
  // 6) resolve hook (throwaway Promise in Promise.all)
  // 6) before hook (throwaway Promise in Promise.all)
  // 7) after hook (throwaway Promise in Promise.all)
  // 8) before hook (p)
  // 9) after hook (p)
  // 10) resolve hook (p1)
  // 11) before hook (p1)
  // 12) after hook (p1)
  CHECK_EQ(12, promise_hook_data->promise_hook_count);
  CHECK(CcTest::global()
            ->Get(CcTest::isolate()->GetCurrentContext(), v8_str("value"))
            .ToLocalChecked()
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8_str(promise_hook_data->promise_hook_value.c_str()))
            .FromJust());

  promise_hook_data->Reset();
  // This test triggers after callbacks right after each other, so
  // lets just check the value at the end.
  promise_hook_data->check_value = false;
  promise_hook_data->promise_hook_value = "Promise.race";
  source =
      "var resolve, value = ''; \n"
      "var tempPromise = new Promise(r => resolve = r); \n"
      "var p = Promise.race([tempPromise]);\n "
      "var p1 = p.then(v => value = v); \n";

  CompileRun(source);
  // 1) init hook (tempPromise)
  // 2) init hook (p)
  // 3) init hook (throwaway Promise in Promise.race, p)
  // 4) init hook (p1, p)
  CHECK_EQ(4, promise_hook_data->promise_hook_count);
  CHECK_EQ(2, promise_hook_data->parent_promise_count);

  promise_hook_data->promise_hook_value = "Promise.race";
  CompileRun("resolve('Promise.race'); \n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  // 5) resolve hook (tempPromise)
  // 6) resolve hook (throwaway Promise in Promise.race)
  // 6) before hook (throwaway Promise in Promise.race)
  // 7) after hook (throwaway Promise in Promise.race)
  // 8) before hook (p)
  // 9) after hook (p)
  // 10) resolve hook (p1)
  // 11) before hook (p1)
  // 12) after hook (p1)
  CHECK_EQ(12, promise_hook_data->promise_hook_count);
  CHECK(CcTest::global()
            ->Get(CcTest::isolate()->GetCurrentContext(), v8_str("value"))
            .ToLocalChecked()
            ->Equals(CcTest::isolate()->GetCurrentContext(),
                     v8_str(promise_hook_data->promise_hook_value.c_str()))
            .FromJust());

  promise_hook_data->Reset();
  promise_hook_data->promise_hook_value = "subclass";
  source =
      "var resolve, value = '';\n"
      "class MyPromise extends Promise { \n"
      "  then(onFulfilled, onRejected) { \n"
      "      return super.then(onFulfilled, onRejected); \n"
      "  };\n"
      "};\n"
      "var p = new MyPromise(r => resolve = r);\n";

  CompileRun(source);
  // 1) init hook (p)
  CHECK_EQ(1, promise_hook_data->promise_hook_count);

  CompileRun("var p1 = p.then(() => value = 'subclass');\n");
  // 2) init hook (p1)
  CHECK_EQ(2, promise_hook_data->promise_hook_count);

  CompileRun("resolve();\n");
  resolve_promise = global->Get(context, v8_str("resolve")).ToLocalChecked();
  before_promise = global->Get(context, v8_str("before")).ToLocalChecked();
  after_promise = global->Get(context, v8_str("after")).ToLocalChecked();
  CHECK(GetPromise("p1")->Equals(env.local(), before_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), after_promise).FromJust());
  CHECK(GetPromise("p1")->Equals(env.local(), resolve_promise).FromJust());
  // 3) resolve hook (p)
  // 4) before hook (p)
  // 5) after hook (p)
  // 6) resolve hook (p1)
  CHECK_EQ(6, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  source =
      "class X extends Promise {\n"
      "  static get [Symbol.species]() {\n"
      "    return Y;\n"
      "  }\n"
      "}\n"
      "class Y {\n"
      "  constructor(executor) {\n"
      "    return new Proxy(new Promise(executor), {});\n"
      "  }\n"
      "}\n"
      "var x = X.resolve().then(() => {});\n";

  CompileRun(source);

  promise_hook_data->Reset();
  source =
      "var resolve, value = '';\n"
      "var p = new Promise(r => resolve = r);\n";

  CompileRun(source);
  CHECK_EQ(v8::Promise::kPending, GetPromise("p")->State());
  CompileRun("resolve(Promise.resolve(value));\n");
  CHECK_EQ(v8::Promise::kFulfilled, GetPromise("p")->State());
  CHECK_EQ(11, promise_hook_data->promise_hook_count);

  promise_hook_data->Reset();
  source =
      "var p = Promise.resolve({\n"
      "  then(r) {\n"
      "    r();\n"
      "  }\n"
      "});";
  CompileRun(source);
  CHECK_EQ(GetPromise("p")->State(), v8::Promise::kFulfilled);
  CHECK_EQ(promise_hook_data->promise_hook_count, 5);

  delete promise_hook_data;
  isolate->SetPromiseHook(nullptr);
}


TEST(EvalWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function foo() { FAIL.FAIL; }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  foo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}


TEST(RecursionWithSourceURLInMessageScriptResourceNameOrSourceURL) {
  LocalContext context;
  v8::HandleScope scope(context->GetIsolate());

  const char *source =
    "function outer() {\n"
    "  var scriptContents = \"function boo(){ boo(); }\\\n"
    "  //# sourceURL=source_url\";\n"
    "  eval(scriptContents);\n"
    "  boo(); }\n"
    "outer();\n"
    "//# sourceURL=outer_url";

  v8::TryCatch try_catch(context->GetIsolate());
  CompileRun(source);
  CHECK(try_catch.HasCaught());

  Local<v8::Message> message = try_catch.Message();
  Local<Value> sourceURL = message->GetScriptOrigin().ResourceName();
  CHECK_EQ(0, strcmp(*v8::String::Utf8Value(context->GetIsolate(), sourceURL),
                     "source_url"));
}


TEST(Regress2333) {
  LocalContext env;
  for (int i = 0; i < 3; i++) {
    i::heap::InvokeMinorGC(CcTest::heap());
  }
}

static uint32_t* stack_limit;

static void GetStackLimitCallback(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  stack_limit = reinterpret_cast<uint32_t*>(
      CcTest::i_isolate()->stack_guard()->real_climit());
}


// Uses the address of a local variable to determine the stack top now.
// Given a size, returns an address that is that far from the current
// top of stack.
static uint32_t* ComputeStackLimit(uint32_t size) {
  // Disable the gcc error which (very correctly) notes that this is an
  // out-of-bounds access.
#if V8_CC_GNU
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif  // V8_CC_GNU
  uint32_t* answer = &size - (size / sizeof(size));
#if V8_CC_GNU
#pragma GCC diagnostic pop
#endif  // V8_CC_GNU
  // If the size is very large and the stack is very near the bottom of
  // memory then the calculation above may wrap around and give an address
  // that is above the (downwards-growing) stack.  In that case we return
  // a very low address.
  if (answer > &size) return reinterpret_cast<uint32_t*>(sizeof(size));
  return answer;
}


// We need at least 165kB for an x64 debug build with clang and ASAN.
static const int stack_breathing_room = 256 * i::KB;


TEST(SetStackLimit) {
  uint32_t* set_limit = ComputeStackLimit(stack_breathing_room);

  // Set stack limit.
  CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

  // Execute a script.
  LocalContext env;
  v8::HandleScope scope(env->GetIsolate());
  Local<v8::FunctionTemplate> fun_templ =
      v8::FunctionTemplate::New(env->GetIsolate(), GetStackLimitCallback);
  Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
  CHECK(env->Global()
            ->Set(env.local(), v8_str("get_stack_limit"), fun)
            .FromJust());
  CompileRun("get_stack_limit();");

  CHECK(stack_limit == set_limit);
}


TEST(SetStackLimitInThread) {
  uint32_t* set_limit;
  {
    v8::Locker locker(CcTest::isolate());
    set_limit = ComputeStackLimit(stack_breathing_room);

    // Set stack limit.
    CcTest::isolate()->SetStackLimit(reinterpret_cast<uintptr_t>(set_limit));

    // Execute a script.
    v8::HandleScope scope(CcTest::isolate());
    LocalContext env;
    Local<v8::FunctionTemplate> fun_templ =
        v8::FunctionTemplate::New(CcTest::isolate(), GetStackLimitCallback);
    Local<Function> fun = fun_templ->GetFunction(env.local()).ToLocalChecked();
    CHECK(env->Global()
              ->Set(env.local(), v8_str("get_stack_limit"), fun)
              .FromJust());
    CompileRun("get_stack_limit();");

    CHECK(stack_limit == set_limit);
  }
  {
    v8::Locker locker(CcTest::isolate());
    CHECK(stack_limit == set_limit);
  }
}

THREADED_TEST(GetHeapStatistics) {
  LocalContext c1;
  v8::HandleScope scope(c1->GetIsolate());
  v8::HeapStatistics heap_statistics;
  CHECK_EQ(0u, heap_statistics.total_heap_size());
  CHECK_EQ(0u, heap_statistics.used_heap_size());
  c1->GetIsolate()->GetHeapStatistics(&heap_statistics);
  CHECK_NE(static_cast<int>(heap_statistics.total_heap_size()), 0);
}

TEST(GetHeapSpaceStatistics) {
  // This test is incompatible with concurrent allocation, which may occur
  // while collecting the statistics and break the final `CHECK_EQ`s.
  if (i::v8_flags.stress_concurrent_allocation) return;

  LocalContext c1;
  v8::Isolate* isolate = c1->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::HeapStatistics heap_statistics;

  // Force allocation in LO_SPACE and TRUSTED_LO_SPACE so that every space has
  // non-zero size.
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  auto unused = i_isolate->factory()->TryNewFixedArray(512 * 1024,
                                                       i::AllocationType::kOld);
  USE(unused);

  isolate->GetHeapStatistics(&heap_statistics);

  // Ensure that the sum of all the spaces matches the totals from
  // GetHeapSpaceStatistics.
  size_t total_size = 0u;
  size_t total_used_size = 0u;
  size_t total_available_size = 0u;
  size_t total_physical_size = 0u;
  for (size_t i = 0; i < isolate->NumberOfHeapSpaces(); ++i) {
    v8::HeapSpaceStatistics space_statistics;
    isolate->GetHeapSpaceStatistics(&space_statistics, i);
    CHECK_NOT_NULL(space_statistics.space_name());
    total_size += space_statistics.space_size();
    total_used_size += space_statistics.space_used_size();
    total_available_size += space_statistics.space_available_size();
    total_physical_size += space_statistics.physical_space_size();
  }
  total_available_size += CcTest::heap()->memory_allocator()->Available();

  CHECK_EQ(total_size, heap_statistics.total_heap_size());
  CHECK_EQ(total_used_size, heap_statistics.used_heap_size());
  CHECK_EQ(total_available_size, heap_statistics.total_available_size());
  CHECK_EQ(total_physical_size, heap_statistics.total_physical_size());
}

TEST(NumberOfNativeContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_native_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    context[i].Reset(CcTest::isolate(), v8::Context::New(CcTest::isolate()));
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_native_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_native_contexts());
  }
}

TEST(NumberOfDetachedContexts) {
  static const size_t kNumTestContexts = 10;
  i::Isolate* isolate = CcTest::i_isolate();
  i::HandleScope scope(isolate);
  v8::Global<v8::Context> context[kNumTestContexts];
  v8::HeapStatistics heap_statistics;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  CcTest::isolate()->GetHeapStatistics(&heap_statistics);
  CHECK_EQ(0u, heap_statistics.number_of_detached_contexts());
  for (size_t i = 0; i < kNumTestContexts; i++) {
    i::HandleScope inner(isolate);
    v8::Local<v8::Context> local = v8::Context::New(CcTest::isolate());
    context[i].Reset(CcTest::isolate(), local);
    local->DetachGlobal();
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(i + 1, heap_statistics.number_of_detached_contexts());
  }
  for (size_t i = 0; i < kNumTestContexts; i++) {
    context[i].Reset();
    i::heap::InvokeAtomicMajorGC(CcTest::heap());
    CcTest::isolate()->GetHeapStatistics(&heap_statistics);
    CHECK_EQ(kNumTestContexts - i - 1u,
             heap_statistics.number_of_detached_contexts());
  }
}

TEST(ExternalizeOldSpaceTwoByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet ❤️')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestResource* resource = new TestResource(
      AsciiToTwoByteString(u"Romeo Montague Juliet Capulet ❤️"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalTwoByte());
  CHECK(cons->IsExternal());
  CHECK_EQ(resource, cons->GetExternalStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::TWO_BYTE_ENCODING, encoding);
}


TEST(ExternalizeOldSpaceOneByteCons) {
  i::v8_flags.allow_natives_syntax = true;
  v8::Isolate* isolate = CcTest::isolate();
  LocalContext env;
  v8::HandleScope scope(isolate);
  v8::Local<v8::String> cons =
      CompileRun("%ConstructConsString('Romeo Montague ', 'Juliet Capulet')")
          ->ToString(env.local())
          .ToLocalChecked();
  CHECK(IsConsString(*v8::Utils::OpenDirectHandle(*cons)));
  i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  CHECK(CcTest::heap()->old_space()->Contains(
      *v8::Utils::OpenDirectHandle(*cons)));

  TestOneByteResource* resource =
      new TestOneByteResource(i::StrDup("Romeo Montague Juliet Capulet"));
  cons->MakeExternal(isolate, resource);

  CHECK(cons->IsExternalOneByte());
  CHECK_EQ(resource, cons->GetExternalOneByteStringResource());
  String::Encoding encoding;
  CHECK_EQ(resource, cons->GetExternalStringResourceBase(&encoding));
  CHECK_EQ(String::ONE_BYTE_ENCODING, encoding);
}

TEST(ExternalStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    const char* s = "One string to test them all, one string to find them.";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        v8::String::NewExternalOneByte(isolate, inscription).ToLocalChecked();
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}


TEST(ExternalInternalizedStringCollectedAtTearDown) {
  int destroyed = 0;
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  { v8::Isolate::Scope isolate_scope(isolate);
    LocalContext env(isolate);
    v8::HandleScope handle_scope(isolate);
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring =
        CompileRun("ring")->ToString(env.local()).ToLocalChecked();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(isolate, inscription);
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  isolate->Dispose();
  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}


TEST(ExternalInternalizedStringCollectedAtGC) {
  int destroyed = 0;
  { LocalContext env;
    v8::HandleScope handle_scope(env->GetIsolate());
    CompileRun("var ring = 'One string to test them all';");
    const char* s = "One string to test them all";
    TestOneByteResource* inscription =
        new TestOneByteResource(i::StrDup(s), &destroyed);
    v8::Local<v8::String> ring = CompileRun("ring").As<v8::String>();
    CHECK(IsInternalizedString(*v8::Utils::OpenDirectHandle(*ring)));
    ring->MakeExternal(env->GetIsolate(), inscription);
    // Ring is still alive.  Orcs are roaming freely across our lands.
    CHECK_EQ(0, destroyed);
    USE(ring);
  }

  // Garbage collector deals swift blows to evil.
  CcTest::i_isolate()->compilation_cache()->Clear();
  {
    // We need to invoke GC without stack, otherwise the resource may not be
    // reclaimed because of conservative stack scanning.
    i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        CcTest::heap());
    i::heap::InvokeMemoryReducingMajorGCs(CcTest::heap());
  }

  // Ring has been destroyed.  Free Peoples of Middle-earth Rejoice.
  CHECK_EQ(1, destroyed);
}

static double DoubleFromBits(uint64_t value) {
  double target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}


static uint64_t DoubleToBits(double value) {
  uint64_t target;
  i::MemCopy(&target, &value, sizeof(target));
  return target;
}


static double DoubleToDateTime(double input) {
  double date_limit = 864e13;
  if (std::isnan(input) || input < -date_limit || input > date_limit) {
    return std::numeric_limits<double>::quiet_NaN();
  }
  return (input < 0) ? -(std::floor(-input)) : std::floor(input);
}


// We don't have a consistent way to write 64-bit constants syntactically, so we
// split them into two 32-bit constants and combine them programmatically.
static double DoubleFromBits(uint32_t high_bits, uint32_t low_bits) {
  return DoubleFromBits((static_cast<uint64_t>(high_bits) << 32) | low_bits);
}


THREADED_TEST(QuietSignalingNaNs) {
  LocalContext context;
  v8::Isolate* isolate = context->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);

  // Special double values.
  double snan = DoubleFromBits(0x7FF00000, 0x00000001);
  double qnan = DoubleFromBits(0x7FF80000, 0x00000000);
  double infinity = DoubleFromBits(0x7FF00000, 0x00000000);
  double max_normal = DoubleFromBits(0x7FEFFFFF, 0xFFFFFFFFu);
  double min_normal = DoubleFromBits(0x00100000, 0x00000000);
  double max_denormal = DoubleFromBits(0x000FFFFF, 0xFFFFFFFFu);
  double min_denormal = DoubleFromBits(0x00000000, 0x00000001);

  // Date values are capped at +/-100000000 days (times 864e5 ms per day)
  // on either side of the epoch.
  double date_limit = 864e13;

  double test_values[] = {
      snan,
      qnan,
      infinity,
      max_normal,
      date_limit + 1,
      date_limit,
      min_normal,
      max_denormal,
      min_denormal,
      0,
      -0,
      -min_denormal,
      -max_denormal,
      -min_normal,
      -date_limit,
      -date_limit - 1,
      -max_normal,
      -infinity,
      -qnan,
      -snan
  };
  int num_test_values = 20;

  for (int i = 0; i < num_test_values; i++) {
    double test_value = test_values[i];

    // Check that Number::New preserves non-NaNs and quiets SNaNs.
    v8::Local<v8::Value> number = v8::Number::New(isolate, test_value);
    double stored_number = number->NumberValue(context.local()).FromJust();
    if (!std::isnan(test_value)) {
      CHECK_EQ(test_value, stored_number);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_number);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }

    // Check that Date::New preserves non-NaNs in the date range and
    // quiets SNaNs.
    v8::Local<v8::Value> date =
        v8::Date::New(context.local(), test_value).ToLocalChecked();
    double expected_stored_date = DoubleToDateTime(test_value);
    double stored_date = date->NumberValue(context.local()).FromJust();
    if (!std::isnan(expected_stored_date)) {
      CHECK_EQ(expected_stored_date, stored_date);
    } else {
      uint64_t stored_bits = DoubleToBits(stored_date);
      // Check if quiet nan (bits 51..62 all set).
#if (defined(V8_TARGET_ARCH_MIPS64)) && !defined(_MIPS_ARCH_MIPS64R6) && \
    !defined(USE_SIMULATOR)
      // Most significant fraction bit for quiet nan is set to 0
      // on MIPS architecture. Allowed by IEEE-754.
      CHECK_EQ(0xFFE, static_cast<int>((stored_bits >> 51) & 0xFFF));
#else
      CHECK_EQ(0xFFF, static_cast<int>((stored_bits >> 51) & 0xFFF));
#endif
    }
  }
}


static void SpaghettiIncident(
    const v8::FunctionCallbackInfo<v8::Value>& args) {
  v8::HandleScope scope(args.GetIsolate());
  v8::TryCatch tc(args.GetIsolate());
  v8::MaybeLocal<v8::String> str(
      args[0]->ToString(args.GetIsolate()->GetCurrentContext()));
  USE(str);
  if (tc.HasCaught()) {
    CHECK(args.GetIsolate()->HasPendingException());
    tc.ReThrow();
    CHECK(args.GetIsolate()->HasPendingException());
  }
}


// Test that an exception can be propagated down through a spaghetti
// stack using ReThrow.
THREADED_TEST(SpaghettiStackReThrow) {
  v8::Isolate* isolate = CcTest::isolate();
  v8::HandleScope scope(isolate);
  LocalContext context;
  context->Global()
      ->Set(context.local(), v8_str("s"),
            v8::FunctionTemplate::New(isolate, SpaghettiIncident)
                ->GetFunction(context.local())
                .ToLocalChecked())
      .FromJust();
  v8::TryCatch try_catch(isolate);
  CompileRun(
      "var i = 0;"
      "var o = {"
      "  toString: function () {"
      "    if (i == 10) {"
      "      throw 'Hey!';"
      "    } else {"
      "      i++;"
      "      return s(o);"
      "    }"
      "  }"
      "};"
      "s(o);");
  CHECK(try_catch.HasCaught());
  v8::String::Utf8Value value(isolate, try_catch.Exception());
  CHECK_EQ(0, strcmp(*value, "Hey!"));
}


TEST(Regress528) {
  i::ManualGCScope manual_gc_scope;
  v8::Isolate* isolate = CcTest::isolate();
  i::v8_flags.retain_maps_for_n_gc = 0;
  v8::HandleScope scope(isolate);
  int gc_count;

  // In this test, we need to invoke GC without stack, otherwise some objects
  // may not be reclaimed because of conservative stack scanning.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  // Create a context used to keep the code from aging in the compilation
  // cache.
  LocalContext other_context(isolate);

  // Context-dependent context data creates reference from the compilation
  // cache to the global object.
  const char* source_simple = "1";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    Local<v8::String> obj = v8_str("");
    context->SetEmbedderData(0, obj);
    CompileRun(source_simple);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_simple);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Eval in a function creates reference from the compilation cache to the
  // global object.
  const char* source_eval = "function f(){eval('1')}; f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    CompileRun(source_eval);
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_eval);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  // Looking up the line number for an exception creates reference from the
  // compilation cache to the global object.
  const char* source_exception = "function f(){throw 1;} f()";
  {
    v8::HandleScope inner_scope(isolate);
    v8::Local<Context> context = Context::New(isolate);

    context->Enter();
    v8::TryCatch try_catch(isolate);
    CompileRun(source_exception);
    CHECK(try_catch.HasCaught());
    v8::Local<v8::Message> message = try_catch.Message();
    CHECK(!message.IsEmpty());
    CHECK_EQ(1, message->GetLineNumber(context).FromJust());
    context->Exit();
  }
  isolate->ContextDisposedNotification();
  for (gc_count = 1; gc_count < 10; gc_count++) {
    other_context->Enter();
    CompileRun(source_exception);
    other_context->Exit();
    i::heap::InvokeMajorGC(CcTest::heap());
    if (GetGlobalObjectsCount() == 1) break;
  }
  CHECK_GE(2, gc_count);
  CHECK_EQ(1, GetGlobalObjectsCount());

  isolate->ContextDisposedNotification();
}


THREADED_TEST(ScriptOrigin) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  Local<v8::PrimitiveArray> array(v8::PrimitiveArray::New(isolate, 1));
  Local<v8::Symbol> symbol(v8::Symbol::New(isolate));
  array->Set(isolate, 0, symbol);

  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 1, 1, true, -1,
                                             v8_str("http://sourceMapUrl"),
                                             true, false, false, array);
  v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("g")).ToLocalChecked());

  v8::ScriptOrigin script_origin_f = f->GetScriptOrigin();
  CHECK_EQ(0, strcmp("test",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_f.ResourceName())));
  CHECK_EQ(1, script_origin_f.LineOffset());
  CHECK(script_origin_f.Options().IsSharedCrossOrigin());
  CHECK(script_origin_f.Options().IsOpaque());
  printf("is name = %d\n", script_origin_f.SourceMapUrl()->IsUndefined());
  CHECK(script_origin_f.GetHostDefinedOptions()
            .As<v8::PrimitiveArray>()
            ->Get(isolate, 0)
            ->IsSymbol());

  CHECK_EQ(0, strcmp("http://sourceMapUrl",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_f.SourceMapUrl())));

  v8::ScriptOrigin script_origin_g = g->GetScriptOrigin();
  CHECK_EQ(0, strcmp("test",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_g.ResourceName())));
  CHECK_EQ(1, script_origin_g.LineOffset());
  CHECK(script_origin_g.Options().IsSharedCrossOrigin());
  CHECK(script_origin_g.Options().IsOpaque());
  CHECK_EQ(0, strcmp("http://sourceMapUrl",
                     *v8::String::Utf8Value(env->GetIsolate(),
                                            script_origin_g.SourceMapUrl())));
  CHECK(script_origin_g.GetHostDefinedOptions()
            .As<v8::PrimitiveArray>()
            ->Get(isolate, 0)
            ->IsSymbol());
}


THREADED_TEST(FunctionGetInferredName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script =
      v8_str("var foo = { bar : { baz : function() {}}}; var f = foo.bar.baz;");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  CHECK_EQ(0,
           strcmp("foo.bar.baz", *v8::String::Utf8Value(env->GetIsolate(),
                                                        f->GetInferredName())));
}


THREADED_TEST(FunctionGetDebugName) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  const char* code =
      "var error = false;"
      "function a() { this.x = 1; };"
      "Object.defineProperty(a, 'name', {value: 'display_a'});"
      "var b = (function() {"
      "  var f = function() { this.x = 2; };"
      "  Object.defineProperty(f, 'name', {value: 'display_b'});"
      "  return f;"
      "})();"
      "var c = function() {};"
      "c.__defineGetter__('name', function() {"
      "  error = true;"
      "  throw new Error();"
      "});"
      "function d() {};"
      "d.__defineGetter__('name', function() {"
      "  error = true;"
      "  return 'wrong_display_name';"
      "});"
      "function e() {};"
      "Object.defineProperty(e, 'name', {value: 'wrong_display_name'});"
      "e.__defineSetter__('name', function() {"
      "  error = true;"
      "  throw new Error();"
      "});"
      "function f() {};"
      "Object.defineProperty(f, 'name', {value: {foo: 6, toString: function() {"
      "  error = true;"
      "  return 'wrong_display_name';"
      "}}});"
      "var g = function() {"
      "  Object.defineProperty(arguments.callee, 'name', {"
      "    value: 'set_in_runtime'"
      "  });"
      "}; g();"
      "var h = function() {};"
      "h.displayName = 'displayName';"
      "Object.defineProperty(h, 'name', { value: 'function.name' });"
      "var i = function() {};"
      "i.displayName = 239;"
      "Object.defineProperty(i, 'name', { value: 'function.name' });"
      "var j = function() {};"
      "Object.defineProperty(j, 'name', { value: 'function.name' });"
      "var foo = { bar : { baz : (0, function() {})}}; var k = foo.bar.baz;"
      "var foo = { bar : { baz : function() {} }}; var l = foo.bar.baz;";
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Script::Compile(env.local(), v8_str(code), &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Value> error =
      env->Global()->Get(env.local(), v8_str("error")).ToLocalChecked();
  CHECK(!error->BooleanValue(isolate));
  const char* functions[] = {"a", "display_a",
                             "b", "display_b",
                             "c", "c",
                             "d", "d",
                             "e", "e",
                             "f", "f",
                             "g", "set_in_runtime",
                             "h", "function.name",
                             "i", "function.name",
                             "j", "function.name",
                             "k", "foo.bar.baz",
                             "l", "baz"};
  for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]) / 2; ++i) {
    v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
        env->Global()
            ->Get(env.local(),
                  v8::String::NewFromUtf8(isolate, functions[i * 2])
                      .ToLocalChecked())
            .ToLocalChecked());
    std::string expected(functions[i * 2 + 1]);
    std::string actual = *v8::String::Utf8Value(isolate, f->GetDebugName());
    CHECK_EQ(expected, actual);
  }
}


THREADED_TEST(ScriptLineNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 0, 0);
  v8::Local<v8::String> script = v8_str("function f() {}\n\nfunction g() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> f = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("f")).ToLocalChecked());
  v8::Local<v8::Function> g = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("g")).ToLocalChecked());
  CHECK_EQ(0, f->GetScriptLineNumber());
  CHECK_EQ(2, g->GetScriptLineNumber());
}


THREADED_TEST(ScriptColumnNumber) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> script =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(14, foo->GetScriptColumnNumber());
  CHECK_EQ(17, bar->GetScriptColumnNumber());
}

THREADED_TEST(ScriptStartPosition) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> script =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Script::Compile(env.local(), script, &origin)
      .ToLocalChecked()
      ->Run(env.local())
      .ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(12, foo->GetScriptStartPosition());
  CHECK_EQ(36, bar->GetScriptStartPosition());
}

THREADED_TEST(FunctionGetScriptId) {
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  v8::HandleScope scope(isolate);
  v8::ScriptOrigin origin = v8::ScriptOrigin(v8_str("test"), 3, 2);
  v8::Local<v8::String> scriptSource =
      v8_str("function foo() {}\n\n     function bar() {}");
  v8::Local<v8::Script> script(
      v8::Script::Compile(env.local(), scriptSource, &origin).ToLocalChecked());
  script->Run(env.local()).ToLocalChecked();
  v8::Local<v8::Function> foo = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("foo")).ToLocalChecked());
  v8::Local<v8::Function> bar = v8::Local<v8::Function>::Cast(
      env->Global()->Get(env.local(), v8_str("bar")).ToLocalChecked());
  CHECK_EQ(script->GetUnboundScri
"""


```