Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is part of the V8 JavaScript engine's test suite, specifically for testing the Promise API.

Here's a breakdown of the code's functionalities and how to present them:

1. **Identify the core purpose:** The code primarily tests the `PromiseRejectCallback` and `PromiseHook` APIs in V8.

2. **Explain `PromiseRejectCallback`:**
    - Describe what it is: A callback function that V8 calls when a promise is rejected.
    - List the different `PromiseRejectEvent` types it handles and what each means.
    - Explain the global variables used to track the callbacks and promise states.
    - Provide JavaScript examples demonstrating different rejection scenarios and how the callback is triggered.

3. **Explain `PromiseHook`:**
    - Describe what it is: A mechanism to observe the lifecycle of promises.
    - List the different `PromiseHookType` events that can be observed.
    - Explain the `PromiseHookData` structure used to track hook calls.
    - Provide JavaScript examples demonstrating how the hooks are triggered during promise creation, resolution, and rejection.

4. **Address specific instructions:**
    - **`.tq` extension:**  Point out that this file is `.cc`, not `.tq`, so it's C++ not Torque.
    - **JavaScript relation:**  Clearly link the C++ code to the JavaScript Promise API. Provide illustrative JavaScript examples.
    - **Logic inference:** For the callback, show how different JavaScript promise operations lead to different callback events and state changes.
    - **Common programming errors:**  Highlight scenarios like unhandled rejections or rejecting already resolved promises.
    - **Part of a larger series:** Note that this is part 19 of 36, implying a focus on testing specific aspects of the API.

5. **Structure the summary:** Organize the information logically, starting with an overview, then detailing each API with examples.

6. **Review and refine:** Ensure clarity, accuracy, and completeness in the explanation.
这是一个V8源代码文件，位于 `v8/test/cctest/test-api.cc`，它是一个 C++ 文件，用于测试 V8 JavaScript 引擎的 API 功能，特别是关于 `Promise` 相关的 API。

**功能归纳:**

这个代码片段主要测试了 V8 中关于 Promise 拒绝回调（`PromiseRejectCallback`）和 Promise 生命周期钩子（`PromiseHook`）的功能。它通过 C++ 代码模拟 JavaScript 环境，创建 Promise 对象，并执行各种 Promise 操作（resolve, reject, then, catch 等），然后验证 V8 是否正确地触发了相应的回调函数，以及回调函数中接收到的参数是否符合预期。

**具体功能分解:**

1. **Promise 拒绝回调 (`PromiseRejectCallback`):**
   - **功能:** 测试当 Promise 被拒绝时，V8 引擎提供的回调机制。这个回调函数可以捕获 Promise 拒绝事件的类型、拒绝原因、以及相关的 Promise 对象。
   - **测试场景:**  代码中定义了一个全局的 `PromiseRejectCallback` 函数，用于接收和记录 Promise 拒绝消息。测试用例通过不同的 Promise 操作来触发拒绝，并断言回调函数被调用的次数、接收到的事件类型（例如 `kPromiseRejectWithNoHandler`, `kPromiseHandlerAddedAfterReject` 等）、拒绝的值、以及相关的 Promise 对象是否正确。
   - **JavaScript 示例:**
     ```javascript
     let rejectFn;
     let p = new Promise((resolve, reject) => {
       rejectFn = reject;
     });

     p.then(() => {
       console.log("Promise resolved (should not happen)");
     });

     rejectFn("Promise rejected!"); // 触发 Promise 拒绝
     ```
     在这个例子中，如果 `p` 被拒绝，V8 引擎会调用通过 `isolate->SetPromiseRejectCallback` 设置的回调函数。

2. **Promise 生命周期钩子 (`PromiseHook`):**
   - **功能:** 测试 V8 提供的观察 Promise 生命周期事件的钩子机制。这些钩子在 Promise 初始化、resolve、reject 以及执行 then/catch 回调前后被触发。
   - **测试场景:** 代码定义了一个全局的 `CustomPromiseHook` 函数，用于接收和记录 Promise 的各种生命周期事件。测试用例通过创建和操作 Promise，验证不同的钩子函数 (`kInit`, `kResolve`, `kBefore`, `kAfter`) 是否被正确调用，以及传递的 Promise 对象和父 Promise 对象是否正确。
   - **JavaScript 示例:**
     ```javascript
     let p = new Promise((resolve, reject) => {
       // Promise 初始化时会触发 kInit 钩子
     });

     p.then(() => {
       // then 回调执行前触发 kBefore 钩子
       // then 回调执行后触发 kAfter 钩子
       console.log("Promise resolved");
     });

     p.resolve(); // Promise resolve 时会触发 kResolve 钩子
     ```
     在这个例子中，Promise 的创建、`then` 方法的调用和 Promise 的 resolve 都会触发不同的 Promise 钩子。

**代码逻辑推理与假设输入输出:**

假设有以下 JavaScript 代码被 `CompileRun` 执行：

```javascript
var reject;
var p = new Promise((res, rej) => { reject = rej; });
reject("error message");
```

**假设输入:** 上述 JavaScript 代码字符串。

**输出 (基于 `PromiseRejectCallback` 的行为):**

- `promise_reject_counter` 的值会增加 1。
- `reject_event` 的值会是 `v8::kPromiseRejectWithNoHandler`，因为 Promise `p` 在被拒绝时没有 reject handler。
- 全局变量 `rejected` 会被设置为 Promise `p`。
- 全局变量 `value` 会被设置为字符串 `"error message"`。

**用户常见的编程错误示例:**

1. **未处理的 Promise 拒绝 (Unhandled Promise Rejection):**
   ```javascript
   let p = new Promise((resolve, reject) => {
     setTimeout(() => {
       reject("Something went wrong!");
     }, 100);
   });
   // 没有 .catch() 或第二个参数的 .then() 来处理拒绝
   ```
   在这个例子中，Promise `p` 会被拒绝，如果没有相应的 reject handler，V8 的 `PromiseRejectCallback` 会被触发，并且事件类型可能是 `kPromiseRejectWithNoHandler`。

2. **在 Promise resolve 后再次 reject 或 resolve:**
   ```javascript
   let resolveFn;
   let rejectFn;
   let p = new Promise((resolve, reject) => {
     resolveFn = resolve;
     rejectFn = reject;
   });

   resolveFn("Resolved value");
   rejectFn("Rejected value"); // 错误：在 resolve 后又 reject

   let p2 = new Promise((resolve, reject) => {
     resolve("First resolve");
     resolve("Second resolve"); // 错误：重复 resolve
   });
   ```
   代码中测试了 `kPromiseRejectAfterResolved` 和 `kPromiseResolveAfterResolved` 事件，这些事件对应了在 Promise 状态确定后尝试再次改变状态的错误。

**关于 `.tq` 结尾:**

代码注释中提到，如果文件以 `.tq` 结尾，则为 V8 Torque 源代码。但当前文件 `v8/test/cctest/test-api.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而非 Torque 源代码。Torque 是一种用于定义 V8 内部 Builtin 函数的领域特定语言。

**总结第 19 部分的功能:**

作为 36 个部分中的第 19 部分，这个代码片段专注于测试 V8 引擎中关于 Promise 错误处理和生命周期观察的关键 API。它确保了当 Promise 状态发生变化时，V8 能够正确地触发相应的回调函数（如 `PromiseRejectCallback`）和钩子函数（如 `PromiseHook`），为开发者提供必要的错误捕获和生命周期管理机制。这对于构建健壮和可维护的异步 JavaScript 应用至关重要。

### 提示词
```
这是目录为v8/test/cctest/test-api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第19部分，共36部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      "class X extends
```