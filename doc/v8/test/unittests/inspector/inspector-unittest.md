Response: The user wants a summary of the C++ source file `v8/test/unittests/inspector/inspector-unittest.cc`.
This file seems to contain unit tests for the V8 Inspector.

Here's a breakdown of the code:

1. **Includes:**  Standard C++ headers and V8/Inspector specific headers.
2. **Namespaces:** Uses `v8`, `v8::internal`, and an anonymous namespace for internal helpers.
3. **Helper Classes/Functions:**
    - `NoopChannel`:  A basic `V8Inspector::Channel` implementation that does nothing. Used for tests that don't need to check responses.
    - `WrapOnInterrupt`: A function used with `v8::Isolate::RequestInterrupt` to trigger object wrapping within an interrupt handler.
4. **Test Fixture:** Uses `InspectorTest` which inherits from `TestWithContext` (likely providing a V8 context for tests).
5. **Test Cases (using `TEST_F` macro):** Each `TEST_F` represents an individual unit test. Looking at the names of the tests gives a good idea of the functionalities being tested:
    - `WrapInsideWrapOnInterrupt`: Tests if wrapping an object inside an interrupt handler works correctly.
    - `BinaryFromBase64`: Tests the functionality of decoding base64 strings to binary data.
    - `BinaryToBase64`: Tests the functionality of encoding binary data to base64 strings.
    - `BinaryBase64RoundTrip`: Tests that encoding to base64 and then decoding back results in the original binary data.
    - `NoInterruptOnGetAssociatedData`: Tests that retrieving associated exception data doesn't trigger an interrupt.
    - `NoConsoleAPIForUntrustedClient`: Tests that the console API is not available for untrusted inspector clients.
    - `CanHandleMalformedCborMessage`: Tests how the inspector handles malformed CBOR messages.
    - `ApiCreatedTasksAreCleanedUp`: Tests that tasks created by the console API are properly garbage collected.
    - `Evaluate`: Tests the `evaluate` functionality of the inspector session, including successful evaluations, exceptions, and handling of unknown contexts.
    - `NoInterruptWhileBuildingConsoleMessages`: Tests that building console messages doesn't cause unintended interrupts.

**Relationship to JavaScript:**

The V8 Inspector is a crucial component for debugging and profiling JavaScript code running in the V8 engine (used by Chrome, Node.js, etc.). These unit tests directly exercise the C++ API that powers the inspector. Many of the tests involve actions that a developer would perform when using the browser's developer tools or a Node.js debugger.

**JavaScript Examples:**

Let's look at some examples of how these tests relate to JavaScript functionalities:

- **`WrapInsideWrapOnInterrupt`:** This relates to how the debugger might interact with JavaScript execution when a breakpoint is hit or an exception occurs. The inspector needs to be able to represent JavaScript objects in a way that the debugger can understand, even during interrupt handling. While you wouldn't directly call "wrapObject" in JavaScript, it's part of the internal mechanics the inspector uses when you inspect variables or objects in the debugger.

- **`BinaryFromBase64` and `BinaryToBase64`:**  This relates to scenarios where the inspector needs to exchange binary data with the client (e.g., the browser's DevTools). This might happen when sending or receiving things like:
    ```javascript
    // Example: Fetching an image and seeing its base64 representation in the debugger
    fetch('data:image/png;base64,...') // ... represents a long base64 string
      .then(response => response.blob())
      .then(blob => {
        console.log(blob); // Inspecting 'blob' in the debugger might involve base64 conversion
      });
    ```

- **`NoConsoleAPIForUntrustedClient`:**  This is directly related to the security model of the inspector. Untrusted clients (e.g., a website trying to inject debugging commands) should not have access to powerful debugging features. In JavaScript, this means functions like `$0` (last evaluated expression) or `debug()` should not be available in such contexts.

- **`Evaluate`:** This directly tests the ability of the debugger to execute arbitrary JavaScript code in the context of the running application.
    ```javascript
    // Example: Evaluating expressions in the browser's console
    console.log(21 + 21); // This is similar to what the 'Evaluate' test checks
    ```

- **`ApiCreatedTasksAreCleanedUp`:** This relates to the `console.createTask()` API which allows associating console messages with specific asynchronous operations. The test ensures that if these tasks are no longer referenced by JavaScript, they don't leak memory within the inspector.
    ```javascript
    // Example: Using console.createTask()
    const task = console.createTask('My Async Task');
    setTimeout(() => {
      console.log('Task completed', task);
    }, 1000);
    ```

In summary, this C++ file contains unit tests that verify the core functionalities of the V8 Inspector, ensuring its reliability and correctness when interacting with JavaScript execution for debugging and profiling purposes.
这个C++源代码文件 `v8/test/unittests/inspector/inspector-unittest.cc` 是 **V8 JavaScript 引擎的 Inspector 组件的单元测试文件**。

它的主要功能是：

* **测试 Inspector 的各种核心功能**，例如：
    * **对象包装 (Object Wrapping):** 测试 Inspector 如何在中断处理程序中正确包装 JavaScript 对象，以便在调试器中检查。
    * **Base64 编码和解码:** 测试 Inspector 如何处理 Base64 编码的二进制数据和将其解码为二进制数据，以及反向操作。这对于在 Inspector 协议中传输二进制数据非常重要。
    * **异常关联数据:** 测试 Inspector 如何关联和检索与 JavaScript 异常相关的数据。
    * **安全性和权限:** 测试 Inspector 如何处理不同信任级别的客户端，例如，确保非信任客户端无法访问某些调试 API (例如命令行 API)。
    * **CBOR 消息处理:** 测试 Inspector 处理格式错误的 CBOR (一种二进制数据序列化格式) 消息的能力。
    * **API 创建的任务清理:** 测试 Inspector 如何管理和清理通过其 API 创建的异步任务。
    * **代码求值 (Evaluation):** 测试 Inspector 如何在 JavaScript 上下文中执行代码，并处理成功和异常情况。
    * **避免中断:** 测试 Inspector 在执行某些内部操作（例如构建控制台消息）时，不会意外触发中断。

**与 JavaScript 功能的关系 (并用 JavaScript 举例说明):**

V8 Inspector 是用于调试和分析 JavaScript 代码的关键组件。 这个 C++ 测试文件中的每一个测试案例都直接关联到开发者在使用浏览器开发者工具或者 Node.js 调试器时会遇到的场景。

以下是一些测试案例与 JavaScript 功能关系的示例：

1. **`WrapInsideWrapOnInterrupt`:**  这个测试与当 JavaScript 代码执行被中断时 (例如，遇到断点或抛出异常)，调试器如何检查变量有关。 Inspector 需要能够正确地包装这些变量的值以便显示。

   **JavaScript 例子 (虽然不是直接对应，但概念相关):**

   ```javascript
   function myFunction() {
     let x = 10;
     debugger; // 设置断点
     console.log(x);
   }
   myFunction();
   ```

   当代码执行到 `debugger` 语句时，执行会被中断，此时调试器会使用 Inspector 来获取 `x` 的值。`WrapInsideWrapOnInterrupt` 测试确保 Inspector 能够在这样的中断上下文中正确处理对象。

2. **`BinaryFromBase64` 和 `BinaryToBase64`:** 这两个测试与 Inspector 协议中二进制数据的传输有关。例如，当你在调试器中查看一个 `Blob` 对象或者下载一个文件时，数据可能以 Base64 编码的形式在 Inspector 协议中传输。

   **JavaScript 例子:**

   ```javascript
   fetch('image.png')
     .then(response => response.blob())
     .then(blob => {
       const reader = new FileReader();
       reader.onloadend = function() {
         console.log(reader.result); // reader.result 是图片的 Base64 编码
       }
       reader.readAsDataURL(blob);
     });
   ```

   当你在调试器中检查 `reader.result` 时，Inspector 可能会用到 Base64 解码功能来显示图像数据。

3. **`NoConsoleAPIForUntrustedClient`:** 这个测试确保了只有受信任的调试会话才能访问某些强大的调试 API，例如 `$0` (指代上一个表达式的返回值) 或 `debug()` 函数。这防止了恶意网站利用这些 API 来获取敏感信息或干扰代码执行。

   **JavaScript 例子 (在浏览器控制台中):**

   ```javascript
   let a = 5;
   a + 3; // 返回 8
   $0;    // 在控制台中会显示 8，因为 $0 指代上一个表达式的返回值
   ```

   `NoConsoleAPIForUntrustedClient` 测试确保在非信任的上下文中 (例如，通过嵌入的 Inspector 客户端)，`$0` 不会被定义。

4. **`Evaluate`:** 这个测试直接关系到调试器中 "在控制台中执行代码" 的功能。开发者可以在调试器中输入 JavaScript 代码并立即执行，Inspector 的 `evaluate` 功能负责处理这个请求。

   **JavaScript 例子 (在浏览器开发者工具的 Console 面板中):**

   ```javascript
   21 + 21; // 在控制台中输入并执行，会返回 42
   ```

   `Evaluate` 测试确保 Inspector 能够正确地执行这些代码，并返回结果或错误信息。

5. **`ApiCreatedTasksAreCleanedUp`:** 这个测试与 `console.createTask()` API 有关，该 API 允许将控制台消息与异步操作关联起来。测试确保当 JavaScript 代码中不再引用这些任务时，Inspector 也能正确地清理它们，防止内存泄漏。

   **JavaScript 例子:**

   ```javascript
   const task = console.createTask('My Async Operation');
   setTimeout(() => {
     console.log('Async operation completed', task);
   }, 1000);
   ```

   `ApiCreatedTasksAreCleanedUp` 测试确保当 `task` 变量不再被引用时，Inspector 内部也会释放与该任务相关的资源。

总而言之，`v8/test/unittests/inspector/inspector-unittest.cc` 文件通过各种单元测试，保障了 V8 Inspector 组件的正确性和稳定性，而 Inspector 组件又是 JavaScript 开发者进行调试和性能分析的强大工具。

Prompt: 
```
这是目录为v8/test/unittests/inspector/inspector-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "include/v8-inspector.h"
#include "include/v8-local-handle.h"
#include "include/v8-primitive.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-runtime-agent-impl.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using v8_inspector::String16;
using v8_inspector::StringBuffer;
using v8_inspector::StringView;
using v8_inspector::toString16;
using v8_inspector::toStringView;
using v8_inspector::V8ContextInfo;
using v8_inspector::V8Inspector;
using v8_inspector::V8InspectorSession;

namespace v8 {
namespace internal {

using InspectorTest = TestWithContext;

namespace {

class NoopChannel : public V8Inspector::Channel {
 public:
  ~NoopChannel() override = default;
  void sendResponse(int callId,
                    std::unique_ptr<StringBuffer> message) override {}
  void sendNotification(std::unique_ptr<StringBuffer> message) override {}
  void flushProtocolNotifications() override {}
};

void WrapOnInterrupt(v8::Isolate* isolate, void* data) {
  const char* object_group = "";
  StringView object_group_view(reinterpret_cast<const uint8_t*>(object_group),
                               strlen(object_group));
  reinterpret_cast<V8InspectorSession*>(data)->wrapObject(
      isolate->GetCurrentContext(), v8::Null(isolate), object_group_view,
      false);
}

}  // namespace

TEST_F(InspectorTest, WrapInsideWrapOnInterrupt) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<V8Inspector> inspector =
      V8Inspector::create(isolate, &default_client);
  const char* name = "";
  StringView name_view(reinterpret_cast<const uint8_t*>(name), strlen(name));
  V8ContextInfo context_info(v8_context(), 1, name_view);
  inspector->contextCreated(context_info);

  NoopChannel channel;
  const char* state = "{}";
  StringView state_view(reinterpret_cast<const uint8_t*>(state), strlen(state));
  std::unique_ptr<V8InspectorSession> session = inspector->connect(
      1, &channel, state_view, v8_inspector::V8Inspector::kFullyTrusted);

  const char* object_group = "";
  StringView object_group_view(reinterpret_cast<const uint8_t*>(object_group),
                               strlen(object_group));
  isolate->RequestInterrupt(&WrapOnInterrupt, session.get());
  session->wrapObject(v8_context(), v8::Null(isolate), object_group_view,
                      false);
}

TEST_F(InspectorTest, BinaryFromBase64) {
  auto checkBinary = [](const v8_inspector::protocol::Binary& binary,
                        const std::vector<uint8_t>& values) {
    std::vector<uint8_t> binary_vector(binary.data(),
                                       binary.data() + binary.size());
    CHECK_EQ(binary_vector, values);
  };

  {
    bool success;
    auto binary = v8_inspector::protocol::Binary::fromBase64("", &success);
    CHECK(success);
    checkBinary(binary, {});
  }
  {
    bool success;
    auto binary = v8_inspector::protocol::Binary::fromBase64("YQ==", &success);
    CHECK(success);
    checkBinary(binary, {'a'});
  }
  {
    bool success;
    auto binary = v8_inspector::protocol::Binary::fromBase64("YWI=", &success);
    CHECK(success);
    checkBinary(binary, {'a', 'b'});
  }
  {
    bool success;
    auto binary = v8_inspector::protocol::Binary::fromBase64("YWJj", &success);
    CHECK(success);
    checkBinary(binary, {'a', 'b', 'c'});
  }
  {
    bool success;
    // Wrong input length:
    auto binary = v8_inspector::protocol::Binary::fromBase64("Y", &success);
    CHECK(!success);
  }
  {
    bool success;
    // Invalid space:
    auto binary = v8_inspector::protocol::Binary::fromBase64("=AAA", &success);
    CHECK(!success);
  }
  {
    bool success;
    // Invalid space in a non-final block of four:
    auto binary =
        v8_inspector::protocol::Binary::fromBase64("AAA=AAAA", &success);
    CHECK(!success);
  }
  {
    bool success;
    // Invalid invalid space in second to last position:
    auto binary = v8_inspector::protocol::Binary::fromBase64("AA=A", &success);
    CHECK(!success);
  }
  {
    bool success;
    // Invalid character:
    auto binary = v8_inspector::protocol::Binary::fromBase64(" ", &success);
    CHECK(!success);
  }
}

TEST_F(InspectorTest, BinaryToBase64) {
  uint8_t input[] = {'a', 'b', 'c'};
  {
    auto binary = v8_inspector::protocol::Binary::fromSpan(
        MemorySpan<const uint8_t>(input, 0));
    v8_inspector::protocol::String base64 = binary.toBase64();
    CHECK_EQ(base64.utf8(), "");
  }
  {
    auto binary = v8_inspector::protocol::Binary::fromSpan(
        MemorySpan<const uint8_t>(input, 1));
    v8_inspector::protocol::String base64 = binary.toBase64();
    CHECK_EQ(base64.utf8(), "YQ==");
  }
  {
    auto binary = v8_inspector::protocol::Binary::fromSpan(
        MemorySpan<const uint8_t>(input, 2));
    v8_inspector::protocol::String base64 = binary.toBase64();
    CHECK_EQ(base64.utf8(), "YWI=");
  }
  {
    auto binary = v8_inspector::protocol::Binary::fromSpan(
        MemorySpan<const uint8_t>(input, 3));
    v8_inspector::protocol::String base64 = binary.toBase64();
    CHECK_EQ(base64.utf8(), "YWJj");
  }
}

TEST_F(InspectorTest, BinaryBase64RoundTrip) {
  std::array<uint8_t, 256> values;
  for (uint16_t b = 0x0; b <= 0xFF; ++b) values[b] = b;
  auto binary = v8_inspector::protocol::Binary::fromSpan(
      MemorySpan<const uint8_t>(values));
  v8_inspector::protocol::String base64 = binary.toBase64();
  bool success = false;
  auto roundtrip_binary =
      v8_inspector::protocol::Binary::fromBase64(base64, &success);
  CHECK(success);
  CHECK_EQ(values.size(), roundtrip_binary.size());
  for (size_t i = 0; i < values.size(); ++i) {
    CHECK_EQ(values[i], roundtrip_binary.data()[i]);
  }
}

TEST_F(InspectorTest, NoInterruptOnGetAssociatedData) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<v8_inspector::V8InspectorImpl> inspector(
      new v8_inspector::V8InspectorImpl(isolate, &default_client));

  v8::Local<v8::Value> error = v8::Exception::Error(NewString("custom error"));
  v8::Local<v8::Name> key = NewString("key");
  v8::Local<v8::Value> value = NewString("value");
  inspector->associateExceptionData(v8_context(), error, key, value);

  struct InterruptRecorder {
    static void handler(v8::Isolate* isolate, void* data) {
      reinterpret_cast<InterruptRecorder*>(data)->WasInvoked = true;
    }

    bool WasInvoked = false;
  } recorder;

  isolate->RequestInterrupt(&InterruptRecorder::handler, &recorder);

  v8::Local<v8::Object> data =
      inspector->getAssociatedExceptionData(error).ToLocalChecked();
  CHECK(!recorder.WasInvoked);

  CHECK_EQ(data->Get(v8_context(), key).ToLocalChecked(), value);

  TryRunJS("0");
  CHECK(recorder.WasInvoked);
}

class TestChannel : public V8Inspector::Channel {
 public:
  ~TestChannel() override = default;
  void sendResponse(int callId,
                    std::unique_ptr<StringBuffer> message) override {
    CHECK_EQ(callId, 1);
    CHECK_NE(toString16(message->string()).find(expected_response_matcher_),
             String16::kNotFound);
  }
  void sendNotification(std::unique_ptr<StringBuffer> message) override {}
  void flushProtocolNotifications() override {}
  v8_inspector::String16 expected_response_matcher_;
};

TEST_F(InspectorTest, NoConsoleAPIForUntrustedClient) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<V8Inspector> inspector =
      V8Inspector::create(isolate, &default_client);
  V8ContextInfo context_info(v8_context(), 1, toStringView(""));
  inspector->contextCreated(context_info);

  TestChannel channel;
  const char kCommand[] = R"({
    "id": 1,
    "method": "Runtime.evaluate",
    "params": {
      "expression": "$0 || 42",
      "contextId": 1,
      "includeCommandLineAPI": true
    }
  })";
  std::unique_ptr<V8InspectorSession> trusted_session =
      inspector->connect(1, &channel, toStringView("{}"),
                         v8_inspector::V8Inspector::kFullyTrusted);
  channel.expected_response_matcher_ = R"("value":42)";
  trusted_session->dispatchProtocolMessage(toStringView(kCommand));

  std::unique_ptr<V8InspectorSession> untrusted_session = inspector->connect(
      1, &channel, toStringView("{}"), v8_inspector::V8Inspector::kUntrusted);
  channel.expected_response_matcher_ = R"("className":"ReferenceError")";
  untrusted_session->dispatchProtocolMessage(toStringView(kCommand));
}

TEST_F(InspectorTest, CanHandleMalformedCborMessage) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<V8Inspector> inspector =
      V8Inspector::create(isolate, &default_client);
  V8ContextInfo context_info(v8_context(), 1, toStringView(""));
  inspector->contextCreated(context_info);

  TestChannel channel;
  const unsigned char kCommand[] = {0xD8, 0x5A, 0x00, 0xBA, 0xDB, 0xEE, 0xF0};
  std::unique_ptr<V8InspectorSession> trusted_session =
      inspector->connect(1, &channel, toStringView("{}"),
                         v8_inspector::V8Inspector::kFullyTrusted);
  channel.expected_response_matcher_ = R"("value":42)";
  trusted_session->dispatchProtocolMessage(
      StringView(kCommand, sizeof(kCommand)));
}

TEST_F(InspectorTest, ApiCreatedTasksAreCleanedUp) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<v8_inspector::V8InspectorImpl> inspector =
      std::make_unique<v8_inspector::V8InspectorImpl>(isolate, &default_client);
  V8ContextInfo context_info(v8_context(), 1, toStringView(""));
  inspector->contextCreated(context_info);

  // Trigger V8Console creation.
  v8_inspector::V8Console* console = inspector->console();
  CHECK(console);

  {
    v8::HandleScope handle_scope(isolate);
    v8::MaybeLocal<v8::Value> result = TryRunJS(isolate, NewString(R"(
      globalThis['task'] = console.createTask('Task');
    )"));
    CHECK(!result.IsEmpty());

    // Run GC and check that the task is still here.
    InvokeMajorGC();
    CHECK_EQ(console->AllConsoleTasksForTest().size(), 1);
  }

  // Get rid of the task on the context, run GC and check we no longer have
  // the TaskInfo in the inspector.
  v8_context()->Global()->Delete(v8_context(), NewString("task")).Check();
  {
    // We need to invoke GC without stack, otherwise some objects may not be
    // reclaimed because of conservative stack scanning.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate()->heap());
    InvokeMajorGC();
  }
  CHECK_EQ(console->AllConsoleTasksForTest().size(), 0);
}

TEST_F(InspectorTest, Evaluate) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<V8Inspector> inspector =
      V8Inspector::create(isolate, &default_client);
  V8ContextInfo context_info(v8_context(), 1, toStringView(""));
  inspector->contextCreated(context_info);

  TestChannel channel;
  std::unique_ptr<V8InspectorSession> trusted_session =
      inspector->connect(1, &channel, toStringView("{}"),
                         v8_inspector::V8Inspector::kFullyTrusted);

  {
    auto result =
        trusted_session->evaluate(v8_context(), toStringView("21 + 21"));
    CHECK_EQ(
        result.type,
        v8_inspector::V8InspectorSession::EvaluateResult::ResultType::kSuccess);
    CHECK_EQ(result.value->IntegerValue(v8_context()).FromJust(), 42);
  }
  {
    auto result = trusted_session->evaluate(
        v8_context(), toStringView("throw new Error('foo')"));
    CHECK_EQ(result.type, v8_inspector::V8InspectorSession::EvaluateResult::
                              ResultType::kException);
    CHECK(result.value->IsNativeError());
  }
  {
    // Unknown context.
    v8::Local<v8::Context> ctx = v8::Context::New(v8_isolate());
    auto result = trusted_session->evaluate(ctx, toStringView("21 + 21"));
    CHECK_EQ(
        result.type,
        v8_inspector::V8InspectorSession::EvaluateResult::ResultType::kNotRun);
  }
  {
    // CommandLine API
    auto result = trusted_session->evaluate(v8_context(),
                                            toStringView("debug(console.log)"),
                                            /*includeCommandLineAPI=*/true);
    CHECK_EQ(
        result.type,
        v8_inspector::V8InspectorSession::EvaluateResult::ResultType::kSuccess);
    CHECK(result.value->IsUndefined());
  }
}

// Regression test for crbug.com/323813642.
TEST_F(InspectorTest, NoInterruptWhileBuildingConsoleMessages) {
  v8::Isolate* isolate = v8_isolate();
  v8::HandleScope handle_scope(isolate);

  v8_inspector::V8InspectorClient default_client;
  std::unique_ptr<v8_inspector::V8InspectorImpl> inspector(
      new v8_inspector::V8InspectorImpl(isolate, &default_client));
  V8ContextInfo context_info(v8_context(), 1, toStringView(""));
  inspector->contextCreated(context_info);

  TestChannel channel;
  std::unique_ptr<V8InspectorSession> session = inspector->connect(
      1, &channel, toStringView("{}"), v8_inspector::V8Inspector::kFullyTrusted,
      v8_inspector::V8Inspector::kNotWaitingForDebugger);
  reinterpret_cast<v8_inspector::V8InspectorSessionImpl*>(session.get())
      ->runtimeAgent()
      ->enable();

  struct InterruptRecorder {
    static void handler(v8::Isolate* isolate, void* data) {
      reinterpret_cast<InterruptRecorder*>(data)->WasInvoked = true;
    }

    bool WasInvoked = false;
  } recorder;

  isolate->RequestInterrupt(&InterruptRecorder::handler, &recorder);

  v8::Local<v8::Value> error = v8::Exception::Error(NewString("custom error"));
  inspector->exceptionThrown(v8_context(), toStringView("message"), error,
                             toStringView("detailed message"),
                             toStringView("https://example.com/script.js"), 42,
                             21, std::unique_ptr<v8_inspector::V8StackTrace>(),
                             0);

  CHECK(!recorder.WasInvoked);

  TryRunJS("0");
  CHECK(recorder.WasInvoked);
}

}  // namespace internal
}  // namespace v8

"""

```