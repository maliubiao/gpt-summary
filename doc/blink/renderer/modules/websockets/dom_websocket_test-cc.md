Response:
The user is asking for an analysis of a C++ source code file, `dom_websocket_test.cc`, which is part of the Chromium Blink engine. The request has several parts:

1. **List the file's functions:** This requires identifying the purpose of the code. Based on the filename and the included headers, it's clearly a unit test file for the `DOMWebSocket` class. Thus, its main function is to test the functionality of `DOMWebSocket`.

2. **Relate to Javascript, HTML, CSS:**  `DOMWebSocket` is a web API that's directly exposed to Javascript. Therefore, the tests in this file are indirectly testing how the underlying C++ implementation behaves when called from Javascript.

3. **Logic inference (input/output):**  Each `TEST` function in the file represents a specific scenario being tested. The "input" is the setup and actions performed within the test (e.g., calling `connect`, `send`, `close` with specific parameters). The "output" is the expected state of the `DOMWebSocket` object and interactions with its mock dependencies (e.g., state transitions, calls to the mock channel).

4. **Common user/programming errors:**  The tests often check for error handling. These tests demonstrate what happens when a user (through Javascript) makes incorrect calls to the `WebSocket` API (e.g., invalid URLs, sending data in the wrong state).

5. **User operation leading to this code:**  This requires tracing the flow. A web developer writes Javascript code that uses the `WebSocket` API. The browser executes this Javascript, which eventually calls into the Blink engine's C++ implementation of `DOMWebSocket`. This test file is a low-level unit test of that C++ code.

6. **Summarize the file's function (part 1 of 2):**  Based on the first part of the file, the primary function is to test the initial states and transitions of the `DOMWebSocket` object, focusing on connection establishment, error handling during connection, and basic `send` and `close` operations. It utilizes a mock `WebSocketChannel` to isolate the `DOMWebSocket` logic.

**Mental Sandbox:**

* **High-level understanding:** This is a unit test file for `DOMWebSocket`.
* **Key classes:** `DOMWebSocket`, `MockWebSocketChannel`, `V8TestingScope`.
* **Test structure:** Each `TEST` function sets up a scenario and uses `EXPECT_CALL` and `EXPECT_EQ` to verify behavior.
* **Javascript connection:** The tests are mimicking Javascript interactions with the `WebSocket` API.
* **Error handling:**  Many tests focus on what happens when invalid inputs are provided.

**Constraint Checklist & Confidence Score:**

* List functions: Yes (identifying the purpose of tests).
* Javascript/HTML/CSS relation: Yes.
* Examples for JS/HTML/CSS: Yes.
* Logic inference (input/output): Yes.
* Input/output examples: Yes.
* User/programming errors: Yes.
* Error examples: Yes.
* User steps to reach code: Yes.
* Debugging clue: Yes.
* Summarize function (part 1): Yes.

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on these insights.
这个C++源代码文件 `dom_websocket_test.cc` 是 Chromium Blink 引擎中用于测试 `DOMWebSocket` 类的单元测试文件。 它的主要功能是验证 `DOMWebSocket` 类的各种功能和行为是否符合预期。

以下是更详细的功能列表和说明：

**主要功能:**

1. **测试 WebSocket 连接的建立:**
   - 测试连接到各种类型的 URL (有效和无效的 URL，包含或不包含子协议的 URL)。
   - 测试安全策略对 WebSocket 连接的影响 (例如，在 HTTPS 页面上尝试连接 `ws://` URL)。
   - 使用 `MockWebSocketChannel` 模拟底层网络通道的行为，以便隔离 `DOMWebSocket` 类的逻辑。
   - 验证连接成功和失败的不同场景，以及 `readyState` 属性的变化。

2. **测试 WebSocket 数据的发送:**
   - 测试在不同的 `readyState` 状态下发送字符串和 ArrayBuffer 数据。
   - 验证在连接建立前、正在关闭或已关闭状态下发送数据会抛出异常。
   - 测试成功发送数据后，`bufferedAmount` 属性的更新。
   - 测试发送非 Latin-1 字符的字符串。

3. **测试 WebSocket 连接的关闭:**
   - 测试在不同的 `readyState` 状态下调用 `close()` 方法。
   - 测试使用不同的关闭代码和原因关闭连接。
   - 验证关闭原因的长度限制。
   - 测试在连接建立中、正在关闭或已关闭状态下再次调用 `close()` 方法的行为。

4. **测试 WebSocket 事件的处理 (间接):**
   - 虽然这个文件没有直接测试事件的触发，但它通过模拟 `WebSocketChannelClient` 的回调 (例如 `DidConnect`, `DidClose`) 来验证 `DOMWebSocket` 对象在接收到这些事件时的状态变化和行为。  更具体的事件测试可能在其他相关的测试文件中。

**与 JavaScript, HTML, CSS 的关系:**

`DOMWebSocket` 是 WebSockets API 的核心实现，它直接暴露给 JavaScript。 因此，这个测试文件间接地测试了当 JavaScript 代码使用 `WebSocket` API 时，底层的 C++ 实现的行为是否正确。

**举例说明:**

* **JavaScript:**  一个 JavaScript 开发者可能会使用以下代码创建一个 WebSocket 连接：
  ```javascript
  let websocket = new WebSocket('ws://example.com/endpoint');

  websocket.onopen = function(event) {
    console.log("WebSocket 连接已打开");
    websocket.send("你好！");
  };

  websocket.onmessage = function(event) {
    console.log("收到消息: " + event.data);
  };

  websocket.onclose = function(event) {
    console.log("WebSocket 连接已关闭");
  };

  websocket.onerror = function(event) {
    console.error("WebSocket 错误发生");
  };

  websocket.close(1000, "用户主动关闭");
  ```
  这个测试文件中的很多测试用例都在模拟上述 JavaScript 代码的行为，例如测试连接到 `'ws://example.com/endpoint'`，调用 `send()` 发送消息，以及调用 `close()` 关闭连接等场景。

* **HTML:** HTML 文件中通常包含运行上述 JavaScript 代码的 `<script>` 标签。  用户通过浏览器加载包含这些脚本的 HTML 页面，就会触发 WebSocket 连接的建立和操作。

* **CSS:** CSS 与 WebSocket 的功能没有直接关系。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  JavaScript 代码尝试创建一个连接到无效 URL `xxx` 的 WebSocket：
  ```javascript
  let websocket = new WebSocket('xxx');
  ```
* **对应测试用例:** `DOMWebSocketTest.connectToBadURL`
* **输出:**  测试期望 `DOMWebSocket` 对象的状态为 `CLOSED`，并且会抛出一个 `SyntaxError` 异常，错误消息为 "The URL 'xxx' is invalid."。

* **假设输入:** JavaScript 代码尝试创建一个连接到 `ws://example.com/endpoint` 的 WebSocket，而当前页面是通过 HTTPS 加载的，并且浏览器的安全策略是阻止这种不安全的请求：
  ```javascript
  let websocket = new WebSocket('ws://example.com/endpoint');
  ```
* **对应测试用例:**  虽然没有完全对应的单个测试用例，但 `DOMWebSocketTest.channelConnectFail` 模拟了连接失败的情况，尽管原因略有不同。 其他测试用例，例如 `DOMWebSocketTest.insecureRequestsUpgrade` 和 `DOMWebSocketTest.insecureRequestsDoNotUpgrade` 涉及到安全策略。
* **输出:** 测试期望 `DOMWebSocket` 对象的状态为 `CLOSED`，并且可能会抛出一个 `SecurityError` 异常，提示不能从 HTTPS 页面发起不安全的 WebSocket 连接。

**用户或编程常见的使用错误:**

* **尝试连接到无效的 URL 格式:** 例如，缺少协议头，或者包含不允许的字符。 测试用例 `DOMWebSocketTest.connectToBadURL`, `DOMWebSocketTest.connectToNonWsURL`, `DOMWebSocketTest.connectToURLHavingFragmentIdentifier` 都在覆盖这类错误。
* **在 WebSocket 连接建立之前尝试发送数据:** 测试用例 `DOMWebSocketTest.sendStringWhenConnecting`, `DOMWebSocketTest.sendArrayBufferWhenConnecting` 验证了这种情况会抛出 `InvalidStateError` 异常。
* **在 WebSocket 连接关闭或正在关闭时尝试发送数据:** 测试用例 `DOMWebSocketTest.sendStringWhenClosing`, `DOMWebSocketTest.sendStringWhenClosed`, `DOMWebSocketTest.sendArrayBufferWhenClosing`, `DOMWebSocketTest.sendArrayBufferWhenClosed` 验证了这种情况不会发送数据。
* **使用过长的关闭原因字符串:** 测试用例 `DOMWebSocketTest.reasonSizeExceeding` 验证了这种情况会抛出 `SyntaxError` 异常。
* **提供无效的子协议字符串:** 测试用例 `DOMWebSocketTest.invalidSubprotocols` 验证了这种情况会抛出 `SyntaxError` 异常。

**用户操作如何一步步地到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL 并加载网页 (例如一个包含 WebSocket 功能的 Web 应用)。**
2. **网页的 HTML 被解析，浏览器开始执行 JavaScript 代码。**
3. **JavaScript 代码中创建了一个 `WebSocket` 对象，并传入一个 WebSocket 服务器的 URL。**
4. **浏览器内部的 JavaScript 引擎会调用 Blink 引擎中 `DOMWebSocket` 类的构造函数。**
5. **`DOMWebSocket` 对象尝试建立与服务器的连接，这涉及到调用 `CreateChannel` 方法，实际会创建 `WebSocketChannel` 对象 (或者像这个测试中一样，使用 `MockWebSocketChannel`)。**
6. **如果连接成功，`DOMWebSocket` 对象的状态会变为 `OPEN`，并触发 `onopen` 事件。**
7. **JavaScript 代码可能会调用 `send()` 方法发送数据，这会调用 `DOMWebSocket` 类的 `send()` 方法。**
8. **JavaScript 代码可能会调用 `close()` 方法关闭连接，这会调用 `DOMWebSocket` 类的 `close()` 方法。**
9. **当 WebSocket 连接关闭时，`DOMWebSocket` 对象的状态会变为 `CLOSED`，并触发 `onclose` 事件。**

在调试过程中，如果发现 WebSocket 的行为不符合预期，开发人员可能会查看 Blink 引擎的源代码，例如 `dom_websocket_test.cc`，来理解 `DOMWebSocket` 类的内部逻辑和测试覆盖情况，从而找到问题所在。  测试用例可以帮助理解在特定条件下 `DOMWebSocket` 应该如何工作。

**这是第1部分，共2部分，请归纳一下它的功能:**

总而言之，这份代码文件 (`dom_websocket_test.cc` 的第一部分) 的主要功能是 **测试 Chromium Blink 引擎中 `DOMWebSocket` 类在建立连接和进行基本的发送/关闭操作时的行为，并验证其对各种有效和无效输入的处理以及状态转换是否正确。** 它使用了模拟对象来隔离被测试的代码，并涵盖了连接建立的各种场景，包括错误处理和安全策略的影响。

### 提示词
```
这是目录为blink/renderer/modules/websockets/dom_websocket_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/websockets/dom_websocket.h"

#include <memory>
#include <string>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_typed_array.h"
#include "third_party/blink/renderer/modules/websockets/mock_websocket_channel.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "v8/include/v8.h"

using testing::_;
using testing::AnyNumber;
using testing::InSequence;
using testing::Ref;
using testing::Return;

namespace blink {

namespace {

typedef testing::StrictMock<testing::MockFunction<void(int)>>
    Checkpoint;  // NOLINT

class DOMWebSocketWithMockChannel final : public DOMWebSocket {
 public:
  static DOMWebSocketWithMockChannel* Create(ExecutionContext* context) {
    DOMWebSocketWithMockChannel* websocket =
        MakeGarbageCollected<DOMWebSocketWithMockChannel>(context);
    websocket->UpdateStateIfNeeded();
    return websocket;
  }

  explicit DOMWebSocketWithMockChannel(ExecutionContext* context)
      : DOMWebSocket(context),
        channel_(MakeGarbageCollected<MockWebSocketChannel>()),
        has_created_channel_(false) {}

  MockWebSocketChannel* Channel() { return channel_.Get(); }

  WebSocketChannel* CreateChannel(ExecutionContext*,
                                  WebSocketChannelClient*) override {
    DCHECK(!has_created_channel_);
    has_created_channel_ = true;
    return channel_.Get();
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(channel_);
    DOMWebSocket::Trace(visitor);
  }

 private:
  Member<MockWebSocketChannel> channel_;
  bool has_created_channel_;
};

class DOMWebSocketTestScope {
  STACK_ALLOCATED();

 public:
  explicit DOMWebSocketTestScope(ExecutionContext* execution_context)
      : websocket_(DOMWebSocketWithMockChannel::Create(execution_context)) {}

  ~DOMWebSocketTestScope() {
    if (!websocket_)
      return;
    // These statements are needed to clear WebSocket::channel_ to
    // avoid ASSERTION failure on ~DOMWebSocket.
    DCHECK(Socket().Channel());
    testing::Mock::VerifyAndClear(Socket().Channel());
    EXPECT_CALL(Channel(), Disconnect()).Times(AnyNumber());

    Socket().DidClose(WebSocketChannelClient::kClosingHandshakeIncomplete, 1006,
                      "");
  }

  MockWebSocketChannel& Channel() { return *websocket_->Channel(); }
  DOMWebSocketWithMockChannel& Socket() { return *websocket_.Get(); }

 private:
  Persistent<DOMWebSocketWithMockChannel> websocket_;
};

TEST(DOMWebSocketTest, connectToBadURL) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  websocket_scope.Socket().Connect("xxx", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSyntaxError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ("The URL 'xxx' is invalid.", scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, connectToNonWsURL) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  websocket_scope.Socket().Connect("bad-scheme://example.com/",
                                   Vector<String>(), scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSyntaxError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ(
      "The URL's scheme must be either 'http', 'https', 'ws', or 'wss'. "
      "'bad-scheme' is not allowed.",
      scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, connectToURLHavingFragmentIdentifier) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  websocket_scope.Socket().Connect("ws://example.com/#fragment",
                                   Vector<String>(), scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSyntaxError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ(
      "The URL contains a fragment identifier ('fragment'). Fragment "
      "identifiers are not allowed in WebSocket URLs.",
      scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

// FIXME: Add a test for Content Security Policy.

TEST(DOMWebSocketTest, invalidSubprotocols) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Vector<String> subprotocols;
  subprotocols.push_back("@subprotocol-|'\"x\x01\x02\x03x");

  websocket_scope.Socket().Connect("ws://example.com/", subprotocols,
                                   scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSyntaxError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ(
      "The subprotocol '@subprotocol-|'\"x\\u0001\\u0002\\u0003x' is invalid.",
      scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, insecureRequestsUpgrade) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("wss://example.com/endpoint"), String()))
        .WillOnce(Return(true));
  }

  scope.GetWindow().GetSecurityContext().SetInsecureRequestPolicy(
      mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests);
  websocket_scope.Socket().Connect("ws://example.com/endpoint",
                                   Vector<String>(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
  EXPECT_EQ(KURL("wss://example.com/endpoint"), websocket_scope.Socket().url());
}

TEST(DOMWebSocketTest, insecureRequestsUpgradePotentiallyTrustworthy) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://127.0.0.1/endpoint"), String()))
        .WillOnce(Return(true));
  }

  scope.GetWindow().GetSecurityContext().SetInsecureRequestPolicy(
      mojom::blink::InsecureRequestPolicy::kUpgradeInsecureRequests);
  websocket_scope.Socket().Connect("ws://127.0.0.1/endpoint", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
  EXPECT_EQ(KURL("ws://127.0.0.1/endpoint"), websocket_scope.Socket().url());
}

TEST(DOMWebSocketTest, insecureRequestsDoNotUpgrade) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/endpoint"), String()))
        .WillOnce(Return(true));
  }

  scope.GetWindow().GetSecurityContext().SetInsecureRequestPolicy(
      mojom::blink::InsecureRequestPolicy::kLeaveInsecureRequestsAlone);
  websocket_scope.Socket().Connect("ws://example.com/endpoint",
                                   Vector<String>(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
  EXPECT_EQ(KURL("ws://example.com/endpoint"), websocket_scope.Socket().url());
}

TEST(DOMWebSocketTest, channelConnectSuccess) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Vector<String> subprotocols;
  subprotocols.push_back("aa");
  subprotocols.push_back("bb");

  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/hoge"), String("aa, bb")))
        .WillOnce(Return(true));
  }

  websocket_scope.Socket().Connect("ws://example.com/hoge",
                                   Vector<String>(subprotocols),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
  EXPECT_EQ(KURL("ws://example.com/hoge"), websocket_scope.Socket().url());
}

TEST(DOMWebSocketTest, channelConnectFail) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Vector<String> subprotocols;
  subprotocols.push_back("aa");
  subprotocols.push_back("bb");

  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String("aa, bb")))
        .WillOnce(Return(false));
    EXPECT_CALL(websocket_scope.Channel(), Disconnect());
  }

  websocket_scope.Socket().Connect("ws://example.com/",
                                   Vector<String>(subprotocols),
                                   scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSecurityError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ(
      "An insecure WebSocket connection may not be initiated from a page "
      "loaded over HTTPS.",
      scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, connectSuccess) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Vector<String> subprotocols;
  subprotocols.push_back("aa");
  subprotocols.push_back("bb");
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String("aa, bb")))
        .WillOnce(Return(true));
  }
  websocket_scope.Socket().Connect("ws://example.com/", subprotocols,
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("bb", "cc");

  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  EXPECT_EQ("bb", websocket_scope.Socket().protocol());
  EXPECT_EQ("cc", websocket_scope.Socket().extensions());
}

TEST(DOMWebSocketTest, didClose) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Disconnect());
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidClose(
      WebSocketChannelClient::kClosingHandshakeIncomplete, 1006, "");

  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, maximumReasonSize) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), FailMock(_, _, _));
  }
  StringBuilder reason;
  for (size_t i = 0; i < 123; ++i)
    reason.Append('a');
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().close(1000, reason.ToString(),
                                 scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, reasonSizeExceeding) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
  }
  StringBuilder reason;
  for (size_t i = 0; i < 124; ++i)
    reason.Append('a');
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().close(1000, reason.ToString(),
                                 scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kSyntaxError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ("The close reason must not be greater than 123 UTF-8 bytes.",
            scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, closeWhenConnecting) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(
        websocket_scope.Channel(),
        FailMock(
            String("WebSocket is closed before the connection is established."),
            mojom::ConsoleMessageLevel::kWarning, _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().close(1000, "bye", scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, close) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Close(3005, String("bye")));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("", "");
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(3005, "bye", scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, closeWithoutReason) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Close(3005, String()));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("", "");
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(3005, scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, closeWithoutCodeAndReason) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Close(-1, String()));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("", "");
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, closeWhenClosing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Close(-1, String()));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("", "");
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());

  websocket_scope.Socket().close(scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, closeWhenClosed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Close(-1, String()));
    EXPECT_CALL(websocket_scope.Channel(), Disconnect());
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidConnect("", "");
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());

  websocket_scope.Socket().DidClose(
      WebSocketChannelClient::kClosingHandshakeComplete, 1000, String());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
  websocket_scope.Socket().close(scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendStringWhenConnecting) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().send("hello", scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kInvalidStateError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ("Still in CONNECTING state.", scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendStringWhenClosing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), FailMock(_, _, _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().close(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().send("hello", scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendStringWhenClosed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Checkpoint checkpoint;
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Disconnect());
    EXPECT_CALL(checkpoint, Call(1));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidClose(
      WebSocketChannelClient::kClosingHandshakeIncomplete, 1006, "");
  checkpoint.Call(1);

  websocket_scope.Socket().send("hello", scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendStringSuccess) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Send(std::string("hello"), _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidConnect("", "");
  websocket_scope.Socket().send("hello", scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendNonLatin1String) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(),
                Send(std::string("\xe7\x8b\x90\xe0\xa4\x94"), _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidConnect("", "");
  UChar non_latin1_string[] = {0x72d0, 0x0914, 0x0000};
  websocket_scope.Socket().send(non_latin1_string, scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendArrayBufferWhenConnecting) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  DOMArrayBufferView* view = DOMUint8Array::Create(8);
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().send(view->buffer(), scope.GetExceptionState());

  EXPECT_TRUE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMExceptionCode::kInvalidStateError,
            scope.GetExceptionState().CodeAs<DOMExceptionCode>());
  EXPECT_EQ("Still in CONNECTING state.", scope.GetExceptionState().Message());
  EXPECT_EQ(DOMWebSocket::kConnecting, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendArrayBufferWhenClosing) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  DOMArrayBufferView* view = DOMUint8Array::Create(8);
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), FailMock(_, _, _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().close(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().send(view->buffer(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosing, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendArrayBufferWhenClosed) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  Checkpoint checkpoint;
  DOMArrayBufferView* view = DOMUint8Array::Create(8);
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Disconnect());
    EXPECT_CALL(checkpoint, Call(1));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidClose(
      WebSocketChannelClient::kClosingHandshakeIncomplete, 1006, "");
  checkpoint.Call(1);

  websocket_scope.Socket().send(view->buffer(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kClosed, websocket_scope.Socket().readyState());
}

TEST(DOMWebSocketTest, sendArrayBufferSuccess) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  DOMArrayBufferView* view = DOMUint8Array::Create(8);
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Send(Ref(*view->buffer()), 0, 8, _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidConnect("", "");
  websocket_scope.Socket().send(view->buffer(), scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(DOMWebSocket::kOpen, websocket_scope.Socket().readyState());
}

// FIXME: We should have Blob tests here.
// We can't create a Blob because the blob registration cannot be mocked yet.

TEST(DOMWebSocketTest, bufferedAmountUpdated) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
                Connect(KURL("ws://example.com/"), String()))
        .WillOnce(Return(true));
    EXPECT_CALL(websocket_scope.Channel(), Send(std::string("hello"), _));
    EXPECT_CALL(websocket_scope.Channel(), Send(std::string("world"), _));
  }
  websocket_scope.Socket().Connect("ws://example.com/", Vector<String>(),
                                   scope.GetExceptionState());

  EXPECT_FALSE(scope.GetExceptionState().HadException());

  websocket_scope.Socket().DidConnect("", "");
  websocket_scope.Socket().send("hello", scope.GetExceptionState());
  EXPECT_EQ(websocket_scope.Socket().bufferedAmount(), 5u);
  websocket_scope.Socket().send("world", scope.GetExceptionState());
  EXPECT_EQ(websocket_scope.Socket().bufferedAmount(), 10u);
  websocket_scope.Socket().DidConsumeBufferedAmount(5);
  websocket_scope.Socket().DidConsumeBufferedAmount(5);
  EXPECT_EQ(websocket_scope.Socket().bufferedAmount(), 10u);
  blink::test::RunPendingTasks();
  EXPECT_EQ(websocket_scope.Socket().bufferedAmount(), 0u);

  EXPECT_FALSE(scope.GetExceptionState().HadException());
}

TEST(DOMWebSocketTest, bufferedAmountUpdatedBeforeOnMessage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMWebSocketTestScope websocket_scope(scope.GetExecutionContext());
  {
    InSequence s;
    EXPECT_CALL(websocket_scope.Channel(),
```