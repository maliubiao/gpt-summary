Response: The user wants to understand the functionality of the C++ source code file `dispatch_test.cc`. I need to summarize its purpose and illustrate any connection to JavaScript with examples.

**Plan:**

1. **Analyze the code:** Read through the test cases and identify the core functionalities being tested.
2. **Summarize the functionality:**  Describe what the code does in general terms.
3. **Identify JavaScript relevance:** Determine if any parts of the code relate to how JavaScript interacts with the tested functionalities. Keywords like "JSON" and the testing of message formats are hints.
4. **Provide JavaScript examples:** If a connection exists, create simple JavaScript code snippets that demonstrate the interaction. Focus on the message format and how JavaScript would send or receive such messages.
这个C++源代码文件 `dispatch_test.cc` 是为了测试与消息分发相关的C++代码功能。它主要测试了两个核心概念：`DispatchResponse` 和 `Dispatchable`，以及一个更高级的组件 `UberDispatcher`。

**功能归纳:**

1. **`DispatchResponse` 测试:**
   - 测试了表示不同分发结果的状态码和消息，例如 `SUCCESS` (成功), `SERVER_ERROR` (服务器错误), `SESSION_NOT_FOUND` (会话未找到), `INTERNAL_ERROR` (内部错误), `INVALID_PARAMS` (无效参数) 和 `FALL_THROUGH` (传递，表示当前处理者无法处理)。
   - 验证了这些响应的状态（是否成功，是否是传递）以及错误消息是否正确。

2. **`Dispatchable` 测试:**
   - 测试了对接收到的、CBOR（Concise Binary Object Representation）编码的DevTools协议消息的解析功能。
   - 验证了消息必须是一个对象。
   - 验证了消息必须包含一个整数类型的 `id` 属性（用于关联请求和响应）。
   - 验证了消息必须包含一个字符串类型的 `method` 属性（表示要调用的方法）。
   - 验证了消息可以包含一个字符串类型的 `sessionId` 属性（用于指定会话）。
   - 验证了消息可以包含一个对象类型的 `params` 属性（包含方法调用的参数）。
   - 验证了消息中不允许包含其他未知的属性。
   - 测试了处理CBOR格式错误的场景，例如重复的键或尾部有多余的数据。
   - 测试了成功解析有效消息的情况，包括有和没有 `params` 属性。

3. **消息创建辅助函数测试:**
   - 测试了创建符合DevTools协议格式的错误响应、错误通知、成功响应和通知的辅助函数。这些函数将数据结构转换为CBOR格式。

4. **`UberDispatcher` 测试:**
   - 测试了一个更高级的分发器，它负责将接收到的消息路由到不同的领域（domains，例如 "Debugger", "Network" 等）。
   - 测试了当没有找到处理特定方法的领域时的情况（`MethodNotFound` 错误）。
   - 测试了将消息正确分发到已注册的领域处理者的情况。
   - 测试了方法重定向的功能，即可以将一个领域的方法调用重定向到另一个领域的方法处理。

**与 JavaScript 的关系（以及 JavaScript 示例）:**

这个 C++ 代码文件所测试的功能是 DevTools 协议（Chrome DevTools Protocol, CDP）的实现基础。DevTools 协议被用于 Chrome 浏览器和外部工具（如 Node.js 的调试器、Puppeteer 等）之间的通信。JavaScript 代码通常会通过 WebSocket 连接与 Chrome 浏览器建立连接，并发送和接收符合 DevTools 协议格式的消息。

**JavaScript 示例:**

以下 JavaScript 示例展示了如何发送符合 `Dispatchable` 所期望的消息格式：

```javascript
// 发送一个请求 (Request)
const requestId = 1; // 假设的请求 ID
const message = {
  id: requestId,
  method: "Network.enable",
  params: {
    maxTotalBufferSize: 1000000,
    maxResourceBufferSize: 500000,
    maxPostDataSize: 10000
  }
};

const messageString = JSON.stringify(message);
websocket.send(messageString);

// 接收一个响应 (Response)
websocket.onmessage = (event) => {
  const response = JSON.parse(event.data);
  if (response.id === requestId) {
    if (response.error) {
      console.error("请求失败:", response.error);
    } else {
      console.log("请求成功:", response.result);
    }
  }
};

// 接收一个通知 (Notification)
websocket.onmessage = (event) => {
  const notification = JSON.parse(event.data);
  if (notification.method === "Network.requestWillBeSent") {
    console.log("发现新的网络请求:", notification.params.request.url);
  }
};
```

**解释:**

- **请求 (Request):**  JavaScript 代码构造了一个包含 `id`、`method` 和 `params` 属性的 JSON 对象。`id` 用于标识这个请求，`method` 指定要调用的 DevTools 协议方法（例如 `Network.enable`），`params` 包含了方法所需的参数。这个 JSON 对象会被序列化成字符串并通过 WebSocket 发送。  `Dispatchable` 的测试就验证了 C++ 代码能够正确解析这种格式的消息。
- **响应 (Response):**  当 C++ 后端处理完请求后，会生成一个响应。响应的 `id` 应该与请求的 `id` 匹配。响应可能包含一个 `error` 属性（如果请求失败）或者一个 `result` 属性（如果请求成功）。`DispatchResponse` 的测试就验证了 C++ 代码能够生成正确的响应结构和状态码。
- **通知 (Notification):**  DevTools 协议还支持服务端主动向客户端发送通知，例如 `Network.requestWillBeSent`。通知消息没有 `id` 属性，只有一个 `method` 和 `params` 属性。 `UberDispatcher` 的作用就是将接收到的请求或通知分发到正确的 C++ 模块进行处理。

总而言之， `dispatch_test.cc` 这个文件测试了 C++ 代码中负责接收、解析和分发 DevTools 协议消息的核心逻辑，这直接关系到 JavaScript 如何与 Chrome 浏览器进行交互以实现开发者工具的各种功能。

### 提示词
```
这是目录为v8/third_party/inspector_protocol/crdtp/dispatch_test.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <vector>

#include "cbor.h"
#include "dispatch.h"
#include "error_support.h"
#include "frontend_channel.h"
#include "json.h"
#include "test_platform.h"

namespace v8_crdtp {
// =============================================================================
// DispatchResponse - Error status and chaining / fall through
// =============================================================================
TEST(DispatchResponseTest, OK) {
  EXPECT_EQ(DispatchCode::SUCCESS, DispatchResponse::Success().Code());
  EXPECT_TRUE(DispatchResponse::Success().IsSuccess());
}

TEST(DispatchResponseTest, ServerError) {
  DispatchResponse error = DispatchResponse::ServerError("Oops!");
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(DispatchCode::SERVER_ERROR, error.Code());
  EXPECT_EQ("Oops!", error.Message());
}

TEST(DispatchResponseTest, SessionNotFound) {
  DispatchResponse error = DispatchResponse::SessionNotFound("OMG!");
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(DispatchCode::SESSION_NOT_FOUND, error.Code());
  EXPECT_EQ("OMG!", error.Message());
}

TEST(DispatchResponseTest, InternalError) {
  DispatchResponse error = DispatchResponse::InternalError();
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(DispatchCode::INTERNAL_ERROR, error.Code());
  EXPECT_EQ("Internal error", error.Message());
}

TEST(DispatchResponseTest, InvalidParams) {
  DispatchResponse error = DispatchResponse::InvalidParams("too cool");
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(DispatchCode::INVALID_PARAMS, error.Code());
  EXPECT_EQ("too cool", error.Message());
}

TEST(DispatchResponseTest, FallThrough) {
  DispatchResponse error = DispatchResponse::FallThrough();
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_TRUE(error.IsFallThrough());
  EXPECT_EQ(DispatchCode::FALL_THROUGH, error.Code());
}

// =============================================================================
// Dispatchable - a shallow parser for CBOR encoded DevTools messages
// =============================================================================
TEST(DispatchableTest, MessageMustBeAnObject) {
  // Provide no input whatsoever.
  span<uint8_t> empty_span;
  Dispatchable empty(empty_span);
  EXPECT_FALSE(empty.ok());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, empty.DispatchError().Code());
  EXPECT_EQ("Message must be an object", empty.DispatchError().Message());
}

TEST(DispatchableTest, MessageMustHaveIntegerIdProperty) {
  // Construct an empty map inside of an envelope.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(json::ConvertJSONToCBOR(SpanFrom("{}"), &cbor).ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_FALSE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message must have integer 'id' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageMustHaveIntegerIdProperty_IncorrectType) {
  // This time we set the id property, but fail to make it an int32.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(
      json::ConvertJSONToCBOR(SpanFrom("{\"id\":\"foo\"}"), &cbor).ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_FALSE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message must have integer 'id' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageMustHaveStringMethodProperty) {
  // This time we set the id property, but not the method property.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(json::ConvertJSONToCBOR(SpanFrom("{\"id\":42}"), &cbor).ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message must have string 'method' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageMustHaveStringMethodProperty_IncorrectType) {
  // This time we set the method property, but fail to make it a string.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(
      json::ConvertJSONToCBOR(SpanFrom("{\"id\":42,\"method\":42}"), &cbor)
          .ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message must have string 'method' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageMayHaveStringSessionIdProperty) {
  // This time, the session id is an int but it should be a string. Method and
  // call id are present.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(json::ConvertJSONToCBOR(
                  SpanFrom("{\"id\":42,\"method\":\"Foo.executeBar\","
                           "\"sessionId\":42"  // int32 is wrong type
                           "}"),
                  &cbor)
                  .ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message may have string 'sessionId' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageMayHaveObjectParamsProperty) {
  // This time, we fail to use the correct type for the params property.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(json::ConvertJSONToCBOR(
                  SpanFrom("{\"id\":42,\"method\":\"Foo.executeBar\","
                           "\"params\":42"  // int32 is wrong type
                           "}"),
                  &cbor)
                  .ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ("Message may have object 'params' property",
            dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, MessageWithUnknownProperty) {
  // This time we set the 'unknown' property, so we are told what's allowed.
  std::vector<uint8_t> cbor;
  ASSERT_TRUE(
      json::ConvertJSONToCBOR(SpanFrom("{\"id\":42,\"unknown\":42}"), &cbor)
          .ok());
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(DispatchCode::INVALID_REQUEST, dispatchable.DispatchError().Code());
  EXPECT_EQ(
      "Message has property other than 'id', 'method', 'sessionId', 'params'",
      dispatchable.DispatchError().Message());
}

TEST(DispatchableTest, DuplicateMapKey) {
  const std::array<std::string, 4> jsons = {
      {"{\"id\":42,\"id\":42}", "{\"params\":null,\"params\":null}",
       "{\"method\":\"foo\",\"method\":\"foo\"}",
       "{\"sessionId\":\"42\",\"sessionId\":\"42\"}"}};
  for (const std::string& json : jsons) {
    SCOPED_TRACE("json = " + json);
    std::vector<uint8_t> cbor;
    ASSERT_TRUE(json::ConvertJSONToCBOR(SpanFrom(json), &cbor).ok());
    Dispatchable dispatchable(SpanFrom(cbor));
    EXPECT_FALSE(dispatchable.ok());
    EXPECT_EQ(DispatchCode::PARSE_ERROR, dispatchable.DispatchError().Code());
    EXPECT_THAT(dispatchable.DispatchError().Message(),
                testing::StartsWith("CBOR: duplicate map key at position "));
  }
}

TEST(DispatchableTest, ValidMessageParsesOK_NoParams) {
  const std::array<std::string, 2> jsons = {
      {"{\"id\":42,\"method\":\"Foo.executeBar\",\"sessionId\":"
       "\"f421ssvaz4\"}",
       "{\"id\":42,\"method\":\"Foo.executeBar\",\"sessionId\":\"f421ssvaz4\","
       "\"params\":null}"}};
  for (const std::string& json : jsons) {
    SCOPED_TRACE("json = " + json);
    std::vector<uint8_t> cbor;
    ASSERT_TRUE(json::ConvertJSONToCBOR(SpanFrom(json), &cbor).ok());
    Dispatchable dispatchable(SpanFrom(cbor));
    EXPECT_TRUE(dispatchable.ok());
    EXPECT_TRUE(dispatchable.HasCallId());
    EXPECT_EQ(42, dispatchable.CallId());
    EXPECT_EQ("Foo.executeBar", std::string(dispatchable.Method().begin(),
                                            dispatchable.Method().end()));
    EXPECT_EQ("f421ssvaz4", std::string(dispatchable.SessionId().begin(),
                                        dispatchable.SessionId().end()));
    EXPECT_TRUE(dispatchable.Params().empty());
  }
}

TEST(DispatchableTest, ValidMessageParsesOK_WithParams) {
  std::vector<uint8_t> cbor;
  cbor::EnvelopeEncoder envelope;
  envelope.EncodeStart(&cbor);
  cbor.push_back(cbor::EncodeIndefiniteLengthMapStart());
  cbor::EncodeString8(SpanFrom("id"), &cbor);
  cbor::EncodeInt32(42, &cbor);
  cbor::EncodeString8(SpanFrom("method"), &cbor);
  cbor::EncodeString8(SpanFrom("Foo.executeBar"), &cbor);
  cbor::EncodeString8(SpanFrom("params"), &cbor);
  cbor::EnvelopeEncoder params_envelope;
  params_envelope.EncodeStart(&cbor);
  // The |Dispatchable| class does not parse into the "params" envelope,
  // so we can stick anything into there for the purpose of this test.
  // For convenience, we use a String8.
  cbor::EncodeString8(SpanFrom("params payload"), &cbor);
  params_envelope.EncodeStop(&cbor);
  cbor::EncodeString8(SpanFrom("sessionId"), &cbor);
  cbor::EncodeString8(SpanFrom("f421ssvaz4"), &cbor);
  cbor.push_back(cbor::EncodeStop());
  envelope.EncodeStop(&cbor);
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_TRUE(dispatchable.ok());
  EXPECT_TRUE(dispatchable.HasCallId());
  EXPECT_EQ(42, dispatchable.CallId());
  EXPECT_EQ("Foo.executeBar", std::string(dispatchable.Method().begin(),
                                          dispatchable.Method().end()));
  EXPECT_EQ("f421ssvaz4", std::string(dispatchable.SessionId().begin(),
                                      dispatchable.SessionId().end()));
  cbor::CBORTokenizer params_tokenizer(dispatchable.Params());
  ASSERT_EQ(cbor::CBORTokenTag::ENVELOPE, params_tokenizer.TokenTag());
  params_tokenizer.EnterEnvelope();
  ASSERT_EQ(cbor::CBORTokenTag::STRING8, params_tokenizer.TokenTag());
  EXPECT_EQ("params payload", std::string(params_tokenizer.GetString8().begin(),
                                          params_tokenizer.GetString8().end()));
}

TEST(DispatchableTest, FaultyCBORTrailingJunk) {
  // In addition to the higher level parsing errors, we also catch CBOR
  // structural corruption. E.g., in this case, the message would be
  // OK but has some extra trailing bytes.
  std::vector<uint8_t> cbor;
  cbor::EnvelopeEncoder envelope;
  envelope.EncodeStart(&cbor);
  cbor.push_back(cbor::EncodeIndefiniteLengthMapStart());
  cbor::EncodeString8(SpanFrom("id"), &cbor);
  cbor::EncodeInt32(42, &cbor);
  cbor::EncodeString8(SpanFrom("method"), &cbor);
  cbor::EncodeString8(SpanFrom("Foo.executeBar"), &cbor);
  cbor::EncodeString8(SpanFrom("sessionId"), &cbor);
  cbor::EncodeString8(SpanFrom("f421ssvaz4"), &cbor);
  cbor.push_back(cbor::EncodeStop());
  envelope.EncodeStop(&cbor);
  size_t trailing_junk_pos = cbor.size();
  cbor.push_back('t');
  cbor.push_back('r');
  cbor.push_back('a');
  cbor.push_back('i');
  cbor.push_back('l');
  Dispatchable dispatchable(SpanFrom(cbor));
  EXPECT_FALSE(dispatchable.ok());
  EXPECT_EQ(DispatchCode::PARSE_ERROR, dispatchable.DispatchError().Code());
  EXPECT_EQ(57u, trailing_junk_pos);
  EXPECT_EQ("CBOR: trailing junk at position 57",
            dispatchable.DispatchError().Message());
}

// =============================================================================
// Helpers for creating protocol cresponses and notifications.
// =============================================================================
TEST(CreateErrorResponseTest, SmokeTest) {
  auto serializable = CreateErrorResponse(
      42, DispatchResponse::InvalidParams("invalid params message"));
  std::string json;
  auto status =
      json::ConvertCBORToJSON(SpanFrom(serializable->Serialize()), &json);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ(
      "{\"id\":42,\"error\":"
      "{\"code\":-32602,"
      "\"message\":\"invalid params message\"}}",
      json);
}

TEST(CreateErrorNotificationTest, SmokeTest) {
  auto serializable =
      CreateErrorNotification(DispatchResponse::InvalidRequest("oops!"));
  std::string json;
  auto status =
      json::ConvertCBORToJSON(SpanFrom(serializable->Serialize()), &json);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ("{\"error\":{\"code\":-32600,\"message\":\"oops!\"}}", json);
}

TEST(CreateResponseTest, SmokeTest) {
  auto serializable = CreateResponse(42, nullptr);
  std::string json;
  auto status =
      json::ConvertCBORToJSON(SpanFrom(serializable->Serialize()), &json);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ("{\"id\":42,\"result\":{}}", json);
}

TEST(CreateNotificationTest, SmokeTest) {
  auto serializable = CreateNotification("Foo.bar");
  std::string json;
  auto status =
      json::ConvertCBORToJSON(SpanFrom(serializable->Serialize()), &json);
  ASSERT_TRUE(status.ok());
  EXPECT_EQ("{\"method\":\"Foo.bar\",\"params\":{}}", json);
}

// =============================================================================
// UberDispatcher - dispatches between domains (backends).
// =============================================================================
class TestChannel : public FrontendChannel {
 public:
  std::string JSON() const {
    std::string json;
    json::ConvertCBORToJSON(SpanFrom(cbor_), &json);
    return json;
  }

 private:
  void SendProtocolResponse(int call_id,
                            std::unique_ptr<Serializable> message) override {
    cbor_ = message->Serialize();
  }

  void SendProtocolNotification(
      std::unique_ptr<Serializable> message) override {
    cbor_ = message->Serialize();
  }

  void FallThrough(int call_id,
                   span<uint8_t> method,
                   span<uint8_t> message) override {}

  void FlushProtocolNotifications() override {}

  std::vector<uint8_t> cbor_;
};

TEST(UberDispatcherTest, MethodNotFound) {
  // No domain dispatchers are registered, so unsuprisingly, we'll get a method
  // not found error and can see that DispatchResult::MethodFound() yields
  // false.
  TestChannel channel;
  UberDispatcher dispatcher(&channel);
  std::vector<uint8_t> message;
  json::ConvertJSONToCBOR(SpanFrom("{\"id\":42,\"method\":\"Foo.bar\"}"),
                          &message);
  Dispatchable dispatchable(SpanFrom(message));
  ASSERT_TRUE(dispatchable.ok());
  UberDispatcher::DispatchResult dispatched = dispatcher.Dispatch(dispatchable);
  EXPECT_FALSE(dispatched.MethodFound());
  dispatched.Run();
  EXPECT_EQ(
      "{\"id\":42,\"error\":"
      "{\"code\":-32601,\"message\":\"'Foo.bar' wasn't found\"}}",
      channel.JSON());
}

// A domain dispatcher which captured dispatched and executed commands in fields
// for testing.
class TestDomain : public DomainDispatcher {
 public:
  explicit TestDomain(FrontendChannel* channel) : DomainDispatcher(channel) {}

  std::function<void(const Dispatchable&)> Dispatch(
      span<uint8_t> command_name) override {
    dispatched_commands_.push_back(
        std::string(command_name.begin(), command_name.end()));
    return [this](const Dispatchable& dispatchable) {
      executed_commands_.push_back(dispatchable.CallId());
    };
  }

  // Command names of the dispatched commands.
  std::vector<std::string> DispatchedCommands() const {
    return dispatched_commands_;
  }

  // Call ids of the executed commands.
  std::vector<int32_t> ExecutedCommands() const { return executed_commands_; }

 private:
  std::vector<std::string> dispatched_commands_;
  std::vector<int32_t> executed_commands_;
};

TEST(UberDispatcherTest, DispatchingToDomainWithRedirects) {
  // This time, we register two domain dispatchers (Foo and Bar) and issue one
  // command 'Foo.execute' which executes on Foo and one command 'Foo.redirect'
  // which executes as 'Bar.redirected'.
  TestChannel channel;
  UberDispatcher dispatcher(&channel);
  auto foo_dispatcher = std::make_unique<TestDomain>(&channel);
  TestDomain* foo = foo_dispatcher.get();
  auto bar_dispatcher = std::make_unique<TestDomain>(&channel);
  TestDomain* bar = bar_dispatcher.get();

  dispatcher.WireBackend(
      SpanFrom("Foo"), {{SpanFrom("Foo.redirect"), SpanFrom("Bar.redirected")}},
      std::move(foo_dispatcher));
  dispatcher.WireBackend(SpanFrom("Bar"), {}, std::move(bar_dispatcher));

  {
    std::vector<uint8_t> message;
    json::ConvertJSONToCBOR(SpanFrom("{\"id\":42,\"method\":\"Foo.execute\"}"),
                            &message);
    Dispatchable dispatchable(SpanFrom(message));
    ASSERT_TRUE(dispatchable.ok());
    UberDispatcher::DispatchResult dispatched =
        dispatcher.Dispatch(dispatchable);
    EXPECT_TRUE(dispatched.MethodFound());
    dispatched.Run();
  }
  {
    std::vector<uint8_t> message;
    json::ConvertJSONToCBOR(SpanFrom("{\"id\":43,\"method\":\"Foo.redirect\"}"),
                            &message);
    Dispatchable dispatchable(SpanFrom(message));
    ASSERT_TRUE(dispatchable.ok());
    UberDispatcher::DispatchResult dispatched =
        dispatcher.Dispatch(dispatchable);
    EXPECT_TRUE(dispatched.MethodFound());
    dispatched.Run();
  }
  EXPECT_THAT(foo->DispatchedCommands(), testing::ElementsAre("execute"));
  EXPECT_THAT(foo->ExecutedCommands(), testing::ElementsAre(42));
  EXPECT_THAT(bar->DispatchedCommands(), testing::ElementsAre("redirected"));
  EXPECT_THAT(bar->ExecutedCommands(), testing::ElementsAre(43));
}
}  // namespace v8_crdtp
```