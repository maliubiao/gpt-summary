Response:
My thinking process to answer the request about `v8/third_party/inspector_protocol/crdtp/dispatch_test.cc` went something like this:

1. **Understand the File Path and Context:** The path `v8/third_party/inspector_protocol/crdtp/dispatch_test.cc` immediately tells me this is a test file within the V8 project related to the Chrome DevTools Protocol (CRDP). The `dispatch` part suggests it's testing how CRDP commands are routed and handled. The `.cc` extension confirms it's C++ code.

2. **Initial Scan for Key Concepts:** I quickly scanned the code for keywords and patterns like `TEST`, `EXPECT_EQ`, `DispatchResponse`, `Dispatchable`, `UberDispatcher`, `DomainDispatcher`, `FrontendChannel`, `json::ConvertJSONToCBOR`, `cbor::`, and namespaces like `v8_crdtp`. These give me a high-level understanding of the file's purpose.

3. **Break Down by Test Case:**  The code is structured as a series of `TEST` blocks. This is the core of the file. I decided to go through each major test category and summarize its functionality:

    * **`DispatchResponseTest`:**  This section is clearly about testing the `DispatchResponse` class. I noted the different error types being tested (OK, ServerError, SessionNotFound, etc.) and that it checks the `Code()` and `Message()` methods.

    * **`DispatchableTest`:** This section focuses on the `Dispatchable` class, which seems to be responsible for parsing and validating incoming CRDP messages (likely in CBOR format). I paid attention to the different validation scenarios being tested: missing `id`, incorrect `id` type, missing `method`, incorrect `method` type, invalid `sessionId`, invalid `params`, unknown properties, and duplicate keys. The tests involving `json::ConvertJSONToCBOR` and `cbor::` confirmed the CBOR and JSON relationship. I also noted the test for valid messages and the handling of the `params` field. The "FaultyCBORTrailingJunk" test highlighted the robustness checks for malformed CBOR.

    * **`CreateErrorResponseTest`, `CreateErrorNotificationTest`, `CreateResponseTest`, `CreateNotificationTest`:** These tests are about helper functions that create standardized CRDP response and notification messages. The tests use `json::ConvertCBORToJSON` to verify the output format.

    * **`UberDispatcherTest`:**  This section tests the `UberDispatcher`, which seems to be the central component responsible for routing incoming messages to the appropriate "domain" handlers. The "MethodNotFound" test is straightforward. The "DispatchingToDomainWithRedirects" test showcases how the dispatcher maps methods to domain handlers and handles method renaming/redirection.

4. **Address Specific Questions in the Prompt:** Once I had a good understanding of the code's structure and functionality, I addressed each specific point in the prompt:

    * **Functionality:**  I summarized the key functionalities based on the test categories I'd identified.

    * **Torque:**  I checked for the `.tq` extension and confirmed it's `.cc`, so it's C++ and not Torque.

    * **JavaScript Relation:**  I considered how this C++ code relates to JavaScript. The CRDP is used to communicate with the JavaScript engine in V8. I explained this connection and provided a JavaScript example of sending a CRDP command, linking it to the C++ parsing and dispatching logic.

    * **Code Logic Inference (Input/Output):** For `DispatchableTest`, I selected a couple of key tests (like the "ValidMessageParsesOK_NoParams") and provided the JSON input, the expected CBOR conversion, and the expected extracted values (`CallId`, `Method`, `SessionId`). This demonstrates the parsing logic.

    * **Common Programming Errors:**  I thought about the types of errors the tests are designed to catch. These directly translate to common mistakes developers might make when implementing or using CRDP: incorrect data types, missing required fields, extra unexpected fields, and malformed message structures. I provided JavaScript examples of these errors to make them more relatable.

5. **Refine and Organize:** I reviewed my notes and organized the information into a clear and structured answer, using headings and bullet points to improve readability. I made sure to explain the purpose of each major component and test category. I also double-checked the code snippets and explanations for accuracy.

Essentially, my process was a combination of top-down (understanding the overall purpose and structure) and bottom-up (examining individual test cases) analysis, guided by the specific questions in the prompt. The key was to connect the individual test cases back to the broader functionality of message dispatching and error handling within the CRDP context.
这个C++源代码文件 `v8/third_party/inspector_protocol/crdtp/dispatch_test.cc` 是 V8 JavaScript 引擎中，用于测试 Chrome DevTools Protocol (CRDP) 消息分发功能的单元测试文件。它主要测试以下几个方面：

**1. `DispatchResponse` 类的功能测试:**

*   **成功状态:**  测试 `DispatchResponse::Success()` 是否能正确表示操作成功。
*   **错误状态:** 测试各种预定义的错误类型（例如 `ServerError`, `SessionNotFound`, `InternalError`, `InvalidParams`）是否能被正确创建和识别，包括错误代码和错误消息。
*   **Fall Through 状态:** 测试 `DispatchResponse::FallThrough()` 是否能表示需要将消息传递给下一个处理器。

**2. `Dispatchable` 类的功能测试:**

*   **消息解析:** 测试 `Dispatchable` 类是否能正确解析 CBOR 格式的 DevTools 消息。
*   **消息结构验证:** 测试 `Dispatchable` 类是否能验证消息的基本结构，例如：
    *   消息必须是一个对象。
    *   必须包含整数类型的 `id` 属性（用于请求/响应匹配）。
    *   必须包含字符串类型的 `method` 属性（表示调用的方法）。
    *   可选的字符串类型的 `sessionId` 属性。
    *   可选的对象类型的 `params` 属性。
*   **错误处理:** 测试当消息格式不正确时，`Dispatchable` 类是否能正确识别并返回相应的错误代码和消息（例如 `INVALID_REQUEST`, `PARSE_ERROR`）。
*   **重复键检测:** 测试 `Dispatchable` 类是否能检测到 CBOR 消息中重复的键。
*   **成功解析:** 测试 `Dispatchable` 类是否能成功解析格式正确的消息，并提取 `id`, `method`, `sessionId`, 和 `params` 等属性。
*   **处理 `params`:** 测试 `Dispatchable` 类如何处理 `params` 属性，即使 `params` 内部的结构不是它直接解析的范围。
*   **处理尾部垃圾数据:** 测试 `Dispatchable` 类在解析 CBOR 消息时，是否能检测到并报错尾部多余的数据。

**3. 创建 CRDP 响应和通知的辅助函数测试:**

*   **`CreateErrorResponse`:** 测试创建包含错误信息的响应消息。
*   **`CreateErrorNotification`:** 测试创建包含错误信息的通知消息。
*   **`CreateResponse`:** 测试创建成功响应消息。
*   **`CreateNotification`:** 测试创建通知消息。

**4. `UberDispatcher` 类的功能测试:**

*   **方法未找到:** 测试当没有注册处理特定方法的后端时，`UberDispatcher` 是否能正确返回 "Method not found" 错误。
*   **消息分发:** 测试 `UberDispatcher` 如何将消息分发到已注册的 `DomainDispatcher`。
*   **方法重定向:** 测试 `UberDispatcher` 是否能根据配置将某个方法重定向到另一个 `DomainDispatcher` 处理。

**如果 `v8/third_party/inspector_protocol/crdtp/dispatch_test.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**

但实际上，这个文件以 `.cc` 结尾，所以它是 C++ 源代码，而不是 Torque 源代码。 Torque 是 V8 用于实现某些内置功能的特定领域语言。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`dispatch_test.cc` 测试的是 CRDP 消息的处理，而 CRDP 正是用于连接 DevTools 前端（通常是用 JavaScript 编写的）和 V8 引擎的桥梁。  当你在 Chrome DevTools 中进行操作时（例如，设置断点、查看控制台输出等），DevTools 前端会发送符合 CRDP 协议的消息给 V8，V8 也会通过 CRDP 发送响应和事件给前端。

例如，一个 JavaScript 代码可能导致 DevTools 前端发送一个 CRDP 请求来评估表达式：

```javascript
// 假设这是 DevTools 前端发送给 V8 的消息 (简化)
const message = {
  id: 1,
  method: "Runtime.evaluate",
  params: {
    expression: "1 + 1",
    returnByValue: true
  }
};

// 这个 JSON 结构会被转换为 CBOR 并发送给 V8。
```

`dispatch_test.cc` 中的 `DispatchableTest` 就是在测试 V8 如何解析和验证这种 CBOR 格式的消息。 `UberDispatcherTest` 则测试 V8 如何将 `Runtime.evaluate` 这个方法名路由到负责处理运行时操作的后端模块。

**如果有代码逻辑推理，请给出假设输入与输出:**

以 `DispatchableTest` 中的 `ValidMessageParsesOK_NoParams` 测试为例：

**假设输入 (JSON 字符串):**

```json
{"id":42,"method":"Foo.executeBar","sessionId":"f421ssvaz4"}
```

**转换成 CBOR (内部表示，不容易直接展示，但概念上会编码这些键值对):**

`Dispatchable` 类会将这个 JSON 字符串转换为 CBOR 格式进行解析。

**预期输出 (`Dispatchable` 对象的属性值):**

*   `dispatchable.ok()`: `true` (表示解析成功)
*   `dispatchable.HasCallId()`: `true`
*   `dispatchable.CallId()`: `42`
*   `dispatchable.Method()`: 指向 "Foo.executeBar" 字符串的 `span`
*   `dispatchable.SessionId()`: 指向 "f421ssvaz4" 字符串的 `span`
*   `dispatchable.Params()`: 空的 `span` (因为没有 `params` 属性或 `params` 为 `null`)

**如果涉及用户常见的编程错误，请举例说明:**

`DispatchableTest` 中测试的很多错误情况都对应着用户在实现 CRDP 客户端或服务端时可能犯的错误：

1. **缺少 `id` 或 `method` 属性:**

    ```javascript
    // 错误的 CRDP 消息，缺少 method
    const badMessage = { id: 1 };
    // 错误的 CRDP 消息，缺少 id
    const anotherBadMessage = { method: "Runtime.evaluate" };
    ```

    `DispatchableTest` 中的 `MessageMustHaveIntegerIdProperty` 和 `MessageMustHaveStringMethodProperty` 就覆盖了这种情况。

2. **`id` 或 `method` 属性类型错误:**

    ```javascript
    // 错误的 CRDP 消息，id 应该是数字
    const badTypeMessage = { id: "1", method: "Runtime.evaluate" };
    ```

    `DispatchableTest` 中的 `MessageMustHaveIntegerIdProperty_IncorrectType` 和 `MessageMustHaveStringMethodProperty_IncorrectType` 覆盖了这种情况。

3. **`sessionId` 或 `params` 属性类型错误:**

    ```javascript
    // 错误的 CRDP 消息，sessionId 应该是字符串
    const badSessionId = { id: 1, method: "Runtime.evaluate", sessionId: 123 };
    // 错误的 CRDP 消息，params 应该是对象
    const badParams = { id: 1, method: "Runtime.evaluate", params: "some string" };
    ```

    `DispatchableTest` 中的 `MessageMayHaveStringSessionIdProperty` 和 `MessageMayHaveObjectParamsProperty` 覆盖了这些错误。

4. **包含未知的属性:**

    ```javascript
    // 错误的 CRDP 消息，包含未知的属性 'extra'
    const unknownProperty = { id: 1, method: "Runtime.evaluate", extra: "value" };
    ```

    `DispatchableTest` 中的 `MessageWithUnknownProperty` 覆盖了这种情况，确保 V8 能识别并拒绝包含未知属性的消息。

5. **发送格式错误的 CBOR 数据 (虽然通常是由序列化库处理，但理解其重要性):**

    虽然开发者通常不会手动构建 CBOR 数据，但如果底层的序列化或传输过程出现错误，可能会导致 CBOR 格式不正确，例如 `DispatchableTest` 中的 `FaultyCBORTrailingJunk` 测试就模拟了这种情况。

总而言之，`v8/third_party/inspector_protocol/crdtp/dispatch_test.cc` 是一个非常重要的测试文件，它确保了 V8 能够正确地接收、解析、验证和分发 Chrome DevTools Protocol 消息，保证了 DevTools 和 V8 引擎之间的可靠通信。

Prompt: 
```
这是目录为v8/third_party/inspector_protocol/crdtp/dispatch_test.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/third_party/inspector_protocol/crdtp/dispatch_test.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
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

"""

```