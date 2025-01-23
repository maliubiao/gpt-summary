Response:
Let's break down the thought process for analyzing this C++ test file for the Blink rendering engine.

**1. Understanding the Goal:**

The primary goal is to understand the purpose of this specific test file (`event_source_parser_test.cc`). We need to figure out what component it's testing, how it tests it, and what the implications are for web development (JavaScript, HTML, CSS).

**2. Initial Scan and Keyword Identification:**

I'll start by quickly scanning the code for key terms and patterns:

* **`EventSourceParser`:** This is the central class being tested. The file name confirms this.
* **`TEST_F` and `TEST`:** These are standard Google Test macros, indicating test cases.
* **`Enqueue` and `EnqueueOneByOne`:**  These functions likely feed input to the `EventSourceParser`.
* **`Events()`:** This function probably retrieves the results of the parsing.
* **`LastEventId()`:**  This suggests the parser keeps track of a last event ID.
* **`OnMessageEvent` and `OnReconnectionTimeSet`:** These are methods in the `Client` class, which is likely a mock or stub used to observe the parser's output.
* **`data:`, `event:`, `id:`, `retry:`:** These look like the field names used in Server-Sent Events (SSE).

**3. Deciphering the Test Structure:**

The `EventSourceParserTest` class sets up the testing environment. It creates an instance of `EventSourceParser` and a `Client` object. The `Enqueue` functions simulate feeding data to the parser. The `Events()` function allows inspection of the events received by the `Client`.

The individual `TEST_F` blocks represent specific test scenarios. Each test focuses on a particular aspect of the parser's behavior.

**4. Connecting to Web Standards (SSE):**

The presence of `data:`, `event:`, `id:`, and `retry:` strongly suggests this test file is related to the **Server-Sent Events (SSE)** standard. SSE is a web technology that allows a server to push updates to a web page over a single HTTP connection.

**5. Analyzing Individual Test Cases:**

Now, I'll go through each test case and interpret its purpose:

* **`EmptyMessageEventShouldNotBeDispatched`:**  Verifies that an empty line doesn't trigger an event.
* **`DispatchSimpleMessageEvent`:**  Tests basic data parsing.
* **`ConstructWithLastEventId`:** Checks how the parser handles an initial `Last-Event-ID`.
* **`DispatchMessageEventWithLastEventId`:** Tests the parsing of the `id` field.
* **`LastEventIdCanBeUpdatedEvenWhenDataIsEmpty`:** Checks that `id` updates even without `data`.
* **`DispatchMessageEventWithCustomEventType`:**  Tests the `event` field.
* **`RetryTakesEffectEvenWhenNotDispatching`:** Verifies handling of the `retry` field.
* **`EventTypeShouldBeReset`:** Ensures event types don't carry over between messages.
* **`DataShouldBeReset`:** Ensures data doesn't carry over.
* **`LastEventIdShouldNotBeReset`:** Confirms `id` persists.
* **`VariousNewLinesShouldBeAllowed`:** Checks support for `\n` and `\r\n`.
* **`RetryWithEmptyValueShouldRestoreDefaultValue`:** Tests the behavior of an empty `retry` value (note the comment about the spec).
* **`NonDigitRetryShouldBeIgnored`:** Verifies that invalid `retry` values are ignored.
* **`UnrecognizedFieldShouldBeIgnored`:** Tests the parser's handling of unknown fields.
* **`CommentShouldBeIgnored`:** Checks that lines starting with `:` are ignored.
* **`BOMShouldBeIgnored` and `BOMShouldBeIgnored_OneByOne`:** Tests handling of the Byte Order Mark.
* **`ColonlessLineShouldBeTreatedAsNameOnlyField`:** Checks behavior of lines without a colon.
* **`AtMostOneLeadingSpaceCanBeSkipped`:** Tests whitespace trimming.
* **`DataShouldAccumulate`:** Verifies that multiple `data:` lines are concatenated.
* **`EventShouldNotAccumulate`:** Ensures only the last `event:` is used.
* **`FeedDataOneByOne`:** Tests parsing when data is fed incrementally.
* **`InvalidUTF8Sequence`:** Checks how the parser handles invalid UTF-8.
* **`StopWhileParsing` (in `EventSourceParserStoppingTest`):** Tests the ability to stop the parser mid-stream.
* **`IgnoreIdHavingNullCharacter`:** Verifies handling of null characters in the `id` field.

**6. Relating to JavaScript, HTML, and CSS:**

* **JavaScript:** The primary interaction with SSE is through the JavaScript `EventSource` API. This test file directly verifies the correct parsing of the data format that `EventSource` relies on. Incorrect parsing in the engine would lead to errors or unexpected behavior in JavaScript code using `EventSource`.
* **HTML:**  While HTML doesn't directly parse SSE, the `EventSource` API is used within the context of a web page, defined by HTML.
* **CSS:** CSS is not directly related to the *parsing* of SSE data. However, the *content* delivered via SSE might be used to dynamically update the styling of a web page via JavaScript, making it indirectly related.

**7. Logical Inferences and Examples:**

Based on the test names and code, I can infer the intended behavior of the parser for different inputs. The "Assumptions and Input/Output" section in the detailed answer provides concrete examples.

**8. Identifying Potential User/Programming Errors:**

By understanding how the parser works and the validation it performs (e.g., for `retry`), I can identify common errors developers might make when setting up SSE on the server-side.

**9. Tracing User Operations:**

To understand how a user's action leads to this code, I think about the chain of events:

1. User navigates to a web page.
2. The JavaScript on the page creates an `EventSource` object, pointing to an SSE endpoint on the server.
3. The browser makes an HTTP request to that endpoint.
4. The server sends back an SSE stream.
5. The browser's networking layer receives the data.
6. The data is passed to the `EventSourceParser` within the Blink rendering engine.

**10. Structuring the Answer:**

Finally, I organize the information into a clear and comprehensive answer, covering the requested points: functionality, relationship to web technologies, logical inferences, common errors, and the user operation trace. I use clear headings and examples to make it easy to understand.
这个文件 `event_source_parser_test.cc` 是 Chromium Blink 引擎中用于测试 `EventSourceParser` 类的单元测试文件。 `EventSourceParser` 负责解析 Server-Sent Events (SSE) 流。

以下是该文件的功能列表以及与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误和调试线索：

**文件功能:**

1. **测试 `EventSourceParser` 的消息解析:** 该文件包含了多个测试用例，用于验证 `EventSourceParser` 是否能正确解析各种格式的 SSE 消息。
2. **测试不同字段的解析:**  测试用例涵盖了对 `data`, `event`, `id`, `retry` 等 SSE 消息中关键字段的解析。
3. **测试边界情况和错误处理:** 测试用例包括空消息、不同类型的换行符、无效的 `retry` 值、未识别的字段、注释、BOM (Byte Order Mark)、以及包含空字符的 `id` 等边界情况和错误输入的处理。
4. **测试 `Last-Event-ID` 的处理:**  测试用例验证了 `EventSourceParser` 如何更新和存储 `Last-Event-ID`，这是 SSE 协议中用于断线重连的重要机制。
5. **测试分段接收数据:**  通过 `EnqueueOneByOne` 函数模拟分段接收 SSE 数据流，验证解析器在接收不完整数据时的处理能力。
6. **测试停止解析:**  `StoppingClient` 类和相关的测试用例展示了在解析过程中停止解析器的功能。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** 该测试文件直接关联到 JavaScript 的 `EventSource` API。 `EventSource` API 允许 JavaScript 代码接收来自服务器的实时推送更新。 `EventSourceParser` 负责解析服务器发送的符合 SSE 规范的数据，然后将解析后的事件传递给 JavaScript。
    * **举例说明:**  在 JavaScript 中创建一个 `EventSource` 对象：
      ```javascript
      const eventSource = new EventSource('/sse-endpoint');

      eventSource.onmessage = function(event) {
        console.log('Received data:', event.data);
      };

      eventSource.addEventListener('custom-event', function(event) {
        console.log('Received custom event:', event.data);
      });
      ```
      当服务器向 `/sse-endpoint` 发送 SSE 数据时，例如 `data: hello\n\n` 或 `event: custom-event\ndata: world\n\n`，Blink 引擎中的 `EventSourceParser` 会解析这些数据，并触发 `onmessage` 或 `custom-event` 对应的事件处理函数。
* **HTML:** HTML 本身不直接参与 SSE 数据的解析，但 `EventSource` API 是在 HTML 页面中的 JavaScript 代码中使用的。 服务器发送的 SSE 数据最终会更新 HTML 页面上的内容。
    * **举例说明:** JavaScript 通过 `EventSource` 接收数据后，可能会动态更新 HTML 元素的内容：
      ```javascript
      const eventSource = new EventSource('/sse-endpoint');
      const outputDiv = document.getElementById('output');

      eventSource.onmessage = function(event) {
        outputDiv.textContent += event.data + '\n';
      };
      ```
* **CSS:** CSS 与 `EventSourceParser` 的关系较为间接。  通过 SSE 接收到的数据可能会触发 JavaScript 代码来修改 HTML 元素的样式，从而间接地影响 CSS 的应用效果。
    * **举例说明:**  服务器发送状态信息，JavaScript 根据状态信息修改元素的 CSS 类：
      ```javascript
      const eventSource = new EventSource('/sse-endpoint');
      const statusElement = document.getElementById('status');

      eventSource.onmessage = function(event) {
        if (event.data === 'online') {
          statusElement.classList.add('online');
          statusElement.classList.remove('offline');
        } else if (event.data === 'offline') {
          statusElement.classList.add('offline');
          statusElement.classList.remove('online');
        }
      };
      ```

**逻辑推理与假设输入/输出:**

许多测试用例都基于对 SSE 规范的逻辑推理。以下是一些例子：

* **假设输入:** `"data:hello\n\n"`
   * **推理:**  根据 SSE 规范，`data:` 行表示数据，`\n\n` 表示消息结束。
   * **预期输出:**  触发 `OnMessageEvent` 回调，`event` 为 "message"，`data` 为 "hello"，`id` 为空。
* **假设输入:** `"event:foo\ndata:hello\n\n"`
   * **推理:** `event:` 行指定了事件类型。
   * **预期输出:** 触发 `OnMessageEvent` 回调，`event` 为 "foo"，`data` 为 "hello"。
* **假设输入:** `"id:123\ndata:hello\n\n"`
   * **推理:** `id:` 行设置了事件的 ID。
   * **预期输出:** 触发 `OnMessageEvent` 回调，`id` 为 "123"，并且 `LastEventId()` 返回 "123"。
* **假设输入:** `"retry:1000\n"`
   * **推理:** `retry:` 行设置了重连等待时间。
   * **预期输出:** 触发 `OnReconnectionTimeSet` 回调，`reconnection_time` 为 1000。
* **假设输入:** `"data:line1\ndata:line2\n\n"`
   * **推理:** 多个 `data:` 行应该连接在一起。
   * **预期输出:** 触发 `OnMessageEvent` 回调，`data` 为 "line1\nline2"。

**用户或编程常见的使用错误:**

1. **服务器发送的 SSE 数据格式不正确:** 例如，缺少 `\n\n` 来分隔消息，字段名拼写错误，或者使用了错误的换行符 (`\r` 而不是 `\n` 或 `\r\n`)。
   * **举例:** 服务器发送了 `"data:hello"` 而没有结尾的 `\n\n`，`EventSourceParser` 将不会触发消息事件。
2. **`retry` 值不是数字:**  根据规范，`retry` 字段的值必须是整数。
   * **举例:** 服务器发送了 `"retry:abc\n"`，`EventSourceParser` 会忽略这个 `retry` 设置。
3. **依赖于特定的字段顺序:**  虽然通常 `data` 字段在其他字段之后，但规范并没有强制要求顺序。
4. **错误地处理 `Last-Event-ID`:**  如果服务器在重连时没有正确使用客户端发送的 `Last-Event-ID`，可能会导致消息丢失或重复。
5. **客户端没有正确处理不同的事件类型:**  如果服务器发送了自定义事件 (`event: custom-event`)，但客户端的 JavaScript 代码只监听 `message` 事件，那么自定义事件将被忽略。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个网页:** 用户在地址栏输入网址或点击链接。
2. **网页加载，JavaScript 代码执行:** 浏览器解析 HTML，加载并执行 JavaScript 代码。
3. **JavaScript 代码创建 `EventSource` 对象:**  例如 `const es = new EventSource('/my-sse-stream');`。
4. **浏览器向服务器发起 HTTP 请求:**  浏览器根据 `EventSource` 的 URL 向服务器发送请求，通常带有 `Accept: text/event-stream` 头。
5. **服务器响应并开始发送 SSE 数据流:** 服务器保持连接打开，并按照 SSE 格式 (例如 `data: ...\n\n`) 向浏览器发送数据。
6. **Blink 引擎接收到数据:** 浏览器的网络层接收到来自服务器的数据流。
7. **数据被传递给 `EventSourceParser`:** Blink 引擎的 `EventSource` 模块将接收到的字节流传递给 `EventSourceParser` 进行解析。
8. **`EventSourceParser` 解析数据:**  `EventSourceParser` 按照 SSE 规范解析数据，提取 `data`, `event`, `id`, `retry` 等字段。
9. **触发客户端回调:** 解析完成后，`EventSourceParser` 会调用 `EventSourceParser::Client` 接口的方法，例如 `OnMessageEvent` 或 `OnReconnectionTimeSet`，这些方法最终会触发 JavaScript 中 `EventSource` 对象的 `onmessage` 或 `addEventListener` 注册的回调函数。
10. **如果解析过程中出现问题:**  例如，接收到的数据格式不正确，可能会触发错误处理逻辑，或者导致消息无法被正确解析和传递给 JavaScript。这时，开发人员可能会查看 Blink 引擎的日志或使用开发者工具的网络面板来检查服务器发送的数据和浏览器端的处理过程。`event_source_parser_test.cc` 中的测试用例就是为了确保 `EventSourceParser` 在各种情况下都能正确工作。

因此，当你在浏览器中访问一个使用 Server-Sent Events 的网页时，你发送的请求和服务器的响应数据会经过 `EventSourceParser` 的处理。如果出现问题，对 `EventSourceParser` 的单元测试可以帮助开发者理解和调试问题所在。 例如，如果 JavaScript 代码没有收到预期的消息，可能是因为服务器发送的数据格式不符合 SSE 规范，而 `event_source_parser_test.cc` 中相关的测试用例（例如测试不同换行符或错误格式的 `retry`）可以帮助定位这类问题。

### 提示词
```
这是目录为blink/renderer/modules/eventsource/event_source_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/eventsource/event_source_parser.h"

#include <string.h>

#include <string_view>

#include "base/ranges/algorithm.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/modules/eventsource/event_source.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"

namespace blink {

namespace {

struct EventOrReconnectionTimeSetting {
  enum Type {
    kEvent,
    kReconnectionTimeSetting,
  };

  EventOrReconnectionTimeSetting(const AtomicString& event,
                                 const String& data,
                                 const AtomicString& id)
      : type(kEvent), event(event), data(data), id(id), reconnection_time(0) {}
  explicit EventOrReconnectionTimeSetting(uint64_t reconnection_time)
      : type(kReconnectionTimeSetting), reconnection_time(reconnection_time) {}

  const Type type;
  const AtomicString event;
  const String data;
  const AtomicString id;
  const uint64_t reconnection_time;
};

class Client : public GarbageCollected<Client>,
               public EventSourceParser::Client {
 public:
  ~Client() override = default;
  const Vector<EventOrReconnectionTimeSetting>& Events() const {
    return events_;
  }
  void OnMessageEvent(const AtomicString& event,
                      const String& data,
                      const AtomicString& id) override {
    events_.push_back(EventOrReconnectionTimeSetting(event, data, id));
  }
  void OnReconnectionTimeSet(uint64_t reconnection_time) override {
    events_.push_back(EventOrReconnectionTimeSetting(reconnection_time));
  }

 private:
  Vector<EventOrReconnectionTimeSetting> events_;
};

class StoppingClient : public GarbageCollected<StoppingClient>,
                       public EventSourceParser::Client {
 public:
  ~StoppingClient() override = default;
  const Vector<EventOrReconnectionTimeSetting>& Events() const {
    return events_;
  }
  void SetParser(EventSourceParser* parser) { parser_ = parser; }
  void OnMessageEvent(const AtomicString& event,
                      const String& data,
                      const AtomicString& id) override {
    parser_->Stop();
    events_.push_back(EventOrReconnectionTimeSetting(event, data, id));
  }
  void OnReconnectionTimeSet(uint64_t reconnection_time) override {
    events_.push_back(EventOrReconnectionTimeSetting(reconnection_time));
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(parser_);
    EventSourceParser::Client::Trace(visitor);
  }

 private:
  Member<EventSourceParser> parser_;
  Vector<EventOrReconnectionTimeSetting> events_;
};

class EventSourceParserTest : public testing::Test {
 protected:
  using Type = EventOrReconnectionTimeSetting::Type;
  EventSourceParserTest()
      : client_(MakeGarbageCollected<Client>()),
        parser_(
            MakeGarbageCollected<EventSourceParser>(AtomicString(), client_)) {}
  ~EventSourceParserTest() override = default;

  void Enqueue(std::string_view chars) { parser_->AddBytes(chars); }
  void EnqueueOneByOne(std::string_view chars) {
    for (char c : chars) {
      parser_->AddBytes(base::span_from_ref(c));
    }
  }

  const Vector<EventOrReconnectionTimeSetting>& Events() {
    return client_->Events();
  }

  EventSourceParser* Parser() { return parser_; }

  test::TaskEnvironment task_environment_;
  Persistent<Client> client_;
  Persistent<EventSourceParser> parser_;
};

TEST_F(EventSourceParserTest, EmptyMessageEventShouldNotBeDispatched) {
  Enqueue("\n");

  EXPECT_EQ(0u, Events().size());
  EXPECT_EQ(String(), Parser()->LastEventId());
}

TEST_F(EventSourceParserTest, DispatchSimpleMessageEvent) {
  Enqueue("data:hello\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
  EXPECT_EQ(String(), Events()[0].id);
  EXPECT_EQ(AtomicString(), Parser()->LastEventId());
}

TEST_F(EventSourceParserTest, ConstructWithLastEventId) {
  parser_ =
      MakeGarbageCollected<EventSourceParser>(AtomicString("hoge"), client_);
  EXPECT_EQ("hoge", Parser()->LastEventId());

  Enqueue("data:hello\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
  EXPECT_EQ("hoge", Events()[0].id);
  EXPECT_EQ("hoge", Parser()->LastEventId());
}

TEST_F(EventSourceParserTest, DispatchMessageEventWithLastEventId) {
  Enqueue("id:99\ndata:hello\n");
  EXPECT_EQ(String(), Parser()->LastEventId());

  Enqueue("\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
  EXPECT_EQ("99", Events()[0].id);
  EXPECT_EQ("99", Parser()->LastEventId());
}

TEST_F(EventSourceParserTest, LastEventIdCanBeUpdatedEvenWhenDataIsEmpty) {
  Enqueue("id:99\n");
  EXPECT_EQ(String(), Parser()->LastEventId());

  Enqueue("\n");

  ASSERT_EQ(0u, Events().size());
  EXPECT_EQ("99", Parser()->LastEventId());
}

TEST_F(EventSourceParserTest, DispatchMessageEventWithCustomEventType) {
  Enqueue("event:foo\ndata:hello\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("foo", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, RetryTakesEffectEvenWhenNotDispatching) {
  Enqueue("retry:999\n");
  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kReconnectionTimeSetting, Events()[0].type);
  ASSERT_EQ(999u, Events()[0].reconnection_time);
}

TEST_F(EventSourceParserTest, EventTypeShouldBeReset) {
  Enqueue("event:foo\ndata:hello\n\ndata:bye\n\n");

  ASSERT_EQ(2u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("foo", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);

  ASSERT_EQ(Type::kEvent, Events()[1].type);
  EXPECT_EQ("message", Events()[1].event);
  EXPECT_EQ("bye", Events()[1].data);
}

TEST_F(EventSourceParserTest, DataShouldBeReset) {
  Enqueue("data:hello\n\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, LastEventIdShouldNotBeReset) {
  Enqueue("id:99\ndata:hello\n\ndata:bye\n\n");

  EXPECT_EQ("99", Parser()->LastEventId());
  ASSERT_EQ(2u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
  EXPECT_EQ("99", Events()[0].id);

  ASSERT_EQ(Type::kEvent, Events()[1].type);
  EXPECT_EQ("message", Events()[1].event);
  EXPECT_EQ("bye", Events()[1].data);
  EXPECT_EQ("99", Events()[1].id);
}

TEST_F(EventSourceParserTest, VariousNewLinesShouldBeAllowed) {
  EnqueueOneByOne("data:hello\r\n\rdata:bye\r\r");

  ASSERT_EQ(2u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);

  ASSERT_EQ(Type::kEvent, Events()[1].type);
  EXPECT_EQ("message", Events()[1].event);
  EXPECT_EQ("bye", Events()[1].data);
}

TEST_F(EventSourceParserTest, RetryWithEmptyValueShouldRestoreDefaultValue) {
  // TODO(yhirano): This is unspecified in the spec. We need to update
  // the implementation or the spec. See https://crbug.com/587980.
  Enqueue("retry\n");
  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kReconnectionTimeSetting, Events()[0].type);
  EXPECT_EQ(EventSource::kDefaultReconnectDelay, Events()[0].reconnection_time);
}

TEST_F(EventSourceParserTest, NonDigitRetryShouldBeIgnored) {
  Enqueue("retry:a0\n");
  Enqueue("retry:xi\n");
  Enqueue("retry:2a\n");
  Enqueue("retry:09a\n");
  Enqueue("retry:1\b\n");
  Enqueue("retry:  1234\n");
  Enqueue("retry:456 \n");

  EXPECT_EQ(0u, Events().size());
}

TEST_F(EventSourceParserTest, UnrecognizedFieldShouldBeIgnored) {
  Enqueue("data:hello\nhoge:fuga\npiyo\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, CommentShouldBeIgnored) {
  Enqueue("data:hello\n:event:a\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, BOMShouldBeIgnored) {
  // This line is recognized because "\xef\xbb\xbf" is a BOM.
  Enqueue(
      "\xef\xbb\xbf"
      "data:hello\n");
  // This line is ignored because "\xef\xbb\xbf" is part of the field name.
  Enqueue(
      "\xef\xbb\xbf"
      "data:bye\n");
  Enqueue("\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, BOMShouldBeIgnored_OneByOne) {
  // This line is recognized because "\xef\xbb\xbf" is a BOM.
  EnqueueOneByOne(
      "\xef\xbb\xbf"
      "data:hello\n");
  // This line is ignored because "\xef\xbb\xbf" is part of the field name.
  EnqueueOneByOne(
      "\xef\xbb\xbf"
      "data:bye\n");
  EnqueueOneByOne("\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, ColonlessLineShouldBeTreatedAsNameOnlyField) {
  Enqueue("data:hello\nevent:a\nevent\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, AtMostOneLeadingSpaceCanBeSkipped) {
  Enqueue("data:  hello  \nevent:  type \n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ(" type ", Events()[0].event);
  EXPECT_EQ(" hello  ", Events()[0].data);
}

TEST_F(EventSourceParserTest, DataShouldAccumulate) {
  Enqueue("data\ndata:hello\ndata: world\ndata\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("\nhello\nworld\n", Events()[0].data);
}

TEST_F(EventSourceParserTest, EventShouldNotAccumulate) {
  Enqueue("data:hello\nevent:a\nevent:b\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("b", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
}

TEST_F(EventSourceParserTest, FeedDataOneByOne) {
  EnqueueOneByOne(
      "data:hello\r\ndata:world\revent:a\revent:b\nid:4\n\nid:8\ndata:"
      "bye\r\n\r");

  ASSERT_EQ(2u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("b", Events()[0].event);
  EXPECT_EQ("hello\nworld", Events()[0].data);
  EXPECT_EQ("4", Events()[0].id);

  ASSERT_EQ(Type::kEvent, Events()[1].type);
  EXPECT_EQ("message", Events()[1].event);
  EXPECT_EQ("bye", Events()[1].data);
  EXPECT_EQ("8", Events()[1].id);
}

TEST_F(EventSourceParserTest, InvalidUTF8Sequence) {
  Enqueue("data:\xffhello\xc2\ndata:bye\n\n");

  ASSERT_EQ(1u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  String expected = String() + kReplacementCharacter + "hello" +
                    kReplacementCharacter + "\nbye";
  EXPECT_EQ(expected, Events()[0].data);
}

TEST(EventSourceParserStoppingTest, StopWhileParsing) {
  test::TaskEnvironment task_environment;
  StoppingClient* client = MakeGarbageCollected<StoppingClient>();
  EventSourceParser* parser =
      MakeGarbageCollected<EventSourceParser>(AtomicString(), client);
  client->SetParser(parser);

  const char kInput[] = "data:hello\nid:99\n\nid:44\ndata:bye\n\n";
  parser->AddBytes(base::span_from_cstring(kInput));

  const auto& events = client->Events();

  ASSERT_EQ(1u, events.size());
  ASSERT_EQ(EventOrReconnectionTimeSetting::Type::kEvent, events[0].type);
  EXPECT_EQ("message", events[0].event);
  EXPECT_EQ("hello", events[0].data);
  EXPECT_EQ("99", parser->LastEventId());
}

TEST_F(EventSourceParserTest, IgnoreIdHavingNullCharacter) {
  constexpr char input[] =
      "id:99\ndata:hello\n\nid:4\x0"
      "23\ndata:bye\n\n";
  // We can't use Enqueue because it relies on strlen.
  parser_->AddBytes(base::span_from_cstring(input));

  EXPECT_EQ("99", Parser()->LastEventId());
  ASSERT_EQ(2u, Events().size());
  ASSERT_EQ(Type::kEvent, Events()[0].type);
  EXPECT_EQ("message", Events()[0].event);
  EXPECT_EQ("hello", Events()[0].data);
  EXPECT_EQ("99", Events()[0].id);

  ASSERT_EQ(Type::kEvent, Events()[1].type);
  EXPECT_EQ("message", Events()[1].event);
  EXPECT_EQ("bye", Events()[1].data);
  EXPECT_EQ("99", Events()[1].id);
}

}  // namespace

}  // namespace blink
```