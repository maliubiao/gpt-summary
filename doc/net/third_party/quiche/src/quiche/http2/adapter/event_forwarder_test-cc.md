Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The primary request is to analyze a specific C++ test file (`event_forwarder_test.cc`) within the Chromium network stack. The focus is on understanding its functionality, its relation to JavaScript (if any), logical reasoning with examples, potential user errors, and debugging information.

2. **Initial Code Scan and Identification of Key Components:** The first step is to quickly read through the code to identify its main parts:
    * Includes:  Headers like `<string>`, `"absl/strings/string_view"`, `"quiche/http2/adapter/event_forwarder.h"`, and others related to HTTP/2 and testing. This immediately suggests the file is related to HTTP/2 handling.
    * Namespace: `http2::adapter::test`. This confirms it's a test file within the HTTP/2 adapter component.
    * `TEST` macros:  These are the core of the file, indicating it uses a testing framework (likely Google Test, given the `EXPECT_CALL`).
    * Test Names: `EventForwarderTest`. This points to the class being tested: `EventForwarder`.
    * `EXPECT_CALL`: This is a strong indicator of mocking and verifying interactions with other objects. The second argument to `EXPECT_CALL` reveals the methods of the mocked object being tested.
    * Lambda Predicate:  The `EventForwarder` constructor takes a lambda `[]() { return true; }` or `[]() { return false; }`. This suggests a conditional forwarding mechanism.
    * Mock Object: `spdy::test::MockSpdyFramerVisitor receiver`. This is the object whose methods are being called and verified.

3. **Deconstruct the Functionality:**  Now, analyze each test case:
    * **`ForwardsEventsWithTruePredicate`:**
        * Creates an `EventForwarder` with a predicate that always returns `true`.
        * Calls various methods of the `EventForwarder` that correspond to different HTTP/2 frame events (e.g., `OnError`, `OnCommonHeader`, `OnDataFrameHeader`, `OnSettings`, etc.).
        * Uses `EXPECT_CALL` to verify that these calls are forwarded to the `receiver` mock object. This means the `EventForwarder` is acting as a pass-through for these events when the predicate is true.
    * **`DoesNotForwardEventsWithFalsePredicate`:**
        * Creates an `EventForwarder` with a predicate that always returns `false`.
        * Calls the same methods as the previous test.
        * Uses `EXPECT_CALL(...).Times(0)` to verify that *none* of these calls are forwarded to the `receiver` mock object. This confirms that the predicate controls whether events are forwarded.

4. **Determine the Core Functionality of `EventForwarder`:** Based on the tests, the `EventForwarder` class acts as an intermediary that selectively forwards HTTP/2 frame events to another object (the `SpdyFramerVisitor`). The forwarding is controlled by a boolean predicate.

5. **Assess the Relationship with JavaScript:**  Consider how HTTP/2 events might relate to JavaScript in a browser context.
    * **Network Layer:** HTTP/2 is a network protocol. JavaScript in a browser interacts with it through higher-level APIs (like `fetch` or WebSockets).
    * **Event Handling:** While the C++ code uses "events," these are internal to the HTTP/2 processing. They are not directly JavaScript events.
    * **Possible Indirect Connection:**  The events handled by `EventForwarder` *could* eventually lead to changes that are observable by JavaScript. For example, receiving data frames might trigger the `onmessage` event in a WebSocket or resolve a `fetch` promise. However, the `EventForwarder` itself doesn't directly interact with JavaScript.

6. **Construct Logical Reasoning Examples:**  Develop scenarios to illustrate the predicate's behavior:
    * **Hypothesis:** The predicate is used for filtering events.
    * **Input (True Predicate):**  An incoming DATA frame.
    * **Output:** The `OnDataFrameHeader` and `OnStreamFrameData` methods of the visitor are called.
    * **Input (False Predicate):** An incoming DATA frame.
    * **Output:** The `OnDataFrameHeader` and `OnStreamFrameData` methods of the visitor are *not* called.

7. **Identify Potential User/Programming Errors:** Think about how someone might misuse this class:
    * **Incorrect Predicate Logic:** Providing a predicate that doesn't accurately reflect the desired filtering behavior. Example:  Wanting to log only errors but the predicate always returns `true`.
    * **Misunderstanding the Purpose:**  Using `EventForwarder` when simple direct forwarding is needed, adding unnecessary overhead.
    * **Forgetting to Set the Predicate Correctly:** Especially if the predicate's logic is dynamic.

8. **Outline Debugging Steps:**  Consider how one would reach this code during debugging:
    * **Network Issues:** Investigating problems with HTTP/2 communication in a Chromium browser.
    * **Event Tracing/Logging:**  Trying to understand the sequence of HTTP/2 events.
    * **Breakpoints:** Setting breakpoints within `EventForwarder` to see if events are being forwarded as expected.
    * **Code Navigation:** Starting from where HTTP/2 frames are received and tracing the processing flow.

9. **Structure the Answer:** Organize the findings logically:
    * Start with the file's function.
    * Discuss the JavaScript relationship (and clarify the distinction).
    * Provide logical reasoning examples with inputs and outputs.
    * Detail common usage errors.
    * Explain the debugging context.

10. **Refine and Elaborate:**  Review the generated answer for clarity, completeness, and accuracy. Add specific examples and explain technical terms where necessary. For instance, explain what a "predicate" is in this context. Ensure the connection (or lack thereof) to JavaScript is explained carefully to avoid confusion. Make sure the debugging steps are practical and informative.
好的，让我们来分析一下这个C++源代码文件 `event_forwarder_test.cc`。

**文件功能：**

这个文件是一个单元测试文件，用于测试 `EventForwarder` 类的功能。`EventForwarder` 类的主要作用是根据一个给定的谓词（predicate）来决定是否将接收到的 HTTP/2 帧事件转发给另一个 `SpdyFramerVisitor` 对象。

具体来说，`EventForwarder` 实现了 `Http2FrameDecoderVisitor` 接口，它可以接收各种 HTTP/2 帧事件的回调，例如：

* **OnError:**  当解析帧时发生错误。
* **OnCommonHeader:**  接收到所有帧的通用头部。
* **OnDataFrameHeader/OnStreamFrameData/OnStreamEnd/OnStreamPadLength/OnStreamPadding:**  处理 DATA 帧相关的事件。
* **OnHeaderFrameStart/OnHeaderFrameEnd:**  处理 HEADERS 帧的开始和结束。
* **OnRstStream:**  接收到 RST_STREAM 帧。
* **OnSettings/OnSetting/OnSettingsEnd/OnSettingsAck:** 处理 SETTINGS 帧相关的事件。
* **OnPing:** 接收到 PING 帧。
* **OnGoAway/OnGoAwayFrameData:** 接收到 GOAWAY 帧。
* **OnHeaders:** 接收到完整的 HEADERS 帧信息。
* **OnWindowUpdate:** 接收到 WINDOW_UPDATE 帧。
* **OnPushPromise:** 接收到 PUSH_PROMISE 帧。
* **OnContinuation:** 接收到 CONTINUATION 帧。
* **OnAltSvc:** 接收到 ALTSVC 帧。
* **OnPriority/OnPriorityUpdate:** 接收到 PRIORITY 或 PRIORITY_UPDATE 帧。
* **OnUnknownFrame/OnUnknownFrameStart:** 接收到未知的帧类型。

`EventForwarder` 的核心逻辑在于其构造函数接收一个返回 `bool` 值的函数（谓词）。只有当这个谓词函数返回 `true` 时，接收到的事件才会被转发给内部持有的 `SpdyFramerVisitor` 对象。

**与 JavaScript 的关系：**

直接来说，这个 C++ 文件本身与 JavaScript 没有直接的代码层面的关系。 然而，从更宏观的角度来看，它在 Chromium 网络栈中扮演着处理 HTTP/2 协议的角色，而 HTTP/2 是现代 Web 浏览器与服务器通信的基础。

JavaScript 代码通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`, WebSocket) 发起网络请求。 当这些请求使用 HTTP/2 协议时，Chromium 的网络栈（包括这个 `EventForwarder` 所在的模块）会负责处理底层的 HTTP/2 帧的编码、解码和事件处理。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 向服务器请求数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器（Chromium）会进行以下（简化的）步骤，其中涉及到 `EventForwarder` 的潜在作用：

1. **JavaScript 发起请求:** `fetch` 调用被执行。
2. **浏览器处理请求:** 浏览器确定使用 HTTP/2 协议与 `example.com` 通信。
3. **发送 HTTP/2 帧:** 浏览器将请求信息编码成 HTTP/2 帧（例如 HEADERS 帧，DATA 帧）。
4. **服务器响应:** 服务器发送包含数据的 HTTP/2 帧返回。
5. **Chromium 网络栈接收帧:**  Chromium 的 HTTP/2 解码器会解析接收到的帧。
6. **`EventForwarder` 处理事件:** 在解码过程中，如果配置了 `EventForwarder`，解码器会调用 `EventForwarder` 的相应方法 (例如 `OnHeaders`, `OnDataFrameHeader`, `OnStreamFrameData`)。
7. **谓词判断:** `EventForwarder` 会执行其持有的谓词函数。
8. **转发事件 (如果谓词为真):** 如果谓词返回 `true`，`EventForwarder` 会将事件转发给它内部的 `SpdyFramerVisitor` 对象，该对象可能会进一步处理这些事件，例如更新连接状态、将数据传递给上层模块等。
9. **数据传递回 JavaScript:** 最终，接收到的数据会被传递回 JavaScript，使得 `fetch` 的 Promise 可以 resolve，并执行 `.then` 中的代码。

**逻辑推理 (假设输入与输出):**

**测试用例 1：谓词始终返回 `true`**

* **假设输入:**  HTTP/2 解码器接收到一个 DATA 帧，该帧属于 stream ID 1，包含 "Hello" 数据。
* **`EventForwarder` 接收到的调用:**
    * `OnCommonHeader(1, 5, /*type=*/0x0, END_STREAM_FLAG)` (假设)
    * `OnDataFrameHeader(1, 5, /*fin=*/false)`
    * `OnStreamFrameData(1, "Hello", 5)`
* **输出:** 由于谓词返回 `true`，这些调用会被原封不动地转发到内部的 `MockSpdyFramerVisitor`，因此 `MockSpdyFramerVisitor` 的 `OnCommonHeader`, `OnDataFrameHeader`, `OnStreamFrameData` 方法会被调用，参数相同。

**测试用例 2：谓词始终返回 `false`**

* **假设输入:**  HTTP/2 解码器接收到一个 RST_STREAM 帧，stream ID 为 1，错误码为 `ERROR_CODE_INTERNAL_ERROR`。
* **`EventForwarder` 接收到的调用:** `OnRstStream(1, ERROR_CODE_INTERNAL_ERROR)`
* **输出:** 由于谓词返回 `false`，这个调用不会被转发到内部的 `MockSpdyFramerVisitor`，因此 `MockSpdyFramerVisitor` 的 `OnRstStream` 方法不会被调用。

**用户或编程常见的使用错误：**

1. **谓词逻辑错误：**  最常见的错误是编写了不正确的谓词逻辑，导致事件被错误地转发或阻止。例如，用户可能只想在特定 stream ID 上记录事件，但谓词的实现不正确，导致所有 stream ID 的事件都被记录或都没有被记录。

   ```c++
   // 错误的谓词，总是返回 true，导致所有事件都被转发
   EventForwarder event_forwarder([]() { return true; }, receiver);

   // 期望只转发特定 stream ID (例如 stream ID 5) 的事件，但谓词不正确
   EventForwarder event_forwarder([](const auto& event) { // 假设事件对象包含 stream ID
     return event.stream_id() == 3; // 错误的 stream ID
   }, receiver);
   ```

2. **忘记初始化或配置 `EventForwarder`：** 如果代码中需要根据特定条件转发事件，但忘记创建或配置 `EventForwarder` 实例，那么事件将不会被按预期处理。

3. **误解 `EventForwarder` 的作用域和生命周期：**  如果在不正确的作用域创建 `EventForwarder`，可能导致它在需要转发事件时已经被销毁。

4. **与其他的 Visitor 冲突：** 如果在同一个 HTTP/2 解码器上注册了多个 Visitor，可能会因为事件被多次处理而导致意外行为。`EventForwarder` 本身旨在转发事件，但如果转发目标也执行了与原始目标相同的操作，可能会产生问题。

**用户操作如何一步步到达这里 (作为调试线索)：**

假设用户在使用 Chromium 浏览器访问一个网站时遇到了网络问题，例如请求被意外终止或数据传输不完整。作为开发人员，在调试 Chromium 网络栈时，可能会沿着以下路径到达 `event_forwarder_test.cc`：

1. **用户报告问题：** 用户报告访问特定网页时出现错误，例如 "连接被重置" 或 "页面加载不完整"。
2. **网络抓包分析：** 开发人员可能会使用网络抓包工具 (如 Wireshark) 来检查浏览器与服务器之间的 HTTP/2 通信。这可以帮助确定是否发生了协议层面的错误，例如 RST_STREAM 帧的发送。
3. **Chromium 内部日志：**  开发人员可能会查看 Chromium 的内部网络日志 (通过 `chrome://net-export/`)，这些日志记录了 HTTP/2 连接和帧的详细信息。
4. **怀疑 HTTP/2 解码器问题：** 如果日志显示了异常的 HTTP/2 帧序列或错误，开发人员可能会怀疑是 HTTP/2 解码器或相关的事件处理逻辑出现了问题。
5. **代码审查和断点：** 开发人员可能会开始审查 Chromium 网络栈中负责 HTTP/2 解码的代码，例如 `SpdyFramer` 和相关的 Visitor 接口的实现。他们可能会在 `EventForwarder` 的方法中设置断点，以观察哪些事件正在被接收，谓词函数的返回值是什么，以及事件是否被转发。
6. **单元测试验证：** 为了验证 `EventForwarder` 的行为是否符合预期，开发人员可能会查看或运行 `event_forwarder_test.cc` 中的单元测试。这些测试用例可以帮助理解在不同谓词条件下，`EventForwarder` 如何处理各种 HTTP/2 帧事件。如果发现测试失败或覆盖不足，可能需要修改测试或修复 `EventForwarder` 的代码。
7. **问题定位和修复：** 通过结合网络抓包、内部日志、代码审查和单元测试，开发人员最终可以定位导致问题的根本原因，并修复 `EventForwarder` 或相关的代码。例如，他们可能会发现某个特定的事件没有被正确转发，或者谓词逻辑存在错误，导致某些重要的事件被忽略。

总而言之，`event_forwarder_test.cc` 是确保 `EventForwarder` 类正确工作的关键部分，它通过各种测试用例覆盖了 `EventForwarder` 在不同条件下的行为，从而保证了 Chromium 网络栈处理 HTTP/2 事件的可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/event_forwarder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/event_forwarder.h"

#include <string>

#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/test_tools/mock_spdy_framer_visitor.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

constexpr absl::string_view some_data = "Here is some data for events";
constexpr spdy::SpdyStreamId stream_id = 1;
constexpr spdy::SpdyErrorCode error_code =
    spdy::SpdyErrorCode::ERROR_CODE_ENHANCE_YOUR_CALM;
constexpr size_t length = 42;

TEST(EventForwarderTest, ForwardsEventsWithTruePredicate) {
  spdy::test::MockSpdyFramerVisitor receiver;
  receiver.DelegateHeaderHandling();
  EventForwarder event_forwarder([]() { return true; }, receiver);

  EXPECT_CALL(
      receiver,
      OnError(Http2DecoderAdapter::SpdyFramerError::SPDY_STOP_PROCESSING,
              std::string(some_data)));
  event_forwarder.OnError(
      Http2DecoderAdapter::SpdyFramerError::SPDY_STOP_PROCESSING,
      std::string(some_data));

  EXPECT_CALL(receiver,
              OnCommonHeader(stream_id, length, /*type=*/0x0, END_STREAM_FLAG));
  event_forwarder.OnCommonHeader(stream_id, length, /*type=*/0x0,
                                 END_STREAM_FLAG);

  EXPECT_CALL(receiver, OnDataFrameHeader(stream_id, length, /*fin=*/true));
  event_forwarder.OnDataFrameHeader(stream_id, length, /*fin=*/true);

  EXPECT_CALL(receiver,
              OnStreamFrameData(stream_id, some_data.data(), some_data.size()));
  event_forwarder.OnStreamFrameData(stream_id, some_data.data(),
                                    some_data.size());

  EXPECT_CALL(receiver, OnStreamEnd(stream_id));
  event_forwarder.OnStreamEnd(stream_id);

  EXPECT_CALL(receiver, OnStreamPadLength(stream_id, length));
  event_forwarder.OnStreamPadLength(stream_id, length);

  EXPECT_CALL(receiver, OnStreamPadding(stream_id, length));
  event_forwarder.OnStreamPadding(stream_id, length);

  EXPECT_CALL(receiver, OnHeaderFrameStart(stream_id));
  spdy::SpdyHeadersHandlerInterface* handler =
      event_forwarder.OnHeaderFrameStart(stream_id);
  EXPECT_EQ(handler, receiver.ReturnTestHeadersHandler(stream_id));

  EXPECT_CALL(receiver, OnHeaderFrameEnd(stream_id));
  event_forwarder.OnHeaderFrameEnd(stream_id);

  EXPECT_CALL(receiver, OnRstStream(stream_id, error_code));
  event_forwarder.OnRstStream(stream_id, error_code);

  EXPECT_CALL(receiver, OnSettings());
  event_forwarder.OnSettings();

  EXPECT_CALL(
      receiver,
      OnSetting(spdy::SpdyKnownSettingsId::SETTINGS_MAX_CONCURRENT_STREAMS,
                100));
  event_forwarder.OnSetting(
      spdy::SpdyKnownSettingsId::SETTINGS_MAX_CONCURRENT_STREAMS, 100);

  EXPECT_CALL(receiver, OnSettingsEnd());
  event_forwarder.OnSettingsEnd();

  EXPECT_CALL(receiver, OnSettingsAck());
  event_forwarder.OnSettingsAck();

  EXPECT_CALL(receiver, OnPing(/*unique_id=*/42, /*is_ack=*/false));
  event_forwarder.OnPing(/*unique_id=*/42, /*is_ack=*/false);

  EXPECT_CALL(receiver, OnGoAway(stream_id, error_code));
  event_forwarder.OnGoAway(stream_id, error_code);

  EXPECT_CALL(receiver, OnGoAwayFrameData(some_data.data(), some_data.size()));
  event_forwarder.OnGoAwayFrameData(some_data.data(), some_data.size());

  EXPECT_CALL(receiver,
              OnHeaders(stream_id, /*payload_length=*/1234,
                        /*has_priority=*/false, /*weight=*/42, stream_id + 2,
                        /*exclusive=*/false, /*fin=*/true, /*end=*/true));
  event_forwarder.OnHeaders(stream_id, /*payload_length=*/1234,
                            /*has_priority=*/false, /*weight=*/42,
                            stream_id + 2, /*exclusive=*/false, /*fin=*/true,
                            /*end=*/true);

  EXPECT_CALL(receiver, OnWindowUpdate(stream_id, /*delta_window_size=*/42));
  event_forwarder.OnWindowUpdate(stream_id, /*delta_window_size=*/42);

  EXPECT_CALL(receiver, OnPushPromise(stream_id, stream_id + 1, /*end=*/true));
  event_forwarder.OnPushPromise(stream_id, stream_id + 1, /*end=*/true);

  EXPECT_CALL(receiver,
              OnContinuation(stream_id, /*payload_length=*/42, /*end=*/true));
  event_forwarder.OnContinuation(stream_id, /*payload_length=*/42,
                                 /*end=*/true);

  const spdy::SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  EXPECT_CALL(receiver, OnAltSvc(stream_id, some_data, altsvc_vector));
  event_forwarder.OnAltSvc(stream_id, some_data, altsvc_vector);

  EXPECT_CALL(receiver, OnPriority(stream_id, stream_id + 2, /*weight=*/42,
                                   /*exclusive=*/false));
  event_forwarder.OnPriority(stream_id, stream_id + 2, /*weight=*/42,
                             /*exclusive=*/false);

  EXPECT_CALL(receiver, OnPriorityUpdate(stream_id, some_data));
  event_forwarder.OnPriorityUpdate(stream_id, some_data);

  EXPECT_CALL(receiver, OnUnknownFrame(stream_id, /*frame_type=*/0x4D));
  event_forwarder.OnUnknownFrame(stream_id, /*frame_type=*/0x4D);

  EXPECT_CALL(receiver, OnUnknownFrameStart(stream_id, /*length=*/42,
                                            /*type=*/0x4D, /*flags=*/0x0));
  event_forwarder.OnUnknownFrameStart(stream_id, /*length=*/42, /*type=*/0x4D,
                                      /*flags=*/0x0);
}

TEST(EventForwarderTest, DoesNotForwardEventsWithFalsePredicate) {
  spdy::test::MockSpdyFramerVisitor receiver;
  receiver.DelegateHeaderHandling();
  EventForwarder event_forwarder([]() { return false; }, receiver);

  EXPECT_CALL(receiver, OnError).Times(0);
  event_forwarder.OnError(
      Http2DecoderAdapter::SpdyFramerError::SPDY_STOP_PROCESSING,
      std::string(some_data));

  EXPECT_CALL(receiver, OnCommonHeader).Times(0);
  event_forwarder.OnCommonHeader(stream_id, length, /*type=*/0x0,
                                 END_STREAM_FLAG);

  EXPECT_CALL(receiver, OnDataFrameHeader).Times(0);
  event_forwarder.OnDataFrameHeader(stream_id, length, /*fin=*/true);

  EXPECT_CALL(receiver, OnStreamFrameData).Times(0);
  event_forwarder.OnStreamFrameData(stream_id, some_data.data(),
                                    some_data.size());

  EXPECT_CALL(receiver, OnStreamEnd).Times(0);
  event_forwarder.OnStreamEnd(stream_id);

  EXPECT_CALL(receiver, OnStreamPadLength).Times(0);
  event_forwarder.OnStreamPadLength(stream_id, length);

  EXPECT_CALL(receiver, OnStreamPadding).Times(0);
  event_forwarder.OnStreamPadding(stream_id, length);

  EXPECT_CALL(receiver, OnHeaderFrameStart(stream_id));
  spdy::SpdyHeadersHandlerInterface* handler =
      event_forwarder.OnHeaderFrameStart(stream_id);
  EXPECT_EQ(handler, receiver.ReturnTestHeadersHandler(stream_id));

  EXPECT_CALL(receiver, OnHeaderFrameEnd).Times(0);
  event_forwarder.OnHeaderFrameEnd(stream_id);

  EXPECT_CALL(receiver, OnRstStream).Times(0);
  event_forwarder.OnRstStream(stream_id, error_code);

  EXPECT_CALL(receiver, OnSettings).Times(0);
  event_forwarder.OnSettings();

  EXPECT_CALL(receiver, OnSetting).Times(0);
  event_forwarder.OnSetting(
      spdy::SpdyKnownSettingsId::SETTINGS_MAX_CONCURRENT_STREAMS, 100);

  EXPECT_CALL(receiver, OnSettingsEnd).Times(0);
  event_forwarder.OnSettingsEnd();

  EXPECT_CALL(receiver, OnSettingsAck).Times(0);
  event_forwarder.OnSettingsAck();

  EXPECT_CALL(receiver, OnPing).Times(0);
  event_forwarder.OnPing(/*unique_id=*/42, /*is_ack=*/false);

  EXPECT_CALL(receiver, OnGoAway).Times(0);
  event_forwarder.OnGoAway(stream_id, error_code);

  EXPECT_CALL(receiver, OnGoAwayFrameData).Times(0);
  event_forwarder.OnGoAwayFrameData(some_data.data(), some_data.size());

  EXPECT_CALL(receiver, OnHeaders).Times(0);
  event_forwarder.OnHeaders(stream_id, /*payload_length=*/1234,
                            /*has_priority=*/false, /*weight=*/42,
                            stream_id + 2, /*exclusive=*/false, /*fin=*/true,
                            /*end=*/true);

  EXPECT_CALL(receiver, OnWindowUpdate).Times(0);
  event_forwarder.OnWindowUpdate(stream_id, /*delta_window_size=*/42);

  EXPECT_CALL(receiver, OnPushPromise).Times(0);
  event_forwarder.OnPushPromise(stream_id, stream_id + 1, /*end=*/true);

  EXPECT_CALL(receiver, OnContinuation).Times(0);
  event_forwarder.OnContinuation(stream_id, /*payload_length=*/42,
                                 /*end=*/true);

  EXPECT_CALL(receiver, OnAltSvc).Times(0);
  const spdy::SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  event_forwarder.OnAltSvc(stream_id, some_data, altsvc_vector);

  EXPECT_CALL(receiver, OnPriority).Times(0);
  event_forwarder.OnPriority(stream_id, stream_id + 2, /*weight=*/42,
                             /*exclusive=*/false);

  EXPECT_CALL(receiver, OnPriorityUpdate).Times(0);
  event_forwarder.OnPriorityUpdate(stream_id, some_data);

  EXPECT_CALL(receiver, OnUnknownFrame).Times(0);
  event_forwarder.OnUnknownFrame(stream_id, /*frame_type=*/0x4D);

  EXPECT_CALL(receiver, OnUnknownFrameStart).Times(0);
  event_forwarder.OnUnknownFrameStart(stream_id, /*length=*/42, /*type=*/0x4D,
                                      /*flags=*/0x0);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
```