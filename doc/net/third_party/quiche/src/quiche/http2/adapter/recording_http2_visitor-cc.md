Response:
Let's break down the thought process for analyzing the provided C++ code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `RecordingHttp2Visitor`, its relation to JavaScript, potential usage errors, and how a user might end up triggering its logic.

**2. Initial Code Scan and Core Concept Identification:**

The first step is to quickly scan the code and identify key elements:

* **Class Name:** `RecordingHttp2Visitor`. The name strongly suggests it's used for *recording* events related to HTTP/2.
* **Inheritance/Interface:** It implements `Http2VisitorInterface`. This tells us it's designed to be a receiver of HTTP/2 events.
* **`events_` Member:** This `std::vector<std::string>` is clearly where the recorded events are stored.
* **Methods:**  A large number of methods like `OnReadyToSend`, `OnFrameHeader`, `OnBeginHeadersForStream`, etc. These correspond to various stages and events in the HTTP/2 protocol lifecycle.
* **`absl::StrFormat`:** This is used for formatting strings, suggesting that the recorded events are stored as human-readable strings.

**3. Determining the Functionality:**

Based on the above observations, the primary function becomes clear: **`RecordingHttp2Visitor` acts as a mock or spy object in testing or debugging scenarios. It intercepts and records HTTP/2 events as they occur.**  This allows developers to verify the sequence and content of HTTP/2 interactions.

**4. Analyzing Individual Methods:**

Now, we go through each method and understand its purpose within the HTTP/2 context:

* **"OnReadyToSend" family:** Relates to sending data.
* **"OnFrameHeader" and related:**  Concerned with the structure of HTTP/2 frames.
* **"OnSettings" family:**  Deals with HTTP/2 settings negotiation.
* **"OnHeaders" family:** Handles HTTP headers.
* **"OnData" family:** Deals with the data payload.
* **"OnStream" related methods:**  Actions specific to an HTTP/2 stream (e.g., `OnEndStream`, `OnRstStream`).
* **"OnPing", "OnPushPromise", "OnGoAway", "OnWindowUpdate":**  Other HTTP/2 control frames.
* **"OnBeforeFrameSent", "OnFrameSent":**  Hooks for observing frames being sent.
* **"OnInvalidFrame":**  Indicates an error in received frames.
* **"OnMetadata" family:** (Likely for HPACK's dynamic table updates, though not explicitly stated in the immediate code, but based on context)
* **"OnErrorDebug":** A generic error logging mechanism within this visitor.

**5. Considering the JavaScript Relationship:**

This requires understanding how HTTP/2 interacts with the browser's JavaScript environment.

* **Key Connection:**  HTTP/2 is the underlying protocol for fetching resources (HTML, CSS, JavaScript, images, etc.) initiated by the browser's JavaScript code. While JavaScript doesn't directly manipulate HTTP/2 frames, its actions trigger HTTP requests and responses that use HTTP/2 when available.

* **Examples:**
    * `fetch()` API: A JavaScript `fetch()` call will result in HTTP/2 requests (if the server supports it). The `RecordingHttp2Visitor` could record the headers and data of such requests.
    * `<img src="...">`:  Loading an image triggers an HTTP request.
    * `XMLHttpRequest`: The older way to make HTTP requests from JavaScript.

* **Important Note:** `RecordingHttp2Visitor` lives in the *C++ network stack* of Chromium. It doesn't directly execute JavaScript. It *observes* the HTTP/2 traffic generated by JavaScript actions.

**6. Developing Hypothetical Scenarios (Input/Output):**

To illustrate the recording behavior, create simple scenarios:

* **Basic GET Request:**  Simulate a JavaScript `fetch('/data')` request. Predict the sequence of `RecordingHttp2Visitor` method calls and the content of the `events_` vector.
* **POST Request with Data:**  Simulate a `fetch('/submit', { method: 'POST', body: '...' })` request, highlighting how data is sent.
* **Server Push:**  Demonstrate how the visitor records a server-initiated push.

**7. Identifying User/Programming Errors:**

Think about common mistakes developers might make when working with HTTP/2 or when using this visitor for testing:

* **Incorrect Header Formatting:**  Simulate sending a request with a malformed header, which might trigger an `OnInvalidFrame` event.
* **Sending Data Before Headers:** Violating the HTTP/2 protocol flow.
* **Using the Visitor Incorrectly in Tests:**  Forgetting to clear the `events_` vector between test cases, leading to incorrect assertions.

**8. Tracing User Actions to the Code (Debugging):**

This requires thinking about the chain of events in a browser:

1. **User Action:**  The user types a URL, clicks a link, or JavaScript code initiates a network request.
2. **Browser's Network Stack:** This is where the C++ code lives. The browser's network code determines if HTTP/2 can be used.
3. **HTTP/2 Session Establishment:** If HTTP/2 is negotiated, an HTTP/2 session is established with the server.
4. **Frame Processing:**  The browser and server exchange HTTP/2 frames.
5. **`RecordingHttp2Visitor` as an Observer:**  At various points during frame processing (parsing, sending), the code calls the methods of a registered `Http2VisitorInterface`, and if `RecordingHttp2Visitor` is being used, its methods are invoked, recording the events.

**9. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Start with the core functionality, then address the specific points in the prompt (JavaScript relationship, examples, errors, debugging). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe JavaScript can directly call into this C++ code?  **Correction:** No, JavaScript interacts with browser APIs, and the browser's network stack handles the underlying HTTP/2 communication. The `RecordingHttp2Visitor` is an internal component.
* **Clarity on "User":** Realize that "user" in this context can mean both the end-user interacting with the browser and a developer writing code that uses the network stack (e.g., in a testing environment).
* **Focus on HTTP/2 Concepts:** Ensure the explanation uses correct HTTP/2 terminology (streams, frames, headers, settings, etc.).

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate response that addresses all aspects of the prompt.
这个 C++ 文件 `recording_http2_visitor.cc` 定义了一个名为 `RecordingHttp2Visitor` 的类，它实现了 `Http2VisitorInterface` 接口。这个类的主要功能是 **记录 HTTP/2 会话中发生的各种事件**。你可以把它想象成一个 HTTP/2 会话的“录音机”。

**具体功能列举:**

`RecordingHttp2Visitor` 类中的每个方法都对应着 HTTP/2 协议中的一个事件或状态变化。它记录了以下信息：

* **发送数据:**
    * `OnReadyToSend`:  记录了准备发送的数据的大小。
    * `OnReadyToSendDataForStream`: 记录了准备为特定流发送数据，以及允许发送的最大长度。
    * `SendDataFrame`: 记录了发送数据帧的流 ID 和有效负载大小。
    * `OnBeforeFrameSent`: 记录了即将发送的帧的类型、流 ID、长度和标志。
    * `OnFrameSent`: 记录了成功发送的帧的类型、流 ID、长度、标志和错误码（如果有）。

* **接收数据和帧:**
    * `OnFrameHeader`: 记录了接收到的帧的流 ID、长度、类型和标志。
    * `OnBeginDataForStream`: 记录了开始接收特定流的数据，以及数据的有效负载长度。
    * `OnDataForStream`: 记录了接收到的特定流的数据内容。
    * `OnDataPaddingLength`: 记录了数据帧的填充长度。
    * `OnEndStream`: 记录了流的结束。
    * `OnInvalidFrame`: 记录了接收到的无效帧及其错误类型。

* **头部处理:**
    * `OnBeginHeadersForStream`: 记录了开始接收特定流的头部。
    * `OnHeaderForStream`: 记录了接收到的特定流的单个头部字段（名称和值）。
    * `OnEndHeadersForStream`: 记录了特定流的头部接收结束。

* **设置 (Settings) 帧处理:**
    * `OnSettingsStart`: 记录了开始接收 SETTINGS 帧。
    * `OnSetting`: 记录了接收到的单个设置及其值。
    * `OnSettingsEnd`: 记录了 SETTINGS 帧接收结束。
    * `OnSettingsAck`: 记录了接收到 SETTINGS 确认帧。

* **错误处理:**
    * `OnConnectionError`: 记录了连接级别的错误。
    * `OnRstStream`: 记录了接收到的 RST_STREAM 帧，包含流 ID 和错误码。
    * `OnCloseStream`: 记录了接收到的关闭流的事件，包含流 ID 和错误码。
    * `OnGoAway`: 记录了接收到的 GOAWAY 帧，包含最后接受的流 ID、错误码和可选的附加数据。

* **其他控制帧:**
    * `OnPriorityForStream`: 记录了接收到的 PRIORITY 帧，包含流 ID、父流 ID、权重和排他性。
    * `OnPing`: 记录了接收到的 PING 帧，包含 Ping ID 和是否为确认帧。
    * `OnPushPromiseForStream`: 记录了接收到的 PUSH_PROMISE 帧，包含发起流 ID 和承诺流 ID。
    * `OnWindowUpdate`: 记录了接收到的 WINDOW_UPDATE 帧，包含流 ID 和窗口增量。

* **元数据 (Metadata) 处理 (可能与 HPACK 相关):**
    * `OnBeginMetadataForStream`: 记录了开始接收特定流的元数据，以及有效负载长度。
    * `OnMetadataForStream`: 记录了接收到的特定流的元数据内容。
    * `OnMetadataEndForStream`: 记录了特定流的元数据接收结束。
    * `PackMetadataForStream`: 记录了打包特定流的元数据的请求。

* **调试信息:**
    * `OnErrorDebug`: 记录了调试消息。

**与 JavaScript 的关系:**

`RecordingHttp2Visitor` 本身是用 C++ 编写的，直接与 JavaScript 没有运行时关系。然而，它的功能与 JavaScript 发起的网络请求息息相关。

当网页上的 JavaScript 代码通过以下方式发起 HTTP 请求时，底层的 Chromium 网络栈会处理这些请求，包括 HTTP/2 协议的协商和通信：

* **`fetch()` API:** 这是现代 JavaScript 中用于发起网络请求的主要方式。
* **`XMLHttpRequest` (XHR):**  较旧但仍然被使用的 API。
* **加载资源标签:** 例如 `<img src="...">`, `<link href="...">`, `<script src="...">` 等。

**`RecordingHttp2Visitor` 的作用是记录这些由 JavaScript 触发的 HTTP/2 通信事件。**

**举例说明:**

假设一个网页上的 JavaScript 代码执行了以下 `fetch` 请求：

```javascript
fetch('/api/data', {
  method: 'GET',
  headers: {
    'X-Custom-Header': 'value'
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

当这个请求通过 HTTP/2 发送时，`RecordingHttp2Visitor` 可能会记录到以下事件（顺序可能因具体实现和网络情况而异）：

1. **`OnReadyToSend <length of SETTINGS frame>`:**  如果需要发送 SETTINGS 帧进行协议协商。
2. **`OnBeforeFrameSent 1 3 9 4`:** (假设 HEADERS 帧类型为 1，流 ID 为 3，长度为 9，标志为 4)
3. **`OnFrameSent 1 3 9 4 0`:**
4. **`OnBeginHeadersForStream 3`:**
5. **`OnHeaderForStream 3 :method GET`:**
6. **`OnHeaderForStream 3 :path /api/data`:**
7. **`OnHeaderForStream 3 host example.com`:** (或相应的 authority 头部)
8. **`OnHeaderForStream 3 x-custom-header value`:**
9. **`OnEndHeadersForStream 3`:**
10. ... (服务器响应)
11. **`OnFrameHeader 3 <length> 1 4`:** (接收到 HEADERS 帧)
12. **`OnBeginHeadersForStream 3`:**
13. **`OnHeaderForStream 3 :status 200`:**
14. **`OnHeaderForStream 3 content-type application/json`:**
15. **`OnEndHeadersForStream 3`:**
16. **`OnFrameHeader 3 <length> 0 0`:** (接收到 DATA 帧)
17. **`OnBeginDataForStream 3 <data length>`:**
18. **`OnDataForStream 3 {"key": "value"}`:** (假设响应的 JSON 数据)
19. **`OnEndStream 3`:**

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个 HTTP/2 连接接收到一个针对流 ID 5 的 DATA 帧，有效负载长度为 100 字节。

**预期输出:**  `RecordingHttp2Visitor` 的 `events_` 向量会增加以下记录：

1. **`OnFrameHeader 5 100 0 0`:**  假设 DATA 帧类型为 0，标志为 0。
2. **`OnBeginDataForStream 5 100`:**
3. **`OnDataForStream 5 <100 bytes of data>`:**  这里会记录实际接收到的数据，但由于是假设，我们用占位符表示。

**涉及用户或编程常见的使用错误:**

1. **测试用例没有清理 `events_`:**  如果 `RecordingHttp2Visitor` 主要用于测试，开发者可能会忘记在每个测试用例执行前后清理 `events_` 向量，导致测试结果受到之前测试的影响。

   ```c++
   // 错误示例：
   TEST_F(MyHttp2Test, TestSomething) {
     visitor_.OnBeginHeadersForStream(1);
     // ... 其他操作
     EXPECT_TRUE(visitor_.events_.contains("OnBeginHeadersForStream 1"));

     // 下一个测试用例可能错误地包含这个事件
   }

   TEST_F(MyHttp2Test, TestSomethingElse) {
     // visitor_.events_ 中可能仍然有上一个测试用例的事件
     EXPECT_TRUE(visitor_.events_.empty()); // 可能失败
   }
   ```

   **正确做法:** 在测试用例开始前或结束后清空 `events_`。

2. **错误地假设事件发生的顺序:**  HTTP/2 允许一定的并发性，某些事件的顺序可能不是严格保证的。开发者在测试时应该考虑到这一点，避免做出过于严格的顺序假设。例如，在处理头部时，多个头部字段的 `OnHeaderForStream` 调用顺序可能不固定。

3. **没有覆盖所有可能的 HTTP/2 事件:**  开发者在使用 `RecordingHttp2Visitor` 进行测试时，可能只关注了部分事件，而忽略了其他重要的事件，导致测试覆盖率不足。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设开发者在使用 Chromium 的网络栈进行 HTTP/2 相关的开发或调试，想要了解 HTTP/2 的具体交互过程。以下是一些可能到达 `RecordingHttp2Visitor` 的步骤：

1. **开发者决定调试 HTTP/2 通信:**  他们可能遇到了 HTTP/2 相关的问题，例如请求失败、性能问题或协议错误。

2. **选择使用 `RecordingHttp2Visitor` 进行调试:**  `RecordingHttp2Visitor` 提供了一种简单的方式来记录所有相关的 HTTP/2 事件，而无需深入到复杂的网络栈内部。这通常是通过在测试代码中或者在某些调试工具中配置使用这个 visitor 来实现的。

3. **配置 HTTP/2 连接以使用 `RecordingHttp2Visitor`:**  在 Chromium 的网络栈中，可能存在某种机制，允许开发者在创建或配置 HTTP/2 会话时指定一个 `Http2VisitorInterface` 的实现。开发者会配置使用 `RecordingHttp2Visitor` 的实例。

4. **发起 HTTP/2 请求 (间接通过用户操作或直接通过代码):**
   * **用户操作:** 用户在浏览器中访问一个支持 HTTP/2 的网站，或者网页上的 JavaScript 代码发起 HTTP/2 请求。
   * **代码触发:** 开发者可能编写了 C++ 测试代码，直接使用 Chromium 的网络 API 发起 HTTP/2 请求。

5. **HTTP/2 会话建立和帧交换:**  当 HTTP/2 连接建立后，Chromium 的网络栈会解析和生成 HTTP/2 帧。

6. **`RecordingHttp2Visitor` 的方法被调用:**  在处理每个 HTTP/2 事件时（例如接收到帧、发送数据等），网络栈的代码会调用已注册的 `Http2VisitorInterface` (在本例中是 `RecordingHttp2Visitor`) 相应的方法，并将事件信息传递给它。

7. **事件被记录到 `events_` 向量中:** `RecordingHttp2Visitor` 的各个方法会将接收到的事件信息格式化成字符串，并添加到 `events_` 向量中。

8. **开发者检查 `events_` 向量:**  调试过程的最后一步是开发者查看 `RecordingHttp2Visitor` 记录的事件，分析 HTTP/2 的交互过程，从而定位问题或理解行为。他们可能会打印 `events_` 的内容，或者在测试断言中使用这些记录的信息。

总而言之，`RecordingHttp2Visitor` 是 Chromium 网络栈中一个非常有用的工具，用于记录和观察 HTTP/2 会话的详细过程，主要用于测试和调试目的。它本身不直接与 JavaScript 交互，但记录的是由 JavaScript 发起的网络请求所产生的 HTTP/2 事件。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/recording_http2_visitor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/recording_http2_visitor.h"

#include "absl/strings/str_format.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_util.h"

namespace http2 {
namespace adapter {
namespace test {

int64_t RecordingHttp2Visitor::OnReadyToSend(absl::string_view serialized) {
  events_.push_back(absl::StrFormat("OnReadyToSend %d", serialized.size()));
  return serialized.size();
}

Http2VisitorInterface::DataFrameHeaderInfo
RecordingHttp2Visitor::OnReadyToSendDataForStream(Http2StreamId stream_id,
                                                  size_t max_length) {
  events_.push_back(absl::StrFormat("OnReadyToSendDataForStream %d %d",
                                    stream_id, max_length));
  return {70000, true, true};
}

bool RecordingHttp2Visitor::SendDataFrame(Http2StreamId stream_id,
                                          absl::string_view /*frame_header*/,
                                          size_t payload_bytes) {
  events_.push_back(
      absl::StrFormat("SendDataFrame %d %d", stream_id, payload_bytes));
  return true;
}

void RecordingHttp2Visitor::OnConnectionError(ConnectionError error) {
  events_.push_back(
      absl::StrFormat("OnConnectionError %s", ConnectionErrorToString(error)));
}

bool RecordingHttp2Visitor::OnFrameHeader(Http2StreamId stream_id,
                                          size_t length, uint8_t type,
                                          uint8_t flags) {
  events_.push_back(absl::StrFormat("OnFrameHeader %d %d %d %d", stream_id,
                                    length, type, flags));
  return true;
}

void RecordingHttp2Visitor::OnSettingsStart() {
  events_.push_back("OnSettingsStart");
}

void RecordingHttp2Visitor::OnSetting(Http2Setting setting) {
  events_.push_back(absl::StrFormat(
      "OnSetting %s %d", Http2SettingsIdToString(setting.id), setting.value));
}

void RecordingHttp2Visitor::OnSettingsEnd() {
  events_.push_back("OnSettingsEnd");
}

void RecordingHttp2Visitor::OnSettingsAck() {
  events_.push_back("OnSettingsAck");
}

bool RecordingHttp2Visitor::OnBeginHeadersForStream(Http2StreamId stream_id) {
  events_.push_back(absl::StrFormat("OnBeginHeadersForStream %d", stream_id));
  return true;
}

Http2VisitorInterface::OnHeaderResult RecordingHttp2Visitor::OnHeaderForStream(
    Http2StreamId stream_id, absl::string_view name, absl::string_view value) {
  events_.push_back(
      absl::StrFormat("OnHeaderForStream %d %s %s", stream_id, name, value));
  return HEADER_OK;
}

bool RecordingHttp2Visitor::OnEndHeadersForStream(Http2StreamId stream_id) {
  events_.push_back(absl::StrFormat("OnEndHeadersForStream %d", stream_id));
  return true;
}

bool RecordingHttp2Visitor::OnDataPaddingLength(Http2StreamId stream_id,
                                                size_t padding_length) {
  events_.push_back(
      absl::StrFormat("OnDataPaddingLength %d %d", stream_id, padding_length));
  return true;
}

bool RecordingHttp2Visitor::OnBeginDataForStream(Http2StreamId stream_id,
                                                 size_t payload_length) {
  events_.push_back(
      absl::StrFormat("OnBeginDataForStream %d %d", stream_id, payload_length));
  return true;
}

bool RecordingHttp2Visitor::OnDataForStream(Http2StreamId stream_id,
                                            absl::string_view data) {
  events_.push_back(absl::StrFormat("OnDataForStream %d %s", stream_id, data));
  return true;
}

bool RecordingHttp2Visitor::OnEndStream(Http2StreamId stream_id) {
  events_.push_back(absl::StrFormat("OnEndStream %d", stream_id));
  return true;
}

void RecordingHttp2Visitor::OnRstStream(Http2StreamId stream_id,
                                        Http2ErrorCode error_code) {
  events_.push_back(absl::StrFormat("OnRstStream %d %s", stream_id,
                                    Http2ErrorCodeToString(error_code)));
}

bool RecordingHttp2Visitor::OnCloseStream(Http2StreamId stream_id,
                                          Http2ErrorCode error_code) {
  events_.push_back(absl::StrFormat("OnCloseStream %d %s", stream_id,
                                    Http2ErrorCodeToString(error_code)));
  return true;
}

void RecordingHttp2Visitor::OnPriorityForStream(Http2StreamId stream_id,
                                                Http2StreamId parent_stream_id,
                                                int weight, bool exclusive) {
  events_.push_back(absl::StrFormat("OnPriorityForStream %d %d %d %d",
                                    stream_id, parent_stream_id, weight,
                                    exclusive));
}

void RecordingHttp2Visitor::OnPing(Http2PingId ping_id, bool is_ack) {
  events_.push_back(absl::StrFormat("OnPing %d %d", ping_id, is_ack));
}

void RecordingHttp2Visitor::OnPushPromiseForStream(
    Http2StreamId stream_id, Http2StreamId promised_stream_id) {
  events_.push_back(absl::StrFormat("OnPushPromiseForStream %d %d", stream_id,
                                    promised_stream_id));
}

bool RecordingHttp2Visitor::OnGoAway(Http2StreamId last_accepted_stream_id,
                                     Http2ErrorCode error_code,
                                     absl::string_view opaque_data) {
  events_.push_back(
      absl::StrFormat("OnGoAway %d %s %s", last_accepted_stream_id,
                      Http2ErrorCodeToString(error_code), opaque_data));
  return true;
}

void RecordingHttp2Visitor::OnWindowUpdate(Http2StreamId stream_id,
                                           int window_increment) {
  events_.push_back(
      absl::StrFormat("OnWindowUpdate %d %d", stream_id, window_increment));
}

int RecordingHttp2Visitor::OnBeforeFrameSent(uint8_t frame_type,
                                             Http2StreamId stream_id,
                                             size_t length, uint8_t flags) {
  events_.push_back(absl::StrFormat("OnBeforeFrameSent %d %d %d %d", frame_type,
                                    stream_id, length, flags));
  return 0;
}

int RecordingHttp2Visitor::OnFrameSent(uint8_t frame_type,
                                       Http2StreamId stream_id, size_t length,
                                       uint8_t flags, uint32_t error_code) {
  events_.push_back(absl::StrFormat("OnFrameSent %d %d %d %d %d", frame_type,
                                    stream_id, length, flags, error_code));
  return 0;
}

bool RecordingHttp2Visitor::OnInvalidFrame(Http2StreamId stream_id,
                                           InvalidFrameError error) {
  events_.push_back(absl::StrFormat("OnInvalidFrame %d %s", stream_id,
                                    InvalidFrameErrorToString(error)));
  return true;
}

void RecordingHttp2Visitor::OnBeginMetadataForStream(Http2StreamId stream_id,
                                                     size_t payload_length) {
  events_.push_back(absl::StrFormat("OnBeginMetadataForStream %d %d", stream_id,
                                    payload_length));
}

bool RecordingHttp2Visitor::OnMetadataForStream(Http2StreamId stream_id,
                                                absl::string_view metadata) {
  events_.push_back(
      absl::StrFormat("OnMetadataForStream %d %s", stream_id, metadata));
  return true;
}

bool RecordingHttp2Visitor::OnMetadataEndForStream(Http2StreamId stream_id) {
  events_.push_back(absl::StrFormat("OnMetadataEndForStream %d", stream_id));
  return true;
}

std::pair<int64_t, bool> RecordingHttp2Visitor::PackMetadataForStream(
    Http2StreamId stream_id, uint8_t* /*dest*/, size_t /*dest_len*/) {
  events_.push_back(absl::StrFormat("PackMetadataForStream %d", stream_id));
  return {1, true};
}

void RecordingHttp2Visitor::OnErrorDebug(absl::string_view message) {
  events_.push_back(absl::StrFormat("OnErrorDebug %s", message));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
```