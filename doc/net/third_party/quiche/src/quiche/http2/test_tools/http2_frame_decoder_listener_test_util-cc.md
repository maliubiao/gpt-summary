Response:
Let's break down the thought process for analyzing this C++ file and generating the detailed explanation.

**1. Initial Understanding of the Request:**

The request asks for the functionality of a specific Chromium source file (`http2_frame_decoder_listener_test_util.cc`), its relation to JavaScript, examples of logical reasoning, common user errors, and debugging context.

**2. High-Level Overview of the File:**

The first step is to scan the file and understand its overall purpose. Keywords like "test_tools," "FailingHttp2FrameDecoderListener," and "LoggingHttp2FrameDecoderListener" are strong indicators that this file is designed for *testing* the HTTP/2 frame decoder. The presence of the `Http2FrameDecoderListener` interface confirms this.

**3. Analyzing `FailingHttp2FrameDecoderListener`:**

* **Purpose:**  The name "Failing" immediately suggests its role. It's designed to *fail* if any of the decoder's callback methods are invoked. This is a common pattern in testing: creating a mock object that throws errors if unexpected behavior occurs.
* **Implementation:** Examine each method (`OnFrameHeader`, `OnDataStart`, etc.). Notice that each method has a `FAIL()` or `ADD_FAILURE()` macro call. This confirms the "failing" behavior.
* **No Functionality:**  It doesn't actually process any HTTP/2 frames. Its sole purpose is to detect incorrect decoder behavior.

**4. Analyzing `LoggingHttp2FrameDecoderListener`:**

* **Purpose:**  The name "Logging" indicates its primary function is to log events. The constructor taking another `Http2FrameDecoderListener*` suggests it's a decorator or wrapper.
* **Implementation:** Each method first logs information about the event using `QUICHE_VLOG(1)`. Then, if a `wrapped_` listener exists, it calls the corresponding method on the wrapped listener.
* **Wrapper Pattern:** This confirms it's a wrapper. It adds logging functionality to an existing `Http2FrameDecoderListener`.

**5. Connecting to the `Http2FrameDecoderListener` Interface:**

Recognize that both classes implement the `Http2FrameDecoderListener` interface (though it's not explicitly shown in this snippet, it's implied by the method signatures). This interface defines the callbacks that an HTTP/2 frame decoder will invoke as it processes incoming data.

**6. Identifying the Testing Context:**

Realize that these classes are utilities for writing unit tests. They help test the *decoder* itself, not the entire HTTP/2 implementation.

**7. Addressing the JavaScript Question:**

* **Indirect Relationship:**  HTTP/2 is a network protocol. Browsers (which run JavaScript) use HTTP/2 to communicate with servers. Therefore, there's an *indirect* relationship.
* **No Direct Interaction:** This C++ code doesn't directly interact with JavaScript. It's part of the browser's *internal* implementation of HTTP/2.
* **Example:** Provide a user-level example of how JavaScript uses HTTP/2 (fetching data). Explain that this C++ code is involved *under the hood* when that happens.

**8. Logical Reasoning (Input/Output):**

* **`FailingHttp2FrameDecoderListener`:**
    * **Input:**  Any valid HTTP/2 frame data fed to the decoder.
    * **Output:** The test will fail because the `FailingHttp2FrameDecoderListener` will encounter an unexpected callback and trigger a `FAIL()` or `ADD_FAILURE()`.
* **`LoggingHttp2FrameDecoderListener`:**
    * **Input:** Any valid HTTP/2 frame data.
    * **Output:** Log messages detailing the events (frame header, data payload, etc.). If wrapped around another listener, it will also forward the events to that listener.

**9. Common User/Programming Errors:**

* **Incorrect Usage of `FailingHttp2FrameDecoderListener`:**  Trying to use it for actual decoding. It's for testing *incorrect* decoder behavior.
* **Forgetting to Wrap:** If using `LoggingHttp2FrameDecoderListener`, forgetting to provide a wrapped listener might result in missing functionality if logging is the *only* intended addition.
* **Misinterpreting Log Output:** Not understanding the meaning of the log messages produced by `LoggingHttp2FrameDecoderListener`.

**10. Debugging Scenario:**

* **User Action:** Start with a high-level user action (opening a webpage).
* **Network Request:** Explain that this triggers an HTTP/2 request.
* **Data Transmission:** Describe the server's HTTP/2 response.
* **Decoder Involvement:**  The browser's HTTP/2 decoder processes the response.
* **Potential Issues:** Mention scenarios where the decoder might encounter errors.
* **Test Utility Usage:** Explain how these test utilities can be used by developers to debug such issues (e.g., using `LoggingHttp2FrameDecoderListener` to trace the decoding process).

**11. Structuring the Explanation:**

Organize the information logically with clear headings and bullet points for readability. Start with a general overview and then delve into the details of each class. Address each part of the original request.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe focus heavily on the HTTP/2 protocol details.
* **Correction:** Realize the request is about the *specific file* and its purpose in *testing*. Shift focus to the testing aspect.
* **Initial Thought:**  Overcomplicate the JavaScript relationship.
* **Correction:** Keep the JavaScript explanation concise and focused on the indirect connection through browser functionality.
* **Initial Thought:**  Only provide code-level examples for errors.
* **Correction:** Add more user-centric examples to illustrate how these low-level components relate to user actions.

By following this structured analysis and incorporating self-correction, a comprehensive and accurate explanation can be generated.
这个文件 `net/third_party/quiche/src/quiche/http2/test_tools/http2_frame_decoder_listener_test_util.cc` 是 Chromium 网络栈中 QUIC 协议的 HTTP/2 实现部分，专门用于 **测试 HTTP/2 帧解码器 (`Http2FrameDecoder`) 的功能**。 它提供了一些辅助工具类，用于验证解码器在处理不同类型的 HTTP/2 帧时的行为是否正确。

**主要功能:**

1. **`FailingHttp2FrameDecoderListener` 类:**
   -  这是一个实现了 `Http2FrameDecoderListener` 接口的类。
   -  它的核心功能是 **在任何被调用的解码器回调方法中都直接触发测试失败 (`FAIL()` 或 `ADD_FAILURE()`)**。
   -  **用途:**  主要用于测试 HTTP/2 帧解码器是否 **不应该** 调用某些回调方法的情况。 例如，当你期望解码器因为输入的数据不完整或格式错误而提前终止解码时，你可以使用这个 Listener。如果解码器意外地调用了任何回调，测试就会失败。

2. **`LoggingHttp2FrameDecoderListener` 类:**
   -  这也是一个实现了 `Http2FrameDecoderListener` 接口的类。
   -  它的核心功能是 **记录 (log) 所有被调用的解码器回调方法及其参数**。
   -  **用途:**
      - **调试:**  可以用于跟踪 HTTP/2 帧解码器处理帧的详细过程，了解哪些回调被调用，以及传递了什么数据。
      - **验证:**  可以用于验证解码器是否按照预期的顺序和方式调用回调方法。
      - **与其他 Listener 结合:**  它可以作为一个 "装饰器 (decorator)"，包装另一个 `Http2FrameDecoderListener`，在调用被包装的 Listener 的方法之前或之后记录日志。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身 **与 JavaScript 没有直接的运行时交互**。它属于浏览器内核的网络栈部分，是使用 C++ 实现的。

然而，它间接地支撑着 JavaScript 中使用 HTTP/2 的功能。当 JavaScript 代码发起一个网络请求 (例如使用 `fetch` API) 并且浏览器决定使用 HTTP/2 协议时，这个文件中的代码（或者说使用了这些测试工具所开发的 HTTP/2 解码器）就会被用于解析从服务器接收到的 HTTP/2 帧。

**举例说明:**

假设 JavaScript 代码执行以下操作：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器发送这个请求并接收到服务器的 HTTP/2 响应时，`Http2FrameDecoder` 会解析响应数据。为了确保解码器正确工作，开发者可能会使用 `LoggingHttp2FrameDecoderListener` 来记录解码过程，查看是否收到了 `HEADERS` 帧 (包含 HTTP 头部) 和 `DATA` 帧 (包含响应体)。

**逻辑推理的例子 (假设输入与输出):**

**场景:** 测试解码器在接收到一个带有填充 (padding) 的 `DATA` 帧时的行为。

**假设输入 (模拟接收到的字节流):**

```
// 帧头 (DATA 帧，流 ID 5，有填充)
0x00 0x00 0x0a  // Length = 10
0x00            // Type = DATA
0x00            // Flags = 0x08 (PADDED)
0x00 0x00 0x00 0x05 // Stream ID = 5

// 填充长度 (1 字节)
0x05

// 数据载荷 (5 字节)
0x61 0x62 0x63 0x64 0x65 // "abcde"

// 填充 (5 字节)
0x00 0x00 0x00 0x00 0x00
```

**使用 `LoggingHttp2FrameDecoderListener` 的预期输出:**

```
OnFrameHeader: [length=10, type=DATA, flags=8, stream_id=5]
OnDataStart: [length=10, type=DATA, flags=8, stream_id=5]
OnPadLength: trailing_length=5
OnDataPayload: len=5
OnPadding: skipped_length=5
OnDataEnd
```

**使用 `FailingHttp2FrameDecoderListener` 的预期行为:**

如果解码器在不应该调用任何回调方法的情况下，调用了任何 `FailingHttp2FrameDecoderListener` 的方法，测试就会失败。例如，如果解码器在帧头解析错误的情况下仍然尝试解析数据载荷，就会触发 `OnDataPayload`，从而导致测试失败。

**用户或编程常见的使用错误 (以及如何到达这里):**

1. **错误地将 `FailingHttp2FrameDecoderListener` 用于正常的解码流程:**
   - **错误:**  开发者可能误以为 `FailingHttp2FrameDecoderListener` 可以用来验证帧的内容。
   - **如何到达这里:** 开发者在编写测试用例时，可能没有仔细阅读文档或理解 `FailingHttp2FrameDecoderListener` 的用途，直接将其作为解码器的监听器，期望它能像一个正常的监听器一样工作。
   - **结果:**  任何成功的帧解码都会导致测试失败，因为 `FailingHttp2FrameDecoderListener` 的所有回调都会触发 `FAIL()`。

2. **忘记在 `LoggingHttp2FrameDecoderListener` 中包装真正的监听器:**
   - **错误:**  开发者可能只想记录日志，但忘记将 `LoggingHttp2FrameDecoderListener` 包装在实际处理帧的监听器周围。
   - **如何到达这里:** 开发者可能创建了一个 `LoggingHttp2FrameDecoderListener` 的实例，并将其传递给解码器，但没有提供 `wrapped_` 参数。
   - **结果:**  日志会被记录，但实际的帧处理逻辑不会被执行，可能导致后续的测试或程序逻辑错误。

3. **误解日志输出:**
   - **错误:** 开发者可能不理解 `LoggingHttp2FrameDecoderListener` 输出的日志信息的含义，例如不明白 `OnPadding` 和 `OnDataPayload` 的区别。
   - **如何到达这里:** 开发者在查看日志时，可能没有深入理解 HTTP/2 帧的结构和解码过程。
   - **结果:**  可能错误地判断解码器的行为是否正确。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个 HTTPS 网站 (例如 `https://example.com`)。**
2. **浏览器与服务器协商使用 HTTP/2 协议。**
3. **用户在网页上执行某些操作，触发浏览器向服务器发送 HTTP/2 请求 (例如点击一个链接或提交一个表单)。**
4. **服务器返回 HTTP/2 响应数据。**
5. **浏览器网络栈中的 HTTP/2 解码器 (`Http2FrameDecoder`) 开始解析接收到的字节流。**
6. **在测试或调试环境下，开发者可能会将一个 `LoggingHttp2FrameDecoderListener` 实例传递给 `Http2FrameDecoder`。**
7. **当解码器解析到不同的 HTTP/2 帧时，它会调用 `LoggingHttp2FrameDecoderListener` 相应的回调方法，例如 `OnFrameHeader`、`OnDataStart`、`OnDataPayload` 等。**
8. **开发者查看 `LoggingHttp2FrameDecoderListener` 输出的日志，以了解解码器的具体行为，例如：**
   -  接收到了哪些类型的帧。
   -  帧的长度、标志位、流 ID 等信息。
   -  数据载荷的内容。
   -  是否存在填充。
9. **如果解码过程中出现错误，例如接收到格式错误的帧，或者填充长度不正确，开发者可能会使用 `FailingHttp2FrameDecoderListener` 来编写测试用例，验证解码器是否正确地处理了这些错误情况（例如，不会继续解析后续的数据，或者会触发错误回调）。**

总而言之，`http2_frame_decoder_listener_test_util.cc` 文件提供的工具类是 HTTP/2 解码器测试的重要组成部分，帮助开发者验证解码器在各种场景下的行为是否符合 HTTP/2 规范。虽然与 JavaScript 没有直接的运行时联系，但它支撑着浏览器中基于 HTTP/2 的网络通信功能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/test_tools/http2_frame_decoder_listener_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/test_tools/http2_frame_decoder_listener_test_util.h"

#include "quiche/http2/decoder/http2_frame_decoder_listener.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/http2/http2_structures.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {

FailingHttp2FrameDecoderListener::FailingHttp2FrameDecoderListener() = default;
FailingHttp2FrameDecoderListener::~FailingHttp2FrameDecoderListener() = default;

bool FailingHttp2FrameDecoderListener::OnFrameHeader(
    const Http2FrameHeader& header) {
  ADD_FAILURE() << "OnFrameHeader: " << header;
  return false;
}

void FailingHttp2FrameDecoderListener::OnDataStart(
    const Http2FrameHeader& header) {
  FAIL() << "OnDataStart: " << header;
}

void FailingHttp2FrameDecoderListener::OnDataPayload(const char* /*data*/,
                                                     size_t len) {
  FAIL() << "OnDataPayload: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnDataEnd() { FAIL() << "OnDataEnd"; }

void FailingHttp2FrameDecoderListener::OnHeadersStart(
    const Http2FrameHeader& header) {
  FAIL() << "OnHeadersStart: " << header;
}

void FailingHttp2FrameDecoderListener::OnHeadersPriority(
    const Http2PriorityFields& priority) {
  FAIL() << "OnHeadersPriority: " << priority;
}

void FailingHttp2FrameDecoderListener::OnHpackFragment(const char* /*data*/,
                                                       size_t len) {
  FAIL() << "OnHpackFragment: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnHeadersEnd() {
  FAIL() << "OnHeadersEnd";
}

void FailingHttp2FrameDecoderListener::OnPriorityFrame(
    const Http2FrameHeader& header, const Http2PriorityFields& priority) {
  FAIL() << "OnPriorityFrame: " << header << "; priority: " << priority;
}

void FailingHttp2FrameDecoderListener::OnContinuationStart(
    const Http2FrameHeader& header) {
  FAIL() << "OnContinuationStart: " << header;
}

void FailingHttp2FrameDecoderListener::OnContinuationEnd() {
  FAIL() << "OnContinuationEnd";
}

void FailingHttp2FrameDecoderListener::OnPadLength(size_t trailing_length) {
  FAIL() << "OnPadLength: trailing_length=" << trailing_length;
}

void FailingHttp2FrameDecoderListener::OnPadding(const char* /*padding*/,
                                                 size_t skipped_length) {
  FAIL() << "OnPadding: skipped_length=" << skipped_length;
}

void FailingHttp2FrameDecoderListener::OnRstStream(
    const Http2FrameHeader& header, Http2ErrorCode error_code) {
  FAIL() << "OnRstStream: " << header << "; code=" << error_code;
}

void FailingHttp2FrameDecoderListener::OnSettingsStart(
    const Http2FrameHeader& header) {
  FAIL() << "OnSettingsStart: " << header;
}

void FailingHttp2FrameDecoderListener::OnSetting(
    const Http2SettingFields& setting_fields) {
  FAIL() << "OnSetting: " << setting_fields;
}

void FailingHttp2FrameDecoderListener::OnSettingsEnd() {
  FAIL() << "OnSettingsEnd";
}

void FailingHttp2FrameDecoderListener::OnSettingsAck(
    const Http2FrameHeader& header) {
  FAIL() << "OnSettingsAck: " << header;
}

void FailingHttp2FrameDecoderListener::OnPushPromiseStart(
    const Http2FrameHeader& header, const Http2PushPromiseFields& promise,
    size_t total_padding_length) {
  FAIL() << "OnPushPromiseStart: " << header << "; promise: " << promise
         << "; total_padding_length: " << total_padding_length;
}

void FailingHttp2FrameDecoderListener::OnPushPromiseEnd() {
  FAIL() << "OnPushPromiseEnd";
}

void FailingHttp2FrameDecoderListener::OnPing(const Http2FrameHeader& header,
                                              const Http2PingFields& ping) {
  FAIL() << "OnPing: " << header << "; ping: " << ping;
}

void FailingHttp2FrameDecoderListener::OnPingAck(const Http2FrameHeader& header,
                                                 const Http2PingFields& ping) {
  FAIL() << "OnPingAck: " << header << "; ping: " << ping;
}

void FailingHttp2FrameDecoderListener::OnGoAwayStart(
    const Http2FrameHeader& header, const Http2GoAwayFields& goaway) {
  FAIL() << "OnGoAwayStart: " << header << "; goaway: " << goaway;
}

void FailingHttp2FrameDecoderListener::OnGoAwayOpaqueData(const char* /*data*/,
                                                          size_t len) {
  FAIL() << "OnGoAwayOpaqueData: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnGoAwayEnd() {
  FAIL() << "OnGoAwayEnd";
}

void FailingHttp2FrameDecoderListener::OnWindowUpdate(
    const Http2FrameHeader& header, uint32_t increment) {
  FAIL() << "OnWindowUpdate: " << header << "; increment=" << increment;
}

void FailingHttp2FrameDecoderListener::OnAltSvcStart(
    const Http2FrameHeader& header, size_t origin_length, size_t value_length) {
  FAIL() << "OnAltSvcStart: " << header << "; origin_length: " << origin_length
         << "; value_length: " << value_length;
}

void FailingHttp2FrameDecoderListener::OnAltSvcOriginData(const char* /*data*/,
                                                          size_t len) {
  FAIL() << "OnAltSvcOriginData: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnAltSvcValueData(const char* /*data*/,
                                                         size_t len) {
  FAIL() << "OnAltSvcValueData: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnAltSvcEnd() {
  FAIL() << "OnAltSvcEnd";
}

void FailingHttp2FrameDecoderListener::OnPriorityUpdateStart(
    const Http2FrameHeader& header,
    const Http2PriorityUpdateFields& priority_update) {
  FAIL() << "OnPriorityUpdateStart: " << header << "; prioritized_stream_id: "
         << priority_update.prioritized_stream_id;
}

void FailingHttp2FrameDecoderListener::OnPriorityUpdatePayload(
    const char* /*data*/, size_t len) {
  FAIL() << "OnPriorityUpdatePayload: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnPriorityUpdateEnd() {
  FAIL() << "OnPriorityUpdateEnd";
}

void FailingHttp2FrameDecoderListener::OnUnknownStart(
    const Http2FrameHeader& header) {
  FAIL() << "OnUnknownStart: " << header;
}

void FailingHttp2FrameDecoderListener::OnUnknownPayload(const char* /*data*/,
                                                        size_t len) {
  FAIL() << "OnUnknownPayload: len=" << len;
}

void FailingHttp2FrameDecoderListener::OnUnknownEnd() {
  FAIL() << "OnUnknownEnd";
}

void FailingHttp2FrameDecoderListener::OnPaddingTooLong(
    const Http2FrameHeader& header, size_t missing_length) {
  FAIL() << "OnPaddingTooLong: " << header
         << "; missing_length: " << missing_length;
}

void FailingHttp2FrameDecoderListener::OnFrameSizeError(
    const Http2FrameHeader& header) {
  FAIL() << "OnFrameSizeError: " << header;
}

LoggingHttp2FrameDecoderListener::LoggingHttp2FrameDecoderListener()
    : wrapped_(nullptr) {}
LoggingHttp2FrameDecoderListener::LoggingHttp2FrameDecoderListener(
    Http2FrameDecoderListener* wrapped)
    : wrapped_(wrapped) {}
LoggingHttp2FrameDecoderListener::~LoggingHttp2FrameDecoderListener() = default;

bool LoggingHttp2FrameDecoderListener::OnFrameHeader(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnFrameHeader: " << header;
  if (wrapped_ != nullptr) {
    return wrapped_->OnFrameHeader(header);
  }
  return true;
}

void LoggingHttp2FrameDecoderListener::OnDataStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnDataStart: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnDataStart(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnDataPayload(const char* data,
                                                     size_t len) {
  QUICHE_VLOG(1) << "OnDataPayload: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnDataPayload(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnDataEnd() {
  QUICHE_VLOG(1) << "OnDataEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnDataEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnHeadersStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnHeadersStart: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnHeadersStart(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnHeadersPriority(
    const Http2PriorityFields& priority) {
  QUICHE_VLOG(1) << "OnHeadersPriority: " << priority;
  if (wrapped_ != nullptr) {
    wrapped_->OnHeadersPriority(priority);
  }
}

void LoggingHttp2FrameDecoderListener::OnHpackFragment(const char* data,
                                                       size_t len) {
  QUICHE_VLOG(1) << "OnHpackFragment: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnHpackFragment(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnHeadersEnd() {
  QUICHE_VLOG(1) << "OnHeadersEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnHeadersEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnPriorityFrame(
    const Http2FrameHeader& header, const Http2PriorityFields& priority) {
  QUICHE_VLOG(1) << "OnPriorityFrame: " << header << "; priority: " << priority;
  if (wrapped_ != nullptr) {
    wrapped_->OnPriorityFrame(header, priority);
  }
}

void LoggingHttp2FrameDecoderListener::OnContinuationStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnContinuationStart: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnContinuationStart(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnContinuationEnd() {
  QUICHE_VLOG(1) << "OnContinuationEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnContinuationEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnPadLength(size_t trailing_length) {
  QUICHE_VLOG(1) << "OnPadLength: trailing_length=" << trailing_length;
  if (wrapped_ != nullptr) {
    wrapped_->OnPadLength(trailing_length);
  }
}

void LoggingHttp2FrameDecoderListener::OnPadding(const char* padding,
                                                 size_t skipped_length) {
  QUICHE_VLOG(1) << "OnPadding: skipped_length=" << skipped_length;
  if (wrapped_ != nullptr) {
    wrapped_->OnPadding(padding, skipped_length);
  }
}

void LoggingHttp2FrameDecoderListener::OnRstStream(
    const Http2FrameHeader& header, Http2ErrorCode error_code) {
  QUICHE_VLOG(1) << "OnRstStream: " << header << "; code=" << error_code;
  if (wrapped_ != nullptr) {
    wrapped_->OnRstStream(header, error_code);
  }
}

void LoggingHttp2FrameDecoderListener::OnSettingsStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsStart: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnSettingsStart(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnSetting(
    const Http2SettingFields& setting_fields) {
  QUICHE_VLOG(1) << "OnSetting: " << setting_fields;
  if (wrapped_ != nullptr) {
    wrapped_->OnSetting(setting_fields);
  }
}

void LoggingHttp2FrameDecoderListener::OnSettingsEnd() {
  QUICHE_VLOG(1) << "OnSettingsEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnSettingsEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnSettingsAck(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsAck: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnSettingsAck(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnPushPromiseStart(
    const Http2FrameHeader& header, const Http2PushPromiseFields& promise,
    size_t total_padding_length) {
  QUICHE_VLOG(1) << "OnPushPromiseStart: " << header << "; promise: " << promise
                 << "; total_padding_length: " << total_padding_length;
  if (wrapped_ != nullptr) {
    wrapped_->OnPushPromiseStart(header, promise, total_padding_length);
  }
}

void LoggingHttp2FrameDecoderListener::OnPushPromiseEnd() {
  QUICHE_VLOG(1) << "OnPushPromiseEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnPushPromiseEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnPing(const Http2FrameHeader& header,
                                              const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPing: " << header << "; ping: " << ping;
  if (wrapped_ != nullptr) {
    wrapped_->OnPing(header, ping);
  }
}

void LoggingHttp2FrameDecoderListener::OnPingAck(const Http2FrameHeader& header,
                                                 const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPingAck: " << header << "; ping: " << ping;
  if (wrapped_ != nullptr) {
    wrapped_->OnPingAck(header, ping);
  }
}

void LoggingHttp2FrameDecoderListener::OnGoAwayStart(
    const Http2FrameHeader& header, const Http2GoAwayFields& goaway) {
  QUICHE_VLOG(1) << "OnGoAwayStart: " << header << "; goaway: " << goaway;
  if (wrapped_ != nullptr) {
    wrapped_->OnGoAwayStart(header, goaway);
  }
}

void LoggingHttp2FrameDecoderListener::OnGoAwayOpaqueData(const char* data,
                                                          size_t len) {
  QUICHE_VLOG(1) << "OnGoAwayOpaqueData: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnGoAwayOpaqueData(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnGoAwayEnd() {
  QUICHE_VLOG(1) << "OnGoAwayEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnGoAwayEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnWindowUpdate(
    const Http2FrameHeader& header, uint32_t increment) {
  QUICHE_VLOG(1) << "OnWindowUpdate: " << header << "; increment=" << increment;
  if (wrapped_ != nullptr) {
    wrapped_->OnWindowUpdate(header, increment);
  }
}

void LoggingHttp2FrameDecoderListener::OnAltSvcStart(
    const Http2FrameHeader& header, size_t origin_length, size_t value_length) {
  QUICHE_VLOG(1) << "OnAltSvcStart: " << header
                 << "; origin_length: " << origin_length
                 << "; value_length: " << value_length;
  if (wrapped_ != nullptr) {
    wrapped_->OnAltSvcStart(header, origin_length, value_length);
  }
}

void LoggingHttp2FrameDecoderListener::OnAltSvcOriginData(const char* data,
                                                          size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcOriginData: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnAltSvcOriginData(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnAltSvcValueData(const char* data,
                                                         size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcValueData: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnAltSvcValueData(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnAltSvcEnd() {
  QUICHE_VLOG(1) << "OnAltSvcEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnAltSvcEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnPriorityUpdateStart(
    const Http2FrameHeader& header,
    const Http2PriorityUpdateFields& priority_update) {
  QUICHE_VLOG(1) << "OnPriorityUpdateStart";
  if (wrapped_ != nullptr) {
    wrapped_->OnPriorityUpdateStart(header, priority_update);
  }
}

void LoggingHttp2FrameDecoderListener::OnPriorityUpdatePayload(const char* data,
                                                               size_t len) {
  QUICHE_VLOG(1) << "OnPriorityUpdatePayload";
  if (wrapped_ != nullptr) {
    wrapped_->OnPriorityUpdatePayload(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnPriorityUpdateEnd() {
  QUICHE_VLOG(1) << "OnPriorityUpdateEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnPriorityUpdateEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnUnknownStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnUnknownStart: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnUnknownStart(header);
  }
}

void LoggingHttp2FrameDecoderListener::OnUnknownPayload(const char* data,
                                                        size_t len) {
  QUICHE_VLOG(1) << "OnUnknownPayload: len=" << len;
  if (wrapped_ != nullptr) {
    wrapped_->OnUnknownPayload(data, len);
  }
}

void LoggingHttp2FrameDecoderListener::OnUnknownEnd() {
  QUICHE_VLOG(1) << "OnUnknownEnd";
  if (wrapped_ != nullptr) {
    wrapped_->OnUnknownEnd();
  }
}

void LoggingHttp2FrameDecoderListener::OnPaddingTooLong(
    const Http2FrameHeader& header, size_t missing_length) {
  QUICHE_VLOG(1) << "OnPaddingTooLong: " << header
                 << "; missing_length: " << missing_length;
  if (wrapped_ != nullptr) {
    wrapped_->OnPaddingTooLong(header, missing_length);
  }
}

void LoggingHttp2FrameDecoderListener::OnFrameSizeError(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnFrameSizeError: " << header;
  if (wrapped_ != nullptr) {
    wrapped_->OnFrameSizeError(header);
  }
}

}  // namespace http2

"""

```