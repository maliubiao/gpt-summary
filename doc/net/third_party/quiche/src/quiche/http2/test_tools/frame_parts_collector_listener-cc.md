Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `FramePartsCollectorListener`, its relation to JavaScript, example inputs/outputs, common user errors, and how a user might trigger this code.

2. **Initial Code Scan (High-Level):**  The first thing to notice is the class name: `FramePartsCollectorListener`. The term "Listener" strongly suggests this class is designed to observe or react to events. The methods like `OnFrameHeader`, `OnDataStart`, `OnHeadersStart`, etc., confirm this. It seems to be receiving notifications about different parts of an HTTP/2 frame.

3. **Focus on Core Functionality:** The core functionality is evident from the individual `On...` methods. Each method corresponds to a specific part or type of an HTTP/2 frame. The logging statements (`QUICHE_VLOG`) indicate that the class is primarily used for debugging and observation. The calls to `ExpectFrameHeader`, `StartFrame`, `CurrentFrame`, and `EndFrame` suggest an internal state management mechanism to keep track of the current frame being processed.

4. **Identify Key Methods and Their Roles:**
    * **`OnFrameHeader`:**  Receives the initial header of a frame.
    * **`OnDataStart/Payload/End`:** Handles the data payload of a DATA frame.
    * **`OnHeadersStart/Priority/HpackFragment/End`:** Handles the header block of a HEADERS frame. The "HpackFragment" is a strong hint this is related to HTTP/2 header compression.
    * **`OnPriorityFrame`:** Handles a PRIORITY frame.
    * **`OnContinuationStart/End`:** Handles CONTINUATION frames, which are used to send large header blocks.
    * **`OnPadLength/Padding`:** Handles padding in frames.
    * **`OnRstStream`:** Handles RST_STREAM frames (stream reset).
    * **`OnSettingsStart/Setting/End/Ack`:** Handles SETTINGS frames for connection configuration.
    * **`OnPushPromiseStart/End`:** Handles PUSH_PROMISE frames for server-initiated pushes.
    * **`OnPing/Ack`:** Handles PING frames for keep-alives and latency measurement.
    * **`OnGoAwayStart/OpaqueData/End`:** Handles GOAWAY frames for graceful shutdown.
    * **`OnWindowUpdate`:** Handles WINDOW_UPDATE frames for flow control.
    * **`OnAltSvcStart/OriginData/ValueData/End`:** Handles ALTSVC frames for advertising alternative services.
    * **`OnPriorityUpdateStart/Payload/End`:** Handles PRIORITY_UPDATE frames for stream priority changes.
    * **`OnUnknownStart/Payload/End`:** Handles frames of unknown types.
    * **`OnPaddingTooLong/FrameSizeError`:** Handles error conditions.

5. **Look for Internal State Management:** The `StartFrame`, `CurrentFrame`, and `EndFrame` methods are crucial. These likely interact with some internal data structure (probably a stack or a queue) to store and manage the state of the currently being processed frame. The `ExpectFrameHeader` method suggests validation.

6. **Relate to HTTP/2 Concepts:** Connect the methods to fundamental HTTP/2 concepts like frames, headers, data, control frames (SETTINGS, PING, GOAWAY, etc.), stream IDs, and flow control.

7. **Consider the "Test Tools" context:** The file path includes "test_tools," indicating this class is likely used in unit tests or integration tests for HTTP/2 implementations. It helps verify that the HTTP/2 frame processing logic is working correctly.

8. **Address the JavaScript Question:** This is where careful consideration is needed. Directly, C++ code doesn't execute in a JavaScript environment. The connection lies in the *purpose* of HTTP/2. JavaScript code in a browser or Node.js makes HTTP requests. These requests and the server's responses are transmitted over the network using HTTP/2. This `FramePartsCollectorListener` is likely used to *test the C++ implementation* of HTTP/2 that handles these network communications. Therefore, JavaScript's interaction is *indirect*.

9. **Develop Examples:** Create concrete examples of HTTP/2 frames and how the `FramePartsCollectorListener` would process them. Think about the sequence of `On...` method calls.

10. **Identify Potential Errors:** Think about common mistakes in handling HTTP/2 frames, like incorrect frame sizes, invalid stream IDs, or out-of-order frames. Relate these errors to how the `FramePartsCollectorListener` might react (e.g., `OnFrameSizeError`).

11. **Trace User Interaction:**  How does a user's action lead to this code being executed? Start from a high-level action (like clicking a link) and work down through the network stack to the HTTP/2 layer. Emphasize that this is part of the *underlying implementation* and not directly manipulated by the user.

12. **Refine and Structure the Answer:** Organize the findings into logical sections (Functionality, Relation to JavaScript, Input/Output, Errors, Debugging). Use clear and concise language. Provide specific examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Could this be used in a web worker?  **Correction:** While web workers deal with network requests, this specific C++ code is part of the Chromium browser's *internal* networking stack, not directly exposed to JavaScript in that way.
* **Initial thought:**  Focus heavily on low-level bit manipulation. **Correction:**  The code abstracts away the raw byte manipulation. Focus on the logical structure of HTTP/2 frames.
* **Initial phrasing:**  "This code *is* HTTP/2". **Correction:**  "This code *implements a part of* the HTTP/2 protocol."

By following these steps,  we can systematically analyze the C++ code and provide a comprehensive answer that addresses all aspects of the request.
这个 C++ 源代码文件 `frame_parts_collector_listener.cc` 定义了一个名为 `FramePartsCollectorListener` 的类，它在 Chromium 的网络栈中扮演着 **HTTP/2 帧解析和收集测试数据的监听器**的角色。

让我们详细列举一下它的功能：

**核心功能:**

1. **监听 HTTP/2 帧的各个组成部分:**  `FramePartsCollectorListener` 类实现了一系列以 `On` 开头的方法，每个方法对应 HTTP/2 帧解析过程中的一个特定事件或部分。这些部分包括：
    * **帧头 (Frame Header):**  `OnFrameHeader`  接收帧的基本信息，如类型、标志、长度和流 ID。
    * **DATA 帧:**
        * `OnDataStart`:  DATA 帧开始。
        * `OnDataPayload`:  接收 DATA 帧的数据载荷。
        * `OnDataEnd`:  DATA 帧结束。
    * **HEADERS 帧:**
        * `OnHeadersStart`:  HEADERS 帧开始。
        * `OnHeadersPriority`:  接收 HEADERS 帧中的优先级信息。
        * `OnHpackFragment`:  接收 HEADERS 帧的 HPACK 压缩片段。
        * `OnHeadersEnd`:  HEADERS 帧结束。
    * **PRIORITY 帧:** `OnPriorityFrame` 接收完整的 PRIORITY 帧信息。
    * **CONTINUATION 帧:**
        * `OnContinuationStart`:  CONTINUATION 帧开始。
        * `OnHpackFragment`:  接收 CONTINUATION 帧的 HPACK 压缩片段。
        * `OnContinuationEnd`:  CONTINUATION 帧结束。
    * **Padding (填充):**
        * `OnPadLength`:  接收填充长度信息。
        * `OnPadding`:  接收填充数据。
    * **RST_STREAM 帧:** `OnRstStream` 接收 RST_STREAM 帧信息。
    * **SETTINGS 帧:**
        * `OnSettingsStart`:  SETTINGS 帧开始。
        * `OnSetting`:  接收 SETTINGS 帧中的单个设置。
        * `OnSettingsEnd`:  SETTINGS 帧结束。
        * `OnSettingsAck`:  接收 SETTINGS 帧的 ACK。
    * **PUSH_PROMISE 帧:**
        * `OnPushPromiseStart`:  PUSH_PROMISE 帧开始。
        * `OnHpackFragment`: 接收 PUSH_PROMISE 帧的 HPACK 压缩片段。
        * `OnPushPromiseEnd`:  PUSH_PROMISE 帧结束。
    * **PING 帧:**
        * `OnPing`:  接收 PING 帧。
        * `OnPingAck`:  接收 PING 帧的 ACK。
    * **GOAWAY 帧:**
        * `OnGoAwayStart`:  GOAWAY 帧开始。
        * `OnGoAwayOpaqueData`:  接收 GOAWAY 帧的额外数据。
        * `OnGoAwayEnd`:  GOAWAY 帧结束。
    * **WINDOW_UPDATE 帧:** `OnWindowUpdate` 接收 WINDOW_UPDATE 帧信息。
    * **ALTSVC 帧:**
        * `OnAltSvcStart`: ALTSVC 帧开始。
        * `OnAltSvcOriginData`: 接收 ALTSVC 帧的 Origin 数据。
        * `OnAltSvcValueData`: 接收 ALTSVC 帧的 Value 数据。
        * `OnAltSvcEnd`: ALTSVC 帧结束。
    * **PRIORITY_UPDATE 帧:**
        * `OnPriorityUpdateStart`: PRIORITY_UPDATE 帧开始。
        * `OnPriorityUpdatePayload`: 接收 PRIORITY_UPDATE 帧的载荷数据。
        * `OnPriorityUpdateEnd`: PRIORITY_UPDATE 帧结束。
    * **Unknown 帧:**
        * `OnUnknownStart`:  未知类型的帧开始。
        * `OnUnknownPayload`:  接收未知类型帧的载荷数据。
        * `OnUnknownEnd`:  未知类型的帧结束。
    * **错误处理:**
        * `OnPaddingTooLong`:  检测到过长的填充。
        * `OnFrameSizeError`:  检测到帧大小错误。

2. **记录和验证帧的组成部分:**  从方法名和内部的 `QUICHE_VLOG` 日志可以看出，这个类的主要目的是收集和记录接收到的 HTTP/2 帧的各个部分。在测试环境中，它可以用于验证 HTTP/2 帧是否按照预期被解析出来。  `ExpectFrameHeader` 的存在也暗示了可能有断言或者验证帧头的功能。

3. **辅助 HTTP/2 功能的单元测试:**  由于它位于 `test_tools` 目录下，可以推断 `FramePartsCollectorListener` 被用作测试 HTTP/2 实现的工具。它可以作为 HTTP/2 帧处理流程中的一个监听器，用于捕获和检查中间状态，帮助开发者编写更健壮的 HTTP/2 代码。

**与 JavaScript 的关系:**

`FramePartsCollectorListener` 本身是用 C++ 编写的，直接在 Chromium 的网络栈内部运行，**与 JavaScript 没有直接的执行关系**。然而，它的功能与 JavaScript 在 Web 开发中的网络请求行为密切相关。

* **间接影响:**  当 JavaScript 代码在浏览器中发起 HTTP/2 请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），Chromium 的网络栈（包括处理 HTTP/2 的部分）会负责处理这些请求和响应。`FramePartsCollectorListener` 可以在这个过程中被使用来测试 Chromium 的 HTTP/2 实现是否正确地解析和处理了网络上传输的 HTTP/2 帧。
* **调试工具的辅助:**  虽然 JavaScript 代码本身不会直接调用 `FramePartsCollectorListener` 的方法，但在开发和调试 Chromium 浏览器时，开发者可能会使用这个类来分析网络请求的底层 HTTP/2 帧的结构，从而理解浏览器和服务器之间的通信细节。

**举例说明:**

假设一个 JavaScript 程序发起了一个简单的 HTTP GET 请求：

```javascript
fetch('https://example.com/data');
```

在幕后，Chromium 的网络栈会建立与 `example.com` 的 HTTP/2 连接，并发送一个 HEADERS 帧来请求 `/data` 资源。当 Chromium 的 HTTP/2 实现接收到服务器的响应时，可能会包含一个 DATA 帧，其中包含了请求的数据。

`FramePartsCollectorListener` 可能会在测试环境中被配置为监听这些帧的解析过程，例如：

* **假设输入 (收到的 DATA 帧的二进制数据):**  `[0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd']`  (假设这是一个长度为 10 的 DATA 帧，流 ID 为 1，包含 "Hello world" 数据)
* **输出 (`FramePartsCollectorListener` 的方法调用顺序):**
    1. `OnFrameHeader(Http2FrameHeader{type=DATA, flags=0x00, length=10, stream_id=1})`
    2. `OnDataStart(Http2FrameHeader{type=DATA, flags=0x00, length=10, stream_id=1})`
    3. `OnDataPayload("Hello world", 11)`
    4. `OnDataEnd()`

**逻辑推理的假设输入与输出:**

假设我们正在测试 HEADERS 帧的解析，并且收到了一个带有优先级的 HEADERS 帧。

* **假设输入 (收到的 HEADERS 帧的二进制数据):**  `[0x00, 0x00, 0x10, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x8f, 0xff, 0xff, 0xff, ...] ` (这是一个简化的例子，包含帧头、优先级信息和 HPACK 数据)
* **输出 (`FramePartsCollectorListener` 的方法调用顺序):**
    1. `OnFrameHeader(Http2FrameHeader{type=HEADERS, flags=0x04, length=16, stream_id=1})`
    2. `OnHeadersStart(Http2FrameHeader{type=HEADERS, flags=0x04, length=16, stream_id=1})`
    3. `OnHeadersPriority(Http2PriorityFields{exclusive=false, stream_dependency=0, weight=15})` (假设解析出的优先级信息)
    4. `OnHpackFragment(...)` (多次调用，取决于 HPACK 数据的分片情况)
    5. `OnHeadersEnd()`

**用户或编程常见的使用错误 (针对 HTTP/2 实现，而非直接使用 `FramePartsCollectorListener`):**

由于 `FramePartsCollectorListener` 是一个测试工具，它主要帮助开发者发现 HTTP/2 实现中的错误。用户或开发者在使用 HTTP/2 时可能犯的错误包括：

1. **错误的帧大小:**  发送的帧的长度字段与实际载荷大小不符。`OnFrameSizeError` 可以检测到这类错误。
   * **例子:**  构造一个 DATA 帧，声明长度为 10，但实际发送了 12 字节的数据。

2. **无效的流 ID:**  在不正确的上下文中使用了流 ID，例如尝试在流 ID 0 上发送数据帧（流 ID 0 用于连接级别的控制帧）。

3. **违反 HTTP/2 状态机:**  例如，在一个 `half-closed (remote)` 状态的流上发送 HEADERS 帧。

4. **HPACK 压缩错误:**  生成或解析 HPACK 压缩的头部时出现错误，导致 `OnHpackFragment` 接收到无效的数据。

5. **填充处理错误:**  错误地计算或处理填充长度，可能导致 `OnPaddingTooLong` 被调用。
   * **例子:**  发送一个带有填充的 DATA 帧，并在帧头中声明了 5 字节的填充，但实际发送的填充少于 5 字节。

**用户操作是如何一步步的到达这里，作为调试线索:**

`FramePartsCollectorListener` 通常不会直接由最终用户操作触发。它是在 Chromium 开发者进行网络功能调试或编写单元测试时使用的。 流程可能如下：

1. **开发者修改 Chromium 的网络代码:**  开发者可能在实现新的 HTTP/2 功能或修复现有 bug。
2. **编写或运行单元测试:**  为了验证代码的正确性，开发者会编写或运行包含 `FramePartsCollectorListener` 的单元测试。
3. **网络请求模拟或实际发生:**  测试框架会模拟网络请求或实际发起网络请求。
4. **HTTP/2 帧被生成或接收:**  Chromium 的 HTTP/2 实现会根据请求生成 HTTP/2 帧，或者接收来自服务器的 HTTP/2 帧。
5. **帧解析过程:**  Chromium 的 HTTP/2 解析器会逐步解析接收到的帧的各个部分。
6. **`FramePartsCollectorListener` 作为监听器接收事件:**  在解析的每个阶段，例如帧头解析完成、数据载荷接收到等，HTTP/2 解析器会调用 `FramePartsCollectorListener` 相应的 `On...` 方法，将解析出的数据传递给它。
7. **日志记录和断言检查:**  `FramePartsCollectorListener` 会记录接收到的帧部分，并可能进行断言检查，例如验证帧头的类型是否符合预期。
8. **测试结果分析:**  开发者会查看 `FramePartsCollectorListener` 的输出日志或断言结果，以判断 HTTP/2 的解析过程是否正确。如果测试失败，这些日志可以作为调试线索，帮助开发者定位问题所在。

总而言之，`FramePartsCollectorListener` 是 Chromium 网络栈中一个用于测试 HTTP/2 帧处理的内部工具，它通过监听和记录帧的各个组成部分，帮助开发者验证 HTTP/2 实现的正确性。它与 JavaScript 的关系是间接的，体现在它辅助确保浏览器能够正确处理 JavaScript 发起的网络请求。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/test_tools/frame_parts_collector_listener.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/test_tools/frame_parts_collector_listener.h"

#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace test {

bool FramePartsCollectorListener::OnFrameHeader(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnFrameHeader: " << header;
  ExpectFrameHeader(header);
  return true;
}

void FramePartsCollectorListener::OnDataStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnDataStart: " << header;
  StartFrame(header)->OnDataStart(header);
}

void FramePartsCollectorListener::OnDataPayload(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnDataPayload: len=" << len;
  CurrentFrame()->OnDataPayload(data, len);
}

void FramePartsCollectorListener::OnDataEnd() {
  QUICHE_VLOG(1) << "OnDataEnd";
  EndFrame()->OnDataEnd();
}

void FramePartsCollectorListener::OnHeadersStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnHeadersStart: " << header;
  StartFrame(header)->OnHeadersStart(header);
}

void FramePartsCollectorListener::OnHeadersPriority(
    const Http2PriorityFields& priority) {
  QUICHE_VLOG(1) << "OnHeadersPriority: " << priority;
  CurrentFrame()->OnHeadersPriority(priority);
}

void FramePartsCollectorListener::OnHpackFragment(const char* data,
                                                  size_t len) {
  QUICHE_VLOG(1) << "OnHpackFragment: len=" << len;
  CurrentFrame()->OnHpackFragment(data, len);
}

void FramePartsCollectorListener::OnHeadersEnd() {
  QUICHE_VLOG(1) << "OnHeadersEnd";
  EndFrame()->OnHeadersEnd();
}

void FramePartsCollectorListener::OnPriorityFrame(
    const Http2FrameHeader& header,
    const Http2PriorityFields& priority_fields) {
  QUICHE_VLOG(1) << "OnPriority: " << header << "; " << priority_fields;
  StartAndEndFrame(header)->OnPriorityFrame(header, priority_fields);
}

void FramePartsCollectorListener::OnContinuationStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnContinuationStart: " << header;
  StartFrame(header)->OnContinuationStart(header);
}

void FramePartsCollectorListener::OnContinuationEnd() {
  QUICHE_VLOG(1) << "OnContinuationEnd";
  EndFrame()->OnContinuationEnd();
}

void FramePartsCollectorListener::OnPadLength(size_t pad_length) {
  QUICHE_VLOG(1) << "OnPadLength: " << pad_length;
  CurrentFrame()->OnPadLength(pad_length);
}

void FramePartsCollectorListener::OnPadding(const char* padding,
                                            size_t skipped_length) {
  QUICHE_VLOG(1) << "OnPadding: " << skipped_length;
  CurrentFrame()->OnPadding(padding, skipped_length);
}

void FramePartsCollectorListener::OnRstStream(const Http2FrameHeader& header,
                                              Http2ErrorCode error_code) {
  QUICHE_VLOG(1) << "OnRstStream: " << header << "; error_code=" << error_code;
  StartAndEndFrame(header)->OnRstStream(header, error_code);
}

void FramePartsCollectorListener::OnSettingsStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsStart: " << header;
  EXPECT_EQ(Http2FrameType::SETTINGS, header.type) << header;
  EXPECT_EQ(Http2FrameFlag(), header.flags) << header;
  StartFrame(header)->OnSettingsStart(header);
}

void FramePartsCollectorListener::OnSetting(
    const Http2SettingFields& setting_fields) {
  QUICHE_VLOG(1) << "Http2SettingFields: setting_fields=" << setting_fields;
  CurrentFrame()->OnSetting(setting_fields);
}

void FramePartsCollectorListener::OnSettingsEnd() {
  QUICHE_VLOG(1) << "OnSettingsEnd";
  EndFrame()->OnSettingsEnd();
}

void FramePartsCollectorListener::OnSettingsAck(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsAck: " << header;
  StartAndEndFrame(header)->OnSettingsAck(header);
}

void FramePartsCollectorListener::OnPushPromiseStart(
    const Http2FrameHeader& header, const Http2PushPromiseFields& promise,
    size_t total_padding_length) {
  QUICHE_VLOG(1) << "OnPushPromiseStart header: " << header
                 << "  promise: " << promise
                 << "  total_padding_length: " << total_padding_length;
  EXPECT_EQ(Http2FrameType::PUSH_PROMISE, header.type);
  StartFrame(header)->OnPushPromiseStart(header, promise, total_padding_length);
}

void FramePartsCollectorListener::OnPushPromiseEnd() {
  QUICHE_VLOG(1) << "OnPushPromiseEnd";
  EndFrame()->OnPushPromiseEnd();
}

void FramePartsCollectorListener::OnPing(const Http2FrameHeader& header,
                                         const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPing: " << header << "; " << ping;
  StartAndEndFrame(header)->OnPing(header, ping);
}

void FramePartsCollectorListener::OnPingAck(const Http2FrameHeader& header,
                                            const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPingAck: " << header << "; " << ping;
  StartAndEndFrame(header)->OnPingAck(header, ping);
}

void FramePartsCollectorListener::OnGoAwayStart(
    const Http2FrameHeader& header, const Http2GoAwayFields& goaway) {
  QUICHE_VLOG(1) << "OnGoAwayStart header: " << header
                 << "; goaway: " << goaway;
  StartFrame(header)->OnGoAwayStart(header, goaway);
}

void FramePartsCollectorListener::OnGoAwayOpaqueData(const char* data,
                                                     size_t len) {
  QUICHE_VLOG(1) << "OnGoAwayOpaqueData: len=" << len;
  CurrentFrame()->OnGoAwayOpaqueData(data, len);
}

void FramePartsCollectorListener::OnGoAwayEnd() {
  QUICHE_VLOG(1) << "OnGoAwayEnd";
  EndFrame()->OnGoAwayEnd();
}

void FramePartsCollectorListener::OnWindowUpdate(
    const Http2FrameHeader& header, uint32_t window_size_increment) {
  QUICHE_VLOG(1) << "OnWindowUpdate: " << header
                 << "; window_size_increment=" << window_size_increment;
  EXPECT_EQ(Http2FrameType::WINDOW_UPDATE, header.type);
  StartAndEndFrame(header)->OnWindowUpdate(header, window_size_increment);
}

void FramePartsCollectorListener::OnAltSvcStart(const Http2FrameHeader& header,
                                                size_t origin_length,
                                                size_t value_length) {
  QUICHE_VLOG(1) << "OnAltSvcStart header: " << header
                 << "; origin_length=" << origin_length
                 << "; value_length=" << value_length;
  StartFrame(header)->OnAltSvcStart(header, origin_length, value_length);
}

void FramePartsCollectorListener::OnAltSvcOriginData(const char* data,
                                                     size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcOriginData: len=" << len;
  CurrentFrame()->OnAltSvcOriginData(data, len);
}

void FramePartsCollectorListener::OnAltSvcValueData(const char* data,
                                                    size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcValueData: len=" << len;
  CurrentFrame()->OnAltSvcValueData(data, len);
}

void FramePartsCollectorListener::OnAltSvcEnd() {
  QUICHE_VLOG(1) << "OnAltSvcEnd";
  EndFrame()->OnAltSvcEnd();
}

void FramePartsCollectorListener::OnPriorityUpdateStart(
    const Http2FrameHeader& header,
    const Http2PriorityUpdateFields& priority_update) {
  QUICHE_VLOG(1) << "OnPriorityUpdateStart header: " << header
                 << "; priority_update=" << priority_update;
  StartFrame(header)->OnPriorityUpdateStart(header, priority_update);
}

void FramePartsCollectorListener::OnPriorityUpdatePayload(const char* data,
                                                          size_t len) {
  QUICHE_VLOG(1) << "OnPriorityUpdatePayload: len=" << len;
  CurrentFrame()->OnPriorityUpdatePayload(data, len);
}

void FramePartsCollectorListener::OnPriorityUpdateEnd() {
  QUICHE_VLOG(1) << "OnPriorityUpdateEnd";
  EndFrame()->OnPriorityUpdateEnd();
}

void FramePartsCollectorListener::OnUnknownStart(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnUnknownStart: " << header;
  StartFrame(header)->OnUnknownStart(header);
}

void FramePartsCollectorListener::OnUnknownPayload(const char* data,
                                                   size_t len) {
  QUICHE_VLOG(1) << "OnUnknownPayload: len=" << len;
  CurrentFrame()->OnUnknownPayload(data, len);
}

void FramePartsCollectorListener::OnUnknownEnd() {
  QUICHE_VLOG(1) << "OnUnknownEnd";
  EndFrame()->OnUnknownEnd();
}

void FramePartsCollectorListener::OnPaddingTooLong(
    const Http2FrameHeader& header, size_t missing_length) {
  QUICHE_VLOG(1) << "OnPaddingTooLong: " << header
                 << "    missing_length: " << missing_length;
  EndFrame()->OnPaddingTooLong(header, missing_length);
}

void FramePartsCollectorListener::OnFrameSizeError(
    const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnFrameSizeError: " << header;
  FrameError(header)->OnFrameSizeError(header);
}

}  // namespace test
}  // namespace http2
```