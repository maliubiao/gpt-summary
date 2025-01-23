Response:
My thought process to analyze the `frame_parts.cc` file and answer the prompt's questions went through these stages:

1. **Understand the Core Purpose:** I first read the file headers and the class definition of `FrameParts`. The comments and the inheritance from `Http2FrameDecoderListener` immediately suggested that this class is designed for *testing* and *verifying* the parsing of HTTP/2 frames. It acts as a sink for the output of an HTTP/2 frame decoder, allowing tests to check if the decoder correctly identified the different parts of a frame.

2. **Identify Key Data Members:** I scanned the class definition for its member variables. These variables (e.g., `frame_header_`, `payload_`, `padding_`, `settings_`, and various optional fields) represent the different components of an HTTP/2 frame. This confirmed the class's role in capturing the parsed frame data.

3. **Analyze Public Methods:** I looked at the public methods of the `FrameParts` class.
    * Constructors: How is an instance of this class created? It can be created with a header, or a header and payload, or a header, payload, and padding length. This suggests different scenarios it can handle.
    * `VerifyEquals()`: This method is clearly for comparison, indicating its use in assertions within tests.
    * `SetTotalPadLength()` and `SetAltSvcExpected()`: These are setter methods for specific frame components, allowing test setup.
    * Overridden `Http2FrameDecoderListener` methods (`OnDataStart`, `OnDataPayload`, etc.): These are the *key* methods. They show how the `FrameParts` object *receives* the parsed components of a frame from a decoder. The `QUICHE_VLOG` calls and `ASSERT_*` macros within these methods further reinforce the testing/verification purpose.

4. **Infer Functionality from Listener Methods:** I meticulously examined each of the overridden `Http2FrameDecoderListener` methods. I paid attention to:
    * The HTTP/2 frame type each method corresponds to (e.g., `OnDataStart` for DATA frames).
    * What data the method receives as input (e.g., `const char* data, size_t len` for payload).
    * How the method stores the received data in the `FrameParts` object's member variables.
    * The assertions (`ASSERT_*`) used within the methods. These provide clues about the expected behavior and invariants.

5. **Address Specific Prompt Questions:** With a good understanding of the file's purpose and functionality, I then addressed each part of the prompt:

    * **Functionality:** I summarized the core purpose as a testing tool for verifying HTTP/2 frame parsing. I listed the key functionalities like storing frame parts and providing comparison methods.
    * **Relationship to JavaScript:** I considered how HTTP/2 frames relate to web browsers. JavaScript interacts with the network stack indirectly through browser APIs like `fetch`. The browser's network stack (which includes Chromium's implementation) handles HTTP/2. Therefore, while this C++ code isn't *directly* JavaScript, it's *instrumental* in enabling HTTP/2 functionality that JavaScript relies on. I gave examples of how JavaScript initiating a `fetch` might result in different HTTP/2 frames being generated and how `FrameParts` could be used to test the parsing of those frames.
    * **Logical Reasoning (Input/Output):** I chose a simple DATA frame as an example. I provided hypothetical input data (header and payload) and described how the `FrameParts` object would store this information. This illustrated the step-by-step processing.
    * **Common Usage Errors:**  I focused on the assertions within the code. The most obvious error is incorrect frame formatting leading to parsing errors detected by the assertions (e.g., incorrect payload length, padding issues). I also mentioned the potential for tests to make incorrect assumptions about frame structure.
    * **User Operation and Debugging:**  I traced a user action (clicking a link) down to the generation of HTTP/2 frames within the browser. I explained how `FrameParts` could be used during debugging to inspect the structure of these frames and pinpoint issues in frame construction or parsing.

6. **Refine and Organize:** Finally, I reviewed my answers, ensuring clarity, accuracy, and a logical flow. I used formatting (like bullet points) to improve readability. I made sure to connect the technical details of the code back to the user's perspective and the role of JavaScript in web interactions.

Essentially, I approached the task like reverse-engineering a component. I started with the broad purpose, then drilled down into the details of the code, and finally connected those details back to the bigger picture of web communication and testing. The presence of test-related keywords and assertions was a major indicator of the file's primary function.

这个文件 `net/third_party/quiche/src/quiche/http2/test_tools/frame_parts.cc` 是 Chromium 网络栈中 QUIC 协议的 HTTP/2 实现部分的一个测试工具。它的主要功能是：

**主要功能：**

1. **作为 HTTP/2 帧解码器的监听器（Listener）：** `FrameParts` 类实现了 `Http2FrameDecoderListener` 接口的所有方法。这意味着它可以接收和记录 HTTP/2 帧解码器在解析帧时产生的各种事件和数据片段。

2. **存储和表示 HTTP/2 帧的各个部分：**  它使用成员变量来存储帧头 (`frame_header_`)、有效载荷 (`payload_`)、填充 (`padding_`) 以及其他特定帧类型的字段（例如，优先级信息、GOAWAY 帧的错误码、SETTINGS 帧的设置等）。

3. **提供帧内容的比对功能：** `VerifyEquals()` 方法允许比较两个 `FrameParts` 对象的内容，用于在测试中验证解码后的帧是否与预期一致。

4. **辅助 HTTP/2 帧解码器的单元测试：** 通过实例化 `FrameParts` 对象并将其注册为 `Http2FrameDecoder` 的监听器，测试代码可以驱动解码器解析一段字节流，然后检查 `FrameParts` 对象中记录的帧信息是否正确。

**与 JavaScript 的关系：**

`FrameParts` 本身是用 C++ 编写的，与 JavaScript 没有直接的代码层面的联系。然而，它在 Chromium 浏览器网络栈中扮演着关键的测试角色，而网络栈负责处理浏览器与服务器之间的 HTTP/2 通信。当 JavaScript 代码发起网络请求（例如，使用 `fetch` API 或 `XMLHttpRequest`）时，浏览器底层的网络栈会构建和解析 HTTP/2 帧。`FrameParts` 可以用来测试网络栈中 HTTP/2 帧的解析逻辑是否正确。

**举例说明：**

假设 JavaScript 代码发起一个简单的 GET 请求：

```javascript
fetch('https://example.com/data');
```

在浏览器底层，网络栈可能会构建一个 HTTP/2 HEADERS 帧来发送这个请求。`FrameParts` 可以用于测试当接收到服务器响应的 HEADERS 帧时，解码器是否正确解析了帧头、首部块以及可能的填充。

例如，可以创建一个 `FrameParts` 对象，并将其作为监听器传递给 HTTP/2 解码器，然后让解码器处理一段包含服务器响应 HEADERS 帧的字节流。之后，可以使用 `VerifyEquals()` 方法将 `FrameParts` 对象中记录的信息与预期的帧结构进行比较，以验证解码器的正确性。

**逻辑推理 (假设输入与输出):**

假设我们有一个包含 HTTP/2 DATA 帧的字节流，其帧头和有效载荷如下：

**假设输入 (字节流)：**

```
00 00 0a  // Length: 10 bytes
00        // Type: DATA (0x00)
00        // Flags: 0x00
00 00 00 05 // Stream Identifier: 5
48 65 6c 6c 6f 20 77 6f 72 6c 64 // Payload: "Hello world" (10 bytes)
```

**测试代码可能如下：**

```c++
Http2FrameHeader header(10, Http2FrameType::DATA, 0x00, 5);
FrameParts expected_frame(header, "Hello world");
FrameParts actual_frame(header);
Http2FrameDecoder decoder(&actual_frame);
decoder.ProcessBytes("\x00\x00\x0a\x00\x00\x00\x00\x05Hello world");
EXPECT_TRUE(actual_frame.VerifyEquals(expected_frame));
```

**预期输出 (存储在 `actual_frame` 对象中)：**

* `frame_header_`:  `Http2FrameHeader(length=10, type=DATA, flags=0x00, stream_id=5)`
* `payload_`: `"Hello world"`
* `opt_payload_length_`: `10`

**用户或编程常见的使用错误：**

1. **未正确设置期望的帧头信息：**  在创建 `FrameParts` 对象时，如果提供的 `Http2FrameHeader` 与实际要解析的帧头不匹配，会导致比对失败。

   ```c++
   // 错误示例：帧长度设置错误
   Http2FrameHeader incorrect_header(5, Http2FrameType::DATA, 0x00, 5);
   FrameParts frame(incorrect_header, "Hello");
   ```

2. **假设帧的顺序或内容：** 当处理连续的帧流时，测试代码需要正确处理每个帧，并且不能假设帧的特定顺序或内容，除非这是测试的明确目标。

3. **忽略帧的标志位：** HTTP/2 帧的标志位会影响帧的解析方式。例如，设置了 `END_STREAM` 标志的 DATA 帧表示数据流的结束。测试代码需要考虑到这些标志位。

4. **处理填充不当：** 如果帧包含填充，解码器需要正确解析填充长度和填充数据。`FrameParts` 提供了 `SetTotalPadLength` 方法来模拟带有填充的帧，测试代码需要正确使用。

   ```c++
   // 假设一个带有 5 字节填充的 DATA 帧
   Http2FrameHeader padded_header(15, Http2FrameType::DATA, 0x08, 5); // 0x08 表示 PADDED 标志
   FrameParts padded_frame(padded_header, "Hello", 5); // "Hello" 是有效载荷，5 是总填充长度
   ```

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问一个使用了 HTTP/2 协议的网站，并遇到了页面加载问题。以下是可能导致调试人员查看 `frame_parts.cc` 的步骤：

1. **用户操作：** 用户在 Chrome 浏览器中输入网址 `https://example.com` 并按下回车键。

2. **网络请求发起：** 浏览器开始建立与 `example.com` 服务器的连接。如果服务器支持 HTTP/2，浏览器会进行协议升级或直接建立 HTTP/2 连接。

3. **HTTP/2 帧的发送和接收：**
   * 浏览器可能会发送 HEADERS 帧来请求页面资源。
   * 服务器可能会发送 SETTINGS 帧、HEADERS 帧（包含响应头）、DATA 帧（包含页面内容）等。

4. **网络栈处理：** Chrome 的网络栈接收到这些 HTTP/2 帧，并使用 `Http2FrameDecoder` 来解析它们。

5. **解码错误或异常：** 如果服务器发送的帧格式错误，或者 `Http2FrameDecoder` 的解析逻辑存在 bug，可能会导致解码错误或异常。

6. **调试过程：**
   * **开发者工具：** 用户或开发者可能会打开 Chrome 的开发者工具，查看 "Network" 标签页，可能会看到请求失败或者状态异常。
   * **抓包分析：** 开发人员可能会使用 Wireshark 等工具抓取网络包，查看实际发送和接收的 HTTP/2 帧的原始字节。
   * **代码调试：** Chromium 的开发人员可能会在网络栈的代码中设置断点，跟踪 HTTP/2 帧的解析过程。
   * **查看 `frame_parts.cc`：** 如果怀疑是 HTTP/2 帧的解析逻辑有问题，开发人员可能会查看 `frame_parts.cc` 相关的单元测试代码，或者使用类似的测试工具来模拟接收到的错误帧，并验证解码器的行为。`frame_parts.cc` 中的 `VerifyEquals` 方法可以帮助他们比对实际解析出的帧结构与预期结构，从而定位问题。

总之，`frame_parts.cc` 是 Chromium 中 HTTP/2 功能测试的关键组成部分。虽然普通用户不会直接接触到这个文件，但它确保了浏览器能够正确地处理 HTTP/2 通信，从而保证用户能够正常浏览使用 HTTP/2 协议的网站。当出现网络问题时，开发人员可能会利用这个文件提供的工具进行调试和问题定位。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/test_tools/frame_parts.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/http2/test_tools/frame_parts.h"

#include <optional>
#include <ostream>
#include <string>
#include <type_traits>

#include "absl/strings/escaping.h"
#include "quiche/http2/test_tools/http2_structures_test_util.h"
#include "quiche/http2/test_tools/verify_macros.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using ::testing::AssertionFailure;
using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using ::testing::ContainerEq;

namespace http2 {
namespace test {
namespace {

static_assert(std::is_base_of<Http2FrameDecoderListener, FrameParts>::value &&
                  !std::is_abstract<FrameParts>::value,
              "FrameParts needs to implement all of the methods of "
              "Http2FrameDecoderListener");

// Compare two optional variables of the same type.
// TODO(jamessynge): Maybe create a ::testing::Matcher for this.
template <class T>
AssertionResult VerifyOptionalEq(const T& opt_a, const T& opt_b) {
  if (opt_a) {
    if (opt_b) {
      HTTP2_VERIFY_EQ(opt_a.value(), opt_b.value());
    } else {
      return AssertionFailure()
             << "opt_b is not set; opt_a.value()=" << opt_a.value();
    }
  } else if (opt_b) {
    return AssertionFailure()
           << "opt_a is not set; opt_b.value()=" << opt_b.value();
  }
  return AssertionSuccess();
}

}  // namespace

FrameParts::FrameParts(const Http2FrameHeader& header) : frame_header_(header) {
  QUICHE_VLOG(1) << "FrameParts, header: " << frame_header_;
}

FrameParts::FrameParts(const Http2FrameHeader& header,
                       absl::string_view payload)
    : FrameParts(header) {
  QUICHE_VLOG(1) << "FrameParts with payload.size() = " << payload.size();
  this->payload_.append(payload.data(), payload.size());
  opt_payload_length_ = payload.size();
}
FrameParts::FrameParts(const Http2FrameHeader& header,
                       absl::string_view payload, size_t total_pad_length)
    : FrameParts(header, payload) {
  QUICHE_VLOG(1) << "FrameParts with total_pad_length=" << total_pad_length;
  SetTotalPadLength(total_pad_length);
}

FrameParts::FrameParts(const FrameParts& header) = default;

FrameParts::~FrameParts() = default;

AssertionResult FrameParts::VerifyEquals(const FrameParts& that) const {
#define COMMON_MESSAGE "\n  this: " << *this << "\n  that: " << that

  HTTP2_VERIFY_EQ(frame_header_, that.frame_header_) << COMMON_MESSAGE;
  HTTP2_VERIFY_EQ(payload_, that.payload_) << COMMON_MESSAGE;
  HTTP2_VERIFY_EQ(padding_, that.padding_) << COMMON_MESSAGE;
  HTTP2_VERIFY_EQ(altsvc_origin_, that.altsvc_origin_) << COMMON_MESSAGE;
  HTTP2_VERIFY_EQ(altsvc_value_, that.altsvc_value_) << COMMON_MESSAGE;
  HTTP2_VERIFY_EQ(settings_, that.settings_) << COMMON_MESSAGE;

#define HTTP2_VERIFY_OPTIONAL_FIELD(field_name) \
  HTTP2_VERIFY_SUCCESS(VerifyOptionalEq(field_name, that.field_name))

  HTTP2_VERIFY_OPTIONAL_FIELD(opt_altsvc_origin_length_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_altsvc_value_length_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_priority_update_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_goaway_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_missing_length_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_pad_length_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_ping_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_priority_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_push_promise_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_rst_stream_error_code_) << COMMON_MESSAGE;
  HTTP2_VERIFY_OPTIONAL_FIELD(opt_window_update_increment_) << COMMON_MESSAGE;

#undef HTTP2_VERIFY_OPTIONAL_FIELD

  return AssertionSuccess();
}

void FrameParts::SetTotalPadLength(size_t total_pad_length) {
  opt_pad_length_.reset();
  padding_.clear();
  if (total_pad_length > 0) {
    ASSERT_LE(total_pad_length, 256u);
    ASSERT_TRUE(frame_header_.IsPadded());
    opt_pad_length_ = total_pad_length - 1;
    char zero = 0;
    padding_.append(opt_pad_length_.value(), zero);
  }

  if (opt_pad_length_) {
    QUICHE_VLOG(1) << "SetTotalPadLength: pad_length="
                   << opt_pad_length_.value();
  } else {
    QUICHE_VLOG(1) << "SetTotalPadLength: has no pad length";
  }
}

void FrameParts::SetAltSvcExpected(absl::string_view origin,
                                   absl::string_view value) {
  altsvc_origin_.append(origin.data(), origin.size());
  altsvc_value_.append(value.data(), value.size());
  opt_altsvc_origin_length_ = origin.size();
  opt_altsvc_value_length_ = value.size();
}

bool FrameParts::OnFrameHeader(const Http2FrameHeader& /*header*/) {
  ADD_FAILURE() << "OnFrameHeader: " << *this;
  return true;
}

void FrameParts::OnDataStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnDataStart: " << header;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::DATA)) << *this;
  opt_payload_length_ = header.payload_length;
}

void FrameParts::OnDataPayload(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnDataPayload: len=" << len
                 << "; frame_header_: " << frame_header_;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::DATA)) << *this;
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &payload_,
                           &opt_payload_length_));
}

void FrameParts::OnDataEnd() {
  QUICHE_VLOG(1) << "OnDataEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::DATA)) << *this;
}

void FrameParts::OnHeadersStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnHeadersStart: " << header;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::HEADERS)) << *this;
  opt_payload_length_ = header.payload_length;
}

void FrameParts::OnHeadersPriority(const Http2PriorityFields& priority) {
  QUICHE_VLOG(1) << "OnHeadersPriority: priority: " << priority
                 << "; frame_header_: " << frame_header_;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::HEADERS)) << *this;
  ASSERT_FALSE(opt_priority_);
  opt_priority_ = priority;
  ASSERT_TRUE(opt_payload_length_);
  opt_payload_length_ =
      opt_payload_length_.value() - Http2PriorityFields::EncodedSize();
}

void FrameParts::OnHpackFragment(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnHpackFragment: len=" << len
                 << "; frame_header_: " << frame_header_;
  ASSERT_TRUE(got_start_callback_);
  ASSERT_FALSE(got_end_callback_);
  ASSERT_TRUE(FrameCanHaveHpackPayload(frame_header_)) << *this;
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &payload_,
                           &opt_payload_length_));
}

void FrameParts::OnHeadersEnd() {
  QUICHE_VLOG(1) << "OnHeadersEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::HEADERS)) << *this;
}

void FrameParts::OnPriorityFrame(const Http2FrameHeader& header,
                                 const Http2PriorityFields& priority) {
  QUICHE_VLOG(1) << "OnPriorityFrame: " << header << "; priority: " << priority;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::PRIORITY)) << *this;
  ASSERT_FALSE(opt_priority_);
  opt_priority_ = priority;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::PRIORITY)) << *this;
}

void FrameParts::OnContinuationStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnContinuationStart: " << header;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::CONTINUATION)) << *this;
  opt_payload_length_ = header.payload_length;
}

void FrameParts::OnContinuationEnd() {
  QUICHE_VLOG(1) << "OnContinuationEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::CONTINUATION)) << *this;
}

void FrameParts::OnPadLength(size_t trailing_length) {
  QUICHE_VLOG(1) << "OnPadLength: trailing_length=" << trailing_length;
  ASSERT_TRUE(InPaddedFrame()) << *this;
  ASSERT_FALSE(opt_pad_length_);
  ASSERT_TRUE(opt_payload_length_);
  size_t total_padding_length = trailing_length + 1;
  ASSERT_GE(opt_payload_length_.value(), total_padding_length);
  opt_payload_length_ = opt_payload_length_.value() - total_padding_length;
  opt_pad_length_ = trailing_length;
}

void FrameParts::OnPadding(const char* pad, size_t skipped_length) {
  QUICHE_VLOG(1) << "OnPadding: skipped_length=" << skipped_length;
  ASSERT_TRUE(InPaddedFrame()) << *this;
  ASSERT_TRUE(opt_pad_length_);
  ASSERT_TRUE(AppendString(absl::string_view(pad, skipped_length), &padding_,
                           &opt_pad_length_));
}

void FrameParts::OnRstStream(const Http2FrameHeader& header,
                             Http2ErrorCode error_code) {
  QUICHE_VLOG(1) << "OnRstStream: " << header << "; code=" << error_code;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::RST_STREAM)) << *this;
  ASSERT_FALSE(opt_rst_stream_error_code_);
  opt_rst_stream_error_code_ = error_code;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::RST_STREAM)) << *this;
}

void FrameParts::OnSettingsStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsStart: " << header;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::SETTINGS)) << *this;
  ASSERT_EQ(0u, settings_.size());
  ASSERT_FALSE(header.IsAck()) << header;
}

void FrameParts::OnSetting(const Http2SettingFields& setting_fields) {
  QUICHE_VLOG(1) << "OnSetting: " << setting_fields;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::SETTINGS)) << *this;
  settings_.push_back(setting_fields);
}

void FrameParts::OnSettingsEnd() {
  QUICHE_VLOG(1) << "OnSettingsEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::SETTINGS)) << *this;
}

void FrameParts::OnSettingsAck(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnSettingsAck: " << header;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::SETTINGS)) << *this;
  ASSERT_EQ(0u, settings_.size());
  ASSERT_TRUE(header.IsAck());
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::SETTINGS)) << *this;
}

void FrameParts::OnPushPromiseStart(const Http2FrameHeader& header,
                                    const Http2PushPromiseFields& promise,
                                    size_t total_padding_length) {
  QUICHE_VLOG(1) << "OnPushPromiseStart header: " << header
                 << "; promise: " << promise
                 << "; total_padding_length: " << total_padding_length;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::PUSH_PROMISE)) << *this;
  ASSERT_GE(header.payload_length, Http2PushPromiseFields::EncodedSize());
  opt_payload_length_ =
      header.payload_length - Http2PushPromiseFields::EncodedSize();
  ASSERT_FALSE(opt_push_promise_);
  opt_push_promise_ = promise;
  if (total_padding_length > 0) {
    ASSERT_GE(opt_payload_length_.value(), total_padding_length);
    OnPadLength(total_padding_length - 1);
  } else {
    ASSERT_FALSE(header.IsPadded());
  }
}

void FrameParts::OnPushPromiseEnd() {
  QUICHE_VLOG(1) << "OnPushPromiseEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::PUSH_PROMISE)) << *this;
}

void FrameParts::OnPing(const Http2FrameHeader& header,
                        const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPing header: " << header << "   ping: " << ping;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::PING)) << *this;
  ASSERT_FALSE(header.IsAck());
  ASSERT_FALSE(opt_ping_);
  opt_ping_ = ping;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::PING)) << *this;
}

void FrameParts::OnPingAck(const Http2FrameHeader& header,
                           const Http2PingFields& ping) {
  QUICHE_VLOG(1) << "OnPingAck header: " << header << "   ping: " << ping;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::PING)) << *this;
  ASSERT_TRUE(header.IsAck());
  ASSERT_FALSE(opt_ping_);
  opt_ping_ = ping;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::PING)) << *this;
}

void FrameParts::OnGoAwayStart(const Http2FrameHeader& header,
                               const Http2GoAwayFields& goaway) {
  QUICHE_VLOG(1) << "OnGoAwayStart: " << goaway;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::GOAWAY)) << *this;
  ASSERT_FALSE(opt_goaway_);
  opt_goaway_ = goaway;
  opt_payload_length_ =
      header.payload_length - Http2GoAwayFields::EncodedSize();
}

void FrameParts::OnGoAwayOpaqueData(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnGoAwayOpaqueData: len=" << len;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::GOAWAY)) << *this;
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &payload_,
                           &opt_payload_length_));
}

void FrameParts::OnGoAwayEnd() {
  QUICHE_VLOG(1) << "OnGoAwayEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::GOAWAY)) << *this;
}

void FrameParts::OnWindowUpdate(const Http2FrameHeader& header,
                                uint32_t increment) {
  QUICHE_VLOG(1) << "OnWindowUpdate header: " << header
                 << "     increment=" << increment;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::WINDOW_UPDATE)) << *this;
  ASSERT_FALSE(opt_window_update_increment_);
  opt_window_update_increment_ = increment;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::WINDOW_UPDATE)) << *this;
}

void FrameParts::OnAltSvcStart(const Http2FrameHeader& header,
                               size_t origin_length, size_t value_length) {
  QUICHE_VLOG(1) << "OnAltSvcStart: " << header
                 << "    origin_length: " << origin_length
                 << "    value_length: " << value_length;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::ALTSVC)) << *this;
  ASSERT_FALSE(opt_altsvc_origin_length_);
  opt_altsvc_origin_length_ = origin_length;
  ASSERT_FALSE(opt_altsvc_value_length_);
  opt_altsvc_value_length_ = value_length;
}

void FrameParts::OnAltSvcOriginData(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcOriginData: len=" << len;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::ALTSVC)) << *this;
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &altsvc_origin_,
                           &opt_altsvc_origin_length_));
}

void FrameParts::OnAltSvcValueData(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnAltSvcValueData: len=" << len;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::ALTSVC)) << *this;
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &altsvc_value_,
                           &opt_altsvc_value_length_));
}

void FrameParts::OnAltSvcEnd() {
  QUICHE_VLOG(1) << "OnAltSvcEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::ALTSVC)) << *this;
}

void FrameParts::OnPriorityUpdateStart(
    const Http2FrameHeader& header,
    const Http2PriorityUpdateFields& priority_update) {
  QUICHE_VLOG(1) << "OnPriorityUpdateStart: " << header
                 << "    prioritized_stream_id: "
                 << priority_update.prioritized_stream_id;
  ASSERT_TRUE(StartFrameOfType(header, Http2FrameType::PRIORITY_UPDATE))
      << *this;
  ASSERT_FALSE(opt_priority_update_);
  opt_priority_update_ = priority_update;
  opt_payload_length_ =
      header.payload_length - Http2PriorityUpdateFields::EncodedSize();
}

void FrameParts::OnPriorityUpdatePayload(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnPriorityUpdatePayload: len=" << len;
  ASSERT_TRUE(InFrameOfType(Http2FrameType::PRIORITY_UPDATE)) << *this;
  payload_.append(data, len);
}

void FrameParts::OnPriorityUpdateEnd() {
  QUICHE_VLOG(1) << "OnPriorityUpdateEnd; frame_header_: " << frame_header_;
  ASSERT_TRUE(EndFrameOfType(Http2FrameType::PRIORITY_UPDATE)) << *this;
}

void FrameParts::OnUnknownStart(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnUnknownStart: " << header;
  ASSERT_FALSE(IsSupportedHttp2FrameType(header.type)) << header;
  ASSERT_FALSE(got_start_callback_);
  ASSERT_EQ(frame_header_, header);
  got_start_callback_ = true;
  opt_payload_length_ = header.payload_length;
}

void FrameParts::OnUnknownPayload(const char* data, size_t len) {
  QUICHE_VLOG(1) << "OnUnknownPayload: len=" << len;
  ASSERT_FALSE(IsSupportedHttp2FrameType(frame_header_.type)) << *this;
  ASSERT_TRUE(got_start_callback_);
  ASSERT_FALSE(got_end_callback_);
  ASSERT_TRUE(AppendString(absl::string_view(data, len), &payload_,
                           &opt_payload_length_));
}

void FrameParts::OnUnknownEnd() {
  QUICHE_VLOG(1) << "OnUnknownEnd; frame_header_: " << frame_header_;
  ASSERT_FALSE(IsSupportedHttp2FrameType(frame_header_.type)) << *this;
  ASSERT_TRUE(got_start_callback_);
  ASSERT_FALSE(got_end_callback_);
  got_end_callback_ = true;
}

void FrameParts::OnPaddingTooLong(const Http2FrameHeader& header,
                                  size_t missing_length) {
  QUICHE_VLOG(1) << "OnPaddingTooLong: " << header
                 << "; missing_length: " << missing_length;
  ASSERT_EQ(frame_header_, header);
  ASSERT_FALSE(got_end_callback_);
  ASSERT_TRUE(FrameIsPadded(header));
  ASSERT_FALSE(opt_pad_length_);
  ASSERT_FALSE(opt_missing_length_);
  opt_missing_length_ = missing_length;
  got_start_callback_ = true;
  got_end_callback_ = true;
}

void FrameParts::OnFrameSizeError(const Http2FrameHeader& header) {
  QUICHE_VLOG(1) << "OnFrameSizeError: " << header;
  ASSERT_EQ(frame_header_, header);
  ASSERT_FALSE(got_end_callback_);
  ASSERT_FALSE(has_frame_size_error_);
  has_frame_size_error_ = true;
  got_end_callback_ = true;
}

void FrameParts::OutputTo(std::ostream& out) const {
  out << "FrameParts{\n  frame_header_: " << frame_header_ << "\n";
  if (!payload_.empty()) {
    out << "  payload_=\"" << absl::CHexEscape(payload_) << "\"\n";
  }
  if (!padding_.empty()) {
    out << "  padding_=\"" << absl::CHexEscape(padding_) << "\"\n";
  }
  if (!altsvc_origin_.empty()) {
    out << "  altsvc_origin_=\"" << absl::CHexEscape(altsvc_origin_) << "\"\n";
  }
  if (!altsvc_value_.empty()) {
    out << "  altsvc_value_=\"" << absl::CHexEscape(altsvc_value_) << "\"\n";
  }
  if (opt_priority_) {
    out << "  priority=" << opt_priority_.value() << "\n";
  }
  if (opt_rst_stream_error_code_) {
    out << "  rst_stream=" << opt_rst_stream_error_code_.value() << "\n";
  }
  if (opt_push_promise_) {
    out << "  push_promise=" << opt_push_promise_.value() << "\n";
  }
  if (opt_ping_) {
    out << "  ping=" << opt_ping_.value() << "\n";
  }
  if (opt_goaway_) {
    out << "  goaway=" << opt_goaway_.value() << "\n";
  }
  if (opt_window_update_increment_) {
    out << "  window_update=" << opt_window_update_increment_.value() << "\n";
  }
  if (opt_payload_length_) {
    out << "  payload_length=" << opt_payload_length_.value() << "\n";
  }
  if (opt_pad_length_) {
    out << "  pad_length=" << opt_pad_length_.value() << "\n";
  }
  if (opt_missing_length_) {
    out << "  missing_length=" << opt_missing_length_.value() << "\n";
  }
  if (opt_altsvc_origin_length_) {
    out << "  origin_length=" << opt_altsvc_origin_length_.value() << "\n";
  }
  if (opt_altsvc_value_length_) {
    out << "  value_length=" << opt_altsvc_value_length_.value() << "\n";
  }
  if (opt_priority_update_) {
    out << "  prioritized_stream_id_=" << opt_priority_update_.value() << "\n";
  }
  if (has_frame_size_error_) {
    out << "  has_frame_size_error\n";
  }
  if (got_start_callback_) {
    out << "  got_start_callback\n";
  }
  if (got_end_callback_) {
    out << "  got_end_callback\n";
  }
  for (size_t ndx = 0; ndx < settings_.size(); ++ndx) {
    out << "  setting[" << ndx << "]=" << settings_[ndx];
  }
  out << "}";
}

AssertionResult FrameParts::StartFrameOfType(
    const Http2FrameHeader& header, Http2FrameType expected_frame_type) {
  HTTP2_VERIFY_EQ(header.type, expected_frame_type);
  HTTP2_VERIFY_FALSE(got_start_callback_);
  HTTP2_VERIFY_FALSE(got_end_callback_);
  HTTP2_VERIFY_EQ(frame_header_, header);
  got_start_callback_ = true;
  return AssertionSuccess();
}

AssertionResult FrameParts::InFrameOfType(Http2FrameType expected_frame_type) {
  HTTP2_VERIFY_TRUE(got_start_callback_);
  HTTP2_VERIFY_FALSE(got_end_callback_);
  HTTP2_VERIFY_EQ(frame_header_.type, expected_frame_type);
  return AssertionSuccess();
}

AssertionResult FrameParts::EndFrameOfType(Http2FrameType expected_frame_type) {
  HTTP2_VERIFY_SUCCESS(InFrameOfType(expected_frame_type));
  got_end_callback_ = true;
  return AssertionSuccess();
}

AssertionResult FrameParts::InPaddedFrame() {
  HTTP2_VERIFY_TRUE(got_start_callback_);
  HTTP2_VERIFY_FALSE(got_end_callback_);
  HTTP2_VERIFY_TRUE(FrameIsPadded(frame_header_));
  return AssertionSuccess();
}

AssertionResult FrameParts::AppendString(absl::string_view source,
                                         std::string* target,
                                         std::optional<size_t>* opt_length) {
  target->append(source.data(), source.size());
  if (opt_length != nullptr) {
    HTTP2_VERIFY_TRUE(*opt_length) << "Length is not set yet\n" << *this;
    HTTP2_VERIFY_LE(target->size(), opt_length->value())
        << "String too large; source.size() = " << source.size() << "\n"
        << *this;
  }
  return ::testing::AssertionSuccess();
}

std::ostream& operator<<(std::ostream& out, const FrameParts& v) {
  v.OutputTo(out);
  return out;
}

}  // namespace test
}  // namespace http2
```