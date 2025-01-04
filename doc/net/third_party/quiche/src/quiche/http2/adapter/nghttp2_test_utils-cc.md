Response:
Let's break down the thought process for analyzing this C++ test utility file.

1. **Understand the Context:** The file path `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_test_utils.cc` immediately tells us a few key things:
    * It's related to networking (`net`).
    * It uses the QUIC implementation (`quiche`).
    * It specifically deals with HTTP/2 (`http2`).
    * It's part of an adapter layer (`adapter`), suggesting it bridges between different implementations.
    * It contains "test utils", meaning it's for writing tests, not core functionality.
    * It mentions `nghttp2`, a popular C library for HTTP/2. This strongly suggests this file provides tools for testing interactions with `nghttp2`.

2. **High-Level Goal:**  The primary goal of test utilities is to make writing tests easier and more readable. They often provide abstractions and specialized matchers for common testing scenarios.

3. **Scanning for Key Elements:**  I would quickly scan the code for significant keywords and patterns:
    * `#include`:  Confirms dependencies (nghttp2, gMock).
    * `namespace`: Organizes the code. The nested namespaces `http2::adapter::test` reinforce the purpose.
    * Class names ending in "Matcher": This is a strong indicator that the file is defining custom gMock matchers. gMock matchers are the core of expressive assertions in C++ tests.
    * Specific frame types (e.g., `NGHTTP2_DATA`, `NGHTTP2_HEADERS`, `NGHTTP2_SETTINGS`):  This tells us the file is about verifying the structure and content of HTTP/2 frames.
    * `DescribeTo`, `DescribeNegationTo`, `MatchAndExplain`: These are standard methods in gMock matchers.
    * Function names starting with "Is" or "Has":  These are common naming conventions for gMock matcher factory functions.

4. **Analyzing the Matchers:**  For each matcher class, I would analyze:
    * **What it matches:** The class name (e.g., `FrameHeaderMatcher`, `DataMatcher`) gives a good clue.
    * **Constructor arguments:**  These reveal what properties of the HTTP/2 frame can be checked (stream ID, type, flags, length, padding, error codes, etc.).
    * **The `MatchAndExplain` method:** This is the heart of the matcher. It compares the actual `nghttp2_frame` data with the expected values provided in the constructor. The use of `listener` is for providing detailed error messages when the match fails.

5. **Connecting to `nghttp2`:**  The matchers directly work with `nghttp2_frame` and `nghttp2_frame_hd` structures. This confirms the file's role in testing interactions with the `nghttp2` library.

6. **Considering JavaScript Relevance:**  The prompt specifically asks about JavaScript. Here's the thought process:
    * **Direct interaction:** This C++ code doesn't directly run in a JavaScript environment.
    * **Indirect relationship:**  Chromium's network stack (where this code resides) is responsible for handling network requests made by JavaScript code running in the browser.
    * **Testing the foundation:** These test utilities are used to ensure the underlying C++ HTTP/2 implementation is correct. If this implementation is buggy, it *will* affect JavaScript network requests.
    * **Example:** A JavaScript `fetch()` request might result in HTTP/2 frames being sent and received. These utilities would be used in C++ tests to verify that those frames are correctly formed according to the HTTP/2 specification. The connection is indirect but crucial.

7. **Logical Reasoning (Hypothetical Input/Output):** For a matcher like `IsData`, consider:
    * **Input:** An `nghttp2_frame*` pointer.
    * **Matcher parameters:** Specific stream ID, length, flags, and padding values that the test expects.
    * **Output:** The `MatchAndExplain` method returns `true` if the frame matches the expectations, and `false` otherwise. The `listener` accumulates error messages.

8. **Common Usage Errors:** Think about how a developer might misuse these utilities:
    * **Incorrect matcher parameters:**  Providing the wrong stream ID or frame type to a matcher.
    * **Misunderstanding flags:**  Forgetting to OR together multiple flags or using the wrong flag.
    * **Using the wrong matcher:**  Trying to use `IsData` on a `HEADERS` frame.

9. **Debugging Scenario:** How would a developer end up looking at this file during debugging?
    * **Reported network issues:**  A user reports a website not loading correctly, or data being corrupted.
    * **Developer investigation:**  The developer suspects an issue with HTTP/2 handling in Chromium.
    * **Code inspection:** The developer might look at the code responsible for sending and receiving HTTP/2 frames. When writing or debugging tests for that code, they would likely encounter these utility functions.
    * **Test failures:**  If a test using these matchers fails, the developer would examine the matcher's error messages and then potentially look at the matcher's implementation to understand why the assertion failed.

10. **Structuring the Answer:** Finally, organize the findings into a clear and structured response, covering the requested points: functionality, JavaScript relevance, logical reasoning, common errors, and debugging scenarios. Use clear language and examples.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_test_utils.cc` 是 Chromium 网络栈中用于测试 HTTP/2 适配器功能的实用工具代码。它提供了一系列自定义的 gMock 匹配器，用于方便地断言 `nghttp2` 库生成的 HTTP/2 帧的特定属性。

**主要功能:**

1. **自定义 gMock 匹配器:**  该文件定义了多个 gMock 匹配器，可以检查 `nghttp2_frame` 结构体的各种字段，例如：
   - **帧头 (Frame Header):**  检查帧的 `stream_id` (流 ID), `type` (类型), 和 `flags` (标志)。
   - **DATA 帧:** 检查流 ID、数据长度、标志以及 padding 长度。
   - **HEADERS 帧:** 检查流 ID、标志以及 HEADERS 类别。
   - **RST_STREAM 帧:** 检查流 ID 和错误码。
   - **SETTINGS 帧:** 检查 SETTINGS 帧中包含的设置项及其值。
   - **PING 帧:** 检查 PING 帧的 opaque data (ID) 以及是否是 ACK。
   - **GOAWAY 帧:** 检查最后一个流 ID、错误码以及 opaque data。
   - **WINDOW_UPDATE 帧:** 检查窗口大小增量。

2. **简化 HTTP/2 帧的断言:**  通过使用这些匹配器，测试代码可以更简洁、更易读地验证 `nghttp2` 库生成的 HTTP/2 帧是否符合预期。例如，无需手动比较 `frame->hd.stream_id` 等字段，可以直接使用 `EXPECT_THAT(frame, IsData(1, _, _, _));` 来断言这是一个流 ID 为 1 的 DATA 帧。

**与 JavaScript 的关系:**

虽然此文件是用 C++ 编写的，但它对 JavaScript 的功能有间接但重要的关系。

- **底层网络支持:** Chromium 的网络栈（包括此文件所在的 HTTP/2 适配器）负责处理浏览器中 JavaScript 代码发起的网络请求。当 JavaScript 使用 `fetch()` API 或 `XMLHttpRequest` 发起 HTTP/2 请求时，底层的 C++ 代码会负责构建和解析 HTTP/2 帧。
- **测试底层实现:** 此文件中的测试工具用于验证底层 C++ HTTP/2 适配器的正确性。如果适配器有 bug，可能会导致 JavaScript 发起的网络请求失败或行为异常。
- **示例:** 假设一个 JavaScript 应用发起了一个 `fetch()` 请求，服务器返回了一个带有特定头部信息的 HTTP/2 响应。为了测试 Chromium 的 HTTP/2 适配器是否正确解析了这个响应头，相关的 C++ 测试代码可能会使用 `IsHeaders` 匹配器来断言接收到的 `nghttp2_frame` 结构体包含了预期的流 ID 和标志。

**逻辑推理 (假设输入与输出):**

假设我们有一个测试函数，模拟 `nghttp2` 库生成了一个 HEADERS 帧：

**假设输入:**

```c++
nghttp2_frame frame;
frame.hd.type = NGHTTP2_HEADERS;
frame.hd.stream_id = 3;
frame.hd.flags = NGHTTP2_FLAG_END_HEADERS;
frame.headers.cat = NGHTTP2_HCAT_RESPONSE;
```

**使用 `IsHeaders` 匹配器:**

```c++
EXPECT_THAT(&frame, http2::adapter::test::IsHeaders(3, NGHTTP2_FLAG_END_HEADERS, NGHTTP2_HCAT_RESPONSE));
```

**预期输出:**  如果 `frame` 的属性与 `IsHeaders` 匹配器的参数一致（流 ID 为 3，标志包含 `NGHTTP2_FLAG_END_HEADERS`，类别为 `NGHTTP2_HCAT_RESPONSE`），则断言通过，不会有输出。如果属性不一致，gMock 会输出详细的错误信息，指出哪个字段不匹配以及期望值和实际值。

**涉及用户或编程常见的使用错误:**

1. **错误地使用匹配器参数:**
   - **错误示例:**  希望断言一个 DATA 帧的流 ID 为 5，但错误地写成 `EXPECT_THAT(frame, IsData(6, _, _, _));`。
   - **后果:** 测试会失败，因为实际的流 ID 与期望的流 ID 不符。
2. **忘记包含必要的头文件:** 如果测试代码中使用了这些匹配器，但忘记包含 `nghttp2_test_utils.h`，会导致编译错误。
3. **对帧类型理解错误:**  例如，试图使用 `IsData` 匹配器来断言一个 HEADERS 帧，会导致匹配失败并产生误导性的错误信息。
4. **标志位的误用:** HTTP/2 的帧标志位通常是多个标志的组合。如果只想检查某个特定标志是否设置，需要使用 gMock 的匹配器组合，例如 `testing::HasFlag(NGHTTP2_FLAG_END_STREAM)`. 直接比较可能会出错。
   - **错误示例:**  假设期望标志位包含 `NGHTTP2_FLAG_END_STREAM`，但错误地写成 `EXPECT_THAT(frame, HasFrameHeader(..., NGHTTP2_FLAG_END_STREAM));`，如果还有其他标志位被设置，这个断言就会失败。应该使用 `EXPECT_THAT(frame, HasFrameHeader(..., testing::HasFlag(NGHTTP2_FLAG_END_STREAM)));`

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户报告网络问题:** 用户在使用 Chromium 浏览器时遇到网页加载缓慢、部分内容缺失或连接错误等问题。
2. **开发人员调查:** Chromium 开发人员开始调查这些网络问题，怀疑可能是 HTTP/2 的实现存在 bug。
3. **定位到 HTTP/2 适配器:** 开发人员可能会查看 Chromium 中负责处理 HTTP/2 连接的代码，这会涉及到 `net/` 目录下的相关文件，包括 `quiche/http2/adapter/`。
4. **查看测试代码:** 为了理解 HTTP/2 适配器的行为以及如何进行测试，开发人员会查看相关的测试代码，这些测试代码会使用 `nghttp2_test_utils.cc` 中定义的匹配器。
5. **调试测试用例:** 如果测试用例失败，开发人员会仔细检查测试代码中使用的匹配器以及被测试代码的逻辑，以找出问题所在。
6. **查看匹配器实现:**  如果对某个匹配器的行为有疑问，或者需要添加新的匹配逻辑，开发人员会查看 `nghttp2_test_utils.cc` 文件的源代码，了解匹配器的具体实现方式。
7. **分析 `nghttp2` 库的交互:** 开发人员可能会需要理解 Chromium 的 HTTP/2 适配器是如何与底层的 `nghttp2` 库交互的，以及 `nghttp2` 库生成的帧结构是什么样的。`nghttp2_test_utils.cc` 文件提供了检查这些帧结构的工具。

总而言之，`net/third_party/quiche/src/quiche/http2/adapter/nghttp2_test_utils.cc` 是 Chromium 网络栈中一个关键的测试辅助文件，它通过提供自定义的 gMock 匹配器，极大地简化了对 HTTP/2 帧的断言，确保了底层 HTTP/2 实现的正确性，从而间接地保障了用户 JavaScript 代码发起的网络请求的可靠性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_test_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/http2/adapter/nghttp2_test_utils.h"

#include <cstring>
#include <ostream>
#include <vector>

#include "quiche/http2/adapter/nghttp2_util.h"
#include "quiche/common/quiche_endian.h"

namespace http2 {
namespace adapter {
namespace test {

namespace {

// Custom gMock matcher, used to implement HasFrameHeader().
class FrameHeaderMatcher {
 public:
  FrameHeaderMatcher(int32_t streamid, uint8_t type,
                     const testing::Matcher<int> flags)
      : stream_id_(streamid), type_(type), flags_(flags) {}

  bool Match(const nghttp2_frame_hd& frame,
             testing::MatchResultListener* listener) const {
    bool matched = true;
    if (stream_id_ != frame.stream_id) {
      *listener << "; expected stream " << stream_id_ << ", saw "
                << frame.stream_id;
      matched = false;
    }
    if (type_ != frame.type) {
      *listener << "; expected frame type " << type_ << ", saw "
                << static_cast<int>(frame.type);
      matched = false;
    }
    if (!flags_.MatchAndExplain(frame.flags, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const {
    *os << "contains a frame header with stream " << stream_id_ << ", type "
        << type_ << ", ";
    flags_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const {
    *os << "does not contain a frame header with stream " << stream_id_
        << ", type " << type_ << ", ";
    flags_.DescribeNegationTo(os);
  }

 private:
  const int32_t stream_id_;
  const int type_;
  const testing::Matcher<int> flags_;
};

class PointerToFrameHeaderMatcher
    : public FrameHeaderMatcher,
      public testing::MatcherInterface<const nghttp2_frame_hd*> {
 public:
  PointerToFrameHeaderMatcher(int32_t streamid, uint8_t type,
                              const testing::Matcher<int> flags)
      : FrameHeaderMatcher(streamid, type, flags) {}

  bool MatchAndExplain(const nghttp2_frame_hd* frame,
                       testing::MatchResultListener* listener) const override {
    return FrameHeaderMatcher::Match(*frame, listener);
  }

  void DescribeTo(std::ostream* os) const override {
    FrameHeaderMatcher::DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    FrameHeaderMatcher::DescribeNegationTo(os);
  }
};

class ReferenceToFrameHeaderMatcher
    : public FrameHeaderMatcher,
      public testing::MatcherInterface<const nghttp2_frame_hd&> {
 public:
  ReferenceToFrameHeaderMatcher(int32_t streamid, uint8_t type,
                                const testing::Matcher<int> flags)
      : FrameHeaderMatcher(streamid, type, flags) {}

  bool MatchAndExplain(const nghttp2_frame_hd& frame,
                       testing::MatchResultListener* listener) const override {
    return FrameHeaderMatcher::Match(frame, listener);
  }

  void DescribeTo(std::ostream* os) const override {
    FrameHeaderMatcher::DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    FrameHeaderMatcher::DescribeNegationTo(os);
  }
};

class DataMatcher : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  DataMatcher(const testing::Matcher<uint32_t> stream_id,
              const testing::Matcher<size_t> length,
              const testing::Matcher<int> flags,
              const testing::Matcher<size_t> padding)
      : stream_id_(stream_id),
        length_(length),
        flags_(flags),
        padding_(padding) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_DATA) {
      *listener << "; expected DATA frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    bool matched = true;
    if (!stream_id_.MatchAndExplain(frame->hd.stream_id, listener)) {
      matched = false;
    }
    if (!length_.MatchAndExplain(frame->hd.length, listener)) {
      matched = false;
    }
    if (!flags_.MatchAndExplain(frame->hd.flags, listener)) {
      matched = false;
    }
    if (!padding_.MatchAndExplain(frame->data.padlen, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a DATA frame, ";
    stream_id_.DescribeTo(os);
    length_.DescribeTo(os);
    flags_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a DATA frame, ";
    stream_id_.DescribeNegationTo(os);
    length_.DescribeNegationTo(os);
    flags_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint32_t> stream_id_;
  const testing::Matcher<size_t> length_;
  const testing::Matcher<int> flags_;
  const testing::Matcher<size_t> padding_;
};

class HeadersMatcher : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  HeadersMatcher(const testing::Matcher<uint32_t> stream_id,
                 const testing::Matcher<int> flags,
                 const testing::Matcher<int> category)
      : stream_id_(stream_id), flags_(flags), category_(category) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_HEADERS) {
      *listener << "; expected HEADERS frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    bool matched = true;
    if (!stream_id_.MatchAndExplain(frame->hd.stream_id, listener)) {
      matched = false;
    }
    if (!flags_.MatchAndExplain(frame->hd.flags, listener)) {
      matched = false;
    }
    if (!category_.MatchAndExplain(frame->headers.cat, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a HEADERS frame, ";
    stream_id_.DescribeTo(os);
    flags_.DescribeTo(os);
    category_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a HEADERS frame, ";
    stream_id_.DescribeNegationTo(os);
    flags_.DescribeNegationTo(os);
    category_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint32_t> stream_id_;
  const testing::Matcher<int> flags_;
  const testing::Matcher<int> category_;
};

class RstStreamMatcher
    : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  RstStreamMatcher(const testing::Matcher<uint32_t> stream_id,
                   const testing::Matcher<uint32_t> error_code)
      : stream_id_(stream_id), error_code_(error_code) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_RST_STREAM) {
      *listener << "; expected RST_STREAM frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    bool matched = true;
    if (!stream_id_.MatchAndExplain(frame->hd.stream_id, listener)) {
      matched = false;
    }
    if (!error_code_.MatchAndExplain(frame->rst_stream.error_code, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a RST_STREAM frame, ";
    stream_id_.DescribeTo(os);
    error_code_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a RST_STREAM frame, ";
    stream_id_.DescribeNegationTo(os);
    error_code_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint32_t> stream_id_;
  const testing::Matcher<uint32_t> error_code_;
};

class SettingsMatcher : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  SettingsMatcher(const testing::Matcher<std::vector<Http2Setting>> values)
      : values_(values) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_SETTINGS) {
      *listener << "; expected SETTINGS frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    std::vector<Http2Setting> settings;
    settings.reserve(frame->settings.niv);
    for (size_t i = 0; i < frame->settings.niv; ++i) {
      const auto& p = frame->settings.iv[i];
      settings.push_back({static_cast<uint16_t>(p.settings_id), p.value});
    }
    return values_.MatchAndExplain(settings, listener);
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a SETTINGS frame, ";
    values_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a SETTINGS frame, ";
    values_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<std::vector<Http2Setting>> values_;
};

class PingMatcher : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  PingMatcher(const testing::Matcher<uint64_t> id, bool is_ack)
      : id_(id), is_ack_(is_ack) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_PING) {
      *listener << "; expected PING frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    bool matched = true;
    bool frame_ack = frame->hd.flags & NGHTTP2_FLAG_ACK;
    if (is_ack_ != frame_ack) {
      *listener << "; expected is_ack=" << is_ack_ << ", saw " << frame_ack;
      matched = false;
    }
    uint64_t data;
    std::memcpy(&data, frame->ping.opaque_data, sizeof(data));
    data = quiche::QuicheEndian::HostToNet64(data);
    if (!id_.MatchAndExplain(data, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a PING frame, ";
    id_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a PING frame, ";
    id_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint64_t> id_;
  const bool is_ack_;
};

class GoAwayMatcher : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  GoAwayMatcher(const testing::Matcher<uint32_t> last_stream_id,
                const testing::Matcher<uint32_t> error_code,
                const testing::Matcher<absl::string_view> opaque_data)
      : last_stream_id_(last_stream_id),
        error_code_(error_code),
        opaque_data_(opaque_data) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_GOAWAY) {
      *listener << "; expected GOAWAY frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    bool matched = true;
    if (!last_stream_id_.MatchAndExplain(frame->goaway.last_stream_id,
                                         listener)) {
      matched = false;
    }
    if (!error_code_.MatchAndExplain(frame->goaway.error_code, listener)) {
      matched = false;
    }
    auto opaque_data =
        ToStringView(frame->goaway.opaque_data, frame->goaway.opaque_data_len);
    if (!opaque_data_.MatchAndExplain(opaque_data, listener)) {
      matched = false;
    }
    return matched;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a GOAWAY frame, ";
    last_stream_id_.DescribeTo(os);
    error_code_.DescribeTo(os);
    opaque_data_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a GOAWAY frame, ";
    last_stream_id_.DescribeNegationTo(os);
    error_code_.DescribeNegationTo(os);
    opaque_data_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint32_t> last_stream_id_;
  const testing::Matcher<uint32_t> error_code_;
  const testing::Matcher<absl::string_view> opaque_data_;
};

class WindowUpdateMatcher
    : public testing::MatcherInterface<const nghttp2_frame*> {
 public:
  WindowUpdateMatcher(const testing::Matcher<uint32_t> delta) : delta_(delta) {}

  bool MatchAndExplain(const nghttp2_frame* frame,
                       testing::MatchResultListener* listener) const override {
    if (frame->hd.type != NGHTTP2_WINDOW_UPDATE) {
      *listener << "; expected WINDOW_UPDATE frame, saw frame of type "
                << static_cast<int>(frame->hd.type);
      return false;
    }
    return delta_.MatchAndExplain(frame->window_update.window_size_increment,
                                  listener);
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "contains a WINDOW_UPDATE frame, ";
    delta_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "does not contain a WINDOW_UPDATE frame, ";
    delta_.DescribeNegationTo(os);
  }

 private:
  const testing::Matcher<uint32_t> delta_;
};

}  // namespace

testing::Matcher<const nghttp2_frame_hd*> HasFrameHeader(
    uint32_t streamid, uint8_t type, const testing::Matcher<int> flags) {
  return MakeMatcher(new PointerToFrameHeaderMatcher(streamid, type, flags));
}

testing::Matcher<const nghttp2_frame_hd&> HasFrameHeaderRef(
    uint32_t streamid, uint8_t type, const testing::Matcher<int> flags) {
  return MakeMatcher(new ReferenceToFrameHeaderMatcher(streamid, type, flags));
}

testing::Matcher<const nghttp2_frame*> IsData(
    const testing::Matcher<uint32_t> stream_id,
    const testing::Matcher<size_t> length, const testing::Matcher<int> flags,
    const testing::Matcher<size_t> padding) {
  return MakeMatcher(new DataMatcher(stream_id, length, flags, padding));
}

testing::Matcher<const nghttp2_frame*> IsHeaders(
    const testing::Matcher<uint32_t> stream_id,
    const testing::Matcher<int> flags, const testing::Matcher<int> category) {
  return MakeMatcher(new HeadersMatcher(stream_id, flags, category));
}

testing::Matcher<const nghttp2_frame*> IsRstStream(
    const testing::Matcher<uint32_t> stream_id,
    const testing::Matcher<uint32_t> error_code) {
  return MakeMatcher(new RstStreamMatcher(stream_id, error_code));
}

testing::Matcher<const nghttp2_frame*> IsSettings(
    const testing::Matcher<std::vector<Http2Setting>> values) {
  return MakeMatcher(new SettingsMatcher(values));
}

testing::Matcher<const nghttp2_frame*> IsPing(
    const testing::Matcher<uint64_t> id) {
  return MakeMatcher(new PingMatcher(id, false));
}

testing::Matcher<const nghttp2_frame*> IsPingAck(
    const testing::Matcher<uint64_t> id) {
  return MakeMatcher(new PingMatcher(id, true));
}

testing::Matcher<const nghttp2_frame*> IsGoAway(
    const testing::Matcher<uint32_t> last_stream_id,
    const testing::Matcher<uint32_t> error_code,
    const testing::Matcher<absl::string_view> opaque_data) {
  return MakeMatcher(
      new GoAwayMatcher(last_stream_id, error_code, opaque_data));
}

testing::Matcher<const nghttp2_frame*> IsWindowUpdate(
    const testing::Matcher<uint32_t> delta) {
  return MakeMatcher(new WindowUpdateMatcher(delta));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2

"""

```