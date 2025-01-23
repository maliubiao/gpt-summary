Response:
Let's break down the thought process for analyzing the `alps_decoder_test.cc` file.

1. **Understand the Core Purpose:** The filename `alps_decoder_test.cc` immediately suggests this file contains unit tests for a component named `AlpsDecoder`. The `.cc` extension indicates C++ source code. Knowing this is a *test* file is crucial; it's not the implementation itself.

2. **Examine Includes:**  The `#include` directives tell us about the dependencies and what functionalities are being tested:
    * `"net/spdy/alps_decoder.h"`: This confirms the file tests the `AlpsDecoder` class defined in this header.
    * `"base/test/metrics/histogram_tester.h"`:  Indicates testing of metrics recording, likely related to errors or usage statistics.
    * `"base/test/scoped_feature_list.h"`:  Shows that the tests involve enabling/disabling features, likely for A/B testing or experimental functionality.
    * `"net/base/features.h"`:  Confirms the use of feature flags within the `net` namespace.
    * `"net/base/hex_utils.h"`:  Suggests the tests involve parsing or manipulating data represented in hexadecimal format.
    * `"testing/gmock/include/gmock/gmock.h"` and `"testing/gtest/include/gtest/gtest.h"`: These are the standard Google Test and Google Mock frameworks, confirming this is a unit test file.

3. **Identify Key Classes and Functions Under Test:** The primary class being tested is `AlpsDecoder`. The test cases call its `Decode()` method and then assert the state of the decoder using methods like `GetAcceptCh()`, `GetSettings()`, and `settings_frame_count()`. This tells us what aspects of the `AlpsDecoder` are important: decoding, extracting Accept-CH headers, extracting settings, and tracking the number of settings frames.

4. **Analyze Individual Test Cases:** Go through each `TEST()` macro and understand its goal:
    * `EmptyInput`: Tests decoding an empty input.
    * `EmptyAcceptChFrame`: Tests decoding an empty ACCEPT_CH frame.
    * `EmptySettingsFrame`: Tests decoding an empty SETTINGS frame.
    * `ParseSettingsAndAcceptChFrames`: Tests decoding both types of frames together.
    * `ParseLargeAcceptChFrame`: Tests handling a large ACCEPT_CH frame.
    * `DisableAlpsParsing` and `DisableAlpsClientHintParsing`: Test the behavior when specific feature flags are disabled.
    * `IncompleteFrame`: Tests handling an incomplete frame.
    * `TwoSettingsFrames`: Tests processing multiple SETTINGS frames.
    * `AcceptChOnInvalidStream`, `AcceptChWithInvalidFlags`, `SettingsOnInvalidStream`, `SettingsAck`, `SettingsWithInvalidFlags`: Test error conditions related to frame headers and stream IDs.
    * `ForbiddenFrame`: Tests handling frames that are not allowed.
    * `UnknownFrame`: Tests handling frames with unknown types.
    * `MalformedAcceptChFrame` (within `AlpsDecoderTestWithFeature`): Tests the behavior when an ACCEPT_CH frame's payload is malformed, and whether a feature flag affects this behavior.

5. **Infer Functionality of `AlpsDecoder`:** Based on the test cases, we can infer that `AlpsDecoder` is responsible for:
    * Parsing a stream of bytes representing ALPS frames (likely a subset of HTTP/2 frames).
    * Identifying and extracting ACCEPT_CH frames, including the origin and associated values.
    * Identifying and extracting SETTINGS frames, including identifiers and values.
    * Handling various error conditions, such as malformed frames, invalid stream IDs, and incorrect flags.
    * Potentially interacting with feature flags to enable/disable certain parsing behaviors.
    * Keeping track of the number of settings frames.

6. **Consider the Relationship to JavaScript:** The `Accept-CH` header is relevant to web development and is often interacted with via JavaScript. Think about how JavaScript might be affected by this C++ code:
    * If the C++ decoder fails to parse an `Accept-CH` header correctly, the information won't be available to the browser's JavaScript APIs.
    *  JavaScript code running on a website might use APIs like `navigator.clientHints.get` (or similar, depending on the specific hint) to access client hint values advertised via `Accept-CH`. If the parsing is broken, these APIs might return incorrect or no data.

7. **Develop Hypothetical Input/Output Examples:** For tests that parse data (like `ParseSettingsAndAcceptChFrames`), it's easy to extract the input (the hex-encoded frame data) and the expected output (the content of `GetAcceptCh()` and `GetSettings()`). For error cases, the input is the malformed frame, and the output is the specific `AlpsDecoder::Error` enum value.

8. **Identify Potential User/Programming Errors:**  Think about how a developer interacting with ALPS or implementing similar protocols might make mistakes:
    * Incorrectly constructing ALPS frames (wrong lengths, types, flags, stream IDs).
    * Sending forbidden frame types in an ALPS context.
    * Not handling potential parsing errors on the receiving end.
    * Misunderstanding the role of feature flags in enabling/disabling ALPS functionality.

9. **Trace User Actions to Reach the Code (Debugging Context):** Imagine a scenario where a developer needs to debug a problem related to `Accept-CH` headers. How might they end up looking at `alps_decoder_test.cc`?
    * A website isn't receiving the client hints it expects.
    * The browser's network logs show an error related to ALPS or HTTP/2 frame parsing.
    * A Chromium developer is working on the network stack and needs to understand how ALPS frame decoding works.
    * They might search the codebase for "AlpsDecoder" or "Accept-CH" and find this test file as a way to understand the expected behavior and how to test their own changes.

10. **Structure the Answer:** Organize the findings into logical sections (functionality, relationship to JavaScript, input/output, user errors, debugging). Use clear and concise language. Provide specific examples from the code.

By following these steps, we can effectively analyze the given C++ test file and extract the necessary information to answer the user's request comprehensively.
这是 Chromium 网络栈中 `net/spdy/alps_decoder_test.cc` 文件的内容。这个文件包含了对 `AlpsDecoder` 类的单元测试。`AlpsDecoder` 的作用是解析 ALPS (Application-Layer Protocol Settings) 帧，这些帧在 HTTP/2 连接建立时用于协商和传递一些连接级别的设置，特别是与客户端提示 (Client Hints) 相关的 `ACCEPT_CH` 帧和通用的 `SETTINGS` 帧。

以下是该文件的功能总结：

**1. 测试 `AlpsDecoder` 的基本功能：**

* **解码空输入:** 测试当输入为空时，解码器是否能正常工作，并且不返回任何 `ACCEPT_CH` 或 `SETTINGS`。
* **解码空的 `ACCEPT_CH` 帧:** 测试解码一个内容为空的 `ACCEPT_CH` 帧是否会正确解析，并且不产生任何 `ACCEPT_CH` 条目。
* **解码空的 `SETTINGS` 帧:** 测试解码一个内容为空的 `SETTINGS` 帧是否会正确解析，并增加 `settings_frame_count`。

**2. 测试解析 `ACCEPT_CH` 和 `SETTINGS` 帧：**

* **解析 `ACCEPT_CH` 帧:** 测试解码包含 `ACCEPT_CH` 信息的帧，验证是否能正确提取出 origin 和对应的 value。可以测试解析多个 origin-value 对。
* **解析 `SETTINGS` 帧:** 测试解码包含 `SETTINGS` 的帧，验证是否能正确提取出 identifier 和 value。可以测试解析多个 setting。
* **同时解析 `ACCEPT_CH` 和 `SETTINGS` 帧:** 测试在一个输入流中同时包含 `ACCEPT_CH` 和 `SETTINGS` 帧时，解码器是否能正确解析它们。

**3. 测试处理大型 `ACCEPT_CH` 帧：**

* 验证解码器是否能处理长度较大的 `ACCEPT_CH` 帧。

**4. 测试禁用 ALPS 解析的场景：**

* 使用 Feature Flags (`features::kAlpsParsing` 和 `features::kAlpsClientHintParsing`) 禁用 ALPS 解析，验证在这种情况下，即使输入包含 `ACCEPT_CH` 帧，解码器也不会解析出任何信息。

**5. 测试处理不完整的帧：**

* 验证解码器在接收到不完整的帧时，是否能返回正确的错误 (`kNotOnFrameBoundary`)。

**6. 测试处理多个 `SETTINGS` 帧：**

* 验证解码器是否能处理并记录多个 `SETTINGS` 帧。

**7. 测试处理带有无效 Stream ID 或 Flags 的 `ACCEPT_CH` 和 `SETTINGS` 帧：**

* **`ACCEPT_CH` 帧：** 测试当 `ACCEPT_CH` 帧的 Stream ID 不为 0 或 Flags 不为 0 时，解码器是否会返回相应的错误 (`kAcceptChInvalidStream` 或 `kAcceptChWithFlags`)。
* **`SETTINGS` 帧：** 测试当 `SETTINGS` 帧的 Stream ID 不为 0 时，解码器是否会返回错误 (`kFramingError`)。
* **`SETTINGS` 帧的 ACK 标志：** 测试当接收到带有 ACK 标志的 `SETTINGS` 帧时，解码器是否会返回错误 (`kSettingsWithAck`)，因为 ALPS 解码器不应该接收到 ACK。
* **`SETTINGS` 帧的无效 Flags:**  虽然规范允许忽略未定义的 flags，但这里也进行了测试，预期是不会报错 (`kNoError`)。

**8. 测试处理禁止的帧类型：**

* 验证解码器在接收到 ALPS 上下文不允许的帧类型 (例如 `DATA` 帧) 时，是否会返回错误 (`kForbiddenFrame`)。

**9. 测试处理未知的帧类型：**

* 验证解码器在接收到未知的帧类型时，是否会忽略它并且不报错 (`kNoError`)。

**10. 基于 Feature Flag 的行为测试 (Malformed `ACCEPT_CH` Frame)：**

* 使用 Feature Flag (`features::kShouldKillSessionOnAcceptChMalformed`) 控制当 `ACCEPT_CH` 帧格式错误时，是直接报错 (`kAcceptChMalformed`) 还是忽略并继续处理 (`kNoError`)。这通常用于灰度发布和兼容性处理。

**与 JavaScript 的关系：**

该文件直接测试的是 C++ 代码，但其功能直接影响浏览器如何处理服务器发送的关于客户端提示的信息。

* **`ACCEPT_CH` 帧:**  服务器通过 `ACCEPT_CH` 帧告知浏览器它可以接受哪些客户端提示。例如，服务器可能发送一个 `ACCEPT_CH` 帧，指示它接受 `Sec-CH-UA-Mobile` 和 `Sec-CH-Viewport-Width` 客户端提示。
* **JavaScript API:**  浏览器解析 `ACCEPT_CH` 帧后，会将这些信息暴露给 JavaScript。开发者可以使用 JavaScript API（例如 `navigator.userAgentData.getHighEntropyValues()`）来获取相应的客户端提示值，并根据服务器的需求进行发送。

**举例说明：**

假设服务器发送了以下 `ACCEPT_CH` 帧（十六进制表示）：

```
00001d  // length
89      // type ACCEPT_CH
00      // flags
00000000 // stream ID
000a     // origin length (10)
68747470733a2f2f6578616d706c652e636f6d // "https://example.com"
0008     // value length (8)
6465766963652d6d6f64656c // "device-model"
```

`AlpsDecoder` 会解析这段数据，并将其转化为：

```
GetAcceptCh() == { {"https://example.com", "device-model"} }
```

然后，当 JavaScript 代码运行在 `https://example.com` 下时，可以使用类似下面的代码来获取 `device-model` 客户端提示（假设浏览器支持）：

```javascript
navigator.userAgentData.getHighEntropyValues(['device-model'])
  .then(data => {
    console.log(data['device-model']);
    // 将 device-model 发送给服务器
  });
```

如果 `AlpsDecoder` 解析失败，那么 `navigator.userAgentData.getHighEntropyValues(['device-model'])` 将无法正常工作，或者服务器要求的客户端提示信息不会被正确传递。

**逻辑推理的假设输入与输出：**

**假设输入 (HexDecoded String):**

```
"000025" // length
"89"     // type ACCEPT_CH
"00"     // flags
"00000000" // stream ID
"0008"     // origin length
"6578616d706c652e6f7267" // "example.org"
"0003"     // value length
"637075"     // "cpu"
"0009"     // origin length
"7375622e6578616d706c652e6f7267" // "sub.example.org"
"0004"     // value length
"6d656d"     // "mem"
```

**预期输出:**

```
decoder.GetAcceptCh() == {
  {"https://example.org", "cpu"},
  {"https://sub.example.org", "mem"}
}
```

**涉及用户或编程常见的使用错误：**

* **服务器配置错误:**  服务器可能错误地配置了发送的 `ACCEPT_CH` 帧，例如长度字段不正确，或者包含了非法的字符。`AlpsDecoder` 的测试覆盖了这些错误情况，例如 `MalformedAcceptChFrame` 测试。
* **中间件或代理问题:**  网络中间件或代理可能错误地修改了 ALPS 帧，导致浏览器解析失败。
* **浏览器实现错误:**  虽然 `alps_decoder_test.cc` 是在测试浏览器的实现，但如果 `AlpsDecoder` 本身存在 bug，那么即使服务器配置正确，浏览器也无法正确处理 `ACCEPT_CH` 信息。
* **Feature Flag 状态错误:**  在开发或测试环境中，如果 Feature Flags 的状态与预期不符，可能会导致 ALPS 解析被禁用，从而影响客户端提示的功能。

**用户操作如何一步步地到达这里，作为调试线索：**

假设用户发现某个网站的客户端提示功能不工作。调试过程可能如下：

1. **用户访问网站:** 用户在浏览器中输入网址并访问该网站。
2. **浏览器发送请求:** 浏览器向服务器发送 HTTP 请求。
3. **服务器响应包含 `ACCEPT_CH` 帧:** 服务器在 HTTP/2 连接的早期阶段（通常是连接建立时）发送包含 `ACCEPT_CH` 信息的 ALPS 帧。
4. **网络栈接收 ALPS 帧:** Chromium 的网络栈接收到这些二进制数据。
5. **`AlpsDecoder` 解析帧:** `AlpsDecoder` 类负责解析接收到的 ALPS 帧。
6. **测试失败或异常:** 如果 `ACCEPT_CH` 帧格式错误，或者 `AlpsDecoder` 存在 bug，解析过程可能会失败。

**作为调试线索，开发者可能会：**

* **抓取网络包:** 使用 Wireshark 或 Chrome 的开发者工具抓取网络包，查看服务器发送的原始 ALPS 帧数据，验证服务器是否发送了正确的 `ACCEPT_CH` 信息。
* **查看 Chrome NetLog:** Chrome 的 `chrome://net-export/` 工具可以记录详细的网络事件，包括 ALPS 帧的解析结果和错误信息。开发者可以查看 NetLog，确认 `AlpsDecoder` 是否成功解析了 `ACCEPT_CH` 帧，如果失败，可以查看具体的错误代码。
* **运行单元测试:** 如果怀疑 `AlpsDecoder` 存在 bug，开发者可以运行 `alps_decoder_test.cc` 中的单元测试，验证 `AlpsDecoder` 在各种场景下的行为是否符合预期。如果某个测试失败，说明 `AlpsDecoder` 的实现可能存在问题。
* **断点调试:** 在 `AlpsDecoder::Decode` 方法中设置断点，逐步跟踪代码执行过程，查看解析过程中哪里出现了问题，例如长度计算错误、类型判断错误等。

总而言之，`alps_decoder_test.cc` 通过各种测试用例，确保 `AlpsDecoder` 能够正确、健壮地解析 ALPS 帧，从而保证客户端提示等基于 ALPS 的功能能够正常工作。它对于理解和调试 HTTP/2 连接建立过程中的协议协商至关重要。

### 提示词
```
这是目录为net/spdy/alps_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/alps_decoder.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/features.h"
#include "net/base/hex_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::spdy::AcceptChOriginValuePair;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Pair;

namespace net {
namespace {

TEST(AlpsDecoderTest, EmptyInput) {
  AlpsDecoder decoder;
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
  EXPECT_THAT(decoder.GetSettings(), IsEmpty());
  EXPECT_EQ(0, decoder.settings_frame_count());

  AlpsDecoder::Error error = decoder.Decode({});
  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);

  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
  EXPECT_THAT(decoder.GetSettings(), IsEmpty());
  EXPECT_EQ(0, decoder.settings_frame_count());
}

TEST(AlpsDecoderTest, EmptyAcceptChFrame) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000000"       // length
                               "89"           // type ACCEPT_CH
                               "00"           // flags
                               "00000000"));  // stream ID

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
  EXPECT_THAT(decoder.GetSettings(), IsEmpty());
  EXPECT_EQ(0, decoder.settings_frame_count());
}

TEST(AlpsDecoderTest, EmptySettingsFrame) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000000"       // length
                               "04"           // type SETTINGS
                               "00"           // flags
                               "00000000"));  // stream ID

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
  EXPECT_THAT(decoder.GetSettings(), IsEmpty());
  EXPECT_EQ(1, decoder.settings_frame_count());
}

TEST(AlpsDecoderTest, ParseSettingsAndAcceptChFrames) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(HexDecode(
      // ACCEPT_CH frame
      "00003d"                    // length
      "89"                        // type ACCEPT_CH
      "00"                        // flags
      "00000000"                  // stream ID
      "0017"                      // origin length
      "68747470733a2f2f7777772e"  //
      "6578616d706c652e636f6d"    // origin "https://www.example.com"
      "0003"                      // value length
      "666f6f"                    // value "foo"
      "0018"                      // origin length
      "68747470733a2f2f6d61696c"  //
      "2e6578616d706c652e636f6d"  // origin "https://mail.example.com"
      "0003"                      // value length
      "626172"                    // value "bar"
      // SETTINGS frame
      "00000c"       // length
      "04"           // type
      "00"           // flags
      "00000000"     // stream ID
      "0dab"         // identifier
      "01020304"     // value
      "1234"         // identifier
      "fedcba98"));  // value

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(
      decoder.GetAcceptCh(),
      ElementsAre(AcceptChOriginValuePair{"https://www.example.com", "foo"},
                  AcceptChOriginValuePair{"https://mail.example.com", "bar"}));
  EXPECT_THAT(decoder.GetSettings(),
              ElementsAre(Pair(0x0dab, 0x01020304), Pair(0x1234, 0xfedcba98)));
  EXPECT_EQ(1, decoder.settings_frame_count());
}

TEST(AlpsDecoderTest, ParseLargeAcceptChFrame) {
  std::string frame = HexDecode(
      // ACCEPT_CH frame
      "0001ab"                    // length: 427 total bytes
      "89"                        // type ACCEPT_CH
      "00"                        // flags
      "00000000"                  // stream ID
      "0017"                      // origin length
      "68747470733a2f2f7777772e"  //
      "6578616d706c652e636f6d"    // origin "https://www.example.com"
      "0190"                      // value length (400 in hex)
  );

  // The Accept-CH tokens payload is a string of 400 'x' characters.
  const std::string accept_ch_tokens(400, 'x');
  // Append the value bytes to the frame.
  frame += accept_ch_tokens;

  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(frame);

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(),
              ElementsAre(AcceptChOriginValuePair{"https://www.example.com",
                                                  accept_ch_tokens}));
}

TEST(AlpsDecoderTest, DisableAlpsParsing) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(features::kAlpsParsing);
  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(HexDecode(
      // ACCEPT_CH frame
      "00003d"                    // length
      "89"                        // type ACCEPT_CH
      "00"                        // flags
      "00000000"                  // stream ID
      "0017"                      // origin length
      "68747470733a2f2f7777772e"  //
      "6578616d706c652e636f6d"    // origin "https://www.example.com"
      "0003"                      // value length
      "666f6f"                    // value "foo"
      "0018"                      // origin length
      "68747470733a2f2f6d61696c"  //
      "2e6578616d706c652e636f6d"  // origin "https://mail.example.com"
      "0003"                      // value length
      "626172"                    // value "bar"
      ));

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
}

TEST(AlpsDecoderTest, DisableAlpsClientHintParsing) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(features::kAlpsClientHintParsing);
  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(HexDecode(
      // ACCEPT_CH frame
      "00003d"                    // length
      "89"                        // type ACCEPT_CH
      "00"                        // flags
      "00000000"                  // stream ID
      "0017"                      // origin length
      "68747470733a2f2f7777772e"  //
      "6578616d706c652e636f6d"    // origin "https://www.example.com"
      "0003"                      // value length
      "666f6f"                    // value "foo"
      "0018"                      // origin length
      "68747470733a2f2f6d61696c"  //
      "2e6578616d706c652e636f6d"  // origin "https://mail.example.com"
      "0003"                      // value length
      "626172"                    // value "bar"
      ));

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
}

TEST(AlpsDecoderTest, IncompleteFrame) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("00000c"    // length
                               "04"        // type
                               "00"        // flags
                               "00000000"  // stream ID
                               "0dab"      // identifier
                               "01"));     // first byte of value

  EXPECT_EQ(AlpsDecoder::Error::kNotOnFrameBoundary, error);
}

TEST(AlpsDecoderTest, TwoSettingsFrames) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000006"       // length
                               "04"           // type SETTINGS
                               "00"           // flags
                               "00000000"     // stream ID
                               "0dab"         // identifier
                               "01020304"     // value
                               "000006"       // length
                               "04"           // type SETTINGS
                               "00"           // flags
                               "00000000"     // stream ID
                               "1234"         // identifier
                               "fedcba98"));  // value

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_EQ(2, decoder.settings_frame_count());
  EXPECT_THAT(decoder.GetSettings(),
              ElementsAre(Pair(0x0dab, 0x01020304), Pair(0x1234, 0xfedcba98)));
}

TEST(AlpsDecoderTest, AcceptChOnInvalidStream) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(
      HexDecode("00001e"                    // length
                "89"                        // type ACCEPT_CH
                "00"                        // flags
                "00000001"                  // invalid stream ID: should be zero
                "0017"                      // origin length
                "68747470733a2f2f7777772e"  //
                "6578616d706c652e636f6d"    // origin "https://www.example.com"
                "0003"                      // value length
                "666f6f"));                 // value "foo"

  EXPECT_EQ(AlpsDecoder::Error::kAcceptChInvalidStream, error);
}

// According to
// https://davidben.github.io/http-client-hint-reliability/ \
// draft-davidben-http-client-hint-reliability.html#name-http-2-accept_ch-frame
// "If a user agent receives an ACCEPT_CH frame whose stream [...] flags
// field is non-zero, it MUST respond with a connection error [...]."
TEST(AlpsDecoderTest, AcceptChWithInvalidFlags) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error = decoder.Decode(
      HexDecode("00001e"                    // length
                "89"                        // type ACCEPT_CH
                "02"                        // invalid flags: should be zero
                "00000000"                  // stream ID
                "0017"                      // origin length
                "68747470733a2f2f7777772e"  //
                "6578616d706c652e636f6d"    // origin "https://www.example.com"
                "0003"                      // value length
                "666f6f"));                 // value "foo"

  EXPECT_EQ(AlpsDecoder::Error::kAcceptChWithFlags, error);
}

TEST(AlpsDecoderTest, SettingsOnInvalidStream) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000006"    // length
                               "04"        // type SETTINGS
                               "00"        // flags
                               "00000001"  // invalid stream ID: should be zero
                               "1234"      // identifier
                               "fedcba98"));  // value

  EXPECT_EQ(AlpsDecoder::Error::kFramingError, error);
}

TEST(AlpsDecoderTest, SettingsAck) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000000"       // length
                               "04"           // type SETTINGS
                               "01"           // ACK flag
                               "00000000"));  // stream ID

  EXPECT_EQ(AlpsDecoder::Error::kSettingsWithAck, error);
}

// According to https://httpwg.org/specs/rfc7540.html#FrameHeader:
// "Flags that have no defined semantics for a particular frame type MUST be
// ignored [...]"
TEST(AlpsDecoderTest, SettingsWithInvalidFlags) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000006"       // length
                               "04"           // type SETTINGS
                               "02"           // invalid flag
                               "00000000"     // stream ID
                               "1234"         // identifier
                               "fedcba98"));  // value

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
}

TEST(AlpsDecoderTest, ForbiddenFrame) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000003"     // length
                               "00"         // frame type DATA
                               "01"         // flags END_STREAM
                               "00000001"   // stream ID
                               "666f6f"));  // payload "foo"

  EXPECT_EQ(AlpsDecoder::Error::kForbiddenFrame, error);
}

TEST(AlpsDecoderTest, UnknownFrame) {
  AlpsDecoder decoder;
  AlpsDecoder::Error error =
      decoder.Decode(HexDecode("000003"     // length
                               "2a"         // unknown frame type
                               "ff"         // flags
                               "00000008"   // stream ID
                               "666f6f"));  // payload "foo"

  EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
  EXPECT_THAT(decoder.GetAcceptCh(), IsEmpty());
  EXPECT_THAT(decoder.GetSettings(), IsEmpty());
  EXPECT_EQ(0, decoder.settings_frame_count());
}

class AlpsDecoderTestWithFeature : public ::testing::TestWithParam<bool> {
 public:
  bool ShouldKillSessionOnAcceptChMalformed() { return GetParam(); }

 private:
  void SetUp() override {
    feature_list_.InitWithFeatureState(
        features::kShouldKillSessionOnAcceptChMalformed,
        ShouldKillSessionOnAcceptChMalformed());
  }

  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All, AlpsDecoderTestWithFeature, testing::Bool());

TEST_P(AlpsDecoderTestWithFeature, MalformedAcceptChFrame) {
  // Correct, complete payload.
  std::string payload = HexDecode(
      "0017"  // origin length
      "68747470733a2f2f7777772e"
      "6578616d706c652e636f6d"  // origin "https://www.example.com"
      "0003"                    // value length
      "666f6f");                // value "foo"

  for (uint8_t payload_length = 1; payload_length < payload.length();
       payload_length++) {
    base::HistogramTester histogram_tester;
    // First two bytes of length.
    std::string frame = HexDecode("0000");
    // Last byte of length.
    frame.push_back(static_cast<char>(payload_length));

    frame.append(
        HexDecode("89"           // type ACCEPT_CH
                  "00"           // flags
                  "00000000"));  // stream ID
    // Incomplete, malformed payload.
    frame.append(payload.data(), payload_length);

    AlpsDecoder decoder;
    AlpsDecoder::Error error = decoder.Decode(frame);
    if (ShouldKillSessionOnAcceptChMalformed()) {
      EXPECT_EQ(AlpsDecoder::Error::kAcceptChMalformed, error);
      histogram_tester.ExpectUniqueSample(
          "Net.SpdySession.AlpsDecoderStatus.Bypassed",
          static_cast<int>(AlpsDecoder::Error::kNoError), 1);
    } else {
      EXPECT_EQ(AlpsDecoder::Error::kNoError, error);
      histogram_tester.ExpectUniqueSample(
          "Net.SpdySession.AlpsDecoderStatus.Bypassed",
          static_cast<int>(AlpsDecoder::Error::kAcceptChMalformed), 1);
    }
  }
}

}  // namespace
}  // namespace net
```