Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Request:**

The request asks for the functionality of a specific Chromium network stack test file (`spdy_framer_test.cc`). It also probes for connections to JavaScript, logical reasoning examples, common user errors, debugging steps, and a summary of the file's purpose as part 5 of 7.

**2. Core Functionality Identification (Reading the Code):**

The filename `spdy_framer_test.cc` immediately suggests it's testing the `SpdyFramer`. The code confirms this by:

* **Including headers:**  It includes `quiche/http2/core/spdy_framer.h` and related test headers, indicating it's testing the functionality defined there.
* **Test Fixture:** The `SpdyFramerTest` class, parameterized by `bool`, sets up the test environment with a `SpdyFramer` instance.
* **TEST_P macros:**  These are Google Test macros for parameterized tests, indicating tests are run with different configurations (likely related to output behavior).
* **Focus on Frame Types:**  The tests directly manipulate and interpret different HTTP/2 frame types like `SETTINGS`, `DATA`, `WINDOW_UPDATE`, `HEADERS`, `CONTINUATION`, `PUSH_PROMISE`, etc.
* **Visitor Pattern:**  The use of `TestSpdyVisitor` demonstrates testing the *parsing* of frames by providing a visitor that records the events triggered during parsing.
* **Serialization and Deserialization:**  The tests involve serializing frames using `framer_.Serialize...` and then feeding the raw bytes to a `deframer_` (likely an instance of `Http2DecoderAdapter` which uses the `SpdyFramer` internally).
* **Error Handling:**  Many tests explicitly check for `visitor.error_count_` and `visitor.deframer_.spdy_framer_error()` to verify correct error detection.

**3. Discerning Specific Test Cases:**

As I read through each `TEST_P` block, I identified the specific scenarios being tested:

* **SETTINGS:** Reading known, unknown, and out-of-order settings, handling ACK frames.
* **DATA:**  Handling padding in data frames.
* **WINDOW_UPDATE:** Reading window update frames.
* **HEADERS/CONTINUATION:**  Reading headers split across multiple frames, including the END_STREAM flag.
* **PUSH_PROMISE/CONTINUATION:** Similar to headers, testing continuation for push promises.
* **Error Scenarios:** Receiving unexpected frames (unknown, out-of-order continuations, data when continuation is expected), reading garbage data.
* **Unknown Frames:** Handling unknown frame types, including interaction with extensions.
* **Garbage/Truncated Data:** Testing robustness against invalid input.
* **Sizes and State/Error String Conversion:** Testing constants and utility functions.

**4. Addressing Specific Request Points:**

* **Functionality List:** This became a matter of summarizing the observed test cases. I grouped them by the HTTP/2 frame type or general functionality being tested.
* **Relationship to JavaScript:** This required understanding where HTTP/2 comes into play in a browser context. The key connection is the network layer, specifically fetching resources. I considered how JavaScript's `fetch` API interacts with the underlying network stack.
* **Logical Reasoning Examples:** I looked for tests that demonstrated a specific input and expected output based on HTTP/2 rules. The "ReadKnownAndUnknownSettings" test is a good example.
* **Common User/Programming Errors:** I thought about mistakes developers might make when constructing or interpreting HTTP/2 frames, such as incorrect padding, wrong stream IDs for continuations, or sending control frames in the wrong order.
* **Debugging Steps:**  I considered how a developer might arrive at this code during debugging. This involves understanding the path of a network request in Chromium.
* **Summary (Part 5 of 7):** I synthesized the overall purpose of the tests based on the individual test cases.

**5. Structuring the Output:**

I organized the information into logical sections based on the request's questions. I used bullet points and code blocks to improve readability. For the logical reasoning examples, I explicitly stated the "Assumption" and "Output" based on the test's expectations.

**Self-Correction/Refinement During the Process:**

* **Initial Focus:**  I might have initially focused too much on the low-level byte manipulation. I realized the higher-level purpose was testing the *framer's ability to correctly parse and interpret* these bytes according to the HTTP/2 specification.
* **JavaScript Connection:**  I had to think carefully about *how* JavaScript interacts with the network stack. It's not a direct interaction with the C++ code, but rather through higher-level APIs like `fetch`.
* **Error Examples:** I tried to frame the "user errors" from the perspective of someone interacting with the HTTP/2 protocol, even if it's indirectly through a library.
* **Debugging Steps:** I refined the debugging path to be more specific to the Chromium context and the role of the `SpdyFramer`.

By following this systematic approach, I could analyze the code, understand its purpose, and address all the specific points raised in the request.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc` 这个文件的功能。

**文件功能归纳**

这个 C++ 文件 `spdy_framer_test.cc` 是 Chromium 网络栈中 QUIC 实现的一部分，它专门用于测试 `SpdyFramer` 类的功能。 `SpdyFramer` 的核心职责是处理 HTTP/2 协议的帧（frames）的序列化（将数据结构转换为字节流）和反序列化（将字节流转换为数据结构）。

**具体功能列表**

这个测试文件通过大量的单元测试用例，覆盖了 `SpdyFramer` 的各种功能，主要包括：

1. **SETTINGS 帧处理:**
   - 测试读取和解析各种有效的 SETTINGS 帧，包括已知设置、未知设置和带有扩展的设置。
   - 测试处理乱序的 SETTINGS 帧。
   - 测试处理 SETTINGS 帧的 ACK 标志。

2. **DATA 帧处理:**
   - 测试带有填充（padding）的 DATA 帧的解析，验证能否正确识别和处理填充字节。

3. **WINDOW_UPDATE 帧处理:**
   - 测试读取和解析 WINDOW_UPDATE 帧，验证能否正确提取流 ID 和窗口更新增量。

4. **PUSH_PROMISE 帧处理:**
   - 测试读取和解析压缩的 PUSH_PROMISE 帧，验证能否正确提取关联的流 ID 和头部信息。

5. **HEADERS 和 CONTINUATION 帧处理:**
   - 测试读取和解析 HEADERS 帧，特别是与 CONTINUATION 帧结合的情况，用于处理头部信息过大的情况。
   - 测试带有 END_STREAM 标志的 HEADERS 帧。

6. **错误处理:**
   - 测试在期望 CONTINUATION 帧时收到其他类型的帧，验证是否能正确报告 `SPDY_UNEXPECTED_FRAME` 错误。
   - 测试收到属于错误 stream 的 CONTINUATION 帧。
   - 测试收到乱序的 CONTINUATION 帧。
   - 测试在期望 CONTINUATION 帧时收到 DATA 或其他控制帧。
   - 测试读取到垃圾数据或格式错误的帧数据。
   - 测试读取到未知类型的扩展帧，并验证是否能正确处理（如果配置允许）。
   - 测试读取带有有效长度但内容是垃圾数据的帧。
   - 测试读取 HPACK 编码错误的头部数据。

7. **常量和工具函数测试:**
   - 测试各种帧的最小尺寸常量（如 `kFrameHeaderSize`，`kDataFrameMinimumSize` 等）。
   - 测试状态和错误码到字符串的转换函数（如 `Http2DecoderAdapter::StateToString`，`Http2DecoderAdapter::SpdyFramerErrorToString`）。

**与 JavaScript 的关系**

`SpdyFramer` 本身是用 C++ 实现的，直接与 JavaScript 没有关联。但是，它在浏览器网络栈中扮演着重要的角色，而浏览器正是 JavaScript 代码运行的环境。

**举例说明:**

当 JavaScript 代码通过 `fetch` API 发起一个 HTTP/2 请求时，浏览器底层的网络栈会使用 `SpdyFramer` 来：

1. **序列化请求头:**  将 JavaScript 中设置的请求头（例如 `Content-Type`, `Authorization` 等）编码成 HTTP/2 的 HEADERS 帧。
2. **序列化请求体:** 如果是 POST 或 PUT 请求，将请求体数据编码成 HTTP/2 的 DATA 帧。
3. **反序列化响应头:**  接收到服务器返回的 HEADERS 帧，`SpdyFramer` 将其解码成浏览器可以理解的头部信息，最终传递给 JavaScript 的 `Response` 对象。
4. **反序列化响应体:** 接收到服务器返回的 DATA 帧，`SpdyFramer` 将其解码成响应体数据，最终可以通过 JavaScript 读取。

**逻辑推理示例**

**假设输入:** 一个包含未知 SETTINGS 参数的 SETTINGS 帧的字节流。

```
const unsigned char kH2FrameData[] = {
    0x00, 0x00, 0x0c,        // Length: 12
    0x04,                    //   Type: SETTINGS
    0x00,                    //  Flags: none
    0x00, 0x00, 0x00, 0x00,  // Stream: 0
    0x12, 0x34,              //  Param: 4660 (未知)
    0x00, 0x00, 0x00, 0x01   //  Value: 1
};
```

**预期输出:**  根据测试用例 `ReadUnknownSettings`，`SpdyFramer` 会忽略这个未知的设置，但会将整个 SETTINGS 帧传递给 visitor。`TestSpdyVisitor` 会记录收到的设置数量，但不会报错。

```
EXPECT_EQ(1, visitor.setting_count_); // 设置数量为 1
EXPECT_EQ(0, visitor.error_count_);   // 没有错误
```

**用户或编程常见的使用错误**

1. **构造错误的帧数据:**  程序员可能会手动构造 HTTP/2 帧，如果长度字段计算错误、帧类型或标志位设置不正确，`SpdyFramer` 在解析时会报错。
   - **示例:**  DATA 帧的长度字段没有正确计算 payload 的大小和 padding 的大小。

2. **错误地处理 CONTINUATION 帧:**  在发送或接收头部信息时，如果头部信息过大，需要使用 CONTINUATION 帧进行分割。常见的错误包括：
   - 忘记发送或接收 CONTINUATION 帧。
   - CONTINUATION 帧的 stream ID 与 HEADERS 帧的 stream ID 不一致。
   - CONTINUATION 帧的 `END_HEADERS` 标志位设置错误。

3. **不理解 HTTP/2 的状态机:**  `SpdyFramer` 的解析过程是有状态的，如果开发者在错误的时刻发送或接收特定类型的帧，会导致解析错误。
   - **示例:** 在期望收到 CONTINUATION 帧时发送一个 DATA 帧。

**用户操作如何一步步到达这里 (调试线索)**

作为一个开发人员，在调试网络请求相关的问题时，可能会深入到 `SpdyFramer` 的层面：

1. **用户在浏览器中访问一个网站或执行某个网络操作。**
2. **浏览器发起 HTTP/2 连接到服务器。**
3. **JavaScript 代码通过 `fetch` API 发起一个请求。**
4. **Chromium 的网络栈开始构建 HTTP/2 帧来发送请求。** 这涉及到使用 `SpdyFramer` 的序列化功能。
5. **请求发送到服务器，服务器返回响应。**
6. **Chromium 的网络栈接收到来自服务器的 HTTP/2 帧。** 这时会使用 `SpdyFramer` 的反序列化功能来解析这些帧。
7. **如果在解析过程中发生错误（例如服务器发送了格式错误的帧），可能会触发 `SpdyFramer` 的错误处理逻辑。**
8. **开发人员可能会通过查看网络日志、断点调试 Chromium 源码等方式，最终定位到 `SpdyFramer` 的相关代码，例如 `spdy_framer_test.cc` 中的测试用例，来理解错误的原因和 `SpdyFramer` 的行为。**

**这是第 5 部分，共 7 部分，请归纳一下它的功能**

作为第 5 部分，这个文件专注于测试 `SpdyFramer` 对于各种 HTTP/2 帧的 **反序列化（解析）** 功能，以及在解析过程中对错误情况的处理。它通过模拟接收不同类型的帧数据，并使用 `TestSpdyVisitor` 来验证 `SpdyFramer` 是否按照 HTTP/2 协议规范正确地解析了帧的各个字段，并能正确地识别和处理错误。

希望以上分析能够帮助你理解这个测试文件的功能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能

"""
 unknown settings because of extensions. However, we
  // pass the SETTINGS to the visitor, which can decide how to handle them.
  EXPECT_EQ(1, visitor.setting_count_);
  EXPECT_EQ(0, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadKnownAndUnknownSettingsWithExtension) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x18,        // Length: 24
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x10,              //  Param: 16
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
      0x00, 0x5f,              //  Param: 95
      0x00, 0x01, 0x00, 0x02,  //  Value: 65538
      0x00, 0x02,              //  Param: ENABLE_PUSH
      0x00, 0x00, 0x00, 0x01,  //  Value: 1
      0x00, 0x08,              //  Param: ENABLE_CONNECT_PROTOCOL
      0x00, 0x00, 0x00, 0x01,  //  Value: 1
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  TestExtension extension;
  visitor.set_extension_visitor(&extension);
  visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));

  // In HTTP/2, we ignore unknown settings because of extensions. However, we
  // pass the SETTINGS to the visitor, which can decide how to handle them.
  EXPECT_EQ(4, visitor.setting_count_);
  EXPECT_EQ(0, visitor.error_count_);

  // The extension receives only the non-standard SETTINGS.
  EXPECT_THAT(
      extension.settings_received_,
      testing::ElementsAre(testing::Pair(16, 2), testing::Pair(95, 65538)));
}

// Tests handling of SETTINGS frame with entries out of order.
TEST_P(SpdyFramerTest, ReadOutOfOrderSettings) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x02,              //  Param: ENABLE_PUSH
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
      0x00, 0x03,              //  Param: MAX_CONCURRENT_STREAMS
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));

  // In HTTP/2, settings are allowed in any order.
  EXPECT_EQ(3, visitor.setting_count_);
  EXPECT_EQ(0, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ProcessSettingsAckFrame) {
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x00,        // Length: 0
      0x04,                    //   Type: SETTINGS
      0x01,                    //  Flags: ACK
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(0, visitor.setting_count_);
  EXPECT_EQ(1, visitor.settings_ack_received_);
}

TEST_P(SpdyFramerTest, ProcessDataFrameWithPadding) {
  const int kPaddingLen = 119;
  const char data_payload[] = "hello";

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  SpdyDataIR data_ir(/* stream_id = */ 1, data_payload);
  data_ir.set_padding_len(kPaddingLen);
  SpdySerializedFrame frame(framer_.SerializeData(data_ir));

  int bytes_consumed = 0;

  // Send the frame header.
  EXPECT_CALL(visitor,
              OnCommonHeader(1, kPaddingLen + strlen(data_payload), 0x0, 0x8));
  EXPECT_CALL(visitor,
              OnDataFrameHeader(1, kPaddingLen + strlen(data_payload), false));
  QUICHE_CHECK_EQ(kDataFrameMinimumSize,
                  deframer_->ProcessInput(frame.data(), kDataFrameMinimumSize));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_READ_DATA_FRAME_PADDING_LENGTH);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
  bytes_consumed += kDataFrameMinimumSize;

  // Send the padding length field.
  EXPECT_CALL(visitor, OnStreamPadLength(1, kPaddingLen - 1));
  QUICHE_CHECK_EQ(1u,
                  deframer_->ProcessInput(frame.data() + bytes_consumed, 1));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_FORWARD_STREAM_FRAME);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
  bytes_consumed += 1;

  // Send the first two bytes of the data payload, i.e., "he".
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 2));
  QUICHE_CHECK_EQ(2u,
                  deframer_->ProcessInput(frame.data() + bytes_consumed, 2));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_FORWARD_STREAM_FRAME);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
  bytes_consumed += 2;

  // Send the rest three bytes of the data payload, i.e., "llo".
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 3));
  QUICHE_CHECK_EQ(3u,
                  deframer_->ProcessInput(frame.data() + bytes_consumed, 3));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_CONSUME_PADDING);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
  bytes_consumed += 3;

  // Send the first 100 bytes of the padding payload.
  EXPECT_CALL(visitor, OnStreamPadding(1, 100));
  QUICHE_CHECK_EQ(100u,
                  deframer_->ProcessInput(frame.data() + bytes_consumed, 100));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_CONSUME_PADDING);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
  bytes_consumed += 100;

  // Send rest of the padding payload.
  EXPECT_CALL(visitor, OnStreamPadding(1, 18));
  QUICHE_CHECK_EQ(18u,
                  deframer_->ProcessInput(frame.data() + bytes_consumed, 18));
  QUICHE_CHECK_EQ(deframer_->state(),
                  Http2DecoderAdapter::SPDY_READY_FOR_FRAME);
  QUICHE_CHECK_EQ(deframer_->spdy_framer_error(),
                  Http2DecoderAdapter::SPDY_NO_ERROR);
}

TEST_P(SpdyFramerTest, ReadWindowUpdate) {
  SpdySerializedFrame control_frame(framer_.SerializeWindowUpdate(
      SpdyWindowUpdateIR(/* stream_id = */ 1, /* delta = */ 2)));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeWindowUpdate(
        SpdyWindowUpdateIR(/* stream_id = */ 1, /* delta = */ 2), &output_));
    control_frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1u, visitor.last_window_update_stream_);
  EXPECT_EQ(2, visitor.last_window_update_delta_);
}

TEST_P(SpdyFramerTest, ReadCompressedPushPromise) {
  SpdyPushPromiseIR push_promise(/* stream_id = */ 42,
                                 /* promised_stream_id = */ 57);
  push_promise.SetHeader("foo", "bar");
  push_promise.SetHeader("bar", "foofoo");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
      &framer_, push_promise, use_output_ ? &output_ : nullptr));
  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size());
  EXPECT_EQ(42u, visitor.last_push_promise_stream_);
  EXPECT_EQ(57u, visitor.last_push_promise_promised_stream_);
  EXPECT_EQ(push_promise.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadHeadersWithContinuation) {
  // frame-format off
  const unsigned char kInput[] = {
      0x00, 0x00, 0x14,                       // Length: 20
      0x01,                                   //   Type: HEADERS
      0x08,                                   //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,                 // Stream: 1
      0x03,                                   // PadLen: 3 trailing bytes
      0x00,                                   // Unindexed Entry
      0x06,                                   // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',       // Name
      0x07,                                   // Value Len: 7
      'f',  'o',  'o',  '=',  'b', 'a', 'r',  // Value
      0x00, 0x00, 0x00,                       // Padding

      0x00, 0x00, 0x14,                            // Length: 20
      0x09,                                        //   Type: CONTINUATION
      0x00,                                        //  Flags: none
      0x00, 0x00, 0x00, 0x01,                      // Stream: 1
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',            // Name
      0x08,                                        // Value Len: 7
      'b',  'a',  'z',  '=',  'b', 'i', 'n', 'g',  // Value
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',                                         // Name (split)

      0x00, 0x00, 0x12,             // Length: 18
      0x09,                         //   Type: CONTINUATION
      0x04,                         //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,       // Stream: 1
      'o',  'o',  'k',  'i',  'e',  // Name (continued)
      0x00,                         // Value Len: 0
      0x00,                         // Unindexed Entry
      0x04,                         // Name Len: 4
      'n',  'a',  'm',  'e',        // Name
      0x05,                         // Value Len: 5
      'v',  'a',  'l',  'u',  'e',  // Value
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);

  EXPECT_THAT(
      visitor.headers_,
      testing::ElementsAre(testing::Pair("cookie", "foo=bar; baz=bing; "),
                           testing::Pair("name", "value")));
}

TEST_P(SpdyFramerTest, ReadHeadersWithContinuationAndFin) {
  // frame-format off
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,                       // Length: 20
      0x01,                                   //   Type: HEADERS
      0x01,                                   //  Flags: END_STREAM
      0x00, 0x00, 0x00, 0x01,                 // Stream: 1
      0x00,                                   // Unindexed Entry
      0x06,                                   // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',       // Name
      0x07,                                   // Value Len: 7
      'f',  'o',  'o',  '=',  'b', 'a', 'r',  // Value

      0x00, 0x00, 0x14,                            // Length: 20
      0x09,                                        //   Type: CONTINUATION
      0x00,                                        //  Flags: none
      0x00, 0x00, 0x00, 0x01,                      // Stream: 1
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',            // Name
      0x08,                                        // Value Len: 7
      'b',  'a',  'z',  '=',  'b', 'i', 'n', 'g',  // Value
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',                                         // Name (split)

      0x00, 0x00, 0x12,             // Length: 18
      0x09,                         //   Type: CONTINUATION
      0x04,                         //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,       // Stream: 1
      'o',  'o',  'k',  'i',  'e',  // Name (continued)
      0x00,                         // Value Len: 0
      0x00,                         // Unindexed Entry
      0x04,                         // Name Len: 4
      'n',  'a',  'm',  'e',        // Name
      0x05,                         // Value Len: 5
      'v',  'a',  'l',  'u',  'e',  // Value
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(1, visitor.fin_flag_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);

  EXPECT_THAT(
      visitor.headers_,
      testing::ElementsAre(testing::Pair("cookie", "foo=bar; baz=bing; "),
                           testing::Pair("name", "value")));
}

TEST_P(SpdyFramerTest, ReadPushPromiseWithContinuation) {
  // frame-format off
  const unsigned char kInput[] = {
      0x00, 0x00, 0x17,                       // Length: 23
      0x05,                                   //   Type: PUSH_PROMISE
      0x08,                                   //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,                 // Stream: 1
      0x02,                                   // PadLen: 2 trailing bytes
      0x00, 0x00, 0x00, 0x2a,                 // Promise: 42
      0x00,                                   // Unindexed Entry
      0x06,                                   // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',       // Name
      0x07,                                   // Value Len: 7
      'f',  'o',  'o',  '=',  'b', 'a', 'r',  // Value
      0x00, 0x00,                             // Padding

      0x00, 0x00, 0x14,                            // Length: 20
      0x09,                                        //   Type: CONTINUATION
      0x00,                                        //  Flags: none
      0x00, 0x00, 0x00, 0x01,                      // Stream: 1
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',  'o',  'o',  'k',  'i', 'e',            // Name
      0x08,                                        // Value Len: 7
      'b',  'a',  'z',  '=',  'b', 'i', 'n', 'g',  // Value
      0x00,                                        // Unindexed Entry
      0x06,                                        // Name Len: 6
      'c',                                         // Name (split)

      0x00, 0x00, 0x12,             // Length: 18
      0x09,                         //   Type: CONTINUATION
      0x04,                         //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,       // Stream: 1
      'o',  'o',  'k',  'i',  'e',  // Name (continued)
      0x00,                         // Value Len: 0
      0x00,                         // Unindexed Entry
      0x04,                         // Name Len: 4
      'n',  'a',  'm',  'e',        // Name
      0x05,                         // Value Len: 5
      'v',  'a',  'l',  'u',  'e',  // Value
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1u, visitor.last_push_promise_stream_);
  EXPECT_EQ(42u, visitor.last_push_promise_promised_stream_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);

  EXPECT_THAT(
      visitor.headers_,
      testing::ElementsAre(testing::Pair("cookie", "foo=bar; baz=bing; "),
                           testing::Pair("name", "value")));
}

// Receiving an unknown frame when a continuation is expected should
// result in a SPDY_UNEXPECTED_FRAME error
TEST_P(SpdyFramerTest, ReceiveUnknownMidContinuation) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x14,        // Length: 20
      0xa9,                    //   Type: UnknownFrameType(169)
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // Payload
      0x6f, 0x6b, 0x69, 0x65,  //
      0x08, 0x62, 0x61, 0x7a,  //
      0x3d, 0x62, 0x69, 0x6e,  //
      0x67, 0x00, 0x06, 0x63,  //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  // Assume the unknown frame is allowed
  visitor.on_unknown_frame_result_ = true;
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

// Receiving an unknown frame when a continuation is expected should
// result in a SPDY_UNEXPECTED_FRAME error
TEST_P(SpdyFramerTest, ReceiveUnknownMidContinuationWithExtension) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x14,        // Length: 20
      0xa9,                    //   Type: UnknownFrameType(169)
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // Payload
      0x6f, 0x6b, 0x69, 0x65,  //
      0x08, 0x62, 0x61, 0x7a,  //
      0x3d, 0x62, 0x69, 0x6e,  //
      0x67, 0x00, 0x06, 0x63,  //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  TestExtension extension;
  visitor.set_extension_visitor(&extension);
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ReceiveContinuationOnWrongStream) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x14,        // Length: 20
      0x09,                    //   Type: CONTINUATION
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x02,  // Stream: 2
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x08, 0x62, 0x61, 0x7a,  //
      0x3d, 0x62, 0x69, 0x6e,  //
      0x67, 0x00, 0x06, 0x63,  //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ReadContinuationOutOfOrder) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x18,        // Length: 24
      0x09,                    //   Type: CONTINUATION
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
}

TEST_P(SpdyFramerTest, ExpectContinuationReceiveData) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x00,        // Length: 0
      0x00,                    //   Type: DATA
      0x01,                    //  Flags: END_STREAM
      0x00, 0x00, 0x00, 0x04,  // Stream: 4

      0xde, 0xad, 0xbe, 0xef,  // Truncated Frame Header
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, ExpectContinuationReceiveControlFrame) {
  const unsigned char kInput[] = {
      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //

      0x00, 0x00, 0x10,        // Length: 16
      0x01,                    //   Type: HEADERS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x06, 0x63, 0x6f,  // HPACK
      0x6f, 0x6b, 0x69, 0x65,  //
      0x07, 0x66, 0x6f, 0x6f,  //
      0x3d, 0x62, 0x61, 0x72,  //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  deframer_->set_visitor(&visitor);
  visitor.SimulateInFramer(kInput, sizeof(kInput));

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0u, visitor.header_buffer_length_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, ReadGarbage) {
  unsigned char garbage_frame[256];
  memset(garbage_frame, ~0, sizeof(garbage_frame));
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(garbage_frame, sizeof(garbage_frame));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadUnknownExtensionFrame) {
  // The unrecognized frame type should still have a valid length.
  const unsigned char unknown_frame[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0xff,                    //   Type: UnknownFrameType(255)
      0xff,                    //  Flags: 0xff
      0xff, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff (R-bit set)
      0xff, 0xff, 0xff, 0xff,  // Payload
      0xff, 0xff, 0xff, 0xff,  //
  };
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);

  // Simulate the case where the stream id validation checks out.
  visitor.on_unknown_frame_result_ = true;
  visitor.SimulateInFramer(unknown_frame, ABSL_ARRAYSIZE(unknown_frame));
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.unknown_frame_count_);
  EXPECT_EQ(8, visitor.unknown_payload_len_);

  // Follow it up with a valid control frame to make sure we handle
  // subsequent frames correctly.
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SETTINGS_HEADER_TABLE_SIZE, 10);
  SpdySerializedFrame control_frame(framer_.SerializeSettings(settings_ir));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
    control_frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.setting_count_);
  EXPECT_EQ(1, visitor.settings_ack_sent_);
}

TEST_P(SpdyFramerTest, ReadUnknownExtensionFrameWithExtension) {
  // The unrecognized frame type should still have a valid length.
  const unsigned char unknown_frame[] = {
      0x00, 0x00, 0x14,        // Length: 20
      0xff,                    //   Type: UnknownFrameType(255)
      0xff,                    //  Flags: 0xff
      0xff, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff (R-bit set)
      0xff, 0xff, 0xff, 0xff,  // Payload
      0xff, 0xff, 0xff, 0xff,  //
      0xff, 0xff, 0xff, 0xff,  //
      0xff, 0xff, 0xff, 0xff,  //
      0xff, 0xff, 0xff, 0xff,  //
  };
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  TestExtension extension;
  visitor.set_extension_visitor(&extension);
  visitor.SimulateInFramer(unknown_frame, ABSL_ARRAYSIZE(unknown_frame));
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(0x7fffffffu, extension.stream_id_);
  EXPECT_EQ(20u, extension.length_);
  EXPECT_EQ(255, extension.type_);
  EXPECT_EQ(0xff, extension.flags_);
  EXPECT_EQ(std::string(20, '\xff'), extension.payload_);

  // Follow it up with a valid control frame to make sure we handle
  // subsequent frames correctly.
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SETTINGS_HEADER_TABLE_SIZE, 10);
  SpdySerializedFrame control_frame(framer_.SerializeSettings(settings_ir));
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.setting_count_);
  EXPECT_EQ(1, visitor.settings_ack_sent_);
}

TEST_P(SpdyFramerTest, ReadGarbageWithValidLength) {
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x08,        // Length: 8
      0xff,                    //   Type: UnknownFrameType(255)
      0xff,                    //  Flags: 0xff
      0xff, 0xff, 0xff, 0xff,  // Stream: 0x7fffffff (R-bit set)
      0xff, 0xff, 0xff, 0xff,  // Payload
      0xff, 0xff, 0xff, 0xff,  //
  };
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, ABSL_ARRAYSIZE(kFrameData));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, ReadGarbageHPACKEncoding) {
  const unsigned char kInput[] = {
      0x00, 0x12, 0x01,        // Length: 4609
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x01, 0xef,  // Stream: 495
      0xef, 0xff,              //  Param: 61439
      0xff, 0xff, 0xff, 0xff,  //  Value: 4294967295
      0xff, 0xff,              //  Param: 0xffff
      0xff, 0xff, 0xff, 0xff,  //  Value: 4294967295
      0xff, 0xff, 0xff, 0xff,  // Settings (Truncated)
      0xff,                    //
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kInput, ABSL_ARRAYSIZE(kInput));
  EXPECT_EQ(1, visitor.error_count_);
}

TEST_P(SpdyFramerTest, SizesTest) {
  EXPECT_EQ(9u, kFrameHeaderSize);
  EXPECT_EQ(9u, kDataFrameMinimumSize);
  EXPECT_EQ(9u, kHeadersFrameMinimumSize);
  EXPECT_EQ(14u, kPriorityFrameSize);
  EXPECT_EQ(13u, kRstStreamFrameSize);
  EXPECT_EQ(9u, kSettingsFrameMinimumSize);
  EXPECT_EQ(13u, kPushPromiseFrameMinimumSize);
  EXPECT_EQ(17u, kPingFrameSize);
  EXPECT_EQ(17u, kGoawayFrameMinimumSize);
  EXPECT_EQ(13u, kWindowUpdateFrameSize);
  EXPECT_EQ(9u, kContinuationFrameMinimumSize);
  EXPECT_EQ(11u, kGetAltSvcFrameMinimumSize);
  EXPECT_EQ(9u, kFrameMinimumSize);

  EXPECT_EQ(16384u, kHttp2DefaultFramePayloadLimit);
  EXPECT_EQ(16393u, kHttp2DefaultFrameSizeLimit);
}

TEST_P(SpdyFramerTest, StateToStringTest) {
  EXPECT_STREQ("ERROR", Http2DecoderAdapter::StateToString(
                            Http2DecoderAdapter::SPDY_ERROR));
  EXPECT_STREQ("FRAME_COMPLETE", Http2DecoderAdapter::StateToString(
                                     Http2DecoderAdapter::SPDY_FRAME_COMPLETE));
  EXPECT_STREQ("READY_FOR_FRAME",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_READY_FOR_FRAME));
  EXPECT_STREQ("READING_COMMON_HEADER",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_READING_COMMON_HEADER));
  EXPECT_STREQ("CONTROL_FRAME_PAYLOAD",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_CONTROL_FRAME_PAYLOAD));
  EXPECT_STREQ("IGNORE_REMAINING_PAYLOAD",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_IGNORE_REMAINING_PAYLOAD));
  EXPECT_STREQ("FORWARD_STREAM_FRAME",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_FORWARD_STREAM_FRAME));
  EXPECT_STREQ(
      "SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK",
      Http2DecoderAdapter::StateToString(
          Http2DecoderAdapter::SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK));
  EXPECT_STREQ("SPDY_CONTROL_FRAME_HEADER_BLOCK",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_CONTROL_FRAME_HEADER_BLOCK));
  EXPECT_STREQ("SPDY_SETTINGS_FRAME_PAYLOAD",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_SETTINGS_FRAME_PAYLOAD));
  EXPECT_STREQ("SPDY_ALTSVC_FRAME_PAYLOAD",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_ALTSVC_FRAME_PAYLOAD));
  EXPECT_STREQ("UNKNOWN_STATE",
               Http2DecoderAdapter::StateToString(
                   Http2DecoderAdapter::SPDY_ALTSVC_FRAME_PAYLOAD + 1));
}

TEST_P(SpdyFramerTest, SpdyFramerErrorToStringTest) {
  EXPECT_STREQ("NO_ERROR", Http2DecoderAdapter::SpdyFramerErrorToString(
                               Http2DecoderAdapter::SPDY_NO_ERROR));
  EXPECT_STREQ("INVALID_STREAM_ID",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INVALID_STREAM_ID));
  EXPECT_STREQ("INVALID_CONTROL_FRAME",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME));
  EXPECT_STREQ("CONTROL_PAYLOAD_TOO_LARGE",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_CONTROL_PAYLOAD_TOO_LARGE));
  EXPECT_STREQ("DECOMPRESS_FAILURE",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_DECOMPRESS_FAILURE));
  EXPECT_STREQ("INVALID_PADDING",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INVALID_PADDING));
  EXPECT_STREQ("INVALID_DATA_FRAME_FLAGS",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS));
  EXPECT_STREQ("UNEXPECTED_FRAME",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME));
  EXPECT_STREQ("INTERNAL_FRAMER_ERROR",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INTERNAL_FRAMER_ERROR));
  EXPECT_STREQ("INVALID_CONTROL_FRAME_SIZE",
               Http2DecoderAdapter::SpdyFramerErrorToString(
                   Http2DecoderAdapter::SPDY_INVALID_CONT
"""


```