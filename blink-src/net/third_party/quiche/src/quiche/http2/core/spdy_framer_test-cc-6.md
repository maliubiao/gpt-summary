Response:
The user is asking for a summary of the functionality of the C++ code file `spdy_framer_test.cc`. This is the last of a 7-part series, so the final request is to summarize the overall purpose.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The filename `spdy_framer_test.cc` strongly suggests this file contains unit tests for a `SpdyFramer` class. The "framer" is likely responsible for encoding and decoding SPDY frames.

2. **Examine Test Cases:**  Go through each `TEST_P` or `TEST` function and understand what aspect of the `SpdyFramer` is being tested. Look for keywords like "Read," "handling," "incorrectly sized," "processes," and the types of SPDY frames being manipulated (PRIORITY, PING, WINDOW_UPDATE, RST_STREAM, HEADERS, DATA, etc.).

3. **Look for Key Classes and Methods:** Identify the main classes and methods being tested. In this case, `SpdyFramer`, `Http2DecoderAdapter`, `MockSpdyFramerVisitor`, `SpdyPriorityIR`, `SpdySerializedFrame`, etc. are important. Pay attention to methods like `ProcessInput`, `SerializePriority`, `SerializeHeaders`, `SerializeData`, `SerializeFrame`.

4. **Identify Error Handling:** Notice tests that check for error conditions like `SPDY_INVALID_STREAM_ID`, `SPDY_INVALID_CONTROL_FRAME_SIZE`, and the use of `EXPECT_CALL(visitor, OnError(...))`.

5. **Determine Positive Testing:** Look for tests that verify correct behavior under normal conditions, like parsing valid PRIORITY frames.

6. **Consider the Context:** The file path `net/third_party/quiche/src/quiche/http2/core/` indicates this is related to the HTTP/2 implementation within the QUIC transport protocol, used by Chromium. While SPDY is an older protocol, it's related to HTTP/2 and likely shares some core framing concepts.

7. **Address Specific Questions:**
    * **Functionality:** Summarize the types of tests being performed (parsing, serialization, error handling, size validation).
    * **JavaScript Relationship:** Consider if the framing logic directly impacts JavaScript. While JavaScript uses HTTP/2 (or potentially SPDY in older scenarios), the *internal* C++ framing implementation isn't directly exposed or used in JavaScript code. The impact is indirect – correct framing enables network communication that JavaScript relies on. An example could involve a JavaScript fetch request triggering network activity that uses this framer under the hood.
    * **Logic and Input/Output:** Choose a specific test case and illustrate the input (the byte array) and the expected output (the visitor method calls).
    * **User/Programming Errors:** Focus on the "incorrectly sized" frame tests. A programmer might incorrectly construct a SPDY frame, leading to parsing errors.
    * **User Operation to Reach Here:** Think about the high-level user action (e.g., browsing a website) that triggers network requests, which eventually involve the SPDY framer.
    * **Final Summary:** Combine the observations from all the tests into a concise description of the file's purpose.

**Pre-computation and Pre-analysis (Internal Thought Process):**

* "Okay, this is a test file. The core function is definitely testing the SPDY framer."
* "I see tests for various SPDY frame types: PRIORITY, PING, WINDOW_UPDATE, RST_STREAM, HEADERS, DATA, SETTINGS, GOAWAY, PUSH_PROMISE, ALTSVC, UNKNOWN."
* "The tests check both valid and invalid frames. Specifically, they check for correct parsing and handling of errors when frames are malformed (incorrect size, invalid stream ID)."
* "The `MockSpdyFramerVisitor` is crucial for verifying that the framer calls the correct methods with the expected data."
* "The `use_output_` flag suggests testing both in-place and separate output buffer serialization."
* "The presence of `Http2DecoderAdapter` implies this SPDY implementation might be related to or used in the context of HTTP/2."
* "The `SpdyFrameIR` classes represent internal representations of SPDY frames, used for serialization."
* "The test about `ProcessAllInput` verifies that the framer can handle multiple frames in a single buffer."
* "The `SpdyFrameIRSize` test is interesting; it seems to be validating the accuracy of the size calculation for different frame types."

By going through these steps and observations, I can formulate a comprehensive answer that addresses all aspects of the user's request.
这是文件 `net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc` 的第 7 部分，也是最后一部分。综合之前的部分和本部分的内容，我们可以归纳一下它的功能：

**总体功能：`spdy_framer_test.cc` 文件是 Chromium 网络栈中 QUIC 协议下 HTTP/2 实现的核心组件 `SpdyFramer` 类的单元测试文件。**

更具体地说，这个文件测试了 `SpdyFramer` 类的以下功能：

1. **SPDY 帧的解析 (Deframing)：**
   - 测试了如何正确解析各种 SPDY 控制帧，例如：
     - PRIORITY (优先级)
     - PING (心跳)
     - WINDOW_UPDATE (窗口更新)
     - RST_STREAM (流重置)
   - 测试了在解析过程中对错误情况的处理，例如：
     - 接收到 stream ID 为 0 的 PRIORITY_UPDATE 帧 (无效的 stream ID)。
     - 接收到大小不正确的控制帧 (PRIORITY, PING, WINDOW_UPDATE, RST_STREAM)。
     - 接收到带有 payload 的 RST_STREAM 帧 (SPDY 规范不允许)。
   - 使用 `Http2DecoderAdapter` 作为 deframer，并使用 `MockSpdyFramerVisitor` 来验证解析结果。

2. **SPDY 帧的序列化 (Framing)：**
   - 尽管本部分代码没有直接展示序列化，但从之前的代码和测试用例中可以推断出，该文件也测试了 `SpdyFramer` 的序列化功能，例如 `framer_.SerializePriority(priority)`。

3. **处理输入数据流：**
   - 测试了 `ProcessInput` 方法，验证它可以一次性处理包含多个 SPDY 帧的输入缓冲区。

4. **`SpdyFrameIR` 的大小计算：**
   - 测试了 `SpdyFrameIR` 对象的 `size()` 方法，用于估算或精确计算各种 SPDY 帧的序列化后的大小。这有助于在发送帧之前预先分配足够的缓冲区。涉及的帧类型包括：
     - DATA
     - RST_STREAM
     - SETTINGS
     - PING
     - GOAWAY
     - HEADERS
     - WINDOW_UPDATE
     - PUSH_PROMISE
     - ALTSVC
     - PRIORITY
     - UNKNOWN

**与 JavaScript 的关系：**

`spdy_framer_test.cc` 文件中的代码是用 C++ 编写的，直接与 JavaScript 没有关系。然而，它测试的网络栈组件最终会影响到 JavaScript 的网络请求行为。

**举例说明：**

当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTP/2 请求时，Chromium 浏览器底层的网络栈会使用 `SpdyFramer` 来将 JavaScript 请求的信息编码成 SPDY/HTTP/2 帧，并通过网络发送出去。同样，接收到的 HTTP/2 响应帧也会通过 `SpdyFramer` 进行解析，然后将数据传递给 JavaScript。

**逻辑推理、假设输入与输出：**

**示例：`TEST_P(SpdyFramerTest, ReadPriority)`**

* **假设输入 (字节数组):**  `frame.data()` 指向的内存区域，内容是序列化后的 PRIORITY 帧。例如，如果 `priority` 对象表示 stream ID 3 的优先级，父 stream ID 为 1，权重为 256，非独占，则 `frame.data()` 可能包含如下字节序列（简化表示）：
   ```
   0x00, 0x00, 0x05, // Length: 5 字节
   0x02,             // Type: PRIORITY (0x2)
   0x00,             // Flags: 0
   0x00, 0x00, 0x00, 0x03, // Stream ID: 3
   0x00, 0x00, 0x00, 0x01, // Prioritized Stream ID: 1
   0x00,             // Weight: 0 (对应 256)
   0x00              // Exclusive: false
   ```
* **预期输出:** `MockSpdyFramerVisitor` 的以下方法会被调用：
   - `OnCommonHeader(3, 5, 0x2, 0x0)`: 通知访问者接收到一个 stream ID 为 3，长度为 5，类型为 PRIORITY (0x2)，Flags 为 0 的帧头。
   - `OnPriority(3, 1, 256, false)`: 通知访问者接收到一个 stream ID 为 3 的 PRIORITY 帧，其父 stream ID 为 1，权重为 256，非独占。

**用户或编程常见的使用错误：**

1. **构造不符合 SPDY 规范的帧:** 程序员可能会错误地构造 SPDY 帧，例如设置了错误的长度、类型或标志位。本文件中的测试用例，如 `ReadIncorrectlySizedPriority`，就是为了检测这种错误。
   ```c++
   // 错误的 PRIORITY 帧，长度应该是 5，这里设置为了 4
   const unsigned char kFrameData[] = {
       0x00, 0x00, 0x04,        // Length: 4 (错误)
       0x02,                    //   Type: PRIORITY
       0x00,                    //  Flags: none
       0x00, 0x00, 0x00, 0x03,  // Stream: 3
       0x00, 0x00, 0x00, 0x01,  // Priority (Truncated)
   };
   ```
   这种错误会导致 `SpdyFramer` 解析失败，并触发 `OnError` 回调。

2. **在不应该发送 payload 的控制帧中添加 payload:** 例如，向 RST_STREAM 帧添加额外的 payload 数据。`ReadInvalidRstStreamWithPayload` 测试用例就是为了防止这种情况。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个使用 HTTPS 的网站。**
2. **浏览器与服务器协商使用 HTTP/2 协议。**
3. **当浏览器需要请求资源时（例如 HTML、CSS、JavaScript、图片），它会创建 HTTP/2 请求。**
4. **Chromium 的网络栈会将这些请求信息转换成 SPDY/HTTP/2 帧。这个过程中会使用 `SpdyFramer` 的序列化功能。**
5. **这些帧通过 TCP 连接（或 QUIC 连接）发送到服务器。**
6. **当浏览器接收到服务器发送的 HTTP/2 响应帧时，网络栈会使用 `SpdyFramer` 的解析功能来解析这些帧。**
7. **如果在解析过程中遇到错误（例如服务器发送了格式错误的帧），`SpdyFramer` 会报告错误，这可能会导致网络请求失败。**

在调试过程中，如果怀疑是 SPDY 帧的编码或解码出现问题，开发者可能会查看 `SpdyFramer` 相关的代码和日志，甚至运行 `spdy_framer_test.cc` 中的单元测试来验证 `SpdyFramer` 的行为是否符合预期。

**第 7 部分功能归纳：**

作为最后一部分，这段代码主要集中在以下几点：

- **继续测试 `SpdyFramer` 的解析功能，特别是针对 PRIORITY 帧。**
- **测试了对格式错误的控制帧（大小不正确，RST_STREAM 带有 payload）的错误处理。**
- **验证了 `SpdyFramer` 可以一次性处理包含多个帧的输入。**
- **测试了 `SpdyFrameIR` 对象计算自身大小的功能，这对于高效的内存管理和帧序列化至关重要。**

总而言之，`spdy_framer_test.cc` 通过各种测试用例，全面验证了 `SpdyFramer` 类的正确性和健壮性，确保其能够可靠地处理 SPDY 帧的编码和解码，这是 Chromium 网络栈中实现 HTTP/2 协议的关键组成部分。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能

"""
     // frame type PRIORITY_UPDATE
      0x00,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID, must be 0
      0x00, 0x00, 0x00, 0x00,  // prioritized stream ID, must not be zero
  };

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  EXPECT_CALL(visitor, OnCommonHeader(0, 4, 0x10, 0x0));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  deframer_->ProcessInput(kFrameData, sizeof(kFrameData));
  EXPECT_TRUE(deframer_->HasError());
}

// Tests handling of PRIORITY frames.
TEST_P(SpdyFramerTest, ReadPriority) {
  SpdyPriorityIR priority(/* stream_id = */ 3,
                          /* parent_stream_id = */ 1,
                          /* weight = */ 256,
                          /* exclusive = */ false);
  SpdySerializedFrame frame(framer_.SerializePriority(priority));
  if (use_output_) {
    output_.Reset();
    ASSERT_TRUE(framer_.SerializePriority(priority, &output_));
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);
  EXPECT_CALL(visitor, OnCommonHeader(3, 5, 0x2, 0x0));
  EXPECT_CALL(visitor, OnPriority(3, 1, 256, false));
  deframer_->ProcessInput(frame.data(), frame.size());

  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Tests handling of PRIORITY frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedPriority) {
  // PRIORITY frame of size 4, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x02,                    //   Type: PRIORITY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x01,  // Priority (Truncated)
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, visitor.deframer_.state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Tests handling of PING frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedPing) {
  // PING frame of size 4, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x06,                    //   Type: PING
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x00, 0x00, 0x01,  // Ping (Truncated)
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, visitor.deframer_.state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Tests handling of WINDOW_UPDATE frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedWindowUpdate) {
  // WINDOW_UPDATE frame of size 3, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x03,        // Length: 3
      0x08,                    //   Type: WINDOW_UPDATE
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x01,        // WindowUpdate (Truncated)
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, visitor.deframer_.state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Tests handling of RST_STREAM frame with incorrect size.
TEST_P(SpdyFramerTest, ReadIncorrectlySizedRstStream) {
  // RST_STREAM frame of size 3, which isn't correct.
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x03,        // Length: 3
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x01,        // RstStream (Truncated)
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, visitor.deframer_.state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Regression test for https://crbug.com/548674:
// RST_STREAM with payload must not be accepted.
TEST_P(SpdyFramerTest, ReadInvalidRstStreamWithPayload) {
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x07,        //  Length: 7
      0x03,                    //    Type: RST_STREAM
      0x00,                    //   Flags: none
      0x00, 0x00, 0x00, 0x01,  //  Stream: 1
      0x00, 0x00, 0x00, 0x00,  //   Error: NO_ERROR
      'f',  'o',  'o'          // Payload: "foo"
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kFrameData, sizeof(kFrameData));

  EXPECT_EQ(Http2DecoderAdapter::SPDY_ERROR, visitor.deframer_.state());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Test that SpdyFramer processes all passed input in one call to ProcessInput.
TEST_P(SpdyFramerTest, ProcessAllInput) {
  auto visitor =
      std::make_unique<TestSpdyVisitor>(SpdyFramer::DISABLE_COMPRESSION);
  deframer_->set_visitor(visitor.get());

  // Create two input frames.
  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  headers.SetHeader("cookie", "key1=value1; key2=value2");
  SpdySerializedFrame headers_frame(SpdyFramerPeer::SerializeHeaders(
      &framer_, headers, use_output_ ? &output_ : nullptr));

  const char four_score[] = "Four score and seven years ago";
  SpdyDataIR four_score_ir(/* stream_id = */ 1, four_score);
  SpdySerializedFrame four_score_frame(framer_.SerializeData(four_score_ir));

  // Put them in a single buffer (new variables here to make it easy to
  // change the order and type of frames).
  SpdySerializedFrame frame1 = std::move(headers_frame);
  SpdySerializedFrame frame2 = std::move(four_score_frame);

  const size_t frame1_size = frame1.size();
  const size_t frame2_size = frame2.size();

  QUICHE_VLOG(1) << "frame1_size = " << frame1_size;
  QUICHE_VLOG(1) << "frame2_size = " << frame2_size;

  std::string input_buffer;
  input_buffer.append(frame1.data(), frame1_size);
  input_buffer.append(frame2.data(), frame2_size);

  const char* buf = input_buffer.data();
  const size_t buf_size = input_buffer.size();

  QUICHE_VLOG(1) << "buf_size = " << buf_size;

  size_t processed = deframer_->ProcessInput(buf, buf_size);
  EXPECT_EQ(buf_size, processed);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_READY_FOR_FRAME, deframer_->state());
  EXPECT_EQ(1, visitor->headers_frame_count_);
  EXPECT_EQ(1, visitor->data_frame_count_);
  EXPECT_EQ(strlen(four_score), static_cast<unsigned>(visitor->data_bytes_));
}

namespace {
void CheckFrameAndIRSize(SpdyFrameIR* ir, SpdyFramer* framer,
                         ArrayOutputBuffer* array_output_buffer) {
  array_output_buffer->Reset();
  SpdyFrameType type = ir->frame_type();
  size_t ir_size = ir->size();
  framer->SerializeFrame(*ir, array_output_buffer);
  if (type == SpdyFrameType::HEADERS || type == SpdyFrameType::PUSH_PROMISE) {
    // For HEADERS and PUSH_PROMISE, the size is an estimate.
    EXPECT_GE(ir_size, array_output_buffer->Size() * 9 / 10);
    EXPECT_LT(ir_size, array_output_buffer->Size() * 11 / 10);
  } else {
    EXPECT_EQ(ir_size, array_output_buffer->Size());
  }
}
}  // namespace

TEST_P(SpdyFramerTest, SpdyFrameIRSize) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);

  const char bytes[] = "this is a very short data frame";
  SpdyDataIR data_ir(1, absl::string_view(bytes, ABSL_ARRAYSIZE(bytes)));
  CheckFrameAndIRSize(&data_ir, &framer, &output_);

  SpdyRstStreamIR rst_ir(/* stream_id = */ 1, ERROR_CODE_PROTOCOL_ERROR);
  CheckFrameAndIRSize(&rst_ir, &framer, &output_);

  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SETTINGS_HEADER_TABLE_SIZE, 5);
  settings_ir.AddSetting(SETTINGS_ENABLE_PUSH, 6);
  settings_ir.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 7);
  CheckFrameAndIRSize(&settings_ir, &framer, &output_);

  SpdyPingIR ping_ir(42);
  CheckFrameAndIRSize(&ping_ir, &framer, &output_);

  SpdyGoAwayIR goaway_ir(97, ERROR_CODE_NO_ERROR, "Goaway description");
  CheckFrameAndIRSize(&goaway_ir, &framer, &output_);

  SpdyHeadersIR headers_ir(1);
  headers_ir.SetHeader("alpha", "beta");
  headers_ir.SetHeader("gamma", "charlie");
  headers_ir.SetHeader("cookie", "key1=value1; key2=value2");
  CheckFrameAndIRSize(&headers_ir, &framer, &output_);

  SpdyHeadersIR headers_ir_with_continuation(1);
  headers_ir_with_continuation.SetHeader("alpha", std::string(100000, 'x'));
  headers_ir_with_continuation.SetHeader("beta", std::string(100000, 'x'));
  headers_ir_with_continuation.SetHeader("cookie", "key1=value1; key2=value2");
  CheckFrameAndIRSize(&headers_ir_with_continuation, &framer, &output_);

  SpdyWindowUpdateIR window_update_ir(4, 1024);
  CheckFrameAndIRSize(&window_update_ir, &framer, &output_);

  SpdyPushPromiseIR push_promise_ir(3, 8);
  push_promise_ir.SetHeader("alpha", std::string(100000, 'x'));
  push_promise_ir.SetHeader("beta", std::string(100000, 'x'));
  push_promise_ir.SetHeader("cookie", "key1=value1; key2=value2");
  CheckFrameAndIRSize(&push_promise_ir, &framer, &output_);

  SpdyAltSvcWireFormat::AlternativeService altsvc1(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector());
  SpdyAltSvcWireFormat::AlternativeService altsvc2(
      "p\"=i:d", "h_\\o\"st", 123, 42, SpdyAltSvcWireFormat::VersionVector{24});
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  altsvc_vector.push_back(altsvc1);
  altsvc_vector.push_back(altsvc2);
  SpdyAltSvcIR altsvc_ir(0);
  altsvc_ir.set_origin("o_r|g!n");
  altsvc_ir.add_altsvc(altsvc1);
  altsvc_ir.add_altsvc(altsvc2);
  CheckFrameAndIRSize(&altsvc_ir, &framer, &output_);

  SpdyPriorityIR priority_ir(3, 1, 256, false);
  CheckFrameAndIRSize(&priority_ir, &framer, &output_);

  const char kDescription[] = "Unknown frame";
  const uint8_t kType = 0xaf;
  const uint8_t kFlags = 0x11;
  SpdyUnknownIR unknown_ir(2, kType, kFlags, kDescription);
  CheckFrameAndIRSize(&unknown_ir, &framer, &output_);
}

}  // namespace test

}  // namespace spdy

"""


```