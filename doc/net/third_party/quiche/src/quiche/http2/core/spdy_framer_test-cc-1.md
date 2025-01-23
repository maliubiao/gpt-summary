Response:
My thinking process to arrive at the summary of the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a specific C++ test file within the Chromium network stack. It's the *second part* of a larger test file. This implies focusing on the tests within *this* specific chunk of code.

2. **Identify the Core Class Under Test:** The filename `spdy_framer_test.cc` immediately tells me the central class being tested is likely `SpdyFramer`. The presence of `deframer_` in the test setup further reinforces this, suggesting it's testing both framing and deframing aspects.

3. **Recognize the Testing Framework:** The use of `TEST_P`, `EXPECT_EQ`, `EXPECT_FALSE`, `EXPECT_TRUE`, `EXPECT_CALL`, `testing::StrictMock`, and `testing::InSequence` clearly indicates the code is using Google Test (gtest) and Google Mock (gmock). This is important context for understanding the structure and assertions.

4. **Scan for Test Case Names:** Quickly read through the `TEST_P` blocks and note down the test case names. This provides a high-level overview of the specific scenarios being tested. Keywords like "OversizedHeadersPaddingError," "CorrectlySizedHeadersPaddingNoError," "DataWithStreamIdZero," "HeadersWithStreamIdZero," etc., are key indicators.

5. **Group Related Test Cases:**  Observe patterns in the test case names. Notice a series of tests focusing on invalid stream IDs for different frame types (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, GOAWAY, CONTINUATION, PUSH_PROMISE). Also, see tests specifically for HEADERS padding. This grouping helps in creating a more structured summary.

6. **Analyze Individual Test Cases (Examples):**  Pick a few representative test cases and examine their implementation:
    * **`OversizedHeadersPaddingError`:**  This test sets up a mock visitor, constructs a HEADERS frame with intentionally invalid padding, and expects a specific error (`SPDY_INVALID_PADDING`) to be triggered.
    * **`DataWithStreamIdZero`:** This test serializes a DATA frame with a stream ID of 0, expects an error (`SPDY_INVALID_STREAM_ID`), and asserts that the error occurs before processing the entire frame.
    * **`MultiValueHeader`:** This test focuses on handling headers with multiple values.
    * **`Basic` and `BasicWithError`:** These tests simulate more complex sequences of frames and verify correct processing (or stopping processing upon encountering an error).

7. **Identify Key Functionality Being Tested:** Based on the test cases, determine the core aspects of `SpdyFramer` being validated in this section:
    * **Error Handling:** A major focus is on detecting and reporting errors related to invalid frame formatting (e.g., padding errors, incorrect stream IDs).
    * **Stream ID Validation:**  Ensuring that control frames have a stream ID of 0 and data/headers frames have non-zero stream IDs.
    * **Padding Handling:** Correctly processing and detecting errors in padding within HEADERS frames.
    * **Basic Frame Processing:** Handling sequences of different frame types (HEADERS, DATA, RST_STREAM).
    * **Flag Handling:** Testing the interpretation of flags like `END_HEADERS` and `END_STREAM`.
    * **Data Compression (Implicitly):** Some tests mention compression being enabled or disabled, although the specific compression logic might be in other parts of the code.

8. **Consider the "Visitor" Pattern:** The use of a `MockSpdyFramerVisitor` is crucial. This indicates that the `SpdyFramer` (or `Http2DecoderAdapter`) interacts with a visitor object to notify it about parsed frames and errors. The tests use mock expectations to verify these interactions.

9. **Address the Specific Questions (Even if Not Explicitly Asked in This Part):**  Although this is part 2, I keep in mind the general prompt's questions about JavaScript relevance, logical inference, user errors, and debugging. While this specific snippet doesn't directly show JavaScript interaction, the *overall* purpose of the `SpdyFramer` is to handle HTTP/2 framing, which is fundamental to web communication and thus has connections to how browsers (which use JavaScript) interact with servers.

10. **Synthesize the Summary:** Combine the identified functionalities and insights into a concise summary, focusing on what this *specific part* of the test file covers. Emphasize the error handling and stream ID validation aspects, as they are prominent.

11. **Review and Refine:** Read the summary to ensure it's accurate, clear, and addresses the essence of the code. Make sure it's specific to the provided snippet and avoids making overly broad generalizations about the entire `spdy_framer_test.cc` file. The mention that it's the second of seven parts helps narrow the focus.

By following these steps, I can systematically analyze the code and produce a comprehensive and accurate summary like the example you provided.
这是 `net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc` 文件的第二部分，主要集中在 **HTTP/2 帧的错误处理和特定场景的测试**。它延续了第一部分的功能，测试 `SpdyFramer` 类在解析 HTTP/2 帧时，对于各种异常情况和边界条件的处理能力。

**本部分的主要功能归纳如下：**

1. **测试 HEADERS 帧的 Padding 处理：**
   - 验证当 HEADERS 帧的 padding 长度大于实际 payload 长度时，`SpdyFramer` 能正确检测并设置 `SPDY_INVALID_PADDING` 错误。
   - 验证当 HEADERS 帧的 padding 长度有效时，`SpdyFramer` 不会产生错误。

2. **测试各种帧类型 Stream ID 为 0 的情况：**
   - 针对 DATA, HEADERS, PRIORITY, RST_STREAM, CONTINUATION, PUSH_PROMISE 等多种帧类型，测试当它们的 Stream ID 为 0 时，`SpdyFramer` 能正确检测并设置 `SPDY_INVALID_STREAM_ID` 错误。

3. **测试 SETTINGS 和 GOAWAY 帧 Stream ID 不为 0 的情况：**
   - 验证当 SETTINGS 和 GOAWAY 帧的 Stream ID 不为 0 时，`SpdyFramer` 能正确检测并设置 `SPDY_INVALID_STREAM_ID` 错误。

4. **测试 PUSH_PROMISE 帧 Promised Stream ID 为 0 的情况：**
   - 验证当 PUSH_PROMISE 帧的 Promised Stream ID 为 0 时，`SpdyFramer` 能正确检测并设置 `SPDY_INVALID_CONTROL_FRAME` 错误。

5. **测试多值 Header 的处理：**
   - 验证 `SpdyFramer` 能正确解析和处理具有相同名称但不同值的多个 Header。

6. **测试压缩空值的 Header：**
   - 验证在启用压缩的情况下，`SpdyFramer` 能正确处理包含空值的 Header。

7. **基本的帧解析流程测试 (Basic):**
   - 提供一系列包含多种帧类型的二进制数据，验证 `SpdyFramer` 能按顺序正确解析这些帧，并调用 Visitor 的相应回调函数。

8. **测试错误发生后停止处理 (BasicWithError):**
   - 模拟在解析过程中发生错误的情况，验证 `SpdyFramer` 能在错误发生后停止进一步的处理，并通知 Visitor 错误。

9. **测试 DATA 帧和 HEADERS 帧的 FIN 标志：**
   - 验证 DATA 帧和 HEADERS 帧的 `END_STREAM` 标志 (FIN 标志) 能正确通知 Visitor 数据流的结束。

10. **测试逐字节输入时的解压缩：**
    - 验证即使将帧数据逐字节地输入 `SpdyFramer`，它也能正确解压缩数据流。

11. **创建和比较 WINDOW_UPDATE 帧：**
    - 测试 `SpdyFramer` 能正确序列化 `SpdyWindowUpdateIR` 对象为二进制帧。

12. **创建和比较 DATA 帧 (包含 padding 的多种情况)：**
    - 测试 `SpdyFramer` 能正确序列化 `SpdyDataIR` 对象为二进制 DATA 帧，并能处理不同长度的 padding。

**与 Javascript 功能的关系：**

虽然这段 C++ 代码本身不直接与 Javascript 交互，但它所实现的功能是 **HTTP/2 协议的关键部分**。Javascript 在浏览器中通过 Fetch API 或 XMLHttpRequest 等方式发起网络请求时，底层就依赖于浏览器实现的 HTTP/2 协议栈来与服务器进行通信。`SpdyFramer` 的功能是处理 HTTP/2 帧的编码和解码，这直接影响着浏览器接收和发送 HTTP/2 数据包的能力。

**举例说明：**

假设一个 Javascript 应用通过 Fetch API 向服务器请求一个资源。

```javascript
fetch('/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个过程中：

1. **浏览器 (C++ 代码部分)** 会将 Javascript 发起的请求转换为一个或多个 HTTP/2 HEADERS 帧 (包含请求头信息) 和 DATA 帧 (如果请求有 body)。
2. **`SpdyFramer` (或者类似的 HTTP/2 帧处理模块)** 负责将这些帧序列化成二进制数据并通过网络发送出去。
3. **服务器收到请求后**，也会使用类似的帧处理模块来解析接收到的二进制数据，还原出 HTTP/2 帧，并最终解析出 Javascript 发起的请求。
4. **服务器响应时**，同样会将响应头信息和数据封装成 HTTP/2 HEADERS 帧和 DATA 帧。
5. **浏览器接收到服务器的响应后**，`SpdyFramer` 负责解析这些帧，将响应头信息和数据传递给浏览器的上层模块。
6. **最终，Javascript 代码中的 `then` 回调函数会接收到服务器返回的数据。**

**逻辑推理与假设输入输出：**

**场景：测试 HEADERS 帧 Padding 错误**

**假设输入 (二进制数据):**

```
00 00 05  // Length: 5
01        // Type: HEADERS
08        // Flags: PADDED
00 00 00 01 // Stream ID: 1
ff        // PadLen: 255 (超出剩余 payload 长度)
00 00 00 00 // 实际 padding (仅 4 字节)
```

**预期输出 (Visitor 的回调):**

- `OnCommonHeader(1, 5, 0x1, 0x8)`
- `OnHeaders(1, 5, false, 0, 0, false, false, false)`
- `OnHeaderFrameStart(1)`
- `OnError(Http2DecoderAdapter::SPDY_INVALID_PADDING, ...)`

**用户或编程常见的使用错误：**

1. **手动构造 HTTP/2 帧时 padding 长度计算错误：** 程序员在手动创建 HTTP/2 帧时，可能会错误地计算 padding 长度，导致发送无效的帧。例如，设置了 `PADDED` 标志，但 `PadLen` 的值超过了帧的剩余长度。

   **例子：**  一个程序尝试发送一个 HEADERS 帧，并添加了 100 字节的 padding，但在计算 `PadLen` 时错误地设置为了 150，导致接收端 `SpdyFramer` 报告 `SPDY_INVALID_PADDING` 错误。

2. **尝试发送 Stream ID 为 0 的 DATA 或 HEADERS 帧：** HTTP/2 协议规定 DATA 和 HEADERS 帧的 Stream ID 必须大于 0。程序员可能在编码时错误地将 Stream ID 设置为 0。

   **例子：**  一个客户端程序在创建新的请求时，错误地将初始的 HEADERS 帧的 Stream ID 设置为 0，导致服务器端的 `SpdyFramer` 报告 `SPDY_INVALID_STREAM_ID` 错误。

**用户操作如何到达这里（调试线索）：**

当网络请求出现问题，并且怀疑是 HTTP/2 协议层的问题时，开发者可能会进行以下调试操作，最终可能会涉及到 `SpdyFramer` 的代码：

1. **使用网络抓包工具 (如 Wireshark)：**  查看实际发送和接收的 HTTP/2 帧的二进制数据，检查帧的结构、长度、标志位等是否符合协议规范。如果发现异常的 padding 长度或 Stream ID 为 0 的帧，就可能定位到问题。

2. **查看浏览器或服务器的调试日志：** 很多浏览器和服务器会提供详细的 HTTP/2 事件日志，包括帧的解析结果和错误信息。这些日志可能会直接指出 `SpdyFramer` 报告的错误类型，例如 `SPDY_INVALID_PADDING` 或 `SPDY_INVALID_STREAM_ID`。

3. **在 Chromium 源码中设置断点：** 如果是 Chromium 相关的开发或调试，开发者可以在 `net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc` 或 `spdy_framer_test.cc` 中设置断点，逐步跟踪帧的解析过程，查看 `SpdyFramer` 如何处理特定的帧数据，以及何时报告错误。

4. **单元测试失败：**  正如这个测试文件所展示的，开发者编写了大量的单元测试来验证 `SpdyFramer` 的行为。如果某个关于 padding 或 Stream ID 的测试失败，就说明 `SpdyFramer` 在处理特定情况时出现了问题，需要进一步调查代码。

总而言之，这个代码片段是 Chromium 网络栈中 HTTP/2 协议实现的关键测试部分，专注于验证帧解析器的错误处理能力，确保网络通信的健壮性和符合协议规范。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
dding(1, 4));
  }

  EXPECT_EQ(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_FALSE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a HEADERS frame with padding length larger than the
// payload length, we set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, OversizedHeadersPaddingError) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  // HEADERS frame with invalid padding length.
  // |kH2FrameData| has to be |unsigned char|, because Chromium on Windows uses
  // MSVC, where |char| is signed by default, which would not compile because of
  // the element exceeding 127.
  unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xff,                    // PadLen: 255 trailing bytes (Too Long)
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame = MakeSerializedFrame(
      reinterpret_cast<char*>(kH2FrameData), sizeof(kH2FrameData));

  EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x1, 0x8));
  EXPECT_CALL(visitor, OnHeaders(1, 5, false, 0, 0, false, false, false));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1)).Times(1);
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_PADDING, _));
  EXPECT_EQ(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_PADDING,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a HEADERS frame with padding length not larger
// than the payload length, we do not set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, CorrectlySizedHeadersPaddingNoError) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  // HEADERS frame with invalid Padding length
  char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x04,                    // PadLen: 4 trailing bytes
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame =
      MakeSerializedFrame(kH2FrameData, sizeof(kH2FrameData));

  EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x1, 0x8));
  EXPECT_CALL(visitor, OnHeaders(1, 5, false, 0, 0, false, false, false));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1)).Times(1);

  EXPECT_EQ(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_FALSE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_NO_ERROR, deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a DATA with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, DataWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  const char bytes[] = "hello";
  SpdyDataIR data_ir(/* stream_id = */ 0, bytes);
  SpdySerializedFrame frame(framer_.SerializeData(data_ir));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x0, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a HEADERS with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, HeadersWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyHeadersIR headers(/* stream_id = */ 0);
  headers.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(
      SpdyFramerPeer::SerializeHeaders(&framer_, headers, &output_));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x1, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a PRIORITY with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, PriorityWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyPriorityIR priority_ir(/* stream_id = */ 0,
                             /* parent_stream_id = */ 1,
                             /* weight = */ 16,
                             /* exclusive = */ true);
  SpdySerializedFrame frame(framer_.SerializeFrame(priority_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(priority_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x2, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a RST_STREAM with stream ID zero, we signal an error
// (but don't crash).
TEST_P(SpdyFramerTest, RstStreamWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyRstStreamIR rst_stream_ir(/* stream_id = */ 0, ERROR_CODE_PROTOCOL_ERROR);
  SpdySerializedFrame frame(framer_.SerializeRstStream(rst_stream_ir));
  if (use_output_) {
    EXPECT_TRUE(framer_.SerializeRstStream(rst_stream_ir, &output_));
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x3, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a SETTINGS with stream ID other than zero,
// we signal an error (but don't crash).
TEST_P(SpdyFramerTest, SettingsWithStreamIdNotZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  // Settings frame with invalid StreamID of 0x01
  char kH2FrameData[] = {
      0x00, 0x00, 0x06,        // Length: 6
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x04,              //  Param: INITIAL_WINDOW_SIZE
      0x0a, 0x0b, 0x0c, 0x0d,  //  Value: 168496141
  };

  SpdySerializedFrame frame =
      MakeSerializedFrame(kH2FrameData, sizeof(kH2FrameData));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(1, 6, 0x4, 0x0));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a GOAWAY with stream ID other than zero,
// we signal an error (but don't crash).
TEST_P(SpdyFramerTest, GoawayWithStreamIdNotZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  // GOAWAY frame with invalid StreamID of 0x01
  char kH2FrameData[] = {
      0x00, 0x00, 0x0a,        // Length: 10
      0x07,                    //   Type: GOAWAY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  //   Last: 0
      0x00, 0x00, 0x00, 0x00,  //  Error: NO_ERROR
      0x47, 0x41,              // Description
  };

  SpdySerializedFrame frame =
      MakeSerializedFrame(kH2FrameData, sizeof(kH2FrameData));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(1, 10, 0x7, 0x0));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a CONTINUATION with stream ID zero, we signal
// SPDY_INVALID_STREAM_ID.
TEST_P(SpdyFramerTest, ContinuationWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyContinuationIR continuation(/* stream_id = */ 0);
  std::string some_nonsense_encoding = "some nonsense encoding";
  continuation.take_encoding(std::move(some_nonsense_encoding));
  continuation.set_end_headers(true);
  SpdySerializedFrame frame(framer_.SerializeContinuation(continuation));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeContinuation(continuation, &output_));
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x9, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a PUSH_PROMISE with stream ID zero, we signal
// SPDY_INVALID_STREAM_ID.
TEST_P(SpdyFramerTest, PushPromiseWithStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyPushPromiseIR push_promise(/* stream_id = */ 0,
                                 /* promised_stream_id = */ 4);
  push_promise.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
      &framer_, push_promise, use_output_ ? &output_ : nullptr));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(0, _, 0x5, _));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_STREAM_ID,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a PUSH_PROMISE with promised stream ID zero, we
// signal SPDY_INVALID_CONTROL_FRAME.
TEST_P(SpdyFramerTest, PushPromiseWithPromisedStreamIdZero) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  SpdyPushPromiseIR push_promise(/* stream_id = */ 3,
                                 /* promised_stream_id = */ 0);
  push_promise.SetHeader("alpha", "beta");
  SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
      &framer_, push_promise, use_output_ ? &output_ : nullptr));

  EXPECT_CALL(visitor, OnCommonHeader(3, _, 0x5, _));
  EXPECT_CALL(visitor,
              OnError(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME, _));
  deframer_->ProcessInput(frame.data(), frame.size());
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, MultiValueHeader) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
  std::string value("value1\0value2", 13);
  // TODO(jgraettinger): If this pattern appears again, move to test class.
  quiche::HttpHeaderBlock header_set;
  header_set["name"] = value;
  HpackEncoder encoder;
  encoder.DisableCompression();
  std::string buffer = encoder.EncodeHeaderBlock(header_set);
  // Frame builder with plentiful buffer size.
  SpdyFrameBuilder frame(1024);
  frame.BeginNewFrame(SpdyFrameType::HEADERS,
                      HEADERS_FLAG_PRIORITY | HEADERS_FLAG_END_HEADERS, 3,
                      buffer.size() + 5 /* priority */);
  frame.WriteUInt32(0);   // Priority exclusivity and dependent stream.
  frame.WriteUInt8(255);  // Priority weight.
  frame.WriteBytes(&buffer[0], buffer.size());

  SpdySerializedFrame control_frame(frame.take());

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());

  EXPECT_THAT(visitor.headers_, testing::ElementsAre(testing::Pair(
                                    "name", absl::string_view(value))));
}

TEST_P(SpdyFramerTest, CompressEmptyHeaders) {
  // See https://crbug.com/172383/
  SpdyHeadersIR headers(1);
  headers.SetHeader("server", "SpdyServer 1.0");
  headers.SetHeader("date", "Mon 12 Jan 2009 12:12:12 PST");
  headers.SetHeader("status", "200");
  headers.SetHeader("version", "HTTP/1.1");
  headers.SetHeader("content-type", "text/html");
  headers.SetHeader("content-length", "12");
  headers.SetHeader("x-empty-header", "");

  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
  SpdySerializedFrame frame1(
      SpdyFramerPeer::SerializeHeaders(&framer, headers, &output_));
}

TEST_P(SpdyFramerTest, Basic) {
  // Send HEADERS frames with PRIORITY and END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200

      0x00, 0x00, 0x0c,        // Length: 12
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x08,        // Length: 8
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x04,        // Length: 4
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL

      0x00, 0x00, 0x00,        // Length: 0
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));

  EXPECT_EQ(24, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(2, visitor.fin_frame_count_);

  EXPECT_EQ(3, visitor.headers_frame_count_);

  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);
  EXPECT_EQ(4, visitor.data_frame_count_);
}

// Verifies that the decoder stops delivering events after a user error.
TEST_P(SpdyFramerTest, BasicWithError) {
  // Send HEADERS frames with PRIORITY and END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200

      0x00, 0x00, 0x0c,        // Length: 12
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x06,        // Length: 6
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131
      0x8c,                    // :status: 200

      0x00, 0x00, 0x08,        // Length: 8
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x04,        // Length: 4
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL

      0x00, 0x00, 0x00,        // Length: 0
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3

      0x00, 0x00, 0x04,        // Length: 4
      0x03,                    //   Type: RST_STREAM
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x03,  // Stream: 3
      0x00, 0x00, 0x00, 0x08,  //  Error: CANCEL
  };
  // frame-format on

  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  testing::InSequence s;
  EXPECT_CALL(visitor, OnCommonHeader(1, 1, 0x1, 0x4));
  EXPECT_CALL(visitor, OnHeaders(1, 1, false, 0, 0, false, false, true));
  EXPECT_CALL(visitor, OnHeaderFrameStart(1));
  EXPECT_CALL(visitor, OnHeaderFrameEnd(1));
  EXPECT_CALL(visitor, OnCommonHeader(1, 12, 0x0, 0x0));
  EXPECT_CALL(visitor, OnDataFrameHeader(1, 12, false));
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 12));
  EXPECT_CALL(visitor, OnCommonHeader(3, 6, 0x1, 0x24));
  EXPECT_CALL(visitor, OnHeaders(3, 6, true, 131, 0, false, false, true));
  EXPECT_CALL(visitor, OnHeaderFrameStart(3));
  EXPECT_CALL(visitor, OnHeaderFrameEnd(3));
  EXPECT_CALL(visitor, OnCommonHeader(3, 8, 0x0, 0x0));
  EXPECT_CALL(visitor, OnDataFrameHeader(3, 8, false))
      .WillOnce(testing::InvokeWithoutArgs(
          [this]() { deframer_->StopProcessing(); }));
  // Remaining frames are not processed due to the error.
  EXPECT_CALL(
      visitor,
      OnError(http2::Http2DecoderAdapter::SpdyFramerError::SPDY_STOP_PROCESSING,
              "Ignoring further events on this connection."));

  size_t processed = deframer_->ProcessInput(
      reinterpret_cast<const char*>(kH2Input), sizeof(kH2Input));
  EXPECT_LT(processed, sizeof(kH2Input));
}

// Test that the FIN flag on a data frame signifies EOF.
TEST_P(SpdyFramerTest, FinOnDataFrame) {
  // Send HEADERS frames with END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200

      0x00, 0x00, 0x0c,        // Length: 12
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
      0xde, 0xad, 0xbe, 0xef,  //
      0xde, 0xad, 0xbe, 0xef,  //

      0x00, 0x00, 0x04,        // Length: 4
      0x00,                    //   Type: DATA
      0x01,                    //  Flags: END_STREAM
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xde, 0xad, 0xbe, 0xef,  // Payload
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(2, visitor.headers_frame_count_);
  EXPECT_EQ(16, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(2, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, FinOnHeadersFrame) {
  // Send HEADERS frames with END_HEADERS set.
  // frame-format off
  const unsigned char kH2Input[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x01,                    //   Type: HEADERS
      0x24,                    //  Flags: END_HEADERS|PRIORITY
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Parent: 0
      0x82,                    // Weight: 131

      0x00, 0x00, 0x01,        // Length: 1
      0x01,                    //   Type: HEADERS
      0x05,                    //  Flags: END_STREAM|END_HEADERS
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x8c,                    // :status: 200
  };
  // frame-format on

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2Input, sizeof(kH2Input));

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(2, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.data_bytes_);
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(1, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(0, visitor.data_frame_count_);
}

// Verify we can decompress the stream even if handed over to the
// framer 1 byte at a time.
TEST_P(SpdyFramerTest, UnclosedStreamDataCompressorsOneByteAtATime) {
  const char kHeader1[] = "header1";
  const char kHeader2[] = "header2";
  const char kValue1[] = "value1";
  const char kValue2[] = "value2";

  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.SetHeader(kHeader1, kValue1);
  headers.SetHeader(kHeader2, kValue2);
  SpdySerializedFrame headers_frame(SpdyFramerPeer::SerializeHeaders(
      &framer_, headers, use_output_ ? &output_ : nullptr));

  const char bytes[] = "this is a test test test test test!";
  SpdyDataIR data_ir(/* stream_id = */ 1,
                     absl::string_view(bytes, ABSL_ARRAYSIZE(bytes)));
  data_ir.set_fin(true);
  SpdySerializedFrame send_frame(framer_.SerializeData(data_ir));

  // Run the inputs through the framer.
  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  const unsigned char* data;
  data = reinterpret_cast<const unsigned char*>(headers_frame.data());
  for (size_t idx = 0; idx < headers_frame.size(); ++idx) {
    visitor.SimulateInFramer(data + idx, 1);
    ASSERT_EQ(0, visitor.error_count_);
  }
  data = reinterpret_cast<const unsigned char*>(send_frame.data());
  for (size_t idx = 0; idx < send_frame.size(); ++idx) {
    visitor.SimulateInFramer(data + idx, 1);
    ASSERT_EQ(0, visitor.error_count_);
  }

  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(ABSL_ARRAYSIZE(bytes), static_cast<unsigned>(visitor.data_bytes_));
  EXPECT_EQ(0, visitor.fin_frame_count_);
  EXPECT_EQ(0, visitor.fin_flag_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(1, visitor.data_frame_count_);
}

TEST_P(SpdyFramerTest, WindowUpdateFrame) {
  SpdyWindowUpdateIR window_update(/* stream_id = */ 1,
                                   /* delta = */ 0x12345678);
  SpdySerializedFrame frame(framer_.SerializeWindowUpdate(window_update));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeWindowUpdate(window_update, &output_));
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }

  const char kDescription[] = "WINDOW_UPDATE frame, stream 1, delta 0x12345678";
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x04,        // Length: 4
      0x08,                    //   Type: WINDOW_UPDATE
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x12, 0x34, 0x56, 0x78,  // Increment: 305419896
  };

  CompareFrame(kDescription, frame, kH2FrameData, ABSL_ARRAYSIZE(kH2FrameData));
}

TEST_P(SpdyFramerTest, CreateDataFrame) {
  {
    const char kDescription[] = "'hello' data frame, no FIN";
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x05,        // Length: 5
        0x00,                    //   Type: DATA
        0x00,                    //  Flags: none
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(/* stream_id = */ 1, bytes);
    SpdySerializedFrame frame(framer_.SerializeData(data_ir));
    CompareFrame(kDescription, frame, kH2FrameData,
                 ABSL_ARRAYSIZE(kH2FrameData));

    SpdyDataIR data_header_ir(/* stream_id = */ 1);
    data_header_ir.SetDataShallow(strlen(bytes));
    frame =
        framer_.SerializeDataFrameHeaderWithPaddingLengthField(data_header_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        kDataFrameMinimumSize, kH2FrameData, kDataFrameMinimumSize);
  }

  {
    const char kDescription[] = "'hello' data frame with more padding, no FIN";
    // clang-format off
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0xfd,        // Length: 253
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0xf7,                    // PadLen: 247 trailing bytes
        'h', 'e', 'l', 'l',      // Payload
        'o',                     //
        // Padding of 247 0x00(s).
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // frame-format on
    // clang-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(/* stream_id = */ 1, bytes);
    // 247 zeros and the pad length field make the overall padding to be 248
    // bytes.
    data_ir.set_padding_len(248);
    SpdySerializedFrame frame(framer_.SerializeData(data_ir));
    CompareFrame(kDescription, frame, kH2FrameData,
                 ABSL_ARRAYSIZE(kH2FrameData));

    frame = framer_.SerializeDataFrameHeaderWithPaddingLengthField(data_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        kDataFrameMinimumSize, kH2FrameData, kDataFrameMinimumSize);
  }

  {
    const char kDescription[] = "'hello' data frame with few padding, no FIN";
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x0d,        // Length: 13
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x07,                    // PadLen: 7 trailing bytes
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
        0x00, 0x00, 0x00, 0x00,  // Padding
        0x00, 0x00, 0x00,        // Padding
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR data_ir(/* stream_id = */ 1, bytes);
    // 7 zeros and the pad length field make the overall padding to be 8 bytes.
    data_ir.set_padding_len(8);
    SpdySerializedFrame frame(framer_.SerializeData(data_ir));
    CompareFrame(kDescription, frame, kH2FrameData,
                 ABSL_ARRAYSIZE(kH2FrameData));

    frame = framer_.SerializeDataFrameHeaderWithPaddingLengthField(data_ir);
    CompareCharArraysWithHexError(
        kDescription, reinterpret_cast<const unsigned char*>(frame.data()),
        kDataFrameMinimumSize, kH2FrameData, kDataFrameMinimumSize);
  }

  {
    const char kDescription[] =
        "'hello' data frame with 1 byte padding, no FIN";
    // frame-format off
    const unsigned char kH2FrameData[] = {
        0x00, 0x00, 0x06,        // Length: 6
        0x00,                    //   Type: DATA
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream: 1
        0x00,                    // PadLen: 0 trailing bytes
        'h',  'e',  'l',  'l',   // Payload
        'o',                     //
    };
    // frame-format on
    const char bytes[] = "hello";

    SpdyDataIR da
```