Response:
The user wants to understand the functionality of the `spdy_framer_test.cc` file in the Chromium network stack. This file is part of the QUIC implementation and focuses on testing the SPDY/HTTP2 frame processing logic.

Here's a breakdown of the user's request and how to address it:

1. **List its functions:** Analyze the provided code snippets to identify the main purposes and test scenarios covered in the file.
2. **Relationship to JavaScript:** Determine if any of the tested functionalities directly interact with or are exposed to JavaScript.
3. **Logic and Input/Output:** For specific test cases, infer the intended input frame data and the expected outcome of processing it.
4. **Common User/Programming Errors:** Identify potential misuses of the SPDY framing mechanisms that these tests aim to prevent or detect.
5. **User Operations and Debugging:**  Describe how a user action might lead to the execution of this code and how it can be used for debugging.
6. **Summarize Functionality (Part 4 of 7):** Based on the analyzed code snippets, provide a concise summary of the functionalities demonstrated in this specific part of the file.

**Mental Walkthrough of the Provided Code Snippets:**

* **CONTINUATION after CONTINUATION Error:**  This test checks the error handling when a CONTINUATION frame unexpectedly follows another CONTINUATION frame.
* **PUSH_PROMISE then CONTINUATION (Uncompressed):** This verifies the correct framing and parsing of a PUSH_PROMISE frame whose header block is split across a CONTINUATION frame.
* **Create AltSvc:**  Tests the serialization of an ALTSVC frame.
* **Create Priority:** Tests the serialization of a PRIORITY frame.
* **Create PriorityUpdate:** Tests the serialization of a PRIORITY_UPDATE frame.
* **Create AcceptCh:** Tests the serialization of an ACCEPT_CH frame.
* **Create Unknown:** Tests the serialization of an unknown frame type.
* **Create Unknown Unchecked:** Tests serialization of an unknown frame with specific attributes.
* **Read Compressed Headers:** Verifies the parsing of compressed headers in a HEADERS frame.
* **Read Compressed Headers with Half Close:**  Verifies parsing of compressed headers in a HEADERS frame with the END_STREAM flag.
* **Too Large Headers Frame Uses Continuation:**  Confirms that large header blocks in HEADERS frames are correctly split into CONTINUATION frames.
* **Multiple Continuation Frames with Iterator:**  Tests the use of an iterator to serialize a large header block across multiple CONTINUATION frames.
* **PushPromise Frames with Iterator:** Tests the use of an iterator to serialize a large header block in a PUSH_PROMISE frame across multiple CONTINUATION frames.
* **Control Frame Iterator Tests (RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, ALTSVC, PRIORITY):**  These test the functionality of iterators for various control frames.
* **Too Large PushPromise Frame Uses Continuation:** Similar to the HEADERS frame test, verifies CONTINUATION for large PUSH_PROMISE frames.
* **Control Frame Much Too Large:** Tests how the framer handles excessively large header blocks and how a visitor can limit the data it receives.
* **Control Frame Sizes Are Validated:** Checks error handling for control frames with invalid sizes.
* **Read Zero Len Settings Frame:**  Verifies that a zero-length SETTINGS frame is handled correctly.
* **Read Bogus Len Settings Frame:** Checks error handling for SETTINGS frames with invalid lengths.
* **Read Large Settings Frame:** Tests the processing of SETTINGS frames with multiple settings.
* **Read Duplicate Settings:**  Verifies the handling of duplicate settings within a SETTINGS frame.
* **Read Unknown Settings Id:**  Tests how the framer handles unknown setting IDs.

**Planning the Response Structure:**

The response should follow the user's prompt structure, addressing each point systematically. The summary should synthesize the information extracted from the analyzed snippets.
这是目录为 `net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc` 的 Chromium 网络栈的源代码文件的第 4 部分，共 7 部分。根据提供的代码片段，我们可以归纳一下它的功能：

**本部分 (`spdy_framer_test.cc` 的一部分) 的主要功能是测试 `SpdyFramer` 类在处理和生成 HTTP/2 帧时的各种场景，特别是针对控制帧和头部块的处理。**  它涵盖了以下几个方面：

1. **错误处理：**
   - 测试当接收到意外的帧类型（例如，在期望其他帧时收到 `CONTINUATION` 帧）时，`SpdyFramer` 如何检测和报告错误。

2. **帧的创建和序列化：**
   - 测试 `SpdyFramer` 类创建特定类型帧（例如 `PUSH_PROMISE`, `ALTSVC`, `PRIORITY`, `PRIORITY_UPDATE`, `ACCEPT_CH`, 以及自定义的 `UNKNOWN` 帧）的正确性，并验证序列化后的帧数据是否符合预期格式。
   - 特别关注了头部块的序列化，包括头部块如何被分割成多个 `CONTINUATION` 帧，以及如何处理带有填充的帧。

3. **帧的读取和反序列化：**
   - 测试 `SpdyFramer` 如何正确地解析和处理接收到的各种帧，包括压缩的头部块。
   - 验证 `SpdyFramer` 能否处理头部块被分割到多个 `CONTINUATION` 帧的情况。
   - 测试对于过大的头部块的处理，以及如何使用迭代器来序列化和处理这些大的头部块。

4. **控制帧大小的校验：**
   - 测试 `SpdyFramer` 是否正确地验证接收到的控制帧的大小是否有效，例如，`GOAWAY` 帧的最小长度，以及 `SETTINGS` 帧的长度是否与其包含的设置数量一致。

5. **`SETTINGS` 帧的特殊处理：**
   - 测试 `SpdyFramer` 对 `SETTINGS` 帧的各种场景的处理，包括：
     - 零长度的 `SETTINGS` 帧。
     - 长度错误的 `SETTINGS` 帧。
     - 包含多个设置项的 `SETTINGS` 帧。
     - 包含重复设置项的 `SETTINGS` 帧。
     - 包含未知设置 ID 的 `SETTINGS` 帧。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的 HTTP/2 协议是 Web 浏览器与服务器通信的基础。JavaScript 发起的网络请求最终会通过浏览器的网络栈，涉及到 HTTP/2 协议的处理。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch()` API 发起一个 HTTP/2 请求，服务器返回一个 `PUSH_PROMISE` 帧，指示即将推送一个资源。 这段代码中的测试 `TEST_P(SpdyFramerTest, CreatePushPromiseThenContinuationUncompressed)`  就模拟了 `PUSH_PROMISE` 帧的创建，而相关的解析逻辑也会在浏览器接收到服务器的 `PUSH_PROMISE` 帧时被执行。

**假设输入与输出 (逻辑推理):**

**示例 1:  CONTINUATION 帧错误处理**

* **假设输入:**  接收到以下字节序列，尝试解析 HTTP/2 帧：
  ```
  0x00, 0x00, 0x12,        // Length: 18
  0x09,                    //   Type: CONTINUATION
  0x04,                    //  Flags: END_HEADERS
  0x00, 0x00, 0x00, 0x2a,  // Stream: 42
  0x00,              // Unindexed Entry
  0x03,              // Name Len: 3
  0x62, 0x61, 0x72,  // bar
  0x03,              // Value Len: 3
  0x66, 0x6f, 0x6f,  // foo
  0x00,              // Unindexed Entry
  0x03,              // Name Len: 3
  0x66, 0x6f, 0x6f,  // foo
  0x03,              // Value Len: 3
  0x62, 0x61, 0x72,  // bar
  ```
* **预期输出:**  `SpdyFramer` 会检测到这是一个意外的 `CONTINUATION` 帧，因为它前面没有对应的 `HEADERS` 或 `PUSH_PROMISE` 帧。`OnError` 回调会被调用，指示 `SPDY_UNEXPECTED_FRAME` 错误。

**示例 2: 创建并序列化 ALTSVC 帧**

* **假设输入:**  调用 `SpdyFramer::SerializeFrame` 方法，并传入一个配置好的 `SpdyAltSvcIR` 对象，描述了可用的替代服务。
* **预期输出:**  `SpdyFramer` 会生成一个符合 HTTP/2 规范的 `ALTSVC` 帧的字节序列，如 `kFrameData` 数组所示：
  ```
  0x00, 0x00, 0x49, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 'o',
  'r',  'i',  'g',  'i',   'n',  'p',  'i',  'd',  '1',  '=',  '"',  'h',
  'o',  's',  't',  ':',   '4',  '4',  '3',  '"',  ';',  ' ',  'm',  'a',
  '=',  '5',  ',',  'p',   '%',  '2',  '2',  '%',  '3',  'D',  'i',  '%',
  '3',  'A',  'd',  '=',   '"',  'h',  '_',  '\\', '\\', 'o',  '\\', '"',
  's',  't',  ':',  '1',   '2',  '3',  '"',  ';',  ' ',  'm',  'a',  '=',
  '4',  '2',  ';',  ' ',   'v',  '=',  '"',  '2',  '4',  '"'
  ```

**用户或编程常见的使用错误：**

1. **在没有发送 `HEADERS` 或 `PUSH_PROMISE` 帧的情况下发送 `CONTINUATION` 帧:** 这是协议错误，`SpdyFramer` 会检测到并报错。
2. **构造的帧长度与实际负载长度不匹配:** 例如，手动构造一个 `SETTINGS` 帧，声明长度为 8 字节，但实际包含的设置项需要的字节数更多或更少。`SpdyFramer` 会进行校验并报告 `SPDY_INVALID_CONTROL_FRAME_SIZE` 错误。
3. **发送过大的头部块而不使用 `CONTINUATION` 帧:**  HTTP/2 对单个帧的大小有限制。如果尝试发送一个包含过大头部块的 `HEADERS` 或 `PUSH_PROMISE` 帧，但不将其分割成多个 `CONTINUATION` 帧，则会导致错误。
4. **错误地计算或设置帧的标志位:** 例如，在 `HEADERS` 帧中忘记设置 `END_HEADERS` 标志，导致接收端一直等待后续的 `CONTINUATION` 帧。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个支持 HTTP/2 的网站时遇到了问题，例如页面加载缓慢或者资源加载失败。作为调试线索，开发者可能会：

1. **使用 Chrome 的开发者工具 (F12):**  在 "Network" 标签页中查看网络请求的详细信息，包括请求头和响应头，以及传输的帧。
2. **启用网络日志记录:** Chrome 允许记录网络事件到日志文件。开发者可以分析这些日志，查看浏览器发送和接收的 HTTP/2 帧的原始数据。
3. **使用网络抓包工具 (如 Wireshark):** 捕获浏览器和服务器之间的网络数据包，并分析其中的 HTTP/2 帧。
4. **如果问题涉及到 QUIC (基于 HTTP/2):**  `spdy_framer_test.cc` 中测试的逻辑也适用于 QUIC 的 HTTP/2 部分。当浏览器使用 QUIC 连接时，底层的帧处理逻辑与 HTTP/2 类似。

如果开发者怀疑是 HTTP/2 帧的解析或生成过程中出现了问题，他们可能会查看 `net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc` 的代码，并可能通过添加日志或断点来跟踪帧的处理过程。  `spdy_framer_test.cc` 中的测试用例可以帮助开发者理解 `SpdyFramer` 的预期行为，并验证他们的修复是否正确。例如，如果开发者在日志中看到接收到了一个意外的 `CONTINUATION` 帧，他们可能会参考 `TEST_P(SpdyFramerTest, ContinuationAfterContinuationError)` 这个测试用例来理解这种错误的场景和 `SpdyFramer` 的处理方式。

**总结 (本部分功能):**

总而言之，本部分的 `spdy_framer_test.cc` 主要负责测试 `SpdyFramer` 类在处理各种 HTTP/2 控制帧，特别是包含头部块的帧 (如 `HEADERS` 和 `PUSH_PROMISE`) 时的正确性和健壮性。它覆盖了帧的创建、序列化、反序列化、错误处理以及对帧大小的校验等关键方面，确保网络栈能够正确地处理和生成符合 HTTP/2 协议规范的帧。 此外，它也测试了 `SETTINGS` 帧的各种边界情况和异常情况。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
/ frame-format off
  char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x09,                    //   Type: CONTINUATION
      0x04,                    //  Flags: END_HEADERS
      0x00, 0x00, 0x00, 0x2a,  // Stream: 42

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x62, 0x61, 0x72,  // bar
      0x03,              // Value Len: 3
      0x66, 0x6f, 0x6f,  // foo

      0x00,              // Unindexed Entry
      0x03,              // Name Len: 3
      0x66, 0x6f, 0x6f,  // foo
      0x03,              // Value Len: 3
      0x62, 0x61, 0x72,  // bar
  };
  // frame-format on

  SpdySerializedFrame frame =
      MakeSerializedFrame(kH2FrameData, sizeof(kH2FrameData));

  // We shouldn't have to read the whole frame before we signal an error.
  EXPECT_CALL(visitor, OnCommonHeader(42, 18, 0x9, 0x4));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME, _));
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

TEST_P(SpdyFramerTest, CreatePushPromiseThenContinuationUncompressed) {
  {
    // Test framing in a case such that a PUSH_PROMISE frame, with one byte of
    // padding, cannot hold all the data payload, which is overflowed to the
    // consecutive CONTINUATION frame.
    SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
    const char kDescription[] =
        "PUSH_PROMISE and CONTINUATION frames with one byte of padding";

    // frame-format off
    const unsigned char kPartialPushPromiseFrameData[] = {
        0x00, 0x3f, 0xf6,        // Length: 16374
        0x05,                    //   Type: PUSH_PROMISE
        0x08,                    //  Flags: PADDED
        0x00, 0x00, 0x00, 0x2a,  // Stream: 42
        0x00,                    // PadLen: 0 trailing bytes
        0x00, 0x00, 0x00, 0x39,  // Promise: 57

        0x00,                    // Unindexed Entry
        0x03,                    // Name Len: 3
        0x78, 0x78, 0x78,        // xxx
        0x7f, 0x80, 0x7f,        // Value Len: 16361
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
    };
    const unsigned char kContinuationFrameData[] = {
        0x00, 0x00, 0x16,        // Length: 22
        0x09,                    //   Type: CONTINUATION
        0x04,                    //  Flags: END_HEADERS
        0x00, 0x00, 0x00, 0x2a,  // Stream: 42
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78, 0x78, 0x78, 0x78,  // xxxx
        0x78,                    // x
    };
    // frame-format on

    SpdyPushPromiseIR push_promise(/* stream_id = */ 42,
                                   /* promised_stream_id = */ 57);
    push_promise.set_padding_len(1);
    std::string big_value(kHttp2MaxControlFrameSendSize, 'x');
    push_promise.SetHeader("xxx", big_value);
    SpdySerializedFrame frame(SpdyFramerPeer::SerializePushPromise(
        &framer, push_promise, use_output_ ? &output_ : nullptr));

    // The entire frame should look like below:
    // Name                     Length in Byte
    // ------------------------------------------- Begin of PUSH_PROMISE frame
    // PUSH_PROMISE header      9
    // Pad length field         1
    // Promised stream          4
    // Length field of key      2
    // Content of key           3
    // Length field of value    3
    // Part of big_value        16361
    // ------------------------------------------- Begin of CONTINUATION frame
    // CONTINUATION header      9
    // Remaining of big_value   22
    // ------------------------------------------- End

    // Length of everything listed above except big_value.
    int len_non_data_payload = 31;
    EXPECT_EQ(kHttp2MaxControlFrameSendSize + len_non_data_payload,
              frame.size());

    // Partially compare the PUSH_PROMISE frame against the template.
    const unsigned char* frame_data =
        reinterpret_cast<const unsigned char*>(frame.data());
    CompareCharArraysWithHexError(kDescription, frame_data,
                                  ABSL_ARRAYSIZE(kPartialPushPromiseFrameData),
                                  kPartialPushPromiseFrameData,
                                  ABSL_ARRAYSIZE(kPartialPushPromiseFrameData));

    // Compare the CONTINUATION frame against the template.
    frame_data += kHttp2MaxControlFrameSendSize;
    CompareCharArraysWithHexError(
        kDescription, frame_data, ABSL_ARRAYSIZE(kContinuationFrameData),
        kContinuationFrameData, ABSL_ARRAYSIZE(kContinuationFrameData));
  }
}

TEST_P(SpdyFramerTest, CreateAltSvc) {
  const char kDescription[] = "ALTSVC frame";
  const unsigned char kType = SerializeFrameType(SpdyFrameType::ALTSVC);
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x49, kType, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 'o',
      'r',  'i',  'g',  'i',   'n',  'p',  'i',  'd',  '1',  '=',  '"',  'h',
      'o',  's',  't',  ':',   '4',  '4',  '3',  '"',  ';',  ' ',  'm',  'a',
      '=',  '5',  ',',  'p',   '%',  '2',  '2',  '%',  '3',  'D',  'i',  '%',
      '3',  'A',  'd',  '=',   '"',  'h',  '_',  '\\', '\\', 'o',  '\\', '"',
      's',  't',  ':',  '1',   '2',  '3',  '"',  ';',  ' ',  'm',  'a',  '=',
      '4',  '2',  ';',  ' ',   'v',  '=',  '"',  '2',  '4',  '"'};
  SpdyAltSvcIR altsvc_ir(/* stream_id = */ 3);
  altsvc_ir.set_origin("origin");
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector()));
  altsvc_ir.add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "p\"=i:d", "h_\\o\"st", 123, 42,
      SpdyAltSvcWireFormat::VersionVector{24}));
  SpdySerializedFrame frame(framer_.SerializeFrame(altsvc_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(altsvc_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

TEST_P(SpdyFramerTest, CreatePriority) {
  const char kDescription[] = "PRIORITY frame";
  const unsigned char kFrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x02,                    //   Type: PRIORITY
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x02,  // Stream: 2
      0x80, 0x00, 0x00, 0x01,  // Parent: 1 (Exclusive)
      0x10,                    // Weight: 17
  };
  SpdyPriorityIR priority_ir(/* stream_id = */ 2,
                             /* parent_stream_id = */ 1,
                             /* weight = */ 17,
                             /* exclusive = */ true);
  SpdySerializedFrame frame(framer_.SerializeFrame(priority_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(priority_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

TEST_P(SpdyFramerTest, CreatePriorityUpdate) {
  const char kDescription[] = "PRIORITY_UPDATE frame";
  const unsigned char kType =
      SerializeFrameType(SpdyFrameType::PRIORITY_UPDATE);
  const unsigned char kFrameData[] = {
      0x00,  0x00, 0x07,        // frame length
      kType,                    // frame type
      0x00,                     // flags
      0x00,  0x00, 0x00, 0x00,  // stream ID, must be 0 for PRIORITY_UPDATE
      0x00,  0x00, 0x00, 0x03,  // prioritized stream ID
      'u',   '=',  '0'};        // priority field value
  SpdyPriorityUpdateIR priority_update_ir(/* stream_id = */ 0,
                                          /* prioritized_stream_id = */ 3,
                                          /* priority_field_value = */ "u=0");
  SpdySerializedFrame frame(framer_.SerializeFrame(priority_update_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(priority_update_ir, &output_),
              frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

TEST_P(SpdyFramerTest, CreateAcceptCh) {
  const char kDescription[] = "ACCEPT_CH frame";
  const unsigned char kType = SerializeFrameType(SpdyFrameType::ACCEPT_CH);
  const unsigned char kFrameData[] = {
      0x00,  0x00, 0x2d,                  // frame length
      kType,                              // frame type
      0x00,                               // flags
      0x00,  0x00, 0x00, 0x00,            // stream ID, must be 0 for ACCEPT_CH
      0x00,  0x0f,                        // origin length
      'w',   'w',  'w',  '.',  'e', 'x',  // origin
      'a',   'm',  'p',  'l',  'e', '.',  //
      'c',   'o',  'm',                   //
      0x00,  0x03,                        // value length
      'f',   'o',  'o',                   // value
      0x00,  0x10,                        // origin length
      'm',   'a',  'i',  'l',  '.', 'e',  //
      'x',   'a',  'm',  'p',  'l', 'e',  //
      '.',   'c',  'o',  'm',             //
      0x00,  0x03,                        // value length
      'b',   'a',  'r'};                  // value
  SpdyAcceptChIR accept_ch_ir(
      {{"www.example.com", "foo"}, {"mail.example.com", "bar"}});
  SpdySerializedFrame frame(framer_.SerializeFrame(accept_ch_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(accept_ch_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

TEST_P(SpdyFramerTest, CreateUnknown) {
  const char kDescription[] = "Unknown frame";
  const uint8_t kType = 0xaf;
  const uint8_t kFlags = 0x11;
  const uint8_t kLength = strlen(kDescription);
  const unsigned char kFrameData[] = {
      0x00,   0x00, kLength,        // Length: 13
      kType,                        //   Type: undefined
      kFlags,                       //  Flags: arbitrary, undefined
      0x00,   0x00, 0x00,    0x02,  // Stream: 2
      0x55,   0x6e, 0x6b,    0x6e,  // "Unkn"
      0x6f,   0x77, 0x6e,    0x20,  // "own "
      0x66,   0x72, 0x61,    0x6d,  // "fram"
      0x65,                         // "e"
  };
  SpdyUnknownIR unknown_ir(/* stream_id = */ 2,
                           /* type = */ kType,
                           /* flags = */ kFlags,
                           /* payload = */ kDescription);
  SpdySerializedFrame frame(framer_.SerializeFrame(unknown_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(unknown_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

// Test serialization of a SpdyUnknownIR with a defined type, a length field
// that does not match the payload size and in fact exceeds framer limits, and a
// stream ID that effectively flips the reserved bit.
TEST_P(SpdyFramerTest, CreateUnknownUnchecked) {
  const char kDescription[] = "Unknown frame";
  const uint8_t kType = 0x00;
  const uint8_t kFlags = 0x11;
  const uint8_t kLength = std::numeric_limits<uint8_t>::max();
  const unsigned int kStreamId = kStreamIdMask + 42;
  const unsigned char kFrameData[] = {
      0x00,   0x00, kLength,        // Length: 16426
      kType,                        //   Type: DATA, defined
      kFlags,                       //  Flags: arbitrary, undefined
      0x80,   0x00, 0x00,    0x29,  // Stream: 2147483689
      0x55,   0x6e, 0x6b,    0x6e,  // "Unkn"
      0x6f,   0x77, 0x6e,    0x20,  // "own "
      0x66,   0x72, 0x61,    0x6d,  // "fram"
      0x65,                         // "e"
  };
  TestSpdyUnknownIR unknown_ir(/* stream_id = */ kStreamId,
                               /* type = */ kType,
                               /* flags = */ kFlags,
                               /* payload = */ kDescription);
  unknown_ir.set_length(kLength);
  SpdySerializedFrame frame(framer_.SerializeFrame(unknown_ir));
  if (use_output_) {
    EXPECT_EQ(framer_.SerializeFrame(unknown_ir, &output_), frame.size());
    frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  CompareFrame(kDescription, frame, kFrameData, ABSL_ARRAYSIZE(kFrameData));
}

TEST_P(SpdyFramerTest, ReadCompressedHeadersHeaderBlock) {
  SpdyHeadersIR headers_ir(/* stream_id = */ 1);
  headers_ir.SetHeader("alpha", "beta");
  headers_ir.SetHeader("gamma", "delta");
  SpdySerializedFrame control_frame(SpdyFramerPeer::SerializeHeaders(
      &framer_, headers_ir, use_output_ ? &output_ : nullptr));
  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.end_of_stream_count_);
  EXPECT_EQ(headers_ir.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, ReadCompressedHeadersHeaderBlockWithHalfClose) {
  SpdyHeadersIR headers_ir(/* stream_id = */ 1);
  headers_ir.set_fin(true);
  headers_ir.SetHeader("alpha", "beta");
  headers_ir.SetHeader("gamma", "delta");
  SpdySerializedFrame control_frame(SpdyFramerPeer::SerializeHeaders(
      &framer_, headers_ir, use_output_ ? &output_ : nullptr));
  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.control_frame_header_data_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
  EXPECT_EQ(headers_ir.header_block(), visitor.headers_);
}

TEST_P(SpdyFramerTest, TooLargeHeadersFrameUsesContinuation) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = kHttp2MaxControlFrameSendSize;
  std::string big_value(kBigValueSize, 'x');
  headers.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(SpdyFramerPeer::SerializeHeaders(
      &framer, headers, use_output_ ? &output_ : nullptr));
  EXPECT_GT(control_frame.size(), kHttp2MaxControlFrameSendSize);

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
}

TEST_P(SpdyFramerTest, MultipleContinuationFramesWithIterator) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
  auto headers = std::make_unique<SpdyHeadersIR>(/* stream_id = */ 1);
  headers->set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = kHttp2MaxControlFrameSendSize;
  std::string big_valuex(kBigValueSize, 'x');
  headers->SetHeader("aa", big_valuex);
  std::string big_valuez(kBigValueSize, 'z');
  headers->SetHeader("bb", big_valuez);

  SpdyFramer::SpdyHeaderFrameIterator frame_it(&framer, std::move(headers));

  EXPECT_TRUE(frame_it.HasNextFrame());
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame headers_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());
  EXPECT_EQ(headers_frame.size(), kHttp2MaxControlFrameSendSize);

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(headers_frame.data()),
      headers_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  output_.Reset();
  EXPECT_TRUE(frame_it.HasNextFrame());
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame first_cont_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());
  EXPECT_EQ(first_cont_frame.size(), kHttp2MaxControlFrameSendSize);

  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(first_cont_frame.data()),
      first_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  output_.Reset();
  EXPECT_TRUE(frame_it.HasNextFrame());
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame second_cont_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());
  EXPECT_LT(second_cont_frame.size(), kHttp2MaxControlFrameSendSize);

  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(second_cont_frame.data()),
      second_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_FALSE(frame_it.HasNextFrame());
}

TEST_P(SpdyFramerTest, PushPromiseFramesWithIterator) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
  auto push_promise =
      std::make_unique<SpdyPushPromiseIR>(/* stream_id = */ 1,
                                          /* promised_stream_id = */ 2);
  push_promise->set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = kHttp2MaxControlFrameSendSize;
  std::string big_valuex(kBigValueSize, 'x');
  push_promise->SetHeader("aa", big_valuex);
  std::string big_valuez(kBigValueSize, 'z');
  push_promise->SetHeader("bb", big_valuez);

  SpdyFramer::SpdyPushPromiseFrameIterator frame_it(&framer,
                                                    std::move(push_promise));

  EXPECT_TRUE(frame_it.HasNextFrame());
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame push_promise_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());
  EXPECT_EQ(push_promise_frame.size(), kHttp2MaxControlFrameSendSize);

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(push_promise_frame.data()),
      push_promise_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(0, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_TRUE(frame_it.HasNextFrame());
  output_.Reset();
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame first_cont_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());

  EXPECT_EQ(first_cont_frame.size(), kHttp2MaxControlFrameSendSize);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(first_cont_frame.data()),
      first_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_TRUE(frame_it.HasNextFrame());
  output_.Reset();
  EXPECT_GT(frame_it.NextFrame(&output_), 0u);
  SpdySerializedFrame second_cont_frame =
      MakeSerializedFrame(output_.Begin(), output_.Size());
  EXPECT_LT(second_cont_frame.size(), kHttp2MaxControlFrameSendSize);

  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(second_cont_frame.data()),
      second_cont_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(2, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);

  EXPECT_FALSE(frame_it.HasNextFrame());
}

class SpdyControlFrameIteratorTest : public quiche::test::QuicheTest {
 public:
  SpdyControlFrameIteratorTest() : output_(output_buffer, kSize) {}

  void RunTest(std::unique_ptr<SpdyFrameIR> ir) {
    SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
    SpdySerializedFrame frame(framer.SerializeFrame(*ir));
    std::unique_ptr<SpdyFrameSequence> it =
        SpdyFramer::CreateIterator(&framer, std::move(ir));
    EXPECT_TRUE(it->HasNextFrame());
    EXPECT_EQ(it->NextFrame(&output_), frame.size());
    EXPECT_FALSE(it->HasNextFrame());
  }

 private:
  ArrayOutputBuffer output_;
};

TEST_F(SpdyControlFrameIteratorTest, RstStreamFrameWithIterator) {
  auto ir = std::make_unique<SpdyRstStreamIR>(0, ERROR_CODE_PROTOCOL_ERROR);
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, SettingsFrameWithIterator) {
  auto ir = std::make_unique<SpdySettingsIR>();
  uint32_t kValue = 0x0a0b0c0d;
  SpdyKnownSettingsId kId = SETTINGS_INITIAL_WINDOW_SIZE;
  ir->AddSetting(kId, kValue);
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, PingFrameWithIterator) {
  const SpdyPingId kPingId = 0x123456789abcdeffULL;
  auto ir = std::make_unique<SpdyPingIR>(kPingId);
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, GoAwayFrameWithIterator) {
  auto ir = std::make_unique<SpdyGoAwayIR>(0, ERROR_CODE_NO_ERROR, "GA");
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, WindowUpdateFrameWithIterator) {
  auto ir = std::make_unique<SpdyWindowUpdateIR>(1, 1);
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, AtlSvcFrameWithIterator) {
  auto ir = std::make_unique<SpdyAltSvcIR>(3);
  ir->set_origin("origin");
  ir->add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "pid1", "host", 443, 5, SpdyAltSvcWireFormat::VersionVector()));
  ir->add_altsvc(SpdyAltSvcWireFormat::AlternativeService(
      "p\"=i:d", "h_\\o\"st", 123, 42,
      SpdyAltSvcWireFormat::VersionVector{24}));
  RunTest(std::move(ir));
}

TEST_F(SpdyControlFrameIteratorTest, PriorityFrameWithIterator) {
  auto ir = std::make_unique<SpdyPriorityIR>(2, 1, 17, true);
  RunTest(std::move(ir));
}

TEST_P(SpdyFramerTest, TooLargePushPromiseFrameUsesContinuation) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);
  SpdyPushPromiseIR push_promise(/* stream_id = */ 1,
                                 /* promised_stream_id = */ 2);
  push_promise.set_padding_len(256);

  // Exact payload length will change with HPACK, but this should be long
  // enough to cause an overflow.
  const size_t kBigValueSize = kHttp2MaxControlFrameSendSize;
  std::string big_value(kBigValueSize, 'x');
  push_promise.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(SpdyFramerPeer::SerializePushPromise(
      &framer, push_promise, use_output_ ? &output_ : nullptr));
  EXPECT_GT(control_frame.size(), kHttp2MaxControlFrameSendSize);

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_TRUE(visitor.header_buffer_valid_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(1, visitor.continuation_count_);
  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
}

// Check that the framer stops delivering header data chunks once the visitor
// declares it doesn't want any more. This is important to guard against
// "zip bomb" types of attacks.
TEST_P(SpdyFramerTest, ControlFrameMuchTooLarge) {
  const size_t kHeaderBufferChunks = 4;
  const size_t kHeaderBufferSize =
      kHttp2DefaultFramePayloadLimit / kHeaderBufferChunks;
  const size_t kBigValueSize = kHeaderBufferSize * 2;
  std::string big_value(kBigValueSize, 'x');
  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.set_fin(true);
  headers.SetHeader("aa", big_value);
  SpdySerializedFrame control_frame(SpdyFramerPeer::SerializeHeaders(
      &framer_, headers, use_output_ ? &output_ : nullptr));
  TestSpdyVisitor visitor(SpdyFramer::ENABLE_COMPRESSION);
  visitor.set_header_buffer_size(kHeaderBufferSize);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  // It's up to the visitor to ignore extraneous header data; the framer
  // won't throw an error.
  EXPECT_GT(visitor.header_bytes_received_, visitor.header_buffer_size_);
  EXPECT_EQ(1, visitor.end_of_stream_count_);
}

TEST_P(SpdyFramerTest, ControlFrameSizesAreValidated) {
  // Create a GoAway frame that has a few extra bytes at the end.
  const size_t length = 20;

  // HTTP/2 GOAWAY frames are only bound by a minimal length, since they may
  // carry opaque data. Verify that minimal length is tested.
  ASSERT_GT(kGoawayFrameMinimumSize, kFrameHeaderSize);
  const size_t less_than_min_length =
      kGoawayFrameMinimumSize - kFrameHeaderSize - 1;
  ASSERT_LE(less_than_min_length, std::numeric_limits<unsigned char>::max());
  const unsigned char kH2Len = static_cast<unsigned char>(less_than_min_length);
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, kH2Len,        // Length: min length - 1
      0x07,                      //   Type: GOAWAY
      0x00,                      //  Flags: none
      0x00, 0x00, 0x00,   0x00,  // Stream: 0
      0x00, 0x00, 0x00,   0x00,  //   Last: 0
      0x00, 0x00, 0x00,          // Truncated Status Field
  };
  const size_t pad_length = length + kFrameHeaderSize - sizeof(kH2FrameData);
  std::string pad(pad_length, 'A');
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);

  visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));
  visitor.SimulateInFramer(reinterpret_cast<const unsigned char*>(pad.c_str()),
                           pad.length());

  EXPECT_EQ(1, visitor.error_count_);  // This generated an error.
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
  EXPECT_EQ(0, visitor.goaway_count_);  // Frame not parsed.
}

TEST_P(SpdyFramerTest, ReadZeroLenSettingsFrame) {
  SpdySettingsIR settings_ir;
  SpdySerializedFrame control_frame(framer_.SerializeSettings(settings_ir));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
    control_frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  SetFrameLength(&control_frame, 0);
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()), kFrameHeaderSize);
  // Zero-len settings frames are permitted as of HTTP/2.
  EXPECT_EQ(0, visitor.error_count_);
}

// Tests handling of SETTINGS frames with invalid length.
TEST_P(SpdyFramerTest, ReadBogusLenSettingsFrame) {
  SpdySettingsIR settings_ir;

  // Add settings to more than fill the frame so that we don't get a buffer
  // overflow when calling SimulateInFramer() below. These settings must be
  // distinct parameters because SpdySettingsIR has a map for settings, and
  // will collapse multiple copies of the same parameter.
  settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 0x00000002);
  settings_ir.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 0x00000002);
  SpdySerializedFrame control_frame(framer_.SerializeSettings(settings_ir));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
    control_frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }
  const size_t kNewLength = 8;
  SetFrameLength(&control_frame, kNewLength);
  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      kFrameHeaderSize + kNewLength);
  // Should generate an error, since its not possible to have a
  // settings frame of length kNewLength.
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME_SIZE,
            visitor.deframer_.spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             visitor.deframer_.spdy_framer_error());
}

// Tests handling of larger SETTINGS frames.
TEST_P(SpdyFramerTest, ReadLargeSettingsFrame) {
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SETTINGS_HEADER_TABLE_SIZE, 5);
  settings_ir.AddSetting(SETTINGS_ENABLE_PUSH, 6);
  settings_ir.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 7);

  SpdySerializedFrame control_frame(framer_.SerializeSettings(settings_ir));
  if (use_output_) {
    ASSERT_TRUE(framer_.SerializeSettings(settings_ir, &output_));
    control_frame = MakeSerializedFrame(output_.Begin(), output_.Size());
  }

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);

  // Read all at once.
  visitor.SimulateInFramer(
      reinterpret_cast<unsigned char*>(control_frame.data()),
      control_frame.size());
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(3, visitor.setting_count_);
  EXPECT_EQ(1, visitor.settings_ack_sent_);

  // Read data in small chunks.
  size_t framed_data = 0;
  size_t unframed_data = control_frame.size();
  size_t kReadChunkSize = 5;  // Read five bytes at a time.
  while (unframed_data > 0) {
    size_t to_read = std::min(kReadChunkSize, unframed_data);
    visitor.SimulateInFramer(
        reinterpret_cast<unsigned char*>(control_frame.data() + framed_data),
        to_read);
    unframed_data -= to_read;
    framed_data += to_read;
  }
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(3 * 2, visitor.setting_count_);
  EXPECT_EQ(2, visitor.settings_ack_sent_);
}

// Tests handling of SETTINGS frame with duplicate entries.
TEST_P(SpdyFramerTest, ReadDuplicateSettings) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x12,        // Length: 18
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
      0x00, 0x01,              //  Param: HEADER_TABLE_SIZE
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
      0x00, 0x03,              //  Param: MAX_CONCURRENT_STREAMS
      0x00, 0x00, 0x00, 0x03,  //  Value: 3
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));

  // In HTTP/2, duplicate settings are allowed;
  // each setting replaces the previous value for that setting.
  EXPECT_EQ(3, visitor.setting_count_);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.settings_ack_sent_);
}

// Tests handling of SETTINGS frame with a setting we don't recognize.
TEST_P(SpdyFramerTest, ReadUnknownSettingsId) {
  const unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x06,        // Length: 6
      0x04,                    //   Type: SETTINGS
      0x00,                    //  Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream: 0
      0x00, 0x10,              //  Param: 16
      0x00, 0x00, 0x00, 0x02,  //  Value: 2
  };

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(kH2FrameData, sizeof(kH2FrameData));

  // In HTTP/2, we ignore
```