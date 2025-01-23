Response:
The user wants me to analyze a C++ source code file for HTTP/3 frame decoding tests.

Here's a breakdown of the thought process to address the request:

1. **Understand the Core Functionality:** The file `http_decoder_test.cc` tests the `HttpDecoder` class. This class is responsible for taking raw byte streams representing HTTP/3 frames and parsing them into structured data. The tests verify that the decoder correctly identifies frame types, extracts data, and handles errors.

2. **Identify Key Test Cases:** The provided code snippet contains various `TEST_F` macros, each targeting a specific HTTP/3 frame type or scenario. I need to enumerate these to summarize the file's functionalities. The test names themselves are quite descriptive (e.g., `EmptySettingsFrame`, `LargeStreamIdInGoAway`, `CorruptPriorityUpdateFrame`).

3. **Look for JavaScript Relevance:** HTTP/3 is a network protocol. While JavaScript doesn't directly interact with the binary decoding process, it's crucial for web browsers and Node.js servers. The decoded frames impact how a JavaScript application receives and processes data. I need to consider the *impact* of this code on JavaScript, not direct interaction.

4. **Address Logic Reasoning (Input/Output):**  Each test case implicitly performs logic reasoning. I can pick a few representative tests and explicitly state the input (byte sequence) and the expected output (actions on the `MockHttpDecoderVisitor`).

5. **Consider User/Programming Errors:**  The "Corrupt" test cases are excellent examples of testing error handling. Empty frames or malformed data are common errors. I need to explain *how* such errors might arise.

6. **Debug Path (User Actions):**  To understand how a user's action could lead to this code being executed, I need to think about the chain of events in a network request. A user action in a browser triggers a network request, which eventually involves decoding HTTP/3 frames.

7. **Part 2 Summary:** Since this is part 2 of the analysis, I need to synthesize the findings from *this* part and provide a concise summary of the functionalities covered in the given code snippet.

**Pre-computation and Pre-analysis (Internal Mocking):**

* **`HttpDecoder`:**  The class under test. Its main method is likely `ProcessInput`.
* **`MockHttpDecoderVisitor`:**  An interface (mock object) to verify the actions taken by the `HttpDecoder`. The tests use `EXPECT_CALL` to set expectations on this visitor.
* **HTTP/3 Frame Types:** I need to be familiar with some common HTTP/3 frame types like SETTINGS, GOAWAY, MAX_PUSH_ID, PRIORITY_UPDATE, ACCEPT_CH, ORIGIN, and potentially web transport streams. The test names give clues about these.
* **Varint Encoding:**  HTTP/3 uses variable-length integers. The tests involving multi-byte identifiers (like in `DecodeSettings`) touch upon this.
* **Error Handling:** The tests use `EXPECT_THAT(decoder_.error(), ...)` to verify the error state and detail.

**Step-by-step detailed thought for a specific test case (e.g., `EmptySettingsFrame`):**

1. **Read the test name:** `EmptySettingsFrame`. This suggests testing the handling of a SETTINGS frame with no content.
2. **Examine the input:**  `absl::HexStringToBytes("04" "00", &input)`. "04" is likely the SETTINGS frame type, and "00" indicates a zero-length payload.
3. **Analyze the `EXPECT_CALL`:** `EXPECT_CALL(visitor_, OnSettingsFrame(empty_frame))`. This means the test expects the `HttpDecoder` to successfully parse an empty SETTINGS frame and call the `OnSettingsFrame` method on the visitor with an `empty_frame` object.
4. **Analyze the processing:** `ProcessInput(input)`. This calls the `HttpDecoder`'s main processing method.
5. **Analyze the assertions:**
   - `EXPECT_EQ(input.size(), ProcessInput(input))`: Verifies that all input bytes were processed.
   - `EXPECT_THAT(decoder_.error(), IsQuicNoError())`: Checks that no error occurred during decoding.
   - `EXPECT_EQ("", decoder_.error_detail())`: Ensures there's no error message.
6. **Formulate the description:** An empty SETTINGS frame is valid. The decoder should process it without errors and notify the visitor.

By applying similar steps to other test cases, I can systematically analyze the functionality of the code. For JavaScript relevance, I connect the successful decoding of these frames to the delivery of data to web applications. For user errors, I consider scenarios where the network might transmit incomplete or incorrect data.

Finally, for the "Part 2 Summary," I consolidate the identified functionalities from the provided code snippet, such as handling various frame types, including those that trigger errors due to incorrect formatting or being empty, and the ability to decode settings frames.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/http/http_decoder_test.cc` 文件的第二部分，它主要包含了针对 `HttpDecoder` 类的单元测试，用于验证 HTTP/3 帧的解码功能是否正确。

**归纳一下它的功能：**

这部分代码主要测试了 `HttpDecoder` 类处理各种特定 HTTP/3 帧的能力，包括：

* **处理空帧:** 测试解码器如何处理长度为 0 的 `SETTINGS`、`GOAWAY` 和 `MAX_PUSH_ID` 帧。这通常会触发错误，因为这些帧需要携带一些数据。
* **处理 `GOAWAY` 帧:** 测试解码器能否正确解析包含大 Stream ID 的 `GOAWAY` 帧。
* **处理过时的 `PRIORITY_UPDATE` 帧:** 测试解码器如何将过时的 `PRIORITY_UPDATE` 帧识别为未知帧并进行处理。
* **处理新的 `PRIORITY_UPDATE` 帧:**  详细测试了 `PRIORITY_UPDATE` 帧的解码过程，包括正常情况、访问者暂停处理的情况以及增量处理的情况。也测试了格式错误的 `PRIORITY_UPDATE` 帧的错误处理。
* **处理 `ACCEPT_CH` 帧:** 测试了解码器处理 `ACCEPT_CH` 帧的能力，包括空帧和带有 origin/value 对的情况，并涵盖了访问者暂停和增量处理的场景。
* **处理 `ORIGIN` 帧:** 测试了解码器处理 `ORIGIN` 帧的能力，包括空帧和包含多个 Origin 的情况，并区分了该功能启用和禁用的两种情况。
* **处理 WebTransport 流:** 测试了解码器在 WebTransport 功能启用和禁用时，对特定帧类型的处理方式。
* **解码 `SETTINGS` 帧:** 测试了 `HttpDecoder` 类中的静态方法 `DecodeSettings`，用于直接从字节流解码 `SETTINGS` 帧，并验证了正确和错误的输入情况。

**与 JavaScript 功能的关系 (举例说明):**

虽然这段 C++ 代码本身不包含 JavaScript，但它解码的 HTTP/3 帧直接影响着浏览器或 Node.js 环境中 JavaScript 的行为。

* **`SETTINGS` 帧:**  当浏览器接收到服务器发送的 `SETTINGS` 帧时，这些设置会影响浏览器的 HTTP/3 连接的行为，例如最大并发流数量、头部压缩表的大小等。这些设置最终会影响 JavaScript 发起的网络请求的性能和行为。例如，如果 `SETTINGS_MAX_CONCURRENT_STREAMS` 设置得较低，JavaScript 发起的多个 `fetch` 请求可能会被排队，而不是并行执行。
* **`GOAWAY` 帧:** 当服务器发送 `GOAWAY` 帧时，它指示服务器即将关闭连接或停止接受新的流。浏览器中的 JavaScript 代码可能会收到网络错误，或者需要重新建立连接来继续进行网络操作。
* **`ACCEPT_CH` 帧:**  这个帧允许服务器声明它支持的客户端提示 (Client Hints)。浏览器接收到这个帧后，后续的 JavaScript 发起的请求可能会自动带上相应的客户端提示头部，从而让服务器可以根据客户端能力提供更优化的内容。
* **`ORIGIN` 帧:** 这个帧允许服务器声明哪些源被认为是同一 Origin 的一部分。这会影响浏览器的安全策略，以及 JavaScript 中跨域请求的行为。
* **WebTransport 流:** 如果启用了 WebTransport，JavaScript 可以使用 WebTransport API 创建双向的数据流。这段代码测试了底层对 WebTransport 特定帧类型的解码，确保 JavaScript 可以正确地发送和接收数据。

**逻辑推理 (假设输入与输出):**

**例子 1: `EmptyGoAwayFrame` 测试**

* **假设输入:** 字节序列 `07 00` (十六进制)，其中 `07` 是 `GOAWAY` 帧类型，`00` 表示长度为 0。
* **预期输出:**
    * `HttpDecoderVisitor` 的 `OnError` 方法被调用。
    * `decoder_.error()` 返回一个表示 HTTP 帧错误的错误码 (`QUIC_HTTP_FRAME_ERROR`)。
    * `decoder_.error_detail()` 返回错误信息 "Unable to read GOAWAY ID."。

**例子 2:  `LargeStreamIdInGoAway` 测试**

* **假设输入:** 由 `HttpEncoder::SerializeGoAwayFrame` 生成的包含一个非常大的 Stream ID (1ull << 60) 的 `GOAWAY` 帧的字节序列。
* **预期输出:**
    * `HttpDecoderVisitor` 的 `OnGoAwayFrame` 方法被调用，并传入一个 `GoAwayFrame` 对象，其 `id` 成员为 1ull << 60。
    * `decoder_.error()` 返回 `IsQuicNoError()`。
    * `decoder_.error_detail()` 返回空字符串。

**用户或编程常见的使用错误 (举例说明):**

* **发送不完整的帧数据:** 如果编程时，在发送 HTTP/3 帧时只发送了帧头，而没有发送完整的数据载荷，`HttpDecoder` 在尝试读取数据时会遇到错误。例如，发送了一个类型为 `SETTINGS`，长度为 5 的帧头，但只发送了 3 个字节的数据，解码器会报告错误。
* **帧长度字段与实际数据不符:**  如果编码器计算的帧长度与实际写入的数据长度不一致，解码器会因为尝试读取超出实际数据范围的数据而报错。
* **发送不支持的帧类型:**  如果客户端或服务器发送了 `HttpDecoder` 当前版本不支持的帧类型，解码器可能会将其识别为未知帧，或者直接报错。
* **在需要数据的帧中发送空数据:**  例如 `EmptyGoAwayFrame` 测试的情况，虽然帧头是有效的，但 `GOAWAY` 帧期望包含一个 Stream ID，如果长度字段为 0，解码器会报告错误。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中发起一个 HTTP/3 请求:** 例如，用户在地址栏输入一个以 `https://` 开头的 URL，并且该网站支持 HTTP/3。
2. **浏览器与服务器建立 QUIC 连接:**  这是 HTTP/3 的底层传输协议。
3. **浏览器或服务器发送 HTTP/3 帧:**  在连接建立后，浏览器和服务器会通过发送各种 HTTP/3 帧进行通信，例如 `HEADERS` 帧 (包含 HTTP 请求头)，`DATA` 帧 (包含 HTTP 消息体)，`SETTINGS` 帧 (协商连接参数) 等。
4. **接收端的网络栈接收到这些字节流:**  操作系统内核或网络库会接收到来自网络的字节流。
5. **QUIC 层处理字节流:** QUIC 层负责处理连接管理、拥塞控制、丢包重传等。
6. **HTTP/3 解码器 (`HttpDecoder`) 被调用:** 当接收到属于 HTTP/3 的数据时，QUIC 层会将数据交给 `HttpDecoder` 进行处理。
7. **`HttpDecoder::ProcessInput` 方法被调用:**  `HttpDecoder` 的 `ProcessInput` 方法会读取字节流，解析帧头，确定帧类型和长度，然后根据帧类型调用相应的处理逻辑。
8. **单元测试模拟了这个过程:**  `http_decoder_test.cc` 中的测试用例通过构造特定的字节序列，然后调用 `HttpDecoder::ProcessInput` 方法，来模拟网络中接收到各种 HTTP/3 帧的情况。如果解码过程中出现错误，测试会捕获这些错误，帮助开发者定位问题。

因此，当在生产环境中遇到 HTTP/3 相关的问题时，例如连接建立失败、请求失败、数据传输错误等，开发者可能会需要查看 `HttpDecoder` 的代码和相关的测试用例，来理解解码过程中可能出现的问题。`http_decoder_test.cc` 文件中的测试用例就提供了一些常见的错误场景，可以帮助开发者更好地理解和调试 HTTP/3 的实现。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/http_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
visitor_, OnSettingsFrame(empty_frame));

  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, EmptyGoAwayFrame) {
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("07"   // type (GOAWAY)
                             "00",  // frame length
                             &input));

  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_ERROR));
  EXPECT_EQ("Unable to read GOAWAY ID.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, EmptyMaxPushIdFrame) {
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("0d"   // type (MAX_PUSH_ID)
                             "00",  // frame length
                             &input));

  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_ERROR));
  EXPECT_EQ("Unable to read MAX_PUSH_ID push_id.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, LargeStreamIdInGoAway) {
  GoAwayFrame frame;
  frame.id = 1ull << 60;
  std::string goaway = HttpEncoder::SerializeGoAwayFrame(frame);
  EXPECT_CALL(visitor_, OnGoAwayFrame(frame));
  EXPECT_GT(goaway.length(), 0u);
  EXPECT_EQ(goaway.length(),
            decoder_.ProcessInput(goaway.data(), goaway.length()));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

// Old PRIORITY_UPDATE frame is parsed as unknown frame.
TEST_F(HttpDecoderTest, ObsoletePriorityUpdateFrame) {
  const QuicByteCount header_length = 2;
  const QuicByteCount payload_length = 3;
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("0f"       // type (obsolete PRIORITY_UPDATE)
                             "03"       // length
                             "666f6f",  // payload "foo"
                             &input));

  // Process frame as a whole.
  EXPECT_CALL(visitor_,
              OnUnknownFrameStart(0x0f, header_length, payload_length));
  EXPECT_CALL(visitor_, OnUnknownFramePayload(Eq("foo")));
  EXPECT_CALL(visitor_, OnUnknownFrameEnd()).WillOnce(Return(false));

  EXPECT_EQ(header_length + payload_length,
            ProcessInputWithGarbageAppended(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process frame byte by byte.
  EXPECT_CALL(visitor_,
              OnUnknownFrameStart(0x0f, header_length, payload_length));
  EXPECT_CALL(visitor_, OnUnknownFramePayload(Eq("f")));
  EXPECT_CALL(visitor_, OnUnknownFramePayload(Eq("o")));
  EXPECT_CALL(visitor_, OnUnknownFramePayload(Eq("o")));
  EXPECT_CALL(visitor_, OnUnknownFrameEnd());

  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, PriorityUpdateFrame) {
  InSequence s;
  std::string input1;
  ASSERT_TRUE(
      absl::HexStringToBytes("800f0700"  // type (PRIORITY_UPDATE)
                             "01"        // length
                             "03",       // prioritized element id
                             &input1));

  PriorityUpdateFrame priority_update1;
  priority_update1.prioritized_element_id = 0x03;

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5)).WillOnce(Return(false));
  absl::string_view remaining_input(input1);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(5u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update1))
      .WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5));
  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update1));
  EXPECT_EQ(input1.size(), ProcessInput(input1));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5));
  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update1));
  ProcessInputCharByChar(input1);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  std::string input2;
  ASSERT_TRUE(
      absl::HexStringToBytes("800f0700"  // type (PRIORITY_UPDATE)
                             "04"        // length
                             "05"        // prioritized element id
                             "666f6f",   // priority field value: "foo"
                             &input2));

  PriorityUpdateFrame priority_update2;
  priority_update2.prioritized_element_id = 0x05;
  priority_update2.priority_field_value = "foo";

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5)).WillOnce(Return(false));
  remaining_input = input2;
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(5u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update2))
      .WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5));
  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update2));
  EXPECT_EQ(input2.size(), ProcessInput(input2));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(5));
  EXPECT_CALL(visitor_, OnPriorityUpdateFrame(priority_update2));
  ProcessInputCharByChar(input2);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, CorruptPriorityUpdateFrame) {
  std::string payload;
  ASSERT_TRUE(absl::HexStringToBytes("4005",  // prioritized element id
                                     &payload));
  struct {
    size_t payload_length;
    const char* const error_message;
  } kTestData[] = {
      {0, "Unable to read prioritized element id."},
      {1, "Unable to read prioritized element id."},
  };

  for (const auto& test_data : kTestData) {
    std::string input;
    ASSERT_TRUE(absl::HexStringToBytes("800f0700",  // type PRIORITY_UPDATE
                                       &input));
    input.push_back(test_data.payload_length);
    size_t header_length = input.size();
    input.append(payload.data(), test_data.payload_length);

    HttpDecoder decoder(&visitor_);
    EXPECT_CALL(visitor_, OnPriorityUpdateFrameStart(header_length));
    EXPECT_CALL(visitor_, OnError(&decoder));

    QuicByteCount processed_bytes =
        decoder.ProcessInput(input.data(), input.size());
    EXPECT_EQ(input.size(), processed_bytes);
    EXPECT_THAT(decoder.error(), IsError(QUIC_HTTP_FRAME_ERROR));
    EXPECT_EQ(test_data.error_message, decoder.error_detail());
  }
}

TEST_F(HttpDecoderTest, AcceptChFrame) {
  InSequence s;
  std::string input1;
  ASSERT_TRUE(
      absl::HexStringToBytes("4089"  // type (ACCEPT_CH)
                             "00",   // length
                             &input1));

  AcceptChFrame accept_ch1;

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3)).WillOnce(Return(false));
  absl::string_view remaining_input(input1);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(3u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch1)).WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3));
  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch1));
  EXPECT_EQ(input1.size(), ProcessInput(input1));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3));
  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch1));
  ProcessInputCharByChar(input1);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  std::string input2;
  ASSERT_TRUE(
      absl::HexStringToBytes("4089"     // type (ACCEPT_CH)
                             "08"       // length
                             "03"       // length of origin
                             "666f6f"   // origin "foo"
                             "03"       // length of value
                             "626172",  // value "bar"
                             &input2));

  AcceptChFrame accept_ch2;
  accept_ch2.entries.push_back({"foo", "bar"});

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3)).WillOnce(Return(false));
  remaining_input = input2;
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(3u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch2)).WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3));
  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch2));
  EXPECT_EQ(input2.size(), ProcessInput(input2));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnAcceptChFrameStart(3));
  EXPECT_CALL(visitor_, OnAcceptChFrame(accept_ch2));
  ProcessInputCharByChar(input2);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, OriginFrame) {
  if (!GetQuicReloadableFlag(enable_h3_origin_frame)) {
    return;
  }
  InSequence s;
  std::string input1;
  ASSERT_TRUE(
      absl::HexStringToBytes("0C"   // type (ORIGIN)
                             "00",  // length
                             &input1));

  OriginFrame origin1;

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2)).WillOnce(Return(false));
  absl::string_view remaining_input(input1);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(2u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnOriginFrame(origin1)).WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2));
  EXPECT_CALL(visitor_, OnOriginFrame(origin1));
  EXPECT_EQ(input1.size(), ProcessInput(input1));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2));
  EXPECT_CALL(visitor_, OnOriginFrame(origin1));
  ProcessInputCharByChar(input1);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  std::string input2;
  ASSERT_TRUE(
      absl::HexStringToBytes("0C"       // type (ORIGIN)
                             "0A"       // length
                             "0003"     // length of origin
                             "666f6f"   // origin "foo"
                             "0003"     // length of origin
                             "626172",  // origin "bar"
                             &input2));
  ASSERT_EQ(12, input2.length());

  OriginFrame origin2;
  origin2.origins = {"foo", "bar"};

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2)).WillOnce(Return(false));
  remaining_input = input2;
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(2u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnOriginFrame(origin2)).WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2));
  EXPECT_CALL(visitor_, OnOriginFrame(origin2));
  EXPECT_EQ(input2.size(), ProcessInput(input2));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnOriginFrameStart(2));
  EXPECT_CALL(visitor_, OnOriginFrame(origin2));
  ProcessInputCharByChar(input2);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, OriginFrameDisabled) {
  if (GetQuicReloadableFlag(enable_h3_origin_frame)) {
    return;
  }
  InSequence s;

  std::string input1;
  ASSERT_TRUE(
      absl::HexStringToBytes("0C"   // type (ORIGIN)
                             "00",  // length
                             &input1));
  EXPECT_CALL(visitor_, OnUnknownFrameStart(0x0C, 2, 0));
  EXPECT_CALL(visitor_, OnUnknownFrameEnd());
  EXPECT_EQ(ProcessInput(input1), input1.size());

  std::string input2;
  ASSERT_TRUE(
      absl::HexStringToBytes("0C"       // type (ORIGIN)
                             "0A"       // length
                             "0003"     // length of origin
                             "666f6f"   // origin "foo"
                             "0003"     // length of origin
                             "626172",  // origin "bar"
                             &input2));
  EXPECT_CALL(visitor_, OnUnknownFrameStart(0x0C, 2, input2.size() - 2));
  EXPECT_CALL(visitor_, OnUnknownFramePayload(input2.substr(2)));
  EXPECT_CALL(visitor_, OnUnknownFrameEnd());
  EXPECT_EQ(ProcessInput(input2), input2.size());
}

TEST_F(HttpDecoderTest, WebTransportStreamDisabled) {
  InSequence s;

  // Unknown frame of type 0x41 and length 0x104.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("40414104", &input));
  EXPECT_CALL(visitor_, OnUnknownFrameStart(0x41, input.size(), 0x104));
  EXPECT_EQ(ProcessInput(input), input.size());
}

TEST(HttpDecoderTestNoFixture, WebTransportStream) {
  testing::StrictMock<MockHttpDecoderVisitor> visitor;
  HttpDecoder decoder(&visitor);
  decoder.EnableWebTransportStreamParsing();

  // WebTransport stream for session ID 0x104, with four bytes of extra data.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("40414104ffffffff", &input));
  EXPECT_CALL(visitor, OnWebTransportStreamFrameType(4, 0x104));
  QuicByteCount bytes = decoder.ProcessInput(input.data(), input.size());
  EXPECT_EQ(bytes, 4u);
}

TEST(HttpDecoderTestNoFixture, WebTransportStreamError) {
  testing::StrictMock<MockHttpDecoderVisitor> visitor;
  HttpDecoder decoder(&visitor);
  decoder.EnableWebTransportStreamParsing();

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("404100", &input));
  EXPECT_CALL(visitor, OnWebTransportStreamFrameType(_, _));
  decoder.ProcessInput(input.data(), input.size());

  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(visitor, OnError(_));
        decoder.ProcessInput(input.data(), input.size());
      },
      "HttpDecoder called after an indefinite-length frame");
}

TEST_F(HttpDecoderTest, DecodeSettings) {
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "04"    // type (SETTINGS)
      "07"    // length
      "01"    // identifier (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
      "02"    // content
      "06"    // identifier (SETTINGS_MAX_HEADER_LIST_SIZE)
      "05"    // content
      "4100"  // identifier, encoded on 2 bytes (0x40), value is 256 (0x100)
      "04",   // content
      &input));

  SettingsFrame frame;
  frame.values[1] = 2;
  frame.values[6] = 5;
  frame.values[256] = 4;

  SettingsFrame out;
  EXPECT_TRUE(HttpDecoder::DecodeSettings(input.data(), input.size(), &out));
  EXPECT_EQ(frame, out);

  // non-settings frame.
  ASSERT_TRUE(
      absl::HexStringToBytes("0D"   // type (MAX_PUSH_ID)
                             "01"   // length
                             "01",  // Push Id
                             &input));

  EXPECT_FALSE(HttpDecoder::DecodeSettings(input.data(), input.size(), &out));

  // Corrupt SETTINGS.
  ASSERT_TRUE(absl::HexStringToBytes(
      "04"   // type (SETTINGS)
      "01"   // length
      "42",  // First byte of setting identifier, indicating a 2-byte varint62.
      &input));

  EXPECT_FALSE(HttpDecoder::DecodeSettings(input.data(), input.size(), &out));
}

}  // namespace
}  // namespace test
}  // namespace quic
```