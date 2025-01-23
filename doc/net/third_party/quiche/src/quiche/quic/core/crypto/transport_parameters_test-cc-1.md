Response:
My thinking process to answer the prompt about the `transport_parameters_test.cc` file goes like this:

1. **Understand the Core Function:** The file name itself is a huge clue. It's a *test* file for *transport parameters*. This immediately tells me the file is about verifying the functionality of code that deals with the negotiation and handling of connection parameters in the QUIC protocol.

2. **Scan for Key Functions and Classes:** I'd quickly scan the code for important keywords and class names. I see `TransportParameters`, `ParseTransportParameters`, `SerializeTransportParameters`, `DegreaseTransportParameters`, and various `TEST_P` and `TEST_F` macros. This confirms my initial understanding and gives me specific functions to focus on.

3. **Identify the Testing Scope:** The `TEST_P` and `TEST_F` macros indicate parameterized and non-parameterized tests. Looking at the test names (`ParseClientHello`, `ParseServerHello`, `SerializeClientHello`, etc.) reveals that the tests cover both parsing and serializing transport parameters, and they differentiate between client and server perspectives.

4. **Analyze Specific Test Cases:** I'd go through some of the individual test cases to understand what specific aspects are being tested. For example:
    * `ParseClientHello`: Tests successful parsing of client transport parameters.
    * `ParseServerHello`: Tests successful parsing of server transport parameters, including optional fields like `preferred_address`.
    * `ParseServerParametersRepeated`: Tests error handling for repeated parameters.
    * `ParseServerParametersEmptyOriginalConnectionId`: Tests handling of an empty connection ID.
    * `VeryLongCustomParameter`: Tests handling of large custom parameters.
    * `SerializationOrderIsRandom`: Tests that the serialization order is not deterministic.
    * `Degrease`: Tests the "degreasing" process (removing optional parameters).
    * `TransportParametersTicketSerializationTest`: Focuses on parameters relevant to session resumption tickets.

5. **Relate to QUIC Concepts:**  I'd connect the code to my knowledge of the QUIC protocol. Transport parameters are a fundamental part of the QUIC handshake. They define limits, timeouts, and other connection-specific settings. The tests verify that these parameters are correctly encoded, decoded, and handled by the QUIC implementation.

6. **Consider JavaScript Relevance (if any):**  I know that QUIC is often used in web browsers and other applications that interact with JavaScript. Therefore, I'd think about how these transport parameters might affect JavaScript code. For instance, knowing the `max_idle_timeout` could be relevant for JavaScript applications that need to keep connections alive or handle disconnections. However, the *direct* manipulation of these parameters is usually handled by the browser's networking stack, not directly by JavaScript. So, the connection is more about the *effects* of these parameters on the browser environment.

7. **Infer Logical Reasoning and Examples:**  Based on the test cases, I can infer the logical reasoning behind the code. For example, the parsing logic needs to handle different parameter IDs and lengths. The serialization logic needs to encode the parameters correctly. I can also construct hypothetical input and output examples based on the provided byte arrays in the tests.

8. **Identify Potential User/Programming Errors:**  The "repeated parameter" test case directly points to a common error – sending the same parameter multiple times. Another potential error is providing incorrect lengths for parameters, which the parsing tests would catch.

9. **Trace User Operations (Debugging):** I would consider how a user's action in a browser (like navigating to a website) would trigger the QUIC handshake and the processing of these transport parameters. This involves the browser sending a `ClientHello`, the server responding with a `ServerHello`, and the exchange of transport parameters as part of that process.

10. **Synthesize and Summarize:** Finally, I'd synthesize my understanding into a concise summary of the file's purpose and key functionalities, drawing upon the insights gained in the previous steps. I would also address the specific points raised in the prompt (JavaScript relevance, logical reasoning, common errors, debugging). For the second part of the prompt, I'd focus on the tests related to server parameters specifically, summarizing their purpose in the connection establishment from the server's perspective.

Essentially, I'm applying a combination of code reading, domain knowledge (QUIC), and logical deduction to understand the purpose and functionality of the test file. The specific test cases provide concrete examples and allow me to infer the underlying logic being tested.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/crypto/transport_parameters_test.cc` 文件内容的第二部分分析，延续了第一部分对该文件功能的探讨。

**归纳其功能：**

这部分代码延续了第一部分的主题，即测试 QUIC 协议中传输参数的解析和序列化功能。具体来说，它涵盖了以下几个关键方面：

1. **服务端传输参数解析的更多测试用例:**
   - `ParseServerParameters`:  延续了对服务端发送的完整传输参数的解析测试，涵盖了更多的参数类型，例如 `min_ack_delay_us`, `disable_active_migration`, `reliable_stream_reset`, `preferred_address`, `active_connection_id_limit`, `initial_source_connection_id`, `retry_source_connection_id`, 以及 Google 的特定扩展参数 `google_connection_options` 和版本信息相关的参数。
   - `ParseServerParametersRepeated`:  测试了当服务端发送重复的传输参数时，解析器是否能正确检测并报错。这确保了参数的唯一性约束得到执行。
   - `ParseServerParametersEmptyOriginalConnectionId`: 测试了服务端发送的 `original_destination_connection_id` 为空时的处理逻辑。

2. **自定义参数的处理能力测试:**
   - `VeryLongCustomParameter`:  测试了对于非常长的自定义传输参数的处理能力，包括序列化和反序列化。这确保了 QUIC 可以灵活地扩展传输参数，而不会受到大小限制。

3. **序列化顺序随机性的测试:**
   - `SerializationOrderIsRandom`:  验证了传输参数的序列化顺序是非确定的。这是为了防止中间件依赖特定的序列化顺序，从而提高 QUIC 的健壮性和互操作性。

4. **“去油”（Degrease）功能的测试:**
   - `Degrease`:  测试了“去油”操作，即将解析出的传输参数中为了增加迷惑性和防止指纹识别而添加的额外参数（grease）移除的功能。这通常发生在客户端接收到服务端的传输参数后。

5. **会话票据（Session Ticket）中传输参数序列化的特定测试:**
   - `TransportParametersTicketSerializationTest`: 专门测试了用于生成会话票据的传输参数序列化功能。
   - `StatelessResetTokenDoesntChangeOutput`:  测试了在生成会话票据时，`stateless_reset_token` 的变化不会影响序列化结果。这是因为会话票据是用于恢复会话的，而 `stateless_reset_token` 通常与特定的连接实例相关。
   - `ConnectionIDDoesntChangeOutput`: 测试了 `original_destination_connection_id` 的变化也不会影响会话票据的序列化结果，原因与 `stateless_reset_token` 类似。
   - `StreamLimitChangesOutput`: 验证了流控制相关的传输参数的改变会影响会话票据的序列化结果，因为这些参数是会话状态的一部分。
   - `ApplicationStateChangesOutput`: 测试了与会话票据一起序列化的应用程序状态的改变会影响序列化结果。

**与 JavaScript 的关系:**

这部分代码仍然主要关注 QUIC 协议的底层实现，与 JavaScript 的直接关系不如高层 API 那么紧密。然而，理解这些底层的传输参数对于理解 QUIC 如何影响基于 JavaScript 的 Web 应用仍然很重要：

* **性能优化:** 像 `max_idle_timeout`, `initial_max_data`, `initial_max_streams_bidi` 等参数直接影响连接的生命周期和并发能力，从而影响 Web 应用的加载速度和用户体验。虽然 JavaScript 代码本身不直接设置这些参数，但浏览器会根据服务器提供的这些参数来管理连接。
* **连接迁移和可靠性:** `disable_active_migration` 和 `preferred_address` 等参数影响连接的迁移行为，这对于移动设备等网络环境不稳定的场景至关重要。JavaScript 应用可以受益于 QUIC 提供的连接迁移能力，而无需显式处理网络切换。
* **安全性和隐私:**  虽然这部分代码没有直接涉及加密，但传输参数的协商是 QUIC 握手过程的一部分，而握手是建立安全连接的关键环节。

**逻辑推理的假设输入与输出 (以 `ParseServerParameters` 为例):**

**假设输入:** 一段包含服务端传输参数的字节数组 `kServerParams` (如代码所示)。

**逻辑推理:**  `ParseTransportParameters` 函数会按照 QUIC 规范解析这段字节数组，提取出各个传输参数的 ID、长度和值，并将它们存储到 `TransportParameters` 结构体 `new_params` 中。

**预期输出:** `new_params` 结构体中的各个字段会被正确赋值，例如：
   - `new_params.original_destination_connection_id` 的值应为 `CreateFakeOriginalDestinationConnectionId()` 的结果。
   - `new_params.max_idle_timeout_ms` 的值应为 `kFakeIdleTimeoutMilliseconds`。
   - `new_params.preferred_address` 应该包含正确的 IPv4 和 IPv6 地址、端口以及关联的连接 ID 和 stateless reset token。
   - 其他参数也应该按照 `kServerParams` 中的值被正确解析。

**用户或编程常见的使用错误 (以 `ParseServerParametersRepeated` 为例):**

* **用户操作:** 如果服务端代码在实现 QUIC 握手时，错误地将同一个传输参数多次添加到要发送的参数列表中。
* **编程错误:**  服务端代码逻辑错误，例如循环添加参数时没有检查是否已经添加过。
* **后果:**  客户端在解析服务端发送的传输参数时，会遇到重复的参数 ID。按照 QUIC 规范，这应该被视为错误。
* **测试用例的验证:** `ParseServerParametersRepeated` 测试用例验证了当出现这种情况时，`ParseTransportParameters` 函数会返回 `false`，并且 `error_details` 会包含 "Received a second max_idle_timeout" 这样的错误信息，从而帮助开发者定位问题。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户发起连接:** 用户在浏览器地址栏输入网址或点击链接，浏览器开始尝试与服务器建立连接。
2. **QUIC 协商:** 如果浏览器和服务器都支持 QUIC，它们会尝试使用 QUIC 协议进行连接。
3. **TLS 握手和传输参数交换:** QUIC 的连接建立过程涉及到 TLS 握手，其中传输参数是加密交换的一部分。
4. **服务端发送 ServerHello:** 服务器在 TLS 握手过程中会发送 `ServerHello` 消息，其中包含了服务端的传输参数。这部分代码中定义的 `kServerParams` 模拟了 `ServerHello` 中传输参数的编码。
5. **客户端解析传输参数:** 客户端接收到 `ServerHello` 后，会调用 `ParseTransportParameters` 函数来解析服务端发送的传输参数。
6. **调试场景:** 如果客户端在解析服务端传输参数时发生错误，例如遇到了重复的参数，那么 `ParseServerParametersRepeated` 这个测试用例就可以作为调试的线索。开发者可以检查服务端发送的传输参数是否符合规范，是否存在重复发送的情况。

**总结来说，这部分代码专注于验证 QUIC 协议中服务端传输参数的解析和序列化逻辑的正确性、健壮性和灵活性，包括处理各种类型的参数、应对错误情况以及支持会话恢复。**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/transport_parameters_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ue
      // initial_max_stream_data_uni
      0x07,  // parameter id
      0x02,  // length
      0x4B, 0xB8,  // value
      // initial_max_streams_bidi
      0x08,  // parameter id
      0x01,  // length
      0x15,  // value
      // initial_max_streams_uni
      0x09,  // parameter id
      0x01,  // length
      0x16,  // value
      // ack_delay_exponent
      0x0a,  // parameter id
      0x01,  // length
      0x0a,  // value
      // max_ack_delay
      0x0b,  // parameter id
      0x01,  // length
      0x33,  // value
      // min_ack_delay_us
      0x80, 0x00, 0xde, 0x1a,  // parameter id
      0x02,  // length
      0x43, 0xe8,  // value
      // disable_active_migration
      0x0c,  // parameter id
      0x00,  // length
      // reliable_stream_reset
      0xc0, 0x17, 0xf7, 0x58, 0x6d, 0x2c, 0xb5, 0x71,  // parameter id
      0x00,  // length
      // preferred_address
      0x0d,  // parameter id
      0x31,  // length
      0x41, 0x42, 0x43, 0x44,  // IPv4 address
      0x48, 0x84,  // IPv4 port
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,  // IPv6 address
      0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
      0x63, 0x36,  // IPv6 port
      0x08,        // connection ID length
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF,  // connection ID
      0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,  // stateless reset token
      0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
      // active_connection_id_limit
      0x0e,  // parameter id
      0x01,  // length
      0x34,  // value
      // initial_source_connection_id
      0x0f,  // parameter id
      0x08,  // length
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x45,
      // retry_source_connection_id
      0x10,  // parameter id
      0x08,  // length
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x76,
      // google_connection_options
      0x71, 0x28,  // parameter id
      0x0c,  // length
      'A', 'L', 'P', 'N',  // value
      'E', 'F', 'G', 0x00,
      'H', 'I', 'J', 0xff,
      // Google version extension
      0x80, 0x00, 0x47, 0x52,  // parameter id
      0x0d,  // length
      0x01, 0x23, 0x45, 0x67,  // negotiated_version
      0x08,  // length of supported versions array
      0x01, 0x23, 0x45, 0x67,
      0x89, 0xab, 0xcd, 0xef,
      // version_information
      0x80, 0xFF, 0x73, 0xDB,  // parameter id
      0x0C,  // length
      0x01, 0x23, 0x45, 0x67,  // chosen version
      0x01, 0x23, 0x45, 0x67,  // other version 1
      0x89, 0xab, 0xcd, 0xef,  // other version 2
  };
  // clang-format on
  const uint8_t* server_params =
      reinterpret_cast<const uint8_t*>(kServerParams);
  size_t server_params_length = ABSL_ARRAYSIZE(kServerParams);
  TransportParameters new_params;
  std::string error_details;
  ASSERT_TRUE(ParseTransportParameters(version_, Perspective::IS_SERVER,
                                       server_params, server_params_length,
                                       &new_params, &error_details))
      << error_details;
  EXPECT_TRUE(error_details.empty());
  EXPECT_EQ(Perspective::IS_SERVER, new_params.perspective);
  ASSERT_TRUE(new_params.legacy_version_information.has_value());
  EXPECT_EQ(kFakeVersionLabel,
            new_params.legacy_version_information.value().version);
  ASSERT_EQ(
      2u,
      new_params.legacy_version_information.value().supported_versions.size());
  EXPECT_EQ(
      kFakeVersionLabel,
      new_params.legacy_version_information.value().supported_versions[0]);
  EXPECT_EQ(
      kFakeVersionLabel2,
      new_params.legacy_version_information.value().supported_versions[1]);
  ASSERT_TRUE(new_params.version_information.has_value());
  EXPECT_EQ(new_params.version_information.value(),
            CreateFakeVersionInformation());
  ASSERT_TRUE(new_params.original_destination_connection_id.has_value());
  EXPECT_EQ(CreateFakeOriginalDestinationConnectionId(),
            new_params.original_destination_connection_id.value());
  EXPECT_EQ(kFakeIdleTimeoutMilliseconds,
            new_params.max_idle_timeout_ms.value());
  EXPECT_EQ(CreateStatelessResetTokenForTest(),
            new_params.stateless_reset_token);
  EXPECT_EQ(kMaxPacketSizeForTest, new_params.max_udp_payload_size.value());
  EXPECT_EQ(kFakeInitialMaxData, new_params.initial_max_data.value());
  EXPECT_EQ(kFakeInitialMaxStreamDataBidiLocal,
            new_params.initial_max_stream_data_bidi_local.value());
  EXPECT_EQ(kFakeInitialMaxStreamDataBidiRemote,
            new_params.initial_max_stream_data_bidi_remote.value());
  EXPECT_EQ(kFakeInitialMaxStreamDataUni,
            new_params.initial_max_stream_data_uni.value());
  EXPECT_EQ(kFakeInitialMaxStreamsBidi,
            new_params.initial_max_streams_bidi.value());
  EXPECT_EQ(kFakeInitialMaxStreamsUni,
            new_params.initial_max_streams_uni.value());
  EXPECT_EQ(kAckDelayExponentForTest, new_params.ack_delay_exponent.value());
  EXPECT_EQ(kMaxAckDelayForTest, new_params.max_ack_delay.value());
  EXPECT_EQ(kMinAckDelayUsForTest, new_params.min_ack_delay_us.value());
  EXPECT_EQ(kFakeDisableMigration, new_params.disable_active_migration);
  EXPECT_EQ(kFakeReliableStreamReset, new_params.reliable_stream_reset);
  ASSERT_NE(nullptr, new_params.preferred_address.get());
  EXPECT_EQ(CreateFakeV4SocketAddress(),
            new_params.preferred_address->ipv4_socket_address);
  EXPECT_EQ(CreateFakeV6SocketAddress(),
            new_params.preferred_address->ipv6_socket_address);
  EXPECT_EQ(CreateFakePreferredConnectionId(),
            new_params.preferred_address->connection_id);
  EXPECT_EQ(CreateFakePreferredStatelessResetToken(),
            new_params.preferred_address->stateless_reset_token);
  EXPECT_EQ(kActiveConnectionIdLimitForTest,
            new_params.active_connection_id_limit.value());
  ASSERT_TRUE(new_params.initial_source_connection_id.has_value());
  EXPECT_EQ(CreateFakeInitialSourceConnectionId(),
            new_params.initial_source_connection_id.value());
  ASSERT_TRUE(new_params.retry_source_connection_id.has_value());
  EXPECT_EQ(CreateFakeRetrySourceConnectionId(),
            new_params.retry_source_connection_id.value());
  ASSERT_TRUE(new_params.google_connection_options.has_value());
  EXPECT_EQ(CreateFakeGoogleConnectionOptions(),
            new_params.google_connection_options.value());
}

TEST_P(TransportParametersTest, ParseServerParametersRepeated) {
  // clang-format off
  const uint8_t kServerParamsRepeated[] = {
      // original_destination_connection_id
      0x00,  // parameter id
      0x08,  // length
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x37,
      // max_idle_timeout
      0x01,  // parameter id
      0x02,  // length
      0x6e, 0xec,  // value
      // stateless_reset_token
      0x02,  // parameter id
      0x10,  // length
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      // max_idle_timeout (repeated)
      0x01,  // parameter id
      0x02,  // length
      0x6e, 0xec,  // value
  };
  // clang-format on
  const uint8_t* server_params =
      reinterpret_cast<const uint8_t*>(kServerParamsRepeated);
  size_t server_params_length = ABSL_ARRAYSIZE(kServerParamsRepeated);
  TransportParameters out_params;
  std::string error_details;
  EXPECT_FALSE(ParseTransportParameters(version_, Perspective::IS_SERVER,
                                        server_params, server_params_length,
                                        &out_params, &error_details));
  EXPECT_EQ(error_details, "Received a second max_idle_timeout");
}

TEST_P(TransportParametersTest,
       ParseServerParametersEmptyOriginalConnectionId) {
  // clang-format off
  const uint8_t kServerParamsEmptyOriginalConnectionId[] = {
      // original_destination_connection_id
      0x00,  // parameter id
      0x00,  // length
      // max_idle_timeout
      0x01,  // parameter id
      0x02,  // length
      0x6e, 0xec,  // value
      // stateless_reset_token
      0x02,  // parameter id
      0x10,  // length
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  };
  // clang-format on
  const uint8_t* server_params =
      reinterpret_cast<const uint8_t*>(kServerParamsEmptyOriginalConnectionId);
  size_t server_params_length =
      ABSL_ARRAYSIZE(kServerParamsEmptyOriginalConnectionId);
  TransportParameters out_params;
  std::string error_details;
  ASSERT_TRUE(ParseTransportParameters(version_, Perspective::IS_SERVER,
                                       server_params, server_params_length,
                                       &out_params, &error_details))
      << error_details;
  ASSERT_TRUE(out_params.original_destination_connection_id.has_value());
  EXPECT_EQ(out_params.original_destination_connection_id.value(),
            EmptyQuicConnectionId());
}

TEST_P(TransportParametersTest, VeryLongCustomParameter) {
  // Ensure we can handle a 70KB custom parameter on both send and receive.
  std::string custom_value(70000, '?');
  TransportParameters orig_params;
  orig_params.perspective = Perspective::IS_CLIENT;
  orig_params.legacy_version_information =
      CreateFakeLegacyVersionInformationClient();
  orig_params.custom_parameters[kCustomParameter1] = custom_value;

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParameters(orig_params, &serialized));

  TransportParameters new_params;
  std::string error_details;
  ASSERT_TRUE(ParseTransportParameters(version_, Perspective::IS_CLIENT,
                                       serialized.data(), serialized.size(),
                                       &new_params, &error_details))
      << error_details;
  EXPECT_TRUE(error_details.empty());
  RemoveGreaseParameters(&new_params);
  EXPECT_EQ(new_params, orig_params);
}

TEST_P(TransportParametersTest, SerializationOrderIsRandom) {
  TransportParameters orig_params;
  orig_params.perspective = Perspective::IS_CLIENT;
  orig_params.legacy_version_information =
      CreateFakeLegacyVersionInformationClient();
  orig_params.max_idle_timeout_ms.set_value(kFakeIdleTimeoutMilliseconds);
  orig_params.max_udp_payload_size.set_value(kMaxPacketSizeForTest);
  orig_params.initial_max_data.set_value(kFakeInitialMaxData);
  orig_params.initial_max_stream_data_bidi_local.set_value(
      kFakeInitialMaxStreamDataBidiLocal);
  orig_params.initial_max_stream_data_bidi_remote.set_value(
      kFakeInitialMaxStreamDataBidiRemote);
  orig_params.initial_max_stream_data_uni.set_value(
      kFakeInitialMaxStreamDataUni);
  orig_params.initial_max_streams_bidi.set_value(kFakeInitialMaxStreamsBidi);
  orig_params.initial_max_streams_uni.set_value(kFakeInitialMaxStreamsUni);
  orig_params.ack_delay_exponent.set_value(kAckDelayExponentForTest);
  orig_params.max_ack_delay.set_value(kMaxAckDelayForTest);
  orig_params.min_ack_delay_us.set_value(kMinAckDelayUsForTest);
  orig_params.disable_active_migration = kFakeDisableMigration;
  orig_params.reliable_stream_reset = kFakeReliableStreamReset;
  orig_params.active_connection_id_limit.set_value(
      kActiveConnectionIdLimitForTest);
  orig_params.initial_source_connection_id =
      CreateFakeInitialSourceConnectionId();
  orig_params.initial_round_trip_time_us.set_value(kFakeInitialRoundTripTime);
  orig_params.google_connection_options = CreateFakeGoogleConnectionOptions();
  orig_params.custom_parameters[kCustomParameter1] = kCustomParameter1Value;
  orig_params.custom_parameters[kCustomParameter2] = kCustomParameter2Value;

  std::vector<uint8_t> first_serialized;
  ASSERT_TRUE(SerializeTransportParameters(orig_params, &first_serialized));
  // Test that a subsequent serialization is different from the first.
  // Run in a loop to avoid a failure in the unlikely event that randomization
  // produces the same result multiple times.
  for (int i = 0; i < 1000; i++) {
    std::vector<uint8_t> serialized;
    ASSERT_TRUE(SerializeTransportParameters(orig_params, &serialized));
    if (serialized != first_serialized) {
      return;
    }
  }
}

TEST_P(TransportParametersTest, Degrease) {
  TransportParameters orig_params;
  orig_params.perspective = Perspective::IS_CLIENT;
  orig_params.legacy_version_information =
      CreateFakeLegacyVersionInformationClient();
  orig_params.version_information = CreateFakeVersionInformation();
  orig_params.max_idle_timeout_ms.set_value(kFakeIdleTimeoutMilliseconds);
  orig_params.max_udp_payload_size.set_value(kMaxPacketSizeForTest);
  orig_params.initial_max_data.set_value(kFakeInitialMaxData);
  orig_params.initial_max_stream_data_bidi_local.set_value(
      kFakeInitialMaxStreamDataBidiLocal);
  orig_params.initial_max_stream_data_bidi_remote.set_value(
      kFakeInitialMaxStreamDataBidiRemote);
  orig_params.initial_max_stream_data_uni.set_value(
      kFakeInitialMaxStreamDataUni);
  orig_params.initial_max_streams_bidi.set_value(kFakeInitialMaxStreamsBidi);
  orig_params.initial_max_streams_uni.set_value(kFakeInitialMaxStreamsUni);
  orig_params.ack_delay_exponent.set_value(kAckDelayExponentForTest);
  orig_params.max_ack_delay.set_value(kMaxAckDelayForTest);
  orig_params.min_ack_delay_us.set_value(kMinAckDelayUsForTest);
  orig_params.disable_active_migration = kFakeDisableMigration;
  orig_params.reliable_stream_reset = kFakeReliableStreamReset;
  orig_params.active_connection_id_limit.set_value(
      kActiveConnectionIdLimitForTest);
  orig_params.initial_source_connection_id =
      CreateFakeInitialSourceConnectionId();
  orig_params.initial_round_trip_time_us.set_value(kFakeInitialRoundTripTime);
  std::string google_handshake_message;
  ASSERT_TRUE(absl::HexStringToBytes(kFakeGoogleHandshakeMessage,
                                     &google_handshake_message));
  orig_params.google_handshake_message = std::move(google_handshake_message);
  orig_params.google_connection_options = CreateFakeGoogleConnectionOptions();
  orig_params.custom_parameters[kCustomParameter1] = kCustomParameter1Value;
  orig_params.custom_parameters[kCustomParameter2] = kCustomParameter2Value;

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParameters(orig_params, &serialized));

  TransportParameters new_params;
  std::string error_details;
  ASSERT_TRUE(ParseTransportParameters(version_, Perspective::IS_CLIENT,
                                       serialized.data(), serialized.size(),
                                       &new_params, &error_details))
      << error_details;
  EXPECT_TRUE(error_details.empty());

  // Deserialized parameters have grease added.
  EXPECT_NE(new_params, orig_params);

  DegreaseTransportParameters(new_params);
  EXPECT_EQ(new_params, orig_params);
}

class TransportParametersTicketSerializationTest : public QuicTest {
 protected:
  void SetUp() override {
    original_params_.perspective = Perspective::IS_SERVER;
    original_params_.legacy_version_information =
        CreateFakeLegacyVersionInformationServer();
    original_params_.original_destination_connection_id =
        CreateFakeOriginalDestinationConnectionId();
    original_params_.max_idle_timeout_ms.set_value(
        kFakeIdleTimeoutMilliseconds);
    original_params_.stateless_reset_token = CreateStatelessResetTokenForTest();
    original_params_.max_udp_payload_size.set_value(kMaxPacketSizeForTest);
    original_params_.initial_max_data.set_value(kFakeInitialMaxData);
    original_params_.initial_max_stream_data_bidi_local.set_value(
        kFakeInitialMaxStreamDataBidiLocal);
    original_params_.initial_max_stream_data_bidi_remote.set_value(
        kFakeInitialMaxStreamDataBidiRemote);
    original_params_.initial_max_stream_data_uni.set_value(
        kFakeInitialMaxStreamDataUni);
    original_params_.initial_max_streams_bidi.set_value(
        kFakeInitialMaxStreamsBidi);
    original_params_.initial_max_streams_uni.set_value(
        kFakeInitialMaxStreamsUni);
    original_params_.ack_delay_exponent.set_value(kAckDelayExponentForTest);
    original_params_.max_ack_delay.set_value(kMaxAckDelayForTest);
    original_params_.min_ack_delay_us.set_value(kMinAckDelayUsForTest);
    original_params_.disable_active_migration = kFakeDisableMigration;
    original_params_.reliable_stream_reset = kFakeReliableStreamReset;
    original_params_.preferred_address = CreateFakePreferredAddress();
    original_params_.active_connection_id_limit.set_value(
        kActiveConnectionIdLimitForTest);
    original_params_.initial_source_connection_id =
        CreateFakeInitialSourceConnectionId();
    original_params_.retry_source_connection_id =
        CreateFakeRetrySourceConnectionId();
    original_params_.google_connection_options =
        CreateFakeGoogleConnectionOptions();

    ASSERT_TRUE(SerializeTransportParametersForTicket(
        original_params_, application_state_, &original_serialized_params_));
  }

  TransportParameters original_params_;
  std::vector<uint8_t> application_state_ = {0, 1};
  std::vector<uint8_t> original_serialized_params_;
};

TEST_F(TransportParametersTicketSerializationTest,
       StatelessResetTokenDoesntChangeOutput) {
  // Test that changing the stateless reset token doesn't change the ticket
  // serialization.
  TransportParameters new_params = original_params_;
  new_params.stateless_reset_token = CreateFakePreferredStatelessResetToken();
  EXPECT_NE(new_params, original_params_);

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParametersForTicket(
      new_params, application_state_, &serialized));
  EXPECT_EQ(original_serialized_params_, serialized);
}

TEST_F(TransportParametersTicketSerializationTest,
       ConnectionIDDoesntChangeOutput) {
  // Changing original destination CID doesn't change serialization.
  TransportParameters new_params = original_params_;
  new_params.original_destination_connection_id = TestConnectionId(0xCAFE);
  EXPECT_NE(new_params, original_params_);

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParametersForTicket(
      new_params, application_state_, &serialized));
  EXPECT_EQ(original_serialized_params_, serialized);
}

TEST_F(TransportParametersTicketSerializationTest, StreamLimitChangesOutput) {
  // Changing a stream limit does change the serialization.
  TransportParameters new_params = original_params_;
  new_params.initial_max_stream_data_bidi_local.set_value(
      kFakeInitialMaxStreamDataBidiLocal + 1);
  EXPECT_NE(new_params, original_params_);

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParametersForTicket(
      new_params, application_state_, &serialized));
  EXPECT_NE(original_serialized_params_, serialized);
}

TEST_F(TransportParametersTicketSerializationTest,
       ApplicationStateChangesOutput) {
  // Changing the application state changes the serialization.
  std::vector<uint8_t> new_application_state = {0};
  EXPECT_NE(new_application_state, application_state_);

  std::vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeTransportParametersForTicket(
      original_params_, new_application_state, &serialized));
  EXPECT_NE(original_serialized_params_, serialized);
}

}  // namespace test
}  // namespace quic
```