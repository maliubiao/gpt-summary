Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a larger file related to QUIC transport parameters in Chromium's network stack. Specifically, this part seems to handle the serialization of transport parameters.

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the core function:** The code snippet is within a function that iterates through a list of `parameter_ids` and writes them to a buffer using a `QuicDataWriter`. This strongly suggests the function's primary purpose is to *serialize* transport parameters.

2. **Analyze the loop and switch statement:** The `for` loop iterates through `parameter_ids`, and the `switch` statement handles each parameter type individually. This means each `case` within the `switch` is responsible for serializing a specific transport parameter.

3. **Recognize serialization patterns:** Within each `case`, the code generally performs these steps:
    * Checks if the corresponding parameter data exists in the input `in`.
    * Writes the parameter's ID using `writer.WriteVarInt62()`.
    * Writes the parameter's value, potentially using helper methods like `Write`, `WriteStringPieceVarInt62`, `WriteUIntXX`, etc.
    * Includes error handling (`QUIC_BUG`) if writing fails.

4. **Identify key transport parameters:**  The `parameter_ids` list and the `case` statements reveal the various transport parameters being serialized, such as `original_destination_connection_id`, `max_idle_timeout`, `stateless_reset_token`, etc.

5. **Consider the "GREASE" parameter:**  The code explicitly adds a random "GREASE" parameter. This is a deliberate mechanism in QUIC to ensure robustness against unknown parameters.

6. **Think about the input and output:** The function takes an input structure (likely containing the transport parameter values) and writes the serialized data to an output buffer. This confirms the serialization purpose.

7. **Address the user's specific questions:**
    * **Functionality:** Summarize the core function as serializing transport parameters for QUIC.
    * **JavaScript relation:**  Transport parameters are exchanged during the QUIC handshake. While JavaScript itself doesn't directly serialize these low-level bytes, it *influences* the values through the WebTransport API or Fetch API (if QUIC is used). Emphasize that the serialization happens on the browser's networking stack (C++) and is opaque to JavaScript.
    * **Logical reasoning (input/output):** Create a simple example input structure and describe the expected serialized output format. Focus on a few key parameters to illustrate the process.
    * **User/programming errors:**  Point out common mistakes like providing incorrect data types, wrong sizes, or attempting to set incompatible parameters.
    * **User journey/debugging:** Explain how a user action in the browser (like accessing a website over HTTPS) triggers the QUIC handshake and the involvement of this serialization logic.
    * **Summarize the current part:** Focus on the serialization of the listed transport parameters, including the randomization and GREASE aspect.

8. **Structure the answer:** Organize the information logically with clear headings and examples. Use bullet points for lists.

9. **Refine the language:** Ensure the explanation is clear, concise, and avoids overly technical jargon where possible.

By following these steps, the detailed and comprehensive answer provided earlier can be constructed. The process involves understanding the code's purpose, dissecting its components, connecting it to the broader context of QUIC, and addressing each of the user's specific requirements.
```cpp
        if (!value_reader.IsDoneReading()) {
          uint32_t connection_option;
          if (!value_reader.ReadUInt32(&connection_option)) {
            *error_details = "Unable to parse google connection option";
            return false;
          }
          out->google_connection_options->push_back(
              static_cast<QuicTag>(connection_option));
        }
      } break;
      case TransportParameters::kGoogleQuicVersion: {
        if (out->legacy_version_information.has_value()) {
          *error_details = "Received a second google_quic_version";
          return false;
        }
        if (value_reader.BytesRemaining() !=
            sizeof(out->legacy_version_information->version)) {
          *error_details =
              "Wrong size google_quic_version, should be size of uint32_t";
          return false;
        }
        QuicVersion version;
        if (!value_reader.ReadUInt32(reinterpret_cast<uint32_t*>(&version))) {
          *error_details = "Unable to parse google_quic_version";
          return false;
        }
        out->legacy_version_information.emplace();
        out->legacy_version_information->version = version;
      } break;
      case TransportParameters::kVersionInformation: {
        if (out->version_information.has_value()) {
          *error_details = "Received a second version_information";
          return false;
        }
        if (value_reader.BytesRemaining() < sizeof(QuicVersionLabel)) {
          *error_details = "Too short version_information";
          return false;
        }
        QuicVersion chosen_version = QUIC_VERSION_UNSUPPORTED;
        if (!value_reader.ReadUInt32(
                reinterpret_cast<uint32_t*>(&chosen_version))) {
          *error_details = "Unable to parse chosen_version";
          return false;
        }
        out->version_information.emplace();
        out->version_information->chosen_version = chosen_version;
        while (value_reader.BytesRemaining() >= sizeof(QuicVersionLabel)) {
          QuicVersion other_version = QUIC_VERSION_UNSUPPORTED;
          if (!value_reader.ReadUInt32(
                  reinterpret_cast<uint32_t*>(&other_version))) {
            *error_details = "Unable to parse other_version";
            return false;
          }
          out->version_information->other_versions.push_back(other_version);
        }
        if (value_reader.BytesRemaining() != 0) {
          *error_details = "version_information has trailing data";
          return false;
        }
      } break;
      case TransportParameters::kMinAckDelay:
        parse_success =
            out->min_ack_delay_us.Read(&value_reader, error_details);
        break;
      default:
        // Ignore unknown parameters.
        break;
    }
    if (!parse_success) {
      return false;
    }
    if (!value_reader.IsDoneReading()) {
      *error_details = "Trailing data in transport parameter " +
                       TransportParameterIdToString(param_id);
      return false;
    }
  }

  QUIC_DLOG(INFO) << "Parsed transport parameters, version: " << version
                  << ", perspective: " << perspective << ", result: " << *out;
  return true;
}

}  // namespace quic
```

**第2部分功能归纳:**

这段代码实现了 `SerializeTransportParameters` 函数，其主要功能是将 `TransportParametersIn` 结构体中包含的各种 QUIC 传输层参数序列化成字节流。 具体来说，它执行以下操作：

1. **确定需要序列化的参数:**  定义了一个 `parameter_ids` 向量，列出了所有可能需要序列化的传输参数的 ID。
2. **计算最大长度:** 预先计算序列化后字节流的最大可能长度，考虑到各种可选参数和自定义参数的长度。 这有助于预分配缓冲区，提高效率。
3. **添加 GREASE 参数:** 为了提高协议的健壮性，会随机添加一个 "GREASE" 类型的传输参数。 这迫使接收方能够处理未知的参数类型。
4. **处理自定义参数:** 将用户提供的自定义参数也添加到序列化过程中。
5. **随机化参数顺序:**  为了避免依赖参数出现的特定顺序，会对参数 ID 的顺序进行随机化。
6. **使用 `QuicDataWriter` 写入:**  创建一个 `QuicDataWriter` 对象，用于将各个参数按照其 ID 和值的格式写入预分配的缓冲区。
7. **处理每个参数:**  使用 `switch` 语句针对每种传输参数 ID 执行特定的序列化逻辑。  这包括：
    * 写入参数 ID (使用 `WriteVarInt62`)。
    * 写入参数值，根据参数类型选择合适的写入方法 (例如 `WriteStringPieceVarInt62`, `WriteUInt32`, 自定义的 `Write` 方法等)。
    * 对一些特定参数进行条件判断，例如，仅在服务器端序列化 `original_destination_connection_id` 和 `stateless_reset_token`。
8. **处理 Google 特定的扩展:**  包括对 Google Connection Options 和 Google QUIC 版本信息的序列化。
9. **处理 Version Information:** 序列化支持的 QUIC 版本信息，并在其中随机插入一个 GREASE 版本。
10. **调整输出缓冲区大小:**  在写入完成后，根据实际写入的字节数调整输出缓冲区的大小。

**与 JavaScript 功能的关系:**

这段代码本身是用 C++ 编写的，属于 Chromium 的网络栈底层实现，JavaScript 代码本身无法直接操作这些底层的字节流。 然而，它与 JavaScript 的功能有间接关系：

* **WebTransport API 和 Fetch API:** 当 JavaScript 使用 WebTransport API 或 Fetch API 发起 QUIC 连接时，浏览器底层会进行 QUIC 握手。 `SerializeTransportParameters` 函数生成的字节流会被包含在握手消息中发送给对方。 接收方会解析这些参数，从而影响连接的建立和后续的数据传输。
* **配置连接参数:**  虽然 JavaScript 不能直接调用这个函数，但开发者可以通过一些配置选项（例如，在创建 `WebTransport` 对象时）来间接影响传输参数的值。 这些配置最终会被传递到 C++ 层，并可能影响 `TransportParametersIn` 结构体的内容，从而影响这里的序列化过程。

**举例说明:**

假设 JavaScript 代码使用 WebTransport API 连接到一个服务器，并且设置了一些特定的配置，例如：

```javascript
const transport = new WebTransport("https://example.com", {
  serverMaxSessionStreams: 100, // 影响 initial_max_streams_bidi
  idleTimeoutMs: 30000,       // 影响 max_idle_timeout
});
```

虽然 JavaScript 代码没有直接调用 `SerializeTransportParameters`，但这些配置信息会被传递到浏览器底层。 当浏览器发起 QUIC 连接时，`SerializeTransportParameters` 函数会被调用，并且 `TransportParametersIn` 结构体中 `initial_max_streams_bidi` 和 `max_idle_timeout_ms` 的值会受到 JavaScript 配置的影响，最终被序列化到握手消息中。

**逻辑推理 (假设输入与输出):**

**假设输入 `TransportParametersIn` 结构体包含以下值 (简化):**

```
in.perspective = Perspective::IS_CLIENT;
in.max_idle_timeout_ms = 60000;
in.initial_max_data = 1048576;
in.initial_max_streams_bidi = 100;
```

**可能的输出 (序列化后的字节流，十六进制表示，顺序可能因随机化而异):**

```
<parameter_id_max_idle_timeout><length_max_idle_timeout><max_idle_timeout_value>
<parameter_id_initial_max_data><length_initial_max_data><initial_max_data_value>
<parameter_id_initial_max_streams_bidi><length_initial_max_streams_bidi><initial_max_streams_bidi_value>
... (其他参数)
<grease_parameter_id><grease_length><grease_value>
```

例如，如果 `max_idle_timeout_ms` 的 ID 是 `0x01`，长度是 2 字节，值是 `0xEA60` (60000 的十六进制)，则可能输出 `01 02 EA 60`。  具体的 ID 和编码方式取决于 QUIC 协议规范。

**用户或编程常见的使用错误:**

* **提供不兼容的参数:** 尝试设置客户端和服务端行为冲突的参数，例如客户端尝试设置 `stateless_reset_token` (通常由服务器设置)。
* **提供错误的数据类型或长度:**  例如，为期望是整数的参数提供了字符串，或者提供了长度不符合规范的连接 ID。
* **重复设置参数:**  某些参数只能设置一次，重复设置会导致解析错误。
* **忽略参数的适用范围:**  某些参数只在特定的 QUIC 版本或上下文中有效，不加判断地设置可能导致问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址并访问一个使用 HTTPS 的网站。**
2. **浏览器开始与服务器建立连接。**
3. **浏览器（或操作系统）的网络栈判断是否可以使用 QUIC 协议与该服务器通信。**  这可能基于之前与该服务器的连接记录或通过 DNS 查询获取的信息。
4. **如果决定使用 QUIC，浏览器会构造一个 ClientHello 消息。**
5. **在构造 ClientHello 消息的过程中，`SerializeTransportParameters` 函数会被调用。**
6. **浏览器会根据自身的配置、服务器的预期以及 QUIC 协议规范来填充 `TransportParametersIn` 结构体。**  例如，它会设置期望的最大空闲超时时间、初始的最大数据量等。
7. **`SerializeTransportParameters` 函数将 `TransportParametersIn` 中的参数序列化成字节流。**
8. **序列化后的字节流会被包含在 ClientHello 消息的特定扩展字段中，并通过 UDP 发送给服务器。**

**调试线索:**

* **网络抓包:** 使用 Wireshark 等工具抓取网络包，可以查看 ClientHello 消息中 Transport Parameters 扩展字段的内容，从而验证 `SerializeTransportParameters` 函数的输出。
* **Chromium 内部日志:**  Chromium 提供了丰富的内部日志，可以搜索与 QUIC 或 Transport Parameters 相关的日志，查看参数的序列化过程和相关错误信息。
* **断点调试:**  如果需要深入了解参数的设置和序列化过程，可以在 `SerializeTransportParameters` 函数中设置断点，逐步跟踪代码执行。

总而言之，`SerializeTransportParameters` 函数在 QUIC 连接建立过程中扮演着关键角色，它负责将抽象的连接参数转换为实际的网络字节流，以便在客户端和服务器之间进行协商，最终建立可靠的 QUIC 连接。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/transport_parameters.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
 google_connection_options
      kTypeAndValueLength;                // google-version

  std::vector<TransportParameters::TransportParameterId> parameter_ids = {
      TransportParameters::kOriginalDestinationConnectionId,
      TransportParameters::kMaxIdleTimeout,
      TransportParameters::kStatelessResetToken,
      TransportParameters::kMaxPacketSize,
      TransportParameters::kInitialMaxData,
      TransportParameters::kInitialMaxStreamDataBidiLocal,
      TransportParameters::kInitialMaxStreamDataBidiRemote,
      TransportParameters::kInitialMaxStreamDataUni,
      TransportParameters::kInitialMaxStreamsBidi,
      TransportParameters::kInitialMaxStreamsUni,
      TransportParameters::kAckDelayExponent,
      TransportParameters::kMaxAckDelay,
      TransportParameters::kMinAckDelay,
      TransportParameters::kActiveConnectionIdLimit,
      TransportParameters::kMaxDatagramFrameSize,
      TransportParameters::kReliableStreamReset,
      TransportParameters::kDiscard,
      TransportParameters::kGoogleHandshakeMessage,
      TransportParameters::kInitialRoundTripTime,
      TransportParameters::kDisableActiveMigration,
      TransportParameters::kPreferredAddress,
      TransportParameters::kInitialSourceConnectionId,
      TransportParameters::kRetrySourceConnectionId,
      TransportParameters::kGoogleConnectionOptions,
      TransportParameters::kGoogleQuicVersion,
      TransportParameters::kVersionInformation,
  };

  size_t max_transport_param_length = kKnownTransportParamLength;
  // google_connection_options.
  if (in.google_connection_options.has_value()) {
    max_transport_param_length +=
        in.google_connection_options->size() * sizeof(QuicTag);
  }
  // Google-specific version extension.
  if (in.legacy_version_information.has_value()) {
    max_transport_param_length +=
        sizeof(in.legacy_version_information->version) +
        1 /* versions length */ +
        in.legacy_version_information->supported_versions.size() *
            sizeof(QuicVersionLabel);
  }
  // version_information.
  if (in.version_information.has_value()) {
    max_transport_param_length +=
        sizeof(in.version_information->chosen_version) +
        // Add one for the added GREASE version.
        (in.version_information->other_versions.size() + 1) *
            sizeof(QuicVersionLabel);
  }
  // discard.
  if (in.discard_length >= 0) {
    max_transport_param_length += in.discard_length;
  }
  // google_handshake_message.
  if (in.google_handshake_message.has_value()) {
    max_transport_param_length += in.google_handshake_message->length();
  }

  // Add a random GREASE transport parameter, as defined in the
  // "Reserved Transport Parameters" section of RFC 9000.
  // This forces receivers to support unexpected input.
  QuicRandom* random = QuicRandom::GetInstance();
  // Transport parameter identifiers are 62 bits long so we need to
  // ensure that the output of the computation below fits in 62 bits.
  uint64_t grease_id64 = random->RandUint64() % ((1ULL << 62) - 31);
  // Make sure grease_id % 31 == 27. Note that this is not uniformely
  // distributed but is acceptable since no security depends on this
  // randomness.
  grease_id64 = (grease_id64 / 31) * 31 + 27;
  TransportParameters::TransportParameterId grease_id =
      static_cast<TransportParameters::TransportParameterId>(grease_id64);
  const size_t grease_length = random->RandUint64() % kMaxGreaseLength;
  QUICHE_DCHECK_GE(kMaxGreaseLength, grease_length);
  char grease_contents[kMaxGreaseLength];
  random->RandBytes(grease_contents, grease_length);
  custom_parameters[grease_id] = std::string(grease_contents, grease_length);

  // Custom parameters.
  for (const auto& kv : custom_parameters) {
    max_transport_param_length += kTypeAndValueLength + kv.second.length();
    parameter_ids.push_back(kv.first);
  }

  // Randomize order of sent transport parameters by walking the array
  // backwards and swapping each element with a random earlier one.
  for (size_t i = parameter_ids.size() - 1; i > 0; i--) {
    std::swap(parameter_ids[i],
              parameter_ids[random->InsecureRandUint64() % (i + 1)]);
  }

  out->resize(max_transport_param_length);
  QuicDataWriter writer(out->size(), reinterpret_cast<char*>(out->data()));

  for (TransportParameters::TransportParameterId parameter_id : parameter_ids) {
    switch (parameter_id) {
      // original_destination_connection_id
      case TransportParameters::kOriginalDestinationConnectionId: {
        if (in.original_destination_connection_id.has_value()) {
          QUICHE_DCHECK_EQ(Perspective::IS_SERVER, in.perspective);
          QuicConnectionId original_destination_connection_id =
              *in.original_destination_connection_id;
          if (!writer.WriteVarInt62(
                  TransportParameters::kOriginalDestinationConnectionId) ||
              !writer.WriteStringPieceVarInt62(absl::string_view(
                  original_destination_connection_id.data(),
                  original_destination_connection_id.length()))) {
            QUIC_BUG(Failed to write original_destination_connection_id)
                << "Failed to write original_destination_connection_id "
                << original_destination_connection_id << " for " << in;
            return false;
          }
        }
      } break;
      // max_idle_timeout
      case TransportParameters::kMaxIdleTimeout: {
        if (!in.max_idle_timeout_ms.Write(&writer)) {
          QUIC_BUG(Failed to write idle_timeout)
              << "Failed to write idle_timeout for " << in;
          return false;
        }
      } break;
      // stateless_reset_token
      case TransportParameters::kStatelessResetToken: {
        if (!in.stateless_reset_token.empty()) {
          QUICHE_DCHECK_EQ(kStatelessResetTokenLength,
                           in.stateless_reset_token.size());
          QUICHE_DCHECK_EQ(Perspective::IS_SERVER, in.perspective);
          if (!writer.WriteVarInt62(
                  TransportParameters::kStatelessResetToken) ||
              !writer.WriteStringPieceVarInt62(
                  absl::string_view(reinterpret_cast<const char*>(
                                        in.stateless_reset_token.data()),
                                    in.stateless_reset_token.size()))) {
            QUIC_BUG(Failed to write stateless_reset_token)
                << "Failed to write stateless_reset_token of length "
                << in.stateless_reset_token.size() << " for " << in;
            return false;
          }
        }
      } break;
      // max_udp_payload_size
      case TransportParameters::kMaxPacketSize: {
        if (!in.max_udp_payload_size.Write(&writer)) {
          QUIC_BUG(Failed to write max_udp_payload_size)
              << "Failed to write max_udp_payload_size for " << in;
          return false;
        }
      } break;
      // initial_max_data
      case TransportParameters::kInitialMaxData: {
        if (!in.initial_max_data.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_data)
              << "Failed to write initial_max_data for " << in;
          return false;
        }
      } break;
      // initial_max_stream_data_bidi_local
      case TransportParameters::kInitialMaxStreamDataBidiLocal: {
        if (!in.initial_max_stream_data_bidi_local.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_stream_data_bidi_local)
              << "Failed to write initial_max_stream_data_bidi_local for "
              << in;
          return false;
        }
      } break;
      // initial_max_stream_data_bidi_remote
      case TransportParameters::kInitialMaxStreamDataBidiRemote: {
        if (!in.initial_max_stream_data_bidi_remote.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_stream_data_bidi_remote)
              << "Failed to write initial_max_stream_data_bidi_remote for "
              << in;
          return false;
        }
      } break;
      // initial_max_stream_data_uni
      case TransportParameters::kInitialMaxStreamDataUni: {
        if (!in.initial_max_stream_data_uni.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_stream_data_uni)
              << "Failed to write initial_max_stream_data_uni for " << in;
          return false;
        }
      } break;
      // initial_max_streams_bidi
      case TransportParameters::kInitialMaxStreamsBidi: {
        if (!in.initial_max_streams_bidi.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_streams_bidi)
              << "Failed to write initial_max_streams_bidi for " << in;
          return false;
        }
      } break;
      // initial_max_streams_uni
      case TransportParameters::kInitialMaxStreamsUni: {
        if (!in.initial_max_streams_uni.Write(&writer)) {
          QUIC_BUG(Failed to write initial_max_streams_uni)
              << "Failed to write initial_max_streams_uni for " << in;
          return false;
        }
      } break;
      // ack_delay_exponent
      case TransportParameters::kAckDelayExponent: {
        if (!in.ack_delay_exponent.Write(&writer)) {
          QUIC_BUG(Failed to write ack_delay_exponent)
              << "Failed to write ack_delay_exponent for " << in;
          return false;
        }
      } break;
      // max_ack_delay
      case TransportParameters::kMaxAckDelay: {
        if (!in.max_ack_delay.Write(&writer)) {
          QUIC_BUG(Failed to write max_ack_delay)
              << "Failed to write max_ack_delay for " << in;
          return false;
        }
      } break;
      // min_ack_delay_us
      case TransportParameters::kMinAckDelay: {
        if (!in.min_ack_delay_us.Write(&writer)) {
          QUIC_BUG(Failed to write min_ack_delay_us)
              << "Failed to write min_ack_delay_us for " << in;
          return false;
        }
      } break;
      // active_connection_id_limit
      case TransportParameters::kActiveConnectionIdLimit: {
        if (!in.active_connection_id_limit.Write(&writer)) {
          QUIC_BUG(Failed to write active_connection_id_limit)
              << "Failed to write active_connection_id_limit for " << in;
          return false;
        }
      } break;
      // max_datagram_frame_size
      case TransportParameters::kMaxDatagramFrameSize: {
        if (!in.max_datagram_frame_size.Write(&writer)) {
          QUIC_BUG(Failed to write max_datagram_frame_size)
              << "Failed to write max_datagram_frame_size for " << in;
          return false;
        }
      } break;
      // discard
      case TransportParameters::kDiscard: {
        if (in.discard_length >= 0) {
          std::string discard_data(in.discard_length, '\0');
          if (!writer.WriteVarInt62(TransportParameters::kDiscard) ||
              !writer.WriteStringPieceVarInt62(discard_data)) {
            QUIC_BUG(Failed to write discard_data)
                << "Failed to write discard data of length: "
                << in.discard_length << " for " << in;
            return false;
          }
        }
      } break;
      // google_handshake_message
      case TransportParameters::kGoogleHandshakeMessage: {
        if (in.google_handshake_message.has_value()) {
          if (!writer.WriteVarInt62(
                  TransportParameters::kGoogleHandshakeMessage) ||
              !writer.WriteStringPieceVarInt62(*in.google_handshake_message)) {
            QUIC_BUG(Failed to write google_handshake_message)
                << "Failed to write google_handshake_message: "
                << *in.google_handshake_message << " for " << in;
            return false;
          }
        }
      } break;
      // initial_round_trip_time_us
      case TransportParameters::kInitialRoundTripTime: {
        if (!in.initial_round_trip_time_us.Write(&writer)) {
          QUIC_BUG(Failed to write initial_round_trip_time_us)
              << "Failed to write initial_round_trip_time_us for " << in;
          return false;
        }
      } break;
      // disable_active_migration
      case TransportParameters::kDisableActiveMigration: {
        if (in.disable_active_migration) {
          if (!writer.WriteVarInt62(
                  TransportParameters::kDisableActiveMigration) ||
              !writer.WriteVarInt62(/* transport parameter length */ 0)) {
            QUIC_BUG(Failed to write disable_active_migration)
                << "Failed to write disable_active_migration for " << in;
            return false;
          }
        }
      } break;
      // reliable_stream_reset
      case TransportParameters::kReliableStreamReset: {
        if (in.reliable_stream_reset) {
          if (!writer.WriteVarInt62(
                  TransportParameters::kReliableStreamReset) ||
              !writer.WriteVarInt62(/* transport parameter length */ 0)) {
            QUIC_BUG(Failed to write reliable_stream_reset)
                << "Failed to write reliable_stream_reset for " << in;
            return false;
          }
        }
      } break;
      // preferred_address
      case TransportParameters::kPreferredAddress: {
        if (in.preferred_address) {
          std::string v4_address_bytes =
              in.preferred_address->ipv4_socket_address.host().ToPackedString();
          std::string v6_address_bytes =
              in.preferred_address->ipv6_socket_address.host().ToPackedString();
          if (v4_address_bytes.length() != 4 ||
              v6_address_bytes.length() != 16 ||
              in.preferred_address->stateless_reset_token.size() !=
                  kStatelessResetTokenLength) {
            QUIC_BUG(quic_bug_10743_12)
                << "Bad lengths " << *in.preferred_address;
            return false;
          }
          const uint64_t preferred_address_length =
              v4_address_bytes.length() + /* IPv4 port */ sizeof(uint16_t) +
              v6_address_bytes.length() + /* IPv6 port */ sizeof(uint16_t) +
              /* connection ID length byte */ sizeof(uint8_t) +
              in.preferred_address->connection_id.length() +
              in.preferred_address->stateless_reset_token.size();
          if (!writer.WriteVarInt62(TransportParameters::kPreferredAddress) ||
              !writer.WriteVarInt62(
                  /* transport parameter length */ preferred_address_length) ||
              !writer.WriteStringPiece(v4_address_bytes) ||
              !writer.WriteUInt16(
                  in.preferred_address->ipv4_socket_address.port()) ||
              !writer.WriteStringPiece(v6_address_bytes) ||
              !writer.WriteUInt16(
                  in.preferred_address->ipv6_socket_address.port()) ||
              !writer.WriteUInt8(
                  in.preferred_address->connection_id.length()) ||
              !writer.WriteBytes(
                  in.preferred_address->connection_id.data(),
                  in.preferred_address->connection_id.length()) ||
              !writer.WriteBytes(
                  in.preferred_address->stateless_reset_token.data(),
                  in.preferred_address->stateless_reset_token.size())) {
            QUIC_BUG(Failed to write preferred_address)
                << "Failed to write preferred_address for " << in;
            return false;
          }
        }
      } break;
      // initial_source_connection_id
      case TransportParameters::kInitialSourceConnectionId: {
        if (in.initial_source_connection_id.has_value()) {
          QuicConnectionId initial_source_connection_id =
              *in.initial_source_connection_id;
          if (!writer.WriteVarInt62(
                  TransportParameters::kInitialSourceConnectionId) ||
              !writer.WriteStringPieceVarInt62(
                  absl::string_view(initial_source_connection_id.data(),
                                    initial_source_connection_id.length()))) {
            QUIC_BUG(Failed to write initial_source_connection_id)
                << "Failed to write initial_source_connection_id "
                << initial_source_connection_id << " for " << in;
            return false;
          }
        }
      } break;
      // retry_source_connection_id
      case TransportParameters::kRetrySourceConnectionId: {
        if (in.retry_source_connection_id.has_value()) {
          QUICHE_DCHECK_EQ(Perspective::IS_SERVER, in.perspective);
          QuicConnectionId retry_source_connection_id =
              *in.retry_source_connection_id;
          if (!writer.WriteVarInt62(
                  TransportParameters::kRetrySourceConnectionId) ||
              !writer.WriteStringPieceVarInt62(
                  absl::string_view(retry_source_connection_id.data(),
                                    retry_source_connection_id.length()))) {
            QUIC_BUG(Failed to write retry_source_connection_id)
                << "Failed to write retry_source_connection_id "
                << retry_source_connection_id << " for " << in;
            return false;
          }
        }
      } break;
      // Google-specific connection options.
      case TransportParameters::kGoogleConnectionOptions: {
        if (in.google_connection_options.has_value()) {
          static_assert(sizeof(in.google_connection_options->front()) == 4,
                        "bad size");
          uint64_t connection_options_length =
              in.google_connection_options->size() * 4;
          if (!writer.WriteVarInt62(
                  TransportParameters::kGoogleConnectionOptions) ||
              !writer.WriteVarInt62(
                  /* transport parameter length */ connection_options_length)) {
            QUIC_BUG(Failed to write google_connection_options)
                << "Failed to write google_connection_options of length "
                << connection_options_length << " for " << in;
            return false;
          }
          for (const QuicTag& connection_option :
               *in.google_connection_options) {
            if (!writer.WriteTag(connection_option)) {
              QUIC_BUG(Failed to write google_connection_option)
                  << "Failed to write google_connection_option "
                  << QuicTagToString(connection_option) << " for " << in;
              return false;
            }
          }
        }
      } break;
      // Google-specific version extension.
      case TransportParameters::kGoogleQuicVersion: {
        if (!in.legacy_version_information.has_value()) {
          break;
        }
        static_assert(sizeof(QuicVersionLabel) == sizeof(uint32_t),
                      "bad length");
        uint64_t google_version_length =
            sizeof(in.legacy_version_information->version);
        if (in.perspective == Perspective::IS_SERVER) {
          google_version_length +=
              /* versions length */ sizeof(uint8_t) +
              sizeof(QuicVersionLabel) *
                  in.legacy_version_information->supported_versions.size();
        }
        if (!writer.WriteVarInt62(TransportParameters::kGoogleQuicVersion) ||
            !writer.WriteVarInt62(
                /* transport parameter length */ google_version_length) ||
            !writer.WriteUInt32(in.legacy_version_information->version)) {
          QUIC_BUG(Failed to write Google version extension)
              << "Failed to write Google version extension for " << in;
          return false;
        }
        if (in.perspective == Perspective::IS_SERVER) {
          if (!writer.WriteUInt8(
                  sizeof(QuicVersionLabel) *
                  in.legacy_version_information->supported_versions.size())) {
            QUIC_BUG(Failed to write versions length)
                << "Failed to write versions length for " << in;
            return false;
          }
          for (QuicVersionLabel version_label :
               in.legacy_version_information->supported_versions) {
            if (!writer.WriteUInt32(version_label)) {
              QUIC_BUG(Failed to write supported version)
                  << "Failed to write supported version for " << in;
              return false;
            }
          }
        }
      } break;
      // version_information.
      case TransportParameters::kVersionInformation: {
        if (!in.version_information.has_value()) {
          break;
        }
        static_assert(sizeof(QuicVersionLabel) == sizeof(uint32_t),
                      "bad length");
        QuicVersionLabelVector other_versions =
            in.version_information->other_versions;
        // Insert one GREASE version at a random index.
        const size_t grease_index =
            random->InsecureRandUint64() % (other_versions.size() + 1);
        other_versions.insert(
            other_versions.begin() + grease_index,
            CreateQuicVersionLabel(QuicVersionReservedForNegotiation()));
        const uint64_t version_information_length =
            sizeof(in.version_information->chosen_version) +
            sizeof(QuicVersionLabel) * other_versions.size();
        if (!writer.WriteVarInt62(TransportParameters::kVersionInformation) ||
            !writer.WriteVarInt62(
                /* transport parameter length */ version_information_length) ||
            !writer.WriteUInt32(in.version_information->chosen_version)) {
          QUIC_BUG(Failed to write chosen version)
              << "Failed to write chosen version for " << in;
          return false;
        }
        for (QuicVersionLabel version_label : other_versions) {
          if (!writer.WriteUInt32(version_label)) {
            QUIC_BUG(Failed to write other version)
                << "Failed to write other version for " << in;
            return false;
          }
        }
      } break;
      // Custom parameters and GREASE.
      default: {
        auto it = custom_parameters.find(parameter_id);
        if (it == custom_parameters.end()) {
          QUIC_BUG(Unknown parameter) << "Unknown parameter " << parameter_id;
          return false;
        }
        if (!writer.WriteVarInt62(parameter_id) ||
            !writer.WriteStringPieceVarInt62(it->second)) {
          QUIC_BUG(Failed to write custom parameter)
              << "Failed to write custom parameter " << parameter_id;
          return false;
        }
      } break;
    }
  }

  out->resize(writer.length());

  QUIC_DLOG(INFO) << "Serialized " << in << " as " << writer.length()
                  << " bytes";

  return true;
}  // NOLINT(readability/fn_size)

bool ParseTransportParameters(ParsedQuicVersion version,
                              Perspective perspective, const uint8_t* in,
                              size_t in_len, TransportParameters* out,
                              std::string* error_details) {
  out->perspective = perspective;
  QuicDataReader reader(reinterpret_cast<const char*>(in), in_len);

  while (!reader.IsDoneReading()) {
    uint64_t param_id64;
    if (!reader.ReadVarInt62(&param_id64)) {
      *error_details = "Failed to parse transport parameter ID";
      return false;
    }
    TransportParameters::TransportParameterId param_id =
        static_cast<TransportParameters::TransportParameterId>(param_id64);
    absl::string_view value;
    if (!reader.ReadStringPieceVarInt62(&value)) {
      *error_details =
          "Failed to read length and value of transport parameter " +
          TransportParameterIdToString(param_id);
      return false;
    }
    QuicDataReader value_reader(value);
    bool parse_success = true;
    switch (param_id) {
      case TransportParameters::kOriginalDestinationConnectionId: {
        if (out->original_destination_connection_id.has_value()) {
          *error_details =
              "Received a second original_destination_connection_id";
          return false;
        }
        const size_t connection_id_length = value_reader.BytesRemaining();
        if (!QuicUtils::IsConnectionIdLengthValidForVersion(
                connection_id_length, version.transport_version)) {
          *error_details = absl::StrCat(
              "Received original_destination_connection_id of invalid length ",
              connection_id_length);
          return false;
        }
        QuicConnectionId original_destination_connection_id;
        if (!value_reader.ReadConnectionId(&original_destination_connection_id,
                                           connection_id_length)) {
          *error_details = "Failed to read original_destination_connection_id";
          return false;
        }
        out->original_destination_connection_id =
            original_destination_connection_id;
      } break;
      case TransportParameters::kMaxIdleTimeout:
        parse_success =
            out->max_idle_timeout_ms.Read(&value_reader, error_details);
        break;
      case TransportParameters::kStatelessResetToken: {
        if (!out->stateless_reset_token.empty()) {
          *error_details = "Received a second stateless_reset_token";
          return false;
        }
        absl::string_view stateless_reset_token =
            value_reader.ReadRemainingPayload();
        if (stateless_reset_token.length() != kStatelessResetTokenLength) {
          *error_details =
              absl::StrCat("Received stateless_reset_token of invalid length ",
                           stateless_reset_token.length());
          return false;
        }
        out->stateless_reset_token.assign(
            stateless_reset_token.data(),
            stateless_reset_token.data() + stateless_reset_token.length());
      } break;
      case TransportParameters::kMaxPacketSize:
        parse_success =
            out->max_udp_payload_size.Read(&value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxData:
        parse_success =
            out->initial_max_data.Read(&value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxStreamDataBidiLocal:
        parse_success = out->initial_max_stream_data_bidi_local.Read(
            &value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxStreamDataBidiRemote:
        parse_success = out->initial_max_stream_data_bidi_remote.Read(
            &value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxStreamDataUni:
        parse_success =
            out->initial_max_stream_data_uni.Read(&value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxStreamsBidi:
        parse_success =
            out->initial_max_streams_bidi.Read(&value_reader, error_details);
        break;
      case TransportParameters::kInitialMaxStreamsUni:
        parse_success =
            out->initial_max_streams_uni.Read(&value_reader, error_details);
        break;
      case TransportParameters::kAckDelayExponent:
        parse_success =
            out->ack_delay_exponent.Read(&value_reader, error_details);
        break;
      case TransportParameters::kMaxAckDelay:
        parse_success = out->max_ack_delay.Read(&value_reader, error_details);
        break;
      case TransportParameters::kDisableActiveMigration:
        if (out->disable_active_migration) {
          *error_details = "Received a second disable_active_migration";
          return false;
        }
        out->disable_active_migration = true;
        break;
      case TransportParameters::kPreferredAddress: {
        TransportParameters::PreferredAddress preferred_address;
        uint16_t ipv4_port, ipv6_port;
        in_addr ipv4_address;
        in6_addr ipv6_address;
        preferred_address.stateless_reset_token.resize(
            kStatelessResetTokenLength);
        if (!value_reader.ReadBytes(&ipv4_address, sizeof(ipv4_address)) ||
            !value_reader.ReadUInt16(&ipv4_port) ||
            !value_reader.ReadBytes(&ipv6_address, sizeof(ipv6_address)) ||
            !value_reader.ReadUInt16(&ipv6_port) ||
            !value_reader.ReadLengthPrefixedConnectionId(
                &preferred_address.connection_id) ||
            !value_reader.ReadBytes(&preferred_address.stateless_reset_token[0],
                                    kStatelessResetTokenLength)) {
          *error_details = "Failed to read preferred_address";
          return false;
        }
        preferred_address.ipv4_socket_address =
            QuicSocketAddress(QuicIpAddress(ipv4_address), ipv4_port);
        preferred_address.ipv6_socket_address =
            QuicSocketAddress(QuicIpAddress(ipv6_address), ipv6_port);
        if (!preferred_address.ipv4_socket_address.host().IsIPv4() ||
            !preferred_address.ipv6_socket_address.host().IsIPv6()) {
          *error_details = "Received preferred_address of bad families " +
                           preferred_address.ToString();
          return false;
        }
        if (!QuicUtils::IsConnectionIdValidForVersion(
                preferred_address.connection_id, version.transport_version)) {
          *error_details = "Received invalid preferred_address connection ID " +
                           preferred_address.ToString();
          return false;
        }
        out->preferred_address =
            std::make_unique<TransportParameters::PreferredAddress>(
                preferred_address);
      } break;
      case TransportParameters::kActiveConnectionIdLimit:
        parse_success =
            out->active_connection_id_limit.Read(&value_reader, error_details);
        break;
      case TransportParameters::kInitialSourceConnectionId: {
        if (out->initial_source_connection_id.has_value()) {
          *error_details = "Received a second initial_source_connection_id";
          return false;
        }
        const size_t connection_id_length = value_reader.BytesRemaining();
        if (!QuicUtils::IsConnectionIdLengthValidForVersion(
                connection_id_length, version.transport_version)) {
          *error_details = absl::StrCat(
              "Received initial_source_connection_id of invalid length ",
              connection_id_length);
          return false;
        }
        QuicConnectionId initial_source_connection_id;
        if (!value_reader.ReadConnectionId(&initial_source_connection_id,
                                           connection_id_length)) {
          *error_details = "Failed to read initial_source_connection_id";
          return false;
        }
        out->initial_source_connection_id = initial_source_connection_id;
      } break;
      case TransportParameters::kRetrySourceConnectionId: {
        if (out->retry_source_connection_id.has_value()) {
          *error_details = "Received a second retry_source_connection_id";
          return false;
        }
        const size_t connection_id_length = value_reader.BytesRemaining();
        if (!QuicUtils::IsConnectionIdLengthValidForVersion(
                connection_id_length, version.transport_version)) {
          *error_details = absl::StrCat(
              "Received retry_source_connection_id of invalid length ",
              connection_id_length);
          return false;
        }
        QuicConnectionId retry_source_connection_id;
        if (!value_reader.ReadConnectionId(&retry_source_connection_id,
                                           connection_id_length)) {
          *error_details = "Failed to read retry_source_connection_id";
          return false;
        }
        out->retry_source_connection_id = retry_source_connection_id;
      } break;
      case TransportParameters::kMaxDatagramFrameSize:
        parse_success =
            out->max_datagram_frame_size.Read(&value_reader, error_details);
        break;
      case TransportParameters::kDiscard:
        out->discard_length = value_reader.ReadRemainingPayload().length();
        break;
      case TransportParameters::kGoogleHandshakeMessage:
        if (out->google_handshake_message.has_value()) {
          *error_details = "Received a second google_handshake_message";
          return false;
        }
        out->google_handshake_message =
            std::string(value_reader.ReadRemainingPayload());
        break;
      case TransportParameters::kInitialRoundTripTime:
        parse_success =
            out->initial_round_trip_time_us.Read(&value_reader, error_details);
        break;
      case TransportParameters::kReliableStreamReset:
        if (out->reliable_stream_reset) {
          *error_details = "Received a second reliable_stream_reset";
          return false;
        }
        out->reliable_stream_reset = true;
        break;
      case TransportParameters::kGoogleConnectionOptions: {
        if (out->google_connection_options.has_value()) {
          *error_details = "Received a second google_connection_options";
          return false;
        }
        out->google_connection_options = QuicTagVector{};
        while (
"""


```