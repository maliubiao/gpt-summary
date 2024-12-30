Response:
The user wants a summary of the functionality of the `quic_framer.cc` file in the Chromium network stack. They also want to know about its relationship with JavaScript, examples of logical reasoning, common usage errors, and how a user operation might lead to this code. This is the sixth part of a nine-part request, so the summary should focus on the content of this specific snippet.

Here's a breakdown of the content in this part:

1. **Header Protection:** Functions for applying (`ApplyHeaderProtection`) and removing (`RemoveHeaderProtection`) header protection.
2. **Payload Encryption and Decryption:** Functions for encrypting (`EncryptPayload`) and decrypting (`DecryptPayload`) the payload of a QUIC packet. Also includes functions for getting ciphertext and plaintext sizes.
3. **ACK Frame Size Calculation (IETF and legacy):** Functions for calculating the size of ACK frames (`GetIetfAckFrameSize`, `GetIetfAckFrameTimestampSize`, `GetAckFrameSize`, `GetAckFrameTimeStampSize`).
4. **Frame Length Calculation:** A function to compute the length of a generic QUIC frame (`ComputeFrameLength`).
5. **Frame Type Appending (IETF and legacy):** Functions to append the type byte of a frame to a buffer (`AppendTypeByte`, `AppendIetfFrameType`).
6. **Data Appending Functions:** Helper functions for appending various QUIC data fields like packet numbers, stream IDs, offsets, and ACK blocks.
7. **Stream Frame Appending (IETF and legacy):** Functions for writing stream frame data to a buffer.
8. **New Token Frame Handling:** Functions for appending and processing `NEW_TOKEN` frames.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_framer.cc` 文件的第六部分，主要涵盖了以下功能：

**核心功能归纳：加密解密、帧大小计算及帧的序列化**

1. **报头保护 (Header Protection):**
   - `ApplyHeaderProtection`:  对 QUIC 数据包的报头进行加密，隐藏部分报头信息，例如包序号的长度和实际值。
   - `RemoveHeaderProtection`: 解密 QUIC 数据包的报头，恢复被保护的信息。

2. **有效载荷加密和解密 (Payload Encryption and Decryption):**
   - `EncryptPayload`: 使用指定的加密级别和密钥加密 QUIC 数据包的有效载荷。
   - `DecryptPayload`: 使用合适的解密器和密钥解密 QUIC 数据包的有效载荷。这个函数还处理密钥更新的情况。
   - `GetCiphertextSize`: 获取给定明文大小的密文大小。
   - `GetMaxPlaintextSize`: 获取给定密文大小的最大明文大小。
   - `GetOneRttEncrypterConfidentialityLimit`: 获取 1-RTT 加密器的保密性限制。

3. **ACK 帧大小计算 (ACK Frame Size Calculation):**
   - `GetIetfAckFrameSize`: 计算 IETF QUIC 格式的 ACK 帧的大小。
   - `GetIetfAckFrameTimestampSize`: 计算 IETF QUIC 格式的包含时间戳的 ACK 帧的大小。
   - `GetAckFrameSize`: 计算传统 QUIC 格式的 ACK 帧的大小。
   - `GetAckFrameTimeStampSize`: 计算传统 QUIC 格式的包含时间戳的 ACK 帧的大小。

4. **帧长度计算 (Frame Length Calculation):**
   - `ComputeFrameLength`: 计算各种 QUIC 帧的长度。

5. **帧类型写入 (Frame Type Appending):**
   - `AppendTypeByte`: 将帧的类型字节写入缓冲区 (用于传统 QUIC)。
   - `AppendIetfFrameType`: 将帧的类型字节写入缓冲区 (用于 IETF QUIC)。

6. **数据字段写入 (Data Field Appending):**
   - `AppendPacketNumber`: 将包序号写入缓冲区。
   - `AppendStreamId`: 将流 ID 写入缓冲区。
   - `AppendStreamOffset`: 将流偏移量写入缓冲区。
   - `AppendAckBlock`: 将 ACK 块信息写入缓冲区。

7. **STREAM 帧处理 (STREAM Frame Handling):**
   - `AppendStreamFrame`: 将 STREAM 帧的数据写入缓冲区 (用于传统 QUIC)。
   - `AppendIetfStreamFrame`: 将 STREAM 帧的数据写入缓冲区 (用于 IETF QUIC)。

8. **NEW_TOKEN 帧处理 (NEW_TOKEN Frame Handling):**
   - `AppendNewTokenFrame`: 将 NEW_TOKEN 帧的数据写入缓冲区。
   - `ProcessNewTokenFrame`: 从缓冲区读取并解析 NEW_TOKEN 帧的数据。

**与 JavaScript 的关系：**

这个 C++ 文件本身不直接与 JavaScript 交互。Chromium 的网络栈在底层使用 C++ 实现，处理 QUIC 协议的细节。JavaScript 通过 Chromium 提供的 Web API (例如 Fetch API 或 WebSocket API) 发起网络请求，这些请求最终会由底层的 C++ 代码处理。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch()` API 向一个支持 QUIC 的服务器发送请求。

1. JavaScript 调用 `fetch()`，浏览器开始构建 HTTP/3 请求（基于 QUIC）。
2. Chromium 的网络栈接收到该请求，并开始构建 QUIC 数据包。
3. 在构建数据包时，`QuicFramer` 会被使用：
   - **`AppendStreamFrame` 或 `AppendIetfStreamFrame`:** 将 HTTP 请求的头部和 body 数据封装到 STREAM 帧中。
   - **`EncryptPayload`:**  根据当前连接的加密级别和密钥，对包含 STREAM 帧的 QUIC 数据包的有效载荷进行加密。
   - **`ApplyHeaderProtection`:**  如果启用了报头保护，则对数据包的报头进行加密。

当收到来自服务器的 QUIC 数据包时：

1. Chromium 的网络栈接收到数据包。
2. **`RemoveHeaderProtection`:** 如果启用了报头保护，则首先解密报头以获取关键信息，例如包序号。
3. **`DecryptPayload`:** 使用相应的解密器解密数据包的有效载荷。
4. **`ProcessNewTokenFrame`:** 如果数据包包含 NEW_TOKEN 帧，则解析该帧以获取新的连接令牌。
5. **`GetIetfAckFrameSize` 或 `GetAckFrameSize`:**  在构建 ACK 帧以确认收到数据包时，计算 ACK 帧的大小。

**逻辑推理的假设输入与输出：**

**假设输入 `ApplyHeaderProtection`:**

* `level`:  `ENCRYPTION_FORWARD_SECURE` (假设使用 1-RTT 加密)
* `buffer`: 指向包含部分报头和待加密包序号的缓冲区。
* `buffer_len`: 缓冲区的总长度。
* `pn_offset`: 包序号在缓冲区中的偏移量。

**输出 `ApplyHeaderProtection`:**

* 如果成功，则 `buffer` 中的包序号部分会被加密（与掩码异或），函数返回 `true`。
* 如果失败（例如，缓冲区长度不足），则返回 `false`。

**假设输入 `DecryptPayload`:**

* `udp_packet_length`: UDP 数据包的总长度。
* `encrypted`:  指向已加密的有效载荷的指针。
* `associated_data`:  与加密有效载荷关联的未加密数据（例如，部分报头）。
* `header`:  已解析的数据包报头信息。
* `decrypted_buffer`:  用于存放解密后数据的缓冲区。
* `buffer_length`: 解密缓冲区的长度。

**输出 `DecryptPayload`:**

* 如果解密成功，`decrypted_buffer` 中包含解密后的数据，`decrypted_length` 指向解密后的数据长度，`decrypted_level` 指示解密使用的加密级别，函数返回 `true`。
* 如果解密失败（例如，使用了错误的密钥），则返回 `false`。

**用户或编程常见的使用错误：**

1. **加密器/解密器未设置：** 在调用 `EncryptPayload` 或 `DecryptPayload` 之前，如果没有为相应的加密级别设置加密器或解密器，会导致断言失败或返回错误。
   * **用户操作如何到达这里：** 这通常是编程错误，例如在握手完成之前尝试发送或接收 1-RTT 数据包，或者在密钥更新过程中没有正确切换加密/解密器。

2. **缓冲区长度不足：** 在加密或解密时，提供的缓冲区长度不足以容纳加密后或解密后的数据。
   * **用户操作如何到达这里：**  这通常也是编程错误，例如在调用加密/解密函数之前没有正确计算所需的缓冲区大小。

3. **使用错误的密钥进行解密：** 尝试使用过期的或不匹配的密钥解密数据包。
   * **用户操作如何到达这里：**  可能发生在密钥更新过程中，如果接收方没有及时更新密钥，或者在处理乱序数据包时，尝试使用错误的密钥。

4. **ACK 帧结构错误：**  在构造 ACK 帧时，逻辑错误导致 ACK 块的顺序或范围不正确。
   * **用户操作如何到达这里：** 这通常是 QUIC 连接管理或拥塞控制算法中的错误，导致生成的 ACK 帧不符合协议规范。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个使用了 HTTP/3 的网站：

1. **用户在地址栏输入网址并按下回车。**
2. **浏览器尝试与服务器建立 QUIC 连接。** 这涉及到 TLS 握手和密钥协商。
3. **在握手过程中，会交换 Initial 报文和 Handshake 报文。**  `QuicFramer` 用于序列化和反序列化这些报文，包括加密和解密。
4. **握手完成后，连接建立，开始传输应用数据。**
5. **当浏览器发送 HTTP 请求时：**
   - JavaScript 代码（例如，通过 `fetch()`）触发网络请求。
   - Chromium 的网络栈接收请求，并将 HTTP 请求数据封装成 QUIC STREAM 帧。
   - `AppendStreamFrame` 或 `AppendIetfStreamFrame` 被调用。
   - `EncryptPayload` 被调用以加密数据。
   - `ApplyHeaderProtection` 可能被调用以保护报头。
6. **当浏览器收到来自服务器的响应时：**
   - 网络栈接收到 QUIC 数据包。
   - `RemoveHeaderProtection` 可能被调用以解保护报头。
   - `DecryptPayload` 被调用以解密数据。
   - 如果收到包含 ACK 帧的数据包，`GetIetfAckFrameSize` 或 `GetAckFrameSize`  可能在后续构建确认包时被用到。
7. **如果服务器发起密钥更新，** `DecryptPayload` 函数会检测到密钥阶段的变化，并可能触发密钥更新流程，涉及到新的加密器和解密器的设置。

**作为调试线索，如果程序运行到这个文件的代码，可能意味着：**

* 正在进行 QUIC 连接的建立、数据传输或密钥更新。
* 正在处理接收到的 QUIC 数据包，需要解密或解析帧。
* 正在构建要发送的 QUIC 数据包，需要加密和序列化帧。
* 在处理 ACK 信息，可能在计算 ACK 帧的大小或解析收到的 ACK 帧。

因此，在调试网络连接问题时，特别是与 QUIC 相关的连接问题，这个文件中的代码是检查数据包加密/解密、帧结构以及连接状态的关键位置。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共9部分，请归纳一下它的功能

"""
ation nonce.
  if (IsLongHeader(type_byte) && header_type == ZERO_RTT_PROTECTED &&
      perspective_ == Perspective::IS_SERVER &&
      version_.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
    if (pn_offset <= kDiversificationNonceSize) {
      QUIC_BUG(quic_bug_10850_62)
          << "Expected diversification nonce, but not enough bytes";
      return false;
    }
    pn_offset -= kDiversificationNonceSize;
  }
  // Advance the reader and writer to the packet number. Both the reader and
  // writer have each read/written one byte.
  if (!buffer_writer.Seek(pn_offset - 1) ||
      !buffer_reader.Seek(pn_offset - 1)) {
    return false;
  }
  // Apply the rest of the mask to the packet number.
  for (size_t i = 0; i < last_written_packet_number_length_; ++i) {
    uint8_t buffer_byte;
    uint8_t pn_mask_byte;
    if (!mask_reader.ReadUInt8(&pn_mask_byte) ||
        !buffer_reader.ReadUInt8(&buffer_byte) ||
        !buffer_writer.WriteUInt8(buffer_byte ^ pn_mask_byte)) {
      return false;
    }
  }
  return true;
}

bool QuicFramer::RemoveHeaderProtection(
    QuicDataReader* reader, const QuicEncryptedPacket& packet,
    QuicDecrypter& decrypter, Perspective perspective,
    const ParsedQuicVersion& version, QuicPacketNumber base_packet_number,
    QuicPacketHeader* header, uint64_t* full_packet_number,
    AssociatedDataStorage& associated_data) {
  bool has_diversification_nonce =
      header->form == IETF_QUIC_LONG_HEADER_PACKET &&
      header->long_packet_type == ZERO_RTT_PROTECTED &&
      perspective == Perspective::IS_CLIENT &&
      version.handshake_protocol == PROTOCOL_QUIC_CRYPTO;

  // Read a sample from the ciphertext and compute the mask to use for header
  // protection.
  absl::string_view remaining_packet = reader->PeekRemainingPayload();
  QuicDataReader sample_reader(remaining_packet);

  // The sample starts 4 bytes after the start of the packet number.
  absl::string_view pn;
  if (!sample_reader.ReadStringPiece(&pn, 4)) {
    QUIC_DVLOG(1) << "Not enough data to sample";
    return false;
  }
  if (has_diversification_nonce) {
    // In Google QUIC, the diversification nonce comes between the packet number
    // and the sample.
    if (!sample_reader.Seek(kDiversificationNonceSize)) {
      QUIC_DVLOG(1) << "No diversification nonce to skip over";
      return false;
    }
  }
  std::string mask = decrypter.GenerateHeaderProtectionMask(&sample_reader);
  QuicDataReader mask_reader(mask.data(), mask.size());
  if (mask.empty()) {
    QUIC_DVLOG(1) << "Failed to compute mask";
    return false;
  }

  // Unmask the rest of the type byte.
  uint8_t bitmask = 0x1f;
  if (IsLongHeader(header->type_byte)) {
    bitmask = 0x0f;
  }
  uint8_t mask_byte;
  if (!mask_reader.ReadUInt8(&mask_byte)) {
    QUIC_DVLOG(1) << "No first byte to read from mask";
    return false;
  }
  header->type_byte ^= (mask_byte & bitmask);

  // Compute the packet number length.
  header->packet_number_length =
      static_cast<QuicPacketNumberLength>((header->type_byte & 0x03) + 1);

  char pn_buffer[IETF_MAX_PACKET_NUMBER_LENGTH] = {};
  QuicDataWriter pn_writer(ABSL_ARRAYSIZE(pn_buffer), pn_buffer);

  // Read the (protected) packet number from the reader and unmask the packet
  // number.
  for (size_t i = 0; i < header->packet_number_length; ++i) {
    uint8_t protected_pn_byte, pn_mask_byte;
    if (!mask_reader.ReadUInt8(&pn_mask_byte) ||
        !reader->ReadUInt8(&protected_pn_byte) ||
        !pn_writer.WriteUInt8(protected_pn_byte ^ pn_mask_byte)) {
      QUIC_DVLOG(1) << "Failed to unmask packet number";
      return false;
    }
  }
  QuicDataReader packet_number_reader(pn_writer.data(), pn_writer.length());
  if (!ProcessAndCalculatePacketNumber(
          &packet_number_reader, header->packet_number_length,
          base_packet_number, full_packet_number)) {
    return false;
  }

  // Get the associated data, and apply the same unmasking operations to it.
  absl::string_view ad = GetAssociatedDataFromEncryptedPacket(
      version.transport_version, packet,
      GetIncludedDestinationConnectionIdLength(*header),
      GetIncludedSourceConnectionIdLength(*header), header->version_flag,
      has_diversification_nonce, header->packet_number_length,
      header->retry_token_length_length, header->retry_token.length(),
      header->length_length);
  associated_data.assign(ad.begin(), ad.end());
  QuicDataWriter ad_writer(associated_data.size(), associated_data.data());

  // Apply the unmasked type byte and packet number to |associated_data|.
  if (!ad_writer.WriteUInt8(header->type_byte)) {
    return false;
  }
  // Put the packet number at the end of the AD, or if there's a diversification
  // nonce, before that (which is at the end of the AD).
  size_t seek_len = ad_writer.remaining() - header->packet_number_length;
  if (has_diversification_nonce) {
    seek_len -= kDiversificationNonceSize;
  }
  if (!ad_writer.Seek(seek_len) ||
      !ad_writer.WriteBytes(pn_writer.data(), pn_writer.length())) {
    QUIC_DVLOG(1) << "Failed to apply unmasking operations to AD";
    return false;
  }

  return true;
}

size_t QuicFramer::EncryptPayload(EncryptionLevel level,
                                  QuicPacketNumber packet_number,
                                  const QuicPacket& packet, char* buffer,
                                  size_t buffer_len) {
  QUICHE_DCHECK(packet_number.IsInitialized());
  if (encrypter_[level] == nullptr) {
    QUIC_BUG(quic_bug_10850_63)
        << ENDPOINT << "Attempted to encrypt without encrypter at level "
        << level;
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  absl::string_view associated_data =
      packet.AssociatedData(version_.transport_version);
  // Copy in the header, because the encrypter only populates the encrypted
  // plaintext content.
  const size_t ad_len = associated_data.length();
  if (packet.length() < ad_len) {
    QUIC_BUG(quic_bug_10850_64)
        << ENDPOINT << "packet is shorter than associated data length. version:"
        << version() << ", packet length:" << packet.length()
        << ", associated data length:" << ad_len;
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }
  memmove(buffer, associated_data.data(), ad_len);
  // Encrypt the plaintext into the buffer.
  size_t output_length = 0;
  if (!encrypter_[level]->EncryptPacket(
          packet_number.ToUint64(), associated_data,
          packet.Plaintext(version_.transport_version), buffer + ad_len,
          &output_length, buffer_len - ad_len)) {
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }
  if (version_.HasHeaderProtection() &&
      !ApplyHeaderProtection(level, buffer, ad_len + output_length, ad_len)) {
    QUIC_DLOG(ERROR) << "Applying header protection failed.";
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  return ad_len + output_length;
}

size_t QuicFramer::GetCiphertextSize(EncryptionLevel level,
                                     size_t plaintext_size) const {
  if (encrypter_[level] == nullptr) {
    QUIC_BUG(quic_bug_10850_65)
        << ENDPOINT
        << "Attempted to get ciphertext size without encrypter at level "
        << level << " using " << version_;
    return plaintext_size;
  }
  return encrypter_[level]->GetCiphertextSize(plaintext_size);
}

size_t QuicFramer::GetMaxPlaintextSize(size_t ciphertext_size) {
  // In order to keep the code simple, we don't have the current encryption
  // level to hand. Both the NullEncrypter and AES-GCM have a tag length of 12.
  size_t min_plaintext_size = ciphertext_size;

  for (int i = ENCRYPTION_INITIAL; i < NUM_ENCRYPTION_LEVELS; i++) {
    if (encrypter_[i] != nullptr) {
      size_t size = encrypter_[i]->GetMaxPlaintextSize(ciphertext_size);
      if (size < min_plaintext_size) {
        min_plaintext_size = size;
      }
    }
  }

  return min_plaintext_size;
}

QuicPacketCount QuicFramer::GetOneRttEncrypterConfidentialityLimit() const {
  if (!encrypter_[ENCRYPTION_FORWARD_SECURE]) {
    QUIC_BUG(quic_bug_10850_66) << "1-RTT encrypter not set";
    return 0;
  }
  return encrypter_[ENCRYPTION_FORWARD_SECURE]->GetConfidentialityLimit();
}

bool QuicFramer::DecryptPayload(size_t udp_packet_length,
                                absl::string_view encrypted,
                                absl::string_view associated_data,
                                const QuicPacketHeader& header,
                                char* decrypted_buffer, size_t buffer_length,
                                size_t* decrypted_length,
                                EncryptionLevel* decrypted_level) {
  if (!EncryptionLevelIsValid(decrypter_level_)) {
    QUIC_BUG(quic_bug_10850_67)
        << "Attempted to decrypt with bad decrypter_level_";
    return false;
  }
  EncryptionLevel level = decrypter_level_;
  QuicDecrypter* decrypter = decrypter_[level].get();
  QuicDecrypter* alternative_decrypter = nullptr;
  bool key_phase_parsed = false;
  bool key_phase;
  bool attempt_key_update = false;
  if (version().KnowsWhichDecrypterToUse()) {
    if (header.form == GOOGLE_QUIC_PACKET) {
      QUIC_BUG(quic_bug_10850_68)
          << "Attempted to decrypt GOOGLE_QUIC_PACKET with a version that "
             "knows which decrypter to use";
      return false;
    }
    level = GetEncryptionLevel(header);
    if (!EncryptionLevelIsValid(level)) {
      QUIC_BUG(quic_bug_10850_69) << "Attempted to decrypt with bad level";
      return false;
    }
    decrypter = decrypter_[level].get();
    if (decrypter == nullptr) {
      return false;
    }
    if (level == ENCRYPTION_ZERO_RTT &&
        perspective_ == Perspective::IS_CLIENT && header.nonce != nullptr) {
      decrypter->SetDiversificationNonce(*header.nonce);
    }
    if (support_key_update_for_connection_ &&
        header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
      QUICHE_DCHECK(version().UsesTls());
      QUICHE_DCHECK_EQ(level, ENCRYPTION_FORWARD_SECURE);
      key_phase = (header.type_byte & FLAGS_KEY_PHASE_BIT) != 0;
      key_phase_parsed = true;
      QUIC_DVLOG(1) << ENDPOINT << "packet " << header.packet_number
                    << " received key_phase=" << key_phase
                    << " current_key_phase_bit_=" << current_key_phase_bit_;
      if (key_phase != current_key_phase_bit_) {
        if ((current_key_phase_first_received_packet_number_.IsInitialized() &&
             header.packet_number >
                 current_key_phase_first_received_packet_number_) ||
            (!current_key_phase_first_received_packet_number_.IsInitialized() &&
             !key_update_performed_)) {
          if (!next_decrypter_) {
            next_decrypter_ =
                visitor_->AdvanceKeysAndCreateCurrentOneRttDecrypter();
            if (!next_decrypter_) {
              QUIC_BUG(quic_bug_10850_70) << "Failed to create next_decrypter";
              return false;
            }
          }
          QUIC_DVLOG(1) << ENDPOINT << "packet " << header.packet_number
                        << " attempt_key_update=true";
          attempt_key_update = true;
          potential_peer_key_update_attempt_count_++;
          decrypter = next_decrypter_.get();
        } else {
          if (previous_decrypter_) {
            QUIC_DVLOG(1) << ENDPOINT
                          << "trying previous_decrypter_ for packet "
                          << header.packet_number;
            decrypter = previous_decrypter_.get();
          } else {
            QUIC_DVLOG(1) << ENDPOINT << "dropping packet "
                          << header.packet_number << " with old key phase";
            return false;
          }
        }
      }
    }
  } else if (alternative_decrypter_level_ != NUM_ENCRYPTION_LEVELS) {
    if (!EncryptionLevelIsValid(alternative_decrypter_level_)) {
      QUIC_BUG(quic_bug_10850_71)
          << "Attempted to decrypt with bad alternative_decrypter_level_";
      return false;
    }
    alternative_decrypter = decrypter_[alternative_decrypter_level_].get();
  }

  if (decrypter == nullptr) {
    QUIC_BUG(quic_bug_10850_72)
        << "Attempting to decrypt without decrypter, encryption level:" << level
        << " version:" << version();
    return false;
  }

  bool success = decrypter->DecryptPacket(
      header.packet_number.ToUint64(), associated_data, encrypted,
      decrypted_buffer, decrypted_length, buffer_length);
  if (success) {
    visitor_->OnDecryptedPacket(udp_packet_length, level);
    if (level == ENCRYPTION_ZERO_RTT &&
        current_key_phase_first_received_packet_number_.IsInitialized() &&
        header.packet_number >
            current_key_phase_first_received_packet_number_) {
      set_detailed_error(absl::StrCat(
          "Decrypted a 0-RTT packet with a packet number ",
          header.packet_number.ToString(),
          " which is higher than a 1-RTT packet number ",
          current_key_phase_first_received_packet_number_.ToString()));
      return RaiseError(QUIC_INVALID_0RTT_PACKET_NUMBER_OUT_OF_ORDER);
    }
    *decrypted_level = level;
    potential_peer_key_update_attempt_count_ = 0;
    if (attempt_key_update) {
      if (!DoKeyUpdate(KeyUpdateReason::kRemote)) {
        set_detailed_error("Key update failed due to internal error");
        return RaiseError(QUIC_INTERNAL_ERROR);
      }
      QUICHE_DCHECK_EQ(current_key_phase_bit_, key_phase);
    }
    if (key_phase_parsed &&
        !current_key_phase_first_received_packet_number_.IsInitialized() &&
        key_phase == current_key_phase_bit_) {
      // Set packet number for current key phase if it hasn't been initialized
      // yet. This is set outside of attempt_key_update since the key update
      // may have been initiated locally, and in that case we don't know yet
      // which packet number from the remote side to use until we receive a
      // packet with that phase.
      QUIC_DVLOG(1) << ENDPOINT
                    << "current_key_phase_first_received_packet_number_ = "
                    << header.packet_number;
      current_key_phase_first_received_packet_number_ = header.packet_number;
      visitor_->OnDecryptedFirstPacketInKeyPhase();
    }
  } else if (alternative_decrypter != nullptr) {
    if (header.nonce != nullptr) {
      QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
      alternative_decrypter->SetDiversificationNonce(*header.nonce);
    }
    bool try_alternative_decryption = true;
    if (alternative_decrypter_level_ == ENCRYPTION_ZERO_RTT) {
      if (perspective_ == Perspective::IS_CLIENT) {
        if (header.nonce == nullptr) {
          // Can not use INITIAL decryption without a diversification nonce.
          try_alternative_decryption = false;
        }
      } else {
        QUICHE_DCHECK(header.nonce == nullptr);
      }
    }

    if (try_alternative_decryption) {
      success = alternative_decrypter->DecryptPacket(
          header.packet_number.ToUint64(), associated_data, encrypted,
          decrypted_buffer, decrypted_length, buffer_length);
    }
    if (success) {
      visitor_->OnDecryptedPacket(udp_packet_length,
                                  alternative_decrypter_level_);
      *decrypted_level = decrypter_level_;
      if (alternative_decrypter_latch_) {
        if (!EncryptionLevelIsValid(alternative_decrypter_level_)) {
          QUIC_BUG(quic_bug_10850_73)
              << "Attempted to latch alternate decrypter with bad "
                 "alternative_decrypter_level_";
          return false;
        }
        // Switch to the alternative decrypter and latch so that we cannot
        // switch back.
        decrypter_level_ = alternative_decrypter_level_;
        alternative_decrypter_level_ = NUM_ENCRYPTION_LEVELS;
      } else {
        // Switch the alternative decrypter so that we use it first next time.
        EncryptionLevel alt_level = alternative_decrypter_level_;
        alternative_decrypter_level_ = decrypter_level_;
        decrypter_level_ = alt_level;
      }
    }
  }

  if (!success) {
    QUIC_DVLOG(1) << ENDPOINT << "DecryptPacket failed for: " << header;
    return false;
  }

  return true;
}

size_t QuicFramer::GetIetfAckFrameSize(const QuicAckFrame& frame) {
  // Type byte, largest_acked, and delay_time are straight-forward.
  size_t ack_frame_size = kQuicFrameTypeSize;
  QuicPacketNumber largest_acked = LargestAcked(frame);
  ack_frame_size += QuicDataWriter::GetVarInt62Len(largest_acked.ToUint64());
  uint64_t ack_delay_time_us;
  ack_delay_time_us = frame.ack_delay_time.ToMicroseconds();
  ack_delay_time_us = ack_delay_time_us >> local_ack_delay_exponent_;
  ack_frame_size += QuicDataWriter::GetVarInt62Len(ack_delay_time_us);

  if (frame.packets.Empty() || frame.packets.Max() != largest_acked) {
    QUIC_BUG(quic_bug_10850_74) << "Malformed ack frame";
    // ACK frame serialization will fail and connection will be closed.
    return ack_frame_size;
  }

  // Ack block count.
  ack_frame_size +=
      QuicDataWriter::GetVarInt62Len(frame.packets.NumIntervals() - 1);

  // First Ack range.
  auto iter = frame.packets.rbegin();
  ack_frame_size += QuicDataWriter::GetVarInt62Len(iter->Length() - 1);
  QuicPacketNumber previous_smallest = iter->min();
  ++iter;

  // Ack blocks.
  for (; iter != frame.packets.rend(); ++iter) {
    const uint64_t gap = previous_smallest - iter->max() - 1;
    const uint64_t ack_range = iter->Length() - 1;
    ack_frame_size += (QuicDataWriter::GetVarInt62Len(gap) +
                       QuicDataWriter::GetVarInt62Len(ack_range));
    previous_smallest = iter->min();
  }

  if (UseIetfAckWithReceiveTimestamp(frame)) {
    ack_frame_size += GetIetfAckFrameTimestampSize(frame);
  } else {
    ack_frame_size += AckEcnCountSize(frame);
  }

  return ack_frame_size;
}

size_t QuicFramer::GetIetfAckFrameTimestampSize(const QuicAckFrame& ack) {
  QUICHE_DCHECK(!ack.received_packet_times.empty());
  std::string detailed_error;
  absl::InlinedVector<AckTimestampRange, 2> timestamp_ranges =
      GetAckTimestampRanges(ack, detailed_error);
  if (!detailed_error.empty()) {
    return 0;
  }

  int64_t size =
      FrameAckTimestampRanges(ack, timestamp_ranges, /*writer=*/nullptr);
  return std::max<int64_t>(0, size);
}

size_t QuicFramer::GetAckFrameSize(
    const QuicAckFrame& ack, QuicPacketNumberLength /*packet_number_length*/) {
  QUICHE_DCHECK(!ack.packets.Empty());
  size_t ack_size = 0;

  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    return GetIetfAckFrameSize(ack);
  }
  AckFrameInfo ack_info = GetAckFrameInfo(ack);
  QuicPacketNumberLength ack_block_length =
      GetMinPacketNumberLength(QuicPacketNumber(ack_info.max_block_length));

  ack_size = GetMinAckFrameSize(version_.transport_version, ack,
                                local_ack_delay_exponent_,
                                UseIetfAckWithReceiveTimestamp(ack));
  // First ack block length.
  ack_size += ack_block_length;
  if (ack_info.num_ack_blocks != 0) {
    ack_size += kNumberOfAckBlocksSize;
    ack_size += std::min(ack_info.num_ack_blocks, kMaxAckBlocks) *
                (ack_block_length + PACKET_1BYTE_PACKET_NUMBER);
  }

  // Include timestamps.
  if (process_timestamps_) {
    ack_size += GetAckFrameTimeStampSize(ack);
  }

  return ack_size;
}

size_t QuicFramer::GetAckFrameTimeStampSize(const QuicAckFrame& ack) {
  if (ack.received_packet_times.empty()) {
    return 0;
  }

  return kQuicNumTimestampsLength + kQuicFirstTimestampLength +
         (kQuicTimestampLength + kQuicTimestampPacketNumberGapLength) *
             (ack.received_packet_times.size() - 1);
}

size_t QuicFramer::ComputeFrameLength(
    const QuicFrame& frame, bool last_frame_in_packet,
    QuicPacketNumberLength packet_number_length) {
  switch (frame.type) {
    case STREAM_FRAME:
      return GetMinStreamFrameSize(
                 version_.transport_version, frame.stream_frame.stream_id,
                 frame.stream_frame.offset, last_frame_in_packet,
                 frame.stream_frame.data_length) +
             frame.stream_frame.data_length;
    case CRYPTO_FRAME:
      return GetMinCryptoFrameSize(frame.crypto_frame->offset,
                                   frame.crypto_frame->data_length) +
             frame.crypto_frame->data_length;
    case ACK_FRAME: {
      return GetAckFrameSize(*frame.ack_frame, packet_number_length);
    }
    case STOP_WAITING_FRAME:
      return GetStopWaitingFrameSize(packet_number_length);
    case MTU_DISCOVERY_FRAME:
      // MTU discovery frames are serialized as ping frames.
      return kQuicFrameTypeSize;
    case MESSAGE_FRAME:
      return GetMessageFrameSize(last_frame_in_packet,
                                 frame.message_frame->message_length);
    case PADDING_FRAME:
      QUICHE_DCHECK(false);
      return 0;
    default:
      return GetRetransmittableControlFrameSize(version_.transport_version,
                                                frame);
  }
}

bool QuicFramer::AppendTypeByte(const QuicFrame& frame,
                                bool last_frame_in_packet,
                                QuicDataWriter* writer) {
  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    return AppendIetfFrameType(frame, last_frame_in_packet, writer);
  }
  uint8_t type_byte = 0;
  switch (frame.type) {
    case STREAM_FRAME:
      type_byte =
          GetStreamFrameTypeByte(frame.stream_frame, last_frame_in_packet);
      break;
    case ACK_FRAME:
      return true;
    case MTU_DISCOVERY_FRAME:
      type_byte = static_cast<uint8_t>(PING_FRAME);
      break;
    case NEW_CONNECTION_ID_FRAME:
      set_detailed_error(
          "Attempt to append NEW_CONNECTION_ID frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case RETIRE_CONNECTION_ID_FRAME:
      set_detailed_error(
          "Attempt to append RETIRE_CONNECTION_ID frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case NEW_TOKEN_FRAME:
      set_detailed_error(
          "Attempt to append NEW_TOKEN frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case MAX_STREAMS_FRAME:
      set_detailed_error(
          "Attempt to append MAX_STREAMS frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case STREAMS_BLOCKED_FRAME:
      set_detailed_error(
          "Attempt to append STREAMS_BLOCKED frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case PATH_RESPONSE_FRAME:
      set_detailed_error(
          "Attempt to append PATH_RESPONSE frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case PATH_CHALLENGE_FRAME:
      set_detailed_error(
          "Attempt to append PATH_CHALLENGE frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case STOP_SENDING_FRAME:
      set_detailed_error(
          "Attempt to append STOP_SENDING frame and not in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case MESSAGE_FRAME:
      return true;

    default:
      type_byte = static_cast<uint8_t>(frame.type);
      break;
  }

  return writer->WriteUInt8(type_byte);
}

bool QuicFramer::AppendIetfFrameType(const QuicFrame& frame,
                                     bool last_frame_in_packet,
                                     QuicDataWriter* writer) {
  uint8_t type_byte = 0;
  switch (frame.type) {
    case PADDING_FRAME:
      type_byte = IETF_PADDING;
      break;
    case RST_STREAM_FRAME:
      type_byte = IETF_RST_STREAM;
      break;
    case CONNECTION_CLOSE_FRAME:
      switch (frame.connection_close_frame->close_type) {
        case IETF_QUIC_APPLICATION_CONNECTION_CLOSE:
          type_byte = IETF_APPLICATION_CLOSE;
          break;
        case IETF_QUIC_TRANSPORT_CONNECTION_CLOSE:
          type_byte = IETF_CONNECTION_CLOSE;
          break;
        default:
          set_detailed_error(absl::StrCat(
              "Invalid QuicConnectionCloseFrame type: ",
              static_cast<int>(frame.connection_close_frame->close_type)));
          return RaiseError(QUIC_INTERNAL_ERROR);
      }
      break;
    case GOAWAY_FRAME:
      set_detailed_error(
          "Attempt to create non-IETF QUIC GOAWAY frame in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case WINDOW_UPDATE_FRAME:
      // Depending on whether there is a stream ID or not, will be either a
      // MAX_STREAM_DATA frame or a MAX_DATA frame.
      if (frame.window_update_frame.stream_id ==
          QuicUtils::GetInvalidStreamId(transport_version())) {
        type_byte = IETF_MAX_DATA;
      } else {
        type_byte = IETF_MAX_STREAM_DATA;
      }
      break;
    case BLOCKED_FRAME:
      if (frame.blocked_frame.stream_id ==
          QuicUtils::GetInvalidStreamId(transport_version())) {
        type_byte = IETF_DATA_BLOCKED;
      } else {
        type_byte = IETF_STREAM_DATA_BLOCKED;
      }
      break;
    case STOP_WAITING_FRAME:
      set_detailed_error(
          "Attempt to append type byte of STOP WAITING frame in IETF QUIC.");
      return RaiseError(QUIC_INTERNAL_ERROR);
    case PING_FRAME:
      type_byte = IETF_PING;
      break;
    case STREAM_FRAME:
      type_byte =
          GetStreamFrameTypeByte(frame.stream_frame, last_frame_in_packet);
      break;
    case ACK_FRAME:
      // Do nothing here, AppendIetfAckFrameAndTypeByte() will put the type byte
      // in the buffer.
      return true;
    case MTU_DISCOVERY_FRAME:
      // The path MTU discovery frame is encoded as a PING frame on the wire.
      type_byte = IETF_PING;
      break;
    case NEW_CONNECTION_ID_FRAME:
      type_byte = IETF_NEW_CONNECTION_ID;
      break;
    case RETIRE_CONNECTION_ID_FRAME:
      type_byte = IETF_RETIRE_CONNECTION_ID;
      break;
    case NEW_TOKEN_FRAME:
      type_byte = IETF_NEW_TOKEN;
      break;
    case MAX_STREAMS_FRAME:
      if (frame.max_streams_frame.unidirectional) {
        type_byte = IETF_MAX_STREAMS_UNIDIRECTIONAL;
      } else {
        type_byte = IETF_MAX_STREAMS_BIDIRECTIONAL;
      }
      break;
    case STREAMS_BLOCKED_FRAME:
      if (frame.streams_blocked_frame.unidirectional) {
        type_byte = IETF_STREAMS_BLOCKED_UNIDIRECTIONAL;
      } else {
        type_byte = IETF_STREAMS_BLOCKED_BIDIRECTIONAL;
      }
      break;
    case PATH_RESPONSE_FRAME:
      type_byte = IETF_PATH_RESPONSE;
      break;
    case PATH_CHALLENGE_FRAME:
      type_byte = IETF_PATH_CHALLENGE;
      break;
    case STOP_SENDING_FRAME:
      type_byte = IETF_STOP_SENDING;
      break;
    case MESSAGE_FRAME:
      return true;
    case CRYPTO_FRAME:
      type_byte = IETF_CRYPTO;
      break;
    case HANDSHAKE_DONE_FRAME:
      type_byte = IETF_HANDSHAKE_DONE;
      break;
    case ACK_FREQUENCY_FRAME:
      type_byte = IETF_ACK_FREQUENCY;
      break;
    case RESET_STREAM_AT_FRAME:
      type_byte = IETF_RESET_STREAM_AT;
      break;
    default:
      QUIC_BUG(quic_bug_10850_75)
          << "Attempt to generate a frame type for an unsupported value: "
          << frame.type;
      return false;
  }
  return writer->WriteVarInt62(type_byte);
}

// static
bool QuicFramer::AppendPacketNumber(QuicPacketNumberLength packet_number_length,
                                    QuicPacketNumber packet_number,
                                    QuicDataWriter* writer) {
  QUICHE_DCHECK(packet_number.IsInitialized());
  if (!IsValidPacketNumberLength(packet_number_length)) {
    QUIC_BUG(quic_bug_10850_76)
        << "Invalid packet_number_length: " << packet_number_length;
    return false;
  }
  return writer->WriteBytesToUInt64(packet_number_length,
                                    packet_number.ToUint64());
}

// static
bool QuicFramer::AppendStreamId(size_t stream_id_length, QuicStreamId stream_id,
                                QuicDataWriter* writer) {
  if (stream_id_length == 0 || stream_id_length > 4) {
    QUIC_BUG(quic_bug_10850_77)
        << "Invalid stream_id_length: " << stream_id_length;
    return false;
  }
  return writer->WriteBytesToUInt64(stream_id_length, stream_id);
}

// static
bool QuicFramer::AppendStreamOffset(size_t offset_length,
                                    QuicStreamOffset offset,
                                    QuicDataWriter* writer) {
  if (offset_length == 1 || offset_length > 8) {
    QUIC_BUG(quic_bug_10850_78)
        << "Invalid stream_offset_length: " << offset_length;
    return false;
  }

  return writer->WriteBytesToUInt64(offset_length, offset);
}

// static
bool QuicFramer::AppendAckBlock(uint8_t gap,
                                QuicPacketNumberLength length_length,
                                uint64_t length, QuicDataWriter* writer) {
  if (length == 0) {
    if (!IsValidPacketNumberLength(length_length)) {
      QUIC_BUG(quic_bug_10850_79)
          << "Invalid packet_number_length: " << length_length;
      return false;
    }
    return writer->WriteUInt8(gap) &&
           writer->WriteBytesToUInt64(length_length, length);
  }
  return writer->WriteUInt8(gap) &&
         AppendPacketNumber(length_length, QuicPacketNumber(length), writer);
}

bool QuicFramer::AppendStreamFrame(const QuicStreamFrame& frame,
                                   bool no_stream_frame_length,
                                   QuicDataWriter* writer) {
  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    return AppendIetfStreamFrame(frame, no_stream_frame_length, writer);
  }
  if (!AppendStreamId(GetStreamIdSize(frame.stream_id), frame.stream_id,
                      writer)) {
    QUIC_BUG(quic_bug_10850_80) << "Writing stream id size failed.";
    return false;
  }
  if (!AppendStreamOffset(GetStreamOffsetSize(frame.offset), frame.offset,
                          writer)) {
    QUIC_BUG(quic_bug_10850_81) << "Writing offset size failed.";
    return false;
  }
  if (!no_stream_frame_length) {
    static_assert(
        std::numeric_limits<decltype(frame.data_length)>::max() <=
            std::numeric_limits<uint16_t>::max(),
        "If frame.data_length can hold more than a uint16_t than we need to "
        "check that frame.data_length <= std::numeric_limits<uint16_t>::max()");
    if (!writer->WriteUInt16(static_cast<uint16_t>(frame.data_length))) {
      QUIC_BUG(quic_bug_10850_82) << "Writing stream frame length failed";
      return false;
    }
  }

  if (data_producer_ != nullptr) {
    QUICHE_DCHECK_EQ(nullptr, frame.data_buffer);
    if (frame.data_length == 0) {
      return true;
    }
    if (data_producer_->WriteStreamData(frame.stream_id, frame.offset,
                                        frame.data_length,
                                        writer) != WRITE_SUCCESS) {
      QUIC_BUG(quic_bug_10850_83) << "Writing frame data failed.";
      return false;
    }
    return true;
  }

  if (!writer->WriteBytes(frame.data_buffer, frame.data_length)) {
    QUIC_BUG(quic_bug_10850_84) << "Writing frame data failed.";
    return false;
  }
  return true;
}

bool QuicFramer::AppendNewTokenFrame(const QuicNewTokenFrame& frame,
                                     QuicDataWriter* writer) {
  if (!writer->WriteVarInt62(static_cast<uint64_t>(frame.token.length()))) {
    set_detailed_error("Writing token length failed.");
    return false;
  }
  if (!writer->WriteBytes(frame.token.data(), frame.token.length())) {
    set_detailed_error("Writing token buffer failed.");
    return false;
  }
  return true;
}

bool QuicFramer::ProcessNewTokenFrame(QuicDataReader* reader,
                                      QuicNewTokenFrame* frame) {
  uint64_t length;
  if (!reader->ReadVarInt62(&length)) {
    set_detailed_error("Unable to read new token length.");
    return false;
  }
  if (length > kMaxNewTokenTokenLength) {
    set_detailed_error("Token length larger than maximum.");
    return false;
  }

  // TODO(ianswett): Don't use absl::string_view as an intermediary.
  absl::string_view data;
  if (!reader->ReadStringPiece(&data, length)) {
    set_detailed_error("Unable to read new token data.");
    return false;
  }
  frame->token = std::string(data);
  return true;
}

// Add a new ietf-format stream frame.
// Bits controlling whether there is a frame-length and frame-offset
// are in the QuicStreamFrame.
bool QuicFramer::AppendIetfStreamFrame(const QuicStreamFrame& frame,
                                       bool last_frame_in_packet,
                                       QuicDataWriter* writer) {
  if (!writer->WriteVarInt62(static_cast<uint64_t>(frame.stream_id))) {
    set_detailed_error("Writing stream id failed.");
    return false;
  }

  if (frame.offset != 0) {
    if (!writer->WriteVarInt62(static_cast<uint64_t>(frame.offset))) {
      set_detailed_error("Writing data offset failed.");
      return f
"""


```