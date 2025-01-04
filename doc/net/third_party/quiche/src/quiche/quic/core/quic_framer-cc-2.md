Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of the `QuicFramer` class in Chromium's QUIC implementation. The request has several constraints:

1. **List functionalities:** Identify the main tasks performed by this code.
2. **Relation to JavaScript:** Explain if and how this code relates to JavaScript's functionality.
3. **Logical reasoning (input/output):**  Provide examples of input data and the expected output after processing.
4. **Common user/programming errors:** Highlight typical mistakes users or developers might make related to this code.
5. **User action leading here:** Describe how a user interaction in a browser could lead to this code being executed.
6. **Part of a larger context:** Acknowledge that this is part 3 of 9 and summarize its role within the broader file.

**Mental Sandbox Simulation:**

* **Functionality identification:**  The code primarily deals with parsing and decrypting incoming QUIC packets. It handles different header formats (short and long), version negotiation, connection IDs, packet numbers, header protection, and payload decryption. It also interacts with a visitor pattern (`visitor_`) to notify higher-level components about the parsed packet structure.
* **JavaScript relationship:** QUIC is a transport protocol underlying web communication. JavaScript running in a browser initiates requests that trigger QUIC connections. This C++ code on the server-side or within the browser's networking stack handles the low-level packet processing related to those requests. The connection is indirect; JavaScript doesn't directly call this C++ code but initiates actions that lead to its execution.
* **Input/Output:** Need to consider the input as the raw bytes of an encrypted QUIC packet and the output as the parsed header information and the decrypted payload. Different header types and scenarios will lead to different processing paths.
* **Common errors:** Misconfiguration of encryption keys, incorrect packet formatting, version mismatches, and issues with connection ID handling are likely candidates for common errors.
* **User action:**  A simple user action like navigating to a website that uses QUIC will trigger the underlying QUIC connection setup and data transfer, eventually leading to this code processing incoming packets.
* **Part 3 of 9:** Considering the surrounding code (based on the "part 3" indication), this section likely focuses on the core packet processing logic *after* initial header parsing (which might be in parts 1 and 2) and *before* higher-level frame processing (which might be in later parts).

**Constraint Checklist & Confidence Score:**

1. List functionalities: Yes
2. Relation to JavaScript: Yes
3. Logical reasoning (input/output): Yes
4. Common user/programming errors: Yes
5. User action leading here: Yes
6. Part of a larger context: Yes

Confidence Score: 5/5  I am confident I can address all constraints effectively.

**Strategizing complete.** I will now generate the response based on the analysis above.
这是文件 `net/third_party/quiche/src/quiche/quic/core/quic_framer.cc` 的第三部分，主要负责**处理接收到的 QUIC 数据包**，包括认证、解密和初步解析数据包头和有效载荷。

以下是该部分的主要功能归纳：

**主要功能:**

* **数据包接收和初步处理:**
    * 接收一个加密的 QUIC 数据包 (`QuicEncryptedPacket`).
    * 检查数据包头部的基本信息，例如是否为长头部或短头部。
    * 对于短头部数据包，检查是否存在可能的无状态重置令牌。
    * 处理数据包长度字段。
* **数据包号处理:**
    * 根据数据包头部的类型（短头部或长头部）以及是否启用了多数据包号空间，确定用于解析数据包号的基础数据包号。
    * **移除头部保护 (Header Protection):** 如果 QUIC 版本支持头部保护，则尝试使用相应的解密器移除头部保护，并解析出完整的数据包号。
    * **解析数据包号:** 如果未启用头部保护，则直接从数据流中解析数据包号。
    * **验证数据包号:** 检查解析出的数据包号是否有效。
* **无状态重置处理:** 如果在头部保护移除失败或数据包号无效的情况下，检测到可能是无状态重置包，则通知 `visitor_`。
* **数据包解密:**
    * 根据数据包头部的信息（例如加密级别），选择合适的解密器。
    * 使用关联数据 (associated data) 解密数据包的有效载荷。
    * 处理解密失败的情况，例如，如果检测到可能是无状态重置包，则通知 `visitor_`，否则通知 `visitor_` 数据包无法解密。
* **数据包大小检查:** 检查解密后的数据包大小是否超过最大允许值。
* **数据包头通知:**  在成功解密后，通知 `visitor_` 接收到的数据包头信息。
* **数据帧处理:**
    * 根据 QUIC 版本是否支持 IETF QUIC 帧格式，调用不同的函数 (`ProcessIetfFrameData` 或 `ProcessFrameData`) 来进一步解析数据包中的帧数据。
* **数据包完成通知:**  在数据包处理完成后，通知 `visitor_`。
* **判断是否为无状态重置包:** 提供函数 `IsIetfStatelessResetPacket` 来判断接收到的数据包是否为无状态重置包。
* **加密器和解密器状态查询:** 提供函数来检查特定加密级别是否存在加密器或解密器。
* **确定发送应用数据的加密级别:** 提供函数 `GetEncryptionLevelToSendApplicationData` 来确定发送应用数据应该使用的加密级别。
* **构建和追加数据包头部:** 提供函数 `AppendIetfHeaderTypeByte` 和 `AppendIetfPacketHeader` 用于构建和追加数据包头部信息到数据写入器。
* **时间戳和数据包号计算:** 提供函数 `CalculateTimestampFromWire` 和 `CalculatePacketNumberFromWire` 用于从网络字节序计算出本地时间戳和数据包号。
* **获取最小数据包号长度:** 提供静态函数 `GetMinPacketNumberLength` 来根据数据包号确定最小的字节长度。
* **获取数据包号标志:** 提供静态函数 `GetPacketNumberFlags` 来根据数据包号长度获取对应的标志。
* **获取 ACK 帧信息:** 提供静态函数 `GetAckFrameInfo` 来获取 ACK 帧的相关信息，例如 ACK 块的数量和最大长度。
* **解析数据包头部字节:** 提供函数 `ProcessIetfHeaderTypeByte` 用于解析数据包的第一个字节，确定数据包类型和头部格式。
* **解析版本标签:** 提供静态函数 `ProcessVersionLabel` 用于解析版本标签。
* **处理和验证连接 ID 长度:** 提供静态函数 `ProcessAndValidateIetfConnectionIdLength` 用于处理和验证连接 ID 的长度。
* **验证接收到的连接 ID:** 提供函数 `ValidateReceivedConnectionIds` 用于验证接收到的连接 ID 是否有效。
* **完整解析 IETF 数据包头部:** 提供函数 `ProcessIetfPacketHeader` 用于从数据流中完整解析 IETF QUIC 数据包的头部信息。
* **处理并计算数据包号:** 提供函数 `ProcessAndCalculatePacketNumber` 用于从数据流中读取并计算出完整的数据包号。

**与 JavaScript 的关系:**

这段 C++ 代码直接运行在 Chromium 浏览器的底层网络栈中，负责处理 QUIC 协议的细节。JavaScript 代码本身并不直接调用这些 C++ 函数。然而，当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，如果浏览器和服务器之间协商使用了 QUIC 协议，那么接收到的 QUIC 数据包最终会被这个 `QuicFramer` 类处理。

**举例说明:**

假设 JavaScript 代码发起了一个 `fetch('https://example.com/data')` 请求，并且该连接使用了 QUIC 协议。

1. **假设输入:** 浏览器接收到了来自 `example.com` 服务器的一个加密的 QUIC 数据包，其原始字节流可能如下（这是一个简化的例子，实际情况会复杂得多）：
   ```
   \xc3\x00\x00\x00\x01\x08\x12\x34\x56\x78\x04\xaa\xbb\xcc\xdd\x05\x00\x01\x02\x03\x...
   ```
   这个字节流代表了一个 IETF QUIC 短头部数据包，包含了连接 ID、数据包号和加密的有效载荷。

2. **逻辑推理与输出:** `QuicFramer::ProcessPacket` 函数接收到这个 `QuicEncryptedPacket` 后：
   * 会调用 `ProcessIetfHeaderTypeByte` 解析第一个字节 `\xc3`，判断这是一个短头部数据包。
   * 如果是短头部，且是客户端，可能会尝试读取无状态重置令牌。
   * 调用 `MaybeProcessIetfLength` 处理可能的长度字段。
   * 调用 `ProcessAndCalculatePacketNumber` 从数据流中解析出数据包号（假设成功解密头部保护）。假设基础数据包号是 100，解析出的数据包号长度为 2 字节，从字节 `\x00\x01` 中计算出完整的数据包号可能是 101。
   * 调用 `DecryptPayload` 使用相应的密钥解密剩余的字节流，得到解密后的数据。
   * 创建 `QuicDataReader` 读取解密后的数据，并调用 `ProcessIetfFrameData` 或 `ProcessFrameData` 解析其中的 QUIC 帧，例如 `STREAM` 帧，其中包含了服务器返回的 `example.com/data` 的内容。

**用户或编程常见的使用错误:**

1. **配置错误的解密密钥:** 如果服务器配置了错误的解密密钥，或者客户端使用的密钥与服务器不匹配，`DecryptPayload` 函数会返回失败，导致 `OnUndecryptablePacket` 被调用。这通常是由于密钥协商或配置错误导致的。
   * **假设输入:** 接收到一个使用错误的密钥加密的数据包。
   * **预期行为:** `DecryptPayload` 返回 `false`，`visitor_->OnUndecryptablePacket` 被调用，浏览器可能会断开连接或尝试重新协商。

2. **接收到不符合预期的包类型:** 例如，客户端在不应该收到长头部数据包的时候收到了，或者收到了格式错误的头部。这可能表明网络传输错误或对端实现存在问题。
   * **假设输入:** 服务器错误地发送了一个本应只由客户端发送的类型的长头部数据包。
   * **预期行为:** `ProcessIetfHeaderTypeByte` 或 `ProcessIetfPacketHeader` 会检测到错误，设置 `detailed_error_` 并调用 `RaiseError`，导致连接异常。

3. **数据包过大:** 如果接收到的数据包解密后的大小超过了 `kMaxIncomingPacketSize`，会导致 `RaiseError(QUIC_PACKET_TOO_LARGE)`。这通常是由于恶意攻击或配置错误导致的。
   * **假设输入:** 接收到一个大小超过限制的数据包。
   * **预期行为:**  `ProcessPacket` 检测到大小超限，调用 `RaiseError`，浏览器可能会记录错误并断开连接。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Chrome 浏览器中输入一个使用了 QUIC 协议的 HTTPS 网址，例如 `https://www.google.com`。**
2. **浏览器发起连接请求。** 如果之前没有与该服务器建立 QUIC 连接，浏览器会尝试与服务器进行 QUIC 握手。
3. **服务器接受连接，并开始发送 QUIC 数据包。** 这些数据包包含了网页的内容、图片、CSS、JavaScript 等资源。
4. **网络层接收到这些来自服务器的 UDP 数据包。**
5. **Chromium 的网络栈（Net 模块）识别出这些是 QUIC 数据包，并将其传递给 `QuicConnection` 对象进行处理。**
6. **`QuicConnection` 对象会将接收到的加密数据包传递给 `QuicFramer::ProcessPacket` 函数。**
7. **`QuicFramer::ProcessPacket` 内部的逻辑（如这段代码所示）会进行数据包头的解析、解密和帧数据的处理。**
8. **如果一切顺利，解密后的数据会被传递给更上层的模块，最终由渲染引擎解析并显示在用户的浏览器窗口中。**

在调试过程中，如果发现网络请求失败或网页加载异常，可以检查网络日志（Chrome DevTools 的 Network 面板）查看是否发生了 QUIC 协议错误。如果需要深入分析 QUIC 协议的细节，可以使用抓包工具（如 Wireshark）捕获网络数据包，并结合 Chromium 的源码进行分析，理解 `QuicFramer` 如何处理接收到的数据包。

**作为第 3 部分的功能归纳:**

这部分 `QuicFramer` 的代码是接收 QUIC 数据包处理流程的核心部分，负责**从接收到的加密字节流中提取出有用的信息**。它完成了以下关键步骤：

* **识别和初步解析数据包头部。**
* **验证和计算数据包号，这是保证数据包顺序和可靠性的关键。**
* **安全地解密数据包的有效载荷，确保数据的机密性。**
* **为后续的帧数据解析做好准备。**

可以认为，这部分代码是 QUIC 数据包处理的“**认证和解密中心**”，确保接收到的数据包是合法的、没有被篡改的，并且能够被正确地解析和处理。它的输入是原始的加密数据包，输出是解密后的数据和初步解析的头部信息，为后续更高层次的 QUIC 帧处理奠定了基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共9部分，请归纳一下它的功能

"""
                                      char* decrypted_buffer,
                                       size_t buffer_length) {
  QUICHE_DCHECK_NE(GOOGLE_QUIC_PACKET, header->form);
  QUICHE_DCHECK(!header->has_possible_stateless_reset_token);
  header->length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
  header->remaining_packet_length = 0;
  if (header->form == IETF_QUIC_SHORT_HEADER_PACKET &&
      perspective_ == Perspective::IS_CLIENT) {
    // Peek possible stateless reset token. Will only be used on decryption
    // failure.
    absl::string_view remaining = encrypted_reader->PeekRemainingPayload();
    if (remaining.length() >= sizeof(header->possible_stateless_reset_token)) {
      header->has_possible_stateless_reset_token = true;
      memcpy(&header->possible_stateless_reset_token,
             &remaining.data()[remaining.length() -
                               sizeof(header->possible_stateless_reset_token)],
             sizeof(header->possible_stateless_reset_token));
    }
  }

  if (!MaybeProcessIetfLength(encrypted_reader, header)) {
    return false;
  }

  absl::string_view associated_data;
  AssociatedDataStorage ad_storage;
  QuicPacketNumber base_packet_number;
  if (header->form == IETF_QUIC_SHORT_HEADER_PACKET ||
      header->long_packet_type != VERSION_NEGOTIATION) {
    QUICHE_DCHECK(header->form == IETF_QUIC_SHORT_HEADER_PACKET ||
                  header->long_packet_type == INITIAL ||
                  header->long_packet_type == HANDSHAKE ||
                  header->long_packet_type == ZERO_RTT_PROTECTED);
    // Process packet number.
    if (supports_multiple_packet_number_spaces_) {
      PacketNumberSpace pn_space = GetPacketNumberSpace(*header);
      if (pn_space == NUM_PACKET_NUMBER_SPACES) {
        return RaiseError(QUIC_INVALID_PACKET_HEADER);
      }
      base_packet_number = largest_decrypted_packet_numbers_[pn_space];
    } else {
      base_packet_number = largest_packet_number_;
    }
    uint64_t full_packet_number;
    bool hp_removal_failed = false;
    if (version_.HasHeaderProtection()) {
      EncryptionLevel expected_decryption_level = GetEncryptionLevel(*header);
      QuicDecrypter* decrypter = decrypter_[expected_decryption_level].get();
      if (decrypter == nullptr) {
        QUIC_DVLOG(1)
            << ENDPOINT
            << "No decrypter available for removing header protection at level "
            << expected_decryption_level;
        hp_removal_failed = true;
      } else if (!RemoveHeaderProtection(encrypted_reader, packet, *decrypter,
                                         perspective_, version_,
                                         base_packet_number, header,
                                         &full_packet_number, ad_storage)) {
        hp_removal_failed = true;
      }
      associated_data = absl::string_view(ad_storage.data(), ad_storage.size());
    } else if (!ProcessAndCalculatePacketNumber(
                   encrypted_reader, header->packet_number_length,
                   base_packet_number, &full_packet_number)) {
      set_detailed_error("Unable to read packet number.");
      RecordDroppedPacketReason(DroppedPacketReason::INVALID_PACKET_NUMBER);
      return RaiseError(QUIC_INVALID_PACKET_HEADER);
    }

    if (hp_removal_failed ||
        !IsValidFullPacketNumber(full_packet_number, version())) {
      if (IsIetfStatelessResetPacket(*header)) {
        // This is a stateless reset packet.
        QuicIetfStatelessResetPacket reset_packet(
            *header, header->possible_stateless_reset_token);
        visitor_->OnAuthenticatedIetfStatelessResetPacket(reset_packet);
        return true;
      }
      if (hp_removal_failed) {
        const EncryptionLevel decryption_level = GetEncryptionLevel(*header);
        const bool has_decryption_key = decrypter_[decryption_level] != nullptr;
        visitor_->OnUndecryptablePacket(
            QuicEncryptedPacket(encrypted_reader->FullPayload()),
            decryption_level, has_decryption_key);
        RecordDroppedPacketReason(DroppedPacketReason::DECRYPTION_FAILURE);
        set_detailed_error(absl::StrCat(
            "Unable to decrypt ", EncryptionLevelToString(decryption_level),
            " header protection", has_decryption_key ? "" : " (missing key)",
            "."));
        return RaiseError(QUIC_DECRYPTION_FAILURE);
      }
      RecordDroppedPacketReason(DroppedPacketReason::INVALID_PACKET_NUMBER);
      set_detailed_error("packet numbers cannot be 0.");
      return RaiseError(QUIC_INVALID_PACKET_HEADER);
    }
    header->packet_number = QuicPacketNumber(full_packet_number);
  }

  // A nonce should only present in SHLO from the server to the client when
  // using QUIC crypto.
  if (header->form == IETF_QUIC_LONG_HEADER_PACKET &&
      header->long_packet_type == ZERO_RTT_PROTECTED &&
      perspective_ == Perspective::IS_CLIENT &&
      version_.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
    if (!encrypted_reader->ReadBytes(
            reinterpret_cast<uint8_t*>(last_nonce_.data()),
            last_nonce_.size())) {
      set_detailed_error("Unable to read nonce.");
      RecordDroppedPacketReason(
          DroppedPacketReason::INVALID_DIVERSIFICATION_NONCE);
      return RaiseError(QUIC_INVALID_PACKET_HEADER);
    }

    header->nonce = &last_nonce_;
  } else {
    header->nonce = nullptr;
  }

  if (!visitor_->OnUnauthenticatedHeader(*header)) {
    set_detailed_error(
        "Visitor asked to stop processing of unauthenticated header.");
    return false;
  }

  absl::string_view encrypted = encrypted_reader->ReadRemainingPayload();
  if (!version_.HasHeaderProtection()) {
    associated_data = GetAssociatedDataFromEncryptedPacket(
        version_.transport_version, packet,
        GetIncludedDestinationConnectionIdLength(*header),
        GetIncludedSourceConnectionIdLength(*header), header->version_flag,
        header->nonce != nullptr, header->packet_number_length,
        header->retry_token_length_length, header->retry_token.length(),
        header->length_length);
  }

  size_t decrypted_length = 0;
  EncryptionLevel decrypted_level;
  if (!DecryptPayload(packet.length(), encrypted, associated_data, *header,
                      decrypted_buffer, buffer_length, &decrypted_length,
                      &decrypted_level)) {
    if (IsIetfStatelessResetPacket(*header)) {
      // This is a stateless reset packet.
      QuicIetfStatelessResetPacket reset_packet(
          *header, header->possible_stateless_reset_token);
      visitor_->OnAuthenticatedIetfStatelessResetPacket(reset_packet);
      return true;
    }
    const EncryptionLevel decryption_level = GetEncryptionLevel(*header);
    const bool has_decryption_key = version_.KnowsWhichDecrypterToUse() &&
                                    decrypter_[decryption_level] != nullptr;
    visitor_->OnUndecryptablePacket(
        QuicEncryptedPacket(encrypted_reader->FullPayload()), decryption_level,
        has_decryption_key);
    set_detailed_error(absl::StrCat(
        "Unable to decrypt ", EncryptionLevelToString(decryption_level),
        " payload with reconstructed packet number ",
        header->packet_number.ToString(), " (largest decrypted was ",
        base_packet_number.ToString(), ")",
        has_decryption_key || !version_.KnowsWhichDecrypterToUse()
            ? ""
            : " (missing key)",
        "."));
    RecordDroppedPacketReason(DroppedPacketReason::DECRYPTION_FAILURE);
    return RaiseError(QUIC_DECRYPTION_FAILURE);
  }

  if (packet.length() > kMaxIncomingPacketSize) {
    set_detailed_error("Packet too large.");
    return RaiseError(QUIC_PACKET_TOO_LARGE);
  }

  QuicDataReader reader(decrypted_buffer, decrypted_length);

  // Update the largest packet number after we have decrypted the packet
  // so we are confident is not attacker controlled.
  if (supports_multiple_packet_number_spaces_) {
    largest_decrypted_packet_numbers_[QuicUtils::GetPacketNumberSpace(
                                          decrypted_level)]
        .UpdateMax(header->packet_number);
  } else {
    largest_packet_number_.UpdateMax(header->packet_number);
  }

  if (!visitor_->OnPacketHeader(*header)) {
    RecordDroppedPacketReason(DroppedPacketReason::INVALID_PACKET_NUMBER);
    // The visitor suppresses further processing of the packet.
    return true;
  }

  // Handle the payload.
  if (VersionHasIetfQuicFrames(version_.transport_version)) {
    current_received_frame_type_ = 0;
    previously_received_frame_type_ = 0;
    if (!ProcessIetfFrameData(&reader, *header, decrypted_level)) {
      current_received_frame_type_ = 0;
      previously_received_frame_type_ = 0;
      QUICHE_DCHECK_NE(QUIC_NO_ERROR,
                       error_);  // ProcessIetfFrameData sets the error.
      QUICHE_DCHECK_NE("", detailed_error_);
      QUIC_DLOG(WARNING) << ENDPOINT << "Unable to process frame data. Error: "
                         << detailed_error_;
      return false;
    }
    current_received_frame_type_ = 0;
    previously_received_frame_type_ = 0;
  } else {
    if (!ProcessFrameData(&reader, *header)) {
      QUICHE_DCHECK_NE(QUIC_NO_ERROR,
                       error_);  // ProcessFrameData sets the error.
      QUICHE_DCHECK_NE("", detailed_error_);
      QUIC_DLOG(WARNING) << ENDPOINT << "Unable to process frame data. Error: "
                         << detailed_error_;
      return false;
    }
  }

  visitor_->OnPacketComplete();
  return true;
}

bool QuicFramer::IsIetfStatelessResetPacket(
    const QuicPacketHeader& header) const {
  QUIC_BUG_IF(quic_bug_12975_3, header.has_possible_stateless_reset_token &&
                                    perspective_ != Perspective::IS_CLIENT)
      << "has_possible_stateless_reset_token can only be true at client side.";
  return header.form == IETF_QUIC_SHORT_HEADER_PACKET &&
         header.has_possible_stateless_reset_token &&
         visitor_->IsValidStatelessResetToken(
             header.possible_stateless_reset_token);
}

bool QuicFramer::HasEncrypterOfEncryptionLevel(EncryptionLevel level) const {
  return encrypter_[level] != nullptr;
}

bool QuicFramer::HasDecrypterOfEncryptionLevel(EncryptionLevel level) const {
  return decrypter_[level] != nullptr;
}

bool QuicFramer::HasAnEncrypterForSpace(PacketNumberSpace space) const {
  switch (space) {
    case INITIAL_DATA:
      return HasEncrypterOfEncryptionLevel(ENCRYPTION_INITIAL);
    case HANDSHAKE_DATA:
      return HasEncrypterOfEncryptionLevel(ENCRYPTION_HANDSHAKE);
    case APPLICATION_DATA:
      return HasEncrypterOfEncryptionLevel(ENCRYPTION_ZERO_RTT) ||
             HasEncrypterOfEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    case NUM_PACKET_NUMBER_SPACES:
      break;
  }
  QUIC_BUG(quic_bug_10850_55)
      << ENDPOINT
      << "Try to send data of space: " << PacketNumberSpaceToString(space);
  return false;
}

EncryptionLevel QuicFramer::GetEncryptionLevelToSendApplicationData() const {
  if (!HasAnEncrypterForSpace(APPLICATION_DATA)) {
    QUIC_BUG(quic_bug_12975_4)
        << "Tried to get encryption level to send application data with no "
           "encrypter available.";
    return NUM_ENCRYPTION_LEVELS;
  }
  if (HasEncrypterOfEncryptionLevel(ENCRYPTION_FORWARD_SECURE)) {
    return ENCRYPTION_FORWARD_SECURE;
  }
  QUICHE_DCHECK(HasEncrypterOfEncryptionLevel(ENCRYPTION_ZERO_RTT));
  return ENCRYPTION_ZERO_RTT;
}

bool QuicFramer::AppendIetfHeaderTypeByte(const QuicPacketHeader& header,
                                          QuicDataWriter* writer) {
  uint8_t type = 0;
  if (header.version_flag) {
    type = static_cast<uint8_t>(
        FLAGS_LONG_HEADER | FLAGS_FIXED_BIT |
        LongHeaderTypeToOnWireValue(header.long_packet_type, version_) |
        PacketNumberLengthToOnWireValue(header.packet_number_length));
  } else {
    type = static_cast<uint8_t>(
        FLAGS_FIXED_BIT | (current_key_phase_bit_ ? FLAGS_KEY_PHASE_BIT : 0) |
        PacketNumberLengthToOnWireValue(header.packet_number_length));
  }
  return writer->WriteUInt8(type);
}

bool QuicFramer::AppendIetfPacketHeader(const QuicPacketHeader& header,
                                        QuicDataWriter* writer,
                                        size_t* length_field_offset) {
  QUIC_DVLOG(1) << ENDPOINT << "Appending IETF header: " << header;
  QuicConnectionId server_connection_id =
      GetServerConnectionIdAsSender(header, perspective_);
  QUIC_BUG_IF(quic_bug_12975_6, !QuicUtils::IsConnectionIdValidForVersion(
                                    server_connection_id, transport_version()))
      << "AppendIetfPacketHeader: attempted to use connection ID "
      << server_connection_id << " which is invalid with version " << version();
  if (!AppendIetfHeaderTypeByte(header, writer)) {
    return false;
  }

  if (header.version_flag) {
    QUICHE_DCHECK_NE(VERSION_NEGOTIATION, header.long_packet_type)
        << "QuicFramer::AppendIetfPacketHeader does not support sending "
           "version negotiation packets, use "
           "QuicFramer::BuildVersionNegotiationPacket instead "
        << header;
    // Append version for long header.
    QuicVersionLabel version_label = CreateQuicVersionLabel(version_);
    if (!writer->WriteUInt32(version_label)) {
      return false;
    }
  }

  // Append connection ID.
  if (!AppendIetfConnectionIds(
          header.version_flag, version_.HasLengthPrefixedConnectionIds(),
          header.destination_connection_id_included != CONNECTION_ID_ABSENT
              ? header.destination_connection_id
              : EmptyQuicConnectionId(),
          header.source_connection_id_included != CONNECTION_ID_ABSENT
              ? header.source_connection_id
              : EmptyQuicConnectionId(),
          writer)) {
    return false;
  }

  last_serialized_server_connection_id_ = server_connection_id;

  // TODO(b/141924462) Remove this QUIC_BUG once we do support sending RETRY.
  QUIC_BUG_IF(quic_bug_12975_7,
              header.version_flag && header.long_packet_type == RETRY)
      << "Sending IETF RETRY packets is not currently supported " << header;

  if (QuicVersionHasLongHeaderLengths(transport_version()) &&
      header.version_flag) {
    if (header.long_packet_type == INITIAL) {
      QUICHE_DCHECK_NE(quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
                       header.retry_token_length_length)
          << ENDPOINT << ParsedQuicVersionToString(version_)
          << " bad retry token length length in header: " << header;
      // Write retry token length.
      if (!writer->WriteVarInt62WithForcedLength(
              header.retry_token.length(), header.retry_token_length_length)) {
        return false;
      }
      // Write retry token.
      if (!header.retry_token.empty() &&
          !writer->WriteStringPiece(header.retry_token)) {
        return false;
      }
    }
    if (length_field_offset != nullptr) {
      *length_field_offset = writer->length();
    }
    // Add fake length to reserve two bytes to add length in later.
    writer->WriteVarInt62(256);
  } else if (length_field_offset != nullptr) {
    *length_field_offset = 0;
  }

  // Append packet number.
  if (!AppendPacketNumber(header.packet_number_length, header.packet_number,
                          writer)) {
    return false;
  }
  last_written_packet_number_length_ = header.packet_number_length;

  if (!header.version_flag) {
    return true;
  }

  if (header.nonce != nullptr) {
    QUICHE_DCHECK(header.version_flag);
    QUICHE_DCHECK_EQ(ZERO_RTT_PROTECTED, header.long_packet_type);
    QUICHE_DCHECK_EQ(Perspective::IS_SERVER, perspective_);
    if (!writer->WriteBytes(header.nonce, kDiversificationNonceSize)) {
      return false;
    }
  }

  return true;
}

const QuicTime::Delta QuicFramer::CalculateTimestampFromWire(
    uint32_t time_delta_us) {
  // The new time_delta might have wrapped to the next epoch, or it
  // might have reverse wrapped to the previous epoch, or it might
  // remain in the same epoch. Select the time closest to the previous
  // time.
  //
  // epoch_delta is the delta between epochs. A delta is 4 bytes of
  // microseconds.
  const uint64_t epoch_delta = UINT64_C(1) << 32;
  uint64_t epoch = last_timestamp_.ToMicroseconds() & ~(epoch_delta - 1);
  // Wrapping is safe here because a wrapped value will not be ClosestTo below.
  uint64_t prev_epoch = epoch - epoch_delta;
  uint64_t next_epoch = epoch + epoch_delta;

  uint64_t time = ClosestTo(
      last_timestamp_.ToMicroseconds(), epoch + time_delta_us,
      ClosestTo(last_timestamp_.ToMicroseconds(), prev_epoch + time_delta_us,
                next_epoch + time_delta_us));

  return QuicTime::Delta::FromMicroseconds(time);
}

uint64_t QuicFramer::CalculatePacketNumberFromWire(
    QuicPacketNumberLength packet_number_length,
    QuicPacketNumber base_packet_number, uint64_t packet_number) {
  // The new packet number might have wrapped to the next epoch, or
  // it might have reverse wrapped to the previous epoch, or it might
  // remain in the same epoch.  Select the packet number closest to the
  // next expected packet number, the previous packet number plus 1.

  // epoch_delta is the delta between epochs the packet number was serialized
  // with, so the correct value is likely the same epoch as the last sequence
  // number or an adjacent epoch.
  if (!base_packet_number.IsInitialized()) {
    return packet_number;
  }
  const uint64_t epoch_delta = UINT64_C(1) << (8 * packet_number_length);
  uint64_t next_packet_number = base_packet_number.ToUint64() + 1;
  uint64_t epoch = base_packet_number.ToUint64() & ~(epoch_delta - 1);
  uint64_t prev_epoch = epoch - epoch_delta;
  uint64_t next_epoch = epoch + epoch_delta;

  return ClosestTo(next_packet_number, epoch + packet_number,
                   ClosestTo(next_packet_number, prev_epoch + packet_number,
                             next_epoch + packet_number));
}

// static
QuicPacketNumberLength QuicFramer::GetMinPacketNumberLength(
    QuicPacketNumber packet_number) {
  QUICHE_DCHECK(packet_number.IsInitialized());
  if (packet_number < QuicPacketNumber(1 << (PACKET_1BYTE_PACKET_NUMBER * 8))) {
    return PACKET_1BYTE_PACKET_NUMBER;
  } else if (packet_number <
             QuicPacketNumber(1 << (PACKET_2BYTE_PACKET_NUMBER * 8))) {
    return PACKET_2BYTE_PACKET_NUMBER;
  } else if (packet_number <
             QuicPacketNumber(UINT64_C(1)
                              << (PACKET_4BYTE_PACKET_NUMBER * 8))) {
    return PACKET_4BYTE_PACKET_NUMBER;
  } else {
    return PACKET_6BYTE_PACKET_NUMBER;
  }
}

// static
uint8_t QuicFramer::GetPacketNumberFlags(
    QuicPacketNumberLength packet_number_length) {
  switch (packet_number_length) {
    case PACKET_1BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_1BYTE_PACKET;
    case PACKET_2BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_2BYTE_PACKET;
    case PACKET_4BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_4BYTE_PACKET;
    case PACKET_6BYTE_PACKET_NUMBER:
    case PACKET_8BYTE_PACKET_NUMBER:
      return PACKET_FLAGS_8BYTE_PACKET;
    default:
      QUIC_BUG(quic_bug_10850_56) << "Unreachable case statement.";
      return PACKET_FLAGS_8BYTE_PACKET;
  }
}

// static
QuicFramer::AckFrameInfo QuicFramer::GetAckFrameInfo(
    const QuicAckFrame& frame) {
  AckFrameInfo new_ack_info;
  if (frame.packets.Empty()) {
    return new_ack_info;
  }
  // The first block is the last interval. It isn't encoded with the gap-length
  // encoding, so skip it.
  new_ack_info.first_block_length = frame.packets.LastIntervalLength();
  auto itr = frame.packets.rbegin();
  QuicPacketNumber previous_start = itr->min();
  new_ack_info.max_block_length = itr->Length();
  ++itr;

  // Don't do any more work after getting information for 256 ACK blocks; any
  // more can't be encoded anyway.
  for (; itr != frame.packets.rend() &&
         new_ack_info.num_ack_blocks < std::numeric_limits<uint8_t>::max();
       previous_start = itr->min(), ++itr) {
    const auto& interval = *itr;
    const QuicPacketCount total_gap = previous_start - interval.max();
    new_ack_info.num_ack_blocks +=
        (total_gap + std::numeric_limits<uint8_t>::max() - 1) /
        std::numeric_limits<uint8_t>::max();
    new_ack_info.max_block_length =
        std::max(new_ack_info.max_block_length, interval.Length());
  }
  return new_ack_info;
}

bool QuicFramer::ProcessIetfHeaderTypeByte(QuicDataReader* reader,
                                           QuicPacketHeader* header) {
  uint8_t type;
  if (!reader->ReadBytes(&type, 1)) {
    set_detailed_error("Unable to read first byte.");
    return false;
  }
  header->type_byte = type;
  // Determine whether this is a long or short header.
  header->form = GetIetfPacketHeaderFormat(type);
  if (header->form == IETF_QUIC_LONG_HEADER_PACKET) {
    // Version is always present in long headers.
    header->version_flag = true;
    // In versions that do not support client connection IDs, we mark the
    // corresponding connection ID as absent.
    header->destination_connection_id_included =
        (perspective_ == Perspective::IS_SERVER ||
         version_.SupportsClientConnectionIds())
            ? CONNECTION_ID_PRESENT
            : CONNECTION_ID_ABSENT;
    header->source_connection_id_included =
        (perspective_ == Perspective::IS_CLIENT ||
         version_.SupportsClientConnectionIds())
            ? CONNECTION_ID_PRESENT
            : CONNECTION_ID_ABSENT;
    // Read version tag.
    QuicVersionLabel version_label;
    if (!ProcessVersionLabel(reader, &version_label)) {
      set_detailed_error("Unable to read protocol version.");
      return false;
    }
    if (!version_label) {
      // Version label is 0 indicating this is a version negotiation packet.
      header->long_packet_type = VERSION_NEGOTIATION;
    } else {
      header->version = ParseQuicVersionLabel(version_label);
      if (header->version.IsKnown()) {
        if (!(type & FLAGS_FIXED_BIT)) {
          set_detailed_error("Fixed bit is 0 in long header.");
          return false;
        }
        header->long_packet_type = GetLongHeaderType(type, header->version);
        switch (header->long_packet_type) {
          case INVALID_PACKET_TYPE:
            set_detailed_error("Illegal long header type value.");
            return false;
          case RETRY:
            if (!version().SupportsRetry()) {
              set_detailed_error("RETRY not supported in this version.");
              return false;
            }
            if (perspective_ == Perspective::IS_SERVER) {
              set_detailed_error("Client-initiated RETRY is invalid.");
              return false;
            }
            break;
          default:
            if (!header->version.HasHeaderProtection()) {
              header->packet_number_length =
                  GetLongHeaderPacketNumberLength(type);
            }
            break;
        }
      }
    }

    QUIC_DVLOG(1) << ENDPOINT << "Received IETF long header: "
                  << QuicUtils::QuicLongHeaderTypetoString(
                         header->long_packet_type);
    return true;
  }

  QUIC_DVLOG(1) << ENDPOINT << "Received IETF short header";
  // Version is not present in short headers.
  header->version_flag = false;
  // In versions that do not support client connection IDs, the client will not
  // receive destination connection IDs.
  header->destination_connection_id_included =
      (perspective_ == Perspective::IS_SERVER ||
       version_.SupportsClientConnectionIds())
          ? CONNECTION_ID_PRESENT
          : CONNECTION_ID_ABSENT;
  header->source_connection_id_included = CONNECTION_ID_ABSENT;
  if (!(type & FLAGS_FIXED_BIT)) {
    set_detailed_error("Fixed bit is 0 in short header.");
    return false;
  }
  if (!version_.HasHeaderProtection()) {
    header->packet_number_length = GetShortHeaderPacketNumberLength(type);
  }
  QUIC_DVLOG(1) << "packet_number_length = " << header->packet_number_length;
  return true;
}

// static
bool QuicFramer::ProcessVersionLabel(QuicDataReader* reader,
                                     QuicVersionLabel* version_label) {
  if (!reader->ReadUInt32(version_label)) {
    return false;
  }
  return true;
}

// static
bool QuicFramer::ProcessAndValidateIetfConnectionIdLength(
    QuicDataReader* reader, ParsedQuicVersion version, Perspective perspective,
    bool should_update_expected_server_connection_id_length,
    uint8_t* expected_server_connection_id_length,
    uint8_t* destination_connection_id_length,
    uint8_t* source_connection_id_length, std::string* detailed_error) {
  uint8_t connection_id_lengths_byte;
  if (!reader->ReadBytes(&connection_id_lengths_byte, 1)) {
    *detailed_error = "Unable to read ConnectionId length.";
    return false;
  }
  uint8_t dcil =
      (connection_id_lengths_byte & kDestinationConnectionIdLengthMask) >> 4;
  if (dcil != 0) {
    dcil += kConnectionIdLengthAdjustment;
  }
  uint8_t scil = connection_id_lengths_byte & kSourceConnectionIdLengthMask;
  if (scil != 0) {
    scil += kConnectionIdLengthAdjustment;
  }
  if (should_update_expected_server_connection_id_length) {
    uint8_t server_connection_id_length =
        perspective == Perspective::IS_SERVER ? dcil : scil;
    if (*expected_server_connection_id_length != server_connection_id_length) {
      QUIC_DVLOG(1) << "Updating expected_server_connection_id_length: "
                    << static_cast<int>(*expected_server_connection_id_length)
                    << " -> " << static_cast<int>(server_connection_id_length);
      *expected_server_connection_id_length = server_connection_id_length;
    }
  }
  if (!should_update_expected_server_connection_id_length &&
      (dcil != *destination_connection_id_length ||
       scil != *source_connection_id_length) &&
      version.IsKnown() && !version.AllowsVariableLengthConnectionIds()) {
    QUIC_DVLOG(1) << "dcil: " << static_cast<uint32_t>(dcil)
                  << ", scil: " << static_cast<uint32_t>(scil);
    *detailed_error = "Invalid ConnectionId length.";
    return false;
  }
  *destination_connection_id_length = dcil;
  *source_connection_id_length = scil;
  return true;
}

bool QuicFramer::ValidateReceivedConnectionIds(const QuicPacketHeader& header) {
  bool skip_server_connection_id_validation =
      perspective_ == Perspective::IS_CLIENT &&
      header.form == IETF_QUIC_SHORT_HEADER_PACKET;
  if (!skip_server_connection_id_validation &&
      !QuicUtils::IsConnectionIdValidForVersion(
          GetServerConnectionIdAsRecipient(header, perspective_),
          transport_version())) {
    set_detailed_error("Received server connection ID with invalid length.");
    return false;
  }

  bool skip_client_connection_id_validation =
      perspective_ == Perspective::IS_SERVER &&
      header.form == IETF_QUIC_SHORT_HEADER_PACKET;
  if (!skip_client_connection_id_validation &&
      version_.SupportsClientConnectionIds() &&
      !QuicUtils::IsConnectionIdValidForVersion(
          GetClientConnectionIdAsRecipient(header, perspective_),
          transport_version())) {
    set_detailed_error("Received client connection ID with invalid length.");
    return false;
  }
  return true;
}

bool QuicFramer::ProcessIetfPacketHeader(QuicDataReader* reader,
                                         QuicPacketHeader* header) {
  if (version_.HasLengthPrefixedConnectionIds()) {
    uint8_t expected_destination_connection_id_length =
        perspective_ == Perspective::IS_CLIENT
            ? expected_client_connection_id_length_
            : expected_server_connection_id_length_;
    QuicVersionLabel version_label;
    bool has_length_prefix;
    std::string detailed_error;
    QuicErrorCode parse_result = QuicFramer::ParsePublicHeader(
        reader, expected_destination_connection_id_length, /*ietf_format=*/true,
        &header->type_byte, &header->form, &header->version_flag,
        &has_length_prefix, &version_label, &header->version,
        &header->destination_connection_id, &header->source_connection_id,
        &header->long_packet_type, &header->retry_token_length_length,
        &header->retry_token, &detailed_error);
    if (parse_result != QUIC_NO_ERROR) {
      set_detailed_error(detailed_error);
      return false;
    }
    header->destination_connection_id_included = CONNECTION_ID_PRESENT;
    header->source_connection_id_included =
        header->version_flag ? CONNECTION_ID_PRESENT : CONNECTION_ID_ABSENT;

    if (!ValidateReceivedConnectionIds(*header)) {
      return false;
    }

    if (header->version_flag &&
        header->long_packet_type != VERSION_NEGOTIATION &&
        !(header->type_byte & FLAGS_FIXED_BIT)) {
      set_detailed_error("Fixed bit is 0 in long header.");
      return false;
    }
    if (!header->version_flag && !(header->type_byte & FLAGS_FIXED_BIT)) {
      set_detailed_error("Fixed bit is 0 in short header.");
      return false;
    }
    if (!header->version_flag) {
      if (!version_.HasHeaderProtection()) {
        header->packet_number_length =
            GetShortHeaderPacketNumberLength(header->type_byte);
      }
      return true;
    }
    if (header->long_packet_type == RETRY) {
      if (!version().SupportsRetry()) {
        set_detailed_error("RETRY not supported in this version.");
        return false;
      }
      if (perspective_ == Perspective::IS_SERVER) {
        set_detailed_error("Client-initiated RETRY is invalid.");
        return false;
      }
      return true;
    }
    if (header->version.IsKnown() && !header->version.HasHeaderProtection()) {
      header->packet_number_length =
          GetLongHeaderPacketNumberLength(header->type_byte);
    }

    return true;
  }

  if (!ProcessIetfHeaderTypeByte(reader, header)) {
    return false;
  }

  uint8_t destination_connection_id_length =
      header->destination_connection_id_included == CONNECTION_ID_PRESENT
          ? (perspective_ == Perspective::IS_SERVER
                 ? expected_server_connection_id_length_
                 : expected_client_connection_id_length_)
          : 0;
  uint8_t source_connection_id_length =
      header->source_connection_id_included == CONNECTION_ID_PRESENT
          ? (perspective_ == Perspective::IS_CLIENT
                 ? expected_server_connection_id_length_
                 : expected_client_connection_id_length_)
          : 0;
  if (header->form == IETF_QUIC_LONG_HEADER_PACKET) {
    if (!ProcessAndValidateIetfConnectionIdLength(
            reader, header->version, perspective_,
            /*should_update_expected_server_connection_id_length=*/false,
            &expected_server_connection_id_length_,
            &destination_connection_id_length, &source_connection_id_length,
            &detailed_error_)) {
      return false;
    }
  }

  // Read connection ID.
  if (!reader->ReadConnectionId(&header->destination_connection_id,
                                destination_connection_id_length)) {
    set_detailed_error("Unable to read destination connection ID.");
    return false;
  }

  if (!reader->ReadConnectionId(&header->source_connection_id,
                                source_connection_id_length)) {
    set_detailed_error("Unable to read source connection ID.");
    return false;
  }

  if (header->source_connection_id_included == CONNECTION_ID_ABSENT) {
    if (!header->source_connection_id.IsEmpty()) {
      QUICHE_DCHECK(!version_.SupportsClientConnectionIds());
      set_detailed_error("Client connection ID not supported in this version.");
      return false;
    }
  }

  return ValidateReceivedConnectionIds(*header);
}

bool QuicFramer::ProcessAndCalculatePacketNumber(
    QuicDataReader* reader, QuicPacketNumberLength packet_number_length,
    QuicPacketNumber base_packet_number, uint64_t* packet_number) {
  uint64_t wire_packet_number;
  if (!reader->ReadBytesToUInt64(packet_number_length, &wire_packet_number)) {
    return false;
  }

  // TODO(ianswett): Explore the usefulness of trying multiple packet numbers
  // in case the first guess is incorrect.
  *packet_number = CalculatePacketNumberFromWire(
      packet_number_length, base_packet_number, wire_packet_number);
  return true;
}

bool QuicFramer::ProcessFrameData(QuicDataReader* reader,
                                  const QuicPacketHeader& header) {
  QUICHE_DCHECK(!VersionHasIetfQuicFrames(version_.transport_version))
      << "IETF QUIC Framing negotiated but attempting to process frames as "
         "non-IETF QUIC.";
  if (reader->IsDoneReading()) {
    set_detailed_error("Packet has no frames.");
    return RaiseError(QUIC_MISSING_PAYLOAD);
  }
  QUIC_DVLOG(2) << ENDPOINT << "Processing packet with header " << header;
  while (!reader->IsDoneReading()) {
 
"""


```