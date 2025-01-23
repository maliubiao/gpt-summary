Response:
The user wants me to analyze the provided C++ code snippet from the `quic_packet_creator.cc` file, focusing on its functionalities. I need to:

1. **Summarize the functions** within the snippet.
2. **Identify any connections to JavaScript** and provide examples.
3. **Perform logical reasoning** where applicable, giving example inputs and outputs.
4. **Point out common user/programming errors** with illustrative examples.
5. **Explain how a user's actions can lead to this code** being executed, providing debugging insights.
6. **Synthesize the overall functionality** of this code portion.

Let's break down the code snippet and address each of these points.

**Code Analysis:**

The snippet mainly focuses on the `QuicPacketCreator::SerializePacket()` function and several related helper functions for creating and serializing different types of QUIC packets. Key functionalities include:

* **Serialization of Data Packets:** The core of `SerializePacket()` is to take queued frames, build a packet header, serialize the frames into a buffer, encrypt the buffer, and return a `SerializedPacket`.
* **Handling of Padding:**  The code checks for `allow_padding` and calls `MaybeAddPadding()` if necessary.
* **Error Handling:**  It checks for missing encryption keys and serialization failures, using `QUIC_BUG` for assertions and logging.
* **Connectivity Probing Packets:** Functions like `SerializeConnectivityProbingPacket()`, `SerializePathChallengeConnectivityProbingPacket()`, and `SerializePathResponseConnectivityProbingPacket()` generate special packets for network path validation.
* **Connection Close Packet with Large Packet Number:** `SerializeLargePacketNumberConnectionClosePacket()` creates a connection close packet with a specific large packet number.
* **Coalesced Packets:** `SerializeCoalescedPacket()` handles the serialization of multiple packets into a single UDP datagram.
* **Helper Functions for Packet Construction:**  Functions like `BuildPaddedPathChallengePacket()`, `BuildPathResponsePacket()`, and `BuildConnectivityProbingPacket()` assemble the frame payloads for different packet types.
* **Managing Packet Metadata:**  Functions like `GetDestinationConnectionId()`, `GetSourceConnectionId()`, `PacketHeaderSize()`, etc., provide information about the packet structure.
* **Consuming Data:** Functions like `ConsumeRetransmittableControlFrame()`, `ConsumeData()`, and `ConsumeCryptoData()` manage adding data to packets.
* **MTU Discovery:** `GenerateMtuDiscoveryPacket()` handles sending packets to discover the maximum transmission unit.

**JavaScript Connections:**

QUIC is a transport protocol often used in web browsers. While the C++ code itself isn't directly JavaScript, the *effects* of its execution are highly relevant to JavaScript running in a browser.

* **Network Requests:** When a JavaScript application makes an HTTP/3 request (which uses QUIC), this C++ code is involved in constructing and sending the underlying QUIC packets.
* **WebSockets over QUIC:**  If WebSockets are implemented over QUIC, this code would be responsible for sending and receiving WebSocket frames within QUIC packets.
* **Real-time Communication:** Applications using WebRTC (which can use QUIC as a transport) rely on this kind of code to transmit audio, video, and data.

**Example:**

Imagine a JavaScript application fetches an image using `fetch()` over HTTP/3.

1. JavaScript `fetch()` initiates the request.
2. The browser's network stack (including this `quic_packet_creator.cc` code) will create QUIC packets containing the HTTP/3 request headers.
3. The `SerializePacket()` function will be called to serialize these headers into a QUIC packet.
4. When the server responds, the reverse process happens: QUIC packets are received and processed, and the image data is eventually delivered back to the JavaScript `fetch()` promise.

**Logical Reasoning and Examples:**

Let's focus on `SerializePacket()` and the `allow_padding` logic.

**Hypothesis:** If `allow_padding` is true, and there's enough space in the packet, padding bytes will be added.

**Input:**
* `allow_padding`: `true`
* `max_plaintext_size_`: 1000 bytes
* `packet_size_` (current size before padding): 500 bytes
* `queued_frames_`: Contains some data frames.

**Expected Output:**
* The serialized packet will be larger than 500 bytes (up to 1000 bytes) due to padding.
* The `framer_->BuildDataPacket()` call will include padding.

**User/Programming Errors:**

* **Incorrectly Calculating `max_plaintext_size_`:**  If the calculated maximum packet size is too small, packets might be unnecessarily fragmented, or serialization might fail.
    * **Example:**  A programmer might forget to account for encryption overhead when setting `max_plaintext_size_`.
* **Adding Too Many Frames:**  If the queued frames exceed `max_plaintext_size_`, the `framer_->BuildDataPacket()` call will likely fail, leading to a `QUIC_BUG`.
    * **Example:**  A logic error in the higher layers might cause an excessive number of control frames to be queued.
* **Missing Encryption Keys:** If `framer_->HasEncrypterOfEncryptionLevel(packet_.encryption_level)` returns `false`, it indicates that encryption keys are not available for the current encryption level. This is a critical error that prevents packet encryption.
    * **Example:**  The handshake process might not have completed successfully, or there might be a key management issue.

**User Operation and Debugging:**

Let's trace how a user action might lead to this code being executed. Imagine a user browsing a website that uses HTTP/3.

1. **User Action:** The user clicks a link or types a URL in the browser.
2. **Request Initiation:** The browser determines that the connection to the website should use HTTP/3 (QUIC).
3. **Packet Creation:**  The browser's network stack begins creating QUIC packets to send the HTTP request. The `QuicPacketCreator` class is instantiated.
4. **Adding Frames:**  HTTP/3 request headers are translated into QUIC frames (e.g., `STREAM_FRAME` for data). These frames are added to the `queued_frames_`.
5. **Serialization:**  The `SerializePacket()` function is called to create a serialized QUIC packet from the queued frames.
6. **Encryption:**  The `framer_->EncryptInPlace()` function encrypts the packet data.
7. **Sending:** The serialized and encrypted packet is sent over the network.

**Debugging:**

If there's an issue (e.g., the page loads slowly or fails to load), a developer might look at network logs or use debugging tools to inspect the QUIC connection. Seeing errors related to packet serialization, encryption, or unexpected packet sizes could point to problems within the `QuicPacketCreator` code. Specifically, the `QUIC_BUG` messages in the code provide valuable clues about potential issues. For instance, a "Failed to serialize" or "Failed to encrypt" message originating from this file would be a direct indication of a problem within this section of the code.

**Part 2 Summary:**

This section of `quic_packet_creator.cc` is responsible for the core process of **serializing various types of QUIC packets**. It takes a collection of QUIC frames, constructs the packet header, serializes the frames into a buffer, adds padding if necessary, encrypts the packet, and produces a `SerializedPacket` object ready for sending. It also handles the creation of specialized packets for connectivity probing and connection closure. The code includes checks for errors during serialization and encryption, and uses assertions (`QUIC_BUG`) to highlight unexpected states.

这是`net/third_party/quiche/src/quiche/quic/core/quic_packet_creator.cc` 文件中 `QuicPacketCreator` 类的 `SerializePacket` 函数及其相关的辅助函数。 这部分代码的主要功能是 **将已准备好的 QUIC 帧序列化成最终可以发送的加密数据包**。

**主要功能归纳:**

1. **数据包序列化核心流程:**
   - 接收已添加到队列中的 QUIC 帧 (`queued_frames_`)。
   - 构建数据包头部 (`header`)，包括包序号、连接 ID 等信息。
   - 可选地添加填充 (`MaybeAddPadding`) 以满足最小包大小或进行 MTU 发现。
   - 使用 `framer_->BuildDataPacket` 将帧序列化到缓冲区 (`encrypted_buffer.buffer`) 中。
   - 检查序列化是否成功。
   - 使用 `framer_->EncryptInPlace` 对序列化后的数据进行加密。
   - 创建并返回一个 `SerializedPacket` 对象，包含加密后的数据和相关元数据。

2. **处理不同类型的探测包:**
   - `SerializeConnectivityProbingPacket`: 创建并序列化用于连通性探测的 PING 包，通常会填充到最大大小。
   - `SerializePathChallengeConnectivityProbingPacket`: 创建并序列化路径挑战包，包含 `PATH_CHALLENGE` 帧并进行填充。
   - `SerializePathResponseConnectivityProbingPacket`: 创建并序列化路径响应包，包含 `PATH_RESPONSE` 帧并可能进行填充。

3. **序列化大包号的连接关闭包:**
   - `SerializeLargePacketNumberConnectionClosePacket`: 用于发送包含较大包号的连接关闭包，用于处理某些特殊情况。

4. **序列化合并包:**
   - `SerializeCoalescedPacket`: 将多个独立的加密数据包合并成一个 UDP 数据报进行发送，通常用于优化握手过程。

5. **构建不同类型的探测包内容:**
   - `BuildPaddedPathChallengePacket`: 构建包含 `PATH_CHALLENGE` 帧和填充的包内容。
   - `BuildPathResponsePacket`: 构建包含 `PATH_RESPONSE` 帧和可选填充的包内容。
   - `BuildConnectivityProbingPacket`: 构建包含 `PING` 帧和填充的包内容。

6. **获取数据包的各种属性:**
   - `GetDestinationConnectionId`, `GetSourceConnectionId`: 获取目标和源连接 ID。
   - `PacketHeaderSize`: 计算数据包头部的长度。
   - `GetPacketNumberLength`: 获取包序号的长度。
   - `GetRetryToken`, `GetRetryTokenLengthLength`: 获取和计算重试令牌相关信息。

7. **管理待发送的帧:**
   - `ConsumeRetransmittableControlFrame`, `ConsumeData`, `ConsumeCryptoData`: 将不同类型的帧添加到待发送队列中。
   - `MaybeBundleOpportunistically`: 允许委托方机会性地捆绑数据。

8. **MTU 发现:**
   - `GenerateMtuDiscoveryPacket`: 生成用于路径 MTU 发现的包。

**与 JavaScript 的功能关系:**

虽然这段 C++ 代码本身不直接涉及 JavaScript，但它是 Chromium 网络栈的一部分，负责处理底层的 QUIC 协议数据包的创建和发送。当 JavaScript 代码通过浏览器发起网络请求（例如使用 `fetch` API 或 WebSocket）时，如果底层使用了 QUIC 协议，那么这段 C++ 代码就会被调用来构建和发送相应的 QUIC 数据包。

**举例说明:**

假设一个 JavaScript 应用需要通过 HTTP/3 发送一些数据到服务器：

1. JavaScript 代码调用 `fetch()` API 发起 POST 请求。
2. Chromium 浏览器网络栈的更上层代码会准备好要发送的 HTTP/3 数据，并将其转换为一系列 QUIC 帧（例如 `STREAM_FRAME`）。
3. 这些 QUIC 帧会被添加到 `QuicPacketCreator` 实例的 `queued_frames_` 中。
4. `SerializePacket()` 函数被调用，将这些帧序列化成一个或多个 QUIC 数据包。
5. 如果 `allow_padding` 为真，并且当前包大小未达到最大值，`MaybeAddPadding()` 可能会被调用来添加填充字节。
6. `framer_->BuildDataPacket()` 会将帧数据写入到 `encrypted_buffer.buffer` 中。
7. `framer_->EncryptInPlace()` 会对缓冲区中的数据进行加密。
8. 生成的 `SerializedPacket` 对象会被传递到更底层的网络层进行发送。

**逻辑推理与假设输入输出:**

**场景:** `SerializePacket` 函数被调用，并且 `allow_padding` 为 `true`。

**假设输入:**

* `queued_frames_`:  包含一个 `STREAM_FRAME`，其序列化后的长度为 400 字节。
* `max_plaintext_size_`: 1000 字节。
* `packet_.encryption_level`: `ENCRYPTION_FORWARD_SECURE`。

**逻辑推理:**

由于 `allow_padding` 为 `true`，并且当前包大小 (400 字节) 小于 `max_plaintext_size_` (1000 字节)，`MaybeAddPadding()` 会被调用。`MaybeAddPadding()` 会添加足够的填充字节，使得最终的明文数据包大小接近 `max_plaintext_size_`，但不会超过。

**预期输出:**

* `framer_->BuildDataPacket()` 生成的 `length` 将大于 400 字节，例如 990 字节（具体取决于填充策略）。
* `encrypted_length` (加密后的长度) 将大于 `length`，因为加密会增加一些开销。

**用户或编程常见的使用错误:**

1. **错误的 `max_plaintext_size_` 设置:**  如果 `max_plaintext_size_` 设置得过小，可能会导致频繁的分包，降低性能。
   - **示例:**  在初始化 `QuicPacketCreator` 时，错误地将最大包大小设置为小于最小 MTU 的值。
2. **在未设置加密器的情况下尝试序列化:**  如果在某个加密级别的密钥尚未就绪时就尝试发送数据，`framer_->HasEncrypterOfEncryptionLevel(packet_.encryption_level)` 将返回 `false`，导致程序崩溃或发送失败。
   - **示例:**  在握手完成之前，尝试发送需要 `ENCRYPTION_FORWARD_SECURE` 保护的应用数据。
3. **添加过多的帧导致超出最大包大小:**  如果添加到 `queued_frames_` 的帧的总大小超过了 `max_plaintext_size_`，`framer_->BuildDataPacket()` 将返回 0，序列化失败。
   - **示例:**  尝试在一个数据包中发送过多的控制帧或过大的数据流帧。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用 HTTP/3 的网站。**
2. **浏览器发起一个 HTTPS 连接请求。**
3. **Chromium 网络栈协商使用 QUIC 协议。**
4. **浏览器需要发送 HTTP 请求头到服务器。**
5. **网络栈将 HTTP 请求头转换为一系列 QUIC 帧 (例如 `STREAM_FRAME`)。**
6. **`QuicPacketCreator` 实例被创建，用于构建要发送的 QUIC 数据包。**
7. **这些 QUIC 帧被添加到 `QuicPacketCreator` 的待发送队列 (`queued_frames_`) 中。**
8. **`SerializePacket()` 函数被调用，开始序列化过程。**
9. **如果在调试过程中遇到问题，例如数据包发送失败，开发者可能会在 `SerializePacket()` 函数中设置断点，检查 `queued_frames_` 的内容、`max_plaintext_size_` 的值、以及 `framer_` 的状态，以找出问题的原因。** 例如，如果 `framer_->HasEncrypterOfEncryptionLevel()` 返回 `false`，则说明加密器未就绪，需要检查密钥协商过程。如果 `framer_->BuildDataPacket()` 返回 0，则说明待发送的帧太大，需要检查帧的来源和大小限制。

**第 2 部分功能归纳:**

这部分代码主要负责 `QuicPacketCreator` 类中 **将已准备好的 QUIC 帧序列化成最终可发送的加密数据包** 的核心流程。它涵盖了标准数据包的序列化、各种探测包的生成、以及特殊场景下的连接关闭包和合并包的处理。 同时，它还提供了一些辅助功能，用于管理待发送的帧、获取数据包属性以及支持 MTU 发现。 这部分代码是 QUIC 协议数据包发送的关键环节。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*is_mtu_discovery=*/QuicUtils::ContainsFrameType(queued_frames_,
                                                          MTU_DISCOVERY_FRAME),
        packet_.encryption_level);
    QUIC_DVLOG(1) << ENDPOINT << "fate of packet " << packet_.packet_number
                  << ": " << SerializedPacketFateToString(packet_.fate)
                  << " of "
                  << EncryptionLevelToString(packet_.encryption_level);
  }

  if (allow_padding) {
    MaybeAddPadding();
  }

  QUIC_DVLOG(2) << ENDPOINT << "Serializing packet " << header
                << QuicFramesToString(queued_frames_) << " at encryption_level "
                << packet_.encryption_level
                << ", allow_padding:" << allow_padding;

  if (!framer_->HasEncrypterOfEncryptionLevel(packet_.encryption_level)) {
    // TODO(fayang): Use QUIC_MISSING_WRITE_KEYS for serialization failures due
    // to missing keys.
    QUIC_BUG(quic_bug_10752_15)
        << ENDPOINT << "Attempting to serialize " << header
        << QuicFramesToString(queued_frames_) << " at missing encryption_level "
        << packet_.encryption_level << " using " << framer_->version();
    return false;
  }

  QUICHE_DCHECK_GE(max_plaintext_size_, packet_size_) << ENDPOINT;
  // Use the packet_size_ instead of the buffer size to ensure smaller
  // packet sizes are properly used.

  size_t length;
  std::optional<size_t> length_with_chaos_protection =
      MaybeBuildDataPacketWithChaosProtection(header, encrypted_buffer.buffer);
  if (length_with_chaos_protection.has_value()) {
    length = *length_with_chaos_protection;
  } else {
    length = framer_->BuildDataPacket(header, queued_frames_,
                                      encrypted_buffer.buffer, packet_size_,
                                      packet_.encryption_level);
  }

  if (length == 0) {
    QUIC_BUG(quic_bug_10752_16)
        << ENDPOINT << "Failed to serialize "
        << QuicFramesToString(queued_frames_)
        << " at encryption_level: " << packet_.encryption_level
        << ", needs_full_padding_: " << needs_full_padding_
        << ", pending_padding_bytes_: " << pending_padding_bytes_
        << ", latched_hard_max_packet_length_: "
        << latched_hard_max_packet_length_
        << ", max_packet_length_: " << max_packet_length_
        << ", header: " << header;
    return false;
  }

  // ACK Frames will be truncated due to length only if they're the only frame
  // in the packet, and if packet_size_ was set to max_plaintext_size_. If
  // truncation due to length occurred, then GetSerializedFrameLength will have
  // returned all bytes free.
  bool possibly_truncated_by_length = packet_size_ == max_plaintext_size_ &&
                                      queued_frames_.size() == 1 &&
                                      queued_frames_.back().type == ACK_FRAME;
  // Because of possible truncation, we can't be confident that our
  // packet size calculation worked correctly.
  if (!possibly_truncated_by_length) {
    QUICHE_DCHECK_EQ(packet_size_, length) << ENDPOINT;
  }
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.packet_number,
      GetStartOfEncryptedData(framer_->transport_version(), header), length,
      encrypted_buffer_len, encrypted_buffer.buffer);
  if (encrypted_length == 0) {
    QUIC_BUG(quic_bug_10752_17)
        << ENDPOINT << "Failed to encrypt packet number "
        << packet_.packet_number;
    return false;
  }

  packet_size_ = 0;
  packet_.encrypted_buffer = encrypted_buffer.buffer;
  packet_.encrypted_length = encrypted_length;

  encrypted_buffer.buffer = nullptr;
  packet_.release_encrypted_buffer = std::move(encrypted_buffer).release_buffer;
  return true;
}

std::unique_ptr<SerializedPacket>
QuicPacketCreator::SerializeConnectivityProbingPacket() {
  QUIC_BUG_IF(quic_bug_12398_11,
              VersionHasIetfQuicFrames(framer_->transport_version()))
      << ENDPOINT
      << "Must not be version 99 to serialize padded ping connectivity probe";
  RemoveSoftMaxPacketLength();
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  FillPacketHeader(&header);

  QUIC_DVLOG(2) << ENDPOINT << "Serializing connectivity probing packet "
                << header;

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  size_t length = BuildConnectivityProbingPacket(
      header, buffer.get(), max_plaintext_size_, packet_.encryption_level);
  QUICHE_DCHECK(length) << ENDPOINT;

  QUICHE_DCHECK_EQ(packet_.encryption_level, ENCRYPTION_FORWARD_SECURE)
      << ENDPOINT;
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.packet_number,
      GetStartOfEncryptedData(framer_->transport_version(), header), length,
      kMaxOutgoingPacketSize, buffer.get());
  QUICHE_DCHECK(encrypted_length) << ENDPOINT;

  std::unique_ptr<SerializedPacket> serialize_packet(new SerializedPacket(
      header.packet_number, header.packet_number_length, buffer.release(),
      encrypted_length, /*has_ack=*/false, /*has_stop_waiting=*/false));

  serialize_packet->release_encrypted_buffer = [](const char* p) {
    delete[] p;
  };
  serialize_packet->encryption_level = packet_.encryption_level;
  serialize_packet->transmission_type = NOT_RETRANSMISSION;

  return serialize_packet;
}

std::unique_ptr<SerializedPacket>
QuicPacketCreator::SerializePathChallengeConnectivityProbingPacket(
    const QuicPathFrameBuffer& payload) {
  QUIC_BUG_IF(quic_bug_12398_12,
              !VersionHasIetfQuicFrames(framer_->transport_version()))
      << ENDPOINT
      << "Must be version 99 to serialize path challenge connectivity probe, "
         "is version "
      << framer_->transport_version();
  RemoveSoftMaxPacketLength();
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  FillPacketHeader(&header);

  QUIC_DVLOG(2) << ENDPOINT << "Serializing path challenge packet " << header;

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  size_t length =
      BuildPaddedPathChallengePacket(header, buffer.get(), max_plaintext_size_,
                                     payload, packet_.encryption_level);
  QUICHE_DCHECK(length) << ENDPOINT;

  QUICHE_DCHECK_EQ(packet_.encryption_level, ENCRYPTION_FORWARD_SECURE)
      << ENDPOINT;
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.packet_number,
      GetStartOfEncryptedData(framer_->transport_version(), header), length,
      kMaxOutgoingPacketSize, buffer.get());
  QUICHE_DCHECK(encrypted_length) << ENDPOINT;

  std::unique_ptr<SerializedPacket> serialize_packet(
      new SerializedPacket(header.packet_number, header.packet_number_length,
                           buffer.release(), encrypted_length,
                           /*has_ack=*/false, /*has_stop_waiting=*/false));

  serialize_packet->release_encrypted_buffer = [](const char* p) {
    delete[] p;
  };
  serialize_packet->encryption_level = packet_.encryption_level;
  serialize_packet->transmission_type = NOT_RETRANSMISSION;

  return serialize_packet;
}

std::unique_ptr<SerializedPacket>
QuicPacketCreator::SerializePathResponseConnectivityProbingPacket(
    const quiche::QuicheCircularDeque<QuicPathFrameBuffer>& payloads,
    const bool is_padded) {
  QUIC_BUG_IF(quic_bug_12398_13,
              !VersionHasIetfQuicFrames(framer_->transport_version()))
      << ENDPOINT
      << "Must be version 99 to serialize path response connectivity probe, is "
         "version "
      << framer_->transport_version();
  RemoveSoftMaxPacketLength();
  QuicPacketHeader header;
  // FillPacketHeader increments packet_number_.
  FillPacketHeader(&header);

  QUIC_DVLOG(2) << ENDPOINT << "Serializing path response packet " << header;

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  size_t length =
      BuildPathResponsePacket(header, buffer.get(), max_plaintext_size_,
                              payloads, is_padded, packet_.encryption_level);
  QUICHE_DCHECK(length) << ENDPOINT;

  QUICHE_DCHECK_EQ(packet_.encryption_level, ENCRYPTION_FORWARD_SECURE)
      << ENDPOINT;
  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.packet_number,
      GetStartOfEncryptedData(framer_->transport_version(), header), length,
      kMaxOutgoingPacketSize, buffer.get());
  QUICHE_DCHECK(encrypted_length) << ENDPOINT;

  std::unique_ptr<SerializedPacket> serialize_packet(
      new SerializedPacket(header.packet_number, header.packet_number_length,
                           buffer.release(), encrypted_length,
                           /*has_ack=*/false, /*has_stop_waiting=*/false));

  serialize_packet->release_encrypted_buffer = [](const char* p) {
    delete[] p;
  };
  serialize_packet->encryption_level = packet_.encryption_level;
  serialize_packet->transmission_type = NOT_RETRANSMISSION;

  return serialize_packet;
}

std::unique_ptr<SerializedPacket>
QuicPacketCreator::SerializeLargePacketNumberConnectionClosePacket(
    QuicPacketNumber largest_acked_packet, QuicErrorCode error,
    const std::string& error_details) {
  QUICHE_DCHECK_EQ(packet_.encryption_level, ENCRYPTION_FORWARD_SECURE)
      << ENDPOINT;
  // Largest packet number is 2^62 - 1 but the packet number is encoded to 1 to
  // 4 bytes.
  // Receiver decodes packet number assuming the packet number is less than or
  // equal to (largest packet number that has been successfully processed) + 1
  // + (1 << (packet_number_length - 1)).
  // So, generate a packet with the largest packet number in this range.
  // Note that FillPacketHeader increments before fills the header.
  const QuicPacketNumber largest_packet_number(
      (largest_acked_packet.IsInitialized()
           ? largest_acked_packet
           : framer_->first_sending_packet_number()) +
      (1L << 31));
  ScopedPacketContextSwitcher switcher(largest_packet_number,
                                       PACKET_4BYTE_PACKET_NUMBER,
                                       ENCRYPTION_FORWARD_SECURE, &packet_);

  QuicPacketHeader header;
  FillPacketHeader(&header);

  QUIC_DVLOG(2) << ENDPOINT << "Serializing connection close packet " << header;

  QuicFrames frames;
  QuicConnectionCloseFrame close_frame(transport_version(), error,
                                       NO_IETF_QUIC_ERROR, error_details, 0);
  frames.push_back(QuicFrame(&close_frame));

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  const size_t length =
      framer_->BuildDataPacket(header, frames, buffer.get(),
                               max_plaintext_size_, packet_.encryption_level);
  QUICHE_DCHECK(length) << ENDPOINT;

  const size_t encrypted_length = framer_->EncryptInPlace(
      packet_.encryption_level, packet_.packet_number,
      GetStartOfEncryptedData(framer_->transport_version(), header), length,
      kMaxOutgoingPacketSize, buffer.get());
  QUICHE_DCHECK(encrypted_length) << ENDPOINT;

  std::unique_ptr<SerializedPacket> serialize_packet(
      new SerializedPacket(header.packet_number, header.packet_number_length,
                           buffer.release(), encrypted_length,
                           /*has_ack=*/false, /*has_stop_waiting=*/false));

  serialize_packet->release_encrypted_buffer = [](const char* p) {
    delete[] p;
  };
  serialize_packet->encryption_level = packet_.encryption_level;
  serialize_packet->transmission_type = NOT_RETRANSMISSION;

  return serialize_packet;
}

size_t QuicPacketCreator::BuildPaddedPathChallengePacket(
    const QuicPacketHeader& header, char* buffer, size_t packet_length,
    const QuicPathFrameBuffer& payload, EncryptionLevel level) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(framer_->transport_version()))
      << ENDPOINT;
  QuicFrames frames;

  // Write a PATH_CHALLENGE frame, which has a random 8-byte payload
  frames.push_back(QuicFrame(QuicPathChallengeFrame(0, payload)));

  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frames.back());
  }

  // Add padding to the rest of the packet in order to assess Path MTU
  // characteristics.
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(padding_frame));

  return framer_->BuildDataPacket(header, frames, buffer, packet_length, level);
}

size_t QuicPacketCreator::BuildPathResponsePacket(
    const QuicPacketHeader& header, char* buffer, size_t packet_length,
    const quiche::QuicheCircularDeque<QuicPathFrameBuffer>& payloads,
    const bool is_padded, EncryptionLevel level) {
  if (payloads.empty()) {
    QUIC_BUG(quic_bug_12398_14)
        << ENDPOINT
        << "Attempt to generate connectivity response with no request payloads";
    return 0;
  }
  QUICHE_DCHECK(VersionHasIetfQuicFrames(framer_->transport_version()))
      << ENDPOINT;

  QuicFrames frames;
  for (const QuicPathFrameBuffer& payload : payloads) {
    // Note that the control frame ID can be 0 since this is not retransmitted.
    frames.push_back(QuicFrame(QuicPathResponseFrame(0, payload)));
    if (debug_delegate_ != nullptr) {
      debug_delegate_->OnFrameAddedToPacket(frames.back());
    }
  }

  if (is_padded) {
    // Add padding to the rest of the packet in order to assess Path MTU
    // characteristics.
    QuicPaddingFrame padding_frame;
    frames.push_back(QuicFrame(padding_frame));
  }

  return framer_->BuildDataPacket(header, frames, buffer, packet_length, level);
}

size_t QuicPacketCreator::BuildConnectivityProbingPacket(
    const QuicPacketHeader& header, char* buffer, size_t packet_length,
    EncryptionLevel level) {
  QuicFrames frames;

  // Write a PING frame, which has no data payload.
  QuicPingFrame ping_frame;
  frames.push_back(QuicFrame(ping_frame));

  // Add padding to the rest of the packet.
  QuicPaddingFrame padding_frame;
  frames.push_back(QuicFrame(padding_frame));

  return framer_->BuildDataPacket(header, frames, buffer, packet_length, level);
}

size_t QuicPacketCreator::SerializeCoalescedPacket(
    const QuicCoalescedPacket& coalesced, char* buffer, size_t buffer_len) {
  if (HasPendingFrames()) {
    QUIC_BUG(quic_bug_10752_18)
        << ENDPOINT << "Try to serialize coalesced packet with pending frames";
    return 0;
  }
  RemoveSoftMaxPacketLength();
  QUIC_BUG_IF(quic_bug_12398_15, coalesced.length() == 0)
      << ENDPOINT << "Attempt to serialize empty coalesced packet";
  size_t packet_length = 0;
  size_t initial_length = 0;
  size_t padding_size = 0;
  if (coalesced.initial_packet() != nullptr) {
    // Padding coalesced packet containing initial packet to full.
    padding_size = coalesced.max_packet_length() - coalesced.length();
    if (framer_->perspective() == Perspective::IS_SERVER &&
        QuicUtils::ContainsFrameType(
            coalesced.initial_packet()->retransmittable_frames,
            CONNECTION_CLOSE_FRAME)) {
      // Do not pad server initial connection close packet.
      padding_size = 0;
    }
    initial_length = ReserializeInitialPacketInCoalescedPacket(
        *coalesced.initial_packet(), padding_size, buffer, buffer_len);
    if (initial_length == 0) {
      QUIC_BUG(quic_bug_10752_19)
          << ENDPOINT
          << "Failed to reserialize ENCRYPTION_INITIAL packet in "
             "coalesced packet";
      return 0;
    }
    QUIC_BUG_IF(quic_reserialize_initial_packet_unexpected_size,
                coalesced.initial_packet()->encrypted_length + padding_size !=
                    initial_length)
        << "Reserialize initial packet in coalescer has unexpected size, "
           "original_length: "
        << coalesced.initial_packet()->encrypted_length
        << ", coalesced.max_packet_length: " << coalesced.max_packet_length()
        << ", coalesced.length: " << coalesced.length()
        << ", padding_size: " << padding_size
        << ", serialized_length: " << initial_length
        << ", retransmittable frames: "
        << QuicFramesToString(
               coalesced.initial_packet()->retransmittable_frames)
        << ", nonretransmittable frames: "
        << QuicFramesToString(
               coalesced.initial_packet()->nonretransmittable_frames);
    buffer += initial_length;
    buffer_len -= initial_length;
    packet_length += initial_length;
  }
  size_t length_copied = 0;
  if (!coalesced.CopyEncryptedBuffers(buffer, buffer_len, &length_copied)) {
    QUIC_BUG(quic_serialize_coalesced_packet_copy_failure)
        << "SerializeCoalescedPacket failed. buffer_len:" << buffer_len
        << ", initial_length:" << initial_length
        << ", padding_size: " << padding_size
        << ", length_copied:" << length_copied
        << ", coalesced.length:" << coalesced.length()
        << ", coalesced.max_packet_length:" << coalesced.max_packet_length()
        << ", coalesced.packet_lengths:"
        << absl::StrJoin(coalesced.packet_lengths(), ":");
    return 0;
  }
  packet_length += length_copied;
  QUIC_DVLOG(1) << ENDPOINT
                << "Successfully serialized coalesced packet of length: "
                << packet_length;
  return packet_length;
}

// TODO(b/74062209): Make this a public method of framer?
SerializedPacket QuicPacketCreator::NoPacket() {
  return SerializedPacket(QuicPacketNumber(), PACKET_1BYTE_PACKET_NUMBER,
                          nullptr, 0, false, false);
}

QuicConnectionId QuicPacketCreator::GetDestinationConnectionId() const {
  if (framer_->perspective() == Perspective::IS_SERVER) {
    return client_connection_id_;
  }
  return server_connection_id_;
}

QuicConnectionId QuicPacketCreator::GetSourceConnectionId() const {
  if (framer_->perspective() == Perspective::IS_CLIENT) {
    return client_connection_id_;
  }
  return server_connection_id_;
}

QuicConnectionIdIncluded QuicPacketCreator::GetDestinationConnectionIdIncluded()
    const {
  // In versions that do not support client connection IDs, the destination
  // connection ID is only sent from client to server.
  return (framer_->perspective() == Perspective::IS_CLIENT ||
          framer_->version().SupportsClientConnectionIds())
             ? CONNECTION_ID_PRESENT
             : CONNECTION_ID_ABSENT;
}

QuicConnectionIdIncluded QuicPacketCreator::GetSourceConnectionIdIncluded()
    const {
  // Long header packets sent by server include source connection ID.
  // Ones sent by the client only include source connection ID if the version
  // supports client connection IDs.
  if (HasIetfLongHeader() &&
      (framer_->perspective() == Perspective::IS_SERVER ||
       framer_->version().SupportsClientConnectionIds())) {
    return CONNECTION_ID_PRESENT;
  }
  if (framer_->perspective() == Perspective::IS_SERVER) {
    return server_connection_id_included_;
  }
  return CONNECTION_ID_ABSENT;
}

uint8_t QuicPacketCreator::GetDestinationConnectionIdLength() const {
  QUICHE_DCHECK(QuicUtils::IsConnectionIdValidForVersion(server_connection_id_,
                                                         transport_version()))
      << ENDPOINT;
  return GetDestinationConnectionIdIncluded() == CONNECTION_ID_PRESENT
             ? GetDestinationConnectionId().length()
             : 0;
}

uint8_t QuicPacketCreator::GetSourceConnectionIdLength() const {
  QUICHE_DCHECK(QuicUtils::IsConnectionIdValidForVersion(server_connection_id_,
                                                         transport_version()))
      << ENDPOINT;
  return GetSourceConnectionIdIncluded() == CONNECTION_ID_PRESENT
             ? GetSourceConnectionId().length()
             : 0;
}

QuicPacketNumberLength QuicPacketCreator::GetPacketNumberLength() const {
  if (HasIetfLongHeader() &&
      !framer_->version().SendsVariableLengthPacketNumberInLongHeader()) {
    return PACKET_4BYTE_PACKET_NUMBER;
  }
  return packet_.packet_number_length;
}

size_t QuicPacketCreator::PacketHeaderSize() const {
  return GetPacketHeaderSize(
      framer_->transport_version(), GetDestinationConnectionIdLength(),
      GetSourceConnectionIdLength(), IncludeVersionInHeader(),
      IncludeNonceInPublicHeader(), GetPacketNumberLength(),
      GetRetryTokenLengthLength(), GetRetryToken().length(), GetLengthLength());
}

quiche::QuicheVariableLengthIntegerLength
QuicPacketCreator::GetRetryTokenLengthLength() const {
  if (QuicVersionHasLongHeaderLengths(framer_->transport_version()) &&
      HasIetfLongHeader() &&
      EncryptionlevelToLongHeaderType(packet_.encryption_level) == INITIAL) {
    return QuicDataWriter::GetVarInt62Len(GetRetryToken().length());
  }
  return quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
}

absl::string_view QuicPacketCreator::GetRetryToken() const {
  if (QuicVersionHasLongHeaderLengths(framer_->transport_version()) &&
      HasIetfLongHeader() &&
      EncryptionlevelToLongHeaderType(packet_.encryption_level) == INITIAL) {
    return retry_token_;
  }
  return absl::string_view();
}

void QuicPacketCreator::SetRetryToken(absl::string_view retry_token) {
  retry_token_ = std::string(retry_token);
}

bool QuicPacketCreator::ConsumeRetransmittableControlFrame(
    const QuicFrame& frame) {
  QUIC_BUG_IF(quic_bug_12398_16, IsControlFrame(frame.type) &&
                                     !GetControlFrameId(frame) &&
                                     frame.type != PING_FRAME)
      << ENDPOINT
      << "Adding a control frame with no control frame id: " << frame;
  QUICHE_DCHECK(QuicUtils::IsRetransmittableFrame(frame.type))
      << ENDPOINT << frame;
  MaybeBundleOpportunistically();
  if (HasPendingFrames()) {
    if (AddFrame(frame, next_transmission_type_)) {
      // There is pending frames and current frame fits.
      return true;
    }
  }
  QUICHE_DCHECK(!HasPendingFrames()) << ENDPOINT;
  if (frame.type != PING_FRAME && frame.type != CONNECTION_CLOSE_FRAME &&
      !delegate_->ShouldGeneratePacket(HAS_RETRANSMITTABLE_DATA,
                                       NOT_HANDSHAKE)) {
    // Do not check congestion window for ping or connection close frames.
    return false;
  }
  const bool success = AddFrame(frame, next_transmission_type_);
  QUIC_BUG_IF(quic_bug_10752_20, !success)
      << ENDPOINT << "Failed to add frame:" << frame
      << " transmission_type:" << next_transmission_type_;
  return success;
}

void QuicPacketCreator::MaybeBundleOpportunistically() {
  // delegate_->MaybeBundleOpportunistically() may change
  // next_transmission_type_ for the bundled data.
  const TransmissionType next_transmission_type = next_transmission_type_;
  delegate_->MaybeBundleOpportunistically(next_transmission_type_);
  next_transmission_type_ = next_transmission_type;
}

QuicConsumedData QuicPacketCreator::ConsumeData(QuicStreamId id,
                                                size_t write_length,
                                                QuicStreamOffset offset,
                                                StreamSendingState state) {
  QUIC_BUG_IF(quic_bug_10752_21, !flusher_attached_)
      << ENDPOINT
      << "Packet flusher is not attached when "
         "generator tries to write stream data.";
  bool has_handshake = QuicUtils::IsCryptoStreamId(transport_version(), id);
  const TransmissionType next_transmission_type = next_transmission_type_;
  MaybeBundleOpportunistically();
  // If the data being consumed is subject to flow control, check the flow
  // control send window to see if |write_length| exceeds the send window after
  // bundling opportunistic data, if so, reduce |write_length| to the send
  // window size.
  // The data being consumed is subject to flow control iff
  // - It is not a retransmission. We check next_transmission_type_ for that.
  // - And it's not handshake data. This is always true for ConsumeData because
  //   the function is not called for handshake data.
  const size_t original_write_length = write_length;
  if (next_transmission_type_ == NOT_RETRANSMISSION) {
    if (QuicByteCount send_window = delegate_->GetFlowControlSendWindowSize(id);
        write_length > send_window) {
      QUIC_DLOG(INFO) << ENDPOINT
                      << "After bundled data, reducing (old) write_length:"
                      << write_length << "to (new) send_window:" << send_window;
      write_length = send_window;
      state = NO_FIN;
    }
  }
  bool fin = state != NO_FIN;
  QUIC_BUG_IF(quic_bug_12398_17, has_handshake && fin)
      << ENDPOINT << "Handshake packets should never send a fin";
  // To make reasoning about crypto frames easier, we don't combine them with
  // other retransmittable frames in a single packet.
  if (has_handshake && HasPendingRetransmittableFrames()) {
    FlushCurrentPacket();
  }

  size_t total_bytes_consumed = 0;
  bool fin_consumed = false;

  if (!HasRoomForStreamFrame(id, offset, write_length)) {
    FlushCurrentPacket();
  }

  if (!fin && (write_length == 0)) {
    QUIC_BUG_IF(quic_bug_10752_22, original_write_length == 0)
        << ENDPOINT
        << "Attempt to consume empty data without FIN. old transmission type:"
        << next_transmission_type
        << ", new transmission type:" << next_transmission_type_;
    return QuicConsumedData(0, false);
  }
  // We determine if we can enter the fast path before executing
  // the slow path loop.
  bool run_fast_path =
      !has_handshake && state != FIN_AND_PADDING && !HasPendingFrames() &&
      write_length - total_bytes_consumed > kMaxOutgoingPacketSize &&
      latched_hard_max_packet_length_ == 0;

  while (!run_fast_path &&
         (has_handshake || delegate_->ShouldGeneratePacket(
                               HAS_RETRANSMITTABLE_DATA, NOT_HANDSHAKE))) {
    QuicFrame frame;
    bool needs_full_padding =
        has_handshake && fully_pad_crypto_handshake_packets_;

    if (!ConsumeDataToFillCurrentPacket(id, write_length - total_bytes_consumed,
                                        offset + total_bytes_consumed, fin,
                                        needs_full_padding,
                                        next_transmission_type_, &frame)) {
      // The creator is always flushed if there's not enough room for a new
      // stream frame before ConsumeData, so ConsumeData should always succeed.
      QUIC_BUG(quic_bug_10752_23)
          << ENDPOINT << "Failed to ConsumeData, stream:" << id;
      return QuicConsumedData(0, false);
    }

    // A stream frame is created and added.
    size_t bytes_consumed = frame.stream_frame.data_length;
    total_bytes_consumed += bytes_consumed;
    fin_consumed = fin && total_bytes_consumed == write_length;
    if (fin_consumed && state == FIN_AND_PADDING) {
      AddRandomPadding();
    }
    QUICHE_DCHECK(total_bytes_consumed == write_length ||
                  (bytes_consumed > 0 && HasPendingFrames()))
        << ENDPOINT;

    if (total_bytes_consumed == write_length) {
      // We're done writing the data. Exit the loop.
      // We don't make this a precondition because we could have 0 bytes of data
      // if we're simply writing a fin.
      break;
    }
    FlushCurrentPacket();

    run_fast_path =
        !has_handshake && state != FIN_AND_PADDING && !HasPendingFrames() &&
        write_length - total_bytes_consumed > kMaxOutgoingPacketSize &&
        latched_hard_max_packet_length_ == 0;
  }

  if (run_fast_path) {
    return ConsumeDataFastPath(id, write_length, offset, state != NO_FIN,
                               total_bytes_consumed);
  }

  // Don't allow the handshake to be bundled with other retransmittable frames.
  if (has_handshake) {
    FlushCurrentPacket();
  }

  return QuicConsumedData(total_bytes_consumed, fin_consumed);
}

QuicConsumedData QuicPacketCreator::ConsumeDataFastPath(
    QuicStreamId id, size_t write_length, QuicStreamOffset offset, bool fin,
    size_t total_bytes_consumed) {
  QUICHE_DCHECK(!QuicUtils::IsCryptoStreamId(transport_version(), id))
      << ENDPOINT;
  if (AttemptingToSendUnencryptedStreamData()) {
    return QuicConsumedData(total_bytes_consumed,
                            fin && (total_bytes_consumed == write_length));
  }

  while (total_bytes_consumed < write_length &&
         delegate_->ShouldGeneratePacket(HAS_RETRANSMITTABLE_DATA,
                                         NOT_HANDSHAKE)) {
    // Serialize and encrypt the packet.
    size_t bytes_consumed = 0;
    CreateAndSerializeStreamFrame(id, write_length, total_bytes_consumed,
                                  offset + total_bytes_consumed, fin,
                                  next_transmission_type_, &bytes_consumed);
    if (bytes_consumed == 0) {
      const std::string error_details =
          "Failed in CreateAndSerializeStreamFrame.";
      QUIC_BUG(quic_bug_10752_24) << ENDPOINT << error_details;
      delegate_->OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                      error_details);
      break;
    }
    total_bytes_consumed += bytes_consumed;
  }

  return QuicConsumedData(total_bytes_consumed,
                          fin && (total_bytes_consumed == write_length));
}

size_t QuicPacketCreator::ConsumeCryptoData(EncryptionLevel level,
                                            size_t write_length,
                                            QuicStreamOffset offset) {
  QUIC_DVLOG(2) << ENDPOINT << "ConsumeCryptoData " << level << " write_length "
                << write_length << " offset " << offset;
  QUIC_BUG_IF(quic_bug_10752_25, !flusher_attached_)
      << ENDPOINT
      << "Packet flusher is not attached when "
         "generator tries to write crypto data.";
  MaybeBundleOpportunistically();
  // To make reasoning about crypto frames easier, we don't combine them with
  // other retransmittable frames in a single packet.
  // TODO(nharper): Once we have separate packet number spaces, everything
  // should be driven by encryption level, and we should stop flushing in this
  // spot.
  if (HasPendingRetransmittableFrames()) {
    FlushCurrentPacket();
  }

  size_t total_bytes_consumed = 0;

  while (
      total_bytes_consumed < write_length &&
      delegate_->ShouldGeneratePacket(HAS_RETRANSMITTABLE_DATA, IS_HANDSHAKE)) {
    QuicFrame frame;
    if (!ConsumeCryptoDataToFillCurrentPacket(
            level, write_length - total_bytes_consumed,
            offset + total_bytes_consumed, fully_pad_crypto_handshake_packets_,
            next_transmission_type_, &frame)) {
      // The only pending data in the packet is non-retransmittable frames.
      // I'm assuming here that they won't occupy so much of the packet that a
      // CRYPTO frame won't fit.
      QUIC_BUG_IF(quic_bug_10752_26, !HasSoftMaxPacketLength()) << absl::StrCat(
          ENDPOINT, "Failed to ConsumeCryptoData at level ", level,
          ", pending_frames: ", GetPendingFramesInfo(),
          ", has_soft_max_packet_length: ", HasSoftMaxPacketLength(),
          ", max_packet_length: ", max_packet_length_, ", transmission_type: ",
          TransmissionTypeToString(next_transmission_type_),
          ", packet_number: ", packet_number().ToString());
      return 0;
    }
    total_bytes_consumed += frame.crypto_frame->data_length;
    FlushCurrentPacket();
  }

  // Don't allow the handshake to be bundled with other retransmittable frames.
  FlushCurrentPacket();

  return total_bytes_consumed;
}

void QuicPacketCreator::GenerateMtuDiscoveryPacket(QuicByteCount target_mtu) {
  // MTU discovery frames must be sent by themselves.
  if (!CanSetMaxPacketLength()) {
    QUIC_BUG(quic_bug_10752_27)
        << ENDPOINT
        << "MTU discovery packets should only be sent when no other "
        << "frames needs to be sent.";
    return;
  }
  const QuicByteCount current_mtu = max_packet_length();

  // The MTU discovery frame is allocated on the stack, since it is going to be
  // serialized within this function.
  QuicMtuDiscoveryFrame mtu_discovery_frame;
  QuicFrame frame(mtu_discovery_frame);

  // Send the probe packet with the new length.
  SetMaxPacketLength(target_mtu);
  const bool success = AddPaddedSavedFrame(frame, next_transmission_type_);
  FlushCurrentPacket();
  // The only reason AddFrame can fail is that the packet is too full to fit in
  // a ping.  This is not possible for any sane MTU.
  QUIC_BUG_IF(quic_bug_10752_28, !success)
      << ENDPOINT << "Failed to send path MTU target_mtu:" << target_mtu
      << " transmission_type:" << next_transmission_type_;

  // Reset the packet length back.
  SetMaxPacketLength(current_mtu);
}

bool QuicPacketCreator::FlushAckFrame(const QuicFrames& frames) {
  QUIC_BUG_IF(quic_bug_10752_30, !flusher_attached_)
      << ENDPOINT
      << "Packet flusher is not attached when "
         "generator tries to send ACK frame.";
  // delegate_->MaybeBundleOpportunistically could be called nestedly when
  // sending a control f
```