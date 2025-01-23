Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Context:** The prompt clearly states this is part of the `quic_framer_test.cc` file within Chromium's QUIC implementation. This immediately tells me it's a unit test file focusing on the `QuicFramer` class. The "part 16 of 16" indicates this is likely the last section of a larger test suite.

2. **Identify the Core Functionality Under Test:**  Scanning the code, the dominant theme is "Key Update". Several test cases explicitly mention "KeyUpdate" in their names: `KeyUpdateReceived`, `KeyUpdateWrongKey`, `KeyUpdateReceivedWhenNotEnabled`, `KeyUpdateLocallyInitiated`, `KeyUpdateLocallyInitiatedReceivedOldPacket`, `KeyUpdateOnFirstReceivedPacket`. This is a strong signal about the primary focus. Other tests, like `ErrorWhenUnexpectedFrameTypeEncountered` and `ShortHeaderWithNonDefaultConnectionIdLength`, suggest testing error handling and specific header parsing scenarios. `ReportEcnCountsIfPresent` highlights testing the handling of Explicit Congestion Notification (ECN).

3. **Analyze Individual Test Cases:** I break down each `TEST_P` block to understand its specific purpose:
    * **`KeyUpdateReceived`:**  Checks if a key update initiated by the peer is correctly processed. It verifies that the `visitor_` receives the correct callbacks.
    * **`KeyUpdateWrongKey`:** Tests the scenario where a packet arrives with an unexpected key during a key update. It verifies that the packet isn't processed immediately, and the framer attempts to use the next derived key.
    * **`KeyUpdateReceivedWhenNotEnabled`:**  Confirms that if key updates aren't explicitly enabled, an incoming packet signaling a key update is rejected.
    * **`KeyUpdateLocallyInitiated`:** Checks the process when the local endpoint initiates a key update. It verifies the local key update logic and the handling of subsequent incoming packets with different key phases.
    * **`KeyUpdateLocallyInitiatedReceivedOldPacket`:** Tests the case where, after a local key update, an old packet (from the previous key phase) arrives *before* a packet from the new key phase.
    * **`KeyUpdateOnFirstReceivedPacket`:** Tests if a key update signaled in the very first received packet is handled correctly.
    * **`ErrorWhenUnexpectedFrameTypeEncountered`:**  Verifies that the framer correctly identifies and reports an error when it encounters an unexpected frame type for the current encryption level (specifically, an ACK frame in a 0-RTT packet).
    * **`ShortHeaderWithNonDefaultConnectionIdLength`:**  Tests the ability of the framer to parse short headers that use a non-default connection ID length. This involves interaction with a `MockConnectionIdGenerator`.
    * **`ReportEcnCountsIfPresent`:** Checks if the framer correctly extracts and reports ECN counts from ACK frames when they are present.

4. **Identify Connections to JavaScript (and lack thereof):**  Based on my understanding of the code and QUIC protocol, there's no direct or obvious relationship to JavaScript functionality within this specific test file. QUIC is a transport layer protocol, and while JavaScript might *use* QUIC via browser APIs for network communication, the core protocol implementation and its testing are done in languages like C++. Therefore, my conclusion is that there's no direct relationship to JavaScript functionality here.

5. **Infer Logical Reasoning (Input/Output):**  For each test case, I try to deduce the intended input (the crafted packets and framer state) and the expected output (the behavior of the framer, the calls to the visitor, and the error status). This helps in understanding the specific logic being tested. For example, in `KeyUpdateWrongKey`, the input is packets with different key tags and phases, and the expected output is that only the packet with the currently installed key is processed initially, while the others trigger attempts with the next key.

6. **Identify Common Usage Errors:** I think about how a developer might misuse the `QuicFramer` or related APIs, leading to the scenarios tested in these cases. For example, failing to enable key updates before expecting them, or sending/receiving packets with incorrect keying material.

7. **Trace User Operations (Debugging):** I imagine how a network connection progresses and how a user action could lead to the reception of the specific packets being tested. This involves understanding the client-server interaction in QUIC and how key updates are negotiated and applied.

8. **Synthesize the Overall Function:** Based on the analysis of individual tests, I summarize the overarching purpose of this part of the test suite. The key takeaway is its focus on validating the key update mechanism and various edge cases related to packet processing, especially around encryption and header parsing.

9. **Structure the Output:** Finally, I organize the gathered information into the requested format, clearly separating the functionalities, the JavaScript relationship (or lack thereof), logical reasoning with examples, common errors, debugging scenarios, and the final summary. I use clear and concise language, highlighting the key aspects of each section.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc` 文件的第 16 部分，也是最后一部分。 从提供的代码片段来看，这一部分主要集中在测试 `QuicFramer` 类在处理密钥更新（Key Update）以及一些特殊情况下的行为。

**主要功能归纳:**

1. **密钥更新（Key Update）处理测试:**
   - **接收到合法的密钥更新:** 测试当 `QuicFramer` 收到对端发起的密钥更新请求时，能否正确处理并更新密钥。
   - **接收到错误的密钥:** 测试当收到使用错误密钥加密的数据包时，`QuicFramer` 的处理逻辑，包括是否会尝试使用下一个密钥。
   - **未启用密钥更新时收到更新:** 测试在连接未启用密钥更新功能时，收到密钥更新数据包的处理情况。
   - **本地发起密钥更新:** 测试本地 `QuicFramer` 发起密钥更新时，自身状态的更新以及对后续接收到的数据包的处理。
   - **本地发起密钥更新后收到旧数据包:** 测试在本地发起密钥更新后，接收到使用旧密钥加密的数据包的处理情况，包括在收到新密钥加密的数据包之前和之后。
   - **在收到的第一个数据包上进行密钥更新:** 测试当收到的第一个数据包就带有密钥更新指示时的处理。

2. **错误处理测试:**
   - **遇到意外的帧类型:** 测试当 `QuicFramer` 在特定加密级别遇到不允许的帧类型时，是否能正确检测并报告错误。

3. **报头解析测试:**
   - **短报头与非默认连接 ID 长度:** 测试 `QuicFramer` 是否能正确解析使用非默认长度连接 ID 的短报头数据包。

4. **ECN 计数报告测试:**
   - **报告 ECN 计数（如果存在）:** 测试 `QuicFramer` 能否正确解析和报告 ACK 帧中携带的显式拥塞通知 (ECN) 计数。

**与 JavaScript 的关系:**

这个 C++ 文件是 Chromium 网络栈的底层实现部分，直接与 JavaScript 没有功能上的关联。JavaScript 通常通过浏览器提供的 Web API（例如 Fetch API、WebSocket API 等）来使用网络功能。这些 API 底层可能会使用 QUIC 协议，但 JavaScript 代码本身不会直接操作 `QuicFramer` 类。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(QuicFramerTest, KeyUpdateReceived)` 为例：

* **假设输入:**
    * `QuicFramer` 初始化为服务器端。
    * 设置了初始解密器。
    * 启用了密钥更新支持。
    * 接收到一个来自客户端的加密数据包，该数据包的密钥阶段（key phase）已更新。
* **预期输出:**
    * `framer_.ProcessPacket(*encrypted)` 返回 `true`，表示数据包处理成功。
    * `visitor_.key_update_count()` 的值增加，表示检测到密钥更新。
    * `visitor_.derive_next_key_count_` 的值增加，表示推导了下一个密钥。
    * `visitor_.decrypted_first_packet_in_key_phase_count_` 的值增加，表示这是新密钥阶段解密的第一个数据包。

以 `TEST_P(QuicFramerTest, KeyUpdateWrongKey)` 为例：

* **假设输入:**
    * `QuicFramer` 初始化为服务器端。
    * 设置了解密器（key=0）。
    * 启用了密钥更新支持。
    * 接收到来自客户端的加密数据包，该数据包的密钥阶段已更新，但使用的密钥与当前解密器不匹配（例如，使用了 key=2）。
* **预期输出:**
    * `framer_.ProcessPacket(*encrypted)` 返回 `false`，表示数据包处理失败。
    * `visitor_.key_update_count()` 保持不变，因为这不是一个合法的密钥更新请求。
    * `visitor_.derive_next_key_count_` 的值可能增加，因为 `QuicFramer` 可能会尝试使用下一个推导的密钥进行解密。
    * `framer_.PotentialPeerKeyUpdateAttemptCount()` 的值增加，表示检测到潜在的对端密钥更新尝试。

**用户或编程常见的使用错误:**

1. **未启用密钥更新支持:** 如果连接的两端没有正确协商并启用密钥更新功能，当一方尝试发起密钥更新时，另一方可能会因为无法识别新的密钥阶段而导致连接中断或数据包丢失。
   ```c++
   // 服务器端忘记设置密钥更新支持
   framer_.SetKeyUpdateSupportForConnection(false);
   ```
2. **密钥不同步:** 如果连接的两端在密钥更新过程中密钥不同步（例如，一方已经更新了密钥，另一方还在使用旧密钥），会导致数据包无法正确解密。这可能是由于实现中的逻辑错误或者网络传输中的延迟导致。
3. **错误地假设密钥阶段:** 在编写自定义的 QUIC 处理逻辑时，可能会错误地假设数据包的密钥阶段，导致使用错误的密钥进行解密。

**用户操作如何一步步到达这里 (调试线索):**

通常，用户不会直接操作到 `QuicFramer` 这一层。这是网络栈的内部实现。但是，以下用户操作可能会间接地触发与密钥更新相关的代码路径：

1. **用户发起一个 HTTPS 连接:** 当用户在浏览器中输入一个 `https://` 网址并访问时，浏览器可能会尝试使用 QUIC 协议建立连接。
2. **QUIC 连接建立和数据传输:** 在 QUIC 连接建立后，双方会使用协商好的密钥进行数据传输。
3. **触发密钥更新:**
   - **时间或数据量触发:** QUIC 协议可以配置为在一定时间间隔或传输一定数据量后触发密钥更新，以提高安全性。
   - **显式协商:**  在某些情况下，连接的一端可能会显式地发起密钥更新协商。
4. **接收到密钥更新相关的数据包:** 当上述密钥更新被触发后，接收端会收到带有新密钥阶段标识的数据包。
5. **`QuicFramer::ProcessPacket()` 被调用:**  网络栈接收到数据包后，会调用 `QuicFramer::ProcessPacket()` 来解析和处理该数据包，其中包括处理密钥更新相关的逻辑。
6. **`QuicFramerTest` 的作用:**  在开发和调试网络栈时，开发人员会编写像 `QuicFramerTest` 这样的单元测试来模拟各种场景，包括正常的密钥更新流程和异常情况（如错误的密钥），以确保 `QuicFramer` 的行为符合预期。如果测试失败，则表明 `QuicFramer` 在处理密钥更新时存在 bug。

**作为第 16 部分的归纳:**

作为整个 `quic_framer_test.cc` 文件的最后一部分，这部分测试主要关注 `QuicFramer` 在处理密钥更新这一关键安全特性时的正确性和鲁棒性。它涵盖了正常更新流程、错误情况处理以及与其他协议特性的交互（如短报头解析和 ECN 报告）。这表明在整个 QUIC 数据包处理流程中，密钥更新是一个复杂且重要的环节，需要进行全面的测试以保证网络连接的安全性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
t_);
  EXPECT_EQ(2, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateWrongKey) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 0, false));
  ASSERT_TRUE(encrypted);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  // Processed valid packet with phase=0, key=1: no key update.
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
  EXPECT_EQ(0u, framer_.PotentialPeerKeyUpdateAttemptCount());

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 2, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet with phase=1 but key=3, should not process and should not cause key
  // update, but next decrypter key should have been created to attempt to
  // decode it.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
  EXPECT_EQ(1u, framer_.PotentialPeerKeyUpdateAttemptCount());

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet with phase=1 but key=1, should not process and should not cause key
  // update.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
  EXPECT_EQ(2u, framer_.PotentialPeerKeyUpdateAttemptCount());

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet with phase=0 but key=2, should not process and should not cause key
  // update.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
  EXPECT_EQ(2u, framer_.PotentialPeerKeyUpdateAttemptCount());

  header.packet_number += 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet with phase=0 and key=0, should process and reset
  // potential_peer_key_update_attempt_count_.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
  EXPECT_EQ(0u, framer_.PotentialPeerKeyUpdateAttemptCount());
}

TEST_P(QuicFramerTest, KeyUpdateReceivedWhenNotEnabled) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 1, true));
  ASSERT_TRUE(encrypted);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Received a packet with key phase updated even though framer hasn't had key
  // update enabled (SetNextOneRttCrypters never called). Should fail to
  // process.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(0u, visitor_.key_update_count());
  EXPECT_EQ(0, visitor_.derive_next_key_count_);
  EXPECT_EQ(0, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateLocallyInitiated) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  EXPECT_TRUE(framer_.DoKeyUpdate(KeyUpdateReason::kLocalForTests));
  // Key update count should be updated, but haven't received packet from peer
  // with new key phase.
  ASSERT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(KeyUpdateReason::kLocalForTests, visitor_.key_update_reasons_[0]);
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(0, visitor_.decrypted_first_packet_in_key_phase_count_);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // Process packet N with phase 1.
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, 1, true));
  ASSERT_TRUE(encrypted);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change and
  // OnDecryptedFirstPacketInKeyPhase should have been called.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N-1 with phase 0. (Receiving packet from previous phase
  // after packet from new phase was received.)
  header.packet_number = kPacketNumber - 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+1 with phase 0 and key 1. This should not decrypt even
  // though it's using the previous key, since the packet number is higher than
  // a packet number received using the current key.
  header.packet_number = kPacketNumber + 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should not decrypt and key update count should not change.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(2, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateLocallyInitiatedReceivedOldPacket) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  EXPECT_TRUE(framer_.DoKeyUpdate(KeyUpdateReason::kLocalForTests));
  // Key update count should be updated, but haven't received packet
  // from peer with new key phase.
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(0, visitor_.decrypted_first_packet_in_key_phase_count_);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // Process packet N with phase 0. (Receiving packet from previous phase
  // after locally initiated key update, but before any packet from new phase
  // was received.)
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted =
      EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change and
  // OnDecryptedFirstPacketInKeyPhase should not have been called since the
  // packet was from the previous key phase.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(0, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+1 with phase 1.
  header.packet_number = kPacketNumber + 1;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 1, true);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should decrypt and key update count should not change, but
  // OnDecryptedFirstPacketInKeyPhase should have been called.
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);

  // Process packet N+2 with phase 0 and key 1. This should not decrypt even
  // though it's using the previous key, since the packet number is higher than
  // a packet number received using the current key.
  header.packet_number = kPacketNumber + 2;
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  data = BuildDataPacket(header, frames);
  ASSERT_TRUE(data != nullptr);
  encrypted = EncryptPacketWithTagAndPhase(*data, 0, false);
  ASSERT_TRUE(encrypted);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  // Packet should not decrypt and key update count should not change.
  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(2, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, KeyUpdateOnFirstReceivedPacket) {
  if (!framer_.version().UsesTls()) {
    // Key update is only used in QUIC+TLS.
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  // Doesn't use SetDecrypterLevel since we want to use StrictTaggingDecrypter
  // instead of TestDecrypter.
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                           std::make_unique<StrictTaggingDecrypter>(/*key=*/0));
  framer_.SetKeyUpdateSupportForConnection(true);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = QuicPacketNumber(123);

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      EncryptPacketWithTagAndPhase(*data, /*tag=*/1, /*phase=*/true));
  ASSERT_TRUE(encrypted);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
  // Processed valid packet with phase=1, key=1: do key update.
  EXPECT_EQ(1u, visitor_.key_update_count());
  EXPECT_EQ(1, visitor_.derive_next_key_count_);
  EXPECT_EQ(1, visitor_.decrypted_first_packet_in_key_phase_count_);
}

TEST_P(QuicFramerTest, ErrorWhenUnexpectedFrameTypeEncountered) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version()) ||
      !QuicVersionHasLongHeaderLengths(framer_.transport_version()) ||
      !framer_.version().HasLongHeaderLengths()) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // public flags (long header with packet type ZERO_RTT_PROTECTED and
    // 4-byte packet number)
    0xD3,
    // version
    QUIC_VERSION_BYTES,
    // destination connection ID length
    0x08,
    // destination connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // source connection ID length
    0x08,
    // source connection ID
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
    // long header packet length
    0x05,
    // packet number
    0x12, 0x34, 0x56, 0x00,
    // unexpected ietf ack frame type in 0-RTT packet
    0x02,
  };
  // clang-format on

  ReviseFirstByteByVersion(packet);
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);

  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  EXPECT_EQ(
      "IETF frame type IETF_ACK is unexpected at encryption level "
      "ENCRYPTION_ZERO_RTT",
      framer_.detailed_error());
}

TEST_P(QuicFramerTest, ShortHeaderWithNonDefaultConnectionIdLength) {
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  unsigned char packet[kMaxIncomingPacketSize + 1] = {
     // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0x28, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x48,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  MockConnectionIdGenerator generator;
    EXPECT_CALL(generator, ConnectionIdLength(0x28)).WillOnce(Return(9));
  unsigned char* p = packet;
  size_t p_size = ABSL_ARRAYSIZE(packet);

  const size_t header_size = GetPacketHeaderSize(
      framer_.transport_version(), kPacket8ByteConnectionId + 1,
      kPacket0ByteConnectionId, !kIncludeVersion,
      !kIncludeDiversificationNonce, PACKET_4BYTE_PACKET_NUMBER,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0,
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0) + 1;
  // Add one because it's a 9 byte connection ID.

  memset(p + header_size, 0, kMaxIncomingPacketSize - header_size);

  QuicEncryptedPacket encrypted(AsChars(p), p_size, false);
  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag;
  QuicConnectionId destination_connection_id, source_connection_id;
  QuicVersionLabel version_label;
  std::string detailed_error;
  bool use_length_prefix;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  EXPECT_EQ(QUIC_NO_ERROR,
      QuicFramer::ParsePublicHeaderDispatcherShortHeaderLengthUnknown(
          encrypted, &format, &long_packet_type, &version_flag,
          &use_length_prefix, &version_label, &parsed_version,
          &destination_connection_id, &source_connection_id, &retry_token,
          &detailed_error, generator));
  EXPECT_EQ(format, IETF_QUIC_SHORT_HEADER_PACKET);
  EXPECT_EQ(destination_connection_id.length(), 9);
  EXPECT_EQ(long_packet_type, INVALID_PACKET_TYPE);
  EXPECT_FALSE(version_flag);
  EXPECT_FALSE(use_length_prefix);
  EXPECT_EQ(version_label, 0);
  EXPECT_EQ(parsed_version, UnsupportedQuicVersion());
  EXPECT_EQ(source_connection_id.length(), 0);
  EXPECT_FALSE(retry_token.has_value());
  EXPECT_EQ(detailed_error, "");
}

TEST_P(QuicFramerTest, ReportEcnCountsIfPresent) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  for (bool ecn_marks : { false, true }) {
    // Add some padding, because TestEncrypter doesn't add an authentication
    // tag. For a small packet, this will cause QuicFramer to fail to get a
    // header protection sample.
    QuicPaddingFrame padding_frame(kTagSize);
    // Create a packet with just an ack.
    QuicAckFrame ack_frame = InitAckFrame(5);
    if (ecn_marks) {
      ack_frame.ecn_counters = QuicEcnCounts(100, 10000, 1000000);
    } else {
      ack_frame.ecn_counters = std::nullopt;
    }
    QuicFrames frames = {QuicFrame(padding_frame), QuicFrame(&ack_frame)};
    // Build an ACK packet.
    QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
    std::unique_ptr<QuicPacket> raw_ack_packet(BuildDataPacket(header, frames));
    ASSERT_TRUE(raw_ack_packet != nullptr);
    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length =
        framer_.EncryptPayload(ENCRYPTION_INITIAL, header.packet_number,
                               *raw_ack_packet, buffer, kMaxOutgoingPacketSize);
    ASSERT_NE(0u, encrypted_length);
    // Now make sure we can turn our ack packet back into an ack frame.
    QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
    MockFramerVisitor visitor;
    framer_.set_visitor(&visitor);
    EXPECT_CALL(visitor, OnPacket()).Times(1);
    EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(visitor, OnUnauthenticatedHeader(_))
        .Times(1)
        .WillOnce(Return(true));
    EXPECT_CALL(visitor, OnPacketHeader(_)).Times(1);
    EXPECT_CALL(visitor, OnDecryptedPacket(_, _)).Times(1);
    EXPECT_CALL(visitor, OnAckFrameStart(_, _)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(visitor, OnAckRange(_, _)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(visitor, OnAckFrameEnd(_, ack_frame.ecn_counters))
        .Times(1).WillOnce(Return(true));
    EXPECT_CALL(visitor, OnPacketComplete()).Times(1);
    ASSERT_TRUE(framer_.ProcessPacket(
                    QuicEncryptedPacket(buffer, encrypted_length, false)));
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
```