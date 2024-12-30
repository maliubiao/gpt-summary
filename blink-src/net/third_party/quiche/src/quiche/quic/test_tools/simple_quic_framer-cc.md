Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of `simple_quic_framer.cc`. The request also specifically asks about its relation to JavaScript, logical inferences (with examples), potential usage errors, and debugging context.

2. **Identify the Primary Role:** I quickly scan the code and see the inclusion of `quiche/quic/core/quic_framer.h` and the class `SimpleQuicFramer` interacting with a `QuicFramer`. This immediately tells me the primary function is related to *parsing* and *processing* QUIC packets. The "simple" in the name suggests it's a simplified version, likely for testing.

3. **Analyze Key Components:** I then examine the main parts of the code:

    * **`SimpleFramerVisitor`:** This class clearly implements the `QuicFramerVisitorInterface`. This is crucial because the `QuicFramer` uses a visitor pattern to notify the client about the parsed frames within a packet. I mentally map out what each `On...Frame` method does: it extracts and stores the frame data. The visitor is the key to understanding what information the `SimpleQuicFramer` extracts.

    * **`SimpleQuicFramer`:** This class holds an instance of `QuicFramer` and the `SimpleFramerVisitor`. Its `ProcessPacket` method is the main entry point, feeding packets to the underlying `QuicFramer` and setting the visitor. The getter methods provide access to the data collected by the visitor.

4. **Summarize Functionality:** Based on the above analysis, I can summarize the core function: `SimpleQuicFramer` is a test utility to parse and examine the contents of QUIC packets. It uses a visitor to extract various frame types and stores them in member variables for later inspection.

5. **Address JavaScript Relationship:** I consider how this C++ code might relate to JavaScript. QUIC is a transport protocol often used in web browsers and servers. Therefore, JavaScript running in a browser *using* QUIC would indirectly interact with the functionality this code represents. The browser's networking stack would use something like `QuicFramer` to process incoming QUIC packets. I make sure to emphasize that `simple_quic_framer.cc` itself isn't directly executed by JavaScript but represents a core piece of the underlying infrastructure.

6. **Provide Logical Inference Examples:**  The request asks for logical inferences. The core logic here is packet processing. I need to come up with simple examples:

    * **Input:** A raw byte string representing a QUIC packet.
    * **Process:** The `ProcessPacket` method would parse this.
    * **Output:**  The visitor's member variables would be populated with the extracted frame data (e.g., stream data, ACK information). I try to create distinct examples for different frame types (STREAM and ACK) to showcase the functionality.

7. **Identify Potential Usage Errors:**  Being a testing utility, the most likely errors involve incorrect usage *of* the utility:

    * **Not calling `ProcessPacket`:**  The visitor wouldn't be populated.
    * **Accessing data before processing:**  The getters would return empty or default values.
    * **Incorrect packet data:** The underlying `QuicFramer` would report errors (which the visitor captures).

8. **Explain Debugging Context:**  The request asks how a user might end up here as a debugging step. I consider the typical scenarios:

    * **Investigating QUIC connection issues:**  When a website using QUIC has problems, developers might need to inspect the raw QUIC packets being exchanged.
    * **Debugging the QUIC implementation itself:** Developers working on Chromium's networking stack would use this kind of tool to verify packet parsing logic. I trace the steps from user action (visiting a website) down to the point where `SimpleQuicFramer` could be used for inspection.

9. **Structure the Answer:**  I organize my thoughts into clear sections corresponding to the user's request: functionality, JavaScript relation, logical inferences, usage errors, and debugging context. I use clear headings and bullet points for readability.

10. **Refine and Review:**  Finally, I reread my answer to make sure it's accurate, complete, and easy to understand. I double-check that I've addressed all parts of the initial request. I ensure the examples are simple and illustrate the points effectively. I also pay attention to the language, using terms familiar to someone working with network protocols.
The file `net/third_party/quiche/src/quiche/quic/test_tools/simple_quic_framer.cc` in the Chromium network stack provides a simplified QUIC framer specifically designed for testing purposes. It's not intended for production use but offers a way to easily parse and inspect the structure of QUIC packets in tests.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Packet Parsing:**  The primary function is to take a raw QUIC packet (represented by `QuicEncryptedPacket`) as input and parse its various components, such as the header and different types of frames (STREAM, ACK, CRYPTO, etc.). This is achieved by leveraging the more comprehensive `QuicFramer` class from the core QUIC implementation.

2. **Simplified Interface:** It wraps the complex `QuicFramer` with a simpler interface that's easier to use in test scenarios. Instead of requiring a full QUIC session context, you can just feed it raw packets.

3. **Frame Extraction:**  It uses a custom visitor class (`SimpleFramerVisitor`) to intercept the parsed frames and store them in member variables. This allows test code to easily access and inspect the individual frames within a packet.

4. **Verification:**  By inspecting the extracted frames, test code can verify that QUIC packets are formatted correctly, contain the expected information, and adhere to the QUIC protocol specifications.

**Relationship to JavaScript:**

This C++ code doesn't directly interact with JavaScript at runtime. JavaScript in a web browser or Node.js doesn't execute this specific file. However, it plays an **indirect role** in ensuring the correctness of the QUIC implementation used by JavaScript.

* **Testing the Underlying Infrastructure:**  This file is used in C++ unit tests within the Chromium project. These tests verify the low-level QUIC parsing logic. If this C++ code finds issues, it indicates a bug in the core QUIC implementation. This, in turn, ensures that when JavaScript uses the browser's networking stack (which includes the QUIC implementation), the QUIC protocol is handled correctly.

**Example:** Imagine a JavaScript application using the `fetch` API to make an HTTP/3 request (which uses QUIC). The browser's underlying networking code (including parts tested by `simple_quic_framer.cc`) will handle the QUIC connection establishment, data transmission, and error handling. If `simple_quic_framer.cc` and related tests find a bug in how STREAM frames are parsed, fixing that bug ensures the JavaScript application receives the correct data.

**Logical Inference with Examples:**

The core logic here is the parsing of a byte stream representing a QUIC packet into structured data.

**Assumption:** We have a well-formed QUIC packet containing a STREAM frame.

**Input:** A `QuicEncryptedPacket` object containing the following raw bytes (this is a simplified example, actual packets are more complex):

```
// Hypothetical raw packet bytes representing a STREAM frame:
// (This is illustrative and not a real, correctly encoded packet)
uint8_t raw_packet[] = {
  0xC0,       // Long header, QUIC version ...
  0x01, 0x02, 0x03, 0x04, // Destination Connection ID
  0x05, 0x06, 0x07, 0x08, // Source Connection ID
  0x0A, 0x00, 0x00, 0x00, // Packet Number
  0x06,       // STREAM frame type
  0x00, 0x00, 0x00, 0x01, // Stream ID 1
  0x00, 0x00, 0x00, 0x00, // Offset 0
  0x05,       // Length of data
  'h', 'e', 'l', 'l', 'o' // Data "hello"
};
QuicEncryptedPacket packet(reinterpret_cast<char*>(raw_packet), sizeof(raw_packet));
```

**Process:**

1. The `SimpleQuicFramer::ProcessPacket(packet)` method is called.
2. Internally, the `QuicFramer` within `SimpleQuicFramer` parses the packet.
3. The `SimpleFramerVisitor`'s `OnStreamFrame` method is called when the STREAM frame is encountered.
4. The `OnStreamFrame` method stores the stream ID (1), offset (0), FIN flag (likely false in this example), and the data ("hello") in its `stream_frames_` member.

**Output:**

After `ProcessPacket` returns, calling `simple_framer.stream_frames()` would return a vector containing one `QuicStreamFrame` object. Inspecting this object would reveal:

* `frame.stream_id == 1`
* `frame.offset == 0`
* `frame.fin == false` (assuming no FIN bit is set in this simplified example)
* `frame.data_buffer` points to "hello"
* `frame.data_length == 5`

**User or Programming Common Usage Errors:**

1. **Processing Malformed Packets:**  If you feed `ProcessPacket` with a completely invalid or truncated QUIC packet, the `QuicFramer` will likely report an error. You should check the framer's error status after processing:

   ```c++
   SimpleQuicFramer framer;
   QuicEncryptedPacket bad_packet("invalid data", 12);
   framer.ProcessPacket(bad_packet);
   if (framer.framer()->error() != QUIC_NO_ERROR) {
     // Handle the error, e.g., log it, fail the test
   }
   ```

2. **Accessing Frame Data Before Processing:**  The frame data is only populated after `ProcessPacket` is called. Accessing `ack_frames()`, `stream_frames()`, etc., before processing a packet will result in empty vectors.

   ```c++
   SimpleQuicFramer framer;
   // Don't do this:
   // const auto& frames = framer.stream_frames(); // frames will be empty here
   QuicEncryptedPacket packet(...);
   framer.ProcessPacket(packet);
   const auto& frames = framer.stream_frames(); // Now frames will be populated
   ```

3. **Misinterpreting "Simple":**  While `SimpleQuicFramer` simplifies the interface for testing, it still relies on the underlying QUIC protocol knowledge. Understanding the structure of QUIC packets is crucial to using it effectively.

**User Operation to Reach This Code (Debugging Clues):**

This code is not directly reached by typical user interactions with a web browser. It's primarily a developer tool. However, let's imagine a scenario where a developer is investigating a QUIC-related issue:

1. **User Reports a Problem:** A user reports a website is not loading correctly, or they are experiencing connection issues specifically with websites using HTTP/3 (QUIC).

2. **Developer Suspects QUIC Issues:** The developer, after initial investigation, suspects a problem in the QUIC implementation within the browser.

3. **Capturing Network Traffic:** The developer might use network capture tools (like Wireshark or Chrome's built-in network inspector with "Capture QUIC debug logs") to capture the raw QUIC packets being exchanged between the browser and the server.

4. **Analyzing Captured Packets:** The developer now has a raw byte representation of the QUIC packets. To understand the contents of these packets, they might:

   * **Use a QUIC Packet Inspector Tool:**  Dedicated tools exist that can parse and display QUIC packet contents.
   * **Write a C++ Unit Test:** If the developer needs to reproduce a specific scenario or test a particular aspect of QUIC parsing, they might write a C++ unit test that uses `SimpleQuicFramer`.

5. **Using `SimpleQuicFramer` in a Test:** The developer would create a test case:

   ```c++
   #include "net/third_party/quiche/src/quiche/quic/test_tools/simple_quic_framer.h"
   #include "testing/gtest/include/gtest/gtest.h"

   namespace quic {
   namespace test {

   TEST(MyQuicTest, ParseSpecificPacket) {
     // 1. Obtain the raw bytes of the problematic packet (e.g., from the capture)
     const char raw_packet_bytes[] = { /* ... raw bytes from capture ... */ };
     QuicEncryptedPacket packet(raw_packet_bytes, sizeof(raw_packet_bytes));

     // 2. Create a SimpleQuicFramer
     SimpleQuicFramer framer;

     // 3. Process the packet
     framer.ProcessPacket(packet);

     // 4. Inspect the extracted frames to understand the packet's contents
     const auto& stream_frames = framer.stream_frames();
     for (const auto& stream_frame : stream_frames) {
       // Check the stream ID, offset, data, etc.
       EXPECT_EQ(stream_frame->stream_id, /* expected stream ID */);
       // ... other assertions ...
     }

     const auto& ack_frames = framer.ack_frames();
     // ... inspect ACK frames ...
   }

   }  // namespace test
   }  // namespace quic
   ```

In this debugging scenario, the developer uses `SimpleQuicFramer` to gain insight into the structure of the captured QUIC packets, helping them pinpoint potential issues in the QUIC implementation or the specific website's behavior.

In summary, `simple_quic_framer.cc` is a valuable testing tool for developers working on the QUIC implementation within Chromium. It provides a simplified way to parse and inspect QUIC packets, ensuring the robustness and correctness of the underlying networking stack that JavaScript applications rely on.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/simple_quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/simple_quic_framer.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_types.h"

namespace quic {
namespace test {

class SimpleFramerVisitor : public QuicFramerVisitorInterface {
 public:
  SimpleFramerVisitor() : error_(QUIC_NO_ERROR) {}
  SimpleFramerVisitor(const SimpleFramerVisitor&) = delete;
  SimpleFramerVisitor& operator=(const SimpleFramerVisitor&) = delete;

  ~SimpleFramerVisitor() override {}

  void OnError(QuicFramer* framer) override { error_ = framer->error(); }

  bool OnProtocolVersionMismatch(ParsedQuicVersion /*version*/) override {
    return false;
  }

  void OnPacket() override {}
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& packet) override {
    version_negotiation_packet_ =
        std::make_unique<QuicVersionNegotiationPacket>((packet));
  }

  void OnRetryPacket(QuicConnectionId /*original_connection_id*/,
                     QuicConnectionId /*new_connection_id*/,
                     absl::string_view /*retry_token*/,
                     absl::string_view /*retry_integrity_tag*/,
                     absl::string_view /*retry_without_tag*/) override {}

  bool OnUnauthenticatedPublicHeader(
      const QuicPacketHeader& /*header*/) override {
    return true;
  }
  bool OnUnauthenticatedHeader(const QuicPacketHeader& /*header*/) override {
    return true;
  }
  void OnDecryptedPacket(size_t /*length*/, EncryptionLevel level) override {
    last_decrypted_level_ = level;
  }
  bool OnPacketHeader(const QuicPacketHeader& header) override {
    has_header_ = true;
    header_ = header;
    return true;
  }

  void OnCoalescedPacket(const QuicEncryptedPacket& packet) override {
    coalesced_packet_ = packet.Clone();
  }

  void OnUndecryptablePacket(const QuicEncryptedPacket& /*packet*/,
                             EncryptionLevel /*decryption_level*/,
                             bool /*has_decryption_key*/) override {}

  bool OnStreamFrame(const QuicStreamFrame& frame) override {
    // Save a copy of the data so it is valid after the packet is processed.
    std::string* string_data =
        new std::string(frame.data_buffer, frame.data_length);
    stream_data_.push_back(absl::WrapUnique(string_data));
    // TODO(ianswett): A pointer isn't necessary with emplace_back.
    stream_frames_.push_back(std::make_unique<QuicStreamFrame>(
        frame.stream_id, frame.fin, frame.offset,
        absl::string_view(*string_data)));
    return true;
  }

  bool OnCryptoFrame(const QuicCryptoFrame& frame) override {
    // Save a copy of the data so it is valid after the packet is processed.
    std::string* string_data =
        new std::string(frame.data_buffer, frame.data_length);
    crypto_data_.push_back(absl::WrapUnique(string_data));
    crypto_frames_.push_back(std::make_unique<QuicCryptoFrame>(
        frame.level, frame.offset, absl::string_view(*string_data)));
    return true;
  }

  bool OnAckFrameStart(QuicPacketNumber largest_acked,
                       QuicTime::Delta ack_delay_time) override {
    QuicAckFrame ack_frame;
    ack_frame.largest_acked = largest_acked;
    ack_frame.ack_delay_time = ack_delay_time;
    ack_frames_.push_back(ack_frame);
    return true;
  }

  bool OnAckRange(QuicPacketNumber start, QuicPacketNumber end) override {
    QUICHE_DCHECK(!ack_frames_.empty());
    ack_frames_[ack_frames_.size() - 1].packets.AddRange(start, end);
    return true;
  }

  bool OnAckTimestamp(QuicPacketNumber /*packet_number*/,
                      QuicTime /*timestamp*/) override {
    return true;
  }

  bool OnAckFrameEnd(
      QuicPacketNumber /*start*/,
      const std::optional<QuicEcnCounts>& /*ecn_counts*/) override {
    return true;
  }

  bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override {
    stop_waiting_frames_.push_back(frame);
    return true;
  }

  bool OnPaddingFrame(const QuicPaddingFrame& frame) override {
    padding_frames_.push_back(frame);
    return true;
  }

  bool OnPingFrame(const QuicPingFrame& frame) override {
    ping_frames_.push_back(frame);
    return true;
  }

  bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override {
    rst_stream_frames_.push_back(frame);
    return true;
  }

  bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override {
    connection_close_frames_.push_back(frame);
    return true;
  }

  bool OnNewConnectionIdFrame(const QuicNewConnectionIdFrame& frame) override {
    new_connection_id_frames_.push_back(frame);
    return true;
  }

  bool OnRetireConnectionIdFrame(
      const QuicRetireConnectionIdFrame& frame) override {
    retire_connection_id_frames_.push_back(frame);
    return true;
  }

  bool OnNewTokenFrame(const QuicNewTokenFrame& frame) override {
    new_token_frames_.push_back(frame);
    return true;
  }

  bool OnStopSendingFrame(const QuicStopSendingFrame& frame) override {
    stop_sending_frames_.push_back(frame);
    return true;
  }

  bool OnPathChallengeFrame(const QuicPathChallengeFrame& frame) override {
    path_challenge_frames_.push_back(frame);
    return true;
  }

  bool OnPathResponseFrame(const QuicPathResponseFrame& frame) override {
    path_response_frames_.push_back(frame);
    return true;
  }

  bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override {
    goaway_frames_.push_back(frame);
    return true;
  }
  bool OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) override {
    max_streams_frames_.push_back(frame);
    return true;
  }

  bool OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) override {
    streams_blocked_frames_.push_back(frame);
    return true;
  }

  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override {
    window_update_frames_.push_back(frame);
    return true;
  }

  bool OnBlockedFrame(const QuicBlockedFrame& frame) override {
    blocked_frames_.push_back(frame);
    return true;
  }

  bool OnMessageFrame(const QuicMessageFrame& frame) override {
    message_frames_.emplace_back(frame.data, frame.message_length);
    return true;
  }

  bool OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) override {
    handshake_done_frames_.push_back(frame);
    return true;
  }

  bool OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) override {
    ack_frequency_frames_.push_back(frame);
    return true;
  }

  bool OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) override {
    reset_stream_at_frames_.push_back(frame);
    return true;
  }

  void OnPacketComplete() override {}

  bool IsValidStatelessResetToken(
      const StatelessResetToken& /*token*/) const override {
    return false;
  }

  void OnAuthenticatedIetfStatelessResetPacket(
      const QuicIetfStatelessResetPacket& packet) override {
    stateless_reset_packet_ =
        std::make_unique<QuicIetfStatelessResetPacket>(packet);
  }

  void OnKeyUpdate(KeyUpdateReason /*reason*/) override {}
  void OnDecryptedFirstPacketInKeyPhase() override {}
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override {
    return nullptr;
  }
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
    return nullptr;
  }

  const QuicPacketHeader& header() const { return header_; }
  const std::vector<QuicAckFrame>& ack_frames() const { return ack_frames_; }
  const std::vector<QuicConnectionCloseFrame>& connection_close_frames() const {
    return connection_close_frames_;
  }

  const std::vector<QuicGoAwayFrame>& goaway_frames() const {
    return goaway_frames_;
  }
  const std::vector<QuicMaxStreamsFrame>& max_streams_frames() const {
    return max_streams_frames_;
  }
  const std::vector<QuicStreamsBlockedFrame>& streams_blocked_frames() const {
    return streams_blocked_frames_;
  }
  const std::vector<QuicRstStreamFrame>& rst_stream_frames() const {
    return rst_stream_frames_;
  }
  const std::vector<std::unique_ptr<QuicStreamFrame>>& stream_frames() const {
    return stream_frames_;
  }
  const std::vector<std::unique_ptr<QuicCryptoFrame>>& crypto_frames() const {
    return crypto_frames_;
  }
  const std::vector<QuicStopWaitingFrame>& stop_waiting_frames() const {
    return stop_waiting_frames_;
  }
  const std::vector<QuicPingFrame>& ping_frames() const { return ping_frames_; }
  const std::vector<QuicMessageFrame>& message_frames() const {
    return message_frames_;
  }
  const std::vector<QuicWindowUpdateFrame>& window_update_frames() const {
    return window_update_frames_;
  }
  const std::vector<QuicPaddingFrame>& padding_frames() const {
    return padding_frames_;
  }
  const std::vector<QuicPathChallengeFrame>& path_challenge_frames() const {
    return path_challenge_frames_;
  }
  const std::vector<QuicPathResponseFrame>& path_response_frames() const {
    return path_response_frames_;
  }
  const QuicVersionNegotiationPacket* version_negotiation_packet() const {
    return version_negotiation_packet_.get();
  }
  EncryptionLevel last_decrypted_level() const { return last_decrypted_level_; }
  const QuicEncryptedPacket* coalesced_packet() const {
    return coalesced_packet_.get();
  }

 private:
  QuicErrorCode error_;
  bool has_header_;
  QuicPacketHeader header_;
  std::unique_ptr<QuicVersionNegotiationPacket> version_negotiation_packet_;
  std::unique_ptr<QuicIetfStatelessResetPacket> stateless_reset_packet_;
  std::vector<QuicAckFrame> ack_frames_;
  std::vector<QuicStopWaitingFrame> stop_waiting_frames_;
  std::vector<QuicPaddingFrame> padding_frames_;
  std::vector<QuicPingFrame> ping_frames_;
  std::vector<std::unique_ptr<QuicStreamFrame>> stream_frames_;
  std::vector<std::unique_ptr<QuicCryptoFrame>> crypto_frames_;
  std::vector<QuicRstStreamFrame> rst_stream_frames_;
  std::vector<QuicGoAwayFrame> goaway_frames_;
  std::vector<QuicStreamsBlockedFrame> streams_blocked_frames_;
  std::vector<QuicMaxStreamsFrame> max_streams_frames_;
  std::vector<QuicConnectionCloseFrame> connection_close_frames_;
  std::vector<QuicStopSendingFrame> stop_sending_frames_;
  std::vector<QuicPathChallengeFrame> path_challenge_frames_;
  std::vector<QuicPathResponseFrame> path_response_frames_;
  std::vector<QuicWindowUpdateFrame> window_update_frames_;
  std::vector<QuicBlockedFrame> blocked_frames_;
  std::vector<QuicNewConnectionIdFrame> new_connection_id_frames_;
  std::vector<QuicRetireConnectionIdFrame> retire_connection_id_frames_;
  std::vector<QuicNewTokenFrame> new_token_frames_;
  std::vector<QuicMessageFrame> message_frames_;
  std::vector<QuicHandshakeDoneFrame> handshake_done_frames_;
  std::vector<QuicAckFrequencyFrame> ack_frequency_frames_;
  std::vector<QuicResetStreamAtFrame> reset_stream_at_frames_;
  std::vector<std::unique_ptr<std::string>> stream_data_;
  std::vector<std::unique_ptr<std::string>> crypto_data_;
  EncryptionLevel last_decrypted_level_;
  std::unique_ptr<QuicEncryptedPacket> coalesced_packet_;
};

SimpleQuicFramer::SimpleQuicFramer()
    : framer_(AllSupportedVersions(), QuicTime::Zero(), Perspective::IS_SERVER,
              kQuicDefaultConnectionIdLength) {}

SimpleQuicFramer::SimpleQuicFramer(
    const ParsedQuicVersionVector& supported_versions)
    : framer_(supported_versions, QuicTime::Zero(), Perspective::IS_SERVER,
              kQuicDefaultConnectionIdLength) {}

SimpleQuicFramer::SimpleQuicFramer(
    const ParsedQuicVersionVector& supported_versions, Perspective perspective)
    : framer_(supported_versions, QuicTime::Zero(), perspective,
              kQuicDefaultConnectionIdLength) {}

SimpleQuicFramer::~SimpleQuicFramer() {}

bool SimpleQuicFramer::ProcessPacket(const QuicEncryptedPacket& packet) {
  visitor_ = std::make_unique<SimpleFramerVisitor>();
  framer_.set_visitor(visitor_.get());
  return framer_.ProcessPacket(packet);
}

void SimpleQuicFramer::Reset() {
  visitor_ = std::make_unique<SimpleFramerVisitor>();
}

const QuicPacketHeader& SimpleQuicFramer::header() const {
  return visitor_->header();
}

const QuicVersionNegotiationPacket*
SimpleQuicFramer::version_negotiation_packet() const {
  return visitor_->version_negotiation_packet();
}

EncryptionLevel SimpleQuicFramer::last_decrypted_level() const {
  return visitor_->last_decrypted_level();
}

QuicFramer* SimpleQuicFramer::framer() { return &framer_; }

size_t SimpleQuicFramer::num_frames() const {
  return ack_frames().size() + goaway_frames().size() +
         rst_stream_frames().size() + stop_waiting_frames().size() +
         path_challenge_frames().size() + path_response_frames().size() +
         stream_frames().size() + ping_frames().size() +
         connection_close_frames().size() + padding_frames().size() +
         crypto_frames().size();
}

const std::vector<QuicAckFrame>& SimpleQuicFramer::ack_frames() const {
  return visitor_->ack_frames();
}

const std::vector<QuicStopWaitingFrame>& SimpleQuicFramer::stop_waiting_frames()
    const {
  return visitor_->stop_waiting_frames();
}

const std::vector<QuicPathChallengeFrame>&
SimpleQuicFramer::path_challenge_frames() const {
  return visitor_->path_challenge_frames();
}
const std::vector<QuicPathResponseFrame>&
SimpleQuicFramer::path_response_frames() const {
  return visitor_->path_response_frames();
}

const std::vector<QuicPingFrame>& SimpleQuicFramer::ping_frames() const {
  return visitor_->ping_frames();
}

const std::vector<QuicMessageFrame>& SimpleQuicFramer::message_frames() const {
  return visitor_->message_frames();
}

const std::vector<QuicWindowUpdateFrame>&
SimpleQuicFramer::window_update_frames() const {
  return visitor_->window_update_frames();
}

const std::vector<std::unique_ptr<QuicStreamFrame>>&
SimpleQuicFramer::stream_frames() const {
  return visitor_->stream_frames();
}

const std::vector<std::unique_ptr<QuicCryptoFrame>>&
SimpleQuicFramer::crypto_frames() const {
  return visitor_->crypto_frames();
}

const std::vector<QuicRstStreamFrame>& SimpleQuicFramer::rst_stream_frames()
    const {
  return visitor_->rst_stream_frames();
}

const std::vector<QuicGoAwayFrame>& SimpleQuicFramer::goaway_frames() const {
  return visitor_->goaway_frames();
}

const std::vector<QuicConnectionCloseFrame>&
SimpleQuicFramer::connection_close_frames() const {
  return visitor_->connection_close_frames();
}

const std::vector<QuicPaddingFrame>& SimpleQuicFramer::padding_frames() const {
  return visitor_->padding_frames();
}

const QuicEncryptedPacket* SimpleQuicFramer::coalesced_packet() const {
  return visitor_->coalesced_packet();
}

}  // namespace test
}  // namespace quic

"""

```