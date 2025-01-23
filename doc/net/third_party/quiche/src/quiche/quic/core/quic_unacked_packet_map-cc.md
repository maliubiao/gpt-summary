Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `quic_unacked_packet_map.cc` in the Chromium QUIC stack. The request also specifically asks for connections to JavaScript, logical inferences with examples, common usage errors, and debugging context.

**2. Initial Code Scan and Keyword Identification:**

I would first scan the code for prominent keywords and structures. Things that jump out:

* **`QuicUnackedPacketMap`:**  This is the central class. The name strongly suggests it's managing packets that haven't been acknowledged.
* **`AddSentPacket`, `AddDispatcherSentPacket`:**  Methods for adding packets.
* **`RemoveObsoletePackets`, `RemoveRetransmittability`, `RemoveFromInFlight`:** Methods for managing the lifecycle of unacknowledged packets.
* **`largest_sent_packet_`, `least_unacked_`:**  Variables related to packet numbering and tracking.
* **`bytes_in_flight_`, `packets_in_flight_`:** Variables related to congestion control and network state.
* **`retransmittable_frames`:**  A member within the `QuicTransmissionInfo` structure, indicating data that might need resending.
* **`NotifyFramesAcked`, `NotifyFramesLost`, `RetransmitFrames`:** Methods related to informing other parts of the QUIC stack about packet acknowledgments and losses.
* **`SessionNotifierInterface`:**  A delegate pattern for interacting with the broader QUIC session.
* **`EncryptionLevel`, `PacketNumberSpace`:**  Concepts related to the different phases and logical separations within the QUIC connection.

**3. Inferring Core Functionality:**

Based on the keywords, I can start forming a picture:

* This class keeps track of packets sent but not yet confirmed as received (unacknowledged).
* It stores metadata about each unacknowledged packet, such as its size, send time, whether it contains retransmittable data, and its encryption level.
* It's used for crucial QUIC features like:
    * **Reliability:**  Knowing which packets need to be retransmitted if lost.
    * **Congestion Control:**  Tracking the number of packets in flight to avoid overwhelming the network.
    * **Round-Trip Time (RTT) Measurement:** Identifying suitable packets for calculating network latency.
    * **Packet Numbering and Ordering:**  Maintaining the sequence of sent packets.
    * **Encryption Context:**  Handling different encryption levels during the handshake and data transfer.

**4. Addressing Specific Questions:**

* **Functionality Listing:** I'd go through the code method by method, summarizing the purpose of each. I'd group related functionalities together (adding packets, removing packets, querying state, etc.).

* **Relationship to JavaScript:**  This is where I need to bridge the gap between low-level C++ and higher-level JavaScript. The key connection is the *result* of this C++ code. The QUIC protocol enables faster and more reliable network communication for web browsers and other applications. JavaScript code running in a browser indirectly benefits from `QuicUnackedPacketMap` because it contributes to a better user experience when accessing websites and web services. I'd provide examples like faster page loads, smoother video streaming, etc. It's important to emphasize the *indirect* nature of the relationship. JavaScript doesn't directly call into this C++ code.

* **Logical Inference:** Here, I'd look for conditional logic and how data is transformed. The examples with `AddSentPacket` and acknowledgment scenarios are good choices. I need to create concrete inputs (e.g., sending a packet with specific flags) and describe the expected changes to the internal state of the `QuicUnackedPacketMap`.

* **Common Usage Errors:** This requires thinking about how a developer might misuse this class or the broader QUIC API. Since this is a core component of the network stack, direct misuse is less likely. Instead, errors would arise from incorrect integration with other parts of the QUIC implementation. Examples like failing to notify the `QuicUnackedPacketMap` about sent packets or misinterpreting its state are relevant.

* **Debugging Context:**  This involves tracing the execution flow that leads to this code. Starting from a user action (e.g., typing a URL) and working down through the browser's network stack to the QUIC implementation is necessary. Highlighting key events and function calls helps illustrate the path.

**5. Refinement and Organization:**

After drafting the initial answers, I'd review and refine them for clarity, accuracy, and completeness. I'd organize the information logically using headings and bullet points to make it easier to read and understand. I would also double-check the code comments for any insights they provide. For example, the comments mentioning specific QUIC bugs (like `quic_bug_10518_1`) can be useful context.

**Self-Correction/Refinement Example during the process:**

Initially, I might focus too much on the technical details of each method. However, the user's request also asks for the "why" and the bigger picture, especially regarding JavaScript. So, I'd need to step back and ensure I'm explaining the high-level benefits and the indirect connection to JavaScript effectively. Similarly, for "common usage errors," I would initially think of low-level C++ mistakes, but I'd realize that errors in *using* the QUIC API (of which this is a part) are more relevant to the request. I'd then adjust my examples accordingly.
The C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_unacked_packet_map.cc` within the Chromium network stack defines the `QuicUnackedPacketMap` class. This class plays a crucial role in managing the state of packets that have been sent by a QUIC connection but have not yet been acknowledged by the receiver.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Tracking Unacknowledged Packets:** The primary function is to store information about every packet sent by the QUIC sender until it receives an acknowledgment (ACK) from the receiver. This information includes:
    * **Packet Number:**  A unique identifier for the packet.
    * **Transmission Type:**  Indicates the reason for transmission (e.g., initial transmission, retransmission).
    * **Sent Time:** The timestamp when the packet was sent.
    * **Bytes Sent:** The size of the packet.
    * **Encryption Level:** The encryption used for the packet.
    * **Retransmittable Frames:** A list of frames within the packet that need to be retransmitted if the packet is lost. This includes STREAM frames (carrying user data), CRYPTO frames (for handshake), etc.
    * **In-flight Status:** Whether the packet is currently considered "in flight" for congestion control purposes.
    * **RTT Measurement Eligibility:** Whether the packet can be used to measure the round-trip time.
    * **ECN Codepoint:** The Explicit Congestion Notification marking on the packet.

2. **Managing Retransmission:** The map is crucial for determining which packets need to be retransmitted. If an ACK indicates that a packet was lost (either implicitly by acknowledging later packets or explicitly via NACK), the `QuicUnackedPacketMap` identifies the lost packet and its retransmittable frames.

3. **Congestion Control:** The map tracks the number of bytes and packets currently "in flight." This information is used by the congestion control algorithm to determine the rate at which new packets can be sent, preventing network congestion.

4. **Round-Trip Time (RTT) Estimation:** The map helps identify packets suitable for RTT measurement. When an ACK arrives, the time difference between the send time of a designated packet and the arrival time of the ACK contributes to the RTT estimate.

5. **Packet Number Space Management:**  For newer QUIC versions, the map supports multiple packet number spaces (Initial, Handshake, Application). It tracks unacknowledged packets within each space separately.

6. **Garbage Collection:**  The map efficiently removes information about packets that are no longer needed, either because they have been acknowledged or because they are considered "useless" (e.g., the data has been retransmitted sufficiently).

7. **Notifying Session on Acks and Losses:** It interacts with a `SessionNotifierInterface` to inform the higher-level QUIC session about acknowledged and lost frames within the packets.

**Relationship to JavaScript Functionality:**

The `QuicUnackedPacketMap` is a low-level C++ component of the Chrome browser's network stack. It doesn't have a direct, synchronous interaction with JavaScript code running in web pages. However, its functionality is fundamental to enabling reliable and efficient network communication for web applications built with JavaScript.

Here's how it indirectly relates:

* **Faster Page Loads:** By ensuring reliable delivery of HTTP/3 data (which uses QUIC), this class contributes to faster loading of web pages accessed by JavaScript code.
* **Smoother Streaming:** For web applications using JavaScript for streaming video or audio, the reliable data transfer provided by QUIC (and managed by this class) leads to a smoother, less error-prone experience.
* **Real-time Communication:**  For web applications using WebSockets or other real-time protocols over QUIC, `QuicUnackedPacketMap`'s reliability mechanisms are crucial for consistent and low-latency communication.
* **Web APIs relying on Network:**  Any JavaScript code using browser APIs that make network requests (e.g., `fetch`, `XMLHttpRequest`, WebSockets) benefits from the underlying QUIC implementation and the correct functioning of `QuicUnackedPacketMap`.

**Example:**

Imagine a JavaScript application using `fetch` to download a large image from a server over HTTPS/3 (which uses QUIC).

1. The `fetch` call in JavaScript initiates the request.
2. The browser's network stack formulates HTTP/3 packets to send the request.
3. These packets are sent, and for each packet containing retransmittable data (like the image data itself), an entry is added to the `QuicUnackedPacketMap`.
4. If one of these packets gets lost in transit, the receiver doesn't send an ACK for it.
5. The sender, based on the `QuicUnackedPacketMap` and the lack of an ACK within a timeout period, determines that the packet needs to be retransmitted.
6. The lost packet (or its retransmittable frames) is resent.
7. Eventually, the receiver ACKs the retransmitted packet.
8. The `QuicUnackedPacketMap` entry for that packet is removed.
9. The browser can then reconstruct the complete image and provide it to the JavaScript application.

**Logical Inference with Assumptions and Outputs:**

**Scenario:** A QUIC sender sends two packets with packet numbers 1 and 2. Packet 1 contains a STREAM frame with some data, and packet 2 is a PING frame.

**Assumptions:**

* `least_unacked_` is initially 1.
* Both packets are considered in-flight.

**Input:**

1. **Sending Packet 1:** `AddSentPacket` is called with information about packet 1 (STREAM frame).
2. **Sending Packet 2:** `AddSentPacket` is called with information about packet 2 (PING frame).
3. **Receiving ACK for Packet 1:** The receiver sends an ACK acknowledging packet 1.

**Internal State Changes:**

* **After sending Packet 1:**
    * `unacked_packets_` will contain an entry for packet 1.
    * The entry will have `retransmittable_frames` containing the STREAM frame.
    * `bytes_in_flight_` will increase by the size of packet 1.
    * `packets_in_flight_` will be 1.
* **After sending Packet 2:**
    * `unacked_packets_` will contain entries for both packets 1 and 2.
    * The entry for packet 2 will have `retransmittable_frames` (likely empty or containing non-retransmittable frames depending on implementation details for PING).
    * `bytes_in_flight_` will increase by the size of packet 2.
    * `packets_in_flight_` will be 2.
* **After receiving ACK for Packet 1:**
    * `NotifyFramesAcked` will be called, informing the session about the acknowledged STREAM frame.
    * The entry for packet 1 in `unacked_packets_` will be marked as no longer needed for retransmission (or potentially removed if garbage collection runs).
    * `bytes_in_flight_` will decrease by the size of packet 1.
    * `packets_in_flight_` will decrease to 1.
    * If garbage collection runs, and packet 1 is no longer useful, it will be removed, and `least_unacked_` might be updated.

**User and Programming Common Usage Errors:**

1. **Incorrectly Determining Retransmittability:**  A common error in a QUIC implementation (not necessarily by a direct user of this class) would be to incorrectly mark certain frames as non-retransmittable when they should be. This would lead to data loss if the packet containing those frames is lost.

2. **Race Conditions in Updating the Map:**  Since network events are asynchronous, care must be taken to avoid race conditions when updating the `QuicUnackedPacketMap` from different parts of the QUIC implementation (e.g., sender and ACK processing). Improper locking or synchronization could lead to inconsistent state.

3. **Memory Leaks:** If packets are not properly removed from the map after being acknowledged or deemed useless, it could lead to a memory leak, especially in long-lived connections.

4. **Incorrectly Calculating Bytes in Flight:**  Errors in adding or subtracting the size of packets to the `bytes_in_flight_` counter can disrupt the congestion control algorithm, potentially leading to either excessive sending (congestion) or underutilization of the network.

**User Operation Steps to Reach This Code (Debugging Context):**

Let's trace how a user action might lead to the execution of code within `quic_unacked_packet_map.cc`:

1. **User types a URL in the Chrome address bar and hits Enter.**
2. **DNS Lookup:** Chrome performs a DNS lookup to find the IP address of the server.
3. **QUIC Connection Establishment (if applicable):**
    * Chrome checks if a QUIC connection to the server already exists. If not, it attempts to establish one.
    * This involves a handshake process where CRYPTO frames are exchanged. Packets containing these frames are tracked in the `QuicUnackedPacketMap`.
4. **Sending the HTTP Request:**
    * Once the QUIC connection is established, Chrome formulates an HTTP/3 GET request.
    * This request is broken down into STREAM frames and encapsulated into QUIC packets.
    * For each packet sent, `QuicUnackedPacketMap::AddSentPacket` is called to record its details, including the STREAM frame containing parts of the HTTP request.
5. **Data Transfer:**
    * The server responds with HTTP/3 data (e.g., HTML, CSS, JavaScript, images).
    * The server's QUIC implementation also uses a `QuicUnackedPacketMap` to track its sent packets.
    * When Chrome receives packets, it sends ACK frames back to the server.
6. **ACK Processing:**
    * When Chrome's QUIC implementation receives an ACK, the `QuicUnackedPacketMap` is updated.
    * `QuicUnackedPacketMap::NotifyFramesAcked` is called to inform the session about the successful delivery of data.
    * If a packet was acknowledged, its entry is eventually removed from the map.
7. **Potential Packet Loss and Retransmission:**
    * If a packet gets lost during the transfer (either the request or the response), Chrome's `QuicUnackedPacketMap` will help detect the loss.
    * After a timeout, `QuicUnackedPacketMap` will identify the lost packet.
    * `QuicUnackedPacketMap::RetransmitFrames` will be called to initiate the retransmission of the lost data.
8. **Connection Closure:**
    * When the page is fully loaded or the user navigates away, the QUIC connection might be closed.
    * Packets related to connection closure are also tracked by `QuicUnackedPacketMap` until acknowledged.

**In summary, `quic_unacked_packet_map.cc` is a foundational component of the QUIC implementation, responsible for ensuring reliable and efficient data delivery. While JavaScript developers don't interact with it directly, its correct functioning is essential for the performance and reliability of web applications.**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_unacked_packet_map.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_unacked_packet_map.h"

#include <cstddef>
#include <limits>
#include <type_traits>
#include <utility>

#include "absl/container/inlined_vector.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"

namespace quic {

namespace {
bool WillStreamFrameLengthSumWrapAround(QuicPacketLength lhs,
                                        QuicPacketLength rhs) {
  static_assert(
      std::is_unsigned<QuicPacketLength>::value,
      "This function assumes QuicPacketLength is an unsigned integer type.");
  return std::numeric_limits<QuicPacketLength>::max() - lhs < rhs;
}

enum QuicFrameTypeBitfield : uint32_t {
  kInvalidFrameBitfield = 0,
  kPaddingFrameBitfield = 1,
  kRstStreamFrameBitfield = 1 << 1,
  kConnectionCloseFrameBitfield = 1 << 2,
  kGoawayFrameBitfield = 1 << 3,
  kWindowUpdateFrameBitfield = 1 << 4,
  kBlockedFrameBitfield = 1 << 5,
  kStopWaitingFrameBitfield = 1 << 6,
  kPingFrameBitfield = 1 << 7,
  kCryptoFrameBitfield = 1 << 8,
  kHandshakeDoneFrameBitfield = 1 << 9,
  kStreamFrameBitfield = 1 << 10,
  kAckFrameBitfield = 1 << 11,
  kMtuDiscoveryFrameBitfield = 1 << 12,
  kNewConnectionIdFrameBitfield = 1 << 13,
  kMaxStreamsFrameBitfield = 1 << 14,
  kStreamsBlockedFrameBitfield = 1 << 15,
  kPathResponseFrameBitfield = 1 << 16,
  kPathChallengeFrameBitfield = 1 << 17,
  kStopSendingFrameBitfield = 1 << 18,
  kMessageFrameBitfield = 1 << 19,
  kNewTokenFrameBitfield = 1 << 20,
  kRetireConnectionIdFrameBitfield = 1 << 21,
  kAckFrequencyFrameBitfield = 1 << 22,
  kResetStreamAtFrameBitfield = 1 << 23,
};

QuicFrameTypeBitfield GetFrameTypeBitfield(QuicFrameType type) {
  switch (type) {
    case PADDING_FRAME:
      return kPaddingFrameBitfield;
    case RST_STREAM_FRAME:
      return kRstStreamFrameBitfield;
    case CONNECTION_CLOSE_FRAME:
      return kConnectionCloseFrameBitfield;
    case GOAWAY_FRAME:
      return kGoawayFrameBitfield;
    case WINDOW_UPDATE_FRAME:
      return kWindowUpdateFrameBitfield;
    case BLOCKED_FRAME:
      return kBlockedFrameBitfield;
    case STOP_WAITING_FRAME:
      return kStopWaitingFrameBitfield;
    case PING_FRAME:
      return kPingFrameBitfield;
    case CRYPTO_FRAME:
      return kCryptoFrameBitfield;
    case HANDSHAKE_DONE_FRAME:
      return kHandshakeDoneFrameBitfield;
    case STREAM_FRAME:
      return kStreamFrameBitfield;
    case ACK_FRAME:
      return kAckFrameBitfield;
    case MTU_DISCOVERY_FRAME:
      return kMtuDiscoveryFrameBitfield;
    case NEW_CONNECTION_ID_FRAME:
      return kNewConnectionIdFrameBitfield;
    case MAX_STREAMS_FRAME:
      return kMaxStreamsFrameBitfield;
    case STREAMS_BLOCKED_FRAME:
      return kStreamsBlockedFrameBitfield;
    case PATH_RESPONSE_FRAME:
      return kPathResponseFrameBitfield;
    case PATH_CHALLENGE_FRAME:
      return kPathChallengeFrameBitfield;
    case STOP_SENDING_FRAME:
      return kStopSendingFrameBitfield;
    case MESSAGE_FRAME:
      return kMessageFrameBitfield;
    case NEW_TOKEN_FRAME:
      return kNewTokenFrameBitfield;
    case RETIRE_CONNECTION_ID_FRAME:
      return kRetireConnectionIdFrameBitfield;
    case ACK_FREQUENCY_FRAME:
      return kAckFrequencyFrameBitfield;
    case RESET_STREAM_AT_FRAME:
      return kResetStreamAtFrameBitfield;
    case NUM_FRAME_TYPES:
      QUIC_BUG(quic_bug_10518_1) << "Unexpected frame type";
      return kInvalidFrameBitfield;
  }
  QUIC_BUG(quic_bug_10518_2) << "Unexpected frame type";
  return kInvalidFrameBitfield;
}

}  // namespace

QuicUnackedPacketMap::QuicUnackedPacketMap(Perspective perspective)
    : perspective_(perspective),
      least_unacked_(FirstSendingPacketNumber()),
      bytes_in_flight_(0),
      bytes_in_flight_per_packet_number_space_{0, 0, 0},
      packets_in_flight_(0),
      last_inflight_packet_sent_time_(QuicTime::Zero()),
      last_inflight_packets_sent_time_{
          {QuicTime::Zero()}, {QuicTime::Zero()}, {QuicTime::Zero()}},
      last_crypto_packet_sent_time_(QuicTime::Zero()),
      session_notifier_(nullptr),
      supports_multiple_packet_number_spaces_(false) {}

QuicUnackedPacketMap::~QuicUnackedPacketMap() {
  for (QuicTransmissionInfo& transmission_info : unacked_packets_) {
    DeleteFrames(&(transmission_info.retransmittable_frames));
  }
}

const QuicTransmissionInfo& QuicUnackedPacketMap::AddDispatcherSentPacket(
    const DispatcherSentPacket& packet) {
  QuicPacketNumber packet_number = packet.packet_number;
  QUICHE_DCHECK_EQ(least_unacked_, FirstSendingPacketNumber());
  QUIC_BUG_IF(quic_unacked_map_dispatcher_packet_num_too_small,
              largest_sent_packet_.IsInitialized() &&
                  largest_sent_packet_ >= packet_number)
      << "largest_sent_packet_: " << largest_sent_packet_
      << ", packet_number: " << packet_number;
  QUICHE_DCHECK_GE(packet_number, least_unacked_ + unacked_packets_.size());
  while (least_unacked_ + unacked_packets_.size() < packet_number) {
    unacked_packets_.push_back(QuicTransmissionInfo());
    unacked_packets_.back().state = NEVER_SENT;
  }

  QuicTransmissionInfo& info =
      unacked_packets_.emplace_back(ENCRYPTION_INITIAL, NOT_RETRANSMISSION,
                                    packet.sent_time, packet.bytes_sent,
                                    /*has_crypto_handshake=*/false,
                                    /*has_ack_frequency=*/false, ECN_NOT_ECT);
  QUICHE_DCHECK(!info.in_flight);
  info.state = NOT_CONTRIBUTING_RTT;
  info.largest_acked = packet.largest_acked;
  largest_sent_largest_acked_.UpdateMax(packet.largest_acked);
  largest_sent_packet_ = packet_number;
  return info;
}

void QuicUnackedPacketMap::AddSentPacket(SerializedPacket* mutable_packet,
                                         TransmissionType transmission_type,
                                         QuicTime sent_time, bool set_in_flight,
                                         bool measure_rtt,
                                         QuicEcnCodepoint ecn_codepoint) {
  const SerializedPacket& packet = *mutable_packet;
  QuicPacketNumber packet_number = packet.packet_number;
  QuicPacketLength bytes_sent = packet.encrypted_length;
  QUIC_BUG_IF(quic_bug_12645_1, largest_sent_packet_.IsInitialized() &&
                                    largest_sent_packet_ >= packet_number)
      << "largest_sent_packet_: " << largest_sent_packet_
      << ", packet_number: " << packet_number;
  QUICHE_DCHECK_GE(packet_number, least_unacked_ + unacked_packets_.size());
  while (least_unacked_ + unacked_packets_.size() < packet_number) {
    unacked_packets_.push_back(QuicTransmissionInfo());
    unacked_packets_.back().state = NEVER_SENT;
  }

  const bool has_crypto_handshake = packet.has_crypto_handshake == IS_HANDSHAKE;
  QuicTransmissionInfo info(packet.encryption_level, transmission_type,
                            sent_time, bytes_sent, has_crypto_handshake,
                            packet.has_ack_frequency, ecn_codepoint);
  info.largest_acked = packet.largest_acked;
  largest_sent_largest_acked_.UpdateMax(packet.largest_acked);

  if (!measure_rtt) {
    QUIC_BUG_IF(quic_bug_12645_2, set_in_flight)
        << "Packet " << mutable_packet->packet_number << ", transmission type "
        << TransmissionTypeToString(mutable_packet->transmission_type)
        << ", retransmittable frames: "
        << QuicFramesToString(mutable_packet->retransmittable_frames)
        << ", nonretransmittable_frames: "
        << QuicFramesToString(mutable_packet->nonretransmittable_frames);
    info.state = NOT_CONTRIBUTING_RTT;
  }

  largest_sent_packet_ = packet_number;
  if (set_in_flight) {
    const PacketNumberSpace packet_number_space =
        GetPacketNumberSpace(info.encryption_level);
    bytes_in_flight_ += bytes_sent;
    bytes_in_flight_per_packet_number_space_[packet_number_space] += bytes_sent;
    ++packets_in_flight_;
    info.in_flight = true;
    largest_sent_retransmittable_packets_[packet_number_space] = packet_number;
    last_inflight_packet_sent_time_ = sent_time;
    last_inflight_packets_sent_time_[packet_number_space] = sent_time;
  }
  unacked_packets_.push_back(std::move(info));
  // Swap the retransmittable frames to avoid allocations.
  // TODO(ianswett): Could use emplace_back when Chromium can.
  if (has_crypto_handshake) {
    last_crypto_packet_sent_time_ = sent_time;
  }

  mutable_packet->retransmittable_frames.swap(
      unacked_packets_.back().retransmittable_frames);
}

void QuicUnackedPacketMap::RemoveObsoletePackets() {
  while (!unacked_packets_.empty()) {
    if (!IsPacketUseless(least_unacked_, unacked_packets_.front())) {
      break;
    }
    DeleteFrames(&unacked_packets_.front().retransmittable_frames);
    unacked_packets_.pop_front();
    ++least_unacked_;
  }
}

bool QuicUnackedPacketMap::HasRetransmittableFrames(
    QuicPacketNumber packet_number) const {
  QUICHE_DCHECK_GE(packet_number, least_unacked_);
  QUICHE_DCHECK_LT(packet_number, least_unacked_ + unacked_packets_.size());
  return HasRetransmittableFrames(
      unacked_packets_[packet_number - least_unacked_]);
}

bool QuicUnackedPacketMap::HasRetransmittableFrames(
    const QuicTransmissionInfo& info) const {
  if (!QuicUtils::IsAckable(info.state)) {
    return false;
  }

  for (const auto& frame : info.retransmittable_frames) {
    if (session_notifier_->IsFrameOutstanding(frame)) {
      return true;
    }
  }
  return false;
}

void QuicUnackedPacketMap::RemoveRetransmittability(
    QuicTransmissionInfo* info) {
  DeleteFrames(&info->retransmittable_frames);
  info->first_sent_after_loss.Clear();
}

void QuicUnackedPacketMap::RemoveRetransmittability(
    QuicPacketNumber packet_number) {
  QUICHE_DCHECK_GE(packet_number, least_unacked_);
  QUICHE_DCHECK_LT(packet_number, least_unacked_ + unacked_packets_.size());
  QuicTransmissionInfo* info =
      &unacked_packets_[packet_number - least_unacked_];
  RemoveRetransmittability(info);
}

void QuicUnackedPacketMap::IncreaseLargestAcked(
    QuicPacketNumber largest_acked) {
  QUICHE_DCHECK(!largest_acked_.IsInitialized() ||
                largest_acked_ <= largest_acked);
  largest_acked_ = largest_acked;
}

void QuicUnackedPacketMap::MaybeUpdateLargestAckedOfPacketNumberSpace(
    PacketNumberSpace packet_number_space, QuicPacketNumber packet_number) {
  largest_acked_packets_[packet_number_space].UpdateMax(packet_number);
}

bool QuicUnackedPacketMap::IsPacketUsefulForMeasuringRtt(
    QuicPacketNumber packet_number, const QuicTransmissionInfo& info) const {
  // Packet can be used for RTT measurement if it may yet be acked as the
  // largest observed packet by the receiver.
  return QuicUtils::IsAckable(info.state) &&
         (!largest_acked_.IsInitialized() || packet_number > largest_acked_) &&
         info.state != NOT_CONTRIBUTING_RTT;
}

bool QuicUnackedPacketMap::IsPacketUsefulForCongestionControl(
    const QuicTransmissionInfo& info) const {
  // Packet contributes to congestion control if it is considered inflight.
  return info.in_flight;
}

bool QuicUnackedPacketMap::IsPacketUsefulForRetransmittableData(
    const QuicTransmissionInfo& info) const {
  // Wait for 1 RTT before giving up on the lost packet.
  return info.first_sent_after_loss.IsInitialized() &&
         (!largest_acked_.IsInitialized() ||
          info.first_sent_after_loss > largest_acked_);
}

bool QuicUnackedPacketMap::IsPacketUseless(
    QuicPacketNumber packet_number, const QuicTransmissionInfo& info) const {
  return !IsPacketUsefulForMeasuringRtt(packet_number, info) &&
         !IsPacketUsefulForCongestionControl(info) &&
         !IsPacketUsefulForRetransmittableData(info);
}

bool QuicUnackedPacketMap::IsUnacked(QuicPacketNumber packet_number) const {
  if (packet_number < least_unacked_ ||
      packet_number >= least_unacked_ + unacked_packets_.size()) {
    return false;
  }
  return !IsPacketUseless(packet_number,
                          unacked_packets_[packet_number - least_unacked_]);
}

void QuicUnackedPacketMap::RemoveFromInFlight(QuicTransmissionInfo* info) {
  if (info->in_flight) {
    QUIC_BUG_IF(quic_bug_12645_3, bytes_in_flight_ < info->bytes_sent);
    QUIC_BUG_IF(quic_bug_12645_4, packets_in_flight_ == 0);
    bytes_in_flight_ -= info->bytes_sent;
    --packets_in_flight_;

    const PacketNumberSpace packet_number_space =
        GetPacketNumberSpace(info->encryption_level);
    if (bytes_in_flight_per_packet_number_space_[packet_number_space] <
        info->bytes_sent) {
      QUIC_BUG(quic_bug_10518_3)
          << "bytes_in_flight: "
          << bytes_in_flight_per_packet_number_space_[packet_number_space]
          << " is smaller than bytes_sent: " << info->bytes_sent
          << " for packet number space: "
          << PacketNumberSpaceToString(packet_number_space);
      bytes_in_flight_per_packet_number_space_[packet_number_space] = 0;
    } else {
      bytes_in_flight_per_packet_number_space_[packet_number_space] -=
          info->bytes_sent;
    }
    if (bytes_in_flight_per_packet_number_space_[packet_number_space] == 0) {
      last_inflight_packets_sent_time_[packet_number_space] = QuicTime::Zero();
    }

    info->in_flight = false;
  }
}

void QuicUnackedPacketMap::RemoveFromInFlight(QuicPacketNumber packet_number) {
  QUICHE_DCHECK_GE(packet_number, least_unacked_);
  QUICHE_DCHECK_LT(packet_number, least_unacked_ + unacked_packets_.size());
  QuicTransmissionInfo* info =
      &unacked_packets_[packet_number - least_unacked_];
  RemoveFromInFlight(info);
}

absl::InlinedVector<QuicPacketNumber, 2>
QuicUnackedPacketMap::NeuterUnencryptedPackets() {
  absl::InlinedVector<QuicPacketNumber, 2> neutered_packets;
  QuicPacketNumber packet_number = GetLeastUnacked();
  for (QuicUnackedPacketMap::iterator it = begin(); it != end();
       ++it, ++packet_number) {
    if (!it->retransmittable_frames.empty() &&
        it->encryption_level == ENCRYPTION_INITIAL) {
      QUIC_DVLOG(2) << "Neutering unencrypted packet " << packet_number;
      // Once the connection swithes to forward secure, no unencrypted packets
      // will be sent. The data has been abandoned in the cryto stream. Remove
      // it from in flight.
      RemoveFromInFlight(packet_number);
      it->state = NEUTERED;
      neutered_packets.push_back(packet_number);
      // Notify session that the data has been delivered (but do not notify
      // send algorithm).
      // TODO(b/148868195): use NotifyFramesNeutered.
      NotifyFramesAcked(*it, QuicTime::Delta::Zero(), QuicTime::Zero());
      QUICHE_DCHECK(!HasRetransmittableFrames(*it));
    }
  }
  QUICHE_DCHECK(!supports_multiple_packet_number_spaces_ ||
                last_inflight_packets_sent_time_[INITIAL_DATA] ==
                    QuicTime::Zero());
  return neutered_packets;
}

absl::InlinedVector<QuicPacketNumber, 2>
QuicUnackedPacketMap::NeuterHandshakePackets() {
  absl::InlinedVector<QuicPacketNumber, 2> neutered_packets;
  QuicPacketNumber packet_number = GetLeastUnacked();
  for (QuicUnackedPacketMap::iterator it = begin(); it != end();
       ++it, ++packet_number) {
    if (!it->retransmittable_frames.empty() &&
        GetPacketNumberSpace(it->encryption_level) == HANDSHAKE_DATA) {
      QUIC_DVLOG(2) << "Neutering handshake packet " << packet_number;
      RemoveFromInFlight(packet_number);
      // Notify session that the data has been delivered (but do not notify
      // send algorithm).
      it->state = NEUTERED;
      neutered_packets.push_back(packet_number);
      // TODO(b/148868195): use NotifyFramesNeutered.
      NotifyFramesAcked(*it, QuicTime::Delta::Zero(), QuicTime::Zero());
    }
  }
  QUICHE_DCHECK(!supports_multiple_packet_number_spaces() ||
                last_inflight_packets_sent_time_[HANDSHAKE_DATA] ==
                    QuicTime::Zero());
  return neutered_packets;
}

bool QuicUnackedPacketMap::HasInFlightPackets() const {
  return bytes_in_flight_ > 0;
}

const QuicTransmissionInfo& QuicUnackedPacketMap::GetTransmissionInfo(
    QuicPacketNumber packet_number) const {
  return unacked_packets_[packet_number - least_unacked_];
}

QuicTransmissionInfo* QuicUnackedPacketMap::GetMutableTransmissionInfo(
    QuicPacketNumber packet_number) {
  return &unacked_packets_[packet_number - least_unacked_];
}

QuicTime QuicUnackedPacketMap::GetLastInFlightPacketSentTime() const {
  return last_inflight_packet_sent_time_;
}

QuicTime QuicUnackedPacketMap::GetLastCryptoPacketSentTime() const {
  return last_crypto_packet_sent_time_;
}

size_t QuicUnackedPacketMap::GetNumUnackedPacketsDebugOnly() const {
  size_t unacked_packet_count = 0;
  QuicPacketNumber packet_number = least_unacked_;
  for (auto it = begin(); it != end(); ++it, ++packet_number) {
    if (!IsPacketUseless(packet_number, *it)) {
      ++unacked_packet_count;
    }
  }
  return unacked_packet_count;
}

bool QuicUnackedPacketMap::HasMultipleInFlightPackets() const {
  if (bytes_in_flight_ > kDefaultTCPMSS) {
    return true;
  }
  size_t num_in_flight = 0;
  for (auto it = rbegin(); it != rend(); ++it) {
    if (it->in_flight) {
      ++num_in_flight;
    }
    if (num_in_flight > 1) {
      return true;
    }
  }
  return false;
}

bool QuicUnackedPacketMap::HasPendingCryptoPackets() const {
  return session_notifier_->HasUnackedCryptoData();
}

bool QuicUnackedPacketMap::HasUnackedRetransmittableFrames() const {
  for (auto it = rbegin(); it != rend(); ++it) {
    if (it->in_flight && HasRetransmittableFrames(*it)) {
      return true;
    }
  }
  return false;
}

QuicPacketNumber QuicUnackedPacketMap::GetLeastUnacked() const {
  return least_unacked_;
}

void QuicUnackedPacketMap::SetSessionNotifier(
    SessionNotifierInterface* session_notifier) {
  session_notifier_ = session_notifier;
}

bool QuicUnackedPacketMap::NotifyFramesAcked(const QuicTransmissionInfo& info,
                                             QuicTime::Delta ack_delay,
                                             QuicTime receive_timestamp) {
  if (session_notifier_ == nullptr) {
    return false;
  }
  bool new_data_acked = false;
  for (const QuicFrame& frame : info.retransmittable_frames) {
    if (session_notifier_->OnFrameAcked(frame, ack_delay, receive_timestamp)) {
      new_data_acked = true;
    }
  }
  return new_data_acked;
}

void QuicUnackedPacketMap::NotifyFramesLost(const QuicTransmissionInfo& info,
                                            TransmissionType /*type*/) {
  for (const QuicFrame& frame : info.retransmittable_frames) {
    session_notifier_->OnFrameLost(frame);
  }
}

bool QuicUnackedPacketMap::RetransmitFrames(const QuicFrames& frames,
                                            TransmissionType type) {
  return session_notifier_->RetransmitFrames(frames, type);
}

void QuicUnackedPacketMap::MaybeAggregateAckedStreamFrame(
    const QuicTransmissionInfo& info, QuicTime::Delta ack_delay,
    QuicTime receive_timestamp) {
  if (session_notifier_ == nullptr) {
    return;
  }
  for (const auto& frame : info.retransmittable_frames) {
    // Determine whether acked stream frame can be aggregated.
    const bool can_aggregate =
        frame.type == STREAM_FRAME &&
        frame.stream_frame.stream_id == aggregated_stream_frame_.stream_id &&
        frame.stream_frame.offset == aggregated_stream_frame_.offset +
                                         aggregated_stream_frame_.data_length &&
        // We would like to increment aggregated_stream_frame_.data_length by
        // frame.stream_frame.data_length, so we need to make sure their sum is
        // representable by QuicPacketLength, which is the type of the former.
        !WillStreamFrameLengthSumWrapAround(
            aggregated_stream_frame_.data_length,
            frame.stream_frame.data_length);

    if (can_aggregate) {
      // Aggregate stream frame.
      aggregated_stream_frame_.data_length += frame.stream_frame.data_length;
      aggregated_stream_frame_.fin = frame.stream_frame.fin;
      if (aggregated_stream_frame_.fin) {
        // Notify session notifier aggregated stream frame gets acked if fin is
        // acked.
        NotifyAggregatedStreamFrameAcked(ack_delay);
      }
      continue;
    }

    NotifyAggregatedStreamFrameAcked(ack_delay);
    if (frame.type != STREAM_FRAME || frame.stream_frame.fin) {
      session_notifier_->OnFrameAcked(frame, ack_delay, receive_timestamp);
      continue;
    }

    // Delay notifying session notifier stream frame gets acked in case it can
    // be aggregated with following acked ones.
    aggregated_stream_frame_.stream_id = frame.stream_frame.stream_id;
    aggregated_stream_frame_.offset = frame.stream_frame.offset;
    aggregated_stream_frame_.data_length = frame.stream_frame.data_length;
    aggregated_stream_frame_.fin = frame.stream_frame.fin;
  }
}

void QuicUnackedPacketMap::NotifyAggregatedStreamFrameAcked(
    QuicTime::Delta ack_delay) {
  if (aggregated_stream_frame_.stream_id == static_cast<QuicStreamId>(-1) ||
      session_notifier_ == nullptr) {
    // Aggregated stream frame is empty.
    return;
  }
  // Note: there is no receive_timestamp for an aggregated stream frame.  The
  // frames that are aggregated may not have been received at the same time.
  session_notifier_->OnFrameAcked(QuicFrame(aggregated_stream_frame_),
                                  ack_delay,
                                  /*receive_timestamp=*/QuicTime::Zero());
  // Clear aggregated stream frame.
  aggregated_stream_frame_.stream_id = -1;
}

PacketNumberSpace QuicUnackedPacketMap::GetPacketNumberSpace(
    QuicPacketNumber packet_number) const {
  return GetPacketNumberSpace(
      GetTransmissionInfo(packet_number).encryption_level);
}

PacketNumberSpace QuicUnackedPacketMap::GetPacketNumberSpace(
    EncryptionLevel encryption_level) const {
  if (supports_multiple_packet_number_spaces_) {
    return QuicUtils::GetPacketNumberSpace(encryption_level);
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    return encryption_level == ENCRYPTION_INITIAL ? HANDSHAKE_DATA
                                                  : APPLICATION_DATA;
  }
  return encryption_level == ENCRYPTION_FORWARD_SECURE ? APPLICATION_DATA
                                                       : HANDSHAKE_DATA;
}

QuicPacketNumber QuicUnackedPacketMap::GetLargestAckedOfPacketNumberSpace(
    PacketNumberSpace packet_number_space) const {
  if (packet_number_space >= NUM_PACKET_NUMBER_SPACES) {
    QUIC_BUG(quic_bug_10518_4)
        << "Invalid packet number space: " << packet_number_space;
    return QuicPacketNumber();
  }
  return largest_acked_packets_[packet_number_space];
}

QuicTime QuicUnackedPacketMap::GetLastInFlightPacketSentTime(
    PacketNumberSpace packet_number_space) const {
  if (packet_number_space >= NUM_PACKET_NUMBER_SPACES) {
    QUIC_BUG(quic_bug_10518_5)
        << "Invalid packet number space: " << packet_number_space;
    return QuicTime::Zero();
  }
  return last_inflight_packets_sent_time_[packet_number_space];
}

QuicPacketNumber
QuicUnackedPacketMap::GetLargestSentRetransmittableOfPacketNumberSpace(
    PacketNumberSpace packet_number_space) const {
  if (packet_number_space >= NUM_PACKET_NUMBER_SPACES) {
    QUIC_BUG(quic_bug_10518_6)
        << "Invalid packet number space: " << packet_number_space;
    return QuicPacketNumber();
  }
  return largest_sent_retransmittable_packets_[packet_number_space];
}

const QuicTransmissionInfo*
QuicUnackedPacketMap::GetFirstInFlightTransmissionInfo() const {
  QUICHE_DCHECK(HasInFlightPackets());
  for (auto it = begin(); it != end(); ++it) {
    if (it->in_flight) {
      return &(*it);
    }
  }
  QUICHE_DCHECK(false);
  return nullptr;
}

const QuicTransmissionInfo*
QuicUnackedPacketMap::GetFirstInFlightTransmissionInfoOfSpace(
    PacketNumberSpace packet_number_space) const {
  // TODO(fayang): Optimize this part if arm 1st PTO with first in flight sent
  // time works.
  for (auto it = begin(); it != end(); ++it) {
    if (it->in_flight &&
        GetPacketNumberSpace(it->encryption_level) == packet_number_space) {
      return &(*it);
    }
  }
  return nullptr;
}

void QuicUnackedPacketMap::EnableMultiplePacketNumberSpacesSupport() {
  if (supports_multiple_packet_number_spaces_) {
    QUIC_BUG(quic_bug_10518_7)
        << "Multiple packet number spaces has already been enabled";
    return;
  }
  if (largest_sent_packet_.IsInitialized()) {
    QUIC_BUG(quic_bug_10518_8)
        << "Try to enable multiple packet number spaces support after any "
           "packet has been sent.";
    return;
  }

  supports_multiple_packet_number_spaces_ = true;
}

int32_t QuicUnackedPacketMap::GetLastPacketContent() const {
  if (empty()) {
    // Use -1 to distinguish with packets with no retransmittable frames nor
    // acks.
    return -1;
  }
  int32_t content = 0;
  const QuicTransmissionInfo& last_packet = unacked_packets_.back();
  for (const auto& frame : last_packet.retransmittable_frames) {
    content |= GetFrameTypeBitfield(frame.type);
  }
  if (last_packet.largest_acked.IsInitialized()) {
    content |= GetFrameTypeBitfield(ACK_FRAME);
  }
  return content;
}

}  // namespace quic
```