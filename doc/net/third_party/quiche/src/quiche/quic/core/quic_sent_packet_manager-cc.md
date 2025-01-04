Response:
My thought process to analyze the C++ code and generate the summary goes through these steps:

1. **Understand the Goal:** The request asks for a functional breakdown of a C++ file (`quic_sent_packet_manager.cc`) within the Chromium network stack. Key aspects include explaining its purpose, relating it to JavaScript (if applicable), outlining logic with examples, identifying common usage errors, tracing user interactions, and summarizing its function (for this first part).

2. **Initial Skim and Keyword Spotting:** I quickly read through the provided code, looking for familiar terms and structural elements. I noticed:
    * `#include` statements indicating dependencies (congestion control, crypto, frames, etc.).
    * Class definition: `QuicSentPacketManager`.
    * Member variables (e.g., `unacked_packets_`, `clock_`, `send_algorithm_`).
    * Member functions (e.g., `SetFromConfig`, `OnPacketSent`, `OnRetransmissionTimeout`).
    * Constants like `kDefaultRetransmissionTimeMs`.
    * Use of namespaces (`quic`).
    * Logging and debugging features (`QUIC_LOG`, `debug_delegate_`).

3. **Identify Core Responsibilities:** Based on the file name and the presence of terms like "sent packet," "congestion control," "retransmission," and "ack," I deduce that this class is responsible for managing the lifecycle of packets sent by the QUIC connection. This includes:
    * Tracking which packets have been sent and whether they've been acknowledged.
    * Managing retransmissions of lost or unacknowledged packets.
    * Implementing congestion control algorithms to regulate the sending rate.
    * Handling timeouts related to packet delivery.

4. **Analyze Key Member Variables:**  I examine the important member variables to understand the internal state managed by the class:
    * `unacked_packets_`:  Crucial for tracking sent packets and their status.
    * `clock_`: Provides the current time for timeouts and RTT calculations.
    * `send_algorithm_`:  An interface to different congestion control algorithms.
    * `loss_algorithm_`: An interface to different loss detection algorithms.
    * `rtt_stats_`:  Manages round-trip time measurements.
    * Counters for retransmissions and timeouts.

5. **Analyze Key Member Functions (Focus on Part 1):** I delve into the functions defined in the provided code snippet, noting their roles:
    * **Constructor/Destructor:**  Initialization and cleanup.
    * **`SetFromConfig`:**  Configures the manager based on QUIC connection parameters. This involves setting up congestion control, loss detection, and initial window sizes.
    * **`ApplyConnectionOptions`:** Handles connection options sent by the peer.
    * **`ResumeConnectionState` and `AdjustNetworkParameters`:** Deal with resuming connections and adapting to network conditions.
    * **`SetLossDetectionTuner`:** Allows customization of loss detection.
    * **`OnConfigNegotiated` and `OnConnectionClosed`:** Lifecycle management related to the QUIC connection.
    * **`SetHandshakeConfirmed`:** Marks the completion of the QUIC handshake.
    * **`PostProcessNewlyAckedPackets`:** Handles the reception of acknowledgment (ACK) frames, triggering loss detection and congestion control updates.
    * **`MaybeInvokeCongestionEvent`:**  Updates the congestion control algorithm based on acknowledgments and losses.
    * **`MarkInitialPacketsForRetransmission` and `MarkZeroRttPacketsForRetransmission`:** Specific logic for retransmitting packets sent during the handshake.
    * **`NeuterUnencryptedPackets` and `NeuterHandshakePackets`:** Logic for invalidating packets sent during early stages of the connection.
    * **`ShouldAddMaxAckDelay` and `GetEarliestPacketSentTimeForPto`:** Functions related to managing Probe Timeouts (PTOs).
    * **`MarkForRetransmission`:**  Marks a packet for retransmission based on a given reason.
    * **`RecordOneSpuriousRetransmission`:**  Tracks instances where a retransmitted packet is later acknowledged.
    * **`MarkPacketHandled`:**  Processes the acknowledgment of a packet.
    * **`CanSendAckFrequency` and `GetUpdatedAckFrequencyFrame`:**  Deal with the Ack Frequency feature (allowing the receiver to control ACK sending).
    * **`RecordEcnMarkingSent`:** Tracks Explicit Congestion Notification (ECN) markings.
    * **`OnPacketSent`:**  Handles the sending of a new packet, updating internal state and informing congestion control.
    * **`AddDispatcherSentPacket`:** Handles packets sent by the dispatcher (likely for stateless resets, etc.).
    * **`OnRetransmissionTimeout`:**  Handles the expiration of the retransmission timer, triggering different actions depending on the current state.

6. **Relate to JavaScript (or Lack Thereof):** I consider whether this C++ code directly interacts with JavaScript. Given its position within the network stack and its focus on low-level packet management, the direct interaction is likely minimal. JavaScript would interact with the higher-level QUIC API provided by the browser, without direct knowledge of this specific C++ class. I formulate an explanation reflecting this.

7. **Logical Inference with Examples:** For functions that involve decision-making, I construct simple "if-then" scenarios to illustrate their behavior. This helps clarify the logic. For example, I consider the conditions under which `SetInitialRtt` is called in `SetFromConfig`.

8. **Identify Potential User/Programming Errors:** I think about common mistakes developers might make when using QUIC or contributing to its implementation. This might involve misconfiguration, incorrect assumptions about packet delivery, or misuse of APIs.

9. **Trace User Operations:** I consider how a user action in a web browser (e.g., navigating to a website) would eventually lead to the execution of this code. This involves understanding the flow from a high-level user action through the network stack to the QUIC implementation.

10. **Summarize Functionality (for Part 1):** Based on the analysis, I condense the key responsibilities of the `QuicSentPacketManager` into a concise summary, focusing on the aspects covered in the first part of the code.

11. **Refine and Organize:** I review the generated text for clarity, accuracy, and organization, ensuring that it addresses all parts of the prompt effectively. I use headings and bullet points to make the information easier to read. I double-check for any inconsistencies or areas where more explanation might be needed. For example, I ensure I've explained the purpose of the key data structures and algorithms managed by this class.
This is the first part of the `quic_sent_packet_manager.cc` file, which is a crucial component of the QUIC protocol implementation in Chromium's network stack. Based on the included code, here's a summary of its functionality:

**Core Functionality of `QuicSentPacketManager` (Part 1):**

The `QuicSentPacketManager` class is responsible for managing the state and lifecycle of packets sent by a QUIC endpoint (either client or server). Its primary functions revolve around ensuring reliable and efficient data delivery by handling:

* **Tracking Sent Packets:** It maintains a record of all packets sent but not yet acknowledged (`unacked_packets_`). This includes information like packet number, transmission time, whether the packet contains retransmittable data, and encryption level.
* **Congestion Control:** It integrates with a congestion control algorithm (`send_algorithm_`) to determine the appropriate rate at which to send data. It updates the congestion window based on acknowledgments and loss events.
* **Loss Detection:** It utilizes a loss detection algorithm (`loss_algorithm_`) to identify lost packets based on acknowledgments and timeouts. Different loss detection mechanisms can be configured.
* **Retransmission Management:**  It handles the retransmission of packets that are deemed lost or are necessary for handshake completion. It tracks different types of retransmissions (handshake, PTO, loss-based).
* **Round-Trip Time (RTT) Estimation:** It calculates and maintains estimates of the round-trip time (`rtt_stats_`) based on the timing of acknowledgments.
* **Pacing:** It can optionally employ a pacing mechanism (`pacing_sender_`) to smooth out packet transmissions, preventing bursts and improving network performance.
* **Handshake Management:** It plays a role in the QUIC handshake by managing the retransmission of handshake packets and ensuring their timely delivery.
* **Configuration and Initialization:** It can be configured with various parameters from the `QuicConfig`, including initial RTT, congestion control algorithm, and loss detection settings.
* **Explicit Congestion Notification (ECN):** It tracks ECN markings on sent and acknowledged packets to respond to network congestion signals.
* **Ack Frequency:** It implements logic for sending and processing Ack Frequency frames, allowing the receiver to influence how often the sender expects acknowledgments.

**Relationship with JavaScript:**

While this C++ code doesn't directly execute JavaScript, it plays a vital role in enabling the network communication that JavaScript applications rely on in a web browser. Here's how they relate:

* **Indirect Impact:** When a JavaScript application in a browser makes a network request (e.g., fetching data via `fetch()` or `XMLHttpRequest`), the browser's network stack, including this `QuicSentPacketManager` class, handles the underlying communication using the QUIC protocol.
* **No Direct Function Calls:** JavaScript code cannot directly call functions within this C++ file. The interaction happens at a lower level through the browser's networking APIs.
* **Performance Implications:** The efficiency of this class directly impacts the performance experienced by JavaScript applications. Effective congestion control and loss detection lead to faster and more reliable data transfer, which translates to quicker page loads and smoother application performance for the user.

**Example of Implicit Interaction:**

Imagine a JavaScript application fetching a large image from a server over a QUIC connection:

1. **JavaScript `fetch()` call:** The JavaScript code initiates a `fetch()` request for the image.
2. **Browser's Network Stack:** The browser's network stack takes over, and if the connection to the server uses QUIC, the `QuicSentPacketManager` is involved.
3. **Packet Sending:** The `QuicSentPacketManager` (in conjunction with other QUIC components) breaks down the image data into QUIC packets and sends them.
4. **Congestion Control and Pacing:**  The `QuicSentPacketManager` uses its congestion control algorithm to determine how many packets to send at a time and uses pacing to regulate the sending rate.
5. **Acknowledgment Handling:** When the server acknowledges the packets, the `QuicSentPacketManager` processes these acknowledgments, updating RTT estimates and potentially increasing the congestion window.
6. **Loss Detection and Retransmission:** If some packets are lost in transit, the `QuicSentPacketManager` detects the loss and triggers retransmissions.
7. **Image Delivery:** Eventually, all the image data packets are successfully delivered to the server, and the browser receives the complete image data.
8. **JavaScript Callback:** The `fetch()` promise in the JavaScript code resolves with the image data, making it available to the application.

**Logical Inference with Assumptions:**

Let's consider the `MarkForRetransmission` function:

* **Hypothetical Input:**
    * `packet_number`: 123 (the sequence number of the packet to retransmit)
    * `transmission_type`: `LOSS_RETRANSMISSION` (indicating the packet is being retransmitted due to loss detection)
* **Assumptions:**
    * Packet 123 exists in the `unacked_packets_` data structure.
    * Packet 123 contains retransmittable data.
* **Logical Steps (within the function):**
    1. The function retrieves the `QuicTransmissionInfo` for packet 123.
    2. It checks if retransmissions of type `LOSS_RETRANSMISSION` should force direct retransmission of frames (in this case, it likely doesn't).
    3. It calls `unacked_packets_.NotifyFramesLost()` to mark the frames within packet 123 as lost, updating the packet's state.
    4. It sets the `transmission_info->state` to `LOST`.
* **Hypothetical Output (Internal State Change):**
    * The `QuicTransmissionInfo` for packet 123 will have its state updated to `LOST`.
    * The frames associated with packet 123 will be marked as lost within the `unacked_packets_` structure.

**User or Programming Common Usage Errors (Indirectly):**

Users don't directly interact with this class, but programming errors in the QUIC implementation or incorrect configuration can lead to issues:

* **Incorrect Congestion Control Configuration:** If the congestion control algorithm is not properly configured or if its parameters are wrong, it can lead to either underutilization of the network (low throughput) or overwhelming the network (congestion and packet loss). For example, setting an excessively large initial congestion window might seem beneficial but can cause problems in lossy networks.
* **Flawed Loss Detection Logic:**  Bugs in the loss detection algorithm could lead to falsely identifying packets as lost (spurious retransmissions) or failing to detect actual losses, both impacting performance.
* **Timer Issues:** Incorrectly configured or implemented retransmission timers can lead to excessive delays or unnecessary retransmissions. Setting the retransmission timeout too short can cause premature retransmissions, while setting it too long delays recovery from packet loss.

**User Operation Leading to This Code (Debugging Clue):**

A user browsing a website that uses QUIC as its transport protocol will indirectly trigger the execution of this code. Here's a simplified step-by-step scenario:

1. **User navigates to a website:** The user types a URL in their browser's address bar and hits Enter, or clicks a link.
2. **DNS resolution:** The browser resolves the website's domain name to an IP address.
3. **Connection establishment:** The browser attempts to establish a connection with the web server. If QUIC is negotiated (either through ALPN or HTTP/3), a QUIC connection establishment process begins.
4. **Handshake:** The QUIC handshake involves exchanging packets to establish encryption parameters and connection properties. The `QuicSentPacketManager` is actively involved in sending and managing these handshake packets.
5. **Data transfer:** Once the connection is established, when the browser requests web page resources (HTML, CSS, images, etc.), the `QuicSentPacketManager` manages the sending of these data packets.
6. **Packet loss or network congestion:** If there are network issues, packets might be lost or delayed. This is where the loss detection and congestion control mechanisms within `QuicSentPacketManager` come into play to retransmit lost packets and adjust the sending rate.
7. **Acknowledgment processing:** When the server sends acknowledgments for the received data packets, the `QuicSentPacketManager` processes these acks to update its internal state and inform the congestion control algorithm.

**Summary of Part 1's Functionality:**

In essence, the first part of `QuicSentPacketManager.cc` lays the groundwork for managing outgoing QUIC packets. It initializes the class, configures its core components (congestion control, loss detection), handles basic packet sending and tracking, and starts the process of reacting to acknowledgments and network conditions. It sets up the fundamental mechanisms for reliable data delivery over QUIC.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_sent_packet_manager.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "quiche/quic/core/congestion_control/general_loss_algorithm.h"
#include "quiche/quic/core/congestion_control/pacing_sender.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/proto/cached_network_parameters_proto.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_transmission_info.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/print_elements.h"

namespace quic {

namespace {
static const int64_t kDefaultRetransmissionTimeMs = 500;

// Ensure the handshake timer isnt't faster than 10ms.
// This limits the tenth retransmitted packet to 10s after the initial CHLO.
static const int64_t kMinHandshakeTimeoutMs = 10;

// Sends up to two tail loss probes before firing an RTO,
// per draft RFC draft-dukkipati-tcpm-tcp-loss-probe.
static const size_t kDefaultMaxTailLossProbes = 2;

// The multiplier for calculating PTO timeout before any RTT sample is
// available.
static const float kPtoMultiplierWithoutRttSamples = 3;

// Returns true of retransmissions of the specified type should retransmit
// the frames directly (as opposed to resulting in a loss notification).
inline bool ShouldForceRetransmission(TransmissionType transmission_type) {
  return transmission_type == HANDSHAKE_RETRANSMISSION ||
         transmission_type == PTO_RETRANSMISSION;
}

// If pacing rate is accurate, > 2 burst token is not likely to help first ACK
// to arrive earlier, and overly large burst token could cause incast packet
// losses.
static const uint32_t kConservativeUnpacedBurst = 2;

// The default number of PTOs to trigger path degrading.
static const uint32_t kNumProbeTimeoutsForPathDegradingDelay = 4;

}  // namespace

#define ENDPOINT                                                         \
  (unacked_packets_.perspective() == Perspective::IS_SERVER ? "Server: " \
                                                            : "Client: ")

QuicSentPacketManager::QuicSentPacketManager(
    Perspective perspective, const QuicClock* clock, QuicRandom* random,
    QuicConnectionStats* stats, CongestionControlType congestion_control_type)
    : unacked_packets_(perspective),
      clock_(clock),
      random_(random),
      stats_(stats),
      debug_delegate_(nullptr),
      network_change_visitor_(nullptr),
      initial_congestion_window_(kInitialCongestionWindow),
      loss_algorithm_(&uber_loss_algorithm_),
      consecutive_crypto_retransmission_count_(0),
      pending_timer_transmission_count_(0),
      using_pacing_(false),
      conservative_handshake_retransmits_(false),
      largest_mtu_acked_(0),
      handshake_finished_(false),
      peer_max_ack_delay_(
          QuicTime::Delta::FromMilliseconds(kDefaultPeerDelayedAckTimeMs)),
      rtt_updated_(false),
      acked_packets_iter_(last_ack_frame_.packets.rbegin()),
      consecutive_pto_count_(0),
      handshake_mode_disabled_(false),
      handshake_packet_acked_(false),
      zero_rtt_packet_acked_(false),
      one_rtt_packet_acked_(false),
      num_ptos_for_path_degrading_(kNumProbeTimeoutsForPathDegradingDelay),
      ignore_pings_(false),
      ignore_ack_delay_(false) {
  SetSendAlgorithm(congestion_control_type);
}

QuicSentPacketManager::~QuicSentPacketManager() {}

void QuicSentPacketManager::SetFromConfig(const QuicConfig& config) {
  const Perspective perspective = unacked_packets_.perspective();
  if (config.HasReceivedInitialRoundTripTimeUs() &&
      config.ReceivedInitialRoundTripTimeUs() > 0) {
    if (!config.HasClientSentConnectionOption(kNRTT, perspective)) {
      SetInitialRtt(QuicTime::Delta::FromMicroseconds(
                        config.ReceivedInitialRoundTripTimeUs()),
                    /*trusted=*/false);
    }
  } else if (config.HasInitialRoundTripTimeUsToSend() &&
             config.GetInitialRoundTripTimeUsToSend() > 0) {
    SetInitialRtt(QuicTime::Delta::FromMicroseconds(
                      config.GetInitialRoundTripTimeUsToSend()),
                  /*trusted=*/false);
  }
  if (config.HasReceivedMaxAckDelayMs()) {
    peer_max_ack_delay_ =
        QuicTime::Delta::FromMilliseconds(config.ReceivedMaxAckDelayMs());
  }
  if (GetQuicReloadableFlag(quic_can_send_ack_frequency) &&
      perspective == Perspective::IS_SERVER) {
    if (config.HasReceivedMinAckDelayMs()) {
      peer_min_ack_delay_ =
          QuicTime::Delta::FromMilliseconds(config.ReceivedMinAckDelayMs());
    }
    if (config.HasClientSentConnectionOption(kAFF1, perspective)) {
      use_smoothed_rtt_in_ack_delay_ = true;
    }
  }
  if (config.HasClientSentConnectionOption(kMAD0, perspective)) {
    ignore_ack_delay_ = true;
  }

  // Configure congestion control.
  if (perspective == Perspective::IS_CLIENT &&
      config.HasClientRequestedIndependentOption(kPRGC, perspective)) {
    SetSendAlgorithm(kPragueCubic);
  }
  if (config.HasClientRequestedIndependentOption(kTBBR, perspective)) {
    SetSendAlgorithm(kBBR);
  }
  if (GetQuicReloadableFlag(quic_allow_client_enabled_bbr_v2) &&
      config.HasClientRequestedIndependentOption(kB2ON, perspective)) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_allow_client_enabled_bbr_v2);
    SetSendAlgorithm(kBBRv2);
  }

  if (config.HasClientRequestedIndependentOption(kRENO, perspective)) {
    SetSendAlgorithm(kRenoBytes);
  } else if (config.HasClientRequestedIndependentOption(kBYTE, perspective) ||
             (GetQuicReloadableFlag(quic_default_to_bbr) &&
              config.HasClientRequestedIndependentOption(kQBIC, perspective))) {
    SetSendAlgorithm(kCubicBytes);
  }

  // Initial window.
  if (config.HasClientRequestedIndependentOption(kIW03, perspective)) {
    initial_congestion_window_ = 3;
    send_algorithm_->SetInitialCongestionWindowInPackets(3);
  }
  if (config.HasClientRequestedIndependentOption(kIW10, perspective)) {
    initial_congestion_window_ = 10;
    send_algorithm_->SetInitialCongestionWindowInPackets(10);
  }
  if (config.HasClientRequestedIndependentOption(kIW20, perspective)) {
    initial_congestion_window_ = 20;
    send_algorithm_->SetInitialCongestionWindowInPackets(20);
  }
  if (config.HasClientRequestedIndependentOption(kIW50, perspective)) {
    initial_congestion_window_ = 50;
    send_algorithm_->SetInitialCongestionWindowInPackets(50);
  }
  if (config.HasClientRequestedIndependentOption(kBWS5, perspective)) {
    initial_congestion_window_ = 10;
    send_algorithm_->SetInitialCongestionWindowInPackets(10);
  }

  if (config.HasClientRequestedIndependentOption(kIGNP, perspective)) {
    ignore_pings_ = true;
  }

  using_pacing_ = !GetQuicFlag(quic_disable_pacing_for_perf_tests);
  // Configure loss detection.
  if (config.HasClientRequestedIndependentOption(kILD0, perspective)) {
    uber_loss_algorithm_.SetReorderingShift(kDefaultIetfLossDelayShift);
    uber_loss_algorithm_.DisableAdaptiveReorderingThreshold();
  }
  if (config.HasClientRequestedIndependentOption(kILD1, perspective)) {
    uber_loss_algorithm_.SetReorderingShift(kDefaultLossDelayShift);
    uber_loss_algorithm_.DisableAdaptiveReorderingThreshold();
  }
  if (config.HasClientRequestedIndependentOption(kILD2, perspective)) {
    uber_loss_algorithm_.EnableAdaptiveReorderingThreshold();
    uber_loss_algorithm_.SetReorderingShift(kDefaultIetfLossDelayShift);
  }
  if (config.HasClientRequestedIndependentOption(kILD3, perspective)) {
    uber_loss_algorithm_.SetReorderingShift(kDefaultLossDelayShift);
    uber_loss_algorithm_.EnableAdaptiveReorderingThreshold();
  }
  if (config.HasClientRequestedIndependentOption(kILD4, perspective)) {
    uber_loss_algorithm_.SetReorderingShift(kDefaultLossDelayShift);
    uber_loss_algorithm_.EnableAdaptiveReorderingThreshold();
    uber_loss_algorithm_.EnableAdaptiveTimeThreshold();
  }
  if (config.HasClientRequestedIndependentOption(kRUNT, perspective)) {
    uber_loss_algorithm_.DisablePacketThresholdForRuntPackets();
  }
  if (config.HasClientSentConnectionOption(kCONH, perspective)) {
    conservative_handshake_retransmits_ = true;
  }
  if (config.HasClientSentConnectionOption(kRNIB, perspective)) {
    pacing_sender_.set_remove_non_initial_burst();
  }
  send_algorithm_->SetFromConfig(config, perspective);
  loss_algorithm_->SetFromConfig(config, perspective);

  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnCongestionChange();
  }

  if (debug_delegate_ != nullptr) {
    DebugDelegate::SendParameters parameters;
    parameters.congestion_control_type =
        send_algorithm_->GetCongestionControlType();
    parameters.use_pacing = using_pacing_;
    parameters.initial_congestion_window = initial_congestion_window_;
    debug_delegate_->OnConfigProcessed(parameters);
  }
}

void QuicSentPacketManager::ApplyConnectionOptions(
    const QuicTagVector& connection_options) {
  std::optional<CongestionControlType> cc_type;
  if (ContainsQuicTag(connection_options, kB2ON)) {
    cc_type = kBBRv2;
  } else if (ContainsQuicTag(connection_options, kTBBR)) {
    cc_type = kBBR;
  } else if (ContainsQuicTag(connection_options, kRENO)) {
    cc_type = kRenoBytes;
  } else if (ContainsQuicTag(connection_options, kQBIC)) {
    cc_type = kCubicBytes;
  }
  // This function is only used in server experiments, so do not apply the
  // client-only PRGC tag.
  QUICHE_DCHECK(unacked_packets_.perspective() == Perspective::IS_SERVER);
  if (cc_type.has_value()) {
    SetSendAlgorithm(*cc_type);
  }

  send_algorithm_->ApplyConnectionOptions(connection_options);
}

void QuicSentPacketManager::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(
      max_bandwidth_resumption
          ? cached_network_params.max_bandwidth_estimate_bytes_per_second()
          : cached_network_params.bandwidth_estimate_bytes_per_second());
  QuicTime::Delta rtt =
      QuicTime::Delta::FromMilliseconds(cached_network_params.min_rtt_ms());
  // This calls the old AdjustNetworkParameters interface, and fills certain
  // fields in SendAlgorithmInterface::NetworkParams
  // (e.g., quic_bbr_fix_pacing_rate) using GFE flags.
  SendAlgorithmInterface::NetworkParams params(
      bandwidth, rtt, /*allow_cwnd_to_decrease = */ false);
  // The rtt is trusted because it's a min_rtt measured from a previous
  // connection with the same network path between client and server.
  params.is_rtt_trusted = true;
  AdjustNetworkParameters(params);
}

void QuicSentPacketManager::AdjustNetworkParameters(
    const SendAlgorithmInterface::NetworkParams& params) {
  const QuicBandwidth& bandwidth = params.bandwidth;
  const QuicTime::Delta& rtt = params.rtt;

  if (!rtt.IsZero()) {
    if (params.is_rtt_trusted) {
      // Always set initial rtt if it's trusted.
      SetInitialRtt(rtt, /*trusted=*/true);
    } else if (rtt_stats_.initial_rtt() ==
               QuicTime::Delta::FromMilliseconds(kInitialRttMs)) {
      // Only set initial rtt if we are using the default. This avoids
      // overwriting a trusted initial rtt by an untrusted one.
      SetInitialRtt(rtt, /*trusted=*/false);
    }
  }

  const QuicByteCount old_cwnd = send_algorithm_->GetCongestionWindow();
  if (GetQuicReloadableFlag(quic_conservative_bursts) && using_pacing_ &&
      !bandwidth.IsZero()) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_conservative_bursts);
    pacing_sender_.SetBurstTokens(kConservativeUnpacedBurst);
  }
  send_algorithm_->AdjustNetworkParameters(params);
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnAdjustNetworkParameters(
        bandwidth, rtt.IsZero() ? rtt_stats_.MinOrInitialRtt() : rtt, old_cwnd,
        send_algorithm_->GetCongestionWindow());
  }
}

void QuicSentPacketManager::SetLossDetectionTuner(
    std::unique_ptr<LossDetectionTunerInterface> tuner) {
  uber_loss_algorithm_.SetLossDetectionTuner(std::move(tuner));
}

void QuicSentPacketManager::OnConfigNegotiated() {
  loss_algorithm_->OnConfigNegotiated();
}

void QuicSentPacketManager::OnConnectionClosed() {
  loss_algorithm_->OnConnectionClosed();
}

void QuicSentPacketManager::SetHandshakeConfirmed() {
  if (!handshake_finished_) {
    handshake_finished_ = true;
    NeuterHandshakePackets();
  }
}

void QuicSentPacketManager::PostProcessNewlyAckedPackets(
    QuicPacketNumber ack_packet_number, EncryptionLevel ack_decrypted_level,
    const QuicAckFrame& ack_frame, QuicTime ack_receive_time, bool rtt_updated,
    QuicByteCount prior_bytes_in_flight,
    std::optional<QuicEcnCounts> ecn_counts) {
  unacked_packets_.NotifyAggregatedStreamFrameAcked(
      last_ack_frame_.ack_delay_time);
  InvokeLossDetection(ack_receive_time);
  MaybeInvokeCongestionEvent(
      rtt_updated, prior_bytes_in_flight, ack_receive_time, ecn_counts,
      peer_ack_ecn_counts_[QuicUtils::GetPacketNumberSpace(
          ack_decrypted_level)]);
  unacked_packets_.RemoveObsoletePackets();

  sustained_bandwidth_recorder_.RecordEstimate(
      send_algorithm_->InRecovery(), send_algorithm_->InSlowStart(),
      send_algorithm_->BandwidthEstimate(), ack_receive_time, clock_->WallNow(),
      rtt_stats_.smoothed_rtt());

  // Anytime we are making forward progress and have a new RTT estimate, reset
  // the backoff counters.
  if (rtt_updated) {
    // Records the max consecutive PTO before forward progress has been made.
    if (consecutive_pto_count_ >
        stats_->max_consecutive_rto_with_forward_progress) {
      stats_->max_consecutive_rto_with_forward_progress =
          consecutive_pto_count_;
    }
    // Reset all retransmit counters any time a new packet is acked.
    consecutive_pto_count_ = 0;
    consecutive_crypto_retransmission_count_ = 0;
  }

  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnIncomingAck(
        ack_packet_number, ack_decrypted_level, ack_frame, ack_receive_time,
        LargestAcked(ack_frame), rtt_updated, GetLeastUnacked());
  }
  // Remove packets below least unacked from all_packets_acked_ and
  // last_ack_frame_.
  last_ack_frame_.packets.RemoveUpTo(unacked_packets_.GetLeastUnacked());
  last_ack_frame_.received_packet_times.clear();
}

void QuicSentPacketManager::MaybeInvokeCongestionEvent(
    bool rtt_updated, QuicByteCount prior_in_flight, QuicTime event_time,
    std::optional<QuicEcnCounts> ecn_counts,
    const QuicEcnCounts& previous_counts) {
  if (!rtt_updated && packets_acked_.empty() && packets_lost_.empty()) {
    return;
  }
  const bool overshooting_detected =
      stats_->overshooting_detected_with_network_parameters_adjusted;
  // A connection should send at most one flavor of ECT, so only one variable
  // is necessary.
  QuicPacketCount newly_acked_ect = 0, newly_acked_ce = 0;
  if (ecn_counts.has_value()) {
    QUICHE_DCHECK(GetQuicRestartFlag(quic_support_ect1));
    newly_acked_ect = ecn_counts->ect1 - previous_counts.ect1;
    if (newly_acked_ect == 0) {
      newly_acked_ect = ecn_counts->ect0 - previous_counts.ect0;
    } else {
      QUIC_BUG_IF(quic_bug_518619343_04,
                  ecn_counts->ect0 - previous_counts.ect0)
          << "Sent ECT(0) and ECT(1) newly acked in the same ACK.";
    }
    newly_acked_ce = ecn_counts->ce - previous_counts.ce;
  }
  if (using_pacing_) {
    pacing_sender_.OnCongestionEvent(rtt_updated, prior_in_flight, event_time,
                                     packets_acked_, packets_lost_,
                                     newly_acked_ect, newly_acked_ce);
  } else {
    send_algorithm_->OnCongestionEvent(rtt_updated, prior_in_flight, event_time,
                                       packets_acked_, packets_lost_,
                                       newly_acked_ect, newly_acked_ce);
  }
  if (debug_delegate_ != nullptr && !overshooting_detected &&
      stats_->overshooting_detected_with_network_parameters_adjusted) {
    debug_delegate_->OnOvershootingDetected();
  }
  packets_acked_.clear();
  packets_lost_.clear();
  if (network_change_visitor_ != nullptr) {
    network_change_visitor_->OnCongestionChange();
  }
}

void QuicSentPacketManager::MarkInitialPacketsForRetransmission() {
  if (unacked_packets_.empty()) {
    return;
  }
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  QuicPacketNumber largest_sent_packet = unacked_packets_.largest_sent_packet();
  for (; packet_number <= largest_sent_packet; ++packet_number) {
    QuicTransmissionInfo* transmission_info =
        unacked_packets_.GetMutableTransmissionInfo(packet_number);
    if (transmission_info->encryption_level == ENCRYPTION_INITIAL) {
      if (transmission_info->in_flight) {
        unacked_packets_.RemoveFromInFlight(transmission_info);
      }
      if (unacked_packets_.HasRetransmittableFrames(*transmission_info)) {
        MarkForRetransmission(packet_number, ALL_INITIAL_RETRANSMISSION);
      }
    }
  }
}

void QuicSentPacketManager::MarkZeroRttPacketsForRetransmission() {
  if (unacked_packets_.empty()) {
    return;
  }
  QuicPacketNumber packet_number = unacked_packets_.GetLeastUnacked();
  QuicPacketNumber largest_sent_packet = unacked_packets_.largest_sent_packet();
  for (; packet_number <= largest_sent_packet; ++packet_number) {
    QuicTransmissionInfo* transmission_info =
        unacked_packets_.GetMutableTransmissionInfo(packet_number);
    if (transmission_info->encryption_level == ENCRYPTION_ZERO_RTT) {
      if (transmission_info->in_flight) {
        // Remove 0-RTT packets and packets of the wrong version from flight,
        // because neither can be processed by the peer.
        unacked_packets_.RemoveFromInFlight(transmission_info);
      }
      if (unacked_packets_.HasRetransmittableFrames(*transmission_info)) {
        MarkForRetransmission(packet_number, ALL_ZERO_RTT_RETRANSMISSION);
      }
    }
  }
}

void QuicSentPacketManager::NeuterUnencryptedPackets() {
  for (QuicPacketNumber packet_number :
       unacked_packets_.NeuterUnencryptedPackets()) {
    send_algorithm_->OnPacketNeutered(packet_number);
  }
  if (handshake_mode_disabled_) {
    consecutive_pto_count_ = 0;
    uber_loss_algorithm_.ResetLossDetection(INITIAL_DATA);
  }
}

void QuicSentPacketManager::NeuterHandshakePackets() {
  for (QuicPacketNumber packet_number :
       unacked_packets_.NeuterHandshakePackets()) {
    send_algorithm_->OnPacketNeutered(packet_number);
  }
  if (handshake_mode_disabled_) {
    consecutive_pto_count_ = 0;
    uber_loss_algorithm_.ResetLossDetection(HANDSHAKE_DATA);
  }
}

bool QuicSentPacketManager::ShouldAddMaxAckDelay(
    PacketNumberSpace space) const {
  // Do not include max_ack_delay when PTO is armed for Initial or Handshake
  // packet number spaces.
  return !supports_multiple_packet_number_spaces() || space == APPLICATION_DATA;
}

QuicTime QuicSentPacketManager::GetEarliestPacketSentTimeForPto(
    PacketNumberSpace* packet_number_space) const {
  QUICHE_DCHECK(supports_multiple_packet_number_spaces());
  QuicTime earliest_sent_time = QuicTime::Zero();
  for (int8_t i = 0; i < NUM_PACKET_NUMBER_SPACES; ++i) {
    const QuicTime sent_time = unacked_packets_.GetLastInFlightPacketSentTime(
        static_cast<PacketNumberSpace>(i));
    if (!handshake_finished_ && i == APPLICATION_DATA) {
      // Do not arm PTO for application data until handshake gets confirmed.
      continue;
    }
    if (!sent_time.IsInitialized() || (earliest_sent_time.IsInitialized() &&
                                       earliest_sent_time <= sent_time)) {
      continue;
    }
    earliest_sent_time = sent_time;
    *packet_number_space = static_cast<PacketNumberSpace>(i);
  }

  return earliest_sent_time;
}

void QuicSentPacketManager::MarkForRetransmission(
    QuicPacketNumber packet_number, TransmissionType transmission_type) {
  QuicTransmissionInfo* transmission_info =
      unacked_packets_.GetMutableTransmissionInfo(packet_number);
  // Packets without retransmittable frames can only be marked for loss
  // retransmission.
  QUIC_BUG_IF(quic_bug_12552_2, transmission_type != LOSS_RETRANSMISSION &&
                                    !unacked_packets_.HasRetransmittableFrames(
                                        *transmission_info))
      << "packet number " << packet_number
      << " transmission_type: " << transmission_type << " transmission_info "
      << transmission_info->DebugString();
  if (ShouldForceRetransmission(transmission_type)) {
    if (!unacked_packets_.RetransmitFrames(
            QuicFrames(transmission_info->retransmittable_frames),
            transmission_type)) {
      // Do not set packet state if the data is not fully retransmitted.
      // This should only happen if packet payload size decreases which can be
      // caused by:
      // 1) connection tries to opportunistically retransmit data
      // when sending a packet of a different packet number space, or
      // 2) path MTU decreases, or
      // 3) packet header size increases (e.g., packet number length
      // increases).
      QUIC_CODE_COUNT(quic_retransmit_frames_failed);
      return;
    }
    QUIC_CODE_COUNT(quic_retransmit_frames_succeeded);
  } else {
    unacked_packets_.NotifyFramesLost(*transmission_info, transmission_type);

    if (!transmission_info->retransmittable_frames.empty()) {
      if (transmission_type == LOSS_RETRANSMISSION) {
        // Record the first packet sent after loss, which allows to wait 1
        // more RTT before giving up on this lost packet.
        transmission_info->first_sent_after_loss =
            unacked_packets_.largest_sent_packet() + 1;
      } else {
        // Clear the recorded first packet sent after loss when version or
        // encryption changes.
        transmission_info->first_sent_after_loss.Clear();
      }
    }
  }

  // Get the latest transmission_info here as it can be invalidated after
  // HandleRetransmission adding new sent packets into unacked_packets_.
  transmission_info =
      unacked_packets_.GetMutableTransmissionInfo(packet_number);

  // Update packet state according to transmission type.
  transmission_info->state =
      QuicUtils::RetransmissionTypeToPacketState(transmission_type);
}

void QuicSentPacketManager::RecordOneSpuriousRetransmission(
    const QuicTransmissionInfo& info) {
  stats_->bytes_spuriously_retransmitted += info.bytes_sent;
  ++stats_->packets_spuriously_retransmitted;
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnSpuriousPacketRetransmission(info.transmission_type,
                                                    info.bytes_sent);
  }
}

void QuicSentPacketManager::MarkPacketHandled(QuicPacketNumber packet_number,
                                              QuicTransmissionInfo* info,
                                              QuicTime ack_receive_time,
                                              QuicTime::Delta ack_delay_time,
                                              QuicTime receive_timestamp) {
  if (info->has_ack_frequency) {
    for (const auto& frame : info->retransmittable_frames) {
      if (frame.type == ACK_FREQUENCY_FRAME) {
        OnAckFrequencyFrameAcked(*frame.ack_frequency_frame);
      }
    }
  }
  // Try to aggregate acked stream frames if acked packet is not a
  // retransmission.
  if (info->transmission_type == NOT_RETRANSMISSION) {
    unacked_packets_.MaybeAggregateAckedStreamFrame(*info, ack_delay_time,
                                                    receive_timestamp);
  } else {
    unacked_packets_.NotifyAggregatedStreamFrameAcked(ack_delay_time);
    const bool new_data_acked = unacked_packets_.NotifyFramesAcked(
        *info, ack_delay_time, receive_timestamp);
    if (!new_data_acked && info->transmission_type != NOT_RETRANSMISSION) {
      // Record as a spurious retransmission if this packet is a
      // retransmission and no new data gets acked.
      QUIC_DVLOG(1) << "Detect spurious retransmitted packet " << packet_number
                    << " transmission type: " << info->transmission_type;
      RecordOneSpuriousRetransmission(*info);
    }
  }
  if (info->state == LOST) {
    // Record as a spurious loss as a packet previously declared lost gets
    // acked.
    const PacketNumberSpace packet_number_space =
        unacked_packets_.GetPacketNumberSpace(info->encryption_level);
    const QuicPacketNumber previous_largest_acked =
        supports_multiple_packet_number_spaces()
            ? unacked_packets_.GetLargestAckedOfPacketNumberSpace(
                  packet_number_space)
            : unacked_packets_.largest_acked();
    QUIC_DVLOG(1) << "Packet " << packet_number
                  << " was detected lost spuriously, "
                     "previous_largest_acked: "
                  << previous_largest_acked;
    loss_algorithm_->SpuriousLossDetected(unacked_packets_, rtt_stats_,
                                          ack_receive_time, packet_number,
                                          previous_largest_acked);
    ++stats_->packet_spuriously_detected_lost;
  }

  if (network_change_visitor_ != nullptr &&
      info->bytes_sent > largest_mtu_acked_) {
    largest_mtu_acked_ = info->bytes_sent;
    network_change_visitor_->OnPathMtuIncreased(largest_mtu_acked_);
  }
  unacked_packets_.RemoveFromInFlight(info);
  unacked_packets_.RemoveRetransmittability(info);
  info->state = ACKED;
}

bool QuicSentPacketManager::CanSendAckFrequency() const {
  return !peer_min_ack_delay_.IsInfinite() && handshake_finished_;
}

QuicAckFrequencyFrame QuicSentPacketManager::GetUpdatedAckFrequencyFrame()
    const {
  QuicAckFrequencyFrame frame;
  if (!CanSendAckFrequency()) {
    QUIC_BUG(quic_bug_10750_1)
        << "New AckFrequencyFrame is created while it shouldn't.";
    return frame;
  }

  QUIC_RELOADABLE_FLAG_COUNT_N(quic_can_send_ack_frequency, 1, 3);
  frame.packet_tolerance = kMaxRetransmittablePacketsBeforeAck;
  auto rtt = use_smoothed_rtt_in_ack_delay_ ? rtt_stats_.SmoothedOrInitialRtt()
                                            : rtt_stats_.MinOrInitialRtt();
  frame.max_ack_delay = rtt * kPeerAckDecimationDelay;
  frame.max_ack_delay = std::max(frame.max_ack_delay, peer_min_ack_delay_);
  // TODO(haoyuewang) Remove this once kDefaultMinAckDelayTimeMs is updated to
  // 5 ms on the client side.
  frame.max_ack_delay =
      std::max(frame.max_ack_delay,
               QuicTime::Delta::FromMilliseconds(kDefaultMinAckDelayTimeMs));
  return frame;
}

void QuicSentPacketManager::RecordEcnMarkingSent(QuicEcnCodepoint ecn_codepoint,
                                                 EncryptionLevel level) {
  PacketNumberSpace space = QuicUtils::GetPacketNumberSpace(level);
  switch (ecn_codepoint) {
    case ECN_NOT_ECT:
      break;
    case ECN_ECT0:
      ++ect0_packets_sent_[space];
      break;
    case ECN_ECT1:
      ++ect1_packets_sent_[space];
      break;
    case ECN_CE:
      // Test only: endpoints MUST NOT send CE. As CE reports will have to
      // correspond to either an ECT(0) or an ECT(1) packet to be valid, just
      // increment both to avoid validation failure.
      ++ect0_packets_sent_[space];
      ++ect1_packets_sent_[space];
      break;
  }
}

bool QuicSentPacketManager::OnPacketSent(
    SerializedPacket* mutable_packet, QuicTime sent_time,
    TransmissionType transmission_type,
    HasRetransmittableData has_retransmittable_data, bool measure_rtt,
    QuicEcnCodepoint ecn_codepoint) {
  const SerializedPacket& packet = *mutable_packet;
  QuicPacketNumber packet_number = packet.packet_number;
  QUICHE_DCHECK_LE(FirstSendingPacketNumber(), packet_number);
  QUICHE_DCHECK(!unacked_packets_.IsUnacked(packet_number));
  QUIC_BUG_IF(quic_bug_10750_2, packet.encrypted_length == 0)
      << "Cannot send empty packets.";
  if (pending_timer_transmission_count_ > 0) {
    --pending_timer_transmission_count_;
  }

  bool in_flight = has_retransmittable_data == HAS_RETRANSMITTABLE_DATA;
  if (ignore_pings_ && mutable_packet->retransmittable_frames.size() == 1 &&
      mutable_packet->retransmittable_frames[0].type == PING_FRAME) {
    // Dot not use PING only packet for RTT measure or congestion control.
    in_flight = false;
    measure_rtt = false;
  }
  if (using_pacing_) {
    pacing_sender_.OnPacketSent(sent_time, unacked_packets_.bytes_in_flight(),
                                packet_number, packet.encrypted_length,
                                has_retransmittable_data);
  } else {
    send_algorithm_->OnPacketSent(sent_time, unacked_packets_.bytes_in_flight(),
                                  packet_number, packet.encrypted_length,
                                  has_retransmittable_data);
  }

  // Deallocate message data in QuicMessageFrame immediately after packet
  // sent.
  if (packet.has_message) {
    for (auto& frame : mutable_packet->retransmittable_frames) {
      if (frame.type == MESSAGE_FRAME) {
        frame.message_frame->message_data.clear();
        frame.message_frame->message_length = 0;
      }
    }
  }

  if (packet.has_ack_frequency) {
    for (const auto& frame : packet.retransmittable_frames) {
      if (frame.type == ACK_FREQUENCY_FRAME) {
        OnAckFrequencyFrameSent(*frame.ack_frequency_frame);
      }
    }
  }
  RecordEcnMarkingSent(ecn_codepoint, packet.encryption_level);
  unacked_packets_.AddSentPacket(mutable_packet, transmission_type, sent_time,
                                 in_flight, measure_rtt, ecn_codepoint);
  // Reset the retransmission timer anytime a pending packet is sent.
  return in_flight;
}

const QuicTransmissionInfo& QuicSentPacketManager::AddDispatcherSentPacket(
    const DispatcherSentPacket& packet) {
  QUIC_DVLOG(1) << "QuicSPM: Adding dispatcher sent packet "
                << packet.packet_number << ", size: " << packet.bytes_sent
                << ", sent_time: " << packet.sent_time
                << ", largest_acked: " << packet.largest_acked;
  if (using_pacing_) {
    pacing_sender_.OnPacketSent(
        packet.sent_time, unacked_packets_.bytes_in_flight(),
        packet.packet_number, packet.bytes_sent, NO_RETRANSMITTABLE_DATA);
  } else {
    send_algorithm_->OnPacketSent(
        packet.sent_time, unacked_packets_.bytes_in_flight(),
        packet.packet_number, packet.bytes_sent, NO_RETRANSMITTABLE_DATA);
  }
  return unacked_packets_.AddDispatcherSentPacket(packet);
}

QuicSentPacketManager::RetransmissionTimeoutMode
QuicSentPacketManager::OnRetransmissionTimeout() {
  QUICHE_DCHECK(unacked_packets_.HasInFlightPackets() ||
                (handshake_mode_disabled_ && !handshake_finished_));
  QUICHE_DCHECK_EQ(0u, pending_timer_transmission_count_);
  // Handshake retransmission, timer based loss detection, TLP, and RTO are
  // implemented with a single alarm. The handshake alarm is set when the
  // handshake has not completed, the loss alarm is set when the loss detection
  // algorithm says to, and the TLP and  RTO alarms are set after that.
  // The TLP alarm is always set to run for under an RTO.
  switch (GetRetransmissionMode()) {
    case HANDSHAKE_MODE:
      QUICHE_DCHECK(!handshake_mode_disabled_);
      ++stats_->crypto_retransmit_count;
      RetransmitCryptoPackets();
      return HANDSHAKE_MODE;
    case LOSS_MODE: {
      ++stats_->loss_timeout_count;
      QuicByteCount prior_in_flight = unacked_packets_.bytes_in_flight();
      const QuicTime now = clock_->Now();
      InvokeLossDetection(now);
      MaybeInvokeCongestionEvent(false, prior_in_flight, now,
                                 std::optional<QuicEcnCounts>(),
                                 peer_ack_ecn_counts_[APPLICATION_DATA]);
      return LOSS_MODE;
    }
    case PTO_MODE:
      QUIC_DVLOG(1) << ENDPOINT << "PTO mode";
      ++stats_->pto_count;
      if (handshake_mode_disabled_ && !handshake_finished_) {
        ++stats_->crypto_retransmit_count;
      }
      ++consecutive_pto_count_;
      pending_timer_transmission_count_ = 1;
      return PTO_MODE;
  }
  QUIC_BUG(quic_bug_10750_3)
   
"""


```