Response:
The user is asking for an analysis of the provided C++ source code file `quic_connection.cc`. The request includes several specific points to address:

1. **Functionality:** What does this code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript code? If so, how?
3. **Logical Reasoning (with examples):**  Are there any logical deductions being made? Provide input and output examples.
4. **Common User/Programming Errors:** What mistakes might developers make when using this code?
5. **User Operation to Reach This Code:** How might a user's actions lead to this code being executed? (Debugging context)
6. **Summary of Functionality:** A concise overview of the code's purpose.

Since this is part 1 of a 10-part series, the focus should be on the initial aspects of the `QuicConnection` class definition and its core responsibilities as presented in this section of the code.

**Plan:**

1. **High-Level Functionality:** Read the code and identify the main purpose of the `QuicConnection` class. Focus on its role in managing a QUIC connection.
2. **JavaScript Interaction:**  Scan the code for any explicit links to JavaScript. Given this is a low-level networking component, direct interaction is unlikely. Explain the likely indirect relationship via the browser.
3. **Logical Reasoning:** Look for conditional statements and decisions within the code. Consider examples related to connection ID handling, version negotiation, and error conditions.
4. **Common Errors:**  Think about common mistakes developers might make when configuring or using a QUIC connection, based on the provided code (e.g., incorrect configuration, assuming certain states, etc.).
5. **User Path:**  Describe the user's high-level actions that would initiate a network request using QUIC, leading to this code's execution.
6. **Summarize Part 1:**  Provide a concise summary of the core functionalities revealed in this initial code snippet.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件的第一部分，它定义了 Chromium 网络栈中 QUIC 协议连接的核心逻辑。  以下是根据您提供的代码片段的功能归纳：

**功能归纳 (基于第 1 部分):**

`QuicConnection` 类是 QUIC 连接的核心实现，负责管理一个 QUIC 连接的生命周期和状态。  在代码的这一部分，其主要功能包括：

1. **连接的初始化和配置:**
   - 创建和初始化 `QuicConnection` 对象，包括设置服务器连接 ID、本地和对端地址、版本信息等。
   - 安装初始加密器和解密器（ENCRYPTION_INITIAL），用于处理连接建立初期的加密数据包。
   - 管理连接的配置信息，包括从 `QuicConfig` 对象中读取和应用连接参数，例如超时时间、连接 ID 相关参数、拥塞控制算法等。
   - 处理版本协商，包括选择与对端兼容的 QUIC 版本。

2. **数据包的接收和处理:**
   - 作为 `QuicFramer` 的访问者，处理接收到的 QUIC 数据包，包括检查协议版本不匹配等错误。
   - 处理版本协商数据包，特别是客户端接收到服务器的版本协商数据包。

3. **连接状态的管理:**
   - 维护连接的各种状态，例如是否已连接 (`connected_`)，加密级别 (`encryption_level_`)，是否完成版本协商 (`version_negotiated_`) 等。
   - 管理连接的路径信息，包括默认路径 (`default_path_`) 以及可能的迁移路径。
   - 维护对端地址信息，并处理可能的地址变更。

4. **数据包的发送:**
   - 管理数据包的创建和序列化 (`QuicPacketCreator`)。
   - 管理已发送数据包的状态，用于重传和拥塞控制 (`SentPacketManager`)。
   - 处理发送失败的情况。

5. **错误处理和连接关闭:**
   - 监测和处理连接过程中出现的错误，并执行连接关闭操作。

6. **拥塞控制和流量控制:**
   - 集成拥塞控制算法 (`SendAlgorithmInterface`) 来管理发送速率。
   -  与 `uber_received_packet_manager_` 协同工作，处理接收到的数据包并生成确认帧。

7. **心跳和活性检测:**
   -  实现客户端的活性检测机制，定期发送探测包以确认连接的有效性。

8. **MTU 探测:**
   - 支持最大传输单元 (MTU) 的探测，以优化数据包大小。

**与 JavaScript 的功能关系：**

`quic_connection.cc` 本身是用 C++ 编写的，并不直接包含 JavaScript 代码。然而，它在 Chromium 浏览器中作为网络栈的一部分运行，负责处理底层的 QUIC 连接。JavaScript 代码（例如，网页中的 JavaScript）可以通过浏览器提供的 Web API（例如 Fetch API 或 WebSocket API）发起网络请求。

**举例说明：**

1. **用户在浏览器中访问一个使用 HTTPS 的网站，并且该网站启用了 QUIC 协议。**
2. **浏览器底层的网络栈会尝试建立一个 QUIC 连接。**
3. **`QuicConnection` 类的实例会被创建，负责管理这个连接。**
4. **如果服务器不支持客户端请求的 QUIC 版本，服务器可能会返回一个 Version Negotiation 包。**
5. **`QuicConnection::OnVersionNegotiationPacket` 函数（在您提供的代码片段中）会被调用来处理这个包，并可能触发连接关闭或重试。**

**逻辑推理 (假设输入与输出):**

**假设输入：**

- 接收到一个版本协商数据包 (`QuicVersionNegotiationPacket`)，其中包含服务器支持的版本列表 `packet.versions = {Q050, H3-29}`。
- 当前连接使用的版本是 `Q046`。
- 客户端支持的版本列表是 `framer_.supported_versions() = {Q046, Q050}`。

**逻辑推理：**

- `QuicConnection::OnVersionNegotiationPacket` 会检查 `packet.versions` 中是否包含当前连接的版本 `Q046`。
- 如果不包含（如本例），则客户端知道服务器不支持当前版本。
- 接下来，代码会检查 `packet.versions` 中是否有客户端支持的版本。在本例中，`Q050` 是客户端支持的。
- 如果找到客户端支持的版本，但与当前版本不同，则表明服务器需要客户端切换版本。
- 如果 `packet.versions` 中包含当前版本，则表明服务器本应接受连接，发送版本协商包是错误行为，连接会被关闭并记录错误。

**输出：**

- 如果 `packet.versions` 中包含 `Q050`，但 *不包含* `Q046`，则客户端可能会关闭当前连接，并尝试使用 `Q050` 重新连接（这部分逻辑可能在更高层处理，但 `OnVersionNegotiationPacket` 负责识别这种情况）。
- 如果 `packet.versions` 中 *包含* `Q046`，则会输出警告信息，并关闭连接，错误码为 `QUIC_INVALID_VERSION_NEGOTIATION_PACKET`。

**用户或编程常见的使用错误 (举例说明):**

1. **配置错误的版本:**  如果客户端或服务器配置了不兼容的 QUIC 版本，可能会导致连接建立失败。例如，客户端只支持旧版本，而服务器只支持新版本。`QuicConnection` 在版本协商阶段会检测到这种不匹配。

2. **错误地假设连接状态:** 开发者可能会在代码中错误地假设连接已经建立或加密级别已经提升到特定状态，从而调用不适用的函数或访问不正确的资源。例如，在握手完成之前尝试发送应用数据可能会失败。

3. **不正确的连接 ID 管理:**  QUIC 连接 ID 的管理至关重要，如果连接两端对连接 ID 的理解不一致，会导致数据包无法正确路由或被丢弃。例如，客户端在迁移路径后没有正确更新使用的源连接 ID。

**用户操作如何一步步到达这里 (调试线索):**

假设用户遇到一个网站连接问题，怀疑是 QUIC 协议导致的，并尝试进行调试：

1. **用户在 Chromium 浏览器中输入一个网址，该网站支持 QUIC。**
2. **浏览器网络栈尝试与服务器建立 QUIC 连接。**
3. **如果服务器响应一个 Version Negotiation 数据包，表明客户端的初始版本请求与服务器支持的版本不匹配。**
4. **Chromium 的 QUIC 实现会调用 `QuicConnection::OnVersionNegotiationPacket` 来处理这个数据包。**
5. **开发者可以通过调试工具（例如 Chrome 的 `chrome://inspect/#devices` 或使用 gdb 等工具）设置断点在 `QuicConnection::OnVersionNegotiationPacket` 函数内部，来检查接收到的版本信息和连接的当前状态，从而了解版本协商失败的原因。**
6. **检查 `packet.versions` 的内容，以及 `framer_.supported_versions()` 返回的值，可以帮助确定客户端和服务器之间是否存在共同支持的版本。**

总而言之，`quic_connection.cc` 的这部分代码是 QUIC 连接管理的基础，涵盖了连接的初始化、版本协商以及初步的数据包处理和错误处理机制。它是理解 Chromium QUIC 实现的关键入口点。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_connection.h"

#include <string.h>
#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packet_creator.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_path_validator.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_client_stats.h"
#include "quiche/quic/platform/api/quic_exported_stats.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_flag_utils.h"
#include "quiche/common/platform/api/quiche_testvalue.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

class QuicDecrypter;
class QuicEncrypter;

namespace {

// Maximum number of consecutive sent nonretransmittable packets.
const QuicPacketCount kMaxConsecutiveNonRetransmittablePackets = 19;

// The minimum release time into future in ms.
const int kMinReleaseTimeIntoFutureMs = 1;

// The maximum number of recorded client addresses.
const size_t kMaxReceivedClientAddressSize = 20;

// An arbitrary limit on the number of PTOs before giving up on ECN, if no ECN-
// marked packet is acked. Avoids abandoning ECN because of one burst loss,
// but doesn't allow multiple RTTs of user delay in the hope of using ECN.
const uint8_t kEcnPtoLimit = 2;

// When the clearer goes out of scope, the coalesced packet gets cleared.
class ScopedCoalescedPacketClearer {
 public:
  explicit ScopedCoalescedPacketClearer(QuicCoalescedPacket* coalesced)
      : coalesced_(coalesced) {}
  ~ScopedCoalescedPacketClearer() { coalesced_->Clear(); }

 private:
  QuicCoalescedPacket* coalesced_;  // Unowned.
};

// Whether this incoming packet is allowed to replace our connection ID.
bool PacketCanReplaceServerConnectionId(const QuicPacketHeader& header,
                                        Perspective perspective) {
  return perspective == Perspective::IS_CLIENT &&
         header.form == IETF_QUIC_LONG_HEADER_PACKET &&
         header.version.IsKnown() &&
         header.version.AllowsVariableLengthConnectionIds() &&
         (header.long_packet_type == INITIAL ||
          header.long_packet_type == RETRY);
}

// Due to a lost Initial packet, a Handshake packet might use a new connection
// ID we haven't seen before. We shouldn't update the connection ID based on
// this, but should buffer the packet in case it works out.
bool NewServerConnectionIdMightBeValid(const QuicPacketHeader& header,
                                       Perspective perspective,
                                       bool connection_id_already_replaced) {
  return perspective == Perspective::IS_CLIENT &&
         header.form == IETF_QUIC_LONG_HEADER_PACKET &&
         header.version.IsKnown() &&
         header.version.AllowsVariableLengthConnectionIds() &&
         header.long_packet_type == HANDSHAKE &&
         !connection_id_already_replaced;
}

CongestionControlType GetDefaultCongestionControlType() {
  if (GetQuicReloadableFlag(quic_default_to_bbr_v2)) {
    return kBBRv2;
  }

  if (GetQuicReloadableFlag(quic_default_to_bbr)) {
    return kBBR;
  }

  return kCubicBytes;
}

bool ContainsNonProbingFrame(const SerializedPacket& packet) {
  for (const QuicFrame& frame : packet.nonretransmittable_frames) {
    if (!QuicUtils::IsProbingFrame(frame.type)) {
      return true;
    }
  }
  for (const QuicFrame& frame : packet.retransmittable_frames) {
    if (!QuicUtils::IsProbingFrame(frame.type)) {
      return true;
    }
  }
  return false;
}

}  // namespace

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

QuicConnection::QuicConnection(
    QuicConnectionId server_connection_id,
    QuicSocketAddress initial_self_address,
    QuicSocketAddress initial_peer_address,
    QuicConnectionHelperInterface* helper, QuicAlarmFactory* alarm_factory,
    QuicPacketWriter* writer, bool owns_writer, Perspective perspective,
    const ParsedQuicVersionVector& supported_versions,
    ConnectionIdGeneratorInterface& generator)
    : framer_(supported_versions, helper->GetClock()->ApproximateNow(),
              perspective, server_connection_id.length()),
      current_packet_content_(NO_FRAMES_RECEIVED),
      is_current_packet_connectivity_probing_(false),
      has_path_challenge_in_current_packet_(false),
      current_effective_peer_migration_type_(NO_CHANGE),
      helper_(helper),
      alarm_factory_(alarm_factory),
      per_packet_options_(nullptr),
      writer_(writer),
      owns_writer_(owns_writer),
      encryption_level_(ENCRYPTION_INITIAL),
      clock_(helper->GetClock()),
      random_generator_(helper->GetRandomGenerator()),
      client_connection_id_is_set_(false),
      direct_peer_address_(initial_peer_address),
      default_path_(initial_self_address, QuicSocketAddress(),
                    /*client_connection_id=*/EmptyQuicConnectionId(),
                    server_connection_id,
                    /*stateless_reset_token=*/std::nullopt),
      active_effective_peer_migration_type_(NO_CHANGE),
      support_key_update_for_connection_(false),
      current_packet_data_(nullptr),
      should_last_packet_instigate_acks_(false),
      max_undecryptable_packets_(0),
      max_tracked_packets_(GetQuicFlag(quic_max_tracked_packet_count)),
      idle_timeout_connection_close_behavior_(
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET),
      num_rtos_for_blackhole_detection_(0),
      uber_received_packet_manager_(&stats_),
      pending_retransmission_alarm_(false),
      defer_send_in_response_to_packets_(false),
      arena_(),
      alarms_(this, *alarm_factory_, arena_),
      visitor_(nullptr),
      debug_visitor_(nullptr),
      packet_creator_(server_connection_id, &framer_, random_generator_, this),
      last_received_packet_info_(clock_->ApproximateNow()),
      sent_packet_manager_(perspective, clock_, random_generator_, &stats_,
                           GetDefaultCongestionControlType()),
      version_negotiated_(false),
      perspective_(perspective),
      connected_(true),
      can_truncate_connection_ids_(perspective == Perspective::IS_SERVER),
      mtu_probe_count_(0),
      previous_validated_mtu_(0),
      peer_max_packet_size_(kDefaultMaxPacketSizeTransportParam),
      largest_received_packet_size_(0),
      write_error_occurred_(false),
      consecutive_num_packets_with_no_retransmittable_frames_(0),
      max_consecutive_num_packets_with_no_retransmittable_frames_(
          kMaxConsecutiveNonRetransmittablePackets),
      bundle_retransmittable_with_pto_ack_(false),
      last_control_frame_id_(kInvalidControlFrameId),
      is_path_degrading_(false),
      flow_label_has_changed_(false),
      processing_ack_frame_(false),
      supports_release_time_(false),
      release_time_into_future_(QuicTime::Delta::Zero()),
      blackhole_detector_(this, alarms_.network_blackhole_detector_alarm()),
      idle_network_detector_(this, clock_->ApproximateNow(),
                             alarms_.idle_network_detector_alarm()),
      path_validator_(alarm_factory_, &arena_, this, random_generator_, clock_,
                      &context_),
      ping_manager_(perspective, this, alarms_.ping_alarm()),
      multi_port_probing_interval_(kDefaultMultiPortProbingInterval),
      connection_id_generator_(generator),
      received_client_addresses_cache_(kMaxReceivedClientAddressSize) {
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT ||
                default_path_.self_address.IsInitialized());

  QUIC_DLOG(INFO) << ENDPOINT << "Created connection with server connection ID "
                  << server_connection_id
                  << " and version: " << ParsedQuicVersionToString(version());

  QUIC_BUG_IF(quic_bug_12714_2, !QuicUtils::IsConnectionIdValidForVersion(
                                    server_connection_id, transport_version()))
      << "QuicConnection: attempted to use server connection ID "
      << server_connection_id << " which is invalid with version " << version();
  framer_.set_visitor(this);
  stats_.connection_creation_time = clock_->ApproximateNow();
  // TODO(ianswett): Supply the NetworkChangeVisitor as a constructor argument
  // and make it required non-null, because it's always used.
  sent_packet_manager_.SetNetworkChangeVisitor(this);
  // Allow the packet writer to potentially reduce the packet size to a value
  // even smaller than kDefaultMaxPacketSize.
  SetMaxPacketLength(perspective_ == Perspective::IS_SERVER
                         ? kDefaultServerMaxPacketSize
                         : kDefaultMaxPacketSize);
  uber_received_packet_manager_.set_max_ack_ranges(255);
  MaybeEnableMultiplePacketNumberSpacesSupport();
  QUICHE_DCHECK(perspective_ == Perspective::IS_CLIENT ||
                supported_versions.size() == 1);
  InstallInitialCrypters(default_path_.server_connection_id);

  // On the server side, version negotiation has been done by the dispatcher,
  // and the server connection is created with the right version.
  if (perspective_ == Perspective::IS_SERVER) {
    version_negotiated_ = true;
  }
  if (default_enable_5rto_blackhole_detection_) {
    num_rtos_for_blackhole_detection_ = 5;
    if (GetQuicReloadableFlag(quic_disable_server_blackhole_detection) &&
        perspective_ == Perspective::IS_SERVER) {
      QUIC_RELOADABLE_FLAG_COUNT(quic_disable_server_blackhole_detection);
      blackhole_detection_disabled_ = true;
    }
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    AddKnownServerAddress(initial_peer_address);
  }
  packet_creator_.SetDefaultPeerAddress(initial_peer_address);
}

void QuicConnection::InstallInitialCrypters(QuicConnectionId connection_id) {
  CrypterPair crypters;
  CryptoUtils::CreateInitialObfuscators(perspective_, version(), connection_id,
                                        &crypters);
  SetEncrypter(ENCRYPTION_INITIAL, std::move(crypters.encrypter));
  if (version().KnowsWhichDecrypterToUse()) {
    InstallDecrypter(ENCRYPTION_INITIAL, std::move(crypters.decrypter));
  } else {
    SetDecrypter(ENCRYPTION_INITIAL, std::move(crypters.decrypter));
  }
}

QuicConnection::~QuicConnection() {
  QUICHE_DCHECK_GE(stats_.max_egress_mtu, long_term_mtu_);
  if (owns_writer_) {
    delete writer_;
  }
  ClearQueuedPackets();
  if (stats_
          .num_tls_server_zero_rtt_packets_received_after_discarding_decrypter >
      0) {
    QUIC_CODE_COUNT_N(
        quic_server_received_tls_zero_rtt_packet_after_discarding_decrypter, 2,
        3);
  } else {
    QUIC_CODE_COUNT_N(
        quic_server_received_tls_zero_rtt_packet_after_discarding_decrypter, 3,
        3);
  }
}

void QuicConnection::ClearQueuedPackets() { buffered_packets_.clear(); }

bool QuicConnection::ValidateConfigConnectionIds(const QuicConfig& config) {
  QUICHE_DCHECK(config.negotiated());
  if (!version().UsesTls()) {
    // QUIC+TLS is required to transmit connection ID transport parameters.
    return true;
  }
  // This function validates connection IDs as defined in IETF draft-28 and
  // later.

  // Validate initial_source_connection_id.
  QuicConnectionId expected_initial_source_connection_id;
  if (perspective_ == Perspective::IS_CLIENT) {
    expected_initial_source_connection_id = default_path_.server_connection_id;
  } else {
    expected_initial_source_connection_id = default_path_.client_connection_id;
  }
  if (!config.HasReceivedInitialSourceConnectionId() ||
      config.ReceivedInitialSourceConnectionId() !=
          expected_initial_source_connection_id) {
    std::string received_value;
    if (config.HasReceivedInitialSourceConnectionId()) {
      received_value = config.ReceivedInitialSourceConnectionId().ToString();
    } else {
      received_value = "none";
    }
    std::string error_details =
        absl::StrCat("Bad initial_source_connection_id: expected ",
                     expected_initial_source_connection_id.ToString(),
                     ", received ", received_value);
    CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    // Validate original_destination_connection_id.
    if (!config.HasReceivedOriginalConnectionId() ||
        config.ReceivedOriginalConnectionId() !=
            GetOriginalDestinationConnectionId()) {
      std::string received_value;
      if (config.HasReceivedOriginalConnectionId()) {
        received_value = config.ReceivedOriginalConnectionId().ToString();
      } else {
        received_value = "none";
      }
      std::string error_details =
          absl::StrCat("Bad original_destination_connection_id: expected ",
                       GetOriginalDestinationConnectionId().ToString(),
                       ", received ", received_value);
      CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION, error_details,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return false;
    }
    // Validate retry_source_connection_id.
    if (retry_source_connection_id_.has_value()) {
      // We received a RETRY packet, validate that the retry source
      // connection ID from the config matches the one from the RETRY.
      if (!config.HasReceivedRetrySourceConnectionId() ||
          config.ReceivedRetrySourceConnectionId() !=
              *retry_source_connection_id_) {
        std::string received_value;
        if (config.HasReceivedRetrySourceConnectionId()) {
          received_value = config.ReceivedRetrySourceConnectionId().ToString();
        } else {
          received_value = "none";
        }
        std::string error_details =
            absl::StrCat("Bad retry_source_connection_id: expected ",
                         retry_source_connection_id_->ToString(), ", received ",
                         received_value);
        CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION, error_details,
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        return false;
      }
    } else {
      // We did not receive a RETRY packet, make sure we did not receive the
      // retry_source_connection_id transport parameter.
      if (config.HasReceivedRetrySourceConnectionId()) {
        std::string error_details = absl::StrCat(
            "Bad retry_source_connection_id: did not receive RETRY but "
            "received ",
            config.ReceivedRetrySourceConnectionId().ToString());
        CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION, error_details,
                        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
        return false;
      }
    }
  }
  return true;
}

void QuicConnection::SetFromConfig(const QuicConfig& config) {
  if (config.negotiated()) {
    if (ShouldFixTimeouts(config)) {
      if (!IsHandshakeComplete()) {
        QUIC_RELOADABLE_FLAG_COUNT_N(quic_fix_timeouts, 1, 2);
        SetNetworkTimeouts(config.max_time_before_crypto_handshake(),
                           config.max_idle_time_before_crypto_handshake());
      } else {
        QUIC_BUG(set_from_config_after_handshake_complete)
            << "SetFromConfig is called after Handshake complete";
        // Network timeouts has been set by session on handshake complete.
      }
    } else {
      // Handshake complete, set handshake timeout to Infinite.
      SetNetworkTimeouts(QuicTime::Delta::Infinite(),
                         config.IdleNetworkTimeout());
    }
    idle_timeout_connection_close_behavior_ =
        ConnectionCloseBehavior::SILENT_CLOSE;
    if (perspective_ == Perspective::IS_SERVER) {
      idle_timeout_connection_close_behavior_ = ConnectionCloseBehavior::
          SILENT_CLOSE_WITH_CONNECTION_CLOSE_PACKET_SERIALIZED;
    }
    if (config.HasClientRequestedIndependentOption(kNSLC, perspective_)) {
      idle_timeout_connection_close_behavior_ =
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET;
    }
    if (!ValidateConfigConnectionIds(config)) {
      return;
    }
    support_key_update_for_connection_ = version().UsesTls();
    framer_.SetKeyUpdateSupportForConnection(
        support_key_update_for_connection_);
  } else {
    SetNetworkTimeouts(config.max_time_before_crypto_handshake(),
                       config.max_idle_time_before_crypto_handshake());
  }

  if (version().HasIetfQuicFrames() &&
      config.HasReceivedPreferredAddressConnectionIdAndToken()) {
    QuicNewConnectionIdFrame frame;
    std::tie(frame.connection_id, frame.stateless_reset_token) =
        config.ReceivedPreferredAddressConnectionIdAndToken();
    frame.sequence_number = 1u;
    frame.retire_prior_to = 0u;
    OnNewConnectionIdFrameInner(frame);
  }

  if (config.DisableConnectionMigration()) {
    active_migration_disabled_ = true;
  }

  sent_packet_manager_.SetFromConfig(config);
  if (perspective_ == Perspective::IS_SERVER &&
      config.HasClientSentConnectionOption(kAFF2, perspective_)) {
    send_ack_frequency_on_handshake_completion_ = true;
  }
  if (config.HasReceivedBytesForConnectionId() &&
      can_truncate_connection_ids_) {
    packet_creator_.SetServerConnectionIdLength(
        config.ReceivedBytesForConnectionId());
  }
  max_undecryptable_packets_ = config.max_undecryptable_packets();

  if (!GetQuicReloadableFlag(quic_enable_mtu_discovery_at_server)) {
    if (config.HasClientRequestedIndependentOption(kMTUH, perspective_)) {
      SetMtuDiscoveryTarget(kMtuDiscoveryTargetPacketSizeHigh);
    }
  }
  if (config.HasClientRequestedIndependentOption(kMTUL, perspective_)) {
    SetMtuDiscoveryTarget(kMtuDiscoveryTargetPacketSizeLow);
  }
  if (default_enable_5rto_blackhole_detection_) {
    if (config.HasClientRequestedIndependentOption(kCBHD, perspective_)) {
      QUIC_CODE_COUNT(quic_client_only_blackhole_detection);
      blackhole_detection_disabled_ = true;
    }
    if (config.HasClientSentConnectionOption(kNBHD, perspective_)) {
      blackhole_detection_disabled_ = true;
    }
  }

  if (config.HasClientRequestedIndependentOption(kFIDT, perspective_)) {
    idle_network_detector_.enable_shorter_idle_timeout_on_sent_packet();
  }
  if (perspective_ == Perspective::IS_CLIENT && version().HasIetfQuicFrames()) {
    // Only conduct those experiments in IETF QUIC because random packets may
    // elicit reset and gQUIC PUBLIC_RESET will cause connection close.
    if (config.HasClientRequestedIndependentOption(kROWF, perspective_)) {
      retransmittable_on_wire_behavior_ = SEND_FIRST_FORWARD_SECURE_PACKET;
    }
    if (config.HasClientRequestedIndependentOption(kROWR, perspective_)) {
      retransmittable_on_wire_behavior_ = SEND_RANDOM_BYTES;
    }
  }
  if (config.HasClientRequestedIndependentOption(k3AFF, perspective_)) {
    anti_amplification_factor_ = 3;
  }
  if (config.HasClientRequestedIndependentOption(k10AF, perspective_)) {
    anti_amplification_factor_ = 10;
  }

  if (GetQuicReloadableFlag(quic_enable_server_on_wire_ping) &&
      perspective_ == Perspective::IS_SERVER &&
      config.HasClientSentConnectionOption(kSRWP, perspective_)) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_enable_server_on_wire_ping);
    set_initial_retransmittable_on_wire_timeout(
        QuicTime::Delta::FromMilliseconds(200));
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSetFromConfig(config);
  }
  uber_received_packet_manager_.SetFromConfig(config, perspective_);
  if (config.HasClientSentConnectionOption(k5RTO, perspective_)) {
    num_rtos_for_blackhole_detection_ = 5;
  }
  if (config.HasClientSentConnectionOption(k6PTO, perspective_) ||
      config.HasClientSentConnectionOption(k7PTO, perspective_) ||
      config.HasClientSentConnectionOption(k8PTO, perspective_)) {
    num_rtos_for_blackhole_detection_ = 5;
  }
  if (config.HasReceivedStatelessResetToken()) {
    default_path_.stateless_reset_token = config.ReceivedStatelessResetToken();
  }
  if (config.HasReceivedAckDelayExponent()) {
    framer_.set_peer_ack_delay_exponent(config.ReceivedAckDelayExponent());
  }
  if (config.HasClientSentConnectionOption(kEACK, perspective_)) {
    bundle_retransmittable_with_pto_ack_ = true;
  }
  if (config.HasClientSentConnectionOption(kDFER, perspective_)) {
    defer_send_in_response_to_packets_ = false;
  }
  if (perspective_ == Perspective::IS_CLIENT &&
      config.HasClientSentConnectionOption(kCDFR, perspective_)) {
    defer_send_in_response_to_packets_ = true;
  }

  if (config.HasClientRequestedIndependentOption(kINVC, perspective_)) {
    send_connection_close_for_invalid_version_ = true;
  }

  if (version().HasIetfQuicFrames() &&
      config.HasReceivedPreferredAddressConnectionIdAndToken() &&
      config.SupportsServerPreferredAddress(perspective_)) {
    if (self_address().host().IsIPv4() &&
        config.HasReceivedIPv4AlternateServerAddress()) {
      received_server_preferred_address_ =
          config.ReceivedIPv4AlternateServerAddress();
    } else if (self_address().host().IsIPv6() &&
               config.HasReceivedIPv6AlternateServerAddress()) {
      received_server_preferred_address_ =
          config.ReceivedIPv6AlternateServerAddress();
    }
    if (received_server_preferred_address_.IsInitialized()) {
      QUICHE_DLOG(INFO) << ENDPOINT << "Received server preferred address: "
                        << received_server_preferred_address_;
      if (config.HasClientRequestedIndependentOption(kSPA2, perspective_)) {
        accelerated_server_preferred_address_ = true;
        visitor_->OnServerPreferredAddressAvailable(
            received_server_preferred_address_);
      }
    }
  }

  if (config.HasReceivedMaxPacketSize()) {
    peer_max_packet_size_ = config.ReceivedMaxPacketSize();
    packet_creator_.SetMaxPacketLength(
        GetLimitedMaxPacketSize(packet_creator_.max_packet_length()));
  }
  if (config.HasReceivedMaxDatagramFrameSize()) {
    packet_creator_.SetMaxDatagramFrameSize(
        config.ReceivedMaxDatagramFrameSize());
  }

  supports_release_time_ =
      writer_ != nullptr && writer_->SupportsReleaseTime() &&
      !config.HasClientSentConnectionOption(kNPCO, perspective_);

  if (supports_release_time_) {
    UpdateReleaseTimeIntoFuture();
  }

  if (perspective_ == Perspective::IS_CLIENT && version().HasIetfQuicFrames() &&
      config.HasClientRequestedIndependentOption(kMPQC, perspective_)) {
    multi_port_stats_ = std::make_unique<MultiPortStats>();
    if (config.HasClientRequestedIndependentOption(kMPQM, perspective_)) {
      multi_port_migration_enabled_ = true;
    }
  }

  framer_.set_process_reset_stream_at(config.SupportsReliableStreamReset());
}

void QuicConnection::AddDispatcherSentPackets(
    absl::Span<const DispatcherSentPacket> dispatcher_sent_packets) {
  QUICHE_DCHECK_EQ(stats_.packets_sent, 0u);
  QUICHE_DCHECK_EQ(stats_.packets_sent_by_dispatcher, 0u);
  QUICHE_DCHECK(!sent_packet_manager_.GetLargestSentPacket().IsInitialized());
  if (dispatcher_sent_packets.empty()) {
    return;
  }
  stats_.packets_sent_by_dispatcher = dispatcher_sent_packets.size();

  for (const DispatcherSentPacket& packet : dispatcher_sent_packets) {
    const QuicTransmissionInfo& info =
        sent_packet_manager_.AddDispatcherSentPacket(packet);
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnPacketSent(
          packet.packet_number, info.bytes_sent, info.has_crypto_handshake,
          info.transmission_type, info.encryption_level,
          info.retransmittable_frames,
          /*nonretransmittable_frames=*/{}, info.sent_time,
          /*batch_id=*/0);
    }
  }

  packet_creator_.set_packet_number(
      dispatcher_sent_packets.back().packet_number);
}

bool QuicConnection::MaybeTestLiveness() {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  if (liveness_testing_disabled_ ||
      encryption_level_ != ENCRYPTION_FORWARD_SECURE) {
    return false;
  }
  const QuicTime idle_network_deadline =
      idle_network_detector_.GetIdleNetworkDeadline();
  if (!idle_network_deadline.IsInitialized()) {
    return false;
  }
  const QuicTime now = clock_->ApproximateNow();
  if (now > idle_network_deadline) {
    QUIC_DLOG(WARNING) << "Idle network deadline has passed";
    return false;
  }
  const QuicTime::Delta timeout = idle_network_deadline - now;
  if (2 * timeout > idle_network_detector_.idle_network_timeout()) {
    // Do not test liveness if timeout is > half timeout. This is used to
    // prevent an infinite loop for short idle timeout.
    return false;
  }
  if (!sent_packet_manager_.IsLessThanThreePTOs(timeout)) {
    return false;
  }
  QUIC_LOG_EVERY_N_SEC(INFO, 60)
      << "Testing liveness, idle_network_timeout: "
      << idle_network_detector_.idle_network_timeout()
      << ", timeout: " << timeout
      << ", Pto delay: " << sent_packet_manager_.GetPtoDelay()
      << ", smoothed_rtt: "
      << sent_packet_manager_.GetRttStats()->smoothed_rtt()
      << ", mean deviation: "
      << sent_packet_manager_.GetRttStats()->mean_deviation();
  SendConnectivityProbingPacket(writer_, peer_address());
  return true;
}

void QuicConnection::ApplyConnectionOptions(
    const QuicTagVector& connection_options) {
  sent_packet_manager_.ApplyConnectionOptions(connection_options);
}

void QuicConnection::OnSendConnectionState(
    const CachedNetworkParameters& cached_network_params) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnSendConnectionState(cached_network_params);
  }
}

void QuicConnection::OnReceiveConnectionState(
    const CachedNetworkParameters& cached_network_params) {
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnReceiveConnectionState(cached_network_params);
  }
}

void QuicConnection::ResumeConnectionState(
    const CachedNetworkParameters& cached_network_params,
    bool max_bandwidth_resumption) {
  sent_packet_manager_.ResumeConnectionState(cached_network_params,
                                             max_bandwidth_resumption);
}

void QuicConnection::SetMaxPacingRate(QuicBandwidth max_pacing_rate) {
  sent_packet_manager_.SetMaxPacingRate(max_pacing_rate);
}

void QuicConnection::SetApplicationDrivenPacingRate(
    QuicBandwidth application_driven_pacing_rate) {
  QUIC_CODE_COUNT(quic_connection_set_app_driven_pacing_rate);
  sent_packet_manager_.SetApplicationDrivenPacingRate(
      application_driven_pacing_rate);
}

void QuicConnection::AdjustNetworkParameters(
    const SendAlgorithmInterface::NetworkParams& params) {
  sent_packet_manager_.AdjustNetworkParameters(params);
}

void QuicConnection::SetLossDetectionTuner(
    std::unique_ptr<LossDetectionTunerInterface> tuner) {
  sent_packet_manager_.SetLossDetectionTuner(std::move(tuner));
}

void QuicConnection::OnConfigNegotiated() {
  sent_packet_manager_.OnConfigNegotiated();

  if (GetQuicReloadableFlag(quic_enable_mtu_discovery_at_server) &&
      perspective_ == Perspective::IS_SERVER) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_enable_mtu_discovery_at_server);
    SetMtuDiscoveryTarget(kMtuDiscoveryTargetPacketSizeHigh);
  }
}

QuicBandwidth QuicConnection::MaxPacingRate() const {
  return sent_packet_manager_.MaxPacingRate();
}

QuicBandwidth QuicConnection::ApplicationDrivenPacingRate() const {
  return sent_packet_manager_.ApplicationDrivenPacingRate();
}

bool QuicConnection::SelectMutualVersion(
    const ParsedQuicVersionVector& available_versions) {
  // Try to find the highest mutual version by iterating over supported
  // versions, starting with the highest, and breaking out of the loop once we
  // find a matching version in the provided available_versions vector.
  const ParsedQuicVersionVector& supported_versions =
      framer_.supported_versions();
  for (size_t i = 0; i < supported_versions.size(); ++i) {
    const ParsedQuicVersion& version = supported_versions[i];
    if (std::find(available_versions.begin(), available_versions.end(),
                  version) != available_versions.end()) {
      framer_.set_version(version);
      return true;
    }
  }

  return false;
}

void QuicConnection::OnError(QuicFramer* framer) {
  // Packets that we can not or have not decrypted are dropped.
  // TODO(rch): add stats to measure this.
  if (!connected_ || !last_received_packet_info_.decrypted) {
    return;
  }
  CloseConnection(framer->error(), framer->detailed_error(),
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicConnection::OnPacket() {
  last_received_packet_info_.decrypted = false;
}

bool QuicConnection::OnProtocolVersionMismatch(
    ParsedQuicVersion received_version) {
  QUIC_DLOG(INFO) << ENDPOINT << "Received packet with mismatched version "
                  << ParsedQuicVersionToString(received_version);
  if (perspective_ == Perspective::IS_CLIENT) {
    const std::string error_details = "Protocol version mismatch.";
    QUIC_BUG(quic_bug_10511_3) << ENDPOINT << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SILENT_CLOSE);
  }

  // Server drops old packets that were sent by the client before the version
  // was negotiated.
  return false;
}

// Handles version negotiation for client connection.
void QuicConnection::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& packet) {
  // Check that any public reset packet with a different connection ID that was
  // routed to this QuicConnection has been redirected before control reaches
  // here.  (Check for a bug regression.)
  QUICHE_DCHECK_EQ(default_path_.server_connection_id, packet.connection_id);
  if (perspective_ == Perspective::IS_SERVER) {
    const std::string error_details =
        "Server received version negotiation packet.";
    QUIC_BUG(quic_bug_10511_4) << error_details;
    QUIC_CODE_COUNT(quic_tear_down_local_connection_on_version_negotiation);
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnVersionNegotiationPacket(packet);
  }

  if (version_negotiated_) {
    // Possibly a duplicate version negotiation packet.
    return;
  }

  if (std::find(packet.versions.begin(), packet.versions.end(), version()) !=
      packet.versions.end()) {
    const std::string error_details = absl::StrCat(
        "Server already supports client's version ",
        ParsedQuicVersionToString(version()),
        " and should have accepted the connection instead of sending {",
        ParsedQuicVersionVectorToString(packet.versions), "}.");
    QUIC_DLOG(WARNING) << error_details;
    CloseConnection(QUIC_INVALID_VERSION_NEGOTIATION_PACKET, error_details,
                    ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  server_supported_versions_ = packet.versions;
  CloseConnection(
      QUIC_INVALID_VERSION,
      absl::StrCat(
          "Client may support one of the versions in the server's list, but "
          "it's going to close the connection anyway. Supported versions: {",
          ParsedQuicVersionVectorToString(framer_.supported_versions()),
          "}, peer supported versions: {",
          ParsedQuicVersionVectorToString(packet.versions), "}"),
      send_connection_close_for_invalid
```