Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding: The Big Picture**

The filename `tls_chlo_extractor_test.cc` immediately tells us this file tests something called `TlsChloExtractor`. The `test.cc` suffix confirms it's a test file within the Chromium/QUIC codebase. The `net/third_party/quiche/src/quiche/quic/core/` path suggests this is a core QUIC component related to TLS. "CHLO" is a common abbreviation for ClientHello in TLS. So, the core function likely involves extracting information from the TLS ClientHello message.

**2. Examining Includes:**

The `#include` directives provide crucial clues about dependencies and functionality:

* `<memory>`, `<optional>`, `<string>`, `<utility>`, `<vector>`: Standard C++ containers and utilities, indicating the class likely deals with data structures.
* `"openssl/ssl.h"`:  A major hint! This confirms the involvement of TLS and the OpenSSL library.
* `"quiche/quic/core/http/quic_spdy_client_session.h"`:  Suggests the `TlsChloExtractor` might interact with or be used within the context of a QUIC client session, specifically related to HTTP/3 (since SPDY is the predecessor).
* `"quiche/quic/core/quic_connection.h"`, `"quiche/quic/core/quic_types.h"`, `"quiche/quic/core/quic_versions.h"`:  Core QUIC components. The extractor likely operates on QUIC connection data.
* `"quiche/quic/platform/api/quic_flags.h"`, `"quiche/quic/platform/api/quic_test.h"`:  Indicates the use of QUIC-specific flags and that this is a test file using the QUIC testing framework.
* `"quiche/quic/test_tools/...`": Various test utilities for crypto, packet generation, and session management. This reinforces the testing purpose.
* `"quiche/common/print_elements.h"`: A general QUIC utility for printing elements, probably used for debugging output in the tests.

**3. Analyzing the Test Class: `TlsChloExtractorTest`**

* **Inheritance:** `QuicTestWithParam<ParsedQuicVersion>` tells us these tests are parameterized based on different QUIC versions. This is important for ensuring compatibility across versions.
* **Member Variables:**
    * `version_`: Stores the current QUIC version being tested.
    * `server_id_`:  Represents the server being connected to.
    * `tls_chlo_extractor_`: The actual class being tested.
    * `config_`:  A `QuicConfig` object, likely used to configure the QUIC connection for generating test ClientHello messages.
    * `packets_`: A vector of `QuicReceivedPacket` representing the initial flight of packets containing the ClientHello.
    * `crypto_stream_size_`: Stores the size of the crypto stream, used for validation.
* **Helper Methods:**  These are crucial for understanding the test setup and execution:
    * `Initialize()`: Sets up the test environment, generating the initial ClientHello packets using `GetAnnotatedFirstFlightOfPackets`. The use of "first flight" is a key indicator that this focuses on the initial handshake.
    * `Initialize(std::unique_ptr<QuicCryptoClientConfig> crypto_config)`:  An overloaded version allowing customization of the crypto configuration, important for testing resumption and early data scenarios.
    * `PerformFullHandshake()`: Simulates a complete QUIC handshake. This is done *before* testing the extractor to create a cached session for resumption tests.
    * `IngestPackets()`:  The core action of feeding the generated packets to the `TlsChloExtractor`. It also includes parsing the QUIC public header.
    * `ValidateChloDetails()`:  Asserts the expected extracted information from the `TlsChloExtractor`, like ALPN, server name, and the raw ClientHello bytes.
    * `IncreaseSizeOfChlo()`:  Modifies the QUIC configuration to make the ClientHello larger, useful for testing multi-packet scenarios.

**4. Examining Individual Test Cases (e.g., `Simple`, `TlsExtensionInfo_ResumptionOnly`):**

Each `TEST_P` macro defines a specific test scenario:

* `Simple`: The most basic test, ensuring the extractor works for a single-packet ClientHello.
* `TlsExtensionInfo_ResumptionOnly`: Tests the extractor's ability to detect a resumption attempt (using a previously established session). `SSL_CTX_set_early_data_enabled(..., 0)` is a key detail here, disabling early data.
* `TlsExtensionInfo_ZeroRtt`: Tests the extractor's ability to detect a zero-RTT (early data) attempt.
* `TlsExtensionInfo_SupportedGroups`, `TlsExtensionInfo_CertCompressionAlgos`: Test extraction of specific TLS extensions.
* `MultiPacket`, `MultiPacketReordered`: Test handling of ClientHello messages split across multiple QUIC packets, including out-of-order delivery.
* `MoveAssignment`, `MoveAssignmentAfterExtraction`, `MoveAssignmentBetweenPackets`: Test the C++ move semantics of the `TlsChloExtractor` class, important for efficiency and correctness.

**5. Identifying Key Functionality of `TlsChloExtractor`:**

Based on the tests, we can infer the core functions of `TlsChloExtractor`:

* **Parsing ClientHello:** The primary function is to parse the TLS ClientHello message from received QUIC packets.
* **Extracting Information:**  It extracts specific pieces of information from the ClientHello, such as:
    * Supported ALPNs (Application-Layer Protocol Negotiation).
    * Server Name Indication (SNI).
    * Raw ClientHello bytes.
    * Whether a session resumption is attempted.
    * Whether early data (0-RTT) is attempted.
    * Supported elliptic curves (supported_groups).
    * Supported certificate compression algorithms.
* **Handling Multi-Packet CHLO:** It correctly handles ClientHello messages that are fragmented across multiple QUIC packets, even if they arrive out of order.
* **State Tracking:** It maintains a state to track whether a full ClientHello has been parsed.

**6. Connecting to JavaScript (if applicable):**

This requires knowledge of how Chromium's network stack interacts with the browser's JavaScript environment. Since this code is deeply embedded in the QUIC implementation, the connection isn't direct but rather through higher-level APIs:

* **`navigator.connect()` API:** JavaScript can initiate QUIC connections using the `navigator.connect()` API (or related Fetch API features). When a connection is established, the browser internally uses code like this to handle the TLS handshake.
* **Network Events:** The browser's JavaScript engine receives events related to network activity. While this specific code isn't directly exposed, the information extracted here (like ALPN) can influence how the browser handles the connection and which protocols are negotiated.
* **Debugging Tools:**  Developers using browser debugging tools might indirectly observe the effects of this code. For example, they might see the negotiated protocol in the network panel, which is influenced by the ALPN extracted here.

**7. Hypothesizing Inputs and Outputs:**

This involves thinking about different scenarios and what the `TlsChloExtractor` should produce. The tests already provide excellent examples.

**8. Identifying Potential User/Programming Errors:**

* **Incorrect Packet Handling:**  If the code ingesting packets doesn't pass them to the `TlsChloExtractor` correctly or drops packets, the extractor might not be able to parse the full ClientHello.
* **Assuming Single-Packet CHLO:** A common mistake might be assuming that the ClientHello always fits in a single packet. This code handles multi-packet scenarios, so developers using it need to be aware of this possibility.
* **Incorrect Configuration:**  If the `QuicConfig` is set up incorrectly, the generated ClientHello might not be what's expected, leading to unexpected behavior.

**9. Tracing User Actions (Debugging Clues):**

This involves understanding the user's journey to trigger the execution of this code:

1. **User Navigates to a Website:** The user enters a URL in the browser or clicks a link.
2. **DNS Resolution:** The browser resolves the domain name to an IP address.
3. **QUIC Connection Attempt:** If the server supports QUIC and the browser is configured to use it, a QUIC connection attempt is initiated.
4. **ClientHello Generation:** The browser's QUIC implementation generates the TLS ClientHello message.
5. **Packet Sending:** The ClientHello is sent to the server in one or more QUIC packets.
6. **Server-Side Processing:** On the server side, code similar to this `TlsChloExtractor` would be used to parse the incoming ClientHello. *However, this specific test file is for the client-side behavior (simulating the client sending the CHLO).*

By following these steps, you can understand the context of this code within the larger QUIC handshake process. The test file focuses on the client *sending* the initial packets, but the concepts are mirrored on the server side for *receiving* and processing them.
This C++ source code file, `tls_chlo_extractor_test.cc`, is a **unit test file** for the `TlsChloExtractor` class within the Chromium network stack's QUIC implementation. Its primary function is to **verify the correct behavior of the `TlsChloExtractor` class**.

Here's a breakdown of its functionalities:

**1. Functionality of `TlsChloExtractor` (as implied by the tests):**

* **Parsing TLS ClientHello (CHLO) messages:** The core purpose of `TlsChloExtractor` is to parse and extract relevant information from the TLS ClientHello message sent by a QUIC client during the handshake.
* **Extracting Key Information:** The tests demonstrate that `TlsChloExtractor` can extract:
    * **ALPN (Application-Layer Protocol Negotiation):**  The list of application protocols the client supports (e.g., HTTP/3).
    * **Server Name Indication (SNI):** The hostname of the server the client intends to connect to.
    * **Raw ClientHello Bytes:** The actual raw byte representation of the ClientHello message.
    * **Resumption Attempted:**  Whether the client is attempting to resume a previous TLS session.
    * **Early Data Attempted (0-RTT):** Whether the client is attempting to send application data in the initial flight of packets.
    * **Supported Groups:** The list of elliptic curve groups the client supports for key exchange.
    * **Certificate Compression Algorithms:** The list of certificate compression algorithms the client supports.
* **Handling Multi-Packet CHLOs:**  The tests confirm that `TlsChloExtractor` can correctly parse ClientHello messages that are fragmented across multiple QUIC packets, including cases where the packets arrive out of order.
* **State Management:**  The `TlsChloExtractor` keeps track of its parsing state (e.g., whether a full CHLO has been parsed).

**2. How the Test File Works:**

* **Test Setup:** The `TlsChloExtractorTest` class sets up various test scenarios. This involves:
    * Creating a `TlsChloExtractor` instance.
    * Generating simulated QUIC client initial packets (containing the ClientHello) using `GetAnnotatedFirstFlightOfPackets`.
    * Optionally performing a full handshake to create a cached session for resumption testing.
    * Configuring the `QuicConfig` to influence the content of the ClientHello (e.g., adding custom parameters to make it larger).
* **Packet Ingestion:** The `IngestPackets()` method feeds the generated QUIC packets to the `TlsChloExtractor` for processing. It also performs basic QUIC header parsing to simulate real packet reception.
* **Validation:** The `ValidateChloDetails()` method asserts that the `TlsChloExtractor` has correctly parsed the ClientHello and extracted the expected information.
* **Specific Test Cases:**  Each `TEST_P` function focuses on a specific aspect of `TlsChloExtractor` functionality, such as:
    * Parsing a simple, single-packet CHLO.
    * Detecting resumption attempts.
    * Detecting early data attempts.
    * Extracting specific TLS extensions (supported groups, certificate compression algorithms).
    * Handling multi-packet CHLOs, including reordered packets.
    * Testing move assignment semantics of the class.

**3. Relationship to JavaScript Functionality:**

This C++ code is part of the underlying network stack of Chromium. It doesn't have a direct, line-by-line correspondence with JavaScript code. However, it plays a crucial role in how a web browser establishes secure connections, which is initiated by JavaScript through browser APIs.

Here's how it indirectly relates to JavaScript:

* **`navigator.connect()` API (Experimental):**  JavaScript can use the experimental `navigator.connect()` API to establish QUIC connections. When this API is used, the browser's underlying QUIC implementation (including code like this) handles the connection setup, including parsing the server's response to the ClientHello.
* **`fetch()` API (with HTTP/3):**  If a website is served over HTTP/3 (which uses QUIC), the JavaScript `fetch()` API will trigger the browser to establish a QUIC connection. The `TlsChloExtractor` (or its server-side counterpart) would be involved in the initial handshake of this connection.
* **Security and Protocol Negotiation:** The information extracted by `TlsChloExtractor`, such as ALPN, directly influences which application-level protocol (e.g., HTTP/3, HTTP/2) is negotiated for the connection. This affects how JavaScript interacts with the server. For example, if HTTP/3 is negotiated, JavaScript might use new HTTP/3 specific APIs or observe different performance characteristics.

**Example:**

Imagine a JavaScript application using `fetch()` to access a resource on a server that supports HTTP/3.

1. **JavaScript `fetch()` call:**  The JavaScript code calls `fetch('https://example.com/data')`.
2. **QUIC Connection Initiation:** The browser checks if it has an existing QUIC connection to `example.com`. If not, it initiates a new connection.
3. **ClientHello Generation (C++):** Chromium's QUIC implementation generates a TLS ClientHello message. This message includes ALPN values indicating the browser's preference for HTTP/3.
4. **`TlsChloExtractor` (Conceptual Server-Side):**  On the server side, a component analogous to `TlsChloExtractor` would parse the incoming ClientHello and see that the client supports HTTP/3.
5. **Protocol Negotiation:** The server responds, confirming the use of HTTP/3.
6. **HTTP/3 Communication:** The JavaScript `fetch()` request and response are now transmitted over the established HTTP/3 connection.

**4. Assumptions, Inputs, and Outputs (Logical Reasoning):**

Let's consider one specific test case: `TEST_P(TlsChloExtractorTest, Simple)`

* **Hypothetical Input:** A single QUIC packet containing a TLS ClientHello message generated by the test setup. This ClientHello will include standard information like the server name and supported ALPN.
* **Processing:** The `IngestPackets()` method feeds this packet to the `tls_chlo_extractor_`.
* **Expected Output:**
    * `tls_chlo_extractor_->HasParsedFullChlo()`:  Should be `true`.
    * `tls_chlo_extractor_->alpns()`: Should be a vector containing the ALPN string for the current QUIC version (e.g., "h3").
    * `tls_chlo_extractor_->server_name()`: Should be the test hostname (e.g., "test.example.com").
    * `tls_chlo_extractor_->client_hello_bytes().size()`: Should be equal to the size of the ClientHello payload in the packet.
    * `tls_chlo_extractor_->state()`: Should be `TlsChloExtractor::State::kParsedFullSinglePacketChlo`.
    * `tls_chlo_extractor_->resumption_attempted()`: Should be `false`.
    * `tls_chlo_extractor_->early_data_attempted()`: Should be `false`.

**5. User or Programming Common Usage Errors:**

* **Incorrect Packet Boundaries:** If the code that feeds packets to `TlsChloExtractor` doesn't respect QUIC packet boundaries, the extractor might receive incomplete or corrupted ClientHello data.
    * **Example:** A developer might try to feed individual TLS handshake messages to the extractor instead of complete QUIC packets.
* **Assuming Single-Packet CHLO:**  A common mistake might be assuming the ClientHello always fits in a single packet. If a developer relies on the extractor after processing only one packet, they might miss data from subsequent packets if the CHLO is large. The tests for multi-packet scenarios highlight the importance of handling fragmentation.
* **Not Handling Reordered Packets:** If the network conditions lead to packet reordering, and the developer's integration with `TlsChloExtractor` doesn't account for this, the parsing might fail. The `MultiPacketReordered` test specifically addresses this.
* **Misunderstanding State:**  Failing to check the `tls_chlo_extractor_->state()` might lead to incorrect assumptions about whether the full ClientHello has been processed.

**6. User Operations and Debugging Clues:**

To reach the point where `TlsChloExtractor` is involved, the user would typically:

1. **Open a web page in Chrome:**  The user types a URL in the address bar or clicks a link.
2. **Browser Initiates Connection:** If the website uses HTTPS and QUIC is enabled (which is often the default), the browser will attempt to establish a QUIC connection with the server.
3. **ClientHello Generation:**  The browser's QUIC implementation generates the TLS ClientHello message.
4. **Packet Transmission:** The ClientHello is sent to the server in one or more QUIC packets.

**Debugging Clues:**

If there are issues with QUIC connection establishment, and you suspect a problem related to ClientHello processing, you might look for the following during debugging:

* **Network Logs (Chrome's `chrome://net-export/`):** These logs capture network events, including QUIC handshake details. You could examine the content of the ClientHello being sent.
* **QUIC Internal Logs (If enabled):** Chromium has internal logging for QUIC. These logs might show details of the `TlsChloExtractor`'s processing of incoming packets.
* **Packet Capture (e.g., Wireshark):**  A packet capture can show the raw QUIC packets being exchanged, including the TLS handshake messages. This allows you to inspect the ClientHello directly.
* **Breakpoints in QUIC Code:**  Developers familiar with the Chromium codebase can set breakpoints within the `TlsChloExtractor` class or related QUIC code to step through the execution and understand what's happening during ClientHello parsing.

In summary, `tls_chlo_extractor_test.cc` is a crucial part of ensuring the reliability and correctness of QUIC's TLS handshake in Chromium. It tests the `TlsChloExtractor`, a component responsible for understanding the initial message sent by the client when establishing a secure QUIC connection. This indirectly affects the functionality and performance of web applications accessed through Chrome.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_chlo_extractor_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_chlo_extractor.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "openssl/ssl.h"
#include "quiche/quic/core/http/quic_spdy_client_session.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/first_flight.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_session_cache.h"
#include "quiche/common/print_elements.h"

namespace quic {
namespace test {
namespace {

static int DummyCompressFunc(SSL* /*ssl*/, CBB* /*out*/, const uint8_t* /*in*/,
                             size_t /*in_len*/) {
  return 1;
}

static int DummyDecompressFunc(SSL* /*ssl*/, CRYPTO_BUFFER** /*out*/,
                               size_t /*uncompressed_len*/,
                               const uint8_t* /*in*/, size_t /*in_len*/) {
  return 1;
}

using testing::_;
using testing::AnyNumber;

class TlsChloExtractorTest : public QuicTestWithParam<ParsedQuicVersion> {
 protected:
  TlsChloExtractorTest() : version_(GetParam()), server_id_(TestServerId()) {}

  void Initialize() {
    tls_chlo_extractor_ = std::make_unique<TlsChloExtractor>();
    AnnotatedPackets packets =
        GetAnnotatedFirstFlightOfPackets(version_, config_);
    packets_ = std::move(packets.packets);
    crypto_stream_size_ = packets.crypto_stream_size;
    QUIC_DLOG(INFO) << "Initialized with " << packets_.size()
                    << " packets with crypto_stream_size:"
                    << crypto_stream_size_;
  }

  void Initialize(std::unique_ptr<QuicCryptoClientConfig> crypto_config) {
    tls_chlo_extractor_ = std::make_unique<TlsChloExtractor>();
    AnnotatedPackets packets = GetAnnotatedFirstFlightOfPackets(
        version_, config_, TestConnectionId(), EmptyQuicConnectionId(),
        std::move(crypto_config));
    packets_ = std::move(packets.packets);
    crypto_stream_size_ = packets.crypto_stream_size;
    QUIC_DLOG(INFO) << "Initialized with " << packets_.size()
                    << " packets with crypto_stream_size:"
                    << crypto_stream_size_;
  }

  // Perform a full handshake in order to insert a SSL_SESSION into
  // crypto_config->session_cache(), which can be used by a TLS resumption.
  void PerformFullHandshake(QuicCryptoClientConfig* crypto_config) const {
    ASSERT_NE(crypto_config->session_cache(), nullptr);
    MockQuicConnectionHelper client_helper, server_helper;
    MockAlarmFactory alarm_factory;
    ParsedQuicVersionVector supported_versions = {version_};
    PacketSavingConnection* client_connection =
        new PacketSavingConnection(&client_helper, &alarm_factory,
                                   Perspective::IS_CLIENT, supported_versions);
    // Advance the time, because timers do not like uninitialized times.
    client_connection->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    QuicSpdyClientSession client_session(config_, supported_versions,
                                         client_connection, server_id_,
                                         crypto_config);
    client_session.Initialize();

    std::unique_ptr<QuicCryptoServerConfig> server_crypto_config =
        crypto_test_utils::CryptoServerConfigForTesting();
    QuicConfig server_config;

    EXPECT_CALL(*client_connection, SendCryptoData(_, _, _)).Times(AnyNumber());
    client_session.GetMutableCryptoStream()->CryptoConnect();

    crypto_test_utils::HandshakeWithFakeServer(
        &server_config, server_crypto_config.get(), &server_helper,
        &alarm_factory, client_connection,
        client_session.GetMutableCryptoStream(),
        AlpnForVersion(client_connection->version()));

    // For some reason, the test client can not receive the server settings and
    // the SSL_SESSION will not be inserted to client's session_cache. We create
    // a dummy settings and call SetServerApplicationStateForResumption manually
    // to ensure the SSL_SESSION is cached.
    // TODO(wub): Fix crypto_test_utils::HandshakeWithFakeServer to make sure a
    // SSL_SESSION is cached at the client, and remove the rest of the function.
    SettingsFrame server_settings;
    server_settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] =
        kDefaultQpackMaxDynamicTableCapacity;
    std::string settings_frame =
        HttpEncoder::SerializeSettingsFrame(server_settings);
    client_session.GetMutableCryptoStream()
        ->SetServerApplicationStateForResumption(
            std::make_unique<ApplicationState>(
                settings_frame.data(),
                settings_frame.data() + settings_frame.length()));
  }

  void IngestPackets() {
    for (const std::unique_ptr<QuicReceivedPacket>& packet : packets_) {
      ReceivedPacketInfo packet_info(
          QuicSocketAddress(TestPeerIPAddress(), kTestPort),
          QuicSocketAddress(TestPeerIPAddress(), kTestPort), *packet);
      std::string detailed_error;
      std::optional<absl::string_view> retry_token;
      const QuicErrorCode error = QuicFramer::ParsePublicHeaderDispatcher(
          *packet, /*expected_destination_connection_id_length=*/0,
          &packet_info.form, &packet_info.long_packet_type,
          &packet_info.version_flag, &packet_info.use_length_prefix,
          &packet_info.version_label, &packet_info.version,
          &packet_info.destination_connection_id,
          &packet_info.source_connection_id, &retry_token, &detailed_error);
      ASSERT_THAT(error, IsQuicNoError()) << detailed_error;
      tls_chlo_extractor_->IngestPacket(packet_info.version,
                                        packet_info.packet);
    }
    packets_.clear();
  }

  void ValidateChloDetails(const TlsChloExtractor* extractor = nullptr) const {
    if (extractor == nullptr) {
      extractor = tls_chlo_extractor_.get();
    }

    EXPECT_TRUE(extractor->HasParsedFullChlo());
    std::vector<std::string> alpns = extractor->alpns();
    ASSERT_EQ(alpns.size(), 1u);
    EXPECT_EQ(alpns[0], AlpnForVersion(version_));
    EXPECT_EQ(extractor->server_name(), TestHostname());
    // Crypto stream has one frame in the following format:
    // CRYPTO Frame {
    //  Type (i) = 0x06,
    //  Offset (i),
    //  Length (i),
    //  Crypto Data (..),
    // }
    //
    // Type is 1 byte long, Offset is zero and also 1 byte long, and
    // all generated ClientHello messages have 2 byte length. So
    // the header is 4 bytes total.
    EXPECT_EQ(extractor->client_hello_bytes().size(), crypto_stream_size_ - 4);
  }

  void IncreaseSizeOfChlo() {
    // Add a 2000-byte custom parameter to increase the length of the CHLO.
    constexpr auto kCustomParameterId =
        static_cast<TransportParameters::TransportParameterId>(0xff33);
    std::string kCustomParameterValue(2000, '-');
    config_.custom_transport_parameters_to_send()[kCustomParameterId] =
        kCustomParameterValue;
  }

  ParsedQuicVersion version_;
  QuicServerId server_id_;
  std::unique_ptr<TlsChloExtractor> tls_chlo_extractor_;
  QuicConfig config_;
  std::vector<std::unique_ptr<QuicReceivedPacket>> packets_;
  uint64_t crypto_stream_size_;
};

INSTANTIATE_TEST_SUITE_P(TlsChloExtractorTests, TlsChloExtractorTest,
                         ::testing::ValuesIn(AllSupportedVersionsWithTls()),
                         ::testing::PrintToStringParamName());

TEST_P(TlsChloExtractorTest, Simple) {
  Initialize();
  EXPECT_EQ(packets_.size(), 1u);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullSinglePacketChlo);
  EXPECT_FALSE(tls_chlo_extractor_->resumption_attempted());
  EXPECT_FALSE(tls_chlo_extractor_->early_data_attempted());
}

TEST_P(TlsChloExtractorTest, TlsExtensionInfo_ResumptionOnly) {
  auto crypto_client_config = std::make_unique<QuicCryptoClientConfig>(
      crypto_test_utils::ProofVerifierForTesting(),
      std::make_unique<SimpleSessionCache>());
  PerformFullHandshake(crypto_client_config.get());

  SSL_CTX_set_early_data_enabled(crypto_client_config->ssl_ctx(), 0);
  Initialize(std::move(crypto_client_config));
  EXPECT_GE(packets_.size(), 1u);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullSinglePacketChlo);
  EXPECT_TRUE(tls_chlo_extractor_->resumption_attempted());
  EXPECT_FALSE(tls_chlo_extractor_->early_data_attempted());
}

TEST_P(TlsChloExtractorTest, TlsExtensionInfo_ZeroRtt) {
  auto crypto_client_config = std::make_unique<QuicCryptoClientConfig>(
      crypto_test_utils::ProofVerifierForTesting(),
      std::make_unique<SimpleSessionCache>());
  PerformFullHandshake(crypto_client_config.get());

  IncreaseSizeOfChlo();
  Initialize(std::move(crypto_client_config));
  EXPECT_GE(packets_.size(), 1u);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullMultiPacketChlo);
  EXPECT_TRUE(tls_chlo_extractor_->resumption_attempted());
  EXPECT_TRUE(tls_chlo_extractor_->early_data_attempted());
}

TEST_P(TlsChloExtractorTest, TlsExtensionInfo_SupportedGroups) {
  const std::vector<std::vector<uint16_t>> preferred_groups_to_test = {
      // Only one group
      {SSL_GROUP_X25519},
      // Two groups
      {SSL_GROUP_X25519_KYBER768_DRAFT00, SSL_GROUP_X25519},
  };
  for (const std::vector<uint16_t>& preferred_groups :
       preferred_groups_to_test) {
    auto crypto_client_config = std::make_unique<QuicCryptoClientConfig>(
        crypto_test_utils::ProofVerifierForTesting());
    crypto_client_config->set_preferred_groups(preferred_groups);

    Initialize(std::move(crypto_client_config));
    IngestPackets();
    ValidateChloDetails();
    EXPECT_EQ(tls_chlo_extractor_->supported_groups(), preferred_groups);
  }
}

TEST_P(TlsChloExtractorTest, TlsExtensionInfo_CertCompressionAlgos) {
  const std::vector<std::vector<uint16_t>> supported_groups_to_test = {
      // No cert compression algos
      {},
      // One cert compression algo
      {1},
      // Two cert compression algos
      {1, 2},
      // Three cert compression algos
      {1, 2, 3},
      // Four cert compression algos
      {1, 2, 3, 65535},
  };
  for (const std::vector<uint16_t>& supported_cert_compression_algos :
       supported_groups_to_test) {
    auto crypto_client_config = std::make_unique<QuicCryptoClientConfig>(
        crypto_test_utils::ProofVerifierForTesting());
    for (uint16_t cert_compression_algo : supported_cert_compression_algos) {
      ASSERT_TRUE(SSL_CTX_add_cert_compression_alg(
          crypto_client_config->ssl_ctx(), cert_compression_algo,
          DummyCompressFunc, DummyDecompressFunc));
    }

    Initialize(std::move(crypto_client_config));
    IngestPackets();
    ValidateChloDetails();
    if (GetQuicReloadableFlag(quic_parse_cert_compression_algos_from_chlo)) {
      EXPECT_EQ(tls_chlo_extractor_->cert_compression_algos(),
                supported_cert_compression_algos)
          << quiche::PrintElements(
                 tls_chlo_extractor_->cert_compression_algos());
    } else {
      EXPECT_TRUE(tls_chlo_extractor_->cert_compression_algos().empty());
    }
  }
}

TEST_P(TlsChloExtractorTest, MultiPacket) {
  IncreaseSizeOfChlo();
  Initialize();
  EXPECT_EQ(packets_.size(), 2u);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullMultiPacketChlo);
}

TEST_P(TlsChloExtractorTest, MultiPacketReordered) {
  IncreaseSizeOfChlo();
  Initialize();
  ASSERT_EQ(packets_.size(), 2u);
  // Artificially reorder both packets.
  std::swap(packets_[0], packets_[1]);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullMultiPacketChlo);
}

TEST_P(TlsChloExtractorTest, MoveAssignment) {
  Initialize();
  EXPECT_EQ(packets_.size(), 1u);
  TlsChloExtractor other_extractor;
  *tls_chlo_extractor_ = std::move(other_extractor);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullSinglePacketChlo);
}

TEST_P(TlsChloExtractorTest, MoveAssignmentAfterExtraction) {
  Initialize();
  EXPECT_EQ(packets_.size(), 1u);
  IngestPackets();
  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullSinglePacketChlo);

  TlsChloExtractor other_extractor = std::move(*tls_chlo_extractor_);

  EXPECT_EQ(other_extractor.state(),
            TlsChloExtractor::State::kParsedFullSinglePacketChlo);
  ValidateChloDetails(&other_extractor);
}

TEST_P(TlsChloExtractorTest, MoveAssignmentBetweenPackets) {
  IncreaseSizeOfChlo();
  Initialize();
  ASSERT_EQ(packets_.size(), 2u);
  TlsChloExtractor other_extractor;

  // Have |other_extractor| parse the first packet.
  ReceivedPacketInfo packet_info(
      QuicSocketAddress(TestPeerIPAddress(), kTestPort),
      QuicSocketAddress(TestPeerIPAddress(), kTestPort), *packets_[0]);
  std::string detailed_error;
  std::optional<absl::string_view> retry_token;
  const QuicErrorCode error = QuicFramer::ParsePublicHeaderDispatcher(
      *packets_[0], /*expected_destination_connection_id_length=*/0,
      &packet_info.form, &packet_info.long_packet_type,
      &packet_info.version_flag, &packet_info.use_length_prefix,
      &packet_info.version_label, &packet_info.version,
      &packet_info.destination_connection_id, &packet_info.source_connection_id,
      &retry_token, &detailed_error);
  ASSERT_THAT(error, IsQuicNoError()) << detailed_error;
  other_extractor.IngestPacket(packet_info.version, packet_info.packet);
  // Remove the first packet from the list.
  packets_.erase(packets_.begin());
  EXPECT_EQ(packets_.size(), 1u);

  // Move the extractor.
  *tls_chlo_extractor_ = std::move(other_extractor);

  // Have |tls_chlo_extractor_| parse the second packet.
  IngestPackets();

  ValidateChloDetails();
  EXPECT_EQ(tls_chlo_extractor_->state(),
            TlsChloExtractor::State::kParsedFullMultiPacketChlo);
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```