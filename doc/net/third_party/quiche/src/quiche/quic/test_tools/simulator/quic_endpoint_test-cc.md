Response:
Let's break down the thought process to analyze the provided C++ code and generate the explanation.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Chromium network stack file (`quic_endpoint_test.cc`). The key elements to identify are its functionality, relationship to JavaScript (if any), logical inferences with input/output examples, common usage errors, and debugging context.

**2. Initial Code Scan and Keyword Spotting:**

A quick scan of the code reveals several key terms and structures:

* **`// Copyright`**: Standard copyright notice, indicating Chromium authorship.
* **`#include`**:  Includes for various QUIC-related headers (`quic_endpoint.h`, `quic_flags.h`, `quic_test.h`, etc.) and standard C++ headers (`memory`, `utility`). This immediately tells us it's a C++ test file within the QUIC library.
* **`namespace quic::simulator`**:  Confirms the location within the QUIC simulator framework.
* **`class QuicEndpointTest : public quic::test::QuicTest`**: This is the core of the analysis. It's a C++ test fixture inheriting from a QUIC testing base class. This strongly suggests the file's primary purpose is *testing*.
* **`Simulator simulator_;`**: An instance of a `Simulator` class – the environment for running the tests.
* **`Switch switch_;`**:  An instance of a `Switch` class – a network element in the simulation.
* **`std::unique_ptr<SymmetricLink> Link(...)` and `CustomLink(...)`**: Functions to create network links with specified bandwidth and delay.
* **`QuicEndpoint endpoint_a(...)`, `endpoint_b(...)`**:  Instances of `QuicEndpoint`, representing network endpoints participating in the simulation. The constructor arguments suggest they represent clients and servers with specific connection IDs.
* **`TEST_F(QuicEndpointTest, ...)`**:  Standard Google Test macros defining individual test cases. The test names (`OneWayTransmission`, `WriteBlocked`, `TwoWayTransmission`, `Competition`) give clues about what each test verifies.
* **`endpoint_a.AddBytesToTransfer(...)`**:  A method to simulate sending data.
* **`simulator_.RunUntil(...)`**:  A mechanism to control the simulation time.
* **`EXPECT_EQ(...)`, `ASSERT_EQ(...)`, `EXPECT_FALSE(...)`, `EXPECT_GT(...)`**: Google Test assertions to verify expected outcomes.

**3. Deduce Functionality:**

Based on the keywords and structure, the primary function is clearly to test the `QuicEndpoint` class within a simulated network environment. It sets up scenarios involving multiple endpoints, switches, and links with configurable properties. The tests verify:

* Basic data transmission (one-way and two-way).
* Handling of write blocking (when the sender's buffer is full or congestion limits are hit).
* Performance and potential packet loss in scenarios with multiple competing senders.

**4. Relationship to JavaScript:**

The code is written in C++. There's no direct indication of JavaScript code within this file. However, it's crucial to understand the *context*. Chromium is a web browser, and QUIC is a transport protocol used for web traffic. Therefore:

* **Indirect Relationship:** The QUIC protocol, and the `QuicEndpoint` class being tested here, are fundamental components that enable faster and more reliable communication for web applications, including those written in JavaScript. When a JavaScript application uses `fetch` or `XMLHttpRequest`, the underlying network stack (which includes QUIC) is responsible for the data transfer.
* **Example:** A JavaScript `fetch` call might trigger the browser to establish a QUIC connection, and the logic tested in this file would be part of ensuring the data is sent and received correctly.

**5. Logical Inferences (Input/Output):**

For each test case, we can infer the intended input and expected output:

* **`OneWayTransmission`:**
    * **Input:**  `endpoint_a` configured to send data to `endpoint_b`. Simulation runs for a certain duration.
    * **Output:** `endpoint_a` transferred the specified number of bytes, `endpoint_b` received the same amount, no data corruption.
* **`WriteBlocked`:**
    * **Input:** `endpoint_a` attempts to send a large amount of data, potentially exceeding flow control or congestion limits.
    * **Output:** `endpoint_a` becomes write-blocked at some point, eventually transfers all data, `endpoint_b` receives all data correctly.
* **`TwoWayTransmission`:**
    * **Input:** Both `endpoint_a` and `endpoint_b` send data to each other simultaneously.
    * **Output:** Both endpoints successfully transfer and receive the intended amount of data.
* **`Competition`:**
    * **Input:** Multiple endpoints send data to a single destination (`endpoint_d`).
    * **Output:** All sending endpoints transfer their data, but due to network congestion, there might be packet loss. The receiving endpoints receive the correct amount of data.

**6. Common Usage Errors:**

Since this is a *test* file, the "users" are typically developers writing or modifying QUIC code or the testing framework itself. Common errors could involve:

* **Incorrect Test Setup:**  Misconfiguring the `Simulator`, `Switch`, or `Link` parameters (e.g., wrong bandwidth, delay). This can lead to tests failing for the wrong reasons.
* **Incorrect Assertions:**  Verifying the wrong metrics or using incorrect expected values in the `EXPECT_*` statements.
* **Flaky Tests:**  Tests that pass or fail inconsistently due to timing issues or subtle interactions within the simulation. This is a common challenge in network simulations.
* **Not Accounting for Simulation Time:**  Rushing the simulation or not running it for a sufficient duration to observe the intended behavior.

**7. Debugging Context (How to Reach This Code):**

A developer might end up looking at this file in several scenarios:

* **Investigating QUIC Behavior:**  If there's a bug or unexpected behavior related to QUIC's performance, congestion control, or data transmission, developers might look at these tests to understand how the system is *supposed* to work and to try to reproduce the issue in a controlled environment.
* **Developing New QUIC Features:** When adding new features to the QUIC implementation, developers would write new test cases in files like this to ensure the new code functions correctly and doesn't break existing functionality.
* **Debugging Test Failures:** If automated tests involving `QuicEndpoint` are failing, developers would examine this file to understand the test logic and identify the source of the failure.
* **Understanding the Simulator Framework:**  Developers new to the QUIC simulator might look at these examples to learn how to set up simulations, create endpoints, and verify network interactions.

**Simplified Breakdown of the Process:**

1. **Identify the file type and location:** C++ test file in the QUIC simulator.
2. **Recognize key classes and functions:** `QuicEndpoint`, `Simulator`, `Switch`, `Link`, `TEST_F`, `EXPECT_*`.
3. **Infer the purpose:** Testing the `QuicEndpoint` class.
4. **Connect to broader context:** QUIC's role in web communication (linking to JavaScript conceptually).
5. **Analyze individual tests:** Determine the setup, intended actions, and expected outcomes.
6. **Consider the target audience:** Developers writing/debugging QUIC code.
7. **Think about debugging scenarios:**  Why would a developer look at this file?

This iterative process of scanning, identifying patterns, and connecting to the larger context allows for a comprehensive understanding of the code's function and relevance.
这个文件 `net/third_party/quiche/src/quiche/quic/test_tools/simulator/quic_endpoint_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它专注于测试 `QuicEndpoint` 类在模拟网络环境下的行为。

**功能列举:**

1. **模拟 QUIC 端点行为:**  该文件定义了一系列的单元测试，用于验证 `QuicEndpoint` 类的各种功能，例如发送和接收数据、处理连接状态、应对网络拥塞等。
2. **测试数据传输:**  测试了单向和双向的数据传输场景，验证数据能否正确发送和接收，以及传输的效率。
3. **测试拥塞控制:** 通过模拟网络瓶颈和设置不同的拥塞控制算法，测试 `QuicEndpoint` 在拥塞情况下的行为，例如是否会触发写阻塞 (write-blocked)。
4. **模拟网络竞争:**  测试了多个 `QuicEndpoint` 同时向一个目标发送数据时的行为，模拟真实网络中的竞争场景。
5. **使用模拟器环境:**  这些测试运行在一个模拟的网络环境中 (`Simulator`)，可以精确控制网络拓扑、延迟、带宽等参数，以便于隔离和复现特定的网络行为。
6. **验证数据完整性:** 测试中会检查接收到的数据是否与发送的数据一致，以确保数据传输的可靠性。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它测试的 QUIC 协议是现代 Web 技术的重要组成部分，与 JavaScript 的功能息息相关。

* **Web 请求的基础:** 当 JavaScript 代码发起一个网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`），浏览器底层可能会使用 QUIC 协议来传输数据。这个文件测试的 `QuicEndpoint` 类就是负责处理这些底层数据传输的核心组件。
* **性能提升:** QUIC 协议旨在提供比传统 TCP 更快、更可靠的网络连接。通过对 `QuicEndpoint` 进行全面的测试，可以确保 QUIC 协议在各种场景下都能提供预期的性能提升，从而改善 JavaScript Web 应用的用户体验。
* **例如:** 假设一个 JavaScript 应用需要从服务器下载大量资源。浏览器可能会使用 QUIC 连接来完成这个下载。这个测试文件中的 `OneWayTransmission` 测试场景就模拟了这种下载行为，验证了 `QuicEndpoint` 能否高效地传输大量数据。

**逻辑推理 (假设输入与输出):**

**测试场景:** `OneWayTransmission` (单向传输)

**假设输入:**

* **Endpoint A (客户端):**
    * 准备发送 600 字节的数据，然后发送 2MB 的数据。
    * 连接到交换机的一个端口。
* **Endpoint B (服务端):**
    * 监听来自 Endpoint A 的连接。
    * 连接到交换机的另一个端口。
* **网络环境:**
    * 交换机连接 Endpoint A 和 Endpoint B。
    * 链路具有默认的带宽和传播延迟。
* **模拟器运行时间:**  足够长，以观察数据传输完成。

**预期输出:**

* **Endpoint A:**
    * 成功发送了 600 字节的数据。
    * 随后成功发送了 2MB 的数据。
    * `bytes_transferred()` 的值等于发送的总字节数 (600 + 2 * 1024 * 1024)。
    * `wrong_data_received()` 返回 `false` (没有接收到错误的数据)。
* **Endpoint B:**
    * 成功接收了来自 Endpoint A 的 600 字节的数据。
    * 随后成功接收了来自 Endpoint A 的 2MB 数据。
    * `bytes_received()` 的值等于接收的总字节数 (600 + 2 * 1024 * 1024)。
    * `wrong_data_received()` 返回 `false` (没有接收到错误的数据)。

**涉及用户或编程常见的使用错误 (假设场景及错误):**

**场景:** 使用 `QuicEndpoint` 进行数据传输时，没有正确设置发送缓冲区大小或者流量控制参数。

**常见错误:**

* **发送缓冲区过小:**  如果发送端 `QuicEndpoint` 的发送缓冲区设置得过小，当需要发送大量数据时，可能会频繁触发写阻塞，导致性能下降。开发者可能没有意识到缓冲区大小的限制，或者错误地估计了所需的缓冲区大小。
* **流量控制参数配置错误:** QUIC 具有流量控制机制，防止发送端发送过快导致接收端过载。如果开发者错误地配置了流量控制参数（例如允许发送端发送远超接收端处理能力的数据），可能会导致丢包或连接不稳定。
* **没有处理写阻塞:** 当 `QuicEndpoint` 进入写阻塞状态时，开发者可能没有正确地处理这种情况。例如，没有等待发送缓冲区可用就继续尝试发送数据，这会导致数据丢失或程序逻辑错误。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用基于 Chromium 内核的浏览器访问某个网站时遇到网络连接问题，例如：

1. **用户尝试访问网页:** 用户在浏览器地址栏输入网址并按下回车键，或者点击一个链接。
2. **浏览器发起网络请求:**  浏览器解析 URL，确定服务器地址，并开始建立网络连接。
3. **QUIC 连接建立 (如果支持):** 如果服务器支持 QUIC 协议，并且浏览器也启用了 QUIC，浏览器会尝试建立 QUIC 连接。
4. **数据传输:** 浏览器通过 QUIC 连接向服务器发送请求，并接收服务器返回的网页内容。
5. **网络问题发生:**  在这个过程中，可能会出现各种网络问题，例如：
    * **连接建立失败:**  可能是由于网络故障、服务器不可用或者 QUIC 协商失败。
    * **数据传输中断或缓慢:**  可能是由于网络拥塞、丢包或者服务器性能问题。
    * **接收到的数据不完整或错误:**  可能是由于数据传输过程中出现错误。

**调试线索和到达 `quic_endpoint_test.cc` 的路径:**

当开发者或网络工程师需要深入调查这些问题时，可能会采取以下步骤，最终到达 `quic_endpoint_test.cc`：

1. **初步排查:** 使用浏览器自带的开发者工具 (例如 Chrome 的 "检查") 查看网络请求的详细信息，例如连接状态、传输时间、错误信息等。
2. **QUIC 相关信息检查:** 检查浏览器是否使用了 QUIC 协议，以及 QUIC 连接的具体参数和状态。
3. **查看 QUIC 内部日志:** Chromium 内核通常会记录详细的 QUIC 协议交互日志。分析这些日志可以了解 QUIC 连接建立和数据传输过程中的具体细节，例如握手过程、拥塞窗口变化、丢包情况等。
4. **定位到 `QuicEndpoint`:** 如果日志显示问题可能出在 QUIC 端点的行为上（例如发送数据失败、接收数据错误、拥塞控制异常），开发者可能会搜索 Chromium 源代码中与 QUIC 端点相关的代码。
5. **找到测试文件:** 为了理解 `QuicEndpoint` 的预期行为和如何进行测试，开发者很可能会找到 `quic_endpoint_test.cc` 这个测试文件。通过阅读测试代码，可以了解 `QuicEndpoint` 的各种功能和在不同网络条件下的行为，从而帮助定位实际网络问题的原因。

总而言之，`quic_endpoint_test.cc` 是一个关键的测试文件，用于确保 QUIC 协议的核心组件 `QuicEndpoint` 的正确性和稳定性。虽然普通用户不会直接接触到这个文件，但它保障了用户在使用基于 QUIC 的网络连接时的良好体验。 当网络问题发生时，这个文件可以作为调试和理解 QUIC 协议行为的重要参考。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/simulator/quic_endpoint_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/simulator/quic_endpoint.h"

#include <memory>
#include <utility>

#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/switch.h"

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace quic {
namespace simulator {

const QuicBandwidth kDefaultBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10 * 1000);
const QuicTime::Delta kDefaultPropagationDelay =
    QuicTime::Delta::FromMilliseconds(20);
const QuicByteCount kDefaultBdp = kDefaultBandwidth * kDefaultPropagationDelay;

// A simple test harness where all hosts are connected to a switch with
// identical links.
class QuicEndpointTest : public quic::test::QuicTest {
 public:
  QuicEndpointTest()
      : simulator_(), switch_(&simulator_, "Switch", 8, kDefaultBdp * 2) {}

 protected:
  Simulator simulator_;
  Switch switch_;

  std::unique_ptr<SymmetricLink> Link(Endpoint* a, Endpoint* b) {
    return std::make_unique<SymmetricLink>(a, b, kDefaultBandwidth,
                                           kDefaultPropagationDelay);
  }

  std::unique_ptr<SymmetricLink> CustomLink(Endpoint* a, Endpoint* b,
                                            uint64_t extra_rtt_ms) {
    return std::make_unique<SymmetricLink>(
        a, b, kDefaultBandwidth,
        kDefaultPropagationDelay +
            QuicTime::Delta::FromMilliseconds(extra_rtt_ms));
  }
};

// Test transmission from one host to another.
TEST_F(QuicEndpointTest, OneWayTransmission) {
  QuicEndpoint endpoint_a(&simulator_, "Endpoint A", "Endpoint B",
                          Perspective::IS_CLIENT, test::TestConnectionId(42));
  QuicEndpoint endpoint_b(&simulator_, "Endpoint B", "Endpoint A",
                          Perspective::IS_SERVER, test::TestConnectionId(42));
  auto link_a = Link(&endpoint_a, switch_.port(1));
  auto link_b = Link(&endpoint_b, switch_.port(2));

  // First transmit a small, packet-size chunk of data.
  endpoint_a.AddBytesToTransfer(600);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromMilliseconds(1000);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  EXPECT_EQ(600u, endpoint_a.bytes_transferred());
  ASSERT_EQ(600u, endpoint_b.bytes_received());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());

  // After a small chunk succeeds, try to transfer 2 MiB.
  endpoint_a.AddBytesToTransfer(2 * 1024 * 1024);
  end_time = simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(5);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  const QuicByteCount total_bytes_transferred = 600 + 2 * 1024 * 1024;
  EXPECT_EQ(total_bytes_transferred, endpoint_a.bytes_transferred());
  EXPECT_EQ(total_bytes_transferred, endpoint_b.bytes_received());
  EXPECT_EQ(0u, endpoint_a.write_blocked_count());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());
}

// Test the situation in which the writer becomes write-blocked.
TEST_F(QuicEndpointTest, WriteBlocked) {
  QuicEndpoint endpoint_a(&simulator_, "Endpoint A", "Endpoint B",
                          Perspective::IS_CLIENT, test::TestConnectionId(42));
  QuicEndpoint endpoint_b(&simulator_, "Endpoint B", "Endpoint A",
                          Perspective::IS_SERVER, test::TestConnectionId(42));
  auto link_a = Link(&endpoint_a, switch_.port(1));
  auto link_b = Link(&endpoint_b, switch_.port(2));

  // Will be owned by the sent packet manager.
  auto* sender = new NiceMock<test::MockSendAlgorithm>();
  EXPECT_CALL(*sender, CanSend(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*sender, PacingRate(_))
      .WillRepeatedly(Return(10 * kDefaultBandwidth));
  EXPECT_CALL(*sender, BandwidthEstimate())
      .WillRepeatedly(Return(10 * kDefaultBandwidth));
  EXPECT_CALL(*sender, GetCongestionWindow())
      .WillRepeatedly(Return(kMaxOutgoingPacketSize *
                             GetQuicFlag(quic_max_congestion_window)));
  test::QuicConnectionPeer::SetSendAlgorithm(endpoint_a.connection(), sender);

  // First transmit a small, packet-size chunk of data.
  QuicByteCount bytes_to_transfer = 3 * 1024 * 1024;
  endpoint_a.AddBytesToTransfer(bytes_to_transfer);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(30);
  simulator_.RunUntil([this, &endpoint_b, bytes_to_transfer, end_time]() {
    return endpoint_b.bytes_received() == bytes_to_transfer ||
           simulator_.GetClock()->Now() >= end_time;
  });

  EXPECT_EQ(bytes_to_transfer, endpoint_a.bytes_transferred());
  EXPECT_EQ(bytes_to_transfer, endpoint_b.bytes_received());
  EXPECT_GT(endpoint_a.write_blocked_count(), 0u);
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());
}

// Test transmission of 1 MiB of data between two hosts simultaneously in both
// directions.
TEST_F(QuicEndpointTest, TwoWayTransmission) {
  QuicEndpoint endpoint_a(&simulator_, "Endpoint A", "Endpoint B",
                          Perspective::IS_CLIENT, test::TestConnectionId(42));
  QuicEndpoint endpoint_b(&simulator_, "Endpoint B", "Endpoint A",
                          Perspective::IS_SERVER, test::TestConnectionId(42));
  auto link_a = Link(&endpoint_a, switch_.port(1));
  auto link_b = Link(&endpoint_b, switch_.port(2));

  endpoint_a.RecordTrace();
  endpoint_b.RecordTrace();

  endpoint_a.AddBytesToTransfer(1024 * 1024);
  endpoint_b.AddBytesToTransfer(1024 * 1024);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(5);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  EXPECT_EQ(1024u * 1024u, endpoint_a.bytes_transferred());
  EXPECT_EQ(1024u * 1024u, endpoint_b.bytes_transferred());
  EXPECT_EQ(1024u * 1024u, endpoint_a.bytes_received());
  EXPECT_EQ(1024u * 1024u, endpoint_b.bytes_received());
  EXPECT_FALSE(endpoint_a.wrong_data_received());
  EXPECT_FALSE(endpoint_b.wrong_data_received());
}

// Simulate three hosts trying to send data to a fourth one simultaneously.
TEST_F(QuicEndpointTest, Competition) {
  auto endpoint_a = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint A", "Endpoint D (A)", Perspective::IS_CLIENT,
      test::TestConnectionId(42));
  auto endpoint_b = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint B", "Endpoint D (B)", Perspective::IS_CLIENT,
      test::TestConnectionId(43));
  auto endpoint_c = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint C", "Endpoint D (C)", Perspective::IS_CLIENT,
      test::TestConnectionId(44));
  auto endpoint_d_a = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint D (A)", "Endpoint A", Perspective::IS_SERVER,
      test::TestConnectionId(42));
  auto endpoint_d_b = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint D (B)", "Endpoint B", Perspective::IS_SERVER,
      test::TestConnectionId(43));
  auto endpoint_d_c = std::make_unique<QuicEndpoint>(
      &simulator_, "Endpoint D (C)", "Endpoint C", Perspective::IS_SERVER,
      test::TestConnectionId(44));
  QuicEndpointMultiplexer endpoint_d(
      "Endpoint D",
      {endpoint_d_a.get(), endpoint_d_b.get(), endpoint_d_c.get()});

  // Create links with slightly different RTTs in order to avoid pathological
  // side-effects of packets entering the queue at the exactly same time.
  auto link_a = CustomLink(endpoint_a.get(), switch_.port(1), 0);
  auto link_b = CustomLink(endpoint_b.get(), switch_.port(2), 1);
  auto link_c = CustomLink(endpoint_c.get(), switch_.port(3), 2);
  auto link_d = Link(&endpoint_d, switch_.port(4));

  endpoint_a->AddBytesToTransfer(2 * 1024 * 1024);
  endpoint_b->AddBytesToTransfer(2 * 1024 * 1024);
  endpoint_c->AddBytesToTransfer(2 * 1024 * 1024);
  QuicTime end_time =
      simulator_.GetClock()->Now() + QuicTime::Delta::FromSeconds(12);
  simulator_.RunUntil(
      [this, end_time]() { return simulator_.GetClock()->Now() >= end_time; });

  for (QuicEndpoint* endpoint :
       {endpoint_a.get(), endpoint_b.get(), endpoint_c.get()}) {
    EXPECT_EQ(2u * 1024u * 1024u, endpoint->bytes_transferred());
    EXPECT_GE(endpoint->connection()->GetStats().packets_lost, 0u);
  }
  for (QuicEndpoint* endpoint :
       {endpoint_d_a.get(), endpoint_d_b.get(), endpoint_d_c.get()}) {
    EXPECT_EQ(2u * 1024u * 1024u, endpoint->bytes_received());
    EXPECT_FALSE(endpoint->wrong_data_received());
  }
}

}  // namespace simulator
}  // namespace quic
```