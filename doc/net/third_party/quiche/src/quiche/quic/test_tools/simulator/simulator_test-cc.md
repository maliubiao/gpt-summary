Response:
Let's break down the thought process to analyze the provided C++ code and generate the detailed explanation.

**1. Understanding the Request:**

The core request is to analyze a specific Chromium networking stack file (`simulator_test.cc`) and describe its functionality, relating it to JavaScript if applicable, explaining any logical reasoning with examples, highlighting common usage errors, and providing debugging clues about how one might end up looking at this file.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly skim the code, looking for keywords and structures that indicate the file's purpose. Key observations:

* **`#include` statements:** These reveal dependencies on testing frameworks (`quic_test.h`), simulator components (`simulator.h`, `link.h`, `queue.h`, etc.), and core QUIC types (`quic_time.h`, `quic_bandwidth.h`). This strongly suggests the file is testing the `simulator` functionality.
* **`TEST_F(SimulatorTest, ...)`:** This pattern confirms it's a test file using the Google Test framework, specifically for a class named `SimulatorTest`.
* **Class definitions:**  The presence of classes like `Counter`, `CounterPort`, `LinkSaturator`, `PacketAcceptor`, `Queue`, `Switch`, `AlarmToggler`, `CounterDelegate`, and `MockPacketFilter` suggests these are components being tested within the simulation environment.
* **Simulator interactions:**  Code frequently creates instances of `Simulator` and calls methods like `RunUntil`, `RunFor`, and interacts with its `AlarmFactory`.
* **Network concepts:** Terms like "bandwidth," "propagation delay," "packets," "queue," "switch," and "traffic policer" clearly point to network simulation.

**3. Deeper Dive into Key Components and Tests:**

Now, go through each test case (`TEST_F`) and the custom classes to understand their individual roles and how they contribute to testing the `Simulator`.

* **`Counter`:**  A simple actor that increments a value periodically. This tests basic event scheduling in the simulator.
* **`CounterPort`:** A passive component that counts received packets and bytes. This is used to verify packet delivery.
* **`LinkSaturator`:**  An active component that generates and sends packets at a specified rate. This simulates traffic generation.
* **`PacketAcceptor`:**  A simple port that stores received packets, used for verifying queue behavior.
* **`Queue`:** Implements a packet queue with a capacity. Tests focus on packet dropping and forwarding.
* **`Switch`:**  Simulates a network switch with multiple ports, enabling routing of packets between connected endpoints.
* **`AlarmToggler` and `CounterDelegate`:**  These are used to test the alarm mechanism of the simulator, verifying scheduling and cancellation.
* **`MockPacketFilter`:** Uses the Google Mock framework to create a mock packet filter, allowing controlled dropping or passing of packets.
* **`TrafficPolicer`:**  Simulates a traffic policer that limits the rate of traffic.

**4. Identifying Functionality and Grouping:**

Based on the individual components and tests, summarize the overall functionality of the file:

* **Core Simulation Engine Testing:**  Testing the basic mechanics of the simulator, like event scheduling and time progression.
* **Network Element Testing:**  Verifying the behavior of individual network components like links, queues, switches, and traffic policers.
* **Packet Handling:**  Testing how packets are created, transmitted, filtered, queued, and received within the simulated environment.
* **Alarm Mechanism Testing:** Ensuring the correctness of the simulator's alarm system.

**5. Relating to JavaScript (and why it's mostly irrelevant here):**

Consider if any of the tested functionality directly translates to JavaScript concepts in a typical browser context. While JavaScript deals with asynchronous operations (like network requests), the *low-level network simulation* happening in this C++ code is far removed from typical JavaScript development. The simulator operates at a level of detail not directly exposed in browser-based JavaScript. Therefore, the relationship is quite weak. It's important to acknowledge this rather than trying to force a connection.

**6. Logical Reasoning with Examples (Hypothetical Inputs and Outputs):**

For key test cases (like `DirectLinkSaturation`, `QueueBottleneck`, `SwitchedNetwork`), devise simple hypothetical scenarios:

* **`DirectLinkSaturation`:** Assume specific packet sizes and link bandwidth. Calculate expected transmission times and packet counts to demonstrate the simulator's accuracy.
* **`QueueBottleneck`:**  Illustrate how a bottleneck link and queue lead to packet loss, and calculate the approximate loss ratio.
* **`SwitchedNetwork`:** Show how packets are routed through a switch and how the switch learns the destination of endpoints.

**7. Common Usage Errors:**

Think about typical mistakes a developer might make when *using* the simulator or interpreting its results:

* **Incorrect Time Units:** Mixing milliseconds and seconds without careful conversion.
* **Unrealistic Network Parameters:** Setting bandwidth or delay values that don't make sense in a real-world context.
* **Forgetting to Run the Simulation:**  Not calling `RunUntil` or `RunFor` to advance the simulation time.
* **Incorrect Termination Conditions:** Setting `RunUntil` conditions that will never be met, leading to infinite loops.
* **Misinterpreting Counters:**  Confusing the number of packets sent versus received.

**8. Debugging Clues (User Journey):**

Imagine a scenario where a developer ends up looking at this specific test file:

* **Debugging Network Issues in QUIC:** A developer working on QUIC implementation might encounter unexpected behavior related to congestion control, packet loss, or routing.
* **Investigating Simulator Bugs:**  If the simulator itself is behaving strangely, a developer might dive into its test files to understand its intended behavior and identify discrepancies.
* **Adding New Simulator Features:**  A developer implementing a new network component for the simulator would likely look at existing test files to understand how to write new tests.
* **Code Review or Learning:**  Someone new to the QUIC codebase might explore test files to get a practical understanding of how the simulator works.

**9. Structuring the Explanation:**

Organize the findings into a clear and logical structure, as demonstrated in the example output. Use headings and bullet points to improve readability. Start with a high-level summary and then delve into specifics for each aspect of the request.

**10. Review and Refinement:**

Finally, review the generated explanation for accuracy, clarity, and completeness. Ensure that the examples are easy to understand and the explanations are concise yet informative. Double-check for any inconsistencies or areas that could be explained more clearly. For example, initially, the connection to JavaScript might have been overemphasized; refining it to acknowledge the weak relationship makes the explanation more accurate.
这个文件 `net/third_party/quiche/src/quiche/quic/test_tools/simulator/simulator_test.cc` 是 Chromium 网络栈中 QUIC 协议仿真器（simulator）的单元测试文件。它包含了多个测试用例，用于验证仿真器及其各个组件的功能是否正确。

**主要功能：**

1. **测试仿真器的核心功能:**
   - **事件调度:** 测试仿真器能否按照时间顺序执行事件（通过 `Actor` 类和 `Schedule` 方法）。
   - **时间推进:** 测试 `RunUntil` 和 `RunFor` 方法能否正确地推进仿真时间。
   - **Actor 生命周期:** 测试在仿真过程中创建和销毁 `Actor` 的能力。

2. **测试网络组件的模拟:**
   - **链路 (Link):** 测试 `SymmetricLink` 和 `OneWayLink` 能否按照指定的带宽和延迟传输数据包。
   - **队列 (Queue):** 测试 `Queue` 能否根据容量限制存储数据包，并在适当的时候转发。包括测试数据包的丢弃和聚合功能。
   - **交换机 (Switch):** 测试 `Switch` 能否根据数据包的目标地址将数据包转发到正确的端口。
   - **流量整形器 (TrafficPolicer):** 测试 `TrafficPolicer` 能否按照设定的速率限制流量，并允许一定的突发。
   - **数据包过滤器 (PacketFilter):** 测试 `PacketFilter` 能否根据自定义规则过滤数据包。
   - **端口 (Port):** 测试不同类型的端口 (`UnconstrainedPortInterface`, `ConstrainedPortInterface`) 如何接收和处理数据包。

3. **测试告警机制 (Alarm):**
   - 测试 `QuicAlarm` 能否在指定的时间触发回调函数。
   - 测试告警的设置、取消和重复触发功能。

**与 JavaScript 功能的关系：**

这个 C++ 文件本身与 JavaScript 没有直接的功能关系。它是在 Chromium 的 C++ 代码库中，用于测试网络协议的仿真环境。然而，理解其功能有助于理解 QUIC 协议在浏览器中的行为，而 QUIC 协议是现代 Web 技术的重要组成部分，与 JavaScript 的网络请求息息相关。

例如：

* **延迟和带宽影响:**  `SimulatorTest` 中测试了链路的延迟和带宽对数据传输的影响。这与 JavaScript 中通过 `fetch` 或 `XMLHttpRequest` 发起网络请求时，实际感受到的网络延迟和传输速度是对应的。
* **队列拥塞和丢包:** 测试用例模拟了队列的拥塞和丢包情况。这可以帮助理解在网络拥塞时，JavaScript 发起的请求可能会失败或超时。
* **流量控制:** `TrafficPolicer` 的测试模拟了网络中的流量控制机制。这可以解释为什么在某些情况下，即使网络带宽很高，JavaScript 的网络请求速度仍然可能受到限制。

**逻辑推理 (假设输入与输出):**

**示例 1: `DirectLinkSaturation` 测试**

* **假设输入:**
    - 两个 `LinkSaturator` (A 和 B) 互相发送数据包。
    - 链路带宽为 1000 KB/s。
    - 从 A 到 B 的数据包大小为 1000 字节。
    - 从 B 到 A 的数据包大小为 100 字节。
    - 仿真运行到 B 接收到 100 个数据包。
* **逻辑推理:**
    - 由于链路是对称的，带宽在两个方向上是共享的。
    - B 接收到 100 个 100 字节的数据包，总共接收到 10000 字节。
    - 根据带宽，可以计算出大致的传输时间。
    - 在这个时间内，A 应该发送了更多的数据包（因为 A 发送的数据包更大）。
* **预期输出:**
    - `saturator_b.counter()->packets()` 的值应该接近 100。
    - `saturator_a.packets_transmitted()` 的值应该大于 100。
    - 观察到的带宽应该接近设定的链路带宽。

**示例 2: `QueueBottleneck` 测试**

* **假设输入:**
    - 一个 `LinkSaturator` 发送数据包到一个 `Queue`。
    - `Queue` 连接到一个带宽较低的 `OneWayLink`。
    - 队列容量有限。
    - `LinkSaturator` 发送大量数据包。
* **逻辑推理:**
    - 由于出口链路带宽较低，`Queue` 会积累数据包。
    - 当 `Queue` 满时，后续到达的数据包将被丢弃。
    - 接收端收到的数据包数量将少于发送端发送的数据包数量。
* **预期输出:**
    - 接收端的 `CounterPort` 接收到的数据包数量会少于发送端的 `LinkSaturator` 发送的数据包数量。
    - 可以计算出一个近似的丢包率。

**用户或编程常见的使用错误：**

1. **时间单位混淆:** 在设置延迟或运行时间时，可能会错误地使用不同的时间单位（例如，秒和毫秒）。
   ```c++
   // 错误示例：假设 period_ 的单位是秒，但设置了毫秒值
   Counter fast_counter(&simulator, "fast_counter", QuicTime::Delta::FromMilliseconds(3));
   ```

2. **`RunUntil` 条件错误:**  `RunUntil` 的条件可能永远无法满足，导致仿真无限期运行。
   ```c++
   // 错误示例：如果 slow_counter 的值增长缓慢，且初始值很大，条件可能永远不成立
   simulator.RunUntil([&slow_counter]() { return slow_counter.get_value() == -1; });
   ```

3. **未正确连接网络组件:**  忘记将 `Endpoint` 的发送端口连接到下游的 `Port`，导致数据包无法传输。
   ```c++
   // 错误示例：忘记设置 saturator_a 的发送端口
   LinkSaturator saturator_a(&simulator, "Saturator A", 1000, "Saturator B");
   LinkSaturator saturator_b(&simulator, "Saturator B", 100, "Saturator A");
   // 缺少将 saturator_a 的发送端口连接到某个 Port 的代码
   ```

4. **队列容量设置不合理:**  队列容量设置过小，导致大量数据包被立即丢弃，无法模拟真实的排队行为。

5. **对仿真结果的误读:**  没有充分理解仿真器的模型和参数，错误地解释仿真结果。例如，将模拟丢包视为真实网络中的丢包。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **遇到网络问题或性能瓶颈:** 用户在使用 Chromium 浏览器时，可能会遇到网页加载缓慢、视频卡顿等网络问题。

2. **怀疑 QUIC 协议有问题:**  如果问题涉及到使用了 QUIC 协议的连接，开发人员可能会怀疑 QUIC 协议的实现是否存在问题。

3. **查看 QUIC 相关的代码:**  开发人员可能会查看 Chromium 中 QUIC 协议相关的源代码，寻找潜在的 bug 或性能瓶颈。

4. **关注 QUIC 的测试工具:**  为了验证 QUIC 协议的实现，开发人员会关注 QUIC 的测试工具，特别是仿真器。

5. **查看 `simulator_test.cc`:**  为了理解仿真器的工作原理以及如何测试不同的网络场景，开发人员可能会打开 `net/third_party/quiche/src/quiche/quic/test_tools/simulator/simulator_test.cc` 文件。

6. **分析测试用例:**  开发人员会仔细分析文件中的各个测试用例，了解如何使用仿真器模拟不同的网络拓扑和流量模式。

7. **调试特定的测试用例:**  如果怀疑某个特定的网络场景存在问题，开发人员可能会修改或运行相关的测试用例，以便更深入地了解问题的根源。

8. **可能修改仿真器代码:**  如果发现仿真器本身存在缺陷，或者需要添加新的仿真功能以复现特定的问题，开发人员可能会修改仿真器的源代码。

总之，`simulator_test.cc` 是一个非常重要的文件，它展示了如何使用 QUIC 协议的仿真器来测试各种网络场景，验证 QUIC 协议实现的正确性，并帮助开发人员理解和调试网络问题。 它是 QUIC 协议开发和维护的重要组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/simulator/simulator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/test_tools/simulator/simulator.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/node_hash_map.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/alarm_factory.h"
#include "quiche/quic/test_tools/simulator/link.h"
#include "quiche/quic/test_tools/simulator/packet_filter.h"
#include "quiche/quic/test_tools/simulator/queue.h"
#include "quiche/quic/test_tools/simulator/switch.h"
#include "quiche/quic/test_tools/simulator/traffic_policer.h"

using testing::_;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace simulator {

// A simple counter that increments its value by 1 every specified period.
class Counter : public Actor {
 public:
  Counter(Simulator* simulator, std::string name, QuicTime::Delta period)
      : Actor(simulator, name), value_(-1), period_(period) {
    Schedule(clock_->Now());
  }
  ~Counter() override {}

  inline int get_value() const { return value_; }

  void Act() override {
    ++value_;
    QUIC_DVLOG(1) << name_ << " has value " << value_ << " at time "
                  << clock_->Now().ToDebuggingValue();
    Schedule(clock_->Now() + period_);
  }

 private:
  int value_;
  QuicTime::Delta period_;
};

class SimulatorTest : public quic::test::QuicTest {};

// Test that the basic event handling works, and that Actors can be created and
// destroyed mid-simulation.
TEST_F(SimulatorTest, Counters) {
  Simulator simulator;
  for (int i = 0; i < 2; ++i) {
    Counter fast_counter(&simulator, "fast_counter",
                         QuicTime::Delta::FromSeconds(3));
    Counter slow_counter(&simulator, "slow_counter",
                         QuicTime::Delta::FromSeconds(10));

    simulator.RunUntil(
        [&slow_counter]() { return slow_counter.get_value() >= 10; });

    EXPECT_EQ(10, slow_counter.get_value());
    EXPECT_EQ(10 * 10 / 3, fast_counter.get_value());
  }
}

// A port which counts the number of packets received on it, both total and
// per-destination.
class CounterPort : public UnconstrainedPortInterface {
 public:
  CounterPort() { Reset(); }
  ~CounterPort() override {}

  inline QuicByteCount bytes() const { return bytes_; }
  inline QuicPacketCount packets() const { return packets_; }

  void AcceptPacket(std::unique_ptr<Packet> packet) override {
    bytes_ += packet->size;
    packets_ += 1;

    per_destination_packet_counter_[packet->destination] += 1;
  }

  void Reset() {
    bytes_ = 0;
    packets_ = 0;
    per_destination_packet_counter_.clear();
  }

  QuicPacketCount CountPacketsForDestination(std::string destination) const {
    auto result_it = per_destination_packet_counter_.find(destination);
    if (result_it == per_destination_packet_counter_.cend()) {
      return 0;
    }
    return result_it->second;
  }

 private:
  QuicByteCount bytes_;
  QuicPacketCount packets_;

  absl::node_hash_map<std::string, QuicPacketCount>
      per_destination_packet_counter_;
};

// Sends the packet to the specified destination at the uplink rate.  Provides a
// CounterPort as an Rx interface.
class LinkSaturator : public Endpoint {
 public:
  LinkSaturator(Simulator* simulator, std::string name,
                QuicByteCount packet_size, std::string destination)
      : Endpoint(simulator, name),
        packet_size_(packet_size),
        destination_(std::move(destination)),
        bytes_transmitted_(0),
        packets_transmitted_(0) {
    Schedule(clock_->Now());
  }

  void Act() override {
    if (tx_port_->TimeUntilAvailable().IsZero()) {
      auto packet = std::make_unique<Packet>();
      packet->source = name_;
      packet->destination = destination_;
      packet->tx_timestamp = clock_->Now();
      packet->size = packet_size_;

      tx_port_->AcceptPacket(std::move(packet));

      bytes_transmitted_ += packet_size_;
      packets_transmitted_ += 1;
    }

    Schedule(clock_->Now() + tx_port_->TimeUntilAvailable());
  }

  UnconstrainedPortInterface* GetRxPort() override {
    return static_cast<UnconstrainedPortInterface*>(&rx_port_);
  }

  void SetTxPort(ConstrainedPortInterface* port) override { tx_port_ = port; }

  CounterPort* counter() { return &rx_port_; }

  inline QuicByteCount bytes_transmitted() const { return bytes_transmitted_; }
  inline QuicPacketCount packets_transmitted() const {
    return packets_transmitted_;
  }

  void Pause() { Unschedule(); }
  void Resume() { Schedule(clock_->Now()); }

 private:
  QuicByteCount packet_size_;
  std::string destination_;

  ConstrainedPortInterface* tx_port_;
  CounterPort rx_port_;

  QuicByteCount bytes_transmitted_;
  QuicPacketCount packets_transmitted_;
};

// Saturate a symmetric link and verify that the number of packets sent and
// received is correct.
TEST_F(SimulatorTest, DirectLinkSaturation) {
  Simulator simulator;
  LinkSaturator saturator_a(&simulator, "Saturator A", 1000, "Saturator B");
  LinkSaturator saturator_b(&simulator, "Saturator B", 100, "Saturator A");
  SymmetricLink link(&saturator_a, &saturator_b,
                     QuicBandwidth::FromKBytesPerSecond(1000),
                     QuicTime::Delta::FromMilliseconds(100) +
                         QuicTime::Delta::FromMicroseconds(1));

  const QuicTime start_time = simulator.GetClock()->Now();
  const QuicTime after_first_50_ms =
      start_time + QuicTime::Delta::FromMilliseconds(50);
  simulator.RunUntil([&simulator, after_first_50_ms]() {
    return simulator.GetClock()->Now() >= after_first_50_ms;
  });
  EXPECT_LE(1000u * 50u, saturator_a.bytes_transmitted());
  EXPECT_GE(1000u * 51u, saturator_a.bytes_transmitted());
  EXPECT_LE(1000u * 50u, saturator_b.bytes_transmitted());
  EXPECT_GE(1000u * 51u, saturator_b.bytes_transmitted());
  EXPECT_LE(50u, saturator_a.packets_transmitted());
  EXPECT_GE(51u, saturator_a.packets_transmitted());
  EXPECT_LE(500u, saturator_b.packets_transmitted());
  EXPECT_GE(501u, saturator_b.packets_transmitted());
  EXPECT_EQ(0u, saturator_a.counter()->bytes());
  EXPECT_EQ(0u, saturator_b.counter()->bytes());

  simulator.RunUntil([&saturator_a, &saturator_b]() {
    if (saturator_a.counter()->packets() > 1000 ||
        saturator_b.counter()->packets() > 100) {
      ADD_FAILURE() << "The simulation did not arrive at the expected "
                       "termination contidition. Saturator A counter: "
                    << saturator_a.counter()->packets()
                    << ", saturator B counter: "
                    << saturator_b.counter()->packets();
      return true;
    }

    return saturator_a.counter()->packets() == 1000 &&
           saturator_b.counter()->packets() == 100;
  });
  EXPECT_EQ(201u, saturator_a.packets_transmitted());
  EXPECT_EQ(2001u, saturator_b.packets_transmitted());
  EXPECT_EQ(201u * 1000, saturator_a.bytes_transmitted());
  EXPECT_EQ(2001u * 100, saturator_b.bytes_transmitted());

  EXPECT_EQ(1000u,
            saturator_a.counter()->CountPacketsForDestination("Saturator A"));
  EXPECT_EQ(100u,
            saturator_b.counter()->CountPacketsForDestination("Saturator B"));
  EXPECT_EQ(0u,
            saturator_a.counter()->CountPacketsForDestination("Saturator B"));
  EXPECT_EQ(0u,
            saturator_b.counter()->CountPacketsForDestination("Saturator A"));

  const QuicTime end_time = simulator.GetClock()->Now();
  const QuicBandwidth observed_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      saturator_a.bytes_transmitted(), end_time - start_time);
  EXPECT_APPROX_EQ(link.bandwidth(), observed_bandwidth, 0.01f);
}

// Accepts packets and stores them internally.
class PacketAcceptor : public ConstrainedPortInterface {
 public:
  void AcceptPacket(std::unique_ptr<Packet> packet) override {
    packets_.emplace_back(std::move(packet));
  }

  QuicTime::Delta TimeUntilAvailable() override {
    return QuicTime::Delta::Zero();
  }

  std::vector<std::unique_ptr<Packet>>* packets() { return &packets_; }

 private:
  std::vector<std::unique_ptr<Packet>> packets_;
};

// Ensure the queue behaves correctly with accepting packets.
TEST_F(SimulatorTest, Queue) {
  Simulator simulator;
  Queue queue(&simulator, "Queue", 1000);
  PacketAcceptor acceptor;
  queue.set_tx_port(&acceptor);

  EXPECT_EQ(0u, queue.bytes_queued());
  EXPECT_EQ(0u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  auto first_packet = std::make_unique<Packet>();
  first_packet->size = 600;
  queue.AcceptPacket(std::move(first_packet));
  EXPECT_EQ(600u, queue.bytes_queued());
  EXPECT_EQ(1u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  // The second packet does not fit and is dropped.
  auto second_packet = std::make_unique<Packet>();
  second_packet->size = 500;
  queue.AcceptPacket(std::move(second_packet));
  EXPECT_EQ(600u, queue.bytes_queued());
  EXPECT_EQ(1u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  auto third_packet = std::make_unique<Packet>();
  third_packet->size = 400;
  queue.AcceptPacket(std::move(third_packet));
  EXPECT_EQ(1000u, queue.bytes_queued());
  EXPECT_EQ(2u, queue.packets_queued());
  EXPECT_EQ(0u, acceptor.packets()->size());

  // Run until there is nothing scheduled, so that the queue can deplete.
  simulator.RunUntil([]() { return false; });
  EXPECT_EQ(0u, queue.bytes_queued());
  EXPECT_EQ(0u, queue.packets_queued());
  ASSERT_EQ(2u, acceptor.packets()->size());
  EXPECT_EQ(600u, acceptor.packets()->at(0)->size);
  EXPECT_EQ(400u, acceptor.packets()->at(1)->size);
}

// Simulate a situation where the bottleneck link is 10 times slower than the
// uplink, and they are separated by a queue.
TEST_F(SimulatorTest, QueueBottleneck) {
  const QuicBandwidth local_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(1000);
  const QuicBandwidth bottleneck_bandwidth = 0.1f * local_bandwidth;
  const QuicTime::Delta local_propagation_delay =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta bottleneck_propagation_delay =
      QuicTime::Delta::FromMilliseconds(20);
  const QuicByteCount bdp =
      bottleneck_bandwidth *
      (local_propagation_delay + bottleneck_propagation_delay);

  Simulator simulator;
  LinkSaturator saturator(&simulator, "Saturator", 1000, "Counter");
  ASSERT_GE(bdp, 1000u);
  Queue queue(&simulator, "Queue", bdp);
  CounterPort counter;

  OneWayLink local_link(&simulator, "Local link", &queue, local_bandwidth,
                        local_propagation_delay);
  OneWayLink bottleneck_link(&simulator, "Bottleneck link", &counter,
                             bottleneck_bandwidth,
                             bottleneck_propagation_delay);
  saturator.SetTxPort(&local_link);
  queue.set_tx_port(&bottleneck_link);

  static const QuicPacketCount packets_received = 1000;
  simulator.RunUntil(
      [&counter]() { return counter.packets() == packets_received; });
  const double loss_ratio = 1 - static_cast<double>(packets_received) /
                                    saturator.packets_transmitted();
  EXPECT_NEAR(loss_ratio, 0.9, 0.001);
}

// Verify that the queue of exactly one packet allows the transmission to
// actually go through.
TEST_F(SimulatorTest, OnePacketQueue) {
  const QuicBandwidth local_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(1000);
  const QuicBandwidth bottleneck_bandwidth = 0.1f * local_bandwidth;
  const QuicTime::Delta local_propagation_delay =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta bottleneck_propagation_delay =
      QuicTime::Delta::FromMilliseconds(20);

  Simulator simulator;
  LinkSaturator saturator(&simulator, "Saturator", 1000, "Counter");
  Queue queue(&simulator, "Queue", 1000);
  CounterPort counter;

  OneWayLink local_link(&simulator, "Local link", &queue, local_bandwidth,
                        local_propagation_delay);
  OneWayLink bottleneck_link(&simulator, "Bottleneck link", &counter,
                             bottleneck_bandwidth,
                             bottleneck_propagation_delay);
  saturator.SetTxPort(&local_link);
  queue.set_tx_port(&bottleneck_link);

  static const QuicPacketCount packets_received = 10;
  // The deadline here is to prevent this tests from looping infinitely in case
  // the packets never reach the receiver.
  const QuicTime deadline =
      simulator.GetClock()->Now() + QuicTime::Delta::FromSeconds(10);
  simulator.RunUntil([&simulator, &counter, deadline]() {
    return counter.packets() == packets_received ||
           simulator.GetClock()->Now() > deadline;
  });
  ASSERT_EQ(packets_received, counter.packets());
}

// Simulate a network where three endpoints are connected to a switch and they
// are sending traffic in circle (1 -> 2, 2 -> 3, 3 -> 1).
TEST_F(SimulatorTest, SwitchedNetwork) {
  const QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(10000);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMilliseconds(50);

  Simulator simulator;
  LinkSaturator saturator1(&simulator, "Saturator 1", 1000, "Saturator 2");
  LinkSaturator saturator2(&simulator, "Saturator 2", 1000, "Saturator 3");
  LinkSaturator saturator3(&simulator, "Saturator 3", 1000, "Saturator 1");
  Switch network_switch(&simulator, "Switch", 8,
                        bandwidth * base_propagation_delay * 10);

  // For determinicity, make it so that the first packet will arrive from
  // Saturator 1, then from Saturator 2, and then from Saturator 3.
  SymmetricLink link1(&saturator1, network_switch.port(1), bandwidth,
                      base_propagation_delay);
  SymmetricLink link2(&saturator2, network_switch.port(2), bandwidth,
                      base_propagation_delay * 2);
  SymmetricLink link3(&saturator3, network_switch.port(3), bandwidth,
                      base_propagation_delay * 3);

  const QuicTime start_time = simulator.GetClock()->Now();
  static const QuicPacketCount bytes_received = 64 * 1000;
  simulator.RunUntil([&saturator1]() {
    return saturator1.counter()->bytes() >= bytes_received;
  });
  const QuicTime end_time = simulator.GetClock()->Now();

  const QuicBandwidth observed_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      bytes_received, end_time - start_time);
  const double bandwidth_ratio =
      static_cast<double>(observed_bandwidth.ToBitsPerSecond()) /
      bandwidth.ToBitsPerSecond();
  EXPECT_NEAR(1, bandwidth_ratio, 0.1);

  const double normalized_received_packets_for_saturator_2 =
      static_cast<double>(saturator2.counter()->packets()) /
      saturator1.counter()->packets();
  const double normalized_received_packets_for_saturator_3 =
      static_cast<double>(saturator3.counter()->packets()) /
      saturator1.counter()->packets();
  EXPECT_NEAR(1, normalized_received_packets_for_saturator_2, 0.1);
  EXPECT_NEAR(1, normalized_received_packets_for_saturator_3, 0.1);

  // Since Saturator 1 has its packet arrive first into the switch, switch will
  // always know how to route traffic to it.
  EXPECT_EQ(0u,
            saturator2.counter()->CountPacketsForDestination("Saturator 1"));
  EXPECT_EQ(0u,
            saturator3.counter()->CountPacketsForDestination("Saturator 1"));

  // Packets from the other saturators will be broadcast at least once.
  EXPECT_EQ(1u,
            saturator1.counter()->CountPacketsForDestination("Saturator 2"));
  EXPECT_EQ(1u,
            saturator3.counter()->CountPacketsForDestination("Saturator 2"));
  EXPECT_EQ(1u,
            saturator1.counter()->CountPacketsForDestination("Saturator 3"));
  EXPECT_EQ(1u,
            saturator2.counter()->CountPacketsForDestination("Saturator 3"));
}

// Toggle an alarm on and off at the specified interval.  Assumes that alarm is
// initially set and unsets it almost immediately after the object is
// instantiated.
class AlarmToggler : public Actor {
 public:
  AlarmToggler(Simulator* simulator, std::string name, QuicAlarm* alarm,
               QuicTime::Delta interval)
      : Actor(simulator, name),
        alarm_(alarm),
        interval_(interval),
        deadline_(alarm->deadline()),
        times_set_(0),
        times_cancelled_(0) {
    EXPECT_TRUE(alarm->IsSet());
    EXPECT_GE(alarm->deadline(), clock_->Now());
    Schedule(clock_->Now());
  }

  void Act() override {
    if (deadline_ <= clock_->Now()) {
      return;
    }

    if (alarm_->IsSet()) {
      alarm_->Cancel();
      times_cancelled_++;
    } else {
      alarm_->Set(deadline_);
      times_set_++;
    }

    Schedule(clock_->Now() + interval_);
  }

  inline int times_set() { return times_set_; }
  inline int times_cancelled() { return times_cancelled_; }

 private:
  QuicAlarm* alarm_;
  QuicTime::Delta interval_;
  QuicTime deadline_;

  // Counts the number of times the alarm was set.
  int times_set_;
  // Counts the number of times the alarm was cancelled.
  int times_cancelled_;
};

// Counts the number of times an alarm has fired.
class CounterDelegate : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit CounterDelegate(size_t* counter) : counter_(counter) {}

  void OnAlarm() override { *counter_ += 1; }

 private:
  size_t* counter_;
};

// Verifies that the alarms work correctly, even when they are repeatedly
// toggled.
TEST_F(SimulatorTest, Alarms) {
  Simulator simulator;
  QuicAlarmFactory* alarm_factory = simulator.GetAlarmFactory();

  size_t fast_alarm_counter = 0;
  size_t slow_alarm_counter = 0;
  std::unique_ptr<QuicAlarm> alarm_fast(
      alarm_factory->CreateAlarm(new CounterDelegate(&fast_alarm_counter)));
  std::unique_ptr<QuicAlarm> alarm_slow(
      alarm_factory->CreateAlarm(new CounterDelegate(&slow_alarm_counter)));

  const QuicTime start_time = simulator.GetClock()->Now();
  alarm_fast->Set(start_time + QuicTime::Delta::FromMilliseconds(100));
  alarm_slow->Set(start_time + QuicTime::Delta::FromMilliseconds(750));
  AlarmToggler toggler(&simulator, "Toggler", alarm_slow.get(),
                       QuicTime::Delta::FromMilliseconds(100));

  const QuicTime end_time =
      start_time + QuicTime::Delta::FromMilliseconds(1000);
  EXPECT_FALSE(simulator.RunUntil([&simulator, end_time]() {
    return simulator.GetClock()->Now() >= end_time;
  }));
  EXPECT_EQ(1u, slow_alarm_counter);
  EXPECT_EQ(1u, fast_alarm_counter);

  EXPECT_EQ(4, toggler.times_set());
  EXPECT_EQ(4, toggler.times_cancelled());
}

// Verifies that a cancelled alarm is never fired.
TEST_F(SimulatorTest, AlarmCancelling) {
  Simulator simulator;
  QuicAlarmFactory* alarm_factory = simulator.GetAlarmFactory();

  size_t alarm_counter = 0;
  std::unique_ptr<QuicAlarm> alarm(
      alarm_factory->CreateAlarm(new CounterDelegate(&alarm_counter)));

  const QuicTime start_time = simulator.GetClock()->Now();
  const QuicTime alarm_at = start_time + QuicTime::Delta::FromMilliseconds(300);
  const QuicTime end_time = start_time + QuicTime::Delta::FromMilliseconds(400);

  alarm->Set(alarm_at);
  alarm->Cancel();
  EXPECT_FALSE(alarm->IsSet());

  EXPECT_FALSE(simulator.RunUntil([&simulator, end_time]() {
    return simulator.GetClock()->Now() >= end_time;
  }));

  EXPECT_FALSE(alarm->IsSet());
  EXPECT_EQ(0u, alarm_counter);
}

// Verifies that alarms can be scheduled into the past.
TEST_F(SimulatorTest, AlarmInPast) {
  Simulator simulator;
  QuicAlarmFactory* alarm_factory = simulator.GetAlarmFactory();

  size_t alarm_counter = 0;
  std::unique_ptr<QuicAlarm> alarm(
      alarm_factory->CreateAlarm(new CounterDelegate(&alarm_counter)));

  const QuicTime start_time = simulator.GetClock()->Now();
  simulator.RunFor(QuicTime::Delta::FromMilliseconds(400));

  alarm->Set(start_time);
  simulator.RunFor(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_FALSE(alarm->IsSet());
  EXPECT_EQ(1u, alarm_counter);
}

// Tests Simulator::RunUntilOrTimeout() interface.
TEST_F(SimulatorTest, RunUntilOrTimeout) {
  Simulator simulator;
  bool simulation_result;

  // Count the number of seconds since the beginning of the simulation.
  Counter counter(&simulator, "counter", QuicTime::Delta::FromSeconds(1));

  // Ensure that the counter reaches the value of 10 given a 20 second deadline.
  simulation_result = simulator.RunUntilOrTimeout(
      [&counter]() { return counter.get_value() == 10; },
      QuicTime::Delta::FromSeconds(20));
  ASSERT_TRUE(simulation_result);

  // Ensure that the counter will not reach the value of 100 given that the
  // starting value is 10 and the deadline is 20 seconds.
  simulation_result = simulator.RunUntilOrTimeout(
      [&counter]() { return counter.get_value() == 100; },
      QuicTime::Delta::FromSeconds(20));
  ASSERT_FALSE(simulation_result);
}

// Tests Simulator::RunFor() interface.
TEST_F(SimulatorTest, RunFor) {
  Simulator simulator;

  Counter counter(&simulator, "counter", QuicTime::Delta::FromSeconds(3));

  simulator.RunFor(QuicTime::Delta::FromSeconds(100));

  EXPECT_EQ(33, counter.get_value());
}

class MockPacketFilter : public PacketFilter {
 public:
  MockPacketFilter(Simulator* simulator, std::string name, Endpoint* endpoint)
      : PacketFilter(simulator, name, endpoint) {}
  MOCK_METHOD(bool, FilterPacket, (const Packet&), (override));
};

// Set up two trivial packet filters, one allowing any packets, and one dropping
// all of them.
TEST_F(SimulatorTest, PacketFilter) {
  const QuicBandwidth bandwidth =
      QuicBandwidth::FromBytesPerSecond(1024 * 1024);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMilliseconds(5);

  Simulator simulator;
  LinkSaturator saturator_a(&simulator, "Saturator A", 1000, "Saturator B");
  LinkSaturator saturator_b(&simulator, "Saturator B", 1000, "Saturator A");

  // Attach packets to the switch to create a delay between the point at which
  // the packet is generated and the point at which it is filtered.  Note that
  // if the saturators were connected directly, the link would be always
  // available for the endpoint which has all of its packets dropped, resulting
  // in saturator looping infinitely.
  Switch network_switch(&simulator, "Switch", 8,
                        bandwidth * base_propagation_delay * 10);
  StrictMock<MockPacketFilter> a_to_b_filter(&simulator, "A -> B filter",
                                             network_switch.port(1));
  StrictMock<MockPacketFilter> b_to_a_filter(&simulator, "B -> A filter",
                                             network_switch.port(2));
  SymmetricLink link_a(&a_to_b_filter, &saturator_b, bandwidth,
                       base_propagation_delay);
  SymmetricLink link_b(&b_to_a_filter, &saturator_a, bandwidth,
                       base_propagation_delay);

  // Allow packets from A to B, but not from B to A.
  EXPECT_CALL(a_to_b_filter, FilterPacket(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(b_to_a_filter, FilterPacket(_)).WillRepeatedly(Return(false));

  // Run the simulation for a while, and expect that only B will receive any
  // packets.
  simulator.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_GE(saturator_b.counter()->packets(), 1u);
  EXPECT_EQ(saturator_a.counter()->packets(), 0u);
}

// Set up a traffic policer in one direction that throttles at 25% of link
// bandwidth, and put two link saturators at each endpoint.
TEST_F(SimulatorTest, TrafficPolicer) {
  const QuicBandwidth bandwidth =
      QuicBandwidth::FromBytesPerSecond(1024 * 1024);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMilliseconds(5);
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);

  Simulator simulator;
  LinkSaturator saturator1(&simulator, "Saturator 1", 1000, "Saturator 2");
  LinkSaturator saturator2(&simulator, "Saturator 2", 1000, "Saturator 1");
  Switch network_switch(&simulator, "Switch", 8,
                        bandwidth * base_propagation_delay * 10);

  static const QuicByteCount initial_burst = 1000 * 10;
  static const QuicByteCount max_bucket_size = 1000 * 100;
  static const QuicBandwidth target_bandwidth = bandwidth * 0.25;
  TrafficPolicer policer(&simulator, "Policer", initial_burst, max_bucket_size,
                         target_bandwidth, network_switch.port(2));

  SymmetricLink link1(&saturator1, network_switch.port(1), bandwidth,
                      base_propagation_delay);
  SymmetricLink link2(&saturator2, &policer, bandwidth, base_propagation_delay);

  // Ensure the initial burst passes without being dropped at all.
  bool simulator_result = simulator.RunUntilOrTimeout(
      [&saturator1]() {
        return saturator1.bytes_transmitted() == initial_burst;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  saturator1.Pause();
  simulator_result = simulator.RunUntilOrTimeout(
      [&saturator2]() {
        return saturator2.counter()->bytes() == initial_burst;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  saturator1.Resume();

  // Run for some time so that the initial burst is not visible.
  const QuicTime::Delta simulation_time = QuicTime::Delta::FromSeconds(10);
  simulator.RunFor(simulation_time);

  // Ensure we've transmitted the amount of data we expected.
  for (auto* saturator : {&saturator1, &saturator2}) {
    EXPECT_APPROX_EQ(bandwidth * simulation_time,
                     saturator->bytes_transmitted(), 0.01f);
  }

  // Check that only one direction is throttled.
  EXPECT_APPROX_EQ(saturator1.bytes_transmitted() / 4,
                   saturator2.counter()->bytes(), 0.1f);
  EXPECT_APPROX_EQ(saturator2.bytes_transmitted(),
                   saturator1.counter()->bytes(), 0.1f);
}

// Ensure that a larger burst is allowed when the policed saturator exits
// quiescence.
TEST_F(SimulatorTest, TrafficPolicerBurst) {
  const QuicBandwidth bandwidth =
      QuicBandwidth::FromBytesPerSecond(1024 * 1024);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMilliseconds(5);
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);

  Simulator simulator;
  LinkSaturator saturator1(&simulator, "Saturator 1", 1000, "Saturator 2");
  LinkSaturator saturator2(&simulator, "Saturator 2", 1000, "Saturator 1");
  Switch network_switch(&simulator, "Switch", 8,
                        bandwidth * base_propagation_delay * 10);

  const QuicByteCount initial_burst = 1000 * 10;
  const QuicByteCount max_bucket_size = 1000 * 100;
  const QuicBandwidth target_bandwidth = bandwidth * 0.25;
  TrafficPolicer policer(&simulator, "Policer", initial_burst, max_bucket_size,
                         target_bandwidth, network_switch.port(2));

  SymmetricLink link1(&saturator1, network_switch.port(1), bandwidth,
                      base_propagation_delay);
  SymmetricLink link2(&saturator2, &policer, bandwidth, base_propagation_delay);

  // Ensure at least one packet is sent on each side.
  bool simulator_result = simulator.RunUntilOrTimeout(
      [&saturator1, &saturator2]() {
        return saturator1.packets_transmitted() > 0 &&
               saturator2.packets_transmitted() > 0;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Wait until the bucket fills up.
  saturator1.Pause();
  saturator2.Pause();
  simulator.RunFor(1.5f * target_bandwidth.TransferTime(max_bucket_size));

  // Send a burst.
  saturator1.Resume();
  simulator.RunFor(bandwidth.TransferTime(max_bucket_size));
  saturator1.Pause();
  simulator.RunFor(2 * base_propagation_delay);

  // Expect the burst to pass without losses.
  EXPECT_APPROX_EQ(saturator1.bytes_transmitted(),
                   saturator2.counter()->bytes(), 0.1f);

  // Expect subsequent traffic to be policed.
  saturator1.Resume();
  simulator.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_APPROX_EQ(saturator1.bytes_transmitted() / 4,
                   saturator2.counter()->bytes(), 0.1f);
}

// Test that the packet aggregation support in queues work.
TEST_F(SimulatorTest, PacketAggregation) {
  // Model network where the delays are dominated by transfer delay.
  const QuicBandwidth bandwidth = QuicBandwidth::FromBytesPerSecond(1000);
  const QuicTime::Delta base_propagation_delay =
      QuicTime::Delta::FromMicroseconds(1);
  const QuicByteCount aggregation_threshold = 1000;
  const QuicTime::Delta aggregation_timeout = QuicTime::Delta::FromSeconds(30);

  Simulator simulator;
  LinkSaturator saturator1(&simulator, "Saturator 1", 10, "Saturator 2");
  LinkSaturator saturator2(&simulator, "Saturator 2", 10, "Saturator 1");
  Switch network_switch(&simulator, "Switch", 8, 10 * aggregation_threshold);

  // Make links with asymmetric propagation delay so that Saturator 2 only
  // receives packets addressed to it.
  SymmetricLink link1(&saturator1, network_switch.port(1), bandwidth,
                      base_propagation_delay);
  SymmetricLink link2(&saturator2, network_switch.port(2), bandwidth,
                      2 * base_propagation_delay);

  // Enable aggregation in 1 -> 2 direction.
  Queue* queue = network_switch.port_queue(2);
  queue->EnableAggregation(aggregation_threshold, aggregation_timeout);

  // Enable aggregation in 2 -> 1 direction in a way that all packets are larger
  // than the threshold, so that aggregation is effectively a no-op.
  network_switch.port_queue(1)->EnableAggregation(5, aggregation_timeout);

  // Fill up the aggregation buffer up to 90% (900 bytes).
  simulator.RunFor(0.9 * bandwidth.TransferTime(aggregation_threshold));
  EXPECT_EQ(0u, saturator2.counter()->bytes());

  // Stop sending, ensure that given a timespan much shorter than timeout, the
  // packets remain in the queue.
  saturator1.Pause();
  saturator2.Pause();
  simulator.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_EQ(0u, saturator2.counter()->bytes());
  EXPECT_EQ(900u, queue->bytes_queued());

  // Ensure that all packets have reached the saturator not affected by
  // aggregation.  Here, 10 extra bytes account for a misrouted packet in the
  // beginning.
  EXPECT_EQ(910u, saturator1.counter()->bytes());

  // Send 500 more bytes.  Since the aggregation threshold is 1000 bytes, and
  // queue already has 900 bytes, 1000 bytes will be send and 400 will be in the
  // queue.
  saturator1.Resume();
  simulator.RunFor(0.5 * bandwidth.TransferTime(aggregation_threshold));
  saturator1.Pause();
  simulator.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_EQ(1000u, saturator2.counter()->bytes());
  EXPECT_EQ(400u, queue->bytes_queued());

  // Actually time out, and cause all of the data to be received.
  simulator.RunFor(aggregation_timeout);
  EXPECT_EQ(1400u, saturator2.counter()->bytes());
  EXPECT_EQ(0u, queue->bytes_queued());

  // Run saturator for a longer time, to ensure that the logic to cancel and
  // reset alarms works correctly.
  saturator1.Resume();
  simulator.RunFor(5.5 * bandwidth.TransferTime(aggregation_threshold));
  saturator1.Pause();
  simulator.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_EQ(6400u, saturator2.counter()->bytes());
  EXPECT_EQ(500u, queue->bytes_queued());

  // Time out again.
  simulator.RunFor(aggregation_timeout);
  EXPECT_EQ(6900u, saturator2.counter()->bytes());
  EXPECT_EQ(0u, queue->bytes_queued());
}

}  // namespace simulator
}  // namespace quic
```