Response:
Let's break down the thought process for analyzing this C++ Chromium networking code.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the `moqt_simulator_bin.cc` file within the Chromium network stack. Specifically, the request asks for:

* **Functionality:** What does the code do?
* **JavaScript Relation:** Does it connect to JavaScript in any way?
* **Logic and I/O:**  Hypothetical inputs and outputs.
* **User Errors:** Common mistakes in usage.
* **Debugging:** How a user might arrive at this code during debugging.

**2. High-Level Analysis of the Code:**

The first step is to scan the code for keywords and structure to get a general idea.

* **Headers:**  Lots of `quiche` and `quic` headers indicate it's related to the QUIC protocol, likely the MoQT extension. Standard C++ headers like `<iostream>`, `<memory>`, `<string>`, `<vector>` are also present, suggesting a standalone application.
* **Copyright and Comments:** The initial comments clearly state it's a simulator for MoQT transport, designed to test behavior under various network conditions. This is a crucial piece of information.
* **Namespaces:** `moqt::test` confirms its testing/simulation context.
* **Key Classes:**  `ObjectGenerator`, `ObjectReceiver`, `MoqtSimulator`. These class names are very descriptive and suggest their roles in the simulation.
* **`main` Function:** This is the entry point of the program and handles command-line flags.
* **Command-Line Flags:**  `bandwidth`, `deadline`, `duration`, `delivery_order`. These immediately point to configurable simulation parameters.

**3. Deep Dive into Key Components:**

Now, examine the most important parts in detail:

* **`SimulationParameters` Struct:**  This defines the configurable aspects of the simulation (bandwidth, RTT, duration, etc.). It's central to how the simulation behaves.
* **`ObjectGenerator`:** This class *generates* data (simulating a media source). The logic for `GetFrameSize` based on `i_to_p_ratio` and `keyframe_interval` suggests it's simulating video-like data. The `AdjustBitrate` function hints at adaptive bitrate capabilities.
* **`ObjectReceiver`:** This class *receives* data and tracks whether it arrived on time. The `OnObjectFragment` method shows it handles potential fragmentation of data. The `OnFullObject` method verifies the received timestamp.
* **`MoqtSimulator`:** This is the orchestrator. It sets up the client and server endpoints, links them with network components (`Switch`, `SymmetricLink`), and runs the simulation using the `ObjectGenerator` and `ObjectReceiver`. The `Run()` method shows the simulation lifecycle, including connection establishment and waiting for a cool-down period. The output in `Run()` provides insights into the metrics being tracked.

**4. Answering the Specific Questions:**

With a good understanding of the code, address each part of the request:

* **Functionality:**  Synthesize the information gathered. The core function is to simulate MoQT behavior, allowing testing under different network conditions and application settings.
* **JavaScript Relation:**  Look for any direct interaction with JavaScript APIs or constructs. The code primarily deals with network protocols and data manipulation at a lower level. There's no immediate evidence of JavaScript interaction within *this* file. *However*, acknowledge that the larger Chromium context means this simulator could be used to *test* features that *are* exposed to JavaScript. This requires a slight inference based on general knowledge of browser architecture.
* **Logic and I/O:** Choose a few key aspects to illustrate with hypothetical inputs and outputs. Good candidates are:
    * The `ObjectGenerator` creating data based on bitrate and keyframe interval.
    * The `ObjectReceiver` checking the timestamp and categorizing received objects as on-time or late.
* **User Errors:** Think about how a developer might misuse the command-line flags or misinterpret the simulation results.
* **Debugging:**  Consider the scenarios where a developer might be looking at this specific file. This often involves investigating network performance issues, MoQT-specific problems, or testing new features. The file's structure and logging (like `absl::PrintF`) provide debugging clues.

**5. Structuring the Response:**

Organize the findings clearly and logically, following the structure of the original request. Use headings and bullet points to improve readability. Provide concrete examples and explanations.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption:**  One might initially assume this code directly interacts with the browser's rendering engine since it involves media. However, closer inspection reveals it's a *simulator* operating at the network protocol level. The focus is on data transmission, not rendering. Adjust the explanation accordingly.
* **JavaScript Link:**  Be careful not to overstate the connection to JavaScript. While there's no direct link in the code, acknowledge the broader context. Use phrases like "indirectly related" or "used to test features that might be exposed to JavaScript."
* **Technical Detail:**  While explaining the code, avoid getting bogged down in every single line. Focus on the major components and their interactions. Explain the *purpose* of code blocks rather than just describing the syntax.

By following this structured approach, including careful reading, analysis of key components, and addressing the specific questions with examples, a comprehensive and accurate understanding of the code can be developed.
这个文件 `net/third_party/quiche/src/quiche/quic/moqt/tools/moqt_simulator_bin.cc` 是 Chromium 网络栈中 QUIC 协议的 MoQT (Media over QUIC Transport) 扩展的一个**模拟器**的可执行文件。 它的主要功能是：

**核心功能：模拟 MoQT 传输行为**

* **模拟客户端和服务器:**  它可以模拟一个 MoQT 客户端和一个 MoQT 服务器的行为，无需真实的客户端或服务器应用程序。
* **模拟网络环境:**  可以配置模拟网络环境的各种参数，例如：
    * **带宽 (Bandwidth):** 模拟网络连接的传输速率。
    * **延迟 (Latency/Min RTT):** 模拟网络数据包的往返时间。
    * **网络队列大小 (Network Queue Size):** 模拟网络中的缓冲队列大小。
    * **丢包 (Loss - 虽然代码中没有直接体现，但可以通过调整网络参数间接观察影响).**
* **模拟数据生成:**  客户端模拟器可以生成符合 MoQT 规范的数据流（例如，模拟视频帧），并按照一定的速率发送。
* **模拟数据接收:**  服务器模拟器接收客户端发送的数据。
* **模拟 MoQT 会话:**  模拟 MoQT 的连接建立、订阅、发布等核心流程。
* **测试不同的配置:**  允许用户通过命令行参数配置不同的网络条件和应用参数，以测试 MoQT 在各种场景下的性能和行为。
* **性能指标测量:**  收集和输出模拟的性能指标，例如：
    * **接收到的对象数量和比例:** 成功接收的数据对象占总发送对象的比例。
    * **按时到达的对象比例:**  在指定延迟 deadline 内到达的数据对象比例。
    * **迟到到达的对象比例:**  超过指定延迟 deadline 到达的数据对象比例。
    * **未接收到的对象比例:**  丢失的数据对象比例。
    * **平均按时吞吐量 (Goodput):**  在规定时间内成功接收的有效数据量。
    * **比特率调整历史:**  观察客户端如何根据网络状况调整发送比特率。

**与 JavaScript 的关系**

这个 C++ 模拟器本身 **不直接** 与 JavaScript 交互。它的目的是在底层模拟网络协议行为。

**然而，它与 JavaScript 的功能有间接关系：**

1. **MoQT 协议的实现和测试:**  这个模拟器可以用来测试 Chromium 中 MoQT 协议的 C++ 实现是否正确，以及在不同网络条件下的行为是否符合预期。  MoQT 协议最终会被用于支持浏览器中的多媒体应用，而这些应用通常会使用 JavaScript API 来操作。

2. **为更高层 JavaScript 功能提供基础:**  Chromium 的网络栈为浏览器提供底层的网络通信能力。MoQT 作为一种新的传输协议，其稳定性和性能直接影响到使用 JavaScript 进行流媒体开发的体验。例如，如果 MoQT 模拟器发现某个网络瓶颈会导致数据延迟，那么开发人员可以针对这个问题进行优化，这最终会提升 JavaScript 开发的 WebRTC 或 Media Source Extensions 等 API 的性能。

**举例说明 JavaScript 关系：**

假设一个使用 JavaScript 的 Web 应用通过 WebRTC 或 Media Source Extensions (MSE) 接收 MoQT 流媒体数据。

* **模拟器作用:**  开发人员可以使用 `moqt_simulator_bin.cc` 模拟一个网络拥塞的场景（例如，设置较低的带宽和较高的延迟）。
* **预期 JavaScript 行为:**  在这种模拟的网络环境下，他们可以观察 JavaScript 应用中的播放器是否会发生卡顿、缓冲，或者是否能根据网络状况切换到较低的码率。
* **调试线索:** 如果 JavaScript 应用出现异常行为，例如播放器频繁卡顿，开发人员可能会回过头来检查 MoQT 协议的实现，并使用这个模拟器来复现和调试底层网络传输问题。

**逻辑推理、假设输入与输出**

**假设输入 (通过命令行参数)：**

```bash
./moqt_simulator_bin --bandwidth=1000 --deadline=1s --duration=30s --delivery_order=asc
```

* `--bandwidth=1000`: 设置模拟网络带宽为 1000 kbps。
* `--deadline=1s`: 设置数据帧交付的截止时间为 1 秒。
* `--duration=30s`: 设置模拟运行时间为 30 秒。
* `--delivery_order=asc`: 设置发布者按照升序发送数据对象。

**逻辑推理:**

1. **连接建立:** 模拟器会先建立客户端和服务器之间的 QUIC 连接，然后建立 MoQT 会话。
2. **数据生成与发送:** 客户端模拟器会按照一定的帧率和比特率生成数据，并按照升序发送。由于带宽有限，可能会出现网络拥塞。
3. **数据接收:** 服务器模拟器接收数据。由于网络延迟和带宽限制，部分数据可能会延迟到达甚至丢失。
4. **性能统计:** 模拟器会统计接收到的数据量、按时到达的数据量、延迟到达的数据量以及丢失的数据量。
5. **比特率调整:**  客户端模拟器可能会根据网络状况调整发送比特率 (虽然示例中没有强制触发调整的场景，但模拟器支持此功能)。

**假设输出 (部分可能的控制台输出):**

```
Ran simulation for 30s + ...ms
Congestion control used: ...
Objects received: 145 / 150 (96.67%)
  on time: 120 / 150 (80.00%)
     late: 25 / 150 (16.67%)
    never: 5 / 150 (3.33%)

Average on-time goodput: ...
Bitrates: ... -> ...
```

**用户或编程常见的使用错误**

1. **错误的命令行参数:**
   * **拼写错误:** 例如，输入 `--bandwith` 而不是 `--bandwidth`。
   * **参数值超出范围:** 例如，设置非常高的带宽，可能导致模拟结果不符合实际场景。
   * **`--delivery_order` 参数错误:**  输入了除 `asc` 或 `desc` 之外的值，会导致程序报错。

   **示例错误输出:**
   ```
   ERROR: unknown command line flag 'bandwith'
   --delivery_order must be 'asc' or 'desc'.
   ```

2. **对模拟结果的误解:**
   * **将模拟结果直接等同于真实环境:** 模拟器是对现实的简化，其结果只能作为参考，不能完全替代真实网络环境的测试。
   * **忽略关键参数的影响:**  例如，只关注带宽，而忽略了延迟对 MoQT 性能的影响。

3. **调试配置不当:**
   * **模拟时间过短:**  可能无法观察到一些长期的网络行为，例如拥塞控制的收敛。
   * **网络参数设置不合理:**  例如，将带宽设置得非常高，导致所有数据都能按时到达，无法测试 MoQT 在网络压力下的表现。

**用户操作是如何一步步的到达这里，作为调试线索**

一个开发者或测试人员可能因为以下原因需要查看或调试 `moqt_simulator_bin.cc`：

1. **MoQT 功能开发或测试:**
   * 正在开发 Chromium 中 MoQT 协议的新功能，需要一个工具来验证其基本行为和性能。
   * 需要测试 MoQT 在不同网络条件下的健壮性，例如在高丢包率或高延迟的环境下。
   * 需要对比不同的 MoQT 实现策略或参数配置对性能的影响。

2. **排查 MoQT 相关的网络问题:**
   * 用户反馈在使用基于 MoQT 的功能时遇到网络问题，例如视频卡顿或音频中断。
   * 开发人员需要一个工具来复现用户遇到的网络场景，并分析 MoQT 协议的运行状况。

3. **理解 MoQT 协议的细节:**
   * 为了更深入地理解 MoQT 的工作原理，需要查看其模拟器的代码，了解数据是如何生成、发送和接收的。
   * 需要分析 MoQT 的拥塞控制机制是如何在模拟环境中工作的。

**调试步骤示例:**

1. **用户报告 MoQT 流媒体播放卡顿:** 用户在使用 Chromium 浏览器观看某个流媒体服务时，发现画面经常卡顿。开发者怀疑是底层的 MoQT 传输出现了问题。

2. **开发者尝试复现问题:**  开发者尝试在自己的网络环境下复现问题，但效果不明显。他们决定使用 `moqt_simulator_bin.cc` 来模拟可能导致卡顿的网络环境。

3. **运行模拟器并调整参数:**  开发者运行 `moqt_simulator_bin.cc`，并逐步调整带宽、延迟等参数，以模拟用户可能遇到的网络状况。他们可能会尝试不同的 `--delivery_order` 来观察数据发送顺序的影响。

4. **查看模拟器输出:**  开发者观察模拟器的输出，例如接收到的对象比例、按时到达的对象比例等，来判断 MoQT 在模拟的网络环境下是否表现正常。如果发现大量对象延迟到达或丢失，则可能表明 MoQT 的某些方面需要优化。

5. **深入代码分析:** 如果模拟器复现了问题，开发者可能会深入 `moqt_simulator_bin.cc` 的代码，例如查看 `ObjectGenerator` 如何生成数据，`ObjectReceiver` 如何处理接收到的数据，以及 `MoqtSimulator` 如何设置网络环境。他们也可能查看相关的 MoQT 协议实现代码。

6. **修改和重新测试:**  根据代码分析的结果，开发者可能会修改 MoQT 协议的实现，然后再次使用 `moqt_simulator_bin.cc` 来验证修改是否解决了问题。

总而言之，`net/third_party/quiche/src/quiche/quic/moqt/tools/moqt_simulator_bin.cc` 是一个用于模拟和测试 MoQT 协议行为的关键工具，它可以帮助开发者理解、调试和优化 Chromium 中的 MoQT 实现，并最终提升基于 MoQT 的多媒体应用的用户体验。虽然它本身不直接与 JavaScript 交互，但它是构建可靠的、能够被 JavaScript 使用的底层网络功能的重要组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/tools/moqt_simulator_bin.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// moqt_simulator simulates the behavior of MoQ Transport under various network
// conditions and application settings.

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_bitrate_adjuster.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_outgoing_queue.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/test_tools/moqt_simulator_harness.h"
#include "quiche/quic/test_tools/simulator/actor.h"
#include "quiche/quic/test_tools/simulator/link.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/switch.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace moqt::test {
namespace {

using ::quiche::QuicheBuffer;
using ::quiche::QuicheMemSlice;

using ::quic::QuicBandwidth;
using ::quic::QuicByteCount;
using ::quic::QuicClock;
using ::quic::QuicTime;
using ::quic::QuicTimeDelta;

using ::quic::simulator::Simulator;

// In the simulation, the server link is supposed to be the bottleneck, so this
// value just has to be sufficiently larger than the server link bandwidth.
constexpr QuicBandwidth kClientLinkBandwidth =
    QuicBandwidth::FromBitsPerSecond(10.0e6);
constexpr MoqtVersion kMoqtVersion = kDefaultMoqtVersion;

// Track name used by the simulator.
FullTrackName TrackName() { return FullTrackName("test", "track"); }

// Parameters describing the scenario being simulated.
struct SimulationParameters {
  // Bottleneck bandwidth of the simulated scenario.
  QuicBandwidth bandwidth = QuicBandwidth::FromBitsPerSecond(2.0e6);
  // Intended RTT (as computed from propagation delay alone) between the client
  // and the server.
  QuicTimeDelta min_rtt = QuicTimeDelta::FromMilliseconds(20);
  // The size of the network queue; if zero, assumed to be twice the BDP.
  QuicByteCount network_queue_size = 0;
  // Duration for which the simulation is run.
  QuicTimeDelta duration = QuicTimeDelta::FromSeconds(60);

  // Count frames as useful only if they were received `deadline` after which
  // they were generated.
  QuicTimeDelta deadline = QuicTimeDelta::FromSeconds(2);
  // Delivery order used by the publisher.
  MoqtDeliveryOrder delivery_order = MoqtDeliveryOrder::kDescending;

  // Number of frames in an individual group.
  int keyframe_interval = 30 * 2;
  // Number of frames generated per second.
  int fps = 30;
  // The ratio by which an I-frame is bigger than a P-frame.
  float i_to_p_ratio = 2 / 1;
  // The target bitrate of the data being exchanged.
  QuicBandwidth bitrate = QuicBandwidth::FromBitsPerSecond(1.0e6);
};

std::string FormatPercentage(size_t n, size_t total) {
  float percentage = 100.0f * n / total;
  return absl::StrFormat("%d / %d (%.2f%%)", n, total, percentage);
}

// Generates test objects at a constant rate.  The first eight bytes of every
// object generated is a timestamp, the rest is all zeroes.  The first object in
// the group can be made bigger than the rest, to simulate the profile of real
// video bitstreams.
class ObjectGenerator : public quic::simulator::Actor,
                        public moqt::BitrateAdjustable {
 public:
  ObjectGenerator(Simulator* simulator, const std::string& actor_name,
                  MoqtSession* session, FullTrackName track_name,
                  int keyframe_interval, int fps, float i_to_p_ratio,
                  QuicBandwidth bitrate)
      : Actor(simulator, actor_name),
        queue_(std::make_shared<MoqtOutgoingQueue>(
            track_name, MoqtForwardingPreference::kSubgroup)),
        keyframe_interval_(keyframe_interval),
        time_between_frames_(QuicTimeDelta::FromMicroseconds(1.0e6 / fps)),
        i_to_p_ratio_(i_to_p_ratio),
        bitrate_(bitrate),
        bitrate_history_({bitrate}) {}

  void Act() override {
    ++frame_number_;
    bool i_frame = (frame_number_ % keyframe_interval_) == 0;
    size_t size = GetFrameSize(i_frame);

    QuicheBuffer buffer(quiche::SimpleBufferAllocator::Get(), size);
    memset(buffer.data(), 0, buffer.size());
    quiche::QuicheDataWriter writer(size, buffer.data());
    bool success = writer.WriteUInt64(clock_->Now().ToDebuggingValue());
    QUICHE_CHECK(success);

    queue_->AddObject(QuicheMemSlice(std::move(buffer)), i_frame);
    Schedule(clock_->Now() + time_between_frames_);
  }

  void Start() { Schedule(clock_->Now()); }
  void Stop() { Unschedule(); }

  std::shared_ptr<MoqtOutgoingQueue> queue() { return queue_; }
  size_t total_objects_sent() const { return frame_number_ + 1; }

  size_t GetFrameSize(bool i_frame) const {
    int p_frame_count = keyframe_interval_ - 1;
    // Compute the frame sizes as a fraction of the total group size.
    float i_frame_fraction = i_to_p_ratio_ / (i_to_p_ratio_ + p_frame_count);
    float p_frame_fraction = 1.0 / (i_to_p_ratio_ + p_frame_count);
    float frame_fraction = i_frame ? i_frame_fraction : p_frame_fraction;

    QuicTimeDelta group_duration = time_between_frames_ * keyframe_interval_;
    QuicByteCount group_byte_count = group_duration * bitrate_;
    size_t frame_size = std::ceil(frame_fraction * group_byte_count);
    QUICHE_CHECK_GE(frame_size, 8u)
        << "Frame size is too small for a timestamp";
    return frame_size;
  }

  quic::QuicBandwidth GetCurrentBitrate() const override { return bitrate_; }
  bool AdjustBitrate(quic::QuicBandwidth bandwidth) override {
    bitrate_ = bandwidth;
    bitrate_history_.push_back(bandwidth);
    return true;
  }
  std::string FormatBitrateHistory() const {
    std::vector<std::string> bits;
    bits.reserve(bitrate_history_.size());
    for (QuicBandwidth bandwidth : bitrate_history_) {
      bits.push_back(absl::StrCat(bandwidth));
    }
    return absl::StrJoin(bits, " -> ");
  }

 private:
  std::shared_ptr<MoqtOutgoingQueue> queue_;
  int keyframe_interval_;
  QuicTimeDelta time_between_frames_;
  float i_to_p_ratio_;
  QuicBandwidth bitrate_;
  int frame_number_ = -1;
  std::vector<QuicBandwidth> bitrate_history_;
};

class ObjectReceiver : public RemoteTrack::Visitor {
 public:
  explicit ObjectReceiver(const QuicClock* clock, QuicTimeDelta deadline)
      : clock_(clock), deadline_(deadline) {}

  void OnReply(const FullTrackName& full_track_name,
               std::optional<absl::string_view> error_reason_phrase) override {
    QUICHE_CHECK(full_track_name == TrackName());
    QUICHE_CHECK(!error_reason_phrase.has_value()) << *error_reason_phrase;
  }

  void OnCanAckObjects(MoqtObjectAckFunction ack_function) override {
    object_ack_function_ = std::move(ack_function);
  }

  void OnObjectFragment(const FullTrackName& full_track_name,
                        FullSequence sequence,
                        MoqtPriority /*publisher_priority*/,
                        MoqtObjectStatus status,
                        MoqtForwardingPreference /*forwarding_preference*/,
                        absl::string_view object,
                        bool end_of_message) override {
    QUICHE_DCHECK(full_track_name == TrackName());
    if (status != MoqtObjectStatus::kNormal) {
      QUICHE_DCHECK(end_of_message);
      return;
    }

    // Buffer and assemble partially available objects.
    // TODO: this logic should be factored out. Also, this should take advantage
    // of the fact that in the current MoQT, the object size is known in
    // advance.
    if (!end_of_message) {
      auto [it, unused] = partial_objects_.try_emplace(sequence);
      it->second.append(object);
      return;
    }
    auto it = partial_objects_.find(sequence);
    if (it == partial_objects_.end()) {
      OnFullObject(sequence, object);
      return;
    }
    std::string full_object = std::move(it->second);
    full_object.append(object);
    partial_objects_.erase(it);
    OnFullObject(sequence, full_object);
  }

  void OnFullObject(FullSequence sequence, absl::string_view payload) {
    QUICHE_CHECK_GE(payload.size(), 8u);
    quiche::QuicheDataReader reader(payload);
    uint64_t time_us;
    reader.ReadUInt64(&time_us);
    QuicTime time = QuicTime::Zero() + QuicTimeDelta::FromMicroseconds(time_us);
    QuicTimeDelta delay = clock_->Now() - time;
    QUICHE_CHECK_GT(delay, QuicTimeDelta::Zero());
    QUICHE_DCHECK(absl::c_all_of(reader.ReadRemainingPayload(),
                                 [](char c) { return c == 0; }));
    ++full_objects_received_;
    if (delay > deadline_) {
      ++full_objects_received_late_;
    } else {
      ++full_objects_received_on_time_;
      total_bytes_received_on_time_ += payload.size();
    }
    if (object_ack_function_) {
      object_ack_function_(sequence.group, sequence.object, deadline_ - delay);
    }
  }

  size_t full_objects_received() const { return full_objects_received_; }
  size_t full_objects_received_on_time() const {
    return full_objects_received_on_time_;
  }
  size_t full_objects_received_late() const {
    return full_objects_received_late_;
  }
  size_t total_bytes_received_on_time() const {
    return total_bytes_received_on_time_;
  }

 private:
  const QuicClock* clock_ = nullptr;
  // TODO: figure out when partial objects should be discarded.
  absl::flat_hash_map<FullSequence, std::string> partial_objects_;
  MoqtObjectAckFunction object_ack_function_ = nullptr;

  size_t full_objects_received_ = 0;

  QuicTimeDelta deadline_;
  size_t full_objects_received_on_time_ = 0;
  size_t full_objects_received_late_ = 0;
  size_t total_bytes_received_on_time_ = 0;
};

// Computes the size of the network queue on the switch.
constexpr QuicByteCount AdjustedQueueSize(
    const SimulationParameters& parameters) {
  if (parameters.network_queue_size > 0) {
    return parameters.network_queue_size;
  }
  QuicByteCount bdp = parameters.bandwidth * parameters.min_rtt;
  return 2 * bdp;
}

// Simulates the performance of MoQT transfer under the specified network
// conditions.
class MoqtSimulator {
 public:
  explicit MoqtSimulator(const SimulationParameters& parameters)
      : simulator_(quic::QuicRandom::GetInstance()),
        client_endpoint_(&simulator_, "Client", "Server", kMoqtVersion),
        server_endpoint_(&simulator_, "Server", "Client", kMoqtVersion),
        switch_(&simulator_, "Switch", 8, AdjustedQueueSize(parameters)),
        client_link_(&client_endpoint_, switch_.port(1), kClientLinkBandwidth,
                     parameters.min_rtt * 0.25),
        server_link_(&server_endpoint_, switch_.port(2), parameters.bandwidth,
                     parameters.min_rtt * 0.25),
        generator_(&simulator_, "Client generator", client_endpoint_.session(),
                   TrackName(), parameters.keyframe_interval, parameters.fps,
                   parameters.i_to_p_ratio, parameters.bitrate),
        receiver_(simulator_.GetClock(), parameters.deadline),
        adjuster_(simulator_.GetClock(), client_endpoint_.session()->session(),
                  &generator_),
        parameters_(parameters) {
    client_endpoint_.RecordTrace();
  }

  MoqtSession* client_session() { return client_endpoint_.session(); }
  MoqtSession* server_session() { return server_endpoint_.session(); }

  std::string GetClientSessionCongestionControl() {
    return quic::CongestionControlTypeToString(
        client_endpoint_.quic_session()
            ->connection()
            ->sent_packet_manager()
            .GetSendAlgorithm()
            ->GetCongestionControlType());
  }

  // Runs the simulation and outputs the results to stdout.
  void Run() {
    // Timeout for establishing the connection.
    constexpr QuicTimeDelta kConnectionTimeout = QuicTimeDelta::FromSeconds(1);

    // Perform the QUIC and the MoQT handshake.
    client_session()->set_support_object_acks(true);
    client_session()->callbacks().session_established_callback = [this] {
      client_established_ = true;
    };
    server_session()->set_support_object_acks(true);
    server_session()->callbacks().session_established_callback = [this] {
      server_established_ = true;
    };
    client_endpoint_.quic_session()->CryptoConnect();
    simulator_.RunUntilOrTimeout(
        [&]() { return client_established_ && server_established_; },
        kConnectionTimeout);
    QUICHE_CHECK(client_established_) << "Client failed to establish session";
    QUICHE_CHECK(server_established_) << "Server failed to establish session";

    generator_.queue()->SetDeliveryOrder(parameters_.delivery_order);
    client_session()->set_publisher(&publisher_);
    client_session()->SetMonitoringInterfaceForTrack(TrackName(), &adjuster_);
    publisher_.Add(generator_.queue());

    // The simulation is started as follows.  At t=0:
    //   (1) The server issues a subscribe request.
    //   (2) The client starts immediately generating data.  At this point, the
    //       server does not yet have an active subscription, so the client has
    //       some catching up to do.
    generator_.Start();
    server_session()->SubscribeCurrentGroup(TrackName(), &receiver_);
    simulator_.RunFor(parameters_.duration);

    // At the end, we wait for eight RTTs until the connection settles down.
    generator_.Stop();
    absl::Duration wait_at_the_end =
        8 * client_endpoint_.quic_session()->GetSessionStats().smoothed_rtt;
    simulator_.RunFor(QuicTimeDelta(wait_at_the_end));
    const QuicTimeDelta total_time =
        parameters_.duration + QuicTimeDelta(wait_at_the_end);

    absl::PrintF("Ran simulation for %v + %.1fms\n", parameters_.duration,
                 absl::ToDoubleMilliseconds(wait_at_the_end));
    absl::PrintF("Congestion control used: %s\n",
                 GetClientSessionCongestionControl());

    size_t total_sent = generator_.total_objects_sent();
    size_t missing_objects =
        generator_.total_objects_sent() - receiver_.full_objects_received();
    absl::PrintF(
        "Objects received: %s\n",
        FormatPercentage(receiver_.full_objects_received(), total_sent));
    absl::PrintF("  on time: %s\n",
                 FormatPercentage(receiver_.full_objects_received_on_time(),
                                  total_sent));
    absl::PrintF(
        "     late: %s\n",
        FormatPercentage(receiver_.full_objects_received_late(), total_sent));
    absl::PrintF("    never: %s\n",
                 FormatPercentage(missing_objects, total_sent));
    absl::PrintF("\n");
    absl::PrintF("Average on-time goodput: %v\n",
                 QuicBandwidth::FromBytesAndTimeDelta(
                     receiver_.total_bytes_received_on_time(), total_time));
    absl::PrintF("Bitrates: %s\n", generator_.FormatBitrateHistory());
  }

 private:
  Simulator simulator_;
  MoqtClientEndpoint client_endpoint_;
  MoqtServerEndpoint server_endpoint_;
  quic::simulator::Switch switch_;
  quic::simulator::SymmetricLink client_link_;
  quic::simulator::SymmetricLink server_link_;
  MoqtKnownTrackPublisher publisher_;
  ObjectGenerator generator_;
  ObjectReceiver receiver_;
  MoqtBitrateAdjuster adjuster_;
  SimulationParameters parameters_;

  bool client_established_ = false;
  bool server_established_ = false;
};

}  // namespace
}  // namespace moqt::test

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    uint64_t, bandwidth,
    moqt::test::SimulationParameters().bandwidth.ToKBitsPerSecond(),
    "Bandwidth of the simulated link, in kilobits per second.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    absl::Duration, deadline,
    moqt::test::SimulationParameters().deadline.ToAbsl(),
    "Frame delivery deadline (used for measurement only).");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    absl::Duration, duration,
    moqt::test::SimulationParameters().duration.ToAbsl(),
    "Duration of the simulation");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, delivery_order, "desc",
    "Delivery order used for the MoQT track simulated ('asc' or 'desc').");

int main(int argc, char** argv) {
  moqt::test::SimulationParameters parameters;
  quiche::QuicheParseCommandLineFlags("moqt_simulator", argc, argv);
  parameters.bandwidth = quic::QuicBandwidth::FromKBitsPerSecond(
      quiche::GetQuicheCommandLineFlag(FLAGS_bandwidth));
  parameters.deadline =
      quic::QuicTimeDelta(quiche::GetQuicheCommandLineFlag(FLAGS_deadline));
  parameters.duration =
      quic::QuicTimeDelta(quiche::GetQuicheCommandLineFlag(FLAGS_duration));

  std::string raw_delivery_order = absl::AsciiStrToLower(
      quiche::GetQuicheCommandLineFlag(FLAGS_delivery_order));
  if (raw_delivery_order == "asc") {
    parameters.delivery_order = moqt::MoqtDeliveryOrder::kAscending;
  } else if (raw_delivery_order == "desc") {
    parameters.delivery_order = moqt::MoqtDeliveryOrder::kDescending;
  } else {
    std::cerr << "--delivery_order must be 'asc' or 'desc'." << std::endl;
    return 1;
  }

  moqt::test::MoqtSimulator simulator(parameters);
  simulator.Run();
  return 0;
}
```