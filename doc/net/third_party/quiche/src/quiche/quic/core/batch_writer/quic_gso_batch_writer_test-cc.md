Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The filename `quic_gso_batch_writer_test.cc` immediately suggests this file tests the `QuicGsoBatchWriter` class. The "GSO" likely stands for "Generic Segmentation Offload," a network optimization technique. "Batch Writer" indicates it's about sending multiple packets together. The `_test.cc` suffix confirms it's a unit test file.

2. **Examine Includes:** The included headers provide valuable context:
    * `<sys/socket.h>`:  Indicates interaction with low-level socket operations.
    * `<cstdint>`, `<limits>`, `<memory>`, `<utility>`, `<vector>`: Standard C++ library headers, suggesting typical data structures and memory management.
    * `"quiche/quic/core/batch_writer/quic_gso_batch_writer.h"`: This is the header for the class being tested, essential for understanding its public interface.
    * `"quiche/quic/platform/api/quic_ip_address.h"` and `"quiche/quic/platform/api/quic_test.h"`:  Relate to QUIC's platform abstraction layer and testing framework.
    * `"quiche/quic/test_tools/quic_mock_syscall_wrapper.h"`:  Crucially indicates that system calls are being mocked for testing purposes.

3. **Scan for Key Classes and Functions:**  Look for the main test fixture (`QuicGsoBatchWriterTest`) and the individual test methods (`TEST_F`). Also note helper classes or structs like `TestQuicGsoBatchWriter` and `BatchCriteriaTestData`.

4. **Analyze `TestQuicGsoBatchWriter`:** This class inherits from `QuicGsoBatchWriter` and exposes some protected members for testing (`batch_buffer`, `buffered_writes`, etc.). The `NewInstanceWithReleaseTimeSupport` function and the `ForceReleaseTimeMs` and `NowInNanosForReleaseTime` overrides hint at testing time-based behavior.

5. **Analyze `BatchCriteriaTestData`:** This struct is used to define various scenarios for testing the batching criteria. It holds packet details (size, addresses, release time) and the expected `can_batch` and `must_flush` results. The different `BatchCriteriaTestData_*` functions create vectors of these test cases, covering different conditions (size changes, address changes, release times, max segments).

6. **Focus on the Test Methods:** Read through each `TEST_F` method to understand its purpose:
    * `BatchCriteria`: Tests the `CanBatch` method under various conditions defined by the `BatchCriteriaTestData`.
    * `WriteSuccess`:  Tests a successful write operation.
    * `WriteBlockDataNotBuffered` and `WriteBlockDataBuffered`: Test scenarios where writing blocks but data may or may not be buffered.
    * `WriteErrorWithoutDataBuffered` and `WriteErrorAfterDataBuffered`: Test error scenarios during writing.
    * `FlushError`: Tests error conditions during flushing the batch.
    * `ReleaseTime`: Focuses on testing the handling of packet release times.
    * `EcnCodepoint` and `EcnCodepointIPv6`: Test the setting and handling of Explicit Congestion Notification (ECN) codepoints.
    * `FlowLabelIPv6`: Tests the setting and handling of IPv6 flow labels.

7. **Look for Mocking and Assertions:** The use of `StrictMock<MockQuicSyscallWrapper>` and `EXPECT_CALL` reveals that system calls like `sendmsg` are being mocked. `ASSERT_EQ`, `ASSERT_TRUE`, and `EXPECT_EQ` are the core assertion macros used to verify the expected behavior.

8. **Consider JavaScript Relevance (and lack thereof):** Think about the core functionality being tested (network packet batching and sending). This is primarily a backend networking concern. While JavaScript in a browser might *trigger* the creation of these packets (e.g., through a `fetch` request), the low-level details of batching and GSO are handled by the operating system and the QUIC implementation in C++. There's no direct, functional relationship in the way a JavaScript developer would interact with this code. The connection is conceptual – JavaScript requests lead to network traffic, and this code optimizes how that traffic is sent.

9. **Infer User Errors and Debugging:**  Think about what could go wrong. Common user/programming errors related to network code include:
    * Sending packets that are too large.
    * Incorrectly setting socket addresses.
    * Not handling blocked writes correctly.
    * Issues with timing or delays in packet delivery.

    For debugging, the test file itself provides valuable clues. The test cases simulate different scenarios. If a bug is suspected in the batch writer, one would look at the `CanBatch` logic, the conditions under which packets are flushed, and the handling of system call errors. The mocking of system calls allows for controlled testing of error conditions.

10. **Structure the Explanation:** Organize the findings into the requested categories: functionality, JavaScript relation, logical reasoning, user errors, and debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the release time mechanism has some JavaScript equivalent in scheduling tasks. **Correction:** While JavaScript has scheduling, it doesn't directly map to the fine-grained network packet release times managed by the OS. The connection is indirect.
* **Initial thought:**  Focus heavily on the system call details. **Correction:** While important, also emphasize the higher-level functionality of the `QuicGsoBatchWriter` and its role in QUIC.
* **Initial thought:** Overlook the importance of the `BatchCriteriaTestData`. **Correction:** Realize that this is a core part of how the batching logic is tested and needs to be explained.
* **Initial thought:** Not explicitly state the lack of *direct* JavaScript interaction. **Correction:** Clearly articulate that the relationship is conceptual and at a lower level than typical JavaScript development.

By following these steps and engaging in self-correction, we arrive at a comprehensive and accurate explanation of the test file's functionality.
这个C++源代码文件 `quic_gso_batch_writer_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicGsoBatchWriter` 类的功能。`QuicGsoBatchWriter` 的作用是利用操作系统提供的 GSO (Generic Segmentation Offload) 技术来批量发送数据包，以提高网络发送效率。

以下是该测试文件的主要功能：

1. **测试批量写入的核心逻辑 (`CanBatch` 方法):**
   - 测试在不同的网络参数和数据包属性下，`QuicGsoBatchWriter` 是否能够正确判断一个新的数据包是否可以添加到当前的批次中。
   - 测试的参数包括：数据包大小、源地址、目标地址、计划释放时间等。
   - 通过 `BatchCriteriaTestData` 结构体定义了各种测试场景，例如：
     - 数据包大小的增加或减少。
     - 源地址或目标地址的改变。
     - 计划释放时间的不同。
     - 批次中数据包数量是否达到最大限制。
   - 每个测试用例会断言 `CanBatch` 方法返回的 `can_batch` (是否可以加入批次) 和 `must_flush` (是否必须刷新当前批次) 结果是否与预期一致。

2. **测试成功的批量写入操作 (`WriteSuccess` 方法):**
   - 模拟多次写入数据包，并期望这些数据包被合并到一个大的 GSO 数据包中发送。
   - 使用 `MockQuicSyscallWrapper` 模拟 `sendmsg` 系统调用，并断言传递给 `sendmsg` 的数据包长度是所有写入数据包的总和。

3. **测试写入阻塞的情况 (`WriteBlockDataNotBuffered`, `WriteBlockDataBuffered` 方法):**
   - 模拟在写入过程中 `sendmsg` 系统调用返回 `EWOULDBLOCK` (表示socket缓冲区已满，暂时无法写入) 的情况。
   - 测试 `QuicGsoBatchWriter` 在遇到阻塞时的行为：
     - `WriteBlockDataNotBuffered`:  在发生阻塞前，批次中的数据包没有被发送出去。
     - `WriteBlockDataBuffered`:  在发生阻塞前，部分数据包已经被缓冲。
   - 断言 `WritePacket` 方法返回 `WRITE_STATUS_BLOCKED` 或 `WRITE_STATUS_BLOCKED_DATA_BUFFERED`。

4. **测试写入错误的情况 (`WriteErrorWithoutDataBuffered`, `WriteErrorAfterDataBuffered` 方法):**
   - 模拟在写入过程中 `sendmsg` 系统调用返回错误 (例如 `EPERM`) 的情况。
   - 测试 `QuicGsoBatchWriter` 如何处理错误，以及是否会丢弃已缓冲的数据包。
   - 断言 `WritePacket` 方法返回 `WRITE_STATUS_ERROR`，并检查 `dropped_packets` 数量。

5. **测试刷新批次时发生错误的情况 (`FlushError` 方法):**
   - 模拟调用 `Flush` 方法刷新批次时，`sendmsg` 系统调用返回错误 (例如 `EINVAL`) 的情况。
   - 断言 `Flush` 方法返回 `WRITE_STATUS_ERROR`，并检查 `dropped_packets` 数量。

6. **测试数据包的计划释放时间 (`ReleaseTime` 方法):**
   - 测试 `QuicGsoBatchWriter` 如何根据数据包的计划释放时间来决定是否将其添加到当前批次。
   - 模拟设置不同的 `release_time_delay` 和 `allow_burst` 参数，并观察数据包是否被缓冲或立即发送。
   - 使用 `ForceReleaseTimeMs` 强制设置当前时间，以模拟时间流逝。

7. **测试 ECN (Explicit Congestion Notification) 标记的处理 (`EcnCodepoint`, `EcnCodepointIPv6` 方法):**
   - 测试 `QuicGsoBatchWriter` 如何为数据包设置 ECN codepoint (ECT0, ECT1)。
   - 模拟 IPv4 和 IPv6 场景，并断言通过 `sendmsg` 发送的数据包中包含了正确的 ECN 信息。

8. **测试 IPv6 Flow Label 的处理 (`FlowLabelIPv6` 方法):**
   - 测试 `QuicGsoBatchWriter` 如何为 IPv6 数据包设置 Flow Label。
   - 断言通过 `sendmsg` 发送的 IPv6 数据包中包含了正确的 Flow Label 信息。

**与 JavaScript 的关系：**

这个 C++ 文件是 Chromium 网络栈的底层实现，与 JavaScript 没有直接的编程接口关系。JavaScript 在浏览器中发起网络请求 (例如使用 `fetch` API 或 `XMLHttpRequest`) 时，最终会调用到浏览器底层的网络栈代码，其中就包括 QUIC 协议的实现。

可以举一个**概念上的例子**：

假设一个网页使用 JavaScript 的 `fetch` API 向服务器发送多个小的数据请求。Chromium 的 QUIC 实现（包括 `QuicGsoBatchWriter`）可能会将这些请求的数据包合并成一个大的 GSO 数据包发送出去，以减少系统调用和网络拥塞。  JavaScript 开发者无需关心底层的 GSO 优化，但它可以间接地受益于这种优化带来的性能提升。

**逻辑推理的假设输入与输出：**

**假设输入：**

- 当前批次中已经有一个大小为 1000 字节的数据包，目标地址为 `peer_address_`。
- 尝试写入一个新的数据包，大小为 300 字节，目标地址也为 `peer_address_`，并且没有设置延迟释放时间。
- `QuicGsoBatchWriter` 的最大批次大小限制为 2000 字节。

**输出：**

- `CanBatch` 方法应该返回 `can_batch = true` 和 `must_flush = false`，因为新的数据包可以添加到当前批次中，且不需要立即发送。
- 如果调用 `WritePacket` 方法，这个 300 字节的数据包会被添加到内部缓冲区，但不会立即发送。

**用户或编程常见的使用错误：**

虽然用户（指最终使用浏览器的用户或编写 JavaScript 代码的开发者）不会直接操作 `QuicGsoBatchWriter`，但编程错误可能会导致 QUIC 连接的异常行为，从而间接影响到这个模块的功能。

**例子：**

- **错误地配置 Socket 选项：** 如果上层代码在创建 socket 时，没有正确地启用 GSO 功能，那么 `QuicGsoBatchWriter` 将无法利用 GSO 进行批量发送，从而可能导致性能下降。 这不是 `QuicGsoBatchWriter` 本身的问题，而是上层使用者的配置错误。

**用户操作如何一步步到达这里作为调试线索：**

要调试与 `QuicGsoBatchWriter` 相关的网络问题，通常需要以下步骤：

1. **用户操作：** 用户在浏览器中访问一个使用了 QUIC 协议的网站或应用程序。例如，用户点击一个链接，导致浏览器发起 HTTP/3 请求。

2. **网络请求发起：** 浏览器内部的 JavaScript 代码 (例如，通过 `fetch` API) 或者浏览器自身的网络模块会创建一个网络请求。

3. **QUIC 连接建立：** 如果服务器支持 QUIC，并且浏览器也启用了 QUIC，那么浏览器会尝试与服务器建立 QUIC 连接。

4. **数据发送：** 当需要发送数据时 (例如，发送 HTTP 请求头部、请求体等)，QUIC 协议栈会将数据封装成 QUIC 数据包。

5. **`QuicGsoBatchWriter` 的使用：** 在发送 QUIC 数据包时，`QuicGsoBatchWriter` 可能会被调用，尝试将多个小的数据包合并成一个大的 GSO 数据包进行发送，以提高效率。

6. **调试线索：** 如果在网络性能分析或调试过程中发现以下情况，可能需要查看 `QuicGsoBatchWriter` 的行为：
   - **大量的 `sendmsg` 系统调用：** 如果没有正确进行批量发送，可能会看到大量的 `sendmsg` 调用，每个调用发送少量数据。
   - **网络抓包显示大量小的数据包：**  如果 GSO 没有生效，抓包可能会显示很多小的 QUIC 数据包，而不是少量大的数据包。
   - **发送队列拥塞：** 在高负载情况下，如果批量发送机制有问题，可能会导致发送队列拥塞。

**总结：**

`quic_gso_batch_writer_test.cc` 文件通过各种测试用例，全面地验证了 `QuicGsoBatchWriter` 类的核心功能，包括批量判断、写入、错误处理、时间控制和协议特定的标记处理。虽然 JavaScript 开发者不直接操作这个类，但它是 Chromium 网络栈中 QUIC 协议高效运行的关键组成部分，直接影响着基于 QUIC 的网络连接的性能。 调试涉及 QUIC 连接性能或底层数据包发送的问题时，这个测试文件和被测试的类都是重要的参考对象。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/batch_writer/quic_gso_batch_writer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/batch_writer/quic_gso_batch_writer.h"

#include <sys/socket.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "quiche/quic/core/flow_label.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_mock_syscall_wrapper.h"

using testing::_;
using testing::Invoke;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

size_t PacketLength(const msghdr* msg) {
  size_t length = 0;
  for (size_t i = 0; i < msg->msg_iovlen; ++i) {
    length += msg->msg_iov[i].iov_len;
  }
  return length;
}

uint64_t MillisToNanos(uint64_t milliseconds) { return milliseconds * 1000000; }

class QUICHE_EXPORT TestQuicGsoBatchWriter : public QuicGsoBatchWriter {
 public:
  using QuicGsoBatchWriter::batch_buffer;
  using QuicGsoBatchWriter::buffered_writes;
  using QuicGsoBatchWriter::CanBatch;
  using QuicGsoBatchWriter::CanBatchResult;
  using QuicGsoBatchWriter::GetReleaseTime;
  using QuicGsoBatchWriter::MaxSegments;
  using QuicGsoBatchWriter::QuicGsoBatchWriter;
  using QuicGsoBatchWriter::ReleaseTime;

  static std::unique_ptr<TestQuicGsoBatchWriter>
  NewInstanceWithReleaseTimeSupport() {
    return std::unique_ptr<TestQuicGsoBatchWriter>(new TestQuicGsoBatchWriter(
        std::make_unique<QuicBatchWriterBuffer>(),
        /*fd=*/-1, CLOCK_MONOTONIC, ReleaseTimeForceEnabler()));
  }

  uint64_t NowInNanosForReleaseTime() const override {
    return MillisToNanos(forced_release_time_ms_);
  }

  void ForceReleaseTimeMs(uint64_t forced_release_time_ms) {
    forced_release_time_ms_ = forced_release_time_ms;
  }

 private:
  uint64_t forced_release_time_ms_ = 1;
};

// TestBufferedWrite is a copy-constructible BufferedWrite.
struct QUICHE_EXPORT TestBufferedWrite : public BufferedWrite {
  using BufferedWrite::BufferedWrite;
  TestBufferedWrite(const TestBufferedWrite& other)
      : BufferedWrite(other.buffer, other.buf_len, other.self_address,
                      other.peer_address,
                      other.options ? other.options->Clone()
                                    : std::unique_ptr<PerPacketOptions>(),
                      QuicPacketWriterParams(), other.release_time) {}
};

// Pointed to by all instances of |BatchCriteriaTestData|. Content not used.
static char unused_packet_buffer[kMaxOutgoingPacketSize];

struct QUICHE_EXPORT BatchCriteriaTestData {
  BatchCriteriaTestData(size_t buf_len, const QuicIpAddress& self_address,
                        const QuicSocketAddress& peer_address,
                        uint64_t release_time, bool can_batch, bool must_flush)
      : buffered_write(unused_packet_buffer, buf_len, self_address,
                       peer_address, std::unique_ptr<PerPacketOptions>(),
                       QuicPacketWriterParams(), release_time),
        can_batch(can_batch),
        must_flush(must_flush) {}

  TestBufferedWrite buffered_write;
  // Expected value of CanBatchResult.can_batch when batching |buffered_write|.
  bool can_batch;
  // Expected value of CanBatchResult.must_flush when batching |buffered_write|.
  bool must_flush;
};

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_SizeDecrease() {
  const QuicIpAddress self_addr;
  const QuicSocketAddress peer_addr;
  std::vector<BatchCriteriaTestData> test_data_table = {
      // clang-format off
  // buf_len   self_addr   peer_addr   t_rel   can_batch       must_flush
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {39,       self_addr,  peer_addr,  0,      true,           true},
    {39,       self_addr,  peer_addr,  0,      false,          true},
    {1350,     self_addr,  peer_addr,  0,      false,          true},
      // clang-format on
  };
  return test_data_table;
}

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_SizeIncrease() {
  const QuicIpAddress self_addr;
  const QuicSocketAddress peer_addr;
  std::vector<BatchCriteriaTestData> test_data_table = {
      // clang-format off
  // buf_len   self_addr   peer_addr   t_rel   can_batch       must_flush
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1351,     self_addr,  peer_addr,  0,      false,          true},
      // clang-format on
  };
  return test_data_table;
}

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_AddressChange() {
  const QuicIpAddress self_addr1 = QuicIpAddress::Loopback4();
  const QuicIpAddress self_addr2 = QuicIpAddress::Loopback6();
  const QuicSocketAddress peer_addr1(self_addr1, 666);
  const QuicSocketAddress peer_addr2(self_addr1, 777);
  const QuicSocketAddress peer_addr3(self_addr2, 666);
  const QuicSocketAddress peer_addr4(self_addr2, 777);
  std::vector<BatchCriteriaTestData> test_data_table = {
      // clang-format off
  // buf_len   self_addr   peer_addr    t_rel  can_batch       must_flush
    {1350,     self_addr1, peer_addr1,  0,     true,           false},
    {1350,     self_addr1, peer_addr1,  0,     true,           false},
    {1350,     self_addr1, peer_addr1,  0,     true,           false},
    {1350,     self_addr2, peer_addr1,  0,     false,          true},
    {1350,     self_addr1, peer_addr2,  0,     false,          true},
    {1350,     self_addr1, peer_addr3,  0,     false,          true},
    {1350,     self_addr1, peer_addr4,  0,     false,          true},
    {1350,     self_addr1, peer_addr4,  0,     false,          true},
      // clang-format on
  };
  return test_data_table;
}

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_ReleaseTime1() {
  const QuicIpAddress self_addr;
  const QuicSocketAddress peer_addr;
  std::vector<BatchCriteriaTestData> test_data_table = {
      // clang-format off
  // buf_len   self_addr   peer_addr   t_rel   can_batch       must_flush
    {1350,     self_addr,  peer_addr,  5,      true,           false},
    {1350,     self_addr,  peer_addr,  5,      true,           false},
    {1350,     self_addr,  peer_addr,  5,      true,           false},
    {1350,     self_addr,  peer_addr,  9,      false,          true},
      // clang-format on
  };
  return test_data_table;
}

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_ReleaseTime2() {
  const QuicIpAddress self_addr;
  const QuicSocketAddress peer_addr;
  std::vector<BatchCriteriaTestData> test_data_table = {
      // clang-format off
  // buf_len   self_addr   peer_addr   t_rel   can_batch       must_flush
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  0,      true,           false},
    {1350,     self_addr,  peer_addr,  9,      false,          true},
      // clang-format on
  };
  return test_data_table;
}

std::vector<BatchCriteriaTestData> BatchCriteriaTestData_MaxSegments(
    size_t gso_size) {
  const QuicIpAddress self_addr;
  const QuicSocketAddress peer_addr;
  std::vector<BatchCriteriaTestData> test_data_table;
  size_t max_segments = TestQuicGsoBatchWriter::MaxSegments(gso_size);
  for (size_t i = 0; i < max_segments; ++i) {
    bool is_last_in_batch = (i + 1 == max_segments);
    test_data_table.push_back({gso_size, self_addr, peer_addr,
                               /*release_time=*/0, true, is_last_in_batch});
  }
  test_data_table.push_back(
      {gso_size, self_addr, peer_addr, /*release_time=*/0, false, true});
  return test_data_table;
}

class QuicGsoBatchWriterTest : public QuicTest {
 protected:
  WriteResult WritePacket(QuicGsoBatchWriter* writer, size_t packet_size) {
    return writer->WritePacket(&packet_buffer_[0], packet_size, self_address_,
                               peer_address_, nullptr,
                               QuicPacketWriterParams());
  }

  WriteResult WritePacketWithParams(QuicGsoBatchWriter* writer,
                                    QuicPacketWriterParams& params) {
    return writer->WritePacket(&packet_buffer_[0], 1350, self_address_,
                               peer_address_, nullptr, params);
  }

  QuicIpAddress self_address_ = QuicIpAddress::Any4();
  QuicSocketAddress peer_address_{QuicIpAddress::Any4(), 443};
  char packet_buffer_[1500];
  StrictMock<MockQuicSyscallWrapper> mock_syscalls_;
  ScopedGlobalSyscallWrapperOverride syscall_override_{&mock_syscalls_};
};

TEST_F(QuicGsoBatchWriterTest, BatchCriteria) {
  std::unique_ptr<TestQuicGsoBatchWriter> writer;

  std::vector<std::vector<BatchCriteriaTestData>> test_data_tables;
  test_data_tables.emplace_back(BatchCriteriaTestData_SizeDecrease());
  test_data_tables.emplace_back(BatchCriteriaTestData_SizeIncrease());
  test_data_tables.emplace_back(BatchCriteriaTestData_AddressChange());
  test_data_tables.emplace_back(BatchCriteriaTestData_ReleaseTime1());
  test_data_tables.emplace_back(BatchCriteriaTestData_ReleaseTime2());
  test_data_tables.emplace_back(BatchCriteriaTestData_MaxSegments(1));
  test_data_tables.emplace_back(BatchCriteriaTestData_MaxSegments(2));
  test_data_tables.emplace_back(BatchCriteriaTestData_MaxSegments(1350));

  for (size_t i = 0; i < test_data_tables.size(); ++i) {
    writer = TestQuicGsoBatchWriter::NewInstanceWithReleaseTimeSupport();

    const auto& test_data_table = test_data_tables[i];
    for (size_t j = 0; j < test_data_table.size(); ++j) {
      const BatchCriteriaTestData& test_data = test_data_table[j];
      SCOPED_TRACE(testing::Message() << "i=" << i << ", j=" << j);
      QuicPacketWriterParams params;
      params.release_time_delay = QuicTime::Delta::FromMicroseconds(
          test_data.buffered_write.release_time);
      TestQuicGsoBatchWriter::CanBatchResult result = writer->CanBatch(
          test_data.buffered_write.buffer, test_data.buffered_write.buf_len,
          test_data.buffered_write.self_address,
          test_data.buffered_write.peer_address, nullptr, params,
          test_data.buffered_write.release_time);

      ASSERT_EQ(test_data.can_batch, result.can_batch);
      ASSERT_EQ(test_data.must_flush, result.must_flush);

      if (result.can_batch) {
        ASSERT_TRUE(writer->batch_buffer()
                        .PushBufferedWrite(
                            test_data.buffered_write.buffer,
                            test_data.buffered_write.buf_len,
                            test_data.buffered_write.self_address,
                            test_data.buffered_write.peer_address, nullptr,
                            params, test_data.buffered_write.release_time)
                        .succeeded);
      }
    }
  }
}

TEST_F(QuicGsoBatchWriterTest, WriteSuccess) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 1000));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(1100u, PacketLength(msg));
        return 1100;
      }));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 1100), WritePacket(&writer, 100));
  ASSERT_EQ(0u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(0u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, WriteBlockDataNotBuffered) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(200u, PacketLength(msg));
        errno = EWOULDBLOCK;
        return -1;
      }));
  ASSERT_EQ(WriteResult(WRITE_STATUS_BLOCKED, EWOULDBLOCK),
            WritePacket(&writer, 150));
  ASSERT_EQ(200u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(2u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, WriteBlockDataBuffered) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(250u, PacketLength(msg));
        errno = EWOULDBLOCK;
        return -1;
      }));
  ASSERT_EQ(WriteResult(WRITE_STATUS_BLOCKED_DATA_BUFFERED, EWOULDBLOCK),
            WritePacket(&writer, 50));

  EXPECT_TRUE(writer.IsWriteBlocked());

  ASSERT_EQ(250u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(3u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, WriteErrorWithoutDataBuffered) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(200u, PacketLength(msg));
        errno = EPERM;
        return -1;
      }));
  WriteResult error_result = WritePacket(&writer, 150);
  ASSERT_EQ(WriteResult(WRITE_STATUS_ERROR, EPERM), error_result);

  ASSERT_EQ(3u, error_result.dropped_packets);
  ASSERT_EQ(0u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(0u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, WriteErrorAfterDataBuffered) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(250u, PacketLength(msg));
        errno = EPERM;
        return -1;
      }));
  WriteResult error_result = WritePacket(&writer, 50);
  ASSERT_EQ(WriteResult(WRITE_STATUS_ERROR, EPERM), error_result);

  ASSERT_EQ(3u, error_result.dropped_packets);
  ASSERT_EQ(0u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(0u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, FlushError) {
  TestQuicGsoBatchWriter writer(/*fd=*/-1);

  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 0), WritePacket(&writer, 100));

  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(200u, PacketLength(msg));
        errno = EINVAL;
        return -1;
      }));
  WriteResult error_result = writer.Flush();
  ASSERT_EQ(WriteResult(WRITE_STATUS_ERROR, EINVAL), error_result);

  ASSERT_EQ(2u, error_result.dropped_packets);
  ASSERT_EQ(0u, writer.batch_buffer().SizeInUse());
  ASSERT_EQ(0u, writer.buffered_writes().size());
}

TEST_F(QuicGsoBatchWriterTest, ReleaseTime) {
  const WriteResult write_buffered(WRITE_STATUS_OK, 0);

  auto writer = TestQuicGsoBatchWriter::NewInstanceWithReleaseTimeSupport();

  QuicPacketWriterParams params;
  EXPECT_TRUE(params.release_time_delay.IsZero());
  EXPECT_FALSE(params.allow_burst);
  EXPECT_EQ(MillisToNanos(1),
            writer->GetReleaseTime(params).actual_release_time);

  // The 1st packet has no delay.
  WriteResult result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(1), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());

  // The 2nd packet has some delay, but allows burst.
  params.release_time_delay = QuicTime::Delta::FromMilliseconds(3);
  params.allow_burst = true;
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(1), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::FromMilliseconds(-3));

  // The 3rd packet has more delay and does not allow burst.
  // The first 2 packets are flushed due to different release time.
  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(2700u, PacketLength(msg));
        errno = 0;
        return 0;
      }));
  params.release_time_delay = QuicTime::Delta::FromMilliseconds(5);
  params.allow_burst = false;
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 2700), result);
  EXPECT_EQ(MillisToNanos(6), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());

  // The 4th packet has same delay, but allows burst.
  params.allow_burst = true;
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(6), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());

  // The 5th packet has same delay, allows burst, but is shorter.
  // Packets 3,4 and 5 are flushed.
  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        EXPECT_EQ(3000u, PacketLength(msg));
        errno = 0;
        return 0;
      }));
  params.allow_burst = true;
  EXPECT_EQ(MillisToNanos(6),
            writer->GetReleaseTime(params).actual_release_time);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 3000),
            writer->WritePacket(&packet_buffer_[0], 300, self_address_,
                                peer_address_, nullptr, params));
  EXPECT_TRUE(writer->buffered_writes().empty());

  // Pretend 1ms has elapsed and the 6th packet has 1ms less delay. In other
  // words, the release time should still be the same as packets 3-5.
  writer->ForceReleaseTimeMs(2);
  params.release_time_delay = QuicTime::Delta::FromMilliseconds(4);
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(6), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());
}

TEST_F(QuicGsoBatchWriterTest, EcnCodepoint) {
  const WriteResult write_buffered(WRITE_STATUS_OK, 0);

  auto writer = TestQuicGsoBatchWriter::NewInstanceWithReleaseTimeSupport();

  QuicPacketWriterParams params;
  EXPECT_TRUE(params.release_time_delay.IsZero());
  EXPECT_FALSE(params.allow_burst);
  params.ecn_codepoint = ECN_ECT0;

  // The 1st packet has no delay.
  WriteResult result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(1), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());

  // The 2nd packet should be buffered.
  params.allow_burst = true;
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);

  // The 3rd packet changes the ECN codepoint.
  // The first 2 packets are flushed due to different codepoint.
  params.ecn_codepoint = ECN_ECT1;
  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        const int kEct0 = 0x02;
        EXPECT_EQ(2700u, PacketLength(msg));
        msghdr mutable_msg;
        memcpy(&mutable_msg, msg, sizeof(*msg));
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&mutable_msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&mutable_msg, cmsg)) {
          if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TOS) {
            EXPECT_EQ(*reinterpret_cast<int*> CMSG_DATA(cmsg), kEct0);
            break;
          }
        }
        errno = 0;
        return 0;
      }));
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 2700), result);
}

TEST_F(QuicGsoBatchWriterTest, EcnCodepointIPv6) {
  const WriteResult write_buffered(WRITE_STATUS_OK, 0);

  self_address_ = QuicIpAddress::Any6();
  peer_address_ = QuicSocketAddress(QuicIpAddress::Any6(), 443);
  auto writer = TestQuicGsoBatchWriter::NewInstanceWithReleaseTimeSupport();

  QuicPacketWriterParams params;
  EXPECT_TRUE(params.release_time_delay.IsZero());
  EXPECT_FALSE(params.allow_burst);
  params.ecn_codepoint = ECN_ECT0;

  // The 1st packet has no delay.
  WriteResult result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);
  EXPECT_EQ(MillisToNanos(1), writer->buffered_writes().back().release_time);
  EXPECT_EQ(result.send_time_offset, QuicTime::Delta::Zero());

  // The 2nd packet should be buffered.
  params.allow_burst = true;
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(write_buffered, result);

  // The 3rd packet changes the ECN codepoint.
  // The first 2 packets are flushed due to different codepoint.
  params.ecn_codepoint = ECN_ECT1;
  EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
      .WillOnce(Invoke([](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
        const int kEct0 = 0x02;
        EXPECT_EQ(2700u, PacketLength(msg));
        msghdr mutable_msg;
        memcpy(&mutable_msg, msg, sizeof(*msg));
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&mutable_msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&mutable_msg, cmsg)) {
          if (cmsg->cmsg_level == IPPROTO_IPV6 &&
              cmsg->cmsg_type == IPV6_TCLASS) {
            EXPECT_EQ(*reinterpret_cast<int*> CMSG_DATA(cmsg), kEct0);
            break;
          }
        }
        errno = 0;
        return 0;
      }));
  result = WritePacketWithParams(writer.get(), params);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 2700), result);
}

TEST_F(QuicGsoBatchWriterTest, FlowLabelIPv6) {
  const WriteResult write_buffered(WRITE_STATUS_OK, 0);

  self_address_ = QuicIpAddress::Any6();
  peer_address_ = QuicSocketAddress(QuicIpAddress::Any6(), 443);
  auto writer = TestQuicGsoBatchWriter::NewInstanceWithReleaseTimeSupport();

  QuicPacketWriterParams params;
  EXPECT_TRUE(params.release_time_delay.IsZero());
  EXPECT_FALSE(params.allow_burst);

  for (uint32_t i = 1; i < 5; ++i) {
    // Generate flow label which are on both side of zero to test
    // coverage when the in-memory label is larger than 20 bits.
    params.flow_label = i - 2;
    WriteResult result = WritePacketWithParams(writer.get(), params);
    ASSERT_EQ(write_buffered, result);

    EXPECT_CALL(mock_syscalls_, Sendmsg(_, _, _))
        .WillOnce(
            Invoke([&params](int /*sockfd*/, const msghdr* msg, int /*flags*/) {
              EXPECT_EQ(1350u, PacketLength(msg));
              msghdr mutable_msg;
              memcpy(&mutable_msg, msg, sizeof(*msg));
              bool found_flow_label = false;
              for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&mutable_msg);
                   cmsg != NULL; cmsg = CMSG_NXTHDR(&mutable_msg, cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IPV6 &&
                    cmsg->cmsg_type == IPV6_FLOWINFO) {
                  found_flow_label = true;
                  uint32_t cmsg_flow_label =
                      ntohl(*reinterpret_cast<uint32_t*> CMSG_DATA(cmsg));
                  EXPECT_EQ(params.flow_label & 0xFFFFF, cmsg_flow_label);
                  break;
                }
              }
              // As long as the flow label is not zero, it should be present.
              EXPECT_EQ(params.flow_label != 0, found_flow_label);
              errno = 0;
              return 0;
            }));
    WriteResult error_result = writer->Flush();
    ASSERT_EQ(WriteResult(WRITE_STATUS_OK, 1350), error_result);
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
```