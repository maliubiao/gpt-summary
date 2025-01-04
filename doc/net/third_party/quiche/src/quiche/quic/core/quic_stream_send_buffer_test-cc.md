Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the test file, its relation to JavaScript (if any), logical inference examples, common usage errors, and debugging hints.

2. **Identify the Core Subject:** The filename `quic_stream_send_buffer_test.cc` and the `#include "quiche/quic/core/quic_stream_send_buffer.h"` immediately tell us this file tests the `QuicStreamSendBuffer` class.

3. **Analyze the Test Structure:** The file uses the Google Test framework (`TEST_F`, `EXPECT_EQ`, `ASSERT_TRUE`, etc.). This means it's a unit test suite. The `QuicStreamSendBufferTest` class is the test fixture, providing setup (`SetUp` implicitly through the constructor) and utility methods.

4. **Examine the Test Fixture (`QuicStreamSendBufferTest`):**
    * **Constructor:**  The constructor is crucial. It initializes a `QuicStreamSendBuffer` and populates it with data using `SaveStreamData` and `SaveMemSlice`. The comments within the constructor are very helpful in understanding the initial state and the breakdown of the data into `BufferedSlices`. Pay attention to `SetQuicFlag(quic_send_buffer_max_data_slice_size, 1024);` as it explains *why* the initial data is split.
    * **`WriteAllData()`:** This utility method writes all the buffered data and marks it as outstanding. It's a common setup step in several tests.
    * **Member Variables:** `allocator_` and `send_buffer_` are the key objects being tested.

5. **Analyze Individual Test Cases:** Go through each `TEST_F` function:
    * **`CopyDataToBuffer`:** Tests if data can be correctly copied into a buffer using `WriteStreamData`. It covers copying within and across slice boundaries and includes tests for invalid copy attempts.
    * **`WriteStreamDataContainsBothRetransmissionAndNewData`:** A regression test focusing on a specific scenario where `WriteStreamData` handles both retransmitted and new data. This highlights the importance of tracking what's been sent and what needs resending.
    * **`RemoveStreamFrame`:** Tests the `OnStreamDataAcked` method for basic ACK scenarios, ensuring that acknowledged data is removed from the buffer.
    * **`RemoveStreamFrameAcrossBoundries`:** Similar to `RemoveStreamFrame` but focuses on ACKs that span multiple internal buffer slices.
    * **`AckStreamDataMultipleTimes`:**  Tests handling of duplicate ACKs or ACKs that cover previously acknowledged data.
    * **`AckStreamDataOutOfOrder`:** Tests the robustness of the ACK handling logic when ACKs arrive out of sequence.
    * **`PendingRetransmission`:**  Tests the logic for identifying and retrieving data that needs to be retransmitted after loss. This involves `OnStreamDataLost`, `HasPendingRetransmission`, and `NextPendingRetransmission`.
    * **`EndOffset`:**  Focuses on the `EndOffset` concept, which represents the highest offset written to the buffer. It tests how this value changes as data is written and acknowledged.
    * **`SaveMemSliceSpan`:** Tests adding multiple `QuicheMemSlice` objects at once.
    * **`SaveEmptyMemSliceSpan`:** Tests that empty slices are not saved.

6. **Infer Functionality:** Based on the test cases, we can deduce the core functionalities of `QuicStreamSendBuffer`:
    * Buffering data to be sent.
    * Copying buffered data for transmission.
    * Tracking outstanding data.
    * Handling acknowledgements (ACKs) and removing acknowledged data.
    * Identifying data that needs retransmission (due to loss).

7. **Consider JavaScript Relevance:** Think about how the concepts of sending data in streams, acknowledging delivery, and handling retransmissions map to web technologies. JavaScript interacts with these concepts through browser APIs like the Fetch API or WebSockets. Although the *implementation* is in C++, the *concepts* are relevant to how data is reliably transferred over the web, which JavaScript relies upon.

8. **Construct Logical Inferences:** For each test case, think about what the input is (the initial state of the buffer, the arguments to the tested method) and what the expected output or state change is (return value, changes to buffer size, outstanding bytes, etc.). Use concrete examples with specific byte counts and offsets.

9. **Identify Potential User/Programming Errors:** Consider common mistakes developers might make when interacting with a send buffer:
    * Trying to write data beyond the buffer's capacity (though this specific class might handle this internally by slicing).
    * Incorrectly calculating offsets or lengths.
    * Not handling acknowledgements properly.
    * Misunderstanding the concept of outstanding data.

10. **Develop Debugging Hints:** Think about how a developer might arrive at this code during debugging. What symptoms would lead them here?  This often involves network issues, connection problems, or data corruption. Tracing the flow of data and acknowledgements is key.

11. **Structure the Answer:**  Organize the information logically according to the prompt's requests: functionality, JavaScript relevance, logical inferences, common errors, and debugging hints. Use clear and concise language.

12. **Review and Refine:**  Read through the answer to ensure accuracy, completeness, and clarity. Make sure the examples are easy to understand and directly relate to the code being tested. Double-check any assumptions made. For example, initially, I might just say "it buffers data". But looking closer at the tests reveals the splitting into `BufferedSlices` is important, so I'd refine the description.
这个 C++ 文件 `quic_stream_send_buffer_test.cc` 是 Chromium QUIC 库中 `QuicStreamSendBuffer` 类的单元测试文件。它的主要功能是验证 `QuicStreamSendBuffer` 类的各项功能是否正常工作。

以下是该文件列举的功能，并根据您的要求进行分析：

**主要功能:**

1. **数据存储 (SaveStreamData, SaveMemSlice, SaveMemSliceSpan):** 测试 `QuicStreamSendBuffer` 是否能正确存储待发送的流数据。数据可以以连续的字符串形式或内存切片 (MemSlice) 的形式保存。
2. **数据写入 (WriteStreamData):** 测试从发送缓冲区中读取数据，并将其写入到 `QuicDataWriter` 中。这模拟了将数据发送到网络的过程。测试涵盖了读取不同偏移量和长度的数据，以及跨越内部缓冲块边界的情况。
3. **数据确认 (OnStreamDataAcked):** 测试当发送的数据被对方确认收到时，`QuicStreamSendBuffer` 是否能正确处理 ACK，并释放已确认的数据占用的空间。测试涵盖了按顺序、乱序以及多次确认的情况。
4. **数据丢失 (OnStreamDataLost):** 测试当发送的数据被认为丢失时，`QuicStreamSendBuffer` 是否能正确记录丢失的数据，并为后续的重传做准备。
5. **数据重传 (OnStreamDataRetransmitted):** 测试当丢失的数据被重传后，`QuicStreamSendBuffer` 是否能正确标记重传的数据。
6. **待重传数据查询 (HasPendingRetransmission, NextPendingRetransmission):** 测试 `QuicStreamSendBuffer` 是否能正确判断是否有待重传的数据，并返回下一个待重传的数据段的信息。
7. **数据状态查询 (IsStreamDataOutstanding):** 测试 `QuicStreamSendBuffer` 是否能正确判断指定偏移量和长度的数据是否还在发送中（未被确认）。
8. **缓冲区大小和偏移量管理 (size, stream_bytes_written, stream_bytes_outstanding, EndOffset):** 测试 `QuicStreamSendBuffer` 是否能正确维护缓冲区的当前大小、已写入的流字节数、待发送的流字节数以及已写入数据的最高偏移量。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它测试的 `QuicStreamSendBuffer` 类是 Chromium 网络栈的一部分，而 Chromium 是 Chrome 浏览器的核心。Chrome 浏览器中的 JavaScript 代码可以通过浏览器提供的 API（例如 Fetch API 或 WebSockets）与网络进行交互，而底层的网络传输可能使用 QUIC 协议。

因此，`QuicStreamSendBuffer` 的功能直接影响着 JavaScript 代码的网络性能和可靠性。如果 `QuicStreamSendBuffer` 的实现有缺陷，可能会导致 JavaScript 发出的网络请求失败、延迟或数据错误。

**举例说明:**

假设一个 JavaScript 应用使用 Fetch API 发送一个大的 POST 请求：

```javascript
fetch('https://example.com/api/data', {
  method: 'POST',
  body: '大量的请求数据...'
})
.then(response => response.json())
.then(data => console.log(data));
```

在这个过程中，浏览器会将 JavaScript 提供的请求数据传递给底层的网络栈。`QuicStreamSendBuffer` 就负责缓冲这些数据，并将其分割成合适的 QUIC 数据包进行发送。如果网络出现丢包，`QuicStreamSendBuffer` 会根据其内部的逻辑判断哪些数据需要重传，确保数据最终可靠地送达服务器。

**逻辑推理 - 假设输入与输出:**

**测试用例: `CopyDataToBuffer`**

* **假设输入:**
    * `send_buffer_` 已经初始化并存储了一些数据 (如构造函数中所示)。
    * 调用 `send_buffer_.WriteStreamData(1000, 1024, &writer2)`，其中 `writer2` 是一个 `QuicDataWriter`，指向一个足够大的缓冲区 `buf`。
* **逻辑推理:**
    * 请求从偏移量 1000 开始读取 1024 字节的数据。
    * `send_buffer_` 内部的数据被组织成多个 `BufferedSlice`。需要从合适的 `BufferedSlice` 中提取数据，并复制到 `writer2` 指向的缓冲区。
    * 由于偏移量 1000 位于第二个 `BufferedSlice` 的中间位置，因此需要跨越内部边界进行复制。
    * 预期复制的内容是第二个 `BufferedSlice` 的一部分 ('a' 和 'b') 以及第三个 `BufferedSlice` 的一部分 ('c')。
* **预期输出:**
    * `send_buffer_.WriteStreamData` 返回 `true` (成功复制)。
    * `buf` 的前 1024 字节的内容为 "aaaa..." (536个a) + "bbbb..." (256个b) + "cccc..." (232个c)。

**测试用例: `RemoveStreamFrame`**

* **假设输入:**
    * `send_buffer_` 中已经写入了 3840 字节的数据 (通过 `WriteAllData()` 方法)。
    * 调用 `send_buffer_.OnStreamDataAcked(1024, 1024, &newly_acked_length)`。
* **逻辑推理:**
    * 收到一个 ACK，确认了从偏移量 1024 开始的 1024 字节的数据。
    * 这部分数据对应于 `send_buffer_` 中的第二个 `BufferedSlice` 的全部内容。
    * `send_buffer_` 应该移除这个 `BufferedSlice`，并更新内部状态。
* **预期输出:**
    * `send_buffer_.OnStreamDataAcked` 返回 `true`。
    * `newly_acked_length` 的值为 1024。
    * `send_buffer_.size()` 的值仍然是 4，因为虽然第二个 slice 被完全 ack 了，但是内部数据结构可能还没立即清理 (从后续的测试来看，这里可能是一个误导，实际会减少)。

**用户或编程常见的使用错误:**

1. **错误的偏移量或长度:**  用户（通常是网络栈的其他组件）在调用 `WriteStreamData` 或 `OnStreamDataAcked` 等方法时，可能会传递错误的偏移量或长度参数，导致读取或确认的数据范围不正确。
   * **示例:**  假设用户想确认发送了 1000 字节的数据，但错误地调用了 `send_buffer_.OnStreamDataAcked(100, 900, &newly_acked_length);`，这将导致部分数据未被确认，或者确认了错误的数据。
2. **重复确认:** 用户可能会重复确认相同的数据范围，导致 `OnStreamDataAcked` 被多次调用。 `QuicStreamSendBuffer` 需要能够处理这种情况，避免错误地释放内存或更新状态。
   * **示例:**  在网络不稳定的情况下，ACK 包可能会重复到达。
3. **乱序确认导致的逻辑错误:** 如果确认包的到达顺序与数据发送顺序不一致，用户需要确保 `QuicStreamSendBuffer` 能够正确处理乱序 ACK，并更新内部状态。
   * **示例:**  先收到偏移量较高的 ACK，后收到偏移量较低的 ACK。
4. **在数据发送完成前就认为全部发送成功:** 用户可能在所有数据都被确认之前就错误地认为发送完成，这可能导致数据丢失。

**用户操作如何一步步到达这里作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了网络问题，例如页面加载缓慢或部分内容加载不出来。作为开发人员，在排查问题时可能会逐步深入到网络栈的底层：

1. **用户反馈或错误报告:** 用户报告网站访问异常。
2. **网络监控工具:** 使用 Chrome 的开发者工具 (Network tab) 或 Wireshark 等工具抓包，发现连接使用了 QUIC 协议，并且存在丢包或乱序的情况。
3. **QUIC 事件追踪:**  查看 QUIC 连接的事件日志，可能会发现某些 Stream 的数据发送存在问题，例如发送缓冲区持续积压，或者出现大量的重传。
4. **代码调试 (C++):** 如果怀疑是发送缓冲区的问题，开发人员可能会设置断点到 `quic_stream_send_buffer.cc` 中的关键方法，例如 `WriteStreamData`、`OnStreamDataAcked`、`OnStreamDataLost` 等。
5. **查看 `quic_stream_send_buffer_test.cc`:** 为了理解 `QuicStreamSendBuffer` 的工作原理和测试覆盖范围，开发人员可能会查看其单元测试文件 `quic_stream_send_buffer_test.cc`，了解各种场景下的行为和预期结果。

通过阅读测试用例，开发人员可以更好地理解 `QuicStreamSendBuffer` 在处理数据写入、确认和丢失等情况下的逻辑，从而更好地定位和解决实际网络问题。例如，如果发现某个测试用例模拟了与当前遇到的网络问题相似的场景，就可以深入研究相关的代码逻辑，找出潜在的 bug 或性能瓶颈。

总而言之，`quic_stream_send_buffer_test.cc` 是理解和调试 Chromium QUIC 协议栈中流发送缓冲区功能的重要资源。它通过一系列精心设计的测试用例，验证了核心逻辑的正确性，并为开发人员提供了排查网络问题的线索。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_send_buffer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream_send_buffer.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_stream_send_buffer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic {
namespace test {
namespace {

class QuicStreamSendBufferTest : public QuicTest {
 public:
  QuicStreamSendBufferTest() : send_buffer_(&allocator_) {
    EXPECT_EQ(0u, send_buffer_.size());
    EXPECT_EQ(0u, send_buffer_.stream_bytes_written());
    EXPECT_EQ(0u, send_buffer_.stream_bytes_outstanding());
    // The stream offset should be 0 since nothing is written.
    EXPECT_EQ(0u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));

    std::string data1 = absl::StrCat(
        std::string(1536, 'a'), std::string(256, 'b'), std::string(256, 'c'));

    quiche::QuicheBuffer buffer1(&allocator_, 1024);
    memset(buffer1.data(), 'c', buffer1.size());
    quiche::QuicheMemSlice slice1(std::move(buffer1));

    quiche::QuicheBuffer buffer2(&allocator_, 768);
    memset(buffer2.data(), 'd', buffer2.size());
    quiche::QuicheMemSlice slice2(std::move(buffer2));

    // `data` will be split into two BufferedSlices.
    SetQuicFlag(quic_send_buffer_max_data_slice_size, 1024);
    send_buffer_.SaveStreamData(data1);

    send_buffer_.SaveMemSlice(std::move(slice1));
    EXPECT_TRUE(slice1.empty());
    send_buffer_.SaveMemSlice(std::move(slice2));
    EXPECT_TRUE(slice2.empty());

    EXPECT_EQ(4u, send_buffer_.size());
    // At this point, `send_buffer_.interval_deque_` looks like this:
    // BufferedSlice1: 'a' * 1024
    // BufferedSlice2: 'a' * 512 + 'b' * 256 + 'c' * 256
    // BufferedSlice3: 'c' * 1024
    // BufferedSlice4: 'd' * 768
  }

  void WriteAllData() {
    // Write all data.
    char buf[4000];
    QuicDataWriter writer(4000, buf, quiche::HOST_BYTE_ORDER);
    send_buffer_.WriteStreamData(0, 3840u, &writer);

    send_buffer_.OnStreamDataConsumed(3840u);
    EXPECT_EQ(3840u, send_buffer_.stream_bytes_written());
    EXPECT_EQ(3840u, send_buffer_.stream_bytes_outstanding());
  }

  quiche::SimpleBufferAllocator allocator_;
  QuicStreamSendBuffer send_buffer_;
};

TEST_F(QuicStreamSendBufferTest, CopyDataToBuffer) {
  char buf[4000];
  QuicDataWriter writer(4000, buf, quiche::HOST_BYTE_ORDER);
  std::string copy1(1024, 'a');
  std::string copy2 =
      std::string(512, 'a') + std::string(256, 'b') + std::string(256, 'c');
  std::string copy3(1024, 'c');
  std::string copy4(768, 'd');

  ASSERT_TRUE(send_buffer_.WriteStreamData(0, 1024, &writer));
  EXPECT_EQ(copy1, absl::string_view(buf, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(1024, 1024, &writer));
  EXPECT_EQ(copy2, absl::string_view(buf + 1024, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2048, 1024, &writer));
  EXPECT_EQ(copy3, absl::string_view(buf + 2048, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(3072, 768, &writer));
  EXPECT_EQ(copy4, absl::string_view(buf + 3072, 768));

  // Test data piece across boundries.
  QuicDataWriter writer2(4000, buf, quiche::HOST_BYTE_ORDER);
  std::string copy5 =
      std::string(536, 'a') + std::string(256, 'b') + std::string(232, 'c');
  ASSERT_TRUE(send_buffer_.WriteStreamData(1000, 1024, &writer2));
  EXPECT_EQ(copy5, absl::string_view(buf, 1024));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2500, 1024, &writer2));
  std::string copy6 = std::string(572, 'c') + std::string(452, 'd');
  EXPECT_EQ(copy6, absl::string_view(buf + 1024, 1024));

  // Invalid data copy.
  QuicDataWriter writer3(4000, buf, quiche::HOST_BYTE_ORDER);
  EXPECT_FALSE(send_buffer_.WriteStreamData(3000, 1024, &writer3));
  EXPECT_QUIC_BUG(send_buffer_.WriteStreamData(0, 4000, &writer3),
                  "Writer fails to write.");

  send_buffer_.OnStreamDataConsumed(3840);
  EXPECT_EQ(3840u, send_buffer_.stream_bytes_written());
  EXPECT_EQ(3840u, send_buffer_.stream_bytes_outstanding());
}

// Regression test for b/143491027.
TEST_F(QuicStreamSendBufferTest,
       WriteStreamDataContainsBothRetransmissionAndNewData) {
  std::string copy1(1024, 'a');
  std::string copy2 =
      std::string(512, 'a') + std::string(256, 'b') + std::string(256, 'c');
  std::string copy3 = std::string(1024, 'c') + std::string(100, 'd');
  char buf[6000];
  QuicDataWriter writer(6000, buf, quiche::HOST_BYTE_ORDER);
  // Write more than one slice.
  EXPECT_EQ(0, QuicStreamSendBufferPeer::write_index(&send_buffer_));
  ASSERT_TRUE(send_buffer_.WriteStreamData(0, 1024, &writer));
  EXPECT_EQ(copy1, absl::string_view(buf, 1024));
  EXPECT_EQ(1, QuicStreamSendBufferPeer::write_index(&send_buffer_));

  // Retransmit the first frame and also send new data.
  ASSERT_TRUE(send_buffer_.WriteStreamData(0, 2048, &writer));
  EXPECT_EQ(copy1 + copy2, absl::string_view(buf + 1024, 2048));

  // Write new data.
  EXPECT_EQ(2048u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2048, 50, &writer));
  EXPECT_EQ(std::string(50, 'c'), absl::string_view(buf + 1024 + 2048, 50));
  EXPECT_EQ(3072u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
  ASSERT_TRUE(send_buffer_.WriteStreamData(2048, 1124, &writer));
  EXPECT_EQ(copy3, absl::string_view(buf + 1024 + 2048 + 50, 1124));
  EXPECT_EQ(3840u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
}

TEST_F(QuicStreamSendBufferTest, RemoveStreamFrame) {
  WriteAllData();

  QuicByteCount newly_acked_length;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(1024, 1024, &newly_acked_length));
  EXPECT_EQ(1024u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2048, 1024, &newly_acked_length));
  EXPECT_EQ(1024u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(0, 1024, &newly_acked_length));
  EXPECT_EQ(1024u, newly_acked_length);

  // Send buffer is cleaned up in order.
  EXPECT_EQ(1u, send_buffer_.size());
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(3072, 768, &newly_acked_length));
  EXPECT_EQ(768u, newly_acked_length);
  EXPECT_EQ(0u, send_buffer_.size());
}

TEST_F(QuicStreamSendBufferTest, RemoveStreamFrameAcrossBoundries) {
  WriteAllData();

  QuicByteCount newly_acked_length;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2024, 576, &newly_acked_length));
  EXPECT_EQ(576u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(0, 1000, &newly_acked_length));
  EXPECT_EQ(1000u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(1000, 1024, &newly_acked_length));
  EXPECT_EQ(1024u, newly_acked_length);
  // Send buffer is cleaned up in order.
  EXPECT_EQ(2u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2600, 1024, &newly_acked_length));
  EXPECT_EQ(1024u, newly_acked_length);
  EXPECT_EQ(1u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(3624, 216, &newly_acked_length));
  EXPECT_EQ(216u, newly_acked_length);
  EXPECT_EQ(0u, send_buffer_.size());
}

TEST_F(QuicStreamSendBufferTest, AckStreamDataMultipleTimes) {
  WriteAllData();
  QuicByteCount newly_acked_length;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(100, 1500, &newly_acked_length));
  EXPECT_EQ(1500u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2000, 500, &newly_acked_length));
  EXPECT_EQ(500u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(0, 2600, &newly_acked_length));
  EXPECT_EQ(600u, newly_acked_length);
  // Send buffer is cleaned up in order.
  EXPECT_EQ(2u, send_buffer_.size());

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2200, 1640, &newly_acked_length));
  EXPECT_EQ(1240u, newly_acked_length);
  EXPECT_EQ(0u, send_buffer_.size());

  EXPECT_FALSE(send_buffer_.OnStreamDataAcked(4000, 100, &newly_acked_length));
}

TEST_F(QuicStreamSendBufferTest, AckStreamDataOutOfOrder) {
  WriteAllData();
  QuicByteCount newly_acked_length;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(500, 1000, &newly_acked_length));
  EXPECT_EQ(1000u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());
  EXPECT_EQ(3840u, QuicStreamSendBufferPeer::TotalLength(&send_buffer_));

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(1200, 1000, &newly_acked_length));
  EXPECT_EQ(700u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());
  // Slice 2 gets fully acked.
  EXPECT_EQ(2816u, QuicStreamSendBufferPeer::TotalLength(&send_buffer_));

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(2000, 1840, &newly_acked_length));
  EXPECT_EQ(1640u, newly_acked_length);
  EXPECT_EQ(4u, send_buffer_.size());
  // Slices 3 and 4 get fully acked.
  EXPECT_EQ(1024u, QuicStreamSendBufferPeer::TotalLength(&send_buffer_));

  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(0, 1000, &newly_acked_length));
  EXPECT_EQ(500u, newly_acked_length);
  EXPECT_EQ(0u, send_buffer_.size());
  EXPECT_EQ(0u, QuicStreamSendBufferPeer::TotalLength(&send_buffer_));
}

TEST_F(QuicStreamSendBufferTest, PendingRetransmission) {
  WriteAllData();
  EXPECT_TRUE(send_buffer_.IsStreamDataOutstanding(0, 3840));
  EXPECT_FALSE(send_buffer_.HasPendingRetransmission());
  // Lost data [0, 1200).
  send_buffer_.OnStreamDataLost(0, 1200);
  // Lost data [1500, 2000).
  send_buffer_.OnStreamDataLost(1500, 500);
  EXPECT_TRUE(send_buffer_.HasPendingRetransmission());

  EXPECT_EQ(StreamPendingRetransmission(0, 1200),
            send_buffer_.NextPendingRetransmission());
  // Retransmit data [0, 500).
  send_buffer_.OnStreamDataRetransmitted(0, 500);
  EXPECT_TRUE(send_buffer_.IsStreamDataOutstanding(0, 500));
  EXPECT_EQ(StreamPendingRetransmission(500, 700),
            send_buffer_.NextPendingRetransmission());
  // Ack data [500, 1200).
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(500, 700, &newly_acked_length));
  EXPECT_FALSE(send_buffer_.IsStreamDataOutstanding(500, 700));
  EXPECT_TRUE(send_buffer_.HasPendingRetransmission());
  EXPECT_EQ(StreamPendingRetransmission(1500, 500),
            send_buffer_.NextPendingRetransmission());
  // Retransmit data [1500, 2000).
  send_buffer_.OnStreamDataRetransmitted(1500, 500);
  EXPECT_FALSE(send_buffer_.HasPendingRetransmission());

  // Lost [200, 800).
  send_buffer_.OnStreamDataLost(200, 600);
  EXPECT_TRUE(send_buffer_.HasPendingRetransmission());
  // Verify [200, 500) is considered as lost, as [500, 800) has been acked.
  EXPECT_EQ(StreamPendingRetransmission(200, 300),
            send_buffer_.NextPendingRetransmission());

  // Verify 0 length data is not outstanding.
  EXPECT_FALSE(send_buffer_.IsStreamDataOutstanding(100, 0));
  // Verify partially acked data is outstanding.
  EXPECT_TRUE(send_buffer_.IsStreamDataOutstanding(400, 800));
}

TEST_F(QuicStreamSendBufferTest, EndOffset) {
  char buf[4000];
  QuicDataWriter writer(4000, buf, quiche::HOST_BYTE_ORDER);

  EXPECT_EQ(1024u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
  ASSERT_TRUE(send_buffer_.WriteStreamData(0, 1024, &writer));
  // Last offset we've seen is 1024
  EXPECT_EQ(1024u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));

  ASSERT_TRUE(send_buffer_.WriteStreamData(1024, 512, &writer));
  // Last offset is now 2048 as that's the end of the next slice.
  EXPECT_EQ(2048u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
  send_buffer_.OnStreamDataConsumed(1024);

  // If data in 1st slice gets ACK'ed, it shouldn't change the indexed slice
  QuicByteCount newly_acked_length;
  EXPECT_TRUE(send_buffer_.OnStreamDataAcked(0, 1024, &newly_acked_length));
  // Last offset is still 2048.
  EXPECT_EQ(2048u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));

  ASSERT_TRUE(
      send_buffer_.WriteStreamData(1024 + 512, 3840 - 1024 - 512, &writer));

  // Last offset is end offset of last slice.
  EXPECT_EQ(3840u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
  quiche::QuicheBuffer buffer(&allocator_, 60);
  memset(buffer.data(), 'e', buffer.size());
  quiche::QuicheMemSlice slice(std::move(buffer));
  send_buffer_.SaveMemSlice(std::move(slice));

  EXPECT_EQ(3840u, QuicStreamSendBufferPeer::EndOffset(&send_buffer_));
}

TEST_F(QuicStreamSendBufferTest, SaveMemSliceSpan) {
  quiche::SimpleBufferAllocator allocator;
  QuicStreamSendBuffer send_buffer(&allocator);

  std::string data(1024, 'a');
  std::vector<quiche::QuicheMemSlice> buffers;
  for (size_t i = 0; i < 10; ++i) {
    buffers.push_back(MemSliceFromString(data));
  }

  EXPECT_EQ(10 * 1024u, send_buffer.SaveMemSliceSpan(absl::MakeSpan(buffers)));
  EXPECT_EQ(10u, send_buffer.size());
}

TEST_F(QuicStreamSendBufferTest, SaveEmptyMemSliceSpan) {
  quiche::SimpleBufferAllocator allocator;
  QuicStreamSendBuffer send_buffer(&allocator);

  std::string data(1024, 'a');
  std::vector<quiche::QuicheMemSlice> buffers;
  for (size_t i = 0; i < 10; ++i) {
    buffers.push_back(MemSliceFromString(data));
  }

  EXPECT_EQ(10 * 1024u, send_buffer.SaveMemSliceSpan(absl::MakeSpan(buffers)));
  // Verify the empty slice does not get saved.
  EXPECT_EQ(10u, send_buffer.size());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```