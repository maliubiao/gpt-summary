Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The core request is to understand the functionality of the given C++ test file. Specifically, it tests the `QuicStreamSequencerBuffer` class. We need to identify its purpose, how it works, and potential issues.

2. **Identify the Target Class:** The `#include "quiche/quic/core/quic_stream_sequencer_buffer.h"` line is the most important clue. This tells us the code under test is `QuicStreamSequencerBuffer`.

3. **Recognize the Test Framework:** The presence of `quiche/quic/platform/api/quic_test.h` and `TEST_F` macros indicates this is a unit test using Google Test (or a similar framework). This means the file contains various test cases that exercise different aspects of the `QuicStreamSequencerBuffer` class.

4. **Scan for Key Methods and Concepts:**  Quickly look through the test functions (`TEST_F`). Notice recurring patterns:
    * `OnStreamData()`:  Likely the method to add data to the buffer.
    * `Readv()`:  Likely a method to read data from the buffer.
    * `GetReadableRegions()`/`GetReadableRegion()`: Methods for inspecting readable data without consuming it.
    * `PeekRegion()`: Another method for inspecting data, suggesting it's non-destructive.
    * `MarkConsumed()`:  A method for acknowledging data has been processed.
    * `Clear()`: A method to reset the buffer.
    * `ReleaseWholeBuffer()`: A method to deallocate the buffer's memory.
    * The use of `iovec`: This suggests the buffer deals with scattered data segments.
    * The naming conventions (e.g., `OnStreamDataWithinBlock`, `ReadvAcrossBlocks`) provide hints about the tested scenarios.

5. **Infer the Purpose of `QuicStreamSequencerBuffer`:** Based on the tested methods, we can infer that `QuicStreamSequencerBuffer` is a buffer designed to handle incoming stream data in a potentially out-of-order manner. It seems to manage:
    * Storing received data.
    * Keeping track of which data has been received.
    * Providing methods to read and acknowledge received data.
    * Handling cases where data arrives in segments (iovecs).

6. **Analyze Individual Test Cases (Focus on Functionality):**  Go through some of the test cases and understand what specific functionality they are verifying:
    * `InitializeWithMaxRecvWindowSize`: Checks buffer initialization.
    * `OnStreamDataWithinBlock`: Tests adding data within a single memory block.
    * `OnStreamDataWithOverlap`: Verifies handling of overlapping data segments.
    * `Readv100Bytes`/`ReadvAcrossBlocks`:  Tests reading data, potentially across memory blocks.
    * `GetReadableRegions...`: Examines how the buffer reports available data.
    * `Peek...`:  Tests the non-destructive inspection of data.
    * `MarkConsumed...`: Tests the acknowledgment of processed data.

7. **Consider Relationships to JavaScript (If Applicable):**  Think about how stream buffering concepts might relate to JavaScript. While this specific C++ code isn't directly used in JS, the *ideas* are relevant:
    * **`ReadableStream` in JavaScript:**  This is the most direct analogy. `QuicStreamSequencerBuffer` serves a similar purpose in the network stack as `ReadableStream` does for data flowing into a JavaScript application. Both handle asynchronous data arrival and provide mechanisms to read it.
    * **Buffering in Network Requests (Fetch API):**  When using `fetch` in JavaScript, the browser internally buffers the response body. The underlying network stack likely uses a mechanism similar to `QuicStreamSequencerBuffer`.
    * **WebSockets:**  Similar buffering is involved in WebSocket communication.

8. **Consider Logic and Edge Cases:** The test names and the assertions within them highlight various scenarios and edge cases:
    * Overlapping data.
    * Data arriving out of order (implied by "sequencer").
    * Reading across block boundaries.
    * Reaching the buffer's capacity.
    * Empty buffers.

9. **Consider User/Programming Errors:** Think about common mistakes a developer might make when using a stream buffer:
    * Providing invalid offsets or lengths.
    * Trying to read more data than available.
    * Not handling out-of-order data correctly (though this buffer *handles* it, *using* it might require careful logic).
    * Memory management issues (though the buffer likely handles its own memory, improper usage could lead to leaks if not integrated correctly).

10. **Trace User Actions (Debugging Context):** Imagine how a user action in a browser could lead to this code being executed:
    * User requests a web page (HTTP/3 uses QUIC).
    * Server sends stream data.
    * The network stack receives packets containing this data.
    * `QuicStreamSequencerBuffer` is used to buffer the incoming stream data, reassembling it in the correct order.

11. **Summarize Functionality (Part 1):**  Based on the above analysis, formulate a concise summary of the file's purpose. Focus on the main functionalities being tested.

12. **Review and Refine:** Read through the generated analysis to ensure accuracy and clarity. Check for any misinterpretations or missing points. Ensure the JavaScript examples are relevant and the debugging scenarios make sense. Make sure the assumptions and inputs/outputs are realistic based on the code.

This systematic approach, starting with the overall goal and progressively diving into the details, allows for a comprehensive understanding of the C++ test file and its implications.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer_buffer_test.cc` 文件的第一部分。该文件主要用于测试 `QuicStreamSequencerBuffer` 类的功能。`QuicStreamSequencerBuffer` 是 QUIC 协议中用于接收乱序到达的流数据的核心组件。

**该文件的主要功能归纳如下：**

1. **单元测试框架：** 该文件使用了 Chromium 的测试框架 (`quic_test.h`) 来创建和执行针对 `QuicStreamSequencerBuffer` 类的各种单元测试。

2. **`QuicStreamSequencerBuffer` 核心功能测试：**  测试用例覆盖了 `QuicStreamSequencerBuffer` 的核心功能，包括：
   - **初始化：**  测试不同大小的初始化，包括最大接收窗口大小。
   - **数据写入 (`OnStreamData`)：**
     - 写入空数据。
     - 写入块内数据。
     - 写入有重叠的数据。
     - 写入没有重叠的数据。
     - 写入到接近或超过容量限制的数据。
     - 长流中的数据写入。
   - **数据读取 (`Readv`)：**
     - 从缓冲区读取数据到 iovec 数组。
     - 跨越内存块读取数据。
     - 读取后清空缓冲区。
     - 跨越最后一个块读取数据。
     - 从空缓冲区读取。
   - **获取可读区域 (`GetReadableRegions`, `GetReadableRegion`)：**
     - 在有间隙的情况下获取可读区域。
     - 获取块内、跨块的可读区域。
     - 获取跨越缓冲区末尾的可读区域。
   - **窥视数据 (`PeekRegion`)：**
     - 窥视单块、多块的数据。
     - 窥视已消费的数据。
     - 窥视环绕缓冲区的数据。
   - **标记为已消费 (`MarkConsumed`)：**
     - 在块内标记为已消费。
     - 标记超出可消费范围。
     - 跨块、跨缓冲区末尾标记为已消费。
   - **缓冲区管理：**
     - 清空缓冲区 (`Clear`)。
     - 释放整个缓冲区 (`ReleaseWholeBuffer`)。
     - 测试缓冲区是否已分配。
     - 测试缓冲区的不变性 (`CheckBufferInvariants`)。
   - **移动语义：** 测试 `QuicStreamSequencerBuffer` 的移动构造函数。

3. **辅助函数和类：** 定义了一些辅助函数 (`IovecToStringPiece`, `GetCharFromIOVecs`) 和一个友元类 (`QuicStreamSequencerBufferPeer`)，用于更方便地进行测试和访问 `QuicStreamSequencerBuffer` 的内部状态。

**与 JavaScript 功能的关系举例：**

虽然这个 C++ 文件是网络栈的底层实现，但其功能与 JavaScript 中处理网络数据流的概念有相似之处，尤其是涉及到 `ReadableStream` API：

* **乱序数据处理：** 就像 `QuicStreamSequencerBuffer` 需要处理乱序到达的网络数据包一样，`ReadableStream` 也可以接收到部分数据块，然后需要将它们组合成有序的数据流。
* **数据缓冲：**  `QuicStreamSequencerBuffer` 负责在内存中缓存接收到的数据，直到可以按顺序读取。`ReadableStream` 也有内部的 buffer，用于存储接收到的数据块。
* **数据读取：** `Readv` 方法类似于 `ReadableStream` 的 `read()` 方法，都用于从缓冲区中读取数据。
* **数据消费：** `MarkConsumed` 可以类比为 `ReadableStream` 中成功读取并处理了一部分数据后，内部指针的移动。

**假设输入与输出 (逻辑推理示例)：**

**测试用例：** `TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithinBlock)`

**假设输入：**
- `offset = 800`
- `source = "aaaaaaaaaa..."` (长度为 1024 的字符串 'a')
- 初始状态下缓冲区为空。

**预期输出：**
- `OnStreamData` 返回 `IsQuicNoError()`。
- 缓冲区的第一个块（block）从偏移量 800 开始存储了 `source` 的内容。
- `helper_->ReadableBytes()` 返回 `0` (因为数据虽然写入，但还没有标记为可读，取决于具体的实现和测试断言)。
- `helper_->bytes_received()` 记录了接收到的数据范围 `[800, 1824)`。

**用户或编程常见的使用错误举例说明：**

* **写入超出容量的数据：** 用户或程序员可能会尝试写入超过 `QuicStreamSequencerBuffer` 最大容量的数据，这会导致错误，例如 `TEST_F(QuicStreamSequencerBufferTest, OnStreamDataBeyondCapacity)` 中测试的情况。
* **提供无效的偏移量或长度：** 尝试使用负数偏移量或导致溢出的偏移量和长度组合，就像 `TEST_F(QuicStreamSequencerBufferTest, OnStreamDataBeyondCapacity)` 中测试的边缘情况。
* **在缓冲区未分配时尝试操作：** 虽然 `QuicStreamSequencerBuffer` 通常会按需分配，但在某些错误的使用场景下，可能会尝试在缓冲区未初始化或已释放的情况下进行读写操作。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在 Chrome 浏览器中访问一个使用 QUIC 协议的网站。**
2. **浏览器与服务器建立 QUIC 连接。**
3. **服务器开始发送 HTTP 响应数据流。**
4. **网络层接收到来自服务器的 QUIC 数据包，这些数据包可能乱序到达。**
5. **QUIC 核心层中的流处理模块使用 `QuicStreamSequencerBuffer` 来缓存和重组这些乱序到达的流数据。**
6. **如果在这个过程中出现错误，例如数据包丢失、重复、顺序错乱等，`QuicStreamSequencerBuffer` 的行为可能会异常。**
7. **在开发或调试阶段，网络工程师或 QUIC 协议开发者可能会运行这些单元测试 (`quic_stream_sequencer_buffer_test.cc`) 来验证 `QuicStreamSequencerBuffer` 在各种场景下的正确性。**
8. **如果某个测试用例失败，就可以作为调试线索，帮助开发者定位 `QuicStreamSequencerBuffer` 实现中的 bug。** 例如，如果 `OnStreamDataWithOverlap` 测试失败，就可能表明在处理重叠数据时存在逻辑错误。

**第一部分功能归纳：**

这部分代码主要定义了针对 `QuicStreamSequencerBuffer` 类的基础单元测试用例，涵盖了其核心的数据写入、读取、获取可读区域、窥视数据以及基本的缓冲区管理功能。这些测试用例旨在验证 `QuicStreamSequencerBuffer` 在处理基本的流数据接收场景时的正确性，包括有序和无序到达的数据，以及各种边界情况。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer_buffer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream_sequencer_buffer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_stream_sequencer_buffer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {

namespace test {

absl::string_view IovecToStringPiece(iovec iov) {
  return absl::string_view(reinterpret_cast<const char*>(iov.iov_base),
                           iov.iov_len);
}

char GetCharFromIOVecs(size_t offset, iovec iov[], size_t count) {
  size_t start_offset = 0;
  for (size_t i = 0; i < count; i++) {
    if (iov[i].iov_len == 0) {
      continue;
    }
    size_t end_offset = start_offset + iov[i].iov_len - 1;
    if (offset >= start_offset && offset <= end_offset) {
      const char* buf = reinterpret_cast<const char*>(iov[i].iov_base);
      return buf[offset - start_offset];
    }
    start_offset += iov[i].iov_len;
  }
  QUIC_LOG(ERROR) << "Could not locate char at offset " << offset << " in "
                  << count << " iovecs";
  for (size_t i = 0; i < count; ++i) {
    QUIC_LOG(ERROR) << "  iov[" << i << "].iov_len = " << iov[i].iov_len;
  }
  return '\0';
}

const size_t kMaxNumGapsAllowed = 2 * kMaxPacketGap;

static const size_t kBlockSizeBytes =
    QuicStreamSequencerBuffer::kBlockSizeBytes;
using BufferBlock = QuicStreamSequencerBuffer::BufferBlock;

namespace {

class QuicStreamSequencerBufferTest : public QuicTest {
 public:
  void SetUp() override { Initialize(); }

  void ResetMaxCapacityBytes(size_t max_capacity_bytes) {
    max_capacity_bytes_ = max_capacity_bytes;
    Initialize();
  }

 protected:
  void Initialize() {
    buffer_ =
        std::make_unique<QuicStreamSequencerBuffer>((max_capacity_bytes_));
    helper_ = std::make_unique<QuicStreamSequencerBufferPeer>((buffer_.get()));
  }

  // Use 8.5 here to make sure that the buffer has more than
  // QuicStreamSequencerBuffer::kInitialBlockCount block and its end doesn't
  // align with the end of a block in order to test all the offset calculation.
  size_t max_capacity_bytes_ = 8.5 * kBlockSizeBytes;

  std::unique_ptr<QuicStreamSequencerBuffer> buffer_;
  std::unique_ptr<QuicStreamSequencerBufferPeer> helper_;
  size_t written_ = 0;
  std::string error_details_;
};

TEST_F(QuicStreamSequencerBufferTest, InitializeWithMaxRecvWindowSize) {
  ResetMaxCapacityBytes(16 * 1024 * 1024);  // 16MB
  EXPECT_EQ(2 * 1024u,                      // 16MB / 8KB = 2K
            helper_->max_blocks_count());
  EXPECT_EQ(max_capacity_bytes_, helper_->max_buffer_capacity());
  EXPECT_TRUE(helper_->CheckInitialState());
}

TEST_F(QuicStreamSequencerBufferTest, InitializationWithDifferentSizes) {
  const size_t kCapacity = 16 * QuicStreamSequencerBuffer::kBlockSizeBytes;
  ResetMaxCapacityBytes(kCapacity);
  EXPECT_EQ(max_capacity_bytes_, helper_->max_buffer_capacity());
  EXPECT_TRUE(helper_->CheckInitialState());

  const size_t kCapacity1 = 32 * QuicStreamSequencerBuffer::kBlockSizeBytes;
  ResetMaxCapacityBytes(kCapacity1);
  EXPECT_EQ(kCapacity1, helper_->max_buffer_capacity());
  EXPECT_TRUE(helper_->CheckInitialState());
}

TEST_F(QuicStreamSequencerBufferTest, ClearOnEmpty) {
  buffer_->Clear();
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamData0length) {
  QuicErrorCode error =
      buffer_->OnStreamData(800, "", &written_, &error_details_);
  EXPECT_THAT(error, IsError(QUIC_EMPTY_STREAM_FRAME_NO_FIN));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithinBlock) {
  EXPECT_FALSE(helper_->IsBufferAllocated());
  std::string source(1024, 'a');
  EXPECT_THAT(buffer_->OnStreamData(800, source, &written_, &error_details_),
              IsQuicNoError());
  BufferBlock* block_ptr = helper_->GetBlock(0);
  for (size_t i = 0; i < source.size(); ++i) {
    ASSERT_EQ('a', block_ptr->buffer[helper_->GetInBlockOffset(800) + i]);
  }
  EXPECT_EQ(2, helper_->IntervalSize());
  EXPECT_EQ(0u, helper_->ReadableBytes());
  EXPECT_EQ(1u, helper_->bytes_received().Size());
  EXPECT_EQ(800u, helper_->bytes_received().begin()->min());
  EXPECT_EQ(1824u, helper_->bytes_received().begin()->max());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_TRUE(helper_->IsBufferAllocated());
}

TEST_F(QuicStreamSequencerBufferTest, Move) {
  EXPECT_FALSE(helper_->IsBufferAllocated());
  std::string source(1024, 'a');
  EXPECT_THAT(buffer_->OnStreamData(800, source, &written_, &error_details_),
              IsQuicNoError());
  BufferBlock* block_ptr = helper_->GetBlock(0);
  for (size_t i = 0; i < source.size(); ++i) {
    ASSERT_EQ('a', block_ptr->buffer[helper_->GetInBlockOffset(800) + i]);
  }

  QuicStreamSequencerBuffer buffer2(std::move(*buffer_));
  QuicStreamSequencerBufferPeer helper2(&buffer2);

  EXPECT_FALSE(helper_->IsBufferAllocated());

  EXPECT_EQ(2, helper2.IntervalSize());
  EXPECT_EQ(0u, helper2.ReadableBytes());
  EXPECT_EQ(1u, helper2.bytes_received().Size());
  EXPECT_EQ(800u, helper2.bytes_received().begin()->min());
  EXPECT_EQ(1824u, helper2.bytes_received().begin()->max());
  EXPECT_TRUE(helper2.CheckBufferInvariants());
  EXPECT_TRUE(helper2.IsBufferAllocated());
}

TEST_F(QuicStreamSequencerBufferTest, DISABLED_OnStreamDataInvalidSource) {
  // Pass in an invalid source, expects to return error.
  absl::string_view source;
  source = absl::string_view(nullptr, 1024);
  EXPECT_THAT(buffer_->OnStreamData(800, source, &written_, &error_details_),
              IsError(QUIC_STREAM_SEQUENCER_INVALID_STATE));
  EXPECT_EQ(0u, error_details_.find(absl::StrCat(
                    "QuicStreamSequencerBuffer error: OnStreamData() "
                    "dest == nullptr: ",
                    false, " source == nullptr: ", true)));
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithOverlap) {
  std::string source(1024, 'a');
  // Write something into [800, 1824)
  EXPECT_THAT(buffer_->OnStreamData(800, source, &written_, &error_details_),
              IsQuicNoError());
  // Try to write to [0, 1024) and [1024, 2048).
  EXPECT_THAT(buffer_->OnStreamData(0, source, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_THAT(buffer_->OnStreamData(1024, source, &written_, &error_details_),
              IsQuicNoError());
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataOverlapAndDuplicateCornerCases) {
  std::string source(1024, 'a');
  // Write something into [800, 1824)
  buffer_->OnStreamData(800, source, &written_, &error_details_);
  source = std::string(800, 'b');
  std::string one_byte = "c";
  // Write [1, 801).
  EXPECT_THAT(buffer_->OnStreamData(1, source, &written_, &error_details_),
              IsQuicNoError());
  // Write [0, 800).
  EXPECT_THAT(buffer_->OnStreamData(0, source, &written_, &error_details_),
              IsQuicNoError());
  // Write [1823, 1824).
  EXPECT_THAT(buffer_->OnStreamData(1823, one_byte, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(0u, written_);
  // write one byte to [1824, 1825)
  EXPECT_THAT(buffer_->OnStreamData(1824, one_byte, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithoutOverlap) {
  std::string source(1024, 'a');
  // Write something into [800, 1824).
  EXPECT_THAT(buffer_->OnStreamData(800, source, &written_, &error_details_),
              IsQuicNoError());
  source = std::string(100, 'b');
  // Write something into [kBlockSizeBytes * 2 - 20, kBlockSizeBytes * 2 + 80).
  EXPECT_THAT(buffer_->OnStreamData(kBlockSizeBytes * 2 - 20, source, &written_,
                                    &error_details_),
              IsQuicNoError());
  EXPECT_EQ(3, helper_->IntervalSize());
  EXPECT_EQ(1024u + 100u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataInLongStreamWithOverlap) {
  // Assume a stream has already buffered almost 4GB.
  uint64_t total_bytes_read = pow(2, 32) - 1;
  helper_->set_total_bytes_read(total_bytes_read);
  helper_->AddBytesReceived(0, total_bytes_read);

  // Three new out of order frames arrive.
  const size_t kBytesToWrite = 100;
  std::string source(kBytesToWrite, 'a');
  // Frame [2^32 + 500, 2^32 + 600).
  QuicStreamOffset offset = pow(2, 32) + 500;
  EXPECT_THAT(buffer_->OnStreamData(offset, source, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(2, helper_->IntervalSize());

  // Frame [2^32 + 700, 2^32 + 800).
  offset = pow(2, 32) + 700;
  EXPECT_THAT(buffer_->OnStreamData(offset, source, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(3, helper_->IntervalSize());

  // Another frame [2^32 + 300, 2^32 + 400).
  offset = pow(2, 32) + 300;
  EXPECT_THAT(buffer_->OnStreamData(offset, source, &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(4, helper_->IntervalSize());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataTillEnd) {
  // Write 50 bytes to the end.
  const size_t kBytesToWrite = 50;
  std::string source(kBytesToWrite, 'a');
  EXPECT_THAT(buffer_->OnStreamData(max_capacity_bytes_ - kBytesToWrite, source,
                                    &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(50u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataTillEndCorner) {
  // Write 1 byte to the end.
  const size_t kBytesToWrite = 1;
  std::string source(kBytesToWrite, 'a');
  EXPECT_THAT(buffer_->OnStreamData(max_capacity_bytes_ - kBytesToWrite, source,
                                    &written_, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(1u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataBeyondCapacity) {
  std::string source(60, 'a');
  EXPECT_THAT(buffer_->OnStreamData(max_capacity_bytes_ - 50, source, &written_,
                                    &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  source = "b";
  EXPECT_THAT(buffer_->OnStreamData(max_capacity_bytes_, source, &written_,
                                    &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  EXPECT_THAT(buffer_->OnStreamData(max_capacity_bytes_ * 1000, source,
                                    &written_, &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  // Disallow current_gap != gaps_.end()
  EXPECT_THAT(buffer_->OnStreamData(static_cast<QuicStreamOffset>(-1), source,
                                    &written_, &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  // Disallow offset + size overflow
  source = "bbb";
  EXPECT_THAT(buffer_->OnStreamData(static_cast<QuicStreamOffset>(-2), source,
                                    &written_, &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_EQ(0u, buffer_->BytesBuffered());
}

TEST_F(QuicStreamSequencerBufferTest, Readv100Bytes) {
  std::string source(1024, 'a');
  // Write something into [kBlockSizeBytes, kBlockSizeBytes + 1024).
  buffer_->OnStreamData(kBlockSizeBytes, source, &written_, &error_details_);
  EXPECT_FALSE(buffer_->HasBytesToRead());
  source = std::string(100, 'b');
  // Write something into [0, 100).
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  EXPECT_TRUE(buffer_->HasBytesToRead());
  // Read into a iovec array with total capacity of 120 bytes.
  char dest[120];
  iovec iovecs[3]{iovec{dest, 40}, iovec{dest + 40, 40}, iovec{dest + 80, 40}};
  size_t read;
  EXPECT_THAT(buffer_->Readv(iovecs, 3, &read, &error_details_),
              IsQuicNoError());
  QUIC_LOG(ERROR) << error_details_;
  EXPECT_EQ(100u, read);
  EXPECT_EQ(100u, buffer_->BytesConsumed());
  EXPECT_EQ(source, absl::string_view(dest, read));
  // The first block should be released as its data has been read out.
  EXPECT_EQ(nullptr, helper_->GetBlock(0));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvAcrossBlocks) {
  std::string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full and extand 50 bytes to next block.
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  EXPECT_EQ(source.size(), helper_->ReadableBytes());
  // Iteratively read 512 bytes from buffer_-> Overwrite dest[] each time.
  char dest[512];
  while (helper_->ReadableBytes()) {
    std::fill(dest, dest + 512, 0);
    iovec iovecs[2]{iovec{dest, 256}, iovec{dest + 256, 256}};
    size_t read;
    EXPECT_THAT(buffer_->Readv(iovecs, 2, &read, &error_details_),
                IsQuicNoError());
  }
  // The last read only reads the rest 50 bytes in 2nd block.
  EXPECT_EQ(std::string(50, 'a'), std::string(dest, 50));
  EXPECT_EQ(0, dest[50]) << "Dest[50] shouln't be filled.";
  EXPECT_EQ(source.size(), buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ClearAfterRead) {
  std::string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full with 'a'.
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  size_t read;
  EXPECT_THAT(buffer_->Readv(&iov, 1, &read, &error_details_), IsQuicNoError());
  // Clear() should make buffer empty while preserving BytesConsumed()
  buffer_->Clear();
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataAcrossLastBlockAndFillCapacity) {
  std::string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full with 'a'.
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  size_t read;
  EXPECT_THAT(buffer_->Readv(&iov, 1, &read, &error_details_), IsQuicNoError());
  EXPECT_EQ(source.size(), written_);

  // Write more than half block size of bytes in the last block with 'b', which
  // will wrap to the beginning and reaches the full capacity.
  source = std::string(0.5 * kBlockSizeBytes + 512, 'b');
  EXPECT_THAT(buffer_->OnStreamData(2 * kBlockSizeBytes, source, &written_,
                                    &error_details_),
              IsQuicNoError());
  EXPECT_EQ(source.size(), written_);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataAcrossLastBlockAndExceedCapacity) {
  std::string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full.
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  size_t read;
  EXPECT_THAT(buffer_->Readv(&iov, 1, &read, &error_details_), IsQuicNoError());

  // Try to write from [max_capacity_bytes_ - 0.5 * kBlockSizeBytes,
  // max_capacity_bytes_ +  512 + 1). But last bytes exceeds current capacity.
  source = std::string(0.5 * kBlockSizeBytes + 512 + 1, 'b');
  EXPECT_THAT(buffer_->OnStreamData(8 * kBlockSizeBytes, source, &written_,
                                    &error_details_),
              IsError(QUIC_INTERNAL_ERROR));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvAcrossLastBlock) {
  // Write to full capacity and read out 512 bytes at beginning and continue
  // appending 256 bytes.
  std::string source(max_capacity_bytes_, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[512]{0};
  const iovec iov{dest, 512};
  size_t read;
  EXPECT_THAT(buffer_->Readv(&iov, 1, &read, &error_details_), IsQuicNoError());
  source = std::string(256, 'b');
  buffer_->OnStreamData(max_capacity_bytes_, source, &written_,
                        &error_details_);
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  // Read all data out.
  std::unique_ptr<char[]> dest1{new char[max_capacity_bytes_]};
  dest1[0] = 0;
  const iovec iov1{dest1.get(), max_capacity_bytes_};
  EXPECT_THAT(buffer_->Readv(&iov1, 1, &read, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(max_capacity_bytes_ - 512 + 256, read);
  EXPECT_EQ(max_capacity_bytes_ + 256, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvEmpty) {
  char dest[512]{0};
  iovec iov{dest, 512};
  size_t read;
  EXPECT_THAT(buffer_->Readv(&iov, 1, &read, &error_details_), IsQuicNoError());
  EXPECT_EQ(0u, read);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsEmpty) {
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(0, iov_count);
  EXPECT_EQ(nullptr, iovs[iov_count].iov_base);
  EXPECT_EQ(0u, iovs[iov_count].iov_len);
}

TEST_F(QuicStreamSequencerBufferTest, ReleaseWholeBuffer) {
  // Tests that buffer is not deallocated unless ReleaseWholeBuffer() is called.
  std::string source(100, 'b');
  // Write something into [0, 100).
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  EXPECT_TRUE(buffer_->HasBytesToRead());
  char dest[120];
  iovec iovecs[3]{iovec{dest, 40}, iovec{dest + 40, 40}, iovec{dest + 80, 40}};
  size_t read;
  EXPECT_THAT(buffer_->Readv(iovecs, 3, &read, &error_details_),
              IsQuicNoError());
  EXPECT_EQ(100u, read);
  EXPECT_EQ(100u, buffer_->BytesConsumed());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_TRUE(helper_->IsBufferAllocated());
  buffer_->ReleaseWholeBuffer();
  EXPECT_FALSE(helper_->IsBufferAllocated());
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsBlockedByGap) {
  // Write into [1, 1024).
  std::string source(1023, 'a');
  buffer_->OnStreamData(1, source, &written_, &error_details_);
  // Try to get readable regions, but none is there.
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(0, iov_count);
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsTillEndOfBlock) {
  // Write first block to full with [0, 256) 'a' and the rest 'b' then read out
  // [0, 256)
  std::string source(kBlockSizeBytes, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(1, iov_count);
  EXPECT_EQ(std::string(kBlockSizeBytes - 256, 'a'),
            IovecToStringPiece(iovs[0]));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsWithinOneBlock) {
  // Write into [0, 1024) and then read out [0, 256)
  std::string source(1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(1, iov_count);
  EXPECT_EQ(std::string(1024 - 256, 'a'), IovecToStringPiece(iovs[0]));
}

TEST_F(QuicStreamSequencerBufferTest,
       GetReadableRegionsAcrossBlockWithLongIOV) {
  // Write into [0, 2 * kBlockSizeBytes + 1024) and then read out [0, 1024)
  std::string source(2 * kBlockSizeBytes + 1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);

  iovec iovs[4];
  int iov_count = buffer_->GetReadableRegions(iovs, 4);
  EXPECT_EQ(3, iov_count);
  EXPECT_EQ(kBlockSizeBytes - 1024, iovs[0].iov_len);
  EXPECT_EQ(kBlockSizeBytes, iovs[1].iov_len);
  EXPECT_EQ(1024u, iovs[2].iov_len);
}

TEST_F(QuicStreamSequencerBufferTest,
       GetReadableRegionsWithMultipleIOVsAcrossEnd) {
  // Write into [0, 8.5 * kBlockSizeBytes - 1024) and then read out [0, 1024)
  // and then append 1024 + 512 bytes.
  std::string source(8.5 * kBlockSizeBytes - 1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  // Write across the end.
  source = std::string(1024 + 512, 'b');
  buffer_->OnStreamData(8.5 * kBlockSizeBytes - 1024, source, &written_,
                        &error_details_);
  // Use short iovec's.
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(2, iov_count);
  EXPECT_EQ(kBlockSizeBytes - 1024, iovs[0].iov_len);
  EXPECT_EQ(kBlockSizeBytes, iovs[1].iov_len);
  // Use long iovec's and wrap the end of buffer.
  iovec iovs1[11];
  EXPECT_EQ(10, buffer_->GetReadableRegions(iovs1, 11));
  EXPECT_EQ(0.5 * kBlockSizeBytes, iovs1[8].iov_len);
  EXPECT_EQ(512u, iovs1[9].iov_len);
  EXPECT_EQ(std::string(512, 'b'), IovecToStringPiece(iovs1[9]));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionEmpty) {
  iovec iov;
  EXPECT_FALSE(buffer_->GetReadableRegion(&iov));
  EXPECT_EQ(nullptr, iov.iov_base);
  EXPECT_EQ(0u, iov.iov_len);
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionBeforeGap) {
  // Write into [1, 1024).
  std::string source(1023, 'a');
  buffer_->OnStreamData(1, source, &written_, &error_details_);
  // GetReadableRegion should return false because range  [0,1) hasn't been
  // filled yet.
  iovec iov;
  EXPECT_FALSE(buffer_->GetReadableRegion(&iov));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionTillEndOfBlock) {
  // Write into [0, kBlockSizeBytes + 1) and then read out [0, 256)
  std::string source(kBlockSizeBytes + 1, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iov;
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov));
  EXPECT_EQ(std::string(kBlockSizeBytes - 256, 'a'), IovecToStringPiece(iov));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionTillGap) {
  // Write into [0, kBlockSizeBytes - 1) and then read out [0, 256)
  std::string source(kBlockSizeBytes - 1, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1023)
  iovec iov;
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov));
  EXPECT_EQ(std::string(kBlockSizeBytes - 1 - 256, 'a'),
            IovecToStringPiece(iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekEmptyBuffer) {
  iovec iov;
  EXPECT_FALSE(buffer_->PeekRegion(0, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(1, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(100, &iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekSingleBlock) {
  std::string source(kBlockSizeBytes, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source, IovecToStringPiece(iov));

  // Peeking again gives the same result.
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source, IovecToStringPiece(iov));

  // Peek at a different offset.
  EXPECT_TRUE(buffer_->PeekRegion(100, &iov));
  EXPECT_EQ(absl::string_view(source).substr(100), IovecToStringPiece(iov));

  // Peeking at or after FirstMissingByte() returns false.
  EXPECT_FALSE(buffer_->PeekRegion(kBlockSizeBytes, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(kBlockSizeBytes + 1, &iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekTwoWritesInSingleBlock) {
  const size_t length1 = 1024;
  std::string source1(length1, 'a');
  buffer_->OnStreamData(0, source1, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));

  // The second frame goes into the same block.
  const size_t length2 = 800;
  std::string source2(length2, 'b');
  buffer_->OnStreamData(length1, source2, &written_, &error_details_);

  EXPECT_TRUE(buffer_->PeekRegion(length1, &iov));
  EXPECT_EQ(source2, IovecToStringPiece(iov));

  // Peek with an offset inside the first write.
  const QuicStreamOffset offset1 = 500;
  EXPECT_TRUE(buffer_->PeekRegion(offset1, &iov));
  EXPECT_EQ(absl::string_view(source1).substr(offset1),
            IovecToStringPiece(iov).substr(0, length1 - offset1));
  EXPECT_EQ(absl::string_view(source2),
            IovecToStringPiece(iov).substr(length1 - offset1));

  // Peek with an offset inside the second write.
  const QuicStreamOffset offset2 = 1500;
  EXPECT_TRUE(buffer_->PeekRegion(offset2, &iov));
  EXPECT_EQ(absl::string_view(source2).substr(offset2 - length1),
            IovecToStringPiece(iov));

  // Peeking at or after FirstMissingByte() returns false.
  EXPECT_FALSE(buffer_->PeekRegion(length1 + length2, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(length1 + length2 + 1, &iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekBufferWithMultipleBlocks) {
  const size_t length1 = 1024;
  std::string source1(length1, 'a');
  buffer_->OnStreamData(0, source1, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));

  const size_t length2 = kBlockSizeBytes + 2;
  std::string source2(length2, 'b');
  buffer_->OnStreamData(length1, source2, &written_, &error_details_);

  // Peek with offset 0 returns the entire block.
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(kBlockSizeBytes, iov.iov_len);
  EXPECT_EQ(source1, IovecToStringPiece(iov).substr(0, length1));
  EXPECT_EQ(absl::string_view(source2).substr(0, kBlockSizeBytes - length1),
            IovecToStringPiece(iov).substr(length1));

  EXPECT_TRUE(buffer_->PeekRegion(length1, &iov));
  EXPECT_EQ(absl::string_view(source2).substr(0, kBlockSizeBytes - length1),
            IovecToStringPiece(iov));

  EXPECT_TRUE(buffer_->PeekRegion(kBlockSizeBytes, &iov));
  EXPECT_EQ(absl::string_view(source2).substr(kBlockSizeBytes - length1),
            IovecToStringPiece(iov));

  // Peeking at or after FirstMissingByte() returns false.
  EXPECT_FALSE(buffer_->PeekRegion(length1 + length2, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(length1 + length2 + 1, &iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekAfterConsumed) {
  std::string source1(kBlockSizeBytes, 'a');
  buffer_->OnStreamData(0, source1, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));

  // Consume some data.
  EXPECT_TRUE(buffer_->MarkConsumed(1024));

  // Peeking into consumed data fails.
  EXPECT_FALSE(buffer_->PeekRegion(0, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(512, &iov));

  EXPECT_TRUE(buffer_->PeekRegion(1024, &iov));
  EXPECT_EQ(absl::string_view(source1).substr(1024), IovecToStringPiece(iov));

  EXPECT_TRUE(buffer_->PeekRegion(1500, &iov));
  EXPECT_EQ(absl::string_view(source1).substr(1500), IovecToStringPiece(iov));

  // Consume rest of block.
  EXPECT_TRUE(buffer_->MarkConsumed(kBlockSizeBytes - 1024));

  // Read new data.
  std::string source2(300, 'b');
  buffer_->OnStreamData(kBlockSizeBytes, source2, &written_, &error_details_);

  // Peek into new data.
  EXPECT_TRUE(buffer_->PeekRegion(kBlockSizeBytes, &iov));
  EXPECT_EQ(source2, IovecToStringPiece(iov));

  EXPECT_TRUE(buffer_->PeekRegion(kBlockSizeBytes + 128, &iov));
  EXPECT_EQ(absl::string_view(source2).substr(128), IovecToStringPiece(iov));

  // Peeking into consumed data still fails.
  EXPECT_FALSE(buffer_->PeekRegion(0, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(512, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(1024, &iov));
  EXPECT_FALSE(buffer_->PeekRegion(1500, &iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekContinously) {
  std::string source1(kBlockSizeBytes, 'a');
  buffer_->OnStreamData(0, source1, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));

  std::string source2(kBlockSizeBytes, 'b');
  buffer_->OnStreamData(kBlockSizeBytes, source2, &written_, &error_details_);

  EXPECT_TRUE(buffer_->PeekRegion(kBlockSizeBytes, &iov));
  EXPECT_EQ(source2, IovecToStringPiece(iov));

  // First block is still there.
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));
}

TEST_F(QuicStreamSequencerBufferTest, PeekRegionWithBufferWrapsAround) {
  ResetMaxCapacityBytes(kBlockSizeBytes * 8);
  std::string source1(kBlockSizeBytes, 'a');
  buffer_->OnStreamData(0, source1, &written_, &error_details_);

  iovec iov;
  EXPECT_TRUE(buffer_->PeekRegion(0, &iov));
  EXPECT_EQ(source1, IovecToStringPiece(iov));
  // Consume half of the block.
  size_t consumed_bytes = kBlockSizeBytes - 4 * 1024;
  buffer_->MarkConsumed(consumed_bytes);

  // Buffer much more data so that the last bytes are stored into the start of
  // the first block, which also contains the first unread bytes.
  std::string source2(max_capacity_bytes_ - 4 * 1024 - 1, 'b');
  buffer_->OnStreamData(kBlockSizeBytes, source2, &written_, &error_details_);
  EXPECT_EQ(max_capacity_bytes_ - 1, buffer_->ReadableBytes());

  EXPECT_TRUE(buffer_->PeekRegion(consumed_bytes, &iov));
  EXPECT_EQ(std::string(4 * 1024, 'a'), IovecToStringPiece(iov));
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedInOneBlock) {
  // Write into [0, 1024) and then read out [0, 256)
  std::string source(1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);

  EXPECT_TRUE(buffer_->MarkConsumed(512));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  EXPECT_EQ(256u, helper_->ReadableBytes());
  buffer_->MarkConsumed(256);
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedNotEnoughBytes) {
  // Write into [0, 1024) and then read out [0, 256)
  std::string source(1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);

  // Consume 1st 512 bytes
  EXPECT_TRUE(buffer_->MarkConsumed(512));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  EXPECT_EQ(256u, helper_->ReadableBytes());
  // Try to consume one bytes more than available. Should return false.
  EXPECT_FALSE(buffer_->MarkConsumed(257));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  iovec iov;
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedAcrossBlock) {
  // Write into [0, 2 * kBlockSizeBytes + 1024) and then read out [0, 1024)
  std::string source(2 * kBlockSizeBytes + 1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);

  buffer_->MarkConsumed(2 * kBlockSizeBytes);
  EXPECT_EQ(source.size(), buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedAcrossEnd) {
  // Write into [0, 8.5 * kBlockSizeBytes - 1024) and then read out [0, 1024)
  // and then append 1024 + 512 bytes.
  std::string source(8.5 * kBlockSizeBytes - 1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  source = std::string(1024 + 512, 'b');
  buffer_->OnStreamData(8.5 * kBlockSizeBytes - 1024, source, &written_,
                        &error_details_);
  EXPECT_EQ(1024u, buffer_->BytesConsumed());

  // Consume to the end of 8th block.
  buffer_->MarkConsumed(8 * kBlockSizeBytes - 1024);
  EXPECT_EQ(8 * kBlockSizeBytes, buffer_->BytesConsumed());
  // Consume across the physical end of buffer
  buffer_->MarkConsumed(0.5 * kBlockSizeBytes + 500);
  EXPECT_EQ(max_capacity_bytes_ + 500, buffer_->BytesConsumed());
  EXPECT_EQ(12u, helper_->ReadableBytes());
  // Consume to the logical end of buffer
  buffer_->MarkConsumed(12);
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, FlushBuff
"""


```