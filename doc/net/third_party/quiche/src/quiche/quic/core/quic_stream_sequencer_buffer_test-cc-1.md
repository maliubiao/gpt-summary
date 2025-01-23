Response:
The user is asking for the functionality of the provided C++ code snippet, which is part of a test file for `QuicStreamSequencerBuffer` in Chromium's QUIC implementation.

Here's a breakdown of the thought process:

1. **Identify the Core Class Under Test:** The filename `quic_stream_sequencer_buffer_test.cc` and the class name `QuicStreamSequencerBufferTest` clearly indicate that the code tests the `QuicStreamSequencerBuffer` class.

2. **Understand the Purpose of `QuicStreamSequencerBuffer`:** Based on the name, it likely deals with buffering and sequencing incoming stream data in the QUIC protocol. This involves handling out-of-order data, managing gaps, and providing mechanisms to read data in the correct sequence.

3. **Analyze Individual Test Cases:** Examine each `TEST_F` function to understand its specific focus:

    * `FlushLargeMergedFrame`: Tests the ability to handle a large, contiguous frame of data, ensuring it can be written and read correctly.
    * `FlushSplitFrame`: Tests the scenario where a frame of data wraps around the buffer's boundary.
    * `TooManyGaps`: Checks the behavior when an excessive number of non-contiguous data chunks (gaps) are received, simulating a potential denial-of-service attack or highly fragmented data.
    * `QuicStreamSequencerBufferRandomIOTest` (and its tests `RandomWriteAndReadv`, `RandomWriteAndConsumeInPlace`): These tests perform randomized write and read operations to thoroughly exercise the buffer under various conditions, including out-of-order arrival and different read/consume methods.
    * `GrowBlockSizeOnDemand`: Focuses on the buffer's dynamic memory allocation, verifying that it increases the number of internal blocks as needed to accommodate incoming data.

4. **Identify Key Functionality Being Tested:**  From the test cases, extract the core functionalities being validated:

    * **Writing Data (`OnStreamData`):**  Handling both contiguous and fragmented data, including data that wraps around the buffer.
    * **Reading Data (`Read`, `Readv`, `GetReadableRegions`):**  Retrieving buffered data, potentially in multiple chunks.
    * **Consuming Data (`MarkConsumed`):**  Indicating that data has been processed.
    * **Gap Management:** Handling out-of-order data and limiting the number of allowed gaps.
    * **Buffer Management:**  Flushing buffered data, clearing the buffer, and ensuring internal invariants are maintained.
    * **Dynamic Memory Allocation:**  Growing the buffer's internal storage as needed.

5. **Relate to JavaScript (if applicable):** Consider if any of these functionalities have direct parallels in JavaScript's network programming. While JavaScript doesn't have direct access to the low-level buffering of network streams in the same way, concepts like handling out-of-order packets or buffering data for processing are relevant. Think about `ReadableStream` and `WritableStream` APIs, which provide mechanisms for handling data chunks.

6. **Construct Hypothesized Inputs and Outputs:** For each test case, imagine a concrete scenario with example data and the expected behavior of the buffer.

7. **Identify Potential User Errors:** Think about common mistakes developers might make when interacting with a stream buffer, such as writing data beyond capacity or trying to read data that hasn't arrived yet.

8. **Explain Debugging Context:** Describe how a developer might end up looking at this code, such as when investigating stream processing issues or performance problems related to buffering.

9. **Synthesize the Summary:** Combine the observations from the individual test cases into a concise overview of the file's purpose.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:** Shift focus to the *functionality* being tested, as requested by the prompt. While the C++ code provides the implementation, the user wants to understand what the tests *verify*.
* **Initial thought:**  Overlook the JavaScript connection.
* **Correction:**  Actively look for conceptual similarities, even if the implementation is different. The core ideas of handling stream data are transferable.
* **Initial thought:**  Provide very technical input/output examples.
* **Correction:**  Keep the examples simple and illustrative, focusing on the high-level behavior.

By following these steps, the generated response accurately reflects the purpose of the code, provides relevant examples, and addresses the user's specific requests.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer_buffer_test.cc` 文件的第二部分，它继续对 `QuicStreamSequencerBuffer` 类进行单元测试。

**归纳一下它的功能:**

这部分代码主要关注 `QuicStreamSequencerBuffer` 在以下方面的功能测试：

* **处理跨越 buffer 边界的数据帧:**  `FlushSplitFrame` 测试了当一个数据帧的起始位置接近 buffer 尾部，导致数据需要环绕到 buffer 开头写入的情况。
* **限制数据帧的碎片数量 (Gaps):** `TooManyGaps` 测试了当接收到过多的不连续数据帧时，buffer 是否能够正确地检测并返回错误，防止潜在的资源耗尽或攻击。
* **随机写入和读取 (通过 `QuicStreamSequencerBufferRandomIOTest`):**
    *  通过随机生成数据块的大小和顺序，模拟真实网络中乱序到达的数据。
    *  `RandomWriteAndReadv` 测试了在随机写入数据后，使用 `Readv` 方法进行读取，验证数据是否被正确缓冲和读取。
    *  `RandomWriteAndConsumeInPlace` 测试了在随机写入数据后，使用 `GetReadableRegions` 获取可读区域，并使用 `MarkConsumed` 标记已消费的数据，验证了原地消费数据的能力。
* **动态调整内部 block 大小:** `GrowBlockSizeOnDemand` 测试了 buffer 在接收更多数据时，能否根据需要动态增加内部存储 block 的数量，提高效率并避免固定大小限制。

**与 JavaScript 功能的关系 (更间接):**

虽然这段 C++ 代码直接关联的是 Chromium 网络栈的底层实现，与 JavaScript 的直接功能没有明显的联系，但其测试的逻辑概念在 JavaScript 的网络编程中也有所体现：

* **数据缓冲和排序:**  在处理 WebSocket 或 Fetch API 返回的流式数据时，JavaScript 需要处理数据块的接收和排序。虽然 JavaScript 引擎内部的实现不同，但确保数据按序到达并可供消费的逻辑是相似的。
* **流量控制和资源管理:**  限制数据帧的碎片数量可以理解为一种流量控制机制，防止过多的碎片占用资源。在 JavaScript 中，可以通过背压 (backpressure) 等机制来控制数据流的速度，防止内存溢出。
* **动态内存管理:** 虽然 JavaScript 具有自动垃圾回收机制，开发者无需手动管理内存，但在处理大量数据时，了解底层数据结构如何动态扩展是有助于理解性能瓶颈的。

**假设输入与输出 (针对部分测试用例):**

* **`FlushSplitFrame`:**
    * **假设输入:**
        * `max_capacity_bytes_`: 8 * `kBlockSizeBytes`
        * 第一次写入: offset 0，数据大小 `max_capacity_bytes_ - 1024`
        * 第二次写入: offset `max_capacity_bytes_`，数据大小 512
        * 读取: 读取 1024 字节
    * **预期输出:**
        * 第一次写入后，buffer 中填充了 `max_capacity_bytes_ - 1024` 字节的数据。
        * 读取操作成功读取 1024 字节。
        * 第二次写入将 512 字节的数据写入 buffer 的开头位置。
        * `FlushBufferedFrames` 返回合并后的数据大小。
        * `BytesConsumed` 反映已消费的字节数。
        * Buffer 为空。

* **`TooManyGaps`:**
    * **假设输入:**
        * `max_capacity_bytes_`: 3 * `kBlockSizeBytes`
        * 连续写入多个大小为 1 字节，但 offset 间隔为 2 的数据帧 (例如 [1,2), [3,4), [5,6)...)
    * **预期输出:**
        * 当写入的数据帧导致 gaps 数量超过 `kMaxNumGapsAllowed` 时，`OnStreamData` 返回错误 `QUIC_TOO_MANY_STREAM_DATA_INTERVALS`。
        * `error_details_` 包含错误信息 "Too many data intervals received for this stream."

**涉及用户或编程常见的使用错误:**

* **写入超出 buffer 容量的数据:** 虽然 `QuicStreamSequencerBuffer` 具有动态扩展能力，但在极端情况下或配置限制下，写入过多数据可能导致错误或性能问题。
* **读取未到达的数据:**  如果尝试读取的 offset 超出了当前 buffer 中已接收到的最大 offset，可能会导致读取失败或返回不完整的数据。
* **错误地计算或管理 consumed 字节数:**  如果 `MarkConsumed` 的参数不正确，可能会导致数据重复读取或丢失。
* **在高并发场景下未进行适当的同步:**  虽然测试代码没有直接展示并发问题，但在实际应用中，多个线程或协程同时操作 `QuicStreamSequencerBuffer` 需要进行适当的同步，以避免数据竞争和状态不一致。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个 Chromium 开发者，在调试 QUIC 连接的 stream 处理相关问题时，可能会逐步深入到 `QuicStreamSequencerBuffer` 的代码：

1. **发现 stream 数据接收或处理异常:** 用户可能会报告网站加载缓慢、数据传输不完整或连接中断等问题，这些问题可能与 QUIC stream 的处理有关。
2. **定位到 QUIC 层:**  开发者会检查网络日志、QUIC 事件日志等信息，判断问题是否发生在 QUIC 协议层。
3. **追踪 stream 的状态:**  可能会检查 `QuicStream` 对象的状态，包括接收到的数据量、已消费的数据量、是否存在 gaps 等信息。
4. **深入到 `QuicStreamSequencerBuffer`:**  如果怀疑问题与数据的缓冲和排序有关，开发者可能会查看 `QuicStreamSequencerBuffer` 的内部状态，例如已分配的 blocks、gaps 的数量等。
5. **查看相关测试用例:** 为了理解 `QuicStreamSequencerBuffer` 的预期行为和可能出现的边界情况，开发者可能会查看 `quic_stream_sequencer_buffer_test.cc` 中的相关测试用例，例如 `FlushSplitFrame` (处理边界情况), `TooManyGaps` (处理恶意碎片), `RandomWriteAndReadv` (处理乱序数据) 等。
6. **运行或修改测试用例:**  开发者可能会尝试运行相关的测试用例，或者修改测试用例的输入参数，以复现或调试特定的问题场景。
7. **单步调试 `QuicStreamSequencerBuffer` 的代码:**  如果需要更深入的分析，开发者可能会使用调试器单步执行 `QuicStreamSequencerBuffer` 的代码，查看变量的值和程序的执行流程。

总而言之，这部分测试代码专注于验证 `QuicStreamSequencerBuffer` 在处理复杂的数据接收场景下的正确性和健壮性，包括跨越 buffer 边界的数据、大量的碎片数据以及随机的写入和读取操作，同时也测试了其动态内存管理的能力。 开发者可以通过分析这些测试用例来理解 `QuicStreamSequencerBuffer` 的工作原理，并辅助调试相关的 stream 处理问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer_buffer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
eredFrames) {
  // Write into [0, 8.5 * kBlockSizeBytes - 1024) and then read out [0, 1024).
  std::string source(max_capacity_bytes_ - 1024, 'a');
  buffer_->OnStreamData(0, source, &written_, &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  EXPECT_EQ(1024u, buffer_->BytesConsumed());
  // Write [1024, 512) to the physical beginning.
  source = std::string(512, 'b');
  buffer_->OnStreamData(max_capacity_bytes_, source, &written_,
                        &error_details_);
  EXPECT_EQ(512u, written_);
  EXPECT_EQ(max_capacity_bytes_ - 1024 + 512, buffer_->FlushBufferedFrames());
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  // Clear buffer at this point should still preserve BytesConsumed().
  buffer_->Clear();
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, TooManyGaps) {
  // Make sure max capacity is large enough that it is possible to have more
  // than |kMaxNumGapsAllowed| number of gaps.
  max_capacity_bytes_ = 3 * kBlockSizeBytes;
  // Feed buffer with 1-byte discontiguous frames. e.g. [1,2), [3,4), [5,6)...
  for (QuicStreamOffset begin = 1; begin <= max_capacity_bytes_; begin += 2) {
    QuicErrorCode rs =
        buffer_->OnStreamData(begin, "a", &written_, &error_details_);

    QuicStreamOffset last_straw = 2 * kMaxNumGapsAllowed - 1;
    if (begin == last_straw) {
      EXPECT_THAT(rs, IsError(QUIC_TOO_MANY_STREAM_DATA_INTERVALS));
      EXPECT_EQ("Too many data intervals received for this stream.",
                error_details_);
      break;
    }
  }
}

class QuicStreamSequencerBufferRandomIOTest
    : public QuicStreamSequencerBufferTest {
 public:
  using OffsetSizePair = std::pair<QuicStreamOffset, size_t>;

  void SetUp() override {
    // Test against a larger capacity then above tests. Also make sure the last
    // block is partially available to use.
    max_capacity_bytes_ = 8.25 * kBlockSizeBytes;
    // Stream to be buffered should be larger than the capacity to test wrap
    // around.
    bytes_to_buffer_ = 2 * max_capacity_bytes_;
    Initialize();

    uint64_t seed = QuicRandom::GetInstance()->RandUint64();
    QUIC_LOG(INFO) << "**** The current seed is " << seed << " ****";
    rng_.set_seed(seed);
  }

  // Create an out-of-order source stream with given size to populate
  // shuffled_buf_.
  void CreateSourceAndShuffle(size_t max_chunk_size_bytes) {
    max_chunk_size_bytes_ = max_chunk_size_bytes;
    std::unique_ptr<OffsetSizePair[]> chopped_stream(
        new OffsetSizePair[bytes_to_buffer_]);

    // Split stream into small chunks with random length. chopped_stream will be
    // populated with segmented stream chunks.
    size_t start_chopping_offset = 0;
    size_t iterations = 0;
    while (start_chopping_offset < bytes_to_buffer_) {
      size_t max_chunk = std::min<size_t>(
          max_chunk_size_bytes_, bytes_to_buffer_ - start_chopping_offset);
      size_t chunk_size = rng_.RandUint64() % max_chunk + 1;
      chopped_stream[iterations] =
          OffsetSizePair(start_chopping_offset, chunk_size);
      start_chopping_offset += chunk_size;
      ++iterations;
    }
    QUICHE_DCHECK(start_chopping_offset == bytes_to_buffer_);
    size_t chunk_num = iterations;

    // Randomly change the sequence of in-ordered OffsetSizePairs to make a
    // out-of-order array of OffsetSizePairs.
    for (int i = chunk_num - 1; i >= 0; --i) {
      size_t random_idx = rng_.RandUint64() % (i + 1);
      QUIC_DVLOG(1) << "chunk offset " << chopped_stream[random_idx].first
                    << " size " << chopped_stream[random_idx].second;
      shuffled_buf_.push_front(chopped_stream[random_idx]);
      chopped_stream[random_idx] = chopped_stream[i];
    }
  }

  // Write the currently first chunk of data in the out-of-order stream into
  // QuicStreamSequencerBuffer. If current chuck cannot be written into buffer
  // because it goes beyond current capacity, move it to the end of
  // shuffled_buf_ and write it later.
  void WriteNextChunkToBuffer() {
    OffsetSizePair& chunk = shuffled_buf_.front();
    QuicStreamOffset offset = chunk.first;
    const size_t num_to_write = chunk.second;
    std::unique_ptr<char[]> write_buf{new char[max_chunk_size_bytes_]};
    for (size_t i = 0; i < num_to_write; ++i) {
      write_buf[i] = (offset + i) % 256;
    }
    absl::string_view string_piece_w(write_buf.get(), num_to_write);
    auto result = buffer_->OnStreamData(offset, string_piece_w, &written_,
                                        &error_details_);
    if (result == QUIC_NO_ERROR) {
      shuffled_buf_.pop_front();
      total_bytes_written_ += num_to_write;
    } else {
      // This chunk offset exceeds window size.
      shuffled_buf_.push_back(chunk);
      shuffled_buf_.pop_front();
    }
    QUIC_DVLOG(1) << " write at offset: " << offset
                  << " len to write: " << num_to_write
                  << " write result: " << result
                  << " left over: " << shuffled_buf_.size();
  }

 protected:
  std::list<OffsetSizePair> shuffled_buf_;
  size_t max_chunk_size_bytes_;
  QuicStreamOffset bytes_to_buffer_;
  size_t total_bytes_written_ = 0;
  size_t total_bytes_read_ = 0;
  SimpleRandom rng_;
};

TEST_F(QuicStreamSequencerBufferRandomIOTest, RandomWriteAndReadv) {
  // Set kMaxReadSize larger than kBlockSizeBytes to test both small and large
  // read.
  const size_t kMaxReadSize = kBlockSizeBytes * 2;
  // kNumReads is larger than 1 to test how multiple read destinations work.
  const size_t kNumReads = 2;
  // Since write and read operation have equal possibility to be called. Bytes
  // to be written into and read out of should roughly the same.
  const size_t kMaxWriteSize = kNumReads * kMaxReadSize;
  size_t iterations = 0;

  CreateSourceAndShuffle(kMaxWriteSize);

  while ((!shuffled_buf_.empty() || total_bytes_read_ < bytes_to_buffer_) &&
         iterations <= 2 * bytes_to_buffer_) {
    uint8_t next_action =
        shuffled_buf_.empty() ? uint8_t{1} : rng_.RandUint64() % 2;
    QUIC_DVLOG(1) << "iteration: " << iterations;
    switch (next_action) {
      case 0: {  // write
        WriteNextChunkToBuffer();
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
      case 1: {  // readv
        std::unique_ptr<char[][kMaxReadSize]> read_buf{
            new char[kNumReads][kMaxReadSize]};
        iovec dest_iov[kNumReads];
        size_t num_to_read = 0;
        for (size_t i = 0; i < kNumReads; ++i) {
          dest_iov[i].iov_base =
              reinterpret_cast<void*>(const_cast<char*>(read_buf[i]));
          dest_iov[i].iov_len = rng_.RandUint64() % kMaxReadSize;
          num_to_read += dest_iov[i].iov_len;
        }
        size_t actually_read;
        EXPECT_THAT(buffer_->Readv(dest_iov, kNumReads, &actually_read,
                                   &error_details_),
                    IsQuicNoError());
        ASSERT_LE(actually_read, num_to_read);
        QUIC_DVLOG(1) << " read from offset: " << total_bytes_read_
                      << " size: " << num_to_read
                      << " actual read: " << actually_read;
        for (size_t i = 0; i < actually_read; ++i) {
          char ch = (i + total_bytes_read_) % 256;
          ASSERT_EQ(ch, GetCharFromIOVecs(i, dest_iov, kNumReads))
              << " at iteration " << iterations;
        }
        total_bytes_read_ += actually_read;
        ASSERT_EQ(total_bytes_read_, buffer_->BytesConsumed());
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
    }
    ++iterations;
    ASSERT_LE(total_bytes_read_, total_bytes_written_);
  }
  EXPECT_LT(iterations, bytes_to_buffer_) << "runaway test";
  EXPECT_LE(bytes_to_buffer_, total_bytes_read_)
      << "iterations: " << iterations;
  EXPECT_LE(bytes_to_buffer_, total_bytes_written_);
}

TEST_F(QuicStreamSequencerBufferRandomIOTest, RandomWriteAndConsumeInPlace) {
  // The value 4 is chosen such that the max write size is no larger than the
  // maximum buffer capacity.
  const size_t kMaxNumReads = 4;
  // Adjust write amount be roughly equal to that GetReadableRegions() can get.
  const size_t kMaxWriteSize = kMaxNumReads * kBlockSizeBytes;
  ASSERT_LE(kMaxWriteSize, max_capacity_bytes_);
  size_t iterations = 0;

  CreateSourceAndShuffle(kMaxWriteSize);

  while ((!shuffled_buf_.empty() || total_bytes_read_ < bytes_to_buffer_) &&
         iterations <= 2 * bytes_to_buffer_) {
    uint8_t next_action =
        shuffled_buf_.empty() ? uint8_t{1} : rng_.RandUint64() % 2;
    QUIC_DVLOG(1) << "iteration: " << iterations;
    switch (next_action) {
      case 0: {  // write
        WriteNextChunkToBuffer();
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
      case 1: {  // GetReadableRegions and then MarkConsumed
        size_t num_read = rng_.RandUint64() % kMaxNumReads + 1;
        iovec dest_iov[kMaxNumReads];
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        size_t actually_num_read =
            buffer_->GetReadableRegions(dest_iov, num_read);
        ASSERT_LE(actually_num_read, num_read);
        size_t avail_bytes = 0;
        for (size_t i = 0; i < actually_num_read; ++i) {
          avail_bytes += dest_iov[i].iov_len;
        }
        // process random number of bytes (check the value of each byte).
        size_t bytes_to_process = rng_.RandUint64() % (avail_bytes + 1);
        size_t bytes_processed = 0;
        for (size_t i = 0; i < actually_num_read; ++i) {
          size_t bytes_in_block = std::min<size_t>(
              bytes_to_process - bytes_processed, dest_iov[i].iov_len);
          if (bytes_in_block == 0) {
            break;
          }
          for (size_t j = 0; j < bytes_in_block; ++j) {
            ASSERT_LE(bytes_processed, bytes_to_process);
            char char_expected =
                (buffer_->BytesConsumed() + bytes_processed) % 256;
            ASSERT_EQ(char_expected,
                      reinterpret_cast<const char*>(dest_iov[i].iov_base)[j])
                << " at iteration " << iterations;
            ++bytes_processed;
          }
        }

        buffer_->MarkConsumed(bytes_processed);

        QUIC_DVLOG(1) << "iteration " << iterations << ": try to get "
                      << num_read << " readable regions, actually get "
                      << actually_num_read
                      << " from offset: " << total_bytes_read_
                      << "\nprocesse bytes: " << bytes_processed;
        total_bytes_read_ += bytes_processed;
        ASSERT_EQ(total_bytes_read_, buffer_->BytesConsumed());
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
    }
    ++iterations;
    ASSERT_LE(total_bytes_read_, total_bytes_written_);
  }
  EXPECT_LT(iterations, bytes_to_buffer_) << "runaway test";
  EXPECT_LE(bytes_to_buffer_, total_bytes_read_)
      << "iterations: " << iterations;
  EXPECT_LE(bytes_to_buffer_, total_bytes_written_);
}

TEST_F(QuicStreamSequencerBufferTest, GrowBlockSizeOnDemand) {
  max_capacity_bytes_ = 1024 * kBlockSizeBytes;
  std::string source_of_one_block(kBlockSizeBytes, 'a');
  Initialize();

  ASSERT_EQ(helper_->current_blocks_count(), 0u);

  // A minimum of 8 blocks are allocated
  buffer_->OnStreamData(0, source_of_one_block, &written_, &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 8u);

  // Number of blocks doesn't grow if the data is within the capacity.
  buffer_->OnStreamData(kBlockSizeBytes * 7, source_of_one_block, &written_,
                        &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 8u);

  // Number of blocks grows by a factor of 4 normally.
  buffer_->OnStreamData(kBlockSizeBytes * 8, "a", &written_, &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 32u);

  // Number of blocks grow to the demanded size of 140 instead of 128 since
  // that's not enough.
  buffer_->OnStreamData(kBlockSizeBytes * 139, source_of_one_block, &written_,
                        &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 140u);

  // Number of blocks grows by a factor of 4 normally.
  buffer_->OnStreamData(kBlockSizeBytes * 140, source_of_one_block, &written_,
                        &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 560u);

  // max_capacity_bytes is reached and number of blocks is capped.
  buffer_->OnStreamData(kBlockSizeBytes * 560, source_of_one_block, &written_,
                        &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 1024u);

  // max_capacity_bytes is reached and number of blocks is capped.
  buffer_->OnStreamData(kBlockSizeBytes * 1025, source_of_one_block, &written_,
                        &error_details_);
  ASSERT_EQ(helper_->current_blocks_count(), 1024u);
}

}  // anonymous namespace

}  // namespace test

}  // namespace quic
```