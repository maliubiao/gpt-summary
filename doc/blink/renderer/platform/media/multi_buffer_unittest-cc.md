Response: Let's break down the thought process for analyzing the provided C++ code and generating the response.

1. **Understand the Goal:** The request asks for the functionality of the given C++ file (`multi_buffer_unittest.cc`), its relation to web technologies (JavaScript, HTML, CSS), examples with input/output, and common usage errors.

2. **Initial Scan and Keywords:** Quickly skim the code for important keywords and class names. I see: `MultiBuffer`, `MultiBufferReader`, `FakeMultiBufferDataProvider`, `LRU`, `testing::Test`, `EXPECT_EQ`, `Advance`, `Read`, `Seek`, `SetPinRange`, `SetPreload`. These give strong hints about the file's purpose.

3. **Identify the Core Functionality:** The presence of `*_unittest.cc` strongly suggests this is a unit test file. It's testing the `MultiBuffer` class. The `FakeMultiBufferDataProvider` likely simulates data sources for the `MultiBuffer`. The `MultiBufferReader` is probably the class used to access data from the `MultiBuffer`. The LRU mentions suggest a Least Recently Used cache is involved.

4. **Focus on `MultiBuffer` and its Dependencies:**
    * **`MultiBuffer`:** This is the central class being tested. Its purpose seems to be managing a buffer of data, likely for media. The `shift` parameter in the constructor and `kBlockSize` suggest it deals with data in blocks. The `GlobalLRU` indicates a caching mechanism to manage memory.
    * **`FakeMultiBufferDataProvider`:**  This class simulates providing data to the `MultiBuffer`. It reads data block by block and can be told to "defer" providing data. This is important for testing asynchronous data loading scenarios. The data it provides is procedurally generated based on the block position.
    * **`MultiBufferReader`:**  This class allows reading data from the `MultiBuffer`. It supports `Read`, `Seek`, `SetPinRange`, and `SetPreload`. These methods are common for accessing media data. `SetPinRange` likely prevents certain parts of the buffer from being evicted by the LRU. `SetPreload` probably triggers pre-fetching of data.
    * **`GlobalLRU`:** This class implements the Least Recently Used caching strategy for the `MultiBuffer`. It manages the eviction of less frequently used blocks to conserve memory.

5. **Analyze the Tests:** Go through each `TEST_F` function to understand what specific aspects of `MultiBuffer` are being tested:
    * **`ReadAll` and `ReadAllAdvanceFirst`:** Test basic reading of data from the buffer, ensuring the correct data is read. `ReadAllAdvanceFirst` explicitly advances the data provider, simulating asynchronous loading.
    * **`ReadAllAdvanceFirst_NeverDefer` and `ReadAllAdvanceFirst_NeverDefer2`:** Test the behavior when a data provider provides too much data after being told to defer, and how the `RangeSupported` flag affects this.
    * **`LRUTest` and `LRUTest2`:** Focus on the Least Recently Used cache functionality, including setting the maximum size, pruning, and freeing memory.
    * **`LRUTestExpirationTest`:** Specifically tests the time-based expiration of LRU entries.
    * **`RandomTest` and `RandomTest_RangeSupported`:** These are more complex tests involving multiple readers, random reads, seeks, and data provider advancements. They thoroughly test the `MultiBuffer` under various conditions.

6. **Relate to Web Technologies:** Think about how the functionality of `MultiBuffer` could be relevant in a browser context:
    * **JavaScript:**  JavaScript media APIs (like `<video>` and `<audio>`) could internally use a mechanism similar to `MultiBuffer` to manage media data downloaded from the network. JavaScript might trigger preloading or seeking operations that interact with the `MultiBuffer`.
    * **HTML:** The `<video>` and `<audio>` elements in HTML are the user-facing entry points for media. The `MultiBuffer` likely works behind the scenes to provide the data these elements need.
    * **CSS:** CSS doesn't directly interact with the data buffering. However, CSS styling can affect the appearance of the media controls or the loading indicators, which indirectly relate to the buffering process.

7. **Construct Input/Output Examples:**  Choose a simple test case (like `ReadAll`) and create hypothetical scenarios. Define the initial state (file size, starting position) and the actions (reading data). Show what the expected output (the read data) would be.

8. **Identify Common Usage Errors:**  Think about potential mistakes developers could make when using a system like `MultiBuffer` (even though this is a unit test, it reflects the design of the real class):
    * Incorrectly setting the pin range.
    * Not handling asynchronous loading correctly.
    * Issues with seeking or reading beyond the available data.

9. **Structure the Response:** Organize the findings into logical sections as requested: functionality, relation to web technologies, input/output examples, and common errors. Use clear and concise language.

10. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Check if all aspects of the request have been addressed. For example, initially, I might focus too much on the technical details and forget to explicitly link it back to user-facing web technologies. Reviewing helps catch such omissions. Also, verify that the examples make sense and the assumptions are clear.
This C++ file, `multi_buffer_unittest.cc`, contains unit tests for the `MultiBuffer` class in the Chromium Blink rendering engine. `MultiBuffer` is likely a component responsible for efficiently managing and caching media data (like audio or video) fetched from a network or local source. The "multi-buffer" name suggests it deals with data in chunks or blocks.

Here's a breakdown of its functionality based on the tests:

**Core Functionality Being Tested:**

1. **Data Buffering and Caching:**
   - **Storing Data Blocks:** The tests demonstrate the ability of `MultiBuffer` to store and retrieve data blocks. The `FakeMultiBufferDataProvider` simulates providing these blocks.
   - **LRU (Least Recently Used) Caching:** The tests extensively use `MultiBuffer::GlobalLRU`, indicating that `MultiBuffer` uses an LRU cache to manage memory. It evicts less recently used data blocks when memory is limited.
   - **Pinning Data:** The `MultiBufferReader::SetPinRange` function suggests the ability to "pin" certain ranges of data in the buffer, preventing them from being evicted by the LRU. This is likely used for data that is currently being played or is needed imminently.
   - **Preloading Data:** `MultiBufferReader::SetPreload` indicates the capability to proactively load data ahead of the current playback position.

2. **Data Reading and Access:**
   - **`MultiBufferReader`:**  This class is the primary way to read data from the `MultiBuffer`. Tests use its `TryRead` method to fetch data.
   - **Seeking:** The `MultiBufferReader::Seek` method is tested, demonstrating the ability to move the read position within the buffered data.
   - **Asynchronous Data Loading:** The `FakeMultiBufferDataProvider` and the `Advance` methods simulate asynchronous data loading. The tests check how `MultiBuffer` handles situations where data isn't immediately available.
   - **Handling End-of-Stream (EOS):** The `FakeMultiBufferDataProvider` creates an EOS buffer, suggesting that `MultiBuffer` can handle the end of the data stream.

3. **Data Provider Management:**
   - **Creating Data Providers:** The `CreateWriter` method (overridden in `TestMultiBuffer`) indicates how `MultiBuffer` interacts with data sources.
   - **Deferred Data Provision:** The `SetDeferred` method in `FakeMultiBufferDataProvider` and the related tests explore scenarios where data providers temporarily stop providing data. This could simulate network interruptions or other delays.
   - **Handling Excess Data:** Tests check the behavior when a data provider provides more data than expected after being deferred, and how `MultiBuffer` might react (potentially destroying the provider if range requests are supported).

4. **Error Handling and Robustness:**
   - **Assertions and Checks:** The tests include `CHECK` and `EXPECT_EQ` statements to verify the internal state and behavior of `MultiBuffer`.
   - **Randomized Testing:** The `RandomTest` functions perform many random read and seek operations, which helps in uncovering potential edge cases and concurrency issues.

**Relationship to JavaScript, HTML, and CSS:**

`MultiBuffer` is a low-level component within the Blink rendering engine, so its interaction with JavaScript, HTML, and CSS is indirect but crucial for media playback functionality.

* **JavaScript:**
    - **Media Source Extensions (MSE):** If the media is being played through MSE, JavaScript code would be responsible for feeding data into the `MultiBuffer` (or a similar underlying buffering mechanism) through `SourceBuffer` objects. The `MultiBuffer` would then manage this buffered data.
    - **HTMLMediaElement (`<video>` and `<audio>`):** When a `<video>` or `<audio>` element is playing a media file, the browser internally uses components like `MultiBuffer` to download, buffer, and provide the data to the media decoder. JavaScript can control the playback (play, pause, seek) and monitor buffering status, indirectly interacting with the underlying buffering mechanisms.
    - **Example:** Imagine a JavaScript application using the `<video>` element to stream a video. When the user starts playback, the browser (using `MultiBuffer` or a related component) starts fetching data from the video source. If the user seeks to a different part of the video, the browser might use the `MultiBufferReader::Seek` functionality to jump to the correct buffered position or initiate a new data fetch if the data isn't already buffered.

* **HTML:**
    - The `<video>` and `<audio>` elements in HTML define the media player elements. They rely on the underlying browser infrastructure, including components like `MultiBuffer`, to function correctly.
    - **Example:**  The `src` attribute of a `<video>` tag points to the media resource. When the browser encounters this tag, it initiates the process of fetching and buffering the media data, potentially utilizing `MultiBuffer`.

* **CSS:**
    - CSS primarily deals with the styling and layout of web pages. It doesn't directly interact with the data buffering process.
    - **Example:** CSS can be used to style the video player controls (play/pause buttons, seek bar), but the actual data fetching and buffering are handled by lower-level components like `MultiBuffer`. CSS might style a loading spinner that is displayed while `MultiBuffer` is fetching data.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider a simplified scenario based on the `ReadAll` test:

**Assumed Input:**

1. **`MultiBuffer` Instance:**  An initialized `MultiBuffer` object.
2. **`MultiBufferReader` Instance:** A reader attached to the `MultiBuffer`, starting at position 0, with an end position of 10000 bytes.
3. **`FakeMultiBufferDataProvider`:** A data provider associated with the `MultiBuffer`, responsible for providing 10000 bytes of data. The data is generated based on the formula: `static_cast<uint8_t>((byte_pos * 15485863) >> 16)`.
4. **`TryRead` Call:** A call to `reader.TryRead(buffer, to_read)` where `to_read` is a small number (e.g., 17).

**Logical Steps:**

1. **Reader Request:** The `MultiBufferReader` requests `to_read` bytes of data from the `MultiBuffer` at the current position.
2. **Data Availability Check:** The `MultiBuffer` checks if the requested data is already in its buffer.
3. **Data Provider Interaction (if needed):** If the data is not available, the `MultiBuffer` might ask its data provider (`FakeMultiBufferDataProvider`) to provide the necessary blocks. In this test, `Advance()` on the data provider is called to simulate this.
4. **Data Retrieval:** The `MultiBuffer` retrieves the requested data from its buffer (or gets it from the provider).
5. **Data Copying:** The retrieved data is copied into the `buffer` provided to `TryRead`.

**Hypothetical Output:**

If `TryRead` is called when the first few bytes are available:

- `bytes_read` (the return value of `TryRead`) would be equal to `to_read` (or less if fewer bytes are available).
- The `buffer` would contain the first `to_read` bytes of the generated data sequence. For example, if `to_read` is 3, and the current position is 0, the `buffer` would contain:
    - `buffer[0] = static_cast<uint8_t>((0 * 15485863) >> 16)`
    - `buffer[1] = static_cast<uint8_t>((1 * 15485863) >> 16)`
    - `buffer[2] = static_cast<uint8_t>((2 * 15485863) >> 16)`

**Common Usage Errors:**

While this is a unit test, it helps illustrate potential issues when working with a buffering system like this in a real-world scenario:

1. **Incorrectly Setting Pin Ranges:**
   - **Error:** Pinning too much data can lead to excessive memory usage and prevent the LRU cache from effectively managing memory.
   - **Example:**  A developer might pin a very large portion of a video file, even parts that are not needed for immediate playback, leading to memory pressure.

2. **Not Handling Asynchronous Loading:**
   - **Error:**  Assuming data is immediately available when it might still be loading.
   - **Example:**  A media player might try to read data and decode frames before enough data has been fetched and buffered, leading to playback glitches or errors. The tests with `Advance()` simulate this scenario.

3. **Incorrectly Calculating Seek Positions:**
   - **Error:**  Seeking to a position that is outside the buffered range.
   - **Example:** A user might try to seek to a point in a video that hasn't been downloaded yet. The application needs to handle this by either waiting for the data to load or displaying a loading indicator.

4. **Memory Leaks due to Unreleased Buffers:**
   - **Error:**  Not properly managing the lifecycle of `MultiBuffer` or related objects, potentially leading to memory leaks.
   - **Example:** If a `MultiBuffer` instance is not properly destroyed when it's no longer needed, the memory it occupies might not be released. The `TearDown()` method in the test fixture aims to prevent such leaks during testing.

5. **Race Conditions in Multi-threaded Scenarios:**
   - **Error:**  If multiple threads are accessing and modifying the `MultiBuffer` without proper synchronization, it can lead to data corruption or unexpected behavior. While this specific test file might not explicitly test multi-threading, it's a common concern in media handling.

In summary, `multi_buffer_unittest.cc` provides a comprehensive set of tests for the `MultiBuffer` class, showcasing its capabilities in managing, caching, and providing media data in an efficient manner. Understanding these tests gives insight into the expected behavior and potential usage scenarios of this core component in the Chromium rendering engine.

Prompt: 
```
这是目录为blink/renderer/platform/media/multi_buffer_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/media/multi_buffer.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/simple_test_tick_clock.h"
#include "media/base/fake_single_thread_task_runner.h"
#include "media/base/test_random.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/media/multi_buffer_reader.h"

namespace blink {
namespace {
class FakeMultiBufferDataProvider;

const int kBlockSizeShift = 8;
const size_t kBlockSize = 1UL << kBlockSizeShift;

std::vector<FakeMultiBufferDataProvider*> writers;

class FakeMultiBufferDataProvider : public MultiBuffer::DataProvider {
 public:
  FakeMultiBufferDataProvider(MultiBufferBlockId pos,
                              size_t file_size,
                              int max_blocks_after_defer,
                              bool must_read_whole_file,
                              MultiBuffer* multibuffer,
                              media::TestRandom* rnd)
      : pos_(pos),
        blocks_until_deferred_(1 << 30),
        max_blocks_after_defer_(max_blocks_after_defer),
        file_size_(file_size),
        must_read_whole_file_(must_read_whole_file),
        multibuffer_(multibuffer),
        rnd_(rnd) {
    writers.push_back(this);
  }

  ~FakeMultiBufferDataProvider() override {
    if (must_read_whole_file_) {
      CHECK_GE(pos_ * kBlockSize, file_size_);
    }
    for (size_t i = 0; i < writers.size(); i++) {
      if (writers[i] == this) {
        writers[i] = writers.back();
        writers.pop_back();
        return;
      }
    }
    LOG(FATAL) << "Couldn't find myself in writers!";
  }

  MultiBufferBlockId Tell() const override { return pos_; }

  bool Available() const override { return !fifo_.empty(); }
  int64_t AvailableBytes() const override { return 0; }

  scoped_refptr<media::DataBuffer> Read() override {
    DCHECK(Available());
    scoped_refptr<media::DataBuffer> ret = fifo_.front();
    fifo_.pop_front();
    ++pos_;
    return ret;
  }

  void SetDeferred(bool deferred) override {
    if (deferred) {
      if (max_blocks_after_defer_ > 0) {
        blocks_until_deferred_ = rnd_->Rand() % max_blocks_after_defer_;
      } else if (max_blocks_after_defer_ < 0) {
        blocks_until_deferred_ = -max_blocks_after_defer_;
      } else {
        blocks_until_deferred_ = 0;
      }
    } else {
      blocks_until_deferred_ = 1 << 30;
    }
  }

  bool Advance() {
    if (blocks_until_deferred_ == 0)
      return false;
    --blocks_until_deferred_;

    bool ret = true;
    auto block =
        base::MakeRefCounted<media::DataBuffer>(static_cast<int>(kBlockSize));
    size_t x = 0;
    size_t byte_pos = (fifo_.size() + pos_) * kBlockSize;
    for (x = 0; x < kBlockSize; x++, byte_pos++) {
      if (byte_pos >= file_size_)
        break;
      block->writable_data()[x] =
          static_cast<uint8_t>((byte_pos * 15485863) >> 16);
    }
    block->set_data_size(static_cast<int>(x));
    fifo_.push_back(block);
    if (byte_pos == file_size_) {
      fifo_.push_back(media::DataBuffer::CreateEOSBuffer());
      ret = false;
    }
    multibuffer_->OnDataProviderEvent(this);
    return ret;
  }

 private:
  base::circular_deque<scoped_refptr<media::DataBuffer>> fifo_;
  MultiBufferBlockId pos_;
  int32_t blocks_until_deferred_;
  int32_t max_blocks_after_defer_;
  size_t file_size_;
  bool must_read_whole_file_;
  raw_ptr<MultiBuffer> multibuffer_;
  raw_ptr<media::TestRandom> rnd_;
};

}  // namespace

class TestMultiBuffer : public MultiBuffer {
 public:
  explicit TestMultiBuffer(int32_t shift,
                           const scoped_refptr<MultiBuffer::GlobalLRU>& lru,
                           media::TestRandom* rnd)
      : MultiBuffer(shift, lru),
        range_supported_(false),
        create_ok_(true),
        max_writers_(10000),
        file_size_(1 << 30),
        max_blocks_after_defer_(0),
        must_read_whole_file_(false),
        writers_created_(0),
        rnd_(rnd) {}

  void SetMaxWriters(size_t max_writers) { max_writers_ = max_writers; }

  void CheckPresentState() {
    IntervalMap<MultiBufferBlockId, int32_t> tmp;
    for (auto i = data_.begin(); i != data_.end(); ++i) {
      CHECK(i->second);  // Null poineters are not allowed in data_
      CHECK_NE(!!pinned_[i->first], lru_->Contains(this, i->first))
          << " i->first = " << i->first;
      tmp.IncrementInterval(i->first, i->first + 1, 1);
    }
    IntervalMap<MultiBufferBlockId, int32_t>::const_iterator tmp_iterator =
        tmp.begin();
    IntervalMap<MultiBufferBlockId, int32_t>::const_iterator present_iterator =
        present_.begin();
    while (tmp_iterator != tmp.end() && present_iterator != present_.end()) {
      EXPECT_EQ(tmp_iterator.interval_begin(),
                present_iterator.interval_begin());
      EXPECT_EQ(tmp_iterator.interval_end(), present_iterator.interval_end());
      EXPECT_EQ(tmp_iterator.value(), present_iterator.value());
      ++tmp_iterator;
      ++present_iterator;
    }
    EXPECT_TRUE(tmp_iterator == tmp.end());
    EXPECT_TRUE(present_iterator == present_.end());
  }

  void CheckLRUState() {
    for (auto i = data_.begin(); i != data_.end(); ++i) {
      CHECK(i->second);  // Null poineters are not allowed in data_
      CHECK_NE(!!pinned_[i->first], lru_->Contains(this, i->first))
          << " i->first = " << i->first;
      CHECK_EQ(1, present_[i->first]) << " i->first = " << i->first;
    }
  }

  void SetFileSize(size_t file_size) { file_size_ = file_size; }

  void SetMaxBlocksAfterDefer(int32_t max_blocks_after_defer) {
    max_blocks_after_defer_ = max_blocks_after_defer;
  }

  void SetMustReadWholeFile(bool must_read_whole_file) {
    must_read_whole_file_ = must_read_whole_file;
  }

  int32_t writers_created() const { return writers_created_; }

  void SetRangeSupported(bool supported) { range_supported_ = supported; }

 protected:
  std::unique_ptr<DataProvider> CreateWriter(const MultiBufferBlockId& pos,
                                             bool) override {
    DCHECK(create_ok_);
    writers_created_++;
    CHECK_LT(writers.size(), max_writers_);
    return std::make_unique<FakeMultiBufferDataProvider>(
        pos, file_size_, max_blocks_after_defer_, must_read_whole_file_, this,
        rnd_);
  }
  void Prune(size_t max_to_free) override {
    // Prune should not cause additional writers to be spawned.
    create_ok_ = false;
    MultiBuffer::Prune(max_to_free);
    create_ok_ = true;
  }

  bool RangeSupported() const override { return range_supported_; }

 private:
  bool range_supported_;
  bool create_ok_;
  size_t max_writers_;
  size_t file_size_;
  int32_t max_blocks_after_defer_;
  bool must_read_whole_file_;
  int32_t writers_created_;
  raw_ptr<media::TestRandom> rnd_;
};

class MultiBufferTest : public testing::Test {
 public:
  MultiBufferTest()
      : rnd_(42),
        task_runner_(
            base::MakeRefCounted<media::FakeSingleThreadTaskRunner>(&clock_)),
        lru_(base::MakeRefCounted<MultiBuffer::GlobalLRU>(task_runner_)),
        multibuffer_(kBlockSizeShift, lru_, &rnd_) {}

  void TearDown() override {
    // Make sure we have nothing left to prune.
    lru_->Prune(1000000);
    // Run the outstanding callback to make sure everything is freed.
    task_runner_->Sleep(base::Seconds(30));
  }

  void Advance() {
    CHECK(writers.size());
    writers[rnd_.Rand() % writers.size()]->Advance();
  }

  bool AdvanceAll() {
    bool advanced = false;
    for (size_t i = 0; i < writers.size(); i++) {
      advanced |= writers[i]->Advance();
    }
    multibuffer_.CheckLRUState();
    return advanced;
  }

 protected:
  media::TestRandom rnd_;
  base::SimpleTestTickClock clock_;
  scoped_refptr<media::FakeSingleThreadTaskRunner> task_runner_;
  scoped_refptr<MultiBuffer::GlobalLRU> lru_;
  TestMultiBuffer multibuffer_;
};

TEST_F(MultiBufferTest, ReadAll) {
  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  multibuffer_.SetMustReadWholeFile(true);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPinRange(2000, 5000);
  reader.SetPreload(1000, 1000);
  while (pos < end) {
    unsigned char buffer[27];
    buffer[17] = 17;
    size_t to_read = std::min<size_t>(end - pos, 17);
    int64_t bytes_read = reader.TryRead(buffer, to_read);
    if (bytes_read) {
      EXPECT_EQ(buffer[17], 17);
      for (int64_t i = 0; i < bytes_read; i++) {
        uint8_t expected = static_cast<uint8_t>((pos * 15485863) >> 16);
        EXPECT_EQ(expected, buffer[i]) << " pos = " << pos;
        pos++;
      }
    } else {
      Advance();
    }
  }
}

TEST_F(MultiBufferTest, ReadAllAdvanceFirst) {
  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  multibuffer_.SetMustReadWholeFile(true);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPinRange(2000, 5000);
  reader.SetPreload(1000, 1000);
  while (pos < end) {
    unsigned char buffer[27];
    buffer[17] = 17;
    size_t to_read = std::min<size_t>(end - pos, 17);
    while (AdvanceAll()) {
    }
    int64_t bytes = reader.TryRead(buffer, to_read);
    EXPECT_GT(bytes, 0);
    EXPECT_EQ(buffer[17], 17);
    for (int64_t i = 0; i < bytes; i++) {
      uint8_t expected = static_cast<uint8_t>((pos * 15485863) >> 16);
      EXPECT_EQ(expected, buffer[i]) << " pos = " << pos;
      pos++;
    }
  }
}

// Checks that if the data provider provides too much data after we told it
// to defer, we kill it.
TEST_F(MultiBufferTest, ReadAllAdvanceFirst_NeverDefer) {
  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  multibuffer_.SetMaxBlocksAfterDefer(-10000);
  multibuffer_.SetRangeSupported(true);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPinRange(2000, 5000);
  reader.SetPreload(1000, 1000);
  while (pos < end) {
    unsigned char buffer[27];
    buffer[17] = 17;
    size_t to_read = std::min<size_t>(end - pos, 17);
    while (AdvanceAll()) {
    }
    int64_t bytes = reader.TryRead(buffer, to_read);
    EXPECT_GT(bytes, 0);
    EXPECT_EQ(buffer[17], 17);
    for (int64_t i = 0; i < bytes; i++) {
      uint8_t expected = static_cast<uint8_t>((pos * 15485863) >> 16);
      EXPECT_EQ(expected, buffer[i]) << " pos = " << pos;
      pos++;
    }
  }
  EXPECT_GT(multibuffer_.writers_created(), 1);
}

// Same as ReadAllAdvanceFirst_NeverDefer, but the url doesn't support
// ranges, so we don't destroy it no matter how much data it provides.
TEST_F(MultiBufferTest, ReadAllAdvanceFirst_NeverDefer2) {
  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  multibuffer_.SetMustReadWholeFile(true);
  multibuffer_.SetMaxBlocksAfterDefer(-10000);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPinRange(2000, 5000);
  reader.SetPreload(1000, 1000);
  while (pos < end) {
    unsigned char buffer[27];
    buffer[17] = 17;
    size_t to_read = std::min<size_t>(end - pos, 17);
    while (AdvanceAll()) {
    }
    int64_t bytes = reader.TryRead(buffer, to_read);
    EXPECT_GT(bytes, 0);
    EXPECT_EQ(buffer[17], 17);
    for (int64_t i = 0; i < bytes; i++) {
      uint8_t expected = static_cast<uint8_t>((pos * 15485863) >> 16);
      EXPECT_EQ(expected, buffer[i]) << " pos = " << pos;
      pos++;
    }
  }
}

TEST_F(MultiBufferTest, LRUTest) {
  int64_t max_size = 17;
  int64_t current_size = 0;
  lru_->IncrementMaxSize(max_size);

  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPreload(10000, 10000);
  // Note, no pinning, all data should end up in LRU.
  EXPECT_EQ(current_size, lru_->Size());
  current_size += max_size;
  while (AdvanceAll()) {
  }
  EXPECT_EQ(current_size, lru_->Size());
  lru_->IncrementMaxSize(-max_size);
  lru_->Prune(3);
  current_size -= 3;
  EXPECT_EQ(current_size, lru_->Size());
  lru_->Prune(3);
  current_size -= 3;
  EXPECT_EQ(current_size, lru_->Size());
  lru_->Prune(1000);
  EXPECT_EQ(0, lru_->Size());
}

TEST_F(MultiBufferTest, LRUTest2) {
  int64_t max_size = 17;
  int64_t current_size = 0;
  lru_->IncrementMaxSize(max_size);

  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPreload(10000, 10000);
  // Note, no pinning, all data should end up in LRU.
  EXPECT_EQ(current_size, lru_->Size());
  current_size += max_size;
  while (AdvanceAll()) {
  }
  EXPECT_EQ(current_size, lru_->Size());
  // Pruning shouldn't do anything here, because LRU is small enough already.
  lru_->Prune(3);
  EXPECT_EQ(current_size, lru_->Size());
  // However TryFree should still work
  lru_->TryFree(3);
  current_size -= 3;
  EXPECT_EQ(current_size, lru_->Size());
  lru_->TryFreeAll();
  EXPECT_EQ(0, lru_->Size());
  lru_->IncrementMaxSize(-max_size);
}

TEST_F(MultiBufferTest, LRUTestExpirationTest) {
  int64_t max_size = 17;
  int64_t current_size = 0;
  lru_->IncrementMaxSize(max_size);

  multibuffer_.SetMaxWriters(1);
  size_t pos = 0;
  size_t end = 10000;
  multibuffer_.SetFileSize(10000);
  MultiBufferReader reader(&multibuffer_, pos, end,
                           /*is_client_audio_element=*/false,
                           base::NullCallback(), task_runner_);
  reader.SetPreload(10000, 10000);
  // Note, no pinning, all data should end up in LRU.
  EXPECT_EQ(current_size, lru_->Size());
  current_size += max_size;
  while (AdvanceAll()) {
  }
  EXPECT_EQ(current_size, lru_->Size());
  EXPECT_FALSE(lru_->Pruneable());

  // Make 3 packets pruneable.
  lru_->IncrementMaxSize(-3);
  max_size -= 3;

  // There should be no change after 29 seconds.
  task_runner_->Sleep(base::Seconds(29));
  EXPECT_EQ(current_size, lru_->Size());
  EXPECT_TRUE(lru_->Pruneable());

  // After 30 seconds, pruning should have happened.
  task_runner_->Sleep(base::Seconds(30));
  current_size -= 3;
  EXPECT_EQ(current_size, lru_->Size());
  EXPECT_FALSE(lru_->Pruneable());

  // Make the rest of the packets pruneable.
  lru_->IncrementMaxSize(-max_size);

  // After another 30 seconds, everything should be pruned.
  task_runner_->Sleep(base::Seconds(30));
  EXPECT_EQ(0, lru_->Size());
  EXPECT_FALSE(lru_->Pruneable());
}

class ReadHelper {
 public:
  ReadHelper(size_t end,
             size_t max_read_size,
             MultiBuffer* multibuffer,
             media::TestRandom* rnd,
             scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : pos_(0),
        end_(end),
        max_read_size_(max_read_size),
        read_size_(0),
        rnd_(rnd),
        reader_(multibuffer,
                pos_,
                end_,
                /*is_client_audio_element=*/false,
                base::NullCallback(),
                std::move(task_runner)) {
    reader_.SetPinRange(2000, 5000);
    reader_.SetPreload(1000, 1000);
  }

  bool Read() {
    if (read_size_ == 0)
      return true;
    unsigned char buffer[4096];
    CHECK_LE(read_size_, static_cast<int64_t>(sizeof(buffer)));
    CHECK_EQ(pos_, reader_.Tell());
    int64_t bytes_read = reader_.TryRead(buffer, read_size_);
    if (bytes_read) {
      for (int64_t i = 0; i < bytes_read; i++) {
        unsigned char expected = (pos_ * 15485863) >> 16;
        EXPECT_EQ(expected, buffer[i]) << " pos = " << pos_;
        pos_++;
      }
      CHECK_EQ(pos_, reader_.Tell());
      return true;
    }
    return false;
  }

  void StartRead() {
    CHECK_EQ(pos_, reader_.Tell());
    read_size_ = std::min(1 + rnd_->Rand() % (max_read_size_ - 1), end_ - pos_);
    if (!Read()) {
      reader_.Wait(read_size_,
                   base::BindOnce(&ReadHelper::WaitCB, base::Unretained(this)));
    }
  }

  void WaitCB() { CHECK(Read()); }

  void Seek() {
    pos_ = rnd_->Rand() % end_;
    reader_.Seek(pos_);
    CHECK_EQ(pos_, reader_.Tell());
  }

 private:
  int64_t pos_;
  int64_t end_;
  int64_t max_read_size_;
  int64_t read_size_;
  raw_ptr<media::TestRandom> rnd_;
  MultiBufferReader reader_;
};

TEST_F(MultiBufferTest, RandomTest) {
  size_t file_size = 1000000;
  multibuffer_.SetFileSize(file_size);
  multibuffer_.SetMaxBlocksAfterDefer(10);
  std::vector<std::unique_ptr<ReadHelper>> read_helpers;
  for (size_t i = 0; i < 20; i++) {
    read_helpers.push_back(std::make_unique<ReadHelper>(
        file_size, 1000, &multibuffer_, &rnd_, task_runner_));
  }
  for (int i = 0; i < 100; i++) {
    for (int j = 0; j < 100; j++) {
      if (rnd_.Rand() & 1) {
        if (!writers.empty())
          Advance();
      } else {
        size_t k = rnd_.Rand() % read_helpers.size();
        if (rnd_.Rand() % 100 < 3)
          read_helpers[k]->Seek();
        read_helpers[k]->StartRead();
      }
    }
    multibuffer_.CheckLRUState();
  }
  multibuffer_.CheckPresentState();
}

TEST_F(MultiBufferTest, RandomTest_RangeSupported) {
  size_t file_size = 1000000;
  multibuffer_.SetFileSize(file_size);
  multibuffer_.SetMaxBlocksAfterDefer(10);
  std::vector<std::unique_ptr<ReadHelper>> read_helpers;
  multibuffer_.SetRangeSupported(true);
  for (size_t i = 0; i < 20; i++) {
    read_helpers.push_back(std::make_unique<ReadHelper>(
        file_size, 1000, &multibuffer_, &rnd_, task_runner_));
  }
  for (int i = 0; i < 100; i++) {
    for (int j = 0; j < 100; j++) {
      if (rnd_.Rand() & 1) {
        if (!writers.empty())
          Advance();
      } else {
        size_t k = rnd_.Rand() % read_helpers.size();
        if (rnd_.Rand() % 100 < 3)
          read_helpers[k]->Seek();
        read_helpers[k]->StartRead();
      }
    }
    multibuffer_.CheckLRUState();
  }
  multibuffer_.CheckPresentState();
}

}  // namespace blink

"""

```