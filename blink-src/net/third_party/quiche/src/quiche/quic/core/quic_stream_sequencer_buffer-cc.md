Response:
Let's break down the thought process for analyzing the provided C++ code for `QuicStreamSequencerBuffer`.

**1. Understanding the Goal:**

The request asks for a breakdown of the code's functionality, its relationship to JavaScript (if any), logical reasoning with input/output examples, common usage errors, and debugging context. This requires a multi-faceted approach.

**2. Initial Skim and Keyword Identification:**

First, I'd quickly skim the code, looking for keywords and patterns that reveal its purpose. Keywords like `buffer`, `stream`, `offset`, `read`, `write`, `capacity`, `block`, `interval`, `bytes`, and `sequencer` immediately suggest this code is about managing incoming data for a stream in a network context, likely dealing with out-of-order delivery. The `quic` namespace reinforces this.

**3. Core Functionality Identification (The "What"):**

Based on the keywords and structure, I can infer the core functionalities:

* **Buffering Stream Data:**  The name itself suggests this. It's likely storing incoming data segments.
* **Handling Out-of-Order Delivery:** The presence of `QuicIntervalSet` (`bytes_received_`) strongly indicates this. It tracks which parts of the stream have been received.
* **Sequential Reading:** The "sequencer" part hints at the ability to read the data in the correct order, even if it arrives out of order.
* **Memory Management:** The use of `BufferBlock`, `blocks_`, and methods like `RetireBlock` and `MaybeAddMoreBlocks` points to managing a pool of memory blocks for storing the data.
* **Capacity Management:** `max_buffer_capacity_bytes_` limits how much data can be buffered.

**4. Detailed Analysis of Key Methods:**

Next, I would delve into the important methods to understand *how* the functionality is implemented:

* **`OnStreamData()` (Writing):** This is the entry point for incoming data. I'd note how it checks for errors, handles duplicates, adds data to the buffer, and updates `bytes_received_`. The use of `QuicIntervalSet` is crucial here.
* **`Readv()` (Reading):**  This handles reading data out of the buffer. I'd focus on how it retrieves data from the blocks, advances the read pointer (`total_bytes_read_`), and potentially retires blocks.
* **`GetReadableRegions()` and `PeekRegion()`:** These methods allow inspection of the buffered data without consuming it, important for flow control or higher-level processing.
* **`MarkConsumed()`:** This advances the read pointer, effectively acknowledging that data has been processed.
* **`Clear()` and `ReleaseWholeBuffer()`:**  These manage the buffer's lifecycle and memory.
* **Helper Methods (e.g., `GetBlockIndex`, `GetInBlockOffset`, `ReadableBytes`):** These provide supporting calculations for block-based storage.

**5. JavaScript Relationship (The "If"):**

This requires thinking about where this C++ code might interact with JavaScript in a browser context. The key connection is through the Chromium network stack. JavaScript uses Web APIs (like `fetch` or `XMLHttpRequest`) that rely on the underlying network stack for data transfer.

* **Hypothesis:**  When JavaScript requests data over a QUIC connection, the received data is processed by the Chromium network stack, and `QuicStreamSequencerBuffer` is likely involved in buffering and reassembling the stream data before it's made available to the JavaScript engine.

**6. Logical Reasoning (The "Then"):**

For this, I'd pick a common scenario, like receiving a fragmented stream:

* **Input:**  Imagine two data packets arriving out of order.
* **Processing:** I'd mentally trace how `OnStreamData()` would handle them, updating `bytes_received_` and writing the data to the appropriate blocks.
* **Output:** Then, I'd consider how `Readv()` would then read the data in the correct sequential order.

**7. Common Usage Errors (The "Watch Out"):**

Thinking about how developers might misuse the API is essential:

* **Writing Beyond Capacity:** What happens if the incoming data exceeds `max_buffer_capacity_bytes_`?
* **Reading Before Data Arrives:** What if `Readv()` is called when there's no data to read?
* **Incorrect Offset Handling:**  Supplying wrong offsets to methods like `PeekRegion`.

**8. Debugging Context (The "How Did We Get Here"):**

This requires tracing the user's action from a high level down to this specific code:

* **User Action:**  A user browses a website.
* **Browser Action:** The browser initiates a network request.
* **Network Stack:** The request uses QUIC.
* **Data Arrival:** QUIC data packets arrive, potentially out of order.
* **`QuicStreamSequencerBuffer`:** This component within the QUIC implementation receives and buffers the data.

**9. Structuring the Answer:**

Finally, I would organize the findings into the requested sections:

* **Functionality:**  Start with a high-level overview and then detail key methods.
* **JavaScript Relationship:** Explain the connection through the Chromium network stack and Web APIs.
* **Logical Reasoning:** Provide a clear input/processing/output example.
* **Common Errors:** List potential pitfalls with illustrative scenarios.
* **Debugging:** Trace the user action down to the code.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "Maybe this is just about in-order delivery."  **Correction:** The `QuicIntervalSet` immediately indicates out-of-order handling.
* **Initial thought:** "JavaScript directly calls this C++ code." **Correction:**  The interaction is indirect, through the browser's network stack.
* **Focusing too much on individual lines:** **Correction:**  Shift focus to the overall purpose of the methods and the class.

By following this structured approach, combining code analysis, domain knowledge (networking, web browsers), and logical reasoning, it's possible to generate a comprehensive and informative answer to the request.
这个 C++ 源代码文件 `quic_stream_sequencer_buffer.cc` 实现了 Chromium QUIC 协议栈中用于**缓存和管理乱序到达的 stream 数据**的组件。它的核心功能是确保上层应用能够以**顺序**的方式读取 stream 数据，即使网络数据包到达的顺序可能不是预期的。

以下是 `QuicStreamSequencerBuffer` 的主要功能：

1. **接收和存储乱序到达的 Stream 数据：**
   - 它接收带有偏移量 (`starting_offset`) 的数据块 (`data`)。
   - 它使用 `QuicIntervalSet` (`bytes_received_`) 来跟踪已接收到的数据范围，从而识别出已接收和缺失的数据段。

2. **按顺序读取数据：**
   - 它维护一个读指针 (`total_bytes_read_`)，指向下一个要读取的字节。
   - 它提供方法 (`Readv`, `GetReadableRegions`, `PeekRegion`) 来按顺序访问已缓存的数据。

3. **管理缓存容量：**
   - 它有一个最大容量 (`max_buffer_capacity_bytes_`)，用于限制可以缓存的数据量。
   - 它使用一系列固定大小的内存块 (`BufferBlock`) 来存储数据。
   - 它动态地分配和释放这些内存块，以适应接收到的数据量，并避免浪费内存。

4. **处理数据重复和覆盖：**
   - 当接收到与已接收数据重叠的数据时，它只会存储尚未接收的部分。

5. **延迟传递数据直到顺序完整：**
   - 它会缓存乱序到达的数据，直到前面的数据也到达，确保上层应用读取到的数据是连续且有序的。

6. **内存优化：**
   - 通过使用固定大小的内存块和按需分配，它试图优化内存使用。
   - `RetireBlock` 方法允许释放不再需要的内存块。

**与 JavaScript 功能的关系：**

`QuicStreamSequencerBuffer` 本身是用 C++ 实现的，直接与 JavaScript 没有编程语言层面的关系。但是，它在浏览器网络栈中扮演着关键角色，而浏览器正是 JavaScript 代码运行的环境。

当 JavaScript 通过诸如 `fetch` 或 `XMLHttpRequest` 等 Web API 发起网络请求时，如果底层连接使用了 QUIC 协议，那么接收到的 stream 数据最终会经过 `QuicStreamSequencerBuffer` 的处理。

**举例说明：**

假设一个 JavaScript 应用通过 `fetch` 下载一个大型文件。底层使用了 QUIC 协议。

1. **用户操作 (JavaScript):**
   ```javascript
   fetch('https://example.com/large_file.txt')
     .then(response => response.text())
     .then(text => {
       console.log('文件内容:', text);
     });
   ```

2. **网络数据包传输 (QUIC):**
   - 文件数据被分割成多个 QUIC 数据包进行传输。
   - 由于网络原因，这些数据包可能乱序到达浏览器。

3. **`QuicStreamSequencerBuffer` 的作用 (C++):**
   - 当乱序的 QUIC 数据包到达时，Chromium 网络栈会将数据交给 `QuicStreamSequencerBuffer`。
   - 例如，偏移量为 1000-2000 的数据包可能比偏移量为 0-1000 的数据包先到达。
   - `QuicStreamSequencerBuffer` 会将偏移量 1000-2000 的数据缓存起来。
   - 当偏移量 0-1000 的数据到达后，`QuicStreamSequencerBuffer` 就能保证上层模块（最终是 JavaScript）可以按顺序读取 0-2000 的完整数据。

4. **数据传递给 JavaScript:**
   - 当数据准备好按顺序读取时，Chromium 网络栈会将数据传递给 JavaScript 引擎，最终触发 `fetch` 的 `then` 回调。

**逻辑推理 (假设输入与输出):**

**假设输入：**

- `max_buffer_capacity_bytes_` = 4096 字节
- `kBlockSizeBytes` = 1024 字节 (假设)
- 初始 `total_bytes_read_` = 0
- 接收到两个数据帧：
    - 帧 1: `starting_offset` = 1024, `data` = "Data Block 2" (假设长度 100 字节)
    - 帧 2: `starting_offset` = 0, `data` = "Data Block 1" (假设长度 1000 字节)

**处理过程：**

1. **接收帧 1:**
   - `OnStreamData(1024, "Data Block 2", ...)` 被调用。
   - `bytes_received_` 更新为包含 [1024, 1124) 的区间。
   - 数据 "Data Block 2" 被写入相应的内存块。

2. **接收帧 2:**
   - `OnStreamData(0, "Data Block 1", ...)` 被调用。
   - `bytes_received_` 更新为包含 [0, 1000) 和 [1024, 1124) 的区间。
   - 数据 "Data Block 1" 被写入相应的内存块。

3. **读取数据：**
   - 当 JavaScript 尝试读取数据时（例如，通过网络栈的更高层接口调用 `Readv`），`QuicStreamSequencerBuffer` 会：
     - 检查 `total_bytes_read_`。
     - 发现偏移量 0 到 1000 的数据已接收。
     - 从内存块中读取 "Data Block 1"。
     - 更新 `total_bytes_read_` 为 1000。
     - 下次读取时，发现偏移量 1000 到 1124 的数据已接收。
     - 读取 "Data Block 2" 的部分内容。

**假设输出 (读取操作):**

- 第一次 `Readv` 调用可能会返回 "Data Block 1"。
- 第二次 `Readv` 调用可能会返回 "Data Block 2"。

**用户或编程常见的使用错误：**

1. **配置过小的 `max_buffer_capacity_bytes_`：**
   - 如果配置的缓冲区大小不足以容纳网络传输过程中可能出现的乱序数据量，可能会导致数据被过早丢弃或连接中断。
   - **用户操作导致：** 用户可能在一个网络条件不佳的环境下尝试下载一个大文件，导致数据包乱序严重，而缓冲区又太小。
   - **调试线索：** 观察到 `QuicStreamSequencerBuffer::OnStreamData` 返回 `QUIC_INTERNAL_ERROR` 或其他与容量相关的错误。日志中可能会出现 "Received data beyond available range." 的信息。

2. **在数据尚未到达时尝试读取：**
   - 上层模块错误地认为数据已经准备好，并调用读取方法，但实际上 `QuicStreamSequencerBuffer` 还没有接收到相应的数据。
   - **用户操作导致：** 这通常不是直接的用户操作，而是编程错误，例如在处理网络事件时逻辑错误。
   - **调试线索：** `QuicStreamSequencerBuffer::ReadableBytes()` 返回 0，但上层模块仍然尝试调用读取方法。可能会导致阻塞或程序异常。

3. **错误地理解偏移量：**
   - 在处理接收到的数据时，错误地计算或传递 `starting_offset`，导致数据写入错误的内存位置。
   - **用户操作导致：** 这不是直接的用户操作，而是底层网络栈实现中的错误。
   - **调试线索：**  观察到缓存的数据内容与预期不符，`bytes_received_` 中的区间信息不正确。日志中可能会有关于偏移量不一致的警告或错误。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问了一个使用 HTTPS (QUIC) 的网站，并开始下载一个大文件。

1. **用户在浏览器地址栏输入 URL 并按下回车。**
2. **浏览器解析 URL，确定目标服务器的 IP 地址和端口。**
3. **浏览器发起与服务器的 QUIC 连接握手。**
4. **QUIC 连接建立后，浏览器发送 HTTP 请求，请求下载文件。**
5. **服务器开始发送文件数据，数据被分割成多个 QUIC 数据包。**
6. **数据包通过互联网传输，可能因为网络拥塞或路由原因乱序到达用户的计算机。**
7. **用户的操作系统接收到这些网络数据包。**
8. **操作系统将数据包交给 Chrome 浏览器进程。**
9. **Chrome 浏览器的 QUIC 实现（位于 `net/third_party/quiche/src/quiche/quic/core/` 目录下）处理接收到的 QUIC 数据包。**
10. **对于表示 stream 数据的数据包，`QuicStreamSequencerBuffer::OnStreamData` 方法会被调用，将数据缓存起来。**
11. **当浏览器需要读取下载的文件数据时（例如，将数据写入磁盘或显示在界面上），会调用 `QuicStreamSequencerBuffer` 的读取方法 (`Readv`, `GetReadableRegions` 等)。**

**调试线索：**

- **网络抓包：** 可以使用 Wireshark 等工具抓取网络数据包，查看数据包的到达顺序，以及是否存在丢包或重传。
- **QUIC 事件日志：** QUIC 协议栈通常会有详细的事件日志，记录连接状态、数据包接收和发送情况、错误信息等。这些日志可以帮助定位问题是否发生在 `QuicStreamSequencerBuffer` 之前或之后。
- **Chromium 内部日志：**  可以通过启动带有特定标志的 Chrome 浏览器来启用更详细的内部日志，例如 `--vmodule=*quic*=3` 可以增加 QUIC 相关模块的日志输出。
- **断点调试：** 在 `QuicStreamSequencerBuffer` 的关键方法（如 `OnStreamData`, `Readv`) 设置断点，可以观察数据的接收和读取过程，检查 `bytes_received_` 的状态、内存块的使用情况等。
- **指标监控：**  监控 QUIC 连接的性能指标，例如丢包率、重传率、延迟等，可以帮助判断问题是否与网络环境有关。

通过以上分析，我们可以了解 `QuicStreamSequencerBuffer` 在 Chromium 网络栈中的重要作用，以及它如何帮助 JavaScript 应用可靠地处理基于 QUIC 协议的网络数据。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_sequencer_buffer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream_sequencer_buffer.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_interval.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {
namespace {

size_t CalculateBlockCount(size_t max_capacity_bytes) {
  return (max_capacity_bytes + QuicStreamSequencerBuffer::kBlockSizeBytes - 1) /
         QuicStreamSequencerBuffer::kBlockSizeBytes;
}

// Upper limit of how many gaps allowed in buffer, which ensures a reasonable
// number of iterations needed to find the right gap to fill when a frame
// arrives.
const size_t kMaxNumDataIntervalsAllowed = 2 * kMaxPacketGap;

// Number of blocks allocated initially.
constexpr size_t kInitialBlockCount = 8u;

// How fast block pointers container grow in size.
// Choose 4 to reduce the amount of reallocation.
constexpr int kBlocksGrowthFactor = 4;

}  // namespace

QuicStreamSequencerBuffer::QuicStreamSequencerBuffer(size_t max_capacity_bytes)
    : max_buffer_capacity_bytes_(max_capacity_bytes),
      max_blocks_count_(CalculateBlockCount(max_capacity_bytes)),
      current_blocks_count_(0u),
      total_bytes_read_(0),
      blocks_(nullptr) {
  QUICHE_DCHECK_GE(max_blocks_count_, kInitialBlockCount);
  Clear();
}

QuicStreamSequencerBuffer::~QuicStreamSequencerBuffer() { Clear(); }

void QuicStreamSequencerBuffer::Clear() {
  if (blocks_ != nullptr) {
    for (size_t i = 0; i < current_blocks_count_; ++i) {
      if (blocks_[i] != nullptr) {
        RetireBlock(i);
      }
    }
  }
  num_bytes_buffered_ = 0;
  bytes_received_.Clear();
  bytes_received_.Add(0, total_bytes_read_);
}

bool QuicStreamSequencerBuffer::RetireBlock(size_t index) {
  if (blocks_[index] == nullptr) {
    QUIC_BUG(quic_bug_10610_1) << "Try to retire block twice";
    return false;
  }
  delete blocks_[index];
  blocks_[index] = nullptr;
  QUIC_DVLOG(1) << "Retired block with index: " << index;
  return true;
}

void QuicStreamSequencerBuffer::MaybeAddMoreBlocks(
    QuicStreamOffset next_expected_byte) {
  if (current_blocks_count_ == max_blocks_count_) {
    return;
  }
  QuicStreamOffset last_byte = next_expected_byte - 1;
  size_t num_of_blocks_needed;
  // As long as last_byte does not wrap around, its index plus one blocks are
  // needed. Otherwise, block_count_ blocks are needed.
  if (last_byte < max_buffer_capacity_bytes_) {
    num_of_blocks_needed =
        std::max(GetBlockIndex(last_byte) + 1, kInitialBlockCount);
  } else {
    num_of_blocks_needed = max_blocks_count_;
  }
  if (current_blocks_count_ >= num_of_blocks_needed) {
    return;
  }
  size_t new_block_count = kBlocksGrowthFactor * current_blocks_count_;
  new_block_count = std::min(std::max(new_block_count, num_of_blocks_needed),
                             max_blocks_count_);
  auto new_blocks = std::make_unique<BufferBlock*[]>(new_block_count);
  if (blocks_ != nullptr) {
    memcpy(new_blocks.get(), blocks_.get(),
           current_blocks_count_ * sizeof(BufferBlock*));
  }
  blocks_ = std::move(new_blocks);
  current_blocks_count_ = new_block_count;
}

QuicErrorCode QuicStreamSequencerBuffer::OnStreamData(
    QuicStreamOffset starting_offset, absl::string_view data,
    size_t* const bytes_buffered, std::string* error_details) {
  *bytes_buffered = 0;
  size_t size = data.size();
  if (size == 0) {
    *error_details = "Received empty stream frame without FIN.";
    return QUIC_EMPTY_STREAM_FRAME_NO_FIN;
  }
  // Write beyond the current range this buffer is covering.
  if (starting_offset + size > total_bytes_read_ + max_buffer_capacity_bytes_ ||
      starting_offset + size < starting_offset) {
    *error_details = "Received data beyond available range.";
    return QUIC_INTERNAL_ERROR;
  }

  if (bytes_received_.Empty() ||
      starting_offset >= bytes_received_.rbegin()->max() ||
      bytes_received_.IsDisjoint(QuicInterval<QuicStreamOffset>(
          starting_offset, starting_offset + size))) {
    // Optimization for the typical case, when all data is newly received.
    bytes_received_.AddOptimizedForAppend(starting_offset,
                                          starting_offset + size);
    if (bytes_received_.Size() >= kMaxNumDataIntervalsAllowed) {
      // This frame is going to create more intervals than allowed. Stop
      // processing.
      *error_details = "Too many data intervals received for this stream.";
      return QUIC_TOO_MANY_STREAM_DATA_INTERVALS;
    }
    MaybeAddMoreBlocks(starting_offset + size);

    size_t bytes_copy = 0;
    if (!CopyStreamData(starting_offset, data, &bytes_copy, error_details)) {
      return QUIC_STREAM_SEQUENCER_INVALID_STATE;
    }
    *bytes_buffered += bytes_copy;
    num_bytes_buffered_ += *bytes_buffered;
    return QUIC_NO_ERROR;
  }
  // Slow path, received data overlaps with received data.
  QuicIntervalSet<QuicStreamOffset> newly_received(starting_offset,
                                                   starting_offset + size);
  newly_received.Difference(bytes_received_);
  if (newly_received.Empty()) {
    return QUIC_NO_ERROR;
  }
  bytes_received_.Add(starting_offset, starting_offset + size);
  if (bytes_received_.Size() >= kMaxNumDataIntervalsAllowed) {
    // This frame is going to create more intervals than allowed. Stop
    // processing.
    *error_details = "Too many data intervals received for this stream.";
    return QUIC_TOO_MANY_STREAM_DATA_INTERVALS;
  }
  MaybeAddMoreBlocks(starting_offset + size);
  for (const auto& interval : newly_received) {
    const QuicStreamOffset copy_offset = interval.min();
    const QuicByteCount copy_length = interval.max() - interval.min();
    size_t bytes_copy = 0;
    if (!CopyStreamData(copy_offset,
                        data.substr(copy_offset - starting_offset, copy_length),
                        &bytes_copy, error_details)) {
      return QUIC_STREAM_SEQUENCER_INVALID_STATE;
    }
    *bytes_buffered += bytes_copy;
  }
  num_bytes_buffered_ += *bytes_buffered;
  return QUIC_NO_ERROR;
}

bool QuicStreamSequencerBuffer::CopyStreamData(QuicStreamOffset offset,
                                               absl::string_view data,
                                               size_t* bytes_copy,
                                               std::string* error_details) {
  *bytes_copy = 0;
  size_t source_remaining = data.size();
  if (source_remaining == 0) {
    return true;
  }
  const char* source = data.data();
  // Write data block by block. If corresponding block has not created yet,
  // create it first.
  // Stop when all data are written or reaches the logical end of the buffer.
  while (source_remaining > 0) {
    const size_t write_block_num = GetBlockIndex(offset);
    const size_t write_block_offset = GetInBlockOffset(offset);
    size_t current_blocks_count = current_blocks_count_;
    QUICHE_DCHECK_GT(current_blocks_count, write_block_num);

    size_t block_capacity = GetBlockCapacity(write_block_num);
    size_t bytes_avail = block_capacity - write_block_offset;

    // If this write meets the upper boundary of the buffer,
    // reduce the available free bytes.
    if (offset + bytes_avail > total_bytes_read_ + max_buffer_capacity_bytes_) {
      bytes_avail = total_bytes_read_ + max_buffer_capacity_bytes_ - offset;
    }

    if (write_block_num >= current_blocks_count) {
      *error_details = absl::StrCat(
          "QuicStreamSequencerBuffer error: OnStreamData() exceed array bounds."
          "write offset = ",
          offset, " write_block_num = ", write_block_num,
          " current_blocks_count_ = ", current_blocks_count);
      return false;
    }
    if (blocks_ == nullptr) {
      *error_details =
          "QuicStreamSequencerBuffer error: OnStreamData() blocks_ is null";
      return false;
    }
    if (blocks_[write_block_num] == nullptr) {
      // TODO(danzh): Investigate if using a freelist would improve performance.
      // Same as RetireBlock().
      blocks_[write_block_num] = new BufferBlock();
    }

    const size_t bytes_to_copy =
        std::min<size_t>(bytes_avail, source_remaining);
    char* dest = blocks_[write_block_num]->buffer + write_block_offset;
    QUIC_DVLOG(1) << "Write at offset: " << offset
                  << " length: " << bytes_to_copy;

    if (dest == nullptr || source == nullptr) {
      *error_details = absl::StrCat(
          "QuicStreamSequencerBuffer error: OnStreamData()"
          " dest == nullptr: ",
          (dest == nullptr), " source == nullptr: ", (source == nullptr),
          " Writing at offset ", offset,
          " Received frames: ", ReceivedFramesDebugString(),
          " total_bytes_read_ = ", total_bytes_read_);
      return false;
    }
    memcpy(dest, source, bytes_to_copy);
    source += bytes_to_copy;
    source_remaining -= bytes_to_copy;
    offset += bytes_to_copy;
    *bytes_copy += bytes_to_copy;
  }
  return true;
}

QuicErrorCode QuicStreamSequencerBuffer::Readv(const iovec* dest_iov,
                                               size_t dest_count,
                                               size_t* bytes_read,
                                               std::string* error_details) {
  *bytes_read = 0;
  for (size_t i = 0; i < dest_count && ReadableBytes() > 0; ++i) {
    char* dest = reinterpret_cast<char*>(dest_iov[i].iov_base);
    QUICHE_DCHECK(dest != nullptr);
    size_t dest_remaining = dest_iov[i].iov_len;
    while (dest_remaining > 0 && ReadableBytes() > 0) {
      size_t block_idx = NextBlockToRead();
      size_t start_offset_in_block = ReadOffset();
      size_t block_capacity = GetBlockCapacity(block_idx);
      size_t bytes_available_in_block = std::min<size_t>(
          ReadableBytes(), block_capacity - start_offset_in_block);
      size_t bytes_to_copy =
          std::min<size_t>(bytes_available_in_block, dest_remaining);
      QUICHE_DCHECK_GT(bytes_to_copy, 0u);
      if (blocks_[block_idx] == nullptr || dest == nullptr) {
        *error_details = absl::StrCat(
            "QuicStreamSequencerBuffer error:"
            " Readv() dest == nullptr: ",
            (dest == nullptr), " blocks_[", block_idx,
            "] == nullptr: ", (blocks_[block_idx] == nullptr),
            " Received frames: ", ReceivedFramesDebugString(),
            " total_bytes_read_ = ", total_bytes_read_);
        return QUIC_STREAM_SEQUENCER_INVALID_STATE;
      }
      memcpy(dest, blocks_[block_idx]->buffer + start_offset_in_block,
             bytes_to_copy);
      dest += bytes_to_copy;
      dest_remaining -= bytes_to_copy;
      num_bytes_buffered_ -= bytes_to_copy;
      total_bytes_read_ += bytes_to_copy;
      *bytes_read += bytes_to_copy;

      // Retire the block if all the data is read out and no other data is
      // stored in this block.
      // In case of failing to retire a block which is ready to retire, return
      // immediately.
      if (bytes_to_copy == bytes_available_in_block) {
        bool retire_successfully = RetireBlockIfEmpty(block_idx);
        if (!retire_successfully) {
          *error_details = absl::StrCat(
              "QuicStreamSequencerBuffer error: fail to retire block ",
              block_idx,
              " as the block is already released, total_bytes_read_ = ",
              total_bytes_read_,
              " Received frames: ", ReceivedFramesDebugString());
          return QUIC_STREAM_SEQUENCER_INVALID_STATE;
        }
      }
    }
  }

  return QUIC_NO_ERROR;
}

int QuicStreamSequencerBuffer::GetReadableRegions(struct iovec* iov,
                                                  int iov_len) const {
  QUICHE_DCHECK(iov != nullptr);
  QUICHE_DCHECK_GT(iov_len, 0);

  if (ReadableBytes() == 0) {
    iov[0].iov_base = nullptr;
    iov[0].iov_len = 0;
    return 0;
  }

  size_t start_block_idx = NextBlockToRead();
  QuicStreamOffset readable_offset_end = FirstMissingByte() - 1;
  QUICHE_DCHECK_GE(readable_offset_end + 1, total_bytes_read_);
  size_t end_block_offset = GetInBlockOffset(readable_offset_end);
  size_t end_block_idx = GetBlockIndex(readable_offset_end);

  // If readable region is within one block, deal with it seperately.
  if (start_block_idx == end_block_idx && ReadOffset() <= end_block_offset) {
    iov[0].iov_base = blocks_[start_block_idx]->buffer + ReadOffset();
    iov[0].iov_len = ReadableBytes();
    QUIC_DVLOG(1) << "Got only a single block with index: " << start_block_idx;
    return 1;
  }

  // Get first block
  iov[0].iov_base = blocks_[start_block_idx]->buffer + ReadOffset();
  iov[0].iov_len = GetBlockCapacity(start_block_idx) - ReadOffset();
  QUIC_DVLOG(1) << "Got first block " << start_block_idx << " with len "
                << iov[0].iov_len;
  QUICHE_DCHECK_GT(readable_offset_end + 1, total_bytes_read_ + iov[0].iov_len)
      << "there should be more available data";

  // Get readable regions of the rest blocks till either 2nd to last block
  // before gap is met or |iov| is filled. For these blocks, one whole block is
  // a region.
  int iov_used = 1;
  size_t block_idx = (start_block_idx + iov_used) % max_blocks_count_;
  while (block_idx != end_block_idx && iov_used < iov_len) {
    QUICHE_DCHECK(nullptr != blocks_[block_idx]);
    iov[iov_used].iov_base = blocks_[block_idx]->buffer;
    iov[iov_used].iov_len = GetBlockCapacity(block_idx);
    QUIC_DVLOG(1) << "Got block with index: " << block_idx;
    ++iov_used;
    block_idx = (start_block_idx + iov_used) % max_blocks_count_;
  }

  // Deal with last block if |iov| can hold more.
  if (iov_used < iov_len) {
    QUICHE_DCHECK(nullptr != blocks_[block_idx]);
    iov[iov_used].iov_base = blocks_[end_block_idx]->buffer;
    iov[iov_used].iov_len = end_block_offset + 1;
    QUIC_DVLOG(1) << "Got last block with index: " << end_block_idx;
    ++iov_used;
  }
  return iov_used;
}

bool QuicStreamSequencerBuffer::GetReadableRegion(iovec* iov) const {
  return GetReadableRegions(iov, 1) == 1;
}

bool QuicStreamSequencerBuffer::PeekRegion(QuicStreamOffset offset,
                                           iovec* iov) const {
  QUICHE_DCHECK(iov);

  if (offset < total_bytes_read_) {
    // Data at |offset| has already been consumed.
    return false;
  }

  if (offset >= FirstMissingByte()) {
    // Data at |offset| has not been received yet.
    return false;
  }

  // Beginning of region.
  size_t block_idx = GetBlockIndex(offset);
  size_t block_offset = GetInBlockOffset(offset);
  iov->iov_base = blocks_[block_idx]->buffer + block_offset;

  // Determine if entire block has been received.
  size_t end_block_idx = GetBlockIndex(FirstMissingByte());
  if (block_idx == end_block_idx &&
      block_offset < GetInBlockOffset(FirstMissingByte())) {
    // If these 2 indexes point to the same block and the fist missing byte
    // offset is larger than the starting offset, this means data available
    // hasn't expanded to the next block yet.
    // Only read part of block before FirstMissingByte().
    iov->iov_len = GetInBlockOffset(FirstMissingByte()) - block_offset;
  } else {
    // Read entire block.
    iov->iov_len = GetBlockCapacity(block_idx) - block_offset;
  }

  QUIC_BUG_IF(quic_invalid_peek_region, iov->iov_len > kBlockSizeBytes)
      << "PeekRegion() at " << offset << " gets bad iov with length "
      << iov->iov_len;
  return true;
}

bool QuicStreamSequencerBuffer::MarkConsumed(size_t bytes_consumed) {
  if (bytes_consumed > ReadableBytes()) {
    return false;
  }
  size_t bytes_to_consume = bytes_consumed;
  while (bytes_to_consume > 0) {
    size_t block_idx = NextBlockToRead();
    size_t offset_in_block = ReadOffset();
    size_t bytes_available = std::min<size_t>(
        ReadableBytes(), GetBlockCapacity(block_idx) - offset_in_block);
    size_t bytes_read = std::min<size_t>(bytes_to_consume, bytes_available);
    total_bytes_read_ += bytes_read;
    num_bytes_buffered_ -= bytes_read;
    bytes_to_consume -= bytes_read;
    // If advanced to the end of current block and end of buffer hasn't wrapped
    // to this block yet.
    if (bytes_available == bytes_read) {
      RetireBlockIfEmpty(block_idx);
    }
  }

  return true;
}

size_t QuicStreamSequencerBuffer::FlushBufferedFrames() {
  size_t prev_total_bytes_read = total_bytes_read_;
  total_bytes_read_ = NextExpectedByte();
  Clear();
  return total_bytes_read_ - prev_total_bytes_read;
}

void QuicStreamSequencerBuffer::ReleaseWholeBuffer() {
  Clear();
  current_blocks_count_ = 0;
  blocks_.reset(nullptr);
}

size_t QuicStreamSequencerBuffer::ReadableBytes() const {
  return FirstMissingByte() - total_bytes_read_;
}

bool QuicStreamSequencerBuffer::HasBytesToRead() const {
  return ReadableBytes() > 0;
}

QuicStreamOffset QuicStreamSequencerBuffer::BytesConsumed() const {
  return total_bytes_read_;
}

size_t QuicStreamSequencerBuffer::BytesBuffered() const {
  return num_bytes_buffered_;
}

size_t QuicStreamSequencerBuffer::GetBlockIndex(QuicStreamOffset offset) const {
  return (offset % max_buffer_capacity_bytes_) / kBlockSizeBytes;
}

size_t QuicStreamSequencerBuffer::GetInBlockOffset(
    QuicStreamOffset offset) const {
  return (offset % max_buffer_capacity_bytes_) % kBlockSizeBytes;
}

size_t QuicStreamSequencerBuffer::ReadOffset() const {
  return GetInBlockOffset(total_bytes_read_);
}

size_t QuicStreamSequencerBuffer::NextBlockToRead() const {
  return GetBlockIndex(total_bytes_read_);
}

bool QuicStreamSequencerBuffer::RetireBlockIfEmpty(size_t block_index) {
  QUICHE_DCHECK(ReadableBytes() == 0 ||
                GetInBlockOffset(total_bytes_read_) == 0)
      << "RetireBlockIfEmpty() should only be called when advancing to next "
      << "block or a gap has been reached.";
  // If the whole buffer becomes empty, the last piece of data has been read.
  if (Empty()) {
    return RetireBlock(block_index);
  }

  // Check where the logical end of this buffer is.
  // Not empty if the end of circular buffer has been wrapped to this block.
  if (GetBlockIndex(NextExpectedByte() - 1) == block_index) {
    return true;
  }

  // Read index remains in this block, which means a gap has been reached.
  if (NextBlockToRead() == block_index) {
    if (bytes_received_.Size() > 1) {
      auto it = bytes_received_.begin();
      ++it;
      if (GetBlockIndex(it->min()) == block_index) {
        // Do not retire the block if next data interval is in this block.
        return true;
      }
    } else {
      QUIC_BUG(quic_bug_10610_2) << "Read stopped at where it shouldn't.";
      return false;
    }
  }
  return RetireBlock(block_index);
}

bool QuicStreamSequencerBuffer::Empty() const {
  return bytes_received_.Empty() ||
         (bytes_received_.Size() == 1 && total_bytes_read_ > 0 &&
          bytes_received_.begin()->max() == total_bytes_read_);
}

size_t QuicStreamSequencerBuffer::GetBlockCapacity(size_t block_index) const {
  if ((block_index + 1) == max_blocks_count_) {
    size_t result = max_buffer_capacity_bytes_ % kBlockSizeBytes;
    if (result == 0) {  // whole block
      result = kBlockSizeBytes;
    }
    return result;
  } else {
    return kBlockSizeBytes;
  }
}

std::string QuicStreamSequencerBuffer::ReceivedFramesDebugString() const {
  return bytes_received_.ToString();
}

QuicStreamOffset QuicStreamSequencerBuffer::FirstMissingByte() const {
  if (bytes_received_.Empty() || bytes_received_.begin()->min() > 0) {
    // Offset 0 is not received yet.
    return 0;
  }
  return bytes_received_.begin()->max();
}

QuicStreamOffset QuicStreamSequencerBuffer::NextExpectedByte() const {
  if (bytes_received_.Empty()) {
    return 0;
  }
  return bytes_received_.rbegin()->max();
}

}  //  namespace quic

"""

```