Response:
My goal is to analyze the provided C++ code snippet from Chromium's network stack and address the user's request comprehensively. Here's a breakdown of the thinking process:

1. **Understanding the Core Request:** The user wants to understand the functionality of `entry_impl.cc`, its relationship with JavaScript, logical inferences (with input/output examples), common user/programming errors, debugging steps, and a summary of its functionality (as this is part 1 of 2).

2. **Initial Code Scan and Keyword Recognition:**  I quickly scanned the code, looking for keywords and patterns that hint at its purpose. Key terms like "disk_cache," "entry," "IOBuffer," "read," "write," "sparse," "NetLog," "backend," and file-related operations immediately stand out. The `#include` directives also provide valuable context about dependencies.

3. **High-Level Functional Decomposition:** I started by breaking down the code into logical components based on class and method definitions. The main class, `EntryImpl`, is clearly the central focus. I identified its key member variables (like `entry_`, `node_`, `backend_`, `user_buffers_`, `sparse_`) and their likely roles.

4. **Detailed Analysis of Key Methods:** I then delved deeper into the crucial methods, such as:
    * `ReadDataImpl`, `WriteDataImpl`: These handle the core reading and writing of data streams. I noted the interaction with `IOBuffer` and the use of callbacks.
    * `ReadSparseDataImpl`, `WriteSparseDataImpl`, `GetAvailableRangeImpl`: These methods deal with sparse data storage. I recognized the `SparseControl` class as a key component.
    * `CreateEntry`, `IsSameEntry`:  These handle entry creation and key matching.
    * `DoomImpl`, `DeleteEntryData`:  These are responsible for entry deletion and cleanup.
    * `InternalReadData`, `InternalWriteData`: These are the lower-level implementations of data I/O, interacting directly with the file system.
    * The `UserBuffer` class:  I recognized this as a mechanism for buffering data in memory before writing to disk, likely for performance optimization.

5. **Identifying Core Functionalities:** Based on the method analysis, I began to list the core functionalities of `EntryImpl`:
    * Managing data storage and retrieval for individual cache entries.
    * Handling both regular data streams and sparse data.
    * Interacting with the underlying file system through the `BackendImpl`.
    * Maintaining metadata about cache entries (key, size, timestamps, etc.).
    * Supporting asynchronous I/O operations using callbacks.
    * Providing mechanisms for entry deletion and purging.
    * Implementing buffering to improve I/O efficiency.
    * Integrating with Chromium's NetLog system for debugging and monitoring.

6. **Addressing the JavaScript Relationship:**  This required understanding how the network stack interacts with the rendering engine (Blink), which executes JavaScript. I reasoned that while this specific C++ code doesn't directly *execute* JavaScript, it's crucial for caching resources (like scripts, images, etc.) that JavaScript relies on. The connection is indirect but fundamental. I looked for terms like "key," which could relate to URLs, a concept shared with JavaScript.

7. **Logical Inferences and Examples:** For methods like `PreWrite` and `PreRead` in `UserBuffer`, I formulated hypothetical input and output scenarios to illustrate their behavior. This involved considering different offsets, lengths, and buffer states.

8. **Identifying Common Errors:**  I thought about typical mistakes developers might make when interacting with a cache system: incorrect indices, invalid offsets/lengths, not handling I/O pending states, and issues with cache size limits.

9. **Debugging Steps and User Operations:**  I traced the likely user actions that would lead to this code being executed. This involved starting with a user request (like browsing a webpage) and following the chain of events through network requests, resource loading, and potential cache hits/misses.

10. **Summarizing Functionality (Part 1):** Based on the analysis, I formulated a concise summary of the file's purpose, focusing on its role as the in-memory representation of a disk cache entry.

11. **Structuring the Output:**  I organized the information into the categories requested by the user: functionality, JavaScript relationship, logical inferences, common errors, debugging steps, and summary. I used clear headings and bullet points to improve readability.

12. **Refinement and Review:** I reread my analysis to ensure accuracy, clarity, and completeness. I checked that the examples were logical and the explanations were easy to understand. I made sure to highlight the "part 1 of 2" aspect in the summary.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:** "This code directly interacts with JavaScript for caching."
* **Correction:** "While this code manages cached resources, it's a C++ component in the network stack. The interaction with JavaScript is indirect through the loading and utilization of these cached resources by the rendering engine." This refinement led to a more accurate explanation of the relationship.

By following this structured thinking process, combining code analysis with domain knowledge of web browsers and caching mechanisms, I could generate a comprehensive and accurate response to the user's request.
这是对 `net/disk_cache/blockfile/entry_impl.cc` 文件功能的详细分析，涵盖了您提出的所有方面。

**文件功能归纳 (作为第 1 部分的总结):**

`entry_impl.cc` 文件定义了 `EntryImpl` 类，它是 Chromium 网络栈磁盘缓存中一个缓存条目的核心实现。它的主要职责是：

1. **代表磁盘上的一个缓存条目:**  它封装了对磁盘上存储的实际缓存数据和元数据的访问和操作。
2. **管理缓存条目的生命周期:** 包括创建、读取、写入、删除（doom）、关闭等操作。
3. **处理数据 I/O:**  提供了读取和写入缓存条目数据的接口，包括对常规数据流和稀疏数据的支持。
4. **实现数据缓冲:**  使用 `UserBuffer` 类在内存中缓冲数据，以提高写入效率并支持部分写入。
5. **维护缓存条目的元数据:** 例如，键值、大小、最后使用时间、最后修改时间等。
6. **与后端缓存实现 (`BackendImpl`) 交互:** 依赖 `BackendImpl` 来执行实际的磁盘操作，管理块分配等。
7. **支持稀疏缓存:**  通过 `SparseControl` 类管理稀疏缓存条目的读写和空间管理。
8. **集成网络日志:**  使用 `net::NetLog` 记录缓存条目的操作，用于调试和监控。
9. **执行完整性检查:** 提供 `SanityCheck` 和 `DataSanityCheck` 方法来验证缓存条目的数据完整性。
10. **支持异步操作:**  利用回调函数 (`CompletionOnceCallback`) 处理耗时的磁盘 I/O 操作。

**详细功能列举:**

* **缓存条目的创建和销毁:**
    * `EntryImpl` 的构造函数根据地址初始化缓存条目。
    * `CreateEntry` 用于在磁盘上创建新的缓存条目，包括存储键值。
    * `DoomImpl` 将缓存条目标记为待删除状态。
    * `DeleteEntryData` 实际删除缓存条目的数据。
    * 析构函数 `~EntryImpl` 在条目不再被使用时执行清理工作，包括刷新缓冲区和保存稀疏数据信息。
* **数据读取和写入:**
    * `ReadDataImpl` 和 `WriteDataImpl` 是同步读取和写入数据的核心实现。
    * `InternalReadData` 和 `InternalWriteData` 执行底层的磁盘读取和写入操作。
    * `ReadSparseDataImpl` 和 `WriteSparseDataImpl` 处理稀疏数据的读写。
    * `GetAvailableRangeImpl` 获取稀疏数据中可用的数据范围。
* **数据缓冲 (`UserBuffer` 类):**
    * `UserBuffer` 在内存中缓存写入的数据，提高性能。
    * `PreWrite` 和 `PreRead` 判断缓冲区是否可以处理读写请求。
    * `Write` 将数据写入缓冲区。
    * `Read` 从缓冲区读取数据。
    * `Truncate` 截断缓冲区。
    * `Reset` 重置缓冲区。
* **元数据管理:**
    * `GetHash` 获取缓存条目的哈希值。
    * `GetKey` 获取缓存条目的键值。
    * `GetLastUsed` 和 `GetLastModified` 获取最后使用和修改时间。
    * `SetTimes` 设置最后使用和修改时间。
    * `GetDataSize` 获取数据流的大小。
* **缓存条目的状态管理:**
    * `IsSameEntry` 判断给定的键值和哈希是否与当前条目匹配。
    * `InternalDoom` 内部标记条目为已删除。
    * `Update` 更新条目的访问时间。
    * `SetDirtyFlag` 设置条目的脏标记。
    * `SetPointerForInvalidEntry` 为无效条目设置指针。
* **与后端交互:**
    * `backend_` 成员变量持有 `BackendImpl` 的弱指针，用于与后端进行交互。
    * 调用 `BackendImpl` 的方法来分配和释放磁盘空间、执行文件操作等。
* **稀疏缓存管理:**
    * `sparse_` 成员变量持有 `SparseControl` 对象，用于管理稀疏缓存条目。
    * `InitSparseData` 初始化稀疏数据管理。
    * `CancelSparseIOImpl` 取消稀疏数据的 I/O 操作。
    * `ReadyForSparseIOImpl` 检查稀疏数据是否准备好进行 I/O。
    * `CouldBeSparse` 判断条目是否可以是稀疏的。
* **网络日志记录:**
    * 使用 `net::NetLog` 记录缓存条目的各种操作，方便调试和监控。
    * 例如，在 `ReadDataImpl` 和 `WriteDataImpl` 中记录读写操作的开始和结束。
* **完整性检查:**
    * `SanityCheck` 检查缓存条目的基本结构和元数据是否一致。
    * `DataSanityCheck` 检查缓存条目的数据完整性，例如键值哈希是否匹配。
    * `FixForDelete` 在删除前修复可能存在的错误。
* **异步操作管理:**
    * 使用 `CompletionOnceCallback` 回调函数来处理异步 I/O 操作的结果。
    * `SyncCallback` 是一个辅助类，用于将文件 I/O 回调转换为 `net::CompletionOnceCallback`。
* **后台队列处理:**
    * `background_queue_` 成员变量持有后台队列的指针，用于将一些操作放到后台线程执行，例如 `Doom` 和 `Close`。

**与 JavaScript 的关系:**

`entry_impl.cc` 本身是用 C++ 编写的，并不直接执行 JavaScript 代码。然而，它在幕后支持着 Web 浏览器中 JavaScript 的功能，具体体现在以下几个方面：

1. **缓存 HTTP 资源:** 当浏览器加载网页时，JavaScript 文件、CSS 文件、图片和其他资源会被下载。`EntryImpl` 负责将这些资源缓存到磁盘上。当 JavaScript 代码尝试加载这些资源时，缓存可以提供快速的访问，而无需再次从网络下载。
2. **Service Worker 缓存:** Service Workers 允许 JavaScript 代码拦截网络请求并提供自定义的响应。`EntryImpl` 可以作为 Service Worker API 中 `CacheStorage` 的底层存储机制，用于缓存 JavaScript 可以控制的资源。
3. **Cache API:**  JavaScript 提供了 Cache API，允许网页将网络请求的响应存储在缓存中。`EntryImpl` 同样可以作为 Cache API 的底层实现。

**举例说明:**

假设一个用户访问了一个包含以下 JavaScript 代码的网页：

```javascript
fetch('/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段代码执行时，浏览器会发起对 `/data.json` 的网络请求。

* **假设这是第一次访问:**  浏览器会从服务器下载 `data.json`。`EntryImpl` 的相关代码会被调用，创建一个新的缓存条目，并将 `data.json` 的内容写入到磁盘上的缓存文件中。
* **假设这是第二次访问 (且缓存有效):**  当 JavaScript 代码再次执行 `fetch('/data.json')` 时，Chromium 的网络栈会首先检查缓存。`EntryImpl` 的读取功能会被调用，从磁盘上的缓存文件中读取 `data.json` 的内容，并将其返回给 JavaScript 代码，从而避免了网络请求。

**逻辑推理与假设输入输出:**

以 `UserBuffer::PreWrite` 方法为例：

**假设输入:**

* `offset`: 1000 (要写入数据的起始偏移量)
* `len`: 500 (要写入的数据长度)
* 当前 `UserBuffer` 的状态:
    * `offset_`: 500 (缓冲区的起始偏移量)
    * `buffer_.size()`: 800 (缓冲区当前数据大小)
    * `buffer_.capacity()`: 1500 (缓冲区当前容量)

**逻辑推理:**

1. `offset` (1000) 大于 `offset_` (500)，因此写入位置在缓冲区之后。
2. 计算写入结束位置：`offset + len` = 1000 + 500 = 1500。
3. 检查写入结束位置是否在缓冲区容量之内：1500 <= 1500。

**输出:**

* `PreWrite` 返回 `true`，表示缓冲区可以处理此次写入。

**假设输入 (不同的情况):**

* `offset`: 100 (要写入数据的起始偏移量)
* `len`: 200 (要写入的数据长度)
* 当前 `UserBuffer` 的状态:
    * `offset_`: 500
    * `buffer_.size()`: 800
    * `buffer_.capacity()`: 1500

**逻辑推理:**

1. `offset` (100) 小于 `offset_` (500)，表示要写入的位置在缓冲区之前。

**输出:**

* `PreWrite` 返回 `false`，表示缓冲区不能处理此次写入。

**用户或编程常见的使用错误:**

1. **错误的索引:** 在调用 `ReadData` 或 `WriteData` 时，使用了超出 `kNumStreams` 范围的 `index` 值。这会导致 `net::ERR_INVALID_ARGUMENT` 错误。
   ```c++
   // 错误示例：假设 kNumStreams 为 3
   entry->ReadData(5, 0, buffer, 100, callback); // 索引 5 超出范围
   ```
2. **无效的偏移量或长度:**  传递给 `ReadData` 或 `WriteData` 的 `offset` 或 `buf_len` 为负数，或者 `offset` 大于缓存条目的实际大小。这同样会导致 `net::ERR_INVALID_ARGUMENT` 错误。
   ```c++
   entry->ReadData(0, -10, buffer, 100, callback); // 负偏移量
   entry->WriteData(0, 0, buffer, -50, callback, false); // 负长度
   ```
3. **在条目被删除后尝试访问:** 用户代码可能持有指向 `EntryImpl` 对象的指针，但在该条目被标记为删除 (`Doom`) 或实际删除后，仍然尝试调用其方法。这会导致未定义的行为或崩溃。
4. **没有正确处理异步操作:** 调用 `ReadData` 或 `WriteData` 时，如果没有提供回调函数，或者没有正确处理 `net::ERR_IO_PENDING` 的情况，会导致数据读取或写入不完整。
5. **假设缓存总是存在:**  代码可能没有处理缓存操作失败的情况，例如磁盘空间不足、文件系统错误等。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中输入 URL 或点击链接:** 这会触发一个网络请求。
2. **Chromium 网络栈处理请求:**  网络栈会检查是否可以从缓存中获取资源。
3. **缓存查找:**  缓存系统会根据请求的 URL (或其他标识符) 查找对应的缓存条目。这可能涉及到哈希计算和索引查找。
4. **找到匹配的缓存条目 (如果存在):**
   * **读取缓存数据:** 如果需要读取缓存的数据，例如渲染网页或执行 JavaScript，则会调用 `EntryImpl` 的 `ReadData` 或 `ReadSparseData` 方法。
   * **更新缓存元数据:**  访问缓存条目可能会更新其最后使用时间，调用 `EntryImpl` 的 `Update` 或 `SetTimes` 方法。
5. **没有找到匹配的缓存条目:**
   * **下载资源:**  网络栈会从服务器下载资源。
   * **创建缓存条目:** 下载完成后，会调用 `EntryImpl` 的 `CreateEntry` 方法创建一个新的缓存条目。
   * **写入缓存数据:**  下载的资源数据会通过 `EntryImpl` 的 `WriteData` 或 `WriteSparseData` 方法写入到磁盘。
6. **用户关闭标签页或浏览器:**  这可能导致缓存条目被关闭，调用 `EntryImpl` 的 `Close` 方法，或者在某些情况下，如果缓存策略需要清理，可能会调用 `Doom` 和 `DeleteEntryData` 方法。
7. **缓存策略触发清理:**  当缓存空间达到限制时，缓存系统会根据一定的策略 (例如 LRU) 删除一些不常用的缓存条目，这会调用 `EntryImpl` 的 `Doom` 和 `DeleteEntryData` 方法。

**调试线索:**

当你在调试网络相关问题，特别是与缓存有关的问题时，可以关注以下几点：

* **网络日志 (net-internals):**  Chromium 提供了 `chrome://net-internals/#events` 页面，可以查看详细的网络事件日志，包括缓存相关的操作，例如缓存命中、未命中、条目创建、读取、写入等。这些日志会显示哪些 `EntryImpl` 的方法被调用。
* **断点调试:**  在 `entry_impl.cc` 的关键方法上设置断点，例如 `ReadDataImpl`, `WriteDataImpl`, `CreateEntry`, `DoomImpl`, 等。当代码执行到这些断点时，你可以检查缓存条目的状态、数据内容以及与后端缓存的交互情况。
* **条件断点:**  结合网络日志中的信息，设置条件断点，例如只在访问特定 URL 的缓存条目时中断，可以更精确地定位问题。
* **查看缓存文件:**  在知道缓存文件的路径后，可以尝试查看磁盘上的缓存文件内容，以验证 `EntryImpl` 是否正确地写入了数据。但需要注意缓存文件的格式可能比较复杂。
* **检查 `BackendImpl` 的行为:**  `EntryImpl` 依赖于 `BackendImpl` 来执行实际的磁盘操作。因此，如果怀疑是底层缓存实现的问题，可以同时调试 `BackendImpl` 相关的代码。

希望以上分析能够帮助你理解 `net/disk_cache/blockfile/entry_impl.cc` 文件的功能和作用。如果你有更具体的问题或场景，欢迎继续提问。

Prompt: 
```
这是目录为net/disk_cache/blockfile/entry_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/blockfile/entry_impl.h"

#include <limits>
#include <memory>

#include "base/files/file_util.h"
#include "base/hash/hash.h"
#include "base/numerics/safe_math.h"
#include "base/strings/string_util.h"
#include "base/time/time.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/bitmap.h"
#include "net/disk_cache/blockfile/disk_format.h"
#include "net/disk_cache/blockfile/sparse_control.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/net_log_parameters.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"

using base::Time;
using base::TimeTicks;

namespace {

// Index for the file used to store the key, if any (files_[kKeyFileIndex]).
const int kKeyFileIndex = 3;

// This class implements FileIOCallback to buffer the callback from a file IO
// operation from the actual net class.
class SyncCallback: public disk_cache::FileIOCallback {
 public:
  // |end_event_type| is the event type to log on completion.  Logs nothing on
  // discard, or when the NetLog is not set to log all events.
  SyncCallback(scoped_refptr<disk_cache::EntryImpl> entry,
               net::IOBuffer* buffer,
               net::CompletionOnceCallback callback,
               net::NetLogEventType end_event_type)
      : entry_(std::move(entry)),
        callback_(std::move(callback)),
        buf_(buffer),
        end_event_type_(end_event_type) {
    entry_->IncrementIoCount();
  }

  SyncCallback(const SyncCallback&) = delete;
  SyncCallback& operator=(const SyncCallback&) = delete;

  ~SyncCallback() override = default;

  void OnFileIOComplete(int bytes_copied) override;
  void Discard();

 private:
  scoped_refptr<disk_cache::EntryImpl> entry_;
  net::CompletionOnceCallback callback_;
  scoped_refptr<net::IOBuffer> buf_;
  const net::NetLogEventType end_event_type_;
};

void SyncCallback::OnFileIOComplete(int bytes_copied) {
  entry_->DecrementIoCount();
  if (!callback_.is_null()) {
    if (entry_->net_log().IsCapturing()) {
      disk_cache::NetLogReadWriteComplete(entry_->net_log(), end_event_type_,
                                          net::NetLogEventPhase::END,
                                          bytes_copied);
    }
    buf_ = nullptr;  // Release the buffer before invoking the callback.
    std::move(callback_).Run(bytes_copied);
  }
  delete this;
}

void SyncCallback::Discard() {
  callback_.Reset();
  buf_ = nullptr;
  OnFileIOComplete(0);
}

const int kMaxBufferSize = 1024 * 1024;  // 1 MB.

}  // namespace

namespace disk_cache {

// This class handles individual memory buffers that store data before it is
// sent to disk. The buffer can start at any offset, but if we try to write to
// anywhere in the first 16KB of the file (kMaxBlockSize), we set the offset to
// zero. The buffer grows up to a size determined by the backend, to keep the
// total memory used under control.
class EntryImpl::UserBuffer {
 public:
  explicit UserBuffer(BackendImpl* backend) : backend_(backend->GetWeakPtr()) {
    buffer_.reserve(kMaxBlockSize);
  }

  UserBuffer(const UserBuffer&) = delete;
  UserBuffer& operator=(const UserBuffer&) = delete;

  ~UserBuffer() {
    if (backend_.get())
      backend_->BufferDeleted(capacity() - kMaxBlockSize);
  }

  // Returns true if we can handle writing |len| bytes to |offset|.
  bool PreWrite(int offset, int len);

  // Truncates the buffer to |offset| bytes.
  void Truncate(int offset);

  // Writes |len| bytes from |buf| at the given |offset|.
  void Write(int offset, IOBuffer* buf, int len);

  // Returns true if we can read |len| bytes from |offset|, given that the
  // actual file has |eof| bytes stored. Note that the number of bytes to read
  // may be modified by this method even though it returns false: that means we
  // should do a smaller read from disk.
  bool PreRead(int eof, int offset, int* len);

  // Read |len| bytes from |buf| at the given |offset|.
  int Read(int offset, IOBuffer* buf, int len);

  // Prepare this buffer for reuse.
  void Reset();

  char* Data() { return buffer_.data(); }
  int Size() { return static_cast<int>(buffer_.size()); }
  int Start() { return offset_; }
  int End() { return offset_ + Size(); }

 private:
  int capacity() { return static_cast<int>(buffer_.capacity()); }
  bool GrowBuffer(int required, int limit);

  base::WeakPtr<BackendImpl> backend_;
  int offset_ = 0;
  std::vector<char> buffer_;
  bool grow_allowed_ = true;
};

bool EntryImpl::UserBuffer::PreWrite(int offset, int len) {
  DCHECK_GE(offset, 0);
  DCHECK_GE(len, 0);
  DCHECK_GE(offset + len, 0);

  // We don't want to write before our current start.
  if (offset < offset_)
    return false;

  // Lets get the common case out of the way.
  if (offset + len <= capacity())
    return true;

  // If we are writing to the first 16K (kMaxBlockSize), we want to keep the
  // buffer offset_ at 0.
  if (!Size() && offset > kMaxBlockSize)
    return GrowBuffer(len, kMaxBufferSize);

  int required = offset - offset_ + len;
  return GrowBuffer(required, kMaxBufferSize * 6 / 5);
}

void EntryImpl::UserBuffer::Truncate(int offset) {
  DCHECK_GE(offset, 0);
  DCHECK_GE(offset, offset_);
  DVLOG(3) << "Buffer truncate at " << offset << " current " << offset_;

  offset -= offset_;
  if (Size() >= offset)
    buffer_.resize(offset);
}

void EntryImpl::UserBuffer::Write(int offset, IOBuffer* buf, int len) {
  DCHECK_GE(offset, 0);
  DCHECK_GE(len, 0);
  DCHECK_GE(offset + len, 0);

  // 0-length writes that don't extend can just be ignored here, and are safe
  // even if they're are before offset_, as truncates are handled elsewhere.
  if (len == 0 && offset < End())
    return;

  DCHECK_GE(offset, offset_);
  DVLOG(3) << "Buffer write at " << offset << " current " << offset_;

  if (!Size() && offset > kMaxBlockSize)
    offset_ = offset;

  offset -= offset_;

  if (offset > Size())
    buffer_.resize(offset);

  if (!len)
    return;

  char* buffer = buf->data();
  int valid_len = Size() - offset;
  int copy_len = std::min(valid_len, len);
  if (copy_len) {
    memcpy(&buffer_[offset], buffer, copy_len);
    len -= copy_len;
    buffer += copy_len;
  }
  if (!len)
    return;

  buffer_.insert(buffer_.end(), buffer, buffer + len);
}

bool EntryImpl::UserBuffer::PreRead(int eof, int offset, int* len) {
  DCHECK_GE(offset, 0);
  DCHECK_GT(*len, 0);

  if (offset < offset_) {
    // We are reading before this buffer.
    if (offset >= eof)
      return true;

    // If the read overlaps with the buffer, change its length so that there is
    // no overlap.
    *len = std::min(*len, offset_ - offset);
    *len = std::min(*len, eof - offset);

    // We should read from disk.
    return false;
  }

  if (!Size())
    return false;

  // See if we can fulfill the first part of the operation.
  return (offset - offset_ < Size());
}

int EntryImpl::UserBuffer::Read(int offset, IOBuffer* buf, int len) {
  DCHECK_GE(offset, 0);
  DCHECK_GT(len, 0);
  DCHECK(Size() || offset < offset_);

  int clean_bytes = 0;
  if (offset < offset_) {
    // We don't have a file so lets fill the first part with 0.
    clean_bytes = std::min(offset_ - offset, len);
    memset(buf->data(), 0, clean_bytes);
    if (len == clean_bytes)
      return len;
    offset = offset_;
    len -= clean_bytes;
  }

  int start = offset - offset_;
  int available = Size() - start;
  DCHECK_GE(start, 0);
  DCHECK_GE(available, 0);
  len = std::min(len, available);
  memcpy(buf->data() + clean_bytes, &buffer_[start], len);
  return len + clean_bytes;
}

void EntryImpl::UserBuffer::Reset() {
  if (!grow_allowed_) {
    if (backend_.get())
      backend_->BufferDeleted(capacity() - kMaxBlockSize);
    grow_allowed_ = true;
    std::vector<char> tmp;
    buffer_.swap(tmp);
    buffer_.reserve(kMaxBlockSize);
  }
  offset_ = 0;
  buffer_.clear();
}

bool EntryImpl::UserBuffer::GrowBuffer(int required, int limit) {
  DCHECK_GE(required, 0);
  int current_size = capacity();
  if (required <= current_size)
    return true;

  if (required > limit)
    return false;

  if (!backend_.get())
    return false;

  int to_add = std::max(required - current_size, kMaxBlockSize * 4);
  to_add = std::max(current_size, to_add);
  required = std::min(current_size + to_add, limit);

  grow_allowed_ = backend_->IsAllocAllowed(current_size, required);
  if (!grow_allowed_)
    return false;

  DVLOG(3) << "Buffer grow to " << required;

  buffer_.reserve(required);
  return true;
}

// ------------------------------------------------------------------------

EntryImpl::EntryImpl(BackendImpl* backend, Addr address, bool read_only)
    : entry_(nullptr, Addr(0)),
      node_(nullptr, Addr(0)),
      backend_(backend->GetWeakPtr()),
      read_only_(read_only) {
  entry_.LazyInit(backend->File(address), address);
}

void EntryImpl::DoomImpl() {
  if (doomed_ || !backend_.get())
    return;

  SetPointerForInvalidEntry(backend_->GetCurrentEntryId());
  backend_->InternalDoomEntry(this);
}

int EntryImpl::ReadDataImpl(int index,
                            int offset,
                            IOBuffer* buf,
                            int buf_len,
                            CompletionOnceCallback callback) {
  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(net_log_, net::NetLogEventType::ENTRY_READ_DATA,
                        net::NetLogEventPhase::BEGIN, index, offset, buf_len,
                        false);
  }

  int result =
      InternalReadData(index, offset, buf, buf_len, std::move(callback));

  if (result != net::ERR_IO_PENDING && net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_, net::NetLogEventType::ENTRY_READ_DATA,
                            net::NetLogEventPhase::END, result);
  }
  return result;
}

int EntryImpl::WriteDataImpl(int index,
                             int offset,
                             IOBuffer* buf,
                             int buf_len,
                             CompletionOnceCallback callback,
                             bool truncate) {
  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(net_log_, net::NetLogEventType::ENTRY_WRITE_DATA,
                        net::NetLogEventPhase::BEGIN, index, offset, buf_len,
                        truncate);
  }

  int result = InternalWriteData(index, offset, buf, buf_len,
                                 std::move(callback), truncate);

  if (result != net::ERR_IO_PENDING && net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_, net::NetLogEventType::ENTRY_WRITE_DATA,
                            net::NetLogEventPhase::END, result);
  }
  return result;
}

int EntryImpl::ReadSparseDataImpl(int64_t offset,
                                  IOBuffer* buf,
                                  int buf_len,
                                  CompletionOnceCallback callback) {
  DCHECK(node_.Data()->dirty || read_only_);
  int result = InitSparseData();
  if (net::OK != result)
    return result;

  result = sparse_->StartIO(SparseControl::kReadOperation, offset, buf, buf_len,
                            std::move(callback));
  return result;
}

int EntryImpl::WriteSparseDataImpl(int64_t offset,
                                   IOBuffer* buf,
                                   int buf_len,
                                   CompletionOnceCallback callback) {
  DCHECK(node_.Data()->dirty || read_only_);
  int result = InitSparseData();
  if (net::OK != result)
    return result;

  result = sparse_->StartIO(SparseControl::kWriteOperation, offset, buf,
                            buf_len, std::move(callback));
  return result;
}

RangeResult EntryImpl::GetAvailableRangeImpl(int64_t offset, int len) {
  int result = InitSparseData();
  if (net::OK != result)
    return RangeResult(static_cast<net::Error>(result));

  return sparse_->GetAvailableRange(offset, len);
}

void EntryImpl::CancelSparseIOImpl() {
  if (!sparse_.get())
    return;

  sparse_->CancelIO();
}

int EntryImpl::ReadyForSparseIOImpl(CompletionOnceCallback callback) {
  DCHECK(sparse_.get());
  return sparse_->ReadyToUse(std::move(callback));
}

uint32_t EntryImpl::GetHash() {
  return entry_.Data()->hash;
}

bool EntryImpl::CreateEntry(Addr node_address,
                            const std::string& key,
                            uint32_t hash) {
  EntryStore* entry_store = entry_.Data();
  RankingsNode* node = node_.Data();
  memset(entry_store, 0, sizeof(EntryStore) * entry_.address().num_blocks());
  memset(node, 0, sizeof(RankingsNode));
  if (!node_.LazyInit(backend_->File(node_address), node_address))
    return false;

  entry_store->rankings_node = node_address.value();
  node->contents = entry_.address().value();

  entry_store->hash = hash;
  entry_store->creation_time = Time::Now().ToInternalValue();
  entry_store->key_len = static_cast<int32_t>(key.size());
  if (entry_store->key_len > kMaxInternalKeyLength) {
    Addr address(0);
    if (!CreateBlock(entry_store->key_len + 1, &address))
      return false;

    entry_store->long_key = address.value();
    File* key_file = GetBackingFile(address, kKeyFileIndex);
    key_ = key;

    size_t offset = 0;
    if (address.is_block_file())
      offset = address.start_block() * address.BlockSize() + kBlockHeaderSize;

    if (!key_file || !key_file->Write(key.data(), key.size() + 1, offset)) {
      DeleteData(address, kKeyFileIndex);
      return false;
    }

    if (address.is_separate_file())
      key_file->SetLength(key.size() + 1);
  } else {
    memcpy(entry_store->key, key.data(), key.size());
    entry_store->key[key.size()] = '\0';
  }
  backend_->ModifyStorageSize(0, static_cast<int32_t>(key.size()));
  node->dirty = backend_->GetCurrentEntryId();
  return true;
}

bool EntryImpl::IsSameEntry(const std::string& key, uint32_t hash) {
  if (entry_.Data()->hash != hash ||
      static_cast<size_t>(entry_.Data()->key_len) != key.size())
    return false;

  return (key.compare(GetKey()) == 0);
}

void EntryImpl::InternalDoom() {
  net_log_.AddEvent(net::NetLogEventType::ENTRY_DOOM);
  DCHECK(node_.HasData());
  if (!node_.Data()->dirty) {
    node_.Data()->dirty = backend_->GetCurrentEntryId();
    node_.Store();
  }
  doomed_ = true;
}

void EntryImpl::DeleteEntryData(bool everything) {
  DCHECK(doomed_ || !everything);

  if (GetEntryFlags() & PARENT_ENTRY) {
    // We have some child entries that must go away.
    SparseControl::DeleteChildren(this);
  }

  for (int index = 0; index < kNumStreams; index++) {
    Addr address(entry_.Data()->data_addr[index]);
    if (address.is_initialized()) {
      backend_->ModifyStorageSize(entry_.Data()->data_size[index] -
                                      unreported_size_[index], 0);
      entry_.Data()->data_addr[index] = 0;
      entry_.Data()->data_size[index] = 0;
      entry_.Store();
      DeleteData(address, index);
    }
  }

  if (!everything)
    return;

  // Remove all traces of this entry.
  backend_->RemoveEntry(this);

  // Note that at this point node_ and entry_ are just two blocks of data, and
  // even if they reference each other, nobody should be referencing them.

  Addr address(entry_.Data()->long_key);
  DeleteData(address, kKeyFileIndex);
  backend_->ModifyStorageSize(entry_.Data()->key_len, 0);

  backend_->DeleteBlock(entry_.address(), true);
  entry_.Discard();

  if (!LeaveRankingsBehind()) {
    backend_->DeleteBlock(node_.address(), true);
    node_.Discard();
  }
}

CacheAddr EntryImpl::GetNextAddress() {
  return entry_.Data()->next;
}

void EntryImpl::SetNextAddress(Addr address) {
  DCHECK_NE(address.value(), entry_.address().value());
  entry_.Data()->next = address.value();
  bool success = entry_.Store();
  DCHECK(success);
}

bool EntryImpl::LoadNodeAddress() {
  Addr address(entry_.Data()->rankings_node);
  if (!node_.LazyInit(backend_->File(address), address))
    return false;
  return node_.Load();
}

bool EntryImpl::Update() {
  DCHECK(node_.HasData());

  if (read_only_)
    return true;

  RankingsNode* rankings = node_.Data();
  if (!rankings->dirty) {
    rankings->dirty = backend_->GetCurrentEntryId();
    if (!node_.Store())
      return false;
  }
  return true;
}

void EntryImpl::SetDirtyFlag(int32_t current_id) {
  DCHECK(node_.HasData());
  if (node_.Data()->dirty && current_id != node_.Data()->dirty)
    dirty_ = true;

  if (!current_id)
    dirty_ = true;
}

void EntryImpl::SetPointerForInvalidEntry(int32_t new_id) {
  node_.Data()->dirty = new_id;
  node_.Store();
}

bool EntryImpl::LeaveRankingsBehind() {
  return !node_.Data()->contents;
}

// This only includes checks that relate to the first block of the entry (the
// first 256 bytes), and values that should be set from the entry creation.
// Basically, even if there is something wrong with this entry, we want to see
// if it is possible to load the rankings node and delete them together.
bool EntryImpl::SanityCheck() {
  if (!entry_.VerifyHash())
    return false;

  EntryStore* stored = entry_.Data();
  if (!stored->rankings_node || stored->key_len <= 0)
    return false;

  if (stored->reuse_count < 0 || stored->refetch_count < 0)
    return false;

  Addr rankings_addr(stored->rankings_node);
  if (!rankings_addr.SanityCheckForRankings())
    return false;

  Addr next_addr(stored->next);
  if (next_addr.is_initialized() && !next_addr.SanityCheckForEntry()) {
    STRESS_NOTREACHED();
    return false;
  }
  STRESS_DCHECK(next_addr.value() != entry_.address().value());

  if (stored->state > ENTRY_DOOMED || stored->state < ENTRY_NORMAL)
    return false;

  Addr key_addr(stored->long_key);
  if ((stored->key_len <= kMaxInternalKeyLength && key_addr.is_initialized()) ||
      (stored->key_len > kMaxInternalKeyLength && !key_addr.is_initialized()))
    return false;

  if (!key_addr.SanityCheck())
    return false;

  if (key_addr.is_initialized() &&
      ((stored->key_len < kMaxBlockSize && key_addr.is_separate_file()) ||
       (stored->key_len >= kMaxBlockSize && key_addr.is_block_file())))
    return false;

  int num_blocks = NumBlocksForEntry(stored->key_len);
  if (entry_.address().num_blocks() != num_blocks)
    return false;

  return true;
}

bool EntryImpl::DataSanityCheck() {
  EntryStore* stored = entry_.Data();
  Addr key_addr(stored->long_key);

  // The key must be NULL terminated.
  if (!key_addr.is_initialized() && stored->key[stored->key_len])
    return false;

  if (stored->hash != base::PersistentHash(GetKey()))
    return false;

  for (int i = 0; i < kNumStreams; i++) {
    Addr data_addr(stored->data_addr[i]);
    int data_size = stored->data_size[i];
    if (data_size < 0)
      return false;
    if (!data_size && data_addr.is_initialized())
      return false;
    if (!data_addr.SanityCheck())
      return false;
    if (!data_size)
      continue;
    if (data_size <= kMaxBlockSize && data_addr.is_separate_file())
      return false;
    if (data_size > kMaxBlockSize && data_addr.is_block_file())
      return false;
  }
  return true;
}

void EntryImpl::FixForDelete() {
  EntryStore* stored = entry_.Data();
  Addr key_addr(stored->long_key);

  if (!key_addr.is_initialized())
    stored->key[stored->key_len] = '\0';

  for (int i = 0; i < kNumStreams; i++) {
    Addr data_addr(stored->data_addr[i]);
    int data_size = stored->data_size[i];
    if (data_addr.is_initialized()) {
      if ((data_size <= kMaxBlockSize && data_addr.is_separate_file()) ||
          (data_size > kMaxBlockSize && data_addr.is_block_file()) ||
          !data_addr.SanityCheck()) {
        STRESS_NOTREACHED();
        // The address is weird so don't attempt to delete it.
        stored->data_addr[i] = 0;
        // In general, trust the stored size as it should be in sync with the
        // total size tracked by the backend.
      }
    }
    if (data_size < 0)
      stored->data_size[i] = 0;
  }
  entry_.Store();
}

void EntryImpl::IncrementIoCount() {
  backend_->IncrementIoCount();
}

void EntryImpl::DecrementIoCount() {
  if (backend_.get())
    backend_->DecrementIoCount();
}

void EntryImpl::OnEntryCreated(BackendImpl* backend) {
  // Just grab a reference to the backround queue.
  background_queue_ = backend->GetBackgroundQueue();
}

void EntryImpl::SetTimes(base::Time last_used, base::Time last_modified) {
  node_.Data()->last_used = last_used.ToInternalValue();
  node_.Data()->last_modified = last_modified.ToInternalValue();
  node_.set_modified();
}

void EntryImpl::BeginLogging(net::NetLog* net_log, bool created) {
  DCHECK(!net_log_.net_log());
  net_log_ = net::NetLogWithSource::Make(
      net_log, net::NetLogSourceType::DISK_CACHE_ENTRY);
  net_log_.BeginEvent(net::NetLogEventType::DISK_CACHE_ENTRY_IMPL, [&] {
    return CreateNetLogParametersEntryCreationParams(this, created);
  });
}

const net::NetLogWithSource& EntryImpl::net_log() const {
  return net_log_;
}

// static
int EntryImpl::NumBlocksForEntry(int key_size) {
  // The longest key that can be stored using one block.
  int key1_len =
      static_cast<int>(sizeof(EntryStore) - offsetof(EntryStore, key));

  if (key_size < key1_len || key_size > kMaxInternalKeyLength)
    return 1;

  return ((key_size - key1_len) / 256 + 2);
}

// ------------------------------------------------------------------------

void EntryImpl::Doom() {
  if (background_queue_.get())
    background_queue_->DoomEntryImpl(this);
}

void EntryImpl::Close() {
  if (background_queue_.get())
    background_queue_->CloseEntryImpl(this);
}

std::string EntryImpl::GetKey() const {
  CacheEntryBlock* entry = const_cast<CacheEntryBlock*>(&entry_);
  int key_len = entry->Data()->key_len;
  if (key_len <= kMaxInternalKeyLength)
    return std::string(entry->Data()->key, key_len);

  // We keep a copy of the key so that we can always return it, even if the
  // backend is disabled.
  if (!key_.empty())
    return key_;

  Addr address(entry->Data()->long_key);
  DCHECK(address.is_initialized());
  size_t offset = 0;
  if (address.is_block_file())
    offset = address.start_block() * address.BlockSize() + kBlockHeaderSize;

  static_assert(kNumStreams == kKeyFileIndex, "invalid key index");
  File* key_file = const_cast<EntryImpl*>(this)->GetBackingFile(address,
                                                                kKeyFileIndex);
  if (!key_file)
    return std::string();

  // We store a trailing \0 on disk.
  if (!offset && key_file->GetLength() != static_cast<size_t>(key_len + 1)) {
    return std::string();
  }

  // Do not attempt read up to the expected on-disk '\0' --- which would be
  // |key_len + 1| bytes total --- as if due to a corrupt file it isn't |key_|
  // would get its internal nul messed up.
  key_.resize(key_len);
  if (!key_file->Read(key_.data(), key_.size(), offset)) {
    key_.clear();
  }
  DCHECK_LE(strlen(key_.data()), static_cast<size_t>(key_len));
  return key_;
}

Time EntryImpl::GetLastUsed() const {
  CacheRankingsBlock* node = const_cast<CacheRankingsBlock*>(&node_);
  return Time::FromInternalValue(node->Data()->last_used);
}

Time EntryImpl::GetLastModified() const {
  CacheRankingsBlock* node = const_cast<CacheRankingsBlock*>(&node_);
  return Time::FromInternalValue(node->Data()->last_modified);
}

int32_t EntryImpl::GetDataSize(int index) const {
  if (index < 0 || index >= kNumStreams)
    return 0;

  CacheEntryBlock* entry = const_cast<CacheEntryBlock*>(&entry_);
  return entry->Data()->data_size[index];
}

int EntryImpl::ReadData(int index,
                        int offset,
                        IOBuffer* buf,
                        int buf_len,
                        CompletionOnceCallback callback) {
  if (callback.is_null())
    return ReadDataImpl(index, offset, buf, buf_len, std::move(callback));

  DCHECK(node_.Data()->dirty || read_only_);
  if (index < 0 || index >= kNumStreams)
    return net::ERR_INVALID_ARGUMENT;

  int entry_size = entry_.Data()->data_size[index];
  if (offset >= entry_size || offset < 0 || !buf_len)
    return 0;

  if (buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  if (!background_queue_.get())
    return net::ERR_UNEXPECTED;

  background_queue_->ReadData(this, index, offset, buf, buf_len,
                              std::move(callback));
  return net::ERR_IO_PENDING;
}

int EntryImpl::WriteData(int index,
                         int offset,
                         IOBuffer* buf,
                         int buf_len,
                         CompletionOnceCallback callback,
                         bool truncate) {
  if (callback.is_null()) {
    return WriteDataImpl(index, offset, buf, buf_len, std::move(callback),
                         truncate);
  }

  DCHECK(node_.Data()->dirty || read_only_);
  if (index < 0 || index >= kNumStreams)
    return net::ERR_INVALID_ARGUMENT;

  if (offset < 0 || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  if (!background_queue_.get())
    return net::ERR_UNEXPECTED;

  background_queue_->WriteData(this, index, offset, buf, buf_len, truncate,
                               std::move(callback));
  return net::ERR_IO_PENDING;
}

int EntryImpl::ReadSparseData(int64_t offset,
                              IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  if (callback.is_null())
    return ReadSparseDataImpl(offset, buf, buf_len, std::move(callback));

  if (!background_queue_.get())
    return net::ERR_UNEXPECTED;

  background_queue_->ReadSparseData(this, offset, buf, buf_len,
                                    std::move(callback));
  return net::ERR_IO_PENDING;
}

int EntryImpl::WriteSparseData(int64_t offset,
                               IOBuffer* buf,
                               int buf_len,
                               CompletionOnceCallback callback) {
  if (callback.is_null())
    return WriteSparseDataImpl(offset, buf, buf_len, std::move(callback));

  if (!background_queue_.get())
    return net::ERR_UNEXPECTED;

  background_queue_->WriteSparseData(this, offset, buf, buf_len,
                                     std::move(callback));
  return net::ERR_IO_PENDING;
}

RangeResult EntryImpl::GetAvailableRange(int64_t offset,
                                         int len,
                                         RangeResultCallback callback) {
  if (!background_queue_.get())
    return RangeResult(net::ERR_UNEXPECTED);

  background_queue_->GetAvailableRange(this, offset, len, std::move(callback));
  return RangeResult(net::ERR_IO_PENDING);
}

bool EntryImpl::CouldBeSparse() const {
  if (sparse_.get())
    return true;

  auto sparse = std::make_unique<SparseControl>(const_cast<EntryImpl*>(this));
  return sparse->CouldBeSparse();
}

void EntryImpl::CancelSparseIO() {
  if (background_queue_.get())
    background_queue_->CancelSparseIO(this);
}

net::Error EntryImpl::ReadyForSparseIO(CompletionOnceCallback callback) {
  if (!sparse_.get())
    return net::OK;

  if (!background_queue_.get())
    return net::ERR_UNEXPECTED;

  background_queue_->ReadyForSparseIO(this, std::move(callback));
  return net::ERR_IO_PENDING;
}

void EntryImpl::SetLastUsedTimeForTest(base::Time time) {
  SetTimes(time, time);
}

// When an entry is deleted from the cache, we clean up all the data associated
// with it for two reasons: to simplify the reuse of the block (we know that any
// unused block is filled with zeros), and to simplify the handling of write /
// read partial information from an entry (don't have to worry about returning
// data related to a previous cache entry because the range was not fully
// written before).
EntryImpl::~EntryImpl() {
  if (!backend_.get()) {
    entry_.clear_modified();
    node_.clear_modified();
    return;
  }

  // Save the sparse info to disk. This will generate IO for this entry and
  // maybe for a child entry, so it is important to do it before deleting this
  // entry.
  sparse_.reset();

  // Remove this entry from the list of open entries.
  backend_->OnEntryDestroyBegin(entry_.address());

  if (doomed_) {
    DeleteEntryData(true);
  } else {
#if defined(NET_BUILD_STRESS_CACHE)
    SanityCheck();
#endif
    net_log_.AddEvent(net::NetLogEventType::ENTRY_CLOSE);
    bool ret = true;
    for (int index = 0; index < kNumStreams; index++) {
      if (user_buffers_[index].get()) {
        ret = Flush(index, 0);
        if (!ret)
          LOG(ERROR) << "Failed to save user data";
      }
      if (unreported_size_[index]) {
        backend_->ModifyStorageSize(
            entry_.Data()->data_size[index] - unreported_size_[index],
            entry_.Data()->data_size[index]);
      }
    }

    if (!ret) {
      // There was a failure writing the actual data. Mark the entry as dirty.
      int current_id = backend_->GetCurrentEntryId();
      node_.Data()->dirty = current_id == 1 ? -1 : current_id - 1;
      node_.Store();
    } else if (node_.HasData() && !dirty_ && node_.Data()->dirty) {
      node_.Data()->dirty = 0;
      node_.Store();
    }
  }

  net_log_.EndEvent(net::NetLogEventType::DISK_CACHE_ENTRY_IMPL);
  backend_->OnEntryDestroyEnd();
}

// ------------------------------------------------------------------------

int EntryImpl::InternalReadData(int index,
                                int offset,
                                IOBuffer* buf,
                                int buf_len,
                                CompletionOnceCallback callback) {
  DCHECK(node_.Data()->dirty || read_only_);
  DVLOG(2) << "Read from " << index << " at " << offset << " : " << buf_len;
  if (index < 0 || index >= kNumStreams)
    return net::ERR_INVALID_ARGUMENT;

  int entry_size = entry_.Data()->data_size[index];
  if (offset >= entry_size || offset < 0 || !buf_len)
    return 0;

  if (buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  if (!backend_.get())
    return net::ERR_UNEXPECTED;

  int end_offset;
  if (!base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset) ||
      end_offset > entry_size)
    buf_len = entry_size - offset;

  UpdateRank(false);

  backend_->OnEvent(Stats::READ_DATA);
  backend_->OnRead(buf_len);

  Addr address(entry_.Data()->data_addr[index]);
  int eof = address.is_initialized() ? entry_size : 0;
  if (user_buffers_[index].get() &&
      user_buffers_[index]->PreRead(eof, offset, &buf_len)) {
    // Complete the operation locally.
    buf_len = user_buffers_[index]->Read(offset, buf, buf_len);
    return buf_len;
  }

  address.set_value(entry_.Data()->data_addr[index]);
  if (!address.is_initialized()) {
    DoomImpl();
    return net::ERR_FAILED;
  }

  File* file = GetBackingFile(address, index);
  if (!file) {
    DoomImpl();
    LOG(ERROR) << "No file for " << std::hex << address.value();
    return net::ERR_FILE_NOT_FOUND;
  }

  size_t file_offset = offset;
  if (address.is_block_file()) {
    DCHECK_LE(offset + buf_len, kMaxBlockSize);
    file_offset += address.start_block() * address.BlockSize() +
                   kBlockHeaderSize;
  }

  SyncCallback* io_callback = nullptr;
  bool null_callback = callback.is_null();
  if (!null_callback) {
    io_callback =
        new SyncCallback(base::WrapRefCounted(this), buf, std::move(callback),
                         net::NetLogEventType::ENTRY_READ_DATA);
  }

  bool completed;
  if (!file->Read(buf->data(), buf_len, file_offset, io_callback, &completed)) {
    if (io_callback)
      io_callback->Discard();
    DoomImpl();
    return net::ERR_CACHE_READ_FAILURE;
  }

  if (io_callback && completed)
    io_callback->Discard();

  return (completed || null_callback) ? buf_len : net::ERR_IO_PENDING;
}

int EntryImpl::InternalWriteData(int index,
                                 int offset,
                                 IOBuffer* buf,
                                 int buf_len,
                                 CompletionOnceCallback callback,
                                 bool truncate) {
  DCHECK(node_.Data()->dirty || read_only_);
  DVLOG(2) << "Write to " << index << " at " << offset << " : " << buf_len;
  if (index < 0 || index >= kNumStreams)
    return net::ERR_INVALID_ARGUMENT;

  if (offset < 0 || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  if (!backend_.get())
    return net::ERR_UNEXPECTED;

  int max_file_size = backend_->MaxFileSize();

  int end_offset;
  if (offset > max_file_size || buf_len > max_file_size ||
      !base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset) ||
   
"""


```