Response:
Let's break down the thought process for analyzing the `sparse_control.cc` file.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code (`sparse_control.cc`) and understand its functionality, its relation to JavaScript (if any), its logic (with examples), potential errors, and how a user's actions might lead to this code being executed.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for key terms and structures. This gives a high-level overview:

* **Includes:**  `net/disk_cache/blockfile/...`, `net/base/...`, `base/...`,  Indicates it's part of Chromium's network stack, specifically the disk cache.
* **`SparseControl` class:**  This is the core entity we need to understand.
* **`SparseOperation` enum:**  `kReadOperation`, `kWriteOperation`, `kGetRangeOperation`. Suggests handling read/write operations on sparse data.
* **`SparseData`, `SparseHeader` structs:** Data structures likely defining the format of sparse data on disk.
* **`ChildrenDeleter` class:**  Responsible for deleting child entries.
* **`Bitmap` class:**  Used for tracking allocated blocks within sparse files.
* **`kSparseIndex`, `kSparseData` constants:**  Likely indices for accessing different streams within a cache entry.
* **`GenerateChildName` function:**  How child entries are named.
* **NetLog integration:**  Indicates logging of operations for debugging and performance analysis.
* **Error codes (e.g., `net::ERR_CACHE_OPERATION_NOT_SUPPORTED`):**  Used for error handling.

**3. Deconstructing the `SparseControl` Class:**

This is the heart of the file. I'd examine its methods individually, trying to grasp their purpose:

* **Constructor/Destructor:** Initialization and cleanup. Note the writing of sparse data in the destructor.
* **`Init()`:**  Determines if the entry is already sparse or needs to be created as such.
* **`CouldBeSparse()`:**  A quick check without fully initializing.
* **`StartIO()`:**  The main entry point for initiating read, write, or range queries. Pay attention to the checks for concurrent operations, invalid arguments, and the usage of callbacks.
* **`GetAvailableRange()`:**  Specifically for finding available ranges in sparse data.
* **`CancelIO()`:**  Mechanism for aborting operations.
* **`ReadyToUse()`:**  Handles callbacks when an operation is cancelled.
* **`DeleteChildren()` (static):**  Important for understanding how child entries are managed and deleted.
* **`CreateSparseEntry()`:**  How a regular cache entry is converted to support sparse data.
* **`OpenSparseEntry()`:**  How an existing sparse entry is loaded from disk.
* **`OpenChild()`, `CloseChild()`:**  Management of child entries that store the actual sparse data.
* **`GenerateChildKey()`:**  How child entry keys are generated.
* **`KillChildAndContinue()`, `ContinueWithoutChild()`:** Error handling during child entry management.
* **`ChildPresent()`, `SetChildBit()`:**  Managing the bitmap of child entries.
* **`WriteSparseData()`:**  Saving the child entry bitmap.
* **`VerifyRange()`:**  Ensuring the requested read operation is valid within the child.
* **`UpdateRange()`:**  Updating the child's bitmap after a write.
* **`PartialBlockLength()`:**  Handling partially written blocks.
* **`InitChildData()`:**  Initializing the metadata for a new child entry.
* **`DoChildrenIO()`, `DoChildIO()`:**  The core logic for iterating through child entries and performing the actual I/O.
* **`DoGetAvailableRange()`:**  The specific logic for finding available ranges within a child entry.
* **Completion callbacks (`OnChildIOCompleted`, `DoUserCallback`, `DoAbortCallbacks`):**  Crucial for asynchronous operations and handling completion/cancellation.

**4. Identifying Relationships and Data Flow:**

* **Parent-Child Relationship:**  Understand how the main entry (parent) manages smaller child entries to store the actual sparse data. The naming convention of child entries is key here.
* **Bitmap Usage:** How the `children_map_` in the parent and `child_map_` in the children track allocated blocks.
* **Asynchronous Operations:** The heavy use of callbacks indicates asynchronous I/O. Track how `StartIO` initiates the process and how the callbacks chain together.
* **NetLog Integration:** Note where logging occurs and what information is being logged. This is helpful for debugging.

**5. Addressing Specific Questions:**

* **Functionality:** Summarize the purpose of each major method and the overall goal of the class (managing sparse data in the cache).
* **JavaScript Relationship:**  Actively look for any direct interactions or concepts that map to JavaScript. In this case, there isn't a direct functional link within *this specific file*. The connection is more architectural—the disk cache supports storing data requested by JavaScript.
* **Logical Reasoning and Examples:** Choose key methods like `StartIO` or `GetAvailableRange` and work through a simple scenario with hypothetical inputs and outputs. Consider edge cases.
* **User/Programming Errors:**  Think about how a programmer might misuse the API or what common pitfalls exist (e.g., concurrent operations).
* **User Operations and Debugging:**  Trace a possible user action (e.g., a large file download) through the network stack to the point where this code might be involved. Think about the data flow and how to debug issues.

**6. Structuring the Answer:**

Organize the findings logically:

* **Overview:**  Start with a concise summary of the file's purpose.
* **Key Functionalities:** List the main functions and their roles.
* **JavaScript Relationship:** Explain the indirect relationship.
* **Logical Reasoning (with examples):**  Provide clear scenarios.
* **Common Errors:** Give practical examples.
* **User Operations and Debugging:**  Outline a path from user action to this code.

**Self-Correction/Refinement During Analysis:**

* **Initial Misconceptions:**  I might initially think a particular function does something slightly different. As I delve deeper, I correct my understanding based on the code.
* **Missing Information:**  If I encounter a part of the code I don't fully understand, I'd look for related documentation or code within the Chromium project. For this example, understanding the `disk_cache` and `net::IOBuffer` concepts would be crucial.
* **Simplification:** When providing examples, keep them simple and focused on illustrating the core logic. Avoid overly complex scenarios initially.

By following this structured approach, combining code analysis with conceptual understanding, and actively seeking answers to the posed questions, I can arrive at a comprehensive and accurate analysis of the `sparse_control.cc` file.
这个文件 `net/disk_cache/blockfile/sparse_control.cc` 是 Chromium 网络栈中磁盘缓存模块的一部分，专门用于**管理稀疏（sparse）缓存条目**。 稀疏缓存条目允许存储可能非常大的数据，而无需在磁盘上预先分配所有空间，从而节省磁盘空间。

以下是它的主要功能：

**核心功能：**

1. **稀疏条目的创建与初始化：** 负责将一个普通的缓存条目转换为稀疏条目，并初始化相关的元数据，例如稀疏索引头信息 (`sparse_header_`) 和子条目位图 (`children_map_`)。
2. **稀疏数据的读写操作：** 提供 `StartIO` 方法来启动对稀疏数据的读 (`kReadOperation`)、写 (`kWriteOperation`) 操作。由于稀疏数据可能分布在多个小的“子条目”中，这个类负责将对整个稀疏条目的读写请求分解为对相应子条目的操作。
3. **子条目的管理：**
    * **命名和查找子条目：** 使用 `GenerateChildName` 函数根据父条目的信息和偏移量生成子条目的名称。
    * **创建和打开子条目：**  当需要读写特定偏移量的数据时，会根据偏移量确定对应的子条目，并创建或打开该子条目。
    * **关闭子条目：**  在操作完成后，会关闭子条目。
    * **删除子条目：**  提供 `DeleteChildren` 静态方法来异步地删除一个稀疏条目的所有子条目。
4. **可用范围查询：** 提供 `GetAvailableRange` 方法来查询稀疏条目中指定偏移量范围内实际已存储数据的范围。
5. **并发控制：**  通过 `operation_` 成员变量来限制同一时间只能进行一个稀疏操作。
6. **错误处理：**  在操作过程中遇到错误时，会返回相应的 `net::Error` 代码。
7. **日志记录：**  使用 `net::NetLog` 记录稀疏操作的开始、结束和相关事件，用于调试和性能分析。

**与 JavaScript 的关系：**

这个 C++ 文件本身并不直接包含 JavaScript 代码或直接执行 JavaScript。 然而，它支持的功能是 Web 浏览器核心功能的一部分，这些功能会被 JavaScript 通过 Web API 间接使用。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 下载一个非常大的文件，而浏览器决定使用 HTTP 缓存来存储这个文件。 如果这个文件足够大，或者浏览器的缓存配置允许，磁盘缓存模块可能会选择使用稀疏条目来存储这个文件。

1. **JavaScript 发起下载：**  `fetch('https://example.com/large_file.iso')`
2. **网络请求和缓存命中/未命中：** Chromium 的网络栈处理这个请求。如果缓存中没有这个文件，会发起实际的网络请求。
3. **缓存存储：** 当响应到达时，磁盘缓存模块会负责存储响应体。对于大文件，可能会创建或使用一个稀疏条目。`sparse_control.cc` 中的代码会被调用来管理这个稀疏条目的创建和数据写入。
4. **JavaScript 再次请求：**  如果 JavaScript 稍后再次请求相同的 URL，并且缓存策略允许，浏览器可能会尝试从缓存中加载。
5. **缓存读取：**  磁盘缓存模块会查找缓存条目。如果找到的是稀疏条目，`sparse_control.cc` 中的代码会被调用来读取分布在各个子条目中的数据，并将它们组合起来返回给网络栈。
6. **数据返回给 JavaScript：**  最终，`fetch` API 的 Promise 会 resolve，并将文件数据返回给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**场景：** 对一个已存在的稀疏缓存条目进行读取操作。

**假设输入：**

* `operation_`: `kReadOperation`
* `offset_`: 1048576 (1MB)
* `buf_len_`: 2048 (2KB)
* 稀疏条目已存在，并且 1MB 到 1MB + 2KB 的数据存储在子条目中。

**逻辑推理过程：**

1. `StartIO` 被调用，传入读取操作的参数。
2. `DoChildrenIO` 被调用，开始处理子条目的 I/O。
3. `OpenChild` 被调用，根据 `offset_` 计算出对应的子条目（假设每个子条目管理 1MB 的范围）。
4. 如果子条目不存在，并且是读取操作，`VerifyRange` 可能会返回 false，导致操作结束。
5. 如果子条目存在，`VerifyRange` 会检查请求的范围是否在子条目的有效数据范围内。
6. `child_->ReadDataImpl` 被调用，从子条目的数据流 (`kSparseData`) 中读取数据到 `user_buf_`。
7. `OnChildIOCompleted` 被调用，更新读取的字节数，偏移量，并检查是否需要读取更多数据。
8. 如果 `buf_len_` 仍然大于 0，`DoChildrenIO` 可能会继续处理下一个需要读取的子条目。
9. 当 `buf_len_` 变为 0 或发生错误时，操作结束。

**假设输出 (成功读取)：**

* `result_`: 2048 (表示成功读取了 2048 字节)
* `user_buf_` 包含从稀疏条目 1MB 偏移量开始的 2KB 数据。

**用户或编程常见的使用错误：**

1. **在未初始化的情况下尝试操作：**  如果在调用 `Init()` 之前就尝试使用 `StartIO` 等方法，会导致错误 (`DCHECK(!init_)` 会触发断言)。
2. **同时发起多个稀疏操作：**  `SparseControl` 不支持并发的稀疏操作。如果在一个操作进行中又调用 `StartIO`，会返回 `net::ERR_CACHE_OPERATION_NOT_SUPPORTED`。
3. **提供的缓冲区不足：**  如果传递给 `StartIO` 的缓冲区大小 (`buf_len`) 与实际要读取或写入的数据大小不匹配，可能会导致数据截断或越界访问（尽管代码中进行了边界检查）。
4. **错误的偏移量或长度：**  传递负数的偏移量或长度会导致 `net::ERR_INVALID_ARGUMENT` 错误。
5. **在析构后尝试访问：**  如果 `SparseControl` 对象被销毁，任何对其成员的访问都是未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个需要从缓存加载资源的页面。**
2. **浏览器网络栈检查缓存，发现匹配的缓存条目，并且该条目是稀疏条目。**
3. **网络栈请求从缓存中读取数据。**
4. **磁盘缓存模块接收到读取请求，并识别出这是一个稀疏条目。**
5. **磁盘缓存模块创建或获取 `SparseControl` 对象来管理这个稀疏条目的读取操作。**
6. **`SparseControl::StartIO` 被调用，传入读取操作的参数 (偏移量，长度，缓冲区等)。**
7. **根据请求的偏移量，`SparseControl` 可能会调用 `OpenChild` 来打开对应的子条目。**
8. **`File::Read` (在 `child_->ReadDataImpl` 中) 会被调用，最终导致对磁盘文件的实际 I/O 操作。**

**调试线索：**

* **NetLog:**  查看浏览器的 `chrome://net-export/` 或使用 `--log-net-log` 命令行参数生成的 NetLog 文件。 搜索包含 `SPARSE_READ` 或相关事件的条目，可以追踪稀疏操作的开始、结束、涉及的子条目等信息。
* **断点调试：**  在 `sparse_control.cc` 的关键方法（例如 `StartIO`, `DoChildrenIO`, `OpenChild`, `VerifyRange`）设置断点，可以单步执行代码，查看变量的值，理解代码的执行流程。
* **查看缓存索引：**  虽然不太直接，但可以检查磁盘缓存的索引文件，了解稀疏条目的元数据信息。
* **分析崩溃堆栈：**  如果程序崩溃，分析崩溃堆栈，看是否涉及到 `sparse_control.cc` 中的代码。

总而言之，`sparse_control.cc` 是 Chromium 磁盘缓存中一个重要的组件，它负责管理稀疏缓存条目的复杂逻辑，使得浏览器能够高效地存储和检索大型资源。 虽然 JavaScript 不会直接调用这个文件中的代码，但它依赖于磁盘缓存提供的功能，而 `sparse_control.cc` 正是这些功能的幕后功臣之一。

### 提示词
```
这是目录为net/disk_cache/blockfile/sparse_control.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/blockfile/sparse_control.h"

#include <stdint.h>

#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/numerics/checked_math.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "net/base/interval.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/file.h"
#include "net/disk_cache/net_log_parameters.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"

using base::Time;

namespace {

// Stream of the sparse data index.
const int kSparseIndex = 2;

// Stream of the sparse data.
const int kSparseData = 1;

// We can have up to 64k children.
const int kMaxMapSize = 8 * 1024;

// The maximum number of bytes that a child can store.
const int kMaxEntrySize = 0x100000;

// How much we can address. 8 KiB bitmap (kMaxMapSize above) gives us offsets
// up to 64 GiB.
const int64_t kMaxEndOffset = 8ll * kMaxMapSize * kMaxEntrySize;

// The size of each data block (tracked by the child allocation bitmap).
const int kBlockSize = 1024;

// Returns the name of a child entry given the base_name and signature of the
// parent and the child_id.
// If the entry is called entry_name, child entries will be named something
// like Range_entry_name:XXX:YYY where XXX is the entry signature and YYY is the
// number of the particular child.
std::string GenerateChildName(const std::string& base_name,
                              int64_t signature,
                              int64_t child_id) {
  return base::StringPrintf("Range_%s:%" PRIx64 ":%" PRIx64, base_name.c_str(),
                            signature, child_id);
}

// This class deletes the children of a sparse entry.
class ChildrenDeleter
    : public base::RefCounted<ChildrenDeleter>,
      public disk_cache::FileIOCallback {
 public:
  ChildrenDeleter(disk_cache::BackendImpl* backend, const std::string& name)
      : backend_(backend->GetWeakPtr()), name_(name) {}

  ChildrenDeleter(const ChildrenDeleter&) = delete;
  ChildrenDeleter& operator=(const ChildrenDeleter&) = delete;

  void OnFileIOComplete(int bytes_copied) override;

  // Two ways of deleting the children: if we have the children map, use Start()
  // directly, otherwise pass the data address to ReadData().
  void Start(std::unique_ptr<char[]> buffer, int len);
  void ReadData(disk_cache::Addr address, int len);

 private:
  friend class base::RefCounted<ChildrenDeleter>;
  ~ChildrenDeleter() override = default;

  void DeleteChildren();

  base::WeakPtr<disk_cache::BackendImpl> backend_;
  std::string name_;
  disk_cache::Bitmap children_map_;
  int64_t signature_ = 0;
  std::unique_ptr<char[]> buffer_;
};

// This is the callback of the file operation.
void ChildrenDeleter::OnFileIOComplete(int bytes_copied) {
  Start(std::move(buffer_), bytes_copied);
}

void ChildrenDeleter::Start(std::unique_ptr<char[]> buffer, int len) {
  buffer_ = std::move(buffer);
  if (len < static_cast<int>(sizeof(disk_cache::SparseData)))
    return Release();

  // Just copy the information from |buffer|, delete |buffer| and start deleting
  // the child entries.
  disk_cache::SparseData* data =
      reinterpret_cast<disk_cache::SparseData*>(buffer_.get());
  signature_ = data->header.signature;

  int num_bits = (len - sizeof(disk_cache::SparseHeader)) * 8;
  children_map_.Resize(num_bits, false);
  children_map_.SetMap(data->bitmap, num_bits / 32);
  buffer_.reset();

  DeleteChildren();
}

void ChildrenDeleter::ReadData(disk_cache::Addr address, int len) {
  DCHECK(address.is_block_file());
  if (!backend_.get())
    return Release();

  disk_cache::File* file(backend_->File(address));
  if (!file)
    return Release();

  size_t file_offset = address.start_block() * address.BlockSize() +
                       disk_cache::kBlockHeaderSize;

  buffer_ = std::make_unique<char[]>(len);
  bool completed;
  if (!file->Read(buffer_.get(), len, file_offset, this, &completed))
    return Release();

  if (completed)
    OnFileIOComplete(len);

  // And wait until OnFileIOComplete gets called.
}

void ChildrenDeleter::DeleteChildren() {
  int child_id = 0;
  if (!children_map_.FindNextSetBit(&child_id) || !backend_.get()) {
    // We are done. Just delete this object.
    return Release();
  }
  std::string child_name = GenerateChildName(name_, signature_, child_id);
  backend_->SyncDoomEntry(child_name);
  children_map_.Set(child_id, false);

  // Post a task to delete the next child.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&ChildrenDeleter::DeleteChildren, this));
}

// Returns the NetLog event type corresponding to a SparseOperation.
net::NetLogEventType GetSparseEventType(
    disk_cache::SparseControl::SparseOperation operation) {
  switch (operation) {
    case disk_cache::SparseControl::kReadOperation:
      return net::NetLogEventType::SPARSE_READ;
    case disk_cache::SparseControl::kWriteOperation:
      return net::NetLogEventType::SPARSE_WRITE;
    case disk_cache::SparseControl::kGetRangeOperation:
      return net::NetLogEventType::SPARSE_GET_RANGE;
    default:
      NOTREACHED();
  }
}

// Logs the end event for |operation| on a child entry.  Range operations log
// no events for each child they search through.
void LogChildOperationEnd(const net::NetLogWithSource& net_log,
                          disk_cache::SparseControl::SparseOperation operation,
                          int result) {
  if (net_log.IsCapturing()) {
    net::NetLogEventType event_type;
    switch (operation) {
      case disk_cache::SparseControl::kReadOperation:
        event_type = net::NetLogEventType::SPARSE_READ_CHILD_DATA;
        break;
      case disk_cache::SparseControl::kWriteOperation:
        event_type = net::NetLogEventType::SPARSE_WRITE_CHILD_DATA;
        break;
      case disk_cache::SparseControl::kGetRangeOperation:
        return;
      default:
        NOTREACHED();
    }
    net_log.EndEventWithNetErrorCode(event_type, result);
  }
}

}  // namespace.

namespace disk_cache {

SparseControl::SparseControl(EntryImpl* entry)
    : entry_(entry),
      child_map_(child_data_.bitmap, kNumSparseBits, kNumSparseBits / 32) {
  memset(&sparse_header_, 0, sizeof(sparse_header_));
  memset(&child_data_, 0, sizeof(child_data_));
}

SparseControl::~SparseControl() {
  if (child_)
    CloseChild();
  if (init_)
    WriteSparseData();
}

int SparseControl::Init() {
  DCHECK(!init_);

  // We should not have sparse data for the exposed entry.
  if (entry_->GetDataSize(kSparseData))
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  // Now see if there is something where we store our data.
  int rv = net::OK;
  int data_len = entry_->GetDataSize(kSparseIndex);
  if (!data_len) {
    rv = CreateSparseEntry();
  } else {
    rv = OpenSparseEntry(data_len);
  }

  if (rv == net::OK)
    init_ = true;
  return rv;
}

bool SparseControl::CouldBeSparse() const {
  DCHECK(!init_);

  if (entry_->GetDataSize(kSparseData))
    return false;

  // We don't verify the data, just see if it could be there.
  return (entry_->GetDataSize(kSparseIndex) != 0);
}

int SparseControl::StartIO(SparseOperation op,
                           int64_t offset,
                           net::IOBuffer* buf,
                           int buf_len,
                           CompletionOnceCallback callback) {
  DCHECK(init_);
  // We don't support simultaneous IO for sparse data.
  if (operation_ != kNoOperation)
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  if (offset < 0 || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  int64_t end_offset = 0;  // non-inclusive.
  if (!base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset)) {
    // Writes aren't permitted to try to cross the end of address space;
    // read/GetAvailableRange clip.
    if (op == kWriteOperation)
      return net::ERR_INVALID_ARGUMENT;
    else
      end_offset = std::numeric_limits<int64_t>::max();
  }

  if (offset >= kMaxEndOffset) {
    // Interval is within valid offset space, but completely outside backend
    // supported range. Permit GetAvailableRange to say "nothing here", actual
    // I/O fails.
    if (op == kGetRangeOperation)
      return 0;
    else
      return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;
  }

  if (end_offset > kMaxEndOffset) {
    // Interval is partially what the backend can handle. Fail writes, clip
    // reads.
    if (op == kWriteOperation)
      return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;
    else
      end_offset = kMaxEndOffset;
  }

  DCHECK_GE(end_offset, offset);
  buf_len = end_offset - offset;

  DCHECK(!user_buf_.get());
  DCHECK(user_callback_.is_null());

  if (!buf && (op == kReadOperation || op == kWriteOperation))
    return 0;

  // Copy the operation parameters.
  operation_ = op;
  offset_ = offset;
  user_buf_ = buf ? base::MakeRefCounted<net::DrainableIOBuffer>(buf, buf_len)
                  : nullptr;
  buf_len_ = buf_len;
  user_callback_ = std::move(callback);

  result_ = 0;
  pending_ = false;
  finished_ = false;
  abort_ = false;

  if (entry_->net_log().IsCapturing()) {
    NetLogSparseOperation(entry_->net_log(), GetSparseEventType(operation_),
                          net::NetLogEventPhase::BEGIN, offset_, buf_len_);
  }
  DoChildrenIO();

  if (!pending_) {
    // Everything was done synchronously.
    operation_ = kNoOperation;
    user_buf_ = nullptr;
    user_callback_.Reset();
    return result_;
  }

  return net::ERR_IO_PENDING;
}

RangeResult SparseControl::GetAvailableRange(int64_t offset, int len) {
  DCHECK(init_);
  // We don't support simultaneous IO for sparse data.
  if (operation_ != kNoOperation)
    return RangeResult(net::ERR_CACHE_OPERATION_NOT_SUPPORTED);

  range_found_ = false;
  int result = StartIO(kGetRangeOperation, offset, nullptr, len,
                       CompletionOnceCallback());
  if (range_found_)
    return RangeResult(offset_, result);

  // This is a failure. We want to return a valid start value if it's just an
  // empty range, though.
  if (result < 0)
    return RangeResult(static_cast<net::Error>(result));
  return RangeResult(offset, 0);
}

void SparseControl::CancelIO() {
  if (operation_ == kNoOperation)
    return;
  abort_ = true;
}

int SparseControl::ReadyToUse(CompletionOnceCallback callback) {
  if (!abort_)
    return net::OK;

  // We'll grab another reference to keep this object alive because we just have
  // one extra reference due to the pending IO operation itself, but we'll
  // release that one before invoking user_callback_.
  entry_->AddRef();  // Balanced in DoAbortCallbacks.
  abort_callbacks_.push_back(std::move(callback));
  return net::ERR_IO_PENDING;
}

// Static
void SparseControl::DeleteChildren(EntryImpl* entry) {
  DCHECK(entry->GetEntryFlags() & PARENT_ENTRY);
  int data_len = entry->GetDataSize(kSparseIndex);
  if (data_len < static_cast<int>(sizeof(SparseData)) ||
      entry->GetDataSize(kSparseData))
    return;

  int map_len = data_len - sizeof(SparseHeader);
  if (map_len > kMaxMapSize || map_len % 4)
    return;

  std::unique_ptr<char[]> buffer;
  Addr address;
  entry->GetData(kSparseIndex, &buffer, &address);
  if (!buffer && !address.is_initialized())
    return;

  entry->net_log().AddEvent(net::NetLogEventType::SPARSE_DELETE_CHILDREN);

  DCHECK(entry->backend_.get());
  ChildrenDeleter* deleter = new ChildrenDeleter(entry->backend_.get(),
                                                 entry->GetKey());
  // The object will self destruct when finished.
  deleter->AddRef();

  if (buffer) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&ChildrenDeleter::Start, deleter,
                                  std::move(buffer), data_len));
  } else {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&ChildrenDeleter::ReadData, deleter, address, data_len));
  }
}

// We are going to start using this entry to store sparse data, so we have to
// initialize our control info.
int SparseControl::CreateSparseEntry() {
  if (CHILD_ENTRY & entry_->GetEntryFlags())
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  memset(&sparse_header_, 0, sizeof(sparse_header_));
  sparse_header_.signature = Time::Now().ToInternalValue();
  sparse_header_.magic = kIndexMagic;
  sparse_header_.parent_key_len = entry_->GetKey().size();
  children_map_.Resize(kNumSparseBits, true);

  // Save the header. The bitmap is saved in the destructor.
  scoped_refptr<net::IOBuffer> buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(base::span_from_ref(sparse_header_)));

  int rv = entry_->WriteData(kSparseIndex, 0, buf.get(), sizeof(sparse_header_),
                             CompletionOnceCallback(), false);
  if (rv != sizeof(sparse_header_)) {
    DLOG(ERROR) << "Unable to save sparse_header_";
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;
  }

  entry_->SetEntryFlags(PARENT_ENTRY);
  return net::OK;
}

// We are opening an entry from disk. Make sure that our control data is there.
int SparseControl::OpenSparseEntry(int data_len) {
  if (data_len < static_cast<int>(sizeof(SparseData)))
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  if (entry_->GetDataSize(kSparseData))
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  if (!(PARENT_ENTRY & entry_->GetEntryFlags()))
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  // Don't go over board with the bitmap.
  int map_len = data_len - sizeof(sparse_header_);
  if (map_len > kMaxMapSize || map_len % 4)
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  scoped_refptr<net::IOBuffer> buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(base::span_from_ref(sparse_header_)));

  // Read header.
  int rv = entry_->ReadData(kSparseIndex, 0, buf.get(), sizeof(sparse_header_),
                            CompletionOnceCallback());
  if (rv != static_cast<int>(sizeof(sparse_header_)))
    return net::ERR_CACHE_READ_FAILURE;

  // The real validation should be performed by the caller. This is just to
  // double check.
  if (sparse_header_.magic != kIndexMagic ||
      sparse_header_.parent_key_len !=
          static_cast<int>(entry_->GetKey().size()))
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  // Read the actual bitmap.
  buf = base::MakeRefCounted<net::IOBufferWithSize>(map_len);
  rv = entry_->ReadData(kSparseIndex, sizeof(sparse_header_), buf.get(),
                        map_len, CompletionOnceCallback());
  if (rv != map_len)
    return net::ERR_CACHE_READ_FAILURE;

  // Grow the bitmap to the current size and copy the bits.
  children_map_.Resize(map_len * 8, false);
  children_map_.SetMap(reinterpret_cast<uint32_t*>(buf->data()), map_len);
  return net::OK;
}

bool SparseControl::OpenChild() {
  DCHECK_GE(result_, 0);

  std::string key = GenerateChildKey();
  if (child_) {
    // Keep using the same child or open another one?.
    if (key == child_->GetKey())
      return true;
    CloseChild();
  }

  // See if we are tracking this child.
  if (!ChildPresent())
    return ContinueWithoutChild(key);

  if (!entry_->backend_.get())
    return false;

  child_ = entry_->backend_->OpenEntryImpl(key);
  if (!child_)
    return ContinueWithoutChild(key);

  if (!(CHILD_ENTRY & child_->GetEntryFlags()) ||
      child_->GetDataSize(kSparseIndex) < static_cast<int>(sizeof(child_data_)))
    return KillChildAndContinue(key, false);

  auto buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(base::span_from_ref(child_data_)));

  // Read signature.
  int rv = child_->ReadData(kSparseIndex, 0, buf.get(), sizeof(child_data_),
                            CompletionOnceCallback());
  if (rv != sizeof(child_data_))
    return KillChildAndContinue(key, true);  // This is a fatal failure.

  if (child_data_.header.signature != sparse_header_.signature ||
      child_data_.header.magic != kIndexMagic)
    return KillChildAndContinue(key, false);

  if (child_data_.header.last_block_len < 0 ||
      child_data_.header.last_block_len >= kBlockSize) {
    // Make sure these values are always within range.
    child_data_.header.last_block_len = 0;
    child_data_.header.last_block = -1;
  }

  return true;
}

void SparseControl::CloseChild() {
  auto buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(base::span_from_ref(child_data_)));

  // Save the allocation bitmap before closing the child entry.
  int rv = child_->WriteData(kSparseIndex, 0, buf.get(), sizeof(child_data_),
                             CompletionOnceCallback(), false);
  if (rv != sizeof(child_data_))
    DLOG(ERROR) << "Failed to save child data";
  child_ = nullptr;
}

std::string SparseControl::GenerateChildKey() {
  return GenerateChildName(entry_->GetKey(), sparse_header_.signature,
                           offset_ >> 20);
}

// We are deleting the child because something went wrong.
bool SparseControl::KillChildAndContinue(const std::string& key, bool fatal) {
  SetChildBit(false);
  child_->DoomImpl();
  child_ = nullptr;
  if (fatal) {
    result_ = net::ERR_CACHE_READ_FAILURE;
    return false;
  }
  return ContinueWithoutChild(key);
}

// We were not able to open this child; see what we can do.
bool SparseControl::ContinueWithoutChild(const std::string& key) {
  if (kReadOperation == operation_)
    return false;
  if (kGetRangeOperation == operation_)
    return true;

  if (!entry_->backend_.get())
    return false;

  child_ = entry_->backend_->CreateEntryImpl(key);
  if (!child_) {
    child_ = nullptr;
    result_ = net::ERR_CACHE_READ_FAILURE;
    return false;
  }
  // Write signature.
  InitChildData();
  return true;
}

bool SparseControl::ChildPresent() {
  int child_bit = static_cast<int>(offset_ >> 20);
  if (children_map_.Size() <= child_bit)
    return false;

  return children_map_.Get(child_bit);
}

void SparseControl::SetChildBit(bool value) {
  int child_bit = static_cast<int>(offset_ >> 20);

  // We may have to increase the bitmap of child entries.
  if (children_map_.Size() <= child_bit)
    children_map_.Resize(Bitmap::RequiredArraySize(child_bit + 1) * 32, true);

  children_map_.Set(child_bit, value);
}

void SparseControl::WriteSparseData() {
  auto buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(children_map_.GetSpan()));

  int rv = entry_->WriteData(kSparseIndex, sizeof(sparse_header_), buf.get(),
                             buf->size(), CompletionOnceCallback(), false);
  if (rv != buf->size()) {
    DLOG(ERROR) << "Unable to save sparse map";
  }
}

bool SparseControl::VerifyRange() {
  DCHECK_GE(result_, 0);

  child_offset_ = static_cast<int>(offset_) & (kMaxEntrySize - 1);
  child_len_ = std::min(buf_len_, kMaxEntrySize - child_offset_);

  // We can write to (or get info from) anywhere in this child.
  if (operation_ != kReadOperation)
    return true;

  // Check that there are no holes in this range.
  int last_bit = (child_offset_ + child_len_ + 1023) >> 10;
  int start = child_offset_ >> 10;
  if (child_map_.FindNextBit(&start, last_bit, false)) {
    // Something is not here.
    DCHECK_GE(child_data_.header.last_block_len, 0);
    DCHECK_LT(child_data_.header.last_block_len, kBlockSize);
    int partial_block_len = PartialBlockLength(start);
    if (start == child_offset_ >> 10) {
      // It looks like we don't have anything.
      if (partial_block_len <= (child_offset_ & (kBlockSize - 1)))
        return false;
    }

    // We have the first part.
    child_len_ = (start << 10) - child_offset_;
    if (partial_block_len) {
      // We may have a few extra bytes.
      child_len_ = std::min(child_len_ + partial_block_len, buf_len_);
    }
    // There is no need to read more after this one.
    buf_len_ = child_len_;
  }
  return true;
}

void SparseControl::UpdateRange(int result) {
  if (result <= 0 || operation_ != kWriteOperation)
    return;

  DCHECK_GE(child_data_.header.last_block_len, 0);
  DCHECK_LT(child_data_.header.last_block_len, kBlockSize);

  // Write the bitmap.
  int first_bit = child_offset_ >> 10;
  int block_offset = child_offset_ & (kBlockSize - 1);
  if (block_offset && (child_data_.header.last_block != first_bit ||
                       child_data_.header.last_block_len < block_offset)) {
    // The first block is not completely filled; ignore it.
    first_bit++;
  }

  int last_bit = (child_offset_ + result) >> 10;
  block_offset = (child_offset_ + result) & (kBlockSize - 1);

  // This condition will hit with the following criteria:
  // 1. The first byte doesn't follow the last write.
  // 2. The first byte is in the middle of a block.
  // 3. The first byte and the last byte are in the same block.
  if (first_bit > last_bit)
    return;

  if (block_offset && !child_map_.Get(last_bit)) {
    // The last block is not completely filled; save it for later.
    child_data_.header.last_block = last_bit;
    child_data_.header.last_block_len = block_offset;
  } else {
    child_data_.header.last_block = -1;
  }

  child_map_.SetRange(first_bit, last_bit, true);
}

int SparseControl::PartialBlockLength(int block_index) const {
  if (block_index == child_data_.header.last_block)
    return child_data_.header.last_block_len;

  // This is really empty.
  return 0;
}

void SparseControl::InitChildData() {
  child_->SetEntryFlags(CHILD_ENTRY);

  memset(&child_data_, 0, sizeof(child_data_));
  child_data_.header = sparse_header_;

  auto buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      base::as_chars(base::span_from_ref(child_data_)));

  int rv = child_->WriteData(kSparseIndex, 0, buf.get(), sizeof(child_data_),
                             CompletionOnceCallback(), false);
  if (rv != sizeof(child_data_))
    DLOG(ERROR) << "Failed to save child data";
  SetChildBit(true);
}

void SparseControl::DoChildrenIO() {
  while (DoChildIO()) continue;

  // Range operations are finished synchronously, often without setting
  // |finished_| to true.
  if (kGetRangeOperation == operation_ && entry_->net_log().IsCapturing()) {
    entry_->net_log().EndEvent(net::NetLogEventType::SPARSE_GET_RANGE, [&] {
      return CreateNetLogGetAvailableRangeResultParams(
          RangeResult(offset_, result_));
    });
  }
  if (finished_) {
    if (kGetRangeOperation != operation_ && entry_->net_log().IsCapturing()) {
      entry_->net_log().EndEvent(GetSparseEventType(operation_));
    }
    if (pending_)
      DoUserCallback();  // Don't touch this object after this point.
  }
}

bool SparseControl::DoChildIO() {
  finished_ = true;
  if (!buf_len_ || result_ < 0)
    return false;

  if (!OpenChild())
    return false;

  if (!VerifyRange())
    return false;

  // We have more work to do. Let's not trigger a callback to the caller.
  finished_ = false;
  CompletionOnceCallback callback;
  if (!user_callback_.is_null()) {
    callback = base::BindOnce(&SparseControl::OnChildIOCompleted,
                              base::Unretained(this));
  }

  int rv = 0;
  switch (operation_) {
    case kReadOperation:
      if (entry_->net_log().IsCapturing()) {
        NetLogSparseReadWrite(entry_->net_log(),
                              net::NetLogEventType::SPARSE_READ_CHILD_DATA,
                              net::NetLogEventPhase::BEGIN,
                              child_->net_log().source(), child_len_);
      }
      rv = child_->ReadDataImpl(kSparseData, child_offset_, user_buf_.get(),
                                child_len_, std::move(callback));
      break;
    case kWriteOperation:
      if (entry_->net_log().IsCapturing()) {
        NetLogSparseReadWrite(entry_->net_log(),
                              net::NetLogEventType::SPARSE_WRITE_CHILD_DATA,
                              net::NetLogEventPhase::BEGIN,
                              child_->net_log().source(), child_len_);
      }
      rv = child_->WriteDataImpl(kSparseData, child_offset_, user_buf_.get(),
                                 child_len_, std::move(callback), false);
      break;
    case kGetRangeOperation:
      rv = DoGetAvailableRange();
      break;
    default:
      NOTREACHED();
  }

  if (rv == net::ERR_IO_PENDING) {
    if (!pending_) {
      pending_ = true;
      // The child will protect himself against closing the entry while IO is in
      // progress. However, this entry can still be closed, and that would not
      // be a good thing for us, so we increase the refcount until we're
      // finished doing sparse stuff.
      entry_->AddRef();  // Balanced in DoUserCallback.
    }
    return false;
  }
  if (!rv)
    return false;

  DoChildIOCompleted(rv);
  return true;
}

int SparseControl::DoGetAvailableRange() {
  if (!child_)
    return child_len_;  // Move on to the next child.

  // Blockfile splits sparse files into multiple child entries, each responsible
  // for managing 1MiB of address space. This method is responsible for
  // implementing GetAvailableRange within a single child.
  //
  // Input:
  //   |child_offset_|, |child_len_|:
  //     describe range in current child's address space the client requested.
  //   |offset_| is equivalent to |child_offset_| but in global address space.
  //
  //   For example if this were child [2] and the original call was for
  //   [0x200005, 0x200007) then |offset_| would be 0x200005, |child_offset_|
  //   would be 5, and |child_len| would be 2.
  //
  // Output:
  //   If nothing found:
  //     return |child_len_|
  //
  //   If something found:
  //     |result_| gets the length of the available range.
  //     |offset_| gets the global address of beginning of the available range.
  //     |range_found_| get true to signal SparseControl::GetAvailableRange().
  //     return 0 to exit loop.
  net::Interval<int> to_find(child_offset_, child_offset_ + child_len_);

  // Within each child, valid portions are mostly tracked via the |child_map_|
  // bitmap which marks which 1KiB 'blocks' have valid data. Scan the bitmap
  // for the first contiguous range of set bits that's relevant to the range
  // [child_offset_, child_offset_ + len)
  int first_bit = child_offset_ >> 10;
  int last_bit = (child_offset_ + child_len_ + kBlockSize - 1) >> 10;
  int found = first_bit;
  int bits_found = child_map_.FindBits(&found, last_bit, true);
  net::Interval<int> bitmap_range(found * kBlockSize,
                                  found * kBlockSize + bits_found * kBlockSize);

  // Bits on the bitmap should only be set when the corresponding block was
  // fully written (it's really being used). If a block is partially used, it
  // has to start with valid data, the length of the valid data is saved in
  // |header.last_block_len| and the block number saved in |header.last_block|.
  // This is updated after every write; with |header.last_block| set to -1
  // if no sub-KiB range is being tracked.
  net::Interval<int> last_write_range;
  if (child_data_.header.last_block >= 0) {
    last_write_range =
        net::Interval<int>(child_data_.header.last_block * kBlockSize,
                           child_data_.header.last_block * kBlockSize +
                               child_data_.header.last_block_len);
  }

  // Often |last_write_range| is contiguously after |bitmap_range|, but not
  // always. See if they can be combined.
  if (!last_write_range.Empty() && !bitmap_range.Empty() &&
      bitmap_range.max() == last_write_range.min()) {
    bitmap_range.SetMax(last_write_range.max());
    last_write_range.Clear();
  }

  // Do any of them have anything relevant?
  bitmap_range.IntersectWith(to_find);
  last_write_range.IntersectWith(to_find);

  // Now return the earliest non-empty interval, if any.
  net::Interval<int> result_range = bitmap_range;
  if (bitmap_range.Empty() || (!last_write_range.Empty() &&
                               last_write_range.min() < bitmap_range.min()))
    result_range = last_write_range;

  if (result_range.Empty()) {
    // Nothing found, so we just skip over this child.
    return child_len_;
  }

  // Package up our results.
  range_found_ = true;
  offset_ += result_range.min() - child_offset_;
  result_ = result_range.max() - result_range.min();
  return 0;
}

void SparseControl::DoChildIOCompleted(int result) {
  LogChildOperationEnd(entry_->net_log(), operation_, result);
  if (result < 0) {
    // We fail the whole operation if we encounter an error.
    result_ = result;
    return;
  }

  UpdateRange(result);

  result_ += result;
  offset_ += result;
  buf_len_ -= result;

  // We'll be reusing the user provided buffer for the next chunk.
  if (buf_len_ && user_buf_.get())
    user_buf_->DidConsume(result);
}

void SparseControl::OnChildIOCompleted(int result) {
  DCHECK_NE(net::ERR_IO_PENDING, result);
  DoChildIOCompleted(result);

  if (abort_) {
    // We'll return the current result of the operation, which may be less than
    // the bytes to read or write, but the user cancelled the operation.
    abort_ = false;
    if (entry_->net_log().IsCapturing()) {
      entry_->net_log().AddEvent(net::NetLogEventType::CANCELLED);
      entry_->net_log().EndEvent(GetSparseEventType(operation_));
    }
    // We have an indirect reference to this object for every callback so if
    // there is only one callback, we may delete this object before reaching
    // DoAbortCallbacks.
    bool has_abort_callbacks = !abort_callbacks_.empty();
    DoUserCallback();
    if (has_abort_callbacks)
      DoAbortCallbacks();
    return;
  }

  // We are running a callback from the message loop. It's time to restart what
  // we were doing before.
  DoChildrenIO();
}

void SparseControl::DoUserCallback() {
  DCHECK(!user_callback_.is_null());
  CompletionOnceCallback cb = std::move(user_callback_);
  user_buf_ = nullptr;
  pending_ = false;
  operation_ = kNoOperation;
  int rv = result_;
  entry_->Release();  // Don't touch object after this line.
  std::move(cb).Run(rv);
}

void SparseControl::DoAbortCallbacks() {
  std::vector<CompletionOnceCallback> abort_callbacks;
  abort_callbacks.swap(abort_callbacks_);

  for (CompletionOnceCallback& callback : abort_callbacks) {
    // Releasing all references to entry_ may result in the destruction of this
    // object so we should not be touching it after the last Release().
    entry_->Release();
    std::move(callback).Run(net::OK);
  }
}

}  // namespace disk_cache
```