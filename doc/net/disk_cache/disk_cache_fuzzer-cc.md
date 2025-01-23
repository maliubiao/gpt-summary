Response:
The user wants to understand the functionality of the `disk_cache_fuzzer.cc` file in Chromium's network stack. This involves:

1. **Listing its functions:**  Identify the main purpose of the code.
2. **Relating to JavaScript:** Check if the fuzzer interacts with any JavaScript-related functionalities.
3. **Providing logical inference examples:** Demonstrate how the fuzzer operates with hypothetical inputs and outputs.
4. **Illustrating common user errors:** Highlight potential mistakes in using the disk cache that the fuzzer might uncover.
5. **Tracing user actions to the code:** Explain how user interactions could lead to this code being executed (as a debugging aid).
6. **Summarizing its functionality:**  Provide a concise overview of the file's role.

Based on the provided code snippet:

- It includes headers related to file operations, memory management, networking, and specifically `disk_cache`.
- It defines a fuzzer that interacts with different disk cache backends (Blockfile, Simple, Memory).
- It uses a protobuf definition (`disk_cache_fuzzer.pb.h`) to define the commands for the fuzzer.
- It simulates various cache operations like creating, opening, closing, writing, reading, and deleting entries.
- It uses asynchronous operations and callbacks.

Therefore, the main function of this file is to **fuzz the disk cache implementation**. It generates sequences of cache operations based on the provided protobuf commands and observes how the cache behaves, looking for crashes, errors, or unexpected behavior.

Let's break down the specific points:
```cpp
        const disk_cache_fuzzer::IteratorOpenNextEntry& ione =
            command.iterator_open_next_entry();

        uint64_t it_id = ione.it_id();
        uint64_t entry_id = ione.entry_id();
        bool async = ione.async();

        auto it_iter = open_iterators_.find(it_id);
        if (it_iter == open_iterators_.end())
          continue;

        if (open_cache_entries_.find(entry_id) != open_cache_entries_.end())
          continue;  // Don't overwrite a currently open cache entry.

        EntryInfo* entry_info = &open_cache_entries_[entry_id];
        entry_info->tcb = std::make_unique<TestEntryResultCompletionCallback>();

        disk_cache::EntryResultCallback cb =
            base::BindOnce(&DiskCacheLPMFuzzer::OpenCacheEntryCallback,
                           base::Unretained(this), entry_id, async, false);

        MAYBE_PRINT << "IteratorOpenNextEntry(it_id = " << it_id << ")"
                    << std::flush;
        disk_cache::EntryResult result =
            it_iter->second->OpenNextEntry(std::move(cb));

        if (!async || result.net_error() != net::ERR_IO_PENDING) {
          result = WaitOnEntry(entry_info, std::move(result));
          int rv = result.net_error();
          if (rv == net::OK)
            entry_info->entry_ptr = result.ReleaseEntry();
          MAYBE_PRINT << " = " << rv << std::endl;
        } else {
          MAYBE_PRINT << " = net::ERR_IO_PENDING (async)" << std::endl;
        }
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kIteratorGetNext: {
        const disk_cache_fuzzer::IteratorGetNext& ign =
            command.iterator_get_next();
        uint64_t it_id = ign.it_id();
        auto it_iter = open_iterators_.find(it_id);
        if (it_iter == open_iterators_.end())
          continue;

        MAYBE_PRINT << "IteratorGetNext(it_id = " << it_id << ")" << std::endl;
        it_iter->second->Next();
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kIteratorReset: {
        const disk_cache_fuzzer::IteratorReset& ir = command.iterator_reset();
        uint64_t it_id = ir.it_id();
        auto it_iter = open_iterators_.find(it_id);
        if (it_iter == open_iterators_.end())
          continue;

        MAYBE_PRINT << "IteratorReset(it_id = " << it_id << ")" << std::endl;
        it_iter->second->Reset();
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kDoomEntriesSince: {
        if (!cache_)
          continue;

        const disk_cache_fuzzer::DoomEntriesSince& des =
            command.doom_entries_since();
        uint64_t time_id = des.time_id();
        bool async = des.async();

        auto time_it = saved_times_.find(time_id);
        if (time_it == saved_times_.end())
          continue;

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::DoomEntriesSince);

        MAYBE_PRINT << "DoomEntriesSince(time = " << time_it->second << ")"
                    << std::flush;
        int rv = cache_->DoomEntriesSince(time_it->second, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kDoomEntriesBetween: {
        if (!cache_)
          continue;

        const disk_cache_fuzzer::DoomEntriesBetween& deb =
            command.doom_entries_between();
        uint64_t from_time_id = deb.from_time_id();
        uint64_t to_time_id = deb.to_time_id();
        bool async = deb.async();

        auto from_time_it = saved_times_.find(from_time_id);
        auto to_time_it = saved_times_.find(to_time_id);
        if (from_time_it == saved_times_.end() ||
            to_time_it == saved_times_.end())
          continue;

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::DoomEntriesBetween);

        MAYBE_PRINT << "DoomEntriesBetween(from_time = " << from_time_it->second
                    << ", to_time = " << to_time_it->second << ")"
                    << std::flush;
        int rv =
            cache_->DoomEntriesBetween(from_time_it->second, to_time_it->second,
                                      std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kGetAvailableRange: {
        if (open_cache_entries_.empty())
          continue;

        const disk_cache_fuzzer::GetAvailableRange& gar =
            command.get_available_range();
        auto entry_it = GetNextValue(&open_cache_entries_, gar.entry_id());
        if (!IsValidEntry(&entry_it->second) ||
            !sparse_entry_tracker_[entry_it->second.entry_ptr])
          continue;

        uint64_t offset = gar.offset();
        if (gar.cap_offset())
          offset %= kMaxEntrySize;
        size_t size = gar.size() % kMaxEntrySize;
        bool async = gar.async();

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::GetAvailableRange);

        MAYBE_PRINT << "GetAvailableRange(\""
                    << entry_it->second.entry_ptr->GetKey()
                    << "\", offset = " << offset << ", size = " << size << ")"
                    << std::flush;
        int rv = entry_it->second.entry_ptr->GetAvailableRange(
            offset, size, nullptr, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kDoomKey: {
        if (!cache_)
          continue;
        const disk_cache_fuzzer::DoomKey& dk = command.doom_key();
        uint64_t key_id = dk.key_id();
        bool async = dk.async();

        if (created_cache_entries_.empty())
          continue;
        auto key_it = GetNextValue(&created_cache_entries_, key_id);

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::DoomKey);

        MAYBE_PRINT << "DoomKey(\"" << key_it->second << "\")" << std::flush;
        int rv = cache_->DoomEntry(key_it->second, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kSetTime: {
        const disk_cache_fuzzer::SetTime& st = command.set_time();
        uint64_t time_id = st.time_id();
        int64_t millis_since_unix_epoch = st.millis_since_unix_epoch();
        // Cap the maximum time that we will set.
        if (millis_since_unix_epoch > kMaxNumMillisToWait)
          millis_since_unix_epoch %= kMaxNumMillisToWait;
        base::Time new_time =
            base::Time::UnixEpoch() +
            base::Milliseconds(millis_since_unix_epoch);
        saved_times_[time_id] = new_time;
        MAYBE_PRINT << "SetTime(id = " << time_id << ", time = " << new_time
                    << ")" << std::endl;
        init_globals->task_environment_->AdvanceClock(
            new_time - base::Time::Now());
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kRunTaskForTest: {
        base::OnceClosure closure = base::BindOnce([]() {
          MAYBE_PRINT << "RunTaskForTest::task running" << std::endl;
        });
        RunTaskForTest(std::move(closure));
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kCloseAndDelete: {
        ShutdownBackend();
        CHECK(base::DeletePathRecursively(cache_path_));
        CHECK(temp_dir_.CreateUniqueTempDir());
        cache_path_ = temp_dir_.GetPath();
        MAYBE_PRINT << "CloseAndDelete()" << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kSetMaxSize:
      case disk_cache_fuzzer::FuzzCommand::kCacheBackend:
      case disk_cache_fuzzer::FuzzCommand::kCacheType:
      case disk_cache_fuzzer::FuzzCommand::kSimpleCacheWaitForIndex:
        // These commands are handled when the backend is created.
        break;
      case disk_cache_fuzzer::FuzzCommand::FUZZ_COMMAND_ONEOF_NOT_SET:
        break;
    }
  }
  ShutdownBackend();
}

DiskCacheLPMFuzzer::~DiskCacheLPMFuzzer() {
  ShutdownBackend();
}

void DiskCacheLPMFuzzer::CloseAllRemainingEntries() {
  for (auto const& [key, val] : open_cache_entries_) {
    if (val.entry_ptr) {
      MAYBE_PRINT << "~DiskCacheLPMFuzzer() closing entry for \""
                  << val.entry_ptr->GetKey() << "\"" << std::endl;
      val.entry_ptr->Close();
    }
  }
  open_cache_entries_.clear();
}

void DiskCacheLPMFuzzer::ShutdownBackend() {
  open_iterators_.clear();
  CloseAllRemainingEntries();
  simple_file_tracker_.reset();
  cache_.reset();
  block_impl_ = nullptr;
  simple_cache_impl_ = nullptr;
  mem_cache_ = nullptr;
  created_cache_entries_.clear();
  sparse_entry_tracker_.clear();
}

int64_t DiskCacheLPMFuzzer::ComputeMaxSize(
    const disk_cache_fuzzer::SetMaxSize* maybe_max_size) {
  if (!maybe_max_size)
    return 0;
  uint64_t max_size_kb = maybe_max_size->max_size_kb();
  if (max_size_kb > kMaxSizeKB)
    max_size_kb %= kMaxSizeKB;
  return static_cast<int64_t>(max_size_kb) * 1024;
}

void DiskCacheLPMFuzzer::CreateBackend(
    disk_cache_fuzzer::FuzzCommands::CacheBackend cache_backend,
    uint32_t mask,
    const disk_cache_fuzzer::SetMaxSize* maybe_max_size,
    net::CacheType type,
    bool simple_cache_wait_for_index) {
  ShutdownBackend();

  int64_t computed_max_size = ComputeMaxSize(maybe_max_size);
  MAYBE_PRINT << "Computed max size = " << computed_max_size << std::endl;

  switch (cache_backend) {
    case disk_cache_fuzzer::FuzzCommands::BLOCKFILE:
      MAYBE_PRINT << "Using Blockfile backend." << std::endl;
      CHECK_EQ(net::OK, disk_cache::CreateBlockCache(
                             cache_path_, computed_max_size, mask,
                             init_globals->task_environment_->GetMainThreadTaskRunner(),
                             &cache_, &block_impl_));
      break;
    case disk_cache_fuzzer::FuzzCommands::SIMPLE:
      MAYBE_PRINT << "Using Simple backend." << std::endl;
      simple_file_tracker_ =
          std::make_unique<disk_cache::SimpleFileTracker>(cache_path_);
      CHECK_EQ(net::OK, disk_cache::CreateSimpleCache(
                             init_globals->task_environment_->GetMainThreadTaskRunner(),
                             cache_path_, computed_max_size, mask,
                             simple_cache_wait_for_index, simple_file_tracker_.get(),
                             &cache_, &simple_cache_impl_));
      break;
    case disk_cache_fuzzer::FuzzCommands::MEMORY:
      MAYBE_PRINT << "Using Memory backend." << std::endl;
      CHECK_EQ(net::OK, disk_cache::CreateMemCache(
                             computed_max_size, mask,
                             init_globals->task_environment_->GetMainThreadTaskRunner(),
                             &cache_, &mem_cache_));
      break;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  disk_cache_fuzzer::FuzzCommands commands;
  if (!commands.ParseFromArray(data, size))
    return 0;

  DiskCacheLPMFuzzer().RunCommands(commands);
  return 0;
}
```

## 功能列举

该C++源代码文件 `disk_cache_fuzzer.cc` 是 Chromium 网络栈中用于对磁盘缓存进行模糊测试（fuzzing）的工具。其主要功能包括：

1. **模拟各种磁盘缓存操作:**  通过解析 `disk_cache_fuzzer.proto` 定义的命令，模拟创建、打开、关闭、写入、读取、删除缓存条目等操作。
2. **支持多种缓存后端:**  可以配置为测试不同的磁盘缓存后端实现，包括 Blockfile、Simple 和 Memory 后端。
3. **异步操作测试:** 能够模拟异步的缓存操作，例如异步创建、打开、写入和读取，以测试异步处理逻辑的正确性。
4. **错误和边界条件测试:** 通过随机生成或预定义的输入，尝试触发磁盘缓存实现中的错误、边界情况和潜在的崩溃。
5. **状态管理:**  维护一个模拟的缓存状态，包括已创建的条目、已打开的条目、已保存的时间戳和打开的迭代器，以便后续操作能够引用这些状态。
6. **可配置的参数:** 允许通过 protobuf 命令配置缓存的类型、最大大小、掩码等参数。
7. **时间控制:**  能够模拟时间的流逝，以便测试依赖于时间的缓存清理和过期机制。
8. **迭代器测试:**  支持创建和操作缓存条目的迭代器，以测试迭代器相关的逻辑。
9. **Doom 操作测试:**  模拟删除特定条目、删除所有条目以及删除指定时间范围内的条目等操作。
10. **稀疏条目测试:** 支持创建和操作稀疏缓存条目。
11. **一致性哈希用于状态管理:** 使用一致性哈希技术来管理打开的缓存条目，以提高模糊测试的效率和稳定性。

## 与 Javascript 的关系

该文件本身是用 C++ 编写的，主要用于测试 Chromium 的底层网络栈中的磁盘缓存实现。它 **不直接与 JavaScript 代码交互**。 然而，磁盘缓存的功能最终会影响到 Web 内容的加载和存储，因此与 JavaScript 的执行有间接关系。

**举例说明：**

假设一个 JavaScript 应用程序通过浏览器请求一个资源（例如，一张图片）。

1. 浏览器会检查磁盘缓存中是否存在该资源的副本。
2. 如果存在，浏览器会从磁盘缓存中加载该资源，而不会发起网络请求，从而提高加载速度。
3. `disk_cache_fuzzer.cc` 的作用是确保磁盘缓存的实现（负责存储和检索这些资源）在各种操作下都能正常工作，不会出现数据损坏或崩溃。

因此，虽然 JavaScript 代码不直接调用 `disk_cache_fuzzer.cc` 中的代码，但该 fuzzer 保证了底层缓存机制的健壮性，从而确保了 JavaScript 应用程序能够可靠地利用缓存。

## 逻辑推理的假设输入与输出

假设有以下 protobuf 命令序列：

**输入 (protobuf commands):**

1. `CreateBackend(SIMPLE, 0, SetMaxSize(1024), DISK_CACHE, false)`: 创建一个 Simple 类型的磁盘缓存后端，最大大小为 1024KB。
2. `CreateEntry(key_id=1, entry_id=10, pri=DEFAULT_PRIORITY, async=false, is_sparse=false)`: 同步创建一个键为 "Key1" 的缓存条目，ID 为 10。
3. `WriteData(entry_id=10, index=0, offset=0, size=5, truncate=false)`: 向 ID 为 10 的缓存条目的流 0 写入 5 字节的数据。
4. `ReadData(entry_id=10, index=0, offset=0, size=5)`: 从 ID 为 10 的缓存条目的流 0 读取 5 字节的数据。
5. `CloseEntry(entry_id=10)`: 关闭 ID 为 10 的缓存条目。

**输出 (推断的执行过程和可能的日志):**

```
CreateBackend()
CreateEntry("Key1", set_is_sparse = 0) = 0
WriteData("Key1", index = 0, offset = 0, size = 5, truncate = 0) = 5
ReadData("Key1", index = 0, offset = 0, size = 5) = 5
CloseEntry("Key1")
```

**解释：**

- 创建后端后，会创建一个新的缓存条目，同步操作会立即完成，返回 `net::OK` (0)。
- 写入操作会将 5 字节的数据写入条目，返回写入的字节数 (5)。
- 读取操作会成功读取之前写入的 5 字节数据，也返回读取的字节数 (5)。
- 最后，关闭缓存条目。

## 涉及的用户或编程常见的使用错误

该 fuzzer 可以帮助发现用户或开发者在使用磁盘缓存时可能犯的错误，例如：

1. **多次关闭同一个缓存条目:**  如果用户代码尝试关闭一个已经被关闭的缓存条目，可能会导致错误或崩溃。Fuzzer 可以通过生成连续的 `CloseEntry` 命令来测试这种情况。
    - **假设输入:**  `OpenEntry(key_id=1, entry_id=10)`, `CloseEntry(entry_id=10)`, `CloseEntry(entry_id=10)`
    - **预期结果:**  第二次 `CloseEntry` 可能导致错误。

2. **在条目被删除后尝试访问它:** 用户代码可能在调用 `DoomEntry` 后仍然持有该条目的指针并尝试进行读写操作。
    - **假设输入:** `OpenEntry(key_id=1, entry_id=10)`, `DoomEntry(entry_id=10)`, `WriteData(entry_id=10, ...)`
    - **预期结果:** `WriteData` 操作应该失败并返回错误。

3. **并发访问冲突:**  虽然这里的 fuzzer 是单线程的，但它模拟了异步操作，可以间接测试并发问题。例如，在异步打开一个条目的同时尝试写入该条目。
    - **假设输入:** `CreateEntry(async=true, ...)`, `WriteData(...)` (在异步创建完成之前)
    - **预期结果:**  取决于缓存的实现，可能写入操作会等待创建完成，或者会失败。

4. **超出条目大小限制的读写:**  用户代码可能尝试读取或写入超过条目实际大小的数据。
    - **假设输入:** `WriteData(size=10)`, `ReadData(size=100)` (假设实际写入的数据只有 10 字节)
    - **预期结果:** 读取操作可能会返回错误或读取到部分数据。

5. **不正确的偏移量访问稀疏条目:**  操作稀疏条目时，使用不正确的偏移量可能会导致错误。
    - **假设输入:** `CreateEntry(is_sparse=true)`, `WriteSparseData(offset=1000, ...)`, `ReadSparseData(offset=500, ...)` (在没有写入数据的偏移量读取)
    - **预期结果:** 读取操作可能会返回未初始化数据或错误。

## 用户操作如何一步步的到达这里 (调试线索)

虽然普通用户不会直接触发这个 fuzzer 代码，但开发人员可能会使用它来调试和测试磁盘缓存。以下是开发人员如何一步步到达这里：

1. **发现磁盘缓存相关的 bug 或潜在问题:** 开发人员可能在集成或使用 Chromium 的网络栈时，遇到与磁盘缓存相关的错误、性能问题或崩溃。
2. **怀疑是磁盘缓存实现的问题:** 通过分析错误日志、性能数据或进行代码审查，开发人员可能会怀疑问题出在磁盘缓存的实现上。
3. **需要更深入的测试和验证:**  为了重现和调试问题，开发人员需要一种方法来系统地测试磁盘缓存的各种操作和边界条件。
4. **选择使用模糊测试:**  模糊测试是一种有效的自动化测试方法，可以生成大量的随机或半随机输入，以发现潜在的漏洞和错误。
5. **运行 `disk_cache_fuzzer`:** 开发人员会编译并运行 `disk_cache_fuzzer` 这个测试工具，并提供一些初始的种子输入或配置。
6. **Fuzzer 生成测试用例:**  `disk_cache_fuzzer` 会根据其内部的算法和种子输入，生成一系列 `FuzzCommands` 的 protobuf 消息。
7. **解析 protobuf 命令并执行缓存操作:** `DiskCacheLPMFuzzer::RunCommands` 函数会解析这些 protobuf 消息，并调用相应的磁盘缓存 API 来执行模拟的缓存操作，例如 `CreateEntry`, `WriteData`, `ReadData` 等。
8. **观察和分析结果:** 开发人员会监控 fuzzer 的运行，观察是否发生了崩溃、断言失败或其他异常行为。如果发现问题，他们可以分析导致问题的具体 protobuf 命令序列，并利用这些信息来定位和修复磁盘缓存代码中的 bug。

## 功能归纳 (第1部分)

到目前为止，该文件主要定义了一个用于模糊测试 Chromium 磁盘缓存的框架。它包含了初始化代码、用于模拟缓存操作的类 `DiskCacheLPMFuzzer`，以及一些辅助函数。 该文件的核心功能是能够 **接收一系列预定义的缓存操作指令 (通过 protobuf 消息)**，并在模拟的缓存环境中 **执行这些操作**，从而达到测试磁盘缓存实现的目的。 它支持多种缓存后端和异步操作，并提供了一致性哈希等机制来管理缓存状态，以提高模糊测试的效率。

### 提示词
```
这是目录为net/disk_cache/disk_cache_fuzzer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cinttypes>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/raw_ptr_exclusion.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/checked_math.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/task_environment.h"
#include "base/test/test_timeouts.h"
#include "base/time/time.h"
#include "net/base/cache_type.h"
#include "net/base/interval.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_fuzzer.pb.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_file_tracker.h"
#include "net/disk_cache/simple/simple_index.h"
#include "testing/libfuzzer/proto/lpm_interface.h"

// To get a good idea of what a test case is doing, just run the libfuzzer
// target with LPM_DUMP_NATIVE_INPUT=1 prefixed. This will trigger all the
// prints below and will convey exactly what the test case is doing: use this
// instead of trying to print the protobuf as text.

// For code coverage:
// python ./tools/code_coverage/coverage.py disk_cache_lpm_fuzzer       -b
// out/coverage -o out/report       -c 'out/coverage/disk_cache_lpm_fuzzer
// -runs=0 -workers=24  corpus_disk_cache_simple'       -f net/disk_cache

void IOCallback(std::string io_type, int rv);

namespace {
const uint32_t kMaxSizeKB = 128;  // 128KB maximum.
const uint32_t kMaxSize = kMaxSizeKB * 1024;
const uint32_t kMaxEntrySize = kMaxSize * 2;
const uint32_t kNumStreams = 3;  // All caches seem to have 3 streams. TODO do
                                 // other specialized caches have this?
const uint64_t kFirstSavedTime =
    5;  // Totally random number chosen by dice roll. ;)
const uint32_t kMaxNumMillisToWait = 2019;
const int kMaxFdsSimpleCache = 10;

// Known colliding key values taken from SimpleCacheCreateCollision unittest.
const std::string kCollidingKey1 =
    "\xfb\x4e\x9c\x1d\x66\x71\xf7\x54\xa3\x11\xa0\x7e\x16\xa5\x68\xf6";
const std::string kCollidingKey2 =
    "\xbc\x60\x64\x92\xbc\xa0\x5c\x15\x17\x93\x29\x2d\xe4\x21\xbd\x03";

#define IOTYPES_APPLY(F) \
  F(WriteData)           \
  F(ReadData)            \
  F(WriteSparseData)     \
  F(ReadSparseData)      \
  F(DoomAllEntries)      \
  F(DoomEntriesSince)    \
  F(DoomEntriesBetween)  \
  F(GetAvailableRange)   \
  F(DoomKey)

enum class IOType {
#define ENUM_ENTRY(IO_TYPE) IO_TYPE,
  IOTYPES_APPLY(ENUM_ENTRY)
#undef ENUM_ENTRY
};

struct InitGlobals {
  InitGlobals() {
    base::CommandLine::Init(0, nullptr);

    print_comms_ = ::getenv("LPM_DUMP_NATIVE_INPUT");

    // TaskEnvironment requires TestTimeouts initialization to watch for
    // problematic long-running tasks.
    TestTimeouts::Initialize();

    // Mark this thread as an IO_THREAD with MOCK_TIME, and ensure that Now()
    // is driven from the same mock clock.
    task_environment_ = std::make_unique<base::test::TaskEnvironment>(
        base::test::TaskEnvironment::MainThreadType::IO,
        base::test::TaskEnvironment::TimeSource::MOCK_TIME);

    // Disable noisy logging as per "libFuzzer in Chrome" documentation:
    // testing/libfuzzer/getting_started.md#Disable-noisy-error-message-logging.
    logging::SetMinLogLevel(logging::LOGGING_FATAL);

    // Re-using this buffer for write operations may technically be against
    // IOBuffer rules but it shouldn't cause any actual problems.
    buffer_ = base::MakeRefCounted<net::IOBufferWithSize>(
        static_cast<size_t>(kMaxEntrySize));
    CacheTestFillBuffer(buffer_->data(), kMaxEntrySize, false);

#define CREATE_IO_CALLBACK(IO_TYPE) \
  io_callbacks_.push_back(base::BindRepeating(&IOCallback, #IO_TYPE));
    IOTYPES_APPLY(CREATE_IO_CALLBACK)
#undef CREATE_IO_CALLBACK
  }

  // This allows us to mock time for all threads.
  std::unique_ptr<base::test::TaskEnvironment> task_environment_;

  // Used as a pre-filled buffer for all writes.
  scoped_refptr<net::IOBuffer> buffer_;

  // Should we print debugging info?
  bool print_comms_;

  // List of IO callbacks. They do nothing (except maybe print) but are used by
  // all async entry operations.
  std::vector<base::RepeatingCallback<void(int)>> io_callbacks_;
};

InitGlobals* init_globals = new InitGlobals();
}  // namespace

class DiskCacheLPMFuzzer {
 public:
  DiskCacheLPMFuzzer() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    cache_path_ = temp_dir_.GetPath();
  }

  ~DiskCacheLPMFuzzer();

  void RunCommands(const disk_cache_fuzzer::FuzzCommands& commands);

 private:
  struct EntryInfo {
    EntryInfo() = default;

    EntryInfo(const EntryInfo&) = delete;
    EntryInfo& operator=(const EntryInfo&) = delete;

    // RAW_PTR_EXCLUSION: #addr-of
    RAW_PTR_EXCLUSION disk_cache::Entry* entry_ptr = nullptr;
    std::unique_ptr<TestEntryResultCompletionCallback> tcb;
  };
  void RunTaskForTest(base::OnceClosure closure);

  // Waits for an entry to be ready. Only should be called if there is a pending
  // callback for this entry; i.e. ei->tcb != nullptr.
  // Also takes the rv that the cache entry creation functions return, and does
  // not wait if rv.net_error != net::ERR_IO_PENDING (and would never have
  // called the callback).
  disk_cache::EntryResult WaitOnEntry(
      EntryInfo* ei,
      disk_cache::EntryResult result =
          disk_cache::EntryResult::MakeError(net::ERR_IO_PENDING));

  // Used as a callback for entry-opening backend calls. Will record the entry
  // in the map as usable and will release any entry-specific calls waiting for
  // the entry to be ready.
  void OpenCacheEntryCallback(uint64_t entry_id,
                              bool async,
                              bool set_is_sparse,
                              disk_cache::EntryResult result);

  // Waits for the entry to finish opening, in the async case. Then, if the
  // entry is successfully open (callback returns net::OK, or was already
  // successfully opened), check if the entry_ptr == nullptr. If so, the
  // entry has been closed.
  bool IsValidEntry(EntryInfo* ei);

  // Closes any non-nullptr entries in open_cache_entries_.
  void CloseAllRemainingEntries();

  // Fully shuts down and cleans up the cache backend.
  void ShutdownBackend();

  int64_t ComputeMaxSize(const disk_cache_fuzzer::SetMaxSize* maybe_max_size);
  void CreateBackend(
      disk_cache_fuzzer::FuzzCommands::CacheBackend cache_backend,
      uint32_t mask,
      const disk_cache_fuzzer::SetMaxSize* maybe_max_size,
      net::CacheType type,
      bool simple_cache_wait_for_index);

  // Places to keep our cache files.
  base::FilePath cache_path_;
  base::ScopedTempDir temp_dir_;

  // Pointers to our backend. Only one of block_impl_, simple_cache_impl_, and
  // mem_cache_ are active at one time.
  std::unique_ptr<disk_cache::Backend> cache_;
  raw_ptr<disk_cache::BackendImpl> block_impl_ = nullptr;
  std::unique_ptr<disk_cache::SimpleFileTracker> simple_file_tracker_;
  raw_ptr<disk_cache::SimpleBackendImpl> simple_cache_impl_ = nullptr;
  raw_ptr<disk_cache::MemBackendImpl> mem_cache_ = nullptr;

  // This "consistent hash table" keeys track of the keys we've added to the
  // backend so far. This should always be indexed by a "key_id" from a
  // protobuf.
  std::map<uint64_t, std::string> created_cache_entries_;
  // This "consistent hash table" keeps track of all opened entries we have from
  // the backend, and also contains some nullptr's where entries were already
  // closed. This should always be indexed by an "entry_id" from a protobuf.
  // When destructed, we close all entries that are still open in order to avoid
  // memory leaks.
  std::map<uint64_t, EntryInfo> open_cache_entries_;
  // This "consistent hash table" keeps track of all times we have saved, so
  // that we can call backend methods like DoomEntriesSince or
  // DoomEntriesBetween with sane timestamps. This should always be indexed by a
  // "time_id" from a protobuf.
  std::map<uint64_t, base::Time> saved_times_;
  // This "consistent hash table" keeps tack of all the iterators we have open
  // from the backend. This should always be indexed by a "it_id" from a
  // protobuf.
  std::map<uint64_t, std::unique_ptr<disk_cache::Backend::Iterator>>
      open_iterators_;

  // This maps keeps track of the sparsity of each entry, using their pointers.
  // TODO(mpdenton) remove if CreateEntry("Key0"); WriteData("Key0", index = 2,
  // ...); WriteSparseData("Key0", ...); is supposed to be valid.
  // Then we can just use CouldBeSparse before the WriteData.
  std::map<disk_cache::Entry*, bool> sparse_entry_tracker_;
};

#define MAYBE_PRINT               \
  if (init_globals->print_comms_) \
  std::cout

inline base::RepeatingCallback<void(int)> GetIOCallback(IOType iot) {
  return init_globals->io_callbacks_[static_cast<int>(iot)];
}

std::string ToKey(uint64_t key_num) {
  // Use one of the two colliding key values in 1% of executions.
  if (key_num % 100 == 99)
    return kCollidingKey1;
  if (key_num % 100 == 98)
    return kCollidingKey2;

  // Otherwise, use a value based on the key id and fuzzy padding.
  std::string padding(key_num & 0xFFFF, 'A');
  return "Key" + padding + base::NumberToString(key_num);
}

net::RequestPriority GetRequestPriority(
    disk_cache_fuzzer::RequestPriority lpm_pri) {
  CHECK(net::MINIMUM_PRIORITY <= static_cast<int>(lpm_pri) &&
        static_cast<int>(lpm_pri) <= net::MAXIMUM_PRIORITY);
  return static_cast<net::RequestPriority>(lpm_pri);
}

net::CacheType GetCacheTypeAndPrint(
    disk_cache_fuzzer::FuzzCommands::CacheType type,
    disk_cache_fuzzer::FuzzCommands::CacheBackend backend) {
  switch (type) {
    case disk_cache_fuzzer::FuzzCommands::APP_CACHE:
      MAYBE_PRINT << "Cache type = APP_CACHE." << std::endl;
      return net::CacheType::APP_CACHE;
    case disk_cache_fuzzer::FuzzCommands::REMOVED_MEDIA_CACHE:
      // Media cache no longer in use; handle as HTTP_CACHE
      MAYBE_PRINT << "Cache type = REMOVED_MEDIA_CACHE." << std::endl;
      return net::CacheType::DISK_CACHE;
    case disk_cache_fuzzer::FuzzCommands::SHADER_CACHE:
      MAYBE_PRINT << "Cache type = SHADER_CACHE." << std::endl;
      return net::CacheType::SHADER_CACHE;
    case disk_cache_fuzzer::FuzzCommands::PNACL_CACHE:
      // Simple cache won't handle PNACL_CACHE.
      if (backend == disk_cache_fuzzer::FuzzCommands::SIMPLE) {
        MAYBE_PRINT << "Cache type = DISK_CACHE." << std::endl;
        return net::CacheType::DISK_CACHE;
      }
      MAYBE_PRINT << "Cache type = PNACL_CACHE." << std::endl;
      return net::CacheType::PNACL_CACHE;
    case disk_cache_fuzzer::FuzzCommands::GENERATED_BYTE_CODE_CACHE:
      MAYBE_PRINT << "Cache type = GENERATED_BYTE_CODE_CACHE." << std::endl;
      return net::CacheType::GENERATED_BYTE_CODE_CACHE;
    case disk_cache_fuzzer::FuzzCommands::GENERATED_NATIVE_CODE_CACHE:
      MAYBE_PRINT << "Cache type = GENERATED_NATIVE_CODE_CACHE." << std::endl;
      return net::CacheType::GENERATED_NATIVE_CODE_CACHE;
    case disk_cache_fuzzer::FuzzCommands::DISK_CACHE:
      MAYBE_PRINT << "Cache type = DISK_CACHE." << std::endl;
      return net::CacheType::DISK_CACHE;
  }
}

void IOCallback(std::string io_type, int rv) {
  MAYBE_PRINT << " [Async IO (" << io_type << ") = " << rv << "]" << std::endl;
}

/*
 * Consistent hashing inspired map for fuzzer state.
 * If we stored open cache entries in a hash table mapping cache_entry_id ->
 * disk_cache::Entry*, then it would be highly unlikely that any subsequent
 * "CloseEntry" or "WriteData" etc. command would come up with an ID that would
 * correspond to a valid entry in the hash table. The optimal solution is for
 * libfuzzer to generate CloseEntry commands with an ID that matches the ID of a
 * previous OpenEntry command. But libfuzzer is stateless and should stay that
 * way.
 *
 * On the other hand, if we stored entries in a vector, and on a CloseEntry
 * command we took the entry at CloseEntry.id % (size of entries vector), we
 * would always generate correct CloseEntries. This is good, but all
 * dumb/general minimization techniques stop working, because deleting a single
 * OpenEntry command changes the indexes of every entry in the vector from then
 * on.
 *
 * So, we use something that's more stable for minimization: consistent hashing.
 * Basically, when we see a CloseEntry.id, we take the entry in the table that
 * has the next highest id (wrapping when there is no higher entry).
 *
 * This makes us resilient to deleting irrelevant OpenEntry commands. But, if we
 * delete from the table on CloseEntry commands, we still screw up all the
 * indexes during minimization. We'll get around this by not deleting entries
 * after CloseEntry commands, but that will result in a slightly less efficient
 * fuzzer, as if there are many closed entries in the table, many of the *Entry
 * commands will be useless. It seems like a decent balance between generating
 * useful fuzz commands and effective minimization.
 */
template <typename T>
typename std::map<uint64_t, T>::iterator GetNextValue(
    typename std::map<uint64_t, T>* entries,
    uint64_t val) {
  auto iter = entries->lower_bound(val);
  if (iter != entries->end())
    return iter;
  // Wrap to 0
  iter = entries->lower_bound(0);
  if (iter != entries->end())
    return iter;

  return entries->end();
}

void DiskCacheLPMFuzzer::RunTaskForTest(base::OnceClosure closure) {
  if (!block_impl_) {
    std::move(closure).Run();
    return;
  }

  net::TestCompletionCallback cb;
  int rv = block_impl_->RunTaskForTest(std::move(closure), cb.callback());
  CHECK_EQ(cb.GetResult(rv), net::OK);
}

// Resets the cb in the map so that WriteData and other calls that work on an
// entry don't wait for its result.
void DiskCacheLPMFuzzer::OpenCacheEntryCallback(
    uint64_t entry_id,
    bool async,
    bool set_is_sparse,
    disk_cache::EntryResult result) {
  // TODO(mpdenton) if this fails should we delete the entry entirely?
  // Would need to mark it for deletion and delete it later, as
  // IsValidEntry might be waiting for it.
  EntryInfo* ei = &open_cache_entries_[entry_id];

  if (async) {
    int rv = result.net_error();
    ei->entry_ptr = result.ReleaseEntry();
    // We are responsible for setting things up.
    if (set_is_sparse && ei->entry_ptr) {
      sparse_entry_tracker_[ei->entry_ptr] = true;
    }
    if (ei->entry_ptr) {
      MAYBE_PRINT << " [Async opening of cache entry for \""
                  << ei->entry_ptr->GetKey() << "\" callback (rv = " << rv
                  << ")]" << std::endl;
    }
    // Unblock any subsequent ops waiting for this --- they don't care about
    // the actual return value, but use something distinctive for debugging.
    ei->tcb->callback().Run(
        disk_cache::EntryResult::MakeError(net::ERR_FILE_VIRUS_INFECTED));
  } else {
    // The operation code will pull the result out of the completion callback,
    // so hand it to it.
    ei->tcb->callback().Run(std::move(result));
  }
}

disk_cache::EntryResult DiskCacheLPMFuzzer::WaitOnEntry(
    EntryInfo* ei,
    disk_cache::EntryResult result) {
  CHECK(ei->tcb);
  result = ei->tcb->GetResult(std::move(result));

  // Reset the callback so nobody accidentally waits on a callback that never
  // comes.
  ei->tcb.reset();
  return result;
}

bool DiskCacheLPMFuzzer::IsValidEntry(EntryInfo* ei) {
  if (ei->tcb) {
    // If we have a callback, we are the first to access this async-created
    // entry. Wait for it, and then delete it so nobody waits on it again.
    WaitOnEntry(ei);
  }
  // entry_ptr will be nullptr if the entry has been closed.
  return ei->entry_ptr != nullptr;
}

/*
 * Async implementation:
 1. RunUntilIdle at the top of the loop to handle any callbacks we've been
 posted from the backend thread.
 2. Only the entry creation functions have important callbacks. The good thing
 is backend destruction will cancel these operations. The entry creation
 functions simply need to keep the entry_ptr* alive until the callback is
 posted, and then need to make sure the entry_ptr is added to the map in order
 to Close it in the destructor.
    As for iterators, it's unclear whether closing an iterator will cancel
 callbacks.

 Problem: WriteData (and similar) calls will fail on the entry_id until the
 callback happens. So, I should probably delay these calls or otherwise will
 have very unreliable test cases. These are the options:
 1. Queue up WriteData (etc.) calls in some map, such that when the OpenEntry
 callback runs, the WriteData calls will all run.
 2. Just sit there and wait for the entry to be ready.

 #2 is probably best as it doesn't prevent any interesting cases and is much
 simpler.
 */

void DiskCacheLPMFuzzer::RunCommands(
    const disk_cache_fuzzer::FuzzCommands& commands) {
  // Skip too long command sequences, they are counterproductive for fuzzing.
  // The number was chosen empirically using the existing fuzzing corpus.
  if (commands.fuzz_commands_size() > 129)
    return;

  uint32_t mask =
      commands.has_set_mask() ? (commands.set_mask() ? 0x1 : 0xf) : 0;
  net::CacheType type =
      GetCacheTypeAndPrint(commands.cache_type(), commands.cache_backend());
  CreateBackend(
      commands.cache_backend(), mask,
      commands.has_set_max_size() ? &commands.set_max_size() : nullptr, type,
      commands.simple_cache_wait_for_index());
  MAYBE_PRINT << "CreateBackend()" << std::endl;

  {
    base::Time curr_time = base::Time::Now();
    saved_times_[kFirstSavedTime] = curr_time;
    // MAYBE_PRINT << "Saved initial time " << curr_time << std::endl;
  }

  for (const disk_cache_fuzzer::FuzzCommand& command :
       commands.fuzz_commands()) {
    // Handle any callbacks that other threads may have posted to us in the
    // meantime, so any successful async OpenEntry's (etc.) add their
    // entry_ptr's to the map.
    init_globals->task_environment_->RunUntilIdle();

    switch (command.fuzz_command_oneof_case()) {
      case disk_cache_fuzzer::FuzzCommand::kCreateEntry: {
        if (!cache_)
          continue;

        const disk_cache_fuzzer::CreateEntry& ce = command.create_entry();
        uint64_t key_id = ce.key_id();
        uint64_t entry_id = ce.entry_id();
        net::RequestPriority pri = GetRequestPriority(ce.pri());
        bool async = ce.async();
        bool is_sparse = ce.is_sparse();

        if (open_cache_entries_.find(entry_id) != open_cache_entries_.end())
          continue;  // Don't overwrite a currently open cache entry.

        std::string key_str = ToKey(key_id);
        created_cache_entries_[key_id] = key_str;

        EntryInfo* entry_info = &open_cache_entries_[entry_id];

        entry_info->tcb = std::make_unique<TestEntryResultCompletionCallback>();
        disk_cache::EntryResultCallback cb =
            base::BindOnce(&DiskCacheLPMFuzzer::OpenCacheEntryCallback,
                           base::Unretained(this), entry_id, async, is_sparse);

        MAYBE_PRINT << "CreateEntry(\"" << key_str
                    << "\", set_is_sparse = " << is_sparse
                    << ") = " << std::flush;
        disk_cache::EntryResult result =
            cache_->CreateEntry(key_str, pri, std::move(cb));
        if (!async || result.net_error() != net::ERR_IO_PENDING) {
          result = WaitOnEntry(entry_info, std::move(result));
          int rv = result.net_error();

          // Ensure we mark sparsity, save entry if the callback never ran.
          if (rv == net::OK) {
            entry_info->entry_ptr = result.ReleaseEntry();
            sparse_entry_tracker_[entry_info->entry_ptr] = is_sparse;
          }
          MAYBE_PRINT << rv << std::endl;
        } else {
          MAYBE_PRINT << "net::ERR_IO_PENDING (async)" << std::endl;
        }
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kOpenEntry: {
        if (!cache_)
          continue;

        const disk_cache_fuzzer::OpenEntry& oe = command.open_entry();
        uint64_t key_id = oe.key_id();
        uint64_t entry_id = oe.entry_id();
        net::RequestPriority pri = GetRequestPriority(oe.pri());
        bool async = oe.async();

        if (created_cache_entries_.empty())
          continue;

        if (open_cache_entries_.find(entry_id) != open_cache_entries_.end())
          continue;  // Don't overwrite a currently open cache entry.

        EntryInfo* entry_info = &open_cache_entries_[entry_id];

        entry_info->tcb = std::make_unique<TestEntryResultCompletionCallback>();
        disk_cache::EntryResultCallback cb =
            base::BindOnce(&DiskCacheLPMFuzzer::OpenCacheEntryCallback,
                           base::Unretained(this), entry_id, async, false);

        auto key_it = GetNextValue(&created_cache_entries_, key_id);
        MAYBE_PRINT << "OpenEntry(\"" << key_it->second
                    << "\") = " << std::flush;
        disk_cache::EntryResult result =
            cache_->OpenEntry(key_it->second, pri, std::move(cb));
        if (!async || result.net_error() != net::ERR_IO_PENDING) {
          result = WaitOnEntry(entry_info, std::move(result));
          int rv = result.net_error();
          if (rv == net::OK)
            entry_info->entry_ptr = result.ReleaseEntry();
          MAYBE_PRINT << rv << std::endl;
        } else {
          MAYBE_PRINT << "net::ERR_IO_PENDING (async)" << std::endl;
        }
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kOpenOrCreateEntry: {
        if (!cache_)
          continue;

        const disk_cache_fuzzer::OpenOrCreateEntry& ooce =
            command.open_or_create_entry();
        uint64_t key_id = ooce.key_id();
        uint64_t entry_id = ooce.entry_id();
        net::RequestPriority pri = GetRequestPriority(ooce.pri());
        bool async = ooce.async();
        bool is_sparse = ooce.is_sparse();

        if (open_cache_entries_.find(entry_id) != open_cache_entries_.end())
          continue;  // Don't overwrite a currently open cache entry.

        std::string key_str;
        // If our proto tells us to create a new entry, create a new entry, just
        // with OpenOrCreateEntry.
        if (ooce.create_new()) {
          // Use a possibly new key.
          key_str = ToKey(key_id);
          created_cache_entries_[key_id] = key_str;
        } else {
          if (created_cache_entries_.empty())
            continue;
          auto key_it = GetNextValue(&created_cache_entries_, key_id);
          key_str = key_it->second;
        }

        // Setup for callbacks.

        EntryInfo* entry_info = &open_cache_entries_[entry_id];

        entry_info->tcb = std::make_unique<TestEntryResultCompletionCallback>();
        disk_cache::EntryResultCallback cb =
            base::BindOnce(&DiskCacheLPMFuzzer::OpenCacheEntryCallback,
                           base::Unretained(this), entry_id, async, is_sparse);

        // Will only be set as sparse if it is created and not opened.
        MAYBE_PRINT << "OpenOrCreateEntry(\"" << key_str
                    << "\", set_is_sparse = " << is_sparse
                    << ") = " << std::flush;
        disk_cache::EntryResult result =
            cache_->OpenOrCreateEntry(key_str, pri, std::move(cb));
        if (!async || result.net_error() != net::ERR_IO_PENDING) {
          result = WaitOnEntry(entry_info, std::move(result));
          int rv = result.net_error();
          bool opened = result.opened();
          entry_info->entry_ptr = result.ReleaseEntry();
          // Ensure we mark sparsity, even if the callback never ran.
          if (rv == net::OK && !opened)
            sparse_entry_tracker_[entry_info->entry_ptr] = is_sparse;
          MAYBE_PRINT << rv << ", opened = " << opened << std::endl;
        } else {
          MAYBE_PRINT << "net::ERR_IO_PENDING (async)" << std::endl;
        }
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kCloseEntry: {
        if (open_cache_entries_.empty())
          continue;

        auto entry_it = GetNextValue(&open_cache_entries_,
                                     command.close_entry().entry_id());
        if (!IsValidEntry(&entry_it->second))
          continue;

        MAYBE_PRINT << "CloseEntry(\"" << entry_it->second.entry_ptr->GetKey()
                    << "\")" << std::endl;
        entry_it->second.entry_ptr->Close();

        // Set the entry_ptr to nullptr to ensure no one uses it anymore.
        entry_it->second.entry_ptr = nullptr;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kDoomEntry: {
        if (open_cache_entries_.empty())
          continue;

        auto entry_it =
            GetNextValue(&open_cache_entries_, command.doom_entry().entry_id());
        if (!IsValidEntry(&entry_it->second))
          continue;

        MAYBE_PRINT << "DoomEntry(\"" << entry_it->second.entry_ptr->GetKey()
                    << "\")" << std::endl;
        entry_it->second.entry_ptr->Doom();
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kWriteData: {
        if (open_cache_entries_.empty())
          continue;

        const disk_cache_fuzzer::WriteData& wd = command.write_data();
        auto entry_it = GetNextValue(&open_cache_entries_, wd.entry_id());
        if (!IsValidEntry(&entry_it->second))
          continue;

        int index = 0;  // if it's sparse, these non-sparse aware streams must
                        // read from stream 0 according to the spec.
                        // Implementations might have weaker constraints.
        if (!sparse_entry_tracker_[entry_it->second.entry_ptr])
          index = wd.index() % kNumStreams;
        uint32_t offset = wd.offset() % kMaxEntrySize;
        size_t size = wd.size() % kMaxEntrySize;
        bool async = wd.async();

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::WriteData);

        MAYBE_PRINT << "WriteData(\"" << entry_it->second.entry_ptr->GetKey()
                    << "\", index = " << index << ", offset = " << offset
                    << ", size = " << size << ", truncate = " << wd.truncate()
                    << ")" << std::flush;
        int rv = entry_it->second.entry_ptr->WriteData(
            index, offset, init_globals->buffer_.get(), size, std::move(cb),
            wd.truncate());
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kReadData: {
        if (open_cache_entries_.empty())
          continue;

        const disk_cache_fuzzer::ReadData& wd = command.read_data();
        auto entry_it = GetNextValue(&open_cache_entries_, wd.entry_id());
        if (!IsValidEntry(&entry_it->second))
          continue;

        int index = 0;  // if it's sparse, these non-sparse aware streams must
                        // read from stream 0 according to the spec.
                        // Implementations might weaker constraints?
        if (!sparse_entry_tracker_[entry_it->second.entry_ptr])
          index = wd.index() % kNumStreams;
        uint32_t offset = wd.offset() % kMaxEntrySize;
        size_t size = wd.size() % kMaxEntrySize;
        bool async = wd.async();
        auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(size);

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::ReadData);

        MAYBE_PRINT << "ReadData(\"" << entry_it->second.entry_ptr->GetKey()
                    << "\", index = " << index << ", offset = " << offset
                    << ", size = " << size << ")" << std::flush;
        int rv = entry_it->second.entry_ptr->ReadData(
            index, offset, buffer.get(), size, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kWriteSparseData: {
        if (open_cache_entries_.empty())
          continue;

        const disk_cache_fuzzer::WriteSparseData& wsd =
            command.write_sparse_data();
        auto entry_it = GetNextValue(&open_cache_entries_, wsd.entry_id());
        if (!IsValidEntry(&entry_it->second) ||
            !sparse_entry_tracker_[entry_it->second.entry_ptr])
          continue;

        uint64_t offset = wsd.offset();
        if (wsd.cap_offset())
          offset %= kMaxEntrySize;
        size_t size = wsd.size() % kMaxEntrySize;
        bool async = wsd.async();

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::WriteSparseData);
        MAYBE_PRINT << "WriteSparseData(\""
                    << entry_it->second.entry_ptr->GetKey()
                    << "\", offset = " << offset << ", size = " << size << ")"
                    << std::flush;
        int rv = entry_it->second.entry_ptr->WriteSparseData(
            offset, init_globals->buffer_.get(), size, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kReadSparseData: {
        if (open_cache_entries_.empty())
          continue;

        const disk_cache_fuzzer::ReadSparseData& rsd =
            command.read_sparse_data();
        auto entry_it = GetNextValue(&open_cache_entries_, rsd.entry_id());
        if (!IsValidEntry(&entry_it->second) ||
            !sparse_entry_tracker_[entry_it->second.entry_ptr])
          continue;

        uint64_t offset = rsd.offset();
        if (rsd.cap_offset())
          offset %= kMaxEntrySize;
        size_t size = rsd.size() % kMaxEntrySize;
        bool async = rsd.async();
        auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(size);

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::ReadSparseData);

        MAYBE_PRINT << "ReadSparseData(\""
                    << entry_it->second.entry_ptr->GetKey()
                    << "\", offset = " << offset << ", size = " << size << ")"
                    << std::flush;
        int rv = entry_it->second.entry_ptr->ReadSparseData(
            offset, buffer.get(), size, std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kDoomAllEntries: {
        if (!cache_)
          continue;
        bool async = command.doom_all_entries().async();

        net::TestCompletionCallback tcb;
        net::CompletionOnceCallback cb =
            !async ? tcb.callback() : GetIOCallback(IOType::DoomAllEntries);
        MAYBE_PRINT << "DoomAllEntries()" << std::flush;
        int rv = cache_->DoomAllEntries(std::move(cb));
        if (!async)
          rv = tcb.GetResult(rv);
        MAYBE_PRINT << " = " << rv << std::endl;
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kFlushQueueForTest: {
        // Blockfile-cache specific method.
        if (!block_impl_)
          return;

        net::TestCompletionCallback cb;
        MAYBE_PRINT << "FlushQueueForTest()" << std::endl;
        int rv = block_impl_->FlushQueueForTest(cb.callback());
        CHECK_EQ(cb.GetResult(rv), net::OK);
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kCreateIterator: {
        if (!cache_)
          continue;
        uint64_t it_id = command.create_iterator().it_id();
        MAYBE_PRINT << "CreateIterator(), id = " << it_id << std::endl;
        open_iterators_[it_id] = cache_->CreateIterator();
        break;
      }
      case disk_cache_fuzzer::FuzzCommand::kIteratorOpenNextEntry: {
        const disk_cache_fuzzer::IteratorOpenNextEntry& ione =
            command.iterator_open_next_entry();

        uint64_t it_id = ione.it_id();
        uint64_t entry_id = ione.entry_
```