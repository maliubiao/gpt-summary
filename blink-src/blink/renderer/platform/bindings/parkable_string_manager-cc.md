Response:
Let's break down the thought process for analyzing the `parkable_string_manager.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific source code file within the Chromium Blink engine. This involves identifying its purpose, key mechanisms, and potential interactions with other parts of the engine (especially JavaScript, HTML, and CSS). We also need to consider potential usage errors and provide illustrative examples.

2. **Initial Skim and Keyword Identification:**  The first step is a quick read-through to get a general sense of the code. Look for recurring keywords and phrases. In this case, "ParkableString," "park," "unpark," "compress," "disk," "memory," "age," "digest," "statistics," and "task" immediately stand out. These provide clues about the core functionality.

3. **Identify the Core Data Structures:**  Pay attention to the main data structures used. Here we see `unparked_strings_`, `parked_strings_`, and `on_disk_strings_`, all of type `StringMap` (which is likely a `HashMap` or similar). This suggests the manager keeps track of strings in different states. The `Statistics` struct also points to performance monitoring and memory management.

4. **Analyze Key Functions and Methods:**  Focus on the public and important-looking methods.

    * **`Instance()`:** This signals a singleton pattern, meaning there's only one instance of this manager.
    * **`Add()`:**  Likely responsible for adding strings to the manager. The presence of `SecureDigest` suggests deduplication or identification of strings.
    * **`Remove()`/`RemoveOnMainThread()`:**  Manages the removal of strings, likely involving reference counting and potentially disk cleanup.
    * **`ParkAll()`/`Park()`:**  The core parking functionality, probably involving compression and moving strings between the different maps.
    * **`Unpark()` (implied by `CompleteUnpark`):**  The reverse of parking, bringing strings back into active memory.
    * **`AgeStringsAndPark()`/`ScheduleAgingTaskIfNeeded()`:**  Suggests a mechanism for periodically moving strings to a parked or disk state.
    * **`PurgeMemory()`:**  A more aggressive form of parking, likely triggered by memory pressure.
    * **`ComputeStatistics()`:** Gathers metrics related to memory usage and savings.
    * **`SetRendererBackgrounded()`/`OnRAILModeChanged()`:**  Indicates the manager's behavior is influenced by the renderer's state (backgrounded or not, and RAIL mode).
    * **`OnMemoryDump()`:**  Related to memory tracing and debugging.

5. **Trace the Lifecycle of a String:** Try to follow a hypothetical string as it interacts with the manager. It might start as an "unparked" string, then be "parked" (potentially compressed), and possibly even moved "on disk."  When needed again, it would be "unparked."

6. **Consider Interactions with JavaScript/HTML/CSS:** This requires connecting the core functionality to the web development context. Think about where large strings might come from in this context:

    * **JavaScript:** Large string concatenations, dynamically generated content, data URIs, large JSON payloads.
    * **HTML:**  While HTML structure itself isn't usually huge, inline `<script>` or `<style>` blocks containing large amounts of code or data could qualify.
    * **CSS:**  Large CSS stylesheets, especially those with many complex rules or embedded data (e.g., `url()` with data URIs).

7. **Infer Logic and Assumptions:** Based on the code and the context, make logical deductions. For example, the aging mechanism likely prioritizes infrequently used strings for parking. The use of digests suggests deduplication to save memory.

8. **Identify Potential Usage Errors:**  Think about how a developer (or even the engine itself) might misuse this. For instance, holding onto references to `ParkableStringImpl` objects after they're intended to be parked could prevent memory savings. Incorrectly assuming a string is always in memory could also lead to issues.

9. **Construct Examples:** Create concrete scenarios to illustrate the functionality and potential issues. These examples should be simple and clear. For instance, a large JavaScript string being parked and then unparked when accessed.

10. **Refine and Organize:** Structure the findings logically, starting with the core functionality and then moving to interactions, logic, and potential errors. Use clear headings and bullet points for readability.

11. **Review and Verify:**  Read through the analysis to ensure it's accurate and covers the key aspects of the code. Double-check for consistency and clarity. (Self-correction during this phase is important!)  For instance, realizing that the `Remove` function posts a task to the main thread highlights the thread-safety considerations.

**(Self-Correction Example during the process):** Initially, I might focus only on the compression aspect. However, seeing the "on_disk" maps and the data allocator indicates another layer of optimization – moving less frequently used strings to disk. This requires adjusting the initial understanding to include this disk-based storage mechanism. Similarly, recognizing the influence of `RAILMode` and backgrounding adds another dimension to the analysis beyond simple memory management.
这个文件 `parkable_string_manager.cc` 是 Chromium Blink 渲染引擎中的一部分，它的主要功能是**管理可以被“停放”（parked）的字符串，以优化内存使用**。  “停放” 意味着将字符串的数据移动到不太常用的内存区域，或者进行压缩，甚至写入磁盘，从而减少主内存的占用。

以下是 `ParkableStringManager` 的主要功能：

1. **存储和管理字符串的不同状态：**  `ParkableStringManager` 维护着三个主要的字符串集合：
    * `unparked_strings_`: 存储当前在主内存中活跃使用的字符串。
    * `parked_strings_`: 存储已经被“停放”的字符串，可能被压缩但仍在内存中。
    * `on_disk_strings_`: 存储已经被移动到磁盘的字符串。

2. **“停放”字符串以节省内存：**  当字符串满足一定的条件（例如，大小超过阈值，且当前不在频繁使用中），`ParkableStringManager` 可以将其“停放”。这通常涉及：
    * **压缩：**  对字符串数据进行压缩以减少内存占用。
    * **移动到不太常用的内存区域：** 将字符串数据移动到一个单独的内存分配器中。
    * **写入磁盘：**  在内存压力较高的情况下，可以将字符串数据写入磁盘。

3. **“取消停放”字符串以供使用：** 当一个被“停放”的字符串需要被使用时，`ParkableStringManager` 会将其“取消停放”，这个过程可能涉及：
    * **从磁盘读取：** 如果字符串在磁盘上，需要先将其读取回内存。
    * **解压缩：** 如果字符串被压缩了，需要对其进行解压缩。
    * **移动到主内存：** 将字符串数据移动到主内存中。

4. **字符串的生命周期管理：**  `ParkableStringManager` 跟踪字符串的使用情况，并决定何时将字符串“停放”或“取消停放”。这通常基于一些启发式策略，例如字符串上次被访问的时间。

5. **内存统计和监控：**  `ParkableStringManager` 收集有关其管理的字符串的统计信息，例如原始大小、压缩后的大小、磁盘占用等，用于监控内存使用情况和优化策略。

6. **与内存压力事件集成：**  `ParkableStringManager` 会监听系统的内存压力事件，并在内存压力较高时更积极地“停放”字符串，甚至将其写入磁盘。

7. **与渲染器后台状态集成：**  当渲染器进入后台状态时，`ParkableStringManager` 可以更积极地“停放”字符串。

8. **使用哈希进行字符串的唯一标识：**  每个被管理的字符串都关联着一个唯一的哈希值 (`SecureDigest`)，用于快速查找和去重。

9. **线程安全管理：**  虽然主要操作发生在主线程，但某些操作可能在其他线程发起，因此需要保证线程安全。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`ParkableStringManager` 管理的字符串通常来源于 Blink 渲染引擎处理 JavaScript, HTML 和 CSS 的过程中产生的字符串数据。 大量的文本内容可能会被 `ParkableStringManager` 管理起来。

* **JavaScript:**
    * **假设输入：** JavaScript 代码中创建了一个非常大的字符串，例如通过读取一个大型文件或通过大量的字符串拼接生成。
    * **输出：** `ParkableStringManager` 可能会检测到这个大字符串，并根据其使用频率和系统内存压力，选择将其“停放”到内存中不常用的区域或磁盘上。
    * **举例：**  一个网页加载了一个包含大量 JSON 数据的 JavaScript 变量。这个 JSON 字符串可能很大，`ParkableStringManager` 可能会在一段时间后将其压缩并“停放”。当 JavaScript 代码再次访问这个 JSON 字符串时，`ParkableStringManager` 会将其“取消停放”。
    * **用户或编程常见的使用错误：**  如果在 JavaScript 中创建了大量生命周期很短但体积很大的字符串，频繁地“停放”和“取消停放”可能会带来性能开销。开发者可能无意中创建了这样的模式，而没有意识到 `ParkableStringManager` 的存在及其行为。

* **HTML:**
    * **假设输入：** 一个 HTML 页面包含一个非常大的 `<textarea>` 元素，其中用户输入了大量的文本。
    * **输出：** `ParkableStringManager` 可能会管理 `<textarea>` 中存储的文本字符串。如果用户长时间不与该 `<textarea>` 交互，这个字符串可能会被“停放”。
    * **举例：**  一个在线文档编辑器，用户在一个大的文本区域中输入了大量的文本。当用户切换到其他标签页一段时间后，这个文本字符串可能会被移动到磁盘上。当用户再次回到这个标签页时，需要从磁盘读取这个字符串。

* **CSS:**
    * **假设输入：** 一个 CSS 文件中包含大量的内联 `url()` 函数，这些函数指向的是 Base64 编码的大型图片或字体文件。
    * **输出：**  `ParkableStringManager` 可能会管理这些 Base64 编码的字符串。
    * **举例：**  一个网页使用了大量的自定义字体，这些字体以 Base64 编码的形式嵌入在 CSS 文件中。这些 Base64 字符串可能很大，`ParkableStringManager` 可能会对其进行管理，并根据需要进行“停放”和“取消停放”。

**逻辑推理的假设输入与输出：**

* **假设输入：**  `ParkableStringManager` 接收到一个大小为 2MB 的 JavaScript 字符串，且系统内存使用率较低。
* **输出：**  `ParkableStringManager` 可能会将这个字符串添加到 `unparked_strings_` 中，暂时不进行“停放”。

* **假设输入：**  一段时间后，相同的 2MB JavaScript 字符串长时间未被访问，且系统内存使用率升高。
* **输出：**  `ParkableStringManager` 的后台任务可能会将这个字符串移动到 `parked_strings_` 并进行压缩，或者在内存压力非常大的情况下，移动到 `on_disk_strings_`。

* **假设输入：**  JavaScript 代码尝试访问一个已经在 `on_disk_strings_` 中的字符串。
* **输出：**  `ParkableStringManager` 会触发从磁盘读取该字符串的操作，将其解压缩（如果需要），并将其移动回 `unparked_strings_`，然后 JavaScript 代码才能访问到这个字符串。

**用户或编程常见的使用错误举例说明：**

1. **过度依赖大字符串拼接：** 在 JavaScript 中，如果开发者频繁地拼接生成非常大的字符串，然后又很快丢弃这些字符串，可能会导致 `ParkableStringManager` 频繁地进行“停放”和“取消停放”，反而降低性能。  开发者应该考虑使用更高效的字符串处理方式，例如使用数组和 `join()` 方法。

2. **持有对可能被“停放”的字符串的长期引用：** 如果 JavaScript 代码持有对一个很大字符串的长期引用，即使这个字符串当前没有被使用，`ParkableStringManager` 也可能无法将其“停放”，因为存在活动的引用。这会导致内存占用无法被有效降低。

3. **不理解“停放”机制带来的延迟：**  当访问一个已经被“停放”到磁盘的字符串时，会引入一定的延迟来从磁盘读取数据。开发者需要理解这种机制，并避免在性能关键的代码路径中频繁访问可能被“停放”的超大字符串。

4. **错误地假设字符串始终在内存中：**  开发者不应该假设一个字符串始终存在于内存中且可以立即访问。  如果一个操作涉及到可能被“停放”的字符串，应该考虑到可能需要额外的处理时间来“取消停放”。

总而言之，`parkable_string_manager.cc` 文件实现了一个复杂的内存管理机制，用于优化 Blink 渲染引擎中大字符串的存储，尤其是在内存受限的环境下。理解其工作原理有助于开发者编写更高效的 Web 应用，并避免一些潜在的性能问题。

Prompt: 
```
这是目录为blink/renderer/platform/bindings/parkable_string_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/bindings/parkable_string_manager.h"

#include <algorithm>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/bindings/parkable_string.h"
#include "third_party/blink/renderer/platform/disk_data_allocator.h"
#include "third_party/blink/renderer/platform/instrumentation/memory_pressure_listener.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

struct ParkableStringManager::Statistics {
  size_t original_size;
  size_t uncompressed_size;
  size_t compressed_original_size;
  size_t compressed_size;
  size_t metadata_size;
  size_t overhead_size;
  size_t total_size;
  int64_t savings_size;
  size_t on_disk_size;
};

namespace {

bool CompressionEnabled() {
  return base::FeatureList::IsEnabled(features::kCompressParkableStrings);
}

class OnPurgeMemoryListener : public GarbageCollected<OnPurgeMemoryListener>,
                              public MemoryPressureListener {
  void OnPurgeMemory() override {
    if (!CompressionEnabled()) {
      return;
    }
    ParkableStringManager::Instance().PurgeMemory();
  }
};

Vector<ParkableStringImpl*> EnumerateStrings(
    const ParkableStringManager::StringMap& strings) {
  WTF::Vector<ParkableStringImpl*> all_strings;
  all_strings.reserve(strings.size());

  for (const auto& kv : strings)
    all_strings.push_back(kv.value);

  return all_strings;
}

void MoveString(ParkableStringImpl* string,
                ParkableStringManager::StringMap* from,
                ParkableStringManager::StringMap* to) {
  auto it = from->find(string->digest());
  CHECK(it != from->end(), base::NotFatalUntil::M130);
  DCHECK_EQ(it->value, string);
  from->erase(it);
  auto insert_result = to->insert(string->digest(), string);
  DCHECK(insert_result.is_new_entry);
}

}  // namespace

const char* ParkableStringManager::kAllocatorDumpName = "parkable_strings";
const base::TimeDelta ParkableStringManager::kFirstParkingDelay;

// static
ParkableStringManagerDumpProvider*
ParkableStringManagerDumpProvider::Instance() {
  DEFINE_STATIC_LOCAL(ParkableStringManagerDumpProvider, instance, ());
  return &instance;
}

bool ParkableStringManagerDumpProvider::OnMemoryDump(
    const base::trace_event::MemoryDumpArgs& args,
    base::trace_event::ProcessMemoryDump* pmd) {
  return ParkableStringManager::Instance().OnMemoryDump(pmd);
}

ParkableStringManagerDumpProvider::~ParkableStringManagerDumpProvider() =
    default;
ParkableStringManagerDumpProvider::ParkableStringManagerDumpProvider() =
    default;

ParkableStringManager& ParkableStringManager::Instance() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ParkableStringManager, instance, ());
  return instance;
}

ParkableStringManager::~ParkableStringManager() = default;

void ParkableStringManager::SetRendererBackgrounded(bool backgrounded) {
  DCHECK(IsMainThread());
  bool was_paused = IsPaused();
  backgrounded_ = backgrounded;

  if (was_paused && !IsPaused() && HasPendingWork()) {
    ScheduleAgingTaskIfNeeded();
  }
}

void ParkableStringManager::OnRAILModeChanged(RAILMode rail_mode) {
  DCHECK(IsMainThread());
  bool was_paused = IsPaused();
  rail_mode_ = rail_mode;

  if (was_paused && !IsPaused() && HasPendingWork()) {
    ScheduleAgingTaskIfNeeded();
  }
}

bool ParkableStringManager::OnMemoryDump(
    base::trace_event::ProcessMemoryDump* pmd) {
  DCHECK(IsMainThread());
  base::trace_event::MemoryAllocatorDump* dump =
      pmd->CreateAllocatorDump(kAllocatorDumpName);

  Statistics stats = ComputeStatistics();

  dump->AddScalar("size", "bytes", stats.total_size);
  dump->AddScalar("original_size", "bytes", stats.original_size);
  dump->AddScalar("uncompressed_size", "bytes", stats.uncompressed_size);
  dump->AddScalar("compressed_size", "bytes", stats.compressed_size);
  dump->AddScalar("metadata_size", "bytes", stats.metadata_size);
  dump->AddScalar("overhead_size", "bytes", stats.overhead_size);
  // Has to be uint64_t.
  dump->AddScalar("savings_size", "bytes",
                  stats.savings_size > 0 ? stats.savings_size : 0);
  dump->AddScalar("on_disk_size", "bytes", stats.on_disk_size);
  dump->AddScalar("on_disk_footprint", "bytes",
                  data_allocator().disk_footprint());
  dump->AddScalar("on_disk_free_chunks", "bytes",
                  data_allocator().free_chunks_size());

  pmd->AddSuballocation(dump->guid(),
                        WTF::Partitions::kAllocatedObjectPoolName);
  return true;
}

// static
bool ParkableStringManager::ShouldPark(const StringImpl& string) {
  // Don't attempt to park strings smaller than this size.
  static constexpr unsigned int kSizeThreshold = 10000;
  // TODO(lizeb): Consider parking non-main thread strings.
  return string.length() > kSizeThreshold && IsMainThread() &&
         CompressionEnabled();
}

// static
base::TimeDelta ParkableStringManager::AgingInterval() {
  return base::FeatureList::IsEnabled(features::kLessAggressiveParkableString)
             ? kLessAggressiveAgingInterval
             : kAgingInterval;
}

scoped_refptr<ParkableStringImpl> ParkableStringManager::Add(
    scoped_refptr<StringImpl>&& string,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest) {
  DCHECK(IsMainThread());

  ScheduleAgingTaskIfNeeded();

  auto string_impl = string;
  if (!digest) {
    digest = ParkableStringImpl::HashString(string_impl.get());
  } else {
#if DCHECK_IS_ON()
    // Verify that the provided hash is the same that we would have computed.
    // Otherwise the lookups below would not correctly deduplicate strings.
    std::unique_ptr<ParkableStringImpl::SecureDigest> expected_digest =
        ParkableStringImpl::HashString(string_impl.get());
    base::span<const uint8_t> expected_span(*expected_digest);
    base::span<const uint8_t> provided_span(*digest);
    CHECK_EQ(expected_span, provided_span);
#endif  // DCHECK_IS_ON()
  }
  DCHECK(digest.get());

  auto it = unparked_strings_.find(digest.get());
  if (it != unparked_strings_.end())
    return it->value;

  it = parked_strings_.find(digest.get());
  if (it != parked_strings_.end())
    return it->value;

  it = on_disk_strings_.find(digest.get());
  if (it != on_disk_strings_.end())
    return it->value;

  // No hit, new unparked string.
  auto new_parkable = ParkableStringImpl::MakeParkable(std::move(string_impl),
                                                       std::move(digest));
  auto insert_result =
      unparked_strings_.insert(new_parkable->digest(), new_parkable.get());
  DCHECK(insert_result.is_new_entry);

  // Lazy registration because registering too early can cause crashes on Linux,
  // see crbug.com/930117, and registering without any strings is pointless
  // anyway.
  if (!did_register_memory_pressure_listener_) {
    // No need to ever unregister, as the only ParkableStringManager instance
    // lives forever.
    MemoryPressureListenerRegistry::Instance().RegisterClient(
        MakeGarbageCollected<OnPurgeMemoryListener>());
    did_register_memory_pressure_listener_ = true;
  }

  if (!has_posted_unparking_time_accounting_task_) {
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&ParkableStringManager::RecordStatisticsAfter5Minutes,
                       base::Unretained(this)),
        base::Minutes(5));
    has_posted_unparking_time_accounting_task_ = true;
  }

  return new_parkable;
}

void ParkableStringManager::RemoveOnMainThread(ParkableStringImpl* string) {
  DCHECK(IsMainThread());
  DCHECK(string->may_be_parked());
  DCHECK(string->digest());

  {
    base::AutoLock locker(string->metadata_->lock_);
    // `RefCountedThreadSafeBase::Release()` may return false if the Main
    // Thread took a new reference to the string between the moment this task
    // was posted from a background thread and its execution.
    if (!string->RefCountedThreadSafeBase::Release()) {
      return;
    }

    StringMap* map = nullptr;
    if (string->is_on_disk_no_lock()) {
      map = &on_disk_strings_;
    } else if (string->is_parked_no_lock()) {
      map = &parked_strings_;
    } else {
      map = &unparked_strings_;
    }

    auto it = map->find(string->digest());
    CHECK(it != map->end(), base::NotFatalUntil::M130);
    map->erase(it);
  }

  if (string->has_on_disk_data()) {
    data_allocator().Discard(std::move(string->metadata_->on_disk_metadata_));
    // Now data_allocator may have enough free space for pending compressed
    // strings. Schedule for them.
    ScheduleAgingTaskIfNeeded();
  }

  delete string;
}

void ParkableStringManager::Remove(ParkableStringImpl* string) {
  if (task_runner_->BelongsToCurrentThread()) {
    RemoveOnMainThread(string);
    return;
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ParkableStringManager::RemoveOnMainThread,
                     base::Unretained(this), base::Unretained(string)));
}

void ParkableStringManager::CompleteUnparkOnMainThread(
    ParkableStringImpl* string,
    base::TimeDelta elapsed,
    base::TimeDelta disk_elapsed) {
  DCHECK(IsMainThread());
  bool was_on_disk = !disk_elapsed.is_min();
  RecordUnparkingTime(elapsed);
  OnUnparked(string, was_on_disk);
  if (was_on_disk) {
    RecordDiskReadTime(disk_elapsed);
  }
}

void ParkableStringManager::CompleteUnpark(ParkableStringImpl* string,
                                           base::TimeDelta elapsed,
                                           base::TimeDelta disk_elapsed) {
  // The task runner is bound to the main thread.
  if (task_runner_->BelongsToCurrentThread()) {
    CompleteUnparkOnMainThread(string, elapsed, disk_elapsed);
    return;
  }
  // Use a retained reference to prevent `string` from being deleted before
  // `CompleteUnpark()` is executed in the main thread.
  task_runner_->PostTask(
      FROM_HERE, BindOnce(&ParkableStringManager::CompleteUnparkOnMainThread,
                          base::Unretained(this), base::RetainedRef(string),
                          elapsed, disk_elapsed));
}

void ParkableStringManager::OnParked(ParkableStringImpl* newly_parked_string) {
  DCHECK(IsMainThread());
  DCHECK(newly_parked_string->may_be_parked());
  MoveString(newly_parked_string, &unparked_strings_, &parked_strings_);
}

void ParkableStringManager::OnWrittenToDisk(
    ParkableStringImpl* newly_written_string) {
  DCHECK(IsMainThread());
  DCHECK(newly_written_string->may_be_parked());
  MoveString(newly_written_string, &parked_strings_, &on_disk_strings_);
}

void ParkableStringManager::OnUnparked(ParkableStringImpl* was_parked_string,
                                       bool was_on_disk) {
  DCHECK(IsMainThread());
  DCHECK(was_parked_string->may_be_parked());
  StringMap* from_map = was_on_disk ? &on_disk_strings_ : &parked_strings_;
  MoveString(was_parked_string, from_map, &unparked_strings_);
  ScheduleAgingTaskIfNeeded();
}

void ParkableStringManager::ParkAll(ParkableStringImpl::ParkingMode mode) {
  DCHECK(IsMainThread());
  DCHECK(CompressionEnabled());

  // Parking may be synchronous, need to copy values first.
  // In case of synchronous parking, |ParkableStringImpl::Park()| calls
  // |OnParked()|, which moves the string from |unparked_strings_|
  // to |parked_strings_|, hence the need to copy values first.
  //
  // Efficiency: In practice, either we are parking strings for the first time,
  // and |unparked_strings_| can contain a few 10s of strings (and we will
  // trigger expensive compression), or this is a subsequent one, and
  // |unparked_strings_| will have few entries.
  auto unparked = EnumerateStrings(unparked_strings_);

  for (ParkableStringImpl* str : unparked) {
    str->Park(mode);
  }
}

size_t ParkableStringManager::Size() const {
  DCHECK(IsMainThread());

  return parked_strings_.size() + unparked_strings_.size();
}

void ParkableStringManager::RecordStatisticsAfter5Minutes() const {
  if (!CompressionEnabled()) {
    return;
  }

  base::UmaHistogramTimes("Memory.ParkableString.TotalParkingThreadTime.5min",
                          total_parking_thread_time_);
  base::UmaHistogramTimes("Memory.ParkableString.TotalUnparkingTime.5min",
                          total_unparking_time_);

  // These metrics only make sense if the disk allocator is used.
  if (data_allocator().may_write()) {
    Statistics stats = ComputeStatistics();
    base::UmaHistogramTimes("Memory.ParkableString.DiskWriteTime.5min",
                            total_disk_write_time_);
    base::UmaHistogramTimes("Memory.ParkableString.DiskReadTime.5min",
                            total_disk_read_time_);
    base::UmaHistogramCounts100000("Memory.ParkableString.OnDiskSizeKb.5min",
                                   static_cast<int>(stats.on_disk_size / 1000));
  }
}

void ParkableStringManager::AgeStringsAndPark() {
  DCHECK(CompressionEnabled());
  has_pending_aging_task_ = false;

  if (IsPaused()) {
    return;
  }

  TRACE_EVENT0("blink", "ParkableStringManager::AgeStringsAndPark");
  auto unparked = EnumerateStrings(unparked_strings_);
  auto parked = EnumerateStrings(parked_strings_);

  bool can_make_progress = false;
  for (ParkableStringImpl* str : unparked) {
    if (str->MaybeAgeOrParkString() ==
        ParkableStringImpl::AgeOrParkResult::kSuccessOrTransientFailure) {
      can_make_progress = true;
    }
  }

  for (ParkableStringImpl* str : parked) {
    if (str->MaybeAgeOrParkString() ==
        ParkableStringImpl::AgeOrParkResult::kSuccessOrTransientFailure) {
      can_make_progress = true;
    }
  }

  // Some strings will never be parkable because there are lasting external
  // references to them. Don't endlessely reschedule the aging task if we are
  // not making progress (that is, no new string was either aged or parked).
  //
  // This ensures that the tasks will stop getting scheduled, assuming that
  // the renderer is otherwise idle. Note that we cannot use "idle" tasks as
  // we need to age and park strings after the renderer becomes idle, meaning
  // that this has to run when the idle tasks are not. As a consequence, it
  // is important to make sure that this will not reschedule tasks forever.
  bool reschedule = HasPendingWork() && can_make_progress;
  if (reschedule)
    ScheduleAgingTaskIfNeeded();
}

void ParkableStringManager::ScheduleAgingTaskIfNeeded() {
  if (IsPaused()) {
    return;
  }

  if (has_pending_aging_task_)
    return;

  base::TimeDelta delay = AgingInterval();
  // Delay the first aging tick, since this renderer may be short-lived, we do
  // not want to waste CPU time compressing memory that is going away soon.
  if (!first_string_aging_was_delayed_) {
    delay = kFirstParkingDelay;
    first_string_aging_was_delayed_ = true;
  }

  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ParkableStringManager::AgeStringsAndPark,
                     base::Unretained(this)),
      delay);
  has_pending_aging_task_ = true;
}

void ParkableStringManager::PurgeMemory() {
  DCHECK(IsMainThread());
  DCHECK(CompressionEnabled());

  ParkAll(ParkableStringImpl::ParkingMode::kCompress);
}

ParkableStringManager::Statistics ParkableStringManager::ComputeStatistics()
    const {
  ParkableStringManager::Statistics stats = {};
  // The digest has an inline capacity set to the digest size, hence sizeof() is
  // accurate.
  constexpr size_t kParkableStringImplActualSize =
      sizeof(ParkableStringImpl) + sizeof(ParkableStringImpl::ParkableMetadata);

  for (const auto& kv : unparked_strings_) {
    ParkableStringImpl* str = kv.value;
    size_t size = str->CharactersSizeInBytes();
    stats.original_size += size;
    stats.uncompressed_size += size;
    stats.metadata_size += kParkableStringImplActualSize;

    if (str->has_compressed_data())
      stats.overhead_size += str->compressed_size();

    if (str->has_on_disk_data())
      stats.on_disk_size += str->on_disk_size();

    // Since ParkableStringManager wants to have a finer breakdown of memory
    // footprint, this doesn't directly use
    // |ParkableStringImpl::MemoryFootprintForDump()|. However we want the two
    // computations to be consistent, hence the DCHECK().
    size_t memory_footprint =
        (str->has_compressed_data() ? str->compressed_size() : 0) + size +
        kParkableStringImplActualSize;
    DCHECK_EQ(memory_footprint, str->MemoryFootprintForDump());
  }

  for (const auto& kv : parked_strings_) {
    ParkableStringImpl* str = kv.value;
    size_t size = str->CharactersSizeInBytes();
    stats.compressed_original_size += size;
    stats.original_size += size;
    stats.compressed_size += str->compressed_size();
    stats.metadata_size += kParkableStringImplActualSize;

    if (str->has_on_disk_data())
      stats.on_disk_size += str->on_disk_size();

    // See comment above.
    size_t memory_footprint =
        str->compressed_size() + kParkableStringImplActualSize;
    DCHECK_EQ(memory_footprint, str->MemoryFootprintForDump());
  }

  for (const auto& kv : on_disk_strings_) {
    ParkableStringImpl* str = kv.value;
    size_t size = str->CharactersSizeInBytes();
    stats.original_size += size;
    stats.metadata_size += kParkableStringImplActualSize;
    stats.on_disk_size += str->on_disk_size();
  }

  stats.total_size = stats.uncompressed_size + stats.compressed_size +
                     stats.metadata_size + stats.overhead_size;
  size_t memory_footprint = stats.compressed_size + stats.uncompressed_size +
                            stats.metadata_size + stats.overhead_size;
  stats.savings_size =
      stats.original_size - static_cast<int64_t>(memory_footprint);

  return stats;
}

void ParkableStringManager::AssertRemoved(ParkableStringImpl* string) {
#if DCHECK_IS_ON()
  auto it = on_disk_strings_.find(string->digest());
  DCHECK_EQ(it, on_disk_strings_.end());

  it = parked_strings_.find(string->digest());
  DCHECK_EQ(it, parked_strings_.end());

  it = unparked_strings_.find(string->digest());
  DCHECK_EQ(it, unparked_strings_.end());
#endif
}

void ParkableStringManager::ResetForTesting() {
  has_pending_aging_task_ = false;
  has_posted_unparking_time_accounting_task_ = false;
  did_register_memory_pressure_listener_ = false;
  total_unparking_time_ = base::TimeDelta();
  total_parking_thread_time_ = base::TimeDelta();
  total_disk_read_time_ = base::TimeDelta();
  total_disk_write_time_ = base::TimeDelta();
  unparked_strings_.clear();
  parked_strings_.clear();
  on_disk_strings_.clear();
  allocator_for_testing_ = nullptr;
  first_string_aging_was_delayed_ = false;
}

bool ParkableStringManager::IsPaused() const {
  DCHECK(IsMainThread());
  if (!CompressionEnabled()) {
    return true;
  }

  if (!base::FeatureList::IsEnabled(features::kLessAggressiveParkableString)) {
    return false;
  }

  return !(backgrounded_ && (rail_mode_ != RAILMode::kLoad));
}

bool ParkableStringManager::HasPendingWork() const {
  return !unparked_strings_.empty() || !parked_strings_.empty();
}

bool ParkableStringManager::IsOnParkedMapForTesting(
    ParkableStringImpl* string) {
  auto it = parked_strings_.find(string->digest());
  return it != parked_strings_.end();
}

bool ParkableStringManager::IsOnDiskMapForTesting(ParkableStringImpl* string) {
  auto it = on_disk_strings_.find(string->digest());
  return it != on_disk_strings_.end();
}

ParkableStringManager::ParkableStringManager()
    : task_runner_(Thread::MainThread()->GetTaskRunner(
          MainThreadTaskRunnerRestricted())) {
  // Should unregister in the destructor, but `this` is a NoDestructor static
  // local.
  ThreadScheduler::Current()->ToMainThreadScheduler()->AddRAILModeObserver(
      this);
}

}  // namespace blink

"""

```