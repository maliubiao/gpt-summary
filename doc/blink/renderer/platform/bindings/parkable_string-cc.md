Response:
Let's break down the thought process for analyzing the provided C++ code snippet and answering the request.

**1. Understanding the Core Request:**

The main goal is to understand the functionality of `parkable_string.cc` in the Chromium Blink engine. The request specifically asks about its relation to JavaScript, HTML, CSS, potential logical inferences, common usage errors, and a summary of its functions. The "Part 1 of 2" suggests a continuation, hinting at more complex interactions later.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for recognizable keywords and patterns. This gives a high-level overview:

* **Includes:**  `#include` directives point to dependencies: `string`, `vector`, `base/`, `third_party/blink/`, `third_party/snappy`, `third_party/zlib`, and potentially `third_party/zstd`. These suggest the file deals with string manipulation, memory management, threading, compression, and interaction with the Blink platform.
* **Namespaces:** The code is within the `blink` namespace.
* **Class Name:** `ParkableStringImpl` is the central class. The name itself is highly indicative of its purpose: managing strings in a way that allows them to be "parked."
* **Comments:**  The comments, especially the introductory ones and those explaining the `State` and `Status` enums, are invaluable.
* **Enums:** `State` (`kUnparked`, `kParked`, `kOnDisk`) and `Status` (`kUnreferencedExternally`, `kTooManyReferences`, `kLocked`) are key to understanding the object's lifecycle and state transitions.
* **Methods:**  Method names like `Lock`, `Unlock`, `ToString`, `Park`, `Unpark`, `CompressInBackground`, `DiscardUncompressedData`, and `DiscardCompressedData` strongly suggest the core operations of the class.
* **Memory Management:** Mentions of `PartitionAlloc`, `ReservedChunk`, and the general handling of compressed data indicate a focus on efficient memory usage.
* **Threading:**  The presence of `base::AutoLock`, `scoped_refptr`, `worker_pool::PostTask`, and the `BackgroundTaskParams` structure strongly suggest the use of background threads for operations like compression.
* **Compression Libraries:**  Includes for `snappy`, `zlib`, and potentially `zstd` confirm the involvement of compression.
* **Metrics:** The use of `base::UmaHistogram...` functions indicates the collection of performance metrics related to parking and unparking.
* **ASan:** The `#if defined(ADDRESS_SANITIZER)` blocks highlight memory safety considerations and interactions with the Address Sanitizer tool.

**3. Deciphering the Core Functionality - "Parking":**

The term "parkable" is central. The code strongly suggests a mechanism to reduce memory usage by compressing or moving string data to disk when it's not actively being used. This "parking" involves these stages:

* **Compression (kParked):** Compressing the string data in the background.
* **Moving to Disk (kOnDisk):** Persisting the compressed data to disk.
* **Unparking (kUnparked):**  Retrieving and decompressing the data when the string is needed.

**4. Identifying Relationships with Web Technologies:**

The filename and the `blink` namespace immediately connect this code to the rendering engine of Chromium, which handles the processing of web content (HTML, CSS, JavaScript).

* **JavaScript:**  JavaScript interacts with strings heavily. When JavaScript code manipulates strings, those strings might be represented by `ParkableStringImpl` objects in the Blink engine. The `ToString()` method is a clear indication of converting the internal representation to a standard string that JavaScript can understand.
* **HTML/CSS:**  HTML and CSS also involve strings (tag names, attribute values, CSS property values). These strings, when processed by Blink, could also be managed by the `ParkableStringImpl` mechanism. While the code doesn't directly mention specific HTML or CSS elements, the general purpose of string management in a rendering engine implies their involvement.

**5. Logical Inferences and Examples:**

Based on the "parking" concept, we can infer the following:

* **Input:** A large string object being held in memory.
* **Process:**  The `ParkableStringImpl` object, after a period of inactivity, might transition to a parked state (compressed or on disk).
* **Output:** The memory footprint of the string is reduced while parked. When the string is accessed again, it's unparked, potentially incurring a slight delay for decompression or disk I/O.

**6. Identifying Potential Usage Errors:**

The locking mechanisms (`Lock()`, `Unlock()`) and the state transitions offer opportunities for errors:

* **Double Locking:** Calling `Lock()` multiple times without corresponding `Unlock()` calls. The code has checks to prevent `lock_depth_` from overflowing.
* **Unlocking Without Locking:** Calling `Unlock()` without a preceding `Lock()`. The code has checks to prevent `lock_depth_` from underflowing.
* **Accessing a Poisoned String (with ASan):**  If ASan is enabled, accessing the string data after it has been poisoned (typically after `Unlock()` when there are no other external references) can lead to errors.

**7. Synthesizing the Functionality Summary:**

The final step is to summarize the identified functionalities in a concise manner. The core ideas are:

* **Memory Optimization:** Reducing memory usage by compressing or moving inactive strings to disk.
* **Background Processing:** Using background threads for expensive operations like compression and disk I/O.
* **State Management:** Tracking the state of the string (unparked, parked, on disk) and its lock status.
* **Integration with Blink:** Being a part of the Chromium Blink rendering engine.
* **Performance Metrics:** Collecting data to analyze the effectiveness of the parking mechanism.
* **Memory Safety:** Using ASan for debugging and identifying memory-related issues.

By following these steps, we can systematically analyze the provided code snippet and generate a comprehensive answer that addresses the specific points raised in the request.
好的，让我们来分析一下 `blink/renderer/platform/bindings/parkable_string.cc` 文件的功能。

**核心功能：内存优化的可停靠字符串**

这个文件的核心功能是实现 `ParkableStringImpl` 类，这个类是对 `blink::String` 的一个包装，旨在优化内存使用。它允许在字符串不被频繁使用时，将其“停靠”（park），通过压缩或移动到磁盘的方式来减少其在内存中的占用。当需要使用字符串时，再将其“取消停靠”（unpark）。

**与 JavaScript, HTML, CSS 的关系**

`ParkableStringImpl` 主要是 Blink 内部使用的机制，用于管理各种字符串数据。这些数据很多都来源于或服务于 JavaScript, HTML, CSS 的处理：

1. **JavaScript 中的字符串:**  当 JavaScript 代码创建或操作字符串时，Blink 内部可能会使用 `ParkableStringImpl` 来存储这些字符串。尤其是一些生命周期较长，但并非总是活跃使用的字符串，例如一些常量字符串或不常用的变量。
    * **举例:**  假设一个 JavaScript 脚本中定义了一个较大的常量字符串，例如一个很长的错误消息。Blink 可能会用 `ParkableStringImpl` 来存储这个字符串。如果这个错误消息在用户会话的大部分时间里都不会被触发，那么这个字符串就可以被停靠，从而节省内存。
    * **逻辑推理:**
        * **假设输入:**  JavaScript 代码 `const errorMessage = "非常长的错误消息字符串...";`
        * **Blink 处理:** Blink 在内部会将 `errorMessage` 的值存储为 `ParkableStringImpl` 对象。在一段时间后，如果该字符串没有被频繁访问，`ParkableStringImpl` 可能会将其压缩或移动到磁盘。
        * **假设再次访问:** 当 JavaScript 代码尝试访问 `errorMessage` 时，`ParkableStringImpl` 会将其解压缩或从磁盘加载回内存。

2. **HTML 和 CSS 中的字符串:** HTML 标签名、属性值，以及 CSS 属性名、属性值等都是字符串。Blink 在解析和处理 HTML 和 CSS 时，也会使用字符串来表示这些信息。`ParkableStringImpl` 可以用于优化这些字符串的存储。
    * **举例:**  一个网站的 CSS 文件中可能包含一些不常用的自定义 CSS 变量。这些变量的值就可以被存储为 `ParkableStringImpl` 对象，并在不使用时被停靠。
    * **逻辑推理:**
        * **假设输入:** CSS 文件中定义了 `--rarely-used-color: #abcdef;`
        * **Blink 处理:**  Blink 在解析 CSS 时，会将 `--rarely-used-color` 和 `#abcdef` 的值存储为 `ParkableStringImpl` 对象。如果这个颜色变量在页面渲染过程中很少被用到，`ParkableStringImpl` 可能会将其停靠。
        * **假设再次使用:** 当某个元素需要使用这个 CSS 变量时，`ParkableStringImpl` 会将其恢复。

**逻辑推理、假设输入与输出**

上面的 JavaScript 和 CSS 的例子已经包含了逻辑推理和假设输入输出。 总结一下 `ParkableStringImpl` 的主要逻辑推理：

* **假设输入:** 一个 `ParkableStringImpl` 对象表示一个字符串，并且该字符串在一段时间内没有被频繁访问。
* **内部处理:** `ParkableStringImpl` 会根据其内部的状态（例如，是否被锁定、是否有外部引用、字符串的“年龄”）以及系统资源情况，决定是否将字符串停靠。停靠的方式可以是压缩数据在内存中，或者将压缩数据写入磁盘。
* **输出（停靠后）:**  该 `ParkableStringImpl` 对象占用的内存减少，或者其主要的字符串数据不再存在于内存中。
* **假设再次访问输入:**  当需要再次访问该 `ParkableStringImpl` 对象所代表的字符串时。
* **内部处理:** `ParkableStringImpl` 会执行“取消停靠”操作，将压缩的数据解压缩或从磁盘读取到内存，并重新创建 `blink::String` 对象。
* **输出（取消停靠后）:**  可以正常访问该字符串，但可能存在一定的延迟（解压缩或磁盘 I/O）。

**用户或编程常见的使用错误**

由于 `ParkableStringImpl` 主要是 Blink 内部使用的机制，开发者一般不会直接操作它。但是，理解其背后的原理可以帮助理解 Blink 的内存管理策略。 常见的错误可能发生在 Blink 内部的开发中：

1. **过早地释放或访问已停靠的字符串:** 如果在后台停靠操作尚未完成时尝试访问或释放字符串，可能会导致数据不一致或崩溃。`ParkableStringImpl` 使用锁 (`base::AutoLock`) 和状态标记 (`metadata_->state_`, `metadata_->background_task_in_progress_`) 来避免这种情况。
2. **在错误的线程访问:**  某些操作（例如停靠到磁盘）是在后台线程执行的，如果在主线程或其他不正确的线程访问相关数据，可能会导致线程安全问题。`ParkableStringImpl` 通过 `scheduler::PostCrossThreadTask` 等机制来确保线程安全。
3. **内存分配失败处理不当:** 在压缩或写入磁盘的过程中，可能会发生内存分配失败。代码中可以看到使用 `WTF::Partitions::BufferPartition()->AllocInline<partition_alloc::AllocFlags::kReturnNull>` 并检查返回值来处理这种情况，但如果处理不当，可能会导致程序崩溃。

**功能归纳**

`blink/renderer/platform/bindings/parkable_string.cc` 文件的主要功能是实现了 `ParkableStringImpl` 类，用于对 `blink::String` 进行内存优化管理。其核心机制包括：

* **停靠 (Parking):**  通过压缩字符串数据或将其移动到磁盘，减少在内存中的占用。
* **取消停靠 (Unparking):**  当需要使用字符串时，将其解压缩或从磁盘加载回内存。
* **状态管理:**  跟踪字符串的停靠状态（未停靠、已停靠、在磁盘上）以及其他相关属性（例如年龄、锁定状态）。
* **后台处理:**  利用后台线程执行耗时的停靠和取消停靠操作，避免阻塞主线程。
* **内存管理:**  使用 PartitionAlloc 进行内存分配，并进行内存安全管理（例如通过 AddressSanitizer 进行检测）。
* **性能监控:**  通过 UMA 宏记录停靠和取消停靠的延迟和吞吐量等指标，用于性能分析和优化。

总结来说，`ParkableStringImpl` 是 Blink 引擎中一个关键的内存优化组件，它通过智能地管理字符串的生命周期和存储方式，有效地降低了内存消耗，从而提升了浏览器的性能和稳定性。

### 提示词
```
这是目录为blink/renderer/platform/bindings/parkable_string.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/bindings/parkable_string.h"

#include <array>
#include <string_view>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/checked_iterators.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/raw_span.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/process/memory.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/typed_macros.h"
#include "partition_alloc/oom.h"
#include "partition_alloc/partition_alloc.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/bindings/buildflags.h"
#include "third_party/blink/renderer/platform/bindings/parkable_string_manager.h"
#include "third_party/blink/renderer/platform/crypto.h"
#include "third_party/blink/renderer/platform/disk_data_allocator.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/web_process_memory_dump.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/sanitizers.h"
#include "third_party/blink/renderer/platform/wtf/thread_specific.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/snappy/src/snappy.h"
#include "third_party/zlib/google/compression_utils.h"

#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
// "GN check" doesn't know that this file is only included when
// BUILDFLAG(HAS_ZSTD_COMPRESSION) is true. Disable it here.
#include "third_party/zstd/src/lib/zstd.h"  // nogncheck
#endif

namespace blink {

namespace {

ParkableStringImpl::Age MakeOlder(ParkableStringImpl::Age age) {
  switch (age) {
    case ParkableStringImpl::Age::kYoung:
      return ParkableStringImpl::Age::kOld;
    case ParkableStringImpl::Age::kOld:
    case ParkableStringImpl::Age::kVeryOld:
      return ParkableStringImpl::Age::kVeryOld;
  }
}

enum class ParkingAction { kParked, kUnparked, kWritten, kRead };

void RecordLatencyHistogram(const char* histogram_name,
                            base::TimeDelta duration) {
  // Size is at least 10kB, and at most ~10MB, and throughput ranges from
  // single-digit MB/s to ~1000MB/s depending on the CPU/disk, hence the ranges.
  base::UmaHistogramCustomMicrosecondsTimes(
      histogram_name, duration, base::Microseconds(500), base::Seconds(1), 100);
}

void RecordThroughputHistogram(const char* histogram_name,
                               int throughput_mb_s) {
  base::UmaHistogramCounts1000(histogram_name, throughput_mb_s);
}

void RecordStatistics(size_t size,
                      base::TimeDelta duration,
                      ParkingAction action) {
  int throughput_mb_s =
      base::ClampRound(size / duration.InSecondsF() / 1000000);
  int size_kb = static_cast<int>(size / 1000);

  switch (action) {
    case ParkingAction::kParked:
      // Size should be <1MiB in most cases.
      base::UmaHistogramCounts1000("Memory.ParkableString.Compression.SizeKb",
                                   size_kb);
      RecordLatencyHistogram("Memory.ParkableString.Compression.Latency",
                             duration);
      break;
    case ParkingAction::kUnparked:
      RecordLatencyHistogram("Memory.ParkableString.Decompression.Latency",
                             duration);
      RecordThroughputHistogram(
          "Memory.ParkableString.Decompression.ThroughputMBps",
          throughput_mb_s);
      break;
    case ParkingAction::kRead:
      RecordLatencyHistogram("Memory.ParkableString.Read.Latency", duration);
      break;
    case ParkingAction::kWritten:
      // No metric recorded.
      break;
  }
}

void AsanPoisonString(const String& string) {
#if defined(ADDRESS_SANITIZER)
  if (string.IsNull())
    return;
  // Since |string| is not deallocated, it remains in the AtomicStringTable,
  // where its content can be accessed for equality comparison for instance,
  // triggering a poisoned memory access. See crbug.com/883344 for an example.
  if (string.Impl()->IsAtomic())
    return;

  ASAN_POISON_MEMORY_REGION(string.Bytes(), string.CharactersSizeInBytes());
#endif  // defined(ADDRESS_SANITIZER)
}

void AsanUnpoisonString(const String& string) {
#if defined(ADDRESS_SANITIZER)
  if (string.IsNull())
    return;

  ASAN_UNPOISON_MEMORY_REGION(string.Bytes(), string.CharactersSizeInBytes());
#endif  // defined(ADDRESS_SANITIZER)
}

// Char buffer allocated using PartitionAlloc, may be nullptr.
class NullableCharBuffer final {
  STACK_ALLOCATED();

 public:
  using iterator = base::CheckedContiguousIterator<const char>;

  explicit NullableCharBuffer(size_t size) {
    data_ = reinterpret_cast<char*>(
        WTF::Partitions::BufferPartition()
            ->AllocInline<partition_alloc::AllocFlags::kReturnNull>(
                size, "NullableCharBuffer"));
    size_ = size;
  }

  NullableCharBuffer(const NullableCharBuffer&) = delete;
  NullableCharBuffer& operator=(const NullableCharBuffer&) = delete;

  ~NullableCharBuffer() {
    if (data_)
      WTF::Partitions::BufferPartition()->Free(data_);
  }

  // May return nullptr.
  char* data() { return data_; }
  const char* data() const { return data_; }
  size_t size() const { return size_; }

  // Iterators, so this type meets the requirements of
  // `std::ranges::contiguous_range`.
  iterator begin() const {
    // SAFETY: The constructor allocates `size_` bytes at `data_`, which are not
    // freed until destruction, and the members are not changed after
    // construction.
    return UNSAFE_BUFFERS(iterator(data_, data_ + size_));
  }
  iterator end() const {
    // SAFETY: As in `begin()` above.
    return UNSAFE_BUFFERS(iterator(data_, data_ + size_, data_ + size_));
  }

 private:
  char* data_;
  size_t size_;
};

}  // namespace

// Created and destroyed on the same thread, accessed on a background thread as
// well. |string|'s reference counting is *not* thread-safe, hence |string|'s
// reference count must *not* change on the background thread.
struct BackgroundTaskParams final {
  BackgroundTaskParams(
      scoped_refptr<ParkableStringImpl> string,
      base::span<const uint8_t> data,
      std::unique_ptr<ReservedChunk> reserved_chunk,
      scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner)
      : callback_task_runner(callback_task_runner),
        string(std::move(string)),
        data(data),
        reserved_chunk(std::move(reserved_chunk)) {}

  BackgroundTaskParams(const BackgroundTaskParams&) = delete;
  BackgroundTaskParams& operator=(const BackgroundTaskParams&) = delete;
  ~BackgroundTaskParams() { DCHECK(IsMainThread()); }

  const scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner;
  const scoped_refptr<ParkableStringImpl> string;
  base::raw_span<const uint8_t> data;
  std::unique_ptr<ReservedChunk> reserved_chunk;
};

// Valid transitions are:
//
// Compression:
// 1. kUnparked -> kParked: Parking completed normally
// 4. kParked -> kUnparked: String has been unparked.
//
// Disk:
// 1. kParked -> kOnDisk: Writing completed successfully
// 4. kOnDisk -> kUnParked: The string is requested, triggering a read and
//    decompression
//
// Since parking and disk writing are not synchronous operations the first time,
// when the asynchronous background task is posted,
// |background_task_in_progress_| is set to true. This prevents further string
// aging, and protects against concurrent background tasks.
//
// Each state can be combined with a string that is either old or
// young. Examples below:
// - kUnParked:
//   - (Very) Old: old strings are not necessarily parked
//   - Young: a string starts young and unparked.
// - kParked:
//   - (Very) Old: Parked, and not touched nor locked since then
//   - Young: Lock() makes a string young but doesn't unpark it.
// - kOnDisk:
//   - Very Old: On disk, and not touched nor locked since then
//   - Young: Lock() makes a string young but doesn't unpark it.
enum class ParkableStringImpl::State : uint8_t { kUnparked, kParked, kOnDisk };

// Current "ownership" status of the underlying data.
//
// - kUnreferencedExternally: |string_| is not referenced externally, and the
//   class is free to change it.
// - kTooManyReferences: |string_| has multiple references pointing to it,
//   cannot change it.
// - kLocked: |this| is locked.
enum class ParkableStringImpl::Status : uint8_t {
  kUnreferencedExternally,
  kTooManyReferences,
  kLocked
};

ParkableStringImpl::ParkableMetadata::ParkableMetadata(
    String string,
    std::unique_ptr<SecureDigest> digest)
    : lock_(),
      lock_depth_(0),
      state_(State::kUnparked),
      compression_failed_(false),
      compressed_(nullptr),
      digest_(*digest),
      age_(Age::kYoung),
      is_8bit_(string.Is8Bit()),
      length_(string.length()) {}

// static
std::unique_ptr<ParkableStringImpl::SecureDigest>
ParkableStringImpl::HashString(StringImpl* string) {
  DigestValue digest_result;

  Digestor digestor(kHashAlgorithmSha256);
  digestor.Update(string->RawByteSpan());
  // Also include encoding in the digest, otherwise two strings with identical
  // byte content but different encoding will be assumed equal, leading to
  // crashes when one is replaced by the other one.
  UpdateDigestWithEncoding(&digestor, string->Is8Bit());
  digestor.Finish(digest_result);

  // The only case where this can return false in BoringSSL is an allocation
  // failure of the temporary data required for hashing. In this case, there
  // is nothing better to do than crashing.
  if (digestor.has_failed()) {
    // Don't know the exact size, the SHA256 spec hints at ~64 (block size)
    // + 32 (digest) bytes.
    base::TerminateBecauseOutOfMemory(64 + kDigestSize);
  }
  // Unless SHA256 is... not 256 bits?
  DCHECK(digest_result.size() == kDigestSize);
  return std::make_unique<SecureDigest>(digest_result);
}

// static
void ParkableStringImpl::UpdateDigestWithEncoding(Digestor* digestor,
                                                  bool is_8bit) {
  std::array<uint8_t, 1> extra_data;
  extra_data[0] = is_8bit ? 1 : 0;
  digestor->Update(extra_data);
}

// static
scoped_refptr<ParkableStringImpl> ParkableStringImpl::MakeNonParkable(
    scoped_refptr<StringImpl>&& impl) {
  return base::AdoptRef(new ParkableStringImpl(std::move(impl), nullptr));
}

// static
scoped_refptr<ParkableStringImpl> ParkableStringImpl::MakeParkable(
    scoped_refptr<StringImpl>&& impl,
    std::unique_ptr<SecureDigest> digest) {
  DCHECK(!!digest);
  return base::AdoptRef(
      new ParkableStringImpl(std::move(impl), std::move(digest)));
}

// static
ParkableStringImpl::CompressionAlgorithm
ParkableStringImpl::GetCompressionAlgorithm() {
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
  if (base::FeatureList::IsEnabled(features::kUseZstdForParkableStrings)) {
    return CompressionAlgorithm::kZstd;
  }
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
  if (features::ParkableStringsUseSnappy()) {
    return CompressionAlgorithm::kSnappy;
  }
  return CompressionAlgorithm::kZlib;
}

ParkableStringImpl::ParkableStringImpl(scoped_refptr<StringImpl>&& impl,
                                       std::unique_ptr<SecureDigest> digest)
    : string_(std::move(impl)),
      metadata_(digest ? std::make_unique<ParkableMetadata>(string_,
                                                            std::move(digest))
                       : nullptr)
#if DCHECK_IS_ON()
      ,
      owning_thread_(CurrentThread())
#endif
{
  DCHECK(!string_.IsNull());
}

ParkableStringImpl::~ParkableStringImpl() {
  if (!may_be_parked())
    return;
  // There is nothing thread-hostile in this method, but the current design
  // should only reach this path through the main thread.
  AssertOnValidThread();
  DCHECK_EQ(0, lock_depth_for_testing());
  AsanUnpoisonString(string_);
  // Cannot destroy while parking is in progress, as the object is kept alive by
  // the background task.
  DCHECK(!metadata_->background_task_in_progress_);
  DCHECK(!has_on_disk_data());
#if DCHECK_IS_ON()
  ParkableStringManager::Instance().AssertRemoved(this);
#endif
}

void ParkableStringImpl::Lock() {
  if (!may_be_parked())
    return;

  base::AutoLock locker(metadata_->lock_);
  metadata_->lock_depth_ += 1;
  CHECK_NE(metadata_->lock_depth_, 0u);
  // Make young as this is a strong (but not certain) indication that the string
  // will be accessed soon.
  MakeYoung();
}

void ParkableStringImpl::Unlock() {
  if (!may_be_parked())
    return;

  base::AutoLock locker(metadata_->lock_);
  metadata_->lock_depth_ -= 1;
  CHECK_NE(metadata_->lock_depth_, std::numeric_limits<unsigned int>::max());

#if defined(ADDRESS_SANITIZER) && DCHECK_IS_ON()
  // There are no external references to the data, nobody should touch the data.
  //
  // Note: Only poison the memory if this is on the owning thread, as this is
  // otherwise racy. Indeed |Unlock()| may be called on any thread, and
  // the owning thread may concurrently call |ToString()|. It is then allowed
  // to use the string until the end of the current owning thread task.
  // Requires DCHECK_IS_ON() for the |owning_thread_| check.
  //
  // Checking the owning thread first as |CurrentStatus()| can only be called
  // from the owning thread.
  if (owning_thread_ == CurrentThread() &&
      CurrentStatus() == Status::kUnreferencedExternally) {
    AsanPoisonString(string_);
  }
#endif  // defined(ADDRESS_SANITIZER) && DCHECK_IS_ON()
}

const String& ParkableStringImpl::ToString() {
  if (!may_be_parked())
    return string_;

  base::AutoLock locker(metadata_->lock_);
  MakeYoung();
  AsanUnpoisonString(string_);
  Unpark();
  return string_;
}

size_t ParkableStringImpl::CharactersSizeInBytes() const {
  if (!may_be_parked())
    return string_.CharactersSizeInBytes();

  return metadata_->length_ * (is_8bit() ? sizeof(LChar) : sizeof(UChar));
}

size_t ParkableStringImpl::MemoryFootprintForDump() const {
  AssertOnValidThread();
  size_t size = sizeof(ParkableStringImpl);

  if (!may_be_parked())
    return size + string_.CharactersSizeInBytes();

  size += sizeof(ParkableMetadata);

  base::AutoLock locker(metadata_->lock_);
  if (!is_parked_no_lock()) {
    size += string_.CharactersSizeInBytes();
  }

  if (metadata_->compressed_)
    size += metadata_->compressed_->size();

  return size;
}

ParkableStringImpl::AgeOrParkResult ParkableStringImpl::MaybeAgeOrParkString() {
  base::AutoLock locker(metadata_->lock_);
  AssertOnValidThread();
  DCHECK(may_be_parked());
  DCHECK(!is_on_disk_no_lock());

  // No concurrent background tasks.
  if (metadata_->background_task_in_progress_)
    return AgeOrParkResult::kSuccessOrTransientFailure;

  // TODO(lizeb): Simplify logic below.
  if (is_parked_no_lock()) {
    if (metadata_->age_ == Age::kVeryOld) {
      bool ok = ParkInternal(ParkingMode::kToDisk);
      if (!ok)
        return AgeOrParkResult::kNonTransientFailure;
    } else {
      metadata_->age_ = MakeOlder(metadata_->age_);
    }
    return AgeOrParkResult::kSuccessOrTransientFailure;
  }

  Status status = CurrentStatus();
  Age age = metadata_->age_;
  if (age == Age::kYoung) {
    if (status == Status::kUnreferencedExternally)
      metadata_->age_ = MakeOlder(age);
  } else if (age == Age::kOld) {
    if (!CanParkNow()) {
      return AgeOrParkResult::kNonTransientFailure;
    }
    bool ok = ParkInternal(ParkingMode::kCompress);
    DCHECK(ok);
    return AgeOrParkResult::kSuccessOrTransientFailure;
  }

  // External references to a string can be long-lived, cannot provide a
  // progress guarantee for this string.
  return status == Status::kTooManyReferences
             ? AgeOrParkResult::kNonTransientFailure
             : AgeOrParkResult::kSuccessOrTransientFailure;
}

bool ParkableStringImpl::Park(ParkingMode mode) {
  base::AutoLock locker(metadata_->lock_);
  AssertOnValidThread();
  DCHECK(may_be_parked());

  if (metadata_->state_ == State::kParked)
    return true;

  // Making the string old to cancel parking if it is accessed/locked before
  // parking is complete.
  metadata_->age_ = Age::kOld;
  if (!CanParkNow())
    return false;

  ParkInternal(mode);
  return true;
}

// Returns false if parking fails and will fail in the future (non-transient
// failure).
bool ParkableStringImpl::ParkInternal(ParkingMode mode) {
  DCHECK(metadata_->state_ == State::kUnparked ||
         metadata_->state_ == State::kParked);
  DCHECK(metadata_->age_ != Age::kYoung);
  DCHECK(CanParkNow());

  // No concurrent background tasks.
  if (metadata_->background_task_in_progress_)
    return true;

  switch (mode) {
    case ParkingMode::kSynchronousOnly:
      if (has_compressed_data())
        DiscardUncompressedData();
      break;
    case ParkingMode::kCompress:
      if (has_compressed_data())
        DiscardUncompressedData();
      else
        PostBackgroundCompressionTask();
      break;
    case ParkingMode::kToDisk:
      auto& manager = ParkableStringManager::Instance();
      if (has_on_disk_data()) {
        DiscardCompressedData();
      } else {
        // If the disk allocator doesn't accept writes, then the failure is not
        // transient, notify the caller. This is important so that
        // ParkableStringManager doesn't endlessly schedule aging tasks when
        // writing to disk is not possible.
        if (!manager.data_allocator().may_write())
          return false;

        auto reserved_chunk = manager.data_allocator().TryReserveChunk(
            metadata_->compressed_->size());
        if (!reserved_chunk) {
          return false;
        }
        PostBackgroundWritingTask(std::move(reserved_chunk));
      }
      break;
  }
  return true;
}

void ParkableStringImpl::DiscardUncompressedData() {
  // Must unpoison the memory before releasing it.
  AsanUnpoisonString(string_);
  string_ = String();

  metadata_->state_ = State::kParked;
  ParkableStringManager::Instance().OnParked(this);
}

void ParkableStringImpl::DiscardCompressedData() {
  metadata_->compressed_ = nullptr;
  metadata_->state_ = State::kOnDisk;
  metadata_->last_disk_parking_time_ = base::TimeTicks::Now();
  ParkableStringManager::Instance().OnWrittenToDisk(this);
}

bool ParkableStringImpl::is_parked_no_lock() const {
  return metadata_->state_ == State::kParked;
}

bool ParkableStringImpl::is_on_disk_no_lock() const {
  return metadata_->state_ == State::kOnDisk;
}

bool ParkableStringImpl::is_compression_failed_no_lock() const {
  return metadata_->compression_failed_;
}

bool ParkableStringImpl::is_parked() const {
  base::AutoLock locker(metadata_->lock_);
  return is_parked_no_lock();
}

bool ParkableStringImpl::is_on_disk() const {
  base::AutoLock locker(metadata_->lock_);
  return is_on_disk_no_lock();
}

ParkableStringImpl::Status ParkableStringImpl::CurrentStatus() const {
  AssertOnValidThread();
  DCHECK(may_be_parked());
  // Can park iff:
  // - |this| is not locked.
  // - There are no external reference to |string_|. Since |this| holds a
  //   reference to |string_|, it must the only one.
  if (metadata_->lock_depth_ != 0)
    return Status::kLocked;
  // Can be null if it is compressed or on disk.
  if (string_.IsNull())
    return Status::kUnreferencedExternally;

  if (!string_.Impl()->HasOneRef())
    return Status::kTooManyReferences;

  return Status::kUnreferencedExternally;
}

bool ParkableStringImpl::CanParkNow() const {
  return CurrentStatus() == Status::kUnreferencedExternally &&
         metadata_->age_ != Age::kYoung && !is_compression_failed_no_lock();
}

void ParkableStringImpl::Unpark() {
  DCHECK(may_be_parked());

  if (metadata_->state_ == State::kUnparked)
    return;

  TRACE_EVENT(
      "blink", "ParkableStringImpl::Unpark", [&](perfetto::EventContext ctx) {
        auto* event = ctx.event<perfetto::protos::pbzero::ChromeTrackEvent>();
        auto* data = event->set_parkable_string_unpark();
        data->set_size_bytes(
            base::saturated_cast<int32_t>(CharactersSizeInBytes()));
        int32_t write_time = base::saturated_cast<int32_t>(
            metadata_->last_disk_parking_time_.is_null()
                ? -1
                : (base::TimeTicks::Now() - metadata_->last_disk_parking_time_)
                      .InSeconds());
        data->set_time_since_last_disk_write_sec(write_time);
      });

  DCHECK(metadata_->compressed_ || metadata_->on_disk_metadata_);
  string_ = UnparkInternal();
  if (metadata_->last_disk_parking_time_ != base::TimeTicks()) {
    // Can be quite short, can be multiple hours, hence long times, and 100
    // buckets.
    metadata_->last_disk_parking_time_ = base::TimeTicks();
  }
}

String ParkableStringImpl::UnparkInternal() {
  DCHECK(is_parked_no_lock() || is_on_disk_no_lock());

  base::ElapsedTimer timer;
  auto& manager = ParkableStringManager::Instance();

  base::TimeDelta disk_elapsed = base::TimeDelta::Min();
  if (is_on_disk_no_lock()) {
    TRACE_EVENT("blink", "ParkableStringImpl::ReadFromDisk");
    base::ElapsedTimer disk_read_timer;
    DCHECK(has_on_disk_data());
    metadata_->compressed_ = std::make_unique<Vector<uint8_t>>();
    metadata_->compressed_->Grow(
        base::checked_cast<wtf_size_t>(metadata_->on_disk_metadata_->size()));
    manager.data_allocator().Read(*metadata_->on_disk_metadata_,
                                  *metadata_->compressed_);
    disk_elapsed = disk_read_timer.Elapsed();
    RecordStatistics(metadata_->on_disk_metadata_->size(), disk_elapsed,
                     ParkingAction::kRead);
  }

  TRACE_EVENT("blink", "ParkableStringImpl::Decompress");
  std::string_view compressed_string_piece(
      reinterpret_cast<const char*>(metadata_->compressed_->data()),
      metadata_->compressed_->size() * sizeof(uint8_t));
  String uncompressed;
  base::span<char> chars;
  if (is_8bit()) {
    base::span<LChar> data;
    uncompressed = String::CreateUninitialized(length(), data);
    chars = base::as_writable_chars(data);
  } else {
    base::span<UChar> data;
    uncompressed = String::CreateUninitialized(length(), data);
    chars = base::as_writable_chars(data);
  }

  switch (GetCompressionAlgorithm()) {
    case CompressionAlgorithm::kZlib: {
      const auto uncompressed_string_piece = base::as_string_view(chars);
      // If the buffer size is incorrect, then we have a corrupted data issue,
      // and in such case there is nothing else to do than crash.
      CHECK_EQ(compression::GetUncompressedSize(compressed_string_piece),
               uncompressed_string_piece.size());
      // If decompression fails, this is either because:
      // 1. Compressed data is corrupted
      // 2. Cannot allocate memory in zlib
      //
      // (1) is data corruption, and (2) is OOM. In all cases, we cannot
      // recover the string we need, nothing else to do than to abort.
      if (!compression::GzipUncompress(compressed_string_piece,
                                       uncompressed_string_piece)) {
        // Since this is almost always OOM, report it as such. We don't have
        // certainty, but memory corruption should be much rarer, and could make
        // us crash anywhere else.
        OOM_CRASH(uncompressed_string_piece.size());
      }
      break;
    }
    case CompressionAlgorithm::kSnappy: {
      size_t uncompressed_size;

      // As above, if size is incorrect, or if data is corrupted, prefer
      // crashing.
      CHECK(snappy::GetUncompressedLength(compressed_string_piece.data(),
                                          compressed_string_piece.size(),
                                          &uncompressed_size));
      CHECK_EQ(uncompressed_size, chars.size());
      CHECK(snappy::RawUncompress(compressed_string_piece.data(),
                                  compressed_string_piece.size(), chars.data()))
          << "Decompression failed, corrupted data?";
      break;
    }
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
    case CompressionAlgorithm::kZstd: {
      uint64_t content_size = ZSTD_getFrameContentSize(
          compressed_string_piece.data(), compressed_string_piece.size());
      // The CHECK()s below indicate memory corruption, terminate.
      CHECK_NE(content_size, ZSTD_CONTENTSIZE_UNKNOWN);
      CHECK_NE(content_size, ZSTD_CONTENTSIZE_ERROR);
      CHECK_EQ(content_size, static_cast<uint64_t>(chars.size()));

      size_t uncompressed_size = ZSTD_decompress(
          chars.data(), chars.size(), compressed_string_piece.data(),
          compressed_string_piece.size());
      CHECK(!ZSTD_isError(uncompressed_size));
      CHECK_EQ(uncompressed_size, chars.size());
      break;
    }
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
  }

  base::TimeDelta elapsed = timer.Elapsed();
  RecordStatistics(CharactersSizeInBytes(), elapsed, ParkingAction::kUnparked);
  metadata_->state_ = State::kUnparked;
  manager.CompleteUnpark(this, elapsed, disk_elapsed);
  return uncompressed;
}

void ParkableStringImpl::ReleaseAndRemoveIfNeeded() const {
  ParkableStringManager::Instance().Remove(
      const_cast<ParkableStringImpl*>(this));
}

void ParkableStringImpl::PostBackgroundCompressionTask() {
  DCHECK(!metadata_->background_task_in_progress_);
  // |string_|'s data should not be touched except in the compression task.
  AsanPoisonString(string_);
  metadata_->background_task_in_progress_ = true;
  auto& manager = ParkableStringManager::Instance();
  DCHECK(manager.task_runner()->BelongsToCurrentThread());
  // |params| keeps |this| alive until |OnParkingCompleteOnMainThread()|.
  auto params = std::make_unique<BackgroundTaskParams>(
      this, string_.RawByteSpan(), /* reserved_chunk */ nullptr,
      manager.task_runner());
  worker_pool::PostTask(
      FROM_HERE, {base::TaskPriority::BEST_EFFORT},
      CrossThreadBindOnce(&ParkableStringImpl::CompressInBackground,
                          std::move(params)));
}

// static
void ParkableStringImpl::CompressInBackground(
    std::unique_ptr<BackgroundTaskParams> params) {
  TRACE_EVENT(
      "blink", "ParkableStringImpl::CompressInBackground",
      [&](perfetto::EventContext ctx) {
        auto* event = ctx.event<perfetto::protos::pbzero::ChromeTrackEvent>();
        auto* data = event->set_parkable_string_compress_in_background();
        data->set_size_bytes(
            base::saturated_cast<int32_t>(params->data.size()));
      });

  base::ElapsedTimer timer;
#if defined(ADDRESS_SANITIZER)
  // Lock the string to prevent a concurrent |Unlock()| on the main thread from
  // poisoning the string in the meantime.
  //
  // Don't make the string young at the same time, otherwise parking would
  // always be cancelled on the main thread with address sanitizer, since the
  // |OnParkingCompleteOnMainThread()| callback would be executed on a young
  // string.
  params->string->LockWithoutMakingYoung();
#endif  // defined(ADDRESS_SANITIZER)
  // Compression touches the string.
  AsanUnpoisonString(params->string->string_);
  bool ok;
  std::string_view data = base::as_string_view(params->data);
  std::unique_ptr<Vector<uint8_t>> compressed;

  // This runs in background, making CPU starvation likely, and not an issue.
  // Hence, report thread time instead of wall clock time.
  base::ElapsedThreadTimer thread_timer;
  {
    // Create a temporary buffer for compressed data. After compression the
    // output bytes are _copied_ to a new vector sized according to the newly
    // discovered compressed size. This is done as a memory saving measure
    // because Vector::Shrink() does not resize the memory allocation.
    //
    // For zlib: the temporary buffer has the same size as the initial data.
    // Compression will fail if this is not large enough.
    // For snappy: the temporary buffer has size
    // GetMaxCompressedLength(inital_data_size). If the compression does not
    // compress, the result is discarded.
    //
    // This is not using:
    // - malloc() or any STL container: this is discouraged in blink, and there
    //   is a suspected memory regression caused by using it (crbug.com/920194).
    // - WTF::Vector<> as allocation failures result in an OOM crash, whereas
    //   we can fail gracefully. See crbug.com/905777 for an example of OOM
    //   triggered from there.

    size_t buffer_size;
    switch (GetCompressionAlgorithm()) {
      case CompressionAlgorithm::kZlib:
        buffer_size = data.size();
        break;
      case CompressionAlgorithm::kSnappy:
        // Contrary to other compression algorithms, snappy requires the buffer
        // to be at least this size, rather than aborting if the provided buffer
        // is too small.
        buffer_size = snappy::MaxCompressedLength(data.size());
        break;
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
      case CompressionAlgorithm::kZstd:
        buffer_size = ZSTD_compressBound(data.size());
        break;
#endif
    }

    NullableCharBuffer buffer(buffer_size);
    ok = buffer.data();
    size_t compressed_size;
    if (ok) {
      switch (GetCompressionAlgorithm()) {
        case CompressionAlgorithm::kZlib:
          ok = compression::GzipCompress(data, buffer.data(), buffer.size(),
                                         &compressed_size, nullptr, nullptr);
          break;
        case CompressionAlgorithm::kSnappy:
          snappy::RawCompress(data.data(), data.size(), buffer.data(),
                              &compressed_size);
          if (compressed_size > data.size()) {
            ok = false;
          }
          break;
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
        case CompressionAlgorithm::kZstd:
          compressed_size =
              ZSTD_compress(buffer.data(), buffer.size(), data.data(),
                            data.size(), features::kZstdCompressionLevel.Get());
          ok =
              !ZSTD_isError(compressed_size) && (compressed_size < data.size());
          break;
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
      }
    }

#if defined(ADDRESS_SANITIZER)
    params->string->Unlock();
#endif  // defined(ADDRESS_SANITIZER)

    if (ok) {
      compressed = std::make_unique<Vector<uint8_t>>();
      // Not using realloc() as we want the compressed data to be a regular
      // WTF::Vector.
      compressed->AppendSpan(base::as_byte_span(buffer).first(compressed_size));
    }
  }
  base::TimeDelta thread_elapsed = thread_timer.Elapsed();

  auto* task_runner = params->callback_task_runner.get();
  size_t size = data.size();
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      CrossThreadBindOnce(
          [](std::unique_ptr<BackgroundTaskParams> params,
             std::unique_ptr<Vector<uint8_t>> compressed,
             base::TimeDelta parking_thread_time) {
            auto* string = params->string.get();
            string->OnParkingCompleteOnMainThread(
                std::move(params), std::move(compressed), parking_thread_time);
          },
          std::move(params), std::move(compressed), thread_elapsed));
  RecordStatistics(size, timer.Elapsed(), ParkingAction::kParked);
}

void ParkableStringImpl::OnParkingCompleteOnMainThread(
    std::unique_ptr<BackgroundTaskParams> params,
    std::unique_ptr<Vector<uint8_t>> compressed,
    base::TimeDelta parking_thread_time) {
  DCHECK(metadata_->background_task_in_progress_);
  base::AutoLock locker(metadata_->lock_);
  DCHECK_EQ(State::kUnparked, metadata_->state_);
  metadata_->background_task_in_progress_ = false;

  // Always keep the compressed data. Compression is expensive, so even if the
  // uncompressed representation cannot be discarded now, avoid compressing
  // multiple times. This will allow synchronous parking next time.
  DCHECK(!metadata_->compressed_);
  if (compressed) {
    metadata_->compressed_ = s
```