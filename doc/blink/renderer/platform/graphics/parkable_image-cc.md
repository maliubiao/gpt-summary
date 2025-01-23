Response:
Let's break down the thought process to generate the description of `parkable_image.cc`.

1. **Understand the Goal:** The request asks for the functionality of the `parkable_image.cc` file in the Chromium Blink engine, its relationship to web technologies, logical inferences with examples, and common usage errors.

2. **Identify Key Classes and Structures:**  The first step is to scan the code and identify the core components. Immediately, `ParkableImage` and `ParkableImageImpl` stand out as the central classes. The presence of `ParkableImageManager` also suggests a management role. Other important pieces include `RWBuffer`, `ROBuffer`, and `SegmentReader`.

3. **Decipher Core Functionality (What does it *do*?):**  By examining the methods of the key classes, we can deduce the primary functions:
    * **Data Storage:**  `ParkableImageImpl` holds image data using `RWBuffer`. The "parkable" aspect hints at a mechanism to move this data in and out of memory.
    * **Memory Management:** The names "park" and "unpark" strongly suggest a memory optimization strategy. The interaction with `ParkableImageManager` confirms this, likely involving disk storage.
    * **Data Access:** Methods like `Data()`, `GetROBufferSegmentReader()`, and `MakeROSnapshot()` indicate ways to access the image data. The presence of `SegmentReader` points to potentially fragmented or non-contiguous data access.
    * **Concurrency Control:** The use of `base::AutoLock lock_` in `ParkableImageImpl` signals thread safety and the need for synchronization.
    * **Disk Interaction:** Functions like `WriteToDiskInBackground()` and `ReadFromDiskIntoBuffer()` clearly show interaction with disk storage.

4. **Establish the "Parking" Mechanism:**  The core concept revolves around the "parkable" nature. Inferring from the code:
    * Images can be "parked" (moved to disk) to reduce memory usage.
    * Images can be "unparked" (loaded back into memory from disk) when needed.
    * This process is likely triggered by memory pressure or inactivity.
    * The `Freeze()` method seems to be a precursor to parking, potentially marking the image as eligible.
    * The `TransientlyUnableToPark()` method introduces a delay before parking.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how image data is used in a web browser.
    * **HTML `<img>` tag:** The most direct link. Images displayed by the `<img>` tag would be candidates for `ParkableImage`.
    * **CSS `background-image`:**  Similar to `<img>`, background images also use image data.
    * **Canvas API:** JavaScript can draw images onto a canvas. The image data for this could be managed by `ParkableImage`.
    * **Image decoding:** The inclusion of  `third_party/blink/renderer/platform/image-decoders/segment_reader.h` suggests `ParkableImage` plays a role in how images are decoded and accessed during rendering.

6. **Formulate Examples:** For each web technology connection, create a simple, concrete example demonstrating how `ParkableImage` might be involved. Focus on the "parking" and "unparking" effects if possible (although these are internal and not directly observable by web developers).

7. **Logical Inferences and Examples:** Think about the state transitions and data flow:
    * **Parking:** Input: An in-memory image. Output: The image data is on disk, and the in-memory representation is potentially discarded.
    * **Unparking:** Input: An image marked as being on disk. Output: The image data is loaded back into memory.
    * Consider edge cases or different scenarios that trigger these transitions.

8. **Identify Potential Usage Errors:** Focus on the public API of `ParkableImage`:
    * **Incorrect locking/unlocking:** Since locking is manual, misusing `LockData()` and `UnlockData()` can lead to crashes or data corruption.
    * **Accessing data after parking:**  Trying to directly access the underlying buffer after it's been parked (and potentially discarded) would be an error. The `Unpark()` mechanism is crucial.
    * **Thread safety violations:** While the class aims to be thread-safe internally, incorrect usage from different threads without proper synchronization *outside* the class could still cause issues.

9. **Structure the Answer:** Organize the information logically:
    * Start with a summary of the file's purpose.
    * Detail the core functionalities.
    * Explain the connection to web technologies with examples.
    * Provide logical inferences with input/output scenarios.
    * List common usage errors.

10. **Refine and Elaborate:** Review the generated description. Ensure clarity, accuracy, and completeness. Add details where necessary. For example, explain *why* parking is beneficial (memory saving). Clarify the role of `ParkableImageManager`.

**(Self-Correction during the process):**

* **Initial thought:** Maybe `ParkableImage` directly manages the disk I/O.
* **Correction:** The presence of `ParkableImageManager` suggests delegation of this responsibility.
* **Initial thought:** The web developer directly interacts with `ParkableImage`.
* **Correction:**  `ParkableImage` is an internal implementation detail of the rendering engine. Web developers interact with higher-level APIs (like `<img>` tags).
* **Initial thought:** Focus only on the `ParkableImage` class.
* **Correction:** Recognize the importance of `ParkableImageImpl` and `ParkableImageManager` to provide a complete picture.

By following these steps and continually refining the understanding of the code, a comprehensive and accurate description of `parkable_image.cc` can be generated.
这是 `blink/renderer/platform/graphics/parkable_image.cc` 文件的功能概述：

**核心功能：管理可“停放”的图像数据以优化内存使用**

这个文件的核心目的是实现 `ParkableImage` 类及其辅助类，用于管理图像数据在内存中的存储和访问。 其关键特性是“停放”（parking），这是一种将图像数据从内存移动到磁盘的机制，以减少内存占用，并在需要时再将其加载回内存。

**具体功能分解：**

1. **数据存储和管理：**
   - `ParkableImage` 和 `ParkableImageImpl` 类负责存储图像的原始数据。
   - 使用 `RWBuffer` (可读写缓冲区) 来存储内存中的图像数据。
   - 当图像被“停放”时，数据会被写入磁盘，并由 `ParkableImageManager` 管理。
   - 使用 `DiskDataMetadata` 结构体来记录磁盘上图像数据的位置和大小等元数据。

2. **“停放”和“取消停放”机制：**
   - **停放 (Parking):**  当系统内存压力较大或图像在一段时间内未被使用时，`ParkableImage` 可以将其数据“停放”到磁盘。
     - `Freeze()` 方法标记图像为可以被停放。
     - `MaybePark()` 方法检查图像是否满足停放条件，如果满足，则将数据异步写入磁盘。
     - 使用后台线程 (`WriteToDiskInBackground()`) 执行磁盘写入操作，避免阻塞主线程。
   - **取消停放 (Unparking):** 当需要访问图像数据时（例如，进行绘制），`ParkableImage` 会将其从磁盘加载回内存。
     - `Unpark()` 方法负责检查图像是否在磁盘上，如果是，则从磁盘读取数据到 `RWBuffer`。
     - 使用延迟初始化策略，仅在真正需要时才从磁盘读取数据。

3. **数据访问控制和线程安全：**
   - 使用 `base::Lock` (`lock_`) 来保护对内部数据结构的并发访问，确保线程安全。
   - `LockData()` 和 `UnlockData()` 方法用于显式地锁定和解锁图像数据，防止在访问期间被停放或修改。
   - `SegmentReader` 类提供了一种只读访问图像数据的方式，允许在不完全加载整个图像到内存的情况下访问部分数据。

4. **性能监控和统计：**
   - 使用 UMA (User Metrics Analysis) 宏 (`base::UmaHistogram...`) 来记录停放和取消停放操作的延迟、吞吐量等性能指标，用于分析和优化性能。

5. **与其他模块的交互：**
   - 与 `ParkableImageManager` 交互，后者负责管理所有的 `ParkableImage` 实例，并处理磁盘空间的分配和回收。
   - 与 `SharedBuffer` 交互，`SharedBuffer` 是 Blink 中用于表示共享内存缓冲区的类。
   - 与 Skia 图形库 (`SkData`) 交互，可以将 `ParkableImage` 中的数据转换为 Skia 可以使用的格式。

**与 JavaScript, HTML, CSS 的关系：**

`ParkableImage` 位于 Blink 渲染引擎的底层，并不直接暴露给 JavaScript, HTML 或 CSS。然而，它对这些技术的功能实现至关重要，因为它负责管理浏览器中图像的内存使用，从而影响页面的加载速度和整体性能。

**举例说明：**

* **HTML `<img>` 标签：** 当浏览器解析 HTML 遇到 `<img>` 标签时，会下载图像数据。`ParkableImage` 可以用于管理这个图像的数据。当图像首次被渲染到屏幕上时，数据可能在内存中。如果该图像在一段时间内未在屏幕上显示，`ParkableImage` 可能会将其数据停放到磁盘以释放内存，供其他资源使用。当用户滚动页面或重新显示该图像时，`ParkableImage` 会将其从磁盘加载回内存。

* **CSS `background-image` 属性：** 类似于 `<img>` 标签，通过 CSS 设置的背景图像也会使用 `ParkableImage` 进行内存管理。例如，一个大型网站的首页可能有很多背景图片，`ParkableImage` 可以帮助浏览器在用户不查看某些部分时，将这些背景图片的数据移出内存。

* **JavaScript Canvas API：**  当 JavaScript 使用 Canvas API 绘制图像时，`ParkableImage` 同样可以参与管理这些图像的内存。例如，一个使用 Canvas 实现的游戏可能加载了大量的纹理图片，`ParkableImage` 可以帮助优化这些纹理的内存占用。

**逻辑推理与假设输入输出：**

**假设输入：** 一个 `ParkableImage` 实例，包含一个 1MB 的图像数据，并且在内存中。系统内存压力增大。

**逻辑推理：**
1. `ParkableImageManager` 或系统其他模块检测到内存压力增大。
2. 检查该 `ParkableImage` 实例是否满足停放条件（例如，一段时间内未被使用，未被锁定）。
3. 调用该 `ParkableImage` 实例的 `MaybePark()` 方法。
4. `MaybePark()` 方法尝试在磁盘上预留 1MB 的空间。
5. 如果预留成功，则启动后台任务 `WriteToDiskInBackground()`。
6. `WriteToDiskInBackground()` 将内存中的 1MB 图像数据写入磁盘。
7. 完成磁盘写入后，更新 `ParkableImage` 的状态，标记为已停放，并可能释放内存中的数据。

**假设输出：** 该 `ParkableImage` 实例的状态变为“已停放”，内存中可能不再持有完整的图像数据，而是持有指向磁盘位置的元数据。

**用户或编程常见的使用错误：**

1. **在数据被停放后尝试直接访问内存中的数据：**
   - **错误示例：**  在调用 `Freeze()` 后，但在下一次渲染前，假设图像已被停放，此时如果直接尝试访问 `ParkableImage` 内部的 `RWBuffer`，可能会导致访问已释放的内存。
   - **正确做法：**  应该通过 `Unpark()` 方法来确保数据在内存中后再进行访问。通常，渲染引擎会自动处理这个过程。

2. **在未解锁数据的情况下尝试停放：**
   - **错误示例：**  如果开发者通过 `LockData()` 显式锁定了 `ParkableImage` 的数据，此时尝试调用 `MaybePark()` 将会失败，因为停放的条件之一是数据未被锁定。
   - **正确做法：**  确保在尝试停放之前调用 `UnlockData()`。

3. **长时间持有 `SegmentReader` 对象：**
   - **错误示例：**  创建一个 `SegmentReader` 用于读取部分图像数据，但是长时间持有该对象而不释放，可能会阻止 `ParkableImage` 被成功停放，因为它会持有对内部缓冲区的引用。
   - **正确做法：**  在完成数据读取后，及时释放 `SegmentReader` 对象。

4. **在错误的时间调用 `Freeze()`：**
   - **错误示例：**  在图像数据尚未完全加载或处理完成时就调用 `Freeze()`，可能会导致数据不完整地被停放。
   - **正确做法：**  通常，`Freeze()` 由渲染引擎在合适的时机调用，开发者一般不需要手动调用。

总而言之，`parkable_image.cc` 文件定义了 Blink 渲染引擎中用于高效管理图像内存的关键机制，通过将不常用的图像数据移至磁盘，从而降低内存占用，提高浏览器性能。虽然开发者不直接操作这个类，但其背后的逻辑直接影响着网页的加载和渲染效率。

### 提示词
```
这是目录为blink/renderer/platform/graphics/parkable_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/parkable_image.h"

#include "base/debug/stack_trace.h"
#include "base/feature_list.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/synchronization/lock.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/platform/graphics/parkable_image_manager.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/sanitizers.h"
#include "third_party/skia/include/core/SkData.h"
#include "third_party/skia/include/core/SkRefCnt.h"

namespace blink {

BASE_FEATURE(kDelayParkingImages,
             "DelayParkingImages",
             base::FEATURE_ENABLED_BY_DEFAULT);

namespace {

void RecordReadStatistics(size_t size,
                          base::TimeDelta duration,
                          base::TimeDelta time_since_freeze) {
  int throughput_mb_s = duration.is_zero()
                            ? INT_MAX
                            : base::saturated_cast<int>(
                                  size / duration.InSecondsF() / (1024 * 1024));

  // Size is usually >1KiB, and at most ~10MiB, and throughput ranges from
  // single-digit MB/s to ~1000MiB/s depending on the CPU/disk, hence the
  // ranges.
  base::UmaHistogramCustomMicrosecondsTimes("Memory.ParkableImage.Read.Latency",
                                            duration, base::Microseconds(500),
                                            base::Seconds(1), 100);
  base::UmaHistogramCounts1000("Memory.ParkableImage.Read.Throughput",
                               throughput_mb_s);
}

void RecordWriteStatistics(size_t size, base::TimeDelta duration) {
  int size_kb = static_cast<int>(size / 1024);  // in KiB

  // Size should be <1MiB in most cases.
  base::UmaHistogramCounts10000("Memory.ParkableImage.Write.Size", size_kb);
  // Size is usually >1KiB, and at most ~10MiB, and throughput ranges from
  // single-digit MB/s to ~1000MiB/s depending on the CPU/disk, hence the
  // ranges.
  base::UmaHistogramCustomMicrosecondsTimes(
      "Memory.ParkableImage.Write.Latency", duration, base::Microseconds(500),
      base::Seconds(1), 100);
}

void AsanPoisonBuffer(RWBuffer* rw_buffer) {
#if defined(ADDRESS_SANITIZER)
  if (!rw_buffer || !rw_buffer->size())
    return;

  auto ro_buffer = rw_buffer->MakeROBufferSnapshot();
  ROBuffer::Iter iter(ro_buffer);
  do {
    ASAN_POISON_MEMORY_REGION(iter.data(), iter.size());
  } while (iter.Next());
#endif
}

void AsanUnpoisonBuffer(RWBuffer* rw_buffer) {
#if defined(ADDRESS_SANITIZER)
  if (!rw_buffer || !rw_buffer->size())
    return;

  auto ro_buffer = rw_buffer->MakeROBufferSnapshot();
  ROBuffer::Iter iter(ro_buffer);
  do {
    ASAN_UNPOISON_MEMORY_REGION(iter.data(), iter.size());
  } while (iter.Next());
#endif
}

// This should be used to make sure that the last reference to the |this| is
// decremented on the main thread (since that's where the destructor must
// run), for example by posting a task with this to the main thread.
void NotifyWriteToDiskFinished(scoped_refptr<ParkableImageImpl>) {
  DCHECK(IsMainThread());
}

}  // namespace

// ParkableImageSegmentReader

class ParkableImageSegmentReader : public SegmentReader {
 public:
  explicit ParkableImageSegmentReader(scoped_refptr<ParkableImage> image);
  size_t size() const override;
  base::span<const uint8_t> GetSomeData(size_t position) const override;
  sk_sp<SkData> GetAsSkData() const override;
  void LockData() override;
  void UnlockData() override;

 private:
  ~ParkableImageSegmentReader() override = default;
  scoped_refptr<ParkableImage> parkable_image_;
  size_t available_;
};

ParkableImageSegmentReader::ParkableImageSegmentReader(
    scoped_refptr<ParkableImage> image)
    : parkable_image_(std::move(image)), available_(parkable_image_->size()) {}

size_t ParkableImageSegmentReader::size() const {
  return available_;
}

base::span<const uint8_t> ParkableImageSegmentReader::GetSomeData(
    size_t position) const {
  if (!parkable_image_) {
    return {};
  }

  base::AutoLock lock(parkable_image_->impl_->lock_);
  DCHECK(parkable_image_->impl_->is_locked());

  RWBuffer::ROIter iter(parkable_image_->impl_->rw_buffer_.get(), available_);
  size_t position_of_block = 0;
  return RWBufferGetSomeData(iter, position_of_block, position);
}

sk_sp<SkData> ParkableImageSegmentReader::GetAsSkData() const {
  if (!parkable_image_) {
    return nullptr;
  }

  base::AutoLock lock(parkable_image_->impl_->lock_);
  parkable_image_->impl_->Unpark();

  RWBuffer::ROIter iter(parkable_image_->impl_->rw_buffer_.get(), available_);

  if (!iter.HasNext()) {  // No need to copy because the data is contiguous.
    // We lock here so that we don't get a use-after-free. ParkableImage can
    // not be parked while it is locked, so the buffer is valid for the whole
    // lifetime of the SkData. We add the ref so that the ParkableImage has a
    // longer limetime than the SkData.
    parkable_image_->AddRef();
    parkable_image_->LockData();
    return SkData::MakeWithProc(
        iter.data(), available_,
        [](const void* ptr, void* context) -> void {
          auto* parkable_image = static_cast<ParkableImage*>(context);
          {
            base::AutoLock lock(parkable_image->impl_->lock_);
            parkable_image->UnlockData();
          }
          // Don't hold the mutex while we call |Release|, since |Release| can
          // free the ParkableImage, if this is the last reference to it;
          // Freeing the ParkableImage while the mutex is held causes a UAF when
          // the dtor for base::AutoLock is called.
          parkable_image->Release();
        },
        parkable_image_.get());
  }

  // Data is not contiguous so we need to copy.
  return RWBufferCopyAsSkData(iter, available_);
}

void ParkableImageSegmentReader::LockData() {
  base::AutoLock lock(parkable_image_->impl_->lock_);
  parkable_image_->impl_->Unpark();

  parkable_image_->LockData();
}

void ParkableImageSegmentReader::UnlockData() {
  base::AutoLock lock(parkable_image_->impl_->lock_);

  parkable_image_->UnlockData();
}

BASE_FEATURE(kUseParkableImageSegmentReader,
             "UseParkableImageSegmentReader",
             base::FEATURE_ENABLED_BY_DEFAULT);

constexpr base::TimeDelta ParkableImageImpl::kParkingDelay;

void ParkableImageImpl::Append(WTF::SharedBuffer* buffer, size_t offset) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  base::AutoLock lock(lock_);
  DCHECK(!is_frozen());
  DCHECK(!is_on_disk());
  DCHECK(rw_buffer_);

  for (auto it = buffer->GetIteratorAt(offset); it != buffer->cend(); ++it) {
    DCHECK_GE(buffer->size(), rw_buffer_->size() + it->size());
    const size_t remaining = buffer->size() - rw_buffer_->size() - it->size();
    rw_buffer_->Append(it->data(), it->size(), remaining);
  }
  size_ = rw_buffer_->size();
}

scoped_refptr<SharedBuffer> ParkableImageImpl::Data() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  base::AutoLock lock(lock_);
  Unpark();
  DCHECK(rw_buffer_);
  scoped_refptr<ROBuffer> ro_buffer(rw_buffer_->MakeROBufferSnapshot());
  scoped_refptr<SharedBuffer> shared_buffer = SharedBuffer::Create();
  ROBuffer::Iter it(ro_buffer.get());
  do {
    shared_buffer->Append(it.data(), it.size());
  } while (it.Next());

  return shared_buffer;
}

scoped_refptr<SegmentReader> ParkableImageImpl::GetROBufferSegmentReader() {
  base::AutoLock lock(lock_);
  Unpark();
  DCHECK(rw_buffer_);
  // The locking and unlocking here is only needed to make sure ASAN unpoisons
  // things correctly here.
  LockData();
  scoped_refptr<ROBuffer> ro_buffer(rw_buffer_->MakeROBufferSnapshot());
  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromROBuffer(std::move(ro_buffer));
  UnlockData();
  return segment_reader;
}

bool ParkableImageImpl::CanParkNow() const {
  DCHECK(!is_on_disk());
  return !TransientlyUnableToPark() && !is_locked() &&
         rw_buffer_->HasNoSnapshots();
}

ParkableImageImpl::ParkableImageImpl(size_t initial_capacity)
    : rw_buffer_(std::make_unique<RWBuffer>(initial_capacity)) {}

ParkableImageImpl::~ParkableImageImpl() {
  DCHECK(IsMainThread());
  DCHECK(!is_locked());
  auto& manager = ParkableImageManager::Instance();
  if (!is_below_min_parking_size() || !is_frozen())
    manager.Remove(this);
  DCHECK(!manager.IsRegistered(this));
  if (on_disk_metadata_)
    manager.data_allocator().Discard(std::move(on_disk_metadata_));
  AsanUnpoisonBuffer(rw_buffer_.get());
}

// static
scoped_refptr<ParkableImageImpl> ParkableImageImpl::Create(
    size_t initial_capacity) {
  return base::MakeRefCounted<ParkableImageImpl>(initial_capacity);
}

void ParkableImageImpl::Freeze() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  base::AutoLock lock(lock_);
  DCHECK(!is_frozen());
  frozen_time_ = base::TimeTicks::Now();

  if (is_below_min_parking_size()) {
    ParkableImageManager::Instance().Remove(this);
    return;
  }

  // If we don't have any snapshots of the current data, that means it could be
  // parked at any time.
  //
  // If we have snapshots, we don't want to poison the buffer, because the
  // snapshot is allowed to access the buffer's data freely.
  if (CanParkNow())
    AsanPoisonBuffer(rw_buffer_.get());
}

void ParkableImageImpl::LockData() {
  // Calling |Lock| only makes sense if the data is available.
  DCHECK(rw_buffer_);

  lock_depth_++;

  AsanUnpoisonBuffer(rw_buffer_.get());
}

void ParkableImageImpl::UnlockData() {
  // Check that we've locked it already.
  DCHECK_GT(lock_depth_, 0u);
  // While locked, we can never write the data to disk.
  DCHECK(!is_on_disk());

  lock_depth_--;

  // We only poison the buffer if we're able to park after unlocking.
  // This is to avoid issues when creating a ROBufferSegmentReader from the
  // ParkableImageImpl.
  if (CanParkNow())
    AsanPoisonBuffer(rw_buffer_.get());
}

// static
void ParkableImageImpl::WriteToDiskInBackground(
    scoped_refptr<ParkableImageImpl> parkable_image,
    scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner) {
  DCHECK(!IsMainThread());
  base::AutoLock lock(parkable_image->lock_);

  DCHECK(ParkableImageManager::IsParkableImagesToDiskEnabled());
  DCHECK(parkable_image);
  DCHECK(parkable_image->reserved_chunk_);
  DCHECK(!parkable_image->on_disk_metadata_);

  AsanUnpoisonBuffer(parkable_image->rw_buffer_.get());

  scoped_refptr<ROBuffer> ro_buffer =
      parkable_image->rw_buffer_->MakeROBufferSnapshot();
  ROBuffer::Iter it(ro_buffer.get());

  Vector<char> vector;
  vector.ReserveInitialCapacity(
      base::checked_cast<wtf_size_t>(parkable_image->size()));

  do {
    vector.Append(reinterpret_cast<const char*>(it.data()),
                  base::checked_cast<wtf_size_t>(it.size()));
  } while (it.Next());

  auto reserved_chunk = std::move(parkable_image->reserved_chunk_);

  // Release the lock while writing, so we don't block for too long.
  parkable_image->lock_.Release();

  base::ElapsedTimer timer;
  auto metadata = ParkableImageManager::Instance().data_allocator().Write(
      std::move(reserved_chunk), base::as_byte_span(vector));
  base::TimeDelta elapsed = timer.Elapsed();

  // Acquire the lock again after writing.
  parkable_image->lock_.Acquire();

  parkable_image->on_disk_metadata_ = std::move(metadata);

  // Nothing to do if the write failed except return. Notably, we need to
  // keep around the data for the ParkableImageImpl in this case.
  if (!parkable_image->on_disk_metadata_) {
    parkable_image->background_task_in_progress_ = false;
    // This ensures that we don't destroy |this| on the background thread at
    // the end of this function, if we happen to have the last reference to
    // |this|.
    //
    // We cannot simply check the reference count here, since it may be
    // changed racily on another thread, so posting a task is the only safe
    // way to proceed.
    PostCrossThreadTask(*callback_task_runner, FROM_HERE,
                        CrossThreadBindOnce(&NotifyWriteToDiskFinished,
                                            std::move(parkable_image)));
  } else {
    RecordWriteStatistics(parkable_image->on_disk_metadata_->size(), elapsed);
    ParkableImageManager::Instance().RecordDiskWriteTime(elapsed);
    PostCrossThreadTask(
        *callback_task_runner, FROM_HERE,
        CrossThreadBindOnce(&ParkableImageImpl::MaybeDiscardData,
                            std::move(parkable_image)));
  }
}

void ParkableImageImpl::MaybeDiscardData() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!is_below_min_parking_size());

  base::AutoLock lock(lock_);
  DCHECK(on_disk_metadata_);

  background_task_in_progress_ = false;

  // If the image is now unparkable, we need to keep the data around.
  // This can happen if, for example, in between the time we posted the task to
  // discard the data and the time MaybeDiscardData is called, we've created a
  // SegmentReader from |rw_buffer_|, since discarding the data would leave us
  // with a dangling pointer in the SegmentReader.
  if (CanParkNow())
    DiscardData();
}

void ParkableImageImpl::DiscardData() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!is_locked());
  AsanUnpoisonBuffer(rw_buffer_.get());

  rw_buffer_ = nullptr;
  ParkableImageManager::Instance().OnWrittenToDisk(this);
}

bool ParkableImageImpl::TransientlyUnableToPark() const {
  if (base::FeatureList::IsEnabled(kDelayParkingImages)) {
    // Most images are used only once, for the initial decode at render time.
    // Since rendering can happen multiple seconds after the image load (e.g.
    // if paint by a synchronous <script> earlier in the document), we instead
    // wait up to kParkingDelay before parking an unused image.
    return !is_frozen() ||
           (base::TimeTicks::Now() - frozen_time_ <= kParkingDelay && !used_);
  } else {
    return !is_frozen();
  }
}

bool ParkableImageImpl::MaybePark(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK(ParkableImageManager::IsParkableImagesToDiskEnabled());
  DCHECK(IsMainThread());

  base::AutoLock lock(lock_);

  if (background_task_in_progress_)
    return true;

  if (!CanParkNow())
    return false;

  if (on_disk_metadata_) {
    DiscardData();
    return true;
  }

  auto reserved_chunk =
      ParkableImageManager::Instance().data_allocator().TryReserveChunk(size());
  if (!reserved_chunk) {
    return false;
  }
  reserved_chunk_ = std::move(reserved_chunk);

  background_task_in_progress_ = true;

  // The writing is done on a background thread. We pass a TaskRunner from the
  // current thread for when we have finished writing.
  worker_pool::PostTask(
      FROM_HERE, {base::MayBlock()},
      CrossThreadBindOnce(&ParkableImageImpl::WriteToDiskInBackground,
                          scoped_refptr<ParkableImageImpl>(this),
                          std::move(task_runner)));
  return true;
}

// static
size_t ParkableImageImpl::ReadFromDiskIntoBuffer(
    DiskDataMetadata* on_disk_metadata,
    base::span<uint8_t> buffer) {
  size_t size = on_disk_metadata->size();
  DCHECK_LE(size, buffer.size());
  ParkableImageManager::Instance().data_allocator().Read(*on_disk_metadata,
                                                         buffer);
  return size;
}

void ParkableImageImpl::Unpark() {
  // We mark the ParkableImage as having been read here, since any access to
  // its data must first make sure it's not on disk.
  used_ = true;

  if (!is_on_disk()) {
    AsanUnpoisonBuffer(rw_buffer_.get());
    return;
  }

  DCHECK(ParkableImageManager::IsParkableImagesToDiskEnabled());

  TRACE_EVENT1("blink", "ParkableImageImpl::Unpark", "size", size());

  DCHECK(on_disk_metadata_);

  base::ElapsedTimer timer;

  DCHECK(!rw_buffer_);
  rw_buffer_ = std::make_unique<RWBuffer>(
      base::BindOnce(&ParkableImageImpl::ReadFromDiskIntoBuffer,
                     base::Unretained(on_disk_metadata_.get())),
      size());

  base::TimeDelta elapsed = timer.Elapsed();
  base::TimeDelta time_since_freeze = base::TimeTicks::Now() - frozen_time_;

  RecordReadStatistics(on_disk_metadata_->size(), elapsed, time_since_freeze);

  ParkableImageManager::Instance().RecordDiskReadTime(elapsed);
  ParkableImageManager::Instance().OnReadFromDisk(this);

  DCHECK(rw_buffer_);
}

size_t ParkableImageImpl::size() const {
  return size_;
}

bool ParkableImageImpl::is_below_min_parking_size() const {
  return size() < ParkableImageImpl::kMinSizeToPark;
}

bool ParkableImageImpl::is_locked() const {
  return lock_depth_ != 0;
}

ParkableImage::ParkableImage(size_t offset)
    : impl_(ParkableImageManager::Instance().CreateParkableImage(offset)) {
  ParkableImageManager::Instance().Add(impl_.get());
}

ParkableImage::~ParkableImage() {
  ParkableImageManager::Instance().DestroyParkableImage(std::move(impl_));
}

// static
scoped_refptr<ParkableImage> ParkableImage::Create(size_t initial_capacity) {
  return base::MakeRefCounted<ParkableImage>(initial_capacity);
}

size_t ParkableImage::size() const {
  DCHECK(impl_);
  return impl_->size();
}

bool ParkableImage::is_on_disk() const {
  DCHECK(impl_);
  return impl_->is_on_disk();
}

scoped_refptr<SegmentReader> ParkableImage::MakeROSnapshot() {
  DCHECK(impl_);
  DCHECK_CALLED_ON_VALID_THREAD(impl_->thread_checker_);

  if (base::FeatureList::IsEnabled(kUseParkableImageSegmentReader)) {
    return CreateSegmentReader();
  } else {
    return impl_->GetROBufferSegmentReader();
  }
}

void ParkableImage::Freeze() {
  DCHECK(impl_);
  impl_->Freeze();
}

scoped_refptr<SharedBuffer> ParkableImage::Data() {
  DCHECK(impl_);
  return impl_->Data();
}

void ParkableImage::Append(WTF::SharedBuffer* buffer, size_t offset) {
  DCHECK(impl_);
  impl_->Append(buffer, offset);
}

void ParkableImage::LockData() {
  DCHECK(impl_);
  impl_->LockData();
}

void ParkableImage::UnlockData() {
  DCHECK(impl_);
  impl_->UnlockData();
}

scoped_refptr<SegmentReader> ParkableImage::CreateSegmentReader() {
  return base::MakeRefCounted<ParkableImageSegmentReader>(this);
}

}  // namespace blink
```