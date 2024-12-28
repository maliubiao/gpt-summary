Response:
Let's break down the thought process to analyze the C++ test file `parkable_image_test.cc`.

1. **Understand the Goal:** The primary goal is to understand the functionality of this *test* file. Test files in software development exist to verify the behavior of specific units of code. Therefore, this file tests the functionality of `ParkableImage`.

2. **Identify the Core Class Under Test:** The `#include "third_party/blink/renderer/platform/graphics/parkable_image.h"` line immediately tells us the central class being tested: `ParkableImage`.

3. **Examine the Test Structure:**  The code uses the Google Test framework (`testing/gtest/include/gtest/gtest.h`). This means we should look for `TEST_F` macros, which define individual test cases. The class structure around these tests is also important. We see `ParkableImageBaseTest`, `ParkableImageTest`, `ParkableImageDelayedTest`, and `ParkableImageNoParkingTest`. This suggests different test configurations or scenarios.

4. **Analyze the Base Test Class (`ParkableImageBaseTest`):**
   - **Setup and Teardown:**  `SetUp()` and `TearDown()` are crucial for setting up the testing environment and cleaning up afterward. We see that it resets `ParkableImageManager`, sets up a memory allocator (`InMemoryDataAllocator`), and ensures no parked images remain after each test.
   - **Helper Functions:**  The base class has several helper functions like `WaitForParking()`, `Wait5MinForStatistics()`, `MaybePark()`, `Unpark()`, `Lock()`, `Unlock()`, `MakeParkableImageForTesting()`, and `IsSameContent()`. These provide utilities to interact with `ParkableImage` and the testing environment in a controlled way. The presence of `MaybePark` and the different test classes strongly hint at the "parking" mechanism being a key feature.
   - **Feature Flags:** The use of `base::test::ScopedFeatureList` in the derived test classes indicates testing different configurations based on feature flags (e.g., `kParkableImagesToDisk`, `kDelayParkingImages`).
   - **Metrics Testing:** The `base::HistogramTester` suggests that the tests verify that certain performance metrics related to `ParkableImage` are being recorded correctly.

5. **Analyze Individual Test Cases (`TEST_F`):** For each test case, try to understand:
   - **What aspect of `ParkableImage` is being tested?** (e.g., size, freezing, locking, appending, parking, unparking).
   - **What are the expected inputs and outputs?** (Though explicit input/output examples might not be in every test, the test logic implicitly sets up inputs and checks for expected outcomes).
   - **Does the test exercise different scenarios or edge cases?** (e.g., parking twice, aborting a park, testing with limited disk capacity).

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** This requires thinking about where images are used in web development:
   - **`<img>` tag in HTML:**  The most direct connection. `ParkableImage` likely handles the image data behind the scenes when an `<img>` tag loads an image.
   - **CSS `background-image`:**  Similar to `<img>`, CSS can use images for styling.
   - **Canvas API in JavaScript:** JavaScript can directly manipulate image data on a canvas.
   - **Fetch API in JavaScript:**  When fetching image resources, the browser needs to manage the downloaded data.
   - **Service Workers:** Service workers can intercept image requests and potentially use cached image data.

7. **Identify Potential User/Programming Errors:** Look for patterns in how `ParkableImage` is used in the tests, and consider common mistakes developers might make when working with similar concepts (e.g., resource management, concurrency):
   - **Forgetting to freeze:** The tests explicitly check that parking doesn't happen if the image isn't frozen.
   - **Incorrect locking/unlocking:** Tests verify the locking mechanism.
   - **Race conditions (addressed by locks):**  The locking mechanism itself is a safeguard against race conditions when accessing image data.
   - **Memory leaks (addressed by `ParkableImageManager`):**  The manager likely plays a role in managing the lifecycle of parked images.
   - **Exceeding disk capacity:** A specific test case covers this.

8. **Synthesize and Organize the Findings:**  Structure the analysis to cover the key aspects: functionality, relation to web technologies, logical reasoning (input/output), and potential errors. Use clear and concise language, and provide examples where possible.

**Self-Correction/Refinement During the Process:**

- **Initial thought:**  "This is just about image loading."  **Correction:** The "parking" aspect is a major theme, suggesting optimization for memory usage. Images might be stored on disk temporarily.
- **Initial thought:** "The tests are too low-level to relate to web technologies." **Correction:**  Consider the underlying mechanisms needed to support image display in browsers. `ParkableImage` likely sits below the higher-level web APIs.
- **Focusing too much on specific data values in tests:**  Realize that the *logic* of the tests (the sequence of operations and assertions) is more important than memorizing exact data sizes. The histograms are about *counts* and *types* of events, not necessarily specific latency or throughput values in these isolated tests.

By following these steps and being open to refining initial assumptions, a comprehensive understanding of the test file and the functionality of `ParkableImage` can be achieved.
这个C++文件 `parkable_image_test.cc` 是 Chromium Blink 渲染引擎中 `ParkableImage` 类的单元测试文件。 `ParkableImage` 是一种用于存储图像数据的类，它具有可以将数据“停放”（park）到磁盘并在需要时恢复（unpark）的能力，以优化内存使用。

以下是 `parkable_image_test.cc` 的主要功能：

**1. 测试 `ParkableImage` 类的核心功能:**

*   **创建和大小 (Creation and Size):** 测试 `ParkableImage` 对象的创建以及获取其大小的方法。
*   **冻结状态 (Frozen State):** 测试 `Freeze()` 方法，该方法将图像标记为可以停放的状态。
*   **锁定和解锁 (Lock and Unlock):** 测试用于同步访问图像数据的锁定和解锁机制，防止并发问题。
*   **追加数据 (Append):** 测试向 `ParkableImage` 对象追加图像数据的功能。
*   **停放和恢复 (Park and Unpark):** 这是核心功能，测试将图像数据移动到磁盘（停放）并在需要时将其加载回内存（恢复）的能力。测试确保数据在停放和恢复后保持不变。
*   **同步停放 (Synchronous Park):** 测试在数据已经存储到磁盘后，可以同步执行停放操作，这主要是丢弃内存中的数据。
*   **中止停放 (Aborted Park):** 测试在停放过程中创建快照 (snapshot) 时，停放操作会被中止。
*   **管理器的交互 (Manager Interaction):** 测试 `ParkableImageManager` 如何管理 `ParkableImage` 对象，包括何时停放图像（基于大小、冻结状态等）。
*   **统计信息记录 (Statistics Recording):** 测试 `ParkableImageManager` 是否正确记录了与停放和恢复相关的统计信息，如延迟、大小、吞吐量等。

**2. 测试在禁用停放功能时的行为:**

*   使用 `ParkableImageNoParkingTest` 类测试在禁用 `ParkableImagesToDisk` 功能时 `ParkableImage` 的行为。在这种情况下，`Unpark` 操作应该是一个空操作 (no-op)。

**3. 测试延迟停放功能:**

*   使用 `ParkableImageDelayedTest` 类测试延迟停放功能。在这种模式下，图像在冻结后不会立即停放，而是在一段时间后或当数据被读取时才进行停放。

**4. 测试磁盘容量限制:**

*   使用 `ParkableImageWithLimitedDiskCapacityTest` 类测试在磁盘容量有限的情况下，`ParkableImage` 的停放行为。

**5. 测试并发场景:**

*   测试在独立线程中销毁 `ParkableImage` 对象时，与主线程停放操作的交互。

**6. 测试写入失败的情况:**

*   模拟写入磁盘失败的情况，并验证 `ParkableImageManager` 的处理方式。

**与 JavaScript, HTML, CSS 的关系:**

`ParkableImage` 本身是一个底层的 C++ 类，直接与 JavaScript, HTML, CSS 没有直接的语法上的关系。但是，它在浏览器渲染引擎中扮演着重要的幕后角色，支持这些前端技术的功能：

*   **`<img>` 标签和 CSS 背景图片:** 当浏览器加载 HTML 中的 `<img>` 标签或 CSS 中的 `background-image` 时，图像数据会被下载并存储。 `ParkableImage` 可以用于管理这些图像数据，尤其是在内存压力较高时，可以将不常用的图像数据停放到磁盘，从而节省内存。
    *   **例子:**  假设一个网页包含大量图片，用户滚动浏览后，不再可见的图片数据可能会被 `ParkableImage` 停放到磁盘，释放内存供其他操作使用。当用户滚动回这些图片时，再从磁盘恢复。
*   **Canvas API:** JavaScript 的 Canvas API 允许动态绘制图像。 `ParkableImage` 可以用于存储 Canvas 操作中涉及的图像数据。
    *   **例子:**  一个使用 Canvas 制作的复杂动画，其中某些静态背景或元素可能使用 `ParkableImage` 来管理，以避免长期占用内存。
*   **Fetch API 和图像资源:** 当 JavaScript 使用 Fetch API 获取图像资源时，下载的图像数据可以被 `ParkableImage` 管理。
    *   **例子:**  一个网页应用使用 JavaScript 动态加载用户上传的图片。`ParkableImage` 可以帮助管理这些上传的图片数据。
*   **Service Workers:** Service Workers 可以缓存网络资源，包括图像。 `ParkableImage` 可以作为 Service Worker 缓存机制的一部分，用于存储缓存的图像数据，并根据需要将其移入或移出内存。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理示例：

*   **测试用例:** `TEST_F(ParkableImageTest, ParkAndUnpark)`
    *   **假设输入:** 创建一个包含一定大小数据的 `ParkableImage` 对象，然后冻结它。
    *   **预期输出:** 调用 `MaybePark` 应该返回 `true`，表明可以停放。执行停放操作后，`is_on_disk()` 应该返回 `true`。调用 `Unpark` 后，`is_on_disk()` 应该返回 `false`，并且使用 `IsSameContent` 检查数据是否与原始数据一致。
*   **测试用例:** `TEST_F(ParkableImageNoParkingTest, Unpark)`
    *   **假设输入:** 创建一个 `ParkableImage` 对象并冻结它（即使停用，也需要冻结才能触发后续操作）。
    *   **预期输出:** 调用 `Unpark` 应该不会将数据移动到磁盘（因为停放功能已禁用），`is_on_disk()` 始终返回 `false`。数据应该仍然在内存中，`IsSameContent` 应该返回 `true`。
*   **测试用例:** `TEST_F(ParkableImageDelayedTest, Simple)`
    *   **假设输入:** 创建并冻结一个 `ParkableImage` 对象。
    *   **预期输出:** 在延迟停放时间到达之前，`is_on_disk()` 应该返回 `false`。等待延迟时间后，`is_on_disk()` 应该返回 `true`。

**用户或编程常见的使用错误举例:**

*   **忘记调用 `Freeze()`:** 如果开发者创建了一个 `ParkableImage` 对象，但忘记调用 `Freeze()` 方法，那么即使内存压力很大，该图像也不会被停放到磁盘。这可能导致不必要的内存占用。
    *   **示例:**  一个开发者在一个循环中创建了大量 `ParkableImage` 对象，但没有意识到需要调用 `Freeze()`，结果导致内存消耗过高。
*   **在未解锁的情况下尝试访问数据:** `ParkableImage` 使用锁来保护数据访问。如果在未获取锁的情况下尝试访问图像数据，可能会导致程序崩溃或数据损坏。虽然测试代码中使用了 `Lock()` 和 `Unlock()`，但在实际使用中，开发者需要小心管理这些锁。
    *   **示例:** 多个线程尝试同时访问同一个 `ParkableImage` 的数据，如果没有适当的锁机制，就会发生数据竞争。
*   **假设停放是立即发生的:**  开发者可能会错误地认为调用 `Freeze()` 后图像会立即被停放到磁盘。实际上，停放操作可能是延迟的，或者只有在满足特定条件时才会发生。依赖立即停放可能导致程序行为与预期不符。
    *   **示例:**  开发者在图像冻结后立即尝试释放某些相关资源，但如果停放尚未完成，释放这些资源可能会导致问题。
*   **在停放功能被禁用时仍然假设会停放:** 如果 Chromium 的某些配置或功能标志导致停放功能被禁用，开发者不应该假设 `ParkableImage` 会自动将数据移动到磁盘。这可能导致对内存管理的错误估计。

总而言之，`parkable_image_test.cc` 是一个非常重要的测试文件，它确保了 `ParkableImage` 类的正确性和可靠性，而 `ParkableImage` 类在 Chromium 渲染引擎中扮演着优化内存使用的关键角色，间接地支持了各种 Web 技术的功能。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/parkable_image_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/parkable_image.h"

#include "base/containers/heap_array.h"
#include "base/memory/raw_ptr.h"
#include "base/synchronization/lock.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/disk_data_allocator_test_utils.h"
#include "third_party/blink/renderer/platform/graphics/parkable_image_manager.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

using ThreadPoolExecutionMode =
    base::test::TaskEnvironment::ThreadPoolExecutionMode;

namespace blink {

namespace {
class LambdaThreadDelegate : public base::PlatformThread::Delegate {
 public:
  explicit LambdaThreadDelegate(base::OnceCallback<void()> f)
      : f_(std::move(f)) {}
  void ThreadMain() override { std::move(f_).Run(); }

 private:
  base::OnceCallback<void()> f_;
};
}  // namespace

// Parent for ParkableImageTest and ParkableImageNoParkingTest. The only
// difference between those two is whether parking is enabled or not.
class ParkableImageBaseTest : public ::testing::Test {
 public:
  ParkableImageBaseTest()
      : task_env_(base::test::TaskEnvironment::TimeSource::MOCK_TIME,
                  ThreadPoolExecutionMode::DEFAULT) {}

  void SetUp() override {
    auto& manager = ParkableImageManager::Instance();
    manager.ResetForTesting();
    auto tmp = std::make_unique<InMemoryDataAllocator>();
    allocator_for_testing_ = tmp.get();
    manager.SetDataAllocatorForTesting(std::move(tmp));
    manager.SetTaskRunnerForTesting(task_env_.GetMainThreadTaskRunner());
  }

  void TearDown() override {
    CHECK_EQ(ParkableImageManager::Instance().Size(), 0u);
    task_env_.FastForwardUntilNoTasksRemain();
  }

 protected:
  void WaitForParking() {
    task_env_.FastForwardBy(ParkableImageManager::kDelayedParkingInterval);
  }

  void WaitForDelayedParking() { task_env_.FastForwardBy(base::Seconds(30)); }

  // To aid in testing that the "Memory.ParkableImage.*.5min" metrics are
  // correctly recorded.
  void Wait5MinForStatistics() { task_env_.FastForwardBy(base::Minutes(5)); }

  void DescribeCurrentTasks() { task_env_.DescribeCurrentTasks(); }

  void RunPostedTasks() { task_env_.RunUntilIdle(); }

  size_t GetPendingMainThreadTaskCount() {
    return task_env_.GetPendingMainThreadTaskCount();
  }

  void set_may_write(bool may_write) {
    allocator_for_testing_->set_may_write_for_testing(may_write);
  }

  bool MaybePark(scoped_refptr<ParkableImage> pi) {
    return pi->impl_->MaybePark(task_env_.GetMainThreadTaskRunner());
  }
  static void Unpark(scoped_refptr<ParkableImage> pi) {
    base::AutoLock lock(pi->impl_->lock_);
    pi->impl_->Unpark();
  }
  static void Lock(scoped_refptr<ParkableImage> pi) {
    base::AutoLock lock(pi->impl_->lock_);
    pi->LockData();
  }
  static void Unlock(scoped_refptr<ParkableImage> pi) {
    base::AutoLock lock(pi->impl_->lock_);
    pi->UnlockData();
  }
  static bool is_on_disk(scoped_refptr<ParkableImage> pi) {
    base::AutoLock lock(pi->impl_->lock_);
    return pi->is_on_disk();
  }
  static bool is_locked(scoped_refptr<ParkableImage> pi) {
    base::AutoLock lock(pi->impl_->lock_);
    return pi->impl_->is_locked();
  }
  static bool is_frozen(scoped_refptr<ParkableImage> pi) {
    return pi->impl_->is_frozen();
  }

  scoped_refptr<ParkableImage> MakeParkableImageForTesting(base::span<const char> buffer) {
    auto pi = ParkableImage::Create();

    pi->Append(WTF::SharedBuffer::Create(buffer.data(), buffer.size()).get(), 0);

    return pi;
  }

  // Checks content matches the ParkableImage returned from
  // |MakeParkableImageForTesting|.
  static bool IsSameContent(scoped_refptr<ParkableImage> pi,
                            base::span<const char> buffer) {
    if (pi->size() != buffer.size()) {
      return false;
    }

    base::AutoLock lock(pi->impl_->lock_);
    pi->LockData();

    auto ro_buffer = pi->impl_->rw_buffer_->MakeROBufferSnapshot();
    ROBuffer::Iter iter(ro_buffer.get());
    const char* cur = buffer.data();
    do {
      if (memcmp(iter.data(), cur, iter.size()) != 0) {
        pi->UnlockData();
        return false;
      }
      cur += iter.size();
    } while (iter.Next());

    pi->UnlockData();
    return true;
  }

  // This checks that the "Memory.ParkableImage.Write.*" statistics from
  // |RecordReadStatistics()| are recorded correctly, namely
  // "Memory.ParkableImage.Write.Latency" and
  // "Memory.ParkableImage.Write.Size".
  //
  // Checks the counts for all 3 metrics, but only checks the value for
  // "Memory.ParkableImage.Write.Size", since the others can't be easily tested.
  void ExpectWriteStatistics(base::HistogramBase::Sample sample,
                             base::HistogramBase::Count expected_count) {
    histogram_tester_.ExpectTotalCount("Memory.ParkableImage.Write.Latency",
                                       expected_count);
    histogram_tester_.ExpectBucketCount("Memory.ParkableImage.Write.Size",
                                        sample, expected_count);
  }

  // This checks that the "Memory.ParkableImage.Read.*" statistics from
  // |RecordReadStatistics()| are recorded correctly, namely
  // "Memory.ParkableImage.Read.Latency", and
  // "Memory.ParkableImage.Read.Throughput".
  //
  // Checks the counts for both metrics, but not their values, since they can't
  // be easily tested.
  void ExpectReadStatistics(base::HistogramBase::Sample sample,
                            base::HistogramBase::Count expected_count) {
    histogram_tester_.ExpectTotalCount("Memory.ParkableImage.Read.Latency",
                                       expected_count);
    histogram_tester_.ExpectTotalCount("Memory.ParkableImage.Read.Throughput",
                                       expected_count);
  }

  base::HistogramTester histogram_tester_;

 private:
  base::test::TaskEnvironment task_env_;
  raw_ptr<InMemoryDataAllocator> allocator_for_testing_;
};

// Parking is enabled for these tests.
class ParkableImageTest : public ParkableImageBaseTest {
 public:
  ParkableImageTest() {
    fl_.InitWithFeatures({features::kParkableImagesToDisk},
                         {kDelayParkingImages});
  }

 private:
  base::test::ScopedFeatureList fl_;
};

// Parking is delayed but enabled for these tests.
class ParkableImageDelayedTest : public ParkableImageBaseTest {
 public:
  ParkableImageDelayedTest() {
    fl_.InitWithFeatures({features::kParkableImagesToDisk, kDelayParkingImages},
                         {});
  }

 private:
  base::test::ScopedFeatureList fl_;
};

// Parking is disabled for these tests.
class ParkableImageNoParkingTest : public ParkableImageBaseTest {
 public:
  ParkableImageNoParkingTest() {
    fl_.InitAndDisableFeature(features::kParkableImagesToDisk);
  }

 private:
  base::test::ScopedFeatureList fl_;
};

class ParkableImageWithLimitedDiskCapacityTest : public ParkableImageBaseTest {
 public:
  ParkableImageWithLimitedDiskCapacityTest() {
    const std::vector<base::test::FeatureRefAndParams> enabled_features = {
        {features::kParkableImagesToDisk, {}},
        {features::kCompressParkableStrings, {{"max_disk_capacity_mb", "1"}}}};
    fl_.InitWithFeaturesAndParameters(enabled_features, {kDelayParkingImages});
  }

 private:
  base::test::ScopedFeatureList fl_;
};

// Tests that ParkableImages are constructed with the correct size.
TEST_F(ParkableImageTest, Size) {
  auto pi = ParkableImage::Create();

  EXPECT_EQ(pi->size(), 0u);

  // This has capacity 10, not size 10; size should still be 0.
  pi = ParkableImage::Create(10);

  EXPECT_EQ(pi->size(), 0u);
}

// Tests that |Freeze|ing a ParkableImage correctly updates its state.
TEST_F(ParkableImageTest, Frozen) {
  auto pi = ParkableImage::Create();
  ASSERT_EQ(pi->size(), 0u);

  // Starts unfrozen.
  EXPECT_FALSE(is_frozen(pi));

  pi->Freeze();

  EXPECT_TRUE(is_frozen(pi));
}

TEST_F(ParkableImageTest, LockAndUnlock) {
  auto pi = ParkableImage::Create();
  ASSERT_EQ(pi->size(), 0u);

  // ParkableImage starts unlocked.
  EXPECT_FALSE(is_locked(pi));

  Lock(pi);

  // Now locked after calling |Lock|.
  EXPECT_TRUE(is_locked(pi));

  Lock(pi);

  // Still locked after locking a second time.
  EXPECT_TRUE(is_locked(pi));

  Unlock(pi);

  // Still locked, we need to unlock a second time to unlock this.
  EXPECT_TRUE(is_locked(pi));

  Unlock(pi);

  // Now unlocked because we have locked twice then unlocked twice.
  EXPECT_FALSE(is_locked(pi));
}

// Tests that |Append|ing to a ParkableImage correctly adds data to it.
TEST_F(ParkableImageTest, Append) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = ParkableImage::Create();
  ASSERT_EQ(pi->size(), 0u);  // Should be empty when created.

  pi->Append(WTF::SharedBuffer::Create(data.data(), data.size()).get(), 0);

  EXPECT_TRUE(IsSameContent(pi, data));
}

// Tests that multiple |Append|s correctly add data to the end of ParkableImage.
TEST_F(ParkableImageTest, AppendMultiple) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = ParkableImage::Create();
  ASSERT_EQ(pi->size(), 0u);  // Should be empty when created.

  auto sb = WTF::SharedBuffer::Create(data.data(), data.size());
  ASSERT_EQ(sb->size(), kDataSize);

  pi->Append(sb.get(), 0);

  EXPECT_TRUE(IsSameContent(pi, data));

  sb->Append(data.data(), kDataSize);
  ASSERT_EQ(sb->size(), 2 * kDataSize);

  pi->Append(sb.get(), pi->size());

  EXPECT_EQ(pi->size(), 2 * kDataSize);
}

// Tests that we can read/write to disk correctly, preserving the data.
TEST_F(ParkableImageTest, ParkAndUnpark) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  // We have no images currently.
  ASSERT_EQ(0u, ParkableImageManager::Instance().Size());

  auto pi = MakeParkableImageForTesting(data);

  // We now have 1 image.
  ASSERT_EQ(1u, ParkableImageManager::Instance().Size());

  // Can't park because it is not frozen.
  EXPECT_FALSE(MaybePark(pi));

  // Should _not_ be on disk now.
  EXPECT_FALSE(is_on_disk(pi));

  pi->Freeze();

  // Parkable now that it's frozen.
  EXPECT_TRUE(MaybePark(pi));

  // Run task to park image.
  RunPostedTasks();

  // Should be on disk now.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);

  // Unparking blocks until it is read from disk, so we expect it to no longer
  // be on disk after unparking.
  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same after unparking.
  EXPECT_TRUE(IsSameContent(pi, data));

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);
}

// Tests that trying to park multiple times doesn't add any extra tasks.
TEST_F(ParkableImageTest, ParkTwiceAndUnpark) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  // We have no images currently.
  ASSERT_EQ(0u, ParkableImageManager::Instance().Size());

  auto pi = MakeParkableImageForTesting(data);

  // We now have 1 image.
  ASSERT_EQ(1u, ParkableImageManager::Instance().Size());
  pi->Freeze();

  // Attempt to park the image twice in a row. This should have the same effect
  // as trying to park it once.
  EXPECT_TRUE(MaybePark(pi));
  EXPECT_TRUE(MaybePark(pi));

  // Run task to park image.
  RunPostedTasks();

  // Should be on disk now.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);

  // Unparking blocks until it is read from disk, so we expect it to no longer
  // be on disk after unparking.
  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same after unparking.
  EXPECT_TRUE(IsSameContent(pi, data));

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);
}

// Tests that we can park to disk synchronously after the data is stored on
// disk the first time.
TEST_F(ParkableImageTest, ParkAndUnparkSync) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  // We have no images currently.
  ASSERT_EQ(0u, ParkableImageManager::Instance().Size());

  auto pi = MakeParkableImageForTesting(data);

  // We now have 1 image.
  ASSERT_EQ(1u, ParkableImageManager::Instance().Size());

  // Can't park because it is not frozen.
  EXPECT_FALSE(MaybePark(pi));

  // Should _not_ be on disk now.
  EXPECT_FALSE(is_on_disk(pi));

  pi->Freeze();

  // Parkable now that it's frozen.
  EXPECT_TRUE(MaybePark(pi));

  // Should not be on disk yet because we haven't run the tasks to write to disk
  // yet.
  EXPECT_FALSE(is_on_disk(pi));

  // Run task to park image.
  RunPostedTasks();

  // Should be on disk now.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);

  // Unparking blocks until it is read from disk, so we expect it to no longer
  // be on disk after unparking.
  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same after unparking.
  EXPECT_TRUE(IsSameContent(pi, data));

  // Try to park a second time.
  EXPECT_TRUE(MaybePark(pi));

  // We already have it on disk, so this time we just need to discard the data,
  // which can be done synchronously.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);

  // Unparking blocks until it is read from disk, so we expect it to no longer
  // be on disk after unparking.
  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same after unparking.
  EXPECT_TRUE(IsSameContent(pi, data));

  // One extra read than write. We discard the data twice, but we only need to
  // write to disk once. Because we've discarded it twice, we need to do two
  // reads.
  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 2);
}

// Tests that creating a snapshot partway through writing correctly aborts
// discarding the data.
TEST_F(ParkableImageTest, ParkAndUnparkAborted) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  // We have no images currently.
  ASSERT_EQ(0u, ParkableImageManager::Instance().Size());

  auto pi = MakeParkableImageForTesting(data);

  // We now have 1 image.
  ASSERT_EQ(1u, ParkableImageManager::Instance().Size());

  // Should _not_ be on disk now.
  ASSERT_FALSE(is_on_disk(pi));

  pi->Freeze();

  // Parkable now that it's frozen.
  EXPECT_TRUE(MaybePark(pi));

  auto snapshot = pi->MakeROSnapshot();
  snapshot->LockData();

  // Run task to park image.
  RunPostedTasks();

  // Should have been aborted, so still not on disk.
  EXPECT_FALSE(is_on_disk(pi));

  // Unparking after aborted write is fine.
  Unpark(pi);

  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same.
  EXPECT_TRUE(IsSameContent(pi, data));

  // We still expect a write to be done in this case, since the only thing
  // preventing it from being parked is the snapshot. However, the data is not
  // discarded here, since we need for the snapshot.
  //
  // Since the data was never discarded, we expect 0 reads however.
  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 0);

  // Since we have a snapshot alive, we can't park.
  EXPECT_FALSE(MaybePark(pi));

  // kill the old snapshot.
  snapshot->UnlockData();
  snapshot = nullptr;

  // Now that snapshot is gone, we can park.
  EXPECT_TRUE(MaybePark(pi));

  RunPostedTasks();

  // Now parking can succeed.
  EXPECT_TRUE(is_on_disk(pi));

  // Unpark after successful write should also work.
  Unpark(pi);

  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same.
  EXPECT_TRUE(IsSameContent(pi, data));

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);
}

// Tests that a frozen image will be written to disk by the manager.
TEST_F(ParkableImageTest, ManagerSimple) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  pi->Freeze();

  EXPECT_EQ(1u, manager.Size());

  // One of these is the delayed parking task
  // |ParkableImageManager::MaybeParkImages|, the other is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // Image should be on disk now.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);
  EXPECT_FALSE(is_on_disk(pi));

  WaitForParking();

  // Even though we unparked earlier, a new delayed parking task should park the
  // image still.
  EXPECT_TRUE(is_on_disk(pi));

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);
}

// Tests that a small image is not kept in the manager.
TEST_F(ParkableImageTest, ManagerSmall) {
  const size_t kDataSize = ParkableImageImpl::kMinSizeToPark - 10;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  EXPECT_EQ(1u, manager.Size());

  pi->Freeze();

  // Image should now be removed from the manager.
  EXPECT_EQ(0u, manager.Size());

  // One of these is the delayed parking task
  // |ParkableImageManager::MaybeParkImages|, the other is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // Image should be on disk now.
  EXPECT_FALSE(is_on_disk(pi));
}

// Tests that the manager can correctly handle multiple parking tasks being
// created at once.
TEST_F(ParkableImageTest, ManagerTwo) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  pi->Freeze();

  EXPECT_EQ(1u, manager.Size());

  // One of these is the delayed parking task
  // |ParkableImageManager::MaybeParkImages|, the other is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // Image should be on disk now.
  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);
  EXPECT_FALSE(is_on_disk(pi));

  WaitForParking();

  // Even though we unparked earlier, a new delayed parking task should park the
  // image still.
  EXPECT_TRUE(is_on_disk(pi));

  ExpectWriteStatistics(kDataSize / 1024, 1);
  ExpectReadStatistics(kDataSize / 1024, 1);
}

// Test that a non-frozen image will not be written to disk.
TEST_F(ParkableImageTest, ManagerNonFrozen) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);

  EXPECT_EQ(1u, manager.Size());

  // One of these is the delayed parking task
  // |ParkableImageManager::MaybeParkImages|, the other is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // Can't park because it is not frozen.
  EXPECT_FALSE(is_on_disk(pi));

  // No read or write was done, so we expect no metrics to be recorded for
  // reading/writing.
  ExpectWriteStatistics(0, 0);
  ExpectReadStatistics(0, 0);
}

// Check that trying to unpark a ParkableImage when parking is disabled has no
// effect.
TEST_F(ParkableImageNoParkingTest, Unpark) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = MakeParkableImageForTesting(data);

  pi->Freeze();

  ASSERT_FALSE(is_on_disk(pi));

  // This is a no-op when parking is disabled.
  Unpark(pi);

  EXPECT_TRUE(IsSameContent(pi, data));

  // No data should be written or read when parking is disabled.
  ExpectWriteStatistics(kDataSize / 1024, 0);
  ExpectReadStatistics(kDataSize / 1024, 0);
}

// Tests that the ParkableImageManager is correctly recording statistics after 5
// minutes.
TEST_F(ParkableImageTest, ManagerStatistics5min) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = MakeParkableImageForTesting(data);
  pi->Freeze();

  Wait5MinForStatistics();

  // We expect "Memory.ParkableImage.OnDiskFootprintKb.5min" not to be emitted,
  // since we've mocked the DiskDataAllocator for testing (and therefore cannot
  // actually write to disk).
  histogram_tester_.ExpectTotalCount(
      "Memory.ParkableImage.OnDiskFootprintKb.5min", 0);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.OnDiskSize.5min", 1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalReadTime.5min",
                                     1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalSize.5min", 1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalWriteTime.5min",
                                     1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.UnparkedSize.5min",
                                     1);
}

// Tests that the ParkableImageManager is correctly recording statistics after 5
// minutes, even when parking is disabled. Only bookkeeping metrics should be
// recorded in this case, since no reads/writes will happen.
TEST_F(ParkableImageNoParkingTest, ManagerStatistics5min) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = MakeParkableImageForTesting(data);
  pi->Freeze();

  Wait5MinForStatistics();

  // Note that we expect 0 counts of some of these metrics.
  histogram_tester_.ExpectTotalCount(
      "Memory.ParkableImage.OnDiskFootprintKb.5min", 0);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.OnDiskSize.5min", 1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalReadTime.5min",
                                     0);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalSize.5min", 1);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.TotalWriteTime.5min",
                                     0);
  histogram_tester_.ExpectTotalCount("Memory.ParkableImage.UnparkedSize.5min",
                                     1);
}

// Tests that the manager doesn't try to park any images when parking is
// disabled.
TEST_F(ParkableImageNoParkingTest, ManagerSimple) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = MakeParkableImageForTesting(data);

  auto& manager = ParkableImageManager::Instance();
  // The manager still keeps track of all images when parking is disabled, but
  // should not park them.
  EXPECT_EQ(1u, manager.Size());

  pi->Freeze();

  // This is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  // This should not do anything, since parking is disabled.
  WaitForParking();

  EXPECT_FALSE(is_on_disk(pi));

  EXPECT_TRUE(IsSameContent(pi, data));

  // No data should be written or read when parking is disabled.
  ExpectWriteStatistics(kDataSize / 1024, 0);
  ExpectReadStatistics(kDataSize / 1024, 0);
}

// Test a locked image will not be written to disk.
TEST_F(ParkableImageTest, ManagerNotUnlocked) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);

  EXPECT_EQ(1u, manager.Size());

  // Freeze, so it would be Parkable (if not for the Lock right after this
  // line).
  pi->Freeze();
  Lock(pi);

  WaitForParking();

  // Can't park because it is locked.
  EXPECT_FALSE(is_on_disk(pi));

  Unlock(pi);
}

// Tests that the manager only reschedules the parking task  when there are
// unfrozen ParkableImages.
TEST_F(ParkableImageTest, ManagerRescheduleUnfrozen) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);

  // This is the delayed
  // accounting task |ParkableImageManager::RecordStatisticsAfter5Minutes|, and
  // the parking task.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  // Fast forward enough for both to run.
  Wait5MinForStatistics();
  WaitForParking();

  // Unfrozen ParkableImages are never parked.
  ASSERT_FALSE(is_on_disk(pi));

  // We have rescheduled the task because we have unfrozen ParkableImages.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  pi->Freeze();
  Lock(pi);

  WaitForParking();

  // Locked ParkableImages are never parked.
  ASSERT_FALSE(is_on_disk(pi));

  // We do no reschedule because there are no un-frozen ParkableImages.
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  Unlock(pi);
}

// We want to test that trying to delete an image while we try to park it works
// correctly. The expected behaviour is we park it, then delete. Slightly
// inefficient, but the safest way to do it.
TEST_F(ParkableImageTest, DestroyOnSeparateThread) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  EXPECT_EQ(1u, manager.Size());

  Wait5MinForStatistics();

  pi->Freeze();

  // Task for parking the image.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  LambdaThreadDelegate delegate{
      base::BindLambdaForTesting([parkable_image = std::move(pi)]() mutable {
        EXPECT_TRUE(!IsMainThread());
        // We destroy the ParkableImage here, on a different thread. This will
        // post a task to the main thread to actually delete it.
        parkable_image = nullptr;
      })};

  base::PlatformThreadHandle thread_handle;
  base::PlatformThread::Create(0, &delegate, &thread_handle);
  base::PlatformThread::Join(thread_handle);

  ASSERT_EQ(pi, nullptr);

  // The manager is still aware of the ParkableImage, since the task for
  // deleting it hasn't been run yet.
  EXPECT_EQ(1u, manager.Size());
  // Task for parking image, followed by task for deleting the image.
  EXPECT_EQ(2u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // Now that the tasks for deleting and parking have run, the image is deleted.
  EXPECT_EQ(0u, manager.Size());
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
}

TEST_F(ParkableImageTest, FailedWrite) {
  auto& manager = ParkableImageManager::Instance();
  set_may_write(false);

  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  EXPECT_EQ(0u, manager.Size());

  WaitForParking();

  {
    auto pi = MakeParkableImageForTesting(data);
    pi->Freeze();
    manager.MaybeParkImagesForTesting();
    EXPECT_EQ(1u, manager.Size());
  }

  WaitForParking();

  EXPECT_EQ(0u, manager.Size());
}

// Test that we park only after 30 seconds, not immediately after freezing.
TEST_F(ParkableImageDelayedTest, Simple) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  EXPECT_EQ(1u, manager.Size());

  Wait5MinForStatistics();

  pi->Freeze();

  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // We have 1 task still, since we need to wait for 30 seconds after the image
  // has been frozen.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
  EXPECT_FALSE(is_on_disk(pi));

  WaitForDelayedParking();

  // After waiting 30 seconds, the image is parked.
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());

  EXPECT_TRUE(is_on_disk(pi));
}

// Test that we park only after 30 seconds or once we have read the data, not
// immediately after freezing.
TEST_F(ParkableImageDelayedTest, Read) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto& manager = ParkableImageManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  auto pi = MakeParkableImageForTesting(data);
  EXPECT_EQ(1u, manager.Size());

  Wait5MinForStatistics();

  pi->Freeze();

  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());

  WaitForParking();

  // We have 1 task still, since we need to wait for 30 seconds after the image
  // has been frozen.
  EXPECT_EQ(1u, GetPendingMainThreadTaskCount());
  EXPECT_FALSE(is_on_disk(pi));

  // Read the data here, which allows us to park the image immediately.
  pi->Data();

  WaitForParking();

  // Image is successfully parked, even though it's been less than 30 seconds.
  EXPECT_EQ(0u, GetPendingMainThreadTaskCount());
  EXPECT_TRUE(is_on_disk(pi));
}

// 30 seconds should be counted from when we freeze, and not be affected by
// parking/unparking.
TEST_F(ParkableImageDelayedTest, ParkAndUnpark) {
  const size_t kDataSize = 3.5 * 4096;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  // We have no images currently.
  ASSERT_EQ(0u, ParkableImageManager::Instance().Size());

  auto pi = MakeParkableImageForTesting(data);

  // We now have 1 image.
  ASSERT_EQ(1u, ParkableImageManager::Instance().Size());

  pi->Freeze();

  WaitForParking();

  EXPECT_FALSE(is_on_disk(pi));

  WaitForDelayedParking();

  EXPECT_TRUE(is_on_disk(pi));

  Unpark(pi);

  // Unparking blocks until it is read from disk, so we expect it to no longer
  // be on disk after unparking.
  EXPECT_FALSE(is_on_disk(pi));

  // Make sure content is the same after unparking.
  EXPECT_TRUE(IsSameContent(pi, data));

  WaitForParking();

  // No need to wait 30 more seconds, we can park immediately.
  EXPECT_TRUE(is_on_disk(pi));
}

TEST_F(ParkableImageWithLimitedDiskCapacityTest, ParkWithLimitedDiskCapacity) {
  constexpr size_t kMB = 1024 * 1024;
  constexpr size_t kDataSize = kMB;
  auto data = base::HeapArray<char>::Uninit(kDataSize);
  PrepareReferenceData(data);

  auto pi = MakeParkableImageForTesting(data);
  pi->Freeze();
  EXPECT_TRUE(MaybePark(pi));
  RunPostedTasks();
  EXPECT_TRUE(is_on_disk(pi));

  // Create another parkable image and attempt to write to disk.
  auto pi2 = MakeParkableImageForTesting(data);
  pi2->Freeze();
  // Should be false because there is no free space.
  EXPECT_FALSE(MaybePark(pi2));

  // Remove first parkable image. Now we can park second image.
  pi = nullptr;
  EXPECT_TRUE(MaybePark(pi2));
  RunPostedTasks();
  EXPECT_TRUE(is_on_disk(pi2));
}

}  // namespace blink

"""

```