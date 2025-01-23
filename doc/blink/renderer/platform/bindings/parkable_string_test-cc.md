Response:
The user wants me to analyze a C++ source code file related to `ParkableString` in the Chromium Blink engine.

My plan is to:
1. **Identify the core functionality**: Understand what `ParkableString` and the associated test file are designed to do.
2. **Look for connections to web technologies**: Determine if and how `ParkableString` interacts with JavaScript, HTML, or CSS.
3. **Analyze logic and provide examples**: If the code involves logical operations, create hypothetical input/output scenarios.
4. **Identify potential errors**: Pinpoint common mistakes users or programmers might make when using this functionality.
5. **Summarize the functionality**:  Provide a concise overview of the file's purpose based on the analysis.
```
这是目录为blink/renderer/platform/bindings/parkable_string_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

**功能列举:**

1. **测试 `ParkableString` 类的核心功能:** 该文件是 `ParkableString` 类的单元测试，用于验证其各种功能是否正常工作。
2. **测试字符串的停靠 (Parking) 和唤醒 (Unparking):**  测试 `ParkableString` 将字符串数据移动到后台以节省内存，以及在需要时重新加载到内存的功能。这包括内存停靠和磁盘停靠两种方式。
3. **测试字符串的压缩和解压缩:** 验证 `ParkableString` 在停靠时压缩字符串数据以进一步减少内存占用，以及唤醒时解压缩的功能。测试支持不同的压缩算法（Zlib, Snappy, Zstd）。
4. **测试字符串的锁定 (Locking) 和解锁 (Unlocking):**  测试 `ParkableString` 提供的锁定机制，防止字符串在被锁定时被停靠或释放。
5. **测试多线程场景下的安全性:** 验证 `ParkableString` 在多线程环境下的行为，例如在后台线程中停靠、唤醒和销毁字符串。
6. **测试内存管理:** 验证 `ParkableStringManager` 类对 `ParkableString` 对象的管理，包括跟踪、老化 (Aging) 和停靠策略。
7. **测试错误处理和边界情况:**  测试停靠失败的情况，以及在各种异常情况下 `ParkableString` 的行为。
8. **测试性能指标:** 使用 `base::HistogramTester` 记录停靠、唤醒、压缩和解压缩的延迟和吞吐量等性能指标。
9. **测试磁盘存储:** 验证 `ParkableString` 将数据存储到磁盘并在需要时从磁盘加载的功能。
10. **测试 ASan (AddressSanitizer) 集成:** 确保在停靠和唤醒操作期间不会发生内存安全问题。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

`ParkableString` 本身是一个底层的 C++ 类，直接与 JavaScript, HTML, 或 CSS 的语法或解析无关。但是，它在 Blink 渲染引擎中用于优化内存使用，这会间接地影响到这些 Web 技术的性能和资源消耗。

* **JavaScript 字符串:**  JavaScript 中大量的字符串操作可能会导致内存压力。Blink 引擎内部会将一些 JavaScript 字符串表示为 `WTF::String` 对象，而 `ParkableString` 可以作为 `WTF::String` 的底层实现的一部分，用于优化这些字符串的存储。例如，当一个 JavaScript 字符串长时间未被使用，`ParkableString` 机制可能会将其停靠到后台，释放主线程的内存。当 JavaScript 再次访问该字符串时，它会被唤醒。

   **假设输入与输出 (逻辑推理):**
   * **假设输入:** 一个包含大量文本内容的 JavaScript 变量被创建并赋值。
   * **中间过程:** Blink 引擎可能将该字符串表示为一个 `WTF::String`，并使用 `ParkableString` 来管理其内存。如果该变量长时间没有被 JavaScript 代码访问，`ParkableString` 可能会将其停靠。
   * **输出:** 当 JavaScript 代码再次访问该变量时，`ParkableString` 会将其唤醒，确保 JavaScript 代码可以正常读取字符串内容。

* **HTML 和 CSS 字符串:** HTML 和 CSS 文档中包含大量的文本信息，例如标签名、属性值、样式规则等。这些文本信息在 Blink 引擎内部也会以字符串的形式存储。`ParkableString` 可以用于优化这些字符串的内存占用。例如，一个大的 CSS 样式表可能包含许多重复的或长时间不使用的字符串，`ParkableString` 可以将其停靠。

   **假设输入与输出 (逻辑推理):**
   * **假设输入:**  浏览器加载一个包含大量 CSS 规则的网页。
   * **中间过程:** Blink 引擎解析 CSS，并将 CSS 规则中的字符串（例如选择器、属性名、属性值）存储在内存中。`ParkableString` 可能会管理这些字符串。
   * **输出:** 如果某些 CSS 规则对应的元素在页面上长时间不可见或不活跃，其相关的 CSS 字符串可能被 `ParkableString` 停靠，以减少内存消耗。

**用户或编程常见的使用错误 (举例说明):**

由于 `ParkableString` 是 Blink 内部使用的类，开发者通常不会直接操作它。然而，理解其背后的原理可以帮助理解 Blink 的内存管理机制，从而避免一些可能导致性能问题的编程模式。

* **过度依赖字符串拷贝:** 如果 JavaScript 或 C++ 代码中频繁地创建和拷贝大量的字符串，即使有 `ParkableString` 的优化，仍然可能导致内存压力。因为每次拷贝都可能需要唤醒被停靠的字符串，或者创建新的字符串副本。
    * **示例:** 在 JavaScript 中使用 `string.substring()` 或 `string.concat()` 创建大量新的临时字符串。

* **长时间持有大字符串:** 如果 JavaScript 代码中存在全局变量或闭包，长时间持有大的字符串，即使这些字符串不被频繁使用，也可能阻止 `ParkableString` 将其停靠。
    * **示例:**  将从服务器获取的大量文本数据存储在一个全局 JavaScript 变量中，但很少在页面上展示或处理。

* **在性能敏感的代码路径中频繁唤醒字符串:** 如果某些关键的渲染或 JavaScript 执行路径需要频繁地访问被停靠的字符串，会导致性能下降，因为每次访问都需要进行唤醒操作。

**第 1 部分功能归纳:**

该文件是 `ParkableString` 类的单元测试，其主要功能是全面验证 `ParkableString` 类的各种特性，包括字符串的停靠、唤醒、压缩、解压缩、锁定、多线程安全性、内存管理、磁盘存储以及错误处理。通过这些测试，可以确保 `ParkableString` 作为 Blink 引擎中重要的内存优化机制能够稳定可靠地工作。它间接地服务于 JavaScript、HTML 和 CSS，通过优化底层字符串的内存管理来提升 Web 应用的性能和资源利用率。

### 提示词
```
这是目录为blink/renderer/platform/bindings/parkable_string_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/bindings/parkable_string.h"

#include <algorithm>
#include <cstring>
#include <limits>

#include "base/functional/bind.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "base/timer/elapsed_timer.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/process_memory_dump.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/bindings/parkable_string_manager.h"
#include "third_party/blink/renderer/platform/disk_data_allocator_test_utils.h"
#include "third_party/blink/renderer/platform/instrumentation/memory_pressure_listener.h"
#include "third_party/blink/renderer/platform/scheduler/public/rail_mode_observer.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"

using ThreadPoolExecutionMode =
    base::test::TaskEnvironment::ThreadPoolExecutionMode;

namespace blink {

namespace {

constexpr size_t kSizeKb = 20;

// Compressed size of the string returned by |MakeLargeString()|.
// Update if the assertion in the |CheckCompressedSize()| test fails.
constexpr size_t kCompressedSizeZlib = 55;
constexpr size_t kCompressedSizeSnappy = 944;
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
constexpr size_t kCompressedSizeZstd = 19;
#endif

String MakeLargeString(char c = 'a') {
  Vector<char> data(kSizeKb * 1000, c);
  return String(data).ReleaseImpl();
}

String MakeComplexString(size_t size) {
  Vector<char> data(size, 'a');
  // This string should not be compressed too much, but also should not
  // be compressed failed. So make only some parts of this random.
  base::RandBytes(base::as_writable_byte_span(data).first(size / 10u));
  return String(data).ReleaseImpl();
}

class LambdaThreadDelegate : public base::PlatformThread::Delegate {
 public:
  explicit LambdaThreadDelegate(base::OnceClosure f) : f_(std::move(f)) {}
  void ThreadMain() override { std::move(f_).Run(); }

 private:
  base::OnceClosure f_;
};

}  // namespace

class ParkableStringTest
    : public testing::TestWithParam<ParkableStringImpl::CompressionAlgorithm> {
 public:
  ParkableStringTest(ThreadPoolExecutionMode thread_pool_execution_mode =
                         ThreadPoolExecutionMode::DEFAULT)
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME,
                          thread_pool_execution_mode) {
    ParkableStringImpl::CompressionAlgorithm algorithm = GetParam();
    switch (algorithm) {
      case ParkableStringImpl::CompressionAlgorithm::kZlib:
        scoped_feature_list_.InitWithFeatures(
            {}, {features::kUseSnappyForParkableStrings,
                 features::kUseZstdForParkableStrings});
        break;
      case ParkableStringImpl::CompressionAlgorithm::kSnappy:
        scoped_feature_list_.InitWithFeatures(
            {features::kUseSnappyForParkableStrings},
            {features::kUseZstdForParkableStrings});
        break;
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
      case ParkableStringImpl::CompressionAlgorithm::kZstd:
        scoped_feature_list_.InitWithFeatures(
            {features::kUseZstdForParkableStrings},
            {features::kUseSnappyForParkableStrings});
        break;
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
    }

    CHECK_EQ(ParkableStringImpl::GetCompressionAlgorithm(), algorithm);
  }

 protected:
  void RunPostedTasks() { task_environment_.RunUntilIdle(); }

  bool ParkAndWait(const ParkableString& string) {
    bool success =
        string.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress);
    RunPostedTasks();
    return success;
  }

  void WaitForAging() {
    if (base::FeatureList::IsEnabled(features::kCompressParkableStrings)) {
      EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
    }

    if (!first_aging_done_) {
      task_environment_.FastForwardBy(
          ParkableStringManager::kFirstParkingDelay);
      first_aging_done_ = true;
    } else {
      task_environment_.FastForwardBy(ParkableStringManager::AgingInterval());
    }
  }

  void WaitForDelayedParking() {
    // First wait for the string to get older.
    WaitForAging();
    // Now wait for the string to get parked.
    WaitForAging();
  }

  void WaitForDiskWriting() {
    WaitForAging();
    WaitForAging();
  }

  void CheckOnlyCpuCostTaskRemains() {
    unsigned expected_count = 0;
    if (ParkableStringManager::Instance()
            .has_posted_unparking_time_accounting_task_) {
      expected_count = 1;
    }
    EXPECT_EQ(expected_count,
              task_environment_.GetPendingMainThreadTaskCount());
  }

  void SetUp() override {
    auto& manager = ParkableStringManager::Instance();
    manager.ResetForTesting();
    manager.SetTaskRunnerForTesting(
        task_environment_.GetMainThreadTaskRunner());
    manager.SetDataAllocatorForTesting(
        std::make_unique<InMemoryDataAllocator>());

    manager.SetRendererBackgrounded(true);
    // No string yet, should not post a task since there is nothing to do.
    ASSERT_EQ(0u, task_environment_.GetPendingMainThreadTaskCount());
  }

  void TearDown() override {
    // No leaks.
    CHECK_EQ(0u, ParkableStringManager::Instance().Size());
    // Delayed tasks may remain, clear the queues.
    task_environment_.FastForwardUntilNoTasksRemain();
  }

  ParkableString CreateAndParkAll() {
    auto& manager = ParkableStringManager::Instance();
    // Checking that there are no other strings, to make sure this doesn't
    // cause side-effects.
    CHECK_EQ(0u, manager.Size());
    ParkableString parkable(MakeLargeString('a').ReleaseImpl());
    EXPECT_FALSE(parkable.Impl()->is_parked());
    WaitForDelayedParking();
    EXPECT_TRUE(parkable.Impl()->is_parked());
    return parkable;
  }

  void DisableOnDiskWriting() {
    ParkableStringManager::Instance().SetDataAllocatorForTesting(nullptr);
  }

  size_t GetExpectedCompressedSize() const {
    switch (ParkableStringImpl::GetCompressionAlgorithm()) {
      case ParkableStringImpl::CompressionAlgorithm::kZlib:
        return kCompressedSizeZlib;
      case ParkableStringImpl::CompressionAlgorithm::kSnappy:
        return kCompressedSizeSnappy;
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
      case ParkableStringImpl::CompressionAlgorithm::kZstd:
        return kCompressedSizeZstd;
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
    }
  }

  bool first_aging_done_ = false;
  base::test::ScopedFeatureList scoped_feature_list_;
  base::test::TaskEnvironment task_environment_;
};

INSTANTIATE_TEST_SUITE_P(
    CompressionAlgorithm,
    ParkableStringTest,
    ::testing::Values(ParkableStringImpl::CompressionAlgorithm::kZlib,
                      ParkableStringImpl::CompressionAlgorithm::kSnappy
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ,
                      ParkableStringImpl::CompressionAlgorithm::kZstd
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ));

// The main aim of this test is to check that the compressed size of a string
// doesn't change. If it does, |kCompressedSizeZlib| and/or
// |kCompressedSizeSnappy| will need to be updated.
TEST_P(ParkableStringTest, CheckCompressedSize) {
  const size_t kCompressedSize = GetExpectedCompressedSize();

  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  RunPostedTasks();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  EXPECT_EQ(kCompressedSize, parkable.Impl()->compressed_size());
}

TEST_P(ParkableStringTest, DontCompressRandomString) {
  base::HistogramTester histogram_tester;
  // Make a large random string. Large to make sure it's parkable, and random to
  // ensure its compressed size is larger than the initial size (at least from
  // gzip's header). Mersenne-Twister implementation is specified, making the
  // test deterministic.
  Vector<unsigned char> data(kSizeKb * 1000);
  base::RandBytes(data);
  ParkableString parkable(String(base::span(data)).ReleaseImpl());

  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  RunPostedTasks();
  // Not parked because the temporary buffer wasn't large enough.
  EXPECT_FALSE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, ParkUnparkIdenticalContent) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  RunPostedTasks();
  EXPECT_TRUE(parkable.Impl()->is_parked());

  EXPECT_EQ(MakeLargeString(), parkable.ToString());
}

TEST_P(ParkableStringTest, DecompressUtf16String) {
  UChar emoji_grinning_face[2] = {0xd83d, 0xde00};
  size_t size_in_chars = 2 * kSizeKb * 1000 / sizeof(UChar);

  Vector<UChar> data(size_in_chars);
  for (size_t i = 0; i < size_in_chars / 2; ++i) {
    data[i * 2] = emoji_grinning_face[0];
    data[i * 2 + 1] = emoji_grinning_face[1];
  }

  String large_string = String(data);
  String copy = String(large_string.Impl()->IsolatedCopy());
  ParkableString parkable(large_string.ReleaseImpl());
  large_string = String();
  EXPECT_FALSE(parkable.Is8Bit());
  EXPECT_EQ(size_in_chars, parkable.length());
  EXPECT_EQ(sizeof(UChar) * size_in_chars, parkable.CharactersSizeInBytes());

  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  EXPECT_TRUE(parkable.Impl()->background_task_in_progress_for_testing());
  RunPostedTasks();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  EXPECT_FALSE(parkable.Impl()->background_task_in_progress_for_testing());

  // Decompression checks that the size is correct.
  String unparked = parkable.ToString();
  EXPECT_FALSE(unparked.Is8Bit());
  EXPECT_EQ(size_in_chars, unparked.length());
  EXPECT_EQ(sizeof(UChar) * size_in_chars, unparked.CharactersSizeInBytes());
  EXPECT_EQ(copy, unparked);
}

TEST_P(ParkableStringTest, Simple) {
  ParkableString parkable_abc(String("abc").ReleaseImpl());

  EXPECT_TRUE(ParkableString().IsNull());
  EXPECT_FALSE(parkable_abc.IsNull());
  EXPECT_TRUE(parkable_abc.Is8Bit());
  EXPECT_EQ(3u, parkable_abc.length());
  EXPECT_EQ(3u, parkable_abc.CharactersSizeInBytes());
  EXPECT_FALSE(
      parkable_abc.may_be_parked());  // Small strings are not parkable.

  EXPECT_EQ(String("abc"), parkable_abc.ToString());
  ParkableString copy = parkable_abc;
  EXPECT_EQ(copy.Impl(), parkable_abc.Impl());
}

TEST_P(ParkableStringTest, Park) {
  {
    ParkableString parkable_a(MakeLargeString('a').ReleaseImpl());
    EXPECT_TRUE(parkable_a.may_be_parked());
    EXPECT_FALSE(parkable_a.Impl()->is_parked());
    EXPECT_TRUE(ParkAndWait(parkable_a));
    EXPECT_TRUE(parkable_a.Impl()->is_parked());
  }

  String large_string = MakeLargeString('b');
  ParkableString parkable_b(large_string.Impl());
  EXPECT_TRUE(parkable_b.may_be_parked());
  // Not the only one to have a reference to the string.
  EXPECT_FALSE(ParkAndWait(parkable_b));
  large_string = String();
  EXPECT_TRUE(ParkAndWait(parkable_b));

  {
    ParkableString parkable_c(MakeLargeString('c').ReleaseImpl());
    EXPECT_TRUE(parkable_c.may_be_parked());
    EXPECT_FALSE(parkable_c.Impl()->is_parked());
    EXPECT_TRUE(
        parkable_c.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    // Should not crash, it is allowed to call |Park()| twice in a row.
    EXPECT_TRUE(
        parkable_c.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    parkable_c = ParkableString();  // Release the reference.
    RunPostedTasks();               // Should not crash.
  }
}

TEST_P(ParkableStringTest, EqualityNoUnparking) {
  String large_string = MakeLargeString();
  String copy = String(large_string.Impl()->IsolatedCopy());
  EXPECT_NE(large_string.Impl(), copy.Impl());

  ParkableString parkable(large_string.Impl());
  large_string = String();

  EXPECT_TRUE(parkable.may_be_parked());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  EXPECT_TRUE(ParkAndWait(parkable));
  EXPECT_TRUE(parkable.Impl()->is_parked());

  ParkableString parkable_copy(copy.Impl());
  EXPECT_EQ(parkable_copy.Impl(), parkable.Impl());  // De-duplicated.
  EXPECT_TRUE(parkable.Impl()->is_parked());
  EXPECT_TRUE(parkable_copy.Impl()->is_parked());

  EXPECT_EQ(1u, ParkableStringManager::Instance().Size());
}

TEST_P(ParkableStringTest, AbortParking) {
  {
    ParkableString parkable(MakeLargeString().ReleaseImpl());
    EXPECT_TRUE(parkable.may_be_parked());
    EXPECT_FALSE(parkable.Impl()->is_parked());

    // The string is locked at the end of parking, should cancel it.
    EXPECT_TRUE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    parkable.Impl()->Lock();
    RunPostedTasks();
    EXPECT_FALSE(parkable.Impl()->is_parked());

    // Unlock, OK to park.
    parkable.Impl()->Unlock();
    EXPECT_TRUE(ParkAndWait(parkable));
  }

  {
    ParkableString parkable(MakeLargeString().ReleaseImpl());
    // |ToString()| cancels parking as |content| is kept alive.
    EXPECT_TRUE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    {
      String content = parkable.Impl()->ToString();
      RunPostedTasks();
      EXPECT_FALSE(parkable.Impl()->is_parked());
    }
    EXPECT_TRUE(ParkAndWait(parkable));
  }

  {
    ParkableString parkable(MakeLargeString().ReleaseImpl());
    // Transient |Lock()| or |ToString()| cancel parking.
    EXPECT_TRUE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    parkable.Impl()->Lock();
    parkable.Impl()->ToString();
    parkable.Impl()->Unlock();
    RunPostedTasks();
    EXPECT_FALSE(parkable.Impl()->is_parked());

    // In order to test synchronous parking below, need to park the string
    // first.
    EXPECT_TRUE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    RunPostedTasks();
    EXPECT_TRUE(parkable.Impl()->is_parked());
    parkable.ToString();

    // Synchronous parking respects locking and external references.
    parkable.ToString();
    EXPECT_TRUE(parkable.Impl()->has_compressed_data());
    parkable.Lock();
    EXPECT_FALSE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    parkable.Unlock();
    {
      String content = parkable.ToString();
      EXPECT_FALSE(
          parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    }
    // Parking is synchronous.
    EXPECT_TRUE(
        parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
    EXPECT_TRUE(parkable.Impl()->is_parked());
  }
}

TEST_P(ParkableStringTest, AbortedParkingRetainsCompressedData) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(parkable.may_be_parked());
  EXPECT_FALSE(parkable.Impl()->is_parked());

  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  parkable.ToString();  // Cancels parking.
  RunPostedTasks();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  // Compressed data is not discarded.
  EXPECT_TRUE(parkable.Impl()->has_compressed_data());

  // Synchronous parking.
  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  EXPECT_TRUE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, Unpark) {
  ParkableString parkable(MakeLargeString().Impl());
  String unparked_copy = String(parkable.ToString().Impl()->IsolatedCopy());
  EXPECT_TRUE(parkable.may_be_parked());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  EXPECT_TRUE(ParkAndWait(parkable));
  EXPECT_TRUE(parkable.Impl()->is_parked());

  String unparked = parkable.ToString();
  EXPECT_EQ(unparked_copy, unparked);
  EXPECT_FALSE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, BackgroundUnparkFromMemory) {
  // Memory parked strings can be unparked on a background thread.
  ParkableString parkable(MakeLargeString().Impl());
  String unparked_copy = String(parkable.ToString().Impl()->IsolatedCopy());
  EXPECT_TRUE(ParkAndWait(parkable));
  ParkableStringImpl* impl = parkable.Impl();
  // Check that the string was added to the correct StringMap.
  auto& manager = ParkableStringManager::Instance();
  EXPECT_TRUE(manager.IsOnParkedMapForTesting(impl));

  // Post unparking task to a background thread.
  base::ThreadPool::PostTask(FROM_HERE, base::BindOnce(
                                            [](ParkableStringImpl* string) {
                                              EXPECT_FALSE(IsMainThread());
                                              string->ToString();
                                            },
                                            base::RetainedRef(impl)));

  // Wait until the background unpark task is completed.
  while (true) {
    if (!impl->is_parked()) {
      break;
    }
  }

  // The move task is already posted, calling `ToString` in the Main thread
  // doesn't move the entry to the unparked string map.
  EXPECT_TRUE(manager.IsOnParkedMapForTesting(impl));
  EXPECT_EQ(parkable.ToString(), unparked_copy);
  EXPECT_TRUE(manager.IsOnParkedMapForTesting(impl));

  // Run the pending move task.
  RunPostedTasks();
  EXPECT_FALSE(manager.IsOnParkedMapForTesting(impl));
}

TEST_P(ParkableStringTest, BackgroundUnparkFromDisk) {
  // On disk strings can be unparked on a background thread.
  ParkableString parkable(MakeLargeString().Impl());
  String unparked_copy = String(parkable.ToString().Impl()->IsolatedCopy());
  EXPECT_TRUE(ParkAndWait(parkable));
  ParkableStringImpl* impl = parkable.Impl();

  WaitForDiskWriting();
  EXPECT_TRUE(impl->is_on_disk());

  // Check that the string was added to the correct StringMap.
  auto& manager = ParkableStringManager::Instance();
  EXPECT_TRUE(manager.IsOnDiskMapForTesting(impl));

  // Post unparking task to a background thread.
  base::ThreadPool::PostTask(FROM_HERE, base::BindOnce(
                                            [](ParkableStringImpl* string) {
                                              EXPECT_FALSE(IsMainThread());
                                              string->ToString();
                                            },
                                            base::RetainedRef(impl)));

  // Wait until the background unpark task is completed.
  while (true) {
    if (!impl->is_on_disk()) {
      break;
    }
  }

  // The move task is already posted, calling `ToString` in the Main thread
  // doesn't move the entry to the on_disk string map.
  EXPECT_TRUE(manager.IsOnDiskMapForTesting(impl));
  EXPECT_EQ(parkable.ToString(), unparked_copy);
  EXPECT_TRUE(manager.IsOnDiskMapForTesting(impl));

  // Run the pending move task.
  RunPostedTasks();
  EXPECT_FALSE(manager.IsOnDiskMapForTesting(impl));
}

struct ParkableStringWrapper {
  explicit ParkableStringWrapper(scoped_refptr<StringImpl> impl)
      : string(ParkableString(std::move(impl))) {}
  ParkableString string;
};

TEST_P(ParkableStringTest, BackgroundDestruct) {
  // Wrap a ParkableString in a unique_ptr to ensure that it is owned and
  // destroyed on a background thread.
  auto parkable =
      std::make_unique<ParkableStringWrapper>(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(parkable->string.Impl()->HasOneRef());
  base::ThreadPool::PostTask(
      FROM_HERE, base::BindOnce(
                     [](std::unique_ptr<ParkableStringWrapper> parkable) {
                       EXPECT_FALSE(IsMainThread());
                       EXPECT_TRUE(parkable->string.Impl()->HasOneRef());
                     },
                     std::move(parkable)));
  RunPostedTasks();
  CHECK_EQ(0u, ParkableStringManager::Instance().Size());
}

TEST_P(ParkableStringTest, LockUnlock) {
  ParkableString parkable(MakeLargeString().Impl());
  ParkableStringImpl* impl = parkable.Impl();
  EXPECT_EQ(0, impl->lock_depth_for_testing());

  parkable.Lock();
  EXPECT_EQ(1, impl->lock_depth_for_testing());
  parkable.Lock();
  parkable.Unlock();
  EXPECT_EQ(1, impl->lock_depth_for_testing());
  parkable.Unlock();
  EXPECT_EQ(0, impl->lock_depth_for_testing());

  parkable.Lock();
  EXPECT_FALSE(ParkAndWait(parkable));
  parkable.Unlock();
  EXPECT_TRUE(ParkAndWait(parkable));

  parkable.ToString();

  LambdaThreadDelegate delegate(
      base::BindLambdaForTesting([&]() { parkable.Lock(); }));
  base::PlatformThreadHandle thread_handle;
  base::PlatformThread::Create(0, &delegate, &thread_handle);
  base::PlatformThread::Join(thread_handle);

  EXPECT_FALSE(ParkAndWait(parkable));
  parkable.Unlock();
  EXPECT_TRUE(ParkAndWait(parkable));
}

TEST_P(ParkableStringTest, LockParkedString) {
  ParkableString parkable = CreateAndParkAll();
  ParkableStringImpl* impl = parkable.Impl();

  parkable.Lock();  // Locking doesn't unpark.
  EXPECT_TRUE(impl->is_parked());
  parkable.ToString();
  EXPECT_FALSE(impl->is_parked());
  EXPECT_EQ(1, impl->lock_depth_for_testing());

  EXPECT_FALSE(ParkAndWait(parkable));

  parkable.Unlock();
  EXPECT_EQ(0, impl->lock_depth_for_testing());
  EXPECT_TRUE(ParkAndWait(parkable));
  EXPECT_TRUE(impl->is_parked());
}

TEST_P(ParkableStringTest, DelayFirstParkingOfString) {
  base::test::ScopedFeatureList features;

  auto& manager = ParkableStringManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  // Create a large string that will end up parked.
  ParkableString parkable(MakeLargeString().Impl());
  ASSERT_FALSE(parkable.Impl()->is_parked());
  EXPECT_EQ(1u, manager.Size());
  // Should age after this point.
  task_environment_.FastForwardBy(ParkableStringManager::kFirstParkingDelay);

  // String is aged but not parked.
  EXPECT_FALSE(parkable.Impl()->is_parked());

  // Now that the first aging took place the next aging task will take place
  // after the normal interval.
  task_environment_.FastForwardBy(ParkableStringManager::AgingInterval());

  EXPECT_TRUE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, ManagerSimple) {
  auto& manager = ParkableStringManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  // Small strings are not tracked.
  ParkableString small(String("abc").ReleaseImpl());
  EXPECT_EQ(0u, manager.Size());

  // Large ones are.
  ParkableString parkable(MakeLargeString().Impl());
  ASSERT_FALSE(parkable.Impl()->is_parked());
  EXPECT_EQ(1u, manager.Size());

  WaitForDelayedParking();
  EXPECT_TRUE(parkable.Impl()->is_parked());

  // Park and unpark.
  parkable.ToString();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  WaitForDelayedParking();
  EXPECT_TRUE(parkable.Impl()->is_parked());

  // More than one reference, no parking.
  String alive_unparked = parkable.ToString();
  WaitForDelayedParking();
  EXPECT_FALSE(parkable.Impl()->is_parked());

  // Since no strings are parkable, the tick stopped.
  CheckOnlyCpuCostTaskRemains();

  // Other reference is dropped, OK to park.
  alive_unparked = String();

  // Tick was not scheduled, no parking.
  WaitForDelayedParking();
  EXPECT_FALSE(parkable.Impl()->is_parked());

  // Create a temporary string to start the tick again.
  { ParkableString tmp(MakeLargeString('b').ReleaseImpl()); }
  WaitForDelayedParking();
  EXPECT_TRUE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, ManagerMultipleStrings) {
  auto& manager = ParkableStringManager::Instance();
  EXPECT_EQ(0u, manager.Size());

  ParkableString parkable(MakeLargeString('a').Impl());
  ParkableString parkable2(MakeLargeString('b').Impl());
  EXPECT_EQ(2u, manager.Size());

  parkable2 = ParkableString();
  EXPECT_EQ(1u, manager.Size());

  ParkableString copy = parkable;
  parkable = ParkableString();
  EXPECT_EQ(1u, manager.Size());
  copy = ParkableString();
  EXPECT_EQ(0u, manager.Size());

  String str = MakeLargeString('c');
  ParkableString parkable3(str.Impl());
  EXPECT_EQ(1u, manager.Size());
  // De-duplicated with the same underlying StringImpl.
  ParkableString other_parkable3(str.Impl());
  EXPECT_EQ(1u, manager.Size());
  EXPECT_EQ(parkable3.Impl(), other_parkable3.Impl());

  {
    // De-duplicated with a different StringImpl but the same content.
    ParkableString other_parkable3_different_string(
        MakeLargeString('c').ReleaseImpl());
    EXPECT_EQ(1u, manager.Size());
    EXPECT_EQ(parkable3.Impl(), other_parkable3_different_string.Impl());
  }

  // If all the references to a string are internal, park it.
  str = String();
  // This string is not parkable, but should still be tracked.
  ParkableString parkable4(MakeLargeString('d').Impl());
  String parkable4_content = parkable4.ToString();

  // Only drop it from the managed strings when the last one is gone.
  parkable3 = ParkableString();
  EXPECT_EQ(2u, manager.Size());
  other_parkable3 = ParkableString();
  EXPECT_EQ(1u, manager.Size());
  parkable4 = ParkableString();
  EXPECT_EQ(0u, manager.Size());
}

TEST_P(ParkableStringTest, ShouldPark) {
  String empty_string("");
  EXPECT_FALSE(ParkableStringManager::ShouldPark(*empty_string.Impl()));
  String parkable(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(ParkableStringManager::ShouldPark(*parkable.Impl()));

  LambdaThreadDelegate delegate(base::BindLambdaForTesting([]() {
    String parkable(MakeLargeString().ReleaseImpl());
    EXPECT_FALSE(ParkableStringManager::ShouldPark(*parkable.Impl()));
  }));
  base::PlatformThreadHandle thread_handle;
  base::PlatformThread::Create(0, &delegate, &thread_handle);
  base::PlatformThread::Join(thread_handle);
}

#if defined(ADDRESS_SANITIZER)
#define EXPECT_ASAN_DEATH(statement, regex) EXPECT_DEATH(statement, regex)
#else
#define EXPECT_ASAN_DEATH(statement, regex) \
  GTEST_UNSUPPORTED_DEATH_TEST(statement, regex, )
#endif

TEST_P(ParkableStringTest, AsanPoisoningTest) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  const LChar* data = parkable.ToString().Characters8();
  EXPECT_TRUE(ParkAndWait(parkable));
  EXPECT_ASAN_DEATH(EXPECT_NE(0, data[10]), "");
}

// Non-regression test for crbug.com/905137.
TEST_P(ParkableStringTest, CorrectAsanPoisoning) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_TRUE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
  // A main thread task is posted once compression is done.
  while (task_environment_.GetPendingMainThreadTaskCount() == 0) {
    parkable.Lock();
    parkable.ToString();
    parkable.Unlock();
  }
  RunPostedTasks();
}

TEST_P(ParkableStringTest, Compression) {
  const size_t kCompressedSize = GetExpectedCompressedSize();

  base::HistogramTester histogram_tester;

  ParkableString parkable = CreateAndParkAll();
  ParkableStringImpl* impl = parkable.Impl();

  EXPECT_TRUE(impl->is_parked());
  EXPECT_TRUE(impl->has_compressed_data());
  EXPECT_EQ(kCompressedSize, impl->compressed_size());
  parkable.ToString();  // First decompression.
  EXPECT_FALSE(impl->is_parked());
  EXPECT_TRUE(impl->has_compressed_data());
  EXPECT_TRUE(impl->Park(ParkableStringImpl::ParkingMode::kSynchronousOnly));
  EXPECT_TRUE(impl->is_parked());
  parkable.ToString();  // Second decompression.

  histogram_tester.ExpectUniqueSample(
      "Memory.ParkableString.Compression.SizeKb", kSizeKb, 1);
  histogram_tester.ExpectTotalCount("Memory.ParkableString.Compression.Latency",
                                    1);
  histogram_tester.ExpectTotalCount(
      "Memory.ParkableString.Decompression.Latency", 2);
  histogram_tester.ExpectTotalCount(
      "Memory.ParkableString.Decompression.ThroughputMBps", 2);
}

TEST_P(ParkableStringTest, SynchronousCompression) {
  ParkableStringManager& manager = ParkableStringManager::Instance();
  ParkableString parkable = CreateAndParkAll();

  parkable.ToString();
  EXPECT_TRUE(parkable.Impl()->has_compressed_data());
  // No waiting, synchronous compression.
  manager.ParkAll(ParkableStringImpl::ParkingMode::kSynchronousOnly);
  EXPECT_TRUE(parkable.Impl()->is_parked());
  task_environment_.FastForwardUntilNoTasksRemain();
}

TEST_P(ParkableStringTest, CompressionFailed) {
  const size_t kSize = 20000;
  Vector<char> data(kSize);
  base::RandBytes(base::as_writable_byte_span(data));
  ParkableString parkable(String(data).ReleaseImpl());
  WaitForDelayedParking();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());

  // Because input string is too complicated, parking has failed.
  EXPECT_FALSE(parkable.Impl()->is_parked());

  // Make sure there will be no additional parking trial for this string.
  EXPECT_EQ(ParkableStringImpl::AgeOrParkResult::kNonTransientFailure,
            parkable.Impl()->MaybeAgeOrParkString());

  // |Park()| should be failed as well.
  EXPECT_FALSE(
      parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress));
}

TEST_P(ParkableStringTest, ToAndFromDisk) {
  base::HistogramTester histogram_tester;

  ParkableString parkable(MakeLargeString('a').ReleaseImpl());
  ParkableStringImpl* impl = parkable.Impl();

  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  parkable.Impl()->MaybeAgeOrParkString();
  EXPECT_EQ(ParkableStringImpl::Age::kVeryOld, impl->age_for_testing());
  impl->MaybeAgeOrParkString();
  EXPECT_FALSE(impl->is_on_disk());
  RunPostedTasks();
  EXPECT_TRUE(impl->is_on_disk());
  parkable.ToString();
  EXPECT_FALSE(impl->is_on_disk());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());

  histogram_tester.ExpectTotalCount("Memory.ParkableString.Read.Latency", 1);
}

TEST_P(ParkableStringTest, UnparkWhileWritingToDisk) {
  base::HistogramTester histogram_tester;

  ParkableString parkable(MakeLargeString('a').ReleaseImpl());
  ParkableStringImpl* impl = parkable.Impl();

  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  parkable.Impl()->MaybeAgeOrParkString();
  EXPECT_EQ(ParkableStringImpl::Age::kVeryOld, impl->age_for_testing());
  impl->MaybeAgeOrParkString();
  EXPECT_FALSE(impl->is_on_disk());
  EXPECT_TRUE(impl->background_task_in_progress_for_testing());

  // Unparking cancels discarding to disk.
  EXPECT_FALSE(parkable.ToString().IsNull());
  EXPECT_TRUE(impl->background_task_in_progress_for_testing());
  RunPostedTasks();
  EXPECT_FALSE(impl->is_on_disk());
  EXPECT_TRUE(impl->has_on_disk_data());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
}

TEST_P(ParkableStringTest, NoCompetingWritingToDisk) {
  ParkableString parkable(MakeLargeString('a').ReleaseImpl());
  ParkableStringImpl* impl = parkable.Impl();

  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
  parkable.Impl()->MaybeAgeOrParkString();
  EXPECT_EQ(ParkableStringImpl::Age::kVeryOld, impl->age_for_testing());
  impl->MaybeAgeOrParkString();
  EXPECT_FALSE(impl->is_on_disk());

  // Unparking cancels discarding to disk.
  EXPECT_FALSE(parkable.ToString().IsNull());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
  // Until the writing is finished, the string cannot age again.
  impl->MaybeAgeOrParkString();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());

  RunPostedTasks();
  EXPECT_FALSE(impl->is_on_disk());
  EXPECT_TRUE(impl->has_on_disk_data());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung, impl->age_for_testing());
  // Aging is now possible again.
  impl->MaybeAgeOrParkString();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
}

TEST_P(ParkableStringTest, SynchronousToDisk) {
  base::HistogramTester histogram_tester;

  ParkableString parkable(MakeLargeString('a').ReleaseImpl());
  ParkableStringImpl* impl = parkable.Impl();

  WaitForDelayedParking();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, impl->age_for_testing());
```