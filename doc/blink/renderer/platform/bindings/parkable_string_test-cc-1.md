Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the `ParkableString` class in the Chromium Blink engine. I need to identify the main purpose of the tests and any relationships to web technologies like JavaScript, HTML, and CSS. I also need to look for examples of logical reasoning, potential user/programming errors, and finally, provide a concise overall summary.

Here's a breakdown of the code's functionality based on the test names:

- **`WaitForAgingAndParking`**: Checks the aging and parking mechanisms of `ParkableString`.
- **`MaybeAgeOrParkString`**: Tests the conditions under which a string is aged and potentially parked, including writing to disk.
- **`OnPurgeMemory`**:  Verifies the behavior of `ParkableString` when the system is under memory pressure, including synchronous parking and purging of compressed data.
- **`ReportMemoryDump`**:  Ensures that memory usage related to `ParkableString` (original size, compressed size, metadata, savings, on-disk size) is correctly reported in memory dumps for tracing.
- **`MemoryFootprintForDump`**: Calculates and verifies the memory footprint of `ParkableString` in different states (compressed, uncompressed, short string).
- **`CompressionDisabled`**: Checks the behavior when the compression feature for `ParkableString` is disabled.
- **`CompressionDisabledDisablesDisk`**: Confirms that disabling compression also disables writing to disk.
- **`Aging`**: Tests the aging mechanism of `ParkableString`, including how locking and external references affect it.
- **`NoPrematureAging`**:  Ensures that aging doesn't happen before the expected time.
- **`OldStringsAreParked`**: Verifies that strings are parked after aging.
- **`AgingTicksStopsAndRestarts`**: Checks if the aging mechanism's timer stops and restarts correctly under various conditions.
- **`AgingTicksStopsWithNoProgress`**: Ensures the aging timer stops when there are no strings that can be aged.
- **`OnlyOneAgingTask`**:  Confirms that only one aging task is scheduled at a time.
- **`ReportTotalUnparkingTime`**:  Tests the reporting of the total time spent unparking strings.
- **`ReportTotalDiskTime`**: Tests the reporting of disk read and write times related to parked strings.
- **`EncodingAndDeduplication`**: Verifies that strings with different encodings but the same content are treated distinctly by the parking mechanism.
- **`AgingParkingInProgress` (with `QueuedThreadPool`)**: Tests the interaction between the aging process and asynchronous parking when using a queued thread pool.
- **`ParkWithLimitedDiskCapacity` (with limited disk capacity)`**: Tests the behavior when the disk capacity for parked strings is limited.
- **`NoParkingInForeground` (with less aggressive mode)`**: Checks that parking is suppressed when the renderer is in the foreground.
- **`NoParkingWhileLoading` (with less aggressive mode)`**: Checks that parking is suppressed while the page is loading.
- **`NoParkingWhileLoadingOrInForeground` (with less aggressive mode)`**: Combines the foreground and loading scenarios for parking suppression.

Based on this analysis, the file primarily tests the core functionalities of the `ParkableString` class, focusing on memory management, compression, disk persistence, and controlled aging/parking of string data.
这是对名为 `blink/renderer/platform/bindings/parkable_string_test.cc` 的 Chromium Blink 引擎源代码文件的功能总结的第二部分。结合第一部分的分析，我们可以归纳出以下功能：

**总体功能：**

该测试文件 (`parkable_string_test.cc`) 主要用于测试 `ParkableString` 类的各项功能，这是一个用于优化内存使用的类，尤其是在处理大量字符串数据时。它通过延迟或异步地将不常使用的字符串数据“停放”（park）到压缩状态或磁盘上，从而减少内存占用。

**测试的核心功能点包括：**

* **老化 (Aging):** 测试 `ParkableString` 对象如何根据其使用时长进行老化，并最终进入停放状态。测试了锁定状态、外部引用等因素对老化过程的影响。
* **停放 (Parking):** 测试 `ParkableString` 对象被停放到压缩状态或磁盘的机制，包括延迟停放和同步停放。
* **内存压力 (Memory Pressure):**  测试在内存压力下 `ParkableString` 的行为，例如同步停放和清理压缩数据。
* **磁盘持久化 (Disk Persistence):** 测试 `ParkableString` 如何将数据写入磁盘以及从磁盘恢复数据，包括异步和同步写入。同时也测试了磁盘容量限制下的行为。
* **内存报告 (Memory Reporting):** 测试 `ParkableString` 如何在内存 dump 中报告其内存使用情况，包括原始大小、压缩大小、元数据大小、节省的空间以及磁盘占用情况。
* **压缩 (Compression):** 测试压缩功能是否启用以及禁用时的行为，包括禁用压缩对磁盘持久化的影响。
* **性能指标报告 (Performance Metrics Reporting):** 测试报告停放和解停操作所花费的时间，以及磁盘读写时间。
* **编码和去重 (Encoding and Deduplication):** 测试具有不同编码但内容相同的字符串如何被 `ParkableString` 处理（虽然内容相同，但由于编码不同，其内部表示也会不同）。
* **与任务调度器的交互 (Interaction with Task Scheduler):** 测试老化和停放任务如何在主线程上调度和执行，以及在没有可停放字符串时如何停止调度。
* **在不同线程池下的行为 (Behavior with Different Thread Pools):** 测试在使用队列线程池时，老化和停放过程的交互。
* **在受限磁盘容量下的行为 (Behavior with Limited Disk Capacity):** 测试在磁盘容量有限的情况下，`ParkableString` 如何管理磁盘上的数据。
* **在不同运行模式下的行为 (Behavior in Different Running Modes):** 测试在前景、后台以及页面加载等不同 RAIL 模式下，`ParkableString` 的停放行为是否符合预期（例如，在前景或加载时抑制停放）。

**与 JavaScript, HTML, CSS 的关系：**

`ParkableString` 本身是一个底层的 C++ 类，直接与 JavaScript、HTML 或 CSS 功能没有直接的语法层面的关系。但是，它在 Blink 引擎中用于优化这些技术的底层实现，从而间接地影响它们的性能。

* **JavaScript 中的字符串:** JavaScript 中大量的字符串操作可能会导致内存占用增加。`ParkableString` 可以用于存储 JavaScript 引擎内部的某些字符串数据，例如编译后的代码、字符串字面量等，并通过停放不常用的字符串来减少内存压力，从而提升 JavaScript 引擎的性能。
* **HTML 和 CSS 中的文本内容:** HTML 结构和 CSS 样式中包含大量的文本信息。Blink 引擎可能会使用类似 `ParkableString` 的机制来管理这些文本数据，尤其是在处理大型网页时，通过停放不常访问的文本内容来优化内存使用。

**逻辑推理与假设输入输出：**

例如，在 `TEST_P(ParkableStringTest, MaybeAgeOrParkString)` 中，我们可以进行逻辑推理：

* **假设输入：** 一个新创建的 `ParkableString` 对象 `parkable`，其内部实现 `impl` 的初始状态为未停放，年龄为 `kYoung`。
* **操作序列：**
    1. `WaitForAging()`:  假设等待足够的时间让字符串老化到 `kVeryOld`。
    2. `impl->MaybeAgeOrParkString()`:  尝试停放字符串。由于是异步写入，此时 `is_on_disk()` 返回 `false`。
    3. `WaitForAging()`: 等待异步写入完成。
    4. `parkable.ToString()`: 解停字符串。
    5. 多次调用 `impl->MaybeAgeOrParkString()`: 模拟多次尝试停放。
    6. 最后一次 `impl->MaybeAgeOrParkString()`:  假设这次是同步写入。
    7. `parkable.ToString()`: 再次解停。
* **预期输出：**  在不同的阶段，`impl->age_for_testing()` 和 `impl->is_on_disk()` 的返回值会根据老化和停放的状态变化。例如，在第一次 `WaitForAging()` 后，`age_for_testing()` 应该为 `kVeryOld`。在第二次 `WaitForAging()` 后，`is_on_disk()` 应该为 `true`。在调用 `ToString()` 后，`is_on_disk()` 应该为 `false`。

**用户或编程常见的使用错误：**

虽然 `ParkableString` 是引擎内部的实现，用户无法直接操作它，但其设计可以避免一些潜在的编程错误，例如：

* **过度缓存大型字符串导致内存溢出:** `ParkableString` 通过自动停放不常用的字符串来缓解这个问题，即使开发者无意中缓存了大量字符串。
* **频繁创建和销毁大型字符串带来的性能损耗:** `ParkableString` 的停放和解停机制可以减少内存分配和释放的频率，从而提高性能。

**对第二部分代码功能的归纳：**

第二部分的测试代码继续深入测试了 `ParkableString` 的核心功能，尤其关注了：

* **更细致的停放和老化流程控制:** 例如，`MaybeAgeOrParkString` 测试了在不同阶段尝试停放的行为，包括异步和同步的情况。
* **内存管理和报告的完整性:** `ReportMemoryDump` 详细验证了各种内存指标的正确性。
* **在特定场景下的行为:** 例如，内存压力下的清理 (`OnPurgeMemory`)，以及磁盘容量限制下的管理。
* **与系统状态的交互:** 例如，在前景/后台和加载状态下停放行为的调整。
* **性能指标的度量:** 例如，停放和解停的时间开销。

总而言之，第二部分的代码继续完善对 `ParkableString` 各种功能的测试，确保其在各种场景下都能正常工作，并达到预期的内存优化效果。这些测试覆盖了其核心的内存管理、持久化、性能以及与系统状态交互的关键方面。

Prompt: 
```
这是目录为blink/renderer/platform/bindings/parkable_string_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kVeryOld, impl->age_for_testing());
  EXPECT_FALSE(impl->is_on_disk());

  // Writing to disk is asynchronous.
  impl->MaybeAgeOrParkString();
  EXPECT_FALSE(impl->is_on_disk());
  WaitForAging();
  EXPECT_TRUE(impl->is_on_disk());

  parkable.ToString();
  EXPECT_FALSE(impl->is_on_disk());

  impl->MaybeAgeOrParkString();
  impl->MaybeAgeOrParkString();
  impl->MaybeAgeOrParkString();

  EXPECT_FALSE(impl->is_on_disk());
  impl->MaybeAgeOrParkString();
  EXPECT_TRUE(impl->is_on_disk());  // Synchronous writing.

  parkable.ToString();
}

TEST_P(ParkableStringTest, OnPurgeMemory) {
  ParkableString parkable1 = CreateAndParkAll();
  ParkableString parkable2(MakeLargeString('b').ReleaseImpl());

  // Park everything.
  WaitForDelayedParking();
  EXPECT_TRUE(parkable1.Impl()->is_on_disk());
  EXPECT_TRUE(parkable2.Impl()->is_parked());

  // Different usage patterns:
  // 1. Parkable, will be parked synchronouly.
  // 2. Cannot be parked, compressed representation is purged.
  parkable1.ToString();
  String retained = parkable2.ToString();
  EXPECT_TRUE(parkable2.Impl()->has_compressed_data());

  MemoryPressureListenerRegistry::Instance().OnPurgeMemory();
  EXPECT_TRUE(parkable1.Impl()->is_parked());  // Parked synchronously.
  EXPECT_FALSE(parkable2.Impl()->is_parked());

  parkable1.ToString();
  EXPECT_TRUE(parkable1.Impl()->has_compressed_data());
}

TEST_P(ParkableStringTest, ReportMemoryDump) {
  const size_t kCompressedSize = GetExpectedCompressedSize();

  using base::trace_event::MemoryAllocatorDump;
  using testing::ByRef;
  using testing::Contains;
  using testing::Eq;

  constexpr size_t kActualSize =
      sizeof(ParkableStringImpl) + sizeof(ParkableStringImpl::ParkableMetadata);

  auto& manager = ParkableStringManager::Instance();
  ParkableString parkable1(MakeLargeString('a').ReleaseImpl());
  ParkableString parkable2(MakeLargeString('b').ReleaseImpl());
  // Not reported in stats below.
  ParkableString parkable3(String("short string, not parkable").ReleaseImpl());

  WaitForDelayedParking();
  parkable1.ToString();

  base::trace_event::MemoryDumpArgs args = {
      base::trace_event::MemoryDumpLevelOfDetail::kDetailed};
  base::trace_event::ProcessMemoryDump pmd(args);
  manager.OnMemoryDump(&pmd);
  base::trace_event::MemoryAllocatorDump* dump =
      pmd.GetAllocatorDump("parkable_strings");
  ASSERT_NE(nullptr, dump);

  constexpr size_t kStringSize = kSizeKb * 1000;
  MemoryAllocatorDump::Entry original("original_size", "bytes",
                                      2 * kStringSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(original))));

  // |parkable1| is unparked.
  MemoryAllocatorDump::Entry uncompressed("uncompressed_size", "bytes",
                                          kStringSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(uncompressed))));

  MemoryAllocatorDump::Entry compressed("compressed_size", "bytes",
                                        kCompressedSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(compressed))));

  // |parkable1| compressed data is overhead.
  MemoryAllocatorDump::Entry overhead("overhead_size", "bytes",
                                      kCompressedSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(overhead))));

  MemoryAllocatorDump::Entry metadata("metadata_size", "bytes",
                                      2 * kActualSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(metadata))));

  MemoryAllocatorDump::Entry savings(
      "savings_size", "bytes",
      2 * kStringSize - (kStringSize + 2 * kCompressedSize + 2 * kActualSize));
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(savings))));

  MemoryAllocatorDump::Entry on_disk("on_disk_size", "bytes", 0);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(on_disk))));
  MemoryAllocatorDump::Entry on_disk_footprint("on_disk_footprint", "bytes", 0);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(on_disk_footprint))));

  WaitForDiskWriting();
  EXPECT_TRUE(parkable1.Impl()->has_compressed_data());
  EXPECT_TRUE(parkable2.Impl()->is_on_disk());

  pmd = base::trace_event::ProcessMemoryDump(args);
  manager.OnMemoryDump(&pmd);
  dump = pmd.GetAllocatorDump("parkable_strings");
  ASSERT_NE(nullptr, dump);
  on_disk =
      MemoryAllocatorDump::Entry("on_disk_size", "bytes", kCompressedSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(on_disk))));
  // |parkable2| is on disk.
  on_disk_footprint =
      MemoryAllocatorDump::Entry("on_disk_footprint", "bytes", kCompressedSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(on_disk_footprint))));

  MemoryAllocatorDump::Entry on_disk_free_chunks =
      MemoryAllocatorDump::Entry("on_disk_free_chunks", "bytes", 0);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(on_disk_free_chunks))));

  // |parkable1| is compressed.
  compressed =
      MemoryAllocatorDump::Entry("compressed_size", "bytes", kCompressedSize);
  EXPECT_THAT(dump->entries(), Contains(Eq(ByRef(compressed))));
}

TEST_P(ParkableStringTest, MemoryFootprintForDump) {
  constexpr size_t kActualSize =
      sizeof(ParkableStringImpl) + sizeof(ParkableStringImpl::ParkableMetadata);

  size_t memory_footprint;
  ParkableString parkable1(MakeLargeString('a').ReleaseImpl());
  ParkableString parkable2(MakeLargeString('b').ReleaseImpl());
  ParkableString parkable3(String("short string, not parkable").ReleaseImpl());

  WaitForDelayedParking();
  parkable1.ToString();

  // Compressed and uncompressed data.
  memory_footprint = kActualSize + parkable1.Impl()->compressed_size() +
                     parkable1.Impl()->CharactersSizeInBytes();
  EXPECT_EQ(memory_footprint, parkable1.Impl()->MemoryFootprintForDump());

  // Compressed uncompressed data only.
  memory_footprint = kActualSize + parkable2.Impl()->compressed_size();
  EXPECT_EQ(memory_footprint, parkable2.Impl()->MemoryFootprintForDump());

  // Short string, no metadata.
  memory_footprint =
      sizeof(ParkableStringImpl) + parkable3.Impl()->CharactersSizeInBytes();
  EXPECT_EQ(memory_footprint, parkable3.Impl()->MemoryFootprintForDump());
}

TEST_P(ParkableStringTest, CompressionDisabled) {
  base::test::ScopedFeatureList features;
  features.InitAndDisableFeature(features::kCompressParkableStrings);

  ParkableString parkable(MakeLargeString().ReleaseImpl());
  WaitForDelayedParking();
  EXPECT_FALSE(parkable.Impl()->may_be_parked());

  MemoryPressureListenerRegistry::Instance().OnPurgeMemory();
  EXPECT_FALSE(parkable.Impl()->may_be_parked());
}

TEST_P(ParkableStringTest, CompressionDisabledDisablesDisk) {
  base::test::ScopedFeatureList features;
  features.InitAndDisableFeature(features::kCompressParkableStrings);

  EXPECT_FALSE(features::IsParkableStringsToDiskEnabled());
}

TEST_P(ParkableStringTest, Aging) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());

  parkable.Lock();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  // Locked strings don't age.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  parkable.Unlock();
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());

  parkable.ToString();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  // No external reference, can age again.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());

  // External references prevent a string from aging.
  String retained = parkable.ToString();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
}

TEST_P(ParkableStringTest, NoPrematureAging) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());

  task_environment_.FastForwardBy(ParkableStringManager::AgingInterval());

  // Since not enough time elapsed not aging was done.
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
}

TEST_P(ParkableStringTest, OldStringsAreParked) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());
  WaitForAging();
  EXPECT_TRUE(parkable.Impl()->is_parked());

  // Unparked, two aging cycles before parking.
  parkable.ToString();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  WaitForAging();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  WaitForAging();
  EXPECT_TRUE(parkable.Impl()->is_parked());

  // Unparked, two consecutive no-access aging cycles before parking.
  parkable.ToString();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  WaitForAging();
  EXPECT_FALSE(parkable.Impl()->is_parked());
  parkable.ToString();
  WaitForAging();
  EXPECT_FALSE(parkable.Impl()->is_parked());
}

TEST_P(ParkableStringTest, AgingTicksStopsAndRestarts) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForAging();
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForAging();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable.Impl()->is_on_disk());
  WaitForAging();
  // Nothing more to do, the tick is not re-scheduled.
  CheckOnlyCpuCostTaskRemains();

  // Unparking, the tick restarts.
  parkable.ToString();
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForDelayedParking();
  WaitForDiskWriting();
  // And stops again. 2 ticks to park the string (age, then park), and one
  // checking that there is nothing left to do.
  CheckOnlyCpuCostTaskRemains();

  // // New string, restarting the tick, temporarily.
  ParkableString parkable2(MakeLargeString().ReleaseImpl());
  WaitForDelayedParking();
  WaitForDiskWriting();
  WaitForAging();
  CheckOnlyCpuCostTaskRemains();
}

TEST_P(ParkableStringTest, AgingTicksStopsWithNoProgress) {
  ParkableString parkable(MakeLargeString('a').ReleaseImpl());
  String retained = parkable.ToString();

  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForAging();
  // The only string is referenced externally, nothing aging can change.
  CheckOnlyCpuCostTaskRemains();

  ParkableString parkable2(MakeLargeString('b').ReleaseImpl());
  WaitForAging();
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForAging();
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  EXPECT_TRUE(parkable2.Impl()->is_parked());
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  WaitForAging();
  WaitForDiskWriting();
  // Once |parkable2| has been parked, back to the case where the only
  // remaining strings are referenced externally.
  CheckOnlyCpuCostTaskRemains();
}

// Flaky on a few platforms: crbug.com/1168170.
TEST_P(ParkableStringTest, DISABLED_OnlyOneAgingTask) {
  ParkableString parkable1(MakeLargeString('a').ReleaseImpl());
  ParkableString parkable2(MakeLargeString('b').ReleaseImpl());

  // Park both, and wait for the tick to stop.
  WaitForDelayedParking();
  EXPECT_TRUE(parkable1.Impl()->is_parked());
  EXPECT_TRUE(parkable2.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable1.Impl()->is_on_disk());
  EXPECT_TRUE(parkable2.Impl()->is_on_disk());
  WaitForAging();
  CheckOnlyCpuCostTaskRemains();

  parkable1.ToString();
  parkable2.ToString();
  EXPECT_GT(task_environment_.GetPendingMainThreadTaskCount(), 0u);
  // Aging task + stats.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
}

TEST_P(ParkableStringTest, ReportTotalUnparkingTime) {
  base::ScopedMockElapsedTimersForTest mock_elapsed_timers;
  base::HistogramTester histogram_tester;

  // Disable on disk parking to keep data merely compressed, and report
  // compression metrics.
  DisableOnDiskWriting();

  ParkableString parkable(MakeLargeString().ReleaseImpl());
  ParkAndWait(parkable);

  // Iteration count: has to be low enough to end before the CPU cost task runs
  // (after 5 minutes), for both regular and less aggressive modes.
  const int kNumIterations = 4;
  for (int i = 0; i < kNumIterations; ++i) {
    parkable.ToString();
    ASSERT_FALSE(parkable.Impl()->is_parked());
    WaitForDelayedParking();
    ASSERT_TRUE(parkable.Impl()->is_parked());
    WaitForDiskWriting();
    WaitForAging();
    CheckOnlyCpuCostTaskRemains();
  }

  task_environment_.FastForwardUntilNoTasksRemain();
}

TEST_P(ParkableStringTest, ReportTotalDiskTime) {
  const size_t kCompressedSize = GetExpectedCompressedSize();

  base::ScopedMockElapsedTimersForTest mock_elapsed_timers;
  base::HistogramTester histogram_tester;
  ASSERT_TRUE(features::IsParkableStringsToDiskEnabled());

  ParkableString parkable(MakeLargeString().ReleaseImpl());
  ParkAndWait(parkable);

  const int kNumIterations = 4;
  for (int i = 0; i < kNumIterations; ++i) {
    parkable.ToString();
    ASSERT_FALSE(parkable.Impl()->is_parked());
    WaitForDelayedParking();
    ASSERT_TRUE(parkable.Impl()->is_parked());
    WaitForDiskWriting();
    WaitForAging();
    CheckOnlyCpuCostTaskRemains();
  }

  task_environment_.FastForwardUntilNoTasksRemain();
  int64_t mock_elapsed_time_ms =
      base::ScopedMockElapsedTimersForTest::kMockElapsedTime.InMilliseconds();
  // String does not get to disk at the first iteration, hence "-1".
  histogram_tester.ExpectUniqueSample(
      "Memory.ParkableString.DiskReadTime.5min",
      mock_elapsed_time_ms * (kNumIterations - 1), 1);

  // The string is only written once despite the multiple parking/unparking
  // calls.
  histogram_tester.ExpectUniqueSample(
      "Memory.ParkableString.DiskWriteTime.5min", mock_elapsed_time_ms, 1);

  histogram_tester.ExpectUniqueSample("Memory.ParkableString.OnDiskSizeKb.5min",
                                      kCompressedSize / 1000, 1);
  histogram_tester.ExpectUniqueSample(
      "Memory.ParkableString.TotalUnparkingTime.5min",
      mock_elapsed_time_ms * kNumIterations - 1, 1);
  histogram_tester.ExpectUniqueSample(
      "Memory.ParkableString.TotalParkingThreadTime.5min", mock_elapsed_time_ms,
      1);
}

TEST_P(ParkableStringTest, EncodingAndDeduplication) {
  size_t size_in_chars = 2 * kSizeKb * 1000 / sizeof(UChar);
  Vector<UChar> data_16(size_in_chars);
  for (size_t i = 0; i < size_in_chars; ++i) {
    data_16[i] = 0x2020;
  }
  String large_string_16 = String(data_16);

  ParkableString parkable_16(large_string_16.Impl());
  ASSERT_TRUE(parkable_16.Impl()->digest());
  ASSERT_TRUE(parkable_16.may_be_parked());

  Vector<LChar> data_8(2 * size_in_chars);
  for (size_t i = 0; i < 2 * size_in_chars; ++i) {
    data_8[i] = 0x20;
  }
  String large_string_8 = String(base::span(data_8));

  ParkableString parkable_8(large_string_8.Impl());
  ASSERT_TRUE(parkable_8.Impl()->digest());
  ASSERT_TRUE(parkable_8.may_be_parked());

  // Same content, but the hash must be different because the encoding is.
  EXPECT_EQ(large_string_16.RawByteSpan(), large_string_8.RawByteSpan());
  EXPECT_NE(*parkable_16.Impl()->digest(), *parkable_8.Impl()->digest());
}

class ParkableStringTestWithQueuedThreadPool : public ParkableStringTest {
 public:
  ParkableStringTestWithQueuedThreadPool()
      : ParkableStringTest(ThreadPoolExecutionMode::QUEUED) {}
};

INSTANTIATE_TEST_SUITE_P(
    CompressionAlgorithm,
    ParkableStringTestWithQueuedThreadPool,
    ::testing::Values(ParkableStringImpl::CompressionAlgorithm::kZlib,
                      ParkableStringImpl::CompressionAlgorithm::kSnappy
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ,
                      ParkableStringImpl::CompressionAlgorithm::kZstd
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ));

TEST_P(ParkableStringTestWithQueuedThreadPool, AgingParkingInProgress) {
  ParkableString parkable(MakeLargeString().ReleaseImpl());

  WaitForAging();
  parkable.Impl()->Park(ParkableStringImpl::ParkingMode::kCompress);

  // Advance the main thread until aging occurs. This uses RunLoop combined
  // with ThreadPoolExecutionMode::QUEUED to force the 2-seconds-delayed aging
  // task on the main thread to kick in before the immediate async compression
  // task completes.
  base::RunLoop run_loop;
  scheduler::GetSingleThreadTaskRunnerForTesting()->PostDelayedTask(
      FROM_HERE, run_loop.QuitClosure(),
      ParkableStringManager::AgingInterval());
  run_loop.Run();

  // The aging task is rescheduled.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());

  // Complete asynchronous work.
  RunPostedTasks();

  EXPECT_TRUE(parkable.Impl()->is_parked());
}

class ParkableStringTestWithLimitedDiskCapacity : public ParkableStringTest {
 public:
  ParkableStringTestWithLimitedDiskCapacity() {
    const std::vector<base::test::FeatureRefAndParams> enabled_features = {
        {features::kCompressParkableStrings, {{"max_disk_capacity_mb", "1"}}}};
    features_.InitWithFeaturesAndParameters(enabled_features, {});
  }

 private:
  base::test::ScopedFeatureList features_;
};

INSTANTIATE_TEST_SUITE_P(
    CompressionAlgorithm,
    ParkableStringTestWithLimitedDiskCapacity,
    ::testing::Values(ParkableStringImpl::CompressionAlgorithm::kZlib,
                      ParkableStringImpl::CompressionAlgorithm::kSnappy
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ,
                      ParkableStringImpl::CompressionAlgorithm::kZstd
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ));

TEST_P(ParkableStringTestWithLimitedDiskCapacity, ParkWithLimitedDiskCapacity) {
  constexpr size_t kMB = 1024 * 1024;
  {
    // Since compression rate is different, we cannot make a string for
    // same compressed data. So accumulate small compressed data until capacity
    // exceeds.
    Vector<ParkableString> strings;
    size_t total_written_compressed_data = 0;
    while (true) {
      ParkableString str(MakeComplexString(kMB).ReleaseImpl());
      WaitForDelayedParking();
      EXPECT_TRUE(str.Impl()->is_parked());

      if (total_written_compressed_data + str.Impl()->compressed_size() > kMB) {
        strings.push_back(str);
        break;
      }

      total_written_compressed_data += str.Impl()->compressed_size();
      WaitForDiskWriting();
      EXPECT_TRUE(str.Impl()->is_on_disk());
      strings.push_back(str);
    }
    WaitForDiskWriting();
    EXPECT_FALSE(strings.back().Impl()->is_on_disk());
  }

  // Since all the written data are discarded, we can write new string to disk.
  ParkableString parkable(MakeComplexString(kMB).ReleaseImpl());
  WaitForDelayedParking();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable.Impl()->is_on_disk());
}

class ParkableStringTestLessAggressiveMode : public ParkableStringTest {
 public:
  ParkableStringTestLessAggressiveMode()
      : features_(features::kLessAggressiveParkableString) {}

 private:
  base::test::ScopedFeatureList features_;
};

TEST_P(ParkableStringTestLessAggressiveMode, NoParkingInForeground) {
  auto& manager = ParkableStringManager::Instance();
  manager.SetRendererBackgrounded(false);

  ParkableString parkable(MakeLargeString().Impl());
  ASSERT_FALSE(parkable.Impl()->is_parked());
  EXPECT_EQ(1u, manager.Size());
  task_environment_.FastForwardBy(ParkableStringManager::kFirstParkingDelay);
  // No aging.
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  CheckOnlyCpuCostTaskRemains();

  manager.SetRendererBackgrounded(true);
  // A tick task has been posted.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  // Aging restarts.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());
  manager.SetRendererBackgrounded(false);
  // Another task has been posted.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  // But the string does not age further, since we are in foreground.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  CheckOnlyCpuCostTaskRemains();

  // Back to foreground, pick up where we left off.
  manager.SetRendererBackgrounded(true);
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  WaitForAging();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable.Impl()->is_on_disk());
  // The tick eventually stops.
  WaitForAging();
  CheckOnlyCpuCostTaskRemains();
}

// Same test as the previous one, with RAIL mode transitions.
TEST_P(ParkableStringTestLessAggressiveMode, NoParkingWhileLoading) {
  auto& manager = ParkableStringManager::Instance();
  manager.OnRAILModeChanged(RAILMode::kLoad);

  ParkableString parkable(MakeLargeString().Impl());
  ASSERT_FALSE(parkable.Impl()->is_parked());
  EXPECT_EQ(1u, manager.Size());
  task_environment_.FastForwardBy(ParkableStringManager::kFirstParkingDelay);
  // No aging.
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  CheckOnlyCpuCostTaskRemains();

  manager.OnRAILModeChanged(RAILMode::kDefault);
  // A tick task has been posted.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  // Aging restarts.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());
  manager.OnRAILModeChanged(RAILMode::kLoad);
  // Another task has been posted.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  // But the string does not age further, since we are in foreground.
  WaitForAging();
  EXPECT_EQ(ParkableStringImpl::Age::kOld, parkable.Impl()->age_for_testing());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  CheckOnlyCpuCostTaskRemains();

  // Back to idle, pick up where we left off.
  manager.OnRAILModeChanged(RAILMode::kDefault);
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  WaitForAging();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable.Impl()->is_on_disk());
  // The tick eventually stops.
  WaitForAging();
  CheckOnlyCpuCostTaskRemains();
}

// Combination of background and loading.
TEST_P(ParkableStringTestLessAggressiveMode,
       NoParkingWhileLoadingOrInForeground) {
  auto& manager = ParkableStringManager::Instance();
  // Loading in background.
  manager.OnRAILModeChanged(RAILMode::kLoad);
  manager.SetRendererBackgrounded(true);

  ParkableString parkable(MakeLargeString().Impl());
  ASSERT_FALSE(parkable.Impl()->is_parked());
  EXPECT_EQ(1u, manager.Size());
  task_environment_.FastForwardBy(ParkableStringManager::kFirstParkingDelay);
  // No aging.
  EXPECT_EQ(ParkableStringImpl::Age::kYoung,
            parkable.Impl()->age_for_testing());
  EXPECT_FALSE(parkable.Impl()->is_parked());
  CheckOnlyCpuCostTaskRemains();

  // Not loading in foreground, no parking.
  manager.SetRendererBackgrounded(false);
  manager.OnRAILModeChanged(RAILMode::kDefault);
  CheckOnlyCpuCostTaskRemains();

  // Not loading in background, restarting the tick.
  manager.SetRendererBackgrounded(true);
  // A tick task has been posted.
  EXPECT_EQ(2u, task_environment_.GetPendingMainThreadTaskCount());
  WaitForDelayedParking();
  EXPECT_TRUE(parkable.Impl()->is_parked());
  WaitForDiskWriting();
  EXPECT_TRUE(parkable.Impl()->is_on_disk());
  // The tick eventually stops.
  WaitForAging();
  CheckOnlyCpuCostTaskRemains();
}

INSTANTIATE_TEST_SUITE_P(
    CompressionAlgorithm,
    ParkableStringTestLessAggressiveMode,
    ::testing::Values(ParkableStringImpl::CompressionAlgorithm::kZlib,
                      ParkableStringImpl::CompressionAlgorithm::kSnappy
#if BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ,
                      ParkableStringImpl::CompressionAlgorithm::kZstd
#endif  // BUILDFLAG(HAS_ZSTD_COMPRESSION)
                      ));

}  // namespace blink

"""


```