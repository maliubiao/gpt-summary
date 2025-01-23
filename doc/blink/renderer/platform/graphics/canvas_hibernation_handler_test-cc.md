Response:
The user wants to understand the functionality of the `canvas_hibernation_handler_test.cc` file in the Chromium Blink engine. I need to:

1. **Summarize the core purpose of the file:** It's a test suite for `CanvasHibernationHandler`.
2. **Explain the functionality being tested:** This involves simulating the hibernation and restoration of canvas elements to save memory.
3. **Identify connections to web technologies (JavaScript, HTML, CSS):**  Canvas is directly related to the `<canvas>` HTML element and its JavaScript APIs. CSS can influence canvas rendering but isn't directly part of the hibernation logic.
4. **Provide illustrative examples:**  Demonstrate how the tests relate to real-world scenarios with user interaction.
5. **Explain logical reasoning in the tests:**  Highlight the input conditions and expected outcomes for specific test cases.
6. **Point out potential user/programming errors:**  Show how incorrect usage of the canvas API or page visibility can affect hibernation.
这个文件是 `blink/renderer/platform/graphics/canvas_hibernation_handler_test.cc`，它是 Chromium Blink 引擎中用于测试 `CanvasHibernationHandler` 类的单元测试文件。 `CanvasHibernationHandler` 的主要功能是：**在页面不可见时，将 canvas 的内容进行压缩并存储，以减少内存占用，当页面重新可见时再进行恢复。**  这个过程被称为 Canvas 休眠 (Hibernation)。

下面我们来详细列举一下这个测试文件的功能，并说明其与 JavaScript、HTML、CSS 的关系，以及其中的逻辑推理和可能的用户/编程错误。

**功能列表:**

1. **测试 Canvas 休眠的基本流程:**
   - 测试当页面变为不可见时，`CanvasHibernationHandler` 是否能够正确地捕获 canvas 的快照，并进行压缩存储。
   - 测试当页面重新变为可见时，`CanvasHibernationHandler` 是否能够正确地解压缩并恢复 canvas 的内容。
2. **测试不同的压缩算法:**
   - 使用 `INSTANTIATE_TEST_SUITE_P` 宏定义，测试了 `CanvasHibernationHandler` 支持的不同压缩算法（例如 Zlib 和 Zstd）。
3. **测试页面可见性变化的影响:**
   - 测试页面在休眠过程中过早回到前台的影响。
   - 测试页面在休眠开始后又立即回到前台，然后再回到后台的影响。
   - 测试在压缩完成前后，页面可见性变化的影响。
4. **测试 `Clear()` 方法:**
   - 测试调用 `Clear()` 方法是否能够正确地结束休眠状态，并释放相关资源。
   - 测试在压缩进行过程中调用 `Clear()` 方法的影响。
5. **测试内存占用指标:**
   - 测试休眠前后 canvas 的内存占用情况，包括压缩后的内存大小和原始内存大小。
   - 测试休眠状态下，内存指标是否能正确地被 `HibernatedCanvasMemoryDumpProvider` 记录。
6. **测试与 GPU 渲染的交互:**
   - 通过 `FakeCanvasResourceHost` 模拟 canvas 资源的宿主环境。
   - 测试在 GPU 渲染模式下，休眠功能是否正常工作。
7. **使用异步任务:**
   - 使用 `TestSingleThreadTaskRunner` 模拟单线程任务执行器，测试压缩和解压缩等异步操作的正确性。
8. **使用直方图进行指标记录:**
   - 使用 `base::HistogramTester` 记录并验证休眠过程中的压缩率、压缩时间、解压缩时间等指标。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  `<canvas>` 元素是触发 Canvas 休眠功能的核心。当包含 `<canvas>` 元素的页面进入后台时，`CanvasHibernationHandler` 会被调用来处理该 canvas 的休眠。
   * **举例说明:**  一个网页包含一个使用 JavaScript 绘制了复杂图形的 `<canvas>` 元素。当用户切换到其他标签页或应用时，这个 canvas 会触发休眠。
* **JavaScript:**  JavaScript 通过 Canvas API（例如 `getContext('2d')`）来操作 `<canvas>` 元素，绘制图形等。`CanvasHibernationHandler` 需要捕获这些绘制操作的结果（像素数据）并进行压缩。当页面恢复可见时，虽然不会直接恢复 JavaScript 的状态，但会恢复 canvas 的视觉状态。
   * **举例说明:**  JavaScript 代码使用 `fillRect()` 和 `drawImage()` 等方法在 canvas 上绘制内容。休眠功能会将这些绘制结果保存下来。
* **CSS:**  CSS 可以影响 `<canvas>` 元素的尺寸和样式，但不会直接参与 Canvas 休眠的逻辑。`CanvasHibernationHandler` 主要关注 canvas 的像素数据。
   * **举例说明:**  CSS 可以设置 canvas 的 `width` 和 `height` 属性。`CanvasHibernationHandler` 需要知道这些尺寸来捕获正确的快照。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例中的逻辑推理示例：

* **假设输入:** 页面不可见 (`SetPageVisible(false)`)，canvas 上绘制了一些内容。
   * **预期输出:**  `handler.IsHibernating()` 返回 `true`，并且在一段时间后 `handler.is_encoded()` 返回 `true`，表示 canvas 数据被压缩存储。
* **假设输入:** 页面在压缩完成前重新变为可见 (`SetPageVisible(true)` 在压缩完成前调用)。
   * **预期输出:**  压缩操作可能会被取消，`handler.is_encoded()` 返回 `false`，因为没有必要恢复一个即将被重新绘制的 canvas。
* **假设输入:**  在休眠状态下调用 `handler.Clear()`。
   * **预期输出:**  `handler.IsHibernating()` 和 `handler.is_encoded()` 都返回 `false`，表示休眠状态被终止。

**用户或编程常见的使用错误:**

1. **误判页面可见性:** 如果开发者错误地判断了页面的可见性状态，可能会导致 `CanvasHibernationHandler` 在不应该休眠的时候休眠，或者在应该休眠的时候没有休眠。
   * **举例说明:**  一个应用可能依赖错误的事件来判断页面是否进入后台，导致 canvas 没有及时休眠，浪费内存。
2. **在休眠过程中进行 canvas 操作:**  虽然 `CanvasHibernationHandler` 会尝试恢复 canvas 的状态，但在页面不可见时继续使用 JavaScript 修改 canvas 可能导致意外行为或数据丢失。开发者应该避免在页面处于休眠状态时进行 canvas 操作。
   * **举例说明:**  一个游戏在页面不可见时仍然尝试更新 canvas 内容，当页面恢复时，这些更新可能会丢失或与恢复的状态冲突。
3. **资源泄漏:**  如果 `CanvasHibernationHandler` 没有正确地管理资源（例如压缩后的数据），可能会导致内存泄漏。这个测试文件中的某些测试用例（例如测试 `Clear()` 方法）就是为了验证资源是否被正确释放。
4. **异步操作处理不当:**  压缩和解压缩是异步操作。如果开发者没有正确处理这些异步操作的回调，可能会导致程序逻辑错误。测试文件中使用了 `TestSingleThreadTaskRunner` 来模拟异步任务，确保这些操作的顺序和结果符合预期。

总而言之，`canvas_hibernation_handler_test.cc` 是一个非常重要的测试文件，它确保了 Canvas 休眠功能的正确性和健壮性，这对于提高 Chromium 的内存使用效率和用户体验至关重要。通过各种测试用例，它覆盖了休眠流程的各个方面，并验证了在不同场景下的行为。

### 提示词
```
这是目录为blink/renderer/platform/graphics/canvas_hibernation_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/canvas_hibernation_handler.h"

#include <list>

#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "components/viz/test/test_context_provider.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/test/fake_canvas_resource_host.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_memory_buffer_test_platform.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

using testing::Test;

class CanvasHibernationHandlerTest
    : public testing::TestWithParam<
          CanvasHibernationHandler::CompressionAlgorithm> {
 public:
  CanvasHibernationHandlerTest() {
    // This only enabled the feature, not necessarily compression using this
    // algorithm, since the current platform may not support it. This is the
    // correct thing to do though, as we care about code behaving well with the
    // two feature states, even on platforms that don't support ZSTD.
    CanvasHibernationHandler::CompressionAlgorithm algorithm = GetParam();
    switch (algorithm) {
      case CanvasHibernationHandler::CompressionAlgorithm::kZlib:
        scoped_feature_list_.InitWithFeatures({},
                                              {kCanvasHibernationSnapshotZstd});
        break;
      case blink::CanvasHibernationHandler::CompressionAlgorithm::kZstd:
        scoped_feature_list_.InitWithFeatures({kCanvasHibernationSnapshotZstd},
                                              {});
        break;
    }
  }

  void SetUp() override {
    test_context_provider_ = viz::TestContextProvider::Create();
    InitializeSharedGpuContextGLES2(test_context_provider_.get());
  }

  virtual bool NeedsMockGL() { return false; }

  void TearDown() override {
    SharedGpuContext::Reset();
    test_context_provider_.reset();
  }

  FakeCanvasResourceHost* Host() {
    DCHECK(host_);
    return host_.get();
  }

 protected:
  test::TaskEnvironment task_environment_;
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  std::unique_ptr<FakeCanvasResourceHost> host_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

namespace {

void SetPageVisible(
    FakeCanvasResourceHost* host,
    CanvasHibernationHandler* hibernation_handler,
    ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform>& platform,
    bool page_visible) {
  host->SetPageVisible(page_visible);

  // TODO(crbug.com/40280152): Make a custom FakeCanvasResourceHost subclass
  // that encapsulates the logic for starting/ending hibernation in its
  // SetPageVisible() implementation and change the tests to directly call
  // SetPageVisible() on the host.
  if (!page_visible) {
    // Trigger hibernation.
    scoped_refptr<StaticBitmapImage> snapshot =
        host->ResourceProvider()->Snapshot(FlushReason::kHibernating);
    hibernation_handler->SaveForHibernation(
        snapshot->PaintImageForCurrentFrame().GetSwSkImage(),
        host->ResourceProvider()->ReleaseRecorder());
    EXPECT_TRUE(hibernation_handler->IsHibernating());
  } else {
    // End hibernation.
    hibernation_handler->Clear();
  }
}

std::map<std::string, uint64_t> GetEntries(
    const base::trace_event::MemoryAllocatorDump& dump) {
  std::map<std::string, uint64_t> result;
  for (const auto& entry : dump.entries()) {
    CHECK(entry.entry_type ==
          base::trace_event::MemoryAllocatorDump::Entry::kUint64);
    result.insert({entry.name, entry.value_uint64});
  }
  return result;
}

void Draw(CanvasResourceHost& host) {
  CanvasResourceProvider* provider = host.GetOrCreateCanvasResourceProvider(
      host.GetRasterMode() == RasterMode::kGPU ? RasterModeHint::kPreferGPU
                                               : RasterModeHint::kPreferCPU);
  provider->Canvas().drawLine(0, 0, 2, 2, cc::PaintFlags());
  provider->FlushCanvas(FlushReason::kTesting);
}

class TestSingleThreadTaskRunner : public base::SingleThreadTaskRunner {
 public:
  bool PostDelayedTask(const base::Location& from_here,
                       base::OnceClosure task,
                       base::TimeDelta delay) override {
    if (delay.is_zero()) {
      immediate_.push_back(std::move(task));
    } else {
      delayed_.push_back(std::move(task));
    }

    return true;
  }
  bool PostNonNestableDelayedTask(const base::Location& from_here,
                                  base::OnceClosure task,
                                  base::TimeDelta delay) override {
    return false;
  }

  // Since this is mocking a SingleThreadTaskRunner, tasks will always be run
  // in the same sequence they are posted from.
  bool RunsTasksInCurrentSequence() const override { return true; }

  static size_t RunAll(std::list<base::OnceClosure>& tasks) {
    size_t count = 0;
    while (!tasks.empty()) {
      std::move(tasks.front()).Run();
      tasks.pop_front();
      count++;
    }
    return count;
  }

  static bool RunOne(std::list<base::OnceClosure>& tasks) {
    if (tasks.empty()) {
      return false;
    }
    std::move(tasks.front()).Run();
    tasks.pop_front();
    return true;
  }

  std::list<base::OnceClosure>& delayed() { return delayed_; }
  std::list<base::OnceClosure>& immediate() { return immediate_; }

 private:
  std::list<base::OnceClosure> delayed_;
  std::list<base::OnceClosure> immediate_;
};

}  // namespace

INSTANTIATE_TEST_SUITE_P(
    CompressionAlgorithm,
    CanvasHibernationHandlerTest,
    ::testing::Values(CanvasHibernationHandler::CompressionAlgorithm::kZlib,
                      CanvasHibernationHandler::CompressionAlgorithm::kZstd));

TEST_P(CanvasHibernationHandlerTest, SimpleTest) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});
  base::HistogramTester histogram_tester;

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, &handler, platform, false);

  EXPECT_TRUE(handler.IsHibernating());
  // Triggers a delayed task for encoding.
  EXPECT_FALSE(task_runner->delayed().empty());
  EXPECT_TRUE(task_runner->immediate().empty());

  TestSingleThreadTaskRunner::RunAll(task_runner->delayed());
  // Posted the background compression task.
  EXPECT_FALSE(task_runner->immediate().empty());

  size_t uncompressed_size = 300u * 200 * 4;
  EXPECT_EQ(handler.width(), 300);
  EXPECT_EQ(handler.height(), 200);
  EXPECT_EQ(uncompressed_size, handler.memory_size());

  // Runs the encoding task, but also the callback one.
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_TRUE(handler.is_encoded());
  EXPECT_LT(handler.memory_size(), uncompressed_size);
  EXPECT_EQ(handler.original_memory_size(), uncompressed_size);

  histogram_tester.ExpectTotalCount(
      "Blink.Canvas.2DLayerBridge.Compression.Ratio", 1);
  histogram_tester.ExpectTotalCount(
      "Blink.Canvas.2DLayerBridge.Compression.ThreadTime", 1);
  histogram_tester.ExpectUniqueSample(
      "Blink.Canvas.2DLayerBridge.Compression.SnapshotSizeKb",
      uncompressed_size / 1024, 1);
  histogram_tester.ExpectTotalCount(
      "Blink.Canvas.2DLayerBridge.Compression.DecompressionTime", 0);

  // It should be possible to decompress the encoded image.
  EXPECT_TRUE(handler.GetImage());
  histogram_tester.ExpectTotalCount(
      "Blink.Canvas.2DLayerBridge.Compression.DecompressionTime", 1);

  SetPageVisible(&host, &handler, platform, true);
  EXPECT_FALSE(handler.is_encoded());

  EXPECT_TRUE(host.GetRasterMode() == RasterMode::kGPU);
  EXPECT_FALSE(handler.IsHibernating());
  EXPECT_TRUE(host.IsResourceValid());
}

TEST_P(CanvasHibernationHandlerTest, ForegroundTooEarly) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);
  SetPageVisible(&host, &handler, platform, false);

  // Triggers a delayed task for encoding.
  EXPECT_FALSE(task_runner->delayed().empty());

  EXPECT_TRUE(handler.IsHibernating());
  SetPageVisible(&host, &handler, platform, true);

  // Nothing happens, because the page came to foreground in-between.
  TestSingleThreadTaskRunner::RunAll(task_runner->delayed());
  EXPECT_TRUE(task_runner->immediate().empty());
  EXPECT_FALSE(handler.is_encoded());
}

TEST_P(CanvasHibernationHandlerTest, BackgroundForeground) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  // Background -> Foreground -> Background
  SetPageVisible(&host, &handler, platform, false);
  SetPageVisible(&host, &handler, platform, true);
  SetPageVisible(&host, &handler, platform, false);

  // 2 delayed task that will potentially trigger encoding.
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  // But a single encoding task (plus the main thread callback).
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_TRUE(handler.is_encoded());
}

TEST_P(CanvasHibernationHandlerTest, ForegroundAfterEncoding) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, &handler, platform, false);
  // Wait for the encoding task to be posted.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_TRUE(TestSingleThreadTaskRunner::RunOne(task_runner->immediate()));
  // Come back to foreground after (or during) compression, but before the
  // callback.
  SetPageVisible(&host, &handler, platform, true);

  // The callback is still pending.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  // But the encoded version is dropped.
  EXPECT_FALSE(handler.is_encoded());
  EXPECT_FALSE(handler.IsHibernating());
}

TEST_P(CanvasHibernationHandlerTest, ForegroundFlipForAfterEncoding) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, &handler, platform, false);
  // Wait for the encoding task to be posted.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_TRUE(TestSingleThreadTaskRunner::RunOne(task_runner->immediate()));
  // Come back to foreground after (or during) compression, but before the
  // callback.
  SetPageVisible(&host, &handler, platform, true);
  // And back to background.
  SetPageVisible(&host, &handler, platform, false);
  EXPECT_TRUE(handler.IsHibernating());

  // The callback is still pending.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  // But the encoded version is dropped (epoch mismatch).
  EXPECT_FALSE(handler.is_encoded());
  // Yet we are hibernating (since the page is in the background).
  EXPECT_TRUE(handler.IsHibernating());

  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_TRUE(handler.is_encoded());
  EXPECT_TRUE(handler.IsHibernating());
}

TEST_P(CanvasHibernationHandlerTest, ForegroundFlipForBeforeEncoding) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, &handler, platform, false);
  // Wait for the encoding task to be posted.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  // Come back to foreground before compression.
  SetPageVisible(&host, &handler, platform, true);
  // And back to background.
  SetPageVisible(&host, &handler, platform, false);
  EXPECT_TRUE(handler.IsHibernating());
  // Compression still happens, since it's a static task, doesn't look at the
  // epoch before compressing.
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));

  // But the encoded version is dropped (epoch mismatch).
  EXPECT_FALSE(handler.is_encoded());
  // Yet we are hibernating (since the page is in the background).
  EXPECT_TRUE(handler.IsHibernating());
}

TEST_P(CanvasHibernationHandlerTest, ClearEndsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, &handler, platform, false);
  // Wait for the canvas to be encoded.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_TRUE(handler.is_encoded());

  handler.Clear();

  EXPECT_FALSE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());
}

TEST_P(CanvasHibernationHandlerTest, ClearWhileCompressingEndsHibernation) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasHibernationHandler handler(host);

  Draw(host);

  handler.SetTaskRunnersForTesting(task_runner, task_runner);

  // Set the page to hidden to kick off hibernation.
  SetPageVisible(&host, &handler, platform, false);
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());

  // Run the task that kicks off compression, then run the compression task
  // itself, but *don't* run the callback for compression completing.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_TRUE(TestSingleThreadTaskRunner::RunOne(task_runner->immediate()));
  EXPECT_TRUE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());

  // A clear while compression is in progress should end hibernation.
  handler.Clear();
  EXPECT_FALSE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());

  // Compression finishing should then be a no-op because the canvas is no
  // longer in hibernation.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_FALSE(handler.IsHibernating());
  EXPECT_FALSE(handler.is_encoded());
}

TEST_P(CanvasHibernationHandlerTest, HibernationMemoryMetrics) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kCanvas2DHibernation}, {});

  auto task_runner = base::MakeRefCounted<TestSingleThreadTaskRunner>();
  ScopedTestingPlatformSupport<GpuMemoryBufferTestPlatform> platform;
  FakeCanvasResourceHost host(gfx::Size(300, 200));
  host.SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  auto handler = std::make_unique<CanvasHibernationHandler>(host);

  Draw(host);

  handler->SetTaskRunnersForTesting(task_runner, task_runner);

  SetPageVisible(&host, handler.get(), platform, false);

  base::trace_event::MemoryDumpArgs args = {
      base::trace_event::MemoryDumpLevelOfDetail::kDetailed};
  {
    base::trace_event::ProcessMemoryDump pmd(args);
    EXPECT_TRUE(HibernatedCanvasMemoryDumpProvider::GetInstance().OnMemoryDump(
        args, &pmd));
    auto* dump = pmd.GetAllocatorDump("canvas/hibernated/canvas_0");
    ASSERT_TRUE(dump);
    auto entries = GetEntries(*dump);
    EXPECT_EQ(entries["memory_size"], handler->memory_size());
    EXPECT_EQ(entries["original_memory_size"], handler->original_memory_size());
    EXPECT_EQ(entries.at("is_encoded"), 0u);
    EXPECT_EQ(entries["height"], 200u);
    EXPECT_EQ(entries["width"], 300u);
  }

  // Wait for the canvas to be encoded.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));
  EXPECT_TRUE(handler->is_encoded());

  {
    base::trace_event::ProcessMemoryDump pmd(args);
    EXPECT_TRUE(HibernatedCanvasMemoryDumpProvider::GetInstance().OnMemoryDump(
        args, &pmd));
    auto* dump = pmd.GetAllocatorDump("canvas/hibernated/canvas_0");
    ASSERT_TRUE(dump);
    auto entries = GetEntries(*dump);
    EXPECT_EQ(entries["memory_size"], handler->memory_size());
    EXPECT_EQ(entries["original_memory_size"], handler->original_memory_size());
    EXPECT_LT(entries["memory_size"], entries["original_memory_size"]);
    EXPECT_EQ(entries["is_encoded"], 1u);
  }

  // End hibernation to be able to verify that hibernation dumps will no longer
  // occur.
  SetPageVisible(&host, handler.get(), platform, true);
  EXPECT_FALSE(handler->IsHibernating());

  {
    base::trace_event::ProcessMemoryDump pmd(args);
    EXPECT_TRUE(HibernatedCanvasMemoryDumpProvider::GetInstance().OnMemoryDump(
        args, &pmd));
    // No more dump, since the canvas is no longer hibernating.
    EXPECT_FALSE(pmd.GetAllocatorDump("canvas/hibernated/canvas_0"));
  }

  SetPageVisible(&host, handler.get(), platform, false);
  // Wait for the canvas to be encoded.
  EXPECT_EQ(1u, TestSingleThreadTaskRunner::RunAll(task_runner->delayed()));
  EXPECT_EQ(2u, TestSingleThreadTaskRunner::RunAll(task_runner->immediate()));

  // We have an hibernated canvas.
  {
    base::trace_event::ProcessMemoryDump pmd(args);
    EXPECT_TRUE(HibernatedCanvasMemoryDumpProvider::GetInstance().OnMemoryDump(
        args, &pmd));
    // No more dump, since the canvas is no longer hibernating.
    EXPECT_TRUE(pmd.GetAllocatorDump("canvas/hibernated/canvas_0"));
  }

  // Handler gets destroyed, no more hibernated canvas.
  handler = nullptr;
  {
    base::trace_event::ProcessMemoryDump pmd(args);
    EXPECT_TRUE(HibernatedCanvasMemoryDumpProvider::GetInstance().OnMemoryDump(
        args, &pmd));
    // No more dump, since the canvas is no longer hibernating.
    EXPECT_FALSE(pmd.GetAllocatorDump("canvas/hibernated/canvas_0"));
  }
}

}  // namespace blink
```