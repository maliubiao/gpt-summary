Response:
My thinking process to analyze the C++ unittest file went something like this:

1. **Understand the Purpose:** The file name `layer_tree_view_unittest.cc` immediately tells me this is a unit test file for the `LayerTreeView` class. Unit tests verify the functionality of individual components in isolation.

2. **Identify Key Classes Under Test:**  The `#include` directives confirm `LayerTreeView` is the central class. Other included classes like `FakeLayerTreeViewDelegate`, `cc::LayerTreeHost`, and various `cc::test` classes are supporting elements for the tests.

3. **Break Down the Tests by Functionality:** I started reading through the `TEST_F` and `TEST` macros, which define individual test cases. I tried to group these tests based on the core functionality they were exercising. This led to categories like:

    * **Frame Sink Creation and Retries:** Several tests (`SucceedOnce`, `SucceedOnce_AfterNullChannel`, `SucceedOnce_AfterLostContext`, etc.) explicitly focus on how `LayerTreeView` handles successful and failed attempts to create a `LayerTreeFrameSink`. The `FakeLayerTreeViewDelegate` plays a crucial role here in simulating different success/failure scenarios.
    * **Visibility and Frame Sink Requests:** The `VisibilityTest` directly tests how the visibility state of the `LayerTreeView` affects when frame sink requests are made.
    * **Presentation Callbacks:** The `RunPresentationCallbackOnSuccess` test verifies that presentation callbacks are executed correctly only when a compositor frame is successfully presented.
    * **Delegate Switching:** The `LayerTreeViewDelegateChangeTest` group of tests focuses on how `LayerTreeView` behaves when its delegate object is replaced. This includes scenarios with pending frame sink requests, initialization in progress, and the impact on deferred commits.

4. **Analyze Test Setup and Assertions:** For each test category, I looked at how the tests were structured:

    * **Setup:** How are the test objects (`LayerTreeView`, `FakeLayerTreeViewDelegate`) initialized?  What are the initial conditions?
    * **Actions:** What actions are performed on the `LayerTreeView` (e.g., `SetVisible`, `RequestNewLayerTreeFrameSink`, `SynchronousComposite`)?  How is the `FakeLayerTreeViewDelegate` configured to simulate different outcomes?
    * **Assertions:** What are the `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_NE` statements verifying? These are the core of the tests, demonstrating the expected behavior.

5. **Connect to Web Concepts (JavaScript, HTML, CSS):**  Once I understood the core functionalities being tested, I started thinking about how these relate to web technologies:

    * **Compositing and Rendering:**  The entire concept of `LayerTreeView` and `LayerTreeFrameSink` is deeply tied to the browser's compositing process, which is how HTML, CSS, and JavaScript are ultimately rendered on the screen. Changes to the DOM (via JavaScript), styling (via CSS), and even animations can trigger compositing.
    * **GPU and Graphics:** The tests involving "null channel" and "lost context" directly relate to the interaction with the GPU. A failure to create a GPU channel or losing the rendering context will impact the ability to composite and display web content.
    * **Visibility and Performance:** The visibility tests highlight an optimization: not requesting resources when the content isn't visible. This is important for performance.
    * **Event Handling:** The `ResetEventListenerPropertiesOnSwap` test, though more internal, touches on how event listeners are managed, which is crucial for JavaScript interactivity.
    * **Frame Synchronization:** Presentation callbacks are directly linked to the browser's rendering pipeline and how it synchronizes with the display. This is important for smooth animations and avoiding jank.

6. **Identify Logical Reasoning and Assumptions:**  The tests often make implicit assumptions about the internal workings of `LayerTreeView`. For example, the retry mechanism for frame sink creation relies on the assumption that a failed creation might be transient and retrying could succeed. The visibility test assumes that `RequestNewLayerTreeFrameSink` will not be called when the view is invisible.

7. **Pinpoint Potential User/Programming Errors:**  By understanding the tested scenarios, I could deduce potential misuse:

    * **Incorrectly Handling Frame Sink Failures:** If a developer were interacting with `LayerTreeView` directly (unlikely in most scenarios), they might need to be aware of the possibility of frame sink creation failures and implement appropriate error handling.
    * **Unexpected Behavior During Delegate Switching:**  If the delegate is swapped at an unexpected time, the developer might observe surprising behavior related to pending operations or resource requests.

8. **Structure the Output:** Finally, I organized my analysis into logical sections, starting with a summary of the file's purpose, then detailing the functionalities, their relevance to web technologies, logical reasoning, and potential errors. I used examples to illustrate the connections to JavaScript, HTML, and CSS.

Essentially, I approached the problem like reverse engineering the code's intention by looking at how it's being tested. The tests themselves are the documentation of how the `LayerTreeView` is *supposed* to work.

这个文件 `blink/renderer/platform/widget/compositing/layer_tree_view_unittest.cc` 是 Chromium Blink 引擎中 `LayerTreeView` 类的单元测试文件。它的主要功能是：

**核心功能：测试 `LayerTreeView` 类的各种行为和功能。**

`LayerTreeView` 是 Blink 渲染引擎中负责管理和协调合成的组件。它与底层的 `cc::LayerTreeHost` 交互，并负责创建和管理 `LayerTreeFrameSink`，后者是实际进行 GPU 渲染的接口。

**具体测试的功能点包括：**

1. **LayerTreeFrameSink 的创建和重试机制：**
   - 测试在创建 `LayerTreeFrameSink` 失败的情况下（例如，GPU 进程崩溃、Context Lost），`LayerTreeView` 是否能够正确地重试创建。
   - 测试在不同的失败场景下（例如，绑定 Context 失败、GPU Channel 失败），重试机制是否按预期工作。
   - 测试在重试期间，当 LayerTreeView 不可见时，是否会暂停重试，直到重新可见。

2. **可见性 (Visibility) 与 FrameSink 请求：**
   - 测试当 `LayerTreeView` 不可见时，是否会避免不必要的 `LayerTreeFrameSink` 请求。
   - 测试当 `LayerTreeView` 从不可见变为可见时，是否会重新发起 `LayerTreeFrameSink` 请求。

3. **Presentation Callbacks（呈现回调）：**
   - 测试只有在合成器帧成功呈现时，才会调用注册的 presentation callback。
   - 测试当呈现失败时，callback 不会被调用，直到后续成功的呈现。

4. **Delegate 切换 (Delegate Change)：**
   - 测试在 `LayerTreeView` 的 delegate 对象被替换时，各种状态和行为是否正确处理。
   - 测试在 delegate 切换的不同阶段（例如，没有 FrameSink，请求正在进行中，FrameSink 正在初始化，FrameSink 已经初始化），`LayerTreeView` 的行为。
   - 测试 delegate 切换是否会影响 commit 的延迟状态 (defer commits)。
   - 测试 delegate 切换是否会重置事件监听器属性。

**与 JavaScript, HTML, CSS 的关系举例：**

`LayerTreeView` 虽然是一个 C++ 组件，但它直接参与了将 JavaScript、HTML 和 CSS 渲染到屏幕上的过程。

* **HTML 和 CSS:**  当浏览器解析 HTML 和 CSS 构建出渲染树后，渲染树会被转化为一个 Layer 树。`LayerTreeView` 负责管理这个 Layer 树，并协调其合成过程。例如，CSS 的 `position: fixed` 或 `transform` 属性可能会导致元素拥有自己的合成层，这些层的管理就涉及到 `LayerTreeView`。
    * **假设输入:**  一个包含 `position: fixed` 元素的 HTML 页面。
    * **输出:** `LayerTreeView` 会为这个固定定位的元素创建一个独立的合成层，以确保它在滚动时保持在屏幕上的固定位置。测试可能会验证在这种情况下 `LayerTreeFrameSink` 的创建和更新是否正常。

* **JavaScript:** JavaScript 可以通过 DOM 操作和 CSS 属性的修改来影响 Layer 树的结构和属性，从而间接地影响 `LayerTreeView` 的行为。例如，JavaScript 动画可能会触发合成层的更新。
    * **假设输入:**  一段使用 `requestAnimationFrame` 修改元素 `transform` 属性的 JavaScript 代码，创建动画效果。
    * **输出:**  `LayerTreeView` 会根据 `transform` 属性的变化，请求合成新的帧。测试可能会验证在动画过程中，`LayerTreeFrameSink` 是否被正确地请求和使用，以及 presentation callback 是否被正确触发。

**逻辑推理 (假设输入与输出):**

考虑 `VisibilityTest` 中的一个场景：

* **假设输入:**
    1. `LayerTreeView` 初始化完成。
    2. `LayerTreeView` 的可见性设置为 `false`。
    3. 调用 `layer_tree_view.RequestNewLayerTreeFrameSink()`。
* **逻辑推理:** 由于 `LayerTreeView` 当前不可见，它应该避免立即请求创建 `LayerTreeFrameSink`，以节省资源。
* **输出:** 测试会断言 `layer_tree_view.num_requests_sent()` 的值在不可见期间调用 `RequestNewLayerTreeFrameSink()` 后仍然为 1（因为只记录了请求的意图，但没有真正发送）。当随后 `LayerTreeView` 的可见性设置为 `true` 后，再次检查 `num_requests_sent()`，其值应该增加到 2，表明在变为可见后才真正发起了请求。

**用户或编程常见的使用错误举例：**

虽然开发者通常不会直接操作 `LayerTreeView`，但理解其行为有助于避免一些性能问题或理解渲染过程。

* **不必要的强制合成：**  过度使用某些 CSS 属性或频繁的 JavaScript DOM 操作可能导致 `LayerTreeView` 频繁地请求创建新的 `LayerTreeFrameSink` 或进行合成，从而消耗大量资源，导致页面卡顿。测试中对 `LayerTreeFrameSink` 创建和重试的测试，实际上反映了引擎在尝试从错误状态恢复或适应变化。

* **在不可见时进行昂贵的操作：** 如果开发者在元素不可见时仍然执行大量的 JavaScript 代码，例如修改样式或进行复杂的计算，这些操作可能会间接地触发 `LayerTreeView` 的一些逻辑（虽然可能不会真正进行渲染），但仍然会消耗资源。测试中关于可见性的部分强调了引擎在不可见时会采取的优化措施。

**总结:**

`layer_tree_view_unittest.cc` 通过模拟各种场景，细致地测试了 `LayerTreeView` 类的核心功能，特别是其与 `LayerTreeFrameSink` 的生命周期管理、可见性处理、以及在不同错误状态下的恢复能力。这些测试确保了 Blink 引擎在合成渲染过程中能够稳定可靠地工作，从而为用户提供流畅的网页浏览体验。 理解这些测试用例有助于深入理解 Blink 渲染引擎的内部机制。

### 提示词
```
这是目录为blink/renderer/platform/widget/compositing/layer_tree_view_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/layer_tree_view.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/test/fake_layer_tree_frame_sink.h"
#include "cc/test/test_task_graph_runner.h"
#include "cc/test/test_ukm_recorder_factory.h"
#include "cc/trees/layer_tree_host.h"
#include "cc/trees/render_frame_metadata_observer.h"
#include "components/viz/test/test_context_provider.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/scheduler/test/web_fake_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/dummy_schedulers.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/widget_scheduler.h"
#include "third_party/blink/renderer/platform/widget/compositing/test/stub_layer_tree_view_delegate.h"

using testing::AllOf;
using testing::Field;

namespace blink {
namespace {

enum FailureMode {
  kNoFailure,
  kBindContextFailure,
  kGpuChannelFailure,
};

class FakeLayerTreeViewDelegate : public StubLayerTreeViewDelegate {
 public:
  FakeLayerTreeViewDelegate() = default;
  FakeLayerTreeViewDelegate(const FakeLayerTreeViewDelegate&) = delete;
  FakeLayerTreeViewDelegate& operator=(const FakeLayerTreeViewDelegate&) =
      delete;

  void RequestNewLayerTreeFrameSink(
      LayerTreeFrameSinkCallback callback) override {
    // Subtract one cuz the current request has already been counted but should
    // not be included for this.
    if (num_requests_since_last_success_ - 1 < num_requests_before_success_) {
      std::move(callback).Run(nullptr, nullptr);
      return;
    }

    auto context_provider = viz::TestContextProvider::Create();
    if (num_failures_since_last_success_ < num_failures_before_success_) {
      context_provider->UnboundTestContextGL()->LoseContextCHROMIUM(
          GL_GUILTY_CONTEXT_RESET_ARB, GL_INNOCENT_CONTEXT_RESET_ARB);
    }
    std::move(callback).Run(
        cc::FakeLayerTreeFrameSink::Create3d(std::move(context_provider)),
        nullptr);
  }

  void Reset() {
    num_requests_ = 0;
    num_requests_before_success_ = 0;
    num_requests_since_last_success_ = 0;
    num_failures_ = 0;
    num_failures_before_success_ = 0;
    num_failures_since_last_success_ = 0;
    num_successes_ = 0;
  }

  void add_success() {
    ++num_successes_;
    num_requests_since_last_success_ = 0;
    num_failures_since_last_success_ = 0;
  }
  int num_successes() const { return num_successes_; }

  void add_request() {
    ++num_requests_since_last_success_;
    ++num_requests_;
  }
  int num_requests() const { return num_requests_; }

  void add_failure() {
    ++num_failures_since_last_success_;
    ++num_failures_;
  }
  int num_failures() const { return num_failures_; }

  void set_num_requests_before_success(int n) {
    num_requests_before_success_ = n;
  }
  void set_num_failures_before_success(int n) {
    num_failures_before_success_ = n;
  }
  int num_failures_before_success() const {
    return num_failures_before_success_;
  }

 private:
  int num_requests_ = 0;
  int num_requests_before_success_ = 0;
  int num_requests_since_last_success_ = 0;
  int num_failures_ = 0;
  int num_failures_before_success_ = 0;
  int num_failures_since_last_success_ = 0;
  int num_successes_ = 0;
};

// Verify that failing to create an output surface will cause the compositor
// to attempt to repeatedly create another output surface.
// The use null output surface parameter allows testing whether failures
// from RenderWidget (couldn't create an output surface) vs failures from
// the compositor (couldn't bind the output surface) are handled identically.
class LayerTreeViewWithFrameSinkTracking : public LayerTreeView {
 public:
  LayerTreeViewWithFrameSinkTracking(FakeLayerTreeViewDelegate* delegate,
                                     PageScheduler& scheduler)
      : LayerTreeView(delegate, scheduler.CreateWidgetScheduler()),
        delegate_(delegate) {}
  LayerTreeViewWithFrameSinkTracking(
      const LayerTreeViewWithFrameSinkTracking&) = delete;
  LayerTreeViewWithFrameSinkTracking& operator=(
      const LayerTreeViewWithFrameSinkTracking&) = delete;

  // Force a new output surface to be created.
  void SynchronousComposite() {
    layer_tree_host()->SetVisible(false);
    layer_tree_host()->ReleaseLayerTreeFrameSink();
    layer_tree_host()->SetVisible(true);

    base::TimeTicks some_time;
    layer_tree_host()->CompositeForTest(some_time, true /* raster */,
                                        base::OnceClosure());
  }

  void RequestNewLayerTreeFrameSink() override {
    delegate_->add_request();
    LayerTreeView::RequestNewLayerTreeFrameSink();
  }

  void DidInitializeLayerTreeFrameSink() override {
    LayerTreeView::DidInitializeLayerTreeFrameSink();
    delegate_->add_success();
    if (delegate_->num_successes() == expected_successes_) {
      EXPECT_EQ(delegate_->num_requests(), expected_requests_);
      EndTest();
    } else {
      // Post the synchronous composite task so that it is not called
      // reentrantly as a part of RequestNewLayerTreeFrameSink.
      blink::scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
          FROM_HERE,
          base::BindOnce(
              &LayerTreeViewWithFrameSinkTracking::SynchronousComposite,
              base::Unretained(this)));
    }
  }

  void DidFailToInitializeLayerTreeFrameSink() override {
    LayerTreeView::DidFailToInitializeLayerTreeFrameSink();
    delegate_->add_failure();
    if (delegate_->num_requests() == expected_requests_) {
      EXPECT_EQ(delegate_->num_successes(), expected_successes_);
      EndTest();
      return;
    }
  }

  void SetUp(int expected_successes,
             int num_tries,
             FailureMode failure_mode,
             base::RunLoop* run_loop) {
    run_loop_ = run_loop;
    failure_mode_ = failure_mode;
    expected_successes_ = expected_successes;
    switch (failure_mode_) {
      case kNoFailure:
        expected_requests_ = expected_successes;
        break;
      case kBindContextFailure:
      case kGpuChannelFailure:
        expected_requests_ = num_tries * std::max(1, expected_successes);
        break;
    }
  }

  void EndTest() { run_loop_->Quit(); }

 private:
  raw_ptr<FakeLayerTreeViewDelegate> delegate_;
  raw_ptr<base::RunLoop> run_loop_ = nullptr;
  int expected_successes_ = 0;
  int expected_requests_ = 0;
  FailureMode failure_mode_ = kNoFailure;
};

class LayerTreeViewWithFrameSinkTrackingTest : public testing::Test {
 public:
  LayerTreeViewWithFrameSinkTrackingTest()
      : dummy_page_scheduler_(scheduler::CreateDummyPageScheduler()),
        layer_tree_view_(&layer_tree_view_delegate_, *dummy_page_scheduler_) {
    cc::LayerTreeSettings settings;
    settings.single_thread_proxy_scheduler = false;
    layer_tree_view_.Initialize(
        settings, blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
        /*compositor_thread=*/nullptr, &test_task_graph_runner_);
  }
  LayerTreeViewWithFrameSinkTrackingTest(
      const LayerTreeViewWithFrameSinkTrackingTest&) = delete;
  LayerTreeViewWithFrameSinkTrackingTest& operator=(
      const LayerTreeViewWithFrameSinkTrackingTest&) = delete;

  void RunTest(int expected_successes, FailureMode failure_mode) {
    layer_tree_view_delegate_.Reset();
    // 6 is just an artibrary "large" number to show it keeps trying.
    const int kTries = 6;
    // If it should fail, then it will fail every attempt, otherwise it fails
    // until the last attempt.
    int tries_before_success = kTries - (expected_successes ? 1 : 0);
    switch (failure_mode) {
      case kNoFailure:
        layer_tree_view_delegate_.set_num_failures_before_success(0);
        layer_tree_view_delegate_.set_num_requests_before_success(0);
        break;
      case kBindContextFailure:
        layer_tree_view_delegate_.set_num_failures_before_success(
            tries_before_success);
        layer_tree_view_delegate_.set_num_requests_before_success(0);
        break;
      case kGpuChannelFailure:
        layer_tree_view_delegate_.set_num_failures_before_success(0);
        layer_tree_view_delegate_.set_num_requests_before_success(
            tries_before_success);
        break;
    }
    base::RunLoop run_loop;
    layer_tree_view_.SetUp(expected_successes, kTries, failure_mode, &run_loop);
    layer_tree_view_.SetVisible(true);
    blink::scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &LayerTreeViewWithFrameSinkTracking::SynchronousComposite,
            base::Unretained(&layer_tree_view_)));
    run_loop.Run();
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  cc::TestTaskGraphRunner test_task_graph_runner_;
  std::unique_ptr<PageScheduler> dummy_page_scheduler_;
  FakeLayerTreeViewDelegate layer_tree_view_delegate_;
  LayerTreeViewWithFrameSinkTracking layer_tree_view_;
};

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedOnce) {
  RunTest(1, kNoFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedOnce_AfterNullChannel) {
  RunTest(1, kGpuChannelFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedOnce_AfterLostContext) {
  RunTest(1, kBindContextFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedTwice) {
  RunTest(2, kNoFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedTwice_AfterNullChannel) {
  RunTest(2, kGpuChannelFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, SucceedTwice_AfterLostContext) {
  RunTest(2, kBindContextFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, FailWithNullChannel) {
  RunTest(0, kGpuChannelFailure);
}

TEST_F(LayerTreeViewWithFrameSinkTrackingTest, FailWithLostContext) {
  RunTest(0, kBindContextFailure);
}

class VisibilityTestLayerTreeView : public LayerTreeView {
 public:
  VisibilityTestLayerTreeView(StubLayerTreeViewDelegate* delegate,
                              PageScheduler& scheduler)
      : LayerTreeView(delegate, scheduler.CreateWidgetScheduler()) {}

  void RequestNewLayerTreeFrameSink() override {
    LayerTreeView::RequestNewLayerTreeFrameSink();
    num_requests_sent_++;
    if (run_loop_)
      run_loop_->Quit();
  }

  void set_run_loop(base::RunLoop* run_loop) { run_loop_ = run_loop; }
  int num_requests_sent() { return num_requests_sent_; }

 private:
  int num_requests_sent_ = 0;
  raw_ptr<base::RunLoop> run_loop_;
};

TEST(LayerTreeViewTest, VisibilityTest) {
  // Test that LayerTreeView does not retry FrameSink request while
  // invisible.

  base::test::TaskEnvironment task_environment;

  cc::TestTaskGraphRunner test_task_graph_runner;
  auto page_scheduler = scheduler::CreateDummyPageScheduler();
  // Synchronously callback with null FrameSink.
  StubLayerTreeViewDelegate layer_tree_view_delegate;
  VisibilityTestLayerTreeView layer_tree_view(&layer_tree_view_delegate,
                                              *page_scheduler);

  layer_tree_view.Initialize(
      cc::LayerTreeSettings(),
      blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
      /*compositor_thread=*/nullptr, &test_task_graph_runner);

  {
    // Make one request and stop immediately while invisible.
    base::RunLoop run_loop;
    layer_tree_view.set_run_loop(&run_loop);
    layer_tree_view.SetVisible(false);
    layer_tree_view.RequestNewLayerTreeFrameSink();
    run_loop.Run();
    layer_tree_view.set_run_loop(nullptr);
    EXPECT_EQ(1, layer_tree_view.num_requests_sent());
  }

  {
    // Make sure there are no more requests.
    base::RunLoop run_loop;
    run_loop.RunUntilIdle();
    EXPECT_EQ(1, layer_tree_view.num_requests_sent());
  }

  {
    // Becoming visible retries request.
    base::RunLoop run_loop;
    layer_tree_view.set_run_loop(&run_loop);
    layer_tree_view.SetVisible(true);
    run_loop.Run();
    layer_tree_view.set_run_loop(nullptr);
    EXPECT_EQ(2, layer_tree_view.num_requests_sent());
  }
}

// Tests that presentation callbacks are only called on successful
// presentations.
TEST(LayerTreeViewTest, RunPresentationCallbackOnSuccess) {
  base::test::TaskEnvironment task_environment;

  cc::TestTaskGraphRunner test_task_graph_runner;
  std::unique_ptr<PageScheduler> dummy_page_scheduler =
      scheduler::CreateDummyPageScheduler();
  StubLayerTreeViewDelegate layer_tree_view_delegate;
  LayerTreeView layer_tree_view(&layer_tree_view_delegate,
                                dummy_page_scheduler->CreateWidgetScheduler());

  layer_tree_view.Initialize(
      cc::LayerTreeSettings(),
      blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
      /*compositor_thread=*/nullptr, &test_task_graph_runner);

  // Register a callback for frame 1.
  base::TimeTicks callback_timestamp;
  layer_tree_view.AddPresentationCallback(
      1, base::BindLambdaForTesting(
             [&](const viz::FrameTimingDetails& frame_timing_details) {
               callback_timestamp =
                   frame_timing_details.presentation_feedback.timestamp;
             }));

  // Respond with a failed presentation feedback for frame 1 and verify that the
  // callback is not called
  base::TimeTicks fail_timestamp =
      base::TimeTicks::Now() + base::Microseconds(2);
  gfx::PresentationFeedback fail_feedback(fail_timestamp, base::TimeDelta(),
                                          gfx::PresentationFeedback::kFailure);
  viz::FrameTimingDetails frame_timing_details;
  frame_timing_details.presentation_feedback = fail_feedback;
  layer_tree_view.DidPresentCompositorFrame(1, frame_timing_details);
  EXPECT_TRUE(callback_timestamp.is_null());

  // Respond with a successful presentation feedback for frame 2 and verify that
  // the callback for frame 1 is now called with presentation timestamp for
  // frame 2.
  base::TimeTicks success_timestamp = fail_timestamp + base::Microseconds(3);
  gfx::PresentationFeedback success_feedback(success_timestamp,
                                             base::TimeDelta(), 0);
  viz::FrameTimingDetails frame_timing_details2;
  frame_timing_details2.presentation_feedback = success_feedback;
  layer_tree_view.DidPresentCompositorFrame(2, frame_timing_details2);
  EXPECT_FALSE(callback_timestamp.is_null());
  EXPECT_NE(callback_timestamp, fail_timestamp);
  EXPECT_EQ(callback_timestamp, success_timestamp);
}

class LayerTreeViewDelegateChangeTest : public testing::Test {
 public:
  LayerTreeViewDelegateChangeTest()
      : dummy_page_scheduler_(scheduler::CreateDummyPageScheduler()),
        layer_tree_view_(&old_layer_tree_view_delegate_,
                         dummy_page_scheduler_->CreateWidgetScheduler()) {
    cc::LayerTreeSettings settings;
    settings.single_thread_proxy_scheduler = false;
    layer_tree_view_.Initialize(
        settings, blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
        /*compositor_thread=*/nullptr, &test_task_graph_runner_);
    layer_tree_view_.SetVisible(true);
  }

  LayerTreeViewDelegateChangeTest(const LayerTreeViewDelegateChangeTest&) =
      delete;
  LayerTreeViewDelegateChangeTest& operator=(
      const LayerTreeViewDelegateChangeTest&) = delete;

  void SwapDelegate() {
    layer_tree_view_.ClearPreviousDelegateAndReattachIfNeeded(
        &new_layer_tree_view_delegate_,
        dummy_page_scheduler_->CreateWidgetScheduler());
  }

 protected:
  class FakeLayerTreeViewDelegate : public StubLayerTreeViewDelegate {
   public:
    void RequestNewLayerTreeFrameSink(
        LayerTreeFrameSinkCallback callback) override {
      EXPECT_FALSE(did_request_frame_sink_);
      did_request_frame_sink_ = true;

      if (service_frame_sink_request_) {
        auto context_provider = viz::TestContextProvider::Create();
        std::move(callback).Run(
            cc::FakeLayerTreeFrameSink::Create3d(std::move(context_provider)),
            nullptr);
      }
    }

    void OnDeferCommitsChanged(
        bool defer_status,
        cc::PaintHoldingReason reason,
        std::optional<cc::PaintHoldingCommitTrigger> trigger) override {
      commit_defer_status_ = defer_status;
      last_paint_holding_trigger_ = trigger;
    }

    std::unique_ptr<cc::RenderFrameMetadataObserver> CreateRenderFrameObserver()
        override {
      EXPECT_FALSE(did_request_frame_observer_);
      did_request_frame_observer_ = true;
      return nullptr;
    }

    bool GetAndResetDidRequestFrameSink() {
      bool val = did_request_frame_sink_;
      did_request_frame_sink_ = false;
      return val;
    }

    bool GetAndResetDidRequestFrameObserver() {
      bool val = did_request_frame_observer_;
      did_request_frame_observer_ = false;
      return val;
    }

    void set_service_frame_sink_request() {
      service_frame_sink_request_ = true;
    }

    bool commit_defer_status() const { return commit_defer_status_; }

    const std::optional<cc::PaintHoldingCommitTrigger>&
    last_paint_holding_trigger() const {
      return last_paint_holding_trigger_;
    }

   private:
    bool did_request_frame_sink_ = false;
    bool did_request_frame_observer_ = false;
    bool service_frame_sink_request_ = false;
    bool commit_defer_status_ = false;
    std::optional<cc::PaintHoldingCommitTrigger> last_paint_holding_trigger_;
  };

  class LayerTreeViewForTesting : public LayerTreeView {
   public:
    LayerTreeViewForTesting(LayerTreeViewDelegate* delegate,
                            scoped_refptr<scheduler::WidgetScheduler> scheduler)
        : LayerTreeView(delegate, std::move(scheduler)) {}

    void set_suppress_initialization_success() {
      suppress_initialization_success_ = true;
    }

    void DidInitializeLayerTreeFrameSink() override {
      EXPECT_FALSE(did_initialize_frame_sink_);
      did_initialize_frame_sink_ = true;

      if (suppress_initialization_success_) {
        return;
      }

      LayerTreeView::DidInitializeLayerTreeFrameSink();
    }

    bool GetAndResetDidInitializeFrameSink() {
      bool val = did_initialize_frame_sink_;
      did_initialize_frame_sink_ = true;
      return val;
    }

   private:
    bool suppress_initialization_success_ = false;
    bool did_initialize_frame_sink_ = false;
  };

  base::test::TaskEnvironment task_environment_;
  cc::TestTaskGraphRunner test_task_graph_runner_;
  std::unique_ptr<PageScheduler> dummy_page_scheduler_;

  FakeLayerTreeViewDelegate old_layer_tree_view_delegate_;
  FakeLayerTreeViewDelegate new_layer_tree_view_delegate_;
  LayerTreeViewForTesting layer_tree_view_;
};

TEST_F(LayerTreeViewDelegateChangeTest, NoFrameSink) {
  // Swap the delegate when no FrameSink is initialized. No frame sink requests
  // should be made.
  SwapDelegate();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());

  base::TimeTicks some_time;
  layer_tree_view_.layer_tree_host()->CompositeForTest(
      some_time, true /* raster */, base::OnceClosure());
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(
      new_layer_tree_view_delegate_.GetAndResetDidRequestFrameObserver());
}

TEST_F(LayerTreeViewDelegateChangeTest, RequestBufferedBecauseInvisible) {
  // Swap the delegate while a request is buffered because the LayerTreeView was
  // hidden.
  layer_tree_view_.SetVisible(false);
  base::TimeTicks some_time;
  layer_tree_view_.layer_tree_host()->CompositeForTest(
      some_time, true /* raster */, base::OnceClosure());
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());

  SwapDelegate();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());

  layer_tree_view_.SetVisible(true);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(
      new_layer_tree_view_delegate_.GetAndResetDidRequestFrameObserver());
}

TEST_F(LayerTreeViewDelegateChangeTest, RequestPendingBeforeSwap) {
  // Swap the delegate while a request is pending with the old delegate. It
  // should be re-issued to the new delegate.
  base::TimeTicks some_time;
  layer_tree_view_.layer_tree_host()->CompositeForTest(
      some_time, true /* raster */, base::OnceClosure());
  EXPECT_TRUE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());

  SwapDelegate();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(
      new_layer_tree_view_delegate_.GetAndResetDidRequestFrameObserver());
}

TEST_F(LayerTreeViewDelegateChangeTest, SwapDuringFrameSinkInitialization) {
  // Swap the delegate while the frame sink is pending initialization in CC.
  // There should be no frame sink request on the new delegate.
  layer_tree_view_.set_suppress_initialization_success();
  old_layer_tree_view_delegate_.set_service_frame_sink_request();
  base::TimeTicks some_time;
  layer_tree_view_.layer_tree_host()->CompositeForTest(
      some_time, true /* raster */, base::OnceClosure());
  EXPECT_TRUE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(layer_tree_view_.GetAndResetDidInitializeFrameSink());

  SwapDelegate();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(
      new_layer_tree_view_delegate_.GetAndResetDidRequestFrameObserver());
}

TEST_F(LayerTreeViewDelegateChangeTest, SwapAfterFrameSinkInitialization) {
  // Swap the delegate after the frame sink is initialized in CC.
  // There should be no frame sink request on the new delegate.
  old_layer_tree_view_delegate_.set_service_frame_sink_request();
  base::TimeTicks some_time;
  layer_tree_view_.layer_tree_host()->CompositeForTest(
      some_time, true /* raster */, base::OnceClosure());
  EXPECT_TRUE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(layer_tree_view_.GetAndResetDidInitializeFrameSink());

  SwapDelegate();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(old_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_FALSE(new_layer_tree_view_delegate_.GetAndResetDidRequestFrameSink());
  EXPECT_TRUE(
      new_layer_tree_view_delegate_.GetAndResetDidRequestFrameObserver());
}

TEST_F(LayerTreeViewDelegateChangeTest, StopDeferringCommitsOnSwap) {
  EXPECT_FALSE(old_layer_tree_view_delegate_.commit_defer_status());
  EXPECT_EQ(old_layer_tree_view_delegate_.last_paint_holding_trigger(),
            std::nullopt);

  layer_tree_view_.layer_tree_host()->StartDeferringCommits(
      base::Seconds(1), cc::PaintHoldingReason::kFirstContentfulPaint);
  EXPECT_TRUE(old_layer_tree_view_delegate_.commit_defer_status());
  EXPECT_EQ(old_layer_tree_view_delegate_.last_paint_holding_trigger(),
            std::nullopt);

  SwapDelegate();
  EXPECT_FALSE(old_layer_tree_view_delegate_.commit_defer_status());
  EXPECT_EQ(old_layer_tree_view_delegate_.last_paint_holding_trigger(),
            cc::PaintHoldingCommitTrigger::kWidgetSwapped);
}

TEST_F(LayerTreeViewDelegateChangeTest, ResetEventListenerPropertiesOnSwap) {
  auto* layer_tree_host = layer_tree_view_.layer_tree_host();
  for (uint32_t i = 0;
       i <= static_cast<uint32_t>(cc::EventListenerClass::kLast); i++) {
    layer_tree_host->SetEventListenerProperties(
        static_cast<cc::EventListenerClass>(i),
        cc::EventListenerProperties::kBlocking);
  }

  SwapDelegate();

  for (uint32_t i = 0;
       i <= static_cast<uint32_t>(cc::EventListenerClass::kLast); i++) {
    EXPECT_EQ(layer_tree_host->event_listener_properties(
                  static_cast<cc::EventListenerClass>(i)),
              cc::EventListenerProperties::kNone);
  }
}

}  // namespace
}  // namespace blink
```