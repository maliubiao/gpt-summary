Response:
The user wants to understand the functionality of the `anchor_element_metrics_sender_test.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its core purpose. This file appears to be a test suite for the `AnchorElementMetricsSender` class.

Here's a breakdown of the functionalities I can identify from the code:

1. **Testing the Reporting of Anchor Element Metrics:** The core function is to verify that `AnchorElementMetricsSender` correctly reports various interactions and changes related to anchor elements to a `MockAnchorElementMetricsHost`.

2. **Simulating Anchor Element Creation and Removal:** The tests cover scenarios where anchor elements are added and removed from the DOM, both during the initial page load and dynamically through JavaScript.

3. **Tracking Viewport Visibility:** The tests check if the sender correctly reports when anchor elements enter and leave the viewport.

4. **Capturing Pointer Events:** The tests simulate mouse movements, hovers, and clicks on anchor elements and verify that corresponding events are reported.

5. **Handling Asynchronous Operations:** The tests seem to account for the asynchronous nature of some operations, like those triggered by `setTimeout` or after layout.

6. **Using a Mock Host:**  A `MockAnchorElementMetricsHost` is used to intercept and verify the metrics sent by `AnchorElementMetricsSender`.

Now, let's relate these functionalities to HTML, CSS, and JavaScript, provide examples, and discuss potential usage errors.
这是 `blink/renderer/core/html/anchor_element_metrics_sender_test.cc` 文件的前一部分，其主要功能是 **测试 `AnchorElementMetricsSender` 类**。

`AnchorElementMetricsSender` 的作用是收集和上报与页面中 `<a>` 标签（锚点元素）相关的用户交互和状态变化的指标数据。 这些指标用于分析用户行为，例如用户点击了哪些链接，哪些链接进入了用户的视野，用户在链接上悬停了多久等等。

以下是根据代码片段推断出的具体功能点：

**功能归纳:**

* **测试锚点元素的添加和移除:**  验证当页面中添加或移除 `<a>` 元素时，`AnchorElementMetricsSender` 是否能正确检测到并报告。
* **测试锚点元素进入和离开视口:** 验证当 `<a>` 元素进入或离开用户的可视区域（视口）时，`AnchorElementMetricsSender` 是否能正确报告这些事件。
* **测试锚点元素的点击事件:** 验证当用户点击 `<a>` 元素时，`AnchorElementMetricsSender` 是否能捕获并报告点击事件的相关信息。
* **测试锚点元素的指针事件 (鼠标悬停等):** 验证当用户的鼠标指针悬停在 `<a>` 元素上或移开时，`AnchorElementMetricsSender` 是否能记录并报告这些事件。
* **使用 Mock 对象进行测试:**  使用 `MockAnchorElementMetricsHost` 这个模拟类来接收 `AnchorElementMetricsSender` 发送的指标数据，并断言接收到的数据是否符合预期。
* **测试在不同场景下的行为:** 包括页面加载时，以及通过 JavaScript 动态添加/删除元素时的行为。
* **测试与导航预测功能的关系:**  该测试用例似乎与 Chromium 的导航预测功能有关，通过 feature flag `kNavigationPredictor` 进行控制。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `AnchorElementMetricsSender` 监控的是 HTML 中的 `<a>` 元素。测试用例中通过构建 HTML 字符串来模拟页面结构，包含不同的 `<a>` 标签。例如：
    ```html
    <a id="anchor1" href="https://example.com">Example Link</a>
    ```
* **JavaScript:** 测试用例使用 JavaScript 代码来动态地创建、添加和移除 `<a>` 元素，并验证 `AnchorElementMetricsSender` 的行为。例如：
    ```javascript
    const a = document.createElement('a');
    a.href = 'https://new.example.com';
    a.textContent = 'New Link';
    document.body.appendChild(a);
    ```
    测试用例还模拟了 `window.addEventListener('load', ...)`  这样的场景，这与 JavaScript 中常用的页面加载完成事件处理相关。
* **CSS:** 虽然代码片段中没有直接操作 CSS 的逻辑，但 `AnchorElementMetricsSender` 可能会受到 CSS 属性的影响，例如元素的尺寸、位置和是否可见。测试用例中使用了内联样式来设置锚点元素的高度，这会影响元素是否在视口内。例如：
    ```html
    <a href="" style="width: 300px; height: 200px;">...</a>
    ```

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 代码：

```html
<a id="link1" href="https://example.com">Link One</a>
```

并且页面加载完成后，JavaScript 执行了以下操作：

```javascript
const link = document.getElementById('link1');
// 假设用户滚动页面，使 'link1' 进入视口
// 假设一段时间后，用户将鼠标悬停在 'link1' 上
// 假设用户点击了 'link1'
```

**假设输入:**

1. 页面加载完成，包含 id 为 "link1" 的 `<a>` 元素。
2. 用户滚动页面， "link1" 进入视口。
3. 用户鼠标指针移动到 "link1" 上。
4. 用户点击了 "link1"。

**预期输出 (根据 `MockAnchorElementMetricsHost` 的方法):**

*   `elements_`: 包含一个 `mojom::blink::AnchorElementMetricsPtr` 对象，描述了 "link1" 的基本信息 (例如 `anchor_id`)。
*   `entered_viewport_`: 包含一个 `mojom::blink::AnchorElementEnteredViewportPtr` 对象，记录了 "link1" 进入视口的时间等信息。
*   `pointer_over_`: 包含一个 `mojom::blink::AnchorElementPointerOverPtr` 对象，记录了鼠标悬停在 "link1" 上的事件和时间。
*   `clicks_`: 包含一个 `mojom::blink::AnchorElementClickPtr` 对象，记录了 "link1" 的点击事件和相关信息。

**用户或编程常见的使用错误 (与本测试文件间接相关):**

尽管这个测试文件本身不涉及用户或编程错误，但它测试的功能是为了确保 Chromium 能够正确收集锚点元素的指标。  以下是一些可能导致指标收集不准确的场景：

* **动态修改 `<a>` 标签的属性后没有触发重新渲染:**  如果 JavaScript 代码在修改了 `<a>` 标签的 `href` 或其他重要属性后，没有触发浏览器的重新渲染或布局，可能导致 `AnchorElementMetricsSender` 收集到过时的信息。
* **在非常短的时间内频繁添加和删除 `<a>` 标签:**  如果 JavaScript 代码在极短的时间内大量添加和删除 `<a>` 标签，可能会导致指标上报出现遗漏或错误。
* **嵌套在复杂的 Shadow DOM 结构中的 `<a>` 标签:** 在复杂的 Shadow DOM 结构中，`AnchorElementMetricsSender` 可能需要特殊的处理来正确识别和跟踪 `<a>` 元素。 这也是为什么测试用例中包含对 Shadow DOM 的引用 (`#include "third_party/blink/renderer/core/dom/shadow_root.h"`)。

总而言之，`anchor_element_metrics_sender_test.cc` 的主要目的是确保 `AnchorElementMetricsSender` 能够可靠地监控和报告页面中锚点元素的各种状态和交互信息，这对于 Chromium 收集用户行为数据和进行性能分析至关重要。

### 提示词
```
这是目录为blink/renderer/core/html/anchor_element_metrics_sender_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/anchor_element_metrics_sender.h"

#include "base/containers/contains.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "cc/trees/browser_controls_params.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/synthetic_web_input_event_builders.h"
#include "third_party/blink/public/mojom/loader/navigation_predictor.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/browser_controls.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics.h"
#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"
#include "third_party/blink/renderer/core/loader/anchor_element_interaction_tracker.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

class MockAnchorElementMetricsHost
    : public mojom::blink::AnchorElementMetricsHost {
 public:
  explicit MockAnchorElementMetricsHost(
      mojo::PendingReceiver<mojom::blink::AnchorElementMetricsHost>
          pending_receiver) {
    receiver_.Bind(std::move(pending_receiver));
  }

 private:
  // mojom::blink::AnchorElementMetricsHost:
  void ReportAnchorElementClick(
      mojom::blink::AnchorElementClickPtr click) override {
    clicks_.emplace_back(std::move(click));
  }

  void ReportAnchorElementsEnteredViewport(
      WTF::Vector<mojom::blink::AnchorElementEnteredViewportPtr> elements)
      override {
    for (auto& element : elements) {
      entered_viewport_.emplace_back(std::move(element));
    }
  }

  void ReportAnchorElementsLeftViewport(
      WTF::Vector<mojom::blink::AnchorElementLeftViewportPtr> elements)
      override {
    for (auto& element : elements) {
      left_viewport_.emplace_back(std::move(element));
    }
  }

  void ReportAnchorElementPointerDataOnHoverTimerFired(
      mojom::blink::AnchorElementPointerDataOnHoverTimerFiredPtr pointer_data)
      override {
    pointer_data_on_hover_.emplace_back(std::move(pointer_data));
  }

  void ReportAnchorElementPointerOver(
      mojom::blink::AnchorElementPointerOverPtr pointer_over_event) override {
    pointer_over_.emplace_back(std::move(pointer_over_event));
  }

  void ReportAnchorElementPointerOut(
      mojom::blink::AnchorElementPointerOutPtr hover_event) override {
    pointer_hover_dwell_time_.emplace_back(std::move(hover_event));
  }

  void ReportAnchorElementPointerDown(
      mojom::blink::AnchorElementPointerDownPtr pointer_down_event) override {
    pointer_down_.emplace_back(std::move(pointer_down_event));
  }

  void ReportAnchorElementsPositionUpdate(
      WTF::Vector<mojom::blink::AnchorElementPositionUpdatePtr>
          position_updates) override {
    for (auto& position_update : position_updates) {
      positions_[position_update->anchor_id] = std::move(position_update);
    }
  }

  void ReportNewAnchorElements(
      WTF::Vector<mojom::blink::AnchorElementMetricsPtr> elements,
      const WTF::Vector<uint32_t>& removed_elements) override {
    for (auto& element : elements) {
      auto [it, inserted] = anchor_ids_.insert(element->anchor_id);
      // Ignore duplicates.
      if (inserted) {
        elements_.emplace_back(std::move(element));
      }
    }
    removed_anchor_ids_.insert(removed_elements.begin(),
                               removed_elements.end());
  }

  void ProcessPointerEventUsingMLModel(
      mojom::blink::AnchorElementPointerEventForMLModelPtr pointer_event)
      override {}

  void ShouldSkipUpdateDelays(
      ShouldSkipUpdateDelaysCallback callback) override {
    // We don't use this mechanism to disable the delay of reports, as the tests
    // cover the delaying logic.
    std::move(callback).Run(false);
  }

 public:
  std::vector<mojom::blink::AnchorElementClickPtr> clicks_;
  std::vector<mojom::blink::AnchorElementEnteredViewportPtr> entered_viewport_;
  std::vector<mojom::blink::AnchorElementLeftViewportPtr> left_viewport_;
  std::map<uint32_t, mojom::blink::AnchorElementPositionUpdatePtr> positions_;
  std::vector<mojom::blink::AnchorElementPointerOverPtr> pointer_over_;
  std::vector<mojom::blink::AnchorElementPointerOutPtr>
      pointer_hover_dwell_time_;
  std::vector<mojom::blink::AnchorElementPointerDownPtr> pointer_down_;
  std::vector<mojom::blink::AnchorElementPointerDataOnHoverTimerFiredPtr>
      pointer_data_on_hover_;
  std::vector<mojom::blink::AnchorElementMetricsPtr> elements_;
  std::set<uint32_t> anchor_ids_;
  std::set<uint32_t> removed_anchor_ids_;

 private:
  mojo::Receiver<mojom::blink::AnchorElementMetricsHost> receiver_{this};
};

class AnchorElementMetricsSenderTest : public SimTest {
 public:
  static constexpr int kViewportWidth = 400;
  static constexpr int kViewportHeight = 600;

 protected:
  AnchorElementMetricsSenderTest() = default;

  void SetUp() override {
    SimTest::SetUp();
    // Allows WidgetInputHandlerManager::InitOnInputHandlingThread() to run.
    platform_->RunForPeriod(base::Milliseconds(1));
    // Report all anchors to avoid non-deterministic behavior.
    std::map<std::string, std::string> params;
    params["random_anchor_sampling_period"] = "1";

    feature_list_.InitAndEnableFeatureWithParameters(
        features::kNavigationPredictor, params);

    IntersectionObserver::SetThrottleDelayEnabledForTesting(false);

    ResizeView(gfx::Size(kViewportWidth, kViewportHeight));
    WebView().MainFrameViewWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);

    MainFrame().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::AnchorElementMetricsHost::Name_,
        WTF::BindRepeating(&AnchorElementMetricsSenderTest::Bind,
                           WTF::Unretained(this)));
  }

  void TearDown() override {
    MainFrame().GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::AnchorElementMetricsHost::Name_, {});
    hosts_.clear();
    IntersectionObserver::SetThrottleDelayEnabledForTesting(true);
    SimTest::TearDown();
  }

  frame_test_helpers::TestWebFrameWidget* CreateWebFrameWidget(
      base::PassKey<WebLocalFrame> pass_key,
      CrossVariantMojoAssociatedRemote<
          mojom::blink::FrameWidgetHostInterfaceBase> frame_widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
          frame_widget,
      CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
          widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
          widget,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const viz::FrameSinkId& frame_sink_id,
      bool hidden,
      bool never_composited,
      bool is_for_child_local_root,
      bool is_for_nested_main_frame,
      bool is_for_scalable_page) override {
    auto* test_web_frame_widget =
        MakeGarbageCollected<frame_test_helpers::TestWebFrameWidget>(
            std::move(pass_key), std::move(frame_widget_host),
            std::move(frame_widget), std::move(widget_host), std::move(widget),
            std::move(task_runner), frame_sink_id, hidden, never_composited,
            is_for_child_local_root, is_for_nested_main_frame,
            is_for_scalable_page);
    display::ScreenInfo screen_info;
    screen_info.rect = gfx::Rect(kViewportWidth, kViewportHeight);
    test_web_frame_widget->SetInitialScreenInfo(screen_info);
    return test_web_frame_widget;
  }

  void Bind(mojo::ScopedMessagePipeHandle message_pipe_handle) {
    auto host = std::make_unique<MockAnchorElementMetricsHost>(
        mojo::PendingReceiver<mojom::blink::AnchorElementMetricsHost>(
            std::move(message_pipe_handle)));
    hosts_.push_back(std::move(host));
  }

  void ProcessEvents(size_t expected_anchors) {
    // Messages are buffered in the renderer and flushed after layout. However
    // since intersection observer detects elements that enter the viewport only
    // after layout, it takes two layout cycles for EnteredViewport messages to
    // be sent to the browser process.
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    // Fastforward execution of delayed tasks.
    if (auto* metrics_sender =
            AnchorElementMetricsSender::From(GetDocument())) {
      metrics_sender->FireUpdateTimerForTesting();
    }
    // Allow the mock host to process messages it received from the renderer.
    base::RunLoop().RunUntilIdle();
    // Wait until we've gotten the reports we expect.
    while (expected_anchors > 0 &&
           (hosts_.empty() || expected_anchors > hosts_[0]->elements_.size())) {
      // Wait 50ms.
      platform_->RunForPeriodSeconds(0.05);
      GetDocument().View()->UpdateAllLifecyclePhasesForTest();
      GetDocument().View()->UpdateAllLifecyclePhasesForTest();
      base::RunLoop().RunUntilIdle();
    }
  }

  void SetMockClock() {
    AnchorElementMetricsSender::From(GetDocument())
        ->SetTickClockForTesting(&clock_);
  }

  void VerticalScroll(float dy) {
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        SyntheticWebGestureEventBuilder::BuildScrollBegin(
            /*dx_hint=*/0.0f, /*dy_hint=*/0.0f,
            WebGestureDevice::kTouchscreen));
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        SyntheticWebGestureEventBuilder::BuildScrollUpdate(
            /*dx=*/0.0f, dy, WebInputEvent::kNoModifiers,
            WebGestureDevice::kTouchscreen));
    GetWebFrameWidget().DispatchThroughCcInputHandler(
        SyntheticWebGestureEventBuilder::Build(
            WebInputEvent::Type::kGestureScrollEnd,
            WebGestureDevice::kTouchscreen));
    Compositor().BeginFrame();
  }

  void ProcessPositionUpdates() {
    platform_->RunForPeriodSeconds(ConvertDOMHighResTimeStampToSeconds(
        AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(GetDocument())
            ->GetIntersectionObserverForTesting()
            ->delay()));
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    platform_->RunForPeriod(AnchorElementMetricsSender::kUpdateMetricsTimeGap);
    base::RunLoop().RunUntilIdle();
  }

  HTMLAnchorElement* AddAnchor(Document& document,
                               String inner_text,
                               int height) {
    auto* anchor = MakeGarbageCollected<HTMLAnchorElement>(document);
    anchor->setInnerText(inner_text);
    anchor->setHref("https://foo.com");
    anchor->SetInlineStyleProperty(CSSPropertyID::kHeight,
                                   String::Format("%dpx", height));
    anchor->SetInlineStyleProperty(CSSPropertyID::kDisplay, "block");
    document.body()->appendChild(anchor);
    return anchor;
  }

  HTMLAnchorElement* AddAnchor(String inner_text, int height) {
    return AddAnchor(GetDocument(), inner_text, height);
  }

  base::test::ScopedFeatureList feature_list_;
  std::vector<std::unique_ptr<MockAnchorElementMetricsHost>> hosts_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
  base::SimpleTestTickClock clock_;
};

// Test that anchors on non-HTTPS pages are not reported.
TEST_F(AnchorElementMetricsSenderTest, AddAnchorElementHTTP) {
  String source("http://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(
      R"HTML(<a id="anchor1" href="">example</a><a id="anchor2" href="">example</a>)HTML");

  ProcessEvents(0);
  EXPECT_EQ(0u, hosts_.size());
}

TEST_F(AnchorElementMetricsSenderTest, AddAnchorElement) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(
      R"HTML(<a id="anchor1" href="">example</a><a id="anchor2" href="">example</a>)HTML");

  ProcessEvents(2);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(2u, mock_host->entered_viewport_.size());
  EXPECT_EQ(2u, mock_host->elements_.size());
}

TEST_F(AnchorElementMetricsSenderTest, AddAnchorElementAfterLoad) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        // Add anchor 1s after onload.
        window.setTimeout(() => {
          const a = document.createElement('a');
          a.text = 'foo';
          a.href = '';
          document.body.appendChild(a);
          console.log('child appended');
        }, 1000);
      })
    </script>
  )HTML");

  // Wait until the script has had time to run.
  platform_->RunForPeriodSeconds(5.);
  ProcessEvents(1);

  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(mock_host->entered_viewport_[0]->anchor_id,
            mock_host->elements_[0]->anchor_id);
}

TEST_F(AnchorElementMetricsSenderTest, AddAndRemoveAnchorElement) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a1 = document.createElement('a');
        a1.text = 'foo';
        a1.href = '';
        document.body.appendChild(a1);
        a1.remove();
        const a2 = document.createElement('a');
        a2.text = 'bar';
        a2.href = '';
        document.body.appendChild(a2);
      });
    </script>
  )HTML");

  // `a1` was added and immediately removed, so it shouldn't be included.
  ProcessEvents(1);

  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  // Treat `a1` as if it were never added.
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());
}

TEST_F(AnchorElementMetricsSenderTest, AddAnchorElementFromDocumentFragment) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const fragment = new DocumentFragment();
        const a = document.createElement('a');
        a.text = 'foo';
        a.href = '';
        fragment.appendChild(a);
        document.body.appendChild(fragment);
      });
    </script>
  )HTML");

  ProcessEvents(1);

  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  // `a` was removed from the DocumentFragment in order to insert it into the
  // document, so it should not be considered removed.
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());
}

TEST_F(AnchorElementMetricsSenderTest, AnchorElementNeverConnected) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a1 = document.createElement('a');
        a1.text = 'a1';
        a1.href = '';
        const div = document.createElement('div');
        div.appendChild(a1);

        const a2 = document.createElement('a');
        a2.text = 'a2';
        a2.href = '';
        document.body.appendChild(a2);
      });
    </script>
  )HTML");

  // `a1` should not be processed.
  ProcessEvents(1);

  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());
}

TEST_F(AnchorElementMetricsSenderTest, RemoveAnchorElement) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a1 = document.createElement('a');
        a1.text = 'foo';
        a1.href = '';
        document.body.appendChild(a1);
        window.a1 = a1;
      });
    </script>
  )HTML");

  // Initially, `a1` should be reported.
  ProcessEvents(1);
  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  ASSERT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());
  uint32_t a1_id = mock_host->elements_[0]->anchor_id;

  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    window.a1.remove();
    const a2 = document.createElement('a');
    a2.text = 'bar';
    a2.href = '';
    document.body.appendChild(a2);
  )SCRIPT")
      ->RunScript(&Window());

  // For the next step, `a2` should be reported and `a1` should be reported as
  // removed.
  ProcessEvents(2);
  EXPECT_EQ(2u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->removed_anchor_ids_.size());
  EXPECT_TRUE(mock_host->removed_anchor_ids_.contains(a1_id));
}

TEST_F(AnchorElementMetricsSenderTest,
       RemoveAnchorElementWithoutMoreInsertions) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a1 = document.createElement('a');
        a1.text = 'foo';
        a1.href = '';
        document.body.appendChild(a1);
        window.a1 = a1;
      });
    </script>
  )HTML");

  ProcessEvents(1);
  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  ASSERT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());
  uint32_t a1_id = mock_host->elements_[0]->anchor_id;

  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    window.a1.remove();
  )SCRIPT")
      ->RunScript(&Window());

  // We should have a report of just the removal of `a1`.
  ProcessEvents(1);
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->removed_anchor_ids_.size());
  EXPECT_TRUE(mock_host->removed_anchor_ids_.contains(a1_id));
}

TEST_F(AnchorElementMetricsSenderTest, RemoveMultipleParents) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a1grandparent = document.createElement('div');
        const a1parent = document.createElement('div');
        const a1 = document.createElement('a');
        a1.text = 'a1';
        a1.href = '';
        a1parent.appendChild(a1);
        a1grandparent.appendChild(a1parent);
        document.body.appendChild(a1grandparent);

        const a2grandparent = document.createElement('div');
        const a2parent = document.createElement('div');
        const a2 = document.createElement('a');
        a2.text = 'a2';
        a2.href = '';
        a2parent.appendChild(a2);
        a2grandparent.appendChild(a2parent);
        document.body.appendChild(a2grandparent);

        window.a1 = a1;
        window.a2 = a2;
      });
    </script>
  )HTML");

  ProcessEvents(2);
  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  ASSERT_EQ(2u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());

  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    window.a1.parentNode.parentNode.remove();
    window.a1.parentNode.remove();
    window.a1.remove();

    const a2grandparent = window.a2.parentNode.parentNode;
    const a2parent = window.a2.parentNode;
    const a2 = window.a2;
    a2grandparent.remove();
    a2parent.remove();
    a2.remove();
    a2parent.appendChild(a2);
    a2grandparent.appendChild(a2parent);
    document.body.appendChild(a2grandparent);

    const a3grandparent = document.createElement('div');
    const a3parent = document.createElement('div');
    const a3 = document.createElement('a');
    a3.text = 'a3';
    a3.href = '';
    a3parent.appendChild(a3);
    a3grandparent.appendChild(a3parent);
    document.body.appendChild(a3grandparent);
    a3grandparent.remove();
    a3parent.remove();
    a3.remove();

    const a4 = document.createElement('a');
    a4.text = 'a4';
    a4.href = '';
    document.body.appendChild(a4);
  )SCRIPT")
      ->RunScript(&Window());

  ProcessEvents(3);
  EXPECT_EQ(3u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->removed_anchor_ids_.size());
}

TEST_F(AnchorElementMetricsSenderTest, RemoveAnchorElementAfterLayout) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <script>
      window.addEventListener('load', () => {
        const a0 = document.createElement('a');
        a0.text = 'a0';
        a0.href = '';
        document.body.appendChild(a0);
        window.a0 = a0;
      });
    </script>
  )HTML");

  // Report an initial anchor.
  ProcessEvents(1);
  ASSERT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->removed_anchor_ids_.size());

  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    const a1 = document.createElement('a');
    a1.text = 'a1';
    a1.href = '';
    document.body.appendChild(a1);

    const a2 = document.createElement('a');
    a2.text = 'a2';
    a2.href = '';
    document.body.appendChild(a2);

    const a3 = document.createElement('a');
    a3.text = 'a3';
    a3.href = '';
    document.body.appendChild(a3);

    const a4 = document.createElement('a');
    a4.text = 'a4';
    a4.href = '';
    document.body.appendChild(a4);

    const a5 = document.createElement('a');
    a5.text = 'a5';
    a5.href = '';
    document.body.appendChild(a5);

    window.a1 = a1;
    window.a2 = a2;
    window.a3 = a3;
    window.a4 = a4;
    window.a5 = a5;
  )SCRIPT")
      ->RunScript(&Window());

  // Layout so the metrics are buffered.
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  // Before metrics are flushed, remove the initial anchor and `a1`, remove and
  // reinsert `a2`, repeatedly remove and reinsert `a3`, repeatedly remove and
  // reinsert then remove `a4`, remove `a5`, add a new anchor `a6`.
  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    window.a0.remove();
    window.a1.remove();

    window.a2.remove();
    document.body.appendChild(window.a2);

    window.a3.remove();
    document.body.appendChild(window.a3);
    window.a3.remove();
    document.body.appendChild(window.a3);

    window.a4.remove();
    document.body.appendChild(window.a4);
    window.a4.remove();

    window.a5.remove();

    const a6 = document.createElement('a');
    a6.text = 'a6';
    a6.href = '';
    document.body.appendChild(a6);
  )SCRIPT")
      ->RunScript(&Window());

  // After another buffering of metrics, reinsert `a5`.
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  ClassicScript::CreateUnspecifiedScript(R"SCRIPT(
    document.body.appendChild(window.a5);
  )SCRIPT")
      ->RunScript(&Window());
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();

  // Flush metrics.
  // At this point, 4 of the anchors are newly inserted and still inserted, 1
  // was previously reported and removed, 2 were newly inserted but removed
  // before the flush (so they're not reported).
  ProcessEvents(5);
  EXPECT_EQ(5u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->removed_anchor_ids_.size());
}

TEST_F(AnchorElementMetricsSenderTest, AnchorElementLeftViewport) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(String::Format(
      R"HTML(
        <body style="margin: 0px">
        <div style="height: %dpx;"></div>
        <a href="" style="width: 300px; height: %dpx;">foo</a>
        </body>)HTML",
      2 * kViewportHeight, kViewportHeight / 2));

  // Check that the element is registered, but there are no other events.
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(0u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());

  SetMockClock();
  AnchorElementMetricsSender::From(GetDocument())
      ->SetNowAsNavigationStartForTesting();

  // Scroll down. Now the anchor element is visible, and should report the
  // entered viewport event. |navigation_start_to_entered_viewport| should be
  // |wait_time1|.
  const auto wait_time1 = base::Milliseconds(100);
  clock_.Advance(wait_time1);

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 2 * kViewportHeight),
      mojom::blink::ScrollType::kProgrammatic);
  ProcessEvents(1);
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(
      wait_time1,
      mock_host->entered_viewport_[0]->navigation_start_to_entered_viewport);
  EXPECT_EQ(0u, mock_host->left_viewport_.size());

  // Scroll up. It should be out of view again, and should report the left
  // viewport event. |time_in_viewport| should be |time_in_viewport_1|.
  const auto time_in_viewport_1 = base::Milliseconds(150);
  clock_.Advance(time_in_viewport_1);
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, -2 * kViewportHeight),
      mojom::blink::ScrollType::kProgrammatic);
  ProcessEvents(1);
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(1u, mock_host->left_viewport_.size());
  EXPECT_EQ(time_in_viewport_1, mock_host->left_viewport_[0]->time_in_viewport);

  // Scroll down to make it visible again. It should send a second entered
  // viewport event. |navigation_start_to_entered_viewport| should be
  // |wait_time1+time_in_viewport_1+wait_time2|.
  const auto wait_time2 = base::Milliseconds(100);
  clock_.Advance(wait_time2);
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 2 * kViewportHeight),
      mojom::blink::ScrollType::kProgrammatic);
  ProcessEvents(1);
  EXPECT_EQ(2u, mock_host->entered_viewport_.size());
  EXPECT_EQ(
      wait_time1 + time_in_viewport_1 + wait_time2,
      mock_host->entered_viewport_[1]->navigation_start_to_entered_viewport);
  EXPECT_EQ(1u, mock_host->left_viewport_.size());

  // Scroll up to push it out of view again. It should send a second left
  // viewport event, and |time_in_viewport| should be |time_in_viewport_2|.
  const auto time_in_viewport_2 = base::Milliseconds(30);
  clock_.Advance(time_in_viewport_2);
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, -2 * kViewportHeight),
      mojom::blink::ScrollType::kProgrammatic);
  ProcessEvents(1);
  EXPECT_EQ(2u, mock_host->entered_viewport_.size());
  EXPECT_EQ(2u, mock_host->left_viewport_.size());
  EXPECT_EQ(time_in_viewport_2, mock_host->left_viewport_[1]->time_in_viewport);
}

TEST_F(AnchorElementMetricsSenderTest,
       AnchorElementInteractionTrackerSendsPointerEvents) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(String::Format(
      R"HTML(
        <body style="margin: 0px">
        <a href="" style="width: %dpx; height: %dpx;">foo</a>
        </body>)HTML",
      kViewportWidth, kViewportHeight / 2));

  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());
  EXPECT_EQ(0u, mock_host->pointer_over_.size());
  EXPECT_EQ(0u, mock_host->pointer_hover_dwell_time_.size());

  auto move_to = [this](const auto x, const auto y) {
    gfx::PointF coordinates(x, y);
    WebMouseEvent event(WebInputEvent::Type::kMouseMove, coordinates,
                        coordinates, WebPointerProperties::Button::kNoButton, 0,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
        event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());
  };
  using Button = WebPointerProperties::Button;
  auto mouse_press = [this](const auto x, const auto y, const auto button) {
    gfx::PointF coordinates(x, y);
    WebInputEvent::Modifiers modifier = WebInputEvent::kLeftButtonDown;
    if (button == Button::kMiddle) {
      modifier = WebInputEvent::kMiddleButtonDown;
    } else if (button == Button::kMiddle) {
      modifier = WebInputEvent::kRightButtonDown;
    }
    WebMouseEvent event(WebInputEvent::Type::kMouseDown, coordinates,
                        coordinates, button, 0, modifier,
                        WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);
  };

  SetMockClock();
  AnchorElementMetricsSender::From(GetDocument())
      ->SetNowAsNavigationStartForTesting();
  // Move the pointer over the link for the first time. We should send pointer
  // over event. |navigation_start_to_pointer_over| should be |wait_time_1|.
  const auto wait_time_1 = base::Milliseconds(150);
  clock_.Advance(wait_time_1);
  move_to(0, 0);
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->pointer_over_.size());
  EXPECT_EQ(mock_host->elements_[0]->anchor_id,
            mock_host->pointer_over_[0]->anchor_id);
  EXPECT_EQ(wait_time_1,
            mock_host->pointer_over_[0]->navigation_start_to_pointer_over);
  EXPECT_EQ(0u, mock_host->pointer_hover_dwell_time_.size());

  // Move the pointer away. We should send pointer hover event and
  // |hover_dwell_time| should be |hover_dwell_time_1|.
  const auto hover_dwell_time_1 = base::Milliseconds(250);
  clock_.Advance(hover_dwell_time_1);
  move_to(kViewportWidth / 2, kViewportHeight);
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(1u, mock_host->pointer_over_.size());
  EXPECT_EQ(1u, mock_host->pointer_hover_dwell_time_.size());
  EXPECT_EQ(mock_host->elements_[0]->anchor_id,
            mock_host->pointer_hover_dwell_time_[0]->anchor_id);
  EXPECT_EQ(hover_dwell_time_1,
            mock_host->pointer_hover_dwell_time_[0]->hover_dwell_time);

  // Move the pointer over the link for a second time. We should send pointer
  // over event. |navigation_start_to_pointer_over| should be
  // |wait_time_1+hover_dwell_time_1+wait_time_2|.
  const auto wait_time_2 = base::Milliseconds(50);
  clock_.Advance(wait_time_2);
  move_to(0, 0);
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  EXPECT_EQ(0u, mock_host->clicks_.
```