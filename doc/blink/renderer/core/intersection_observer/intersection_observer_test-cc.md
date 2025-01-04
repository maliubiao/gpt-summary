Response:
The user is asking for a summary of the functionality of the provided C++ code file. The file is a unit test file for the `IntersectionObserver` API in the Chromium Blink rendering engine.

To summarize, the file tests the correct behavior of the `IntersectionObserver` API, focusing on:

1. **Core Functionality:** How the observer detects when an element intersects with its root (viewport or a specified element).
2. **Configuration Options:**  Testing how parameters like `threshold`, `rootMargin`, and `scrollMargin` affect intersection detection.
3. **Integration with Rendering Lifecycle:**  Verifying that the observer correctly interacts with layout, painting, scrolling, and compositing.
4. **Edge Cases and Error Handling:** Testing scenarios like removing the root element, targets becoming invisible, or having zero-sized dimensions.
5. **Interaction with JavaScript and DOM:**  Confirming the correct triggering of callbacks and the structure of the `IntersectionObserverEntry` objects.

Now, let's break down the request and address each point:

*   **List the functionalities:** Identify the key aspects of the `IntersectionObserver` being tested.
*   **Relation to JavaScript, HTML, CSS:** Explain how the tested C++ code relates to the web developer-facing APIs and technologies. Provide examples of how JavaScript uses the `IntersectionObserver`, how HTML structures the elements being observed, and how CSS affects their layout and visibility.
*   **Logic Reasoning (Assumptions and Outputs):**  For some tests, outline the setup (input) and the expected outcome (output).
*   **Common User/Programming Errors:**  Think about how a developer might misuse the `IntersectionObserver` API and give examples.
*   **Overall Functionality Summary:**  Provide a concise summary of the purpose of the test file.
这是对 Chromium Blink 引擎中 `IntersectionObserver` 功能进行单元测试的 C++ 代码文件。它的主要功能是验证 `IntersectionObserver` API 的各种行为和边缘情况是否符合预期。

以下是根据提供的代码片段归纳出的功能点，并解释了它们与 JavaScript, HTML, CSS 的关系，以及可能涉及的逻辑推理和常见错误：

**功能归纳:**

1. **基本的 Intersection 检测:** 测试 `IntersectionObserver` 能否正确检测到目标元素与根元素（默认是视口，也可以是指定的元素）是否相交。
2. **`rootMargin` 和 `scrollMargin` 的作用:**  验证 `rootMargin`（根元素的边距）和 `scrollMargin`（滚动容器的边距）参数如何影响 Intersection 的计算。
3. **嵌套滚动容器的处理:**  测试在嵌套的滚动容器中，`IntersectionObserver` 是否能正确计算 Intersection。
4. **性能优化：`minScrollDeltaToUpdate`:** 验证 `IntersectionObserver` 如何利用 `minScrollDeltaToUpdate` 来优化性能，避免不必要的更新。
5. **异步通知机制:**  确认 `IntersectionObserver` 的通知是异步的，会在下一帧渲染时触发回调。
6. **根元素被移除的场景:**  测试当 `IntersectionObserver` 的根元素被移除时，是否会发送相应的通知。
7. **iframe 中的 Intersection:** 验证 `IntersectionObserver` 在 iframe 环境中是否能正常工作。
8. **`intersectionRatio` 的计算:** 测试 `IntersectionObserver` 能否正确报告目标元素与根元素相交的比例。
9. **`threshold` 参数的作用:**  验证 `threshold` 参数（相交比例的阈值）如何控制回调的触发。
10. **目标元素变换（transform）的影响:** 测试目标元素应用 CSS transform 后，`IntersectionObserver` 是否能正确计算 Intersection。
11. **目标元素 visibility 属性的影响:** 测试目标元素的 `visibility: hidden` 属性变化时，`IntersectionObserver` 的行为。
12. **页面暂停和恢复的影响:**  验证当页面暂停和恢复时，`IntersectionObserver` 的通知机制是否正确。
13. **在 Mutation 之后进行 HitTest:**  测试在 DOM 发生变化后，`IntersectionObserver` 是否能进行正确的 hit-test。
14. **`disconnect()` 方法的作用:**  验证调用 `disconnect()` 方法后，`IntersectionObserver` 会停止观察，并且清除未发送的通知。
15. **在 `forceZeroLayoutHeight` 模式下的行为:** 测试在一种特殊模式下，`IntersectionObserver` 与根元素的 Intersection 计算。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **JavaScript:**  `IntersectionObserver` 是一个 JavaScript API，用于异步观察目标元素与其祖先元素或视口交叉状态的变化。开发者通过 JavaScript 创建 `IntersectionObserver` 实例，并提供一个回调函数来处理 Intersection 事件。

    ```javascript
    const target = document.getElementById('target');
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          console.log('Target is intersecting!');
          // 执行一些操作，例如加载图片或触发动画
        } else {
          console.log('Target is not intersecting.');
        }
      });
    });
    observer.observe(target);
    ```

*   **HTML:** HTML 用于定义需要被观察的目标元素和作为根元素的容器（如果需要）。

    ```html
    <div id="root" style="overflow: scroll; height: 200px;">
      <div id="target" style="width: 100px; height: 100px;"></div>
    </div>
    ```

*   **CSS:** CSS 可以影响元素的大小、位置、可见性、滚动容器的属性等，这些都会影响 `IntersectionObserver` 的计算结果。例如，`overflow: scroll` 可以创建一个滚动容器，`transform` 会改变元素的布局。

    ```css
    #scroller { width: 100px; height: 100px; overflow: scroll; }
    #target { width: 50px; height: 50px; }
    ```

**逻辑推理 (假设输入与输出):**

例如，在 `TestScrollMargin` 函数中：

*   **假设输入:**  `scroll_margin` 设置为一个特定的值，HTML 结构中有一个滚动容器 `#scroller` 和一个目标元素 `#target`。滚动容器的滚动位置使得目标元素部分可见或不可见。
*   **预期输出:**  `IntersectionObserver` 的回调函数会被调用一次，返回的 `IntersectionObserverEntry` 对象的 `isIntersecting` 属性和 `intersectionRatio` 属性会根据 `scroll_margin` 的设置和目标元素的可见性返回预期的布尔值和数值。

    例如，如果 `scroll_margin` 设置为正值，相当于增大了滚动容器的有效可视区域，即使目标元素实际未完全进入滚动容器的物理边界，也可能被判定为相交。反之，负值则会缩小有效可视区域。

**用户或编程常见的使用错误举例:**

1. **忘记调用 `observe()` 方法:** 创建了 `IntersectionObserver` 实例，但忘记调用 `observe()` 方法来监听目标元素，导致回调永远不会被触发。
2. **误解 `rootMargin` 的作用:**  错误地认为 `rootMargin` 是目标元素的边距，实际上它是根元素的边距，用于扩展或缩小根元素的裁剪边界。
3. **在回调函数中执行耗时操作:** `IntersectionObserver` 的回调会在主线程执行，如果在回调中执行大量的同步操作，可能会导致页面卡顿。应该尽量将耗时操作放在异步任务中执行。
4. **不理解 `threshold` 的作用:**  对 `threshold` 参数的理解有误，导致回调触发的时机与预期不符。例如，希望元素完全可见时才触发回调，但 `threshold` 设置的过小。
5. **在不需要时没有 `disconnect()` 观察器:** 如果不再需要观察某个元素，没有调用 `disconnect()` 方法，可能会导致内存泄漏和不必要的性能消耗。
6. **在元素被移除后继续持有观察器的引用:**  即使目标元素从 DOM 中移除，如果 JavaScript 代码中仍然持有该元素的观察器的引用，观察器可能仍然会尝试执行回调，导致错误。

**总结:**

总而言之，`blink/renderer/core/intersection_observer/intersection_observer_test.cc` 这个文件通过各种单元测试，确保 Chromium Blink 引擎中的 `IntersectionObserver` API 的实现是正确、健壮和符合规范的。它涵盖了 API 的核心功能、配置选项、与浏览器渲染机制的交互以及各种边界情况。这些测试对于保证 Web 开发者能够可靠地使用 `IntersectionObserver` API 构建功能丰富的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/intersection_observer/intersection_observer.h"

#include "build/build_config.h"
#include "third_party/blink/renderer/bindings/core/v8/sanitize_script_errors.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_intersection_observer_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_document_element.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_doublesequence.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/intersection_observer/element_intersection_observer_data.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_controller.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_delegate.h"
#include "third_party/blink/renderer/core/intersection_observer/intersection_observer_entry.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/intersection_observer_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "ui/gfx/geometry/test/geometry_util.h"

namespace blink {

class IntersectionObserverTest : public SimTest {
 protected:
  void TestScrollMargin(int scroll_margin,
                        bool is_intersecting,
                        double intersectionRatio) {
    WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");
    main_resource.Complete(R"HTML(
    <style>
    #scroller { width: 100px; height: 100px; overflow: scroll; }
    #spacer { width: 50px; height: 110px; }
    #target { width: 50px; height: 50px; }
    </style>

    <div id=scroller>
      <div id=spacer></div>
      <div id=target></div>
    </div>
  )HTML");

    Compositor().BeginFrame();

    Element* target = GetDocument().getElementById(AtomicString("target"));
    ASSERT_TRUE(target);

    TestIntersectionObserverDelegate* scroll_margin_delegate =
        MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

    IntersectionObserver* scroll_margin_observer =
        MakeGarbageCollected<IntersectionObserver>(
            *scroll_margin_delegate,
            LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
            IntersectionObserver::Params{
                .margin = {Length::Fixed(10)},
                .scroll_margin = {Length::Fixed(scroll_margin)},
                .thresholds = {
                    std::numeric_limits<float>::min(),
                }});

    DummyExceptionStateForTesting exception_state;
    scroll_margin_observer->observe(target, exception_state);
    ASSERT_FALSE(exception_state.HadException());

    Compositor().BeginFrame();
    test::RunPendingTasks();
    ASSERT_FALSE(Compositor().NeedsBeginFrame());

    EXPECT_EQ(scroll_margin_delegate->CallCount(), 1);
    EXPECT_EQ(scroll_margin_delegate->EntryCount(), 1);
    EXPECT_EQ(is_intersecting,
              scroll_margin_delegate->LastEntry()->isIntersecting());
    EXPECT_NEAR(intersectionRatio,
                scroll_margin_delegate->LastEntry()->intersectionRatio(),
                0.001);
  }

  void TestScrollMarginNested(int scroll_margin,
                              bool is_intersecting,
                              double intersectionRatio) {
    WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");
    main_resource.Complete(R"HTML(
    <style>
    #scroller { width: 100px; height: 100px; overflow: scroll; }
    #scroller2 { width: 130px; height: 130px; overflow: scroll; }
    #spacer { width: 10px; height: 110px; }
    #target { width: 50px; height: 50px; }
    </style>

    <div id=scroller2>
      <div id=scroller>
        <div id=spacer></div>
        <div id=target></div>
      </div>
    </div>
  )HTML");

    Compositor().BeginFrame();

    Element* target = GetDocument().getElementById(AtomicString("target"));
    ASSERT_TRUE(target);

    TestIntersectionObserverDelegate* scroll_margin_delegate =
        MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

    IntersectionObserver* scroll_margin_observer =
        MakeGarbageCollected<IntersectionObserver>(
            *scroll_margin_delegate,
            LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
            IntersectionObserver::Params{
                .margin = {Length::Fixed(10)},
                .scroll_margin = {Length::Fixed(scroll_margin)},
                .thresholds = {std::numeric_limits<float>::min()}});

    DummyExceptionStateForTesting exception_state;
    scroll_margin_observer->observe(target, exception_state);
    ASSERT_FALSE(exception_state.HadException());

    Compositor().BeginFrame();
    test::RunPendingTasks();
    ASSERT_FALSE(Compositor().NeedsBeginFrame());

    EXPECT_EQ(scroll_margin_delegate->CallCount(), 1);
    EXPECT_EQ(scroll_margin_delegate->EntryCount(), 1);
    EXPECT_EQ(is_intersecting,
              scroll_margin_delegate->LastEntry()->isIntersecting());
    EXPECT_NEAR(intersectionRatio,
                scroll_margin_delegate->LastEntry()->intersectionRatio(),
                0.001);
  }

  void TestMinScrollDeltaToUpdateWithIntermediateClip() {
    Element* root = GetDocument().getElementById(AtomicString("root"));
    Element* target = GetDocument().getElementById(AtomicString("target"));
    LocalFrameView* frame_view = GetDocument().View();

    auto* observer_init = IntersectionObserverInit::Create();
    observer_init->setRoot(
        MakeGarbageCollected<V8UnionDocumentOrElement>(root));
    DummyExceptionStateForTesting exception_state;
    TestIntersectionObserverDelegate* observer_delegate =
        MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
    IntersectionObserver* observer = IntersectionObserver::Create(
        observer_init, *observer_delegate,
        LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
        exception_state);
    ASSERT_FALSE(exception_state.HadException());
    observer->observe(target, exception_state);
    ASSERT_FALSE(exception_state.HadException());
    const IntersectionObservation* observation =
        target->IntersectionObserverData()->GetObservationFor(*observer);
    EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kRequired,
              frame_view->GetIntersectionObservationStateForTesting());

    Compositor().BeginFrame();
    test::RunPendingTasks();
    EXPECT_EQ(observer_delegate->CallCount(), 1);
    EXPECT_EQ(observer_delegate->EntryCount(), 1);
    EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
    EXPECT_EQ(gfx::Vector2dF(50, 100), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kNotNeeded,
              frame_view->GetIntersectionObservationStateForTesting());

    root->scrollTo(0, 50);
    EXPECT_EQ(gfx::Vector2dF(50, 100), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
              frame_view->GetIntersectionObservationStateForTesting());
    Compositor().BeginFrame();
    test::RunPendingTasks();
    EXPECT_EQ(observer_delegate->CallCount(), 1);
    EXPECT_EQ(observer_delegate->EntryCount(), 1);
    EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());

    root->scrollTo(0, 100);
    EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
              frame_view->GetIntersectionObservationStateForTesting());
    Compositor().BeginFrame();
    test::RunPendingTasks();
    EXPECT_EQ(observer_delegate->CallCount(), 2);
    EXPECT_EQ(observer_delegate->EntryCount(), 2);
    EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
    EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kNotNeeded,
              frame_view->GetIntersectionObservationStateForTesting());

    root->scrollTo(0, 101);
    EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
              frame_view->GetIntersectionObservationStateForTesting());
    Compositor().BeginFrame();
    test::RunPendingTasks();
    EXPECT_EQ(observer_delegate->CallCount(), 2);
    EXPECT_EQ(observer_delegate->EntryCount(), 2);
    EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
    EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
    EXPECT_EQ(LocalFrameView::kNotNeeded,
              frame_view->GetIntersectionObservationStateForTesting());
  }

  bool CanUseCachedRects(const IntersectionObservation& observation) {
    return observation.CanUseCachedRectsForTesting(
        GetDocument().View()->GetIntersectionObservationStateForTesting() <=
        LocalFrameView::kScrollAndVisibilityOnly);
  }
};

class IntersectionObserverV2Test : public IntersectionObserverTest {
 public:
  IntersectionObserverV2Test() {
    IntersectionObserver::SetThrottleDelayEnabledForTesting(false);
  }

  ~IntersectionObserverV2Test() override {
    IntersectionObserver::SetThrottleDelayEnabledForTesting(true);
  }
};

TEST_F(IntersectionObserverTest, ObserveSchedulesFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete("<div id='target'></div>");

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_TRUE(observer->takeRecords(exception_state).empty());
  EXPECT_EQ(observer_delegate->CallCount(), 0);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);
  EXPECT_TRUE(Compositor().NeedsBeginFrame());
}

TEST_F(IntersectionObserverTest, NotificationSentWhenRootRemoved) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    #target {
      width: 100px;
      height: 100px;
    }
    </style>
    <div id='root'>
      <div id='target'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* root = GetDocument().getElementById(AtomicString("root"));
  ASSERT_TRUE(root);
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());

  root->remove();
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, DocumentRootClips) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest iframe_resource("https://example.com/iframe.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <iframe src="iframe.html" style="width:200px; height:100px"></iframe>
  )HTML");
  iframe_resource.Complete(R"HTML(
    <div id='target'>Hello, world!</div>
    <div id='spacer' style='height:2000px'></div>
  )HTML");
  Compositor().BeginFrame();

  Document* iframe_document = To<WebLocalFrameImpl>(MainFrame().FirstChild())
                                  ->GetFrame()
                                  ->GetDocument();
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(
      MakeGarbageCollected<V8UnionDocumentOrElement>(iframe_document));
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  Element* target = iframe_document->getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());

  iframe_document->View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 1000), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, ReportsFractionOfTargetOrRoot) {
  // Place a 100x100 target element in the middle of a 200x200 main frame.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    #target {
      position: absolute;
      top: 50px; left: 50px; width: 100px; height: 100px;
    }
    </style>
    <div id='target'></div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  // 100% of the target element's area intersects with the frame.
  constexpr float kExpectedFractionOfTarget = 1.0f;

  // 25% of the frame's area is covered by the target element.
  constexpr float kExpectedFractionOfRoot = 0.25f;

  TestIntersectionObserverDelegate* target_observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* target_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_observer_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {kExpectedFractionOfTarget / 2},
          });

  DummyExceptionStateForTesting exception_state;
  target_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  TestIntersectionObserverDelegate* root_observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* root_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *root_observer_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {kExpectedFractionOfRoot / 2},
              .semantics = IntersectionObserver::kFractionOfRoot});

  root_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 1);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(target_observer_delegate->LastEntry()->isIntersecting());
  EXPECT_NEAR(kExpectedFractionOfTarget,
              target_observer_delegate->LastEntry()->intersectionRatio(), 1e-6);

  EXPECT_EQ(root_observer_delegate->CallCount(), 1);
  EXPECT_EQ(root_observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(root_observer_delegate->LastEntry()->isIntersecting());
  EXPECT_NEAR(kExpectedFractionOfRoot,
              root_observer_delegate->LastEntry()->intersectionRatio(), 1e-6);
}

TEST_F(IntersectionObserverTest, TargetRectIsEmptyAfterMapping) {
  // Place a 100x100 target element in the middle of a 200x200 main frame.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    .clipper {
      transform: rotatey(90deg);
    }
    .container {
      overflow: hidden;
    }
    #target {
      width: 10px;
      height: 10px;
    }
    </style>
    <div class=clipper>
      <div class=container>
        <div id=target></div>
      </div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  TestIntersectionObserverDelegate* target_observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* target_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_observer_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {std::numeric_limits<float>::min()},
          });

  DummyExceptionStateForTesting exception_state;
  target_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 1);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(target_observer_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, DirectlyUpdateTransform) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body {
      width: 500px;
      height: 500px;
    }
    #container {
      transform: translateX(100px);
      width: 100px;
    }
    #target {
      width: 10px;
      height: 10px;
    }
    </style>
    <div id=container>
      <div id=target></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  TestIntersectionObserverDelegate* target_observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* target_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_observer_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {std::numeric_limits<float>::min()},
          });

  DummyExceptionStateForTesting exception_state;
  target_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 1);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(target_observer_delegate->LastEntry()->isIntersecting());

  Element* container = GetDocument().getElementById(AtomicString("container"));
  container->SetInlineStyleProperty(CSSPropertyID::kTransform,
                                    "translateX(300px)");
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(GetDocument().GetLayoutView()->NeedsPaintPropertyUpdate());
  EXPECT_FALSE(
      GetDocument().GetLayoutView()->DescendantNeedsPaintPropertyUpdate());
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(LocalFrameView::kDesired,
            GetDocument().View()->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 2);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(target_observer_delegate->LastEntry()->isIntersecting());

  container->SetInlineStyleProperty(CSSPropertyID::kColor, "yellow");
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            GetDocument().View()->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 2);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(target_observer_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, VisibilityHiddenChangeSize) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body {
      width: 500px;
      height: 500px;
    }
    #target {
      position: absolute;
      visibility: hidden;
      top: -20px;
      width: 10px;
      height: 10px;
    }
    </style>
    <div id=target></div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  TestIntersectionObserverDelegate* target_observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* target_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_observer_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .thresholds = {std::numeric_limits<float>::min()},
          });

  DummyExceptionStateForTesting exception_state;
  target_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 1);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(target_observer_delegate->LastEntry()->isIntersecting());

  target->SetInlineStyleProperty(CSSPropertyID::kHeight, "100px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_observer_delegate->CallCount(), 2);
  EXPECT_EQ(target_observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(target_observer_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, ResumePostsTask) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='leading-space' style='height: 700px;'></div>
    <div id='target'></div>
    <div id='trailing-space' style='height: 700px;'></div>
  )HTML");

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);

  // When document is not suspended, beginFrame() will generate notifications
  // and post a task to deliver them.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);

  // When a document is suspended, beginFrame() will generate a notification,
  // but it will not be delivered.  The notification will, however, be
  // available via takeRecords();
  WebView().GetPage()->SetPaused(true);
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 0), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_FALSE(observer->takeRecords(exception_state).empty());

  // Generate a notification while document is suspended; then resume
  // document. Notification should happen in a post task.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  WebView().GetPage()->SetPaused(false);
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
}

TEST_F(IntersectionObserverTest, HitTestAfterMutation) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='leading-space' style='height: 700px;'></div>
    <div id='target'></div>
    <div id='trailing-space' style='height: 700px;'></div>
  )HTML");

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);

  GetDocument().View()->ScheduleAnimation();

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic);

  HitTestLocation location{PhysicalOffset()};
  HitTestResult result(
      HitTestRequest(HitTestRequest::kReadOnly | HitTestRequest::kActive |
                     HitTestRequest::kAllowChildFrameContent),
      location);
  GetDocument().View()->GetLayoutView()->HitTest(location, result);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
}

TEST_F(IntersectionObserverTest, DisconnectClearsNotifications) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='leading-space' style='height: 700px;'></div>
    <div id='target'></div>
    <div id='trailing-space' style='height: 700px;'></div>
  )HTML");

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  IntersectionObserverController& controller =
      GetDocument().EnsureIntersectionObserverController();
  observer->observe(target, exception_state);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 1u);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);

  // If disconnect() is called while an observer has unsent notifications,
  // those notifications should be discarded.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 300), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  observer->disconnect();
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
}

TEST_F(IntersectionObserverTest, RootIntersectionWithForceZeroLayoutHeight) {
  WebView().GetSettings()->SetForceZeroLayoutHeight(true);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      body {
        margin: 0;
        height: 2000px;
      }

      #target {
        width: 100px;
        height: 100px;
        position: absolute;
        top: 1000px;
        left: 200px;
      }
    </style>
    <div id='target'></div>
  )HTML");

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  observer->observe(target, exception_state);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_TRUE(observer_delegate->LastIntersectionRect().IsEmpty());

  GetDocument().View()->LayoutViewport()->SetScrollOf
"""


```