Response:
The user wants a summary of the functionality of the C++ code provided.
The code is a test file for `AnchorElementMetricsSender` in the Chromium Blink engine.
It seems to focus on tracking user interactions with anchor elements (`<a>` tags) and sending metrics about these interactions.

Here's a breakdown of the code's actions:
- **Event Handling:** Simulates various browser events like mouse movements, clicks, and scrolling.
- **Metrics Tracking:** Checks if the `AnchorElementMetricsSender` correctly records events like:
    - When an anchor enters or leaves the viewport.
    - Pointer hovering over an anchor, including dwell time.
    - Mouse button presses on anchors.
    - Clicks on anchors, including the target URL and time taken.
    - Pointer data on hover.
- **Intersection Observer:**  Tests how the Intersection Observer API is used to track the visibility of anchor elements.
- **Position Updates:** Checks how the position of anchors relative to pointer down events and the viewport is calculated and recorded, taking into account scrolling and zooming.
- **Subframe Handling:** Includes tests for scenarios involving iframes and how interactions within iframes are (or are not) tracked.
- **Browser Controls:** Considers the impact of browser UI elements like top controls (e.g., address bar) on anchor position calculations.

Therefore, the main function of this test file is to verify that the `AnchorElementMetricsSender` correctly gathers and reports metrics related to user interaction with anchor elements in various scenarios.这是`blink/renderer/core/html/anchor_element_metrics_sender_test.cc`文件的第二部分，主要的功能是测试`AnchorElementMetricsSender`类在各种场景下如何收集和发送关于锚元素（`<a>` 标签）的指标数据。以下是更详细的归纳：

**核心功能归纳：**

1. **模拟用户交互并验证指标记录:**  该部分测试模拟了鼠标移动、鼠标按下、滚动等用户与包含锚元素的网页进行交互的行为，并验证 `AnchorElementMetricsSender` 是否正确记录了这些交互产生的指标数据。

2. **Pointer 事件测试 (鼠标悬停和按下):**  测试了鼠标指针悬停在锚元素上的行为，包括悬停时长 (`hover_dwell_time`) 的计算以及相关指标的记录 (`pointer_over_`, `pointer_hover_dwell_time_`)。同时测试了不同鼠标按键（左键、中键）按下时指标的记录 (`pointer_down_`)。

3. **锚元素进入和离开视口测试:** 测试了锚元素在页面加载后，通过滚动进入视口 (`AnchorElementEnteredViewportLater`) 以及被 Intersection Observer 观察到或不再观察到时，相关指标 (`entered_viewport_`, `left_viewport_`) 的记录。

4. **锚元素点击事件测试:**  测试了通过 JavaScript 代码模拟点击锚元素 (`AnchorElementClicked`) 时，是否正确记录了点击事件的相关指标，例如目标 URL (`target_url`) 和从导航开始到点击的时间差 (`navigation_start_to_click`)。

5. **悬停定时器和指针数据测试:**  测试了当鼠标指针在锚元素上悬停足够长的时间后，是否会触发定时器并记录指针的移动数据 (`ReportAnchorElementPointerDataOnHoverTimerFired`)，例如鼠标速度 (`mouse_velocity`)。

6. **Intersection Observer 的观察数量限制测试:**  测试了在启用 `NavigationPredictor` 特性并设置最大观察数量限制 (`max_intersection_observations`) 后，Intersection Observer 如何管理和更新其观察的锚元素集合 (`MaxIntersectionObservations`)。这包括添加、删除锚元素，以及在锚元素大小不同时，Intersection Observer 如何选择要观察的锚元素。

7. **Intersection Observer 未观察到锚元素的测试:**  测试了当锚元素不再被 Intersection Observer 观察到时，是否会发送相应的离开视口的消息 (`AnchorUnobservedByIntersectionObserver`)。

8. **视口外锚元素不被 Intersection Observer 观察的测试:**  测试了初始状态就在视口外的锚元素是否会被 Intersection Observer 观察到，以及是否会发送进入或离开视口的消息 (`AnchorNotInViewportUnobservedByIntersectionObserver`)。

9. **Intersection Observer 的延迟测试:**  测试了可以配置 Intersection Observer 的延迟时间 (`IntersectionObserverDelay`)。

10. **位置更新测试 (PositionUpdate):**  该部分着重测试了在用户进行交互（例如鼠标按下并滚动）时，如何计算和记录锚元素相对于指针按下位置和视口的距离和位置比例。该测试还考虑了页面缩放 (`SetPageScaleFactor`) 的影响。

11. **忽略在本地根子框架内的指针按下事件测试:**  测试了当鼠标按下事件发生在不属于主框架的本地根子框架内时，`AnchorElementMetricsSender` 是否会忽略该事件 (`PositionUpdate_IgnorePointerDownInsideLocalRootSubframe`)，避免错误的距离计算。

12. **不为本地根子框架内的锚元素计算位置更新的测试:**  测试了是否不会为位于不属于主框架的本地根子框架内的锚元素计算位置更新 (`PositionUpdate_NotComputedForAnchorInsideLocalRootSubframe`)。

13. **考虑浏览器顶部控件高度的位置更新测试:**  测试了在存在浏览器顶部控件（例如地址栏）并影响视口大小时，如何正确计算锚元素的位置信息 (`PositionUpdate_BrowserTopControlsHeight`)。

14. **子框架中被观察的锚元素被移除的测试:**  测试了当包含被观察锚元素的子框架被移除时，是否能正确处理 (`SubframeWithObservedAnchorsDetached`)。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 测试直接操作 HTML 结构，例如添加和移除锚元素，设置锚元素的属性（如 `href`，`style`），验证对锚元素的事件监听和触发（例如 `click()`）。例如：
    ```html
    <a id="anchor" href="p2">foo</a>
    <div style="height: %dpx;"></div>
    ```
* **JavaScript:** 测试中使用 JavaScript 代码来模拟用户点击行为，验证点击事件的指标记录。例如：
    ```javascript
    window.addEventListener('load', () => {
      const a = document.getElementById('anchor');
      a.click();
    });
    ```
* **CSS:**  测试中通过 CSS 样式来控制锚元素的位置和大小，以便模拟不同的视口场景和 Intersection Observer 的行为。例如：
    ```css
    <a href="" style="width: 300px; height: %dpx;">foo</a>
    <div style="height: %dpx;"></div>
    ```

**逻辑推理的假设输入与输出示例：**

**假设输入:**

* 用户将鼠标指针移动到 `id="anchor"` 的锚元素上。
* 鼠标指针在该锚元素上停留了 500 毫秒。

**预期输出:**

* `mock_host->pointer_over_.size()` 的值会增加 1。
* `mock_host->pointer_hover_dwell_time_.size()` 的值会增加 1。
* `mock_host->pointer_hover_dwell_time_[0]->hover_dwell_time` 的值接近 500 毫秒。
* `mock_host->pointer_hover_dwell_time_[0]->anchor_id` 与 `id="anchor"` 对应的内部 ID 匹配。

**用户或编程常见的使用错误举例：**

* **忘记设置锚元素的 `href` 属性:**  虽然这不会直接导致测试失败，但 `AnchorElementMetricsSender` 收集的点击事件指标中的 `target_url` 将为空，这可能是用户在编写 HTML 时的疏忽。测试中会验证这种情况，但实际应用中可能需要提示开发者。
* **过度依赖 Intersection Observer 的即时性:**  Intersection Observer 的回调可能不会立即触发，特别是当存在延迟配置时。开发者需要理解这一点，避免在回调未触发时就假设锚元素已进入或离开视口。测试中会通过 `ProcessEvents()` 来模拟事件处理，确保 Intersection Observer 的回调被执行。
* **在复杂的 JavaScript 交互后立即断言指标:**  如果 JavaScript 代码在用户交互后执行了异步操作，那么在异步操作完成前断言指标可能会导致测试失败。测试中使用了 `platform_->RunForPeriodSeconds(5.)` 或 `base::RunLoop().RunUntilIdle()` 来等待异步操作完成。

总而言之，这部分测试文件专注于验证 `AnchorElementMetricsSender` 在各种用户交互和页面状态下，能否准确可靠地收集关于锚元素的性能和行为指标，为后续的导航预测和其他优化提供数据支持。

### 提示词
```
这是目录为blink/renderer/core/html/anchor_element_metrics_sender_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(2u, mock_host->pointer_over_.size());
  EXPECT_EQ(mock_host->elements_[0]->anchor_id,
            mock_host->pointer_over_[1]->anchor_id);
  EXPECT_EQ(wait_time_1 + hover_dwell_time_1 + wait_time_2,
            mock_host->pointer_over_[1]->navigation_start_to_pointer_over);
  EXPECT_EQ(1u, mock_host->pointer_hover_dwell_time_.size());

  // Move the pointer away for a second time. We should send pointer hover event
  // and |hover_dwell_time| should be |hover_dwell_time_2|.
  const auto hover_dwell_time_2 = base::Milliseconds(200);
  clock_.Advance(hover_dwell_time_2);
  move_to(kViewportWidth / 2, kViewportHeight);
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(2u, mock_host->pointer_over_.size());
  EXPECT_EQ(2u, mock_host->pointer_hover_dwell_time_.size());
  EXPECT_EQ(mock_host->elements_[0]->anchor_id,
            mock_host->pointer_hover_dwell_time_[1]->anchor_id);
  EXPECT_EQ(hover_dwell_time_2,
            mock_host->pointer_hover_dwell_time_[1]->hover_dwell_time);

  // Check mouse right button down event.
  move_to(0, 0);
  mouse_press(0, 0, /*button=*/Button::kRight);
  ProcessEvents(1);
  EXPECT_EQ(0u, mock_host->pointer_down_.size());

  // Check mouse left button down event.
  move_to(0, 0);
  mouse_press(0, 0, /*button=*/Button::kLeft);
  ProcessEvents(1);
  EXPECT_EQ(1u, mock_host->pointer_down_.size());
  EXPECT_EQ(wait_time_1 + hover_dwell_time_1 + wait_time_2 + hover_dwell_time_2,
            mock_host->pointer_down_[0]->navigation_start_to_pointer_down);

  // Check mouse middle button down event.
  move_to(0, 0);
  mouse_press(0, 0, /*button=*/Button::kMiddle);
  ProcessEvents(1);
  EXPECT_EQ(2u, mock_host->pointer_down_.size());
  EXPECT_EQ(wait_time_1 + hover_dwell_time_1 + wait_time_2 + hover_dwell_time_2,
            mock_host->pointer_down_[1]->navigation_start_to_pointer_down);
}

TEST_F(AnchorElementMetricsSenderTest, AnchorElementEnteredViewportLater) {
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

  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(0u, mock_host->entered_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());

  // Scroll down. Now the anchor element is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 2 * kViewportHeight),
      mojom::blink::ScrollType::kProgrammatic);
  ProcessEvents(1);
  EXPECT_EQ(1u, hosts_.size());
  EXPECT_EQ(0u, mock_host->clicks_.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(1u, mock_host->elements_.size());
  EXPECT_EQ(mock_host->entered_viewport_[0]->anchor_id,
            mock_host->elements_[0]->anchor_id);
}

TEST_F(AnchorElementMetricsSenderTest, AnchorElementClicked) {
  String source("https://example.com/p1");

  SimRequest main_resource(source, "text/html");
  SimRequest next_page("https://example.com/p2", "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <a id="anchor" href="p2">foo</a>
    <script>
      window.addEventListener('load', () => {
        const a = document.getElementById('anchor');
        a.click();
      });
    </script>
  )HTML");

  ProcessEvents(0);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->clicks_.size());
  EXPECT_EQ("https://example.com/p2", mock_host->clicks_[0]->target_url);
  EXPECT_LE(base::TimeDelta(),
            mock_host->clicks_[0]->navigation_start_to_click);
  // Wait until the script has had time to run.
  platform_->RunForPeriodSeconds(5.);
  next_page.Complete("empty");
  ProcessEvents(0);
  // The second page load has no anchor elements and therefore no host is bound.
  ASSERT_EQ(1u, hosts_.size());
  EXPECT_EQ(1u, mock_host->clicks_.size());
}

TEST_F(AnchorElementMetricsSenderTest,
       ReportAnchorElementPointerDataOnHoverTimerFired) {
  String source("https://example.com/p1");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"HTML(
    <a href='https://anchor1.com/'>
      <div style='padding: 0px; width: 400px; height: 400px;'></div>
    </a>
  )HTML");

  auto task_runner = base::MakeRefCounted<scheduler::FakeTaskRunner>();
  GetDocument().GetAnchorElementInteractionTracker()->SetTaskRunnerForTesting(
      task_runner, task_runner->GetMockTickClock());

  constexpr gfx::PointF origin{200, 200};
  constexpr gfx::Vector2dF velocity{20, 20};
  constexpr base::TimeDelta timestep = base::Milliseconds(20);
  for (base::TimeDelta t;
       t <= 2 * AnchorElementInteractionTracker::GetHoverDwellTime();
       t += timestep) {
    gfx::PointF coordinates =
        origin + gfx::ScaleVector2d(velocity, t.InSecondsF());
    WebMouseEvent event(WebInputEvent::Type::kMouseMove, coordinates,
                        coordinates, WebPointerProperties::Button::kNoButton, 0,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests());
    GetDocument().GetFrame()->GetEventHandler().HandleMouseMoveEvent(
        event, Vector<WebMouseEvent>(), Vector<WebMouseEvent>());
    task_runner->AdvanceTimeAndRun(timestep);
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->pointer_data_on_hover_.size());
  EXPECT_TRUE(
      mock_host->pointer_data_on_hover_[0]->pointer_data->is_mouse_pointer);
  EXPECT_NEAR(
      20.0 * std::sqrt(2.0),
      mock_host->pointer_data_on_hover_[0]->pointer_data->mouse_velocity, 0.5);
}

TEST_F(AnchorElementMetricsSenderTest, MaxIntersectionObservations) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kNavigationPredictor, {{"max_intersection_observations", "3"},
                                       {"random_anchor_sampling_period", "1"}});

  String source("https://example.com/p1");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"html(
    <body></body>
  )html");

  // Add 3 anchors; they should all be observed by the IntersectionObserver.
  auto* anchor_1 = AddAnchor("one", 100);
  auto* anchor_2 = AddAnchor("two", 200);
  auto* anchor_3 = AddAnchor("three", 300);

  ProcessEvents(3);
  ASSERT_EQ(1u, hosts_.size());
  auto* intersection_observer =
      AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(GetDocument())
          ->GetIntersectionObserverForTesting();
  EXPECT_EQ(hosts_[0]->elements_.size(), 3u);
  EXPECT_EQ(intersection_observer->Observations().size(), 3u);

  auto observations = [&]() -> HeapVector<Member<HTMLAnchorElement>> {
    HeapVector<Member<HTMLAnchorElement>> observed_anchors;
    base::ranges::transform(
        intersection_observer->Observations(),
        std::back_inserter(observed_anchors),
        [](IntersectionObservation* observation) {
          return To<HTMLAnchorElement>(observation->Target());
        });
    return observed_anchors;
  };
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_1, anchor_2, anchor_3));

  // Remove anchor 1.
  anchor_1->remove();
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_2, anchor_3));

  // Readd anchor 1.
  GetDocument().body()->appendChild(anchor_1);
  ProcessEvents(3);
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_1, anchor_2, anchor_3));

  // Add a fourth anchor (larger than all existing anchors). It should be
  // observed instead of anchor 1.
  auto* anchor_4 = AddAnchor("four", 400);
  ProcessEvents(4);
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_2, anchor_3, anchor_4));

  // Add a fifth anchor (smaller than all existing anchors). The observations
  // should not change (i.e. it should not be observed).
  auto* anchor_5 = AddAnchor("five", 50);
  ProcessEvents(5);
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_2, anchor_3, anchor_4));

  // Remove anchor 2. It should no longer be observed, and anchor_1 (the
  // largest unobserved anchor) should be observed in its place.
  anchor_2->remove();
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_1, anchor_3, anchor_4));

  // Remove anchor 5. There should be no changes in anchors observed.
  anchor_5->remove();
  EXPECT_THAT(observations(),
              ::testing::UnorderedElementsAre(anchor_1, anchor_3, anchor_4));
}

TEST_F(AnchorElementMetricsSenderTest, AnchorUnobservedByIntersectionObserver) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kNavigationPredictor, {{"max_intersection_observations", "1"},
                                       {"random_anchor_sampling_period", "1"}});

  String source("https://example.com/p1");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"html(
    <body></body>
  )html");

  auto* intersection_observer =
      AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(GetDocument())
          ->GetIntersectionObserverForTesting();

  auto* anchor_1 = AddAnchor("one", 100);
  ProcessEvents(1);
  ASSERT_EQ(1u, hosts_.size());
  auto* host = hosts_[0].get();

  EXPECT_EQ(host->elements_.size(), 1u);
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  EXPECT_EQ(host->entered_viewport_.size(), 1u);

  host->entered_viewport_.clear();
  auto* anchor_2 = AddAnchor("two", 200);
  ProcessEvents(2);

  // `anchor_2` will now be observed by the intersection observer, `anchor_1`
  // will be unobserved, and should be reported as leaving the viewport.
  EXPECT_EQ(host->elements_.size(), 2u);
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  EXPECT_EQ(host->entered_viewport_.size(), 1u);
  ASSERT_EQ(host->left_viewport_.size(), 1u);
  EXPECT_EQ(AnchorElementId(*anchor_1), host->left_viewport_[0]->anchor_id);

  host->entered_viewport_.clear();
  host->left_viewport_.clear();
  AddAnchor("three", 50);
  ProcessEvents(3);

  // `anchor_3` will not be observed immediately by the intersection observer
  // (as it is smaller than anchor_2). No viewport messages should be
  // dispatched.
  EXPECT_EQ(host->elements_.size(), 3u);
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  EXPECT_EQ(host->entered_viewport_.size(), 0u);
  EXPECT_EQ(host->left_viewport_.size(), 0u);

  anchor_2->remove();
  ProcessEvents(2);

  // Note: We don't dispatch a "left viewport" message for anchor_2 here
  // because it was removed from the document; we just report it as a
  // removed anchor.
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  ASSERT_EQ(host->entered_viewport_.size(), 1u);
  EXPECT_EQ(AnchorElementId(*anchor_1), host->entered_viewport_[0]->anchor_id);
  EXPECT_EQ(host->left_viewport_.size(), 0u);
  EXPECT_EQ(host->removed_anchor_ids_.size(), 1u);
}

TEST_F(AnchorElementMetricsSenderTest,
       AnchorNotInViewportUnobservedByIntersectionObserver) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kNavigationPredictor, {{"max_intersection_observations", "1"},
                                       {"random_anchor_sampling_period", "1"}});

  String source("https://example.com/p1");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(String::Format(R"html(
    <body>
      <div style="height: %dpx;"></div>
    </body>
  )html",
                                        kViewportHeight + 100));

  AddAnchor("one", 100);
  ProcessEvents(1);
  ASSERT_EQ(1u, hosts_.size());
  auto* host = hosts_[0].get();
  auto* intersection_observer =
      AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(GetDocument())
          ->GetIntersectionObserverForTesting();

  EXPECT_EQ(host->elements_.size(), 1u);
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  EXPECT_EQ(host->entered_viewport_.size(), 0u);
  EXPECT_EQ(host->left_viewport_.size(), 0u);

  AddAnchor("two", 200);
  ProcessEvents(2);

  // We don't dispatch "left viewport" for anchor_1 here, because it was
  // never reported to be in the viewport.
  EXPECT_EQ(intersection_observer->Observations().size(), 1u);
  EXPECT_EQ(host->entered_viewport_.size(), 0u);
  EXPECT_EQ(host->left_viewport_.size(), 0u);
}

TEST_F(AnchorElementMetricsSenderTest, IntersectionObserverDelay) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      features::kNavigationPredictor,
      {{"intersection_observer_delay", "252ms"}});

  String source("https://foo.com/bar.html");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete("");

  IntersectionObserver* intersection_observer =
      AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(GetDocument())
          ->GetIntersectionObserverForTesting();
  EXPECT_EQ(intersection_observer->delay(), 252.0);
}

TEST_F(AnchorElementMetricsSenderTest, PositionUpdate) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kNavigationPredictorNewViewportFeatures);
  String source("https://foo.com");

  SimRequest main_resource(source, "text/html");
  LoadURL(source);

  // viewport |  div_1
  //    ..    |  div_1
  //    ..    |  div_1
  //    ..    |  anchor_1
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2
  // --------------------
  //   XXXX   |  anchor_2
  //   XXXX   |  anchor_3
  ASSERT_EQ(kViewportHeight % 8, 0);
  const int unit = kViewportHeight / 8;
  const int div_1_height = 3 * unit;
  const int anchor_1_height = 1 * unit;
  const int div_2_height = 4 * unit;
  const int anchor_2_height = 1 * unit;
  const int anchor_3_height = 1 * unit;
  const int pointer_down_y = 5 * unit;

  main_resource.Complete(String::Format(
      R"HTML(
    <body style="margin: 0px">
      <div style="height: %dpx;"></div>
      <a href="https://bar.com/1"
         style="height: %dpx; display: block;">
        one
      </a>
      <div style="height: %dpx;"></div>
      <a href="https://bar.com/2"
         style="height: %dpx; display: block;">
        two
      </a>
      <a href="https://bar.com/3"
         style="height: %dpx; display: block;">
        three
      </a>
    </body>
  )HTML",
      div_1_height, anchor_1_height, div_2_height, anchor_2_height,
      anchor_3_height));
  Compositor().BeginFrame();

  ProcessEvents(/*expected_anchors=*/3);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  auto& positions = mock_host->positions_;
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, mock_host->left_viewport_.size());

  HTMLCollection* anchors = GetDocument().links();
  EXPECT_EQ(3u, anchors->length());
  uint32_t anchor_1_id =
      AnchorElementId(To<HTMLAnchorElement>(*anchors->item(0)));
  uint32_t anchor_2_id =
      AnchorElementId(To<HTMLAnchorElement>(*anchors->item(1)));
  uint32_t anchor_3_id =
      AnchorElementId(To<HTMLAnchorElement>(*anchors->item(2)));

  auto get_distance_ratio = [&positions](uint32_t anchor_id) {
    auto it = positions.find(anchor_id);
    CHECK(it != positions.end());
    return it->second->distance_from_pointer_down_ratio.value();
  };

  auto get_position_ratio = [&positions](uint32_t anchor_id) {
    auto it = positions.find(anchor_id);
    CHECK(it != positions.end());
    return it->second->vertical_position_ratio;
  };

  // Simulate a pointer down and a scroll.
  //   XXXX   |  div_1
  // --------------------
  // viewport |  div_1
  //    ..    |  div_1
  //    ..    |  anchor_1
  //    ..    |  div_2
  //    ..    |  div_2          . pointerdown
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  anchor_2
  // ----------------------
  //   XXXX   |  anchor_3
  gfx::PointF coordinates(10.0f, pointer_down_y);
  gfx::PointF screen_coordinates(coordinates.x(), coordinates.y() + 2 * unit);
  WebInputEvent::Modifiers modifier = WebInputEvent::kLeftButtonDown;
  WebMouseEvent event(WebInputEvent::Type::kMouseDown, coordinates,
                      screen_coordinates, WebPointerProperties::Button::kLeft,
                      0, modifier, WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);
  VerticalScroll(-unit);
  ProcessPositionUpdates();

  EXPECT_EQ(2u, mock_host->entered_viewport_.size());
  EXPECT_EQ(2u, positions.size());
  EXPECT_FLOAT_EQ(-2.5f * unit / kViewportHeight,
                  get_distance_ratio(anchor_1_id));
  EXPECT_FLOAT_EQ(2.5f * unit / kViewportHeight,
                  get_position_ratio(anchor_1_id));
  EXPECT_FLOAT_EQ(2.5f * unit / kViewportHeight,
                  get_distance_ratio(anchor_2_id));
  EXPECT_FLOAT_EQ(7.5f * unit / kViewportHeight,
                  get_position_ratio((anchor_2_id)));
  // anchor_3 is not in the viewport, so a ratio isn't reported.
  EXPECT_TRUE(!base::Contains(positions, anchor_3_id));
  positions.clear();

  // Zoom (visual as opposed to logical), and scroll up by 2 units post-zoom.
  //         ...
  //   XXXX   |  div_1
  // --------------------
  // viewport |  div_1
  //    ..    |  div_1
  //    ..    |  anchor_1
  //    ..    |  anchor_1
  //    ..    |  div_2          . pointerdown
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2
  // ----------------------
  //   XXXX   |  div_2
  //   XXXX   |  div_2
  //   XXXX   |  div_2
  //   XXXX   |  div_2
  //   XXXX   |  anchor_2
  //   XXXX   |  anchor_2
  //         ...
  GetDocument().GetPage()->SetPageScaleFactor(2.0f);
  Compositor().BeginFrame();
  VerticalScroll(-2 * unit);
  ProcessPositionUpdates();

  EXPECT_EQ(2u, positions.size());
  EXPECT_FLOAT_EQ(-2.0f * unit / kViewportHeight,
                  get_distance_ratio(anchor_1_id));
  EXPECT_FLOAT_EQ(3.0f * unit / kViewportHeight,
                  get_position_ratio(anchor_1_id));
  // Note: anchor_2 is not in the visual viewport after the zoom, but is still
  // in the layout viewport (and will be considered as intersecting by
  // IntersectionObserver, so we still report a distance ratio).
  EXPECT_FLOAT_EQ(8.0f * unit / kViewportHeight,
                  get_distance_ratio(anchor_2_id));
  EXPECT_FLOAT_EQ(13.0f * unit / kViewportHeight,
                  get_position_ratio(anchor_2_id));
  EXPECT_TRUE(!base::Contains(positions, anchor_3_id));
}

// TODO(crbug.com/347719430): This test can be removed if
// LocalFrameView::FrameToViewport supports local root subframes with local
// main frames.
TEST_F(AnchorElementMetricsSenderTest,
       PositionUpdate_IgnorePointerDownInsideLocalRootSubframe) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kNavigationPredictorNewViewportFeatures);

  ASSERT_EQ(0, kViewportHeight % 8);
  int unit = kViewportHeight / 8;
  int div_1_height = unit;
  int anchor_height = unit;
  int iframe_height = 3 * unit;
  int div_2_height = 8 * unit;

  // Navigate the main frame.
  String source("https://foo.com");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(String::Format(R"HTML(
    <body style="margin: 0px">
      <div style="height: %dpx"></div>
      <a href="https://bar.com"
         style="height: %dpx; display: block;">Bar</a>
      <iframe height="%dpx;"></iframe>
      <div style="height: %dpx;"></div>
    </body>
  )HTML",
                                        div_1_height, anchor_height,
                                        iframe_height, div_2_height));
  EXPECT_EQ(1u, GetDocument().links()->length());

  // Make the iframe remote, and add a local child to it (the child is a local
  // root).
  WebRemoteFrameImpl* remote_child = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame().FirstChild(), remote_child);
  EXPECT_TRUE(MainFrame().FirstChild()->IsWebRemoteFrame());
  WebLocalFrameImpl* local_child =
      WebViewHelper().CreateLocalChild(*remote_child);
  local_child->FrameWidget()->Resize(gfx::Size(200, iframe_height));

  // Navigate the local root iframe.
  String iframe_source("https://foo.com/2");
  SimRequest iframe_resource(iframe_source, "text/html");
  frame_test_helpers::LoadFrameDontWait(local_child, KURL(iframe_source));
  iframe_resource.Complete(String::Format(R"HTML(
    <body>
      <div height="%dpx"></div>
    </body>
  )HTML",
                                          iframe_height * 2));

  Compositor().BeginFrame();
  ProcessEvents(/*expected_anchors=*/1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  auto& positions = mock_host->positions_;
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
  EXPECT_EQ(0u, positions.size());

  auto create_mouse_press = [](gfx::PointF coordinates) -> WebMouseEvent {
    return WebMouseEvent(WebInputEvent::Type::kMouseDown, coordinates,
                         coordinates, WebPointerProperties::Button::kLeft, 0,
                         WebInputEvent::kLeftButtonDown,
                         WebInputEvent::GetStaticTimeStampForTests());
  };

  // Dispatch 2 pointerdown events, the first to the main frame, and the second
  // to the local root subframe.
  WebMouseEvent press_1 = create_mouse_press(gfx::PointF(10.f, 6.f * unit));
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(press_1);
  WebMouseEvent press_2 = create_mouse_press(gfx::PointF(10.f, 4.f * unit));
  local_child->GetFrame()->GetEventHandler().HandleMousePressEvent(press_2);
  // Scroll to trigger computation and dispatch of position updates.
  VerticalScroll(-unit);
  ProcessPositionUpdates();

  EXPECT_EQ(1u, positions.size());
  // The distance should be calculated using press_1's coordinates and not
  // press_2 (even though press_2 was dispatched after) as press_2 was inside
  // a subframe whose local root is not the main frame.
  EXPECT_FLOAT_EQ(
      -5.5f * unit / kViewportHeight,
      positions.begin()->second->distance_from_pointer_down_ratio.value());
}

// TODO(crbug.com/347719430): This test can be removed if
// LocalFrameView::FrameToViewport supports local root subframes with local
// main frames.
TEST_F(AnchorElementMetricsSenderTest,
       PositionUpdate_NotComputedForAnchorInsideLocalRootSubframe) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kNavigationPredictorNewViewportFeatures);

  // Navigate the main frame.
  String source("https://foo.com");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(R"html(
    <body>
      <iframe></iframe>
      <div style="height: 1000px"></div>
    </body>
  )html");

  // Make the subframe a remote frame.
  WebRemoteFrameImpl* remote_child = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(MainFrame().FirstChild(), remote_child);
  EXPECT_TRUE(MainFrame().FirstChild()->IsWebRemoteFrame());
  // Add a local subframe to the remote subframe, the local subframe is a local
  // root.
  WebLocalFrameImpl* local_child =
      WebViewHelper().CreateLocalChild(*remote_child);
  WebFrameWidget* widget = local_child->FrameWidget();
  ASSERT_TRUE(widget);
  gfx::Size local_child_size(200, 400);
  widget->Resize(local_child_size);
  // This is needed to make IntersectionObserver to observe the anchor element
  // inside the local subframe as intersecting the viewport.
  auto viewport_intersection_state =
      mojom::blink::ViewportIntersectionState::New();
  gfx::Rect viewport_intersection(local_child_size);
  viewport_intersection_state->viewport_intersection = viewport_intersection;
  viewport_intersection_state->main_frame_intersection = viewport_intersection;
  viewport_intersection_state->compositor_visible_rect = viewport_intersection;
  static_cast<WebFrameWidgetImpl*>(widget)->ApplyViewportIntersectionForTesting(
      std::move(viewport_intersection_state));

  // Navigate the local root.
  String iframe_source("https://foo.com/2");
  SimRequest iframe_resource(iframe_source, "text/html");
  frame_test_helpers::LoadFrameDontWait(local_child, KURL(iframe_source));
  iframe_resource.Complete(R"HTML(
    <body>
      <a href="https://bar.com"
         style="height: 75px; width: 60px; display: block;">Link</a>
    </body>
  )HTML");

  HTMLCollection* anchors = local_child->GetFrame()->GetDocument()->links();
  EXPECT_EQ(1u, anchors->length());

  Compositor().BeginFrame();
  local_child->GetFrame()->View()->UpdateAllLifecyclePhasesForTest();
  ProcessEvents(/*expected_anchors=*/1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  auto& positions = mock_host->positions_;
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());

  // Pointer down and scroll in the main frame.
  gfx::PointF coordinates(10.0f, 100.0f);
  WebInputEvent::Modifiers modifier = WebInputEvent::kLeftButtonDown;
  WebMouseEvent event(WebInputEvent::Type::kMouseDown, coordinates, coordinates,
                      WebPointerProperties::Button::kLeft, 0, modifier,
                      WebInputEvent::GetStaticTimeStampForTests());
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(event);
  VerticalScroll(-50.0f);
  ProcessPositionUpdates();

  // We should not get a position update for the anchor inside the local
  // subframe because its local root is not the main frame.
  EXPECT_EQ(0u, positions.size());
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());
}

TEST_F(AnchorElementMetricsSenderTest,
       PositionUpdate_BrowserTopControlsHeight) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kNavigationPredictorNewViewportFeatures);

  ASSERT_EQ(0, kViewportHeight % 8);
  int unit = kViewportHeight / 8;
  const int top_controls_height = unit;

  // Set up the viewport as follows:
  //
  // controls |  XXXX
  // viewport |  div_1
  //    ..    |  div_1
  //    ..    |  div_1
  //    ..    |  anchor_1
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2
  // -------------------
  const int div_1_height = 3 * unit;
  const int anchor_height = unit;
  const int div_2_height = 8 * unit;

  WebView().ResizeWithBrowserControls(
      gfx::Size(kViewportWidth, kViewportHeight - top_controls_height),
      top_controls_height, /*bottom_controls_height=*/0,
      /*browser_controls_shrink_layout=*/true);
  BrowserControls& browser_controls = WebView().GetBrowserControls();
  EXPECT_TRUE(browser_controls.ShrinkViewport());
  browser_controls.SetShownRatio(1.f, 0.f);
  EXPECT_EQ(top_controls_height, browser_controls.ContentOffset());
  const VisualViewport& visual_viewport = GetPage().GetVisualViewport();
  EXPECT_EQ(kViewportHeight - top_controls_height,
            visual_viewport.Size().height());

  // Navigate the main frame.
  String source("https://foo.com");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  main_resource.Complete(String::Format(R"HTML(
    <body style="margin: 0px">
      <div style="height: %dpx"></div>
      <a href="https://bar.com"
         style="height: %dpx; display: block;">Bar</a>
      <div style="height: %dpx;"></div>
    </body>
  )HTML",
                                        div_1_height, anchor_height,
                                        div_2_height));
  EXPECT_EQ(1u, GetDocument().links()->length());

  Compositor().BeginFrame();
  ProcessEvents(/*expected_anchors=*/1);
  EXPECT_EQ(1u, hosts_.size());
  const auto& mock_host = hosts_[0];
  EXPECT_EQ(1u, mock_host->entered_viewport_.size());

  // Pointer down and scroll down by 3 units. The browser controls should be
  // hidden.
  //
  // viewport |  div_1
  //    ..    |  anchor_1
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2
  //    ..    |  div_2        . pointerdown
  //    ..    |  div_2
  //    ..    |  div_2
  // -------------------
  gfx::PointF coordinates(10.0f, 5.f * unit);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      WebMouseEvent(WebInputEvent::Type::kMouseDown, coordinates, coordinates,
                    WebPointerProperties::Button::kLeft, 0,
                    WebInputEvent::kLeftButtonDown,
                    WebInputEvent::GetStaticTimeStampForTests()));
  VerticalScroll(-3.f * unit);
  EXPECT_FLOAT_EQ(0.f, browser_controls.TopShownRatio());
  // Simulates the viewport size being updated after the top controls are hidden
  // (this happens through WidgetBase::UpdateVisualProperties in practice).
  WebView().ResizeWithBrowserControls(
      gfx::Size(kViewportWidth, kViewportHeight), top_controls_height,
      /*bottom_controls_height=*/0, /*browser_controls_shrink_layout=*/true);
  EXPECT_EQ(0, browser_controls.ContentOffset());
  EXPECT_EQ(kViewportHeight, visual_viewport.Size().height());
  ProcessPositionUpdates();

  const auto& positions = mock_host->positions_;
  EXPECT_FLOAT_EQ(
      -4.5f * unit / kViewportHeight,
      positions.begin()->second->distance_from_pointer_down_ratio.value());
  EXPECT_FLOAT_EQ(1.5f * unit / kViewportHeight,
                  positions.begin()->second->vertical_position_ratio);

  // Pointer down and scroll up by 2 units. The browser controls should be
  // back.
  //
  // controls | XXXX
  // viewport |  div_1
  //    ..    |  div_1
  //    ..    |  anchor_1
  //    ..    |  div_2
  //    ..    |  div_2        . pointerdown
  //    ..    |  div_2
  //    ..    |  div_2
  // -------------------
  coordinates = gfx::PointF(10.0f, 6.f * unit);
  GetDocument().GetFrame()->GetEventHandler().HandleMousePressEvent(
      WebMouseEvent(WebInputEvent::Type::kMouseDown, coordinates, coordinates,
                    WebPointerProperties::Button::kLeft, 0,
                    WebInputEvent::kLeftButtonDown,
                    WebInputEvent::GetStaticTimeStampForTests()));
  VerticalScroll(2.f * unit);
  EXPECT_FLOAT_EQ(1.f, browser_controls.TopShownRatio());
  WebView().ResizeWithBrowserControls(
      gfx::Size(kViewportWidth, kViewportHeight - top_controls_height),
      top_controls_height, /*bottom_controls_height=*/0,
      /*browser_controls_shrink_layout=*/true);
  EXPECT_EQ(top_controls_height, browser_controls.ContentOffset());
  EXPECT_EQ(kViewportHeight - top_controls_height,
            visual_viewport.Size().height());
  ProcessPositionUpdates();

  EXPECT_FLOAT_EQ(
      -2.5f * unit / kViewportHeight,
      positions.begin()->second->distance_from_pointer_down_ratio.value());
  EXPECT_FLOAT_EQ(3.5f * unit / kViewportHeight,
                  positions.begin()->second->vertical_position_ratio);
}

// Regression test for crbug.com/352973572.
TEST_F(AnchorElementMetricsSenderTest, SubframeWithObservedAnchorsDetached) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kNavigationPredictorNewViewportFeatures);

  // Navigate the main frame.
  String source("https://foo.com");
  SimRequest main_resource(source, "text/html");
  LoadURL(source);
  const int scroll_height_px = 100;
  main_resource.Complete(String::Format(R"html(
    <body>
      <div style="height: %dpx;"></div>
      <iframe width="400px" height="400px"></iframe>
      <a href="https://foo.com/one">one</a>
      <div style="height: 1000px;"></div>
    </body>
  )html",
                                        scroll_height_px));

  String subframe_source("https://foo.com/iframe");
  SimRequest subframe_resource(subframe_source, "text/html");
  frame_test_helpers::LoadFrameDontWait(
      MainFrame().FirstChild()->ToWebLocalFrame(), KURL(subframe_source));
  subframe_resource.Complete(R"html(
    <body>
      <a href="https://foo.com/two">one</a>
    </body>
  )html");

  Compositor().BeginFrame();
  ProcessEvents(/*expected_anchors=*/2);

  WebLocalFrameImpl* subfra
```