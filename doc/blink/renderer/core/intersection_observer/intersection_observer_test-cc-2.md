Response:
The user wants to understand the functionality of the provided C++ code snippet from `intersection_observer_test.cc`. This involves:

1. **Identifying the core purpose:**  The file name suggests it's a test file for the Intersection Observer API in the Blink rendering engine.
2. **Analyzing the code:**  The code sets up HTML structures, creates `IntersectionObserver` objects, observes elements, and checks for expected behavior.
3. **Relating to web technologies:**  The Intersection Observer API is a JavaScript API, so the tests likely simulate scenarios involving JavaScript, HTML, and CSS.
4. **Identifying test logic:** The tests focus on the `MinScrollDeltaToUpdate` functionality, checking how much scrolling is needed to trigger an intersection observation update.
5. **Inferring assumptions and outputs:** Each `TEST_F` block represents a specific test case with defined HTML and expected outcomes.
6. **Recognizing potential user errors:** Although it's a test file, the scenarios can highlight common mistakes when using the Intersection Observer API.
7. **Summarizing the functionality:** Based on the analysis, provide a concise overview of the code's purpose.

**Plan:**

1. State that the file tests the Intersection Observer API.
2. Explain that the tests focus on `MinScrollDeltaToUpdate`.
3. Provide examples of how the tests relate to JavaScript, HTML, and CSS, drawing from the code's setup (e.g., `IntersectionObserver` creation in C++, HTML structure, CSS styling).
4. Give an example of a test case with assumed input (HTML structure, initial state) and expected output (observer callback count, intersection status, `MinScrollDeltaToUpdate` value).
5. Provide an example of a common user error when using the Intersection Observer API based on the scenarios tested in the code.
6. Summarize the file's function as testing the `MinScrollDeltaToUpdate` behavior of the Intersection Observer in various scenarios.
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

这个C++源代码文件 (`intersection_observer_test.cc`) 的主要功能是**测试 Chromium Blink 引擎中 Intersection Observer API 的实现**。更具体地说，这部分代码专注于测试 `IntersectionObserver` 的一个关键特性：**`MinScrollDeltaToUpdate`**。

以下是更详细的功能分解和与 Web 技术的关系：

**功能列表:**

1. **测试 `MinScrollDeltaToUpdate` 的计算:**  这部分测试的核心目标是验证在各种不同的 HTML 结构、CSS 样式和滚动条件下，`IntersectionObserver` 正确计算出触发下一次 Intersection Observer 回调所需的最小滚动距离。

2. **模拟不同的 HTML 结构:** 代码中使用了 `R"HTML(...)HTML"` 字符串来定义不同的 HTML 结构。这些结构包括包含滚动容器 (`overflow: scroll`)、目标元素 (`#target`) 以及可能的中间裁剪元素 (`overflow: clip`, `clip-path`).

3. **设置不同的 CSS 样式:**  测试用例中会通过设置元素的 `style` 属性来模拟不同的 CSS 样式，例如设置容器的宽度和高度、滚动行为、以及目标元素的尺寸。

4. **创建和配置 `IntersectionObserver`:**  代码创建了 `IntersectionObserver` 对象，并可以配置其 `root` 元素（观察的滚动容器）和 `threshold` （交叉比例阈值）。

5. **模拟滚动操作:**  虽然代码本身不是直接模拟用户滚动，但它通过改变元素的样式（例如改变滚动容器的高度）或使用 `scrollTo` 方法来间接地触发布局和 Intersection Observer 的更新，从而测试在不同滚动状态下的 `MinScrollDeltaToUpdate`。

6. **断言测试结果:**  每个 `TEST_F` 都会进行一系列的断言 (`EXPECT_EQ`, `ASSERT_FALSE`, `EXPECT_TRUE`)，以验证 `IntersectionObserver` 的行为是否符合预期，例如回调被调用的次数、是否发生交叉、以及 `MinScrollDeltaToUpdate` 的值。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** Intersection Observer API 本身是一个 **JavaScript API**，允许网页监听目标元素与其祖先元素或视口交叉状态的变化。虽然这段 C++ 代码是测试其底层实现，但它模拟了 JavaScript 使用该 API 的场景。
    * **例子:**  在 JavaScript 中，你会这样创建一个 Intersection Observer 并观察元素：
      ```javascript
      const observer = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            console.log('Target is intersecting!');
          }
        });
      });
      const target = document.getElementById('target');
      observer.observe(target);
      ```
      这段 C++ 测试代码就是在验证 `IntersectionObserver` 类的内部逻辑，确保当 JavaScript 调用 `observe()` 方法时，其背后的 C++ 代码能正确工作。

* **HTML:** HTML 提供了网页的结构。测试代码通过创建不同的 HTML 结构来验证 Intersection Observer 在不同布局下的行为。
    * **例子:**  `<div id='target' style="width: 50px; height: 100px"></div>`  定义了一个简单的 `div` 元素作为观察目标。测试会检查当这个目标元素进入或离开其父元素的视口时，`MinScrollDeltaToUpdate` 的计算是否正确。

* **CSS:** CSS 用于控制网页的样式和布局。测试代码通过设置 CSS 属性（例如 `overflow: scroll`, `height`, `width`, `clip-path`) 来模拟不同的视觉效果和滚动容器，并测试 Intersection Observer 在这些情况下的表现。
    * **例子:**  `<div id='root' style="width: 100px; height: 100px; overflow: scroll">` 创建了一个可以滚动的容器。测试会验证当目标元素在这个滚动容器中时，需要滚动多少距离才能触发 Intersection Observer 的回调。

**逻辑推理的假设输入与输出举例:**

**测试用例:** `TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThresholdZero)`

**假设输入:**

* **HTML 结构:**
  ```html
  <div id='root' style="width: 100px; height: 100px; overflow: scroll">
    <div style="height: 200px"></div>
    <div id='target' style="width: 50px; height: 100px"></div>
    <div style="width: 1000px; height: 1000px"></div>
  </div>
  ```
* **Intersection Observer 配置:** `threshold` 设置为 0 (意味着只要目标元素与根元素有任何交叉就触发回调)。
* **初始状态:** 目标元素 `#target` 最初不在滚动容器 `#root` 的可视区域内。

**预期输出:**

1. **第一次 `Compositor().BeginFrame()` 后:**
   * `observer_delegate->CallCount()` 为 1 (回调被调用一次)。
   * `observer_delegate->EntryCount()` 为 1 (有一个观察条目)。
   * `observer_delegate->LastEntry()->isIntersecting()` 为 `false` (目标元素未交叉)。
   * `observation->MinScrollDeltaToUpdate()` 为 `gfx::Vector2dF(50, 100)`。 这意味着需要向右滚动 50px 或向下滚动 100px 才能使目标元素开始与根元素交叉。

2. **`root->scrollTo(0, 100)` 后:**
   * `observer_delegate->CallCount()` 为 2 (回调再次被调用)。
   * `observer_delegate->EntryCount()` 为 2。
   * `observer_delegate->LastEntry()->isIntersecting()` 为 `true` (目标元素已交叉)。
   * `observation->MinScrollDeltaToUpdate()` 为 `gfx::Vector2dF(50, 0)`。  这意味着如果现在要让目标元素不再交叉，需要向右滚动至少 50px。

**用户或编程常见的使用错误举例:**

* **未正确设置 `root` 元素:**  如果用户在使用 Intersection Observer 时没有正确指定 `root` 元素，或者指定的 `root` 元素不是一个滚动容器，那么 `MinScrollDeltaToUpdate` 的计算可能不准确，导致回调触发时机与预期不符。  例如，如果 `root` 设置为 `null`，则默认使用视口，但如果用户期望相对于某个特定的滚动容器进行观察，就会出错。

* **对 `threshold` 理解不足:**  用户可能不清楚 `threshold` 参数的作用，导致在目标元素只有少量交叉时就触发了回调，或者反之，在期望触发回调的时候却没有触发。这段测试代码通过测试不同的 `threshold` 值（例如 0 和 0.5）来确保 Blink 引擎的实现符合规范。

**归纳一下它的功能 (第3部分):**

作为测试套件的第 3 部分，这段代码主要负责**测试 Intersection Observer API 中 `MinScrollDeltaToUpdate` 功能的正确性**。它通过创建各种包含滚动容器和目标元素的 HTML 结构，并模拟滚动相关的操作（如改变容器高度或使用 `scrollTo`），来验证在不同场景下，Blink 引擎能否准确计算出触发下一次 Intersection Observer 回调所需的最小滚动距离。这部分测试覆盖了不同的 `threshold` 值和 CSS 样式，确保了该功能在各种情况下的稳定性和准确性。

### 提示词
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
adURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

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
  EXPECT_EQ(IntersectionGeometry::kInfiniteScrollDelta,
            observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateNotScrollableToScrollable) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 200px; height: 200px; overflow: scroll">
      <div style="height: 150px"></div>
      <div id="target" style="width: 30px; height: 30px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

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
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(IntersectionGeometry::kInfiniteScrollDelta,
            observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->SetInlineStyleProperty(CSSPropertyID::kHeight, "130px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(30, 20), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->SetInlineStyleProperty(CSSPropertyID::kHeight, "200px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(IntersectionGeometry::kInfiniteScrollDelta,
            observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateInlineLayout) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 200px; height: 200px; overflow: scroll">
      <div id="spacer" style="height: 150px"></div>
      <span id="target">Target</span>
      <div style="height: 200px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* spacer = GetDocument().getElementById(AtomicString("spacer"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

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
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(50, observation->MinScrollDeltaToUpdate().y());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  spacer->SetInlineStyleProperty(CSSPropertyID::kHeight, "220px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(20, observation->MinScrollDeltaToUpdate().y());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  spacer->SetInlineStyleProperty(CSSPropertyID::kHeight, "100px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(100, observation->MinScrollDeltaToUpdate().y());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThresholdZero) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

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
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());

  root->scrollTo(0, 30);
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  // This checks we didn't do a full update. MinScrollDeltaToUpdate is
  // subtracted by abs(scroll-delta). If we did a full update,
  // MinScrollDeltaToUpdate would be recomputed to (50, 70).
  EXPECT_EQ(gfx::Vector2dF(50, 30), observation->MinScrollDeltaToUpdate());

  root->scrollTo(0, 100);
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(51, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(1, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateWithPageZoom) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  GetDocument().GetFrame()->SetLayoutZoomFactor(2);

  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  // The test HTML is the same as MinScrollDeltaToUpdateThresholdZero.
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

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
  EXPECT_EQ(gfx::Vector2dF(100, 200), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  // Note that this CSSOM function uses CSS (unzoomed) coordinates.
  root->scrollTo(0, 50);
  // While our internal geometries are zoomed.
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(100, 100), observation->MinScrollDeltaToUpdate());

  root->scrollTo(0, 100);
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(100, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 101);
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(100, 2), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(51, 101);
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(2, 2), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateImplicitRoot) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(300, 300));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>body { margin: 0; }</style>
    <div style="height: 400px"></div>
    <div id='target' style="width: 50px; height: 100px"></div>
    <div style="width: 1000px; height: 1000px"></div>
  )HTML");

  LocalDOMWindow& window = Window();
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
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

  window.scrollTo(0, 50);
  EXPECT_EQ(gfx::Vector2dF(50, 100), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  window.scrollTo(0, 100);
  EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  window.scrollTo(0, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  window.scrollTo(51, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(1, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdZeroIntermediateClip) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id="clip" style="width: 50px; height: 20px; overflow: clip">
        <div id='target' style="width: 50px; height: 100px"></div>
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  TestMinScrollDeltaToUpdateWithIntermediateClip();
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdZeroIntermediateClipPath) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id="clip" style="width: 50px; height: 20px; clip-path: border-box">
        <div id='target' style="width: 50px; height: 100px"></div>
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  TestMinScrollDeltaToUpdateWithIntermediateClip();
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdZeroClipPathOnTarget) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px;
                              clip-path: rect(0 50px 20px 0)"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  TestMinScrollDeltaToUpdateWithIntermediateClip();
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateMinimumThreshold) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  observer_init->setThreshold(
      MakeGarbageCollected<V8UnionDoubleOrDoubleSequence>(
          IntersectionObserver::kMinimumThreshold));
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
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(51, 101);
  EXPECT_EQ(gfx::Vector2dF(50, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(1, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThreshold0_5) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  observer_init->setThreshold(
      MakeGarbageCollected<V8UnionDoubleOrDoubleSequence>(0.5));
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
  EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());

  root->scrollTo(0, 100);
  EXPECT_EQ(gfx::Vector2dF(50, 50), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 101);
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 151);
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
```