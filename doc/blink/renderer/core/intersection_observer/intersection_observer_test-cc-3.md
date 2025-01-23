Response:
The user wants a summary of the functionality of the provided C++ code snippet from `intersection_observer_test.cc`. They also want to know how it relates to JavaScript, HTML, and CSS, with examples, logical inferences with assumed inputs and outputs, common user/programming errors, and a general summarization.

**Plan:**

1. **Identify the core purpose of the code:** The code snippet contains a series of C++ tests for the Intersection Observer API implementation in Blink.
2. **Explain the connection to web technologies:** The Intersection Observer API is a JavaScript API that allows developers to observe changes in the intersection of a target element with an ancestor element or with the viewport. The C++ code tests the underlying implementation that makes this JavaScript API work. HTML and CSS are used to structure and style the elements being observed in the tests.
3. **Provide examples:** Illustrate how the C++ tests interact with the JavaScript API, and how the HTML and CSS in the test setup influence the intersection calculations.
4. **Infer logic and provide examples with input/output:** Analyze specific test cases and deduce the expected behavior based on the test setup and assertions. Provide hypothetical scenarios and their likely outcomes.
5. **Identify potential errors:** Based on the tests, pinpoint common mistakes developers might make when using the Intersection Observer API.
6. **Summarize the functionality:**  Provide a concise overview of the code's purpose.
这是 `blink/renderer/core/intersection_observer/intersection_observer_test.cc` 文件的一部分，主要功能是**测试 Blink 引擎中 Intersection Observer API 的各种特性，特别是关于 `MinScrollDeltaToUpdate` 的计算和 `trackVisibility` 特性**。

具体来说，这部分代码主要测试了以下功能：

1. **`MinScrollDeltaToUpdate` 的计算：**
   - 测试在不同的阈值（threshold）下，目标元素与根元素（或视口）发生交叉时，需要滚动的最小距离（`MinScrollDeltaToUpdate`）的计算是否正确。
   - 测试根元素或目标元素应用了 CSS `filter` 属性时，`MinScrollDeltaToUpdate` 的计算是否受到影响。
   - 这些测试验证了 Blink 引擎在优化 Intersection Observer 性能方面所做的努力，即避免不必要的 Intersection Observer 回调。只有当滚动距离达到一定阈值，才触发回调。

2. **`trackVisibility` 特性：**
   - 测试 `trackVisibility` 属性的初始化和生效。
   - 验证当目标元素被其他元素遮挡（occlusion）、透明度降低（opacity）、或应用了不允许的 CSS `transform` 时，Intersection Observer 是否能正确检测到元素的可见性变化。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `IntersectionObserver` 是一个 JavaScript API。这些 C++ 测试直接测试了该 API 在 Blink 引擎中的底层实现。JavaScript 代码会创建 `IntersectionObserver` 对象并监听回调，而这些 C++ 测试模拟了各种场景来验证底层计算的正确性。
    * **举例说明:**  JavaScript 代码可以像这样创建一个 `IntersectionObserver`：
      ```javascript
      const observer = new IntersectionObserver(callback, { threshold: 1 });
      const target = document.getElementById('target');
      observer.observe(target);
      ```
      这段 C++ 代码中的测试，例如 `MinScrollDeltaToUpdateThresholdOne`，就是在模拟当 JavaScript 设置 `threshold` 为 1 时，Blink 引擎内部如何计算 `MinScrollDeltaToUpdate` 以及何时触发 `callback`。

* **HTML:**  测试用例中使用了 HTML 来创建被观察的目标元素和根元素，以及模拟各种布局场景，例如滚动容器、遮挡元素等。
    * **举例说明:**  在 `MinScrollDeltaToUpdateThresholdOne` 测试中，HTML 代码创建了一个可滚动的 `div` 作为根元素，以及一个需要被观察的 `div` 作为目标元素。HTML 的结构和样式直接影响了交叉状态的计算。

* **CSS:** CSS 用于设置元素的样式，例如宽度、高度、`overflow`、`filter`、`opacity`、`transform` 等。这些样式会影响元素的布局和渲染，进而影响 Intersection Observer 的交叉状态和可见性判断。
    * **举例说明:**  `MinScrollDeltaToUpdateThresholdFilterOnRoot` 测试中，给根元素应用了 `filter: blur(20px)`，测试了这种情况下 `MinScrollDeltaToUpdate` 的计算。`BasicOcclusion` 测试中，通过 CSS 的 `margin-top` 属性来模拟遮挡效果。`BasicOpacity` 测试了透明度对可见性的影响。

**逻辑推理 (假设输入与输出):**

**场景 1 (基于 `MinScrollDeltaToUpdateThresholdOne` 测试):**

* **假设输入 (HTML):**
  ```html
  <div id='root' style="width: 100px; height: 100px; overflow: scroll">
    <div style="height: 200px"></div>
    <div id='target' style="width: 50px; height: 100px; margin-left: 30px"></div>
  </div>
  ```
* **假设输入 (JavaScript 设置):** `threshold` 为 1。
* **初始状态:** 目标元素部分可见。
* **操作:** 用户在 `root` 元素中垂直滚动 99px。
* **预期输出:**  `observer_delegate->CallCount()` 仍然是 1 (初始交叉状态的回调)，因为尚未达到 `MinScrollDeltaToUpdate` 的阈值。`observer_delegate->LastEntry()->isIntersecting()` 仍然为 `false`。
* **操作:** 用户继续垂直滚动到 100px。
* **预期输出:** `observer_delegate->CallCount()` 变为 2，触发新的回调。 `observer_delegate->LastEntry()->isIntersecting()` 变为 `true`，因为目标元素完全进入根元素的可视区域。

**场景 2 (基于 `BasicOcclusion` 测试):**

* **假设输入 (HTML):**
  ```html
  <div id='target'></div>
  <div id='occluder' style="margin-top: -10px;"></div>
  ```
* **假设输入 (JavaScript 设置):** `trackVisibility` 为 `true`， `delay` 为 100ms。
* **初始状态:** 目标元素未被遮挡。
* **操作:**  页面加载完成。
* **预期输出:**  `observer_delegate` 会收到一个回调， `isIntersecting` 为 `true`， `isVisible` 也为 `true`。
* **操作:** `occluder` 元素的 `margin-top` 设置为负值，使其遮挡目标元素。
* **预期输出:** 在下一个渲染帧后，`observer_delegate` 会收到一个新的回调， `isIntersecting` 仍然为 `true`（可能部分交叉），但 `isVisible` 变为 `false`。

**用户或编程常见的使用错误举例:**

1. **`trackVisibility` 使用不当:**
   - **错误:**  在初始化 `IntersectionObserver` 时设置 `trackVisibility: true` 但没有设置 `delay`。
   - **结果:**  JavaScript 会抛出一个异常，因为 `trackVisibility` 必须与一个非零的 `delay` 配合使用。该测试用例 `TrackVisibilityInit` 就验证了这一点。
   - **正确做法:** 同时设置 `trackVisibility` 和一个合适的 `delay` 值（通常大于等于 100ms）。

2. **误解 `MinScrollDeltaToUpdate`:**
   - **错误:**  开发者认为只要目标元素的交叉状态发生变化，Intersection Observer 的回调就会立即触发。
   - **结果:**  在某些情况下，特别是对于性能优化，Blink 引擎会延迟回调，直到滚动距离达到一定的阈值。这可能会让开发者感到困惑，认为回调没有按预期触发。
   - **理解:**  `MinScrollDeltaToUpdate` 是一个优化机制，旨在减少不必要的回调。开发者应该理解，只有在滚动距离足够大时，回调才会被触发。

3. **忽略 CSS 属性对 Intersection Observer 的影响:**
   - **错误:**  开发者没有考虑到 CSS 的 `filter`、`opacity`、`transform` 等属性可能会影响 Intersection Observer 的行为，特别是 `trackVisibility` 功能。
   - **结果:**  例如，一个元素即使在视口内，但如果其祖先元素设置了 `opacity: 0.99`，`trackVisibility` 可能会认为该元素不可见。或者，某些复杂的 `transform` 可能会导致 `isVisible` 为 `false`。开发者需要仔细测试各种 CSS 组合。

**功能归纳:**

这部分 `intersection_observer_test.cc` 文件的主要功能是**验证 Blink 引擎中 Intersection Observer API 的核心逻辑，特别是 `MinScrollDeltaToUpdate` 的计算以及 `trackVisibility` 功能的正确性**。它通过创建各种 HTML 结构和应用不同的 CSS 样式，并模拟滚动和渲染过程，来测试 Intersection Observer 在不同场景下的行为是否符合预期。 这些测试确保了当 JavaScript 代码使用 Intersection Observer API 时，底层的 C++ 实现能够准确地报告元素的交叉状态和可见性，并进行合理的性能优化。

### 提示词
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
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

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThresholdOne) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 50px; height: 100px; margin-left: 30px">
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  observer_init->setThreshold(
      MakeGarbageCollected<V8UnionDoubleOrDoubleSequence>(1));
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
  EXPECT_EQ(gfx::Vector2dF(20, 200), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 100);
  EXPECT_EQ(gfx::Vector2dF(20, 200), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(20, 100), observation->MinScrollDeltaToUpdate());

  root->scrollTo(0, 200);
  EXPECT_EQ(gfx::Vector2dF(20, 100), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(20, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(20, 200);
  EXPECT_EQ(gfx::Vector2dF(20, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(10, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(31, 201);
  EXPECT_EQ(gfx::Vector2dF(10, 0), observation->MinScrollDeltaToUpdate());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(1, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThresholdOneOfRoot) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root' style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id='target' style="width: 100px; height: 150px; margin-left: 30px">
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());

  IntersectionObserver* observer = MakeGarbageCollected<IntersectionObserver>(
      *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      IntersectionObserver::Params{
          .root = root,
          .thresholds = {1},
          .semantics = IntersectionObserver::kFractionOfRoot,
      });

  DummyExceptionStateForTesting exception_state;
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
  EXPECT_EQ(gfx::Vector2dF(30, 200), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(0, 100);
  EXPECT_EQ(gfx::Vector2dF(30, 200), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(30, 100), observation->MinScrollDeltaToUpdate());

  root->scrollTo(30, 200);
  EXPECT_EQ(gfx::Vector2dF(30, 100), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kScrollAndVisibilityOnly,
            frame_view->GetIntersectionObservationStateForTesting());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(0, 0), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());

  root->scrollTo(31, 201);
  EXPECT_EQ(gfx::Vector2dF(0, 0), observation->MinScrollDeltaToUpdate());
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_EQ(gfx::Vector2dF(1, 1), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateThresholdFilterOnRoot) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 100px; height: 100px; overflow: scroll;
                          filter: blur(20px)">
      <div style="height: 200px"></div>
      <div id="target" style="width: 100px; height: 150px"></div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  DummyExceptionStateForTesting exception_state;
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
  EXPECT_EQ(gfx::Vector2dF(100, 100), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdFilterOnTarget) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div id="target" style="width: 100px; height: 150px; filter: blur(20px)">
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  TestIntersectionObserverDelegate* observer_delegate_js =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  TestIntersectionObserverDelegate* observer_delegate_display_lock =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  DummyExceptionStateForTesting exception_state;
  IntersectionObserver* observer_js = IntersectionObserver::Create(
      observer_init, *observer_delegate_js,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  IntersectionObserver* observer_display_lock = IntersectionObserver::Create(
      observer_init, *observer_delegate_display_lock,
      LocalFrameUkmAggregator::kDisplayLockIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer_js->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer_display_lock->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  const IntersectionObservation* observation_js =
      target->IntersectionObserverData()->GetObservationFor(*observer_js);
  EXPECT_EQ(gfx::Vector2dF(), observation_js->MinScrollDeltaToUpdate());
  const IntersectionObservation* observation_display_lock =
      target->IntersectionObserverData()->GetObservationFor(
          *observer_display_lock);
  EXPECT_EQ(gfx::Vector2dF(),
            observation_display_lock->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kRequired,
            frame_view->GetIntersectionObservationStateForTesting());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(gfx::Vector2dF(100, 100), observation_js->MinScrollDeltaToUpdate());
  EXPECT_EQ(gfx::Vector2dF(),
            observation_display_lock->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdFilterOnIntermediateContainer) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 100px; height: 100px; overflow: scroll">
      <div style="height: 200px"></div>
      <div style="filter: blur(20px)">
        <div id="target" style="width: 100px; height: 150px"></div>
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  DummyExceptionStateForTesting exception_state;
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kDisplayLockIntersectionObserver,
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
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverTest,
       MinScrollDeltaToUpdateThresholdFilterOnIntermediateNonContainer) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="width: 100px; height: 100px; overflow: scroll;
                          position: relative">
      <div style="height: 200px"></div>
      <div style="filter: blur(20px)">
        <div id="target" style="width: 100px; height: 150px;
                                position: absolute"></div>
      </div>
      <div style="width: 1000px; height: 1000px"></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));
  LocalFrameView* frame_view = GetDocument().View();

  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  DummyExceptionStateForTesting exception_state;
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kDisplayLockIntersectionObserver,
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
  EXPECT_EQ(gfx::Vector2dF(), observation->MinScrollDeltaToUpdate());
  EXPECT_EQ(LocalFrameView::kNotNeeded,
            frame_view->GetIntersectionObservationStateForTesting());
}

TEST_F(IntersectionObserverV2Test, TrackVisibilityInit) {
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      ASSERT_NO_EXCEPTION);
  EXPECT_FALSE(observer->trackVisibility());

  // This should fail because no delay is set.
  {
    DummyExceptionStateForTesting exception_state;
    observer_init->setTrackVisibility(true);
    observer = IntersectionObserver::Create(
        observer_init, *observer_delegate,
        LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
        exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  // This should fail because the delay is < 100.
  {
    DummyExceptionStateForTesting exception_state;
    observer_init->setDelay(99.9);
    observer = IntersectionObserver::Create(
        observer_init, *observer_delegate,
        LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
        exception_state);
    EXPECT_TRUE(exception_state.HadException());
  }

  {
    DummyExceptionStateForTesting exception_state;
    observer_init->setDelay(101.);
    observer = IntersectionObserver::Create(
        observer_init, *observer_delegate,
        LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
        exception_state);
    ASSERT_FALSE(exception_state.HadException());
    EXPECT_TRUE(observer->trackVisibility());
    EXPECT_EQ(observer->delay(), 101.);
  }
}

TEST_F(IntersectionObserverV2Test, BasicOcclusion) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      div {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='target'>
      <div id='child'></div>
    </div>
    <div id='occluder'></div>
  )HTML");
  Compositor().BeginFrame();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setTrackVisibility(true);
  observer_init->setDelay(100);
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* occluder = GetDocument().getElementById(AtomicString("occluder"));
  ASSERT_TRUE(target);
  observer->observe(target);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_TRUE(observer_delegate->LastEntry()->isVisible());

  occluder->SetInlineStyleProperty(CSSPropertyID::kMarginTop, "-10px");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_FALSE(observer_delegate->LastEntry()->isVisible());

  // Zero-opacity objects should not count as occluding.
  occluder->SetInlineStyleProperty(CSSPropertyID::kOpacity, "0");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_EQ(observer_delegate->EntryCount(), 3);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_TRUE(observer_delegate->LastEntry()->isVisible());
}

TEST_F(IntersectionObserverV2Test, BasicOpacity) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      div {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='transparent'>
      <div id='target'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setTrackVisibility(true);
  observer_init->setDelay(100);
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* transparent =
      GetDocument().getElementById(AtomicString("transparent"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(transparent);
  observer->observe(target);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_TRUE(observer_delegate->LastEntry()->isVisible());

  transparent->SetInlineStyleProperty(CSSPropertyID::kOpacity, "0.99");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_FALSE(observer_delegate->LastEntry()->isVisible());
}

TEST_F(IntersectionObserverV2Test, BasicTransform) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
      div {
        width: 100px;
        height: 100px;
      }
    </style>
    <div id='transformed'>
      <div id='target'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setTrackVisibility(true);
  observer_init->setDelay(100);
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Element* transformed =
      GetDocument().getElementById(AtomicString("transformed"));
  ASSERT_TRUE(target);
  ASSERT_TRUE(transformed);
  observer->observe(target);

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_TRUE(observer_delegate->LastEntry()->isVisible());

  // 2D translations and proportional upscaling is permitted.
  transformed->SetInlineStyleProperty(
      CSSPropertyID::kTransform, "translateX(10px) translateY(20px) scale(2)");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);

  // Any other transform is not permitted.
  transformed->SetInlineStyleProperty(CSSPropertyID::kTransform,
                                      "skewX(10deg)");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_EQ(observer_delegate->EntryCount(), 2);
  EXPECT_TRUE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_FALSE(observer_delegate->LastEntry()->isVisible());
}

TEST_F(IntersectionObserverTest, ApplyMarginToTarget) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    #scroller { height: 100px; overflow: scroll; }
    #target { width: 50px; height: 50px; }
    .spacer { height: 105px; }
    </style>
    <div id=scroller>
      <div class=spacer></div>
      <div id=target></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  TestIntersectionObserverDelegate* root_margin_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* root_margin_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *root_margin_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .margin = {Length::Fixed(10)},
              .thresholds = {std::numeric_limits<float>::min()},
          });

  DummyExceptionStateForTesting exception_state;
  root_margin_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  TestIntersectionObserverDelegate* target_margin_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  // Same parameters as above except that margin is applied to target.
  IntersectionObserver* target_margin_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_margin_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .margin = {Length::Fixed(10)},
              .margin_target = IntersectionObserver::kApplyMarginToTarget,
              .thresholds = {std::numeric_limits<float>::min()},
          });

  target_margin_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(root_margin_delegate->CallCount(), 1);
  EXPECT_EQ(root_margin_delegate->EntryCount(), 1);
  // Since the inner scroller clips content, the root margin has no effect and
  // target is not intersecting.
  EXPECT_FALSE(root_margin_delegate->LastEntry()->isIntersecting());

  EXPECT_EQ(target_margin_delegate->CallCount(), 1);
  EXPECT_EQ(target_margin_delegate->EntryCount(), 1);
  // Since the margin is applied to the target, the inner scroller clips an
  // expanded rect, which ends up being visible in the root. Hence, it is
  // intersecting.
  EXPECT_TRUE(target_margin_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, TargetMarginPercentResolvesAgainstRoot) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 500));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    #scroller { height: 100px; overflow: scroll; }
    #target { width: 50px; height: 50px; }
    .spacer { height: 145px; }
    </style>
    <div id=scroller>
      <div class=spacer></div>
      <div id=target></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);

  TestIntersectionObserverDelegate* target_margin_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  // 10% margin on a target would be 5px if it resolved against target, which
  // is not enough to intersect. It would be 10px if it resolved against the
  // scroller, which is also not enough. However, it would be 50px if it
  // resolved against root, which would make it intersecting.
  IntersectionObserver* target_margin_observer =
      MakeGarbageCollected<IntersectionObserver>(
          *target_margin_delegate,
          LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
          IntersectionObserver::Params{
              .margin = {Length::Percent(10)},
              .margin_target = IntersectionObserver::kApplyMarginToTarget,
              .thresholds = {std::numeric_limits<float>::min()},
          });

  DummyExceptionStateForTesting exception_state;
  target_margin_observer->observe(target, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_FALSE(Compositor().NeedsBeginFrame());

  EXPECT_EQ(target_margin_delegate->CallCount(), 1);
  EXPECT_EQ(target_margin_delegate->EntryCount(), 1);
  EXPECT_TRUE(target_margin_delegate->LastEntry()->isIntersecting());
}

TEST_F(IntersectionObserverTest, ScrollMarginIntersecting) {
  // The scroller should not clip the content because the scroll margin is
  // larger than the spacer and target should intersect.
  TestScrollMargin(/* scroll_margin */ 20, /* is_intersecting */ true,
                   /* intersectionRatio */ 0.2);
}

TEST_F(IntersectionObserverTest, ScrollMarginNotIntersecting) {
  // The scroller should clip the content because the scroll margin is smaller
  // than the spacer and target should not intersect.
  TestScrollMargin(/* scroll_margin */ 9, /* is_intersecting */ false,
                   /* intersectionRatio */ 0.0);
}

TEST_F(IntersectionObserverTest, NoScrollMargin) {
  // The scroller should clip the content because the scroll margin is zero
  // and target should not intersect.
  TestScrollMargin(/* scroll_margin */ 0, /* is_intersecting */ false,
                   /* intersectionRatio */ 0.0);
}

TEST_F(IntersectionObserverTest, ScrollMarginNestedIntersecting) {
  // The scroller should not clip the content because the scroll margin is
  // larger than the spacer and target should intersect.
  TestScrollMarginNested(/* scroll_margin */ 20, /* is_intersecting */ true,
                         /* intersectionRatio */ 0.2);
}

TEST_F(IntersectionObserverTest, ScrollMarginNestedNotIntersecting) {
  // The scroller should clip the content because the scroll margin is smaller
  // than the spacer and target should not intersect.
  TestScrollMarginNested(/* scroll_margin */ 9, /* is_intersecting */ false,
                         /* intersectionRatio */ 0.0);
}

TEST_F(IntersectionObserverTest, NoScrollMarginNested) {
  // The scroller should clip the content be
```