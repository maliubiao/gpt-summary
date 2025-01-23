Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This snippet is part of a larger test file (`intersection_observer_test.cc`) for the Intersection Observer API in the Chromium Blink engine.

I need to analyze each test case (`TEST_F`) within the provided snippet and identify its purpose. Then, I'll synthesize a summary that covers the key functionalities being tested.

Specifically, I need to look for:
- What aspect of the Intersection Observer API is being tested?
- Does the test involve JavaScript, HTML, or CSS and how?
- Are there explicit assumptions about inputs and expected outputs?
- Are there any common usage errors being highlighted?

Based on the test names and the code within each `TEST_F`:

- `TEST_F(IntersectionObserverTest, ScrollCallback)`: Tests the callback mechanism when the observed element scrolls into and out of view.
- `TEST_F(IntersectionObserverTest, TrackedTargetBookkeeping)`: Tests how the Intersection Observer keeps track of observed targets.
- `TEST_F(IntersectionObserverTest, TrackedRootBookkeeping)`: Tests how the Intersection Observer keeps track of root elements.
- `TEST_F(IntersectionObserverTest, InaccessibleTarget)`: Tests the behavior when the observed target element is removed from the DOM.
- `TEST_F(IntersectionObserverTest, InaccessibleTargetBeforeDelivery)`: Similar to the previous one but focuses on removal before the initial callback.
- `TEST_F(IntersectionObserverTest, RootMarginDevicePixelRatio)`: Tests how `rootMargin` interacts with device pixel ratio.
- Tests related to `CachedRects...`: These tests are about optimizing intersection calculations by caching rect information and checking under what conditions the cache is invalidated. These involve scenarios with scrolling, different overflow behaviors, and CSS property changes.

Now I can formulate the summary.
这是 `blink/renderer/core/intersection_observer/intersection_observer_test.cc` 文件的一部分，主要功能是**测试 Intersection Observer API 的各种核心行为和优化策略**。 这部分代码侧重于以下几个方面的测试：

**1. 滚动事件触发回调 (ScrollCallback):**

*   **功能:**  验证当被观察元素与视口（或指定的根元素）发生滚动交互时，Intersection Observer 的回调函数是否被正确调用，以及回调中包含的交叉矩形信息是否准确。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:** 通过创建包含目标元素的 HTML 结构来模拟页面布局。
    *   **CSS:**  通过 CSS 设置目标元素和视口的大小和位置，影响交叉的发生。
    *   **JavaScript:**  虽然测试代码是用 C++ 编写，但它模拟了 JavaScript 中使用 Intersection Observer 的场景。测试验证了当 JavaScript 代码创建并配置 Intersection Observer 实例后，滚动操作是否能触发预期的回调。
*   **假设输入与输出:**
    *   **假设输入:**  页面加载，一个 `div` 元素作为观察目标，并且视口的高度设置为 600px。观察目标的初始位置使得它最初不在视口内。
    *   **操作:** 通过 `GetDocument().View()->LayoutViewport()->SetScrollOffset()` 方法模拟用户或程序滚动视口。
    *   **预期输出:**
        *   第一次滚动到目标元素进入视口时，回调函数被调用，并且 `LastIntersectionRect()` 返回的矩形不为空，其值与目标元素在视口内的位置和大小一致 (例如 `gfx::RectF(200, 400, 100, 100)`)。
        *   第二次滚动到目标元素完全离开视口时，回调函数再次被调用，并且 `LastIntersectionRect()` 返回的矩形为空。
*   **用户或编程常见的使用错误:**  没有明确体现用户错误，但测试确保了 API 在滚动场景下的正确性，间接防止了开发者在使用 Intersection Observer 处理滚动相关逻辑时遇到错误。

**2. 追踪目标元素的生命周期 (TrackedTargetBookkeeping):**

*   **功能:**  测试 Intersection Observer 如何跟踪被观察的目标元素，以及在目标元素被添加到 DOM、从 DOM 移除、重新添加到 DOM 以及取消观察时，内部状态的维护是否正确。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:**  创建包含目标元素的 HTML 结构。
    *   **JavaScript:**  模拟 JavaScript 中创建和操作 Intersection Observer 的过程，例如 `observer.observe(target)` 和 `observer.unobserve(target)`。
*   **假设输入与输出:**
    *   **假设输入:** 创建一个包含一个 `div` 元素的 HTML 页面。创建两个 Intersection Observer 实例并观察同一个目标元素。
    *   **操作:**  进行一系列 DOM 操作：移除目标元素，重新添加目标元素，取消其中一个观察者的观察，取消另一个观察者的观察。
    *   **预期输出:**  `IntersectionObserverController` 维护的 `TrackedObservationCountForTesting()` 的值会随着观察和取消观察以及目标元素的 DOM 状态变化而更新。例如，当两个观察者都观察目标时，计数为 2；移除目标元素后为 0；重新添加后又变为 2；取消一个观察后变为 1，全部取消后为 0。
*   **用户或编程常见的使用错误:**  如果开发者在目标元素被移除后没有正确地取消观察，可能会导致内存泄漏或意外行为。这个测试确保了 Intersection Observer 能够正确处理这些情况。

**3. 追踪根元素的生命周期 (TrackedRootBookkeeping):**

*   **功能:** 测试当 Intersection Observer 指定了显式的根元素 (`root` 选项) 时，根元素的追踪机制。重点在于根元素是否被跟踪，以及在根元素从 DOM 中移除、重新添加、以及观察者断开连接时，追踪状态的改变。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:**  创建包含根元素和目标元素的 HTML 结构。
    *   **JavaScript:**  模拟 JavaScript 中创建带有 `root` 选项的 Intersection Observer 并进行观察和断开连接的操作。
*   **假设输入与输出:**
    *   **假设输入:** 创建一个包含根元素 (`div`，id为 `root`) 和目标元素 (`div`，id为 `target1`) 的 HTML 页面。创建一个 Intersection Observer 实例，并将其 `root` 选项设置为根元素。
    *   **操作:**  观察目标元素，移除根元素，重新添加根元素，断开观察者的连接，重新观察目标元素，取消观察目标元素，观察目标元素后进行垃圾回收，移除目标元素后进行垃圾回收，移除根元素后进行垃圾回收。
    *   **预期输出:** `IntersectionObserverController` 维护的 `TrackedObserverCountForTesting()` 的值会随着根元素的状态（连接状态、是否有观察者）和观察者的状态（是否观察目标）而变化。只有当根元素已连接到 DOM 并且有观察者正在观察其内部的目标元素时，根元素才会被追踪。
*   **用户或编程常见的使用错误:**  如果开发者错误地认为根元素总是会被追踪，可能会对性能产生影响。此测试验证了 Intersection Observer 的优化策略，只有在必要时才追踪根元素。

**4. 处理不可访问的目标元素 (InaccessibleTarget 和 InaccessibleTargetBeforeDelivery):**

*   **功能:**  测试当被观察的目标元素在回调函数执行之前或之后从 DOM 中移除时，Intersection Observer 的行为，包括是否会产生回调，以及观察者和委托对象是否会被垃圾回收。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:** 创建包含目标元素的 HTML 结构。
    *   **JavaScript:**  模拟 JavaScript 中创建 Intersection Observer 并观察目标元素，然后移除目标元素。
*   **假设输入与输出:**
    *   **假设输入:** 创建一个包含一个 `div` 元素的 HTML 页面。创建一个 Intersection Observer 实例并观察该目标元素。
    *   **操作:**  在观察目标元素后，立即移除目标元素。在 `InaccessibleTarget` 中，移除发生在观察之后，并等待回调执行。在 `InaccessibleTargetBeforeDelivery` 中，移除发生在观察之后，但在回调执行之前。
    *   **预期输出:**
        *   在 `InaccessibleTarget` 中，即使目标元素被移除，由于观察已开始，回调函数仍然会被执行一次。之后，当没有其他活动时，目标元素、观察者和委托对象都应该可以被垃圾回收。
        *   在 `InaccessibleTargetBeforeDelivery` 中，即使目标元素在回调执行前被移除，回调函数仍然会被触发（因为观察任务已经被加入队列），但是回调中的交叉信息会反映目标元素已不存在的状态。最终，目标元素、观察者和委托对象也应该可以被垃圾回收。
*   **用户或编程常见的使用错误:**  开发者可能没有考虑到目标元素在其生命周期内可能被移除的情况。这些测试确保了 Intersection Observer 能够优雅地处理这种情况，避免内存泄漏。

**5. `rootMargin` 和设备像素比 (RootMarginDevicePixelRatio):**

*   **功能:**  测试 `rootMargin` 选项是否能正确地考虑到设备的像素比率，从而精确地定义根元素的边界。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:**  创建包含目标元素的 HTML 结构。
    *   **CSS:**  设置目标元素的高度。
    *   **JavaScript:**  模拟 JavaScript 中创建带有 `rootMargin` 选项的 Intersection Observer。
*   **假设输入与输出:**
    *   **假设输入:**  设置设备像素比为 3.5。创建一个包含一个高度为 30px 的 `div` 元素的 HTML 页面。创建一个 Intersection Observer 实例，并设置 `rootMargin` 为 "-31px 0px 0px 0px"。
    *   **操作:**  观察目标元素，并触发布局和 compositing。
    *   **预期输出:**  回调函数被调用，`LastEntry()->GetGeometry().RootRect()` 返回的根矩形会考虑到设备像素比率，使得上边距为 31px（原始值）而不是计算后的像素值。

**6. 缓存矩形优化 (CachedRects... 系列测试):**

*   **功能:**  测试 Intersection Observer 的矩形缓存机制，这是一种性能优化策略，用于避免在每次检查交叉状态时都重新计算元素的位置和大小。这些测试验证了在不同场景下（例如滚动、CSS 属性变化、元素 display 属性变化、固定定位元素等），缓存是否被正确地使用和失效。
*   **与 JavaScript, HTML, CSS 的关系:**
    *   **HTML:**  创建包含各种布局结构的 HTML 页面，包括带有滚动条的容器、不同定位方式的元素等。
    *   **CSS:**  使用 CSS 设置元素的样式，例如 `overflow`, `position`, `opacity`, `transform`, `display` 等，这些样式会影响元素的布局和渲染，从而影响缓存的有效性。
    *   **JavaScript:**  模拟 JavaScript 中创建 Intersection Observer 并观察目标元素。测试代码通过 C++ 函数 `CanUseCachedRects()` 来检查是否可以使用缓存的矩形。
*   **假设输入与输出:**  每个 `CachedRects` 开头的测试都定义了特定的 HTML 和 CSS 结构。
    *   **操作:**  进行各种操作，例如滚动容器、修改元素的 CSS 属性、移动元素等。
    *   **预期输出:**  在每次操作前后，`CanUseCachedRects()` 的返回值会根据是否应该使用缓存的矩形而变化。例如，在没有影响布局的情况下滚动通常不会使缓存失效，而修改元素的布局属性则会使缓存失效。
*   **用户或编程常见的使用错误:**  开发者可能不了解 Intersection Observer 的缓存机制，错误地认为每次回调都会进行精确的布局计算，从而可能低估其性能优势。这些测试帮助理解缓存机制的适用场景和限制。

**总结此部分的功能:**

这部分 `intersection_observer_test.cc` 的代码主要集中在 **验证 Intersection Observer API 在各种场景下的核心功能和性能优化策略**。 具体来说，它测试了：

*   **基本的滚动触发回调机制**，确保在元素进入和离开视口时能正确触发回调并提供准确的交叉信息。
*   **目标元素和根元素的生命周期追踪**，确保内部状态在 DOM 操作和观察者生命周期变化时保持一致，避免内存泄漏。
*   **处理不可访问目标元素的机制**，确保即使目标元素被移除也能正确处理，避免程序崩溃。
*   **`rootMargin` 选项与设备像素比的正确交互**，保证在不同设备上的一致性。
*   **矩形缓存优化策略的有效性**，验证在不同布局和渲染场景下，缓存是否被正确地使用和失效，从而提高性能。

这些测试覆盖了 Intersection Observer API 的关键方面，确保了其在 Blink 引擎中的正确性和效率。

### 提示词
```
这是目录为blink/renderer/core/intersection_observer/intersection_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
fset(
      ScrollOffset(0, 600), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_EQ(observer_delegate->CallCount(), 2);
  EXPECT_FALSE(observer_delegate->LastIntersectionRect().IsEmpty());
  EXPECT_EQ(gfx::RectF(200, 400, 100, 100),
            observer_delegate->LastIntersectionRect());

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 1200), mojom::blink::ScrollType::kProgrammatic);
  Compositor().BeginFrame();
  test::RunPendingTasks();
  ASSERT_EQ(observer_delegate->CallCount(), 3);
  EXPECT_TRUE(observer_delegate->LastIntersectionRect().IsEmpty());
}

TEST_F(IntersectionObserverTest, TrackedTargetBookkeeping) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    </style>
    <div id='target'></div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer1 = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);
  observer1->observe(target);
  IntersectionObserver* observer2 = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);
  observer2->observe(target);

  ElementIntersectionObserverData* target_data =
      target->IntersectionObserverData();
  ASSERT_TRUE(target_data);
  IntersectionObserverController& controller =
      GetDocument().EnsureIntersectionObserverController();
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 2u);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);

  target->remove();
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);
  GetDocument().body()->AppendChild(target);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 2u);

  observer1->unobserve(target);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 1u);

  observer2->unobserve(target);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);
}

TEST_F(IntersectionObserverTest, TrackedRootBookkeeping) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root'>
      <div id='target1'></div>
      <div id='target2'></div>
    </div>
  )HTML");

  IntersectionObserverController& controller =
      GetDocument().EnsureIntersectionObserverController();
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);

  Persistent<Element> root = GetDocument().getElementById(AtomicString("root"));
  Persistent<Element> target =
      GetDocument().getElementById(AtomicString("target1"));
  Persistent<IntersectionObserverInit> observer_init =
      IntersectionObserverInit::Create();
  observer_init->setRoot(MakeGarbageCollected<V8UnionDocumentOrElement>(root));
  Persistent<TestIntersectionObserverDelegate> observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  Persistent<IntersectionObserver> observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);

  // For an explicit-root observer, the root element is tracked only when it
  // has observations and is connected. Target elements are not tracked.
  ElementIntersectionObserverData* root_data = root->IntersectionObserverData();
  ASSERT_TRUE(root_data);
  EXPECT_FALSE(root_data->IsEmpty());
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);

  observer->observe(target);
  ElementIntersectionObserverData* target_data =
      target->IntersectionObserverData();
  ASSERT_TRUE(target_data);
  EXPECT_FALSE(target_data->IsEmpty());
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 1u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);

  // Root should not be tracked if it's not connected.
  root->remove();
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  GetDocument().body()->AppendChild(root);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 1u);

  // Root should not be tracked if it has no observations.
  observer->disconnect();
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  observer->observe(target);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 1u);
  observer->unobserve(target);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  observer->observe(target);
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 1u);

  // The existing observation should keep the observer alive and active.
  // Flush any pending notifications, which hold a hard reference to the
  // observer and can prevent it from being gc'ed. The observation will be the
  // only thing keeping the observer alive.
  test::RunPendingTasks();
  observer_delegate->Clear();
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_FALSE(root_data->IsEmpty());
  EXPECT_FALSE(target_data->IsEmpty());
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 1u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);

  // When the last observation is disconnected, as a result of the target
  // being gc'ed, the root element should no longer be tracked after the next
  // lifecycle update.
  target->remove();
  target = nullptr;
  target_data = nullptr;
  // Removing the target from the DOM tree forces a notification to be
  // queued, so flush it out.
  test::RunPendingTasks();
  observer_delegate->Clear();
  ThreadState::Current()->CollectAllGarbageForTesting();
  Compositor().BeginFrame();
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);

  // Removing the last reference to the observer should allow it to be dropeed
  // from the root's ElementIntersectionObserverData.
  observer = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_TRUE(root_data->IsEmpty());

  target = GetDocument().getElementById(AtomicString("target2"));
  observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);
  observer->observe(target);
  target_data = target->IntersectionObserverData();
  ASSERT_TRUE(target_data);

  // If the explicit root of an observer goes away, any existing observations
  // should be disconnected.
  target->remove();
  root->remove();
  root = nullptr;
  test::RunPendingTasks();
  observer_delegate->Clear();
  observer_delegate = nullptr;
  observer_init = nullptr;
  // Removing the target from the tree is not enough to disconnect the
  // observation.
  EXPECT_FALSE(target_data->IsEmpty());
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_TRUE(target_data->IsEmpty());
  EXPECT_EQ(controller.GetTrackedObserverCountForTesting(), 0u);
  EXPECT_EQ(controller.GetTrackedObservationCountForTesting(), 0u);
}

TEST_F(IntersectionObserverTest, InaccessibleTarget) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id=target></div>
  )HTML");

  Persistent<TestIntersectionObserverDelegate> observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  Persistent<IntersectionObserver> observer = IntersectionObserver::Create(
      IntersectionObserverInit::Create(), *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);

  Persistent<Element> target =
      GetDocument().getElementById(AtomicString("target"));
  ASSERT_EQ(observer_delegate->CallCount(), 0);
  ASSERT_FALSE(observer->HasPendingActivity());

  // When we start observing a target, we should queue up a task to deliver
  // the observation. The observer should have pending activity.
  observer->observe(target);
  Compositor().BeginFrame();
  ASSERT_EQ(observer_delegate->CallCount(), 0);
  EXPECT_TRUE(observer->HasPendingActivity());

  // After the observation is delivered, the observer no longer has activity
  // pending.
  test::RunPendingTasks();
  ASSERT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_FALSE(observer->HasPendingActivity());

  WeakPersistent<TestIntersectionObserverDelegate> observer_delegate_weak =
      observer_delegate.Get();
  WeakPersistent<IntersectionObserver> observer_weak = observer.Get();
  WeakPersistent<Element> target_weak = target.Get();
  ASSERT_TRUE(target_weak);
  ASSERT_TRUE(observer_weak);
  ASSERT_TRUE(observer_delegate_weak);

  // When |target| is no longer live, and |observer| has no more pending
  // tasks, both should be garbage-collected.
  target->remove();
  target = nullptr;
  observer = nullptr;
  observer_delegate = nullptr;
  test::RunPendingTasks();
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_FALSE(target_weak);
  EXPECT_FALSE(observer_weak);
  EXPECT_FALSE(observer_delegate_weak);
}

TEST_F(IntersectionObserverTest, InaccessibleTargetBeforeDelivery) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id=target></div>
  )HTML");

  Persistent<TestIntersectionObserverDelegate> observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  Persistent<IntersectionObserver> observer = IntersectionObserver::Create(
      IntersectionObserverInit::Create(), *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver);

  Persistent<Element> target =
      GetDocument().getElementById(AtomicString("target"));
  ASSERT_EQ(observer_delegate->CallCount(), 0);
  ASSERT_FALSE(observer->HasPendingActivity());

  WeakPersistent<TestIntersectionObserverDelegate> observer_delegate_weak =
      observer_delegate.Get();
  WeakPersistent<IntersectionObserver> observer_weak = observer.Get();
  WeakPersistent<Element> target_weak = target.Get();
  ASSERT_TRUE(target_weak);
  ASSERT_TRUE(observer_weak);
  ASSERT_TRUE(observer_delegate_weak);

  // When we start observing |target|, a task should be queued to call the
  // callback with |target| and other information. So even if we remove
  // |target| in the same tick, |observer| would be kept alive.
  observer->observe(target);
  target->remove();
  target = nullptr;
  observer = nullptr;
  observer_delegate = nullptr;
  Compositor().BeginFrame();
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_TRUE(target_weak);
  EXPECT_TRUE(observer_weak);
  EXPECT_TRUE(observer_delegate_weak);

  // Once we run the callback, the observer has no more pending tasks, and so
  // it should be garbage-collected along with the target.
  test::RunPendingTasks();
  ThreadState::Current()->CollectAllGarbageForTesting();
  EXPECT_FALSE(target_weak);
  EXPECT_FALSE(observer_weak);
  EXPECT_FALSE(observer_delegate_weak);
}

TEST_F(IntersectionObserverTest, RootMarginDevicePixelRatio) {
  WebView().SetZoomFactorForDeviceScaleFactor(3.5f);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(2800, 2100));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body {
      margin: 0;
    }
    #target {
      height: 30px;
    }
    </style>
    <div id='target'>Hello, world!</div>
  )HTML");
  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  observer_init->setRootMargin("-31px 0px 0px 0px");
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
  ASSERT_FALSE(exception_state.HadException());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(observer_delegate->CallCount(), 1);
  EXPECT_EQ(observer_delegate->EntryCount(), 1);
  EXPECT_FALSE(observer_delegate->LastEntry()->isIntersecting());
  EXPECT_RECTF_NEAR(observer_delegate->LastEntry()->GetGeometry().RootRect(),
                    gfx::RectF(0, 31, 800, 600 - 31), 0.0001);
}

TEST_F(IntersectionObserverTest, CachedRectsWithScrollers) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body { margin: 0; }
    .spacer { height: 1000px; }
    .scroller { overflow-y: scroll; height: 100px; position: relative; }
    </style>
    <div id='root' class='scroller'>
      <div id='target1-container'>
        <div id='target1'>Hello, world!</div>
      </div>
      <div class='scroller'>
        <div id='target2'>Hello, world!</div>
        <div class='spacer'></div>
      </div>
      <div class='scroller' style='overflow-y: hidden'>
        <div id='target3'>Hello, world!</div>
        <div class='spacer'></div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target1 = GetDocument().getElementById(AtomicString("target1"));
  Element* target2 = GetDocument().getElementById(AtomicString("target2"));
  Element* target3 = GetDocument().getElementById(AtomicString("target3"));
  // Ensure target3's ScrollTranslation node.
  target3->parentElement()->scrollTo(0, 10);

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
  observer->observe(target1, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target2, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target3, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  // CanUseCachedRectsForTesting requires clean layout.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  IntersectionObservation* observation1 =
      target1->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  IntersectionObservation* observation2 =
      target2->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  IntersectionObservation* observation3 =
      target3->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Generate initial notifications and populate cache
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  // observation2 can't use cached rects because the observer's root is not
  // the target's enclosing scroller.
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Scrolling the root should not invalidate.
  root->scrollTo(0, 100);
  target2->parentElement()->scrollTo(0, 100);
  target3->parentElement()->scrollTo(0, 100);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Scroll again.
  root->scrollTo(0, 200);
  target2->parentElement()->scrollTo(0, 200);
  target3->parentElement()->scrollTo(0, 200);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Changing layout between root and target should invalidate.
  target1->parentElement()->SetInlineStyleProperty(CSSPropertyID::kMarginLeft,
                                                   "10px");
  // Invalidation happens during compositing inputs update, so force it here.
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Moving target2/target3 out from the subscroller should allow it to cache
  // rects.
  target2->remove();
  root->appendChild(target2);
  target3->remove();
  root->appendChild(target3);
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_TRUE(CanUseCachedRects(*observation2));
  EXPECT_TRUE(CanUseCachedRects(*observation3));
}

TEST_F(IntersectionObserverTest, CachedRectsWithOverflowHidden) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body { margin: 0; }
    .spacer { height: 1000px; }
    .scroller { overflow-y: hidden; height: 100px; position: relative; }
    </style>
    <div id='root' class='scroller'>
      <div id='target1-container'>
        <div id='target1'>Hello, world!</div>
      </div>
      <div class='scroller' style='overflow-y: scroll'>
        <div id='target2'>Hello, world!</div>
        <div class='spacer'></div>
      </div>
      <div class='scroller'>
        <div id='target3'>Hello, world!</div>
        <div class='spacer'></div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target1 = GetDocument().getElementById(AtomicString("target1"));
  Element* target2 = GetDocument().getElementById(AtomicString("target2"));
  Element* target3 = GetDocument().getElementById(AtomicString("target3"));

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
  observer->observe(target1, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target2, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target3, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  // CanUseCachedRectsForTesting requires clean layout.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  IntersectionObservation* observation1 =
      target1->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  IntersectionObservation* observation2 =
      target2->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  IntersectionObservation* observation3 =
      target3->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Generate initial notifications and populate cache
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  // observation2 can't use cached rects because the observer's root is not
  // the target's enclosing scroller.
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Scrolling the root the first time creates a scroll translation node which
  // causes the invalidation.
  root->scrollTo(0, 100);
  target2->parentElement()->scrollTo(0, 100);
  target3->parentElement()->scrollTo(0, 100);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Generate initial notifications and populate cache
  Compositor().BeginFrame();
  test::RunPendingTasks();

  // Scroll again.
  root->scrollTo(0, 200);
  target2->parentElement()->scrollTo(0, 200);
  target3->parentElement()->scrollTo(0, 200);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation3));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Changing layout between root and target should invalidate.
  target1->parentElement()->SetInlineStyleProperty(CSSPropertyID::kMarginLeft,
                                                   "10px");
  // Invalidation happens during compositing inputs update, so force it here.
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation3));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_FALSE(CanUseCachedRects(*observation3));

  // Moving target2/target3 out from the subscroller should allow it to cache
  // rects.
  target2->remove();
  root->appendChild(target2);
  target3->remove();
  root->appendChild(target3);
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_TRUE(CanUseCachedRects(*observation2));
  EXPECT_TRUE(CanUseCachedRects(*observation3));
}

TEST_F(IntersectionObserverTest, CachedRectsWithoutIntermediateScrollable) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <style>
    body { margin: 0; }
    .spacer { height: 1000px; }
    .scroller { overflow-y: scroll; height: 100px; }
    </style>
    <div id='scroller1' class='scroller'>
      <div id='root' style='position: absolute'>
        <div id='target1'>Target1</div>
        <div id='scroller2' class='scroller'>
          <div id='target2'>Target2</div>
          <!-- No spacer, thus this scroller is not scrollable. -->
        </div>
        <div id='scroller3' class='scroller'>
          <!-- target3 is not contained by the scroller -->
          <div id='target3' style='position: absolute'>Target3</div>
          <div id='target4'>Target4</div>
          <div class='spacer'></div>
        </div>
      </div>
      <div class='spacer'></div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target1 = GetDocument().getElementById(AtomicString("target1"));
  Element* target2 = GetDocument().getElementById(AtomicString("target2"));
  Element* target3 = GetDocument().getElementById(AtomicString("target3"));
  Element* target4 = GetDocument().getElementById(AtomicString("target4"));

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
  observer->observe(target1, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target2, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target3, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(target4, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  // CanUseCachedRectsForTesting requires clean layout.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  IntersectionObservation* observation1 =
      target1->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  IntersectionObservation* observation2 =
      target2->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  IntersectionObservation* observation3 =
      target3->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation3));
  IntersectionObservation* observation4 =
      target4->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation4));

  // Generate initial notifications and populate cache.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_FALSE(CanUseCachedRects(*observation2));
  EXPECT_TRUE(CanUseCachedRects(*observation3));
  // scroller3 is an intermediate scroller between root and target4.
  EXPECT_FALSE(CanUseCachedRects(*observation4));
}

TEST_F(IntersectionObserverTest, CachedRectsWithPaintPropertyChange) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="root" style="position: absolute">
      <div id="container" style="opacity: 0.5; transform: translateX(10px)">
        <div id="target">Target</div>
      </div>
    </div>
  </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* target = GetDocument().getElementById(AtomicString("target"));

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

  IntersectionObservation* observation =
      target->IntersectionObserverData()->GetObservationFor(*observer);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation));

  // Generate initial notifications and populate cache.
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_TRUE(CanUseCachedRects(*observation));

  // Change of opacity doesn't invalidate cached rects.
  container->SetInlineStyleProperty(CSSPropertyID::kOpacity, "0.6");
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(CanUseCachedRects(*observation));
  container->SetInlineStyleProperty(CSSPropertyID::kTransform,
                                    "translateY(20px)");
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation));
}

TEST_F(IntersectionObserverTest, CachedRectsDisplayNone) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id='root'>
      <div id='target'>Hello, world!</div>
    </div>
  )HTML");

  Element* root = GetDocument().getElementById(AtomicString("root"));
  Element* target = GetDocument().getElementById(AtomicString("target"));

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
  IntersectionObservation* observation =
      target->IntersectionObserverData()->GetObservationFor(*observer);

  // Generate initial notifications and populate cache.
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation));

  target->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(CanUseCachedRects(*observation));
}

TEST_F(IntersectionObserverTest, CachedRectsWithFixedPosition) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <div id="fixed" style="position: fixed">
      <div id="child">Child</div>
    </div>
  )HTML");

  Element* fixed = GetDocument().getElementById(AtomicString("fixed"));
  Element* child = GetDocument().getElementById(AtomicString("child"));

  IntersectionObserverInit* observer_init = IntersectionObserverInit::Create();
  DummyExceptionStateForTesting exception_state;
  TestIntersectionObserverDelegate* observer_delegate =
      MakeGarbageCollected<TestIntersectionObserverDelegate>(GetDocument());
  IntersectionObserver* observer = IntersectionObserver::Create(
      observer_init, *observer_delegate,
      LocalFrameUkmAggregator::kJavascriptIntersectionObserver,
      exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(fixed, exception_state);
  ASSERT_FALSE(exception_state.HadException());
  observer->observe(child, exception_state);
  ASSERT_FALSE(exception_state.HadException());

  // CanUseCachedRectsForTesting requires clean layout.
  GetDocument().View()->UpdateLifecycleToLayoutClean(
      DocumentUpdateReason::kTest);

  IntersectionObservation* observation1 =
      fixed->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation1));
  IntersectionObservation* observation2 =
      child->IntersectionObserverData()->GetObservationFor(*observer);
  EXPECT_FALSE(CanUseCachedRects(*observation2));

  // Generate initial notifications and populate cache
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_TRUE(CanUseCachedRects(*observation2));

  GetDocument().domWindow()->scrollTo(0, 100);
  GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kTest);
  EXPECT_TRUE(CanUseCachedRects(*observation1));
  EXPECT_TRUE(CanUseCachedRects(*observation2));
}

TEST_F(IntersectionObserverTest, MinScrollDeltaToUpdateNotScrollable) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest main_resource("https://example.com/", "text/html");
  Lo
```