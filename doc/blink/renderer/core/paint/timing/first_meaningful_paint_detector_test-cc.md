Response:
Let's break down the thought process to arrive at the detailed explanation of the `first_meaningful_paint_detector_test.cc` file.

1. **Understand the Core Purpose:** The file name itself gives a huge clue: `first_meaningful_paint_detector_test.cc`. This immediately suggests that the primary function is to *test* the `FirstMeaningfulPaintDetector` class.

2. **Examine the Includes:** The included headers reveal the key components involved:
    * `FirstMeaningfulPaintDetector.h`:  The class being tested.
    * `gtest/gtest.h`: The Google Test framework, indicating unit tests.
    * `PaintEvent.h`, `PaintTiming.h`:  These are related to the paint lifecycle and timing measurements, crucial for understanding FMP.
    * `PageTestBase.h`: A base class for Blink tests, providing a testing environment.
    * `wtf/text/StringBuilder.h`: A utility for building strings, likely used to generate HTML content.

3. **Identify the Test Fixture:** The `FirstMeaningfulPaintDetectorTest` class inherits from `PageTestBase`. This is a standard practice in Blink testing. The constructor and `SetUp`/`TearDown` methods are important for setting up and cleaning up the testing environment. Notice the manipulation of the clock (`AdvanceClock`, `SetTickClockForTesting`), which is essential for testing time-sensitive metrics like FMP.

4. **Analyze Helper Functions:** The protected member functions within the test fixture are key to understanding how the tests work:
    * `Now()`, `AdvanceClockAndGetTime()`:  Time manipulation.
    * `GetPaintTiming()`, `Detector()`: Accessors to the core classes being tested.
    * `SimulateLayoutAndPaint()`:  The most crucial helper. It simulates adding elements, triggering layout, and notifying the detector about a paint event. This is how test scenarios are created. *Initially, I might just gloss over the details, but a closer look reveals the use of `StringBuilder` to create HTML dynamically, linking it to HTML rendering.*
    * `SimulateNetworkStable()`, `SimulateUserInput()`:  Simulate key browser events that affect FMP calculation.
    * `Clear*PresentationPromise()`: Functions related to clearing presentation callbacks, important for asynchronicity in rendering.
    * `OutstandingDetectorPresentationPromiseCount()`:  Allows verification of internal state.
    * `MarkFirstContentfulPaintAndClearPresentationPromise()`, `MarkFirstPaintAndClearPresentationPromise()`:  Helper functions to simulate the completion of earlier paint metrics.

5. **Examine the Test Cases (TEST_F Macros):** Each `TEST_F` macro defines a specific test scenario. By reading the names of the tests, we can get a high-level understanding of what aspects of FMP detection are being tested:
    * "NoFirstPaint":  What happens if there's no initial paint.
    * "OneLayout", "TwoLayoutsSignificantSecond", etc.:  Scenarios with varying numbers of layouts and their impact on FMP. The terms "significant first/second" hint at the logic of how FMP is determined based on the size of the paint.
    * Tests involving `NetworkStable`, `UserInput`: How these external events influence FMP.
    * Tests involving `PresentationPromise`:  Testing the asynchronous nature of FMP calculation.

6. **Connect to Web Technologies:** At this stage, we start linking the test scenarios to how web pages work:
    * **HTML:** The `SimulateLayoutAndPaint()` function uses `GetDocument().write()` to inject HTML. This is the direct link to HTML content. The number of added elements (`new_elements`) directly relates to the amount of HTML content being rendered.
    * **CSS:** While not explicitly manipulated in this test *at the level of setting CSS properties*, the act of layout and paint inherently involves CSS. The rendering engine uses CSS to style the elements and determine their layout. The "significant" in test names implies changes in visual output, which CSS affects.
    * **JavaScript:**  `SimulateUserInput()` mimics user interaction, which often triggers JavaScript. The tests explore how user interaction affects the FMP calculation, especially the delay or cancellation of FMP. JavaScript can dynamically modify the DOM, leading to repaints and potentially influencing FMP.
    * **Network:** `SimulateNetworkStable()` represents the point when all initial resources are loaded. This is a crucial signal for FMP determination.

7. **Infer Logic and Examples:** Based on the test names and the helper functions, we can infer the logic being tested. For example:
    * "TwoLayoutsSignificantSecond" likely tests that if the second paint is much larger than the first, it's more likely to be considered the FMP.
    * Tests involving `PresentationPromise` check that FMP isn't finalized until the rendering pipeline confirms the paint has been presented to the user.

8. **Identify Potential User/Programming Errors:**  Consider how developers might misuse the APIs or how the browser could behave unexpectedly. The tests themselves often highlight potential issues:
    * FMP happening before FCP is an illogical state that the tests verify is prevented.
    * User interaction resetting FMP is a design consideration being tested.

9. **Trace User Actions (Debugging):** Think about how a user's actions lead to the execution of this code. Loading a webpage, the browser parsing HTML/CSS, network requests for resources, rendering the page, user interactions – these are the steps. The test file simulates these actions in a controlled way. As a debugger, you might set breakpoints in the `FirstMeaningfulPaintDetector` class or related paint timing code to understand the flow when specific user actions occur.

10. **Refine and Structure:**  Organize the findings into clear categories (functionality, relation to web tech, logic, errors, user journey). Provide specific examples from the code and relate them to real-world web development scenarios.

By following this methodical approach, examining the code structure, and connecting it to web technologies and user interactions, we can arrive at a comprehensive understanding of the `first_meaningful_paint_detector_test.cc` file's purpose and implications.
这个文件 `first_meaningful_paint_detector_test.cc` 是 Chromium Blink 渲染引擎的一部分，它的主要**功能是测试 `FirstMeaningfulPaintDetector` 这个类的逻辑是否正确**。 `FirstMeaningfulPaintDetector` 的职责是 **检测网页的首次有意义绘制 (First Meaningful Paint, FMP) 的时间点**。

以下是更详细的解释：

**文件功能:**

1. **单元测试:**  该文件包含了针对 `FirstMeaningfulPaintDetector` 类的各种单元测试用例。这些测试用例旨在覆盖 FMP 检测器的不同状态、输入和预期行为。
2. **验证 FMP 计算逻辑:** 测试用例模拟不同的场景，例如：
    * 不同的布局和绘制事件的顺序和重要性。
    * 网络状态的变化 (例如，网络何时稳定)。
    * 用户交互事件的发生。
    * 各种 paint timing 事件 (例如，First Contentful Paint)。
3. **确保 FMP 的准确性:** 通过运行这些测试，开发者可以验证 `FirstMeaningfulPaintDetector` 是否在各种情况下都能正确地计算和报告 FMP 的时间。

**与 JavaScript, HTML, CSS 的关系:**

`FirstMeaningfulPaintDetector` 的目标是衡量用户感知到的网页加载速度，这与 JavaScript、HTML 和 CSS 的渲染过程紧密相关。

* **HTML:** HTML 定义了网页的结构和内容。当浏览器解析 HTML 并构建 DOM 树时，`FirstMeaningfulPaintDetector` 会跟踪渲染过程。HTML 中包含的资源 (例如，图片、脚本) 的加载也会影响 FMP。测试用例中的 `SimulateLayoutAndPaint()` 方法会通过 `GetDocument().write()` 注入 HTML 片段，模拟内容的变化。例如，`SimulateLayoutAndPaint(10)` 意味着添加了 10 个 `<span>a</span>` 元素，这会触发布局和绘制。
* **CSS:** CSS 负责网页的样式和布局。CSS 的解析和应用会影响渲染树的构建和最终的绘制结果。`FirstMeaningfulPaintDetector` 会关注哪些绘制是“有意义的”，这意味着用户能够看到主要内容。虽然测试用例没有直接操作 CSS 属性，但布局和绘制过程本身就包含了 CSS 的影响。 例如，如果一个包含大量 CSS 样式的页面需要更长的时间才能呈现出主要内容，FMP 的时间也会相应地推迟。
* **JavaScript:** JavaScript 可以动态地修改 DOM 结构和 CSS 样式，从而触发重绘和回流。`FirstMeaningfulPaintDetector` 需要能够处理这些动态变化。测试用例中的 `SimulateUserInput()` 方法模拟用户交互，这可能会触发 JavaScript 代码的执行，从而影响 FMP 的计算。例如，如果用户在页面加载初期进行交互，可能会导致 FMP 的计算被推迟，因为此时可能还不是“有意义”的绘制。

**举例说明:**

* **HTML:**  假设一个网页的 HTML 结构如下：
  ```html
  <!DOCTYPE html>
  <html>
  <head>
    <title>My Page</title>
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <header>
      <h1>Welcome</h1>
    </header>
    <main>
      <p>This is the main content.</p>
      <img src="important-image.jpg" alt="Important Image">
    </main>
    <footer>
      <p>&copy; 2023</p>
    </footer>
    <script src="script.js"></script>
  </body>
  </html>
  ```
  `FirstMeaningfulPaintDetector` 的目标可能是检测到 `main` 标签内的内容 (段落和图片) 何时被渲染出来。

* **CSS:**  `style.css` 文件可能会定义 `main` 标签内元素的样式，例如：
  ```css
  main p {
    font-size: 16px;
    color: #333;
  }
  main img {
    width: 50%;
  }
  ```
  CSS 加载和解析的快慢会影响 `main` 标签内元素的渲染时间，进而影响 FMP 的时间点。

* **JavaScript:** `script.js` 可能会在页面加载后动态地修改 `main` 标签的内容，例如添加新的段落。`FirstMeaningfulPaintDetector` 需要考虑这种动态变化，确保在主要的、用户关心的内容渲染出来后才记录 FMP。

**逻辑推理与假设输入输出:**

考虑 `TEST_F(FirstMeaningfulPaintDetectorTest, TwoLayoutsSignificantSecond)` 这个测试用例：

* **假设输入:**
    1. 首先，触发一个包含少量元素 (`SimulateLayoutAndPaint(1)`) 的布局和绘制。
    2. 然后，触发一个包含大量元素 (`SimulateLayoutAndPaint(10)`) 的布局和绘制。
    3. 最后，模拟网络稳定 (`SimulateNetworkStable()`)。

* **逻辑推理:**  如果第二个布局绘制的内容比第一个重要得多 (元素数量更多，通常意味着视觉上的变化更大)，那么 FMP 应该发生在第二个布局绘制之后，且在网络稳定之前。

* **预期输出:** `GetPaintTiming().FirstMeaningfulPaint()` 的值应该大于第一个布局绘制的时间 (`after_layout1`)，但小于第二个布局绘制的时间 (`after_layout2`)。

**用户或编程常见的使用错误:**

* **过早地认为页面加载完成:** 开发者可能会在所有资源都加载完成之前就执行一些依赖于页面内容的 JavaScript 代码，导致错误或不一致的行为。FMP 可以帮助开发者了解用户何时能够看到主要内容，从而更好地组织 JavaScript 代码的执行时机。
* **忽略初始渲染的重要性:** 有些开发者可能只关注交互性，而忽略了初始渲染速度。FMP 可以作为一个指标，提醒开发者优化初始渲染路径，提升用户体验。
* **不正确的 FMP 定义:**  开发者可能对“有意义的绘制”有不同的理解。`FirstMeaningfulPaintDetector` 的实现是基于一定的启发式规则，开发者需要理解这些规则，并根据自己的应用场景进行调整或考虑使用其他性能指标。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击一个链接。**
2. **浏览器发起网络请求获取 HTML 资源。**
3. **浏览器解析 HTML，构建 DOM 树。**  在这个过程中，`FirstMeaningfulPaintDetector` 开始工作。
4. **浏览器解析 CSS，构建 CSSOM 树。**
5. **浏览器将 DOM 树和 CSSOM 树合并成渲染树。**
6. **浏览器进行布局 (Layout)，计算每个节点在屏幕上的位置和大小。** `SimulateLayoutAndPaint()` 模拟了这个过程。
7. **浏览器进行绘制 (Paint)，将渲染树的节点绘制到屏幕上。** `Detector().NotifyPaint()` 通知 `FirstMeaningfulPaintDetector` 发生了绘制事件。
8. **如果 HTML 中包含外部资源 (例如，图片、CSS、JavaScript)，浏览器会发起额外的网络请求。** `SimulateNetworkStable()` 模拟了所有关键资源加载完成的状态。
9. **JavaScript 代码可能会执行，并动态地修改 DOM 或 CSS，导致回流和重绘。** `SimulateUserInput()` 可以模拟用户交互，这可能触发 JavaScript 代码的执行。
10. **`FirstMeaningfulPaintDetector` 会监听这些事件，并根据其内部逻辑判断 FMP 的时间点。**
11. **开发者可以使用浏览器的开发者工具 (例如，Performance 面板) 来查看 FMP 的值，以及与 FMP 相关的其他性能指标。**

在调试与 FMP 相关的问题时，开发者可能会：

* **查看 Performance 面板的时间线，分析渲染事件和网络请求。**
* **使用 `console.time()` 和 `console.timeEnd()` API 来测量特定代码块的执行时间，以找出性能瓶颈。**
* **检查网络请求瀑布图，分析资源加载顺序和耗时。**
* **分析页面的 HTML 结构和 CSS 样式，找出可能导致渲染阻塞的因素。**
* **使用 Chrome 的 `about:tracing` 工具进行更底层的性能分析。**

`first_meaningful_paint_detector_test.cc` 文件中的测试用例模拟了这些底层的渲染和网络事件，帮助开发者理解 `FirstMeaningfulPaintDetector` 的工作原理，并在开发过程中尽早发现和修复与 FMP 相关的问题。

### 提示词
```
这是目录为blink/renderer/core/paint/timing/first_meaningful_paint_detector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/first_meaningful_paint_detector.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/paint/paint_event.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class FirstMeaningfulPaintDetectorTest : public PageTestBase {
 public:
  FirstMeaningfulPaintDetectorTest()
      : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

 protected:
  void SetUp() override {
    EnablePlatform();
    AdvanceClock(base::Seconds(1));
    const base::TickClock* test_clock = platform()->GetTickClock();
    FirstMeaningfulPaintDetector::SetTickClockForTesting(test_clock);
    PageTestBase::SetUp();
    GetPaintTiming().SetTickClockForTesting(test_clock);
  }

  void TearDown() override {
    const base::TickClock* clock = base::DefaultTickClock::GetInstance();
    GetPaintTiming().SetTickClockForTesting(clock);
    PageTestBase::TearDown();
    FirstMeaningfulPaintDetector::SetTickClockForTesting(clock);
  }

  base::TimeTicks Now() { return platform()->NowTicks(); }

  base::TimeTicks AdvanceClockAndGetTime() {
    AdvanceClock(base::Seconds(1));
    return Now();
  }

  PaintTiming& GetPaintTiming() { return PaintTiming::From(GetDocument()); }
  FirstMeaningfulPaintDetector& Detector() {
    return GetPaintTiming().GetFirstMeaningfulPaintDetector();
  }

  void SimulateLayoutAndPaint(int new_elements) {
    AdvanceClock(base::Milliseconds(1));
    StringBuilder builder;
    for (int i = 0; i < new_elements; i++)
      builder.Append("<span>a</span>");
    GetDocument().write(builder.ToString());
    GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
    Detector().NotifyPaint();
  }

  void SimulateNetworkStable() {
    GetDocument().SetParsingState(Document::kFinishedParsing);
    Detector().OnNetwork2Quiet();
  }

  void SimulateUserInput() { Detector().NotifyInputEvent(); }

  void ClearFirstPaintPresentationPromise() {
    AdvanceClock(base::Milliseconds(1));
    viz::FrameTimingDetails presentation_details;
    presentation_details.presentation_feedback.timestamp = Now();
    GetPaintTiming().ReportPresentationTime(PaintEvent::kFirstPaint,
                                            presentation_details);
  }

  void ClearFirstContentfulPaintPresentationPromise() {
    AdvanceClock(base::Milliseconds(1));
    viz::FrameTimingDetails presentation_details;
    presentation_details.presentation_feedback.timestamp = Now();
    GetPaintTiming().ReportPresentationTime(PaintEvent::kFirstContentfulPaint,
                                            presentation_details);
  }

  void ClearProvisionalFirstMeaningfulPaintPresentationPromise() {
    AdvanceClock(base::Milliseconds(1));
    ClearProvisionalFirstMeaningfulPaintPresentationPromise(Now());
  }

  void ClearProvisionalFirstMeaningfulPaintPresentationPromise(
      base::TimeTicks timestamp) {
    viz::FrameTimingDetails presentation_details;
    presentation_details.presentation_feedback.timestamp = timestamp;
    Detector().ReportPresentationTime(
        PaintEvent::kProvisionalFirstMeaningfulPaint, presentation_details);
  }

  unsigned OutstandingDetectorPresentationPromiseCount() {
    return Detector().outstanding_presentation_promise_count_;
  }

  void MarkFirstContentfulPaintAndClearPresentationPromise() {
    GetPaintTiming().MarkFirstContentfulPaint();
    ClearFirstContentfulPaintPresentationPromise();
  }

  void MarkFirstPaintAndClearPresentationPromise() {
    GetPaintTiming().MarkFirstPaint();
    ClearFirstPaintPresentationPromise();
  }
};

TEST_F(FirstMeaningfulPaintDetectorTest, NoFirstPaint) {
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 0U);
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
}

TEST_F(FirstMeaningfulPaintDetectorTest, OneLayout) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  base::TimeTicks after_paint = AdvanceClockAndGetTime();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  SimulateNetworkStable();
  EXPECT_LT(GetPaintTiming().FirstMeaningfulPaint(), after_paint);
}

TEST_F(FirstMeaningfulPaintDetectorTest, TwoLayoutsSignificantSecond) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  base::TimeTicks after_layout1 = AdvanceClockAndGetTime();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  base::TimeTicks after_layout2 = AdvanceClockAndGetTime();
  SimulateNetworkStable();
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(), after_layout1);
  EXPECT_LT(GetPaintTiming().FirstMeaningfulPaint(), after_layout2);
}

TEST_F(FirstMeaningfulPaintDetectorTest, TwoLayoutsSignificantFirst) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  base::TimeTicks after_layout1 = AdvanceClockAndGetTime();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 0U);
  SimulateNetworkStable();
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(),
            GetPaintTiming().FirstPaintRendered());
  EXPECT_LT(GetPaintTiming().FirstMeaningfulPaint(), after_layout1);
}

TEST_F(FirstMeaningfulPaintDetectorTest, FirstMeaningfulPaintCandidate) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(),
            base::TimeTicks());
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  base::TimeTicks after_paint = AdvanceClockAndGetTime();
  // The first candidate gets ignored.
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(),
            base::TimeTicks());
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  // The second candidate gets reported.
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaintCandidate(), after_paint);
  base::TimeTicks candidate = GetPaintTiming().FirstMeaningfulPaintCandidate();
  // The third candidate gets ignored since we already saw the first candidate.
  SimulateLayoutAndPaint(20);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(), candidate);
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       OnlyOneFirstMeaningfulPaintCandidateBeforeNetworkStable) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(),
            base::TimeTicks());
  base::TimeTicks before_paint = AdvanceClockAndGetTime();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  // The first candidate is initially ignored.
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(),
            base::TimeTicks());
  SimulateNetworkStable();
  // The networkStable then promotes the first candidate.
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaintCandidate(), before_paint);
  base::TimeTicks candidate = GetPaintTiming().FirstMeaningfulPaintCandidate();
  // The second candidate is then ignored.
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 0U);
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaintCandidate(), candidate);
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       NetworkStableBeforeFirstContentfulPaint) {
  MarkFirstPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateNetworkStable();
  EXPECT_NE(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       FirstMeaningfulPaintShouldNotBeBeforeFirstContentfulPaint) {
  MarkFirstPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  AdvanceClock(base::Milliseconds(1));
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateNetworkStable();
  EXPECT_GE(GetPaintTiming().FirstMeaningfulPaint(),
            GetPaintTiming().FirstContentfulPaintIgnoringSoftNavigations());
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       FirstMeaningfulPaintAfterUserInteraction) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateUserInput();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
}

TEST_F(FirstMeaningfulPaintDetectorTest, UserInteractionBeforeFirstPaint) {
  SimulateUserInput();
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  SimulateNetworkStable();
  EXPECT_NE(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       WaitForSingleOutstandingPresentationPromiseAfterNetworkStable) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  EXPECT_NE(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       WaitForMultipleOutstandingPresentationPromisesAfterNetworkStable) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  AdvanceClock(base::Milliseconds(1));
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 2U);
  // Having outstanding presentation promises should defer setting FMP.
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  // Clearing the first presentation promise should have no effect on FMP.
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  base::TimeTicks after_first_presentation = AdvanceClockAndGetTime();
  // Clearing the last outstanding presentation promise should set FMP.
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 0U);
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(), after_first_presentation);
}

TEST_F(FirstMeaningfulPaintDetectorTest,
       WaitForFirstContentfulPaintPresentationpAfterNetworkStable) {
  MarkFirstPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);
  ClearProvisionalFirstMeaningfulPaintPresentationPromise();
  AdvanceClock(base::Milliseconds(1));
  GetPaintTiming().MarkFirstContentfulPaint();
  // FCP > FMP candidate, but still waiting for FCP presentation.
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  // Trigger notifying the detector about the FCP presentation.
  ClearFirstContentfulPaintPresentationPromise();
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(),
            GetPaintTiming().FirstContentfulPaintIgnoringSoftNavigations());
}

TEST_F(
    FirstMeaningfulPaintDetectorTest,
    ProvisionalTimestampChangesAfterNetworkQuietWithOutstandingPresentationPromise) {
  MarkFirstContentfulPaintAndClearPresentationPromise();
  SimulateLayoutAndPaint(1);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);

  // Simulate network stable so provisional FMP will be set on next layout.
  base::TimeTicks pre_stable_timestamp = AdvanceClockAndGetTime();
  AdvanceClock(base::Milliseconds(1));
  SimulateNetworkStable();
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());

  // Force another FMP candidate while there is a pending presentation promise
  // and the FMP non-presentation timestamp is set.
  AdvanceClock(base::Milliseconds(1));
  SimulateLayoutAndPaint(10);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 1U);

  // Simulate a delay in receiving the PresentationPromise timestamp. Clearing
  // this PresentationPromise will set FMP, and this will crash if the new
  // provisional non-presentation timestamp is used.
  ClearProvisionalFirstMeaningfulPaintPresentationPromise(pre_stable_timestamp);
  EXPECT_EQ(OutstandingDetectorPresentationPromiseCount(), 0U);
  EXPECT_GT(GetPaintTiming().FirstMeaningfulPaint(), base::TimeTicks());
  EXPECT_EQ(GetPaintTiming().FirstMeaningfulPaint(), pre_stable_timestamp);
}

}  // namespace blink
```