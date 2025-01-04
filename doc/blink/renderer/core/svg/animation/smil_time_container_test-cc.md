Response:
The user wants to understand the functionality of the `smil_time_container_test.cc` file in the Chromium Blink engine. I need to analyze the code and provide:

1. **Overall Functionality:** Describe what the test file is intended to do.
2. **Relationship with Web Technologies:** Explain how the tested code relates to JavaScript, HTML, and CSS, providing examples.
3. **Logical Reasoning:**  Identify any logical flows or conditions being tested, offering hypothetical inputs and outputs.
4. **Common User/Programming Errors:** Point out potential mistakes users or developers might make in relation to the tested functionality.
5. **Debugging Information:** Describe user steps that might lead to this code being executed, aiding in debugging.

**Analysis of the Code:**

The file contains unit tests for `SMILTimeContainer`. `SMILTimeContainer` is responsible for managing the timing of SMIL animations within an SVG document. The tests cover various aspects of its behavior, including:

*   Synchronization of animations with the rendering pipeline.
*   Handling of time progression and potential lag.
*   Interaction with document lifecycle events like `DOMContentLoaded`.
*   Behavior under different animation policies (e.g., `animate-once`).
*   Functionality of pausing, unpausing, and setting the elapsed time of the animation timeline.

**Mapping to Web Technologies:**

*   **HTML:** The tests use HTML snippets to define SVG elements and their animations using SMIL tags like `<animate>` and `<set>`.
*   **CSS:** While not explicitly tested, SMIL animations can affect the visual presentation of SVG elements, which are often styled using CSS. The `fill` attribute in the examples demonstrates a basic styling aspect.
*   **JavaScript:** While the tests are in C++, they verify the behavior of the SMIL animation engine, which is exposed and controllable through JavaScript APIs like `getCurrentTime()` on SVG animation elements.

**Logical Reasoning:**

The tests involve setting up specific scenarios with SMIL animations and then advancing the simulated time to check if the animation behaves as expected. This involves comparing the actual state of the animated properties (e.g., `rect->height()->CurrentValue()->Value(length_context)`) with the expected state at a given time.

**User/Programming Errors:**

Common errors could involve incorrect syntax in SMIL attributes, misunderstanding how time values are interpreted, or expecting animations to behave in a certain way without considering the specific timing attributes (`begin`, `dur`, `repeatCount`).

**Debugging Scenario:**

A developer might end up investigating this code if they are encountering issues with SMIL animations in their web application. This could involve animations not starting or stopping at the expected times, or inconsistencies in animation behavior across different browsers.

**Plan:**

1. Summarize the core functionality of `SMILTimeContainerTest`.
2. Explain the connection to HTML, CSS, and JavaScript with concrete examples from the code.
3. Provide examples of logical reasoning within the tests, including input HTML and expected animation outcomes.
4. List common user errors related to SMIL animations.
5. Outline a user interaction scenario that would trigger the execution of the tested code.
这个文件 `smil_time_container_test.cc` 是 Chromium Blink 引擎中用于测试 `SMILTimeContainer` 类的单元测试文件。`SMILTimeContainer` 类主要负责管理 SVG 文档中 SMIL (Synchronized Multimedia Integration Language) 动画的时间轴。

以下是该文件的功能分解：

**1. 核心功能：测试 SMIL 动画的时间管理**

   - 该文件通过一系列的单元测试用例来验证 `SMILTimeContainer` 类在不同场景下的行为是否符合预期。
   - 测试内容涵盖了动画的启动、暂停、恢复、时间推进、以及在特定动画策略下的行为。
   - 它模拟了时间的流逝，并检查动画的状态和属性是否按照 SMIL 规范进行更新。

**2. 与 JavaScript, HTML, CSS 的关系**

   - **HTML:** 该测试文件通过加载包含 SVG 元素的 HTML 字符串来创建测试环境。这些 SVG 元素通常包含 SMIL 动画标签，例如 `<animate>` 和 `<set>`。
     * **举例:** 代码中使用了 `R"HTML(...)HTML"` 这样的原始字符串字面量来定义包含 `<svg>`, `<rect>`, `<animate>`, `<set>` 等标签的 HTML 结构。这些 HTML 结构定义了要进行动画的元素及其动画属性。
   - **CSS:** 虽然该测试文件没有直接测试 CSS 的功能，但 SMIL 动画会改变 SVG 元素的属性，这些属性的变化最终会影响元素的渲染样式。例如，`<animate attributeName="width" ...>` 会改变矩形的宽度，而矩形的填充颜色 (如 `fill="green"`) 可以通过 CSS 进行设置。
     * **举例:** 测试用例中创建的 `<rect width="100" height="0" fill="green"/>`，`fill="green"` 就是一个内联样式，虽然简单，但也体现了样式与动画的交互。动画改变 `width` 和 `height` 属性，从而影响元素的最终视觉呈现。
   - **JavaScript:** SMIL 动画的行为最终是由浏览器引擎实现的，而开发者可以使用 JavaScript 来与 SMIL 动画进行交互，例如获取动画的当前时间、暂停或恢复动画。该测试文件模拟了浏览器引擎的内部行为，验证了这些交互的正确性。虽然测试本身是用 C++ 编写的，但它测试的功能是用户可以通过 JavaScript 影响的。
     * **举例:**  用户可以使用 JavaScript 获取 SVG 元素的动画状态，例如使用 `element.animationsPaused()` 来检查动画是否暂停，或者使用 `element.getCurrentTime()` 获取当前动画时间。该测试文件验证了引擎内部管理时间的方式与这些 JavaScript API 的预期行为一致。

**3. 逻辑推理与假设输入输出**

   - **假设输入:** 一个包含一个矩形和对其 `height` 属性进行动画的 `<set>` 元素的 SVG 字符串。
     ```html
     <svg id="container">
       <rect width="100" height="0" fill="green">
         <set attributeName="height" to="100" />
       </rect>
     </svg>
     ```
   - **测试逻辑:**  测试用例 `ServiceAnimationsFlushesPendingSynchronizations` 插入了这个 `<set>` 元素，然后模拟一个帧回调。
   - **预期输出:**  在帧回调后，即使同步计时器没有触发，矩形的高度应该立即更新为 100。这是因为帧回调应该刷新所有待处理的同步操作。
   - **具体断言:** `EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));`

   - **假设输入:** 一个包含一个矩形和对其 `width` 属性进行无限循环动画的 `<animate>` 元素的 SVG 字符串，动画时长为 5 分钟。
     ```html
     <svg id="container">
       <rect width="100" height="100" fill="blue">
         <animate begin="0s" dur="5min" repeatCount="indefinite"
                  attributeName="width" from="0" to="100"/>
       </rect>
     </svg>
     ```
   - **测试逻辑:** 测试用例 `ServiceAnimationsResyncOnLag` 将时间快进 60 分钟。
   - **预期输出:**  由于动画从 t=0s 开始生成帧回调，它会在 1 分钟后自动挂起。因此，时间容器的经过时间应该为 60 秒。
   - **具体断言:** `EXPECT_EQ(SMILTime::FromSecondsD(60), time_container->Elapsed());`

**4. 用户或编程常见的使用错误**

   - **错误理解 SMIL 时间语义:** 用户可能会错误地理解 SMIL 动画的 `begin`, `dur`, `repeatCount` 等属性如何影响动画的播放时间。例如，认为设置了 `begin="50min"` 的动画会在页面加载后立即开始，而实际上它会等待 50 分钟才开始首次播放。
     * **测试用例体现:** `ServiceAnimationsNoResyncAfterFutureFrame` 测试了这种情况，确保即使时间提前了，但动画尚未开始，时间容器也不会出现意外的同步行为。
   - **不理解动画挂起和恢复的机制:** 用户可能不清楚浏览器何时会自动挂起 SMIL 动画，以及如何通过 JavaScript 手动控制动画的暂停和恢复。
     * **测试用例体现:** `ServiceAnimationsNoSuspendOnAnimationSync` 确保在没有动画运行的情况下插入动画元素不会导致时间轴被意外挂起。
   - **在动画策略为 "animate-once" 时的误用:** 当动画策略设置为 "animate-once" 时，动画只会播放一次。用户可能期望在之后能像无限循环动画一样继续播放，但实际不会。
     * **测试用例体现:** `SMILTimeContainerAnimationPolicyOnceTest` 系列的测试用例覆盖了在这种策略下，设置 elapsed time、暂停、恢复等操作的行为。例如，`PauseAfterStart` 测试了在动画开始后暂停，然后恢复，动画是否会从暂停的地方继续播放一次。

**5. 用户操作如何一步步到达这里 (调试线索)**

   1. **用户在 HTML 中使用了 SVG 元素并添加了 SMIL 动画。** 例如，在网页中嵌入了包含 `<animate>` 或 `<set>` 标签的 SVG 代码。
   2. **浏览器加载并解析该 HTML 文档。** Blink 引擎会解析这些 SMIL 动画声明。
   3. **当浏览器需要渲染动画帧时，或者当 JavaScript 与动画进行交互时（例如，获取动画的当前时间），`SMILTimeContainer` 类会被调用。** 这个类负责管理动画的时间进度。
   4. **如果在动画播放过程中出现异常行为，例如动画没有按预期开始、停止、或更新属性，开发者可能会开始调试。**
   5. **作为 Chromium 开发者，为了排查 Blink 引擎中 SMIL 动画的 bug，可能会查看 `smil_time_container_test.cc` 文件，** 以了解 `SMILTimeContainer` 的预期行为和现有的测试覆盖范围。
   6. **开发者可能会运行这些测试用例，或者添加新的测试用例来复现和验证他们发现的问题。**
   7. **更进一步，开发者可能会在 Blink 引擎的源代码中设置断点，跟踪 `SMILTimeContainer` 的执行流程，** 以理解在特定用户操作下，时间是如何被管理和更新的。例如，可能会在 `SMILTimeContainer::ServiceAnimations()` 或 `SMILTimeContainer::SetElapsed()` 等方法中设置断点。
   8. **用户的特定操作，例如页面加载、定时器触发、或者 JavaScript 代码的执行，都可能触发对 `SMILTimeContainer` 的调用。**  `SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());`  这行代码模拟了在动画帧渲染时调用 SMIL 服务的情况，这在实际浏览器中是周期性发生的。

总而言之，`smil_time_container_test.cc` 文件是 Blink 引擎中确保 SMIL 动画时间管理功能正确性的重要组成部分。它通过模拟各种场景和用户操作，来验证 `SMILTimeContainer` 类的行为是否符合预期，从而保证了网页中 SVG 动画的正常运行。

Prompt: 
```
这是目录为blink/renderer/core/svg/animation/smil_time_container_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/svg/animation/smil_time_container.h"

#include "base/time/time.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_document_extensions.h"
#include "third_party/blink/renderer/core/svg/svg_length.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_rect_element.h"
#include "third_party/blink/renderer/core/svg/svg_set_element.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
namespace {

class SMILTimeContainerTest : public PageTestBase {
 public:
  SMILTimeContainerTest()
      : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    EnablePlatform();
    PageTestBase::SetUp();
  }

  void Load(std::string_view data) {
    auto params = WebNavigationParams::CreateWithHTMLStringForTesting(
        data, KURL("http://example.com"));
    GetFrame().Loader().CommitNavigation(std::move(params),
                                         nullptr /* extra_data */);
    GetAnimationClock().OverrideDynamicClockForTesting(
        platform()->GetTickClock());
    GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
    GetDocument().Timeline().ResetForTesting();
  }

  void StepTime(base::TimeDelta delta) {
    AnimationClock::NotifyTaskStart();
    AdvanceClock(delta);
    GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
    GetAnimationClock().UpdateTime(platform()->NowTicks());
  }
};

TEST_F(SMILTimeContainerTest, ServiceAnimationsFlushesPendingSynchronizations) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green"/>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(0, rect->height()->CurrentValue()->Value(length_context));

  // Insert an animation: <set attributeName="height" to="100"/> of the <rect>.
  auto* animation = MakeGarbageCollected<SVGSetElement>(GetDocument());
  animation->setAttribute(svg_names::kAttributeTypeAttr, AtomicString("XML"));
  animation->setAttribute(svg_names::kAttributeNameAttr,
                          AtomicString("height"));
  animation->setAttribute(svg_names::kToAttr, AtomicString("100"));
  rect->appendChild(animation);

  // Frame callback before the synchronization timer fires.
  SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());
  SVGDocumentExtensions::ServiceWebAnimationsOnAnimationFrame(GetDocument());

  // The frame callback should have flushed any pending updates.
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(500));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(0.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerTest, ServiceAnimationsResyncOnLag) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="100" fill="blue">
        <animate begin="0s" dur="5min" repeatCount="indefinite"
                 attributeName="width" from="0" to="100"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());

  // Step an hour ahead. Since the animation starts generating frame callbacks
  // at t=0s it will auto-suspend after 1 minute.
  StepTime(base::Minutes(60));
  SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());

  EXPECT_EQ(SMILTime::FromSecondsD(60), time_container->Elapsed());
}

TEST_F(SMILTimeContainerTest, ServiceAnimationsNoResyncAfterFutureFrame) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="100" fill="blue">
        <animate begin="50min" dur="5min" repeatCount="indefinite"
                 attributeName="width" from="0" to="100"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());

  // Like PageAnimator::PostAnimate(). Allows the clock to adjust for/during
  // the timer delay.
  GetAnimationClock().SetAllowedToDynamicallyUpdateTime(true);

  // Step 30 seconds into the first repeat of the animations interval. Since
  // the animation doesn't start generating frame callbacks until t=50min it
  // will not auto-suspend.
  const base::TimeDelta lag = base::Minutes(50) + base::Seconds(30);
  StepTime(lag);
  SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());

  EXPECT_EQ(SMILTime::FromTimeDelta(lag), time_container->Elapsed());
}

TEST_F(SMILTimeContainerTest, ServiceAnimationsNoSuspendOnAnimationSync) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="100" fill="blue"/>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());

  // Like PageAnimator::PostAnimate(). Allows the clock to adjust for/during
  // the timer delay.
  GetAnimationClock().SetAllowedToDynamicallyUpdateTime(true);

  // Step an hour ahead. There are no animations running, but the timeline is
  // active.
  const base::TimeDelta elapsed = base::Minutes(60);
  StepTime(elapsed);

  // Insert an animation element:
  //  <animate begin="0s" dur="5min" repeatCount="indefinite"
  //           attributeName="width" from="0" to="100"/>
  auto* animation = GetDocument().CreateRawElement(svg_names::kAnimateTag);
  animation->setAttribute(svg_names::kBeginAttr, AtomicString("0s"));
  animation->setAttribute(svg_names::kDurAttr, AtomicString("5min"));
  animation->setAttribute(svg_names::kRepeatCountAttr,
                          AtomicString("indefinite"));
  animation->setAttribute(svg_names::kAttributeNameAttr, AtomicString("width"));
  animation->setAttribute(svg_names::kFromAttr, AtomicString("0"));
  animation->setAttribute(svg_names::kToAttr, AtomicString("100"));
  svg_root->AppendChild(animation);

  SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());

  // The timeline should not have been suspended (i.e the time elapsed on the
  // timeline should equal the currently elapsed time).
  EXPECT_EQ(SMILTime::FromTimeDelta(elapsed), time_container->Elapsed());
}

class ContentLoadedEventListener final : public NativeEventListener {
 public:
  using CallbackType = base::OnceCallback<void(Document&)>;
  explicit ContentLoadedEventListener(CallbackType callback)
      : callback_(std::move(callback)) {}

  void Invoke(ExecutionContext* execution_context, Event*) override {
    std::move(callback_).Run(
        *To<LocalDOMWindow>(execution_context)->document());
  }

 private:
  CallbackType callback_;
};

class SMILTimeContainerAnimationPolicyOnceTest : public PageTestBase {
 public:
  SMILTimeContainerAnimationPolicyOnceTest()
      : PageTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    EnablePlatform();
    PageTestBase::SetupPageWithClients(nullptr, nullptr, &OverrideSettings);
  }

  void Load(std::string_view data) {
    auto params = WebNavigationParams::CreateWithHTMLStringForTesting(
        data, KURL("http://example.com"));
    GetFrame().Loader().CommitNavigation(std::move(params),
                                         nullptr /* extra_data */);
    GetAnimationClock().ResetTimeForTesting();
    GetAnimationClock().SetAllowedToDynamicallyUpdateTime(false);
    GetDocument().Timeline().ResetForTesting();
  }

  void StepTime(base::TimeDelta delta) {
    FastForwardBy(delta);
    current_time_ += delta;
    GetAnimationClock().UpdateTime(current_time_);
    SVGDocumentExtensions::ServiceSmilOnAnimationFrame(GetDocument());
    SVGDocumentExtensions::ServiceWebAnimationsOnAnimationFrame(GetDocument());
  }

  void OnContentLoaded(base::OnceCallback<void(Document&)> callback) {
    GetFrame().DomWindow()->addEventListener(
        event_type_names::kDOMContentLoaded,
        MakeGarbageCollected<ContentLoadedEventListener>(std::move(callback)));
  }

 private:
  static void OverrideSettings(Settings& settings) {
    settings.SetImageAnimationPolicy(
        mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAnimateOnce);
  }

  base::TimeTicks current_time_;
};

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, NoAction) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2500));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(500));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(3), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, SetElapsedAfterStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  time_container->SetElapsed(SMILTime::FromSecondsD(5.5));
  EXPECT_EQ(SMILTime::FromSecondsD(5.5), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2000));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(8.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, SetElapsedBeforeStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  OnContentLoaded(WTF::BindOnce([](Document& document) {
    auto* svg_root =
        To<SVGSVGElement>(document.getElementById(AtomicString("container")));
    ASSERT_TRUE(svg_root);
    auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
    ASSERT_TRUE(rect);
    SVGLengthContext length_context(rect);

    SMILTimeContainer* time_container = svg_root->TimeContainer();
    EXPECT_FALSE(time_container->IsStarted());
    EXPECT_FALSE(time_container->IsPaused());
    time_container->SetElapsed(SMILTime::FromSecondsD(5.5));
    EXPECT_EQ(0, rect->height()->CurrentValue()->Value(length_context));
  }));
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(5.5), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2000));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(8.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, PauseAfterStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  time_container->Pause();
  EXPECT_TRUE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());

  time_container->Unpause();
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());

  StepTime(base::Milliseconds(4000));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(4.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, PauseBeforeStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  OnContentLoaded(WTF::BindOnce([](Document& document) {
    auto* svg_root =
        To<SVGSVGElement>(document.getElementById(AtomicString("container")));
    ASSERT_TRUE(svg_root);
    auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
    ASSERT_TRUE(rect);
    SVGLengthContext length_context(rect);

    SMILTimeContainer* time_container = svg_root->TimeContainer();
    EXPECT_FALSE(time_container->IsStarted());
    EXPECT_FALSE(time_container->IsPaused());
    time_container->Pause();
    EXPECT_TRUE(time_container->IsPaused());
    EXPECT_EQ(0, rect->height()->CurrentValue()->Value(length_context));
  }));
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_TRUE(time_container->IsPaused());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(SMILTime::FromSecondsD(0), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  time_container->Unpause();
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(0), time_container->Elapsed());

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2500));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(3), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, PauseAndSetElapsedAfterStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  time_container->Pause();
  EXPECT_TRUE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());

  time_container->SetElapsed(SMILTime::FromSecondsD(0.5));
  EXPECT_EQ(SMILTime::FromSecondsD(0.5), time_container->Elapsed());

  time_container->Unpause();
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(0.5), time_container->Elapsed());

  StepTime(base::Milliseconds(4000));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(3.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest,
       PauseAndSetElapsedBeforeStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  OnContentLoaded(WTF::BindOnce([](Document& document) {
    auto* svg_root =
        To<SVGSVGElement>(document.getElementById(AtomicString("container")));
    ASSERT_TRUE(svg_root);
    auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
    ASSERT_TRUE(rect);
    SVGLengthContext length_context(rect);

    SMILTimeContainer* time_container = svg_root->TimeContainer();
    EXPECT_FALSE(time_container->IsStarted());
    EXPECT_FALSE(time_container->IsPaused());
    time_container->Pause();
    EXPECT_TRUE(time_container->IsPaused());
    time_container->SetElapsed(SMILTime::FromSecondsD(1.5));
    EXPECT_TRUE(time_container->IsPaused());
    EXPECT_EQ(0, rect->height()->CurrentValue()->Value(length_context));
  }));
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_TRUE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  time_container->Unpause();
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(1.5), time_container->Elapsed());

  StepTime(base::Milliseconds(2000));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2000));
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(4.5), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, PauseAndResumeBeforeStart) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  OnContentLoaded(WTF::BindOnce([](Document& document) {
    auto* svg_root =
        To<SVGSVGElement>(document.getElementById(AtomicString("container")));
    ASSERT_TRUE(svg_root);
    auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
    ASSERT_TRUE(rect);
    SVGLengthContext length_context(rect);

    SMILTimeContainer* time_container = svg_root->TimeContainer();
    EXPECT_FALSE(time_container->IsStarted());
    EXPECT_FALSE(time_container->IsPaused());
    time_container->Pause();
    EXPECT_TRUE(time_container->IsPaused());
    time_container->Unpause();
    EXPECT_FALSE(time_container->IsPaused());
    EXPECT_EQ(0, rect->height()->CurrentValue()->Value(length_context));
  }));
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(2500));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(500));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(3), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, PauseAndResumeAfterSuspended) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(0), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(1.0), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(2.0), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(SMILTime::FromSecondsD(3.0), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  time_container->Pause();
  EXPECT_TRUE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(3.0), time_container->Elapsed());

  time_container->Unpause();
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(3.0), time_container->Elapsed());

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(4.0), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(5.0), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(6.0), time_container->Elapsed());
}

TEST_F(SMILTimeContainerAnimationPolicyOnceTest, SetElapsedAfterSuspended) {
  Load(R"HTML(
    <svg id="container">
      <rect width="100" height="0" fill="green">
        <animate begin="0s" dur="3s" repeatCount="indefinite"
                 attributeName="height" values="30;50;100" calcMode="discrete"/>
      </rect>
    </svg>
  )HTML");
  platform()->RunUntilIdle();

  auto* svg_root = To<SVGSVGElement>(GetElementById("container"));
  ASSERT_TRUE(svg_root);
  auto* rect = Traversal<SVGRectElement>::FirstChild(*svg_root);
  ASSERT_TRUE(rect);
  SVGLengthContext length_context(rect);

  SMILTimeContainer* time_container = svg_root->TimeContainer();
  EXPECT_TRUE(time_container->IsStarted());
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(0), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(1.0), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(2.0), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(SMILTime::FromSecondsD(3.0), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  time_container->SetElapsed(SMILTime::FromSecondsD(5.5));
  EXPECT_FALSE(time_container->IsPaused());
  EXPECT_EQ(SMILTime::FromSecondsD(5.5), time_container->Elapsed());
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(6.5), time_container->Elapsed());
  EXPECT_EQ(30, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1000));
  EXPECT_EQ(SMILTime::FromSecondsD(7.5), time_container->Elapsed());
  EXPECT_EQ(50, rect->height()->CurrentValue()->Value(length_context));

  StepTime(base::Milliseconds(1500));
  EXPECT_EQ(100, rect->height()->CurrentValue()->Value(length_context));
  EXPECT_EQ(SMILTime::FromSecondsD(8.5), time_container->Elapsed());
}

}  // namespace
}  // namespace blink

"""

```