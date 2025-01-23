Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for an explanation of the given C++ test file's functionality within the Chromium Blink engine, specifically focusing on its relationship with web technologies (JavaScript, HTML, CSS), logical inferences, and common usage errors.

2. **High-Level Overview:** I first skim the file to get a general idea of its purpose. The presence of `TEST_F` macros immediately tells me this is a test file. The class name `CSSScrollTimelineTest` and the included headers (like `css/properties/longhands.h`, `dom/element.h`, `html/html_element.h`) strongly suggest it's testing the implementation of CSS Scroll Timelines.

3. **Identify Key Components:**  I then go through the file more carefully, identifying the key components and their roles:
    * **`CSSScrollTimelineTest` Class:** This is the main test fixture, inheriting from `PageTestBase` (implying integration testing with a simplified rendering environment). The `ScopedScrollTimelineForTest` suggests enabling/disabling the feature being tested. The helper function `GetDocumentAnimations()` is also important.
    * **`TEST_F` Macros:** These define individual test cases, each focusing on a specific aspect of scroll timelines.
    * **HTML Snippets:**  The `R"HTML(...)HTML"` strings contain HTML and CSS code used to set up test scenarios.
    * **Assertions (`ASSERT_TRUE`, `EXPECT_EQ`, `EXPECT_NE`):** These are used to verify the expected behavior of the code under test.
    * **Blink-Specific Classes:**  Classes like `Element`, `Animation`, `ScrollTimeline`, `ComputedStyle`, etc., are central to the Blink rendering engine and provide clues about the tested functionalities.

4. **Analyze Individual Tests:**  I go through each `TEST_F` block and try to understand what it's testing. For each test, I ask:
    * What HTML/CSS is being set up?
    * What is the core functionality being exercised? (e.g., shared timelines, behavior across lifecycle passes, interaction with ResizeObserver, scoping rules)
    * What are the assertions checking? What's the expected outcome?

5. **Relate to Web Technologies:** As I analyze each test, I actively think about how the tested functionality relates to HTML, CSS, and (indirectly) JavaScript:
    * **HTML:** The structure of the page, the elements involved (divs, main, shadow roots), and attributes like `id` and `class`.
    * **CSS:** The styling rules, especially the `scroll-timeline`, `view-timeline`, `animation-timeline`, `animation-name`, `keyframes`, etc. I connect these CSS properties to their effects on animations and timeline behavior.
    * **JavaScript (Indirectly):** While this test is C++, it's testing features that are controlled and manipulated by JavaScript in a real browser environment. I consider how a developer would use these CSS features and how JavaScript might interact with the resulting animations. For example, `getAnimations()` is a JavaScript API.

6. **Identify Logical Inferences and Assumptions:** I look for places where the tests make implicit assumptions about how the browser engine should behave. The comments within the code are helpful here, especially explanations of spec rules and potential issues. I consider the inputs (HTML/CSS) and the expected outputs (animation behavior, timeline sharing, etc.).

7. **Consider Common Usage Errors:**  Based on my understanding of the tests, I think about the mistakes a web developer might make when using CSS Scroll Timelines. This involves:
    * Incorrectly naming timelines.
    * Issues with timeline scoping within shadow DOM.
    * Not understanding the timing of timeline creation and layout.
    * Confusing `scroll-timeline` and `view-timeline`.
    * Problems with attaching animations to the correct timelines.

8. **Structure the Answer:** I organize the information logically, starting with a general overview and then going into more specific details for each aspect of the request:
    * **Functionality:** A concise summary of what the test file does.
    * **Relationship with Web Technologies:**  Specific examples from the tests illustrating the connection to HTML, CSS, and JavaScript.
    * **Logical Inferences:**  Explicitly state the assumptions and expected outcomes of certain tests, along with input/output examples.
    * **Common Usage Errors:**  Provide concrete examples of mistakes developers might make based on the tested scenarios.

9. **Refine and Elaborate:** I review my answer, making sure it's clear, accurate, and provides sufficient detail. I elaborate on the examples and explanations to make them easier to understand. I ensure I've addressed all parts of the original request. For instance, I explicitly mention the purpose of each test function.

By following these steps, I can effectively analyze the C++ test file and provide a comprehensive explanation of its functionality and its relevance to web development. The key is to connect the low-level C++ testing code back to the higher-level concepts and technologies that web developers work with.
这个C++源代码文件 `css_scroll_timeline_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 **CSS Scroll Timelines** 功能的实现。

**它的主要功能是：**

1. **验证 CSS Scroll Timeline 的核心机制:**  测试在不同场景下，CSS Scroll Timeline 是否能够正确地创建、关联和驱动动画。这包括：
    * **命名的时间线 (Named Timelines):**  测试通过 `scroll-timeline-name` 定义和 `animation-timeline` 引用的时间线能否正确工作。
    * **共享的时间线 (Shared Timelines):**  测试多个元素或动画是否可以共享同一个 scroll timeline 实例。
    * **祖先滚动容器 (Ancestor Scrollers):**  测试当动画元素不在直接滚动容器内时，是否能正确关联到祖先元素的滚动时间线。
    * **多次生命周期阶段 (Multiple Lifecycle Passes):** 测试在样式计算和布局过程中，即使滚动容器最初不可用，后续更新能否正确关联时间线。
    * **`ResizeObserver` 触发的时间线:** 测试通过 `ResizeObserver` 动态添加 `scroll-timeline` 属性后，时间线是否能正确激活。
    * **View Timelines (`view-timeline`):** 测试基于元素在滚动容器中的可见性的时间线功能。
    * **Shadow DOM 中的时间线作用域:** 测试 `view-timeline` 和 `scroll-timeline` 在 Shadow DOM 中的作用域规则，包括 `:host`, `::slotted`, 和 `::part` 的影响。

2. **确保代码的健壮性和正确性:**  通过编写各种测试用例，覆盖 CSS Scroll Timeline 的不同使用场景和边缘情况，确保 Blink 引擎在实现该功能时没有错误或漏洞。

**它与 Javascript, HTML, CSS 的关系：**

这个测试文件直接测试的是 **CSS** 的功能。 CSS Scroll Timelines 允许开发者使用 CSS 来定义与滚动容器的滚动位置关联的动画。

* **CSS:**  测试的核心在于解析和应用 CSS 属性，例如：
    * `scroll-timeline`: 用于为一个滚动容器定义一个命名的滚动时间线。
    * `scroll-timeline-name`: 用于为一个滚动容器指定多个命名滚动时间线。
    * `scroll-timeline-attachment`: 控制滚动时间线的附加行为。
    * `animation-timeline`:  用于将一个动画与一个滚动时间线关联起来。
    * `view-timeline`:  用于定义基于元素可见性的时间线。
* **HTML:**  测试用例中使用了 HTML 结构来创建滚动容器和需要动画的元素。例如，创建带有 `overflow: scroll` 属性的 `div` 元素作为滚动容器。
* **Javascript (间接关系):**  虽然这个测试文件是 C++ 代码，但它测试的 CSS 功能最终会被 JavaScript API (如 `getAnimations()`) 暴露出来，允许 JavaScript 开发者查询和操作这些基于滚动位置的动画。

**举例说明：**

**假设输入 (HTML & CSS):**

```html
<style>
  #scroller {
    height: 100px;
    overflow: scroll;
    scroll-timeline: --my-timeline;
  }
  #scroller > div {
    height: 200px;
  }
  #element {
    animation-name: slide;
    animation-duration: 1s; /* 持续时间不重要，因为由滚动驱动 */
    animation-timeline: --my-timeline;
  }
  @keyframes slide {
    from { transform: translateX(0); }
    to { transform: translateX(100px); }
  }
</style>
<div id="scroller">
  <div></div>
</div>
<div id="element"></div>
```

**逻辑推理 (测试 `SharedTimelines`):**

在 `SharedTimelines` 测试中，代码创建了两个滚动容器 (`#scroller1`, `#scroller2`) 和两个需要动画的元素 (`#element1`, `#element2`)。 它们共享了命名的时间线 `--timeline1` 和 `--timeline2`。

* **假设输入 (CSS):**
    ```css
    body {
      scroll-timeline-attachment: defer;
      scroll-timeline-name: --timeline1, --timeline2;
    }
    @keyframes anim1 { to { top: 200px; } }
    @keyframes anim2 { to { left: 200px; } }
    @keyframes anim3 { to { right: 200px; } }
    .scroller {
      height: 100px;
      overflow: scroll;
      scroll-timeline-attachment: ancestor;
    }
    .scroller > div {
      height: 200px;
    }
    #scroller1 {
      scroll-timeline: --timeline1;
    }
    #scroller2 {
      scroll-timeline: --timeline2;
    }
    #element1, #element2 {
      animation-name: anim1, anim2, anim3;
      animation-duration: 10s;
      animation-timeline: --timeline1, --timeline1, --timeline2;
    }
    ```

* **输出 (通过 `EXPECT_EQ` 断言验证):**
    * `animations1[0]` (关联到 `anim1` 和 `--timeline1`) 和 `animations1[1]` (关联到 `anim2` 和 `--timeline1`) 应该共享同一个 timeline 实例。
    * `animations1[1]` 和 `animations2[0]` (关联到 `anim1` 和 `--timeline1`) 也应该共享同一个 timeline 实例。
    * `animations1[2]` (关联到 `anim3` 和 `--timeline2`) 和 `animations2[2]` (关联到 `anim3` 和 `--timeline2`) 应该共享另一个 timeline 实例，但这个实例与 `--timeline1` 的实例不同。

**常见的使用错误举例说明：**

* **未正确命名时间线导致动画不生效:**
    ```html
    <style>
      #scroller {
        scroll-timeline: my-timeline; /* 缺少了 -- 前缀 */
        overflow: scroll;
        height: 100px;
      }
      #scroller > div {
        height: 200px;
      }
      #element {
        animation-name: slide;
        animation-timeline: my-timeline; /* 需要与 scroller 中定义的匹配 */
      }
      @keyframes slide {
        from { transform: translateX(0); }
        to { transform: translateX(100px); }
      }
    </style>
    <div id="scroller"><div></div></div>
    <div id="element"></div>
    ```
    **错误:** 在 `scroll-timeline` 中定义的时间线名称缺少了 `--` 前缀，导致 `#element` 无法找到对应的时间线，动画不会随滚动生效。正确的写法是 `scroll-timeline: --my-timeline;`。

* **在 Shadow DOM 中作用域混淆导致时间线未找到:**  例如 `ViewTimelineHost` 和 `ScrollTimelineHost` 测试用例旨在验证在 Shadow DOM 中，时间线的定义是否按照 CSS 作用域规则生效。如果开发者在 Shadow DOM 中定义了时间线，但尝试在外部的元素上使用，可能会导致时间线未找到。

* **过早应用动画，滚动容器尚未布局:** `MultipleLifecyclePasses` 测试用例模拟了这种情况。如果动画元素在滚动容器完成布局之前就尝试关联滚动时间线，最初可能无法关联。Blink 引擎会进行额外的处理来尝试解决这个问题，但开发者应该注意确保滚动容器在动画应用时是可用的。

总而言之，`css_scroll_timeline_test.cc` 是一个至关重要的测试文件，它通过 C++ 代码详细地验证了 CSS Scroll Timeline 功能在 Blink 引擎中的实现是否符合规范，并且能够帮助发现和修复潜在的错误，从而确保开发者能够可靠地使用这一强大的 CSS 功能。

### 提示词
```
这是目录为blink/renderer/core/animation/css/css_scroll_timeline_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/id_target_observer_registry.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class CSSScrollTimelineTest : public PageTestBase,
                              private ScopedScrollTimelineForTest {
 public:
  CSSScrollTimelineTest() : ScopedScrollTimelineForTest(true) {}

  DocumentAnimations& GetDocumentAnimations() const {
    return GetDocument().GetDocumentAnimations();
  }

  const HeapHashSet<WeakMember<ScrollSnapshotClient>>&
  GetScrollSnapshotClientsForTesting() {
    return GetFrame().GetScrollSnapshotClientsForTesting();
  }
};

TEST_F(CSSScrollTimelineTest, SharedTimelines) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        scroll-timeline-attachment: defer;
        scroll-timeline-name: --timeline1, --timeline2;
      }
      @keyframes anim1 { to { top: 200px; } }
      @keyframes anim2 { to { left: 200px; } }
      @keyframes anim3 { to { right: 200px; } }
      .scroller {
        height: 100px;
        overflow: scroll;
        scroll-timeline-attachment: ancestor;
      }
      .scroller > div {
        height: 200px;
      }
      #scroller1 {
        scroll-timeline: --timeline1;
      }
      #scroller2 {
        scroll-timeline: --timeline2;
      }
    </style>
    <div id=scroller1 class=scroller><div></div></div>
    <div id=scroller2 class=scroller><div></div></div>
    <main id=main></main>
  )HTML");
  // #scroller[1,2] etc is created in a separate lifecycle phase to ensure that
  // we get a layout box for #scroller[1,2] before the animations are started.

  Element* main = GetDocument().getElementById(AtomicString("main"));
  ASSERT_TRUE(main);
  main->setInnerHTML(R"HTML(
    <style>
      #element1, #element2 {
        animation-name: anim1, anim2, anim3;
        animation-duration: 10s;
        animation-timeline: --timeline1, --timeline1, --timeline2;
      }
    </style>
    <div id=element1></div>
    <div id=element2></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* element1 = GetDocument().getElementById(AtomicString("element1"));
  Element* element2 = GetDocument().getElementById(AtomicString("element2"));
  ASSERT_TRUE(element1);
  ASSERT_TRUE(element2);
  HeapVector<Member<Animation>> animations1 = element1->getAnimations();
  HeapVector<Member<Animation>> animations2 = element2->getAnimations();
  EXPECT_EQ(3u, animations1.size());
  EXPECT_EQ(3u, animations2.size());

  // The animations associated with anim1 and anim2 should share the same
  // timeline instance, also across elements.
  EXPECT_EQ(animations1[0]->TimelineInternal(),
            animations1[1]->TimelineInternal());
  EXPECT_EQ(animations1[1]->TimelineInternal(),
            animations2[0]->TimelineInternal());
  EXPECT_EQ(animations2[0]->TimelineInternal(),
            animations2[1]->TimelineInternal());

  // The animation associated with anim3 uses a different timeline
  // from anim1/2.
  EXPECT_EQ(animations1[2]->TimelineInternal(),
            animations2[2]->TimelineInternal());

  EXPECT_NE(animations2[2]->TimelineInternal(),
            animations1[0]->TimelineInternal());
  EXPECT_NE(animations2[2]->TimelineInternal(),
            animations1[1]->TimelineInternal());
}

TEST_F(CSSScrollTimelineTest, MultipleLifecyclePasses) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { color: green; }
        to { color: green; }
      }
      #scroller {
        height: 100px;
        overflow: scroll;
        scroll-timeline: --timeline;
      }
      #scroller > div {
        height: 200px;
      }
      #element {
        color: red;
        animation: anim 10s;
        animation-timeline: --timeline;
      }
    </style>
    <div id=scroller>
      <div id=contents></div>
    </div>
    <div id=element></div>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("element"));
  ASSERT_TRUE(element);

  // According to the rules of the spec [1], the timeline is now inactive,
  // because #scroller did not have a layout box at the time style recalc
  // for #element happened.
  //
  // However, we do an additional style/layout pass if we detect new
  // CSSScrollTimelines in this situation, hence we ultimately do expect
  // the animation to apply [2].
  //
  // See also DocumentAnimations::ValidateTimelines.
  //
  // [1] https://drafts.csswg.org/scroll-animations-1/#avoiding-cycles
  // [2] https://github.com/w3c/csswg-drafts/issues/5261
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            element->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

namespace {

class AnimationTriggeringDelegate : public ResizeObserver::Delegate {
 public:
  explicit AnimationTriggeringDelegate(Element* scroller_element)
      : scroller_element_(scroller_element) {}

  void OnResize(
      const HeapVector<Member<ResizeObserverEntry>>& entries) override {
    scroller_element_->SetInlineStyleProperty(CSSPropertyID::kScrollTimeline,
                                              "--timeline");
  }

  void Trace(Visitor* visitor) const override {
    ResizeObserver::Delegate::Trace(visitor);
    visitor->Trace(scroller_element_);
  }

 private:
  Member<Element> scroller_element_;
};

}  // namespace

TEST_F(CSSScrollTimelineTest, ResizeObserverTriggeredTimelines) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes anim {
        from { width: 100px; }
        to { width: 100px; }
      }
      #scroller {
        height: 100px;
        overflow: scroll;
      }
      #scroller > div {
        height: 200px;
      }
      #element {
        width: 1px;
        animation: anim 10s --timeline;
      }
    </style>
    <div id=main></div>
  )HTML");

  ASSERT_TRUE(GetScrollSnapshotClientsForTesting().empty());

  Element* element = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  element->setAttribute(blink::html_names::kIdAttr, AtomicString("element"));

  Element* scroller = MakeGarbageCollected<HTMLDivElement>(GetDocument());
  scroller->setAttribute(blink::html_names::kIdAttr, AtomicString("scroller"));
  scroller->AppendChild(MakeGarbageCollected<HTMLDivElement>(GetDocument()));

  Element* main = GetDocument().getElementById(AtomicString("main"));
  ASSERT_TRUE(main);
  main->AppendChild(scroller);
  main->AppendChild(element);

  auto* delegate = MakeGarbageCollected<AnimationTriggeringDelegate>(scroller);
  ResizeObserver* observer =
      ResizeObserver::Create(GetDocument().domWindow(), delegate);
  observer->observe(element);

  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1u, GetScrollSnapshotClientsForTesting().size());
}

namespace {

std::optional<ScrollTimeline::ScrollAxis> GetTimelineAxis(
    const Animation& animation) {
  if (auto* scroll_timeline =
          DynamicTo<ScrollTimeline>(animation.TimelineInternal())) {
    return scroll_timeline->GetAxis();
  }
  return std::nullopt;
}

}  // namespace

TEST_F(CSSScrollTimelineTest, ViewTimelineHost) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      @keyframes anim {
        from { z-index: 100; }
        to { z-index: 100; }
      }
      .target {
        animation: anim 10s linear;
        animation-timeline: --timeline;
      }
      .scroller > div {
        view-timeline: --timeline x;
      }
    </style>
    <div class=scroller>
      <div>
        <div class=target>
          <template shadowrootmode=open>
            <style>
              :host {
                view-timeline: --timeline y;
              }
            </style>
          </template>
        </div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Outer animation can not see view timeline defined by :host";
}

TEST_F(CSSScrollTimelineTest, ViewTimelineSlotted) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      @keyframes anim {
        from { z-index: 100; }
        to { z-index: 100; }
      }
      .target {
        animation: anim 10s linear;
        animation-timeline: --timeline;
      }
      .host {
        view-timeline: --timeline x;
      }
    </style>
    <div class=scroller>
      <div class=host>
        <template shadowrootmode=open>
          <style>
            ::slotted(.target) {
              view-timeline: --timeline y;
            }
          </style>
          <slot></slot>
        </template>
        <div class=target></div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Outer animation can not see view timeline defined by ::slotted";
}

TEST_F(CSSScrollTimelineTest, ViewTimelinePart) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      .host {
        view-timeline: --timeline y;
      }
      .host::part(foo) {
        view-timeline: --timeline x;
      }
    </style>
    <div class=host>
      <template shadowrootmode=open>
        <style>
            /* Not placing 'anim2' at document scope, due to
               https://crbug.com/1334534 */
            @keyframes anim2 {
              from { z-index: 100; }
              to { z-index: 100; }
            }
          .target {
            animation: anim2 10s linear;
            animation-timeline: --timeline;
          }
        </style>
        <div part=foo>
          <div class=target></div>
        </div>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* host = GetDocument().QuerySelector(AtomicString(".host"));
  ASSERT_TRUE(host);
  ASSERT_TRUE(host->GetShadowRoot());
  Element* target =
      host->GetShadowRoot()->QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Inner animation can see view timeline defined by ::part";
}

TEST_F(CSSScrollTimelineTest, ScrollTimelineHost) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      @keyframes anim {
        from { z-index: 100; }
        to { z-index: 100; }
      }
      .target {
        animation: anim 10s linear;
        animation-timeline: --timeline;
      }
      main > .scroller {
        scroll-timeline: --timeline x;
      }
    </style>
    <main>
      <div class=scroller>
        <div class=scroller>
          <template shadowrootmode=open>
            <style>
              :host {
                scroll-timeline: --timeline y;
              }
            </style>
            <slot></slot>
          </template>
          <div class=target></div>
        </div>
      </div>
    </main>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Outer animation can not see scroll timeline defined by :host";
}

TEST_F(CSSScrollTimelineTest, ScrollTimelineSlotted) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      @keyframes anim {
        from { z-index: 100; }
        to { z-index: 100; }
      }
      .target {
        animation: anim 10s linear;
        animation-timeline: --timeline;
      }
      .host {
        scroll-timeline: --timeline x;
      }
    </style>
    <div class=host>
      <template shadowrootmode=open>
        <style>
          ::slotted(.scroller) {
            scroll-timeline: --timeline y;
          }
        </style>
        <slot></slot>
      </template>
      <div class=scroller>
        <div class=target></div>
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* target = GetDocument().QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Outer animation can not see scroll timeline defined by ::slotted";
}

TEST_F(CSSScrollTimelineTest, ScrollTimelinePart) {
  ScopedCSSTreeScopedTimelinesForTest scoped_feature(true);
  GetDocument().documentElement()->setHTMLUnsafe(R"HTML(
    <style>
      .host {
        scroll-timeline: --timeline y;
      }
      .host::part(foo) {
        scroll-timeline: --timeline x;
      }
    </style>
    <div class=host>
      <template shadowrootmode=open>
        <style>
            /* Not placing 'anim2' at document scope, due to
               https://crbug.com/1334534 */
            @keyframes anim2 {
              from { z-index: 100; background-color: green; }
              to { z-index: 100; background-color: green; }
            }
          .target {
            animation: anim2 10s linear;
            animation-timeline: --timeline;
          }
        </style>
        <div part=foo>
          <div class=target></div>
        </div>
      </template>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* host = GetDocument().QuerySelector(AtomicString(".host"));
  ASSERT_TRUE(host);
  ASSERT_TRUE(host->GetShadowRoot());
  Element* target =
      host->GetShadowRoot()->QuerySelector(AtomicString(".target"));
  ASSERT_TRUE(target);
  HeapVector<Member<Animation>> animations = target->getAnimations();
  ASSERT_EQ(1u, animations.size());
  ASSERT_EQ(ScrollTimeline::ScrollAxis::kX, GetTimelineAxis(*animations[0]))
      << "Inner animation can see scroll timeline defined by ::part";
}

}  // namespace blink
```