Response:
The user wants a summary of the provided C++ code.
This is the last part of a four-part series, so I need to provide a final summary based on this specific part of the code.

The code is a test file for the `CompositorAnimations` functionality in the Chromium Blink engine. It checks if animations can be run on the compositor thread, which is crucial for smooth performance, especially for animations related to CSS properties like `transform` and `opacity`.

Here's a breakdown of what this specific part of the code does:

1. **Tests for starting animations based on Paint Properties:** It verifies if an animation can start on the compositor based on whether the element has a `PaintProperties` object and if that object has a compositing reason set.
2. **Tests for `requestAnimationFrame` (rAF) tracking:** It checks if the engine correctly tracks rAF callbacks, including cases where the rAF is scheduled with `setTimeout`.
3. **Tests for SVG Animation tracking:** It verifies the tracking of SMIL animations in SVG elements.
4. **Tests for composited custom properties:** It ensures that animations of custom CSS properties can be composited.
5. **Tests for composited `transform` and `scale` animations:** It verifies that `transform` and `scale` animations are correctly started on the compositor and that the related state (e.g., `maximum_animation_scale`) is initialized.
6. **Tests for updating non-animated `transform` properties during an animation:** It checks if changes to properties like `backface-visibility` are correctly propagated to the compositor even when a transform animation is running.
7. **Regression tests for SVG animations:** Addresses specific bugs related to starting compositor animations on SVG elements.
8. **Tests for document without settings:** Ensures that the code handles cases where a document is not attached to a frame (and thus has no settings) without crashing.
9. **Tests for detaching compositor timelines:** Verifies that compositor timelines can be detached.
10. **Tests for starting transform animations on various SVG elements:** It checks which types of SVG elements and their properties allow transform animations to run on the compositor.
11. **Tests for unsupported SVG CSS properties:** It verifies the behavior when animating CSS properties not supported for compositor animation on SVG elements.
12. **Tests for tracking animation counts across documents:** It checks the total number of active animations across all documents.
13. **Tests for excluding inactive animations from the count:** Verifies that paused animations are not counted as active.
14. **Tests for tracking rAF across documents:** Checks if rAF callbacks are tracked correctly across multiple frames.
15. **Tests for fragmented elements:** It verifies that animations on elements split across columns (fragmented) are not run on the compositor.
16. **Tests for canceling incompatible transform compositor animations:** It checks if an existing compositor animation is correctly canceled when a new, incompatible transform animation is started.
17. **Tests for long active duration with negative playback rate:** It tests a specific edge case with animation duration and playback rate that could lead to issues.
18. **Tests for background shorthand property animation:** It verifies that animating the `background` shorthand property works with compositor animations.
19. **Tests for static properties in animations:** It checks the behavior and use counting when animations include properties that don't change their value.
20. **Tests for empty keyframes:** It verifies the behavior of animations with empty keyframe lists.
21. **Tests for vendor-prefixed and unprefixed properties:** It ensures that animations using both vendor-prefixed and unprefixed versions of the same property work correctly.
这个C++代码文件 `compositor_animations_test.cc` 是 Chromium Blink 引擎中负责测试合成器动画 (Compositor Animations) 功能的一部分。作为第4部分，它延续了前几部分的功能测试，更深入地检验了动画在合成器线程上运行的各种场景和边界情况。

**归纳一下它的功能：**

这个文件主要用于测试 Blink 引擎是否能够正确地将 CSS 动画 (特别是 `transform` 和 `opacity` 属性相关的动画) 以及 `requestAnimationFrame` (rAF) 回调等转移到合成器线程上执行。这样做的好处是可以提高动画性能，避免在主线程繁忙时出现卡顿。

**与 JavaScript, HTML, CSS 的功能关系以及举例说明：**

该测试文件直接关联到前端开发中常用的 JavaScript API (`requestAnimationFrame`) 和 CSS 动画属性。

*   **CSS 动画 (CSS Animations):**  测试验证了当 HTML 元素应用了 CSS 动画时，Blink 引擎能否将其正确地交给合成器处理。例如：
    ```html
    <style>
      #target {
        animation: move 1s infinite;
      }
      @keyframes move {
        from { transform: translateX(0); }
        to { transform: translateX(100px); }
      }
    </style>
    <div id="target"></div>
    ```
    测试代码会创建这样的 HTML 结构，并断言 `CheckCanStartElementOnCompositor` 函数返回成功，表明该动画可以运行在合成器上。特别地，它测试了 `transform` 属性的不同变种 (例如 `scale`, `rotate`) 以及在动画进行时动态修改其他非动画属性 (例如 `backface-visibility`) 的情况。

*   **CSS 自定义属性 (CSS Custom Properties):**  测试了对 CSS 自定义属性进行动画时是否能运行在合成器上。例如：
    ```html
    <style>
      #target {
        animation: color-change 1s;
        --my-color: red;
        background-color: var(--my-color);
      }
      @keyframes color-change {
        to { --my-color: blue; }
      }
    </style>
    <div id="target"></div>
    ```
    测试会验证对 `--my-color` 这个自定义属性的动画是否可以被合成器处理。

*   **`requestAnimationFrame` (rAF):** 测试了 Blink 引擎对 `requestAnimationFrame` 的追踪和处理。例如，一个网页可能包含以下 JavaScript 代码：
    ```javascript
    function animate() {
      // 执行动画相关的操作
      requestAnimationFrame(animate);
    }
    animate();
    ```
    测试代码 (`TrackRafAnimation` 等测试用例) 会加载包含此类 rAF 调用的 HTML 文件，并验证合成器是否能正确地检测到当前帧和下一帧是否有待处理的 rAF 回调。这对于优化基于 JavaScript 的动画非常重要。

*   **SVG 动画 (SMIL 和 CSS Animations on SVG):** 测试了 SVG 元素的动画，包括 SMIL 动画和 CSS 动画。例如：
    ```html
    <svg>
      <rect id="rect" width="100" height="100">
        <animate attributeName="x" from="0" to="100" dur="1s" repeatCount="indefinite"/>
      </rect>
    </svg>
    ```
    测试代码 (`TrackSVGAnimation` 和相关的 `CannotStartElementOnCompositorEffectSVG` 等测试) 验证了对 SVG 元素的 `transform` 属性进行 CSS 动画，以及 SMIL 动画的处理情况，并特别关注了某些 SVG 特性 (例如 `use` 元素，带有 `vector-effect` 属性的元素) 对合成器动画的影响。

**逻辑推理的假设输入与输出：**

许多测试用例都基于以下逻辑推理：

*   **假设输入：** 一个 HTML 元素，应用了特定的 CSS 动画 (例如 `transform: rotate(45deg)`) 或者通过 JavaScript 调用了 `requestAnimationFrame`。
*   **预期输出：**  `CheckCanStartElementOnCompositor` 函数返回 `CompositorAnimations::kNoFailure`，表明该动画可以运行在合成器上。对于 rAF，则预期 `cc::AnimationHost` 的 `CurrentFrameHadRAF()` 和 `NextFrameHasPendingRAF()` 方法返回正确的值，反映 rAF 的执行状态。

例如，在 `CanStartElementOnCompositorTransformBased` 测试中：

*   **假设输入：** 一个带有 `transform` 动画的 HTML 元素。
*   **预期输出：** `CheckCanStartElementOnCompositor` 返回 `CompositorAnimations::kNoFailure`。

在 `TrackRafAnimation` 测试中：

*   **假设输入：** 一个包含使用 `requestAnimationFrame` 的 JavaScript 代码的 HTML 页面。
*   **预期输出：** 在动画执行的帧中，`host->CurrentFrameHadRAF()` 返回 `true`，`host->NextFrameHasPendingRAF()` 返回 `true` (直到动画结束)。

**涉及用户或者编程常见的使用错误，并举例说明：**

该测试文件也涵盖了一些用户或开发者可能犯的错误，并验证了 Blink 引擎的应对机制：

*   **在不支持合成器动画的元素上使用动画：** 例如，对一个内部包含 SMIL 动画的 SVG 元素直接进行 CSS `transform` 动画，可能无法在合成器上运行。测试用例 `CannotStartElementOnCompositorEffectSVG` 验证了这种情况，预期 `CheckCanStartElementOnCompositor` 返回表示失败的状态。
*   **同时应用不兼容的合成器动画：** 例如，如果一个元素已经有一个运行在合成器上的 `transform` 动画，然后又添加了一个新的 `transform` 动画，可能会导致之前的动画被取消。`CancelIncompatibleTransformCompositorAnimation` 测试验证了这种取消行为。
*   **使用了不支持在合成器上运行的 CSS 属性：** 某些 CSS 属性的动画无法直接在合成器上执行。`UnsupportedSVGCSSProperty` 测试验证了当 SVG 元素的 CSS 动画包含 `stroke-dashoffset` 这样的属性时，引擎会正确判断其不能在合成器上运行。
*   **在 `requestAnimationFrame` 中使用了 `setTimeout(..., 0)`：**  开发者可能会误以为 `setTimeout(func, 0)` 会立即执行，从而影响 rAF 的调度。`TrackRafAnimationTimeout` 测试验证了即使使用 `setTimeout(func, 0)` 调度的 rAF，也不会被认为是“pending”的下一个 rAF。

总而言之，`compositor_animations_test.cc` (作为最后一部分) 是一个细致而全面的测试套件，用于确保 Chromium Blink 引擎能够有效地将各种类型的动画转移到合成器线程，从而提供流畅的用户体验，并能正确处理各种边界情况和潜在的错误用法。

Prompt: 
```
这是目录为blink/renderer/core/animation/compositor_animations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
 the transform node entirely should also produce false.
  properties.ClearTransform();
  EXPECT_TRUE(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_) &
      CompositorAnimations::kTargetHasInvalidCompositingState);

  element->SetLayoutObject(nullptr);
  LayoutObjectProxy::Dispose(layout_object);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartElementOnCompositorEffectBasedOnPaintProperties) {
  Persistent<Element> element =
      GetDocument().CreateElementForBinding(AtomicString("shared"));
  LayoutObjectProxy* layout_object = LayoutObjectProxy::Create(element.Get());
  layout_object->EnsureIdForTestingProxy();
  element->SetLayoutObject(layout_object);

  auto& properties = layout_object->GetMutableForPainting()
                         .FirstFragment()
                         .EnsurePaintProperties();

  // Add an effect with a compositing reason, which should allow starting
  // animation.
  UpdateDummyEffectNode(properties,
                        CompositingReason::kActiveTransformAnimation);
  EXPECT_EQ(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);

  // Setting to CompositingReasonNone should produce false.
  UpdateDummyEffectNode(properties, CompositingReason::kNone);
  EXPECT_TRUE(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_) &
      CompositorAnimations::kTargetHasInvalidCompositingState);

  // Clearing the effect node entirely should also produce false.
  properties.ClearEffect();
  EXPECT_TRUE(
      CheckCanStartElementOnCompositor(*element, *keyframe_animation_effect2_) &
      CompositorAnimations::kTargetHasInvalidCompositingState);

  element->SetLayoutObject(nullptr);
  LayoutObjectProxy::Dispose(layout_object);
}

TEST_P(AnimationCompositorAnimationsTest, TrackRafAnimation) {
  LoadTestData("raf-countdown.html");

  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();

  // The test file registers two rAF 'animations'; one which ends after 5
  // iterations and the other that ends after 10.
  for (int i = 0; i < 9; i++) {
    BeginFrame();
    EXPECT_TRUE(host->CurrentFrameHadRAF());
    EXPECT_TRUE(host->NextFrameHasPendingRAF());
  }

  // On the 10th iteration, there should be a current rAF, but no more pending
  // rAFs.
  BeginFrame();
  EXPECT_TRUE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());

  // On the 11th iteration, there should be no more rAFs firing.
  BeginFrame();
  EXPECT_FALSE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());
}

TEST_P(AnimationCompositorAnimationsTest, TrackRafAnimationTimeout) {
  LoadTestData("raf-timeout.html");

  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();

  // The test file executes a rAF, which fires a setTimeout for the next rAF.
  // Even with setTimeout(func, 0), the next rAF is not considered pending.
  BeginFrame();
  EXPECT_TRUE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());
}

TEST_P(AnimationCompositorAnimationsTest, TrackSVGAnimation) {
  LoadTestData("svg-smil-animation.html");

  cc::AnimationHost* host = GetFrame()->View()->GetCompositorAnimationHost();

  BeginFrame();
  EXPECT_TRUE(host->HasSmilAnimation());
}

TEST_P(AnimationCompositorAnimationsTest, TrackRafAnimationNoneRegistered) {
  SetBodyInnerHTML("<div id='box'></div>");

  // Run a full frame after loading the test data so that scripted animations
  // are serviced and data propagated.
  BeginFrame();

  // The HTML does not have any rAFs.
  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();
  EXPECT_FALSE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());

  // And still shouldn't after another frame.
  BeginFrame();
  EXPECT_FALSE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());
}

TEST_P(AnimationCompositorAnimationsTest, CompositedCustomProperty) {
  RegisterProperty(GetDocument(), "--foo", "<number>", "0", false);
  SetCustomProperty("--foo", "0");
  StringKeyframeEffectModel* effect =
      CreateKeyframeEffectModel(CreateReplaceOpKeyframe("--foo", "20", 0),
                                CreateReplaceOpKeyframe("--foo", "100", 1.0));
  LoadTestData("custom-property.html");
  Document* document = GetFrame()->GetDocument();
  Element* target = document->getElementById(AtomicString("target"));
  // Make sure the animation is started on the compositor.
  EXPECT_EQ(CheckCanStartElementOnCompositor(*target, *effect),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest, CompositedTransformAnimation) {
  LoadTestData("transform-animation.html");
  Document* document = GetFrame()->GetDocument();
  Element* target = document->getElementById(AtomicString("target"));
  const ObjectPaintProperties* properties =
      target->GetLayoutObject()->FirstFragment().PaintProperties();
  ASSERT_NE(nullptr, properties);
  const auto* transform = properties->Transform();
  ASSERT_NE(nullptr, transform);
  EXPECT_TRUE(transform->HasDirectCompositingReasons());
  EXPECT_TRUE(transform->HasActiveTransformAnimation());

  // Make sure the animation state is initialized in paint properties.
  auto* property_trees =
      document->View()->RootCcLayer()->layer_tree_host()->property_trees();
  const auto* cc_transform =
      property_trees->transform_tree().FindNodeFromElementId(
          transform->GetCompositorElementId());
  ASSERT_NE(nullptr, cc_transform);
  EXPECT_TRUE(cc_transform->has_potential_animation);
  EXPECT_TRUE(cc_transform->is_currently_animating);
  EXPECT_EQ(1.f, cc_transform->maximum_animation_scale);

  // Make sure the animation is started on the compositor.
  EXPECT_EQ(
      CheckCanStartElementOnCompositor(*target, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);
  EXPECT_EQ(document->Timeline().AnimationsNeedingUpdateCount(), 1u);
}

TEST_P(AnimationCompositorAnimationsTest, CompositedScaleAnimation) {
  LoadTestData("scale-animation.html");
  Document* document = GetFrame()->GetDocument();
  Element* target = document->getElementById(AtomicString("target"));
  const ObjectPaintProperties* properties =
      target->GetLayoutObject()->FirstFragment().PaintProperties();
  ASSERT_NE(nullptr, properties);
  const auto* transform = properties->Transform();
  ASSERT_NE(nullptr, transform);
  EXPECT_TRUE(transform->HasDirectCompositingReasons());
  EXPECT_TRUE(transform->HasActiveTransformAnimation());

  // Make sure the animation state is initialized in paint properties.
  auto* property_trees =
      document->View()->RootCcLayer()->layer_tree_host()->property_trees();
  const auto* cc_transform =
      property_trees->transform_tree().FindNodeFromElementId(
          transform->GetCompositorElementId());
  ASSERT_NE(nullptr, cc_transform);
  EXPECT_TRUE(cc_transform->has_potential_animation);
  EXPECT_TRUE(cc_transform->is_currently_animating);
  EXPECT_EQ(5.f, cc_transform->maximum_animation_scale);

  // Make sure the animation is started on the compositor.
  EXPECT_EQ(
      CheckCanStartElementOnCompositor(*target, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);
  EXPECT_EQ(document->Timeline().AnimationsNeedingUpdateCount(), 1u);
}

TEST_P(AnimationCompositorAnimationsTest,
       NonAnimatedTransformPropertyChangeGetsUpdated) {
  LoadTestData("transform-animation-update.html");
  Document* document = GetFrame()->GetDocument();
  Element* target = document->getElementById(AtomicString("target"));
  const ObjectPaintProperties* properties =
      target->GetLayoutObject()->FirstFragment().PaintProperties();
  ASSERT_NE(nullptr, properties);
  const auto* transform = properties->Transform();
  ASSERT_NE(nullptr, transform);
  // Make sure composited animation is running on #target.
  EXPECT_TRUE(transform->HasDirectCompositingReasons());
  EXPECT_TRUE(transform->HasActiveTransformAnimation());
  EXPECT_EQ(
      CheckCanStartElementOnCompositor(*target, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);
  // Make sure the animation state is initialized in paint properties.
  auto* property_trees =
      document->View()->RootCcLayer()->layer_tree_host()->property_trees();
  const auto* cc_transform =
      property_trees->transform_tree().FindNodeFromElementId(
          transform->GetCompositorElementId());
  ASSERT_NE(nullptr, cc_transform);
  EXPECT_TRUE(cc_transform->has_potential_animation);
  EXPECT_TRUE(cc_transform->is_currently_animating);
  // Make sure the animation is started on the compositor.
  EXPECT_EQ(document->Timeline().AnimationsNeedingUpdateCount(), 1u);
  // Make sure the backface-visibility is correctly set, both in blink and on
  // the cc::Layer.
  EXPECT_FALSE(transform->Matrix().IsIdentity());  // Rotated
  EXPECT_EQ(transform->GetBackfaceVisibilityForTesting(),
            TransformPaintPropertyNode::BackfaceVisibility::kVisible);
  const auto& layer =
      *CcLayersByDOMElementId(document->View()->RootCcLayer(), "target")[0];
  EXPECT_FALSE(layer.should_check_backface_visibility());

  // Change the backface visibility, while the compositor animation is
  // happening.
  target->setAttribute(html_names::kClassAttr, AtomicString("backface-hidden"));
  ForceFullCompositingUpdate();
  // Make sure the setting made it to both blink and all the way to CC.
  EXPECT_EQ(transform->GetBackfaceVisibilityForTesting(),
            TransformPaintPropertyNode::BackfaceVisibility::kHidden);
  EXPECT_TRUE(layer.should_check_backface_visibility())
      << "Change to hidden did not get propagated to CC";
  // Make sure the animation state is initialized in paint properties after
  // blink pushing new paint properties without animation state change.
  property_trees =
      document->View()->RootCcLayer()->layer_tree_host()->property_trees();
  cc_transform = property_trees->transform_tree().FindNodeFromElementId(
      transform->GetCompositorElementId());
  ASSERT_NE(nullptr, cc_transform);
  EXPECT_TRUE(cc_transform->has_potential_animation);
  EXPECT_TRUE(cc_transform->is_currently_animating);
}

// Regression test for https://crbug.com/781305. When we have a transform
// animation on a SVG element, the effect can be started on compositor but the
// element itself cannot.
TEST_P(AnimationCompositorAnimationsTest,
       CannotStartElementOnCompositorEffectSVG) {
  LoadTestData("transform-animation-on-svg.html");
  Document* document = GetFrame()->GetDocument();
  Element* target = document->getElementById(AtomicString("dots"));
  EXPECT_TRUE(
      CheckCanStartElementOnCompositor(*target, *keyframe_animation_effect2_) &
      CompositorAnimations::kTargetHasInvalidCompositingState);
  EXPECT_EQ(document->Timeline().AnimationsNeedingUpdateCount(), 4u);
}

// Regression test for https://crbug.com/999333. We were relying on the Document
// always having Settings, which will not be the case if it is not attached to a
// Frame.
TEST_P(AnimationCompositorAnimationsTest,
       DocumentWithoutSettingShouldNotCauseCrash) {
  SetBodyInnerHTML("<div id='target'></div>");
  Element* target = GetElementById("target");
  ASSERT_TRUE(target);

  ScopedNullExecutionContext execution_context;
  // Move the target element to another Document, that does not have a frame
  // (and thus no Settings).
  Document* another_document =
      Document::CreateForTest(execution_context.GetExecutionContext());
  ASSERT_FALSE(another_document->GetSettings());

  another_document->adoptNode(target, ASSERT_NO_EXCEPTION);

  // This should not crash.
  EXPECT_NE(
      CheckCanStartElementOnCompositor(*target, *keyframe_animation_effect2_),
      CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest, DetachCompositorTimelinesTest) {
  LoadTestData("transform-animation.html");
  Document* document = GetFrame()->GetDocument();
  cc::AnimationHost* host = document->View()->GetCompositorAnimationHost();

  Element* target = document->getElementById(AtomicString("target"));
  const Animation& animation =
      *target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_TRUE(animation.GetCompositorAnimation());

  cc::AnimationTimeline* compositor_timeline =
      animation.TimelineInternal()->CompositorTimeline();
  ASSERT_TRUE(compositor_timeline);
  int id = compositor_timeline->id();
  ASSERT_TRUE(host->GetTimelineById(id));
  document->GetDocumentAnimations().DetachCompositorTimelines();
  ASSERT_FALSE(host->GetTimelineById(id));
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartTransformAnimationOnCompositorForSVG) {
  SetBodyInnerHTML(R"HTML(
    <style>
      .animate {
        width: 100px;
        height: 100px;
        animation: wave 1s infinite;
      }
      @keyframes wave {
        0% { transform: rotate(-5deg); }
        100% { transform: rotate(5deg); }
      }
    </style>
    <svg id="svg" class="animate">
      <rect id="rect" class="animate"/>
      <rect id="rect-useref" class="animate"/>
      <rect id="rect-smil" class="animate">
        <animateMotion dur="10s" repeatCount="indefinite"
                       path="M0,0 L100,100 z"/>
      </rect>
      <rect id="rect-effect" class="animate"
            vector-effect="non-scaling-stroke"/>
      <g id="g-effect" class="animate">
        <rect class="animate" vector-effect="non-scaling-stroke"/>
      </g>
      <svg id="nested-svg" class="animate"/>
      <foreignObject id="foreign" class="animate"/>
      <foreignObject id="foreign-zoomed" class="animate"
                     style="zoom: 1.5; will-change: opacity"/>
      <use id="use" href="#rect-useref" class="animate"/>
      <use id="use-offset" href="#rect-useref" x="10" class="animate"/>
    </svg>
    <svg id="svg-zoomed" class="animate" style="zoom: 1.5">
      <rect id="rect-zoomed" class="animate"/>
    </svg>
  )HTML");

  auto CanStartAnimation = [&](const char* id) -> bool {
    return CompositorAnimations::CanStartTransformAnimationOnCompositorForSVG(
        To<SVGElement>(*GetElementById(id)));
  };

  EXPECT_TRUE(CanStartAnimation("svg"));
  EXPECT_TRUE(CanStartAnimation("rect"));
  EXPECT_FALSE(CanStartAnimation("rect-useref"));
  EXPECT_FALSE(CanStartAnimation("rect-smil"));
  EXPECT_FALSE(CanStartAnimation("rect-effect"));
  EXPECT_FALSE(CanStartAnimation("g-effect"));
  EXPECT_FALSE(CanStartAnimation("nested-svg"));
  EXPECT_TRUE(CanStartAnimation("foreign"));
  EXPECT_FALSE(CanStartAnimation("foreign-zoomed"));
  EXPECT_TRUE(CanStartAnimation("use"));
  EXPECT_FALSE(CanStartAnimation("use-offset"));

  EXPECT_FALSE(CanStartAnimation("svg-zoomed"));
  EXPECT_FALSE(CanStartAnimation("rect-zoomed"));

  To<SVGElement>(GetDocument().getElementById(AtomicString("rect")))
      ->SetWebAnimatedAttribute(
          svg_names::kXAttr,
          MakeGarbageCollected<SVGLength>(SVGLength::Initial::kPercent50,
                                          SVGLengthMode::kOther));
  EXPECT_FALSE(CanStartAnimation("rect"));
}

TEST_P(AnimationCompositorAnimationsTest, UnsupportedSVGCSSProperty) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes mixed {
        0% { transform: rotate(-5deg); stroke-dashoffset: 0; }
        100% { transform: rotate(5deg); stroke-dashoffset: 180; }
      }
    </style>
    <svg>
      <rect id="rect"
            style="width: 100px; height: 100px; animation: mixed 1s infinite"/>
    </svg>
  )HTML");

  Element* element = GetDocument().getElementById(AtomicString("rect"));
  const Animation& animation =
      *element->GetElementAnimations()->Animations().begin()->key;
  EXPECT_EQ(CompositorAnimations::kUnsupportedCSSProperty,
            animation.CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));
}

TEST_P(AnimationCompositorAnimationsTest,
       TotalAnimationCountAcrossAllDocuments) {
  LoadTestData("animation-in-main-frame.html");

  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();

  // We are checking that the animation count for all documents is 1 for every
  // frame.
  for (int i = 0; i < 9; i++) {
    BeginFrame();
    EXPECT_EQ(1U, host->MainThreadAnimationsCount());
  }
}

TEST_P(AnimationCompositorAnimationsTest,
       MainAnimationCountExcludesInactiveAnimations) {
  LoadTestData("inactive-animations.html");

  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();

  // Verify that the paused animation does not count as a running main thread
  // animation.
  EXPECT_EQ(0U, host->MainThreadAnimationsCount());
}

TEST_P(AnimationCompositorAnimationsTest, TrackRafAnimationAcrossAllDocuments) {
  LoadTestData("raf-countdown-in-main-frame.html");

  cc::AnimationHost* host =
      GetFrame()->GetDocument()->View()->GetCompositorAnimationHost();

  // The test file registers two rAF 'animations'; one which ends after 5
  // iterations and the other that ends after 10.
  for (int i = 0; i < 9; i++) {
    BeginFrame();
    EXPECT_TRUE(host->CurrentFrameHadRAF());
    EXPECT_TRUE(host->NextFrameHasPendingRAF());
  }

  // On the 10th iteration, there should be a current rAF, but no more pending
  // rAFs.
  BeginFrame();
  EXPECT_TRUE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());

  // On the 11th iteration, there should be no more rAFs firing.
  BeginFrame();
  EXPECT_FALSE(host->CurrentFrameHadRAF());
  EXPECT_FALSE(host->NextFrameHasPendingRAF());
}

TEST_P(AnimationCompositorAnimationsTest, Fragmented) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes move {
        0% { transform: translateX(10px); }
        100% { transform: translateX(20px); }
      }
      #target {
        width: 10px;
        height: 150px;
        background: green;
      }
    </style>
    <div style="columns: 2; height: 100px">
      <div id="target" style="animation: move 1s infinite">
      </div>
    </div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  const Animation& animation =
      *target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_TRUE(target->GetLayoutObject()->IsFragmented());
  EXPECT_EQ(CompositorAnimations::kTargetHasInvalidCompositingState,
            animation.CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));
}

TEST_P(AnimationCompositorAnimationsTest,
       CancelIncompatibleTransformCompositorAnimation) {
  const auto& style = GetDocument().GetStyleResolver().InitialStyle();

  // The first animation for transform is ok to run on the compositor.
  StringKeyframeEffectModel* effect1 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "none", 0.0),
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "scale(2)", 1.0));
  auto* keyframe_effect1 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect1, timing_);
  Animation* animation1 = timeline_->Play(keyframe_effect1);
  effect1->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                            animation1, *effect1),
            CompositorAnimations::kNoFailure);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(animation1->HasActiveAnimationsOnCompositor());

  // The animation for rotation is ok to run on the compositor as it is a
  // different transformation property.
  StringKeyframeEffectModel* effect2 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kRotate, "0deg", 0.0),
      CreateReplaceOpKeyframe(CSSPropertyID::kRotate, "90deg", 1.0));
  KeyframeEffect* keyframe_effect2 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect2, timing_);
  Animation* animation2 = timeline_->Play(keyframe_effect2);
  effect2->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                            animation2, *effect2),
            CompositorAnimations::kNoFailure);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(animation1->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation2->HasActiveAnimationsOnCompositor());

  // The second animation for transform is not ok to run on the compositor.
  StringKeyframeEffectModel* effect3 = CreateKeyframeEffectModel(
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "none", 0.0),
      CreateReplaceOpKeyframe(CSSPropertyID::kTransform, "translateX(10px)",
                              1.0));
  KeyframeEffect* keyframe_effect3 =
      MakeGarbageCollected<KeyframeEffect>(element_.Get(), effect3, timing_);
  Animation* animation3 = timeline_->Play(keyframe_effect3);
  effect3->SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), style,
                                                     nullptr);
  EXPECT_EQ(CheckCanStartEffectOnCompositor(timing_, *element_.Get(),
                                            animation3, *effect3),
            CompositorAnimations::kTargetHasIncompatibleAnimations);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(animation1->HasActiveAnimationsOnCompositor());
  EXPECT_TRUE(animation2->HasActiveAnimationsOnCompositor());
  EXPECT_FALSE(animation3->HasActiveAnimationsOnCompositor());
}

TEST_P(AnimationCompositorAnimationsTest,
       LongActiveDurationWithNegativePlaybackRate) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes move {
        0% { transform: translateX(10px); }
        100% { transform: translateX(20px); }
      }
      #target {
        width: 10px;
        height: 150px;
        background: green;
        animation: move 1s 2222222200000;
      }
    </style>
    <div id="target"></div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));
  // Setting a small negative playback rate has the following effects:
  // The scaled active duration in microseconds now exceeds the max
  // for an int64. Since the playback rate is negative we need to jump
  // to the end and play backwards, which triggers problems with math
  // involving infinity.
  animation->setPlaybackRate(-0.01);
  EXPECT_TRUE(CompositorAnimations::kInvalidAnimationOrEffect &
              animation->CheckCanStartAnimationOnCompositor(
                  GetDocument().View()->GetPaintArtifactCompositor()));
}

class ScopedBackgroundColorPaintImageGenerator {
 public:
  explicit ScopedBackgroundColorPaintImageGenerator(LocalFrame* frame)
      : paint_image_generator_(
        MakeGarbageCollected<FakeBackgroundColorPaintImageGenerator>()),
        frame_(frame) {
    frame_->SetBackgroundColorPaintImageGeneratorForTesting(
        paint_image_generator_);
  }

  ~ScopedBackgroundColorPaintImageGenerator() {
    frame_->SetBackgroundColorPaintImageGeneratorForTesting(nullptr);
  }

 private:
  class FakeBackgroundColorPaintImageGenerator
      : public BackgroundColorPaintImageGenerator {
    scoped_refptr<Image> Paint(const gfx::SizeF& container_size,
                               const Node* node) override {
      return BitmapImage::Create();
    }

    Animation* GetAnimationIfCompositable(const Element* element) override {
      // Note that the complete test for determining eligibility to run on the
      // compositor is in modules code. It is a layering violation to include
      // here. Instead, we assume that no paint definition specific constraints
      // are violated. These additional constraints should be tested in
      // *_paint_definitiion_test.cc.
      return element->GetElementAnimations()->Animations().begin()->key;
    }

    void Shutdown() override {}
  };

  Persistent<FakeBackgroundColorPaintImageGenerator> paint_image_generator_;
  Persistent<LocalFrame> frame_;
};

TEST_P(AnimationCompositorAnimationsTest, BackgroundShorthand) {
  ClearUseCounters();
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes colorize {
        0% { background: red; }
        100% { background: green; }
      }
      #target {
        width: 100px;
        height: 100px;
        animation: colorize 1s linear;
      }
    </style>
    <div id="target"></div>
  )HTML");

  // Normally, we don't get image generators set up in a testing environment.
  // Construct a fake one to allow us to test that we are making the correct
  // compositing decision.
  ScopedBackgroundColorPaintImageGenerator image_generator(
      GetDocument().GetFrame());

  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;

  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));

  EXPECT_TRUE(IsUseCounted(WebFeature::kStaticPropertyInAnimation));
}

TEST_P(AnimationCompositorAnimationsTest, StaticNonCompositableProperty) {
  ClearUseCounters();
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes fade-in {
        0% { opacity: 0; left: 0px; }
        100% { opacity: 1; left: 0px; }
      }
      #target {
        width: 100px;
        height: 100px;
        animation: fade-in 1s linear;
      }
    </style>
    <div id="target"></div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));
  EXPECT_TRUE(IsUseCounted(WebFeature::kStaticPropertyInAnimation));
}

TEST_P(AnimationCompositorAnimationsTest, StaticCompositableProperty) {
  ClearUseCounters();
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes static {
        0% { opacity: 1; }
        100% { opacity: 1; }
      }
      #target {
        width: 100px;
        height: 100px;
        animation: static 1s linear;
      }
    </style>
    <div id="target"></div>
  )HTML");

  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_TRUE(CompositorAnimations::kAnimationHasNoVisibleChange &
              animation->CheckCanStartAnimationOnCompositor(
                  GetDocument().View()->GetPaintArtifactCompositor()));
  EXPECT_TRUE(IsUseCounted(WebFeature::kStaticPropertyInAnimation));
}

TEST_P(AnimationCompositorAnimationsTest, EmptyKeyframes) {
  ClearUseCounters();
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes no-op {
      }
      #target {
        width: 100px;
        height: 100px;
        animation: no-op 1s linear;
      }
    </style>
    <div id="target"></div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_TRUE(CompositorAnimations::kAnimationHasNoVisibleChange &
              animation->CheckCanStartAnimationOnCompositor(
                  GetDocument().View()->GetPaintArtifactCompositor()));
  EXPECT_FALSE(IsUseCounted(WebFeature::kStaticPropertyInAnimation));
}

TEST_P(AnimationCompositorAnimationsTest,
       WebKitPrefixedPlusUnprefixedProperty) {
  SetBodyInnerHTML(R"HTML(
    <style>
      @keyframes test {
        from {
          -webkit-filter: saturate(0.25);
          filter: saturate(0.25);
        }
        to {
          -webkit-filter: saturate(0.75);
          filter: saturate(0.75);
        }
      }
      #target {
        animation: test 1e3s;
        height: 100px;
        width: 100px;
        background: green;
      }
    </style>
    <div id="target"></div>
  )HTML");
  Element* target = GetDocument().getElementById(AtomicString("target"));
  Animation* animation =
      target->GetElementAnimations()->Animations().begin()->key;
  EXPECT_EQ(CompositorAnimations::kNoFailure,
            animation->CheckCanStartAnimationOnCompositor(
                GetDocument().View()->GetPaintArtifactCompositor()));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(animation->HasActiveAnimationsOnCompositor());
}

}  // namespace blink

"""


```