Response:
My goal is to analyze the provided C++ code snippet and summarize its functionality, highlighting its connections to web technologies and potential usage errors. Here's a breakdown of my thought process:

1. **Identify the Core Purpose:** The file name `compositor_animations_test.cc` immediately suggests that this code is for testing the `CompositorAnimations` functionality within the Blink rendering engine. The presence of `gtest/gtest.h` confirms this.

2. **Scan Includes for Key Components:**  The included headers provide valuable clues about the code's scope:
    * `compositor_animations.h`:  This is the primary target of the tests.
    * `cc/animation/...`:  Indicates interaction with the Chromium Compositor (CC) animation system.
    * `core/animation/...`:  Shows involvement with Blink's core animation concepts.
    * `core/css/...`:  Highlights the connection to CSS properties and values.
    * `core/dom/...`:  Implies manipulation of the Document Object Model.
    * `core/frame/...`: Suggests interactions within the browser frame structure.
    * `platform/graphics/compositing/...`:  Points to how animations interact with the compositing process.

3. **Analyze the Test Fixture:** The `AnimationCompositorAnimationsTest` class, inheriting from `PaintTestConfigurations` and `RenderingTest`, establishes the testing environment. Key observations:
    * It sets up timing functions (`linear_timing_function_`, `cubic_ease_timing_function_`, etc.).
    * It creates mock animation data structures (`keyframe_vector2_`, `keyframe_animation_effect2_`, etc.).
    * It creates and manipulates DOM elements (`element_`, `inline_`).
    * It has methods like `ConvertTimingForCompositor`, `CanStartEffectOnCompositor`, and `GetAnimationOnCompositor`, which are clearly testing functions related to moving animations to the compositor.

4. **Focus on Key Testing Methods:** I looked for recurring patterns and important function calls within the test fixture. The methods like `CanStartEffectOnCompositor` and `CheckCanStartEffectOnCompositor` seem crucial for verifying whether animations can be offloaded to the compositor. The presence of `FailureReasons` suggests that the tests are checking for specific conditions that prevent compositing.

5. **Identify Connections to Web Technologies:**
    * **JavaScript:** While the test code is C++, it directly tests features triggered by JavaScript animation APIs (e.g., `element.animate()`). The code manipulates CSS properties that are often animated via JavaScript.
    * **HTML:** The test sets up HTML elements using `SetBodyInnerHTML`. The animations are applied to these HTML elements.
    * **CSS:** The tests heavily involve CSS properties (e.g., `opacity`, `transform`, `color`, custom properties). The code checks how these properties behave when animated on the compositor. The inclusion of `CSSPropertyID` enumerations confirms this.

6. **Look for Logic and Assumptions:**  The code makes assumptions about the compositing process. For example, the `ConvertTimingForCompositor` method likely translates Blink's animation timing model to the Chromium Compositor's model. The `CanStartEffectOnCompositor` methods implicitly assume criteria for an animation being eligible for compositing (e.g., animatable properties, element compositing status).

7. **Consider Potential User/Programming Errors:** The tests implicitly reveal potential errors:
    * Trying to animate non-compositable CSS properties will lead to failures.
    * Incorrect timing settings might prevent animations from starting correctly on the compositor.
    * Animating properties on non-composited elements will also be an issue.

8. **Synthesize a Summary:** Based on the above analysis, I can now formulate a concise summary:

    * **Core Function:** The code tests the functionality of `CompositorAnimations`, which is responsible for determining if a CSS animation can be offloaded to the browser's compositor thread for smoother performance.

    * **Web Technology Links:** It directly relates to JavaScript (as animations are often triggered by JS), HTML (as animations are applied to HTML elements), and CSS (as it tests the compositing of CSS properties).

    * **Logical Reasoning (Hypothetical):** If a CSS animation targeting the `opacity` property is applied to a composited element with valid timing, the test expects `CanStartEffectOnCompositor` to return success. If the property were `color`, the test would likely expect failure.

    * **User/Programming Errors:**  Common errors include attempting to animate non-compositable properties or trying to animate elements that aren't composited.

    * **Part 1 Summary:** This initial part sets up the testing infrastructure and includes basic tests for determining if animations of specific CSS properties can be handled by the compositor. It focuses on individual keyframes and their properties.

By following these steps, I can effectively analyze the code snippet and provide a comprehensive overview of its purpose and context.好的，让我们来分析一下 `blink/renderer/core/animation/compositor_animations_test.cc` 这个文件的功能。

**文件功能归纳：**

这个 C++ 文件是 Chromium Blink 引擎的一部分，专门用于测试 `CompositorAnimations` 类的功能。`CompositorAnimations` 负责决定是否可以将 CSS 动画转移到合成器线程（compositor thread）进行处理，以提高动画性能和平滑度。因此，这个测试文件的主要目的是验证 `CompositorAnimations` 在各种场景下是否能够正确判断动画是否可以合成。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件虽然是用 C++ 编写的，但它直接关系到 Web 开发中常用的 JavaScript, HTML 和 CSS 技术，因为其测试的核心是 CSS 动画的合成。

* **CSS (Cascading Style Sheets):**
    * **功能关系：**  CSS 负责定义网页元素的样式和动画效果。`CompositorAnimations` 的核心任务就是判断哪些 CSS 动画可以在合成器线程上运行。
    * **举例说明：**
        * **假设输入（CSS）：**  一个简单的 CSS 动画定义，例如：
          ```css
          .animated-element {
            animation: fadeIn 1s linear;
          }

          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }
          ```
        * **逻辑推理（文件内部测试）：**  `compositor_animations_test.cc` 中会创建类似的动画效果数据结构，并调用 `CompositorAnimations` 的方法来判断 `opacity` 属性的动画是否可以合成。由于 `opacity` 是一个可以合成的属性，测试会验证 `CompositorAnimations` 返回成功。
        * **假设输入（CSS）：**  另一个 CSS 动画定义，使用了不能直接合成的属性，例如：
          ```css
          .animated-element {
            animation: changeColor 1s linear;
          }

          @keyframes changeColor {
            from { background-color: red; }
            to { background-color: blue; }
          }
          ```
        * **逻辑推理（文件内部测试）：**  测试会验证 `CompositorAnimations` 对于 `background-color` 属性的动画会返回失败（或需要进行特殊处理）。

* **HTML (HyperText Markup Language):**
    * **功能关系：** HTML 定义了网页的结构和内容。CSS 动画是应用于 HTML 元素的。
    * **举例说明：**
        * **假设输入（HTML）：**
          ```html
          <div class="animated-element">Hello</div>
          ```
        * **逻辑推理（文件内部测试）：**  测试会创建或获取到对应的 `<div>` 元素，并将动画效果与之关联，然后判断这个元素的动画是否可以合成。元素的某些属性（例如是否开启了硬件加速）会影响动画的可合成性。

* **JavaScript:**
    * **功能关系：** JavaScript 可以用来动态地创建、修改和控制 CSS 动画。
    * **举例说明：**
        * **假设输入（JavaScript）：**
          ```javascript
          const element = document.querySelector('.animated-element');
          element.animate([
            { opacity: 0 },
            { opacity: 1 }
          ], {
            duration: 1000,
            easing: 'linear'
          });
          ```
        * **逻辑推理（文件内部测试）：**  虽然测试文件本身是 C++，但它模拟了 JavaScript 创建动画的场景，通过构建相应的动画数据结构，来测试 `CompositorAnimations` 的判断逻辑。

**逻辑推理的假设输入与输出：**

* **假设输入：** 一个包含了 `opacity` 属性从 0 到 1 变化的 CSS 动画关键帧数据。
* **输出：**  `CompositorAnimations` 的相关方法返回成功，表明该动画可以交给合成器线程处理。

* **假设输入：** 一个包含了 `background-color` 属性从红色到蓝色变化的 CSS 动画关键帧数据。
* **输出：** `CompositorAnimations` 的相关方法返回失败（或指示需要特殊的处理），表明该动画可能需要在主线程处理。

**涉及用户或者编程常见的使用错误：**

* **尝试动画非合成属性：**  用户（开发者）可能会尝试动画某些无法直接在合成器线程上高效运行的 CSS 属性，例如 `background-color`、`text-shadow` 等复杂的绘制属性。`CompositorAnimations` 的测试会覆盖这种情况，帮助开发者理解哪些属性的动画性能更好。
* **在非合成层上应用动画：**  即使动画的属性本身可以合成，如果目标元素没有被提升为合成层（例如没有应用 `transform` 或 `opacity` 等属性），动画可能仍然无法在合成器线程运行。测试会验证这种情况。
* **错误的 timing 设置：**  动画的 `start-delay`、`duration`、`easing` 函数等 timing 属性可能会影响动画的合成。测试会检查这些因素。

**第1部分功能归纳：**

这部分代码主要做了以下几件事：

1. **引入必要的头文件：**  包含了 `CompositorAnimations` 的定义以及其他 Blink 和 Chromium Compositor 相关的类。
2. **定义测试环境：**  创建了一个名为 `AnimationCompositorAnimationsTest` 的测试类，继承自 `PaintTestConfigurations` 和 `RenderingTest`，用于搭建测试所需的渲染环境。
3. **初始化测试数据：**  创建了一些常用的 timing 函数（如线性、ease 等）和简单的关键帧数据结构，用于后续的测试用例。
4. **设置测试辅助函数：**  定义了一些辅助函数，例如 `ConvertTimingForCompositor`（用于转换动画 timing 信息），`CanStartEffectOnCompositor` 和 `CheckCanStartEffectOnCompositor`（用于检查动画是否可以在合成器上启动），以及创建不同类型的关键帧的方法。
5. **基础测试用例：**  包含了一些基础的测试用例，例如 `CanStartEffectOnCompositorKeyframeMultipleCSSProperties` 和 `CanStartEffectOnCompositorKeyframeEffectModel`，初步测试了对于不同 CSS 属性和关键帧配置的动画，`CompositorAnimations` 的判断能力。

总而言之，这部分代码是 `compositor_animations_test.cc` 文件的开始，它搭建了测试框架和基础工具，并开始测试 `CompositorAnimations` 的核心功能，即判断动画是否可以进行合成优化。它与 Web 开发中的 CSS 动画息息相关，验证了引擎对于不同动画场景的处理能力。

Prompt: 
```
这是目录为blink/renderer/core/animation/compositor_animations_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2013, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/animation/compositor_animations.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/auto_reset.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "cc/animation/animation_host.h"
#include "cc/animation/keyframe_model.h"
#include "cc/layers/picture_layer.h"
#include "cc/trees/transform_node.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_string_unrestricteddouble.h"
#include "third_party/blink/renderer/core/animation/animation.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/css/compositor_keyframe_double.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect.h"
#include "third_party/blink/renderer/core/animation/pending_animations.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_paint_value.h"
#include "third_party/blink/renderer/core/css/css_syntax_definition.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/mock_css_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/paint/object_paint_properties.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/core/style/style_generated_image.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_length.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/testing/find_cc_layer.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/transforms/transform_operations.h"
#include "third_party/blink/renderer/platform/transforms/translate_transform_operation.h"
#include "third_party/blink/renderer/platform/wtf/hash_functions.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/animation/keyframe/animation_curve.h"
#include "ui/gfx/animation/keyframe/keyframed_animation_curve.h"
#include "ui/gfx/geometry/size.h"

using testing::_;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::Values;

namespace blink {

namespace {
// CSSPaintImageGenerator requires that CSSPaintImageGeneratorCreateFunction be
// a static method. As such, it cannot access a class member and so instead we
// store a pointer to the overriding generator globally.
MockCSSPaintImageGenerator* g_override_generator = nullptr;
CSSPaintImageGenerator* ProvideOverrideGenerator(
    const String&,
    const Document&,
    CSSPaintImageGenerator::Observer*) {
  return g_override_generator;
}

}  // namespace

using css_test_helpers::RegisterProperty;

class AnimationCompositorAnimationsTest : public PaintTestConfigurations,
                                          public RenderingTest {
 protected:
  scoped_refptr<TimingFunction> linear_timing_function_;
  scoped_refptr<TimingFunction> cubic_ease_timing_function_;
  scoped_refptr<TimingFunction> cubic_custom_timing_function_;
  scoped_refptr<TimingFunction> step_timing_function_;

  Timing timing_;
  CompositorAnimations::CompositorTiming compositor_timing_;
  Persistent<HeapVector<Member<StringKeyframe>>> keyframe_vector2_;
  Persistent<StringKeyframeEffectModel> keyframe_animation_effect2_;
  Persistent<HeapVector<Member<StringKeyframe>>> keyframe_vector5_;
  Persistent<StringKeyframeEffectModel> keyframe_animation_effect5_;

  Persistent<Element> element_;
  Persistent<Element> inline_;
  Persistent<DocumentTimeline> timeline_;

  void SetUp() override {
    EnableCompositing();
    RenderingTest::SetUp();
    linear_timing_function_ = LinearTimingFunction::Shared();
    cubic_ease_timing_function_ = CubicBezierTimingFunction::Preset(
        CubicBezierTimingFunction::EaseType::EASE);
    cubic_custom_timing_function_ =
        CubicBezierTimingFunction::Create(1, 2, 3, 4);
    step_timing_function_ =
        StepsTimingFunction::Create(1, StepsTimingFunction::StepPosition::END);

    timing_ = CreateCompositableTiming();
    compositor_timing_ = CompositorAnimations::CompositorTiming();

    keyframe_vector2_ = CreateCompositableFloatKeyframeVector(2);
    keyframe_animation_effect2_ =
        MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector2_);

    keyframe_vector5_ = CreateCompositableFloatKeyframeVector(5);
    keyframe_animation_effect5_ =
        MakeGarbageCollected<StringKeyframeEffectModel>(*keyframe_vector5_);

    GetAnimationClock().ResetTimeForTesting();

    timeline_ = GetDocument().Timeline();
    timeline_->ResetForTesting();

    // Make sure the CompositableTiming is really compositable, otherwise
    // most other tests will fail.
    ASSERT_TRUE(ConvertTimingForCompositor(timing_, compositor_timing_));

    // Using will-change ensures that this object will need paint properties.
    // Having an animation would normally ensure this but these tests don't
    // explicitly construct a full animation on the element.
    SetBodyInnerHTML(R"HTML(
      <div id='test' style='will-change: opacity,filter,transform,rotate;
                            height:100px; background: green;'>
      </div>
      <span id='inline' style='will-change: opacity,filter,transform;'>
        text
      </span>
    )HTML");
    element_ = GetDocument().getElementById(AtomicString("test"));
    inline_ = GetDocument().getElementById(AtomicString("inline"));

    helper_.Initialize(nullptr, nullptr, nullptr);
    helper_.Resize(gfx::Size(800, 600));
    base_url_ = "http://www.test.com/";
  }

 public:
  AnimationCompositorAnimationsTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  bool ConvertTimingForCompositor(const Timing& t,
                                  CompositorAnimations::CompositorTiming& out,
                                  double playback_rate = 1) {
    return CompositorAnimations::ConvertTimingForCompositor(
        t, NormalizedTiming(t), base::TimeDelta(), out, playback_rate);
  }

  CompositorAnimations::FailureReasons CanStartEffectOnCompositor(
      const Timing& timing,
      const KeyframeEffectModelBase& effect) {
    // TODO(crbug.com/725385): Remove once compositor uses InterpolationTypes.
    const auto* style = GetDocument().GetStyleResolver().ResolveStyle(
        element_, StyleRecalcContext());
    effect.SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), *style,
                                                     nullptr);
    return CheckCanStartEffectOnCompositor(timing, *element_.Get(), nullptr,
                                           effect);
  }
  CompositorAnimations::FailureReasons CheckCanStartEffectOnCompositor(
      const Timing& timing,
      const Element& element,
      const Animation* animation,
      const EffectModel& effect_model,
      PropertyHandleSet* unsupported_properties = nullptr) {
    const PaintArtifactCompositor* paint_artifact_compositor =
        GetDocument().View()->GetPaintArtifactCompositor();
    return CompositorAnimations::CheckCanStartEffectOnCompositor(
        timing, NormalizedTiming(timing), element, animation, effect_model,
        paint_artifact_compositor, 1, unsupported_properties);
  }

  CompositorAnimations::FailureReasons CheckCanStartElementOnCompositor(
      const Element& element,
      const EffectModel& model) {
    return CompositorAnimations::CheckCanStartElementOnCompositor(element,
                                                                  model);
  }

  void GetAnimationOnCompositor(
      Timing& timing,
      StringKeyframeEffectModel& effect,
      Vector<std::unique_ptr<cc::KeyframeModel>>& keyframe_models,
      double animation_playback_rate) {
    CompositorAnimations::GetAnimationOnCompositor(
        *element_, timing, NormalizedTiming(timing), 0, std::nullopt,
        base::TimeDelta(), effect, keyframe_models, animation_playback_rate,
        /*is_monotonic_timeline=*/true, /*is_boundary_aligned=*/false);
  }

  CompositorAnimations::FailureReasons
  CreateKeyframeListAndTestIsCandidateOnResult(StringKeyframe* first_frame,
                                               StringKeyframe* second_frame) {
    EXPECT_EQ(first_frame->CheckedOffset(), 0);
    EXPECT_EQ(second_frame->CheckedOffset(), 1);
    StringKeyframeVector frames;
    frames.push_back(first_frame);
    frames.push_back(second_frame);
    return CanStartEffectOnCompositor(
        timing_, *MakeGarbageCollected<StringKeyframeEffectModel>(frames));
  }

  CompositorAnimations::FailureReasons CheckKeyframeVector(
      const StringKeyframeVector& frames) {
    return CanStartEffectOnCompositor(
        timing_, *MakeGarbageCollected<StringKeyframeEffectModel>(frames));
  }

  // -------------------------------------------------------------------

  Timing CreateCompositableTiming() {
    Timing timing;
    timing.start_delay = Timing::Delay(AnimationTimeDelta());
    timing.fill_mode = Timing::FillMode::NONE;
    timing.iteration_start = 0;
    timing.iteration_count = 1;
    timing.iteration_duration = ANIMATION_TIME_DELTA_FROM_SECONDS(1);
    timing.direction = Timing::PlaybackDirection::NORMAL;
    timing.timing_function = linear_timing_function_;
    return timing;
  }

  // Simplified version of what happens in AnimationEffect::NormalizedTiming()
  Timing::NormalizedTiming NormalizedTiming(Timing timing) {
    Timing::NormalizedTiming normalized_timing;

    // Currently, compositor animation tests are using document timelines
    // exclusively. In order to support scroll timelines, the algorithm would
    // need to correct for the intrinsic iteration duration of the timeline.
    EXPECT_TRUE(timeline_->IsDocumentTimeline());

    normalized_timing.start_delay = timing.start_delay.AsTimeValue();
    normalized_timing.end_delay = timing.end_delay.AsTimeValue();

    normalized_timing.iteration_duration =
        timing.iteration_duration.value_or(AnimationTimeDelta());

    normalized_timing.active_duration =
        normalized_timing.iteration_duration * timing.iteration_count;

    normalized_timing.end_time = std::max(
        normalized_timing.start_delay + normalized_timing.active_duration +
            normalized_timing.end_delay,
        AnimationTimeDelta());

    return normalized_timing;
  }

  StringKeyframe* CreateReplaceOpKeyframe(CSSPropertyID id,
                                          const String& value,
                                          double offset = 0) {
    auto* keyframe = MakeGarbageCollected<StringKeyframe>();
    keyframe->SetCSSPropertyValue(id, value,
                                  SecureContextMode::kInsecureContext, nullptr);
    keyframe->SetComposite(EffectModel::kCompositeReplace);
    keyframe->SetOffset(offset);
    keyframe->SetEasing(LinearTimingFunction::Shared());
    return keyframe;
  }

  StringKeyframe* CreateReplaceOpKeyframe(const String& property_name,
                                          const String& value,
                                          double offset = 0) {
    auto* keyframe = MakeGarbageCollected<StringKeyframe>();
    keyframe->SetCSSPropertyValue(
        AtomicString(property_name), value,
        GetDocument().GetExecutionContext()->GetSecureContextMode(),
        GetDocument().ElementSheet().Contents());
    keyframe->SetComposite(EffectModel::kCompositeReplace);
    keyframe->SetOffset(offset);
    keyframe->SetEasing(LinearTimingFunction::Shared());
    return keyframe;
  }

  StringKeyframe* CreateDefaultKeyframe(CSSPropertyID id,
                                        EffectModel::CompositeOperation op,
                                        double offset = 0) {
    String value = "0.1";
    if (id == CSSPropertyID::kTransform)
      value = "none";
    else if (id == CSSPropertyID::kColor)
      value = "red";

    StringKeyframe* keyframe = CreateReplaceOpKeyframe(id, value, offset);
    keyframe->SetComposite(op);
    return keyframe;
  }

  StringKeyframeVector CreateDefaultKeyframeVector(
      CSSPropertyID id,
      EffectModel::CompositeOperation op) {
    StringKeyframeVector results;
    String first, second;
    switch (id) {
      case CSSPropertyID::kOpacity:
        first = "0.1";
        second = "1";
        break;

      case CSSPropertyID::kTransform:
        first = "none";
        second = "scale(1)";
        break;

      case CSSPropertyID::kColor:
        first = "red";
        second = "green";
        break;

      default:
        NOTREACHED();
    }

    StringKeyframe* keyframe = CreateReplaceOpKeyframe(id, first, 0);
    keyframe->SetComposite(op);
    results.push_back(keyframe);
    keyframe = CreateReplaceOpKeyframe(id, second, 1);
    keyframe->SetComposite(op);
    results.push_back(keyframe);
    return results;
  }

  HeapVector<Member<StringKeyframe>>* CreateCompositableFloatKeyframeVector(
      size_t n) {
    Vector<double> values;
    for (size_t i = 0; i < n; i++) {
      values.push_back(static_cast<double>(i));
    }
    return CreateCompositableFloatKeyframeVector(values);
  }

  HeapVector<Member<StringKeyframe>>* CreateCompositableFloatKeyframeVector(
      Vector<double>& values) {
    HeapVector<Member<StringKeyframe>>* frames =
        MakeGarbageCollected<HeapVector<Member<StringKeyframe>>>();
    for (wtf_size_t i = 0; i < values.size(); i++) {
      double offset = 1.0 / (values.size() - 1) * i;
      String value = String::Number(values[i]);
      frames->push_back(
          CreateReplaceOpKeyframe(CSSPropertyID::kOpacity, value, offset));
    }
    return frames;
  }

  void SetCustomProperty(const String& name, const String& value) {
    DummyExceptionStateForTesting exception_state;
    element_->style()->setProperty(GetDocument().GetExecutionContext(), name,
                                   value, g_empty_string, exception_state);
    EXPECT_FALSE(exception_state.HadException());
    EXPECT_TRUE(element_->style()->getPropertyValue(name));
  }

  bool IsUseCounted(mojom::WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  void ClearUseCounters() {
    GetDocument().ClearUseCounterForTesting(
        WebFeature::kStaticPropertyInAnimation);
    // If other use counters are test, be sure the clear them here.
  }

  // This class exists to dodge the interlock between creating compositor
  // keyframe values iff we can animate them on the compositor, and hence can
  // start their animations on it. i.e. two far away switch statements have
  // matching non-default values, preventing us from testing the default.
  class MockStringKeyframe : public StringKeyframe {
   public:
    static StringKeyframe* Create(double offset) {
      return MakeGarbageCollected<MockStringKeyframe>(offset);
    }

    MockStringKeyframe(double offset)
        : StringKeyframe(),
          property_specific_(
              MakeGarbageCollected<MockPropertySpecificStringKeyframe>(
                  offset)) {
      SetOffset(offset);
    }

    Keyframe::PropertySpecificKeyframe* CreatePropertySpecificKeyframe(
        const PropertyHandle&,
        EffectModel::CompositeOperation,
        double) const final {
      return property_specific_.Get();  // We know a shortcut.
    }

    void Trace(Visitor* visitor) const override {
      visitor->Trace(property_specific_);
      StringKeyframe::Trace(visitor);
    }

   private:
    class MockPropertySpecificStringKeyframe : public PropertySpecificKeyframe {
     public:
      // Pretend to have a compositor keyframe value. Pick the offset for pure
      // convenience: it matters not what it is.
      MockPropertySpecificStringKeyframe(double offset)
          : PropertySpecificKeyframe(offset,
                                     LinearTimingFunction::Shared(),
                                     EffectModel::kCompositeReplace),
            compositor_keyframe_value_(
                MakeGarbageCollected<CompositorKeyframeDouble>(offset)) {}
      bool IsNeutral() const final { return true; }
      bool IsRevert() const final { return false; }
      bool IsRevertLayer() const final { return false; }
      PropertySpecificKeyframe* CloneWithOffset(double) const final {
        NOTREACHED();
      }
      bool PopulateCompositorKeyframeValue(
          const PropertyHandle&,
          Element&,
          const ComputedStyle& base_style,
          const ComputedStyle* parent_style) const final {
        return true;
      }
      const CompositorKeyframeValue* GetCompositorKeyframeValue() const final {
        return compositor_keyframe_value_.Get();
      }
      PropertySpecificKeyframe* NeutralKeyframe(
          double,
          scoped_refptr<TimingFunction>) const final {
        NOTREACHED();
      }

      void Trace(Visitor* visitor) const override {
        visitor->Trace(compositor_keyframe_value_);
        PropertySpecificKeyframe::Trace(visitor);
      }

     private:
      Member<CompositorKeyframeDouble> compositor_keyframe_value_;
    };

    Member<PropertySpecificKeyframe> property_specific_;
  };

  StringKeyframe* CreateMockReplaceKeyframe(CSSPropertyID id,
                                            const String& value,
                                            double offset) {
    StringKeyframe* keyframe = MockStringKeyframe::Create(offset);
    keyframe->SetCSSPropertyValue(id, value,
                                  SecureContextMode::kInsecureContext, nullptr);
    keyframe->SetComposite(EffectModel::kCompositeReplace);
    keyframe->SetEasing(LinearTimingFunction::Shared());

    return keyframe;
  }

  StringKeyframe* CreateSVGKeyframe(const QualifiedName& name,
                                    const String& value,
                                    double offset) {
    auto* keyframe = MakeGarbageCollected<StringKeyframe>();
    keyframe->SetSVGAttributeValue(name, value);
    keyframe->SetComposite(EffectModel::kCompositeReplace);
    keyframe->SetOffset(offset);
    keyframe->SetEasing(LinearTimingFunction::Shared());

    return keyframe;
  }

  StringKeyframeEffectModel* CreateKeyframeEffectModel(
      StringKeyframe* from,
      StringKeyframe* to,
      StringKeyframe* c = nullptr,
      StringKeyframe* d = nullptr) {
    EXPECT_EQ(from->CheckedOffset(), 0);
    StringKeyframeVector frames;
    frames.push_back(from);
    EXPECT_LE(from->Offset(), to->Offset());
    frames.push_back(to);
    if (c) {
      EXPECT_LE(to->Offset(), c->Offset());
      frames.push_back(c);
    }
    if (d) {
      frames.push_back(d);
      EXPECT_LE(c->Offset(), d->Offset());
      EXPECT_EQ(d->CheckedOffset(), 1.0);
    } else {
      EXPECT_EQ(to->CheckedOffset(), 1.0);
    }
    if (!HasFatalFailure()) {
      return MakeGarbageCollected<StringKeyframeEffectModel>(frames);
    }
    return nullptr;
  }

  void SimulateFrame(double time) {
    GetAnimationClock().UpdateTime(base::TimeTicks() + base::Seconds(time));
    timeline_->ServiceAnimations(kTimingUpdateForAnimationFrame);
    GetPendingAnimations().Update(nullptr, false);
  }

  std::unique_ptr<cc::KeyframeModel> ConvertToCompositorAnimation(
      StringKeyframeEffectModel& effect,
      double animation_playback_rate) {
    // As the compositor code only understands CompositorKeyframeValues, we must
    // snapshot the effect to make those available.
    // TODO(crbug.com/725385): Remove once compositor uses InterpolationTypes.
    const auto* style = GetDocument().GetStyleResolver().ResolveStyle(
        element_, StyleRecalcContext());
    effect.SnapshotAllCompositorKeyframesIfNecessary(*element_.Get(), *style,
                                                     nullptr);

    Vector<std::unique_ptr<cc::KeyframeModel>> result;
    GetAnimationOnCompositor(timing_, effect, result, animation_playback_rate);
    DCHECK_EQ(1U, result.size());
    return std::move(result[0]);
  }

  std::unique_ptr<cc::KeyframeModel> ConvertToCompositorAnimation(
      StringKeyframeEffectModel& effect) {
    return ConvertToCompositorAnimation(effect, 1.0);
  }

  std::unique_ptr<gfx::KeyframedFloatAnimationCurve>
  CreateKeyframedFloatAnimationCurve(cc::KeyframeModel* keyframe_model) {
    const gfx::AnimationCurve* curve = keyframe_model->curve();
    DCHECK_EQ(gfx::AnimationCurve::FLOAT, curve->Type());

    return base::WrapUnique(static_cast<gfx::KeyframedFloatAnimationCurve*>(
        curve->Clone().release()));
  }

  std::unique_ptr<gfx::KeyframedColorAnimationCurve>
  CreateKeyframedColorAnimationCurve(cc::KeyframeModel* keyframe_model) const {
    const gfx::AnimationCurve* curve = keyframe_model->curve();
    DCHECK_EQ(gfx::AnimationCurve::COLOR, curve->Type());

    return base::WrapUnique(static_cast<gfx::KeyframedColorAnimationCurve*>(
        curve->Clone().release()));
  }

  void ExpectKeyframeTimingFunctionCubic(
      const gfx::FloatKeyframe& keyframe,
      const CubicBezierTimingFunction::EaseType ease_type) {
    auto keyframe_timing_function =
        CreateCompositorTimingFunctionFromCC(keyframe.timing_function());
    DCHECK_EQ(keyframe_timing_function->GetType(),
              TimingFunction::Type::CUBIC_BEZIER);
    const auto& cubic_timing_function =
        To<CubicBezierTimingFunction>(*keyframe_timing_function);
    EXPECT_EQ(cubic_timing_function.GetEaseType(), ease_type);
  }

  void LoadTestData(const std::string& file_name) {
    String testing_path =
        test::BlinkRootDir() + "/renderer/core/animation/test_data/";
    WebURL url = url_test_helpers::RegisterMockedURLLoadFromBase(
        WebString::FromUTF8(base_url_), testing_path,
        WebString::FromUTF8(file_name));
    frame_test_helpers::LoadFrame(helper_.GetWebView()->MainFrameImpl(),
                                  base_url_ + file_name);
    ForceFullCompositingUpdate();
    url_test_helpers::RegisterMockedURLUnregister(url);
  }

  LocalFrame* GetFrame() const { return helper_.LocalMainFrame()->GetFrame(); }

  void BeginFrame() {
    helper_.GetWebView()
        ->MainFrameViewWidget()
        ->SynchronouslyCompositeForTesting(base::TimeTicks::Now());
  }

  void ForceFullCompositingUpdate() {
    helper_.GetWebView()->MainFrameWidget()->UpdateAllLifecyclePhases(
        DocumentUpdateReason::kTest);
  }

 private:
  frame_test_helpers::WebViewHelper helper_;
  std::string base_url_;
};

class LayoutObjectProxy : public LayoutObject {
 public:
  static LayoutObjectProxy* Create(Node* node) {
    return MakeGarbageCollected<LayoutObjectProxy>(node);
  }

  static void Dispose(LayoutObjectProxy* proxy) { proxy->Destroy(); }

  const char* GetName() const override { return nullptr; }
  gfx::RectF LocalBoundingBoxRectForAccessibility() const override {
    return gfx::RectF();
  }

  void EnsureIdForTestingProxy() {
    // We need Ids of proxies to be valid.
    EnsureIdForTesting();
  }

  explicit LayoutObjectProxy(Node* node) : LayoutObject(node) {}
};

// -----------------------------------------------------------------------
// -----------------------------------------------------------------------

INSTANTIATE_PAINT_TEST_SUITE_P(AnimationCompositorAnimationsTest);

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorKeyframeMultipleCSSProperties) {
  StringKeyframeVector supported_mixed_keyframe_vector;
  auto* keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(0);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "0",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kTransform, "none",
                                SecureContextMode::kInsecureContext, nullptr);

  supported_mixed_keyframe_vector.push_back(keyframe);
  keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(1);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "1",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kTransform, "scale(1, 1)",
                                SecureContextMode::kInsecureContext, nullptr);
  supported_mixed_keyframe_vector.push_back(keyframe);
  EXPECT_EQ(CheckKeyframeVector(supported_mixed_keyframe_vector),
            CompositorAnimations::kNoFailure);

  StringKeyframeVector unsupported_mixed_keyframe_vector;
  keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(0);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kColor, "red",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "0",
                                SecureContextMode::kInsecureContext, nullptr);
  unsupported_mixed_keyframe_vector.push_back(keyframe);
  keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(1);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kColor, "green",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "1",
                                SecureContextMode::kInsecureContext, nullptr);
  unsupported_mixed_keyframe_vector.push_back(keyframe);
  EXPECT_TRUE(CheckKeyframeVector(unsupported_mixed_keyframe_vector) &
              CompositorAnimations::kUnsupportedCSSProperty);

  StringKeyframeVector supported_mixed_keyframe_vector_static_color;
  keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(0);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kColor, "red",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "0",
                                SecureContextMode::kInsecureContext, nullptr);
  supported_mixed_keyframe_vector_static_color.push_back(keyframe);
  keyframe = MakeGarbageCollected<StringKeyframe>();
  keyframe->SetOffset(1);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kColor, "red",
                                SecureContextMode::kInsecureContext, nullptr);
  keyframe->SetCSSPropertyValue(CSSPropertyID::kOpacity, "1",
                                SecureContextMode::kInsecureContext, nullptr);
  supported_mixed_keyframe_vector_static_color.push_back(keyframe);
  EXPECT_EQ(CheckKeyframeVector(supported_mixed_keyframe_vector_static_color),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorKeyframeEffectModel) {
  StringKeyframeVector frames_same;

  frames_same.push_back(CreateDefaultKeyframe(
      CSSPropertyID::kColor, EffectModel::kCompositeReplace, 0.0));
  frames_same.push_back(CreateDefaultKeyframe(
      CSSPropertyID::kColor, EffectModel::kCompositeReplace, 1.0));
  EXPECT_TRUE(CheckKeyframeVector(frames_same) &
              CompositorAnimations::kAnimationHasNoVisibleChange);

  StringKeyframeVector color_keyframes = CreateDefaultKeyframeVector(
      CSSPropertyID::kColor, EffectModel::kCompositeReplace);
  EXPECT_TRUE(CheckKeyframeVector(color_keyframes) &
              CompositorAnimations::kUnsupportedCSSProperty);

  StringKeyframeVector opacity_keyframes = CreateDefaultKeyframeVector(
      CSSPropertyID::kOpacity, EffectModel::kCompositeReplace);
  EXPECT_EQ(CheckKeyframeVector(opacity_keyframes),
            CompositorAnimations::kNoFailure);
}

TEST_P(AnimationCompositorAnimationsTest,
       CanStartEffectOnCompositorCustomCssProperty) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  RegisterProperty(GetDocument(), "--foo", "<number>", "0", false);
  RegisterProperty(GetDocument(), "--bar", "<length>", "10px", false);
  RegisterProperty(GetDocument(), "--loo", "<color>", "rgb(0, 0, 0)", false);
  RegisterProperty(GetDocument(), "--x", "<number>", "0", false);
  RegisterProperty(GetDocument(), "--y", "<number>", "200", false);
  RegisterProperty(GetDocument(), "--z", "<number>", "200", false);
  SetCustomProperty("--foo", "10");
  SetCustomProperty("--bar", "10px");
  SetCustomProperty("--loo", "rgb(0, 255, 0)");
  SetCustomProperty("--x", "5");

  UpdateAllLifecyclePhasesForTest();
  const auto* style = GetDocument().GetStyleResolver().ResolveStyle(
      element_, StyleRecalcContext());
  EXPECT_TRUE(style->NonInheritedVariables());
  EXPECT_TRUE(style->NonInheritedVariables()
                  ->GetData(AtomicString("--foo"))
                  .value_or(nullptr));
  EXPECT_TRUE(style->NonInheritedVariables()
                  ->GetData(AtomicString("--bar"))
                  .value_or(nullptr));
  EXPECT_TRUE(style->NonInheritedVariables()
                  ->GetData(AtomicString("--loo"))
                  .value_or(nullptr));
  EXPECT_TRUE(style->NonInheritedVariables()
                  ->GetData(AtomicString("--x"))
                  .value_or(nullptr));
  EXPECT_TRUE(style->GetVariableData(AtomicString("--y")));
  EXPECT_TRUE(style->GetVariableData(AtomicString("--z")));

  NiceMock<MockCSSPaintImageGenerator>* mock_generator =
      MakeGarbageCollected<NiceMock<MockCSSPaintImageGenerator>>();
  base::AutoReset<MockCSSPaintImageGenerator*> scoped_override_generator(
      &g_override_generator, mock_generator);
  base::AutoReset<CSSPaintImageGener
"""


```