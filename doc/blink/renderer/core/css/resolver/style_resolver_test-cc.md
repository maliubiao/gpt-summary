Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a Chromium Blink engine source file, `style_resolver_test.cc`. Key points to cover are its function, relationship to web technologies (HTML, CSS, JavaScript), logical reasoning within the tests, common user/programming errors it might help uncover, and how a user might reach this code (debugging context). Crucially, it's the *first part* of a larger file.

**2. High-Level Analysis (Skimming the Includes and Class Declaration):**

The `#include` directives immediately give clues about the file's purpose. We see:

* `style_resolver.h`:  This is the core functionality being tested. The file is about testing the `StyleResolver`.
* `testing/gtest/include/gtest/gtest.h`: Indicates this is a unit test file using the Google Test framework.
* Various `blink/public/mojom/...`: Hints at communication or data structures related to the rendering process.
* A large number of includes from `blink/renderer/core/...`: This points to the core rendering engine functionalities being interacted with: animation, CSS, DOM, frames, layout, etc. The sheer number suggests the `StyleResolver` is a central component with many dependencies.

The class declaration `class StyleResolverTest : public PageTestBase` confirms this is a test fixture. `PageTestBase` implies it sets up a minimal web page environment for testing.

**3. Deeper Dive into the Test Methods:**

The test methods (functions starting with `TEST_F`) are the heart of understanding the functionality. I'd go through them individually, identifying the core action and what aspect of the `StyleResolver` it's verifying. Here's a breakdown of the thought process for a few examples:

* **`StyleForTextInDisplayNone`:**  The code sets `display:none` on the `body`. It then checks if the `StyleResolver` produces a style for the text node inside. The expectation is that it *doesn't*. This points to the `StyleResolver` being aware of `display: none` and not processing styles for those elements' text content. This is clearly related to CSS's `display` property.

* **`AnimationBaseComputedStyle`:** This test sets up CSS with an animation. It retrieves the computed style of the animated element and then checks for `GetBaseComputedStyle()`. The test then intentionally tries to get the style with a *different* parent style and verifies the original base style remains unchanged. This suggests the `StyleResolver` has a concept of a "base" style for animations that needs to be preserved, potentially for performance or correctness during animation updates. This is related to CSS animations and how styles are calculated during those animations.

* **`HasEmUnits`:** This test toggles the presence of `width: 1em` and checks the `HasEmUnits()` method on the computed style. This is straightforwardly testing if the `StyleResolver` correctly identifies when an element's styles use `em` units, a CSS unit.

* **`AnimationNotMaskedByImportant` / `AnimationMaskedByImportant`:** These tests introduce `!important` in CSS and check how animations interact with it. They verify that animations *can* override normal styles but are overridden by `!important`. This directly relates to CSS specificity and the `!important` keyword's behavior.

* **`BackgroundImageFetch`:** This is a more complex test. It sets up various scenarios involving `display: none`, `visibility: hidden`, `display: contents`, pseudo-elements, and framesets. It then checks if the `StyleResolver` marks background images as "pending" (meaning they haven't been fetched yet). The expectations are that images in `display: none` elements or certain pseudo-elements are *not* fetched immediately, while images in visible elements *are*. This is tied to browser optimization: don't waste resources fetching images that aren't currently visible.

**4. Identifying Relationships with Web Technologies:**

As each test is analyzed, the connection to HTML, CSS, and JavaScript becomes apparent:

* **HTML:**  The tests manipulate the DOM structure using methods like `setInnerHTML` and `createElement`. The tests are fundamentally about applying styles to HTML elements.
* **CSS:** The tests directly use CSS properties (`display`, `font-size`, `width`, `height`, `background-image`, etc.) and concepts like specificity (`!important`), units (`em`, `px`), selectors (IDs, pseudo-elements), and animations.
* **JavaScript (Indirectly):** While the tests are in C++, they are testing the engine that *interprets* and *applies* CSS, often triggered by JavaScript actions or DOM manipulations. The presence of `mojom` suggests inter-process communication, potentially related to JavaScript's interaction with the rendering engine.

**5. Inferring Logical Reasoning and Input/Output:**

For each test, consider:

* **Input:** The HTML structure and CSS rules defined in the test.
* **Process:** The `StyleResolver`'s logic being tested (how it calculates styles).
* **Output:** The computed style of the target element and the assertions made about its properties.

For example, in `StyleForTextInDisplayNone`, the input is HTML with `display: none`. The `StyleResolver` processes this. The expected output is that calling `StyleForText` returns `nullptr`.

**6. Considering User/Programming Errors:**

Think about what common mistakes developers might make that these tests could catch:

* **Misunderstanding CSS Specificity:** The `!important` tests directly address this.
* **Incorrectly assuming styles apply to `display: none` elements:**  `StyleForTextInDisplayNone` highlights this.
* **Not understanding how animations interact with existing styles:** The animation tests cover this.
* **Overlooking the performance implications of fetching resources for hidden elements:** `BackgroundImageFetch` touches on this.

**7. Tracing User Actions (Debugging Context):**

Imagine a developer debugging a styling issue. How might they end up looking at `style_resolver_test.cc`?

* **Seeing unexpected styling:** A user might notice an element isn't styled as expected.
* **Investigating CSS rules:** They might use browser developer tools to inspect the applied styles.
* **Suspecting a rendering engine bug:** If the dev tools show the correct CSS but the rendering is wrong, they might suspect a bug in Blink's style resolution logic.
* **Searching Chromium source code:** They might search for keywords related to style resolution, CSS properties, or specific bugs, potentially leading them to these tests. The tests serve as both documentation and a way to verify the engine's correctness.

**8. Summarizing Functionality (for Part 1):**

Finally, after analyzing several tests, synthesize the overall purpose of the file. Focus on the key responsibilities of the `StyleResolver` that are being tested:

* Calculating the final styles of elements based on CSS rules.
* Handling CSS specificity and the `!important` keyword.
* Managing styles during animations and transitions.
* Optimizing resource loading (e.g., for background images).
* Handling different display types (`none`, `contents`).
* Managing styles for pseudo-elements.
*  Possibly handling styles in specific contexts like printing (`@page`).

**Self-Correction/Refinement:**

During the analysis, I might initially focus too much on the individual tests. It's important to step back and see the bigger picture: what are the core responsibilities of the `StyleResolver` being validated across these tests?  Also, consider the audience of this analysis – someone who might not be deeply familiar with the Blink engine. Therefore, clear explanations of the web technology connections are essential.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation_test_helpers.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/style/anchor_specifier_value.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

using animation_test_helpers::CreateSimpleKeyframeEffectForTest;

class StyleResolverTest : public PageTestBase {
 protected:
  const ComputedStyle* StyleForId(
      const char* id,
      StyleRecalcContext style_recalc_context = {}) {
    Element* element = GetElementById(id);
    style_recalc_context.old_style = element->GetComputedStyle();
    const auto* style = GetStyleEngine().GetStyleResolver().ResolveStyle(
        element, style_recalc_context);
    DCHECK(style);
    return style;
  }

  String ComputedValue(String name, const ComputedStyle& style) {
    CSSPropertyRef ref(name, GetDocument());
    DCHECK(ref.IsValid());
    return ref.GetProperty()
        .CSSValueFromComputedStyle(style, nullptr, false,
                                   CSSValuePhase::kComputedValue)
        ->CssText();
  }

  void MatchAllRules(StyleResolverState& state,
                     ElementRuleCollector& collector) {
    GetDocument().GetStyleEngine().GetStyleResolver().MatchAllRules(
        state, collector, false /* include_smil_properties */);
  }

  bool IsUseCounted(mojom::WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  // Access protected inset and sizing property getters
  const Length& GetTop(const ComputedStyle& style) const { return style.Top(); }
  const Length& GetBottom(const ComputedStyle& style) const {
    return style.Bottom();
  }
  const Length& GetLeft(const ComputedStyle& style) const {
    return style.Left();
  }
  const Length& GetRight(const ComputedStyle& style) const {
    return style.Right();
  }
  const Length& GetWidth(const ComputedStyle& style) const {
    return style.Width();
  }
  const Length& GetMinWidth(const ComputedStyle& style) const {
    return style.MinWidth();
  }
  const Length& GetMaxWidth(const ComputedStyle& style) const {
    return style.MaxWidth();
  }
  const Length& GetHeight(const ComputedStyle& style) const {
    return style.Height();
  }
  const Length& GetMinHeight(const ComputedStyle& style) const {
    return style.MinHeight();
  }
  const Length& GetMaxHeight(const ComputedStyle& style) const {
    return style.MaxHeight();
  }

  void UpdateStyleForOutOfFlow(Element& element, AtomicString try_name) {
    ScopedCSSName* scoped_name =
        MakeGarbageCollected<ScopedCSSName>(try_name, &GetDocument());
    StyleRulePositionTry* rule =
        GetStyleEngine().GetPositionTryRule(*scoped_name);
    CHECK(rule);
    GetStyleEngine().UpdateStyleForOutOfFlow(
        element, /* try_set */ &rule->Properties(), kNoTryTactics,
        /* anchor_evaluator */ nullptr);
  }

  size_t GetCurrentOldStylesCount() {
    return PostStyleUpdateScope::CurrentAnimationData()->old_styles_.size();
  }
};

class StyleResolverTestCQ : public StyleResolverTest {
 protected:
  StyleResolverTestCQ() = default;
};

TEST_F(StyleResolverTest, StyleForTextInDisplayNone) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <body style="display:none">Text</body>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument().body()->EnsureComputedStyle();

  ASSERT_TRUE(GetDocument().body()->GetComputedStyle());
  EXPECT_TRUE(
      GetDocument().body()->GetComputedStyle()->IsEnsuredInDisplayNone());
  EXPECT_FALSE(GetStyleEngine().GetStyleResolver().StyleForText(
      To<Text>(GetDocument().body()->firstChild())));
}

TEST_F(StyleResolverTest, AnimationBaseComputedStyle) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html { font-size: 10px; }
      body { font-size: 20px; }
      @keyframes fade { to { opacity: 0; }}
      #div { animation: fade 1s; }
    </style>
    <div id="div">Test</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  ElementAnimations& animations = div->EnsureElementAnimations();
  animations.SetAnimationStyleChange(true);

  StyleResolver& resolver = GetStyleEngine().GetStyleResolver();
  StyleRecalcContext recalc_context;
  recalc_context.old_style = div->GetComputedStyle();
  const auto* style1 = resolver.ResolveStyle(div, recalc_context);
  ASSERT_TRUE(style1);
  EXPECT_EQ(20, style1->FontSize());
  ASSERT_TRUE(style1->GetBaseComputedStyle());
  EXPECT_EQ(20, style1->GetBaseComputedStyle()->FontSize());

  // Getting style with customized parent style should not affect previously
  // produced animation base computed style.
  const ComputedStyle* parent_style =
      GetDocument().documentElement()->GetComputedStyle();
  StyleRequest style_request;
  style_request.parent_override = parent_style;
  style_request.layout_parent_override = parent_style;
  style_request.can_trigger_animations = false;
  EXPECT_EQ(
      10,
      resolver.ResolveStyle(div, recalc_context, style_request)->FontSize());
  ASSERT_TRUE(style1->GetBaseComputedStyle());
  EXPECT_EQ(20, style1->GetBaseComputedStyle()->FontSize());
  EXPECT_EQ(20, resolver.ResolveStyle(div, recalc_context)->FontSize());
}

TEST_F(StyleResolverTest, HasEmUnits) {
  GetDocument().documentElement()->setInnerHTML("<div id=div>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(StyleForId("div")->HasEmUnits());

  GetDocument().documentElement()->setInnerHTML(
      "<div id=div style='width:1em'>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(StyleForId("div")->HasEmUnits());
}

TEST_F(StyleResolverTest, BaseReusableIfFontRelativeUnitsAbsent) {
  GetDocument().documentElement()->setInnerHTML("<div id=div>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(
      div, CSSPropertyID::kFontSize, "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("font-size", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  StyleForId("div");

  StyleResolverState state(GetDocument(), *div);
  EXPECT_TRUE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_F(StyleResolverTest, AnimationNotMaskedByImportant) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kWidth,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* style = StyleForId("div");

  const CSSBitset* bitset = style->GetBaseImportantSet();
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      div->GetElementAnimations(), bitset, KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(style->GetBaseComputedStyle());
  EXPECT_FALSE(bitset && bitset->Has(CSSPropertyID::kWidth));
  EXPECT_TRUE(bitset && bitset->Has(CSSPropertyID::kHeight));
}

TEST_F(StyleResolverTest, AnimationNotMaskedWithoutElementAnimations) {
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      /* ElementAnimations */ nullptr, std::make_unique<CSSBitset>().get(),
      KeyframeEffect::kDefaultPriority));
}

TEST_F(StyleResolverTest, AnimationNotMaskedWithoutBitset) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kWidth,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  StyleForId("div");

  ASSERT_TRUE(div->GetElementAnimations());
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      div->GetElementAnimations(), /* CSSBitset */ nullptr,
      KeyframeEffect::kDefaultPriority));
}

TEST_F(StyleResolverTest, AnimationMaskedByImportant) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kHeight,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("10px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* style = StyleForId("div");

  EXPECT_TRUE(style->GetBaseComputedStyle());
  EXPECT_TRUE(style->GetBaseImportantSet());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_FALSE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_F(StyleResolverTest,
       TransitionRetargetRelativeFontSizeOnParentlessElement) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html {
        font-size: 20px;
        transition: font-size 100ms;
      }
      .adjust { font-size: 50%; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* element = GetDocument().documentElement();
  element->setAttribute(html_names::kIdAttr, AtomicString("target"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("20px", ComputedValue("font-size", *StyleForId("target")));
  ElementAnimations* element_animations = element->GetElementAnimations();
  EXPECT_FALSE(element_animations);

  // Trigger a transition with a dependency on the parent style.
  element->setAttribute(html_names::kClassAttr, AtomicString("adjust"));
  UpdateAllLifecyclePhasesForTest();
  element_animations = element->GetElementAnimations();
  EXPECT_TRUE(element_animations);
  Animation* transition = (*element_animations->Animations().begin()).key;
  EXPECT_TRUE(transition);
  EXPECT_EQ("20px", ComputedValue("font-size", *StyleForId("target")));

  // Bump the animation time to ensure a transition reversal.
  transition->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50),
                             ASSERT_NO_EXCEPTION);
  transition->pause();
  UpdateAllLifecyclePhasesForTest();
  const String before_reversal_font_size =
      ComputedValue("font-size", *StyleForId("target"));

  // Verify there is no discontinuity in the font-size on transition reversal.
  element->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_animations = element->GetElementAnimations();
  EXPECT_TRUE(element_animations);
  Animation* reverse_transition =
      (*element_animations->Animations().begin()).key;
  EXPECT_TRUE(reverse_transition);
  EXPECT_EQ(before_reversal_font_size,
            ComputedValue("font-size", *StyleForId("target")));
}

class StyleResolverFontRelativeUnitTest
    : public testing::WithParamInterface<const char*>,
      public StyleResolverTest {};

TEST_P(StyleResolverFontRelativeUnitTest,
       BaseNotReusableIfFontRelativeUnitPresent) {
  GetDocument().documentElement()->setInnerHTML(
      String::Format("<div id=div style='width:1%s'>Test</div>", GetParam()));
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  auto* effect = CreateSimpleKeyframeEffectForTest(
      div, CSSPropertyID::kFontSize, "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("50px", ComputedValue("font-size", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* computed_style = StyleForId("div");

  EXPECT_TRUE(computed_style->HasFontRelativeUnits());
  EXPECT_TRUE(computed_style->GetBaseComputedStyle());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_FALSE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_P(StyleResolverFontRelativeUnitTest,
       BaseReusableIfNoFontAffectingAnimation) {
  GetDocument().documentElement()->setInnerHTML(
      String::Format("<div id=div style='width:1%s'>Test</div>", GetParam()));
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kHeight,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("50px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* computed_style = StyleForId("div");

  EXPECT_TRUE(computed_style->HasFontRelativeUnits());
  EXPECT_TRUE(computed_style->GetBaseComputedStyle());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_TRUE(StyleResolver::CanReuseBaseComputedStyle(state));
}

INSTANTIATE_TEST_SUITE_P(All,
                         StyleResolverFontRelativeUnitTest,
                         testing::Values("em", "rem", "ex", "ch"));

namespace {

const CSSImageValue& GetBackgroundImageValue(const ComputedStyle& style) {
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyBackgroundImage(), style);

  const CSSValueList* bg_img_list = To<CSSValueList>(computed_value);

  return To<CSSImageValue>(bg_img_list->Item(0));
}

const CSSImageValue& GetBackgroundImageValue(const Element* element) {
  DCHECK(element);
  return GetBackgroundImageValue(element->ComputedStyleRef());
}

const CSSImageSetValue& GetBackgroundImageSetValue(const ComputedStyle& style) {
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyBackgroundImage(), style);

  const CSSValueList* bg_img_list = To<CSSValueList>(computed_value);

  return To<CSSImageSetValue>(bg_img_list->Item(0));
}

const CSSImageSetValue& GetBackgroundImageSetValue(const Element* element) {
  DCHECK(element);
  return GetBackgroundImageSetValue(element->ComputedStyleRef());
}

}  // namespace

TEST_F(StyleResolverTest, BackgroundImageFetch) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #none {
        display: none;
        background-image: url(img-none.png);
      }
      #inside-none {
        background-image: url(img-inside-none.png);
      }
      #none-image-set {
        display: none;
        background-image: image-set(url(img-none.png) 1x);
      }
      #hidden {
        visibility: hidden;
        background-image: url(img-hidden.png);
      }
      #inside-hidden {
        background-image: url(img-inside-hidden.png);
      }
      #contents {
        display: contents;
        background-image: url(img-contents.png);
      }
      #inside-contents-parent {
        display: contents;
        background-image: url(img-inside-contents.png);
      }
      #inside-contents {
        background-image: inherit;
      }
      #non-slotted {
        background-image: url(img-non-slotted.png);
      }
      #no-pseudo::before {
        background-image: url(img-no-pseudo.png);
      }
      #first-line::first-line {
        background-image: url(first-line.png);
      }
      #first-line-span::first-line {
        background-image: url(first-line-span.png);
      }
      #first-line-none { display: none; }
      #first-line-none::first-line {
        background-image: url(first-line-none.png);
      }
      frameset {
        display: none;
        border-color: currentColor; /* UA inherit defeats caching */
        background-image: url(frameset-none.png);
      }
    </style>
    <div id="none">
      <div id="inside-none"></div>
    </div>
    <div id="none-image-set">
    </div>
    <div id="hidden">
      <div id="inside-hidden"></div>
    </div>
    <div id="contents"></div>
    <div id="inside-contents-parent">
      <div id="inside-contents"></div>
    </div>
    <div id="host">
      <div id="non-slotted"></div>
    </div>
    <div id="no-pseudo"></div>
    <div id="first-line">XXX</div>
    <span id="first-line-span">XXX</span>
    <div id="first-line-none">XXX</div>
  )HTML");

  auto* frameset1 = GetDocument().CreateRawElement(html_names::kFramesetTag);
  auto* frameset2 = GetDocument().CreateRawElement(html_names::kFramesetTag);
  GetDocument().documentElement()->AppendChild(frameset1);
  GetDocument().documentElement()->AppendChild(frameset2);

  GetDocument()
      .getElementById(AtomicString("host"))
      ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhasesForTest();

  auto* none = GetDocument().getElementById(AtomicString("none"));
  auto* inside_none = GetDocument().getElementById(AtomicString("inside-none"));
  auto* none_image_set =
      GetDocument().getElementById(AtomicString("none-image-set"));
  auto* hidden = GetDocument().getElementById(AtomicString("hidden"));
  auto* inside_hidden =
      GetDocument().getElementById(AtomicString("inside-hidden"));
  auto* contents = GetDocument().getElementById(AtomicString("contents"));
  auto* inside_contents =
      GetDocument().getElementById(AtomicString("inside-contents"));
  auto* non_slotted = GetDocument().getElementById(AtomicString("non-slotted"));
  auto* no_pseudo = GetDocument().getElementById(AtomicString("no-pseudo"));
  auto* first_line = GetDocument().getElementById(AtomicString("first-line"));
  auto* first_line_span =
      GetDocument().getElementById(AtomicString("first-line-span"));
  auto* first_line_none =
      GetDocument().getElementById(AtomicString("first-line-none"));

  inside_none->EnsureComputedStyle();
  non_slotted->EnsureComputedStyle();
  none_image_set->EnsureComputedStyle();
  auto* before_style = no_pseudo->EnsureComputedStyle(kPseudoIdBefore);
  auto* first_line_style = first_line->EnsureComputedStyle(kPseudoIdFirstLine);
  auto* first_line_span_style =
      first_line_span->EnsureComputedStyle(kPseudoIdFirstLine);
  auto* first_line_none_style =
      first_line_none->EnsureComputedStyle(kPseudoIdFirstLine);

  ASSERT_TRUE(before_style);
  EXPECT_TRUE(GetBackgroundImageValue(*before_style).IsCachePending())
      << "No fetch for non-generated ::before";
  ASSERT_TRUE(first_line_style);
  EXPECT_FALSE(GetBackgroundImageValue(*first_line_style).IsCachePending())
      << "Fetched by layout of ::first-line";
  ASSERT_TRUE(first_line_span_style);
  EXPECT_TRUE(GetBackgroundImageValue(*first_line_span_style).IsCachePending())
      << "No fetch for inline with ::first-line";
  ASSERT_TRUE(first_line_none_style);
  EXPECT_TRUE(GetBackgroundImageValue(*first_line_none_style).IsCachePending())
      << "No fetch for display:none with ::first-line";
  EXPECT_TRUE(GetBackgroundImageValue(none
### 提示词
```
这是目录为blink/renderer/core/css/resolver/style_resolver_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_cssnumericvalue_double.h"
#include "third_party/blink/renderer/core/animation/animation_test_helpers.h"
#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_image_set_value.h"
#include "third_party/blink/renderer/core/css/css_image_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/post_style_update_scope.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/style/anchor_specifier_value.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/geometry/calculation_value.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

using animation_test_helpers::CreateSimpleKeyframeEffectForTest;

class StyleResolverTest : public PageTestBase {
 protected:
  const ComputedStyle* StyleForId(
      const char* id,
      StyleRecalcContext style_recalc_context = {}) {
    Element* element = GetElementById(id);
    style_recalc_context.old_style = element->GetComputedStyle();
    const auto* style = GetStyleEngine().GetStyleResolver().ResolveStyle(
        element, style_recalc_context);
    DCHECK(style);
    return style;
  }

  String ComputedValue(String name, const ComputedStyle& style) {
    CSSPropertyRef ref(name, GetDocument());
    DCHECK(ref.IsValid());
    return ref.GetProperty()
        .CSSValueFromComputedStyle(style, nullptr, false,
                                   CSSValuePhase::kComputedValue)
        ->CssText();
  }

  void MatchAllRules(StyleResolverState& state,
                     ElementRuleCollector& collector) {
    GetDocument().GetStyleEngine().GetStyleResolver().MatchAllRules(
        state, collector, false /* include_smil_properties */);
  }

  bool IsUseCounted(mojom::WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  // Access protected inset and sizing property getters
  const Length& GetTop(const ComputedStyle& style) const { return style.Top(); }
  const Length& GetBottom(const ComputedStyle& style) const {
    return style.Bottom();
  }
  const Length& GetLeft(const ComputedStyle& style) const {
    return style.Left();
  }
  const Length& GetRight(const ComputedStyle& style) const {
    return style.Right();
  }
  const Length& GetWidth(const ComputedStyle& style) const {
    return style.Width();
  }
  const Length& GetMinWidth(const ComputedStyle& style) const {
    return style.MinWidth();
  }
  const Length& GetMaxWidth(const ComputedStyle& style) const {
    return style.MaxWidth();
  }
  const Length& GetHeight(const ComputedStyle& style) const {
    return style.Height();
  }
  const Length& GetMinHeight(const ComputedStyle& style) const {
    return style.MinHeight();
  }
  const Length& GetMaxHeight(const ComputedStyle& style) const {
    return style.MaxHeight();
  }

  void UpdateStyleForOutOfFlow(Element& element, AtomicString try_name) {
    ScopedCSSName* scoped_name =
        MakeGarbageCollected<ScopedCSSName>(try_name, &GetDocument());
    StyleRulePositionTry* rule =
        GetStyleEngine().GetPositionTryRule(*scoped_name);
    CHECK(rule);
    GetStyleEngine().UpdateStyleForOutOfFlow(
        element, /* try_set */ &rule->Properties(), kNoTryTactics,
        /* anchor_evaluator */ nullptr);
  }

  size_t GetCurrentOldStylesCount() {
    return PostStyleUpdateScope::CurrentAnimationData()->old_styles_.size();
  }
};

class StyleResolverTestCQ : public StyleResolverTest {
 protected:
  StyleResolverTestCQ() = default;
};

TEST_F(StyleResolverTest, StyleForTextInDisplayNone) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <body style="display:none">Text</body>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  GetDocument().body()->EnsureComputedStyle();

  ASSERT_TRUE(GetDocument().body()->GetComputedStyle());
  EXPECT_TRUE(
      GetDocument().body()->GetComputedStyle()->IsEnsuredInDisplayNone());
  EXPECT_FALSE(GetStyleEngine().GetStyleResolver().StyleForText(
      To<Text>(GetDocument().body()->firstChild())));
}

TEST_F(StyleResolverTest, AnimationBaseComputedStyle) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html { font-size: 10px; }
      body { font-size: 20px; }
      @keyframes fade { to { opacity: 0; }}
      #div { animation: fade 1s; }
    </style>
    <div id="div">Test</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  ElementAnimations& animations = div->EnsureElementAnimations();
  animations.SetAnimationStyleChange(true);

  StyleResolver& resolver = GetStyleEngine().GetStyleResolver();
  StyleRecalcContext recalc_context;
  recalc_context.old_style = div->GetComputedStyle();
  const auto* style1 = resolver.ResolveStyle(div, recalc_context);
  ASSERT_TRUE(style1);
  EXPECT_EQ(20, style1->FontSize());
  ASSERT_TRUE(style1->GetBaseComputedStyle());
  EXPECT_EQ(20, style1->GetBaseComputedStyle()->FontSize());

  // Getting style with customized parent style should not affect previously
  // produced animation base computed style.
  const ComputedStyle* parent_style =
      GetDocument().documentElement()->GetComputedStyle();
  StyleRequest style_request;
  style_request.parent_override = parent_style;
  style_request.layout_parent_override = parent_style;
  style_request.can_trigger_animations = false;
  EXPECT_EQ(
      10,
      resolver.ResolveStyle(div, recalc_context, style_request)->FontSize());
  ASSERT_TRUE(style1->GetBaseComputedStyle());
  EXPECT_EQ(20, style1->GetBaseComputedStyle()->FontSize());
  EXPECT_EQ(20, resolver.ResolveStyle(div, recalc_context)->FontSize());
}

TEST_F(StyleResolverTest, HasEmUnits) {
  GetDocument().documentElement()->setInnerHTML("<div id=div>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(StyleForId("div")->HasEmUnits());

  GetDocument().documentElement()->setInnerHTML(
      "<div id=div style='width:1em'>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(StyleForId("div")->HasEmUnits());
}

TEST_F(StyleResolverTest, BaseReusableIfFontRelativeUnitsAbsent) {
  GetDocument().documentElement()->setInnerHTML("<div id=div>Test</div>");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(
      div, CSSPropertyID::kFontSize, "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("font-size", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  StyleForId("div");

  StyleResolverState state(GetDocument(), *div);
  EXPECT_TRUE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_F(StyleResolverTest, AnimationNotMaskedByImportant) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kWidth,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* style = StyleForId("div");

  const CSSBitset* bitset = style->GetBaseImportantSet();
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      div->GetElementAnimations(), bitset, KeyframeEffect::kDefaultPriority));
  EXPECT_TRUE(style->GetBaseComputedStyle());
  EXPECT_FALSE(bitset && bitset->Has(CSSPropertyID::kWidth));
  EXPECT_TRUE(bitset && bitset->Has(CSSPropertyID::kHeight));
}

TEST_F(StyleResolverTest, AnimationNotMaskedWithoutElementAnimations) {
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      /* ElementAnimations */ nullptr, std::make_unique<CSSBitset>().get(),
      KeyframeEffect::kDefaultPriority));
}

TEST_F(StyleResolverTest, AnimationNotMaskedWithoutBitset) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kWidth,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("50px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  StyleForId("div");

  ASSERT_TRUE(div->GetElementAnimations());
  EXPECT_FALSE(CSSAnimations::IsAnimatingStandardProperties(
      div->GetElementAnimations(), /* CSSBitset */ nullptr,
      KeyframeEffect::kDefaultPriority));
}

TEST_F(StyleResolverTest, AnimationMaskedByImportant) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      div {
        width: 10px;
        height: 10px !important;
      }
    </style>
    <div id=div></div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().getElementById(AtomicString("div"));

  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kHeight,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ("10px", ComputedValue("width", *StyleForId("div")));
  EXPECT_EQ("10px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* style = StyleForId("div");

  EXPECT_TRUE(style->GetBaseComputedStyle());
  EXPECT_TRUE(style->GetBaseImportantSet());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_FALSE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_F(StyleResolverTest,
       TransitionRetargetRelativeFontSizeOnParentlessElement) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html {
        font-size: 20px;
        transition: font-size 100ms;
      }
      .adjust { font-size: 50%; }
    </style>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* element = GetDocument().documentElement();
  element->setAttribute(html_names::kIdAttr, AtomicString("target"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("20px", ComputedValue("font-size", *StyleForId("target")));
  ElementAnimations* element_animations = element->GetElementAnimations();
  EXPECT_FALSE(element_animations);

  // Trigger a transition with a dependency on the parent style.
  element->setAttribute(html_names::kClassAttr, AtomicString("adjust"));
  UpdateAllLifecyclePhasesForTest();
  element_animations = element->GetElementAnimations();
  EXPECT_TRUE(element_animations);
  Animation* transition = (*element_animations->Animations().begin()).key;
  EXPECT_TRUE(transition);
  EXPECT_EQ("20px", ComputedValue("font-size", *StyleForId("target")));

  // Bump the animation time to ensure a transition reversal.
  transition->setCurrentTime(MakeGarbageCollected<V8CSSNumberish>(50),
                             ASSERT_NO_EXCEPTION);
  transition->pause();
  UpdateAllLifecyclePhasesForTest();
  const String before_reversal_font_size =
      ComputedValue("font-size", *StyleForId("target"));

  // Verify there is no discontinuity in the font-size on transition reversal.
  element->setAttribute(html_names::kClassAttr, g_empty_atom);
  UpdateAllLifecyclePhasesForTest();
  element_animations = element->GetElementAnimations();
  EXPECT_TRUE(element_animations);
  Animation* reverse_transition =
      (*element_animations->Animations().begin()).key;
  EXPECT_TRUE(reverse_transition);
  EXPECT_EQ(before_reversal_font_size,
            ComputedValue("font-size", *StyleForId("target")));
}

class StyleResolverFontRelativeUnitTest
    : public testing::WithParamInterface<const char*>,
      public StyleResolverTest {};

TEST_P(StyleResolverFontRelativeUnitTest,
       BaseNotReusableIfFontRelativeUnitPresent) {
  GetDocument().documentElement()->setInnerHTML(
      String::Format("<div id=div style='width:1%s'>Test</div>", GetParam()));
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  auto* effect = CreateSimpleKeyframeEffectForTest(
      div, CSSPropertyID::kFontSize, "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("50px", ComputedValue("font-size", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* computed_style = StyleForId("div");

  EXPECT_TRUE(computed_style->HasFontRelativeUnits());
  EXPECT_TRUE(computed_style->GetBaseComputedStyle());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_FALSE(StyleResolver::CanReuseBaseComputedStyle(state));
}

TEST_P(StyleResolverFontRelativeUnitTest,
       BaseReusableIfNoFontAffectingAnimation) {
  GetDocument().documentElement()->setInnerHTML(
      String::Format("<div id=div style='width:1%s'>Test</div>", GetParam()));
  UpdateAllLifecyclePhasesForTest();

  Element* div = GetDocument().getElementById(AtomicString("div"));
  auto* effect = CreateSimpleKeyframeEffectForTest(div, CSSPropertyID::kHeight,
                                                   "50px", "100px");
  GetDocument().Timeline().Play(effect);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ("50px", ComputedValue("height", *StyleForId("div")));

  div->SetNeedsAnimationStyleRecalc();
  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  const auto* computed_style = StyleForId("div");

  EXPECT_TRUE(computed_style->HasFontRelativeUnits());
  EXPECT_TRUE(computed_style->GetBaseComputedStyle());

  StyleResolverState state(GetDocument(), *div);
  EXPECT_TRUE(StyleResolver::CanReuseBaseComputedStyle(state));
}

INSTANTIATE_TEST_SUITE_P(All,
                         StyleResolverFontRelativeUnitTest,
                         testing::Values("em", "rem", "ex", "ch"));

namespace {

const CSSImageValue& GetBackgroundImageValue(const ComputedStyle& style) {
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyBackgroundImage(), style);

  const CSSValueList* bg_img_list = To<CSSValueList>(computed_value);

  return To<CSSImageValue>(bg_img_list->Item(0));
}

const CSSImageValue& GetBackgroundImageValue(const Element* element) {
  DCHECK(element);
  return GetBackgroundImageValue(element->ComputedStyleRef());
}

const CSSImageSetValue& GetBackgroundImageSetValue(const ComputedStyle& style) {
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyBackgroundImage(), style);

  const CSSValueList* bg_img_list = To<CSSValueList>(computed_value);

  return To<CSSImageSetValue>(bg_img_list->Item(0));
}

const CSSImageSetValue& GetBackgroundImageSetValue(const Element* element) {
  DCHECK(element);
  return GetBackgroundImageSetValue(element->ComputedStyleRef());
}

}  // namespace

TEST_F(StyleResolverTest, BackgroundImageFetch) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #none {
        display: none;
        background-image: url(img-none.png);
      }
      #inside-none {
        background-image: url(img-inside-none.png);
      }
      #none-image-set {
        display: none;
        background-image: image-set(url(img-none.png) 1x);
      }
      #hidden {
        visibility: hidden;
        background-image: url(img-hidden.png);
      }
      #inside-hidden {
        background-image: url(img-inside-hidden.png);
      }
      #contents {
        display: contents;
        background-image: url(img-contents.png);
      }
      #inside-contents-parent {
        display: contents;
        background-image: url(img-inside-contents.png);
      }
      #inside-contents {
        background-image: inherit;
      }
      #non-slotted {
        background-image: url(img-non-slotted.png);
      }
      #no-pseudo::before {
        background-image: url(img-no-pseudo.png);
      }
      #first-line::first-line {
        background-image: url(first-line.png);
      }
      #first-line-span::first-line {
        background-image: url(first-line-span.png);
      }
      #first-line-none { display: none; }
      #first-line-none::first-line {
        background-image: url(first-line-none.png);
      }
      frameset {
        display: none;
        border-color: currentColor; /* UA inherit defeats caching */
        background-image: url(frameset-none.png);
      }
    </style>
    <div id="none">
      <div id="inside-none"></div>
    </div>
    <div id="none-image-set">
    </div>
    <div id="hidden">
      <div id="inside-hidden"></div>
    </div>
    <div id="contents"></div>
    <div id="inside-contents-parent">
      <div id="inside-contents"></div>
    </div>
    <div id="host">
      <div id="non-slotted"></div>
    </div>
    <div id="no-pseudo"></div>
    <div id="first-line">XXX</div>
    <span id="first-line-span">XXX</span>
    <div id="first-line-none">XXX</div>
  )HTML");

  auto* frameset1 = GetDocument().CreateRawElement(html_names::kFramesetTag);
  auto* frameset2 = GetDocument().CreateRawElement(html_names::kFramesetTag);
  GetDocument().documentElement()->AppendChild(frameset1);
  GetDocument().documentElement()->AppendChild(frameset2);

  GetDocument()
      .getElementById(AtomicString("host"))
      ->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhasesForTest();

  auto* none = GetDocument().getElementById(AtomicString("none"));
  auto* inside_none = GetDocument().getElementById(AtomicString("inside-none"));
  auto* none_image_set =
      GetDocument().getElementById(AtomicString("none-image-set"));
  auto* hidden = GetDocument().getElementById(AtomicString("hidden"));
  auto* inside_hidden =
      GetDocument().getElementById(AtomicString("inside-hidden"));
  auto* contents = GetDocument().getElementById(AtomicString("contents"));
  auto* inside_contents =
      GetDocument().getElementById(AtomicString("inside-contents"));
  auto* non_slotted = GetDocument().getElementById(AtomicString("non-slotted"));
  auto* no_pseudo = GetDocument().getElementById(AtomicString("no-pseudo"));
  auto* first_line = GetDocument().getElementById(AtomicString("first-line"));
  auto* first_line_span =
      GetDocument().getElementById(AtomicString("first-line-span"));
  auto* first_line_none =
      GetDocument().getElementById(AtomicString("first-line-none"));

  inside_none->EnsureComputedStyle();
  non_slotted->EnsureComputedStyle();
  none_image_set->EnsureComputedStyle();
  auto* before_style = no_pseudo->EnsureComputedStyle(kPseudoIdBefore);
  auto* first_line_style = first_line->EnsureComputedStyle(kPseudoIdFirstLine);
  auto* first_line_span_style =
      first_line_span->EnsureComputedStyle(kPseudoIdFirstLine);
  auto* first_line_none_style =
      first_line_none->EnsureComputedStyle(kPseudoIdFirstLine);

  ASSERT_TRUE(before_style);
  EXPECT_TRUE(GetBackgroundImageValue(*before_style).IsCachePending())
      << "No fetch for non-generated ::before";
  ASSERT_TRUE(first_line_style);
  EXPECT_FALSE(GetBackgroundImageValue(*first_line_style).IsCachePending())
      << "Fetched by layout of ::first-line";
  ASSERT_TRUE(first_line_span_style);
  EXPECT_TRUE(GetBackgroundImageValue(*first_line_span_style).IsCachePending())
      << "No fetch for inline with ::first-line";
  ASSERT_TRUE(first_line_none_style);
  EXPECT_TRUE(GetBackgroundImageValue(*first_line_none_style).IsCachePending())
      << "No fetch for display:none with ::first-line";
  EXPECT_TRUE(GetBackgroundImageValue(none).IsCachePending())
      << "No fetch for display:none";
  EXPECT_TRUE(GetBackgroundImageValue(inside_none).IsCachePending())
      << "No fetch inside display:none";
  EXPECT_TRUE(GetBackgroundImageSetValue(none_image_set).IsCachePending(1.0f))
      << "No fetch for display:none";
  EXPECT_FALSE(GetBackgroundImageValue(hidden).IsCachePending())
      << "Fetch for visibility:hidden";
  EXPECT_FALSE(GetBackgroundImageValue(inside_hidden).IsCachePending())
      << "Fetch for inherited visibility:hidden";
  EXPECT_FALSE(GetBackgroundImageValue(contents).IsCachePending())
      << "Fetch for display:contents";
  EXPECT_FALSE(GetBackgroundImageValue(inside_contents).IsCachePending())
      << "Fetch for image inherited from display:contents";
  EXPECT_TRUE(GetBackgroundImageValue(non_slotted).IsCachePending())
      << "No fetch for element outside the flat tree";

  // Added two frameset elements to hit the MatchedPropertiesCache for the
  // second one. Frameset adjusts style to display:block in StyleAdjuster, but
  // adjustments are not run before ComputedStyle is added to the
  // MatchedPropertiesCache leaving the cached style with StylePendingImage
  // unless we also check for LayoutObjectIsNeeded in
  // StyleResolverState::LoadPendingImages.
  EXPECT_FALSE(GetBackgroundImageValue(frameset1).IsCachePending())
      << "Fetch for display:none frameset";
  EXPECT_FALSE(GetBackgroundImageValue(frameset2).IsCachePending())
      << "Fetch for display:none frameset - cached";
}

TEST_F(StyleResolverTest, FetchForAtPage) {
  // Without PageMarginBoxes enabled, only a thimbleful of properties are
  // supported, and background-image is not one of them.
  ScopedPageMarginBoxesForTest enable(true);

  // The background-image property applies in an @page context, according to
  // https://drafts.csswg.org/css-page-3/#page-property-list
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @page {
        background-image: url(bg-img.png);
      }
    </style>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const ComputedStyle* page_style =
      GetDocument().GetStyleResolver().StyleForPage(0, g_empty_atom);
  ASSERT_TRUE(page_style);
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyBackgroundImage(), *page_style);

  const CSSValueList* bg_img_list = To<CSSValueList>(computed_value);
  EXPECT_FALSE(To<CSSImageValue>(bg_img_list->Item(0)).IsCachePending());
}

TEST_F(StyleResolverTest, NoFetchForAtPage) {
  ScopedPageMarginBoxesForTest enable(true);

  // The list-style-image property doesn't apply in an @page context, since
  // it's not in https://drafts.csswg.org/css-page-3/#page-property-list
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      @page {
        list-style-image: url(bg-img.png);
      }
    </style>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const ComputedStyle* page_style =
      GetDocument().GetStyleResolver().StyleForPage(0, g_empty_atom);
  ASSERT_TRUE(page_style);
  const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
      GetCSSPropertyListStyleImage(), *page_style);
  const auto* keyword = DynamicTo<CSSIdentifierValue>(computed_value);
  ASSERT_TRUE(keyword);
  EXPECT_EQ(keyword->GetValueID(), CSSValueID::kNone);
}

// The computed style for a page context isn't web-exposed, so here's a unit
// test for it. See https://drafts.csswg.org/css-page-3/#page-property-list for
// applicable properties within a page context.
TEST_F(StyleResolverTest, PageComputedStyle) {
  ScopedPageMarginBoxesForTest enable(true);

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html {
        font-size: 32px;
        margin: 66px;
        width: 123px;
      }
      body {
        /* Note: @page inherits from html, but not body. */
        font-size: 13px;
        margin: 13px;
      }
      @page {
        size: 100px 150px;
        margin: inherit;
        margin-top: 11px;
        margin-inline-end: 12px;
        page-orientation: rotate-left;
        padding-top: 7px;
        line-height: 2em;
        font-family: cursive,fantasy,monospace,sans-serif,serif,UnquotedFont,"QuotedFont\",";

        /* Non-applicable properties will be ignored. */
        columns: 100px 7;
        column-gap: 13px;
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const ComputedStyle* style =
      GetDocument().GetStyleResolver().StyleForPage(0, g_empty_atom);
  ASSERT_TRUE(style);

  EXPECT_EQ(style->GetPageSizeType(), PageSizeType::kFixed);
  gfx::SizeF page_size = style->PageSize();
  EXPECT_EQ(page_size.width(), 100);
  EXPECT_EQ(page_size.height(), 150);

  EXPECT_EQ(style->MarginTop(), Length::Fixed(11));
  EXPECT_EQ(style->MarginRight(), Length::Fixed(12));
  EXPECT_EQ(style->MarginBottom(), Length::Fixed(66));
  EXPECT_EQ(style->MarginLeft(), Length::Fixed(66));
  EXPECT_EQ(style->GetPageOrientation(), PageOrientation::kRotateLeft);

  EXPECT_EQ(style->PaddingTop(), Length::Fixed(7));

  EXPECT_EQ(style->Width(), Length::Auto());

  EXPECT_EQ(style->LineHeight(), Length::Fixed(64));
  EXPECT_EQ(style->FontSize(), 32);
  String font_family = ComputedStyleUtils::ValueForFontFamily(
                           style->GetFontDescription().Family())
                           ->CssText();
  EXPECT_EQ(
      font_family,
      R"(cursive, fantasy, monospace, sans-serif, serif, UnquotedFont, "QuotedFont\",")");

  // Non-applicable properties:
  EXPECT_TRUE(style->HasAutoColumnCount());
  EXPECT_TRUE(style->HasAutoColumnWidth());
  EXPECT_FALSE(style->ColumnGap().has_value());
}

TEST_F(StyleResolverTest, PageComputedStyleLimited) {
  ScopedPageMarginBoxesForTest enable(false);

  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      html {
        margin: 77px;
      }
      body {
        /* Note: @page inherits from html, but not body. */
        margin: 13px;
      }
      @page {
        size: 100px 150px;
        margin: inherit;
        margin-top: 11px;
        margin-inline-end: 12px;
        page-orientation: rotate-left;
        padding-top: 7px;
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const ComputedStyle* style =
      GetDocument().GetStyleResolver().StyleForPage(0, g_empty_atom);
  ASSERT_TRUE(style);

  EXPECT_EQ(style->GetPageSizeType(), PageSizeType::kFixed);
  gfx::SizeF page_size = style->PageSize();
  EXPECT_EQ(page_size.width(), 100);
  EXPECT_EQ(page_size.height(), 150);

  EXPECT_EQ(style->MarginTop(), Length::Fixed(11));
  EXPECT_EQ(style->MarginRight(), Length::Fixed(12));
  EXPECT_EQ(style->MarginBottom(), Length::Fixed(77));
  EXPECT_EQ(style->MarginLeft(), Length::Fixed(77));
  EXPECT_EQ(style->GetPageOrientation(), PageOrientation::kRotateLeft);

  // The padding-top declaration should be ignored.
  EXPECT_EQ(style->PaddingTop(), Length::Fixed(0));
}

TEST_F(StyleResolverTest, NoFetchForHighlightPseudoElements) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body::target-text, body::selection {
        color: green;
        background-image: url(bg-img.png);
        cursor: url(cursor.ico), auto;
      }
    </style>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  auto* body = GetDocument().body();
  ASSERT_TRUE(body);
  const auto* element_style = body->GetComputedStyle();
  ASSERT_TRUE(element_style);

  StyleRequest pseudo_style_request;
  pseudo_style_request.parent_override = element_style;
  pseudo_style_request.layout_parent_override = element_style;
  pseudo_style_request.originating_element_style = element_style;

  StyleRequest target_text_style_request = pseudo_style_request;
  target_text_style_request.pseudo_id = kPseudoIdTargetText;

  const ComputedStyle* target_text_style =
      GetDocument().GetStyleResolver().ResolveStyle(GetDocument().body(),
                                                    StyleRecalcContext(),
                                                    target_text_style_request);
  ASSERT_TRUE(target_text_style);

  StyleRequest selection_style_style_request = pseudo_style_request;
  selection_style_style_request.pseudo_id = kPseudoIdSelection;

  const ComputedStyle* selection_style =
      GetDocument().GetStyleResolver().ResolveStyle(
          GetDocument().body(), StyleRecalcContext(),
          selection_style_style_request);
  ASSERT_TRUE(selection_style);

  // Check that the cursor does not apply to ::selection.
  ASSERT_FALSE(selection_style->Cursors());

  // Check that the cursor does not apply to ::target-text.
  ASSERT_FALSE(target_text_style->Cursors());

  // Check that we don't fetch the cursor url() for ::target-text.
  CursorList* cursor_list = target_text_style->Cursors();
  ASSERT_FALSE(cursor_list);

  for (const auto* pseudo_style : {target_text_style, selection_style}) {
    // Check that the color applies.
    EXPECT_EQ(Color(0, 128, 0),
              pseudo_style->VisitedDependentColor(GetCSSPropertyColor()));

    // Check that the background-image does not apply.
    const CSSValue* computed_value = ComputedStyleUtils::ComputedPropertyValue(
        GetCSSPropertyBackgroundImage(), *pseudo_style);
    const CSSValueList* list = DynamicTo<CSSValueList>(computed_value);
    ASSERT_TRUE(list);
    ASSERT_EQ(1u, list->length());
    const auto* keyword = DynamicTo<CSSIdentifierValue>(list->Item(0));
    ASSERT_TRUE(keyword);
    EXPECT_EQ(CSSValueID::kNone, keyword->GetValueID());
  }
}

TEST_F(StyleResolverTest, CSSMarkerPseudoElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      b::before {
        content: "[before]";
        display: list-item;
      }
      #marker ::marker {
        color: blue;
      }
      #before-marker ::before::marker {
        color: blue;
      }
    </style>
    <ul>
      <li style="list-style: decimal outside"><b></b></li>
      <li style="list-style: decimal inside"><b></b></li>
      <li style="list-style: disc outside"><b></b></li>
      <li style="l
```