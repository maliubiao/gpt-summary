Response:
The user wants to understand the functionality of the `style_engine_test.cc` file in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose of the file:** The name `style_engine_test.cc` strongly suggests that this file contains tests for the `StyleEngine` class.

2. **Analyze the includes:** The included headers provide clues about the functionalities being tested. Look for key CSS-related classes like `StyleEngine`, `CSSStyleSheet`, `CSSRuleList`, `ComputedStyle`, `StyleResolver`, etc. Also note testing-related includes like `gtest/gtest.h`.

3. **Examine the test structure:** Look for the use of `TEST_F` macros, which indicate individual test cases. Analyze the names of these test cases (even though they are not fully shown in this excerpt, the initial ones like `DocumentDirtyAfterInject` and `AnalyzedInject` are visible and indicative).

4. **Connect to web technologies:**  Relate the tested functionalities to core web technologies like HTML, CSS, and potentially JavaScript (for dynamic styling).

5. **Infer user interaction and debugging:**  Consider how the functionalities being tested relate to user actions on a web page and how a developer might use these tests for debugging.

6. **Address specific instructions:**  Ensure that the answer covers the relationship with JavaScript, HTML, and CSS, provides examples, discusses user errors, and explains how a user might reach this code.这是 `blink/renderer/core/css/style_engine_test.cc` 文件的第一部分，它的主要功能是为 Blink 渲染引擎中的 `StyleEngine` 类编写单元测试。`StyleEngine` 负责处理 CSS 样式，并将这些样式应用于 DOM 树中的元素。

**归纳一下它的功能：**

这个文件的主要功能是 **测试 `StyleEngine` 类的各项功能，确保其能正确地解析、应用和管理 CSS 样式。**  它通过创建不同的场景和条件，验证 `StyleEngine` 在各种情况下的行为是否符合预期。

**与 Javascript, HTML, CSS 的功能关系以及举例说明：**

`StyleEngine` 处于 Web 浏览器渲染流程的核心位置，它直接关联着 HTML 结构和 CSS 样式，并且会受到 Javascript 的动态操作的影响。这个测试文件通过模拟各种 HTML 结构、CSS 规则以及 Javascript 的操作，来测试 `StyleEngine` 的正确性。

* **HTML:**  测试文件中会创建各种 HTML 元素和文档结构，例如 `<div>`, `<style>`,  `<span>` 等，用来测试 `StyleEngine` 如何根据 HTML 结构应用 CSS 规则。
    * **举例:**  可以看到代码中使用了 `GetDocument().body()->setInnerHTML(R"HTML(...)HTML");` 来动态创建 HTML 结构，然后针对这些结构中的元素进行 CSS 样式的验证。

* **CSS:**  测试文件中会定义各种 CSS 规则，包括选择器、属性、属性值等，用来测试 `StyleEngine` 如何解析和应用这些规则。
    * **举例:** 代码中使用了 `parsed_sheet->ParseString("div {}");`  来创建一个简单的 CSS 规则，并用 `GetStyleEngine().InjectSheet()` 将其注入到 `StyleEngine` 中进行测试。  还测试了 `@font-face`, `@keyframes`, 媒体查询 (`@media`)，自定义属性 (`--`) 等高级 CSS 特性。

* **Javascript:**  虽然这个文件的主要目的是测试 `StyleEngine` 本身，但 `StyleEngine` 的行为会受到 Javascript 的影响。  例如，Javascript 可以动态修改元素的 style 属性，或者动态添加/删除 `<style>` 标签。  虽然在这个文件中没有直接展示 Javascript 代码，但可以推断出，`StyleEngine` 的测试会考虑到 Javascript 的这些动态操作。
    * **推测的测试场景:**  可能会有测试用例模拟 Javascript 动态修改元素的 `style` 属性，然后验证 `StyleEngine` 能否正确地更新元素的计算样式。

**逻辑推理，假设输入与输出：**

假设一个测试用例的输入是一个包含以下内容的 HTML 字符串和一个 CSS 字符串：

**假设输入:**

* **HTML:** `<div id='test-div' class='red-text'>Hello</div>`
* **CSS:** `.red-text { color: red; }`

**逻辑推理:**  `StyleEngine` 会解析 CSS，找到与 ID 为 `test-div` 且 class 为 `red-text` 的元素匹配的规则，并将 `color` 属性设置为 `red`。

**预期输出:**

* `GetDocument().getElementById("test-div")->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor())`  应该返回代表红色的颜色值。

**涉及用户或者编程常见的使用错误，举例说明：**

这个测试文件通过各种测试用例，可以帮助发现和预防用户或开发者在使用 CSS 时可能遇到的错误，以及 Blink 引擎在处理这些错误时的行为。

* **CSS 语法错误:**  测试用例可能会故意包含一些 CSS 语法错误，例如不完整的属性值 (如代码中 `section div#t1 { color:rgb(0`)，来验证 `StyleEngine` 如何处理这些错误，是忽略该规则还是有其他行为。

* **选择器优先级问题:**  测试用例会设计具有不同选择器优先级的 CSS 规则，来验证 `StyleEngine` 是否按照 CSS 规范正确地应用样式。例如，测试 `!important` 规则的覆盖行为。

* **级联和继承问题:**  测试用例会创建包含嵌套元素的 HTML 结构，并定义相应的 CSS 规则，验证 `StyleEngine` 是否正确处理样式的级联和继承。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

通常情况下，普通用户不会直接与这个 C++ 代码文件交互。这个文件是 Blink 引擎的内部测试代码。但是，用户在浏览器中的操作会触发 Blink 引擎的 CSS 处理流程，间接地与 `StyleEngine` 发生关系。  当出现 CSS 样式问题时，开发者可能会需要查看相关的 Blink 源代码进行调试。

**调试线索:**

1. **用户报告样式问题:** 用户在浏览网页时发现某些元素的样式显示不正确。
2. **开发者检查 CSS:**  开发者首先会检查网页的 CSS 代码，确认 CSS 规则本身没有错误。
3. **浏览器开发者工具:** 开发者可能会使用浏览器开发者工具（例如 Chrome 的开发者工具）来查看元素的计算样式，以及哪些 CSS 规则在起作用。
4. **Blink 渲染流程分析:** 如果开发者工具无法直接定位问题，怀疑是 Blink 引擎的 CSS 处理逻辑错误，可能会开始分析 Blink 的渲染流程。
5. **`StyleEngine` 成为怀疑对象:**  由于 `StyleEngine` 负责 CSS 样式的计算和应用，它很可能成为开发者重点关注的模块。
6. **查看 `style_engine_test.cc`:**  为了理解 `StyleEngine` 的工作原理，或者排查潜在的 bug，开发者可能会查看 `style_engine_test.cc` 文件中的测试用例，了解 `StyleEngine` 在各种情况下的预期行为。  这些测试用例可以提供关于 `StyleEngine` 如何处理特定 CSS 场景的线索。
7. **运行或修改测试用例:** 开发者可能会运行相关的测试用例，或者根据遇到的 bug 场景修改或添加新的测试用例，以复现和修复问题。

总而言之，`style_engine_test.cc` 虽然不是用户直接接触的代码，但它是保证 Blink 引擎 CSS 处理正确性的关键组成部分，对于开发者理解和调试 CSS 相关问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/style_engine.h"

#include <algorithm>
#include <limits>
#include <memory>

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/css/forced_colors.h"
#include "third_party/blink/public/common/css/navigation_controls.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/platform/web_theme_engine.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_shadow_root_init.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/cascade_layer.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/counter_style.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/media_query_list.h"
#include "third_party/blink/renderer/core/css/media_query_list_listener.h"
#include "third_party/blink/renderer/core/css/media_query_matcher.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_stats.h"
#include "third_party/blink/renderer/core/css/style_scope_frame.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/first_letter_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scriptable_document_parser.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/viewport_data.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/list/list_marker.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/page/viewport_description.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "ui/base/mojom/window_show_state.mojom-blink.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

class StyleEngineTest : public PageTestBase {
 protected:
  bool IsDocumentStyleSheetCollectionClean() {
    return !GetStyleEngine().ShouldUpdateDocumentStyleSheetCollection();
  }

  void ApplyRuleSetInvalidation(TreeScope&, const String& css_text);

  // A wrapper to add a reason for UpdateAllLifecyclePhases
  void UpdateAllLifecyclePhases() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  Node* GetStyleRecalcRoot() {
    return GetStyleEngine().style_recalc_root_.GetRootNode();
  }

  const CSSValue* ComputedValue(Element* element, String property_name) {
    CSSPropertyRef ref(property_name, GetDocument());
    DCHECK(ref.IsValid());
    return ref.GetProperty().CSSValueFromComputedStyle(
        element->ComputedStyleRef(),
        /* layout_object */ nullptr,
        /* allow_visited_style */ false, CSSValuePhase::kResolvedValue);
  }

  void InjectSheet(String key, WebCssOrigin origin, String text) {
    auto* context = MakeGarbageCollected<CSSParserContext>(GetDocument());
    auto* sheet = MakeGarbageCollected<StyleSheetContents>(context);
    sheet->ParseString(text);
    GetStyleEngine().InjectSheet(StyleSheetKey(key), sheet, origin);
  }

  bool IsUseCounted(mojom::WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  void ClearUseCounter(mojom::WebFeature feature) {
    GetDocument().ClearUseCounterForTesting(feature);
    DCHECK(!IsUseCounted(feature));
  }

  String GetListMarkerText(LayoutObject* list_item) {
    LayoutObject* marker = ListMarker::MarkerFromListItem(list_item);
    return ListMarker::Get(marker)->GetTextChild(*marker).TransformedText();
  }

  size_t FillOrClipPathCacheSize() {
    return GetStyleEngine().fill_or_clip_path_uri_value_cache_.size();
  }

  void SimulateFrame() {
    auto new_time = GetAnimationClock().CurrentTime() + base::Milliseconds(100);
    GetPage().Animator().ServiceScriptedAnimations(new_time);
  }

  std::unique_ptr<DummyPageHolder> DummyPageHolderWithHTML(String html) {
    auto holder = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
    holder->GetDocument().documentElement()->setInnerHTML(html);
    holder->GetDocument().View()->UpdateAllLifecyclePhasesForTest();
    return holder;
  }
};

class StyleEngineContainerQueryTest : public StyleEngineTest {};

void StyleEngineTest::ApplyRuleSetInvalidation(TreeScope& tree_scope,
                                               const String& css_text) {
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(
          kHTMLStandardMode, SecureContextMode::kInsecureContext));
  sheet->ParseString(css_text);
  HeapHashSet<Member<RuleSet>> rule_sets;
  RuleSet& rule_set =
      sheet->EnsureRuleSet(MediaQueryEvaluator(GetDocument().GetFrame()));
  rule_set.CompactRulesIfNeeded();
  rule_sets.insert(&rule_set);
  SelectorFilter selector_filter;
  selector_filter.PushAllParentsOf(tree_scope);
  StyleScopeFrame style_scope_frame(
      IsA<ShadowRoot>(tree_scope)
          ? To<ShadowRoot>(tree_scope).host()
          : *tree_scope.GetDocument().documentElement());
  GetStyleEngine().ApplyRuleSetInvalidationForTreeScope(
      tree_scope, tree_scope.RootNode(), selector_filter, style_scope_frame,
      rule_sets, /*changed_rule_flags=*/0);
}

TEST_F(StyleEngineTest, DocumentDirtyAfterInject) {
  auto* parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  parsed_sheet->ParseString("div {}");
  GetStyleEngine().InjectSheet(g_empty_atom, parsed_sheet);
  EXPECT_FALSE(IsDocumentStyleSheetCollectionClean());
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsDocumentStyleSheetCollectionClean());
}

TEST_F(StyleEngineTest, AnalyzedInject) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
     @font-face {
      font-family: 'Cool Font';
      src: url(dummy);
      font-weight: bold;
     }
     :root {
      --stop-color: black !important;
      --go-color: white;
     }
     #t1 { color: red !important }
     #t2 { color: black }
     #t4 { font-family: 'Cool Font'; font-weight: bold; font-style: italic }
     #t5 { animation-name: dummy-animation }
     #t6 { color: var(--stop-color); }
     #t7 { color: var(--go-color); }
     .red { color: red; }
     #t11 { color: white; }
    </style>
    <div id='t1'>Green</div>
    <div id='t2'>White</div>
    <div id='t3' style='color: black !important'>White</div>
    <div id='t4'>I look cool.</div>
    <div id='t5'>I animate!</div>
    <div id='t6'>Stop!</div>
    <div id='t7'>Go</div>
    <div id='t8' style='color: white !important'>screen: Red; print: Black</div>
    <div id='t9' class='red'>Green</div>
    <div id='t10' style='color: black !important'>Black</div>
    <div id='t11'>White</div>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  Element* t3 = GetDocument().getElementById(AtomicString("t3"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t2);
  ASSERT_TRUE(t3);
  ASSERT_TRUE(t1->GetComputedStyle());
  ASSERT_TRUE(t2->GetComputedStyle());
  ASSERT_TRUE(t3->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t2->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t3->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  const unsigned initial_count = GetStyleEngine().StyleForElementCount();

  auto* green_parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  green_parsed_sheet->ParseString(
      "#t1 { color: green !important }"
      "#t2 { color: white !important }"
      "#t3 { color: white }");
  StyleSheetKey green_key("green");
  GetStyleEngine().InjectSheet(green_key, green_parsed_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(3u, GetStyleEngine().StyleForElementCount() - initial_count);

  ASSERT_TRUE(t1->GetComputedStyle());
  ASSERT_TRUE(t2->GetComputedStyle());
  ASSERT_TRUE(t3->GetComputedStyle());

  // Important user rules override both regular and important author rules.
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t2->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t3->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* blue_parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  blue_parsed_sheet->ParseString(
      "#t1 { color: blue !important }"
      "#t2 { color: silver }"
      "#t3 { color: silver !important }");
  StyleSheetKey blue_key("blue");
  GetStyleEngine().InjectSheet(blue_key, blue_parsed_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(6u, GetStyleEngine().StyleForElementCount() - initial_count);

  ASSERT_TRUE(t1->GetComputedStyle());
  ASSERT_TRUE(t2->GetComputedStyle());
  ASSERT_TRUE(t3->GetComputedStyle());

  // Only important user rules override previously set important user rules.
  EXPECT_EQ(
      Color::FromRGB(0, 0, 255),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t2->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  // Important user rules override inline author rules.
  EXPECT_EQ(
      Color::FromRGB(192, 192, 192),
      t3->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(green_key, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(9u, GetStyleEngine().StyleForElementCount() - initial_count);
  ASSERT_TRUE(t1->GetComputedStyle());
  ASSERT_TRUE(t2->GetComputedStyle());
  ASSERT_TRUE(t3->GetComputedStyle());

  // Regular user rules do not override author rules.
  EXPECT_EQ(
      Color::FromRGB(0, 0, 255),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t2->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(192, 192, 192),
      t3->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(blue_key, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(12u, GetStyleEngine().StyleForElementCount() - initial_count);
  ASSERT_TRUE(t1->GetComputedStyle());
  ASSERT_TRUE(t2->GetComputedStyle());
  ASSERT_TRUE(t3->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t2->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t3->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  // @font-face rules

  Element* t4 = GetDocument().getElementById(AtomicString("t4"));
  ASSERT_TRUE(t4);
  ASSERT_TRUE(t4->GetComputedStyle());

  // There's only one font and it's bold and normal.
  EXPECT_EQ(1u, GetStyleEngine()
                    .GetFontSelector()
                    ->GetFontFaceCache()
                    ->GetNumSegmentedFacesForTesting());
  CSSSegmentedFontFace* font_face =
      GetStyleEngine().GetFontSelector()->GetFontFaceCache()->Get(
          t4->GetComputedStyle()->GetFontDescription(),
          AtomicString("Cool Font"));
  EXPECT_TRUE(font_face);
  FontSelectionCapabilities capabilities =
      font_face->GetFontSelectionCapabilities();
  ASSERT_EQ(capabilities.weight,
            FontSelectionRange({kBoldWeightValue, kBoldWeightValue}));
  ASSERT_EQ(capabilities.slope,
            FontSelectionRange({kNormalSlopeValue, kNormalSlopeValue}));

  auto* font_face_parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  font_face_parsed_sheet->ParseString(
      "@font-face {"
      " font-family: 'Cool Font';"
      " src: url(dummy);"
      " font-weight: bold;"
      " font-style: italic;"
      "}");
  StyleSheetKey font_face_key("font_face");
  GetStyleEngine().InjectSheet(font_face_key, font_face_parsed_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  // After injecting a more specific font, now there are two and the
  // bold-italic one is selected.
  EXPECT_EQ(2u, GetStyleEngine()
                    .GetFontSelector()
                    ->GetFontFaceCache()
                    ->GetNumSegmentedFacesForTesting());
  font_face = GetStyleEngine().GetFontSelector()->GetFontFaceCache()->Get(
      t4->GetComputedStyle()->GetFontDescription(), AtomicString("Cool Font"));
  EXPECT_TRUE(font_face);
  capabilities = font_face->GetFontSelectionCapabilities();
  ASSERT_EQ(capabilities.weight,
            FontSelectionRange({kBoldWeightValue, kBoldWeightValue}));
  ASSERT_EQ(capabilities.slope,
            FontSelectionRange({kItalicSlopeValue, kItalicSlopeValue}));

  auto* style_element = MakeGarbageCollected<HTMLStyleElement>(GetDocument());
  style_element->setInnerHTML(
      "@font-face {"
      " font-family: 'Cool Font';"
      " src: url(dummy);"
      " font-weight: normal;"
      " font-style: italic;"
      "}");
  GetDocument().body()->AppendChild(style_element);
  UpdateAllLifecyclePhases();

  // Now there are three fonts, but the newest one does not override the older,
  // better matching one.
  EXPECT_EQ(3u, GetStyleEngine()
                    .GetFontSelector()
                    ->GetFontFaceCache()
                    ->GetNumSegmentedFacesForTesting());
  font_face = GetStyleEngine().GetFontSelector()->GetFontFaceCache()->Get(
      t4->GetComputedStyle()->GetFontDescription(), AtomicString("Cool Font"));
  EXPECT_TRUE(font_face);
  capabilities = font_face->GetFontSelectionCapabilities();
  ASSERT_EQ(capabilities.weight,
            FontSelectionRange({kBoldWeightValue, kBoldWeightValue}));
  ASSERT_EQ(capabilities.slope,
            FontSelectionRange({kItalicSlopeValue, kItalicSlopeValue}));

  GetStyleEngine().RemoveInjectedSheet(font_face_key, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  // After removing the injected style sheet we're left with a bold-normal and
  // a normal-italic font, and the latter is selected by the matching algorithm
  // as font-style trumps font-weight.
  EXPECT_EQ(2u, GetStyleEngine()
                    .GetFontSelector()
                    ->GetFontFaceCache()
                    ->GetNumSegmentedFacesForTesting());
  font_face = GetStyleEngine().GetFontSelector()->GetFontFaceCache()->Get(
      t4->GetComputedStyle()->GetFontDescription(), AtomicString("Cool Font"));
  EXPECT_TRUE(font_face);
  capabilities = font_face->GetFontSelectionCapabilities();
  ASSERT_EQ(capabilities.weight,
            FontSelectionRange({kNormalWeightValue, kNormalWeightValue}));
  ASSERT_EQ(capabilities.slope,
            FontSelectionRange({kItalicSlopeValue, kItalicSlopeValue}));

  // @keyframes rules

  Element* t5 = GetDocument().getElementById(AtomicString("t5"));
  ASSERT_TRUE(t5);

  // There's no @keyframes rule named dummy-animation
  ASSERT_FALSE(GetStyleEngine()
                   .GetStyleResolver()
                   .FindKeyframesRule(t5, t5, AtomicString("dummy-animation"))
                   .rule);

  auto* keyframes_parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  keyframes_parsed_sheet->ParseString("@keyframes dummy-animation { from {} }");
  StyleSheetKey keyframes_key("keyframes");
  GetStyleEngine().InjectSheet(keyframes_key, keyframes_parsed_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  // After injecting the style sheet, a @keyframes rule named dummy-animation
  // is found with one keyframe.
  StyleRuleKeyframes* keyframes =
      GetStyleEngine()
          .GetStyleResolver()
          .FindKeyframesRule(t5, t5, AtomicString("dummy-animation"))
          .rule;
  ASSERT_TRUE(keyframes);
  EXPECT_EQ(1u, keyframes->Keyframes().size());

  style_element = MakeGarbageCollected<HTMLStyleElement>(GetDocument());
  style_element->setInnerHTML("@keyframes dummy-animation { from {} to {} }");
  GetDocument().body()->AppendChild(style_element);
  UpdateAllLifecyclePhases();

  // Author @keyframes rules take precedence; now there are two keyframes (from
  // and to).
  keyframes = GetStyleEngine()
                  .GetStyleResolver()
                  .FindKeyframesRule(t5, t5, AtomicString("dummy-animation"))
                  .rule;
  ASSERT_TRUE(keyframes);
  EXPECT_EQ(2u, keyframes->Keyframes().size());

  GetDocument().body()->RemoveChild(style_element);
  UpdateAllLifecyclePhases();

  keyframes = GetStyleEngine()
                  .GetStyleResolver()
                  .FindKeyframesRule(t5, t5, AtomicString("dummy-animation"))
                  .rule;
  ASSERT_TRUE(keyframes);
  EXPECT_EQ(1u, keyframes->Keyframes().size());

  GetStyleEngine().RemoveInjectedSheet(keyframes_key, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();

  // Injected @keyframes rules are no longer available once removed.
  ASSERT_FALSE(GetStyleEngine()
                   .GetStyleResolver()
                   .FindKeyframesRule(t5, t5, AtomicString("dummy-animation"))
                   .rule);

  // Custom properties

  Element* t6 = GetDocument().getElementById(AtomicString("t6"));
  Element* t7 = GetDocument().getElementById(AtomicString("t7"));
  ASSERT_TRUE(t6);
  ASSERT_TRUE(t7);
  ASSERT_TRUE(t6->GetComputedStyle());
  ASSERT_TRUE(t7->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t6->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t7->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* custom_properties_parsed_sheet =
      MakeGarbageCollected<StyleSheetContents>(
          MakeGarbageCollected<CSSParserContext>(GetDocument()));
  custom_properties_parsed_sheet->ParseString(
      ":root {"
      " --stop-color: red !important;"
      " --go-color: green;"
      "}");
  StyleSheetKey custom_properties_key("custom_properties");
  GetStyleEngine().InjectSheet(custom_properties_key,
                               custom_properties_parsed_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t6->GetComputedStyle());
  ASSERT_TRUE(t7->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t6->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t7->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(custom_properties_key,
                                       WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t6->GetComputedStyle());
  ASSERT_TRUE(t7->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t6->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t7->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  // Media queries

  Element* t8 = GetDocument().getElementById(AtomicString("t8"));
  ASSERT_TRUE(t8);
  ASSERT_TRUE(t8->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t8->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* media_queries_parsed_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  media_queries_parsed_sheet->ParseString(
      "@media screen {"
      " #t8 {"
      "  color: red !important;"
      " }"
      "}"
      "@media print {"
      " #t8 {"
      "  color: black !important;"
      " }"
      "}");
  StyleSheetKey media_queries_sheet_key("media_queries_sheet");
  GetStyleEngine().InjectSheet(media_queries_sheet_key,
                               media_queries_parsed_sheet, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t8->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t8->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  gfx::SizeF page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size));
  ASSERT_TRUE(t8->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t8->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetDocument().GetFrame()->EndPrinting();
  ASSERT_TRUE(t8->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t8->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(media_queries_sheet_key,
                                       WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t8->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t8->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  // Author style sheets

  Element* t9 = GetDocument().getElementById(AtomicString("t9"));
  Element* t10 = GetDocument().getElementById(AtomicString("t10"));
  ASSERT_TRUE(t9);
  ASSERT_TRUE(t10);
  ASSERT_TRUE(t9->GetComputedStyle());
  ASSERT_TRUE(t10->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t9->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t10->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* parsed_author_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  parsed_author_sheet->ParseString(
      "#t9 {"
      " color: green;"
      "}"
      "#t10 {"
      " color: white !important;"
      "}");
  StyleSheetKey author_sheet_key("author_sheet");
  GetStyleEngine().InjectSheet(author_sheet_key, parsed_author_sheet,
                               WebCssOrigin::kAuthor);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t9->GetComputedStyle());
  ASSERT_TRUE(t10->GetComputedStyle());

  // Specificity works within author origin.
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t9->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  // Important author rules do not override important inline author rules.
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t10->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(author_sheet_key, WebCssOrigin::kAuthor);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t9->GetComputedStyle());
  ASSERT_TRUE(t10->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t9->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t10->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  // Style sheet removal

  Element* t11 = GetDocument().getElementById(AtomicString("t11"));
  ASSERT_TRUE(t11);
  ASSERT_TRUE(t11->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* parsed_removable_red_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  parsed_removable_red_sheet->ParseString("#t11 { color: red !important; }");
  StyleSheetKey removable_red_sheet_key("removable_red_sheet");
  GetStyleEngine().InjectSheet(removable_red_sheet_key,
                               parsed_removable_red_sheet, WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* parsed_removable_green_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  parsed_removable_green_sheet->ParseString(
      "#t11 { color: green !important; }");
  StyleSheetKey removable_green_sheet_key("removable_green_sheet");
  GetStyleEngine().InjectSheet(removable_green_sheet_key,
                               parsed_removable_green_sheet,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* parsed_removable_red_sheet2 = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  parsed_removable_red_sheet2->ParseString("#t11 { color: red !important; }");
  GetStyleEngine().InjectSheet(removable_red_sheet_key,
                               parsed_removable_red_sheet2,
                               WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(removable_red_sheet_key,
                                       WebCssOrigin::kAuthor);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  // Removal works only within the same origin.
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(removable_red_sheet_key,
                                       WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  // The last sheet with the given key is removed.
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(removable_green_sheet_key,
                                       WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  // Only the last sheet with the given key is removed.
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetStyleEngine().RemoveInjectedSheet(removable_red_sheet_key,
                                       WebCssOrigin::kUser);
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(t11->GetComputedStyle());

  EXPECT_EQ(
      Color::FromRGB(255, 255, 255),
      t11->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, InjectedUserNoAuthorFontFace) {
  UpdateAllLifecyclePhases();

  FontDescription font_description;
  FontFaceCache* cache = GetStyleEngine().GetFontSelector()->GetFontFaceCache();
  EXPECT_FALSE(cache->Get(font_description, AtomicString("User")));

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(
      "@font-face {"
      "  font-family: 'User';"
      "  src: url(font.ttf);"
      "}");

  StyleSheetKey user_key("user");
  GetStyleEngine().InjectSheet(user_key, user_sheet, WebCssOrigin::kUser);

  UpdateAllLifecyclePhases();

  EXPECT_TRUE(cache->Get(font_description, AtomicString("User")));
}

TEST_F(StyleEngineTest, InjectedFontFace) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
     @font-face {
      font-family: 'Author';
      src: url(user);
     }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();

  FontDescription font_description;
  FontFaceCache* cache = GetStyleEngine().GetFontSelector()->GetFontFaceCache();
  EXPECT_TRUE(cache->Get(font_description, AtomicString("Author")));
  EXPECT_FALSE(cache->Get(font_description, AtomicString("User")));

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString(
      "@font-face {"
      "  font-family: 'User';"
      "  src: url(author);"
      "}");

  StyleSheetKey user_key("user");
  GetStyleEngine().InjectSheet(user_key, user_sheet, WebCssOrigin::kUser);

  UpdateAllLifecyclePhases();

  EXPECT_TRUE(cache->Get(font_description, AtomicString("Author")));
  EXPECT_TRUE(cache->Get(font_description, AtomicString("User")));
}

TEST_F(StyleEngineTest, IgnoreInvalidPropertyValue) {
  GetDocument().body()->setInnerHTML(
      "<section><div id='t1'>Red</div></section>"
      "<style id='s1'>div { color: red; } section div#t1 { color:rgb(0");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, TextToSheetCache) {
  auto* element = MakeGarbageCollected<HTMLStyleElement>(GetDocument());

  String sheet_text("d
"""


```