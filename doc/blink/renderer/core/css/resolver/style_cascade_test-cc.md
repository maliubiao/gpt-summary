Response:
The user wants to understand the functionality of the `style_cascade_test.cc` file in the Chromium Blink engine. They are particularly interested in its relation to JavaScript, HTML, and CSS, and want examples of logic reasoning, potential user/programming errors, and how a user's action might lead to this code being executed.

**Plan:**

1. **Summarize the file's primary function:**  Based on the name and included headers, it's clear this file contains unit tests for the `StyleCascade` class. This class is responsible for managing and applying CSS rules to determine the final style of an element.

2. **Explain the relationship with JavaScript, HTML, and CSS:**
    *   **CSS:** The core function is directly related to CSS cascading and resolution.
    *   **HTML:** The tests operate on HTML elements and documents, simulating how CSS is applied to them.
    *   **JavaScript:**  While the tests are in C++, they indirectly relate to JavaScript as JavaScript can manipulate the DOM and CSS styles, triggering the cascade process.

3. **Provide examples of logic reasoning:** The tests themselves demonstrate logical reasoning. They set up specific CSS scenarios (inputs) and assert the expected computed styles (outputs).

4. **Illustrate user/programming errors:**  These tests help catch errors in the CSS cascade logic. I can provide examples of common CSS mistakes that these tests would help detect.

5. **Explain how a user action leads here:**  Any user interaction that causes a re-styling of a webpage can trigger this code.

6. **Summarize the functionality of the provided code snippet (part 1):** Focus on the classes defined in this part: `TestCascadeResolver`, `AddOptions`, `TestCascade`, and `TestCascadeAutoLock`. Explain their roles in the testing framework.
这是 `blink/renderer/core/css/resolver/style_cascade_test.cc` 文件的第一部分，其主要功能是**为 Blink 渲染引擎中的 `StyleCascade` 类提供单元测试**。

`StyleCascade` 类在 CSS 样式解析过程中扮演着核心角色，它负责：

*   **管理和应用不同来源的 CSS 声明** (例如，用户代理样式、用户样式、作者样式、内联样式、动画和过渡样式)。
*   **处理 CSS 声明的优先级和层叠规则**，以确定最终应用于元素的 CSS 属性值。
*   **处理 `!important` 标记**，覆盖常规的优先级规则。
*   **处理 `all` 属性**，一次性重置或修改多个 CSS 属性。
*   **处理自定义属性 (CSS variables)** 及其回退值。
*   **检测并处理 CSS 变量的循环引用**。
*   **在动画和过渡过程中应用插值**。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **CSS:**  该测试文件直接测试 CSS 的核心概念，例如优先级、层叠、`!important`、`all` 属性、自定义属性和简写属性。 例如，`TEST_F(StyleCascadeTest, ApplyImportance)` 测试用例验证了 `!important` 标记是否能覆盖普通样式的优先级。

    ```c++
    TEST_F(StyleCascadeTest, ApplyImportance) {
      TestCascade cascade(GetDocument());
      cascade.Add("width:1px !important", CascadeOrigin::kUserAgent); // 用户代理设置了 !important
      cascade.Add("width:2px", CascadeOrigin::kAuthor);             // 作者样式
      cascade.Apply();

      EXPECT_EQ("1px", cascade.ComputedValue("width")); // 预期用户代理的样式生效
    }
    ```

*   **HTML:** 测试用例操作的是 HTML 元素，模拟 CSS 如何应用于 HTML 元素。例如，`TestCascade` 类在初始化时需要一个 `Document` 和一个 `Element` 对象。

    ```c++
    TestCascade cascade(GetDocument()); // GetDocument() 返回一个 Document 对象
    ```

*   **JavaScript:** 虽然这个测试文件本身是用 C++ 编写的，但它测试的 CSS 功能直接影响 JavaScript 对 DOM 的操作和样式获取。 例如，JavaScript 可以通过 `element.style.width` 或 `getComputedStyle(element).width` 获取元素的宽度，而这些值正是 `StyleCascade` 计算的结果。  当 JavaScript 动态修改元素的样式时，也会触发 `StyleCascade` 的重新计算。

**逻辑推理的假设输入与输出举例说明:**

*   **假设输入:**
    *   一个 HTML 元素 `<div id="test"></div>`
    *   以下 CSS 规则:
        ```css
        #test {
          color: red;
        }
        .override {
          color: blue !important;
        }
        ```
    *   JavaScript 代码动态添加了 `override` 类名: `document.getElementById('test').classList.add('override');`

*   **逻辑推理 (测试用例可能模拟的场景):**  测试 `StyleCascade` 是否正确处理了 `!important` 标记的优先级。

*   **预期输出:**  该元素的计算样式 `color` 应该为 `blue`，因为带有 `!important` 标记的类选择器优先级更高。

**涉及用户或者编程常见的使用错误举例说明:**

*   **CSS 优先级理解错误:**  开发者可能错误地认为作者样式总能覆盖用户代理样式，而忽略了 `!important` 标记的影响。  例如，用户在用户样式表中设置了 `body { background-color: black !important; }`，开发者在网站的 CSS 中设置了 `body { background-color: white; }`，但最终背景仍然是黑色。 `StyleCascadeTest` 中的用例可以帮助验证这种优先级规则的正确性。

*   **CSS 变量循环引用:**  开发者可能会不小心创建 CSS 变量的循环引用，例如 `--a: var(--b); --b: var(--a);`。这会导致无限循环。 `StyleCascadeTest` 中有专门的测试用例 (`TEST_F(StyleCascadeTest, ResolverDetectCycle)`) 来检测这种循环引用。如果 `StyleCascade` 的逻辑不正确，可能会导致崩溃或者性能问题。

*   **错误地使用 `all` 属性:** 开发者可能误用 `all: initial` 或 `all: unset`，导致意外的样式重置。测试用例可以帮助确保 `all` 属性的行为符合预期。 例如，`TEST_F(StyleCascadeTest, ApplyAllImportance)` 验证了 `all` 属性在遇到 `!important` 标记时的行为。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中加载一个网页 (HTML)。**
2. **浏览器解析 HTML 结构，构建 DOM 树。**
3. **浏览器开始解析 CSS 样式表 (外部样式、`<style>` 标签、内联样式)。**
4. **对于 DOM 树中的每个元素，`StyleCascade` 类会被调用来计算其最终的样式。**
5. **`StyleCascade` 会收集来自不同来源的 CSS 声明，并根据优先级和层叠规则进行排序和应用。**
6. **如果在样式计算过程中出现错误，或者需要验证样式计算的正确性，开发者可能会编写或运行 `style_cascade_test.cc` 中的单元测试。**

   例如，开发者在调试一个关于 CSS 优先级的问题时，可能会修改 `style_cascade_test.cc` 中的现有测试用例，或者添加新的测试用例来复现和验证该问题。  当代码被提交到 Chromium 项目时，这些测试用例会被自动化运行，以确保代码的质量和稳定性。

**归纳一下它的功能 (第 1 部分):**

这部分代码定义了用于测试 `StyleCascade` 类的基础设施和一些基础的测试用例。

*   **`TestCascadeResolver` 类:**  提供了一个封装 `CascadeResolver` 的测试辅助类，用于在测试中模拟样式解析过程中的循环检测。
*   **`AddOptions` 结构体:**  定义了在向 `TestCascade` 添加 CSS 声明时可以使用的选项，例如指定来源、链接匹配类型、层叠顺序等。
*   **`TestCascade` 类:**  这是核心的测试辅助类，用于创建一个模拟的样式层叠环境。它允许添加不同来源的 CSS 声明，并执行样式层叠和解析过程。它提供了 `Add` 方法用于添加 CSS 规则，`Apply` 方法用于执行层叠计算，以及 `ComputedValue` 方法用于获取最终计算出的样式值。
*   **`TestCascadeAutoLock` 类:**  用于测试 CSS 变量循环引用检测的辅助类，模拟在解析过程中锁定和解锁 CSS 属性。
*   **`StyleCascadeTest` 类:**  继承自 `PageTestBase`，提供了创建测试页面的环境和一些辅助方法，例如创建 CSS 样式表 (`CreateSheet`) 和获取文档元素。  它包含了一系列的 `TEST_F` 宏定义的测试用例，用于验证 `StyleCascade` 类的各种功能。

总而言之，这部分代码构建了一个测试框架，允许开发者编写和运行各种场景的单元测试，以确保 `StyleCascade` 类能够正确地处理 CSS 样式的层叠和解析，保证了 Blink 渲染引擎的正确性和稳定性。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_cascade_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"

#include <vector>

#include "third_party/blink/renderer/bindings/core/v8/v8_css_style_sheet_init.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/active_style_sheets.h"
#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_initial_color_value.h"
#include "third_party/blink/renderer/core/css/css_pending_substitution_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_revert_value.h"
#include "third_party/blink/renderer/core/css/css_test_helpers.h"
#include "third_party/blink/renderer/core/css/css_unparsed_declaration_value.h"
#include "third_party/blink/renderer/core/css/document_style_environment_variables.h"
#include "third_party/blink/renderer/core/css/document_style_sheet_collection.h"
#include "third_party/blink/renderer/core/css/media_query_evaluator.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_property_instances.h"
#include "third_party/blink/renderer/core/css/properties/css_property_ref.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/longhands/custom_property.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_filter.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_interpolations.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_map.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_priority.h"
#include "third_party/blink/renderer/core/css/resolver/cascade_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/testing/color_scheme_helper.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

using css_test_helpers::ParseDeclarationBlock;
using css_test_helpers::RegisterProperty;
using Origin = CascadeOrigin;
using Priority = CascadePriority;
using UnitType = CSSPrimitiveValue::UnitType;

class TestCascadeResolver {
  STACK_ALLOCATED();

 public:
  explicit TestCascadeResolver(uint8_t generation = 0)
      : resolver_(CascadeFilter(), generation) {}
  bool InCycle() const { return resolver_.InCycle(); }
  bool DetectCycle(const CSSProperty& property) {
    return resolver_.DetectCycle(property);
  }
  wtf_size_t CycleStart() const { return resolver_.cycle_start_; }
  wtf_size_t CycleEnd() const { return resolver_.cycle_end_; }
  uint8_t GetGeneration() { return resolver_.generation_; }
  CascadeResolver& InnerResolver() { return resolver_; }
  const CSSProperty* CurrentProperty() const {
    return resolver_.CurrentProperty();
  }

 private:
  friend class TestCascadeAutoLock;

  CascadeResolver resolver_;
};

struct AddOptions {
  CascadeOrigin origin = CascadeOrigin::kAuthor;
  unsigned link_match_type = CSSSelector::kMatchAll;
  uint16_t layer_order = CascadeLayerMap::kImplicitOuterLayerOrder;
  bool is_inline_style = false;
  bool is_try_style = false;
  bool is_try_tactics_style = false;
};

class TestCascade {
  STACK_ALLOCATED();

 public:
  explicit TestCascade(Document& document,
                       Element* target = nullptr,
                       const StyleRecalcContext* style_recalc_context = nullptr)
      : state_(document,
               target ? *target : *document.body(),
               style_recalc_context),
        cascade_(InitState(state_, nullptr)) {}

  TestCascade(Document& document,
              const ComputedStyle* parent_style,
              Element* target = nullptr)
      : state_(document, target ? *target : *document.body()),
        cascade_(InitState(state_, parent_style)) {}

  const ComputedStyle* TakeStyle() { return state_.TakeStyle(); }

  StyleResolverState& State() { return state_; }
  StyleCascade& InnerCascade() { return cascade_; }

  //  Note that because of how MatchResult works, declarations must be added
  //  in "origin order", i.e. UserAgent first, then User, then Author.

  void Add(String block, AddOptions options = {}) {
    CSSParserMode mode = options.origin == CascadeOrigin::kUserAgent
                             ? kUASheetMode
                             : kHTMLStandardMode;
    Add(ParseDeclarationBlock(block, mode), options);
  }

  void Add(String block, CascadeOrigin origin) {
    Add(block, {.origin = origin});
  }

  void Add(String name, String value, CascadeOrigin origin = Origin::kAuthor) {
    Add(name + ":" + value, origin);
  }

  void Add(const CSSPropertyValueSet* set, AddOptions options = {}) {
    DCHECK_LE(options.origin, CascadeOrigin::kAuthor)
        << "Animations not supported";
    DCHECK_LE(current_origin_, options.origin)
        << "Please add declarations in order";
    EnsureAtLeast(options.origin);
    cascade_.MutableMatchResult().AddMatchedProperties(
        set,
        {
            .link_match_type = static_cast<uint8_t>(options.link_match_type),
            .is_inline_style = options.is_inline_style,
            .is_try_style = options.is_try_style,
            .origin = options.origin,
            .layer_order = options.layer_order,
            .is_try_tactics_style = options.is_try_tactics_style,
        });
  }

  void Apply(CascadeFilter filter = CascadeFilter()) {
    EnsureAtLeast(CascadeOrigin::kAnimation);
    cascade_.Apply(filter);
  }

  void ApplySingle(const CSSProperty& property) {
    EnsureAtLeast(CascadeOrigin::kAnimation);
    cascade_.AnalyzeIfNeeded();
    TestCascadeResolver resolver(++cascade_.generation_);
    cascade_.LookupAndApply(property, resolver.InnerResolver());
  }

  void AnalyzeIfNeeded() { cascade_.AnalyzeIfNeeded(); }

  const CSSValue* Resolve(const CSSProperty& property,
                          const CSSValue& value,
                          CascadeOrigin& origin) {
    TestCascadeResolver resolver;
    return cascade_.Resolve(property, value, CascadePriority(origin), origin,
                            resolver.InnerResolver());
  }

  static const CSSValue* StaticResolve(StyleResolverState& state,
                                       String name,
                                       String value) {
    const CSSPropertyValueSet* set =
        ParseDeclarationBlock(name + ":" + value, kHTMLStandardMode);
    DCHECK(set);
    DCHECK(set->PropertyCount());
    CSSPropertyValueSet::PropertyReference reference = set->PropertyAt(0);
    return StyleCascade::Resolve(state, reference.Name(), reference.Value());
  }

  std::unique_ptr<CSSBitset> GetImportantSet() {
    return cascade_.GetImportantSet();
  }

  String ComputedValue(String name) const {
    CSSPropertyRef ref(name, GetDocument());
    DCHECK(ref.IsValid());
    const LayoutObject* layout_object = nullptr;
    bool allow_visited_style = false;
    CSSValuePhase value_phase = CSSValuePhase::kResolvedValue;
    const ComputedStyle* style = state_.StyleBuilder().CloneStyle();
    const CSSValue* value = ref.GetProperty().CSSValueFromComputedStyle(
        *style, layout_object, allow_visited_style, value_phase);
    return value ? value->CssText() : g_null_atom;
  }

  CascadePriority GetPriority(String name) {
    return GetPriority(
        *CSSPropertyName::From(GetDocument().GetExecutionContext(), name));
  }

  CascadePriority* FindPriority(CSSPropertyName name) {
    return cascade_.map_.Find(name);
  }

  CascadePriority GetPriority(CSSPropertyName name) {
    CascadePriority* c = FindPriority(name);
    return c ? *c : CascadePriority();
  }

  CascadeOrigin GetOrigin(String name) { return GetPriority(name).GetOrigin(); }

  void AddInterpolations() {
    state_.StyleBuilder().SetBaseData(
        StyleBaseData::Create(state_.StyleBuilder().CloneStyle(), nullptr));

    CalculateInterpolationUpdate();

    // Add to cascade:
    const auto& update = state_.AnimationUpdate();
    if (update.IsEmpty()) {
      return;
    }

    cascade_.AddInterpolations(&update.ActiveInterpolationsForAnimations(),
                               CascadeOrigin::kAnimation);
    cascade_.AddInterpolations(&update.ActiveInterpolationsForTransitions(),
                               CascadeOrigin::kTransition);
  }

  void Reset() {
    cascade_.Reset();
    current_origin_ = CascadeOrigin::kUserAgent;
  }

  bool NeedsMatchResultAnalyze() const {
    return cascade_.needs_match_result_analyze_;
  }
  bool NeedsInterpolationsAnalyze() const {
    return cascade_.needs_interpolations_analyze_;
  }
  bool DependsOnCascadeAffectingProperty() const {
    return cascade_.depends_on_cascade_affecting_property_;
  }
  bool InlineStyleLostCascade() const { return cascade_.InlineStyleLost(); }

  HeapHashMap<CSSPropertyName, Member<const CSSValue>> GetCascadedValues()
      const {
    return cascade_.GetCascadedValues();
  }

 private:
  Document& GetDocument() const { return state_.GetDocument(); }
  Element* Body() const { return GetDocument().body(); }

  static StyleResolverState& InitState(StyleResolverState& state,
                                       const ComputedStyle* parent_style) {
    state.GetDocument().GetStyleEngine().UpdateViewportSize();
    if (parent_style) {
      state.CreateNewStyle(*InitialStyle(state.GetDocument()), *parent_style);
      state.SetParentStyle(parent_style);
    } else {
      state.SetStyle(*InitialStyle(state.GetDocument()));
      state.SetParentStyle(InitialStyle(state.GetDocument()));
    }
    state.SetOldStyle(state.GetElement().GetComputedStyle());
    return state;
  }

  static const ComputedStyle* InitialStyle(Document& document) {
    return document.GetStyleResolver().InitialStyleForElement();
  }

  void FinishOrigin() {
    switch (current_origin_) {
      case CascadeOrigin::kUserAgent:
        current_origin_ = CascadeOrigin::kUser;
        break;
      case CascadeOrigin::kUser:
        current_origin_ = CascadeOrigin::kAuthorPresentationalHint;
        break;
      case CascadeOrigin::kAuthorPresentationalHint:
        cascade_.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(
            GetDocument());
        current_origin_ = CascadeOrigin::kAuthor;
        break;
      case CascadeOrigin::kAuthor:
        current_origin_ = CascadeOrigin::kAnimation;
        break;
      case CascadeOrigin::kAnimation:
        break;
      default:
        NOTREACHED();
    }
  }

  void EnsureAtLeast(CascadeOrigin origin) {
    while (current_origin_ < origin) {
      FinishOrigin();
    }
  }

  void CalculateInterpolationUpdate() {
    CSSAnimations::CalculateTransitionUpdate(
        state_.AnimationUpdate(), state_.GetElement(), state_.StyleBuilder(),
        state_.OldStyle(), true /* can_trigger_animations */);
    CSSAnimations::CalculateAnimationUpdate(
        state_.AnimationUpdate(), state_.GetElement(), state_.GetElement(),
        state_.StyleBuilder(), state_.ParentStyle(),
        &GetDocument().GetStyleResolver(), true /* can_trigger_animations */);
  }

  CascadeOrigin current_origin_ = CascadeOrigin::kUserAgent;
  StyleResolverState state_;
  StyleCascade cascade_;
};

class TestCascadeAutoLock {
  STACK_ALLOCATED();

 public:
  TestCascadeAutoLock(const CSSProperty& property,
                      TestCascadeResolver& resolver)
      : lock_(property, resolver.resolver_) {}

 private:
  CascadeResolver::AutoLock lock_;
};

class StyleCascadeTest : public PageTestBase {
 public:
  CSSStyleSheet* CreateSheet(const String& css_text) {
    auto* init = MakeGarbageCollected<CSSStyleSheetInit>();
    DummyExceptionStateForTesting exception_state;
    CSSStyleSheet* sheet =
        CSSStyleSheet::Create(GetDocument(), init, exception_state);
    sheet->replaceSync(css_text, exception_state);
    sheet->Contents()->EnsureRuleSet(
        MediaQueryEvaluator(GetDocument().GetFrame()));
    return sheet;
  }

  void AppendSheet(const String& css_text) {
    CSSStyleSheet* sheet = CreateSheet(css_text);
    ASSERT_TRUE(sheet);

    Element* body = GetDocument().body();
    ASSERT_TRUE(body->IsInTreeScope());
    TreeScope& tree_scope = body->GetTreeScope();
    ScopedStyleResolver& scoped_resolver =
        tree_scope.EnsureScopedStyleResolver();
    ActiveStyleSheetVector active_sheets;
    active_sheets.push_back(
        std::make_pair(sheet, &sheet->Contents()->GetRuleSet()));
    scoped_resolver.AppendActiveStyleSheets(0, active_sheets);
    GetDocument()
        .GetStyleEngine()
        .GetDocumentStyleSheetCollection()
        .AppendActiveStyleSheet(active_sheets[0]);
  }

  Element* DocumentElement() const { return GetDocument().documentElement(); }

  void SetRootFont(String value) {
    DocumentElement()->SetInlineStyleProperty(CSSPropertyID::kFontSize, value);
    UpdateAllLifecyclePhasesForTest();
  }

  const MutableCSSPropertyValueSet* AnimationTaintedSet(const char* name,
                                                        String value) {
    CSSParserMode mode = kHTMLStandardMode;
    auto* set = MakeGarbageCollected<MutableCSSPropertyValueSet>(mode);
    set->ParseAndSetCustomProperty(AtomicString(name), value,
                                   /* important */ false,
                                   SecureContextMode::kSecureContext,
                                   /* context_style_sheet */ nullptr,
                                   /* is_animation_tainted */ true);
    return set;
  }

  const CSSPropertyValueSet* FlipRevertSet(String from_property,
                                           String to_property) {
    auto* set =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
    set->SetProperty(PropertyName(from_property).Id(),
                     *MakeGarbageCollected<cssvalue::CSSFlipRevertValue>(
                         PropertyName(to_property).Id(), TryTacticTransform()));
    return set;
  }

  // Temporarily create a CSS Environment Variable.
  // https://drafts.csswg.org/css-env-1/
  class AutoEnv {
    STACK_ALLOCATED();

   public:
    AutoEnv(PageTestBase& test, const char* name, String value)
        : document_(&test.GetDocument()), name_(name) {
      EnsureEnvironmentVariables().SetVariable(name_, value);
    }
    ~AutoEnv() { EnsureEnvironmentVariables().RemoveVariable(name_); }

   private:
    DocumentStyleEnvironmentVariables& EnsureEnvironmentVariables() {
      return document_->GetStyleEngine().EnsureEnvironmentVariables();
    }

    Document* document_;
    AtomicString name_;
  };

  CSSPropertyName PropertyName(String name) {
    return *CSSPropertyName::From(GetDocument().GetExecutionContext(), name);
  }

  String CssText(const CSSValue* value) {
    if (!value) {
      return g_null_atom;
    }
    return value->CssText();
  }

  String CssTextAt(
      const HeapHashMap<CSSPropertyName, Member<const CSSValue>>& map,
      String name) {
    return CssText(map.at(PropertyName(name)));
  }
};

TEST_F(StyleCascadeTest, ApplySingle) {
  TestCascade cascade(GetDocument());
  cascade.Add("width", "1px", CascadeOrigin::kUserAgent);
  cascade.Add("width", "2px", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("2px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, ApplyImportance) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:1px !important", CascadeOrigin::kUserAgent);
  cascade.Add("width:2px", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, ApplyAll) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:1px", CascadeOrigin::kUserAgent);
  cascade.Add("height:1px", CascadeOrigin::kUserAgent);
  cascade.Add("all:initial", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("auto", cascade.ComputedValue("width"));
  EXPECT_EQ("auto", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, ApplyAllImportance) {
  TestCascade cascade(GetDocument());
  cascade.Add("opacity:0.5", CascadeOrigin::kUserAgent);
  cascade.Add("display:block !important", CascadeOrigin::kUserAgent);
  cascade.Add("all:initial", CascadeOrigin::kAuthor);
  cascade.Apply();

  EXPECT_EQ("1", cascade.ComputedValue("opacity"));
  EXPECT_EQ("block", cascade.ComputedValue("display"));
}

TEST_F(StyleCascadeTest, ApplyAllWithPhysicalLonghands) {
  TestCascade cascade(GetDocument());
  cascade.Add("width:1px", CascadeOrigin::kUserAgent);
  cascade.Add("height:1px !important", CascadeOrigin::kUserAgent);
  cascade.Add("all:initial", CascadeOrigin::kAuthor);
  cascade.Apply();
  EXPECT_EQ("auto", cascade.ComputedValue("width"));
  EXPECT_EQ("1px", cascade.ComputedValue("height"));
}

TEST_F(StyleCascadeTest, ApplyCustomProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", " 10px ");
  cascade.Add("--y", "nope");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
  EXPECT_EQ("nope", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, ApplyGenerations) {
  TestCascade cascade(GetDocument());

  cascade.Add("--x:10px");
  cascade.Add("width:20px");
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
  EXPECT_EQ("20px", cascade.ComputedValue("width"));

  cascade.State().StyleBuilder().SetWidth(Length::Auto());
  cascade.State().StyleBuilder().SetVariableData(AtomicString("--x"), nullptr,
                                                 true);
  EXPECT_EQ(g_null_atom, cascade.ComputedValue("--x"));
  EXPECT_EQ("auto", cascade.ComputedValue("width"));

  // Apply again
  cascade.Apply();
  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
  EXPECT_EQ("20px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, ApplyCustomPropertyVar) {
  // Apply --x first.
  {
    TestCascade cascade(GetDocument());
    cascade.Add("--x", "yes and var(--y)");
    cascade.Add("--y", "no");
    cascade.Apply();

    EXPECT_EQ("yes and no", cascade.ComputedValue("--x"));
    EXPECT_EQ("no", cascade.ComputedValue("--y"));
  }

  // Apply --y first.
  {
    TestCascade cascade(GetDocument());
    cascade.Add("--y", "no");
    cascade.Add("--x", "yes and var(--y)");
    cascade.Apply();

    EXPECT_EQ("yes and no", cascade.ComputedValue("--x"));
    EXPECT_EQ("no", cascade.ComputedValue("--y"));
  }
}

TEST_F(StyleCascadeTest, InvalidVarReferenceCauseInvalidVariable) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "nope var(--y)");
  cascade.Apply();

  EXPECT_EQ(g_null_atom, cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, ApplyCustomPropertyFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "yes and var(--y,no)");
  cascade.Apply();

  EXPECT_EQ("yes and no", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RegisteredPropertyFallback) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "var(--y,10px)");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RegisteredPropertyFallbackValidation) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "10px");
  cascade.Add("--y", "var(--x,red)");  // Fallback must be valid <length>.
  cascade.Add("--z", "var(--y,pass)");
  cascade.Apply();

  EXPECT_EQ("pass", cascade.ComputedValue("--z"));
}

TEST_F(StyleCascadeTest, VarInFallback) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "one var(--z,two var(--y))");
  cascade.Add("--y", "three");
  cascade.Apply();

  EXPECT_EQ("one two three", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, VarReferenceInNormalProperty) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "10px");
  cascade.Add("width", "var(--x)");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("width"));
}

TEST_F(StyleCascadeTest, MultipleVarRefs) {
  TestCascade cascade(GetDocument());
  cascade.Add("--x", "var(--y) bar var(--y)");
  cascade.Add("--y", "foo");
  cascade.Apply();

  EXPECT_EQ("foo bar foo", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RegisteredPropertyComputedValue) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "1in");
  cascade.Apply();

  EXPECT_EQ("96px", cascade.ComputedValue("--x"));
}

TEST_F(StyleCascadeTest, RegisteredPropertySyntaxErrorCausesInitial) {
  RegisterProperty(GetDocument(), "--x", "<length>", "10px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "#fefefe");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();

  EXPECT_EQ("10px", cascade.ComputedValue("--x"));
  EXPECT_EQ("10px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RegisteredPropertySubstitution) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "1in");
  cascade.Add("--y", "var(--x)");
  cascade.Apply();

  EXPECT_EQ("96px", cascade.ComputedValue("--y"));
}

TEST_F(StyleCascadeTest, RegisteredPropertyChain) {
  RegisterProperty(GetDocument(), "--x", "<length>", "0px", false);
  RegisterProperty(GetDocument(), "--z", "<length>", "0px", false);

  TestCascade cascade(GetDocument());
  cascade.Add("--x", "1in");
  cascade.Add("--y", "var(--x)");
  cascade.Add("--z", "calc(var(--y) + 1in)");
  cascade.Apply();

  EXPECT_EQ("96px", cascade.ComputedValue("--x"));
  EXPECT_EQ("96px", cascade.ComputedValue("--y"));
  EXPECT_EQ("192px", cascade.ComputedValue("--z"));
}

TEST_F(StyleCascadeTest, BasicShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin", "1px 2px 3px 4px");
  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("2px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("3px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("4px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, BasicVarShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin", "1px var(--x) 3px 4px");
  cascade.Add("--x", "2px");
  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("2px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("3px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("4px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, ApplyingPendingSubstitutionFirst) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin", "1px var(--x) 3px 4px");
  cascade.Add("--x", "2px");
  cascade.Add("margin-right", "5px");
  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("5px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("3px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("4px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, ApplyingPendingSubstitutionLast) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin-right", "5px");
  cascade.Add("margin", "1px var(--x) 3px 4px");
  cascade.Add("--x", "2px");
  cascade.Apply();

  EXPECT_EQ("1px", cascade.ComputedValue("margin-top"));
  EXPECT_EQ("2px", cascade.ComputedValue("margin-right"));
  EXPECT_EQ("3px", cascade.ComputedValue("margin-bottom"));
  EXPECT_EQ("4px", cascade.ComputedValue("margin-left"));
}

TEST_F(StyleCascadeTest, PendingSubstitutionInLogicalShorthand) {
  TestCascade cascade(GetDocument());
  cascade.Add("margin-inline:var(--x)");
  cascade.Add("--x:10px 20px");
  cascade.Add("direction:rtl");
  cascade.Apply();

  EXPECT_EQ("20px", cascade.ComputedValue("margin-left"));
  EXPECT_EQ("10px", cascade.ComputedValue("margin-right"));
}

TEST_F(StyleCascadeTest, DetectCycleByName) {
  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  // Two different CustomProperty instances with the same name:
  CustomProperty a1(AtomicString("--a"), GetDocument());
  CustomProperty a2(AtomicString("--a"), GetDocument());

  {
    TestCascadeAutoLock lock(a1, resolver);
    EXPECT_FALSE(resolver.InCycle());

    // This should still be detected as a cycle, even though it's not the same
    // CustomProperty instance.
    EXPECT_TRUE(resolver.DetectCycle(a2));
    EXPECT_TRUE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, ResolverDetectCycle) {
  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());

  {
    TestCascadeAutoLock lock_a(a, resolver);
    EXPECT_FALSE(resolver.InCycle());
    {
      TestCascadeAutoLock lock_b(b, resolver);
      EXPECT_FALSE(resolver.InCycle());
      {
        TestCascadeAutoLock lock_c(c, resolver);
        EXPECT_FALSE(resolver.InCycle());

        EXPECT_TRUE(resolver.DetectCycle(a));
        EXPECT_TRUE(resolver.InCycle());
      }
      EXPECT_TRUE(resolver.InCycle());
    }
    EXPECT_TRUE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, ResolverDetectNoCycle) {
  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());
  CustomProperty x(AtomicString("--x"), GetDocument());

  {
    TestCascadeAutoLock lock_a(a, resolver);
    EXPECT_FALSE(resolver.InCycle());
    {
      TestCascadeAutoLock lock_b(b, resolver);
      EXPECT_FALSE(resolver.InCycle());
      {
        TestCascadeAutoLock lock_c(c, resolver);
        EXPECT_FALSE(resolver.InCycle());

        EXPECT_FALSE(resolver.DetectCycle(x));
        EXPECT_FALSE(resolver.InCycle());
      }
      EXPECT_FALSE(resolver.InCycle());
    }
    EXPECT_FALSE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, ResolverDetectCycleSelf) {
  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());

  {
    TestCascadeAutoLock lock(a, resolver);
    EXPECT_FALSE(resolver.InCycle());

    EXPECT_TRUE(resolver.DetectCycle(a));
    EXPECT_TRUE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, ResolverDetectMultiCycle) {
  using AutoLock = TestCascadeAutoLock;

  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());
  CustomProperty d(AtomicString("--d"), GetDocument());

  {
    AutoLock lock_a(a, resolver);
    EXPECT_FALSE(resolver.InCycle());
    {
      AutoLock lock_b(b, resolver);
      EXPECT_FALSE(resolver.InCycle());
      {
        AutoLock lock_c(c, resolver);
        EXPECT_FALSE(resolver.InCycle());
        {
          AutoLock lock_d(d, resolver);
          EXPECT_FALSE(resolver.InCycle());

          // Cycle 1 (big cycle):
          EXPECT_TRUE(resolver.DetectCycle(b));
          EXPECT_TRUE(resolver.InCycle());
          EXPECT_EQ(1u, resolver.CycleStart());

          // Cycle 2 (small cycle):
          EXPECT_TRUE(resolver.DetectCycle(c));
          EXPECT_TRUE(resolver.InCycle());
          EXPECT_EQ(1u, resolver.CycleStart());
        }
      }
      EXPECT_TRUE(resolver.InCycle());
    }
    EXPECT_FALSE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, ResolverDetectMultiCycleReverse) {
  using AutoLock = TestCascadeAutoLock;

  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());
  CustomProperty d(AtomicString("--d"), GetDocument());

  {
    AutoLock lock_a(a, resolver);
    EXPECT_FALSE(resolver.InCycle());
    {
      AutoLock lock_b(b, resolver);
      EXPECT_FALSE(resolver.InCycle());
      {
        AutoLock lock_c(c, resolver);
        EXPECT_FALSE(resolver.InCycle());
        {
          AutoLock lock_d(d, resolver);
          EXPECT_FALSE(resolver.InCycle());

          // Cycle 1 (small cycle):
          EXPECT_TRUE(resolver.DetectCycle(c));
          EXPECT_TRUE(resolver.InCycle());
          EXPECT_EQ(2u, resolver.CycleStart());

          // Cycle 2 (big cycle):
          EXPECT_TRUE(resolver.DetectCycle(b));
          EXPECT_TRUE(resolver.InCycle());
          EXPECT_EQ(1u, resolver.CycleStart());
        }
      }
      EXPECT_TRUE(resolver.InCycle());
    }
    EXPECT_FALSE(resolver.InCycle());
  }
  EXPECT_FALSE(resolver.InCycle());
}

TEST_F(StyleCascadeTest, CurrentProperty) {
  using AutoLock = TestCascadeAutoLock;

  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());

  EXPECT_FALSE(resolver.CurrentProperty());
  {
    AutoLock lock_a(a, resolver);
    EXPECT_EQ(&a, resolver.CurrentProperty());
    {
      AutoLock lock_b(b, resolver);
      EXPECT_EQ(&b, resolver.CurrentProperty());
      {
        AutoLock lock_c(c, resolver);
        EXPECT_EQ(&c, resolver.CurrentProperty());
      }
      EXPECT_EQ(&b, resolver.CurrentProperty());
    }
    EXPECT_EQ(&a, resolver.CurrentProperty());
  }
  EXPECT_FALSE(resolver.CurrentProperty());
}

TEST_F(StyleCascadeTest, CycleWithExtraEdge) {
  using AutoLock = TestCascadeAutoLock;

  TestCascade cascade(GetDocument());
  TestCascadeResolver resolver;

  CustomProperty a(AtomicString("--a"), GetDocument());
  CustomProperty b(AtomicString("--b"), GetDocument());
  CustomProperty c(AtomicString("--c"), GetDocument());
  CustomProperty d(AtomicString("--d"), GetDocument());

  {
    AutoLock lock_a(a, resolver);
    EXPECT_FALSE(resolver.InCycle());
    {
      AutoLock lock_b(b, resolver);
      EXPECT_FALSE(resolver.InCycle());

      {
        AutoLock lock_c(c, resolver);
        EXPECT_FALSE(resolver.InCycle());

        // Cycle:
        EXPECT_TRUE(resolver.DetectCycle(b));
        EXPECT_TRUE(resolver.InCycle());
        EXPECT_EQ(1u, resolver.CycleStart());
        EXPECT_EQ(3u, resolver.CycleEnd());
      }

      // ~AutoLock must shrink the in-cycle range:
      EXPECT_EQ(1u, resolver.CycleStart());
      EXPECT_EQ(2u, resolver.CycleEnd());

      {
        // We should not be in a cycle when locking a new property ...
        AutoLock lock_d(d, resolver);
        EXPECT_FALSE(resolver.InCycle());
        // AutoLock ctor does not affect in-cycle range:
        EXPECT_EQ(1u, resolver.CycleStart());
        EXPECT_EQ(2u, resolver.CycleEnd());
      }

      EXPECT_EQ(1u, resolver.CycleStart());
      EXPECT_EQ(2u, resolver.CycleEnd());

      // ... however we should be back InCycle when that AutoLock is destroyed.
      EXPECT_TRUE(resolver.InCycle());
    }

    // ~AutoLock should reduce cycle-end to equal cycle-start, hence we
    // are no longer in a cycle.
    EXPECT_EQ(kNotFound, resolver.CycleStart());
    EXPECT_EQ(kNotFound, resolver
"""


```