Response:
Let's break down the thought process for analyzing the `ScopedStyleResolver.cc` file and generating the comprehensive explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of this specific C++ file within the Chromium/Blink rendering engine. This involves identifying its purpose, how it interacts with other parts of the system (especially CSS, HTML, and potentially JavaScript), common errors, and debugging approaches.

2. **Initial Scan and Keyword Identification:** Start by quickly scanning the code for recognizable keywords and class names. Terms like "resolver," "style," "scoped," "keyframes," "font-face," "counter-style," "cascade," "media query," "rule," "sheet," "element," "document," and "shadow root" immediately stand out. These provide initial clues about the file's responsibilities.

3. **Deconstruct the Class Name:** The class name `ScopedStyleResolver` is very informative. "Scoped" suggests it deals with styles within a specific scope (likely a document or shadow root). "Style" clearly points to CSS style processing. "Resolver" indicates its role in finding or determining the applicable styles.

4. **Analyze Member Variables:** Examining the member variables provides a deeper understanding of the data the class manages:
    * `active_style_sheets_`:  A vector of style sheets, which suggests this class manages the active stylesheets within its scope.
    * `media_query_result_flags_`:  Indicates handling of media queries.
    * `keyframes_rule_map_`, `position_try_rule_map_`, `function_rule_map_`, `font_feature_values_storage_map_`: These maps store different types of CSS rules (@keyframes, @position-try, @function, @font-feature-values), suggesting this class is responsible for managing these specific rule types within its scope.
    * `counter_style_map_`:  Manages `@counter-style` rules.
    * `cascade_layer_map_`:  Deals with CSS cascade layers.
    * `scope_`:  A pointer to the `TreeScope`, confirming the "scoped" aspect.
    * `needs_append_all_sheets_`, `has_unresolved_keyframes_rule_`:  Internal flags for optimization and state management.

5. **Examine Public Methods (Functionality):** Focus on the public methods to understand the actions the `ScopedStyleResolver` can perform:
    * `Parent()`:  Navigates up the tree scope hierarchy to find the parent resolver, indicating a hierarchical structure of style resolution.
    * `AddKeyframeRules()`, `AddFontFaceRules()`, `AddCounterStyleRules()`, `AddPositionTryRules()`, `AddFunctionRules()`, `AddFontFeatureValuesRules()`:  Methods for adding different types of CSS rules, confirming their management within this class.
    * `AppendActiveStyleSheets()`:  The primary method for adding style sheets to the resolver, including handling deduplication.
    * `CollectFeaturesTo()`:  Gathers features from the stylesheets, used for optimization or dependency tracking.
    * `ResetStyle()`: Clears all cached style information.
    * `KeyframeStylesForAnimation()`: Retrieves `@keyframes` rules by name.
    * `KeyframesRulesAdded()`:  Handles events related to adding/removing `@keyframes` rules and triggering style invalidation.
    * `CollectMatchingElementScopeRules()`, `CollectMatchingShadowHostRules()`, `CollectMatchingSlottedRules()`, `CollectMatchingPartPseudoRules()`: Methods for finding matching CSS rules for different parts of the DOM tree.
    * `MatchPageRules()`: Handles matching `@page` rules.
    * `RebuildCascadeLayerMap()`:  Reconstructs the cascade layer map.
    * `PositionTryForName()`, `FunctionForName()`, `FontFeatureValuesForFamily()`:  Retrieves specific rules by name or family.
    * `AddImplicitScopeTriggers()`, `RemoveImplicitScopeTriggers()`: Manages implicit scoping based on `@scope` rules.

6. **Identify Relationships with HTML, CSS, and JavaScript:**
    * **CSS:** The entire file revolves around CSS concepts like style sheets, rules, selectors, cascade layers, and specific at-rules (`@keyframes`, `@font-face`, etc.).
    * **HTML:** The `ScopedStyleResolver` is associated with a `TreeScope`, which corresponds to a Document or ShadowRoot – HTML structures. It interacts with `Element` objects to determine matching styles. The handling of Shadow DOM (`CollectMatchingShadowHostRules`, `CollectMatchingSlottedRules`) is a key connection.
    * **JavaScript:** While this C++ file doesn't directly *execute* JavaScript, it's crucial for the rendering process that's often triggered or manipulated by JavaScript. JavaScript's ability to add/remove `<style>` tags, modify element attributes (affecting selectors), and trigger animations directly impacts the work of the `ScopedStyleResolver`.

7. **Infer Logic and Reasoning (Hypothetical Inputs and Outputs):** For methods like `KeyframeStylesForAnimation`, consider:
    * **Input:** An animation name (e.g., `"slide-in"`).
    * **Output:** A pointer to the `StyleRuleKeyframes` object with that name, or `nullptr` if no such rule exists.

8. **Consider Common Usage Errors:** Think about scenarios where things might go wrong:
    * **Conflicting Styles:**  Multiple stylesheets defining the same property, highlighting the importance of the cascade and specificity.
    * **Incorrect Selectors:**  CSS selectors that don't match the intended elements.
    * **Invalid CSS Syntax:**  While the parser handles this initially, runtime issues could arise if the parsed data is inconsistent.
    * **Unexpected Shadow DOM Interactions:**  Incorrectly understanding how styles are inherited or encapsulated within shadow roots.

9. **Trace User Operations to Reach the Code (Debugging):** Imagine a user browsing a web page:
    * **Loading a Page:** The browser parses HTML, encounters `<link>` or `<style>` tags, and initiates loading and parsing of CSS.
    * **Dynamic Updates:** JavaScript might add or remove `<style>` tags, modify element classes/attributes, or start animations. These actions will trigger updates in the style system, potentially involving the `ScopedStyleResolver`.
    * **Inspecting Styles:**  Using browser developer tools to inspect an element's styles would involve the browser querying the style system, eventually leading back to how the styles were resolved.

10. **Structure the Explanation:** Organize the information logically:
    * Start with a high-level overview of the file's purpose.
    * Detail the functionalities based on the methods.
    * Explain the relationships with HTML, CSS, and JavaScript with concrete examples.
    * Provide hypothetical input/output scenarios for key methods.
    * Discuss common user/programming errors.
    * Outline debugging approaches.

11. **Refine and Clarify:** Review the explanation for clarity, accuracy, and completeness. Ensure the language is accessible and avoids excessive technical jargon where possible. Use examples to illustrate abstract concepts.

By following this systematic approach, combining code analysis with domain knowledge (web rendering, CSS), and thinking about practical usage and debugging scenarios, a comprehensive and informative explanation of the `ScopedStyleResolver.cc` file can be generated.
好的，让我们来详细分析 `blink/renderer/core/css/resolver/scoped_style_resolver.cc` 这个文件。

**功能概述**

`ScopedStyleResolver` 类在 Blink 渲染引擎中负责管理和解析特定作用域内的 CSS 样式规则。这个作用域通常是一个 `TreeScope`，它可以是整个文档 (Document) 或者一个 Shadow DOM 树。  它的主要职责是：

1. **存储和组织样式表:**  它维护着当前作用域内激活的 CSS 样式表 (包括 `<style>` 标签和通过 `<link>` 引入的样式表) 的列表。
2. **管理特定类型的 CSS 规则:** 除了普通的样式规则，它还专门管理以下类型的 CSS 规则：
    * **`@keyframes` 动画规则:** 存储和查找用于 CSS 动画的 `@keyframes` 规则。
    * **`@font-face` 字体规则:**  处理自定义字体的加载和应用（尽管代码中有注释表明对作用域样式表的支持尚不完善）。
    * **`@counter-style` 计数器样式规则:**  管理自定义列表标记样式。
    * **`@position-try` 规则:**  用于声明在定位元素时尝试的不同位置。
    * **`@function` 规则:**  定义自定义 CSS 函数。
    * **`@font-feature-values` 规则:**  定义 OpenType 字体特性值的别名。
    * **`@scope` 作用域规则:** 管理 CSS 作用域，决定样式规则的应用范围。
3. **媒体查询处理:**  记录和使用媒体查询的结果来确定哪些样式表是活动的。
4. **级联层 (Cascade Layers) 管理:**  处理 CSS 级联层，决定样式规则的优先级。
5. **样式匹配:**  当需要为元素计算样式时，`ScopedStyleResolver` 提供方法来收集匹配特定元素的选择器和规则。
6. **样式失效 (Invalidation):**  当样式表或规则发生变化时，触发必要的样式重新计算。
7. **隐式作用域触发器 (Implicit Scope Triggers):**  处理 `@scope` 规则创建的隐式作用域，并跟踪哪些元素会触发这些作用域的激活。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **CSS:**  `ScopedStyleResolver` 的核心功能就是处理 CSS。它解析 CSS 语法，提取规则，并根据 CSS 规范进行组织和匹配。
    * **例子:** 当浏览器解析到以下 CSS 时，`ScopedStyleResolver` 会存储这些规则：
      ```css
      /* style 标签内的 CSS */
      .my-class {
        color: red;
      }

      @keyframes fade-in {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      @font-face {
        font-family: 'MyCustomFont';
        src: url('/fonts/custom.woff2') format('woff2');
      }
      ```
* **HTML:**  `ScopedStyleResolver` 与 HTML 结构紧密相关，因为它处理的是应用于 HTML 元素的样式。
    * **例子:**  当 HTML 中有以下元素时，`ScopedStyleResolver` 需要确定 `.my-class` 的样式是否应该应用到这个 `div` 元素：
      ```html
      <div class="my-class">This is some text.</div>
      ```
    * **Shadow DOM:** `ScopedStyleResolver` 可以为 Shadow Root 管理独立的样式作用域。这意味着 Shadow DOM 内部的样式不会影响外部文档，反之亦然（除非使用了特定的 CSS 功能如 `::part` 和 `::slotted`）。
* **JavaScript:**  JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会影响 `ScopedStyleResolver` 的行为。
    * **例子:**  JavaScript 可以动态地创建 `<style>` 标签并添加到文档中：
      ```javascript
      const style = document.createElement('style');
      style.textContent = '.another-class { font-weight: bold; }';
      document.head.appendChild(style);
      ```
      `ScopedStyleResolver` 会检测到这个新的样式表并将其纳入管理。
    * **CSSOM 操作:** JavaScript 可以通过 CSSOM API (如 `document.styleSheets`) 修改样式表的规则，这些修改也会触发 `ScopedStyleResolver` 的更新。
    * **动画触发:** JavaScript 可以启动 CSS 动画，`ScopedStyleResolver` 需要找到对应的 `@keyframes` 规则。

**逻辑推理及假设输入与输出**

假设 `ScopedStyleResolver` 正在处理一个包含以下 HTML 和 CSS 的文档：

**HTML:**

```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .text { color: blue; }
  </style>
</head>
<body>
  <div class="text">Hello</div>
</body>
</html>
```

**CSS (在 `<style>` 标签内):**

```css
.text { color: blue; }
```

**假设输入:**  `ScopedStyleResolver` 收到一个为 `<div>` 元素查找匹配样式规则的请求。

**逻辑推理:**

1. `ScopedStyleResolver` 会遍历其管理的活动样式表列表。
2. 它会检查每个样式表中的规则，看是否有选择器匹配该 `<div>` 元素。
3. 在本例中，它会找到 `.text { color: blue; }` 规则，该规则的选择器 `.text` 匹配 `<div>` 元素的 `class` 属性。

**假设输出:** `ScopedStyleResolver` 会返回一个包含匹配规则 (`.text { color: blue; }`) 的集合。  这个集合会被传递给后续的样式计算阶段，最终决定 `<div>` 元素的文本颜色为蓝色。

**涉及用户或编程常见的使用错误及举例说明**

1. **CSS 优先级冲突:** 当多个样式规则应用于同一个元素并且定义了相同的属性时，CSS 的优先级规则 (specificity, origin, and order) 决定哪个规则生效。 用户可能会因为不理解优先级规则而遇到样式未按预期应用的情况。
    * **例子:**
      ```html
      <div id="myDiv" class="text" style="color: green;">Hello</div>
      ```
      ```css
      .text { color: blue; }
      #myDiv { color: red; }
      ```
      用户可能期望文本是蓝色，但由于 `#myDiv` 的 ID 选择器优先级更高，文本最终会是红色。内联样式 (`style="color: green;"`) 的优先级最高，所以最终文本颜色会是绿色。

2. **Shadow DOM 样式隔离理解错误:**  开发者可能错误地认为外部样式会自动应用到 Shadow DOM 内部，或者反之亦然。
    * **例子:**
      ```html
      <my-component>
        #shadow-root
        <div class="shadow-text">Shadow Content</div>
      </my-component>
      <style>
        .shadow-text { color: purple; } /* 这个样式不会直接应用到 shadow-text */
      </style>
      ```
      要穿透 Shadow DOM 或允许外部样式影响内部，需要使用 `::part` 或 `::slotted` 等 CSS 功能。

3. **动态添加样式后未触发更新:**  在某些情况下，如果以不当的方式动态添加或修改样式，浏览器可能不会立即重新计算样式，导致页面显示不一致。
    * **例子:**  直接操作 CSSRule 对象而不是修改 `textContent` 或使用 CSSOM API 的方式可能会导致问题。

**用户操作如何一步步到达这里 (调试线索)**

当开发者或浏览器执行以下操作时，代码执行流程可能会涉及到 `ScopedStyleResolver`：

1. **页面加载和解析:**
   * 浏览器解析 HTML 文档，遇到 `<link>` 和 `<style>` 标签。
   * 对于每个样式表，Blink 会创建相应的 `CSSStyleSheet` 对象。
   * `ScopedStyleResolver` 会将这些样式表添加到其管理的列表中。
   * 浏览器解析 CSS 内容，构建 CSS 规则树，并将其关联到 `ScopedStyleResolver`。

2. **动态修改样式:**
   * JavaScript 通过 DOM API (如 `document.createElement('style')`, `element.classList.add()`, `element.style.color = '...'`) 修改页面样式。
   * 当新的样式表被添加到文档或现有样式表被修改时，`ScopedStyleResolver` 会接收通知并更新其内部状态。

3. **触发样式计算:**
   * 当元素的样式需要被计算时 (例如，首次渲染、属性或类名更改、伪类状态改变等)，Blink 的样式系统会查询 `ScopedStyleResolver` 来获取适用于该元素的匹配规则。
   * 开发者工具中的 "Inspect" 或 "Elements" 面板显示元素的 computed styles，这些信息的获取就依赖于 `ScopedStyleResolver` 的工作。

4. **处理 CSS 动画和过渡:**
   * 当 CSS 动画或过渡开始时，浏览器需要查找对应的 `@keyframes` 规则，这会调用 `ScopedStyleResolver::KeyframeStylesForAnimation()`。

**调试线索:**

* **查看元素的 computed styles:**  在浏览器开发者工具中查看元素的 "Computed" (计算后) 样式，可以帮助理解哪些 CSS 规则最终应用到了该元素。如果样式与预期不符，可以追溯到具体的 CSS 规则。
* **检查样式表列表:**  在调试过程中，可以查看 `ScopedStyleResolver` 管理的 `active_style_sheets_` 列表，确认哪些样式表被认为是活动的。
* **断点调试:**  在 `ScopedStyleResolver` 的关键方法 (如 `AppendActiveStyleSheets`, `CollectMatchingElementScopeRules`, `KeyframeStylesForAnimation`) 设置断点，可以跟踪样式的加载、匹配和应用过程。
* **使用 Performance 面板:**  Blink 的 Performance 面板可以记录样式的计算和重绘过程，帮助识别性能瓶颈和样式问题的来源。

希望以上分析能够帮助你理解 `blink/renderer/core/css/resolver/scoped_style_resolver.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/scoped_style_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"

#include "third_party/blink/renderer/core/animation/document_timeline.h"
#include "third_party/blink/renderer/core/css/cascade_layer_map.h"
#include "third_party/blink/renderer/core/css/counter_style_map.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/font_face.h"
#include "third_party/blink/renderer/core/css/page_rule_collector.h"
#include "third_party/blink/renderer/core/css/part_names.h"
#include "third_party/blink/renderer/core/css/resolver/match_request.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/rule_feature_set.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_scope_data.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"

namespace blink {

ScopedStyleResolver* ScopedStyleResolver::Parent() const {
  for (TreeScope* scope = GetTreeScope().ParentTreeScope(); scope;
       scope = scope->ParentTreeScope()) {
    if (ScopedStyleResolver* resolver = scope->GetScopedStyleResolver()) {
      return resolver;
    }
  }
  return nullptr;
}

void ScopedStyleResolver::AddKeyframeRules(const RuleSet& rule_set) {
  const HeapVector<Member<StyleRuleKeyframes>> keyframes_rules =
      rule_set.KeyframesRules();
  for (auto rule : keyframes_rules) {
    AddKeyframeStyle(rule);
  }
}

CounterStyleMap& ScopedStyleResolver::EnsureCounterStyleMap() {
  if (!counter_style_map_) {
    counter_style_map_ = CounterStyleMap::CreateAuthorCounterStyleMap(*scope_);
  }
  return *counter_style_map_;
}

void ScopedStyleResolver::AddFontFaceRules(const RuleSet& rule_set) {
  // TODO(crbug.com/336876): We don't add @font-face rules of scoped style
  // sheets for the moment.
  if (!GetTreeScope().RootNode().IsDocumentNode()) {
    return;
  }

  Document& document = GetTreeScope().GetDocument();
  CSSFontSelector* css_font_selector =
      document.GetStyleEngine().GetFontSelector();
  const HeapVector<Member<StyleRuleFontFace>> font_face_rules =
      rule_set.FontFaceRules();
  for (auto& font_face_rule : font_face_rules) {
    if (FontFace* font_face = FontFace::Create(&document, font_face_rule,
                                               false /* is_user_style */)) {
      css_font_selector->GetFontFaceCache()->Add(font_face_rule, font_face);
    }
  }
  if (font_face_rules.size()) {
    document.GetStyleResolver().InvalidateMatchedPropertiesCache();
  }
}

void ScopedStyleResolver::AddCounterStyleRules(const RuleSet& rule_set) {
  if (rule_set.CounterStyleRules().empty()) {
    return;
  }
  EnsureCounterStyleMap().AddCounterStyles(rule_set);
}

void ScopedStyleResolver::AppendActiveStyleSheets(
    unsigned index,
    const ActiveStyleSheetVector& active_sheets) {
  for (const ActiveStyleSheet& active_sheet :
       base::span(active_sheets).subspan(index)) {
    CSSStyleSheet* sheet = active_sheet.first;
    media_query_result_flags_.Add(sheet->GetMediaQueryResultFlags());
    if (!active_sheet.second) {
      continue;
    }

    const RuleSet& rule_set = *active_sheet.second;
    if (!active_style_sheets_.empty() &&
        active_style_sheets_.back().second == active_sheet.second) {
      // Some frameworks generate a ton of identical <style> tags;
      // we have already deduplicated them earlier to have the same
      // pointer, so we can just discard them here. Of course,
      // this assumes they come immediately after each other,
      // but this is a cheap win for something that is rather pathological.
      //
      // TODO(sesse): Consider deduplicating noncontiguous stylesheets;
      // however, we'd need to make sure this doesn't change @layer ordering.
    } else {
      active_style_sheets_.push_back(active_sheet);
      AddKeyframeRules(rule_set);
      AddFontFaceRules(rule_set);
      AddCounterStyleRules(rule_set);
      AddPositionTryRules(rule_set);
      AddFunctionRules(rule_set);
      AddFontFeatureValuesRules(rule_set);
    }
    AddImplicitScopeTriggers(*sheet, rule_set);
  }
}

void ScopedStyleResolver::CollectFeaturesTo(
    RuleFeatureSet& features,
    HeapHashSet<Member<const StyleSheetContents>>&
        visited_shared_style_sheet_contents) const {
  features.MutableMediaQueryResultFlags().Add(media_query_result_flags_);

  for (auto [sheet, rule_set] : active_style_sheets_) {
    DCHECK(sheet->ownerNode() || sheet->IsConstructed());
    StyleSheetContents* contents = sheet->Contents();
    if (contents->HasOneClient() ||
        visited_shared_style_sheet_contents.insert(contents).is_new_entry) {
      features.Merge(rule_set->Features());
    }
  }
}

void ScopedStyleResolver::ResetStyle() {
  RemoveImplicitScopeTriggers();
  active_style_sheets_.clear();
  media_query_result_flags_.Clear();
  keyframes_rule_map_.clear();
  position_try_rule_map_.clear();
  font_feature_values_storage_map_.clear();
  function_rule_map_.clear();
  if (counter_style_map_) {
    counter_style_map_->Dispose();
  }
  cascade_layer_map_ = nullptr;
  needs_append_all_sheets_ = false;
}

StyleRuleKeyframes* ScopedStyleResolver::KeyframeStylesForAnimation(
    const AtomicString& animation_name) {
  if (keyframes_rule_map_.empty()) {
    return nullptr;
  }

  KeyframesRuleMap::iterator it = keyframes_rule_map_.find(animation_name);
  if (it == keyframes_rule_map_.end()) {
    return nullptr;
  }

  return it->value.Get();
}

void ScopedStyleResolver::AddKeyframeStyle(StyleRuleKeyframes* rule) {
  AtomicString name = rule->GetName();

  KeyframesRuleMap::iterator it = keyframes_rule_map_.find(name);
  if (it == keyframes_rule_map_.end() ||
      KeyframeStyleShouldOverride(rule, it->value)) {
    keyframes_rule_map_.Set(name, rule);
  }
}

bool ScopedStyleResolver::KeyframeStyleShouldOverride(
    const StyleRuleKeyframes* new_rule,
    const StyleRuleKeyframes* existing_rule) const {
  if (new_rule->IsVendorPrefixed() != existing_rule->IsVendorPrefixed()) {
    return existing_rule->IsVendorPrefixed();
  }
  return !cascade_layer_map_ || cascade_layer_map_->CompareLayerOrder(
                                    existing_rule->GetCascadeLayer(),
                                    new_rule->GetCascadeLayer()) <= 0;
}

Element& ScopedStyleResolver::InvalidationRootForTreeScope(
    const TreeScope& tree_scope) {
  DCHECK(tree_scope.GetDocument().documentElement());
  if (tree_scope.RootNode() == tree_scope.GetDocument()) {
    return *tree_scope.GetDocument().documentElement();
  }
  return To<ShadowRoot>(tree_scope.RootNode()).host();
}

void ScopedStyleResolver::KeyframesRulesAdded(const TreeScope& tree_scope) {
  // Called when @keyframes rules are about to be added/removed from a
  // TreeScope. @keyframes rules may apply to animations on elements in the
  // same TreeScope as the stylesheet, or the host element in the parent
  // TreeScope if the TreeScope is a shadow tree.
  if (!tree_scope.GetDocument().documentElement()) {
    return;
  }

  ScopedStyleResolver* resolver = tree_scope.GetScopedStyleResolver();
  ScopedStyleResolver* parent_resolver =
      tree_scope.ParentTreeScope()
          ? tree_scope.ParentTreeScope()->GetScopedStyleResolver()
          : nullptr;

  bool had_unresolved_keyframes = false;
  if (resolver && resolver->has_unresolved_keyframes_rule_) {
    resolver->has_unresolved_keyframes_rule_ = false;
    had_unresolved_keyframes = true;
  }
  if (parent_resolver && parent_resolver->has_unresolved_keyframes_rule_) {
    parent_resolver->has_unresolved_keyframes_rule_ = false;
    had_unresolved_keyframes = true;
  }

  StyleChangeReasonForTracing reason = StyleChangeReasonForTracing::Create(
      style_change_reason::kKeyframesRuleChange);
  if (had_unresolved_keyframes) {
    // If an animation ended up not being started because no @keyframes
    // rules were found for the animation-name, we need to recalculate style
    // for the elements in the scope, including its shadow host if
    // applicable.
    InvalidationRootForTreeScope(tree_scope)
        .SetNeedsStyleRecalc(kSubtreeStyleChange, reason);
    return;
  }

  // If we have animations running, added/removed @keyframes may affect these.
  tree_scope.GetDocument().Timeline().InvalidateKeyframeEffects(tree_scope,
                                                                reason);
}

namespace {

bool CanRejectRuleSet(ElementRuleCollector& collector,
                      const RuleSet& rule_set) {
  const StyleScope* scope = rule_set.SingleScope();
  return scope && collector.CanRejectScope(*scope);
}

}  // namespace

template <class Func>
void ScopedStyleResolver::ForAllStylesheets(ElementRuleCollector& collector,
                                            const Func& func) {
  if (active_style_sheets_.empty()) {
    return;
  }

  MatchRequest match_request{&scope_->RootNode()};
  for (auto [sheet, rule_set] : active_style_sheets_) {
    if (CanRejectRuleSet(collector, *rule_set)) {
      continue;
    }
    match_request.AddRuleset(rule_set.Get());
    if (match_request.IsFull()) {
      func(match_request);
      match_request.ClearAfterMatching();
    }
  }
  if (!match_request.IsEmpty()) {
    func(match_request);
  }
}

void ScopedStyleResolver::CollectMatchingElementScopeRules(
    ElementRuleCollector& collector,
    PartNames* part_names) {
  ForAllStylesheets(
      collector, [&collector, part_names](const MatchRequest& match_request) {
        collector.CollectMatchingRules(match_request, part_names);
      });
}

void ScopedStyleResolver::CollectMatchingShadowHostRules(
    ElementRuleCollector& collector) {
  ForAllStylesheets(collector, [&collector](const MatchRequest& match_request) {
    collector.CollectMatchingShadowHostRules(match_request);
  });
}

void ScopedStyleResolver::CollectMatchingSlottedRules(
    ElementRuleCollector& collector) {
  ForAllStylesheets(collector, [&collector](const MatchRequest& match_request) {
    collector.CollectMatchingSlottedRules(match_request);
  });
}

void ScopedStyleResolver::CollectMatchingPartPseudoRules(
    ElementRuleCollector& collector,
    PartNames* part_names,
    bool for_shadow_pseudo) {
  ForAllStylesheets(collector, [&](const MatchRequest& match_request) {
    collector.CollectMatchingPartPseudoRules(match_request, part_names,
                                             for_shadow_pseudo);
  });
}

void ScopedStyleResolver::MatchPageRules(PageRuleCollector& collector) {
  // Currently, only @page rules in the document scope apply.
  DCHECK(scope_->RootNode().IsDocumentNode());
  for (auto [sheet, rule_set] : active_style_sheets_) {
    collector.MatchPageRules(rule_set.Get(), CascadeOrigin::kAuthor, scope_,
                             GetCascadeLayerMap());
  }
}

void ScopedStyleResolver::RebuildCascadeLayerMap(
    const ActiveStyleSheetVector& sheets) {
  cascade_layer_map_ = MakeGarbageCollected<CascadeLayerMap>(sheets);
}

void ScopedStyleResolver::AddPositionTryRules(const RuleSet& rule_set) {
  for (StyleRulePositionTry* rule : rule_set.PositionTryRules()) {
    auto result = position_try_rule_map_.insert(rule->Name(), rule);
    if (result.is_new_entry) {
      continue;
    }
    Member<StyleRulePositionTry>& stored_rule = result.stored_value->value;
    const bool should_override =
        !cascade_layer_map_ ||
        cascade_layer_map_->CompareLayerOrder(stored_rule->GetCascadeLayer(),
                                              rule->GetCascadeLayer()) <= 0;
    if (should_override) {
      stored_rule = rule;
    }
  }
}

void ScopedStyleResolver::AddFunctionRules(const RuleSet& rule_set) {
  const HeapVector<Member<StyleRuleFunction>> function_rules =
      rule_set.FunctionRules();
  for (StyleRuleFunction* rule : function_rules) {
    // TODO(crbug.com/324780202): Handle @layer.
    function_rule_map_.Set(rule->GetName(), rule);
  }
}

void ScopedStyleResolver::AddFontFeatureValuesRules(const RuleSet& rule_set) {
  // TODO(https://crbug.com/1382722): Support @font-feature-values in shadow
  // trees and support scoping correctly. See CSSFontSelector::GetFontData: In
  // that function we would need to look for parent TreeScopes, but currently,
  // we only check the Document-level TreeScope.
  if (!GetTreeScope().RootNode().IsDocumentNode()) {
    return;
  }

  const HeapVector<Member<StyleRuleFontFeatureValues>>
      font_feature_values_rules = rule_set.FontFeatureValuesRules();
  for (auto& rule : font_feature_values_rules) {
    for (auto& font_family : rule->GetFamilies()) {
      unsigned layer_order = CascadeLayerMap::kImplicitOuterLayerOrder;
      if (cascade_layer_map_ && rule->GetCascadeLayer() != nullptr) {
        layer_order =
            cascade_layer_map_->GetLayerOrder(*rule->GetCascadeLayer());
      }
      auto add_result = font_feature_values_storage_map_.insert(
          String(font_family).FoldCase(), rule->Storage());
      if (add_result.is_new_entry) {
        add_result.stored_value->value.SetLayerOrder(layer_order);
      } else {
        add_result.stored_value->value.FuseUpdate(rule->Storage(), layer_order);
      }
    }
  }
}

StyleRulePositionTry* ScopedStyleResolver::PositionTryForName(
    const AtomicString& try_name) {
  DCHECK(try_name);
  auto iter = position_try_rule_map_.find(try_name);
  if (iter != position_try_rule_map_.end()) {
    return iter->value.Get();
  }
  return nullptr;
}

StyleRuleFunction* ScopedStyleResolver::FunctionForName(StringView name) {
  auto iter = function_rule_map_.find(name.ToString());
  if (iter != function_rule_map_.end()) {
    return iter->value.Get();
  }
  return nullptr;
}

const FontFeatureValuesStorage* ScopedStyleResolver::FontFeatureValuesForFamily(
    AtomicString font_family) {
  if (font_feature_values_storage_map_.empty() || font_family.empty()) {
    return nullptr;
  }

  auto it =
      font_feature_values_storage_map_.find(String(font_family).FoldCase());
  if (it == font_feature_values_storage_map_.end()) {
    return nullptr;
  }

  return &(it->value);
}

// When appending/removing stylesheets, we go through all implicit
// StyleScope instances in each stylesheet and store those instances
// in the StyleScopeData (ElementRareData) of the triggering element.
//
// See StyleScopeData for more information.

namespace {

Element* ImplicitScopeTrigger(TreeScope& scope, CSSStyleSheet& sheet) {
  if (Element* owner_parent = sheet.OwnerParentOrShadowHostElement()) {
    return owner_parent;
  }
  if (sheet.IsAdoptedByTreeScope(scope)) {
    if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(scope)) {
      return &shadow_root->host();
    }
  }
  return nullptr;
}

template <typename Func>
void ForEachImplicitScopeTrigger(TreeScope& scope,
                                 CSSStyleSheet& sheet,
                                 const RuleSet& rule_set,
                                 Func func) {
  for (const RuleSet::Interval<StyleScope>& interval :
       rule_set.ScopeIntervals()) {
    const StyleScope* style_scope = interval.value.Get();
    while (style_scope) {
      if (style_scope->IsImplicit()) {
        if (Element* scoping_root = ImplicitScopeTrigger(scope, sheet)) {
          func(*scoping_root, *style_scope);
        }
      }
      // Note that ScopeIntervals() only reaches the @scope rules that
      // hold some style rule directly, but it's also possible to do e.g.
      // @scope { @scope (.a) { div {} } }, where an implicit @scope exists
      // as a parent-@scope only.
      style_scope = style_scope->Parent();
    }
  }
}

}  // namespace

void ScopedStyleResolver::AddImplicitScopeTriggers(CSSStyleSheet& sheet,
                                                   const RuleSet& rule_set) {
  ForEachImplicitScopeTrigger(
      *scope_, sheet, rule_set,
      [&](Element& element, const StyleScope& style_scope) {
        AddImplicitScopeTrigger(element, style_scope);
      });
}

void ScopedStyleResolver::AddImplicitScopeTrigger(
    Element& element,
    const StyleScope& style_scope) {
  DCHECK(style_scope.IsImplicit());
  element.EnsureStyleScopeData().AddTriggeredImplicitScope(style_scope);
}

void ScopedStyleResolver::RemoveImplicitScopeTriggers() {
  for (auto [sheet, rule_set] : active_style_sheets_) {
    RemoveImplicitScopeTriggers(*sheet, *rule_set);
  }
}

void ScopedStyleResolver::RemoveImplicitScopeTriggers(CSSStyleSheet& sheet,
                                                      const RuleSet& rule_set) {
  ForEachImplicitScopeTrigger(
      *scope_, sheet, rule_set,
      [&](Element& element, const StyleScope& style_scope) {
        RemoveImplicitScopeTrigger(element, style_scope);
      });
}

void ScopedStyleResolver::RemoveImplicitScopeTrigger(
    Element& element,
    const StyleScope& style_scope) {
  if (StyleScopeData* style_scope_data = element.GetStyleScopeData()) {
    style_scope_data->RemoveTriggeredImplicitScope(style_scope);
  }
}

void ScopedStyleResolver::Trace(Visitor* visitor) const {
  visitor->Trace(scope_);
  visitor->Trace(active_style_sheets_);
  visitor->Trace(keyframes_rule_map_);
  visitor->Trace(position_try_rule_map_);
  visitor->Trace(function_rule_map_);
  visitor->Trace(counter_style_map_);
  visitor->Trace(cascade_layer_map_);
}

}  // namespace blink

"""

```