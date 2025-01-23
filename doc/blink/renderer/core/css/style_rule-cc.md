Response:
The user wants to understand the functionality of the `style_rule.cc` file in the Chromium Blink rendering engine. I need to explain what this file does, how it relates to web technologies (HTML, CSS, JavaScript), provide examples, discuss potential errors, and explain how a user interaction could lead to this code being executed. Finally, I need to summarize the functionality.

**Plan:**

1. **Core Functionality:** Identify the primary role of `style_rule.cc`. It seems to define the structure and behavior of different types of CSS rules.
2. **Relationship with Web Technologies:**
    *   **CSS:**  Explain how this file is fundamental to parsing and representing CSS rules. Give examples of different CSS rules (like `style`, `@media`, `@font-face`) and how they are represented here.
    *   **HTML:** Explain how CSS rules are applied to HTML elements.
    *   **JavaScript:** Discuss how JavaScript can interact with and manipulate CSS rules via the CSSOM (CSS Object Model).
3. **Logic and Examples:** For different rule types, provide simple CSS examples and explain how the corresponding C++ classes in this file would represent them.
4. **User/Programming Errors:**  Think about common mistakes related to CSS syntax or manipulation that could surface issues in this code.
5. **User Interaction and Debugging:** Describe a typical user action (e.g., loading a web page) and the steps involved in CSS processing that lead to the use of these classes.
6. **Summary:**  Provide a concise summary of the file's purpose.
这是 `blink/renderer/core/css/style_rule.cc` 文件的第一部分，它主要负责定义和实现 Blink 渲染引擎中各种 CSS 规则的基类和具体子类。它构成了 CSS 对象模型（CSSOM）在 C++ 端的表示。

**主要功能归纳:**

1. **定义 CSS 规则的抽象基类 `StyleRuleBase`:**  这个基类为所有类型的 CSS 规则（如样式规则、媒体查询、字体规则等）提供了一个通用的接口和基础结构。它定义了所有 CSS 规则共有的行为，例如创建 CSSOM 包装器、进行垃圾回收跟踪和清理。

2. **定义各种具体 CSS 规则的子类:**  文件中包含了多种 CSS 规则类型的定义，例如：
    *   `StyleRule`:  普通的 CSS 样式规则（选择器和属性声明）。
    *   `StyleRulePage`: `@page` 规则。
    *   `StyleRuleMedia`: `@media` 规则。
    *   `StyleRuleFontFace`: `@font-face` 规则。
    *   `StyleRuleImport`: `@import` 规则。
    *   `StyleRuleKeyframes`: `@keyframes` 规则。
    *   `StyleRuleNamespace`: `@namespace` 规则。
    *   `StyleRuleSupports`: `@supports` 规则。
    *   `StyleRuleContainer`: `@container` 规则。
    *   `StyleRuleCounterStyle`: `@counter-style` 规则。
    *   `StyleRuleLayerBlock`: `@layer` 块规则。
    *   `StyleRuleLayerStatement`: `@layer` 声明规则。
    *   `StyleRuleScope`: `@scope` 规则。
    *   `StyleRuleProperty`: `@property` 规则。
    *   `StyleRuleStartingStyle`: `@starting-style` 规则。
    *   `StyleRuleViewTransition`: `@view-transition` 规则。
    *   `StyleRulePageMargin`: `@page` 内部的页边距规则（例如 `@top-left`）。
    *   `StyleRuleNestedDeclarations`:  用于表示嵌套声明块的规则。
    *   `StyleRulePositionTry`: `@position-try` 规则。
    *   等等。

3. **实现 CSS 规则的生命周期管理:**  包括对象的创建、垃圾回收跟踪 (`Trace`) 和清理 (`FinalizeGarbageCollectedObject`)。

4. **提供创建 CSSOM 包装器的方法:**  `CreateCSSOMWrapper` 方法负责将 C++ 端的 `StyleRuleBase` 对象转换为 JavaScript 可以访问的 CSSOM (`CSSRule`) 对象。

5. **支持复制 CSS 规则:**  部分 CSS 规则实现了 `Copy()` 方法，用于创建规则的深拷贝。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:** 这个文件是 Blink 引擎解析和表示 CSS 规则的核心。当浏览器解析 CSS 样式表时，会根据 CSS 语法创建相应的 `StyleRuleBase` 或其子类的对象来表示每个 CSS 规则。

    *   **示例:**  对于以下 CSS 规则：
        ```css
        .my-class {
          color: blue;
          font-size: 16px;
        }
        ```
        Blink 引擎会创建一个 `StyleRule` 对象来表示这个规则，其中包含选择器 `.my-class` 和属性值对 `color: blue` 和 `font-size: 16px`。

    *   **示例:**  对于以下 `@media` 规则：
        ```css
        @media (max-width: 768px) {
          body {
            font-size: 14px;
          }
        }
        ```
        Blink 引擎会创建一个 `StyleRuleMedia` 对象，其中包含媒体查询条件 `(max-width: 768px)` 和一个包含 `body` 样式规则的子规则列表。

*   **HTML:**  CSS 规则的目标是 HTML 元素。当浏览器加载 HTML 文档并解析 CSS 时，会根据 CSS 选择器将 CSS 规则应用到匹配的 HTML 元素上，从而控制元素的样式。

    *   **示例:** 上述的 `.my-class` CSS 规则会被应用到 HTML 中所有带有 `class="my-class"` 属性的元素上。

*   **JavaScript:**  JavaScript 可以通过 CSSOM (CSS Object Model) 来访问和操作 CSS 规则。`CreateCSSOMWrapper` 方法正是为了将 C++ 端的 `StyleRuleBase` 对象转换为 JavaScript 可以操作的 `CSSRule` 对象。

    *   **示例:**  JavaScript 代码可以使用 `document.styleSheets` 获取样式表列表，然后遍历其中的规则，访问和修改规则的属性，例如：
        ```javascript
        const styleSheet = document.styleSheets[0];
        const rules = styleSheet.cssRules || styleSheet.rules;
        for (let i = 0; i < rules.length; i++) {
          if (rules[i].selectorText === '.my-class') {
            rules[i].style.color = 'red';
            break;
          }
        }
        ```
        在这个过程中，JavaScript 操作的 `rules[i]` 对象就是由 C++ 端的 `StyleRule` 对象通过 `CreateCSSOMWrapper` 创建的。

**逻辑推理和假设输入/输出:**

假设输入是一个简单的 CSS 样式规则：

```css
h1 {
  font-weight: bold;
}
```

**处理流程 (简化的):**

1. **解析:** CSS 解析器会读取 CSS 代码，识别出选择器 `h1` 和属性声明 `font-weight: bold;`。
2. **对象创建:** Blink 引擎会创建一个 `StyleRule` 类的实例来表示这个规则。
3. **数据存储:**  选择器 `h1` 会被存储在 `StyleRule` 对象的选择器列表中。属性 `font-weight` 和值 `bold` 会被存储在 `StyleRule` 对象的 `CSSPropertyValueSet` 中。

**假设输出:**  一个 `StyleRule` 对象，其内部数据结构大致如下：

```
StyleRule {
  type_: kStyle,
  selectors_: [ CSSSelector { ... selector data for "h1" ... } ],
  properties_: CSSPropertyValueSet {
    property_map_: {
      font_weight: CSSValue { ... value data for "bold" ... }
    }
  },
  lazy_property_parser_: nullptr,
  child_rules_: nullptr
}
```

**用户或编程常见的使用错误及举例说明:**

*   **CSS 语法错误:**  如果 CSS 样式表中存在语法错误，例如属性名拼写错误或缺少分号，CSS 解析器可能会失败，导致无法创建正确的 `StyleRule` 对象，或者创建的规则不完整。

    *   **示例:**  `h1 { font-weigth: bold; }` (拼写错误)。解析器可能会忽略这个规则或者创建一个不包含 `font-weight` 属性的 `StyleRule` 对象。

*   **JavaScript 操作 CSSOM 时的错误:**  在 JavaScript 中尝试访问或修改不存在的 CSS 规则或属性，可能会导致错误或不预期的行为。

    *   **示例:**  尝试访问一个不存在的选择器的样式：
        ```javascript
        const rule = Array.from(document.styleSheets[0].cssRules).find(r => r.selectorText === '.non-existent-class');
        if (rule) {
          rule.style.color = 'red'; // 如果 rule 为 undefined，这里会报错
        }
        ```

*   **类型转换错误:** 在 Blink 内部代码中，如果对 `StyleRuleBase` 指针进行错误的类型转换，可能会导致程序崩溃或出现未定义行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中输入网址或点击链接:**  浏览器开始加载网页的 HTML 内容。
2. **浏览器解析 HTML:**  解析器遇到 `<link>` 标签引用的外部 CSS 文件或 `<style>` 标签内的内联 CSS。
3. **CSS 解析:**  Blink 的 CSS 解析器（通常在 `css_parser.cc` 等文件中）读取 CSS 代码，并将其分解为词法单元（tokens）。
4. **创建 `StyleRuleBase` 对象:**  根据解析得到的 CSS 规则类型，创建相应的 `StyleRuleBase` 子类对象，例如 `StyleRule`、`StyleRuleMedia` 等。这个过程会调用 `style_rule.cc` 中定义的构造函数。
5. **构建样式表对象模型:** 创建的 `StyleRuleBase` 对象被添加到 `CSSStyleSheet` 对象中，形成 CSSOM 的内部表示。
6. **样式计算:**  Blink 的样式计算模块会遍历 DOM 树和 CSSOM，根据选择器匹配规则，计算出每个 HTML 元素的最终样式。
7. **渲染:**  最终的样式信息被用于渲染网页内容。

**作为调试线索:**  如果开发者在调试过程中遇到与 CSS 样式应用相关的问题，例如样式没有生效、样式被覆盖、或者在 JavaScript 操作 CSSOM 时出现错误，那么他们可能会需要检查 `style_rule.cc` 中的代码，以了解 CSS 规则是如何被表示和处理的。例如，他们可能会：

*   **设置断点:** 在 `StyleRule` 或其子类的构造函数中设置断点，查看是否创建了预期的 CSS 规则对象，以及对象内部的数据是否正确。
*   **查看 `CreateCSSOMWrapper` 的调用:**  检查何时以及如何将 C++ 的 `StyleRuleBase` 对象转换为 JavaScript 可以访问的 `CSSRule` 对象，以排查 CSSOM 交互中的问题。
*   **分析垃圾回收过程:** 检查 `Trace` 和 `FinalizeGarbageCollectedObject` 方法，了解 CSS 规则对象是如何被垃圾回收的，以及是否存在内存泄漏的风险。

### 提示词
```
这是目录为blink/renderer/core/css/style_rule.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * (C) 2002-2003 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2002, 2005, 2006, 2008, 2012 Apple Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/style_rule.h"

#include "third_party/blink/renderer/core/css/cascade_layer.h"
#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_counter_style_rule.h"
#include "third_party/blink/renderer/core/css/css_font_face_rule.h"
#include "third_party/blink/renderer/core/css/css_font_feature_values_rule.h"
#include "third_party/blink/renderer/core/css/css_font_palette_values_rule.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_layer_block_rule.h"
#include "third_party/blink/renderer/core/css/css_layer_statement_rule.h"
#include "third_party/blink/renderer/core/css/css_margin_rule.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_namespace_rule.h"
#include "third_party/blink/renderer/core/css/css_nested_declarations_rule.h"
#include "third_party/blink/renderer/core/css/css_page_rule.h"
#include "third_party/blink/renderer/core/css/css_position_try_rule.h"
#include "third_party/blink/renderer/core/css/css_property_rule.h"
#include "third_party/blink/renderer/core/css/css_scope_rule.h"
#include "third_party/blink/renderer/core/css/css_starting_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_supports_rule.h"
#include "third_party/blink/renderer/core/css/css_view_transition_rule.h"
#include "third_party/blink/renderer/core/css/parser/container_query_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_supports_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/style_rule_counter_style.h"
#include "third_party/blink/renderer/core/css/style_rule_font_feature_values.h"
#include "third_party/blink/renderer/core/css/style_rule_font_palette_values.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_keyframe.h"
#include "third_party/blink/renderer/core/css/style_rule_namespace.h"
#include "third_party/blink/renderer/core/css/style_rule_nested_declarations.h"
#include "third_party/blink/renderer/core/css/style_rule_view_transition.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

struct SameSizeAsStyleRuleBase final
    : public GarbageCollected<SameSizeAsStyleRuleBase> {
  uint8_t field;
};

ASSERT_SIZE(StyleRuleBase, SameSizeAsStyleRuleBase);

CSSRule* StyleRuleBase::CreateCSSOMWrapper(wtf_size_t position_hint,
                                           CSSStyleSheet* parent_sheet,
                                           bool trigger_use_counters) const {
  return CreateCSSOMWrapper(position_hint, parent_sheet, nullptr,
                            trigger_use_counters);
}

CSSRule* StyleRuleBase::CreateCSSOMWrapper(wtf_size_t position_hint,
                                           CSSRule* parent_rule,
                                           bool trigger_use_counters) const {
  return CreateCSSOMWrapper(position_hint, nullptr, parent_rule,
                            trigger_use_counters);
}

void StyleRuleBase::Trace(Visitor* visitor) const {
  switch (GetType()) {
    case kCharset:
      To<StyleRuleCharset>(this)->TraceAfterDispatch(visitor);
      return;
    case kStyle:
      To<StyleRule>(this)->TraceAfterDispatch(visitor);
      return;
    case kPage:
      To<StyleRulePage>(this)->TraceAfterDispatch(visitor);
      return;
    case kPageMargin:
      To<StyleRulePageMargin>(this)->TraceAfterDispatch(visitor);
      return;
    case kProperty:
      To<StyleRuleProperty>(this)->TraceAfterDispatch(visitor);
      return;
    case kFontFace:
      To<StyleRuleFontFace>(this)->TraceAfterDispatch(visitor);
      return;
    case kFontPaletteValues:
      To<StyleRuleFontPaletteValues>(this)->TraceAfterDispatch(visitor);
      return;
    case kFontFeatureValues:
      To<StyleRuleFontFeatureValues>(this)->TraceAfterDispatch(visitor);
      return;
    case kFontFeature:
      To<StyleRuleFontFeature>(this)->TraceAfterDispatch(visitor);
      return;
    case kMedia:
      To<StyleRuleMedia>(this)->TraceAfterDispatch(visitor);
      return;
    case kNestedDeclarations:
      To<StyleRuleNestedDeclarations>(this)->TraceAfterDispatch(visitor);
      return;
    case kScope:
      To<StyleRuleScope>(this)->TraceAfterDispatch(visitor);
      return;
    case kSupports:
      To<StyleRuleSupports>(this)->TraceAfterDispatch(visitor);
      return;
    case kImport:
      To<StyleRuleImport>(this)->TraceAfterDispatch(visitor);
      return;
    case kKeyframes:
      To<StyleRuleKeyframes>(this)->TraceAfterDispatch(visitor);
      return;
    case kKeyframe:
      To<StyleRuleKeyframe>(this)->TraceAfterDispatch(visitor);
      return;
    case kLayerBlock:
      To<StyleRuleLayerBlock>(this)->TraceAfterDispatch(visitor);
      return;
    case kLayerStatement:
      To<StyleRuleLayerStatement>(this)->TraceAfterDispatch(visitor);
      return;
    case kNamespace:
      To<StyleRuleNamespace>(this)->TraceAfterDispatch(visitor);
      return;
    case kContainer:
      To<StyleRuleContainer>(this)->TraceAfterDispatch(visitor);
      return;
    case kCounterStyle:
      To<StyleRuleCounterStyle>(this)->TraceAfterDispatch(visitor);
      return;
    case kStartingStyle:
      To<StyleRuleStartingStyle>(this)->TraceAfterDispatch(visitor);
      return;
    case kViewTransition:
      To<StyleRuleViewTransition>(this)->TraceAfterDispatch(visitor);
      return;
    case kFunction:
      To<StyleRuleFunction>(this)->TraceAfterDispatch(visitor);
      return;
    case kMixin:
      To<StyleRuleMixin>(this)->TraceAfterDispatch(visitor);
      return;
    case kApplyMixin:
      To<StyleRuleApplyMixin>(this)->TraceAfterDispatch(visitor);
      return;
    case kPositionTry:
      To<StyleRulePositionTry>(this)->TraceAfterDispatch(visitor);
      return;
  }
  DUMP_WILL_BE_NOTREACHED();
}

void StyleRuleBase::FinalizeGarbageCollectedObject() {
  switch (GetType()) {
    case kCharset:
      To<StyleRuleCharset>(this)->~StyleRuleCharset();
      return;
    case kStyle:
      To<StyleRule>(this)->~StyleRule();
      return;
    case kPage:
      To<StyleRulePage>(this)->~StyleRulePage();
      return;
    case kPageMargin:
      To<StyleRulePageMargin>(this)->~StyleRulePageMargin();
      return;
    case kProperty:
      To<StyleRuleProperty>(this)->~StyleRuleProperty();
      return;
    case kFontFace:
      To<StyleRuleFontFace>(this)->~StyleRuleFontFace();
      return;
    case kFontPaletteValues:
      To<StyleRuleFontPaletteValues>(this)->~StyleRuleFontPaletteValues();
      return;
    case kFontFeatureValues:
      To<StyleRuleFontFeatureValues>(this)->~StyleRuleFontFeatureValues();
      return;
    case kFontFeature:
      To<StyleRuleFontFeature>(this)->~StyleRuleFontFeature();
      return;
    case kMedia:
      To<StyleRuleMedia>(this)->~StyleRuleMedia();
      return;
    case kNestedDeclarations:
      To<StyleRuleNestedDeclarations>(this)->~StyleRuleNestedDeclarations();
      return;
    case kScope:
      To<StyleRuleScope>(this)->~StyleRuleScope();
      return;
    case kSupports:
      To<StyleRuleSupports>(this)->~StyleRuleSupports();
      return;
    case kImport:
      To<StyleRuleImport>(this)->~StyleRuleImport();
      return;
    case kKeyframes:
      To<StyleRuleKeyframes>(this)->~StyleRuleKeyframes();
      return;
    case kKeyframe:
      To<StyleRuleKeyframe>(this)->~StyleRuleKeyframe();
      return;
    case kLayerBlock:
      To<StyleRuleLayerBlock>(this)->~StyleRuleLayerBlock();
      return;
    case kLayerStatement:
      To<StyleRuleLayerStatement>(this)->~StyleRuleLayerStatement();
      return;
    case kNamespace:
      To<StyleRuleNamespace>(this)->~StyleRuleNamespace();
      return;
    case kContainer:
      To<StyleRuleContainer>(this)->~StyleRuleContainer();
      return;
    case kCounterStyle:
      To<StyleRuleCounterStyle>(this)->~StyleRuleCounterStyle();
      return;
    case kStartingStyle:
      To<StyleRuleStartingStyle>(this)->~StyleRuleStartingStyle();
      return;
    case kViewTransition:
      To<StyleRuleViewTransition>(this)->~StyleRuleViewTransition();
      return;
    case kFunction:
      To<StyleRuleFunction>(this)->~StyleRuleFunction();
      return;
    case kMixin:
      To<StyleRuleMixin>(this)->~StyleRuleMixin();
      return;
    case kApplyMixin:
      To<StyleRuleApplyMixin>(this)->~StyleRuleApplyMixin();
      return;
    case kPositionTry:
      To<StyleRulePositionTry>(this)->~StyleRulePositionTry();
      return;
  }
  NOTREACHED();
}

StyleRuleBase* StyleRuleBase::Copy() const {
  switch (GetType()) {
    case kStyle:
      return To<StyleRule>(this)->Copy();
    case kPage:
      return To<StyleRulePage>(this)->Copy();
    case kPageMargin:
      return To<StyleRulePageMargin>(this)->Copy();
    case kProperty:
      return To<StyleRuleProperty>(this)->Copy();
    case kFontFace:
      return To<StyleRuleFontFace>(this)->Copy();
    case kFontPaletteValues:
      return To<StyleRuleFontPaletteValues>(this)->Copy();
    case kFontFeatureValues:
      return To<StyleRuleFontFeatureValues>(this)->Copy();
    case kFontFeature:
      return To<StyleRuleFontFeature>(this)->Copy();
    case kMedia:
      return To<StyleRuleMedia>(this)->Copy();
    case kNestedDeclarations:
      return To<StyleRuleNestedDeclarations>(this)->Copy();
    case kScope:
      return To<StyleRuleScope>(this)->Copy();
    case kSupports:
      return To<StyleRuleSupports>(this)->Copy();
    case kImport:
      // FIXME: Copy import rules.
      NOTREACHED();
    case kKeyframes:
      return To<StyleRuleKeyframes>(this)->Copy();
    case kLayerBlock:
      return To<StyleRuleLayerBlock>(this)->Copy();
    case kLayerStatement:
      return To<StyleRuleLayerStatement>(this)->Copy();
    case kNamespace:
      return To<StyleRuleNamespace>(this)->Copy();
    case kCharset:
    case kKeyframe:
    case kFunction:
    case kMixin:
    case kApplyMixin:
      NOTREACHED();
    case kContainer:
      return To<StyleRuleContainer>(this)->Copy();
    case kCounterStyle:
      return To<StyleRuleCounterStyle>(this)->Copy();
    case kStartingStyle:
      return To<StyleRuleStartingStyle>(this)->Copy();
    case kViewTransition:
      return To<StyleRuleViewTransition>(this)->Copy();
    case kPositionTry:
      return To<StyleRulePositionTry>(this)->Copy();
  }
  NOTREACHED();
}

CSSRule* StyleRuleBase::CreateCSSOMWrapper(wtf_size_t position_hint,
                                           CSSStyleSheet* parent_sheet,
                                           CSSRule* parent_rule,
                                           bool trigger_use_counters) const {
  CSSRule* rule = nullptr;
  StyleRuleBase* self = const_cast<StyleRuleBase*>(this);
  switch (GetType()) {
    case kStyle:
      rule = MakeGarbageCollected<CSSStyleRule>(To<StyleRule>(self),
                                                parent_sheet, position_hint);
      break;
    case kPage:
      if (trigger_use_counters && parent_sheet) {
        UseCounter::Count(parent_sheet->OwnerDocument(),
                          WebFeature::kCSSPageRule);
      }
      rule = MakeGarbageCollected<CSSPageRule>(To<StyleRulePage>(self),
                                               parent_sheet);
      break;
    case kPageMargin:
      rule = MakeGarbageCollected<CSSMarginRule>(To<StyleRulePageMargin>(self),
                                                 parent_sheet);
      break;
    case kProperty:
      rule = MakeGarbageCollected<CSSPropertyRule>(To<StyleRuleProperty>(self),
                                                   parent_sheet);
      break;
    case kFontFace:
      rule = MakeGarbageCollected<CSSFontFaceRule>(To<StyleRuleFontFace>(self),
                                                   parent_sheet);
      break;
    case kFontPaletteValues:
      rule = MakeGarbageCollected<CSSFontPaletteValuesRule>(
          To<StyleRuleFontPaletteValues>(self), parent_sheet);
      break;
    case kFontFeatureValues:
      rule = MakeGarbageCollected<CSSFontFeatureValuesRule>(
          To<StyleRuleFontFeatureValues>(self), parent_sheet);
      break;
    case kMedia:
      rule = MakeGarbageCollected<CSSMediaRule>(To<StyleRuleMedia>(self),
                                                parent_sheet);
      break;
    case kNestedDeclarations:
      rule = MakeGarbageCollected<CSSNestedDeclarationsRule>(
          To<StyleRuleNestedDeclarations>(self), parent_sheet);
      break;
    case kScope:
      rule = MakeGarbageCollected<CSSScopeRule>(To<StyleRuleScope>(self),
                                                parent_sheet);
      break;
    case kSupports:
      rule = MakeGarbageCollected<CSSSupportsRule>(To<StyleRuleSupports>(self),
                                                   parent_sheet);
      break;
    case kImport:
      rule = MakeGarbageCollected<CSSImportRule>(To<StyleRuleImport>(self),
                                                 parent_sheet);
      break;
    case kKeyframes:
      rule = MakeGarbageCollected<CSSKeyframesRule>(
          To<StyleRuleKeyframes>(self), parent_sheet);
      break;
    case kLayerBlock:
      rule = MakeGarbageCollected<CSSLayerBlockRule>(
          To<StyleRuleLayerBlock>(self), parent_sheet);
      break;
    case kLayerStatement:
      rule = MakeGarbageCollected<CSSLayerStatementRule>(
          To<StyleRuleLayerStatement>(self), parent_sheet);
      break;
    case kNamespace:
      rule = MakeGarbageCollected<CSSNamespaceRule>(
          To<StyleRuleNamespace>(self), parent_sheet);
      break;
    case kContainer:
      rule = MakeGarbageCollected<CSSContainerRule>(
          To<StyleRuleContainer>(self), parent_sheet);
      break;
    case kCounterStyle:
      rule = MakeGarbageCollected<CSSCounterStyleRule>(
          To<StyleRuleCounterStyle>(self), parent_sheet);
      break;
    case kStartingStyle:
      rule = MakeGarbageCollected<CSSStartingStyleRule>(
          To<StyleRuleStartingStyle>(self), parent_sheet);
      break;
    case kViewTransition:
      rule = MakeGarbageCollected<CSSViewTransitionRule>(
          To<StyleRuleViewTransition>(self), parent_sheet);
      break;
    case kPositionTry:
      rule = MakeGarbageCollected<CSSPositionTryRule>(
          To<StyleRulePositionTry>(self), parent_sheet);
      break;
    case kFontFeature:
    case kKeyframe:
    case kCharset:
    case kFunction:
    case kMixin:
    case kApplyMixin:
      NOTREACHED();
  }
  if (parent_rule) {
    rule->SetParentRule(parent_rule);
  }
  return rule;
}

unsigned StyleRule::AverageSizeInBytes() {
  return sizeof(StyleRule) + sizeof(CSSSelector) +
         CSSPropertyValueSet::AverageSizeInBytes();
}

StyleRule::StyleRule(base::PassKey<StyleRule>,
                     base::span<CSSSelector> selector_vector,
                     CSSPropertyValueSet* properties)
    : StyleRuleBase(kStyle), properties_(properties) {
  CSSSelectorList::AdoptSelectorVector(selector_vector, SelectorArray());
}

StyleRule::StyleRule(base::PassKey<StyleRule>,
                     base::span<CSSSelector> selector_vector,
                     CSSLazyPropertyParser* lazy_property_parser)
    : StyleRuleBase(kStyle), lazy_property_parser_(lazy_property_parser) {
  CSSSelectorList::AdoptSelectorVector(selector_vector, SelectorArray());
}

StyleRule::StyleRule(base::PassKey<StyleRule>,
                     base::span<CSSSelector> selector_vector)
    : StyleRuleBase(kStyle) {
  CSSSelectorList::AdoptSelectorVector(selector_vector, SelectorArray());
}

StyleRule::StyleRule(base::PassKey<StyleRule>,
                     base::span<CSSSelector> selector_vector,
                     StyleRule&& other)
    : StyleRuleBase(kStyle),
      properties_(other.properties_),
      lazy_property_parser_(other.lazy_property_parser_),
      child_rules_(std::move(other.child_rules_)) {
  CSSSelectorList::AdoptSelectorVector(selector_vector, SelectorArray());
}

const CSSPropertyValueSet& StyleRule::Properties() const {
  if (!properties_) {
    properties_ = lazy_property_parser_->ParseProperties();
    lazy_property_parser_.Clear();
  }
  return *properties_;
}

StyleRule::StyleRule(const StyleRule& other, size_t flattened_size)
    : StyleRuleBase(kStyle), properties_(other.Properties().MutableCopy()) {
  for (unsigned i = 0; i < flattened_size; ++i) {
    new (&SelectorArray()[i]) CSSSelector(other.SelectorArray()[i]);
  }
  if (other.child_rules_ != nullptr) {
    // Since we are getting copied, we also need to copy any child rules
    // so that both old and new can be freely mutated. This also
    // parses them eagerly (see comment in StyleSheetContents'
    // copy constructor).
    child_rules_ = MakeGarbageCollected<HeapVector<Member<StyleRuleBase>>>();
    child_rules_->ReserveInitialCapacity(other.child_rules_->size());
    for (const StyleRuleBase* child_rule : *other.child_rules_) {
      child_rules_->push_back(child_rule->Copy());
    }
  }
}

StyleRule::~StyleRule() {
  // Clean up any RareData that the selectors may be owning.
  CSSSelector* selector = SelectorArray();
  for (;;) {
    bool is_last = selector->IsLastInSelectorList();
    selector->~CSSSelector();
    if (is_last) {
      break;
    } else {
      ++selector;
    }
  }
}

MutableCSSPropertyValueSet& StyleRule::MutableProperties() {
  // Ensure properties_ is initialized.
  if (!Properties().IsMutable()) {
    properties_ = properties_->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(properties_.Get());
}

bool StyleRule::PropertiesHaveFailedOrCanceledSubresources() const {
  return properties_ && properties_->HasFailedOrCanceledSubresources();
}

bool StyleRule::HasParsedProperties() const {
  // StyleRule should only have one of {lazy_property_parser_, properties_} set.
  DCHECK(lazy_property_parser_ || properties_);
  DCHECK(!lazy_property_parser_ || !properties_);
  return !lazy_property_parser_;
}

void StyleRule::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(properties_);
  visitor->Trace(lazy_property_parser_);
  visitor->Trace(child_rules_);

  const CSSSelector* current = SelectorArray();
  do {
    visitor->Trace(*current);
  } while (!(current++)->IsLastInSelectorList());

  StyleRuleBase::TraceAfterDispatch(visitor);
}

void StyleRuleBase::Reparent(StyleRule* new_parent) {
  switch (GetType()) {
    case kStyle:
      CSSSelectorList::Reparent(To<StyleRule>(this)->SelectorArray(),
                                new_parent);
      break;
    case kScope:
    case kLayerBlock:
    case kContainer:
    case kMedia:
    case kSupports:
    case kStartingStyle:
      for (StyleRuleBase* child :
           DynamicTo<StyleRuleGroup>(this)->ChildRules()) {
        child->Reparent(new_parent);
      }
      break;
    case kPage:
      for (StyleRuleBase* child :
           DynamicTo<StyleRulePage>(this)->ChildRules()) {
        child->Reparent(new_parent);
      }
      break;
    case kMixin:
    case kApplyMixin:
      // The parent pointers in mixins don't really matter;
      // they are always replaced during application anyway.
      break;
    case kNestedDeclarations:
      // CSSNestedDeclarations rules hold a *copy* of their parent
      // selector instead of just referencing them with '&'.
      DynamicTo<StyleRuleNestedDeclarations>(this)->ReplaceSelectorList(
          new_parent->SelectorArray());
      break;
    case kPageMargin:
    case kProperty:
    case kFontFace:
    case kFontPaletteValues:
    case kFontFeatureValues:
    case kFontFeature:
    case kImport:
    case kKeyframes:
    case kLayerStatement:
    case kNamespace:
    case kCounterStyle:
    case kKeyframe:
    case kCharset:
    case kViewTransition:
    case kFunction:
    case kPositionTry:
      // Cannot have any child rules.
      break;
  }
}

StyleRuleProperty::StyleRuleProperty(const String& name,
                                     CSSPropertyValueSet* properties)
    : StyleRuleBase(kProperty), name_(name), properties_(properties) {}

StyleRuleProperty::StyleRuleProperty(const StyleRuleProperty& property_rule)
    : StyleRuleBase(property_rule),
      name_(property_rule.name_),
      properties_(property_rule.properties_->MutableCopy()) {}

MutableCSSPropertyValueSet& StyleRuleProperty::MutableProperties() {
  if (!properties_->IsMutable()) {
    properties_ = properties_->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(properties_.Get());
}

const CSSValue* StyleRuleProperty::GetSyntax() const {
  return properties_->GetPropertyCSSValue(CSSPropertyID::kSyntax);
}

const CSSValue* StyleRuleProperty::Inherits() const {
  return properties_->GetPropertyCSSValue(CSSPropertyID::kInherits);
}

const CSSValue* StyleRuleProperty::GetInitialValue() const {
  return properties_->GetPropertyCSSValue(CSSPropertyID::kInitialValue);
}

bool StyleRuleProperty::SetNameText(const ExecutionContext* execution_context,
                                    const String& name_text) {
  DCHECK(!name_text.IsNull());
  String name = CSSParser::ParseCustomPropertyName(name_text);
  if (!name)
    return false;

  name_ = name;
  return true;
}

void StyleRuleProperty::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(properties_);
  visitor->Trace(layer_);
  StyleRuleBase::TraceAfterDispatch(visitor);
}

StyleRuleFontFace::StyleRuleFontFace(CSSPropertyValueSet* properties)
    : StyleRuleBase(kFontFace), properties_(properties) {}

StyleRuleFontFace::StyleRuleFontFace(const StyleRuleFontFace& font_face_rule)
    : StyleRuleBase(font_face_rule),
      properties_(font_face_rule.properties_->MutableCopy()) {}

MutableCSSPropertyValueSet& StyleRuleFontFace::MutableProperties() {
  if (!properties_->IsMutable()) {
    properties_ = properties_->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(properties_.Get());
}

void StyleRuleFontFace::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(properties_);
  visitor->Trace(layer_);
  StyleRuleBase::TraceAfterDispatch(visitor);
}

StyleRuleScope::StyleRuleScope(const StyleScope& style_scope,
                               HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleGroup(kScope, std::move(rules)), style_scope_(&style_scope) {}

StyleRuleScope::StyleRuleScope(const StyleRuleScope& other)
    : StyleRuleGroup(other),
      style_scope_(MakeGarbageCollected<StyleScope>(*other.style_scope_)) {}

void StyleRuleScope::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(style_scope_);
  StyleRuleGroup::TraceAfterDispatch(visitor);
}

void StyleRuleScope::SetPreludeText(const ExecutionContext* execution_context,
                                    String value,
                                    CSSNestingType nesting_type,
                                    StyleRule* parent_rule_for_nesting,
                                    bool is_within_scope,
                                    StyleSheetContents* style_sheet) {
  auto* parser_context =
      MakeGarbageCollected<CSSParserContext>(*execution_context);
  CSSParserTokenStream stream(value);

  style_scope_ =
      StyleScope::Parse(stream, parser_context, nesting_type,
                        parent_rule_for_nesting, is_within_scope, style_sheet);
  if (!stream.AtEnd()) {
    style_scope_ = nullptr;
  }

  // Reparent rules within the @scope's body.
  Reparent(style_scope_->RuleForNesting());
}

StyleRuleGroup::StyleRuleGroup(RuleType type,
                               HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleBase(type), child_rules_(std::move(rules)) {}

StyleRuleGroup::StyleRuleGroup(const StyleRuleGroup& group_rule)
    : StyleRuleBase(group_rule), child_rules_(group_rule.child_rules_.size()) {
  for (unsigned i = 0; i < child_rules_.size(); ++i) {
    child_rules_[i] = group_rule.child_rules_[i]->Copy();
  }
}

void StyleRuleGroup::WrapperInsertRule(CSSStyleSheet* parent_sheet,
                                       unsigned index,
                                       StyleRuleBase* rule) {
  child_rules_.insert(index, rule);
  if (parent_sheet) {
    parent_sheet->Contents()->NotifyRuleChanged(rule);
  }
}

void StyleRuleGroup::WrapperRemoveRule(CSSStyleSheet* parent_sheet,
                                       unsigned index) {
  if (parent_sheet) {
    parent_sheet->Contents()->NotifyRuleChanged(child_rules_[index]);
  }
  child_rules_.EraseAt(index);
}

void StyleRuleGroup::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(child_rules_);
  StyleRuleBase::TraceAfterDispatch(visitor);
}

// static
String StyleRuleBase::LayerNameAsString(
    const StyleRuleBase::LayerName& name_parts) {
  StringBuilder result;
  for (const auto& part : name_parts) {
    if (result.length()) {
      result.Append(".");
    }
    SerializeIdentifier(part, result);
  }
  return result.ReleaseString();
}

StyleRuleLayerBlock::StyleRuleLayerBlock(
    LayerName&& name,
    HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleGroup(kLayerBlock, std::move(rules)), name_(std::move(name)) {}

StyleRuleLayerBlock::StyleRuleLayerBlock(const StyleRuleLayerBlock& other) =
    default;

void StyleRuleLayerBlock::TraceAfterDispatch(blink::Visitor* visitor) const {
  StyleRuleGroup::TraceAfterDispatch(visitor);
}

String StyleRuleLayerBlock::GetNameAsString() const {
  return LayerNameAsString(name_);
}

StyleRuleLayerStatement::StyleRuleLayerStatement(Vector<LayerName>&& names)
    : StyleRuleBase(kLayerStatement), names_(std::move(names)) {}

StyleRuleLayerStatement::StyleRuleLayerStatement(
    const StyleRuleLayerStatement& other) = default;

void StyleRuleLayerStatement::TraceAfterDispatch(
    blink::Visitor* visitor) const {
  StyleRuleBase::TraceAfterDispatch(visitor);
}

Vector<String> StyleRuleLayerStatement::GetNamesAsStrings() const {
  Vector<String> result;
  for (const auto& name : names_) {
    result.push_back(LayerNameAsString(name));
  }
  return result;
}

StyleRulePage::StyleRulePage(CSSSelectorList* selector_list,
                             CSSPropertyValueSet* properties,
                             HeapVector<Member<StyleRuleBase>> child_rules)
    : StyleRuleGroup(kPage, std::move(child_rules)),
      properties_(properties),
      selector_list_(selector_list) {}

StyleRulePage::StyleRulePage(const StyleRulePage& page_rule)
    : StyleRuleGroup(page_rule),
      properties_(page_rule.properties_->MutableCopy()),
      selector_list_(page_rule.selector_list_->Copy()) {}

MutableCSSPropertyValueSet& StyleRulePage::MutableProperties() {
  if (!properties_->IsMutable()) {
    properties_ = properties_->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(properties_.Get());
}

void StyleRulePage::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(properties_);
  visitor->Trace(layer_);
  visitor->Trace(selector_list_);
  StyleRuleGroup::TraceAfterDispatch(visitor);
}

StyleRulePageMargin::StyleRulePageMargin(CSSAtRuleID id,
                                         CSSPropertyValueSet* properties)
    : StyleRuleBase(kPageMargin), id_(id), properties_(properties) {}

StyleRulePageMargin::StyleRulePageMargin(
    const StyleRulePageMargin& page_margin_rule)
    : StyleRuleBase(page_margin_rule),
      properties_(page_margin_rule.properties_->MutableCopy()) {}

MutableCSSPropertyValueSet& StyleRulePageMargin::MutableProperties() {
  if (!properties_->IsMutable()) {
    properties_ = properties_->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(properties_.Get());
}

void StyleRulePageMargin::TraceAfterDispatch(blink::Visitor* visitor) const {
  visitor->Trace(properties_);
  StyleRuleBase::TraceAfterDispatch(visitor);
}

StyleRuleCondition::StyleRuleCondition(RuleType type,
                                       HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleGroup(type, std::move(rules)) {}

StyleRuleCondition::StyleRuleCondition(RuleType type,
                                       const String& condition_text,
                                       HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleGroup(type, std::move(rules)), condition_text_(condition_text) {}

StyleRuleCondition::StyleRuleCondition(
    const StyleRuleCondition& condition_rule) = default;

StyleRuleMedia::StyleRuleMedia(const MediaQuerySet* media,
                               HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleCondition(kMedia, std::move(rules)), media_queries_(media) {}

void StyleRuleMedia::TraceAfterDispatch(blink::Visitor* visitor) const {
  StyleRuleCondition::TraceAfterDispatch(visitor);
  visitor->Trace(media_queries_);
}

StyleRuleSupports::StyleRuleSupports(const String& condition_text,
                                     bool condition_is_supported,
                                     HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleCondition(kSupports, condition_text, std::move(rules)),
      condition_is_supported_(condition_is_supported) {}

StyleRuleSupports::StyleRuleSupports(const StyleRuleSupports& supports_rule)
    : StyleRuleCondition(supports_rule),
      condition_is_supported_(supports_rule.condition_is_supported_) {}

void StyleRuleSupports::SetConditionText(
    const ExecutionContext* execution_context,
    String value) {
  CSSParserTokenStream stream(value);
  auto* context = MakeGarbageCollected<CSSParserContext>(*execution_context);
  CSSParserImpl parser(context);

  CSSSupportsParser::Result result =
      CSSSupportsParser::ConsumeSupportsCondition(stream, parser);
  condition_text_ = value;
  condition_is_supported_ = result == CSSSupportsParser::Result::kSupported;
}

StyleRuleContainer::StyleRuleContainer(ContainerQuery& container_query,
                                       HeapVector<Member<StyleRuleBase>> rules)
    : StyleRuleCondition(kContainer,
                         container_query.ToString(),
                         std::move(rules)),
      container_query_(&container_query) {}

StyleRuleContainer::StyleRuleContainer(const StyleRuleContainer& container_rule)
    : StyleRuleCondition(container_rule) {
  DCHECK(container_rule.container_query_);
  container_query_ =
      MakeGarbageCollected<ContainerQuery>(*container_rule.container_query_);
}

void StyleRuleContainer::SetConditionText(
    const ExecutionContext* execution_context,
    String value) {
  auto* context = MakeGarbageCollected<CSSParserContext>(*execution_context);
  ContainerQueryParser parser(*context);

  if (const MediaQueryExpNode* exp_node = parser.ParseCondit
```