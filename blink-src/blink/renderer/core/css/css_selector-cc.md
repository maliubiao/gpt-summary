Response:
The user wants a summary of the functionality of the `css_selector.cc` file in the Chromium Blink engine. I need to:

1. **Identify the core purpose of the file**: Based on the file name and included headers, it likely deals with the representation and manipulation of CSS selectors.
2. **Extract key functionalities**:  Look for methods and data structures that indicate the operations performed on CSS selectors. This includes creation, parsing, specificity calculation, and matching.
3. **Explain the relationship with web technologies**: Connect the functionality to how CSS selectors are used in HTML, CSS, and potentially JavaScript.
4. **Provide examples**: Illustrate the concepts with concrete examples of CSS selectors and how the code might process them.
5. **Consider user errors**: Think about common mistakes developers make with CSS selectors and how this code might be involved.
6. **Describe the user journey**: Outline the steps a user takes in a web browser that lead to the execution of this code.
7. **Focus on the first part**: Since this is the first part of a larger request, I need to provide a concise summary of the overall functionality covered by this code snippet.

**Overall Plan:**

- Identify the primary data structure: `CSSSelector` class.
- Summarize the key functionalities related to `CSSSelector`: creation, specificity calculation, pseudo-class/element handling.
- Explain the connection to CSS and HTML.
- Provide a high-level overview of the user interaction.
好的，根据提供的 Chromium Blink 引擎源代码文件 `blink/renderer/core/css/css_selector.cc` 的内容，其主要功能可以归纳如下：

**核心功能：表示和操作 CSS 选择器**

该文件定义了 `CSSSelector` 类及其相关功能，用于在 Blink 渲染引擎中表示和处理 CSS 选择器。这包括：

1. **选择器的创建和存储:**
   - 提供了多种构造函数来创建不同类型的 CSS 选择器，例如：
     - 标签选择器 (`kTag`)
     - 类选择器 (`kClass`)
     - ID 选择器 (`kId`)
     - 属性选择器 (`kAttributeSet`, `kAttributeExact` 等)
     - 伪类选择器 (`kPseudoClass`)
     - 伪元素选择器 (`kPseudoElement`)
   - 使用位域 (`bits_`) 和联合体 (`data_`) 来高效地存储选择器的各种属性，例如匹配类型、属性名、属性值、伪类/伪元素类型等。

2. **选择器的匹配类型:**
   - 定义了 `MatchType` 枚举，表示选择器的匹配方式，例如：`kTag` (标签名匹配)、`kClass` (类名匹配)、`kAttributeSet` (属性存在)、`kPseudoClass` (伪类匹配) 等。

3. **选择器的特异性计算:**
   - 实现了 `Specificity()` 方法来计算 CSS 选择器的特异性值。
   - 特异性用于确定在样式冲突时哪个样式规则会被应用。
   - `SpecificityForOneSelector()` 计算单个简单选择器的特异性。
   - `SpecificityForPage()` 计算 `@page` 规则内选择器的特异性。
   - 提供了 `SpecificityTuple()` 方法以元组的形式返回特异性值（a, b, c）。

4. **伪类和伪元素处理:**
   - 使用 `PseudoType` 枚举表示各种 CSS 伪类和伪元素。
   - 提供了 `GetPseudoType()` 方法获取选择器的伪类/伪元素类型。
   - 提供了 `GetPseudoId()` 方法将 `PseudoType` 映射到 `PseudoId`。
   - 提供了 `NameToPseudoType()` 函数，根据字符串名称判断是否是合法的伪类或伪元素，并返回对应的 `PseudoType`。

5. **选择器之间的关系:**
   - 使用 `Relation` 枚举表示选择器之间的关系（例如，后代选择器、子选择器等，但这部分在提供的代码片段中没有直接体现，但从 `kSubSelector` 的使用可以推断）。
   - 提供了 `NextSimpleSelector()` 方法来遍历复合选择器中的简单选择器。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:** 该文件直接负责处理 CSS 选择器的解析、表示和特异性计算。这是 CSS 样式应用的核心部分。
    * **举例:** 当 CSS 样式规则 ` .my-class { color: red; } ` 被解析时，会创建一个 `CSSSelector` 对象，其 `Match()` 类型为 `kClass`，`Value()` 为 "my-class"。
    * **举例:** 对于 CSS 样式规则 ` #my-id { font-size: 16px; } `，会创建一个 `CSSSelector` 对象，其 `Match()` 类型为 `kId`，`Value()` 为 "my-id"。
    * **举例:** 对于伪类选择器 `:hover`，会创建一个 `CSSSelector` 对象，其 `Match()` 类型为 `kPseudoClass`，`GetPseudoType()` 返回 `kPseudoHover`。
    * **举例:** 对于属性选择器 `[data-type="button"]`，会创建一个 `CSSSelector` 对象，其 `Match()` 类型为 `kAttributeExact`，`Attribute()` 为 "data-type"，`Argument()` 为 "button"。

* **HTML:** CSS 选择器的目标是 HTML 元素。`CSSSelector` 对象最终会用于匹配 HTML 文档中的元素，以确定哪些样式规则应该应用于哪些元素。
    * **举例:**  当浏览器遇到 HTML 元素 `<div class="my-class"></div>` 时，渲染引擎会使用之前创建的 `CSSSelector` 对象（针对 `.my-class`）来判断该元素是否匹配。

* **JavaScript:** JavaScript 可以通过 DOM API 获取和操作元素的样式。虽然该文件本身不直接涉及 JavaScript 代码的执行，但 JavaScript 代码的执行可能会触发样式的重新计算，从而间接地与 `CSSSelector` 的处理相关。例如，当 JavaScript 修改元素的 class 列表时，可能需要重新评估哪些 CSS 规则匹配该元素。
    * **举例:** JavaScript 代码 `document.querySelector('.my-class')` 会使用 CSS 选择器 `.my-class` 来查找 HTML 元素。Blink 引擎内部会使用 `CSSSelector` 相关的机制来执行这个查找过程。

**逻辑推理的假设输入与输出：**

假设输入一个 CSS 选择器字符串 ".example#test[data-attr='value']:hover::before"，则可能创建如下 `CSSSelector` 对象链（简化表示）：

* **::before**: `CSSSelector` ( `kPseudoElement`, `kPseudoBefore` )
* **:hover**: `CSSSelector` ( `kPseudoClass`, `kPseudoHover` )， `Relation` 为 `kSubSelector` (表示是前一个选择器的条件)
* **[data-attr='value']**: `CSSSelector` ( `kAttributeExact`, attribute: "data-attr", value: "value" )， `Relation` 为 `kSubSelector`
* **#test**: `CSSSelector` ( `kId`, value: "test" )， `Relation` 为 `kSubSelector`
* **.example**: `CSSSelector` ( `kClass`, value: "example" )， `Relation` 为 `kSubSelector`

输出：一个表示该复合选择器的 `CSSSelector` 对象链，每个对象存储了相应简单选择器的信息。调用 `Specificity()` 方法会返回该复合选择器的特异性值。

**用户或编程常见的使用错误：**

* **特异性理解错误:**  开发者可能不理解 CSS 选择器的特异性规则，导致样式被意外覆盖。例如，使用过于具体的选择器（例如 `div#container .item`) 可能会使后续的更通用的选择器无法生效。`Specificity()` 方法的计算逻辑是确保浏览器按照 CSS 规范正确处理特异性。
* **伪类/伪元素名称拼写错误或使用了不存在的伪类/伪元素:** `NameToPseudoType()` 函数会返回 `kPseudoUnknown`，帮助引擎识别并忽略这些无效的伪类/伪元素。
* **不正确的属性选择器语法:**  例如，属性值缺少引号或使用了不支持的匹配操作符。虽然此代码片段不直接处理语法解析，但它表示了不同类型的属性匹配 (`kAttributeExact`, `kAttributeContain` 等)，对应于不同的语法。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器加载 HTML 文档。**
3. **浏览器解析 HTML，构建 DOM 树。**
4. **浏览器加载并解析 CSS 样式表（外部 CSS 文件、`<style>` 标签、行内样式）。**
5. **CSS 解析器会遍历 CSS 规则，并创建 `CSSSelector` 对象来表示每个选择器。**  `css_selector.cc` 中的代码会被调用来创建和初始化这些 `CSSSelector` 对象。
6. **渲染引擎将 CSS 规则与 DOM 树中的元素进行匹配。** `CSSSelector` 对象的匹配逻辑会被使用。
7. **计算每个匹配规则的特异性。** `Specificity()` 方法会被调用。
8. **根据特异性和来源顺序，确定最终应用于每个元素的样式。**
9. **浏览器根据计算出的样式信息渲染网页。**

**功能归纳 (第1部分):**

该文件 `css_selector.cc` 的核心功能是定义了 `CSSSelector` 类，用于在 Blink 渲染引擎中 **表示和操作 CSS 选择器**。这包括创建各种类型的选择器，存储其属性（匹配类型、值、伪类/伪元素类型等），以及计算选择器的特异性。它是 CSS 样式处理流程中的关键组成部分，负责将 CSS 选择器转化为内部表示，以便后续与 HTML 元素进行匹配和应用样式。

Prompt: 
```
这是目录为blink/renderer/core/css/css_selector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 1999-2003 Lars Knoll (knoll@kde.org)
 *               1999 Waldo Bastian (bastian@kde.org)
 *               2001 Andreas Schlapbach (schlpbch@iam.unibe.ch)
 *               2001-2003 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2002, 2006, 2007, 2008, 2009, 2010 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2008 David Smith (catfish.man@gmail.com)
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/css_selector.h"

#include <algorithm>
#include <memory>

#include "style_rule.h"
#include "third_party/blink/renderer/core/css/css_markup.h"
#include "third_party/blink/renderer/core/css/css_selector_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/pseudo_element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

#if DCHECK_IS_ON()
#include <stdio.h>
#endif  // DCHECK_IS_ON()

namespace blink {

namespace {

constexpr bool kExpandPseudoParent = true;

unsigned MaximumSpecificity(const CSSSelectorList* list) {
  if (!list) {
    return 0;
  }
  return list->MaximumSpecificity();
}

}  // namespace

// Returns the maximum specificity across a selector list, only including
// the (complex) selectors for which the `predicate` returns true.
template <typename Predicate>
unsigned MaximumSpecificity(
    const CSSSelector* first_selector,
    Predicate predicate = [](const CSSSelector*) { return true; }) {
  unsigned specificity = 0;
  for (const CSSSelector* s = first_selector; s;
       s = CSSSelectorList::Next(*s)) {
    if (predicate(s)) {
      specificity = std::max(specificity, s->Specificity());
    }
  }
  return specificity;
}

struct SameSizeAsCSSSelector {
  unsigned bitfields;
  union {
    AtomicString value_;
    QualifiedName tag_q_name_or_attribute_;
    Member<void*> rare_data_;
  } pointers;
};

ASSERT_SIZE(CSSSelector, SameSizeAsCSSSelector);

CSSSelector::CSSSelector(MatchType match_type,
                         const QualifiedName& attribute,
                         AttributeMatchType case_sensitivity)
    : bits_(
          RelationField::encode(kSubSelector) | MatchField::encode(match_type) |
          PseudoTypeField::encode(kPseudoUnknown) |
          IsLastInSelectorListField::encode(false) |
          IsLastInComplexSelectorField::encode(false) |
          HasRareDataField::encode(false) | IsForPageField::encode(false) |
          IsImplicitlyAddedField::encode(false) |
          IsCoveredByBucketingField::encode(false) |
          AttributeMatchField::encode(static_cast<unsigned>(case_sensitivity)) |
          LegacyCaseInsensitiveMatchField::encode(
              !HTMLDocument::IsCaseSensitiveAttribute(attribute) &&
              case_sensitivity != AttributeMatchType::kCaseSensitiveAlways) |
          IsScopeContainingField::encode(false)),
      data_(attribute) {
  DCHECK_EQ(match_type, kAttributeSet);
}

CSSSelector::CSSSelector(MatchType match_type,
                         const QualifiedName& attribute,
                         AttributeMatchType case_sensitivity,
                         const AtomicString& value)
    : bits_(
          RelationField::encode(kSubSelector) |
          MatchField::encode(static_cast<unsigned>(match_type)) |
          PseudoTypeField::encode(kPseudoUnknown) |
          IsLastInSelectorListField::encode(false) |
          IsLastInComplexSelectorField::encode(false) |
          HasRareDataField::encode(true) | IsForPageField::encode(false) |
          IsImplicitlyAddedField::encode(false) |
          IsCoveredByBucketingField::encode(false) |
          AttributeMatchField::encode(static_cast<unsigned>(case_sensitivity)) |
          LegacyCaseInsensitiveMatchField::encode(
              !HTMLDocument::IsCaseSensitiveAttribute(attribute) &&
              case_sensitivity != AttributeMatchType::kCaseSensitiveAlways) |
          IsScopeContainingField::encode(false)),
      data_(MakeGarbageCollected<RareData>(value)) {
  DCHECK(IsAttributeSelector());
  data_.rare_data_->attribute_ = attribute;
}

void CSSSelector::CreateRareData() {
  DCHECK_NE(Match(), kTag);
  if (HasRareData()) {
    return;
  }
  // This transitions the DataUnion from |value_| to |rare_data_| and thus needs
  // to be careful to correctly manage explicitly destruction of |value_|
  // followed by placement new of |rare_data_|. A straight-assignment will
  // compile and may kinda work, but will be undefined behavior.
  auto* rare_data = MakeGarbageCollected<RareData>(data_.value_);
  data_.value_.~AtomicString();
  data_.rare_data_ = rare_data;
  bits_.set<HasRareDataField>(true);
}

unsigned CSSSelector::Specificity() const {
  if (IsForPage()) {
    return SpecificityForPage() & CSSSelector::kMaxValueMask;
  }

  unsigned total = 0;
  unsigned temp = 0;

  for (const CSSSelector* selector = this; selector;
       selector = selector->NextSimpleSelector()) {
    temp = total + selector->SpecificityForOneSelector();
    // Clamp each component to its max in the case of overflow.
    if ((temp & kIdMask) < (total & kIdMask)) {
      total |= kIdMask;
    } else if ((temp & kClassMask) < (total & kClassMask)) {
      total |= kClassMask;
    } else if ((temp & kElementMask) < (total & kElementMask)) {
      total |= kElementMask;
    } else {
      total = temp;
    }
  }
  return total;
}

std::array<uint8_t, 3> CSSSelector::SpecificityTuple() const {
  unsigned specificity = Specificity();

  uint8_t a = (specificity & kIdMask) >> 16;
  uint8_t b = (specificity & kClassMask) >> 8;
  uint8_t c = (specificity & kElementMask);

  return {a, b, c};
}

inline unsigned CSSSelector::SpecificityForOneSelector() const {
  // FIXME: Pseudo-elements and pseudo-classes do not have the same specificity.
  // This function isn't quite correct.
  // http://www.w3.org/TR/selectors/#specificity
  switch (Match()) {
    case kId:
      return kIdSpecificity;
    case kPseudoClass:
      switch (GetPseudoType()) {
        case kPseudoWhere:
          return 0;
        case kPseudoHost:
          if (!SelectorList()) {
            return kClassLikeSpecificity;
          }
          [[fallthrough]];
        case kPseudoHostContext:
          DCHECK(SelectorList()->IsSingleComplexSelector());
          return kClassLikeSpecificity + SelectorList()->First()->Specificity();
        case kPseudoNot:
          DCHECK(SelectorList());
          [[fallthrough]];
        case kPseudoIs:
          return MaximumSpecificity(SelectorList());
        case kPseudoHas:
          return MaximumSpecificity(SelectorList());
        case kPseudoParent:
          if (data_.parent_rule_ == nullptr) {
            // & in a non-nesting context matches nothing.
            return 0;
          }
          return MaximumSpecificity(
              data_.parent_rule_->FirstSelector(),
              [](const CSSSelector* selector) {
                return selector->IsAllowedInParentPseudo();
              });
        case kPseudoNthChild:
        case kPseudoNthLastChild:
          if (SelectorList()) {
            return kClassLikeSpecificity + MaximumSpecificity(SelectorList());
          } else {
            return kClassLikeSpecificity;
          }
        case kPseudoRelativeAnchor:
          return 0;
        case kPseudoScope:
          if (IsImplicit()) {
            // Implicit :scope pseudo-classes are added to selectors
            // within @scope. Such pseudo-classes must not have any effect
            // on the specificity of the scoped selector.
            //
            // https://drafts.csswg.org/css-cascade-6/#scope-effects
            return 0;
          }
          break;
        // FIXME: PseudoAny should base the specificity on the sub-selectors.
        // See http://lists.w3.org/Archives/Public/www-style/2010Sep/0530.html
        case kPseudoAny:
        default:
          break;
      }
      return kClassLikeSpecificity;
    case kPseudoElement:
      switch (GetPseudoType()) {
        case kPseudoSlotted:
          DCHECK(SelectorList()->IsSingleComplexSelector());
          return kTagSpecificity + SelectorList()->First()->Specificity();
        case kPseudoViewTransitionGroup:
        case kPseudoViewTransitionImagePair:
        case kPseudoViewTransitionOld:
        case kPseudoViewTransitionNew: {
          CHECK(!IdentList().empty());
          return (IdentList().size() == 1u && IdentList()[0].IsNull())
                     ? 0
                     : kTagSpecificity;
        }
        default:
          break;
      }
      return kTagSpecificity;
    case kClass:
    case kAttributeExact:
    case kAttributeSet:
    case kAttributeList:
    case kAttributeHyphen:
    case kAttributeContain:
    case kAttributeBegin:
    case kAttributeEnd:
      return kClassLikeSpecificity;
    case kTag:
      if (TagQName().LocalName() == UniversalSelectorAtom()) {
        return 0;
      }
      return kTagSpecificity;
    case kInvalidList:
    case kPagePseudoClass:
      NOTREACHED();
    case kUnknown:
      return 0;
  }
  NOTREACHED();
}

unsigned CSSSelector::SpecificityForPage() const {
  // See https://drafts.csswg.org/css-page/#cascading-and-page-context
  unsigned s = 0;

  for (const CSSSelector* component = this; component;
       component = component->NextSimpleSelector()) {
    switch (component->Match()) {
      case kTag:
        s += TagQName().LocalName() == UniversalSelectorAtom() ? 0 : 4;
        break;
      case kPagePseudoClass:
        switch (component->GetPseudoType()) {
          case kPseudoFirstPage:
            s += 2;
            break;
          case kPseudoLeftPage:
          case kPseudoRightPage:
            s += 1;
            break;
          default:
            NOTREACHED();
        }
        break;
      default:
        break;
    }
  }
  return s;
}

PseudoId CSSSelector::GetPseudoId(PseudoType type) {
  switch (type) {
    case kPseudoFirstLine:
      return kPseudoIdFirstLine;
    case kPseudoFirstLetter:
      return kPseudoIdFirstLetter;
    case kPseudoSelection:
      return kPseudoIdSelection;
    case kPseudoCheck:
      return kPseudoIdCheck;
    case kPseudoBefore:
      return kPseudoIdBefore;
    case kPseudoAfter:
      return kPseudoIdAfter;
    case kPseudoSelectArrow:
      return kPseudoIdSelectArrow;
    case kPseudoMarker:
      return kPseudoIdMarker;
    case kPseudoBackdrop:
      return kPseudoIdBackdrop;
    case kPseudoScrollbar:
      return kPseudoIdScrollbar;
    case kPseudoScrollMarker:
      return kPseudoIdScrollMarker;
    case kPseudoScrollMarkerGroup:
      return kPseudoIdScrollMarkerGroup;
    case kPseudoScrollNextButton:
      return kPseudoIdScrollNextButton;
    case kPseudoScrollPrevButton:
      return kPseudoIdScrollPrevButton;
    case kPseudoColumn:
      return kPseudoIdColumn;
    case kPseudoScrollbarButton:
      return kPseudoIdScrollbarButton;
    case kPseudoScrollbarCorner:
      return kPseudoIdScrollbarCorner;
    case kPseudoScrollbarThumb:
      return kPseudoIdScrollbarThumb;
    case kPseudoScrollbarTrack:
      return kPseudoIdScrollbarTrack;
    case kPseudoScrollbarTrackPiece:
      return kPseudoIdScrollbarTrackPiece;
    case kPseudoResizer:
      return kPseudoIdResizer;
    case kPseudoSearchText:
      return kPseudoIdSearchText;
    case kPseudoTargetText:
      return kPseudoIdTargetText;
    case kPseudoHighlight:
      return kPseudoIdHighlight;
    case kPseudoSpellingError:
      return kPseudoIdSpellingError;
    case kPseudoGrammarError:
      return kPseudoIdGrammarError;
    case kPseudoPlaceholder:
      return kPseudoIdPlaceholder;
    case kPseudoFileSelectorButton:
      return kPseudoIdFileSelectorButton;
    case kPseudoDetailsContent:
      return kPseudoIdDetailsContent;
    case kPseudoPicker:
      // NOTE: When we support more than one argument to ::picker() we will
      // need to refactor something here (possibly the callers of this method)
      // to account for this.
      return kPseudoIdPickerSelect;
    case kPseudoViewTransition:
      return kPseudoIdViewTransition;
    case kPseudoViewTransitionGroup:
      return kPseudoIdViewTransitionGroup;
    case kPseudoViewTransitionImagePair:
      return kPseudoIdViewTransitionImagePair;
    case kPseudoViewTransitionOld:
      return kPseudoIdViewTransitionOld;
    case kPseudoViewTransitionNew:
      return kPseudoIdViewTransitionNew;
    case kPseudoActive:
    case kPseudoActiveViewTransition:
    case kPseudoActiveViewTransitionType:
    case kPseudoAny:
    case kPseudoAnyLink:
    case kPseudoAutofill:
    case kPseudoAutofillPreviewed:
    case kPseudoAutofillSelected:
    case kPseudoBlinkInternalElement:
    case kPseudoChecked:
    case kPseudoClosed:
    case kPseudoCornerPresent:
    case kPseudoCue:
    case kPseudoCurrent:
    case kPseudoDecrement:
    case kPseudoDefault:
    case kPseudoDefined:
    case kPseudoDialogInTopLayer:
    case kPseudoDir:
    case kPseudoDisabled:
    case kPseudoDoubleButton:
    case kPseudoDrag:
    case kPseudoEmpty:
    case kPseudoEnabled:
    case kPseudoEnd:
    case kPseudoFirstChild:
    case kPseudoFirstOfType:
    case kPseudoFirstPage:
    case kPseudoFocus:
    case kPseudoFocusVisible:
    case kPseudoFocusWithin:
    case kPseudoFullPageMedia:
    case kPseudoFullScreen:
    case kPseudoFullScreenAncestor:
    case kPseudoFullscreen:
    case kPseudoFutureCue:
    case kPseudoHas:
    case kPseudoHasSlotted:
    case kPseudoHasDatalist:
    case kPseudoHorizontal:
    case kPseudoHost:
    case kPseudoHostContext:
    case kPseudoHostHasNonAutoAppearance:
    case kPseudoHover:
    case kPseudoInRange:
    case kPseudoIncrement:
    case kPseudoIndeterminate:
    case kPseudoInvalid:
    case kPseudoIs:
    case kPseudoIsHtml:
    case kPseudoLang:
    case kPseudoLastChild:
    case kPseudoLastOfType:
    case kPseudoLeftPage:
    case kPseudoLink:
    case kPseudoListBox:
    case kPseudoModal:
    case kPseudoMultiSelectFocus:
    case kPseudoNoButton:
    case kPseudoNot:
    case kPseudoNthChild:
    case kPseudoNthLastChild:
    case kPseudoNthLastOfType:
    case kPseudoNthOfType:
    case kPseudoOnlyChild:
    case kPseudoOnlyOfType:
    case kPseudoOpen:
    case kPseudoOptional:
    case kPseudoOutOfRange:
    case kPseudoParent:
    case kPseudoPart:
    case kPseudoPastCue:
    case kPseudoPaused:
    case kPseudoPermissionElementInvalidStyle:
    case kPseudoPermissionElementOccluded:
    case kPseudoPermissionGranted:
    case kPseudoPictureInPicture:
    case kPseudoPlaceholderShown:
    case kPseudoPlaying:
    case kPseudoPopoverInTopLayer:
    case kPseudoPopoverOpen:
    case kPseudoReadOnly:
    case kPseudoReadWrite:
    case kPseudoRelativeAnchor:
    case kPseudoRequired:
    case kPseudoRightPage:
    case kPseudoRoot:
    case kPseudoScope:
    case kPseudoSelectorFragmentAnchor:
    case kPseudoSingleButton:
    case kPseudoSlotted:
    case kPseudoSpatialNavigationFocus:
    case kPseudoStart:
    case kPseudoState:
    case kPseudoStateDeprecatedSyntax:
    case kPseudoTarget:
    case kPseudoUnknown:
    case kPseudoUnparsed:
    case kPseudoUserInvalid:
    case kPseudoUserValid:
    case kPseudoValid:
    case kPseudoVertical:
    case kPseudoVideoPersistent:
    case kPseudoVideoPersistentAncestor:
    case kPseudoVisited:
    case kPseudoWebKitAutofill:
    case kPseudoWebKitCustomElement:
    case kPseudoWebkitAnyLink:
    case kPseudoWhere:
    case kPseudoWindowInactive:
    case kPseudoXrOverlay:
      return kPseudoIdNone;
  }

  NOTREACHED();
}

void CSSSelector::Reparent(StyleRule* new_parent) {
  if (GetPseudoType() == CSSSelector::kPseudoParent) {
    data_.parent_rule_ = new_parent;
  } else if (HasRareData() && data_.rare_data_->selector_list_) {
    data_.rare_data_->selector_list_->Reparent(new_parent);
  }
}

// Could be made smaller and faster by replacing pointer with an
// offset into a string buffer and making the bit fields smaller but
// that could not be maintained by hand.
struct NameToPseudoStruct {
  const char* string;
  unsigned type : 8;
};

// These tables must be kept sorted.
constexpr static NameToPseudoStruct kPseudoTypeWithoutArgumentsMap[] = {
    {"-internal-autofill-previewed", CSSSelector::kPseudoAutofillPreviewed},
    {"-internal-autofill-selected", CSSSelector::kPseudoAutofillSelected},
    {"-internal-dialog-in-top-layer", CSSSelector::kPseudoDialogInTopLayer},
    {"-internal-has-datalist", CSSSelector::kPseudoHasDatalist},
    {"-internal-is-html", CSSSelector::kPseudoIsHtml},
    {"-internal-list-box", CSSSelector::kPseudoListBox},
    {"-internal-media-controls-overlay-cast-button",
     CSSSelector::kPseudoWebKitCustomElement},
    {"-internal-multi-select-focus", CSSSelector::kPseudoMultiSelectFocus},
    {"-internal-popover-in-top-layer", CSSSelector::kPseudoPopoverInTopLayer},
    {"-internal-relative-anchor", CSSSelector::kPseudoRelativeAnchor},
    {"-internal-selector-fragment-anchor",
     CSSSelector::kPseudoSelectorFragmentAnchor},
    {"-internal-shadow-host-has-non-auto-appearance",
     CSSSelector::kPseudoHostHasNonAutoAppearance},
    {"-internal-spatial-navigation-focus",
     CSSSelector::kPseudoSpatialNavigationFocus},
    {"-internal-video-persistent", CSSSelector::kPseudoVideoPersistent},
    {"-internal-video-persistent-ancestor",
     CSSSelector::kPseudoVideoPersistentAncestor},
    {"-webkit-any-link", CSSSelector::kPseudoWebkitAnyLink},
    {"-webkit-autofill", CSSSelector::kPseudoWebKitAutofill},
    {"-webkit-drag", CSSSelector::kPseudoDrag},
    {"-webkit-full-page-media", CSSSelector::kPseudoFullPageMedia},
    {"-webkit-full-screen", CSSSelector::kPseudoFullScreen},
    {"-webkit-full-screen-ancestor", CSSSelector::kPseudoFullScreenAncestor},
    {"-webkit-resizer", CSSSelector::kPseudoResizer},
    {"-webkit-scrollbar", CSSSelector::kPseudoScrollbar},
    {"-webkit-scrollbar-button", CSSSelector::kPseudoScrollbarButton},
    {"-webkit-scrollbar-corner", CSSSelector::kPseudoScrollbarCorner},
    {"-webkit-scrollbar-thumb", CSSSelector::kPseudoScrollbarThumb},
    {"-webkit-scrollbar-track", CSSSelector::kPseudoScrollbarTrack},
    {"-webkit-scrollbar-track-piece", CSSSelector::kPseudoScrollbarTrackPiece},
    {"active", CSSSelector::kPseudoActive},
    {"active-view-transition", CSSSelector::kPseudoActiveViewTransition},
    {"after", CSSSelector::kPseudoAfter},
    {"any-link", CSSSelector::kPseudoAnyLink},
    {"autofill", CSSSelector::kPseudoAutofill},
    {"backdrop", CSSSelector::kPseudoBackdrop},
    {"before", CSSSelector::kPseudoBefore},
    {"check", CSSSelector::kPseudoCheck},
    {"checked", CSSSelector::kPseudoChecked},
    {"closed", CSSSelector::kPseudoClosed},
    {"column", CSSSelector::kPseudoColumn},
    {"corner-present", CSSSelector::kPseudoCornerPresent},
    {"cue", CSSSelector::kPseudoWebKitCustomElement},
    {"current", CSSSelector::kPseudoCurrent},
    {"decrement", CSSSelector::kPseudoDecrement},
    {"default", CSSSelector::kPseudoDefault},
    {"defined", CSSSelector::kPseudoDefined},
    {"details-content", CSSSelector::kPseudoDetailsContent},
    {"disabled", CSSSelector::kPseudoDisabled},
    {"double-button", CSSSelector::kPseudoDoubleButton},
    {"empty", CSSSelector::kPseudoEmpty},
    {"enabled", CSSSelector::kPseudoEnabled},
    {"end", CSSSelector::kPseudoEnd},
    {"file-selector-button", CSSSelector::kPseudoFileSelectorButton},
    {"first", CSSSelector::kPseudoFirstPage},
    {"first-child", CSSSelector::kPseudoFirstChild},
    {"first-letter", CSSSelector::kPseudoFirstLetter},
    {"first-line", CSSSelector::kPseudoFirstLine},
    {"first-of-type", CSSSelector::kPseudoFirstOfType},
    {"focus", CSSSelector::kPseudoFocus},
    {"focus-visible", CSSSelector::kPseudoFocusVisible},
    {"focus-within", CSSSelector::kPseudoFocusWithin},
    {"fullscreen", CSSSelector::kPseudoFullscreen},
    {"future", CSSSelector::kPseudoFutureCue},
    {"grammar-error", CSSSelector::kPseudoGrammarError},
    {"granted", CSSSelector::kPseudoPermissionGranted},
    {"has-slotted", CSSSelector::kPseudoHasSlotted},
    {"horizontal", CSSSelector::kPseudoHorizontal},
    {"host", CSSSelector::kPseudoHost},
    {"hover", CSSSelector::kPseudoHover},
    {"in-range", CSSSelector::kPseudoInRange},
    {"increment", CSSSelector::kPseudoIncrement},
    {"indeterminate", CSSSelector::kPseudoIndeterminate},
    {"invalid", CSSSelector::kPseudoInvalid},
    {"invalid-style", CSSSelector::kPseudoPermissionElementInvalidStyle},
    {"last-child", CSSSelector::kPseudoLastChild},
    {"last-of-type", CSSSelector::kPseudoLastOfType},
    {"left", CSSSelector::kPseudoLeftPage},
    {"link", CSSSelector::kPseudoLink},
    {"marker", CSSSelector::kPseudoMarker},
    {"modal", CSSSelector::kPseudoModal},
    {"no-button", CSSSelector::kPseudoNoButton},
    {"occluded", CSSSelector::kPseudoPermissionElementOccluded},
    {"only-child", CSSSelector::kPseudoOnlyChild},
    {"only-of-type", CSSSelector::kPseudoOnlyOfType},
    {"open", CSSSelector::kPseudoOpen},
    {"optional", CSSSelector::kPseudoOptional},
    {"out-of-range", CSSSelector::kPseudoOutOfRange},
    {"past", CSSSelector::kPseudoPastCue},
    {"paused", CSSSelector::kPseudoPaused},
    {"picture-in-picture", CSSSelector::kPseudoPictureInPicture},
    {"placeholder", CSSSelector::kPseudoPlaceholder},
    {"placeholder-shown", CSSSelector::kPseudoPlaceholderShown},
    {"playing", CSSSelector::kPseudoPlaying},
    {"popover-open", CSSSelector::kPseudoPopoverOpen},
    {"read-only", CSSSelector::kPseudoReadOnly},
    {"read-write", CSSSelector::kPseudoReadWrite},
    {"required", CSSSelector::kPseudoRequired},
    {"right", CSSSelector::kPseudoRightPage},
    {"root", CSSSelector::kPseudoRoot},
    {"scope", CSSSelector::kPseudoScope},
    {"scroll-marker", CSSSelector::kPseudoScrollMarker},
    {"scroll-marker-group", CSSSelector::kPseudoScrollMarkerGroup},
    {"scroll-next-button", CSSSelector::kPseudoScrollNextButton},
    {"scroll-prev-button", CSSSelector::kPseudoScrollPrevButton},
    {"search-text", CSSSelector::kPseudoSearchText},
    {"select-arrow", CSSSelector::kPseudoSelectArrow},
    {"selection", CSSSelector::kPseudoSelection},
    {"single-button", CSSSelector::kPseudoSingleButton},
    {"spelling-error", CSSSelector::kPseudoSpellingError},
    {"start", CSSSelector::kPseudoStart},
    {"target", CSSSelector::kPseudoTarget},
    {"target-text", CSSSelector::kPseudoTargetText},
    {"user-invalid", CSSSelector::kPseudoUserInvalid},
    {"user-valid", CSSSelector::kPseudoUserValid},
    {"valid", CSSSelector::kPseudoValid},
    {"vertical", CSSSelector::kPseudoVertical},
    {"view-transition", CSSSelector::kPseudoViewTransition},
    {"visited", CSSSelector::kPseudoVisited},
    {"window-inactive", CSSSelector::kPseudoWindowInactive},
    {"xr-overlay", CSSSelector::kPseudoXrOverlay},
};

constexpr static NameToPseudoStruct kPseudoTypeWithArgumentsMap[] = {
    {"-webkit-any", CSSSelector::kPseudoAny},
    {"active-view-transition-type",
     CSSSelector::kPseudoActiveViewTransitionType},
    {"cue", CSSSelector::kPseudoCue},
    {"dir", CSSSelector::kPseudoDir},
    {"has", CSSSelector::kPseudoHas},
    {"highlight", CSSSelector::kPseudoHighlight},
    {"host", CSSSelector::kPseudoHost},
    {"host-context", CSSSelector::kPseudoHostContext},
    {"is", CSSSelector::kPseudoIs},
    {"lang", CSSSelector::kPseudoLang},
    {"not", CSSSelector::kPseudoNot},
    {"nth-child", CSSSelector::kPseudoNthChild},
    {"nth-last-child", CSSSelector::kPseudoNthLastChild},
    {"nth-last-of-type", CSSSelector::kPseudoNthLastOfType},
    {"nth-of-type", CSSSelector::kPseudoNthOfType},
    {"part", CSSSelector::kPseudoPart},
    {"picker", CSSSelector::kPseudoPicker},
    {"slotted", CSSSelector::kPseudoSlotted},
    {"state", CSSSelector::kPseudoState},
    {"view-transition-group", CSSSelector::kPseudoViewTransitionGroup},
    {"view-transition-image-pair", CSSSelector::kPseudoViewTransitionImagePair},
    {"view-transition-new", CSSSelector::kPseudoViewTransitionNew},
    {"view-transition-old", CSSSelector::kPseudoViewTransitionOld},
    {"where", CSSSelector::kPseudoWhere},
};

CSSSelector::PseudoType CSSSelector::NameToPseudoType(
    const AtomicString& name,
    bool has_arguments,
    const Document* document) {
  if (name.IsNull() || !name.Is8Bit()) {
    return CSSSelector::kPseudoUnknown;
  }

  const NameToPseudoStruct* pseudo_type_map;
  const NameToPseudoStruct* pseudo_type_map_end;
  if (has_arguments) {
    pseudo_type_map = kPseudoTypeWithArgumentsMap;
    pseudo_type_map_end =
        kPseudoTypeWithArgumentsMap + std::size(kPseudoTypeWithArgumentsMap);
  } else {
    pseudo_type_map = kPseudoTypeWithoutArgumentsMap;
    pseudo_type_map_end = kPseudoTypeWithoutArgumentsMap +
                          std::size(kPseudoTypeWithoutArgumentsMap);
  }
  const NameToPseudoStruct* match = std::lower_bound(
      pseudo_type_map, pseudo_type_map_end, name,
      [](const NameToPseudoStruct& entry, const AtomicString& name) -> bool {
        DCHECK(name.Is8Bit());
        DCHECK(entry.string);
        // If strncmp returns 0, then either the keys are equal, or |name| sorts
        // before |entry|.
        return strncmp(entry.string,
                       reinterpret_cast<const char*>(name.Characters8()),
                       name.length()) < 0;
      });
  if (match == pseudo_type_map_end || match->string != name.GetString()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPaused &&
      !RuntimeEnabledFeatures::CSSPseudoPlayingPausedEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPlaying &&
      !RuntimeEnabledFeatures::CSSPseudoPlayingPausedEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoState &&
      !RuntimeEnabledFeatures::CSSCustomStateNewSyntaxEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoDetailsContent &&
      !RuntimeEnabledFeatures::DetailsStylingEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPermissionElementInvalidStyle &&
      !RuntimeEnabledFeatures::PermissionElementEnabled(
          document ? document->GetExecutionContext() : nullptr)) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPermissionElementOccluded &&
      !RuntimeEnabledFeatures::PermissionElementEnabled(
          document ? document->GetExecutionContext() : nullptr)) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPermissionGranted &&
      !RuntimeEnabledFeatures::PermissionElementEnabled(
          document ? document->GetExecutionContext() : nullptr)) {
    return CSSSelector::kPseudoUnknown;
  }

  if ((match->type == CSSSelector::kPseudoScrollMarker ||
       match->type == CSSSelector::kPseudoScrollMarkerGroup) &&
      !RuntimeEnabledFeatures::CSSPseudoScrollMarkersEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if ((match->type == CSSSelector::kPseudoScrollNextButton ||
       match->type == CSSSelector::kPseudoScrollPrevButton) &&
      !RuntimeEnabledFeatures::CSSPseudoScrollButtonsEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoColumn &&
      !RuntimeEnabledFeatures::CSSPseudoColumnEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if ((match->type == CSSSelector::kPseudoOpen ||
       match->type == CSSSelector::kPseudoClosed) &&
      !RuntimeEnabledFeatures::CSSPseudoOpenClosedEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoPicker &&
      !RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if ((match->type == CSSSelector::kPseudoSearchText ||
       match->type == CSSSelector::kPseudoCurrent) &&
      !RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  if (match->type == CSSSelector::kPseudoHasSlotted &&
      !RuntimeEnabledFeatures::CSSPseudoHasSlottedEnabled()) {
    return CSSSelector::kPseudoUnknown;
  }

  return static_cast<CSSSelector::PseudoType>(match->type);
}

#if DCHECK_IS_ON()
void CSSSelector::Show(int indent) const {
  printf("%*sSelectorText(): %s\n", indent, "", SelectorText().Ascii().c_str());
  printf("%*smatch_: %d\n", indent, "", Match());
  if (Match() != kTag) {
    printf("%*sValue(): %s\n", indent, "", Value().Ascii().c_str());
  }
  printf("%*sGetPseudoType(): %d\n", indent, "", GetPseudoType());
  if (Match() == kTag) {
    printf("%*sTagQName().LocalName(): %s\n", indent, "",
           TagQName().LocalName().Ascii().c_str());
  }
  printf("%*sIsAttributeSelector(): %d\n", indent, "", IsAttributeSelector());
  if (IsAttributeSelector()) {
    printf("%*sAttribute(): %s\n", indent, "",
           Attribute().LocalName().Ascii().c_str());
  }
  printf("%*sArgument(): %s\n", indent, "", Argument().Ascii().c_str());
  printf("%*sSpecificity(): %u\n", indent, "", Specificity());
  if (NextSimpleSelector()) {
    printf("\n%*s--> (Relation() == %d)\n", indent, "", Relation());
    NextSimpleSelector()->Show(indent + 2);
  } else {
    printf("\n%*s--> (Relation() == %d)\n", indent, "", Relation());
  }
}

void CSSSelector::Show() const {
  printf("\n******* CSSSelector::Show(\"%s\") *******\n",
         SelectorText().Ascii().c_str());
  Show(2);
  printf("******* end *******\n");
}
#endif  // DCHECK_IS_ON()

void CSSSelector::UpdatePseudoPage(const AtomicString& value,
                                   const Document* document) {
  DCHECK_EQ(Match(), kPagePseudoClass);
  SetValue(value);
  PseudoType type = CSSSelectorParser::ParsePseudoType(value, false, document);
  if (type != kPseudoFirstPage && type != kPseudoLeftPage &&
      type != kPseudoRightPage) {
    type = kPseudoUnknown;
  }
  bits_.set<PseudoTypeField>(type);
}

void CSSSelector::UpdatePseudoType(const AtomicString& value,
                                   const CSSParserContext& context,
                                   bool has_arguments,
                                   CSSParserMode mode) {
  DCHECK(Match() == kPseudoClass || Match() == kPseudoElement);
  AtomicString lower_value = value.LowerASCII();
  PseudoType pseudo_type = CSSSelectorParser::ParsePseudoType(
      lower_value, has_arguments, context.GetDocument());
  SetPseudoType(pseudo_type);
  SetValue(pseudo_type == kPseudoStateDeprecatedSyntax ? value : lower_value);

  switch (GetPseudoType()) {
    case kPseudoAfter:
    case kPseudoBefore:
    case kPseudoFirstLetter:
    case kPseudoFirstLine:
      // The spec says some pseudos allow both single and double colons like
      // :before for backwards compatibility. Single colon becomes PseudoClass,
      // but should be PseudoElement like double colon.
      if (Match() == kPseudoClass) {
        bits_.set<MatchField>(kPseudoElement);
      }
      [[fallthrough]];
    // For pseudo elements

"""


```