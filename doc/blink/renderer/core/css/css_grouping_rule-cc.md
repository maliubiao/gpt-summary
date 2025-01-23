Response:
Let's break down the thought process for analyzing this `css_grouping_rule.cc` file.

1. **Understand the Context:** The prompt clearly states this is a Chromium Blink rendering engine source file located at `blink/renderer/core/css/`. This immediately tells us it deals with CSS and how it's processed within a web browser. The filename `css_grouping_rule.cc` suggests it's specifically concerned with CSS rules that can contain other rules (like `@media`, `@supports`, `@scope`).

2. **Initial Code Scan - Identify Key Structures and Functions:**  A quick skim reveals important elements:
    * **Includes:**  Headers like `css_page_rule.h`, `css_rule_list.h`, `css_style_rule.h`, `css_style_sheet.h`, and `css_parser.h` are strong indicators of the file's purpose. It interacts with different types of CSS rules, manages lists of rules, and uses a CSS parser.
    * **Namespace:** The code is within the `blink` namespace, confirming its origin.
    * **Helper Functions:**  Functions like `FindClosestParentStyleRuleOrNull`, `FindClosestStyleOrScopeRule`, and `IsWithinScopeRule` suggest the code needs to navigate the CSS rule hierarchy.
    * **`CalculateNestingContext`:** This function is crucial. Its name and parameters (`CSSNestingType`, `parent_rule_for_nesting`, `is_within_scope`, `is_nested_scope_rule`) strongly hint at handling how CSS rules are nested within each other, especially in the context of newer features like `@scope`.
    * **`ParseRuleForInsert`:** This is a core function for dynamically adding CSS rules. It takes a rule string, parses it, and handles potential errors.
    * **`CSSGroupingRule` Class:** This is the central class. It has methods like `insertRule`, `deleteRule`, `length`, `Item`, and `cssRules`. These directly correspond to the DOM API for manipulating CSS grouping rules.
    * **Member Variables:** `group_rule_`, `child_rule_cssom_wrappers_`, and `rule_list_cssom_wrappers_` store the underlying data structure, the JavaScript wrappers for child rules, and the wrapper for the `cssRules` list.

3. **Analyze Core Functionality - Deduce the Purpose:** Based on the identified elements:
    * **Represents CSS Grouping Rules:** The class name and the inclusion of various specific rule types confirm this. It's the C++ representation of CSS rules like `@media`, `@supports`, `@container`, and `@scope`.
    * **Manages Child Rules:** The `insertRule`, `deleteRule`, `length`, and `Item` methods directly deal with adding, removing, and accessing the rules nested within a grouping rule. The `child_rule_cssom_wrappers_` variable reinforces this.
    * **Parsing and Insertion:** `ParseRuleForInsert` is responsible for taking a string of CSS text and turning it into a usable rule object, handling various scenarios and potential errors. The `CalculateNestingContext` function plays a vital role in determining how parsing should occur based on the parent rule's context.
    * **DOM API Interaction:** The methods in `CSSGroupingRule` mirror the methods available on CSS grouping rule objects in JavaScript (e.g., `insertRule`, `deleteRule`, `cssRules`). This suggests it's the backend implementation for these APIs.
    * **Nesting Context:** The code explicitly handles the complexities of CSS nesting, particularly with the introduction of `@scope`. The `CalculateNestingContext` function and the checks within `ParseRuleForInsert` demonstrate this.

4. **Connect to JavaScript, HTML, and CSS:**
    * **JavaScript:**  The `insertRule` and `deleteRule` methods are directly called from JavaScript when manipulating CSS rules via the DOM. The `cssRules` property returns a `CSSRuleList` that JavaScript can iterate through. Example: `styleSheet.cssRules[0].insertRule(...)`.
    * **HTML:**  The CSS rules defined in `<style>` tags or linked stylesheets are parsed and represented by these C++ objects. The structure of the HTML determines the initial hierarchy of CSS rules.
    * **CSS:**  This file is *all about* CSS. It interprets the syntax, manages the structure of CSS rules, and enforces the rules regarding which rules can be nested within others. Examples include `@media screen { ... }` or `@supports (display: grid) { ... }`.

5. **Logical Reasoning and Examples:**
    * **`CalculateNestingContext`:**  Think of a `@media` rule within a `@supports` rule. This function determines that the inner `@media` is nested and identifies the `@supports` rule as the relevant parent for nesting purposes.
    * **`ParseRuleForInsert` Error Handling:**  If you try to insert an invalid CSS rule string, this function will catch the syntax error and throw a DOMException that JavaScript can handle.

6. **User/Programming Errors:**
    * **Invalid Index:**  Trying to `insertRule` or `deleteRule` at an out-of-bounds index will lead to an `IndexSizeError`.
    * **Invalid CSS Syntax:**  Passing a syntactically incorrect CSS string to `insertRule` will result in a `SyntaxError`.
    * **Hierarchy Errors:** Trying to insert an `@import` rule within a `@media` rule will cause a `HierarchyRequestError`. The code enforces these restrictions.

7. **Debugging Scenario:**  Imagine a user reports that a dynamically added `@media` rule inside an existing `@supports` rule isn't working correctly. As a debugger, you'd:
    * Start by examining the JavaScript code that adds the rule.
    * Set breakpoints in the `insertRule` method of the `CSSGroupingRule` class.
    * Step through the `ParseRuleForInsert` and `CalculateNestingContext` functions to see how the rule is being parsed and if the nesting context is being correctly determined.
    * Inspect the `group_rule_` and `child_rule_cssom_wrappers_` to see the current structure of the rules.

By following these steps, we can systematically analyze the provided code snippet and extract the necessary information to answer the prompt comprehensively. The key is to understand the role of each part of the code within the larger context of the Blink rendering engine and its interaction with web technologies.
好的，让我们详细分析一下 `blink/renderer/core/css/css_grouping_rule.cc` 文件的功能。

**文件功能概述:**

`css_grouping_rule.cc` 文件定义了 `CSSGroupingRule` 类，这个类是 Blink 渲染引擎中用于表示可以包含其他 CSS 规则的 CSS 规则（称为“分组规则”）的基类。  这些分组规则包括：

* `@media` 规则
* `@supports` 规则
* `@container` 规则
* `@page` 规则
* `@font-face` 规则 (尽管 `@font-face` 本身不是分组规则，但 `CSSGroupingRule` 的某些机制可能被它复用或影响其上下文)
* `@scope` 规则

简单来说，这个文件的主要职责是：

1. **提供一个抽象基类:**  定义了所有 CSS 分组规则的通用行为和接口。
2. **管理子规则:**  负责存储、添加、删除和访问包含在分组规则内部的子规则。
3. **处理规则插入和删除:**  实现了 `insertRule` 和 `deleteRule` 方法，允许通过 JavaScript DOM API 动态修改分组规则的内容。
4. **处理 CSS 文本的序列化:**  定义了如何将分组规则及其包含的子规则转换回 CSS 文本表示。
5. **维护 CSSOM (CSS Object Model) 结构:**  将底层的 `StyleRuleGroup` 对象与 JavaScript 可访问的 `CSSGroupingRule` 对象连接起来。
6. **处理 CSS 规则的嵌套上下文:**  特别是对于新的 CSS 功能如 `@scope` 和 CSS Nesting，该文件包含逻辑来确定规则插入的有效性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件是 Blink 渲染引擎的核心部分，它直接参与了将 HTML 和 CSS 代码转换为用户可见的网页的过程。它与 JavaScript、HTML 和 CSS 的关系非常密切：

* **CSS:**  这个文件处理的是 CSS 语法结构中的分组规则。例如，对于以下 CSS 代码：

   ```css
   @media screen and (max-width: 600px) {
     .small-text {
       font-size: 14px;
     }
   }
   ```

   `CSSGroupingRule` 的一个具体子类（例如 `CSSMediaRule`）的实例会表示这个 `@media` 规则。它会存储选择器 `screen and (max-width: 600px)` 和包含的 `.small-text` 样式规则。

* **HTML:**  当浏览器解析 HTML 文档中的 `<style>` 标签或链接的 CSS 文件时，CSS 解析器会创建 `CSSGroupingRule` (或其子类) 的实例来表示 CSS 中的分组规则。这些对象会构建成一个树状结构，反映 CSS 的层叠和包含关系。

* **JavaScript:**  通过 JavaScript 的 CSSOM API，开发者可以访问和修改 CSS 规则。`CSSGroupingRule` 提供了与这些 API 交互的接口。例如：

   ```javascript
   const stylesheet = document.styleSheets[0];
   const mediaRule = stylesheet.cssRules[0]; // 假设第一个规则是 @media
   if (mediaRule instanceof CSSGroupingRule) {
     mediaRule.insertRule('.new-class { color: blue; }', mediaRule.cssRules.length);
   }
   ```

   在这个例子中，JavaScript 代码通过 `insertRule` 方法向一个 `CSSGroupingRule` 实例中添加了一个新的样式规则。 `css_grouping_rule.cc` 中的 `insertRule` 方法会被调用来执行这个操作。

**逻辑推理及假设输入与输出:**

文件中的 `ParseRuleForInsert` 函数负责解析要插入的 CSS 规则字符串。 让我们假设以下输入：

**假设输入:**

* `rule_string`: ".another-class { font-weight: bold; }"
* `index`: 0 (插入到子规则列表的开头)
* `parent_rule`:  一个表示 `@media screen and (max-width: 600px)` 的 `CSSGroupingRule` 实例。

**逻辑推理:**

1. `ParseRuleForInsert` 函数会使用 CSS 解析器解析 `rule_string`。
2. 解析器会创建一个新的 `CSSStyleRule` 对象来表示 `.another-class { font-weight: bold; }`。
3. 该函数会检查新规则是否允许插入到 `parent_rule` 中（例如，确保不是在分组规则中插入 `@import` 或 `@namespace` 规则）。
4. 如果一切正常，`insertRule` 方法会将新创建的 `CSSStyleRule` 添加到 `parent_rule` 的子规则列表中。

**预期输出:**

* `ParseRuleForInsert` 返回新创建的 `CSSStyleRule` 对象的指针。
* `parent_rule` 实例的子规则列表现在包含了新添加的 `CSSStyleRule`。
* 如果通过 JavaScript 的 `mediaRule.cssRules` 访问，会看到新添加的规则。

**用户或编程常见的使用错误及举例说明:**

* **插入无效的 CSS 规则字符串:**

   ```javascript
   mediaRule.insertRule('invalid css;', 0); // "invalid css;" 不是合法的 CSS 规则
   ```

   在这种情况下，`ParseRuleForInsert` 会解析失败，并抛出一个 `DOMException` (SyntaxError)。

* **在不允许的位置插入特定类型的规则:**

   ```javascript
   mediaRule.insertRule('@import "some.css";', 0); // @import 不能插入到分组规则中
   ```

   `ParseRuleForInsert` 会检查规则类型，发现 `@import` 规则不能插入到分组规则中，会抛出一个 `DOMException` (HierarchyRequestError)。

* **使用超出范围的索引进行插入或删除:**

   ```javascript
   mediaRule.insertRule('.another-class { ... }', 100); // 假设子规则数量远小于 100
   ```

   `insertRule` 方法会检查索引是否有效，如果超出范围，会抛出一个 `DOMException` (IndexSizeError)。 `deleteRule` 方法也会进行类似的检查。

**用户操作如何一步步到达这里，作为调试线索:**

假设一个用户访问一个网页，并且该网页使用了 JavaScript 来动态添加 CSS 规则到一个 `@media` 查询中。

1. **用户加载网页:** 浏览器开始解析 HTML 文档。
2. **解析到 `<style>` 标签或链接的 CSS 文件:** Blink 的 CSS 解析器会解析 CSS 代码，并创建 `CSSGroupingRule` (例如 `CSSMediaRule`) 的实例来表示 `@media` 查询。
3. **JavaScript 代码执行:** 网页中的 JavaScript 代码被执行。这段代码可能包含了类似以下的逻辑：
   ```javascript
   const stylesheet = document.styleSheets[0];
   const mediaRule = Array.from(stylesheet.cssRules).find(rule => rule instanceof CSSMediaRule);
   if (mediaRule) {
     mediaRule.insertRule('.dynamic-style { color: red; }', 0);
   }
   ```
4. **调用 `insertRule`:**  当 JavaScript 调用 `mediaRule.insertRule(...)` 时，这个调用会最终到达 `blink/renderer/core/css/css_grouping_rule.cc` 文件中 `CSSGroupingRule` 类的 `insertRule` 方法。
5. **规则解析和插入:** `insertRule` 方法会调用 `ParseRuleForInsert` 来解析传入的 CSS 规则字符串。如果解析成功且规则类型允许插入，新的规则会被添加到该分组规则的子规则列表中。
6. **渲染更新:** 浏览器会根据新添加的 CSS 规则重新计算样式并更新页面的渲染。

**调试线索:**

如果用户报告动态添加的 CSS 规则没有生效，或者出现错误，调试可以从以下几个方面入手：

* **检查 JavaScript 代码:** 确认 JavaScript 代码是否正确地获取了 `CSSGroupingRule` 对象，以及传递给 `insertRule` 的规则字符串和索引是否正确。
* **断点调试 `insertRule`:** 在 `blink/renderer/core/css/css_grouping_rule.cc` 的 `insertRule` 方法中设置断点，可以查看传入的 `rule_string` 和 `index` 的值，以及父规则的状态。
* **断点调试 `ParseRuleForInsert`:**  在 `ParseRuleForInsert` 函数中设置断点，可以检查规则字符串的解析过程，以及是否因为语法错误或类型错误导致插入失败。
* **查看 CSSOM 结构:** 使用浏览器的开发者工具查看当前的 CSSOM 结构，确认动态添加的规则是否正确地添加到了预期的 `CSSGroupingRule` 中。
* **检查控制台错误:** 浏览器控制台可能会显示由于插入无效规则而抛出的 `DOMException` 错误信息。

总而言之，`css_grouping_rule.cc` 文件是 Blink 渲染引擎中处理 CSS 分组规则的核心组件，它连接了 CSS 语法结构、JavaScript 的 CSSOM 操作以及最终的页面渲染。理解这个文件的功能对于理解浏览器如何处理和操作 CSS 至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/css_grouping_rule.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Adobe Systems Incorporated. All rights reserved.
 * Copyright (C) 2012 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/css_grouping_rule.h"

#include "third_party/blink/renderer/core/css/css_page_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_scope_rule.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

StyleRule* FindClosestParentStyleRuleOrNull(CSSRule* parent) {
  if (parent == nullptr) {
    return nullptr;
  }
  if (parent->type() == CSSRule::kStyleRule) {
    return To<CSSStyleRule>(parent)->GetStyleRule();
  }
  return FindClosestParentStyleRuleOrNull(parent->parentRule());
}

CSSRule* FindClosestStyleOrScopeRule(CSSRule* parent) {
  if (parent == nullptr) {
    return nullptr;
  }
  if (IsA<CSSStyleRule>(parent) || IsA<CSSScopeRule>(parent)) {
    return parent;
  }
  return FindClosestStyleOrScopeRule(parent->parentRule());
}

bool IsWithinScopeRule(CSSRule* rule) {
  if (rule == nullptr) {
    return false;
  }
  if (IsA<CSSScopeRule>(rule)) {
    return true;
  }
  return IsWithinScopeRule(rule->parentRule());
}

// Parsing child rules is highly dependent on the ancestor rules.
// Under normal, full-stylesheet parsing, this information is available
// on the stack, but for rule insertion we need to traverse and inspect
// the ancestor chain.
//
// The 'is_nested_scope_rule' parameter is set to true when
// `parent_rule` is a CSSScopeRule with an immediate CSSStyleRule parent,
// making it a "nested group rule" [1]. Certain child rule insertions into
// CSSScopeRule are only valid when it's a nested group rule.
// TODO(crbug.com/351045927): This parameter can be removed once declarations
// are valid directly in top-level @scope rules.
//
// [1] https://drafts.csswg.org/css-nesting-1/#nested-group-rules
void CalculateNestingContext(CSSRule& parent_rule,
                             CSSNestingType& nesting_type,
                             StyleRule*& parent_rule_for_nesting,
                             bool& is_within_scope,
                             bool& is_nested_scope_rule) {
  nesting_type = CSSNestingType::kNone;
  parent_rule_for_nesting = nullptr;
  is_within_scope = false;
  is_nested_scope_rule = false;

  if (CSSRule* closest_style_or_scope_rule =
          FindClosestStyleOrScopeRule(&parent_rule)) {
    is_within_scope = IsWithinScopeRule(closest_style_or_scope_rule);
    if (auto* style_rule =
            DynamicTo<CSSStyleRule>(closest_style_or_scope_rule)) {
      nesting_type = CSSNestingType::kNesting;
      parent_rule_for_nesting = style_rule->GetStyleRule();
    } else if (auto* scope_rule =
                   DynamicTo<CSSScopeRule>(closest_style_or_scope_rule)) {
      nesting_type = CSSNestingType::kScope;
      // The <scope-start> selector acts as the parent style rule.
      // https://drafts.csswg.org/css-nesting-1/#nesting-at-scope
      parent_rule_for_nesting =
          scope_rule->GetStyleRuleScope().GetStyleScope().RuleForNesting();
      is_nested_scope_rule = IsA<CSSStyleRule>(scope_rule->parentRule());
    } else {
      NOTREACHED();
    }
  }
}

StyleRuleBase* ParseRuleForInsert(const ExecutionContext* execution_context,
                                  const String& rule_string,
                                  unsigned index,
                                  size_t num_child_rules,
                                  CSSRule& parent_rule,
                                  ExceptionState& exception_state) {
  if (index > num_child_rules) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "the index " + String::Number(index) +
            " must be less than or equal to the length of the rule list.");
    return nullptr;
  }

  CSSStyleSheet* style_sheet = parent_rule.parentStyleSheet();
  auto* context = MakeGarbageCollected<CSSParserContext>(
      parent_rule.ParserContext(execution_context->GetSecureContextMode()),
      style_sheet);
  StyleRuleBase* new_rule = nullptr;
  if (IsA<CSSPageRule>(parent_rule)) {
    new_rule = CSSParser::ParseMarginRule(
        context, style_sheet ? style_sheet->Contents() : nullptr, rule_string);
  } else {
    CSSNestingType nesting_type;
    StyleRule* parent_rule_for_nesting;
    bool is_within_scope;
    bool is_nested_scope_rule;
    CalculateNestingContext(parent_rule, nesting_type, parent_rule_for_nesting,
                            is_within_scope, is_nested_scope_rule);

    new_rule = CSSParser::ParseRule(
        context, style_sheet ? style_sheet->Contents() : nullptr, nesting_type,
        parent_rule_for_nesting, is_within_scope, rule_string);

    bool allow_nested_declarations =
        (nesting_type == CSSNestingType::kNesting) || is_nested_scope_rule;
    if (!new_rule && allow_nested_declarations &&
        RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled()) {
      // Retry as a CSSNestedDeclarations rule.
      // https://drafts.csswg.org/cssom/#insert-a-css-rule
      new_rule = CSSParser::ParseNestedDeclarationsRule(
          context, nesting_type, parent_rule_for_nesting, is_within_scope,
          rule_string);
    }
  }

  if (!new_rule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "the rule '" + rule_string + "' is invalid and cannot be parsed.");
    return nullptr;
  }

  if (new_rule->IsNamespaceRule()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "'@namespace' rules cannot be inserted inside a group rule.");
    return nullptr;
  }

  if (new_rule->IsImportRule()) {
    // FIXME: an HierarchyRequestError should also be thrown for a nested @media
    // rule. They are currently not getting parsed, resulting in a SyntaxError
    // to get raised above.
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "'@import' rules cannot be inserted inside a group rule.");
    return nullptr;
  }

  if (!new_rule->IsConditionRule() && !new_rule->IsScopeRule() &&
      !new_rule->IsStyleRule() && !new_rule->IsNestedDeclarationsRule()) {
    for (const CSSRule* current = &parent_rule; current != nullptr;
         current = current->parentRule()) {
      if (IsA<CSSStyleRule>(current)) {
        // We are in nesting context (directly or indirectly),
        // so inserting this rule is not allowed.
        exception_state.ThrowDOMException(
            DOMExceptionCode::kHierarchyRequestError,
            "Only conditional nested group rules, style rules, @scope rules,"
            "and nested declaration rules may be nested.");
        return nullptr;
      }
    }
  }

  return new_rule;
}

CSSGroupingRule::CSSGroupingRule(StyleRuleGroup* group_rule,
                                 CSSStyleSheet* parent)
    : CSSRule(parent),
      group_rule_(group_rule),
      child_rule_cssom_wrappers_(group_rule->ChildRules().size()) {}

CSSGroupingRule::~CSSGroupingRule() = default;

unsigned CSSGroupingRule::insertRule(const ExecutionContext* execution_context,
                                     const String& rule_string,
                                     unsigned index,
                                     ExceptionState& exception_state) {
  DCHECK_EQ(child_rule_cssom_wrappers_.size(),
            group_rule_->ChildRules().size());

  StyleRuleBase* new_rule = ParseRuleForInsert(
      execution_context, rule_string, index, group_rule_->ChildRules().size(),
      *this, exception_state);

  if (new_rule == nullptr) {
    // Already raised an exception above.
    return 0;
  } else {
    CSSStyleSheet::RuleMutationScope mutation_scope(this);
    group_rule_->WrapperInsertRule(parentStyleSheet(), index, new_rule);
    child_rule_cssom_wrappers_.insert(index, Member<CSSRule>(nullptr));
    return index;
  }
}

void CSSGroupingRule::deleteRule(unsigned index,
                                 ExceptionState& exception_state) {
  DCHECK_EQ(child_rule_cssom_wrappers_.size(),
            group_rule_->ChildRules().size());

  if (index >= group_rule_->ChildRules().size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "the index " + String::Number(index) +
            " is greated than the length of the rule list.");
    return;
  }

  CSSStyleSheet::RuleMutationScope mutation_scope(this);

  group_rule_->WrapperRemoveRule(parentStyleSheet(), index);

  if (child_rule_cssom_wrappers_[index]) {
    child_rule_cssom_wrappers_[index]->SetParentRule(nullptr);
  }
  child_rule_cssom_wrappers_.EraseAt(index);
}

void CSSGroupingRule::AppendCSSTextForItems(StringBuilder& result) const {
  // https://drafts.csswg.org/cssom-1/#serialize-a-css-rule,
  // using CSSMediaRule as an example:

  // The result of concatenating the following:
  // 1. The string "@media", followed by a single SPACE (U+0020).
  // 2. The result of performing serialize a media query list on rule’s media
  //    query list.
  // [1–2 is done in the parent, and is different for @container etc.]

  // 3. A single SPACE (U+0020), followed by the string "{", i.e., LEFT CURLY
  //    BRACKET (U+007B), followed by a newline.
  result.Append(" {\n");

  // 4. The result of performing serialize a CSS rule on each rule in the rule’s
  //    cssRules list, filtering out empty strings, indenting each item
  //    with two spaces, all joined with newline.
  for (unsigned i = 0; i < length(); ++i) {
    CSSRule* child = ItemInternal(i);
    String child_text = child->cssText();
    if (!child_text.empty()) {
      result.Append("  ");
      result.Append(child_text);
      result.Append('\n');
    }
  }

  // A newline, followed by the string "}", i.e., RIGHT CURLY BRACKET (U+007D)
  result.Append('}');
}

unsigned CSSGroupingRule::length() const {
  return group_rule_->ChildRules().size();
}

CSSRule* CSSGroupingRule::Item(unsigned index,
                               bool trigger_use_counters) const {
  if (index >= length()) {
    return nullptr;
  }
  DCHECK_EQ(child_rule_cssom_wrappers_.size(),
            group_rule_->ChildRules().size());
  Member<CSSRule>& rule = child_rule_cssom_wrappers_[index];
  if (!rule) {
    rule = group_rule_->ChildRules()[index]->CreateCSSOMWrapper(
        index, const_cast<CSSGroupingRule*>(this), trigger_use_counters);
  }
  return rule.Get();
}

CSSRuleList* CSSGroupingRule::cssRules() const {
  if (!rule_list_cssom_wrapper_) {
    rule_list_cssom_wrapper_ =
        MakeGarbageCollected<LiveCSSRuleList<CSSGroupingRule>>(
            const_cast<CSSGroupingRule*>(this));
  }
  return rule_list_cssom_wrapper_.Get();
}

void CSSGroupingRule::Reattach(StyleRuleBase* rule) {
  DCHECK(rule);
  group_rule_ = static_cast<StyleRuleGroup*>(rule);
  for (unsigned i = 0; i < child_rule_cssom_wrappers_.size(); ++i) {
    if (child_rule_cssom_wrappers_[i]) {
      child_rule_cssom_wrappers_[i]->Reattach(
          group_rule_->ChildRules()[i].Get());
    }
  }
}

void CSSGroupingRule::Trace(Visitor* visitor) const {
  CSSRule::Trace(visitor);
  visitor->Trace(child_rule_cssom_wrappers_);
  visitor->Trace(group_rule_);
  visitor->Trace(rule_list_cssom_wrapper_);
}

}  // namespace blink
```