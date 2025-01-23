Response:
Let's break down the thought process for analyzing the provided `InspectorCSSParserObserver.cc` code.

1. **Understand the Goal:** The core request is to analyze the functionality of this specific Chromium Blink engine source code file. The prompt also asks for connections to JavaScript, HTML, and CSS, examples of logic, and common user/programming errors.

2. **Identify the Core Class:** The filename and the `#include` directive immediately point to the central class: `InspectorCSSParserObserver`. This is the primary focus of the analysis.

3. **Analyze the Class's Purpose:**  The name "InspectorCSSParserObserver" strongly suggests its role: it observes the CSS parsing process within the browser's rendering engine and collects information relevant to the browser's developer tools ("Inspector"). The "Observer" part implies it's likely a callback mechanism used during parsing.

4. **Examine Member Variables:**  Skimming through the member variables provides crucial context:
    * `parsed_text_`:  Holds the CSS text being parsed. This is the input.
    * `document_`:  A pointer to the `Document` object, linking the CSS to the HTML structure.
    * `result_`:  A vector of `CSSRuleSourceData`, indicating this class builds a tree-like representation of the CSS rules.
    * `current_rule_data_stack_`: A stack of `CSSRuleSourceData`, suggesting the parser handles nested CSS rules.
    * `current_rule_data_`: A pointer to the currently being processed rule.
    * `replaceable_property_offset_`:  Indicates a mechanism for handling potentially invalid or replaceable properties.
    * `issue_reporting_context_`: Used for reporting issues found during parsing.
    * `line_endings_`: Helps determine line and column numbers for error reporting.

5. **Analyze Key Methods (Focus on Public and Important Logic):**  Go through the methods, grouping them by their likely purpose:
    * **Rule Handling:** `StartRuleHeader`, `SetRuleHeaderEnd`, `EndRuleHeader`, `StartRuleBody`, `EndRuleBody`, `AddNewRuleToSourceTree`, `RemoveLastRuleFromSourceTree`, `PopRuleData`. These clearly manage the lifecycle of CSS rule processing.
    * **Selector Handling:** `ObserveSelector`. Straightforward.
    * **Property Handling:** `ObserveProperty`. Key for tracking CSS property information.
    * **Comment Handling:** `ObserveComment`. Interesting – it seems to attempt to parse CSS properties *within* comments.
    * **Error/Issue Reporting:** `ObserveErroneousAtRule`, `ReportPropertyRuleFailure`. These link to the "Inspector" functionality for debugging.
    * **Nested Declarations:** `ObserveNestedDeclarations`. Handles the newer CSS nesting feature.
    * **Utility:** `GetTextPosition`, `GetLineEndings`, `ParserContextForDocument`. Helper functions.

6. **Connect to Core Web Technologies (JavaScript, HTML, CSS):**
    * **CSS:** The entire file revolves around parsing CSS. The methods directly correspond to CSS syntax elements (rules, selectors, properties).
    * **HTML:** The `document_` member connects the CSS to the HTML structure. The parsing is triggered when the browser encounters `<style>` tags or linked CSS files in the HTML.
    * **JavaScript:** While this specific file doesn't directly *execute* JavaScript, the collected information is used by the browser's developer tools, which are often implemented using JavaScript. The Inspector allows developers to view and modify CSS, affecting how JavaScript interacts with the DOM.

7. **Identify Logical Reasoning and Assumptions:**  Look for conditional statements, loops, and data structures that indicate decision-making:
    * The stack-based approach for handling nested rules is a clear logical structure.
    * The `replaceable_property_offset_` logic involves checking offsets and potentially removing data, indicating a specific handling for invalid properties.
    * The `ObserveComment` logic attempts to parse comments as if they were inline styles, making an assumption about developer intent (potentially for disabled properties).
    * The handling of `CSSNestedDeclarationsEnabled()` feature flags shows conditional logic based on browser capabilities.

8. **Consider Potential User/Programming Errors:** Think about how developers might write incorrect CSS that this code would encounter:
    * Invalid CSS syntax (e.g., missing semicolons, incorrect property names).
    * Using `@import` statements late in the CSS.
    * Errors in `@property` rules.
    * The somewhat unusual behavior of parsing CSS within comments could be a source of confusion if not understood.

9. **Construct Examples (Hypothetical Input/Output):** Create simplified scenarios to illustrate the behavior of key methods. For instance, showing how `StartRuleHeader`, `ObserveSelector`, and `EndRuleBody` work with a simple CSS rule.

10. **Structure the Analysis:** Organize the findings into logical sections as requested by the prompt (Functionality, Relation to Web Technologies, Logical Reasoning, User Errors). Use clear headings and bullet points.

11. **Refine and Elaborate:**  Review the analysis, adding more detail and explanation where needed. Ensure the language is precise and easy to understand. For instance, clarify the purpose of the `CSSRuleSourceData` structure.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe the observer directly modifies the DOM. **Correction:**  The code primarily *observes* the parsing and collects data, which is then used by other parts of the browser (like the Inspector).
* **Realization:** The `ObserveComment` logic is quite specific. **Refinement:** Highlight the assumption it makes and the potential use case (disabled properties).
* **Clarity:**  The handling of nested rules might be confusing. **Refinement:** Emphasize the use of the stack and how it manages the hierarchy of rules.
* **Completeness:** Ensure all aspects of the prompt are addressed (JavaScript, HTML, CSS relationships, examples, errors).

By following this structured approach, combining code analysis with a high-level understanding of the browser's rendering process and developer tools, a comprehensive and accurate analysis of the `InspectorCSSParserObserver.cc` file can be achieved.好的，让我们来分析一下 `blink/renderer/core/inspector/inspector_css_parser_observer.cc` 这个文件的功能。

**主要功能：**

`InspectorCSSParserObserver` 类的主要功能是在 Blink 渲染引擎解析 CSS 样式表的过程中，作为一个观察者，收集和记录 CSS 规则的结构和源信息。这些信息随后会被用于浏览器的开发者工具（特别是 Elements 面板），以便开发者能够查看和编辑样式，以及进行性能分析和问题排查。

**具体功能分解：**

1. **跟踪 CSS 规则的开始和结束：**
   - `StartRuleHeader(StyleRule::RuleType type, unsigned offset)`:  在解析到一个新的 CSS 规则头部时被调用，例如选择器部分。它会创建一个 `CSSRuleSourceData` 对象来存储该规则的信息，并记录规则头部的起始偏移量。
   - `SetRuleHeaderEnd()`:  记录规则头部的结束偏移量。
   - `EndRuleHeader(unsigned offset)`: 在规则头部解析完毕时调用。
   - `StartRuleBody(unsigned offset)`: 在规则体部（花括号 `{}` 内）开始解析时调用，记录规则体部的起始偏移量。
   - `EndRuleBody(unsigned offset)`: 在规则体部解析完毕时调用，记录规则体部的结束偏移量，并将收集到的规则信息添加到源树中。

2. **记录选择器信息：**
   - `ObserveSelector(unsigned start_offset, unsigned end_offset)`: 当解析到一个 CSS 选择器时被调用，记录选择器在源代码中的起始和结束偏移量。

3. **记录属性信息：**
   - `ObserveProperty(unsigned start_offset, unsigned end_offset, bool is_important, bool is_parsed)`:  当解析到一个 CSS 属性声明时被调用，记录属性的起始和结束偏移量、是否带有 `!important` 标记以及是否成功解析。

4. **处理 CSS 注释：**
   - `ObserveComment(unsigned start_offset, unsigned end_offset)`: 当解析到 CSS 注释时被调用。有趣的是，这个方法会尝试解析注释内部的内容是否像一个 CSS 属性声明，并将其作为禁用状态的属性记录下来。这允许开发者工具展示那些被注释掉的属性。

5. **构建 CSS 规则的源树：**
   - `AddNewRuleToSourceTree(CSSRuleSourceData* rule)`: 将解析完成的 `CSSRuleSourceData` 对象添加到表示 CSS 规则结构的树形数据结构中。这个树形结构反映了 CSS 规则的嵌套关系（例如，媒体查询内部的样式规则）。
   - `RemoveLastRuleFromSourceTree()`:  在解析过程中发生错误时，移除最后添加的规则。
   - `PopRuleData()`:  从规则数据栈中弹出当前规则的数据。

6. **处理错误的 `@` 规则：**
   - `ObserveErroneousAtRule(unsigned start_offset, CSSAtRuleID id, const Vector<CSSPropertyID, 2>& invalid_properties)`:  当解析到一个有错误的 `@` 规则时被调用，例如错误的 `@import` 或 `@property` 规则。它可以报告特定的错误类型，例如 `@import` 过晚导致性能问题，或者 `@property` 规则中的无效属性。

7. **处理 CSS 嵌套声明 (CSS Nesting)：**
   - `ObserveNestedDeclarations(unsigned insert_rule_index)`:  当启用了 CSS 嵌套功能时，用于处理嵌套的声明块。它会将这些嵌套的声明提取出来，作为一个独立的 `CSSRuleSourceData` 对象插入到规则树中。

8. **错误报告和审计：**
   - 涉及到 `issue_reporting_context_` 和 `AuditsIssue`，说明此观察者还参与 CSS 解析过程中的错误和潜在问题（如性能问题）的审计和报告。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这是此观察者直接作用的对象。它监听 CSS 解析器的事件，提取 CSS 规则、选择器和属性的信息。
   * **举例:** 当解析到 `body { background-color: red; }` 时，`StartRuleHeader` 会被调用（类型为 `kStyle`），`ObserveSelector` 会记录 "body" 的位置，`StartRuleBody` 会被调用，`ObserveProperty` 会记录 "background-color: red" 的信息，`EndRuleBody` 会完成规则的记录。

* **HTML:**  此观察者与 HTML 有间接关系。CSS 样式表通常是通过 HTML 中的 `<style>` 标签或 `<link>` 标签引入的。观察者在解析这些样式表时，会知道这些样式是属于哪个 `Document` 对象的。
   * **举例:** 如果一个 HTML 文件包含 `<style> .container { width: 100px; } </style>`，那么当浏览器解析这段 CSS 时，`InspectorCSSParserObserver` 会捕捉到 `.container` 选择器和 `width: 100px` 属性，并将它们关联到该 HTML 文档。

* **JavaScript:**  此观察者本身是用 C++ 实现的，但它收集的信息会被用于浏览器的开发者工具，而开发者工具的 UI 和部分逻辑是用 JavaScript 实现的。JavaScript 代码可以通过 Chrome DevTools Protocol (CDP) 获取 `InspectorCSSParserObserver` 收集到的 CSS 结构信息，并在 Elements 面板中展示。
   * **举例:** 当你在 Elements 面板中查看一个元素的样式时，面板上展示的 CSS 规则、选择器和属性信息，很多就是来源于 `InspectorCSSParserObserver` 在解析 CSS 时记录的数据。你甚至可以编辑这些样式，这些修改最终也会通过某种机制反映到渲染引擎。

**逻辑推理 (假设输入与输出)：**

假设输入的 CSS 代码片段为：

```css
.box {
  color: blue;
  /* font-size: 16px; */
}
```

**观察者的调用顺序和记录的信息：**

1. `StartRuleHeader(kStyle, offset_of_.box)`
2. `ObserveSelector(offset_of_.box, offset_of_.curly_brace_open)`
3. `EndRuleHeader(offset_of_.curly_brace_open)`
4. `StartRuleBody(offset_of_.curly_brace_open)`
5. `ObserveProperty(offset_of_color, offset_of_semi_colon_1, false, true)`  // 记录 color: blue;
6. `ObserveComment(offset_of_comment_start, offset_of_comment_end)` // 尝试解析 /* font-size: 16px; */
   - 内部会尝试解析 "font-size: 16px"，并记录为一个 `disabled` 的属性。
7. `EndRuleBody(offset_of_curly_brace_close)`
8. `AddNewRuleToSourceTree(...)` // 将包含选择器和属性信息的 `CSSRuleSourceData` 对象添加到树中。

**假设输出 (简化的 `CSSRuleSourceData` 结构)：**

```
CSSRuleSourceData {
  type: kStyle,
  rule_header_range: { start: offset_of_.box, end: offset_of_.curly_brace_open },
  rule_body_range: { start: offset_of_.curly_brace_open, end: offset_of_curly_brace_close },
  selector_ranges: [ { start: offset_of_.box, end: offset_of_.curly_brace_open } ],
  property_data: [
    { name: "color", value: "blue", important: false, disabled: false, parsed_ok: true, range: { ... } },
    { name: "font-size", value: "16px", important: false, disabled: true, parsed_ok: true, range: { offset_of_comment_start, offset_of_comment_end } }
  ]
}
```

**用户或编程常见的使用错误：**

1. **CSS 语法错误:**  如果 CSS 代码中存在语法错误，例如拼写错误的属性名、缺少分号等，`InspectorCSSParserObserver` 会记录这些错误。虽然它本身不负责纠正错误，但它会提供足够的信息让开发者工具能够高亮显示错误，并帮助开发者定位问题。
   * **举例:**  `body { backgroud-color: red }` (拼写错误)。`is_parsed` 可能会为 `false`，并且开发者工具会显示一个警告。

2. **`@import` 使用不当:**  在 CSS 中，`@import` 语句应该放在所有其他规则之前。如果 `@import` 出现在其他规则之后，`ObserveErroneousAtRule` 会被调用，并可能报告性能问题，因为延迟加载样式表会阻塞渲染。

3. **错误的 `@property` 规则:**  `@property` 允许开发者定义自定义 CSS 属性。如果 `@property` 规则的语法不正确（例如缺少 `syntax`、`inherits` 或 `initial-value` 描述符，或者描述符的值无效），`ObserveErroneousAtRule` 会被调用，并可以报告具体的错误原因。

4. **误解注释内的属性:** 开发者可能会误以为注释内的属性仍然有效。`InspectorCSSParserObserver` 将其记录为 `disabled` 状态，开发者工具会以特殊的方式展示它们，提醒开发者这些属性是被禁用的。

**总结:**

`InspectorCSSParserObserver` 是 Blink 渲染引擎中一个至关重要的组件，它充当 CSS 解析过程的观察者，负责提取并组织 CSS 规则的结构和源信息。这些信息对于浏览器的开发者工具（特别是 Elements 面板）的功能至关重要，能够帮助开发者理解、调试和优化网页的样式。它与 CSS 直接相关，并通过 HTML 将 CSS 与文档结构联系起来，最终，其收集的数据被 JavaScript 驱动的开发者工具所使用。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_css_parser_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/inspector/inspector_css_parser_observer.h"

#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"

namespace blink {

namespace {

const CSSParserContext* ParserContextForDocument(const Document* document) {
  // Fallback to an insecure context parser if no document is present.
  return document ? MakeGarbageCollected<CSSParserContext>(*document)
                  : StrictCSSParserContext(SecureContextMode::kInsecureContext);
}

}  // namespace

void InspectorCSSParserObserver::StartRuleHeader(StyleRule::RuleType type,
                                                 unsigned offset) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_stack_.pop_back();
  }

  CSSRuleSourceData* data = MakeGarbageCollected<CSSRuleSourceData>(type);
  data->rule_header_range.start = offset;
  current_rule_data_ = data;
  current_rule_data_stack_.push_back(data);
}

template <typename CharacterType>
void InspectorCSSParserObserver::SetRuleHeaderEnd(
    const base::span<const CharacterType> data_start,
    unsigned list_end_offset) {
  while (list_end_offset > 1) {
    if (IsHTMLSpace<CharacterType>(data_start[list_end_offset - 1])) {
      --list_end_offset;
    } else {
      break;
    }
  }

  current_rule_data_stack_.back()->rule_header_range.end = list_end_offset;
  if (!current_rule_data_stack_.back()->selector_ranges.empty()) {
    current_rule_data_stack_.back()->selector_ranges.back().end =
        list_end_offset;
  }
}

void InspectorCSSParserObserver::EndRuleHeader(unsigned offset) {
  DCHECK(!current_rule_data_stack_.empty());

  if (parsed_text_.Is8Bit()) {
    SetRuleHeaderEnd<LChar>(parsed_text_.Span8(), offset);
  } else {
    SetRuleHeaderEnd<UChar>(parsed_text_.Span16(), offset);
  }
}

void InspectorCSSParserObserver::ObserveSelector(unsigned start_offset,
                                                 unsigned end_offset) {
  DCHECK(current_rule_data_stack_.size());
  current_rule_data_stack_.back()->selector_ranges.push_back(
      SourceRange(start_offset, end_offset));
}

void InspectorCSSParserObserver::StartRuleBody(unsigned offset) {
  current_rule_data_ = nullptr;
  DCHECK(!current_rule_data_stack_.empty());
  if (parsed_text_[offset] == '{') {
    ++offset;  // Skip the rule body opening brace.
  }
  current_rule_data_stack_.back()->rule_body_range.start = offset;

  // If this style rule appears on the same offset as a failed property,
  // we need to remove the corresponding CSSPropertySourceData.
  // See `replaceable_property_offset_` for more information.
  if (replaceable_property_offset_.has_value() &&
      current_rule_data_stack_.size() >= 2) {
    if (replaceable_property_offset_ ==
        current_rule_data_stack_.back()->rule_header_range.start) {
      // The outer rule holds a property at the same offset. Remove it.
      CSSRuleSourceData& outer_rule =
          *current_rule_data_stack_[current_rule_data_stack_.size() - 2];
      DCHECK(!outer_rule.property_data.empty());
      outer_rule.property_data.pop_back();
      replaceable_property_offset_ = std::nullopt;
    }
  }
}

void InspectorCSSParserObserver::EndRuleBody(unsigned offset) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_ = nullptr;
    current_rule_data_stack_.pop_back();
  }
  DCHECK(!current_rule_data_stack_.empty());

  CSSRuleSourceData* current_rule = current_rule_data_stack_.back().Get();
  Vector<CSSPropertySourceData>& property_data = current_rule->property_data;

  // See comment about non-empty property_data for rules with
  // HasProperties()==false in ObserveProperty.
  if (!current_rule->HasProperties()) {
    // It's possible for nested grouping rules to still hold some
    // CSSPropertySourceData objects if only commented-out or invalid
    // declarations were observed. There will be no ObserveNestedDeclarations
    // call in that case.
    property_data.clear();
  }

  current_rule->rule_body_range.end = offset;
  current_rule->rule_declarations_range = current_rule->rule_body_range;

  if (!current_rule->child_rules.empty() && !property_data.empty()) {
    // Cut off the declarations range at the end of the last declaration
    // if there are child rules. Following bare declarations are captured
    // by CSSNestedDeclarations.
    unsigned end_of_last_declaration =
        property_data.empty() ? current_rule->rule_declarations_range.start
                              : property_data.back().range.end;
    current_rule->rule_declarations_range.end = end_of_last_declaration;
  }

  AddNewRuleToSourceTree(PopRuleData());
}

void InspectorCSSParserObserver::AddNewRuleToSourceTree(
    CSSRuleSourceData* rule) {
  // After a rule is parsed, if it doesn't have a header range
  // and if it is a style rule it means that this is a "nested group
  // rule"[1][2]. When there are property declarations in this rule there is an
  // implicit nested rule is created for this to hold these declarations[3].
  // However, when there aren't any property declarations in this rule
  // there won't be an implicit nested rule for it and it will only
  // contain parsed child rules[3].
  // So, for that case, we are not adding the source data for the non
  // existent implicit nested rule since it won't exist in the parsed
  // CSS rules from the parser itself.
  //
  // We're also not adding the source data for the non-existent
  // implicit nested rule when there aren't any non-disabled properties
  // inside the rule. A `disabled` property means that
  // it is a commented out property and parsing it happens
  // inside the inspector[4] and it is not a feature of the Blink CSS parser.
  // So, even if there is a disabled property in the rule; the rule is not added
  // as a CSSOM rule in the blink parser, because of this, we're not adding it
  // as a rule to the source data as well.
  //
  //   NOTE: After the introduction of CSSNestedDeclarations, the implicit
  //         wrapper rules are instead handled by ObserveNestedDeclarations.
  //
  // [1]: https://drafts.csswg.org/css-nesting-1/#nested-group-rules
  // [2]:
  // https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/blink/renderer/core/css/parser/css_parser_impl.cc;l=2122;drc=255b4e7036f1326f2219bd547d3d6dcf76064870
  // [3]:
  // https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/blink/renderer/core/css/parser/css_parser_impl.cc;l=2131;drc=255b4e7036f1326f2219bd547d3d6dcf76064870
  // [4]:
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/core/inspector/inspector_style_sheet.cc;l=484?q=f:inspector_style_sheet
  if (!RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled() &&
      rule->rule_header_range.length() == 0 &&
      (rule->type == StyleRule::RuleType::kStyle)) {
    // Check if there is an active property inside the style rule.
    bool contains_active_property = false;
    for (const auto& property_data : rule->property_data) {
      if (!property_data.disabled) {
        contains_active_property = true;
        break;
      }
    }

    // If there isn't any active property declaration
    // there won't be an implicit nested rule created for this rule.
    // So, we skip adding it here too and only add its child rules.
    if (!contains_active_property) {
      // Add the source data for the child rules since they exist in the
      // rule data coming from the parser.
      for (auto& child_rule : rule->child_rules) {
        AddNewRuleToSourceTree(child_rule);
      }
      return;
    }
  }

  if (current_rule_data_stack_.empty()) {
    result_->push_back(rule);
  } else {
    current_rule_data_stack_.back()->child_rules.push_back(rule);
  }
}

void InspectorCSSParserObserver::RemoveLastRuleFromSourceTree() {
  if (current_rule_data_stack_.empty()) {
    result_->pop_back();
  } else {
    current_rule_data_stack_.back()->child_rules.pop_back();
  }
}

CSSRuleSourceData* InspectorCSSParserObserver::PopRuleData() {
  DCHECK(!current_rule_data_stack_.empty());
  current_rule_data_ = nullptr;
  CSSRuleSourceData* data = current_rule_data_stack_.back().Get();
  current_rule_data_stack_.pop_back();
  return data;
}

namespace {

wtf_size_t FindColonIndex(const String& property_string) {
  wtf_size_t index = 0;
  while (index != kNotFound && index < property_string.length()) {
    index = std::min(property_string.Find("/*", index),
                     property_string.Find(":", index));
    if (index == kNotFound || property_string[index] == ':') {
      return index;
    }
    if (index >= property_string.length() - 2) {
      return kNotFound;
    }
    // We're in a comment inside the property name, skip past it.
    index = property_string.Find("*/", index + 2);
    if (index != kNotFound) {
      index += 2;
    }
  }
  return kNotFound;
}

}  // namespace

void InspectorCSSParserObserver::ObserveProperty(unsigned start_offset,
                                                 unsigned end_offset,
                                                 bool is_important,
                                                 bool is_parsed) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_ = nullptr;
    current_rule_data_stack_.pop_back();
  }

  if (current_rule_data_stack_.empty()) {
    return;
  }
  if (!current_rule_data_stack_.back()->HasProperties()) {
    if (!RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled()) {
      // We normally don't allow rules with HasProperties()==false to hold
      // properties directly.
      return;
    }
    // However, with CSSNestedDeclarations enabled, we *can* see ObserveProperty
    // calls for nested group rules, e.g. @media.
    //
    // Example:
    //
    //  div {
    //    @media (width > 100px) {
    //      width: 100px;
    //      height: 100px;
    //    }
    //  }
    //
    // Here, the declarations appear directly within @media, and they are
    // reported as such through the CSSParserObserver. We therefore allow
    // properties (CSSPropertySourceData objects) to exist temporarily
    // on rules with HasProperties()==false, with the expectation that
    // an ObserveNestedDeclarations call will come later and erase those
    // properties again.
  }

  DCHECK_LE(end_offset, parsed_text_.length());
  if (end_offset < parsed_text_.length() &&
      parsed_text_[end_offset] ==
          ';') {  // Include semicolon into the property text.
    ++end_offset;
  }

  DCHECK_LT(start_offset, end_offset);
  String property_string =
      parsed_text_.Substring(start_offset, end_offset - start_offset)
          .StripWhiteSpace();
  if (property_string.EndsWith(';')) {
    property_string = property_string.Left(property_string.length() - 1);
  }
  wtf_size_t colon_index = FindColonIndex(property_string);
  DCHECK_NE(colon_index, kNotFound);

  String name = property_string.Left(colon_index).StripWhiteSpace();
  String value =
      property_string.Substring(colon_index + 1, property_string.length())
          .StripWhiteSpace();
  current_rule_data_stack_.back()->property_data.push_back(
      CSSPropertySourceData(name, value, is_important, false, is_parsed,
                            SourceRange(start_offset, end_offset)));

  // Any property with is_parsed=false becomes a replaceable property.
  // A replaceable property can be replaced by a (valid) style rule
  // at the same offset.
  replaceable_property_offset_ = is_parsed
                                     ? std::optional<unsigned>()
                                     : std::optional<unsigned>(start_offset);
}

void InspectorCSSParserObserver::ObserveComment(unsigned start_offset,
                                                unsigned end_offset) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_ = nullptr;
    current_rule_data_stack_.pop_back();
  }
  DCHECK_LE(end_offset, parsed_text_.length());

  if (current_rule_data_stack_.empty() ||
      !current_rule_data_stack_.back()->rule_header_range.end) {
    return;
  }
  if (!current_rule_data_stack_.back()->HasProperties() &&
      !RuntimeEnabledFeatures::CSSNestedDeclarationsEnabled()) {
    // See comment for similar check in ObserveProperty.
    return;
  }

  // The lexer is not inside a property AND it is scanning a declaration-aware
  // rule body.
  String comment_text =
      parsed_text_.Substring(start_offset, end_offset - start_offset);

  DCHECK(comment_text.StartsWith("/*"));
  comment_text = comment_text.Substring(2);

  // Require well-formed comments.
  if (!comment_text.EndsWith("*/")) {
    return;
  }
  comment_text =
      comment_text.Substring(0, comment_text.length() - 2).StripWhiteSpace();
  if (comment_text.empty()) {
    return;
  }

  // FIXME: Use the actual rule type rather than STYLE_RULE?
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();

  InspectorCSSParserObserver observer(comment_text, document_, source_data);
  CSSParser::ParseDeclarationListForInspector(
      ParserContextForDocument(document_), comment_text, observer);
  Vector<CSSPropertySourceData>& comment_property_data =
      source_data->front()->property_data;
  if (comment_property_data.size() != 1) {
    return;
  }
  CSSPropertySourceData& property_data = comment_property_data.at(0);
  bool parsed_ok = property_data.parsed_ok ||
                   property_data.name.StartsWith("-moz-") ||
                   property_data.name.StartsWith("-o-") ||
                   property_data.name.StartsWith("-webkit-") ||
                   property_data.name.StartsWith("-ms-");
  if (!parsed_ok || property_data.range.length() != comment_text.length()) {
    return;
  }

  current_rule_data_stack_.back()->property_data.push_back(
      CSSPropertySourceData(property_data.name, property_data.value, false,
                            true, true, SourceRange(start_offset, end_offset)));
}

static OrdinalNumber AddOrdinalNumbers(OrdinalNumber a, OrdinalNumber b) {
  if (a == OrdinalNumber::BeforeFirst() || b == OrdinalNumber::BeforeFirst()) {
    return a;
  }
  return OrdinalNumber::FromZeroBasedInt(a.ZeroBasedInt() + b.ZeroBasedInt());
}

TextPosition InspectorCSSParserObserver::GetTextPosition(
    unsigned start_offset) {
  if (!issue_reporting_context_) {
    return TextPosition::BelowRangePosition();
  }
  const LineEndings* line_endings = GetLineEndings();
  TextPosition start =
      TextPosition::FromOffsetAndLineEndings(start_offset, *line_endings);
  if (start.line_.ZeroBasedInt() == 0) {
    start.column_ = AddOrdinalNumbers(
        start.column_, issue_reporting_context_->OffsetInSource.column_);
  }
  start.line_ = AddOrdinalNumbers(
      start.line_, issue_reporting_context_->OffsetInSource.line_);
  return start;
}

void InspectorCSSParserObserver::ObserveErroneousAtRule(
    unsigned start_offset,
    CSSAtRuleID id,
    const Vector<CSSPropertyID, 2>& invalid_properties) {
  switch (id) {
    case CSSAtRuleID::kCSSAtRuleImport:
      if (issue_reporting_context_) {
        TextPosition start = GetTextPosition(start_offset);
        AuditsIssue::ReportStylesheetLoadingLateImportIssue(
            document_, issue_reporting_context_->DocumentURL, start.line_,
            start.column_);
      }
      break;
    case CSSAtRuleID::kCSSAtRuleProperty: {
      if (invalid_properties.empty()) {
        if (issue_reporting_context_) {
          // Invoked from the prelude handling, which means the name is invalid.
          TextPosition start = GetTextPosition(start_offset);
          AuditsIssue::ReportPropertyRuleIssue(
              document_, issue_reporting_context_->DocumentURL, start.line_,
              start.column_,
              protocol::Audits::PropertyRuleIssueReasonEnum::InvalidName, {});
        }
      } else {
        // The rule is being dropped because it lacks required descriptors, or
        // some descriptors have invalid values. The rule has already been
        // committed and must be removed.
        for (CSSPropertyID invalid_property : invalid_properties) {
          ReportPropertyRuleFailure(start_offset, invalid_property);
        }
        RemoveLastRuleFromSourceTree();
      }
      break;
    }
    default:
      break;
  }
}

void InspectorCSSParserObserver::ObserveNestedDeclarations(
    unsigned insert_rule_index) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_ = nullptr;
    current_rule_data_stack_.pop_back();
  }

  CHECK(!current_rule_data_stack_.empty());
  CSSRuleSourceData* rule = current_rule_data_stack_.back().Get();
  Vector<CSSPropertySourceData>& property_data = rule->property_data;
  HeapVector<Member<CSSRuleSourceData>>& child_rules = rule->child_rules;

  CHECK_LE(insert_rule_index, child_rules.size());

  // We're going to insert a CSSRuleSourceData for the nested declarations
  // rule at `insert_rule_index`. The rule that ends up immediately before
  // that CSSRuleSourceData is the "preceding rule".
  CSSRuleSourceData* preceding_rule =
      (insert_rule_index > 0) ? child_rules[insert_rule_index - 1].Get()
                              : nullptr;

  // Traverse backwards until we see a declaration at the preceding rule,
  // or earlier.
  Vector<CSSPropertySourceData>::iterator iter = property_data.end();
  while (iter != property_data.begin()) {
    Vector<CSSPropertySourceData>::iterator prev = std::prev(iter);
    if (preceding_rule &&
        (prev->range.start <= preceding_rule->rule_body_range.end)) {
      break;
    }
    iter = prev;
  }

  // Copy the CSSPropertySourceData objects between preceding and following
  // rules into a new CSSRuleSourceData object for the nested declarations.
  Vector<CSSPropertySourceData> nested_property_data;
  std::ranges::copy(iter, property_data.end(),
                    std::back_inserter(nested_property_data));
  // Remove the objects we just copied from the original vector. They should
  // only exist in one place.
  property_data.resize(property_data.size() - nested_property_data.size());

  // Determine the range for the CSSNestedDeclarations rule body.
  SourceRange range;

  if (!nested_property_data.empty()) {
    range.start = nested_property_data.front().range.start;
    range.end = nested_property_data.back().range.end;
  } else {
    // Completely empty CSSNestedDeclarations rules can happen when there are no
    // declarations at at all (not even a commented-out/invalid declaration).
    // In this case, we need to pick another reasonable location for the
    // would-be CSSNestedDeclarations rule.
    if (preceding_rule) {
      // Add one to move past the final '}'.
      range.start = preceding_rule->rule_body_range.end + 1;
      range.end = range.start;
    } else {
      range.start = rule->rule_body_range.start;
      range.end = range.start;
    }
  }

  // Note that the nested declarations rule has no prelude (i.e. no selector
  // list), and no curly brackets surrounding its body. Therefore, the header
  // range is empty, and exists at the same offset as the body-start.
  auto* nested_declarations_rule =
      MakeGarbageCollected<CSSRuleSourceData>(StyleRule::kStyle);
  // Note: CSSNestedDeclarations rules have no prelude, hence
  // `rule_header_range` is always empty.
  nested_declarations_rule->rule_header_range.start = range.start;
  nested_declarations_rule->rule_header_range.end = range.start;
  nested_declarations_rule->rule_body_range = range;
  nested_declarations_rule->rule_declarations_range = range;
  nested_declarations_rule->property_data = std::move(nested_property_data);
  child_rules.insert(insert_rule_index, nested_declarations_rule);
}

static CSSPropertySourceData* GetPropertySourceData(
    CSSRuleSourceData& source_data,
    StringView propertyName) {
  auto property = std::find_if(
      source_data.property_data.rbegin(), source_data.property_data.rend(),
      [propertyName](auto&& prop) { return prop.name == propertyName; });
  if (property == source_data.property_data.rend()) {
    return nullptr;
  }
  return &*property;
}

static std::pair<const char*, const char*> GetPropertyNameAndIssueReason(
    CSSPropertyID invalid_property) {
  switch (invalid_property) {
    case CSSPropertyID::kInitialValue:
      return std::make_pair(
          "initial-value",
          protocol::Audits::PropertyRuleIssueReasonEnum::InvalidInitialValue);
    case CSSPropertyID::kSyntax:
      return std::make_pair(
          "syntax",
          protocol::Audits::PropertyRuleIssueReasonEnum::InvalidSyntax);
    case CSSPropertyID::kInherits:
      return std::make_pair(
          "inherits",
          protocol::Audits::PropertyRuleIssueReasonEnum::InvalidInherits);
    default:
      return std::make_pair(nullptr, nullptr);
  }
}

void InspectorCSSParserObserver::ReportPropertyRuleFailure(
    unsigned start_offset,
    CSSPropertyID invalid_property) {
  if (!issue_reporting_context_) {
    return;
  }
  auto [property_name, issue_reason] =
      GetPropertyNameAndIssueReason(invalid_property);
  if (!property_name) {
    return;
  }

  // We expect AddNewRuleToSourceTree to have been called
  DCHECK((current_rule_data_stack_.empty() && !result_->empty()) ||
         (!current_rule_data_stack_.empty() &&
          !current_rule_data_stack_.back()->child_rules.empty()));
  auto source_data = current_rule_data_stack_.empty()
                         ? result_->back()
                         : current_rule_data_stack_.back()->child_rules.back();

  CSSPropertySourceData* property_data =
      GetPropertySourceData(*source_data, property_name);
  TextPosition start = GetTextPosition(
      property_data ? property_data->range.start : start_offset);
  String value = property_data ? property_data->value : String();
  AuditsIssue::ReportPropertyRuleIssue(
      document_, issue_reporting_context_->DocumentURL, start.line_,
      start.column_, issue_reason, value);
}

const LineEndings* InspectorCSSParserObserver::GetLineEndings() {
  if (line_endings_->size() > 0) {
    return line_endings_.get();
  }
  line_endings_ = WTF::GetLineEndings(parsed_text_);
  return line_endings_.get();
}

}  // namespace blink
```