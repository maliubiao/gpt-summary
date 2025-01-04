Response:
Let's break down the thought process for analyzing the `StyleSheetContents.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JS, HTML, CSS), examples, logical reasoning, common errors, and debugging context. Essentially, we need to understand what this C++ file *does* within the Blink rendering engine.

2. **Initial Scan for Keywords and Structure:**  I'd first skim the code, looking for:
    * **File Headers:**  Copyright notices can give hints about the file's age and origin (in this case, KDE and Apple, suggesting a long history).
    * **Includes:** These are crucial. They tell us what other parts of the Blink engine this file interacts with:
        * `css/`:  Obvious connection to CSS concepts like `CSSPropertyValueSet`, `CSSStyleSheet`, `CSSParser`, `StyleEngine`, `StyleRule`, etc.
        * `dom/`:  Interaction with the Document Object Model (`Document`, `Node`, `ShadowRoot`).
        * `inspector/`: Hints at debugging and developer tools integration.
        * `loader/resource/`:  Loading of CSS resources.
        * `platform/`: Lower-level platform abstractions.
    * **Class Definition:** The core of the file is the `StyleSheetContents` class. I'd note its members and methods.
    * **Static Members:**  `SingleOwnerDocument` stands out.
    * **Constructor/Destructor:** How are these objects created and destroyed?
    * **Methods related to rules:** `ParserAppendRule`, `RuleAt`, `RuleCount`, `ClearRules`, `WrapperInsertRule`, `WrapperDeleteRule`, etc. These are central to managing CSS rules.
    * **Methods related to parsing:** `ParseAuthorStyleSheet`, `ParseString`.
    * **Methods related to loading:** `IsLoading`, `LoadCompleted`, `CheckLoaded`, `NotifyLoadedSheet`.
    * **Methods related to clients:** `RegisterClient`, `UnregisterClient`, `ClientLoadCompleted`, `ClientLoadStarted`. This hints at how `StyleSheetContents` is used by other parts of the engine.
    * **Methods related to mutations:** `StartMutation`, `ClearRuleSet`.
    * **Namespace Handling:** `ParserAddNamespace`, `NamespaceURIFromPrefix`.
    * **Memory Management:** `EstimatedSizeInBytes`.

3. **Categorize Functionality:** Based on the initial scan, I'd start grouping the methods into functional areas:
    * **Core CSS Rule Management:**  Adding, removing, accessing, and iterating over CSS rules.
    * **Parsing:**  Taking CSS text and turning it into the internal representation.
    * **Loading and Resource Management:** Handling the loading of external stylesheets and tracking their status.
    * **Client Management:**  Keeping track of which `CSSStyleSheet` objects are using this `StyleSheetContents`.
    * **Namespace Support:** Handling `@namespace` declarations.
    * **Mutation and Change Tracking:**  Supporting modifications to stylesheets and tracking changes.
    * **Memory Estimation:**  For caching purposes.
    * **Debugging and Inspection:** Integration with developer tools.

4. **Relate to Web Technologies:** Now, I'd explicitly connect the categorized functionality to JS, HTML, and CSS:
    * **CSS:** The most direct relationship. Everything in this file is about representing and managing CSS. Examples would be the different types of rules (`StyleRule`, `StyleRuleImport`, etc.) and the parsing process.
    * **HTML:**  How are stylesheets attached to HTML?  The `<style>` tag and `<link>` tag. The `ownerNode()` concept links back to the HTML element. Shadow DOM is also mentioned, indicating support for encapsulated styling.
    * **JavaScript:** How does JS interact with stylesheets?  The CSSOM (CSS Object Model) allows JS to manipulate stylesheets. Methods like `insertRule`, `deleteRule`, and accessing `cssRules` are the JS side of the operations performed in this C++ file.

5. **Develop Examples:**  For each category or key method, create concrete examples:
    * **CSS:** Show the syntax for `@import`, `@namespace`, and regular CSS rules.
    * **HTML:**  Illustrate the `<style>` and `<link>` tags.
    * **JavaScript:** Demonstrate using `document.styleSheets`, `insertRule`, etc.

6. **Logical Reasoning (Input/Output):**  Think about how the methods transform data.
    * **Parsing:**  Input: CSS text. Output: A structured representation of CSS rules within `StyleSheetContents`.
    * **`WrapperInsertRule`:** Input: A new `StyleRuleBase` and an index. Output: Modification of the internal rule lists, potentially returning `true` or `false` based on validity.
    * **Loading:**  Input: A CSS resource URL. Output: Populated rule lists.

7. **Common Errors:** Consider what mistakes developers might make that would involve this file:
    * **CSS Syntax Errors:**  The parser would encounter these.
    * **Incorrect `@import` Placement:** The parser enforces this.
    * **Modifying Immutable Stylesheets:**  Attempting to use methods like `WrapperInsertRule` on a stylesheet that isn't mutable.
    * **Namespace Conflicts:**  Trying to define the same prefix multiple times.

8. **Debugging Scenario:**  Imagine a specific problem and how a developer might arrive at this file during debugging:
    * **Problem:** Styles aren't being applied correctly.
    * **Steps:** Inspect the CSS rules in the browser's developer tools. Notice an imported stylesheet isn't loading or has errors. Set breakpoints in Blink's CSS loading code, potentially landing in `StyleSheetContents.cc` to understand how the rules are being processed and if loading is completing correctly.

9. **Structure and Refine:** Organize the information logically. Start with a high-level overview, then delve into specifics. Use clear headings and bullet points. Ensure the language is precise but also understandable. For instance, explaining the "client" concept is important for understanding the file's role.

10. **Self-Correction/Review:**  Read through the explanation. Does it make sense? Are the examples clear? Have I addressed all parts of the request?  For example, I initially might not have emphasized the "client" concept enough, but upon review, I'd realize it's crucial for understanding how `StyleSheetContents` interacts with `CSSStyleSheet`. Similarly, explicitly mentioning the CSSOM bridges the gap between C++ implementation and JavaScript usage.
这个文件 `blink/renderer/core/css/style_sheet_contents.cc` 是 Chromium Blink 引擎中负责**存储和管理 CSS 样式表内容**的核心组件。它可以被看作是 CSS 样式表的内部数据模型。

以下是它的主要功能：

**1. 存储 CSS 规则：**

* 它维护着一个包含各种 CSS 规则的列表，例如：
    * **Style Rules (规则集):** 包含选择器和声明块 (例如 `p { color: red; }`)。
    * **Import Rules (`@import`):** 引用其他样式表。
    * **Namespace Rules (`@namespace`):** 定义 XML 命名空间。
    * **Layer Statement Rules (`@layer`):** 定义级联层叠上下文。
    * **其他规则:** 例如 `@media`, `@font-face` 等。
* 它使用不同的内部数据结构来组织这些规则，例如 `pre_import_layer_statement_rules_`, `import_rules_`, `namespace_rules_`, `child_rules_`。

**2. 解析和构建样式表：**

* 当浏览器加载一个 CSS 文件或遇到 `<style>` 标签时，Blink 的 CSS 解析器会将 CSS 文本转换为 `StyleSheetContents` 对象，并将解析出的规则存储在其中。
* `ParseAuthorStyleSheet` 方法负责解析外部 CSS 资源。
* `ParseString` 方法负责解析字符串形式的 CSS 内容。
* `ParserAppendRule` 方法在解析过程中将单个规则添加到 `StyleSheetContents` 中。

**3. 管理样式表的元数据：**

* 存储样式表的原始 URL (`original_url_`)。
* 记录是否成功加载 (`did_load_error_occur_`)。
* 标记样式表是否可以修改 (`is_mutable_`)。
* 标记样式表是否包含 `@font-face` 规则 (`has_font_face_rule_`) 或媒体查询 (`has_media_queries_`)。
* 管理与此样式表关联的命名空间 (`namespaces_`, `default_namespace_`)。

**4. 处理 `@import` 规则：**

* 跟踪导入的样式表 (`import_rules_`)。
* 触发对导入的样式表的加载 (`RequestStyleSheet`).
* 维护父样式表的引用 (`owner_rule_`).

**5. 支持动态修改样式表：**

* 提供 `WrapperInsertRule` 和 `WrapperDeleteRule` 方法，允许 JavaScript 通过 CSSOM (CSS Object Model) 动态地添加或删除规则。
* `StartMutation` 方法标记样式表开始被修改。

**6. 与渲染引擎集成：**

* 提供方法来获取特定索引的规则 (`RuleAt`).
* 提供方法来获取规则的数量 (`RuleCount`).
* 提供 `ClearRules` 方法来清空所有规则。
* 当样式表内容发生变化时，会通知渲染引擎更新样式 (`ClearRuleSet`).

**7. 缓存和性能优化：**

* 提供 `EstimatedSizeInBytes` 方法来估算内存占用，用于缓存管理。
* 提供 `IsCacheableForResource` 和 `IsCacheableForStyleElement` 方法来判断是否可以缓存。

**8. 与其他 Blink 组件的交互：**

* 与 `CSSParser` 协同完成 CSS 解析。
* 与 `StyleEngine` 交互，通知样式更新。
* 与 `Document` 和 `Node` 关联，表示样式表属于哪个文档或节点。
* 与 `CSSStyleSheet` (JavaScript 可访问的 CSSOM 对象) 关联，作为其内部数据。
* 与 `CSSStyleSheetResource` 关联，表示外部加载的 CSS 资源。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  `StyleSheetContents` 是 CSS 规则在 Blink 内部的表示。它解析 CSS 文本，并将规则存储在内部数据结构中。
    * **举例:** 当解析器遇到 `p { color: blue; }` 时，会创建一个 `StyleRule` 对象并将其添加到 `child_rules_` 列表中。
* **HTML:** HTML 中的 `<style>` 标签或 `<link>` 标签会触发创建 `StyleSheetContents` 对象。
    * **举例:** 当浏览器解析到 `<style> body { margin: 0; }</style>` 时，会创建一个 `StyleSheetContents` 对象，并将 `body { margin: 0; }` 解析成一个 `StyleRule` 存储起来。
    * **举例:** 当浏览器解析到 `<link rel="stylesheet" href="style.css">` 时，会创建一个 `StyleSheetContents` 对象来存储 `style.css` 的内容。
* **JavaScript:** JavaScript 通过 CSSOM 与 `StyleSheetContents` 交互。`CSSStyleSheet` 对象在 JavaScript 中代表一个样式表，而 `StyleSheetContents` 是 `CSSStyleSheet` 的底层实现。
    * **举例:**  在 JavaScript 中执行 `document.styleSheets[0].insertRule("a { text-decoration: none; }", 0)`，最终会调用 `StyleSheetContents` 的 `WrapperInsertRule` 方法，将新的 `StyleRule` 添加到其内部的规则列表中。
    * **举例:**  在 JavaScript 中访问 `document.styleSheets[0].cssRules` 会间接地访问 `StyleSheetContents` 中存储的 CSS 规则。

**逻辑推理 (假设输入与输出):**

假设输入一段 CSS 字符串：

```css
@import "reset.css";
@namespace svg url("http://www.w3.org/2000/svg");
body { font-size: 16px; }
```

**假设输入:**  包含上述 CSS 字符串的 `sheet_text` 传递给 `ParseString` 方法。

**输出:**

* `import_rules_` 列表中会包含一个 `StyleRuleImport` 对象，其 URL 为 "reset.css"。
* `namespace_rules_` 列表中会包含一个 `StyleRuleNamespace` 对象，前缀为 "svg"，URI 为 "http://www.w3.org/2000/svg"。
* `child_rules_` 列表中会包含一个 `StyleRule` 对象，选择器为 "body"，声明块包含 `font-size: 16px;`。

**涉及用户或编程常见的使用错误及举例说明：**

* **错误的 `@import` 放置:** CSS 规定 `@import` 规则必须放在其他规则之前。如果用户在 `<style>` 标签中或通过 JavaScript 的 `insertRule` 在其他规则之后添加 `@import`，Blink 的解析器会拒绝并可能报错。
    * **例子:**
    ```html
    <style>
      body { color: black; }
      @import "other.css"; /* 错误：@import 应该放在前面 */
    </style>
    ```
    Blink 会忽略这个 `@import` 规则。

* **修改不可变样式表:** 从外部 CSS 文件加载的样式表通常是不可变的。尝试通过 JavaScript 的 CSSOM 修改这些样式表会失败。
    * **例子:** 如果 `style.css` 是通过 `<link>` 标签引入的，尝试 `document.styleSheets[0].insertRule(...)` 可能会抛出异常或不生效。

* **命名空间前缀冲突:**  如果在一个样式表中定义了重复的命名空间前缀，可能会导致样式应用不符合预期。
    * **例子:**
    ```css
    @namespace svg url("http://www.w3.org/2000/svg");
    @namespace svg url("http://example.com/different"); /* 可能会导致冲突 */
    ```

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **浏览器解析 HTML 文档。**
3. **当浏览器遇到 `<style>` 标签或 `<link>` 标签时，会触发 CSS 资源的加载和解析。**
4. **Blink 的网络模块下载 CSS 文件 (对于 `<link>` 标签)。**
5. **Blink 的 CSS 解析器 (位于 `blink/renderer/core/css/parser/`) 开始解析 CSS 文本。**
6. **解析器会创建一个 `StyleSheetContents` 对象来存储样式表的内容。**
7. **在解析过程中，每当解析到一个 CSS 规则，`CSSParser` 就会调用 `StyleSheetContents` 的 `ParserAppendRule` 方法将其添加到内部列表中。**
8. **如果遇到 `@import` 规则，`StyleSheetContents` 会触发对被导入样式表的加载。**
9. **当 JavaScript 代码通过 CSSOM (例如 `document.styleSheets[0].insertRule(...)`) 修改样式表时，会调用 `StyleSheetContents` 相应的方法 (例如 `WrapperInsertRule`)。**

**调试线索:**

* **样式没有按预期应用:**  可能需要检查 `StyleSheetContents` 中存储的规则是否正确，是否存在优先级问题，或者是否因为解析错误导致规则没有被正确添加。
* **`@import` 规则没有生效:** 可以检查 `import_rules_` 列表是否为空，以及被导入的样式表是否加载成功。
* **JavaScript 修改样式表失败:**  可以检查样式表是否是可变的 (`is_mutable_`)，以及调用的 CSSOM 方法和参数是否正确。
* **命名空间相关样式问题:** 可以检查 `namespaces_` 和 `default_namespace_` 的值是否符合预期。

通过在 `StyleSheetContents.cc` 及其相关文件中设置断点，例如在 `ParserAppendRule`, `WrapperInsertRule`, `ParseAuthorStyleSheet` 等方法中，开发者可以跟踪 CSS 规则的解析、添加和修改过程，从而定位样式问题的根源。  观察 `StyleSheetContents` 对象的内部状态，例如规则列表的内容，可以帮助理解浏览器是如何处理 CSS 的。

Prompt: 
```
这是目录为blink/renderer/core/css/style_sheet_contents.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * (C) 1999-2003 Lars Knoll (knoll@kde.org)
 * Copyright (C) 2004, 2006, 2007, 2012 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/css/style_sheet_contents.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_rule_counter_style.h"
#include "third_party/blink/renderer/core/css/style_rule_import.h"
#include "third_party/blink/renderer/core/css/style_rule_namespace.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/loader/resource/css_style_sheet_resource.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

// static
const Document* StyleSheetContents::SingleOwnerDocument(
    const StyleSheetContents* style_sheet_contents) {
  // TODO(https://crbug.com/242125): We may want to handle stylesheets that have
  // multiple owners when this is used for UseCounter.
  if (style_sheet_contents && style_sheet_contents->HasSingleOwnerNode()) {
    return style_sheet_contents->SingleOwnerDocument();
  }
  return nullptr;
}

// Rough size estimate for the memory cache.
unsigned StyleSheetContents::EstimatedSizeInBytes() const {
  // Note that this does not take into account size of the strings hanging from
  // various objects. The assumption is that nearly all of of them are atomic
  // and would exist anyway.
  unsigned size = sizeof(*this);

  // FIXME: This ignores the children of media rules.
  // Most rules are StyleRules.
  size += RuleCount() * StyleRule::AverageSizeInBytes();

  for (unsigned i = 0; i < import_rules_.size(); ++i) {
    if (StyleSheetContents* sheet = import_rules_[i]->GetStyleSheet()) {
      size += sheet->EstimatedSizeInBytes();
    }
  }
  return size;
}

StyleSheetContents::StyleSheetContents(const CSSParserContext* context,
                                       const String& original_url,
                                       StyleRuleImport* owner_rule)
    : owner_rule_(owner_rule),
      original_url_(original_url),
      default_namespace_(g_star_atom),
      has_syntactically_valid_css_header_(true),
      did_load_error_occur_(false),
      is_mutable_(false),
      has_font_face_rule_(false),
      has_media_queries_(false),
      has_single_owner_document_(true),
      is_used_from_text_cache_(false),
      parser_context_(context) {}

StyleSheetContents::StyleSheetContents(const StyleSheetContents& o)
    : owner_rule_(nullptr),
      original_url_(o.original_url_),
      pre_import_layer_statement_rules_(
          o.pre_import_layer_statement_rules_.size()),
      import_rules_(o.import_rules_.size()),
      namespace_rules_(o.namespace_rules_.size()),
      child_rules_(o.child_rules_.size()),
      namespaces_(o.namespaces_),
      default_namespace_(o.default_namespace_),
      has_syntactically_valid_css_header_(
          o.has_syntactically_valid_css_header_),
      did_load_error_occur_(false),
      is_mutable_(false),
      has_font_face_rule_(o.has_font_face_rule_),
      has_media_queries_(o.has_media_queries_),
      has_single_owner_document_(true),
      is_used_from_text_cache_(false),
      parser_context_(o.parser_context_) {
  for (unsigned i = 0; i < pre_import_layer_statement_rules_.size(); ++i) {
    pre_import_layer_statement_rules_[i] = To<StyleRuleLayerStatement>(
        o.pre_import_layer_statement_rules_[i]->Copy());
  }

  // FIXME: Copy import rules.
  DCHECK(o.import_rules_.empty());

  for (unsigned i = 0; i < namespace_rules_.size(); ++i) {
    namespace_rules_[i] =
        static_cast<StyleRuleNamespace*>(o.namespace_rules_[i]->Copy());
  }

  // Copying child rules is a strict point for deferred property parsing, so
  // there is no need to copy lazy parsing state here.
  for (unsigned i = 0; i < child_rules_.size(); ++i) {
    child_rules_[i] = o.child_rules_[i]->Copy();
  }
}

StyleSheetContents::~StyleSheetContents() = default;

void StyleSheetContents::SetHasSyntacticallyValidCSSHeader(bool is_valid_css) {
  has_syntactically_valid_css_header_ = is_valid_css;
}

bool StyleSheetContents::IsCacheableForResource() const {
  // This would require dealing with multiple clients for load callbacks.
  if (!LoadCompleted()) {
    return false;
  }
  // FIXME: Support copying import rules.
  if (!import_rules_.empty()) {
    return false;
  }
  // FIXME: Support cached stylesheets in import rules.
  if (owner_rule_) {
    return false;
  }
  if (did_load_error_occur_) {
    return false;
  }
  // It is not the original sheet anymore.
  if (is_mutable_) {
    return false;
  }
  // If the header is valid we are not going to need to check the
  // SecurityOrigin.
  // FIXME: Valid mime type avoids the check too.
  if (!has_syntactically_valid_css_header_) {
    return false;
  }
  return true;
}

bool StyleSheetContents::IsCacheableForStyleElement() const {
  // FIXME: Support copying import rules.
  if (!ImportRules().empty()) {
    return false;
  }
  // Until import rules are supported in cached sheets it's not possible for
  // loading to fail.
  DCHECK(!DidLoadErrorOccur());
  // It is not the original sheet anymore.
  if (IsMutable()) {
    return false;
  }
  if (!HasSyntacticallyValidCSSHeader()) {
    return false;
  }
  return true;
}

void StyleSheetContents::ParserAppendRule(StyleRuleBase* rule) {
  if (auto* layer_statement_rule = DynamicTo<StyleRuleLayerStatement>(rule)) {
    if (import_rules_.empty() && namespace_rules_.empty() &&
        child_rules_.empty()) {
      pre_import_layer_statement_rules_.push_back(layer_statement_rule);
      return;
    }
    // Falls through, insert it into child_rules_ as a regular rule
  }

  if (auto* import_rule = DynamicTo<StyleRuleImport>(rule)) {
    // Parser enforces that @import rules come before anything else other than
    // empty layer statements
    DCHECK(child_rules_.empty());
    if (import_rule->MediaQueries()) {
      SetHasMediaQueries();
    }
    import_rules_.push_back(import_rule);
    import_rules_.back()->SetParentStyleSheet(this);
    import_rules_.back()->RequestStyleSheet();
    return;
  }

  if (auto* namespace_rule = DynamicTo<StyleRuleNamespace>(rule)) {
    // Parser enforces that @namespace rules come before all rules other than
    // import/charset rules and empty layer statements
    DCHECK(child_rules_.empty());
    ParserAddNamespace(namespace_rule->Prefix(), namespace_rule->Uri());
    namespace_rules_.push_back(namespace_rule);
    return;
  }

  child_rules_.push_back(rule);
}

void StyleSheetContents::SetHasMediaQueries() {
  has_media_queries_ = true;
  if (ParentStyleSheet()) {
    ParentStyleSheet()->SetHasMediaQueries();
  }
}

StyleRuleBase* StyleSheetContents::RuleAt(unsigned index) const {
  SECURITY_DCHECK(index < RuleCount());

  if (index < pre_import_layer_statement_rules_.size()) {
    return pre_import_layer_statement_rules_[index].Get();
  }

  index -= pre_import_layer_statement_rules_.size();

  if (index < import_rules_.size()) {
    return import_rules_[index].Get();
  }

  index -= import_rules_.size();

  if (index < namespace_rules_.size()) {
    return namespace_rules_[index].Get();
  }

  index -= namespace_rules_.size();

  return child_rules_[index].Get();
}

unsigned StyleSheetContents::RuleCount() const {
  return pre_import_layer_statement_rules_.size() + import_rules_.size() +
         namespace_rules_.size() + child_rules_.size();
}

void StyleSheetContents::ClearRules() {
  pre_import_layer_statement_rules_.clear();
  for (unsigned i = 0; i < import_rules_.size(); ++i) {
    DCHECK_EQ(import_rules_.at(i)->ParentStyleSheet(), this);
    import_rules_[i]->ClearParentStyleSheet();
  }

  if (rule_set_diff_) {
    rule_set_diff_->MarkUnrepresentable();
  }

  import_rules_.clear();
  namespace_rules_.clear();
  child_rules_.clear();
}

static wtf_size_t ReplaceRuleIfExistsInternal(
    const StyleRuleBase* old_rule,
    StyleRuleBase* new_rule,
    HeapVector<Member<StyleRuleBase>>& child_rules) {
  for (wtf_size_t i = 0; i < child_rules.size(); ++i) {
    StyleRuleBase* rule = child_rules[i].Get();
    if (rule == old_rule) {
      child_rules[i] = new_rule;
      return i;
    }
    if (auto* style_rule_group = DynamicTo<StyleRuleGroup>(rule)) {
      if (ReplaceRuleIfExistsInternal(old_rule, new_rule,
                                      style_rule_group->ChildRules()) !=
          std::numeric_limits<wtf_size_t>::max()) {
        return 0;  // Dummy non-failure value.
      }
    } else if (auto* style_rule = DynamicTo<StyleRule>(rule);
               style_rule && style_rule->ChildRules()) {
      if (ReplaceRuleIfExistsInternal(old_rule, new_rule,
                                      *style_rule->ChildRules()) !=
          std::numeric_limits<wtf_size_t>::max()) {
        return 0;  // Dummy non-failure value.
      }
    }
  }

  // Not found.
  return std::numeric_limits<wtf_size_t>::max();
}

wtf_size_t StyleSheetContents::ReplaceRuleIfExists(StyleRuleBase* old_rule,
                                                   StyleRuleBase* new_rule,
                                                   wtf_size_t position_hint) {
  if (rule_set_diff_) {
    rule_set_diff_->AddDiff(old_rule);
    rule_set_diff_->AddDiff(new_rule);
  }

  if (position_hint < child_rules_.size() &&
      child_rules_[position_hint] == old_rule) {
    child_rules_[position_hint] = new_rule;
    return position_hint;
  }

  return ReplaceRuleIfExistsInternal(old_rule, new_rule, child_rules_);
}

bool StyleSheetContents::WrapperInsertRule(StyleRuleBase* rule,
                                           unsigned index) {
  DCHECK(is_mutable_);
  SECURITY_DCHECK(index <= RuleCount());

  if (rule_set_diff_) {
    rule_set_diff_->AddDiff(rule);
  }

  // If the sheet starts with empty layer statements without any import or
  // namespace rules, we should be able to insert any rule before and between
  // the empty layer statements. To support this case, we move any existing
  // empty layer statement to child_rules_ first.
  if (pre_import_layer_statement_rules_.size() && !import_rules_.size() &&
      !namespace_rules_.size()) {
    child_rules_.PrependVector(pre_import_layer_statement_rules_);
    pre_import_layer_statement_rules_.clear();
  }

  if (index < pre_import_layer_statement_rules_.size() ||
      (index == pre_import_layer_statement_rules_.size() &&
       rule->IsLayerStatementRule())) {
    // Empty layer statements before import rules should be a continuous block.
    auto* layer_statement_rule = DynamicTo<StyleRuleLayerStatement>(rule);
    if (!layer_statement_rule) {
      return false;
    }

    pre_import_layer_statement_rules_.insert(index, layer_statement_rule);
    return true;
  }

  index -= pre_import_layer_statement_rules_.size();

  if (index < import_rules_.size() ||
      (index == import_rules_.size() && rule->IsImportRule())) {
    // Inserting non-import rule before @import is not allowed.
    auto* import_rule = DynamicTo<StyleRuleImport>(rule);
    if (!import_rule) {
      return false;
    }

    if (import_rule->MediaQueries()) {
      SetHasMediaQueries();
    }

    import_rules_.insert(index, import_rule);
    import_rules_[index]->SetParentStyleSheet(this);
    import_rules_[index]->RequestStyleSheet();
    // FIXME: Stylesheet doesn't actually change meaningfully before the
    // imported sheets are loaded.
    return true;
  }
  // Inserting @import rule after a non-import rule is not allowed.
  if (rule->IsImportRule()) {
    return false;
  }

  index -= import_rules_.size();

  if (index < namespace_rules_.size() ||
      (index == namespace_rules_.size() && rule->IsNamespaceRule())) {
    // Inserting non-namespace rules other than import rule before @namespace is
    // not allowed.
    auto* namespace_rule = DynamicTo<StyleRuleNamespace>(rule);
    if (!namespace_rule) {
      return false;
    }
    // Inserting @namespace rule when rules other than import/namespace/charset
    // are present is not allowed.
    if (!child_rules_.empty()) {
      return false;
    }

    namespace_rules_.insert(index, namespace_rule);
    // For now to be compatible with IE and Firefox if namespace rule with same
    // prefix is added irrespective of adding the rule at any index, last added
    // rule's value is considered.
    // TODO (ramya.v@samsung.com): As per spec last valid rule should be
    // considered, which means if namespace rule is added in the middle of
    // existing namespace rules, rule which comes later in rule list with same
    // prefix needs to be considered.
    ParserAddNamespace(namespace_rule->Prefix(), namespace_rule->Uri());
    return true;
  }

  if (rule->IsNamespaceRule()) {
    return false;
  }

  index -= namespace_rules_.size();

  child_rules_.insert(index, rule);
  return true;
}

bool StyleSheetContents::WrapperDeleteRule(unsigned index) {
  DCHECK(is_mutable_);
  SECURITY_DCHECK(index < RuleCount());

  if (index < pre_import_layer_statement_rules_.size()) {
    if (rule_set_diff_) {
      rule_set_diff_->AddDiff(pre_import_layer_statement_rules_[index]);
    }
    pre_import_layer_statement_rules_.EraseAt(index);
    return true;
  }
  index -= pre_import_layer_statement_rules_.size();

  if (index < import_rules_.size()) {
    if (rule_set_diff_) {
      rule_set_diff_->AddDiff(import_rules_[index]);
    }
    import_rules_[index]->ClearParentStyleSheet();
    import_rules_.EraseAt(index);
    return true;
  }
  index -= import_rules_.size();

  if (index < namespace_rules_.size()) {
    if (rule_set_diff_) {
      rule_set_diff_->AddDiff(namespace_rules_[index]);
    }
    if (!child_rules_.empty()) {
      return false;
    }
    namespace_rules_.EraseAt(index);
    return true;
  }
  index -= namespace_rules_.size();

  if (rule_set_diff_) {
    rule_set_diff_->AddDiff(child_rules_[index]);
  }
  if (child_rules_[index]->IsFontFaceRule()) {
    NotifyRemoveFontFaceRule(To<StyleRuleFontFace>(child_rules_[index].Get()));
  }
  child_rules_.EraseAt(index);
  return true;
}

void StyleSheetContents::ParserAddNamespace(const AtomicString& prefix,
                                            const AtomicString& uri) {
  DCHECK(!uri.IsNull());
  if (prefix.IsNull()) {
    default_namespace_ = uri;
    return;
  }
  namespaces_.Set(prefix, uri);
}

const AtomicString& StyleSheetContents::NamespaceURIFromPrefix(
    const AtomicString& prefix) const {
  auto it = namespaces_.find(prefix);
  return it != namespaces_.end() ? it->value : WTF::g_null_atom;
}

void StyleSheetContents::ParseAuthorStyleSheet(
    const CSSStyleSheetResource* cached_style_sheet) {
  TRACE_EVENT1("blink,devtools.timeline", "ParseAuthorStyleSheet", "data",
               [&](perfetto::TracedValue context) {
                 inspector_parse_author_style_sheet_event::Data(
                     std::move(context), cached_style_sheet);
               });

  const ResourceResponse& response = cached_style_sheet->GetResponse();
  CSSStyleSheetResource::MIMETypeCheck mime_type_check =
      (IsQuirksModeBehavior(parser_context_->Mode()) &&
       response.IsCorsSameOrigin())
          ? CSSStyleSheetResource::MIMETypeCheck::kLax
          : CSSStyleSheetResource::MIMETypeCheck::kStrict;
  String sheet_text =
      cached_style_sheet->SheetText(parser_context_, mime_type_check);

  source_map_url_ = response.HttpHeaderField(http_names::kSourceMap);
  if (source_map_url_.empty()) {
    // Try to get deprecated header.
    source_map_url_ = response.HttpHeaderField(http_names::kXSourceMap);
  }

  const auto* context =
      MakeGarbageCollected<CSSParserContext>(ParserContext(), this);
  CSSParser::ParseSheet(context, this, sheet_text,
                        CSSDeferPropertyParsing::kYes);
}

ParseSheetResult StyleSheetContents::ParseString(
    const String& sheet_text,
    bool allow_import_rules,
    CSSDeferPropertyParsing defer_property_parsing) {
  const auto* context =
      MakeGarbageCollected<CSSParserContext>(ParserContext(), this);
  return CSSParser::ParseSheet(context, this, sheet_text,
                               defer_property_parsing, allow_import_rules);
}

bool StyleSheetContents::IsLoading() const {
  for (unsigned i = 0; i < import_rules_.size(); ++i) {
    if (import_rules_[i]->IsLoading()) {
      return true;
    }
  }
  return false;
}

bool StyleSheetContents::LoadCompleted() const {
  StyleSheetContents* parent_sheet = ParentStyleSheet();
  if (parent_sheet) {
    return parent_sheet->LoadCompleted();
  }

  StyleSheetContents* root = RootStyleSheet();
  return root->loading_clients_.empty();
}

void StyleSheetContents::CheckLoaded() {
  if (IsLoading()) {
    return;
  }

  StyleSheetContents* parent_sheet = ParentStyleSheet();
  if (parent_sheet) {
    parent_sheet->CheckLoaded();
    return;
  }

  DCHECK_EQ(this, RootStyleSheet());
  if (loading_clients_.empty()) {
    return;
  }

  // Avoid |CSSSStyleSheet| and |OwnerNode| being deleted by scripts that run
  // via ScriptableDocumentParser::ExecuteScriptsWaitingForResources(). Also
  // protect the |CSSStyleSheet| from being deleted during iteration via the
  // |SheetLoaded| method.
  //
  // When a sheet is loaded it is moved from the set of loading clients
  // to the set of completed clients. We therefore need the copy in order to
  // not modify the set while iterating it.
  HeapVector<Member<CSSStyleSheet>> loading_clients(loading_clients_);

  for (unsigned i = 0; i < loading_clients.size(); ++i) {
    if (loading_clients[i]->LoadCompleted()) {
      continue;
    }
    DCHECK(!loading_clients[i]->IsConstructed());

    // sheetLoaded might be invoked after its owner node is removed from
    // document.
    if (Node* owner_node = loading_clients[i]->ownerNode()) {
      if (loading_clients[i]->SheetLoaded()) {
        owner_node->NotifyLoadedSheetAndAllCriticalSubresources(
            did_load_error_occur_ ? Node::kErrorOccurredLoadingSubresource
                                  : Node::kNoErrorLoadingSubresource);
      }
    }
  }
}

void StyleSheetContents::NotifyLoadedSheet(const CSSStyleSheetResource* sheet) {
  DCHECK(sheet);
  did_load_error_occur_ |= sheet->ErrorOccurred();
  // updateLayoutIgnorePendingStyleSheets can cause us to create the RuleSet on
  // this sheet before its imports have loaded. So clear the RuleSet when the
  // imports load since the import's subrules are flattened into its parent
  // sheet's RuleSet.
  ClearRuleSet();
}

void StyleSheetContents::SetToPendingState() {
  StyleSheetContents* root = RootStyleSheet();
  for (const auto& client : root->loading_clients_) {
    client->SetToPendingState();
  }
  // Copy the completed clients to a vector for iteration.
  // SetToPendingState() will move the style sheet from the completed state
  // to the loading state which modifies the set of completed clients. We
  // therefore need the copy in order to not modify the set of completed clients
  // while iterating it.
  HeapVector<Member<CSSStyleSheet>> completed_clients(completed_clients_);
  for (unsigned i = 0; i < completed_clients.size(); ++i) {
    completed_clients[i]->SetToPendingState();
  }
}

StyleSheetContents* StyleSheetContents::RootStyleSheet() const {
  const StyleSheetContents* root = this;
  while (root->ParentStyleSheet()) {
    root = root->ParentStyleSheet();
  }
  return const_cast<StyleSheetContents*>(root);
}

bool StyleSheetContents::HasSingleOwnerNode() const {
  return RootStyleSheet()->HasOneClient();
}

Node* StyleSheetContents::SingleOwnerNode() const {
  StyleSheetContents* root = RootStyleSheet();
  if (!root->HasOneClient()) {
    return nullptr;
  }
  if (root->loading_clients_.size()) {
    return (*root->loading_clients_.begin())->ownerNode();
  }
  return (*root->completed_clients_.begin())->ownerNode();
}

Document* StyleSheetContents::SingleOwnerDocument() const {
  StyleSheetContents* root = RootStyleSheet();
  return root->ClientSingleOwnerDocument();
}

Document* StyleSheetContents::AnyOwnerDocument() const {
  return RootStyleSheet()->ClientAnyOwnerDocument();
}

static bool ChildRulesHaveFailedOrCanceledSubresources(
    const HeapVector<Member<StyleRuleBase>>& rules) {
  for (unsigned i = 0; i < rules.size(); ++i) {
    const StyleRuleBase* rule = rules[i].Get();
    switch (rule->GetType()) {
      case StyleRuleBase::kStyle:
        if (To<StyleRule>(rule)->PropertiesHaveFailedOrCanceledSubresources()) {
          return true;
        }
        break;
      case StyleRuleBase::kFontFace:
        if (To<StyleRuleFontFace>(rule)
                ->Properties()
                .HasFailedOrCanceledSubresources()) {
          return true;
        }
        break;
      case StyleRuleBase::kContainer:
      case StyleRuleBase::kMedia:
      case StyleRuleBase::kLayerBlock:
      case StyleRuleBase::kScope:
      case StyleRuleBase::kStartingStyle:
        if (ChildRulesHaveFailedOrCanceledSubresources(
                To<StyleRuleGroup>(rule)->ChildRules())) {
          return true;
        }
        break;
      case StyleRuleBase::kCharset:
      case StyleRuleBase::kImport:
      case StyleRuleBase::kNamespace:
      case StyleRuleBase::kMixin:
        NOTREACHED();
      case StyleRuleBase::kNestedDeclarations:
      case StyleRuleBase::kPage:
      case StyleRuleBase::kPageMargin:
      case StyleRuleBase::kProperty:
      case StyleRuleBase::kKeyframes:
      case StyleRuleBase::kKeyframe:
      case StyleRuleBase::kLayerStatement:
      case StyleRuleBase::kSupports:
      case StyleRuleBase::kFontPaletteValues:
      case StyleRuleBase::kFontFeatureValues:
      case StyleRuleBase::kFontFeature:
      case StyleRuleBase::kViewTransition:
      case StyleRuleBase::kFunction:
      case StyleRuleBase::kPositionTry:
        break;
      case StyleRuleBase::kApplyMixin:
        // TODO(sesse): Should we go down into the rules here?
        // Do we need to do a new name lookup then?
        break;
      case StyleRuleBase::kCounterStyle:
        if (To<StyleRuleCounterStyle>(rule)
                ->HasFailedOrCanceledSubresources()) {
          return true;
        }
        break;
    }
  }
  return false;
}

bool StyleSheetContents::HasFailedOrCanceledSubresources() const {
  DCHECK(IsCacheableForResource());
  return ChildRulesHaveFailedOrCanceledSubresources(child_rules_);
}

Document* StyleSheetContents::ClientAnyOwnerDocument() const {
  if (ClientSize() <= 0) {
    return nullptr;
  }
  if (loading_clients_.size()) {
    return (*loading_clients_.begin())->OwnerDocument();
  }
  return (*completed_clients_.begin())->OwnerDocument();
}

Document* StyleSheetContents::ClientSingleOwnerDocument() const {
  return has_single_owner_document_ ? ClientAnyOwnerDocument() : nullptr;
}

StyleSheetContents* StyleSheetContents::ParentStyleSheet() const {
  return owner_rule_ ? owner_rule_->ParentStyleSheet() : nullptr;
}

void StyleSheetContents::RegisterClient(CSSStyleSheet* sheet) {
  DCHECK(!loading_clients_.Contains(sheet));
  DCHECK(!completed_clients_.Contains(sheet));
  // InspectorCSSAgent::BuildObjectForRule creates CSSStyleSheet without any
  // owner node.
  if (!sheet->OwnerDocument()) {
    return;
  }

  if (Document* document = ClientSingleOwnerDocument()) {
    if (sheet->OwnerDocument() != document) {
      has_single_owner_document_ = false;
    }
  }

  if (sheet->IsConstructed()) {
    // Constructed stylesheets don't need loading. Note that @import is ignored
    // in both CSSStyleSheet.replaceSync and CSSStyleSheet.replace.
    //
    // https://drafts.csswg.org/cssom/#dom-cssstylesheet-replacesync
    // https://drafts.csswg.org/cssom/#dom-cssstylesheet-replace
    completed_clients_.insert(sheet);
  } else {
    loading_clients_.insert(sheet);
  }
}

void StyleSheetContents::UnregisterClient(CSSStyleSheet* sheet) {
  loading_clients_.erase(sheet);
  completed_clients_.erase(sheet);

  if (!sheet->OwnerDocument() || !loading_clients_.empty() ||
      !completed_clients_.empty()) {
    return;
  }

  has_single_owner_document_ = true;
}

void StyleSheetContents::ClientLoadCompleted(CSSStyleSheet* sheet) {
  DCHECK(loading_clients_.Contains(sheet) || !sheet->OwnerDocument());
  loading_clients_.erase(sheet);
  // In owner_node_->SheetLoaded, the CSSStyleSheet might be detached.
  // (i.e. ClearOwnerNode was invoked.)
  // In this case, we don't need to add the stylesheet to completed clients.
  if (!sheet->OwnerDocument()) {
    return;
  }
  completed_clients_.insert(sheet);
}

void StyleSheetContents::ClientLoadStarted(CSSStyleSheet* sheet) {
  DCHECK(completed_clients_.Contains(sheet));
  completed_clients_.erase(sheet);
  loading_clients_.insert(sheet);
}

void StyleSheetContents::SetReferencedFromResource(
    CSSStyleSheetResource* resource) {
  DCHECK(resource);
  DCHECK(!IsReferencedFromResource());
  DCHECK(IsCacheableForResource());
  referenced_from_resource_ = resource;
}

void StyleSheetContents::ClearReferencedFromResource() {
  DCHECK(IsReferencedFromResource());
  DCHECK(IsCacheableForResource());
  referenced_from_resource_ = nullptr;
}

RuleSet& StyleSheetContents::EnsureRuleSet(const MediaQueryEvaluator& medium) {
  if (rule_set_ && rule_set_->DidMediaQueryResultsChange(medium)) {
    rule_set_ = nullptr;
  }
  if (rule_set_diff_) {
    rule_set_diff_->NewRuleSetCleared();
  }
  if (!rule_set_) {
    rule_set_ = MakeGarbageCollected<RuleSet>();
    rule_set_->AddRulesFromSheet(this, medium);
    if (rule_set_diff_) {
      rule_set_diff_->NewRuleSetCreated(rule_set_);
    }
  }
  return *rule_set_.Get();
}

static void SetNeedsActiveStyleUpdateForClients(
    HeapHashSet<WeakMember<CSSStyleSheet>>& clients) {
  for (const auto& sheet : clients) {
    Document* document = sheet->OwnerDocument();
    Node* node = sheet->ownerNode();
    if (!document || !node || !node->isConnected()) {
      continue;
    }
    document->GetStyleEngine().SetNeedsActiveStyleUpdate(node->GetTreeScope());
  }
}

void StyleSheetContents::StartMutation() {
  is_mutable_ = true;
  if (rule_set_) {
    rule_set_diff_ = MakeGarbageCollected<RuleSetDiff>(rule_set_);
  }
}

void StyleSheetContents::ClearRuleSet() {
  if (StyleSheetContents* parent_sheet = ParentStyleSheet()) {
    parent_sheet->ClearRuleSet();
  }

  if (!rule_set_) {
    return;
  }

  rule_set_.Clear();
  if (rule_set_diff_) {
    rule_set_diff_->NewRuleSetCleared();
  }
  SetNeedsActiveStyleUpdateForClients(loading_clients_);
  SetNeedsActiveStyleUpdateForClients(completed_clients_);
}

static void RemoveFontFaceRules(HeapHashSet<WeakMember<CSSStyleSheet>>& clients,
                                const StyleRuleFontFace* font_face_rule) {
  for (const auto& sheet : clients) {
    if (Node* owner_node = sheet->ownerNode()) {
      owner_node->GetDocument().GetStyleEngine().RemoveFontFaceRules(
          HeapVector<Member<const StyleRuleFontFace>>(1, font_face_rule));
    }
  }
}

void StyleSheetContents::NotifyRemoveFontFaceRule(
    const StyleRuleFontFace* font_face_rule) {
  StyleSheetContents* root = RootStyleSheet();
  RemoveFontFaceRules(root->loading_clients_, font_face_rule);
  RemoveFontFaceRules(root->completed_clients_, font_face_rule);
}

void StyleSheetContents::Trace(Visitor* visitor) const {
  visitor->Trace(owner_rule_);
  visitor->Trace(pre_import_layer_statement_rules_);
  visitor->Trace(import_rules_);
  visitor->Trace(namespace_rules_);
  visitor->Trace(child_rules_);
  visitor->Trace(loading_clients_);
  visitor->Trace(completed_clients_);
  visitor->Trace(rule_set_);
  visitor->Trace(referenced_from_resource_);
  visitor->Trace(parser_context_);
  visitor->Trace(rule_set_diff_);
}

}  // namespace blink

"""

```