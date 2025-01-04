Response:
The user wants to understand the functionality of the `css_style_sheet.cc` file in the Chromium Blink rendering engine. I need to analyze the code and explain its role, focusing on its interactions with JavaScript, HTML, and CSS. I also need to provide examples, logical reasoning with assumptions, common usage errors, and debugging clues related to this file.

Here's a breakdown of the tasks:

1. **Functionality Listing:** Identify the main responsibilities of the `CSSStyleSheet` class implemented in this file. This will involve looking at the methods and member variables.

2. **Relationship with JavaScript, HTML, and CSS:** Explain how `CSSStyleSheet` interacts with these web technologies. Provide concrete examples.

3. **Logical Reasoning (Input/Output):**  Select a method or a section of code and demonstrate its behavior with a hypothetical input and expected output. Make sure to state the assumptions clearly.

4. **Common Usage Errors:** Identify potential mistakes developers might make when working with CSS style sheets and how this file might be involved.

5. **Debugging Clues (User Operations):**  Describe user actions that could lead to the execution of code within this file, aiding in debugging.
好的，我们来分析一下 `blink/renderer/core/css/css_style_sheet.cc` 这个文件。

**功能列举:**

这个文件定义了 `CSSStyleSheet` 类，它是 Blink 渲染引擎中表示 CSS 样式表的关键类。其主要功能包括：

1. **表示和管理 CSS 规则:** `CSSStyleSheet` 负责存储和管理样式表中的 CSS 规则。它内部维护了一个 `StyleSheetContents` 对象，实际存储了解析后的 CSS 规则。
2. **处理 CSS 文本:**  提供了方法（如 `SetText`）来解析和加载 CSS 文本，将其转换为内部的规则表示。
3. **提供 CSSOM 接口:** 实现了 Web 标准定义的 CSSOM (CSS Object Model) 接口，允许 JavaScript 通过 `document.styleSheets` 等 API 操作样式表，例如：
    * 获取规则列表 (`cssRules`)
    * 插入规则 (`insertRule`)
    * 删除规则 (`deleteRule`)
    * 修改样式表是否禁用 (`disabled`)
    * 获取媒体查询信息 (`media`)
    * 替换样式表内容 (`replace`, `replaceSync`)
4. **处理不同类型的样式表:**  可以表示内联样式表（通过 `<style>` 标签或 `style` 属性定义）、外部样式表（通过 `<link>` 标签引入）以及通过 JavaScript 构建的样式表（Constructed Stylesheets）。
5. **管理样式表的元数据:** 存储样式表的元数据，如：
    * `href`: 外部样式表的 URL
    * `media`: 样式表应用的媒体查询
    * `title`: 样式表的标题
    * `ownerNode`: 拥有此样式表的 DOM 节点（例如 `<link>` 或 `<style>` 元素）
    * `ownerRule`: 如果是 `@import` 引入的样式表，则指向其 `@import` 规则。
6. **处理样式表的生命周期:** 涉及到样式表的加载、解析、更新和失效。
7. **支持 Constructible Stylesheets:** 实现了 Constructible Stylesheets API，允许 JavaScript 创建和修改新的、独立的样式表。
8. **与渲染流水线集成:**  与 Blink 的样式解析器、选择器匹配器等组件紧密集成，确保样式规则能够正确地应用到 DOM 元素上。
9. **支持 Inspector:** 提供了用于开发者工具（Inspector）访问和修改样式规则的接口。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **与 HTML 的关系:**
    * **`<link>` 元素:** 当浏览器遇到 `<link rel="stylesheet" href="...">` 时，会创建一个 `CSSStyleSheet` 对象来表示这个外部样式表。 `CSSStyleSheet::Create` 方法会被调用。
        ```html
        <link rel="stylesheet" href="style.css">
        ```
    * **`<style>` 元素:** 当浏览器解析到 `<style>` 标签时，会创建一个 `CSSStyleSheet` 对象来表示内嵌的样式。 `CSSStyleSheet::CreateInline` 方法会被调用。
        ```html
        <style>
          body {
            background-color: lightblue;
          }
        </style>
        ```
    * **`style` 属性:** 虽然 `style` 属性不是直接创建 `CSSStyleSheet` 对象，但它的内容会被解析并影响元素的内联样式，这与样式表的解析过程类似。
* **与 CSS 的关系:**
    * `CSSStyleSheet` 的核心职责就是管理 CSS 规则。它负责解析 CSS 文本，并将其存储为内部的数据结构，供渲染引擎使用。
    * 文件中的很多方法，如 `insertRule`、`deleteRule`、`SetText` 等，都直接操作 CSS 规则。
* **与 JavaScript 的关系:**
    * **`document.styleSheets`:** JavaScript 可以通过 `document.styleSheets` 属性访问页面中所有的 `CSSStyleSheet` 对象。
        ```javascript
        const stylesheets = document.styleSheets;
        console.log(stylesheets.length); // 输出样式表的数量
        ```
    * **CSSOM API:** JavaScript 可以使用 `CSSStyleSheet` 对象提供的 API 来动态地修改样式表。
        ```javascript
        const stylesheet = document.styleSheets[0];
        stylesheet.insertRule('body { color: red; }', 0); // 在样式表开头插入一条规则
        ```
    * **Constructible Stylesheets API:** JavaScript 可以使用 `new CSSStyleSheet()` 创建独立的样式表，然后通过 `adoptedStyleSheets` 将其应用到 Shadow DOM 或 Document 上。
        ```javascript
        const sheet = new CSSStyleSheet();
        sheet.replaceSync('body { font-size: 20px; }');
        document.adoptedStyleSheets = [sheet];
        ```
    * **事件监听:**  虽然 `CSSStyleSheet` 本身不直接触发事件，但 JavaScript 可以监听与样式表加载相关的事件，例如 `<link>` 元素的 `load` 和 `error` 事件。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. 一个包含以下 CSS 规则的字符串，传递给 `CSSStyleSheet::SetText` 方法：
   ```css
   .my-class {
     color: blue;
     font-size: 16px;
   }
   ```
2. 假设当前的 `CSSStyleSheet` 对象是新创建的，没有任何已有的规则。

**输出:**

1. `CSSStyleSheet` 对象内部的 `StyleSheetContents` 将会存储解析后的 CSS 规则。
2. 调用 `length()` 方法将会返回 `1`，因为成功解析了一个规则。
3. 调用 `item(0)` 将会返回一个 `CSSStyleRule` 对象，表示 `.my-class` 的样式规则。
4. 这个 `CSSStyleRule` 对象可以通过其 API 访问到选择器 (`.my-class`) 和声明块 (`color: blue; font-size: 16px;`)。

**用户或编程常见的使用错误:**

1. **尝试修改跨域的样式表:**  如果 JavaScript 尝试修改一个来自不同域名的样式表，由于浏览器的同源策略限制，会导致安全错误。
   ```javascript
   // 假设 stylesheet 来自不同的域名
   try {
     stylesheet.insertRule('body { color: red; }', 0);
   } catch (error) {
     console.error(error); // 会抛出一个 SecurityError
   }
   ```
   **`css_style_sheet.cc` 中的相关逻辑:** `CSSStyleSheet::CanAccessRules()` 方法会检查样式表的来源是否安全。

2. **在 Constructible Stylesheet 中插入 `@import` 规则:** Constructible Stylesheets 不允许使用 `@import` 规则。
   ```javascript
   const sheet = new CSSStyleSheet();
   try {
     sheet.insertRule('@import url("other.css");', 0);
   } catch (error) {
     console.error(error); // 会抛出一个 SyntaxError
   }
   ```
   **`css_style_sheet.cc` 中的相关逻辑:** `CSSStyleSheet::insertRule` 方法会检查是否是 Constructible Stylesheet 以及插入的规则是否是 `@import`。

3. **使用错误的索引访问或修改规则:** 尝试使用超出范围的索引来访问或删除规则会导致 `IndexSizeError`。
   ```javascript
   const stylesheet = document.styleSheets[0];
   try {
     stylesheet.deleteRule(stylesheet.cssRules.length); // 索引超出范围
   } catch (error) {
     console.error(error); // 会抛出一个 DOMException (IndexSizeError)
   }
   ```
   **`css_style_sheet.cc` 中的相关逻辑:** `CSSStyleSheet::item`、`insertRule` 和 `deleteRule` 方法中都有对索引范围的检查。

**用户操作如何一步步的到达这里，作为调试线索:**

以下是一些用户操作可能触发 `css_style_sheet.cc` 中代码执行的情况：

1. **加载网页:** 当用户访问一个网页时，浏览器会解析 HTML，遇到 `<link>` 和 `<style>` 标签时，会创建 `CSSStyleSheet` 对象并加载和解析 CSS 资源。调试时可以在网络面板查看 CSS 资源的加载情况。

2. **修改 HTML 或 CSS 文件:** 如果开发者修改了 HTML 或 CSS 文件，浏览器重新加载页面或热重载时，会重新解析样式表。

3. **JavaScript 动态修改样式:**
    * 用户执行的 JavaScript 代码调用了 `document.createElement('link')` 并设置了 `href` 和 `rel="stylesheet"`，或者创建了 `<style>` 元素并设置了其内容。
    * 用户执行的 JavaScript 代码使用了 CSSOM API (如 `insertRule`, `deleteRule`, `replaceSync`) 来修改已有的样式表。
    * 用户执行的 JavaScript 代码使用了 Constructible Stylesheets API (`new CSSStyleSheet()`, `replaceSync`, `adoptedStyleSheets`).

4. **浏览器扩展或开发者工具操作:** 某些浏览器扩展或开发者工具可能会修改页面的样式表。

5. **CSS 动画和过渡:**  虽然 CSS 动画和过渡本身不直接创建或修改 `CSSStyleSheet` 对象，但它们依赖于样式规则的定义。如果动画或过渡导致样式计算的更新，可能会间接涉及到与样式表相关的数据结构。

**调试线索:**

* **断点调试:**  在 `css_style_sheet.cc` 中的关键方法（例如 `Create`, `SetText`, `insertRule`, `deleteRule`) 设置断点，可以跟踪样式表创建、加载和修改的过程。
* **Console 输出:** 在 JavaScript 中打印 `document.styleSheets` 的信息，查看样式表的数量、`href`、`media` 等属性，有助于了解当前页面的样式表状态.
* **Performance 面板:** 使用浏览器的 Performance 面板，可以分析样式计算 (Recalculate Style) 的耗时，这有助于识别性能瓶颈，可能与复杂的样式表或频繁的样式修改有关。
* **Elements 面板:**  使用开发者工具的 Elements 面板，查看元素的 Computed 样式，可以了解哪些 CSS 规则最终应用到了元素上，这有助于排查样式覆盖或优先级问题。
* **Network 面板:**  检查 CSS 资源的加载状态，确保外部样式表已成功加载。

希望以上分析对您有所帮助！

Prompt: 
```
这是目录为blink/renderer/core/css/css_style_sheet.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/core/css/css_style_sheet.h"

#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_css_style_sheet_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_medialist_string.h"
#include "third_party/blink/renderer/core/core_probes_inl.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/media_list.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class StyleSheetCSSRuleList final : public CSSRuleList {
 public:
  StyleSheetCSSRuleList(CSSStyleSheet* sheet) : style_sheet_(sheet) {}

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_sheet_);
    CSSRuleList::Trace(visitor);
  }

 private:
  unsigned length() const override { return style_sheet_->length(); }
  CSSRule* Item(unsigned index, bool trigger_use_counters) const override {
    return style_sheet_->item(index, trigger_use_counters);
  }

  CSSStyleSheet* GetStyleSheet() const override { return style_sheet_.Get(); }

  Member<CSSStyleSheet> style_sheet_;
};

#if DCHECK_IS_ON()
static bool IsAcceptableCSSStyleSheetParent(const Node& parent_node) {
  // Only these nodes can be parents of StyleSheets, and they need to call
  // clearOwnerNode() when moved out of document. Note that destructor of
  // the nodes don't call clearOwnerNode() with Oilpan.
  return parent_node.IsDocumentNode() || IsA<HTMLLinkElement>(parent_node) ||
         IsA<HTMLStyleElement>(parent_node) ||
         IsA<SVGStyleElement>(parent_node) ||
         parent_node.getNodeType() == Node::kProcessingInstructionNode;
}
#endif

// static
const Document* CSSStyleSheet::SingleOwnerDocument(
    const CSSStyleSheet* style_sheet) {
  if (style_sheet) {
    return StyleSheetContents::SingleOwnerDocument(style_sheet->Contents());
  }
  return nullptr;
}

CSSStyleSheet* CSSStyleSheet::Create(Document& document,
                                     const CSSStyleSheetInit* options,
                                     ExceptionState& exception_state) {
  return CSSStyleSheet::Create(document, document.BaseURL(), options,
                               exception_state);
}

CSSStyleSheet* CSSStyleSheet::Create(Document& document,
                                     const KURL& base_url,
                                     const CSSStyleSheetInit* options,
                                     ExceptionState& exception_state) {
  auto* parser_context =
      MakeGarbageCollected<CSSParserContext>(document, base_url);
  if (AdTracker::IsAdScriptExecutingInDocument(&document)) {
    parser_context->SetIsAdRelated();
  }

  auto* contents = MakeGarbageCollected<StyleSheetContents>(parser_context);
  return MakeGarbageCollected<CSSStyleSheet>(contents, document, options);
}

CSSStyleSheet* CSSStyleSheet::CreateInline(StyleSheetContents* sheet,
                                           Node& owner_node,
                                           const TextPosition& start_position) {
  DCHECK(sheet);
  return MakeGarbageCollected<CSSStyleSheet>(sheet, owner_node, true,
                                             start_position);
}

CSSStyleSheet* CSSStyleSheet::CreateInline(Node& owner_node,
                                           const KURL& base_url,
                                           const TextPosition& start_position,
                                           const WTF::TextEncoding& encoding) {
  Document& owner_node_document = owner_node.GetDocument();
  auto* parser_context = MakeGarbageCollected<CSSParserContext>(
      owner_node_document, owner_node_document.BaseURL(),
      true /* origin_clean */,
      Referrer(
          // Fetch requests from an inline CSS use the referrer of the owner
          // document. `Referrer::ClientReferrerString()` for a fetch request
          // just means "use the default referrer", which will be computed from
          // the client (in this case, the owner document's ExecutionContext)
          // when fetching.
          Referrer::ClientReferrerString(),
          network::mojom::ReferrerPolicy::kDefault),
      encoding);
  if (AdTracker::IsAdScriptExecutingInDocument(&owner_node.GetDocument())) {
    parser_context->SetIsAdRelated();
  }
  auto* sheet = MakeGarbageCollected<StyleSheetContents>(parser_context,
                                                         base_url.GetString());
  return MakeGarbageCollected<CSSStyleSheet>(sheet, owner_node, true,
                                             start_position);
}

CSSStyleSheet::CSSStyleSheet(StyleSheetContents* contents,
                             CSSImportRule* owner_rule)
    : contents_(contents),
      owner_rule_(owner_rule),
      start_position_(TextPosition::MinimumPosition()) {
  contents_->RegisterClient(this);
}

CSSStyleSheet::CSSStyleSheet(StyleSheetContents* contents,
                             Document& document,
                             const CSSStyleSheetInit* options)
    : CSSStyleSheet(contents, nullptr) {
  // Following steps at spec draft
  // https://wicg.github.io/construct-stylesheets/#dom-cssstylesheet-cssstylesheet
  SetConstructorDocument(document);
  ClearOwnerNode();
  ClearOwnerRule();
  Contents()->RegisterClient(this);
  switch (options->media()->GetContentType()) {
    case V8UnionMediaListOrString::ContentType::kMediaList:
      media_queries_ = options->media()->GetAsMediaList()->Queries();
      break;
    case V8UnionMediaListOrString::ContentType::kString:
      media_queries_ = MediaQuerySet::Create(options->media()->GetAsString(),
                                             document.GetExecutionContext());
      break;
  }
  if (options->alternate()) {
    SetAlternateFromConstructor(true);
  }
  if (options->disabled()) {
    setDisabled(true);
  }
}

CSSStyleSheet::CSSStyleSheet(StyleSheetContents* contents,
                             Node& owner_node,
                             bool is_inline_stylesheet,
                             const TextPosition& start_position)
    : contents_(contents),
      owner_node_(&owner_node),
      owner_parent_or_shadow_host_element_(
          owner_node.ParentOrShadowHostElement()),
      start_position_(start_position),
      is_inline_stylesheet_(is_inline_stylesheet) {
#if DCHECK_IS_ON()
  DCHECK(IsAcceptableCSSStyleSheetParent(owner_node));
#endif
  contents_->RegisterClient(this);
}

CSSStyleSheet::~CSSStyleSheet() = default;

void CSSStyleSheet::WillMutateRules() {
  // If we are the only client it is safe to mutate.
  if (!contents_->IsUsedFromTextCache() &&
      !contents_->IsReferencedFromResource()) {
    contents_->StartMutation();
    contents_->ClearRuleSet();
    return;
  }
  // Only cacheable stylesheets should have multiple clients.
  DCHECK(contents_->IsCacheableForStyleElement() ||
         contents_->IsCacheableForResource());

  // Copy-on-write. Note that this eagerly parses any rules that were
  // lazily parsed.
  contents_->UnregisterClient(this);
  contents_ = contents_->Copy();
  contents_->RegisterClient(this);

  contents_->StartMutation();

  // Any existing CSSOM wrappers need to be connected to the copied child rules.
  ReattachChildRuleCSSOMWrappers();
}

void CSSStyleSheet::DidMutate(Mutation mutation) {
  if (mutation == Mutation::kRules) {
    DCHECK(contents_->IsMutable());
    DCHECK_LE(contents_->ClientSize(), 1u);
  }
  Document* document = OwnerDocument();
  if (!document || !document->IsActive()) {
    return;
  }
  if (!custom_element_tag_names_.empty()) {
    document->GetStyleEngine().ScheduleCustomElementInvalidations(
        custom_element_tag_names_);
  }
  bool invalidate_matched_properties_cache = false;
  if (ownerNode() && ownerNode()->isConnected()) {
    document->GetStyleEngine().SetNeedsActiveStyleUpdate(
        ownerNode()->GetTreeScope());
    invalidate_matched_properties_cache = true;
  } else if (!adopted_tree_scopes_.empty()) {
    for (auto tree_scope : adopted_tree_scopes_.Keys()) {
      // It is currently required that adopted sheets can not be moved between
      // documents.
      DCHECK(tree_scope->GetDocument() == document);
      if (!tree_scope->RootNode().isConnected()) {
        continue;
      }
      document->GetStyleEngine().SetNeedsActiveStyleUpdate(*tree_scope);
      invalidate_matched_properties_cache = true;
    }
  }
  if (mutation == Mutation::kRules) {
    if (invalidate_matched_properties_cache) {
      document->GetStyleResolver().InvalidateMatchedPropertiesCache();
    }
    probe::DidMutateStyleSheet(document, this);
  }
}

void CSSStyleSheet::EnableRuleAccessForInspector() {
  enable_rule_access_for_inspector_ = true;
}
void CSSStyleSheet::DisableRuleAccessForInspector() {
  enable_rule_access_for_inspector_ = false;
}

CSSStyleSheet::InspectorMutationScope::InspectorMutationScope(
    CSSStyleSheet* sheet)
    : style_sheet_(sheet) {
  style_sheet_->EnableRuleAccessForInspector();
}

CSSStyleSheet::InspectorMutationScope::~InspectorMutationScope() {
  style_sheet_->DisableRuleAccessForInspector();
}

void CSSStyleSheet::ReattachChildRuleCSSOMWrappers() {
  for (unsigned i = 0; i < child_rule_cssom_wrappers_.size(); ++i) {
    if (!child_rule_cssom_wrappers_[i]) {
      continue;
    }
    child_rule_cssom_wrappers_[i]->Reattach(contents_->RuleAt(i));
  }
}

void CSSStyleSheet::setDisabled(bool disabled) {
  if (disabled == is_disabled_) {
    return;
  }
  is_disabled_ = disabled;

  DidMutate(Mutation::kSheet);
}

bool CSSStyleSheet::MatchesMediaQueries(const MediaQueryEvaluator& evaluator) {
  media_query_result_flags_.Clear();

  if (!media_queries_) {
    return true;
  }
  return evaluator.Eval(*media_queries_, &media_query_result_flags_);
}

void CSSStyleSheet::AddedAdoptedToTreeScope(TreeScope& tree_scope) {
  auto add_result = adopted_tree_scopes_.insert(&tree_scope, 1u);
  if (!add_result.is_new_entry) {
    add_result.stored_value->value++;
  }
}

void CSSStyleSheet::RemovedAdoptedFromTreeScope(TreeScope& tree_scope) {
  auto it = adopted_tree_scopes_.find(&tree_scope);
  if (it != adopted_tree_scopes_.end()) {
    CHECK_GT(it->value, 0u);
    if (--it->value == 0) {
      adopted_tree_scopes_.erase(&tree_scope);
    }
  }
}

bool CSSStyleSheet::IsAdoptedByTreeScope(TreeScope& tree_scope) {
  return adopted_tree_scopes_.Contains(&tree_scope);
}

bool CSSStyleSheet::HasViewportDependentMediaQueries() const {
  return media_query_result_flags_.is_viewport_dependent;
}

bool CSSStyleSheet::HasDynamicViewportDependentMediaQueries() const {
  return media_query_result_flags_.unit_flags &
         MediaQueryExpValue::UnitFlags::kDynamicViewport;
}

unsigned CSSStyleSheet::length() const {
  return contents_->RuleCount();
}

CSSRule* CSSStyleSheet::item(unsigned index, bool trigger_use_counters) {
  unsigned rule_count = length();
  if (index >= rule_count) {
    return nullptr;
  }

  if (child_rule_cssom_wrappers_.empty()) {
    child_rule_cssom_wrappers_.Grow(rule_count);
  }
  DCHECK_EQ(child_rule_cssom_wrappers_.size(), rule_count);

  Member<CSSRule>& css_rule = child_rule_cssom_wrappers_[index];
  if (!css_rule) {
    css_rule = contents_->RuleAt(index)->CreateCSSOMWrapper(
        index, this, trigger_use_counters);
  }
  return css_rule.Get();
}

void CSSStyleSheet::ClearOwnerNode() {
  DidMutate(Mutation::kSheet);
  if (owner_node_) {
    contents_->UnregisterClient(this);
  }
  owner_node_ = nullptr;
}

bool CSSStyleSheet::CanAccessRules() const {
  return enable_rule_access_for_inspector_ || contents_->IsOriginClean();
}

CSSRuleList* CSSStyleSheet::rules(ExceptionState& exception_state) {
  return cssRules(exception_state);
}

unsigned CSSStyleSheet::insertRule(const String& rule_string,
                                   unsigned index,
                                   ExceptionState& exception_state) {
  if (!CanAccessRules()) {
    exception_state.ThrowSecurityError(
        "Cannot access StyleSheet to insertRule");
    return 0;
  }

  DCHECK(child_rule_cssom_wrappers_.empty() ||
         child_rule_cssom_wrappers_.size() == contents_->RuleCount());

  if (index > length()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The index provided (" + String::Number(index) +
            ") is larger than the maximum index (" + String::Number(length()) +
            ").");
    return 0;
  }

  const auto* context =
      MakeGarbageCollected<CSSParserContext>(contents_->ParserContext(), this);

  StyleRuleBase* rule =
      CSSParser::ParseRule(context, contents_.Get(), CSSNestingType::kNone,
                           /*parent_rule_for_nesting=*/nullptr,
                           /*is_within_scope=*/false, rule_string);

  if (!rule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Failed to parse the rule '" + rule_string + "'.");
    return 0;
  }
  RuleMutationScope mutation_scope(this);
  if (rule->IsImportRule() && IsConstructed()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Can't insert @import rules into a constructed stylesheet.");
    return 0;
  }
  bool success = contents_->WrapperInsertRule(rule, index);
  if (!success) {
    if (rule->IsNamespaceRule()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                        "Failed to insert the rule");
    } else {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kHierarchyRequestError,
          "Failed to insert the rule.");
    }
    return 0;
  }
  if (!child_rule_cssom_wrappers_.empty()) {
    child_rule_cssom_wrappers_.insert(index, Member<CSSRule>(nullptr));
  }

  return index;
}

void CSSStyleSheet::deleteRule(unsigned index,
                               ExceptionState& exception_state) {
  if (!CanAccessRules()) {
    exception_state.ThrowSecurityError(
        "Cannot access StyleSheet to deleteRule");
    return;
  }

  DCHECK(child_rule_cssom_wrappers_.empty() ||
         child_rule_cssom_wrappers_.size() == contents_->RuleCount());

  if (index >= length()) {
    if (length()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kIndexSizeError,
          "The index provided (" + String::Number(index) +
              ") is larger than the maximum index (" +
              String::Number(length() - 1) + ").");
    } else {
      exception_state.ThrowDOMException(DOMExceptionCode::kIndexSizeError,
                                        "Style sheet is empty (length 0).");
    }
    return;
  }

  RuleMutationScope mutation_scope(this);

  bool success = contents_->WrapperDeleteRule(index);
  if (!success) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Failed to delete rule");
    return;
  }

  if (!child_rule_cssom_wrappers_.empty()) {
    if (child_rule_cssom_wrappers_[index]) {
      child_rule_cssom_wrappers_[index]->SetParentStyleSheet(nullptr);
    }
    child_rule_cssom_wrappers_.EraseAt(index);
  }
}

int CSSStyleSheet::addRule(const String& selector,
                           const String& style,
                           int index,
                           ExceptionState& exception_state) {
  StringBuilder text;
  text.Append(selector);
  text.Append(" { ");
  text.Append(style);
  if (!style.empty()) {
    text.Append(' ');
  }
  text.Append('}');
  insertRule(text.ReleaseString(), index, exception_state);

  // As per Microsoft documentation, always return -1.
  return -1;
}

int CSSStyleSheet::addRule(const String& selector,
                           const String& style,
                           ExceptionState& exception_state) {
  return addRule(selector, style, length(), exception_state);
}

ScriptPromise<CSSStyleSheet> CSSStyleSheet::replace(
    ScriptState* script_state,
    const String& text,
    ExceptionState& exception_state) {
  if (!IsConstructed()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Can't call replace on non-constructed CSSStyleSheets.");
    return EmptyPromise();
  }
  SetText(text, CSSImportRules::kIgnoreWithWarning);
  probe::DidReplaceStyleSheetText(OwnerDocument(), this, text);
  // We currently parse synchronously, and since @import support was removed,
  // nothing else happens asynchronously. This API is left as-is, so that future
  // async parsing can still be supported here.
  return ToResolvedPromise<CSSStyleSheet>(script_state, this);
}

void CSSStyleSheet::replaceSync(const String& text,
                                ExceptionState& exception_state) {
  if (!IsConstructed()) {
    return exception_state.ThrowDOMException(
        DOMExceptionCode::kNotAllowedError,
        "Can't call replaceSync on non-constructed CSSStyleSheets.");
  }
  SetText(text, CSSImportRules::kIgnoreWithWarning);
  probe::DidReplaceStyleSheetText(OwnerDocument(), this, text);
}

CSSRuleList* CSSStyleSheet::cssRules(ExceptionState& exception_state) {
  if (!CanAccessRules()) {
    exception_state.ThrowSecurityError("Cannot access rules");
    return nullptr;
  }
  if (!rule_list_cssom_wrapper_) {
    rule_list_cssom_wrapper_ =
        MakeGarbageCollected<StyleSheetCSSRuleList>(this);
  }
  return rule_list_cssom_wrapper_.Get();
}

String CSSStyleSheet::href() const {
  return contents_->OriginalURL();
}

KURL CSSStyleSheet::BaseURL() const {
  return contents_->BaseURL();
}

bool CSSStyleSheet::IsLoading() const {
  return contents_->IsLoading();
}

MediaList* CSSStyleSheet::media() {
  if (!media_queries_) {
    media_queries_ = MediaQuerySet::Create();
  }
  if (!media_cssom_wrapper_) {
    media_cssom_wrapper_ = MakeGarbageCollected<MediaList>(this);
  }
  return media_cssom_wrapper_.Get();
}

CSSStyleSheet* CSSStyleSheet::parentStyleSheet() const {
  return owner_rule_ ? owner_rule_->parentStyleSheet() : nullptr;
}

Document* CSSStyleSheet::OwnerDocument() const {
  if (CSSStyleSheet* parent = parentStyleSheet()) {
    return parent->OwnerDocument();
  }
  if (IsConstructed()) {
    DCHECK(!ownerNode());
    return ConstructorDocument();
  }
  return ownerNode() ? &ownerNode()->GetDocument() : nullptr;
}

bool CSSStyleSheet::SheetLoaded() {
  DCHECK(owner_node_);
  SetLoadCompleted(owner_node_->SheetLoaded());
  return load_completed_;
}

void CSSStyleSheet::SetToPendingState() {
  SetLoadCompleted(false);
  owner_node_->SetToPendingState();
}

void CSSStyleSheet::SetLoadCompleted(bool completed) {
  if (completed == load_completed_) {
    return;
  }

  load_completed_ = completed;

  if (completed) {
    contents_->ClientLoadCompleted(this);
  } else {
    contents_->ClientLoadStarted(this);
  }
}

void CSSStyleSheet::SetText(const String& text, CSSImportRules import_rules) {
  child_rule_cssom_wrappers_.clear();

  CSSStyleSheet::RuleMutationScope mutation_scope(this);
  contents_->ClearRules();
  bool allow_imports = import_rules == CSSImportRules::kAllow;
  if (contents_->ParseString(text, allow_imports) ==
          ParseSheetResult::kHasUnallowedImportRule &&
      import_rules == CSSImportRules::kIgnoreWithWarning) {
    OwnerDocument()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kJavaScript,
        mojom::blink::ConsoleMessageLevel::kWarning,
        "@import rules are not allowed here. See "
        "https://github.com/WICG/construct-stylesheets/issues/"
        "119#issuecomment-588352418."));
  }
}

void CSSStyleSheet::SetAlternateFromConstructor(
    bool alternate_from_constructor) {
  alternate_from_constructor_ = alternate_from_constructor;
}

bool CSSStyleSheet::IsAlternate() const {
  if (owner_node_) {
    auto* owner_element = DynamicTo<Element>(owner_node_.Get());
    return owner_element &&
           owner_element->FastGetAttribute(html_names::kRelAttr)
               .Contains("alternate");
  }
  return alternate_from_constructor_;
}

bool CSSStyleSheet::CanBeActivated(
    const String& current_preferrable_name) const {
  if (disabled()) {
    return false;
  }

  if (owner_node_ && owner_node_->IsInShadowTree()) {
    if (IsA<HTMLStyleElement>(owner_node_.Get()) ||
        IsA<SVGStyleElement>(owner_node_.Get())) {
      return true;
    }
  }

  auto* html_link_element = DynamicTo<HTMLLinkElement>(owner_node_.Get());
  if (!owner_node_ ||
      owner_node_->getNodeType() == Node::kProcessingInstructionNode ||
      !html_link_element || !html_link_element->IsEnabledViaScript()) {
    if (!title_.empty() && title_ != current_preferrable_name) {
      return false;
    }
  }

  if (IsAlternate() && title_.empty()) {
    return false;
  }

  return true;
}

void CSSStyleSheet::Trace(Visitor* visitor) const {
  visitor->Trace(contents_);
  visitor->Trace(media_queries_);
  visitor->Trace(owner_node_);
  visitor->Trace(owner_parent_or_shadow_host_element_);
  visitor->Trace(owner_rule_);
  visitor->Trace(media_cssom_wrapper_);
  visitor->Trace(child_rule_cssom_wrappers_);
  visitor->Trace(rule_list_cssom_wrapper_);
  visitor->Trace(adopted_tree_scopes_);
  visitor->Trace(constructor_document_);
  StyleSheet::Trace(visitor);
}

}  // namespace blink

"""

```