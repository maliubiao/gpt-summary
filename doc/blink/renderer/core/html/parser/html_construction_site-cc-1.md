Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. The code belongs to the `HTMLConstructionSite` class. I need to:

1. **Summarize the overall purpose of the code.**  This part of the `HTMLConstructionSite` seems responsible for handling the insertion of various DOM nodes based on parsed HTML tokens.

2. **Identify relationships with web technologies (JavaScript, HTML, CSS).**
    - **HTML:** The code directly deals with HTML elements and their attributes.
    - **JavaScript:**  The code interacts with custom elements, which are defined and controlled by JavaScript. There are also mentions of script execution and microtasks, linking it to JavaScript's execution model.
    - **CSS:** While not directly manipulating CSS, the code builds the DOM tree, which is fundamental for CSS to apply styles. The concept of Shadow DOM, which is related to CSS encapsulation, is also present.

3. **Provide examples of logical reasoning with inputs and outputs.** For instance, how does the code handle different types of HTML tokens and what DOM nodes are created as a result?

4. **Illustrate common user/programming errors.**  What mistakes could developers make that this code helps to prevent or handles?

5. **Synthesize the functionalities described in this specific code block.**  Focus on the actions performed within these methods.
这是 `blink/renderer/core/html/parser/html_construction_site.cc` 文件 `HTMLConstructionSite` 类的部分代码，主要负责根据 HTML 解析器生成的 token 创建和插入 DOM 节点。以下是对其功能的详细解释：

**主要功能归纳：**

这段代码的核心功能是 **将 HTML 解析器产生的 token 转化为实际的 DOM 节点并将其插入到 DOM 树中**。它处理各种类型的 token，包括文档类型声明、注释、DOM 节点（元素）、文本节点等，并根据当前的解析状态（例如是否在 `<template>` 元素内部）进行不同的处理。

**详细功能列举：**

1. **`InsertDoctype(AtomicHTMLToken* token)`:**
   - 功能：处理文档类型声明 (`<!DOCTYPE>`).
   - 作用：创建 `DocumentType` 节点，并将其附加到文档根节点。
   - 影响：根据文档类型声明判断是否需要进入怪异模式（Quirks Mode），从而影响后续的 HTML 解析和渲染行为。
   - **与 HTML 的关系：**  直接处理 HTML 文档的起始声明，决定浏览器的渲染模式。
   - **假设输入与输出：**
     - **假设输入：** 一个表示 `<!DOCTYPE html>` 的 `AtomicHTMLToken`。
     - **输出：**  创建一个 `DocumentType` 节点，其名称为 "html"，公共标识符和系统标识符为空。`SetCompatibilityMode` 可能会被调用以设置文档的兼容模式为标准模式。
     - **假设输入：** 一个表示 `<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">` 的 `AtomicHTMLToken`。
     - **输出：** 创建一个 `DocumentType` 节点，包含相应的名称、公共标识符和系统标识符。`SetCompatibilityModeFromDoctype` 会根据这些标识符来判断是否需要进入怪异模式或有限怪异模式。

2. **`InsertComment(AtomicHTMLToken* token)`:**
   - 功能：处理 HTML 注释 (`<!-- ... -->`).
   - 作用：创建 `Comment` 节点，并将其附加到当前的父节点。
   - **与 HTML 的关系：**  处理 HTML 中的注释内容。
   - **假设输入与输出：**
     - **假设输入：** 一个表示 `<!-- This is a comment -->` 的 `AtomicHTMLToken`。
     - **输出：**  创建一个内容为 " This is a comment " 的 `Comment` 节点，并将其添加到当前正在构建的 DOM 树中。

3. **`InsertDOMPart(AtomicHTMLToken* token)`:**
   - 功能：处理与 DOM Parts API 相关的 token。
   - 作用：在 DOM 树中插入占位符注释节点，用于标记 DOM Parts 的开始和结束。
   - **与 JavaScript, HTML 的关系：**  DOM Parts API 允许 JavaScript 将 DOM 树的一部分标记为可替换的“部件”，用于更高效的更新和渲染。这些注释节点是标记这些部件的。
   - **假设输入与输出：**
     - **假设输入：** 一个 `DOMPartTokenType::kChildNodePartStart` 类型的 `AtomicHTMLToken`，可能包含元数据。
     - **输出：** 插入一个空的 `Comment` 节点，如果 `RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()` 为 false，则将相关的元数据添加到 `pending_dom_parts_` 中。
     - **假设输入：** 一个 `DOMPartTokenType::kChildNodePartEnd` 类型的 `AtomicHTMLToken`。
     - **输出：** 插入一个空的 `Comment` 节点，并在 `pending_dom_parts_` 中标记当前子节点部件的结束。

4. **`InsertCommentOnDocument(AtomicHTMLToken* token)`:**
   - 功能：在文档级别插入注释。
   - 作用：创建 `Comment` 节点，并将其附加到文档对象本身。
   - **与 HTML 的关系：**  处理位于 `<html>` 标签之前的注释。

5. **`InsertCommentOnHTMLHtmlElement(AtomicHTMLToken* token)`:**
   - 功能：在 `<html>` 元素上插入注释。
   - 作用：创建 `Comment` 节点，并将其附加到 `<html>` 元素。
   - **与 HTML 的关系：**  处理位于 `<html>` 标签内部的注释。

6. **`InsertHTMLHeadElement(AtomicHTMLToken* token)`:**
   - 功能：处理 `<head>` 标签。
   - 作用：创建 `HTMLHeadElement` 节点，将其附加到当前父节点，并将该元素推入开放元素栈中。
   - **与 HTML 的关系：**  构建 HTML 文档的头部。

7. **`InsertHTMLBodyElement(AtomicHTMLToken* token)`:**
   - 功能：处理 `<body>` 标签。
   - 作用：创建 `HTMLBodyElement` 节点，将其附加到当前父节点，并将该元素推入开放元素栈中。
   - **与 HTML 的关系：**  构建 HTML 文档的主体。

8. **`InsertHTMLFormElement(AtomicHTMLToken* token, bool is_demoted)`:**
   - 功能：处理 `<form>` 标签。
   - 作用：创建 `HTMLFormElement` 节点，将其附加到当前父节点，并将该元素推入开放元素栈中。如果不在 `<template>` 内部，则将其设置为当前的 `form_` 引用。
   - **与 HTML 的关系：**  构建 HTML 表单元素。
   - **用户或编程常见的使用错误：** 嵌套的 `<form>` 元素通常是不允许的，但浏览器会尝试解析。`is_demoted` 参数可能与处理此类错误有关，例如将内部的 `<form>` 视为普通元素。

9. **`InsertHTMLTemplateElement(AtomicHTMLToken* token, String declarative_shadow_root_mode)`:**
   - 功能：处理 `<template>` 标签。
   - 作用：创建 `HTMLTemplateElement` 节点。如果指定了 `declarative_shadow_root_mode` 并且当前父元素可以作为 Shadow Host，则尝试创建声明式 Shadow DOM。否则，将 `<template>` 元素添加到 DOM 树。
   - **与 JavaScript, HTML 的关系：**  用于创建模板和声明式 Shadow DOM，这些都与 JavaScript 和组件化开发密切相关。
   - **假设输入与输出：**
     - **假设输入：** 一个表示 `<template>` 的 `AtomicHTMLToken`。
     - **输出：** 创建一个 `HTMLTemplateElement` 节点，并将其附加到当前父节点，同时为其创建一个空的 `DocumentFragment` 作为内容。
     - **假设输入：** 一个表示 `<template shadowrootmode="open">` 并且当前父元素是一个允许 Shadow Host 的元素的 `AtomicHTMLToken`。
     - **输出：** 创建一个 `HTMLTemplateElement` 节点，并尝试在其父元素上创建一个 Shadow Root。如果成功，则不会直接将 `<template>` 附加到 DOM 树，而是将其关联到新创建的 Shadow Root。

10. **`InsertHTMLElement(AtomicHTMLToken* token)`:**
    - 功能：处理大多数其他的 HTML 元素。
    - 作用：创建与 token 对应的 `HTMLElement` 节点，将其附加到当前父节点，并将该元素推入开放元素栈中。
    - **与 HTML 的关系：**  构建 HTML 文档的各种元素。

11. **`InsertSelfClosingHTMLElementDestroyingToken(AtomicHTMLToken* token)`:**
    - 功能：处理自闭合的 HTML 元素，例如 `<br/>` 或 `<img/>`。
    - 作用：创建与 token 对应的 `HTMLElement` 节点，并立即将其附加到当前父节点。由于是自闭合标签，不会将其推入开放元素栈。
    - **与 HTML 的关系：**  处理 HTML 中的自闭合标签。

12. **`InsertFormattingElement(AtomicHTMLToken* token)`:**
    - 功能：处理格式化元素，例如 `<b>`, `<i>`, `<u>` 等。
    - 作用：创建对应的 `HTMLElement` 节点，将其附加到当前父节点，并将其推入开放元素栈和活动格式化元素列表。
    - **与 HTML 的关系：**  处理 HTML 中的格式化标签。

13. **`InsertScriptElement(AtomicHTMLToken* token)`:**
    - 功能：处理 `<script>` 标签。
    - 作用：创建 `HTMLScriptElement` 节点，设置相关属性，并根据是否允许脚本执行将其附加到 DOM 树。将其推入开放元素栈。
    - **与 JavaScript, HTML 的关系：**  构建 HTML 文档中的脚本元素，是 JavaScript 代码执行的入口。

14. **`InsertForeignElement(AtomicHTMLToken* token, const AtomicString& namespace_uri)`:**
    - 功能：处理非 HTML 命名空间的元素，例如 SVG 或 MathML。
    - 作用：创建具有指定命名空间的元素节点，并将其附加到当前父节点。
    - **与 HTML 的关系：**  处理嵌入在 HTML 文档中的其他 XML 词汇表。

15. **`InsertTextNode(const StringView& string, WhitespaceMode whitespace_mode)`:**
    - 功能：处理文本节点。
    - 作用：创建一个 `Text` 节点，并将其添加到当前父节点。会处理 foster parenting 的情况，并在必要时刷新待处理的文本。
    - **与 HTML 的关系：**  处理 HTML 元素中的文本内容。

16. **`Reparent(HTMLStackItem* new_parent, HTMLStackItem* child)`:**
    - 功能：将一个节点从一个父节点移动到另一个父节点。
    - 作用：将一个已存在的节点重新附加到新的父节点。
    - **内部逻辑推理：**  假设在解析过程中，由于某些规则，需要将一个节点移动到不同的位置，例如处理表格相关的错误。

17. **`InsertAlreadyParsedChild(HTMLStackItem* new_parent, HTMLStackItem* child)`:**
    - 功能：插入一个已经解析过的子节点。
    - 作用：将一个已经创建好的节点附加到新的父节点。
    - **内部逻辑推理：**  可能用于处理文档片段的插入或处理 `<template>` 元素的内容。

18. **`TakeAllChildren(HTMLStackItem* new_parent, HTMLStackItem* old_parent)`:**
    - 功能：将一个父节点的所有子节点移动到另一个父节点。
    - 作用：将一个父节点的所有子节点转移到新的父节点。
    - **内部逻辑推理：**  可能用于处理某些复杂的 DOM 结构调整。

19. **`GetCreateElementFlags()`:**
    - 功能：获取创建元素时使用的标志。
    - 作用：返回一个 `CreateElementFlags` 对象，指示元素是如何创建的（例如，是否由解析器创建）。

20. **`OwnerDocumentForCurrentNode()`:**
    - 功能：获取当前节点的所属文档。
    - 作用：返回当前正在构建的节点的文档对象。对于 `<template>` 元素，返回其内容文档。

21. **`LookUpCustomElementDefinition(...)`:**
    - 功能：查找自定义元素的定义。
    - 作用：根据标签名和 `is` 属性在文档的自定义元素注册表中查找对应的定义。
    - **与 JavaScript 的关系：**  与 JavaScript 中定义的自定义元素相关联。

22. **`CreateElement(AtomicHTMLToken* token, const AtomicString& namespace_uri)`:**
    - 功能：根据 token 创建一个元素。
    - 作用：根据 token 的信息（标签名、属性、命名空间）创建一个新的 DOM 元素。会考虑自定义元素的定义。
    - **与 JavaScript, HTML 的关系：**  负责将 HTML 标签转化为 DOM 元素，并且与自定义元素的创建和生命周期管理相关。

23. **`CreateElementFromSavedToken(HTMLStackItem* item)`:**
    - 功能：从保存的 token 信息创建一个元素。
    - 作用：用于重新创建之前处理过的元素，例如在处理格式化元素时。

24. **`IndexOfFirstUnopenFormattingElement(...)` 和 `ReconstructTheActiveFormattingElements()`:**
    - 功能：用于处理嵌套格式化元素时的错误恢复。
    - 作用：查找第一个未打开的格式化元素，并重新创建这些元素。
    - **与 HTML 的关系：**  处理 HTML 格式化元素嵌套的特殊规则。

25. **`GenerateImpliedEndTagsWithExclusion(...)` 和 `GenerateImpliedEndTags()`:**
    - 功能：生成隐含的结束标签。
    - 作用：在某些情况下，HTML 允许省略结束标签。这些函数用于在解析过程中自动生成这些隐含的结束标签。
    - **与 HTML 的关系：**  处理 HTML 语法的灵活性。

26. **`InQuirksMode()`:**
    - 功能：判断当前是否处于怪异模式。
    - 作用：返回一个布尔值，指示当前的解析是否处于怪异模式。
    - **与 HTML 的关系：**  影响 HTML 的解析和渲染行为。

27. **`FindFosterSite(HTMLConstructionSiteTask& task)`:**
    - 功能：查找用于 foster parenting 的插入位置。
    - 作用：当遇到某些特定元素时，需要将其插入到 DOM 树的特定位置，而不是当前父节点。这个函数用于确定这个特殊的位置。
    - **与 HTML 的关系：**  处理 HTML 中某些元素（如 `<td>` 在 `<table>` 外部）的特殊插入规则。

28. **`ShouldFosterParent()`:**
    - 功能：判断是否应该进行 foster parenting。
    - 作用：返回一个布尔值，指示当前是否应该使用 foster parenting 算法来插入节点。

29. **`FosterParent(Node* node)`:**
    - 功能：执行 foster parenting 操作。
    - 作用：将指定的节点插入到通过 `FindFosterSite` 找到的位置。
    - **与 HTML 的关系：**  处理 HTML 中某些元素（如 `<td>` 在 `<table>` 外部）的特殊插入规则。

30. **`FinishedTemplateElement(DocumentFragment* content_fragment)`:**
    - 功能：在完成 `<template>` 元素的解析后进行清理工作。
    - 作用：例如，弹出与 `<template>` 相关的 DOM Parts 根节点。

31. **`PendingDOMParts` 类及其相关方法：**
    - 功能：管理待处理的 DOM Parts。
    - 作用：用于记录和管理在解析过程中遇到的 DOM Parts 的开始和结束，以及相关的元数据。
    - **与 JavaScript, HTML 的关系：**  支持 DOM Parts API。

32. **`PendingText` 结构体：**
    - 功能：暂存待插入的文本节点信息。
    - 作用：在某些情况下，文本节点可能需要稍后插入，这个结构体用于暂存这些信息。

**用户或编程常见的使用错误举例：**

- **在 `<table>` 元素外部直接添加 `<td>` 或 `<tr>` 等表格子元素：** 浏览器会使用 foster parenting 算法将这些元素插入到 `<table>` 元素之前或之后的最合适位置，而不是直接作为其子元素。
- **在不允许的位置使用声明式 Shadow DOM：** 例如，在非元素的节点上使用 `<template shadowrootmode="...">`，解析器会将其视为普通的 `<template>` 元素。
- **不正确的文档类型声明：** 可能导致浏览器进入怪异模式，从而影响页面的布局和行为。

总而言之，这段代码是 Blink 渲染引擎中 HTML 解析器的核心组成部分，它负责将解析后的 HTML 结构转化为浏览器可以理解和渲染的 DOM 树。它处理了各种 HTML 语法规则、错误处理以及与 JavaScript 功能（如自定义元素和 DOM Parts）的集成。

### 提示词
```
这是目录为blink/renderer/core/html/parser/html_construction_site.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
gImpl::Create8BitIfPossible(token->SystemIdentifier());
  auto* doctype = MakeGarbageCollected<DocumentType>(
      document_, token->GetName(), public_id, system_id);
  AttachLater(attachment_root_, doctype);

  // DOCTYPE nodes are only processed when parsing fragments w/o
  // contextElements, which never occurs.  However, if we ever chose to support
  // such, this code is subtly wrong, because context-less fragments can
  // determine their own quirks mode, and thus change parsing rules (like <p>
  // inside <table>).  For now we ASSERT that we never hit this code in a
  // fragment, as changing the owning document's compatibility mode would be
  // wrong.
  DCHECK(!is_parsing_fragment_);
  if (is_parsing_fragment_)
    return;

  if (token->ForceQuirks())
    SetCompatibilityMode(Document::kQuirksMode);
  else {
    SetCompatibilityModeFromDoctype(token->GetHTMLTag(), public_id, system_id);
  }
}

void HTMLConstructionSite::InsertComment(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kComment);
  auto comment = token->Comment();
  Comment& comment_node =
      *Comment::Create(OwnerDocumentForCurrentNode(), comment);
  AttachLater(CurrentNode(), &comment_node);
}

void HTMLConstructionSite::InsertDOMPart(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kDOMPart);
  CHECK(pending_dom_parts_);
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(InParsePartsScope());
  // Insert an empty comment in place of the part token.
  Comment& comment_node = *Comment::Create(OwnerDocumentForCurrentNode(), "");
  if (RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
    // Just set a bit on this comment node that it has a NodePart, and change
    // the content of the comment to kChildNodePartStartCommentData or
    // kChildNodePartEndCommentData, as appropriate.
    comment_node.SetHasNodePart();
    switch (token->DOMPartType()) {
      case DOMPartTokenType::kChildNodePartStart:
        comment_node.setData(kChildNodePartStartCommentData);
        break;
      case DOMPartTokenType::kChildNodePartEnd:
        comment_node.setData(kChildNodePartEndCommentData);
        break;
    }
  } else {
    switch (token->DOMPartType()) {
      case DOMPartTokenType::kChildNodePartStart:
        pending_dom_parts_->AddChildNodePartStart(comment_node,
                                                  token->DOMPartMetadata());
        break;
      case DOMPartTokenType::kChildNodePartEnd:
        pending_dom_parts_->AddChildNodePartEnd(comment_node);
        break;
    }
  }
  AttachLater(CurrentNode(), &comment_node);
}

void HTMLConstructionSite::InsertCommentOnDocument(AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kComment);
  DCHECK(document_);
  AttachLater(attachment_root_, Comment::Create(*document_, token->Comment()));
}

void HTMLConstructionSite::InsertCommentOnHTMLHtmlElement(
    AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kComment);
  ContainerNode* parent = open_elements_.RootNode();
  AttachLater(parent, Comment::Create(parent->GetDocument(), token->Comment()));
}

void HTMLConstructionSite::InsertHTMLHeadElement(AtomicHTMLToken* token) {
  DCHECK(!ShouldFosterParent());
  head_ = HTMLStackItem::Create(
      CreateElement(token, html_names::xhtmlNamespaceURI), token);
  AttachLater(CurrentNode(), head_->GetElement(), token->GetDOMPartsNeeded());
  open_elements_.PushHTMLHeadElement(head_);
}

void HTMLConstructionSite::InsertHTMLBodyElement(AtomicHTMLToken* token) {
  DCHECK(!ShouldFosterParent());
  Element* body = CreateElement(token, html_names::xhtmlNamespaceURI);
  AttachLater(CurrentNode(), body, token->GetDOMPartsNeeded());
  open_elements_.PushHTMLBodyElement(HTMLStackItem::Create(body, token));
  if (document_)
    document_->WillInsertBody();
}

void HTMLConstructionSite::InsertHTMLFormElement(AtomicHTMLToken* token,
                                                 bool is_demoted) {
  auto* form_element =
      To<HTMLFormElement>(CreateElement(token, html_names::xhtmlNamespaceURI));
  if (!OpenElements()->HasTemplateInHTMLScope())
    form_ = form_element;
  if (is_demoted) {
    UseCounter::Count(OwnerDocumentForCurrentNode(),
                      WebFeature::kDemotedFormElement);
  }
  AttachLater(CurrentNode(), form_element, token->GetDOMPartsNeeded());
  open_elements_.Push(HTMLStackItem::Create(form_element, token));
}

void HTMLConstructionSite::InsertHTMLTemplateElement(
    AtomicHTMLToken* token,
    String declarative_shadow_root_mode) {
  // Regardless of whether a declarative shadow root is being attached, the
  // template element is always created. If the template is a valid declarative
  // Shadow Root (has a valid attribute value and parent element), then the
  // template is only added to the stack of open elements, but is not attached
  // to the DOM tree.
  auto* template_element = To<HTMLTemplateElement>(
      CreateElement(token, html_names::xhtmlNamespaceURI));
  HTMLStackItem* template_stack_item =
      HTMLStackItem::Create(template_element, token);
  bool should_attach_template = true;
  if (!declarative_shadow_root_mode.IsNull() &&
      IsA<Element>(open_elements_.TopStackItem()->GetNode())) {
    auto focus_delegation = template_stack_item->GetAttributeItem(
                                html_names::kShadowrootdelegatesfocusAttr)
                                ? FocusDelegation::kDelegateFocus
                                : FocusDelegation::kNone;
    // TODO(crbug.com/1063157): Add an attribute for imperative slot
    // assignment.
    auto slot_assignment_mode = SlotAssignmentMode::kNamed;
    bool serializable =
        template_stack_item->GetAttributeItem(
            html_names::kShadowrootserializableAttr);
    bool clonable = template_stack_item->GetAttributeItem(
        html_names::kShadowrootclonableAttr);
    const auto* reference_target_attr =
        RuntimeEnabledFeatures::ShadowRootReferenceTargetEnabled()
            ? template_stack_item->GetAttributeItem(
                  html_names::kShadowrootreferencetargetAttr)
            : nullptr;
    const auto& reference_target =
        reference_target_attr ? reference_target_attr->Value() : g_null_atom;
    HTMLStackItem* shadow_host_stack_item = open_elements_.TopStackItem();
    Element* host = shadow_host_stack_item->GetElement();

    bool success = host->AttachDeclarativeShadowRoot(
        *template_element, declarative_shadow_root_mode, focus_delegation,
        slot_assignment_mode, serializable, clonable, reference_target);
    // If the shadow root attachment fails, e.g. if the host element isn't a
    // valid shadow host, then we leave should_attach_template true, so that
    // a "normal" template element gets attached to the DOM tree.
    if (success) {
      DCHECK(host->AuthorShadowRoot());
      UseCounter::Count(host->GetDocument(),
                        WebFeature::kStreamingDeclarativeShadowDOM);
      should_attach_template = false;
      template_element->SetDeclarativeShadowRoot(*host->AuthorShadowRoot());
    }
  }
  if (should_attach_template) {
    // Attach a normal template element.
    AttachLater(CurrentNode(), template_element, token->GetDOMPartsNeeded());
    DocumentFragment* template_content = template_element->content();
    if (pending_dom_parts_ && template_content &&
        !RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
      DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
      pending_dom_parts_->PushPartRoot(&template_content->getPartRoot());
    }
  }
  open_elements_.Push(template_stack_item);
}

void HTMLConstructionSite::InsertHTMLElement(AtomicHTMLToken* token) {
  Element* element = CreateElement(token, html_names::xhtmlNamespaceURI);
  AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.Push(HTMLStackItem::Create(element, token));
}

void HTMLConstructionSite::InsertSelfClosingHTMLElementDestroyingToken(
    AtomicHTMLToken* token) {
  DCHECK_EQ(token->GetType(), HTMLToken::kStartTag);
  // Normally HTMLElementStack is responsible for calling finishParsingChildren,
  // but self-closing elements are never in the element stack so the stack
  // doesn't get a chance to tell them that we're done parsing their children.
  AttachLater(CurrentNode(),
              CreateElement(token, html_names::xhtmlNamespaceURI),
              token->GetDOMPartsNeeded(), /*self_closing*/ true);
  // FIXME: Do we want to acknowledge the token's self-closing flag?
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/tokenization.html#acknowledge-self-closing-flag
}

void HTMLConstructionSite::InsertFormattingElement(AtomicHTMLToken* token) {
  // http://www.whatwg.org/specs/web-apps/current-work/multipage/parsing.html#the-stack-of-open-elements
  // Possible active formatting elements include:
  // a, b, big, code, em, font, i, nobr, s, small, strike, strong, tt, and u.
  InsertHTMLElement(token);
  active_formatting_elements_.Append(CurrentStackItem());
}

void HTMLConstructionSite::InsertScriptElement(AtomicHTMLToken* token) {
  CreateElementFlags flags;
  bool should_be_parser_inserted =
      parser_content_policy_ !=
      kAllowScriptingContentAndDoNotMarkAlreadyStarted;
  flags
      // http://www.whatwg.org/specs/web-apps/current-work/multipage/scripting-1.html#already-started
      // http://html5.org/specs/dom-parsing.html#dom-range-createcontextualfragment
      // For createContextualFragment, the specifications say to mark it
      // parser-inserted and already-started and later unmark them. However, we
      // short circuit that logic to avoid the subtree traversal to find script
      // elements since scripts can never see those flags or effects thereof.
      .SetCreatedByParser(should_be_parser_inserted,
                          should_be_parser_inserted ? document_ : nullptr)
      .SetAlreadyStarted(is_parsing_fragment_ && flags.IsCreatedByParser());
  HTMLScriptElement* element = nullptr;
  if (const auto* is_attribute = token->GetAttributeItem(html_names::kIsAttr)) {
    element = To<HTMLScriptElement>(OwnerDocumentForCurrentNode().CreateElement(
        html_names::kScriptTag, flags, is_attribute->Value()));
  } else {
    element = MakeGarbageCollected<HTMLScriptElement>(
        OwnerDocumentForCurrentNode(), flags);
  }
  SetAttributes(element, token);
  if (is_scripting_content_allowed_)
    AttachLater(CurrentNode(), element, token->GetDOMPartsNeeded());
  open_elements_.Push(HTMLStackItem::Create(element, token));
}

void HTMLConstructionSite::InsertForeignElement(
    AtomicHTMLToken* token,
    const AtomicString& namespace_uri) {
  DCHECK_EQ(token->GetType(), HTMLToken::kStartTag);
  // parseError when xmlns or xmlns:xlink are wrong.
  DVLOG(1) << "Not implemented.";

  Element* element = CreateElement(token, namespace_uri);
  if (is_scripting_content_allowed_ || !element->IsScriptElement()) {
    DCHECK(!token->GetDOMPartsNeeded());
    AttachLater(CurrentNode(), element, /*dom_parts_needed*/ {},
                token->SelfClosing());
  }
  if (!token->SelfClosing()) {
    open_elements_.Push(HTMLStackItem::Create(element, token, namespace_uri));
  }
}

void HTMLConstructionSite::InsertTextNode(const StringView& string,
                                          WhitespaceMode whitespace_mode) {
  HTMLConstructionSiteTask dummy_task(HTMLConstructionSiteTask::kInsert);
  dummy_task.parent = CurrentNode();

  if (ShouldFosterParent())
    FindFosterSite(dummy_task);

  if (auto* template_element =
          DynamicTo<HTMLTemplateElement>(*dummy_task.parent)) {
    // If the Document was detached in the middle of parsing, the template
    // element won't be able to initialize its contents.
    if (auto* content =
            template_element->TemplateContentOrDeclarativeShadowRoot()) {
      dummy_task.parent = content;
    }
  }

  // Unclear when parent != case occurs. Somehow we insert text into two
  // separate nodes while processing the same Token. The nextChild !=
  // dummy.nextChild case occurs whenever foster parenting happened and we hit a
  // new text node "<table>a</table>b" In either case we have to flush the
  // pending text into the task queue before making more.
  if (!pending_text_.IsEmpty() &&
      (pending_text_.parent != dummy_task.parent ||
       pending_text_.next_child != dummy_task.next_child))
    FlushPendingText();
  pending_text_.Append(dummy_task.parent, dummy_task.next_child, string,
                       whitespace_mode);
}

void HTMLConstructionSite::Reparent(HTMLStackItem* new_parent,
                                    HTMLStackItem* child) {
  HTMLConstructionSiteTask task(HTMLConstructionSiteTask::kReparent);
  task.parent = new_parent->GetNode();
  task.child = child->GetNode();
  QueueTask(task, true);
}

void HTMLConstructionSite::InsertAlreadyParsedChild(HTMLStackItem* new_parent,
                                                    HTMLStackItem* child) {
  if (new_parent->CausesFosterParenting()) {
    FosterParent(child->GetNode());
    return;
  }

  HTMLConstructionSiteTask task(
      HTMLConstructionSiteTask::kInsertAlreadyParsedChild);
  task.parent = new_parent->GetNode();
  task.child = child->GetNode();
  QueueTask(task, true);
}

void HTMLConstructionSite::TakeAllChildren(HTMLStackItem* new_parent,
                                           HTMLStackItem* old_parent) {
  HTMLConstructionSiteTask task(HTMLConstructionSiteTask::kTakeAllChildren);
  task.parent = new_parent->GetNode();
  task.child = old_parent->GetNode();
  QueueTask(task, true);
}

CreateElementFlags HTMLConstructionSite::GetCreateElementFlags() const {
  return is_parsing_fragment_ ? CreateElementFlags::ByFragmentParser(document_)
                              : CreateElementFlags::ByParser(document_);
}

Document& HTMLConstructionSite::OwnerDocumentForCurrentNode() {
  // TODO(crbug.com/1070667): For <template> elements, many operations need to
  // be re-targeted to the .content() document of the template. This function is
  // used in those places. The spec needs to be updated to reflect this
  // behavior, and when that happens, a link to the spec should be placed here.
  if (auto* template_element = DynamicTo<HTMLTemplateElement>(*CurrentNode())) {
    // If the Document was detached in the middle of parsing, The template
    // element won't be able to initialize its contents. Fallback to the
    // current node's document in that case..
    if (auto* content =
            template_element->TemplateContentOrDeclarativeShadowRoot()) {
      return content->GetDocument();
    }
  }
  return CurrentNode()->GetDocument();
}

// "look up a custom element definition" for a token
// https://html.spec.whatwg.org/C/#look-up-a-custom-element-definition
// static
CustomElementDefinition* HTMLConstructionSite::LookUpCustomElementDefinition(
    Document& document,
    const QualifiedName& tag_name,
    const AtomicString& is) {
  // "1. If namespace is not the HTML namespace, return null."
  if (tag_name.NamespaceURI() != html_names::xhtmlNamespaceURI)
    return nullptr;

  // "2. If document does not have a browsing context, return null."
  LocalDOMWindow* window = document.domWindow();
  if (!window)
    return nullptr;

  // "3. Let registry be document's browsing context's Window's
  // CustomElementRegistry object."
  CustomElementRegistry* registry = window->MaybeCustomElements();
  if (!registry)
    return nullptr;

  const AtomicString& local_name = tag_name.LocalName();
  const AtomicString& name = !is.IsNull() ? is : local_name;
  CustomElementDescriptor descriptor(name, local_name);

  // 4.-6.
  return registry->DefinitionFor(descriptor);
}

// "create an element for a token"
// https://html.spec.whatwg.org/C/#create-an-element-for-the-token
Element* HTMLConstructionSite::CreateElement(
    AtomicHTMLToken* token,
    const AtomicString& namespace_uri) {
  // "1. Let document be intended parent's node document."
  Document& document = OwnerDocumentForCurrentNode();

  // "2. Let local name be the tag name of the token."
  QualifiedName tag_name =
      ((token->IsValidHTMLTag() &&
        namespace_uri == html_names::xhtmlNamespaceURI)
           ? static_cast<const QualifiedName&>(
                 html_names::TagToQualifiedName(token->GetHTMLTag()))
           : QualifiedName(g_null_atom, token->GetName(), namespace_uri));
  // "3. Let is be the value of the "is" attribute in the given token ..." etc.
  const Attribute* is_attribute = token->GetAttributeItem(html_names::kIsAttr);
  const AtomicString& is = is_attribute ? is_attribute->Value() : g_null_atom;
  // "4. Let definition be the result of looking up a custom element ..." etc.
  auto* definition = LookUpCustomElementDefinition(document, tag_name, is);
  // "5. If definition is non-null and the parser was not originally created
  // for the HTML fragment parsing algorithm, then let will execute script
  // be true."
  bool will_execute_script = definition && !is_parsing_fragment_;

  Element* element;

  // This check and the steps inside are duplicated in
  // XMLDocumentParser::StartElementNs.
  if (will_execute_script) {
    // "6.1 Increment the document's throw-on-dynamic-insertion counter."
    ThrowOnDynamicMarkupInsertionCountIncrementer
        throw_on_dynamic_markup_insertions(&document);

    // "6.2 If the JavaScript execution context stack is empty,
    // then perform a microtask checkpoint."

    // TODO(dominicc): This is the way the Blink HTML parser performs
    // checkpoints, but note the spec is different--it talks about the
    // JavaScript stack, not the script nesting level.
    if (0u == reentry_permit_->ScriptNestingLevel())
      document.GetAgent().event_loop()->PerformMicrotaskCheckpoint();

    // "6.3 Push a new element queue onto the custom element
    // reactions stack."
    CEReactionsScope reactions;

    // "7. Let element be the result of creating an element given document,
    // localName, given namespace, null, and is. If will execute script is true,
    // set the synchronous custom elements flag; otherwise, leave it unset."
    // TODO(crbug.com/1080673): We clear the CreatedbyParser flag here, so that
    // elements get fully constructed. Some elements (e.g. HTMLInputElement)
    // only partially construct themselves when created by the parser, but since
    // this is a custom element, we need a fully-constructed element here.
    element = definition->CreateElement(
        document, tag_name,
        GetCreateElementFlags().SetCreatedByParser(false, nullptr));

    // "8. Append each attribute in the given token to element." We don't use
    // setAttributes here because the custom element constructor may have
    // manipulated attributes.
    for (const auto& attribute : token->Attributes())
      element->setAttribute(attribute.GetName(), attribute.Value());

    // "9. If will execute script is true, then ..." etc. The CEReactionsScope
    // and ThrowOnDynamicMarkupInsertionCountIncrementer destructors implement
    // steps 9.1-3.
  } else {
    if (definition) {
      DCHECK(GetCreateElementFlags().IsAsyncCustomElements());
      element = definition->CreateElement(document, tag_name,
                                          GetCreateElementFlags());
    } else {
      element = CustomElement::CreateUncustomizedOrUndefinedElement(
          document, tag_name, GetCreateElementFlags(), is);
    }
    // Definition for the created element does not exist here and it cannot be
    // custom, precustomized, or failed.
    DCHECK_NE(element->GetCustomElementState(), CustomElementState::kCustom);
    DCHECK_NE(element->GetCustomElementState(),
              CustomElementState::kPreCustomized);
    DCHECK_NE(element->GetCustomElementState(), CustomElementState::kFailed);

    // TODO(dominicc): Move these steps so they happen for custom
    // elements as well as built-in elements when customized built in
    // elements are implemented for resettable, listed elements.

    // 10. If element has an xmlns attribute in the XMLNS namespace
    // whose value is not exactly the same as the element's namespace,
    // that is a parse error. Similarly, if element has an xmlns:xlink
    // attribute in the XMLNS namespace whose value is not the XLink
    // Namespace, that is a parse error.

    // TODO(dominicc): Implement step 10 when the HTML parser does
    // something useful with parse errors.

    // 11. If element is a resettable element, invoke its reset
    // algorithm. (This initializes the element's value and
    // checkedness based on the element's attributes.)
    // TODO(dominicc): Implement step 11, resettable elements.

    // 12. If element is a form-associated element, and the form
    // element pointer is not null, and there is no template element
    // on the stack of open elements, ...
    auto* html_element = DynamicTo<HTMLElement>(element);
    FormAssociated* form_associated_element =
        html_element ? html_element->ToFormAssociatedOrNull() : nullptr;
    if (form_associated_element && document.GetFrame() && form_.Get()) {
      // ... and element is either not listed or doesn't have a form
      // attribute, and the intended parent is in the same tree as the
      // element pointed to by the form element pointer, associate
      // element with the form element pointed to by the form element
      // pointer, and suppress the running of the reset the form owner
      // algorithm when the parser subsequently attempts to insert the
      // element.

      // TODO(dominicc): There are many differences to the spec here;
      // some of them are observable:
      //
      // - The HTML spec tracks whether there is a template element on
      //   the stack both for manipulating the form element pointer
      //   and using it here.
      // - FormAssociated::AssociateWith implementations don't do the
      //   "same tree" check; for example
      //   HTMLImageElement::AssociateWith just checks whether the form
      //   is in *a* tree. This check should be done here consistently.
      // - ListedElement is a mixin; add IsListedElement and skip
      //   setting the form for listed attributes with form=. Instead
      //   we set attributes (step 8) out of order, after this step,
      //   to reset the form association.
      form_associated_element->AssociateWith(form_.Get());
    }
    // "8. Append each attribute in the given token to element."
    SetAttributes(element, token);
  }

  return element;
}

HTMLStackItem* HTMLConstructionSite::CreateElementFromSavedToken(
    HTMLStackItem* item) {
  Element* element;
  // NOTE: Moving from item -> token -> item copies the Attribute vector twice!
  Vector<Attribute> attributes;
  attributes.ReserveInitialCapacity(
      static_cast<wtf_size_t>(item->Attributes().size()));
  for (Attribute& attr : item->Attributes()) {
    attributes.push_back(std::move(attr));
  }
  AtomicHTMLToken fake_token(HTMLToken::kStartTag, item->GetTokenName(),
                             std::move(attributes));
  element = CreateElement(&fake_token, item->NamespaceURI());
  return HTMLStackItem::Create(element, &fake_token, item->NamespaceURI());
}

bool HTMLConstructionSite::IndexOfFirstUnopenFormattingElement(
    unsigned& first_unopen_element_index) const {
  if (active_formatting_elements_.IsEmpty())
    return false;
  unsigned index = active_formatting_elements_.size();
  do {
    --index;
    const HTMLFormattingElementList::Entry& entry =
        active_formatting_elements_.at(index);
    if (entry.IsMarker() || open_elements_.Contains(entry.GetElement())) {
      first_unopen_element_index = index + 1;
      return first_unopen_element_index < active_formatting_elements_.size();
    }
  } while (index);
  first_unopen_element_index = index;
  return true;
}

void HTMLConstructionSite::ReconstructTheActiveFormattingElements() {
  unsigned first_unopen_element_index;
  if (!IndexOfFirstUnopenFormattingElement(first_unopen_element_index))
    return;

  unsigned unopen_entry_index = first_unopen_element_index;
  DCHECK_LT(unopen_entry_index, active_formatting_elements_.size());
  for (; unopen_entry_index < active_formatting_elements_.size();
       ++unopen_entry_index) {
    HTMLFormattingElementList::Entry& unopened_entry =
        active_formatting_elements_.at(unopen_entry_index);
    HTMLStackItem* reconstructed =
        CreateElementFromSavedToken(unopened_entry.StackItem());
    AttachLater(CurrentNode(), reconstructed->GetNode());
    open_elements_.Push(reconstructed);
    unopened_entry.ReplaceElement(reconstructed);
  }
}

void HTMLConstructionSite::GenerateImpliedEndTagsWithExclusion(
    const HTMLTokenName& name) {
  while (HasImpliedEndTag(CurrentStackItem()) &&
         !CurrentStackItem()->MatchesHTMLTag(name))
    open_elements_.Pop();
}

void HTMLConstructionSite::GenerateImpliedEndTags() {
  while (HasImpliedEndTag(CurrentStackItem()))
    open_elements_.Pop();
}

bool HTMLConstructionSite::InQuirksMode() {
  return in_quirks_mode_;
}

// Adjusts |task| to match the "adjusted insertion location" determined by the
// foster parenting algorithm, laid out as the substeps of step 2 of
// https://html.spec.whatwg.org/C/#appropriate-place-for-inserting-a-node
void HTMLConstructionSite::FindFosterSite(HTMLConstructionSiteTask& task) {
  // 2.1
  HTMLStackItem* last_template =
      open_elements_.Topmost(html_names::HTMLTag::kTemplate);

  // 2.2
  HTMLStackItem* last_table =
      open_elements_.Topmost(html_names::HTMLTag::kTable);

  // 2.3
  if (last_template &&
      (!last_table || last_template->IsAboveItemInStack(last_table))) {
    task.parent = last_template->GetElement();
    return;
  }

  // 2.4
  if (!last_table) {
    // Fragment case
    task.parent = open_elements_.RootNode();  // DocumentFragment
    return;
  }

  // 2.5
  if (ContainerNode* parent = last_table->GetElement()->parentNode()) {
    task.parent = parent;
    task.next_child = last_table->GetElement();
    return;
  }

  // 2.6, 2.7
  task.parent = last_table->NextItemInStack()->GetElement();
}

bool HTMLConstructionSite::ShouldFosterParent() const {
  return redirect_attach_to_foster_parent_ &&
         CurrentStackItem()->IsElementNode() &&
         CurrentStackItem()->CausesFosterParenting();
}

void HTMLConstructionSite::FosterParent(Node* node) {
  HTMLConstructionSiteTask task(HTMLConstructionSiteTask::kInsert);
  FindFosterSite(task);
  task.child = node;
  DCHECK(task.parent);
  QueueTask(task, true);
}

void HTMLConstructionSite::FinishedTemplateElement(
    DocumentFragment* content_fragment) {
  if (!pending_dom_parts_) {
    return;
  }
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  if (!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled()) {
    pending_dom_parts_->PopPartRoot();
  }
}

HTMLConstructionSite::PendingDOMParts::PendingDOMParts(
    ContainerNode* attachment_root) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  if (Document* document = DynamicTo<Document>(attachment_root)) {
    part_root_stack_.push_back(&document->getPartRoot());
  } else {
    DocumentFragment* fragment = DynamicTo<DocumentFragment>(attachment_root);
    CHECK(fragment) << "Attachment root should be Document or DocumentFragment";
    part_root_stack_.push_back(&fragment->getPartRoot());
  }
}

void HTMLConstructionSite::PendingDOMParts::AddChildNodePartStart(
    Node& previous_sibling,
    Vector<String> metadata) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  // Note that this ChildNodePart is constructed with both `previous_sibling`
  // and `next_sibling` pointing to the same node, `previous_sibling`. That's
  // because at this point we will move on to parse the children of this
  // ChildNodePart, and at that point, we'll need a constructed PartRoot for
  // those to attach to. So we build this currently-invalid ChildNodePart, and
  // then update its `next_sibling` later when we find it, rendering it (and
  // any dependant Parts) valid.
  ChildNodePart* new_part = MakeGarbageCollected<ChildNodePart>(
      *CurrentPartRoot(), previous_sibling, previous_sibling,
      std::move(metadata));
  part_root_stack_.push_back(new_part);
}

void HTMLConstructionSite::PendingDOMParts::AddChildNodePartEnd(
    Node& next_sibling) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  PartRoot* current_part_root = CurrentPartRoot();
  if (current_part_root->IsDocumentPartRoot()) {
    // Mismatched opening/closing child parts.
    return;
  }
  ChildNodePart* last_child_node_part =
      static_cast<ChildNodePart*>(current_part_root);
  last_child_node_part->setNextSibling(next_sibling);
  part_root_stack_.pop_back();
}

void HTMLConstructionSite::PendingDOMParts::ConstructDOMPartsIfNeeded(
    Node& last_node,
    const DOMPartsNeeded& dom_parts_needed) {
  if (!dom_parts_needed) {
    return;
  }
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  DCHECK(pending_node_part_metadata_.empty());
  // For now, there's no syntax for metadata, so just use empty.
  Vector<String> metadata;
  if (dom_parts_needed.needs_node_part) {
    MakeGarbageCollected<NodePart>(*CurrentPartRoot(), last_node, metadata);
  }
  if (!dom_parts_needed.needs_attribute_parts.empty()) {
    Element& element = To<Element>(last_node);
    for (auto attribute_name : dom_parts_needed.needs_attribute_parts) {
      MakeGarbageCollected<AttributePart>(*CurrentPartRoot(), element,
                                          attribute_name, metadata);
    }
  }
}

PartRoot* HTMLConstructionSite::PendingDOMParts::CurrentPartRoot() const {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  CHECK(!part_root_stack_.empty());
  return part_root_stack_.back().Get();
}

void HTMLConstructionSite::PendingDOMParts::PushPartRoot(PartRoot* root) {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  DCHECK(root);
  return part_root_stack_.push_back(root);
}

PartRoot* HTMLConstructionSite::PendingDOMParts::PopPartRoot() {
  DCHECK(RuntimeEnabledFeatures::DOMPartsAPIEnabled());
  DCHECK(!RuntimeEnabledFeatures::DOMPartsAPIMinimalEnabled());
  CHECK(!part_root_stack_.empty());
  PartRoot* popped = part_root_stack_.back();
  part_root_stack_.pop_back();
  return popped;
}

void HTMLConstructionSite::PendingText::Trace(Visitor* visitor) const {
  visitor->Trace(parent);
  visitor->Trace(next_child);
}

void HTMLConstructionSite::PendingDOMParts::Trace(Visitor* visitor) const {
  visitor->Trace(part_root_stack_);
}

}  // namespace blink
```