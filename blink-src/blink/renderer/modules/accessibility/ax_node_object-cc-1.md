Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ax_node_object.cc`. This code appears to be part of the accessibility implementation in the Chromium browser engine (Blink). Specifically, it seems to be involved in determining whether a given HTML element should be included in the accessibility tree.

Here's a breakdown of the code's logic:

1. **`ShouldIncludeBasedOnSemantics(IgnoredReasons* ignored_reasons) const`**: This function seems to be the core of the provided snippet. It determines if an element should be included in the accessibility tree based on its semantic meaning and attributes.

2. **Early Exit for SVG `<g>` elements:** It checks for SVG `<g>` elements and includes them if a specific setting is enabled. This prevents properties in a `<symbol>` subtree from causing inclusion.

3. **Inclusion of Table-related elements:** It explicitly includes table-like elements (`<table>`, `<tr>`, `<td>`, `<th>`, `<thead>`, `<tfoot>`).

4. **Exclusion of `<html>`:** The `<html>` element itself is ignored for accessibility purposes.

5. **Inclusion of Focusable Elements:**  Focusable elements (except `<body>` and `<html>`) are generally included.

6. **Inclusion of Links and Clickable Elements:**  Links and elements with click handlers are included.

7. **Inclusion of Headings:** Heading elements (`<h1>` to `<h6>`) are included.

8. **Inclusion of Header and Footer Tags:** `<header>` and `<footer>` elements are included.

9. **Inclusion of Controls:** Form controls are included.

10. **Inclusion of `<optgroup>`:**  `<optgroup>` elements are included.

11. **Inclusion of Elements with ARIA Roles:** Elements with explicit ARIA roles are included.

12. **Inclusion of Editable Roots:** The root of editable regions is included.

13. **Inclusion of `<legend>` (with exceptions):** `<legend>` elements are generally included, except when they are inside an `<optgroup>` and the `CustomizableSelectEnabled` feature is on.

14. **Inclusion of Elements with Specific ARIA Roles:** A long list of ARIA roles (e.g., `article`, `banner`, `dialog`, `list`, etc.) triggers inclusion.

15. **Inclusion of `<hgroup>`:** `<hgroup>` elements are included.

16. **Inclusion based on `title` Attribute or ARIA Attributes:** Elements with a `title` attribute or any ARIA attribute are included.

17. **Inclusion of Images (with `alt` attribute considerations):** Images are included unless their `alt` attribute is explicitly empty (`alt=""`). A missing `alt` attribute is treated as a mistake, and the image is included to allow for potential repair.

18. **Inclusion of Potential In-Page Link Targets:** Elements that could be the target of an in-page link are included.

19. **Conditional Inclusion of Inline Block Elements:**  If the `ui::AXMode::kInlineTextBoxes` mode is enabled, inline-block elements with siblings are included (with certain role-based exceptions).

20. **Inclusion based on CSS `alt` text:**  Elements with non-empty CSS `alt` text are included. Empty CSS `alt` text results in exclusion.

21. **Exclusion of `<span>` (default):** `<span>` elements are generally ignored unless they have other ARIA information.

22. **Exclusion of Redundant `<label>`:** `<label>` elements that are already associated with a control are ignored to avoid redundancy.

23. **Exclusion of `<foreignObject>` (default):** `<svg:foreignObject>` elements are generally considered presentational and are ignored by default.

24. **`ComputeIsIgnored(IgnoredReasons* ignored_reasons) const`**: This function uses the result of `ShouldIncludeBasedOnSemantics` and other factors (like visibility and layout) to determine if an element should be completely ignored by the accessibility tree.

25. **`GetCSSAltText(const Element* element)`**: A static helper function to retrieve the CSS `alt` text of an element.

26. **Table-related role determination functions**:  `DetermineTableSectionRole`, `DetermineTableRowRole`, and `DetermineTableCellRole` determine the specific ARIA role for table elements based on their context.

27. **Table data retrieval functions**: `ColumnCount`, `RowCount`, `ColumnIndex`, `RowIndex`, `ColumnSpan`, `RowSpan`, `GetSortDirection`, `CellForColumnAndRow`, `FindAllTableCellsWithRole`, `ColumnHeaders`, `RowHeaders`, and `HeaderObject` are functions to extract information about table structure and cells.

28. **`IsDataTable()`**: A heuristic to determine if a table is a "data" table (to be exposed as `kTable`) or a "layout" table (to be exposed as `kLayoutTable`).

**Summary for Part 2:**

This section of the `ax_node_object.cc` file primarily focuses on **determining whether a given HTML element should be included or ignored in the accessibility tree based on its semantic properties, attributes, and role within the document structure, particularly for table elements**. It implements logic to identify elements that are semantically significant for accessibility, such as headings, links, form controls, and elements with specific ARIA roles. It also handles specific cases like SVG elements, images with `alt` attributes, and the treatment of inline-block elements. A significant portion of this section deals with correctly identifying and classifying different parts of a table structure for accessibility purposes.

好的，根据提供的代码片段，`blink/renderer/modules/accessibility/ax_node_object.cc` 文件的第 2 部分（共 10 部分）主要功能是：

**核心功能：基于元素的语义和属性判断其是否应该包含在可访问性树中 (Accessibility Tree)。**

这个代码片段定义了 `AXNodeObject::ShouldIncludeBasedOnSemantics(IgnoredReasons* ignored_reasons) const` 函数，该函数根据一系列规则来决定一个 DOM 节点是否应该被认为是“有趣的”并包含在可访问性树中。 如果该函数返回 `kIncludeObject`，则表示该节点应该被包含。

**具体功能点归纳：**

1. **SVG `<g>` 元素处理：**  检查是否启用了包含 SVG `<g>` 元素的设置，如果启用则包含。这是为了防止 `<symbol>` 子树中的属性导致意外包含。
   * **与 HTML 关系：** SVG 是 HTML 的一部分，此功能处理了特定 SVG 元素的包含逻辑。
   * **假设输入与输出：**
      * **假设输入：** 一个 SVG `<g>` 元素节点。
      * **输出：** 如果 `settings->GetAccessibilityIncludeSvgGElement()` 为真，则返回 `kIncludeObject`，否则继续执行后续判断。

2. **表格相关元素的处理：**  显式地包含表格布局相关的元素，例如 `<table>`、`<tr>`、`<td>`、`<th>` 以及 `<thead>` 和 `<tfoot>` 标签。
   * **与 HTML 关系：** 这些是构成 HTML 表格结构的关键元素。
   * **假设输入与输出：**
      * **假设输入：** 一个表示表格或表格行、单元格的 HTML 元素节点。
      * **输出：** 返回 `kIncludeObject`。

3. **`<html>` 元素的忽略：**  `<html>` 元素自身被标记为不感兴趣并被忽略。
   * **与 HTML 关系：** 这是 HTML 文档的根元素。
   * **假设输入与输出：**
      * **假设输入：** `<html>` 元素节点。
      * **输出：** 返回 `kIgnoreObject`。

4. **可聚焦元素的处理：**  除了 `<body>` 和 `<html>` 之外，所有可以设置焦点属性的元素都被包含。
   * **与 HTML 关系：** 涉及 HTML 元素的焦点管理和可交互性。
   * **假设输入与输出：**
      * **假设输入：** 一个可以获得焦点的 HTML 元素节点（非 `<body>` 或 `<html>`）。
      * **输出：** 返回 `kIncludeObject`。

5. **链接的处理：** 链接元素 (`<a>`) 被包含。
   * **与 HTML 关系：** 这是 HTML 中定义超链接的元素。
   * **假设输入与输出：**
      * **假设输入：** `<a>` 元素节点。
      * **输出：** 返回 `kIncludeObject`。

6. **可点击元素的处理：** 具有点击处理器的元素（例如，通过 JavaScript 添加事件监听器）被包含。
   * **与 JavaScript 和 HTML 关系：** 关联到 JavaScript 事件处理和 HTML 元素的交互性。
   * **假设输入与输出：**
      * **假设输入：** 一个具有点击事件处理器的 HTML 元素节点。
      * **输出：** 返回 `kIncludeObject`。

7. **标题元素的处理：** 标题元素 (`<h1>` 到 `<h6>`) 被包含。
   * **与 HTML 关系：** 这些是 HTML 中定义标题的元素。
   * **假设输入与输出：**
      * **假设输入：** 一个标题元素节点 (`<h1>` 到 `<h6>`)。
      * **输出：** 返回 `kIncludeObject`。

8. **页眉和页脚标签的处理：** `<header>` 和 `<footer>` 标签被包含。
   * **与 HTML 关系：** 这些是 HTML5 中定义的语义化布局元素。
   * **假设输入与输出：**
      * **假设输入：** `<header>` 或 `<footer>` 元素节点。
      * **输出：** 返回 `kIncludeObject`。

9. **控件元素的处理：** 表单控件元素（例如，`<input>`、`<button>`、`<select>`）被包含。
   * **与 HTML 关系：** 这些是 HTML 中用于用户交互的表单元素。
   * **假设输入与输出：**
      * **假设输入：** 一个表单控件元素节点。
      * **输出：** 返回 `kIncludeObject`。

10. **`<optgroup>` 元素的处理：** `<optgroup>` 元素被包含。
    * **与 HTML 关系：** 用于在 `<select>` 元素中对选项进行分组。
    * **假设输入与输出：**
       * **假设输入：** `<optgroup>` 元素节点。
       * **输出：** 返回 `kIncludeObject`。

11. **具有显式 ARIA 角色的元素的处理：** 任何具有非 `kUnknown` ARIA 角色的元素都被包含。
    * **与 HTML 关系：** 涉及使用 ARIA 属性增强 HTML 的可访问性。
    * **假设输入与输出：**
       * **假设输入：** 一个具有 ARIA `role` 属性的 HTML 元素节点。
       * **输出：** 返回 `kIncludeObject`。

12. **可编辑根元素的处理：** 可编辑区域的根元素被包含。
    * **与 HTML 关系：** 涉及 HTML 中可编辑区域的处理，例如使用 `contenteditable` 属性。
    * **假设输入与输出：**
       * **假设输入：** 一个作为可编辑区域根的 HTML 元素节点。
       * **输出：** 返回 `kIncludeObject`。

13. **`<legend>` 元素的处理：** `<legend>` 元素通常被包含，但当它位于 `<optgroup>` 内部且 `CustomizableSelectEnabled` 功能启用时会被忽略。
    * **与 HTML 关系：** `<legend>` 用于为 `<fieldset>` 元素定义标题。
    * **假设输入与输出：**
       * **假设输入：** `<legend>` 元素节点。
       * **输出：**  如果不在 `<optgroup>` 内部或 `CustomizableSelectEnabled` 未启用，则返回 `kIncludeObject`；否则，返回 `kIgnoreObject`。

14. **特定 ARIA 角色的元素处理：**  代码中定义了一个包含大量 ARIA 角色的静态集合 `always_included_computed_roles`，如果元素的计算角色在这个集合中，则被包含。
    * **与 HTML 关系：** 进一步利用 ARIA 属性增强 HTML 的可访问性。
    * **假设输入与输出：**
       * **假设输入：** 一个具有特定 ARIA 角色（例如 `article`, `banner`, `dialog` 等）的 HTML 元素节点。
       * **输出：** 返回 `kIncludeObject`。

15. **`<hgroup>` 元素的处理：** `<hgroup>` 元素被包含。
    * **与 HTML 关系：** 用于组合标题。
    * **假设输入与输出：**
       * **假设输入：** `<hgroup>` 元素节点。
       * **输出：** 返回 `kIncludeObject`。

16. **基于 `title` 属性或 ARIA 属性的处理：** 如果元素具有 `title` 属性或任何 ARIA 属性，则被包含。
    * **与 HTML 关系：**  利用 HTML 的 `title` 属性和 ARIA 属性提供可访问性信息。
    * **假设输入与输出：**
       * **假设输入：** 一个具有 `title` 属性或 ARIA 属性的 HTML 元素节点。
       * **输出：** 返回 `kIncludeObject`。

17. **图像元素的处理：**  `<img>` 元素会被包含，除非其 `alt` 属性为空字符串 (`alt=""`)。如果 `alt` 属性缺失（`IsNull()` 返回 true），则认为可能是一个错误，仍然会包含该图像。
    * **与 HTML 关系：** 处理 HTML `<img>` 元素的 `alt` 属性，这是提供图像可访问性文本的关键。
    * **假设输入与输出：**
       * **假设输入：** `<img>` 元素节点。
       * **输出：** 如果 `alt` 属性非空或缺失，则返回 `kIncludeObject`；如果 `alt` 属性为空字符串，则返回 `kIgnoreObject`。

18. **潜在的页面内链接目标的处理：**  如果元素可能是页面内链接的目标，则被包含。
    * **与 HTML 关系：** 涉及处理 HTML 锚点和页面内导航。
    * **假设输入与输出：**
       * **假设输入：** 一个可能是页面内链接目标的 HTML 元素节点。
       * **输出：** 返回 `kIncludeObject`。

19. **内联块元素的条件处理：**  当 `AXMode` 包含 `kInlineTextBoxes` 时，内联块元素（`display: inline-block`）且拥有兄弟节点的元素会被包含（某些角色会被排除）。
    * **与 CSS 和 HTML 关系：** 涉及 CSS 的 `display` 属性和 HTML 元素的布局。
    * **假设输入与输出：**
       * **假设输入：** 一个 `display: inline-block` 的 HTML 元素节点，且其父元素拥有多个子元素。
       * **输出：** 返回 `kIncludeObject`（前提是 `IsExemptFromInlineBlockCheck` 返回 false）。

20. **CSS `alt` 文本的处理：**  如果元素具有非空的 CSS `alt` 文本 (通过 `content` 属性定义)，则被包含；如果 CSS `alt` 文本为空，则被忽略。
    * **与 CSS 关系：** 涉及 CSS 的 `content` 属性和 `alt` 文本的定义。
    * **假设输入与输出：**
       * **假设输入：** 一个通过 CSS `content` 属性定义了 `alt` 文本的 HTML 元素节点。
       * **输出：** 如果 CSS `alt` 文本非空，则返回 `kIncludeObject`；如果为空，则返回 `kIgnoreObject`。

21. **`<span>` 元素的处理：**  默认情况下，`<span>` 元素会被忽略，除非它们具有其他 ARIA 信息。
    * **与 HTML 关系：** `<span>` 通常作为通用的内联容器。
    * **假设输入与输出：**
       * **假设输入：** `<span>` 元素节点。
       * **输出：** 返回 `kIgnoreObject`。

22. **冗余 `<label>` 元素的处理：**  如果 `<label>` 元素已经被用于命名一个控件，则会被忽略以避免冗余。
    * **与 HTML 关系：**  涉及 HTML 表单元素 `<label>` 及其 `for` 属性的使用。
    * **假设输入与输出：**
       * **假设输入：** 一个与表单控件关联的 `<label>` 元素节点。
       * **输出：** 返回 `kIgnoreObject`。

23. **`<foreignObject>` 元素的处理：**  `<svg:foreignObject>` 元素默认情况下被认为是展示性的并被忽略。
    * **与 HTML 和 SVG 关系：** 涉及 SVG 中嵌入外部 XML 内容的元素。
    * **假设输入与输出：**
       * **假设输入：** `<svg:foreignObject>` 元素节点。
       * **输出：** 返回 `kIgnoreObject`。

**用户操作到达此处的调试线索：**

当用户与网页交互时，例如加载网页、滚动、点击元素或者使用辅助技术浏览网页时，Blink 引擎会构建可访问性树。  `AXNodeObject::ShouldIncludeBasedOnSemantics` 函数会在构建此树的过程中被调用，针对每个 DOM 节点评估其是否应该被包含。

例如：

1. **加载包含表格的网页：**  当浏览器渲染包含表格的 HTML 页面时，会为表格的 `<table>`, `<tr>`, `<td>`, `<th>` 等元素创建 `AXNodeObject`，并调用此函数来决定是否将它们添加到可访问性树中。
2. **用户点击一个 `<div>` 元素，该元素通过 JavaScript 添加了点击事件处理器：**  在构建可访问性树时，会检测到该 `<div>` 元素上的点击事件处理器，从而将其包含在可访问性树中。
3. **屏幕阅读器用户浏览一个带有 `alt` 属性的 `<img>` 元素：**  引擎会检查 `<img>` 元素的 `alt` 属性，根据其值决定是否包含该元素，以便屏幕阅读器可以读取 `alt` 文本。

**常见使用错误举例：**

1. **图像缺少 `alt` 属性：**  开发者忘记为 `<img>` 元素添加 `alt` 属性，导致辅助技术用户无法理解图像内容。代码中会将缺少 `alt` 属性的图像包含进来，这可以被视为一种容错机制，但最佳实践仍然是提供有意义的 `alt` 文本。
2. **过度使用 `<span>` 标签而没有提供可访问性信息：**  开发者可能使用大量的 `<span>` 标签进行样式布局，而没有添加任何 ARIA 属性，导致这些 `<span>` 元素被可访问性树忽略，损失了潜在的结构信息。
3. **将语义化的内容包裹在 `role="presentation"` 的元素中：**  开发者可能错误地使用 `role="presentation"` 隐藏了元素的语义信息，导致其子元素也被忽略。
4. **CSS `alt` 文本使用不当：**  开发者可能错误地使用空的 CSS `alt` 文本，导致应该被暴露的内容被隐藏。

总结来说，这个代码片段是 Blink 引擎可访问性实现的关键部分，它定义了元素是否对辅助技术“可见”的基本规则，并对各种 HTML 元素和 ARIA 属性进行了细致的处理。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能

"""
Settings* settings = GetDocument()->GetSettings();
      if (settings->GetAccessibilityIncludeSvgGElement()) {
        return kIncludeObject;
      }
    }

    // If we return kDefaultBehavior here, the logic related to inclusion of
    // clickable objects, links, controls, etc. will not be reached. We handle
    // SVG elements early to ensure properties in a <symbol> subtree do not
    // result in inclusion.
  }

  if (IsTableLikeRole() || IsTableRowLikeRole() || IsTableCellLikeRole() ||
      element->HasTagName(html_names::kTheadTag) ||
      element->HasTagName(html_names::kTfootTag)) {
    return kIncludeObject;
  }

  if (IsA<HTMLHtmlElement>(node)) {
    if (ignored_reasons) {
      ignored_reasons->push_back(IgnoredReason(kAXUninteresting));
    }
    return kIgnoreObject;
  }

  // All focusable elements except the <body> and <html> are included.
  if (!IsA<HTMLBodyElement>(node) && CanSetFocusAttribute())
    return kIncludeObject;

  if (IsLink())
    return kIncludeObject;

  // A click handler might be placed on an otherwise ignored non-empty block
  // element, e.g. a div. We shouldn't ignore such elements because if an AT
  // sees the |ax::mojom::blink::DefaultActionVerb::kClickAncestor|, it will
  // look for the clickable ancestor and it expects to find one.
  if (IsClickable())
    return kIncludeObject;

  if (IsHeading())
    return kIncludeObject;

  // Header and footer tags may also be exposed as landmark roles but not
  // always.
  if (node->HasTagName(html_names::kHeaderTag) ||
      node->HasTagName(html_names::kFooterTag))
    return kIncludeObject;

  // All controls are accessible.
  if (IsControl())
    return kIncludeObject;

  if (IsA<HTMLOptGroupElement>(node)) {
    return kIncludeObject;
  }

  // Anything with an explicit ARIA role should be included.
  if (RawAriaRole() != ax::mojom::blink::Role::kUnknown) {
    return kIncludeObject;
  }

  // Anything that is an editable root should not be ignored. However, one
  // cannot just call `AXObject::IsEditable()` since that will include the
  // contents of an editable region too. Only the editable root should always be
  // exposed.
  if (IsEditableRoot())
    return kIncludeObject;

  // Don't ignored legends, because JAWS uses them to determine redundant text.
  if (IsA<HTMLLegendElement>(node)) {
    if (RuntimeEnabledFeatures::CustomizableSelectEnabled()) {
      // When a <legend> is used inside an <optgroup>, it is used to set the
      // name of the <optgroup> and shouldn't be redundantly repeated.
      for (auto* ancestor = node->parentNode(); ancestor;
           ancestor = ancestor->parentNode()) {
        if (IsA<HTMLOptGroupElement>(ancestor)) {
          return kIgnoreObject;
        }
      }
    }
    return kIncludeObject;
  }

  static constexpr auto always_included_computed_roles =
      base::MakeFixedFlatSet<ax::mojom::blink::Role>({
          ax::mojom::blink::Role::kAbbr,
          ax::mojom::blink::Role::kApplication,
          ax::mojom::blink::Role::kArticle,
          ax::mojom::blink::Role::kAudio,
          ax::mojom::blink::Role::kBanner,
          ax::mojom::blink::Role::kBlockquote,
          ax::mojom::blink::Role::kCode,
          ax::mojom::blink::Role::kComplementary,
          ax::mojom::blink::Role::kContentDeletion,
          ax::mojom::blink::Role::kContentInfo,
          ax::mojom::blink::Role::kContentInsertion,
          ax::mojom::blink::Role::kDefinition,
          ax::mojom::blink::Role::kDescriptionList,
          ax::mojom::blink::Role::kDetails,
          ax::mojom::blink::Role::kDialog,
          ax::mojom::blink::Role::kDocAcknowledgments,
          ax::mojom::blink::Role::kDocAfterword,
          ax::mojom::blink::Role::kDocAppendix,
          ax::mojom::blink::Role::kDocBibliography,
          ax::mojom::blink::Role::kDocChapter,
          ax::mojom::blink::Role::kDocConclusion,
          ax::mojom::blink::Role::kDocCredits,
          ax::mojom::blink::Role::kDocEndnotes,
          ax::mojom::blink::Role::kDocEpilogue,
          ax::mojom::blink::Role::kDocErrata,
          ax::mojom::blink::Role::kDocForeword,
          ax::mojom::blink::Role::kDocGlossary,
          ax::mojom::blink::Role::kDocIntroduction,
          ax::mojom::blink::Role::kDocPart,
          ax::mojom::blink::Role::kDocPreface,
          ax::mojom::blink::Role::kDocPrologue,
          ax::mojom::blink::Role::kDocToc,
          ax::mojom::blink::Role::kEmphasis,
          ax::mojom::blink::Role::kFigcaption,
          ax::mojom::blink::Role::kFigure,
          ax::mojom::blink::Role::kFooter,
          ax::mojom::blink::Role::kForm,
          ax::mojom::blink::Role::kHeader,
          ax::mojom::blink::Role::kList,
          ax::mojom::blink::Role::kListItem,
          ax::mojom::blink::Role::kMain,
          ax::mojom::blink::Role::kMark,
          ax::mojom::blink::Role::kMath,
          ax::mojom::blink::Role::kMathMLMath,
          // Don't ignore MathML nodes by default, since MathML
          // relies on child positions to determine semantics
          // (e.g. numerator is the first child of a fraction).
          ax::mojom::blink::Role::kMathMLFraction,
          ax::mojom::blink::Role::kMathMLIdentifier,
          ax::mojom::blink::Role::kMathMLMultiscripts,
          ax::mojom::blink::Role::kMathMLNoneScript,
          ax::mojom::blink::Role::kMathMLNumber,
          ax::mojom::blink::Role::kMathMLOperator,
          ax::mojom::blink::Role::kMathMLOver,
          ax::mojom::blink::Role::kMathMLPrescriptDelimiter,
          ax::mojom::blink::Role::kMathMLRoot,
          ax::mojom::blink::Role::kMathMLRow,
          ax::mojom::blink::Role::kMathMLSquareRoot,
          ax::mojom::blink::Role::kMathMLStringLiteral,
          ax::mojom::blink::Role::kMathMLSub,
          ax::mojom::blink::Role::kMathMLSubSup,
          ax::mojom::blink::Role::kMathMLSup,
          ax::mojom::blink::Role::kMathMLTable,
          ax::mojom::blink::Role::kMathMLTableCell,
          ax::mojom::blink::Role::kMathMLTableRow,
          ax::mojom::blink::Role::kMathMLText,
          ax::mojom::blink::Role::kMathMLUnder,
          ax::mojom::blink::Role::kMathMLUnderOver,
          ax::mojom::blink::Role::kMeter,
          ax::mojom::blink::Role::kMenuListOption,
          ax::mojom::blink::Role::kMenuListPopup,
          ax::mojom::blink::Role::kNavigation,
          ax::mojom::blink::Role::kPluginObject,
          ax::mojom::blink::Role::kProgressIndicator,
          ax::mojom::blink::Role::kRegion,
          ax::mojom::blink::Role::kRuby,
          ax::mojom::blink::Role::kSearch,
          ax::mojom::blink::Role::kSection,
          ax::mojom::blink::Role::kSplitter,
          ax::mojom::blink::Role::kSubscript,
          ax::mojom::blink::Role::kSuperscript,
          ax::mojom::blink::Role::kStrong,
          ax::mojom::blink::Role::kTerm,
          ax::mojom::blink::Role::kTime,
          ax::mojom::blink::Role::kVideo,
      });

  if (base::Contains(always_included_computed_roles, RoleValue())) {
    return kIncludeObject;
  }

  // An <hgroup> element has the "group" aria role.
  if (GetNode()->HasTagName(html_names::kHgroupTag)) {
    return kIncludeObject;
  }

  // Using the title or accessibility description (so we
  // check if there's some kind of accessible name for the element)
  // to decide an element's visibility is not as definitive as
  // previous checks, so this should remain as one of the last.
  if (ElementHasAnyAriaAttribute() ||
      !GetElement()->FastGetAttribute(kTitleAttr).empty()) {
    return kIncludeObject;
  }

  if (IsImage() && !IsA<SVGElement>(node)) {
    String alt = GetElement()->FastGetAttribute(kAltAttr);
    // A null alt attribute means the attribute is not present. We assume this
    // is a mistake, and expose the image so that it can be repaired.
    // In contrast, alt="" is treated as intentional markup to ignore the image.
    if (!alt.empty() || alt.IsNull())
      return kIncludeObject;
    if (ignored_reasons)
      ignored_reasons->push_back(IgnoredReason(kAXEmptyAlt));
    return kIgnoreObject;
  }

  // Process potential in-page link targets
  if (IsPotentialInPageLinkTarget(*element))
    return kIncludeObject;

  if (AXObjectCache().GetAXMode().has_mode(ui::AXMode::kInlineTextBoxes)) {
    // We are including inline block elements since we might rely on these for
    // NextOnLine/PreviousOnLine computations.
    //
    // If we have an element with inline
    // block specified, we should include. There are some roles where we
    // shouldn't include even if inline block, or we'll get test failures.
    //
    // We also only want to include in the tree if the inline block element has
    // siblings.
    // Otherwise we will include nodes that we don't need for anything.
    // Consider a structure where we have a subtree of 12 layers, where each
    // layer has an inline-block node with a single child that points to the
    // next layer. All nodes have a single child, meaning that this child has no
    // siblings.
    if (!IsExemptFromInlineBlockCheck(native_role_) && GetLayoutObject() &&
        GetLayoutObject()->IsInline() &&
        GetLayoutObject()->IsAtomicInlineLevel() &&
        node->parentNode()->childElementCount() > 1) {
      return kIncludeObject;
    }
  }

  // Anything with non empty CSS alt should be included.
  // https://drafts.csswg.org/css-content/#alt
  // Descendants are pruned: IsRelevantPseudoElementDescendant() returns false.
  std::optional<String> alt_text = GetCSSAltText(GetElement());
  if (alt_text) {
    if (alt_text->empty()) {
      return kIgnoreObject;
    } else {
      return kIncludeObject;
    }
  }

  // <span> tags are inline tags and not meant to convey information if they
  // have no other ARIA information on them. If we don't ignore them, they may
  // emit signals expected to come from their parent.
  if (IsA<HTMLSpanElement>(node)) {
    if (ignored_reasons)
      ignored_reasons->push_back(IgnoredReason(kAXUninteresting));
    return kIgnoreObject;
  }

  // Ignore labels that are already used to name a control.
  // See IsRedundantLabel() for more commentary.
  if (HTMLLabelElement* label = DynamicTo<HTMLLabelElement>(node)) {
    if (IsRedundantLabel(label)) {
      if (ignored_reasons) {
        ignored_reasons->push_back(
            IgnoredReason(kAXLabelFor, AXObjectCache().Get(label->Control())));
      }
      return kIgnoreObject;
    }
    return kIncludeObject;
  }

  // The SVG-AAM says the foreignObject element is normally presentational.
  if (IsA<SVGForeignObjectElement>(node)) {
    if (ignored_reasons) {
      ignored_reasons->push_back(IgnoredReason(kAXPresentational));
    }
    return kIgnoreObject;
  }

  return kDefaultBehavior;
}

bool AXNodeObject::ComputeIsIgnored(
    IgnoredReasons* ignored_reasons) const {
  Node* node = GetNode();

  if (ShouldIgnoreForHiddenOrInert(ignored_reasons)) {
    if (IsAriaHidden()) {
      return true;
    }
    // Keep structure of <select size=1> even when collapsed.
    if (const AXObject* ax_menu_list = ParentObject()->AncestorMenuList()) {
      return ax_menu_list->IsIgnored();
    }

    // Fallback elements inside of a <canvas> are invisible, but are not ignored
    if (IsHiddenViaStyle() || !node || !node->parentElement() ||
        !node->parentElement()->IsInCanvasSubtree()) {
      return true;
    }
  }

  // Handle content that is either visible or in a canvas subtree.

  AXObjectInclusion include = ShouldIncludeBasedOnSemantics(ignored_reasons);
  if (include == kIncludeObject) {
    return false;
  }
  if (include == kIgnoreObject) {
    return true;
  }

  if (!GetLayoutObject()) {
    // Text without a layout object that has reached this point is not
    // explicitly hidden, e.g. is in a <canvas> fallback or is display locked.
    if (IsA<Text>(node)) {
      return false;
    }
    if (ignored_reasons) {
      ignored_reasons->push_back(IgnoredReason(kAXUninteresting));
    }
    return true;
  }

  // Inner editor element of editable area with empty text provides bounds
  // used to compute the character extent for index 0. This is the same as
  // what the caret's bounds would be if the editable area is focused.
  if (node) {
    const TextControlElement* text_control = EnclosingTextControl(node);
    if (text_control) {
      // Keep only the inner editor element and it's children.
      // If inline textboxes are being loaded, then the inline textbox for the
      // text wil be included by AXNodeObject::AddInlineTextboxChildren().
      // By only keeping the inner editor and its text, it makes finding the
      // inner editor simpler on the browser side.
      // See BrowserAccessibility::GetTextFieldInnerEditorElement().
      // TODO(accessibility) In the future, we may want to keep all descendants
      // of the inner text element -- right now we only include one internally
      // used container, it's text, and possibly the text's inlinext text box.
      return text_control->InnerEditorElement() != node &&
             text_control->InnerEditorElement() != NodeTraversal::Parent(*node);
    }
  }

  // A LayoutEmbeddedContent is an iframe element or embedded object element or
  // something like that. We don't want to ignore those.
  if (GetLayoutObject()->IsLayoutEmbeddedContent()) {
    return false;
  }

  if (node && node->IsInUserAgentShadowRoot()) {
    Element* host = node->OwnerShadowHost();
    if (auto* containing_media_element = DynamicTo<HTMLMediaElement>(host)) {
      if (!containing_media_element->ShouldShowControls()) {
        return true;
      }
    }
    if (IsA<HTMLOptGroupElement>(host)) {
      return false;
    }
  }

  if (IsCanvas()) {
    if (CanvasHasFallbackContent()) {
      return false;
    }

    // A 1x1 canvas is too small for the user to see and thus ignored.
    const auto* canvas = DynamicTo<LayoutHTMLCanvas>(GetLayoutObject());
    if (canvas && (canvas->Size().height <= 1 || canvas->Size().width <= 1)) {
      if (ignored_reasons) {
        ignored_reasons->push_back(IgnoredReason(kAXProbablyPresentational));
      }
      return true;
    }

    // Otherwise fall through; use presence of help text, title, or description
    // to decide.
  }

  if (GetLayoutObject()->IsBR()) {
    return false;
  }

  if (GetLayoutObject()->IsText()) {
    if (GetLayoutObject()->IsInListMarker()) {
      // Ignore TextAlternative of the list marker for SUMMARY because:
      //  - TextAlternatives for disclosure-* are triangle symbol characters
      //  used to visually indicate the expansion state.
      //  - It's redundant. The host DETAILS exposes the expansion state.
      // Also ignore text descendants of any non-ignored list marker because the
      // text descendants do not provide any extra information than the
      // TextAlternative on the list marker. Besides, with 'speak-as', they will
      // be inconsistent with the list marker.
      const AXObject* list_marker_object =
          ContainerListMarkerIncludingIgnored();
      if (list_marker_object &&
          (list_marker_object->GetLayoutObject()->IsListMarkerForSummary() ||
           !list_marker_object->IsIgnored())) {
        if (ignored_reasons) {
          ignored_reasons->push_back(IgnoredReason(kAXPresentational));
        }
        return true;
      }
    }

    // Ignore text inside of an ignored <label>.
    // To save processing, only walk up the ignored objects.
    // This means that other interesting objects inside the <label> will
    // cause the text to be unignored.
    if (IsUsedForLabelOrDescription()) {
      const AXObject* ancestor = ParentObject();
      while (ancestor && ancestor->IsIgnored()) {
        if (ancestor->RoleValue() == ax::mojom::blink::Role::kLabelText) {
          if (ignored_reasons) {
            ignored_reasons->push_back(IgnoredReason(kAXPresentational));
          }
          return true;
        }
        ancestor = ancestor->ParentObject();
      }
    }
    return false;
  }

  if (GetLayoutObject()->IsListMarker()) {
    // Ignore TextAlternative of the list marker for SUMMARY because:
    //  - TextAlternatives for disclosure-* are triangle symbol characters used
    //    to visually indicate the expansion state.
    //  - It's redundant. The host DETAILS exposes the expansion state.
    if (GetLayoutObject()->IsListMarkerForSummary()) {
      if (ignored_reasons) {
        ignored_reasons->push_back(IgnoredReason(kAXPresentational));
      }
      return true;
    }
    return false;
  }

  // Positioned elements and scrollable containers are important for determining
  // bounding boxes, so don't ignore them unless they are pseudo-content.
  if (!GetLayoutObject()->IsPseudoElement()) {
    if (IsScrollableContainer()) {
      return false;
    }
    if (GetLayoutObject()->IsPositioned()) {
      return false;
    }
  }

  // Ignore a block flow (display:block, display:inline-block), unless it
  // directly parents inline children.
  // This effectively trims a lot of uninteresting divs out of the tree.
  if (auto* block_flow = DynamicTo<LayoutBlockFlow>(GetLayoutObject())) {
    if (block_flow->ChildrenInline() && block_flow->FirstChild()) {
      return false;
    }
  }

  // By default, objects should be ignored so that the AX hierarchy is not
  // filled with unnecessary items.
  if (ignored_reasons) {
    ignored_reasons->push_back(IgnoredReason(kAXUninteresting));
  }
  return true;
}

// static
std::optional<String> AXNodeObject::GetCSSAltText(const Element* element) {
  // CSS alt text rules allow text to be assigned to ::before/::after content.
  // For example, the following CSS assigns "bullet" text to bullet.png:
  // .something::before {
  //   content: url(bullet.png) / "bullet";
  // }

  if (!element) {
    return std::nullopt;
  }
  const ComputedStyle* style = element->GetComputedStyle();
  if (!style || style->ContentBehavesAsNormal()) {
    return std::nullopt;
  }

  if (element->IsPseudoElement()) {
    for (const ContentData* content_data = style->GetContentData();
         content_data; content_data = content_data->Next()) {
      if (auto* css_alt = DynamicTo<AltTextContentData>(content_data)) {
        return css_alt->ConcatenateAltText();
      }
    }
    return std::nullopt;
  }

  // If the content property is used on a non-pseudo element, match the
  // behaviour of LayoutObject::CreateObject and only honour the style if
  // there is exactly one piece of content, which is an image.
  const ContentData* content_data = style->GetContentData();
  if (content_data && content_data->IsImage() && content_data->Next() &&
      content_data->Next()->IsAltText()) {
    return To<AltTextContentData>(content_data->Next())->ConcatenateAltText();
  }

  return std::nullopt;
}

// The following lists are for deciding whether the tags aside,
// header and footer can be interpreted as roles complementary, banner and
// contentInfo or if they should be interpreted as generic, sectionheader, or
// sectionfooter.
// This function only handles the complementary, banner, and contentInfo roles,
// which belong to the landmark roles set.
static HashSet<ax::mojom::blink::Role>& GetLandmarkIsNotAllowedAncestorRoles(
    ax::mojom::blink::Role landmark) {
  // clang-format off
  DEFINE_STATIC_LOCAL(
      // https://html.spec.whatwg.org/multipage/dom.html#sectioning-content-2
      // The aside element should not assume the complementary role when nested
      // within the following sectioning content elements.
      HashSet<ax::mojom::blink::Role>, complementary_is_not_allowed_roles,
      ({
        ax::mojom::blink::Role::kArticle,
        ax::mojom::blink::Role::kComplementary,
        ax::mojom::blink::Role::kNavigation,
        ax::mojom::blink::Role::kSection
      }));
      // https://w3c.github.io/html-aam/#el-header-ancestorbody
      // The header and footer elements should not assume the banner and
      // contentInfo roles, respectively, when nested within any of the
      // sectioning content elements or the main element.
  DEFINE_STATIC_LOCAL(
      HashSet<ax::mojom::blink::Role>, landmark_is_not_allowed_roles,
      ({
        ax::mojom::blink::Role::kArticle,
        ax::mojom::blink::Role::kComplementary,
        ax::mojom::blink::Role::kMain,
        ax::mojom::blink::Role::kNavigation,
        ax::mojom::blink::Role::kSection
      }));
  // clang-format on

  if (landmark == ax::mojom::blink::Role::kComplementary) {
    return complementary_is_not_allowed_roles;
  }
  return landmark_is_not_allowed_roles;
}

bool AXNodeObject::IsDescendantOfLandmarkDisallowedElement() const {
  if (!GetNode())
    return false;

  auto role_names = GetLandmarkIsNotAllowedAncestorRoles(RoleValue());

  for (AXObject* parent = ParentObjectUnignored(); parent;
       parent = parent->ParentObjectUnignored()) {
    if (role_names.Contains(parent->RoleValue())) {
      return true;
    }
  }
  return false;
}

static bool IsNonEmptyNonHeaderCell(const Node* cell) {
  return cell && cell->hasChildren() && cell->HasTagName(html_names::kTdTag);
}

static bool IsHeaderCell(const Node* cell) {
  return cell && cell->HasTagName(html_names::kThTag);
}

static ax::mojom::blink::Role DecideRoleFromSiblings(Element* cell) {
  // If this header is only cell in its row, it is a column header.
  // It is also a column header if it has a header on either side of it.
  // If instead it has a non-empty td element next to it, it is a row header.

  const Node* next_cell = LayoutTreeBuilderTraversal::NextSibling(*cell);
  const Node* previous_cell =
      LayoutTreeBuilderTraversal::PreviousSibling(*cell);
  if (!next_cell && !previous_cell)
    return ax::mojom::blink::Role::kColumnHeader;
  if (IsHeaderCell(next_cell) && IsHeaderCell(previous_cell))
    return ax::mojom::blink::Role::kColumnHeader;
  if (IsNonEmptyNonHeaderCell(next_cell) ||
      IsNonEmptyNonHeaderCell(previous_cell))
    return ax::mojom::blink::Role::kRowHeader;

  const auto* row = DynamicTo<HTMLTableRowElement>(cell->parentNode());
  if (!row)
    return ax::mojom::blink::Role::kColumnHeader;

  // If this row's first or last cell is a non-empty td, this is a row header.
  // Do the same check for the second and second-to-last cells because tables
  // often have an empty cell at the intersection of the row and column headers.
  const Element* first_cell = ElementTraversal::FirstChild(*row);
  DCHECK(first_cell);

  const Element* last_cell = ElementTraversal::LastChild(*row);
  DCHECK(last_cell);

  if (IsNonEmptyNonHeaderCell(first_cell) || IsNonEmptyNonHeaderCell(last_cell))
    return ax::mojom::blink::Role::kRowHeader;

  if (IsNonEmptyNonHeaderCell(ElementTraversal::NextSibling(*first_cell)) ||
      IsNonEmptyNonHeaderCell(ElementTraversal::PreviousSibling(*last_cell)))
    return ax::mojom::blink::Role::kRowHeader;

  // We have no evidence that this is not a column header.
  return ax::mojom::blink::Role::kColumnHeader;
}

ax::mojom::blink::Role AXNodeObject::DetermineTableSectionRole() const {
  if (!GetElement())
    return ax::mojom::blink::Role::kGenericContainer;

  AXObject* parent = GetDOMTableAXAncestor(GetNode(), AXObjectCache());
  if (!parent || !parent->IsTableLikeRole())
    return ax::mojom::blink::Role::kGenericContainer;

  if (parent->RoleValue() == ax::mojom::blink::Role::kLayoutTable)
    return ax::mojom::blink::Role::kGenericContainer;

  return ax::mojom::blink::Role::kRowGroup;
}

ax::mojom::blink::Role AXNodeObject::DetermineTableRowRole() const {
  AXObject* parent = GetDOMTableAXAncestor(GetNode(), AXObjectCache());

  if (!parent || !parent->IsTableLikeRole())
    return ax::mojom::blink::Role::kGenericContainer;

  if (parent->RoleValue() == ax::mojom::blink::Role::kLayoutTable)
    return ax::mojom::blink::Role::kLayoutTableRow;

  return ax::mojom::blink::Role::kRow;
}

ax::mojom::blink::Role AXNodeObject::DetermineTableCellRole() const {
  AXObject* parent = GetDOMTableAXAncestor(GetNode(), AXObjectCache());
  if (!parent || !parent->IsTableRowLikeRole())
    return ax::mojom::blink::Role::kGenericContainer;

  // Ensure table container.
  AXObject* grandparent =
      GetDOMTableAXAncestor(parent->GetNode(), AXObjectCache());
  if (!grandparent || !grandparent->IsTableLikeRole())
    return ax::mojom::blink::Role::kGenericContainer;

  if (parent->RoleValue() == ax::mojom::blink::Role::kLayoutTableRow)
    return ax::mojom::blink::Role::kLayoutTableCell;

  if (!GetElement() || !GetNode()->HasTagName(html_names::kThTag))
    return ax::mojom::blink::Role::kCell;

  const AtomicString& scope =
      GetElement()->FastGetAttribute(html_names::kScopeAttr);
  if (EqualIgnoringASCIICase(scope, "row") ||
      EqualIgnoringASCIICase(scope, "rowgroup"))
    return ax::mojom::blink::Role::kRowHeader;
  if (EqualIgnoringASCIICase(scope, "col") ||
      EqualIgnoringASCIICase(scope, "colgroup"))
    return ax::mojom::blink::Role::kColumnHeader;

  return DecideRoleFromSiblings(GetElement());
}

unsigned AXNodeObject::ColumnCount() const {
  if (RawAriaRole() != ax::mojom::blink::Role::kUnknown) {
    return AXObject::ColumnCount();
  }

  if (const auto* table = DynamicTo<LayoutTable>(GetLayoutObject())) {
    return table->EffectiveColumnCount();
  }

  return AXObject::ColumnCount();
}

unsigned AXNodeObject::RowCount() const {
  if (RawAriaRole() != ax::mojom::blink::Role::kUnknown) {
    return AXObject::RowCount();
  }

  LayoutTable* table;
  auto* table_section = FirstTableSection(GetLayoutObject(), &table);
  if (!table_section) {
    return AXObject::RowCount();
  }

  unsigned row_count = 0;
  while (table_section) {
    row_count += table_section->NumRows();
    table_section = table->NextSection(table_section);
  }
  return row_count;
}

unsigned AXNodeObject::ColumnIndex() const {
  auto* cell = DynamicTo<LayoutTableCell>(GetLayoutObject());
  if (cell && cell->GetNode()) {
    return cell->Table()->AbsoluteColumnToEffectiveColumn(
        cell->AbsoluteColumnIndex());
  }

  return AXObject::ColumnIndex();
}

unsigned AXNodeObject::RowIndex() const {
  LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object || !layout_object->GetNode()) {
    return AXObject::RowIndex();
  }

  unsigned row_index = 0;
  const LayoutTableSection* row_section = nullptr;
  const LayoutTable* table = nullptr;
  if (const auto* row = DynamicTo<LayoutTableRow>(layout_object)) {
    row_index = row->RowIndex();
    row_section = row->Section();
    table = row->Table();
  } else if (const auto* cell = DynamicTo<LayoutTableCell>(layout_object)) {
    row_index = cell->RowIndex();
    row_section = cell->Section();
    table = cell->Table();
  } else {
    return AXObject::RowIndex();
  }

  if (!table || !row_section) {
    return AXObject::RowIndex();
  }

  // Since our table might have multiple sections, we have to offset our row
  // appropriately.
  const LayoutTableSection* section = table->FirstSection();
  while (section && section != row_section) {
    row_index += section->NumRows();
    section = table->NextSection(section);
  }

  return row_index;
}

unsigned AXNodeObject::ColumnSpan() const {
  auto* cell = DynamicTo<LayoutTableCell>(GetLayoutObject());
  if (!cell) {
    return AXObject::ColumnSpan();
  }

  LayoutTable* table = cell->Table();
  unsigned absolute_first_col = cell->AbsoluteColumnIndex();
  unsigned absolute_last_col = absolute_first_col + cell->ColSpan() - 1;
  unsigned effective_first_col =
      table->AbsoluteColumnToEffectiveColumn(absolute_first_col);
  unsigned effective_last_col =
      table->AbsoluteColumnToEffectiveColumn(absolute_last_col);
  return effective_last_col - effective_first_col + 1;
}

unsigned AXNodeObject::RowSpan() const {
  auto* cell = DynamicTo<LayoutTableCell>(GetLayoutObject());
  return cell ? cell->ResolvedRowSpan() : AXObject::RowSpan();
}

ax::mojom::blink::SortDirection AXNodeObject::GetSortDirection() const {
  if (RoleValue() != ax::mojom::blink::Role::kRowHeader &&
      RoleValue() != ax::mojom::blink::Role::kColumnHeader) {
    return ax::mojom::blink::SortDirection::kNone;
  }

  if (const AtomicString& aria_sort =
          AriaTokenAttribute(html_names::kAriaSortAttr)) {
    if (EqualIgnoringASCIICase(aria_sort, "none")) {
      return ax::mojom::blink::SortDirection::kNone;
    }
    if (EqualIgnoringASCIICase(aria_sort, "ascending")) {
      return ax::mojom::blink::SortDirection::kAscending;
    }
    if (EqualIgnoringASCIICase(aria_sort, "descending")) {
      return ax::mojom::blink::SortDirection::kDescending;
    }
    // Technically, illegal values should be exposed as is, but this does
    // not seem to be worth the implementation effort at this time.
    return ax::mojom::blink::SortDirection::kOther;
  }
  return ax::mojom::blink::SortDirection::kNone;
}

AXObject* AXNodeObject::CellForColumnAndRow(unsigned target_column_index,
                                            unsigned target_row_index) const {
  LayoutTable* table;
  auto* table_section = FirstTableSection(GetLayoutObject(), &table);
  if (!table_section) {
    return AXObject::CellForColumnAndRow(target_column_index, target_row_index);
  }

  unsigned row_offset = 0;
  while (table_section) {
    // Iterate backwards through the rows in case the desired cell has a rowspan
    // and exists in a previous row.
    for (LayoutTableRow* row = table_section->LastRow(); row;
         row = row->PreviousRow()) {
      unsigned row_index = row->RowIndex() + row_offset;
      for (LayoutTableCell* cell = row->LastCell(); cell;
           cell = cell->PreviousCell()) {
        unsigned absolute_first_col = cell->AbsoluteColumnIndex();
        unsigned absolute_last_col = absolute_first_col + cell->ColSpan() - 1;
        unsigned effective_first_col =
            table->AbsoluteColumnToEffectiveColumn(absolute_first_col);
        unsigned effective_last_col =
            table->AbsoluteColumnToEffectiveColumn(absolute_last_col);
        unsigned row_span = cell->ResolvedRowSpan();
        if (target_column_index >= effective_first_col &&
            target_column_index <= effective_last_col &&
            target_row_index >= row_index &&
            target_row_index < row_index + row_span) {
          return AXObjectCache().Get(cell);
        }
      }
    }

    row_offset += table_section->NumRows();
    table_section = table->NextSection(table_section);
  }

  return nullptr;
}

bool AXNodeObject::FindAllTableCellsWithRole(ax::mojom::blink::Role role,
                                             AXObjectVector& cells) const {
  LayoutTable* table;
  auto* table_section = FirstTableSection(GetLayoutObject(), &table);
  if (!table_section) {
    return false;
  }

  while (table_section) {
    for (LayoutTableRow* row = table_section->FirstRow(); row;
         row = row->NextRow()) {
      for (LayoutTableCell* cell = row->FirstCell(); cell;
           cell = cell->NextCell()) {
        AXObject* ax_cell = AXObjectCache().Get(cell);
        if (ax_cell && ax_cell->RoleValue() == role) {
          cells.push_back(ax_cell);
        }
      }
    }

    table_section = table->NextSection(table_section);
  }

  return true;
}

void AXNodeObject::ColumnHeaders(AXObjectVector& headers) const {
  if (!FindAllTableCellsWithRole(ax::mojom::blink::Role::kColumnHeader,
                                 headers)) {
    AXObject::ColumnHeaders(headers);
  }
}

void AXNodeObject::RowHeaders(AXObjectVector& headers) const {
  if (!FindAllTableCellsWithRole(ax::mojom::blink::Role::kRowHeader, headers)) {
    AXObject::RowHeaders(headers);
  }
}

AXObject* AXNodeObject::HeaderObject() const {
  auto* row = DynamicTo<LayoutTableRow>(GetLayoutObject());
  if (!row) {
    return nullptr;
  }

  for (LayoutTableCell* cell = row->FirstCell(); cell;
       cell = cell->NextCell()) {
    AXObject* ax_cell = cell ? AXObjectCache().Get(cell) : nullptr;
    if (ax_cell && ax_cell->RoleValue() == ax::mojom::blink::Role::kRowHeader) {
      return ax_cell;
    }
  }

  return nullptr;
}

// The following is a heuristic used to determine if a
// <table> should be with ax::mojom::blink::Role::kTable or
// ax::mojom::blink::Role::kLayoutTable.
// Only "data" tables should be exposed as tables.
// Unfortunately, there is no determinsistic or precise way to differentiate a
// layout table vs a data table. Fortunately, CSS authoring techniques have
// improved a lot and mostly supplanted the practice of using tables for layout.
bool AXNodeObject::IsDataTable() const {
  DCHECK(!IsDetached());

  auto* table_element = DynamicTo<HTMLTableElement>(GetNode());
  if (!table_element) {
    return false;
  }

  if (!GetLayoutObject()) {
    // The table is not rendered, so the author has 
"""


```