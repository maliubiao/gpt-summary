Response:
The user wants to understand the functionality of the provided C++ code snippet from `ax_node_object.cc`. The snippet contains several methods related to accessibility properties of DOM nodes. I need to analyze each method and explain its purpose, relating it to HTML, CSS, and JavaScript concepts where applicable. I also need to provide examples, potential user errors, and debugging hints. Finally, I need to summarize the overall functionality of this code section.

**Plan:**

1. **Iterate through each method:**
   - Explain the core functionality.
   - Check for relationships with HTML attributes, CSS properties, and JavaScript APIs.
   - Provide examples of how these relationships manifest.
   - If there's logical deduction, create hypothetical input and output scenarios.
   - Identify common user or programming errors.
   - Outline how a user action could lead to this code being executed (debugging hints).
2. **Synthesize the information:**
   - Summarize the key functionalities of the code snippet.

**Specific Method Analysis (and related concepts):**

*   `WritingDirectionToAXWritingDirection`: Converts Blink's `WritingDirection` enum to an accessibility-specific `WritingDirection` enum. This relates to CSS's `direction` property and potentially HTML's `dir` attribute.
*   `GetTextPositionFromRole`: Determines the text position (subscript/superscript) based on the ARIA `role` attribute. This directly connects to HTML's `role` attribute and ARIA semantics.
*   `GetTextPosition`:  Determines text position based on both ARIA `role` and CSS's `vertical-align` property. This links to both HTML and CSS.
*   `GetTextStyleAndTextDecorationStyle`:  Extracts text styling information (bold, italic, underline, etc.) from CSS properties like `font-weight`, `font-style`, and `text-decoration`. This is heavily reliant on CSS.
*   `GetTextAlign`:  Retrieves the text alignment from CSS's `text-align` property. Direct CSS relationship.
*   `GetTextIndent`:  Gets the text indentation from CSS's `text-indent` property. Direct CSS relationship.
*   `ImageDataUrl`: Converts image, canvas, or video elements into data URLs, potentially resizing them. This relates to HTML's `<img>`, `<canvas>`, and `<video>` tags and their content, as well as JavaScript APIs for manipulating these elements.
*   `AccessKey`:  Retrieves the value of the HTML `accesskey` attribute. Direct HTML relationship.
*   `ColorValue`:  Gets the color value from an `<input type="color">` element. Relates to HTML's `<input>` tag and its `value` attribute.
*   `BackgroundColor`:  Retrieves the background color of an element, considering both CSS and document-level settings. Direct CSS relationship, and some document-level logic.
*   `GetColor`:  Gets the text color of an element from CSS's `color` property. Direct CSS relationship.
*   `ComputedFontFamily`:  Gets the computed font family name from CSS. Direct CSS relationship.
*   `FontFamilyForSerialization`:  Similar to `ComputedFontFamily`, but retrieves the platform-specific font family name, primarily for serialization purposes. Direct CSS relationship.
*   `FontSize`: Gets the font size from CSS. Direct CSS relationship.
*   `FontWeight`: Gets the font weight from CSS. Direct CSS relationship.
*   `GetAriaCurrentState`:  Retrieves the value of the ARIA `aria-current` attribute. Direct ARIA/HTML relationship.
*   `GetInvalidState`:  Determines the invalid state of a form control based on ARIA's `aria-invalid` attribute and native form validation. Links to both HTML (form elements) and ARIA.
*   `IsValidFormControl`: Helper function to determine if a form control is valid. Directly relates to HTML form elements and their validation mechanisms.
*   `PosInSet`: Gets the position of an element within a set, using ARIA's `aria-posinset` or the selected index of a `<select>` element. Links to HTML and ARIA.
*   `SetSize`: Gets the size of a set, using ARIA's `aria-setsize` or the number of options in a `<select>` element. Links to HTML and ARIA.
*   `ValueForRange`: Gets the current value for range-like elements (sliders, progress bars) using ARIA's `aria-valuenow` or the element's native value. Links to HTML and ARIA.
*   `MaxValueForRange`: Gets the maximum value for range-like elements using ARIA's `aria-valuemax` or the element's native maximum. Links to HTML and ARIA.
*   `MinValueForRange`: Gets the minimum value for range-like elements using ARIA's `aria-valuemin` or the element's native minimum. Links to HTML and ARIA.
*   `StepValueForRange`: Gets the step value for range-like elements. Links to HTML and ARIA.
*   `Url`:  Retrieves the URL of a link, image, or the current document. Links to various HTML elements and document context.
*   `ChooserPopup`:  Identifies associated popup elements for certain input types (color, date). Links to HTML input elements and their associated UI.
*   `GetValueForControl`: Gets the accessible value of a form control, handling different input types and ARIA attributes. Core function related to HTML form elements and ARIA.
*   `SlowGetValueForControlIncludingContentEditable`: Gets the value for editable content, including `contenteditable` elements. Links to HTML's `contenteditable` attribute.
*   `RawAriaRole`: Returns the raw ARIA role. Direct ARIA/HTML relationship.
*   `HasPopup`:  Determines if an element has a popup associated with it, using ARIA's `aria-haspopup`. Direct ARIA/HTML relationship.
*   `IsPopup`:  Determines if the current element is a popup. Links to HTML and potentially the Popover API.
*   `IsEditableRoot`: Determines if an element is an editable root due to the `contenteditable` attribute. Direct HTML relationship.
*   `HasContentEditableAttributeSet`: Checks if the `contenteditable` attribute is set. Direct HTML relationship.

By following this detailed analysis, I can generate a comprehensive and accurate answer to the user's request.
这是 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件的第五部分，主要包含 `AXNodeObject` 类中与文本属性、颜色、字体、ARIA 属性以及表单控件值相关的各种方法。 它的主要功能是**提供关于 DOM 节点对象的辅助功能属性信息**，这些信息将被辅助技术（例如屏幕阅读器）使用，以便用户更好地理解和操作网页内容。

以下是该部分代码功能的详细列举和说明：

**核心功能归纳：**

*   **获取和转换文本方向:**  `WritingDirectionToAXWritingDirection` 将 Blink 内部的文本方向枚举转换为辅助功能 API 使用的枚举。
*   **确定文本位置 (上标/下标):** `GetTextPositionFromRole` 和 `GetTextPosition`  根据元素的 ARIA 角色 (`role="subscript"` 或 `role="superscript"`) 或 CSS 的 `vertical-align` 属性来判断文本是否为上标或下标。
*   **提取文本样式和装饰:** `GetTextStyleAndTextDecorationStyle` 从 CSS 属性中提取文本的样式信息（粗体、斜体、删除线、下划线、上划线）和装饰样式。
*   **获取文本对齐方式:** `GetTextAlign`  从 CSS 的 `text-align` 属性中获取文本的对齐方式。
*   **获取文本缩进:** `GetTextIndent` 从 CSS 的 `text-indent` 属性中获取文本的缩进值。
*   **生成图像数据的 Data URL:** `ImageDataUrl` 将 `<img>`、`<canvas>` 或 `<video>` 元素的内容转换为 Data URL 格式的字符串，可以用于在辅助功能 API 中表示图像数据。
*   **获取访问键:** `AccessKey` 获取 HTML 元素的 `accesskey` 属性值。
*   **获取颜色值:** `ColorValue`  专门针对 `<input type="color">` 元素获取其颜色值。
*   **获取背景颜色:** `BackgroundColor` 获取元素的背景颜色，考虑了 CSS 样式和文档的默认背景色。
*   **获取文本颜色:** `GetColor` 获取元素的文本颜色，来源于 CSS 的 `color` 属性。
*   **获取计算后的字体系列:** `ComputedFontFamily` 获取元素计算后的字体系列名称。
*   **获取用于序列化的字体系列:** `FontFamilyForSerialization` 获取用于序列化的字体系列名称，可能与平台相关。
*   **获取字体大小:** `FontSize` 获取元素的字体大小，单位为像素。
*   **获取字体粗细:** `FontWeight` 获取元素的字体粗细值。
*   **获取 ARIA current 状态:** `GetAriaCurrentState` 获取 ARIA `aria-current` 属性的值。
*   **获取 invalid 状态:** `GetInvalidState`  判断表单控件的验证状态，考虑了 ARIA `aria-invalid` 属性和原生表单验证。
*   **判断表单控件是否有效:** `IsValidFormControl` 是一个辅助函数，用于判断给定的表单控件是否有效。
*   **获取在集合中的位置:** `PosInSet`  获取元素在集合中的位置，主要用于列表和组合框等结构，考虑了 ARIA `aria-posinset` 属性。
*   **获取集合大小:** `SetSize` 获取集合的大小，主要用于列表和组合框等结构，考虑了 ARIA `aria-setsize` 属性。
*   **获取范围控件的当前值:** `ValueForRange` 获取像滑块或进度条这样的范围控件的当前值，考虑了 ARIA `aria-valuenow` 属性。
*   **获取范围控件的最大值:** `MaxValueForRange` 获取范围控件的最大值，考虑了 ARIA `aria-valuemax` 属性。
*   **获取范围控件的最小值:** `MinValueForRange` 获取范围控件的最小值，考虑了 ARIA `aria-valuemin` 属性。
*   **获取范围控件的步进值:** `StepValueForRange` 获取范围控件的步进值，用于辅助技术进行值的调整。
*   **获取 URL:** `Url` 获取元素的 URL，例如链接的 href，图片的 src 等。
*   **获取选择器弹出窗口:** `ChooserPopup`  查找与某些输入控件（例如颜色选择器、日期选择器）关联的弹出窗口。
*   **获取控件的值:** `GetValueForControl` 获取表单控件的可访问值，根据控件类型进行不同的处理，例如文本框、下拉列表等。
*   **缓慢获取控件的值（包含 contenteditable）:** `SlowGetValueForControlIncludingContentEditable`  用于获取包含 `contenteditable` 属性的元素的值。
*   **获取原始 ARIA 角色:** `RawAriaRole` 获取元素的原始 ARIA 角色。
*   **判断是否有弹出窗口:** `HasPopup`  判断元素是否关联有弹出窗口，考虑了 ARIA `aria-haspopup` 属性。
*   **判断是否为弹出窗口:** `IsPopup` 判断当前元素是否为一个弹出窗口。
*   **判断是否为可编辑根元素:** `IsEditableRoot`  判断元素是否是可编辑的根元素，由 `contenteditable` 属性决定。
*   **判断是否设置了 contenteditable 属性:** `HasContentEditableAttributeSet` 判断元素是否设置了 `contenteditable` 属性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**
    *   **`AccessKey()`:** 与 HTML 的 `accesskey` 属性直接相关。例如，`<button accesskey="s">Save</button>`。
    *   **`ColorValue()`:**  与 `<input type="color">` 元素及其 `value` 属性相关。例如，`<input type="color" value="#ff0000">`。
    *   **`Url()`:** 与 `<a>`, `<img>`, `<link>` 等元素的 `href`, `src` 属性相关。例如，`<a href="https://example.com">Link</a>`，`<img src="image.png">`。
    *   **`GetAriaCurrentState()`, `GetInvalidState()`, `PosInSet()`, `SetSize()`, `ValueForRange()`, `MaxValueForRange()`, `MinValueForRange()`, `HasPopup()`:**  都直接读取 HTML 元素的 ARIA 属性，例如 `<div aria-current="page">Current Page</div>`，`<input type="text" aria-invalid="true">`。
    *   **`GetValueForControl()`:**  会根据不同的 HTML 元素类型（`<input>`, `<textarea>`, `<select>`) 获取其对应的可访问值。
    *   **`IsEditableRoot()`, `HasContentEditableAttributeSet()`:** 与 HTML 的 `contenteditable` 属性直接相关。例如，`<div contenteditable="true">Edit me</div>`。

*   **CSS:**
    *   **`WritingDirectionToAXWritingDirection()`:** 与 CSS 的 `direction` 属性相关。例如，`body { direction: rtl; }`。
    *   **`GetTextPosition()`:** 与 CSS 的 `vertical-align` 属性相关。例如，`sup { vertical-align: super; }`。
    *   **`GetTextStyleAndTextDecorationStyle()`:** 与 CSS 的 `font-weight`, `font-style`, `text-decoration-line`, `text-decoration-style` 等属性相关。例如，`strong { font-weight: bold; }`, `u { text-decoration: underline dotted red; }`。
    *   **`GetTextAlign()`:** 与 CSS 的 `text-align` 属性相关。例如，`p { text-align: center; }`。
    *   **`GetTextIndent()`:** 与 CSS 的 `text-indent` 属性相关。例如，`p { text-indent: 2em; }`。
    *   **`BackgroundColor()`:** 与 CSS 的 `background-color` 属性相关。例如，`.element { background-color: blue; }`。
    *   **`GetColor()`:** 与 CSS 的 `color` 属性相关。例如，`p { color: green; }`。
    *   **`ComputedFontFamily()`:** 与 CSS 的 `font-family` 属性相关。例如，`body { font-family: Arial, sans-serif; }`。
    *   **`FontSize()`:** 与 CSS 的 `font-size` 属性相关。例如，`h1 { font-size: 2em; }`。
    *   **`FontWeight()`:** 与 CSS 的 `font-weight` 属性相关。例如，`.bold-text { font-weight: 700; }`。

*   **JavaScript:**
    *   **`ImageDataUrl()`:** 虽然本身是 C++ 代码，但它处理的 HTML 元素 (`<img>`, `<canvas>`, `<video>`) 的内容可能由 JavaScript 动态生成或修改。例如，使用 JavaScript 在 `<canvas>` 上绘制图像，然后此方法会将其转换为 Data URL。
    *   **表单控件的值:** JavaScript 可以通过 `element.value` 等属性获取和设置表单控件的值，这些值最终会被 `GetValueForControl()` 等方法读取。
    *   **动态修改 ARIA 属性:** JavaScript 可以使用 `element.setAttribute('aria-label', 'New Label')` 等方法动态修改元素的 ARIA 属性，这些修改会影响 `GetAriaCurrentState()` 等方法的返回值.
    *   **`contenteditable` 的动态控制:** JavaScript 可以动态设置元素的 `contenteditable` 属性。

**逻辑推理 (假设输入与输出):**

*   **假设输入 (对于 `GetTextPosition()`):**
    *   一个 `<span>` 元素： `<span style="vertical-align: sub;">text</span>`
    *   对应的 `AXNodeObject` 实例。
*   **输出:** `ax::mojom::blink::TextPosition::kSubscript`

*   **假设输入 (对于 `GetTextStyleAndTextDecorationStyle()`):**
    *   一个 `<strong>` 元素： `<strong style="text-decoration: underline wavy red;">Important</strong>`
    *   对应的 `AXNodeObject` 实例。
    *   `text_style` 指针
    *   `text_overline_style` 指针
    *   `text_strikethrough_style` 指针
    *   `text_underline_style` 指针
*   **输出:**
    *   `*text_style` 将包含 `ax::mojom::blink::TextStyle::kBold | ax::mojom::blink::TextStyle::kUnderline` 的标志。
    *   `*text_overline_style` 将为 `ax::mojom::blink::TextDecorationStyle::kNone`。
    *   `*text_strikethrough_style` 将为 `ax::mojom::blink::TextDecorationStyle::kNone`。
    *   `*text_underline_style` 将为 `ax::mojom::blink::TextDecorationStyle::kWavy`。

*   **假设输入 (对于 `ValueForRange()`):**
    *   一个 `<input type="range" min="0" max="100" value="50" aria-valuenow="70">` 元素。
    *   对应的 `AXNodeObject` 实例。
    *   `out_value` 指针。
*   **输出:**
    *   `*out_value` 将为 `70.0f` (因为 `aria-valuenow` 属性存在并覆盖了原生 `value` 属性)。

**用户或编程常见的使用错误举例说明:**

*   **ARIA 属性值错误:** 用户可能在 HTML 中设置了无效的 ARIA 属性值，例如 `<div aria-invalid="maybe"></div>`，这会导致 `GetInvalidState()` 等方法返回非预期的结果。
*   **CSS 属性覆盖:**  用户可能在 CSS 中意外地覆盖了某些样式，导致辅助功能 API 获取到的信息不准确。例如，设置了 `strong { font-weight: normal; }`，导致 `GetTextStyleAndTextDecorationStyle()` 认为 `<strong>` 元素不是粗体。
*   **JavaScript 动态修改后未更新辅助功能树:**  如果 JavaScript 动态修改了 DOM 结构或属性，但辅助功能树没有及时更新，那么这些方法返回的信息可能过时。
*   **使用了错误的 HTML 语义:** 使用了不合适的 HTML 标签可能会导致辅助功能 API 误判元素的角色和属性。例如，使用 `<div>` 模拟按钮而不是使用 `<button>`。
*   **误解 ARIA 属性的优先级:**  开发者可能不清楚 ARIA 属性与原生 HTML 属性和 CSS 样式的优先级关系，导致辅助功能信息不准确。例如，错误地认为设置了 CSS 样式就能完全覆盖 ARIA 属性的影响。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与网页交互:** 用户通过鼠标、键盘或其他输入设备与网页进行交互。例如，点击一个按钮，填写一个表单，或者滚动页面。
2. **浏览器事件触发:** 用户的交互会触发相应的浏览器事件（例如 `click`, `focus`, `input`, `scroll`）。
3. **渲染引擎处理事件:**  Blink 渲染引擎接收到这些事件，并根据事件类型和目标元素执行相应的操作。
4. **辅助功能树更新:** 当 DOM 结构或样式发生变化时，Blink 的辅助功能模块会更新辅助功能树 (Accessibility Tree)。
5. **辅助功能 API 调用:** 操作系统或辅助技术（例如屏幕阅读器）会通过辅助功能 API (例如 MSAA/UIA on Windows, AXMac on macOS, AT-SPI on Linux) 查询辅助功能树中的节点信息。
6. **`AXNodeObject` 方法调用:** 当辅助技术需要获取特定元素的属性信息时，例如文本内容、角色、状态等，就会调用 `AXNodeObject` 类中相应的方法，例如 `GetValueForControl()`, `GetRole()`, `GetState()` 等。该部分代码中的方法就是在这一步被调用的。

**调试线索:**

*   **检查 HTML 结构和属性:**  确认 HTML 元素是否使用了正确的语义标签和 ARIA 属性，并且属性值是否正确。
*   **检查 CSS 样式:**  确认 CSS 样式是否按预期生效，并且没有意外的覆盖。
*   **使用浏览器的辅助功能检查工具:**  Chrome DevTools 的 "Accessibility" 面板可以帮助开发者查看辅助功能树的结构和元素的属性，从而定位问题。
*   **使用屏幕阅读器等辅助技术进行测试:**  实际使用辅助技术来体验网页，可以发现潜在的辅助功能问题。
*   **断点调试:** 在 `AXNodeObject` 的相关方法中设置断点，可以跟踪代码执行流程，查看变量的值，从而理解信息的来源和处理过程。

**总结该部分的功能:**

该部分代码的核心功能是**为 Blink 渲染引擎中的 `AXNodeObject` 类提供获取各种可访问性相关属性的方法**。这些方法从 HTML 结构、ARIA 属性和 CSS 样式中提取信息，并将其转换为辅助功能 API 可以理解的格式。这使得辅助技术能够理解网页的内容和结构，并将其呈现给有视觉障碍或其他障碍的用户。 简而言之，这部分代码是浏览器将网页信息“翻译”成辅助技术可以理解的语言的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能

"""
m::blink::WritingDirection::kLtr;
    case PhysicalDirection::kLeft:
      return ax::mojom::blink::WritingDirection::kRtl;
    case PhysicalDirection::kDown:
      return ax::mojom::blink::WritingDirection::kTtb;
    case PhysicalDirection::kUp:
      return ax::mojom::blink::WritingDirection::kBtt;
  }

  NOTREACHED();
}

ax::mojom::blink::TextPosition AXNodeObject::GetTextPositionFromRole() const {
  // Check for role="subscript" or role="superscript" on the element, or if
  // static text, on the containing element.
  AXObject* obj = nullptr;
  if (RoleValue() == ax::mojom::blink::Role::kStaticText)
    obj = ParentObject();
  else
    obj = const_cast<AXNodeObject*>(this);

  if (obj->RoleValue() == ax::mojom::blink::Role::kSubscript)
    return ax::mojom::blink::TextPosition::kSubscript;
  if (obj->RoleValue() == ax::mojom::blink::Role::kSuperscript)
    return ax::mojom::blink::TextPosition::kSuperscript;

  if (!GetLayoutObject() || !GetLayoutObject()->IsInline())
    return ax::mojom::blink::TextPosition::kNone;

  // We could have an inline element which descends from a subscript or
  // superscript.
  if (auto* parent = obj->ParentObjectUnignored())
    return static_cast<AXNodeObject*>(parent)->GetTextPositionFromRole();

  return ax::mojom::blink::TextPosition::kNone;
}

ax::mojom::blink::TextPosition AXNodeObject::GetTextPosition() const {
  if (GetNode()) {
    const auto& text_position = GetTextPositionFromRole();
    if (text_position != ax::mojom::blink::TextPosition::kNone)
      return text_position;
  }

  if (!GetLayoutObject())
    return AXObject::GetTextPosition();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::GetTextPosition();

  switch (style->VerticalAlign()) {
    case EVerticalAlign::kBaseline:
    case EVerticalAlign::kMiddle:
    case EVerticalAlign::kTextTop:
    case EVerticalAlign::kTextBottom:
    case EVerticalAlign::kTop:
    case EVerticalAlign::kBottom:
    case EVerticalAlign::kBaselineMiddle:
    case EVerticalAlign::kLength:
      return AXObject::GetTextPosition();
    case EVerticalAlign::kSub:
      return ax::mojom::blink::TextPosition::kSubscript;
    case EVerticalAlign::kSuper:
      return ax::mojom::blink::TextPosition::kSuperscript;
  }
}

void AXNodeObject::GetTextStyleAndTextDecorationStyle(
    int32_t* text_style,
    ax::mojom::blink::TextDecorationStyle* text_overline_style,
    ax::mojom::blink::TextDecorationStyle* text_strikethrough_style,
    ax::mojom::blink::TextDecorationStyle* text_underline_style) const {
  if (!GetLayoutObject()) {
    AXObject::GetTextStyleAndTextDecorationStyle(
        text_style, text_overline_style, text_strikethrough_style,
        text_underline_style);
    return;
  }
  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style) {
    AXObject::GetTextStyleAndTextDecorationStyle(
        text_style, text_overline_style, text_strikethrough_style,
        text_underline_style);
    return;
  }

  *text_style = 0;
  *text_overline_style = ax::mojom::blink::TextDecorationStyle::kNone;
  *text_strikethrough_style = ax::mojom::blink::TextDecorationStyle::kNone;
  *text_underline_style = ax::mojom::blink::TextDecorationStyle::kNone;

  if (style->GetFontWeight() == kBoldWeightValue) {
    *text_style |= TextStyleFlag(ax::mojom::blink::TextStyle::kBold);
  }
  if (style->GetFontDescription().Style() == kItalicSlopeValue) {
    *text_style |= TextStyleFlag(ax::mojom::blink::TextStyle::kItalic);
  }

  for (const auto& decoration : style->AppliedTextDecorations()) {
    if (EnumHasFlags(decoration.Lines(), TextDecorationLine::kOverline)) {
      *text_style |= TextStyleFlag(ax::mojom::blink::TextStyle::kOverline);
      *text_overline_style =
          TextDecorationStyleToAXTextDecorationStyle(decoration.Style());
    }
    if (EnumHasFlags(decoration.Lines(), TextDecorationLine::kLineThrough)) {
      *text_style |= TextStyleFlag(ax::mojom::blink::TextStyle::kLineThrough);
      *text_strikethrough_style =
          TextDecorationStyleToAXTextDecorationStyle(decoration.Style());
    }
    if (EnumHasFlags(decoration.Lines(), TextDecorationLine::kUnderline)) {
      *text_style |= TextStyleFlag(ax::mojom::blink::TextStyle::kUnderline);
      *text_underline_style =
          TextDecorationStyleToAXTextDecorationStyle(decoration.Style());
    }
  }
}

ax::mojom::blink::TextAlign AXNodeObject::GetTextAlign() const {
  // Object attributes are not applied to text objects.
  if (IsTextObject() || !GetLayoutObject())
    return ax::mojom::blink::TextAlign::kNone;

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return ax::mojom::blink::TextAlign::kNone;

  switch (style->GetTextAlign()) {
    case ETextAlign::kLeft:
    case ETextAlign::kWebkitLeft:
    case ETextAlign::kStart:
      return ax::mojom::blink::TextAlign::kLeft;
    case ETextAlign::kRight:
    case ETextAlign::kWebkitRight:
    case ETextAlign::kEnd:
      return ax::mojom::blink::TextAlign::kRight;
    case ETextAlign::kCenter:
    case ETextAlign::kWebkitCenter:
      return ax::mojom::blink::TextAlign::kCenter;
    case ETextAlign::kJustify:
      return ax::mojom::blink::TextAlign::kJustify;
  }
}

float AXNodeObject::GetTextIndent() const {
  // Text-indent applies to lines or blocks, but not text.
  if (IsTextObject() || !GetLayoutObject())
    return 0.0f;
  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return 0.0f;

  const blink::LayoutBlock* layout_block =
      GetLayoutObject()->InclusiveContainingBlock();
  if (!layout_block)
    return 0.0f;
  float text_indent = layout_block->TextIndentOffset().ToFloat();
  return text_indent / kCssPixelsPerMillimeter;
}

String AXNodeObject::ImageDataUrl(const gfx::Size& max_size) const {
  Node* node = GetNode();
  if (!node)
    return String();

  ImageBitmapOptions* options = ImageBitmapOptions::Create();
  ImageBitmap* image_bitmap = nullptr;
  if (auto* image = DynamicTo<HTMLImageElement>(node)) {
    image_bitmap =
        MakeGarbageCollected<ImageBitmap>(image, std::nullopt, options);
  } else if (auto* canvas = DynamicTo<HTMLCanvasElement>(node)) {
    image_bitmap =
        MakeGarbageCollected<ImageBitmap>(canvas, std::nullopt, options);
  } else if (auto* video = DynamicTo<HTMLVideoElement>(node)) {
    image_bitmap =
        MakeGarbageCollected<ImageBitmap>(video, std::nullopt, options);
  }
  if (!image_bitmap)
    return String();

  scoped_refptr<StaticBitmapImage> bitmap_image = image_bitmap->BitmapImage();
  if (!bitmap_image)
    return String();

  sk_sp<SkImage> image =
      bitmap_image->PaintImageForCurrentFrame().GetSwSkImage();
  if (!image || image->width() <= 0 || image->height() <= 0)
    return String();

  // Determine the width and height of the output image, using a proportional
  // scale factor such that it's no larger than |maxSize|, if |maxSize| is not
  // empty. It only resizes the image to be smaller (if necessary), not
  // larger.
  float x_scale =
      max_size.width() ? max_size.width() * 1.0 / image->width() : 1.0;
  float y_scale =
      max_size.height() ? max_size.height() * 1.0 / image->height() : 1.0;
  float scale = std::min(x_scale, y_scale);
  if (scale >= 1.0)
    scale = 1.0;
  int width = std::round(image->width() * scale);
  int height = std::round(image->height() * scale);

  // Draw the image into a bitmap in native format.
  SkBitmap bitmap;
  SkPixmap unscaled_pixmap;
  if (scale == 1.0 && image->peekPixels(&unscaled_pixmap)) {
    bitmap.installPixels(unscaled_pixmap);
  } else {
    bitmap.allocPixels(
        SkImageInfo::MakeN32(width, height, kPremul_SkAlphaType));
    SkCanvas canvas(bitmap, SkSurfaceProps{});
    canvas.clear(SK_ColorTRANSPARENT);
    canvas.drawImageRect(image, SkRect::MakeIWH(width, height),
                         SkSamplingOptions());
  }

  // Copy the bits into a buffer in RGBA_8888 unpremultiplied format
  // for encoding.
  SkImageInfo info = SkImageInfo::Make(width, height, kRGBA_8888_SkColorType,
                                       kUnpremul_SkAlphaType);
  size_t row_bytes = info.minRowBytes();
  Vector<char> pixel_storage(
      base::checked_cast<wtf_size_t>(info.computeByteSize(row_bytes)));
  SkPixmap pixmap(info, pixel_storage.data(), row_bytes);
  if (!SkImages::RasterFromBitmap(bitmap)->readPixels(pixmap, 0, 0)) {
    return String();
  }

  // Encode as a PNG and return as a data url.
  std::unique_ptr<ImageDataBuffer> buffer = ImageDataBuffer::Create(pixmap);

  if (!buffer)
    return String();

  return buffer->ToDataURL(kMimeTypePng, 1.0);
}

const AtomicString& AXNodeObject::AccessKey() const {
  auto* element = DynamicTo<Element>(GetNode());
  if (!element)
    return g_null_atom;
  return element->FastGetAttribute(html_names::kAccesskeyAttr);
}

RGBA32 AXNodeObject::ColorValue() const {
  auto* input = DynamicTo<HTMLInputElement>(GetNode());
  if (!input || !IsColorWell())
    return AXObject::ColorValue();

  const AtomicString& type = input->getAttribute(kTypeAttr);
  if (!EqualIgnoringASCIICase(type, "color"))
    return AXObject::ColorValue();

  // HTMLInputElement::Value always returns a string parseable by Color.
  Color color;
  bool success = color.SetFromString(input->Value());
  DCHECK(success);
  return color.Rgb();
}

RGBA32 AXNodeObject::BackgroundColor() const {
  LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object)
    return Color::kTransparent.Rgb();

  if (IsA<Document>(GetNode())) {
    LocalFrameView* view = DocumentFrameView();
    if (view)
      return view->BaseBackgroundColor().Rgb();
    else
      return Color::kWhite.Rgb();
  }

  const ComputedStyle* style = layout_object->Style();
  if (!style || !style->HasBackground())
    return Color::kTransparent.Rgb();

  return style->VisitedDependentColor(GetCSSPropertyBackgroundColor()).Rgb();
}

RGBA32 AXNodeObject::GetColor() const {
  if (!GetLayoutObject() || IsColorWell())
    return AXObject::GetColor();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::GetColor();

  Color color = style->VisitedDependentColor(GetCSSPropertyColor());
  return color.Rgb();
}

const AtomicString& AXNodeObject::ComputedFontFamily() const {
  if (!GetLayoutObject())
    return AXObject::ComputedFontFamily();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::ComputedFontFamily();

  const FontDescription& font_description = style->GetFontDescription();
  return font_description.FirstFamily().FamilyName();
}

String AXNodeObject::FontFamilyForSerialization() const {
  if (!GetLayoutObject())
    return AXObject::FontFamilyForSerialization();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::FontFamilyForSerialization();

  const SimpleFontData* primary_font = style->GetFont().PrimaryFont();
  if (!primary_font)
    return AXObject::FontFamilyForSerialization();

  // Note that repeatedly querying this can be expensive - only use this when
  // serializing. For other comparisons consider using `ComputedFontFamily`.
  return primary_font->PlatformData().FontFamilyName();
}

// Blink font size is provided in pixels.
// Platform APIs may convert to another unit (IA2 converts to points).
float AXNodeObject::FontSize() const {
  if (!GetLayoutObject())
    return AXObject::FontSize();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::FontSize();

  // Font size should not be affected by scale transform or page zoom, because
  // users of authoring tools may want to check that their text is formatted
  // with the font size they expected.
  // E.g. use SpecifiedFontSize() instead of ComputedFontSize(), and do not
  // multiply by style->Scale()->Transform()->Y();
  return style->SpecifiedFontSize();
}

float AXNodeObject::FontWeight() const {
  if (!GetLayoutObject())
    return AXObject::FontWeight();

  const ComputedStyle* style = GetLayoutObject()->Style();
  if (!style)
    return AXObject::FontWeight();

  return style->GetFontWeight();
}

ax::mojom::blink::AriaCurrentState AXNodeObject::GetAriaCurrentState() const {
  const AtomicString& attribute_value =
      AriaTokenAttribute(html_names::kAriaCurrentAttr);
  if (attribute_value.IsNull()) {
    return ax::mojom::blink::AriaCurrentState::kNone;
  }
  if (EqualIgnoringASCIICase(attribute_value, "false")) {
    return ax::mojom::blink::AriaCurrentState::kFalse;
  }
  if (EqualIgnoringASCIICase(attribute_value, "page")) {
    return ax::mojom::blink::AriaCurrentState::kPage;
  }
  if (EqualIgnoringASCIICase(attribute_value, "step")) {
    return ax::mojom::blink::AriaCurrentState::kStep;
  }
  if (EqualIgnoringASCIICase(attribute_value, "location")) {
    return ax::mojom::blink::AriaCurrentState::kLocation;
  }
  if (EqualIgnoringASCIICase(attribute_value, "date")) {
    return ax::mojom::blink::AriaCurrentState::kDate;
  }
  if (EqualIgnoringASCIICase(attribute_value, "time")) {
    return ax::mojom::blink::AriaCurrentState::kTime;
  }

  // An unknown value should return true.
  return ax::mojom::blink::AriaCurrentState::kTrue;
}

ax::mojom::blink::InvalidState AXNodeObject::GetInvalidState() const {
  // First check aria-invalid.
  if (const AtomicString& attribute_value =
          AriaTokenAttribute(html_names::kAriaInvalidAttr)) {
    // aria-invalid="false".
    if (EqualIgnoringASCIICase(attribute_value, "false")) {
      return ax::mojom::blink::InvalidState::kFalse;
    }
    // In most cases, aria-invalid="spelling"| "grammar" are used on inline text
    // elements, and are exposed via Markers() as if they are native errors.
    // Therefore, they are exposed as InvalidState:kNone here in order to avoid
    // exposing the state twice, and to prevent superfluous "invalid"
    // announcements in some screen readers.
    // On text fields, they are simply exposed as if aria-invalid="true".
    if (EqualIgnoringASCIICase(attribute_value, "spelling") ||
        EqualIgnoringASCIICase(attribute_value, "grammar")) {
      return RoleValue() == ax::mojom::blink::Role::kTextField
                 ? ax::mojom::blink::InvalidState::kTrue
                 : ax::mojom::blink::InvalidState::kNone;
    }
    // Any other non-empty value is considered true.
    if (!attribute_value.empty()) {
      return ax::mojom::blink::InvalidState::kTrue;
    }
  }

  // Next check for native the invalid state.
  if (GetElement()) {
    ListedElement* form_control = ListedElement::From(*GetElement());
    if (form_control) {
      return IsValidFormControl(form_control)
                 ? ax::mojom::blink::InvalidState::kFalse
                 : ax::mojom::blink::InvalidState::kTrue;
    }
  }

  return AXObject::GetInvalidState();
}

bool AXNodeObject::IsValidFormControl(ListedElement* form_control) const {
  // If the control is marked with a custom error, the form control is invalid.
  if (form_control->CustomError())
    return false;

  // If the form control checks for validity, and has passed the checks,
  // then consider it valid.
  if (form_control->IsNotCandidateOrValid())
    return true;

  // The control is invalid, as far as CSS is concerned.
  // However, we ignore a failed check inside of an empty required text field,
  // in order to avoid redundant verbalizations (screen reader already says
  // required).
  if (IsAtomicTextField() && IsRequired() && GetValueForControl().length() == 0)
    return true;

  return false;
}

int AXNodeObject::PosInSet() const {
  // A <select size=1> exposes posinset as the index of the selected option.
  if (RoleValue() == ax::mojom::blink::Role::kComboBoxSelect) {
    if (auto* select_element = DynamicTo<HTMLSelectElement>(*GetNode())) {
      return 1 + select_element->selectedIndex();
    }
  }

  if (SupportsARIASetSizeAndPosInSet()) {
    int32_t pos_in_set;
    if (AriaIntAttribute(html_names::kAriaPosinsetAttr, &pos_in_set)) {
      return pos_in_set;
    }
  }
  return 0;
}

int AXNodeObject::SetSize() const {
  if (auto* select_element = DynamicTo<HTMLSelectElement>(GetNode())) {
    return static_cast<int>(select_element->length());
  }

  if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    return ParentObject()->SetSize();
  }

  if (SupportsARIASetSizeAndPosInSet()) {
    int32_t set_size;
    if (AriaIntAttribute(html_names::kAriaSetsizeAttr, &set_size)) {
      return set_size;
    }
  }
  return 0;
}

bool AXNodeObject::ValueForRange(float* out_value) const {
  float value_now;
  if (AriaFloatAttribute(html_names::kAriaValuenowAttr, &value_now)) {
    // Adjustment when the aria-valuenow is less than aria-valuemin or greater
    // than the aria-valuemax value.
    // See https://w3c.github.io/aria/#authorErrorDefaultValuesTable.
    float min_value, max_value;
    if (MinValueForRange(&min_value)) {
      if (value_now < min_value) {
        *out_value = min_value;
        return true;
      }
    }
    if (MaxValueForRange(&max_value)) {
      if (value_now > max_value) {
        *out_value = max_value;
        return true;
      }
    }

    *out_value = value_now;
    return true;
  }

  if (IsNativeSlider() || IsNativeSpinButton()) {
    *out_value = To<HTMLInputElement>(*GetNode()).valueAsNumber();
    return std::isfinite(*out_value);
  }

  if (auto* meter = DynamicTo<HTMLMeterElement>(GetNode())) {
    *out_value = meter->value();
    return true;
  }

  // In ARIA 1.1, default values for aria-valuenow were changed as below.
  // - meter: A value matching the implicit or explicitly set aria-valuemin.
  // - scrollbar, slider : half way between aria-valuemin and aria-valuemax
  // - separator : 50
  // - spinbutton : 0
  switch (RawAriaRole()) {
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSlider: {
      float min_value, max_value;
      if (MinValueForRange(&min_value) && MaxValueForRange(&max_value)) {
        *out_value = (min_value + max_value) / 2.0f;
        return true;
      }
      [[fallthrough]];
    }
    case ax::mojom::blink::Role::kSplitter: {
      *out_value = 50.0f;
      return true;
    }
    case ax::mojom::blink::Role::kMeter: {
      float min_value;
      if (MinValueForRange(&min_value)) {
        *out_value = min_value;
        return true;
      }
      [[fallthrough]];
    }
    case ax::mojom::blink::Role::kSpinButton: {
      *out_value = 0.0f;
      return true;
    }
    default:
      break;
  }

  return false;
}

bool AXNodeObject::MaxValueForRange(float* out_value) const {
  if (AriaFloatAttribute(html_names::kAriaValuemaxAttr, out_value)) {
    return true;
  }

  if (IsNativeSlider() || IsNativeSpinButton()) {
    *out_value = static_cast<float>(To<HTMLInputElement>(*GetNode()).Maximum());
    return std::isfinite(*out_value);
  }

  if (auto* meter = DynamicTo<HTMLMeterElement>(GetNode())) {
    *out_value = meter->max();
    return true;
  }

  // In ARIA 1.1, default value of scrollbar, separator and slider
  // for aria-valuemax were changed to 100. This change was made for
  // progressbar in ARIA 1.2.
  switch (RawAriaRole()) {
    case ax::mojom::blink::Role::kMeter:
    case ax::mojom::blink::Role::kProgressIndicator:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kSlider: {
      *out_value = 100.0f;
      return true;
    }
    default:
      break;
  }

  return false;
}

bool AXNodeObject::MinValueForRange(float* out_value) const {
  if (AriaFloatAttribute(html_names::kAriaValueminAttr, out_value)) {
    return true;
  }

  if (IsNativeSlider() || IsNativeSpinButton()) {
    *out_value = static_cast<float>(To<HTMLInputElement>(*GetNode()).Minimum());
    return std::isfinite(*out_value);
  }

  if (auto* meter = DynamicTo<HTMLMeterElement>(GetNode())) {
    *out_value = meter->min();
    return true;
  }

  // In ARIA 1.1, default value of scrollbar, separator and slider
  // for aria-valuemin were changed to 0. This change was made for
  // progressbar in ARIA 1.2.
  switch (RawAriaRole()) {
    case ax::mojom::blink::Role::kMeter:
    case ax::mojom::blink::Role::kProgressIndicator:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kSlider: {
      *out_value = 0.0f;
      return true;
    }
    default:
      break;
  }

  return false;
}

bool AXNodeObject::StepValueForRange(float* out_value) const {
  if (IsNativeSlider() || IsNativeSpinButton()) {
    auto step_range =
        To<HTMLInputElement>(*GetNode()).CreateStepRange(kRejectAny);
    auto step = step_range.Step().ToString().ToFloat();

    // Provide a step if ATs incrementing slider should move by step, otherwise
    // AT will move by 5%.
    // If there are too few allowed stops (< 20), incrementing/decrementing
    // the slider by 5% could get stuck, and therefore the step is exposed.
    // The step is also exposed if moving by 5% would cause intermittent
    // behavior where sometimes the slider would alternate by 1 or 2 steps.
    // Therefore the final decision is to use the step if there are
    // less than stops in the slider, otherwise, move by 5%.
    float max = step_range.Maximum().ToString().ToFloat();
    float min = step_range.Minimum().ToString().ToFloat();
    int num_stops = base::saturated_cast<int>((max - min) / step);
    constexpr int kNumStopsForFivePercentRule = 40;
    if (num_stops >= kNumStopsForFivePercentRule) {
      // No explicit step, and the step is very small -- don't expose a step
      // so that Talkback will move by 5% increments.
      *out_value = 0.0f;
      return false;
    }

    *out_value = step;
    return std::isfinite(*out_value);
  }

  switch (RawAriaRole()) {
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kSlider: {
      *out_value = 0.0f;
      return true;
    }
    default:
      break;
  }

  return false;
}

KURL AXNodeObject::Url() const {
  if (IsLink())  // <area>, <link>, <html:a> or <svg:a>
    return GetElement()->HrefURL();

  if (IsWebArea()) {
    DCHECK(GetDocument());
    return GetDocument()->Url();
  }

  auto* html_image_element = DynamicTo<HTMLImageElement>(GetNode());
  if (IsImage() && html_image_element) {
    // Using ImageSourceURL handles both src and srcset.
    String source_url = html_image_element->ImageSourceURL();
    String stripped_image_source_url =
        StripLeadingAndTrailingHTMLSpaces(source_url);
    if (!stripped_image_source_url.empty())
      return GetDocument()->CompleteURL(stripped_image_source_url);
  }

  if (IsInputImage())
    return To<HTMLInputElement>(GetNode())->Src();

  return KURL();
}

AXObject* AXNodeObject::ChooserPopup() const {
  // When color & date chooser popups are visible, they can be found in the tree
  // as a group child of the <input> control itself.
  switch (native_role_) {
    case ax::mojom::blink::Role::kColorWell:
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kDate:
    case ax::mojom::blink::Role::kDateTime:
    case ax::mojom::blink::Role::kInputTime:
    case ax::mojom::blink::Role::kTextFieldWithComboBox: {
      for (const auto& child : ChildrenIncludingIgnored()) {
        if (IsA<Document>(child->GetNode())) {
          return child.Get();
        }
      }
      return nullptr;
    }
    default:
#if DCHECK_IS_ON()
      for (const auto& child : ChildrenIncludingIgnored()) {
        DCHECK(!IsA<Document>(child->GetNode()) ||
               !child->ParentObject()->IsVisible())
            << "Chooser popup exists for " << native_role_
            << "\n* Child: " << child
            << "\n* Child's immediate parent: " << child->ParentObject();
      }
#endif
      return nullptr;
  }
}

String AXNodeObject::GetValueForControl() const {
  AXObjectSet visited;
  return GetValueForControl(visited);
}

String AXNodeObject::GetValueForControl(AXObjectSet& visited) const {
  // TODO(crbug.com/1165853): Remove this method completely and compute value on
  // the browser side.
  Node* node = GetNode();
  if (!node)
    return String();

  if (const auto* select_element = DynamicTo<HTMLSelectElement>(*node)) {
    if (!select_element->UsesMenuList())
      return String();

    // In most cases, we want to return what's actually displayed inside the
    // <select> element on screen, unless there is an ARIA label overriding it.
    int selected_index = select_element->SelectedListIndex();
    const HeapVector<Member<HTMLElement>>& list_items =
        select_element->GetListItems();
    if (selected_index >= 0 &&
        static_cast<wtf_size_t>(selected_index) < list_items.size()) {
      const AtomicString& overridden_description = AriaAttribute(
          *list_items[selected_index], html_names::kAriaLabelAttr);
      if (!overridden_description.IsNull())
        return overridden_description;
    }

    // We don't retrieve the element's value attribute on purpose. The value
    // attribute might be sanitized and might be different from what is actually
    // displayed inside the <select> element on screen.
    return select_element->InnerElement().GetInnerTextWithoutUpdate();
  }

  if (IsAtomicTextField()) {
    // This is an "<input type=text>" or a "<textarea>": We should not simply
    // return the "value" attribute because it might be sanitized in some input
    // control types, e.g. email fields. If we do that, then "selectionStart"
    // and "selectionEnd" indices will not match with the text in the sanitized
    // value.
    String inner_text = ToTextControl(*node).InnerEditorValue();
    unsigned int unmasked_text_length = inner_text.length();
    // If the inner text is empty, we return a null string to let the text
    // alternative algorithm continue searching for an accessible name.
    if (!unmasked_text_length) {
      return String();
    }

    if (!IsPasswordFieldAndShouldHideValue())
      return inner_text;

    if (!GetLayoutObject())
      return inner_text;

    const ComputedStyle* style = GetLayoutObject()->Style();
    if (!style)
      return inner_text;

    UChar mask_character = 0;
    switch (style->TextSecurity()) {
      case ETextSecurity::kNone:
        break;  // Fall through to the non-password branch.
      case ETextSecurity::kDisc:
        mask_character = kBulletCharacter;
        break;
      case ETextSecurity::kCircle:
        mask_character = kWhiteBulletCharacter;
        break;
      case ETextSecurity::kSquare:
        mask_character = kBlackSquareCharacter;
        break;
    }
    if (!mask_character)
      return inner_text;

    StringBuilder masked_text;
    masked_text.ReserveCapacity(unmasked_text_length);
    for (unsigned int i = 0; i < unmasked_text_length; ++i)
      masked_text.Append(mask_character);
    return masked_text.ToString();
  }

  if (IsRangeValueSupported()) {
    return AriaAttribute(html_names::kAriaValuetextAttr).GetString();
  }

  // Handle other HTML input elements that aren't text controls, like date and
  // time controls, by returning their value converted to text, with the
  // exception of checkboxes and radio buttons (which would return "on"), and
  // buttons which will return their name.
  // https://html.spec.whatwg.org/C/#dom-input-value
  if (const auto* input = DynamicTo<HTMLInputElement>(node)) {
    if (input->FormControlType() == FormControlType::kInputFile) {
      return input->FileStatusText();
    }

    if (input->FormControlType() != FormControlType::kInputButton &&
        input->FormControlType() != FormControlType::kInputCheckbox &&
        input->FormControlType() != FormControlType::kInputImage &&
        input->FormControlType() != FormControlType::kInputRadio &&
        input->FormControlType() != FormControlType::kInputReset &&
        input->FormControlType() != FormControlType::kInputSubmit) {
      return input->Value();
    }
  }

  if (RoleValue() == ax::mojom::blink::Role::kComboBoxMenuButton) {
    // An ARIA combobox can get value from inner contents.
    return TextFromDescendants(visited, nullptr, false);
  }

  return String();
}

String AXNodeObject::SlowGetValueForControlIncludingContentEditable() const {
  AXObjectSet visited;
  return SlowGetValueForControlIncludingContentEditable(visited);
}

String AXNodeObject::SlowGetValueForControlIncludingContentEditable(
    AXObjectSet& visited) const {
  if (IsNonAtomicTextField()) {
    Element* element = GetElement();
    return element ? element->GetInnerTextWithoutUpdate() : String();
  }
  return GetValueForControl(visited);
}

ax::mojom::blink::Role AXNodeObject::RawAriaRole() const {
  return aria_role_;
}

ax::mojom::blink::HasPopup AXNodeObject::HasPopup() const {
  if (const AtomicString& has_popup =
          AriaTokenAttribute(html_names::kAriaHaspopupAttr)) {
    if (EqualIgnoringASCIICase(has_popup, "false"))
      return ax::mojom::blink::HasPopup::kFalse;

    if (EqualIgnoringASCIICase(has_popup, "listbox"))
      return ax::mojom::blink::HasPopup::kListbox;

    if (EqualIgnoringASCIICase(has_popup, "tree"))
      return ax::mojom::blink::HasPopup::kTree;

    if (EqualIgnoringASCIICase(has_popup, "grid"))
      return ax::mojom::blink::HasPopup::kGrid;

    if (EqualIgnoringASCIICase(has_popup, "dialog"))
      return ax::mojom::blink::HasPopup::kDialog;

    // To provide backward compatibility with ARIA 1.0 content,
    // user agents MUST treat an aria-haspopup value of true
    // as equivalent to a value of menu.
    if (EqualIgnoringASCIICase(has_popup, "true") ||
        EqualIgnoringASCIICase(has_popup, "menu"))
      return ax::mojom::blink::HasPopup::kMenu;
  }

  // ARIA 1.1 default value of haspopup for combobox is "listbox".
  if (RoleValue() == ax::mojom::blink::Role::kComboBoxMenuButton ||
      RoleValue() == ax::mojom::blink::Role::kTextFieldWithComboBox) {
    return ax::mojom::blink::HasPopup::kListbox;
  }

  if (AXObjectCache().GetAutofillSuggestionAvailability(AXObjectID()) !=
      WebAXAutofillSuggestionAvailability::kNoSuggestions) {
    return ax::mojom::blink::HasPopup::kMenu;
  }

  return AXObject::HasPopup();
}

ax::mojom::blink::IsPopup AXNodeObject::IsPopup() const {
  if (IsDetached() || !GetElement()) {
    return ax::mojom::blink::IsPopup::kNone;
  }
  const auto* html_element = DynamicTo<HTMLElement>(GetElement());
  if (!html_element) {
    return ax::mojom::blink::IsPopup::kNone;
  }
  if (RoleValue() == ax::mojom::blink::Role::kMenuListPopup) {
    return ax::mojom::blink::IsPopup::kAuto;
  }
  switch (html_element->PopoverType()) {
    case PopoverValueType::kNone:
      return ax::mojom::blink::IsPopup::kNone;
    case PopoverValueType::kAuto:
      return ax::mojom::blink::IsPopup::kAuto;
    case PopoverValueType::kHint:
      return ax::mojom::blink::IsPopup::kHint;
    case PopoverValueType::kManual:
      return ax::mojom::blink::IsPopup::kManual;
  }
}

bool AXNodeObject::IsEditableRoot() const {
  const Node* node = GetNode();
  if (IsDetached() || !node)
    return false;
#if DCHECK_IS_ON()  // Required in order to get Lifecycle().ToString()
  DCHECK(GetDocument());
  DCHECK_GE(GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kStyleClean)
      << "Unclean document style at lifecycle state "
      << GetDocument()->Lifecycle().ToString();
#endif  // DCHECK_IS_ON()

  // Catches the case where the 'contenteditable' attribute is set on an atomic
  // text field (which shouldn't have any effect).
  if (IsAtomicTextField())
    return false;

  // The DOM inside native text fields is an implementation detail that should
  // not be exposed to platform accessibility APIs.
  if (EnclosingTextControl(node))
    return false;

  if (IsRootEditableElement(*node))
    return true;

  // Catches the case where a contenteditable is inside another contenteditable.
  // This is especially important when the two nested contenteditables have
  // different attributes, e.g. "true" vs. "plaintext-only".
  if (HasContentEditableAttributeSet())
    return true;

  return false;
}

bool AXNodeObject::HasContentEditableAttributeSet() const {
  if (IsDetached() || !GetNode())
    return false;

  const auto* html_element = DynamicTo<HTMLElement>(GetNode());
  if (!html_element)
    return false;

  ContentEditableType normalized_value =
      html_element->contentEditableNormalized();
  return normalized_value == ContentEditableType::kContentEditable ||
         normalized_value == ContentEditableType::kPlaintextOnly;
}

// Returns the nearest block-level LayoutBlockFlow ancestor
static LayoutBlockFlow* GetNearestBlockFlow(LayoutObject* object) {
  LayoutObject
"""


```