Response:
My goal is to analyze the provided C++ code snippet from `ax_object.cc` and extract its functionality, relationships with web technologies, potential errors, debugging information, and provide a concise summary. Here's my thought process:

1. **Understand the Context:** The file path `blink/renderer/modules/accessibility/ax_object.cc` immediately tells me this code is part of the Blink rendering engine, specifically dealing with accessibility (`AXObject`). This means it's responsible for exposing information about the rendered web page to assistive technologies.

2. **Identify Key Functions:** I'll go through the code and identify the distinct functions (methods) defined within the `AXObject` class. I'll pay attention to their names and what they seem to be doing based on the code.

3. **Analyze Individual Function Functionality:** For each function, I'll try to determine its purpose. Keywords like `Serialize`, `AddAttribute`, and the names of the attributes (e.g., `kRole`, `kHtmlTag`, `kClassName`) are strong clues. I'll look for patterns and how data is being manipulated.

4. **Relate to Web Technologies (HTML, CSS, JavaScript):** As I analyze each function, I'll consider how it relates to the core web technologies. For example:
    * Functions dealing with `kHtmlTag`, `kClassName`, `kHtmlId`, and `html_attributes` directly interact with HTML elements and their attributes.
    * Functions related to `kRole`, `aria-*` attributes, and states like `kExpanded` connect to ARIA (Accessible Rich Internet Applications), which enhances the accessibility of HTML.
    * Functions referencing computed styles (`GetComputedStyle`) and CSS properties (`kDisplay`) clearly relate to CSS.
    * While this specific snippet doesn't show direct JavaScript interaction, I know that changes made by JavaScript can influence the attributes and properties that these serialization functions are processing.

5. **Identify Potential User/Programming Errors:**  I'll look for scenarios where things could go wrong or where a developer might misuse the system. For instance:
    * Incorrect or missing ARIA attributes could lead to accessibility issues.
    * Relying on non-standard attributes (like those mentioned for JAWS) is generally discouraged as they might not be universally supported and could break in the future.
    * Incorrectly setting `role` attributes could misrepresent the purpose of elements to assistive technologies.

6. **Infer Debugging Information/User Actions:** I'll think about how a developer would end up in this code during debugging. Common scenarios include:
    * Inspecting the accessibility tree in browser developer tools.
    * Investigating why an element isn't being represented correctly by assistive technologies.
    * Tracing the serialization process when accessibility information is being generated. User actions that trigger rendering or changes to the DOM (like clicking, typing, page load) can lead to this code being executed.

7. **Hypothesize Inputs and Outputs (Logical Reasoning):**  For functions that seem to perform transformations, I'll try to imagine a simple input and the corresponding output. For example, if a function serializes the `class` attribute, a hypothetical input might be an HTML element like `<div class="my-class">`, and the output would be the `kClassName` attribute in `ui::AXNodeData` being set to "my-class".

8. **Synthesize a Summary:** Finally, I'll condense all the identified functionalities into a concise summary, highlighting the core purpose of this code within the accessibility framework.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on low-level details.
* **Correction:** Shift focus to the higher-level purpose of each function and its contribution to accessibility serialization.
* **Initial thought:** Overlook the connection to CSS.
* **Correction:** Recognize functions like `SerializeScreenReaderAttributes` and the use of `GetComputedStyle` clearly indicate interaction with CSS properties.
* **Initial thought:**  Not explicitly mention ARIA enough.
* **Correction:**  Emphasize the role of ARIA attributes in influencing the serialized data, especially with functions like `SerializeAriaRole`.
* **Initial thought:**  Not connect user actions to the code execution.
* **Correction:** Realize that rendering and DOM manipulation triggered by user actions are the primary drivers for this accessibility code.

By following these steps, I can systematically analyze the code snippet and provide a comprehensive and well-structured explanation of its functionality and related aspects.
这是提供的 `blink/renderer/modules/accessibility/ax_object.cc` 文件的一部分源代码，它主要负责将 `AXObject` 的各种属性和状态序列化到 `ui::AXNodeData` 结构中。这个结构是 Chromium 中表示可访问性信息的标准方式，会被传递给辅助技术（例如屏幕阅读器）。

**功能归纳 (针对提供的代码片段):**

这段代码的主要功能是 **序列化与 HTML 元素属性相关的可访问性信息**。它包含了以下几个关键方面：

1. **序列化 ARIA 角色 (SerializeAriaRole):**  获取并序列化元素的 ARIA 角色属性。如果没有 ARIA 角色，则尝试使用等效的 HTML 角色（如果存在于 `xml-roles` 中）。
2. **序列化 HTML 标签和类名 (SerializeHTMLTagAndClass):** 获取并序列化元素的 HTML 标签名（转换为小写）和 `class` 属性。对于 `Document` 类型的节点，标签名为 "#document"。
3. **序列化 HTML ID (SerializeHTMLId):** 获取并序列化元素的 `id` 属性。
4. **序列化其他 HTML 属性 (SerializeHTMLAttributesForSnapshot):** 遍历元素的所有属性，并将除了 `id` 和 `class` 以外的其他属性名和值以字符串键值对的形式添加到 `node_data->html_attributes` 中。
5. **序列化非标准的 HTML 属性 (SerializeHTMLNonStandardAttributesForJAWS):**  专门为 JAWS 屏幕阅读器序列化一些非标准的 HTML 属性，例如 `brailleonlyregion`，`data-at-shortcutkeys` 和 `formcontrolname`。这些属性用于特定的功能，未来可能会被标准的 ARIA 特性取代。
6. **序列化内联文本框信息 (SerializeInlineTextBox):**  对于内联文本框（`ax::mojom::blink::Role::kInlineTextBox`），序列化行属性、标记属性、边界框属性、文本方向、字符偏移、单词边界以及可编辑状态。如果启用了 `IsAccessibilityPruneRedundantInlineTextEnabled()` 特性，并且该内联文本框是其父元素的唯一子元素，并且其文本内容与父元素的可见文本相同，则会跳过序列化，以避免冗余数据。
7. **序列化语言属性 (SerializeLangAttribute):** 获取并序列化元素的 `lang` 属性。如果当前元素的语言与父元素的语言相同，则会跳过序列化。
8. **序列化行相关属性 (SerializeLineAttributes):**  获取并序列化同一行上相邻元素的 ID (`kNextOnLineId`, `kPreviousOnLineId`)。
9. **序列化列表相关属性 (SerializeListAttributes):**  对于列表项，序列化 `setsize` 和 `posinset` 属性。
10. **序列化列表标记相关属性 (SerializeListMarkerAttributes):** 对于列表标记，序列化单词边界。
11. **序列化 Live Region 相关属性 (SerializeLiveRegionAttributes):**  对于 Live Region，序列化 `aria-atomic`, `aria-live`, `aria-relevant` 等属性，以及容器 Live Region 的相关信息。
12. **序列化 Name 和 Description 属性 (SerializeNameAndDescriptionAttributes):**  获取并序列化元素的名称（`name`，通常来自标签内容、`aria-label` 或 `aria-labelledby`）和描述（`description`，通常来自 `aria-describedby`），以及 `title` 属性和 `placeholder` 属性。
13. **序列化屏幕阅读器相关的属性 (SerializeScreenReaderAttributes):** 序列化一些对于屏幕阅读器重要的属性，例如 HTML 标签和类名、`display` 样式、是否存在 ARIA 属性、键盘快捷键 (`accesskey`) 以及激活的后代元素 (`activedescendant`)。
14. **序列化其他的屏幕阅读器属性 (SerializeOtherScreenReaderAttributes):** 序列化一些其他的屏幕阅读器属性，例如 `busy` 状态（仅用于 Document）、`color-value` (对于颜色选择器)、链接目标、单选按钮组、`aria-current` 状态、`aria-invalid` 状态、`aria-checked` 状态、列表标记属性、`accesskey`、`autocomplete`、默认动作、错误消息、层级级别、Canvas 是否有后备内容以及范围值相关的属性。
15. **序列化 MathML 内容 (SerializeMathContent):**  对于 MathML 元素，序列化其内部的 HTML 内容。
16. **序列化滚动属性 (SerializeScrollAttributes):** 序列化元素是否可滚动以及其滚动偏移量、最小和最大滚动范围。
17. **序列化关系属性 (SerializeRelationAttributes):** 序列化使用 `aria-controls`, `aria-details`, `aria-flowto`, `aria-activedescendant`, 和 `aria-errormessage` 定义的关系。
18. **序列化样式属性 (SerializeStyleAttributes):** 序列化元素的字体族、字体大小、字体粗细、列表样式、文本对齐方式、文本缩进、文本方向、文本位置和文本装饰线样式。
19. **序列化表格属性 (SerializeTableAttributes):**  序列化表格、行和单元格的属性，例如列数、行数、表头 ID、跨列数、跨行数、行索引、列索引和排序方向。
20. **序列化未忽略的属性 (SerializeUnignoredAttributes):**  针对未被忽略的节点，序列化名称和描述属性、标记属性、样式属性、链接状态、用户是否可选状态、展开/折叠状态、是否有弹出窗口、是否是弹出窗口、自动填充可用状态、默认状态、悬停状态、多行状态、多选状态、密码字段状态、必填状态、选中状态、方向、列表属性和表格属性。还会根据限制条件序列化动作属性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  这些函数直接处理 HTML 元素及其属性。
    * **举例:** `SerializeHTMLTagAndClass` 获取 `<div class="container">` 的标签名 "div" 和类名 "container"。
    * **举例:** `SerializeHTMLId` 获取 `<button id="submit-button">` 的 ID "submit-button"。
    * **举例:** `SerializeAriaRole` 获取 `<div role="dialog">` 的 ARIA 角色 "dialog"。
* **CSS:** 一些函数涉及到 CSS 样式信息。
    * **举例:** `SerializeScreenReaderAttributes` 获取元素的 `display` 属性值 (例如 "block", "inline", "none")。
    * **举例:** `SerializeStyleAttributes` 获取元素的 `font-family`, `font-size`, `font-weight`, `text-align` 等样式信息。这些信息是通过 `ComputedStyle` 对象获取的，它反映了最终应用到元素的 CSS 规则。
* **JavaScript:** 虽然这段代码本身是 C++，但 JavaScript 可以动态地修改 HTML 结构、属性和 CSS 样式，从而影响这些序列化函数的结果。
    * **假设输入:**  JavaScript 代码使用 `element.setAttribute('aria-label', '关闭')` 修改了一个元素的 ARIA 标签。
    * **输出:**  `SerializeNameAndDescriptionAttributes` 函数会读取到这个新的 `aria-label` 值，并将其序列化到 `node_data` 的 `kName` 属性中。
    * **假设输入:** JavaScript 代码使用 `element.classList.add('highlighted')` 给元素添加了一个 CSS 类。
    * **输出:** `SerializeHTMLTagAndClass` 函数会将新的类名 "highlighted" 添加到 `node_data` 的 `kClassName` 属性中。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个 HTML 元素 `<button aria-pressed="true">按钮</button>`。
* **输出:**
    * `SerializeAriaRole` 会识别到没有明确的 role 属性，但会根据 button 标签推断出 role 为 "button"。
    * `SerializeUnignoredAttributes` 中的代码会检查 `aria-pressed` 属性，并将其转换为 `ax::mojom::blink::State::kPressed` 状态添加到 `node_data` 中。
    * `SerializeNameAndDescriptionAttributes` 会将 "按钮" 作为元素的名称序列化。

**涉及用户或编程常见的使用错误及举例说明:**

* **错误使用 ARIA 属性:**  开发者可能会使用错误的 ARIA 属性或值，导致辅助技术无法正确理解元素的语义。
    * **举例:**  使用 `role="heading"` 但没有设置合适的层级 (h1-h6)，或者在一个不应该使用 `aria-live` 的元素上设置了该属性。这会导致 `SerializeAriaRole` 或 `SerializeLiveRegionAttributes` 序列化不正确的信息。
* **过度依赖非标准属性:**  依赖 `SerializeHTMLNonStandardAttributesForJAWS` 中处理的属性可能导致代码在其他浏览器或辅助技术上无法正常工作。
    * **举例:**  过度使用 `data-at-shortcutkeys` 而不使用标准的 ARIA 方式提供键盘快捷键信息。
* **动态修改属性后未更新可访问性树:** 如果 JavaScript 动态修改了元素的属性（例如 `aria-label`），但没有触发可访问性树的更新，辅助技术获取到的信息可能仍然是旧的。虽然这不在 `ax_object.cc` 的职责范围内，但会影响最终的用户体验。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载网页:** 当用户在浏览器中加载一个网页时，Blink 渲染引擎会解析 HTML、CSS 和 JavaScript。
2. **渲染树构建:** 渲染引擎会根据解析结果构建渲染树。
3. **可访问性树构建 (如果启用):** 如果浏览器的可访问性功能被启用（例如，屏幕阅读器正在运行），或者开发者工具中打开了可访问性面板，Blink 会构建可访问性树。
4. **AXObject 创建:**  渲染树中的每个相关节点（通常是 HTML 元素）都会对应一个 `AXObject`。
5. **序列化过程:**  为了将可访问性信息传递给辅助技术，系统会遍历可访问性树，并调用 `AXObject::Serialize` 方法（以及其调用的各种 `Serialize*` 方法，包括这里列出的这些）。
6. **调用特定序列化函数:**  根据 `AXObject` 对应的元素类型和属性，会调用不同的 `Serialize*` 函数。例如，如果当前 `AXObject` 对应一个 `<div>` 元素，`SerializeHTMLTagAndClass` 就会被调用。如果该元素有 `role` 属性，`SerializeAriaRole` 也会被调用。
7. **数据填充:** 这些 `Serialize*` 函数会将相关的属性和状态信息填充到 `ui::AXNodeData` 结构中。
8. **传递给辅助技术:**  `ui::AXNodeData` 结构会被传递给 Chromium 的可访问性基础设施，最终传递给操作系统或辅助技术。

**调试线索:** 如果在调试可访问性问题时发现某个元素的属性信息不正确，可以设置断点在相关的 `Serialize*` 函数中，例如：

* **角色不正确:** 在 `SerializeAriaRole` 中检查 `GetRoleStringForSerialization(node_data)` 的返回值。
* **类名或标签名不正确:** 在 `SerializeHTMLTagAndClass` 中检查 `element->tagName()` 和 `element->GetClassAttribute()` 的值。
* **ARIA 属性未被序列化:**  在对应的 `Serialize*` 函数中检查相关 ARIA 属性的获取和添加逻辑。

**总结这段代码的功能:**

这段代码片段是 `AXObject` 类中负责将其各种与 HTML 元素属性相关的可访问性信息序列化到 `ui::AXNodeData` 结构的关键部分。它涵盖了 ARIA 角色、HTML 标签和属性、非标准属性以及其他与屏幕阅读器相关的属性。它的主要目标是将网页的结构和语义信息以辅助技术能够理解的方式表达出来。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
es object
  // attribute. Prefer the raw ARIA role attribute value, otherwise, the ARIA
  // equivalent role is used, if it is a role that is exposed in xml-roles.
  const AtomicString& role_str = GetRoleStringForSerialization(node_data);
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kRole, role_str);
}

void AXObject::SerializeHTMLTagAndClass(ui::AXNodeData* node_data) const {
  Element* element = GetElement();
  if (!element) {
    if (IsA<Document>(GetNode())) {
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kHtmlTag, "#document");
    }
    return;
  }

  TruncateAndAddStringAttribute(node_data,
                                ax::mojom::blink::StringAttribute::kHtmlTag,
                                element->tagName().LowerASCII());

  if (const AtomicString& class_name = element->GetClassAttribute()) {
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kClassName, class_name);
  }
}

void AXObject::SerializeHTMLId(ui::AXNodeData* node_data) const {
  Element* element = GetElement();
  if (!element) {
    return;
  }

  TruncateAndAddStringAttribute(node_data,
                                ax::mojom::blink::StringAttribute::kHtmlId,
                                element->GetIdAttribute());
}

void AXObject::SerializeHTMLAttributesForSnapshot(
    ui::AXNodeData* node_data) const {
  for (const Attribute& attr : GetElement()->AttributesWithoutUpdate()) {
    const QualifiedName& attr_name = attr.GetName();
    if (attr_name == html_names::kIdAttr ||
        attr_name == html_names::kClassAttr) {
      // Attribute already in kHtmlId or kClassName.
      continue;
    }
    std::string name = attr_name.LocalName().LowerASCII().Utf8();
    std::string value = attr.Value().Utf8();
    node_data->html_attributes.push_back(std::make_pair(name, value));
  }
}

// For now, serialize for legacy support of nonstandard attributes equired by
// the JAWS screen reader.
// TODO(accessibility) Remove support once JAWS has released 2+ versions that
// do not require support.
void AXObject::SerializeHTMLNonStandardAttributesForJAWS(
    ui::AXNodeData* node_data) const {
#if BUILDFLAG(IS_WIN)
  // brailleonlyregion: a nonstandard attribute used by national testing orgs
  // to allow testing of reading ability by rendering only to Braille display,
  // and not to TTS.
  // TODO(https://github.com/w3c/aria/issues/2352): replace with ARIA feature.
  DEFINE_STATIC_LOCAL(QualifiedName, brailleonlyregion_attr,
                      (AtomicString("brailleonlyregion")));
  if (GetElement()->FastHasAttribute(brailleonlyregion_attr)) {
    node_data->html_attributes.push_back(
        std::make_pair(brailleonlyregion_attr.LocalName().Utf8(), ""));
  }

  // data-at-shortcutkeys: a nonstandard attribute used by Twitter and Facebook
  // to provide keyboard shortcuts for an entire web page, in the form of a
  // parseable JSON map, which AT can use to help avoid keyboard conflicts.
  // TODO(https://github.com/w3c/aria/issues/2351): Replace with ARIA feature.
  DEFINE_STATIC_LOCAL(QualifiedName, data_at_shortcutkeys_attr,
                      (AtomicString("data-at-shortcutkeys")));
  const AtomicString& data_at_shorcutkeys_value =
      GetElement()->FastGetAttribute(data_at_shortcutkeys_attr);
  if (data_at_shorcutkeys_value) {
    node_data->html_attributes.push_back(
        std::make_pair(data_at_shortcutkeys_attr.LocalName().Utf8(),
                       data_at_shorcutkeys_value.Utf8()));
  }

  // formcontrolname: a nonstandard attribute used by Angular and consumed by
  // some password managers (see https://crbug.com/378908266).
  DEFINE_STATIC_LOCAL(QualifiedName, formcontrolname_attr,
                      (AtomicString("formcontrolname")));
  const AtomicString& formcontrolname_value =
      GetElement()->FastGetAttribute(formcontrolname_attr);
  if (formcontrolname_value) {
    node_data->html_attributes.push_back(std::make_pair(
        formcontrolname_attr.LocalName().Utf8(), formcontrolname_value.Utf8()));
  }

#endif
}

void AXObject::SerializeInlineTextBox(ui::AXNodeData* node_data) const {
  DCHECK_EQ(ax::mojom::blink::Role::kInlineTextBox, node_data->role);

  SerializeLineAttributes(node_data);
  SerializeMarkerAttributes(node_data);
  SerializeBoundingBoxAttributes(*node_data);
  if (GetTextDirection() != ax::mojom::blink::WritingDirection::kNone) {
    node_data->SetTextDirection(GetTextDirection());
  }

  Vector<int> character_offsets;
  TextCharacterOffsets(character_offsets);
  AddIntListAttributeFromOffsetVector(
      ax::mojom::blink::IntListAttribute::kCharacterOffsets, character_offsets,
      node_data);

  // TODO(kevers): This data can be calculated on demand from the text content
  // and should not need to be serialized.
  Vector<int> word_starts;
  Vector<int> word_ends;
  GetWordBoundaries(word_starts, word_ends);
  AddIntListAttributeFromOffsetVector(
      ax::mojom::blink::IntListAttribute::kWordStarts, word_starts, node_data);
  AddIntListAttributeFromOffsetVector(
      ax::mojom::blink::IntListAttribute::kWordEnds, word_ends, node_data);

  // TODO(accessibility) Only need these editable states on ChromeOS, which
  // should be able to infer them from the static text parent.
  if (IsEditable()) {
    node_data->AddState(ax::mojom::blink::State::kEditable);
    if (IsRichlyEditable()) {
      node_data->AddState(ax::mojom::blink::State::kRichlyEditable);
    }
  }

  ax::mojom::blink::NameFrom name_from;
  AXObjectVector name_objects;
  String name = GetName(name_from, &name_objects);
  DCHECK_EQ(name_from, ax::mojom::blink::NameFrom::kContents);
  node_data->SetNameFrom(ax::mojom::blink::NameFrom::kContents);

  if (::features::IsAccessibilityPruneRedundantInlineTextEnabled()) {
    DCHECK(parent_);
    DCHECK(parent_->GetLayoutObject()->IsText());
    if (IsOnlyChild()) {
      auto* layout_text = To<LayoutText>(parent_->GetLayoutObject());
      String visible_text = layout_text->PlainText();
      if (name == visible_text) {
        // The text of an only-child inline text box can be inferred directly
        // from the parent. No need to serialize redundant data.
        return;
      }
    }
  }

  TruncateAndAddStringAttribute(node_data,
                                ax::mojom::blink::StringAttribute::kName, name,
                                kMaxStringAttributeLength);
}

void AXObject::SerializeLangAttribute(ui::AXNodeData* node_data) const {
  AXObject* parent = ParentObject();
  if (Language().length()) {
    // Trim redundant languages.
    if (!parent || parent->Language() != Language()) {
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kLanguage, Language());
    }
  }
}

void AXObject::SerializeLineAttributes(ui::AXNodeData* node_data) const {
  AXObjectCache().ComputeNodesOnLine(GetLayoutObject());

  if (AXObject* next_on_line = NextOnLine()) {
    CHECK(!next_on_line->IsDetached());
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kNextOnLineId,
                               next_on_line->AXObjectID());
  }

  if (AXObject* prev_on_line = PreviousOnLine()) {
    CHECK(!prev_on_line->IsDetached());
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kPreviousOnLineId,
        prev_on_line->AXObjectID());
  }
}

void AXObject::SerializeListAttributes(ui::AXNodeData* node_data) const {
  if (SetSize()) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kSetSize,
                               SetSize());
  }

  if (PosInSet()) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kPosInSet,
                               PosInSet());
  }
}

void AXObject::SerializeListMarkerAttributes(ui::AXNodeData* node_data) const {
  DCHECK_EQ(ax::mojom::blink::Role::kListMarker, node_data->role);

  Vector<int> word_starts;
  Vector<int> word_ends;
  GetWordBoundaries(word_starts, word_ends);
  AddIntListAttributeFromOffsetVector(
      ax::mojom::blink::IntListAttribute::kWordStarts, word_starts, node_data);
  AddIntListAttributeFromOffsetVector(
      ax::mojom::blink::IntListAttribute::kWordEnds, word_ends, node_data);
}

void AXObject::SerializeLiveRegionAttributes(ui::AXNodeData* node_data) const {
  DCHECK(LiveRegionRoot());

  node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kLiveAtomic,
                              LiveRegionAtomic());
  TruncateAndAddStringAttribute(node_data,
                                ax::mojom::blink::StringAttribute::kLiveStatus,
                                LiveRegionStatus());
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kLiveRelevant,
      LiveRegionRelevant());
  // If we are not at the root of an atomic live region.
  if (ContainerLiveRegionAtomic() && !LiveRegionRoot()->IsDetached() &&
      !LiveRegionAtomic()) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kMemberOfId,
                               LiveRegionRoot()->AXObjectID());
  }
  node_data->AddBoolAttribute(
      ax::mojom::blink::BoolAttribute::kContainerLiveAtomic,
      ContainerLiveRegionAtomic());
  node_data->AddBoolAttribute(
      ax::mojom::blink::BoolAttribute::kContainerLiveBusy,
      ContainerLiveRegionBusy());
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kContainerLiveStatus,
      ContainerLiveRegionStatus());
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kContainerLiveRelevant,
      ContainerLiveRegionRelevant());
}

void AXObject::SerializeNameAndDescriptionAttributes(
    ui::AXMode accessibility_mode,
    ui::AXNodeData* node_data) const {
  ax::mojom::blink::NameFrom name_from;
  AXObjectVector name_objects;
  String name = GetName(name_from, &name_objects);

  if (name_from == ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty) {
    node_data->AddStringAttribute(ax::mojom::blink::StringAttribute::kName,
                                  std::string());
    node_data->SetNameFrom(
        ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty);
  } else if (!name.empty()) {
    DCHECK_NE(name_from, ax::mojom::blink::NameFrom::kProhibited);
    int max_length = node_data->role == ax::mojom::blink::Role::kStaticText
                         ? kMaxStaticTextLength
                         : kMaxStringAttributeLength;
    if (TruncateAndAddStringAttribute(node_data,
                                      ax::mojom::blink::StringAttribute::kName,
                                      name, max_length)) {
      node_data->SetNameFrom(name_from);
      AddIntListAttributeFromObjects(
          ax::mojom::blink::IntListAttribute::kLabelledbyIds, name_objects,
          node_data);
    }
  } else if (name_from == ax::mojom::blink::NameFrom::kProhibited) {
    DCHECK(name.empty());
    node_data->SetNameFrom(ax::mojom::blink::NameFrom::kProhibited);
  }

  ax::mojom::blink::DescriptionFrom description_from;
  AXObjectVector description_objects;
  String description =
      Description(name_from, description_from, &description_objects);
  if (description.empty()) {
    DCHECK_NE(name_from, ax::mojom::blink::NameFrom::kProhibited)
        << "Should expose prohibited name as description: " << GetNode();
  } else {
    DCHECK_NE(description_from, ax::mojom::blink::DescriptionFrom::kNone)
        << this << "\n* Description: " << description;
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kDescription,
        description);
    node_data->SetDescriptionFrom(description_from);
    AddIntListAttributeFromObjects(
        ax::mojom::blink::IntListAttribute::kDescribedbyIds,
        description_objects, node_data);
  }

  String title = Title(name_from);
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kTooltip, title);

  if (!accessibility_mode.has_mode(ui::AXMode::kScreenReader))
    return;

  String placeholder = Placeholder(name_from);
  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kPlaceholder, placeholder);
}

void AXObject::SerializeScreenReaderAttributes(ui::AXNodeData* node_data) const {
  if (ui::IsText(RoleValue())) {
    // Don't serialize these attributes on text, where it is uninteresting.
    return;
  }
  SerializeHTMLTagAndClass(node_data);

  String display_style;
  if (Element* element = GetElement()) {
    if (const ComputedStyle* computed_style = element->GetComputedStyle()) {
      display_style = CSSProperty::Get(CSSPropertyID::kDisplay)
                          .CSSValueFromComputedStyle(
                              *computed_style, /* layout_object */ nullptr,
                              /* allow_visited_style */ false,
                              CSSValuePhase::kComputedValue)
                          ->CssText();
      if (!display_style.empty()) {
        TruncateAndAddStringAttribute(
            node_data, ax::mojom::blink::StringAttribute::kDisplay,
            display_style);
      }
    }

    // Whether it has ARIA attributes at all.
    if (ElementHasAnyAriaAttribute()) {
      node_data->AddBoolAttribute(
          ax::mojom::blink::BoolAttribute::kHasAriaAttribute, true);
    }
  }

  if (KeyboardShortcut().length() &&
      !node_data->HasStringAttribute(
          ax::mojom::blink::StringAttribute::kKeyShortcuts)) {
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kKeyShortcuts,
        KeyboardShortcut());
  }

  if (AXObject* active_descendant = ActiveDescendant()) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kActivedescendantId,
        active_descendant->AXObjectID());
  }
}

String AXObject::KeyboardShortcut() const {
  const AtomicString& access_key = AccessKey();
  if (access_key.IsNull())
    return String();

  DEFINE_STATIC_LOCAL(String, modifier_string, ());
  if (modifier_string.IsNull()) {
    unsigned modifiers = KeyboardEventManager::kAccessKeyModifiers;
    // Follow the same order as Mozilla MSAA implementation:
    // Ctrl+Alt+Shift+Meta+key. MSDN states that keyboard shortcut strings
    // should not be localized and defines the separator as "+".
    StringBuilder modifier_string_builder;
    if (modifiers & WebInputEvent::kControlKey)
      modifier_string_builder.Append("Ctrl+");
    if (modifiers & WebInputEvent::kAltKey)
      modifier_string_builder.Append("Alt+");
    if (modifiers & WebInputEvent::kShiftKey)
      modifier_string_builder.Append("Shift+");
    if (modifiers & WebInputEvent::kMetaKey)
      modifier_string_builder.Append("Win+");
    modifier_string = modifier_string_builder.ToString();
  }

  return String(modifier_string + access_key);
}

void AXObject::SerializeOtherScreenReaderAttributes(
    ui::AXNodeData* node_data) const {
  DCHECK_NE(node_data->role, ax::mojom::blink::Role::kUnknown);

  if (IsA<Document>(GetNode())) {
    // The busy attribute is only relevant for actual Documents, not popups.
    if (RoleValue() == ax::mojom::blink::Role::kRootWebArea && !IsLoaded()) {
      node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kBusy, true);
    }

    if (AXObject* parent = ParentObject()) {
      DCHECK(parent->ChooserPopup() == this)
          << "ChooserPopup missing for: " << parent;
      node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kPopupForId,
                                 parent->AXObjectID());
    }
  } else {
    SerializeLineAttributes(node_data);
  }

  if (node_data->role == ax::mojom::blink::Role::kColorWell) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kColorValue,
                               ColorValue());
  }

  if (node_data->role == ax::mojom::blink::Role::kLink) {
    AXObject* target = InPageLinkTarget();
    if (target) {
      int32_t target_id = target->AXObjectID();
      node_data->AddIntAttribute(
          ax::mojom::blink::IntAttribute::kInPageLinkTargetId, target_id);
    }

    // `ax::mojom::blink::StringAttribute::kLinkTarget` is only valid on <a> and
    // <area> elements. <area> elements should link to something in order to be
    // considered, see `AXImageMap::Role()`.
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kLinkTarget,
        EffectiveTarget());
  }

  if (node_data->role == ax::mojom::blink::Role::kRadioButton) {
    AddIntListAttributeFromObjects(
        ax::mojom::blink::IntListAttribute::kRadioGroupIds,
        RadioButtonsInGroup(), node_data);
  }

  if (GetAriaCurrentState() != ax::mojom::blink::AriaCurrentState::kNone) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kAriaCurrentState,
        static_cast<int32_t>(GetAriaCurrentState()));
  }

  if (GetInvalidState() != ax::mojom::blink::InvalidState::kNone)
    node_data->SetInvalidState(GetInvalidState());

  if (CheckedState() != ax::mojom::blink::CheckedState::kNone) {
    node_data->SetCheckedState(CheckedState());
  }

  if (node_data->role == ax::mojom::blink::Role::kListMarker) {
    SerializeListMarkerAttributes(node_data);
  }

  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kAccessKey, AccessKey());

  TruncateAndAddStringAttribute(
      node_data, ax::mojom::blink::StringAttribute::kAutoComplete,
      AutoComplete());

  if (Action() != ax::mojom::blink::DefaultActionVerb::kNone) {
    node_data->SetDefaultActionVerb(Action());
  }

  AXObjectVector error_messages = ErrorMessage();
  if (error_messages.size() > 0) {
    AddIntListAttributeFromObjects(
        ax::mojom::blink::IntListAttribute::kErrormessageIds, error_messages,
        node_data);
  }

  if (ui::SupportsHierarchicalLevel(node_data->role) && HierarchicalLevel()) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kHierarchicalLevel,
        HierarchicalLevel());
  }

  if (CanvasHasFallbackContent()) {
    node_data->AddBoolAttribute(
        ax::mojom::blink::BoolAttribute::kCanvasHasFallback, true);
  }

  if (IsRangeValueSupported()) {
    float value;
    if (ValueForRange(&value)) {
      node_data->AddFloatAttribute(
          ax::mojom::blink::FloatAttribute::kValueForRange, value);
    }

    float max_value;
    if (MaxValueForRange(&max_value)) {
      node_data->AddFloatAttribute(
          ax::mojom::blink::FloatAttribute::kMaxValueForRange, max_value);
    }

    float min_value;
    if (MinValueForRange(&min_value)) {
      node_data->AddFloatAttribute(
          ax::mojom::blink::FloatAttribute::kMinValueForRange, min_value);
    }

    float step_value;
    if (StepValueForRange(&step_value)) {
      node_data->AddFloatAttribute(
          ax::mojom::blink::FloatAttribute::kStepValueForRange, step_value);
    }
  }

  if (ui::IsDialog(node_data->role)) {
    node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kModal,
                                IsModal());
  }
}

void AXObject::SerializeMathContent(ui::AXNodeData* node_data) const {
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_CHROMEOS)
  const Element* element = GetElement();
  if (!element) {
    return;
  }
  if (node_data->role == ax::mojom::blink::Role::kMath ||
      node_data->role == ax::mojom::blink::Role::kMathMLMath) {
    TruncateAndAddStringAttribute(
        node_data, ax::mojom::blink::StringAttribute::kMathContent,
        element->innerHTML(), kMaxStaticTextLength);
  }
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_CHROMEOS)
}

void AXObject::SerializeScrollAttributes(ui::AXNodeData* node_data) const {
  // Only mark as scrollable if user has actual scrollbars to use.
  node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kScrollable,
                              IsUserScrollable());
  // Provide x,y scroll info if scrollable in any way (programmatically or via
  // user).
  gfx::Point scroll_offset = GetScrollOffset();
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollX,
                             scroll_offset.x());
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollY,
                             scroll_offset.y());

  gfx::Point min_scroll_offset = MinimumScrollOffset();
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollXMin,
                             min_scroll_offset.x());
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollYMin,
                             min_scroll_offset.y());

  gfx::Point max_scroll_offset = MaximumScrollOffset();
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollXMax,
                             max_scroll_offset.x());
  node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kScrollYMax,
                             max_scroll_offset.y());
}

void AXObject::SerializeRelationAttributes(ui::AXNodeData* node_data) const {
  // No need to call this for objects without an element, as relations are
  // only possible between elements.
  DCHECK(GetElement());

  // TODO(accessibility) Consider checking role before serializing
  // aria-activedescendant, aria-errormessage.

  if (AXObject* active_descendant = ActiveDescendant()) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kActivedescendantId,
        active_descendant->AXObjectID());
  }

  if (RuntimeEnabledFeatures::AriaActionsEnabled()) {
    AddIntListAttributeFromObjects(
        ax::mojom::blink::IntListAttribute::kActionsIds,
        RelationVectorFromAria(html_names::kAriaActionsAttr), node_data);
  }

  AddIntListAttributeFromObjects(
      ax::mojom::blink::IntListAttribute::kControlsIds,
      RelationVectorFromAria(html_names::kAriaControlsAttr), node_data);
  AddIntListAttributeFromObjects(
      ax::mojom::blink::IntListAttribute::kDetailsIds,
      RelationVectorFromAria(html_names::kAriaDetailsAttr), node_data);
  AddIntListAttributeFromObjects(
      ax::mojom::blink::IntListAttribute::kFlowtoIds,
      RelationVectorFromAria(html_names::kAriaFlowtoAttr), node_data);
}

void AXObject::SerializeStyleAttributes(ui::AXNodeData* node_data) const {
  // Only serialize font family if there is one, and it is different from the
  // parent. Use the value from computed style first since that is a fast lookup
  // and comparison, and serialize the user-friendly name at points in the tree
  // where the font family changes between parent/child.
  // TODO(accessibility) No need to serialize these for inline text boxes.
  const AtomicString& computed_family = ComputedFontFamily();
  if (computed_family.length()) {
    AXObject* parent = ParentObjectUnignored();
    if (!parent || parent->ComputedFontFamily() != computed_family) {
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kFontFamily,
          FontFamilyForSerialization());
    }
  }

  // Font size is in pixels.
  if (FontSize()) {
    node_data->AddFloatAttribute(ax::mojom::blink::FloatAttribute::kFontSize,
                                 FontSize());
  }

  if (FontWeight()) {
    node_data->AddFloatAttribute(ax::mojom::blink::FloatAttribute::kFontWeight,
                                 FontWeight());
  }

  if (RoleValue() == ax::mojom::blink::Role::kListItem &&
      GetListStyle() != ax::mojom::blink::ListStyle::kNone) {
    node_data->SetListStyle(GetListStyle());
  }

  if (GetTextAlign() != ax::mojom::blink::TextAlign::kNone) {
    node_data->SetTextAlign(GetTextAlign());
  }

  if (GetTextIndent() != 0.0f) {
    node_data->AddFloatAttribute(ax::mojom::blink::FloatAttribute::kTextIndent,
                                 GetTextIndent());
  }

  if (GetTextDirection() != ax::mojom::blink::WritingDirection::kNone) {
    node_data->SetTextDirection(GetTextDirection());
  }

  if (GetTextPosition() != ax::mojom::blink::TextPosition::kNone) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kTextPosition,
                               static_cast<int32_t>(GetTextPosition()));
  }

  int32_t text_style = 0;
  ax::mojom::blink::TextDecorationStyle text_overline_style;
  ax::mojom::blink::TextDecorationStyle text_strikethrough_style;
  ax::mojom::blink::TextDecorationStyle text_underline_style;
  GetTextStyleAndTextDecorationStyle(&text_style, &text_overline_style,
                                     &text_strikethrough_style,
                                     &text_underline_style);
  if (text_style) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kTextStyle,
                               text_style);
  }

  if (text_overline_style != ax::mojom::blink::TextDecorationStyle::kNone) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kTextOverlineStyle,
        static_cast<int32_t>(text_overline_style));
  }

  if (text_strikethrough_style !=
      ax::mojom::blink::TextDecorationStyle::kNone) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kTextStrikethroughStyle,
        static_cast<int32_t>(text_strikethrough_style));
  }

  if (text_underline_style != ax::mojom::blink::TextDecorationStyle::kNone) {
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kTextUnderlineStyle,
        static_cast<int32_t>(text_underline_style));
  }
}

void AXObject::SerializeTableAttributes(ui::AXNodeData* node_data) const {
  if (ui::IsTableLike(RoleValue())) {
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaColumnCount,
                    html_names::kAriaColcountAttr, node_data,
                    ColumnCount() + 1);
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaRowCount,
                    html_names::kAriaRowcountAttr, node_data, RowCount() + 1);
  }

  if (ui::IsTableRow(RoleValue())) {
    AXObject* header = HeaderObject();
    if (header && !header->IsDetached()) {
      // TODO(accessibility): these should be computed by ui::AXTableInfo and
      // removed here.
      node_data->AddIntAttribute(
          ax::mojom::blink::IntAttribute::kTableRowHeaderId,
          header->AXObjectID());
    }
  }

  if (ui::IsCellOrTableHeader(RoleValue())) {
    // Both HTML rowspan/colspan and ARIA rowspan/colspan are serialized.
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaCellColumnSpan,
                    html_names::kAriaColspanAttr, node_data, 1);
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kTableCellColumnSpan, ColumnSpan());
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaCellRowSpan,
                    html_names::kAriaRowspanAttr, node_data, 1);
    node_data->AddIntAttribute(
        ax::mojom::blink::IntAttribute::kTableCellRowSpan, RowSpan());
  }

  if (ui::IsCellOrTableHeader(RoleValue()) || ui::IsTableRow(RoleValue())) {
    // aria-rowindex and aria-colindex are supported on cells, headers and
    // rows.
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaCellRowIndex,
                    html_names::kAriaRowindexAttr, node_data, 1);
    AddIntAttribute(this, ax::mojom::blink::IntAttribute::kAriaCellColumnIndex,
                    html_names::kAriaColindexAttr, node_data, 1);
    if (RuntimeEnabledFeatures::AriaRowColIndexTextEnabled()) {
      // TODO(accessibility): Remove deprecated attribute support for
      // aria-rowtext/aria-coltext once Sheets uses standard attribute names
      // aria-rowindextext/aria-colindextext.
      AtomicString aria_cell_row_index_text =
          AriaAttribute(html_names::kAriaRowindextextAttr);
      if (aria_cell_row_index_text.empty()) {
        aria_cell_row_index_text =
            AriaAttribute(DeprecatedAriaRowtextAttrName());
      }
      TruncateAndAddStringAttribute(
          node_data, ax::mojom::blink::StringAttribute::kAriaCellRowIndexText,
          aria_cell_row_index_text);
      AtomicString aria_cell_column_index_text =
          AriaAttribute(html_names::kAriaColindextextAttr);
      if (aria_cell_column_index_text.empty()) {
        aria_cell_column_index_text =
            AriaAttribute(DeprecatedAriaColtextAttrName());
      }
      TruncateAndAddStringAttribute(
          node_data,
          ax::mojom::blink::StringAttribute::kAriaCellColumnIndexText,
          aria_cell_column_index_text);
    }
  }

  if (ui::IsTableHeader(RoleValue()) &&
      GetSortDirection() != ax::mojom::blink::SortDirection::kNone) {
    node_data->AddIntAttribute(ax::mojom::blink::IntAttribute::kSortDirection,
                               static_cast<int32_t>(GetSortDirection()));
  }
}

// Attributes that don't need to be serialized on ignored nodes.
void AXObject::SerializeUnignoredAttributes(ui::AXNodeData* node_data,
                                            ui::AXMode accessibility_mode,
                                            bool is_snapshot) const {
  SerializeNameAndDescriptionAttributes(accessibility_mode, node_data);

  if (accessibility_mode.has_mode(ui::AXMode::kScreenReader)) {
    SerializeMarkerAttributes(node_data);
#if BUILDFLAG(IS_ANDROID)
    // On Android, style attributes are only serialized for snapshots.
    if (is_snapshot) {
      SerializeStyleAttributes(node_data);
    }
#else
    SerializeStyleAttributes(node_data);
#endif
  }

  if (IsLinked()) {
    node_data->AddState(ax::mojom::blink::State::kLinked);
    if (IsVisited()) {
      node_data->AddState(ax::mojom::blink::State::kVisited);
    }
  }

  if (IsNotUserSelectable()) {
    node_data->AddBoolAttribute(
        ax::mojom::blink::BoolAttribute::kNotUserSelectableStyle, true);
  }

  // If text, return early as a performance tweak, as the rest of the properties
  // in this method do not apply to text.
  if (RoleValue() == ax::mojom::blink::Role::kStaticText) {
    return;
  }

  AccessibilityExpanded expanded = IsExpanded();
  if (expanded) {
    if (expanded == kExpandedCollapsed)
      node_data->AddState(ax::mojom::blink::State::kCollapsed);
    else if (expanded == kExpandedExpanded)
      node_data->AddState(ax::mojom::blink::State::kExpanded);
  }

  ax::mojom::blink::Role role = RoleValue();
  if (HasPopup() != ax::mojom::blink::HasPopup::kFalse) {
    node_data->SetHasPopup(HasPopup());
  } else if (role == ax::mojom::blink::Role::kPopUpButton ||
             role == ax::mojom::blink::Role::kComboBoxSelect) {
    node_data->SetHasPopup(ax::mojom::blink::HasPopup::kMenu);
  } else if (ui::IsComboBox(role)) {
    node_data->SetHasPopup(ax::mojom::blink::HasPopup::kListbox);
  }

  if (IsPopup() != ax::mojom::blink::IsPopup::kNone) {
    node_data->SetIsPopup(IsPopup());
  }

  if (IsAutofillAvailable())
    node_data->AddState(ax::mojom::blink::State::kAutofillAvailable);

  if (IsDefault())
    node_data->AddState(ax::mojom::blink::State::kDefault);

  if (IsHovered())
    node_data->AddState(ax::mojom::blink::State::kHovered);

  if (IsMultiline())
    node_data->AddState(ax::mojom::blink::State::kMultiline);

  if (IsMultiSelectable())
    node_data->AddState(ax::mojom::blink::State::kMultiselectable);

  if (IsPasswordField())
    node_data->AddState(ax::mojom::blink::State::kProtected);

  if (IsRequired())
    node_data->AddState(ax::mojom::blink::State::kRequired);

  if (IsSelected() != blink::kSelectedStateUndefined) {
    node_data->AddBoolAttribute(ax::mojom::blink::BoolAttribute::kSelected,
                                IsSelected() == blink::kSelectedStateTrue);
    node_data->AddBoolAttribute(
        ax::mojom::blink::BoolAttribute::kSelectedFromFocus,
        IsSelectedFromFocus());
  }

  if (Orientation() == kAccessibilityOrientationVertical)
    node_data->AddState(ax::mojom::blink::State::kVertical);
  else if (Orientation() == blink::kAccessibilityOrientationHorizontal)
    node_data->AddState(ax::mojom::blink::State::kHorizontal);

  if (accessibility_mode.has_mode(ui::AXMode::kScreenReader) ||
      accessibility_mode.has_mode(ui::AXMode::kPDFPrinting)) {
    // Heading level.
    if (ui::IsHeading(role) && HeadingLevel()) {
      node_data->AddIntAttribute(
          ax::mojom::blink::IntAttribute::kHierarchicalLevel, HeadingLevel());
    }

    SerializeListAttributes(node_data);
    SerializeTableAttributes(node_data);
  }

  if (accessibility_mode.has_mode(ui::AXMode::kPDFPrinting)) {
    // Return early. None of the following attributes are needed for PDFs.
    return;
  }

  switch (Restriction()) {
    case AXRestriction::kRestrictionReadOnly:
      node_data->SetRestriction(ax::mojom::blink::Restriction::kReadOnly);
      break;
    case AXRestriction::kRestrictionDisabled:
      node_data->SetRestriction(ax::mojom::blink::Restriction::kDisabled);
      break;
    case AXRestriction::kRestrictionNone:
      SerializeActionAttributes(node_data);
      break;
  }

  TruncateAndAddStringAttribute(
```