Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `ax_node_object.cc` file. I need to identify the main purpose of this code and highlight its connections to web technologies like JavaScript, HTML, and CSS. I should also provide examples, consider potential user errors, outline debugging steps, and finally, summarize the overall function as the 9th part of a 10-part series.

Here's a breakdown of how I'll approach this:

1. **Identify the core functionality:** The code deals with accessibility (AX). It has functions like `Description`, `SVGDescription`, `Placeholder`, and `Title`, suggesting it's involved in determining accessible names and descriptions for web elements.

2. **Analyze the relationship with HTML:**  The code directly interacts with HTML elements and attributes (e.g., `aria-describedby`, `aria-label`, `title`, `placeholder`, `<desc>`, `<title>`, `<caption>`, `<summary>`, `interesttarget`, `popovertarget`). It uses `GetElement()` and checks tag names. I'll need to provide examples of how these HTML elements and attributes influence the accessible description.

3. **Analyze the relationship with CSS:** While not as direct as with HTML, the code interacts with the layout tree (`GetLayoutObject()`, `IsInline()`, `IsAtomicInlineLevel()`) which is influenced by CSS. I'll need to point out how CSS properties affecting layout (like `display: inline` or `display: inline-block`) might indirectly affect the accessibility tree and how this code handles inline elements.

4. **Analyze the relationship with JavaScript:** The code doesn't directly interact with JavaScript in this snippet. However, JavaScript can dynamically modify HTML attributes that this code reads (e.g., using `setAttribute` to change `aria-label`). I should mention this indirect relationship.

5. **Provide examples:** I'll create scenarios with HTML, CSS (briefly), and how JavaScript could interact, showing how the code determines the accessible description.

6. **Consider logical reasoning (hypothetical input/output):** I can demonstrate how, for a given HTML snippet, the code would determine the accessible description based on the order of precedence of ARIA attributes, native attributes, and element content.

7. **Identify common user errors:** Users might misuse ARIA attributes (e.g., incorrect syntax, applying them to inappropriate elements) or rely on visual cues instead of providing proper accessible descriptions. I'll give examples of these mistakes.

8. **Outline debugging steps:**  Explain how a developer might end up inspecting this code, perhaps when troubleshooting accessibility issues, like an incorrect accessible name or description being reported by assistive technologies. I'll trace a possible user interaction leading to this code.

9. **Summarize the functionality:**  Condense the above points into a concise summary, emphasizing the code's role in calculating accessible descriptions for web elements based on various sources.

10. **Address the "part 9 of 10" instruction:**  I'll frame the summary as a key component of the accessibility calculation process, hinting at the existence of other related parts.

**(Self-correction/Refinement):**  Initially, I might focus too heavily on the technical details of the C++ code. I need to remember the target audience and explain the concepts in a way that connects to web development practices. Also, the prompt asks for "features" (功能), so I need to frame the explanation around what the code *does* rather than just what it *is*. I need to be careful not to overstate the direct influence of CSS; its impact is more indirect. I also need to ensure the debugging steps are practical and relate to common accessibility debugging workflows.
好的，让我们来分析一下 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件中提供的代码片段的功能。

**核心功能：计算可访问描述 (Accessible Description)**

这段代码的主要功能是为一个 `AXNodeObject` 计算其可访问描述 (Accessible Description)。可访问描述是提供关于元素的额外信息的文本，用于辅助技术（例如屏幕阅读器）向用户传达元素的用途和上下文。

**与 JavaScript, HTML, CSS 的关系：**

这段代码与 HTML 结构和 ARIA 属性紧密相关，并且间接地受到 CSS 的影响。

* **HTML:**
    * 代码直接检查 HTML 元素和属性，例如：
        * `aria-describedby` 属性：通过 `ElementsFromAttributeOrInternals` 方法获取引用的元素，并从中提取文本作为描述。
        * `aria-description` 属性：直接读取该属性的值作为描述。
        * `<desc>` 和 `<title>` 元素（在 SVG 中）：用于提供 SVG 元素的描述。
        * `value` 属性（对于某些 input 元素）：作为按钮的描述。
        * `<caption>` 元素（对于 table）：作为表格的描述。
        * `<summary>` 元素（对于 details 元素）：作为 details 的描述。
        * `title` 属性：作为描述的来源之一。
        * `interesttarget` 属性：引用作为兴趣目标的元素，并使用其内容作为描述。
        * `popovertarget` 属性：引用作为弹出框目标的元素，并使用其内容作为描述。
        * `<rt>` 元素（在 ruby 注释中）：提取其内容作为描述。
    * 代码通过 `GetElement()` 方法获取关联的 HTML 元素。
    * 代码使用 `HasTagName` 等方法来判断元素的类型。

    **举例说明：**

    ```html
    <p id="info">更多信息请参考这里。</p>
    <button aria-describedby="info">点击我</button>
    ```
    在这个例子中，当计算 "点击我" 按钮的可访问描述时，`AXNodeObject::Description` 函数会找到 `aria-describedby` 属性，并使用 `ElementsFromAttributeOrInternals` 找到 `id` 为 "info" 的 `<p>` 元素。然后，它会提取 `<p>` 元素中的文本 "更多信息请参考这里。" 作为按钮的可访问描述。

* **JavaScript:**
    * JavaScript 可以动态地修改 HTML 结构和属性，包括用于计算可访问描述的 ARIA 属性。因此，JavaScript 的操作会间接地影响这段代码的输出。
    * 例如，JavaScript 可以使用 `setAttribute` 方法来动态设置 `aria-describedby` 属性，从而改变元素的可访问描述。

    **举例说明：**

    ```javascript
    const button = document.querySelector('button');
    const infoParagraph = document.createElement('p');
    infoParagraph.textContent = '这是动态添加的描述。';
    infoParagraph.id = 'dynamic-info';
    document.body.appendChild(infoParagraph);
    button.setAttribute('aria-describedby', 'dynamic-info');
    ```
    在这个例子中，JavaScript 代码动态创建了一个段落并将其添加到页面中，然后使用 `setAttribute` 将按钮的 `aria-describedby` 属性设置为指向新创建的段落。当重新计算按钮的可访问描述时，`AXNodeObject::Description` 函数会使用新指向的元素的内容。

* **CSS:**
    * CSS 主要负责视觉呈现，但它可以通过影响元素的渲染方式（例如，`display: none` 或 `visibility: hidden`）来间接地影响辅助技术所能访问到的信息。虽然这段代码本身不直接处理 CSS，但元素的可见性会影响其是否被包含在可访问性树中，从而影响其描述是否会被计算。
    * 此外，CSS 的一些属性可能会影响文本的呈现，但这部分通常在提取文本内容后进行处理。

**逻辑推理 (假设输入与输出)：**

假设我们有以下 HTML 片段：

```html
<img src="cat.jpg" alt="一只可爱的猫" title="胖橘"/>
```

假设我们正在计算这个 `<img>` 元素的 `AXNodeObject` 的可访问描述，并且没有设置 `aria-describedby` 或 `aria-description` 属性。

* **假设输入：**
    * `name_from`:  某个值，例如 `ax::mojom::blink::NameFrom::kAttribute` (因为 alt 属性会作为名称)
    * `description_from`:  初始状态
    * 没有 `aria-describedby` 属性
    * 没有 `aria-description` 属性
    * 存在 `title` 属性 "胖橘"
    * `GetElement()->GetInnerTextWithoutUpdate()` 返回空字符串（因为 `<img>` 元素没有子文本内容）

* **逻辑推理过程：**
    1. 首先检查 `aria-describedby`，不存在。
    2. 然后检查 `aria-description`，不存在。
    3. 接下来检查 SVG 相关的描述（如果元素是 SVG），这里是 `<img>`，所以跳过。
    4. 检查 `value` 属性对于特定的 input 类型，这里是 `<img>`，跳过。
    5. 检查 ruby 注释，跳过。
    6. 检查表格标题，跳过。
    7. 检查 summary 元素，跳过。
    8. 检查 `title` 属性。`title` 属性存在，值为 "胖橘"。
    9. 比较 `title` 属性的值和元素的内部文本（空字符串）。两者不相同。

* **预期输出：**
    * `description`: "胖橘"
    * `description_from`: `ax::mojom::blink::DescriptionFrom::kTitle`

**用户或编程常见的使用错误：**

1. **过度依赖 `title` 属性作为描述：** `title` 属性通常作为鼠标悬停时的提示信息，但对于可访问性来说，`aria-describedby` 或 `aria-description` 提供了更清晰的语义关联。

    **错误示例：**

    ```html
    <button title="点击提交表单">提交</button>
    ```
    屏幕阅读器可能会读取 "提交"，但用户无法知道 "点击提交表单" 这个更完整的描述。应该使用 `aria-describedby` 指向一个包含完整描述的元素。

2. **`aria-describedby` 指向不存在或不相关的元素：** 这会导致辅助技术无法找到描述信息。

    **错误示例：**

    ```html
    <button aria-describedby="non-existent-id">操作</button>
    ```

3. **`aria-describedby` 指向的元素内容不明确或冗余：** 描述应该简洁明了，提供必要的上下文信息。

    **错误示例：**

    ```html
    <p id="desc">这个按钮的功能是用来执行特定的操作，当用户点击它时，会触发服务器端的处理，并且在成功完成后会显示相应的提示信息。</p>
    <button aria-describedby="desc">执行</button>
    ```
    更好的做法是提供更简洁的描述，例如 "执行操作"。

4. **混淆 `aria-label` 和 `aria-describedby` 的用途：** `aria-label` 用于提供元素的 **名称**，而 `aria-describedby` 用于提供元素的 **描述**。

    **错误示例：**

    ```html
    <button aria-label="这个按钮执行提交操作。" >提交</button>
    ```
    这里本意可能是提供描述，但错误地使用了 `aria-label`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户与网页交互：** 用户使用屏幕阅读器等辅助技术浏览网页。
2. **辅助技术请求信息：** 当焦点移动到一个元素上时，屏幕阅读器会请求该元素的可访问信息，包括名称、角色和描述。
3. **浏览器处理请求：** 浏览器会调用 Blink 引擎的 Accessibility 模块来构建可访问性树 (Accessibility Tree)。
4. **创建 `AXNodeObject`：**  对于 HTML 元素，会创建相应的 `AXNodeObject`。
5. **计算描述信息：**  屏幕阅读器请求元素的描述信息时，会调用 `AXNodeObject::Description` 方法。
6. **代码执行：**  `AXNodeObject::Description` 方法会按照定义的逻辑，检查各种可能的描述来源（ARIA 属性、原生属性、子元素等），并返回最终的描述字符串。

**调试线索：** 如果辅助技术报告的元素描述不正确，开发者可能会：

* 使用浏览器的辅助功能检查工具（例如 Chrome DevTools 的 Accessibility 标签）来查看元素的可访问属性，包括计算出的描述。
* 如果描述来源是 `aria-describedby`，检查该属性指向的元素是否存在，内容是否正确。
* 检查元素是否有 `aria-description` 或 `title` 属性，以及它们的值是否符合预期。
* 断点调试 `AXNodeObject::Description` 函数，跟踪代码的执行流程，查看哪个描述来源被选中。

**作为第 9 部分，共 10 部分，请归纳一下它的功能：**

作为构建可访问性树和提供辅助技术所需信息的关键环节，`AXNodeObject::Description` 函数负责确定一个 `AXNodeObject` 的可访问描述。它是整个可访问性计算流程中的一个重要组成部分，确保了网页内容的含义能够被不同能力的用户理解和使用。 这部分代码专注于从多种来源（包括 ARIA 属性、原生 HTML 属性和特定的 HTML 元素）收集并确定最合适的描述信息，为最终呈现给辅助技术的可访问性信息奠定了基础。 可以推测，其他部分可能涉及可访问性名称的计算、角色确定、事件处理以及与操作系统辅助功能 API 的交互等。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
ription = DatetimeAncestor()->Description(
        datetime_ancestor_name_from, description_from, description_objects);
    if (!result.empty() && !ancestor_description.empty())
      return result + " " + ancestor_description;
    if (!ancestor_description.empty())
      return ancestor_description;
  }

  return result;
}

// Based on
// http://rawgit.com/w3c/aria/master/html-aam/html-aam.html#accessible-name-and-description-calculation
String AXNodeObject::Description(
    ax::mojom::blink::NameFrom name_from,
    ax::mojom::blink::DescriptionFrom& description_from,
    DescriptionSources* description_sources,
    AXRelatedObjectVector* related_objects) const {
  // If descriptionSources is non-null, relatedObjects is used in filling it in,
  // so it must be non-null as well.
  // Important: create a DescriptionSource for every *potential* description
  // source, even if it ends up not being present.
  // When adding a new description_from type:
  // * Also add it to AXValueNativeSourceType here:
  //   blink/public/devtools_protocol/browser_protocol.pdl
  // * Update InspectorTypeBuilderHelper to map the new enum to
  //   the browser_protocol enum in NativeSourceType():
  //   blink/renderer/modules/accessibility/inspector_type_builder_helper.cc
  // * Update devtools_frontend to add a new string for the new type of
  //   description. See AXNativeSourceTypes at:
  //   devtools-frontend/src/front_end/accessibility/AccessibilityStrings.js
  if (description_sources)
    DCHECK(related_objects);

  if (!GetNode())
    return String();

  String description;
  bool found_description = false;

  description_from = ax::mojom::blink::DescriptionFrom::kRelatedElement;
  if (description_sources) {
    description_sources->push_back(
        DescriptionSource(found_description, html_names::kAriaDescribedbyAttr));
    description_sources->back().type = description_from;
  }

  // aria-describedby overrides any other accessible description, from:
  // http://rawgit.com/w3c/aria/master/html-aam/html-aam.html
  Element* element = GetElement();
  if (!element)
    return String();

  const HeapVector<Member<Element>>* elements_from_attribute =
      ElementsFromAttributeOrInternals(element,
                                       html_names::kAriaDescribedbyAttr);
  if (elements_from_attribute) {
    // TODO(meredithl): Determine description sources when |aria_describedby| is
    // the empty string, in order to make devtools work with attr-associated
    // elements.
    if (description_sources) {
      description_sources->back().attribute_value =
          AriaAttribute(html_names::kAriaDescribedbyAttr);
    }
    AXObjectSet visited;
    description = TextFromElements(true, visited, *elements_from_attribute,
                                   related_objects);

    if (!description.IsNull()) {
      if (description_sources) {
        DescriptionSource& source = description_sources->back();
        source.type = description_from;
        source.related_objects = *related_objects;
        source.text = description;
        found_description = true;
      } else {
        return description;
      }
    } else if (description_sources) {
      description_sources->back().invalid = true;
    }
  }

  // aria-description overrides any HTML-based accessible description,
  // but not aria-describedby.
  const AtomicString& aria_desc =
      AriaAttribute(html_names::kAriaDescriptionAttr);
  if (aria_desc) {
    description_from = ax::mojom::blink::DescriptionFrom::kAriaDescription;
    description = aria_desc;
    if (description_sources) {
      found_description = true;
      description_sources->back().text = description;
    } else {
      return description;
    }
  }

  // SVG-AAM specifies additional description sources when ARIA sources have not
  // been found. https://w3c.github.io/svg-aam/#mapping_additional_nd
  if (IsA<SVGElement>(GetNode())) {
    String svg_description = SVGDescription(
        name_from, description_from, description_sources, related_objects);
    if (!svg_description.empty()) {
      return svg_description;
    }
  }

  const auto* input_element = DynamicTo<HTMLInputElement>(GetNode());

  // value, 5.2.2 from: https://www.w3.org/TR/html-aam-1.0/
  if (name_from != ax::mojom::blink::NameFrom::kValue && input_element &&
      input_element->IsTextButton()) {
    description_from = ax::mojom::blink::DescriptionFrom::kButtonLabel;
    if (description_sources) {
      description_sources->push_back(
          DescriptionSource(found_description, kValueAttr));
      description_sources->back().type = description_from;
    }
    String value = input_element->Value();
    if (!value.IsNull()) {
      description = value;
      if (description_sources) {
        DescriptionSource& source = description_sources->back();
        source.text = description;
        found_description = true;
      } else {
        return description;
      }
    }
  }

  if (RoleValue() == ax::mojom::blink::Role::kRuby) {
    description_from = ax::mojom::blink::DescriptionFrom::kRubyAnnotation;
    if (description_sources) {
      description_sources->push_back(DescriptionSource(found_description));
      description_sources->back().type = description_from;
      description_sources->back().native_source =
          kAXTextFromNativeHTMLRubyAnnotation;
    }
    AXObject* ruby_annotation_ax_object = nullptr;
    for (const auto& child : children_) {
      if (child->RoleValue() == ax::mojom::blink::Role::kRubyAnnotation &&
          child->GetNode() &&
          child->GetNode()->HasTagName(html_names::kRtTag)) {
        ruby_annotation_ax_object = child;
        break;
      }
    }
    if (ruby_annotation_ax_object) {
      AXObjectSet visited;
      description =
          RecursiveTextAlternative(*ruby_annotation_ax_object, this, visited);
      if (related_objects) {
        related_objects->push_back(
            MakeGarbageCollected<NameSourceRelatedObject>(
                ruby_annotation_ax_object, description));
      }
      if (description_sources) {
        DescriptionSource& source = description_sources->back();
        source.related_objects = *related_objects;
        source.text = description;
        found_description = true;
      } else {
        return description;
      }
    }
  }

  // table caption, 5.9.2 from: https://www.w3.org/TR/html-aam-1.0/
  auto* table_element = DynamicTo<HTMLTableElement>(element);
  if (name_from != ax::mojom::blink::NameFrom::kCaption && table_element) {
    description_from = ax::mojom::blink::DescriptionFrom::kTableCaption;
    if (description_sources) {
      description_sources->push_back(DescriptionSource(found_description));
      description_sources->back().type = description_from;
      description_sources->back().native_source =
          kAXTextFromNativeHTMLTableCaption;
    }
    HTMLTableCaptionElement* caption = table_element->caption();
    if (caption) {
      AXObject* caption_ax_object = AXObjectCache().Get(caption);
      if (caption_ax_object) {
        AXObjectSet visited;
        description =
            RecursiveTextAlternative(*caption_ax_object, nullptr, visited);
        if (related_objects) {
          related_objects->push_back(
              MakeGarbageCollected<NameSourceRelatedObject>(caption_ax_object,
                                                            description));
        }

        if (description_sources) {
          DescriptionSource& source = description_sources->back();
          source.related_objects = *related_objects;
          source.text = description;
          found_description = true;
        } else {
          return description;
        }
      }
    }
  }

  // summary, 5.8.2 from: https://www.w3.org/TR/html-aam-1.0/
  if (name_from != ax::mojom::blink::NameFrom::kContents &&
      IsA<HTMLSummaryElement>(GetNode())) {
    description_from = ax::mojom::blink::DescriptionFrom::kSummary;
    if (description_sources) {
      description_sources->push_back(DescriptionSource(found_description));
      description_sources->back().type = description_from;
    }

    AXObjectSet visited;
    description = TextFromDescendants(visited, nullptr, false);

    if (!description.empty()) {
      if (description_sources) {
        found_description = true;
        description_sources->back().text = description;
      } else {
        return description;
      }
    }
  }

  // title attribute, from: https://www.w3.org/TR/html-aam-1.0/
  if (name_from != ax::mojom::blink::NameFrom::kTitle) {
    description_from = ax::mojom::blink::DescriptionFrom::kTitle;
    if (description_sources) {
      description_sources->push_back(
          DescriptionSource(found_description, kTitleAttr));
      description_sources->back().type = description_from;
    }
    const AtomicString& title = GetElement()->FastGetAttribute(kTitleAttr);
    if (!title.empty() &&
        String(title).StripWhiteSpace() !=
            GetElement()->GetInnerTextWithoutUpdate().StripWhiteSpace()) {
      description = title;
      if (description_sources) {
        found_description = true;
        description_sources->back().text = description;
      } else {
        return description;
      }
    }
  }

  // For form controls that act as interest target triggering elements, use
  // the target for a description if it only contains plain contents.
  if (RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled() &&
      name_from != ax::mojom::blink::NameFrom::kInterestTarget) {
    if (Element* interest_target = GetElement()->interestTargetElement()) {
      DCHECK(RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled());
      description_from = ax::mojom::blink::DescriptionFrom::kInterestTarget;
      if (description_sources) {
        description_sources->push_back(DescriptionSource(
            found_description, html_names::kInteresttargetAttr));
        description_sources->back().type = description_from;
      }
      AXObject* interest_ax_object = AXObjectCache().Get(interest_target);
      if (interest_ax_object && interest_ax_object->IsPlainContent()) {
        AXObjectSet visited;
        description = RecursiveTextAlternative(*interest_ax_object,
                                               interest_ax_object, visited);
        if (related_objects) {
          related_objects->push_back(
              MakeGarbageCollected<NameSourceRelatedObject>(interest_ax_object,
                                                            description));
        }
        if (description_sources) {
          DescriptionSource& source = description_sources->back();
          source.related_objects = *related_objects;
          source.text = description;
          found_description = true;
        } else {
          return description;
        }
      }
    }
  }

  // For form controls that act as triggering elements for popovers of type
  // kHint, then set aria-describedby to the popover.
  if (name_from != ax::mojom::blink::NameFrom::kPopoverTarget) {
    if (auto* form_control = DynamicTo<HTMLFormControlElement>(element)) {
      auto popover_target = form_control->popoverTargetElement();
      if (popover_target.popover &&
          popover_target.popover->PopoverType() == PopoverValueType::kHint) {
        DCHECK(RuntimeEnabledFeatures::HTMLPopoverHintEnabled());
        description_from = ax::mojom::blink::DescriptionFrom::kPopoverTarget;
        if (description_sources) {
          description_sources->push_back(DescriptionSource(
              found_description, html_names::kPopovertargetAttr));
          description_sources->back().type = description_from;
        }
        AXObject* popover_ax_object =
            AXObjectCache().Get(popover_target.popover);
        if (popover_ax_object && popover_ax_object->IsPlainContent()) {
          AXObjectSet visited;
          description = RecursiveTextAlternative(*popover_ax_object,
                                                 popover_ax_object, visited);
          if (related_objects) {
            related_objects->push_back(
                MakeGarbageCollected<NameSourceRelatedObject>(popover_ax_object,
                                                              description));
          }
          if (description_sources) {
            DescriptionSource& source = description_sources->back();
            source.related_objects = *related_objects;
            source.text = description;
            found_description = true;
          } else {
            return description;
          }
        }
      }
    }
  }

  // There was a name, but it is prohibited for this role. Move to description.
  if (name_from == ax::mojom::blink::NameFrom::kProhibited) {
    description_from = ax::mojom::blink::DescriptionFrom::kProhibitedNameRepair;
    ax::mojom::blink::NameFrom orig_name_from_without_prohibited;
    HeapHashSet<Member<const AXObject>> visited;
    description = TextAlternative(false, nullptr, visited,
                                  orig_name_from_without_prohibited,
                                  related_objects, nullptr);
    DCHECK(!description.empty());
    if (description_sources) {
      description_sources->push_back(DescriptionSource(found_description));
      DescriptionSource& source = description_sources->back();
      source.type = description_from;
      source.related_objects = *related_objects;
      source.text = description;
      found_description = true;
    } else {
      return description;
    }
  }

  description_from = ax::mojom::blink::DescriptionFrom::kNone;

  if (found_description) {
    DCHECK(description_sources)
        << "Should only reach here if description_sources are tracked";
    // Use the first non-null description.
    // TODO(accessibility) Why do we need to check superceded if that will
    // always be the first one?
    for (DescriptionSource& description_source : *description_sources) {
      if (!description_source.text.IsNull() && !description_source.superseded) {
        description_from = description_source.type;
        if (!description_source.related_objects.empty())
          *related_objects = description_source.related_objects;
        return description_source.text;
      }
    }
  }

  return String();
}

String AXNodeObject::SVGDescription(
    ax::mojom::blink::NameFrom name_from,
    ax::mojom::blink::DescriptionFrom& description_from,
    DescriptionSources* description_sources,
    AXRelatedObjectVector* related_objects) const {
  DCHECK(IsA<SVGElement>(GetNode()));
  String description;
  bool found_description = false;
  Element* element = GetElement();

  description_from = ax::mojom::blink::DescriptionFrom::kSvgDescElement;
  if (description_sources) {
    description_sources->push_back(DescriptionSource(found_description));
    description_sources->back().type = description_from;
    description_sources->back().native_source = kAXTextFromNativeSVGDescElement;
  }
  if (Element* desc = ElementTraversal::FirstChild(
          *element, HasTagName(svg_names::kDescTag))) {
    // TODO(accessibility): In most cases <desc> and <title> can participate in
    // the recursive text alternative calculation. However when the <desc> or
    // <title> is the child of a <use>, |AXObjectCache::GetOrCreate| will fail
    // when |AXObject::ComputeNonARIAParent| returns null because the <use>
    // element's subtree isn't visited by LayoutTreeBuilderTraversal. In
    // addition, while aria-label and other text alternative sources are are
    // technically valid on SVG <desc> and <title>, it is not clear if user
    // agents must expose their values. Therefore until we hear otherwise, just
    // use the inner text. See https://github.com/w3c/svgwg/issues/867
    description = desc->GetInnerTextWithoutUpdate();
    if (!description.empty()) {
      if (description_sources) {
        DescriptionSource& source = description_sources->back();
        source.related_objects = *related_objects;
        source.text = description;
        found_description = true;
      } else {
        return description;
      }
    }
  }

  // If we haven't found a description source yet and the title is present,
  // SVG-AAM states to use the <title> if ARIA label attributes are used to
  // provide the accessible name.
  if (IsNameFromAriaAttribute(element)) {
    description_from = ax::mojom::blink::DescriptionFrom::kTitle;
    if (description_sources) {
      description_sources->push_back(DescriptionSource(found_description));
      description_sources->back().type = description_from;
      description_sources->back().native_source = kAXTextFromNativeTitleElement;
    }
    if (Element* title = ElementTraversal::FirstChild(
            *element, HasTagName(svg_names::kTitleTag))) {
      // TODO(accessibility): In most cases <desc> and <title> can participate
      // in the recursive text alternative calculation. However when the <desc>
      // or <title> is the child of a <use>, |AXObjectCache::GetOrCreate| will
      // fail when |AXObject::ComputeNonARIAParent| returns null because the
      // <use> element's subtree isn't visited by LayoutTreeBuilderTraversal. In
      // addition, while aria-label and other text alternative sources are are
      // technically valid on SVG <desc> and <title>, it is not clear if user
      // agents must expose their values. Therefore until we hear otherwise,
      // just use the inner text. See https://github.com/w3c/svgwg/issues/867
      description = title->GetInnerTextWithoutUpdate();
      if (!description.empty()) {
        if (description_sources) {
          DescriptionSource& source = description_sources->back();
          source.related_objects = *related_objects;
          source.text = description;
          found_description = true;
        } else {
          return description;
        }
      }
    }
  }

  // In the case of an SVG <a>, the last description source is the xlink:title
  // attribute, if it didn't serve as the name source.
  if (IsA<SVGAElement>(GetNode()) &&
      name_from != ax::mojom::blink::NameFrom::kAttribute) {
    description_from = ax::mojom::blink::DescriptionFrom::kTitle;
    const AtomicString& title_attr =
        DynamicTo<Element>(GetNode())->FastGetAttribute(
            xlink_names::kTitleAttr);
    if (!title_attr.empty()) {
      description = title_attr;
      if (description_sources) {
        found_description = true;
        description_sources->back().text = description;
      } else {
        return description;
      }
    }
  }
  return String();
}

String AXNodeObject::Placeholder(ax::mojom::blink::NameFrom name_from) const {
  if (name_from == ax::mojom::blink::NameFrom::kPlaceholder)
    return String();

  Node* node = GetNode();
  if (!node || !node->IsHTMLElement())
    return String();

  String native_placeholder = PlaceholderFromNativeAttribute();
  if (!native_placeholder.empty())
    return native_placeholder;

  const AtomicString& aria_placeholder =
      AriaAttribute(html_names::kAriaPlaceholderAttr);
  if (!aria_placeholder.empty())
    return aria_placeholder;

  return String();
}

String AXNodeObject::Title(ax::mojom::blink::NameFrom name_from) const {
  if (name_from == ax::mojom::blink::NameFrom::kTitle)
    return String();  // Already exposed the title in the name field.

  return GetTitle(GetElement());
}

String AXNodeObject::PlaceholderFromNativeAttribute() const {
  Node* node = GetNode();
  if (!node || !blink::IsTextControl(*node))
    return String();
  return ToTextControl(node)->StrippedPlaceholder();
}

String AXNodeObject::GetValueContributionToName(AXObjectSet& visited) const {
  if (IsTextField())
    return SlowGetValueForControlIncludingContentEditable();

  if (IsRangeValueSupported()) {
    const AtomicString& aria_valuetext =
        AriaAttribute(html_names::kAriaValuetextAttr);
    if (aria_valuetext) {
      return aria_valuetext.GetString();
    }
    float value;
    if (ValueForRange(&value))
      return String::Number(value);
  }

  // "If the embedded control has role combobox or listbox, return the text
  // alternative of the chosen option."
  if (UseNameFromSelectedOption()) {
    AXObjectVector selected_options;
    SelectedOptions(selected_options);
    if (selected_options.size() == 0) {
      // Per https://www.w3.org/TR/wai-aria/#combobox, a combobox gets its
      // value in the following way:
      // "If the combobox element is a host language element that provides a
      // value, such as an HTML input element, the value of the combobox is the
      // value of that element. Otherwise, the value of the combobox is
      // represented by its descendant elements and can be determined using the
      // same method used to compute the name of a button from its descendant
      // content."
      //
      // Section 2C of the accname computation steps for the combobox/listbox
      // case (https://w3c.github.io/accname/#comp_embedded_control) only
      // mentions getting the text alternative from the chosen option, which
      // doesn't precisely fit for combobox, but a clarification is coming; see
      // https://github.com/w3c/accname/issues/232 and
      // https://github.com/w3c/accname/issues/200.
      return SlowGetValueForControlIncludingContentEditable(visited);
    } else {
      StringBuilder accumulated_text;
      for (const auto& child : selected_options) {
        if (visited.insert(child).is_new_entry) {
          if (accumulated_text.length()) {
            accumulated_text.Append(" ");
          }
          accumulated_text.Append(child->ComputedName());
        }
      }
      return accumulated_text.ToString();
    }
  }

  return String();
}

bool AXNodeObject::UseNameFromSelectedOption() const {
  // Assumes that the node was reached via recursion in the name calculation.
  switch (RoleValue()) {
    // Step 2E from: http://www.w3.org/TR/accname-aam-1.1
    case ax::mojom::blink::Role::kComboBoxGrouping:
    case ax::mojom::blink::Role::kComboBoxMenuButton:
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kListBox:
      return true;
    default:
      return false;
  }
}

ScrollableArea* AXNodeObject::GetScrollableAreaIfScrollable() const {
  if (IsA<Document>(GetNode())) {
    return DocumentFrameView()->LayoutViewport();
  }

  if (auto* box = DynamicTo<LayoutBox>(GetLayoutObject())) {
    PaintLayerScrollableArea* scrollable_area = box->GetScrollableArea();
    if (scrollable_area && scrollable_area->HasOverflow()) {
      return scrollable_area;
    }
  }

  return nullptr;
}

AXObject* AXNodeObject::AccessibilityHitTest(const gfx::Point& point) const {
  // Must be called for the document's root or a popup's root.
  if (!IsA<Document>(GetNode())) {
    return nullptr;
  }

  CHECK(GetLayoutObject());

  // Must be called with lifecycle >= pre-paint clean
  DCHECK_GE(GetDocument()->Lifecycle().GetState(),
            DocumentLifecycle::kPrePaintClean);

  DCHECK(GetLayoutObject()->IsLayoutView());
  PaintLayer* layer = To<LayoutBox>(GetLayoutObject())->Layer();
  DCHECK(layer);

  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(point);
  HitTestResult hit_test_result = HitTestResult(request, location);
  layer->HitTest(location, hit_test_result, PhysicalRect(InfiniteIntRect()));

  Node* node = hit_test_result.InnerNode();
  if (!node) {
    return nullptr;
  }

  if (auto* area = DynamicTo<HTMLAreaElement>(node)) {
    return AccessibilityImageMapHitTest(area, point);
  }

  if (auto* option = DynamicTo<HTMLOptionElement>(node)) {
    node = option->OwnerSelectElement();
    if (!node) {
      return nullptr;
    }
  }

  // If |node| is in a user-agent shadow tree, reassign it as the host to hide
  // details in the shadow tree. Previously this was implemented by using
  // Retargeting (https://dom.spec.whatwg.org/#retarget), but this caused
  // elements inside regular shadow DOMs to be ignored by screen reader. See
  // crbug.com/1111800 and crbug.com/1048959.
  const TreeScope& tree_scope = node->GetTreeScope();
  if (auto* shadow_root = DynamicTo<ShadowRoot>(tree_scope.RootNode())) {
    if (shadow_root->IsUserAgent()) {
      node = &shadow_root->host();
    }
  }

  LayoutObject* obj = node->GetLayoutObject();
  AXObject* result = AXObjectCache().Get(obj);
  if (!result) {
    return nullptr;
  }

  // Allow the element to perform any hit-testing it might need to do to reach
  // non-layout children.
  result = result->ElementAccessibilityHitTest(point);

  while (result && result->IsIgnored()) {
    CHECK(!result->IsDetached());
    // If this element is the label of a control, a hit test should return the
    // control. The label is ignored because it's already reflected in the name.
    if (auto* label = DynamicTo<HTMLLabelElement>(result->GetNode())) {
      if (HTMLElement* control = label->Control()) {
        if (AXObject* ax_control = AXObjectCache().Get(control)) {
          result = ax_control;
          break;
        }
      }
    }

    result = result->ParentObject();
  }

  return result->IsIncludedInTree() ? result
                                    : result->ParentObjectIncludedInTree();
}

AXObject* AXNodeObject::AccessibilityImageMapHitTest(
    HTMLAreaElement* area,
    const gfx::Point& point) const {
  if (!area) {
    return nullptr;
  }

  AXObject* parent = AXObjectCache().Get(area->ImageElement());
  if (!parent) {
    return nullptr;
  }

  PhysicalOffset physical_point(point);
  for (const auto& child : parent->ChildrenIncludingIgnored()) {
    if (child->GetBoundsInFrameCoordinates().Contains(physical_point)) {
      return child.Get();
    }
  }

  return nullptr;
}

AXObject* AXNodeObject::GetFirstInlineBlockOrDeepestInlineAXChildInLayoutTree(
    AXObject* start_object,
    bool first) const {
  if (!start_object) {
    return nullptr;
  }

  // Return the deepest last child that is included.
  // Uses LayoutTreeBuildTraversaler to get children, in order to avoid getting
  // children unconnected to the line, e.g. via aria-owns. Doing this first also
  // avoids the issue that |start_object| may not be included in the tree.
  AXObject* result = start_object;
  Node* current_node = start_object->GetNode();
  while (current_node) {
    // If we find a node that is inline-block, we want to return it rather than
    // getting the deepest child for that. This is because these are now always
    // being included in the tree and the Next/PreviousOnLine could be set on
    // the inline-block element. We exclude list markers since those technically
    // fulfill the inline-block condition.
    AXObject* ax_object = start_object->AXObjectCache().Get(current_node);
    if (ax_object && ax_object->IsIncludedInTree() &&
        !current_node->IsMarkerPseudoElement()) {
      if (ax_object->GetLayoutObject() &&
          ax_object->GetLayoutObject()->IsInline() &&
          ax_object->GetLayoutObject()->IsAtomicInlineLevel()) {
        return ax_object;
      }
    }

    current_node = first ? LayoutTreeBuilderTraversal::FirstChild(*current_node)
                         : LayoutTreeBuilderTraversal::LastChild(*current_node);
    if (!current_node) {
      break;
    }

    AXObject* tentative_child = start_object->AXObjectCache().Get(current_node);

    if (tentative_child && tentative_child->IsIncludedInTree()) {
      result = tentative_child;
    }
  }

  // Have reached the end of LayoutTreeBuilderTraversal. From here on, traverse
  // AXObjects to get deepest descendant of pseudo element or static text,
  // such as an AXInlineTextBox.

  // Relevant static text or pseudo element is always included.
  if (!result->IsIncludedInTree()) {
    return nullptr;
  }

  // Already a leaf: return current result.
  if (!result->ChildCountIncludingIgnored()) {
    return result;
  }

  // Get deepest AXObject descendant.
  return first ? result->DeepestFirstChildIncludingIgnored()
               : result->DeepestLastChildIncludingIgnored();
}

void AXNodeObject::MaybeResetCache() const {
  uint64_t generation = AXObjectCache().GenerationalCacheId();
  if (!generational_cache_) {
    generational_cache_ = MakeGarbageCollected<GenerationalCache>();
  }
  DCHECK(AXObjectCache().IsFrozen());
  if (generation != generational_cache_->generation) {
    generational_cache_->generation = generation;
    generational_cache_->next_on_line = nullptr;
    generational_cache_->previous_on_line = nullptr;
  } else {
#if DCHECK_IS_ON()
    // AXObjects cannot be detached while the tree is frozen.
    // These are sanity checks. Limited to DCHECK enabled builds due to
    // potential performance impact with to the sheer volume of calls.
    if (AXObject* next = generational_cache_->next_on_line) {
      CHECK(!next->IsDetached());
    }
    if (AXObject* previous = generational_cache_->previous_on_line) {
      CHECK(!previous->IsDetached());
    }
#endif
  }
}

void AXNodeObject::GenerationalCache::Trace(Visitor* visitor) const {
  visitor->Trace(next_on_line);
  visitor->Trace(previous_on_line);
}

AXObject* AXNodeObject::SetNextOnLine(AXObject* next_on_line) const {
  CHECK(generational_cache_) << "Must call MaybeResetCache ahead of this call";
  generational_cache_->next_on_line = next_on_line;
  return next_on_line;
}

AXObject* AXNodeObject::SetPreviousOnLine(AXObject* previous_on_line) const {
  CHECK(generational_cache_) << "Must call MaybeResetCache ahead of this call";
  generational_cache_->previous_on_line = previous_on_line;
  return previous_on_line;
}

AXObject* AXNodeObject::NextOnLine() const {
  // If this is the last object on the line, nullptr is returned. Otherwise, all
  // inline AXNodeObjects, regardless of role and tree depth, are connected to
  // the next inline text box on the same line. If there is no inline text box,
  // they are connected to the next leaf AXObject.
  DCHECK(!IsDetached());

  MaybeResetCache();
  if (generational_cache_->next_on_line) {
    return generational_cache_->next_on_line;
  }

  const LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object) {
    return SetNextOnLine(nullptr);
  }

  if (!AXObjectCache().IsFrozen() ||
      !AXObjectCache().HasCachedDataForNodesOnLine()) {
    // TODO(crbug.com/372084397): Solve race condition for web AX API and frozen
    // states of accessibility lifecycle.
    // Not all serialization data comes from the regular flow (see
    // third_party/blink/renderer/modules/accessibility/ax_object_cache_lifecycle.h).
    // Some serialization requests come through a special test API (see
    // third_party/blink/public/web/web_ax_object.h), which requires us to force
    // the data to be computed in case it is not computed yet.
    AXObjectCache().ComputeNodesOnLine(layout_object);
  }

  if (DisplayLockUtilities::LockedAncestorPreventingPaint(*layout_object)) {
    return SetNextOnLine(nullptr);
  }

  if (const auto* list_marker =
          GetListMarker(*layout_object, ParentObjectIfPresent())) {
    // A list marker should be followed by a list item on the same line.
    // Note that pseudo content is always included in the tree, so
    // NextSiblingIncludingIgnored() will succeed.
    auto* ax_list_marker = AXObjectCache().Get(list_marker);
    if (ax_list_marker && ax_list_marker->IsIncludedInTree()) {
      return SetNextOnLine(
          GetFirstInlineBlockOrDeepestInlineAXChildInLayoutTree(
              ax_list_marker->NextSiblingIncludingIgnored(), true));
    }
    return SetNextOnLine(nullptr);
  }

  if (!ShouldUseLayoutNG(*layout_object)) {
    return SetNextOnLine(nullptr);
  }

  if (!layout_object->IsInLayoutNGInlineFormattingContext()) {
    return SetNextOnLine(nullptr);
  }

  // Obtain the next LayoutObject that is in the same line, which was previously
  // computed in `AXObjectCacheImpl::ComputeNodesOnLine()`. If one does not
  // exist, move to children and Repeate the process.
  // If a LayoutObject is found, in the next loop we compute if it has an
  // AXObject that is included in the tree. If so, connect them.
  const LayoutObject* next_layout_object = nullptr;
  while (layout_object) {
    next_layout_object = AXObjectCache().CachedNextOnLine(layout_object);
    if (next_layout_object) {
      break;
    }
    const auto* child = layout_object->SlowLastChild();
    if (!child) {
      break;
    }
    layout_object = child;
  }

  while (next_layout_object) {
    AXObject* result = AXObjectCache().Get(next_layout_object);

    // We want to continue searching for the next inline leaf if the
    // current one is inert or aria-hidden.
    // We don't necessarily want to keep searching in the case of any ignored
    // node, because we anticipate t
```