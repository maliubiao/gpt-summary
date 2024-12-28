Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding - The Context:**

The prompt tells us this is `blink/renderer/core/dom/element.cc`, a core file for the Chromium Blink rendering engine. Specifically, it deals with the `Element` class, a fundamental building block of the DOM. The fact it's the 12th of 13 parts suggests it's a substantial file with many responsibilities.

**2. High-Level Functionality Scan:**

I'd start by reading through the method signatures and looking for keywords. I see:

* `SetInlineStyleProperty`, `RemoveInlineStyleProperty`, `RemoveAllInlineStyleProperties`: Clearly related to inline styles.
* `UpdatePresentationAttributeStyle`, `CreatePresentationAttributeStyle`, `AddPropertyToPresentationAttributeStyle`:  Likely related to how attributes influence styling.
* `MapLanguageAttributeToLocale`:  Deals with the `lang` attribute.
* `LogAddElementIfIsolatedWorldAndInDocument`, `LogUpdateAttributeIfIsolatedWorldAndInDocument`: Suggests logging/debugging, possibly for extension contexts or isolated worlds.
* `HasPart`, `GetPart`, `part()`:  Related to the `part` attribute and shadow DOM styling.
* `SetHovered`, `SetActive`:  Handles interaction states.
* `InvalidateStyleAttribute`, `RecalcTransitionPseudoTreeStyle`, `RebuildTransitionPseudoLayoutTree`:  Deals with style recalculation and view transitions.
* `IsInertRoot`, `GetFocusgroupFlags`: Features related to accessibility and focus management.
* `checkVisibility`: A method to check element visibility.
* `WeakLowercaseIfNecessary`, `SynchronizeAttributeHinted`, `GetAttributeHinted`, `LookupAttributeQNameHinted`, `ValidateAttributeIndex`, `SetAttributeWithoutValidation`, `SetAttributeWithValidation`, `SetSynchronizedLazyAttribute`, `SetAttributeHinted`, `FindAttributeIndex`, `SetAttributeInternal`, `setAttributeNode`:  A large section dedicated to attribute management.

**3. Grouping and Categorization:**

Based on the initial scan, I can group the functionalities:

* **Styling:** Inline styles, presentation attributes, `part` attribute, hover/active states, style invalidation, view transitions.
* **Attributes:**  General attribute setting, getting, removal, and synchronization.
* **Accessibility/Interactions:** `inert`, focus groups, hover/active states.
* **Visibility:**  Checking element visibility.
* **Logging/Debugging:** Logging actions in isolated worlds.
* **Language:** Handling the `lang` attribute.

**4. Deeper Dive into Specific Areas:**

Now, let's look for connections to HTML, CSS, and JavaScript:

* **Inline Styles:**  Directly maps to the HTML `style` attribute and JavaScript's `element.style` property.
    * **Example:** HTML: `<div style="color: red;"></div>`, JS: `element.style.backgroundColor = 'blue';`
* **Presentation Attributes:** Attributes like `width`, `height`, `align`, etc., which historically influenced styling. CSS can override these.
    * **Example:** HTML: `<table align="center"></table>`. CSS: `table { text-align: left; }`
* **`part` Attribute:**  Used in shadow DOM to style internal parts of a component. CSS uses the `::part()` pseudo-element.
    * **Example:** HTML: `<my-component><button part="important-button">Click</button></my-component>`, CSS: `my-component::part(important-button) { ... }`
* **Hover/Active States:**  CSS pseudo-classes `:hover` and `:active`. JavaScript can trigger these programmatically in some cases.
    * **Example:** CSS: `button:hover { background-color: lightblue; }`, JS:  (While not direct manipulation of these states, JS can trigger actions that lead to them).
* **Style Invalidation:** Changes here trigger re-rendering, which is core to how the browser updates the display based on HTML, CSS, and JavaScript changes.
* **View Transitions:** A newer web API for creating smooth transitions between DOM changes. Involves CSS and JavaScript.
* **Attributes:**  Fundamental to HTML. JavaScript interacts heavily with attributes via methods like `getAttribute`, `setAttribute`, `removeAttribute`.
    * **Example:** HTML: `<img src="image.png" alt="An image">`, JS: `element.setAttribute('title', 'Image title');`
* **`inert` Attribute:**  HTML attribute for disabling user interaction.
* **Focusgroup:**  Relates to keyboard navigation and accessibility (HTML and potentially ARIA attributes).
* **`checkVisibility`:** JavaScript API `element.checkVisibility()`.

**5. Logical Reasoning and Examples:**

For methods like `SetInlineStyleProperty`, we can infer:

* **Input:** A CSS property name (e.g., "color"), a CSS value (e.g., "blue"), and an importance flag (boolean).
* **Output:** Likely a boolean indicating success or void (as seen in the code).
* **Assumption:** The element is a styled element.

For `checkVisibility`:

* **Input:**  `CheckVisibilityOptions` object with flags for checking CSS visibility, opacity, etc.
* **Output:** A boolean indicating whether the element is visible.
* **Logical Steps:** The code checks various CSS properties and states (visibility, opacity, `content-visibility`) on the element and its ancestors.

**6. Common Errors:**

* **Setting invalid attribute names:** The `SetAttributeHinted` method has error handling for this.
* **Trying to reuse `Attr` nodes without cloning:** The `setAttributeNode` method explicitly checks for this and throws an error.
* **Incorrectly manipulating inline styles:** Setting invalid CSS syntax via JavaScript's `element.style` (though the C++ code handles valid CSS values).

**7. Debugging and User Actions:**

How does a user operation reach this code?

1. **HTML Parsing:** The initial structure of the DOM is created based on HTML. The `Element` objects are created during this process.
2. **CSS Parsing and Application:** CSS rules (from stylesheets or inline styles) are parsed and applied to `Element` objects, potentially triggering calls to `SetInlineStyleProperty` or `UpdatePresentationAttributeStyle`.
3. **JavaScript Interactions:**  JavaScript code can directly manipulate element attributes and styles using methods like `setAttribute`, `removeAttribute`, and the `style` property. These actions will likely call the corresponding C++ methods in `element.cc`.
4. **User Interactions:** User actions like hovering over an element or clicking on it can trigger state changes that call `SetHovered` or `SetActive`.
5. **View Transitions API:**  Using the View Transitions API in JavaScript will lead to calls to methods like `RecalcTransitionPseudoTreeStyle`.

**8. Synthesizing the Summary (for part 12 of 13):**

Given that it's the second to last part, it likely covers a significant portion of the `Element` class's functionality. The focus seems to be on:

* **Styling mechanisms:** Both inline styles and how attributes influence styling.
* **Attribute management:** A comprehensive set of methods for setting, getting, removing, and synchronizing attributes.
* **Interaction and state:** Handling hover and active states.
* **More advanced features:** View Transitions, inert attribute, focus groups.
* **Visibility checks:** A dedicated method for determining element visibility.

It's reasonable to assume that the *next* (and final) part might cover other crucial aspects of the `Element` class, possibly related to events, DOM manipulation (beyond attributes), or lifecycle management.

This detailed breakdown reflects the process of understanding the code by examining its structure, keywords, and connections to web technologies, and then using logical reasoning to infer behavior and identify potential issues.
这个代码片段是 `blink/renderer/core/dom/element.cc` 文件的第 12 部分，主要集中在 `Element` 类中与 **样式（Style）** 和 **属性（Attribute）** 操作相关的成员函数。 考虑到这是倒数第二部分，可以推测它涵盖了 `Element` 类中一些比较核心和复杂的功能。

**主要功能归纳:**

1. **内联样式操作:**
   - 提供添加、修改和移除元素的内联样式（`style` 属性）的方法。
   - `SetInlineStyleProperty`: 设置内联样式属性。
   - `RemoveInlineStyleProperty`: 移除内联样式属性。
   - `RemoveAllInlineStyleProperties`: 移除所有内联样式属性。
   - `InlineStyleChanged`:  一个内部方法，当内联样式发生变化时被调用，用于触发样式重新计算。

2. **表现属性样式（Presentation Attribute Style）:**
   - 管理通过 HTML 属性直接影响元素样式的机制（例如 `width`, `height`, `align` 等）。
   - `UpdatePresentationAttributeStyle`:  同步所有属性，并根据属性计算表现属性样式。
   - `CreatePresentationAttributeStyle`: 创建并返回一个包含表现属性样式的 `CSSPropertyValueSet` 对象。
   - `AddPropertyToPresentationAttributeStyle`: 向表现属性样式对象添加属性。
   - 特别处理了 `hidden="until-found"` 属性。

3. **语言属性映射 (Language Attribute Mapping):**
   - `MapLanguageAttributeToLocale`:  处理 `lang` 属性，将其映射到 CSS 的 `webkit-locale` 属性，并进行一些使用情况的统计。

4. **调试和日志 (Debugging and Logging):**
   - 提供在隔离世界（Isolated World，通常用于扩展）中添加和更新元素属性时记录日志的函数。
   - `LogAddElementIfIsolatedWorldAndInDocument` (多个重载): 记录添加元素的信息。
   - `LogUpdateAttributeIfIsolatedWorldAndInDocument`: 记录更新属性的信息。

5. **`part` 属性支持:**
   - 提供了与 Shadow DOM 的 `part` 属性相关的操作。
   - `HasPart`: 检查元素是否有 `part` 属性。
   - `GetPart`: 获取 `part` 属性的 `DOMTokenList`。
   - `part()`: 获取或创建 `part` 属性的 `DOMTokenList`。
   - `HasPartNamesMap`, `PartNamesMap`:  用于存储和访问 `part` 属性的名称映射。

6. **交互状态管理 (Interaction State Management):**
   - 管理元素的 `:hover` 和 `:active` 伪类状态。
   - `SetHovered`: 设置元素的 hover 状态。
   - `SetActive`: 设置元素的 active 状态。
   - 这些方法会触发样式重新计算，如果元素的样式受到这些伪类的影响。

7. **样式属性失效 (Style Attribute Invalidation):**
   - `InvalidateStyleAttribute`:  标记 `style` 属性已更改，需要重新计算样式。

8. **视图过渡伪元素样式重新计算 (View Transition Pseudo Element Style Recalculation):**
   - `RecalcTransitionPseudoTreeStyle`:  处理视图过渡（View Transitions）API 创建的伪元素的样式重新计算。
   - `RebuildTransitionPseudoLayoutTree`: 重建视图过渡伪元素的布局树。

9. **`inert` 属性支持:**
   - `IsInertRoot`:  检查元素是否是 `inert` 属性的根节点。

10. **焦点组标志 (Focusgroup Flags):**
    - `GetFocusgroupFlags`:  获取与焦点管理相关的标志。

11. **元素可见性检查 (Element Visibility Check):**
    - `checkVisibility`: 提供更精细的元素可见性检查，可以考虑 CSS 的 `visibility`、`opacity` 和 `content-visibility` 属性。

12. **属性名称处理和同步 (Attribute Name Handling and Synchronization):**
    - `WeakLowercaseIfNecessary`:  在必要时将属性名称转换为小写。
    - `SynchronizeAttributeHinted`:  同步特定属性（通常是 `style` 或 SVG 相关属性），确保内部状态与实际属性值一致。
    - `GetAttributeHinted`:  获取属性值，并同时进行同步。
    - `LookupAttributeQNameHinted`: 查找属性的限定名 (Qualified Name)。
    - `ValidateAttributeIndex`: 验证属性索引。

13. **设置属性 (Setting Attributes):**
    - 提供多种设置属性的方法，包括带验证和不带验证的版本，以及处理 `Trusted Types` 的情况。
    - `SetAttributeWithoutValidation`:  不进行验证直接设置属性。
    - `SetAttributeWithValidation`:  进行验证后设置属性。
    - `SetSynchronizedLazyAttribute`:  设置延迟同步的属性。
    - `SetAttributeHinted`:  根据提示信息设置属性。
    - `SetAttributeInternal`:  内部的属性设置实现。

14. **设置属性节点 (Setting Attribute Node):**
    - `setAttributeNode`:  通过 `Attr` 节点设置属性。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    - JavaScript 可以通过 `element.style` 属性直接读写元素的内联样式，这会调用到 `SetInlineStyleProperty` 和相关的函数。
        ```javascript
        const div = document.getElementById('myDiv');
        div.style.color = 'blue'; // 可能会调用 SetInlineStyleProperty
        div.style.backgroundColor = 'yellow';
        ```
    - JavaScript 可以使用 `element.setAttribute('style', '...')` 设置或修改 `style` 属性，也会触发相关的内联样式处理逻辑。
    - JavaScript 可以通过 `element.setAttribute('width', '100px')` 等方式设置影响样式的属性，这会影响表现属性样式的计算。
    - JavaScript 的 `element.checkVisibility()` 方法会最终调用到 `Element::checkVisibility`。
    - JavaScript 的 `element.part.add('...')` 和 `element.part.remove('...')` 操作会影响 `Element` 对象的 `part` 属性管理。
    - JavaScript 可以监听 `mouseover` 和 `mouseout` 事件，间接地导致 `SetHovered` 被调用。类似地，鼠标点击事件可能导致 `SetActive` 被调用。
    - View Transitions API 是由 JavaScript 驱动的，相关 API 的调用会触发 `RecalcTransitionPseudoTreeStyle` 和 `RebuildTransitionPseudoLayoutTree`。

* **HTML:**
    - HTML 的 `style` 属性直接对应于内联样式，文件中处理内联样式的方法就是为了处理这个属性。
        ```html
        <div style="font-size: 16px;">Hello</div>
        ```
    - HTML 的各种属性（如 `class`, `id`, `width`, `height`, `align`, `lang`, `hidden`, `part`, `inert` 等）都会被 `Element` 对象解析和处理。例如，`lang` 属性的处理就对应了 `MapLanguageAttributeToLocale`。
    - `hidden="until-found"` 属性的处理逻辑也在 `UpdatePresentationAttributeStyle` 中。
    - `<div part="my-part">` 中的 `part` 属性与代码中的 `part()` 方法相关联。
    - `<div inert>` 中的 `inert` 属性与 `IsInertRoot()` 方法相关联。

* **CSS:**
    - CSS 规则会影响元素的最终样式，但这个代码片段主要关注的是直接在 `Element` 对象上进行的样式操作，比如内联样式和表现属性样式。当 CSS 规则需要被应用时，会触发更上层的样式计算流程。
    - CSS 的 `:hover` 和 `:active` 伪类与 `SetHovered` 和 `SetActive` 方法管理的状态相对应。
    - CSS 的 `::part()` 伪元素用于样式化 Shadow DOM 中的 part，这与 `part()` 方法提供的功能相关。
    - CSS 的 `visibility`, `opacity`, `content-visibility` 属性会被 `checkVisibility` 方法考虑。
    - CSS 视图过渡（View Transitions）与 `RecalcTransitionPseudoTreeStyle` 和 `RebuildTransitionPseudoLayoutTree` 处理的伪元素相关。

**逻辑推理的假设输入与输出举例:**

假设输入 JavaScript 代码:

```javascript
const element = document.getElementById('myElement');
element.style.color = 'red';
```

**假设 `SetInlineStyleProperty` 被调用:**

* **输入:**
    * `name`:  `CSSPropertyName` 对象，表示 "color"。
    * `value`: `CSSValue` 对象，表示 "red"。
    * `important`: `false` (通常默认为 false)。
* **输出:** `void` (该函数通常不直接返回有意义的值，但会触发内部状态更新)。
* **内部逻辑:**  该函数会确保存在可变的内联样式对象，并将 "color: red" 添加到该对象中，然后调用 `InlineStyleChanged()` 触发样式重新计算。

假设输入 HTML:

```html
<div align="center">Text</div>
```

**假设在解析时 `UpdatePresentationAttributeStyle` 被调用:**

* **输入:**  `Element` 对象本身。
* **输出:** `void`。
* **内部逻辑:** 该函数会检查元素的属性，发现 `align="center"`，然后调用 `CollectStyleForPresentationAttribute` 或类似的方法，将 `text-align: center` 添加到表现属性样式中。

**用户或编程常见的使用错误举例:**

1. **直接操作只读的内联样式对象:**  如果尝试在获取到的只读内联样式对象上设置属性，会导致错误。需要确保操作的是可变的内联样式对象，可以通过 `EnsureMutableInlineStyle()` 获取。

2. **不区分表现属性和 CSS 样式:**  初学者可能不清楚某些 HTML 属性可以直接影响样式，而另一些则不能。错误地期望所有属性都能像 CSS 属性一样被处理。

3. **在不适用的元素上使用 `part` 属性:**  `part` 属性主要用于 Shadow DOM，在普通元素上使用可能不会达到预期的效果。

4. **错误地假设 `checkVisibility` 的结果:**  `checkVisibility` 的行为可能比简单的 `display: none` 检查更复杂，需要理解其考虑的各种因素。

5. **尝试在 `setAttributeNode` 中使用已经属于其他元素的 `Attr` 节点:**  这会抛出 `InUseAttributeError` 异常。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载包含特定 HTML 结构的页面:**  浏览器解析 HTML，创建 `Element` 对象，并处理其属性，可能涉及到表现属性样式的计算。
2. **页面包含内联样式:**  浏览器解析到带有 `style` 属性的元素，会调用相应的内联样式处理函数。
3. **用户鼠标悬停在元素上:** 浏览器触发 `mouseover` 事件，可能导致 JavaScript 代码或者浏览器内部调用 `SetHovered`。
4. **用户点击元素:** 浏览器触发 `mousedown` 和 `mouseup` 事件，可能导致 JavaScript 代码或者浏览器内部调用 `SetActive`。
5. **JavaScript 代码动态修改元素样式或属性:**  例如，通过 `element.style.xxx = '...'` 或 `element.setAttribute('yyy', '...')`，会直接调用到 `element.cc` 中的相关函数。
6. **页面使用了 Shadow DOM 和 `part` 属性:**  浏览器处理带有 `part` 属性的元素，并可能在样式计算时使用 `part()` 方法。
7. **页面使用了 View Transitions API:**  JavaScript 调用 View Transitions API 会触发相关的样式和布局更新，涉及 `RecalcTransitionPseudoTreeStyle` 等函数。
8. **开发者使用开发者工具检查元素:** 开发者工具可能会触发对元素属性和样式的访问，间接调用一些 getter 方法。

**作为第 12 部分的功能归纳:**

作为 `blink/renderer/core/dom/element.cc` 文件的第 12 部分，这段代码主要集中在 **`Element` 对象的样式和属性管理** 的核心功能上。它涵盖了从最基本的内联样式操作，到更复杂的表现属性样式、`part` 属性、交互状态管理、视图过渡伪元素处理以及元素可见性检查等多个方面。 考虑到这是倒数第二部分，它很可能包含了 `Element` 类中与样式和属性相关的大部分重要逻辑，为渲染引擎正确地呈现和交互网页内容提供了基础。 剩下的最后一部分可能涉及其他方面，例如事件处理、DOM 结构操作或其他辅助功能。

Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共13部分，请归纳一下它的功能

"""
alue, important,
          GetExecutionContext() ? GetExecutionContext()->GetSecureContextMode()
                                : SecureContextMode::kInsecureContext,
          GetDocument().ElementSheet().Contents()) >=
      MutableCSSPropertyValueSet::kModifiedExisting;
  if (did_change) {
    InlineStyleChanged();
  }
  return did_change;
}

void Element::SetInlineStyleProperty(const CSSPropertyName& name,
                                     const CSSValue& value,
                                     bool important) {
  DCHECK(IsStyledElement());
  EnsureMutableInlineStyle().SetProperty(name, value, important);
  InlineStyleChanged();
}

bool Element::RemoveInlineStyleProperty(CSSPropertyID property_id) {
  DCHECK(IsStyledElement());
  if (!InlineStyle()) {
    return false;
  }
  bool did_change = EnsureMutableInlineStyle().RemoveProperty(property_id);
  if (did_change) {
    InlineStyleChanged();
  }
  return did_change;
}

bool Element::RemoveInlineStyleProperty(const AtomicString& property_name) {
  DCHECK(IsStyledElement());
  if (!InlineStyle()) {
    return false;
  }
  bool did_change = EnsureMutableInlineStyle().RemoveProperty(property_name);
  if (did_change) {
    InlineStyleChanged();
  }
  return did_change;
}

void Element::RemoveAllInlineStyleProperties() {
  DCHECK(IsStyledElement());
  if (!InlineStyle()) {
    return;
  }
  EnsureMutableInlineStyle().Clear();
  InlineStyleChanged();
}

void Element::UpdatePresentationAttributeStyle() {
  SynchronizeAllAttributes();
  // ShareableElementData doesn't store presentation attribute style, so make
  // sure we have a UniqueElementData.
  UniqueElementData& element_data = EnsureUniqueElementData();
  element_data.SetPresentationAttributeStyleIsDirty(false);
  element_data.presentation_attribute_style_ =
      ComputePresentationAttributeStyle(*this);

  // We could do this in CreatePresentationAttributeStyle or
  // HTMLElement::CollectStyleForPresentationAttribute when we actually iterate
  // over attributes, but the presentational style gets cached so those
  // functions aren't necessarily called every time. This function actually gets
  // called every time, so we must do this check here.
  AttributeCollection attributes = AttributesWithoutUpdate();
  auto* hidden_attr = attributes.Find(html_names::kHiddenAttr);
  if (hidden_attr && hidden_attr->Value() == "until-found") {
    EnsureDisplayLockContext().SetIsHiddenUntilFoundElement(true);
  } else if (DisplayLockContext* context = GetDisplayLockContext()) {
    context->SetIsHiddenUntilFoundElement(false);
  }
}

CSSPropertyValueSet* Element::CreatePresentationAttributeStyle() {
  auto* style = MakeGarbageCollected<MutableCSSPropertyValueSet>(
      IsSVGElement() ? kSVGAttributeMode : kHTMLStandardMode);
  AttributeCollection attributes = AttributesWithoutUpdate();
  for (const Attribute& attr : attributes) {
    CollectStyleForPresentationAttribute(attr.GetName(), attr.Value(), style);
  }
  CollectExtraStyleForPresentationAttribute(style);
  return style;
}

void Element::AddPropertyToPresentationAttributeStyle(
    MutableCSSPropertyValueSet* style,
    CSSPropertyID property_id,
    CSSValueID identifier) {
  DCHECK(IsStyledElement());
  DCHECK_NE(property_id, CSSPropertyID::kWhiteSpace);
  style->SetLonghandProperty(property_id,
                             *CSSIdentifierValue::Create(identifier));
}

void Element::AddPropertyToPresentationAttributeStyle(
    MutableCSSPropertyValueSet* style,
    CSSPropertyID property_id,
    double value,
    CSSPrimitiveValue::UnitType unit) {
  DCHECK(IsStyledElement());
  style->SetLonghandProperty(property_id,
                             *CSSNumericLiteralValue::Create(value, unit));
}

void Element::AddPropertyToPresentationAttributeStyle(
    MutableCSSPropertyValueSet* style,
    CSSPropertyID property_id,
    const String& value) {
  DCHECK(IsStyledElement());
  style->ParseAndSetProperty(property_id, value, false,
                             GetExecutionContext()
                                 ? GetExecutionContext()->GetSecureContextMode()
                                 : SecureContextMode::kInsecureContext,
                             GetDocument().ElementSheet().Contents());
}

void Element::AddPropertyToPresentationAttributeStyle(
    MutableCSSPropertyValueSet* style,
    CSSPropertyID property_id,
    const CSSValue& value) {
  DCHECK(IsStyledElement());
  style->SetLonghandProperty(property_id, value);
}

void Element::MapLanguageAttributeToLocale(const AtomicString& value,
                                           MutableCSSPropertyValueSet* style) {
  if (!value.empty()) {
    // Have to quote so the locale id is treated as a string instead of as a CSS
    // keyword.
    AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kWebkitLocale,
                                            SerializeString(value));

    // FIXME: Remove the following UseCounter code when we collect enough
    // data.
    UseCounter::Count(GetDocument(), WebFeature::kLangAttribute);
    if (IsA<HTMLHtmlElement>(this)) {
      UseCounter::Count(GetDocument(), WebFeature::kLangAttributeOnHTML);
    } else if (IsA<HTMLBodyElement>(this)) {
      UseCounter::Count(GetDocument(), WebFeature::kLangAttributeOnBody);
    }
    String html_language = value.GetString();
    wtf_size_t first_separator = html_language.find('-');
    if (first_separator != kNotFound) {
      html_language = html_language.Left(first_separator);
    }
    String ui_language = DefaultLanguage();
    first_separator = ui_language.find('-');
    if (first_separator != kNotFound) {
      ui_language = ui_language.Left(first_separator);
    }
    first_separator = ui_language.find('_');
    if (first_separator != kNotFound) {
      ui_language = ui_language.Left(first_separator);
    }
    if (!DeprecatedEqualIgnoringCase(html_language, ui_language)) {
      UseCounter::Count(GetDocument(),
                        WebFeature::kLangAttributeDoesNotMatchToUILocale);
    }
  } else {
    // The empty string means the language is explicitly unknown.
    AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kWebkitLocale,
                                            CSSValueID::kAuto);
  }
}

void Element::LogAddElementIfIsolatedWorldAndInDocument(
    const char element[],
    const QualifiedName& attr1) {
  // TODO(crbug.com/361461518): Investigate the root cause of execution context
  // is unexpectedly null.
  if (!GetDocument().GetExecutionContext()) {
    return;
  }

  if (!isConnected() ||
      !V8DOMActivityLogger::HasActivityLoggerInIsolatedWorlds()) {
    return;
  }
  V8DOMActivityLogger* activity_logger =
      V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
          GetDocument().GetAgent().isolate());
  if (!activity_logger) {
    return;
  }
  Vector<String, 2> argv;
  argv.push_back(element);
  argv.push_back(FastGetAttribute(attr1));
  activity_logger->LogEvent(GetDocument().GetExecutionContext(),
                            "blinkAddElement", argv);
}

void Element::LogAddElementIfIsolatedWorldAndInDocument(
    const char element[],
    const QualifiedName& attr1,
    const QualifiedName& attr2) {
  // TODO(crbug.com/361461518): Investigate the root cause of execution context
  // is unexpectedly null.
  if (!GetDocument().GetExecutionContext()) {
    return;
  }

  if (!isConnected() ||
      !V8DOMActivityLogger::HasActivityLoggerInIsolatedWorlds()) {
    return;
  }
  V8DOMActivityLogger* activity_logger =
      V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
          GetDocument().GetAgent().isolate());
  if (!activity_logger) {
    return;
  }
  Vector<String, 3> argv;
  argv.push_back(element);
  argv.push_back(FastGetAttribute(attr1));
  argv.push_back(FastGetAttribute(attr2));
  activity_logger->LogEvent(GetDocument().GetExecutionContext(),
                            "blinkAddElement", argv);
}

void Element::LogAddElementIfIsolatedWorldAndInDocument(
    const char element[],
    const QualifiedName& attr1,
    const QualifiedName& attr2,
    const QualifiedName& attr3) {
  // TODO(crbug.com/361461518): Investigate the root cause of execution context
  // is unexpectedly null.
  if (!GetDocument().GetExecutionContext()) {
    return;
  }

  if (!isConnected() ||
      !V8DOMActivityLogger::HasActivityLoggerInIsolatedWorlds()) {
    return;
  }
  V8DOMActivityLogger* activity_logger =
      V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
          GetDocument().GetAgent().isolate());
  if (!activity_logger) {
    return;
  }
  Vector<String, 4> argv;
  argv.push_back(element);
  argv.push_back(FastGetAttribute(attr1));
  argv.push_back(FastGetAttribute(attr2));
  argv.push_back(FastGetAttribute(attr3));
  activity_logger->LogEvent(GetDocument().GetExecutionContext(),
                            "blinkAddElement", argv);
}

void Element::LogUpdateAttributeIfIsolatedWorldAndInDocument(
    const char element[],
    const AttributeModificationParams& params) {
  if (!isConnected() ||
      !V8DOMActivityLogger::HasActivityLoggerInIsolatedWorlds()) {
    return;
  }
  V8DOMActivityLogger* activity_logger =
      V8DOMActivityLogger::CurrentActivityLoggerIfIsolatedWorld(
          GetDocument().GetAgent().isolate());
  if (!activity_logger) {
    return;
  }
  Vector<String, 4> argv;
  argv.push_back(element);
  argv.push_back(params.name.ToString());
  argv.push_back(params.old_value);
  argv.push_back(params.new_value);
  activity_logger->LogEvent(GetDocument().GetExecutionContext(),
                            "blinkSetAttribute", argv);
}

void Element::Trace(Visitor* visitor) const {
  visitor->Trace(computed_style_);
  visitor->Trace(element_data_);
  ContainerNode::Trace(visitor);
}

bool Element::HasPart() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    if (auto* part = data->GetPart()) {
      return part->length() > 0;
    }
  }
  return false;
}

DOMTokenList* Element::GetPart() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetPart();
  }
  return nullptr;
}

DOMTokenList& Element::part() {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  DOMTokenList* part = rare_data.GetPart();
  if (!part) {
    part = MakeGarbageCollected<DOMTokenList>(*this, html_names::kPartAttr);
    rare_data.SetPart(part);
  }
  return *part;
}

bool Element::HasPartNamesMap() const {
  const NamesMap* names_map = PartNamesMap();
  return names_map && names_map->size() > 0;
}

const NamesMap* Element::PartNamesMap() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->PartNamesMap();
  }
  return nullptr;
}

bool Element::ChildStyleRecalcBlockedByDisplayLock() const {
  auto* context = GetDisplayLockContext();
  return context && !context->ShouldStyleChildren();
}

void Element::SetHovered(bool hovered) {
  if (hovered == IsHovered()) {
    return;
  }

  GetDocument().UserActionElements().SetHovered(this, hovered);

  const ComputedStyle* style = GetComputedStyle();
  if (!style || style->AffectedByHover()) {
    StyleChangeType change_type = kLocalStyleChange;
    if (style && style->HasPseudoElementStyle(kPseudoIdFirstLetter)) {
      change_type = kSubtreeStyleChange;
    }
    SetNeedsStyleRecalc(change_type,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_hover));
  }
  PseudoStateChanged(CSSSelector::kPseudoHover);

  InvalidateIfHasEffectiveAppearance();

  if (hovered && RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled()) {
    InterestGained();
  }
}

void Element::SetActive(bool active) {
  if (active == IsActive()) {
    return;
  }

  GetDocument().UserActionElements().SetActive(this, active);

  if (!GetLayoutObject()) {
    if (!ChildrenOrSiblingsAffectedByActive()) {
      SetNeedsStyleRecalc(kLocalStyleChange,
                          StyleChangeReasonForTracing::CreateWithExtraData(
                              style_change_reason::kPseudoClass,
                              style_change_extra_data::g_active));
    }
    PseudoStateChanged(CSSSelector::kPseudoActive);
    return;
  }

  if (GetComputedStyle()->AffectedByActive()) {
    StyleChangeType change_type =
        GetComputedStyle()->HasPseudoElementStyle(kPseudoIdFirstLetter)
            ? kSubtreeStyleChange
            : kLocalStyleChange;
    SetNeedsStyleRecalc(change_type,
                        StyleChangeReasonForTracing::CreateWithExtraData(
                            style_change_reason::kPseudoClass,
                            style_change_extra_data::g_active));
  }
  PseudoStateChanged(CSSSelector::kPseudoActive);

  if (!IsDisabledFormControl()) {
    InvalidateIfHasEffectiveAppearance();
  }
}

void Element::InvalidateStyleAttribute(
    bool only_changed_independent_properties) {
  DCHECK(HasElementData());
  GetElementData()->SetStyleAttributeIsDirty(true);
  SetNeedsStyleRecalc(only_changed_independent_properties
                          ? kInlineIndependentStyleChange
                          : kLocalStyleChange,
                      StyleChangeReasonForTracing::Create(
                          style_change_reason::kInlineCSSStyleMutated));
  GetDocument().GetStyleEngine().AttributeChangedForElement(
      html_names::kStyleAttr, *this);
}

void Element::RecalcTransitionPseudoTreeStyle(
    const Vector<AtomicString>& view_transition_names) {
  DCHECK_EQ(this, GetDocument().documentElement());

  DisplayLockStyleScope display_lock_style_scope(this);
  if (!display_lock_style_scope.ShouldUpdateChildStyle()) {
    return;
  }

  PseudoElement* old_transition_pseudo =
      GetPseudoElement(kPseudoIdViewTransition);
  const auto* transition = ViewTransitionUtils::GetTransition(GetDocument());
  if (!transition && !old_transition_pseudo) {
    return;
  }

  if (transition && old_transition_pseudo &&
      !transition->IsGeneratingPseudo(
          To<ViewTransitionPseudoElementBase>(*old_transition_pseudo))) {
    ClearPseudoElement(kPseudoIdViewTransition);
    old_transition_pseudo = nullptr;
  }

  const StyleRecalcChange style_recalc_change;
  const StyleRecalcContext style_recalc_context =
      StyleRecalcContext::FromInclusiveAncestors(
          *GetDocument().documentElement());

  PseudoElement* transition_pseudo =
      UpdatePseudoElement(kPseudoIdViewTransition, style_recalc_change,
                          style_recalc_context, g_null_atom);
  if (!transition_pseudo) {
    return;
  }

  for (const auto& view_transition_name : view_transition_names) {
    // If the container (::view-transition-group(name)) is already created
    // for the implementation purposes of capturing the old state, we need
    // to check if it needs to be reparented to its containing group.
    bool container_already_created_in_view_transition_pseudo =
        !!transition_pseudo->GetPseudoElement(
            PseudoId::kPseudoIdViewTransitionGroup, view_transition_name);
    PseudoElement* parent =
        To<ViewTransitionTransitionElement>(transition_pseudo)
            ->FindViewTransitionGroupPseudoElementParent(view_transition_name);
    if (container_already_created_in_view_transition_pseudo &&
        parent != transition_pseudo) {
      transition_pseudo->ClearPseudoElement(
          PseudoId::kPseudoIdViewTransitionGroup, view_transition_name);
    }

    PseudoElement* container_pseudo =
        parent ? parent->UpdatePseudoElement(
                     kPseudoIdViewTransitionGroup, style_recalc_change,
                     style_recalc_context, view_transition_name)
               : nullptr;
    if (!container_pseudo) {
      continue;
    }

    // Nested pseudo elements don't keep pointers to their children, only their
    // parents (i.e. firstChild() in a  ::view-transition is nullptr but
    // parentNode of ::view-transition-group is ::view-transition). However,
    // the layout tree is reattached by descending the DOM tree by child
    // pointers so if any pseudo needs a reattach we have to explicitly mark
    // all descendant pseudos as needing a reattach explicitly.
    // TODO(crbug.com/1455139): Implement tree traversal for nested pseudos.
    if (transition_pseudo->NeedsReattachLayoutTree()) {
      container_pseudo->SetNeedsReattachLayoutTree();
    }

    PseudoElement* wrapper_pseudo = container_pseudo->UpdatePseudoElement(
        kPseudoIdViewTransitionImagePair, style_recalc_change,
        style_recalc_context, view_transition_name);
    if (!wrapper_pseudo) {
      continue;
    }
    if (container_pseudo->NeedsReattachLayoutTree()) {
      wrapper_pseudo->SetNeedsReattachLayoutTree();
    }

    PseudoElement* old_pseudo = wrapper_pseudo->UpdatePseudoElement(
        kPseudoIdViewTransitionOld, style_recalc_change, style_recalc_context,
        view_transition_name);
    PseudoElement* new_pseudo = wrapper_pseudo->UpdatePseudoElement(
        kPseudoIdViewTransitionNew, style_recalc_change, style_recalc_context,
        view_transition_name);

    if (wrapper_pseudo->NeedsReattachLayoutTree()) {
      if (old_pseudo) {
        old_pseudo->SetNeedsReattachLayoutTree();
      }
      if (new_pseudo) {
        new_pseudo->SetNeedsReattachLayoutTree();
      }
    }

    container_pseudo->ClearChildNeedsStyleRecalc();
    wrapper_pseudo->ClearChildNeedsStyleRecalc();
  }

  // Regular pseudo update doesn't clear child style, since there are
  // (typically) no children / dirty child style. However, here we do need to
  // clear the child dirty bit.
  transition_pseudo->ClearChildNeedsStyleRecalc();
}

void Element::RebuildTransitionPseudoLayoutTree(
    const Vector<AtomicString>& view_transition_names) {
  DCHECK_EQ(this, GetDocument().documentElement());

  const bool has_transition =
      !!ViewTransitionUtils::GetTransition(GetDocument());
  if (!has_transition) {
    DCHECK(!GetPseudoElement(kPseudoIdViewTransition));
    return;
  }

  WhitespaceAttacher whitespace_attacher;
  auto rebuild_pseudo_tree =
      [&whitespace_attacher](PseudoElement* pseudo_element) {
        pseudo_element->RebuildLayoutTree(whitespace_attacher);
      };
  ViewTransitionUtils::ForEachTransitionPseudo(GetDocument(),
                                               rebuild_pseudo_tree);
}

bool Element::IsInertRoot() const {
  return FastHasAttribute(html_names::kInertAttr) && IsHTMLElement();
}

FocusgroupFlags Element::GetFocusgroupFlags() const {
  ExecutionContext* context = GetExecutionContext();
  if (!RuntimeEnabledFeatures::FocusgroupEnabled(context)) {
    return FocusgroupFlags::kNone;
  }
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetFocusgroupFlags();
  }
  return FocusgroupFlags::kNone;
}

bool Element::checkVisibility(CheckVisibilityOptions* options) const {
  if (options->checkVisibilityCSS()) {
    UseCounter::Count(
        GetDocument(),
        WebFeature::kElementCheckVisibilityOptionCheckVisibilityCSS);
  }
  if (options->checkOpacity()) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kElementCheckVisibilityOptionCheckOpacity);
  }
  if (options->contentVisibilityAuto()) {
    UseCounter::Count(
        GetDocument(),
        WebFeature::kElementCheckVisibilityOptionContentVisibilityAuto);
  }
  if (options->opacityProperty()) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kElementCheckVisibilityOptionOpacityProperty);
  }
  if (options->visibilityProperty()) {
    UseCounter::Count(
        GetDocument(),
        WebFeature::kElementCheckVisibilityOptionVisibilityProperty);
  }

  // If we're checking content-visibility: auto, then we can just check if we're
  // display locked at all. This is because, content-visibility: hidden is
  // always checked, so regardless of _why_ we're locked, the answer will be
  // false if we're locked.
  if (RuntimeEnabledFeatures::CheckVisibilityExtraPropertiesEnabled() &&
      options->contentVisibilityAuto() &&
      DisplayLockUtilities::IsDisplayLockedPreventingPaint(this)) {
    return false;
  }

  // Now, unlock ancestor content-visibility:auto elements. If this element is
  // offscreen and locked due to content-visibility:auto, this method should not
  // count that as invisible. That's checked above.
  DisplayLockUtilities::ScopedForcedUpdate force_locks(
      this, DisplayLockContext::ForcedPhase::kStyleAndLayoutTree,
      /*include_self=*/false, /*only_cv_auto=*/true,
      /*emit_warnings=*/false);
  GetDocument().UpdateStyleAndLayoutTree();

  if (!GetLayoutObject()) {
    return false;
  }

  auto* style = GetComputedStyle();
  if (!style) {
    return false;
  }

  DCHECK(options);
  if ((options->checkVisibilityCSS() ||
       (RuntimeEnabledFeatures::CheckVisibilityExtraPropertiesEnabled() &&
        options->visibilityProperty())) &&
      style->Visibility() != EVisibility::kVisible) {
    return false;
  }

  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(*this)) {
    if (Element* ancestor_element = DynamicTo<Element>(ancestor)) {
      // Check for content-visibility:hidden
      if (ancestor_element != this) {
        if (auto* lock = ancestor_element->GetDisplayLockContext()) {
          if (lock->IsLocked() &&
              !lock->IsActivatable(DisplayLockActivationReason::kViewport)) {
            return false;
          }
        }
      }

      // Check for opacity:0
      if (options->checkOpacity() ||
          (RuntimeEnabledFeatures::CheckVisibilityExtraPropertiesEnabled() &&
           options->opacityProperty())) {
        if (style = ancestor_element->GetComputedStyle(); style) {
          if (style->Opacity() == 0.f) {
            return false;
          }
        }
      }
    }
  }

  return true;
}

WTF::AtomicStringTable::WeakResult Element::WeakLowercaseIfNecessary(
    const AtomicString& name) const {
  if (name.IsLowerASCII()) [[likely]] {
    return WTF::AtomicStringTable::WeakResult(name);
  }
  if (IsHTMLElement() && IsA<HTMLDocument>(GetDocument())) [[likely]] {
    return WTF::AtomicStringTable::Instance().WeakFindLowercase(name);
  }
  return WTF::AtomicStringTable::WeakResult(name);
}

// Note, SynchronizeAttributeHinted is safe to call between a WeakFind() and
// a check on the AttributeCollection for the element even though it may
// modify the AttributeCollection to insert a "style" attribute. The reason
// is because html_names::kStyleAttr.LocalName() is an AtomicString
// representing "style". This means the AtomicStringTable will always have
// an entry for "style" and a `hint` that corresponds to
// html_names::kStyleAttr.LocalName() will never refer to a deleted object
// thus it is safe to insert html_names::kStyleAttr.LocalName() into the
// AttributeCollection collection after the WeakFind() when `hint` is
// referring to "style". A subsequent lookup will match itself correctly
// without worry for UaF or false positives.
void Element::SynchronizeAttributeHinted(
    const AtomicString& local_name,
    WTF::AtomicStringTable::WeakResult hint) const {
  // This version of SynchronizeAttribute() is streamlined for the case where
  // you don't have a full QualifiedName, e.g when called from DOM API.
  if (!HasElementData()) {
    return;
  }
  // TODO(ajwong): Does this unnecessarily synchronize style attributes on
  // SVGElements?
  if (GetElementData()->style_attribute_is_dirty() &&
      hint == html_names::kStyleAttr.LocalName()) {
    DCHECK(IsStyledElement());
    SynchronizeStyleAttributeInternal();
    return;
  }
  if (GetElementData()->svg_attributes_are_dirty()) {
    // We're passing a null namespace argument. svg_names::k*Attr are defined in
    // the null namespace, but for attributes that are not (like 'href' in the
    // XLink NS), this will not do the right thing.

    // TODO(fs): svg_attributes_are_dirty_ stays dirty unless
    // SynchronizeAllSVGAttributes is called. This means that even if
    // Element::SynchronizeAttribute() is called on all attributes,
    // svg_attributes_are_dirty_ remains true.
    To<SVGElement>(this)->SynchronizeSVGAttribute(QualifiedName(local_name));
  }
}

const AtomicString& Element::GetAttributeHinted(
    const AtomicString& name,
    WTF::AtomicStringTable::WeakResult hint) const {
  if (!HasElementData()) {
    return g_null_atom;
  }
  SynchronizeAttributeHinted(name, hint);
  if (const Attribute* attribute =
          GetElementData()->Attributes().FindHinted(name, hint)) {
    return attribute->Value();
  }
  return g_null_atom;
}

std::pair<wtf_size_t, const QualifiedName> Element::LookupAttributeQNameHinted(
    AtomicString name,
    WTF::AtomicStringTable::WeakResult hint) const {
  if (!HasElementData()) {
    return std::make_pair(kNotFound,
                          QualifiedName(LowercaseIfNecessary(std::move(name))));
  }

  AttributeCollection attributes = GetElementData()->Attributes();
  wtf_size_t index = attributes.FindIndexHinted(name, hint);
  return std::make_pair(
      index, index != kNotFound
                 ? attributes[index].GetName()
                 : QualifiedName(LowercaseIfNecessary(std::move(name))));
}

ALWAYS_INLINE wtf_size_t
Element::ValidateAttributeIndex(wtf_size_t index,
                                const QualifiedName& qname) const {
  // Checks whether attributes[index] points to qname, and re-calculates
  // index if not. This is necessary to accommodate cases where the element
  // is modified *while* we are setting an attribute.
  //
  // See https://crbug.com/333739948.

  if (index == kNotFound) {
    return index;
  }

  // If we previously found an attribute, we must also have attribute data.
  DCHECK(HasElementData());

  const AttributeCollection& attributes = GetElementData()->Attributes();
  if (index < attributes.size() && attributes[index].Matches(qname)) {
    return index;
  }

  return FindAttributeIndex(qname);
}

void Element::SetAttributeWithoutValidation(const QualifiedName& name,
                                            const AtomicString& value) {
  SynchronizeAttribute(name);
  SetAttributeInternal(FindAttributeIndex(name), name, value,
                       AttributeModificationReason::kDirectly);
}

void Element::SetAttributeWithValidation(const QualifiedName& name,
                                         const AtomicString& value,
                                         ExceptionState& exception_state) {
  SynchronizeAttribute(name);

  AtomicString trusted_value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(name), value, GetExecutionContext(),
      "Element", "setAttribute", exception_state));
  if (exception_state.HadException()) {
    return;
  }

  SetAttributeInternal(FindAttributeIndex(name), name, trusted_value,
                       AttributeModificationReason::kDirectly);
}

void Element::SetSynchronizedLazyAttribute(const QualifiedName& name,
                                           const AtomicString& value) {
  SetAttributeInternal(
      FindAttributeIndex(name), name, value,
      AttributeModificationReason::kBySynchronizationOfLazyAttribute);
}

void Element::SetAttributeHinted(AtomicString local_name,
                                 WTF::AtomicStringTable::WeakResult hint,
                                 String value,
                                 ExceptionState& exception_state) {
  if (!Document::IsValidName(local_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + local_name + "' is not a valid attribute name.");
    return;
  }
  SynchronizeAttributeHinted(local_name, hint);

  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(local_name), hint);

  AtomicString trusted_value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(q_name), std::move(value),
      GetExecutionContext(), "Element", "setAttribute", exception_state));
  if (exception_state.HadException()) {
    return;
  }
  // The `TrustedTypesCheckFor` call above may run script, which may modify
  // the current element, which in turn may invalidate the index. So we'll
  // check, and re-calculcate it if necessary.
  index = ValidateAttributeIndex(index, q_name);

  SetAttributeInternal(index, q_name, trusted_value,
                       AttributeModificationReason::kDirectly);
}

void Element::SetAttributeHinted(AtomicString local_name,
                                 WTF::AtomicStringTable::WeakResult hint,
                                 const V8TrustedType* trusted_string,
                                 ExceptionState& exception_state) {
  if (!Document::IsValidName(local_name)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidCharacterError,
        "'" + local_name + "' is not a valid attribute name.");
    return;
  }
  SynchronizeAttributeHinted(local_name, hint);

  auto [index, q_name] =
      LookupAttributeQNameHinted(std::move(local_name), hint);
  AtomicString value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(q_name), trusted_string,
      GetExecutionContext(), "Element", "setAttribute", exception_state));
  if (exception_state.HadException()) {
    return;
  }
  // The `TrustedTypesCheckFor` call above may run script, which may modify
  // the current element, which in turn may invalidate the index. So we'll
  // check, and re-calculcate it if necessary.
  index = ValidateAttributeIndex(index, q_name);

  SetAttributeInternal(index, q_name, value,
                       AttributeModificationReason::kDirectly);
}

wtf_size_t Element::FindAttributeIndex(const QualifiedName& name) const {
  if (HasElementData()) {
    return GetElementData()->Attributes().FindIndex(name);
  }
  return kNotFound;
}

ALWAYS_INLINE void Element::SetAttributeInternal(
    wtf_size_t index,
    const QualifiedName& name,
    const AtomicString& new_value,
    AttributeModificationReason reason) {
  if (new_value.IsNull()) {
    if (index != kNotFound) {
      RemoveAttributeInternal(index, reason);
    }
    return;
  }

  if (index == kNotFound) {
    AppendAttributeInternal(name, new_value, reason);
    return;
  }

  const Attribute& existing_attribute =
      GetElementData()->Attributes().at(index);
  QualifiedName existing_attribute_name = existing_attribute.GetName();

  if (new_value == existing_attribute.Value()) {
    if (reason !=
        AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
      WillModifyAttribute(existing_attribute_name, new_value, new_value);
      DidModifyAttribute(existing_attribute_name, new_value, new_value, reason);
    }
  } else {
    Attribute& new_attribute = EnsureUniqueElementData().Attributes().at(index);
    AtomicString existing_attribute_value = std::move(new_attribute.Value());
    if (reason !=
        AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
      WillModifyAttribute(existing_attribute_name, existing_attribute_value,
                          new_value);
    }
    new_attribute.SetValue(new_value);
    if (reason !=
        AttributeModificationReason::kBySynchronizationOfLazyAttribute) {
      DidModifyAttribute(existing_attribute_name, existing_attribute_value,
                         new_value, reason);
    }
  }
}

Attr* Element::setAttributeNode(Attr* attr_node,
                                ExceptionState& exception_state) {
  Attr* old_attr_node = AttrIfExists(attr_node->GetQualifiedName());
  if (old_attr_node == attr_node) {
    return attr_node;  // This Attr is already attached to the element.
  }

  // InUseAttributeError: Raised if node is an Attr that is already an attribute
  // of another Element object.  The DOM user must explicitly clone Attr nodes
  // to re-use them in other elements.
  if (attr_node->ownerElement()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInUseAttributeError,
        "The node provided is an attribute node that is already an attribute "
        "of another Element; attribute nodes must be explicitly cloned.");
    return nullptr;
  }

  if (!IsHTMLElement() && IsA<HTMLDocument>(attr_node->GetDocument()) &&
      attr_node->name() != attr_node->name().LowerASCII()) {
    UseCounter::Count(
        GetDocument(),
        WebFeature::
            kNonHTMLElementSetAttributeNodeFromHTMLDocumentNameNotLowercase);
  }

  SynchronizeAllAttributes();
  const UniqueElementData& element_data = EnsureUniqueElementData();

  AtomicString value(TrustedTypesCheckFor(
      ExpectedTrustedTypeForAttribute(attr_node->GetQualifiedName()),
      attr_node->value(), GetExecutionContext(), "Element", "setAttributeNode",
      exception_state));

"""


```