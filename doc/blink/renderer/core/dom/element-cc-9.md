Response:
My thought process to answer the request goes through these stages:

1. **Understanding the Core Request:** The request asks for the functionality of the `element.cc` file, specifically focusing on its relation to JavaScript, HTML, and CSS, providing examples, inferring logic with hypothetical inputs/outputs, detailing common user/programming errors, explaining how a user reaches this code, and summarizing its function as part 10 of 13.

2. **Initial Code Scan and High-Level Function Identification:** I first read through the provided code snippets to get a general idea of what it's doing. Keywords like `ComputedStyle`, `StyleRecalcContext`, `PseudoElement`, `SelectorFilter`, `LayoutObject`, and methods like `EnsureOwnComputedStyle`, `UpdatePseudoElement`, and `CanGeneratePseudoElement` immediately stand out. This suggests the file is heavily involved in calculating and managing the styling of elements, including pseudo-elements.

3. **Categorizing Functionality:**  I then try to group related code blocks into logical functional units. For example, the code dealing with `EnsureOwnComputedStyle` seems to be about ensuring an element has a computed style. The code with `PseudoElement` clearly manages pseudo-elements. The `SelectorFilter` part suggests interaction with CSS selectors.

4. **Relating to Web Technologies (HTML, CSS, JavaScript):** Now, I explicitly think about how these functional units relate to the core web technologies:

    * **HTML:** Elements are the fundamental building blocks of HTML. The file is named `element.cc`, so it directly deals with HTML elements. The code mentions attributes (`xml:lang`, `lang`), indicating interaction with HTML structure and semantics.

    * **CSS:**  The frequent mention of `ComputedStyle`, `SelectorFilter`, and pseudo-elements (like `::before`, `::after`, `::backdrop`) directly ties the file to CSS styling rules and their application to elements. The code calculates and caches these styles.

    * **JavaScript:** While the provided code is C++, it's part of a web browser engine that *executes* JavaScript. JavaScript's `getComputedStyle()` function would inevitably lead to the execution of code within this file. JavaScript also manipulates the DOM, which this file is a part of.

5. **Generating Examples:**  For each identified relationship, I create concrete examples. For instance, for the CSS relationship with pseudo-elements, I provide examples of CSS rules targeting `::before` and `::backdrop`. For JavaScript, I show how `window.getComputedStyle()` would trigger this code.

6. **Inferring Logic and Hypothetical Inputs/Outputs:**  I analyze code blocks with conditional logic (`if` statements). For example, the `is_in_flat_tree` check and its impact on the `filter` variable allows me to construct a hypothetical scenario where an element is outside the flat tree and predict the output (filter being disabled). Similarly, the logic for pseudo-element creation based on `CanGeneratePseudoElement` leads to input/output examples.

7. **Identifying Common Errors:** I consider what mistakes developers commonly make related to styling and DOM manipulation. For example, forgetting to set `content` for `::before`/`::after` or incorrectly assuming `getComputedStyle()` returns live values are good candidates.

8. **Tracing User Actions:** I think about the typical user interactions with a webpage that would eventually lead to this code being executed. Loading a webpage, interacting with elements (hovering, clicking), and the browser's need to render and update styles are key steps.

9. **Summarizing the Function:**  Based on the detailed analysis, I synthesize a concise summary of the file's primary role. I focus on the core tasks of style calculation, pseudo-element management, and integration with the rendering pipeline.

10. **Addressing the "Part 10 of 13" Context:**  Knowing this is part of a larger series, I infer that the preceding parts likely dealt with earlier stages of the rendering pipeline (parsing HTML/CSS, building the DOM), and the subsequent parts probably handle layout and painting. This helps contextualize the current file's position in the overall process.

11. **Refinement and Organization:** Finally, I review and organize my thoughts, ensuring clarity, accuracy, and completeness. I use headings and bullet points to structure the information logically. I double-check that I've addressed all aspects of the original request. For example, making sure to distinguish between user errors and programming errors.

Essentially, I approach the problem by dissecting the code, understanding its individual components, connecting those components to the bigger picture of web technologies, and then reconstructing the information in a way that addresses all the specific requirements of the prompt.
好的，让我们来详细分析 `blink/renderer/core/dom/element.cc` 文件的功能。

**文件功能总览:**

`element.cc` 文件是 Chromium Blink 渲染引擎中关于 DOM (Document Object Model) 元素的关键实现文件。它包含了 `Element` 类的各种方法，负责管理和维护 DOM 元素的属性、样式、以及与其他 DOM 节点的关系。这个文件是连接 HTML 结构、CSS 样式和 JavaScript 行为的核心桥梁。

**具体功能列举:**

1. **计算和管理元素的样式 (Computed Style):**
   - **`EnsureOwnComputedStyle()`:**  这是核心方法，负责确保元素拥有计算后的样式。它会检查是否需要重新计算样式，并利用 `StyleResolver` 来获取最终的样式信息。
   - **`GetComputedStyle()`:**  获取元素当前计算后的样式对象。
   - **样式重计算 (Style Recalc):** 代码中涉及 `StyleRecalcContext` 和 `StyleRecalcChange`，表明此文件参与了样式的增量更新和重新计算过程。
   - **处理 `display: contents`:**  代码中包含了对 `display: contents` 属性的特殊处理，这会影响子元素的样式继承和布局。

2. **管理伪元素 (Pseudo-elements):**
   - **`GetPseudoElement()`:** 获取元素关联的伪元素 (例如 `::before`, `::after`)。
   - **`CreatePseudoElementIfNeeded()`:**  根据 CSS 规则和元素状态，创建必要的伪元素。
   - **`UpdatePseudoElement()`:**  更新伪元素的样式。
   - **`CanGeneratePseudoElement()`:**  判断是否可以为元素生成特定的伪元素。
   - **针对特定伪元素的处理:**  代码中专门处理了 `::backdrop`, `::first-letter`, `::column`, `::scroll-marker-group` 等伪元素。

3. **处理样式继承:**
   - **`ComputeInheritedLanguage()`:** 计算元素的继承语言属性，影响文本的显示和处理。

4. **与布局 (Layout) 交互:**
   - 代码中多次提到 `LayoutObject`，表明 `element.cc` 与布局过程紧密相关。样式的计算结果会影响元素的布局。
   - **`CancelSelectionAfterLayout()`:**  在布局完成后取消文本选择。

5. **处理选择器过滤 (Selector Filtering):**
   - 代码使用了 `SelectorFilter`，这是一个优化样式计算的机制，用于快速排除不匹配的选择器。

6. **处理容器查询 (Container Queries):**
   - 代码中出现了 `IsContainerForSizeContainerQueries()` 和对 `style_recalc_context.container` 的处理，表明支持 CSS 容器查询功能。

7. **处理自定义样式回调 (Custom Style Callbacks):**
   - **`HasCustomStyleCallbacks()` 和 `CustomStyleForLayoutObject()`:**  允许某些元素 (例如 `<image>`) 提供自定义的样式计算逻辑。

8. **处理视图过渡 (View Transitions):**
   - 代码中包含了对 `::view-transition` 相关伪元素的处理，支持 CSS 视图过渡 API。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    - **`window.getComputedStyle(element)`:** 当 JavaScript 调用 `getComputedStyle` 方法时，Blink 引擎最终会执行 `element.cc` 中的相关代码来计算并返回元素的样式信息。
    - **DOM 操作:** JavaScript 通过 DOM API (例如 `document.createElement`, `element.classList.add`) 修改 HTML 结构和元素属性，这些操作可能会触发 `element.cc` 中样式的重新计算和伪元素的更新。
    - **事件监听:** JavaScript 监听用户交互事件，例如 `click`, `mouseover`，这些事件可能导致元素状态变化，进而触发样式更新。

    **举例:**

    ```javascript
    const myDiv = document.getElementById('myDiv');
    const style = window.getComputedStyle(myDiv);
    console.log(style.backgroundColor); // 调用 getComputedStyle 会触发 element.cc 中的样式计算逻辑

    myDiv.classList.add('highlight'); // 修改 class 会触发样式重新计算
    ```

* **HTML:**
    - **HTML 元素标签:**  `element.cc` 中的 `Element` 类对应于 HTML 文档中的各种元素标签 (例如 `<div>`, `<p>`, `<span>`).
    - **HTML 属性:** HTML 元素的属性 (例如 `class`, `id`, `style`, `lang`) 会影响元素的样式和行为，`element.cc` 需要处理这些属性。

    **举例:**

    ```html
    <div id="myDiv" class="container special" style="color: blue;">
      这是一个 div 元素
    </div>
    ```
    当浏览器解析这段 HTML 时，会创建对应的 `Element` 对象，并使用 `element.cc` 中的代码来处理 `id`, `class`, `style` 属性。

* **CSS:**
    - **CSS 规则:** CSS 规则定义了元素的样式。Blink 引擎的 CSS 解析器会解析 CSS，然后 `element.cc` 中的代码会根据这些规则计算元素的最终样式。
    - **选择器:** CSS 选择器用于选中特定的 HTML 元素。`element.cc` 中使用的 `SelectorFilter` 与 CSS 选择器的匹配过程有关。
    - **伪元素:** CSS 允许为元素添加伪元素 (例如 `::before`, `::after`)，`element.cc` 负责管理和渲染这些伪元素。
    - **容器查询:** CSS 的 `@container` 规则会触发 `element.cc` 中与容器查询相关的逻辑。
    - **视图过渡:** CSS 的 `view-transition-name` 属性会触发 `element.cc` 中视图过渡相关的伪元素创建和管理。

    **举例:**

    ```css
    #myDiv {
      background-color: red;
    }

    .container {
      padding: 10px;
    }

    #myDiv::before {
      content: "Before ";
      color: green;
    }

    @container (min-width: 300px) {
      #myDiv {
        font-size: 20px;
      }
    }

    ::view-transition-old(main-image) {
      /* ... */
    }
    ```
    当浏览器应用这些 CSS 规则时，`element.cc` 会负责计算 `myDiv` 元素的背景色、内边距、`::before` 伪元素的内容和颜色，以及处理容器查询和视图过渡的样式。

**逻辑推理和假设输入/输出:**

**假设输入:** 一个 `<div>` 元素，其 CSS 规则如下：

```css
.my-element {
  color: black;
}

.my-element::before {
  content: "前缀";
  color: red;
}
```

**代码片段:**

```c++
PseudoElement* Element::UpdatePseudoElement(
    PseudoId pseudo_id,
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context,
    const AtomicString& view_transition_name) {
  PseudoElement* element = GetPseudoElement(pseudo_id, view_transition_name);
  if (!element) {
    if ((element = CreatePseudoElementIfNeeded(pseudo_id, style_recalc_context,
                                               view_transition_name))) {
      // ::before and ::after can have a nested ::marker
      element->CreatePseudoElementIfNeeded(kPseudoIdMarker,
                                           style_recalc_context);
      element->SetNeedsReattachLayoutTree();
    }
    return element;
  }

  // ... (省略后续代码)
}

bool Element::CanGeneratePseudoElement(PseudoId pseudo_id) const {
  if (pseudo_id == kPseudoIdViewTransition) {
    DCHECK_EQ(this, GetDocument().documentElement());
    return !!ViewTransitionUtils::GetTransition(GetDocument());
  }
  if (pseudo_id == kPseudoIdFirstLetter && IsSVGElement()) {
    return false;
  }
  if (const ComputedStyle* style = GetComputedStyle()) {
    return style->CanGeneratePseudoElement(pseudo_id);
  }
  return false;
}
```

**推理:**

1. 当需要更新 `.my-element` 的 `::before` 伪元素时，会调用 `UpdatePseudoElement(kPseudoIdBefore, ...)`。
2. `GetPseudoElement(kPseudoIdBefore)` 会检查该元素是否已经存在 `::before` 伪元素。假设这是第一次更新，伪元素不存在。
3. `CreatePseudoElementIfNeeded(kPseudoIdBefore, ...)` 会被调用。
4. `CanGeneratePseudoElement(kPseudoIdBefore)` 会被调用，它会检查元素的 `ComputedStyle` 中是否允许生成 `::before` 伪元素 (根据 CSS 规则)。
5. 如果 CSS 规则中定义了 `.my-element::before`，`CanGeneratePseudoElement` 返回 `true`。
6. `CreatePseudoElementIfNeeded` 会创建 `::before` 伪元素。
7. 由于 `::before` 可以有嵌套的 `::marker` 伪元素，`element->CreatePseudoElementIfNeeded(kPseudoIdMarker, ...)` 也会被调用。
8. `element->SetNeedsReattachLayoutTree()` 被调用，表明伪元素的创建需要重新附加布局树。
9. 函数返回新创建的伪元素对象。

**假设输出:** 如果 `.my-element` 没有 `::before` 伪元素，该代码片段的执行结果是创建一个新的 `PseudoElement` 对象，其 `pseudo_id` 为 `kPseudoIdBefore`，并且该元素会被标记为需要重新附加布局树。

**用户或编程常见的使用错误及举例说明:**

1. **忘记设置 `content` 属性 для `::before` 或 `::after`:** 这是最常见的错误。即使定义了 `::before` 或 `::after` 选择器，如果没有设置 `content` 属性，伪元素也不会显示。

   ```css
   .my-element::before {
     /* 缺少 content 属性 */
     color: red;
   }
   ```

2. **过度依赖 `getComputedStyle` 获取动态样式:** `getComputedStyle` 返回的是当前计算后的静态样式值。如果样式是通过 JavaScript 动态修改的，在修改后需要重新调用 `getComputedStyle` 才能获取最新的值。

   ```javascript
   const element = document.getElementById('myElement');
   element.style.backgroundColor = 'blue';
   const style = window.getComputedStyle(element);
   console.log(style.backgroundColor); // 此时的 backgroundColor 可能是修改前的值，因为 getComputedStyle 是在修改前调用的
   ```

3. **在不适用的元素上使用伪元素:** 某些伪元素只适用于特定类型的元素。例如，`::first-letter` 通常只适用于块级元素。

4. **错误地理解样式继承和层叠:**  开发者可能会错误地预测样式的最终计算结果，忽略了 CSS 的继承、特殊性和层叠规则。

5. **性能问题:**  频繁地修改元素样式或进行大量的 DOM 操作可能导致浏览器频繁地进行样式重计算和布局，影响页面性能。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载网页:** 当用户在浏览器中打开一个包含 HTML 和 CSS 的网页时，Blink 引擎开始解析 HTML 构建 DOM 树，解析 CSS 构建 CSSOM 树。
2. **样式计算触发:**
   - **初始样式计算:** 在构建 DOM 和 CSSOM 后，Blink 会进行初始的样式计算，确定每个元素的初始样式。这会调用 `element.cc` 中的 `EnsureOwnComputedStyle` 等方法。
   - **动态样式更新:**
     - **用户交互:** 用户与网页进行交互 (例如鼠标悬停、点击、滚动) 可能会触发 JavaScript 代码修改元素样式或添加/删除 CSS 类。
     - **JavaScript 动画:** JavaScript 动画也可能动态修改元素样式。
     - **CSS 伪类状态变化:**  当元素的状态发生变化 (例如 `:hover`, `:focus`) 时，会触发样式的重新计算。
3. **`getComputedStyle` 调用:** 如果 JavaScript 代码调用 `window.getComputedStyle()` 方法来获取元素的样式信息，也会直接触发 `element.cc` 中的相关代码。
4. **伪元素更新:** 当 CSS 规则中定义了伪元素，或者元素的状态变化影响到伪元素的显示时，会调用 `element.cc` 中的 `UpdatePseudoElement` 等方法来创建或更新伪元素。
5. **开发者工具调试:** 开发者在使用浏览器开发者工具查看元素的 Computed 样式时，浏览器会执行 `element.cc` 中的代码来获取并显示这些信息.

**第 10 部分功能归纳:**

作为 13 个部分中的第 10 部分，`blink/renderer/core/dom/element.cc` 文件主要负责以下功能：

- **元素样式计算和管理:**  确保元素拥有正确的计算后样式，并处理样式的重新计算。
- **伪元素管理:**  创建、更新和管理元素的伪元素，响应 CSS 规则和元素状态的变化。
- **与样式系统的集成:**  与 `StyleResolver` 和 `SelectorFilter` 协同工作，完成样式解析和应用。
- **为后续布局阶段提供样式信息:**  计算出的样式将用于布局阶段，确定元素在页面上的位置和大小。

总的来说，`element.cc` 在 Blink 渲染引擎的样式处理流程中扮演着至关重要的角色，它将 HTML 结构和 CSS 样式连接起来，为元素的最终渲染呈现提供必要的样式信息。它处于样式计算流程的核心位置，是理解浏览器如何应用 CSS 的关键文件之一。

### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
Traversal::ParentElement(*top);
  Element* document_element = top->GetDocument().documentElement();

  // The filter doesn't support rejecting rules for elements outside of the
  // flat tree.  Detect that case and disable calls to the filter until
  // https://crbug.com/831568 is fixed.
  bool is_in_flat_tree =
      top == document_element ||
      (filter_root &&
       !filter_root->ComputedStyleRef().IsEnsuredOutsideFlatTree());
  if (!is_in_flat_tree) {
    filter_root = nullptr;
  }

  SelectorFilterRootScope root_scope(filter_root);
  SelectorFilterParentScope::EnsureParentStackIsPushed();
  SelectorFilter& filter =
      top->GetDocument().GetStyleResolver().GetSelectorFilter();
  GetDocument().GetStyleEngine().UpdateViewportSize();

  // Don't call FromAncestors for elements whose parent is outside the
  // flat-tree, since those elements don't actually participate in style recalc.
  auto style_recalc_context = LayoutTreeBuilderTraversal::Parent(*top)
                                  ? StyleRecalcContext::FromAncestors(*top)
                                  : StyleRecalcContext();
  style_recalc_context.is_outside_flat_tree = !is_in_flat_tree;

  for (auto it = ancestors.rbegin(); it != ancestors.rend(); it++) {
    Element* ancestor = it->Get();
    const ComputedStyle* style =
        ancestor->EnsureOwnComputedStyle(style_recalc_context, kPseudoIdNone);
    if (is_in_flat_tree) {
      filter.PushParent(*ancestor);
    }
    if (style->IsContainerForSizeContainerQueries()) {
      style_recalc_context.container = ancestor;
    }
  }

  const ComputedStyle* style = EnsureOwnComputedStyle(
      style_recalc_context, pseudo_element_specifier, pseudo_argument);

  if (is_in_flat_tree) {
    for (auto& ancestor : ancestors) {
      filter.PopParent(*ancestor.Get());
    }
  }

  return style;
}

const ComputedStyle* Element::EnsureOwnComputedStyle(
    const StyleRecalcContext& style_recalc_context,
    PseudoId pseudo_element_specifier,
    const AtomicString& pseudo_argument) {
  // FIXME: Find and use the layoutObject from the pseudo element instead of the
  // actual element so that the 'length' properties, which are only known by the
  // layoutObject because it did the layout, will be correct and so that the
  // values returned for the ":selection" pseudo-element will be correct.
  const ComputedStyle* element_style = GetComputedStyle();
  if (NeedsEnsureComputedStyle(*this)) {
    if (element_style && NeedsStyleRecalc()) {
      // RecalcStyle() will not traverse into connected elements outside the
      // flat tree and we may have a dirty element or ancestors if this
      // element is not in the flat tree. If we don't need a style recalc,
      // we can just re-use the ComputedStyle from the last
      // getComputedStyle(). Otherwise, we need to clear the ensured styles
      // for the uppermost dirty ancestor and all of its descendants. If
      // this element was not the uppermost dirty element, we would not end
      // up here because a dirty ancestor would have cleared the
      // ComputedStyle via EnsureComputedStyle and element_style would
      // have been null.
      GetDocument().GetStyleEngine().ClearEnsuredDescendantStyles(*this);
      element_style = nullptr;
    }
    if (!element_style) {
      StyleRecalcContext local_style_recalc_context = style_recalc_context;
      local_style_recalc_context.is_ensuring_style = true;
      const ComputedStyle* new_style = nullptr;
      // TODO(crbug.com/953707): Avoid setting inline style during
      // HTMLImageElement::CustomStyleForLayoutObject.
      if (HasCustomStyleCallbacks() && !IsA<HTMLImageElement>(*this)) {
        new_style = CustomStyleForLayoutObject(local_style_recalc_context);
      } else {
        new_style = OriginalStyleForLayoutObject(local_style_recalc_context);
      }
      element_style = new_style;
      SetComputedStyle(new_style);
    }
  }

  if (!pseudo_element_specifier) {
    return element_style;
  }

  if (pseudo_element_specifier == kPseudoIdSearchText &&
      !RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled()) {
    return nullptr;
  }

  if (const ComputedStyle* pseudo_element_style =
          element_style->GetCachedPseudoElementStyle(pseudo_element_specifier,
                                                     pseudo_argument)) {
    return pseudo_element_style;
  }

  const ComputedStyle* layout_parent_style = element_style;
  if (HasDisplayContentsStyle()) {
    LayoutObject* parent_layout_object =
        LayoutTreeBuilderTraversal::ParentLayoutObject(*this);
    if (parent_layout_object) {
      layout_parent_style = parent_layout_object->Style();
    }
  }

  StyleRequest style_request;
  style_request.pseudo_id = pseudo_element_specifier;
  style_request.type = StyleRequest::kForComputedStyle;
  if (style_request.pseudo_id == kPseudoIdSearchText) {
    // getComputedStyle for ::search-text is always :not(:current);
    // see <https://github.com/w3c/csswg-drafts/issues/10297>.
    DCHECK_EQ(style_request.type, StyleRequest::kForComputedStyle);
    style_request.search_text_request = StyleRequest::kNotCurrent;
  }
  if (UsesHighlightPseudoInheritance(pseudo_element_specifier)) {
    const ComputedStyle* highlight_element_style = nullptr;
    if (Element* parent = LayoutTreeBuilderTraversal::ParentElement(*this)) {
      highlight_element_style =
          parent->GetComputedStyle()->HighlightData().Style(
              pseudo_element_specifier, pseudo_argument);
    }
    style_request.parent_override = highlight_element_style;
    // All properties that apply to highlight pseudos are treated as inherited,
    // so we don't need to do anything special regarding display contents (see
    // https://drafts.csswg.org/css-pseudo/#highlight-cascade).
    style_request.layout_parent_override = highlight_element_style;
    style_request.originating_element_style = element_style;
  } else {
    style_request.parent_override = element_style;
    style_request.layout_parent_override = layout_parent_style;
  }
  style_request.pseudo_argument = pseudo_argument;

  StyleRecalcContext child_recalc_context = style_recalc_context;
  child_recalc_context.is_ensuring_style = true;
  if (element_style->IsContainerForSizeContainerQueries()) {
    child_recalc_context.container = this;
  }

  const ComputedStyle* result = GetDocument().GetStyleResolver().ResolveStyle(
      this, child_recalc_context, style_request);
  DCHECK(result);
  return element_style->AddCachedPseudoElementStyle(
      result, pseudo_element_specifier, pseudo_argument);
}

bool Element::HasDisplayContentsStyle() const {
  if (const ComputedStyle* style = GetComputedStyle()) {
    return style->Display() == EDisplay::kContents;
  }
  return false;
}

bool Element::ShouldStoreComputedStyle(const ComputedStyle& style) const {
  // If we're in a locked subtree and we're a top layer element, it means that
  // we shouldn't be creating a layout object. This path can happen if we're
  // force-updating style on the locked subtree and reach this node. Note that
  // we already detached layout when this element was added to the top layer, so
  // we simply maintain the fact that it doesn't have a layout object/subtree.
  if (style.IsRenderedInTopLayer(*this) &&
      DisplayLockUtilities::LockedAncestorPreventingPaint(*this)) {
    return false;
  }

  if (LayoutObjectIsNeeded(style)) {
    return true;
  }
  if (auto* svg_element = DynamicTo<SVGElement>(this)) {
    if (!svg_element->HasSVGParent()) {
      return false;
    }
    if (IsA<SVGStopElement>(*this)) {
      return true;
    }
  }
  return style.Display() == EDisplay::kContents;
}

AtomicString Element::ComputeInheritedLanguage() const {
  const Node* n = this;
  AtomicString value;
  // The language property is inherited, so we iterate over the parents to find
  // the first language.
  do {
    if (n->IsElementNode()) {
      if (const auto* element_data = To<Element>(n)->GetElementData()) {
        AttributeCollection attributes = element_data->Attributes();
        // Spec: xml:lang takes precedence -- http://www.w3.org/TR/xhtml1/#C_7
        if (const Attribute* attribute =
                attributes.Find(xml_names::kLangAttr)) {
          value = attribute->Value();
        } else if (n->IsHTMLElement() || n->IsSVGElement()) {
          attribute = attributes.Find(html_names::kLangAttr);
          if (attribute) {
            value = attribute->Value();
          }
        }
      }
    } else if (auto* document = DynamicTo<Document>(n)) {
      // checking the MIME content-language
      value = document->ContentLanguage();
    }

    n = n->ParentOrShadowHostNode();
  } while (n && value.IsNull());

  return value;
}

Locale& Element::GetLocale() const {
  return GetDocument().GetCachedLocale(ComputeInheritedLanguage());
}

void Element::CancelSelectionAfterLayout() {
  if (GetDocument().FocusedElement() == this) {
    GetDocument().SetShouldUpdateSelectionAfterLayout(false);
  }
}

bool Element::ShouldUpdateBackdropPseudoElement(
    const StyleRecalcChange change) {
  PseudoElement* element = GetPseudoElement(
      PseudoId::kPseudoIdBackdrop, /* view_transition_name */ g_null_atom);
  bool generate_pseudo = CanGeneratePseudoElement(PseudoId::kPseudoIdBackdrop);

  if (element) {
    return !generate_pseudo || change.ShouldUpdatePseudoElement(*element);
  }

  return generate_pseudo;
}

void Element::UpdateBackdropPseudoElement(
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context) {
  if (!ShouldUpdateBackdropPseudoElement(change)) {
    return;
  }

  if (GetDocument().GetStyleEngine().GetInterleavingRecalcRoot() != this) {
    UpdatePseudoElement(PseudoId::kPseudoIdBackdrop, change,
                        style_recalc_context);
    return;
  }

  // We have a problem when ::backdrop appears on the interleaving container,
  // because in that case ::backdrop's LayoutObject appears before the
  // container's LayoutObject. In other words, it is too late to update
  // ::backdrop at this point. Therefore, we add a pending update and deal with
  // it in a separate pass.
  //
  // See also PostStyleUpdateScope::PseudoData::AddPendingBackdrop.
  if (PostStyleUpdateScope::PseudoData* pseudo_data =
          PostStyleUpdateScope::CurrentPseudoData()) {
    pseudo_data->AddPendingBackdrop(/* originating_element */ *this);
  }
}

void Element::ApplyPendingBackdropPseudoElementUpdate() {
  PseudoElement* element = GetPseudoElement(
      PseudoId::kPseudoIdBackdrop, /* view_transition_name */ g_null_atom);

  if (!element && CanGeneratePseudoElement(PseudoId::kPseudoIdBackdrop)) {
    element = PseudoElement::Create(this, PseudoId::kPseudoIdBackdrop,
                                    /* view_transition_name */ g_null_atom);
    EnsureElementRareData().SetPseudoElement(
        PseudoId::kPseudoIdBackdrop, element,
        /* view_transition_name */ g_null_atom);
    element->InsertedInto(*this);
    GetDocument().AddToTopLayer(element, this);
  }

  DCHECK(element);
  element->SetNeedsStyleRecalc(kLocalStyleChange,
                               StyleChangeReasonForTracing::Create(
                                   style_change_reason::kConditionalBackdrop));
}

void Element::UpdateFirstLetterPseudoElement(StyleUpdatePhase phase) {
  if (CanGeneratePseudoElement(kPseudoIdFirstLetter) ||
      GetPseudoElement(kPseudoIdFirstLetter)) {
    UpdateFirstLetterPseudoElement(
        phase, StyleRecalcContext::FromInclusiveAncestors(*this));
  }
}

void Element::UpdateFirstLetterPseudoElement(
    StyleUpdatePhase phase,
    const StyleRecalcContext& style_recalc_context) {
  // Update the ::first-letter pseudo elements presence and its style. This
  // method may be called from style recalc or layout tree rebuilding/
  // reattachment. In order to know if an element generates a ::first-letter
  // element, we need to know if:
  //
  // * The element generates a block level box to which ::first-letter applies.
  // * The element's layout subtree generates any first letter text.
  // * None of the descendant blocks generate a ::first-letter element.
  //   (This is not correct according to spec as all block containers should be
  //   able to generate ::first-letter elements around the first letter of the
  //   first formatted text, but Blink is only supporting a single
  //   ::first-letter element which is the innermost block generating a
  //   ::first-letter).
  //
  // We do not always do this at style recalc time as that would have required
  // us to collect the information about how the layout tree will look like
  // after the layout tree is attached. So, instead we will wait until we have
  // an up-to-date layout sub-tree for the element we are considering for
  // ::first-letter.
  //
  // The StyleUpdatePhase tells where we are in the process of updating style
  // and layout tree.

  // We need to update quotes to create the correct text fragments before the
  // first letter element update.
  if (StyleContainmentScopeTree* tree =
          GetDocument().GetStyleEngine().GetStyleContainmentScopeTree()) {
    tree->UpdateQuotes();
  }

  PseudoElement* element = GetPseudoElement(kPseudoIdFirstLetter);
  if (!element) {
    element =
        CreatePseudoElementIfNeeded(kPseudoIdFirstLetter, style_recalc_context);
    // If we are in Element::AttachLayoutTree, don't mess up the ancestor flags
    // for layout tree attachment/rebuilding. We will unconditionally call
    // AttachLayoutTree for the created pseudo element immediately after this
    // call.
    if (element && phase != StyleUpdatePhase::kAttachLayoutTree) {
      element->SetNeedsReattachLayoutTree();
    }
    return;
  }

  if (!CanGeneratePseudoElement(kPseudoIdFirstLetter)) {
    GetElementRareData()->SetPseudoElement(kPseudoIdFirstLetter, nullptr);
    return;
  }

  LayoutObject* remaining_text_layout_object =
      FirstLetterPseudoElement::FirstLetterTextLayoutObject(*element);

  if (!remaining_text_layout_object) {
    GetElementRareData()->SetPseudoElement(kPseudoIdFirstLetter, nullptr);
    return;
  }

  if (phase == StyleUpdatePhase::kRebuildLayoutTree &&
      element->NeedsReattachLayoutTree()) {
    // We were already updated in RecalcStyle and ready for reattach.
    DCHECK(element->GetComputedStyle());
    return;
  }

  bool text_node_changed =
      remaining_text_layout_object !=
      To<FirstLetterPseudoElement>(element)->RemainingTextLayoutObject();

  if (phase == StyleUpdatePhase::kAttachLayoutTree) {
    // RemainingTextLayoutObject should have been cleared from DetachLayoutTree.
    DCHECK(!To<FirstLetterPseudoElement>(element)->RemainingTextLayoutObject());
    DCHECK(text_node_changed);
    const ComputedStyle* pseudo_style =
        element->StyleForLayoutObject(style_recalc_context);
    if (PseudoElementLayoutObjectIsNeeded(kPseudoIdFirstLetter, pseudo_style,
                                          this)) {
      element->SetComputedStyle(pseudo_style);
    } else {
      GetElementRareData()->SetPseudoElement(kPseudoIdFirstLetter, nullptr);
    }
    element->ClearNeedsStyleRecalc();
    return;
  }

  StyleRecalcChange change(StyleRecalcChange::kRecalcDescendants);
  // Remaining text part should be next to first-letter pseudo element.
  // See http://crbug.com/984389 for details.
  if (text_node_changed || remaining_text_layout_object->PreviousSibling() !=
                               element->GetLayoutObject()) {
    change = change.ForceReattachLayoutTree();
  }

  element->RecalcStyle(change, style_recalc_context);

  if (element->NeedsReattachLayoutTree() &&
      !PseudoElementLayoutObjectIsNeeded(kPseudoIdFirstLetter,
                                         element->GetComputedStyle(), this)) {
    GetElementRareData()->SetPseudoElement(kPseudoIdFirstLetter, nullptr);
    GetDocument().GetStyleEngine().PseudoElementRemoved(*this);
  }
}

void Element::ClearPseudoElement(PseudoId pseudo_id,
                                 const AtomicString& view_transition_name) {
  GetElementRareData()->SetPseudoElement(pseudo_id, nullptr,
                                         view_transition_name);
  GetDocument().GetStyleEngine().PseudoElementRemoved(*this);
}

void Element::UpdateColumnPseudoElements(const StyleRecalcChange change,
                                         const StyleRecalcContext& context) {
  const ElementRareDataVector* data = GetElementRareData();
  if (!data) {
    return;
  }
  const ColumnPseudoElementsVector* columns = data->GetColumnPseudoElements();
  if (!columns) {
    return;
  }
  if (!CanGeneratePseudoElement(kPseudoIdColumn)) {
    return ClearColumnPseudoElements();
  }
  for (ColumnPseudoElement* column : *columns) {
    if (change.ShouldUpdatePseudoElement(*column)) {
      column->RecalcStyle(change, context);
    }
  }
}

PseudoElement* Element::UpdateScrollMarkerGroupPseudoElement(
    PseudoId pseudo_id,
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context) {
  DCHECK(pseudo_id == kPseudoIdScrollMarkerGroupBefore ||
         pseudo_id == kPseudoIdScrollMarkerGroupAfter);
  StyleRecalcContext scroll_marker_group_context(style_recalc_context);
  if (style_recalc_context.container &&
      style_recalc_context.container == this) {
    // TODO(crbug.com/378584781): Needs specification.
    //
    // The ::scroll-marker-group box is a sibling of its originating element,
    // which means that it's laid out before or after its originating element.
    // That means the ::scroll-marker-group is not contained by its parent and
    // size container queries will break down. This behavior is not specified,
    // but we currently make the grandparent the first size container query
    // candidate to avoid crashing. Note that the originating element can still
    // be a query container for style() queries, for instance.
    scroll_marker_group_context.container =
        ContainerQueryEvaluator::ParentContainerCandidateElement(
            *style_recalc_context.container);
  }
  return UpdatePseudoElement(pseudo_id, change, scroll_marker_group_context);
}

PseudoElement* Element::UpdatePseudoElement(
    PseudoId pseudo_id,
    const StyleRecalcChange change,
    const StyleRecalcContext& style_recalc_context,
    const AtomicString& view_transition_name) {
  PseudoElement* element = GetPseudoElement(pseudo_id, view_transition_name);
  if (!element) {
    if ((element = CreatePseudoElementIfNeeded(pseudo_id, style_recalc_context,
                                               view_transition_name))) {
      // ::before and ::after can have a nested ::marker
      element->CreatePseudoElementIfNeeded(kPseudoIdMarker,
                                           style_recalc_context);
      element->SetNeedsReattachLayoutTree();
    }
    return element;
  }

  if (change.ShouldUpdatePseudoElement(*element)) {
    bool generate_pseudo = CanGeneratePseudoElement(pseudo_id);
    if (generate_pseudo) {
      if (auto* cache = GetDocument().ExistingAXObjectCache()) {
        cache->RemoveSubtree(this, /*remove_root*/ false);
      }
      element->RecalcStyle(change.ForPseudoElement(), style_recalc_context);
      if (element->NeedsReattachLayoutTree() &&
          !PseudoElementLayoutObjectIsNeeded(
              pseudo_id, element->GetComputedStyle(), this)) {
        generate_pseudo = false;
      }
    }
    if (!generate_pseudo) {
      ClearPseudoElement(pseudo_id, view_transition_name);
      element = nullptr;
    }
  }

  return element;
}

PseudoElement* Element::CreatePseudoElementIfNeeded(
    PseudoId pseudo_id,
    const StyleRecalcContext& style_recalc_context,
    const AtomicString& view_transition_name) {
  if (!CanGeneratePseudoElement(pseudo_id)) {
    return nullptr;
  }
  if (pseudo_id == kPseudoIdFirstLetter) {
    if (!FirstLetterPseudoElement::FirstLetterTextLayoutObject(*this)) {
      return nullptr;
    }
  }

  PseudoElement* pseudo_element =
      PseudoElement::Create(this, pseudo_id, view_transition_name);
  EnsureElementRareData().SetPseudoElement(pseudo_id, pseudo_element,
                                           view_transition_name);
  pseudo_element->InsertedInto(*this);

  const ComputedStyle* pseudo_style =
      pseudo_element->StyleForLayoutObject(style_recalc_context);
  if (!PseudoElementLayoutObjectIsNeeded(pseudo_id, pseudo_style, this)) {
    GetElementRareData()->SetPseudoElement(pseudo_id, nullptr,
                                           view_transition_name);
    return nullptr;
  }

  if (pseudo_id == kPseudoIdBackdrop) {
    GetDocument().AddToTopLayer(pseudo_element, this);
  }

  pseudo_element->SetComputedStyle(pseudo_style);

  probe::PseudoElementCreated(pseudo_element);

  return pseudo_element;
}

void Element::AttachPseudoElement(PseudoId pseudo_id, AttachContext& context) {
  if (PseudoElement* pseudo_element = GetPseudoElement(pseudo_id)) {
    pseudo_element->AttachLayoutTree(context);
  }
}

void Element::DetachPseudoElement(PseudoId pseudo_id,
                                  bool performing_reattach) {
  if (PseudoElement* pseudo_element = GetPseudoElement(pseudo_id)) {
    pseudo_element->DetachLayoutTree(performing_reattach);
  }
}

PseudoElement* Element::GetPseudoElement(
    PseudoId pseudo_id,
    const AtomicString& view_transition_name) const {
  if (ElementRareDataVector* data = GetElementRareData()) {
    return data->GetPseudoElement(pseudo_id, view_transition_name);
  }
  return nullptr;
}

Element* Element::GetStyledPseudoElement(
    PseudoId pseudo_id,
    const AtomicString& view_transition_name) const {
  if (!IsTransitionPseudoElement(pseudo_id)) {
    if (PseudoElement* result =
            GetPseudoElement(pseudo_id, view_transition_name)) {
      return result;
    }
    const AtomicString& pseudo_string =
        shadow_element_utils::StringForUAShadowPseudoId(pseudo_id);
    if (pseudo_string != g_null_atom) {
      // This is a pseudo-element that refers to an element in the UA shadow
      // tree (such as a element-backed pseudo-element).  Find it in the
      // shadow tree.
      if (ShadowRoot* root = GetShadowRoot()) {
        if (root->IsUserAgent()) {
          for (Element& el : ElementTraversal::DescendantsOf(*root)) {
            if (el.ShadowPseudoId() == pseudo_string) {
              return &el;
            }
          }
        }
      }
    }

    return nullptr;
  }

  // The transition pseudos can currently only exist on the document element.
  if (!IsDocumentElement()) {
    return nullptr;
  }

  // This traverses the pseudo element hierarchy generated in
  // RecalcTransitionPseudoTreeStyle to query nested ::view-transition-group
  // ::view-transition-image-pair and
  // ::view-transition-{old,new} pseudo elements.
  auto* transition_pseudo = GetPseudoElement(kPseudoIdViewTransition);
  if (!transition_pseudo || pseudo_id == kPseudoIdViewTransition) {
    return transition_pseudo;
  }

  auto* container_pseudo =
      To<ViewTransitionTransitionElement>(transition_pseudo)
          ->FindViewTransitionGroupPseudoElement(view_transition_name);
  if (!container_pseudo || pseudo_id == kPseudoIdViewTransitionGroup) {
    return container_pseudo;
  }

  auto* wrapper_pseudo = container_pseudo->GetPseudoElement(
      kPseudoIdViewTransitionImagePair, view_transition_name);
  if (!wrapper_pseudo || pseudo_id == kPseudoIdViewTransitionImagePair) {
    return wrapper_pseudo;
  }

  return wrapper_pseudo->GetPseudoElement(pseudo_id, view_transition_name);
}

LayoutObject* Element::PseudoElementLayoutObject(PseudoId pseudo_id) const {
  if (Element* element = GetStyledPseudoElement(
          pseudo_id, /*view_transition_name*/ g_null_atom)) {
    return element->GetLayoutObject();
  }
  return nullptr;
}

bool Element::PseudoElementStylesAffectCounters() const {
  const ComputedStyle* style = GetComputedStyle();
  if (!style) {
    return false;
  }
  const ElementRareDataVector* rare_data = GetElementRareData();
  if (!rare_data) {
    return false;
  }

  if (rare_data->PseudoElementStylesAffectCounters()) {
    return true;
  }

  if (!style->HasAnyPseudoElementStyles()) {
    return false;
  }

  for (PseudoElement* pseudo_element : rare_data->GetPseudoElements()) {
    if (pseudo_element->GetComputedStyle()->GetCounterDirectives()) {
      return true;
    }
  }

  return false;
}

bool Element::PseudoElementStylesDependOnFontMetrics() const {
  const ComputedStyle* style = GetComputedStyle();
  const ElementRareDataVector* rare_data = GetElementRareData();
  if (style && rare_data &&
      rare_data->ScrollbarPseudoElementStylesDependOnFontMetrics()) {
    return true;
  }

  auto func = [](const ComputedStyle& style) {
    return style.DependsOnFontMetrics();
  };
  return PseudoElementStylesDependOnFunc(func);
}

bool Element::PseudoElementStylesDependOnAttr() const {
  DCHECK(RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled());

  auto func = [](const ComputedStyle& style) {
    return style.HasAttrFunction();
  };
  return PseudoElementStylesDependOnFunc(func);
}

template <typename Functor>
bool Element::PseudoElementStylesDependOnFunc(Functor& func) const {
  const ComputedStyle* style = GetComputedStyle();
  if (!style) {
    return false;
  }

  if (style->HasCachedPseudoElementStyle(func)) {
    return true;
  }

  // If we don't generate a PseudoElement, its style must have been cached on
  // the originating element's ComputedStyle. Hence, it remains to check styles
  // on the generated PseudoElements.
  const ElementRareDataVector* rare_data = GetElementRareData();
  if (!rare_data) {
    return false;
  }

  // Note that |HasAnyPseudoElementStyles()| counts public pseudo elements only.
  // ::-webkit-scrollbar-*  are internal, and hence are not counted. So we must
  // perform this check after checking scrollbar pseudo element styles.
  if (!style->HasAnyPseudoElementStyles()) {
    return false;
  }

  for (PseudoElement* pseudo_element : rare_data->GetPseudoElements()) {
    if (func(*pseudo_element->GetComputedStyle())) {
      return true;
    }
  }

  return false;
}

const ComputedStyle* Element::CachedStyleForPseudoElement(
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  // Highlight pseudos are resolved into StyleHighlightData during originating
  // style recalc, and should never be stored in StyleCachedData.
  DCHECK(!UsesHighlightPseudoInheritance(pseudo_id));

  const ComputedStyle* style = GetComputedStyle();

  if (!style) {
    return nullptr;
  }
  if (pseudo_id <= kLastTrackedPublicPseudoId &&
      !style->HasPseudoElementStyle(pseudo_id)) {
    return nullptr;
  }

  if (const ComputedStyle* cached =
          style->GetCachedPseudoElementStyle(pseudo_id, pseudo_argument)) {
    return cached;
  }

  // When not using Highlight Pseudo Inheritance, as asserted above, the
  // originating element style is the same as the parent style.
  const ComputedStyle* result = UncachedStyleForPseudoElement(
      StyleRequest(pseudo_id, style, style, pseudo_argument));
  if (result) {
    return style->AddCachedPseudoElementStyle(result, pseudo_id,
                                              pseudo_argument);
  }
  return nullptr;
}

const ComputedStyle* Element::UncachedStyleForPseudoElement(
    const StyleRequest& request) {
  // Highlight pseudos are resolved into StyleHighlightData during originating
  // style recalc, where we have the actual StyleRecalcContext.
  DCHECK(!UsesHighlightPseudoInheritance(request.pseudo_id));

  return StyleForPseudoElement(
      StyleRecalcContext::FromInclusiveAncestors(*this), request);
}

const ComputedStyle* Element::StyleForPseudoElement(
    const StyleRecalcContext& style_recalc_context,
    const StyleRequest& request) {
  GetDocument().GetStyleEngine().UpdateViewportSize();

  PseudoId pseudo_id = IsPseudoElement() && request.pseudo_id == kPseudoIdNone
                           ? GetPseudoIdForStyling()
                           : request.pseudo_id;

  const bool is_before_or_after_like =
      pseudo_id == kPseudoIdCheck || pseudo_id == kPseudoIdBefore ||
      pseudo_id == kPseudoIdAfter || pseudo_id == kPseudoIdSelectArrow;

  if (is_before_or_after_like) {
    DCHECK(request.parent_override);
    DCHECK(request.layout_parent_override);

    const ComputedStyle* layout_parent_style = request.parent_override;
    if (layout_parent_style->Display() == EDisplay::kContents) {
      // TODO(futhark@chromium.org): Calling getComputedStyle for elements
      // outside the flat tree should return empty styles, but currently we do
      // not. See issue https://crbug.com/831568. We can replace the if-test
      // with DCHECK(layout_parent) when that issue is fixed.
      if (Element* layout_parent =
              LayoutTreeBuilderTraversal::LayoutParentElement(*this)) {
        layout_parent_style = layout_parent->GetComputedStyle();
      }
    }
    StyleRequest before_after_request = request;
    before_after_request.layout_parent_override = layout_parent_style;
    const ComputedStyle* result = GetDocument().GetStyleResolver().ResolveStyle(
        this, style_recalc_context, before_after_request);
    if (result) {
      if (result->GetCounterDirectives()) {
        SetPseudoElementStylesChangeCounters(true);
      }
      Element* originating_element_or_self =
          IsPseudoElement()
              ? To<PseudoElement>(this)->UltimateOriginatingElement()
              : this;
      if (auto* quote =
              DynamicTo<HTMLQuoteElement>(originating_element_or_self)) {
        ComputedStyleBuilder builder(*result);
        quote->AdjustPseudoStyleLocale(builder);
        result = builder.TakeStyle();
      }
    }
    return result;
  }

  if (pseudo_id == kPseudoIdFirstLineInherited) {
    StyleRequest first_line_inherited_request = request;
    first_line_inherited_request.pseudo_id =
        IsPseudoElement() ? To<PseudoElement>(this)->GetPseudoIdForStyling()
                          : kPseudoIdNone;
    first_line_inherited_request.can_trigger_animations = false;
    StyleRecalcContext local_recalc_context(style_recalc_context);
    local_recalc_context.old_style = PostStyleUpdateScope::GetOldStyle(*this);
    Element* target = IsPseudoElement() ? parentElement() : this;
    const ComputedStyle* result = GetDocument().GetStyleResolver().ResolveStyle(
        target, local_recalc_context, first_line_inherited_request);
    if (result) {
      ComputedStyleBuilder builder(*result);
      builder.SetStyleType(kPseudoIdFirstLineInherited);
      result = builder.TakeStyle();
    }
    return result;
  }

  // We use the originating DOM element when resolving style for ::transition*
  // pseudo elements instead of the element's direct ancestor (which could
  // itself be a pseudo element).
  DCHECK(!IsTransitionPseudoElement(GetPseudoId()) ||
         (GetDocument().documentElement() == this));

  const ComputedStyle* result = GetDocument().GetStyleResolver().ResolveStyle(
      this, style_recalc_context, request);
  if (result && result->GetCounterDirectives()) {
    SetPseudoElementStylesChangeCounters(true);
  }
  return result;
}

const ComputedStyle* Element::StyleForHighlightPseudoElement(
    const StyleRecalcContext& style_recalc_context,
    const ComputedStyle* highlight_parent,
    const ComputedStyle& originating_style,
    const PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  StyleRequest style_request{pseudo_id, highlight_parent, &originating_style,
                             pseudo_argument};
  return StyleForPseudoElement(style_recalc_context, style_request);
}

const ComputedStyle* Element::StyleForSearchTextPseudoElement(
    const StyleRecalcContext& style_recalc_context,
    const ComputedStyle* highlight_parent,
    const ComputedStyle& originating_style,
    StyleRequest::SearchTextRequest search_text_request) {
  StyleRequest style_request{kPseudoIdSearchText, highlight_parent,
                             &originating_style};
  style_request.search_text_request = search_text_request;
  return StyleForPseudoElement(style_recalc_context, style_request);
}

bool Element::CanGeneratePseudoElement(PseudoId pseudo_id) const {
  if (pseudo_id == kPseudoIdViewTransition) {
    DCHECK_EQ(this, GetDocument().documentElement());
    return !!ViewTransitionUtils::GetTransition(GetDocument());
  }
  if (pseudo_id == kPseudoIdFirstLetter && IsSVGElement()) {
    return false;
  }
  if (const ComputedStyle* style = GetComputedStyle()) {
    return style->CanGeneratePseudoElement(pseudo_id);
  }
  return false;
}

bool Element::MayTriggerVirtualKeyboard() const {
  return IsEditable(*this);
}

bool Element::matches(const AtomicString& s
```