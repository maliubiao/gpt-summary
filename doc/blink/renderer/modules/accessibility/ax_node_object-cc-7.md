Response:
The user wants to understand the functionality of the `ax_node_object.cc` file in the Chromium Blink engine, focusing on its role in accessibility. I need to break down the provided code snippets, explain what each part does, and connect it to web technologies like JavaScript, HTML, and CSS where applicable.

Here's a plan:

1. **Analyze `SelectedOptions` function:** Explain how it retrieves selected options from `<select>` elements and listboxes.
2. **Analyze `HandleAriaExpandedChanged` function:** Describe how it handles changes to the `aria-expanded` attribute and posts relevant accessibility notifications.
3. **Analyze `HandleActiveDescendantChanged` function:** Explain how it manages changes to the active descendant of an element and updates the accessibility tree accordingly.
4. **Analyze `ErrorMessage` function:** Detail how it retrieves error messages, prioritizing ARIA attributes and then HTML validation messages.
5. **Analyze `RelationVectorFromAria` function:** Explain how it retrieves related elements based on ARIA attributes.
6. **Analyze `ErrorMessageFromHTML` function:** Describe how it retrieves error messages from HTML validation.
7. **Analyze `TextAlternativeFromTooltip` function:** Explain how it derives text alternatives from the `title` attribute, interest targets, and hint popovers.
8. **Analyze `TextAlternativeFromTitleAttribute` function:**  Explain how it extracts text alternatives specifically from the `title` attribute.
9. **Analyze `NativeTextAlternative` function:** This is a complex function. I'll break it down by the HTML elements it handles (option, optgroup, label, input types, img/area, table, SVG elements, fieldset, document) and explain how it determines the text alternative for each.
10. **Analyze `GetSavedTextAlternativeFromNameSource` function:** Explain how it retrieves a previously determined text alternative and its source.
11. **Analyze `MaybeAppendFileDescriptionToName` function:** Describe how it appends the file name to the accessible name for file input elements.
12. **Analyze `ShouldIncludeContentInTextAlternative` function:** Explain the logic for determining whether an element's content should be included in its accessible name.
13. **Analyze the beginning of the `Description` function:** Explain how it calculates the accessible description of an element.
14. **Summarize the overall functionality** of the file based on the analysis of the code snippets.
这是 `blink/renderer/modules/accessibility/ax_node_object.cc` 文件的第 8 部分，主要包含以下功能：

**1. 获取选中选项 (`SelectedOptions`)**

* **功能:**  这个函数用于获取一个元素中被选中的选项。它会根据元素类型的不同进行不同的处理。
* **与 HTML 的关系:**
    * **`<select>` 元素:** 如果当前对象对应的 HTML 元素是 `<select>`，它会遍历 `select->selectedOptions()` 获取所有被选中的 `<option>` 元素，并为每个选项创建 `AXObject` 对象。
    * **例子:**
      ```html
      <select>
        <option value="apple">Apple</option>
        <option value="banana" selected>Banana</option>
        <option value="orange" selected>Orange</option>
      </select>
      ```
      假设 `GetNode()` 返回了上述 `<select>` 元素，那么 `SelectedOptions` 函数会返回包含 "Banana" 和 "Orange" 对应的 `AXObject` 的向量。
    * **ComboBox (组合框):** 如果元素的角色是 `kComboBoxGrouping` 或 `kComboBoxMenuButton`，它会查找子元素中角色为 `kListBox` 的列表框，并递归调用该列表框的 `SelectedOptions` 方法。这对应于使用 ARIA 属性构建的自定义组合框。
    * **例子:**
      ```html
      <div role="combobox" aria-expanded="true">
        <button>选择水果</button>
        <ul role="listbox">
          <li role="option">Apple</li>
          <li role="option" aria-selected="true">Banana</li>
          <li role="option" aria-selected="true">Orange</li>
        </ul>
      </div>
      ```
      如果 `GetNode()` 返回了上述 `<div>` 元素，`SelectedOptions` 会找到 `<ul>` 元素并返回 "Banana" 和 "Orange" 对应的 `AXObject`。
    * **其他元素:** 对于其他类型的元素，它会遍历其子元素，并将 `IsSelected()` 返回 `kSelectedStateTrue` 的子元素添加到结果中。这适用于使用 ARIA 属性（例如 `aria-selected="true"`) 标记选中状态的元素。
    * **例子:**
      ```html
      <div role="radiogroup">
        <div role="radio">Apple</div>
        <div role="radio" aria-checked="true">Banana</div>
        <div role="radio">Orange</div>
      </div>
      ```
      如果 `GetNode()` 返回了上述 `<div>` 元素，`SelectedOptions` 会返回 "Banana" 对应的 `AXObject` (假设 `IsSelected()` 内部逻辑会根据 `aria-checked` 属性判断选中状态)。

**2. 处理 `aria-expanded` 属性变化 (`HandleAriaExpandedChanged`)**

* **功能:** 当元素的 `aria-expanded` 属性发生变化时，这个函数会被调用。它会向上查找特定的父元素（如表格、树形结构、网格等），并通知它们行数可能发生了变化。同时，它还会通知自身展开或折叠的状态。
* **与 HTML 和 JavaScript 的关系:**
    * **HTML (ARIA):**  依赖于 HTML 中使用的 `aria-expanded` 属性来指示元素是否展开。
    * **JavaScript:**  当 JavaScript 代码修改元素的 `aria-expanded` 属性时，Blink 引擎会捕获到这个变化并触发 `HandleAriaExpandedChanged`。
    * **例子 (假设输入):**
      ```html
      <ul role="tree">
        <li role="treeitem" aria-expanded="false">
          Parent 1
          <ul>
            <li role="treeitem">Child 1</li>
          </ul>
        </li>
      </ul>
      <script>
        const parent1 = document.querySelector('li[role="treeitem"]');
        parent1.setAttribute('aria-expanded', 'true');
      </script>
      ```
      **假设输入:**  JavaScript 将 `aria-expanded` 从 "false" 修改为 "true"。
      **输出:**
        * 向上查找，如果找到 `<ul role="tree">` 元素，则会向该父元素发送 `ax::mojom::blink::Event::kRowCountChanged` 通知，因为展开了一个子项，可能导致行数增加。
        * 向自身 (role="treeitem") 发送 `ax::mojom::blink::Event::kRowExpanded` 通知，表明该行已展开。

**3. 处理活动后代变化 (`HandleActiveDescendantChanged`)**

* **功能:** 当元素的 ARIA `aria-activedescendant` 属性指向的后代元素发生变化时，此函数会被调用。它主要处理焦点变化和选择状态的更新。
* **与 HTML 和 JavaScript 的关系:**
    * **HTML (ARIA):**  依赖于 HTML 中使用的 `aria-activedescendant` 属性来指定当前活动（获得焦点）的后代元素。
    * **JavaScript:** 当 JavaScript 代码修改元素的 `aria-activedescendant` 属性，或者通过其他方式将焦点移动到某个后代元素时，可能会触发此函数。
    * **假设输入与输出:**
      ```html
      <div role="listbox" tabindex="0" aria-activedescendant="option2">
        <div role="option" id="option1">Option 1</div>
        <div role="option" id="option2">Option 2</div>
        <div role="option" id="option3">Option 3</div>
      </div>
      <script>
        const listbox = document.querySelector('div[role="listbox"]');
        const option3 = document.getElementById('option3');
        listbox.setAttribute('aria-activedescendant', 'option3');
        option3.focus(); // 或者通过其他方式使 option3 成为焦点
      </script>
      ```
      **假设输入:** `aria-activedescendant` 从 "option2" 变为 "option3"，并且焦点也移动到了 "Option 3"。
      **输出:**
        * 如果获得焦点的节点 (`GetDocument()->FocusedElement()`) 是 listbox 元素本身，并且新的活动后代 (`ActiveDescendant()`) 存在：
          * 如果活动后代是被选中状态 (`IsSelectedFromFocus()` 为真，例如单选列表)，则会触发活动后代的 `HandleAriaSelectedChangedWithCleanLayout`，确保辅助技术收到选择状态变化的通知。
          * 如果活动后代的角色是 `kRow` (表格行)，则会将该活动后代标记为脏 (dirty)，因为其可访问名称可能从内容中获取。
        * 无论如何，会将 listbox 元素本身标记为脏，`AXEventGenerator` 会自动推断出活动后代发生了变化，并通知辅助技术。

**4. 获取错误消息 (`ErrorMessage`)**

* **功能:**  这个函数用于获取与当前元素关联的错误消息。它首先查找 ARIA `aria-errormessage` 属性引用的元素，如果找不到，则查找 HTML 验证 API 提供的错误消息。
* **与 HTML 和 JavaScript 的关系:**
    * **HTML (ARIA):**  支持使用 `aria-errormessage` 属性关联错误消息元素。
    * **HTML (验证 API):** 支持使用 HTML 表单验证和 `setCustomValidity` 等 JavaScript 方法设置错误消息。
    * **例子:**
      ```html
      <input type="text" aria-invalid="true" aria-errormessage="msg">
      <div id="msg">This field is required.</div>

      <input type="email" required id="email">
      <span id="email-error" role="alert" aria-live="assertive"></span>
      <script>
        const emailInput = document.getElementById('email');
        const emailError = document.getElementById('email-error');
        emailInput.addEventListener('invalid', function(event) {
          event.preventDefault();
          emailError.textContent = 'Please enter a valid email address.';
        });
      </script>
      ```
      **假设输入:** 对于第一个 `<input>` 元素，`ErrorMessage` 会找到 `aria-errormessage` 指向的 `<div>` 元素，并返回其对应的 `AXObject`。对于第二个 `<input>` 元素，如果由于验证失败而触发了错误消息，并且焦点在该输入框上，`ErrorMessage` 可能会返回由验证 API 提供的错误消息对应的 `AXObject` (通过 `AXObjectCache().ValidationMessageObjectIfInvalid()`)。

**5. 从 ARIA 属性获取关联对象向量 (`RelationVectorFromAria`)**

* **功能:**  根据指定的 ARIA 属性 (例如 `aria-describedby`, `aria-labelledby`) 的值，找到引用的 HTML 元素，并返回这些元素对应的 `AXObject` 向量。
* **与 HTML 的关系:**  直接依赖于 HTML 中使用的 ARIA 关系属性。
* **例子:**
  ```html
  <label id="label1" for="input1">Enter your name:</label>
  <input type="text" id="input1" aria-describedby="desc1">
  <p id="desc1">This is where you enter your name.</p>
  ```
  如果针对 `<input>` 元素调用 `RelationVectorFromAria(html_names::kAriaDescribedbyAttr)`，它会找到 `desc1` 对应的 `<p>` 元素，并返回其 `AXObject`。

**6. 从 HTML 获取错误消息向量 (`ErrorMessageFromHTML`)**

* **功能:**  获取由 HTML 表单验证机制产生的错误消息。只有当焦点在当前元素上且该元素无效时，才会尝试获取验证消息对象。
* **与 HTML 和 JavaScript 的关系:**
    * **HTML (验证):**  依赖于 HTML 元素的验证属性 (例如 `required`, `pattern`)。
    * **JavaScript (验证 API):**  依赖于 JavaScript 的 `setCustomValidity` 方法设置自定义验证消息。
* **假设输入与输出:**
  ```html
  <input type="email" required id="email">
  <script>
    const emailInput = document.getElementById('email');
    emailInput.setCustomValidity('This is a custom error message.');
  </script>
  ```
  **假设输入:**  焦点在 `email` 输入框上，且该输入框由于 `setCustomValidity` 设置了错误消息而无效。
  **输出:** `ErrorMessageFromHTML` 会调用 `AXObjectCache().ValidationMessageObjectIfInvalid()`，如果存在验证消息对象，则返回包含该对象的向量。

**7. 从 Tooltip 获取文本替代 (`TextAlternativeFromTooltip`)**

* **功能:** 尝试从元素的 `title` 属性、兴趣目标 (`interestTarget`) 或提示弹出框 (`hint popover`) 中获取文本替代。它会优先考虑兴趣目标和提示弹出框，如果内容是纯文本，则直接使用其文本内容作为替代文本。
* **与 HTML 和 JavaScript 的关系:**
    * **HTML:**  依赖于 `title` 属性、`interesttarget` 属性（实验性特性）和弹出框 API (`popover`)。
    * **JavaScript:**  JavaScript 可以动态设置这些属性或创建弹出框。
* **例子:**
  ```html
  <button title="Click me">Submit</button>

  <button interesttarget="hint1">Hover me</button>
  <div id="hint1">This is a helpful hint.</div>

  <button popovertarget="hint2">Hover for hint</button>
  <div popover id="hint2" popover-type="hint">Another hint here.</div>
  ```
  * 对于第一个按钮，`TextAlternativeFromTooltip` 会返回 "Click me"。
  * 对于第二个按钮，如果启用了 `HTMLInterestTargetAttributeEnabled()`，且 "This is a helpful hint." 是纯文本内容，则会返回 "This is a helpful hint."。
  * 对于第三个按钮，如果启用了 `HTMLPopoverHintEnabled()`，且 "Another hint here." 是纯文本内容，则会返回 "Another hint here."。

**8. 从 Title 属性获取文本替代 (`TextAlternativeFromTitleAttribute`)**

* **功能:**  专门从元素的 `title` 属性中提取文本替代。如果 `title` 属性的值与元素的内部文本相同，则不会使用该 `title` 属性作为替代文本。
* **与 HTML 的关系:**  直接依赖于 HTML 的 `title` 属性。
* **例子:**
  ```html
  <a href="#" title="Learn more">Learn more</a>
  <abbr title="World Health Organization">WHO</abbr>
  ```
  * 对于第一个链接，由于 `title` 属性的值与内部文本相同，`TextAlternativeFromTitleAttribute` 将返回空字符串。
  * 对于第二个缩写，`TextAlternativeFromTitleAttribute` 将返回 "World Health Organization"。

**9. 获取原生文本替代 (`NativeTextAlternative`)**

* **功能:**  这是获取元素原生文本替代的核心函数。它根据元素的不同类型和属性，按照 HTML AAM 规范规定的优先级顺序提取文本替代。
* **与 HTML 的关系:**  该函数处理各种 HTML 元素，例如：
    * **`<option>`:** 使用 `DisplayLabel()` 方法，除非有有趣的子元素。
    * **`<optgroup>`:** 使用 `GroupLabelText()`。
    * **可被 Label 关联的元素 (例如 `<input>`, `<select>`):**  查找关联的 `<label>` 元素，并提取其文本内容。
    * **`<input type="button">`, `<input type="submit">`, `<input type="reset">`:** 使用 `value` 属性，或者在未布局时使用默认标签。
    * **`<input type="image">`:** 优先使用 `alt` 属性，其次是 `value` 属性，然后是 `title` 或弹出框，最后是本地化的默认值（例如 "Submit"）。
    * **`<input type="file">`:** 使用影子 DOM 中按钮的标签加上 `value` 属性。
    * **文本输入框:** 优先使用 `title` 属性或弹出框，然后是 `placeholder` 属性，最后是 ARIA `aria-placeholder` 属性。
    * **`<img>` 和 `<area>`:** 使用 `alt` 属性。
    * **`<table>`:** 使用 `<caption>` 元素的文本内容，然后是 `summary` 属性。
    * **SVG 元素:** 使用 `<title>` 元素的文本内容，对于链接 `<a ref="...">` 还会考虑 `xlink:title` 属性。
    * **`<fieldset>`:** 使用 `<legend>` 元素的文本内容.
    * **`document`:** 使用 `aria-label` 属性，然后是 `<title>` 元素的内容。
* **逻辑推理 (假设输入与输出示例):**
  ```html
  <input type="text" placeholder="Enter your email" aria-label="Email Address">
  ```
  **假设输入:** `GetNode()` 返回上述 `<input>` 元素。
  **输出:** `NativeTextAlternative` 会首先检查 `aria-label` 属性，发现其值为 "Email Address"，因此返回 "Email Address"，并将 `name_from` 设置为 `ax::mojom::blink::NameFrom::kAttribute`。

**10. 获取已保存的来自名称来源的文本替代 (`GetSavedTextAlternativeFromNameSource`)**

* **功能:**  从 `NameSources` 结构中检索之前计算并保存的文本替代及其来源信息。这允许在计算过程中重用已有的结果，避免重复计算。
* **与之前功能的联系:**  `NativeTextAlternative` 等函数会将计算出的文本替代和来源信息存储在 `NameSources` 中，供后续使用。
* **假设输入与输出:**
  **假设输入:** `name_sources` 中包含一个条目，其中 `text` 为 "Example Text"，`type` 为 `ax::mojom::blink::NameFrom::kAriaLabel`。
  **输出:** 该函数将返回 "Example Text"，并将 `name_from` 设置为 `ax::mojom::blink::NameFrom::kAriaLabel`。

**11. 可能将文件描述附加到名称 (`MaybeAppendFileDescriptionToName`)**

* **功能:**  如果当前元素是 `<input type="file">`，则将用户选择的文件名附加到已有的名称上。
* **与 HTML 的关系:**  专门针对 `<input type="file">` 元素。
* **例子:**
  ```html
  <label for="file-upload">Upload file:</label>
  <input type="file" id="file-upload">
  ```
  **假设输入:** 用户选择了名为 "document.pdf" 的文件，并且该 `<input>` 元素的名称 (通过其他方式计算得到) 为 "Upload file"。
  **输出:** `MaybeAppendFileDescriptionToName` 将返回 "Upload file: document.pdf"。

**12. 应该在文本替代中包含内容 (`ShouldIncludeContentInTextAlternative`)**

* **功能:**  判断是否应该将元素的内部内容包含在其文本替代中。这取决于多种因素，包括元素是否支持从内容获取名称 (`SupportsNameFromContents`)，以及是否是特定的元素类型 (例如 `<select>`, 文本输入框)。
* **与 HTML 的关系:**  涉及到各种 HTML 元素的特性。
* **逻辑推理:**
    * 如果既不是在计算 `aria-label` 或 `aria-description` 的上下文，且元素不支持从内容获取名称，则返回 `false`。
    * 如果是 `<select>` 元素，则返回 `false` (避免包含选项的文本)。
    * 如果是文本输入框，并且不是因为 `aria-labelledby` 明确引用了自身的内容，则返回 `false` (避免将输入框的值包含在名称中)。

**13. 描述信息 (`Description`) 的开始**

* **功能:**  这是计算元素可访问描述信息的函数。它会调用底层的描述计算逻辑，并处理一些后续的清理和特殊情况。
* **与之前功能的联系:**  该函数会调用其他函数来获取描述信息。
* **用户或编程常见的使用错误:** 如果开发者过度依赖自动生成的描述信息，可能会导致描述信息过于冗余或不准确。例如，如果一个按钮的文本内容已经很清晰，就不需要额外的描述信息。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户与网页交互:** 用户在网页上进行操作，例如点击按钮、输入文本、选择下拉框选项、展开/折叠树形节点等。
2. **浏览器事件触发:** 这些用户操作会触发相应的浏览器事件 (例如 `click`, `input`, `change`, `focus`).
3. **Blink 引擎处理事件:** Blink 引擎接收到这些事件，并更新 DOM 树和渲染树。
4. **辅助功能树更新:**  当 DOM 树或渲染树发生变化，与辅助功能相关的部分也会被标记为需要更新。
5. **`AXObjectCache` 参与:** `AXObjectCache` 负责维护辅助功能对象树。当需要获取或更新某个元素的辅助功能信息时，会涉及到 `AXNodeObject` 类。
6. **调用 `AXNodeObject` 的方法:**  例如，当需要获取一个元素的选中选项时，可能会调用 `SelectedOptions`；当 `aria-expanded` 属性变化时，会调用 `HandleAriaExpandedChanged`。
7. **例如，展开一个树形节点:**
    * 用户点击一个带有 `aria-expanded="false"` 的树形节点。
    * JavaScript 代码可能会修改该节点的 `aria-expanded` 属性为 "true"。
    * Blink 引擎观察到 `aria-expanded` 属性的变化。
    * 针对该节点对应的 `AXNodeObject` 对象，`HandleAriaExpandedChanged` 方法被调用。
    * 该方法向上查找父元素，并通知它们行数可能发生变化，同时通知自身已展开。
8. **例如，获取表单元素的错误消息:**
    * 用户提交表单，或者焦点离开一个带有验证错误的表单字段。
    * Blink 引擎会检查表单的验证状态。
    * 当辅助技术请求获取某个表单字段的错误消息时，会调用该字段对应 `AXNodeObject` 的 `ErrorMessage` 方法。
    * `ErrorMessage` 方法会尝试从 `aria-errormessage` 或 HTML 验证 API 获取错误消息。

**总结第 8 部分的功能:**

`ax_node_object.cc` 文件的第 8 部分主要负责以下辅助功能相关的逻辑：

* **处理元素的选择状态:** 获取选中选项。
* **响应 `aria-expanded` 属性的变化:** 通知相关的父元素和自身展开/折叠状态的变化。
* **管理活动后代:**  处理 `aria-activedescendant` 属性的变化，更新焦点和选择状态。
* **获取元素的错误消息:** 从 ARIA 属性或 HTML 验证机制中获取错误消息。
* **获取关联对象:**  根据 ARIA 关系属性查找关联的辅助功能对象。
* **计算元素的文本替代 (Accessible Name):**  这是核心功能，它根据 HTML 规范和 ARIA 属性，以不同的策略为不同类型的元素计算出可访问的名称。包括从 `title` 属性、`alt` 属性、`label` 元素、`placeholder` 属性、弹出框等多种来源获取。
* **辅助功能描述 (Accessible Description) 的开始:**  开始计算元素的可访问描述信息。

总而言之，这部分代码是 Blink 引擎实现 Web 内容可访问性的关键组成部分，它连接了 HTML 结构、ARIA 属性和 JavaScript 行为，为辅助技术提供了理解和呈现网页内容所需的必要信息。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_node_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
o<HTMLSelectElement>(GetNode())) {
    for (auto* const option : *select->selectedOptions()) {
      AXObject* ax_option = AXObjectCache().Get(option);
      if (ax_option)
        options.push_back(ax_option);
    }
    return;
  }

  const AXObjectVector& children = ChildrenIncludingIgnored();
  if (RoleValue() == ax::mojom::blink::Role::kComboBoxGrouping ||
      RoleValue() == ax::mojom::blink::Role::kComboBoxMenuButton) {
    for (const auto& obj : children) {
      if (obj->RoleValue() == ax::mojom::blink::Role::kListBox) {
        obj->SelectedOptions(options);
        return;
      }
    }
  }

  for (const auto& obj : children) {
    if (obj->IsSelected() == kSelectedStateTrue)
      options.push_back(obj);
  }
}

//
// Notifications that this object may have changed.
//

void AXNodeObject::HandleAriaExpandedChanged() {
  // Find if a parent of this object should handle aria-expanded changes.
  AXObject* container_parent = ParentObject();
  while (container_parent) {
    bool found_parent = false;

    switch (container_parent->RoleValue()) {
      case ax::mojom::blink::Role::kLayoutTable:
      case ax::mojom::blink::Role::kTree:
      case ax::mojom::blink::Role::kTreeGrid:
      case ax::mojom::blink::Role::kGrid:
      case ax::mojom::blink::Role::kTable:
        found_parent = true;
        break;
      default:
        break;
    }

    if (found_parent)
      break;

    container_parent = container_parent->ParentObject();
  }

  // Post that the row count changed.
  if (container_parent) {
    AXObjectCache().PostNotification(container_parent,
                                     ax::mojom::blink::Event::kRowCountChanged);
  }

  // Post that the specific row either collapsed or expanded.
  AccessibilityExpanded expanded = IsExpanded();
  if (!expanded)
    return;

  if (RoleValue() == ax::mojom::blink::Role::kRow ||
      RoleValue() == ax::mojom::blink::Role::kTreeItem) {
    ax::mojom::blink::Event notification =
        ax::mojom::blink::Event::kRowExpanded;
    if (expanded == kExpandedCollapsed)
      notification = ax::mojom::blink::Event::kRowCollapsed;

    AXObjectCache().PostNotification(this, notification);
  } else {
    AXObjectCache().PostNotification(this,
                                     ax::mojom::blink::Event::kExpandedChanged);
  }
}

void AXNodeObject::HandleActiveDescendantChanged() {
  if (!GetLayoutObject() || !GetNode() || !GetDocument())
    return;

  Node* focused_node = GetDocument()->FocusedElement();
  if (focused_node == GetNode()) {
    AXObject* active_descendant = ActiveDescendant();
    if (active_descendant) {
      if (active_descendant->IsSelectedFromFocus()) {
        // In single selection containers, selection follows focus, so a
        // selection changed event must be fired. This ensures the AT is
        // notified that the selected state has changed, so that it does not
        // read "unselected" as the user navigates through the items.
        AXObjectCache().HandleAriaSelectedChangedWithCleanLayout(
            active_descendant->GetNode());
      } else if (active_descendant->RoleValue() ==
                 ax::mojom::blink::Role::kRow) {
        // Active descendant rows must be marked dirty because that can make
        // them gain accessible name from contents
        // (see AXObject::SupportsNameFromContents).
        AXObjectCache().MarkAXObjectDirtyWithCleanLayout(active_descendant);
      }
    }

    // Mark this node dirty. AXEventGenerator will automatically infer
    // that the active descendant changed.
    AXObjectCache().MarkAXObjectDirtyWithCleanLayout(this);
  }
}

AXObject::AXObjectVector AXNodeObject::ErrorMessage() const {
  if (GetInvalidState() == ax::mojom::blink::InvalidState::kFalse)
    return AXObjectVector();

  AXObjectVector aria_error_messages =
      RelationVectorFromAria(html_names::kAriaErrormessageAttr);
  if (aria_error_messages.size() > 0) {
    return aria_error_messages;
  }

  AXObjectVector html_error_messages = ErrorMessageFromHTML();
  if (html_error_messages.size() > 0) {
    return html_error_messages;
  }

  return AXObjectVector();
}

AXObject::AXObjectVector AXNodeObject::RelationVectorFromAria(
    const QualifiedName& attr_name) const {
  Element* el = GetElement();
  if (!el) {
    return AXObjectVector();
  }

  const HeapVector<Member<Element>>* elements_from_attribute =
      ElementsFromAttributeOrInternals(el, attr_name);
  if (!elements_from_attribute) {
    return AXObjectVector();
  }

  AXObjectVector objects;
  for (Element* element : *elements_from_attribute) {
    AXObject* obj = AXObjectCache().Get(element);
    if (obj && !obj->IsIgnored()) {
      objects.push_back(obj);
    }
  }
  return objects;
}

AXObject::AXObjectVector AXNodeObject::ErrorMessageFromHTML() const {
  // This can only be visible for a focused
  // control. Corollary: if there is a visible validationMessage alert box, then
  // it is related to the current focus.
  if (this != AXObjectCache().FocusedObject()) {
    return AXObjectVector();
  }

  AXObject* native_error_message =
      AXObjectCache().ValidationMessageObjectIfInvalid();
  if (native_error_message && !native_error_message->IsDetached()) {
    CHECK_GE(native_error_message->IndexInParent(), 0);
    return AXObjectVector({native_error_message});
  }

  return AXObjectVector();
}

String AXNodeObject::TextAlternativeFromTooltip(
    ax::mojom::blink::NameFrom& name_from,
    NameSources* name_sources,
    bool* found_text_alternative,
    String* text_alternative,
    AXRelatedObjectVector* related_objects) const {
  if (!GetElement()) {
    return String();
  }
  name_from = ax::mojom::blink::NameFrom::kTitle;
  const AtomicString& title = GetElement()->FastGetAttribute(kTitleAttr);
  String title_text = TextAlternativeFromTitleAttribute(
      title, name_from, name_sources, found_text_alternative);
  // Do not use if empty or if redundant with inner text.
  if (!title_text.empty()) {
    *text_alternative = title_text;
    return title_text;
  }

  // First try for interest target, then for hint popover.
  // TODO(accessibility) Consider only using interest target.
  AXObject* popover_ax_object = nullptr;
  if (RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled()) {
    popover_ax_object =
        AXObjectCache().Get(GetElement()->interestTargetElement());
  }
  if (popover_ax_object) {
    DCHECK(RuntimeEnabledFeatures::HTMLInterestTargetAttributeEnabled());
    name_from = ax::mojom::blink::NameFrom::kInterestTarget;
  } else {
    auto* form_control = DynamicTo<HTMLFormControlElement>(GetElement());
    if (!form_control) {
      return String();
    }
    auto popover_target = form_control->popoverTargetElement();
    if (!popover_target.popover ||
        popover_target.popover->PopoverType() != PopoverValueType::kHint) {
      return String();
    }
    popover_ax_object = AXObjectCache().Get(popover_target.popover);
    name_from = ax::mojom::blink::NameFrom::kPopoverTarget;
    DCHECK(RuntimeEnabledFeatures::HTMLPopoverHintEnabled());
  }

  if (name_sources) {
    name_sources->push_back(
        NameSource(*found_text_alternative, html_names::kPopovertargetAttr));
    name_sources->back().type = name_from;
  }

  // Hint popovers and interest targets are used for text if and only if all of
  // the contents are plain, e.g. have no interesting semantic or interactive
  // elements. Otherwise, the hint will be exposed via the kDetails
  // relationship. The motivation for this is that by reusing the simple
  // mechanism of titles, screen reader users can easily access the information
  // of plain hints without having to navigate to it, making the content more
  // accessible. However, in the case of rich hints, a kDetails relationship is
  // required to ensure that users are able to access and interact with the hint
  // as they can navigate to it using commands.
  if (!popover_ax_object || !popover_ax_object->IsPlainContent()) {
    return String();
  }
  AXObjectSet visited;
  String popover_text =
      RecursiveTextAlternative(*popover_ax_object, popover_ax_object, visited);
  // Do not use if redundant with inner text.
  if (popover_text.StripWhiteSpace() ==
      GetElement()->GetInnerTextWithoutUpdate().StripWhiteSpace()) {
    return String();
  }
  *text_alternative = popover_text;
  if (related_objects) {
    related_objects->push_back(MakeGarbageCollected<NameSourceRelatedObject>(
        popover_ax_object, popover_text));
  }

  if (name_sources) {
    NameSource& source = name_sources->back();
    source.related_objects = *related_objects;
    source.text = *text_alternative;
    *found_text_alternative = true;
  }

  return popover_text;
}

String AXNodeObject::TextAlternativeFromTitleAttribute(
    const AtomicString& title,
    ax::mojom::blink::NameFrom& name_from,
    NameSources* name_sources,
    bool* found_text_alternative) const {
  DCHECK(GetElement());
  String text_alternative;
  if (name_sources) {
    name_sources->push_back(NameSource(*found_text_alternative, kTitleAttr));
    name_sources->back().type = name_from;
  }
  name_from = ax::mojom::blink::NameFrom::kTitle;
  if (!title.IsNull() &&
      String(title).StripWhiteSpace() !=
          GetElement()->GetInnerTextWithoutUpdate().StripWhiteSpace()) {
    text_alternative = title;
    if (name_sources) {
      NameSource& source = name_sources->back();
      source.attribute_value = title;
      source.attribute_value = title;
      source.text = text_alternative;
      *found_text_alternative = true;
    }
  }
  return text_alternative;
}

// Based on
// https://www.w3.org/TR/html-aam-1.0/#accessible-name-and-description-computation
String AXNodeObject::NativeTextAlternative(
    AXObjectSet& visited,
    ax::mojom::blink::NameFrom& name_from,
    AXRelatedObjectVector* related_objects,
    NameSources* name_sources,
    bool* found_text_alternative) const {
  if (!GetNode())
    return String();

  // If nameSources is non-null, relatedObjects is used in filling it in, so it
  // must be non-null as well.
  if (name_sources)
    DCHECK(related_objects);

  String text_alternative;
  AXRelatedObjectVector local_related_objects;

  if (auto* option_element = DynamicTo<HTMLOptionElement>(GetNode())) {
    if (option_element->HasOneTextChild()) {
      // Use the DisplayLabel() method if there are no interesting children.
      // If there are interesting children, fall through and compute the name
      // from contents rather, so that descendant markup is respected.
      name_from = ax::mojom::blink::NameFrom::kContents;
      text_alternative = option_element->DisplayLabel();
      if (!text_alternative.empty()) {
        if (name_sources) {
          name_sources->push_back(NameSource(*found_text_alternative));
          name_sources->back().type = name_from;
          name_sources->back().text = text_alternative;
          *found_text_alternative = true;
        }
        return text_alternative;
      }
    }
  }

  if (auto* opt_group_element = DynamicTo<HTMLOptGroupElement>(GetNode())) {
    name_from = ax::mojom::blink::NameFrom::kAttribute;
    text_alternative = opt_group_element->GroupLabelText();
    if (!text_alternative.empty()) {
      if (name_sources) {
        name_sources->push_back(NameSource(*found_text_alternative));
        name_sources->back().type = name_from;
        name_sources->back().text = text_alternative;
        *found_text_alternative = true;
      }
      return text_alternative;
    }
  }

  // 5.1/5.5 Text inputs, Other labelable Elements
  // If you change this logic, update AXNodeObject::IsNameFromLabelElement, too.
  auto* html_element = DynamicTo<HTMLElement>(GetNode());
  if (html_element && html_element->IsLabelable()) {
    name_from = ax::mojom::blink::NameFrom::kRelatedElement;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative));
      name_sources->back().type = name_from;
      name_sources->back().native_source = kAXTextFromNativeHTMLLabel;
    }

    LabelsNodeList* labels = nullptr;
    if (AXObjectCache().MayHaveHTMLLabel(*html_element))
      labels = html_element->labels();
    if (labels && labels->length() > 0) {
      HeapVector<Member<Element>> label_elements;
      for (unsigned label_index = 0; label_index < labels->length();
           ++label_index) {
        Element* label = labels->item(label_index);
        if (name_sources) {
          if (!label->FastGetAttribute(html_names::kForAttr).empty() &&
              label->FastGetAttribute(html_names::kForAttr) ==
                  html_element->GetIdAttribute()) {
            name_sources->back().native_source = kAXTextFromNativeHTMLLabelFor;
          } else {
            name_sources->back().native_source =
                kAXTextFromNativeHTMLLabelWrapped;
          }
        }
        label_elements.push_back(label);
      }

      text_alternative =
          TextFromElements(false, visited, label_elements, related_objects);
      if (!text_alternative.IsNull()) {
        *found_text_alternative = true;
        if (name_sources) {
          NameSource& source = name_sources->back();
          source.related_objects = *related_objects;
          source.text = text_alternative;
        } else {
          return text_alternative.StripWhiteSpace();
        }
      } else if (name_sources) {
        name_sources->back().invalid = true;
      }
    }
  }

  // 5.2 input type="button", input type="submit" and input type="reset"
  const auto* input_element = DynamicTo<HTMLInputElement>(GetNode());
  if (input_element && input_element->IsTextButton()) {
    // value attribute.
    name_from = ax::mojom::blink::NameFrom::kValue;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kValueAttr));
      name_sources->back().type = name_from;
    }
    String value = input_element->Value();
    if (!value.IsNull()) {
      text_alternative = value;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }

    // Get default value if object is not laid out.
    // If object is laid out, it will have a layout object for the label.
    if (!GetLayoutObject()) {
      String default_label = input_element->ValueOrDefaultLabel();
      if (value.IsNull() && !default_label.IsNull()) {
        // default label
        name_from = ax::mojom::blink::NameFrom::kContents;
        if (name_sources) {
          name_sources->push_back(NameSource(*found_text_alternative));
          name_sources->back().type = name_from;
        }
        text_alternative = default_label;
        if (name_sources) {
          NameSource& source = name_sources->back();
          source.text = text_alternative;
          *found_text_alternative = true;
        } else {
          return text_alternative;
        }
      }
    }
    return text_alternative;
  }

  // 5.3 input type="image"
  if (input_element &&
      input_element->getAttribute(kTypeAttr) == input_type_names::kImage) {
    // alt attr
    const AtomicString& alt = input_element->getAttribute(kAltAttr);
    const bool is_empty = alt.empty() && !alt.IsNull();
    name_from = is_empty ? ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty
                         : ax::mojom::blink::NameFrom::kAttribute;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kAltAttr));
      name_sources->back().type = name_from;
    }
    if (!alt.empty()) {
      text_alternative = alt;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.attribute_value = alt;
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }

    // value attribute.
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kValueAttr));
      name_sources->back().type = name_from;
    }
    name_from = ax::mojom::blink::NameFrom::kAttribute;
    String value = input_element->Value();
    if (!value.IsNull()) {
      text_alternative = value;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }

    // title attr or popover
    String resulting_text = TextAlternativeFromTooltip(
        name_from, name_sources, found_text_alternative, &text_alternative,
        related_objects);
    if (!resulting_text.empty()) {
      if (name_sources) {
        text_alternative = resulting_text;
      } else {
        return resulting_text;
      }
    }

    // localised default value ("Submit")
    name_from = ax::mojom::blink::NameFrom::kValue;
    text_alternative =
        input_element->GetLocale().QueryString(IDS_FORM_SUBMIT_LABEL);
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kTypeAttr));
      NameSource& source = name_sources->back();
      source.attribute_value = input_element->getAttribute(kTypeAttr);
      source.type = name_from;
      source.text = text_alternative;
      *found_text_alternative = true;
    } else {
      return text_alternative;
    }
    return text_alternative;
  }

  // <input type="file">
  if (input_element &&
      input_element->FormControlType() == FormControlType::kInputFile) {
    // Append label of inner shadow root button + value attribute.
    name_from = ax::mojom::blink::NameFrom::kContents;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kValueAttr));
      name_sources->back().type = name_from;
    }
    if (ShadowRoot* shadow_root = input_element->UserAgentShadowRoot()) {
      text_alternative =
          To<HTMLInputElement>(shadow_root->firstElementChild())->Value();
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }
  }

  // 5.1 Text inputs - step 3 (placeholder attribute)
  if (html_element && html_element->IsTextControl()) {
    // title attr
    String resulting_text = TextAlternativeFromTooltip(
        name_from, name_sources, found_text_alternative, &text_alternative,
        related_objects);
    if (!resulting_text.empty()) {
      if (name_sources) {
        text_alternative = resulting_text;
      } else {
        return resulting_text;
      }
    }

    name_from = ax::mojom::blink::NameFrom::kPlaceholder;
    if (name_sources) {
      name_sources->push_back(
          NameSource(*found_text_alternative, html_names::kPlaceholderAttr));
      NameSource& source = name_sources->back();
      source.type = name_from;
    }
    const String placeholder = PlaceholderFromNativeAttribute();
    if (!placeholder.empty()) {
      text_alternative = placeholder;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.text = text_alternative;
        source.attribute_value =
            html_element->FastGetAttribute(html_names::kPlaceholderAttr);
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }
  }

  // Also check for aria-placeholder.
  if (IsTextField()) {
    name_from = ax::mojom::blink::NameFrom::kPlaceholder;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative,
                                         html_names::kAriaPlaceholderAttr));
      NameSource& source = name_sources->back();
      source.type = name_from;
    }
    const AtomicString& aria_placeholder =
        AriaAttribute(html_names::kAriaPlaceholderAttr);
    if (!aria_placeholder.empty()) {
      text_alternative = aria_placeholder;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.text = text_alternative;
        source.attribute_value = aria_placeholder;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }

    return text_alternative;
  }

  // 5.8 img or area Element
  if (IsA<HTMLImageElement>(GetNode()) || IsA<HTMLAreaElement>(GetNode())) {
    // alt
    const AtomicString& alt = GetElement()->FastGetAttribute(kAltAttr);
    const bool is_empty = alt.empty() && !alt.IsNull();
    name_from = is_empty ? ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty
                         : ax::mojom::blink::NameFrom::kAttribute;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative, kAltAttr));
      name_sources->back().type = name_from;
    }
    if (!alt.empty()) {
      text_alternative = alt;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.attribute_value = alt;
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }
    return text_alternative;
  }

  // 5.9 table Element
  if (auto* table_element = DynamicTo<HTMLTableElement>(GetNode())) {
    // caption
    name_from = ax::mojom::blink::NameFrom::kCaption;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative));
      name_sources->back().type = name_from;
      name_sources->back().native_source = kAXTextFromNativeHTMLTableCaption;
    }
    HTMLTableCaptionElement* caption = table_element->caption();
    if (caption) {
      AXObject* caption_ax_object = AXObjectCache().Get(caption);
      if (caption_ax_object) {
        text_alternative =
            RecursiveTextAlternative(*caption_ax_object, nullptr, visited);
        if (related_objects) {
          local_related_objects.push_back(
              MakeGarbageCollected<NameSourceRelatedObject>(caption_ax_object,
                                                            text_alternative));
          *related_objects = local_related_objects;
          local_related_objects.clear();
        }

        if (name_sources) {
          NameSource& source = name_sources->back();
          source.related_objects = *related_objects;
          source.text = text_alternative;
          *found_text_alternative = true;
        } else {
          return text_alternative;
        }
      }
    }

    // summary
    name_from = ax::mojom::blink::NameFrom::kAttribute;
    if (name_sources) {
      name_sources->push_back(
          NameSource(*found_text_alternative, html_names::kSummaryAttr));
      name_sources->back().type = name_from;
    }
    const AtomicString& summary =
        GetElement()->FastGetAttribute(html_names::kSummaryAttr);
    if (!summary.IsNull()) {
      text_alternative = summary;
      if (name_sources) {
        NameSource& source = name_sources->back();
        source.attribute_value = summary;
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }

    return text_alternative;
  }

  // Per SVG AAM 1.0's modifications to 2D of this algorithm.
  if (GetNode()->IsSVGElement()) {
    name_from = ax::mojom::blink::NameFrom::kRelatedElement;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative));
      name_sources->back().type = name_from;
      name_sources->back().native_source = kAXTextFromNativeTitleElement;
    }
    auto* container_node = To<ContainerNode>(GetNode());
    Element* title = ElementTraversal::FirstChild(
        *container_node, HasTagName(svg_names::kTitleTag));

    if (title) {
      // TODO(accessibility): In most cases <desc> and <title> can
      // participate in the recursive text alternative calculation. However
      // when the <desc> or <title> is the child of a <use>,
      // |AXObjectCache::GetOrCreate| will fail when
      // |AXObject::ComputeNonARIAParent| returns null because the <use>
      // element's subtree isn't visited by LayoutTreeBuilderTraversal. In
      // addition, while aria-label and other text alternative sources are
      // are technically valid on SVG <desc> and <title>, it is not clear if
      // user agents must expose their values. Therefore until we hear
      // otherwise, just use the inner text. See
      // https://github.com/w3c/svgwg/issues/867
      text_alternative = title->GetInnerTextWithoutUpdate();
      if (!text_alternative.empty()) {
        if (name_sources) {
          NameSource& source = name_sources->back();
          source.text = text_alternative;
          source.related_objects = *related_objects;
          *found_text_alternative = true;
        } else {
          return text_alternative;
        }
      }
    }
    // The SVG-AAM says that the xlink:title participates as a name source
    // for links.
    if (IsA<SVGAElement>(GetNode())) {
      name_from = ax::mojom::blink::NameFrom::kAttribute;
      if (name_sources) {
        name_sources->push_back(
            NameSource(*found_text_alternative, xlink_names::kTitleAttr));
        name_sources->back().type = name_from;
      }

      const AtomicString& title_attr =
          DynamicTo<Element>(GetNode())->FastGetAttribute(
              xlink_names::kTitleAttr);
      if (!title_attr.empty()) {
        text_alternative = title_attr;
        if (name_sources) {
          NameSource& source = name_sources->back();
          source.text = text_alternative;
          source.attribute_value = title_attr;
          *found_text_alternative = true;
        } else {
          return text_alternative;
        }
      }
    }
  }

  // Fieldset / legend.
  if (auto* html_field_set_element =
          DynamicTo<HTMLFieldSetElement>(GetNode())) {
    name_from = ax::mojom::blink::NameFrom::kRelatedElement;
    if (name_sources) {
      name_sources->push_back(NameSource(*found_text_alternative));
      name_sources->back().type = name_from;
      name_sources->back().native_source = kAXTextFromNativeHTMLLegend;
    }
    HTMLElement* legend = html_field_set_element->Legend();
    if (legend) {
      AXObject* legend_ax_object = AXObjectCache().Get(legend);
      // Avoid an infinite loop
      if (legend_ax_object && !visited.Contains(legend_ax_object)) {
        text_alternative =
            RecursiveTextAlternative(*legend_ax_object, nullptr, visited);

        if (related_objects) {
          local_related_objects.push_back(
              MakeGarbageCollected<NameSourceRelatedObject>(legend_ax_object,
                                                            text_alternative));
          *related_objects = local_related_objects;
          local_related_objects.clear();
        }

        if (name_sources) {
          NameSource& source = name_sources->back();
          source.related_objects = *related_objects;
          source.text = text_alternative;
          *found_text_alternative = true;
        } else {
          return text_alternative;
        }
      }
    }
  }

  // Document.
  if (Document* document = DynamicTo<Document>(GetNode())) {
    if (document) {
      name_from = ax::mojom::blink::NameFrom::kAttribute;
      if (name_sources) {
        name_sources->push_back(
            NameSource(found_text_alternative, html_names::kAriaLabelAttr));
        name_sources->back().type = name_from;
      }
      if (Element* document_element = document->documentElement()) {
        const AtomicString& aria_label =
            AriaAttribute(*document_element, html_names::kAriaLabelAttr);
        if (!aria_label.empty()) {
          text_alternative = aria_label;

          if (name_sources) {
            NameSource& source = name_sources->back();
            source.text = text_alternative;
            source.attribute_value = aria_label;
            *found_text_alternative = true;
          } else {
            return text_alternative;
          }
        }
      }

      text_alternative = document->title();
      bool is_empty_title_element =
          text_alternative.empty() && document->TitleElement();
      if (is_empty_title_element)
        name_from = ax::mojom::blink::NameFrom::kAttributeExplicitlyEmpty;
      else
        name_from = ax::mojom::blink::NameFrom::kRelatedElement;

      if (name_sources) {
        name_sources->push_back(NameSource(*found_text_alternative));
        NameSource& source = name_sources->back();
        source.type = name_from;
        source.native_source = kAXTextFromNativeTitleElement;
        source.text = text_alternative;
        *found_text_alternative = true;
      } else {
        return text_alternative;
      }
    }
  }

  return text_alternative;
}

// static
String AXNodeObject::GetSavedTextAlternativeFromNameSource(
    bool found_text_alternative,
    ax::mojom::NameFrom& name_from,
    AXRelatedObjectVector* related_objects,
    NameSources* name_sources) {
  name_from = ax::mojom::blink::NameFrom::kNone;
  if (!name_sources || !found_text_alternative) {
    return String();
  }

  for (NameSource& name_source : *name_sources) {
    if (name_source.text.empty() || name_source.superseded) {
      continue;
    }

    name_from = name_source.type;
    if (!name_source.related_objects.empty()) {
      *related_objects = name_source.related_objects;
    }
    return name_source.text;
  }

  return String();
}

// This is not part of the spec, but we think it's a worthy addition: if the
// labelled input is of type="file", we append the chosen file name to it. We do
// this because this type of input is actually exposed as a button, and buttons
// may not have a "value" field. An unlabelled input is manager later in this
// function, it's named with the default text in the button, 'Choose File', plus
// the file name.
String AXNodeObject::MaybeAppendFileDescriptionToName(
    const String& name) const {
  const auto* input_element = DynamicTo<HTMLInputElement>(GetNode());
  if (!input_element ||
      input_element->FormControlType() != FormControlType::kInputFile) {
    return name;
  }

  String displayed_file_path = GetValueForControl();
  if (!displayed_file_path.empty()) {
    if (GetTextDirection() == ax::mojom::blink::WritingDirection::kRtl)
      return name + " :" + displayed_file_path;
    else
      return name + ": " + displayed_file_path;
  }
  return name;
}

bool AXNodeObject::ShouldIncludeContentInTextAlternative(
    bool recursive,
    const AXObject* aria_label_or_description_root,
    AXObjectSet& visited) const {
  if (!aria_label_or_description_root &&
      !SupportsNameFromContents(recursive, /*consider_focus*/ true)) {
    return false;
  }

  // Avoid option descendent text.
  if (IsA<HTMLSelectElement>(GetNode())) {
    return false;
  }

  // A textfield's name should not include its value (see crbug.com/352665697),
  // unless aria-labelledby explicitly references its own content.
  //
  // Example from aria-labelledby-on-input.html:
  //   <input id="time" value="10" aria-labelledby="message time unit"/>
  //
  // When determining the name for the <input>, we parse the list of IDs in
  // aria-labelledby. When "time" is reached, aria_label_or_description_root
  // points to the element we are naming (the <input>) and 'this' refers to the
  // element we are currently traversing, which is the element with id="time"
  // (so, aria_label_or_description_root == this). In this case, since the
  // author explicitly included the input id, the value of the input should be
  // included in the name.
  if (IsTextField() && aria_label_or_description_root != this) {
    return false;
  }
  return true;
}

String AXNodeObject::Description(
    ax::mojom::blink::NameFrom name_from,
    ax::mojom::blink::DescriptionFrom& description_from,
    AXObjectVector* description_objects) const {
  AXRelatedObjectVector related_objects;
  String result =
      Description(name_from, description_from, nullptr, &related_objects);
  if (description_objects) {
    description_objects->clear();
    for (NameSourceRelatedObject* related_object : related_objects)
      description_objects->push_back(related_object->object);
  }

  result = result.SimplifyWhiteSpace(IsHTMLSpace<UChar>);

  if (RoleValue() == ax::mojom::blink::Role::kSpinButton &&
      DatetimeAncestor()) {
    // Fields inside a datetime control need to merge the field description
    // with the description of the <input> element.
    const AXObject* datetime_ancestor = DatetimeAncestor();
    ax::mojom::blink::NameFrom datetime_ancestor_name_from;
    datetime_ancestor->GetName(datetime_ancestor_name_from, nullptr);
    if (description_objects)
      description_objects->clear();
    String ancestor_desc
```