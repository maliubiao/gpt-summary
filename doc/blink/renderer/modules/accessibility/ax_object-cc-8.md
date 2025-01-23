Response:
The user wants to understand the functionality of the `ax_object.cc` file in the Chromium Blink engine, focusing on accessibility.

Here's a breakdown of the thought process to answer the request:

1. **Identify the core purpose:** The file name `ax_object.cc` strongly suggests that this file is about the `AXObject` class, which is central to Blink's accessibility implementation. Accessibility objects represent elements in the render tree for assistive technologies.

2. **Analyze the code snippets provided:**  The snippets showcase two main functionalities:
    * **Updating layout:** The first snippet addresses situations where layout needs to be updated to ensure the accessibility tree is current, especially for "display locked" nodes.
    * **Performing actions:** The second, larger snippet deals with `PerformAction`, a method that handles various accessibility actions (like clicking, focusing, scrolling).

3. **Categorize the functionalities:**  Based on the code and general knowledge of accessibility APIs, categorize the functions:
    * **Layout Updates:** Ensuring the accessibility tree reflects the current visual state.
    * **Action Handling:** Responding to requests from assistive technologies to interact with the page.
    * **State Management:**  Functions related to focus, selection, and other element states.
    * **Event Handling:**  Dispatching events based on accessibility actions.
    * **Role Determination:**  Logic for deciding the accessible role of an element.
    * **Name Calculation:**  Determining how an element's accessible name is derived.

4. **Relate to web technologies (HTML, CSS, JavaScript):**  Think about how each category interacts with web standards:
    * **Layout:** Directly affected by CSS and JavaScript that modifies styles or DOM structure.
    * **Actions:**  Trigger JavaScript event handlers (e.g., `onclick`), modify HTML attributes (e.g., `focus`), and respect CSS styling that affects interactivity.
    * **Roles and Names:** Heavily influenced by ARIA attributes in HTML. JavaScript can dynamically add or modify these attributes.

5. **Provide concrete examples:** For each relationship with web technologies, create specific scenarios:
    * **Layout:** A CSS animation or JavaScript-driven DOM manipulation that requires an accessibility update.
    * **Actions:** A user clicking a button (HTML), focusing on an input field (HTML), or using arrow keys to expand a menu (ARIA attributes).
    * **Roles and Names:** Use of `role="button"`, `aria-label`, `aria-labelledby`.

6. **Consider logical reasoning (assumptions and outputs):**  For `PerformAction`, analyze the `switch` statement. Imagine an assistive technology requesting a specific action and trace how the code would handle it. Think about the input (the `action_data`) and the potential output (a boolean indicating success or failure).

7. **Address common usage errors:**  Think about mistakes developers might make that would cause issues in this code:
    * Incorrect or missing ARIA attributes.
    * JavaScript interfering with default browser behavior for accessibility.
    * Not considering accessibility during dynamic content updates.

8. **Explain the user journey (debugging):**  Describe the sequence of events that would lead to this code being executed during debugging:
    * A user interacting with the page (mouse click, keyboard input).
    * The browser receiving the event and routing it.
    * The accessibility system intercepting the event or receiving a request from an assistive technology.
    * The `AXObject`'s methods being called to handle the interaction.

9. **Synthesize the functionality (for the final part of the question):** Based on the analysis, create a concise summary of the file's purpose. Emphasize its role in bridging the gap between the rendered web page and assistive technologies.

10. **Review and Refine:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or areas where more detail might be needed. For instance, make sure to explicitly state that `AXObject` represents the accessible representation of a DOM node. Also ensure the explanation addresses the "part 9 of 10" aspect by summarizing the already covered ground and what might be coming next.
这是目录为 `blink/renderer/modules/accessibility/ax_object.cc` 的 Chromium Blink 引擎源代码文件，是关于 `AXObject` 类的实现。 `AXObject` 是 Blink 中 Accessibility 模块的核心类，它代表了可访问性树中的一个节点，通常对应于 DOM 树中的一个 DOM 节点，但也可能对应于 DOM 树中不存在的辅助可访问性对象。

以下是 `ax_object.cc` 文件的功能列表：

1. **表示可访问性对象:**  `AXObject` 类是可访问性树中节点的基类。它存储了关于可访问性对象的信息，例如角色（role）、状态（state）、属性（attributes）和与其他可访问性对象的关系。

2. **处理可访问性操作 (Actions):** 该文件包含了 `PerformAction` 方法，用于处理来自辅助技术的各种操作请求。这些操作包括但不限于：
    * **焦点管理:**  `kFocus`, `kBlur`, `kSetAccessibilityFocus`, `kClearAccessibilityFocus`, `kSetSequentialFocusNavigationStartingPoint`
    * **点击和激活:** `kDoDefault` (通常映射到点击)
    * **展开和折叠:** `kExpand`, `kCollapse`
    * **滚动:** `kScrollToPoint`, `kSetScrollOffset`, `kScrollToMakeVisible`, `kScrollBackward`, `kScrollDown`, `kScrollForward`, `kScrollLeft`, `kScrollRight`, `kScrollUp`
    * **值操作:** `kSetValue`, `kIncrement`, `kDecrement`
    * **上下文菜单:** `kShowContextMenu`
    * **选择:** `kSetSelectedAction`
    * **子树连接:** `kStitchChildTree` (用于 iframe 等)

3. **与渲染引擎交互:** `AXObject` 需要与渲染引擎交互以获取和更新信息。例如：
    * **获取 DOM 节点:** `GetNode()`, `GetElement()` 等方法用于获取关联的 DOM 节点或元素。
    * **更新样式和布局:** `UpdateStyleAndLayoutTreeForNode()` 方法用于确保可访问性信息基于最新的样式和布局。这在处理某些操作前至关重要。
    * **滚动操作:** 调用 `scroll_into_view_util::ScrollRectToVisible` 来执行实际的滚动操作。

4. **模拟用户交互:** 对于某些操作，例如 `kDoDefault`，`AXObject` 可以模拟用户的交互，例如触发点击事件。

5. **处理键盘事件:**  对于某些操作，例如 `kExpand` 和 `kCollapse`，如果角色支持箭头键，则会模拟发送键盘事件 (`DispatchKeyboardEvent`)。

6. **管理焦点:**  `RequestFocusAction` 等方法用于请求将焦点设置到相应的元素。

7. **处理上下文菜单:** `RequestShowContextMenuAction` 用于请求显示上下文菜单。

8. **处理 ARIA 属性:**  文件中包含了一些辅助方法，用于处理 ARIA 属性，例如 `HasARIAOwns` 和 `FirstValidRoleInRoleString`。

9. **确定名称来源 (Name From Contents):** `SupportsNameFromContents` 方法用于判断一个可访问性对象是否可以从其内容获取名称。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **角色映射:** HTML 元素的语义会影响 `AXObject` 的角色。例如，`<button>` 元素通常对应于 `ax::mojom::blink::Role::kButton` 的 `AXObject`。
    * **ARIA 属性:** ARIA 属性（如 `role`, `aria-label`, `aria-expanded` 等）直接影响 `AXObject` 的属性和状态。
        * **例子:** `<div role="button" aria-pressed="false">Click me</div>`  这个 HTML 代码会创建一个角色为 `button` 且 `pressed` 状态为 `false` 的 `AXObject`。`PerformAction` 中的 `kDoDefault` 操作可能会改变 `aria-pressed` 属性，从而更新 `AXObject` 的状态。
    * **语义化标签:** 使用语义化的 HTML 标签（如 `<nav>`, `<article>`, `<aside>`) 可以提供更准确的可访问性信息。

* **CSS:**
    * **布局影响:** CSS 影响元素的布局和可见性，这会直接影响 `AXObject` 的边界和是否被渲染。例如，`display: none` 的元素不会有对应的 `AXObject` (通常)。
    * **可聚焦性:** CSS 属性（如 `tabindex`) 可以影响元素是否可聚焦，这会影响 `AXObject` 对 `kFocus` 等操作的响应。

* **Javascript:**
    * **动态更新:** JavaScript 可以动态修改 DOM 结构、属性和样式，这些修改需要同步到可访问性树。 `UpdateStyleAndLayoutTreeForNode` 等方法确保了 `AXObject` 反映最新的状态。
    * **事件监听:** JavaScript 事件监听器可以响应用户的交互，而这些交互也可能是通过辅助技术触发的。例如，一个 JavaScript 的 `onclick` 事件监听器可能会被 `PerformAction` 中的 `kDoDefault` 操作触发。
    * **操作触发:** JavaScript 可以通过 Accessibility API (例如 Chrome 的 `chrome.automation`) 触发可访问性操作，这些操作会传递到 `AXObject` 的 `PerformAction` 方法。
        * **例子:** JavaScript 代码 `chrome.automation.performAction({ target: myNode, actionType: 'doDefault' });`  会调用对应 `AXObject` 的 `PerformAction` 方法，并传递 `kDoDefault` 操作。

**逻辑推理 (假设输入与输出):**

假设输入一个 `ui::AXActionData` 对象，其 `action` 字段为 `ax::mojom::blink::Action::kFocus`，并且 `target` 指向一个可聚焦的 `<input>` 元素对应的 `AXObject`。

* **输入:** `action_data.action = ax::mojom::blink::Action::kFocus`, `action_data.target` 指向可聚焦的输入框的 `AXObject`。
* **代码执行流程:**
    1. `PerformAction` 方法被调用。
    2. 代码检查文档和节点是否存在。
    3. `UpdateStyleAndLayoutTreeForNode` 被调用以确保布局是最新的。
    4. `switch` 语句匹配到 `case ax::mojom::blink::Action::kFocus:`。
    5. `RequestFocusAction()` 被调用。
    6. `RequestFocusAction()` 通常会调用 `OnNativeFocusAction()`，该方法会执行将焦点设置到对应元素的逻辑。
* **输出:** 函数返回 `true`，表示焦点操作成功。对应的 HTML 元素获得焦点，屏幕阅读器可能会播报该元素的信息。

假设输入一个 `ui::AXActionData` 对象，其 `action` 字段为 `ax::mojom::blink::Action::kClick`，并且 `target` 指向一个 `<button>` 元素对应的 `AXObject`。

* **输入:** `action_data.action = ax::mojom::blink::Action::kDoDefault`, `action_data.target` 指向按钮的 `AXObject`。
* **代码执行流程:**
    1. `PerformAction` 方法被调用。
    2. 代码检查文档和节点是否存在。
    3. `UpdateStyleAndLayoutTreeForNode` 被调用。
    4. `switch` 语句匹配到 `case ax::mojom::blink::Action::kDoDefault:`。
    5. `RequestClickAction()` 被调用。
    6. `RequestClickAction()` 会模拟用户的点击行为，可能会触发按钮的 `onclick` 事件。
* **输出:** 函数返回 `true`，按钮的点击事件被触发，屏幕阅读器可能会播报按钮的文本内容。

**用户或编程常见的使用错误举例:**

1. **ARIA 属性使用不当:**
    * **错误:** 使用了错误的 ARIA 角色，例如将一个链接的 `role` 设为 `button` 而没有相应的 JavaScript 行为。
    * **后果:** 辅助技术可能会错误地解释该元素，导致用户操作失败或产生混淆。 `PerformAction` 中的 `kDoDefault` 操作可能不会按预期工作。

2. **动态内容更新后未更新可访问性树:**
    * **错误:** JavaScript 动态添加或删除 DOM 元素后，没有触发可访问性树的更新。
    * **后果:** 辅助技术可能无法感知到这些变化，导致用户无法访问新的内容或与更新后的界面交互。调用 `UpdateStyleAndLayoutTreeForNode` 的时机不正确会导致可访问性信息不同步。

3. **阻止默认行为但不提供替代的可访问性方案:**
    * **错误:** 使用 JavaScript 的 `preventDefault()` 阻止了元素的默认行为（例如链接跳转），但没有提供替代的可访问性操作。
    * **后果:** 依赖默认行为的辅助技术用户可能无法完成操作。例如，阻止了链接的默认跳转但没有实现 `kDoDefault` 的自定义处理。

4. **自定义组件缺少必要的 ARIA 属性:**
    * **错误:** 开发自定义的 UI 组件（例如自定义的下拉菜单）时，没有添加必要的 ARIA 属性来描述其角色、状态和属性。
    * **后果:** 辅助技术无法理解这些组件的结构和行为，导致用户无法使用。例如，自定义下拉菜单没有 `role="combobox"` 以及相关的 `aria-expanded` 和 `aria-controls` 属性。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户交互:** 用户使用键盘、鼠标或其他输入设备与网页进行交互。例如，点击一个按钮，按下 Tab 键移动焦点，或者使用屏幕阅读器的快捷键触发某个操作。

2. **浏览器事件处理:** 浏览器捕获用户的交互事件（如 `click`, `keydown`, `focus`）。

3. **事件路由:** 浏览器将事件路由到相应的渲染对象或 DOM 节点。

4. **辅助技术请求 (Accessibility API):**  如果用户使用了辅助技术（如屏幕阅读器、语音控制软件），辅助技术可能会通过操作系统的 Accessibility API (例如 Windows 上的 UIA, macOS 上的 NSAccessibility) 发出请求。

5. **Blink Accessibility 模块:** 这些来自辅助技术的请求会被 Blink 的 Accessibility 模块接收。

6. **`RenderAccessibilityImpl`:**  通常，请求会先到达 `blink/renderer/modules/accessibility/render_accessibility_impl.cc` 中的方法。

7. **`AXObjectCache`:** `RenderAccessibilityImpl` 与 `AXObjectCache` 交互，`AXObjectCache` 维护着可访问性树的缓存。

8. **`AXObject` 方法调用:**  对于需要对特定可访问性对象执行的操作，`RenderAccessibilityImpl` 或 `AXObjectCache` 会调用对应 `AXObject` 实例的 `PerformAction` 方法，并传递相应的 `ui::AXActionData`。

9. **代码执行:**  `PerformAction` 方法根据 `action_data.action` 的值执行相应的逻辑，可能会更新 `AXObject` 的状态，与渲染引擎交互，或模拟用户交互。

**作为调试线索:**

* **断点设置:** 在 `PerformAction` 方法的入口处设置断点，可以观察是哪个操作被触发以及传递了哪些参数。
* **日志输出:** 在 `switch` 语句的各个 `case` 分支中添加日志输出，可以跟踪代码的执行路径。
* **查看 `ui::AXActionData`:**  检查 `action_data` 对象的 `action` 和其他属性，了解操作的类型和目标。
* **检查 `AXObject` 的状态:**  在 `PerformAction` 执行前后检查 `AXObject` 的属性和状态，了解操作是否成功以及状态是否发生了变化。
* **使用 Accessibility Inspector:**  使用浏览器提供的 Accessibility Inspector 工具可以查看可访问性树的结构和属性，以及监听可访问性事件。

**第9部分，共10部分，功能归纳:**

作为整个 Accessibility 模块的一部分，`ax_object.cc` 文件中的代码主要负责：

* **处理来自辅助技术的操作请求:** 这是 `AXObject` 的核心功能之一，使其能够响应用户的操作指令。
* **将可访问性操作映射到浏览器内部行为:** 例如，将 `kDoDefault` 映射到点击事件的模拟。
* **维护和更新可访问性对象的状态:**  响应操作可能会改变 `AXObject` 的状态，例如焦点状态、选中状态、展开/折叠状态等。
* **作为可访问性树中可操作元素的接口:**  `AXObject` 提供了与可访问性树中节点进行交互的标准方法。

在整个可访问性流程中，`ax_object.cc` 扮演着至关重要的角色，它连接了辅助技术和渲染引擎，使得辅助技术能够理解和操作网页内容。 这部分代码专注于处理用户的交互意图，并将这些意图转化为浏览器可以理解和执行的动作。 考虑到这是第 9 部分，可以推测之前的部分可能涵盖了 `AXObject` 的创建、属性获取、以及可访问性树的构建，而最后一部分可能涉及可访问性事件的通知和更高级的特性。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
e) {
  // In most cases, UpdateAllLifecyclePhasesExceptPaint() is enough, but if
  // the action is part of a display locked node, that will not update the node
  // because it's not part of the layout update cycle yet. In that case, calling
  // UpdateStyleAndLayoutTreeForElement() is also necessary.
  if (const Element* element =
          FlatTreeTraversal::InclusiveParentElement(node)) {
    element->GetDocument().UpdateStyleAndLayoutTreeForElement(
        element, DocumentUpdateReason::kAccessibility);
  }
}

//
// Modify or take an action on an object.
//

bool AXObject::PerformAction(const ui::AXActionData& action_data) {
  Document* document = GetDocument();
  if (!document) {
    return false;
  }
  AXObjectCacheImpl& cache = AXObjectCache();
  Node* node = GetNode();
  if (!node) {
    node = GetClosestElement();
    if (!node) {
      return false;
    }
  }

  UpdateStyleAndLayoutTreeForNode(*node);
  cache.UpdateAXForAllDocuments();

  // Updating style and layout for the node can cause it to gain layout,
  // detaching the original AXNodeObject to make room for a new one with layout.
  if (IsDetached()) {
    AXObject* new_object = cache.Get(node);
    return new_object ? new_object->PerformAction(action_data) : false;
  }

  switch (action_data.action) {
    case ax::mojom::blink::Action::kBlur:
      return OnNativeBlurAction();
    case ax::mojom::blink::Action::kClearAccessibilityFocus:
      return InternalClearAccessibilityFocusAction();
    case ax::mojom::blink::Action::kCollapse:
      return RequestCollapseAction();
    case ax::mojom::blink::Action::kDecrement:
      return RequestDecrementAction();
    case ax::mojom::blink::Action::kDoDefault:
      return RequestClickAction();
    case ax::mojom::blink::Action::kExpand:
      return RequestExpandAction();
    case ax::mojom::blink::Action::kFocus:
      return RequestFocusAction();
    case ax::mojom::blink::Action::kIncrement:
      return RequestIncrementAction();
    case ax::mojom::blink::Action::kScrollToPoint:
      return RequestScrollToGlobalPointAction(action_data.target_point);
    case ax::mojom::blink::Action::kSetAccessibilityFocus:
      return InternalSetAccessibilityFocusAction();
    case ax::mojom::blink::Action::kSetScrollOffset:
      SetScrollOffset(action_data.target_point);
      return true;
    case ax::mojom::blink::Action::kSetSequentialFocusNavigationStartingPoint:
      return RequestSetSequentialFocusNavigationStartingPointAction();
    case ax::mojom::blink::Action::kSetValue:
      return RequestSetValueAction(String::FromUTF8(action_data.value));
    case ax::mojom::blink::Action::kShowContextMenu:
      return RequestShowContextMenuAction();
    case ax::mojom::blink::Action::kScrollToMakeVisible:
      return RequestScrollToMakeVisibleAction();
    case ax::mojom::blink::Action::kScrollBackward:
    case ax::mojom::blink::Action::kScrollDown:
    case ax::mojom::blink::Action::kScrollForward:
    case ax::mojom::blink::Action::kScrollLeft:
    case ax::mojom::blink::Action::kScrollRight:
    case ax::mojom::blink::Action::kScrollUp:
      Scroll(action_data.action);
      return true;
    case ax::mojom::blink::Action::kStitchChildTree:
      if (action_data.child_tree_id == ui::AXTreeIDUnknown()) {
        return false;  // No child tree ID provided.;
      }
      // This action can only be performed on elements, since only elements can
      // be parents of child trees. The closest example in HTML is an iframe,
      // but this action extends the same functionality to all HTML elements.
      if (!GetElement()) {
        return false;
      }
      SetChildTree(action_data.child_tree_id);
      return true;
    case ax::mojom::blink::Action::kAnnotatePageImages:
    case ax::mojom::blink::Action::kCustomAction:
    case ax::mojom::blink::Action::kGetImageData:
    case ax::mojom::blink::Action::kGetTextLocation:
    case ax::mojom::blink::Action::kHideTooltip:
    case ax::mojom::blink::Action::kHitTest:
    case ax::mojom::blink::Action::kInternalInvalidateTree:
    case ax::mojom::blink::Action::kLoadInlineTextBoxes:
    case ax::mojom::blink::Action::kNone:
    case ax::mojom::blink::Action::kReplaceSelectedText:
    case ax::mojom::blink::Action::kSetSelection:
    case ax::mojom::blink::Action::kShowTooltip:
    case ax::mojom::blink::Action::kSignalEndOfTest:
    case ax::mojom::blink::Action::kResumeMedia:
    case ax::mojom::blink::Action::kStartDuckingMedia:
    case ax::mojom::blink::Action::kStopDuckingMedia:
    case ax::mojom::blink::Action::kSuspendMedia:
    case ax::mojom::blink::Action::kLongClick:
    case ax::mojom::blink::Action::kScrollToPositionAtRowColumn:
      return false;  // Handled in `RenderAccessibilityImpl`.
  }
}

// TODO(crbug.com/369945541): remove these unnecessary methods.
bool AXObject::RequestDecrementAction() {
  return OnNativeDecrementAction();
}

bool AXObject::RequestClickAction() {
  return OnNativeClickAction();
}

bool AXObject::OnNativeClickAction() {
  Document* document = GetDocument();
  if (!document)
    return false;

  LocalFrame::NotifyUserActivation(
      document->GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);

  if (IsTextField())
    return OnNativeFocusAction();

  Element* element = GetClosestElement();

  // Forward default action on custom select to its button.
  if (auto* select = DynamicTo<HTMLSelectElement>(GetNode())) {
    if (select->IsAppearanceBaseButton()) {
      if (auto* button = select->SlottedButton()) {
        element = button;
      }
    }
  }

  if (element) {
    // Always set the sequential focus navigation starting point.
    // Even if this element isn't focusable, if you press "Tab" it will
    // start the search from this element.
    GetDocument()->SetSequentialFocusNavigationStartingPoint(element);

    // Explicitly focus the element if it's focusable but not currently
    // the focused element, to be consistent with
    // EventHandler::HandleMousePressEvent.
    if (element->IsFocusable(Element::UpdateBehavior::kNoneForAccessibility) &&
        !element->IsFocusedElementInDocument()) {
      Page* const page = GetDocument()->GetPage();
      if (page) {
        page->GetFocusController().SetFocusedElement(
            element, GetDocument()->GetFrame(),
            FocusParams(SelectionBehaviorOnFocus::kNone,
                        mojom::blink::FocusType::kMouse, nullptr));
      }
    }

    // For most elements, AccessKeyAction triggers sending a simulated
    // click, including simulating the mousedown, mouseup, and click events.
    element->AccessKeyAction(SimulatedClickCreationScope::kFromAccessibility);
    return true;
  }

  if (CanSetFocusAttribute())
    return OnNativeFocusAction();

  return false;
}

bool AXObject::RequestFocusAction() {
  return OnNativeFocusAction();
}

bool AXObject::RequestIncrementAction() {
  return OnNativeIncrementAction();
}

bool AXObject::RequestScrollToGlobalPointAction(const gfx::Point& point) {
  return OnNativeScrollToGlobalPointAction(point);
}

bool AXObject::RequestScrollToMakeVisibleAction() {
  return OnNativeScrollToMakeVisibleAction();
}

bool AXObject::RequestScrollToMakeVisibleWithSubFocusAction(
    const gfx::Rect& subfocus,
    blink::mojom::blink::ScrollAlignment horizontal_scroll_alignment,
    blink::mojom::blink::ScrollAlignment vertical_scroll_alignment) {
  Document* document = GetDocument();
  if (!document) {
    return false;
  }
  AXObjectCacheImpl& cache = AXObjectCache();
  Node* node = GetNode();
  if (!node) {
    node = GetClosestElement();
    if (!node) {
      return false;
    }
  }

  UpdateStyleAndLayoutTreeForNode(*node);

  document->View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kAccessibility);

  // Updating style and layout for the node can cause it to gain layout,
  // detaching the original AXNodeObject to make room for a new one with layout.
  if (IsDetached()) {
    AXObject* new_object = cache.Get(node);
    return new_object
               ? new_object->OnNativeScrollToMakeVisibleWithSubFocusAction(
                     subfocus, horizontal_scroll_alignment,
                     vertical_scroll_alignment)
               : false;
  }

  return OnNativeScrollToMakeVisibleWithSubFocusAction(
      subfocus, horizontal_scroll_alignment, vertical_scroll_alignment);
}

bool AXObject::RequestSetSelectedAction(bool selected) {
  return OnNativeSetSelectedAction(selected);
}

bool AXObject::RequestSetSequentialFocusNavigationStartingPointAction() {
  return OnNativeSetSequentialFocusNavigationStartingPointAction();
}

bool AXObject::RequestSetValueAction(const String& value) {
  return OnNativeSetValueAction(value);
}

bool AXObject::RequestShowContextMenuAction() {
  return OnNativeShowContextMenuAction();
}

bool AXObject::RequestExpandAction() {
  if (ui::SupportsArrowKeysForExpandCollapse(RoleValue())) {
    return OnNativeKeyboardAction(ax::mojom::blink::Action::kExpand);
  }
  return RequestClickAction();
}

bool AXObject::RequestCollapseAction() {
  if (ui::SupportsArrowKeysForExpandCollapse(RoleValue())) {
    return OnNativeKeyboardAction(ax::mojom::blink::Action::kCollapse);
  }
  return RequestClickAction();
}

bool AXObject::OnNativeKeyboardAction(const ax::mojom::Action action) {
  LocalDOMWindow* local_dom_window = GetDocument()->domWindow();

  DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kRawKeyDown,
                        action);
  DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kKeyUp, action);

  return true;
}

bool AXObject::InternalSetAccessibilityFocusAction() {
  return false;
}

bool AXObject::InternalClearAccessibilityFocusAction() {
  return false;
}

LayoutObject* AXObject::GetLayoutObjectForNativeScrollAction() const {
  Node* node = GetNode();
  if (!node || !node->isConnected()) {
    return nullptr;
  }

  // Node might not have a LayoutObject due to the fact that it is in a locked
  // subtree. Force the update to create the LayoutObject (and update position
  // information) for this node.
  GetDocument()->UpdateStyleAndLayoutForNode(
      node, DocumentUpdateReason::kDisplayLock);
  return node->GetLayoutObject();
}

void AXObject::DispatchKeyboardEvent(LocalDOMWindow* local_dom_window,
                                     WebInputEvent::Type type,
                                     ax::mojom::blink::Action action) const {
  blink::WebKeyboardEvent key(type,
                              blink::WebInputEvent::Modifiers::kNoModifiers,
                              base::TimeTicks::Now());
  switch (action) {
    case ax::mojom::blink::Action::kExpand:
      DCHECK(ui::SupportsArrowKeysForExpandCollapse(RoleValue()));
      key.dom_key = ui::DomKey::ARROW_RIGHT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_RIGHT);
      key.native_key_code = key.windows_key_code = blink::VKEY_RIGHT;
      break;
    case ax::mojom::blink::Action::kCollapse:
      DCHECK(ui::SupportsArrowKeysForExpandCollapse(RoleValue()));
      key.dom_key = ui::DomKey::ARROW_LEFT;
      key.dom_code = static_cast<int>(ui::DomCode::ARROW_LEFT);
      key.native_key_code = key.windows_key_code = blink::VKEY_LEFT;
      break;
    case ax::mojom::blink::Action::kShowContextMenu:
      key.dom_key = ui::DomKey::CONTEXT_MENU;
      key.dom_code = static_cast<int>(ui::DomCode::CONTEXT_MENU);
      key.native_key_code = key.windows_key_code = blink::VKEY_APPS;
      break;
    case ax::mojom::blink::Action::kScrollUp:
      key.dom_key = ui::DomKey::PAGE_UP;
      key.dom_code = static_cast<int>(ui::DomCode::PAGE_UP);
      key.native_key_code = key.windows_key_code = blink::VKEY_PRIOR;
      break;
    case ax::mojom::blink::Action::kScrollDown:
      key.dom_key = ui::DomKey::PAGE_DOWN;
      key.dom_code = static_cast<int>(ui::DomCode::PAGE_DOWN);
      key.native_key_code = key.windows_key_code = blink::VKEY_NEXT;
      break;
    default:
      NOTREACHED();
  }
  GetNode()->DispatchEvent(
      *blink::KeyboardEvent::Create(key, local_dom_window, true));
}

bool AXObject::OnNativeScrollToMakeVisibleAction() const {
  LayoutObject* layout_object = GetLayoutObjectForNativeScrollAction();
  if (!layout_object)
    return false;
  PhysicalRect target_rect(layout_object->AbsoluteBoundingBoxRect());
  scroll_into_view_util::ScrollRectToVisible(
      *layout_object, target_rect,
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::CenterIfNeeded(), ScrollAlignment::CenterIfNeeded(),
          mojom::blink::ScrollType::kProgrammatic, false,
          mojom::blink::ScrollBehavior::kAuto));
  AXObjectCache().PostNotification(GetDocument(),
                                   ax::mojom::blink::Event::kLocationChanged);
  return true;
}

bool AXObject::OnNativeScrollToMakeVisibleWithSubFocusAction(
    const gfx::Rect& rect,
    blink::mojom::blink::ScrollAlignment horizontal_scroll_alignment,
    blink::mojom::blink::ScrollAlignment vertical_scroll_alignment) const {
  LayoutObject* layout_object = GetLayoutObjectForNativeScrollAction();
  if (!layout_object)
    return false;

  PhysicalRect target_rect =
      layout_object->LocalToAbsoluteRect(PhysicalRect(rect));
  scroll_into_view_util::ScrollRectToVisible(
      *layout_object, target_rect,
      scroll_into_view_util::CreateScrollIntoViewParams(
          horizontal_scroll_alignment, vertical_scroll_alignment,
          mojom::blink::ScrollType::kProgrammatic,
          false /* make_visible_in_visual_viewport */,
          mojom::blink::ScrollBehavior::kAuto));
  AXObjectCache().PostNotification(GetDocument(),
                                   ax::mojom::blink::Event::kLocationChanged);
  return true;
}

bool AXObject::OnNativeScrollToGlobalPointAction(
    const gfx::Point& global_point) const {
  LayoutObject* layout_object = GetLayoutObjectForNativeScrollAction();
  if (!layout_object)
    return false;

  PhysicalRect target_rect(layout_object->AbsoluteBoundingBoxRect());
  target_rect.Move(-PhysicalOffset(global_point));
  scroll_into_view_util::ScrollRectToVisible(
      *layout_object, target_rect,
      scroll_into_view_util::CreateScrollIntoViewParams(
          ScrollAlignment::LeftAlways(), ScrollAlignment::TopAlways(),
          mojom::blink::ScrollType::kProgrammatic, false,
          mojom::blink::ScrollBehavior::kAuto));
  AXObjectCache().PostNotification(GetDocument(),
                                   ax::mojom::blink::Event::kLocationChanged);
  return true;
}

bool AXObject::OnNativeSetSequentialFocusNavigationStartingPointAction() {
  // Call it on the nearest ancestor that overrides this with a specific
  // implementation.
  if (ParentObject()) {
    return ParentObject()
        ->OnNativeSetSequentialFocusNavigationStartingPointAction();
  }
  return false;
}

bool AXObject::OnNativeDecrementAction() {
  return false;
}

bool AXObject::OnNativeBlurAction() {
  return false;
}

bool AXObject::OnNativeFocusAction() {
  return false;
}

bool AXObject::OnNativeIncrementAction() {
  return false;
}

bool AXObject::OnNativeSetValueAction(const String&) {
  return false;
}

bool AXObject::OnNativeSetSelectedAction(bool) {
  return false;
}

bool AXObject::OnNativeShowContextMenuAction() {
  Element* element = GetElement();
  if (!element)
    element = ParentObject() ? ParentObject()->GetElement() : nullptr;
  if (!element)
    return false;

  Document* document = GetDocument();
  if (!document || !document->GetFrame())
    return false;

  LocalDOMWindow* local_dom_window = GetDocument()->domWindow();
  if (RuntimeEnabledFeatures::
          SynthesizedKeyboardEventsForAccessibilityActionsEnabled()) {
    // To make less evident that the events are synthesized, we have to emit
    // them in this order: 1) keydown. 2) contextmenu. 3) keyup.
    DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kRawKeyDown,
                          ax::mojom::blink::Action::kShowContextMenu);
  }

  ContextMenuAllowedScope scope;
  WebInputEventResult result =
      document->GetFrame()->GetEventHandler().ShowNonLocatedContextMenu(
          element, kMenuSourceKeyboard);

  // The node may have ceased to exist due to the event handler actions, so we
  // check its detached state. We also check the result of the contextMenu
  // event: if it was consumed by the system, executing the default action, we
  // don't synthesize the keyup event because it would not be produced normally;
  // the system context menu captures it and never reaches the DOM.
  if (!IsDetached() && result != WebInputEventResult::kHandledSystem &&
      RuntimeEnabledFeatures::
          SynthesizedKeyboardEventsForAccessibilityActionsEnabled()) {
    DispatchKeyboardEvent(local_dom_window, WebInputEvent::Type::kKeyUp,
                          ax::mojom::blink::Action::kShowContextMenu);
  }

  return true;
}

// static
bool AXObject::IsFrame(const Node* node) {
  auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node);
  if (!frame_owner)
    return false;
  switch (frame_owner->OwnerType()) {
    case FrameOwnerElementType::kIframe:
    case FrameOwnerElementType::kFrame:
    case FrameOwnerElementType::kFencedframe:
      return true;
    case FrameOwnerElementType::kObject:
    case FrameOwnerElementType::kEmbed:
    case FrameOwnerElementType::kNone:
      return false;
  }
}

// static
bool AXObject::HasARIAOwns(Element* element) {
  if (!element)
    return false;

  // A LayoutObject is not required, because an invisible object can still
  // use aria-owns to point to visible children.

  const AtomicString& aria_owns =
      AriaAttribute(*element, html_names::kAriaOwnsAttr);

  // TODO(accessibility): do we need to check !AriaOwnsElements.empty() ? Is
  // that fundamentally different from HasExplicitlySetAttrAssociatedElements()?
  return !aria_owns.empty() || element->HasExplicitlySetAttrAssociatedElements(
                                   html_names::kAriaOwnsAttr);
}

// static
ax::mojom::blink::Role AXObject::FirstValidRoleInRoleString(
    const String& value,
    bool ignore_form_and_region) {
  DCHECK(!value.empty());

  static const ARIARoleMap* role_map = CreateARIARoleMap();

  Vector<String> role_vector;
  value.SimplifyWhiteSpace().Split(' ', role_vector);
  ax::mojom::blink::Role role = ax::mojom::blink::Role::kUnknown;
  for (const auto& child : role_vector) {
    auto it = role_map->find(child);
    if (it == role_map->end() ||
        (ignore_form_and_region &&
         (it->value == ax::mojom::blink::Role::kForm ||
          it->value == ax::mojom::blink::Role::kRegion))) {
      continue;
    }
    return it->value;
  }

  return role;
}

bool AXObject::SupportsNameFromContents(bool recursive,
                                        bool consider_focus) const {
  // ARIA 1.1, section 5.2.7.5.
  bool result = false;

  switch (RoleValue()) {
    // ----- NameFrom: contents -------------------------
    // Get their own name from contents, or contribute to ancestors
    case ax::mojom::blink::Role::kButton:
    case ax::mojom::blink::Role::kCell:
    case ax::mojom::blink::Role::kCheckBox:
    case ax::mojom::blink::Role::kColumnHeader:
    case ax::mojom::blink::Role::kDocBackLink:
    case ax::mojom::blink::Role::kDocBiblioRef:
    case ax::mojom::blink::Role::kDocNoteRef:
    case ax::mojom::blink::Role::kDocGlossRef:
    case ax::mojom::blink::Role::kDisclosureTriangle:
    case ax::mojom::blink::Role::kDisclosureTriangleGrouped:
    case ax::mojom::blink::Role::kGridCell:
    case ax::mojom::blink::Role::kHeading:
    case ax::mojom::blink::Role::kLayoutTableCell:
    case ax::mojom::blink::Role::kLineBreak:
    case ax::mojom::blink::Role::kLink:
    case ax::mojom::blink::Role::kListBoxOption:
    case ax::mojom::blink::Role::kListMarker:
    case ax::mojom::blink::Role::kMath:
    case ax::mojom::blink::Role::kMenuItem:
    case ax::mojom::blink::Role::kMenuItemCheckBox:
    case ax::mojom::blink::Role::kMenuItemRadio:
    case ax::mojom::blink::Role::kPopUpButton:
    case ax::mojom::blink::Role::kRadioButton:
    case ax::mojom::blink::Role::kRowHeader:
    case ax::mojom::blink::Role::kStaticText:
    case ax::mojom::blink::Role::kSwitch:
    case ax::mojom::blink::Role::kTab:
    case ax::mojom::blink::Role::kToggleButton:
    case ax::mojom::blink::Role::kTreeItem:
    case ax::mojom::blink::Role::kTooltip:
      result = true;
      break;

    case ax::mojom::blink::Role::kMenuListOption:
      // If only has one text child, will use HTMLOptionElement::DisplayLabel().
      result = !GetElement()->HasOneTextChild();
      break;

    // ----- No name from contents -------------------------
    // These never have or contribute a name from contents, as they are
    // containers for many subobjects. Superset of nameFrom:author ARIA roles.
    case ax::mojom::blink::Role::kAlert:
    case ax::mojom::blink::Role::kAlertDialog:
    case ax::mojom::blink::Role::kApplication:
    case ax::mojom::blink::Role::kAudio:
    case ax::mojom::blink::Role::kArticle:
    case ax::mojom::blink::Role::kBanner:
    case ax::mojom::blink::Role::kBlockquote:
    case ax::mojom::blink::Role::kColorWell:
    case ax::mojom::blink::Role::kComboBoxMenuButton:  // Only value from
                                                       // content.
    case ax::mojom::blink::Role::kComboBoxGrouping:
    case ax::mojom::blink::Role::kComboBoxSelect:
    case ax::mojom::blink::Role::kComment:
    case ax::mojom::blink::Role::kComplementary:
    case ax::mojom::blink::Role::kContentInfo:
    case ax::mojom::blink::Role::kDate:
    case ax::mojom::blink::Role::kDateTime:
    case ax::mojom::blink::Role::kDialog:
    case ax::mojom::blink::Role::kDocCover:
    case ax::mojom::blink::Role::kDocBiblioEntry:
    case ax::mojom::blink::Role::kDocEndnote:
    case ax::mojom::blink::Role::kDocFootnote:
    case ax::mojom::blink::Role::kDocPageBreak:
    case ax::mojom::blink::Role::kDocPageFooter:
    case ax::mojom::blink::Role::kDocPageHeader:
    case ax::mojom::blink::Role::kDocAbstract:
    case ax::mojom::blink::Role::kDocAcknowledgments:
    case ax::mojom::blink::Role::kDocAfterword:
    case ax::mojom::blink::Role::kDocAppendix:
    case ax::mojom::blink::Role::kDocBibliography:
    case ax::mojom::blink::Role::kDocChapter:
    case ax::mojom::blink::Role::kDocColophon:
    case ax::mojom::blink::Role::kDocConclusion:
    case ax::mojom::blink::Role::kDocCredit:
    case ax::mojom::blink::Role::kDocCredits:
    case ax::mojom::blink::Role::kDocDedication:
    case ax::mojom::blink::Role::kDocEndnotes:
    case ax::mojom::blink::Role::kDocEpigraph:
    case ax::mojom::blink::Role::kDocEpilogue:
    case ax::mojom::blink::Role::kDocErrata:
    case ax::mojom::blink::Role::kDocExample:
    case ax::mojom::blink::Role::kDocForeword:
    case ax::mojom::blink::Role::kDocGlossary:
    case ax::mojom::blink::Role::kDocIndex:
    case ax::mojom::blink::Role::kDocIntroduction:
    case ax::mojom::blink::Role::kDocNotice:
    case ax::mojom::blink::Role::kDocPageList:
    case ax::mojom::blink::Role::kDocPart:
    case ax::mojom::blink::Role::kDocPreface:
    case ax::mojom::blink::Role::kDocPrologue:
    case ax::mojom::blink::Role::kDocPullquote:
    case ax::mojom::blink::Role::kDocQna:
    case ax::mojom::blink::Role::kDocSubtitle:
    case ax::mojom::blink::Role::kDocTip:
    case ax::mojom::blink::Role::kDocToc:
    case ax::mojom::blink::Role::kDocument:
    case ax::mojom::blink::Role::kEmbeddedObject:
    case ax::mojom::blink::Role::kFeed:
    case ax::mojom::blink::Role::kFigure:
    case ax::mojom::blink::Role::kForm:
    case ax::mojom::blink::Role::kGraphicsDocument:
    case ax::mojom::blink::Role::kGraphicsObject:
    case ax::mojom::blink::Role::kGraphicsSymbol:
    case ax::mojom::blink::Role::kGrid:
    case ax::mojom::blink::Role::kGroup:
    case ax::mojom::blink::Role::kHeader:
    case ax::mojom::blink::Role::kIframePresentational:
    case ax::mojom::blink::Role::kIframe:
    case ax::mojom::blink::Role::kImage:
    case ax::mojom::blink::Role::kInputTime:
    case ax::mojom::blink::Role::kListBox:
    case ax::mojom::blink::Role::kLog:
    case ax::mojom::blink::Role::kMain:
    case ax::mojom::blink::Role::kMarquee:
    case ax::mojom::blink::Role::kMathMLFraction:
    case ax::mojom::blink::Role::kMathMLIdentifier:
    case ax::mojom::blink::Role::kMathMLMath:
    case ax::mojom::blink::Role::kMathMLMultiscripts:
    case ax::mojom::blink::Role::kMathMLNoneScript:
    case ax::mojom::blink::Role::kMathMLNumber:
    case ax::mojom::blink::Role::kMathMLOperator:
    case ax::mojom::blink::Role::kMathMLOver:
    case ax::mojom::blink::Role::kMathMLPrescriptDelimiter:
    case ax::mojom::blink::Role::kMathMLRoot:
    case ax::mojom::blink::Role::kMathMLRow:
    case ax::mojom::blink::Role::kMathMLSquareRoot:
    case ax::mojom::blink::Role::kMathMLStringLiteral:
    case ax::mojom::blink::Role::kMathMLSub:
    case ax::mojom::blink::Role::kMathMLSubSup:
    case ax::mojom::blink::Role::kMathMLSup:
    case ax::mojom::blink::Role::kMathMLTable:
    case ax::mojom::blink::Role::kMathMLTableCell:
    case ax::mojom::blink::Role::kMathMLTableRow:
    case ax::mojom::blink::Role::kMathMLText:
    case ax::mojom::blink::Role::kMathMLUnder:
    case ax::mojom::blink::Role::kMathMLUnderOver:
    case ax::mojom::blink::Role::kMenuListPopup:
    case ax::mojom::blink::Role::kMenu:
    case ax::mojom::blink::Role::kMenuBar:
    case ax::mojom::blink::Role::kMeter:
    case ax::mojom::blink::Role::kNavigation:
    case ax::mojom::blink::Role::kNote:
    case ax::mojom::blink::Role::kPluginObject:
    case ax::mojom::blink::Role::kProgressIndicator:
    case ax::mojom::blink::Role::kRadioGroup:
    case ax::mojom::blink::Role::kRootWebArea:
    case ax::mojom::blink::Role::kRowGroup:
    case ax::mojom::blink::Role::kScrollBar:
    case ax::mojom::blink::Role::kScrollView:
    case ax::mojom::blink::Role::kSearch:
    case ax::mojom::blink::Role::kSearchBox:
    case ax::mojom::blink::Role::kSectionFooter:
    case ax::mojom::blink::Role::kSectionHeader:
    case ax::mojom::blink::Role::kSplitter:
    case ax::mojom::blink::Role::kSlider:
    case ax::mojom::blink::Role::kSpinButton:
    case ax::mojom::blink::Role::kStatus:
    case ax::mojom::blink::Role::kSuggestion:
    case ax::mojom::blink::Role::kSvgRoot:
    case ax::mojom::blink::Role::kTable:
    case ax::mojom::blink::Role::kTabList:
    case ax::mojom::blink::Role::kTabPanel:
    case ax::mojom::blink::Role::kTerm:
    case ax::mojom::blink::Role::kTextField:
    case ax::mojom::blink::Role::kTextFieldWithComboBox:
    case ax::mojom::blink::Role::kTimer:
    case ax::mojom::blink::Role::kToolbar:
    case ax::mojom::blink::Role::kTree:
    case ax::mojom::blink::Role::kTreeGrid:
    case ax::mojom::blink::Role::kVideo:
      result = false;
      break;

    // ----- role="row" -------
    // ARIA spec says to compute "name from content" on role="row" at
    // https://w3c.github.io/aria/#row.
    // However, for performance reasons we only do it if the row is the
    // descendant of a grid/treegrid.
    case ax::mojom::blink::Role::kRow: {
      if (GetDocument() == AXObjectCache().GetPopupDocumentIfShowing()) {
        // role="row" is used in date pickers, but rows are not focusable
        // there and don't need a name. If we do decide to use focusable
        // rows in built-in HTML the name should be set manually, e.g. via
        // aria-label, as the name-from-contents algorithm often leads to
        // overly verbose names for rows.
        return false;
      }
      // Check for relevant ancestor.
      AXObject* ancestor = ParentObjectUnignored();
      while (ancestor) {
        // If in a grid/treegrid that's after a combobox textfield using
        // aria-activedescendant, then consider the row focusable.
        if (ancestor->RoleValue() == ax::mojom::blink::Role::kGrid ||
            ancestor->RoleValue() == ax::mojom::blink::Role::kTreeGrid) {
          return true;
        }
        if (ancestor->RoleValue() !=
                ax::mojom::blink::Role::kGenericContainer &&
            ancestor->RoleValue() != ax::mojom::blink::Role::kNone &&
            ancestor->RoleValue() != ax::mojom::blink::Role::kGroup &&
            ancestor->RoleValue() != ax::mojom::blink::Role::kRowGroup) {
          // Any other role other than those that are neutral in a [tree]grid,
          // indicate that we are not in a [tree]grid.
          return false;
        }
        ancestor = ancestor->ParentObjectUnignored();
      }
      return false;
    }

    // ----- Conditional: contribute to ancestor only, unless focusable -------
    // Some objects can contribute their contents to ancestor names, but
    // only have their own name if they are focusable
    case ax::mojom::blink::Role::kGenericContainer:
      if (IsA<HTMLBodyElement>(GetNode()) ||
          GetNode() == GetDocument()->documentElement()) {
        return false;
      }
      [[fallthrough]];
    case ax::mojom::blink::Role::kAbbr:
    case ax::mojom::blink::Role::kCanvas:
    case ax::mojom::blink::Role::kCaption:
    case ax::mojom::blink::Role::kCode:
    case ax::mojom::blink::Role::kContentDeletion:
    case ax::mojom::blink::Role::kContentInsertion:
    case ax::mojom::blink::Role::kDefinition:
    case ax::mojom::blink::Role::kDescriptionList:
    case ax::mojom::blink::Role::kDetails:
    case ax::mojom::blink::Role::kEmphasis:
    case ax::mojom::blink::Role::kFigcaption:
    case ax::mojom::blink::Role::kFooter:
    case ax::mojom::blink::Role::kInlineTextBox:
    case ax::mojom::blink::Role::kLabelText:
    case ax::mojom::blink::Role::kLayoutTable:
    case ax::mojom::blink::Role::kLayoutTableRow:
    case ax::mojom::blink::Role::kLegend:
    case ax::mojom::blink::Role::kList:
    case ax::mojom::blink::Role::kListItem:
    case ax::mojom::blink::Role::kMark:
    case ax::mojom::blink::Role::kNone:
    case ax::mojom::blink::Role::kParagraph:
    case ax::mojom::blink::Role::kRegion:
    case ax::mojom::blink::Role::kRuby:
    case ax::mojom::blink::Role::kSection:
    case ax::mojom::blink::Role::kSectionWithoutName:
    case ax::mojom::blink::Role::kStrong:
    case ax::mojom::blink::Role::kSubscript:
    case ax::mojom::blink::Role::kSuperscript:
    case ax::mojom::blink::Role::kTime:
      // Usually these items don't have a name, but Blink provides one if they
      // are tabbable, as a repair, so that if a user navigates to one, screen
      // reader users have enough context to understand where they landed.
      if (recursive) {
        // Use contents if part of a recursive name computation. This doesn't
        // affect the final serialized name for this object, but it allows it
        // to contribute to an ancestor name.
        result = true;
      } else if (!GetElement() || GetElement()->IsInUserAgentShadowRoot()) {
        // Built-in UI must have correct accessibility without needing repairs.
        result = false;
      } else if (IsEditable() ||
                 ElementFromAttributeOrInternals(
                     GetElement(), html_names::kAriaActivedescendantAttr)) {
        // Handle exceptions:
        // 1.Elements with contenteditable, where using the contents as a name
        //   would cause them to be double-announced.
        // 2.Containers with aria-activedescendant, where the focus is being
        //   forwarded somewhere else.
        result = false;
      } else {
        // Don't repair name from contents to focusable elements unless
        // focused, because providing a repaired accessible name
        // often leads to redundant verbalizations.
        result = consider_focus && IsFocused();
#if DCHECK_IS_ON()
        // TODO(crbug.com/350528330): Add this check and address focusable
        // UI elements that are missing a role, or using an improper role.
        // DCHECK(!result || !AXObjectCache().IsInternalUICheckerOn(*this))
        //     << "A focusable node lacked proper accessibility markup, "
        //        "causing a repair situation:"
        //     << "\n* Is name prohibited: " << IsNameProhibited()
        //     << "\n* Role: " << RoleValue()
        //     << "\n* URL: " << GetDocument()->Url()
        //     << "\n* Outer html: " << GetElement()->outerHTML()
        //     << "\n* AXObject ancestry:\n"
        //     << ParentChainToStringHelper(this);
#endif
      }
      break;

    case ax::mojom::blink::Role::kRubyAnnotation:
      // Ruby annotations are removed from accessible names and instead used
      // as a description of the parent Role::kRuby object. The benefit is that
      // announcement of the description can be togg
```