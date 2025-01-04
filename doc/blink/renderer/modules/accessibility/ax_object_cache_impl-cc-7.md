Response:
The user wants to understand the functionality of the `ax_object_cache_impl.cc` file in the Chromium Blink rendering engine. I need to:

1. **List the functionalities** of the code.
2. **Explain the relationship** between these functionalities and JavaScript, HTML, and CSS, providing examples.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs.
4. **Illustrate common user/programming errors** related to the functionalities.
5. **Describe how user actions lead to this code** being executed, as a debugging guide.
6. **Summarize the overall function** of the code, keeping in mind this is the last of eight parts.

Based on the provided code snippet, the core functionalities seem to revolve around managing the accessibility tree, handling updates, and providing information about accessibility objects.

**Functionalities Breakdown:**

*   **Caching Accessibility Objects:** Managing a cache of accessibility objects (`objects_`).
*   **Handling Bounding Box Changes:**  Tracking and invalidating bounding boxes of elements (`HandleLayoutObjectMoved`, `HandleScrollPositionChanged`, `InvalidateBoundingBox`, `InvalidateBoundingBoxForFixedOrStickyPosition`).
*   **Computing Accessibility Properties:** Calculating the computed role and name of nodes (`ComputedRoleForNode`, `ComputedNameForNode`).
*   **Handling Hover Events:** Processing accessibility hover events (`OnTouchAccessibilityHover`).
*   **Setting Canvas Object Bounds:**  Specifically setting bounds for canvas elements (`SetCanvasObjectBounds`).
*   **Managing Plugin Accessibility Trees:** Integrating accessibility information from plugins (`AddPluginTreeToUpdate`, `GetPluginTreeSource`, `SetPluginTreeSource`, `GetPluginTreeSerializer`, `ResetPluginTreeSerializer`, `MarkPluginDescendantDirty`).
*   **Tracking Nodes on a Line:**  Determining the next and previous accessible objects on the same line of text (`ComputeNodesOnLine`, `CachedNextOnLine`, `CachedPreviousOnLine`, `ClearCachedNodesOnLine`, `ConnectToTrailingWhitespaceOnLine`).
*   **Autofill Suggestion Availability:**  Managing the availability of autofill suggestions for accessibility (`GetAutofillSuggestionAvailability`, `SetAutofillSuggestionAvailability`).
*   **Serialization and Updates:** Managing the serialization and updating of the accessibility tree (`pending_objects_to_serialize_`, `node_to_parse_before_more_tree_updates_`).
*   **Event Tracking:** Determining the source of accessibility events (`ComputeEventFrom`).
*   **Tracing:** Providing a mechanism for tracing object relationships for debugging (`Trace`).

**Relationship with Web Technologies:**

*   **HTML:** The code directly interacts with HTML elements (Nodes, Elements, HTMLCanvasElement). It uses information about the HTML structure to build the accessibility tree. For example, `GetClosestNodeForLayoutObject` maps layout objects back to their corresponding HTML nodes.
*   **CSS:** CSS properties (like `position: fixed` or `position: sticky`) influence how bounding boxes are handled (`InvalidateBoundingBoxForFixedOrStickyPosition`). The layout of elements, determined by CSS, is crucial for `ComputeNodesOnLine`.
*   **JavaScript:** While this C++ code doesn't directly execute JavaScript, it provides the underlying accessibility information that JavaScript can access through the Accessibility Object Model (AOM) APIs. JavaScript can then use this information to create richer user experiences or for assistive technologies.

**Logical Reasoning Examples:**

*   **Hypothetical Input:** A `<div>` element with `position: fixed` is moved on the screen.
    *   **Processing:** `HandleLayoutObjectMoved` is called. The function checks if the layout object's document matches. `InvalidateBoundingBoxForFixedOrStickyPosition` is called because the element is fixed. The bounding box for the `<div>`'s corresponding AX object is marked for reserialization.
    *   **Output:** The accessibility tree is updated with the new bounding box of the `<div>`.

*   **Hypothetical Input:** A user hovers the mouse over a link.
    *   **Processing:** `OnTouchAccessibilityHover` is called with the mouse coordinates. `Root()->AccessibilityHitTest(location)` determines the accessibility object at that location. If it's not a frame or plugin, `PostNotification` is called to send a hover accessibility event.
    *   **Output:** An accessibility hover event is fired, which assistive technologies might use to provide feedback to the user.

**Common Errors:**

*   **Forgetting to mark an object as dirty:** If a change to an element's properties (that affect accessibility) is made, but the corresponding AX object isn't marked as dirty, assistive technologies might not receive the update. For example, if the `aria-label` of an element is changed via JavaScript, `MarkAXObjectDirty` should be called for the associated AX object.
*   **Incorrectly implementing plugin accessibility:** If a plugin doesn't correctly update its accessibility tree, the information exposed to assistive technologies will be inaccurate. For instance, if a plugin dynamically adds a new interactive element, it needs to use the provided interfaces (`AddPluginTreeToUpdate`, etc.) to inform Blink.
*   **Assuming immediate updates:** Accessibility updates are not always synchronous. Code relying on immediate changes in the accessibility tree after a DOM manipulation might encounter issues.

**User Actions as Debugging Clues:**

1. **Page Load:** When a page loads, the initial accessibility tree is built. This involves creating `AXObjectCacheImpl` and populating it with AX objects based on the HTML structure.
2. **Scrolling:** Scrolling the page triggers `HandleScrollPositionChanged`, which invalidates bounding boxes of fixed/sticky elements. Observing calls to this function helps in debugging issues with element positioning in the accessibility tree.
3. **Mouse Hover:** Hovering over elements calls `OnTouchAccessibilityHover`. This is a key entry point for debugging focus and interaction issues reported by assistive technology users.
4. **Dynamic Content Updates (JavaScript):** JavaScript manipulating the DOM (e.g., adding/removing elements, changing attributes) will lead to various functions in `AXObjectCacheImpl` being called to update the accessibility tree. Debugging these scenarios involves tracing the sequence of calls following a specific JavaScript action.
5. **Plugin Interactions:** When a plugin's content changes, the plugin's accessibility tree needs to be merged. Calls to `AddPluginTreeToUpdate` indicate this process is happening.

**Summary of Functionality (Part 8 of 8):**

As the final part, this section of `ax_object_cache_impl.cc` focuses on **advanced accessibility features and optimizations**. It deals with integrating accessibility information from plugins, efficiently determining the layout of elements on a line for better screen reader navigation, and managing autofill suggestions for accessibility. It also includes essential infrastructure for tracing and determining the origin of accessibility events. The inclusion of plugin support and line-based navigation highlights the engine's commitment to supporting complex web content and providing a rich experience for assistive technology users. The autofill functionality demonstrates the integration of accessibility with other browser features to enhance usability. Overall, this part showcases the sophisticated mechanisms employed to maintain an accurate and up-to-date accessibility tree that reflects the dynamic nature of modern web pages.

这是 `blink/renderer/modules/accessibility/ax_object_cache_impl.cc` 文件的第八部分，主要负责管理和更新 Chromium Blink 引擎中的可访问性对象缓存。它维护了页面元素的辅助功能表示，以便辅助技术（例如屏幕阅读器）可以理解页面内容并与用户交互。

以下是该文件片段中列出的功能及其与 JavaScript、HTML 和 CSS 的关系，以及相关的示例、逻辑推理、常见错误和用户操作的调试线索：

**功能列举:**

1. **处理布局对象移动 (`HandleLayoutObjectMoved`)**: 当页面上的元素位置发生变化时，此函数会被调用。它会检查元素是否是固定或粘性定位的，并标记其边界框需要重新序列化。
2. **处理滚动位置变化 (`HandleScrollPositionChanged`)**: 当页面滚动时，此函数会被调用。它会标记所有固定或粘性定位的对象的边界框需要重新序列化，因为它们的绝对位置会随着滚动而改变。
3. **获取节点的计算角色 (`ComputedRoleForNode`)**: 返回给定节点的计算辅助功能角色（例如，按钮、链接）。此函数确保在获取对象之前可访问性树已更新。
4. **获取节点的计算名称 (`ComputedNameForNode`)**: 返回给定节点的计算辅助功能名称（例如，按钮的文本标签）。同样，它确保可访问性树已更新。
5. **处理触摸辅助功能悬停 (`OnTouchAccessibilityHover`)**: 当用户在支持触摸的设备上进行辅助功能悬停操作时调用。它会找到悬停位置的辅助功能对象，并发布一个悬停事件。
6. **设置 Canvas 对象的边界 (`SetCanvasObjectBounds`)**: 允许为 Canvas 元素及其相关的其他元素设置特定的边界矩形。
7. **追踪 (`Trace`)**:  用于 Blink 的追踪基础设施，可以记录 `AXObjectCacheImpl` 中的重要对象和状态，用于调试和性能分析。
8. **计算事件来源 (`ComputeEventFrom`)**: 确定触发辅助功能事件的来源，例如用户操作或页面加载。
9. **获取自动填充建议可用性 (`GetAutofillSuggestionAvailability`)**:  获取特定辅助功能 ID 的自动填充建议的可用性状态。
10. **设置自动填充建议可用性 (`SetAutofillSuggestionAvailability`)**: 设置特定辅助功能 ID 的自动填充建议的可用性状态，并在状态改变时标记相应的辅助功能对象为脏。
11. **添加插件树以进行更新 (`AddPluginTreeToUpdate`)**: 将插件提供的辅助功能树整合到主渲染树的更新中。
12. **获取插件树源 (`GetPluginTreeSource`)**: 返回插件辅助功能树的源。
13. **设置插件树源 (`SetPluginTreeSource`)**: 设置插件辅助功能树的源和序列化器。
14. **获取插件树序列化器 (`GetPluginTreeSerializer`)**: 返回用于序列化插件辅助功能树的序列化器。
15. **重置插件树序列化器 (`ResetPluginTreeSerializer`)**: 重置插件辅助功能树的序列化器状态。
16. **标记插件后代为脏 (`MarkPluginDescendantDirty`)**: 标记插件辅助功能树中的特定节点及其子树为脏，表示需要更新。
17. **计算行上的节点 (`ComputeNodesOnLine`)**:  计算并缓存同一文本行上的布局对象，用于在屏幕阅读器等工具中进行逐行导航。
18. **连接到行尾的尾随空格 (`ConnectToTrailingWhitespaceOnLine`)**:  将行尾的尾随空格连接到同一行上的其他对象，以确保屏幕阅读器能够正确识别行尾的空格。
19. **缓存行上的下一个对象 (`CachedNextOnLine`)**:  从缓存中获取给定布局对象在同一行上的下一个布局对象。
20. **缓存行上的前一个对象 (`CachedPreviousOnLine`)**: 从缓存中获取给定布局对象在同一行上的前一个布局对象。
21. **清除缓存的行上节点 (`ClearCachedNodesOnLine`)**: 清除缓存的行上节点信息。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **HTML**:
    *   `HandleLayoutObjectMoved` 和 `HandleScrollPositionChanged` 会响应 HTML 元素位置的变化。例如，当 JavaScript 使用 `element.style.left` 修改元素位置或用户滚动页面时，这些函数会被调用。
    *   `ComputedRoleForNode` 和 `ComputedNameForNode` 基于 HTML 元素的语义和属性（例如，`role` 属性、文本内容、`alt` 属性等）计算辅助功能角色和名称。例如，`<button>Click me</button>` 的角色是 "button"，名称是 "Click me"。
    *   `SetCanvasObjectBounds` 用于处理 `<canvas>` 元素，允许为其内部绘制的内容定义辅助功能边界，这对于动态生成的可交互图形至关重要。
*   **CSS**:
    *   `HandleLayoutObjectMoved` 和 `HandleScrollPositionChanged` 特别关注 CSS 的 `position: fixed` 和 `position: sticky` 属性，因为这些元素的定位方式会影响其在滚动时的辅助功能表示。
    *   元素的布局（由 CSS 决定）直接影响 `ComputeNodesOnLine` 的结果。例如，`display: inline-block` 或 `float` 属性会影响元素在行内的排列。
*   **JavaScript**:
    *   JavaScript 可以动态地修改 DOM 结构和元素的属性，这些修改会触发 `AXObjectCacheImpl` 中的更新。例如，使用 JavaScript 创建新的 HTML 元素或修改现有元素的 `aria-label` 属性会导致辅助功能树的更新。
    *   `OnTouchAccessibilityHover` 响应用户的触摸操作，这些操作通常由 JavaScript 事件处理程序触发。
    *   `SetAutofillSuggestionAvailability` 可能在 JavaScript 代码处理自动填充事件时被调用，以告知辅助功能系统建议的可用性。

**逻辑推理的假设输入与输出:**

假设输入一个 `<div>` 元素，其 `style` 属性被 JavaScript 修改，使其 `left` 值发生变化。

*   **假设输入:**
    ```html
    <div id="myDiv" style="position: fixed; left: 10px;">Content</div>
    <script>
      document.getElementById('myDiv').style.left = '20px';
    </script>
    ```
*   **处理:** 当 JavaScript 修改 `left` 属性时，渲染引擎会检测到布局变化，并调用 `HandleLayoutObjectMoved`。由于 `myDiv` 的 `position` 是 `fixed`，`InvalidateBoundingBoxForFixedOrStickyPosition` 会被调用。
*   **输出:**  `myDiv` 对应的辅助功能对象的边界框会被标记为需要重新序列化，最终辅助功能树会更新，反映出 `myDiv` 的新位置。辅助技术（如屏幕阅读器）会感知到元素位置的改变。

假设输入一个带有 `aria-label` 属性的按钮：

*   **假设输入:** `<button aria-label="关闭窗口">X</button>`
*   **处理:** 当需要获取此按钮的计算名称时，`ComputedNameForNode` 会被调用。
*   **输出:** 函数会返回 "关闭窗口"，因为 `aria-label` 属性提供了明确的辅助功能名称。

**涉及用户或编程常见的使用错误:**

1. **忘记标记对象为脏:** 当通过 JavaScript 修改了影响辅助功能的元素属性（如 `aria-label`, `role` 等）后，如果没有显式地调用 `MarkAXObjectDirty` 或触发相关的布局更新，辅助技术可能无法感知到这些变化。
    *   **错误示例:**
        ```javascript
        const button = document.querySelector('button');
        button.setAttribute('aria-label', '新标签');
        // 缺少显式的辅助功能更新触发
        ```
2. **插件辅助功能集成不当:** 插件开发者可能未能正确实现 `AddPluginTreeToUpdate` 或相关接口，导致插件内部的可访问内容无法正确地暴露给辅助技术。
3. **过度依赖位置信息:**  虽然 `HandleLayoutObjectMoved` 和 `HandleScrollPositionChanged` 可以更新位置信息，但过度依赖绝对位置进行辅助功能交互可能导致在不同视口或缩放级别下出现问题。应该更多地依赖语义化的 HTML 和 ARIA 属性。
4. **行内节点计算错误:** 在复杂的布局中，`ComputeNodesOnLine` 的计算可能出现错误，导致屏幕阅读器在逐行导航时出现跳跃或遗漏的情况。这通常与复杂的 CSS 布局或动态内容更新有关。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **页面加载:** 当用户首次加载页面时，Blink 引擎会解析 HTML 和 CSS，创建布局树，并随后构建辅助功能树。`AXObjectCacheImpl` 会被初始化，并创建代表页面元素的辅助功能对象。
2. **滚动页面:** 用户滚动页面时，会触发 `HandleScrollPositionChanged`，特别是当页面包含 `position: fixed` 或 `position: sticky` 的元素时。调试时，如果发现固定定位元素的辅助功能信息未正确更新，可以检查此函数是否被调用。
3. **鼠标悬停或触摸:** 用户将鼠标悬停在元素上或在触摸设备上进行辅助功能触摸操作时，会触发 `OnTouchAccessibilityHover`。这可以用于调试焦点管理和交互问题。
4. **动态内容更新:** 用户与页面交互导致 JavaScript 修改 DOM 结构或元素属性时，例如点击按钮、填写表单等，这些操作会触发辅助功能树的更新。通过观察 `MarkAXObjectDirty` 的调用和相关的更新流程，可以追踪辅助功能信息的改变。
5. **使用屏幕阅读器导航:** 当用户使用屏幕阅读器等辅助技术浏览页面时，屏幕阅读器会请求辅助功能信息，这会导致 `ComputedRoleForNode`、`ComputedNameForNode` 和 `ComputeNodesOnLine` 等函数被调用。如果用户报告屏幕阅读器无法正确识别元素或在行间导航出现问题，可以重点调试这些函数。
6. **插件交互:** 如果页面包含插件（如 Flash 或其他类型的嵌入内容），当插件内容发生变化时，`AddPluginTreeToUpdate` 等函数会被调用。调试插件辅助功能集成问题时，需要关注这些函数的调用和插件提供的辅助功能数据。

**归纳一下它的功能 (第 8 部分，共 8 部分):**

作为 `ax_object_cache_impl.cc` 的最后一部分，此代码片段集中于一些更高级和优化的辅助功能处理功能。它涵盖了处理元素位置变化、计算辅助功能属性、处理用户交互（如触摸悬停）、集成插件提供的辅助功能信息、以及优化屏幕阅读器等工具的逐行导航体验。此外，它还涉及了自动填充建议的辅助功能支持和事件来源的追踪。  总而言之，这部分代码负责确保辅助功能树能够准确、高效地反映页面的动态变化和复杂结构，从而为使用辅助技术的用户提供更好的体验。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共8部分，请归纳一下它的功能

"""
ized, we store the last value for it
  // in cached_bounding_boxes_, to help with comparing if it really changed
  // or not when sending another serialization later.
  cached_bounding_boxes_.Set(id,
                             CachedLocationChange(bounds, scroll_x, scroll_y));
}

void AXObjectCacheImpl::HandleScrollPositionChanged(
    LayoutObject* layout_object) {
  if (layout_object->GetDocument() != document_) {
    return;
  }

  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  // When the scroll position position changes, mark the bounding boxes of all
  // fixed/sticky positioned objects for reserialization, because they are
  // relative to the top left of the document.
  InvalidateBoundingBoxForFixedOrStickyPosition();

  Node* node = GetClosestNodeForLayoutObject(layout_object);
  if (node) {
    InvalidateBoundingBox(node->GetDomNodeId());
  }
}

const AtomicString& AXObjectCacheImpl::ComputedRoleForNode(Node* node) {
  // Accessibility tree must be updated before getting an object.
  // Disallow a scope transition on the main document (which needs to already be
  // updated to its correct lifecycle state at this point, or else there would
  // be an illegal re-entrance to its lifecycle), but not for any popup document
  // that is open. That's because popup documents update their lifecycle async
  // from the main document, and hence any forced update to the popup document's
  // lifecycle here is not re-entrance but rather a "forced" lifecycle update.
  DocumentLifecycle::DisallowTransitionScope scoped(document_->Lifecycle());
  CommitAXUpdates(GetDocument(), /*force*/ true);
  ScopedFreezeAXCache scoped_freeze_cache(*this);
  AXObject* obj = Get(node);
  return AXObject::AriaRoleName(obj ? obj->ComputeFinalRoleForSerialization()
                                    : ax::mojom::blink::Role::kUnknown);
}

String AXObjectCacheImpl::ComputedNameForNode(Node* node) {
  // Accessibility tree must be updated before getting an object. See comment in
  // ComputedRoleForNode() for explanation of disallow transition scope usage.
  DocumentLifecycle::DisallowTransitionScope scoped(document_->Lifecycle());
  CommitAXUpdates(GetDocument(), /*force*/ true);
  ScopedFreezeAXCache scoped_freeze_cache(*this);
  AXObject* obj = Get(node);
  return obj ? obj->ComputedName() : "";
}

void AXObjectCacheImpl::OnTouchAccessibilityHover(const gfx::Point& location) {
  DocumentLifecycle::DisallowTransitionScope disallow(document_->Lifecycle());
  AXObject* hit = Root()->AccessibilityHitTest(location);
  if (hit) {
    // Ignore events on a frame or plug-in, because the touch events
    // will be re-targeted there and we don't want to fire duplicate
    // accessibility events.
    if (hit->GetLayoutObject() &&
        hit->GetLayoutObject()->IsLayoutEmbeddedContent())
      return;

    PostNotification(hit, ax::mojom::Event::kHover);
  }
}

void AXObjectCacheImpl::SetCanvasObjectBounds(HTMLCanvasElement* canvas,
                                              Element* element,
                                              const PhysicalRect& rect) {
  SCOPED_DISALLOW_LIFECYCLE_TRANSITION();

  AXObject* obj = Get(element);
  if (!obj)
    return;

  AXObject* ax_canvas = Get(canvas);
  if (!ax_canvas)
    return;

  obj->SetElementRect(rect, ax_canvas);
}

void AXObjectCacheImpl::Trace(Visitor* visitor) const {
  visitor->Trace(agents_);
  visitor->Trace(document_);
  visitor->Trace(popup_document_);
  visitor->Trace(last_selected_from_active_descendant_);
  visitor->Trace(layout_object_mapping_);
  visitor->Trace(inline_text_box_object_mapping_);
  visitor->Trace(active_aria_modal_dialog_);

  visitor->Trace(objects_);
  visitor->Trace(next_on_line_map_);
  visitor->Trace(processed_blocks_);
  visitor->Trace(previous_on_line_map_);

  visitor->Trace(tree_update_callback_queue_main_);
  visitor->Trace(tree_update_callback_queue_popup_);
  visitor->Trace(render_accessibility_host_);
  visitor->Trace(ax_tree_source_);
  visitor->Trace(pending_objects_to_serialize_);
  visitor->Trace(node_to_parse_before_more_tree_updates_);
  visitor->Trace(weak_factory_for_serialization_pipeline_);
  visitor->Trace(weak_factory_for_loc_updates_pipeline_);

  visitor->Trace(active_block_flow_data_);
  visitor->Trace(active_block_flow_container_);

  AXObjectCache::Trace(visitor);
}

ax::mojom::blink::EventFrom AXObjectCacheImpl::ComputeEventFrom() {
  if (active_event_from_ != ax::mojom::blink::EventFrom::kNone)
    return active_event_from_;

  if (document_ && document_->View() &&
      LocalFrame::HasTransientUserActivation(
          &(document_->View()->GetFrame()))) {
    return ax::mojom::blink::EventFrom::kUser;
  }

  return ax::mojom::blink::EventFrom::kPage;
}

WebAXAutofillSuggestionAvailability
AXObjectCacheImpl::GetAutofillSuggestionAvailability(AXID id) const {
  auto iter = autofill_suggestion_availability_map_.find(id);
  if (iter == autofill_suggestion_availability_map_.end()) {
    return WebAXAutofillSuggestionAvailability::kNoSuggestions;
  }
  return iter->value;
}

void AXObjectCacheImpl::SetAutofillSuggestionAvailability(
    AXID id,
    WebAXAutofillSuggestionAvailability suggestion_availability) {
  WebAXAutofillSuggestionAvailability previous_suggestion_availability =
      GetAutofillSuggestionAvailability(id);
  if (suggestion_availability != previous_suggestion_availability) {
    autofill_suggestion_availability_map_.Set(id, suggestion_availability);
    MarkAXObjectDirty(ObjectFromAXID(id));
  }
}

void AXObjectCacheImpl::AddPluginTreeToUpdate(ui::AXTreeUpdate* update) {
  if (!plugin_tree_source_) {
    return;
  }

  // Conceptually, a plugin tree "stitches" itself into an existing Blink
  // accessibility node. For example, the node could be an <embed>. The plugin
  // tree itself contains a root who's parent is the target of the stitching
  // (e.g. the <embed> in the Blink accessibility tree). The plugin tree manages
  // its own tree of nodes and the below logic handles how that gets integrated
  // into Blink accessibility.

  CHECK(plugin_serializer_.get());

  // Search for the Blink accessibility node onto which we want to stitch the
  // plugin tree.
  for (ui::AXNodeData& node : update->nodes) {
    if (node.role == ax::mojom::Role::kEmbeddedObject) {
      // The embed node should already exist in the blink tree source's client
      // tree.
      CHECK(ax_tree_serializer_->IsInClientTree(
          ax_tree_source_->GetFromId(node.id)));

      // The plugin tree contains its own tree source, serializer pair. It isn't
      // using Blink's source, serializer pair because its backing template tree
      // source type is a pure AXNodeData.
      const ui::AXNode* root = plugin_tree_source_->GetRoot();
      if (!root) {
        // The tree may not yet be ready.
        continue;
      }
      node.child_ids.push_back(root->id());

      // Serialize changes and integrate them into Blink accessibility's tree
      // updates.
      ui::AXTreeUpdate plugin_update;
      plugin_serializer_->SerializeChanges(root, &plugin_update);

      update->nodes.reserve(update->nodes.size() + plugin_update.nodes.size());
      base::ranges::move(plugin_update.nodes,
                         std::back_inserter(update->nodes));

      if (plugin_tree_source_->GetTreeData(&update->tree_data)) {
        update->has_tree_data = true;
      }
      break;
    }
  }
}

ui::AXTreeSource<const ui::AXNode*, ui::AXTreeData*, ui::AXNodeData>*
AXObjectCacheImpl::GetPluginTreeSource() {
  return plugin_tree_source_.get();
}

void AXObjectCacheImpl::SetPluginTreeSource(
    ui::AXTreeSource<const ui::AXNode*, ui::AXTreeData*, ui::AXNodeData>*
        source) {
  if (plugin_tree_source_.get() == source) {
    return;
  }

  plugin_tree_source_ = source;
  plugin_serializer_ =
      source ? std::make_unique<PluginAXTreeSerializer>(source) : nullptr;
}

ui::AXTreeSerializer<const ui::AXNode*,
                     std::vector<const ui::AXNode*>,
                     ui::AXTreeUpdate*,
                     ui::AXTreeData*,
                     ui::AXNodeData>*
AXObjectCacheImpl::GetPluginTreeSerializer() {
  return plugin_serializer_.get();
}

void AXObjectCacheImpl::ResetPluginTreeSerializer() {
  if (plugin_serializer_.get()) {
    plugin_serializer_->Reset();
  }
}

void AXObjectCacheImpl::MarkPluginDescendantDirty(ui::AXNodeID node_id) {
  if (plugin_serializer_.get()) {
    plugin_serializer_->MarkSubtreeDirty(node_id);
  }
}

void AXObjectCacheImpl::ComputeNodesOnLine(const LayoutObject* layout_object) {
  // The following computation is expensive.
  //
  // This function works as follows:
  // 1. If a layout object associated with an AXNodeObject has its data already
  // computed, we finish early;
  // 2. If the associated Layout Block that the inline element is contained is
  // already processed, we finish early. Note that 2 must come after 1, since
  // retrieving the block is not so cheap;
  // 3. For each line of this layout block flow, we connect and store the layout
  // objects that are part of this line. They are later used in
  // Next|PreviousOnLine.
  //
  // The main advantage of this approach is to be able to, in a single pass,
  // compute the next and previous objects in a single line.
  if (!layout_object) {
    return;
  }
  if (!layout_object->IsInline() ||
      !layout_object->IsInLayoutNGInlineFormattingContext()) {
    return;
  }
  if (CachedNextOnLine(layout_object)) {
    return;
  }
  const LayoutBlockFlow* block_flow = layout_object->FragmentItemsContainer();
  if (!block_flow) {
    return;
  }
  if (!processed_blocks_.insert(block_flow).is_new_entry) {
    return;
  }
  InlineCursor cursor(*block_flow);
  if (!cursor) {
    // Cursor may be null if all objects of this cursor are collapsed.
    return;
  }

  // Important! The next call to MoveToNextInlineLeaf() below fails if we are
  // not inside a line.
  cursor.MoveToFirstLine();
  if (!cursor) {
    return;
  }

  do {
    InlineCursor line_cursor = cursor;

    // Moves to first LayoutObject that a11y cares about.
    line_cursor.MoveToNextInlineLeaf();

    // Maximum number of attempts to try to find a next object on the line. Used
    // to
    // detect unlikely (but theoretically possible), loops.
    constexpr int kMaxInlineCursorNextObjectCalls = 250000;
    int runs = 0;
    while (line_cursor) {
      runs++;

      if (runs >= kMaxInlineCursorNextObjectCalls) [[unlikely]] {
        // TODO(crbug.com/378761505): Move DUMP_WILL_BE_NOTREACHED() to CHECK().
        DUMP_WILL_BE_NOTREACHED()
            << "Did not find an end to the processing of next / previous on "
               "line candidates for "
            << layout_object << "(" << Get(layout_object) << ") after " << runs
            << " runs.";
        break;
      }
      auto* line_object = line_cursor.CurrentMutableLayoutObject();
      line_cursor.MoveToNextInlineLeafOnLine();

      if (!line_object) [[unlikely]] {
        // TODO(crbug.com/378761505): Move DUMP_WILL_BE_NOTREACHED() to CHECK().
        DUMP_WILL_BE_NOTREACHED()
            << "InlineCursor says that has an existing position however no "
               "LayoutObject was found. Found this while processing "
            << layout_object << "(" << Get(layout_object) << ") after " << runs
            << " runs.";
        break;
      }
      if (line_object) {
        auto* next_line_object =
            line_cursor ? line_cursor.CurrentMutableLayoutObject() : nullptr;

        if (line_object == next_line_object) [[unlikely]] {
          // TODO(crbug.com/378761505): Move DUMP_WILL_BE_NOTREACHED() to
          // CHECK().
          DUMP_WILL_BE_NOTREACHED()
              << "InlineCursor says it moved to the next inline leaf object "
                 "for a different LayyoutObject, but returned value is the "
                 "same as previous inline leaf."
              << "same object was: " << line_object << "(" << Get(line_object)
              << ") while processing " << layout_object << " after " << runs
              << " runs.";
          break;
        }
        if (next_line_object) {
          next_on_line_map_.insert(line_object, next_line_object);
          previous_on_line_map_.insert(next_line_object, line_object);
        } else {
          // Reached the end of the line. Check if it contains a trailing white
          // space that was not visited by the inline cursor because it was
          // collapsed.
          // The white space at the end of the line is important for a11y
          // because if it is not part of the line text, a screen reader may not
          // know that it has reached a previous line when going back to the
          // previous line.
          ConnectToTrailingWhitespaceOnLine(*line_object, *block_flow);
        }
      }
    }
    cursor.MoveToNextLine();
  } while (cursor);
}

void AXObjectCacheImpl::ConnectToTrailingWhitespaceOnLine(
    const LayoutObject& line_object,
    const LayoutBlockFlow& block_flow) {
  LayoutObject* trailing_whitespace_object =
      PreviousLayoutObjectTextOnLine(line_object, block_flow);
  if (!trailing_whitespace_object) {
    return;
  }
  if (!IsAllCollapsedWhiteSpace(*trailing_whitespace_object)) {
    return;
  }
  if (AXObject* obj = Get(trailing_whitespace_object);
      obj && obj->IsIncludedInTree()) {
    if (auto* previous = PreviousLayoutObjectTextOnLine(
            *trailing_whitespace_object, block_flow)) {
      // `trailing_whitespace_object` has a LayoutObject that is in
      // the same line, connect them here.
      // Note: we use `Set()` here to override if a value exists, where in
      // `ComputeNodesOnLine()` we use `insert()`, which does not. This is
      // necessary in case a object in the line pointed to something else, where
      // now it needs to point to the trailing whitespace.
      next_on_line_map_.Set(previous, trailing_whitespace_object);
      previous_on_line_map_.Set(trailing_whitespace_object, previous);
    }
  }
}

const LayoutObject* AXObjectCacheImpl::CachedNextOnLine(
    const LayoutObject* layout_object) {
  auto it = next_on_line_map_.find(layout_object);
  if (it != next_on_line_map_.end()) {
    return it->value;
  }
  return nullptr;
}

const LayoutObject* AXObjectCacheImpl::CachedPreviousOnLine(
    const LayoutObject* layout_object) {
  auto it = previous_on_line_map_.find(layout_object);
  if (it != previous_on_line_map_.end()) {
    return it->value;
  }
  return nullptr;
}

void AXObjectCacheImpl::ClearCachedNodesOnLine() {
  next_on_line_map_.clear();
  previous_on_line_map_.clear();
  processed_blocks_.clear();
}

std::ostream& operator<<(std::ostream& stream, const AXObjectCacheImpl& cache) {
  return stream << "AXObjectCache: " << cache.lifecycle().ToString();
}

}  // namespace blink

"""


```