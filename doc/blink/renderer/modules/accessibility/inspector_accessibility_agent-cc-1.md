Response:
The user wants me to analyze the provided C++ code snippet from Chromium's Blink rendering engine. This is the second part of a two-part analysis. I need to summarize the functionality of this part, considering its relation to web technologies (JavaScript, HTML, CSS), potential logic, user errors, and how a user might trigger this code.

Here's a breakdown of the tasks:

1. **Summarize functionality:** Identify the main purpose and actions performed by the code.
2. **Relate to JavaScript, HTML, CSS:** Explain how the code interacts with or reflects concepts from these web technologies.
3. **Logic and examples:** If the code performs logical operations, provide hypothetical inputs and outputs.
4. **User errors:** Identify common mistakes users might make that could lead to this code being executed.
5. **User journey:** Describe the steps a user might take in a web browser that would eventually involve this code.
6. **Consider it's part 2:**  Integrate the understanding from the first part (although not provided here, I need to infer some context).

Based on the code, it seems to be responsible for retrieving and providing accessibility information of web page elements to an external tool (likely the browser's DevTools). It interacts with the Accessibility Object Model (AXOM), which is a representation of the page's structure for accessibility purposes.

**Mental Sandbox:**

* **Summarization:** The code handles requests for accessibility tree data, individual node information, and querying the tree based on attributes. It also listens for accessibility events and updates the DevTools accordingly.
* **Web Tech Relation:** HTML elements have corresponding accessibility objects. CSS properties can influence the accessibility tree (e.g., `display: none` will likely lead to an ignored node). JavaScript can dynamically modify the DOM, leading to accessibility tree updates.
* **Logic and examples:**  The `queryAXTree` function takes criteria (name, role) and searches the tree. Input: `accessible_name="button"`. Output: A list of AXNodes representing buttons.
* **User Errors:**  A developer might write incorrect ARIA attributes in their HTML, leading to an inaccurate accessibility tree.
* **User Journey:** A developer opens the browser's DevTools, navigates to the "Accessibility" tab, and then inspects or queries accessibility information about elements on the page. This triggers the communication with this C++ code.

Now I can formulate the detailed explanation.
这是 `InspectorAccessibilityAgent` 类的实现代码的第二部分，延续了第一部分的功能，主要集中在处理来自前端（通常是开发者工具）的关于页面可访问性信息的请求，并维护和更新可访问性树的状态。

**功能归纳:**

这部分代码主要负责以下功能：

1. **获取完整的可访问性树 (getFullAXTree):**
   - 接收一个可选的 `depth` 参数来限制返回的树的深度，以及一个可选的 `frame_id` 来指定要获取哪个 frame 的可访问性树。
   - 调用 `WalkAXNodesToDepth` 遍历并构建指定深度的可访问性树。
   - 返回包含可访问性节点信息的数组。

2. **获取根可访问性节点 (getRootAXNode):**
   - 接收一个可选的 `frame_id` 参数来指定要获取哪个 frame 的根节点。
   - 确保可访问性功能已启用。
   - 构建并返回根可访问性节点的信息。

3. **获取可访问性节点及其祖先 (getAXNodeAndAncestors):**
   - 接收 DOM 节点的 ID (`dom_node_id`, `backend_node_id`, 或 `object_id`) 来定位目标节点。
   - 确保可访问性功能已启用。
   - 向上遍历可访问性树，构建包含目标节点及其所有祖先节点的数组。
   - 如果目标 DOM 节点没有对应的可访问性节点，则会创建一个临时的 AXNode 对象。

4. **获取子可访问性节点 (getChildAXNodes):**
   - 接收父可访问性节点的 ID (`in_id`) 和可选的 `frame_id`。
   - 确保可访问性功能已启用。
   - 构建并返回指定父节点的所有子可访问性节点的信息数组。

5. **填充核心属性 (FillCoreProperties):**
   - 为给定的可访问性对象 (`AXObject`) 填充名称、描述和值等核心属性到 `AXNode` 对象中。

6. **添加子节点 (AddChildren):**
   - 递归地将一个可访问性对象的所有子节点（包括被忽略的节点）添加到给定的节点数组中。

7. **查询可访问性树 (queryAXTree):**
   - 允许根据 DOM 节点 ID、可访问名称和角色查询可访问性树。
   - 将查询请求添加到队列中，并在可访问性树准备好后执行查询。

8. **完成查询 (CompleteQuery):**
   - 执行添加到队列中的可访问性树查询，并使用 `sendSuccess` 或 `sendFailure` 将结果发送回前端。

9. **可访问性准备就绪回调 (AXReadyCallback):**
   - 当文档的可访问性树准备就绪时被调用。
   - 处理待处理的查询请求和脏节点更新。
   - 在页面加载完成时通知前端。

10. **处理待处理的查询 (ProcessPendingQueries):**
    - 执行指定文档上所有待处理的可访问性树查询。

11. **处理待处理的脏节点 (ProcessPendingDirtyNodes):**
    - 定期同步并发送已更改的可访问性节点信息到前端。为了避免过于频繁的更新，这里使用了节流 (throttling) 机制。

12. **调度可访问性更新 (ScheduleAXUpdateIfNeeded, ScheduleAXChangeNotification):**
    - 当可访问性树发生更改时，调度可访问性树的更新。使用了定时器来合并更新，避免过于频繁的计算。

13. **可访问性事件触发 (AXEventFired):**
    - 监听可访问性事件，例如 `LoadComplete`，并根据事件类型标记节点为脏并安排更新。

14. **标记可访问性对象为脏 (MarkAXObjectDirty):**
    - 将指定的 `AXObject` 标记为已更改，以便后续同步到前端。只有当该节点之前被请求过时才会被标记。

15. **可访问性对象被修改 (AXObjectModified):**
    - 当可访问性对象或其子树被修改时，标记相关的可访问性对象为脏并安排更新。

16. **启用和重置 (EnableAndReset):**
    - 启用可访问性检查器代理，并将其添加到已启用代理的集合中。

17. **启用 (enable):**
    - 启用可访问性检查器代理。

18. **禁用 (disable):**
    - 禁用可访问性检查器代理，并清理相关的状态和缓存。

19. **恢复 (Restore):**
    - 在某些场景下恢复可访问性检查器代理的状态。

20. **提供给 (ProvideTo):**
    - 将可访问性检查器代理附加到指定的 frame 的可访问性对象缓存。

21. **附加到可访问性对象缓存 (AttachToAXObjectCache):**
    - 将可访问性检查器代理附加到指定文档的可访问性对象缓存，以便监听和处理可访问性相关的事件和请求。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**  HTML 结构是可访问性树的基础。每个 HTML 元素（以及某些伪元素）都可能在可访问性树中有一个对应的节点 (`AXObject`)。代码通过 DOM 节点 ID 来查找对应的可访问性对象。例如，`getAXNodeAndAncestors` 方法接收 DOM 节点 ID，然后获取其对应的可访问性节点。
    ```html
    <button id="myButton" aria-label="Click me">Submit</button>
    ```
    前端可以通过 `DOM.getNodeId` 获取 `myButton` 的节点 ID，然后传递给 `getAXNodeAndAncestors` 来获取按钮及其祖先的可访问性信息。

* **CSS:** CSS 样式可以影响可访问性树的呈现方式和某些属性。例如，`display: none` 或 `visibility: hidden` 可能会导致元素在可访问性树中被忽略。代码中，`AXObject::IsIgnored()` 方法会考虑 CSS 样式的影响。
    ```css
    .hidden {
      display: none;
    }
    ```
    如果一个 HTML 元素应用了 `.hidden` 类，那么它的 `AXObject::IsIgnored()` 方法可能会返回 true，`AddChildren` 方法会根据 `follow_ignored` 参数决定是否继续遍历其子节点。

* **JavaScript:** JavaScript 可以动态修改 DOM 结构和属性，这些修改会触发可访问性树的更新。例如，当 JavaScript 通过 `setAttribute` 修改元素的 `aria-label` 属性时，会触发 `AXObjectModified` 事件，导致相关的可访问性节点被标记为脏，并最终同步到前端。
    ```javascript
    document.getElementById('myButton').setAttribute('aria-label', 'Submit the form');
    ```
    这个 JavaScript 操作会触发可访问性树的更新，`InspectorAccessibilityAgent` 会捕获这个变化并通过 `nodesUpdated` 方法将更新后的节点信息发送到开发者工具。

**逻辑推理举例 (queryAXTree):**

**假设输入:**

* `dom_node_id`:  (假设存在一个 `div` 元素的 DOM 节点 ID 为 123)
* `accessible_name`: "Search"
* `role`: "textbox"

**输出:**

一个包含所有满足以下条件的可访问性节点的 `AXNode` 数组：

1. 它是以 DOM 节点 123 为根的子树中的节点。
2. 它的可访问名称 (accessible name) 为 "Search"。
3. 它的角色 (role) 为 "textbox"。

**用户或编程常见的使用错误:**

* **未启用可访问性检查器:** 用户可能在开发者工具中没有启用 "Accessibility" 面板，此时调用相关方法会返回错误，例如 `getRootAXNode` 会返回 "Accessibility has not been enabled."。
* **传递无效的节点 ID:**  前端可能会传递一个不存在的 DOM 节点 ID 或可访问性节点 ID，导致 `FrameFromIdOrRoot` 或 `cache.ObjectFromAXID` 返回空指针，从而导致错误响应。
* **在可访问性树未准备好时查询:**  用户可能在页面加载初期或 DOM 结构频繁变化时进行查询，此时可能无法获取到最新的可访问性信息。`queryAXTree` 方法会将查询添加到队列中，等待可访问性树准备好后再执行，但这仍然可能导致用户在短时间内看到旧的数据。
* **错误地理解可访问性属性:**  开发者可能设置了错误的 ARIA 属性，导致可访问性树的结构或属性与预期不符。例如，错误地使用了 `aria-hidden="true"` 可能会导致元素在可访问性树中被忽略，但在视觉上仍然可见。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开 Chrome 浏览器，访问一个网页。**
2. **用户打开开发者工具 (通常通过右键点击页面元素并选择 "检查"，或使用 F12 快捷键)。**
3. **用户导航到开发者工具的 "Elements" (元素) 面板。**
4. **用户选中一个 HTML 元素。**
5. **用户切换到开发者工具的 "Accessibility" (无障碍) 面板。**
6. **在 "Accessibility" 面板中，用户可能会：**
   - 查看当前选中元素的 "Accessibility Tree" (可访问性树)，这会触发 `getRootAXNode` 或 `getAXNodeAndAncestors` 方法来获取相关节点信息。
   - 点击 "Inspect" (检查) 按钮来查看特定元素的可访问性属性，这也会触发获取节点信息的方法。
   - 使用 "Query" (查询) 功能，输入可访问名称或角色等条件来搜索可访问性树，这会触发 `queryAXTree` 方法。
7. **开发者工具的前端 JavaScript 代码会根据用户的操作，调用 Chrome DevTools Protocol (CDP) 中与可访问性相关的命令，例如 `Accessibility.getFullAXTree`，`Accessibility.getRootAXNode` 等。**
8. **这些 CDP 命令会被路由到 `InspectorAccessibilityAgent` 类的相应方法中，例如 `getFullAXTree`，`getRootAXNode` 等。**
9. **`InspectorAccessibilityAgent` 类的方法会与 Blink 渲染引擎的可访问性 API 交互，例如 `AXObjectCache`，来获取和构建可访问性信息。**
10. **获取到的可访问性信息会被序列化成 CDP 协议规定的格式，并通过 CDP 连接发送回开发者工具的前端进行展示。**

总而言之，这部分代码是 Chromium Blink 引擎中负责向开发者工具暴露页面可访问性信息的关键组件，它响应来自前端的请求，并维护和更新可访问性树的状态，以便开发者能够理解和调试其网页的无障碍特性。

Prompt: 
```
这是目录为blink/renderer/modules/accessibility/inspector_accessibility_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ce& name_source : name_sources) {
        name_source_properties->emplace_back(CreateValueSource(name_source));
        if (name_source.text.IsNull() || name_source.superseded)
          continue;
        if (!name_source.related_objects.empty()) {
          properties->emplace_back(CreateRelatedNodeListProperty(
              AXPropertyNameEnum::Labelledby, name_source.related_objects));
        }
      }
      name->setSources(std::move(name_source_properties));
    }
    node_object->setProperties(std::move(properties));
    node_object->setName(std::move(name));
  } else {
    node_object->setProperties(std::move(properties));
  }

  FillCoreProperties(ax_object, node_object.get());
  return node_object;
}

LocalFrame* InspectorAccessibilityAgent::FrameFromIdOrRoot(
    const protocol::Maybe<String>& frame_id) {
  if (frame_id.has_value()) {
    return IdentifiersFactory::FrameById(inspected_frames_.Get(),
                                         frame_id.value());
  }
  return inspected_frames_->Root();
}

protocol::Response InspectorAccessibilityAgent::getFullAXTree(
    protocol::Maybe<int> depth,
    Maybe<String> frame_id,
    std::unique_ptr<protocol::Array<AXNode>>* nodes) {
  LocalFrame* frame = FrameFromIdOrRoot(frame_id);
  if (!frame) {
    return protocol::Response::InvalidParams(
        "Frame with the given frameId is not found.");
  }

  Document* document = frame->GetDocument();
  if (!document)
    return protocol::Response::InternalError();
  if (document->View()->NeedsLayout() || document->NeedsLayoutTreeUpdate())
    document->UpdateStyleAndLayout(DocumentUpdateReason::kInspector);

  *nodes = WalkAXNodesToDepth(document, depth.value_or(-1));

  return protocol::Response::Success();
}

std::unique_ptr<protocol::Array<AXNode>>
InspectorAccessibilityAgent::WalkAXNodesToDepth(Document* document,
                                                int max_depth) {
  std::unique_ptr<protocol::Array<AXNode>> nodes =
      std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();

  auto& cache = AttachToAXObjectCache(document);
  cache.UpdateAXForAllDocuments();
  ScopedFreezeAXCache freeze(cache);

  Deque<std::pair<AXID, int>> id_depths;
  id_depths.emplace_back(cache.Root()->AXObjectID(), 1);
  nodes->emplace_back(BuildProtocolAXNodeForAXObject(*cache.Root()));

  while (!id_depths.empty()) {
    std::pair<AXID, int> id_depth = id_depths.front();
    id_depths.pop_front();
    AXObject* ax_object = cache.ObjectFromAXID(id_depth.first);
    if (!ax_object)
      continue;
    AddChildren(*ax_object, true, nodes, cache);

    const AXObject::AXObjectVector& children = ax_object->UnignoredChildren();

    for (auto& child_ax_object : children) {
      int depth = id_depth.second;
      if (max_depth == -1 || depth < max_depth)
        id_depths.emplace_back(child_ax_object->AXObjectID(), depth + 1);
    }
  }

  return nodes;
}

protocol::Response InspectorAccessibilityAgent::getRootAXNode(
    Maybe<String> frame_id,
    std::unique_ptr<AXNode>* node) {
  LocalFrame* frame = FrameFromIdOrRoot(frame_id);
  if (!frame) {
    return protocol::Response::InvalidParams(
        "Frame with the given frameId is not found.");
  }
  if (!enabled_.Get()) {
    return protocol::Response::ServerError(
        "Accessibility has not been enabled.");
  }

  Document* document = frame->GetDocument();
  if (!document)
    return protocol::Response::InternalError();

  auto& cache = AttachToAXObjectCache(document);
  cache.UpdateAXForAllDocuments();
  auto& root = *cache.Root();

  ScopedFreezeAXCache freeze(cache);

  *node = BuildProtocolAXNodeForAXObject(root);
  nodes_requested_.insert(root.AXObjectID());

  return protocol::Response::Success();
}

protocol::Response InspectorAccessibilityAgent::getAXNodeAndAncestors(
    Maybe<int> dom_node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    std::unique_ptr<protocol::Array<protocol::Accessibility::AXNode>>*
        out_nodes) {
  if (!enabled_.Get()) {
    return protocol::Response::ServerError(
        "Accessibility has not been enabled.");
  }

  Node* dom_node = nullptr;
  protocol::Response response =
      dom_agent_->AssertNode(dom_node_id, backend_node_id, object_id, dom_node);
  if (!response.IsSuccess())
    return response;

  Document& document = dom_node->GetDocument();
  LocalFrame* local_frame = document.GetFrame();
  if (!local_frame)
    return protocol::Response::ServerError("Frame is detached.");

  auto& cache = AttachToAXObjectCache(&document);
  cache.UpdateAXForAllDocuments();
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      document.Lifecycle());

  AXObject* ax_object = cache.Get(dom_node);

  ScopedFreezeAXCache freeze(cache);

  *out_nodes =
      std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();

  if (!ax_object) {
    (*out_nodes)
        ->emplace_back(BuildProtocolAXNodeForDOMNodeWithNoAXNode(
            IdentifiersFactory::IntIdForNode(dom_node)));
    return protocol::Response::Success();
  }

  do {
    nodes_requested_.insert(ax_object->AXObjectID());
    std::unique_ptr<AXNode> ancestor =
        BuildProtocolAXNodeForAXObject(*ax_object);
    (*out_nodes)->emplace_back(std::move(ancestor));
    ax_object = ax_object->ParentObjectIncludedInTree();
  } while (ax_object);

  return protocol::Response::Success();
}

protocol::Response InspectorAccessibilityAgent::getChildAXNodes(
    const String& in_id,
    Maybe<String> frame_id,
    std::unique_ptr<protocol::Array<protocol::Accessibility::AXNode>>*
        out_nodes) {
  if (!enabled_.Get()) {
    return protocol::Response::ServerError(
        "Accessibility has not been enabled.");
  }

  LocalFrame* frame = FrameFromIdOrRoot(frame_id);
  if (!frame) {
    return protocol::Response::InvalidParams(
        "Frame with the given frameId is not found.");
  }

  Document* document = frame->GetDocument();
  if (!document)
    return protocol::Response::InternalError();

  auto& cache = AttachToAXObjectCache(document);
  cache.UpdateAXForAllDocuments();

  ScopedFreezeAXCache freeze(cache);

  AXID ax_id = in_id.ToInt();
  AXObject* ax_object = cache.ObjectFromAXID(ax_id);

  if (!ax_object || ax_object->IsDetached())
    return protocol::Response::InvalidParams("Invalid ID");

  *out_nodes =
      std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();

  AddChildren(*ax_object, /* follow_ignored */ true, *out_nodes, cache);

  for (const auto& child : **out_nodes)
    nodes_requested_.insert(child->getNodeId().ToInt());

  return protocol::Response::Success();
}

void InspectorAccessibilityAgent::FillCoreProperties(
    AXObject& ax_object,
    AXNode* node_object) const {
  ax::mojom::NameFrom name_from;
  AXObject::AXObjectVector name_objects;
  ax_object.GetName(name_from, &name_objects);

  ax::mojom::DescriptionFrom description_from;
  AXObject::AXObjectVector description_objects;
  String description =
      ax_object.Description(name_from, description_from, &description_objects);
  if (!description.empty()) {
    node_object->setDescription(
        CreateValue(description, AXValueTypeEnum::ComputedString));
  }
  // Value.
  if (ax_object.IsRangeValueSupported()) {
    float value;
    if (ax_object.ValueForRange(&value))
      node_object->setValue(CreateValue(value));
  } else {
    String value = ax_object.SlowGetValueForControlIncludingContentEditable();
    if (!value.empty())
      node_object->setValue(CreateValue(value));
  }
}

void InspectorAccessibilityAgent::AddChildren(
    AXObject& ax_object,
    bool follow_ignored,
    std::unique_ptr<protocol::Array<AXNode>>& nodes,
    AXObjectCacheImpl& cache) const {
  HeapVector<Member<AXObject>> reachable;
  reachable.AppendRange(ax_object.ChildrenIncludingIgnored().rbegin(),
                        ax_object.ChildrenIncludingIgnored().rend());

  while (!reachable.empty()) {
    AXObject* descendant = reachable.back();
    reachable.pop_back();
    if (descendant->IsDetached())
      continue;

    // If the node is ignored or has no corresponding DOM node, we include
    // another layer of children.
    if (follow_ignored &&
        (descendant->IsIgnoredButIncludedInTree() ||
         !descendant->GetNode())) {
      reachable.AppendRange(descendant->ChildrenIncludingIgnored().rbegin(),
                            descendant->ChildrenIncludingIgnored().rend());
    }
    auto child_node = BuildProtocolAXNodeForAXObject(*descendant);
    nodes->emplace_back(std::move(child_node));
  }
}

void InspectorAccessibilityAgent::queryAXTree(
    Maybe<int> dom_node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    Maybe<String> accessible_name,
    Maybe<String> role,
    std::unique_ptr<QueryAXTreeCallback> callback) {
  Node* root_dom_node = nullptr;
  protocol::Response response = dom_agent_->AssertNode(
      dom_node_id, backend_node_id, object_id, root_dom_node);
  if (!response.IsSuccess()) {
    callback->sendFailure(response);
    return;
  }

  // Shadow roots are missing from a11y tree.
  // We start searching the host element instead as a11y tree does not
  // care about shadow roots.
  if (root_dom_node->IsShadowRoot()) {
    root_dom_node = root_dom_node->OwnerShadowHost();
  }
  if (!root_dom_node) {
    callback->sendFailure(
        protocol::Response::InvalidParams("Root DOM node could not be found"));
    return;
  }

  Document& document = root_dom_node->GetDocument();
  auto& cache = AttachToAXObjectCache(&document);
  cache.UpdateAXForAllDocuments();

  AXQuery query = {std::move(dom_node_id), std::move(backend_node_id),
                   std::move(object_id),   std::move(accessible_name),
                   std::move(role),        std::move(callback)};
  auto it = queries_.find(&document);
  if (it != queries_.end()) {
    it->value.push_back(std::move(query));
  } else {
    Vector<AXQuery> vector;
    vector.emplace_back(std::move(query));
    queries_.insert(&document, std::move(vector));
  }
  // ScheduleAXUpdate() ensures the lifecycle doesn't get stalled,
  // and therefore ensures we get the AXReadyCallback callback as soon as a11y
  // is clean again.
  cache.ScheduleAXUpdate();
}

void InspectorAccessibilityAgent::CompleteQuery(AXQuery& query) {
  Node* root_dom_node = nullptr;

  protocol::Response response = dom_agent_->AssertNode(
      query.dom_node_id, query.backend_node_id, query.object_id, root_dom_node);
  if (!response.IsSuccess()) {
    query.callback->sendFailure(response);
    return;
  }

  // Shadow roots are missing from a11y tree.
  // We start searching the host element instead as a11y tree does not
  // care about shadow roots.
  if (root_dom_node->IsShadowRoot())
    root_dom_node = root_dom_node->OwnerShadowHost();
  if (!root_dom_node) {
    query.callback->sendFailure(
        protocol::Response::InvalidParams("Root DOM node could not be found"));
    return;
  }
  Document& document = root_dom_node->GetDocument();

  document.UpdateStyleAndLayout(DocumentUpdateReason::kInspector);
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      document.Lifecycle());
  auto& cache = AttachToAXObjectCache(&document);
  ScopedFreezeAXCache freeze(cache);

  std::unique_ptr<protocol::Array<AXNode>> nodes =
      std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();
  AXObject* root_ax_node = cache.Get(root_dom_node);

  HeapVector<Member<AXObject>> reachable;
  if (root_ax_node)
    reachable.push_back(root_ax_node);

  while (!reachable.empty()) {
    AXObject* ax_object = reachable.back();
    if (ax_object->IsDetached() ||
        !ax_object->IsIncludedInTree()) {
      reachable.pop_back();
      continue;
    }
    ui::AXNodeData node_data;
    ax_object->Serialize(&node_data, ui::kAXModeComplete);
    reachable.pop_back();
    const AXObject::AXObjectVector& children =
        ax_object->ChildrenIncludingIgnored();
    reachable.AppendRange(children.rbegin(), children.rend());

    const bool ignored = ax_object->IsIgnored();
    // if querying by name: skip if name of current object does not match.
    // For now, we need to handle names of ignored nodes separately, since they
    // do not get a name assigned when serializing to AXNodeData.
    if (ignored && query.accessible_name.has_value() &&
        query.accessible_name.value() != ax_object->ComputedName()) {
      continue;
    }
    if (!ignored && query.accessible_name.has_value() &&
        query.accessible_name.value().Utf8() !=
            node_data.GetStringAttribute(
                ax::mojom::blink::StringAttribute::kName)) {
      continue;
    }

    // if querying by role: skip if role of current object does not match.
    if (query.role.has_value() &&
        query.role.value() != AXObject::RoleName(node_data.role)) {
      continue;
    }

    // both name and role are OK, so we can add current object to the result.
    nodes->push_back(BuildProtocolAXNodeForAXObject(
        *ax_object, /* force_name_and_role */ true));
  }

  query.callback->sendSuccess(std::move(nodes));
}

void InspectorAccessibilityAgent::AXReadyCallback(Document& document) {
  ProcessPendingQueries(document);
  ProcessPendingDirtyNodes(document);
  if (load_complete_needs_processing_.Contains(&document) &&
      document.IsLoadCompleted()) {
    load_complete_needs_processing_.erase(&document);
    AXObjectCache* cache = document.ExistingAXObjectCache();
    CHECK(cache);
    AXObject* root = cache->Root();
    CHECK(root);
    dirty_nodes_.clear();
    nodes_requested_.clear();
    nodes_requested_.insert(root->AXObjectID());
    ScopedFreezeAXCache freeze(*cache);
    GetFrontend()->loadComplete(BuildProtocolAXNodeForAXObject(*root));
  }
}

void InspectorAccessibilityAgent::ProcessPendingQueries(Document& document) {
  auto it = queries_.find(&document);
  if (it == queries_.end())
    return;
  for (auto& query : it->value)
    CompleteQuery(query);
  queries_.erase(&document);
}

void InspectorAccessibilityAgent::ProcessPendingDirtyNodes(Document& document) {
  auto now = base::Time::Now();

  if (!last_sync_times_.Contains(&document))
    last_sync_times_.insert(&document, now);
  else if (now - last_sync_times_.at(&document) < kNodeSyncThrottlePeriod)
    return;
  else
    last_sync_times_.at(&document) = now;

  if (!dirty_nodes_.Contains(&document))
    return;
  // Sometimes, computing properties for an object while serializing will
  // mark other objects dirty. This makes us re-enter this function.
  // To make this benign, we use a copy of dirty_nodes_ when iterating.
  Member<HeapHashSet<WeakMember<AXObject>>> dirty_nodes =
      dirty_nodes_.Take(&document);
  auto nodes =
      std::make_unique<protocol::Array<protocol::Accessibility::AXNode>>();

  CHECK(document.ExistingAXObjectCache());
  ScopedFreezeAXCache freeze(*document.ExistingAXObjectCache());
  for (AXObject* changed_node : *dirty_nodes) {
    if (!changed_node->IsDetached())
      nodes->push_back(BuildProtocolAXNodeForAXObject(*changed_node));
  }
  GetFrontend()->nodesUpdated(std::move(nodes));
}

void InspectorAccessibilityAgent::ScheduleAXUpdateIfNeeded(TimerBase*,
                                                           Document* document) {
  DCHECK(document);

  if (!dirty_nodes_.Contains(document))
    return;

  // Scheduling an AX update for the cache will schedule it for both the main
  // document, and the popup document (if present).
  if (auto* cache = document->ExistingAXObjectCache()) {
    cache->ScheduleAXUpdate();
  }
}

void InspectorAccessibilityAgent::ScheduleAXChangeNotification(
    Document* document) {
  DCHECK(document);
  if (!timers_.Contains(document)) {
    timers_.insert(document,
                   MakeGarbageCollected<DisallowNewWrapper<DocumentTimer>>(
                       document, this,
                       &InspectorAccessibilityAgent::ScheduleAXUpdateIfNeeded));
  }
  DisallowNewWrapper<DocumentTimer>* timer = timers_.at(document);
  if (!timer->Value().IsActive())
    timer->Value().StartOneShot(kVisualUpdateCheckInterval, FROM_HERE);
}

void InspectorAccessibilityAgent::AXEventFired(AXObject* ax_object,
                                               ax::mojom::blink::Event event) {
  if (!enabled_.Get())
    return;
  DCHECK(ax_object->IsIncludedInTree());

  switch (event) {
    case ax::mojom::blink::Event::kLoadComplete: {
      // Will be handled in AXReadyCallback().
      load_complete_needs_processing_.insert(ax_object->GetDocument());
    } break;
    case ax::mojom::blink::Event::kLocationChanged:
      // Since we do not serialize location data we can ignore changes to this.
      break;
    default:
      MarkAXObjectDirty(ax_object);
      ScheduleAXChangeNotification(ax_object->GetDocument());
      break;
  }
}

bool InspectorAccessibilityAgent::MarkAXObjectDirty(AXObject* ax_object) {
  if (!nodes_requested_.Contains(ax_object->AXObjectID()))
    return false;
  Document* document = ax_object->GetDocument();
  auto inserted = dirty_nodes_.insert(document, nullptr);
  if (inserted.is_new_entry) {
    inserted.stored_value->value =
        MakeGarbageCollected<HeapHashSet<WeakMember<AXObject>>>();
  }
  return inserted.stored_value->value->insert(ax_object).is_new_entry;
}

void InspectorAccessibilityAgent::AXObjectModified(AXObject* ax_object,
                                                   bool subtree) {
  if (!enabled_.Get())
    return;
  DCHECK(ax_object->IsIncludedInTree());
  if (subtree) {
    HeapVector<Member<AXObject>> reachable;
    reachable.push_back(ax_object);
    while (!reachable.empty()) {
      AXObject* descendant = reachable.back();
      reachable.pop_back();
      DCHECK(descendant->IsIncludedInTree());
      if (!MarkAXObjectDirty(descendant))
        continue;
      const AXObject::AXObjectVector& children =
          descendant->ChildrenIncludingIgnored();
      reachable.AppendRange(children.rbegin(), children.rend());
    }
  } else {
    MarkAXObjectDirty(ax_object);
  }
  ScheduleAXChangeNotification(ax_object->GetDocument());
}

void InspectorAccessibilityAgent::EnableAndReset() {
  enabled_.Set(true);
  LocalFrame* frame = inspected_frames_->Root();
  if (!EnabledAgents().Contains(frame)) {
    EnabledAgents().Set(
        frame, MakeGarbageCollected<
                   HeapHashSet<Member<InspectorAccessibilityAgent>>>());
  }
  EnabledAgents().find(frame)->value->insert(this);
  for (auto& context : document_to_context_map_.Values()) {
    auto& cache = To<AXObjectCacheImpl>(context->GetAXObjectCache());
    cache.AddInspectorAgent(this);
  }
}

protocol::Response InspectorAccessibilityAgent::enable() {
  if (!enabled_.Get())
    EnableAndReset();
  return protocol::Response::Success();
}

protocol::Response InspectorAccessibilityAgent::disable() {
  if (!enabled_.Get())
    return protocol::Response::Success();
  enabled_.Set(false);
  for (auto& document : document_to_context_map_.Keys()) {
    DCHECK(document);
    // We do not rely on AXContext::GetAXObjectCache here, since it might
    // dereference nullptrs and requires several preconditions to be checked.
    // Instead, we remove the agent from any document that has an existing
    // AXObjectCache.
    AXObjectCache* existing_cache = document->ExistingAXObjectCache();
    if (!existing_cache) {
      continue;
    }
    auto& cache = To<AXObjectCacheImpl>(*existing_cache);
    cache.RemoveInspectorAgent(this);
  }
  document_to_context_map_.clear();
  nodes_requested_.clear();
  dirty_nodes_.clear();
  LocalFrame* frame = inspected_frames_->Root();
  DCHECK(EnabledAgents().Contains(frame));
  auto it = EnabledAgents().find(frame);
  it->value->erase(this);
  if (it->value->empty())
    EnabledAgents().erase(frame);
  return protocol::Response::Success();
}

void InspectorAccessibilityAgent::Restore() {
  if (enabled_.Get())
    EnableAndReset();
}

void InspectorAccessibilityAgent::ProvideTo(LocalFrame* frame) {
  if (!EnabledAgents().Contains(frame))
    return;
  for (InspectorAccessibilityAgent* agent :
       *EnabledAgents().find(frame)->value) {
    agent->AttachToAXObjectCache(frame->GetDocument());
  }
}

AXObjectCacheImpl& InspectorAccessibilityAgent::AttachToAXObjectCache(
    Document* document) {
  DCHECK(document);
  DCHECK(document->IsActive());
  if (!document_to_context_map_.Contains(document)) {
    auto context = std::make_unique<AXContext>(*document, ui::kAXModeComplete);
    document_to_context_map_.insert(document, std::move(context));
  }
  AXObjectCacheImpl* cache =
      To<AXObjectCacheImpl>(document->ExistingAXObjectCache());
  cache->AddInspectorAgent(this);
  return *cache;
}

void InspectorAccessibilityAgent::Trace(Visitor* visitor) const {
  visitor->Trace(inspected_frames_);
  visitor->Trace(dom_agent_);
  visitor->Trace(document_to_context_map_);
  visitor->Trace(dirty_nodes_);
  visitor->Trace(timers_);
  visitor->Trace(queries_);
  visitor->Trace(last_sync_times_);
  visitor->Trace(load_complete_needs_processing_);
  InspectorBaseAgent::Trace(visitor);
}

}  // namespace blink

"""


```