Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its functionality, its relationship to web technologies, and potential usage scenarios.

**1. Initial Understanding - The Big Picture:**

* **File Location:** The path `blink/renderer/modules/accessibility/blink_ax_tree_source.cc` immediately suggests this code is part of Blink (the rendering engine of Chromium) and deals with accessibility. The "AX" likely stands for Accessibility. The "Tree Source" part hints at the code's role in providing a structured representation of the web page for accessibility purposes.

* **Includes:**  Scanning the `#include` directives provides further clues:
    *  `third_party/blink/renderer/core/...`:  Indicates interaction with core Blink components like frames, HTML elements, and the DOM structure.
    *  `third_party/blink/renderer/modules/accessibility/...`:  Shows connections to other accessibility-related modules within Blink.
    *  `ui/accessibility/...`:  Points to platform-agnostic accessibility interfaces, likely from the Chromium "ui" layer.
    *  Standard C++ headers (`<stddef.h>`, `"base/containers/contains.h"`, etc.): Show general utility and data structures.

* **Namespace:** The code is within the `blink` namespace, confirming its place within the Blink engine.

* **Class Name:** `BlinkAXTreeSource` is the central class. The name suggests it's the source of the accessibility tree information within Blink.

**2. Deeper Dive - Core Functionality and Methods:**

* **Constructor and Destructor:**  The constructor takes an `AXObjectCacheImpl` and a boolean `is_snapshot`. This suggests the class works with a cache of accessibility objects and can represent either a live or a static ("snapshot") view of the accessibility tree.

* **`Selection()`:** This method clearly deals with retrieving the current text selection information: anchor node, focus node, offsets, and affinities. This is crucial for screen readers and other assistive technologies to understand what the user has selected.

* **`GetTreeData()`:** This is a key function. It populates a `ui::AXTreeData` structure with information about the entire accessibility tree: doctype, loading status, MIME type, title, URL, focus, and crucially, selection details. The inclusion of metadata extraction (script tags with `application/ld+json`, link, title, and meta elements) highlights the semantic information it captures. The call to `GetAXTreeID` shows it handles embedded frames.

* **`Freeze()` and `Thaw()`:** These methods likely control the state of the `BlinkAXTreeSource`. `Freeze()` seems to take a snapshot of the current accessibility tree by caching the root and focused elements. `Thaw()` reverses this. This is a common pattern to ensure consistency when traversing the tree.

* **Tree Traversal Methods (`GetRoot()`, `GetFocusedObject()`, `GetFromId()`, `GetId()`, `GetChildCount()`, `ChildAt()`, `GetParent()`):** These methods provide the interface for navigating the accessibility tree structure. They are fundamental for any accessibility tool that needs to understand the hierarchy of elements on the page.

* **`IsIgnored()`:** Determines if an element is ignored for accessibility purposes.

* **`IsEqual()`:**  A simple equality check for AXObjects.

* **`GetNull()`:** Returns a null pointer.

* **`GetDebugString()`:**  Provides a human-readable representation of an AXObject, useful for debugging.

* **`SerializeNode()`:**  This is the core of the data extraction. It calls the `Serialize()` method of an `AXObject` to populate a `ui::AXNodeData` structure. The `DocumentLifecycle::DisallowTransitionScope` is a safety mechanism to prevent unwanted side effects during serialization.

* **`Trace()`:** Used for Blink's garbage collection and tracing infrastructure.

**3. Relating to Web Technologies (JavaScript, HTML, CSS):**

* **HTML:** The code directly interacts with HTML elements (`HTMLHeadElement`, `HTMLLinkElement`, `HTMLMetaElement`, etc.). The `GetTreeData()` function extracts information like the document title, URL, and metadata from HTML elements. The accessibility tree itself is a representation of the HTML DOM.

* **CSS:** While not explicitly manipulating CSS properties, the accessibility tree *is* influenced by CSS. For example, `display: none` or `visibility: hidden` can cause elements to be ignored for accessibility. The layout and rendering influenced by CSS determine how the accessibility tree is structured (e.g., the order of elements). The code indirectly reflects CSS influence through the structure and properties of the `AXObject`s.

* **JavaScript:** JavaScript can dynamically modify the DOM, which in turn triggers updates to the accessibility tree. When JavaScript adds, removes, or changes elements, the `AXObjectCacheImpl` (passed to the `BlinkAXTreeSource`) will be notified, and the accessibility tree will be updated. The selection information retrieved by `Selection()` might reflect a selection made by JavaScript.

**4. Logical Reasoning (Hypothetical Input and Output):**

Imagine a simple HTML snippet:

```html
<!DOCTYPE html>
<html>
<head>
  <title>My Webpage</title>
  <meta name="description" content="A simple webpage">
</head>
<body>
  <h1>Hello World</h1>
  <p>This is some text.</p>
  <a href="#">A link</a>
</body>
</html>
```

* **Input to `GetTreeData()`:** When called for this page, the `BlinkAXTreeSource` would traverse the DOM and populate the `ui::AXTreeData`.

* **Hypothetical Output of `GetTreeData()` (partial):**
    * `tree_data->doctype = "html";`
    * `tree_data->loaded = true;` (assuming the page is loaded)
    * `tree_data->title = "My Webpage";`
    * `tree_data->url = "the URL of the page";`
    * `tree_data->metadata` would contain strings like `<title>My Webpage</title>` and `<meta name="description" content="A simple webpage">`.
    * The structure of the tree would reflect the HTML hierarchy (document -> html -> head/body -> h1, p, a, etc.). Each element would be represented by an `AXObject`.

* **Input to `Selection()`:** If the user selects "some text" with the mouse.

* **Hypothetical Output of `Selection()`:**
    * `*anchor_object` would point to the `AXObject` representing the `<p>` element.
    * `anchor_offset` would be the starting character index of "some" within the text content.
    * `*focus_object` would also point to the `AXObject` representing the `<p>` element.
    * `focus_offset` would be the ending character index of "text".

**5. User and Programming Errors:**

* **User Errors:**  A common user error that leads to accessibility issues is creating content that is not semantically meaningful or lacks proper ARIA attributes. This can result in an incorrect or incomplete accessibility tree, making it difficult for assistive technologies to interpret the page. While this code doesn't *directly* cause these errors, it *reflects* them.

* **Programming Errors (Blink Developers):**
    * **Incorrectly determining if an element should be ignored:**  If the logic in `IsIgnored()` is flawed, elements might be incorrectly excluded from the accessibility tree.
    * **Errors in building the `AXObject` hierarchy:**  Mistakes in the `AXObjectCacheImpl` or the logic that creates `AXObject`s could lead to an incorrect tree structure. The `CHECK` statements in `ChildAt()` are a safeguard against such errors.
    * **Serialization issues:** Bugs in the `Serialize()` methods of `AXObject`s could lead to incomplete or incorrect data being passed to the browser process.

**6. User Operation to Reach This Code (Debugging Clues):**

1. **User interacts with the webpage:**  This could involve:
    * **Loading a page:**  The accessibility tree needs to be built when a page loads.
    * **Navigating with the keyboard (Tab key):** This changes the focus, which is tracked by the accessibility system.
    * **Selecting text with the mouse or keyboard:** This triggers the `Selection()` logic.
    * **Interacting with form controls:**  Accessibility information is needed for these elements.
    * **Dynamic content updates (JavaScript):**  Changes to the DOM require updates to the accessibility tree.

2. **Accessibility software is active:** When a screen reader, switch control, or other assistive technology is running, it requests accessibility information from the browser.

3. **The browser (Chromium) requests the accessibility tree:**  The browser process uses the accessibility APIs to get a representation of the page's structure and content.

4. **Blink's accessibility system is invoked:** The browser process's request reaches Blink's accessibility components.

5. **`BlinkAXTreeSource` is used to build the tree:**  The `AXObjectCacheImpl` and the `BlinkAXTreeSource` work together to create the accessibility tree data that will be sent to the browser process.

**In Summary:** The code acts as a crucial bridge between the internal representation of a web page in Blink and the accessibility APIs used by assistive technologies. It's responsible for providing a structured, semantic view of the page that is essential for users with disabilities. Understanding its functions and how they relate to web technologies is key to debugging accessibility issues in Chromium.
`blink_ax_tree_source.cc` 文件是 Chromium Blink 渲染引擎中负责构建和提供 **无障碍树 (Accessibility Tree)** 数据的核心组件。它的主要功能是将 Blink 内部的 DOM 结构和相关信息转换成一个符合无障碍规范的树状结构，供操作系统和辅助技术（如屏幕阅读器）使用。

以下是该文件的详细功能列表和相关说明：

**主要功能:**

1. **作为无障碍树的数据源 (Data Source for Accessibility Tree):**  `BlinkAXTreeSource` 实现了 `ui::AXTreeSource` 接口，负责提供构建无障碍树所需的节点信息和树结构。这意味着它知道如何从 Blink 的内部表示（主要是 `AXObject`）中提取数据，并将其组织成树形结构。

2. **管理和提供根节点 (Root Node):**  它维护着无障碍树的根节点 (`root_`)，通常对应于文档的 `<html>` 元素。

3. **管理和提供焦点节点 (Focused Node):**  它跟踪当前获得焦点的无障碍对象 (`focus_`)。

4. **提供节点间的父子关系 (Parent-Child Relationships):**  通过 `GetChildCount` 和 `ChildAt` 方法，它能够告知给定节点的子节点数量和指定索引的子节点。`GetParent` 方法则返回节点的父节点。

5. **提供节点属性信息 (Node Attributes):**  `SerializeNode` 方法负责将 Blink 内部的 `AXObject` 的属性信息序列化到 `ui::AXNodeData` 结构中。这些属性包括节点的角色、名称、值、状态等等，这些信息对于辅助技术理解页面内容至关重要。

6. **处理文本选择 (Text Selection):** `Selection` 方法负责获取当前页面的文本选择信息，包括锚点和焦点的对象、偏移量和文本方向性 (affinity)。

7. **提供文档级别的元数据 (Document-Level Metadata):** `GetTreeData` 方法负责填充 `ui::AXTreeData` 结构，其中包含了关于整个文档的信息，例如文档类型、加载状态、MIME 类型、标题、URL，以及重要的元数据信息，如 `<title>`, `<meta>`, `<link>`, `<script type="application/ld+json">` 标签的内容。

8. **管理树的冻结和解冻 (Freeze and Thaw):** `Freeze` 方法在开始构建无障碍树之前被调用，用于捕获当前树的状态（根节点、焦点节点），确保在构建过程中状态不会改变。`Thaw` 方法在构建完成后被调用，释放捕获的状态。

9. **判断节点是否被忽略 (Is Ignored):**  `IsIgnored` 方法判断一个给定的 `AXObject` 是否应该被包含在无障碍树中。某些装饰性的或不重要的元素可能会被忽略。

10. **提供调试信息 (Debug String):** `GetDebugString` 方法返回一个 `AXObject` 的字符串表示，用于调试目的。

**与 JavaScript, HTML, CSS 的关系 (并举例说明):**

* **HTML:**
    * **功能关系:**  `BlinkAXTreeSource` 的核心任务是将 HTML 结构转化为无障碍树。它遍历 HTML 元素，并为每个相关的元素创建对应的 `AXObject`，最终构成无障碍树的节点。
    * **举例:**  当 HTML 中存在一个 `<button>` 元素时，`BlinkAXTreeSource` 会创建一个角色为 `kButton` 的 `AXObject`，并将其包含在无障碍树中。按钮的文本内容会作为该 `AXObject` 的名称属性。
    * **代码关联:**  `GetTreeData` 中会提取 `<title>` 标签的内容作为树的标题 (`tree_data->title`)，并提取 `<meta>`、`<link>` 等标签的内容作为元数据 (`tree_data->metadata`)。

* **CSS:**
    * **功能关系:** CSS 的渲染效果会影响无障碍树的构建。例如，`display: none` 或 `visibility: hidden` 样式的元素通常会被 `BlinkAXTreeSource` 标记为忽略，不会出现在无障碍树中。CSS 的视觉层叠和布局也会影响无障碍对象的层级关系和一些属性的计算。
    * **举例:**  如果一个 `<div>` 元素通过 CSS 设置了 `role="button"`，`BlinkAXTreeSource` 可能会将其识别为一个按钮角色，即使它在 HTML 中不是一个原生的 `<button>` 元素。
    * **代码关联:**  虽然 `BlinkAXTreeSource` 本身不直接解析 CSS，但它依赖于 Blink 渲染引擎提供的 `AXObject` 信息，这些 `AXObject` 的属性（如是否被忽略）已经考虑了 CSS 的影响。

* **JavaScript:**
    * **功能关系:** JavaScript 可以动态地修改 DOM 结构，这些修改会触发 `BlinkAXTreeSource` 重新构建或更新无障碍树。当 JavaScript 添加、删除或修改 DOM 元素时，无障碍树也需要同步更新，以反映最新的页面结构。
    * **举例:**  当 JavaScript 代码通过 `document.createElement()` 创建一个新的 `<div>` 元素并添加到 DOM 中时，`BlinkAXTreeSource` 会感知到这个变化，并为新的 `<div>` 创建一个 `AXObject` 并将其插入到无障碍树的相应位置。
    * **代码关联:**  `Selection` 方法中会调用 `AXSelection::FromCurrentSelection`，这会考虑用户通过 JavaScript 或原生浏览器操作产生的文本选择。

**逻辑推理 (假设输入与输出):**

假设输入以下简单的 HTML 片段：

```html
<!DOCTYPE html>
<html>
<head>
  <title>Example Page</title>
</head>
<body>
  <h1>Welcome</h1>
  <p>This is some text.</p>
  <a href="#">Click me</a>
</body>
</html>
```

当 `BlinkAXTreeSource` 为这个 HTML 构建无障碍树时，预期的一些输出：

* **`GetRoot()` 输出:** 指向代表 `<html>` 元素的 `AXObject`。
* **`GetChildCount(root_)` 输出:**  通常是 2，分别代表 `<head>` 和 `<body>` 的 `AXObject`。
* **`ChildAt(root_, 1)` 输出:** 指向代表 `<body>` 元素的 `AXObject`。
* **`GetChildCount(body_object)` 输出:** 通常是 3，分别代表 `<h1>`, `<p>`, `<a>` 的 `AXObject`。
* **`SerializeNode(h1_object, &node_data)` 输出 (部分):**
    * `node_data.role = ax::mojom::blink::Role::kHeading;`
    * `node_data.name = "Welcome";`
    * `node_data.child_ids` 会包含代表 "Welcome" 文本节点的 ID。
* **`GetTreeData(&tree_data)` 输出 (部分):**
    * `tree_data.title = "Example Page";`
    * `tree_data.url` 会是当前页面的 URL。

**用户或编程常见的使用错误 (并举例说明):**

* **用户错误 (开发者角度):**
    * **缺乏语义化的 HTML 结构:**  使用 `<div>` 和 `<span>` 标签来代替具有语义的 HTML5 标签（如 `<article>`, `<nav>`, `<aside>`），会导致 `BlinkAXTreeSource` 无法准确推断元素的角色和含义，从而影响辅助技术对内容的理解。
    * **ARIA 属性使用不当:** 错误地使用 ARIA 属性，例如赋予了错误的 `role` 或提供了不准确的 `aria-label`，会导致生成的无障碍树信息错误。
    * **动态内容更新后未及时更新 ARIA 属性:** 如果 JavaScript 动态修改了页面内容，但没有相应地更新相关的 ARIA 属性，会导致无障碍树信息过时。

* **编程错误 (Blink 引擎开发角度):**
    * **在 `SerializeNode` 中遗漏了重要的属性:** 如果在 `AXObject::Serialize` 方法中没有正确地将某些重要的属性序列化到 `ui::AXNodeData` 中，会导致这些信息无法传递给辅助技术。
    * **父子关系计算错误:** 如果 `GetChildCount` 或 `ChildAt` 方法的逻辑有误，会导致无障碍树的结构不正确。
    * **忽略了某些需要包含在无障碍树中的元素:** 如果 `IsIgnored` 方法的判断逻辑有问题，可能会错误地将某些重要的元素排除在无障碍树之外。

**用户操作如何一步步到达这里 (作为调试线索):**

当用户与网页进行交互，并且有辅助技术（如屏幕阅读器）运行时，以下步骤可能会触发 `BlinkAXTreeSource` 的工作：

1. **用户加载网页:** 当浏览器加载网页时，Blink 渲染引擎会解析 HTML、CSS 和 JavaScript，构建 DOM 树和渲染树。
2. **辅助技术请求无障碍信息:** 屏幕阅读器等辅助技术会通过操作系统提供的无障碍 API 向浏览器请求当前页面的无障碍信息。
3. **浏览器进程向渲染进程请求无障碍树:** 浏览器进程接收到辅助技术的请求后，会向渲染进程（运行 Blink 的进程）发送请求，要求提供当前页面的无障碍树数据。
4. **Blink 渲染引擎构建无障碍树:**
   * Blink 的无障碍管理器会协调无障碍树的构建。
   * `BlinkAXTreeSource` 的实例会被创建或复用。
   * `Freeze()` 方法会被调用，用于捕获当前状态。
   * `GetRoot()` 方法会被调用以获取根节点。
   * `GetChildCount()` 和 `ChildAt()` 方法会被递归调用，遍历 DOM 结构，构建树的层级关系。
   * 对于每个需要包含在无障碍树中的 `AXObject`，`SerializeNode()` 方法会被调用，将其属性信息填充到 `ui::AXNodeData` 中。
   * `GetTreeData()` 方法会被调用，收集文档级别的元数据。
   * `Thaw()` 方法会被调用，释放捕获的状态。
5. **无障碍树数据传递给浏览器进程:** 构建好的无障碍树数据会被传递回浏览器进程。
6. **浏览器进程将数据传递给辅助技术:** 浏览器进程将接收到的无障碍树数据通过操作系统的无障碍 API 提供给屏幕阅读器等辅助技术。
7. **用户与页面交互 (例如，tab 键切换焦点):**  当用户通过键盘或鼠标与页面交互时，可能会触发焦点变化。
8. **焦点变化导致无障碍树更新:**  焦点变化会通知 Blink 的无障碍管理器，`BlinkAXTreeSource` 会更新焦点节点的信息，并通过无障碍 API 将焦点变化事件通知给辅助技术。`Selection()` 方法也会在文本选择发生变化时被调用。

**调试线索:**

如果在调试无障碍相关的问题时，例如屏幕阅读器无法正确读取页面内容或焦点顺序不正确，可以考虑以下调试线索：

* **检查 `BlinkAXTreeSource` 中的 `SerializeNode` 方法:** 确认关键的属性是否被正确地序列化。
* **检查 `IsIgnored` 方法的逻辑:**  确认是否有元素被错误地忽略。
* **查看 `GetChildCount` 和 `ChildAt` 方法的实现:**  确保父子关系的计算是正确的。
* **断点调试 `GetTreeData` 方法:**  查看文档级别的元数据是否正确。
* **跟踪用户交互流程:** 了解用户操作的步骤，以及这些操作如何触发无障碍树的更新。
* **使用 Chromium 提供的无障碍检查工具:**  例如，chrome://inspect/#accessibility 可以查看当前页面的无障碍树结构，对比实际的 DOM 结构和预期的无障碍树结构。

总而言之，`blink_ax_tree_source.cc` 文件在 Blink 渲染引擎的无障碍支持中扮演着至关重要的角色，它负责将网页的内部表示转化为辅助技术可以理解的形式，从而帮助残障人士更好地访问和使用互联网。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/blink_ax_tree_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/accessibility/blink_ax_tree_source.h"

#include <stddef.h>

#include "base/containers/contains.h"
#include "base/memory/ptr_util.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_link_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_selection.h"
#include "ui/accessibility/ax_role_properties.h"
#include "ui/accessibility/ax_tree_id.h"

namespace blink {

BlinkAXTreeSource::BlinkAXTreeSource(AXObjectCacheImpl& ax_object_cache,
                                     bool is_snapshot)
    : ax_object_cache_(ax_object_cache), is_snapshot_(is_snapshot) {}

BlinkAXTreeSource::~BlinkAXTreeSource() = default;

static ax::mojom::blink::TextAffinity ToAXAffinity(TextAffinity affinity) {
  switch (affinity) {
    case TextAffinity::kUpstream:
      return ax::mojom::blink::TextAffinity::kUpstream;
    case TextAffinity::kDownstream:
      return ax::mojom::blink::TextAffinity::kDownstream;
    default:
      NOTREACHED();
  }
}

void BlinkAXTreeSource::Selection(
    const AXObject* obj,
    bool& is_selection_backward,
    const AXObject** anchor_object,
    int& anchor_offset,
    ax::mojom::blink::TextAffinity& anchor_affinity,
    const AXObject** focus_object,
    int& focus_offset,
    ax::mojom::blink::TextAffinity& focus_affinity) const {
  is_selection_backward = false;
  *anchor_object = nullptr;
  anchor_offset = -1;
  anchor_affinity = ax::mojom::blink::TextAffinity::kDownstream;
  *focus_object = nullptr;
  focus_offset = -1;
  focus_affinity = ax::mojom::blink::TextAffinity::kDownstream;

  if (!obj || obj->IsDetached())
    return;

  const AXObject* focus = GetFocusedObject();
  if (!focus || focus->IsDetached())
    return;

  const auto ax_selection =
      focus->IsAtomicTextField()
          ? AXSelection::FromCurrentSelection(ToTextControl(*focus->GetNode()))
          : AXSelection::FromCurrentSelection(*focus->GetDocument());
  if (!ax_selection)
    return;

  const AXPosition base = ax_selection.Anchor();
  *anchor_object = base.ContainerObject();
  const AXPosition extent = ax_selection.Focus();
  *focus_object = extent.ContainerObject();

  is_selection_backward = base > extent;
  if (base.IsTextPosition()) {
    anchor_offset = base.TextOffset();
    anchor_affinity = ToAXAffinity(base.Affinity());
  } else {
    anchor_offset = base.ChildIndex();
  }

  if (extent.IsTextPosition()) {
    focus_offset = extent.TextOffset();
    focus_affinity = ToAXAffinity(extent.Affinity());
  } else {
    focus_offset = extent.ChildIndex();
  }
}

static ui::AXTreeID GetAXTreeID(LocalFrame* local_frame) {
  const std::optional<base::UnguessableToken>& embedding_token =
      local_frame->GetEmbeddingToken();
  if (embedding_token && !embedding_token->is_empty())
    return ui::AXTreeID::FromToken(embedding_token.value());
  return ui::AXTreeIDUnknown();
}

bool BlinkAXTreeSource::GetTreeData(ui::AXTreeData* tree_data) const {
  CHECK(frozen_);
  const AXObject* root = GetRoot();
  tree_data->doctype = "html";
  tree_data->loaded = root->IsLoaded();
  tree_data->loading_progress = root->EstimatedLoadingProgress();
  const Document& document = ax_object_cache_->GetDocument();
  tree_data->mimetype = document.IsXHTMLDocument() ? "text/xhtml" : "text/html";
  tree_data->title = document.title().Utf8();
  tree_data->url = document.Url().GetString().Utf8();

  if (const AXObject* focus = GetFocusedObject())
    tree_data->focus_id = focus->AXObjectID();

  bool is_selection_backward = false;
  const AXObject *anchor_object, *focus_object;
  int anchor_offset, focus_offset;
  ax::mojom::blink::TextAffinity anchor_affinity, focus_affinity;
  Selection(root, is_selection_backward, &anchor_object, anchor_offset,
            anchor_affinity, &focus_object, focus_offset, focus_affinity);
  if (anchor_object && focus_object && anchor_offset >= 0 &&
      focus_offset >= 0) {
    int32_t anchor_id = anchor_object->AXObjectID();
    int32_t focus_id = focus_object->AXObjectID();
    tree_data->sel_is_backward = is_selection_backward;
    tree_data->sel_anchor_object_id = anchor_id;
    tree_data->sel_anchor_offset = anchor_offset;
    tree_data->sel_focus_object_id = focus_id;
    tree_data->sel_focus_offset = focus_offset;
    tree_data->sel_anchor_affinity = anchor_affinity;
    tree_data->sel_focus_affinity = focus_affinity;
  }

  // Get the tree ID for this frame.
  if (LocalFrame* local_frame = document.GetFrame())
    tree_data->tree_id = GetAXTreeID(local_frame);

  if (auto* root_scroller = root->RootScroller())
    tree_data->root_scroller_id = root_scroller->AXObjectID();
  else
    tree_data->root_scroller_id = 0;

  if (ax_object_cache_->GetAXMode().has_mode(ui::AXMode::kHTMLMetadata)) {
    if (HTMLHeadElement* head = ax_object_cache_->GetDocument().head()) {
      for (Node* child = head->firstChild(); child;
           child = child->nextSibling()) {
        const Element* elem = DynamicTo<Element>(*child);
        if (!elem) {
          continue;
        }
        if (IsA<HTMLScriptElement>(*elem)) {
          if (elem->getAttribute(html_names::kTypeAttr) !=
              "application/ld+json") {
            continue;
          }
        } else if (!IsA<HTMLLinkElement>(*elem) &&
                   !IsA<HTMLTitleElement>(*elem) &&
                   !IsA<HTMLMetaElement>(*elem)) {
          continue;
        }
        // TODO(chrishtr): replace the below with elem->outerHTML().
        String tag = elem->tagName().LowerASCII();
        String html = "<" + tag;
        for (unsigned i = 0; i < elem->Attributes().size(); i++) {
          html = html + String(" ") + elem->Attributes().at(i).LocalName() +
                 String("=\"") + elem->Attributes().at(i).Value() + "\"";
        }
        html = html + String(">") + elem->innerHTML() + String("</") + tag +
               String(">");
        tree_data->metadata.push_back(html.Utf8());
      }
    }
  }

  return true;
}

void BlinkAXTreeSource::Freeze() {
  CHECK(!frozen_);
  frozen_ = true;

  // The root cannot be null.
  root_ = ax_object_cache_->Root();
  CHECK(root_);
  focus_ = ax_object_cache_->FocusedObject();
  CHECK(focus_);
}

void BlinkAXTreeSource::Thaw() {
  CHECK(frozen_);
  frozen_ = false;
  root_ = nullptr;
  focus_ = nullptr;
}

const AXObject* BlinkAXTreeSource::GetRoot() const {
  CHECK(frozen_);
  CHECK(root_);
  return root_;
}

const AXObject* BlinkAXTreeSource::GetFocusedObject() const {
  CHECK(frozen_);
  CHECK(focus_);
  return focus_;
}

const AXObject* BlinkAXTreeSource::GetFromId(int32_t id) const {
  const AXObject* result = ax_object_cache_->ObjectFromAXID(id);
  if (result && !result->IsIncludedInTree()) {
    DCHECK(false) << "Should not serialize an unincluded object:" << "\nChild: "
                  << result->ToString().Utf8();
    return nullptr;
  }
  return result;
}

int32_t BlinkAXTreeSource::GetId(const AXObject* node) const {
  return node->AXObjectID();
}

size_t BlinkAXTreeSource::GetChildCount(const AXObject* node) const {
  if (ShouldTruncateInlineTextBoxes() &&
      ui::CanHaveInlineTextBoxChildren(node->RoleValue())) {
    return 0;
  }
  return node->ChildCountIncludingIgnored();
}

AXObject* BlinkAXTreeSource::ChildAt(const AXObject* node, size_t index) const {
  if (ShouldTruncateInlineTextBoxes()) {
    CHECK(!ui::CanHaveInlineTextBoxChildren(node->RoleValue()));
  }
  auto* child = node->ChildAtIncludingIgnored(static_cast<int>(index));

  // The child may be invalid due to issues in blink accessibility code.
  CHECK(child);
  if (child->IsDetached()) {
    NOTREACHED(base::NotFatalUntil::M127)
        << "Should not try to serialize an invalid child:" << "\nParent: "
        << node->ToString().Utf8() << "\nChild: " << child->ToString().Utf8();
    return nullptr;
  }

  if (!child->IsIncludedInTree()) {
    NOTREACHED(base::NotFatalUntil::M127)
        << "Should not receive unincluded child."
        << "\nChild: " << child->ToString().Utf8()
        << "\nParent: " << node->ToString().Utf8();
    return nullptr;
  }

  // These should not be produced by Blink. They are only needed on Mac and
  // handled in AXTableInfo on the browser side.
  DCHECK_NE(child->RoleValue(), ax::mojom::blink::Role::kColumn);
  DCHECK_NE(child->RoleValue(), ax::mojom::blink::Role::kTableHeaderContainer);
  DCHECK(child->ParentObjectIncludedInTree() == node)
      << "Child thinks it has a different preexisting parent:"
      << "\nChild: " << child << "\nPassed-in parent: " << node
      << "\nPreexisting parent: " << child->ParentObjectIncludedInTree();

  return child;
}

AXObject* BlinkAXTreeSource::GetParent(const AXObject* node) const {
  return node->ParentObjectIncludedInTree();
}

bool BlinkAXTreeSource::IsIgnored(const AXObject* node) const {
  if (!node || node->IsDetached())
    return false;
  return node->IsIgnored();
}

bool BlinkAXTreeSource::IsEqual(const AXObject* node1, const AXObject* node2) const {
  return node1 == node2;
}

AXObject* BlinkAXTreeSource::GetNull() const {
  return nullptr;
}

std::string BlinkAXTreeSource::GetDebugString(const AXObject* node) const {
  if (!node || node->IsDetached())
    return "";
  return node->ToString().Utf8();
}

void BlinkAXTreeSource::SerializeNode(const AXObject* src,
                                      ui::AXNodeData* dst) const {
#if DCHECK_IS_ON()
  // Never causes a document lifecycle change during serialization,
  // because the assumption is that layout is in a safe, stable state.
  DocumentLifecycle::DisallowTransitionScope disallow(
      ax_object_cache_->GetDocument().Lifecycle());
#endif

  if (!src || src->IsDetached() || !src->IsIncludedInTree()) {
    NOTREACHED();
  }

  src->Serialize(dst, ax_object_cache_->GetAXMode(), is_snapshot_);
}

void BlinkAXTreeSource::Trace(Visitor* visitor) const {
  visitor->Trace(ax_object_cache_);
  visitor->Trace(root_);
  visitor->Trace(focus_);
}

}  // namespace blink
```