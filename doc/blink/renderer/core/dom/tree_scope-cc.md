Response:
Let's break down the thought process for analyzing the `tree_scope.cc` file and generating the detailed response.

**1. Initial Understanding and Goal:**

The request asks for a comprehensive analysis of `tree_scope.cc`. The key elements to identify are its functionalities, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning within the code, common user/programming errors related to it, and debugging strategies. Essentially, we need to understand what this file *does* within the Blink rendering engine.

**2. High-Level Overview of `TreeScope`:**

The name "TreeScope" strongly suggests a concept related to hierarchical structures, likely the DOM tree. The included headers (`#include`) offer immediate clues:

* `dom/document.h`, `dom/element.h`, `dom/node.h`: Core DOM building blocks.
* `css/...`: Indicates involvement with CSS styling.
* `html/...`: Shows interaction with HTML elements.
* `frame/...`: Points to the concept of frames and iframes.
* `svg/...`: Suggests support for SVG.

This initial scan suggests `TreeScope` manages a portion of the DOM tree and is involved in styling, element lookup, and potentially frame interactions.

**3. Deeper Dive into the Code - Identifying Key Functionalities:**

The next step is to systematically go through the code, focusing on public methods and data members. For each identified element, ask "What does this do?" and "Why is this needed?".

* **Constructors and Destructor:**  How is a `TreeScope` created and destroyed? The constructors reveal it's associated with either a `Document` or a `ContainerNode` (like a `ShadowRoot`).
* **`IsInclusiveAncestorTreeScopeOf`:**  Clearly related to the hierarchical nature of `TreeScope`s.
* **`SetParentTreeScope`:**  Shows the ability to move a `TreeScope` within the hierarchy (important for Shadow DOM).
* **`EnsureScopedStyleResolver` and `ClearScopedStyleResolver`:** Directly linked to CSS styling within this scope.
* **`getElementById`, `GetAllElementsById`, `AddElementById`, `RemoveElementById`:**  Mechanisms for efficient element lookup based on IDs, a fundamental HTML concept.
* **`AddImageMap`, `RemoveImageMap`, `GetImageMap`:**  Handles image map functionality in HTML.
* **`ElementFromPoint`, `HitTestPoint`, `ElementsFromPoint`:**  Essential for event handling and determining what's under the mouse cursor. This directly relates to user interaction.
* **`EnsureSVGTreeScopedResources`:** Indicates specialized handling for SVG.
* **`EnsureAdoptedStyleSheets`, related methods:**  A modern CSS feature allowing programmatic addition of stylesheets.
* **`GetSelection`:** Manages the current text selection within the scope.
* **`FindAnchorWithName`, `FindAnchor`:**  Deals with finding elements based on their `name` or the URL fragment, crucial for navigation.
* **`AdoptIfNeeded`:**  Manages moving nodes between `TreeScope`s, core to Shadow DOM.
* **`Retarget`:** A key Shadow DOM concept for event delivery.
* **`AdjustedFocusedElement`, `AdjustedElement`:**  Needed to correctly identify the focused element in the context of Shadow DOM.
* **`StyleSheets`:** Provides access to the stylesheets associated with the scope.
* **`activeElement`, `getAnimations`, `pointerLockElement`, `fullscreenElement`, `pictureInPictureElement`:**  Provide access to various global properties within the scope.
* **`ComparePosition`, `CommonAncestorTreeScope`:** Methods for comparing the relative positions of `TreeScope`s.
* **`GetElementByAccessKey`:**  Handles access keys for keyboard navigation.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

As each functionality is identified, consider its direct relationship to web technologies:

* **HTML:** `getElementById`, `image maps`, `anchor tags`, `accesskey`, the concept of the DOM tree itself.
* **CSS:** `ScopedStyleResolver`, `adoptedStyleSheets`, styling rules applied within a specific scope.
* **JavaScript:**  Many of these functionalities are exposed to JavaScript through the DOM API. For example, `document.getElementById()`, `elementFromPoint()`, accessing `document.styleSheets`, and the Shadow DOM API.

**5. Logical Reasoning and Examples:**

For more complex functionalities like `Retarget` or `AdjustedFocusedElement`, it's helpful to think through scenarios:

* **`Retarget`:** Imagine a click event inside a shadow DOM. How does the browser determine which element in the main document should receive the event? This is where `Retarget` comes in. Develop a simple example with nested shadow DOMs to illustrate the process.
* **`AdjustedFocusedElement`:**  Consider a scenario where an element inside a shadow DOM has focus. How does the browser report the `document.activeElement` in the main document's context?  This is what `AdjustedFocusedElement` handles.

**6. Identifying Potential Errors:**

Think about how developers might misuse these features or encounter unexpected behavior:

* **ID Collisions:**  Adding the same ID to multiple elements within the same `TreeScope`.
* **Incorrect `AdoptIfNeeded` Usage:** Trying to move nodes between documents incorrectly.
* **Misunderstanding Shadow DOM Encapsulation:** Expecting styles or script behavior to bleed through shadow boundaries when they shouldn't.
* **Incorrectly Using `adoptedStyleSheets`:**  Trying to adopt non-constructed stylesheets or sharing constructed stylesheets across documents.

**7. Debugging Strategies and User Actions:**

Consider how a developer would end up inspecting or debugging code that involves `TreeScope`:

* **Inspecting the DOM Tree:** Using browser developer tools to examine the structure of the DOM, including shadow roots.
* **Debugging Event Listeners:** Setting breakpoints in JavaScript to understand the event flow, especially when dealing with Shadow DOM.
* **Examining Styles:** Inspecting the computed styles of elements to understand how CSS is being applied within different `TreeScope`s.
* **Using `console.log`:**  Outputting information about `document.activeElement`, event targets, or the results of `elementFromPoint()`.

**8. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Start with a general overview, then delve into specific functionalities, connections to web technologies, examples, potential errors, and debugging. This makes the information easier to understand and digest.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe `TreeScope` is only about Shadow DOM.
* **Correction:**  Realizing it's a more fundamental concept, also used for the main document itself, and encompasses features like `getElementById` which predate Shadow DOM.
* **Initial thought:** Just list the methods.
* **Refinement:**  Explain *what* each method does and *why* it's important. Connect it to user-facing behavior.
* **Initial thought:**  Focus only on the code.
* **Refinement:**  Include examples of user actions that trigger the code and debugging techniques.

By following this structured approach, combining code analysis with an understanding of web technologies and potential use cases, we can generate a comprehensive and informative response to the request.
好的，让我们来详细分析一下 `blink/renderer/core/dom/tree_scope.cc` 这个 Chromium Blink 引擎源代码文件。

**功能概述**

`TreeScope` 类在 Blink 渲染引擎中扮演着至关重要的角色，它代表了一个文档或文档的子树（例如，Shadow DOM 的内容）。它的核心功能是**管理和维护一个独立的 DOM 树的上下文环境**。更具体地说，它负责以下方面：

1. **维护 DOM 树结构:**  `TreeScope` 关联着一个根节点 (`root_node_`)，该节点是该 `TreeScope` 所代表的 DOM 子树的起始点。对于整个文档来说，根节点是 `Document` 对象；对于 Shadow DOM 来说，根节点是 `ShadowRoot` 对象。
2. **管理元素 ID:**  它负责跟踪和管理在其管辖范围内的元素的 ID (`elements_by_id_`)，提供快速通过 ID 查找元素的能力 (`getElementById`)。
3. **管理 `name` 属性:**  类似于 ID，它也管理带有 `name` 属性的元素，尤其用于处理 HTML 的 `<map>` 元素 (`image_maps_by_name_`)，允许通过 `name` 查找 `map`。
4. **处理样式（CSS）:**  `TreeScope` 与样式系统紧密相关，它拥有一个 `ScopedStyleResolver` 对象，用于解析和应用 CSS 样式到其管辖的 DOM 树。它也管理 `adoptedStyleSheets`，允许通过 JavaScript 将 CSSStyleSheet 对象直接添加到这个作用域。
5. **处理事件:**  虽然 `TreeScope` 本身不直接处理事件，但它是事件冒泡和捕获路径的关键组成部分。它定义了事件传播的边界，特别是在涉及到 Shadow DOM 的时候。
6. **处理焦点:**  它参与确定哪个元素在当前 `TreeScope` 中获得了焦点 (`AdjustedFocusedElement`)。
7. **处理选择:**  它管理当前 `TreeScope` 中的文本选择 (`DOMSelection`)。
8. **处理活动元素 (`activeElement`):**  提供获取当前 `TreeScope` 中活动元素的方法。
9. **处理 `adoptedStyleSheets`:**  管理通过 JavaScript 添加的 CSS 样式表。
10. **实现 Shadow DOM 隔离:**  对于 Shadow DOM，`TreeScope` 确保了 Shadow DOM 内部的元素和样式与外部文档隔离，除非通过特定的机制（如 slot）暴露。
11. **实现 `retargeting` 算法:** 当事件穿过 Shadow DOM 边界时，`TreeScope` 负责调整事件的目标，使其指向正确的元素。
12. **提供坐标点查找元素 (`ElementFromPoint`, `HitTestPoint`):**  允许根据给定的屏幕坐标，在其管理的 DOM 树中查找对应的元素。
13. **处理动画:**  提供获取当前 `TreeScope` 中所有动画的方法 (`getAnimations`)。
14. **处理 `pointerLockElement`, `fullscreenElement`, `pictureInPictureElement`:**  提供获取当前 `TreeScope` 中处于这些状态的元素。
15. **比较 `TreeScope` 的位置 (`ComparePosition`):**  确定两个 `TreeScope` 在 DOM 树层次结构中的相对位置。
16. **查找共同祖先 `TreeScope` (`CommonAncestorTreeScope`):** 确定两个 `TreeScope` 的最近公共祖先 `TreeScope`。
17. **处理访问键 (`GetElementByAccessKey`):**  查找具有特定访问键的元素。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`TreeScope` 是连接 JavaScript, HTML, 和 CSS 的关键桥梁。

* **HTML:**
    * **`getElementById`:**  JavaScript 可以调用 `document.getElementById()` 来查找具有特定 ID 的 HTML 元素。`TreeScope` 内部的 `getElementById` 方法正是这个功能的底层实现。
        ```html
        <!DOCTYPE html>
        <html>
        <head>
          <title>TreeScope Example</title>
        </head>
        <body>
          <div id="myDiv">这是一个 div 元素</div>
          <script>
            const divElement = document.getElementById('myDiv'); // JavaScript 调用
            console.log(divElement.textContent); // 输出 "这是一个 div 元素"
          </script>
        </body>
        </html>
        ```
        当 JavaScript 调用 `document.getElementById('myDiv')` 时，浏览器会找到与当前文档关联的 `TreeScope`，并调用其内部的 `getElementById` 方法来查找 ID 为 "myDiv" 的元素。
    * **`<map>` 元素和 `name` 属性:**  HTML 的 `<map>` 元素通过 `name` 属性关联图像映射。`TreeScope` 维护着 `image_maps_by_name_` 来支持这个功能。
        ```html
        <img src="shapes.png" usemap="#shapes">
        <map name="shapes">
          <area shape="rect" coords="0,0,50,50" href="rect.html">
        </map>
        <script>
          const mapElement = document.querySelector('map[name="shapes"]');
          // ... 浏览器内部会用到 TreeScope 来查找这个 map
        </script>
        ```

* **CSS:**
    * **样式隔离（Shadow DOM）:**  当使用 Shadow DOM 时，`TreeScope` 确保了 Shadow Root 内部的 CSS 规则不会影响到外部文档，反之亦然。
        ```html
        <div id="host"></div>
        <script>
          const host = document.getElementById('host');
          const shadowRoot = host.attachShadow({ mode: 'open' });
          shadowRoot.innerHTML = `
            <style>
              p { color: red; }
            </style>
            <p>This is inside the shadow DOM.</p>
          `;
          document.body.innerHTML += '<p>This is outside the shadow DOM.</p>';
        </script>
        ```
        在这个例子中，Shadow Root 有自己的 `TreeScope`，其中定义的 `p` 元素的样式（红色）不会影响到外部文档的 `p` 元素。
    * **`adoptedStyleSheets`:**  JavaScript 可以通过 `document.adoptedStyleSheets` 或 `shadowRoot.adoptedStyleSheets` 来添加或获取样式表。`TreeScope` 负责管理这些样式表。
        ```javascript
        const sheet = new CSSStyleSheet();
        sheet.replaceSync('p { font-weight: bold; }');
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
        ```

* **JavaScript:**
    * **`elementFromPoint`:**  JavaScript 的 `document.elementFromPoint(x, y)` 方法允许获取指定坐标下的元素。`TreeScope` 的 `HitTestPoint` 方法是这个功能的底层实现。
        ```javascript
        document.addEventListener('click', (event) => {
          const element = document.elementFromPoint(event.clientX, event.clientY);
          console.log('Clicked on:', element);
        });
        ```
        当用户点击页面时，浏览器会确定点击位置的坐标，并调用与该位置关联的 `TreeScope` 的 `HitTestPoint` 方法来找到最底层的元素。
    * **事件冒泡和 `retargeting`:**  在 Shadow DOM 中，事件会沿着特定的路径冒泡，并且事件的目标会被“重定向” (`retargeting`)，以便在外部文档看来事件好像发生在 Shadow Host 上。`TreeScope` 的 `Retarget` 方法实现了这个逻辑。

**逻辑推理与假设输入/输出**

假设我们有以下简单的 HTML 结构，并且用户点击了 Shadow DOM 内部的 `<button>` 元素：

```html
<div id="host">
  #shadow-root
    <button id="myButton">Click Me</button>
</div>
<script>
  const host = document.getElementById('host');
  const shadowRoot = host.attachShadow({ mode: 'open' });
  shadowRoot.innerHTML = '<button id="myButton">Click Me</button>';

  host.addEventListener('click', (event) => {
    console.log('Click on host:', event.target);
  });

  shadowRoot.querySelector('button').addEventListener('click', (event) => {
    console.log('Click on button in shadow:', event.target);
  });
</script>
```

**假设输入:** 用户点击了 Shadow DOM 内部的 `<button>` 元素。

**涉及的 `TreeScope`:**

1. **文档的 `TreeScope`:** 管理整个文档。
2. **Shadow Root 的 `TreeScope`:** 管理 Shadow DOM 的内容。

**逻辑推理 (简化版):**

1. **事件触发:**  用户点击操作在 Shadow Root 的 `TreeScope` 内部触发了一个 `click` 事件。
2. **Shadow DOM 事件流:**  事件首先在 Shadow DOM 内部传播。
3. **Shadow Root 上的监听器:** Shadow Root 内部的 `<button>` 上的事件监听器被触发，`console.log('Click on button in shadow:', event.target)` 会执行，此时 `event.target` 是 Shadow DOM 内部的 `<button>` 元素。
4. **事件冒泡到 Shadow Boundary:** 事件冒泡到 Shadow Boundary。
5. **`retargeting`:**  当事件穿过 Shadow Boundary 时，Blink 的事件系统会调用 `TreeScope::Retarget` 方法。这个方法会调整事件的目标，使其指向 Shadow Host (`<div id="host">`)。
6. **文档 `TreeScope` 上的监听器:** 事件继续冒泡到文档的 `TreeScope`，`host` 元素上的事件监听器被触发，`console.log('Click on host:', event.target)` 会执行，此时 `event.target` 是 Shadow Host 元素。

**输出 (console.log):**

```
Click on button in shadow: <button id="myButton">Click Me</button>
Click on host: <div id="host"></div>
```

**用户或编程常见的使用错误**

1. **ID 冲突:** 在同一个 `TreeScope` 内使用重复的 ID。这会导致 `getElementById` 返回意外的结果。
    ```html
    <div>
      <p id="myElement">Paragraph 1</p>
      <p id="myElement">Paragraph 2</p>
    </div>
    <script>
      const element = document.getElementById('myElement');
      console.log(element.textContent); // 可能输出 "Paragraph 1"，但不确定
    </script>
    ```
    **错误:**  HTML 规范要求 ID 在整个文档中是唯一的。虽然浏览器可能不会立即报错，但依赖于重复 ID 的行为是不可靠的。

2. **假设样式会穿透 Shadow DOM:**  开发者可能会错误地认为外部样式会自动应用到 Shadow DOM 内部的元素。
    ```html
    <style>
      button { color: blue; }
    </style>
    <div id="host"></div>
    <script>
      const host = document.getElementById('host');
      const shadowRoot = host.attachShadow({ mode: 'open' });
      shadowRoot.innerHTML = '<button>Click Me</button>';
      // 按钮的颜色可能不是蓝色，因为样式被 Shadow DOM 隔离
    </script>
    ```
    **错误:**  需要使用 CSS Shadow Parts 或 CSS Shadow-piercing combinators（已废弃）等机制来控制样式穿透。

3. **不理解事件在 Shadow DOM 中的冒泡行为:**  开发者可能不清楚事件是如何穿过 Shadow Boundary 的，以及 `event.target` 在不同阶段的指向。
    ```html
    <div id="host">
      #shadow-root
        <button>Click Me</button>
    </div>
    <script>
      document.addEventListener('click', (event) => {
        console.log(event.target); // 当点击按钮时，这里会打印 host 元素
      });
    </script>
    ```
    **错误:**  需要理解 `retargeting` 机制，如果需要在 Shadow DOM 内部捕获事件，可以使用 `composed: true` 的事件监听器选项。

4. **错误地操作属于不同 `TreeScope` 的节点:**  在不理解 `TreeScope` 的情况下，尝试直接将一个节点从一个 `TreeScope` 移动到另一个 `TreeScope` 可能会导致错误或意外行为。应该使用 `Node.adoptNode()` 或其他 DOM 操作来正确处理。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在一个包含 Shadow DOM 的网页上点击了一个按钮，并且开发者正在调试事件处理流程。

1. **用户操作:** 用户使用鼠标点击了页面上的一个按钮。
2. **浏览器事件捕获:** 浏览器接收到鼠标点击事件。
3. **确定目标元素:** 浏览器根据点击的坐标，通过 hit-testing (涉及 `TreeScope::HitTestPoint`) 确定被点击的元素。如果点击发生在 Shadow DOM 内部，目标元素将是 Shadow DOM 内部的元素。
4. **事件冒泡 (Shadow DOM):** 如果目标元素在 Shadow DOM 内部，点击事件首先会在 Shadow DOM 内部冒泡，触发内部的事件监听器。
5. **穿过 Shadow Boundary:** 当事件冒泡到 Shadow Boundary 时，事件系统会调用 `TreeScope::Retarget` 来调整事件的目标。
6. **事件冒泡 (文档):**  事件继续在文档的 `TreeScope` 中冒泡，触发绑定在 Shadow Host 或文档上的事件监听器。
7. **JavaScript 代码执行:**  相关的 JavaScript 事件处理函数被执行。
8. **开发者调试:** 如果开发者在事件处理函数中设置了断点，或者使用 `console.log` 输出信息，他们可能会观察到 `event.target` 的变化，这会引导他们思考 Shadow DOM 和 `TreeScope` 的作用。

**调试线索:**

* **检查 `event.target`:**  在事件处理函数中打印 `event.target` 可以帮助开发者理解事件的目标是什么，特别是在涉及 Shadow DOM 的时候。如果目标与预期不符，可能意味着 `retargeting` 正在发生。
* **检查 DOM 结构:** 使用浏览器开发者工具的 "Elements" 面板，可以查看完整的 DOM 树结构，包括 Shadow Roots，这有助于理解不同元素所属的 `TreeScope`。
* **使用事件断点:**  在开发者工具中设置事件断点，可以追踪事件的传播路径，查看事件在不同阶段的目标和当前目标。
* **查看 `adoptedStyleSheets`:** 如果样式没有按预期应用，检查 `document.adoptedStyleSheets` 和 `shadowRoot.adoptedStyleSheets` 可以帮助确定样式表是否已正确添加。
* **审查元素 ID:**  如果 `getElementById` 返回了错误的元素，检查页面上是否存在重复的 ID。

总而言之，`blink/renderer/core/dom/tree_scope.cc` 中定义的 `TreeScope` 类是 Blink 渲染引擎中一个核心的 DOM 抽象，它管理着 DOM 树的上下文，处理元素查找、样式、事件、焦点、选择以及 Shadow DOM 的隔离和事件重定向等关键功能。理解 `TreeScope` 的作用对于深入理解浏览器的渲染机制和处理涉及 Shadow DOM 的复杂场景至关重要。

### 提示词
```
这是目录为blink/renderer/core/dom/tree_scope.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All Rights Reserved.
 * Copyright (C) 2012 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/dom/tree_scope.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_throw_dom_exception.h"
#include "third_party/blink/renderer/core/animation/document_animations.h"
#include "third_party/blink/renderer/core/css/resolver/scoped_style_resolver.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/dom/id_target_observer_registry.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/tree_scope_adopter.h"
#include "third_party/blink/renderer/core/editing/dom_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/svg/svg_text_content_element.h"
#include "third_party/blink/renderer/core/svg/svg_tree_scope_resources.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/point_conversions.h"

namespace blink {

TreeScope::TreeScope(ContainerNode& root_node, Document& document)
    : document_(&document),
      root_node_(&root_node),
      parent_tree_scope_(&document) {
  DCHECK_NE(root_node, document);
  root_node_->SetTreeScope(this);
}

TreeScope::TreeScope(Document& document)
    : document_(&document), root_node_(document) {
  root_node_->SetTreeScope(this);
}

TreeScope::~TreeScope() = default;

bool TreeScope::IsInclusiveAncestorTreeScopeOf(const TreeScope& scope) const {
  for (const TreeScope* current = &scope; current;
       current = current->ParentTreeScope()) {
    if (current == this)
      return true;
  }
  return false;
}

void TreeScope::SetParentTreeScope(TreeScope& new_parent_scope) {
  // A document node cannot be re-parented.
  DCHECK(!RootNode().IsDocumentNode());

  parent_tree_scope_ = &new_parent_scope;
  SetDocument(new_parent_scope.GetDocument());
}

ScopedStyleResolver& TreeScope::EnsureScopedStyleResolver() {
  CHECK(this);
  if (!scoped_style_resolver_)
    scoped_style_resolver_ = MakeGarbageCollected<ScopedStyleResolver>(*this);
  return *scoped_style_resolver_;
}

void TreeScope::ClearScopedStyleResolver() {
  if (scoped_style_resolver_)
    scoped_style_resolver_->ResetStyle();
  scoped_style_resolver_.Clear();
}

Element* TreeScope::getElementById(const AtomicString& element_id) const {
  if (element_id.empty())
    return nullptr;
  if (!elements_by_id_)
    return nullptr;
  return elements_by_id_->GetElementById(element_id, *this);
}

const HeapVector<Member<Element>>& TreeScope::GetAllElementsById(
    const AtomicString& element_id) const {
  DEFINE_STATIC_LOCAL(Persistent<HeapVector<Member<Element>>>, empty_vector,
                      (MakeGarbageCollected<HeapVector<Member<Element>>>()));
  if (element_id.empty())
    return *empty_vector;
  if (!elements_by_id_)
    return *empty_vector;
  return elements_by_id_->GetAllElementsById(element_id, *this);
}

void TreeScope::AddElementById(const AtomicString& element_id,
                               Element& element) {
  if (!elements_by_id_) {
    elements_by_id_ = MakeGarbageCollected<TreeOrderedMap>();
  }
  elements_by_id_->Add(element_id, element);
  if (id_target_observer_registry_) {
    id_target_observer_registry_->NotifyObservers(element_id);
  }
}

void TreeScope::RemoveElementById(const AtomicString& element_id,
                                  Element& element) {
  if (!elements_by_id_) {
    return;
  }
  elements_by_id_->Remove(element_id, element);
  if (id_target_observer_registry_) {
    id_target_observer_registry_->NotifyObservers(element_id);
  }
}

Node* TreeScope::AncestorInThisScope(Node* node) const {
  while (node) {
    if (node->GetTreeScope() == this)
      return node;
    if (!node->IsInShadowTree())
      return nullptr;

    node = node->OwnerShadowHost();
  }

  return nullptr;
}

void TreeScope::AddImageMap(HTMLMapElement& image_map) {
  const AtomicString& name = image_map.GetName();
  const AtomicString& id = image_map.GetIdAttribute();
  if (!name && !id) {
    return;
  }
  if (!image_maps_by_name_)
    image_maps_by_name_ = MakeGarbageCollected<TreeOrderedMap>();
  if (name)
    image_maps_by_name_->Add(name, image_map);
  if (id) {
    image_maps_by_name_->Add(id, image_map);
  }
}

void TreeScope::RemoveImageMap(HTMLMapElement& image_map) {
  if (!image_maps_by_name_)
    return;
  if (const AtomicString& name = image_map.GetName())
    image_maps_by_name_->Remove(name, image_map);
  if (const AtomicString& id = image_map.GetIdAttribute()) {
    image_maps_by_name_->Remove(id, image_map);
  }
}

HTMLMapElement* TreeScope::GetImageMap(const String& url) const {
  if (url.IsNull())
    return nullptr;
  if (!image_maps_by_name_)
    return nullptr;
  wtf_size_t hash_pos = url.find('#');
  if (hash_pos == kNotFound)
    return nullptr;
  String name = url.Substring(hash_pos + 1);
  if (name.empty()) {
    return nullptr;
  }
  return To<HTMLMapElement>(
      image_maps_by_name_->GetElementByMapName(AtomicString(name), *this));
}

// If the point is not in the viewport, returns false. Otherwise, adjusts the
// point to account for the frame's zoom and scroll.
static bool PointInFrameContentIfVisible(Document& document,
                                         gfx::PointF& point_in_frame) {
  LocalFrame* frame = document.GetFrame();
  if (!frame)
    return false;
  LocalFrameView* frame_view = frame->View();
  if (!frame_view)
    return false;

  // The VisibleContentRect check below requires that scrollbars are up-to-date.
  document.UpdateStyleAndLayout(DocumentUpdateReason::kHitTest);

  auto* scrollable_area = frame_view->LayoutViewport();
  gfx::Rect visible_frame_rect(scrollable_area->VisibleContentRect().size());
  visible_frame_rect = gfx::ScaleToRoundedRect(visible_frame_rect,
                                               1 / frame->LayoutZoomFactor());
  if (!visible_frame_rect.Contains(gfx::ToRoundedPoint(point_in_frame)))
    return false;

  point_in_frame.Scale(frame->LayoutZoomFactor());
  return true;
}

HitTestResult HitTestInDocument(Document* document,
                                double x,
                                double y,
                                const HitTestRequest& request) {
  if (!document->IsActive())
    return HitTestResult();

  gfx::PointF hit_point(x, y);
  if (!PointInFrameContentIfVisible(*document, hit_point))
    return HitTestResult();

  HitTestLocation location(hit_point);
  HitTestResult result(request, location);
  document->GetLayoutView()->HitTest(location, result);
  return result;
}

Element* TreeScope::ElementFromPoint(double x, double y) const {
  return HitTestPoint(x, y,
                      HitTestRequest::kReadOnly | HitTestRequest::kActive);
}

Element* TreeScope::HitTestPoint(double x,
                                 double y,
                                 const HitTestRequest& request) const {
  HitTestResult result =
      HitTestInDocument(&RootNode().GetDocument(), x, y, request);
  if (request.AllowsChildFrameContent()) {
    return HitTestPointInternal(result.InnerNode(),
                                HitTestPointType::kInternal);
  }
  return HitTestPointInternal(result.InnerNode(),
                              HitTestPointType::kWebExposed);
}

Element* TreeScope::HitTestPointInternal(Node* node,
                                         HitTestPointType type) const {
  if (!node || node->IsDocumentNode())
    return nullptr;
  Element* element;
  if ((node->IsPseudoElement() && !node->IsScrollMarkerPseudoElement()) ||
      node->IsTextNode()) {
    element = node->ParentOrShadowHostElement();
  } else {
    element = To<Element>(node);
  }
  if (!element)
    return nullptr;
  if (type == HitTestPointType::kWebExposed)
    return &Retarget(*element);
  return element;
}

static bool ShouldAcceptNonElementNode(const Node& node) {
  Node* parent = node.parentNode();
  if (!parent)
    return false;
  // In some cases the hit test doesn't return slot elements, so we can only
  // get it through its child and can't skip it.
  if (IsA<HTMLSlotElement>(*parent))
    return true;
  // SVG text content elements has no background, and are thus not
  // hit during the background phase of hit-testing. Because of that
  // we need to allow any child (Text) node of these elements.
  return IsA<SVGTextContentElement>(parent);
}

HeapVector<Member<Element>> TreeScope::ElementsFromHitTestResult(
    HitTestResult& result) const {
  HeapVector<Member<Element>> elements;
  Node* last_node = nullptr;
  for (const auto& rect_based_node : result.ListBasedTestResult()) {
    Node* node = rect_based_node.Get();
    if (!node->IsElementNode() && !ShouldAcceptNonElementNode(*node))
      continue;
    node = HitTestPointInternal(node, HitTestPointType::kWebExposed);
    // Prune duplicate entries. A pseduo ::before content above its parent
    // node should only result in a single entry.
    if (node == last_node)
      continue;

    if (auto* element = DynamicTo<Element>(node)) {
      elements.push_back(element);
      last_node = node;
    }
  }
  if (Element* document_element = GetDocument().documentElement()) {
    if (elements.empty() || elements.back() != document_element)
      elements.push_back(document_element);
  }
  return elements;
}

HeapVector<Member<Element>> TreeScope::ElementsFromPoint(double x,
                                                         double y) const {
  Document& document = RootNode().GetDocument();
  gfx::PointF hit_point(x, y);
  if (!PointInFrameContentIfVisible(document, hit_point))
    return HeapVector<Member<Element>>();

  HitTestLocation location(hit_point);
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive |
                         HitTestRequest::kListBased |
                         HitTestRequest::kPenetratingList);
  HitTestResult result(request, location);
  document.GetLayoutView()->HitTest(location, result);

  return ElementsFromHitTestResult(result);
}

SVGTreeScopeResources& TreeScope::EnsureSVGTreeScopedResources() {
  if (!svg_tree_scoped_resources_) {
    svg_tree_scoped_resources_ =
        MakeGarbageCollected<SVGTreeScopeResources>(this);
  }
  return *svg_tree_scoped_resources_;
}

V8ObservableArrayCSSStyleSheet& TreeScope::EnsureAdoptedStyleSheets() {
  if (!adopted_style_sheets_) [[unlikely]] {
    adopted_style_sheets_ =
        MakeGarbageCollected<V8ObservableArrayCSSStyleSheet>(
            this, &OnAdoptedStyleSheetSet, &OnAdoptedStyleSheetDelete);
  }
  return *adopted_style_sheets_;
}

bool TreeScope::HasAdoptedStyleSheets() const {
  return adopted_style_sheets_ && adopted_style_sheets_->size();
}

void TreeScope::StyleSheetWasAdded(CSSStyleSheet* sheet) {
  GetDocument().GetStyleEngine().AdoptedStyleSheetAdded(*this, sheet);
}

void TreeScope::StyleSheetWasRemoved(CSSStyleSheet* sheet) {
  GetDocument().GetStyleEngine().AdoptedStyleSheetRemoved(*this, sheet);
}

// We pass TreeScope to the bindings array to be informed via set and delete
// callbacks. Bindings doesn't know about DOM types, so we can only pass
// ScriptWrappable (i.e. Document or ShadowRoot) or a GarbageCollectedMixin. We
// choose the mixin as that avoids dispatching from Document back to TreeScope
// essentially implementing a cast. The mixin is passed as void*-like object
// that is only passed back from the observable array into the set/delete
// callbacks where it is again used as TreeScope.
//
// static
void TreeScope::OnAdoptedStyleSheetSet(
    GarbageCollectedMixin* tree_scope,
    ScriptState* script_state,
    V8ObservableArrayCSSStyleSheet& observable_array,
    uint32_t index,
    Member<CSSStyleSheet>& sheet) {
  if (!sheet->IsConstructed()) {
    V8ThrowDOMException::Throw(script_state->GetIsolate(),
                               DOMExceptionCode::kNotAllowedError,
                               "Can't adopt non-constructed stylesheets.");
    return;
  }
  TreeScope* self = reinterpret_cast<TreeScope*>(tree_scope);
  Document* document = sheet->ConstructorDocument();
  if (document && *document != self->GetDocument()) {
    V8ThrowDOMException::Throw(
        script_state->GetIsolate(), DOMExceptionCode::kNotAllowedError,
        "Sharing constructed stylesheets in multiple documents is not allowed");
    return;
  }
  self->StyleSheetWasAdded(sheet.Get());
}

// See OnAdoptedStyleSheetSet() for description around inner workings.
//
// static
void TreeScope::OnAdoptedStyleSheetDelete(
    GarbageCollectedMixin* tree_scope,
    ScriptState* script_state,
    V8ObservableArrayCSSStyleSheet& observable_array,
    uint32_t index) {
  TreeScope* self = reinterpret_cast<TreeScope*>(tree_scope);
  self->StyleSheetWasRemoved(self->adopted_style_sheets_->at(index));
}

void TreeScope::ClearAdoptedStyleSheets() {
  if (!HasAdoptedStyleSheets()) {
    return;
  }
  HeapVector<Member<CSSStyleSheet>> removed;
  removed.AppendRange(adopted_style_sheets_->begin(),
                      adopted_style_sheets_->end());
  adopted_style_sheets_->clear();
  for (auto sheet : removed) {
    StyleSheetWasRemoved(sheet);
  }
}

void TreeScope::SetAdoptedStyleSheetsForTesting(
    HeapVector<Member<CSSStyleSheet>>& adopted_style_sheets) {
  ClearAdoptedStyleSheets();
  EnsureAdoptedStyleSheets();
  for (auto sheet : adopted_style_sheets) {
    DCHECK(sheet->IsConstructed());
    DCHECK_EQ(sheet->ConstructorDocument(), GetDocument());
    adopted_style_sheets_->push_back(sheet);
    StyleSheetWasAdded(sheet);
  }
}

DOMSelection* TreeScope::GetSelection() const {
  if (!RootNode().GetDocument().GetFrame())
    return nullptr;

  if (selection_)
    return selection_.Get();

  // FIXME: The correct selection in Shadow DOM requires that Position can have
  // a ShadowRoot as a container.  See
  // https://bugs.webkit.org/show_bug.cgi?id=82697
  selection_ = MakeGarbageCollected<DOMSelection>(this);
  return selection_.Get();
}

Element* TreeScope::FindAnchorWithName(const String& name) {
  if (name.empty())
    return nullptr;
  if (Element* element = getElementById(AtomicString(name)))
    return element;
  // TODO(crbug.com/369219144): Should this be Traversal<HTMLAnchorElementBase>?
  for (HTMLAnchorElement& anchor :
       Traversal<HTMLAnchorElement>::StartsAfter(RootNode())) {
    if (RootNode().GetDocument().InQuirksMode()) {
      // Quirks mode, case insensitive comparison of names.
      if (DeprecatedEqualIgnoringCase(anchor.GetName(), name))
        return &anchor;
    } else {
      // Strict mode, names need to match exactly.
      if (anchor.GetName() == name)
        return &anchor;
    }
  }
  return nullptr;
}

Node* TreeScope::FindAnchor(const String& fragment) {
  Node* anchor = nullptr;
  // https://html.spec.whatwg.org/C/#the-indicated-part-of-the-document
  // 1. Let fragment be the document's URL's fragment.

  // 2. If fragment is "", top of the document.
  // TODO(1117212) Move empty check to here.

  // 3. Try the raw fragment (for HTML documents; skip it for `svgView()`).
  // TODO(1117212) Remove this 'raw' check, or make it actually 'raw'
  if (!GetDocument().IsSVGDocument()) {
    anchor = FindAnchorWithName(fragment);
    if (anchor)
      return anchor;
  }

  // 4. Let fragmentBytes be the percent-decoded fragment.
  // 5. Let decodedFragment be the UTF-8 decode without BOM of fragmentBytes.
  String name = DecodeURLEscapeSequences(fragment, DecodeURLMode::kUTF8);
  // 6. Try decodedFragment.
  anchor = FindAnchorWithName(name);
  if (anchor)
    return anchor;

  // 7. If decodedFragment is "top", top of the document.
  // TODO(1117212) Move the IsEmpty check to step 2.
  if (fragment.empty() || EqualIgnoringASCIICase(name, "top"))
    anchor = &GetDocument();

  return anchor;
}

void TreeScope::AdoptIfNeeded(Node& node) {
  DCHECK(!node.IsDocumentNode());
  if (&node.GetTreeScope() == this) [[likely]] {
    return;
  }

  // Script is forbidden to protect against event handlers firing in the middle
  // of rescoping in |didMoveToNewDocument| callbacks. See
  // https://crbug.com/605766 and https://crbug.com/606651.
  ScriptForbiddenScope forbid_script;
  TreeScopeAdopter adopter(node, *this);
  if (adopter.NeedsScopeChange())
    adopter.Execute();
}

// This method corresponds to the Retarget algorithm specified in
// https://dom.spec.whatwg.org/#retarget
// This retargets |target| against the root of |this|.
// The steps are different with the spec for performance reasons,
// but the results should be the same.
Element& TreeScope::Retarget(const Element& target) const {
  const TreeScope& target_scope = target.GetTreeScope();
  if (!target_scope.RootNode().IsShadowRoot())
    return const_cast<Element&>(target);

  HeapVector<Member<const TreeScope>> target_ancestor_scopes;
  HeapVector<Member<const TreeScope>> context_ancestor_scopes;
  for (const TreeScope* tree_scope = &target_scope; tree_scope;
       tree_scope = tree_scope->ParentTreeScope())
    target_ancestor_scopes.push_back(tree_scope);
  for (const TreeScope* tree_scope = this; tree_scope;
       tree_scope = tree_scope->ParentTreeScope())
    context_ancestor_scopes.push_back(tree_scope);

  auto target_ancestor_riterator = target_ancestor_scopes.rbegin();
  auto context_ancestor_riterator = context_ancestor_scopes.rbegin();
  while (context_ancestor_riterator != context_ancestor_scopes.rend() &&
         target_ancestor_riterator != target_ancestor_scopes.rend() &&
         *context_ancestor_riterator == *target_ancestor_riterator) {
    ++context_ancestor_riterator;
    ++target_ancestor_riterator;
  }

  if (target_ancestor_riterator == target_ancestor_scopes.rend())
    return const_cast<Element&>(target);
  Node& first_different_scope_root =
      (*target_ancestor_riterator).Get()->RootNode();
  return To<ShadowRoot>(first_different_scope_root).host();
}

Element* TreeScope::AdjustedFocusedElementInternal(
    const Element& target) const {
  for (const Element* ancestor = &target; ancestor;
       ancestor = ancestor->OwnerShadowHost()) {
    if (this == ancestor->GetTreeScope())
      return const_cast<Element*>(ancestor);
  }
  return nullptr;
}

Element* TreeScope::AdjustedFocusedElement() const {
  Document& document = RootNode().GetDocument();
  Element* element = document.FocusedElement();
  if (!element && document.GetPage())
    element = document.GetPage()->GetFocusController().FocusedFrameOwnerElement(
        *document.GetFrame());
  if (!element)
    return nullptr;

  // https://github.com/flackr/carousel/tree/main/scroll-marker#what-is-the-documentactiveelement-of-a-focused-pseudo-element
  if (auto* scroll_marker = DynamicTo<ScrollMarkerPseudoElement>(element)) {
    CHECK(scroll_marker->ScrollMarkerGroup());
    element = scroll_marker->ScrollMarkerGroup()->UltimateOriginatingElement();
  } else if (auto* pseudo_element = DynamicTo<PseudoElement>(element)) {
    element = pseudo_element->UltimateOriginatingElement();
  }

  CHECK(!element->IsPseudoElement());

  if (RootNode().IsInShadowTree()) {
    if (Element* retargeted = AdjustedFocusedElementInternal(*element)) {
      return (this == &retargeted->GetTreeScope()) ? retargeted : nullptr;
    }
    return nullptr;
  }

  EventPath* event_path = MakeGarbageCollected<EventPath>(*element);
  for (const auto& context : event_path->NodeEventContexts()) {
    if (context.GetNode() == RootNode()) {
      // context.target() is one of the followings:
      // - InsertionPoint
      // - shadow host
      // - Document::focusedElement()
      // So, it's safe to do To<Element>().
      return To<Element>(context.Target()->ToNode());
    }
  }
  return nullptr;
}

Element* TreeScope::AdjustedElement(const Element& target) const {
  const Element* adjusted_target = &target;
  for (const Element* ancestor = &target; ancestor;
       ancestor = ancestor->OwnerShadowHost()) {
    if (ancestor->GetShadowRoot())
      adjusted_target = ancestor;
    if (this == ancestor->GetTreeScope())
      return const_cast<Element*>(adjusted_target);
  }
  return nullptr;
}

StyleSheetList& TreeScope::StyleSheets() {
  if (!style_sheet_list_) {
    style_sheet_list_ = MakeGarbageCollected<StyleSheetList>(this);
  }
  return *style_sheet_list_;
}

Element* TreeScope::activeElement() const {
  if (Element* element = AdjustedFocusedElement()) {
    return element;
  }
  return document_ == this ? document_->body() : nullptr;
}

HeapVector<Member<Animation>> TreeScope::getAnimations() {
  return GetDocument().GetDocumentAnimations().getAnimations(*this);
}

Element* TreeScope::pointerLockElement() {
  UseCounter::Count(GetDocument(), WebFeature::kShadowRootPointerLockElement);
  const Element* target = GetDocument().PointerLockElement();
  return target ? AdjustedElement(*target) : nullptr;
}

Element* TreeScope::fullscreenElement() {
  return Fullscreen::FullscreenElementForBindingFrom(*this);
}

Element* TreeScope::pictureInPictureElement() {
  return PictureInPictureController::From(GetDocument())
      .PictureInPictureElement(*this);
}

uint16_t TreeScope::ComparePosition(const TreeScope& other_scope) const {
  if (other_scope == this)
    return Node::kDocumentPositionEquivalent;

  HeapVector<Member<const TreeScope>, 16> chain1;
  HeapVector<Member<const TreeScope>, 16> chain2;
  const TreeScope* current;
  for (current = this; current; current = current->ParentTreeScope())
    chain1.push_back(current);
  for (current = &other_scope; current; current = current->ParentTreeScope())
    chain2.push_back(current);

  unsigned index1 = chain1.size();
  unsigned index2 = chain2.size();
  if (chain1[index1 - 1] != chain2[index2 - 1])
    return Node::kDocumentPositionDisconnected |
           Node::kDocumentPositionImplementationSpecific;

  for (unsigned i = std::min(index1, index2); i; --i) {
    const TreeScope* child1 = chain1[--index1];
    const TreeScope* child2 = chain2[--index2];
    if (child1 != child2) {
      Node* shadow_host1 = child1->RootNode().ParentOrShadowHostNode();
      Node* shadow_host2 = child2->RootNode().ParentOrShadowHostNode();
      if (shadow_host1 != shadow_host2)
        return shadow_host1->compareDocumentPosition(
            shadow_host2, Node::kTreatShadowTreesAsDisconnected);
      return Node::kDocumentPositionPreceding;
    }
  }

  // There was no difference between the two parent chains, i.e., one was a
  // subset of the other. The shorter chain is the ancestor.
  return index1 < index2 ? Node::kDocumentPositionFollowing |
                               Node::kDocumentPositionContainedBy
                         : Node::kDocumentPositionPreceding |
                               Node::kDocumentPositionContains;
}

const TreeScope* TreeScope::CommonAncestorTreeScope(
    const TreeScope& other) const {
  HeapVector<Member<const TreeScope>, 16> this_chain;
  for (const TreeScope* tree = this; tree; tree = tree->ParentTreeScope())
    this_chain.push_back(tree);

  HeapVector<Member<const TreeScope>, 16> other_chain;
  for (const TreeScope* tree = &other; tree; tree = tree->ParentTreeScope())
    other_chain.push_back(tree);

  // Keep popping out the last elements of these chains until a mismatched pair
  // is found. If |this| and |other| belong to different documents, null will be
  // returned.
  const TreeScope* last_ancestor = nullptr;
  while (!this_chain.empty() && !other_chain.empty() &&
         this_chain.back() == other_chain.back()) {
    last_ancestor = this_chain.back();
    this_chain.pop_back();
    other_chain.pop_back();
  }
  return last_ancestor;
}

TreeScope* TreeScope::CommonAncestorTreeScope(TreeScope& other) {
  return const_cast<TreeScope*>(
      static_cast<const TreeScope&>(*this).CommonAncestorTreeScope(other));
}

bool TreeScope::IsInclusiveAncestorOf(const TreeScope& scope) const {
  for (const TreeScope* current = &scope; current;
       current = current->ParentTreeScope()) {
    if (current == this)
      return true;
  }
  return false;
}

Element* TreeScope::GetElementByAccessKey(const String& key) const {
  if (key.empty())
    return nullptr;
  Element* result = nullptr;
  Node& root = RootNode();
  for (Element& element : ElementTraversal::DescendantsOf(root)) {
    if (DeprecatedEqualIgnoringCase(
            element.FastGetAttribute(html_names::kAccesskeyAttr), key))
      result = &element;
    if (ShadowRoot* shadow_root = element.GetShadowRoot()) {
      if (Element* shadow_result = shadow_root->GetElementByAccessKey(key))
        result = shadow_result;
    }
  }
  return result;
}

void TreeScope::Trace(Visitor* visitor) const {
  visitor->Trace(root_node_);
  visitor->Trace(document_);
  visitor->Trace(parent_tree_scope_);
  visitor->Trace(id_target_observer_registry_);
  visitor->Trace(selection_);
  visitor->Trace(elements_by_id_);
  visitor->Trace(image_maps_by_name_);
  visitor->Trace(scoped_style_resolver_);
  visitor->Trace(radio_button_group_scope_);
  visitor->Trace(svg_tree_scoped_resources_);
  visitor->Trace(style_sheet_list_);
  visitor->Trace(adopted_style_sheets_);
}

IdTargetObserverRegistry& TreeScope::EnsureIdTargetObserverRegistry() {
  if (!id_target_observer_registry_) [[unlikely]] {
    id_target_observer_registry_ =
        MakeGarbageCollected<IdTargetObserverRegistry>();
  }
  return *id_target_observer_registry_;
}

}  // namespace blink
```