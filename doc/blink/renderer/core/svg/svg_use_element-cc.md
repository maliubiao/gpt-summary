Response:
Let's break down the thought process for analyzing the `SVGUseElement.cc` file and generating the comprehensive response.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of `SVGUseElement.cc` within the Chromium Blink rendering engine. The request also explicitly asks for connections to HTML, CSS, and JavaScript, examples of logical reasoning, common user errors, and debugging information.

**2. Decomposition of the File's Purpose (Skimming the Code):**

The first step is to quickly skim the code, paying attention to:

* **Copyright and License:** This provides context but isn't directly functional.
* **Includes:** These are crucial. They tell us what other parts of the engine this file interacts with. We see includes related to:
    * DOM (`Document`, `Element`, `Node`, `ShadowRoot`, `Event`)
    * SVG (`SVG*Element`, `SVGAnimatedLength`, `SVGLengthContext`)
    * Layout (`LayoutSVGTransformableContainer`)
    * Resource loading (`ResourceFetcher`, `FetchParameters`)
    * Utilities (`wtf/vector.h`)
* **Class Declaration (`SVGUseElement`):**  This is the central point. We see inheritance from `SVGGraphicsElement` and `SVGURIReference`. This hints at its nature: a graphical SVG element that references external resources.
* **Member Variables:**  `x_`, `y_`, `width_`, `height_`, `element_url_`, `document_content_`, etc. These suggest core properties and state.
* **Methods:**  `InsertedInto`, `RemovedFrom`, `SvgAttributeChanged`, `BuildPendingResource`, `AttachShadowTree`, `DetachShadowTree`, `CreateLayoutObject`, etc. These indicate the lifecycle and functionality of the element.

**3. Identifying Key Functionality Areas:**

Based on the includes, class declaration, and methods, we can identify the main responsibilities:

* **Referencing and Instancing:** The core purpose of `<use>` is to reuse SVG content. This involves fetching, parsing, and instantiating the referenced content. Methods like `UpdateTargetReference`, `ResolveTargetElement`, `CreateInstanceTree`, `AttachShadowTree` are key here.
* **Shadow DOM:** The use of `CreateUserAgentShadowRoot`, `AttachShadowTree`, `DetachShadowTree` points to how `<use>` implements its functionality using the Shadow DOM. The instance of the referenced content is created within the shadow root.
* **Attributes:**  The `x_`, `y_`, `width_`, `height_` members and `SvgAttributeChanged` method highlight how the `<use>` element's attributes affect the rendered instance.
* **Resource Loading:** The inclusion of `ResourceFetcher` and related classes indicates handling external SVG resources referenced via the `href` attribute.
* **Layout:**  `CreateLayoutObject` and `LayoutSVGTransformableContainer` connect the element to the rendering pipeline.
* **Error Handling and Edge Cases:**  The code includes checks for disallowed elements, cyclic references, and handles loading errors.

**4. Connecting to HTML, CSS, and JavaScript:**

* **HTML:** The `<use>` element is directly used in HTML to embed and reuse SVG content. Examples are straightforward.
* **CSS:** CSS styles can be applied to the `<use>` element itself and potentially cascade into the instantiated content within the shadow DOM (though Shadow DOM boundaries can affect this). The `x`, `y` attributes have corresponding CSS properties.
* **JavaScript:** JavaScript can manipulate the `<use>` element's attributes (e.g., changing the `href`), triggering updates and re-renders. Events like `load` and `error` are also relevant for JavaScript interaction.

**5. Logical Reasoning and Examples:**

This requires thinking about the flow of data and actions within the code. Consider a scenario:

* **Input:** A `<use>` element with an `href` pointing to a local `<symbol>` element.
* **Processing:** `UpdateTargetReference` identifies a local reference. `ResolveTargetElement` finds the `<symbol>`. `CreateInstanceTree` clones the `<symbol>` (and converts it to `<svg>`). `AttachShadowTree` adds this cloned content to the shadow root.
* **Output:**  The content of the `<symbol>` is rendered at the location of the `<use>` element.

Similarly, consider the case of an external resource, error handling, etc.

**6. Common User Errors:**

Think about what mistakes developers might make when using `<use>`:

* **Incorrect `href`:**  Typing errors, wrong paths.
* **Referencing non-existent IDs.**
* **Cyclic references:**  A `<use>` element referencing itself directly or indirectly.
* **Trying to modify content inside the shadow DOM directly (which is generally discouraged).**
* **Not understanding how `width` and `height` on `<use>` interact with the referenced element.**

**7. Debugging Clues:**

How would a developer reach this code during debugging?

* **Inspecting the DOM tree in the browser's developer tools:**  Seeing a `<use>` element and wanting to understand how it works.
* **Setting breakpoints in JavaScript:**  Observing attribute changes or layout updates related to a `<use>` element.
* **Looking at network requests:**  Seeing a request for the SVG resource specified in the `href`.
* **Analyzing rendering issues:**  If the content isn't appearing as expected, investigating the shadow DOM and the instantiation process.
* **Following stack traces related to layout or rendering.**

**8. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Provide specific code examples where relevant. Start with a high-level overview and then delve into more detail.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the C++ implementation details.
* **Correction:** The request emphasizes the *functionality* and its relationship to web technologies. Shift the focus to explaining *what* the code does in the context of SVG, HTML, CSS, and JavaScript, rather than just *how* it does it in C++.
* **Initial thought:**  Provide very detailed explanations of each method.
* **Correction:** Summarize the main purpose of key methods and provide more detailed explanations for the core functionalities like referencing and shadow DOM creation.
* **Initial thought:**  Only provide code snippets from the C++ file.
* **Correction:**  Include examples of how `<use>` is used in HTML and how CSS might interact with it.

By following this kind of structured approach, combining code skimming with understanding the underlying concepts of SVG and the Shadow DOM, and considering the perspective of a web developer, it's possible to generate a comprehensive and helpful answer to the request.
好的，让我们详细分析一下 `blink/renderer/core/svg/svg_use_element.cc` 文件的功能。

**文件功能概述:**

`SVGUseElement.cc` 文件定义了 Blink 渲染引擎中 `SVGUseElement` 类的实现。 `SVGUseElement` 对应于 SVG 规范中的 `<use>` 元素。  `<use>` 元素允许在 SVG 文档中重用已存在的 SVG 图形对象。  该文件的核心功能是：

1. **处理 `<use>` 元素的属性:**  包括 `x`, `y`, `width`, `height` 和 `href` (通过 `SVGURIReference` 接口)。
2. **解析 `href` 属性:**  确定要引用的目标元素，可以是文档内部的元素（通过 ID 引用）或外部 SVG 文件中的元素。
3. **创建被引用元素的“实例”:**  当 `<use>` 元素被渲染时，它会创建一个被引用元素的“克隆”或“实例”，并将其插入到 `<use>` 元素的影子 DOM 中。
4. **处理实例的属性和样式:**  `<use>` 元素自身的 `x`, `y`, `width`, `height` 属性可以覆盖被引用元素的相应属性。
5. **管理影子 DOM:**  `<use>` 元素使用影子 DOM 来包含被引用元素的实例，从而实现封装和样式隔离。
6. **处理资源加载:**  如果 `href` 指向外部 SVG 文件，则需要加载该文件并解析其中的目标元素。
7. **处理循环引用:**  检测并防止 `<use>` 元素之间的循环引用，避免无限递归。
8. **与渲染流程集成:**  参与布局、绘制等渲染流程，确保被引用元素的实例能够正确显示。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    * **功能关系:**  `<use>` 元素本身就是 HTML（或者更准确地说，XML，因为 SVG 是一种 XML 应用）的一部分。开发者在 HTML 中使用 `<svg>` 元素及其子元素，包括 `<use>`.
    * **举例:**
      ```html
      <svg width="200" height="200">
        <defs>
          <circle id="myCircle" cx="50" cy="50" r="40" stroke="black" stroke-width="3" fill="red" />
        </defs>
        <use href="#myCircle" x="100" y="100" fill="blue" />
      </svg>
      ```
      在这个例子中，`<use href="#myCircle" ...>`  使用了 `SVGUseElement` 来引用 `<circle>` 元素，并在指定的位置和样式创建了一个新的圆。

* **CSS:**
    * **功能关系:** CSS 可以用来设置 `<use>` 元素自身的样式，例如 `opacity`，`transform` 等。此外，通过 CSS 继承和级联，某些样式可能会影响到 `<use>` 元素影子 DOM 中的实例，但这受到 Shadow DOM 的封装性影响。
    * **举例:**
      ```css
      use {
        opacity: 0.8;
      }

      #instance1 {
        fill: green; /* 尝试修改实例的样式，可能会被影子 DOM 隔离 */
      }
      ```
      ```html
      <svg width="200" height="200">
        <defs>
          <circle id="myCircle" cx="50" cy="50" r="40" fill="red" />
        </defs>
        <use id="instance1" href="#myCircle" x="10" y="10" />
      </svg>
      ```
      CSS 规则 `use { opacity: 0.8; }` 会应用到 `<use>` 元素本身。尝试通过 `#instance1` 直接修改影子 DOM 中圆的 `fill` 属性可能不会生效，因为影子 DOM 提供了样式封装。正确的做法可能是在 `<defs>` 中定义好样式，或者使用 CSS 变量等机制。

* **JavaScript:**
    * **功能关系:** JavaScript 可以动态地创建、修改和删除 `<use>` 元素及其属性。可以用来实现交互式的 SVG 效果。
    * **举例:**
      ```javascript
      const svgNS = "http://www.w3.org/2000/svg";
      const useElement = document.createElementNS(svgNS, "use");
      useElement.setAttribute("href", "#myOtherCircle");
      useElement.setAttribute("x", 50);
      useElement.setAttribute("y", 50);
      document.querySelector("svg").appendChild(useElement);

      // 动态修改 href
      setTimeout(() => {
        useElement.setAttribute("href", "external.svg#anotherShape");
      }, 2000);
      ```
      这段 JavaScript 代码动态创建了一个 `<use>` 元素，设置了其属性，并将其添加到 SVG 文档中。之后又动态修改了 `href` 属性，这会导致 `SVGUseElement.cc` 中的逻辑被触发，去加载和渲染新的目标。

**逻辑推理与假设输入输出:**

假设有以下 SVG 代码：

```html
<svg width="100" height="100">
  <rect id="box" width="50" height="50" fill="yellow"/>
  <use href="#box" x="20" y="20" fill="green" />
</svg>
```

* **假设输入:**  Blink 渲染引擎解析到上述 SVG 代码。
* **逻辑推理:**
    1. 解析器创建 `SVGRectElement` 对象对应 `<rect id="box" ...>`.
    2. 解析器创建 `SVGUseElement` 对象对应 `<use href="#box" ...>`.
    3. `SVGUseElement` 的 `href` 属性被解析为 `#box`，表示引用当前文档中的元素。
    4. `SVGUseElement` 查找 ID 为 `box` 的元素（即 `SVGRectElement`）。
    5. `SVGUseElement` 创建 `SVGRectElement` 的一个实例到其影子 DOM 中。
    6. 实例的属性会受到 `<use>` 元素自身属性的影响：
        * `x` 和 `y` 会被设置为 `20`。
        * `fill` 会被设置为 `green`，覆盖了原始 `rect` 的 `yellow`。
        * `width` 和 `height` 如果 `<use>` 没有指定，则会继承原始 `rect` 的值 `50`。
* **预期输出:** 渲染结果会显示一个绿色的正方形，其位置在 (20, 20)，大小为 50x50。

**用户或编程常见的使用错误:**

1. **`href` 属性指向不存在的 ID:**
   ```html
   <svg><use href="#nonExistent" /></svg>
   ```
   * **错误:**  `<use>` 元素无法找到目标元素。
   * **后果:**  在渲染结果中可能看不到任何内容，或者浏览器会报告错误。Blink 的 `SVGUseElement.cc` 中会处理这种情况，`ResolveTargetElement` 方法会返回空，导致无法创建实例。

2. **循环引用:**
   ```html
   <svg>
     <use id="use1" href="#use2" />
     <use id="use2" href="#use1" />
   </svg>
   ```
   * **错误:**  `<use>` 元素相互引用，导致无限递归。
   * **后果:**  浏览器会检测到循环引用并阻止渲染，避免性能问题和崩溃。`SVGUseElement::HasCycleUseReferencing` 方法就是用来检测这种情况的。

3. **尝试直接修改影子 DOM 内容:**
   ```html
   <svg>
     <defs><circle id="base" cx="10" cy="10" r="5" fill="red" /></defs>
     <use id="myUse" href="#base"></use>
   </svg>
   <script>
     document.querySelector('#myUse circle').setAttribute('fill', 'blue'); // 尝试修改影子 DOM 中的圆
   </script>
   ```
   * **错误:**  开发者尝试使用 CSS 选择器或 JavaScript 直接访问和修改 `<use>` 元素影子 DOM 中的内容。
   * **后果:**  由于影子 DOM 的封装性，这种直接修改通常不会生效。开发者应该通过修改原始定义或使用 CSS 变量等方式来影响实例的样式。

4. **外部资源加载失败:**
   ```html
   <svg><use href="nonexistent.svg#shape" /></svg>
   ```
   * **错误:**  `href` 指向的外部 SVG 文件不存在或无法访问。
   * **后果:**  `<use>` 元素无法加载目标资源，导致渲染失败。`SVGUseElement::ResourceNotifyFinished` 方法会处理加载完成的情况，包括错误。

**用户操作如何一步步到达这里 (作为调试线索):**

假设开发者正在调试一个 SVG 渲染问题，涉及到 `<use>` 元素，以下是可能的操作步骤，最终可能会涉及到 `SVGUseElement.cc` 的代码：

1. **页面加载:** 用户在浏览器中打开包含 SVG 的 HTML 页面。
2. **渲染引擎启动:** Blink 渲染引擎开始解析 HTML 和 SVG 代码。
3. **遇到 `<use>` 元素:** 当解析器遇到 `<use>` 元素时，会创建 `SVGUseElement` 对象。
4. **解析 `href` 属性:**  `SVGUseElement` 会解析其 `href` 属性，确定引用的目标。
5. **查找目标元素:**
   * **内部引用:** 如果 `href` 是 `#id` 的形式，则会在当前文档中查找具有该 ID 的元素。`ResolveTargetElement` 方法会被调用。
   * **外部引用:** 如果 `href` 是 `url#id` 的形式，则会发起网络请求加载外部 SVG 文件。`SVGResourceDocumentContent::Fetch` 方法会被调用，并涉及到资源加载的流程。
6. **创建实例:** 一旦找到目标元素，`SVGUseElement::CreateInstanceTree` 方法会被调用，创建目标元素的克隆。
7. **插入影子 DOM:**  创建的实例会被插入到 `SVGUseElement` 的影子 DOM 中。`AttachShadowTree` 方法会被调用。
8. **布局和绘制:**  布局阶段会计算 `<use>` 元素及其影子 DOM 内容的布局。绘制阶段会将这些内容绘制到屏幕上。 `CreateLayoutObject` 方法创建布局对象。
9. **样式应用:** CSS 样式会应用到 `<use>` 元素及其影子 DOM 中的内容。
10. **用户交互或 JavaScript 动态修改:** 用户可能与页面交互，或者 JavaScript 代码可能会动态修改 `<use>` 元素的属性（例如 `x`, `y`, `href`）。这会导致 `SvgAttributeChanged` 方法被调用，触发重新解析、加载或渲染。
11. **调试工具介入:** 开发者可能使用浏览器开发者工具：
    * **Elements 面板:** 查看 DOM 树，包括 `<use>` 元素的影子 DOM 结构。
    * **Network 面板:** 检查外部 SVG 资源的加载情况。
    * **Console 面板:** 查看可能的错误信息。
    * **Sources 面板:** 设置断点在 JavaScript 代码中，观察 `<use>` 元素属性的变化。
    * **Performance 面板:** 分析渲染性能，可能发现与 `<use>` 元素相关的性能瓶颈。
12. **Blink 源码调试:** 如果开发者需要深入了解 `<use>` 元素的行为，可能会下载 Chromium 源码，并设置断点在 `blink/renderer/core/svg/svg_use_element.cc` 文件中的相关方法，例如 `ResolveTargetElement`, `CreateInstanceTree`, `AttachShadowTree`, `SvgAttributeChanged` 等，以跟踪代码执行流程，理解其内部实现逻辑。

总而言之，`SVGUseElement.cc` 是 Blink 渲染引擎中实现 SVG `<use>` 元素核心功能的关键文件，它涉及到 SVG 的引用、复用、影子 DOM 管理以及与 HTML、CSS、JavaScript 的交互。理解这个文件的功能有助于开发者深入理解 SVG 渲染机制，并解决相关的渲染问题。

### 提示词
```
这是目录为blink/renderer/core/svg/svg_use_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008 Nikolas Zimmermann
 * <zimmermann@kde.org>
 * Copyright (C) 2004, 2005, 2006, 2007 Rob Buis <buis@kde.org>
 * Copyright (C) Research In Motion Limited 2009-2010. All rights reserved.
 * Copyright (C) 2011 Torch Mobile (Beijing) Co. Ltd. All rights reserved.
 * Copyright (C) 2012 University of Szeged
 * Copyright (C) 2012 Renata Hodovan <reni@webkit.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/svg/svg_use_element.h"

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/id_target_observer.h"
#include "third_party/blink/renderer/core/dom/increment_load_event_delay_count.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/xml_document.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_transformable_container.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_circle_element.h"
#include "third_party/blink/renderer/core/svg/svg_ellipse_element.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_path_element.h"
#include "third_party/blink/renderer/core/svg/svg_polygon_element.h"
#include "third_party/blink/renderer/core/svg/svg_polyline_element.h"
#include "third_party/blink/renderer/core/svg/svg_rect_element.h"
#include "third_party/blink/renderer/core/svg/svg_resource_document_content.h"
#include "third_party/blink/renderer/core/svg/svg_svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_symbol_element.h"
#include "third_party/blink/renderer/core/svg/svg_text_element.h"
#include "third_party/blink/renderer/core/svg/svg_title_element.h"
#include "third_party/blink/renderer/core/svg_names.h"
#include "third_party/blink/renderer/core/xlink_names.h"
#include "third_party/blink/renderer/core/xml/parser/xml_document_parser.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_parameters.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

SVGUseElement::SVGUseElement(Document& document)
    : SVGGraphicsElement(svg_names::kUseTag, document),
      SVGURIReference(this),
      x_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kXAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kUnitlessZero,
          CSSPropertyID::kX)),
      y_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kYAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kUnitlessZero,
          CSSPropertyID::kY)),
      width_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kWidthAttr,
          SVGLengthMode::kWidth,
          SVGLength::Initial::kUnitlessZero)),
      height_(MakeGarbageCollected<SVGAnimatedLength>(
          this,
          svg_names::kHeightAttr,
          SVGLengthMode::kHeight,
          SVGLength::Initial::kUnitlessZero)),
      element_url_is_local_(true),
      needs_shadow_tree_recreation_(false) {
  DCHECK(HasCustomStyleCallbacks());

  CreateUserAgentShadowRoot();
}

SVGUseElement::~SVGUseElement() = default;

void SVGUseElement::Trace(Visitor* visitor) const {
  visitor->Trace(document_content_);
  visitor->Trace(external_resource_target_);
  visitor->Trace(x_);
  visitor->Trace(y_);
  visitor->Trace(width_);
  visitor->Trace(height_);
  visitor->Trace(target_id_observer_);
  SVGGraphicsElement::Trace(visitor);
  SVGURIReference::Trace(visitor);
}

#if DCHECK_IS_ON()
static inline bool IsWellFormedDocument(const Document& document) {
  if (IsA<XMLDocument>(document))
    return static_cast<XMLDocumentParser*>(document.Parser())->WellFormed();
  return true;
}
#endif

Node::InsertionNotificationRequest SVGUseElement::InsertedInto(
    ContainerNode& root_parent) {
  SVGGraphicsElement::InsertedInto(root_parent);
  if (root_parent.isConnected()) {
    InvalidateShadowTree();
#if DCHECK_IS_ON()
    DCHECK(!InstanceRoot() || !IsWellFormedDocument(GetDocument()));
#endif
  }
  return kInsertionDone;
}

void SVGUseElement::RemovedFrom(ContainerNode& root_parent) {
  SVGGraphicsElement::RemovedFrom(root_parent);
  if (root_parent.isConnected()) {
    ClearResourceReference();
    CancelShadowTreeRecreation();
  }
}

void SVGUseElement::DidMoveToNewDocument(Document& old_document) {
  SVGGraphicsElement::DidMoveToNewDocument(old_document);
  if (load_event_delayer_) {
    load_event_delayer_->DocumentChanged(GetDocument());
  }
  UpdateTargetReference();
}

static void TransferUseWidthAndHeightIfNeeded(
    const SVGUseElement& use,
    SVGElement& shadow_element,
    const SVGElement& original_element) {
  // Use |original_element| for checking the element type, because we will
  // have replaced a <symbol> with an <svg> in the instance tree.
  if (!IsA<SVGSymbolElement>(original_element) &&
      !IsA<SVGSVGElement>(original_element))
    return;

  // "The width and height properties on the 'use' element override the values
  // for the corresponding properties on a referenced 'svg' or 'symbol' element
  // when determining the used value for that property on the instance root
  // element. However, if the computed value for the property on the 'use'
  // element is auto, then the property is computed as normal for the element
  // instance. ... Because auto is the initial value, if dimensions are not
  // explicitly set on the 'use' element, the values set on the 'svg' or
  // 'symbol' will be used as defaults."
  // (https://svgwg.org/svg2-draft/struct.html#UseElement)
  AtomicString width_value(
      use.width()->IsSpecified()
          ? use.width()->CurrentValue()->ValueAsString()
          : original_element.getAttribute(svg_names::kWidthAttr));
  shadow_element.setAttribute(svg_names::kWidthAttr, width_value);
  AtomicString height_value(
      use.height()->IsSpecified()
          ? use.height()->CurrentValue()->ValueAsString()
          : original_element.getAttribute(svg_names::kHeightAttr));
  shadow_element.setAttribute(svg_names::kHeightAttr, height_value);
}

bool SVGUseElement::IsStructurallyExternal() const {
  return !element_url_is_local_ &&
         !EqualIgnoringFragmentIdentifier(element_url_, GetDocument().Url());
}

bool SVGUseElement::HaveLoadedRequiredResources() {
  return !document_content_ || !document_content_->IsLoading();
}

void SVGUseElement::UpdateDocumentContent(
    SVGResourceDocumentContent* document_content) {
  if (document_content_ == document_content) {
    return;
  }
  auto old_load_event_delayer = std::move(load_event_delayer_);
  if (document_content_) {
    document_content_->RemoveObserver(this);
  }
  document_content_ = document_content;
  if (document_content_) {
    load_event_delayer_ =
        std::make_unique<IncrementLoadEventDelayCount>(GetDocument());
    document_content_->AddObserver(this);
  }
}

void SVGUseElement::UpdateTargetReference() {
  const String& url_string = HrefString();
  element_url_ = GetDocument().CompleteURL(url_string);
  element_url_is_local_ = url_string.StartsWith('#');
  if (!IsStructurallyExternal() || !GetDocument().IsActive()) {
    UpdateDocumentContent(nullptr);
    pending_event_.Cancel();
    return;
  }
  if (!element_url_.HasFragmentIdentifier() ||
      (document_content_ && EqualIgnoringFragmentIdentifier(
                                element_url_, document_content_->Url()))) {
    return;
  }

  pending_event_.Cancel();

  if (element_url_.ProtocolIsData()) {
    Deprecation::CountDeprecation(GetDocument().domWindow(),
                                  WebFeature::kDataUrlInSvgUse);
  }

  auto* context_document = &GetDocument();
  ExecutionContext* execution_context = context_document->GetExecutionContext();
  ResourceLoaderOptions options(execution_context->GetCurrentWorld());
  options.initiator_info.name = fetch_initiator_type_names::kUse;
  FetchParameters params(ResourceRequest(element_url_), options);
  params.MutableResourceRequest().SetMode(
      network::mojom::blink::RequestMode::kSameOrigin);
  auto* document_content =
      SVGResourceDocumentContent::Fetch(params, *context_document);
  UpdateDocumentContent(document_content);
}

void SVGUseElement::SvgAttributeChanged(
    const SvgAttributeChangedParams& params) {
  const QualifiedName& attr_name = params.name;
  if (attr_name == svg_names::kXAttr || attr_name == svg_names::kYAttr ||
      attr_name == svg_names::kWidthAttr ||
      attr_name == svg_names::kHeightAttr) {
    if (attr_name == svg_names::kXAttr || attr_name == svg_names::kYAttr) {
      UpdatePresentationAttributeStyle(params.property);
    }

    UpdateRelativeLengthsInformation();
    if (SVGElement* instance_root = InstanceRoot()) {
      DCHECK(instance_root->CorrespondingElement());
      TransferUseWidthAndHeightIfNeeded(*this, *instance_root,
                                        *instance_root->CorrespondingElement());
    }

    if (LayoutObject* object = GetLayoutObject())
      MarkForLayoutAndParentResourceInvalidation(*object);
    return;
  }

  if (SVGURIReference::IsKnownAttribute(attr_name)) {
    UpdateTargetReference();
    InvalidateShadowTree();
    return;
  }

  SVGGraphicsElement::SvgAttributeChanged(params);
}

static bool IsDisallowedElement(const Element& element) {
  // Spec: "Any 'svg', 'symbol', 'g', graphics element or other 'use' is
  // potentially a template object that can be re-used (i.e., "instanced") in
  // the SVG document via a 'use' element." "Graphics Element" is defined as
  // 'circle', 'ellipse', 'image', 'line', 'path', 'polygon', 'polyline',
  // 'rect', 'text' Excluded are anything that is used by reference or that only
  // make sense to appear once in a document.
  if (!element.IsSVGElement())
    return true;

  DEFINE_STATIC_LOCAL(HashSet<QualifiedName>, allowed_element_tags,
                      ({
                          svg_names::kATag,        svg_names::kCircleTag,
                          svg_names::kDescTag,     svg_names::kEllipseTag,
                          svg_names::kGTag,        svg_names::kImageTag,
                          svg_names::kLineTag,     svg_names::kMetadataTag,
                          svg_names::kPathTag,     svg_names::kPolygonTag,
                          svg_names::kPolylineTag, svg_names::kRectTag,
                          svg_names::kSVGTag,      svg_names::kSwitchTag,
                          svg_names::kSymbolTag,   svg_names::kTextTag,
                          svg_names::kTextPathTag, svg_names::kTitleTag,
                          svg_names::kTSpanTag,    svg_names::kUseTag,
                      }));
  return !allowed_element_tags.Contains<SVGAttributeHashTranslator>(
      element.TagQName());
}

void SVGUseElement::ScheduleShadowTreeRecreation() {
  needs_shadow_tree_recreation_ = true;
  GetDocument().ScheduleUseShadowTreeUpdate(*this);
}

void SVGUseElement::CancelShadowTreeRecreation() {
  needs_shadow_tree_recreation_ = false;
  GetDocument().UnscheduleUseShadowTreeUpdate(*this);
}

void SVGUseElement::ClearResourceReference() {
  external_resource_target_.Clear();
  UnobserveTarget(target_id_observer_);
  RemoveAllOutgoingReferences();
}

Element* SVGUseElement::ResolveTargetElement() {
  if (!element_url_.HasFragmentIdentifier())
    return nullptr;
  AtomicString element_identifier(DecodeURLEscapeSequences(
      element_url_.FragmentIdentifier(), DecodeURLMode::kUTF8OrIsomorphic));

  if (!IsStructurallyExternal()) {
    // Only create observers for non-instance use elements.
    // Instances will be updated by their corresponding elements.
    if (InUseShadowTree()) {
      return OriginatingTreeScope().getElementById(element_identifier);
    } else {
      return ObserveTarget(
          target_id_observer_, OriginatingTreeScope(), element_identifier,
          WTF::BindRepeating(&SVGUseElement::InvalidateTargetReference,
                             WrapWeakPersistent(this)));
    }
  }
  if (!document_content_) {
    return nullptr;
  }
  external_resource_target_ =
      document_content_->GetResourceTarget(element_identifier);
  if (!external_resource_target_) {
    return nullptr;
  }
  return external_resource_target_->target;
}

SVGElement* SVGUseElement::InstanceRoot() const {
  if (ShadowTreeRebuildPending())
    return nullptr;
  return To<SVGElement>(UseShadowRoot().firstChild());
}

void SVGUseElement::BuildPendingResource() {
  if (!isConnected()) {
    DCHECK(!needs_shadow_tree_recreation_);
    return;  // Already replaced by rebuilding ancestor.
  }
  CancelShadowTreeRecreation();

  // Check if this element is scheduled (by an ancestor) to be replaced.
  SVGUseElement* ancestor = GeneratingUseElement();
  while (ancestor) {
    if (ancestor->needs_shadow_tree_recreation_)
      return;
    ancestor = ancestor->GeneratingUseElement();
  }

  DetachShadowTree();
  ClearResourceReference();

  if (auto* target = DynamicTo<SVGElement>(ResolveTargetElement())) {
    DCHECK(target->isConnected());
    AttachShadowTree(*target);
  }
  DCHECK(!needs_shadow_tree_recreation_);
}

String SVGUseElement::title() const {
  // Find the first <title> child in <use> which doesn't cover shadow tree.
  if (Element* title_element = Traversal<SVGTitleElement>::FirstChild(*this))
    return title_element->innerText();

  // If there is no <title> child in <use>, we lookup first <title> child in
  // shadow tree.
  if (SVGElement* instance_root = InstanceRoot()) {
    if (Element* title_element =
            Traversal<SVGTitleElement>::FirstChild(*instance_root))
      return title_element->innerText();
  }
  // Otherwise return a null string.
  return String();
}

static void PostProcessInstanceTree(SVGElement& target_root,
                                    SVGElement& instance_root) {
  DCHECK(!instance_root.isConnected());
  // We checked this before creating the cloned subtree.
  DCHECK(!IsDisallowedElement(instance_root));
  // Associate the roots.
  instance_root.SetCorrespondingElement(&target_root);

  // The subtrees defined by |target_root| and |instance_root| should be
  // isomorphic at this point, so we can walk both trees simultaneously to be
  // able to create the corresponding element mapping.
  //
  // We don't walk the target tree element-by-element, and clone each element,
  // but instead use cloneNode(deep=true). This is an optimization for the
  // common case where <use> doesn't contain disallowed elements
  // (ie. <foreignObject>).  Though if there are disallowed elements in the
  // subtree, we have to remove them. For instance: <use> on <g> containing
  // <foreignObject> (indirect case).
  // We do that at the same time as the association back to the corresponding
  // element is performed to avoid having instance elements in a half-way
  // inconsistent state.
  Element* target_element = ElementTraversal::FirstWithin(target_root);
  Element* instance_element = ElementTraversal::FirstWithin(instance_root);
  while (target_element) {
    DCHECK(instance_element);
    DCHECK(!IsA<SVGElement>(*instance_element) ||
           !To<SVGElement>(*instance_element).CorrespondingElement());
    if (IsDisallowedElement(*target_element)) {
      Element* instance_next = ElementTraversal::NextSkippingChildren(
          *instance_element, &instance_root);
      // The subtree is not in the document so this won't generate events that
      // could mutate the tree.
      instance_element->parentNode()->RemoveChild(instance_element);

      // Since the target subtree isn't mutated, it can just be traversed in
      // the normal way (without saving next traversal target).
      target_element =
          ElementTraversal::NextSkippingChildren(*target_element, &target_root);
      instance_element = instance_next;
    } else {
      // Set up the corresponding element association.
      if (auto* svg_instance_element =
              DynamicTo<SVGElement>(instance_element)) {
        svg_instance_element->SetCorrespondingElement(
            To<SVGElement>(target_element));
      }
      target_element = ElementTraversal::Next(*target_element, &target_root);
      instance_element =
          ElementTraversal::Next(*instance_element, &instance_root);
    }
  }
  DCHECK(!instance_element);
}

static void MoveChildrenToReplacementElement(ContainerNode& source_root,
                                             ContainerNode& destination_root) {
  for (Node* child = source_root.firstChild(); child;) {
    Node* next_child = child->nextSibling();
    destination_root.AppendChild(child);
    child = next_child;
  }
}

SVGElement* SVGUseElement::CreateInstanceTree(SVGElement& target_root) const {
  NodeCloningData data{CloneOption::kIncludeDescendants};
  SVGElement* instance_root = &To<SVGElement>(target_root.CloneWithChildren(
      data, /*document*/ nullptr, /*append_to*/ nullptr));
  if (IsA<SVGSymbolElement>(target_root)) {
    // Spec: The referenced 'symbol' and its contents are deep-cloned into
    // the generated tree, with the exception that the 'symbol' is replaced
    // by an 'svg'. This generated 'svg' will always have explicit values
    // for attributes width and height. If attributes width and/or height
    // are provided on the 'use' element, then these attributes will be
    // transferred to the generated 'svg'. If attributes width and/or
    // height are not specified, the generated 'svg' element will use
    // values of 100% for these attributes.
    auto* svg_element =
        MakeGarbageCollected<SVGSVGElement>(target_root.GetDocument());
    // Transfer all attributes from the <symbol> to the new <svg>
    // element.
    svg_element->CloneAttributesFrom(*instance_root);
    // Move already cloned elements to the new <svg> element.
    MoveChildrenToReplacementElement(*instance_root, *svg_element);
    instance_root = svg_element;
  }
  TransferUseWidthAndHeightIfNeeded(*this, *instance_root, target_root);
  PostProcessInstanceTree(target_root, *instance_root);
  return instance_root;
}

void SVGUseElement::AttachShadowTree(SVGElement& target) {
  DCHECK(!InstanceRoot());
  DCHECK(!needs_shadow_tree_recreation_);

  // Do not allow self-referencing.
  if (IsDisallowedElement(target) || HasCycleUseReferencing(*this, target))
    return;

  // Set up root SVG element in shadow tree.
  // Clone the target subtree into the shadow tree, not handling <use> and
  // <symbol> yet.
  UseShadowRoot().AppendChild(CreateInstanceTree(target));

  // Assure shadow tree building was successful.
  DCHECK(InstanceRoot());
  DCHECK_EQ(InstanceRoot()->GeneratingUseElement(), this);
  DCHECK_EQ(InstanceRoot()->CorrespondingElement(), &target);

  for (SVGElement& instance :
       Traversal<SVGElement>::DescendantsOf(UseShadowRoot())) {
    SVGElement* corresponding_element = instance.CorrespondingElement();
    // Transfer non-markup event listeners.
    if (EventTargetData* data = corresponding_element->GetEventTargetData()) {
      data->event_listener_map.CopyEventListenersNotCreatedFromMarkupToTarget(
          &instance);
    }
    // Setup the mapping from the corresponding (original) element back to the
    // instance.
    corresponding_element->AddInstance(&instance);
  }
}

void SVGUseElement::DetachShadowTree() {
  ShadowRoot& shadow_root = UseShadowRoot();
  // FIXME: We should try to optimize this, to at least allow partial reclones.
  shadow_root.RemoveChildren(kOmitSubtreeModifiedEvent);
}

LayoutObject* SVGUseElement::CreateLayoutObject(const ComputedStyle&) {
  return MakeGarbageCollected<LayoutSVGTransformableContainer>(this);
}

static bool IsDirectReference(const SVGElement& element) {
  return IsA<SVGPathElement>(element) || IsA<SVGRectElement>(element) ||
         IsA<SVGCircleElement>(element) || IsA<SVGEllipseElement>(element) ||
         IsA<SVGPolygonElement>(element) || IsA<SVGPolylineElement>(element) ||
         IsA<SVGTextElement>(element);
}

Path SVGUseElement::ToClipPath() const {
  const SVGGraphicsElement* element = VisibleTargetGraphicsElementForClipping();
  auto* geometry_element = DynamicTo<SVGGeometryElement>(element);
  if (!geometry_element)
    return Path();

  DCHECK(GetLayoutObject());
  Path path = geometry_element->ToClipPath();
  AffineTransform transform = GetLayoutObject()->LocalSVGTransform();
  if (!transform.IsIdentity())
    path.Transform(transform);
  return path;
}

SVGGraphicsElement* SVGUseElement::VisibleTargetGraphicsElementForClipping()
    const {
  auto* svg_graphics_element = DynamicTo<SVGGraphicsElement>(InstanceRoot());
  if (!svg_graphics_element)
    return nullptr;

  // Spec: "If a <use> element is a child of a clipPath element, it must
  // directly reference <path>, <text> or basic shapes elements. Indirect
  // references are an error and the clipPath element must be ignored."
  // https://drafts.fxtf.org/css-masking/#the-clip-path
  if (!IsDirectReference(*svg_graphics_element)) {
    // Spec: Indirect references are an error (14.3.5)
    return nullptr;
  }

  return svg_graphics_element;
}

bool SVGUseElement::HasCycleUseReferencing(const ContainerNode& target_instance,
                                           const SVGElement& target) const {
  // Shortcut for self-references
  if (&target == this)
    return true;

  AtomicString target_id = target.GetIdAttribute();
  auto* element =
      DynamicTo<SVGElement>(target_instance.ParentOrShadowHostElement());
  while (element) {
    if (element->HasID() && element->GetIdAttribute() == target_id &&
        element->GetDocument() == target.GetDocument())
      return true;
    element = DynamicTo<SVGElement>(element->ParentOrShadowHostElement());
  }
  return false;
}

bool SVGUseElement::ShadowTreeRebuildPending() const {
  // The shadow tree is torn down lazily, so check if there's a pending rebuild
  // or if we're disconnected from the document.
  return !InActiveDocument() || needs_shadow_tree_recreation_;
}

void SVGUseElement::InvalidateShadowTree() {
  if (ShadowTreeRebuildPending())
    return;
  ScheduleShadowTreeRecreation();
}

void SVGUseElement::InvalidateTargetReference() {
  InvalidateShadowTree();
  for (SVGElement* instance : InstancesForElement())
    To<SVGUseElement>(instance)->InvalidateShadowTree();
}

bool SVGUseElement::SelfHasRelativeLengths() const {
  return x_->CurrentValue()->IsRelative() || y_->CurrentValue()->IsRelative() ||
         width_->CurrentValue()->IsRelative() ||
         height_->CurrentValue()->IsRelative();
}

gfx::RectF SVGUseElement::GetBBox() {
  DCHECK(GetLayoutObject());
  auto& transformable_container =
      To<LayoutSVGTransformableContainer>(*GetLayoutObject());
  // Don't apply the additional translation if the oBB is invalid.
  if (!transformable_container.IsObjectBoundingBoxValid())
    return gfx::RectF();

  // TODO(fs): Preferably this would just use objectBoundingBox() (and hence
  // don't need to override SVGGraphicsElement::getBBox at all) and be
  // correct without additional work. That will not work out ATM without
  // additional quirks. The problem stems from including the additional
  // translation directly on the LayoutObject corresponding to the
  // SVGUseElement.
  gfx::RectF bbox = transformable_container.ObjectBoundingBox();
  bbox.Offset(transformable_container.AdditionalTranslation());
  return bbox;
}

void SVGUseElement::QueueOrDispatchPendingEvent(
    const AtomicString& event_name) {
  if (GetDocument().GetExecutionContext() &&
      GetDocument().GetExecutionContext()->is_in_back_forward_cache()) {
    // Queue the event if the page is in back/forward cache.
    EnqueueEvent(*Event::Create(event_name), TaskType::kDOMManipulation);
  } else {
    DispatchEvent(*Event::Create(event_name));
  }
}

void SVGUseElement::ResourceNotifyFinished(
    SVGResourceDocumentContent* document_content) {
  DCHECK_EQ(document_content_, document_content);
  load_event_delayer_.reset();
  if (!isConnected())
    return;
  InvalidateShadowTree();

  const bool is_error = document_content->ErrorOccurred();
  const AtomicString& event_name =
      is_error ? event_type_names::kError : event_type_names::kLoad;
  DCHECK(!pending_event_.IsActive());
  pending_event_ = PostCancellableTask(
      *GetDocument().GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      WTF::BindOnce(&SVGUseElement::QueueOrDispatchPendingEvent,
                    WrapPersistent(this), event_name));
}

SVGAnimatedPropertyBase* SVGUseElement::PropertyFromAttribute(
    const QualifiedName& attribute_name) const {
  if (attribute_name == svg_names::kXAttr) {
    return x_.Get();
  } else if (attribute_name == svg_names::kYAttr) {
    return y_.Get();
  } else if (attribute_name == svg_names::kWidthAttr) {
    return width_.Get();
  } else if (attribute_name == svg_names::kHeightAttr) {
    return height_.Get();
  } else {
    SVGAnimatedPropertyBase* ret =
        SVGURIReference::PropertyFromAttribute(attribute_name);
    if (ret) {
      return ret;
    } else {
      return SVGGraphicsElement::PropertyFromAttribute(attribute_name);
    }
  }
}

void SVGUseElement::SynchronizeAllSVGAttributes() const {
  SVGAnimatedPropertyBase* attrs[]{x_.Get(), y_.Get(), width_.Get(),
                                   height_.Get()};
  SynchronizeListOfSVGAttributes(attrs);
  SVGURIReference::SynchronizeAllSVGAttributes();
  SVGGraphicsElement::SynchronizeAllSVGAttributes();
}

void SVGUseElement::CollectExtraStyleForPresentationAttribute(
    MutableCSSPropertyValueSet* style) {
  auto pres_attrs =
      std::to_array<const SVGAnimatedPropertyBase*>({x_.Get(), y_.Get()});
  AddAnimatedPropertiesToPresentationAttributeStyle(pres_attrs, style);
  SVGGraphicsElement::CollectExtraStyleForPresentationAttribute(style);
}

}  // namespace blink
```