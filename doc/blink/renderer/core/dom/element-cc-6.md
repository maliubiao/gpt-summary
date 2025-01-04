Response:
My thinking process to analyze the provided code snippet and generate the detailed explanation follows these steps:

1. **Initial Understanding of the Context:**  I first recognize that the code is part of the Chromium Blink rendering engine, specifically within the `blink/renderer/core/dom/element.cc` file. This immediately tells me the code is dealing with the internal representation and manipulation of DOM elements.

2. **High-Level Overview of the Functions:** I quickly scan the function names to get a general idea of what the code is doing. Keywords like `PseudoStateChanged`, `SetTargetedSnapAreaIdsForSnapContainers`, `ClearTargetedSnapAreaIdsForSnapContainers`, `CalculateHighlightRecalc`, `RecalcHighlightStyles`, `SetAnimationStyleChange`, `SetNeedsAnimationStyleRecalc`, `SetNeedsCompositingUpdate`, `SetRegionCaptureCropId`, `SetRestrictionTargetId`, `SetIsEligibleForElementCapture`, `SetCustomElementDefinition`, `SetIsValue`, `SetDidAttachInternals`, `EnsureElementInternals`, `CanAttachShadowRoot`, `ErrorMessageForAttachShadow`, `attachShadow`, `AttachDeclarativeShadowRoot`, `CreateUserAgentShadowRoot`, `AttachShadowRootInternal`, `OpenShadowRoot`, `ClosedShadowRoot`, `AuthorShadowRoot`, `UserAgentShadowRoot`, `EnsureUserAgentShadowRoot`, `ChildTypeAllowed`, `CheckForEmptyStyleChange`, `ChildrenChanged` provide strong hints. I see a lot related to styling, layout, shadow DOM, and custom elements.

3. **Detailed Analysis of Each Function (Iterative Process):**  I go through each function individually, attempting to understand its purpose and how it fits into the broader context of element manipulation.

    * **`PseudoStateChanged`:**  The name is self-explanatory. It deals with changes to pseudo-classes. I note the connection to CSS and how changes trigger style recalculation.

    * **`SetTargetedSnapAreaIdsForSnapContainers` and `ClearTargetedSnapAreaIdsForSnapContainers`:**  These clearly relate to CSS scroll snapping. I see logic for traversing the DOM tree to find snap containers and areas.

    * **`CalculateHighlightRecalc` and `RecalcHighlightStyles`:** These are central to handling the styling of highlight pseudo-elements (like `::selection`, `::spelling-error`, custom highlights). I pay attention to the different `HighlightRecalc` states and the conditions under which recalculation is needed.

    * **`SetAnimationStyleChange` and `SetNeedsAnimationStyleRecalc`:** These are about managing style changes caused by CSS animations and transitions. I see checks to avoid redundant recalculations.

    * **`SetNeedsCompositingUpdate`:**  This function is related to the compositing process, which is a key aspect of browser rendering for performance.

    * **`SetRegionCaptureCropId` and `GetRegionCaptureCropId`:** These relate to a specific feature, likely related to screen capture and cropping.

    * **`SetRestrictionTargetId` and `GetRestrictionTargetId`, `SetIsEligibleForElementCapture`:**  These functions clearly manage the "Element Capture" feature, allowing elements to be targets for capture. I notice the console logging related to eligibility.

    * **`SetCustomElementDefinition`, `GetCustomElementDefinition`, `SetIsValue`, `IsValue`, `SetDidAttachInternals`, `DidAttachInternals`, `EnsureElementInternals`, `GetElementInternals`:** This block deals with the lifecycle and internal state of custom elements.

    * **Shadow DOM Functions (`CanAttachShadowRoot`, `ErrorMessageForAttachShadow`, `attachShadow`, `AttachDeclarativeShadowRoot`, `CreateUserAgentShadowRoot`, `AttachShadowRootInternal`, `OpenShadowRoot`, `ClosedShadowRoot`, `AuthorShadowRoot`, `UserAgentShadowRoot`, `EnsureUserAgentShadowRoot`):** This is a significant portion focusing on attaching and managing Shadow DOM trees. I analyze the different modes (open, closed, user-agent), declarative shadow roots, and the conditions for attaching shadow roots.

    * **`ChildTypeAllowed`:** A simple helper function to check if a given node type is allowed as a child.

    * **`CheckForEmptyStyleChange`:**  This deals with the `:empty` pseudo-class and how changes in child nodes affect its state.

    * **`ChildrenChanged`:** This function is a notification that the element's children have changed. The comment hints at interaction with Mutation Observers.

4. **Identifying Relationships with Web Technologies:** As I analyze each function, I actively connect them to corresponding JavaScript, HTML, and CSS features. For example:

    * `PseudoStateChanged` -> CSS pseudo-classes (`:hover`, `:active`, etc.) and JavaScript event listeners.
    * Scroll snapping functions -> CSS `scroll-snap-type`, `scroll-snap-align`, etc.
    * Highlight recalc functions -> CSS highlight pseudo-elements (`::selection`).
    * Shadow DOM functions ->  JavaScript `attachShadow()` method and `<template>` elements with `shadowroot` attribute.
    * Custom element functions -> JavaScript `customElements.define()` and the `is` attribute in HTML.
    * `:empty` -> CSS `:empty` pseudo-class.

5. **Inferring Logic and Providing Examples:**  For functions with more complex logic (like `CalculateHighlightRecalc`), I try to create hypothetical scenarios with different inputs and expected outputs. This helps illustrate how the code works.

6. **Considering User/Programmer Errors:** I think about common mistakes developers might make that would lead to these code paths being executed or reveal potential issues. For instance, trying to attach multiple shadow roots without understanding the limitations.

7. **Tracing User Operations (Debugging Clues):** I imagine a user interacting with a web page and how their actions might trigger these code paths. For example, selecting text leading to `RecalcHighlightStyles` or hovering over an element leading to `PseudoStateChanged`.

8. **Structuring the Output:** Finally, I organize my findings into a clear and structured format, using headings and bullet points to make the information easy to understand. I ensure I address all parts of the prompt.

9. **Review and Refinement:**  I reread my analysis to check for accuracy, clarity, and completeness. I ensure that the examples are relevant and the explanations are easy to follow. I also double-check that I have addressed the "part 7 of 13" aspect by providing a concise summary of the overall functionality covered in this specific snippet.

This iterative process of analyzing individual functions, connecting them to web technologies, inferring logic, considering errors, and tracing user actions allows me to generate a comprehensive explanation of the provided code snippet.
这是 `blink/renderer/core/dom/element.cc` 文件的第 7 部分（共 13 部分）。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：样式和渲染更新、Shadow DOM 管理、自定义元素支持以及一些特定浏览器功能。**

更具体地说，这部分代码主要负责处理以下几个方面：

**1. 伪类状态变化 (`PseudoStateChanged`)：**

* **功能:**  当元素相关的伪类（例如 `:hover`, `:active` 等）状态发生改变时，通知样式系统进行更新。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** JavaScript 事件（如鼠标事件）可能导致伪类状态改变。
    * **HTML:**  HTML 结构定义了元素及其可能的伪类。
    * **CSS:** CSS 规则定义了当伪类激活时元素的样式。
* **假设输入与输出:**
    * **假设输入:** 用户鼠标悬停在一个按钮元素上。
    * **输出:**  调用 `PseudoStateChanged` 并传入 `:hover` 伪类信息，触发样式系统重新计算该按钮的样式，应用 `:hover` 样式规则。
* **用户或编程常见的使用错误:**  没有正确理解伪类的作用域和优先级，导致样式更新不符合预期。例如，在一个父元素上定义了影响子元素的伪类样式，但子元素自身也有伪类样式，可能出现覆盖问题。
* **用户操作如何到达这里:** 用户将鼠标指针移动到元素上方，触发了鼠标悬停事件。浏览器事件处理机制会检测到状态变化，并最终调用到 `PseudoStateChanged`。

**2. 管理滚动捕捉点 (`SetTargetedSnapAreaIdsForSnapContainers`, `ClearTargetedSnapAreaIdsForSnapContainers`)：**

* **功能:**  设置和清除滚动容器的目标捕捉区域 ID。这与 CSS 滚动捕捉功能 (`scroll-snap-type`, `scroll-snap-align`) 相关。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:**  可以通过 JavaScript 动态控制滚动行为，间接影响捕捉点。
    * **HTML:** HTML 结构定义了滚动容器和捕捉区域。
    * **CSS:**  CSS 属性 `scroll-snap-type` 和 `scroll-snap-align` 定义了滚动捕捉的行为。
* **假设输入与输出:**
    * **假设输入:** 页面加载时，浏览器解析到定义了滚动捕捉的 HTML 和 CSS。
    * **输出:** `SetTargetedSnapAreaIdsForSnapContainers` 会遍历 DOM 树，找到滚动容器和捕捉区域，并将它们关联起来。滚动时，滚动容器会尝试捕捉到指定的目标区域。
* **用户或编程常见的使用错误:**  CSS 滚动捕捉属性配置错误，导致滚动行为不流畅或无法捕捉到预期位置。
* **用户操作如何到达这里:**  页面加载时，渲染引擎会解析 CSS 布局，并根据 `scroll-snap-type` 等属性调用相关函数进行初始化设置。

**3. 高亮伪元素样式重算 (`CalculateHighlightRecalc`, `ShouldRecalcHighlightPseudoStyle`, `RecalcCustomHighlightPseudoStyle`, `RecalcHighlightStyles`)：**

* **功能:** 决定是否需要重新计算高亮伪元素（如 `::selection`, `::spelling-error`, `::grammar-error` 以及自定义高亮）的样式，并执行重算。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** JavaScript 可以通过 Selection API 或 ContentEditable 等特性影响文本选择，从而触发 `::selection` 样式的更新。
    * **HTML:**  HTML 内容是高亮样式应用的对象。
    * **CSS:** CSS 规则定义了高亮伪元素的样式。
* **假设输入与输出:**
    * **假设输入:** 用户在页面上选中了一段文本。
    * **输出:**  `CalculateHighlightRecalc` 判断需要重新计算 `::selection` 的样式，然后 `RecalcHighlightStyles` 会根据 CSS 规则生成新的样式并应用。
* **用户或编程常见的使用错误:**  高亮样式与其他样式冲突，或者自定义高亮样式定义不正确。
* **用户操作如何到达这里:** 用户执行文本选择操作（例如，鼠标拖拽选中文字）。浏览器会检测到选择变化，并触发高亮样式的重算。

**4. 动画样式变化处理 (`SetAnimationStyleChange`, `SetNeedsAnimationStyleRecalc`)：**

* **功能:**  标记元素需要进行动画相关的样式重算，并进行必要的检查以避免重复计算。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** JavaScript 可以通过 Web Animations API 或 CSS Transitions/Animations 来触发动画效果。
    * **HTML:** HTML 结构定义了可能应用动画的元素。
    * **CSS:** CSS 定义了动画的关键帧、过渡效果等。
* **假设输入与输出:**
    * **假设输入:**  一个元素的 CSS `transition` 属性生效，或者一个 CSS 动画开始播放。
    * **输出:**  `SetNeedsAnimationStyleRecalc` 会被调用，标记该元素需要进行动画相关的样式更新。
* **用户或编程常见的使用错误:**  动画效果与预期不符，可能是由于样式重算时机不正确或者动画定义冲突。
* **用户操作如何到达这里:** 用户与页面交互触发了 CSS 动画或过渡效果，例如鼠标悬停导致元素属性发生变化。

**5. 强制合成更新 (`SetNeedsCompositingUpdate`)：**

* **功能:**  通知渲染引擎需要更新元素的合成层。这通常用于处理一些需要独立渲染层的情况，例如使用了 `will-change` 属性或某些特殊的 CSS 效果。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:**  JavaScript 可能会动态修改元素的样式，从而影响合成。
    * **HTML:**  HTML 结构定义了元素。
    * **CSS:** CSS 属性（如 `will-change`) 可以影响元素的合成。
* **假设输入与输出:**
    * **假设输入:**  一个元素的 `will-change` 属性被设置为 `transform`。
    * **输出:** `SetNeedsCompositingUpdate` 会被调用，确保该元素拥有独立的合成层，以便进行高效的变换动画。
* **用户或编程常见的使用错误:**  过度使用 `will-change` 可能导致性能下降。
* **用户操作如何到达这里:** 用户的操作可能触发了需要独立合成层的 CSS 效果或动画。

**6. 区域捕获裁剪 ID (`SetRegionCaptureCropId`, `GetRegionCaptureCropId`)：**

* **功能:**  设置和获取元素用于区域捕获的裁剪 ID。这可能与屏幕共享或录制等功能相关。
* **与 JavaScript, HTML, CSS 的关系:**  目前看来与标准的 JavaScript, HTML, CSS 关联较少，更可能是浏览器特定的扩展功能。
* **假设输入与输出:**
    * **假设输入:**  浏览器或应用程序发起对特定区域的捕获请求，并指定了裁剪区域。
    * **输出:**  `SetRegionCaptureCropId` 会将裁剪 ID 与目标元素关联。
* **用户或编程常见的使用错误:**  不当的裁剪 ID 配置可能导致捕获区域错误。
* **用户操作如何到达这里:**  用户发起屏幕共享或录制操作，并且选择了特定的区域进行捕获。

**7. 限制目标 ID 和元素捕获资格 (`SetRestrictionTargetId`, `GetRestrictionTargetId`, `SetIsEligibleForElementCapture`)：**

* **功能:**  设置元素的限制目标 ID，并标记元素是否符合元素捕获的条件。这与 "Element Capture" 功能相关，允许特定元素被屏幕共享或录制。
* **与 JavaScript, HTML, CSS 的关系:**  目前看来与标准的 JavaScript, HTML, CSS 关联较少，更可能是浏览器特定的扩展功能。
* **假设输入与输出:**
    * **假设输入:**  应用程序尝试限制屏幕共享或录制到特定的元素。
    * **输出:** `SetRestrictionTargetId` 会将该元素标记为限制目标，`SetIsEligibleForElementCapture` 会根据条件判断该元素是否符合资格。
* **用户或编程常见的使用错误:**  尝试限制不符合条件的元素。
* **用户操作如何到达这里:**  用户发起屏幕共享或录制操作，并且应用程序尝试将捕获范围限制到特定元素。

**8. 自定义元素管理 (`SetCustomElementDefinition`, `GetCustomElementDefinition`, `SetIsValue`, `IsValue`, `SetDidAttachInternals`, `DidAttachInternals`, `EnsureElementInternals`, `GetElementInternals`)：**

* **功能:**  管理自定义元素的相关信息，例如定义、`is` 属性值以及内部状态。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** 使用 `customElements.define()` 定义自定义元素。
    * **HTML:**  使用自定义元素标签或带有 `is` 属性的标准元素来实例化自定义元素。
    * **CSS:** 可以使用普通的 CSS 选择器来样式化自定义元素。
* **假设输入与输出:**
    * **假设输入:**  JavaScript 代码调用 `customElements.define('my-element', MyElementClass)`.
    * **输出:** `SetCustomElementDefinition` 会将 `MyElementClass` 的定义关联到 `my-element` 标签。当 HTML 中出现 `<my-element>` 时，会创建 `MyElementClass` 的实例。
* **用户或编程常见的使用错误:**  自定义元素定义不规范，或者生命周期回调函数处理不当。
* **用户操作如何到达这里:** 页面加载时，浏览器解析到自定义元素的定义和实例。

**9. Shadow DOM 管理 (`CanAttachShadowRoot`, `ErrorMessageForAttachShadow`, `attachShadow`, `AttachDeclarativeShadowRoot`, `CreateUserAgentShadowRoot`, `AttachShadowRootInternal`, `OpenShadowRoot`, `ClosedShadowRoot`, `AuthorShadowRoot`, `UserAgentShadowRoot`, `EnsureUserAgentShadowRoot`)：**

* **功能:**  处理 Shadow DOM 的创建、附加和访问。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** 使用 `element.attachShadow()` 方法创建 Shadow DOM。
    * **HTML:**  可以使用 `<template shadowrootmode="open|closed">` 声明式地创建 Shadow DOM。
    * **CSS:**  Shadow DOM 拥有自己的样式作用域，可以使用普通的 CSS 规则。
* **假设输入与输出:**
    * **假设输入:**  JavaScript 代码调用 `element.attachShadow({ mode: 'open' })`.
    * **输出:** `attachShadow` 函数会创建一个新的 ShadowRoot 对象并将其附加到 `element` 上。
* **用户或编程常见的使用错误:**  尝试在不支持 Shadow DOM 的元素上附加 Shadow DOM，或者不理解 Shadow DOM 的作用域规则。
* **用户操作如何到达这里:** 页面加载时，浏览器解析到 JavaScript 代码或声明式的 Shadow DOM 定义，并调用相应的 Shadow DOM 管理函数。

**10. 子节点类型检查 (`ChildTypeAllowed`)：**

* **功能:**  检查指定的节点类型是否允许作为当前元素的子节点。
* **与 JavaScript, HTML, CSS 的关系:**  与 HTML 文档的结构规则相关。
* **假设输入与输出:**
    * **假设输入:**  尝试将一个属性节点（`Attr`）添加到 `<div>` 元素中。
    * **输出:** `ChildTypeAllowed` 会返回 `false`，因为属性节点不能直接作为元素节点的子节点。
* **用户或编程常见的使用错误:**  尝试在 DOM 树中插入不合法的节点类型。
* **用户操作如何到达这里:**  JavaScript 代码尝试使用 `appendChild` 或 `insertBefore` 等方法添加子节点时，会进行类型检查。

**11. 空元素样式变化检查 (`CheckForEmptyStyleChange`)：**

* **功能:**  当元素的子节点发生变化时，检查是否影响了 `:empty` 伪类的状态，并触发相应的样式更新。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** JavaScript 的 DOM 操作会触发子节点变化。
    * **HTML:** HTML 结构定义了元素的子节点。
    * **CSS:** CSS 规则定义了 `:empty` 伪类激活时的样式。
* **假设输入与输出:**
    * **假设输入:**  一个空的 `<div>` 元素添加了一个子节点。
    * **输出:** `CheckForEmptyStyleChange` 会检测到子节点不再为空，并通知样式系统移除 `:empty` 伪类的样式。
* **用户或编程常见的使用错误:**  依赖 `:empty` 伪类来判断元素是否为空，但没有考虑到文本节点或注释节点。
* **用户操作如何到达这里:**  通过 JavaScript 添加或移除元素的子节点。

**12. 子节点变化通知 (`ChildrenChanged`)：**

* **功能:**  当元素的子节点发生改变时，执行一些必要的处理。代码片段中的注释提到可能与 `SetNeedsAssignmentRecalc` 相关，这暗示着与 Shadow DOM 的插槽 (slot) 分配有关。
* **与 JavaScript, HTML, CSS 的关系:**
    * **JavaScript:** JavaScript 的 DOM 操作会触发子节点变化。
    * **HTML:** HTML 结构定义了元素的子节点以及可能的插槽。
* **假设输入与输出:**
    * **假设输入:**  一个元素的子节点被添加、移除或替换。
    * **输出:** `ChildrenChanged` 会被调用，执行必要的更新，例如重新计算插槽分配。
* **用户操作如何到达这里:**  通过 JavaScript 操作 DOM 结构，或者由于浏览器解析 HTML 结构导致子节点发生变化。

**总结这部分代码的功能：**

这部分 `element.cc` 代码主要负责处理元素在样式、渲染、Shadow DOM 和自定义元素方面的各种状态变化和管理任务。它连接了 HTML 结构、CSS 样式和 JavaScript 行为，确保浏览器能够正确地渲染和更新页面，并支持 Web Components 等高级特性。它涉及到样式的重算、合成层的管理、Shadow DOM 的生命周期管理以及自定义元素的状态维护。  它在整个渲染流程中扮演着至关重要的角色，确保用户与页面的交互能够得到正确的视觉反馈。

Prompt: 
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共13部分，请归纳一下它的功能

"""
t();
  if (document.InStyleRecalc()) {
    return;
  }
  if (affected_by_pseudo.children_or_siblings ||
      affected_by_pseudo.ancestors_or_siblings) {
    document.GetStyleEngine().PseudoStateChangedForElement(
        pseudo, *this, affected_by_pseudo.children_or_siblings,
        affected_by_pseudo.ancestors_or_siblings);
  }
}

void Element::SetTargetedSnapAreaIdsForSnapContainers() {
  std::optional<cc::ElementId> targeted_area_id = std::nullopt;
  const LayoutBox* box = GetLayoutBox();
  while (box) {
    if (const ComputedStyle* style = box->Style()) {
      // If this is a snap area, associate it with the first snap area we
      // encountered, if any, since the previous snap container.
      if (box->IsScrollContainer() && !style->GetScrollSnapType().is_none) {
        if (auto* scrollable_area = box->GetScrollableArea()) {
          scrollable_area->SetTargetedSnapAreaId(targeted_area_id);
          GetDocument().View()->AddPendingSnapUpdate(scrollable_area);
        }
        targeted_area_id.reset();
      }
      // Only update |targeted_area_id| if we don't already have one so that we
      // prefer associating snap containers with their innermost snap targets.
      const auto& snap_align = style->GetScrollSnapAlign();
      if (!targeted_area_id &&
          (snap_align.alignment_block != cc::SnapAlignment::kNone ||
           snap_align.alignment_inline != cc::SnapAlignment::kNone)) {
        if (Node* node = box->GetNode()) {
          targeted_area_id =
              CompositorElementIdFromDOMNodeId(node->GetDomNodeId());
        }
        // Though not spec'd, we should prefer associating snap containers with
        // their innermost (in DOM hierarchy) snap areas.
        // This means we can skip any snap areas between this area and its snap
        // container.
        box = box->ContainingScrollContainer();
        continue;
      }
    }
    box = box->ContainingBlock();
  }
}

void Element::ClearTargetedSnapAreaIdsForSnapContainers() {
  const LayoutBox* box = GetLayoutBox();
  while (box) {
    if (const ComputedStyle* style = box->Style()) {
      if (box->IsScrollContainer() && !style->GetScrollSnapType().is_none) {
        if (auto* scrollable_area = box->GetScrollableArea()) {
          scrollable_area->SetTargetedSnapAreaId(std::nullopt);
        }
      }
    }
    box = box->ContainingBlock();
  }
}

Element::HighlightRecalc Element::CalculateHighlightRecalc(
    const ComputedStyle* old_style,
    const ComputedStyle& new_style,
    const ComputedStyle* parent_style) const {
  if (!new_style.HasAnyHighlightPseudoElementStyles()) {
    return HighlightRecalc::kNone;
  }
  // If we are a root element (our parent is a Document or ShadowRoot), we can
  // skip highlight recalc if there neither are nor were any non-UA highlight
  // rules (regardless of whether or not they are non-universal), and the root’s
  // effective zoom (‘zoom’ × page zoom × device scale factor) did not change.
  // In that case, we only need to calculate highlight styles once, because our
  // UA styles only use type selectors and we never change them dynamically.
  DCHECK(IsInTreeScope());
  if (parentNode() == GetTreeScope().RootNode()) {
    if (new_style.HasNonUaHighlightPseudoStyles()) {
      return HighlightRecalc::kFull;
    }
    if (old_style) {
      if (old_style->HasNonUaHighlightPseudoStyles()) {
        return HighlightRecalc::kFull;
      }
      if (old_style->EffectiveZoom() != new_style.EffectiveZoom()) {
        return HighlightRecalc::kFull;
      }
      // Neither the new style nor the old style has any non-UA highlight rules,
      // so they will be equal. Let’s reuse the old styles for all highlights.
      return HighlightRecalc::kReuse;
    }
    return HighlightRecalc::kFull;
  }

  // If the parent matched any non-universal highlight rules, then we need
  // to recalc, in case there are universal highlight rules.
  bool parent_non_universal =
      parent_style != nullptr &&
      parent_style->HasNonUniversalHighlightPseudoStyles();

  // If we matched any non-universal highlight rules, then we need to recalc
  // and our children also need to recalc (see above).
  bool self_non_universal = new_style.HasNonUniversalHighlightPseudoStyles();

  if (parent_non_universal || self_non_universal) {
    return HighlightRecalc::kFull;
  }

  // If the parent has any relative units then we may need
  // recalc to capture sizes from the originating element. But note that
  // self will be recalculated regardless if self has its own non-universal
  // pseudo style.
  if (parent_style != nullptr &&
      parent_style->HighlightPseudoElementStylesDependOnRelativeUnits()) {
    return HighlightRecalc::kOriginatingDependent;
  }

  // If the parent style depends on custom properties we may need recalc
  // in the event the originating element has changed the values for those
  // properties.
  if (parent_style != nullptr &&
      parent_style->HighlightPseudoElementStylesHaveVariableReferences()) {
    return HighlightRecalc::kOriginatingDependent;
  }
  return HighlightRecalc::kNone;
}

bool Element::ShouldRecalcHighlightPseudoStyle(
    HighlightRecalc highlight_recalc,
    const ComputedStyle* highlight_parent,
    const ComputedStyle& originating_style,
    const Element* originating_container) const {
  if (highlight_recalc == HighlightRecalc::kFull) {
    return true;
  }
  DCHECK(highlight_recalc == HighlightRecalc::kOriginatingDependent);
  // If the highlight depends on variables and the variables on the
  // originating element have changed, we need to re-evaluate.
  if (highlight_parent && highlight_parent->HasVariableReference() &&
      (originating_style.InheritedVariables() !=
           highlight_parent->InheritedVariables() ||
       originating_style.NonInheritedVariables() !=
           highlight_parent->NonInheritedVariables())) {
    return true;
  }
  // Font relative units must be recomputed if the font size has changed.
  if (highlight_parent && highlight_parent->HasFontRelativeUnits() &&
      originating_style.SpecifiedFontSize() !=
          highlight_parent->SpecifiedFontSize()) {
    return true;
  }
  // If the originating element is a container for sizes, it means the
  // container has changed from that of the parent highlight, so we need
  // to re-evaluate container units.
  if (highlight_parent && highlight_parent->HasContainerRelativeUnits() &&
      originating_container == this &&
      originating_style.CanMatchSizeContainerQueries(*this)) {
    return true;
  }
  // If there are logical direction relative units and the writing mode is
  // different from that of the parent, we need to re-evaluate the units.
  if (highlight_parent &&
      highlight_parent->HasLogicalDirectionRelativeUnits() &&
      originating_style.IsHorizontalWritingMode() !=
          highlight_parent->IsHorizontalWritingMode()) {
    return true;
  }
  // We do not need to return true for viewport unit dependencies because the
  // parent, if there is one, will have the same viewport dimensions. If the
  // parent otherwise has different units we must have already decided to do
  // a recalc.
  return false;
}

void Element::RecalcCustomHighlightPseudoStyle(
    const StyleRecalcContext& style_recalc_context,
    HighlightRecalc highlight_recalc,
    ComputedStyleBuilder& builder,
    const StyleHighlightData* parent_highlights,
    const ComputedStyle& originating_style) {
  const HashSet<AtomicString>* highlight_names =
      originating_style.CustomHighlightNames();
  if (!highlight_names) {
    return;
  }

  StyleHighlightData& highlights = builder.AccessHighlightData();
  for (auto highlight_name : *highlight_names) {
    const ComputedStyle* highlight_parent =
        parent_highlights ? parent_highlights->CustomHighlight(highlight_name)
                          : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc, highlight_parent,
                                         originating_style,
                                         style_recalc_context.container)) {
      const ComputedStyle* highlight_style = StyleForHighlightPseudoElement(
          style_recalc_context, highlight_parent, originating_style,
          kPseudoIdHighlight, highlight_name);
      if (highlight_style) {
        highlights.SetCustomHighlight(highlight_name, highlight_style);
      }
    }
  }
}

const ComputedStyle* Element::RecalcHighlightStyles(
    const StyleRecalcContext& style_recalc_context,
    const ComputedStyle* old_style,
    const ComputedStyle& new_style,
    const ComputedStyle* parent_style) {
  HighlightRecalc highlight_recalc =
      CalculateHighlightRecalc(old_style, new_style, parent_style);
  if (highlight_recalc == HighlightRecalc::kNone) {
    return &new_style;
  }

  ComputedStyleBuilder builder(new_style);

  if (highlight_recalc == HighlightRecalc::kReuse) {
    DCHECK(old_style);
    builder.SetHighlightData(old_style->HighlightData());
    return builder.TakeStyle();
  }

  const StyleHighlightData* parent_highlights =
      parent_style ? &parent_style->HighlightData() : nullptr;

  if (UsesHighlightPseudoInheritance(kPseudoIdSelection) &&
      new_style.HasPseudoElementStyle(kPseudoIdSelection)) {
    const ComputedStyle* highlight_parent =
        parent_highlights ? parent_highlights->Selection() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc, highlight_parent,
                                         new_style,
                                         style_recalc_context.container)) {
      builder.AccessHighlightData().SetSelection(
          StyleForHighlightPseudoElement(style_recalc_context, highlight_parent,
                                         new_style, kPseudoIdSelection));
    }
  }

  if (RuntimeEnabledFeatures::SearchTextHighlightPseudoEnabled() &&
      UsesHighlightPseudoInheritance(kPseudoIdSearchText) &&
      new_style.HasPseudoElementStyle(kPseudoIdSearchText)) {
    const ComputedStyle* highlight_parent_current =
        parent_highlights ? parent_highlights->SearchTextCurrent() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc,
                                         highlight_parent_current, new_style,
                                         style_recalc_context.container)) {
      builder.AccessHighlightData().SetSearchTextCurrent(
          StyleForSearchTextPseudoElement(style_recalc_context,
                                          highlight_parent_current, new_style,
                                          StyleRequest::kCurrent));
    }
    const ComputedStyle* highlight_parent_not_current =
        parent_highlights ? parent_highlights->SearchTextNotCurrent() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(
            highlight_recalc, highlight_parent_not_current, new_style,
            style_recalc_context.container)) {
      builder.AccessHighlightData().SetSearchTextNotCurrent(
          StyleForSearchTextPseudoElement(
              style_recalc_context, highlight_parent_not_current, new_style,
              StyleRequest::kNotCurrent));
    }
  }

  if (UsesHighlightPseudoInheritance(kPseudoIdTargetText) &&
      new_style.HasPseudoElementStyle(kPseudoIdTargetText)) {
    const ComputedStyle* highlight_parent =
        parent_highlights ? parent_highlights->TargetText() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc, highlight_parent,
                                         new_style,
                                         style_recalc_context.container)) {
      builder.AccessHighlightData().SetTargetText(
          StyleForHighlightPseudoElement(style_recalc_context, highlight_parent,
                                         new_style, kPseudoIdTargetText));
    }
  }

  if (UsesHighlightPseudoInheritance(kPseudoIdSpellingError) &&
      new_style.HasPseudoElementStyle(kPseudoIdSpellingError)) {
    const ComputedStyle* highlight_parent =
        parent_highlights ? parent_highlights->SpellingError() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc, highlight_parent,
                                         new_style,
                                         style_recalc_context.container)) {
      builder.AccessHighlightData().SetSpellingError(
          StyleForHighlightPseudoElement(style_recalc_context, highlight_parent,
                                         new_style, kPseudoIdSpellingError));
    }
  }

  if (UsesHighlightPseudoInheritance(kPseudoIdGrammarError) &&
      new_style.HasPseudoElementStyle(kPseudoIdGrammarError)) {
    const ComputedStyle* highlight_parent =
        parent_highlights ? parent_highlights->GrammarError() : nullptr;
    if (ShouldRecalcHighlightPseudoStyle(highlight_recalc, highlight_parent,
                                         new_style,
                                         style_recalc_context.container)) {
      builder.AccessHighlightData().SetGrammarError(
          StyleForHighlightPseudoElement(style_recalc_context, highlight_parent,
                                         new_style, kPseudoIdGrammarError));
    }
  }

  if (UsesHighlightPseudoInheritance(kPseudoIdHighlight) &&
      new_style.HasPseudoElementStyle(kPseudoIdHighlight)) {
    RecalcCustomHighlightPseudoStyle(style_recalc_context, highlight_recalc,
                                     builder, parent_highlights, new_style);
  }

  return builder.TakeStyle();
}

void Element::SetAnimationStyleChange(bool animation_style_change) {
  if (animation_style_change && GetDocument().InStyleRecalc()) {
    return;
  }

  if (ElementRareDataVector* data = GetElementRareData()) {
    if (ElementAnimations* element_animations = data->GetElementAnimations()) {
      element_animations->SetAnimationStyleChange(animation_style_change);
    }
  }
}

void Element::SetNeedsAnimationStyleRecalc() {
  if (GetDocument().InStyleRecalc()) {
    return;
  }
  if (GetDocument().GetStyleEngine().InApplyAnimationUpdate()) {
    return;
  }
  if (GetStyleChangeType() != kNoStyleChange) {
    return;
  }

  SetNeedsStyleRecalc(kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                             style_change_reason::kAnimation));

  // Setting this flag to 'true' only makes sense if there's an existing style,
  // otherwise there is no previous style to use as the basis for the new one.
  if (NeedsStyleRecalc() && GetComputedStyle() &&
      !GetComputedStyle()->IsEnsuredInDisplayNone()) {
    SetAnimationStyleChange(true);
  }
}

void Element::SetNeedsCompositingUpdate() {
  if (!GetDocument().IsActive()) {
    return;
  }
  LayoutBoxModelObject* layout_object = GetLayoutBoxModelObject();
  if (!layout_object) {
    return;
  }

  auto* painting_layer = layout_object->PaintingLayer();
  // Repaint because the foreign layer may have changed.
  painting_layer->SetNeedsRepaint();

  // Changes to AdditionalCompositingReasons can change direct compositing
  // reasons which affect paint properties.
  if (layout_object->CanHaveAdditionalCompositingReasons()) {
    layout_object->SetNeedsPaintPropertyUpdate();
  }
}

void Element::SetRegionCaptureCropId(
    std::unique_ptr<RegionCaptureCropId> crop_id) {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  CHECK(!rare_data.GetRegionCaptureCropId());

  // Propagate efficient form through the rendering pipeline.
  rare_data.SetRegionCaptureCropId(std::move(crop_id));

  // If a LayoutObject does not yet exist, this full paint invalidation
  // will occur automatically after it is created.
  if (LayoutObject* layout_object = GetLayoutObject()) {
    // The SubCaptureTarget ID needs to be propagated to the paint system.
    layout_object->SetShouldDoFullPaintInvalidation();
  }
}

const RegionCaptureCropId* Element::GetRegionCaptureCropId() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetRegionCaptureCropId();
  }
  return nullptr;
}

void Element::SetRestrictionTargetId(std::unique_ptr<RestrictionTargetId> id) {
  CHECK(RuntimeEnabledFeatures::ElementCaptureEnabled(GetExecutionContext()));

  ElementRareDataVector& rare_data = EnsureElementRareData();
  CHECK(!rare_data.GetRestrictionTargetId());

  // Propagate efficient form through the rendering pipeline.
  // This has the intended side effect of forcing the element
  // into its own stacking context during rendering.
  rare_data.SetRestrictionTargetId(std::move(id));

  // If a LayoutObject does not yet exist, this full paint invalidation
  // will occur automatically after it is created.
  if (LayoutObject* layout_object = GetLayoutObject()) {
    // The paint properties need to updated, even though the style hasn't
    // changed.
    layout_object->SetNeedsPaintPropertyUpdate();

    // The SubCaptureTarget ID needs to be propagated to the paint system.
    layout_object->SetShouldDoFullPaintInvalidation();
  }
}

const RestrictionTargetId* Element::GetRestrictionTargetId() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetRestrictionTargetId();
  }
  return nullptr;
}

void Element::SetIsEligibleForElementCapture(bool value) {
  CHECK(GetRestrictionTargetId());

  const bool has_checked =
      HasElementFlag(ElementFlags::kHasCheckedElementCaptureEligibility);
  if (!has_checked) {
    SetElementFlag(ElementFlags::kHasCheckedElementCaptureEligibility, true);
  }

  if (has_checked) {
    const bool old_value =
        HasElementFlag(ElementFlags::kIsEligibleForElementCapture);

    if (value != old_value) {
      AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kInfo,
          String::Format("restrictTo(): Element %s restriction eligibility. "
                         "For eligibility conditions, see "
                         "https://screen-share.github.io/element-capture/"
                         "#elements-eligible-for-restriction",
                         value ? "gained" : "lost"));
    }
  } else {
    // We want to issue a different log message if the element is not eligible
    // when first painted.
    if (!value) {
      AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kRendering,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "restrictTo(): Element is not eligible for restriction. For "
          "eligibility conditions, see "
          "https://screen-share.github.io/element-capture/"
          "#elements-eligible-for-restriction");
    }
  }

  return SetElementFlag(ElementFlags::kIsEligibleForElementCapture, value);
}

void Element::SetCustomElementDefinition(CustomElementDefinition* definition) {
  DCHECK(definition);
  DCHECK(!GetCustomElementDefinition());
  EnsureElementRareData().SetCustomElementDefinition(definition);
  SetCustomElementState(CustomElementState::kCustom);
}

CustomElementDefinition* Element::GetCustomElementDefinition() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetCustomElementDefinition();
  }
  return nullptr;
}

void Element::SetIsValue(const AtomicString& is_value) {
  DCHECK(IsValue().IsNull()) << "SetIsValue() should be called at most once.";
  EnsureElementRareData().SetIsValue(is_value);
}

const AtomicString& Element::IsValue() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->IsValue();
  }
  return g_null_atom;
}

void Element::SetDidAttachInternals() {
  EnsureElementRareData().SetDidAttachInternals();
}

bool Element::DidAttachInternals() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->DidAttachInternals();
  }
  return false;
}

ElementInternals& Element::EnsureElementInternals() {
  return EnsureElementRareData().EnsureElementInternals(To<HTMLElement>(*this));
}

const ElementInternals* Element::GetElementInternals() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->GetElementInternals();
  }
  return nullptr;
}

bool Element::CanAttachShadowRoot() const {
  const AtomicString& local_name = localName();
  // Checking IsCustomElement() here is just an optimization
  // because IsValidName is not cheap.
  return (IsCustomElement() && CustomElement::IsValidName(local_name)) ||
         IsValidShadowHostName(local_name);
}

const char* Element::ErrorMessageForAttachShadow(
    String mode,
    bool for_declarative,
    ShadowRootMode& mode_out) const {
  // https://dom.spec.whatwg.org/#concept-attach-a-shadow-root
  // 1. If shadow host’s namespace is not the HTML namespace, then throw a
  // "NotSupportedError" DOMException.
  // 2. If shadow host’s local name is not a valid custom element name,
  // "article", "aside", "blockquote", "body", "div", "footer", "h1", "h2",
  // "h3", "h4", "h5", "h6", "header", "main", "nav", "p", "section", or "span",
  // then throw a "NotSupportedError" DOMException.
  if (!CanAttachShadowRoot()) {
    return "This element does not support attachShadow";
  }

  // 3. If shadow host’s local name is a valid custom element name, or shadow
  // host’s is value is not null, then:
  // 3.1 Let definition be the result of looking up a custom element
  // definition given shadow host’s node document, its namespace, its local
  // name, and its is value.
  // 3.2 If definition is not null and definition’s
  // disable shadow is true, then throw a "NotSupportedError" DOMException.
  // Note: Checking IsCustomElement() is just an optimization because
  // IsValidName() is not cheap.
  if (IsCustomElement() &&
      (CustomElement::IsValidName(localName()) || !IsValue().IsNull())) {
    auto* registry = CustomElement::Registry(*this);
    auto* definition =
        registry ? registry->DefinitionForName(IsValue().IsNull() ? localName()
                                                                  : IsValue())
                 : nullptr;
    if (definition && definition->DisableShadow()) {
      return "attachShadow() is disabled by disabledFeatures static field.";
    }
  }
  if (EqualIgnoringASCIICase(mode, keywords::kOpen)) {
    mode_out = ShadowRootMode::kOpen;
  } else if (EqualIgnoringASCIICase(mode, keywords::kClosed)) {
    mode_out = ShadowRootMode::kClosed;
  } else {
    CHECK(for_declarative);
    return "Invalid declarative shadowrootmode attribute value. Valid values "
           "are \"open\" and \"closed\".";
  }

  if (!GetShadowRoot()) {
    return nullptr;
  }
  // If shadow host has a non-null shadow root and "for declarative" is set,
  // then throw a "NotSupportedError" DOMException.
  if (for_declarative) {
    return "A second declarative shadow root cannot be created on a host.";
  }
  // If shadow host has a non-null shadow root, "for declarative" is unset,
  // and shadow root's "is declarative shadow root" property is false, then
  // throw a "NotSupportedError" DOMException.
  if (!GetShadowRoot()->IsDeclarativeShadowRoot()) {
    return "Shadow root cannot be created on a host which already hosts a "
           "shadow tree.";
  }
  return nullptr;
}

ShadowRoot* Element::attachShadow(const ShadowRootInit* shadow_root_init_dict,
                                  ExceptionState& exception_state) {
  DCHECK(shadow_root_init_dict->hasMode());
  String mode_string =
      V8ShadowRootModeToString(shadow_root_init_dict->mode().AsEnum());
  bool serializable = shadow_root_init_dict->getSerializableOr(false);
  if (serializable) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kElementAttachSerializableShadow);
  }
  bool clonable = shadow_root_init_dict->getClonableOr(false);

  auto focus_delegation = (shadow_root_init_dict->hasDelegatesFocus() &&
                           shadow_root_init_dict->delegatesFocus())
                              ? FocusDelegation::kDelegateFocus
                              : FocusDelegation::kNone;
  auto slot_assignment = (shadow_root_init_dict->hasSlotAssignment() &&
                          shadow_root_init_dict->slotAssignment() == "manual")
                             ? SlotAssignmentMode::kManual
                             : SlotAssignmentMode::kNamed;
  auto reference_target =
      shadow_root_init_dict->hasReferenceTarget()
          ? AtomicString(shadow_root_init_dict->referenceTarget())
          : g_null_atom;
  CustomElementRegistry* registry = shadow_root_init_dict->hasRegistry()
                                        ? shadow_root_init_dict->registry()
                                        : nullptr;
  ShadowRootMode mode;
  if (const char* error_message = ErrorMessageForAttachShadow(
          mode_string, /*for_declarative*/ false, mode)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      error_message);
    return nullptr;
  }

  switch (mode) {
    case ShadowRootMode::kOpen:
      UseCounter::Count(GetDocument(), WebFeature::kElementAttachShadowOpen);
      break;
    case ShadowRootMode::kClosed:
      UseCounter::Count(GetDocument(), WebFeature::kElementAttachShadowClosed);
      break;
    case ShadowRootMode::kUserAgent:
      NOTREACHED();
  }

  // If there's already a declarative shadow root, verify that the existing
  // mode is the same as the requested mode.
  if (auto* existing_shadow = GetShadowRoot()) {
    CHECK(existing_shadow->IsDeclarativeShadowRoot());
    if (existing_shadow->GetMode() != mode) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotSupportedError,
          "The requested mode does not match the existing declarative shadow "
          "root's mode");
      return nullptr;
    }
  }

  ShadowRoot& shadow_root = AttachShadowRootInternal(
      mode, focus_delegation, slot_assignment, registry, serializable, clonable,
      reference_target);

  // Ensure that the returned shadow root is not marked as declarative so that
  // attachShadow() calls after the first one do not succeed for a shadow host
  // with a declarative shadow root.
  shadow_root.SetIsDeclarativeShadowRoot(false);
  return &shadow_root;
}

bool Element::AttachDeclarativeShadowRoot(
    HTMLTemplateElement& template_element,
    String mode_string,
    FocusDelegation focus_delegation,
    SlotAssignmentMode slot_assignment,
    bool serializable,
    bool clonable,
    const AtomicString& reference_target) {
  // 12. Run attach a shadow root with shadow host equal to declarative shadow
  // host element, mode equal to declarative shadow mode, and delegates focus
  // equal to declarative shadow delegates focus. If an exception was thrown by
  // attach a shadow root, catch it, and ignore the exception.
  ShadowRootMode mode;
  if (const char* error_message = ErrorMessageForAttachShadow(
          mode_string, /*for_declarative*/ true, mode)) {
    GetDocument().AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError, error_message));
    return false;
  }
  CHECK(mode == ShadowRootMode::kOpen || mode == ShadowRootMode::kClosed);

  // TODO(crbug.com/1523816): Declarative shadow roots should set the registry
  // argument here.
  ShadowRoot& shadow_root = AttachShadowRootInternal(
      mode, focus_delegation, slot_assignment,
      /*registry*/ nullptr, serializable, clonable, reference_target);
  // 13.1. Set declarative shadow host element's shadow host's "is declarative
  // shadow root" property to true.
  shadow_root.SetIsDeclarativeShadowRoot(true);
  // 13.NEW. Set declarative shadow host element's shadow host's "available
  // to element internals" to true.
  shadow_root.SetAvailableToElementInternals(true);
  return true;
}

ShadowRoot& Element::CreateUserAgentShadowRoot(SlotAssignmentMode mode) {
  DCHECK(!GetShadowRoot());
  GetDocument().SetContainsShadowRoot();
  return CreateAndAttachShadowRoot(ShadowRootMode::kUserAgent, mode);
}

ShadowRoot& Element::AttachShadowRootInternal(
    ShadowRootMode type,
    FocusDelegation focus_delegation,
    SlotAssignmentMode slot_assignment_mode,
    CustomElementRegistry* registry,
    bool serializable,
    bool clonable,
    const AtomicString& reference_target) {
  // SVG <use> is a special case for using this API to create a closed shadow
  // root.
  DCHECK(CanAttachShadowRoot() || IsA<SVGUseElement>(*this));
  DCHECK(type == ShadowRootMode::kOpen || type == ShadowRootMode::kClosed)
      << type;
  DCHECK(!AlwaysCreateUserAgentShadowRoot());
  DCHECK(reference_target.IsNull() ||
         RuntimeEnabledFeatures::ShadowRootReferenceTargetEnabled());

  GetDocument().SetContainsShadowRoot();

  if (auto* shadow_root = GetShadowRoot()) {
    // NEW. If shadow host has a non-null shadow root whose "is declarative
    // shadow root property is true, then remove all of shadow root’s children,
    // in tree order. Return shadow host’s shadow root.
    DCHECK(shadow_root->IsDeclarativeShadowRoot());
    shadow_root->RemoveChildren();
    return *shadow_root;
  }

  // 5. Let shadow be a new shadow root whose node document is this’s node
  // document, host is this, and mode is init’s mode.
  ShadowRoot& shadow_root =
      CreateAndAttachShadowRoot(type, slot_assignment_mode);
  // 6. Set shadow’s delegates focus to init’s delegatesFocus.
  shadow_root.SetDelegatesFocus(focus_delegation ==
                                FocusDelegation::kDelegateFocus);
  // 9. Set shadow’s declarative to false.
  shadow_root.SetIsDeclarativeShadowRoot(false);

  shadow_root.SetRegistry(registry);
  // 11. Set shadow’s serializable to serializable.
  shadow_root.setSerializable(serializable);
  // 10. Set shadow’s clonable to clonable.
  shadow_root.setClonable(clonable);
  // NEW. Set reference target.
  shadow_root.setReferenceTarget(reference_target);

  // 7. If this’s custom element state is "precustomized" or "custom", then set
  // shadow’s available to element internals to true.
  shadow_root.SetAvailableToElementInternals(
      !(IsCustomElement() &&
        GetCustomElementState() != CustomElementState::kCustom &&
        GetCustomElementState() != CustomElementState::kPreCustomized));

  // 8. Set this’s shadow root to shadow.
  return shadow_root;
}

ShadowRoot* Element::OpenShadowRoot() const {
  ShadowRoot* root = GetShadowRoot();
  return root && root->GetMode() == ShadowRootMode::kOpen ? root : nullptr;
}

ShadowRoot* Element::ClosedShadowRoot() const {
  ShadowRoot* root = GetShadowRoot();
  if (!root) {
    return nullptr;
  }
  return root->GetMode() == ShadowRootMode::kClosed ? root : nullptr;
}

ShadowRoot* Element::AuthorShadowRoot() const {
  ShadowRoot* root = GetShadowRoot();
  if (!root) {
    return nullptr;
  }
  return !root->IsUserAgent() ? root : nullptr;
}

ShadowRoot* Element::UserAgentShadowRoot() const {
  ShadowRoot* root = GetShadowRoot();
  DCHECK(!root || root->IsUserAgent());
  return root;
}

ShadowRoot& Element::EnsureUserAgentShadowRoot(SlotAssignmentMode mode) {
  if (ShadowRoot* shadow_root = UserAgentShadowRoot()) {
    CHECK_EQ(shadow_root->GetMode(), ShadowRootMode::kUserAgent);
    CHECK_EQ(shadow_root->GetSlotAssignmentMode(), mode);
    return *shadow_root;
  }
  ShadowRoot& shadow_root = CreateUserAgentShadowRoot(mode);
  DidAddUserAgentShadowRoot(shadow_root);
  return shadow_root;
}

bool Element::ChildTypeAllowed(NodeType type) const {
  switch (type) {
    case kElementNode:
    case kTextNode:
    case kCommentNode:
    case kProcessingInstructionNode:
    case kCdataSectionNode:
      return true;
    default:
      break;
  }
  return false;
}

namespace {

bool HasSiblingsForNonEmpty(const Node* sibling,
                            Node* (*next_func)(const Node&)) {
  for (; sibling; sibling = next_func(*sibling)) {
    if (sibling->IsElementNode()) {
      return true;
    }
    auto* text_node = DynamicTo<Text>(sibling);
    if (text_node && !text_node->data().empty()) {
      return true;
    }
  }
  return false;
}

}  // namespace

void Element::CheckForEmptyStyleChange(const Node* node_before_change,
                                       const Node* node_after_change) {
  if (!InActiveDocument()) {
    return;
  }
  if (!StyleAffectedByEmpty()) {
    return;
  }
  if (HasSiblingsForNonEmpty(node_before_change,
                             NodeTraversal::PreviousSibling) ||
      HasSiblingsForNonEmpty(node_after_change, NodeTraversal::NextSibling)) {
    return;
  }
  PseudoStateChanged(CSSSelector::kPseudoEmpty);
}

void Element::ChildrenChanged(const ChildrenChange& change) {
  // ContainerNode::ChildrenChanged may run SynchronousMutationObservers which
  // want to do flat tree traversals. If we SetNeedsAssignmentRecalc after those
  // mutation observers
"""


```