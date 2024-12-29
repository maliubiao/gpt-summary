Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/svg/svg_element.cc`. This is the second part of a two-part request, so I need to synthesize the information from both parts to provide a comprehensive overview.

Here's a breakdown of the code's functionalities and their relation to web technologies:

1. **Attribute Handling:** Processing and reacting to changes in SVG attributes.
2. **Event Handling:** Managing event listeners for SVG elements, including handling shadow DOM scenarios.
3. **Resource Loading:**  Determining if required resources for the SVG element have been loaded and triggering 'load' events.
4. **Style Management:** Handling presentation attributes and their impact on styling, including interactions with CSS.
5. **Animation:** Supporting SMIL and potentially Web Animations for SVG elements.
6. **Layout:**  Interacting with the layout engine to determine if a layout object is needed for the SVG element.
7. **Referencing and Instancing:** Managing how SVG elements can reference other elements (e.g., via `<use>`) and invalidating these instances when the referenced element changes.
8. **SVG Resource Management:**  Participating in the SVG resource management system.
9. **Synchronization:** Ensuring that the underlying attribute values and the animated values are in sync.

I need to connect these functionalities to JavaScript, HTML, and CSS where applicable, provide examples, and consider potential user errors. I should also be mindful of how a user's actions in a web browser might lead to the execution of this code.

**Plan:**

*   Summarize the functions in the provided code snippet.
*   Connect these functions to the broader functionality of `SVGElement` as described in the first part.
*   Illustrate the relationships with JavaScript, HTML, and CSS with concrete examples.
*   Consider user errors.
*   Describe user interactions that might trigger this code.
这是`blink/renderer/core/svg/svg_element.cc`文件第二部分代码的功能归纳：

**核心功能：SVG 元素的动态行为和属性管理**

这部分代码主要负责处理 SVG 元素在运行时发生的各种变化，以及如何将这些变化反映到渲染和交互中。它关注的是 SVG 元素的动态行为，例如属性变更、事件处理、动画以及与其他 SVG 元素的关联。

**具体功能点：**

1. **语言属性处理 (`MapLanguageAttributeToLocale`):**
    *   当 `lang` 或 `xml:lang` 属性发生变化时，将语言信息映射到元素的样式中，以便进行正确的文本渲染。
    *   **与 HTML 的关系：** HTML 元素也有 `lang` 属性，其作用类似。SVG 元素也遵循这一标准，确保在文档中语言设置的一致性。
    *   **假设输入与输出：**
        *   **输入：** SVG 元素设置了 `lang="fr"` 属性。
        *   **输出：** 元素的样式信息中会包含 `lang: fr;`，影响字体选择和排版。

2. **资源加载状态检查 (`HaveLoadedRequiredResources`):**
    *   递归地检查当前 SVG 元素及其所有子元素是否已加载所需的资源（例如外部图片或字体）。
    *   **与 HTML 的关系：** HTML 中的 `<img>` 和 `<link>` 等元素也有加载资源的概念。SVG 元素需要确保所有依赖资源都已加载完毕才能正常渲染。

3. **事件监听器管理 ( `AddedEventListener`, `RemovedEventListener`):**
    *   除了在自身添加/移除事件监听器外，还会同步地在 shadow DOM 中的实例上添加/移除相同的监听器。这确保了事件能够正确地传播到所有实例化的 SVG 元素。
    *   **与 JavaScript 的关系：** 这是 JavaScript 中事件驱动编程的核心机制。通过这些函数，JavaScript 代码可以使用 `addEventListener` 和 `removeEventListener` 来监听 SVG 元素上的事件。
    *   **假设输入与输出：**
        *   **输入：** JavaScript 调用 `element.addEventListener('click', handler)`，其中 `element` 是一个 SVG 元素，并且该元素被 `<use>` 实例化了多次。
        *   **输出：**  `AddedEventListener` 会被调用，不仅会在原始的 `element` 上添加监听器，也会在所有通过 `<use>` 创建的实例上添加相同的监听器。

4. **'load' 事件发送 (`SendSVGLoadEventIfPossible`, `SendSVGLoadEventToSelfAndAncestorChainIfPossible`):**
    *   在所有必需的资源加载完成后，并且该元素是外部资源或根 SVG 元素，并且有 'load' 事件监听器时，会触发 'load' 事件。
    *   **与 HTML 和 JavaScript 的关系：**  类似于 HTML 的 `window.onload` 或 `img.onload`，SVG 的 'load' 事件表示 SVG 文档或元素已加载完成，JavaScript 可以监听此事件执行初始化操作。
    *   **用户操作到达这里的路径：** 用户在浏览器中打开包含 SVG 的页面，浏览器解析 SVG 并开始加载资源。当所有资源加载完毕，并且满足条件时，会执行到这些函数来触发 'load' 事件。

5. **属性变更处理 (`AttributeChanged`):**
    *   当 SVG 元素的属性发生变化时被调用。
    *   它会更新与该属性关联的动画属性对象 (`SVGAnimatedPropertyBase`)。
    *   对于 `class` 属性，会触发 `ClassAttributeChanged` 来更新类名列表。
    *   对于 `style` 属性，由于样式属性是延迟处理的，这里不做额外操作。
    *   对于其他影响样式的属性，会调用 `UpdatePresentationAttributeStyle` 来更新元素的呈现样式。
    *   会调用 `InvalidateInstances()` 来通知所有引用该元素的 `<use>` 元素需要更新。
    *   **与 HTML、CSS 和 JavaScript 的关系：**
        *   **HTML:**  属性是 HTML 元素的基本构成部分，SVG 元素也继承了这一概念。
        *   **CSS:** 许多 SVG 属性（如 `fill`, `stroke` 等）可以作为 CSS 属性来控制元素的样式。`AttributeChanged` 中对 `UpdatePresentationAttributeStyle` 的调用会将属性的变化同步到元素的样式中。
        *   **JavaScript:**  JavaScript 可以通过 `setAttribute` 等方法修改 SVG 元素的属性，从而触发 `AttributeChanged`。
    *   **假设输入与输出：**
        *   **输入：** JavaScript 代码执行 `element.setAttribute('fill', 'red')`。
        *   **输出：** `AttributeChanged` 会被调用，更新 `fill` 属性对应的 `SVGAnimatedPropertyBase` 对象，并最终导致元素的填充颜色变为红色。

6. **SVG 动画属性变更处理 (`SvgAttributeChanged`):**
    *   当 `SVGAnimatedPropertyBase` 的值发生变化时被调用。
    *   专门处理 `class` 属性的变更。

7. **基础值变更处理 (`BaseValueChanged`):**
    *   当 SVG 动画属性的基础值（非动画值）发生变化时被调用。
    *   标记 SVG 属性为脏，并触发 `SvgAttributeChanged`。
    *   更新 `class` 属性的类名列表。
    *   通知 Web Animations 系统属性的基础值已更新。

8. **Web Animations 集成 (`UpdateWebAnimatedAttributeOnBaseValChange`, `EnsureAttributeAnimValUpdated`):**
    *   处理 Web Animations API 对 SVG 属性的影响。
    *   当动画属性的基础值改变时，通知 Web Animations 系统。
    *   确保在需要时更新动画效果。
    *   **与 JavaScript 的关系：** Web Animations API 是 JavaScript 中进行动画控制的标准方式。这些函数将 SVG 元素的属性变化与 Web Animations 系统同步。

9. **SVG 属性同步 (`SynchronizeSVGAttribute`, `SynchronizeAllSVGAttributes`):**
    *   确保 SVG 属性的内部表示与 DOM 属性值同步。这对于处理动画和脚本修改非常重要。

10. **呈现属性样式更新 (`GetPresentationAttributeStyleForDirectUpdate`, `UpdatePresentationAttributeStyle`, `AddAnimatedPropertyToPresentationAttributeStyle`):**
    *   管理 SVG 元素的呈现属性样式。
    *   提供直接更新样式的优化路径。
    *   处理动画属性对呈现样式的影响。
    *   **与 CSS 的关系：** 这些函数负责将 SVG 属性的值转换为 CSS 样式规则，从而影响元素的渲染。

11. **自定义样式处理 (`CustomStyleForLayoutObject`):**
    *   为 SVG 元素创建自定义样式对象，用于布局计算。
    *   在处理通过 `<use>` 实例化的元素时，会使用对应原始元素的样式信息。

12. **布局对象需求判断 (`LayoutObjectIsNeeded`, `HasSVGParent`):**
    *   确定 SVG 元素是否需要创建布局对象。
    *   只有当 SVG 元素有效且有 SVG 父元素时，才需要布局对象。

13. **SMIL 动画支持 (`AnimatedSMILStyleProperties`, `EnsureAnimatedSMILStyleProperties`, `BaseComputedStyleForSMIL`, `GetTimeContainer`):**
    *   支持 SVG 的 SMIL 动画特性。
    *   管理 SMIL 动画产生的样式属性。
    *   获取用于 SMIL 动画计算的基础样式。
    *   获取时间容器，用于控制动画的时间。
    *   **与 JavaScript 的关系：** 虽然 SMIL 是声明式动画，但 JavaScript 可以通过 DOM API 与 SMIL 动画进行交互。

14. **焦点事件监听 (`HasFocusEventListeners`):**
    *   检查元素是否注册了焦点相关的事件监听器。

15. **布局和资源失效通知 (`MarkForLayoutAndParentResourceInvalidation`, `NotifyResourceClients`):**
    *   在需要时标记元素及其父元素进行重新布局和资源失效。
    *   通知依赖于当前 SVG 资源的客户端（例如其他 SVG 元素）其内容已发生变化。

16. **实例管理和失效 (`InvalidateInstances`, `SetNeedsStyleRecalcForInstances`):**
    *   维护所有通过 `<use>` 元素引用的当前 SVG 元素的实例集合。
    *   当原始元素发生变化时，通知所有实例需要更新（重新构建 shadow tree 或重新计算样式）。
    *   **与 HTML 的关系：** `<use>` 元素是 HTML 中复用 SVG 内容的方式。

17. **引用管理 (`SetOfIncomingReferences`, `AddReferenceTo`, `GetDependencyTraversalVisitedSet`, `RemoveAllIncomingReferences`, `RemoveAllOutgoingReferences`):**
    *   跟踪 SVG 元素之间的引用关系（例如，通过 `url()` 引用）。
    *   这对于在元素发生变化时，能够正确地更新所有依赖于它的元素至关重要。

18. **资源客户端 (`GetSVGResourceClient`, `EnsureSVGResourceClient`):**
    *   获取或创建与当前 SVG 元素关联的资源客户端对象，用于管理其作为资源的行为。

19. **其他工具函数：**
    *   `Trace`: 用于调试和内存管理。
    *   `AccessKeyAction`: 处理访问键操作。
    *   `SynchronizeListOfSVGAttributes`, `AddAnimatedPropertiesToPresentationAttributeStyle`: 批量处理属性。
    *   `AttachLayoutTree`:  在元素附加到布局树时执行的操作，包括启动 SMIL 动画。

**用户或编程常见的使用错误：**

*   **忘记同步更新实例：** 当修改一个被 `<use>` 引用的 SVG 元素时，如果没有调用 `InvalidateInstances()`，那么引用的实例可能不会更新，导致显示不一致。
    *   **用户操作：** 用户修改了 SVG 编辑器中一个被复用的图形，但预览页面没有及时更新。
*   **不正确的事件监听器管理：**  在 shadow DOM 环境下，直接操作实例化的元素添加事件监听器可能不会生效，应该在原始元素上添加。
    *   **用户操作：** 用户尝试通过 JavaScript 为 `<use>` 元素创建的实例添加点击事件，但事件没有响应。
*   **资源加载时序问题：**  在资源尚未完全加载时就尝试操作 SVG 元素可能会导致错误。
    *   **用户操作：** 用户打开一个包含复杂 SVG 的页面，并且有一个脚本在页面加载完成后立即尝试访问 SVG 元素的属性，但由于网络延迟，资源尚未完全加载，导致脚本出错。

**调试线索 - 用户操作到达这里的步骤：**

1. **加载包含 SVG 的 HTML 页面：** 用户在浏览器中输入 URL 或点击链接，导航到包含 SVG 内容的页面。
2. **浏览器解析 HTML 和 SVG：** 浏览器开始解析 HTML 文档，遇到 `<svg>` 标签时，会创建对应的 `SVGSVGElement` 或其他 SVG 元素对象。
3. **加载 SVG 资源：** 如果 SVG 引用了外部资源（例如图片、字体），浏览器会发起请求加载这些资源。`HaveLoadedRequiredResources` 会被调用来检查加载状态。
4. **JavaScript 操作 SVG 元素：** 页面中的 JavaScript 代码可能会使用 DOM API 来操作 SVG 元素，例如修改属性、添加事件监听器等。这些操作会触发 `AttributeChanged`、`AddedEventListener` 等函数。
5. **用户交互触发事件：** 用户与 SVG 元素进行交互，例如点击、鼠标悬停等，会触发相应的事件。
6. **动画播放：** 如果 SVG 中定义了 SMIL 动画或使用了 Web Animations API，动画的每一帧更新都可能涉及到这里代码的执行，例如更新属性值。
7. **`<use>` 元素实例化：** 如果页面中使用了 `<use>` 元素来复用 SVG 内容，当原始元素发生变化时，会触发 `InvalidateInstances` 来更新所有实例。

总而言之，这部分代码是 Chromium 中处理 SVG 元素动态行为的关键组成部分，它连接了 HTML 结构、CSS 样式和 JavaScript 交互，确保 SVG 内容能够正确地渲染和响应用户的操作。

Prompt: 
```
这是目录为blink/renderer/core/svg/svg_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ngAttr)) {
    MapLanguageAttributeToLocale(value, style);
  } else if (name == svg_names::kLangAttr) {
    if (!FastHasAttribute(xml_names::kLangAttr)) {
      MapLanguageAttributeToLocale(value, style);
    }
  }
}

bool SVGElement::HaveLoadedRequiredResources() {
  for (SVGElement* child = Traversal<SVGElement>::FirstChild(*this); child;
       child = Traversal<SVGElement>::NextSibling(*child)) {
    if (!child->HaveLoadedRequiredResources())
      return false;
  }
  return true;
}

static inline void CollectInstancesForSVGElement(
    SVGElement* element,
    HeapHashSet<WeakMember<SVGElement>>& instances) {
  DCHECK(element);
  if (element->ContainingShadowRoot())
    return;

  instances = element->InstancesForElement();
}

void SVGElement::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  // Add event listener to regular DOM element
  Node::AddedEventListener(event_type, registered_listener);

  // Add event listener to all shadow tree DOM element instances
  HeapHashSet<WeakMember<SVGElement>> instances;
  CollectInstancesForSVGElement(this, instances);
  AddEventListenerOptionsResolved* options = registered_listener.Options();
  EventListener* listener = registered_listener.Callback();
  for (SVGElement* element : instances) {
    bool result =
        element->Node::AddEventListenerInternal(event_type, listener, options);
    DCHECK(result);
  }
}

void SVGElement::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  Node::RemovedEventListener(event_type, registered_listener);

  // Remove event listener from all shadow tree DOM element instances
  HeapHashSet<WeakMember<SVGElement>> instances;
  CollectInstancesForSVGElement(this, instances);
  EventListenerOptions* options = registered_listener.Options();
  const EventListener* listener = registered_listener.Callback();
  for (SVGElement* shadow_tree_element : instances) {
    DCHECK(shadow_tree_element);

    shadow_tree_element->Node::RemoveEventListenerInternal(event_type, listener,
                                                           options);
  }
}

static bool HasLoadListener(Element* element) {
  if (element->HasEventListeners(event_type_names::kLoad))
    return true;

  for (element = element->ParentOrShadowHostElement(); element;
       element = element->ParentOrShadowHostElement()) {
    EventListenerVector* entry =
        element->GetEventListeners(event_type_names::kLoad);
    if (!entry)
      continue;
    for (auto& registered_event_listener : *entry) {
      if (registered_event_listener->Capture()) {
        return true;
      }
    }
  }

  return false;
}

bool SVGElement::SendSVGLoadEventIfPossible() {
  if (!HaveLoadedRequiredResources())
    return false;
  if ((IsStructurallyExternal() || IsA<SVGSVGElement>(*this)) &&
      HasLoadListener(this))
    DispatchEvent(*Event::Create(event_type_names::kLoad));
  return true;
}

void SVGElement::SendSVGLoadEventToSelfAndAncestorChainIfPossible() {
  // Let Document::implicitClose() dispatch the 'load' to the outermost SVG
  // root.
  if (IsOutermostSVGSVGElement())
    return;

  // Save the next parent to dispatch to in case dispatching the event mutates
  // the tree.
  Element* parent = ParentOrShadowHostElement();
  if (!SendSVGLoadEventIfPossible())
    return;

  // If document/window 'load' has been sent already, then only deliver to
  // the element in question.
  if (GetDocument().LoadEventFinished())
    return;

  auto* svg_element = DynamicTo<SVGElement>(parent);
  if (!svg_element)
    return;

  svg_element->SendSVGLoadEventToSelfAndAncestorChainIfPossible();
}

void SVGElement::AttributeChanged(const AttributeModificationParams& params) {
  // Note about the 'class' attribute:
  // The "special storage" (SVGAnimatedString) for the 'class' attribute (and
  // the 'className' property) is updated by the following block (`class_name_`
  // returned by PropertyFromAttribute().). SvgAttributeChanged then triggers
  // the resulting style updates (as well as Element::AttributeChanged()).
  SVGAnimatedPropertyBase* property = PropertyFromAttribute(params.name);
  if (property) {
    SVGParsingError parse_error = property->AttributeChanged(params.new_value);
    ReportAttributeParsingError(parse_error, params.name, params.new_value);
  }

  Element::AttributeChanged(params);

  if (property) {
    SvgAttributeChanged({*property, params.name, params.reason});
    UpdateWebAnimatedAttributeOnBaseValChange(*property);
    InvalidateInstances();
    return;
  }

  if (params.name == html_names::kIdAttr) {
    InvalidateInstances();
    return;
  }

  // Changes to the style attribute are processed lazily (see
  // Element::getAttribute() and related methods), so we don't want changes to
  // the style attribute to result in extra work here.
  if (params.name == html_names::kStyleAttr)
    return;

  CSSPropertyID prop_id =
      CssPropertyIdForSVGAttributeName(GetExecutionContext(), params.name);
  if (prop_id > CSSPropertyID::kInvalid) {
    UpdatePresentationAttributeStyle(prop_id, params.name, params.new_value);
    InvalidateInstances();
    return;
  }
}

void SVGElement::SvgAttributeChanged(const SvgAttributeChangedParams& params) {
  if (class_name_ == &params.property) {
    ClassAttributeChanged(AtomicString(class_name_->CurrentValue()->Value()));
    return;
  }
}

void SVGElement::BaseValueChanged(const SVGAnimatedPropertyBase& property) {
  EnsureUniqueElementData().SetSvgAttributesAreDirty(true);
  SvgAttributeChanged({property, property.AttributeName(),
                       AttributeModificationReason::kDirectly});
  if (class_name_ == &property) {
    UpdateClassList(g_null_atom,
                    AtomicString(class_name_->BaseValue()->Value()));
  }
  UpdateWebAnimatedAttributeOnBaseValChange(property);
  InvalidateInstances();
}

void SVGElement::UpdateWebAnimatedAttributeOnBaseValChange(
    const SVGAnimatedPropertyBase& property) {
  if (!HasSVGRareData())
    return;
  const auto& animated_attributes = SvgRareData()->WebAnimatedAttributes();
  if (animated_attributes.empty() ||
      !animated_attributes.Contains(property.AttributeName())) {
    return;
  }
  // TODO(alancutter): Only mark attributes as dirty if their animation depends
  // on the underlying value.
  SvgRareData()->SetWebAnimatedAttributesDirty(true);
  EnsureAttributeAnimValUpdated();
}

void SVGElement::EnsureAttributeAnimValUpdated() {
  if (!RuntimeEnabledFeatures::WebAnimationsSVGEnabled())
    return;

  if ((HasSVGRareData() && SvgRareData()->WebAnimatedAttributesDirty()) ||
      (GetElementAnimations() &&
       GetDocument().GetDocumentAnimations().NeedsAnimationTimingUpdate())) {
    GetDocument().GetDocumentAnimations().UpdateAnimationTimingIfNeeded();
    ApplyActiveWebAnimations();
  }
}

void SVGElement::SynchronizeSVGAttribute(const QualifiedName& name) const {
  DCHECK(HasElementData());
  DCHECK(GetElementData()->svg_attributes_are_dirty());
  SVGAnimatedPropertyBase* property = PropertyFromAttribute(name);
  if (property && property->NeedsSynchronizeAttribute()) {
    property->SynchronizeAttribute();
  }
}

void SVGElement::SynchronizeAllSVGAttributes() const {
  DCHECK(HasElementData());
  DCHECK(GetElementData()->svg_attributes_are_dirty());
  if (class_name_->NeedsSynchronizeAttribute()) {
    class_name_->SynchronizeAttribute();
  }
  GetElementData()->SetSvgAttributesAreDirty(false);
}

MutableCSSPropertyValueSet*
SVGElement::GetPresentationAttributeStyleForDirectUpdate() {
  if (!RuntimeEnabledFeatures::SvgEagerPresAttrStyleUpdateEnabled()) {
    return nullptr;
  }
  // If the element is not attached to the layout tree, then just mark dirty.
  if (!GetLayoutObject()) {
    return nullptr;
  }
  auto& element_data = EnsureUniqueElementData();
  // If _something_ has already marked our presentation attribute style as
  // dirty, just roll with that and let the normal update via
  // CollectStyleForPresentationAttribute() handle it.
  if (element_data.presentation_attribute_style_is_dirty()) {
    return nullptr;
  }
  // Ditto if no property value set has been created yet.
  if (!element_data.PresentationAttributeStyle()) {
    return nullptr;
  }
  return To<MutableCSSPropertyValueSet>(
      element_data.presentation_attribute_style_.Get());
}

void SVGElement::UpdatePresentationAttributeStyle(
    const SVGAnimatedPropertyBase& property) {
  DCHECK(property.HasPresentationAttributeMapping());
  if (auto* mutable_style = GetPresentationAttributeStyleForDirectUpdate()) {
    const CSSPropertyID property_id = property.CssPropertyId();
    if (property.IsSpecified()) {
      if (const CSSValue* value = property.CssValue()) {
        mutable_style->SetProperty(property_id, *value);
      } else {
        mutable_style->RemoveProperty(property_id);
      }
    } else {
      mutable_style->RemoveProperty(property_id);
    }
  } else {
    InvalidateSVGPresentationAttributeStyle();
  }
  SetNeedsStyleRecalc(
      kLocalStyleChange,
      StyleChangeReasonForTracing::FromAttribute(property.AttributeName()));
}

void SVGElement::UpdatePresentationAttributeStyle(
    CSSPropertyID property_id,
    const QualifiedName& attr_name,
    const AtomicString& value) {
  auto set_result = MutableCSSPropertyValueSet::kModifiedExisting;
  if (auto* mutable_style = GetPresentationAttributeStyleForDirectUpdate()) {
    auto* execution_context = GetExecutionContext();
    set_result = mutable_style->ParseAndSetProperty(
        property_id, value, false,
        execution_context ? execution_context->GetSecureContextMode()
                          : SecureContextMode::kInsecureContext,
        GetDocument().ElementSheet().Contents());
    // We want "replace" semantics, so if parsing failed, then make sure any
    // existing value is removed.
    if (set_result == MutableCSSPropertyValueSet::kParseError) {
      if (mutable_style->RemoveProperty(property_id)) {
        set_result = MutableCSSPropertyValueSet::kChangedPropertySet;
      }
    }
  } else {
    InvalidateSVGPresentationAttributeStyle();
  }
  if (set_result >= MutableCSSPropertyValueSet::kModifiedExisting) {
    SetNeedsStyleRecalc(kLocalStyleChange,
                        StyleChangeReasonForTracing::FromAttribute(attr_name));
  }
}

void SVGElement::AddAnimatedPropertyToPresentationAttributeStyle(
    const SVGAnimatedPropertyBase& property,
    MutableCSSPropertyValueSet* style) {
  DCHECK(property.HasPresentationAttributeMapping());
  // Apply values from animating attributes that are also presentation
  // attributes, but do not have a corresponding content attribute.
  if (property.HasContentAttribute() || !property.IsAnimating()) {
    return;
  }
  const CSSValue* value = property.CssValue();
  if (!value) {
    return;
  }
  AddPropertyToPresentationAttributeStyle(style, property.CssPropertyId(),
                                          *value);
}

const ComputedStyle* SVGElement::CustomStyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  // If ResolveStyle() needs to create presentation attribute style for the
  // SVG object, those values need to be parsed, and we want that to happen in
  // SVG mode using the element sheet (which is a fake stylesheet used for
  // things like inline style). We don't need to switch the parser mode here
  // for correctness, but if we don't, CSSParser::ParseValue() will create a
  // new parser context due to mismatch. So override it temporarily here
  // to gain a tiny bit of performance.
  CSSParserContext::ParserModeOverridingScope scope(
      *GetDocument().ElementSheet().Contents()->ParserContext(),
      kSVGAttributeMode);

  SVGElement* corresponding_element = CorrespondingElement();
  if (!corresponding_element) {
    return GetDocument().GetStyleResolver().ResolveStyle(this,
                                                         style_recalc_context);
  }

  const ComputedStyle* style = nullptr;
  if (Element* parent = ParentOrShadowHostElement())
    style = parent->GetComputedStyle();

  StyleRequest style_request;
  style_request.parent_override = style;
  style_request.layout_parent_override = style;
  style_request.styled_element = this;
  StyleRecalcContext corresponding_recalc_context(style_recalc_context);
  corresponding_recalc_context.old_style =
      PostStyleUpdateScope::GetOldStyle(*this);
  return GetDocument().GetStyleResolver().ResolveStyle(
      corresponding_element, corresponding_recalc_context, style_request);
}

bool SVGElement::LayoutObjectIsNeeded(const DisplayStyle& style) const {
  return IsValid() && HasSVGParent() && Element::LayoutObjectIsNeeded(style);
}

bool SVGElement::HasSVGParent() const {
  Element* parent = FlatTreeTraversal::ParentElement(*this);
  return parent && parent->IsSVGElement();
}

MutableCSSPropertyValueSet* SVGElement::AnimatedSMILStyleProperties() const {
  if (HasSVGRareData())
    return SvgRareData()->AnimatedSMILStyleProperties();
  return nullptr;
}

MutableCSSPropertyValueSet* SVGElement::EnsureAnimatedSMILStyleProperties() {
  return EnsureSVGRareData()->EnsureAnimatedSMILStyleProperties();
}

const ComputedStyle* SVGElement::BaseComputedStyleForSMIL() {
  if (!HasSVGRareData())
    return EnsureComputedStyle();
  const ComputedStyle* parent_style = nullptr;
  if (Element* parent = LayoutTreeBuilderTraversal::ParentElement(*this)) {
    parent_style = parent->EnsureComputedStyle();
  }
  return SvgRareData()->OverrideComputedStyle(this, parent_style);
}

bool SVGElement::HasFocusEventListeners() const {
  return HasEventListeners(event_type_names::kFocusin) ||
         HasEventListeners(event_type_names::kFocusout) ||
         HasEventListeners(event_type_names::kFocus) ||
         HasEventListeners(event_type_names::kBlur);
}

void SVGElement::MarkForLayoutAndParentResourceInvalidation(
    LayoutObject& layout_object) {
  LayoutSVGResourceContainer::MarkForLayoutAndParentResourceInvalidation(
      layout_object, true);
}

void SVGElement::NotifyResourceClients() const {
  LocalSVGResource* resource =
      GetTreeScope().EnsureSVGTreeScopedResources().ExistingResourceForId(
          GetIdAttribute());
  if (!resource || resource->Target() != this) {
    return;
  }
  resource->NotifyContentChanged();
}

void SVGElement::InvalidateInstances() {
  const HeapHashSet<WeakMember<SVGElement>>& set = InstancesForElement();
  if (set.empty())
    return;

  // Mark all use elements referencing 'element' for rebuilding
  for (SVGElement* instance : set) {
    instance->SetCorrespondingElement(nullptr);

    if (SVGUseElement* element = instance->GeneratingUseElement()) {
      DCHECK(element->isConnected());
      element->InvalidateShadowTree();
    }
  }

  SvgRareData()->ElementInstances().clear();
}

void SVGElement::SetNeedsStyleRecalcForInstances(
    StyleChangeType change_type,
    const StyleChangeReasonForTracing& reason) {
  const HeapHashSet<WeakMember<SVGElement>>& set = InstancesForElement();
  if (set.empty())
    return;

  for (SVGElement* instance : set)
    instance->SetNeedsStyleRecalc(change_type, reason);
}

#if DCHECK_IS_ON()
bool SVGElement::IsAnimatableAttribute(const QualifiedName& name) const {
  // This static is atomically initialized to dodge a warning about
  // a race when dumping debug data for a layer.
  DEFINE_THREAD_SAFE_STATIC_LOCAL(HashSet<QualifiedName>, animatable_attributes,
                                  ({
                                      svg_names::kAmplitudeAttr,
                                      svg_names::kAzimuthAttr,
                                      svg_names::kBaseFrequencyAttr,
                                      svg_names::kBiasAttr,
                                      svg_names::kClipPathUnitsAttr,
                                      svg_names::kCxAttr,
                                      svg_names::kCyAttr,
                                      svg_names::kDiffuseConstantAttr,
                                      svg_names::kDivisorAttr,
                                      svg_names::kDxAttr,
                                      svg_names::kDyAttr,
                                      svg_names::kEdgeModeAttr,
                                      svg_names::kElevationAttr,
                                      svg_names::kExponentAttr,
                                      svg_names::kFilterUnitsAttr,
                                      svg_names::kFxAttr,
                                      svg_names::kFyAttr,
                                      svg_names::kGradientTransformAttr,
                                      svg_names::kGradientUnitsAttr,
                                      svg_names::kHeightAttr,
                                      svg_names::kHrefAttr,
                                      svg_names::kIn2Attr,
                                      svg_names::kInAttr,
                                      svg_names::kInterceptAttr,
                                      svg_names::kK1Attr,
                                      svg_names::kK2Attr,
                                      svg_names::kK3Attr,
                                      svg_names::kK4Attr,
                                      svg_names::kKernelMatrixAttr,
                                      svg_names::kKernelUnitLengthAttr,
                                      svg_names::kLengthAdjustAttr,
                                      svg_names::kLimitingConeAngleAttr,
                                      svg_names::kMarkerHeightAttr,
                                      svg_names::kMarkerUnitsAttr,
                                      svg_names::kMarkerWidthAttr,
                                      svg_names::kMaskContentUnitsAttr,
                                      svg_names::kMaskUnitsAttr,
                                      svg_names::kMethodAttr,
                                      svg_names::kModeAttr,
                                      svg_names::kNumOctavesAttr,
                                      svg_names::kOffsetAttr,
                                      svg_names::kOperatorAttr,
                                      svg_names::kOrderAttr,
                                      svg_names::kOrientAttr,
                                      svg_names::kPathLengthAttr,
                                      svg_names::kPatternContentUnitsAttr,
                                      svg_names::kPatternTransformAttr,
                                      svg_names::kPatternUnitsAttr,
                                      svg_names::kPointsAtXAttr,
                                      svg_names::kPointsAtYAttr,
                                      svg_names::kPointsAtZAttr,
                                      svg_names::kPreserveAlphaAttr,
                                      svg_names::kPreserveAspectRatioAttr,
                                      svg_names::kPrimitiveUnitsAttr,
                                      svg_names::kRadiusAttr,
                                      svg_names::kRAttr,
                                      svg_names::kRefXAttr,
                                      svg_names::kRefYAttr,
                                      svg_names::kResultAttr,
                                      svg_names::kRotateAttr,
                                      svg_names::kRxAttr,
                                      svg_names::kRyAttr,
                                      svg_names::kScaleAttr,
                                      svg_names::kSeedAttr,
                                      svg_names::kSlopeAttr,
                                      svg_names::kSpacingAttr,
                                      svg_names::kSpecularConstantAttr,
                                      svg_names::kSpecularExponentAttr,
                                      svg_names::kSpreadMethodAttr,
                                      svg_names::kStartOffsetAttr,
                                      svg_names::kStdDeviationAttr,
                                      svg_names::kStitchTilesAttr,
                                      svg_names::kSurfaceScaleAttr,
                                      svg_names::kTableValuesAttr,
                                      svg_names::kTargetAttr,
                                      svg_names::kTargetXAttr,
                                      svg_names::kTargetYAttr,
                                      svg_names::kTransformAttr,
                                      svg_names::kTypeAttr,
                                      svg_names::kValuesAttr,
                                      svg_names::kViewBoxAttr,
                                      svg_names::kWidthAttr,
                                      svg_names::kX1Attr,
                                      svg_names::kX2Attr,
                                      svg_names::kXAttr,
                                      svg_names::kXChannelSelectorAttr,
                                      svg_names::kY1Attr,
                                      svg_names::kY2Attr,
                                      svg_names::kYAttr,
                                      svg_names::kYChannelSelectorAttr,
                                      svg_names::kZAttr,
                                  }));

  if (name == html_names::kClassAttr)
    return true;

  return animatable_attributes.Contains(name);
}
#endif  // DCHECK_IS_ON()

SVGElementSet* SVGElement::SetOfIncomingReferences() const {
  if (!HasSVGRareData())
    return nullptr;
  return &SvgRareData()->IncomingReferences();
}

void SVGElement::AddReferenceTo(SVGElement* target_element) {
  DCHECK(target_element);

  EnsureSVGRareData()->OutgoingReferences().insert(target_element);
  target_element->EnsureSVGRareData()->IncomingReferences().insert(this);
}

SVGElementSet& SVGElement::GetDependencyTraversalVisitedSet() {
  // This strong reference is safe, as it is guaranteed that this set will be
  // emptied at the end of recursion in NotifyIncomingReferences.
  DEFINE_STATIC_LOCAL(Persistent<SVGElementSet>, invalidating_dependencies,
                      (MakeGarbageCollected<SVGElementSet>()));
  return *invalidating_dependencies;
}

void SVGElement::RemoveAllIncomingReferences() {
  if (!HasSVGRareData())
    return;

  SVGElementSet& incoming_references = SvgRareData()->IncomingReferences();
  for (SVGElement* source_element : incoming_references) {
    DCHECK(source_element->HasSVGRareData());
    source_element->EnsureSVGRareData()->OutgoingReferences().erase(this);
  }
  incoming_references.clear();
}

void SVGElement::RemoveAllOutgoingReferences() {
  if (!HasSVGRareData())
    return;

  SVGElementSet& outgoing_references = SvgRareData()->OutgoingReferences();
  for (SVGElement* target_element : outgoing_references) {
    DCHECK(target_element->HasSVGRareData());
    target_element->EnsureSVGRareData()->IncomingReferences().erase(this);
  }
  outgoing_references.clear();
}

SVGElementResourceClient* SVGElement::GetSVGResourceClient() {
  if (!HasSVGRareData())
    return nullptr;
  return SvgRareData()->GetSVGResourceClient();
}

SVGElementResourceClient& SVGElement::EnsureSVGResourceClient() {
  return EnsureSVGRareData()->EnsureSVGResourceClient(this);
}

void SVGElement::Trace(Visitor* visitor) const {
  visitor->Trace(elements_with_relative_lengths_);
  visitor->Trace(svg_rare_data_);
  visitor->Trace(class_name_);
  Element::Trace(visitor);
}

void SVGElement::AccessKeyAction(SimulatedClickCreationScope creation_scope) {
  DispatchSimulatedClick(nullptr, creation_scope);
}

void SVGElement::SynchronizeListOfSVGAttributes(
    const base::span<SVGAnimatedPropertyBase*> attributes) {
  for (SVGAnimatedPropertyBase* attr : attributes) {
    if (attr->NeedsSynchronizeAttribute()) {
      attr->SynchronizeAttribute();
    }
  }
}

void SVGElement::AddAnimatedPropertiesToPresentationAttributeStyle(
    const base::span<const SVGAnimatedPropertyBase*> properties,
    MutableCSSPropertyValueSet* style) {
  for (const SVGAnimatedPropertyBase* property : properties) {
    AddAnimatedPropertyToPresentationAttributeStyle(*property, style);
  }
}

void SVGElement::AttachLayoutTree(AttachContext& context) {
  Element::AttachLayoutTree(context);

  if (!context.performing_reattach && GetLayoutObject() &&
      GetSMILAnimations()) {
    GetTimeContainer()->DidAttachLayoutObject();
  }
}

SMILTimeContainer* SVGElement::GetTimeContainer() const {
  if (auto* svg_root = DynamicTo<SVGSVGElement>(*this)) {
    return svg_root->TimeContainer();
  }

  return ownerSVGElement()->TimeContainer();
}

}  // namespace blink

"""


```