Response:
My thought process to answer the request goes through these stages:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ code snippet from `element.cc` and explain its functionality, especially in relation to web technologies (JavaScript, HTML, CSS). The request also asks for examples, debugging information, and a summary. Crucially, it notes this is part 11 of 13, implying I need to provide a summary that fits within the context of a larger file.

2. **Initial Code Scan and Keyword Identification:** I'll quickly scan the code looking for familiar web-related terms and common C++ patterns. Keywords like `matches`, `closest`, `classList`, `dataset`, `href`, `style`, `spellcheck`, `fullscreen`, `pointerLock`, `attribute`, `id`, `name`, etc., immediately jump out. These suggest areas of functionality directly tied to web standards.

3. **Function-by-Function Analysis (and Grouping):** I will go through the provided code section function by function, trying to understand the purpose of each. I'll group related functions together to avoid redundancy in my explanation. For instance, `matches(selectors, ...)` and `matches(selectors)` are clearly related. Similarly, the various `Get*Attribute` and `Set*Attribute` methods form a group.

4. **Connecting to Web Technologies:**  As I analyze each function group, I'll actively think about how it relates to JavaScript, HTML, and CSS.

    * **JavaScript:** Functions like `matches`, `closest`, `classList`, `dataset`, `requestPointerLock` are directly exposed to JavaScript through the DOM API. I'll consider how a JavaScript developer would use these.
    * **HTML:** The attribute manipulation functions (`Get/Set*Attribute`, `DidAddAttribute`, `DidModifyAttribute`, `DidRemoveAttribute`), and properties like `id`, `name`, `class`, `href`, `spellcheck`, `style` are all fundamental HTML concepts.
    * **CSS:** Functions and properties related to `style`, `matches`, `closest`, and the fullscreen pseudo-class clearly have ties to CSS selectors and styling.

5. **Generating Examples:** For each functional area, I will create concise and illustrative examples demonstrating the interaction between the C++ code and web technologies. The examples should be simple and easy to understand. I'll focus on common use cases.

6. **Considering Logic and Assumptions:**  Where the code involves conditional logic (like checking for `nullptr`, or `if` statements), I'll consider potential inputs and outputs. For instance, what happens if the selector in `matches()` is invalid? The code handles this by returning `false`. This leads to the "Assumptions and Logic" section.

7. **Identifying Potential User Errors:**  Based on my understanding of the functions and their parameters, I'll brainstorm common mistakes a web developer might make when using the corresponding JavaScript APIs. For example, using an invalid CSS selector with `matches()` or `closest()`.

8. **Tracing User Actions (Debugging Clues):** I'll think about the sequence of user interactions and browser processes that could lead to the execution of these specific C++ functions. This often involves user interaction with the DOM, JavaScript execution, and browser rendering.

9. **Summarization (Contextual):**  Given that this is part 11 of 13, the summary should focus on the main themes covered in this specific snippet, which are primarily around element attribute management, CSS selector matching, and some advanced features like fullscreen and pointer lock. I'll avoid summarizing the entire `element.cc` file, as that's likely covered in other parts.

10. **Iteration and Refinement:**  After drafting the initial response, I'll review it for clarity, accuracy, and completeness. I'll ensure the examples are correct and the explanations are easy to follow. I'll also double-check that I've addressed all aspects of the prompt. For instance, ensuring I explicitly state the relationship with JavaScript, HTML, and CSS. I will also verify that the assumptions, error examples, and debugging clues are logical and relevant.

**Self-Correction Example during the process:**

Initially, I might just list the functions and their basic C++ purpose. However, I would quickly realize that this doesn't address the core of the request, which is the connection to web technologies. So, I'd go back and explicitly connect each function or group of functions to the relevant JavaScript APIs, HTML attributes, or CSS concepts. Similarly, I might initially forget to provide specific examples and would need to add those in. The "part 11 of 13" instruction reminds me to focus the summary specifically on the features present in this code block.

By following these steps, I can systematically analyze the code and generate a comprehensive and helpful response to the user's request.
这是`blink/renderer/core/dom/element.cc`文件的第 11 部分，延续了之前关于 `Element` 类功能的讨论。根据提供的代码片段，我们可以归纳出以下功能：

**主要功能归纳:**

这部分代码主要集中在 `Element` 类的以下几个方面：

* **CSS 选择器匹配:** 提供了 `matches()` 和 `closest()` 方法，允许元素自身或其祖先元素根据 CSS 选择器进行匹配。
* **类名 (Class) 操作:**  通过 `classList()` 方法提供对元素的 `class` 属性的 `DOMTokenList` 接口，方便进行类名的添加、删除和查询。
* **数据集 (Dataset) 操作:** 通过 `dataset()` 方法提供对元素的 `data-*` 属性的 `DOMStringMap` 接口，用于存储自定义数据。
* **URL 属性处理:** 提供了一系列方法 (`HrefURL()`, `GetURLAttribute()`, `GetURLAttributeAsKURL()`, `GetNonEmptyURLAttribute()`) 用于获取和处理元素的 URL 相关的属性 (如 `href`)。
* **数值型属性处理:**  提供了一系列方法 (`GetIntegralAttribute()`, `GetUnsignedIntegralAttribute()`, `SetIntegralAttribute()`, `SetUnsignedIntegralAttribute()`, `GetFloatingPointAttribute()`, `SetFloatingPointAttribute()`) 用于获取和设置元素的数值型属性。
* **全屏 (Fullscreen) 控制:** 提供了 `SetContainsFullScreenElement()` 和 `SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries()` 方法来标记元素及其祖先是否包含全屏元素，这会影响 CSS 的 `:fullscreen-ancestor` 伪类。
* **持久化视频 (Persistent Video) 控制:** 提供了 `SetContainsPersistentVideo()` 方法来标记元素是否包含持久化的视频，这会影响 CSS 的 `:video-persistent-ancestor` 伪类。
* **顶层 (Top Layer) 控制:** 提供了 `SetIsInTopLayer()` 方法来标记元素是否在顶层，这与 HTML 的 `<dialog>` 和 `popover` 等元素的渲染有关。
* **指针锁定 (Pointer Lock) 请求:** 提供了 `requestPointerLock()` 方法来请求指针锁定。
* **拼写检查 (Spellcheck) 控制:** 提供了 `GetSpellcheckAttributeState()` 和 `IsSpellCheckingEnabled()` 方法来获取和判断元素的拼写检查状态。
* **属性修改回调:**  提供了 `WillModifyAttribute()`, `DidAddAttribute()`, `DidModifyAttribute()`, `DidRemoveAttribute()` 等方法，在元素属性被修改时触发，用于执行相关的逻辑，例如更新内部状态、通知观察者等。
* **文档移动处理:** 提供了 `DidMoveToNewDocument()` 方法，在元素被移动到新的文档时进行处理，例如重新解析内联样式中的 URL。
* **命名项注册:** 提供了 `UpdateName()`, `UpdateId()`, `UpdateNamedItemRegistration()`, `UpdateIdNamedItemRegistration()` 等方法来维护元素在文档中的命名项注册，这与通过 `document.getElementById()`, `document.getElementsByName()` 等方法访问元素有关。
* **焦点组 (Focusgroup) 管理:** 提供了 `UpdateFocusgroup()` 和 `UpdateFocusgroupInShadowRootIfNeeded()` 方法来处理元素的 `focusgroup` 属性，用于自定义焦点导航顺序。
* **属性节点 (Attr) 管理:** 提供了 `AttrIfExists()`, `EnsureAttr()`, `DetachAttrNodeFromElementWithValue()`, `DetachAllAttrNodesFromElement()` 等方法来管理与元素关联的属性节点。
* **样式重计算回调:** 提供了 `WillRecalcStyle()` 和 `DidRecalcStyle()` 方法，在样式重计算前后触发。
* **自定义样式调整:** 提供了 `CustomStyleForLayoutObject()` 和 `AdjustStyle()` 方法，允许元素进行自定义的样式调整。
* **属性克隆:** 提供了 `CloneAttributesFrom()` 方法，用于从另一个元素克隆属性。
* **内联样式 (Inline Style) 处理:** 提供了 `style()`, `attributeStyleMap()`, `ComputedStyleMap()`, `EnsureMutableInlineStyle()`, `ClearMutableInlineStyleIfEmpty()`, `NotifyInlineStyleMutation()`, `SetInlineStyleFromString()`, `IsStyleAttributeChangeAllowed()`, `StyleAttributeChanged()`, `InlineStyleChanged()`, `SetInlineStyleProperty()` 等方法，用于获取、设置和管理元素的内联样式。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * `element.matches(selector)`:  判断元素是否匹配给定的 CSS 选择器字符串。
        * **假设输入:**  HTML: `<div id="myDiv" class="container"></div>`, JavaScript: `document.getElementById('myDiv').matches('.container')`
        * **输出:** `true`
    * `element.closest(selector)`:  查找匹配给定 CSS 选择器的最近的祖先元素（包括自身）。
        * **假设输入:** HTML: `<div class="parent"><p id="myPara"><span></span></p></div>`, JavaScript: `document.querySelector('span').closest('.parent')`
        * **输出:**  返回 `div.parent` 对应的 Element 对象。
    * `element.classList`:  返回元素的类名集合 (DOMTokenList)，可以用于添加、删除、切换类名。
        * **举例:** HTML: `<div id="myDiv" class="active"></div>`, JavaScript: `document.getElementById('myDiv').classList.remove('active'); document.getElementById('myDiv').classList.add('inactive');`
    * `element.dataset`: 返回元素的 data-* 属性集合 (DOMStringMap)。
        * **举例:** HTML: `<div id="myDiv" data-user-id="123"></div>`, JavaScript: `console.log(document.getElementById('myDiv').dataset.userId);`  // 输出 "123"
    * `element.requestPointerLock()`: 允许 JavaScript 请求锁定鼠标指针。
        * **用户操作:** 用户点击一个 "进入全屏" 按钮。
        * **JavaScript 代码:**  `element.requestPointerLock();`

* **HTML:**
    * `element.href`:  JavaScript 可以通过 `element.href` 访问和修改 `<a>`, `<area>`, `<link>` 等元素的 `href` 属性。  `HrefURL()` 和相关的 `GetURLAttribute*()` 方法就是为这些操作提供底层支持。
    * 属性的设置和获取 (例如 `element.id = 'newId'`, `element.getAttribute('name')`) 会最终调用到 `Set*Attribute()` 和 `Get*Attribute()` 等 C++ 方法。
    * `data-*` 属性直接对应 `dataset()` 方法。
    * `class` 属性直接对应 `classList()` 方法。
    * `style` 属性的修改 (例如 `element.style.color = 'red'`) 会触发 `StyleAttributeChanged()` 等方法。

* **CSS:**
    * `matches()` 和 `closest()` 方法直接使用了 CSS 选择器语法。
    * `:fullscreen-ancestor` 和 `:video-persistent-ancestor` 等伪类的状态由 `SetContainsFullScreenElement()` 和 `SetContainsPersistentVideo()` 等方法控制。
    * 内联样式的设置会影响元素的渲染，`EnsureMutableInlineStyle()` 等方法负责管理这些内联样式。

**假设输入与输出 (逻辑推理):**

* **假设输入:** 一个 `<div>` 元素具有 `class="foo bar"`。
* **调用:** `element.classList()`
* **输出:**  返回一个 `DOMTokenList` 对象，其包含两个元素: `"foo"` 和 `"bar"`。

* **假设输入:** 一个 `<a>` 元素具有 `href="/path/to/resource"`，当前文档的 URL 是 `http://example.com/page`.
* **调用:** `element.HrefURL()`
* **输出:** 返回一个 `KURL` 对象，其值为 `http://example.com/path/to/resource` (已解析为绝对 URL)。

* **假设输入:** 一个元素具有属性 `data-item-count="5"`.
* **调用:** `element.dataset()` 后访问 `dataset.itemCount`
* **输出:** 返回字符串 `"5"`。

**用户或编程常见的使用错误及举例说明:**

* **使用无效的 CSS 选择器:**  传递给 `matches()` 或 `closest()` 方法的 CSS 选择器字符串格式不正确。
    * **举例:** `element.matches('{invalid-selector}')`  可能会导致异常或返回意外结果。
* **尝试设置非法的属性值:**  例如，尝试将一个非数字字符串设置为需要数字的属性。
    * **举例:** `element.SetIntegralAttribute(html_names::kWidthAttr, "abc");`  虽然代码会尝试解析，但最终结果可能不是期望的。
* **在不适用的元素上使用特定方法:** 例如，在非链接元素上调用 `HrefURL()`。
    * **举例:** 在一个 `<div>` 元素上调用 `document.querySelector('div').HrefURL()` 将返回一个空的 `KURL`。
* **误解 `closest()` 的行为:** 认为 `closest()` 只查找父元素，而忽略了它会检查自身。
    * **举例:** 如果一个元素本身就匹配选择器，`closest()` 会返回该元素自身。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中加载一个网页。**
2. **网页的 HTML 被解析，创建 DOM 树。**  在这个过程中，会创建 `Element` 类的实例来表示 HTML 元素。
3. **JavaScript 代码执行:**
    * **调用 DOM API:**  例如，JavaScript 代码可能调用 `document.getElementById('myElement').matches('.active')` 或 `element.classList.add('newClass')`。这些 JavaScript 调用会映射到 `Element` 类的相应 C++ 方法，例如 `matches()` 和 `classList()`.
    * **事件处理:** 用户与页面交互 (例如点击按钮、鼠标移动) 可能会触发事件处理函数，这些函数中可能会有操作 DOM 的代码。
    * **框架或库的使用:**  JavaScript 框架 (如 React, Angular, Vue) 内部也会进行大量的 DOM 操作。
4. **CSS 样式计算和应用:** 浏览器在计算元素的最终样式时，可能会使用到 `matches()` 等方法来确定哪些样式规则适用。
5. **属性的动态修改:**  JavaScript 代码可能会动态地修改元素的属性 (例如通过 `setAttribute()` 或直接修改属性)。  这些修改会触发 `WillModifyAttribute()`, `DidModifyAttribute()` 等回调。
6. **全屏操作:** 用户点击全屏按钮或调用全屏 API 会导致 `SetContainsFullScreenElement()` 等方法被调用。
7. **指针锁定:** 用户触发某个操作后，JavaScript 代码可能调用 `element.requestPointerLock()`。

**总结:**

这部分 `element.cc` 代码主要负责实现 `Element` 类中与 CSS 选择器匹配、类名操作、数据集操作、URL 和数值型属性处理、全屏和指针锁定控制、属性修改回调、文档移动处理、命名项注册、焦点组管理、属性节点管理、样式重计算回调、自定义样式调整和内联样式管理等密切相关的核心功能。这些功能直接支撑了 JavaScript 操作 DOM 元素，以及 CSS 样式规则的应用，是 Blink 渲染引擎中至关重要的一部分。

### 提示词
```
这是目录为blink/renderer/core/dom/element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
electors,
                      ExceptionState& exception_state) {
  SelectorQuery* selector_query = GetDocument().GetSelectorQueryCache().Add(
      selectors, GetDocument(), exception_state);
  if (!selector_query) {
    return false;
  }
  return selector_query->Matches(*this);
}

bool Element::matches(const AtomicString& selectors) {
  return matches(selectors, ASSERT_NO_EXCEPTION);
}

Element* Element::closest(const AtomicString& selectors,
                          ExceptionState& exception_state) {
  SelectorQuery* selector_query = GetDocument().GetSelectorQueryCache().Add(
      selectors, GetDocument(), exception_state);
  if (!selector_query) {
    return nullptr;
  }
  return selector_query->Closest(*this);
}

Element* Element::closest(const AtomicString& selectors) {
  return closest(selectors, ASSERT_NO_EXCEPTION);
}

DOMTokenList& Element::classList() {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  if (!rare_data.GetClassList()) {
    auto* class_list =
        MakeGarbageCollected<DOMTokenList>(*this, html_names::kClassAttr);
    class_list->DidUpdateAttributeValue(g_null_atom,
                                        getAttribute(html_names::kClassAttr));
    rare_data.SetClassList(class_list);
  }
  return *rare_data.GetClassList();
}

DOMStringMap& Element::dataset() {
  ElementRareDataVector& rare_data = EnsureElementRareData();
  if (!rare_data.Dataset()) {
    rare_data.SetDataset(MakeGarbageCollected<DatasetDOMStringMap>(this));
  }
  return *rare_data.Dataset();
}

KURL Element::HrefURL() const {
  // FIXME: These all have href() or url(), but no common super class. Why
  // doesn't <link> implement URLUtils?
  if (IsA<HTMLAnchorElement>(*this) || IsA<HTMLAreaElement>(*this) ||
      IsA<HTMLLinkElement>(*this)) {
    return GetURLAttributeAsKURL(html_names::kHrefAttr);
  }
  if (auto* svg_a = DynamicTo<SVGAElement>(*this)) {
    return svg_a->LegacyHrefURL(GetDocument());
  }
  return KURL();
}

String Element::GetURLAttribute(const QualifiedName& name) const {
#if DCHECK_IS_ON()
  if (HasElementData()) {
    if (const Attribute* attribute = Attributes().Find(name)) {
      DCHECK(IsURLAttribute(*attribute));
    }
  }
#endif
  KURL url = GetDocument().CompleteURL(
      StripLeadingAndTrailingHTMLSpaces(getAttribute(name)));
  return url.IsValid()
             ? url
             : StripLeadingAndTrailingHTMLSpaces(getAttribute(name));
}

KURL Element::GetURLAttributeAsKURL(const QualifiedName& name) const {
  return GetDocument().CompleteURL(
      StripLeadingAndTrailingHTMLSpaces(getAttribute(name)));
}

KURL Element::GetNonEmptyURLAttribute(const QualifiedName& name) const {
#if DCHECK_IS_ON()
  if (HasElementData()) {
    if (const Attribute* attribute = Attributes().Find(name)) {
      DCHECK(IsURLAttribute(*attribute));
    }
  }
#endif
  String value = StripLeadingAndTrailingHTMLSpaces(getAttribute(name));
  if (value.empty()) {
    return KURL();
  }
  return GetDocument().CompleteURL(value);
}

int Element::GetIntegralAttribute(const QualifiedName& attribute_name) const {
  return GetIntegralAttribute(attribute_name, 0);
}

int Element::GetIntegralAttribute(const QualifiedName& attribute_name,
                                  int default_value) const {
  int integral_value = default_value;
  ParseHTMLInteger(getAttribute(attribute_name), integral_value);
  return integral_value;
}

unsigned int Element::GetUnsignedIntegralAttribute(
    const QualifiedName& attribute_name) const {
  return static_cast<unsigned int>(
      std::max(0, GetIntegralAttribute(attribute_name)));
}

void Element::SetIntegralAttribute(const QualifiedName& attribute_name,
                                   int value) {
  setAttribute(attribute_name, AtomicString::Number(value));
}

void Element::SetUnsignedIntegralAttribute(const QualifiedName& attribute_name,
                                           unsigned value,
                                           unsigned default_value) {
  // Range restrictions are enforced for unsigned IDL attributes that
  // reflect content attributes,
  //   http://www.whatwg.org/specs/web-apps/current-work/multipage/common-dom-interfaces.html#reflecting-content-attributes-in-idl-attributes
  if (value > 0x7fffffffu) {
    value = default_value;
  }
  setAttribute(attribute_name, AtomicString::Number(value));
}

double Element::GetFloatingPointAttribute(const QualifiedName& attribute_name,
                                          double fallback_value) const {
  return ParseToDoubleForNumberType(getAttribute(attribute_name),
                                    fallback_value);
}

void Element::SetFloatingPointAttribute(const QualifiedName& attribute_name,
                                        double value) {
  String serialized_value = SerializeForNumberType(value);
  setAttribute(attribute_name, AtomicString(serialized_value));
}

void Element::SetContainsFullScreenElement(bool flag) {
  SetElementFlag(ElementFlags::kContainsFullScreenElement, flag);
  // When exiting fullscreen, the element's document may not be active.
  if (flag) {
    DCHECK(GetDocument().IsActive());
    GetDocument().GetStyleEngine().EnsureUAStyleForFullscreen(*this);
  }
  PseudoStateChanged(CSSSelector::kPseudoFullScreenAncestor);
}

// Unlike Node::parentOrShadowHostElement, this can cross frame boundaries.
static Element* NextAncestorElement(Element* element) {
  DCHECK(element);
  if (element->ParentOrShadowHostElement()) {
    return element->ParentOrShadowHostElement();
  }

  Frame* frame = element->GetDocument().GetFrame();
  if (!frame || !frame->Owner()) {
    return nullptr;
  }

  // Find the next LocalFrame on the ancestor chain, and return the
  // corresponding <iframe> element for the remote child if it exists.
  while (frame->Tree().Parent() && frame->Tree().Parent()->IsRemoteFrame()) {
    frame = frame->Tree().Parent();
  }

  if (auto* frame_owner_element =
          DynamicTo<HTMLFrameOwnerElement>(frame->Owner())) {
    return frame_owner_element;
  }

  return nullptr;
}

void Element::SetContainsFullScreenElementOnAncestorsCrossingFrameBoundaries(
    bool flag) {
  for (Element* element = NextAncestorElement(this); element;
       element = NextAncestorElement(element)) {
    element->SetContainsFullScreenElement(flag);
  }
}

void Element::SetContainsPersistentVideo(bool value) {
  SetElementFlag(ElementFlags::kContainsPersistentVideo, value);
  PseudoStateChanged(CSSSelector::kPseudoVideoPersistentAncestor);

  // In some rare situations, when the persistent video has been removed from
  // the tree, part of the tree might still carry the flag.
  if (!value && Fullscreen::IsFullscreenElement(*this)) {
    for (Node* node = firstChild(); node;) {
      auto* element = DynamicTo<Element>(node);
      if (!element || !element->ContainsPersistentVideo()) {
        node = node->nextSibling();
        break;
      }

      element->SetContainsPersistentVideo(false);
      node = node->firstChild();
    }
  }
}

void Element::SetIsInTopLayer(bool in_top_layer) {
  if (IsInTopLayer() == in_top_layer) {
    return;
  }
  SetElementFlag(ElementFlags::kIsInTopLayer, in_top_layer);
  if (!isConnected()) {
    return;
  }

  if (!GetDocument().InStyleRecalc()) {
    if (in_top_layer) {
      // Need to force re-attachment in case the element was removed and re-
      // added between two lifecycle updates since the overlay computed value
      // would not change, but the layout object order may have.
      SetForceReattachLayoutTree();
    }
  }
}

ScriptPromise<IDLUndefined> Element::requestPointerLock(
    ScriptState* script_state,
    const PointerLockOptions* options,
    ExceptionState& exception_state) {
  if (!GetDocument().GetPage()) {
    return ScriptPromise<IDLUndefined>::RejectWithDOMException(
        script_state, MakeGarbageCollected<DOMException>(
                          DOMExceptionCode::kWrongDocumentError,
                          "PointerLock cannot be requested when there "
                          "is no frame or that frame has no page."));
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  GetDocument().GetPage()->GetPointerLockController().RequestPointerLock(
      resolver, this, options);
  return resolver->Promise();
}

SpellcheckAttributeState Element::GetSpellcheckAttributeState() const {
  const AtomicString& value = FastGetAttribute(html_names::kSpellcheckAttr);
  if (value == g_null_atom) {
    return kSpellcheckAttributeDefault;
  }
  if (EqualIgnoringASCIICase(value, "true") ||
      EqualIgnoringASCIICase(value, "")) {
    return kSpellcheckAttributeTrue;
  }
  if (EqualIgnoringASCIICase(value, "false")) {
    return kSpellcheckAttributeFalse;
  }

  return kSpellcheckAttributeDefault;
}

bool Element::IsSpellCheckingEnabled() const {
  // TODO(crbug.com/1365686): This is not compliant with the spec
  // https://html.spec.whatwg.org/#concept-spellcheck-default
  for (const Element* element = this; element;
       element = element->ParentOrShadowHostElement()) {
    switch (element->GetSpellcheckAttributeState()) {
      case kSpellcheckAttributeTrue:
        return true;
      case kSpellcheckAttributeFalse:
        return false;
      case kSpellcheckAttributeDefault:
        if (const auto* input = DynamicTo<HTMLInputElement>(element)) {
          if (input->HasBeenPasswordField()) {
            return false;
          }
        }
        break;
    }
  }

  if (!GetDocument().GetPage()) {
    return true;
  }

  return GetDocument().GetPage()->GetSettings().GetSpellCheckEnabledByDefault();
}

#if DCHECK_IS_ON()
bool Element::FastAttributeLookupAllowed(const QualifiedName& name) const {
  if (name == html_names::kStyleAttr) {
    return false;
  }

  if (auto* svg_element = DynamicTo<SVGElement>(this)) {
    return !svg_element->IsAnimatableAttribute(name);
  }

  return true;
}
#endif

#if DUMP_NODE_STATISTICS
bool Element::HasNamedNodeMap() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->AttributeMap();
  }
  return false;
}
#endif

inline void Element::UpdateName(const AtomicString& old_name,
                                const AtomicString& new_name) {
  if (!IsInDocumentTree()) {
    return;
  }

  if (old_name == new_name) {
    return;
  }

  NamedItemType type = GetNamedItemType();
  if (type != NamedItemType::kNone) {
    UpdateNamedItemRegistration(type, old_name, new_name);
  }
}

inline void Element::UpdateId(const AtomicString& old_id,
                              const AtomicString& new_id) {
  if (!IsInTreeScope()) {
    return;
  }

  if (old_id == new_id) {
    return;
  }

  DCHECK(IsInTreeScope());
  UpdateId(GetTreeScope(), old_id, new_id);
}

inline void Element::UpdateId(TreeScope& scope,
                              const AtomicString& old_id,
                              const AtomicString& new_id) {
  DCHECK(IsInTreeScope());
  DCHECK_NE(old_id, new_id);

  if (!old_id.empty()) {
    scope.RemoveElementById(old_id, *this);
  }
  if (!new_id.empty()) {
    scope.AddElementById(new_id, *this);
  }

  NamedItemType type = GetNamedItemType();
  if (type == NamedItemType::kNameOrId ||
      type == NamedItemType::kNameOrIdWithName) {
    UpdateIdNamedItemRegistration(type, old_id, new_id);
  }
}

inline void Element::UpdateFocusgroup(const AtomicString& input) {
  ExecutionContext* context = GetExecutionContext();
  if (!RuntimeEnabledFeatures::FocusgroupEnabled(context)) {
    return;
  }

  if (ShadowRoot* shadow_root = ContainingShadowRoot()) {
    shadow_root->SetHasFocusgroupAttributeOnDescendant(true);
  }

  EnsureElementRareData().SetFocusgroupFlags(
      focusgroup::ParseFocusgroup(this, input));
}

void Element::UpdateFocusgroupInShadowRootIfNeeded() {
  ShadowRoot* shadow_root = GetShadowRoot();
  DCHECK(shadow_root);

  // There's no need to re-run the focusgroup parser on the nodes of the shadow
  // tree if none of them had the focusgroup attribute set.
  if (!shadow_root->HasFocusgroupAttributeOnDescendant()) {
    return;
  }

  Element* ancestor = this;
  bool has_focusgroup_ancestor = false;
  while (ancestor) {
    if (ancestor->GetFocusgroupFlags() != FocusgroupFlags::kNone) {
      has_focusgroup_ancestor = true;
      break;
    }
    ancestor = ancestor->parentElement();
  }

  // We don't need to update the focusgroup value for the ShadowDOM elements if
  // there is no ancestor with a focusgroup value, since the parsing would be
  // exactly the same as the one that happened when we first built the
  // ShadowDOM.
  if (!has_focusgroup_ancestor) {
    return;
  }

  // In theory, we should only reach this point when at least one node within
  // the shadow tree has the focusgroup attribute. However, it's possible to get
  // here if a node initially had the focusgroup attribute but then lost it
  // since we don't reset the `ShadowRoot::HasFocusgroupAttributeOnDescendant`
  // upon removing the attribute.
  //
  // Setting this value back to false before iterating over the nodes of the
  // shadow tree allow us to reset the bit in case an update to the shadow tree
  // removed all focusgroup attributes from the shadow tree. If there's still
  // a focusgroup attribute, then the call to `UpdateFocusgroup` below will
  // make sure that the bit is set to true for the containing shadow root.
  shadow_root->SetHasFocusgroupAttributeOnDescendant(false);

  Node* next = FlatTreeTraversal::Next(*this, this);
  while (next) {
    bool skip_subtree = false;
    if (Element* next_element = DynamicTo<Element>(next)) {
      const AtomicString& focusgroup_value =
          next_element->FastGetAttribute(html_names::kFocusgroupAttr);
      if (!focusgroup_value.IsNull()) {
        next_element->UpdateFocusgroup(focusgroup_value);
      }

      if (auto* next_shadow_root = next_element->GetShadowRoot()) {
        skip_subtree = !next_shadow_root->HasFocusgroupAttributeOnDescendant();
      }
    }

    if (skip_subtree) {
      next = FlatTreeTraversal::NextSkippingChildren(*next, this);
    } else {
      next = FlatTreeTraversal::Next(*next, this);
    }
  }
}

void Element::WillModifyAttribute(const QualifiedName& name,
                                  const AtomicString& old_value,
                                  const AtomicString& new_value) {
  if (name == html_names::kNameAttr) {
    UpdateName(old_value, new_value);
  }

  if (GetCustomElementState() == CustomElementState::kCustom) {
    CustomElement::EnqueueAttributeChangedCallback(*this, name, old_value,
                                                   new_value);
  }

  if (old_value != new_value) {
    GetDocument().GetStyleEngine().AttributeChangedForElement(name, *this);
  }

  if (MutationObserverInterestGroup* recipients =
          MutationObserverInterestGroup::CreateForAttributesMutation(*this,
                                                                     name)) {
    recipients->EnqueueMutationRecord(
        MutationRecord::CreateAttributes(this, name, old_value));
  }
  probe::WillModifyDOMAttr(this, old_value, new_value);
}

DISABLE_CFI_PERF
void Element::DidAddAttribute(const QualifiedName& name,
                              const AtomicString& value) {
  AttributeChanged(AttributeModificationParams(
      name, g_null_atom, value, AttributeModificationReason::kDirectly));
  if (name == html_names::kIdAttr) {
    UpdateId(g_null_atom, value);
  }
  probe::DidModifyDOMAttr(this, name, value);
  DispatchSubtreeModifiedEvent();
}

void Element::DidModifyAttribute(const QualifiedName& name,
                                 const AtomicString& old_value,
                                 const AtomicString& new_value,
                                 AttributeModificationReason reason) {
  if (name == html_names::kIdAttr) {
    UpdateId(old_value, new_value);
  }
  AttributeChanged(
      AttributeModificationParams(name, old_value, new_value, reason));
  probe::DidModifyDOMAttr(this, name, new_value);
  // Do not dispatch a DOMSubtreeModified event here; see bug 81141.
}

void Element::DidRemoveAttribute(const QualifiedName& name,
                                 const AtomicString& old_value) {
  if (name == html_names::kIdAttr) {
    UpdateId(old_value, g_null_atom);
  }
  AttributeChanged(AttributeModificationParams(
      name, old_value, g_null_atom, AttributeModificationReason::kDirectly));
  probe::DidRemoveDOMAttr(this, name);
  DispatchSubtreeModifiedEvent();
}

static bool NeedsURLResolutionForInlineStyle(const Element& element,
                                             const Document& old_document,
                                             const Document& new_document) {
  if (old_document == new_document) {
    return false;
  }
  if (old_document.BaseURL() == new_document.BaseURL()) {
    return false;
  }
  const CSSPropertyValueSet* style = element.InlineStyle();
  if (!style) {
    return false;
  }
  for (unsigned i = 0; i < style->PropertyCount(); ++i) {
    if (style->PropertyAt(i).Value().MayContainUrl()) {
      return true;
    }
  }
  return false;
}

static void ReResolveURLsInInlineStyle(const Document& document,
                                       MutableCSSPropertyValueSet& style) {
  for (unsigned i = 0; i < style.PropertyCount(); ++i) {
    const CSSValue& value = style.PropertyAt(i).Value();
    if (value.MayContainUrl()) {
      value.ReResolveUrl(document);
    }
  }
}

void Element::DidMoveToNewDocument(Document& old_document) {
  Node::DidMoveToNewDocument(old_document);

  // If the documents differ by quirks mode then they differ by case sensitivity
  // for class and id names so we need to go through the attribute change logic
  // to pick up the new casing in the ElementData. If the id/class is already
  // lower-case, then it's not impacted by quirks mode and no change is
  // necessary.
  if (old_document.InQuirksMode() != GetDocument().InQuirksMode()) {
    // TODO(tkent): If new owner Document has a ShareableElementData matching to
    // this element's attributes, we shouldn't make UniqueElementData, and this
    // element should point to the shareable one.

    if (const AtomicString& id_attr = GetIdAttribute()) {
      if (!id_attr.IsLowerASCII()) {
        EnsureUniqueElementData();
        SetIdAttribute(id_attr);
      }
    }
    if (const AtomicString& class_attr = GetClassAttribute()) {
      if (!class_attr.IsLowerASCII()) {
        EnsureUniqueElementData();
        // Going through setAttribute() to synchronize the attribute is only
        // required when setting the "style" attribute (this sets the "class"
        // attribute) or for an SVG element (in which case `GetClassAttribute`
        // above would already have synchronized).
        SetAttributeInternal(FindAttributeIndex(html_names::kClassAttr),
                             html_names::kClassAttr, class_attr,
                             AttributeModificationReason::kByMoveToNewDocument);
      }
    }
  }
  // TODO(tkent): Even if Documents' modes are same, keeping
  // ShareableElementData owned by old_document isn't right.

  if (NeedsURLResolutionForInlineStyle(*this, old_document, GetDocument())) {
    ReResolveURLsInInlineStyle(GetDocument(), EnsureMutableInlineStyle());
  }

  if (auto* context = GetDisplayLockContext()) {
    context->DidMoveToNewDocument(old_document);
  }
}

void Element::UpdateNamedItemRegistration(NamedItemType type,
                                          const AtomicString& old_name,
                                          const AtomicString& new_name) {
  auto* doc = DynamicTo<HTMLDocument>(GetDocument());
  if (!doc) {
    return;
  }

  if (!old_name.empty()) {
    doc->RemoveNamedItem(old_name);
  }

  if (!new_name.empty()) {
    doc->AddNamedItem(new_name);
  }

  if (type == NamedItemType::kNameOrIdWithName) {
    const AtomicString id = GetIdAttribute();
    if (!id.empty()) {
      if (!old_name.empty() && new_name.empty()) {
        doc->RemoveNamedItem(id);
      } else if (old_name.empty() && !new_name.empty()) {
        doc->AddNamedItem(id);
      }
    }
  }
}

void Element::UpdateIdNamedItemRegistration(NamedItemType type,
                                            const AtomicString& old_id,
                                            const AtomicString& new_id) {
  auto* doc = DynamicTo<HTMLDocument>(GetDocument());
  if (!doc) {
    return;
  }

  if (type == NamedItemType::kNameOrIdWithName && GetNameAttribute().empty()) {
    return;
  }

  if (!old_id.empty()) {
    doc->RemoveNamedItem(old_id);
  }

  if (!new_id.empty()) {
    doc->AddNamedItem(new_id);
  }
}

ScrollOffset Element::SavedLayerScrollOffset() const {
  if (const ElementRareDataVector* data = GetElementRareData()) {
    return data->SavedLayerScrollOffset();
  }
  return ScrollOffset();
}

void Element::SetSavedLayerScrollOffset(const ScrollOffset& size) {
  if (ElementRareDataVector* data = GetElementRareData()) {
    return data->SetSavedLayerScrollOffset(size);
  } else if (!size.IsZero()) {
    EnsureElementRareData().SetSavedLayerScrollOffset(size);
  }
}

Attr* Element::AttrIfExists(const QualifiedName& name) {
  if (AttrNodeList* attr_node_list = GetAttrNodeList()) {
    for (const auto& attr : *attr_node_list) {
      if (attr->GetQualifiedName().Matches(name)) {
        return attr.Get();
      }
    }
  }
  return nullptr;
}

Attr* Element::EnsureAttr(const QualifiedName& name) {
  Attr* attr_node = AttrIfExists(name);
  if (!attr_node) {
    attr_node = MakeGarbageCollected<Attr>(*this, name);
    GetTreeScope().AdoptIfNeeded(*attr_node);
    EnsureElementRareData().AddAttr(attr_node);
  }
  return attr_node;
}

void Element::DetachAttrNodeFromElementWithValue(Attr* attr_node,
                                                 const AtomicString& value) {
  DCHECK(GetAttrNodeList());
  attr_node->DetachFromElementWithValue(value);

  AttrNodeList* list = GetAttrNodeList();
  wtf_size_t index = list->Find(attr_node);
  DCHECK_NE(index, kNotFound);
  list->EraseAt(index);
  if (list->empty()) {
    RemoveAttrNodeList();
  }
}

void Element::DetachAllAttrNodesFromElement() {
  AttrNodeList* list = GetAttrNodeList();
  if (!list) {
    return;
  }

  AttributeCollection attributes = GetElementData()->Attributes();
  for (const Attribute& attr : attributes) {
    if (Attr* attr_node = AttrIfExists(attr.GetName())) {
      attr_node->DetachFromElementWithValue(attr.Value());
    }
  }

  RemoveAttrNodeList();
}

void Element::WillRecalcStyle(const StyleRecalcChange) {
  DCHECK(HasCustomStyleCallbacks());
}

void Element::DidRecalcStyle(const StyleRecalcChange) {
  DCHECK(HasCustomStyleCallbacks());
}

const ComputedStyle* Element::CustomStyleForLayoutObject(
    const StyleRecalcContext& style_recalc_context) {
  DCHECK(HasCustomStyleCallbacks());
  return OriginalStyleForLayoutObject(style_recalc_context);
}

void Element::AdjustStyle(ComputedStyleBuilder&) {
  DCHECK(HasCustomStyleCallbacks());
}

void Element::CloneAttributesFrom(const Element& other) {
  if (GetElementRareData()) {
    DetachAllAttrNodesFromElement();
  }

  other.SynchronizeAllAttributes();
  if (!other.element_data_) {
    element_data_.Clear();
    return;
  }

  const AtomicString& old_id = GetIdAttribute();
  const AtomicString& new_id = other.GetIdAttribute();

  if (!old_id.IsNull() || !new_id.IsNull()) {
    UpdateId(old_id, new_id);
  }

  const AtomicString& old_name = GetNameAttribute();
  const AtomicString& new_name = other.GetNameAttribute();

  if (!old_name.IsNull() || !new_name.IsNull()) {
    UpdateName(old_name, new_name);
  }

  // Quirks mode makes class and id not case sensitive. We can't share the
  // ElementData if the idForStyleResolution and the className need different
  // casing.
  bool owner_documents_have_different_case_sensitivity = false;
  if (other.HasClass() || other.HasID()) {
    owner_documents_have_different_case_sensitivity =
        other.GetDocument().InQuirksMode() != GetDocument().InQuirksMode();
  }

  // If 'other' has a mutable ElementData, convert it to an immutable one so we
  // can share it between both elements.
  // We can only do this if there are no presentation attributes and sharing the
  // data won't result in different case sensitivity of class or id.
  auto* unique_element_data =
      DynamicTo<UniqueElementData>(other.element_data_.Get());
  if (unique_element_data && !owner_documents_have_different_case_sensitivity &&
      !other.element_data_->PresentationAttributeStyle()) {
    const_cast<Element&>(other).element_data_ =
        unique_element_data->MakeShareableCopy();
  }

  if (!other.element_data_->IsUnique() &&
      !owner_documents_have_different_case_sensitivity &&
      !NeedsURLResolutionForInlineStyle(other, other.GetDocument(),
                                        GetDocument())) {
    element_data_ = other.element_data_;
  } else {
    element_data_ = other.element_data_->MakeUniqueCopy();
  }

  for (const Attribute& attr : element_data_->Attributes()) {
    AttributeChanged(
        AttributeModificationParams(attr.GetName(), g_null_atom, attr.Value(),
                                    AttributeModificationReason::kByCloning));
  }

  if (other.nonce() != g_null_atom) {
    setNonce(other.nonce());
  }
}

void Element::CreateUniqueElementData() {
  if (!element_data_) {
    element_data_ = MakeGarbageCollected<UniqueElementData>();
  } else {
    DCHECK(!IsA<UniqueElementData>(element_data_.Get()));
    element_data_ =
        To<ShareableElementData>(element_data_.Get())->MakeUniqueCopy();
  }
}

void Element::SynchronizeStyleAttributeInternal() const {
  DCHECK(IsStyledElement());
  DCHECK(HasElementData());
  DCHECK(GetElementData()->style_attribute_is_dirty());
  GetElementData()->SetStyleAttributeIsDirty(false);
  const CSSPropertyValueSet* inline_style = InlineStyle();
  const_cast<Element*>(this)->SetSynchronizedLazyAttribute(
      html_names::kStyleAttr,
      inline_style ? AtomicString(inline_style->AsText()) : g_empty_atom);
}

CSSStyleDeclaration* Element::style() {
  if (!IsStyledElement()) {
    return nullptr;
  }
  return &EnsureElementRareData().EnsureInlineCSSStyleDeclaration(this);
}

StylePropertyMap* Element::attributeStyleMap() {
  if (!IsStyledElement()) {
    return nullptr;
  }
  return &EnsureElementRareData().EnsureInlineStylePropertyMap(this);
}

StylePropertyMapReadOnly* Element::ComputedStyleMap() {
  return GetDocument().ComputedStyleMap(this);
}

MutableCSSPropertyValueSet& Element::EnsureMutableInlineStyle() {
  DCHECK(IsStyledElement());
  Member<CSSPropertyValueSet>& inline_style =
      EnsureUniqueElementData().inline_style_;
  if (!inline_style) {
    CSSParserMode mode = (!IsHTMLElement() || GetDocument().InQuirksMode())
                             ? kHTMLQuirksMode
                             : kHTMLStandardMode;
    inline_style = MakeGarbageCollected<MutableCSSPropertyValueSet>(mode);
  } else if (!inline_style->IsMutable()) {
    inline_style = inline_style->MutableCopy();
  }
  return *To<MutableCSSPropertyValueSet>(inline_style.Get());
}

void Element::ClearMutableInlineStyleIfEmpty() {
  if (EnsureMutableInlineStyle().IsEmpty()) {
    EnsureUniqueElementData().inline_style_.Clear();
  }
}

void Element::NotifyInlineStyleMutation() {
  if (GetLayoutObject() && GetLayoutObject()->PreviousVisibilityVisible() &&
      GetDocument().GetPage()) {
    GetDocument().GetPage()->Animator().SetHasInlineStyleMutation();
  }
}

inline void Element::SetInlineStyleFromString(
    const AtomicString& new_style_string) {
  DCHECK(IsStyledElement());
  Member<CSSPropertyValueSet>& inline_style = GetElementData()->inline_style_;

  // Avoid redundant work if we're using shared attribute data with already
  // parsed inline style.
  if (inline_style && !GetElementData()->IsUnique()) {
    return;
  }

  // We reconstruct the property set instead of mutating if there is no CSSOM
  // wrapper.  This makes wrapperless property sets immutable and so cacheable.
  if (inline_style && !inline_style->IsMutable()) {
    inline_style.Clear();
  }

  if (!inline_style) {
    inline_style =
        CSSParser::ParseInlineStyleDeclaration(new_style_string, this);
  } else {
    DCHECK(inline_style->IsMutable());
    static_cast<MutableCSSPropertyValueSet*>(inline_style.Get())
        ->ParseDeclarationList(
            new_style_string,
            GetExecutionContext()
                ? GetExecutionContext()->GetSecureContextMode()
                : SecureContextMode::kInsecureContext,
            GetDocument().ElementSheet().Contents());
  }
}

bool Element::IsStyleAttributeChangeAllowed(const AtomicString& style_string) {
  if (auto* shadow_root = ContainingShadowRoot()) {
    if (shadow_root->IsUserAgent()) {
      return true;
    }
  }

  if (auto* context = GetExecutionContext()) {
    if (auto* policy = context->GetContentSecurityPolicyForCurrentWorld()) {
      WTF::OrdinalNumber start_line_number = WTF::OrdinalNumber::BeforeFirst();
      auto& document = GetDocument();
      if (document.GetScriptableDocumentParser() &&
          !document.IsInDocumentWrite()) {
        start_line_number =
            document.GetScriptableDocumentParser()->LineNumber();
      }
      return policy->AllowInline(
          ContentSecurityPolicy::InlineType::kStyleAttribute, this,
          style_string, String() /* nonce */, document.Url(),
          start_line_number);
    }
  }
  return false;
}

void Element::StyleAttributeChanged(
    const AtomicString& new_style_string,
    AttributeModificationReason modification_reason) {
  DCHECK(IsStyledElement());

  if (new_style_string.IsNull()) {
    EnsureUniqueElementData().inline_style_.Clear();
  } else if (modification_reason == AttributeModificationReason::kByCloning ||
             IsStyleAttributeChangeAllowed(new_style_string)) {
    SetInlineStyleFromString(new_style_string);
  }

  GetElementData()->SetStyleAttributeIsDirty(false);

  SetNeedsStyleRecalc(kLocalStyleChange,
                      StyleChangeReasonForTracing::Create(
                          style_change_reason::kStyleAttributeChange));
  probe::DidInvalidateStyleAttr(this);
}

void Element::InlineStyleChanged() {
  // NOTE: This is conservative; we can be more precise it in the future
  // if need be.
  const bool only_changed_independent_properties = false;

  DCHECK(IsStyledElement());
  InvalidateStyleAttribute(only_changed_independent_properties);
  probe::DidInvalidateStyleAttr(this);

  if (MutationObserverInterestGroup* recipients =
          MutationObserverInterestGroup::CreateForAttributesMutation(
              *this, html_names::kStyleAttr)) {
    // We don't use getAttribute() here to get a style attribute value
    // before the change.
    AtomicString old_value;
    if (const Attribute* attribute =
            GetElementData()->Attributes().Find(html_names::kStyleAttr)) {
      old_value = attribute->Value();
    }
    recipients->EnqueueMutationRecord(MutationRecord::CreateAttributes(
        this, html_names::kStyleAttr, old_value));
    // Need to synchronize every time so that following MutationRecords will
    // have correct oldValues.
    SynchronizeAttribute(html_names::kStyleAttr);
  }
}

void Element::SetInlineStyleProperty(CSSPropertyID property_id,
                                     CSSValueID identifier,
                                     bool important) {
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  SetInlineStyleProperty(property_id, *CSSIdentifierValue::Create(identifier),
                         important);
}

void Element::SetInlineStyleProperty(CSSPropertyID property_id,
                                     double value,
                                     CSSPrimitiveValue::UnitType unit,
                                     bool important) {
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  SetInlineStyleProperty(
      property_id, *CSSNumericLiteralValue::Create(value, unit), important);
}

void Element::SetInlineStyleProperty(CSSPropertyID property_id,
                                     const CSSValue& value,
                                     bool important) {
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  DCHECK(IsStyledElement());
  EnsureMutableInlineStyle().SetProperty(property_id, value, important);
  InlineStyleChanged();
}

bool Element::SetInlineStyleProperty(CSSPropertyID property_id,
                                     const String& value,
                                     bool important) {
  DCHECK_NE(property_id, CSSPropertyID::kVariable);
  DCHECK(IsStyledElement());
  bool did_change =
      EnsureMutableInlineStyle().ParseAndSetProperty(
          property_id, v
```