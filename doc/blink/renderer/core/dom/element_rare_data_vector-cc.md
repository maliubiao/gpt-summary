Response:
Let's break down the thought process for analyzing this C++ source code file.

1. **Identify the Core Purpose:** The file name `element_rare_data_vector.cc` and the class name `ElementRareDataVector` strongly suggest it's about storing data associated with `Element` objects in the Blink rendering engine. The "rare" part hints that this data isn't needed for every element, and using a vector suggests dynamic allocation and management of these less common properties.

2. **Scan the Includes:** The `#include` directives reveal the types of data this vector manages. This is crucial for understanding its functionality. We see:
    * Animation (`ElementAnimations`)
    * CSS (`ContainerQueryData`, `InlineStylePropertyMap`, `InlineCSSStyleDeclaration`, `OutOfFlowData`, `StyleScopeData`)
    * DOM fundamentals (`Attr`, `DatasetDOMStringMap`, `DOMTokenList`, `NamedNodeMap`, `ShadowRoot`, `SpaceSplitString`)
    * HTML specifics (`AnchorElementObserver`, `CustomElementDefinition`, `ElementInternals`, `HTMLElement`)
    * Intersection Observer (`ElementIntersectionObserverData`)
    * Layout (`AnchorPositionScrollData`)
    * Resize Observer (`ResizeObservation`, `ResizeObserver`)
    * Other internal types (`DisplayLockContext`, `EditContext`, `NamesMap`)

3. **Examine the Class Structure:** The `ElementRareDataVector` class has:
    * A constructor and destructor. The destructor has a `DCHECK` hinting at a specific condition (no pseudo-element data).
    * `GetField` and `SetField` methods, suggesting a key-value or indexed approach to storing data. The `FieldId` enum (though not shown in this file) is likely the key.
    * Specific getter and setter methods for various types of data (e.g., `GetShadowRoot`, `SetShadowRoot`, `GetClassList`, `SetClassList`). This indicates direct access and management of specific element properties.
    * Methods for handling pseudo-elements, including adding, getting, and clearing them.
    * `Ensure...` methods (e.g., `EnsureInlineCSSStyleDeclaration`). These likely create and store the data if it doesn't already exist.
    * `Remove...` methods to clear specific data.
    * A `Trace` method, which is common in Blink for garbage collection and debugging.

4. **Infer Functionality based on Members and Includes:** Now we can start connecting the dots:
    * **CSS Related:**  The presence of CSS-related includes and methods like `EnsureInlineCSSStyleDeclaration`, `GetContainerQueryEvaluator`, `EnsureOutOfFlowData` confirms that this class manages CSS-related information that isn't always present on every element.
    * **DOM Related:**  Includes like `Attr`, `NamedNodeMap`, `DOMTokenList`, `ShadowRoot` and their corresponding methods indicate the management of DOM-specific attributes and structures that might not be present for all elements.
    * **HTML Related:**  Includes and methods related to custom elements, element internals, and anchor elements show this class also handles HTML-specific features.
    * **Observers:** The inclusion of Intersection Observer and Resize Observer data and methods suggests this class is used to track the data associated with these features on elements.
    * **Pseudo-elements:** The dedicated section for pseudo-elements signifies this is a key responsibility of this class.

5. **Relate to JavaScript, HTML, and CSS:**  With the understanding of the managed data, we can draw connections to web technologies:
    * **JavaScript:**  JavaScript interacts with these properties through the DOM API. For example, `element.classList` would eventually lead to accessing the `DOMTokenList` managed by this class. `element.style` relates to the inline style declaration. Custom element lifecycle hooks might interact with the `CustomElementDefinition`.
    * **HTML:**  HTML attributes like `class`, `id`, `style`, `data-*`, and the presence of shadow DOM are directly linked to the data stored here. Features like popovers and anchor positioning are also handled.
    * **CSS:** Inline styles, container queries, and the styling of pseudo-elements are all represented within this class.

6. **Consider Logic and Examples:** Think about how these features are used and what data needs to be stored. For instance:
    * **Pseudo-elements:** If an element has `::before` or `::after`, the corresponding `PseudoElement` objects would be stored here.
    * **Inline styles:** When JavaScript sets `element.style.color = 'red'`, this information gets stored in the `InlineCSSStyleDeclaration`.
    * **Shadow DOM:**  When `element.attachShadow()` is called, the created `ShadowRoot` object is stored.

7. **Identify Potential Usage Errors (though limited in this low-level file):** At this level, user errors are less direct. The code itself has `DCHECK` statements for internal consistency. However, misunderstanding the lifecycle or intended usage of certain features (like trying to access pseudo-elements before they are created) could indirectly lead to issues where this data is unexpectedly null.

8. **Trace User Operations:** Think about the user actions that trigger these data structures to be created and modified. Loading a page, manipulating the DOM with JavaScript, CSS styling, and using browser features like intersection observers all contribute. For debugging, knowing *when* and *how* this data is created is crucial. Following the creation paths of these objects (e.g., when a style attribute is parsed, when `attachShadow` is called) is the way to trace execution.

9. **Refine and Organize:**  Structure the findings into clear sections addressing the specific questions asked in the prompt. Provide concrete examples to illustrate the connections to web technologies. Use the code snippets as evidence for the identified functionality.

By following these steps, we can systematically analyze the provided C++ source code and understand its role within the larger context of the Blink rendering engine. The key is to leverage the file name, includes, class structure, and method names to infer the purpose and relationships of this code.
好的，让我们来分析一下 `blink/renderer/core/dom/element_rare_data_vector.cc` 这个文件。

**功能概要**

`ElementRareDataVector` 类在 Chromium Blink 引擎中扮演着一个重要的角色，它被设计用来存储与 `Element` 对象相关的**不常用但可能存在**的数据。  与其将所有可能的属性都直接添加到 `Element` 类中（这会造成内存浪费，因为很多元素并不需要这些属性），Blink 采用了这种优化的方式，将这些“稀有”数据集中管理在一个单独的容器中。

可以把它想象成一个元素对象的可选扩展属性包，只有当元素真正需要某个特性时，才会去 `ElementRareDataVector` 中存储或获取相关的数据。

**具体功能列举**

`ElementRareDataVector` 负责存储以下类型的数据，这些数据在 `Element` 对象生命周期中可能存在：

* **伪元素数据 (`PseudoElementData`)**: 存储元素的伪元素（例如 `::before`, `::after`）的相关信息。
* **内联样式声明 (`InlineCSSStyleDeclaration`)**:  通过元素的 `style` 属性设置的 CSS 样式。
* **Shadow DOM (`ShadowRoot`)**:  如果元素是 Shadow Host，则存储其关联的 Shadow Root。
* **属性映射 (`NamedNodeMap`)**: 存储元素的属性（attributes）。
* **类名列表 (`DOMTokenList`)**: 存储元素的 `class` 属性值。
* **数据集 (`DatasetDOMStringMap`)**: 存储元素的 `data-*` 自定义属性。
* **保存的层滚动偏移 (`ScrollOffset`)**:  用于某些滚动相关的优化。
* **元素动画 (`ElementAnimations`)**: 存储应用于元素的 CSS 动画和过渡。
* **属性节点列表 (`AttrNodeList`)**:  一个更细粒度的属性列表。
* **Intersection Observer 数据 (`ElementIntersectionObserverData`)**:  存储与元素相关的 Intersection Observer 的信息。
* **Container Query 求值器 (`ContainerQueryEvaluator`)**: 用于处理 CSS 容器查询。
* **Nonce 值 (`AtomicString`)**: 用于脚本执行策略 (CSP)。
* **`is` 属性值 (`AtomicString`)**: 用于自定义内置元素。
* **编辑上下文 (`EditContext`)**: 用于富文本编辑。
* **Part 属性 (`DOMTokenList`)**:  用于 Web Components 的 `part` 属性。
* **Part 名称映射 (`NamesMap`)**:  与 `part` 属性相关。
* **CSSOM 样式属性映射 (`InlineStylePropertyMap`)**:  用于 JavaScript 操作内联样式的底层映射。
* **Element Internals (`ElementInternals`)**: 用于 Web Components 的 `ElementInternals` API。
* **显示锁上下文 (`DisplayLockContext`)**: 用于处理渲染更新的同步。
* **Container Query 数据 (`ContainerQueryData`)**: 存储与元素相关的容器查询信息。
* **Style Scope 数据 (`StyleScopeData`)**:  用于 CSS 作用域。
* **OutOfFlow 数据 (`OutOfFlowData`)**:  存储脱离文档流的元素的相关信息。
* **区域捕获裁剪 ID (`RegionCaptureCropId`)**: 用于屏幕共享中的区域捕获。
* **限制目标 ID (`RestrictionTargetId`)**:  可能与安全或权限限制相关。
* **Resize Observer 数据 (`ResizeObserverDataMap`)**: 存储与元素相关的 Resize Observer 的信息。
* **自定义元素定义 (`CustomElementDefinition`)**:  存储自定义元素的定义信息。
* **最后记住的块大小和内联大小 (`std::optional<LayoutUnit>`)**: 用于布局优化。
* **Popover 数据 (`PopoverData`)**: 存储与 Popover API 相关的状态和信息。
* **锚点位置滚动数据 (`AnchorPositionScrollData`)**:  用于处理锚点链接的滚动行为。
* **锚点元素观察者 (`AnchorElementObserver`)**:  用于观察 `<a>` 元素的行为。
* **隐式锚定元素计数 (`wtf_size_t`)**:  跟踪隐式锚定的元素。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`ElementRareDataVector` 中存储的许多数据都直接对应于 Web 开发中使用的 JavaScript, HTML 和 CSS 特性。

* **JavaScript:**
    * **`element.style`**: 当你在 JavaScript 中访问或修改 `element.style` 属性时，实际上是在与 `InlineCSSStyleDeclaration` 进行交互，该对象存储在 `ElementRareDataVector` 中。
        ```javascript
        const div = document.createElement('div');
        div.style.color = 'blue'; // 这里的操作会影响到 ElementRareDataVector 中存储的 InlineCSSStyleDeclaration
        console.log(div.style.color);
        ```
    * **`element.classList`**:  访问 `element.classList` 返回的 `DOMTokenList` 对象也存储在 `ElementRareDataVector` 中。
        ```javascript
        const div = document.createElement('div');
        div.classList.add('my-class'); // 修改的是 ElementRareDataVector 中存储的 DOMTokenList
        console.log(div.classList.contains('my-class'));
        ```
    * **`element.dataset`**:  访问 `element.dataset` 属性会返回一个 `DOMStringMap` 对象，该对象也存储在 `ElementRareDataVector` 中。
        ```javascript
        const div = document.createElement('div');
        div.dataset.userId = '123'; // 数据存储在 ElementRareDataVector 的 DatasetDOMStringMap 中
        console.log(div.dataset.userId);
        ```
    * **Shadow DOM API (`attachShadow`)**:  当你使用 `element.attachShadow()` 创建 Shadow DOM 时，创建的 `ShadowRoot` 对象会被存储在 `ElementRareDataVector` 中。
        ```javascript
        const host = document.createElement('div');
        const shadowRoot = host.attachShadow({ mode: 'open' }); // ShadowRoot 对象存储在 ElementRareDataVector
        shadowRoot.innerHTML = '<p>In shadow DOM</p>';
        ```
    * **Custom Elements API**: 当你定义一个自定义元素时，其定义信息 (`CustomElementDefinition`) 会存储在 `ElementRareDataVector` 中。
    * **Web Components `part` 属性**:  通过 JavaScript 获取或设置元素的 `part` 属性，会操作 `ElementRareDataVector` 中存储的 `DOMTokenList`。

* **HTML:**
    * **`class` 属性**: HTML 中的 `class` 属性值会被解析并存储到 `ElementRareDataVector` 的 `DOMTokenList` 中。
    * **`style` 属性**: HTML 中的 `style` 属性值会被解析并存储到 `ElementRareDataVector` 的 `InlineCSSStyleDeclaration` 中。
    * **`data-*` 属性**: HTML 中的 `data-*` 属性会被解析并存储到 `ElementRareDataVector` 的 `DatasetDOMStringMap` 中。
    * **`id` 属性**: 虽然 `id` 属性本身可能不直接存储在 `ElementRareDataVector` 中（因为它更常见，可能直接存储在 `Element` 对象本身），但 `ElementRareDataVector` 可以存储与 `id` 相关的其他稀有数据，比如与锚点链接相关的。
    * **`<template>` 标签和 Shadow DOM**: 使用 `<template>` 标签创建的 Shadow DOM 的根节点信息会存储在 `ElementRareDataVector` 中。
    * **自定义元素标签**:  HTML 中使用的自定义元素标签会与 `ElementRareDataVector` 中存储的 `CustomElementDefinition` 相关联。

* **CSS:**
    * **内联样式**:  通过 HTML 的 `style` 属性或 JavaScript 的 `element.style` 设置的 CSS 样式会影响 `ElementRareDataVector` 中存储的 `InlineCSSStyleDeclaration`。
    * **CSS 伪元素**:  CSS 中定义的伪元素（如 `::before`, `::after`）对应的 `PseudoElement` 对象会被存储在 `ElementRareDataVector` 中。
    * **CSS 容器查询**:  当 CSS 中使用了容器查询时，相关的求值器和数据会存储在 `ElementRareDataVector` 中。

**逻辑推理的假设输入与输出**

假设一个 `HTMLElement` 对象 `element` 被创建：

* **假设输入:**  创建一个空的 `<div>` 元素。
* **预期输出:**  最初，`element` 的 `ElementRareDataVector` 可能为空或只包含一些默认值。例如，伪元素数据、内联样式声明、Shadow Root 等很可能为 null。

* **假设输入:**  使用 JavaScript 设置元素的 `class` 属性： `element.className = 'my-class another-class';`
* **预期输出:**  `element` 的 `ElementRareDataVector` 中，与 `FieldId::kClassList` 关联的 `DOMTokenList` 对象将被创建（如果不存在），并包含 "my-class" 和 "another-class" 两个 token。

* **假设输入:**  使用 JavaScript 设置元素的内联样式： `element.style.color = 'red';`
* **预期输出:**  `element` 的 `ElementRareDataVector` 中，与 `FieldId::kCssomWrapper` 关联的 `InlineCSSStyleDeclaration` 对象将被创建（如果不存在），并且其 `color` 属性将被设置为 "red"。

* **假设输入:**  为元素创建 Shadow DOM： `element.attachShadow({mode: 'open'});`
* **预期输出:**  `element` 的 `ElementRareDataVector` 中，与 `FieldId::kShadowRoot` 关联的 `ShadowRoot` 对象将被创建并存储。

**用户或编程常见的使用错误**

由于 `ElementRareDataVector` 是 Blink 引擎内部使用的类，普通 Web 开发者不会直接与其交互。然而，如果开发者在理解 Web API 的基础上出现错误，可能会间接地导致与 `ElementRareDataVector` 相关的状态不符合预期。

* **错误地假设属性总是存在**:  例如，在检查元素的 Shadow Root 之前，没有判断 `shadowRoot` 是否为 null。这反映了 `ElementRareDataVector` 中 `ShadowRoot` 可能不存在的情况。
    ```javascript
    const div = document.getElementById('myDiv');
    // 错误的做法，没有检查 shadowRoot 是否存在
    div.shadowRoot.innerHTML = '<p>Content in shadow</p>';

    // 正确的做法
    if (div.shadowRoot) {
        div.shadowRoot.innerHTML = '<p>Content in shadow</p>';
    }
    ```
* **过度依赖内联样式**:  虽然可以通过 `element.style` 设置样式，但过度使用可能会导致样式管理混乱。理解内联样式存储在 `ElementRareDataVector` 中，有助于理解其优先级和特性。
* **不理解 Shadow DOM 的边界**:  尝试直接访问 Shadow DOM 内部的元素可能会失败，因为 Shadow DOM 形成了一个封装的边界。这与 `ElementRareDataVector` 中存储的 `ShadowRoot` 对象及其包含的内容有关。

**用户操作是如何一步步到达这里，作为调试线索**

作为调试线索，理解用户操作如何触发 `ElementRareDataVector` 中数据的创建和修改至关重要。以下是一些示例：

1. **加载 HTML 页面**: 当浏览器加载 HTML 页面并开始解析时：
   * 对于每个遇到的 HTML 元素标签，Blink 会创建一个对应的 `HTMLElement` 对象。
   * 如果元素有 `class` 属性，解析器会创建 `DOMTokenList` 并存储到 `ElementRareDataVector`。
   * 如果元素有 `style` 属性，解析器会创建 `InlineCSSStyleDeclaration` 并存储。
   * 如果元素有 `data-*` 属性，会创建 `DatasetDOMStringMap` 并存储。
   * 如果元素是自定义元素，相关的定义信息会被关联。

2. **JavaScript 操作 DOM**:  用户与页面交互或 JavaScript 代码执行时：
   * 当 JavaScript 代码通过 `element.className = ...` 修改类名时，会更新 `ElementRareDataVector` 中的 `DOMTokenList`。
   * 当 JavaScript 代码通过 `element.style.color = ...` 修改内联样式时，会更新 `InlineCSSStyleDeclaration`。
   * 当调用 `element.attachShadow()` 创建 Shadow DOM 时，会创建 `ShadowRoot` 并存储。
   * 当使用 Intersection Observer API 监听元素时，相关数据会存储在 `ElementRareDataVector` 中。

3. **CSS 样式应用**:  CSS 规则的应用也可能间接影响 `ElementRareDataVector`：
   * 虽然 CSS 规则主要影响元素的渲染树，但某些 CSS 特性，如应用于伪元素的样式，会涉及到 `ElementRareDataVector` 中 `PseudoElementData` 的创建和更新。

**调试线索**

如果你在 Blink 引擎的开发中进行调试，并且怀疑某个元素的特定属性没有被正确设置或获取，你可以：

1. **定位到相关的 `HTMLElement` 对象**:  通过调试工具或日志输出，找到你感兴趣的 `HTMLElement` 对象的实例。
2. **查看其 `ElementRareDataVector`**:  在调试器中查看该元素的内部结构，找到其 `ElementRareDataVector` 成员。
3. **检查特定 `FieldId` 对应的数据**:  根据你怀疑出错的属性，找到 `ElementRareDataVector` 中对应的 `FieldId`，并检查其存储的数据是否符合预期。例如，如果类名有问题，检查 `FieldId::kClassList` 对应的 `DOMTokenList`。
4. **追踪数据的修改**:  通过设置断点在 `ElementRareDataVector` 的 `SetField` 方法或特定数据类型的 setter 方法中，追踪数据是如何被创建和修改的。

总而言之，`ElementRareDataVector` 是 Blink 引擎为了优化内存使用和管理元素属性而设计的一个关键组件。理解其功能和与 Web 技术的关系，对于理解浏览器渲染引擎的工作原理以及进行深层次的调试非常有帮助。

Prompt: 
```
这是目录为blink/renderer/core/dom/element_rare_data_vector.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/element_rare_data_vector.h"

#include "third_party/blink/renderer/core/animation/element_animations.h"
#include "third_party/blink/renderer/core/css/container_query_data.h"
#include "third_party/blink/renderer/core/css/cssom/inline_style_property_map.h"
#include "third_party/blink/renderer/core/css/inline_css_style_declaration.h"
#include "third_party/blink/renderer/core/css/out_of_flow_data.h"
#include "third_party/blink/renderer/core/css/style_scope_data.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_context.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/dataset_dom_string_map.h"
#include "third_party/blink/renderer/core/dom/dom_token_list.h"
#include "third_party/blink/renderer/core/dom/has_invalidation_flags.h"
#include "third_party/blink/renderer/core/dom/named_node_map.h"
#include "third_party/blink/renderer/core/dom/names_map.h"
#include "third_party/blink/renderer/core/dom/node_rare_data.h"
#include "third_party/blink/renderer/core/dom/popover_data.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/space_split_string.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/html/anchor_element_observer.h"
#include "third_party/blink/renderer/core/html/custom/custom_element_definition.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/intersection_observer/element_intersection_observer_data.h"
#include "third_party/blink/renderer/core/layout/anchor_position_scroll_data.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observation.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"

namespace blink {

ElementRareDataVector::ElementRareDataVector() = default;

ElementRareDataVector::~ElementRareDataVector() {
  DCHECK(!GetField(FieldId::kPseudoElementData));
}

ElementRareDataField* ElementRareDataVector::GetField(FieldId field_id) const {
  if (fields_.HasField(field_id)) {
    return fields_.GetField(field_id).Get();
  }
  return nullptr;
}

void ElementRareDataVector::SetField(FieldId field_id,
                                     ElementRareDataField* field) {
  if (field) {
    fields_.SetField(field_id, field);
  } else {
    fields_.EraseField(field_id);
  }
}

bool ElementRareDataVector::HasPseudoElements() const {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data)
    return false;
  return data->HasPseudoElements();
}
void ElementRareDataVector::ClearPseudoElements() {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (data) {
    data->ClearPseudoElements();
    SetField(FieldId::kPseudoElementData, nullptr);
  }
}
void ElementRareDataVector::SetPseudoElement(
    PseudoId pseudo_id,
    PseudoElement* element,
    const AtomicString& document_transition_tag) {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data) {
    if (!element)
      return;
    data = MakeGarbageCollected<PseudoElementData>();
    SetField(FieldId::kPseudoElementData, data);
  }
  data->SetPseudoElement(pseudo_id, element, document_transition_tag);
}
PseudoElement* ElementRareDataVector::GetPseudoElement(
    PseudoId pseudo_id,
    const AtomicString& document_transition_tag) const {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data)
    return nullptr;
  return data->GetPseudoElement(pseudo_id, document_transition_tag);
}
PseudoElementData::PseudoElementVector
ElementRareDataVector::GetPseudoElements() const {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data)
    return {};
  return data->GetPseudoElements();
}
void ElementRareDataVector::AddColumnPseudoElement(
    ColumnPseudoElement& column_pseudo_element) {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data) {
    data = MakeGarbageCollected<PseudoElementData>();
    SetField(FieldId::kPseudoElementData, data);
  }
  data->AddColumnPseudoElement(column_pseudo_element);
}

const ColumnPseudoElementsVector*
ElementRareDataVector::GetColumnPseudoElements() const {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data) {
    return nullptr;
  }
  return data->GetColumnPseudoElements();
}
void ElementRareDataVector::ClearColumnPseudoElements() {
  PseudoElementData* data =
      static_cast<PseudoElementData*>(GetField(FieldId::kPseudoElementData));
  if (!data) {
    return;
  }
  data->ClearColumnPseudoElements();
}

CSSStyleDeclaration& ElementRareDataVector::EnsureInlineCSSStyleDeclaration(
    Element* owner_element) {
  return EnsureField<InlineCSSStyleDeclaration>(FieldId::kCssomWrapper,
                                                owner_element);
}

ShadowRoot* ElementRareDataVector::GetShadowRoot() const {
  return static_cast<ShadowRoot*>(GetField(FieldId::kShadowRoot));
}
void ElementRareDataVector::SetShadowRoot(ShadowRoot& shadow_root) {
  DCHECK(!GetField(FieldId::kShadowRoot));
  SetField(FieldId::kShadowRoot, &shadow_root);
}

NamedNodeMap* ElementRareDataVector::AttributeMap() const {
  return static_cast<NamedNodeMap*>(GetField(FieldId::kAttributeMap));
}
void ElementRareDataVector::SetAttributeMap(NamedNodeMap* attribute_map) {
  SetField(FieldId::kAttributeMap, attribute_map);
}

DOMTokenList* ElementRareDataVector::GetClassList() const {
  return static_cast<DOMTokenList*>(GetField(FieldId::kClassList));
}
void ElementRareDataVector::SetClassList(DOMTokenList* class_list) {
  SetField(FieldId::kClassList, class_list);
}

DatasetDOMStringMap* ElementRareDataVector::Dataset() const {
  return static_cast<DatasetDOMStringMap*>(GetField(FieldId::kDataset));
}
void ElementRareDataVector::SetDataset(DatasetDOMStringMap* dataset) {
  SetField(FieldId::kDataset, dataset);
}

ScrollOffset ElementRareDataVector::SavedLayerScrollOffset() const {
  if (auto* value =
          GetWrappedField<ScrollOffset>(FieldId::kSavedLayerScrollOffset)) {
    return *value;
  }
  static ScrollOffset offset;
  return offset;
}
void ElementRareDataVector::SetSavedLayerScrollOffset(ScrollOffset offset) {
  SetWrappedField<ScrollOffset>(FieldId::kSavedLayerScrollOffset, offset);
}

ElementAnimations* ElementRareDataVector::GetElementAnimations() {
  return static_cast<ElementAnimations*>(GetField(FieldId::kElementAnimations));
}
void ElementRareDataVector::SetElementAnimations(
    ElementAnimations* element_animations) {
  SetField(FieldId::kElementAnimations, element_animations);
}

AttrNodeList& ElementRareDataVector::EnsureAttrNodeList() {
  return EnsureWrappedField<AttrNodeList>(FieldId::kAttrNodeList);
}
AttrNodeList* ElementRareDataVector::GetAttrNodeList() {
  return GetWrappedField<AttrNodeList>(FieldId::kAttrNodeList);
}
void ElementRareDataVector::RemoveAttrNodeList() {
  SetField(FieldId::kAttrNodeList, nullptr);
}
void ElementRareDataVector::AddAttr(Attr* attr) {
  EnsureAttrNodeList().push_back(attr);
}

ElementIntersectionObserverData*
ElementRareDataVector::IntersectionObserverData() const {
  return static_cast<ElementIntersectionObserverData*>(
      GetField(FieldId::kIntersectionObserverData));
}
ElementIntersectionObserverData&
ElementRareDataVector::EnsureIntersectionObserverData() {
  return EnsureField<ElementIntersectionObserverData>(
      FieldId::kIntersectionObserverData);
}

ContainerQueryEvaluator* ElementRareDataVector::GetContainerQueryEvaluator()
    const {
  ContainerQueryData* container_query_data = GetContainerQueryData();
  if (!container_query_data)
    return nullptr;
  return container_query_data->GetContainerQueryEvaluator();
}
void ElementRareDataVector::SetContainerQueryEvaluator(
    ContainerQueryEvaluator* evaluator) {
  ContainerQueryData* container_query_data = GetContainerQueryData();
  if (container_query_data)
    container_query_data->SetContainerQueryEvaluator(evaluator);
  else if (evaluator)
    EnsureContainerQueryData().SetContainerQueryEvaluator(evaluator);
}

const AtomicString& ElementRareDataVector::GetNonce() const {
  auto* value = GetWrappedField<AtomicString>(FieldId::kNonce);
  return value ? *value : g_null_atom;
}
void ElementRareDataVector::SetNonce(const AtomicString& nonce) {
  SetWrappedField<AtomicString>(FieldId::kNonce, nonce);
}

const AtomicString& ElementRareDataVector::IsValue() const {
  auto* value = GetWrappedField<AtomicString>(FieldId::kIsValue);
  return value ? *value : g_null_atom;
}
void ElementRareDataVector::SetIsValue(const AtomicString& is_value) {
  SetWrappedField<AtomicString>(FieldId::kIsValue, is_value);
}

EditContext* ElementRareDataVector::GetEditContext() const {
  return static_cast<EditContext*>(GetField(FieldId::kEditContext));
}
void ElementRareDataVector::SetEditContext(EditContext* edit_context) {
  SetField(FieldId::kEditContext, edit_context);
}

void ElementRareDataVector::SetPart(DOMTokenList* part) {
  SetField(FieldId::kPart, part);
}
DOMTokenList* ElementRareDataVector::GetPart() const {
  return static_cast<DOMTokenList*>(GetField(FieldId::kPart));
}

void ElementRareDataVector::SetPartNamesMap(const AtomicString part_names) {
  EnsureWrappedField<NamesMap>(FieldId::kPartNamesMap).Set(part_names);
}
const NamesMap* ElementRareDataVector::PartNamesMap() const {
  return GetWrappedField<NamesMap>(FieldId::kPartNamesMap);
}

InlineStylePropertyMap& ElementRareDataVector::EnsureInlineStylePropertyMap(
    Element* owner_element) {
  return EnsureField<InlineStylePropertyMap>(FieldId::kCssomMapWrapper,
                                             owner_element);
}
InlineStylePropertyMap* ElementRareDataVector::GetInlineStylePropertyMap() {
  return static_cast<InlineStylePropertyMap*>(
      GetField(FieldId::kCssomMapWrapper));
}

const ElementInternals* ElementRareDataVector::GetElementInternals() const {
  return static_cast<ElementInternals*>(GetField(FieldId::kElementInternals));
}
ElementInternals& ElementRareDataVector::EnsureElementInternals(
    HTMLElement& target) {
  return EnsureField<ElementInternals>(FieldId::kElementInternals, target);
}

DisplayLockContext* ElementRareDataVector::EnsureDisplayLockContext(
    Element* element) {
  return &EnsureField<DisplayLockContext>(FieldId::kDisplayLockContext,
                                          element);
}
DisplayLockContext* ElementRareDataVector::GetDisplayLockContext() const {
  return static_cast<DisplayLockContext*>(
      GetField(FieldId::kDisplayLockContext));
}

ContainerQueryData& ElementRareDataVector::EnsureContainerQueryData() {
  return EnsureField<ContainerQueryData>(FieldId::kContainerQueryData);
}
ContainerQueryData* ElementRareDataVector::GetContainerQueryData() const {
  return static_cast<ContainerQueryData*>(
      GetField(FieldId::kContainerQueryData));
}
void ElementRareDataVector::ClearContainerQueryData() {
  SetField(FieldId::kContainerQueryData, nullptr);
}

StyleScopeData& ElementRareDataVector::EnsureStyleScopeData() {
  return EnsureField<StyleScopeData>(FieldId::kStyleScopeData);
}
StyleScopeData* ElementRareDataVector::GetStyleScopeData() const {
  return static_cast<StyleScopeData*>(GetField(FieldId::kStyleScopeData));
}

OutOfFlowData& ElementRareDataVector::EnsureOutOfFlowData() {
  return EnsureField<OutOfFlowData>(FieldId::kOutOfFlowData);
}

OutOfFlowData* ElementRareDataVector::GetOutOfFlowData() const {
  return static_cast<OutOfFlowData*>(GetField(FieldId::kOutOfFlowData));
}

void ElementRareDataVector::ClearOutOfFlowData() {
  SetField(FieldId::kOutOfFlowData, nullptr);
}

const RegionCaptureCropId* ElementRareDataVector::GetRegionCaptureCropId()
    const {
  auto* value = GetWrappedField<std::unique_ptr<RegionCaptureCropId>>(
      FieldId::kRegionCaptureCropId);
  return value ? value->get() : nullptr;
}
void ElementRareDataVector::SetRegionCaptureCropId(
    std::unique_ptr<RegionCaptureCropId> crop_id) {
  CHECK(!GetRegionCaptureCropId());
  CHECK(crop_id);
  CHECK(!crop_id->value().is_zero());
  SetWrappedField<std::unique_ptr<RegionCaptureCropId>>(
      FieldId::kRegionCaptureCropId, std::move(crop_id));
}

const RestrictionTargetId* ElementRareDataVector::GetRestrictionTargetId()
    const {
  auto* value = GetWrappedField<std::unique_ptr<RestrictionTargetId>>(
      FieldId::kRestrictionTargetId);
  return value ? value->get() : nullptr;
}
void ElementRareDataVector::SetRestrictionTargetId(
    std::unique_ptr<RestrictionTargetId> id) {
  CHECK(!GetRestrictionTargetId());
  CHECK(id);
  CHECK(!id->value().is_zero());
  SetWrappedField<std::unique_ptr<RestrictionTargetId>>(
      FieldId::kRestrictionTargetId, std::move(id));
}

ElementRareDataVector::ResizeObserverDataMap*
ElementRareDataVector::ResizeObserverData() const {
  return GetWrappedField<ElementRareDataVector::ResizeObserverDataMap>(
      FieldId::kResizeObserverData);
}
ElementRareDataVector::ResizeObserverDataMap&
ElementRareDataVector::EnsureResizeObserverData() {
  return EnsureWrappedField<ElementRareDataVector::ResizeObserverDataMap>(
      FieldId::kResizeObserverData);
}

void ElementRareDataVector::SetCustomElementDefinition(
    CustomElementDefinition* definition) {
  SetField(FieldId::kCustomElementDefinition, definition);
}
CustomElementDefinition* ElementRareDataVector::GetCustomElementDefinition()
    const {
  return static_cast<CustomElementDefinition*>(
      GetField(FieldId::kCustomElementDefinition));
}

void ElementRareDataVector::SetLastRememberedBlockSize(
    std::optional<LayoutUnit> size) {
  SetOptionalField(FieldId::kLastRememberedBlockSize, size);
}
void ElementRareDataVector::SetLastRememberedInlineSize(
    std::optional<LayoutUnit> size) {
  SetOptionalField(FieldId::kLastRememberedInlineSize, size);
}

std::optional<LayoutUnit> ElementRareDataVector::LastRememberedBlockSize()
    const {
  return GetOptionalField<LayoutUnit>(FieldId::kLastRememberedBlockSize);
}
std::optional<LayoutUnit> ElementRareDataVector::LastRememberedInlineSize()
    const {
  return GetOptionalField<LayoutUnit>(FieldId::kLastRememberedInlineSize);
}

PopoverData* ElementRareDataVector::GetPopoverData() const {
  return static_cast<PopoverData*>(GetField(FieldId::kPopoverData));
}
PopoverData& ElementRareDataVector::EnsurePopoverData() {
  return EnsureField<PopoverData>(FieldId::kPopoverData);
}
void ElementRareDataVector::RemovePopoverData() {
  SetField(FieldId::kPopoverData, nullptr);
}

AnchorPositionScrollData* ElementRareDataVector::GetAnchorPositionScrollData()
    const {
  return static_cast<AnchorPositionScrollData*>(
      GetField(FieldId::kAnchorPositionScrollData));
}
void ElementRareDataVector::RemoveAnchorPositionScrollData() {
  SetField(FieldId::kAnchorPositionScrollData, nullptr);
}
AnchorPositionScrollData& ElementRareDataVector::EnsureAnchorPositionScrollData(
    Element* anchored_element) {
  DCHECK(!GetAnchorPositionScrollData() ||
         GetAnchorPositionScrollData()->AnchoredElement() == anchored_element);
  return EnsureField<AnchorPositionScrollData>(
      FieldId::kAnchorPositionScrollData, anchored_element);
}

AnchorElementObserver& ElementRareDataVector::EnsureAnchorElementObserver(
    Element* new_source_element) {
  DCHECK(!GetAnchorElementObserver() ||
         GetAnchorElementObserver()->GetSourceElement() == new_source_element);
  CHECK(RuntimeEnabledFeatures::HTMLAnchorAttributeEnabled());
  return EnsureField<AnchorElementObserver>(FieldId::kAnchorElementObserver,
                                            new_source_element);
}

AnchorElementObserver* ElementRareDataVector::GetAnchorElementObserver() const {
  return static_cast<AnchorElementObserver*>(
      GetField(FieldId::kAnchorElementObserver));
}

void ElementRareDataVector::IncrementImplicitlyAnchoredElementCount() {
  EnsureWrappedField<wtf_size_t>(FieldId::kImplicitlyAnchoredElementCount)++;
}
void ElementRareDataVector::DecrementImplicitlyAnchoredElementCount() {
  wtf_size_t& anchored_element_count =
      EnsureWrappedField<wtf_size_t>(FieldId::kImplicitlyAnchoredElementCount);
  DCHECK(anchored_element_count);
  anchored_element_count--;
}
bool ElementRareDataVector::HasImplicitlyAnchoredElement() const {
  wtf_size_t* anchored_element_count =
      GetWrappedField<wtf_size_t>(FieldId::kImplicitlyAnchoredElementCount);
  return anchored_element_count ? *anchored_element_count : false;
}

void ElementRareDataVector::Trace(blink::Visitor* visitor) const {
  visitor->Trace(fields_);
  NodeRareData::Trace(visitor);
}

}  // namespace blink

"""

```