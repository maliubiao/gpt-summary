Response:
My thought process for analyzing the `invalidation_set.cc` file went through these stages:

1. **Initial Skim for Overview:** I first read through the entire file to get a general understanding of its purpose. I looked for keywords like "invalidation," "style," "CSS," and "element" to confirm its connection to the style system. The copyright notice and includes provided context about its place within Chromium's Blink rendering engine.

2. **Identify Key Data Structures:** I paid attention to class definitions and member variables. The `InvalidationSet` class itself was the central focus. I noted its different backing types (string, hash set) for storing classes, IDs, tag names, and attributes. The `InvalidationFlags` struct also stood out as holding boolean flags related to invalidation scope. The `SiblingInvalidationSet` and `DescendantInvalidationSet` subclasses indicated a hierarchy or specialization.

3. **Analyze Key Functions:** I then focused on the functions within the `InvalidationSet` class. Functions like `InvalidatesElement`, `Combine`, `AddClass`, `AddId`, `AddTagName`, `AddAttribute`, and `SetWholeSubtreeInvalid` seemed crucial to the core functionality. I tried to understand what each function did and how they interacted. For instance, `InvalidatesElement` checks if an element matches the invalidation criteria stored within the `InvalidationSet`. `Combine` merges two `InvalidationSet` objects.

4. **Connect to CSS Concepts:**  I started to connect the code to known CSS concepts. The presence of functions like `AddClass`, `AddId`, `AddTagName`, and `AddAttribute` directly maps to CSS selectors (e.g., `.class`, `#id`, `tag`, `[attribute]`). The flags like `WholeSubtreeInvalid`, `InvalidatesNth`, and `InvalidatesSlotted` suggested more complex invalidation scenarios arising from CSS features like `:nth-child`, `<slot>`, and shadow DOM.

5. **Look for Interactions with Other Parts of Blink:** The `#include` directives provided clues about interactions with other Blink components. `StyleResolver.h` indicated its role in the style resolution process. `Element.h` showed its interaction with the DOM. `inspector/` headers suggested debugging and profiling capabilities.

6. **Infer Functionality and Relationships:**  Based on the identified data structures, functions, and connections, I started to infer the overall functionality. I reasoned that the `InvalidationSet` is a data structure used to efficiently track what needs to be restyled when something changes in the DOM or CSS. The different flags and backing types allow for targeted invalidation, avoiding unnecessary restyling of the entire page.

7. **Consider JavaScript and HTML Connection:** I then considered how JavaScript and HTML might trigger the use of this code. JavaScript manipulations of the DOM (adding/removing classes, changing attributes, creating/deleting elements) or changes to the `style` attribute would lead to recalculations and potentially trigger the creation and use of `InvalidationSet` objects. Similarly, changes in the HTML structure would also necessitate style invalidation.

8. **Think About Use Cases and Errors:** I tried to imagine scenarios where this code would be used and potential errors. For example, if a CSS rule targets a specific class, adding or removing that class from an element would trigger invalidation. A common error might be inadvertently invalidating a large portion of the DOM due to overly broad CSS selectors.

9. **Trace User Actions:** Finally, I worked backward from the code to consider how a user's actions could lead to its execution. A user interacting with a webpage (e.g., clicking a button, hovering over an element, scrolling) can trigger JavaScript events, which in turn might modify the DOM or CSS, leading to the involvement of the style invalidation system and this specific file.

10. **Refine and Structure the Explanation:** After the initial analysis, I structured my findings into the requested categories: functionality, relation to JavaScript/HTML/CSS, logical reasoning with examples, common usage errors, and debugging clues. I tried to provide concrete examples to illustrate each point. I also paid attention to the level of detail expected for each category.

Essentially, my approach was a combination of:

* **Code Reading and Interpretation:** Understanding the syntax and semantics of the C++ code.
* **Domain Knowledge:** Applying my knowledge of web technologies (HTML, CSS, JavaScript) and browser rendering engines.
* **Deductive Reasoning:** Inferring the purpose and behavior of the code based on its structure and interactions.
* **Scenario Planning:** Imagining different use cases and potential issues.
* **Working Backwards:** Tracing the path from user interaction to the execution of this specific code.

This iterative process of reading, analyzing, connecting, and refining allowed me to build a comprehensive understanding of the `invalidation_set.cc` file.
这个 `invalidation_set.cc` 文件是 Chromium Blink 引擎中负责 **CSS 样式失效跟踪和管理** 的核心组件。它的主要功能是：

**核心功能:**

1. **表示需要重新计算样式的元素集合:**  `InvalidationSet` 对象存储了导致某些元素样式失效的信息。这个信息可以是：
    * **特定的 CSS 选择器:**  比如类名、ID、标签名、属性选择器等。
    * **更广范围的失效标记:** 比如整个子树失效、与特定伪类相关的失效等。

2. **优化样式失效过程:** 通过精确地跟踪哪些元素因为哪些 CSS 规则的变化而需要重新计算样式，Blink 引擎可以避免不必要的样式计算，提高渲染性能。

3. **组合和管理失效信息:**  当多个 CSS 规则或 DOM 变化导致样式失效时，`InvalidationSet` 提供了合并和管理这些失效信息的能力。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`InvalidationSet` 处于连接 HTML 结构 (DOM)、CSS 样式和 JavaScript 行为的关键位置。

* **HTML (DOM):**
    * **关系:** 当 HTML 结构发生变化（例如，添加、删除元素、修改元素的类名、ID、属性等）时，会触发样式失效。`InvalidationSet` 会记录这些变化影响到的元素。
    * **举例:**
        * **假设输入:**  JavaScript 代码 `element.classList.add('new-class');` 给一个 HTML 元素添加了一个新的类名。
        * **输出:**  如果 CSS 中存在针对 `.new-class` 的规则，那么会创建一个 `InvalidationSet`，其中包含了 `.new-class` 这个类名，并关联到 `element`。

* **CSS:**
    * **关系:**  当 CSS 规则发生变化（例如，修改样式表、添加新的 CSS 规则、删除现有的 CSS 规则）时，需要确定哪些元素受到影响，并将其添加到失效集合中。`InvalidationSet` 存储了与这些变化相关的选择器信息。
    * **举例:**
        * **假设输入:**  JavaScript 代码修改了 CSS 规则： `document.styleSheets[0].rules[0].style.color = 'blue';`
        * **输出:**  Blink 引擎会分析被修改的 CSS 规则的选择器，并创建或更新 `InvalidationSet` 对象，使其包含与该选择器匹配的元素的相关信息。例如，如果选择器是 `p`, 那么所有 `<p>` 元素都可能被添加到失效集合中。

* **JavaScript:**
    * **关系:** JavaScript 代码经常会直接或间接地触发样式失效。例如，通过修改 DOM 结构或元素的属性，或者通过动态地添加/删除 CSS 类。
    * **举例:**
        * **假设输入:**  JavaScript 代码 `element.style.display = 'none';` 直接修改了元素的样式。
        * **输出:**  虽然这个例子没有直接涉及到 CSS 选择器，但它仍然会导致样式失效。Blink 可能会创建一个 `InvalidationSet`，标记该元素需要重新计算样式。
        * **假设输入:**  JavaScript 代码动态地创建并插入一个包含特定类名的元素。
        * **输出:**  如果 CSS 中存在针对该类名的规则，会创建一个 `InvalidationSet`，其中包含了该类名。

**逻辑推理及假设输入与输出:**

* **假设输入:** 存在一个 CSS 规则 `.active { color: red; }`，并且一个 HTML 元素 `<div id="myDiv"></div>`。JavaScript 代码执行 `document.getElementById('myDiv').classList.add('active');`
* **逻辑推理:**
    1. JavaScript 代码修改了 DOM 元素的类名。
    2. Blink 的样式系统会检测到 DOM 的变化。
    3. 样式系统会检查是否存在与新添加的类名 `.active` 匹配的 CSS 规则。
    4. 发现存在匹配的规则。
    5. 创建一个 `InvalidationSet` 对象。
    6. 该 `InvalidationSet` 对象会包含类名 `active`。
    7. 该 `InvalidationSet` 对象会与 `id="myDiv"` 的元素关联。
* **输出:**  一个 `InvalidationSet` 对象，其 `classes_` 成员（用于存储类名）包含 "active"。

**用户或编程常见的使用错误及举例说明:**

虽然用户不会直接操作 `InvalidationSet`，但编程上的错误会导致意外的样式失效，从而影响性能。

* **常见错误:**  过度使用通配符选择器 (e.g., `*`) 或过于宽泛的选择器 (e.g.,  直接使用标签名而不加限制)，导致不必要的元素被添加到失效集合。
    * **举例:**  CSS 规则 `* { margin: 0; }` 会导致任何元素的样式改变都可能触发广泛的失效。
    * **后果:** 每次有元素发生变化，几乎所有元素都可能需要重新计算样式，导致性能下降。

* **常见错误:**  在 JavaScript 中频繁地修改元素的 style 属性，而不是通过修改类名来应用样式。
    * **举例:**  JavaScript 代码中循环遍历大量元素并直接修改它们的 `style.color` 属性。
    * **后果:**  这可能导致频繁且细粒度的样式失效，难以被 `InvalidationSet` 有效地优化。

**用户操作是如何一步步的到达这里，作为调试线索:**

当开发者需要调试与样式失效相关的问题时，理解用户操作如何触发 `InvalidationSet` 的创建和使用至关重要。以下是一个可能的路径：

1. **用户操作:** 用户与网页进行交互，例如：
    * **点击按钮:**  触发 JavaScript 事件。
    * **鼠标悬停:** 触发 CSS 伪类 `:hover` 的状态改变。
    * **输入文本:**  可能触发表单元素的样式变化。
    * **页面滚动:**  可能触发粘性布局或视口相关的样式变化。

2. **JavaScript 执行 (如果涉及):** 用户操作可能触发 JavaScript 代码的执行，这些代码可能会：
    * **修改 DOM 结构:**  添加、删除元素。
    * **修改元素属性或类名:**  使用 `setAttribute`, `classList.add`, `classList.remove` 等。
    * **修改元素的 style 属性:**  直接设置元素的内联样式。
    * **动态修改 CSS 样式表:**  通过 JavaScript 操作 `document.styleSheets`。

3. **样式系统检测变化:**  Blink 的样式系统会监听 DOM 和 CSS 的变化。当检测到变化时，会开始评估哪些元素的样式可能受到影响。

4. **创建或更新 InvalidationSet:**  根据变化的类型和影响范围，Blink 会创建或更新 `InvalidationSet` 对象：
    * **如果 DOM 元素的类名或 ID 发生变化，并且存在匹配的 CSS 选择器，`InvalidationSet` 会记录这些类名或 ID。**
    * **如果 CSS 规则被添加、删除或修改，`InvalidationSet` 会记录与这些规则选择器匹配的元素相关信息。**
    * **某些操作，例如修改伪类状态，也会导致创建特定的 `InvalidationSet`。**

5. **样式重新计算:**  接下来，Blink 的样式解析器会利用 `InvalidationSet` 中存储的信息，高效地选择需要重新计算样式的元素，并进行样式计算。

**作为调试线索:**

* **Performance 面板:**  Chrome 开发者工具的 Performance 面板可以帮助开发者分析样式计算 (Recalculate Style) 的耗时，以及哪些 CSS 规则和元素参与了样式计算。
* **"Show Style Recalculations" 设置:** 在 Chrome 的 "Rendering" 设置中，可以开启 "Show Style Recalculations"，这会在页面上高亮显示需要重新计算样式的区域，帮助开发者直观地了解哪些元素被包含在失效集合中。
* **代码断点:** 开发者可以在 `invalidation_set.cc` 文件中的关键函数（例如 `InvalidatesElement`, `Combine`, `AddClass` 等）设置断点，观察 `InvalidationSet` 的创建、更新和使用过程，从而理解特定用户操作是如何导致样式失效的。
* **Tracing 工具:**  Blink 内部的 tracing 工具（如 Perfetto）可以提供更底层的性能分析数据，包括 `InvalidationSet` 的创建和传递。

总而言之，`invalidation_set.cc` 中定义的 `InvalidationSet` 类是 Blink 引擎高效处理 CSS 样式失效的核心机制，它连接了 HTML、CSS 和 JavaScript 的变化，并通过精确跟踪需要重新计算样式的元素，优化了渲染性能。理解其工作原理对于理解和调试 Web 应用的性能问题至关重要。

### 提示词
```
这是目录为blink/renderer/core/css/invalidation/invalidation_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/css/invalidation/invalidation_set.h"

#include <memory>
#include <utility>

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/css/invalidation/invalidation_tracing_flag.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/inspector/invalidation_set_to_selector_map.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

template <InvalidationSet::BackingType type>
bool BackingEqual(const InvalidationSet::BackingFlags& a_flags,
                  const InvalidationSet::Backing<type>& a,
                  const InvalidationSet::BackingFlags& b_flags,
                  const InvalidationSet::Backing<type>& b) {
  if (a.Size(a_flags) != b.Size(b_flags)) {
    return false;
  }
  for (const AtomicString& value : a.Items(a_flags)) {
    if (!b.Contains(b_flags, value)) {
      return false;
    }
  }
  return true;
}

}  // namespace

#define TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED( \
    element, reason, invalidationSet, singleSelectorPart)             \
  if (InvalidationTracingFlag::IsEnabled()) [[unlikely]]              \
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART(                \
        element, reason, invalidationSet, singleSelectorPart);

// static
void InvalidationSetDeleter::Destruct(const InvalidationSet* obj) {
  obj->Destroy();
}

bool InvalidationSet::operator==(const InvalidationSet& other) const {
  if (GetType() != other.GetType()) {
    return false;
  }

  if (GetType() == InvalidationType::kInvalidateSiblings) {
    const auto& this_sibling = To<SiblingInvalidationSet>(*this);
    const auto& other_sibling = To<SiblingInvalidationSet>(other);
    if ((this_sibling.MaxDirectAdjacentSelectors() !=
         other_sibling.MaxDirectAdjacentSelectors()) ||
        !base::ValuesEquivalent(this_sibling.Descendants(),
                                other_sibling.Descendants()) ||
        !base::ValuesEquivalent(this_sibling.SiblingDescendants(),
                                other_sibling.SiblingDescendants())) {
      return false;
    }
  }

  if (invalidation_flags_ != other.invalidation_flags_) {
    return false;
  }
  if (invalidates_self_ != other.invalidates_self_) {
    return false;
  }

  return BackingEqual(backing_flags_, classes_, other.backing_flags_,
                      other.classes_) &&
         BackingEqual(backing_flags_, ids_, other.backing_flags_, other.ids_) &&
         BackingEqual(backing_flags_, tag_names_, other.backing_flags_,
                      other.tag_names_) &&
         BackingEqual(backing_flags_, attributes_, other.backing_flags_,
                      other.attributes_);
}

InvalidationSet::InvalidationSet(InvalidationType type)
    : type_(static_cast<unsigned>(type)),
      invalidates_self_(false),
      invalidates_nth_(false),
      is_alive_(true) {}

bool InvalidationSet::InvalidatesElement(Element& element) const {
  if (invalidation_flags_.WholeSubtreeInvalid()) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
        element, kInvalidationSetInvalidatesSubtree, *this, g_empty_atom);
    return true;
  }

  if (HasTagNames() && HasTagName(element.LocalNameForSelectorMatching())) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
        element, kInvalidationSetMatchedTagName, *this,
        element.LocalNameForSelectorMatching());
    return true;
  }

  if (element.HasID() && HasIds() && HasId(element.IdForStyleResolution())) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
        element, kInvalidationSetMatchedId, *this,
        element.IdForStyleResolution());
    return true;
  }

  if (element.HasClass() && HasClasses()) {
    if (const AtomicString* class_name = FindAnyClass(element)) {
      TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
          element, kInvalidationSetMatchedClass, *this, *class_name);
      return true;
    }
  }

  if (element.hasAttributes() && HasAttributes()) {
    if (const AtomicString* attribute = FindAnyAttribute(element)) {
      TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
          element, kInvalidationSetMatchedAttribute, *this, *attribute);
      return true;
    }
  }

  if (element.HasPart() && invalidation_flags_.InvalidatesParts()) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
        element, kInvalidationSetMatchedPart, *this, g_empty_atom);
    return true;
  }

  return false;
}

bool InvalidationSet::InvalidatesTagName(Element& element) const {
  if (HasTagNames() && HasTagName(element.LocalNameForSelectorMatching())) {
    TRACE_STYLE_INVALIDATOR_INVALIDATION_SELECTORPART_IF_ENABLED(
        element, kInvalidationSetMatchedTagName, *this,
        element.LocalNameForSelectorMatching());
    return true;
  }

  return false;
}

void InvalidationSet::Combine(const InvalidationSet& other) {
  CHECK(is_alive_);
  CHECK(other.is_alive_);
  CHECK_EQ(GetType(), other.GetType());

  if (IsSelfInvalidationSet()) {
    // We should never modify the SelfInvalidationSet singleton. When
    // aggregating the contents from another invalidation set into an
    // invalidation set which only invalidates self, we instantiate a new
    // DescendantInvalidation set before calling Combine(). We still may end up
    // here if we try to combine two references to the singleton set.
    DCHECK(other.IsSelfInvalidationSet());
    return;
  }

  CHECK_NE(&other, this);
  InvalidationSetToSelectorMap::CombineScope combine_scope(this, &other);

  if (auto* invalidation_set = DynamicTo<SiblingInvalidationSet>(this)) {
    SiblingInvalidationSet& siblings = *invalidation_set;
    const SiblingInvalidationSet& other_siblings =
        To<SiblingInvalidationSet>(other);

    siblings.UpdateMaxDirectAdjacentSelectors(
        other_siblings.MaxDirectAdjacentSelectors());
    if (other_siblings.SiblingDescendants()) {
      siblings.EnsureSiblingDescendants().Combine(
          *other_siblings.SiblingDescendants());
    }
    if (other_siblings.Descendants()) {
      siblings.EnsureDescendants().Combine(*other_siblings.Descendants());
    }
  }

  if (other.InvalidatesNth()) {
    SetInvalidatesNth();
  }

  if (other.InvalidatesSelf()) {
    SetInvalidatesSelf();
    if (other.IsSelfInvalidationSet()) {
      return;
    }
  }

  // No longer bother combining data structures, since the whole subtree is
  // deemed invalid.
  if (WholeSubtreeInvalid()) {
    return;
  }

  if (other.WholeSubtreeInvalid()) {
    SetWholeSubtreeInvalid();
    return;
  }

  if (other.CustomPseudoInvalid()) {
    SetCustomPseudoInvalid();
  }

  if (other.TreeBoundaryCrossing()) {
    SetTreeBoundaryCrossing();
  }

  if (other.InsertionPointCrossing()) {
    SetInsertionPointCrossing();
  }

  if (other.InvalidatesSlotted()) {
    SetInvalidatesSlotted();
  }

  if (other.InvalidatesParts()) {
    SetInvalidatesParts();
  }

  for (const auto& class_name : other.Classes()) {
    AddClass(class_name);
  }

  for (const auto& id : other.Ids()) {
    AddId(id);
  }

  for (const auto& tag_name : other.TagNames()) {
    AddTagName(tag_name);
  }

  for (const auto& attribute : other.Attributes()) {
    AddAttribute(attribute);
  }
}

void InvalidationSet::Destroy() const {
  InvalidationSetToSelectorMap::RemoveEntriesForInvalidationSet(this);
  if (auto* invalidation_set = DynamicTo<DescendantInvalidationSet>(this)) {
    delete invalidation_set;
  } else {
    delete To<SiblingInvalidationSet>(this);
  }
}

void InvalidationSet::ClearAllBackings() {
  classes_.Clear(backing_flags_);
  ids_.Clear(backing_flags_);
  tag_names_.Clear(backing_flags_);
  attributes_.Clear(backing_flags_);
}

bool InvalidationSet::HasEmptyBackings() const {
  return classes_.IsEmpty(backing_flags_) && ids_.IsEmpty(backing_flags_) &&
         tag_names_.IsEmpty(backing_flags_) &&
         attributes_.IsEmpty(backing_flags_);
}

const AtomicString* InvalidationSet::FindAnyClass(Element& element) const {
  const SpaceSplitString& class_names = element.ClassNames();
  wtf_size_t size = class_names.size();
  if (const AtomicString* string = classes_.GetString(backing_flags_)) {
    for (wtf_size_t i = 0; i < size; ++i) {
      if (*string == class_names[i]) {
        return string;
      }
    }
  }
  if (const HashSet<AtomicString>* set = classes_.GetHashSet(backing_flags_)) {
    for (wtf_size_t i = 0; i < size; ++i) {
      auto item = set->find(class_names[i]);
      if (item != set->end()) {
        return item.Get();
      }
    }
  }
  return nullptr;
}

const AtomicString* InvalidationSet::FindAnyAttribute(Element& element) const {
  if (const AtomicString* string = attributes_.GetString(backing_flags_)) {
    if (element.HasAttributeIgnoringNamespace(*string)) {
      return string;
    }
  }
  if (const HashSet<AtomicString>* set =
          attributes_.GetHashSet(backing_flags_)) {
    for (const auto& attribute : *set) {
      if (element.HasAttributeIgnoringNamespace(attribute)) {
        return &attribute;
      }
    }
  }
  return nullptr;
}

void InvalidationSet::AddClass(const AtomicString& class_name) {
  if (WholeSubtreeInvalid()) {
    return;
  }
  CHECK(!class_name.empty());
  classes_.Add(backing_flags_, class_name);
}

void InvalidationSet::AddId(const AtomicString& id) {
  if (WholeSubtreeInvalid()) {
    return;
  }
  CHECK(!id.empty());
  ids_.Add(backing_flags_, id);
}

void InvalidationSet::AddTagName(const AtomicString& tag_name) {
  if (WholeSubtreeInvalid()) {
    return;
  }
  CHECK(!tag_name.empty());
  tag_names_.Add(backing_flags_, tag_name);
}

void InvalidationSet::AddAttribute(const AtomicString& attribute) {
  if (WholeSubtreeInvalid()) {
    return;
  }
  CHECK(!attribute.empty());
  attributes_.Add(backing_flags_, attribute);
}

void InvalidationSet::SetWholeSubtreeInvalid() {
  if (invalidation_flags_.WholeSubtreeInvalid()) {
    return;
  }

  invalidation_flags_.SetWholeSubtreeInvalid(true);
  invalidation_flags_.SetInvalidateCustomPseudo(false);
  invalidation_flags_.SetTreeBoundaryCrossing(false);
  invalidation_flags_.SetInsertionPointCrossing(false);
  invalidation_flags_.SetInvalidatesSlotted(false);
  invalidation_flags_.SetInvalidatesParts(false);
  ClearAllBackings();
}

namespace {

scoped_refptr<DescendantInvalidationSet> CreateSelfInvalidationSet() {
  auto new_set = DescendantInvalidationSet::Create();
  new_set->SetInvalidatesSelf();
  return new_set;
}

scoped_refptr<DescendantInvalidationSet> CreatePartInvalidationSet() {
  auto new_set = DescendantInvalidationSet::Create();
  new_set->SetInvalidatesParts();
  new_set->SetTreeBoundaryCrossing();
  return new_set;
}

}  // namespace

InvalidationSet* InvalidationSet::SelfInvalidationSet() {
  DEFINE_STATIC_REF(InvalidationSet, singleton_, CreateSelfInvalidationSet());
  return singleton_;
}

InvalidationSet* InvalidationSet::PartInvalidationSet() {
  DEFINE_STATIC_REF(InvalidationSet, singleton_, CreatePartInvalidationSet());
  return singleton_;
}

void InvalidationSet::WriteIntoTrace(perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();

  dict.Add("id", DescendantInvalidationSetToIdString(*this));

  if (invalidation_flags_.WholeSubtreeInvalid()) {
    dict.Add("allDescendantsMightBeInvalid", true);
  }
  if (invalidation_flags_.InvalidateCustomPseudo()) {
    dict.Add("customPseudoInvalid", true);
  }
  if (invalidation_flags_.TreeBoundaryCrossing()) {
    dict.Add("treeBoundaryCrossing", true);
  }
  if (invalidation_flags_.InsertionPointCrossing()) {
    dict.Add("insertionPointCrossing", true);
  }
  if (invalidation_flags_.InvalidatesSlotted()) {
    dict.Add("invalidatesSlotted", true);
  }
  if (invalidation_flags_.InvalidatesParts()) {
    dict.Add("invalidatesParts", true);
  }

  if (HasIds()) {
    dict.Add("ids", Ids());
  }

  if (HasClasses()) {
    dict.Add("classes", Classes());
  }

  if (HasTagNames()) {
    dict.Add("tagNames", TagNames());
  }

  if (HasAttributes()) {
    dict.Add("attributes", Attributes());
  }
}

String InvalidationSet::ToString() const {
  auto format_backing = [](auto range, const char* prefix, const char* suffix) {
    StringBuilder builder;

    Vector<AtomicString> names;
    for (const auto& str : range) {
      names.push_back(str);
    }
    std::sort(names.begin(), names.end(), WTF::CodeUnitCompareLessThan);

    for (const auto& name : names) {
      if (!builder.empty()) {
        builder.Append(" ");
      }
      builder.Append(prefix);
      builder.Append(name);
      builder.Append(suffix);
    }

    return builder.ReleaseString();
  };

  StringBuilder features;

  if (HasIds()) {
    features.Append(format_backing(Ids(), "#", ""));
  }
  if (HasClasses()) {
    features.Append(!features.empty() ? " " : "");
    features.Append(format_backing(Classes(), ".", ""));
  }
  if (HasTagNames()) {
    features.Append(!features.empty() ? " " : "");
    features.Append(format_backing(TagNames(), "", ""));
  }
  if (HasAttributes()) {
    features.Append(!features.empty() ? " " : "");
    features.Append(format_backing(Attributes(), "[", "]"));
  }

  auto format_max_direct_adjancent = [](const InvalidationSet* set) -> String {
    const auto* sibling = DynamicTo<SiblingInvalidationSet>(set);
    if (!sibling) {
      return g_empty_atom;
    }
    unsigned max = sibling->MaxDirectAdjacentSelectors();
    if (max == SiblingInvalidationSet::kDirectAdjacentMax) {
      return "~";
    }
    if (max != 1) {
      return String::Number(max);
    }
    return g_empty_atom;
  };

  StringBuilder metadata;
  metadata.Append(InvalidatesSelf() ? "$" : "");
  metadata.Append(InvalidatesNth() ? "N" : "");
  metadata.Append(invalidation_flags_.WholeSubtreeInvalid() ? "W" : "");
  metadata.Append(invalidation_flags_.InvalidateCustomPseudo() ? "C" : "");
  metadata.Append(invalidation_flags_.TreeBoundaryCrossing() ? "T" : "");
  metadata.Append(invalidation_flags_.InsertionPointCrossing() ? "I" : "");
  metadata.Append(invalidation_flags_.InvalidatesSlotted() ? "S" : "");
  metadata.Append(invalidation_flags_.InvalidatesParts() ? "P" : "");
  metadata.Append(format_max_direct_adjancent(this));

  StringBuilder main;
  main.Append("{");
  if (!features.empty()) {
    main.Append(" ");
    main.Append(features);
  }
  if (!metadata.empty()) {
    main.Append(" ");
    main.Append(metadata);
  }
  main.Append(" }");

  return main.ReleaseString();
}

SiblingInvalidationSet::SiblingInvalidationSet(
    scoped_refptr<DescendantInvalidationSet> descendants)
    : InvalidationSet(InvalidationType::kInvalidateSiblings),
      max_direct_adjacent_selectors_(1),
      descendant_invalidation_set_(std::move(descendants)) {}

SiblingInvalidationSet::SiblingInvalidationSet()
    : InvalidationSet(InvalidationType::kInvalidateNthSiblings),
      max_direct_adjacent_selectors_(kDirectAdjacentMax) {}

DescendantInvalidationSet& SiblingInvalidationSet::EnsureSiblingDescendants() {
  if (!sibling_descendant_invalidation_set_) {
    sibling_descendant_invalidation_set_ = DescendantInvalidationSet::Create();
  }
  return *sibling_descendant_invalidation_set_;
}

DescendantInvalidationSet& SiblingInvalidationSet::EnsureDescendants() {
  if (!descendant_invalidation_set_) {
    descendant_invalidation_set_ = DescendantInvalidationSet::Create();
  }
  return *descendant_invalidation_set_;
}

std::ostream& operator<<(std::ostream& ostream, const InvalidationSet& set) {
  return ostream << set.ToString().Utf8();
}

}  // namespace blink
```