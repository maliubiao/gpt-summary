Response:
The user wants me to analyze the provided C++ code snippet from the Chromium Blink engine and describe its functionalities. I need to explain its relationship with web technologies like JavaScript, HTML, and CSS, providing examples. I should also discuss logical reasoning with input/output examples, common user errors, and steps to reach this code during debugging. Finally, I need to summarize the overall function of this code, considering this is the third part of the analysis.

**Plan:**

1. **Overall Function:** Based on the code, the primary function is to manage and create `InvalidationSet` objects. These sets seem to be used for tracking which parts of the DOM tree need to be re-rendered when CSS rules change.
2. **CSS Relationship:** The code directly deals with `CSSSelector` and its pseudo-classes. This strongly ties it to CSS rule processing and invalidation.
3. **HTML Relationship:** Invalidation is triggered by changes in the HTML structure or attributes. This code likely plays a role in determining which elements are affected by CSS rule changes based on their HTML attributes, classes, IDs, etc.
4. **JavaScript Relationship:** JavaScript can manipulate the DOM, which can trigger CSS invalidation. While this code doesn't directly interact with JavaScript, its output (the `InvalidationSet`) would be used by other parts of the engine when JavaScript modifies the DOM and affects CSS rules.
5. **Logical Reasoning:** I'll focus on the conditional logic within the `Ensure...InvalidationSet` functions. I'll create hypothetical scenarios where different inputs (selector types, invalidation types, positions) lead to different outputs (creation of specific `InvalidationSet` types or returning existing ones).
6. **User Errors:**  Since this is backend code, direct user errors are less likely. However, incorrect CSS syntax or illogical CSS rules could indirectly lead to issues that might be investigated using this code as part of the debugging process.
7. **Debugging Steps:** I'll outline a typical scenario where a developer might be investigating why a certain CSS rule is not being applied correctly after a DOM manipulation, leading them to examine the invalidation logic.
8. **Part 3 Summary:** I'll focus on the specific functionalities covered in this code snippet, which are primarily the creation and retrieval of different types of `InvalidationSet` objects based on CSS selectors. I'll integrate the insights from parts 1 and 2 if they are available in the user's prompt history. (Since they are not provided, I will focus on the provided snippet).
这是 blink 渲染引擎中 `RuleInvalidationDataVisitor` 的第三部分代码，其主要功能是 **确保和管理用于 CSS 规则失效的各种类型的 `InvalidationSet` 对象**。`InvalidationSet` 用于跟踪当 CSS 规则发生变化时，哪些 DOM 树的部分需要重新渲染。

**以下是该部分代码功能的详细列举和说明：**

1. **为不同类型的 CSS 选择器元素创建或获取 `InvalidationSet`：**
    *   **`EnsureClassInvalidationSet`:**  为类选择器（例如 `.my-class`）创建或获取 `InvalidationSet`。
    *   **`EnsureAttributeInvalidationSet`:** 为属性选择器（例如 `[data-attribute]`）创建或获取 `InvalidationSet`。
    *   **`EnsureIdInvalidationSet`:** 为 ID 选择器（例如 `#my-id`）创建或获取 `InvalidationSet`。
    *   **`EnsurePseudoInvalidationSet`:** 为伪类选择器（例如 `:hover`, `:nth-child`）创建或获取 `InvalidationSet`。

2. **处理不同的伪类：**
    *   代码中 `switch` 语句覆盖了大量的 CSS 伪类，并根据伪类的类型决定是否需要创建特定的 `InvalidationSet`。
    *   对于像 `:hover`, `:focus`, `:active` 这样的状态伪类，它会调用 `EnsurePseudoInvalidationSet`。
    *   对于像 `:nth-child`, `:first-of-type` 这样的结构化伪类，它会调用 `EnsureNthInvalidationSet`。
    *   对于 `:has` 伪类，它会根据 `position` 参数来决定是否创建 `InvalidationSet`。

3. **处理通用兄弟选择器：**
    *   **`EnsureUniversalSiblingInvalidationSet`:**  为通用兄弟选择器 (`~`) 创建或获取 `InvalidationSet`。

4. **处理结构化伪类（如 nth-child）：**
    *   **`EnsureNthInvalidationSet`:** 为结构化伪类选择器创建或获取 `InvalidationSet`。

5. **向 `InvalidationSet` 添加特征：**
    *   **`AddFeaturesToInvalidationSet`:**  将从 CSS 选择器中提取的特征（如 ID、类名、标签名、属性）添加到相应的 `InvalidationSet` 中。这些特征用于更精确地确定哪些元素需要失效。

6. **设置 `InvalidationSet` 的属性：**
    *   **`SetWholeSubtreeInvalid`:** 标记 `InvalidationSet` 为整个子树失效。
    *   **`SetInvalidatesSelf`:** 标记 `InvalidationSet` 为自身失效。
    *   **`SetInvalidatesNth`:** 标记 `InvalidationSet` 与 `nth` 选择器相关。
    *   **`UpdateMaxDirectAdjacentSelectors`:**  更新兄弟失效集合中直接相邻选择器的最大数量。

7. **使用 Bloom Filter 优化自失效判断：**
    *   **`InsertIntoSelfInvalidationBloomFilter`:** 使用 Bloom Filter 来快速判断某个名字（如类名、ID）是否会导致自身失效。这是一种性能优化，避免了在所有失效集合中查找。

8. **处理兄弟后代失效：**
    *   **`EnsureSiblingDescendantInvalidationSet`:** 确保为兄弟选择器 (`+`, `~`) 的后代创建或获取 `InvalidationSet`。

9. **确保 `InvalidationSet` 的可修改性：**
    *   **`EnsureMutableInvalidationSet`:** 确保返回的 `InvalidationSet` 是可修改的，必要时会复制 `InvalidationSet` 以避免修改共享的实例。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

*   **CSS:** 该代码直接处理 CSS 选择器，是 CSS 规则失效机制的核心部分。它根据 CSS 规则中使用的选择器类型创建相应的失效集合。
    *   **例子：** 当 CSS 规则 `.my-class { color: red; }` 被添加到样式表中时，`EnsureClassInvalidationSet("my-class", ...)` 会被调用，创建一个与类名 "my-class" 关联的失效集合。

*   **HTML:**  `InvalidationSet` 最终会影响 HTML 元素。当 HTML 元素的属性、类名或 ID 发生变化时，或者当元素的状态发生变化（例如鼠标悬停），与这些变化相关的 `InvalidationSet` 会被触发，导致浏览器重新渲染受影响的元素。
    *   **例子：**  如果一个 HTML 元素从 `<div class="old-class">` 变为 `<div class="my-class">`，那么与 "old-class" 相关的失效集合可能不再匹配，而与 "my-class" 相关的失效集合会被激活，触发与 `.my-class` 规则相关的样式更新。

*   **JavaScript:** JavaScript 可以通过 DOM API 修改 HTML 结构和元素的属性，这些修改会触发 CSS 失效。
    *   **例子：** 当 JavaScript 代码使用 `element.classList.add('my-class')` 为一个元素添加类名时，这个操作可能会导致与 `.my-class` 选择器相关的 CSS 规则生效，而 `RuleInvalidationDataVisitor` 参与了这个失效过程，确保相关的元素被标记为需要重新渲染。

**逻辑推理和假设输入与输出：**

假设输入一个 CSS 选择器 `:hover` 应用于一个 `<a>` 标签。

*   **输入：**
    *   `selector.GetPseudoType()` 返回 `CSSSelector::kPseudoHover`
    *   `type` 可能为 `InvalidationType::kInvalidateDescendants` 或 `InvalidationType::kInvalidateSiblings`，取决于具体的上下文。
    *   `position` 可能为 `kSubject` 或 `kAncestor`，取决于 `:hover` 是直接应用在目标元素上还是作为祖先元素的一部分。
    *   `in_nth_child` 可能为 `true` 或 `false`。
*   **输出：**
    *   `EnsurePseudoInvalidationSet(CSSSelector::kPseudoHover, type, position, in_nth_child)` 将被调用。
    *   如果与 `:hover` 相关的 `InvalidationSet` 已经存在，则返回该实例。
    *   如果不存在，则创建一个新的 `InvalidationSet` 并返回。

假设输入一个 CSS 选择器 `div.active`，并且当前正在处理类名 "active"。

*   **输入：**
    *   `class_name` 为 `"active"`
    *   `type`, `position`, `in_nth_child` 的值取决于上下文。
*   **输出：**
    *   `EnsureClassInvalidationSet("active", type, position, in_nth_child)` 将被调用。
    *   如果与类名 "active" 相关的 `InvalidationSet` 已经存在，并且类型匹配，则返回该实例。
    *   如果不存在或类型不匹配，则可能创建一个新的 `InvalidationSet` 或返回现有集合的子集（例如，如果需要后代失效，但只找到兄弟+后代失效集合）。

**用户或编程常见的使用错误：**

由于这段代码是 Blink 引擎的内部实现，普通用户不会直接与之交互。编程错误通常发生在编写和管理 CSS 规则的过程中，这些错误可能会导致不期望的失效行为，而 `RuleInvalidationDataVisitor` 会参与处理这些情况。

*   **CSS 选择器效率低下：** 使用过于宽泛或复杂的 CSS 选择器可能会导致过多的元素失效，影响性能。例如，使用 `*` 选择器或没有限制的后代选择器 (`div p`)。
*   **频繁的 DOM 操作：**  JavaScript 代码频繁地修改 DOM 结构或元素属性会导致 CSS 失效频繁触发，可能导致页面卡顿。例如，在一个循环中不断添加或删除元素的类名。
*   **CSS 动画和过渡：**  虽然不是错误，但过度使用 CSS 动画和过渡可能会导致频繁的样式计算和失效。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户遇到了一个问题：当鼠标悬停在一个链接上时，链接的样式没有正确更新。作为调试线索，开发者可能会按照以下步骤进行：

1. **用户交互：** 用户将鼠标光标移动到 HTML 中的一个 `<a>` 标签上。
2. **浏览器事件触发：** 鼠标悬停事件被浏览器捕获。
3. **状态变化：** 链接元素的状态从非悬停变为悬停。
4. **样式重新计算触发：** 浏览器需要重新计算元素的样式，以应用 `:hover` 伪类的样式规则。
5. **CSS 规则匹配：** 浏览器会查找与该元素匹配的 CSS 规则，包括包含 `:hover` 伪类的规则。
6. **`RuleInvalidationDataVisitor` 参与：**  当涉及到 `:hover` 伪类时，`RuleInvalidationDataVisitor::EnsurePseudoInvalidationSet(CSSSelector::kPseudoHover, ...)` 会被调用，以获取或创建与 `:hover` 相关的 `InvalidationSet`。
7. **失效集合检查：**  浏览器会检查与该元素相关的失效集合，确定是否需要重新渲染。
8. **样式应用和渲染：** 如果需要重新渲染，浏览器会根据匹配到的 CSS 规则更新元素的样式并进行渲染。

如果样式没有正确更新，开发者可能会在 `RuleInvalidationDataVisitor` 相关的代码中设置断点，例如在 `EnsurePseudoInvalidationSet` 函数中，检查是否正确创建了失效集合，以及与 `:hover` 相关的规则是否被正确关联。

**归纳一下它的功能（第3部分）：**

作为第三部分，这段代码的核心功能是 **具体实现了 `RuleInvalidationDataVisitor` 中用于创建和管理各种类型 `InvalidationSet` 对象的逻辑**。它涵盖了处理不同类型的 CSS 选择器（类、ID、属性、伪类）以及结构化伪类和通用兄弟选择器的机制。此外，它还负责将从选择器中提取的特征信息添加到相应的 `InvalidationSet` 中，并使用 Bloom Filter 进行性能优化。简单来说，这部分代码是 `RuleInvalidationDataVisitor` 中构建 CSS 规则失效信息的核心组成部分。

### 提示词
```
这是目录为blink/renderer/core/css/invalidation/rule_invalidation_data_visitor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
case CSSSelector::kPseudoWebkitAnyLink:
      case CSSSelector::kPseudoAnyLink:
      case CSSSelector::kPseudoAutofill:
      case CSSSelector::kPseudoWebKitAutofill:
      case CSSSelector::kPseudoAutofillPreviewed:
      case CSSSelector::kPseudoAutofillSelected:
      case CSSSelector::kPseudoHover:
      case CSSSelector::kPseudoDrag:
      case CSSSelector::kPseudoFocus:
      case CSSSelector::kPseudoFocusVisible:
      case CSSSelector::kPseudoFocusWithin:
      case CSSSelector::kPseudoActive:
      case CSSSelector::kPseudoChecked:
      case CSSSelector::kPseudoEnabled:
      case CSSSelector::kPseudoDefault:
      case CSSSelector::kPseudoDisabled:
      case CSSSelector::kPseudoOptional:
      case CSSSelector::kPseudoPlaceholderShown:
      case CSSSelector::kPseudoRequired:
      case CSSSelector::kPseudoReadOnly:
      case CSSSelector::kPseudoReadWrite:
      case CSSSelector::kPseudoState:
      case CSSSelector::kPseudoStateDeprecatedSyntax:
      case CSSSelector::kPseudoUserInvalid:
      case CSSSelector::kPseudoUserValid:
      case CSSSelector::kPseudoValid:
      case CSSSelector::kPseudoInvalid:
      case CSSSelector::kPseudoIndeterminate:
      case CSSSelector::kPseudoTarget:
      case CSSSelector::kPseudoLang:
      case CSSSelector::kPseudoDir:
      case CSSSelector::kPseudoFullScreen:
      case CSSSelector::kPseudoFullScreenAncestor:
      case CSSSelector::kPseudoFullscreen:
      case CSSSelector::kPseudoPaused:
      case CSSSelector::kPseudoPermissionElementInvalidStyle:
      case CSSSelector::kPseudoPermissionElementOccluded:
      case CSSSelector::kPseudoPermissionGranted:
      case CSSSelector::kPseudoPictureInPicture:
      case CSSSelector::kPseudoPlaying:
      case CSSSelector::kPseudoInRange:
      case CSSSelector::kPseudoOutOfRange:
      case CSSSelector::kPseudoDefined:
      case CSSSelector::kPseudoOpen:
      case CSSSelector::kPseudoClosed:
      case CSSSelector::kPseudoPopoverOpen:
      case CSSSelector::kPseudoVideoPersistent:
      case CSSSelector::kPseudoVideoPersistentAncestor:
      case CSSSelector::kPseudoXrOverlay:
      case CSSSelector::kPseudoHasDatalist:
      case CSSSelector::kPseudoMultiSelectFocus:
      case CSSSelector::kPseudoModal:
      case CSSSelector::kPseudoSelectorFragmentAnchor:
      case CSSSelector::kPseudoActiveViewTransition:
      case CSSSelector::kPseudoActiveViewTransitionType:
      case CSSSelector::kPseudoHasSlotted:
        return EnsurePseudoInvalidationSet(selector.GetPseudoType(), type,
                                           position, in_nth_child);
      case CSSSelector::kPseudoFirstOfType:
      case CSSSelector::kPseudoLastOfType:
      case CSSSelector::kPseudoOnlyOfType:
      case CSSSelector::kPseudoNthChild:
      case CSSSelector::kPseudoNthOfType:
      case CSSSelector::kPseudoNthLastChild:
      case CSSSelector::kPseudoNthLastOfType:
        return EnsureNthInvalidationSet();
      case CSSSelector::kPseudoHas:
        return position == kAncestor
                   ? EnsurePseudoInvalidationSet(selector.GetPseudoType(), type,
                                                 position, in_nth_child)
                   : nullptr;
      case CSSSelector::kPseudoPart:
      default:
        break;
    }
  }
  return nullptr;
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureClassInvalidationSet(
    const AtomicString& class_name,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  CHECK(!class_name.empty());
  return EnsureInvalidationSet(rule_invalidation_data_.class_invalidation_sets,
                               class_name, type, position, in_nth_child);
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureAttributeInvalidationSet(
    const AtomicString& attribute_name,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  CHECK(!attribute_name.empty());
  return EnsureInvalidationSet(
      rule_invalidation_data_.attribute_invalidation_sets, attribute_name, type,
      position, in_nth_child);
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureIdInvalidationSet(
    const AtomicString& id,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  CHECK(!id.empty());
  return EnsureInvalidationSet(rule_invalidation_data_.id_invalidation_sets, id,
                               type, position, in_nth_child);
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsurePseudoInvalidationSet(
    CSSSelector::PseudoType pseudo_type,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  CHECK_NE(pseudo_type, CSSSelector::kPseudoUnknown);
  return EnsureInvalidationSet(rule_invalidation_data_.pseudo_invalidation_sets,
                               pseudo_type, type, position, in_nth_child);
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureInvalidationSet(
    InvalidationSetMapType& map,
    const AtomicString& key,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  if constexpr (is_builder()) {
    scoped_refptr<InvalidationSet>& invalidation_set =
        map.insert(key, nullptr).stored_value->value;
    return &EnsureMutableInvalidationSet(type, position, in_nth_child,
                                         invalidation_set);
  } else {
    auto it = map.find(key);
    if (it != map.end()) {
      const InvalidationSet* invalidation_set = it->value.get();
      if (invalidation_set->GetType() == type) {
        return invalidation_set;
      } else {
        // The caller wanted descendant and we found sibling+descendant.
        CHECK(type == InvalidationType::kInvalidateDescendants);
        return To<SiblingInvalidationSet>(invalidation_set)->Descendants();
      }
    }
    // It is possible for the Tracer not to find an InvalidationSet we expect to
    // be there. One case where this can happen is when, at the time we run the
    // Tracer, a rule has been added to a stylesheet but not yet indexed. In
    // such a case, we'll pick up information about the new rule as it gets
    // indexed on the next document lifecycle update.
    return nullptr;
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureInvalidationSet(
    PseudoTypeInvalidationSetMapType& map,
    CSSSelector::PseudoType key,
    InvalidationType type,
    PositionType position,
    bool in_nth_child) {
  if constexpr (is_builder()) {
    scoped_refptr<InvalidationSet>& invalidation_set =
        map.insert(key, nullptr).stored_value->value;
    return &EnsureMutableInvalidationSet(type, position, in_nth_child,
                                         invalidation_set);
  } else {
    auto it = map.find(key);
    if (it != map.end()) {
      const InvalidationSet* invalidation_set = it->value.get();
      if (invalidation_set->GetType() == type) {
        return invalidation_set;
      } else {
        // The caller wanted descendant and we found sibling+descendant.
        CHECK(type == InvalidationType::kInvalidateDescendants);
        return To<SiblingInvalidationSet>(invalidation_set)->Descendants();
      }
    }
    // It is possible for the Tracer not to find an InvalidationSet we expect to
    // be there. One case where this can happen is when, at the time we run the
    // Tracer, a rule has been added to a stylesheet but not yet indexed. In
    // such a case, we'll pick up information about the new rule as it gets
    // indexed on the next document lifecycle update.
    return nullptr;
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::SiblingInvalidationSetType*
RuleInvalidationDataVisitor<
    VisitorType>::EnsureUniversalSiblingInvalidationSet() {
  if constexpr (is_builder()) {
    if (!rule_invalidation_data_.universal_sibling_invalidation_set) {
      rule_invalidation_data_.universal_sibling_invalidation_set =
          SiblingInvalidationSet::Create(nullptr);
    }
  }
  return rule_invalidation_data_.universal_sibling_invalidation_set.get();
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::SiblingInvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::EnsureNthInvalidationSet() {
  if constexpr (is_builder()) {
    if (!rule_invalidation_data_.nth_invalidation_set) {
      rule_invalidation_data_.nth_invalidation_set =
          NthSiblingInvalidationSet::Create();
    }
  }
  return rule_invalidation_data_.nth_invalidation_set.get();
}

// Add features extracted from the rightmost compound selector to descendant
// invalidation sets for features found in other compound selectors.
//
// We use descendant invalidation for descendants, sibling invalidation for
// siblings and their subtrees.
//
// As we encounter a descendant type of combinator, the features only need to be
// checked against descendants in the same subtree only. features.adjacent is
// set to false, and we start adding features to the descendant invalidation
// set.
template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::AddFeaturesToInvalidationSet(
    InvalidationSetType* invalidation_set,
    const InvalidationSetFeatures& features) {
  if (features.invalidation_flags.TreeBoundaryCrossing()) {
    if constexpr (is_builder()) {
      invalidation_set->SetTreeBoundaryCrossing();
    }
  }
  if (features.invalidation_flags.InsertionPointCrossing()) {
    if constexpr (is_builder()) {
      invalidation_set->SetInsertionPointCrossing();
    }
  }
  if (features.invalidation_flags.InvalidatesSlotted()) {
    if constexpr (is_builder()) {
      invalidation_set->SetInvalidatesSlotted();
    }
  }
  if (features.invalidation_flags.WholeSubtreeInvalid()) {
    SetWholeSubtreeInvalid(invalidation_set);
  }
  if (features.invalidation_flags.InvalidatesParts()) {
    if constexpr (is_builder()) {
      invalidation_set->SetInvalidatesParts();
    }
  }
  if (features.content_pseudo_crossing ||
      features.invalidation_flags.WholeSubtreeInvalid()) {
    return;
  }

  for (const auto& id : features.ids) {
    if constexpr (is_builder()) {
      invalidation_set->AddId(id);
    }
    InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
        invalidation_set,
        InvalidationSetToSelectorMap::SelectorFeatureType::kId, id);
  }
  for (const auto& tag_name : features.tag_names) {
    if constexpr (is_builder()) {
      invalidation_set->AddTagName(tag_name);
    }
    InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
        invalidation_set,
        InvalidationSetToSelectorMap::SelectorFeatureType::kTagName, tag_name);
  }
  for (const auto& emitted_tag_name : features.emitted_tag_names) {
    if constexpr (is_builder()) {
      invalidation_set->AddTagName(emitted_tag_name);
    }
    InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
        invalidation_set,
        InvalidationSetToSelectorMap::SelectorFeatureType::kTagName,
        emitted_tag_name);
  }
  for (const auto& class_name : features.classes) {
    if constexpr (is_builder()) {
      invalidation_set->AddClass(class_name);
    }
    InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
        invalidation_set,
        InvalidationSetToSelectorMap::SelectorFeatureType::kClass, class_name);
  }
  for (const auto& attribute : features.attributes) {
    if constexpr (is_builder()) {
      invalidation_set->AddAttribute(attribute);
    }
    InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
        invalidation_set,
        InvalidationSetToSelectorMap::SelectorFeatureType::kAttribute,
        attribute);
  }
  if (features.invalidation_flags.InvalidateCustomPseudo()) {
    if constexpr (is_builder()) {
      invalidation_set->SetCustomPseudoInvalid();
    }
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::SetWholeSubtreeInvalid(
    InvalidationSetType* invalidation_set) {
  if constexpr (is_builder()) {
    invalidation_set->SetWholeSubtreeInvalid();
  }
  InvalidationSetToSelectorMap::RecordInvalidationSetEntry(
      invalidation_set,
      InvalidationSetToSelectorMap::SelectorFeatureType::kWholeSubtree,
      g_empty_atom);
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::SetInvalidatesSelf(
    InvalidationSetType* invalidation_set) {
  if constexpr (is_builder()) {
    invalidation_set->SetInvalidatesSelf();
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::SetInvalidatesNth(
    InvalidationSetType* invalidation_set) {
  if constexpr (is_builder()) {
    invalidation_set->SetInvalidatesNth();
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
void RuleInvalidationDataVisitor<VisitorType>::UpdateMaxDirectAdjacentSelectors(
    SiblingInvalidationSetType* invalidation_set,
    unsigned value) {
  if constexpr (is_builder()) {
    invalidation_set->UpdateMaxDirectAdjacentSelectors(value);
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
bool RuleInvalidationDataVisitor<VisitorType>::
    InsertIntoSelfInvalidationBloomFilter(const AtomicString& value, int salt) {
  if constexpr (is_builder()) {
    if (rule_invalidation_data_.names_with_self_invalidation == nullptr) {
      if (rule_invalidation_data_.num_candidates_for_names_bloom_filter++ <
          50) {
        // It's not worth spending 2 kB on the Bloom filter for this
        // style sheet yet, so just insert a regular entry.
        return false;
      } else {
        rule_invalidation_data_.names_with_self_invalidation =
            std::make_unique<WTF::BloomFilter<14>>();
      }
    }
    rule_invalidation_data_.names_with_self_invalidation->Add(value.Hash() *
                                                              salt);
    return true;
  } else {
    // In the non-builder case, assume we did not add to the Bloom filter and
    // fall back to looking in the invalidation sets.
    return false;
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
RuleInvalidationDataVisitor<VisitorType>::InvalidationSetType*
RuleInvalidationDataVisitor<VisitorType>::
    EnsureSiblingDescendantInvalidationSet(
        SiblingInvalidationSetType* invalidation_set) {
  if constexpr (is_builder()) {
    return &invalidation_set->EnsureSiblingDescendants();
  } else {
    return invalidation_set->SiblingDescendants();
  }
}

template <RuleInvalidationDataVisitorType VisitorType>
InvalidationSet&
RuleInvalidationDataVisitor<VisitorType>::EnsureMutableInvalidationSet(
    InvalidationType type,
    PositionType position,
    bool in_nth_child,
    scoped_refptr<InvalidationSet>& invalidation_set) {
  if (!invalidation_set) {
    // Create a new invalidation set of the right type.
    if (type == InvalidationType::kInvalidateDescendants) {
      if (position == kSubject && !in_nth_child) {
        invalidation_set = InvalidationSet::SelfInvalidationSet();
      } else {
        invalidation_set = DescendantInvalidationSet::Create();
      }
    } else {
      invalidation_set = SiblingInvalidationSet::Create(nullptr);
    }
    return *invalidation_set;
  }

  if (invalidation_set->IsSelfInvalidationSet() &&
      type == InvalidationType::kInvalidateDescendants &&
      position == kSubject && !in_nth_child) {
    // NOTE: This is fairly dodgy; we're returning the singleton
    // self-invalidation set (which is very much immutable) from a
    // function promising to return something mutable. We pretty much
    // rely on the caller to do the right thing and not mutate the
    // self-invalidation set if asking for it (ie., giving this
    // combination of type/position).
    return *invalidation_set;
  }

  // If the currently stored invalidation_set is shared with other
  // RuleInvalidationData instances, or it is the SelfInvalidationSet()
  // singleton, we must copy it before modifying it.
  //
  // If we are retrieving the invalidation set for a simple selector in a non-
  // rightmost compound, it means we plan to add features to the set. If so,
  // create a DescendantInvalidationSet we are allowed to modify.
  //
  // Note that we also construct a DescendantInvalidationSet instead of using
  // the SelfInvalidationSet() when we create a SiblingInvalidationSet. We may
  // be able to let SiblingInvalidationSets reference the singleton set for
  // descendants as well. TODO(futhark@chromium.org)
  if (invalidation_set->IsSelfInvalidationSet() ||
      !invalidation_set->HasOneRef()) {
    invalidation_set = CopyInvalidationSet(*invalidation_set);
    DCHECK(invalidation_set->HasOneRef());
  }

  if (invalidation_set->GetType() == type) {
    return *invalidation_set;
  }

  if (type == InvalidationType::kInvalidateDescendants) {
    // sibling → sibling+descendant.
    DescendantInvalidationSet& embedded_invalidation_set =
        To<SiblingInvalidationSet>(*invalidation_set).EnsureDescendants();
    return embedded_invalidation_set;
  } else {
    // descendant → sibling+descendant.
    scoped_refptr<InvalidationSet> descendants = invalidation_set;
    invalidation_set = SiblingInvalidationSet::Create(
        To<DescendantInvalidationSet>(descendants.get()));
    return *invalidation_set;
  }
}

template class RuleInvalidationDataVisitor<
    RuleInvalidationDataVisitorType::kBuilder>;
template class RuleInvalidationDataVisitor<
    RuleInvalidationDataVisitorType::kTracer>;

}  // namespace blink
```