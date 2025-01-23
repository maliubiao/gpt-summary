Response:
The user wants a summary of the functionality of the provided C++ code snippet from `focus_controller.cc`. This is the second part of a three-part request.

Here's a breakdown of the code's main responsibilities:

1. **Focus Navigation Logic:** This part of the code defines how focus moves between elements on a web page, considering factors like `tabindex`, shadow DOM, and iframe boundaries.
2. **`ScopedFocusNavigation` Class:** This class appears to manage the navigation within a specific scope (e.g., within a document, shadow tree, or iframe). It has methods to find the next or previous focusable element based on different criteria.
3. **Handling `tabindex`:**  The code explicitly deals with the `tabindex` attribute to determine the order of focusable elements. It considers both positive, zero, and negative `tabindex` values.
4. **Shadow DOM Integration:** The code incorporates logic to traverse into and out of shadow DOM trees while navigating focus.
5. **Iframe Navigation:**  It handles the movement of focus between different iframes embedded in a page.
6. **Reading Flow Context:** There's mention of "reading flow" and related logic, which seems to influence the focus order.
7. **Recursive Search:**  The code utilizes recursive functions (`FindFocusableElementRecursivelyForward`, `FindFocusableElementRecursivelyBackward`) to search for focusable elements within nested structures.
根据提供的代码片段，`blink/renderer/core/page/focus_controller.cc` 文件的这部分主要负责实现**在特定范围内进行焦点导航**的功能。它定义了 `ScopedFocusNavigation` 类以及相关的辅助函数，用于在文档、Shadow DOM 和 iframe 之间查找下一个或上一个可获得焦点的元素。

以下是更详细的功能归纳：

**主要功能:**

1. **定义焦点导航范围 (`ScopedFocusNavigation`):**  `ScopedFocusNavigation` 类用于管理在特定容器内的焦点导航，例如一个文档、一个 Shadow Host 的内部、一个 iframe 等。它维护了当前元素，并提供了移动到下一个或上一个元素的方法。
2. **基于 `tabindex` 查找元素:**  提供了根据精确的 `tabindex` 值 (`FindElementWithExactTabIndex`) 或大于/小于指定 `tabindex` 的值 (`NextElementWithGreaterTabIndex`, `PreviousElementWithLowerTabIndex`) 来查找元素的功能。
3. **确定是否应该访问元素 (`ShouldVisit`):**  定义了哪些元素应该被包含在焦点导航中，这取决于元素是否可获得键盘焦点、是否是委托焦点的 Shadow Host 或者是非焦点的焦点范围所有者。
4. **调整 `tabindex` 值 (`ReadingFlowAdjustedTabIndex`):**  根据是否存在阅读流容器，调整元素的 `tabindex` 值。如果存在阅读流容器，并且元素的 `tabindex` 大于 0，则会被调整为 0。
5. **查找下一个/上一个可获得焦点的元素 (`NextFocusableElement`, `PreviousFocusableElement`):**  实现了在当前焦点导航范围内，根据 `tabindex` 和文档树顺序，查找下一个或上一个可以获得焦点的元素。会考虑负 `tabindex` 的情况。
6. **递归查找可获得焦点的元素 (`FindFocusableElementRecursivelyForward`, `FindFocusableElementRecursivelyBackward`, `FindFocusableElementRecursively`):**  这些函数用于递归地在包含 Shadow DOM 或其他嵌套焦点范围的结构中查找可获得焦点的元素。
7. **跨焦点范围查找可获得焦点的元素 (`FindFocusableElementAcrossFocusScopesForward`, `FindFocusableElementAcrossFocusScopesBackward`, `FindFocusableElementAcrossFocusScopes`):** 实现了在不同的焦点范围（例如，跨越 Shadow DOM 边界或 iframe）之间查找下一个或上一个可获得焦点的元素。
8. **处理 iframe 边界 (`FindFocusableElementDescendingDownIntoFrameDocument`):**  当焦点导航遇到 iframe 时，会进入 iframe 的文档中查找可获得焦点的元素。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**
    * **`tabindex` 属性:** 代码直接读取和使用 HTML 元素的 `tabindex` 属性来决定焦点顺序。例如，`element.GetIntegralAttribute(html_names::kTabindexAttr, 0)` 用于获取 `tabindex` 的值。
    * **Shadow DOM:** 代码中大量逻辑处理 Shadow Host 和 Shadow Root，例如 `IsShadowHostWithoutCustomFocusLogic` 和 `element.IsShadowHostWithDelegatesFocus()`，这直接关系到 HTML 的 Shadow DOM 特性。
    * **`<slot>` 元素:** `IsA<HTMLSlotElement>(element)` 表明代码考虑了 `<slot>` 元素在焦点导航中的作用。
    * **`<iframe>` 元素:** `FindFocusableElementDescendingDownIntoFrameDocument` 函数专门处理了进入 iframe 文档查找焦点的情况。
* **JavaScript:**
    * 当 JavaScript 代码调用 `element.focus()` 方法时，Blink 引擎的这部分代码可能会被触发，以确定下一个或上一个可以获得焦点的元素。
    * JavaScript 可以通过 `document.activeElement` 获取当前获得焦点的元素，而 `FocusController` 负责维护和更新这个状态。
* **CSS:**
    * CSS 的 `visibility: hidden` 或 `display: none` 可能会影响元素是否可获得焦点，但这部分代码主要关注的是 `tabindex` 和 DOM 结构，可能依赖其他代码来判断 CSS 的可见性。

**逻辑推理的假设输入与输出:**

**假设输入 1:**

* 当前焦点在文档的某个 `<input>` 元素 A 上。
* 用户按下 Tab 键（前进焦点）。

**输出 1:**

* `NextFocusableElement()` 会被调用。
* 代码会根据元素 A 的 `tabindex` 和文档顺序，找到下一个应该获得焦点的元素 B。
* 如果元素 B 存在并且可获得焦点，则焦点会移动到元素 B。

**假设输入 2:**

* 当前焦点在一个 Shadow Host 的内部元素 C 上。
* 用户按下 Shift + Tab 键（后退焦点）。

**输出 2:**

* `PreviousFocusableElement()` 会被调用。
* 代码会先在 Shadow Host 内部查找前一个可获得焦点的元素。
* 如果没有，则会移动到 Shadow Host 本身（如果可获得焦点），或者移动到 Shadow Host 之前的元素。

**用户或编程常见的使用错误举例说明:**

* **错误地使用负 `tabindex`:** 开发者可能错误地给一个应该可以获得焦点的元素设置了负的 `tabindex`，导致用户无法通过 Tab 键访问到该元素。`DCHECK(!element.IsKeyboardFocusable() || FocusController::AdjustedTabIndex(element) >= 0)` 这行代码就用于检查这种情况。
* **忘记处理 Shadow DOM 的焦点:**  开发者可能在创建自定义组件时，忘记处理 Shadow DOM 的焦点委托，导致用户无法通过 Tab 键正确地在组件内部和外部导航。代码中对 `IsShadowHostWithDelegatesFocus()` 的检查就与此相关。
* **在 iframe 中焦点管理不当:**  开发者可能没有考虑到 iframe 带来的焦点管理问题，导致用户在不同 iframe 之间切换焦点时出现混乱。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户与网页交互:** 用户打开一个包含多个可交互元素的网页。
2. **按下 Tab 键或 Shift + Tab 键:** 用户尝试通过键盘在不同的元素之间移动焦点。
3. **浏览器捕获键盘事件:** 浏览器接收到 Tab 键或 Shift + Tab 键的事件。
4. **焦点管理逻辑触发:**  浏览器的焦点管理模块（包括 `FocusController`）被触发，开始寻找下一个或上一个可以获得焦点的元素。
5. **调用 `ScopedFocusNavigation` 的方法:**  `FocusController` 可能会创建 `ScopedFocusNavigation` 对象，并调用其 `NextFocusableElement()` 或 `PreviousFocusableElement()` 等方法。
6. **`ShouldVisit()` 和 `ReadingFlowAdjustedTabIndex()` 等函数被调用:**  这些辅助函数会被用来判断哪些元素应该被访问，以及它们的有效 `tabindex` 值。
7. **递归或跨范围搜索:** 如果涉及到 Shadow DOM 或 iframe，相关的递归或跨范围搜索函数会被调用。
8. **找到目标元素或没有找到:** 经过一系列判断和搜索，代码会找到下一个或上一个可以获得焦点的元素，或者确定在当前范围内没有更多可获得焦点的元素。
9. **焦点更新:** 最终，浏览器的焦点会移动到找到的元素上，或者保持不变。

通过调试器，开发者可以设置断点在 `ScopedFocusNavigation` 的方法或相关的辅助函数中，观察变量的值，例如当前的元素、`tabindex` 值、Shadow Host 的状态等，从而理解焦点导航的流程和定位问题。

### 提示词
```
这是目录为blink/renderer/core/page/focus_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
It is a scroller with focusable children
  // When tabindex is negative, we should not visit the host.
  return !(element.GetIntegralAttribute(html_names::kTabindexAttr, 0) < 0);
}

inline bool IsNonKeyboardFocusableReadingFlowOwner(const Element& element) {
  return IsReadingFlowScopeOwner(&element) && !element.IsKeyboardFocusable();
}

inline bool IsKeyboardFocusableReadingFlowOwner(const Element& element) {
  return IsReadingFlowScopeOwner(&element) && element.IsKeyboardFocusable();
}

inline bool IsKeyboardFocusableShadowHost(const Element& element) {
  return IsShadowHostWithoutCustomFocusLogic(element) &&
         (element.IsKeyboardFocusable() ||
          element.IsShadowHostWithDelegatesFocus());
}

inline bool IsNonFocusableFocusScopeOwner(Element& element) {
  return IsNonKeyboardFocusableShadowHost(element) ||
         IsA<HTMLSlotElement>(element) ||
         IsNonKeyboardFocusableReadingFlowOwner(element);
}

inline bool ShouldVisit(Element& element) {
  DCHECK(!element.IsKeyboardFocusable() ||
         FocusController::AdjustedTabIndex(element) >= 0)
      << "Keyboard focusable element with negative tabindex" << element;
  return element.IsKeyboardFocusable() ||
         element.IsShadowHostWithDelegatesFocus() ||
         IsNonFocusableFocusScopeOwner(element);
}

Element* ScopedFocusNavigation::FindElementWithExactTabIndex(
    int tab_index,
    mojom::blink::FocusType type) {
  // Search is inclusive of start
  for (; CurrentElement(); type == mojom::blink::FocusType::kForward
                               ? MoveToNext()
                               : MoveToPrevious()) {
    Element* current = CurrentElement();
    if (ShouldVisit(*current) &&
        ReadingFlowAdjustedTabIndex(*current) == tab_index) {
      return current;
    }
  }
  return nullptr;
}

Element* ScopedFocusNavigation::NextElementWithGreaterTabIndex(int tab_index) {
  // Search is inclusive of start
  int winning_tab_index = std::numeric_limits<int>::max();
  Element* winner = nullptr;
  for (; CurrentElement(); MoveToNext()) {
    Element* current = CurrentElement();
    int current_tab_index = ReadingFlowAdjustedTabIndex(*current);
    if (ShouldVisit(*current) && current_tab_index > tab_index) {
      if (!winner || current_tab_index < winning_tab_index) {
        winner = current;
        winning_tab_index = current_tab_index;
      }
    }
  }
  SetCurrentElement(winner);
  return winner;
}

Element* ScopedFocusNavigation::PreviousElementWithLowerTabIndex(
    int tab_index) {
  // Search is inclusive of start
  int winning_tab_index = 0;
  Element* winner = nullptr;
  for (; CurrentElement(); MoveToPrevious()) {
    Element* current = CurrentElement();
    int current_tab_index = ReadingFlowAdjustedTabIndex(*current);
    if (ShouldVisit(*current) && current_tab_index < tab_index &&
        current_tab_index > winning_tab_index) {
      winner = current;
      winning_tab_index = current_tab_index;
    }
  }
  SetCurrentElement(winner);
  return winner;
}

// This function adjust the tabindex by the FocusController and by the rules of
// the reading-flow container focus navigation scope. If a reading-flow item
// has a tabindex higher than 0, it should be re-adjusted to 0.
// TODO(dizhangg) Add link to spec when it is available.
int ScopedFocusNavigation::ReadingFlowAdjustedTabIndex(const Element& element) {
  int tab_index = FocusController::AdjustedTabIndex(element);
  if (navigation_->HasReadingFlowContainer()) {
    return std::min(0, tab_index);
  }
  return tab_index;
}

Element* ScopedFocusNavigation::NextFocusableElement() {
  Element* current = CurrentElement();
  if (current) {
    int tab_index = ReadingFlowAdjustedTabIndex(*current);
    // If an element is excluded from the normal tabbing cycle, the next
    // focusable element is determined by tree order.
    if (tab_index < 0) {
      for (MoveToNext(); CurrentElement(); MoveToNext()) {
        current = CurrentElement();
        if (ShouldVisit(*current) &&
            ReadingFlowAdjustedTabIndex(*current) >= 0) {
          return current;
        }
      }
    } else {
      // First try to find an element with the same tabindex as start that comes
      // after start in the scope.
      MoveToNext();
      if (Element* winner = FindElementWithExactTabIndex(
              tab_index, mojom::blink::FocusType::kForward))
        return winner;
    }
    if (!tab_index) {
      // We've reached the last element in the document with a tabindex of 0.
      // This is the end of the tabbing order.
      return nullptr;
    }
  }

  // Look for the first element in the scope that:
  // 1) has the lowest tabindex that is higher than start's tabindex (or 0, if
  //    start is null), and
  // 2) comes first in the scope, if there's a tie.
  MoveToFirst();
  if (Element* winner = NextElementWithGreaterTabIndex(
          current ? ReadingFlowAdjustedTabIndex(*current) : 0)) {
    return winner;
  }

  // There are no elements with a tabindex greater than start's tabindex,
  // so find the first element with a tabindex of 0.
  MoveToFirst();
  return FindElementWithExactTabIndex(0, mojom::blink::FocusType::kForward);
}

Element* ScopedFocusNavigation::PreviousFocusableElement() {
  // First try to find the last element in the scope that comes before start and
  // has the same tabindex as start.  If start is null, find the last element in
  // the scope with a tabindex of 0.
  int tab_index;
  Element* current = CurrentElement();
  if (current) {
    MoveToPrevious();
    tab_index = ReadingFlowAdjustedTabIndex(*current);
  } else {
    MoveToLast();
    tab_index = 0;
  }

  // However, if an element is excluded from the normal tabbing cycle, the
  // previous focusable element is determined by tree order
  if (tab_index < 0) {
    for (; CurrentElement(); MoveToPrevious()) {
      current = CurrentElement();
      if (ShouldVisit(*current) && ReadingFlowAdjustedTabIndex(*current) >= 0) {
        return current;
      }
    }
  } else {
    if (Element* winner = FindElementWithExactTabIndex(
            tab_index, mojom::blink::FocusType::kBackward))
      return winner;
  }

  // There are no elements before start with the same tabindex as start, so look
  // for an element that:
  // 1) has the highest non-zero tabindex (that is less than start's tabindex),
  //    and
  // 2) comes last in the scope, if there's a tie.
  tab_index =
      (current && tab_index) ? tab_index : std::numeric_limits<int>::max();
  MoveToLast();
  return PreviousElementWithLowerTabIndex(tab_index);
}

Element* FindFocusableElementRecursivelyForward(
    ScopedFocusNavigation& scope,
    FocusController::OwnerMap& owner_map) {
  // Starting element is exclusive.
  while (Element* found =
             scope.FindFocusableElement(mojom::blink::FocusType::kForward)) {
    if (found->IsShadowHostWithDelegatesFocus()) {
      // If tabindex is positive, invalid, or missing, find focusable element
      // inside its shadow tree.
      if (FocusController::AdjustedTabIndex(*found) >= 0 &&
          IsShadowHostWithoutCustomFocusLogic(*found)) {
        ScopedFocusNavigation inner_scope =
            ScopedFocusNavigation::OwnedByShadowHost(*found, owner_map);
        if (Element* found_in_inner_focus_scope =
                FindFocusableElementRecursivelyForward(inner_scope,
                                                       owner_map)) {
          return found_in_inner_focus_scope;
        }
      }
      // Skip to the next element in the same scope.
      continue;
    }
    if (!IsNonFocusableFocusScopeOwner(*found))
      return found;

    // Now |found| is on a non focusable scope owner (either shadow host or
    // slot) Find inside the inward scope and return it if found. Otherwise
    // continue searching in the same scope.
    ScopedFocusNavigation inner_scope =
        ScopedFocusNavigation::OwnedByNonFocusableFocusScopeOwner(*found,
                                                                  owner_map);
    if (Element* found_in_inner_focus_scope =
            FindFocusableElementRecursivelyForward(inner_scope, owner_map))
      return found_in_inner_focus_scope;
  }
  return nullptr;
}

Element* FindFocusableElementRecursivelyBackward(
    ScopedFocusNavigation& scope,
    FocusController::OwnerMap& owner_map) {
  // Starting element is exclusive.
  while (Element* found =
             scope.FindFocusableElement(mojom::blink::FocusType::kBackward)) {
    // Now |found| is on a focusable shadow host.
    // Find inside shadow backwards. If any focusable element is found, return
    // it, otherwise return the host itself.
    if (IsKeyboardFocusableShadowHost(*found)) {
      ScopedFocusNavigation inner_scope =
          ScopedFocusNavigation::OwnedByShadowHost(*found, owner_map);
      Element* found_in_inner_focus_scope =
          FindFocusableElementRecursivelyBackward(inner_scope, owner_map);
      if (found_in_inner_focus_scope)
        return found_in_inner_focus_scope;
      if (found->IsShadowHostWithDelegatesFocus()) {
        continue;
      }
      return found;
    }

    // Now |found| is on a focusable reading flow owner. Find inside
    // container backwards. If any focusable element is found, return it,
    // otherwise return the container itself.
    if (IsKeyboardFocusableReadingFlowOwner(*found)) {
      ScopedFocusNavigation inner_scope =
          ScopedFocusNavigation::OwnedByReadingFlow(*found, owner_map);
      Element* found_in_inner_focus_scope =
          FindFocusableElementRecursivelyBackward(inner_scope, owner_map);
      if (found_in_inner_focus_scope) {
        return found_in_inner_focus_scope;
      }
      return found;
    }

    // If delegatesFocus is true and tabindex is negative, skip the whole shadow
    // tree under the shadow host.
    if (found->IsShadowHostWithDelegatesFocus() &&
        FocusController::AdjustedTabIndex(*found) < 0) {
      continue;
    }

    // Now |found| is on a non focusable scope owner (a shadow host or a slot).
    // Find focusable element in descendant scope. If not found, find the next
    // focusable element within the current scope.
    if (IsNonFocusableFocusScopeOwner(*found)) {
      ScopedFocusNavigation inner_scope =
          ScopedFocusNavigation::OwnedByNonFocusableFocusScopeOwner(*found,
                                                                    owner_map);
      if (Element* found_in_inner_focus_scope =
              FindFocusableElementRecursivelyBackward(inner_scope, owner_map))
        return found_in_inner_focus_scope;
      continue;
    }
    if (!found->IsShadowHostWithDelegatesFocus()) {
      return found;
    }
  }
  return nullptr;
}

Element* FindFocusableElementRecursively(mojom::blink::FocusType type,
                                         ScopedFocusNavigation& scope,
                                         FocusController::OwnerMap& owner_map) {
  return (type == mojom::blink::FocusType::kForward)
             ? FindFocusableElementRecursivelyForward(scope, owner_map)
             : FindFocusableElementRecursivelyBackward(scope, owner_map);
}

Element* FindFocusableElementDescendingDownIntoFrameDocument(
    mojom::blink::FocusType type,
    Element* element,
    FocusController::OwnerMap& owner_map) {
  // The element we found might be a HTMLFrameOwnerElement, so descend down the
  // tree until we find either:
  // 1) a focusable element, or
  // 2) the deepest-nested HTMLFrameOwnerElement.
  while (IsA<HTMLFrameOwnerElement>(element)) {
    HTMLFrameOwnerElement& owner = To<HTMLFrameOwnerElement>(*element);
    auto* container_local_frame = DynamicTo<LocalFrame>(owner.ContentFrame());
    if (!container_local_frame)
      break;
    container_local_frame->GetDocument()->UpdateStyleAndLayout(
        DocumentUpdateReason::kFocus);
    ScopedFocusNavigation scope =
        ScopedFocusNavigation::OwnedByIFrame(owner, owner_map);
    Element* found_element =
        FindFocusableElementRecursively(type, scope, owner_map);
    if (!found_element)
      break;
    DCHECK_NE(element, found_element);
    element = found_element;
  }
  return element;
}

Element* FindFocusableElementAcrossFocusScopesForward(
    ScopedFocusNavigation& scope,
    FocusController::OwnerMap& owner_map) {
  const Element* current = scope.CurrentElement();
  Element* found = nullptr;
  if (current && IsShadowHostWithoutCustomFocusLogic(*current)) {
    ScopedFocusNavigation inner_scope =
        ScopedFocusNavigation::OwnedByShadowHost(*current, owner_map);
    found = FindFocusableElementRecursivelyForward(inner_scope, owner_map);
  } else if (IsOpenPopoverInvoker(current)) {
    ScopedFocusNavigation inner_scope =
        ScopedFocusNavigation::OwnedByPopoverInvoker(*current, owner_map);
    found = FindFocusableElementRecursivelyForward(inner_scope, owner_map);
  } else if (current && IsReadingFlowScopeOwner(current)) {
    ScopedFocusNavigation inner_scope =
        ScopedFocusNavigation::OwnedByReadingFlow(*current, owner_map);
    found = FindFocusableElementRecursivelyForward(inner_scope, owner_map);
  }
  if (!found)
    found = FindFocusableElementRecursivelyForward(scope, owner_map);

  // If there's no focusable element to advance to, move up the focus scopes
  // until we find one.
  ScopedFocusNavigation current_scope = scope;
  while (!found) {
    Element* owner = current_scope.Owner();
    if (!owner)
      break;
    current_scope = ScopedFocusNavigation::CreateFor(*owner, owner_map);
    found = FindFocusableElementRecursivelyForward(current_scope, owner_map);
  }
  return FindFocusableElementDescendingDownIntoFrameDocument(
      mojom::blink::FocusType::kForward, found, owner_map);
}

Element* FindFocusableElementAcrossFocusScopesBackward(
    ScopedFocusNavigation& scope,
    FocusController::OwnerMap& owner_map) {
  Element* found = FindFocusableElementRecursivelyBackward(scope, owner_map);

  while (IsOpenPopoverInvoker(found)) {
    ScopedFocusNavigation inner_scope =
        ScopedFocusNavigation::OwnedByPopoverInvoker(*found, owner_map);
    // If no inner element is focusable, then focus should be on the current
    // found popover invoker.
    if (Element* inner_found =
            FindFocusableElementRecursivelyBackward(inner_scope, owner_map)) {
      found = inner_found;
    } else {
      break;
    }
  }

  // If there's no focusable element to advance to, move up the focus scopes
  // until we find one.
  ScopedFocusNavigation current_scope = scope;
  while (!found) {
    Element* owner = current_scope.Owner();
    if (!owner)
      break;
    if ((IsKeyboardFocusableShadowHost(*owner) &&
         !owner->IsShadowHostWithDelegatesFocus()) ||
        IsOpenPopoverInvoker(owner) ||
        IsKeyboardFocusableReadingFlowOwner(*owner)) {
      found = owner;
      break;
    }
    current_scope = ScopedFocusNavigation::CreateFor(*owner, owner_map);
    found = FindFocusableElementRecursivelyBackward(current_scope, owner_map);
  }
  return FindFocusableElementDescendingDownIntoFrameDocument(
      mojom::blink::FocusType::kBackward, found, owner_map);
}

Element* FindFocusableElementAcrossFocusScopes(
    mojom::blink::FocusType type,
    ScopedFocusNavigation& scope,
    FocusController::OwnerMap& owner_map) {
  return (type == mojom::blink::FocusType::kForward)
             ? FindFocusableElementAcrossFocusScopesForward(scope, owner_map)
             : FindFocusableElementAcrossFocusScopesBackward(scope, owner_map);
}

}  // anonymous namespace

FocusController::FocusController(Page* page)
    : page_(page),
      is_active_(false),
      is_focused_(false),
      is_changing_focused_frame_(false),
      is_emulating_focus_(false) {}

void FocusController::SetFocusedFrame(Frame* frame, bool notify_embedder) {
  DCHECK(!frame || frame->GetPage() == page_);
  if (focused_frame_ == frame || (is_changing_focused_frame_ && frame))
    return;

  is_changing_focused_frame_ = true;

  // Fenced frames will try to pass focus to a dummy frame that represents the
  // inner frame tree. We instead want to give focus to the outer
  // HTMLFencedFrameElement. This will allow methods like document.activeElement
  // and document.hasFocus() to properly handle when a fenced frame has focus.
  if (frame && IsA<HTMLFrameOwnerElement>(frame->Owner())) {
    auto* fenced_frame = DynamicTo<HTMLFencedFrameElement>(
        To<HTMLFrameOwnerElement>(frame->Owner()));
    if (fenced_frame) {
      // SetFocusedElement will call back to FocusController::SetFocusedFrame.
      // However, `is_changing_focused_frame_` will be true when it is called,
      // causing the function to early return, so we still need the rest of this
      // invocation of the function to run.
      SetFocusedElement(fenced_frame, frame);
    }
  }

  auto* old_frame = DynamicTo<LocalFrame>(focused_frame_.Get());
  auto* new_frame = DynamicTo<LocalFrame>(frame);

  focused_frame_ = frame;

  // Now that the frame is updated, fire events and update the selection focused
  // states of both frames.
  if (old_frame && old_frame->View()) {
    old_frame->Selection().SetFrameIsFocused(false);
    old_frame->DomWindow()->DispatchEvent(
        *Event::Create(event_type_names::kBlur));
  }

  if (new_frame && new_frame->View() && IsFocused()) {
    new_frame->Selection().SetFrameIsFocused(true);
    new_frame->DomWindow()->DispatchEvent(
        *Event::Create(event_type_names::kFocus));
  }

  is_changing_focused_frame_ = false;

  // Checking IsAttached() is necessary, as the frame might have been detached
  // as part of dispatching the focus event above. See https://crbug.com/570874.
  if (notify_embedder && focused_frame_ && focused_frame_->IsAttached())
    focused_frame_->DidFocus();

  NotifyFocusChangedObservers();
}

void FocusController::FocusDocumentView(Frame* frame, bool notify_embedder) {
  DCHECK(!frame || frame->GetPage() == page_);
  if (focused_frame_ == frame)
    return;

  auto* focused_frame = DynamicTo<LocalFrame>(focused_frame_.Get());
  if (focused_frame && focused_frame->View()) {
    Document* document = focused_frame->GetDocument();
    Element* focused_element = document ? document->FocusedElement() : nullptr;
    if (focused_element)
      document->ClearFocusedElement();
  }

  auto* new_focused_frame = DynamicTo<LocalFrame>(frame);
  if (new_focused_frame && new_focused_frame->View()) {
    Document* document = new_focused_frame->GetDocument();
    Element* focused_element = document ? document->FocusedElement() : nullptr;
    if (focused_element)
      DispatchFocusEvent(*document, *focused_element);
  }

  // dispatchBlurEvent/dispatchFocusEvent could have changed the focused frame,
  // or detached the frame.
  if (new_focused_frame && !new_focused_frame->View())
    return;

  SetFocusedFrame(frame, notify_embedder);
}

LocalFrame* FocusController::FocusedFrame() const {
  // All callsites only care about *local* focused frames.
  return DynamicTo<LocalFrame>(focused_frame_.Get());
}

Frame* FocusController::FocusedOrMainFrame() const {
  if (LocalFrame* frame = FocusedFrame())
    return frame;

  // TODO(dcheng, alexmos): https://crbug.com/820786: This is a temporary hack
  // to ensure that we return a LocalFrame, even when the mainFrame is remote.
  // FocusController needs to be refactored to deal with RemoteFrames
  // cross-process focus transfers.
  for (Frame* frame = &page_->MainFrame()->Tree().Top(); frame;
       frame = frame->Tree().TraverseNext()) {
    auto* local_frame = DynamicTo<LocalFrame>(frame);
    if (local_frame)
      return frame;
  }

  return page_->MainFrame();
}

void FocusController::FrameDetached(Frame* detached_frame) {
  if (detached_frame == focused_frame_)
    SetFocusedFrame(nullptr);
}

HTMLFrameOwnerElement* FocusController::FocusedFrameOwnerElement(
    LocalFrame& current_frame) const {
  Frame* focused_frame = focused_frame_.Get();
  for (; focused_frame; focused_frame = focused_frame->Tree().Parent()) {
    if (focused_frame->Tree().Parent() == &current_frame) {
      DCHECK(focused_frame->Owner()->IsLocal());
      return focused_frame->DeprecatedLocalOwner();
    }
  }
  return nullptr;
}

bool FocusController::IsDocumentFocused(const Document& document) const {
  if (!IsActive()) {
    return false;
  }

  if (!focused_frame_) {
    return false;
  }

  if (IsA<HTMLFrameOwnerElement>(focused_frame_->Owner())) {
    auto* fenced_frame = DynamicTo<HTMLFencedFrameElement>(
        To<HTMLFrameOwnerElement>(focused_frame_->Owner()));
    if (fenced_frame && fenced_frame == document.ActiveElement()) {
      return fenced_frame->GetDocument().GetFrame()->Tree().IsDescendantOf(
          document.GetFrame());
    }
  }

  if (!IsFocused()) {
    return false;
  }

  return focused_frame_->Tree().IsDescendantOf(document.GetFrame());
}

void FocusController::FocusHasChanged() {
  bool focused = IsFocused();
  if (!focused) {
    if (auto* focused_or_main_local_frame =
            DynamicTo<LocalFrame>(FocusedOrMainFrame()))
      focused_or_main_local_frame->GetEventHandler().StopAutoscroll();
  }

  // Do not set a focused frame when being unfocused. This might reset
  // is_focused_ to true.
  if (!focused_frame_ && focused)
    SetFocusedFrame(page_->MainFrame());

  // SetFocusedFrame above might reject to update focused_frame_, or
  // focused_frame_ might be changed by blur/focus event handlers.
  auto* focused_local_frame = DynamicTo<LocalFrame>(focused_frame_.Get());
  if (focused_local_frame && focused_local_frame->View()) {
    focused_local_frame->Selection().SetFrameIsFocused(focused);
    DispatchEventsOnWindowAndFocusedElement(focused_local_frame->GetDocument(),
                                            focused);
  }

  NotifyFocusChangedObservers();
}

void FocusController::SetFocused(bool focused) {
  // If we are setting focus, we should be active.
  DCHECK(!focused || is_active_);
  if (is_focused_ == focused)
    return;
  is_focused_ = focused;
  if (!is_emulating_focus_)
    FocusHasChanged();

  // If the page has completely lost focus ensure we clear the focused
  // frame.
  if (!is_focused_ && page_->IsMainFrameFencedFrameRoot()) {
    SetFocusedFrame(nullptr);
  }
}

void FocusController::SetFocusEmulationEnabled(bool emulate_focus) {
  if (emulate_focus == is_emulating_focus_)
    return;
  bool active = IsActive();
  bool focused = IsFocused();
  is_emulating_focus_ = emulate_focus;
  if (active != IsActive())
    ActiveHasChanged();
  if (focused != IsFocused())
    FocusHasChanged();
}

bool FocusController::SetInitialFocus(mojom::blink::FocusType type) {
  bool did_advance_focus = AdvanceFocus(type, true);

  // If focus is being set initially, accessibility needs to be informed that
  // system focus has moved into the web area again, even if focus did not
  // change within WebCore.  PostNotification is called instead of
  // handleFocusedUIElementChanged, because this will send the notification even
  // if the element is the same.
  if (auto* focused_or_main_local_frame =
          DynamicTo<LocalFrame>(FocusedOrMainFrame())) {
    Document* document = focused_or_main_local_frame->GetDocument();
    if (AXObjectCache* cache = document->ExistingAXObjectCache())
      cache->HandleInitialFocus();
  }

  return did_advance_focus;
}

bool FocusController::AdvanceFocus(
    mojom::blink::FocusType type,
    bool initial_focus,
    InputDeviceCapabilities* source_capabilities) {
  // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
  TRACE_EVENT0("input", "FocusController::AdvanceFocus");
  switch (type) {
    case mojom::blink::FocusType::kForward:
    case mojom::blink::FocusType::kBackward: {
      // We should never hit this when a RemoteFrame is focused, since the key
      // event that initiated focus advancement should've been routed to that
      // frame's process from the beginning.
      auto* starting_frame = To<LocalFrame>(FocusedOrMainFrame());
      return AdvanceFocusInDocumentOrder(starting_frame, nullptr, type,
                                         initial_focus, source_capabilities);
    }
    case mojom::blink::FocusType::kSpatialNavigation:
      // Fallthrough - SpatialNavigation should use
      // SpatialNavigationController.
    default:
      NOTREACHED();
  }
}

bool FocusController::AdvanceFocusAcrossFrames(
    mojom::blink::FocusType type,
    RemoteFrame* from,
    LocalFrame* to,
    InputDeviceCapabilities* source_capabilities) {
  Element* start = nullptr;

  // If we are shifting focus from a child frame to its parent, the
  // child frame has no more focusable elements, and we should continue
  // looking for focusable elements in the parent, starting from the element
  // of the child frame. This applies both to fencedframes and iframes.
  Element* start_candidate = DynamicTo<HTMLFrameOwnerElement>(from->Owner());
  if (start_candidate && start_candidate->GetDocument().GetFrame() == to) {
    start = start_candidate;
  }

  // If we're coming from a parent frame, we need to restart from the first or
  // last focusable element.
  bool initial_focus = to->Tree().Parent() == from;

  return AdvanceFocusInDocumentOrder(to, start, type, initial_focus,
                                     source_capabilities);
}

#if DCHECK_IS_ON()
inline bool IsNonFocusableShadowHost(const Element& element) {
  return IsShadowHostWithoutCustomFocusLogic(element) && !element.IsFocusable();
}
#endif

bool FocusController::AdvanceFocusInDocumentOrder(
    LocalFrame* frame,
    Element* start,
    mojom::blink::FocusType type,
    bool initial_focus,
    InputDeviceCapabilities* source_capabilities) {
  // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
  TRACE_EVENT0("input", "FocusController::AdvanceFocusInDocumentOrder");
  DCHECK(frame);
  Document* document = frame->GetDocument();
  OwnerMap owner_map;

  Element* current = start;
#if DCHECK_IS_ON()
  DCHECK(!current || !IsNonFocusableShadowHost(*current));
#endif
  if (!current && !initial_focus)
    current = document->SequentialFocusNavigationStartingPoint(type);

  document->UpdateStyleAndLayout(DocumentUpdateReason::kFocus);
  ScopedFocusNavigation scope =
      (current && current->IsInTreeScope())
          ? ScopedFocusNavigation::CreateFor(*current, owner_map)
          : ScopedFocusNavigation::CreateForDocument(*document, owner_map);
  Element* element =
      FindFocusableElementAcrossFocusScopes(type, scope, owner_map);
  if (!element) {
    // If there's a RemoteFrame on the ancestor chain, we need to continue
    // searching for focusable elements there.
    if (frame->LocalFrameRoot() != frame->Tree().Top()) {
      document->ClearFocusedElement();
      document->SetSequentialFocusNavigationStartingPoint(nullptr);
      SetFocusedFrame(nullptr);
      To<RemoteFrame>(frame->LocalFrameRoot().Tree().Parent())
          ->AdvanceFocus(type, &frame->LocalFrameRoot());
      return true;
    }

    // We didn't find an element to focus, so we should try to pass focus to
    // Chrome.
    if ((!initial_focus || document->GetFrame()->IsFencedFrameRoot()) &&
        page_->GetChromeClient().CanTakeFocus(type)) {
      document->ClearFocusedElement();
      document->SetSequentialFocusNavigationStartingPoint(nullptr);
      SetFocusedFrame(nullptr);
      page_->GetChromeClient().TakeFocus(type);
      return true;
    }

    // Chrome doesn't want focus, so we should wrap focus.
    ScopedFocusNavigation doc_scope = ScopedFocusNavigation::CreateForDocument(
        *To<LocalFrame>(page_->MainFrame())->GetDocument(), owner_map);
    element = FindFocusableElementRecursively(type, doc_scope, owner_map);
    element = FindFocusableElementDescendingDownIntoFrameDocument(type, element,
                                                                  owner_map);

    if (!element) {
      // TODO (liviutinta) remove TRACE after fixing crbug.com/1063548
      TRACE_EVENT_INSTANT1(
          "input", "FocusController::AdvanceFocusInDocumentOrder",
          TRACE_EVENT_SCOPE_THREAD, "reason_for_no_focus_element",
          "no_recursive_focusable_element");
      return false;
    }
  }

  if (element == document->FocusedElement()) {
    // Focus is either coming from a remote frame or has wrapped around.
    if (FocusedFrame() != document->GetFrame()) {
      SetFocusedFrame(document->GetFrame());
      DispatchFocusEvent(*document, *element);
    }
    return true;
  }

  // Focus frames rather than frame owners.  Note that we should always attempt
  // to descend into frame owners with remote frames, since we don't know ahead
  // of time whether they contain focusable elements.  If a remote frame
  // doesn't contain any focusable elements, the search will eventually return
  // back to this frame and continue looking for focusable elements after the
  // frame owner.
  auto* owner = DynamicTo<HTMLFrameOwnerElement>(element);
  bool has_remote_frame =
      owner && owner->ContentFrame() && owner->ContentFrame()->IsRemoteFrame();
  if (owner && (has_remote_frame || !IsA<HTMLPlugInElement>(*element) ||
                !element->IsKeyboardFocusable())) {
    // FIXME: We should not focus frames that have no scrollbars, as focusing
    // them isn't useful to the user.
    if (!owner->ContentFrame()) {
      return false;
    }

    document->ClearFocusedElement();

    // If ContentFrame is remote, continue the search for focusable elements in
    // that frame's process. The target ContentFrame's process will grab focus
    // from inside AdvanceFocusInDocumentOrder().
    //
    // ClearFocusedElement() fires events that might detach the contentFrame,
    // hence the need to null-check it again.
    if (auto* remote_frame = DynamicTo<RemoteFrame>(owner->ContentFrame()))
      remote_frame->AdvanceFocus(type, frame);
    else
      SetFocusedFrame(owner->ContentFrame());

    return true;
  }

  DCHECK(element->IsFocusable());

  // FIXME: It would be nice to just be able to call setFocusedElement(element)
  // here, but we can't do that because some elements (e.g. HTMLInputElement
  // and HTMLTextAreaElement) do extra work in their focus() methods.
  Document& new_document = element->GetDocument();

  if (&new_document != document) {
    // Focus is going away from this document, so clear the focused element.
    document->ClearFocusedElement();
    document->SetSequentialFocusNavigationStartingPoint(nullptr);
  }

  SetFocusedFrame(new_document.GetFrame());

  element->Focus(FocusParams(SelectionBehaviorOnFocus::kReset, type,
                             source_capabilities, FocusOptions::Create(),
                             FocusTrigger::kUserGesture));
  return true;
}

Element* FocusController::FindFocusableElement(mojom::blink::FocusType type,
                                               Element& element,
                                               OwnerMap& owner_map) {
  // FIXME: No spacial navigation code yet.
  DCHECK(type == mojom::blink::FocusType::kForward ||
         type == mojom::blink::FocusType::kBackward);
  ScopedFocusNavigation scope =
      ScopedFocusNavigation::CreateFor(element, owner_map);
  return FindFocusableElementAcrossFocusScopes(type, scope, owner_map);
}

Element* FocusController::NextFocusableElementForImeAndAutofill(
    Element* element,
    mojom::blink::FocusType focus_type) {
  // TODO(ajith.v) Due to crbug.com/781026 when next/previous element is far
  // from current element in terms of tabindex, then it's signalling CPU load.
  // Will investigate further for a proper solution later.
  static const int kFocusTraversalThreshold = 50;
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kFocus);
  auto* html_element = DynamicTo<HTMLElement>(element);
  if (!html_element)
    return nullptr;

  auto* form_control_element = DynamicTo<HTMLFormControlElement>(element);
  if (!form_control_element && !html_element->isContentEditableForBinding())
    return nullptr;

  HTMLFormElement* form_owner = nullptr;
  if (html_element->isContentEditableForBinding())
    form_owner = Traversal<HTMLFormElement>::FirstAncestor(*element);
  else
    form_owner = form_control_element->formOwner();

  OwnerMap owner_map;
  Element* next_element = FindFocusableElement(focus_type, *element, owner_map);
  int traversal = 0;
  for (; next_element && traversal < kFocusTraversalThreshold;
       next_element =
           FindFocusableElement(focus_type, *next_element, owner_map),
       ++traversal) {
    auto* next_html_element = DynamicTo<HTMLElement>(next_element);
    if (!next_html_element)
      continue;
    if (next_html_element->isContentEditableForBinding()) {
      if (form_owner) {
        if (next_element->IsDescendantOf(form_owner)) {
          // |eleme
```