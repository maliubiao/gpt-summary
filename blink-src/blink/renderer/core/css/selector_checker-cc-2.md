Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C++ code snippet from `selector_checker.cc`. They're specifically interested in its relationship with web technologies (JavaScript, HTML, CSS), examples, logical reasoning, potential errors, debugging hints, and a concise summary.

2. **Identify the Code's Purpose:**  The code is a series of `case` statements within a `switch` block. The `switch` is based on `selector.GetPseudoType()`, strongly indicating this code is responsible for checking if an element matches a specific CSS pseudo-class or pseudo-element. The `SelectorChecker` class name itself is a strong hint.

3. **Analyze Each `case`:** I'll go through each `case` block, focusing on what it's doing. Key things to look for:
    * **The `case` value:** This tells us the specific pseudo-class/element being checked (e.g., `:first-of-type`, `::placeholder`, `:hover`).
    * **The logic within the `case`:** What conditions must be true for the element to match the pseudo-class/element? This often involves:
        * Checking element properties or attributes (e.g., `element.IsLink()`, `text_control->IsPlaceholderVisible()`, `dialog->FastHasAttribute(html_names::kOpenAttr)`).
        * Calling other functions (e.g., `IsFirstOfType()`, `MatchesAnyInList()`, `MatchesFocusPseudoClass()`).
        * Setting flags or properties on the element or its parent (e.g., `parent->SetChildrenAffectedByForwardPositionalRules()`).
        * Checking runtime conditions (e.g., `RuntimeEnabledFeatures::CSSPseudoHasSlottedEnabled()`).
        * Interacting with other browser subsystems (e.g., `probe::ForcePseudoState()`, `Fullscreen::IsFullscreenFlagSetFor()`).

4. **Relate to Web Technologies:** As I analyze each `case`, I'll think about how it connects to HTML, CSS, and potentially JavaScript:
    * **HTML:**  Many checks directly involve HTML elements and their attributes (e.g., `<input>`, `<dialog>`, `open` attribute).
    * **CSS:** The entire code is about CSS selectors. I need to explain how each pseudo-class/element affects styling.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, it's triggered by the browser's rendering engine when processing CSS, which can be influenced by JavaScript interactions (e.g., dynamically adding/removing classes, changing element states).

5. **Generate Examples:** For each relevant pseudo-class/element, I'll create simple HTML and CSS examples to illustrate its effect. This makes the explanation more concrete.

6. **Consider Logical Reasoning (Input/Output):**  For some pseudo-classes, the logic is straightforward. For others (like `:nth-child`), there's a clear input (the element and its siblings) and output (whether it matches). I'll provide hypothetical scenarios.

7. **Identify Potential User/Programming Errors:** I'll think about common mistakes developers make when using these pseudo-classes/elements in their CSS. For example, misunderstanding the difference between `:nth-child` and `:nth-of-type`.

8. **Describe User Actions (Debugging):**  I'll trace how a user interaction in the browser could lead to this code being executed. For example, a user hovering over an element triggers the `:hover` check.

9. **Synthesize a Summary:** Finally, I'll condense the detailed analysis into a concise summary of the code's overall function.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe I should group the pseudo-classes by their functionality.
* **Correction:** It's better to explain them in the order they appear in the code, as this reflects the code's structure. I can still group related concepts in my explanations.
* **Initial thought:** Focus heavily on the C++ details.
* **Correction:**  The user is likely more interested in the *web technology* implications. Keep the C++ explanations clear but prioritize the connection to HTML, CSS, and JavaScript.
* **Initial thought:** Provide very technical explanations of every single line of code.
* **Correction:**  Focus on the *purpose* of each `case` and the high-level logic. Avoid getting bogged down in implementation details unless they are crucial for understanding the functionality.
* **Initial thought:** Only provide trivial examples.
* **Correction:**  Try to include examples that demonstrate the nuances of certain pseudo-classes, such as the `of` clause in `:nth-child`.

By following these steps and being willing to refine my approach, I can generate a comprehensive and helpful answer that addresses all aspects of the user's request.
这是对 `blink/renderer/core/css/selector_checker.cc` 文件中关于 CSS 伪类选择器匹配逻辑的代码片段的分析。

**功能归纳 (基于提供的代码片段):**

这段代码主要负责检查一个给定的元素是否匹配特定的 CSS 伪类选择器。它遍历各种 CSS 伪类，并根据伪类的类型执行相应的匹配逻辑。  核心功能是 **确定元素是否符合特定伪类的条件**。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这段 C++ 代码是 Blink 渲染引擎的一部分，负责 CSS 样式计算的核心逻辑。它直接影响浏览器如何理解和应用 CSS 样式规则。

* **CSS:**  这段代码处理各种 CSS 伪类选择器，例如 `:first-of-type`, `:last-of-type`, `:nth-child`, `:hover`, `:active`, `:disabled` 等等。它实现了 CSS 规范中定义的这些伪类的匹配行为。

    * **例子:**  当 CSS 规则中使用了 `:hover` 伪类时，例如 `button:hover { background-color: yellow; }`，当用户鼠标悬停在按钮上时，这段 C++ 代码会被调用来检查该按钮元素是否匹配 `:hover` 状态。如果匹配，浏览器会将背景色设置为黄色。

* **HTML:**  代码中大量的判断基于 HTML 元素的属性和状态。例如，`:checked` 伪类会检查 `<input>` 元素的 `checked` 属性，`:disabled` 伪类会检查表单元素的 `disabled` 属性。

    * **例子:**  对于 HTML 代码 `<input type="checkbox" checked>`, 当 CSS 规则中使用了 `input:checked { border: 2px solid blue; }` 时，这段代码会判断该 `input` 元素的 `checked` 属性为 true，从而匹配 `:checked` 伪类，并应用蓝色边框样式。

* **JavaScript:**  虽然这段代码本身是用 C++ 编写的，但 JavaScript 可以间接地影响这些伪类的匹配。例如，JavaScript 可以动态地修改 HTML 元素的属性（例如使用 `element.setAttribute('checked', true)`），或者添加/移除元素，从而影响伪类选择器的匹配结果。

    * **例子:**  一个 JavaScript 脚本可能会监听用户的点击事件，并在满足特定条件时，使用 `element.disabled = true;` 将一个按钮禁用。随后，CSS 规则 `button:disabled { opacity: 0.5; }` 会生效，因为这段 C++ 代码会检查到该按钮的 `disabled` 状态为真。

**逻辑推理 (假设输入与输出):**

假设输入为一个 `<div>` 元素和 CSS 选择器 `div:first-of-type`:

* **输入:**
    * `element`: 一个 `HTMLDivElement` 对象。
    * `selector`:  表示 `:first-of-type` 伪类的 `CSSSelector` 对象。

* **执行逻辑:** 代码会进入 `case CSSSelector::kPseudoFirstOfType:` 分支。它会检查该 `div` 元素是否是其父元素下同类型（即 `div` 标签）的第一个子元素。

* **输出:**
    * 如果该 `div` 元素是其父元素下第一个 `div` 子元素，则返回 `true` (匹配)。
    * 否则，返回 `false` (不匹配)。

假设输入为一个 `<input type="text">` 元素和 CSS 选择器 `input:placeholder-shown`:

* **输入:**
    * `element`: 一个 `HTMLInputElement` 对象。
    * `selector`: 表示 `::placeholder-shown` 伪类的 `CSSSelector` 对象。

* **执行逻辑:** 代码会进入 `case CSSSelector::kPseudoPlaceholderShown:` 分支。它会检查该 `input` 元素是否显示 placeholder 文本。这通常意味着该输入框当前没有用户输入。

* **输出:**
    * 如果该 `input` 元素显示 placeholder 文本，则返回 `true` (匹配)。
    * 否则，返回 `false` (不匹配)。

**用户或编程常见的使用错误及举例说明:**

* **混淆 `:nth-child` 和 `:nth-of-type`:**  这是常见的 CSS 选择器错误。
    * **错误:** 用户可能期望 `p:nth-child(2)` 选中所有父元素下的第二个 `<p>` 元素。
    * **实际:** `:nth-child(2)` 选中所有父元素下的第二个 *子元素*，并且该子元素必须是 `<p>` 标签。如果第二个子元素不是 `<p>`，则不会匹配。
    * **调试线索:**  当样式没有如预期应用时，检查元素在 DOM 树中的位置和类型。使用浏览器的开发者工具查看元素的父元素和兄弟元素。

* **对动态变化的伪类状态理解不足:**  像 `:hover`, `:focus`, `:active` 这样的伪类状态是动态的，依赖于用户的交互。
    * **错误:**  开发者可能期望通过 JavaScript 修改 CSS 来永久地模拟 `:hover` 状态，但实际上 `:hover` 状态只在鼠标悬停时生效。
    * **调试线索:** 使用浏览器的开发者工具查看元素的当前状态（例如，是否处于 `:hover` 状态）。尝试手动触发状态变化（例如，移动鼠标）。

* **忽略伪类的优先级:**  伪类会影响 CSS 规则的特殊性。
    * **错误:**  开发者可能定义了一个更通用的规则，但期望带有特定伪类的规则生效，却发现通用规则覆盖了它。
    * **调试线索:** 使用浏览器的开发者工具查看应用的 CSS 规则，检查它们的特殊性。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **加载网页:** 用户在浏览器中打开一个包含 CSS 样式和 HTML 元素的网页。
2. **渲染过程:** 浏览器开始解析 HTML 和 CSS，构建 DOM 树和 CSSOM 树。
3. **样式计算:**  渲染引擎需要确定每个元素应该应用哪些 CSS 规则。这涉及到 CSS 选择器的匹配。
4. **伪类匹配:** 当遇到包含伪类选择器的 CSS 规则时，`selector_checker.cc` 中的这段代码会被调用。
5. **用户交互 (例如):**
    * **鼠标悬停:** 用户将鼠标指针移动到一个元素上。这会触发 `:hover` 伪类的检查。
    * **点击元素:** 用户点击一个元素。这会触发 `:active` 伪类的检查。
    * **表单交互:** 用户与表单元素交互（例如，选中复选框，输入文本）。这会触发 `:checked`, `:enabled`, `:disabled`, `:placeholder-shown` 等伪类的检查。
6. **匹配结果:** 代码返回匹配结果 (true/false)。
7. **样式应用:** 基于匹配结果，浏览器决定是否将相应的 CSS 属性应用到元素上。

**总结 (基于提供的代码片段):**

这段 `selector_checker.cc` 中的代码片段是 Chromium Blink 引擎中负责 **评估 CSS 伪类选择器是否与特定 HTML 元素匹配** 的关键部分。它通过检查元素的各种属性和状态，以及与浏览器的其他子系统交互，来实现 CSS 规范中定义的伪类选择器的行为。 这段代码直接影响了网页的最终渲染效果，并与 HTML、CSS 和 JavaScript 都有着紧密的联系。

Prompt: 
```
这是目录为blink/renderer/core/css/selector_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
ent->SetChildrenAffectedByBackwardPositionalRules();
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      return IsFirstOfType(element, element.TagQName()) &&
             IsLastOfType(element, element.TagQName());
    }
    case CSSSelector::kPseudoPlaceholderShown: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoPlaceholderShown,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      if (auto* text_control = ToTextControlOrNull(element)) {
        return text_control->IsPlaceholderVisible();
      }
      break;
    }
    case CSSSelector::kPseudoNthChild:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent = element.ParentElementOrDocumentFragment()) {
          parent->SetChildrenAffectedByForwardPositionalRules();
        }
      }
      if (selector.SelectorList()) {
        // Check if the element itself matches the “of” selector.
        // Note that this will also propagate the correct MatchResult flags,
        // so NthIndexCache does not have to do that.
        if (!MatchesAnyInList(context, selector.SelectorList()->First(),
                              result)) {
          return false;
        }
      }
      return selector.MatchNth(NthIndexCache::NthChildIndex(
          element, selector.SelectorList(), this, &context));
    case CSSSelector::kPseudoNthOfType:
      if (mode_ == kResolvingStyle) {
        if (ContainerNode* parent = element.ParentElementOrDocumentFragment()) {
          parent->SetChildrenAffectedByForwardPositionalRules();
        }
      }
      return selector.MatchNth(NthIndexCache::NthOfTypeIndex(element));
    case CSSSelector::kPseudoNthLastChild: {
      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle && parent) {
        parent->SetChildrenAffectedByBackwardPositionalRules();
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      if (selector.SelectorList()) {
        // Check if the element itself matches the “of” selector.
        if (!MatchesAnyInList(context, selector.SelectorList()->First(),
                              result)) {
          return false;
        }
      }
      return selector.MatchNth(NthIndexCache::NthLastChildIndex(
          element, selector.SelectorList(), this, &context));
    }
    case CSSSelector::kPseudoNthLastOfType: {
      ContainerNode* parent = element.ParentElementOrDocumentFragment();
      if (mode_ == kResolvingStyle && parent) {
        parent->SetChildrenAffectedByBackwardPositionalRules();
      }
      if (mode_ != kQueryingRules && parent &&
          !parent->IsFinishedParsingChildren()) {
        return false;
      }
      return selector.MatchNth(NthIndexCache::NthLastOfTypeIndex(element));
    }
    case CSSSelector::kPseudoSelectorFragmentAnchor:
      return MatchesSelectorFragmentAnchorPseudoClass(element);
    case CSSSelector::kPseudoTarget:
      probe::ForcePseudoState(&element, CSSSelector::kPseudoTarget,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      return element == element.GetDocument().CssTarget() ||
             MatchesExternalSVGUseTarget(element);
    case CSSSelector::kPseudoIs:
    case CSSSelector::kPseudoWhere:
    case CSSSelector::kPseudoAny:
      return MatchesAnyInList(context, selector.SelectorListOrParent(), result);
    case CSSSelector::kPseudoParent: {
      const CSSSelector* parent = selector.SelectorListOrParent();
      if (parent == nullptr) {
        // & at top level matches like :scope.
        return CheckPseudoScope(context, result);
      } else {
        return MatchesAnyInList(context, parent, result);
      }
    }
    case CSSSelector::kPseudoAutofill:
    case CSSSelector::kPseudoWebKitAutofill:
    case CSSSelector::kPseudoAutofillPreviewed:
    case CSSSelector::kPseudoAutofillSelected:
      return CheckPseudoAutofill(selector.GetPseudoType(), element);
    case CSSSelector::kPseudoAnyLink:
    case CSSSelector::kPseudoWebkitAnyLink:
      return element.IsLink();
    case CSSSelector::kPseudoLink:
      return element.IsLink() && !context.match_visited;
    case CSSSelector::kPseudoVisited:
      return element.IsLink() && context.match_visited;
    case CSSSelector::kPseudoDrag:
      if (mode_ == kResolvingStyle) {
        if (ImpactsNonSubject(context)) {
          element.SetChildrenOrSiblingsAffectedByDrag();
        }
      }
      if (ImpactsSubject(context)) {
        result.SetFlag(MatchFlag::kAffectedByDrag);
      }
      return element.IsDragged();
    case CSSSelector::kPseudoFocus:
      if (mode_ == kResolvingStyle) {
        if (context.is_inside_has_pseudo_class) [[unlikely]] {
          element.SetAncestorsOrSiblingsAffectedByFocusInHas();
        } else {
          if (ImpactsNonSubject(context)) {
            element.SetChildrenOrSiblingsAffectedByFocus();
          }
        }
      }
      return MatchesFocusPseudoClass(element,
                                     context.previously_matched_pseudo_element);
    case CSSSelector::kPseudoFocusVisible:
      if (mode_ == kResolvingStyle) {
        if (context.is_inside_has_pseudo_class) [[unlikely]] {
          element.SetAncestorsOrSiblingsAffectedByFocusVisibleInHas();
        } else {
          if (ImpactsNonSubject(context)) {
            element.SetChildrenOrSiblingsAffectedByFocusVisible();
          }
        }
      }
      return MatchesFocusVisiblePseudoClass(element);
    case CSSSelector::kPseudoFocusWithin:
      if (mode_ == kResolvingStyle) {
        if (context.is_inside_has_pseudo_class) [[unlikely]] {
          element.SetAncestorsOrSiblingsAffectedByFocusInHas();
        } else if (ImpactsNonSubject(context)) {
          element.SetChildrenOrSiblingsAffectedByFocusWithin();
        }
      }
      if (ImpactsSubject(context)) {
        result.SetFlag(MatchFlag::kAffectedByFocusWithin);
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoFocusWithin,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      return element.HasFocusWithin();
    case CSSSelector::kPseudoHasSlotted:
      DCHECK(RuntimeEnabledFeatures::CSSPseudoHasSlottedEnabled());
      if (auto* slot = DynamicTo<HTMLSlotElement>(element)) {
        return slot->HasAssignedNodesNoRecalc();
      }
      return false;
    case CSSSelector::kPseudoHover:
      if (mode_ == kResolvingStyle) {
        if (context.is_inside_has_pseudo_class) [[unlikely]] {
          element.SetAncestorsOrSiblingsAffectedByHoverInHas();
        } else if (ImpactsNonSubject(context)) {
          element.SetChildrenOrSiblingsAffectedByHover();
        }
      }
      if (ImpactsSubject(context)) {
        result.SetFlag(MatchFlag::kAffectedByHover);
      }
      if (!ShouldMatchHoverOrActive(context)) {
        return false;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoHover,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      return element.IsHovered();
    case CSSSelector::kPseudoActive:
      if (mode_ == kResolvingStyle) {
        if (context.is_inside_has_pseudo_class) [[unlikely]] {
          element.SetAncestorsOrSiblingsAffectedByActiveInHas();
        } else if (ImpactsNonSubject(context)) {
          element.SetChildrenOrSiblingsAffectedByActive();
        }
      }
      if (ImpactsSubject(context)) {
        result.SetFlag(MatchFlag::kAffectedByActive);
      }
      if (!ShouldMatchHoverOrActive(context)) {
        return false;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoActive,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      return element.IsActive();
    case CSSSelector::kPseudoEnabled: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoEnabled,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoDisabled,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.MatchesEnabledPseudoClass();
    }
    case CSSSelector::kPseudoFullPageMedia:
      return element.GetDocument().IsMediaDocument();
    case CSSSelector::kPseudoDefault:
      return element.MatchesDefaultPseudoClass();
    case CSSSelector::kPseudoDisabled:
      probe::ForcePseudoState(&element, CSSSelector::kPseudoDisabled,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoEnabled,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      if (auto* fieldset = DynamicTo<HTMLFieldSetElement>(element)) {
        // <fieldset> should never be considered disabled, but should still
        // match the :enabled or :disabled pseudo-classes according to whether
        // the attribute is set or not. See here for context:
        // https://github.com/whatwg/html/issues/5886#issuecomment-1582410112
        return fieldset->IsActuallyDisabled();
      }
      return element.IsDisabledFormControl();
    case CSSSelector::kPseudoReadOnly: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoReadOnly,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoReadWrite,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.MatchesReadOnlyPseudoClass();
    }
    case CSSSelector::kPseudoReadWrite: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoReadWrite,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoReadOnly,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.MatchesReadWritePseudoClass();
    }
    case CSSSelector::kPseudoOptional: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoOptional,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoRequired,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.IsOptionalFormControl();
    }
    case CSSSelector::kPseudoRequired: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoRequired,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoOptional,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.IsRequiredFormControl();
    }
    case CSSSelector::kPseudoUserInvalid: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoUserInvalid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoUserValid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      if (auto* form_control =
              DynamicTo<HTMLFormControlElementWithState>(element)) {
        return form_control->MatchesUserInvalidPseudo();
      }
      return false;
    }
    case CSSSelector::kPseudoUserValid: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoUserValid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoUserInvalid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      if (auto* form_control =
              DynamicTo<HTMLFormControlElementWithState>(element)) {
        return form_control->MatchesUserValidPseudo();
      }
      return false;
    }
    case CSSSelector::kPseudoValid:
      probe::ForcePseudoState(&element, CSSSelector::kPseudoValid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoInvalid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.MatchesValidityPseudoClasses() && element.IsValidElement();
    case CSSSelector::kPseudoInvalid: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoInvalid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoValid,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.MatchesValidityPseudoClasses() &&
             !element.IsValidElement();
    }
    case CSSSelector::kPseudoChecked: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoChecked,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      if (auto* input_element = DynamicTo<HTMLInputElement>(element)) {
        // Even though WinIE allows checked and indeterminate to
        // co-exist, the CSS selector spec says that you can't be
        // both checked and indeterminate. We will behave like WinIE
        // behind the scenes and just obey the CSS spec here in the
        // test for matching the pseudo.
        if (input_element->ShouldAppearChecked() &&
            !input_element->ShouldAppearIndeterminate()) {
          return true;
        }
      } else if (auto* option_element = DynamicTo<HTMLOptionElement>(element)) {
        if (option_element->Selected()) {
          return true;
        }
      } else if (element.IsScrollMarkerPseudoElement()) {
        return To<ScrollMarkerPseudoElement>(element).IsSelected();
      }
      break;
    }
    case CSSSelector::kPseudoIndeterminate: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoIndeterminate,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      return element.ShouldAppearIndeterminate();
    }
    case CSSSelector::kPseudoRoot:
      return element == element.GetDocument().documentElement();
    case CSSSelector::kPseudoLang: {
      auto* vtt_element = DynamicTo<VTTElement>(element);
      AtomicString value = vtt_element ? vtt_element->Language()
                                       : element.ComputeInheritedLanguage();
      const AtomicString& argument = selector.Argument();
      if (value.empty() ||
          !value.StartsWith(argument, kTextCaseASCIIInsensitive)) {
        break;
      }
      if (value.length() != argument.length() &&
          value[argument.length()] != '-') {
        break;
      }
      return true;
    }
    case CSSSelector::kPseudoDir: {
      const AtomicString& argument = selector.Argument();
      if (argument.empty()) {
        break;
      }

      TextDirection direction;
      if (EqualIgnoringASCIICase(argument, "ltr")) {
        direction = TextDirection::kLtr;
      } else if (EqualIgnoringASCIICase(argument, "rtl")) {
        direction = TextDirection::kRtl;
      } else {
        break;
      }

      // Recomputing the slot assignment can update cached directionality.  In
      // most cases it's OK for this code to be run when slot assignments are
      // dirty; however for API calls like Element.matches() we should recalc
      // them now.
      Document& document = element.GetDocument();
      if (mode_ == kQueryingRules && document.IsSlotAssignmentDirty()) {
        document.GetSlotAssignmentEngine().RecalcSlotAssignments();
      }

      return element.CachedDirectionality() == direction;
    }
    case CSSSelector::kPseudoDialogInTopLayer:
      if (auto* dialog = DynamicTo<HTMLDialogElement>(element)) {
        if (dialog->IsModal() &&
            dialog->FastHasAttribute(html_names::kOpenAttr)) {
          DCHECK(dialog->GetDocument().TopLayerElements().Contains(dialog));
          return true;
        }
        // When the dialog is transitioning to closed, we have to check the
        // elements which are in the top layer but are pending removal to see if
        // this element used to be open as a dialog.
        std::optional<Document::TopLayerReason> top_layer_reason =
            dialog->GetDocument().IsScheduledForTopLayerRemoval(dialog);
        return top_layer_reason &&
               *top_layer_reason == Document::TopLayerReason::kDialog;
      }
      return false;
    case CSSSelector::kPseudoPopoverInTopLayer:
      if (auto* html_element = DynamicTo<HTMLElement>(element);
          html_element && html_element->HasPopoverAttribute()) {
        // When the popover is open and is not transitioning to closed,
        // popoverOpen will return true.
        if (html_element->popoverOpen()) {
          DCHECK(html_element->GetDocument().TopLayerElements().Contains(
              html_element));
          return true;
        }
        // When the popover is transitioning to closed, popoverOpen won't return
        // true and we have to check the elements which are in the top layer but
        // are pending removal to see if this element used to be popoverOpen.
        std::optional<Document::TopLayerReason> top_layer_reason =
            html_element->GetDocument().IsScheduledForTopLayerRemoval(
                html_element);
        return top_layer_reason &&
               *top_layer_reason == Document::TopLayerReason::kPopover;
      }
      return false;
    case CSSSelector::kPseudoPopoverOpen:
      if (auto* html_element = DynamicTo<HTMLElement>(element);
          html_element && html_element->HasPopoverAttribute()) {
        return html_element->popoverOpen();
      }
      return false;
    case CSSSelector::kPseudoOpen:
      if (auto* dialog = DynamicTo<HTMLDialogElement>(element)) {
        return dialog->FastHasAttribute(html_names::kOpenAttr);
      } else if (auto* details = DynamicTo<HTMLDetailsElement>(element)) {
        return details->FastHasAttribute(html_names::kOpenAttr);
      } else if (auto* select = DynamicTo<HTMLSelectElement>(element)) {
        return select->PopupIsVisible();
      }
      return false;
    case CSSSelector::kPseudoClosed:
      if (auto* dialog = DynamicTo<HTMLDialogElement>(element)) {
        return !dialog->FastHasAttribute(html_names::kOpenAttr);
      } else if (auto* details = DynamicTo<HTMLDetailsElement>(element)) {
        return !details->FastHasAttribute(html_names::kOpenAttr);
      } else if (auto* select = DynamicTo<HTMLSelectElement>(element)) {
        return select->UsesMenuList() && !select->PopupIsVisible();
      }
      return false;
    case CSSSelector::kPseudoFullscreen:
    // fall through
    case CSSSelector::kPseudoFullScreen:
      return Fullscreen::IsFullscreenFlagSetFor(element);
    case CSSSelector::kPseudoFullScreenAncestor:
      return element.ContainsFullScreenElement();
    case CSSSelector::kPseudoPaused: {
      DCHECK(RuntimeEnabledFeatures::CSSPseudoPlayingPausedEnabled());
      auto* media_element = DynamicTo<HTMLMediaElement>(element);
      return media_element && media_element->paused();
    }
    case CSSSelector::kPseudoPermissionGranted: {
      CHECK(RuntimeEnabledFeatures::PermissionElementEnabled(
          element.GetExecutionContext()));
      auto* permission_element = DynamicTo<HTMLPermissionElement>(element);
      return permission_element && permission_element->granted();
    }
    case CSSSelector::kPseudoPermissionElementInvalidStyle: {
      CHECK(RuntimeEnabledFeatures::PermissionElementEnabled(
          element.GetExecutionContext()));
      auto* permission_element = DynamicTo<HTMLPermissionElement>(element);
      return permission_element && permission_element->HasInvalidStyle();
    }
    case CSSSelector::kPseudoPermissionElementOccluded: {
      CHECK(RuntimeEnabledFeatures::PermissionElementEnabled(
          element.GetExecutionContext()));
      auto* permission_element = DynamicTo<HTMLPermissionElement>(element);
      return permission_element && permission_element->IsOccluded();
    }
    case CSSSelector::kPseudoPictureInPicture:
      return PictureInPictureController::IsElementInPictureInPicture(&element);
    case CSSSelector::kPseudoPlaying: {
      DCHECK(RuntimeEnabledFeatures::CSSPseudoPlayingPausedEnabled());
      auto* media_element = DynamicTo<HTMLMediaElement>(element);
      return media_element && !media_element->paused();
    }
    case CSSSelector::kPseudoVideoPersistent: {
      DCHECK(is_ua_rule_);
      auto* video_element = DynamicTo<HTMLVideoElement>(element);
      return video_element && video_element->IsPersistent();
    }
    case CSSSelector::kPseudoVideoPersistentAncestor:
      DCHECK(is_ua_rule_);
      return element.ContainsPersistentVideo();
    case CSSSelector::kPseudoXrOverlay:
      // In immersive AR overlay mode, apply a pseudostyle to the DOM Overlay
      // element. This is the same as the fullscreen element in the current
      // implementation, but could be different for AR headsets.
      return element.GetDocument().IsXrOverlay() &&
             Fullscreen::IsFullscreenElement(element);
    case CSSSelector::kPseudoInRange: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoInRange,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoOutOfRange,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.IsInRange();
    }
    case CSSSelector::kPseudoOutOfRange: {
      probe::ForcePseudoState(&element, CSSSelector::kPseudoOutOfRange,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return true;
      }
      probe::ForcePseudoState(&element, CSSSelector::kPseudoInRange,
                              &force_pseudo_state);
      if (force_pseudo_state) {
        return false;
      }
      return element.IsOutOfRange();
    }
    case CSSSelector::kPseudoFutureCue: {
      auto* vtt_element = DynamicTo<VTTElement>(element);
      return vtt_element && !vtt_element->IsPastNode();
    }
    case CSSSelector::kPseudoPastCue: {
      auto* vtt_element = DynamicTo<VTTElement>(element);
      return vtt_element && vtt_element->IsPastNode();
    }
    case CSSSelector::kPseudoScope:
      return CheckPseudoScope(context, result);
    case CSSSelector::kPseudoDefined:
      return element.IsDefined();
    case CSSSelector::kPseudoHostContext:
      UseCounter::Count(
          context.element->GetDocument(),
          mode_ == kQueryingRules
              ? WebFeature::kCSSSelectorHostContextInSnapshotProfile
              : WebFeature::kCSSSelectorHostContextInLiveProfile);
      [[fallthrough]];
    case CSSSelector::kPseudoHost:
      return CheckPseudoHost(context, result);
    case CSSSelector::kPseudoSpatialNavigationFocus:
      DCHECK(is_ua_rule_);
      return MatchesSpatialNavigationFocusPseudoClass(element);
    case CSSSelector::kPseudoHasDatalist:
      DCHECK(is_ua_rule_);
      return MatchesHasDatalistPseudoClass(element);
    case CSSSelector::kPseudoIsHtml:
      DCHECK(is_ua_rule_);
      return IsA<HTMLDocument>(element.GetDocument());
    case CSSSelector::kPseudoListBox:
      DCHECK(is_ua_rule_);
      return MatchesListBoxPseudoClass(element);
    case CSSSelector::kPseudoMultiSelectFocus:
      DCHECK(is_ua_rule_);
      return MatchesMultiSelectFocusPseudoClass(element);
    case CSSSelector::kPseudoHostHasNonAutoAppearance:
      DCHECK(is_ua_rule_);
      if (ShadowRoot* root = element.ContainingShadowRoot()) {
        if (!root->IsUserAgent()) {
          return false;
        }
        const ComputedStyle* style = root->host().GetComputedStyle();
        return style && style->HasEffectiveAppearance();
      }
      return false;
    case CSSSelector::kPseudoWindowInactive:
      if (context.previously_matched_pseudo_element != kPseudoIdSelection) {
        return false;
      }
      return !element.GetDocument().GetPage()->GetFocusController().IsActive();
    case CSSSelector::kPseudoStateDeprecatedSyntax: {
      CHECK(RuntimeEnabledFeatures::CSSCustomStateDeprecatedSyntaxEnabled());
      return element.DidAttachInternals() &&
             element.EnsureElementInternals().HasState(selector.Value());
    }
    case CSSSelector::kPseudoState: {
      CHECK(RuntimeEnabledFeatures::CSSCustomStateNewSyntaxEnabled());
      return element.DidAttachInternals() &&
             element.EnsureElementInternals().HasState(selector.Argument());
    }
    case CSSSelector::kPseudoHorizontal:
    case CSSSelector::kPseudoVertical:
    case CSSSelector::kPseudoDecrement:
    case CSSSelector::kPseudoIncrement:
    case CSSSelector::kPseudoStart:
    case CSSSelector::kPseudoEnd:
    case CSSSelector::kPseudoDoubleButton:
    case CSSSelector::kPseudoSingleButton:
    case CSSSelector::kPseudoNoButton:
    case CSSSelector::kPseudoCornerPresent:
      return false;
    case CSSSelector::kPseudoModal:
      if (Fullscreen::IsFullscreenElement(element)) {
        return true;
      }
      if (const auto* dialog_element = DynamicTo<HTMLDialogElement>(element)) {
        return dialog_element->IsModal();
      }
      return false;
    case CSSSelector::kPseudoHas:
      if (mode_ == kResolvingStyle) {
        // Set 'AffectedBySubjectHas' or 'AffectedByNonSubjectHas' flag to
        // indicate that the element is affected by a subject or non-subject
        // :has() state change. It means that, when we have a mutation on
        // an element, and the element is in the :has() argument checking scope
        // of a :has() anchor element, we may need to invalidate the subject
        // element of the style rule containing the :has() pseudo class because
        // the mutation can affect the state of the :has().
        if (ImpactsSubject(context)) {
          element.SetAffectedBySubjectHas();
        }
        if (ImpactsNonSubject(context)) {
          element.SetAffectedByNonSubjectHas();
        }

        if (selector.ContainsPseudoInsideHasPseudoClass()) {
          element.SetAffectedByPseudoInHas();
        }

        if (selector.ContainsComplexLogicalCombinationsInsideHasPseudoClass()) {
          element.SetAffectedByLogicalCombinationsInHas();
        }
      }
      return CheckPseudoHas(context, result);
    case CSSSelector::kPseudoRelativeAnchor:
      DCHECK(context.relative_anchor_element);
      return context.relative_anchor_element == &element;
    case CSSSelector::kPseudoActiveViewTransition: {
      // :active-view-transition is only valid on the document element.
      if (!element.IsDocumentElement()) {
        return false;
      }

      // The pseudo is only valid if there is a transition.
      auto* transition =
          ViewTransitionUtils::GetTransition(element.GetDocument());
      if (!transition) {
        return false;
      }

      // Ask the transition to match for active-view-transition.
      return transition->MatchForActiveViewTransition();
    }
    case CSSSelector::kPseudoActiveViewTransitionType: {
      // :active-view-transition-type is only valid on the document element.
      if (!element.IsDocumentElement()) {
        return false;
      }

      // The pseudo is only valid if there is a transition.
      auto* transition =
          ViewTransitionUtils::GetTransition(element.GetDocument());
      if (!transition) {
        return false;
      }

      // Ask the transition to match based on the argument list.
      return transition->MatchForActiveViewTransitionType(selector.IdentList());
    }
    case CSSSelector::kPseudoUnparsed:
      // Only kept around for parsing; can never match anything
      // (because we don't know what it's supposed to mean).
      return false;
    case CSSSelector::kPseudoCurrent:
      if (context.previously_matched_pseudo_element != kPseudoIdSearchText) {
        return false;
      }
      return context.search_text_request_is_current;
    case CSSSelector::kPseudoUnknown:
    default:
      NOTREACHED();
  }
  return false;
}

static bool MatchesUAShadowElement(Element& element, const AtomicString& id) {
  Element* originating_element =
      element.IsPseudoElement()
          ? To<PseudoElement>(element).UltimateOriginatingElement()
          : &element;
  ShadowRoot* root = originating_element->ContainingShadowRoot();
  return root && root->IsUserAgent() &&
         originating_element->ShadowPseudoId() == id;
}

bool SelectorChecker::CheckPseudoAutofill(CSSSelector::PseudoType pseudo_type,
                                          Element& element) const {
  bool force_pseudo_state = false;
  probe::ForcePseudoState(&element, CSSSelector::kPseudoAutofill,
                          &force_pseudo_state);
  if (force_pseudo_state) {
    return true;
  }
  HTMLFormControlElement* form_control_element =
      DynamicTo<HTMLFormControlElement>(&element);
  if (!form_control_element) {
    return false;
  }
  switch (pseudo_type) {
    case CSSSelector::kPseudoAutofill:
    case CSSSelector::kPseudoWebKitAutofill:
      return form_control_element->IsAutofilled() ||
             form_control_element->IsPreviewed();
    case CSSSelector::kPseudoAutofillPreviewed:
      return form_control_element->GetAutofillState() ==
             WebAutofillState::kPreviewed;
    case CSSSelector::kPseudoAutofillSelected:
      return form_control_element->IsAutofilled();
    default:
      NOTREACHED();
  }
}

bool SelectorChecker::CheckPseudoElement(const SelectorCheckingContext& context,
                                         MatchResult& result) const {
  const CSSSelector& selector = *context.selector;
  PseudoId pseudo_id = selector.GetPseudoId(selector.GetPseudoType());
  // Only descend down the ancestors chain if matching a (real) PseudoElement.
  if (pseudo_id != kPseudoIdNone && pseudo_id <= kLastTrackedPublicPseudoId) {
    result.DescendToNextPseudoElement();
  }
  Element& element =
      context.GetElementForMatching(result.pseudo_ancestor_index);

  if (context.in_nested_complex_selector) {
    // This would normally be rejected parse-time, but can happen
    // with the & selector, so reject it match-time.
    // See https://github.com/w3c/csswg-drafts/issues/7912.
    return false;
  }

  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoCue: {
      SelectorCheckingContext sub_context(context);
      sub_context.is_sub_selector = true;
      sub_context.scope = nullptr;
      sub_context.treat_shadow_host_as_normal_scope = false;

      for (sub_context.selector = selector.SelectorList()->First();
           sub_context.selector; sub_context.selector = CSSSelectorList::Next(
                                     *sub_context.selector)) {
        SubResult sub_result(result);
        if (MatchSelector(sub_context, sub_result) == kSelectorMatches) {
          return true;
        }
      }
      return false;
    }
    case CSSSelector::kPseudoPart:
      if (!part_names_) {
        return false;
      }
      for (const auto& part_name : selector.IdentList()) {
        if (!part_names_->Contains(part_name)) {
          return false;
        }
      }
      return true;
    case CSSSelector::kPseudoFileSelectorButton:
      return MatchesUAShadowElement(
          element, shadow_element_names::kPseudoFileUploadButton);
    case CSSSelector::kPseudoPicker:
      if (selector.Argument() == "select") {
        return MatchesUAShadowElement(element,
                                      shadow_element_names::kPickerSelect);
      } else {
        return false;
      }
    case CSSSelector::kPseudoPlaceholder:
      return MatchesUAShadowElement(
          element, shadow_element_names::kPseudoInputPlaceholder);
    case CSSSelector::kPseudoDetailsContent:
     
"""


```