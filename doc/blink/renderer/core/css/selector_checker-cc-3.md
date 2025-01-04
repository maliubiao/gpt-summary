Response:
My thought process to answer the request about `selector_checker.cc` goes like this:

1. **Understand the Core Request:** The user wants to know the functionality of `selector_checker.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of its behavior, potential errors, how users reach this code, and a summary of its purpose. The fact that it's part 4 of 4 suggests a deep dive is expected, building on previous parts.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the provided code, looking for key terms and patterns. Immediately, I see:
    * `CSSSelector`: This is central and confirms the file deals with CSS selectors.
    * `MatchSelector`, `Check...`:  These indicate the core function is determining if an element matches a given selector.
    * Pseudo-classes and pseudo-elements (like `::slotted`, `:host`, `::before`, etc.): This is a major focus of the code.
    * Shadow DOM related terms (`shadow_element_names`, `MatchesUAShadowElement`, `OwnerShadowHost`): This signals involvement with Shadow DOM.
    * `StyleScope`, `StyleScopeActivations`: These suggest handling of CSS `@scope` rules.
    * `UseCounter`, `WebFeature`:  Indicates tracking of CSS feature usage.
    * `Document`, `Element`: Core HTML DOM concepts.
    * `FocusController`, `IsFocused`: Relates to focus states.
    * `probe::ForcePseudoState`: Suggests a debugging or testing mechanism.

3. **Categorize Functionality:** I start grouping the observed functionalities:
    * **Pseudo-class/element Matching:** The code has explicit `case` statements for various pseudo-classes and pseudo-elements, handling their specific matching logic. This is a primary function.
    * **Shadow DOM Handling:**  Functions like `MatchesUAShadowElement` and the logic within `:host` and `::slotted` sections clearly point to Shadow DOM support.
    * **CSS `@scope` rule processing:**  The `StyleScope` and activation-related code indicate it handles the matching logic for scoped CSS.
    * **Focus and State Matching:**  Functions like `MatchesFocusPseudoClass` and `MatchesFocusVisiblePseudoClass` deal with matching based on focus states.
    * **Scrollbar Styling:** The `CheckScrollbarPseudoClass` function handles pseudo-classes specific to scrollbars.
    * **Internal Logic/Helpers:**  Functions like `ActivationCeiling`, `DefaultActivations`, and `MatchesWithScope` are helper functions for the core matching process.

4. **Relate to Web Technologies:**
    * **CSS:**  The entire file is about CSS selector matching. I need to provide concrete examples of how each pseudo-class/element is used in CSS and what it does.
    * **HTML:** The code operates on `Element` objects, which represent HTML elements. The Shadow DOM interactions are directly related to HTML's Shadow DOM feature. The `@scope` rules are applied to sections of the HTML.
    * **JavaScript:** While this C++ code doesn't directly execute JavaScript, it's crucial for the functionality of web pages where JavaScript often manipulates the DOM and CSS. For instance, JavaScript might create Shadow DOM, add classes that trigger CSS rules, or change focus, indirectly invoking this code.

5. **Construct Examples (Hypothetical Input/Output):**  For each major functional area, I devise simple HTML and CSS snippets and predict the outcome of the `selector_checker`. This involves thinking about how the matching logic would behave with specific inputs. For example:
    * `:hover`:  An element, mouse cursor over it -> `true`.
    * `::slotted`: Shadow host with slotted content and a selector that matches the content -> `true`.
    * `@scope`:  A specific structure of HTML and CSS `@scope` rules, and predicting which elements would match.

6. **Identify Potential User/Programming Errors:** I consider common mistakes developers might make when using the related web technologies that would lead to unexpected behavior handled by this code:
    * Incorrectly using Shadow DOM selectors.
    * Misunderstanding `@scope` rule boundaries.
    * Expecting focus styles to always appear without considering `:focus-visible`.
    * Issues with browser compatibility of certain pseudo-classes/elements.

7. **Explain User Journey/Debugging:** I think about how a web developer might end up investigating this code:
    * Seeing unexpected styling.
    * Using browser developer tools to inspect applied styles and trace the matching process.
    * Potentially looking at Chromium's DevTools source code which might lead them to this area.

8. **Summarize Functionality:** I condense the detailed explanations into a concise summary of the file's overall purpose.

9. **Structure the Answer:** I organize the information logically with clear headings and bullet points to make it easy to read and understand. I address each part of the user's request explicitly.

10. **Refine and Review:** I re-read my answer to ensure accuracy, clarity, and completeness, checking if I have addressed all aspects of the prompt. I look for areas where I can add more detail or improve explanations. For instance, I initially might not have emphasized the role of `is_ua_rule_` and then realize it's important for differentiating user-agent stylesheets.

By following this structured approach, I can systematically analyze the provided code and generate a comprehensive and informative answer that addresses all the user's requirements. The key is breaking down the complex code into smaller, manageable parts and then connecting those parts back to the broader context of web development.
好的，让我们来归纳一下`blink/renderer/core/css/selector_checker.cc`文件的功能，基于你提供的最后一部分代码。

**整体功能归纳：**

`selector_checker.cc` 文件的核心功能是 **判断一个给定的 HTML 元素是否匹配一个 CSS 选择器**。它实现了 CSS 规范中定义的各种选择器类型和伪类/伪元素的匹配逻辑。这个文件是 Blink 渲染引擎中 CSS 样式计算的关键组件，负责确定哪些 CSS 规则应用于哪些 DOM 元素。

**更细致的功能点 (基于提供的最后一部分代码):**

* **处理伪类和伪元素匹配:** 代码中大量的 `case CSSSelector::kPseudo...` 结构表明，该文件负责处理各种 CSS 伪类和伪元素的选择器匹配，例如：
    * **Shadow DOM 相关:** `:host`, `::slotted`, `-webkit-details-content`, `-webkit-custom-element`, `-blink-internal-element` 等，用于处理 Shadow DOM 边界和内容。
    * **高亮和过渡:** `::highlight`, `::view-transition-*` 等，用于处理文本高亮和视图过渡效果。
    * **滚动条:** `::scrollbar-*` 等，用于样式化滚动条的不同部分。
    * **其他伪类:** `:target-text`，以及其他未明确列出的伪类，通过 `default` 分支处理。
* **处理 `:host` 伪类:** 专门实现了 `:host` 伪类的匹配逻辑，包括带参数和不带参数的情况，并考虑了 Shadow DOM 的上下文。
* **处理 `:scope` 伪类:** 实现了 `:scope` 伪类的匹配逻辑，用于限定选择器的作用域。
* **处理滚动条相关的伪类:** 实现了 `:enabled`, `:disabled`, `:hover`, `:active`, `:horizontal`, `:vertical`, `:decrement`, `:increment`, `:start`, `:end`, `:double-button`, `:single-button`, `:no-button`, `:corner-present`, `:window-inactive` 等滚动条特有的伪类匹配。
* **处理 `:target-text` 伪类:**  用于匹配 URL 片段标识符指向的文本。
* **处理 `:focus` 和 `:focus-visible` 伪类:** 实现了 `:focus` 和 `:focus-visible` 伪类的匹配逻辑，考虑了元素是否获得焦点以及焦点是否应该可见。
* **处理 `@scope` 规则:**  实现了对 CSS `@scope` 规则的处理，包括计算激活的 scope 和判断元素是否在 scope 的边界内。这涉及到 `StyleScope` 和 `StyleScopeActivations` 的管理。
* **缓存机制:**  代码中提到了 `StyleScopeFrame`，暗示了对 `@scope` 规则匹配结果的缓存，以提高性能。
* **用户代理 (UA) 样式处理:** 代码中使用了 `is_ua_rule_` 标志，表明该文件也处理用户代理提供的默认样式规则。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **CSS:**  `selector_checker.cc` 直接对应 CSS 的选择器规范。它负责解释和执行 CSS 选择器，判断样式规则是否应用于特定的 HTML 元素。
    * **例子:** 当 CSS 规则 `#myDiv:hover { background-color: red; }` 应用于一个 ID 为 `myDiv` 的 `<div>` 元素时，`selector_checker.cc` 会在鼠标悬停在该元素上时，判断 `:hover` 伪类是否匹配，从而决定是否应用 `background-color: red;` 样式。
    * **例子 (伪元素):** 对于 CSS 规则 `#myDiv::before { content: "Hello"; }`，`selector_checker.cc` 会在渲染时为 `#myDiv` 元素创建一个 `::before` 伪元素，并应用相应的样式。
    * **例子 (@scope):** 对于 CSS 规则 `@scope (.card) to (.footer) { .title { color: blue; } }`，当遇到 `.title` 元素时，`selector_checker.cc` 会检查该元素是否在一个 `.card` 元素内部，且不在 `.footer` 元素内部，从而决定是否应用 `color: blue;`。

* **HTML:** `selector_checker.cc` 接收 HTML 元素作为输入，并根据 CSS 选择器对这些元素进行匹配。它理解 DOM 树的结构，并能根据选择器的要求遍历 DOM 树。
    * **例子:**  当 CSS 选择器是 `div p` (后代选择器) 时，`selector_checker.cc` 会检查当前元素的所有祖先元素中是否存在 `<div>` 元素。
    * **例子 (Shadow DOM):** 对于 Shadow DOM 中的元素，例如，当 CSS 选择器是 `:host(.dark)` 时，`selector_checker.cc` 会检查 Shadow Host 元素是否具有 `dark` 类。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和元素的属性，这会触发样式的重新计算。当 JavaScript 改变了元素的类名、ID 或添加/移除元素时，`selector_checker.cc` 会被调用以重新评估哪些样式规则应该应用。
    * **例子:** JavaScript 代码 `document.getElementById('myDiv').classList.add('active');` 可能会触发 CSS 规则 `.active { font-weight: bold; }` 的应用。`selector_checker.cc` 会判断该元素现在匹配 `.active` 选择器。

**逻辑推理的假设输入与输出：**

假设输入一个 `<div>` 元素，其 ID 为 "test"，并且具有类名 "container"。

* **假设输入:**
    * `element`:  一个 `HTMLDivElement` 对象，`id` 属性为 "test"，`class` 属性包含 "container"。
    * `selector`:  CSS 选择器字符串 "#test.container:hover"
    * `context`:  当前的样式匹配上下文 (例如，鼠标是否悬停在元素上)。

* **输出:**
    * 如果鼠标悬停在该 `<div>` 元素上，`MatchSelector` 函数 (或其他相关函数) 应该返回 `kSelectorMatches` (或类似的表示匹配成功的状态)。
    * 如果鼠标没有悬停在该元素上，则返回不匹配的状态。

**用户或编程常见的使用错误举例说明：**

* **CSS 选择器拼写错误:** 用户在编写 CSS 时，可能会错误地拼写类名、ID 或伪类/伪元素名称，导致选择器无法匹配到预期的元素。
    * **例子:** CSS 中写了 `.containr` 而不是 `.container`，或者写了 `::afterr` 而不是 `::after`。`selector_checker.cc` 会因为选择器找不到对应的元素而返回不匹配。
* **Shadow DOM 边界问题:**  开发者可能不理解 Shadow DOM 的作用域规则，导致选择器无法穿透 Shadow DOM 边界或意外地匹配到 Shadow DOM 内部的元素。
    * **例子:**  尝试使用父选择器直接选择 Shadow DOM 内部的元素，例如 `my-element > #shadowChild`，除非使用了 `::slotted` 或其他穿透 Shadow DOM 的方法，否则通常不会匹配。
* **对伪类状态的误解:**  开发者可能错误地认为某个伪类应该始终生效，而忽略了其触发条件。
    * **例子:**  认为 `:hover` 样式会在页面加载时立即应用，而实际上只有在鼠标悬停时才会生效。
* ** `@scope` 规则的范围理解错误:**  开发者可能没有正确理解 `@scope` 规则的 `to` 子句的作用，导致样式意外地应用到超出预期范围的元素。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户加载网页:**  当用户在浏览器中打开一个网页时，浏览器会下载 HTML、CSS 和 JavaScript 资源。
2. **解析 HTML 和 CSS:**  Blink 渲染引擎会解析 HTML 构建 DOM 树，解析 CSS 构建 CSSOM 树。
3. **样式计算:**  渲染引擎开始进行样式计算，这个过程会遍历 DOM 树，并根据 CSS 选择器将匹配的样式规则应用到相应的元素上。
4. **调用 `selector_checker.cc`:** 在样式计算过程中，当需要判断一个 CSS 规则是否适用于某个 DOM 元素时，就会调用 `selector_checker.cc` 中的相关函数（例如 `MatchSelector`）。
5. **用户交互或 DOM 变化:**  用户的交互行为（如鼠标悬停、点击、滚动）或 JavaScript 代码对 DOM 的修改，都可能触发样式的重新计算。
6. **调试线索:**
    * **在浏览器的开发者工具中查看 "Elements" 面板:**  开发者可以查看元素的 "Computed" 标签，了解最终应用到该元素的样式。如果样式不符合预期，可以查看 "Styles" 标签，了解哪些 CSS 规则匹配上了该元素。
    * **使用开发者工具的 "Inspect" 功能:**  选择元素后，可以查看其应用的样式规则以及这些规则的来源。
    * **利用 "Performance" 或 "Timeline" 面板:**  可以分析样式计算的性能，查看哪些选择器导致了大量的计算。
    * **设置断点 (需要 Chromium 源码环境):**  如果开发者有 Chromium 源码环境，可以在 `selector_checker.cc` 的关键函数中设置断点，例如 `MatchSelector`，来跟踪样式匹配的具体过程，查看输入的元素、选择器以及匹配结果。这有助于理解为什么某些样式规则被应用或没有被应用。

总而言之，`selector_checker.cc` 是 Blink 渲染引擎中至关重要的一个模块，它就像一个精密的“裁判”，根据 CSS 规则判断哪些样式应该应用于哪些 HTML 元素，直接影响着网页最终的视觉呈现。它的工作贯穿于网页加载、渲染和用户交互的整个生命周期。

Prompt: 
```
这是目录为blink/renderer/core/css/selector_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
 return MatchesUAShadowElement(element,
                                    shadow_element_names::kIdDetailsContent);
    case CSSSelector::kPseudoWebKitCustomElement:
      return MatchesUAShadowElement(element, selector.Value());
    case CSSSelector::kPseudoBlinkInternalElement:
      DCHECK(is_ua_rule_);
      return MatchesUAShadowElement(element, selector.Value());
    case CSSSelector::kPseudoSlotted: {
      SelectorCheckingContext sub_context(context);
      sub_context.is_sub_selector = true;
      sub_context.scope = nullptr;
      sub_context.treat_shadow_host_as_normal_scope = false;

      // ::slotted() only allows one compound selector.
      DCHECK(selector.SelectorList()->First());
      DCHECK(!CSSSelectorList::Next(*selector.SelectorList()->First()));
      sub_context.selector = selector.SelectorList()->First();
      SubResult sub_result(result);
      if (MatchSelector(sub_context, sub_result) != kSelectorMatches) {
        return false;
      }
      return true;
    }
    case CSSSelector::kPseudoHighlight: {
      result.dynamic_pseudo = PseudoId::kPseudoIdHighlight;
      // A null pseudo_argument_ means we are matching rules on the originating
      // element. We keep track of which pseudo elements may match for the
      // element through result.dynamic_pseudo. For ::highlight() pseudo
      // elements we have a single flag for tracking whether an element may
      // match _any_ ::highlight() element (kPseudoIdHighlight).
      if (!pseudo_argument_ || pseudo_argument_ == selector.Argument()) {
        result.custom_highlight_name = selector.Argument().Impl();
        return true;
      }
      return false;
    }
    case CSSSelector::kPseudoViewTransition:
    case CSSSelector::kPseudoViewTransitionGroup:
    case CSSSelector::kPseudoViewTransitionImagePair:
    case CSSSelector::kPseudoViewTransitionOld:
    case CSSSelector::kPseudoViewTransitionNew: {
      const PseudoId selector_pseudo_id =
          CSSSelector::GetPseudoId(selector.GetPseudoType());
      if (element.IsDocumentElement() && context.pseudo_id == kPseudoIdNone) {
        // We don't strictly need to use dynamic_pseudo since we don't rely on
        // SetHasPseudoElementStyle but we need to return a match to invalidate
        // the originating element and set dynamic_pseudo to avoid collecting
        // it as a matched rule in ElementRuleCollector.
        result.dynamic_pseudo = selector_pseudo_id;
        return true;
      }

      if (selector_pseudo_id != context.pseudo_id) {
        return false;
      }
      result.dynamic_pseudo = context.pseudo_id;
      if (selector_pseudo_id == kPseudoIdViewTransition) {
        return true;
      }

      CHECK(!selector.IdentList().empty());
      const AtomicString& name_or_wildcard = selector.IdentList()[0];

      // note that the pseudo_ident_list_ is the class list, and
      // pseudo_argument_ is the name, while in the selector the IdentList() is
      // both the name and the classes.
      if (name_or_wildcard != CSSSelector::UniversalSelectorAtom() &&
          name_or_wildcard != pseudo_argument_) {
        return false;
      }

      // https://drafts.csswg.org/css-view-transitions-2/#typedef-pt-class-selector
      // A named view transition pseudo-element selector which has one or more
      // <custom-ident> values in its <pt-class-selector> would only match an
      // element if the class list value in named elements for the
      // pseudo-element’s view-transition-name contains all of those values.

      // selector.IdentList() is equivalent to
      // <pt-name-selector><pt-class-selector>, as in [name, class, class, ...]
      // so we check that all of its items excluding the first one are
      // contained in the pseudo element's classes (pseudo_ident_list_).
      return base::ranges::all_of(
          selector.IdentList().begin() + 1, selector.IdentList().end(),
          [&](const AtomicString& class_from_selector) {
            return base::Contains(pseudo_ident_list_, class_from_selector);
          });
    }
    case CSSSelector::kPseudoScrollbarButton:
    case CSSSelector::kPseudoScrollbarCorner:
    case CSSSelector::kPseudoScrollbarThumb:
    case CSSSelector::kPseudoScrollbarTrack:
    case CSSSelector::kPseudoScrollbarTrackPiece: {
      if (CSSSelector::GetPseudoId(selector.GetPseudoType()) !=
          context.pseudo_id) {
        return false;
      }
      result.dynamic_pseudo = context.pseudo_id;
      return true;
    }
    case CSSSelector::kPseudoTargetText:
      if (!is_ua_rule_) {
        UseCounter::Count(context.element->GetDocument(),
                          WebFeature::kCSSSelectorTargetText);
      }
      [[fallthrough]];
    default:
      DCHECK_NE(mode_, kQueryingRules);
      result.dynamic_pseudo =
          CSSSelector::GetPseudoId(selector.GetPseudoType());
      DCHECK_NE(result.dynamic_pseudo, kPseudoIdNone);
      // If we are matching for pseudo element, we can be
      // at some pseudo element sub selector here, check that
      // it matches the current element from ancestor pseudo elements
      // (element would be set to one above).
      // E.g. when matching for scroll marker pseudo element that is
      // generated from column pseudo element that is generated from element
      // with id=div and selector is #div::column::scroll-marker, we can end up
      // here with `element`=column pseudo element and sub-selector being
      // ::column, so return true, but if the selector was
      // #div::after::scroll-marker, we would fail here as ::after shouldn't
      // match column pseudo element.
      if (context.pseudo_element) {
        // #div::before::before for before of #div should be added as a rule to
        // before, but for before of before of #div, only set before pseudo
        // element style flag for before of #div.
        if (result.pseudo_ancestor_index ==
                context.pseudo_element_ancestors.size() - 1 &&
            context.pseudo_element == element) {
          result.dynamic_pseudo = kPseudoIdNone;
        }
        // If `pseudo_ancestor_index` == size, it means that we've match the
        // ancestors chain and now collect pseudo styles for pseudo element,
        // always match in this case. E.g. column pseudo element and rule
        // div::column::scroll-marker. When ::column is matched and now we
        // look at ::scroll-marker part, index == size == 1, so just mark
        // column as having scroll-marker style.
        return element.GetPseudoIdForStyling() ==
                   selector.GetPseudoId(selector.GetPseudoType()) ||
               result.pseudo_ancestor_index ==
                   context.pseudo_element_ancestors.size();
      }
      // Don't allow matching nested pseudo elements from regular elements,
      // e.g. #div::column::scroll-marker on #div.
      return context.previously_matched_pseudo_element == kPseudoIdNone;
  }
}

bool SelectorChecker::CheckPseudoHost(const SelectorCheckingContext& context,
                                      MatchResult& result) const {
  const CSSSelector& selector = *context.selector;
  Element& element =
      context.GetElementForMatching(result.pseudo_ancestor_index);

  // :host only matches a shadow host when :host is in a shadow tree of the
  // shadow host.
  if (!context.scope) {
    return false;
  }
  const ContainerNode* shadow_host = context.scope->OwnerShadowHost();
  if (!shadow_host || shadow_host != element) {
    return false;
  }
  DCHECK(IsShadowHost(element));
  DCHECK(element.GetShadowRoot());

  // For the case with no parameters, i.e. just :host.
  if (!selector.SelectorList()) {
    return true;
  }

  DCHECK(selector.SelectorList()->IsSingleComplexSelector());

  SelectorCheckingContext sub_context(context);
  sub_context.is_sub_selector = true;
  sub_context.selector = selector.SelectorList()->First();
  sub_context.treat_shadow_host_as_normal_scope = true;
  sub_context.scope = context.scope;
  // Use FlatTreeTraversal to traverse a composed ancestor list of a given
  // element.
  Element* next_element = &element;
  SelectorCheckingContext host_context(sub_context);
  do {
    SubResult sub_result(result);
    host_context.element = next_element;
    if (MatchSelector(host_context, sub_result) == kSelectorMatches) {
      return true;
    }
    host_context.treat_shadow_host_as_normal_scope = false;
    host_context.scope = nullptr;

    if (selector.GetPseudoType() == CSSSelector::kPseudoHost) {
      break;
    }

    host_context.in_rightmost_compound = false;
    host_context.impact = Impact::kNonSubject;
    next_element = FlatTreeTraversal::ParentElement(*next_element);
  } while (next_element);

  // FIXME: this was a fallthrough condition.
  return false;
}

bool SelectorChecker::CheckPseudoScope(const SelectorCheckingContext& context,
                                       MatchResult& result) const {
  Element& element = *context.element;
  if (!context.scope) {
    return false;
  }
  if (context.scope->IsElementNode()) {
    return context.scope == &element;
  }
  return element == element.GetDocument().documentElement();
}

bool SelectorChecker::CheckScrollbarPseudoClass(
    const SelectorCheckingContext& context,
    MatchResult& result) const {
  const CSSSelector& selector = *context.selector;

  if (selector.GetPseudoType() == CSSSelector::kPseudoNot) {
    return CheckPseudoNot(context, result);
  }

  // FIXME: This is a temporary hack for resizers and scrollbar corners.
  // Eventually :window-inactive should become a real
  // pseudo class and just apply to everything.
  if (selector.GetPseudoType() == CSSSelector::kPseudoWindowInactive) {
    return !context.element->GetDocument()
                .GetPage()
                ->GetFocusController()
                .IsActive();
  }

  if (!scrollbar_) {
    return false;
  }

  switch (selector.GetPseudoType()) {
    case CSSSelector::kPseudoEnabled:
      return scrollbar_->Enabled();
    case CSSSelector::kPseudoDisabled:
      return !scrollbar_->Enabled();
    case CSSSelector::kPseudoHover: {
      ScrollbarPart hovered_part = scrollbar_->HoveredPart();
      if (scrollbar_part_ == kScrollbarBGPart) {
        return hovered_part != kNoPart;
      }
      if (scrollbar_part_ == kTrackBGPart) {
        return hovered_part == kBackTrackPart ||
               hovered_part == kForwardTrackPart || hovered_part == kThumbPart;
      }
      return scrollbar_part_ == hovered_part;
    }
    case CSSSelector::kPseudoActive: {
      ScrollbarPart pressed_part = scrollbar_->PressedPart();
      if (scrollbar_part_ == kScrollbarBGPart) {
        return pressed_part != kNoPart;
      }
      if (scrollbar_part_ == kTrackBGPart) {
        return pressed_part == kBackTrackPart ||
               pressed_part == kForwardTrackPart || pressed_part == kThumbPart;
      }
      return scrollbar_part_ == pressed_part;
    }
    case CSSSelector::kPseudoHorizontal:
      return scrollbar_->Orientation() == kHorizontalScrollbar;
    case CSSSelector::kPseudoVertical:
      return scrollbar_->Orientation() == kVerticalScrollbar;
    case CSSSelector::kPseudoDecrement:
      return scrollbar_part_ == kBackButtonStartPart ||
             scrollbar_part_ == kBackButtonEndPart ||
             scrollbar_part_ == kBackTrackPart;
    case CSSSelector::kPseudoIncrement:
      return scrollbar_part_ == kForwardButtonStartPart ||
             scrollbar_part_ == kForwardButtonEndPart ||
             scrollbar_part_ == kForwardTrackPart;
    case CSSSelector::kPseudoStart:
      return scrollbar_part_ == kBackButtonStartPart ||
             scrollbar_part_ == kForwardButtonStartPart ||
             scrollbar_part_ == kBackTrackPart;
    case CSSSelector::kPseudoEnd:
      return scrollbar_part_ == kBackButtonEndPart ||
             scrollbar_part_ == kForwardButtonEndPart ||
             scrollbar_part_ == kForwardTrackPart;
    case CSSSelector::kPseudoDoubleButton:
      // :double-button matches nothing on all platforms.
      return false;
    case CSSSelector::kPseudoSingleButton:
      if (!scrollbar_->GetTheme().NativeThemeHasButtons()) {
        return false;
      }
      return scrollbar_part_ == kBackButtonStartPart ||
             scrollbar_part_ == kForwardButtonEndPart ||
             scrollbar_part_ == kBackTrackPart ||
             scrollbar_part_ == kForwardTrackPart;
    case CSSSelector::kPseudoNoButton:
      if (scrollbar_->GetTheme().NativeThemeHasButtons()) {
        return false;
      }
      return scrollbar_part_ == kBackTrackPart ||
             scrollbar_part_ == kForwardTrackPart;
    case CSSSelector::kPseudoCornerPresent:
      return scrollbar_->IsScrollCornerVisible();
    default:
      return false;
  }
}

bool SelectorChecker::MatchesSelectorFragmentAnchorPseudoClass(
    const Element& element) {
  return element == element.GetDocument().CssTarget() &&
         element.GetDocument().View()->GetFragmentAnchor() &&
         element.GetDocument()
             .View()
             ->GetFragmentAnchor()
             ->IsSelectorFragmentAnchor();
}

bool SelectorChecker::MatchesFocusPseudoClass(
    const Element& element,
    PseudoId matching_for_pseudo_element) {
  const Element* matching_element = &element;
  if (matching_for_pseudo_element != kPseudoIdNone) {
    matching_element = element.GetPseudoElement(matching_for_pseudo_element);
    if (!matching_element) {
      return false;
    }
  }
  bool force_pseudo_state = false;
  probe::ForcePseudoState(const_cast<Element*>(matching_element),
                          CSSSelector::kPseudoFocus, &force_pseudo_state);
  if (force_pseudo_state) {
    return true;
  }
  return matching_element->IsFocused() && IsFrameFocused(*matching_element);
}

bool SelectorChecker::MatchesFocusVisiblePseudoClass(const Element& element) {
  bool force_pseudo_state = false;
  probe::ForcePseudoState(const_cast<Element*>(&element),
                          CSSSelector::kPseudoFocusVisible,
                          &force_pseudo_state);
  if (force_pseudo_state) {
    return true;
  }

  if (!element.IsFocused() || !IsFrameFocused(element)) {
    return false;
  }

  const Document& document = element.GetDocument();
  // Exclude shadow hosts with non-UA ShadowRoot.
  if (document.FocusedElement() != element && element.GetShadowRoot() &&
      !element.GetShadowRoot()->IsUserAgent()) {
    return false;
  }

  const Settings* settings = document.GetSettings();
  bool always_show_focus = settings->GetAccessibilityAlwaysShowFocus();
  bool is_text_input = element.MayTriggerVirtualKeyboard();
  bool last_focus_from_mouse =
      document.GetFrame() &&
      document.GetFrame()->Selection().FrameIsFocusedAndActive() &&
      document.LastFocusType() == mojom::blink::FocusType::kMouse;
  bool had_keyboard_event = document.HadKeyboardEvent();

  return (always_show_focus || is_text_input || !last_focus_from_mouse ||
          had_keyboard_event);
}

namespace {

// CalculateActivations will not produce any activations unless there is
// an outer activation (i.e. an activation of the outer StyleScope). If there
// is no outer StyleScope, we use this DefaultActivations as the outer
// activation. The scope provided to DefaultActivations is typically
// a ShadowTree.
StyleScopeActivations& DefaultActivations(const ContainerNode* scope) {
  auto* activations = MakeGarbageCollected<StyleScopeActivations>();
  activations->vector = HeapVector<StyleScopeActivation>(
      1, StyleScopeActivation{scope, std::numeric_limits<unsigned>::max()});
  return *activations;
}

// The activation ceiling is the highest ancestor element that can
// match inside some StyleScopeActivation.
//
// You would think that only elements inside the scoping root (activation.root)
// could match, but it is possible for a selector to be matched with respect to
// some scoping root [1] without actually being scoped to that root [2].
//
// This is relevant when matching elements inside a shadow tree, where the root
// of the default activation will be the ShadowRoot, but the host element (which
// sits *above* the ShadowRoot) should still be reached with :host.
//
// [1] https://drafts.csswg.org/selectors-4/#the-scope-pseudo
// [2] https://drafts.csswg.org/selectors-4/#scoped-selector
const Element* ActivationCeiling(const StyleScopeActivation& activation) {
  if (!activation.root) {
    return nullptr;
  }
  if (auto* element = DynamicTo<Element>(activation.root.Get())) {
    return element;
  }
  ShadowRoot* shadow_root = activation.root->GetShadowRoot();
  return shadow_root ? &shadow_root->host() : nullptr;
}

// True if this StyleScope has an implicit root at the specified element.
// This is used to find the roots for prelude-less @scope rules.
bool HasImplicitRoot(const StyleScope& style_scope, Element& element) {
  if (const StyleScopeData* style_scope_data = element.GetStyleScopeData()) {
    return style_scope_data->TriggersScope(style_scope);
  }
  return false;
}

}  // namespace

const StyleScopeActivations& SelectorChecker::EnsureActivations(
    const SelectorCheckingContext& context,
    const StyleScope& style_scope) const {
  DCHECK(context.style_scope_frame);

  // The *outer activations* are the activations of the outer StyleScope.
  // If there is no outer StyleScope, we create a "default" activation to
  // make the code in CalculateActivations more readable.
  //
  // Must not be confused with the *parent activations* (seen in
  // CalculateActivations), which are the activations (for the same StyleScope)
  // of the *parent element*.
  const StyleScopeActivations* outer_activations =
      style_scope.Parent() ? &EnsureActivations(context, *style_scope.Parent())
                           : &DefaultActivations(context.scope);
  // The `match_visited` flag may have been set to false e.g. due to a link
  // having been encountered (see DisallowMatchVisited), but scope activations
  // are calculated lazily when :scope is first seen in a compound selector,
  // and the scoping limit needs to evaluate according to the original setting.
  //
  // Consider the following, which should not match, because the :visited link
  // is a scoping limit:
  //
  //  @scope (#foo) to (:visited) { :scope a:visited { ... } }
  //
  // In the above selector, we first match a:visited, and set match_visited to
  // false since a link was encountered. Then we encounter a compound
  // with :scope, which causes scopes to be activated (NeedsScopeActivation
  // ()). At this point we try to find the scoping limit (:visited), but it
  // wouldn't match anything because match_visited is set to false, so the
  // selector would incorrectly match. For this reason we need to evaluate the
  // scoping root and limits with the original match_visited setting.
  bool match_visited = context.match_visited || context.had_match_visited;
  // We only use the cache when matching normal/non-visited rules. Otherwise
  // we'd need to double up the cache.
  StyleScopeFrame* style_scope_frame =
      match_visited ? nullptr : context.style_scope_frame;
  const StyleScopeActivations* activations = CalculateActivations(
      context.style_scope_frame->element_, style_scope, *outer_activations,
      style_scope_frame, match_visited);
  DCHECK(activations);
  return *activations;
}

// Calculates all activations (i.e. active scopes) for `element`.
//
// This function will traverse the whole ancestor chain in the worst case,
// however, if a StyleScopeFrame is provided, it will reuse cached results
// found on that StyleScopeFrame.
const StyleScopeActivations* SelectorChecker::CalculateActivations(
    Element& element,
    const StyleScope& style_scope,
    const StyleScopeActivations& outer_activations,
    StyleScopeFrame* style_scope_frame,
    bool match_visited) const {
  Member<const StyleScopeActivations>* cached_activations_entry = nullptr;
  if (style_scope_frame) {
    auto entry = style_scope_frame->data_.insert(&style_scope, nullptr);
    // We must not modify `style_scope_frame->data_` for the remainder
    // of this function, since `cached_activations_entry` now points into
    // the hash table.
    cached_activations_entry = &entry.stored_value->value;
    if (!entry.is_new_entry) {
      DCHECK(cached_activations_entry->Get());
      return cached_activations_entry->Get();
    }
  }

  auto* activations = MakeGarbageCollected<StyleScopeActivations>();

  if (!outer_activations.vector.empty()) {
    const StyleScopeActivations* parent_activations = nullptr;

    // Remain within the outer scope. I.e. don't look at elements above the
    // highest outer activation.
    if (&element != ActivationCeiling(outer_activations.vector.front())) {
      if (Element* parent = element.ParentOrShadowHostElement()) {
        // When calculating the activations on the parent element, we pass
        // the parent StyleScopeFrame (if we have it) to be able to use the
        // cached results, and avoid traversing the ancestor chain.
        StyleScopeFrame* parent_frame =
            style_scope_frame ? style_scope_frame->GetParentFrameOrNull(*parent)
                              : nullptr;
        // Disable :visited matching when encountering the first link.
        // This matches the behavior for regular child/descendant combinators.
        bool parent_match_visited = match_visited && !element.IsLink();
        parent_activations =
            CalculateActivations(*parent, style_scope, outer_activations,
                                 parent_frame, parent_match_visited);
      }
    }

    // The activations of the parent element are still active for this element,
    // unless this element is a scoping limit.
    if (parent_activations) {
      activations->match_flags = parent_activations->match_flags;

      for (const StyleScopeActivation& activation :
           parent_activations->vector) {
        if (!ElementIsScopingLimit(style_scope, activation, element,
                                   match_visited, activations->match_flags)) {
          activations->vector.push_back(
              StyleScopeActivation{activation.root, activation.proximity + 1});
        }
      }
    }

    // Check if we need to add a new activation for this element.
    for (const StyleScopeActivation& outer_activation :
         outer_activations.vector) {
      if (style_scope.From()
              ? MatchesWithScope(element, *style_scope.From(),
                                 outer_activation.root, match_visited,
                                 activations->match_flags)
              : HasImplicitRoot(style_scope, element)) {
        StyleScopeActivation activation{&element, 0};
        // It's possible for a newly created activation to be immediately
        // limited (e.g. @scope (.x) to (.x)).
        if (!ElementIsScopingLimit(style_scope, activation, element,
                                   match_visited, activations->match_flags)) {
          activations->vector.push_back(activation);
        }
        break;
      }
      // TODO(crbug.com/1280240): Break if we don't depend on :scope.
    }
  }

  // Cache the result if possible.
  if (cached_activations_entry) {
    *cached_activations_entry = activations;
  }

  return activations;
}

bool SelectorChecker::MatchesWithScope(Element& element,
                                       const CSSSelector& selector_list,
                                       const ContainerNode* scope,
                                       bool match_visited,
                                       MatchFlags& match_flags) const {
  SelectorCheckingContext context(&element);
  context.scope = scope;
  context.match_visited = match_visited;
  // We are matching this selector list with the intent of storing the result
  // in a cache (StyleScopeFrame). The :scope pseudo-class which triggered
  // this call to MatchesWithScope, is either part of the subject compound
  // or *not* part of the subject compound, but subsequent cache hits which
  // return this result may have the opposite subject/non-subject position.
  // Therefore we're using Impact::kBoth, to ensure sufficient invalidation.
  context.impact = Impact::kBoth;
  for (context.selector = &selector_list; context.selector;
       context.selector = CSSSelectorList::Next(*context.selector)) {
    MatchResult match_result;
    bool match = MatchSelector(context, match_result) ==
                 SelectorChecker::kSelectorMatches;
    match_flags |= match_result.flags;
    if (match) {
      return true;
    }
  }
  return false;
}

bool SelectorChecker::ElementIsScopingLimit(
    const StyleScope& style_scope,
    const StyleScopeActivation& activation,
    Element& element,
    bool match_visited,
    MatchFlags& match_flags) const {
  if (!style_scope.To()) {
    return false;
  }
  return MatchesWithScope(element, *style_scope.To(), activation.root.Get(),
                          match_visited, match_flags);
}

}  // namespace blink

"""


```