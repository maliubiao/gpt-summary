Response:
The user wants a summary of the functionality of the provided C++ code snippet from `style_resolver.cc`. I need to identify the main actions performed in this part of the code, especially focusing on its relation to CSS, HTML, and JavaScript. I also need to consider potential user errors and debugging steps to reach this code.

Here's a breakdown of the code's key functions:

1. **`MatchStyleAttribute`**: Handles styles defined directly in the HTML `style` attribute.
2. **`MatchElementScopeRules`**:  Deals with CSS rules defined within the same scope as the element, considering shadow boundaries.
3. **`MatchOuterScopeRules`**:  Handles CSS rules from parent scopes, specifically for `::part()` and user-agent shadow pseudo-elements.
4. **`MatchPseudoPartRulesForUAHost` & `MatchPseudoPartRules`**: Manage matching of `::part()` pseudo-element rules.
5. **`MatchPositionTryRules`**:  Adds properties related to try/tactics styling.
6. **`MatchAuthorRules`**: Orchestrates the matching of author-defined CSS rules (including inline styles, scoped styles, `::part()` rules, and VTT styles).
7. **`MatchUserRules`**: Collects and applies user-defined CSS rules.
8. **`ForEachUARulesForElement` & `MatchUARules`**: Handle the application of browser's default (user-agent) styles.
9. **`MatchPresentationalHints`**:  Applies styling from HTML presentational attributes.
10. **`MatchAllRules`**:  Coordinates the application of all types of CSS rules (UA, user, author).
11. **`StyleForViewport`**:  Creates the initial style for the viewport.
12. **`ResolveStyle`**: The core function for computing the final style of an element, including handling animations and caching.
13. **`InitStyle`**: Initializes the `ComputedStyle` object for an element.
14. **`ApplyMathMLCustomStyleProperties`**:  Applies specific styling for MathML elements.
15. **`CanApplyInlineStyleIncrementally`**: Determines if inline style changes can be applied without a full style recalculation.

Now, I can formulate the summary, providing examples and considering potential errors and debugging.
这是 `blink/renderer/core/css/resolver/style_resolver.cc` 源代码文件的第二部分，主要负责**匹配和应用各种来源的 CSS 规则**到一个元素上，以确定其最终的计算样式 (ComputedStyle)。  它涵盖了以下主要功能：

**核心功能归纳:**

* **处理不同作用域的 CSS 规则:**  这部分代码的核心在于如何有效地收集和应用来自不同作用域的 CSS 规则，包括元素自身作用域、父作用域以及更外层的作用域（特别是涉及到 Shadow DOM 时）。
* **处理不同来源的 CSS 规则:** 代码处理了来自 `style` 属性的内联样式、 `<style>` 标签或外部 CSS 文件中定义的作者样式、用户自定义样式以及浏览器默认的 User-Agent 样式。
* **处理特殊的 CSS 特性:**  包括对 `::part()` 伪元素、用户代理 Shadow DOM 内部的伪元素、以及 VTT (Video Text Tracks) 样式的特殊处理。
* **优化内联样式的处理:**  针对频繁修改的内联样式，采取了不进行缓存的策略，以避免性能问题。
* **作为样式计算的核心流程的一部分:** 这部分代码是 `StyleResolver::ResolveStyle` 函数调用的重要环节，负责规则匹配，为后续的样式计算和应用奠定基础。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:**
   * **`style` 属性:**  `MatchStyleAttribute` 函数直接处理 HTML 元素 `style` 属性中定义的内联样式。
     * **例子:**  对于 `<div style="color: red;"></div>`，`MatchStyleAttribute` 会将 `color: red;` 作为作者样式应用到该 `div` 元素。
   * **Shadow DOM:**  `MatchElementScopeRules` 和 `MatchOuterScopeRules` 负责处理跨越 Shadow DOM 边界的样式规则，例如 `:host-context` 和 `::part()`。
     * **例子:**  一个自定义元素内部的 Shadow DOM 中，CSS 规则 `:host-context(.theme-dark)` 可以根据外部宿主元素是否拥有 `theme-dark` 类来改变内部样式。 `::part(button)` 可以选择 Shadow DOM 内部拥有 `part="button"` 属性的元素。
   * **`<style>` 标签:**  这部分代码间接处理了 `<style>` 标签中定义的 CSS 规则，这些规则会被解析并存储在 `StyleEngine` 中，并通过 `MatchElementScopeRules` 和 `MatchOuterScopeRules` 等函数进行匹配。
   * **`part` 属性:** `MatchPseudoPartRules` 函数专门处理带有 `part` 属性的元素，并匹配针对这些 "part" 定义的 `::part()` 伪元素规则。
     * **例子:** `<button part="primary submit"></button>` 中的 `part` 属性允许 CSS 通过 `::part(primary)` 或 `::part(submit)` 选择器来设置样式。

2. **CSS:**
   * **选择器匹配:**  这部分代码是浏览器 CSS 引擎进行选择器匹配的核心部分。例如，`MatchHostRules` 匹配 `:host` 和 `:host()` 伪类选择器。
     * **例子:**  对于 Shadow DOM 中的样式规则 `:host(.active) button { ... }`，`MatchHostRules` 会确保只有当 Shadow Host 元素拥有 `active` 类时，`button` 元素的样式才会生效。
   * **级联 (Cascade):**  代码中多次出现的 `CascadeOrigin` 枚举 (如 `kAuthor`, `kUser`, `kUserAgent`) 以及排序和传输匹配规则的操作 (`SortAndTransferMatchedRules`) 都与 CSS 的级联机制紧密相关。不同的来源的样式具有不同的优先级。
   * **伪元素:**  代码专门处理了各种伪元素，例如 `::part()`, 用户代理 Shadow DOM 的内部伪元素 (例如 `::-webkit-media-controls-play-button`)，以及 VTT 相关的伪元素。
   * **`@exportparts` 规则:** `MatchOuterScopeRules` 中考虑了 `@exportparts` 规则，它允许 Shadow DOM 将内部元素的 "part" 暴露给外部作用域。

3. **JavaScript:**
   * **修改 `style` 属性:**  JavaScript 可以通过修改元素的 `style` 属性来动态改变元素的样式。`MatchStyleAttribute` 函数确保这些修改后的内联样式被应用。
     * **例子:**  JavaScript 代码 `document.getElementById('myDiv').style.backgroundColor = 'blue';` 会直接影响 `MatchStyleAttribute` 的处理结果。
   * **操作 DOM 结构:**  JavaScript 对 DOM 结构的修改（例如添加或删除元素，改变元素的父子关系）会导致样式的重新计算，从而触发这部分代码的执行。
   * **自定义元素 (Custom Elements) 和 Shadow DOM:** JavaScript 用于创建自定义元素和关联 Shadow DOM。 这部分 C++ 代码负责处理这些场景下的样式规则匹配。
   * **`element.partList`:** JavaScript 可以通过 `element.partList` API 来访问和修改元素的 `part` 属性，这会直接影响 `MatchPseudoPartRules` 的行为。

**逻辑推理和假设输入/输出:**

假设有以下 HTML 结构和一个简单的 CSS 规则：

**HTML:**
```html
<div id="myDiv" style="font-size: 16px;">
  <button part="main">Click Me</button>
</div>
<style>
  #myDiv { color: blue; }
  #myDiv::part(main) { background-color: yellow; }
</style>
```

**假设输入:**  `StyleResolver` 尝试计算 `button` 元素的样式。

**逻辑推理:**

1. **`MatchElementScopeRules` (针对 `button` 元素):**
   * 收集与 `button` 元素自身作用域相关的作者样式规则。
   * 由于 `button` 元素有 `part="main"` 属性，`MatchHostPartRules` (如果 `CSSCascadeCorrectScopeEnabled` 为 true) 或后续的 `MatchPseudoPartRules` 会被调用。

2. **`MatchOuterScopeRules` (针对 `button` 元素的宿主元素 `div#myDiv`):**
   * 如果 `CSSCascadeCorrectScopeEnabled` 为 true，则会检查父作用域 (包含 `div#myDiv` 的作用域) 中是否有针对 `::part(main)` 的规则。

3. **`MatchPseudoPartRules` (针对 `button` 元素):**
   * 遍历 `button` 元素的祖先元素，查找定义了针对 `::part(main)` 的规则的作用域。
   * 在包含 `<style>` 标签的作用域中找到了 `#myDiv::part(main) { background-color: yellow; }` 规则。

4. **`MatchStyleAttribute` (针对 `button` 元素):**
   * 检查 `button` 元素自身是否有内联 `style` 属性，本例中没有。

5. **`MatchAuthorRules`:** 整合以上匹配到的规则。

**假设输出 (部分):**

* `button` 元素的计算样式中，`background-color` 属性的值为 `yellow` (来自 `#myDiv::part(main)` 规则)。
* 其他样式属性会根据 CSS 级联规则，结合来自 `#myDiv` 的规则和其他可能的规则来确定。

**用户或编程常见的使用错误及举例说明:**

1. **在 Shadow DOM 内部错误地使用 `::part()`:**  如果在外部样式表中尝试使用 `::part()` 选择一个没有 `part` 属性的内部元素，或者 `part` 属性的值拼写错误，则样式不会生效。
   * **例子:**  Shadow DOM 内部的 `<span class="inner">Text</span>`，外部 CSS 使用 `my-element::part(innder) { ... }` (拼写错误)，则样式不会应用。

2. **对频繁动画的元素使用内联样式并期望高性能缓存:**  代码中提到，对于通过 JavaScript 每帧修改 `style` 属性来创建动画的情况，这些样式默认不进行 MPC 缓存。如果用户期望这些频繁变化的内联样式被缓存，可能会导致误解和性能问题。
   * **例子:**  使用 JavaScript 每帧修改 `element.style.transform` 来创建动画，这些样式不会被 MPC 缓存。

3. **不理解 Shadow DOM 的作用域规则:**  在 Shadow DOM 中定义的样式默认不会影响外部 DOM，除非使用了像 `:host`, `:host-context`, `::part` 或 `@exportparts` 这样的机制。用户可能会错误地认为内部样式会直接影响外部元素。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户加载网页:**  当用户在浏览器中打开一个包含 CSS 样式和可能包含 Shadow DOM 的网页时，浏览器开始解析 HTML 和 CSS。
2. **样式计算触发:**  浏览器需要计算页面上每个元素的最终样式，以便进行渲染。这可能发生在页面首次加载时，或者在 DOM 结构或 CSS 规则发生变化时。
3. **`StyleResolver::ResolveStyle` 调用:**  对于需要计算样式的元素，Blink 的样式引擎会调用 `StyleResolver::ResolveStyle` 函数。
4. **进入规则匹配阶段:**  在 `ResolveStyle` 函数内部，会调用 `MatchAllRules` 函数，该函数会依次调用 `MatchUARules`, `MatchUserRules`, `MatchAuthorRules` 等函数。
5. **`MatchAuthorRules` 深入:**  如果正在处理作者样式，`MatchAuthorRules` 会被调用，它会进一步调用 `MatchHostRules`, `MatchSlottedRules`, `MatchElementScopeRules`, `MatchOuterScopeRules`, `MatchPseudoPartRules` 和 `MatchVTTRules` 等函数，具体调用的函数取决于元素的类型、所在的作用域以及相关的 CSS 规则。
6. **`MatchStyleAttribute` 触发:** 如果当前正在处理的元素具有 `style` 属性，并且需要应用作者样式，则会调用 `MatchStyleAttribute` 来处理内联样式。
7. **`MatchPseudoPartRules` 触发:** 如果正在处理的元素具有 `part` 属性，或者其祖先元素定义了针对该元素的 `::part()` 规则，则会调用 `MatchPseudoPartRules`。

**调试线索:**

* **查看元素的 `style` 属性:**  检查元素的 `style` 属性，确认是否有预期的内联样式。
* **检查相关的 CSS 规则:**  使用浏览器的开发者工具查看应用于元素的 CSS 规则，确认是否有预期的作者样式规则，特别是涉及到 Shadow DOM 和 `::part()` 的规则。
* **检查 Shadow DOM 结构:**  如果涉及到 Shadow DOM，使用开发者工具查看 Shadow DOM 的结构，确认元素的 `part` 属性是否正确设置，以及外部的 `::part()` 选择器是否指向了正确的内部元素。
* **断点调试:**  在 `style_resolver.cc` 中相关的函数（如 `MatchStyleAttribute`, `MatchPseudoPartRules`）设置断点，可以逐步跟踪样式匹配的过程，查看哪些规则被匹配，哪些没有被匹配。
* **使用 "Inspect" 功能:**  开发者工具的 "Inspect" 功能可以显示元素的计算样式，这有助于了解最终应用到元素的样式是什么，并可以帮助缩小问题范围。

总而言之，这部分代码是 Blink 渲染引擎中至关重要的一个环节，它负责理解和应用各种来源和作用域的 CSS 规则，最终确定元素的视觉呈现。理解这部分代码的功能有助于深入理解浏览器的样式计算机制，并能更有效地调试 CSS 相关的问题，特别是涉及到 Shadow DOM 和自定义元素时。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
InlineStyle() &&
      collector.GetPseudoId() == kPseudoIdNone) {
    // Do not add styles depending on style attributes to the
    // MatchedPropertiesCache (MPC) if they have been modified after parsing.
    // The reason is that these are typically used for animations by modifying
    // the style attribute every frame, and making the style cacheable would
    // effectively just fill up the MPC with unnecessary ComputedStyles.
    //
    // Note that we have a special fast path for modifying certain independent
    // attributes on inline style, which also bypasses the MPC.
    bool is_inline_style_cacheable = !element.InlineStyle()->IsMutable();
    collector.AddElementStyleProperties(
        element.InlineStyle(), CascadeOrigin::kAuthor,
        is_inline_style_cacheable, true /* is_inline_style */);
  }
}

// Matches rules from the element's scope. The selectors may cross shadow
// boundaries during matching, like for :host-context.
void MatchElementScopeRules(const Element& element,
                            ElementRuleCollector& collector,
                            StyleRuleUsageTracker* tracker) {
  ScopedStyleResolver* element_scope_resolver = ScopedResolverFor(element);
  bool style_attribute_cascaded_in_parent_scope = false;
  bool use_parent_resolver = UseParentResolverForUAShadowPseudo(
      element, &style_attribute_cascaded_in_parent_scope);
  collector.BeginAddingAuthorRulesForTreeScope(element.GetTreeScope());
  if (element_scope_resolver) {
    collector.ClearMatchedRules();
    DCHECK_EQ(&element_scope_resolver->GetTreeScope(), &element.GetTreeScope());
    element_scope_resolver->CollectMatchingElementScopeRules(
        collector, /*part_shadow_host*/ nullptr);
    if (RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled()) {
      MatchHostPartRules(element, collector, tracker);
    }
    collector.SortAndTransferMatchedRules(
        CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker);
  }

  if (!style_attribute_cascaded_in_parent_scope) {
    MatchStyleAttribute(element, collector, tracker);
  }

  if (use_parent_resolver &&
      !RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled()) {
    ScopedStyleResolver* parent_scope_resolver =
        element.GetTreeScope().ParentTreeScope()->GetScopedStyleResolver();
    if (parent_scope_resolver) {
      // TODO(crbug.com/40280846): Pseudo elements matching elements inside
      // UA shadow trees (::-internal-*, ::-webkit-*, ::placeholder, etc.,
      // although not ::cue) should end up in the same cascade context as
      // other rules from an outer tree (like ::part() rules), and
      // collected separately from the element's tree scope. That should
      // remove the need for the ParentScopedResolver() here.
      collector.ClearMatchedRules();
      collector.BeginAddingAuthorRulesForTreeScope(
          parent_scope_resolver->GetTreeScope());
      parent_scope_resolver->CollectMatchingElementScopeRules(
          collector, /*part_shadow_host*/ nullptr);
      collector.SortAndTransferMatchedRules(
          CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker);
      if (style_attribute_cascaded_in_parent_scope) {
        MatchStyleAttribute(element, collector, tracker);
      }
    } else {
      CHECK(!style_attribute_cascaded_in_parent_scope);
    }
  }
}

void MatchOuterScopeRules(const Element& matching_element,
                          ElementRuleCollector& collector,
                          StyleRuleUsageTracker* tracker) {
  CHECK(RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled());

  // Because ::part() is never allowed after ::part(), or after another
  // pseudo-element, and because elements (generally those in UA shadow trees,
  // but this is also used for VTT) that are exposed as pseudos ("shadow
  // pseudos") are never exposed as parts, the rules from a particular scope
  // can only be used for one of the states below.
  enum class MatchingState {
    kDone,
    kShadowPseudo,
    kPart,
    kPartAboveShadowPseudo,
  };

  MatchingState state = MatchingState::kDone;

  // Given an element that we're trying to match, and a scope containing
  // style rules, there is only a single set of part names that can
  // match the element in that scope.  (It doesn't depend on the
  // selector.  It only depends on what parts are exported from each
  // scope to the scope outside it, via either part= or exportparts=.)
  //
  // This does depend on the idea (see above) that the same element can't be
  // exposed as both a UA shadow pseudo and as a part.
  //
  // Present when state is kMatchingPart or kMatchingPartAboveShadowPseudo.
  std::optional<PartNames> current_part_names;

  auto set_part_names = [&current_part_names](const Element* element) -> bool {
    if (DOMTokenList* part = element->GetPart()) {
      if (part->length() && element->IsInShadowTree()) {
        current_part_names.emplace(part->TokenSet());
        return true;
      }
    }
    current_part_names.reset();
    return false;
  };

  bool style_attribute_cascaded_in_parent_scope = false;
  if (set_part_names(&matching_element)) {
    state = MatchingState::kPart;
  } else if (UseParentResolverForUAShadowPseudo(
                 matching_element, &style_attribute_cascaded_in_parent_scope)) {
    state = MatchingState::kShadowPseudo;
  }

  // Consider rules for ::part() and for UA shadow pseudo-elements from scopes
  // outside this tree scope.  Note that :host::part() rules in the element's
  // own scope are considered in MatchElementScopeRules.
  for (const Element* element = matching_element.OwnerShadowHost();
       element && state != MatchingState::kDone;
       element = element->OwnerShadowHost()) {
    // Consider the ::part rules and pseudo-element rules for the given scope.
    TreeScope& tree_scope = element->GetTreeScope();
    if (ScopedStyleResolver* resolver = tree_scope.GetScopedStyleResolver()) {
      // PartRulesScope must be provided with the host where we want to start
      // the search for container query containers.  Since we're not handling
      // :host::part() here, `element` is the correct starting element/host.
      ElementRuleCollector::PartRulesScope scope(
          collector, const_cast<Element&>(*element));
      collector.ClearMatchedRules();
      collector.BeginAddingAuthorRulesForTreeScope(resolver->GetTreeScope());
      if (state == MatchingState::kPart) {
        resolver->CollectMatchingPartPseudoRules(collector,
                                                 &*current_part_names, false);
      } else {
        resolver->CollectMatchingElementScopeRules(
            collector, base::OptionalToPtr(current_part_names));
      }

      collector.SortAndTransferMatchedRules(
          CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker);

      if (style_attribute_cascaded_in_parent_scope) {
        MatchStyleAttribute(matching_element, collector, tracker);
      }
    }

    if (state == MatchingState::kShadowPseudo) {
      CHECK(!current_part_names);
      // The style attribute only goes in the parent scope (in some legacy
      // cases), never higher.
      style_attribute_cascaded_in_parent_scope = false;

      if (set_part_names(element)) {
        state = MatchingState::kPartAboveShadowPseudo;
      } else {
        // For now we only handle shadow pseudos in the parent scope.
        //
        // TODO(https://crbug.com/356158098): In theory this should be an
        // "else if (element->ShadowPseudoId().empty())", since there could be
        // a chain of pseudo-elements in the next scope outside, and we should
        // continue looping when there are more shadow pseudos to match.
        // However, we don't currently parse any such selectors as valid
        // right now, so it seems wasteful to gather rules from the second
        // outer scope (for example, on an element that's conceptually
        // ::-webkit-media-controls-timeline::-webkit-slider-container) when
        // we know none of them will match.
        state = MatchingState::kDone;
      }
    } else {
      CHECK(current_part_names);
      // Subsequent containing tree scopes require mapping part names through
      // @exportparts before considering ::part rules. If no parts are
      // forwarded, the element is now unreachable and we can stop handling
      // ::part() rules.
      if (element->HasPartNamesMap()) {
        current_part_names->PushMap(*element->PartNamesMap());
      } else {
        state = MatchingState::kDone;
      }
    }
  }
}

}  // namespace

void StyleResolver::MatchPseudoPartRulesForUAHost(
    const Element& element,
    ElementRuleCollector& collector) {
  CHECK(!RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled());

  const AtomicString& pseudo_id = element.ShadowPseudoId();
  if (pseudo_id == g_null_atom) {
    return;
  }

  // We allow any pseudo element after ::part(). See
  // MatchSlottedRulesForUAHost for a more detailed explanation.
  Element* shadow_host = element.OwnerShadowHost();
  CHECK(shadow_host);
  MatchPseudoPartRules(*shadow_host, collector, /* for_shadow_pseudo */ true);
}

void StyleResolver::MatchPseudoPartRules(const Element& part_matching_element,
                                         ElementRuleCollector& collector,
                                         bool for_shadow_pseudo) {
  CHECK(!RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled());

  if (!for_shadow_pseudo) {
    MatchPseudoPartRulesForUAHost(part_matching_element, collector);
  }

  DOMTokenList* part = part_matching_element.GetPart();
  if (!part || !part->length() || !part_matching_element.IsInShadowTree()) {
    return;
  }

  PartNames current_names(part->TokenSet());

  // Consider ::part rules in this element’s tree scope or above. Rules in this
  // element’s tree scope will only match if preceded by a :host or :host() that
  // matches one of its containing shadow hosts (see MatchForRelation).
  for (const Element* element = &part_matching_element; element;
       element = element->OwnerShadowHost()) {
    // Consider the ::part rules for the given scope.
    TreeScope& tree_scope = element->GetTreeScope();
    if (ScopedStyleResolver* resolver = tree_scope.GetScopedStyleResolver()) {
      // PartRulesScope must be provided with the host where we want to start
      // the search for container query containers. For the first iteration of
      // this loop, `element` is the `part_matching_element`, but we want to
      // start the search at `part_matching_element`'s host. For subsequent
      // iterations, `element` is the correct starting element/host.
      const Element* host = (element == &part_matching_element)
                                ? element->OwnerShadowHost()
                                : element;
      DCHECK(IsShadowHost(host));
      ElementRuleCollector::PartRulesScope scope(collector,
                                                 const_cast<Element&>(*host));
      collector.ClearMatchedRules();
      collector.BeginAddingAuthorRulesForTreeScope(resolver->GetTreeScope());
      resolver->CollectMatchingPartPseudoRules(collector, &current_names,
                                               for_shadow_pseudo);
      collector.SortAndTransferMatchedRules(
          CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker_);
    }

    // If we have now considered the :host/:host() ::part rules in our own tree
    // scope and the ::part rules in the scope directly above...
    if (element != &part_matching_element) {
      // ...then subsequent containing tree scopes require mapping part names
      // through @exportparts before considering ::part rules. If no parts are
      // forwarded, the element is now unreachable and we can stop.
      if (element->HasPartNamesMap()) {
        current_names.PushMap(*element->PartNamesMap());
      } else {
        return;
      }
    }
  }
}

void StyleResolver::MatchPositionTryRules(ElementRuleCollector& collector) {
  collector.AddTryStyleProperties();
  collector.AddTryTacticsStyleProperties();
}

void StyleResolver::MatchAuthorRules(const Element& element,
                                     ElementRuleCollector& collector) {
  const Element& originating_element =
      UltimateOriginatingElementOrSelf(element);
  MatchHostRules(originating_element, collector, tracker_);
  MatchSlottedRules(originating_element, collector, tracker_);
  MatchElementScopeRules(element, collector, tracker_);
  if (RuntimeEnabledFeatures::CSSCascadeCorrectScopeEnabled()) {
    MatchOuterScopeRules(originating_element, collector, tracker_);
  } else {
    MatchPseudoPartRules(originating_element, collector);
  }
  MatchVTTRules(element, collector, tracker_);
  MatchPositionTryRules(collector);
}

void StyleResolver::MatchUserRules(ElementRuleCollector& collector) {
  collector.ClearMatchedRules();
  GetDocument().GetStyleEngine().CollectMatchingUserRules(collector);
  collector.SortAndTransferMatchedRules(
      CascadeOrigin::kUser, /*is_vtt_embedded_style=*/false, tracker_);
}

namespace {

bool IsInMediaUAShadow(const Element& element) {
  ShadowRoot* root =
      UltimateOriginatingElementOrSelf(element).ContainingShadowRoot();
  if (!root || !root->IsUserAgent()) {
    return false;
  }
  ShadowRoot* outer_root;
  do {
    outer_root = root;
    root = root->host().ContainingShadowRoot();
  } while (root && root->IsUserAgent());
  return outer_root->host().IsMediaElement();
}

}  // namespace

template <typename Functor>
void StyleResolver::ForEachUARulesForElement(const Element& element,
                                             ElementRuleCollector* collector,
                                             Functor& func) const {
  CSSDefaultStyleSheets& default_style_sheets =
      CSSDefaultStyleSheets::Instance();
  if (!print_media_type_) {
    if (element.IsHTMLElement() || element.IsPseudoElement() ||
        element.IsVTTElement()) [[likely]] {
      func(default_style_sheets.DefaultHtmlStyle());
    } else if (element.IsSVGElement()) {
      func(default_style_sheets.DefaultSVGStyle());
    } else if (element.namespaceURI() == mathml_names::kNamespaceURI) {
      func(default_style_sheets.DefaultMathMLStyle());
    }
    if (Fullscreen::HasFullscreenElements()) {
      func(default_style_sheets.DefaultFullscreenStyle());
    }
  } else {
    func(default_style_sheets.DefaultPrintStyle());
  }

  // In quirks mode, we match rules from the quirks user agent sheet.
  if (GetDocument().InQuirksMode()) {
    func(default_style_sheets.DefaultHtmlQuirksStyle());
  }

  // If document uses view source styles (in view source mode or in xml
  // viewer mode), then we match rules from the view source style sheet.
  if (GetDocument().IsViewSource()) {
    func(default_style_sheets.DefaultViewSourceStyle());
  }

  // If the system is in forced colors mode, match rules from the forced colors
  // style sheet.
  if (IsForcedColorsModeEnabled()) {
    func(default_style_sheets.DefaultForcedColorStyle());
  }

  if (GetDocument().IsJSONDocument()) {
    func(default_style_sheets.DefaultJSONDocumentStyle());
  }

  const auto pseudo_id = GetPseudoId(element, collector);
  if (pseudo_id == kPseudoIdNone) {
    return;
  }

  auto* rule_set =
      IsTransitionPseudoElement(pseudo_id)
          ? GetDocument().GetStyleEngine().DefaultViewTransitionStyle()
          : (pseudo_id == kPseudoIdMarker
                 ? default_style_sheets.DefaultPseudoElementStyleOrNull()
                 : nullptr);
  if (rule_set) {
    func(rule_set);
  }
}

void StyleResolver::MatchUARules(const Element& element,
                                 ElementRuleCollector& collector) {
  collector.SetMatchingUARules(true);

  MatchRequest match_request;
  auto func = [&match_request](RuleSet* rules) {
    match_request.AddRuleset(rules);
  };
  ForEachUARulesForElement(element, &collector, func);

  if (!match_request.IsEmpty()) {
    collector.ClearMatchedRules();
    collector.CollectMatchingRules(match_request, /*part_names*/ nullptr);
    collector.SortAndTransferMatchedRules(
        CascadeOrigin::kUserAgent, /*is_vtt_embedded_style=*/false, tracker_);
  }

  if (IsInMediaUAShadow(element)) {
    RuleSet* rule_set =
        IsForcedColorsModeEnabled()
            ? CSSDefaultStyleSheets::Instance()
                  .DefaultForcedColorsMediaControlsStyle()
            : CSSDefaultStyleSheets::Instance().DefaultMediaControlsStyle();
    // Match media controls UA shadow rules in separate UA origin, as they
    // should override UA styles regardless of specificity.
    MatchRequest media_controls_request(rule_set);
    collector.ClearMatchedRules();
    collector.CollectMatchingRules(media_controls_request,
                                   /*part_names*/ nullptr);
    collector.SortAndTransferMatchedRules(
        CascadeOrigin::kUserAgent, /*is_vtt_embedded_style=*/false, tracker_);
  }

  collector.SetMatchingUARules(false);
}

void StyleResolver::MatchPresentationalHints(StyleResolverState& state,
                                             ElementRuleCollector& collector) {
  Element& element = state.GetElement();
  if (element.IsStyledElement() && !state.IsForPseudoElement()) {
    collector.AddElementStyleProperties(
        element.PresentationAttributeStyle(),
        CascadeOrigin::kAuthorPresentationalHint);

    // Now we check additional mapped declarations.
    // Tables and table cells share an additional mapped rule that must be
    // applied after all attributes, since their mapped style depends on the
    // values of multiple attributes.
    collector.AddElementStyleProperties(
        element.AdditionalPresentationAttributeStyle(),
        CascadeOrigin::kAuthorPresentationalHint);

    if (auto* html_element = DynamicTo<HTMLElement>(element)) {
      if (html_element->HasDirectionAuto()) {
        collector.AddElementStyleProperties(
            html_element->CachedDirectionality() == TextDirection::kLtr
                ? LeftToRightDeclaration()
                : RightToLeftDeclaration(),
            CascadeOrigin::kAuthorPresentationalHint);
      }
    }
  }
}

DISABLE_CFI_PERF
void StyleResolver::MatchAllRules(StyleResolverState& state,
                                  ElementRuleCollector& collector,
                                  bool include_smil_properties) {
  Element& element = state.GetElement();
  MatchUARules(element, collector);
  MatchUserRules(collector);

  // Now check author rules, beginning first with presentational attributes
  // mapped from HTML.
  MatchPresentationalHints(state, collector);

  MatchAuthorRules(element, collector);

  if (element.IsStyledElement() && !state.IsForPseudoElement()) {
    collector.BeginAddingAuthorRulesForTreeScope(element.GetTreeScope());
    // Now check SMIL animation override style.
    auto* svg_element = DynamicTo<SVGElement>(element);
    if (include_smil_properties && svg_element) {
      collector.AddElementStyleProperties(
          svg_element->AnimatedSMILStyleProperties(), CascadeOrigin::kAuthor,
          false /* isCacheable */);
    }
  }
}

const ComputedStyle* StyleResolver::StyleForViewport() {
  ComputedStyleBuilder builder = InitialStyleBuilderForElement();

  builder.SetZIndex(0);
  builder.SetForcesStackingContext(true);
  builder.SetDisplay(EDisplay::kBlock);
  builder.SetPosition(EPosition::kAbsolute);

  // Document::InheritHtmlAndBodyElementStyles will set the final overflow
  // style values, but they should initially be auto to avoid premature
  // scrollbar removal in PaintLayerScrollableArea::UpdateAfterStyleChange.
  builder.SetOverflowX(EOverflow::kAuto);
  builder.SetOverflowY(EOverflow::kAuto);

  GetDocument().GetStyleEngine().ApplyVisionDeficiencyStyle(builder);

  return builder.TakeStyle();
}

static StyleBaseData* GetBaseData(const StyleResolverState& state) {
  Element* animating_element = state.GetAnimatingElement();
  if (!animating_element) {
    return nullptr;
  }
  auto* old_style = animating_element->GetComputedStyle();
  return old_style ? old_style->BaseData() : nullptr;
}

static const ComputedStyle* CachedAnimationBaseComputedStyle(
    StyleResolverState& state) {
  if (auto* base_data = GetBaseData(state)) {
    return base_data->GetBaseComputedStyle();
  }
  return nullptr;
}

static void IncrementResolvedStyleCounters(const StyleRequest& style_request,
                                           Document& document) {
  document.GetStyleEngine().IncStyleForElementCount();

  if (style_request.IsPseudoStyleRequest()) {
    INCREMENT_STYLE_STATS_COUNTER(document.GetStyleEngine(),
                                  pseudo_elements_styled, 1);
  } else {
    INCREMENT_STYLE_STATS_COUNTER(document.GetStyleEngine(), elements_styled,
                                  1);
  }
}

// This is the core of computing style for a given element, ie., first compute
// base style and then apply animation style. (Not all elements needing style
// recalc ever hit ResolveStyle(); e.g., the “independent inherited properties
// optimization” can cause it to be skipped.)
//
// Generally, when an element is marked for style recalc, we do not reuse any
// style from previous computations, but re-compute from scratch every time.
// However: If possible, we compute base style only once and cache it, and then
// just apply animation style on top of the cached base style. This is because
// it's a common situation that elements have an unchanging base and then some
// independent animation properties that change every frame and don't affect
// any other properties or elements. (The exceptions can be found in
// CanReuseBaseComputedStyle().) This is known as the “base computed style
// optimization”.
const ComputedStyle* StyleResolver::ResolveStyle(
    Element* element,
    const StyleRecalcContext& style_recalc_context,
    const StyleRequest& style_request) {
  if (!element) {
    DCHECK(style_request.IsPseudoStyleRequest());
    return nullptr;
  }

  DCHECK(GetDocument().GetFrame());
  DCHECK(GetDocument().GetSettings());

  SelectorFilterParentScope::EnsureParentStackIsPushed();

  // The StyleResolverState is where we actually end up accumulating the
  // computed style. It's just a convenient way of not having to send
  // a lot of input/output variables around between the different functions.
  StyleResolverState state(GetDocument(), *element, &style_recalc_context,
                           style_request);

  STACK_UNINITIALIZED StyleCascade cascade(state);

  // Compute the base style, or reuse an existing cached base style if
  // applicable (ie., only animation has changed). This is the bulk of the
  // style computation itself, also where the caching for the base
  // computed style optimization happens.
  ApplyBaseStyle(element, style_recalc_context, style_request, state, cascade);

  if (style_recalc_context.is_ensuring_style) {
    state.StyleBuilder().SetIsEnsuredInDisplayNone();
  }

  if ((element->IsPseudoElement() || style_request.IsPseudoStyleRequest()) &&
      state.HadNoMatchedProperties()) {
    DCHECK(!cascade.InlineStyleLost());
    return state.TakeStyle();
  }

  if (ApplyAnimatedStyle(state, cascade)) {
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  styles_animated, 1);
    StyleAdjuster::AdjustComputedStyle(
        state,
        (element->IsPseudoElement() || style_request.IsPseudoStyleRequest())
            ? nullptr
            : element);
  }

  ApplyAnchorData(state);

  IncrementResolvedStyleCounters(style_request, GetDocument());

  if (!style_request.IsPseudoStyleRequest()) {
    if (IsA<HTMLBodyElement>(*element)) {
      GetDocument().GetTextLinkColors().SetTextColor(
          state.StyleBuilder().GetCurrentColor());
    }

    if (IsA<MathMLElement>(element)) {
      ApplyMathMLCustomStyleProperties(element, state);
    }
  } else if (IsHighlightPseudoElement(style_request.pseudo_id)) {
    if (element->GetComputedStyle() &&
        element->GetComputedStyle()->TextShadow() !=
            state.StyleBuilder().TextShadow()) {
      // This counts the usage of text-shadow in CSS highlight pseudos.
      UseCounter::Count(GetDocument(),
                        WebFeature::kTextShadowInHighlightPseudo);
      if (state.StyleBuilder().TextShadow()) {
        // This counts the cases in which text-shadow is not "none" in CSS
        // highlight pseudos, as the most common use case is using it to disable
        // text-shadow, and that won't be need once some painting issues related
        // to highlight pseudos are fixed.
        UseCounter::Count(GetDocument(),
                          WebFeature::kTextShadowNotNoneInHighlightPseudo);
      }
    }
  }

  if (Element* animating_element = state.GetAnimatingElement()) {
    SetAnimationUpdateIfNeeded(style_recalc_context, state, *animating_element);
  }

  GetDocument().AddViewportUnitFlags(state.StyleBuilder().ViewportUnitFlags());

  if (state.StyleBuilder().HasRootFontRelativeUnits()) {
    GetDocument().GetStyleEngine().SetUsesRootFontRelativeUnits(true);
  }

  if (state.StyleBuilder().HasGlyphRelativeUnits()) {
    GetDocument().GetStyleEngine().SetUsesGlyphRelativeUnits(true);
    UseCounter::Count(GetDocument(), WebFeature::kHasGlyphRelativeUnits);
  }

  if (state.StyleBuilder().HasLineHeightRelativeUnits()) {
    GetDocument().GetStyleEngine().SetUsesLineHeightUnits(true);
  }

  state.LoadPendingResources();

  // Now return the style.
  return state.TakeStyle();
}

void StyleResolver::InitStyle(Element& element,
                              const StyleRequest& style_request,
                              const ComputedStyle& source_for_noninherited,
                              const ComputedStyle* parent_style,
                              StyleResolverState& state) {
  if (state.UsesHighlightPseudoInheritance()) {
    // When resolving highlight styles for children, we need to default all
    // properties (whether or not defined as inherited) to parent values.

    // Sadly, ComputedStyle creation is unavoidable until ElementRuleCollector
    // and friends stop relying on ComputedStyle mutation. The good news is that
    // if the element has no rules for this highlight pseudo, we skip resolution
    // entirely (leaving the scoped_refptr untouched). The bad news is that if
    // the element has rules but no matched properties, we currently clone.
    state.SetStyle(*parent_style);

    // Highlight Pseudos do not support custom properties defined on the
    // pseudo itself. They may use var() references but those must be resolved
    // against the originating element. Share the variables from the originating
    // style.
    state.StyleBuilder().CopyInheritedVariablesFrom(
        state.OriginatingElementStyle());
    state.StyleBuilder().CopyNonInheritedVariablesFrom(
        state.OriginatingElementStyle());
  } else {
    state.CreateNewStyle(
        source_for_noninherited, *parent_style,
        (!style_request.IsPseudoStyleRequest() && IsAtShadowBoundary(&element))
            ? ComputedStyleBuilder::kAtShadowBoundary
            : ComputedStyleBuilder::kNotAtShadowBoundary);

    // contenteditable attribute (implemented by -webkit-user-modify) should
    // be propagated from shadow host to distributed node.
    if (!element.IsPseudoElement() && !style_request.IsPseudoStyleRequest() &&
        element.AssignedSlot()) {
      if (Element* parent = element.parentElement()) {
        if (!RuntimeEnabledFeatures::
                InheritUserModifyWithoutContenteditableEnabled() ||
            !element.FastHasAttribute(html_names::kContenteditableAttr)) {
          if (const ComputedStyle* shadow_host_style =
                  parent->GetComputedStyle()) {
            state.StyleBuilder().SetUserModify(shadow_host_style->UserModify());
          }
        }
      }
    }
  }
  if (element.IsPseudoElement()) {
    state.StyleBuilder().SetStyleType(element.GetPseudoIdForStyling());
  } else {
    state.StyleBuilder().SetStyleType(style_request.pseudo_id);
  }
  state.StyleBuilder().SetPseudoArgument(style_request.pseudo_argument);

  // For highlight inheritance, propagate link visitedness, forced-colors
  // status, the font and the line height from the originating element. The
  // font and line height are necessary to correctly resolve font relative
  // units.
  if (state.UsesHighlightPseudoInheritance()) {
    state.StyleBuilder().SetInForcedColorsMode(
        style_request.originating_element_style->InForcedColorsMode());
    state.StyleBuilder().SetForcedColorAdjust(
        style_request.originating_element_style->ForcedColorAdjust());
    state.StyleBuilder().SetFont(
        style_request.originating_element_style->GetFont());
    state.StyleBuilder().SetLineHeight(
        style_request.originating_element_style->LineHeight());
    state.StyleBuilder().SetWritingMode(
        style_request.originating_element_style->GetWritingMode());
  }

  if (!style_request.IsPseudoStyleRequest() && element.IsLink()) {
    state.StyleBuilder().SetIsLink();
  }

  if (!style_request.IsPseudoStyleRequest()) {
    // Preserve the text autosizing multiplier on style recalc. Autosizer will
    // update it during layout if needed.
    // NOTE: This must occur before CascadeAndApplyMatchedProperties for correct
    // computation of font-relative lengths.
    // NOTE: This can never be overwritten by a MPC hit, since we don't use the
    // MPC if TextAutosizingMultiplier() is different from 1.
    state.StyleBuilder().SetTextAutosizingMultiplier(
        state.TextAutosizingMultiplier());
  }
}

void StyleResolver::ApplyMathMLCustomStyleProperties(
    Element* element,
    StyleResolverState& state) {
  DCHECK(IsA<MathMLElement>(element));
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (auto* space = DynamicTo<MathMLSpaceElement>(*element)) {
    space->AddMathBaselineIfNeeded(builder, state.CssToLengthConversionData());
  } else if (auto* padded = DynamicTo<MathMLPaddedElement>(*element)) {
    padded->AddMathBaselineIfNeeded(builder, state.CssToLengthConversionData());
    padded->AddMathPaddedDepthIfNeeded(builder,
                                       state.CssToLengthConversionData());
    padded->AddMathPaddedLSpaceIfNeeded(builder,
                                        state.CssToLengthConversionData());
    padded->AddMathPaddedVOffsetIfNeeded(builder,
                                         state.CssToLengthConversionData());
  } else if (auto* fraction = DynamicTo<MathMLFractionElement>(*element)) {
    fraction->AddMathFractionBarThicknessIfNeeded(
        builder, state.CssToLengthConversionData());
  } else if (auto* operator_element =
                 DynamicTo<MathMLOperatorElement>(*element)) {
    operator_element->AddMathLSpaceIfNeeded(builder,
                                            state.CssToLengthConversionData());
    operator_element->AddMathRSpaceIfNeeded(builder,
                                            state.CssToLengthConversionData());
    operator_element->AddMathMinSizeIfNeeded(builder,
                                             state.CssToLengthConversionData());
    operator_element->AddMathMaxSizeIfNeeded(builder,
                                             state.CssToLengthConversionData());
  }
}

bool CanApplyInlineStyleIncrementally(Element* element,
                                      const StyleResolverState& state,
                                      const StyleRequest& style_request) {
  // If non-independent properties are modified, we need to do a full
  // recomputation; otherwise, the properties we're setting could affect
  // the interpretation of other properties (e.g. if a script is setting
  // el.style.fontSize = "24px", that could affect the interpretation
  // of "border-width: 0.2em", but our incremental style recalculation
  // won't update border width).
  //
  // This also covers the case where the inline style got new or removed
  // existing property declarations. We cannot say easily how that would
  // affect the cascade, so we do a full recalculation in that case.
  if (element->GetStyleChangeType() != kInlineIndependentStyleChange) {
    return false;
  }

  // We must, obviously, have an existing style to do incremental calculation.
  if (!element->GetComputedStyle()) {
    return false;
  }

  // Pseudo-elements can't have inline styles. We also don't have the old
  // style in this situation (|element| is the originating element in in
  // this case, so using that style would be wrong).
  if (style_request.IsPseudoStyleRequest()) {
    return false;
  }

  // Links have special handling of visited/not-visited colors (they are
  // represe
"""


```