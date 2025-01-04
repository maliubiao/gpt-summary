Response:
My thought process for analyzing the `StyleResolver::ApplyBaseStyle` function in `style_resolver.cc` goes like this:

1. **Understand the Core Function:** The name `ApplyBaseStyle` strongly suggests this function's primary role is to compute the "base" style of an element. The comment confirms this, stating it calculates style excluding animations.

2. **Identify the Key Steps:** The comment within `ApplyBaseStyleNoCache` outlines the standard flow:
    * Collect applicable CSS rules.
    * Determine parent and initial styles.
    * Construct a `ComputedStyle` by merging parent and initial styles.
    * Apply the collected CSS rule properties.

3. **Look for Optimizations/Special Cases:** The comment in `ApplyBaseStyle` mentions "computed base style optimization" and "incremental inline style updates."  This immediately tells me there are scenarios where the full recalculation is avoided for performance.

4. **Analyze the Code for Optimizations:**
    * **`CanReuseBaseComputedStyle`:** This suggests a caching mechanism. The code checks this condition and uses `CachedAnimationBaseComputedStyle` if true, reusing a previously calculated style. The surrounding `#if DCHECK_IS_ON()` block is for debugging, comparing the optimized result with a full recalculation.
    * **`CanApplyInlineStyleIncrementally`:** This indicates another optimization for inline style changes. If this condition is met, the code takes the *existing* `ComputedStyle` and applies the element's inline styles on top, avoiding full cascade resolution. The code iterating through `element->InlineStyle()` confirms this.

5. **Connect to CSS Concepts:**
    * **Cascading:**  The core functionality deals with applying CSS rules based on specificity and origin, which is the essence of the CSS cascade.
    * **Inheritance:** The use of `parent_style` directly relates to CSS inheritance.
    * **Initial Values:** `InitialStyleForElement()` represents the initial values defined by CSS.
    * **Inline Styles:** The incremental update focuses specifically on `<element style="...">`.
    * **Animations:** The "base" style explicitly excludes animations, indicating a separation of concerns.

6. **Infer Relationships to HTML and JavaScript:**
    * **HTML:** The function operates on `Element` objects, which are direct representations of HTML elements in the DOM.
    * **JavaScript:**  The incremental inline style update is a prime example of interaction with JavaScript. JavaScript frequently modifies inline styles to achieve dynamic effects.

7. **Consider User/Developer Errors:** The conditions in `CanApplyInlineStyleIncrementally` hint at potential pitfalls:
    * Modifying non-idempotent inline styles.
    * Using CSS variables or `revert` within inline styles in scenarios where incremental updates are attempted. These require the full cascade.

8. **Trace User Actions (Debugging Clues):** The incremental style optimization is triggered by changes to inline styles. A typical user action leading here would be a JavaScript interaction that directly modifies an element's `style` attribute.

9. **Synthesize and Summarize:** Combine the observations into a concise description of the function's purpose, its relation to web technologies, optimizations, potential errors, and debugging clues.

10. **Address the "Part 3" Request:** Explicitly state that this section focuses on the core style application logic and its optimizations.

By following this thought process, I can systematically dissect the code, understand its purpose, and explain its significance within the larger context of a browser engine. The key is to identify the core functionality, look for deviations and optimizations, and connect these back to fundamental web development concepts and potential user interactions.
这是对Chromium Blink引擎源代码文件 `blink/renderer/core/css/resolver/style_resolver.cc` 的第3部分分析，专注于 `StyleResolver::ApplyBaseStyle` 函数的功能。

**`StyleResolver::ApplyBaseStyle` 的功能归纳:**

`StyleResolver::ApplyBaseStyle` 函数是计算元素基础样式（base style）的核心入口点。基础样式指的是不依赖于 CSS 动画影响的样式。它的主要职责是：

1. **确定元素的最终基础样式**：它综合考虑了从父元素继承的样式、CSS 默认值（initial style）以及应用于当前元素的 CSS 规则。
2. **应用各种优化策略以提高性能**：
    * **基础计算样式缓存重用 (Base Computed Style Optimization):** 如果检测到可以重用之前计算的基础样式（例如，在动画的每一帧，如果只有动画相关的属性发生变化），则直接使用缓存，避免重复计算。
    * **增量内联样式更新 (Incremental Inline Style Updates):** 如果只有元素的内联样式发生了改变，并且满足某些条件（例如，修改的属性是幂等的，不涉及 CSS 变量等），则可以在现有的计算样式基础上直接应用内联样式，无需重新执行完整的样式计算流程。
3. **协调完整的样式计算流程 (如果无法优化):** 如果无法使用缓存或增量更新，则调用 `ApplyBaseStyleNoCache` 函数来执行完整的样式计算。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS:** `ApplyBaseStyle` 的核心功能是解析和应用 CSS 规则。它处理 CSS 属性的层叠 (cascade)、继承 (inheritance) 和优先级。
    * **举例:** 当 CSS 规则 `.my-class { color: blue; }` 应用到一个 HTML 元素 `<div class="my-class"></div>` 时，`ApplyBaseStyle` 会识别这个规则并将其 `color` 属性的值（`blue`）应用到该元素的样式中。
* **HTML:** 该函数操作的是 HTML 元素 (`Element* element`)，根据元素的标签名、类名、ID 等信息匹配 CSS 规则。
    * **举例:**  `ApplyBaseStyle` 会根据 HTML 元素的 `class` 属性值来查找匹配的 CSS 类选择器，并将相应的样式应用到元素。
* **JavaScript:** JavaScript 可以通过修改元素的内联样式来动态改变元素的视觉呈现。`ApplyBaseStyle` 中的增量内联样式更新就是为了优化这种场景。
    * **举例:**  JavaScript 代码 `element.style.backgroundColor = 'red';` 会直接修改元素的内联 `background-color` 属性。如果满足增量更新的条件，`ApplyBaseStyle` 可以高效地将这个内联样式变化应用到元素的样式上，而不需要重新计算所有应用的 CSS 规则。

**逻辑推理 (假设输入与输出):**

假设输入：

* **`element`**: 一个 HTML `<div>` 元素，`class="example"`，内联样式 `style="font-size: 16px;"`。
* **`state`**: 包含父元素计算样式信息的 `StyleResolverState` 对象。
* **`style_recalc_context`**:  指示可以进行增量样式计算。

**场景 1：可以应用增量内联样式更新**

* **假设条件:**  之前已经计算过该元素的样式，并且只有内联 `font-size` 属性发生了改变，且 `font-size` 是幂等的。
* **输出:**  `state` 中元素的计算样式会被更新，`font-size` 的值会被设置为 `16px`，但不会重新执行完整的 CSS 规则匹配和层叠过程。

**场景 2：无法应用增量内联样式更新**

* **假设条件:**  元素的内联样式中包含 `var(--my-variable)`，这是一个 CSS 变量。
* **输出:**  `ApplyBaseStyle` 会调用 `ApplyBaseStyleNoCache`，执行完整的 CSS 规则匹配和层叠过程来解析 CSS 变量。

**用户或编程常见的使用错误及举例说明:**

* **在尝试增量更新时修改非幂等属性:** 某些 CSS 属性在多次应用时可能会产生不同的结果。例如，修改带有计数器的自定义属性。如果在尝试增量更新时修改了这类属性，可能会导致样式计算错误。
    * **举例:**  假设 CSS 中定义了 counter，然后通过 JavaScript 修改了内联样式中与 counter 相关的属性，此时如果尝试进行增量更新，可能会得到不期望的 counter 值。
* **在尝试增量更新时使用 CSS 变量或 `revert` 等复杂值:**  这些值需要在完整的层叠上下文中解析。如果在内联样式中使用了这些值，就无法进行简单的增量更新。
    * **举例:**  如果一个元素的内联样式是 `style="color: var(--main-color);"`, 当 `--main-color` 变量的值发生变化时，需要重新进行完整的样式计算才能正确更新元素的颜色。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个网页:**  浏览器开始解析 HTML、CSS，并构建 DOM 树和渲染树。
2. **CSS 引擎开始工作:**  对于 DOM 树中的每个元素，都需要计算其最终的样式。
3. **触发样式计算:**  可能是初始加载、动态修改 CSS 规则、JavaScript 修改元素样式、或者元素状态变化（例如 `:hover` 伪类激活）。
4. **调用 `StyleResolver::ResolveStyle`:**  这是样式解析的入口点。
5. **`StyleResolver::ResolveStyle` 调用 `ApplyBaseStyle`:**  在计算元素的基础样式阶段，会调用 `ApplyBaseStyle`。
6. **`ApplyBaseStyle` 根据情况选择优化策略:**  如果满足条件，则进行缓存重用或增量更新；否则，调用 `ApplyBaseStyleNoCache` 进行完整的样式计算。

**作为调试线索，了解 `ApplyBaseStyle` 的行为可以帮助开发者理解以下问题:**

* **为什么我的样式更新没有生效？** 可能因为增量更新的条件没有满足，或者存在更高优先级的样式覆盖。
* **为什么我的页面在某些操作后出现性能问题？** 可能因为频繁的样式修改导致无法进行有效的缓存或增量更新，需要进行大量的样式重计算。
* **为什么内联样式修改后，某些看似无关的样式也发生了变化？** 可能因为内联样式的修改触发了完整的样式重计算，导致其他 CSS 规则重新生效。

总而言之，`StyleResolver::ApplyBaseStyle` 是 Blink 引擎中负责高效计算元素基础样式的关键函数，它通过优化策略来提升性能，并在必要时执行完整的样式计算流程。理解其工作原理对于进行 Web 性能优化和调试样式问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
nted using special -internal-* properties), which happens
  // during expansion of the CSS cascade. Since incremental style doesn't
  // replicate this behavior, we don't try to compute incremental style
  // for anything that is a link or inside a link.
  if (element->GetComputedStyle()->InsideLink() !=
      EInsideLink::kNotInsideLink) {
    return false;
  }

  // If in the existing style, any inline property _lost_ the cascade
  // (e.g. to an !important class declaration), modifying the ComputedStyle
  // directly may be wrong. This is rare, so we can just skip those cases.
  if (element->GetComputedStyle()->InlineStyleLostCascade()) {
    return false;
  }

  // Custom style callbacks can do style adjustment after style resolution.
  if (element->HasCustomStyleCallbacks()) {
    return false;
  }

  // We don't bother with the root element; it's a special case.
  if (!state.ParentStyle()) {
    return false;
  }

  // We don't currently support combining incremental style and the
  // base computed style animation; we'd have to apply the incremental
  // style onto the base as opposed to the computed style itself,
  // and we don't support that. It should be rare to animate elements
  // _both_ with animations and mutating inline style anyway.
  if (GetElementAnimations(state) || element->GetComputedStyle()->BaseData()) {
    return false;
  }

  // ComputedStyles produced by OOF-interleaving (StyleEngine::
  // UpdateStyleForOutOfFlow) have this flag set. We can not apply the style
  // incrementally on top of this, because ComputedStyles produced by normal
  // style recalcs should not have this flag.
  if (element->GetComputedStyle()->HasAnchorEvaluator()) {
    return false;
  }

  const CSSPropertyValueSet* inline_style = element->InlineStyle();
  if (inline_style) {
    int num_properties = inline_style->PropertyCount();
    for (int property_idx = 0; property_idx < num_properties; ++property_idx) {
      CSSPropertyValueSet::PropertyReference property =
          inline_style->PropertyAt(property_idx);

      // If a script mutated inline style properties that are not idempotent,
      // we would not normally even reach this path (we wouldn't get a changed
      // signal saying “inline incremental style modified”, just “style
      // modified”). However, we could have such properties set on inline style
      // _before_ this calculation, and their continued existence blocks us from
      // reusing the style (because e.g. the StyleAdjuster is not necessarily
      // idempotent in such cases).
      if (!CSSProperty::Get(property.Id()).IsIdempotent()) {
        return false;
      }

      // Variables and reverts are resolved in StyleCascade, which we don't run
      // in this path; thus, we cannot support them.
      if (property.Value().IsUnparsedDeclaration() ||
          property.Value().IsPendingSubstitutionValue() ||
          property.Value().IsRevertValue() ||
          property.Value().IsRevertLayerValue()) {
        return false;
      }
    }
  }

  return true;
}

// This is the core of computing base style for a given element, ie., the style
// that does not depend on animations. For our purposes, style consists of three
// parts:
//
//  A. Properties inherited from the parent (parent style).
//  B. Properties that come from the defaults (initial style).
//  C. Properties from CSS rules that apply from this element
//     (matched properties).
//
// The typical flow (barring special rules for pseudo-elements and similar) is:
//
//   1. Collect all CSS rules that apply to this element
//      (MatchAllRules(), into ElementRuleCollector).
//   2. Figure out where we should get parent style (A) from, and where we
//      should get initial style (B) from; typically the parent element and
//      the global initial style, respectively.
//   3. Construct a new ComputedStyle, merging the two sources (InitStyle()).
//   4. Apply all the found properties (C) in the correct order
//      (ApplyPropertiesFromCascade(), using StyleCascade).
//
// However, the MatchedPropertiesCache can often give us A with the correct
// parts of C pre-applied, or similar for B+C, or simply A+B+C (a full MPC hit).
// Thus, after step 1, we look up the set of properties we've collected in the
// MPC, and if we have a full MPC hit, we stop after step 1. (This is the reason
// why step 1 needs to be first.) If we have a partial hit (we can use A+C
// but not B+C, or the other way around), we use that as one of our sources
// in step 3, and can skip the relevant properties in step 4.
//
// The base style is cached by the caller if possible (see ResolveStyle() on
// the “base computed style optimization”).
void StyleResolver::ApplyBaseStyleNoCache(
    Element* element,
    const StyleRecalcContext& style_recalc_context,
    const StyleRequest& style_request,
    StyleResolverState& state,
    StyleCascade& cascade) {
  // For some very special elements (e.g. <video>): Ensure internal UA style
  // rules that are relevant for the element exist in the stylesheet.
  GetDocument().GetStyleEngine().EnsureUAStyleForElement(*element);

  if (!style_request.IsPseudoStyleRequest()) {
    if (IsForcedColorsModeEnabled()) {
      cascade.MutableMatchResult().AddMatchedProperties(
          ForcedColorsUserAgentDeclarations(),
          {.origin = CascadeOrigin::kUserAgent});
    }

    // UA rule: * { overlay: none !important }
    // and
    // UA rule: ::scroll-marker-group { contain: size !important; }
    // Implemented here because DCHECKs ensures we don't add universal rules to
    // the UA sheets. Note that this is a universal rule in any namespace.
    // Adding this to the html.css would only do the override in the HTML
    // namespace since the sheet has a default namespace.
    cascade.MutableMatchResult().AddMatchedProperties(
        UniversalOverlayUserAgentDeclaration(),
        {.origin = CascadeOrigin::kUserAgent});

    // This adds a CSSInitialColorValue to the cascade for the document
    // element. The CSSInitialColorValue will resolve to a color-scheme
    // sensitive color in Color::ApplyValue. It is added at the start of the
    // MatchResult such that subsequent declarations (even from the UA sheet)
    // get a higher priority.
    //
    // TODO(crbug.com/1046753): Remove this when canvastext is supported.
    if (element == state.GetDocument().documentElement()) {
      cascade.MutableMatchResult().AddMatchedProperties(
          DocumentElementUserAgentDeclarations(),
          {.origin = CascadeOrigin::kUserAgent});
    }
  }

  ElementRuleCollector collector(state.ElementContext(), style_recalc_context,
                                 selector_filter_, cascade.MutableMatchResult(),
                                 state.InsideLink());

  if (element->IsPseudoElement() || style_request.IsPseudoStyleRequest()) {
    if (element->IsScrollMarkerGroupPseudoElement() ||
        style_request.pseudo_id == kPseudoIdScrollMarkerGroup) {
      cascade.MutableMatchResult().AddMatchedProperties(
          ScrollMarkerGroupUserAgentDeclaration(),
          {.origin = CascadeOrigin::kUserAgent});
    }

    collector.SetPseudoElementStyleRequest(style_request);
    if (element->IsPseudoElement()) {
      GetDocument().GetStyleEngine().EnsureUAStyleForPseudoElement(
          element->GetPseudoIdForStyling());
    } else {
      GetDocument().GetStyleEngine().EnsureUAStyleForPseudoElement(
          style_request.pseudo_id);
    }
  }

  if (!state.ParentStyle()) {
    // We have no parent so use the initial style as the parent. Note that we
    // need to do this before MPC lookup, so that the parent comparison (to
    // determine if we have a hit on inherited properties) is correctly
    // determined.
    state.SetParentStyle(InitialStyleForElement());
    state.SetLayoutParentStyle(state.ParentStyle());

    if (!style_request.IsPseudoStyleRequest() &&
        *element != GetDocument().documentElement()) {
      // Strictly, we should only allow the root element to inherit from
      // initial styles, but we allow getComputedStyle() for connected
      // elements outside the flat tree rooted at an unassigned shadow host
      // child or a slot fallback element.
      DCHECK((IsShadowHost(element->parentNode()) ||
              IsA<HTMLSlotElement>(element->parentNode())) &&
             !LayoutTreeBuilderTraversal::ParentElement(*element));
    }
  }

  if (style_request.rules_to_include == StyleRequest::kUAOnly) {
    MatchUARules(*element, collector);
  } else {
    MatchAllRules(
        state, collector,
        style_request.matching_behavior != kMatchAllRulesExcludingSMIL);
  }

  const MatchResult& match_result = collector.MatchedResult();

  if (element->IsPseudoElement() || style_request.IsPseudoStyleRequest()) {
    if (!match_result.HasMatchedProperties()) {
      InitStyle(*element, style_request, *initial_style_, state.ParentStyle(),
                state);
      StyleAdjuster::AdjustComputedStyle(state, nullptr /* element */);
      state.SetHadNoMatchedProperties();
      return;
    }
  }

  const MatchResult& result = cascade.GetMatchResult();
  CacheSuccess cache_success = ApplyMatchedCache(state, style_request, result);
  ComputedStyleBuilder& builder = state.StyleBuilder();

  if (style_recalc_context.is_ensuring_style &&
      style_recalc_context.is_outside_flat_tree) {
    builder.SetIsEnsuredOutsideFlatTree();
  }

  if (!cache_success.IsHit()) {
    ApplyPropertiesFromCascade(state, cascade);
    MaybeAddToMatchedPropertiesCache(state, cache_success.key);
  }

  // TODO(crbug.com/1024156): do this for CustomHighlightNames too, so we
  // can remove the cache-busting for ::highlight() in IsStyleCacheable
  builder.SetHasNonUniversalHighlightPseudoStyles(
      match_result.HasNonUniversalHighlightPseudoStyles());
  builder.SetHasNonUaHighlightPseudoStyles(
      match_result.HasNonUaHighlightPseudoStyles());
  builder.SetHighlightsDependOnSizeContainerQueries(
      match_result.HighlightsDependOnSizeContainerQueries());

  if (match_result.HasFlag(MatchFlag::kAffectedByDrag)) {
    builder.SetAffectedByDrag();
  }
  if (match_result.HasFlag(MatchFlag::kAffectedByFocusWithin)) {
    builder.SetAffectedByFocusWithin();
  }
  if (match_result.HasFlag(MatchFlag::kAffectedByHover)) {
    builder.SetAffectedByHover();
  }
  if (match_result.HasFlag(MatchFlag::kAffectedByActive)) {
    builder.SetAffectedByActive();
  }
  if (match_result.HasFlag(MatchFlag::kAffectedByStartingStyle)) {
    builder.SetIsStartingStyle();
  }
  if (match_result.DependsOnSizeContainerQueries()) {
    builder.SetDependsOnSizeContainerQueries(true);
  }
  if (match_result.DependsOnStyleContainerQueries()) {
    builder.SetDependsOnStyleContainerQueries(true);
  }
  if (match_result.DependsOnScrollStateContainerQueries()) {
    builder.SetDependsOnScrollStateContainerQueries(true);
  }
  if (match_result.FirstLineDependsOnSizeContainerQueries()) {
    builder.SetFirstLineDependsOnSizeContainerQueries(true);
  }
  if (match_result.DependsOnStaticViewportUnits()) {
    builder.SetHasStaticViewportUnits();
  }
  if (match_result.DependsOnDynamicViewportUnits()) {
    builder.SetHasDynamicViewportUnits();
  }
  if (match_result.DependsOnRootFontContainerQueries()) {
    builder.SetHasRootFontRelativeUnits();
  }
  if (match_result.ConditionallyAffectsAnimations()) {
    state.SetConditionallyAffectsAnimations();
  }
  if (!match_result.CustomHighlightNames().empty()) {
    builder.SetCustomHighlightNames(match_result.CustomHighlightNames());
  }
  builder.SetPseudoElementStyles(match_result.PseudoElementStyles());

  if (element->IsPseudoElement()) {
    state.StyleBuilder().SetStyleType(element->GetPseudoIdForStyling());
  }

  // Now we're done with all operations that may overwrite InsideLink,
  // so we can set it once and for all.
  builder.SetInsideLink(state.InsideLink());

  ApplyCallbackSelectors(state);
  if (element->IsLink() && (element->HasTagName(html_names::kATag) ||
                            element->HasTagName(html_names::kAreaTag))) {
    ApplyDocumentRulesSelectors(state, To<ContainerNode>(&element->TreeRoot()));
  }

  // Cache our if our original display is inline.
  builder.SetIsOriginalDisplayInlineType(
      ComputedStyle::IsDisplayInlineType(builder.Display()));

  StyleAdjuster::AdjustComputedStyle(
      state, style_request.IsPseudoStyleRequest() ? nullptr : element);

  ApplyAnchorData(state);
}

// In the normal case, just a forwarder to ApplyBaseStyleNoCache(); see that
// function for the meat of the computation. However, this is where the
// “computed base style optimization” is applied if possible, and also
// incremental inline style updates:
//
// If we have an existing computed style, and the only changes have been
// mutations of independent properties on the element's inline style
// (see CanApplyInlineStyleIncrementally() for the precise conditions),
// we may reuse the old computed style and just reapply the element's
// inline style on top of it. This allows us to skip collecting elements
// and computing the full cascade, which can be a significant win when
// animating elements via inline style from JavaScript.
void StyleResolver::ApplyBaseStyle(
    Element* element,
    const StyleRecalcContext& style_recalc_context,
    const StyleRequest& style_request,
    StyleResolverState& state,
    StyleCascade& cascade) {
  DCHECK(style_request.pseudo_id != kPseudoIdFirstLineInherited);

  if (state.CanTriggerAnimations() && CanReuseBaseComputedStyle(state)) {
    const ComputedStyle* animation_base_computed_style =
        CachedAnimationBaseComputedStyle(state);
    DCHECK(animation_base_computed_style);
#if DCHECK_IS_ON()
    // The invariant in the base computed style optimization is that as long as
    // |IsAnimationStyleChange| is true, the computed style that would be
    // generated by the style resolver is equivalent to the one we hold
    // internally. To ensure this, we always compute a new style here
    // disregarding the fact that we have a base computed style when DCHECKs are
    // enabled, and call ComputeBaseComputedStyleDiff() to check that the
    // optimization was sound.
    ApplyBaseStyleNoCache(element, style_recalc_context, style_request, state,
                          cascade);
    const ComputedStyle* style_snapshot = state.StyleBuilder().CloneStyle();
    DCHECK_EQ(g_null_atom, ComputeBaseComputedStyleDiff(
                               animation_base_computed_style, *style_snapshot));
#endif

    state.SetStyle(*animation_base_computed_style);
    state.StyleBuilder().SetBaseData(GetBaseData(state));
    if (element->IsPseudoElement()) {
      state.StyleBuilder().SetStyleType(element->GetPseudoIdForStyling());
    } else {
      state.StyleBuilder().SetStyleType(style_request.pseudo_id);
    }
    if (!state.ParentStyle()) {
      state.SetParentStyle(InitialStyleForElement());
      state.SetLayoutParentStyle(state.ParentStyle());
    }
    MaybeResetCascade(cascade);
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  base_styles_used, 1);
    return;
  }

  if (style_recalc_context.can_use_incremental_style &&
      CanApplyInlineStyleIncrementally(element, state, style_request)) {
    // We are in a situation where we can reuse the old style
    // and just apply the element's inline style on top of it
    // (see the function comment).
    state.SetStyle(*element->GetComputedStyle());

    // This is always false when creating a new style, but is not reset
    // when copying the style, so it needs to happen here. After us,
    // Element::StyleForLayoutObject() will call AdjustElementStyle(),
    // which sets it to true if applicable.
    state.StyleBuilder().ResetSkipsContents();

    const CSSPropertyValueSet* inline_style = element->InlineStyle();
    if (inline_style) {
      int num_properties = inline_style->PropertyCount();
      for (int property_idx = 0; property_idx < num_properties;
           ++property_idx) {
        CSSPropertyValueSet::PropertyReference property =
            inline_style->PropertyAt(property_idx);
        StyleBuilder::ApplyProperty(
            property.Name(), state,
            property.Value().EnsureScopedValue(&GetDocument()));
      }
    }

    // Sets flags related to length unit conversions which may have taken
    // place during StyleBuilder::ApplyProperty.
    ApplyLengthConversionFlags(state);

    StyleAdjuster::AdjustComputedStyle(
        state, style_request.IsPseudoStyleRequest() ? nullptr : element);

    // Normally done by StyleResolver::MaybeAddToMatchedPropertiesCache(),
    // when applying the cascade. Note that this is probably redundant
    // (we'll be loading pending resources later), but not doing so would
    // currently create diffs below.
    state.LoadPendingResources();

    ApplyAnchorData(state);

#if DCHECK_IS_ON()
    // Verify that we got the right answer.
    const ComputedStyle* incremental_style = state.TakeStyle();
    ApplyBaseStyleNoCache(element, style_recalc_context, style_request, state,
                          cascade);

    // Having false positives here is OK (and can happen if an inline style
    // element used to be “inherit” but no longer is); it is only used to see
    // whether parent elements need to propagate inherited properties down to
    // children or not. We'd be doing too much work in such cases, but still
    // maintain correctness.
    if (incremental_style->HasExplicitInheritance()) {
      state.StyleBuilder().SetHasExplicitInheritance();
    }

    // Similarly, if a style went from using viewport units to not,
    // the flags can stick around in the incremental version. This can cause
    // invalidations when none are needed, but is otherwise harmless.
    state.StyleBuilder().SetViewportUnitFlags(
        state.StyleBuilder().ViewportUnitFlags() |
        incremental_style->ViewportUnitFlags());

    const ComputedStyle* style_snapshot = state.StyleBuilder().CloneStyle();
    DCHECK_EQ(g_null_atom,
              ComputeBaseComputedStyleDiff(incremental_style, *style_snapshot));
    // The incremental style must not contain BaseData, otherwise we'd risk
    // creating an infinite chain of BaseData/ComputedStyle in
    // ApplyAnimatedStyle.
    DCHECK(!incremental_style->BaseData());
#endif
    return;
  }

  // None of the caches applied, so we need a full recalculation.
  ApplyBaseStyleNoCache(element, style_recalc_context, style_request, state,
                        cascade);
}

CompositorKeyframeValue* StyleResolver::CreateCompositorKeyframeValueSnapshot(
    Element& element,
    const ComputedStyle& base_style,
    const ComputedStyle* parent_style,
    const PropertyHandle& property,
    const CSSValue* value,
    double offset) {
  // TODO(alancutter): Avoid creating a StyleResolverState just to apply a
  // single value on a ComputedStyle.
  StyleResolverState state(element.GetDocument(), element,
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(parent_style));
  state.SetStyle(base_style);
  if (value) {
    STACK_UNINITIALIZED StyleCascade cascade(state);
    auto* set =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(state.GetParserMode());
    set->SetProperty(property.GetCSSPropertyName(), *value);
    cascade.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(
        element.GetTreeScope());
    cascade.MutableMatchResult().AddMatchedProperties(
        set, {.origin = CascadeOrigin::kAuthor});
    cascade.Apply();
  }
  const ComputedStyle* style = state.TakeStyle();
  return CompositorKeyframeValueFactory::Create(property, *style, offset);
}

const ComputedStyle* StyleResolver::StyleForPage(uint32_t page_index,
                                                 const AtomicString& page_name,
                                                 float page_fitting_scale,
                                                 bool ignore_author_style) {
  // The page context inherits from the root element.
  Element* root_element = GetDocument().documentElement();
  if (!root_element) {
    return InitialStyleForElement();
  }
  DCHECK(!GetDocument().NeedsLayoutTreeUpdateForNode(*root_element));
  const ComputedStyle* parent_style = root_element->EnsureComputedStyle();
  StyleResolverState state(GetDocument(), *root_element,
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(parent_style));
  state.CreateNewStyle(*InitialStyleForElement(), *parent_style);

  if (parent_style->Display() == EDisplay::kNone) {
    // The root is display:none. One page box will still be created, but no
    // properties should apply.
    return InitialStyleForElement();
  }

  auto& builder = state.StyleBuilder();
  // Page boxes are blocks.
  builder.SetDisplay(EDisplay::kBlock);

  STACK_UNINITIALIZED StyleCascade cascade(state);

  PageRuleCollector collector(parent_style, CSSAtRuleID::kCSSAtRulePage,
                              page_index, page_name,
                              cascade.MutableMatchResult());

  collector.MatchPageRules(
      CSSDefaultStyleSheets::Instance().DefaultPrintStyle(),
      CascadeOrigin::kUserAgent, nullptr /* tree_scope */,
      nullptr /* layer_map */);

  // Calling this function without being in print mode is unusual and special,
  // but it happens from unit tests, if nothing else.
  if (GetDocument().Printing()) {
    auto* value = CSSNumericLiteralValue::Create(
        page_fitting_scale, CSSPrimitiveValue::UnitType::kNumber);
    StyleBuilder::ApplyProperty(GetCSSPropertyZoom(), state, *value);

    const WebPrintParams& params = GetDocument().GetFrame()->GetPrintParams();
    const WebPrintPageDescription& description =
        params.default_page_description;
    // Set margins from print settings. They may be overridden by author styles,
    // unless params.ignore_css_margins is set.
    auto* set =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
    value = CSSNumericLiteralValue::Create(
        description.margin_top, CSSPrimitiveValue::UnitType::kPixels);
    set->SetProperty(CSSPropertyID::kMarginTop, *value,
                     /*important=*/params.ignore_css_margins);
    value = CSSNumericLiteralValue::Create(
        description.margin_right, CSSPrimitiveValue::UnitType::kPixels);
    set->SetProperty(CSSPropertyID::kMarginRight, *value,
                     /*important=*/params.ignore_css_margins);
    value = CSSNumericLiteralValue::Create(
        description.margin_bottom, CSSPrimitiveValue::UnitType::kPixels);
    set->SetProperty(CSSPropertyID::kMarginBottom, *value,
                     /*important=*/params.ignore_css_margins);
    value = CSSNumericLiteralValue::Create(
        description.margin_left, CSSPrimitiveValue::UnitType::kPixels);
    set->SetProperty(CSSPropertyID::kMarginLeft, *value,
                     /*important=*/params.ignore_css_margins);
    cascade.MutableMatchResult().AddMatchedProperties(
        set, {.origin = CascadeOrigin::kUserAgent});
  }

  if (!ignore_author_style) {
    if (ScopedStyleResolver* scoped_resolver =
            GetDocument().GetScopedStyleResolver()) {
      scoped_resolver->MatchPageRules(collector);
    }
  }

  cascade.Apply();

  state.LoadPendingResources();

  // Now return the style.
  return state.TakeStyle();
}

void StyleResolver::StyleForPageMargins(const ComputedStyle& page_style,
                                        uint32_t page_index,
                                        const AtomicString& page_name,
                                        PageMarginsStyle* margins_style) {
  Element* root_element = GetDocument().documentElement();
  if (!root_element) {
    return;
  }

  struct Entry {
    PageMarginsStyle::MarginSlot slot;
    CSSAtRuleID at_rule_id;
  };
  const Entry table[] = {
      {PageMarginsStyle::TopLeft, CSSAtRuleID::kCSSAtRuleTopLeft},
      {PageMarginsStyle::TopCenter, CSSAtRuleID::kCSSAtRuleTopCenter},
      {PageMarginsStyle::TopRight, CSSAtRuleID::kCSSAtRuleTopRight},
      {PageMarginsStyle::RightTop, CSSAtRuleID::kCSSAtRuleRightTop},
      {PageMarginsStyle::RightMiddle, CSSAtRuleID::kCSSAtRuleRightMiddle},
      {PageMarginsStyle::RightBottom, CSSAtRuleID::kCSSAtRuleRightBottom},
      {PageMarginsStyle::BottomLeft, CSSAtRuleID::kCSSAtRuleBottomLeft},
      {PageMarginsStyle::BottomCenter, CSSAtRuleID::kCSSAtRuleBottomCenter},
      {PageMarginsStyle::BottomRight, CSSAtRuleID::kCSSAtRuleBottomRight},
      {PageMarginsStyle::LeftTop, CSSAtRuleID::kCSSAtRuleLeftTop},
      {PageMarginsStyle::LeftMiddle, CSSAtRuleID::kCSSAtRuleLeftMiddle},
      {PageMarginsStyle::LeftBottom, CSSAtRuleID::kCSSAtRuleLeftBottom},
      {PageMarginsStyle::TopLeftCorner, CSSAtRuleID::kCSSAtRuleTopLeftCorner},
      {PageMarginsStyle::TopRightCorner, CSSAtRuleID::kCSSAtRuleTopRightCorner},
      {PageMarginsStyle::BottomRightCorner,
       CSSAtRuleID::kCSSAtRuleBottomRightCorner},
      {PageMarginsStyle::BottomLeftCorner,
       CSSAtRuleID::kCSSAtRuleBottomLeftCorner}};

  for (const Entry& entry : table) {
    StyleResolverState margin_state(GetDocument(), *root_element,
                                    /*StyleRecalcContext=*/nullptr,
                                    StyleRequest(&page_style));
    margin_state.CreateNewStyle(*InitialStyleForElement(), page_style);
    margin_state.StyleBuilder().SetDisplay(EDisplay::kBlock);
    margin_state.StyleBuilder().SetIsPageMarginBox(true);

    STACK_UNINITIALIZED StyleCascade margin_cascade(margin_state);
    PageRuleCollector margin_rule_collector(
        &page_style, entry.at_rule_id, page_index, page_name,
        margin_cascade.MutableMatchResult());
    margin_rule_collector.MatchPageRules(
        CSSDefaultStyleSheets::Instance().DefaultPrintStyle(),
        CascadeOrigin::kUserAgent, /*tree_scope=*/nullptr,
        /*layer_map=*/nullptr);

    if (ScopedStyleResolver* scoped_resolver =
            GetDocument().GetScopedStyleResolver()) {
      scoped_resolver->MatchPageRules(margin_rule_collector);
    }

    margin_cascade.Apply();

    margin_state.LoadPendingResources();

    (*margins_style)[entry.slot] = margin_state.TakeStyle();
  }
}

void StyleResolver::LoadPaginationResources() {
  // Compute style for pages and page margins (LoadPendingResources()), to
  // initiate loading of resources only needed by printing.
  //
  // TODO(crbug.com/346799729): Make sure that all resources needed are
  // loaded. As it is now, only resources needed on the first page (with no page
  // name) will be loaded. Any resource inside a non-empty @page selector
  // (unless it happens to match the first page) will be missing.
  const ComputedStyle* page_style = StyleForPage(0, /*page_name=*/g_null_atom);
  PageMarginsStyle ignored;
  StyleForPageMargins(*page_style, 0, /*page_name=*/g_null_atom, &ignored);
}

const ComputedStyle& StyleResolver::InitialStyle() const {
  DCHECK(initial_style_);
  return *initial_style_;
}

ComputedStyleBuilder StyleResolver::CreateComputedStyleBuilder() const {
  DCHECK(initial_style_);
  return ComputedStyleBuilder(*initial_style_);
}

ComputedStyleBuilder StyleResolver::CreateComputedStyleBuilderInheritingFrom(
    const ComputedStyle& parent_style) const {
  DCHECK(initial_style_);
  return ComputedStyleBuilder(*initial_style_, parent_style);
}

float StyleResolver::InitialZoom() const {
  const Document& document = GetDocument();
  if (const LocalFrame* frame = document.GetFrame()) {
    return !document.Printing() ? frame->LayoutZoomFactor() : 1;
  }
  return 1;
}

ComputedStyleBuilder StyleResolver::InitialStyleBuilderForElement() const {
  StyleEngine& engine = GetDocument().GetStyleEngine();

  ComputedStyleBuilder builder = CreateComputedStyleBuilder();
  builder.SetRtlOrdering(GetDocument().VisuallyOrdered() ? EOrder::kVisual
                                                         : EOrder::kLogical);
  builder.SetZoom(InitialZoom());
  builder.SetEffectiveZoom(InitialZoom());
  builder.SetInForcedColorsMode(GetDocument().InForcedColorsMode());
  builder.SetTapHighlightColor(
      ComputedStyleInitialValues::InitialTapHighlightColor());

  builder.SetUsedColorScheme(engine.GetPageColorSchemes(),
                             engine.GetPreferredColorScheme(),
                             engine.GetForceDarkModeEnabled());

  FontDescription document_font_description = builder.GetFontDescription();
  document_font_description.SetLocale(
      LayoutLocale::Get(GetDocument().ContentLanguage()));

  builder.SetFontDescription(document_font_description);
  builder.SetUserModify(GetDocument().InDesignMode() ? EUserModify::kReadWrite
                                                     : EUserModify::kReadOnly);
  FontBuilder(&GetDocument()).CreateInitialFont(builder);

  if (StyleInitialData* initial_data = engine.MaybeCreateAndGetInitialData()) {
    builder.SetInitialData(initial_data);
  }

  if (RuntimeEnabledFeatures::PreferDefaultScrollbarStylesEnabled()) {
    Settings* settings = GetDocument().GetSettings();
    if (settings && settings->GetPrefersDefaultScrollbarStyles()) {
      builder.SetPrefersDefaultScrollbarStyles(true);
    }
  }

  return builder;
}

const ComputedStyle* StyleResolver::InitialStyleForElement() const {
  return InitialStyleBuilderForElement().TakeStyle();
}

const ComputedStyle* StyleResolver::StyleForText(Text* text_node) {
  DCHECK(text_node);
  if (Element* parent = LayoutTreeBuilderTraversal::ParentElement(*text_node)) {
    const ComputedStyle* style = parent->GetComputedStyle();
    if (style && !style->IsEnsuredInDisplayNone()) {
      return style;
    }
  }
  return nullptr;
}

void StyleResolver::AddMatchedRulesToTracker(
    const ElementRuleCollector& collector) {
  collector.AddMatchedRulesToTracker(tracker_);
}

StyleRuleList* StyleResolver::StyleRulesForElement(Element* element,
                                                   unsigned rules_to_include) {
  DCHECK(element);
  StyleResolverState state(GetDocument(), *element);
  MatchResult match_result;
  ElementRuleCollector collector(
      state.ElementContext(), StyleRecalcContext::FromAncestors(*element),
      selector_filter_, match_result, EInsideLink::kNotInsideLink);
  collector.SetMode(SelectorChecker::kCollectingStyleRules);
  collector.SetSuppressVisited(true);
  CollectPseudoRulesForElement(*element, collector, kPseudoIdNone, g_null_atom,
                               rules_to_include);
  return collector.MatchedStyleRuleList();
}

HeapHashMap<CSSPropertyName, Member<const CSSValue>>
StyleResolver::CascadedValuesForElement(Element* element, PseudoId pseudo_id) {
  StyleResolverState state(GetDocument(), *element);
  state.SetStyle(InitialStyle());

  STACK_UNINITIALIZED StyleCascade cascade(state);
  ElementRuleCollector collector(state.ElementContext(),
                                 StyleRecalcContext::FromAncestors(*element),
                                 selector_filter_, cascade.MutableMatchResult(),
                                 EInsideLink::kNotInsideLink);
  collector.SetPseudoElementStyleRequest(StyleRequest(pseudo_id, nullptr));
  MatchAllRules(state, collector, false /* include_smil_properties */);

  cascade.Apply();
  return cascade.GetCascadedValues();
}

Element* StyleResolver::FindContainerForElement(
    Element* element,
    const ContainerSelector& container_selector,
    const TreeScope* selector_tree_scope) {
  DCHECK(element);
  return ContainerQueryEvaluator::FindContainer(
      ContainerQueryEvaluator::ParentContainerCandidateElement(*element),
      container_selector, selector_tree_scope);
}

RuleIndexList* StyleResolver::PseudoCSSRulesForElement(
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& view_transition_name,
    unsigned rules_to_include) {
  DCHECK(element);
  StyleResolverState state(GetDocument(), *element);
  MatchResult match_result;
  StyleRecalcContext style_recalc_context =
      StyleRecalcContext::FromAncestors(*element);
  ElementRuleCollector collector(state.ElementContext(), style_recalc_context,
                                 selector_filter_, match_result,
                                 state.ElementLinkState());
  collector.SetMode(SelectorChecker::kCollectingCSSRules);
  CollectPseudoRulesForElement(*element, collector, pseudo_id,
                               view_transition_name, rules_to_include);

  if (tracker_) {
    AddMatchedRulesToTracker(collector);
  }
  return collector.MatchedCSSRuleList();
}

RuleIndexList* StyleResolver::CssRulesForElement(Element* element,
                                                 unsigned ru
"""


```