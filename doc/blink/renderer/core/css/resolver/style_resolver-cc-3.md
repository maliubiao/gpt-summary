Response:
The user wants a summary of the functionality of the provided C++ code snippet from `style_resolver.cc`. I need to analyze the code and identify its key responsibilities, especially concerning its interaction with JavaScript, HTML, and CSS. I also need to look for examples of logical reasoning, potential user errors, and how a user action might lead to this code being executed. Since this is part 4 of 5, I should focus on the functionality presented in this specific section and avoid repeating information from previous parts (though I don't have access to those parts).

Here's a breakdown of the code's functionality:

1. **Collecting Pseudo-element Styles:** The `CollectPseudoRulesForElement` function gathers CSS rules applicable to pseudo-elements.
2. **Applying Animated Styles:** The `ApplyAnimatedStyle` function handles the application of CSS animations and transitions.
3. **Applying Anchor Data:** The `ApplyAnchorData` function deals with CSS anchor positioning features.
4. **Finding Keyframe Rules:** The `FindKeyframesRule` function searches for `@keyframes` rules.
5. **Caching Matched Properties:** The `ApplyMatchedCache` and `MaybeAddToMatchedPropertiesCache` functions manage a cache for previously resolved CSS properties to improve performance.
6. **Reusing Base Computed Style:** The `CanReuseBaseComputedStyle` function determines if a previously calculated style can be reused as a starting point for applying animations.
7. **Computing and Resolving CSS Values:** The `ComputeValue`, `ResolveValue`, and `ComputeFilterOperations` functions are responsible for calculating the final computed values of CSS properties.
8. **Applying Interpolations:** The `ApplyInterpolations` and `BeforeChangeStyleForTransitionUpdate` functions handle applying interpolated values for animations and transitions.
9. **Applying Properties from Cascade:** The `ApplyPropertiesFromCascade` function takes the ordered list of matched CSS rules (the cascade) and applies them to the element's style.
10. **Applying Callback and Document Rules Selectors:** The `ApplyCallbackSelectors` and `ApplyDocumentRulesSelectors` functions handle specific types of CSS rules.
11. **Computing Font:** The `ComputeFont` function calculates the final font style based on various font-related CSS properties.
12. **Updating Media Type:** The `UpdateMediaType` function tracks the current media type (e.g., print, screen).
13. **Propagating Style to Viewport:** The `PropagateStyleToViewport` function handles the transfer of certain styles from the document or body element to the viewport.
这是 `blink/renderer/core/css/resolver/style_resolver.cc` 源代码文件的第 4 部分，主要功能集中在 **应用动画、处理 CSS 锚点、缓存样式、以及计算和应用最终的 CSS 属性值**。

以下是该部分代码的功能归纳：

**1. 应用动画 (ApplyAnimatedStyle):**

* **功能:**  负责将 CSS 动画 (animations) 和过渡 (transitions) 的效果应用到元素的样式上。
* **与 CSS 的关系:**  直接处理 CSS 的 `animation` 和 `transition` 属性。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个元素正在执行一个 `opacity` 从 0 到 1 的 CSS 动画。
    * **输出:**  `ApplyAnimatedStyle` 会根据动画的当前时间进度，计算出 `opacity` 的中间值，并将其应用到元素的样式中。
* **用户操作如何到达这里:**  用户在 CSS 中定义了一个元素的动画效果，当动画开始播放时，Blink 引擎会调用此函数来更新元素的渲染。

**2. 应用锚点数据 (ApplyAnchorData):**

* **功能:**  处理 CSS 锚点定位 (`anchor()` 和 `position-fallback`) 相关的功能。它会预先计算锚点的中心偏移量，以便布局代码可以直接使用。
* **与 CSS 的关系:**  处理 CSS 锚点定位相关的属性和函数。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  CSS 中定义了 `position: anchor(--my-anchor center);`。
    * **输出:**  `ApplyAnchorData` 会找到名为 `--my-anchor` 的元素，计算其中心相对于当前元素的偏移量，并将其存储在当前元素的样式中。
* **用户操作如何到达这里:**  用户在 CSS 中使用了 `anchor()` 或 `position-fallback()` 函数，当需要计算元素的布局时，会调用此函数。

**3. 查找关键帧规则 (FindKeyframesRule):**

* **功能:**  在不同的作用域 (包括 Shadow DOM) 中查找与指定动画名称匹配的 `@keyframes` 规则。
* **与 CSS 的关系:**  查找 CSS 的 `@keyframes` 规则。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个元素的 `animation-name` 属性设置为 `slide-in`。
    * **输出:**  `FindKeyframesRule` 会在文档的样式表以及可能存在的 Shadow DOM 中查找名为 `slide-in` 的 `@keyframes` 规则，并返回找到的规则和其所在的作用域。
* **用户操作如何到达这里:**  用户在 CSS 中定义了动画，当元素开始播放动画时，需要找到对应的关键帧规则。

**4. 缓存匹配的属性 (ApplyMatchedCache, MaybeAddToMatchedPropertiesCache):**

* **功能:**  使用缓存来存储之前匹配过的 CSS 属性及其计算结果，以提高样式解析的效率。如果已经存在匹配的缓存，则直接使用缓存结果，否则在计算完成后将结果添加到缓存。
* **与 CSS 的关系:**  优化 CSS 属性解析过程。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个元素及其父元素的某些 CSS 属性和之前解析过的完全相同。
    * **输出:**  `ApplyMatchedCache` 会在缓存中找到匹配的项，并直接使用缓存的计算样式，避免重复计算。 `MaybeAddToMatchedPropertiesCache` 会将新计算的、可缓存的样式添加到缓存中。
* **用户操作如何到达这里:**  当浏览器需要解析元素的样式时，会尝试从缓存中查找匹配项。 频繁访问具有相同或相似样式规则的页面或元素会提高缓存命中率。

**5. 判断是否可以重用基础计算样式 (CanReuseBaseComputedStyle):**

* **功能:**  判断在应用动画时，是否可以重用之前计算的基础样式，以进一步优化性能。 某些情况下（例如动画自定义属性、revert 动画、影响字体或行高的动画），不能直接重用。
* **与 CSS 的关系:**  与 CSS 动画和过渡相关，用于优化性能。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个元素正在执行一个不会影响字体、行高等关键属性的简单动画。
    * **输出:**  `CanReuseBaseComputedStyle` 返回 `true`，表示可以重用之前的计算样式。
* **用户操作如何到达这里:**  当元素有正在进行的动画时，Blink 引擎会尝试优化动画应用的流程。

**6. 计算和解析 CSS 值 (ComputeValue, ResolveValue, ComputeFilterOperations):**

* **功能:**
    * `ComputeValue`:  基于给定的 CSS 属性和值，以及元素的上下文，计算出最终的计算值。
    * `ResolveValue`:  在给定的已计算样式的基础上，解析特定 CSS 属性的值。
    * `ComputeFilterOperations`: 计算 `filter` 属性的滤镜操作。
* **与 CSS 的关系:**  核心的 CSS 属性值计算和解析功能。
* **逻辑推理 (假设输入与输出):**
    * **ComputeValue 假设输入:**  一个 `div` 元素，`font-size` 属性值为 `16px`。
    * **ComputeValue 输出:**  返回一个表示 `16px` 的 `CSSValue` 对象。
    * **ResolveValue 假设输入:**  一个元素的计算样式中 `font-size` 为 `1em`，父元素的 `font-size` 为 `16px`。
    * **ResolveValue 输出:**  返回一个表示 `16px` 的 `CSSValue` 对象。
    * **ComputeFilterOperations 假设输入:**  一个 `img` 元素，`filter` 属性值为 `blur(5px)`。
    * **ComputeFilterOperations 输出:**  返回一个包含模糊滤镜操作的 `FilterOperations` 对象。
* **用户操作如何到达这里:**  当浏览器需要确定元素的某个 CSS 属性的最终值时，会调用这些函数。 例如，在首次渲染页面或在 CSS 动画/过渡过程中。

**7. 应用插值 (ApplyInterpolations, BeforeChangeStyleForTransitionUpdate):**

* **功能:**  处理动画和过渡过程中的值插值。 `ApplyInterpolations` 将插值应用到样式层叠中， `BeforeChangeStyleForTransitionUpdate` 在过渡更新之前准备样式，并应用过渡的插值。
* **与 CSS 的关系:**  处理 CSS 动画和过渡的中间状态。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一个元素正在进行一个 `width` 从 `100px` 过渡到 `200px` 的过渡，当前过渡进度为 50%。
    * **输出:**  这些函数会计算出 `width` 的中间值 `150px`，并将其应用到元素的样式中。
* **用户操作如何到达这里:**  当元素发生 CSS 过渡或动画时，需要在每个动画帧之间计算属性的中间值。

**8. 从层叠应用属性 (ApplyPropertiesFromCascade):**

* **功能:**  按照 CSS 层叠规则的顺序，将匹配到的 CSS 属性应用到元素的样式中。 它还处理了旧的重叠属性 (legacy overlapping properties) 的兼容性问题。
* **与 CSS 的关系:**  实现 CSS 层叠的核心逻辑。
* **用户操作如何到达这里:**  在样式解析的最后阶段，需要将所有匹配的规则按照优先级顺序应用到元素。

**9. 应用回调选择器和文档规则选择器 (ApplyCallbackSelectors, ApplyDocumentRulesSelectors):**

* **功能:**  处理特定的选择器，例如用于观察元素状态变化的回调选择器和文档规则选择器。
* **与 CSS 的关系:**  处理特殊的 CSS 选择器。
* **用户操作如何到达这里:**  当页面使用了这些特殊选择器时，需要在样式解析过程中进行处理。

**10. 计算字体 (ComputeFont):**

* **功能:**  基于各种字体相关的 CSS 属性 (如 `font-size`, `font-family`, `font-weight` 等) 计算出元素的最终字体样式。
* **与 CSS 的关系:**  处理 CSS 的字体相关属性。
* **用户操作如何到达这里:**  当需要确定元素的文本渲染样式时，会调用此函数。

**11. 更新媒体类型 (UpdateMediaType):**

* **功能:**  跟踪当前的媒体类型 (例如 "screen", "print")，并根据媒体类型的变化清理依赖于视口的缓存。
* **与 CSS 的关系:**  处理 CSS 媒体查询。
* **用户操作如何到达这里:**  当用户切换到打印预览模式或改变了视口大小时，可能会触发媒体类型的变化。

**12. 传播样式到视口 (PropagateStyleToViewport):**

* **功能:**  将某些特定的样式属性从文档元素 (`<html>`) 或 `<body>` 元素传播到视口 (viewport)，例如 `background-color`, `direction`, `writing-mode` 等。
* **与 HTML 和 CSS 的关系:**  处理 HTML 文档根元素和 `<body>` 元素对视口样式的继承和影响。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  `<html>` 元素的 `background-color` 设置为 `red`。
    * **输出:**  `PropagateStyleToViewport` 会将视口的背景色也设置为 `red`。
* **用户操作如何到达这里:**  在页面加载和渲染过程中，需要确定视口的最终样式。

**常见的用户或编程错误举例:**

* **动画相关:**  定义了复杂的动画但性能不佳，导致 `ApplyAnimatedStyle` 函数执行时间过长，造成页面卡顿。
* **锚点定位:**  错误地使用 `anchor()` 函数，例如锚点元素不存在，导致布局错误。
* **缓存:**  修改了影响缓存的关键因素但没有触发缓存失效，导致使用了过时的样式信息。
* **属性值计算:**  使用了不支持的 CSS 值或单位，导致 `ComputeValue` 或 `ResolveValue` 计算出错。
* **媒体查询:**  在 CSS 中定义了复杂的媒体查询，但在 JavaScript 中没有正确处理媒体类型的变化，可能导致样式不一致。

**用户操作如何一步步的到达这里作为调试线索:**

1. **用户加载网页:**  当用户在浏览器中输入网址或点击链接加载网页时，Blink 引擎开始解析 HTML、CSS 和 JavaScript。
2. **解析 CSS:**  Blink 的 CSS 解析器会将 CSS 样式表解析成内部数据结构。
3. **样式匹配:**  对于 HTML 中的每个元素，样式解析器会根据 CSS 选择器找到与之匹配的样式规则。这涉及到 `MatchAuthorRules` 等函数（在之前的代码部分）。
4. **应用层叠:**  `ApplyPropertiesFromCascade` 函数会按照 CSS 层叠规则的优先级顺序应用匹配到的属性。
5. **处理动画/过渡:**  如果元素定义了 CSS 动画或过渡，当动画开始或过渡发生时，`ApplyAnimatedStyle` 会被调用来更新元素的样式。
6. **处理锚点:** 如果 CSS 中使用了锚点定位，在布局阶段会调用 `ApplyAnchorData` 来计算锚点偏移。
7. **计算最终值:**  当需要确定某个 CSS 属性的最终值时，例如在渲染或动画过程中，会调用 `ComputeValue` 或 `ResolveValue`。
8. **使用缓存:**  在样式匹配和属性应用过程中，`ApplyMatchedCache` 会尝试利用缓存来提高效率。
9. **媒体查询生效:**  如果 CSS 中有媒体查询，当浏览器窗口大小改变或用户切换到打印预览时，`UpdateMediaType` 会更新媒体类型，并可能触发样式的重新计算。

理解这些步骤以及相关函数的职责，可以帮助开发者在 Chromium Blink 引擎中调试 CSS 相关的 bug。例如，如果发现动画效果不正确，可以在 `ApplyAnimatedStyle` 函数中设置断点，查看动画值的计算过程。如果锚点定位出现问题，可以在 `ApplyAnchorData` 中检查锚点元素的查找和偏移计算。

总而言之，这部分 `StyleResolver` 的代码是 Blink 引擎中处理 CSS 动画、过渡、锚点定位以及优化样式计算的关键组成部分。它确保了 CSS 样式能够正确地应用到 HTML 元素上，并提供了性能优化的机制。

Prompt: 
```
这是目录为blink/renderer/core/css/resolver/style_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
les_to_include) {
  return PseudoCSSRulesForElement(element, kPseudoIdNone, g_null_atom,
                                  rules_to_include);
}

void StyleResolver::CollectPseudoRulesForElement(
    const Element& element,
    ElementRuleCollector& collector,
    PseudoId pseudo_id,
    const AtomicString& view_transition_name,
    unsigned rules_to_include) {
  StyleRequest style_request{pseudo_id,
                             /* parent_style */ nullptr,
                             /* originating_element_style */ nullptr,
                             view_transition_name};
  if (pseudo_id == kPseudoIdSearchText) {
    // TODO(crbug.com/339298411): handle :current?
    style_request.search_text_request = StyleRequest::kNotCurrent;
  }
  collector.SetPseudoElementStyleRequest(style_request);

  if (rules_to_include & kUACSSRules) {
    MatchUARules(element, collector);
  }

  if (rules_to_include & kUserCSSRules) {
    MatchUserRules(collector);
  }

  if (rules_to_include & kAuthorCSSRules) {
    MatchAuthorRules(element, collector);
  }
}

bool StyleResolver::ApplyAnimatedStyle(StyleResolverState& state,
                                       StyleCascade& cascade) {
  Element& element = state.GetUltimateOriginatingElementOrSelf();

  // The animating element may be this element, the pseudo element we are
  // resolving style for, or null if we are resolving style for a pseudo
  // element which is not represented by a PseudoElement like scrollbar pseudo
  // elements.
  Element* animating_element = state.GetAnimatingElement();

  if (!animating_element) {
    return false;
  }

  if (HasTimelines(state)) {
    CSSAnimations::CalculateTimelineUpdate(
        state.AnimationUpdate(), *animating_element, state.StyleBuilder());
  }

  if (!HasAnimationsOrTransitions(state)) {
    return false;
  }

  // TODO(crbug.com/1276575) : This assert is currently hit for nested ::marker
  // pseudo elements.
  DCHECK(
      animating_element == &element ||
      (animating_element->IsSVGElement() &&
       To<SVGElement>(animating_element)->CorrespondingElement() == &element) ||
      DynamicTo<PseudoElement>(animating_element)
              ->UltimateOriginatingElement() == &element);

  if (!IsAnimationStyleChange(*animating_element) ||
      !state.StyleBuilder().BaseData()) {
    state.StyleBuilder().SetBaseData(StyleBaseData::Create(
        state.StyleBuilder().CloneStyle(), cascade.GetImportantSet()));
  }

  CSSAnimations::CalculateAnimationUpdate(
      state.AnimationUpdate(), *animating_element, element,
      state.StyleBuilder(), state.ParentStyle(), this,
      state.CanTriggerAnimations());
  CSSAnimations::CalculateTransitionUpdate(
      state.AnimationUpdate(), *animating_element, state.StyleBuilder(),
      state.OldStyle(), state.CanTriggerAnimations());

  bool apply = !state.AnimationUpdate().IsEmpty();
  if (apply) {
    const ActiveInterpolationsMap& animations =
        state.AnimationUpdate().ActiveInterpolationsForAnimations();
    const ActiveInterpolationsMap& transitions =
        state.AnimationUpdate().ActiveInterpolationsForTransitions();

    cascade.AddInterpolations(&animations, CascadeOrigin::kAnimation);
    cascade.AddInterpolations(&transitions, CascadeOrigin::kTransition);

    // Note: this applies the same filter to pseudo elements as its originating
    // element since state.GetElement() returns the originating element when
    // resolving style for pseudo elements.
    CascadeFilter filter =
        UltimateOriginatingElementOrSelf(state.GetElement()).GetCascadeFilter();
    if (state.StyleBuilder().StyleType() == kPseudoIdMarker) {
      filter = filter.Add(CSSProperty::kValidForMarker, false);
    }
    if (IsHighlightPseudoElement(state.StyleBuilder().StyleType())) {
      if (UsesHighlightPseudoInheritance(state.StyleBuilder().StyleType())) {
        filter = filter.Add(CSSProperty::kValidForHighlight, false);
      } else {
        filter = filter.Add(CSSProperty::kValidForHighlightLegacy, false);
      }
    }
    filter = filter.Add(CSSProperty::kAnimation, true);

    cascade.Apply(filter);

    // Start loading resources used by animations.
    state.LoadPendingResources();

    // Apply any length conversion flags produced by CSS/Web animations (e.g.
    // animations involving viewport units would set such flags).
    ApplyLengthConversionFlags(state);

    DCHECK(!state.GetFontBuilder().FontDirty());
  }

  CSSAnimations::CalculateCompositorAnimationUpdate(
      state.AnimationUpdate(), *animating_element, element,
      *state.StyleBuilder().GetBaseComputedStyle(), state.ParentStyle(),
      WasViewportResized(), state.AffectsCompositorSnapshots());
  CSSAnimations::SnapshotCompositorKeyframes(
      *animating_element, state.AnimationUpdate(),
      *state.StyleBuilder().GetBaseComputedStyle(), state.ParentStyle());
  CSSAnimations::UpdateAnimationFlags(
      *animating_element, state.AnimationUpdate(), state.StyleBuilder());

  return apply;
}

void StyleResolver::ApplyAnchorData(StyleResolverState& state) {
  if (AnchorEvaluator* evaluator =
          state.CssToLengthConversionData().GetAnchorEvaluator()) {
    // Pre-compute anchor-center offset so that the OOF layout code does not
    // need to set up an AnchorEvaluator but simply retrieve the offsets from
    // the ComputedStyle.
    if (std::optional<PhysicalOffset> offset =
            evaluator->ComputeAnchorCenterOffsets(state.StyleBuilder());
        offset.has_value()) {
      state.StyleBuilder().SetAnchorCenterOffset(offset);
    }

    // See ComputedStyle::HasAnchorFunctionsWithoutEvaluator.
    state.StyleBuilder().SetHasAnchorEvaluator();
  }
}

StyleResolver::FindKeyframesRuleResult StyleResolver::FindKeyframesRule(
    const Element* element,
    const Element* animating_element,
    const AtomicString& animation_name) {
  HeapVector<Member<ScopedStyleResolver>, 8> resolvers;
  CollectScopedResolversForHostedShadowTrees(*element, resolvers);
  if (ScopedStyleResolver* scoped_resolver =
          element->GetTreeScope().GetScopedStyleResolver()) {
    resolvers.push_back(scoped_resolver);
  }

  for (auto& resolver : resolvers) {
    if (StyleRuleKeyframes* keyframes_rule =
            resolver->KeyframeStylesForAnimation(animation_name)) {
      return FindKeyframesRuleResult{keyframes_rule, &resolver->GetTreeScope()};
    }
  }

  if (StyleRuleKeyframes* keyframes_rule =
          GetDocument().GetStyleEngine().KeyframeStylesForAnimation(
              animation_name)) {
    return FindKeyframesRuleResult{keyframes_rule, nullptr};
  }

  // Match UA keyframe rules after user and author rules.
  StyleRuleKeyframes* matched_keyframes_rule = nullptr;
  auto func = [&matched_keyframes_rule, &animation_name](RuleSet* rules) {
    auto keyframes_rules = rules->KeyframesRules();
    for (auto& keyframes_rule : keyframes_rules) {
      if (keyframes_rule->GetName() == animation_name) {
        matched_keyframes_rule = keyframes_rule;
      }
    }
  };
  ForEachUARulesForElement(*animating_element, nullptr, func);
  if (matched_keyframes_rule) {
    return FindKeyframesRuleResult{matched_keyframes_rule, nullptr};
  }

  for (auto& resolver : resolvers) {
    resolver->SetHasUnresolvedKeyframesRule();
  }
  return FindKeyframesRuleResult();
}

void StyleResolver::InvalidateMatchedPropertiesCache() {
  matched_properties_cache_.Clear();
}

void StyleResolver::SetResizedForViewportUnits() {
  was_viewport_resized_ = true;
  GetDocument().GetStyleEngine().UpdateActiveStyle();
  matched_properties_cache_.ClearViewportDependent();
}

void StyleResolver::ClearResizedForViewportUnits() {
  was_viewport_resized_ = false;
}

StyleResolver::CacheSuccess StyleResolver::ApplyMatchedCache(
    StyleResolverState& state,
    const StyleRequest& style_request,
    const MatchResult& match_result) {
  Element& element = state.GetElement();

  MatchedPropertiesCache::Key key(match_result);

  bool can_use_cache = match_result.IsCacheable();
  // NOTE: Do not add anything here without also adding it to
  // MatchedPropertiesCache::IsCacheable(); you would be inserting
  // elements that can never be fetched.
  if (state.UsesHighlightPseudoInheritance()) {
    // Some pseudo-elements, like ::highlight, are special in that
    // they inherit _non-inherited_ properties from their parent.
    // This is different from what the MPC expects; it checks that
    // the parents are the same before declaring that we have a
    // valid hit (the check for InheritedDataShared() below),
    // but it does not do so for non-inherited properties; it assumes
    // that the base for non-inherited style (before applying the
    // matched properties) is always the initial style.
    // Thus, for simplicity, we simply disable the MPC in these cases.
    //
    // TODO(sesse): Why don't we have this problem when we use
    // a different initial style for <img>?
    can_use_cache = false;
  }
  if (!state.GetElement().GetCascadeFilter().IsEmpty()) {
    // The result of applying properties with the same matching declarations can
    // be different if the cascade filter is different.
    can_use_cache = false;
  }

  const CachedMatchedProperties::Entry* cached_matched_properties =
      can_use_cache ? matched_properties_cache_.Find(key, state) : nullptr;

  if (cached_matched_properties) {
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  matched_property_cache_hit, 1);

    const ComputedStyle* parent_style =
        cached_matched_properties->computed_style.Get();

    InitStyle(element, style_request, *parent_style, parent_style, state);

    if (cached_matched_properties->computed_style->CanAffectAnimations()) {
      // Need to set this flag from the cached ComputedStyle to make
      // ShouldStoreOldStyle() correctly return true. We do not collect matching
      // rules when the cache is hit, and the flag is set as part of that
      // process for the full style resolution.
      state.StyleBuilder().SetCanAffectAnimations();
    }

    // If the cache item parent style has identical inherited properties to
    // the current parent style then the resulting style will be identical
    // too. We copied the inherited properties over from the cache, so we
    // are done.
    //
    // If the child style is a cache hit, we'll never reach StyleBuilder::
    // ApplyProperty, hence we'll never set the flag on the parent.
    // (We do the same thing for independently inherited properties in
    // Element::RecalcOwnStyle().)
    if (state.StyleBuilder().HasExplicitInheritance()) {
      state.ParentStyle()->SetChildHasExplicitInheritance();
    }
    state.UpdateFont();
  } else {
    // Initialize a new, plain ComputedStyle with only initial
    // style and inheritance accounted for. We'll return a cache
    // miss, which will cause the caller to apply all the matched
    // properties on top of it.
    //
    // We use a different initial_style for <img> elements to match the
    // overrides in html.css. This avoids allocation overhead from copy-on-write
    // when these properties are set only via UA styles. The overhead shows up
    // on MotionMark, which stress-tests this code. See crbug.com/1369454 for
    // details.
    const ComputedStyle& initial_style = IsA<HTMLImageElement>(element)
                                             ? *initial_style_for_img_
                                             : *initial_style_;
    InitStyle(element, style_request, initial_style, state.ParentStyle(),
              state);
  }

  // This is needed because pseudo_argument is copied to the
  // state.StyleBuilder() as part of a raredata field when copying
  // non-inherited values from the cached result. The argument isn't a style
  // property per se, it represents the argument to the matching element which
  // should remain unchanged.
  state.StyleBuilder().SetPseudoArgument(style_request.pseudo_argument);

  return CacheSuccess(key, cached_matched_properties);
}

void StyleResolver::MaybeAddToMatchedPropertiesCache(
    StyleResolverState& state,
    const MatchedPropertiesCache::Key& key) {
  state.LoadPendingResources();

  if (key.IsCacheable() && MatchedPropertiesCache::IsCacheable(state)) {
    INCREMENT_STYLE_STATS_COUNTER(GetDocument().GetStyleEngine(),
                                  matched_property_cache_added, 1);
    matched_properties_cache_.Add(key, state.StyleBuilder().CloneStyle(),
                                  state.ParentStyle());
  }
}

bool StyleResolver::CanReuseBaseComputedStyle(const StyleResolverState& state) {
  ElementAnimations* element_animations = GetElementAnimations(state);
  if (!element_animations || !element_animations->IsAnimationStyleChange()) {
    return false;
  }

  StyleBaseData* base_data = GetBaseData(state);
  const ComputedStyle* base_style =
      base_data ? base_data->GetBaseComputedStyle() : nullptr;
  if (!base_style) {
    return false;
  }

  // Animating a custom property can have side effects on other properties
  // via variable references. Disallow base computed style optimization in such
  // cases.
  if (CSSAnimations::IsAnimatingCustomProperties(element_animations)) {
    return false;
  }

  // We need to build the cascade to know what to revert to.
  if (CSSAnimations::IsAnimatingRevert(element_animations)) {
    return false;
  }

  // When applying an animation or transition for a font affecting property,
  // font-relative units (e.g. em, ex) in the base style must respond to the
  // animation. We cannot use the base computed style optimization in such
  // cases.
  if (CSSAnimations::IsAnimatingFontAffectingProperties(element_animations)) {
    if (base_style->HasFontRelativeUnits()) {
      return false;
    }
  }

  // Likewise, When applying an animation or transition for line-height, lh unit
  // lengths in the base style must respond to the animation.
  if (CSSAnimations::IsAnimatingLineHeightProperty(element_animations)) {
    if (base_style->HasLineHeightRelativeUnits()) {
      return false;
    }
  }

  // Normally, we apply all active animation effects on top of the style created
  // by regular CSS declarations. However, !important declarations have a
  // higher priority than animation effects [1]. If we're currently animating
  // (not transitioning) a property which was declared !important in the base
  // style, we disable the base computed style optimization.
  // [1] https://drafts.csswg.org/css-cascade-4/#cascade-origin
  if (CSSAnimations::IsAnimatingStandardProperties(
          element_animations, base_data->GetBaseImportantSet(),
          KeyframeEffect::kDefaultPriority)) {
    return false;
  }

  if (TextAutosizingMultiplierChanged(state, *base_style)) {
    return false;
  }

  // TODO(crbug.com/40943044): If we need to disable the optimization for
  // elements with position-fallback/anchor(), we probably need to disable
  // for descendants of such elements as well.
  if (base_style->GetPositionTryFallbacks() != nullptr) {
    return false;
  }

  if (base_style->HasAnchorFunctions() || base_style->HasAnchorEvaluator()) {
    // TODO(crbug.com/41483417): Enable this optimization for styles with
    // anchor queries.
    return false;
  }

  return true;
}

const CSSValue* StyleResolver::ComputeValue(
    Element* element,
    const CSSPropertyName& property_name,
    const CSSValue& value) {
  const ComputedStyle* base_style = element->GetComputedStyle();
  StyleResolverState state(element->GetDocument(), *element);
  STACK_UNINITIALIZED StyleCascade cascade(state);
  state.SetStyle(*base_style);
  auto* set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(state.GetParserMode());
  set->SetProperty(property_name, value);
  cascade.MutableMatchResult().BeginAddingAuthorRulesForTreeScope(
      element->GetTreeScope());
  cascade.MutableMatchResult().AddMatchedProperties(
      set, {.origin = CascadeOrigin::kAuthor});
  cascade.Apply();

  if (state.HasUnsupportedGuaranteedInvalid()) {
    return nullptr;
  }
  CSSPropertyRef property_ref(property_name, element->GetDocument());
  const ComputedStyle* style = state.TakeStyle();
  return ComputedStyleUtils::ComputedPropertyValue(property_ref.GetProperty(),
                                                   *style);
}

const CSSValue* StyleResolver::ResolveValue(
    Element& element,
    const ComputedStyle& style,
    const CSSPropertyName& property_name,
    const CSSValue& value) {
  StyleResolverState state(element.GetDocument(), element);
  state.SetStyle(style);
  return StyleCascade::Resolve(state, property_name, value);
}

FilterOperations StyleResolver::ComputeFilterOperations(
    Element* element,
    const Font& font,
    const CSSValue& filter_value) {
  ComputedStyleBuilder parent_builder = CreateComputedStyleBuilder();
  parent_builder.SetFont(font);
  const ComputedStyle* parent = parent_builder.TakeStyle();

  StyleResolverState state(GetDocument(), *element,
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(parent));

  GetDocument().GetStyleEngine().UpdateViewportSize();
  state.SetStyle(*parent);

  StyleBuilder::ApplyProperty(GetCSSPropertyFilter(), state,
                              filter_value.EnsureScopedValue(&GetDocument()));

  state.LoadPendingResources();

  const ComputedStyle* style = state.TakeStyle();
  return style->Filter();
}

const ComputedStyle* StyleResolver::StyleForInterpolations(
    Element& element,
    ActiveInterpolationsMap& interpolations) {
  StyleRecalcContext style_recalc_context =
      StyleRecalcContext::FromAncestors(element);
  StyleRequest style_request;
  StyleResolverState state(GetDocument(), element, &style_recalc_context,
                           style_request);
  STACK_UNINITIALIZED StyleCascade cascade(state);

  ApplyBaseStyle(&element, style_recalc_context, style_request, state, cascade);
  state.StyleBuilder().SetBaseData(StyleBaseData::Create(
      state.StyleBuilder().CloneStyle(), cascade.GetImportantSet()));

  ApplyInterpolations(state, cascade, interpolations);
  return state.TakeStyle();
}

void StyleResolver::ApplyInterpolations(
    StyleResolverState& state,
    StyleCascade& cascade,
    ActiveInterpolationsMap& interpolations) {
  cascade.AddInterpolations(&interpolations, CascadeOrigin::kAnimation);
  cascade.Apply();
}

const ComputedStyle* StyleResolver::BeforeChangeStyleForTransitionUpdate(
    Element& element,
    const ComputedStyle& base_style,
    ActiveInterpolationsMap& transition_interpolations) {
  StyleResolverState state(GetDocument(), element);
  STACK_UNINITIALIZED StyleCascade cascade(state);
  state.SetStyle(base_style);

  // Various property values may depend on the parent style. A valid parent
  // style is required, even if animating the root element, in order to
  // handle these dependencies. The root element inherits from initial
  // styles.
  if (!state.ParentStyle()) {
    if (element != GetDocument().documentElement()) {
      // Do not apply interpolations to a detached element.
      return state.TakeStyle();
    }
    state.SetParentStyle(InitialStyleForElement());
    state.SetLayoutParentStyle(state.ParentStyle());
  }

  state.StyleBuilder().SetBaseData(StyleBaseData::Create(&base_style, nullptr));

  // TODO(crbug.com/1098937): Include active CSS animations in a separate
  // interpolations map and add each map at the appropriate CascadeOrigin.
  ApplyInterpolations(state, cascade, transition_interpolations);
  return state.TakeStyle();
}

void StyleResolver::ApplyPropertiesFromCascade(StyleResolverState& state,
                                               StyleCascade& cascade) {
  const ComputedStyle* old_style = nullptr;
  if (count_computed_style_bytes_) {
    old_style = state.StyleBuilder().CloneStyle();
  }

  // Note: this applies the same filter to pseudo elements as its originating
  // element since state.GetElement() returns the originating element when
  // resolving style for pseudo elements.
  CascadeFilter filter = state.GetElement().GetCascadeFilter();

  // In order to use-count whether or not legacy overlapping properties
  // made a real difference to the ComputedStyle, we first apply the cascade
  // while filtering out such properties. If the filter did reject
  // any legacy overlapping properties, we apply all overlapping properties
  // again to get the correct result.
  cascade.Apply(filter.Add(CSSProperty::kLegacyOverlapping, true));

  if (state.RejectedLegacyOverlapping()) {
    const ComputedStyle* non_legacy_style = state.StyleBuilder().CloneStyle();
    // Re-apply all overlapping properties (both legacy and non-legacy).
    cascade.Apply(filter.Add(CSSProperty::kOverlapping, false));
    UseCountLegacyOverlapping(GetDocument(), *non_legacy_style,
                              state.StyleBuilder());
  }

  if (count_computed_style_bytes_) {
    constexpr size_t kOilpanOverheadBytes =
        sizeof(void*);  // See cppgc::internal::HeapObjectHeader.
    const ComputedStyle* new_style = state.StyleBuilder().CloneStyle();
    for (const auto& [group_name, size] :
         old_style->FindChangedGroups(*new_style)) {
      computed_style_bytes_used_ += size + kOilpanOverheadBytes;
    }
    computed_style_bytes_used_ += sizeof(*new_style) + kOilpanOverheadBytes;
  }

  // NOTE: This flag (and the length conversion flags) need to be set before the
  // entry is added to the matched properties cache, or it will be wrong on
  // cache hits.
  state.StyleBuilder().SetInlineStyleLostCascade(cascade.InlineStyleLost());
  ApplyLengthConversionFlags(state);

  DCHECK(!state.GetFontBuilder().FontDirty());
}

void StyleResolver::ApplyCallbackSelectors(StyleResolverState& state) {
  StyleRuleList* rules = CollectMatchingRulesFromUnconnectedRuleSet(
      state, GetDocument().GetStyleEngine().WatchedSelectorsRuleSet(),
      /*scope=*/nullptr);
  if (!rules) {
    return;
  }
  for (auto rule : *rules) {
    state.StyleBuilder().AddCallbackSelector(rule->SelectorsText());
  }
}

void StyleResolver::ApplyDocumentRulesSelectors(StyleResolverState& state,
                                                ContainerNode* scope) {
  StyleRuleList* rules = CollectMatchingRulesFromUnconnectedRuleSet(
      state, GetDocument().GetStyleEngine().DocumentRulesSelectorsRuleSet(),
      scope);
  if (!rules) {
    return;
  }
  for (auto rule : *rules) {
    state.StyleBuilder().AddDocumentRulesSelector(rule);
  }
}

StyleRuleList* StyleResolver::CollectMatchingRulesFromUnconnectedRuleSet(
    StyleResolverState& state,
    RuleSet* rule_set,
    ContainerNode* scope) {
  if (!rule_set) {
    return nullptr;
  }

  MatchResult match_result;
  ElementRuleCollector collector(state.ElementContext(), StyleRecalcContext(),
                                 selector_filter_, match_result,
                                 state.InsideLink());
  collector.SetMatchingRulesFromNoStyleSheet(true);
  collector.SetMode(SelectorChecker::kCollectingStyleRules);
  MatchRequest match_request(rule_set, scope);
  collector.CollectMatchingRules(match_request, /*part_names*/ nullptr);
  collector.SortAndTransferMatchedRules(
      CascadeOrigin::kAuthor, /*is_vtt_embedded_style=*/false, tracker_);
  collector.SetMatchingRulesFromNoStyleSheet(false);

  return collector.MatchedStyleRuleList();
}

// Font properties are also handled by FontStyleResolver outside the main
// thread. If you add/remove properties here, make sure they are also properly
// handled by FontStyleResolver.
Font StyleResolver::ComputeFont(Element& element,
                                const ComputedStyle& style,
                                const CSSPropertyValueSet& property_set) {
  static const CSSProperty* properties[6] = {
      &GetCSSPropertyFontSize(),        &GetCSSPropertyFontFamily(),
      &GetCSSPropertyFontStretch(),     &GetCSSPropertyFontStyle(),
      &GetCSSPropertyFontVariantCaps(), &GetCSSPropertyFontWeight(),
  };

  // TODO(timloh): This is weird, the style is being used as its own parent
  StyleResolverState state(GetDocument(), element,
                           nullptr /* StyleRecalcContext */,
                           StyleRequest(&style));
  GetDocument().GetStyleEngine().UpdateViewportSize();
  state.SetStyle(style);
  if (const ComputedStyle* parent_style = element.GetComputedStyle()) {
    state.SetParentStyle(parent_style);
  }

  for (const CSSProperty* property : properties) {
    // TODO(futhark): If we start supporting fonts on ShadowRoot.fonts in
    // addition to Document.fonts, we need to pass the correct TreeScope instead
    // of GetDocument() in the EnsureScopedValue below.
    StyleBuilder::ApplyProperty(
        *property, state,
        property_set.GetPropertyCSSValue(property->PropertyID())
            ->EnsureScopedValue(&GetDocument()));
  }
  state.UpdateFont();
  const ComputedStyle* font_style = state.TakeStyle();
  return font_style->GetFont();
}

void StyleResolver::UpdateMediaType() {
  if (LocalFrameView* view = GetDocument().View()) {
    bool was_print = print_media_type_;
    print_media_type_ =
        EqualIgnoringASCIICase(view->MediaType(), media_type_names::kPrint);
    if (was_print != print_media_type_) {
      matched_properties_cache_.ClearViewportDependent();
    }
  }
}

void StyleResolver::Trace(Visitor* visitor) const {
  visitor->Trace(matched_properties_cache_);
  visitor->Trace(initial_style_);
  visitor->Trace(initial_style_for_img_);
  visitor->Trace(selector_filter_);
  visitor->Trace(document_);
  visitor->Trace(tracker_);
}

bool StyleResolver::IsForcedColorsModeEnabled() const {
  return GetDocument().InForcedColorsMode();
}

ComputedStyleBuilder StyleResolver::CreateAnonymousStyleBuilderWithDisplay(
    const ComputedStyle& parent_style,
    EDisplay display) {
  ComputedStyleBuilder builder(*initial_style_, parent_style);
  builder.SetUnicodeBidi(parent_style.GetUnicodeBidi());
  builder.SetDisplay(display);
  return builder;
}

const ComputedStyle* StyleResolver::CreateAnonymousStyleWithDisplay(
    const ComputedStyle& parent_style,
    EDisplay display) {
  return CreateAnonymousStyleBuilderWithDisplay(parent_style, display)
      .TakeStyle();
}

const ComputedStyle* StyleResolver::CreateInheritedDisplayContentsStyleIfNeeded(
    const ComputedStyle& parent_style,
    const ComputedStyle& layout_parent_style) {
  if (parent_style.InheritedEqual(layout_parent_style)) {
    return nullptr;
  }
  return CreateAnonymousStyleWithDisplay(parent_style, EDisplay::kInline);
}

#define PROPAGATE_FROM(source, getter, setter, initial) \
  PROPAGATE_VALUE(source ? source->getter() : initial, getter, setter);

#define PROPAGATE_VALUE(value, getter, setter)            \
  if ((new_viewport_style_builder.getter()) != (value)) { \
    new_viewport_style_builder.setter(value);             \
    changed = true;                                       \
  }

namespace {

bool PropagateScrollSnapStyleToViewport(
    Document& document,
    const ComputedStyle* document_element_style,
    ComputedStyleBuilder& new_viewport_style_builder) {
  bool changed = false;
  // We only propagate the properties related to snap container since viewport
  // defining element cannot be a snap area.
  PROPAGATE_FROM(document_element_style, GetScrollSnapType, SetScrollSnapType,
                 cc::ScrollSnapType());
  PROPAGATE_FROM(document_element_style, ScrollPaddingTop, SetScrollPaddingTop,
                 Length());
  PROPAGATE_FROM(document_element_style, ScrollPaddingRight,
                 SetScrollPaddingRight, Length());
  PROPAGATE_FROM(document_element_style, ScrollPaddingBottom,
                 SetScrollPaddingBottom, Length());
  PROPAGATE_FROM(document_element_style, ScrollPaddingLeft,
                 SetScrollPaddingLeft, Length());

  return changed;
}

}  // namespace

bool StyleResolver::ShouldStopBodyPropagation(const Element& body_or_html) {
  DCHECK(!body_or_html.NeedsReattachLayoutTree())
      << "This method relies on LayoutObject to be attached and up-to-date";
  DCHECK(IsA<HTMLBodyElement>(body_or_html) ||
         IsA<HTMLHtmlElement>(body_or_html));
  LayoutObject* layout_object = body_or_html.GetLayoutObject();
  if (!layout_object) {
    return true;
  }
  bool contained = layout_object->ShouldApplyAnyContainment();
  if (contained) {
    UseCounter::Count(GetDocument(), IsA<HTMLHtmlElement>(body_or_html)
                                         ? WebFeature::kHTMLRootContained
                                         : WebFeature::kHTMLBodyContained);
  }
  DCHECK_EQ(contained,
            layout_object->StyleRef().ShouldApplyAnyContainment(body_or_html))
      << "Applied containment must give the same result from LayoutObject and "
         "ComputedStyle";
  return contained;
}

void StyleResolver::PropagateStyleToViewport() {
  DCHECK(GetDocument().InStyleRecalc());
  Element* document_element = GetDocument().documentElement();
  const ComputedStyle* document_element_style =
      document_element && document_element->GetLayoutObject()
          ? document_element->GetComputedStyle()
          : nullptr;
  const ComputedStyle* body_style = nullptr;
  if (HTMLBodyElement* body = GetDocument().FirstBodyElement()) {
    if (!ShouldStopBodyPropagation(*document_element) &&
        !ShouldStopBodyPropagation(*body)) {
      body_style = body->GetComputedStyle();
    }
  }

  const ComputedStyle& viewport_style =
      GetDocument().GetLayoutView()->StyleRef();
  ComputedStyleBuilder new_viewport_style_builder(viewport_style);
  bool changed = false;
  bool update_scrollbar_style = false;

  // Writing mode and direction
  {
    const ComputedStyle* direction_style =
        body_style ? body_style : document_element_style;
    PROPAGATE_FROM(direction_style, GetWritingMode, SetWritingMode,
                   WritingMode::kHorizontalTb);
    PROPAGATE_FROM(direction_style, Direction, SetDirection,
                   TextDirection::kLtr);
  }

  // Background
  {
    const ComputedStyle* background_style = document_element_style;
    // http://www.w3.org/TR/css3-background/#body-background
    // <html> root element with no background steals background from its first
    // <body> child.
    // Also see LayoutBoxModelObject::BackgroundTransfersToView()
    if (body_style && !background_style->HasBackground()) {
      background_style = body_style;
    }

    Color background_color = Color::kTransparent;
    FillLayer background_layers(EFillLayerType::kBackground, true);
    EImageRendering image_rendering = EImageRendering::kAuto;

    if (background_style) {
      background_color = background_style->VisitedDependentColor(
          GetCSSPropertyBackgroundColor());
      background_layers = background_style->BackgroundLayers();
      for (auto* current_layer = &background_layers; current_layer;
           current_layer = current_layer->Next()) {
        // http://www.w3.org/TR/css3-background/#root-background
        // The root element background always have painting area of the whole
        // canvas.
        current_layer->SetClip(EFillBox::kBorder);

        // The root element doesn't scroll. It always propagates its layout
        // overflow to the viewport. Positioning background against either box
        // is equivalent to positioning against the scrolled box of the
        // viewport.
        if (current_layer->Attachment() == EFillAttachment::kScroll) {
          current_layer->SetAttachment(EFillAttachment::kLocal);
        }
      }
      image_rendering = background_style->ImageRendering();
    }

    if (viewport_style.VisitedDependentColor(GetCSSPropertyBackgroundColor()) !=
            background_color ||
        viewport_style.BackgroundLayers() != background_layers ||
        viewport_style.ImageRendering() != image_rendering) {
      changed = true;
      new_viewport_style_builder.SetBackgroundColor(
          StyleColor(background_color));
      new_viewport_style_builder.AccessBackgroundLayers() = background_layers;
      new_viewport_style_builder.SetImageRendering(image_rendering);
    }

    // https://github.com/w3c/csswg-drafts/issues/6307
    // In forced colors mode, the internal forced background color is
    // propagated from the root element to the viewport.
    if (IsForcedColorsModeEnabled()) {
      Color internal_forced_background_color =
          document_element_style
              ? document_element_style->VisitedDependentColor(
                    GetCSSPropertyInternalForcedBackgroundColor())
              : Color::kTransparent;
      if (viewport_style.VisitedDependentColor(
              GetCSSPropertyInternalForcedBackgroundColor()) !=
          internal_forced_background_co
"""


```