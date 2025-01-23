Response:
The user wants a summary of the functionality of the provided C++ code snippet from `style_engine.cc`.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Class:** The code is part of the `StyleEngine` class. This class is responsible for managing the styling of elements in a web page.

2. **Analyze Individual Methods:**  Go through each method in the provided snippet and understand its purpose. Look for keywords and patterns.

    * `ComputeFont`:  Clearly related to calculating font styles.
    * `RuleSetForSheet`:  Deals with retrieving rule sets for stylesheets, considering media queries.
    * `RuleSetScope::RuleSetForSheet`: An overload, likely handling specific scoping for rule sets, especially concerning cascade layers and shared stylesheet content. The "WillMutateRules()" call suggests handling modifications to these shared resources.
    * `ClearResolvers`:  Indicates cleaning up style resolvers, which are key components in the style calculation process. The `DCHECK(!GetDocument().InStyleRecalc())` is important – it hints at when this cleanup is allowed.
    * `DidDetach`:  Handles the cleanup when the `StyleEngine` is detached, releasing various resources like resolvers, rule sets, and caches.
    * `ClearFontFaceCacheAndAddUserFonts`:  Manages the font face cache, allowing for clearing and adding user-defined fonts.
    * `UpdateGenericFontFamilySettings`: Updates settings related to generic font families. The `DCHECK(GetDocument().IsActive())` suggests it's only relevant for active documents.
    * `RemoveFontFaceRules`: Removes specific font face rules.
    * `MarkTreeScopeDirty`, `MarkDocumentDirty`, `MarkUserStyleDirty`, `MarkViewportStyleDirty`: These methods mark different aspects of the style system as "dirty," triggering recalculations. The calls to `GetDocument().ScheduleLayoutTreeUpdateIfNeeded()` are crucial, showing how style changes affect layout.
    * `CreateSheet`, `ParseSheet`:  Deal with creating and parsing CSS stylesheets from `<style>` elements or inline styles. The caching mechanism in `CreateSheet` is noteworthy.
    * `CollectUserStyleFeaturesTo`, `CollectScopedStyleFeaturesTo`: These methods gather information about the features used in stylesheets, likely for optimization or invalidation purposes.
    * `MarkViewportUnitDirty`: Marks viewport units as dirty, triggering updates for styles that depend on them.
    * `InvalidateViewportUnitStylesIfNeeded`:  Performs the actual invalidation of styles based on dirty viewport units. The check for custom properties is important.
    * `InvalidateStyleAndLayoutForFontUpdates`:  Triggers style and layout invalidation specifically for font updates.
    * `MarkFontsNeedUpdate`, `MarkCounterStylesNeedUpdate`: Mark flags indicating that fonts or counter styles need updating.
    * `FontsNeedUpdate`: A callback when font updates occur, invalidating caches and marking styles dirty.
    * `PlatformColorsChanged`: Handles changes in system color settings, triggering style recalculations.
    * `ShouldSkipInvalidationFor`:  A check to see if style invalidation should be skipped for a particular element, with various conditions.
    * `IsSubtreeAndSiblingsStyleDirty`: Checks if the style of a subtree or its siblings is already marked as dirty.
    * `PossiblyScheduleNthPseudoInvalidations`:  Handles invalidation related to `:nth-child` and similar pseudo-classes.
    * `InvalidateElementAffectedByHas`: Invalidates the style of elements that are affected by the `:has()` pseudo-class.
    * `PseudoHasInvalidationTraversalContext`: A helper class to manage the context for invalidating elements affected by `:has()`.
    * `InvalidateAncestorsOrSiblingsAffectedByHas`:  The core logic for invalidating ancestors and siblings based on `:has()`.
    * `InvalidateChangedElementAffectedByLogicalCombinationsInHas`:  Handles invalidation for `:has()` with complex selectors.
    * `ClassChangedForElement` (two overloads): Handles style invalidation when an element's class attribute changes.
    * `HasAttributeDependentGeneratedContent`, `HasAttributeDependentStyle`: Functions to check if an element's style depends on attributes.
    * `AttributeChangedForElement`: Handles style invalidation when an element's attribute changes.
    * `IdChangedForElement`: Handles style invalidation when an element's ID changes.

3. **Group Functionalities:**  Group the methods by their common purpose. This helps to create a more structured summary. For example:

    * **Style Computation:** `ComputeFont`
    * **Stylesheet Management:** `RuleSetForSheet`, `RuleSetScope::RuleSetForSheet`, `CreateSheet`, `ParseSheet`
    * **Invalidation Management:** `ClearResolvers`, `DidDetach`, `MarkTreeScopeDirty`, `MarkDocumentDirty`, `MarkUserStyleDirty`, `MarkViewportStyleDirty`, `MarkViewportUnitDirty`, `InvalidateViewportUnitStylesIfNeeded`, `InvalidateStyleAndLayoutForFontUpdates`, `MarkFontsNeedUpdate`, `MarkCounterStylesNeedUpdate`, `FontsNeedUpdate`, `PlatformColorsChanged`, `ShouldSkipInvalidationFor`, `IsSubtreeAndSiblingsStyleDirty`
    * **`:has()` Pseudo-class Invalidation:** `PossiblyScheduleNthPseudoInvalidations`, `InvalidateElementAffectedByHas`, `PseudoHasInvalidationTraversalContext`, `InvalidateAncestorsOrSiblingsAffectedByHas`, `InvalidateChangedElementAffectedByLogicalCombinationsInHas`
    * **Attribute/Class/ID Change Handling:** `ClassChangedForElement`, `HasAttributeDependentGeneratedContent`, `HasAttributeDependentStyle`, `AttributeChangedForElement`, `IdChangedForElement`
    * **Font Management:** `ClearFontFaceCacheAndAddUserFonts`, `UpdateGenericFontFamilySettings`, `RemoveFontFaceRules`
    * **Feature Collection:** `CollectUserStyleFeaturesTo`, `CollectScopedStyleFeaturesTo`

4. **Synthesize the Summary:** Write a concise summary of each group of functionalities. Use clear and understandable language. Highlight the key responsibilities of the `StyleEngine`.

5. **Address Specific Requirements:**  Go back to the user's request and ensure all points are covered:

    * **Functionality Listing:** The grouped summaries effectively list the functionalities.
    * **Relationship to JavaScript, HTML, CSS:** Explain how each group interacts with these technologies. Provide concrete examples.
    * **Logical Reasoning (Assumptions, Input/Output):**  For complex methods like `RuleSetScope::RuleSetForSheet` or invalidation functions, provide hypothetical scenarios with inputs and expected outcomes.
    * **User/Programming Errors:** Identify potential mistakes users or developers might make that would interact with this code (e.g., incorrect CSS syntax, manipulating styles during a style recalc).
    * **User Operations to Reach Here (Debugging):** Describe typical user actions that would lead to the execution of this code.
    * **Part 2 of 6:** Acknowledge this context.

6. **Review and Refine:**  Read through the entire summary to ensure accuracy, clarity, and completeness. Make any necessary edits for better flow and understanding. For instance, ensure that the examples are relevant and easy to grasp. Check for redundant information and consolidate where possible. Emphasize the core responsibility of `StyleEngine` in the context of rendering web pages.这是 blink 渲染引擎中 `blink/renderer/core/css/style_engine.cc` 文件的第二个代码片段，主要负责样式计算、样式表的管理和失效，以及处理特定 CSS 特性的更新和失效。以下是其功能的归纳：

**核心功能归纳:**

1. **字体样式计算:**
   - `ComputeFont`:  根据元素、已有的字体样式和新的字体属性，计算出最终的字体样式。

2. **样式表规则集的获取:**
   - `RuleSetForSheet`:  根据给定的 CSS 样式表，检查其是否满足媒体查询条件，并返回相应的规则集。
   - `RuleSetScope::RuleSetForSheet`: 在特定作用域内获取样式表的规则集，并处理包含级联层且与其他样式表共享 `StyleSheetContents` 的情况，以避免匿名层的错误识别。

3. **样式解析器的清理:**
   - `ClearResolvers`: 清除文档和所有激活的 TreeScope 中的样式解析器。这通常在样式重新计算之前或之后进行，以确保状态的正确性。

4. **引擎析构时的清理:**
   - `DidDetach`:  当 `StyleEngine` 对象被分离时执行清理操作，包括清除样式解析器、全局规则集、脏标记、活动作用域、viewport 解析器、媒体查询评估器、失效根以及字体选择器和环境变量。

5. **字体缓存管理:**
   - `ClearFontFaceCacheAndAddUserFonts`: 清除 CSS 连接的字体缓存，并添加用户样式表中的 `@font-face` 规则。
   - `UpdateGenericFontFamilySettings`: 更新通用字体族设置，并使匹配的属性缓存失效。
   - `RemoveFontFaceRules`: 移除指定的 `@font-face` 规则，并使匹配的属性缓存失效。

6. **标记样式失效:**
   - `MarkTreeScopeDirty`: 标记特定 `TreeScope` 的样式失效，并调度布局树的更新。
   - `MarkDocumentDirty`: 标记整个文档的样式失效，并调度布局树的更新。
   - `MarkUserStyleDirty`: 标记用户样式失效，并调度布局树的更新。
   - `MarkViewportStyleDirty`: 标记视口样式失效，并调度布局树的更新。

7. **样式表的创建和解析:**
   - `CreateSheet`:  为元素创建 CSS 样式表，处理内联样式，并利用缓存机制避免重复解析相同的样式内容。
   - `ParseSheet`:  解析给定的 CSS 文本，创建一个 `CSSStyleSheet` 对象。

8. **收集样式特性:**
   - `CollectUserStyleFeaturesTo`:  收集所有激活的用户样式表中的样式特性。
   - `CollectScopedStyleFeaturesTo`: 收集所有作用域样式表中的样式特性。

9. **视口单位失效:**
   - `MarkViewportUnitDirty`: 标记特定视口单位的样式失效，并调度布局树的更新。
   - `InvalidateViewportUnitStylesIfNeeded`:  检查是否有视口单位失效的标记，并针对依赖这些单位的样式进行失效处理。

10. **字体更新的样式和布局失效:**
    - `InvalidateStyleAndLayoutForFontUpdates`:  触发字体更新后的样式和布局失效。
    - `MarkFontsNeedUpdate`: 标记需要进行字体更新。
    - `MarkCounterStylesNeedUpdate`: 标记需要更新计数器样式。
    - `FontsNeedUpdate`:  在字体更新时被调用，使匹配的属性缓存失效，并标记视口样式和字体需要更新。

11. **平台颜色变化处理:**
    - `PlatformColorsChanged`:  当平台颜色发生变化时，更新强制背景色、配色方案背景，并使所有元素的样式失效。

12. **跳过失效检查:**
    - `ShouldSkipInvalidationFor`:  判断是否应该跳过对特定元素的样式失效操作，例如在非活动文档或样式重计算过程中。

13. **判断子树和兄弟节点的样式是否已失效:**
    - `IsSubtreeAndSiblingsStyleDirty`: 检查特定元素的子树或兄弟节点的样式是否已经被标记为失效。

14. **处理 `:nth-*` 伪类的失效:**
    - `PossiblyScheduleNthPseudoInvalidations`:  当节点可能影响其父节点的 `:nth-*` 伪类选择器时，调度失效。

15. **处理 `:has()` 伪类的失效:**
    - `InvalidateElementAffectedByHas`:  使受 `:has()` 伪类影响的元素样式失效。
    - `PseudoHasInvalidationTraversalContext`:  一个辅助类，用于管理 `:has()` 失效遍历的上下文信息。
    - `InvalidateAncestorsOrSiblingsAffectedByHas`:  使受 `:has()` 伪类影响的祖先或兄弟节点的样式失效。
    - `InvalidateChangedElementAffectedByLogicalCombinationsInHas`: 处理在 `:has()` 伪类中使用逻辑组合符时的元素失效。

16. **处理类名变化的样式失效:**
    - `ClassChangedForElement`:  当元素的 `class` 属性发生变化时，根据规则失效数据来使相关的元素样式失效。提供了处理新增和移除类名的优化逻辑。

17. **检查属性相关的样式依赖:**
    - `HasAttributeDependentGeneratedContent`:  检查元素是否有依赖属性值的生成内容 (针对旧版本的 `@attr` 函数)。
    - `HasAttributeDependentStyle`: 检查元素的样式是否依赖属性值 (针对新的 `@attr()` 函数)。

18. **处理属性变化的样式失效:**
    - `AttributeChangedForElement`:  当元素的属性发生变化时，根据规则失效数据来使相关的元素样式失效。

19. **处理 ID 变化的样式失效:**
    - `IdChangedForElement`: 当元素的 `id` 属性发生变化时，根据规则失效数据来使相关的元素样式失效。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:** 当 JavaScript 代码修改元素的 class 属性 (例如 `element.classList.add('new-class')`) 或 style 属性 (例如 `element.style.color = 'red'`) 时，会触发 `StyleEngine` 中的相应方法，例如 `ClassChangedForElement` 或导致样式失效，最终需要 `StyleEngine` 重新计算样式。
* **HTML:** HTML 结构的变化，例如添加或删除 `<style>` 标签，或者修改元素的属性，都会触发 `StyleEngine` 的功能。例如，添加 `<style>` 标签会调用 `CreateSheet` 和 `ParseSheet` 来解析新的样式规则。修改元素的 `class` 或 `id` 属性会调用 `ClassChangedForElement` 或 `IdChangedForElement`。
* **CSS:** `StyleEngine` 的核心功能就是解析和应用 CSS 规则。它负责读取 CSS 样式表中的选择器和属性，并根据优先级和层叠规则计算出元素的最终样式。例如，`ComputeFont` 方法直接处理 CSS 的字体相关属性。`RuleSetForSheet` 处理 CSS 样式表的媒体查询。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

一个 `div` 元素，初始 `class` 为 "old-class"。
CSS 规则:
```css
.old-class { color: black; }
.new-class { color: red; }
```
JavaScript 代码: `element.classList.replace('old-class', 'new-class');`

**输出:**

`StyleEngine::ClassChangedForElement` 方法会被调用，`old_classes` 参数为包含 "old-class" 的 `SpaceSplitString`，`new_classes` 参数为包含 "new-class" 的 `SpaceSplitString`。
`StyleEngine` 会根据 CSS 规则，使该 `div` 元素的样式失效，并重新计算样式，最终 `div` 元素的文本颜色会变为红色。

**用户或编程常见的使用错误举例:**

* **错误地在样式重计算过程中修改样式：**  如果在 JavaScript 代码中，在某些事件处理函数中（例如 `scroll` 或 `resize`）直接修改元素的样式，可能会在样式重计算过程中触发新的样式修改，导致性能问题甚至死循环。`StyleEngine` 中的 `DCHECK(!GetDocument().InStyleRecalc())`  会在调试模式下捕获这类错误。
* **CSS 选择器过于复杂：**  编写过于复杂的 CSS 选择器，例如深度嵌套的选择器或者包含大量 `:not()` 伪类的选择器，会导致样式匹配和失效的性能下降，最终影响页面渲染速度。`StyleEngine` 需要遍历规则来找到匹配的规则，复杂的选择器会增加遍历的成本。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户加载网页:** 当用户在浏览器中打开一个网页时，HTML 解析器会构建 DOM 树。
2. **遇到 `<style>` 标签或外部 CSS 文件链接:**  解析器会触发资源加载，加载 CSS 文件或解析 `<style>` 标签内的 CSS 代码。
3. **`StyleEngine` 创建样式表:** `StyleEngine::CreateSheet` 或相关方法会被调用，将 CSS 代码解析成 `CSSStyleSheet` 对象。
4. **用户与页面交互 (例如鼠标悬停，滚动):**  用户的交互可能导致元素状态变化，例如 `:hover` 状态的改变。
5. **JavaScript 修改 DOM 或样式:** JavaScript 代码可能会修改元素的属性、类名或直接操作样式。
6. **触发样式失效:**  例如，`element.classList.add('highlight')` 会调用 `StyleEngine::ClassChangedForElement`，标记相关元素的样式需要重新计算。
7. **样式重计算:**  浏览器会调度样式重计算，`StyleEngine` 会遍历匹配的 CSS 规则，计算出元素的最终样式，涉及到 `ComputeFont` 等方法。
8. **布局和绘制:**  基于计算出的样式，浏览器会进行布局和绘制操作。

**总结:**

这段代码是 Blink 渲染引擎中负责核心样式管理和计算的关键部分。它处理了从 CSS 规则的解析和存储，到元素样式的计算和失效，以及对特定 CSS 特性（如字体、视口单位、`:has()` 伪类等）的特殊处理。其功能直接关系到网页的最终呈现效果和性能。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
const ComputedStyle& font_style,
                              const CSSPropertyValueSet& font_properties) {
  UpdateActiveStyle();
  return GetStyleResolver().ComputeFont(element, font_style, font_properties);
}

RuleSet* StyleEngine::RuleSetForSheet(CSSStyleSheet& sheet) {
  if (!sheet.MatchesMediaQueries(EnsureMediaQueryEvaluator())) {
    return nullptr;
  }
  return &sheet.Contents()->EnsureRuleSet(*media_query_evaluator_);
}

RuleSet* StyleEngine::RuleSetScope::RuleSetForSheet(StyleEngine& engine,
                                                    CSSStyleSheet* css_sheet) {
  RuleSet* rule_set = engine.RuleSetForSheet(*css_sheet);
  if (rule_set && rule_set->HasCascadeLayers() &&
      !css_sheet->Contents()->HasSingleOwnerNode() &&
      !layer_rule_sets_.insert(rule_set).is_new_entry) {
    // The condition above is met for a stylesheet with cascade layers which
    // shares StyleSheetContents with another stylesheet in this TreeScope.
    // WillMutateRules() creates a unique StyleSheetContents for this sheet to
    // avoid incorrectly identifying two separate anonymous layers as the same
    // layer.
    css_sheet->WillMutateRules();
    rule_set = engine.RuleSetForSheet(*css_sheet);
  }
  return rule_set;
}

void StyleEngine::ClearResolvers() {
  DCHECK(!GetDocument().InStyleRecalc());

  GetDocument().ClearScopedStyleResolver();
  for (TreeScope* tree_scope : active_tree_scopes_) {
    tree_scope->ClearScopedStyleResolver();
  }

  if (resolver_) {
    TRACE_EVENT1("blink", "StyleEngine::clearResolver", "frame",
                 GetFrameIdForTracing(GetDocument().GetFrame()));
    resolver_->Dispose();
    resolver_.Clear();
  }
}

void StyleEngine::DidDetach() {
  ClearResolvers();
  if (global_rule_set_) {
    global_rule_set_->Dispose();
  }
  global_rule_set_ = nullptr;
  dirty_tree_scopes_.clear();
  active_tree_scopes_.clear();
  viewport_resolver_ = nullptr;
  media_query_evaluator_ = nullptr;
  style_invalidation_root_.Clear();
  style_recalc_root_.Clear();
  layout_tree_rebuild_root_.Clear();
  if (font_selector_) {
    font_selector_->GetFontFaceCache()->ClearAll();
  }
  font_selector_ = nullptr;
  if (environment_variables_) {
    environment_variables_->DetachFromParent();
  }
  environment_variables_ = nullptr;
  style_containment_scope_tree_ = nullptr;
}

bool StyleEngine::ClearFontFaceCacheAndAddUserFonts(
    const ActiveStyleSheetVector& user_sheets) {
  bool fonts_changed = false;

  if (font_selector_ &&
      font_selector_->GetFontFaceCache()->ClearCSSConnected()) {
    fonts_changed = true;
    if (resolver_) {
      resolver_->InvalidateMatchedPropertiesCache();
    }
  }

  // Rebuild the font cache with @font-face rules from user style sheets.
  for (unsigned i = 0; i < user_sheets.size(); ++i) {
    DCHECK(user_sheets[i].second);
    if (AddUserFontFaceRules(*user_sheets[i].second)) {
      fonts_changed = true;
    }
  }

  return fonts_changed;
}

void StyleEngine::UpdateGenericFontFamilySettings() {
  // FIXME: we should not update generic font family settings when
  // document is inactive.
  DCHECK(GetDocument().IsActive());

  if (!font_selector_) {
    return;
  }

  font_selector_->UpdateGenericFontFamilySettings(*document_);
  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  FontCache::Get().InvalidateShapeCache();
}

void StyleEngine::RemoveFontFaceRules(
    const HeapVector<Member<const StyleRuleFontFace>>& font_face_rules) {
  if (!font_selector_) {
    return;
  }

  FontFaceCache* cache = font_selector_->GetFontFaceCache();
  for (const auto& rule : font_face_rules) {
    cache->Remove(rule);
  }
  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
}

void StyleEngine::MarkTreeScopeDirty(TreeScope& scope) {
  if (scope == document_) {
    MarkDocumentDirty();
    return;
  }

  TreeScopeStyleSheetCollection* collection = StyleSheetCollectionFor(scope);
  DCHECK(collection);
  collection->MarkSheetListDirty();
  dirty_tree_scopes_.insert(&scope);
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::MarkDocumentDirty() {
  document_scope_dirty_ = true;
  document_style_sheet_collection_->MarkSheetListDirty();
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::MarkUserStyleDirty() {
  user_style_dirty_ = true;
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::MarkViewportStyleDirty() {
  viewport_style_dirty_ = true;
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

CSSStyleSheet* StyleEngine::CreateSheet(
    Element& element,
    const String& text,
    TextPosition start_position,
    PendingSheetType type,
    RenderBlockingBehavior render_blocking_behavior) {
  DCHECK(element.GetDocument() == GetDocument());
  CSSStyleSheet* style_sheet = nullptr;

  if (type != PendingSheetType::kNonBlocking) {
    AddPendingBlockingSheet(element, type);
  }

  // The style sheet text can be long; hundreds of kilobytes. In order not to
  // insert such a huge string into the AtomicString table, we take its hash
  // instead and use that. (This is not a cryptographic hash, so a page could
  // cause collisions if it wanted to, but only within its own renderer.)
  // Note that in many cases, we won't actually be able to free the
  // memory used by the string, since it may e.g. be already stuck in
  // the DOM (as text contents of the <style> tag), but it may eventually
  // be parked (compressed, or stored to disk) if there's memory pressure,
  // or otherwise dropped, so this keeps us from being the only thing
  // that keeps it alive.
  AtomicString key;
  if (text.length() >= 1024) {
    size_t digest = FastHash(text.RawByteSpan());
    key = AtomicString(base::byte_span_from_ref(digest));
  } else {
    key = AtomicString(text);
  }

  auto result = text_to_sheet_cache_.insert(key, nullptr);
  StyleSheetContents* contents = result.stored_value->value;
  if (result.is_new_entry || !contents ||
      !contents->IsCacheableForStyleElement()) {
    result.stored_value->value = nullptr;
    style_sheet =
        ParseSheet(element, text, start_position, render_blocking_behavior);
    if (style_sheet->Contents()->IsCacheableForStyleElement()) {
      result.stored_value->value = style_sheet->Contents();
    }
  } else {
    DCHECK(contents);
    DCHECK(contents->IsCacheableForStyleElement());
    DCHECK(contents->HasSingleOwnerDocument());
    contents->SetIsUsedFromTextCache();
    style_sheet =
        CSSStyleSheet::CreateInline(contents, element, start_position);
  }

  DCHECK(style_sheet);
  if (!element.IsInShadowTree()) {
    String title = element.title();
    if (!title.empty()) {
      style_sheet->SetTitle(title);
      SetPreferredStylesheetSetNameIfNotSet(title);
    }
  }
  return style_sheet;
}

CSSStyleSheet* StyleEngine::ParseSheet(
    Element& element,
    const String& text,
    TextPosition start_position,
    RenderBlockingBehavior render_blocking_behavior) {
  CSSStyleSheet* style_sheet = nullptr;
  style_sheet = CSSStyleSheet::CreateInline(element, NullURL(), start_position,
                                            GetDocument().Encoding());
  style_sheet->Contents()->SetRenderBlocking(render_blocking_behavior);
  style_sheet->Contents()->ParseString(text);
  return style_sheet;
}

void StyleEngine::CollectUserStyleFeaturesTo(RuleFeatureSet& features) const {
  for (unsigned i = 0; i < active_user_style_sheets_.size(); ++i) {
    CSSStyleSheet* sheet = active_user_style_sheets_[i].first;
    features.MutableMediaQueryResultFlags().Add(
        sheet->GetMediaQueryResultFlags());
    DCHECK(sheet->Contents()->HasRuleSet());
    features.Merge(sheet->Contents()->GetRuleSet().Features());
  }
}

void StyleEngine::CollectScopedStyleFeaturesTo(RuleFeatureSet& features) const {
  HeapHashSet<Member<const StyleSheetContents>>
      visited_shared_style_sheet_contents;
  if (GetDocument().GetScopedStyleResolver()) {
    GetDocument().GetScopedStyleResolver()->CollectFeaturesTo(
        features, visited_shared_style_sheet_contents);
  }
  for (TreeScope* tree_scope : active_tree_scopes_) {
    if (ScopedStyleResolver* resolver = tree_scope->GetScopedStyleResolver()) {
      resolver->CollectFeaturesTo(features,
                                  visited_shared_style_sheet_contents);
    }
  }
}

void StyleEngine::MarkViewportUnitDirty(ViewportUnitFlag flag) {
  if (viewport_unit_dirty_flags_ & static_cast<unsigned>(flag)) {
    return;
  }

  viewport_unit_dirty_flags_ |= static_cast<unsigned>(flag);
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

namespace {

template <typename Func>
void MarkElementsForRecalc(TreeScope& tree_scope,
                           const StyleChangeReasonForTracing& reason,
                           Func predicate) {
  for (Element* element = ElementTraversal::FirstWithin(tree_scope.RootNode());
       element; element = ElementTraversal::NextIncludingPseudo(*element)) {
    if (ShadowRoot* root = element->GetShadowRoot()) {
      MarkElementsForRecalc(*root, reason, predicate);
    }
    const ComputedStyle* style = element->GetComputedStyle();
    if (style && predicate(*style)) {
      element->SetNeedsStyleRecalc(kLocalStyleChange, reason);
    }
  }
}

}  // namespace

void StyleEngine::InvalidateViewportUnitStylesIfNeeded() {
  if (!viewport_unit_dirty_flags_) {
    return;
  }
  unsigned dirty_flags = 0;
  std::swap(viewport_unit_dirty_flags_, dirty_flags);

  // If there are registered custom properties which depend on the invalidated
  // viewport units, it can potentially affect every element.
  if (initial_data_ && (initial_data_->GetViewportUnitFlags() & dirty_flags)) {
    InvalidateInitialData();
    MarkAllElementsForStyleRecalc(StyleChangeReasonForTracing::Create(
        style_change_reason::kViewportUnits));
    return;
  }

  const auto& reason =
      StyleChangeReasonForTracing::Create(style_change_reason::kViewportUnits);
  MarkElementsForRecalc(
      GetDocument(), reason, [dirty_flags](const ComputedStyle& style) {
        return (style.ViewportUnitFlags() & dirty_flags) ||
               style.HighlightPseudoElementStylesDependOnViewportUnits();
      });
}

void StyleEngine::InvalidateStyleAndLayoutForFontUpdates() {
  if (!fonts_need_update_) {
    return;
  }

  TRACE_EVENT0("blink", "StyleEngine::InvalidateStyleAndLayoutForFontUpdates");

  fonts_need_update_ = false;

  if (Element* root = GetDocument().documentElement()) {
    TRACE_EVENT0("blink", "Node::MarkSubtreeNeedsStyleRecalcForFontUpdates");
    root->MarkSubtreeNeedsStyleRecalcForFontUpdates();
  }

  // TODO(xiaochengh): Move layout invalidation after style update.
  if (LayoutView* layout_view = GetDocument().GetLayoutView()) {
    TRACE_EVENT0("blink", "LayoutObject::InvalidateSubtreeForFontUpdates");
    layout_view->InvalidateSubtreeLayoutForFontUpdates();
  }
}

void StyleEngine::MarkFontsNeedUpdate() {
  fonts_need_update_ = true;
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::MarkCounterStylesNeedUpdate() {
  counter_styles_need_update_ = true;
  if (LayoutView* layout_view = GetDocument().GetLayoutView()) {
    layout_view->SetNeedsMarkerOrCounterUpdate();
  }
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::FontsNeedUpdate(FontSelector*, FontInvalidationReason) {
  if (!GetDocument().IsActive()) {
    return;
  }

  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  MarkViewportStyleDirty();
  MarkFontsNeedUpdate();

  probe::FontsUpdated(document_->GetExecutionContext(), nullptr, String(),
                      nullptr);
}

void StyleEngine::PlatformColorsChanged() {
  UpdateForcedBackgroundColor();
  UpdateColorSchemeBackground(/* color_scheme_changed */ true);
  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  MarkAllElementsForStyleRecalc(StyleChangeReasonForTracing::Create(
      style_change_reason::kPlatformColorChange));

  // Invalidate paint so that SVG images can update the preferred color scheme
  // of their document.
  if (auto* view = GetDocument().GetLayoutView()) {
    view->InvalidatePaintForViewAndDescendants();
  }
}

bool StyleEngine::ShouldSkipInvalidationFor(const Element& element) const {
  DCHECK(element.GetDocument() == &GetDocument())
      << "Only schedule invalidations using the StyleEngine of the Document "
         "which owns the element.";
  if (!element.InActiveDocument()) {
    return true;
  }
  if (!global_rule_set_) {
    // TODO(crbug.com/1175902): This is a speculative fix for a crash.
    NOTREACHED()
        << "global_rule_set_ should only be null for inactive documents.";
  }
  if (GetDocument().InStyleRecalc()) {
#if DCHECK_IS_ON()
    // TODO(futhark): The InStyleRecalc() if-guard above should have been a
    // DCHECK(!InStyleRecalc()), but there are a couple of cases where we try to
    // invalidate style from style recalc:
    //
    // 1. We may animate the class attribute of an SVG element and change it
    //    during style recalc when applying the animation effect.
    // 2. We may call SetInlineStyle on elements in a UA shadow tree as part of
    //    style recalc. For instance from HTMLImageFallbackHelper.
    //
    // If there are more cases, we need to adjust the DCHECKs below, but ideally
    // The origin of these invalidations should be fixed.
    if (!element.IsSVGElement()) {
      DCHECK(element.ContainingShadowRoot());
      DCHECK(element.ContainingShadowRoot()->IsUserAgent());
    }
#endif  // DCHECK_IS_ON()
    return true;
  }
  return false;
}

bool StyleEngine::IsSubtreeAndSiblingsStyleDirty(const Element& element) const {
  if (GetDocument().GetStyleChangeType() == kSubtreeStyleChange) {
    return true;
  }
  Element* root = GetDocument().documentElement();
  if (!root || root->GetStyleChangeType() == kSubtreeStyleChange) {
    return true;
  }
  if (!element.parentNode()) {
    return true;
  }
  return element.parentNode()->GetStyleChangeType() == kSubtreeStyleChange;
}

namespace {

bool PossiblyAffectingHasState(Element& element) {
  return element.AncestorsOrAncestorSiblingsAffectedByHas() ||
         element.GetSiblingsAffectedByHasFlags() ||
         element.AffectedByLogicalCombinationsInHas();
}

bool InsertionOrRemovalPossiblyAffectHasStateOfAncestorsOrAncestorSiblings(
    Element* parent) {
  // Only if the parent of the inserted element or subtree has the
  // AncestorsOrAncestorSiblingsAffectedByHas or
  // SiblingsAffectedByHasForSiblingDescendantRelationship flag set, the
  // inserted element or subtree possibly affect the :has() state on its (or the
  // subtree root's) ancestors.
  return parent && (parent->AncestorsOrAncestorSiblingsAffectedByHas() ||
                    parent->HasSiblingsAffectedByHasFlags(
                        SiblingsAffectedByHasFlags::
                            kFlagForSiblingDescendantRelationship));
}

bool InsertionOrRemovalPossiblyAffectHasStateOfPreviousSiblings(
    Element* previous_sibling) {
  // Only if the previous sibling of the inserted element or subtree has the
  // SiblingsAffectedByHas flag set, the inserted element or subtree possibly
  // affect the :has() state on its (or the subtree root's) previous siblings.
  return previous_sibling && previous_sibling->GetSiblingsAffectedByHasFlags();
}

inline Element* SelfOrPreviousSibling(Node* node) {
  if (!node) {
    return nullptr;
  }
  if (Element* element = DynamicTo<Element>(node)) {
    return element;
  }
  return ElementTraversal::PreviousSibling(*node);
}

}  // namespace

void PossiblyScheduleNthPseudoInvalidations(Node& node) {
  if (!node.IsElementNode()) {
    return;
  }
  ContainerNode* parent = node.parentNode();
  if (parent == nullptr) {
    return;
  }

  if ((parent->ChildrenAffectedByForwardPositionalRules() &&
       node.nextSibling()) ||
      (parent->ChildrenAffectedByBackwardPositionalRules() &&
       node.previousSibling())) {
    node.GetDocument().GetStyleEngine().ScheduleNthPseudoInvalidations(*parent);
  }
}

void StyleEngine::InvalidateElementAffectedByHas(
    Element& element,
    bool for_element_affected_by_pseudo_in_has) {
  if (for_element_affected_by_pseudo_in_has &&
      !element.AffectedByPseudoInHas()) {
    return;
  }

  if (element.AffectedBySubjectHas()) {
    // TODO(blee@igalia.com) Need filtering for irrelevant elements.
    // e.g. When we have '.a:has(.b) {}', '.c:has(.d) {}', mutation of class
    // value 'd' can invalidate ancestor with class value 'a' because we
    // don't have any filtering for this case.
    element.SetNeedsStyleRecalc(
        StyleChangeType::kLocalStyleChange,
        StyleChangeReasonForTracing::Create(
            blink::style_change_reason::kAffectedByHas));

    if (GetRuleFeatureSet().GetRuleInvalidationData().UsesHasInsideNth()) {
      PossiblyScheduleNthPseudoInvalidations(element);
    }
  }

  if (element.AffectedByNonSubjectHas()) {
    InvalidationLists invalidation_lists;
    GetRuleFeatureSet()
        .GetRuleInvalidationData()
        .CollectInvalidationSetsForPseudoClass(invalidation_lists, element,
                                               CSSSelector::kPseudoHas);
    pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                           element);
  }
}

// Context class to provide :has() invalidation traversal information.
//
// This class provides this information to the :has() invalidation traversal:
// - first element of the traversal.
// - flag to indicate whether the traversal moves to the parent of the first
//   element.
// - flag to indicate whether the :has() invalidation invalidates the elements
//   with AffectedByPseudoInHas flag set.
class StyleEngine::PseudoHasInvalidationTraversalContext {
  STACK_ALLOCATED();

 public:
  Element* FirstElement() const { return first_element_; }

  // Returns true if the traversal starts at the shadow host for an
  // insertion/removal at a shadow root. In that case we only need to
  // invalidate for that host.
  bool IsFirstElementShadowHost() const {
    return is_first_element_shadow_host_;
  }

  bool TraverseToParentOfFirstElement() const {
    return traverse_to_parent_of_first_element_;
  }

  bool ForElementAffectedByPseudoInHas() const {
    return for_element_affected_by_pseudo_in_has_;
  }

  PseudoHasInvalidationTraversalContext& SetForElementAffectedByPseudoInHas() {
    for_element_affected_by_pseudo_in_has_ = true;
    return *this;
  }

  // Create :has() invalidation traversal context for attribute change or
  // pseudo state change without structural DOM changes.
  static PseudoHasInvalidationTraversalContext ForAttributeOrPseudoStateChange(
      Element& changed_element) {
    bool traverse_ancestors =
        changed_element.AncestorsOrAncestorSiblingsAffectedByHas();

    Element* first_element = nullptr;
    bool is_first_element_shadow_host = false;
    if (traverse_ancestors) {
      first_element = changed_element.parentElement();
      if (!first_element) {
        first_element = changed_element.ParentOrShadowHostElement();
        is_first_element_shadow_host = first_element;
      }
    }

    Element* previous_sibling =
        changed_element.GetSiblingsAffectedByHasFlags()
            ? ElementTraversal::PreviousSibling(changed_element)
            : nullptr;
    if (previous_sibling) {
      first_element = previous_sibling;
      is_first_element_shadow_host = false;
    }

    return PseudoHasInvalidationTraversalContext(
        first_element, is_first_element_shadow_host, traverse_ancestors);
  }

  // Create :has() invalidation traversal context for element or subtree
  // insertion.
  static PseudoHasInvalidationTraversalContext ForInsertion(
      Element* parent_or_shadow_host,
      bool insert_shadow_root_child,
      Element* previous_sibling) {
    Element* first_element = parent_or_shadow_host;
    bool is_first_element_shadow_host = false;
    bool traverse_ancestors = false;

    if (first_element) {
      traverse_ancestors =
          first_element->AncestorsOrAncestorSiblingsAffectedByHas();
      is_first_element_shadow_host = insert_shadow_root_child;
    }

    if (previous_sibling) {
      first_element = previous_sibling;
      is_first_element_shadow_host = false;
    }

    return PseudoHasInvalidationTraversalContext(
        first_element, is_first_element_shadow_host, traverse_ancestors);
  }

  // Create :has() invalidation traversal context for element or subtree
  // removal. In case of subtree removal, the subtree root element will be
  // passed through the 'removed_element'.
  static PseudoHasInvalidationTraversalContext ForRemoval(
      Element* parent_or_shadow_host,
      bool remove_shadow_root_child,
      Element* previous_sibling,
      Element& removed_element) {
    Element* first_element = nullptr;
    bool is_first_element_shadow_host = false;

    bool traverse_ancestors =
        removed_element.AncestorsOrAncestorSiblingsAffectedByHas();
    if (traverse_ancestors) {
      first_element = parent_or_shadow_host;
      if (first_element) {
        is_first_element_shadow_host = remove_shadow_root_child;
      }
    }

    if (!removed_element.GetSiblingsAffectedByHasFlags()) {
      previous_sibling = nullptr;
    }

    if (previous_sibling) {
      first_element = previous_sibling;
      is_first_element_shadow_host = false;
    }

    return PseudoHasInvalidationTraversalContext(
        first_element, is_first_element_shadow_host, traverse_ancestors);
  }

  // Create :has() invalidation traversal context for removing all children of
  // a parent.
  static PseudoHasInvalidationTraversalContext ForAllChildrenRemoved(
      Element& parent) {
    return PseudoHasInvalidationTraversalContext(
        &parent, /* is_first_element_shadow_host */ false,
        parent.AncestorsOrAncestorSiblingsAffectedByHas());
  }

 private:
  PseudoHasInvalidationTraversalContext(
      Element* first_element,
      bool is_first_element_shadow_host,
      bool traverse_to_parent_of_first_element)
      : first_element_(first_element),
        is_first_element_shadow_host_(is_first_element_shadow_host),
        traverse_to_parent_of_first_element_(
            traverse_to_parent_of_first_element) {}

  // The first element of the :has() invalidation traversal.
  Element* first_element_;

  bool is_first_element_shadow_host_;

  // This flag indicates whether the :has() invalidation traversal moves to the
  // parent of the first element or not.
  bool traverse_to_parent_of_first_element_;

  // This flag indicates that the :has() invalidation invalidates a element
  // only when the element has the AffectedByPseudoInHas flag set. If this flag
  // is true, the :has() invalidation skips the elements that doesn't have the
  // AffectedByPseudoInHas flag set even if the elements have the
  // AffectedBy[Subject|NonSubject]Has flag set.
  //
  // FYI. The AffectedByPseudoInHas flag indicates that the element can be
  // affected by any pseudo state change. (e.g. :hover state change by moving
  // mouse pointer) If an element doesn't have the flag set, it means the
  // element is not affected by any pseudo state change.
  bool for_element_affected_by_pseudo_in_has_{false};
};

void StyleEngine::InvalidateAncestorsOrSiblingsAffectedByHas(
    const PseudoHasInvalidationTraversalContext& traversal_context) {
  bool traverse_to_parent = traversal_context.TraverseToParentOfFirstElement();
  bool traverse_to_previous_sibling = false;
  Element* element = traversal_context.FirstElement();
  bool for_element_affected_by_pseudo_in_has =
      traversal_context.ForElementAffectedByPseudoInHas();
  Element* shadow_host = nullptr;
  if (traversal_context.IsFirstElementShadowHost()) {
    shadow_host = element;
    element = nullptr;
  }

  while (element) {
    traverse_to_parent |= element->AncestorsOrAncestorSiblingsAffectedByHas();
    traverse_to_previous_sibling = element->GetSiblingsAffectedByHasFlags();

    InvalidateElementAffectedByHas(*element,
                                   for_element_affected_by_pseudo_in_has);

    if (traverse_to_previous_sibling) {
      if (Element* previous = ElementTraversal::PreviousSibling(*element)) {
        element = previous;
        continue;
      }
    }

    if (!traverse_to_parent) {
      return;
    }

    if (Element* parent = element->parentElement()) {
      element = parent;
    } else {
      shadow_host = element->ParentOrShadowHostElement();
      element = nullptr;
    }
    traverse_to_parent = false;
  }

  if (shadow_host) {
    InvalidateElementAffectedByHas(*shadow_host,
                                   for_element_affected_by_pseudo_in_has);
  }
}

void StyleEngine::InvalidateChangedElementAffectedByLogicalCombinationsInHas(
    Element& changed_element,
    bool for_element_affected_by_pseudo_in_has) {
  if (!changed_element.AffectedByLogicalCombinationsInHas()) {
    return;
  }
  InvalidateElementAffectedByHas(changed_element,
                                 for_element_affected_by_pseudo_in_has);
}

void StyleEngine::ClassChangedForElement(
    const SpaceSplitString& changed_classes,
    Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  if (rule_invalidation_data.NeedsHasInvalidationForClassChange() &&
      PossiblyAffectingHasState(element)) {
    for (const AtomicString& changed_class : changed_classes) {
      if (rule_invalidation_data.NeedsHasInvalidationForClass(changed_class)) {
        InvalidateChangedElementAffectedByLogicalCombinationsInHas(
            element, /* for_element_affected_by_pseudo_in_has */ false);
        InvalidateAncestorsOrSiblingsAffectedByHas(
            PseudoHasInvalidationTraversalContext::
                ForAttributeOrPseudoStateChange(element));
        break;
      }
    }
  }

  if (IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }

  InvalidationLists invalidation_lists;
  for (const AtomicString& changed_class : changed_classes) {
    rule_invalidation_data.CollectInvalidationSetsForClass(
        invalidation_lists, element, changed_class);
  }
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         element);
}

void StyleEngine::ClassChangedForElement(const SpaceSplitString& old_classes,
                                         const SpaceSplitString& new_classes,
                                         Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }

  if (!old_classes.size()) {
    ClassChangedForElement(new_classes, element);
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  bool needs_schedule_invalidation = !IsSubtreeAndSiblingsStyleDirty(element);
  bool possibly_affecting_has_state =
      rule_invalidation_data.NeedsHasInvalidationForClassChange() &&
      PossiblyAffectingHasState(element);
  if (!needs_schedule_invalidation && !possibly_affecting_has_state) {
    return;
  }

  // Class vectors tend to be very short. This is faster than using a hash
  // table.
  WTF::Vector<bool> remaining_class_bits(old_classes.size());

  InvalidationLists invalidation_lists;
  bool affecting_has_state = false;

  for (const AtomicString& new_class : new_classes) {
    bool found = false;
    for (unsigned i = 0; i < old_classes.size(); ++i) {
      if (new_class == old_classes[i]) {
        // Mark each class that is still in the newClasses so we can skip doing
        // an n^2 search below when looking for removals. We can't break from
        // this loop early since a class can appear more than once.
        remaining_class_bits[i] = true;
        found = true;
      }
    }
    // Class was added.
    if (!found) {
      if (needs_schedule_invalidation) [[likely]] {
        rule_invalidation_data.CollectInvalidationSetsForClass(
            invalidation_lists, element, new_class);
      }
      if (possibly_affecting_has_state) [[unlikely]] {
        if (rule_invalidation_data.NeedsHasInvalidationForClass(new_class)) {
          affecting_has_state = true;
          possibly_affecting_has_state = false;  // Clear to skip check
        }
      }
    }
  }

  for (unsigned i = 0; i < old_classes.size(); ++i) {
    if (remaining_class_bits[i]) {
      continue;
    }
    // Class was removed.
    if (needs_schedule_invalidation) [[likely]] {
      rule_invalidation_data.CollectInvalidationSetsForClass(
          invalidation_lists, element, old_classes[i]);
    }
    if (possibly_affecting_has_state) [[unlikely]] {
      if (rule_invalidation_data.NeedsHasInvalidationForClass(old_classes[i])) {
        affecting_has_state = true;
        possibly_affecting_has_state = false;  // Clear to skip check
      }
    }
  }
  if (needs_schedule_invalidation) {
    pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                           element);
  }

  if (affecting_has_state) {
    InvalidateChangedElementAffectedByLogicalCombinationsInHas(
        element, /* for_element_affected_by_pseudo_in_has */ false);
    InvalidateAncestorsOrSiblingsAffectedByHas(
        PseudoHasInvalidationTraversalContext::ForAttributeOrPseudoStateChange(
            element));
  }
}

namespace {

bool HasAttributeDependentGeneratedContent(const Element& element) {
  DCHECK(!RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled());

  const auto HasAttrFunc = [](PseudoElement* pseudo_element) {
    if (!pseudo_element) {
      return false;
    }

    const ComputedStyle* style = pseudo_element->GetComputedStyle();
    return style && style->HasAttrFunction();
  };

  return HasAttrFunc(element.GetPseudoElement(kPseudoIdCheck)) ||
         HasAttrFunc(element.GetPseudoElement(kPseudoIdBefore)) ||
         HasAttrFunc(element.GetPseudoElement(kPseudoIdAfter)) ||
         HasAttrFunc(element.GetPseudoElement(kPseudoIdSelectArrow)) ||
         HasAttrFunc(element.GetPseudoElement(kPseudoIdScrollMarker));
}

bool HasAttributeDependentStyle(const Element& element) {
  DCHECK(RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled());
  const ComputedStyle* style = element.GetComputedStyle();
  if (style && style->HasAttrFunction()) {
    return true;
  }
  return element.PseudoElementStylesDependOnAttr();
}

}  // namespace

void StyleEngine::AttributeChangedForElement(
    const QualifiedName& attribute_name,
    Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  if (rule_invalidation_data.NeedsHasInvalidationForAttributeChange() &&
      PossiblyAffectingHasState(element)) {
    if (rule_invalidation_data.NeedsHasInvalidationForAttribute(
            attribute_name)) {
      InvalidateChangedElementAffectedByLogicalCombinationsInHas(
          element, /* for_element_affected_by_pseudo_in_has */ false);
      InvalidateAncestorsOrSiblingsAffectedByHas(
          PseudoHasInvalidationTraversalContext::
              ForAttributeOrPseudoStateChange(element));
    }
  }

  if (IsSubtreeAndSiblingsStyleDirty(element)) {
    return;
  }

  InvalidationLists invalidation_lists;
  rule_invalidation_data.CollectInvalidationSetsForAttribute(
      invalidation_lists, element, attribute_name);
  pending_invalidations_.ScheduleInvalidationSetsForNode(invalidation_lists,
                                                         element);

  if (!element.NeedsStyleRecalc()) {
    bool attr_dependent =
        RuntimeEnabledFeatures::CSSAdvancedAttrFunctionEnabled()
            ? HasAttributeDependentStyle(element)
            : HasAttributeDependentGeneratedContent(element);
    if (attr_dependent) {
      element.SetNeedsStyleRecalc(
          kLocalStyleChange,
          StyleChangeReasonForTracing::FromAttribute(attribute_name));
    }
  }
}

void StyleEngine::IdChangedForElement(const AtomicString& old_id,
                                      const AtomicString& new_id,
                                      Element& element) {
  if (ShouldSkipInvalidationFor(element)) {
    return;
  }

  const RuleInvalidationData& rule_invalidation_data =
      GetRuleFeatureSet().GetRuleInvalidationData();

  if (rule_invalidation_data.NeedsHasInvalidationForIdChange() &&
      PossiblyAffectingHasState(element)) {
    if ((!old_id.empty() &&
         rule_invalidation_data.NeedsHasInvalidationForId(old_id)) ||
        (!new_id.empty() &&
         rule_invalidat
```