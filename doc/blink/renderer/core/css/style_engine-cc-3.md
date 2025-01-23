Response:
The user wants to understand the functionality of the `style_engine.cc` file in the Chromium Blink rendering engine, focusing on its relationship with JavaScript, HTML, and CSS. They also want examples of logical reasoning, common user/programming errors, and debugging steps. This is part 4 of a 6-part request, so I need to summarize the functions described in this snippet.

Here's a breakdown of the provided code snippet and the aspects the user is interested in:

1. **`Priority` struct and related functions (`GetPriority`, `AddAndCascade`, `GetLayerOrder`)**: This deals with managing the priority of CSS rules, particularly within cascade layers.
2. **`ApplyUserRuleSetChanges` function**: This function handles changes to user-defined stylesheets, managing various at-rules like `@layer`, `@font-face`, `@keyframes`, `@counter-style`, `@property`, `@font-palette-values`, and `@position-try`.
3. **`ApplyRuleSetChanges` function**: This function handles changes to author stylesheets within a specific `TreeScope` (which can be a document or a shadow tree). It also deals with various at-rules and cascade layers.
4. **`LoadVisionDeficiencyFilter`, `VisionDeficiencyChanged`, `ApplyVisionDeficiencyStyle`**: These functions manage visual filters applied for users with vision deficiencies.
5. **`EnsureMediaQueryEvaluator`**: This function ensures the existence of a media query evaluator.
6. **`StyleMaybeAffectedByLayout`, `UpdateRootFontRelativeUnits`**: These functions relate to how layout affects styles, especially regarding root font relative units (rem, rlh).
7. **`PropertyRegistryChanged`, `EnvironmentVariableChanged`, `InvalidateEnvDependentStylesIfNeeded`**: These functions handle updates related to custom properties and environment variables.
8. **`NodeWillBeRemoved`, `ChildrenRemoved`**: These functions handle style invalidation when nodes are removed from the DOM.
9. **`CollectMatchingUserRules`**: This function collects user-defined CSS rules that match a given element.
10. **`ClearKeyframeRules`, `ClearPropertyRules`**: These functions clear cached keyframe and custom property rules.
11. **`AddPropertyRulesFromSheets`, `AddFontPaletteValuesRulesFromSheets`**: These functions add custom property and font palette rules from stylesheets.
12. **`AddUserFontFaceRules`, `AddUserKeyframeRules`, `AddUserKeyframeStyle`, `UserKeyframeStyleShouldOverride`**: These functions handle the addition and management of user-defined `@font-face` and `@keyframes` rules.
13. **`AddViewTransitionRules`**: This function handles the addition of `@view-transition` rules.
14. **`AddFontPaletteValuesRules`, `AddPropertyRules`**: These functions add specific types of at-rules.
15. **`KeyframeStylesForAnimation`, `FontPaletteValuesForNameAndFamily`**: These functions retrieve specific keyframe and font palette rules by name.
16. **`EnsureEnvironmentVariables`**: This function ensures the existence of a style environment variables object.
17. **`MaybeCreateAndGetInitialData`**: This function creates and retrieves initial style data based on registered custom properties.
18. **`RecalcHighlightStylesForContainer`**: This function recalculates styles for highlight pseudo-elements on container elements.
19. **`RecalcStyleForContainer`, `UpdateStyleForNonEligibleContainer`, `UpdateStyleAndLayoutTreeForContainer`**: These functions are involved in triggering and managing style recalculation for container queries.

Based on this, I can address each of the user's points and then summarize the functionality covered in this snippet.
这是对 `blink/renderer/core/css/style_engine.cc` 文件代码片段的功能总结：

**归纳：**

这段代码主要负责 **应用和管理 CSS 规则的变更，特别是用户样式表的变更，以及处理与 CSS 特性相关的特定 at-规则（如 `@layer`, `@font-face`, `@keyframes`, `@counter-style`, `@property`, `@font-palette-values`, `@view-transition`）**。 它还涉及处理视觉缺陷滤镜、媒体查询、根字体相对单位、自定义属性、环境变化，以及在 DOM 节点移除时进行样式失效处理。  此外，还涵盖了与容器查询相关的样式重算逻辑。

**详细功能列举和说明：**

1. **管理 CSS 规则优先级 (Cascading):**
    *   定义了 `Priority` 结构体，用于比较 CSS 规则的优先级，考虑了是否是用户样式以及层叠层 (cascade layer) 的顺序。
    *   `GetPriority` 函数根据是否是用户样式以及层叠层信息生成 `Priority` 对象。
    *   `AddAndCascade` 函数用于添加带有优先级的 CSS 规则名称到内部映射中，并确保只有最高优先级的同名规则被保留。
    *   `GetLayerOrder` 函数根据是否是用户样式以及层叠层对象，获取该层的排序值。

    **与 CSS 的关系举例：**
    *   假设有两个样式规则都设置了同一个元素的颜色：一个是普通的作者样式 `color: blue;`，另一个是用户样式 `color: red !important;`。`Priority` 结构体会将用户样式标记为更高优先级，`AddAndCascade` 会确保最终应用的是红色。
    *   使用了 `@layer` 声明了层叠层，例如 `@layer utilities, theme;`，`GetLayerOrder` 会根据这个声明返回 `utilities` 和 `theme` 对应的层级顺序，用于确定规则优先级。

2. **应用用户样式表变更 (`ApplyUserRuleSetChanges`):**
    *   比较旧的和新的用户样式表列表，找出发生变化的规则集。
    *   当用户样式表添加或移除时，会标记全局规则集为脏，需要重新聚合规则元数据。
    *   处理 `@layer` 规则的变更，重建用户层叠层映射 `user_cascade_layer_map_`，并可能导致匹配属性缓存失效和整个文档的样式重算。
    *   处理 `@font-face` 规则的变更，可能需要重建字体缓存。
    *   处理 `@keyframes` 规则的变更，添加或移除用户定义的动画关键帧规则。
    *   处理 `@counter-style` 规则的变更，管理用户定义的计数器样式。
    *   处理 `@property` 规则的变更，注册或移除 CSS 自定义属性。
    *   处理 `@font-palette-values` 规则的变更，管理用户定义的字体调色板值。
    *   处理 `@position-try` 规则的变更（当前版本代码中注释说明尚未支持用户样式表）。
    *   调用 `InvalidateForRuleSetChanges` 来触发受影响元素的样式失效。

    **与 HTML, CSS, JavaScript 的关系举例：**
    *   **HTML:** 用户可以通过浏览器的开发者工具或者浏览器扩展插入自定义 CSS 规则。
    *   **CSS:**  `ApplyUserRuleSetChanges` 直接处理用户编写的 CSS 规则，例如用户添加了 `body { font-size: 18px; }`。
    *   **JavaScript:** JavaScript 可以通过 `document.styleSheets` API 修改或添加样式表，这些修改会最终触发 `ApplyUserRuleSetChanges`。例如，一个浏览器扩展可以使用 JavaScript 添加自定义样式表来改变网页的主题。

    **假设输入与输出：**
    *   **假设输入：** 用户通过浏览器开发者工具添加了新的 CSS 规则：`div.important { color: purple !important; }`。`old_style_sheets` 不包含这个规则，`new_style_sheets` 包含这个规则。
    *   **输出：** `ApplyUserRuleSetChanges` 会检测到 `new_style_sheets` 中新增了规则，标记全局规则集为脏，并可能触发样式重算，使得所有 class 为 `important` 的 `div` 元素颜色变为紫色。

3. **应用样式表变更 (非用户样式) (`ApplyRuleSetChanges`):**
    *   类似于 `ApplyUserRuleSetChanges`，但处理的是作者样式表的变更，适用于特定的 `TreeScope`（例如，文档或 Shadow DOM）。
    *   可以处理更细粒度的规则集差异 (`RuleSetDiff`)。
    *   处理层叠层、关键帧、计数器样式等 at-规则的变更。
    *   根据变更类型和作用域，决定是否需要重建层叠层映射、重置样式、或仅追加新的样式表。

    **与 HTML, CSS, JavaScript 的关系举例：**
    *   **HTML:**  HTML 文档中通过 `<link>` 标签引入的外部 CSS 文件或 `<style>` 标签内的样式发生变化。
    *   **CSS:** `ApplyRuleSetChanges` 处理这些 CSS 规则的添加、删除或修改。
    *   **JavaScript:** JavaScript 可以动态创建和添加 `<style>` 标签，或者修改现有样式表的内容，这些操作会触发 `ApplyRuleSetChanges`。

    **假设输入与输出：**
    *   **假设输入：** JavaScript 代码动态创建了一个新的 `<style>` 标签并添加到文档的 `<head>` 中，内容为 `span { font-weight: bold; }`。`old_style_sheets` 不包含这个规则，`new_style_sheets` 包含这个规则。
    *   **输出：** `ApplyRuleSetChanges` 会检测到新增的样式表，并触发样式更新，使得文档中所有的 `span` 元素字体加粗。

4. **视觉缺陷滤镜 (`LoadVisionDeficiencyFilter`, `VisionDeficiencyChanged`, `ApplyVisionDeficiencyStyle`):**
    *   `LoadVisionDeficiencyFilter` 加载与用户设置的视觉缺陷类型对应的 SVG 滤镜。
    *   `VisionDeficiencyChanged` 在用户的视觉缺陷设置改变时被调用，标记视口样式为脏。
    *   `ApplyVisionDeficiencyStyle` 将加载的滤镜应用到布局视图的样式构建器中。

    **与 CSS 的关系举例：**
    *   虽然不是直接的 CSS 规则，但视觉缺陷滤镜通过 CSS `filter` 属性应用，修改元素的渲染效果。

    **用户操作到达此处：**
    1. 用户在操作系统或浏览器设置中启用了视觉辅助功能，例如模拟某种色盲。
    2. 浏览器检测到该设置的更改。
    3. Blink 渲染引擎接收到视觉缺陷类型的信息。
    4. `VisionDeficiencyChanged` 被调用，标记样式为脏。
    5. 在样式计算过程中，`ApplyVisionDeficiencyStyle` 被调用。
    6. `LoadVisionDeficiencyFilter` 根据视觉缺陷类型创建或获取相应的 SVG 滤镜 URL。
    7. 该 SVG 滤镜被加载。
    8. `ApplyVisionDeficiencyStyle` 将该滤镜添加到根元素的样式中，影响整个页面的渲染。

5. **媒体查询评估器 (`EnsureMediaQueryEvaluator`):**
    *   确保 `MediaQueryEvaluator` 对象存在，用于评估 CSS 媒体查询的结果。

    **与 CSS 的关系举例：**
    *   当 CSS 中包含媒体查询（例如 `@media (max-width: 768px) { ... }`）时，`MediaQueryEvaluator` 会根据当前的视口大小和其他环境因素来判断这些规则是否应该应用。

6. **布局对样式的影响 (`StyleMaybeAffectedByLayout`, `UpdateRootFontRelativeUnits`):**
    *   `StyleMaybeAffectedByLayout` 判断元素的样式是否可能受到布局的影响。
    *   `UpdateRootFontRelativeUnits` 检测根元素的字体大小或行高是否发生变化，如果使用了 `rem` 或 `rlh` 单位，则需要失效匹配属性缓存。

    **与 CSS 的关系举例：**
    *   **CSS 单位:** `rem` 单位依赖于根元素的字体大小，`rlh` 单位依赖于根元素的行高。如果根元素的这些属性改变，使用这些单位的元素的样式也需要更新。

7. **自定义属性和环境变化 (`PropertyRegistryChanged`, `EnvironmentVariableChanged`, `InvalidateEnvDependentStylesIfNeeded`):**
    *   `PropertyRegistryChanged` 在自定义属性注册表发生变化时调用，标记所有元素需要重新计算样式。
    *   `EnvironmentVariableChanged` 在 CSS 环境变量发生变化时调用，标记环境为脏。
    *   `InvalidateEnvDependentStylesIfNeeded` 根据环境脏标记，失效依赖于环境变量的样式。

    **与 CSS 的关系举例：**
    *   **CSS 自定义属性:** 当使用 CSS 自定义属性（例如 `--main-color: blue;`）并通过 JavaScript 修改时，`PropertyRegistryChanged` 会被调用。
    *   **CSS 环境变量:**  当 CSS 中使用 `env()` 函数访问环境变量，例如 `color: env(--theme-color);`，环境变量的值变化时，`EnvironmentVariableChanged` 和 `InvalidateEnvDependentStylesIfNeeded` 会确保样式更新。

8. **节点移除时的样式失效 (`NodeWillBeRemoved`, `ChildrenRemoved`):**
    *   `NodeWillBeRemoved` 在节点即将被移除时调用，检查该节点是否包含影响计数器的样式，并标记计数器为脏。
    *   `ChildrenRemoved` 在容器节点的子节点被移除后调用，更新样式失效和重算的根节点。

    **与 HTML, CSS 的关系举例：**
    *   **HTML 结构变化:** 当 JavaScript 从 DOM 中删除一个元素时，这些函数会被调用，确保与该元素相关的样式（包括计数器样式）被正确更新。

9. **收集匹配的用户规则 (`CollectMatchingUserRules`):**
    *   遍历激活的用户样式表，收集与指定元素匹配的 CSS 规则。

    **与 HTML, CSS 的关系举例：**
    *   这在样式计算过程中用于查找适用于特定元素的用户定义的 CSS 规则。

10. **清除规则缓存 (`ClearKeyframeRules`, `ClearPropertyRules`):**
    *   `ClearKeyframeRules` 清除关键帧规则的缓存。
    *   `ClearPropertyRules` 移除已声明的自定义属性。

11. **从样式表添加规则 (`AddPropertyRulesFromSheets`, `AddFontPaletteValuesRulesFromSheets`):**
    *   从给定的样式表中提取并添加自定义属性规则和字体调色板值规则。

12. **添加用户定义的规则 (`AddUserFontFaceRules`, `AddUserKeyframeRules`, `AddUserKeyframeStyle`, `UserKeyframeStyleShouldOverride`):**
    *   处理用户定义的 `@font-face` 和 `@keyframes` 规则的添加和管理。
    *   `UserKeyframeStyleShouldOverride` 判断新的用户关键帧规则是否应该覆盖已有的规则。

13. **添加视图过渡规则 (`AddViewTransitionRules`):**
    *   处理 `@view-transition` 规则的添加，用于视图过渡动画。

14. **添加特定类型的规则 (`AddFontPaletteValuesRules`, `AddPropertyRules`):**
    *   分别添加字体调色板值规则和自定义属性规则到相应的映射中。

15. **按名称查找规则 (`KeyframeStylesForAnimation`, `FontPaletteValuesForNameAndFamily`):**
    *   根据动画名称查找对应的关键帧规则。
    *   根据调色板名称和字体族查找对应的字体调色板值规则。

16. **确保环境对象存在 (`EnsureEnvironmentVariables`):**
    *   创建并返回文档的样式环境变量对象。

17. **创建和获取初始样式数据 (`MaybeCreateAndGetInitialData`):**
    *   基于注册的自定义属性创建并返回初始样式数据。

18. **重算高亮样式 (`RecalcHighlightStylesForContainer`):**
    *   针对容器元素，重新计算其高亮伪元素的样式，尤其是在这些样式依赖于容器查询时。

19. **容器的样式重算 (`RecalcStyleForContainer`, `UpdateStyleForNonEligibleContainer`, `UpdateStyleAndLayoutTreeForContainer`):**
    *   这些函数负责触发和管理容器查询相关的样式重算和布局更新。
    *   `RecalcStyleForContainer`  对容器元素及其子元素进行样式重算。
    *   `UpdateStyleForNonEligibleContainer` 处理因布局限制而跳过样式重算的容器。
    *   `UpdateStyleAndLayoutTreeForContainer`  在容器尺寸变化时更新样式和布局树。

**用户或编程常见的使用错误举例：**

*   **CSS 优先级问题：**  用户或开发者可能不理解 CSS 优先级规则，导致预期的样式没有生效。例如，在一个更具体的选择器中定义的样式被一个 `!important` 标记的通用选择器覆盖。调试时，开发者可能会在此文件中检查 `Priority` 和 `AddAndCascade` 的行为，以理解为什么某个规则没有生效。
*   **用户样式覆盖：** 用户自定义的样式可能意外地覆盖了网站的正常样式，导致页面显示异常。例如，用户设置了 `* { color: red; }`，导致所有文本都变成红色。开发者可能需要检查 `ApplyUserRuleSetChanges` 的逻辑，查看用户样式是如何应用的。
*   **`@layer` 使用不当：**  对 `@layer` 的声明顺序理解错误，导致层叠顺序不符合预期，使得某些层内的样式规则优先级低于预期。调试时，开发者可能需要查看 `GetLayerOrder` 的返回值来理解层叠顺序。
*   **动态添加样式表的性能问题：**  频繁地通过 JavaScript 动态添加或修改大型样式表可能导致性能问题，因为这会触发 `ApplyRuleSetChanges` 并可能导致大量的样式重算。

**用户操作到达此处的调试线索：**

假设开发者想要调试一个问题，即用户自定义的某个样式没有生效。以下是可能的操作步骤，最终可能会涉及到 `style_engine.cc`：

1. **用户报告问题：** 用户反馈在他们的浏览器中，某个网站的样式显示不正确，与预期不符。
2. **开发者检查用户样式：** 开发者怀疑是用户自定义的样式影响了页面，于是在浏览器的开发者工具中查看 "渲染" 或 "样式" 相关的面板，确认用户是否添加了自定义 CSS。
3. **分析用户样式表：** 开发者查看用户添加的 CSS 规则，尝试理解这些规则是如何与网站自身的样式冲突的。
4. **断点调试 Blink 渲染引擎：**  如果问题比较复杂，开发者可能需要在 Blink 渲染引擎的源代码中设置断点，例如在 `ApplyUserRuleSetChanges` 函数入口处，来跟踪用户样式表的变化是如何被处理的。
5. **观察规则优先级：**  开发者可能会单步执行代码，观察 `Priority` 对象的创建和比较过程，以理解为什么用户定义的样式最终没有生效（例如，优先级低于作者样式）。
6. **检查层叠层顺序：** 如果涉及到 `@layer`，开发者可能会查看 `GetLayerOrder` 的返回值，确认层叠顺序是否正确。
7. **分析样式失效：** 如果问题涉及到动态添加样式或 DOM 结构变化，开发者可能会检查 `InvalidateForRuleSetChanges` 或 `NodeWillBeRemoved` 等函数，理解样式失效是如何触发的。

总而言之，`style_engine.cc` 中的这段代码是 Blink 渲染引擎处理 CSS 样式变更的核心部分，尤其关注用户自定义样式以及各种高级 CSS 特性的实现和管理。 开发者理解这段代码的逻辑，有助于诊断和解决与样式渲染相关的各种问题。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
if (is_user_style != other.is_user_style) {
        return is_user_style;
      }
      return layer_order < other.layer_order;
    }
  };

  Priority GetPriority(bool is_user_style, const CascadeLayer* layer) {
    return Priority{is_user_style, GetLayerOrder(is_user_style, layer)};
  }

  // Returns true if this is the first rule with the name, or if this has a
  // higher priority than all the previously added rules with the same name.
  bool AddAndCascade(const AtomicString& name, Priority priority) {
    auto add_result = map_.insert(name, priority);
    if (add_result.is_new_entry) {
      return true;
    }
    if (priority < add_result.stored_value->value) {
      return false;
    }
    add_result.stored_value->value = priority;
    return true;
  }

 private:
  uint16_t GetLayerOrder(bool is_user_style, const CascadeLayer* layer) {
    if (!layer) {
      return CascadeLayerMap::kImplicitOuterLayerOrder;
    }
    const CascadeLayerMap* layer_map = nullptr;
    if (is_user_style) {
      layer_map = document_.GetStyleEngine().GetUserCascadeLayerMap();
    } else if (document_.GetScopedStyleResolver()) {
      layer_map = document_.GetScopedStyleResolver()->GetCascadeLayerMap();
    }
    if (!layer_map) {
      return CascadeLayerMap::kImplicitOuterLayerOrder;
    }
    return layer_map->GetLayerOrder(*layer);
  }

  Document& document_;
  HashMap<AtomicString, Priority> map_;
};

void StyleEngine::ApplyUserRuleSetChanges(
    const ActiveStyleSheetVector& old_style_sheets,
    const ActiveStyleSheetVector& new_style_sheets) {
  DCHECK(global_rule_set_);
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  ActiveSheetsChange change = CompareActiveStyleSheets(
      old_style_sheets, new_style_sheets, /*diffs=*/{}, changed_rule_sets);

  if (change == kNoActiveSheetsChanged) {
    return;
  }

  // With rules added or removed, we need to re-aggregate rule meta data.
  global_rule_set_->MarkDirty();

  unsigned changed_rule_flags = GetRuleSetFlags(changed_rule_sets);

  // Cascade layer map must be built before adding other at-rules, because other
  // at-rules rely on layer order to resolve name conflicts.
  if (changed_rule_flags & kLayerRules) {
    // Rebuild cascade layer map in all cases, because a newly inserted
    // sub-layer can precede an original layer in the final ordering.
    user_cascade_layer_map_ =
        MakeGarbageCollected<CascadeLayerMap>(new_style_sheets);

    if (resolver_) {
      resolver_->InvalidateMatchedPropertiesCache();
    }

    // When we have layer changes other than appended, existing layer ordering
    // may be changed, which requires rebuilding all at-rule registries and
    // full document style recalc.
    if (change == kActiveSheetsChanged) {
      changed_rule_flags = kRuleSetFlagsAll;
    }
  }

  if (changed_rule_flags & kFontFaceRules) {
    if (ScopedStyleResolver* scoped_resolver =
            GetDocument().GetScopedStyleResolver()) {
      // User style and document scope author style shares the font cache. If
      // @font-face rules are added/removed from user stylesheets, we need to
      // reconstruct the font cache because @font-face rules from author style
      // need to be added to the cache after user rules.
      scoped_resolver->SetNeedsAppendAllSheets();
      MarkDocumentDirty();
    } else {
      bool has_rebuilt_font_face_cache =
          ClearFontFaceCacheAndAddUserFonts(new_style_sheets);
      if (has_rebuilt_font_face_cache) {
        GetFontSelector()->FontFaceInvalidated(
            FontInvalidationReason::kGeneralInvalidation);
      }
    }
  }

  if (changed_rule_flags & kKeyframesRules) {
    if (change == kActiveSheetsChanged) {
      ClearKeyframeRules();
    }

    for (const auto& sheet : new_style_sheets) {
      DCHECK(sheet.second);
      AddUserKeyframeRules(*sheet.second);
    }
    ScopedStyleResolver::KeyframesRulesAdded(GetDocument());
  }

  if (changed_rule_flags & kCounterStyleRules) {
    if (change == kActiveSheetsChanged && user_counter_style_map_) {
      user_counter_style_map_->Dispose();
    }

    for (const auto& sheet : new_style_sheets) {
      DCHECK(sheet.second);
      if (!sheet.second->CounterStyleRules().empty()) {
        EnsureUserCounterStyleMap().AddCounterStyles(*sheet.second);
      }
    }

    MarkCounterStylesNeedUpdate();
  }

  if (changed_rule_flags &
      (kPropertyRules | kFontPaletteValuesRules | kFontFeatureValuesRules)) {
    if (changed_rule_flags & kPropertyRules) {
      ClearPropertyRules();
      AtRuleCascadeMap cascade_map(GetDocument());
      AddPropertyRulesFromSheets(cascade_map, new_style_sheets,
                                 true /* is_user_style */);
    }

    if (changed_rule_flags & kFontPaletteValuesRules) {
      font_palette_values_rule_map_.clear();
      AddFontPaletteValuesRulesFromSheets(new_style_sheets);
      MarkFontsNeedUpdate();
    }

    // TODO(https://crbug.com/1402199): kFontFeatureValuesRules changes not
    // handled in user sheets.

    // We just cleared all the rules, which includes any author rules. They
    // must be forcibly re-added.
    if (ScopedStyleResolver* scoped_resolver =
            GetDocument().GetScopedStyleResolver()) {
      scoped_resolver->SetNeedsAppendAllSheets();
      MarkDocumentDirty();
    }
  }

  if (changed_rule_flags & kPositionTryRules) {
    // TODO(crbug.com/1383907): @position-try rules are not yet collected from
    // user stylesheets.
    MarkPositionTryStylesDirty(changed_rule_sets);
  }

  InvalidateForRuleSetChanges(GetDocument(), changed_rule_sets,
                              changed_rule_flags, kInvalidateAllScopes);
}

void StyleEngine::ApplyRuleSetChanges(
    TreeScope& tree_scope,
    const ActiveStyleSheetVector& old_style_sheets,
    const ActiveStyleSheetVector& new_style_sheets,
    const HeapVector<Member<RuleSetDiff>>& diffs) {
  DCHECK(global_rule_set_);
  HeapHashSet<Member<RuleSet>> changed_rule_sets;

  ActiveSheetsChange change = CompareActiveStyleSheets(
      old_style_sheets, new_style_sheets, diffs, changed_rule_sets);

  unsigned changed_rule_flags = GetRuleSetFlags(changed_rule_sets);

  bool rebuild_font_face_cache = change == kActiveSheetsChanged &&
                                 (changed_rule_flags & kFontFaceRules) &&
                                 tree_scope.RootNode().IsDocumentNode();
  bool rebuild_at_property_registry = false;
  bool rebuild_at_font_palette_values_map = false;
  ScopedStyleResolver* scoped_resolver = tree_scope.GetScopedStyleResolver();
  if (scoped_resolver && scoped_resolver->NeedsAppendAllSheets()) {
    rebuild_font_face_cache = true;
    rebuild_at_property_registry = true;
    rebuild_at_font_palette_values_map = true;
    change = kActiveSheetsChanged;
  }

  if (change == kNoActiveSheetsChanged) {
    return;
  }

  // With rules added or removed, we need to re-aggregate rule meta data.
  global_rule_set_->MarkDirty();

  if (changed_rule_flags & kKeyframesRules) {
    ScopedStyleResolver::KeyframesRulesAdded(tree_scope);
  }

  if (changed_rule_flags & kCounterStyleRules) {
    MarkCounterStylesNeedUpdate();
  }

  unsigned append_start_index = 0;
  bool rebuild_cascade_layer_map = changed_rule_flags & kLayerRules;
  if (scoped_resolver) {
    // - If all sheets were removed, we remove the ScopedStyleResolver
    // - If new sheets were appended to existing ones, start appending after the
    //   common prefix, and rebuild CascadeLayerMap only if layers are changed.
    // - For other diffs, reset author style and re-add all sheets for the
    //   TreeScope. If new sheets need a CascadeLayerMap, rebuild it.
    if (new_style_sheets.empty()) {
      rebuild_cascade_layer_map = false;
      ResetAuthorStyle(tree_scope);
    } else if (change == kActiveSheetsAppended) {
      append_start_index = old_style_sheets.size();
    } else {
      rebuild_cascade_layer_map = (changed_rule_flags & kLayerRules) ||
                                  scoped_resolver->HasCascadeLayerMap();
      scoped_resolver->ResetStyle();
    }
  }

  if (rebuild_cascade_layer_map) {
    tree_scope.EnsureScopedStyleResolver().RebuildCascadeLayerMap(
        new_style_sheets);
  }

  if (changed_rule_flags & kLayerRules) {
    if (resolver_) {
      resolver_->InvalidateMatchedPropertiesCache();
    }

    // When we have layer changes other than appended, existing layer ordering
    // may be changed, which requires rebuilding all at-rule registries and
    // full document style recalc.
    if (change == kActiveSheetsChanged) {
      changed_rule_flags = kRuleSetFlagsAll;
      if (tree_scope.RootNode().IsDocumentNode()) {
        rebuild_font_face_cache = true;
      }
    }
  }

  if ((changed_rule_flags & kPropertyRules) || rebuild_at_property_registry) {
    // @property rules are (for now) ignored in shadow trees, per spec.
    // https://drafts.css-houdini.org/css-properties-values-api-1/#at-property-rule
    if (tree_scope.RootNode().IsDocumentNode()) {
      ClearPropertyRules();
      AtRuleCascadeMap cascade_map(GetDocument());
      AddPropertyRulesFromSheets(cascade_map, active_user_style_sheets_,
                                 true /* is_user_style */);
      AddPropertyRulesFromSheets(cascade_map, new_style_sheets,
                                 false /* is_user_style */);
    }
  }

  if ((changed_rule_flags & kFontPaletteValuesRules) ||
      rebuild_at_font_palette_values_map) {
    // TODO(crbug.com/1296114): Support @font-palette-values in shadow trees and
    // support scoping correctly.
    if (tree_scope.RootNode().IsDocumentNode()) {
      font_palette_values_rule_map_.clear();
      AddFontPaletteValuesRulesFromSheets(active_user_style_sheets_);
      AddFontPaletteValuesRulesFromSheets(new_style_sheets);
    }
  }

  // The kFontFeatureValuesRules case is handled in
  // tree_scope.EnsureScopedStyleResolver().AppendActiveStyleSheets below.

  if (tree_scope.RootNode().IsDocumentNode()) {
    bool has_rebuilt_font_face_cache = false;
    if (rebuild_font_face_cache) {
      has_rebuilt_font_face_cache =
          ClearFontFaceCacheAndAddUserFonts(active_user_style_sheets_);
    }
    if ((changed_rule_flags & kFontFaceRules) ||
        (changed_rule_flags & kFontPaletteValuesRules) ||
        (changed_rule_flags & kFontFeatureValuesRules) ||
        has_rebuilt_font_face_cache) {
      GetFontSelector()->FontFaceInvalidated(
          FontInvalidationReason::kGeneralInvalidation);
    }
  }

  if (changed_rule_flags & kPositionTryRules) {
    MarkPositionTryStylesDirty(changed_rule_sets);
  }

  if (changed_rule_flags & kViewTransitionRules) {
    // Since a shadow-tree isn't an independent navigable, @view-transition
    // doesn't apply within one.
    if (tree_scope.RootNode().IsDocumentNode()) {
      AddViewTransitionRules(new_style_sheets);
    }
  }

  if (changed_rule_flags & kFunctionRules) {
    // Changes in function can affect function-using declarations
    // in arbitrary ways.
    if (resolver_) {
      resolver_->InvalidateMatchedPropertiesCache();
    }
  }

  if (!new_style_sheets.empty()) {
    tree_scope.EnsureScopedStyleResolver().AppendActiveStyleSheets(
        append_start_index, new_style_sheets);
  }

  InvalidateForRuleSetChanges(tree_scope, changed_rule_sets, changed_rule_flags,
                              kInvalidateCurrentScope);
}

void StyleEngine::LoadVisionDeficiencyFilter() {
  VisionDeficiency old_vision_deficiency = vision_deficiency_;
  vision_deficiency_ = GetDocument().GetPage()->GetVisionDeficiency();
  if (vision_deficiency_ == old_vision_deficiency) {
    return;
  }

  if (vision_deficiency_ == VisionDeficiency::kNoVisionDeficiency) {
    vision_deficiency_filter_ = nullptr;
  } else {
    AtomicString url = CreateVisionDeficiencyFilterUrl(vision_deficiency_);
    cssvalue::CSSURIValue* css_uri_value =
        MakeGarbageCollected<cssvalue::CSSURIValue>(CSSUrlData(url));
    SVGResource* svg_resource = css_uri_value->EnsureResourceReference();
    // Note: The fact that we're using data: URLs here is an
    // implementation detail. Emulating vision deficiencies should still
    // work even if the Document's Content-Security-Policy disallows
    // data: URLs.
    svg_resource->LoadWithoutCSP(GetDocument());
    vision_deficiency_filter_ =
        MakeGarbageCollected<ReferenceFilterOperation>(url, svg_resource);
  }
}

void StyleEngine::VisionDeficiencyChanged() {
  MarkViewportStyleDirty();
}

void StyleEngine::ApplyVisionDeficiencyStyle(
    ComputedStyleBuilder& layout_view_style_builder) {
  LoadVisionDeficiencyFilter();
  if (vision_deficiency_filter_) {
    FilterOperations ops;
    ops.Operations().push_back(vision_deficiency_filter_);
    layout_view_style_builder.SetFilter(ops);
  }
}

const MediaQueryEvaluator& StyleEngine::EnsureMediaQueryEvaluator() {
  if (!media_query_evaluator_) {
    if (GetDocument().GetFrame()) {
      media_query_evaluator_ =
          MakeGarbageCollected<MediaQueryEvaluator>(GetDocument().GetFrame());
    } else {
      media_query_evaluator_ = MakeGarbageCollected<MediaQueryEvaluator>("all");
    }
  }
  return *media_query_evaluator_;
}

bool StyleEngine::StyleMaybeAffectedByLayout(const Element& element) {
  // Note that the StyleAffectedByLayout flag is set based on which
  // ComputedStyles we've resolved previously. Since style resolution may never
  // reach elements in display:none, we defensively treat any null-or-ensured
  // ComputedStyle as affected by layout.
  return StyleAffectedByLayout() ||
         ComputedStyle::IsNullOrEnsured(element.GetComputedStyle());
}

bool StyleEngine::UpdateRootFontRelativeUnits(
    const ComputedStyle* old_root_style,
    const ComputedStyle* new_root_style) {
  if (!new_root_style || !UsesRootFontRelativeUnits()) {
    return false;
  }
  bool rem_changed = !old_root_style || old_root_style->SpecifiedFontSize() !=
                                            new_root_style->SpecifiedFontSize();
  bool root_font_glyphs_changed =
      !old_root_style ||
      (UsesGlyphRelativeUnits() &&
       old_root_style->GetFont() != new_root_style->GetFont());
  bool root_line_height_changed =
      !old_root_style ||
      (UsesLineHeightUnits() &&
       old_root_style->LineHeight() != new_root_style->LineHeight());
  bool root_font_changed =
      rem_changed || root_font_glyphs_changed || root_line_height_changed;
  if (root_font_changed) {
    // Resolved root font relative units are stored in the matched properties
    // cache so we need to make sure to invalidate the cache if the
    // documentElement font size changes.
    GetStyleResolver().InvalidateMatchedPropertiesCache();
    return true;
  }
  return false;
}

void StyleEngine::PropertyRegistryChanged() {
  // TODO(timloh): Invalidate only elements with this custom property set
  MarkAllElementsForStyleRecalc(StyleChangeReasonForTracing::Create(
      style_change_reason::kPropertyRegistration));
  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  InvalidateInitialData();
}

void StyleEngine::EnvironmentVariableChanged() {
  is_env_dirty_ = true;
  if (resolver_) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void StyleEngine::InvalidateEnvDependentStylesIfNeeded() {
  if (!is_env_dirty_) {
    return;
  }
  is_env_dirty_ = false;
  const auto& reason = StyleChangeReasonForTracing::Create(
      style_change_reason::kEnvironmentVariableChanged);
  MarkElementsForRecalc(GetDocument(), reason, [](const ComputedStyle& style) {
    return style.HasEnv();
  });
}

void StyleEngine::NodeWillBeRemoved(Node& node) {
  if (auto* element = DynamicTo<Element>(node)) {
    if (const ComputedStyle* style = element->GetComputedStyle();
        style && style->GetCounterDirectives()) {
      MarkCountersDirty();
    }
    if (element->GetComputedStyle() &&
        element->ComputedStyleRef().ContainsStyle()) {
      MarkCountersDirty();
    }
    if (element->PseudoElementStylesAffectCounters()) {
      MarkCountersDirty();
    }
    if (StyleContainmentScopeTree* tree = GetStyleContainmentScopeTree()) {
      if (element->GetComputedStyle() &&
          element->ComputedStyleRef().ContainsStyle()) {
        tree->RemoveScopeForElement(*element);
      }
    }
    pending_invalidations_.RescheduleSiblingInvalidationsAsDescendants(
        *element);
  }
}

void StyleEngine::ChildrenRemoved(ContainerNode& parent) {
  if (!parent.isConnected()) {
    return;
  }
  DCHECK(!layout_tree_rebuild_root_.GetRootNode());
  if (InDOMRemoval()) {
    // This is necessary for nested removals. There are elements which
    // removes parts of its UA shadow DOM as part of being removed which means
    // we do a removal from within another removal where isConnected() is not
    // completely up to date which would confuse this code. Also, the removal
    // doesn't have to be in the same subtree as the outer removal. For instance
    // for the ListAttributeTargetChanged mentioned below.
    //
    // Instead we fall back to use the document root as the traversal root for
    // all traversal roots.
    //
    // TODO(crbug.com/882869): MediaControlLoadingPanelElement
    // TODO(crbug.com/888448): TextFieldInputType::ListAttributeTargetChanged
    if (style_invalidation_root_.GetRootNode()) {
      UpdateStyleInvalidationRoot(nullptr, nullptr);
    }
    if (style_recalc_root_.GetRootNode()) {
      UpdateStyleRecalcRoot(nullptr, nullptr);
    }
    return;
  }
  style_invalidation_root_.SubtreeModified(parent);
  style_recalc_root_.SubtreeModified(parent);
}

void StyleEngine::CollectMatchingUserRules(
    ElementRuleCollector& collector) const {
  MatchRequest match_request;
  for (const ActiveStyleSheet& style_sheet : active_user_style_sheets_) {
    match_request.AddRuleset(style_sheet.second);
    if (match_request.IsFull()) {
      collector.CollectMatchingRules(match_request, /*part_names*/ nullptr);
      match_request.ClearAfterMatching();
    }
  }
  if (!match_request.IsEmpty()) {
    collector.CollectMatchingRules(match_request, /*part_names*/ nullptr);
  }
}

void StyleEngine::ClearKeyframeRules() {
  keyframes_rule_map_.clear();
}

void StyleEngine::ClearPropertyRules() {
  PropertyRegistration::RemoveDeclaredProperties(GetDocument());
}

void StyleEngine::AddPropertyRulesFromSheets(
    AtRuleCascadeMap& cascade_map,
    const ActiveStyleSheetVector& sheets,
    bool is_user_style) {
  for (const ActiveStyleSheet& active_sheet : sheets) {
    if (RuleSet* rule_set = active_sheet.second) {
      AddPropertyRules(cascade_map, *rule_set, is_user_style);
    }
  }
}

void StyleEngine::AddFontPaletteValuesRulesFromSheets(
    const ActiveStyleSheetVector& sheets) {
  for (const ActiveStyleSheet& active_sheet : sheets) {
    if (RuleSet* rule_set = active_sheet.second) {
      AddFontPaletteValuesRules(*rule_set);
    }
  }
}

bool StyleEngine::AddUserFontFaceRules(const RuleSet& rule_set) {
  if (!font_selector_) {
    return false;
  }

  const HeapVector<Member<StyleRuleFontFace>> font_face_rules =
      rule_set.FontFaceRules();
  for (auto& font_face_rule : font_face_rules) {
    if (FontFace* font_face = FontFace::Create(document_, font_face_rule,
                                               true /* is_user_style */)) {
      font_selector_->GetFontFaceCache()->Add(font_face_rule, font_face);
    }
  }
  if (resolver_ && font_face_rules.size()) {
    resolver_->InvalidateMatchedPropertiesCache();
  }
  return font_face_rules.size();
}

void StyleEngine::AddUserKeyframeRules(const RuleSet& rule_set) {
  const HeapVector<Member<StyleRuleKeyframes>> keyframes_rules =
      rule_set.KeyframesRules();
  for (unsigned i = 0; i < keyframes_rules.size(); ++i) {
    AddUserKeyframeStyle(keyframes_rules[i]);
  }
}

void StyleEngine::AddUserKeyframeStyle(StyleRuleKeyframes* rule) {
  AtomicString animation_name(rule->GetName());

  KeyframesRuleMap::iterator it = keyframes_rule_map_.find(animation_name);
  if (it == keyframes_rule_map_.end() ||
      UserKeyframeStyleShouldOverride(rule, it->value)) {
    keyframes_rule_map_.Set(animation_name, rule);
  }
}

bool StyleEngine::UserKeyframeStyleShouldOverride(
    const StyleRuleKeyframes* new_rule,
    const StyleRuleKeyframes* existing_rule) const {
  if (new_rule->IsVendorPrefixed() != existing_rule->IsVendorPrefixed()) {
    return existing_rule->IsVendorPrefixed();
  }
  return !user_cascade_layer_map_ || user_cascade_layer_map_->CompareLayerOrder(
                                         existing_rule->GetCascadeLayer(),
                                         new_rule->GetCascadeLayer()) <= 0;
}

void StyleEngine::AddViewTransitionRules(const ActiveStyleSheetVector& sheets) {
  if (!RuntimeEnabledFeatures::ViewTransitionOnNavigationEnabled()) {
    return;
  }
  view_transition_rule_.Clear();

  for (const ActiveStyleSheet& active_sheet : sheets) {
    RuleSet* rule_set = active_sheet.second;
    if (!rule_set || rule_set->ViewTransitionRules().empty()) {
      continue;
    }

    const CascadeLayerMap* layer_map =
        document_->GetScopedStyleResolver()
            ? document_->GetScopedStyleResolver()->GetCascadeLayerMap()
            : nullptr;
    for (auto& rule : rule_set->ViewTransitionRules()) {
      if (!view_transition_rule_ || !layer_map ||
          layer_map->CompareLayerOrder(view_transition_rule_->GetCascadeLayer(),
                                       rule->GetCascadeLayer()) <= 0) {
        view_transition_rule_ = rule;
      }
    }
  }

  UpdateViewTransitionOptIn();
}

void StyleEngine::AddFontPaletteValuesRules(const RuleSet& rule_set) {
  const HeapVector<Member<StyleRuleFontPaletteValues>>
      font_palette_values_rules = rule_set.FontPaletteValuesRules();
  for (auto& rule : font_palette_values_rules) {
    // TODO(https://crbug.com/1170794): Handle cascade layer reordering here.
    for (auto& family : ConvertFontFamilyToVector(rule->GetFontFamily())) {
      font_palette_values_rule_map_.Set(
          std::make_pair(rule->GetName(), String(family).FoldCase()), rule);
    }
  }
}

void StyleEngine::AddPropertyRules(AtRuleCascadeMap& cascade_map,
                                   const RuleSet& rule_set,
                                   bool is_user_style) {
  const HeapVector<Member<StyleRuleProperty>> property_rules =
      rule_set.PropertyRules();
  for (unsigned i = 0; i < property_rules.size(); ++i) {
    StyleRuleProperty* rule = property_rules[i];
    AtomicString name(rule->GetName());

    PropertyRegistration* registration =
        PropertyRegistration::MaybeCreateForDeclaredProperty(GetDocument(),
                                                             name, *rule);
    if (!registration) {
      continue;
    }

    auto priority =
        cascade_map.GetPriority(is_user_style, rule->GetCascadeLayer());
    if (!cascade_map.AddAndCascade(name, priority)) {
      continue;
    }

    GetDocument().EnsurePropertyRegistry().DeclareProperty(name, *registration);
    PropertyRegistryChanged();
  }
}

StyleRuleKeyframes* StyleEngine::KeyframeStylesForAnimation(
    const AtomicString& animation_name) {
  if (keyframes_rule_map_.empty()) {
    return nullptr;
  }

  KeyframesRuleMap::iterator it = keyframes_rule_map_.find(animation_name);
  if (it == keyframes_rule_map_.end()) {
    return nullptr;
  }

  return it->value.Get();
}

StyleRuleFontPaletteValues* StyleEngine::FontPaletteValuesForNameAndFamily(
    AtomicString palette_name,
    AtomicString family_name) {
  if (font_palette_values_rule_map_.empty() || palette_name.empty()) {
    return nullptr;
  }

  auto it = font_palette_values_rule_map_.find(
      std::make_pair(palette_name, String(family_name).FoldCase()));
  if (it == font_palette_values_rule_map_.end()) {
    return nullptr;
  }

  return it->value.Get();
}

DocumentStyleEnvironmentVariables& StyleEngine::EnsureEnvironmentVariables() {
  if (!environment_variables_) {
    environment_variables_ =
        MakeGarbageCollected<DocumentStyleEnvironmentVariables>(
            StyleEnvironmentVariables::GetRootInstance(), *document_);
  }
  return *environment_variables_.Get();
}

StyleInitialData* StyleEngine::MaybeCreateAndGetInitialData() {
  if (!initial_data_) {
    if (const PropertyRegistry* registry = document_->GetPropertyRegistry()) {
      if (!registry->IsEmpty()) {
        initial_data_ =
            MakeGarbageCollected<StyleInitialData>(GetDocument(), *registry);
      }
    }
  }
  return initial_data_.Get();
}

bool StyleEngine::RecalcHighlightStylesForContainer(Element& container) {
  const ComputedStyle& style = container.ComputedStyleRef();
  // If we depend on container queries we need to update styles, and also
  // the styles for dependents. Hence we return this value, which is used
  // in RecalcStyleForContainer to set the flag for child recalc.
  bool depends_on_container_queries =
      style.HighlightData().DependsOnSizeContainerQueries() ||
      style.HighlightsDependOnSizeContainerQueries();
  if (!style.HasAnyHighlightPseudoElementStyles() ||
      !style.HasNonUaHighlightPseudoStyles() || !depends_on_container_queries) {
    return false;
  }

  // We are recalculating styles for a size container whose highlight pseudo
  // styles depend on size container queries. Make sure we update those styles
  // based on the changed container size.
  StyleRecalcContext recalc_context;
  recalc_context.container = &container;
  if (const ComputedStyle* new_style = container.RecalcHighlightStyles(
          recalc_context, nullptr /* old_style */, style,
          container.ParentComputedStyle());
      new_style != &style) {
    container.SetComputedStyle(new_style);
    container.GetLayoutObject()->SetStyle(new_style,
                                          LayoutObject::ApplyStyleChanges::kNo);
  }

  return depends_on_container_queries;
}

#if DCHECK_IS_ON()
namespace {
bool ContainerStyleChangesAllowed(Element& container,
                                  const ComputedStyle* old_element_style,
                                  const ComputedStyle* old_layout_style) {
  // Generally, the size container element style is not allowed to change during
  // layout, but for highlight pseudo elements depending on queries against
  // their originating element, we need to update the style during layout since
  // the highlight styles hangs off the originating element's ComputedStyle.
  const ComputedStyle* new_element_style = container.GetComputedStyle();
  const ComputedStyle* new_layout_style =
      container.GetLayoutObject() ? container.GetLayoutObject()->Style()
                                  : nullptr;

  if (!new_element_style || !old_element_style) {
    // The container should always have a ComputedStyle.
    return false;
  }
  if (new_element_style != old_element_style) {
    Vector<ComputedStyleBase::DebugDiff> diff =
        old_element_style->DebugDiffFields(*new_element_style);
    // Allow highlight styles to change, but only highlight styles.
    if (diff.size() > 1 ||
        (diff.size() == 1 &&
         diff[0].field != ComputedStyleBase::DebugField::highlight_data_)) {
      return false;
    }
  }
  if (new_layout_style == old_layout_style) {
    return true;
  }
  if (!new_layout_style || !old_element_style) {
    // Container may not have a LayoutObject when called from
    // UpdateStyleForNonEligibleContainer(), but then make sure the style is
    // null for both cases.
    return new_layout_style == old_element_style;
  }
  Vector<ComputedStyleBase::DebugDiff> diff =
      old_layout_style->DebugDiffFields(*new_layout_style);
  // Allow highlight styles to change, but only highlight styles.
  return diff.size() == 0 ||
         (diff.size() == 1 &&
          diff[0].field == ComputedStyleBase::DebugField::highlight_data_);
}
}  // namespace
#endif  // DCHECK_IS_ON()

void StyleEngine::RecalcStyleForContainer(Element& container,
                                          StyleRecalcChange change) {
  // The container node must not need recalc at this point.
  DCHECK(!StyleRecalcChange().ShouldRecalcStyleFor(container));

#if DCHECK_IS_ON()
  const ComputedStyle* old_element_style = container.GetComputedStyle();
  const ComputedStyle* old_layout_style =
      container.GetLayoutObject() ? container.GetLayoutObject()->Style()
                                  : nullptr;
#endif  // DCHECK_IS_ON()

  // If the container itself depends on an outer container, then its
  // DependsOnSizeContainerQueries flag will be set, and we would recalc its
  // style (due to ForceRecalcContainer/ForceRecalcDescendantSizeContainers).
  // This is not necessary, hence we suppress recalc for this element.
  change = change.SuppressRecalc();

  // The StyleRecalcRoot invariants requires the root to be dirty/child-dirty
  container.SetChildNeedsStyleRecalc();
  style_recalc_root_.Update(nullptr, &container);

  if (RecalcHighlightStylesForContainer(container)) {
    change = change.ForceRecalcDescendantSizeContainers();
  }

  // TODO(crbug.com/1145970): Consider use a caching mechanism for FromAncestors
  // as we typically will call it for all containers on the first style/layout
  // pass.
  RecalcStyle(change, StyleRecalcContext::FromAncestors(container));

#if DCHECK_IS_ON()
  DCHECK(ContainerStyleChangesAllowed(container, old_element_style,
                                      old_layout_style));
#endif  // DCHECK_IS_ON()
}

void StyleEngine::UpdateStyleForNonEligibleContainer(Element& container) {
  DCHECK(InRebuildLayoutTree());
  // This method is called from AttachLayoutTree() when we skipped style recalc
  // for descendants of a size query container but figured that the LayoutObject
  // we created is not going to be reached for layout in block_node.cc where
  // we would otherwise resume style recalc.
  //
  // This may be due to legacy layout fallback, inline box, table box, etc.
  // Also, if we could not predict that the LayoutObject would not be created,
  // like if the parent LayoutObject returns false for IsChildAllowed.
  ContainerQueryData* cq_data = container.GetContainerQueryData();
  if (!cq_data) {
    return;
  }

  StyleRecalcChange change;
  ContainerQueryEvaluator& evaluator =
      container.EnsureContainerQueryEvaluator();
  ContainerQueryEvaluator::Change query_change =
      evaluator.SizeContainerChanged(PhysicalSize(), kPhysicalAxesNone);
  switch (query_change) {
    case ContainerQueryEvaluator::Change::kNone:
      DCHECK(cq_data->SkippedStyleRecalc());
      break;
    case ContainerQueryEvaluator::Change::kNearestContainer:
      if (RuntimeEnabledFeatures::CSSFlatTreeContainerEnabled() ||
          !IsShadowHost(container)) {
        change = change.ForceRecalcSizeContainer();
        break;
      }
      // Since the nearest container is found in shadow-including ancestors
      // and not in flat tree ancestors, and style recalc traversal happens in
      // flat tree order, we need to invalidate inside flat tree descendant
      // containers if such containers are inside shadow trees.
      //
      // See also StyleRecalcChange::FlagsForChildren where we turn
      // kRecalcContainer into kRecalcDescendantContainers when traversing
      // past a shadow host.
      [[fallthrough]];
    case ContainerQueryEvaluator::Change::kDescendantContainers:
      change = change.ForceRecalcDescendantSizeContainers();
      break;
  }
  if (query_change != ContainerQueryEvaluator::Change::kNone) {
    container.ComputedStyleRef().ClearCachedPseudoElementStyles();
  }

  AllowMarkForReattachFromRebuildLayoutTreeScope allow_reattach(*this);
  base::AutoReset<bool> cq_recalc(&in_container_query_style_recalc_, true);
  RecalcStyleForContainer(container, change);
}

void StyleEngine::UpdateStyleAndLayoutTreeForContainer(
    Element& container,
    const LogicalSize& logical_size,
    LogicalAxes contained_axes) {
  DCHECK(!style_recalc_root_.GetRootNode());
  DCHECK(!container.NeedsStyleRecalc());
  DCHECK(!in_container_query_style_recalc_);

  base::AutoReset<bool> cq_recalc(&in_container_query_style_recalc_, true);

  DCHECK(container.GetLayoutObject()) << "Containers must have a LayoutObject";
  const ComputedStyle& style = container.GetLayoutObject()->StyleRef();
  DCHECK(style.IsContainerForSizeContainerQueries());
  WritingMode writing_mode = style.GetWritingMode();
  PhysicalSize physical_size = AdjustForAbsoluteZoom::AdjustPhysicalSize(
      ToPhysicalSize(logical_size, writing_mode), style);
  PhysicalAxes physical_axes = ToPhysicalAxes(contained_axes, writing_mode);

  StyleRecalcChange change;

  ContainerQueryEvaluator::Change query_change =
      container.EnsureContainerQueryEvaluator().SizeCon
```