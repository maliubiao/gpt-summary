Response:
The user wants to understand the functionality of the provided C++ code snippet from the Chromium Blink engine's `text_autosizer.cc` file. They're particularly interested in:

1. **General functionality:** What does this code do?
2. **Relationship to web technologies:** How does it interact with JavaScript, HTML, and CSS?
3. **Logic and reasoning:** Can I infer input/output based on the code?
4. **Common errors:** What mistakes might developers make when this code is involved?
5. **Overall purpose:** A high-level summary of the code's role.

Let's break down the code section by section to address these points.

**Section 1: `CreateClusterIfNeeded`**

This function decides whether a new "Cluster" object is needed for a given `LayoutBlock`. Clusters seem to be related to grouping blocks for text autosizing.

*   It checks if the block is a potential root (`POTENTIAL_ROOT` flag).
*   It handles cases where the block is the root of the layout (`LayoutView`).
*   It determines if the block needs its own cluster based on whether it would alter the `SUPPRESSING` flag compared to its parent. Independent blocks or blocks with explicit widths always get a cluster.
*   It might create a "Supercluster" if needed, using `fingerprint_mapper_`.

**Section 2: `CreateSuperclusterIfNeeded`**

This function manages the creation of "Superclusters".

*   It uses a `Fingerprint` of the block to identify potential groups.
*   A Supercluster is created if multiple blocks share the same fingerprint (meaning `roots->size() >= 2`) and the current block is one of those roots.
*   It uses a `SuperclusterMap` to store and retrieve Superclusters, ensuring only one Supercluster exists per fingerprint.

**Section 3: `ClusterMultiplier`**

This function calculates a "multiplier" for a given "Cluster". This multiplier likely influences the text size.

*   It caches the multiplier if already calculated.
*   It checks if the cluster is wider or narrower than its parent (using `IsWiderOrNarrowerDescendant`).
*   For independent or wider/narrower clusters:
    *   It might use a `SuperclusterMultiplier` if the cluster belongs to a Supercluster.
    *   Otherwise, if the cluster has enough text, it calculates the multiplier using `MultiplierFromBlock`.
    *   Otherwise, the multiplier is 1.0f (no autosizing).
*   For other clusters, it inherits the multiplier from its parent.

**Section 4: `SuperclusterHasEnoughTextToAutosize`**

This function determines if a "Supercluster" contains enough text to warrant autosizing.

*   It caches the result.
*   It iterates through the root blocks of the Supercluster.
*   It skips blocks that don't need a full layout (if `skip_layouted_nodes` is true).
*   It uses `ClusterWouldHaveEnoughTextToAutosize` to check each individual root.

**Section 5: `SuperclusterMultiplier`**

Calculates the multiplier for a "Supercluster".

*   It caches the result.
*   It finds the block with the maximum width within the Supercluster using `MaxClusterWidthProvider`.
*   It calls `SuperclusterHasEnoughTextToAutosize`. If true, it calculates the multiplier using `MultiplierFromBlock`; otherwise, it's 1.0f.

**Section 6: `ClusterWidthProvider`**

Determines the "width provider" for a "Cluster". This block's width is used for calculating the multiplier.

*   If the root block is a table or table cell, it's the width provider.
*   Otherwise, it finds the deepest block containing all the text within the root.

**Section 7: `MaxClusterWidthProvider`**

Finds the block with the maximum width among all the root blocks of a "Supercluster".

*   It iterates through the roots of the Supercluster.
*   It skips blocks that need layout.
*   It compares the widths of the width providers of each root and returns the one with the maximum width.

**Section 8: `WidthFromBlock`**

Calculates the width of a `LayoutBlock`.

*   Handles table, table cell, and list item cases.
*   For other blocks, it uses `ContentInlineSize`.
*   For tables, it tries to get the width from specified widths (fixed or percentage) and falls back to the containing block's width.

**Section 9: `MultiplierFromBlock`**

Calculates the text autosizing multiplier based on a `LayoutBlock`.

*   It gets the block's width and the main frame's layout width.
*   The multiplier is based on the ratio of these widths, adjusted by accessibility font scale and device scale.
*   It ensures the multiplier is at least 1.0f (no shrinking).

**Section 10: `DeepestBlockContainingAllText` (two versions)**

Finds the deepest `LayoutBlock` that contains all the text within a "Cluster" or a given root block. This is likely used to determine the effective width of the text content.

*   It handles the `LayoutView` case specifically.
*   It finds the first and last text leaves within the block.
*   It then finds the lowest common ancestor (LCA) of these text leaves.
*   If the LCA is a `LayoutBlock`, it's returned.
*   Otherwise, it returns the containing block of the LCA.

**Section 11: `FindTextLeaf`**

Recursively searches for the first or last text-containing `LayoutObject` within a given parent.

*   List items are considered text.
*   It skips blocks classified as `INDEPENDENT` (likely representing the boundaries of separate autosizing regions).

**Section 12: `IsCrossSite`**

Checks if two `Frame` objects belong to different sites (based on eTLD+1).

**Section 13: `ReportIfCrossSiteFrame`**

Reports the usage of text autosizing in cross-site iframes.

**Section 14: `ApplyMultiplier`**

Applies the calculated text autosizing `multiplier` to a `LayoutObject`.

*   It considers the `text-size-adjust` CSS property. If it's not `auto`, it might disable or adjust the autosizing multiplier.
*   It avoids shrinking text (multiplier is clamped to at least 1).
*   It updates the `TextAutosizingMultiplier` style property on the `LayoutObject`.
*   It triggers relayout and repainting if necessary.
*   It tracks if any text has been autosized.

**Section 15: `IsWiderOrNarrowerDescendant`**

Determines if a "Cluster's" root block is significantly wider or narrower than the text content of its parent's deepest containing block. This is used to decide if the cluster should autosize independently.

**Section 16: `Supercluster::Trace` and `Cluster::Trace`**

These functions are used for garbage collection tracing, allowing the engine to track object dependencies.

**Section 17: `CurrentCluster`**

Returns the currently active "Cluster" from a stack.

**Section 18: `Cluster` Constructor**

Initializes a "Cluster" object.

**Section 19: `FingerprintMapper::AssertMapsAreConsistent`**

A debug function to ensure the internal data structures of the `FingerprintMapper` are consistent.

**Section 20: `FingerprintMapper::Add` (two versions)**

Adds a mapping between a `LayoutObject` (or `LayoutBlock`) and its `Fingerprint`. The `AddTentativeClusterRoot` version also adds the block to a set of potential cluster roots for that fingerprint.

**Section 21: `FingerprintMapper::Remove`**

Removes the fingerprint mapping for a `LayoutObject`. It also handles removing the block from the set of tentative cluster roots and potentially removing empty Superclusters.

**Section 22: `FingerprintMapper::Get`**

Retrieves the `Fingerprint` for a given `LayoutObject`.

**Section 23: `FingerprintMapper::GetTentativeClusterRoots`**

Retrieves the set of tentative cluster roots for a given `Fingerprint`.

**Section 24 - 27: Various Scope Classes (`LayoutScope`, `TableLayoutScope`, `DeferUpdatePageInfo`, `NGLayoutScope`)**

These classes are RAII wrappers that manage the lifecycle of text autosizing related operations during layout. They ensure that `BeginLayout` and `EndLayout` (and related functions) are called correctly. `NGLayoutScope` specifically handles registration of inline sizes for LayoutNG.

**Section 28: `MaybeRegisterInlineSize`**

A static utility to register inline sizes.

**Section 29: `ComputeAutosizedFontSize`**

Calculates the final autosized font size based on the computed size, the multiplier, and the effective zoom level. It includes logic to gradually reduce the multiplier's effect on larger font sizes.

**Section 30: `CheckSuperclusterConsistency`**

A function to re-evaluate Superclusters that might have become inconsistent due to changes in their members.

**Section 31: `ContentInlineSize`**

Returns the content inline size of a `LayoutBlock`, handling both legacy layout and LayoutNG.

**Section 32 & 33: `RegisterInlineSize` and `UnregisterInlineSize`**

Functions to manage the mapping of inline sizes for LayoutNG blocks.

**Section 34 & 35: `Trace` (for `TextAutosizer` and `FingerprintMapper`)**

Used for garbage collection tracing.

**Overall Functionality:**

This code is responsible for the **text autosizing feature in the Blink rendering engine**. It dynamically adjusts the font sizes of text content to improve readability, especially on mobile devices or when accessibility settings are enabled.

**Relationship to JavaScript, HTML, CSS:**

*   **HTML:** The code operates on the rendered layout of HTML elements. It identifies blocks of text within the HTML structure.
*   **CSS:**
    *   The `text-size-adjust` CSS property directly influences how this code behaves. The code checks the value of this property to decide whether to apply autosizing and how.
    *   The layout and dimensions of HTML elements, determined by CSS, are crucial inputs for the autosizing calculations (e.g., block widths).
    *   The final adjusted font size is applied as a style to the text, affecting how it's rendered.
*   **JavaScript:** While this code is C++, JavaScript can indirectly affect text autosizing by:
    *   Dynamically modifying the HTML structure or CSS styles, which would trigger relayout and potentially re-evaluation of autosizing.
    *   Using APIs related to viewport size or zoom level, which can influence the autosizing parameters.

**Examples:**

*   **HTML:** A `<div>` containing a long paragraph of text might be considered for autosizing.
*   **CSS:** Setting `text-size-adjust: auto;` on the `<body>` would enable text autosizing for the entire page (subject to the logic in this code). Setting `text-size-adjust: none;` would disable it.
*   **JavaScript:** A script that dynamically adds a large block of text to the page would cause the text autosizer to potentially adjust its font size.

**Logic and Reasoning (Assumptions and Inferences):**

*   **Input:** A `LayoutBlock` representing a portion of the rendered HTML structure. The current zoom level, accessibility settings, and the layout dimensions of the block and its ancestors.
*   **Process:** The code determines if the block (or a group of blocks) contains enough text to warrant autosizing. It calculates a multiplier based on available width and other factors.
*   **Output:** A floating-point multiplier that will be applied to the original font size of the text within the block. This multiplier is then stored as a style property.

**Common User/Programming Errors:**

*   **Unexpected Autosizing:** Developers might be surprised when text is automatically resized if they haven't explicitly considered the `text-size-adjust` property.
*   **Layout Instability:** Aggressive or frequent text autosizing could potentially lead to layout thrashing if the autosizing logic is triggered repeatedly.
*   **Interference with Custom Zoom/Scaling:**  Custom JavaScript-based zoom or scaling implementations might conflict with the browser's built-in text autosizing.
*   **Incorrect `text-size-adjust` Usage:**  Misunderstanding the `text-size-adjust` property and how it interacts with the browser's default autosizing behavior. For instance, setting a small fixed value might prevent the desired level of automatic adjustment.

**归纳一下它的功能 (Summary of its functionality):**

The provided code snippet from `text_autosizer.cc` implements the core logic for **dynamically adjusting text sizes** in the Chromium Blink rendering engine. It groups layout blocks into "Clusters" and "Superclusters," calculates a scaling "multiplier" based on available width, text content, and settings, and then applies this multiplier to the font sizes of the text within those blocks. This aims to improve readability, particularly on devices with varying screen sizes and resolutions, and to accommodate accessibility needs. The code interacts closely with the layout process, CSS styles (especially `text-size-adjust`), and relies on information about the page structure and rendering context.

这是`blink/renderer/core/layout/text_autosizer.cc`文件的第二部分，延续了第一部分关于文本自动调整大小（text autosizing）功能的实现。以下是对这部分代码功能的归纳总结，并结合第一部分进行整体理解：

**核心功能总结:**

这部分代码主要负责以下关键的文本自动调整大小的逻辑：

1. **创建和管理文本布局的逻辑分组 (Clusters 和 Superclusters):**
    *   **`CreateClusterIfNeeded`:**  决定是否需要为给定的 `LayoutBlock` 创建一个新的 `Cluster` 对象。`Cluster` 可以被理解为需要独立进行文本大小调整的区域。创建的依据包括是否是根元素、是否独立 (`INDEPENDENT` 标志)、是否有明确宽度等。
    *   **`CreateSuperclusterIfNeeded`:**  根据 `Fingerprint` (指纹，一种标识符) 将多个相关的 `Cluster` 组织成 `Supercluster`。`Supercluster` 用于更高级别的文本大小调整决策，特别是在多个相似布局的块需要统一调整时。

2. **计算文本大小调整的倍数 (Multiplier):**
    *   **`ClusterMultiplier`:**  计算一个 `Cluster` 的文本大小调整倍数。这个倍数决定了该区域内的文本字体大小需要放大多少。计算逻辑会考虑父 `Cluster` 的倍数、自身是否独立、是否有足够的文本量等因素。
    *   **`SuperclusterMultiplier`:** 计算 `Supercluster` 的文本大小调整倍数。这通常基于 `Supercluster` 中具有最大可用宽度的 `Cluster` 的情况来决定。
    *   **`MultiplierFromBlock`:** 基于给定的 `LayoutBlock` 的宽度以及主框架的宽度等信息计算出一个基础的调整倍数。

3. **判断文本量是否足够进行自动调整:**
    *   **`SuperclusterHasEnoughTextToAutosize`:** 判断一个 `Supercluster` 是否包含足够的文本量，从而决定是否需要进行自动调整。
    *   **`ClusterWouldHaveEnoughTextToAutosize` (未在本段代码中):**  第一部分可能包含此函数，用于判断单个 `Cluster` 是否有足够的文本进行调整。

4. **确定用于计算宽度的参考块:**
    *   **`ClusterWidthProvider`:**  确定哪个 `LayoutBlock` 的宽度应该被用作计算文本调整倍数的参考。对于表格或表格单元格，自身就是参考，否则会找到包含所有文本的最深块。
    *   **`MaxClusterWidthProvider`:**  在 `Supercluster` 中找到提供最大宽度的 `LayoutBlock`，用于计算 `Supercluster` 的调整倍数。
    *   **`WidthFromBlock`:**  实际计算给定 `LayoutBlock` 的宽度，会考虑不同类型的元素 (如表格) 的宽度计算方式。
    *   **`ContentInlineSize`:** 获取 `LayoutBlock` 的内容内联尺寸 (宽度或高度，取决于书写模式)。

5. **确定包含所有文本的最深块:**
    *   **`DeepestBlockContainingAllText`:**  找到一个 `Cluster` 或一个 `LayoutBlock` 中包含所有文本的最深的 `LayoutBlock`。这有助于确定文本内容的有效宽度。

6. **应用文本大小调整倍数:**
    *   **`ApplyMultiplier`:**  将计算出的文本大小调整倍数应用到 `LayoutObject` 上。这会修改元素的样式，并可能触发重新布局和重绘。此函数还会考虑 CSS 属性 `text-size-adjust` 的影响。

7. **处理跨站点 Frame 的情况:**
    *   **`IsCrossSite`:**  判断两个 `Frame` 是否属于不同的站点。
    *   **`ReportIfCrossSiteFrame`:**  如果当前文档位于跨站点的 iframe 中，则会记录相关的使用情况。

8. **辅助功能和设备缩放的考虑:**
    *   代码中会考虑辅助功能字体缩放因子 (`page_info_.accessibility_font_scale_factor_`) 和设备缩放调整 (`page_info_.shared_info_.device_scale_adjustment`)，确保文本调整能够更好地服务于有特殊需求的用户。

9. **布局过程中的集成:**
    *   **`LayoutScope`, `TableLayoutScope`, `NGLayoutScope`:**  这些类作为 RAII 封装器，用于在布局过程的开始和结束时执行特定的文本自动调整大小的相关操作，例如注册内联尺寸、标记需要重新布局的元素等。

10. **指纹映射 (Fingerprint Mapping):**
    *   **`FingerprintMapper`:**  用于管理 `LayoutObject` 和其 `Fingerprint` 之间的映射关系。`Fingerprint` 用于识别具有相似布局特征的块，以便将它们组织到一起进行统一的文本大小调整。

**与 Javascript, HTML, CSS 的关系:**

*   **HTML:** `TextAutosizer` 处理的是已经布局完成的 HTML 元素。它根据 HTML 结构和内容来判断哪些文本需要调整大小。
*   **CSS:**
    *   **`text-size-adjust` 属性:**  此代码会读取和响应 CSS 的 `text-size-adjust` 属性。如果该属性设置为 `auto`，则启用文本自动调整大小。如果设置为其他值 (如 `none` 或具体的百分比)，则会影响或禁用自动调整。
    *   **布局属性:** CSS 的布局属性（如 `width`, `height`, `display` 等）直接影响 `LayoutBlock` 的尺寸，而这些尺寸是计算文本调整倍数的关键输入。
    *   **字体大小:** 最终，`TextAutosizer` 会修改元素的字体大小（通过应用调整倍数），从而影响文本的最终渲染效果。
*   **Javascript:** Javascript 可以通过以下方式间接影响 `TextAutosizer` 的行为：
    *   动态修改 DOM 结构或 CSS 样式，这会导致重新布局，从而可能触发 `TextAutosizer` 重新评估文本大小。
    *   Javascript 可以读取或修改影响布局的属性，例如视口大小，这也会影响 `TextAutosizer` 的计算。

**逻辑推理的假设输入与输出:**

**假设输入:**

*   一个包含大量文本的 `<div>` 元素，其父元素的宽度较小，导致文本溢出。
*   CSS 中 `text-size-adjust: auto;` 已设置。
*   设备的屏幕宽度较小。

**预期输出:**

*   `TextAutosizer` 会识别出该 `<div>` 中的文本需要进行自动调整大小。
*   `ClusterMultiplier` 会计算出一个大于 1 的倍数。
*   `ApplyMultiplier` 会将该倍数应用到 `<div>` 内的文本元素，增大其字体大小，以更好地适应父元素的宽度，避免溢出。

**用户或编程常见的使用错误:**

1. **误解 `text-size-adjust: none;` 的作用:** 开发者可能会认为设置了 `none` 就完全禁用了所有形式的字体大小调整，但实际上，浏览器可能仍然会出于其他原因（例如用户设置的全局字体大小）进行调整。`TextAutosizer` 的逻辑也会受到此属性的影响。
2. **过度依赖自动调整而忽略响应式设计:** 开发者可能会依赖浏览器的自动调整功能，而忽略编写良好的响应式 CSS，导致在某些情况下文本调整效果不佳或出现布局问题。
3. **动态修改内容后未触发重新布局:** 如果 Javascript 动态修改了文本内容或元素的布局，但没有触发浏览器的重新布局，`TextAutosizer` 可能不会立即更新文本大小，导致显示不一致。
4. **在复杂布局中难以预测调整效果:** 在复杂的嵌套布局中，`TextAutosizer` 的调整逻辑可能变得难以预测，开发者可能需要仔细测试以确保文本大小调整符合预期。

**总结来说，这部分代码是 Chromium Blink 引擎中实现文本自动调整大小功能的核心组成部分，负责将文本内容组织成逻辑单元，计算调整倍数，并将其应用到渲染的文本上，从而提升用户在不同设备和场景下的阅读体验。**

### 提示词
```
这是目录为blink/renderer/core/layout/text_autosizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
k(block);
  if (!(flags & POTENTIAL_ROOT))
    return nullptr;

  Cluster* parent_cluster = cluster_stack_.empty() ? nullptr : CurrentCluster();
  DCHECK(parent_cluster || IsA<LayoutView>(block));

  // If a non-independent block would not alter the SUPPRESSING flag, it doesn't
  // need to be a cluster.
  bool parent_suppresses =
      parent_cluster && (parent_cluster->flags_ & SUPPRESSING);
  if (!(flags & INDEPENDENT) && !(flags & EXPLICIT_WIDTH) &&
      !!(flags & SUPPRESSING) == parent_suppresses)
    return nullptr;

  bool is_new_entry = false;
  Cluster* cluster = MakeGarbageCollected<Cluster>(
      block, flags, parent_cluster,
      fingerprint_mapper_.CreateSuperclusterIfNeeded(block, is_new_entry));
  return cluster;
}

TextAutosizer::Supercluster*
TextAutosizer::FingerprintMapper::CreateSuperclusterIfNeeded(
    LayoutBlock* block,
    bool& is_new_entry) {
  Fingerprint fingerprint = Get(block);
  if (!fingerprint)
    return nullptr;

  BlockSet* roots = GetTentativeClusterRoots(fingerprint);
  if (!roots || roots->size() < 2 || !roots->Contains(block))
    return nullptr;

  SuperclusterMap::AddResult add_result =
      superclusters_.insert(fingerprint, nullptr);
  is_new_entry = add_result.is_new_entry;
  if (!add_result.is_new_entry)
    return add_result.stored_value->value.Get();

  Supercluster* supercluster = MakeGarbageCollected<Supercluster>(roots);
  add_result.stored_value->value = supercluster;
  return supercluster;
}

float TextAutosizer::ClusterMultiplier(Cluster* cluster) {
  if (cluster->multiplier_)
    return cluster->multiplier_;

  // FIXME: why does isWiderOrNarrowerDescendant crash on independent clusters?
  if (!(cluster->flags_ & INDEPENDENT) && IsWiderOrNarrowerDescendant(cluster))
    cluster->flags_ |= WIDER_OR_NARROWER;

  if (cluster->flags_ & (INDEPENDENT | WIDER_OR_NARROWER)) {
    if (cluster->supercluster_) {
      cluster->multiplier_ = SuperclusterMultiplier(cluster);
      cluster->supercluster_->inherit_parent_multiplier_ =
          kDontInheritMultiplier;
    } else if (ClusterHasEnoughTextToAutosize(cluster)) {
      cluster->multiplier_ =
          MultiplierFromBlock(ClusterWidthProvider(cluster->root_));
    } else {
      cluster->multiplier_ = 1.0f;
    }
  } else {
    cluster->multiplier_ =
        cluster->parent_ ? ClusterMultiplier(cluster->parent_) : 1.0f;
    if (cluster->supercluster_)
      cluster->supercluster_->inherit_parent_multiplier_ = kInheritMultiplier;
  }

  DCHECK(cluster->multiplier_);
  return cluster->multiplier_;
}

bool TextAutosizer::SuperclusterHasEnoughTextToAutosize(
    Supercluster* supercluster,
    const LayoutBlock* width_provider,
    const bool skip_layouted_nodes) {
  if (supercluster->has_enough_text_to_autosize_ != kUnknownAmountOfText)
    return supercluster->has_enough_text_to_autosize_ == kHasEnoughText;

  for (const auto& root : *supercluster->roots_) {
    if (skip_layouted_nodes && !root->ChildNeedsFullLayout()) {
      continue;
    }
    if (ClusterWouldHaveEnoughTextToAutosize(root, width_provider)) {
      supercluster->has_enough_text_to_autosize_ = kHasEnoughText;
      return true;
    }
  }
  supercluster->has_enough_text_to_autosize_ = kNotEnoughText;
  return false;
}

float TextAutosizer::SuperclusterMultiplier(Cluster* cluster) {
  Supercluster* supercluster = cluster->supercluster_;
  if (!supercluster->multiplier_) {
    const LayoutBlock* width_provider =
        MaxClusterWidthProvider(cluster->supercluster_, cluster->root_);
    CHECK(width_provider);
    supercluster->multiplier_ =
        SuperclusterHasEnoughTextToAutosize(supercluster, width_provider, false)
            ? MultiplierFromBlock(width_provider)
            : 1.0f;
  }
  DCHECK(supercluster->multiplier_);
  return supercluster->multiplier_;
}

const LayoutBlock* TextAutosizer::ClusterWidthProvider(
    const LayoutBlock* root) const {
  if (root->IsTable() || root->IsTableCell())
    return root;

  return DeepestBlockContainingAllText(root);
}

const LayoutBlock* TextAutosizer::MaxClusterWidthProvider(
    Supercluster* supercluster,
    const LayoutBlock* current_root) const {
  const LayoutBlock* result = nullptr;
  if (current_root)
    result = ClusterWidthProvider(current_root);

  float max_width = 0;
  if (result)
    max_width = WidthFromBlock(result);

  const BlockSet* roots = supercluster->roots_;
  for (const auto& root : *roots) {
    const LayoutBlock* width_provider = ClusterWidthProvider(root);
    if (width_provider->NeedsLayout())
      continue;
    float width = WidthFromBlock(width_provider);
    if (width > max_width) {
      max_width = width;
      result = width_provider;
    }
  }
  return result;
}

float TextAutosizer::WidthFromBlock(const LayoutBlock* block) const {
  CHECK(block);
  CHECK(block->Style());

  if (!(block->IsTable() || block->IsTableCell() || block->IsListItem())) {
    return ContentInlineSize(block);
  }

  if (!block->ContainingBlock())
    return 0;

  // Tables may be inflated before computing their preferred widths. Try several
  // methods to obtain a width, and fall back on a containing block's width.
  for (; block; block = block->ContainingBlock()) {
    float width;
    Length specified_width = block->StyleRef().LogicalWidth();
    if (specified_width.IsFixed()) {
      if ((width = specified_width.Value()) > 0)
        return width;
    }
    if (specified_width.HasPercent()) {
      if (float container_width = ContentInlineSize(block->ContainingBlock())) {
        if ((width = FloatValueForLength(specified_width, container_width)) > 0)
          return width;
      }
    }
    if ((width = ContentInlineSize(block)) > 0)
      return width;
  }
  return 0;
}

float TextAutosizer::MultiplierFromBlock(const LayoutBlock* block) {
// If block->needsLayout() is false, it does not need to be in
// m_blocksThatHaveBegunLayout. This can happen during layout of a positioned
// object if the cluster's DBCAT is deeper than the positioned object's
// containing block, and wasn't marked as needing layout.
#if DCHECK_IS_ON()
  DCHECK(blocks_that_have_begun_layout_.Contains(block) ||
         !block->NeedsLayout() || IsA<LayoutMultiColumnFlowThread>(block));
#endif
  // Block width, in CSS pixels.
  float block_width = WidthFromBlock(block);
  float layout_width = std::min(
      block_width,
      static_cast<float>(page_info_.shared_info_.main_frame_layout_width));
  float multiplier =
      page_info_.shared_info_.main_frame_width
          ? layout_width / page_info_.shared_info_.main_frame_width
          : 1.0f;
  multiplier *= page_info_.accessibility_font_scale_factor_ *
                page_info_.shared_info_.device_scale_adjustment;
  return std::max(multiplier, 1.0f);
}

const LayoutBlock* TextAutosizer::DeepestBlockContainingAllText(
    Cluster* cluster) {
  if (!cluster->deepest_block_containing_all_text_)
    cluster->deepest_block_containing_all_text_ =
        DeepestBlockContainingAllText(cluster->root_);

  return cluster->deepest_block_containing_all_text_.Get();
}

// FIXME: Refactor this to look more like TextAutosizer::deepestCommonAncestor.
const LayoutBlock* TextAutosizer::DeepestBlockContainingAllText(
    const LayoutBlock* root) const {
  // To avoid font-size shaking caused by the change of LayoutView's
  // DeepestBlockContainingAllText.
  if (IsA<LayoutView>(root))
    return root;

  size_t first_depth = 0;
  const LayoutObject* first_text_leaf = FindTextLeaf(root, first_depth, kFirst);
  if (!first_text_leaf)
    return root;

  size_t last_depth = 0;
  const LayoutObject* last_text_leaf = FindTextLeaf(root, last_depth, kLast);
  DCHECK(last_text_leaf);

  // Equalize the depths if necessary. Only one of the while loops below will
  // get executed.
  const LayoutObject* first_node = first_text_leaf;
  const LayoutObject* last_node = last_text_leaf;
  while (first_depth > last_depth) {
    first_node = first_node->Parent();
    --first_depth;
  }
  while (last_depth > first_depth) {
    last_node = last_node->Parent();
    --last_depth;
  }

  // Go up from both nodes until the parent is the same. Both pointers will
  // point to the LCA then.
  while (first_node != last_node) {
    first_node = first_node->Parent();
    last_node = last_node->Parent();
  }

  if (auto* layout_block = DynamicTo<LayoutBlock>(first_node))
    return layout_block;

  // containingBlock() should never leave the cluster, since it only skips
  // ancestors when finding the container of position:absolute/fixed blocks, and
  // those cannot exist between a cluster and its text node's lowest common
  // ancestor as isAutosizingCluster would have made them into their own
  // independent cluster.
  const LayoutBlock* containing_block = first_node->ContainingBlock();
  if (!containing_block)
    return root;

  DCHECK(containing_block->IsDescendantOf(root));
  return containing_block;
}

const LayoutObject* TextAutosizer::FindTextLeaf(
    const LayoutObject* parent,
    size_t& depth,
    TextLeafSearch first_or_last) const {
  // List items are treated as text due to the marker.
  if (parent->IsListItem()) {
    return parent;
  }

  if (parent->IsText())
    return parent;

  ++depth;
  const LayoutObject* child = (first_or_last == kFirst)
                                  ? parent->SlowFirstChild()
                                  : parent->SlowLastChild();
  while (child) {
    // Note: At this point clusters may not have been created for these blocks
    // so we cannot rely on m_clusters. Instead, we use a best-guess about
    // whether the block will become a cluster.
    if (!ClassifyBlock(child, INDEPENDENT)) {
      if (const LayoutObject* leaf = FindTextLeaf(child, depth, first_or_last))
        return leaf;
    }
    child = (first_or_last == kFirst) ? child->NextSibling()
                                      : child->PreviousSibling();
  }
  --depth;

  return nullptr;
}

static bool IsCrossSite(const Frame& frame1, const Frame& frame2) {
  // Cross-site differs from cross-origin. For example, http://foo.com and
  // http://sub.foo.com are cross-origin but same-site. Only cross-site text
  // autosizing is impacted by site isolation (crbug.com/393285).

  const auto* origin1 = frame1.GetSecurityContext()->GetSecurityOrigin();
  const auto* origin2 = frame2.GetSecurityContext()->GetSecurityOrigin();
  if (!origin1 || !origin2 || origin1->CanAccess(origin2))
    return false;

  if (origin1->Protocol() != origin2->Protocol())
    return true;

  // Compare eTLD+1.
  return network_utils::GetDomainAndRegistry(
             origin1->Host(), network_utils::kIncludePrivateRegistries) !=
         network_utils::GetDomainAndRegistry(
             origin2->Host(), network_utils::kIncludePrivateRegistries);
}

void TextAutosizer::ReportIfCrossSiteFrame() {
  LocalFrame* frame = document_->GetFrame();
  LocalFrameView* view = document_->View();
  if (!frame || !view || !view->IsAttached() || !view->IsVisible() ||
      view->Size().IsEmpty() || !IsCrossSite(*frame, frame->Tree().Top()))
    return;

  document_->CountUse(WebFeature::kTextAutosizedCrossSiteIframe);
}

void TextAutosizer::ApplyMultiplier(LayoutObject* layout_object,
                                    float multiplier,
                                    RelayoutBehavior relayout_behavior) {
  DCHECK(layout_object);
  const ComputedStyle& current_style = layout_object->StyleRef();
  if (!current_style.GetTextSizeAdjust().IsAuto()) {
    if (RuntimeEnabledFeatures::TextSizeAdjustImprovementsEnabled()) {
      // Non-auto values of text-size-adjust should fully disable automatic
      // text size adjustment, including the accessibility font scale factor.
      multiplier = 1;
    } else {
      // The accessibility font scale factor is applied by the autosizer so we
      // need to apply that scale factor on top of the text-size-adjust
      // multiplier. Only apply the accessibility factor if the autosizer has
      // determined a multiplier should be applied so that text-size-adjust:none
      // does not cause a multiplier to be applied when it wouldn't be
      // otherwise.
      bool should_apply_accessibility_font_scale_factor = multiplier > 1;
      multiplier = current_style.GetTextSizeAdjust().Multiplier();
      if (should_apply_accessibility_font_scale_factor) {
        multiplier *= page_info_.accessibility_font_scale_factor_;
      }
    }
  } else if (multiplier < 1) {
    // Unlike text-size-adjust, the text autosizer should only inflate fonts.
    multiplier = 1;
  }

  if (current_style.TextAutosizingMultiplier() == multiplier)
    return;

  ComputedStyleBuilder builder(current_style);
  builder.SetTextAutosizingMultiplier(multiplier);
  const ComputedStyle* style = builder.TakeStyle();

  if (multiplier > 1 && !did_check_cross_site_use_count_) {
    ReportIfCrossSiteFrame();
    did_check_cross_site_use_count_ = true;
  }

  switch (relayout_behavior) {
    case kAlreadyInLayout:
      layout_object->SetModifiedStyleOutsideStyleRecalc(
          style, LayoutObject::ApplyStyleChanges::kNo);
      if (layout_object->IsText())
        To<LayoutText>(layout_object)->AutosizingMultiplerChanged();
      layout_object->SetNeedsLayoutAndFullPaintInvalidation(
          layout_invalidation_reason::kTextAutosizing, kMarkContainerChain);
      break;

    case kLayoutNeeded:
      layout_object->SetModifiedStyleOutsideStyleRecalc(
          style, LayoutObject::ApplyStyleChanges::kYes);
      break;
  }

  if (multiplier != 1)
    page_info_.has_autosized_ = true;
}

bool TextAutosizer::IsWiderOrNarrowerDescendant(Cluster* cluster) {
  // FIXME: Why do we return true when hasExplicitWidth returns false??
  if (!cluster->parent_ || !HasExplicitWidth(cluster->root_))
    return true;

  const LayoutBlock* parent_deepest_block_containing_all_text =
      DeepestBlockContainingAllText(cluster->parent_);
#if DCHECK_IS_ON()
  DCHECK(blocks_that_have_begun_layout_.Contains(cluster->root_));
  DCHECK(blocks_that_have_begun_layout_.Contains(
      parent_deepest_block_containing_all_text));
#endif

  float content_width =
      ContentInlineSize(DeepestBlockContainingAllText(cluster));
  float cluster_text_width =
      ContentInlineSize(parent_deepest_block_containing_all_text);

  // Clusters with a root that is wider than the deepestBlockContainingAllText
  // of their parent autosize independently of their parent.
  if (content_width > cluster_text_width)
    return true;

  // Clusters with a root that is significantly narrower than the
  // deepestBlockContainingAllText of their parent autosize independently of
  // their parent.
  constexpr float kNarrowWidthDifference = 200;
  if (cluster_text_width - content_width > kNarrowWidthDifference)
    return true;

  return false;
}

void TextAutosizer::Supercluster::Trace(Visitor* visitor) const {
  visitor->Trace(roots_);
}

TextAutosizer::Cluster* TextAutosizer::CurrentCluster() const {
  SECURITY_DCHECK(!cluster_stack_.empty());
  return cluster_stack_.back().Get();
}

TextAutosizer::Cluster::Cluster(const LayoutBlock* root,
                                BlockFlags flags,
                                Cluster* parent,
                                Supercluster* supercluster)
    : root_(root),
      flags_(flags),
      deepest_block_containing_all_text_(nullptr),
      parent_(parent),
      multiplier_(0),
      has_enough_text_to_autosize_(kUnknownAmountOfText),
      supercluster_(supercluster),
      has_table_ancestor_(root->IsTableCell() ||
                          (parent_ && parent_->has_table_ancestor_)) {}

void TextAutosizer::Cluster::Trace(Visitor* visitor) const {
  visitor->Trace(root_);
  visitor->Trace(deepest_block_containing_all_text_);
  visitor->Trace(parent_);
  visitor->Trace(supercluster_);
}

#if DCHECK_IS_ON()
void TextAutosizer::FingerprintMapper::AssertMapsAreConsistent() {
  // For each fingerprint -> block mapping in m_blocksForFingerprint we should
  // have an associated map from block -> fingerprint in m_fingerprints.
  ReverseFingerprintMap::iterator end = blocks_for_fingerprint_.end();
  for (ReverseFingerprintMap::iterator fingerprint_it =
           blocks_for_fingerprint_.begin();
       fingerprint_it != end; ++fingerprint_it) {
    Fingerprint fingerprint = fingerprint_it->key;
    BlockSet* blocks = fingerprint_it->value;
    for (auto& block : *blocks)
      DCHECK_EQ(fingerprints_.at(block), fingerprint);
  }
}
#endif

void TextAutosizer::FingerprintMapper::Add(LayoutObject* layout_object,
                                           Fingerprint fingerprint) {
  Remove(layout_object);

  fingerprints_.Set(layout_object, fingerprint);
#if DCHECK_IS_ON()
  AssertMapsAreConsistent();
#endif
}

void TextAutosizer::FingerprintMapper::AddTentativeClusterRoot(
    LayoutBlock* block,
    Fingerprint fingerprint) {
  Add(block, fingerprint);

  ReverseFingerprintMap::AddResult add_result =
      blocks_for_fingerprint_.insert(fingerprint, nullptr);
  if (add_result.is_new_entry)
    add_result.stored_value->value = MakeGarbageCollected<BlockSet>();
  add_result.stored_value->value->insert(block);
#if DCHECK_IS_ON()
  AssertMapsAreConsistent();
#endif
}

bool TextAutosizer::FingerprintMapper::Remove(LayoutObject* layout_object) {
  Fingerprint fingerprint = fingerprints_.Take(layout_object);
  if (!fingerprint || !layout_object->IsLayoutBlock())
    return false;

  ReverseFingerprintMap::iterator blocks_iter =
      blocks_for_fingerprint_.find(fingerprint);
  if (blocks_iter == blocks_for_fingerprint_.end())
    return false;

  BlockSet& blocks = *blocks_iter->value;
  blocks.erase(To<LayoutBlock>(layout_object));
  if (blocks.empty()) {
    blocks_for_fingerprint_.erase(blocks_iter);

    SuperclusterMap::iterator supercluster_iter =
        superclusters_.find(fingerprint);

    if (supercluster_iter != superclusters_.end()) {
      Supercluster* supercluster = supercluster_iter->value;
      potentially_inconsistent_superclusters_.erase(supercluster);
      superclusters_.erase(supercluster_iter);
    }
  }
#if DCHECK_IS_ON()
  AssertMapsAreConsistent();
#endif
  return true;
}

TextAutosizer::Fingerprint TextAutosizer::FingerprintMapper::Get(
    const LayoutObject* layout_object) {
  auto it = fingerprints_.find(layout_object);
  return it != fingerprints_.end() ? it->value : TextAutosizer::Fingerprint();
}

TextAutosizer::BlockSet*
TextAutosizer::FingerprintMapper::GetTentativeClusterRoots(
    Fingerprint fingerprint) {
  auto it = blocks_for_fingerprint_.find(fingerprint);
  return it != blocks_for_fingerprint_.end() ? &*it->value : nullptr;
}

TextAutosizer::LayoutScope::LayoutScope(LayoutBlock* block)
    : text_autosizer_(block->GetDocument().GetTextAutosizer()), block_(block) {
  if (!text_autosizer_)
    return;

  if (text_autosizer_->ShouldHandleLayout())
    text_autosizer_->BeginLayout(block_);
  else
    text_autosizer_ = nullptr;
}

TextAutosizer::LayoutScope::~LayoutScope() {
  if (text_autosizer_)
    text_autosizer_->EndLayout(block_);
}

TextAutosizer::TableLayoutScope::TableLayoutScope(LayoutTable* table)
    : LayoutScope(table) {
  if (text_autosizer_) {
    DCHECK(text_autosizer_->ShouldHandleLayout());
    text_autosizer_->InflateAutoTable(table);
  }
}

TextAutosizer::DeferUpdatePageInfo::DeferUpdatePageInfo(Page* page)
    : main_frame_(page->DeprecatedLocalMainFrame()) {
  // TODO(wjmaclean): see if we need to try and extend deferred updates to
  // renderers for remote main frames or not. For now, it's safe to assume
  // main_frame_ will be local, see WebViewImpl::ResizeViewWhileAnchored().
  DCHECK(main_frame_);
  if (TextAutosizer* text_autosizer =
          main_frame_->GetDocument()->GetTextAutosizer()) {
    DCHECK(!text_autosizer->update_page_info_deferred_);
    text_autosizer->update_page_info_deferred_ = true;
  }
}

// static
void TextAutosizer::MaybeRegisterInlineSize(const LayoutBlock& ng_block,
                                            LayoutUnit inline_size) {
  if (auto* text_autosizer = ng_block.GetDocument().GetTextAutosizer()) {
    if (text_autosizer->ShouldHandleLayout())
      text_autosizer->RegisterInlineSize(ng_block, inline_size);
  }
}

TextAutosizer::NGLayoutScope::NGLayoutScope(LayoutBox* box,
                                            LayoutUnit inline_size)
    : text_autosizer_(box->GetDocument().GetTextAutosizer()),
      block_(DynamicTo<LayoutBlock>(box)) {
  // Bail if:
  //  - Text autosizing isn't enabled.
  //  - If the chid isn't a LayoutBlock.
  //  - If the child is a LayoutOutsideListMarker. (They are super-small
  //    blocks, and using them to determine if we should autosize the text will
  //    typically false, overriding whatever its parent has already correctly
  //    determined).
  if (!text_autosizer_ || !text_autosizer_->ShouldHandleLayout() || !block_ ||
      block_->IsLayoutOutsideListMarker()) {
    text_autosizer_ = nullptr;
    return;
  }

  // In order for the text autosizer to do anything useful at all, it needs to
  // know the inline size of the block. So register it. LayoutNG normally
  // writes back to the legacy tree *after* layout, but this one must be ready
  // before, at least if the autosizer is enabled.
  text_autosizer_->RegisterInlineSize(*block_, inline_size);

  text_autosizer_->BeginLayout(block_);
}

TextAutosizer::NGLayoutScope::~NGLayoutScope() {
  if (text_autosizer_) {
    text_autosizer_->EndLayout(block_);
    text_autosizer_->UnregisterInlineSize(*block_);
  }
}

TextAutosizer::DeferUpdatePageInfo::~DeferUpdatePageInfo() {
  if (TextAutosizer* text_autosizer =
          main_frame_->GetDocument()->GetTextAutosizer()) {
    DCHECK(text_autosizer->update_page_info_deferred_);
    text_autosizer->update_page_info_deferred_ = false;
    TextAutosizer::UpdatePageInfoInAllFrames(main_frame_);
  }
}

float TextAutosizer::ComputeAutosizedFontSize(float computed_size,
                                              float multiplier,
                                              float effective_zoom) {
  DCHECK_GE(multiplier, 0);

  // Somewhat arbitrary "pleasant" font size.
  const float kPleasantSize = 16 * effective_zoom;

  // Multiply fonts that the page author has specified to be larger than
  // pleasantSize by less and less, until huge fonts are not increased at all.
  // For specifiedSize between 0 and pleasantSize we directly apply the
  // multiplier; hence for specifiedSize == pleasantSize, computedSize will be
  // multiplier * pleasantSize. For greater specifiedSizes we want to
  // gradually fade out the multiplier, so for every 1px increase in
  // specifiedSize beyond pleasantSize we will only increase computedSize
  // by gradientAfterPleasantSize px until we meet the
  // computedSize = specifiedSize line, after which we stay on that line (so
  // then every 1px increase in specifiedSize increases computedSize by 1px).
  const float kGradientAfterPleasantSize = 0.5;

  float auto_sized_size;
  // Skip linear backoff for multipliers that shrink the size or when the font
  // sizes are small.
  if (multiplier <= 1 || computed_size <= kPleasantSize) {
    auto_sized_size = multiplier * computed_size;
  } else {
    auto_sized_size =
        multiplier * kPleasantSize +
        kGradientAfterPleasantSize * (computed_size - kPleasantSize);
    if (auto_sized_size < computed_size)
      auto_sized_size = computed_size;
  }
  return auto_sized_size;
}

void TextAutosizer::CheckSuperclusterConsistency() {
  HeapHashSet<Member<Supercluster>>& potentially_inconsistent_superclusters =
      fingerprint_mapper_.GetPotentiallyInconsistentSuperclusters();
  if (potentially_inconsistent_superclusters.empty())
    return;

  for (Supercluster* supercluster : potentially_inconsistent_superclusters) {
    if (kHasEnoughText == supercluster->has_enough_text_to_autosize_)
      continue;

    float old_multipiler = supercluster->multiplier_;
    supercluster->multiplier_ = 0;
    supercluster->has_enough_text_to_autosize_ = kUnknownAmountOfText;
    const LayoutBlock* width_provider =
        MaxClusterWidthProvider(supercluster, nullptr);
    if (!width_provider)
      continue;

    if (SuperclusterHasEnoughTextToAutosize(supercluster, width_provider,
                                            true) == kHasEnoughText) {
      for (const auto& root : *supercluster->roots_) {
        if (!root->EverHadLayout())
          continue;

        DCHECK(root);
        SetAllTextNeedsLayout(root);
      }
    } else {
      supercluster->multiplier_ = old_multipiler;
    }
  }
  potentially_inconsistent_superclusters.clear();
}

float TextAutosizer::ContentInlineSize(const LayoutBlock* block) const {
  if (!block->IsLayoutNGObject())
    return block->ContentLogicalWidth().ToFloat();
  auto iter = inline_size_map_.find(block);
  if (iter == inline_size_map_.end())
    return block->ContentLogicalWidth().ToFloat();
  LayoutUnit size = iter.Get()->value;
  if (block->IsHorizontalWritingMode()) {
    size = block->ClientWidthFrom(size) - block->PaddingLeft() -
           block->PaddingRight();
  } else {
    size = block->ClientHeightFrom(size) - block->PaddingTop() -
           block->PaddingBottom();
  }
  return size.ClampNegativeToZero().ToFloat();
}

void TextAutosizer::RegisterInlineSize(const LayoutBlock& ng_block,
                                       LayoutUnit inline_size) {
  inline_size_map_.insert(&ng_block, inline_size);
}

void TextAutosizer::UnregisterInlineSize(const LayoutBlock& ng_block) {
  inline_size_map_.erase(&ng_block);
}

void TextAutosizer::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
  visitor->Trace(first_block_to_begin_layout_);
  visitor->Trace(inline_size_map_);
#if DCHECK_IS_ON()
  visitor->Trace(blocks_that_have_begun_layout_);
#endif
  visitor->Trace(cluster_stack_);
  visitor->Trace(fingerprint_mapper_);
}

void TextAutosizer::FingerprintMapper::Trace(Visitor* visitor) const {
  visitor->Trace(fingerprints_);
  visitor->Trace(blocks_for_fingerprint_);
  visitor->Trace(superclusters_);
  visitor->Trace(potentially_inconsistent_superclusters_);
}

}  // namespace blink
```