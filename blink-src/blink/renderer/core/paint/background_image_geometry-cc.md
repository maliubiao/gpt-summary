Response:
The user wants to understand the functionality of the `background_image_geometry.cc` file in the Chromium Blink rendering engine. I need to analyze the code and identify its purpose, focusing on how it relates to rendering background images. Specifically, I should address the following:

1. **Core Functionality:** What is the primary task of this file?
2. **Relationship to Web Technologies:** How does it interact with JavaScript, HTML, and CSS? Provide examples.
3. **Logical Reasoning:**  If the code performs calculations or adjustments, illustrate with hypothetical inputs and outputs.
4. **Common User/Programming Errors:** Identify potential mistakes that could lead to issues handled by this code.
5. **Debugging Context:**  Explain how a user's actions could lead to this code being executed, aiding in debugging.
6. **Summary of Functionality:** Provide a concise overview of the file's purpose, given this is part 1 of 2.

Based on the code, it seems the primary function is to **calculate the geometry (size, position, and tiling) of background images** for rendering. This involves considering various CSS properties related to background images.

Here's a breakdown of how I'll structure the answer:

* **Core Functionality:**  State that the file calculates background image geometry based on CSS properties.
* **Relationship to Web Technologies:**
    * **CSS:**  Give examples of CSS properties this file handles (e.g., `background-image`, `background-repeat`, `background-size`, `background-position`, `background-clip`, `background-origin`).
    * **HTML:** Briefly mention how HTML elements are styled using these CSS properties.
    * **JavaScript:** Explain how JavaScript can dynamically modify these CSS properties, indirectly triggering this code.
* **Logical Reasoning:**
    * Provide an example scenario, perhaps related to `background-repeat: space` or `background-size: contain`.
    * Define some input values (e.g., container size, image size, CSS properties).
    * Explain the calculation performed by the relevant functions (e.g., `GetSpaceBetweenImageTiles`, `ComputeRoundedTileSize`).
    * Show the expected output (e.g., the calculated space between tiles or the rounded tile size).
* **Common User/Programming Errors:**
    * Give examples like incorrect units in CSS, conflicting CSS properties, or large image sizes.
    * Briefly explain how this code helps handle or mitigate these errors.
* **Debugging Context:**
    * Describe a user interaction (e.g., scrolling, resizing the window, or a CSS animation changing background properties).
    * Explain how these actions might trigger a repaint, leading to the execution of the code in this file.
* **Summary of Functionality (Part 1):**  Summarize the aspects of background image geometry calculation covered by the provided code snippet. Since it deals with size, repeat, and position calculations, focus on those.

Planning complete. I will now generate the response following these steps.
```
这是目录为blink/renderer/core/paint/background_image_geometry.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**blink/renderer/core/paint/background_image_geometry.cc 的功能:**

这个文件的主要功能是**计算并确定背景图片的几何属性**，以便在渲染过程中正确地绘制背景图片。这些几何属性包括：

* **目标矩形 (Destination Rectangle):**  背景图片最终绘制到的区域大小和位置。
* **平铺大小 (Tile Size):**  当背景图片需要平铺时，单个平铺单元的大小。
* **相位 (Phase):**  用于控制平铺背景图片的起始位置，实现 `background-position` 和 `background-repeat` 的效果。
* **间距大小 (Space Size):**  用于 `background-repeat: space` 属性，计算平铺单元之间的间距。
* **定位区域 (Positioning Area):**  用于计算背景图片位置和大小的参考区域，受到 `background-origin` 的影响。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件与前端三大核心技术紧密相关，因为它负责解析和应用 CSS 中与背景图片相关的属性：

* **CSS:**
    * **`background-image`:**  决定了要绘制的背景图片。这个文件会处理不同类型的背景图片，包括 URL 引用的图片和渐变等。
    * **`background-repeat`:**  控制背景图片是否以及如何平铺 (`repeat`, `no-repeat`, `repeat-x`, `repeat-y`, `space`, `round`)。文件中的 `SetRepeatX`, `SetRepeatY`, `SetSpaceX`, `SetSpaceY` 等函数就对应了这些不同的平铺方式。
    * **`background-size`:**  指定背景图片的大小 (`auto`, `cover`, `contain`, `<length>`, `<percentage>`)。 `CalculateFillTileSize` 函数负责根据 `background-size` 的值计算出合适的平铺大小。
    * **`background-position`:**  设置背景图片的起始位置。 `ResolveXPosition` 和 `ResolveYPosition` 函数根据 `background-position` 的值计算偏移量。
    * **`background-origin`:**  决定 `background-position` 的参考原点 (`padding-box`, `border-box`, `content-box`)。 文件中的 `fill_layer.BackgroundXOrigin()` 和 `fill_layer.BackgroundYOrigin()` 就用于获取这个属性。
    * **`background-clip`:**  指定背景绘制的裁剪区域 (`border-box`, `padding-box`, `content-box`, `text`)。 `ComputeDestRectAdjustments` 函数会考虑 `background-clip` 的值来调整目标矩形。
    * **`background-attachment`:**  控制背景图片是否随着滚动条滚动 (`fixed`, `local`, `scroll`)。 `paint_context.ShouldUseFixedAttachment(fill_layer)` 用于判断是否是 `fixed` 附件，并进行相应的处理。
    * **`mask-origin` 和 `mask-clip`:** 虽然文件名为 `background_image_geometry.cc`，但代码中也涉及到了对 mask 的处理，例如 `NeedsFullSizeDestination` 函数。

    **例子：**

    ```html
    <div id="example" style="background-image: url('image.png'); background-repeat: repeat-x; background-position: center top; background-size: contain;"></div>
    ```

    当浏览器渲染这个 `div` 时，`background_image_geometry.cc` 中的代码会被调用，根据上述 CSS 属性计算出 `image.png` 的平铺方式（水平重复），起始位置（水平居中，顶部对齐），以及大小（等比缩放以完全包含在元素内）。

* **HTML:** HTML 元素通过 `style` 属性或外部 CSS 文件定义其样式，这些样式中包含的背景图片属性会最终传递给渲染引擎处理。

* **JavaScript:** JavaScript 可以动态地修改 HTML 元素的样式，包括背景图片相关的属性。例如：

    ```javascript
    document.getElementById('example').style.backgroundImage = "url('new_image.png')";
    document.getElementById('example').style.backgroundSize = "50%";
    ```

    当这些 JavaScript 代码执行后，浏览器需要重新计算背景图片的几何属性，`background_image_geometry.cc` 中的代码会被再次调用，使用新的属性值进行计算。

**逻辑推理的假设输入与输出:**

**假设场景：**  一个 `div` 元素，设置了 `background-image` 和 `background-repeat: space`。

**假设输入:**

* `area_size` (可用区域大小，例如 `div` 的宽度): `200px`
* `tile_size` (背景图片原始宽度): `50px`

**调用的函数:** `GetSpaceBetweenImageTiles(area_size, tile_size)`

**逻辑推理:**

1. 计算可以容纳的完整平铺单元数量: `number_of_tiles = floor(area_size / tile_size) = floor(200 / 50) = 4`
2. 如果平铺单元数量大于 1，则计算剩余空间: `remaining_space = area_size - number_of_tiles * tile_size = 200 - 4 * 50 = 0`
3. 计算平铺单元之间的间距: `space = remaining_space / (number_of_tiles - 1) = 0 / (4 - 1) = 0`

**假设输出:** `space = 0px`

**假设输入 (另一个场景，有剩余空间):**

* `area_size`: `220px`
* `tile_size`: `50px`

**逻辑推理:**

1. `number_of_tiles = floor(220 / 50) = 4`
2. `remaining_space = 220 - 4 * 50 = 20`
3. `space = 20 / (4 - 1) = 6.66...px`

**假设输出:** `space = 6.66...px` (实际实现可能会有精度处理)

**用户或编程常见的使用错误及举例说明:**

* **错误的单位或语法:**  在 CSS 中使用了错误的单位（例如 `background-size: 50;` 而不是 `50px` 或 `50%`）或错误的语法，导致属性解析失败或产生意外效果。`background_image_geometry.cc` 的代码可能会根据解析后的值进行计算，如果解析结果不符合预期，可能会导致渲染错误。
* **`background-position` 的理解偏差:**  用户可能不清楚 `background-position` 的参考原点，导致背景图片定位不符合预期。例如，认为 `background-position: 0 0;` 总是相对于元素的左上角，而忽略了 `background-origin` 的影响。
* **`background-size: cover` 或 `contain` 的误用:**  在不了解图片宽高比的情况下使用 `cover` 或 `contain`，可能会导致图片被裁剪或出现留白。
* **性能问题:**  使用非常大的背景图片或复杂的平铺模式可能会导致性能下降。虽然 `background_image_geometry.cc` 本身不直接负责性能优化，但其计算结果会影响后续的绘制操作。
* **与 `mask` 属性的冲突:**  不当的 `mask` 属性设置可能导致背景图片显示异常。例如，mask 的大小或位置与背景图片的设置不匹配。

**用户操作到达这里的调试线索:**

用户操作最终导致浏览器需要重新渲染页面，而背景图片的绘制是渲染过程的一部分。以下是一些可能触发 `background_image_geometry.cc` 代码执行的用户操作：

1. **加载网页:**  当浏览器首次加载包含背景图片的 HTML 页面时，会解析 CSS 样式并计算背景图片的几何属性。
2. **窗口大小调整:**  调整浏览器窗口大小可能会影响元素的尺寸，从而需要重新计算背景图片的大小和位置。
3. **滚动页面:**  如果背景图片的 `background-attachment` 属性为 `fixed` 或 `local`，滚动页面时可能需要重新定位背景图片。
4. **鼠标悬停或点击元素:**  通过 CSS 伪类（如 `:hover`）改变元素的背景图片属性时，会触发重新渲染。
5. **JavaScript 动态修改样式:**  如前面所述，JavaScript 修改背景图片相关的 CSS 属性会直接导致重新计算。
6. **CSS 动画或过渡:**  当背景图片相关的属性参与 CSS 动画或过渡时，每一帧的变化都需要重新计算几何属性。
7. **DOM 结构变化:**  添加或删除 DOM 元素可能导致布局变化，从而影响背景图片的渲染。

**调试线索:**

如果在调试过程中发现背景图片显示异常，可以检查以下方面：

* **CSS 样式:**  确认与背景图片相关的 CSS 属性是否设置正确，单位和语法是否正确。
* **浏览器开发者工具:**  使用浏览器的开发者工具（例如 Chrome 的 DevTools）的 "Elements" 面板查看元素的计算样式（Computed），确认背景图片相关的属性值是否符合预期。
* **Performance 面板:**  如果怀疑性能问题，可以使用 Performance 面板分析渲染过程，查看是否有大量的背景图片绘制操作。
* **Paint Flashing:**  在 DevTools 的 Rendering 设置中开启 "Paint Flashing"，可以高亮显示需要重绘的区域，帮助定位问题。

**功能归纳 (第 1 部分):**

在第一部分的代码中，`background_image_geometry.cc` 的主要功能集中在：

* **处理基本的背景图片几何计算:**  包括目标矩形、平铺大小、相位等核心属性的计算。
* **考虑多种 CSS 背景图片属性:**  例如 `background-repeat` 的不同取值 (`no-repeat`, `repeat-x`, `repeat-y`, `space`, `round`)，并实现相应的平铺逻辑。
* **初步处理 `background-size`:**  根据不同的 `background-size` 值计算出合适的背景图片大小。
* **根据 `background-position` 和 `background-origin` 计算背景图片的位置偏移。**
* **部分涉及 `mask` 属性的处理:**  例如判断是否需要全尺寸的目标矩形。

总的来说，这部分代码负责背景图片最基础也是最重要的几何属性计算，为后续的实际绘制工作奠定基础。后续的部分可能会涉及更复杂的场景，例如渐变背景、多层背景等。

Prompt: 
```
这是目录为blink/renderer/core/paint/background_image_geometry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/background_image_geometry.h"

#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/paint/svg_background_paint_context.h"

namespace blink {

namespace {

// Return the amount of space to leave between image tiles for the
// background-repeat: space property.
inline LayoutUnit GetSpaceBetweenImageTiles(LayoutUnit area_size,
                                            LayoutUnit tile_size) {
  int number_of_tiles = (area_size / tile_size).ToInt();
  LayoutUnit space(-1);
  if (number_of_tiles > 1) {
    // Spec doesn't specify rounding, so use the same method as for
    // background-repeat: round.
    space = (area_size - number_of_tiles * tile_size) / (number_of_tiles - 1);
  }

  return space;
}

LayoutUnit ComputeRoundedTileSize(LayoutUnit area_size, LayoutUnit tile_size) {
  int nr_tiles = std::max(1, RoundToInt(area_size / tile_size));
  return area_size / nr_tiles;
}

LayoutUnit ComputeTilePhase(LayoutUnit position, LayoutUnit tile_extent) {
  // Assuming a non-integral number of tiles, find out how much of the
  // partial tile is visible. That is the phase.
  return tile_extent ? tile_extent - IntMod(position, tile_extent)
                     : LayoutUnit();
}

LayoutUnit ResolveWidthForRatio(LayoutUnit height,
                                const PhysicalSize& natural_ratio) {
  LayoutUnit resolved_width =
      height.MulDiv(natural_ratio.width, natural_ratio.height);
  if (natural_ratio.width >= 1 && resolved_width < 1) {
    return LayoutUnit(1);
  }
  return resolved_width;
}

LayoutUnit ResolveHeightForRatio(LayoutUnit width,
                                 const PhysicalSize& natural_ratio) {
  LayoutUnit resolved_height =
      width.MulDiv(natural_ratio.height, natural_ratio.width);
  if (natural_ratio.height >= 1 && resolved_height < 1) {
    return LayoutUnit(1);
  }
  return resolved_height;
}

LayoutUnit ResolveXPosition(const FillLayer& fill_layer,
                            LayoutUnit available_width,
                            LayoutUnit offset) {
  const LayoutUnit edge_relative_position =
      MinimumValueForLength(fill_layer.PositionX(), available_width);
  // Convert from edge-relative form to absolute.
  const LayoutUnit absolute_position =
      fill_layer.BackgroundXOrigin() == BackgroundEdgeOrigin::kRight
          ? available_width - edge_relative_position
          : edge_relative_position;
  return absolute_position - offset;
}

LayoutUnit ResolveYPosition(const FillLayer& fill_layer,
                            LayoutUnit available_height,
                            LayoutUnit offset) {
  const LayoutUnit edge_relative_position =
      MinimumValueForLength(fill_layer.PositionY(), available_height);
  // Convert from edge-relative form to absolute.
  const LayoutUnit absolute_position =
      fill_layer.BackgroundYOrigin() == BackgroundEdgeOrigin::kBottom
          ? available_height - edge_relative_position
          : edge_relative_position;
  return absolute_position - offset;
}

}  // anonymous namespace

bool NeedsFullSizeDestination(const FillLayer& fill_layer) {
  // When dealing with a mask, the dest rect needs to maintain the full size
  // and the mask should be expanded to fill it out. This allows the mask to
  // correctly mask the entire area it is meant to. This is unnecessary on the
  // last layer, so the normal background path is taken for efficiency when
  // creating the paint shader later on.
  return fill_layer.GetType() == EFillLayerType::kMask && fill_layer.Next() &&
         fill_layer.Composite() != kCompositeSourceOver;
}

void BackgroundImageGeometry::SetNoRepeatX(const FillLayer& fill_layer,
                                           LayoutUnit x_offset,
                                           LayoutUnit snapped_x_offset) {
  if (NeedsFullSizeDestination(fill_layer)) {
    SetPhaseX(-x_offset);
    SetSpaceSize(
        PhysicalSize(unsnapped_dest_rect_.Width(), SpaceSize().height));
    return;
  }

  if (x_offset > 0) {
    // Move the dest rect if the offset is positive. The image "stays" where
    // it is over the dest rect, so this effectively modifies the phase.
    unsnapped_dest_rect_.Move(PhysicalOffset(x_offset, LayoutUnit()));
    snapped_dest_rect_.SetX(LayoutUnit(unsnapped_dest_rect_.X().Round()));

    // Make the dest as wide as a tile, which will reduce the dest
    // rect if the tile is too small to fill the paint_rect. If not,
    // the dest rect will be clipped when intersected with the paint
    // rect.
    unsnapped_dest_rect_.SetWidth(tile_size_.width);
    snapped_dest_rect_.SetWidth(tile_size_.width);

    SetPhaseX(LayoutUnit());
  } else {
    // Otherwise, if the offset is negative use it to move the image under
    // the dest rect (since we can't paint outside the paint_rect).
    SetPhaseX(-x_offset);

    // Reduce the width of the dest rect to draw only the portion of the
    // tile that remains visible after offsetting the image.
    unsnapped_dest_rect_.SetWidth(tile_size_.width + x_offset);
    snapped_dest_rect_.SetWidth(tile_size_.width + snapped_x_offset);
  }

  // Force the horizontal space to zero, retaining vertical.
  SetSpaceSize(PhysicalSize(LayoutUnit(), SpaceSize().height));
}

void BackgroundImageGeometry::SetNoRepeatY(const FillLayer& fill_layer,
                                           LayoutUnit y_offset,
                                           LayoutUnit snapped_y_offset) {
  if (NeedsFullSizeDestination(fill_layer)) {
    SetPhaseY(-y_offset);
    SetSpaceSize(
        PhysicalSize(SpaceSize().width, unsnapped_dest_rect_.Height()));
    return;
  }

  if (y_offset > 0) {
    // Move the dest rect if the offset is positive. The image "stays" where
    // it is in the paint rect, so this effectively modifies the phase.
    unsnapped_dest_rect_.Move(PhysicalOffset(LayoutUnit(), y_offset));
    snapped_dest_rect_.SetY(LayoutUnit(unsnapped_dest_rect_.Y().Round()));

    // Make the dest as wide as a tile, which will reduce the dest
    // rect if the tile is too small to fill the paint_rect. If not,
    // the dest rect will be clipped when intersected with the paint
    // rect.
    unsnapped_dest_rect_.SetHeight(tile_size_.height);
    snapped_dest_rect_.SetHeight(tile_size_.height);

    SetPhaseY(LayoutUnit());
  } else {
    // Otherwise, if the offset is negative, use it to move the image under
    // the dest rect (since we can't paint outside the paint_rect).
    SetPhaseY(-y_offset);

    // Reduce the height of the dest rect to draw only the portion of the
    // tile that remains visible after offsetting the image.
    unsnapped_dest_rect_.SetHeight(tile_size_.height + y_offset);
    snapped_dest_rect_.SetHeight(tile_size_.height + snapped_y_offset);
  }

  // Force the vertical space to zero, retaining horizontal.
  SetSpaceSize(PhysicalSize(SpaceSize().width, LayoutUnit()));
}

void BackgroundImageGeometry::SetRepeatX(LayoutUnit x_offset) {
  // All values are unsnapped to accurately set phase in the presence of
  // zoom and large values. That is, accurately render the
  // background-position value.
  SetPhaseX(ComputeTilePhase(x_offset, tile_size_.width));
  SetSpaceSize(PhysicalSize(LayoutUnit(), SpaceSize().height));
}

void BackgroundImageGeometry::SetRepeatY(LayoutUnit y_offset) {
  // All values are unsnapped to accurately set phase in the presence of
  // zoom and large values. That is, accurately render the
  // background-position value.
  SetPhaseY(ComputeTilePhase(y_offset, tile_size_.height));
  SetSpaceSize(PhysicalSize(SpaceSize().width, LayoutUnit()));
}

void BackgroundImageGeometry::SetSpaceX(LayoutUnit space,
                                        LayoutUnit extra_offset) {
  SetSpaceSize(PhysicalSize(space, SpaceSize().height));
  // Modify the phase to start a full tile at the edge of the paint area.
  SetPhaseX(ComputeTilePhase(extra_offset, tile_size_.width + space));
}

void BackgroundImageGeometry::SetSpaceY(LayoutUnit space,
                                        LayoutUnit extra_offset) {
  SetSpaceSize(PhysicalSize(SpaceSize().width, space));
  // Modify the phase to start a full tile at the edge of the paint area.
  SetPhaseY(ComputeTilePhase(extra_offset, tile_size_.height + space));
}

SnappedAndUnsnappedOutsets BackgroundImageGeometry::ComputeDestRectAdjustments(
    const FillLayer& fill_layer,
    const BoxBackgroundPaintContext& paint_context,
    const PhysicalRect& unsnapped_positioning_area,
    bool disallow_border_derived_adjustment) const {
  SnappedAndUnsnappedOutsets dest_adjust;
  switch (paint_context.EffectiveClip(fill_layer)) {
    case EFillBox::kNoClip:
      dest_adjust.unsnapped = paint_context.VisualOverflowOutsets();
      dest_adjust.snapped = dest_adjust.unsnapped;
      break;
    case EFillBox::kFillBox:
    // Spec: For elements with associated CSS layout box, the used values for
    // fill-box compute to content-box.
    // https://drafts.fxtf.org/css-masking/#the-mask-clip
    case EFillBox::kContent:
      // If the PaddingOutsets are zero then this is equivalent to
      // kPadding and we should apply the snapping logic.
      dest_adjust.unsnapped = paint_context.PaddingOutsets();
      if (!dest_adjust.unsnapped.IsZero()) {
        dest_adjust.unsnapped += paint_context.BorderOutsets();
        // We're not trying to match a border position, so don't snap.
        dest_adjust.snapped = dest_adjust.unsnapped;
        break;
      }
      [[fallthrough]];
    case EFillBox::kPadding:
      dest_adjust.unsnapped = paint_context.BorderOutsets();
      if (disallow_border_derived_adjustment) {
        // Nothing to drive snapping behavior, so don't snap.
        dest_adjust.snapped = dest_adjust.unsnapped;
      } else {
        // Force the snapped dest rect to match the inner border to
        // avoid gaps between the background and border.
        dest_adjust.snapped = paint_context.InnerBorderOutsets(
            unsnapped_dest_rect_, unsnapped_positioning_area);
      }
      break;
    case EFillBox::kStrokeBox:
    case EFillBox::kViewBox:
    // Spec: For elements with associated CSS layout box, ... stroke-box and
    // view-box compute to border-box.
    // https://drafts.fxtf.org/css-masking/#the-mask-clip
    case EFillBox::kBorder: {
      if (disallow_border_derived_adjustment) {
        // All adjustments remain 0.
        break;
      }

      // The dest rects can be adjusted. The snapped dest rect is forced
      // to match the inner border to avoid gaps between the background and
      // border, while the unsnapped dest moves according to the
      // border box outsets. This leaves the unsnapped dest accurately
      // conveying the content creator's intent when used for determining
      // the pixels to use from sprite maps and other size and positioning
      // properties.
      // Note that the snapped adjustments do not have the same effect as
      // pixel snapping the unsnapped rectangle. Border snapping snaps both
      // the size and position of the borders, sometimes adjusting the inner
      // border by more than a pixel when done (particularly under magnifying
      // zoom).
      dest_adjust = paint_context.ObscuredBorderOutsets(
          unsnapped_dest_rect_, unsnapped_positioning_area);
      break;
    }
    case EFillBox::kText:
      break;
  }
  return dest_adjust;
}

SnappedAndUnsnappedOutsets
BackgroundImageGeometry::ComputePositioningAreaAdjustments(
    const FillLayer& fill_layer,
    const BoxBackgroundPaintContext& paint_context,
    const PhysicalRect& unsnapped_positioning_area,
    bool disallow_border_derived_adjustment) const {
  SnappedAndUnsnappedOutsets box_outset;
  switch (fill_layer.Origin()) {
    case EFillBox::kFillBox:
    // Spec: For elements with associated CSS layout box, the used values for
    // fill-box compute to content-box.
    // https://drafts.fxtf.org/css-masking/#the-mask-clip
    case EFillBox::kContent:
      // If the PaddingOutsets are zero then this is equivalent to
      // kPadding and we should apply the snapping logic.
      box_outset.unsnapped = paint_context.PaddingOutsets();
      if (!box_outset.unsnapped.IsZero()) {
        box_outset.unsnapped += paint_context.BorderOutsets();
        // We're not trying to match a border position, so don't snap.
        box_outset.snapped = box_outset.unsnapped;
        break;
      }
      [[fallthrough]];
    case EFillBox::kPadding:
      box_outset.unsnapped = paint_context.BorderOutsets();
      if (disallow_border_derived_adjustment) {
        box_outset.snapped = box_outset.unsnapped;
      } else {
        // Force the snapped positioning area to fill to the borders.
        // Note that the snapped adjustments do not have the same effect as
        // pixel snapping the unsnapped rectangle. Border snapping snaps both
        // the size and position of the borders, sometimes adjusting the inner
        // border by more than a pixel when done (particularly under magnifying
        // zoom).
        box_outset.snapped = paint_context.InnerBorderOutsets(
            unsnapped_positioning_area, unsnapped_positioning_area);
      }
      break;
    case EFillBox::kStrokeBox:
    case EFillBox::kViewBox:
    // Spec: For elements with associated CSS layout box, ... stroke-box and
    // view-box compute to border-box.
    // https://drafts.fxtf.org/css-masking/#the-mask-clip
    case EFillBox::kBorder:
      // All adjustments remain 0.
      break;
    case EFillBox::kNoClip:
    case EFillBox::kText:
      // These are not supported mask-origin values.
      NOTREACHED();
  }
  return box_outset;
}

void BackgroundImageGeometry::AdjustPositioningArea(
    const FillLayer& fill_layer,
    const BoxBackgroundPaintContext& paint_context,
    const PaintInfo& paint_info,
    PhysicalRect& unsnapped_positioning_area,
    PhysicalRect& snapped_positioning_area,
    PhysicalOffset& unsnapped_box_offset,
    PhysicalOffset& snapped_box_offset) {
  // Attempt to shrink the destination rect if possible while also ensuring
  // that it paints to the border:
  //
  //   * for background-clip content-box/padding-box, we can restrict to the
  //     respective box, but for padding-box we also try to force alignment
  //     with the inner border.
  //
  //   * for border-box, we can modify individual edges iff the border fully
  //     obscures the background.
  //
  // It is unsafe to derive dest from border information when any of the
  // following is true:
  // * the layer is not painted as part of a regular background phase
  //  (e.g.paint_phase == kMask)
  // * non-SrcOver compositing is active
  // * painting_view_ is set, meaning we're dealing with a
  //   LayoutView - for which dest rect is overflowing (expanded to cover
  //   the whole canvas).
  // * We are painting table cells using the table background, or the table
  //   has collapsed borders
  // * We are painting a block-fragmented box.
  // * There is a border image, because it may not be opaque or may be outset.
  bool disallow_border_derived_adjustment =
      !ShouldPaintSelfBlockBackground(paint_info.phase) ||
      fill_layer.Composite() != CompositeOperator::kCompositeSourceOver ||
      paint_context.DisallowBorderDerivedAdjustment();

  // Compute all the outsets we need to apply to the rectangles. These
  // outsets also include the snapping behavior.
  const SnappedAndUnsnappedOutsets dest_adjust = ComputeDestRectAdjustments(
      fill_layer, paint_context, unsnapped_positioning_area,
      disallow_border_derived_adjustment);
  const SnappedAndUnsnappedOutsets box_outset =
      ComputePositioningAreaAdjustments(fill_layer, paint_context,
                                        unsnapped_positioning_area,
                                        disallow_border_derived_adjustment);

  // Offset of the positioning area from the corner of positioning_box_.
  unsnapped_box_offset =
      box_outset.unsnapped.Offset() - dest_adjust.unsnapped.Offset();
  snapped_box_offset =
      box_outset.snapped.Offset() - dest_adjust.snapped.Offset();

  // Apply the adjustments.
  snapped_dest_rect_ = unsnapped_dest_rect_;
  snapped_dest_rect_.Contract(dest_adjust.snapped);
  snapped_dest_rect_ = PhysicalRect(ToPixelSnappedRect(snapped_dest_rect_));
  snapped_dest_rect_.size.ClampNegativeToZero();
  unsnapped_dest_rect_.Contract(dest_adjust.unsnapped);
  unsnapped_dest_rect_.size.ClampNegativeToZero();
  snapped_positioning_area = unsnapped_positioning_area;
  snapped_positioning_area.Contract(box_outset.snapped);
  snapped_positioning_area =
      PhysicalRect(ToPixelSnappedRect(snapped_positioning_area));
  snapped_positioning_area.size.ClampNegativeToZero();
  unsnapped_positioning_area.Contract(box_outset.unsnapped);
  unsnapped_positioning_area.size.ClampNegativeToZero();
}

void BackgroundImageGeometry::CalculateFillTileSize(
    const FillLayer& fill_layer,
    const ComputedStyle& style,
    const PhysicalSize& unsnapped_positioning_area_size,
    const PhysicalSize& snapped_positioning_area_size) {
  StyleImage* image = fill_layer.GetImage();
  EFillSizeType type = fill_layer.SizeType();

  // Tile size is snapped for images without intrinsic dimensions (typically
  // generated content) and unsnapped for content that has intrinsic
  // dimensions. Once we choose here we stop tracking whether the tile size is
  // snapped or unsnapped.
  IntrinsicSizingInfo sizing_info = image->GetNaturalSizingInfo(
      style.EffectiveZoom(), style.ImageOrientation());
  PhysicalSize image_aspect_ratio =
      PhysicalSize::FromSizeFFloor(sizing_info.aspect_ratio);
  PhysicalSize positioning_area_size = !image->HasIntrinsicSize()
                                           ? snapped_positioning_area_size
                                           : unsnapped_positioning_area_size;
  switch (type) {
    case EFillSizeType::kSizeLength: {
      tile_size_ = positioning_area_size;

      const Length& layer_width = fill_layer.SizeLength().Width();
      const Length& layer_height = fill_layer.SizeLength().Height();

      if (layer_width.IsFixed()) {
        tile_size_.width = LayoutUnit(layer_width.Value());
      } else if (layer_width.IsPercent() || layer_width.IsCalculated()) {
        tile_size_.width =
            ValueForLength(layer_width, positioning_area_size.width);
      }

      if (layer_height.IsFixed()) {
        tile_size_.height = LayoutUnit(layer_height.Value());
      } else if (layer_height.IsPercent() || layer_height.IsCalculated()) {
        tile_size_.height =
            ValueForLength(layer_height, positioning_area_size.height);
      }

      // An auto value for one dimension is resolved by using the image's
      // natural aspect ratio and the size of the other dimension, or failing
      // that, using the image's natural size, or failing that, treating it as
      // 100%.
      // If both values are auto then the natural width and/or height of the
      // image should be used, if any, the missing dimension (if any)
      // behaving as auto as described above. If the image has neither
      // natural size, its size is determined as for contain.
      if (layer_width.IsAuto() && !layer_height.IsAuto()) {
        if (!image_aspect_ratio.IsEmpty()) {
          tile_size_.width =
              ResolveWidthForRatio(tile_size_.height, image_aspect_ratio);
        } else if (sizing_info.has_width) {
          tile_size_.width =
              LayoutUnit::FromFloatFloor(sizing_info.size.width());
        } else {
          tile_size_.width = positioning_area_size.width;
        }
      } else if (!layer_width.IsAuto() && layer_height.IsAuto()) {
        if (!image_aspect_ratio.IsEmpty()) {
          tile_size_.height =
              ResolveHeightForRatio(tile_size_.width, image_aspect_ratio);
        } else if (sizing_info.has_height) {
          tile_size_.height =
              LayoutUnit::FromFloatFloor(sizing_info.size.height());
        } else {
          tile_size_.height = positioning_area_size.height;
        }
      } else if (layer_width.IsAuto() && layer_height.IsAuto()) {
        PhysicalSize concrete_image_size =
            PhysicalSize::FromSizeFFloor(image->ImageSize(
                style.EffectiveZoom(), gfx::SizeF(positioning_area_size),
                style.ImageOrientation()));
        tile_size_ = concrete_image_size;
      }

      tile_size_.ClampNegativeToZero();
      return;
    }
    case EFillSizeType::kContain:
    case EFillSizeType::kCover: {
      if (image_aspect_ratio.IsEmpty()) {
        tile_size_ = snapped_positioning_area_size;
        return;
      }
      // Always use the snapped positioning area size for this computation,
      // so that we resize the image to completely fill the actual painted
      // area.
      // Force the dimension that determines the size to exactly match the
      // positioning_area_size in that dimension.
      tile_size_ = snapped_positioning_area_size.FitToAspectRatio(
          image_aspect_ratio, type == EFillSizeType::kCover
                                  ? kAspectRatioFitGrow
                                  : kAspectRatioFitShrink);
      // Snap the dependent dimension to avoid bleeding/blending artifacts
      // at the edge of the image when we paint it.
      if (type == EFillSizeType::kContain) {
        if (tile_size_.width != snapped_positioning_area_size.width)
          tile_size_.width = LayoutUnit(std::max(1, tile_size_.width.Round()));
        if (tile_size_.height != snapped_positioning_area_size.height) {
          tile_size_.height =
              LayoutUnit(std::max(1, tile_size_.height.Round()));
        }
      } else {
        if (tile_size_.width != snapped_positioning_area_size.width)
          tile_size_.width = std::max(LayoutUnit(1), tile_size_.width);
        if (tile_size_.height != snapped_positioning_area_size.height)
          tile_size_.height = std::max(LayoutUnit(1), tile_size_.height);
      }
      return;
    }
    case EFillSizeType::kSizeNone:
      // This value should only be used while resolving style.
      NOTREACHED();
  }

  NOTREACHED();
}

void BackgroundImageGeometry::CalculateRepeatAndPosition(
    const FillLayer& fill_layer,
    const PhysicalOffset& offset_in_background,
    const PhysicalSize& unsnapped_positioning_area_size,
    const PhysicalSize& snapped_positioning_area_size,
    const PhysicalOffset& unsnapped_box_offset,
    const PhysicalOffset& snapped_box_offset) {
  EFillRepeat background_repeat_x = fill_layer.Repeat().x;
  EFillRepeat background_repeat_y = fill_layer.Repeat().y;

  // Maintain both snapped and unsnapped available widths and heights.
  // Unsnapped values are used for most thing, but snapped are used
  // to computed sizes that must fill the area, such as round and space.
  const LayoutUnit unsnapped_available_width =
      unsnapped_positioning_area_size.width - tile_size_.width;
  const LayoutUnit unsnapped_available_height =
      unsnapped_positioning_area_size.height - tile_size_.height;
  const LayoutUnit snapped_available_width =
      snapped_positioning_area_size.width - tile_size_.width;
  const LayoutUnit snapped_available_height =
      snapped_positioning_area_size.height - tile_size_.height;

  if (background_repeat_x == EFillRepeat::kRoundFill &&
      snapped_positioning_area_size.width > LayoutUnit() &&
      tile_size_.width > LayoutUnit()) {
    LayoutUnit rounded_width = ComputeRoundedTileSize(
        snapped_positioning_area_size.width, tile_size_.width);
    // Maintain aspect ratio if background-size: auto is set
    if (fill_layer.SizeLength().Height().IsAuto() &&
        background_repeat_y != EFillRepeat::kRoundFill) {
      tile_size_.height = ResolveHeightForRatio(rounded_width, tile_size_);
    }
    tile_size_.width = rounded_width;

    // Force the first tile to line up with the edge of the positioning area.
    const LayoutUnit x_offset = ResolveXPosition(
        fill_layer, snapped_available_width, offset_in_background.left);
    SetPhaseX(ComputeTilePhase(x_offset + unsnapped_box_offset.left,
                               tile_size_.width));
    SetSpaceSize(PhysicalSize());
  }

  if (background_repeat_y == EFillRepeat::kRoundFill &&
      snapped_positioning_area_size.height > LayoutUnit() &&
      tile_size_.height > LayoutUnit()) {
    LayoutUnit rounded_height = ComputeRoundedTileSize(
        snapped_positioning_area_size.height, tile_size_.height);
    // Maintain aspect ratio if background-size: auto is set
    if (fill_layer.SizeLength().Width().IsAuto() &&
        background_repeat_x != EFillRepeat::kRoundFill) {
      tile_size_.width = ResolveWidthForRatio(rounded_height, tile_size_);
    }
    tile_size_.height = rounded_height;

    // Force the first tile to line up with the edge of the positioning area.
    const LayoutUnit y_offset = ResolveYPosition(
        fill_layer, snapped_available_height, offset_in_background.top);
    SetPhaseY(ComputeTilePhase(y_offset + unsnapped_box_offset.top,
                               tile_size_.height));
    SetSpaceSize(PhysicalSize());
  }

  if (background_repeat_x == EFillRepeat::kRepeatFill) {
    // Repeat must set the phase accurately, so use unsnapped values.
    // Recompute computed position because here we need to resolve against
    // unsnapped widths to correctly set the phase.
    const LayoutUnit x_offset = ResolveXPosition(
        fill_layer, unsnapped_available_width, offset_in_background.left);
    SetRepeatX(unsnapped_box_offset.left + x_offset);
  } else if (background_repeat_x == EFillRepeat::kSpaceFill &&
             tile_size_.width > LayoutUnit()) {
    // SpaceFill uses snapped values to fill the painted area.
    LayoutUnit space = GetSpaceBetweenImageTiles(
        snapped_positioning_area_size.width, tile_size_.width);
    if (space >= LayoutUnit())
      SetSpaceX(space, snapped_box_offset.left);
    else
      background_repeat_x = EFillRepeat::kNoRepeatFill;
  }
  if (background_repeat_x == EFillRepeat::kNoRepeatFill) {
    // NoRepeat moves the dest rects, so needs both snapped and
    // unsnapped parameters.
    const LayoutUnit x_offset = ResolveXPosition(
        fill_layer, unsnapped_available_width, offset_in_background.left);
    const LayoutUnit snapped_x_offset = ResolveXPosition(
        fill_layer, snapped_available_width, offset_in_background.left);
    SetNoRepeatX(fill_layer, unsnapped_box_offset.left + x_offset,
                 snapped_box_offset.left + snapped_x_offset);
  }

  if (background_repeat_y == EFillRepeat::kRepeatFill) {
    // Repeat must set the phase accurately, so use unsnapped values.
    // Recompute computed position because here we need to resolve against
    // unsnapped widths to correctly set the phase.
    const LayoutUnit y_offset = ResolveYPosition(
        fill_layer, unsnapped_available_height, offset_in_background.top);
    SetRepeatY(unsnapped_box_offset.top + y_offset);
  } else if (background_repeat_y == EFillRepeat::kSpaceFill &&
             tile_size_.height > LayoutUnit()) {
    // SpaceFill uses snapped values to fill the painted area.
    LayoutUnit space = GetSpaceBetweenImageTiles(
        snapped_positioning_area_size.height, tile_size_.height);
    if (space >= LayoutUnit())
      SetSpaceY(space, snapped_box_offset.top);
    else
      background_repeat_y = EFillRepeat::kNoRepeatFill;
  }
  if (background_repeat_y == EFillRepeat::kNoRepeatFill) {
    // NoRepeat moves the dest rects, so needs both snapped and
    // unsnapped parameters.
    const LayoutUnit y_offset = ResolveYPosition(
        fill_layer, unsnapped_available_height, offset_in_background.top);
    const LayoutUnit snapped_y_offset = ResolveYPosition(
        fill_layer, snapped_available_height, offset_in_background.top);
    SetNoRepeatY(fill_layer, unsnapped_box_offset.top + y_offset,
                 snapped_box_offset.top + snapped_y_offset);
  }
}

void BackgroundImageGeometry::Calculate(
    const FillLayer& fill_layer,
    const BoxBackgroundPaintContext& paint_context,
    const PhysicalRect& paint_rect,
    const PaintInfo& paint_info) {
  // Unsnapped positioning area is used to derive quantities
  // that reference source image maps and define non-integer values, such
  // as phase and position.
  PhysicalRect unsnapped_positioning_area;

  // Snapped positioning area is used for sizing images based on the
  // background area (like cover and contain), and for setting the repeat
  // spacing.
  PhysicalRect snapped_positioning_area;

  // Additional offset from the corner of the positioning_box_
  PhysicalOffset unsnapped_box_offset;
  PhysicalOffset snapped_box_offset;

  if (paint_context.ShouldUseFixedAttachment(fill_layer)) {
    unsnapped_positioning_area =
        paint_context.FixedAttachmentPositioningArea(paint_info);
    unsnapped_dest_rect_ = snapped_dest_rect_ = snapped_positioning_area =
        unsnapped_positioning_area;
  } else {
    unsnapped_positioning_area =
        paint_context.NormalPositioningArea(paint_rect);
    unsnapped_dest_rect_ = paint_rect;

    // This method adjusts `unsnapped_dest_rect_` and sets
    // `snapped_dest_rect_`.
    AdjustPositioningArea(fill_layer, paint_context, paint_info,
                          unsnapped_positioning_area, snapped_positioning_area,
                          unsnapped_box_offset, snapped_box_offset);
  }

  // Sets the tile_size_.
  CalculateFillTileSize(fill_layer, paint_context.Style(),
                        unsnapped_positioning_area.size,
                        snapped_positioning_area.size);

  // Applies *-repeat and *-position.
  const PhysicalOffset offset_in_background =
      paint_context.OffsetInBackground(fill_layer);
  CalculateRepeatAndPosition(
      fill_layer, offset_in_background, unsnapped_positioning_area.size,
      snapped_positioning_area.size, unsnapped_box_offset, snapped_box_offset);

  if (paint_context.ShouldUseFixedAttachment(fill_layer)) {
    PhysicalOffset fixed_adjustment =
        paint_rect.offset - unsnapped_dest_rect_.offset;
    fixed_adjustment.ClampNegativeToZero();
    phase_ += fixed_adjustment;
  }

  // The actual painting area can be bigger than the provided background
  // geometry (`paint_rect`) for `mask-clip: no-clip`, so avoid clipping.
  if (fill_layer.Clip() != EFillBox::kNoClip) {
    // Clip the final output rect to the paint rect.
    unsnapped_dest_rect_.Intersect(paint_rect);
    snapped_dest_rect_.Intersect(paint_rect);
  }
  // Re-snap the dest rect as we may have adjusted it with unsnapped values.
  snapped_dest_rect_ = PhysicalRect(ToPixelSnappedRect(snapped_dest_rect_));
}

gfx::RectF BackgroundImageGeometry::ComputePositioningArea(
    const FillLayer& layer,
    const SVGBackgroundPaintContext& paint_context) const {
  switch (layer.Origin()) {
    case EFillBox::kNoClip:
    case EFillBox::kText:
      NOTREACHED();
    case EFillBox::kBorder:
    case EFillBox::kContent:
    case EFillBox::kFillBox:
    case EFillBox::kPadding:
      return paint_context.ReferenceBox(GeometryBox::kFillBox);
    case EFillBox::kStrokeBox:
      return paint_context.ReferenceBox(GeometryBox::kStrokeBox);
    case EFillBox::kViewBox:
      return paint_context.ReferenceBox(GeometryBox::kViewBox);
  }
}

gfx::RectF BackgroundImageGeometry::ComputePaintingArea(
    const FillLayer& layer,
    const SVGBackgroundPaintContext& paint_context,
    const gfx::RectF& positioning_area) const {
  switch (layer.Clip()) {
    case EFillBox::kText:
    case EFillBox::kNoClip:
      return paint_context.VisualOverflowRect();
    case EFillBox::kContent:
    case EFillBox::kFillBox:
    case EFillBox::kPadding:
      return positioning_area;
    case EFillBox::kStrokeBox:
    case EFillBox::kBorder:
      return paint_context.ReferenceBox(GeometryBox::kStrokeBox);
    case EFillBox::kViewBox:
      return paint_context.ReferenceBox(GeometryBox::kViewBox);
  }
}

void BackgroundImageGeometry::Calculate(
    const FillLayer& fill_layer,
    const SVGBackgroundPaintContext& paint_context) {
  const gfx::RectF positioning_area =
      ComputePositioningArea(fill_layer, paint_context);
  const gfx::RectF painting_area =
      ComputePaintingArea(fill_layer, paint_context, positioning_area);
  // Unsnapped positioning area is used to derive quantities
  // that reference source image maps and define non-integer values, such
  // as phase and position.
  PhysicalRect unsnapped_positioning_area =
      PhysicalRect::EnclosingRect(positioning_area);
  unsnapped_dest_
"""


```