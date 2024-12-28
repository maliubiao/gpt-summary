Response:
The user wants a summary of the functionality of the provided C++ code, focusing on its role in the Chromium Blink rendering engine. I need to identify the core purpose of the `PageContainerLayoutAlgorithm` class and explain its interactions with web technologies like JavaScript, HTML, and CSS. I also need to look for logical deductions, potential user/programming errors, and provide examples where applicable.

Here's a breakdown of the code's functionality based on the included headers and the logic within the `Layout()` method:

1. **Page Layout:** The class is responsible for laying out the container for a single page in a paginated context (like printing or PDF generation).
2. **Page Size and Margins:** It handles the calculation and application of page sizes and margins defined by CSS `@page` rules and potentially printer settings.
3. **Page Border Box:** It lays out the page border box, which represents the printable area of the page, taking into account margins.
4. **Page Margin Boxes:** It lays out the various page margin boxes (e.g., `@top-left`, `@bottom-center`) where content like headers and footers can be placed.
5. **Counter Management:** It manages CSS counters within the page context, particularly the `pages` counter for total page count.
6. **Scaling:** It handles scaling of page content to fit the target paper size.
7. **Existing Page Handling:** It can handle scenarios where a page container already exists, potentially for updating counter values without a full relayout.这是 `blink/renderer/core/layout/page_container_layout_algorithm.cc` 文件的第 1 部分，它主要负责执行以下功能：

**核心功能：页面容器的布局**

* **创建页面容器 Fragment:**  该类 `PageContainerLayoutAlgorithm` 的主要目的是为一个页面创建并布局一个 `PhysicalFragment`，类型为 `kPageContainer`。这个 Fragment 代表了渲染输出中的一个单独的页面。
* **处理页面尺寸和边距：** 它负责计算和应用页面尺寸和边距，这些尺寸和边距可能来自 CSS 的 `@page` 规则或者打印设置。
* **布局页面边框盒子 (Page Border Box)：**  它会布局页面的核心内容区域，即页面边框盒子。这个盒子的大小受 `@page` 规则影响。
* **布局页面边距盒子 (Page Margin Boxes)：** 它负责布局各种页面边距盒子，例如 `@top-left-corner`、`@top-center` 等，这些盒子用于放置页眉、页脚等内容。
* **管理页面计数器：** 它参与管理与页面相关的 CSS 计数器，特别是 `counter(pages)`，用于显示总页数。
* **处理页面缩放：**  在打印或生成 PDF 时，如果页面内容需要缩放以适应纸张大小，这个类会参与处理。
* **复用现有页面容器：** 如果已经存在一个页面容器（例如，为了更新总页数而重新访问），它可以复用现有的布局结果，避免重复布局内容。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS (@page 规则)：**  这个类深度依赖于 CSS 的 `@page` 规则。它会解析 `@page` 中定义的 `size` (页面尺寸) 和 margin (边距) 属性，并根据这些属性来计算页面容器和页面边框盒子的大小和位置。
    * **例子：**  如果在 CSS 中定义了 `@page { size: A4; margin: 1in; }`，这个类会根据 A4 纸张的尺寸和 1 英寸的边距来设置页面容器和页面边框盒子的属性。
* **HTML (文档结构)：**  它接收一个 `content_node_`，这通常是文档的主体内容（`<body>` 元素），用于在页面边框盒子中进行布局。
    * **例子：**  HTML 中 `<body><div>This is page content.</div></body>`，`content_node_` 就指向 `<body>` 元素，`<div>` 元素会在页面边框盒子内被布局。
* **CSS (content 属性和计数器)：**  它会处理页面边距盒子中 `content` 属性生成的内容，包括文本、图像和 CSS 计数器。
    * **例子：**  如果在 CSS 中定义了 `@page :left { @bottom-left { content: "Page " counter(page); } }`，这个类会创建相应的布局对象，并根据当前页码设置 `content` 的值。
    * **例子：**  如果在 CSS 中定义了 `@page { @bottom-center { content: "Total Pages: " counter(pages); } }`，这个类会负责获取或计算总页数，并更新 `content` 的值。

**逻辑推理 (假设输入与输出):**

假设 CSS 中定义了：

```css
@page {
  size: 200px 300px;
  margin: 20px;
}
```

**假设输入：**

* `available_size` (可用的纸张尺寸，可能大于或等于页面尺寸):  例如 210px x 310px
* `page_index_`: 0 (第一页)
* `total_page_count_`: 5
* `content_node_`: 代表 `<body>` 元素的 `BlockNode`

**逻辑推理过程：**

1. **计算未缩放的几何信息：** 根据 `@page` 规则计算出理想的页面边框盒子大小 (200px - 20px * 2 = 160px 宽度，300px - 20px * 2 = 260px 高度) 和边距。
2. **计算目标边框盒子矩形：**  根据纸张尺寸和理想的页面边框盒子大小，计算出页面边框盒子在纸张上的位置。如果纸张比页面大，则居中显示。
3. **布局页面边框盒子：** 创建一个 `LayoutBlockFlow` 对象来布局页面内容。
4. **布局边距盒子：** 根据 `@page` 规则中定义的边距盒子（例如 `@top-left`），创建相应的布局对象，并根据其内容和可用空间进行布局。例如，对于 `@bottom-center { content: counter(pages); }`，会显示 "5"。

**可能的输出 (部分):**

* `container_builder_` 中包含一个类型为 `kPageContainer` 的 `PhysicalFragment`。
* 该 `PhysicalFragment` 的尺寸接近 `available_size` (210px x 310px)。
* 该 `PhysicalFragment` 的子 `PhysicalFragment` 代表页面边框盒子，其逻辑尺寸为 160px x 260px，并根据纸张尺寸进行定位。
* 该 `PhysicalFragment` 可能包含多个子 `PhysicalFragment`，分别代表各个边距盒子，例如 `@bottom-center` 盒子的内容为 "5"。

**用户或编程常见的使用错误：**

* **在 `@page` 规则中定义了冲突的尺寸或边距：** 例如，定义的边距过大，导致页面内容无法容纳。 这会导致布局计算出现问题，或者内容被截断。
    * **例子：**  `@page { size: 100px; margin: 60px; }`  会导致页面边框盒子的尺寸为负数。
* **错误地使用 CSS 计数器：** 例如，在页面边距盒子中使用了不存在的计数器，或者在需要总页数时，过早地访问了 `counter(pages)`，此时总页数可能尚未确定。 这会导致显示不正确的值或者布局错误。
    * **例子：**  在没有其他自定义计数器的情况下使用 `counter(my-counter)`。
* **假设页面边距盒子拥有与页面内容相同的布局特性：** 页面边距盒子的布局规则与正常的 HTML 元素有所不同，例如它们的定位方式是相对于页面的边缘。  尝试在边距盒子中使用过于复杂的布局可能会导致意想不到的结果。

**归纳一下它的功能 (第 1 部分):**

`PageContainerLayoutAlgorithm` 类的第 1 部分主要负责**初始化和构建页面容器的框架**。它处理了页面级别的属性，例如尺寸、边距，以及页面边框盒子的布局。 此外，它还开始处理页面边距盒子的布局，并初步涉及了页面计数器的管理。 简而言之，它为页面的内容和页眉页脚等元素的最终布局奠定了基础。

Prompt: 
```
这是目录为blink/renderer/core/layout/page_container_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/layout/page_container_layout_algorithm.h"

#include "third_party/blink/renderer/core/css/page_margins_style.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/pagination_state.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_counter.h"
#include "third_party/blink/renderer/core/layout/layout_quote.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/logical_fragment.h"
#include "third_party/blink/renderer/core/layout/page_border_box_layout_algorithm.h"
#include "third_party/blink/renderer/core/layout/pagination_utils.h"
#include "third_party/blink/renderer/core/style/content_data.h"

namespace blink {

namespace {

void PrepareMarginBoxSpaceBuilder(LogicalSize available_size,
                                  ConstraintSpaceBuilder* builder) {
  builder->SetAvailableSize(available_size);
  builder->SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  builder->SetBlockAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  builder->SetDecorationPercentageResolutionType(
      DecorationPercentageResolutionType::kContainingBlockSize);

  // Each page-margin box always establishes a stacking context.
  builder->SetIsPaintedAtomically(true);
}

LogicalRect SnappedBorderBoxRect(const LogicalRect& rect) {
  // Some considerations here: The offset should be integers, since a
  // translation transform will be applied when printing, and everything will
  // look blurry otherwise. The value should be rounded to the nearest integer
  // (not ceil / floor), to match what it would look like if the same offset
  // were applied from within the document contents (e.g. margin / padding on a
  // regular DIV). The size needs to be rounded up to the nearest integer, to
  // match the page area size used during layout. This is rounded up mainly so
  // that authors may assume that an element with the same block-size as the
  // specified page size will fit on one page.
  return LogicalRect(LayoutUnit(rect.offset.inline_offset.Round()),
                     LayoutUnit(rect.offset.block_offset.Round()),
                     LayoutUnit(rect.size.inline_size.Ceil()),
                     LayoutUnit(rect.size.block_size.Ceil()));
}

}  // anonymous namespace

PageContainerLayoutAlgorithm::PageContainerLayoutAlgorithm(
    const LayoutAlgorithmParams& params,
    wtf_size_t page_index,
    wtf_size_t total_page_count,
    const AtomicString& page_name,
    const BlockNode& content_node,
    const CountersAttachmentContext& counters_context,
    const PageAreaLayoutParams& page_area_params,
    bool ignore_author_page_style,
    const PhysicalBoxFragment* existing_page_container)
    : LayoutAlgorithm(params),
      page_index_(page_index),
      total_page_count_(total_page_count),
      page_name_(page_name),
      content_node_(content_node),
      counters_context_(counters_context.DeepClone()),
      page_area_params_(page_area_params),
      ignore_author_page_style_(ignore_author_page_style),
      existing_page_container_(existing_page_container) {}

const LayoutResult* PageContainerLayoutAlgorithm::Layout() {
  DCHECK(!GetBreakToken());
  container_builder_.SetBoxType(PhysicalFragment::kPageContainer);

  Document& document = Node().GetDocument();

  // The size of a page container will always match the size of the destination
  // (if the destination is actual paper, this is given by the paper size - if
  // it's PDF, the destination size will be calculated solely using the input
  // page size and @page properties).
  //
  // The page border box, on the other hand, is in the coordinate system of
  // layout, which means that it will be affected by @page properties, even if
  // there's a given paper size. When painting the paginated layout, the page
  // border box will be scaled down to fit the paper if necessary, and then
  // centered.
  //
  // If the page size computed from @page properties is smaller than the actual
  // paper, there will be a gap between the page margins and the page border
  // box. This gap will not be used for anything, i.e. the specified margins
  // will left as-is, not expanded.
  //
  // Example: The paper size is 816x1056 (US Letter). Margins are 50px on each
  // side. The size of the page container becomes 816x1056. @page size is 500px
  // (a square). The page border box size will become 400x400 (margins
  // subtracted). The page border box will be centered on paper, meaning that
  // the page border box offset will be 208,328 ((816-400)/2, (1056-400)/2).
  // This does *not* mean that the left,top margins will be 208,328; they remain
  // at 50px. This what will be available to browser-generated headers / footers
  // (and @page margin boxes).
  //
  // When the page size computed from @page properties is larger than the actual
  // paper, it needs to be scaled down before it can be centered. Since it's the
  // page container (and not the page area) that is being scaled down (this is
  // how it's "always" been in Chromium, and it does make sense in a way, since
  // it reduces the amount of shrinking needed), the margins may also need to be
  // shrunk. Example: The paper size is 816x1056 (US Letter). Margins are
  // specified as 50px on each side (from print settings or from @page - doesn't
  // matter). The size of the page container becomes 816x1056. @page size is
  // 1632px (a square). The scale factor will be min(816/1632, 1056/1632) =
  // 0.5. The page border box size used by layout will be 1532x1532 (margins
  // subtracted). When painted, it will be scaled down to 766x766. When centered
  // on paper, we're going to need a border box left,top offset of 25,145. The
  // remaining width after scaling down the page border box is 816-766=50. The
  // remaining height is 1056-766=290. There's 50px of available width for
  // horizontal margins, but they actually wanted 50px each. So they need to be
  // adjusted to 25px. There's 290px of available height for vertical
  // margins. They wanted 50px each, and will be kept at that value.
  //
  // We now need to figure out how large the page "wants to be" in layout
  // (source), compare to constraints given by the physical paper size, scale it
  // down, adjust margins, and center on the sheet accordingly (destination).
  FragmentGeometry unscaled_geometry;
  BoxStrut margins;
  LogicalSize containing_block_size =
      DesiredPageContainingBlockSize(document, Style());
  ResolvePageBoxGeometry(Node(), containing_block_size, &unscaled_geometry,
                         &margins);

  LogicalSize source_page_margin_box_size(
      unscaled_geometry.border_box_size.inline_size + margins.InlineSum(),
      unscaled_geometry.border_box_size.block_size + margins.BlockSum());
  LogicalRect target_page_border_box_rect = TargetPageBorderBoxLogicalRect(
      document, Style(), source_page_margin_box_size, margins);
  target_page_border_box_rect =
      SnappedBorderBoxRect(target_page_border_box_rect);

  // The offset of the page border box is in the coordinate system of the target
  // (fitting to the sheet of paper, if applicable, for instance), whereas the
  // *size* of the page border box is in the coordinate system of layout (which
  // honors @page size, and various sorts of scaling). We now need to help the
  // fragment builder a bit, so that it ends up with the correct physical target
  // offset in the end.
  WritingModeConverter converter(Style().GetWritingDirection(),
                                 GetConstraintSpace().AvailableSize());
  PhysicalRect border_box_physical_rect =
      converter.ToPhysical(target_page_border_box_rect);
  // We have the correct physical offset in the target coordinate system here,
  // but in order to calculate the corresponding logical offset, we need to
  // convert it against the margin box size in the layout coordinate system, so
  // that, when the fragment builder eventually wants to calculate the physical
  // offset, it will get it right, by converting against the fragment's border
  // box size (which is in the layout coordinate system), with the outer size
  // being the target ("paper") size.
  border_box_physical_rect.size =
      converter.ToPhysical(unscaled_geometry.border_box_size);
  LogicalOffset target_offset =
      converter.ToLogical(border_box_physical_rect).offset;

  counters_context_.EnterObject(*Node().GetLayoutBox(), /*is_page_box=*/true);

  LayoutPageBorderBox(containing_block_size, target_offset);

  // Paper fitting may require margins to be reduced. If contents are scaled
  // down to fit, so are the margins.
  BoxStrut minimal_margins(GetConstraintSpace().AvailableSize(),
                           target_page_border_box_rect);
  margins.Intersect(minimal_margins);

  LayoutAllMarginBoxes(margins);

  counters_context_.LeaveObject(*Node().GetLayoutBox(), /*is_page_box=*/true);

  return container_builder_.ToBoxFragment();
}

void PageContainerLayoutAlgorithm::LayoutPageBorderBox(
    LogicalSize containing_block_size,
    LogicalOffset target_offset) {
  if (existing_page_container_) {
    // A page container was created previously. But we had to come back and
    // update the total page count (counter(pages)). We can just keep the old
    // page border box (including all paginated content), though. No need for a
    // re-layout.
    const PhysicalBoxFragment& page_border_box_fragment =
        GetPageBorderBox(*existing_page_container_);
    const LayoutResult* existing_border_box_result =
        page_border_box_fragment.OwnerLayoutBox()->GetLayoutResult(0);
    container_builder_.AddResult(*existing_border_box_result, target_offset,
                                 /*margins=*/std::nullopt);
    return;
  }

  Document& document = Node().GetDocument();
  const LayoutView& layout_view = *document.GetLayoutView();
  const ComputedStyle* content_scaled_style = &Style();
  float layout_scale = layout_view.PaginationScaleFactor();
  if (layout_scale != 1 && !ignore_author_page_style_) {
    // Scaling shouldn't apply to @page borders etc. Apply a zoom property to
    // cancel out the effect of layout scaling.
    content_scaled_style = document.GetStyleResolver().StyleForPage(
        page_index_, page_name_, layout_scale);
  }

  LayoutBlockFlow* page_border_box =
      document.View()->GetPaginationState()->CreateAnonymousPageLayoutObject(
          document, *content_scaled_style);
  BlockNode page_border_box_node(page_border_box);

  FragmentGeometry geometry;
  ResolvePageBoxGeometry(page_border_box_node,
                         containing_block_size * layout_scale, &geometry);

  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       Style().GetWritingDirection(),
                                       /*is_new_fc=*/true);
  space_builder.SetAvailableSize(GetConstraintSpace().AvailableSize());
  space_builder.SetIsPaintedAtomically(true);
  ConstraintSpace child_space = space_builder.ToConstraintSpace();
  LayoutAlgorithmParams params(page_border_box_node, geometry, child_space,
                               /*break_token=*/nullptr);
  PageBorderBoxLayoutAlgorithm child_algorithm(params, content_node_,
                                               page_area_params_);
  const LayoutResult* result = child_algorithm.Layout();

  // Since we didn't lay out via BlockNode::Layout(), but rather picked and
  // initialized a child layout algorithm on our own, we have some additional
  // work to invoke on our own:
  page_border_box_node.FinishPageContainerLayout(result);

  container_builder_.AddResult(*result, target_offset,
                               /*margins=*/std::nullopt);

  fragmentainer_break_token_ = child_algorithm.FragmentainerBreakToken();
}

void PageContainerLayoutAlgorithm::LayoutAllMarginBoxes(
    const BoxStrut& logical_margins) {
  Document& document = Node().GetDocument();
  PageMarginsStyle margins_style;
  document.GetStyleResolver().StyleForPageMargins(Style(), page_index_,
                                                  page_name_, &margins_style);

  // Margin boxes are positioned according to their type physically - meaning
  // that e.g. @top-left-corner always means the top left corner, regardless of
  // writing mode. Although layout works on logical sizes and offsets, it's less
  // confusing here to use physical ones (and convert to logical values right
  // before entering layout), rather than inventing a bunch of writing-mode
  // agnositic terminology that doesn't exist in the spec.
  PhysicalSize page_box_size =
      ToPhysicalSize(GetConstraintSpace().AvailableSize(),
                     GetConstraintSpace().GetWritingMode());
  PhysicalBoxStrut margins = logical_margins.ConvertToPhysical(
      GetConstraintSpace().GetWritingDirection());
  LayoutUnit right_edge = page_box_size.width - margins.right;
  LayoutUnit bottom_edge = page_box_size.height - margins.bottom;

  PhysicalRect top_left_corner_rect(LayoutUnit(), LayoutUnit(), margins.left,
                                    margins.top);
  PhysicalRect top_right_corner_rect(right_edge, LayoutUnit(), margins.right,
                                     margins.top);
  PhysicalRect bottom_right_corner_rect(right_edge, bottom_edge, margins.right,
                                        margins.bottom);
  PhysicalRect bottom_left_corner_rect(LayoutUnit(), bottom_edge, margins.left,
                                       margins.bottom);
  PhysicalRect top_edge_rect(margins.left, LayoutUnit(),
                             page_box_size.width - margins.HorizontalSum(),
                             margins.top);
  PhysicalRect right_edge_rect(right_edge, margins.top, margins.right,
                               page_box_size.height - margins.VerticalSum());
  PhysicalRect bottom_edge_rect(margins.left, bottom_edge,
                                page_box_size.width - margins.HorizontalSum(),
                                margins.bottom);
  PhysicalRect left_edge_rect(LayoutUnit(), margins.top, margins.left,
                              page_box_size.height - margins.VerticalSum());

  // Lay out in default paint order. Start in the top left corner and go
  // clockwise. See https://drafts.csswg.org/css-page-3/#painting
  LayoutCornerMarginNode(margins_style[PageMarginsStyle::TopLeftCorner],
                         top_left_corner_rect, TopEdge | LeftEdge);
  LayoutEdgeMarginNodes(margins_style[PageMarginsStyle::TopLeft],
                        margins_style[PageMarginsStyle::TopCenter],
                        margins_style[PageMarginsStyle::TopRight],
                        top_edge_rect, TopEdge);
  LayoutCornerMarginNode(margins_style[PageMarginsStyle::TopRightCorner],
                         top_right_corner_rect, TopEdge | RightEdge);
  LayoutEdgeMarginNodes(margins_style[PageMarginsStyle::RightTop],
                        margins_style[PageMarginsStyle::RightMiddle],
                        margins_style[PageMarginsStyle::RightBottom],
                        right_edge_rect, RightEdge);
  LayoutCornerMarginNode(margins_style[PageMarginsStyle::BottomRightCorner],
                         bottom_right_corner_rect, BottomEdge | RightEdge);
  LayoutEdgeMarginNodes(margins_style[PageMarginsStyle::BottomLeft],
                        margins_style[PageMarginsStyle::BottomCenter],
                        margins_style[PageMarginsStyle::BottomRight],
                        bottom_edge_rect, BottomEdge);
  LayoutCornerMarginNode(margins_style[PageMarginsStyle::BottomLeftCorner],
                         bottom_left_corner_rect, BottomEdge | LeftEdge);
  LayoutEdgeMarginNodes(margins_style[PageMarginsStyle::LeftTop],
                        margins_style[PageMarginsStyle::LeftMiddle],
                        margins_style[PageMarginsStyle::LeftBottom],
                        left_edge_rect, LeftEdge);

  container_builder_.SetFragmentsTotalBlockSize(
      container_builder_.FragmentBlockSize());
}

void PageContainerLayoutAlgorithm::LayoutCornerMarginNode(
    const ComputedStyle* corner_style,
    const PhysicalRect& rect,
    EdgeAdjacency edge_adjacency) {
  BlockNode corner_node = CreateBlockNodeIfNeeded(corner_style);
  if (!corner_node) {
    return;
  }

  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       corner_style->GetWritingDirection(),
                                       /*is_new_fc=*/true);
  WritingModeConverter converter(Style().GetWritingDirection(),
                                 GetConstraintSpace().AvailableSize());
  LogicalRect logical_rect = converter.ToLogical(rect);
  PrepareMarginBoxSpaceBuilder(logical_rect.size, &space_builder);
  ConstraintSpace child_space = space_builder.ToConstraintSpace();

  const LayoutResult* result = corner_node.Layout(child_space);
  const auto& box_fragment =
      To<PhysicalBoxFragment>(result->GetPhysicalFragment());
  PhysicalBoxStrut physical_margins =
      ResolveMargins(child_space, *corner_style, box_fragment.Size(), rect.size,
                     edge_adjacency);
  BoxStrut logical_margins =
      physical_margins.ConvertToLogical(Style().GetWritingDirection());
  LogicalOffset offset = logical_rect.offset + logical_margins.StartOffset();
  container_builder_.AddResult(*result, offset);
}

void PageContainerLayoutAlgorithm::LayoutEdgeMarginNodes(
    const ComputedStyle* start_box_style,
    const ComputedStyle* center_box_style,
    const ComputedStyle* end_box_style,
    const PhysicalRect& edge_rect,
    EdgeAdjacency edge_adjacency) {
  BlockNode nodes[3] = {CreateBlockNodeIfNeeded(start_box_style),
                        CreateBlockNodeIfNeeded(center_box_style),
                        CreateBlockNodeIfNeeded(end_box_style)};
  LayoutUnit main_axis_sizes[3];

  ProgressionDirection dir;
  switch (edge_adjacency) {
    case TopEdge:
      dir = LeftToRight;
      break;
    case RightEdge:
      dir = TopToBottom;
      break;
    case BottomEdge:
      dir = RightToLeft;
      break;
    case LeftEdge:
      dir = BottomToTop;
      break;
    default:
      NOTREACHED();
  }

  CalculateEdgeMarginBoxSizes(edge_rect.size, nodes, dir, main_axis_sizes);

  if (IsReverse(dir)) {
    LayoutEdgeMarginNode(nodes[EndMarginBox], edge_rect,
                         main_axis_sizes[EndMarginBox], EndMarginBox,
                         edge_adjacency, dir);
    LayoutEdgeMarginNode(nodes[CenterMarginBox], edge_rect,
                         main_axis_sizes[CenterMarginBox], CenterMarginBox,
                         edge_adjacency, dir);
    LayoutEdgeMarginNode(nodes[StartMarginBox], edge_rect,
                         main_axis_sizes[StartMarginBox], StartMarginBox,
                         edge_adjacency, dir);
  } else {
    LayoutEdgeMarginNode(nodes[StartMarginBox], edge_rect,
                         main_axis_sizes[StartMarginBox], StartMarginBox,
                         edge_adjacency, dir);
    LayoutEdgeMarginNode(nodes[CenterMarginBox], edge_rect,
                         main_axis_sizes[CenterMarginBox], CenterMarginBox,
                         edge_adjacency, dir);
    LayoutEdgeMarginNode(nodes[EndMarginBox], edge_rect,
                         main_axis_sizes[EndMarginBox], EndMarginBox,
                         edge_adjacency, dir);
  }
}

BlockNode PageContainerLayoutAlgorithm::CreateBlockNodeIfNeeded(
    const ComputedStyle* page_margin_style) {
  if (!page_margin_style) {
    return BlockNode(nullptr);
  }
  const ContentData* content = page_margin_style->GetContentData();
  if (!content) {
    return BlockNode(nullptr);
  }

  Document& document = Node().GetDocument();
  LayoutBlockFlow* margin_layout_box =
      document.View()->GetPaginationState()->CreateAnonymousPageLayoutObject(
          document, *page_margin_style);

  counters_context_.EnterObject(*margin_layout_box);

  int quote_depth = 0;
  for (; content; content = content->Next()) {
    if (content->IsAltText() || content->IsNone()) {
      continue;
    }
    LayoutObject* child = content->CreateLayoutObject(*margin_layout_box);
    if (margin_layout_box->IsChildAllowed(child, *page_margin_style)) {
      margin_layout_box->AddChild(child);

      if (auto* quote = DynamicTo<LayoutQuote>(child)) {
        quote->SetDepth(quote_depth);
        quote->UpdateText();
        quote_depth = quote->GetNextDepth();
      } else if (auto* counter = DynamicTo<LayoutCounter>(child)) {
        Vector<int> values;
        const auto* counter_data = To<CounterContentData>(content);
        if (counter_data->Identifier() == "pages") {
          if (!total_page_count_) {
            // Someone wants to output the total page count. In order to
            // calculate a total page count, we first have to lay out all pages,
            // and then come back for a second pass.
            DCHECK(!existing_page_container_);
            needs_total_page_count_ = true;
          }
          values.push_back(total_page_count_);
        } else {
          values = counters_context_.GetCounterValues(
              *Node().GetLayoutBox(), counter->Identifier(),
              counter->Separator().IsNull());
        }
        counter->UpdateCounter(std::move(values));
      }
    } else {
      child->Destroy();
    }
  }

  counters_context_.LeaveObject(*margin_layout_box);

  if (!margin_layout_box->FirstChild()) {
    // No content was added.
    margin_layout_box = nullptr;
  }

  return BlockNode(margin_layout_box);
}

PageContainerLayoutAlgorithm::PreferredSizeInfo
PageContainerLayoutAlgorithm::EdgeMarginNodePreferredSize(
    const BlockNode& child,
    LogicalSize containing_block_size,
    ProgressionDirection dir) const {
  DCHECK(child);
  ConstraintSpaceBuilder space_builder(GetConstraintSpace(),
                                       child.Style().GetWritingDirection(),
                                       /*is_new_fc=*/true);

  space_builder.SetAvailableSize(containing_block_size);
  space_builder.SetDecorationPercentageResolutionType(
      DecorationPercentageResolutionType::kContainingBlockSize);
  ConstraintSpace child_space = space_builder.ToConstraintSpace();
  BoxStrut margins = ComputeMarginsForSelf(child_space, child.Style());

  MinMaxSizes minmax;
  LayoutUnit margin_sum;

  bool main_axis_is_inline_for_child =
      IsHorizontal(dir) == child.Style().IsHorizontalWritingMode();
  bool main_axis_is_auto;
  if (main_axis_is_inline_for_child) {
    main_axis_is_auto = child.Style().LogicalWidth().IsAuto();
    if (main_axis_is_auto) {
      ConstraintSpaceBuilder intrinsic_space_builder(
          GetConstraintSpace(), child.Style().GetWritingDirection(),
          /*is_new_fc=*/true);
      intrinsic_space_builder.SetCacheSlot(LayoutResultCacheSlot::kMeasure);
      minmax = ComputeMinAndMaxContentContributionForSelf(
                   child, intrinsic_space_builder.ToConstraintSpace())
                   .sizes;
    } else {
      BoxStrut border_padding = ComputeBorders(child_space, child) +
                                ComputePadding(child_space, child.Style());
      minmax = ComputeInlineSizeForFragment(child_space, child, border_padding);
    }
    margin_sum = margins.InlineSum();
  } else {
    // Need to lay out for block-sizes.
    main_axis_is_auto = child.Style().LogicalHeight().IsAuto();
    const LayoutResult* result = child.Layout(child_space);
    LogicalSize size = result->GetPhysicalFragment().Size().ConvertToLogical(
        child_space.GetWritingMode());
    minmax.min_size = size.block_size;
    minmax.max_size = size.block_size;
    margin_sum = margins.BlockSum();
  }

  return PreferredSizeInfo(minmax, margin_sum, main_axis_is_auto);
}

void PageContainerLayoutAlgorithm::CalculateEdgeMarginBoxSizes(
    PhysicalSize available_physical_size,
    const BlockNode nodes[3],
    ProgressionDirection dir,
    LayoutUnit final_main_axis_sizes[3]) const {
  LayoutUnit available_main_axis_size;
  if (IsHorizontal(dir)) {
    available_main_axis_size = available_physical_size.width;
  } else {
    available_main_axis_size = available_physical_size.height;
  }

  LogicalSize available_logical_size =
      available_physical_size.ConvertToLogical(Style().GetWritingMode());
  PreferredSizeInfo preferred_main_axis_sizes[3];
  LayoutUnit total_max_size_for_auto;
  bool has_auto_sized_box = false;
  for (int i = 0; i < 3; i++) {
    if (!nodes[i]) {
      continue;
    }
    preferred_main_axis_sizes[i] =
        EdgeMarginNodePreferredSize(nodes[i], available_logical_size, dir);
    // Tentatively set main sizes to the preferred ones. Any auto specified size
    // will be adjusted further below.
    final_main_axis_sizes[i] = preferred_main_axis_sizes[i].MaxLength();

    if (preferred_main_axis_sizes[i].IsAuto()) {
      has_auto_sized_box = true;
      total_max_size_for_auto += preferred_main_axis_sizes[i].MaxLength();
    }
  }

  if (has_auto_sized_box && !total_max_size_for_auto) {
    // There's no content in any of the auto-sized boxes to take up space. Make
    // sure that extra space is distributed evenly by giving them a non-zero max
    // content size (1) so that they get the same flex factor.
    for (auto& preferred_main_axis_size : preferred_main_axis_sizes) {
      if (preferred_main_axis_size.IsAuto()) {
        preferred_main_axis_size = PreferredSizeInfo(
            /*min_max=*/{LayoutUnit(1), LayoutUnit(1)},
            /*margin_sum=*/LayoutUnit(), /*is_auto=*/true);
      }
    }
  }

  if (nodes[CenterMarginBox]) {
    if (preferred_main_axis_sizes[CenterMarginBox].IsAuto()) {
      // To resolve auto center size, and to allow for center placement, resolve
      // for start and end separately multiplied by two. Figure out which one
      // results in a bigger size, and thus a smaller center size.
      //
      // The spec introduces an imaginary "AC" box, which is twice the larger of
      // start and end, but this needs to be done in two separate steps, in case
      // one of start and end has auto size, whereas the other doesn't (and
      // should therefore not be stretched).
      //
      // See https://drafts.csswg.org/css-page-3/#variable-auto-sizing
      PreferredSizeInfo ac_sizes_for_start[3] = {
          preferred_main_axis_sizes[CenterMarginBox], PreferredSizeInfo(),
          preferred_main_axis_sizes[StartMarginBox].Doubled()};
      PreferredSizeInfo ac_sizes_for_end[3] = {
          preferred_main_axis_sizes[CenterMarginBox], PreferredSizeInfo(),
          preferred_main_axis_sizes[EndMarginBox].Doubled()};

      LayoutUnit center_size1;
      LayoutUnit center_size2;
      LayoutUnit ignored_ac_size;
      ResolveTwoEdgeMarginBoxLengths(ac_sizes_for_start,
                                     available_main_axis_size, &center_size1,
                                     &ignored_ac_size);
      ResolveTwoEdgeMarginBoxLengths(ac_sizes_for_end, available_main_axis_size,
                                     &center_size2, &ignored_ac_size);
      final_main_axis_sizes[CenterMarginBox] =
          std::min(center_size1, center_size2);
    }
    // Any auto start or end should receive half of the space not used by
    // center.
    LayoutUnit side_space =
        available_main_axis_size - final_main_axis_sizes[CenterMarginBox];
    if (preferred_main_axis_sizes[StartMarginBox].IsAuto()) {
      final_main_axis_sizes[StartMarginBox] = side_space / 2;
    }
    if (preferred_main_axis_sizes[EndMarginBox].IsAuto()) {
      // If both start and end are auto, make sure that start+end is exactly
      // side_space (avoid rounding errors).
      final_main_axis_sizes[EndMarginBox] = side_space - side_space / 2;
    }
  } else {
    ResolveTwoEdgeMarginBoxLengths(preferred_main_axis_sizes,
                                   available_main_axis_size,
                                   &final_main_axis_sizes[StartMarginBox],
                                   &final_main_axis_sizes[EndMarginBox]);
  }

  // TODO(crbug.com/40341678): Honor min-width, max-width, min-height,
  // max-height.

  // Convert from margin-box to border-box lengths.
  for (int i = 0; i < 3; i++) {
    final_main_axis_sizes[i] -= preferred_main_axis_sizes[i].MarginSum();
    final_main_axis_sizes[i] = final_main_axis_sizes[i].ClampNegativeToZero();
  }
}

void PageContainerLayoutAlgorithm::ResolveTwoEdgeMarginBoxLengths(
    const PreferredSizeInfo preferred_main_axis_sizes[3],
    LayoutUnit available_main_axis_size,
    LayoutUnit* first_main_axis_size,
    LayoutUnit* second_main_axis_size) {
  // If the center box has non-auto main size, preferred_main_axis_sizes will
  // here simply be that of the start, center and end boxes.
  //
  // However, if center has auto size, the actual preferred sizes for auto is
  // moved to FirstResolvee, and the double of the preferred size for either
  // start or end can be found at SecondResolvee. In this case, this function
  // will be called twice, once for the double start box and once for the double
  // end box. Then the caller will decide which result to keep.
  DCHECK(!preferred_main_axis_sizes[NonResolvee].IsAuto());

  // First determine how much of the space is auto, to calculate bases for the
  // flex factor sum (min, max, or max minus min; see below), and how much space
  // is available for the auto-sized boxes.
  LayoutUnit available_main_axis_size_for_flex = available_main_axis_size;
  LayoutUnit total_auto_min_size;
  LayoutUnit total_auto_max_size;
  for (int i = 0; i < 3; i++) {
    if (preferred_main_axis_sizes[i].IsAuto()) {
      total_auto_min_size += preferred_main_axis_sizes[i].MinLength();
      total_auto_max_size += preferred_main_axis_sizes[i].MaxLength();
    } else {
      // Fixed-size box.
      available_main_axis_size_for_flex -=
          preferred_main_axis_sizes[i].Length();
    }
  }

  LayoutUnit flex_space;  // Additional space to distribute to auto-sized boxes.
  LayoutUnit unflexed_sizes[3];
  LayoutUnit flex_factors[3];
  if (available_main_axis_size_for_flex > total_auto_max_size) {
    flex_space = available_main_axis_size_for_flex - total_auto_max_size;
    // The sum of the max content lengths is less than available length. Each
    // box's flex factor is proportional to its max content length.
    for (int i = 0; i < 3; i++) {
      unflexed_sizes[i] = preferred_main_axis_sizes[i].MaxLength();
      flex_factors[i] = unflexed_sizes[i];
    }
  } else {
    flex_space = available_main_axis_size_for_flex - total_auto_min_size;
    for (int i = 0; i < 3; i++) {
      unflexed_sizes[i] = preferred_main_axis_sizes[i].MinLength();
    }
    if (flex_space > LayoutUnit()) {
      // The sum of the min content lengths is less than the available length
      // (whereas the sum of the *max* content lengths is not). Each box's flex
      // factor as proportional to its max content length minus min content
      // length,
      for (int i = 0; i < 3; i++) {
        flex_factors[i] = preferred_main_axis_sizes[i].MaxLength() -
                          preferred_main_axis_sizes[i].MinLength();
      }
    } else {
      // The sum of min sizes is larger than available size. Boxes will have to
      // shrink below their min content length to fit.
      for (int i = 0; i < 3; i++) {
        flex_factors[i] = preferred_main_axis_sizes[i].MinLength();
      }
    }
  }

  *first_main_axis_size = unflexed_sizes[FirstResolvee];
  *second_main_axis_size = unflexed_sizes[SecondResolvee];
  if (preferred_main_axis_sizes[FirstResolvee].IsAuto()) {
    if (preferred_main_axis_sizes[SecondResolvee].IsAuto()) {
      // Both have auto size.
      LayoutUnit total_flex =
          flex_factors[FirstResolvee] + flex_factors[SecondResolvee];
      if (total_flex > LayoutUnit()) {
        *first_main_axis_size +=
            flex_space * flex_factors[FirstResolvee] / total_flex;
      }
    } else {
      // Only first has auto size.
      *first_main_axis_size = available_main_axis_size - *second_main_axis_size;
    }
  }
  if (preferred_m
"""


```