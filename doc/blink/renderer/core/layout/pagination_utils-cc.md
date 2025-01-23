Response:
Let's break down the thought process for analyzing the provided `pagination_utils.cc` file and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this specific Chromium Blink engine source file (`pagination_utils.cc`) and explain its relevance to web technologies (JavaScript, HTML, CSS) and potential usage scenarios, including common errors.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for key terms and patterns. This involves noticing:

* **Includes:**  `printing/mojom/print.mojom-blink.h`, `WebPrintPageDescription.h`, `WebPrintParams.h`, and various layout-related headers (`LayoutBlockFlow.h`, `LayoutView.h`, etc.). This immediately signals a strong connection to printing functionality and the layout engine.
* **Namespaces:**  `blink` and an anonymous namespace. This is standard Chromium practice.
* **Function Names:**  Descriptive names like `ShouldCenterPageOnPaper`, `PageBoxDefaultSize`, `SetUpSpaceBuilderForPageBox`, `DesiredPageContainingBlockSize`, `ResolvePageBoxGeometry`, `CalculateInitialContainingBlockSizeForPagination`, `TargetScaleForPage`, `FittedPageContainerSize`, `TargetPageBorderBoxLogicalRect`, `PageCount`, `GetPageContainer`, `GetPageArea`, `StitchedPageContentRect`, `CalculateOverflowShrinkForPrinting`, `GetPageDescriptionFromLayout`. These names are crucial for inferring functionality.
* **Data Structures:**  `WebPrintParams`, `WebPrintPageDescription`, `PhysicalSize`, `LogicalSize`, `FragmentGeometry`, `BoxStrut`, `PhysicalBoxFragment`, `ComputedStyle`. These indicate the types of data being manipulated.
* **Constants/Enums:** `printing::mojom::blink::PrintScalingOption`.
* **Core Logic Patterns:** Calculations involving sizes, offsets, scaling, and manipulation of layout fragments (pages, borders, areas).

**3. Deeper Dive into Functionality (Grouping and Categorization):**

Based on the initial scan, I start to group the functions based on their apparent purpose:

* **Printing Parameters & Page Setup:** Functions like `ShouldCenterPageOnPaper`, `PageBoxDefaultSize`, `PageBoxDefaultSizeWithSourceOrientation`, `DesiredPageContainingBlockSize`, `SetUpSpaceBuilderForPageBox`. These seem to handle initial page configuration based on print settings and CSS.
* **Layout Calculations & Geometry:** Functions like `ResolvePageBoxGeometry`, `CalculateInitialContainingBlockSizeForPagination`, `TargetScaleForPage`, `FittedPageContainerSize`, `TargetPageBorderBoxLogicalRect`. These are clearly involved in calculating the size and position of page elements during layout, especially for printing.
* **Page Fragment Access & Information Retrieval:**  Functions like `PageCount`, `GetPageContainer`, `GetPageArea`, `GetPageBorderBox`, `StitchedPageContentRect`, `PageNumberFromPageArea`. These provide ways to navigate and extract information from the layout tree's page fragments.
* **Scaling and Overflow Handling:** `TargetShrinkScaleFactor`, `CalculateOverflowShrinkForPrinting`. These deal with adjusting content to fit the page.
* **Generating Print Description:** `GetPageDescriptionFromLayout`. This seems to be the final stage of gathering information for the actual print output.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Now, I start connecting the identified functionalities to how these relate to web development:

* **CSS:** The file heavily uses `ComputedStyle`, and functions like `DesiredPageContainingBlockSize` and `ResolvePageBoxGeometry` directly interact with CSS properties like `size`, `orientation`, and margins. The concept of page margin boxes directly relates to CSS.
* **HTML:**  While the C++ code doesn't directly parse HTML, it operates on the *rendered* output of HTML. The layout engine processes the HTML structure and applies CSS. The pagination concepts are essential when printing multi-page HTML documents.
* **JavaScript:**  JavaScript's `window.print()` API triggers the printing process that this code supports. While the C++ code doesn't execute JavaScript, it provides the underlying mechanisms for how the browser handles the print request. Specifically, JavaScript can influence print settings.

**5. Creating Examples and Scenarios:**

To solidify understanding, I create hypothetical examples:

* **CSS `size` property:**  Demonstrating how the `size: A4 landscape;` CSS affects the output.
* **CSS margins:**  Explaining how margins are handled and the possibility of negative margins.
* **`window.print()`:**  Illustrating how JavaScript initiates the process.

**6. Identifying Logic and Assumptions:**

I examine functions like `TargetShrinkScaleFactor` and note the implicit assumption that content should be shrunk to fit rather than clipped if it overflows. This leads to the "Assumption/Logic" section.

**7. Considering Common Errors:**

Based on the functionalities, I think about common mistakes developers might make:

* **Incorrect `size` values:** Leading to unexpected page sizes or orientations.
* **Conflicting CSS:** When multiple styles conflict, the output might be surprising.
* **Large unbreakable content:** This can force scaling or overflow, which the `CalculateOverflowShrinkForPrinting` function handles.

**8. Structuring the Explanation:**

Finally, I organize the information logically, using headings and bullet points for clarity:

* **Core Functionality:** A high-level overview.
* **Detailed Functionality Breakdown:** Explaining each function group with more detail.
* **Relationship to Web Technologies:** Connecting to JavaScript, HTML, and CSS with concrete examples.
* **Logic and Assumptions:**  Highlighting internal workings.
* **Common Usage Errors:** Providing practical advice.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This seems solely about printing."  **Correction:** While heavily focused on printing, it's deeply integrated with the layout engine and how CSS styles are applied during rendering for printing.
* **Initial thought:** "Just list the function names and their parameters." **Correction:** Provide a higher-level explanation of the *purpose* of the functions and how they work together.
* **Initial thought:** "Focus only on the code." **Correction:**  Emphasize the user-facing implications and how developers interact with these features through web technologies.

By following this iterative process of scanning, categorizing, connecting, exemplifying, and refining, I can create a comprehensive and understandable explanation of the `pagination_utils.cc` file.
这个文件 `blink/renderer/core/layout/pagination_utils.cc` 是 Chromium Blink 渲染引擎中的一个源代码文件，它提供了一系列用于处理 **分页 (pagination)** 相关的实用工具函数。这些函数主要服务于将网页内容分割成多个页面以进行打印或在分页媒介上显示。

以下是该文件主要功能的详细列表：

**核心功能：**

1. **页面尺寸和方向处理:**
   - 计算和确定页面的默认尺寸 (`PageBoxDefaultSize`)，包括考虑打印参数和文档信息。
   - 根据 CSS 样式（如 `size` 和 `orientation` 属性）调整页面尺寸和方向 (`DesiredPageContainingBlockSize`)。
   - 处理页面尺寸类型的变化，例如 `auto`，`landscape`，`portrait` 和 `fixed`。
   - 考虑用户是否忽略页面大小的打印设置。

2. **页面布局和几何计算:**
   - 为页面框 (page box) 设置约束空间构建器 (`SetUpSpaceBuilderForPageBox`)，用于布局计算。
   - 解析页面框的几何属性，包括边框盒尺寸和边距 (`ResolvePageBoxGeometry`)。
   - 计算分页的初始包含块尺寸 (`CalculateInitialContainingBlockSizeForPagination`)。

3. **页面缩放处理:**
   - 计算在打印时将内容缩放到目标页面尺寸的缩放因子 (`TargetShrinkScaleFactor`, `TargetScaleForPage`)，以避免内容溢出。
   - 确定适合页面容器的尺寸 (`FittedPageContainerSize`)，考虑到是否需要居中页面。
   - 计算目标页面的边框盒逻辑矩形 (`TargetPageBorderBoxLogicalRect`)，包括考虑缩放和居中。

4. **页面片段 (Fragment) 管理:**
   - 获取页面总数 (`PageCount`)。
   - 获取指定索引的页面容器片段 (`GetPageContainer`) 和页面区域片段 (`GetPageArea`)。
   - 获取页面边框盒片段的链接和实际片段 (`GetPageBorderBoxLink`, `GetPageBorderBox`).
   - 获取页面区域片段 (`GetPageArea`).

5. **内容拼接和偏移计算:**
   - 计算缝合后的页面内容矩形 (`StitchedPageContentRect`)，用于处理多列或连续页面布局。
   - 查找指定页面区域之前的中断标记 (`FindPreviousBreakTokenForPageArea`)，用于确定内容的偏移。

6. **打印溢出处理:**
   - 计算打印时由于内容溢出需要进行的缩小比例 (`CalculateOverflowShrinkForPrinting`)。

7. **生成打印页面描述:**
   - 从布局信息中生成 `WebPrintPageDescription` 对象 (`GetPageDescriptionFromLayout`)，包含了页面的尺寸、边距、方向等信息，用于实际的打印操作。 这部分会考虑页面边距框，并根据其与页面边缘的相交情况来抑制浏览器默认的页眉页脚。

**与 JavaScript, HTML, CSS 的关系：**

该文件直接服务于浏览器如何渲染和打印通过 HTML 和 CSS 定义的网页内容。

* **CSS:** 该文件深入理解和使用了 CSS 的分页相关属性，例如：
    - **`size`**:  `DesiredPageContainingBlockSize` 函数会根据 CSS 的 `size` 属性（例如 `size: A4 landscape;`）来设置页面的尺寸和方向。
    - **`orientation`**: 同样，`DesiredPageContainingBlockSize` 也会考虑 CSS 的 `orientation` 属性（`portrait` 或 `landscape`）。
    - **`margin`**: `ResolvePageBoxGeometry` 和 `TargetPageBorderBoxLogicalRect` 函数会处理 CSS 的 `margin` 属性，计算页面的边距。
    - **Page Margin Boxes (@page rules):** `GetPageDescriptionFromLayout` 函数会遍历页面边距框（例如 `@page :left { margin-left: 2cm; }` 定义的），并根据其位置调整打印页面的边距，以避免与浏览器默认的页眉页脚重叠。
    - **Writing Modes:** 函数中使用了 `style.GetWritingMode()` 来处理不同的书写模式（水平或垂直），这会影响尺寸和方向的解释。

* **HTML:**  虽然此 C++ 文件不直接解析 HTML，但它操作的是由 HTML 结构和 CSS 样式渲染出来的布局树。分页是将 HTML 内容分割成逻辑页面的过程，因此它依赖于 HTML 的内容结构。

* **JavaScript:** JavaScript 的 `window.print()` 方法会触发浏览器的打印流程，而 `pagination_utils.cc` 中的代码则参与了如何将当前渲染的 HTML 内容分割成适合打印的页面，并生成打印所需的元数据（如 `WebPrintPageDescription`）。例如，当 JavaScript 调用 `window.print()` 时，Blink 引擎会使用这里的逻辑来确定如何分页和设置页面属性。

**逻辑推理的假设输入与输出：**

假设我们有一个简单的 HTML 文档，并为其应用了一些 CSS 样式：

**假设输入：**

* **HTML:**
  ```html
  <!DOCTYPE html>
  <html>
  <head>
  <style>
  @page {
    size: A4 portrait;
    margin: 1cm;
  }
  p {
    height: 500px; /* 模拟大量内容 */
  }
  </style>
  </head>
  <body>
    <p>This is a long paragraph that will span multiple pages.</p>
    <p>This is another long paragraph.</p>
  </body>
  </html>
  ```
* **CSS 渲染后的样式信息:**  `@page` 规则指定了 A4 纵向的页面尺寸和 1cm 的边距。
* **LayoutView 对象:**  包含了根据 HTML 和 CSS 构建的布局树。

**逻辑推理与输出示例 (部分):**

1. **`DesiredPageContainingBlockSize(document, style)`:**
   - **输入:**  `document` 对象和 `@page` 规则解析出的 `style` 对象（包含 `size: A4 portrait`）。
   - **输出:**  一个 `LogicalSize` 对象，表示 A4 纵向页面的逻辑尺寸（宽度大约 210mm，高度大约 297mm，转换为 Blink 内部的 LayoutUnit）。

2. **`ResolvePageBoxGeometry(temporary_page_node, containing_block_size, &geometry)`:**
   - **输入:**  一个临时的 `BlockNode` 代表页面框，上一步计算出的 `containing_block_size`。
   - **输出:**  `geometry` 对象会被填充，包含页面内容区域的尺寸、边距等信息，例如 `geometry.border_box_size` 会接近 A4 的尺寸减去边距。

3. **多次调用相关函数:**  随着内容超出单个页面，布局引擎会多次调用这些函数来创建和布局后续的页面片段。

4. **`GetPageCount(layout_view)`:**
   - **输入:**  布局完成后的 `LayoutView` 对象。
   - **输出:**  返回页面总数，例如，如果两个段落内容需要占用 3 个 A4 页面，则输出为 `3`。

5. **`GetPageDescriptionFromLayout(document, page_number)`:**
   - **输入:**  `document` 对象和要获取描述的页码（例如 `0` 代表第一页）。
   - **输出:**  一个 `WebPrintPageDescription` 对象，包含了第一页的尺寸（接近 A4）、上下左右边距（1cm 转换为浮点数）、页面尺寸类型（`kFixed` 或其他对应 A4 的类型）、方向（`kPortrait`）。

**用户或编程常见的使用错误：**

1. **CSS 分页属性使用不当:**
   - **错误示例:**  错误地使用了 `@page` 规则，例如 `size: letter landscapeee;` (拼写错误) 或提供了无效的尺寸值。这可能导致 `DesiredPageContainingBlockSize` 无法正确解析页面尺寸，从而使用默认尺寸或产生未定义的行为。
   - **后果:**  打印出来的页面尺寸或方向与预期不符。

2. **内容溢出且未处理:**
   - **错误示例:**  网页内容非常宽或高，超出了页面尺寸，但没有使用 CSS 属性（如 `overflow: auto;` 或使用媒体查询针对打印进行优化）来处理溢出。
   - **后果:**  部分内容可能被裁剪掉，或者 `CalculateOverflowShrinkForPrinting` 会强制缩小内容以适应页面，导致文字过小难以阅读。

3. **对打印样式与屏幕样式考虑不足:**
   - **错误示例:**  只考虑了屏幕显示效果，没有为打印提供专门的 CSS 样式。
   - **后果:**  打印出来的页面布局混乱，颜色、字体等与预期不符，背景图片可能被打印出来导致墨水浪费。

4. **JavaScript 打印方法使用错误:**
   - **错误示例:**  在 JavaScript 中直接使用 `window.print()`，没有充分利用浏览器提供的打印配置选项，例如设置打印方向、选择纸张大小等（虽然这些主要由浏览器 UI 提供，但了解分页机制有助于理解其背后的原理）。

5. **误解分页上下文:**
   - **错误示例:**  在非分页的上下文中（例如屏幕显示）错误地假设或使用了分页相关的概念或 API，这通常不会直接引起 `pagination_utils.cc` 的错误，但会造成逻辑上的混淆。

总而言之，`blink/renderer/core/layout/pagination_utils.cc` 文件是 Blink 渲染引擎中负责将网页内容转化为可打印页面的核心组件之一。它深入理解 CSS 的分页特性，并进行复杂的布局和几何计算，以确保内容能够正确地分割和呈现在目标页面上。理解这个文件的工作原理有助于开发者更好地控制网页的打印效果。

### 提示词
```
这是目录为blink/renderer/core/layout/pagination_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/pagination_utils.h"

#include "printing/mojom/print.mojom-blink.h"
#include "third_party/blink/public/web/web_print_page_description.h"
#include "third_party/blink/public/web/web_print_params.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/layout/block_break_token.h"
#include "third_party/blink/renderer/core/layout/block_node.h"
#include "third_party/blink/renderer/core/layout/constraint_space.h"
#include "third_party/blink/renderer/core/layout/constraint_space_builder.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/fragment_geometry.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/length_utils.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/physical_fragment_link.h"
#include "third_party/blink/renderer/core/style/computed_style.h"

namespace blink {

namespace {

bool ShouldCenterPageOnPaper(const WebPrintParams& params) {
  if (params.print_scaling_option ==
      printing::mojom::blink::PrintScalingOption::kCenterShrinkToFitPaper) {
    return true;
  }
  DCHECK(params.print_scaling_option ==
         printing::mojom::blink::PrintScalingOption::kSourceSize);
  return false;
}

PhysicalSize PageBoxDefaultSize(const Document& document) {
  const WebPrintParams& params = document.GetFrame()->GetPrintParams();
  return PhysicalSize::FromSizeFRound(params.default_page_description.size);
}

LogicalSize PageBoxDefaultSizeWithSourceOrientation(const Document& document,
                                                    const ComputedStyle& style,
                                                    LogicalSize layout_size) {
  DCHECK(ShouldCenterPageOnPaper(document.GetFrame()->GetPrintParams()));
  LogicalSize target_size =
      PageBoxDefaultSize(document).ConvertToLogical(style.GetWritingMode());
  if (layout_size.inline_size != layout_size.block_size &&
      (target_size.inline_size > target_size.block_size) !=
          (layout_size.inline_size > layout_size.block_size)) {
    // Match orientation requested / implied by CSS.
    std::swap(target_size.inline_size, target_size.block_size);
  }
  return target_size;
}

float TargetShrinkScaleFactor(LogicalSize target_size,
                              LogicalSize source_size) {
  if (source_size.IsEmpty()) {
    return 1.0f;
  }
  float inline_scale =
      target_size.inline_size.ToFloat() / source_size.inline_size.ToFloat();
  float block_scale =
      target_size.block_size.ToFloat() / source_size.block_size.ToFloat();
  return std::min(1.0f, std::min(inline_scale, block_scale));
}

wtf_size_t PageNumberFromPageArea(const PhysicalBoxFragment& page_area) {
  DCHECK_EQ(page_area.GetBoxType(), PhysicalFragment::kPageArea);
  if (const BlockBreakToken* break_token = page_area.GetBreakToken()) {
    return break_token->SequenceNumber();
  }
  const LayoutView& view = *page_area.GetDocument().GetLayoutView();
  DCHECK_GE(PageCount(view), 1u);
  return PageCount(view) - 1;
}

}  // anonymous namespace

void SetUpSpaceBuilderForPageBox(LogicalSize available_size,
                                 ConstraintSpaceBuilder* builder) {
  builder->SetAvailableSize(available_size);
  builder->SetPercentageResolutionSize(available_size);
  builder->SetInlineAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  builder->SetBlockAutoBehavior(AutoSizeBehavior::kStretchImplicit);
  builder->SetDecorationPercentageResolutionType(
      DecorationPercentageResolutionType::kContainingBlockSize);
}

LogicalSize DesiredPageContainingBlockSize(const Document& document,
                                           const ComputedStyle& style) {
  PhysicalSize layout_size = PageBoxDefaultSize(document);
  switch (style.GetPageSizeType()) {
    case PageSizeType::kAuto:
      break;
    case PageSizeType::kLandscape:
      if (layout_size.width < layout_size.height) {
        std::swap(layout_size.width, layout_size.height);
      }
      break;
    case PageSizeType::kPortrait:
      if (layout_size.width > layout_size.height) {
        std::swap(layout_size.width, layout_size.height);
      }
      break;
    case PageSizeType::kFixed: {
      auto css_size = PhysicalSize::FromSizeFRound(style.PageSize());
      if (document.GetFrame()->GetPrintParams().ignore_page_size) {
        // Keep the page size, but match orientation.
        if ((css_size.width > css_size.height) !=
            (layout_size.width > layout_size.height)) {
          std::swap(layout_size.width, layout_size.height);
        }
        break;
      }
      layout_size = css_size;
      break;
    }
  }

  return layout_size.ConvertToLogical(style.GetWritingMode());
}

void ResolvePageBoxGeometry(const BlockNode& page_box,
                            LogicalSize page_containing_block_size,
                            FragmentGeometry* geometry,
                            BoxStrut* margins) {
  const ComputedStyle& style = page_box.Style();
  ConstraintSpaceBuilder space_builder(style.GetWritingMode(),
                                       style.GetWritingDirection(),
                                       /* is_new_fc */ true);
  SetUpSpaceBuilderForPageBox(page_containing_block_size, &space_builder);
  ConstraintSpace space = space_builder.ToConstraintSpace();
  *geometry = CalculateInitialFragmentGeometry(space, page_box,
                                               /*BlockBreakToken=*/nullptr);

  if (!margins) {
    return;
  }

  *margins = ComputeMarginsForSelf(space, style);

  // Resolve any auto margins. Note that this may result in negative margins, if
  // the specified width/height is larger than the specified containing block
  // size (the 'size' property). See
  // https://github.com/w3c/csswg-drafts/issues/8508 for discussion around
  // negative page margins in general.
  LayoutUnit additional_inline_space =
      space.AvailableSize().inline_size -
      (geometry->border_box_size.inline_size + margins->InlineSum());
  LayoutUnit additional_block_space =
      space.AvailableSize().block_size -
      (geometry->border_box_size.block_size + margins->BlockSum());
  ResolveAutoMargins(style.MarginInlineStart(), style.MarginInlineEnd(),
                     style.MarginBlockStart(), style.MarginBlockEnd(),
                     additional_inline_space, additional_block_space, margins);
}

PhysicalSize CalculateInitialContainingBlockSizeForPagination(
    Document& document) {
  const LayoutView& layout_view = *document.GetLayoutView();
  const ComputedStyle* page_style;
  // The initial containing block is the size of the first page area.
  if (const PhysicalBoxFragment* first_page =
          GetPageContainer(layout_view, 0)) {
    // We have already laid out. Grab the page style off the first page
    // fragment. It may have been adjusted due to named pages or unusable sizes
    // requested, which means that recomputing style here would not always give
    // the correct results.
    page_style = &first_page->Style();
  } else {
    page_style =
        document.GetStyleResolver().StyleForPage(0, /*page_name=*/g_null_atom);
  }

  // Simply reading out the size of the page container fragment (if it exists at
  // all) won't do, since we don't know if page scaling has been accounted for
  // or not at this point. Note that we may not even have created the first page
  // yet. This function is called before entering layout, so that viewport sizes
  // (to resolve viewport units) are set up before entering layout (and, after
  // layout, the sizes may need to be adjusted, if the initial estimate turned
  // out to be wrong). Create a temporary node and resolve the size.
  auto* page_box = LayoutBlockFlow::CreateAnonymous(&document, page_style);
  BlockNode temporary_page_node(page_box);

  FragmentGeometry geometry;
  LogicalSize containing_block_size =
      DesiredPageContainingBlockSize(document, *page_style);
  ResolvePageBoxGeometry(temporary_page_node, containing_block_size, &geometry);
  LogicalSize logical_size = ShrinkLogicalSize(
      geometry.border_box_size, geometry.border + geometry.padding);

  // Note: Don't get the writing mode directly from the LayoutView, since that
  // one is untrustworthy unless we have entered layout (which we might not have
  // at this point). See StyleResolver::StyleForViewport() and how it's called.
  WritingMode writing_mode = page_style->GetWritingMode();

  // So long, and thanks for all the size.
  page_box->Destroy();

  return ToPhysicalSize(logical_size, writing_mode) *
         layout_view.PaginationScaleFactor();
}

float TargetScaleForPage(const PhysicalBoxFragment& page_container) {
  DCHECK_EQ(page_container.GetBoxType(), PhysicalFragment::kPageContainer);
  const Document& document = page_container.GetDocument();
  const LayoutView& layout_view = *document.GetLayoutView();
  // Print parameters may set a scale factor, and layout may also use a larger
  // viewport size in order to fit more unbreakable content in the inline
  // direction.
  float layout_scale = 1.f / layout_view.PaginationScaleFactor();
  if (!ShouldCenterPageOnPaper(document.GetFrame()->GetPrintParams())) {
    return layout_scale;
  }

  // The source margin box size isn't stored anywhere, so it needs to be
  // recomputed now.
  BlockNode page_node(To<LayoutBox>(page_container.GetMutableLayoutObject()));
  const ComputedStyle& style = page_node.Style();
  FragmentGeometry geometry;
  BoxStrut margins;
  ResolvePageBoxGeometry(page_node,
                         DesiredPageContainingBlockSize(document, style),
                         &geometry, &margins);
  LogicalSize source_size = geometry.border_box_size + margins;
  LogicalSize target_size =
      page_container.Size().ConvertToLogical(style.GetWritingMode());

  return layout_scale * TargetShrinkScaleFactor(target_size, source_size);
}

LogicalSize FittedPageContainerSize(const Document& document,
                                    const ComputedStyle& style,
                                    LogicalSize source_margin_box_size) {
  if (!ShouldCenterPageOnPaper(document.GetFrame()->GetPrintParams())) {
    return source_margin_box_size;
  }

  // The target page size is fixed. This happens when printing to an actual
  // printer, whose page size is obviously confined to the size of the paper
  // sheets in the printer. Only honor orientation.
  return PageBoxDefaultSizeWithSourceOrientation(document, style,
                                                 source_margin_box_size);
}

LogicalRect TargetPageBorderBoxLogicalRect(
    const Document& document,
    const ComputedStyle& style,
    const LogicalSize& source_margin_box_size,
    const BoxStrut& margins) {
  LogicalSize source_border_box_size(
      source_margin_box_size.inline_size - margins.InlineSum(),
      source_margin_box_size.block_size - margins.BlockSum());
  LogicalRect rect(LogicalOffset(margins.inline_start, margins.block_start),
                   source_border_box_size);

  if (!ShouldCenterPageOnPaper(document.GetFrame()->GetPrintParams())) {
    return rect;
  }

  LogicalSize target_size = PageBoxDefaultSizeWithSourceOrientation(
      document, style, source_margin_box_size);

  float scale = TargetShrinkScaleFactor(target_size, source_margin_box_size);

  rect.offset.inline_offset =
      LayoutUnit(rect.offset.inline_offset.ToFloat() * scale +
                 (target_size.inline_size.ToFloat() -
                  source_margin_box_size.inline_size.ToFloat() * scale) /
                     2);
  rect.offset.block_offset =
      LayoutUnit(rect.offset.block_offset.ToFloat() * scale +
                 (target_size.block_size.ToFloat() -
                  source_margin_box_size.block_size.ToFloat() * scale) /
                     2);
  rect.size.inline_size = LayoutUnit(rect.size.inline_size.ToFloat() * scale);
  rect.size.block_size = LayoutUnit(rect.size.block_size.ToFloat() * scale);

  return rect;
}

wtf_size_t PageCount(const LayoutView& view) {
  DCHECK(view.ShouldUsePaginatedLayout());
  const auto& fragments = view.GetPhysicalFragment(0)->Children();
  return ClampTo<wtf_size_t>(fragments.size());
}

const PhysicalBoxFragment* GetPageContainer(const LayoutView& view,
                                            wtf_size_t page_index) {
  if (!view.PhysicalFragmentCount()) {
    return nullptr;
  }
  const auto& pages = view.GetPhysicalFragment(0)->Children();
  if (page_index >= pages.size()) {
    return nullptr;
  }
  const auto* child = To<PhysicalBoxFragment>(pages[page_index].get());
  if (child->GetBoxType() != PhysicalFragment::kPageContainer) {
    // Not paginated, at least not yet.
    return nullptr;
  }
  return child;
}

const PhysicalBoxFragment* GetPageArea(const LayoutView& view,
                                       wtf_size_t page_index) {
  const auto* page_container = GetPageContainer(view, page_index);
  if (!page_container) {
    return nullptr;
  }
  return &GetPageArea(GetPageBorderBox(*page_container));
}

const PhysicalFragmentLink& GetPageBorderBoxLink(
    const PhysicalBoxFragment& page_container) {
  DCHECK_EQ(page_container.GetBoxType(), PhysicalFragment::kPageContainer);
  for (const auto& child : page_container.Children()) {
    if (child->GetBoxType() == PhysicalFragment::kPageBorderBox) {
      return child;
    }
  }
  // A page container will never be laid out without a page border box child.
  NOTREACHED();
}

const PhysicalBoxFragment& GetPageBorderBox(
    const PhysicalBoxFragment& page_container) {
  return *To<PhysicalBoxFragment>(GetPageBorderBoxLink(page_container).get());
}

const PhysicalBoxFragment& GetPageArea(
    const PhysicalBoxFragment& page_border_box) {
  DCHECK_EQ(page_border_box.GetBoxType(), PhysicalFragment::kPageBorderBox);
  DCHECK_EQ(page_border_box.Children().size(), 1u);
  const auto& page_area =
      *DynamicTo<PhysicalBoxFragment>(page_border_box.Children()[0].get());
  DCHECK_EQ(page_area.GetBoxType(), PhysicalFragment::kPageArea);
  return page_area;
}

PhysicalRect StitchedPageContentRect(const LayoutView& layout_view,
                                     wtf_size_t page_index) {
  return StitchedPageContentRect(*GetPageContainer(layout_view, page_index));
}

PhysicalRect StitchedPageContentRect(
    const PhysicalBoxFragment& page_container) {
  DCHECK_EQ(page_container.GetBoxType(), PhysicalFragment::kPageContainer);
  const PhysicalBoxFragment& page_border_box = GetPageBorderBox(page_container);
  const PhysicalBoxFragment& page_area = GetPageArea(page_border_box);
  PhysicalRect physical_page_rect = page_area.LocalRect();

  if (const BlockBreakToken* previous_break_token =
          FindPreviousBreakTokenForPageArea(page_area)) {
    LayoutUnit consumed_block_size = previous_break_token->ConsumedBlockSize();
    PhysicalDirection block_end =
        page_container.Style().GetWritingDirection().BlockEnd();
    if (block_end == PhysicalDirection::kLeft) {
      const LayoutView& view = *page_container.GetDocument().GetLayoutView();
      const PhysicalBoxFragment& first_page_area = *GetPageArea(view, 0);
      physical_page_rect.offset.left += first_page_area.Size().width;
      physical_page_rect.offset.left -=
          consumed_block_size + page_area.Size().width;
    } else if (block_end == PhysicalDirection::kRight) {
      physical_page_rect.offset.left += consumed_block_size;
    } else {
      CHECK_EQ(block_end, PhysicalDirection::kDown);
      physical_page_rect.offset.top += consumed_block_size;
    }
  }

  return physical_page_rect;
}

const BlockBreakToken* FindPreviousBreakTokenForPageArea(
    const PhysicalBoxFragment& page_area) {
  DCHECK_EQ(page_area.GetBoxType(), PhysicalFragment::kPageArea);
  wtf_size_t page_number = PageNumberFromPageArea(page_area);
  if (page_number == 0) {
    return nullptr;
  }
  const LayoutView& view = *page_area.GetDocument().GetLayoutView();
  return GetPageArea(view, page_number - 1)->GetBreakToken();
}

float CalculateOverflowShrinkForPrinting(const LayoutView& view,
                                         float maximum_shrink_factor) {
  float overall_scale_factor = 1.0;
  for (const PhysicalFragmentLink& link :
       view.GetPhysicalFragment(0)->Children()) {
    const auto& page_container = To<PhysicalBoxFragment>(*link);
    for (const PhysicalFragmentLink& child : page_container.Children()) {
      if (child->GetBoxType() == PhysicalFragment::kPageBorderBox) {
        const auto& page = *To<PhysicalBoxFragment>(child->Children()[0].get());
        // Check the inline axis overflow on each individual page, to find the
        // largest relative overflow.
        float page_scale_factor;
        if (view.StyleRef().IsHorizontalWritingMode()) {
          page_scale_factor = page.ScrollableOverflow().Right().ToFloat() /
                              page.Size().width.ToFloat();
        } else {
          page_scale_factor = page.ScrollableOverflow().Bottom().ToFloat() /
                              page.Size().height.ToFloat();
        }
        overall_scale_factor =
            std::max(overall_scale_factor, page_scale_factor);
        break;
      }
    }

    if (overall_scale_factor >= maximum_shrink_factor) {
      return maximum_shrink_factor;
    }
  }

  return overall_scale_factor;
}

WebPrintPageDescription GetPageDescriptionFromLayout(const Document& document,
                                                     wtf_size_t page_number) {
  const PhysicalBoxFragment& page_container =
      *GetPageContainer(*document.GetLayoutView(), page_number);
  const ComputedStyle& style = page_container.Style();
  const PhysicalFragmentLink& border_box = GetPageBorderBoxLink(page_container);
  float scale = TargetScaleForPage(page_container);
  PhysicalRect page_border_box_rect(border_box.offset,
                                    border_box->Size() * scale);

  PhysicalBoxStrut insets(page_container.Size(), page_border_box_rect);

  // Go through all page margin boxes, and see which page edges they intersect
  // with. Set margins to zero for those edges, to suppress browser-generated
  // headers and footers, so that they don't overlap with the page margin boxes.
  PhysicalRect top_edge_rect(LayoutUnit(), LayoutUnit(),
                             page_container.Size().width, insets.top);
  PhysicalRect right_edge_rect(insets.left + page_border_box_rect.Width(),
                               LayoutUnit(), insets.right,
                               page_container.Size().height);
  PhysicalRect bottom_edge_rect(LayoutUnit(),
                                insets.top + page_border_box_rect.Height(),
                                page_container.Size().width, insets.bottom);
  PhysicalRect left_edge_rect(LayoutUnit(), LayoutUnit(), insets.left,
                              page_container.Size().height);
  for (const PhysicalFragmentLink& child_link : page_container.Children()) {
    if (child_link->GetBoxType() != PhysicalFragment::kPageMargin) {
      continue;
    }
    PhysicalRect box_rect(child_link.offset, child_link->Size());
    if (box_rect.Intersects(top_edge_rect)) {
      insets.top = LayoutUnit();
    }
    if (box_rect.Intersects(right_edge_rect)) {
      insets.right = LayoutUnit();
    }
    if (box_rect.Intersects(bottom_edge_rect)) {
      insets.bottom = LayoutUnit();
    }
    if (box_rect.Intersects(left_edge_rect)) {
      insets.left = LayoutUnit();
    }
  }

  WebPrintPageDescription description(gfx::SizeF(page_container.Size()));
  description.margin_top = insets.top.ToFloat();
  description.margin_right = insets.right.ToFloat();
  description.margin_bottom = insets.bottom.ToFloat();
  description.margin_left = insets.left.ToFloat();

  description.page_size_type = style.GetPageSizeType();
  description.orientation = style.GetPageOrientation();

  return description;
}

}  // namespace blink
```