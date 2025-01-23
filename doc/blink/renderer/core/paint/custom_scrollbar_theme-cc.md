Response:
Let's break down the thought process for analyzing the `custom_scrollbar_theme.cc` file.

**1. Understanding the Core Purpose:**

The filename itself, `custom_scrollbar_theme.cc`, is a huge clue. The term "theme" in UI development usually refers to the visual appearance and behavior of elements. "Custom scrollbar" indicates that this code is about handling scrollbars that aren't the default operating system ones. The `.cc` extension means it's C++ code, implying low-level control and interaction with the rendering engine.

**2. Initial Code Scan and Keyword Identification:**

Quickly scan the code, looking for important keywords and structures:

* **`namespace blink`:** This confirms it's part of the Blink rendering engine.
* **`CustomScrollbarTheme` class:** This is the central entity. Look for methods within it.
* **`GetCustomScrollbarTheme()`:**  This looks like a singleton pattern, ensuring only one instance of the theme exists.
* **Methods like `HitTest`, `ButtonRect`, `TrackRect`, `Paint...`:** These suggest the class is responsible for determining how scrollbars interact with the mouse and how they are visually rendered.
* **`ScrollbarPart` enum:** This indicates different parts of a scrollbar are being handled individually.
* **`GraphicsContext`:**  This is a crucial class for drawing operations in Blink.
* **`LayoutCustomScrollbarPart`:**  This links the visual representation to the layout engine.
* **`third_party/blink/renderer/core/...` includes:** These headers point to dependencies within the Blink engine, like layout objects, paint information, and the base `Scrollbar` class.

**3. Deconstructing Functionality by Method:**

Go through each method in `CustomScrollbarTheme` and infer its purpose:

* **`GetCustomScrollbarTheme()`:**  Singleton pattern, as noted.
* **`HitTest()`:** Determines which part of the scrollbar was clicked. The logic for "double buttons" is interesting and specific to the custom theme.
* **`ButtonSizesAlongTrackAxis()`:**  Calculates the space occupied by buttons.
* **`HasButtons()`:**  Checks if there's enough space to display buttons.
* **`HasThumb()`:**  Checks if a draggable thumb should be displayed.
* **`MinimumThumbLength()`:**  Gets the minimum size of the thumb.
* **`ButtonRect()`, `BackButtonRect()`, `ForwardButtonRect()`:**  Calculate the bounding boxes of the buttons.
* **`TrackRect()`:**  Calculates the rectangle of the scrollbar track, taking buttons into account.
* **`ConstrainTrackRectToTrackPieces()`:**  Ensures the track rectangle fits within the visual track pieces.
* **`PaintScrollCorner()`:**  Draws the corner where horizontal and vertical scrollbars meet. The "FIXME: Implement" comment is a key observation.
* **`PaintTrackBackgroundAndButtons()`:**  Draws the background, buttons, and possibly parts of the track.
* **`PaintButton()`, `PaintThumb()`:**  Draw the individual button and thumb elements.
* **`PaintTickmarks()`:**  Delegates to the base theme for drawing tick marks (not directly handled here).
* **`PaintIntoRect()`:**  The entry point for painting a custom scrollbar part, linking to layout.
* **`PaintPart()`:**  Helper function to paint a specific scrollbar part by finding its layout object.

**4. Identifying Relationships with Web Technologies:**

Now connect the C++ code to web technologies:

* **CSS:**  The most obvious link is CSS. Properties like `-webkit-scrollbar-*` directly influence the behavior and appearance handled by this code. Think about what CSS properties would affect the presence, size, and styling of buttons, thumbs, and tracks.
* **HTML:**  Scrollbars appear on scrollable elements. When an HTML element's content overflows, the browser might use this `CustomScrollbarTheme` to draw the scrollbars.
* **JavaScript:**  JavaScript can indirectly trigger scrollbar rendering by manipulating the DOM, causing content overflow, or by using APIs that directly interact with scrolling.

**5. Constructing Examples and Scenarios:**

Think of concrete examples for each relationship:

* **CSS:** Provide CSS snippets demonstrating customization of scrollbar parts.
* **HTML:** Show a simple HTML structure that would lead to scrollbars being displayed.
* **JavaScript:** Give an example of JavaScript code that programmatically scrolls an element.

**6. Considering User Errors and Debugging:**

* **User Errors:** Focus on incorrect CSS usage as this is the most common way users interact with scrollbar styling.
* **Debugging:** Trace how user actions (like clicking and dragging) lead to the execution of methods in this class. Highlight the role of developer tools.

**7. Logical Inference and Assumptions:**

Where the code is less explicit, make reasonable assumptions based on context:

* Assume that the "double buttons" logic is for a specific visual style.
* Assume the `Paint...` methods interact with the underlying graphics rendering pipeline.

**8. Structuring the Answer:**

Organize the information logically:

* Start with a high-level summary of the file's purpose.
* Detail the functionality of each method.
* Explain the relationships with JavaScript, HTML, and CSS with examples.
* Provide scenarios for logical inference.
* Illustrate common user errors.
* Describe the debugging process.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file directly handles all the visual styling.
* **Correction:** Realize that it *manages* the drawing process but likely relies on other components for the actual visual assets (like images or vector graphics). The `PaintPart` method and the connection to `LayoutCustomScrollbarPart` are key here.
* **Initial thought:** Focus solely on the technical implementation.
* **Refinement:** Emphasize the user-facing aspects and how developers use CSS to interact with this code.

By following these steps, including careful reading of the code and making logical connections, we arrive at a comprehensive understanding of the `custom_scrollbar_theme.cc` file and its role in the Blink rendering engine.
这个文件 `blink/renderer/core/paint/custom_scrollbar_theme.cc` 是 Chromium Blink 引擎中负责**自定义滚动条主题**的核心代码。它定义了 `CustomScrollbarTheme` 类，该类继承自 `ScrollbarTheme`，并提供了绘制和处理自定义滚动条外观和行为的具体实现。

以下是它的主要功能：

**1. 提供自定义滚动条的绘制逻辑:**

   - **`PaintScrollCorner()`:** 绘制滚动条角落的空白区域。
   - **`PaintTrackBackgroundAndButtons()`:** 绘制滚动条的背景和按钮（向上/向下，向左/向右）。
   - **`PaintButton()`:** 绘制滚动条的单个按钮。
   - **`PaintThumb()`:** 绘制滚动条的滑块（thumb）。
   - **`PaintTickmarks()`:** 绘制滚动条上的刻度线（通常用于 `<input type="range">`）。
   - **`PaintIntoRect()` 和 `PaintPart()`:**  这些方法是更通用的绘制入口，用于绘制滚动条的各个组成部分，它们会根据 `LayoutCustomScrollbarPart` 对象的信息进行绘制。

**2. 处理滚动条的交互逻辑和尺寸计算:**

   - **`HitTest()`:**  确定鼠标点击的位置落在滚动条的哪个部分（例如，向上按钮、滑块、轨道）。  它扩展了默认的 `ScrollbarTheme::HitTest`，考虑了自定义的双按钮布局。
   - **`ButtonSizesAlongTrackAxis()`:** 计算滚动条轨道轴向上按钮占据的总尺寸。
   - **`HasButtons()`:** 判断滚动条是否应该显示按钮（基于空间是否足够）。
   - **`HasThumb()`:** 判断滚动条是否应该显示滑块。
   - **`MinimumThumbLength()`:** 获取自定义滚动条滑块的最小长度。
   - **`ButtonRect()`，`BackButtonRect()`，`ForwardButtonRect()`:**  计算滚动条各个按钮的矩形区域。
   - **`TrackRect()`:** 计算滚动条轨道的矩形区域，会考虑按钮的存在。
   - **`ConstrainTrackRectToTrackPieces()`:**  将给定的矩形约束到滚动条轨道的实际可用区域内。

**3. 单例模式:**

   - **`GetCustomScrollbarTheme()`:** 使用单例模式确保只有一个 `CustomScrollbarTheme` 实例存在，这对于管理全局的自定义滚动条样式非常重要。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件直接处理的是渲染层的逻辑，它响应由 HTML 和 CSS 定义的样式，并为 JavaScript 提供的滚动操作提供视觉反馈。

**CSS 关系：**

- **自定义滚动条样式属性：** CSS 提供了以 `-webkit-scrollbar-*` 开头的属性，允许开发者自定义滚动条的各个部分，例如：
    ```css
    ::-webkit-scrollbar {
      width: 10px;
      height: 10px;
    }

    ::-webkit-scrollbar-thumb {
      background-color: rgba(0, 0, 0, 0.5);
      border-radius: 5px;
    }

    ::-webkit-scrollbar-track {
      background-color: #f1f1f1;
    }

    ::-webkit-scrollbar-button {
      background-color: #ccc;
    }

    ::-webkit-scrollbar-corner {
      background-color: white;
    }
    ```
    `CustomScrollbarTheme` 的代码会读取和解释这些 CSS 属性，并根据这些属性来绘制滚动条的不同部分。例如，`PaintThumb()` 方法的实现会参考 `::-webkit-scrollbar-thumb` 相关的 CSS 属性来确定滑块的颜色、形状等。

- **逻辑推理：**
    - **假设输入 CSS:**
      ```css
      ::-webkit-scrollbar-thumb { background-color: blue; }
      ```
    - **预期输出 (影响 `PaintThumb()`):** 当绘制滑块时，`PaintThumb()` 方法会使用蓝色作为滑块的填充颜色。

**HTML 关系：**

- **可滚动元素：** 当 HTML 元素的内容超出其容器大小时，浏览器会显示滚动条。`CustomScrollbarTheme` 负责渲染这些滚动条。
    ```html
    <div style="width: 100px; height: 100px; overflow: auto;">
      <p style="width: 200px; height: 200px;">内容超出容器</p>
    </div>
    ```
    在这个例子中，`overflow: auto;` 会在内容溢出时触发滚动条的显示，`CustomScrollbarTheme` 将负责绘制这个滚动条。

**JavaScript 关系：**

- **滚动操作：** JavaScript 可以通过修改元素的 `scrollTop` 或 `scrollLeft` 属性来滚动内容。当发生滚动时，`CustomScrollbarTheme` 绘制的滚动条滑块会相应地移动，以反映当前的滚动位置。
    ```javascript
    const div = document.querySelector('div');
    div.scrollTop = 50; // JavaScript 触发滚动
    ```
    当 `scrollTop` 被修改时，滚动条需要重新绘制，`CustomScrollbarTheme` 会参与到这个重绘过程中，更新滑块的位置。

- **事件监听：** JavaScript 可以监听滚动事件 (`scroll`)。当用户与滚动条交互（例如拖动滑块）时，`CustomScrollbarTheme` 会处理这些交互，并最终导致 `scroll` 事件的触发。

**逻辑推理 (更深入的例子):**

- **假设输入 (用户操作):** 用户将鼠标悬停在滚动条的向上按钮上。
- **预期输出 (影响 `HitTest()` 和 `PaintButton()`):**
    1. 当鼠标移动时，`HitTest()` 方法会被调用，以确定鼠标是否悬停在 `kBackButtonStartPart` (向上按钮) 上。
    2. 如果是，相关的状态可能会被更新，例如按钮的高亮状态。
    3. 随后，`PaintButton()` 方法会被调用，并根据按钮的当前状态（例如，高亮）来绘制按钮，可能会显示不同的背景色或边框。

**用户或编程常见的使用错误及举例说明:**

1. **错误的 CSS 语法:** 使用了错误的 `-webkit-scrollbar-*` 属性名或值，导致样式没有生效。
   ```css
   /* 错误的属性名 */
   ::-webkit-scrollbar-thum { /* 应该为 -thumb */
     background-color: red;
   }
   ```

2. **过度复杂的 CSS 导致性能问题:**  自定义滚动条的每个部分都可能涉及复杂的绘制逻辑，过度使用复杂的样式（例如，大量的阴影、渐变）可能会导致滚动性能下降。

3. **与浏览器兼容性问题:** `-webkit-scrollbar-*` 属性是 WebKit 浏览器的特定扩展，在其他浏览器中可能不被支持或效果不同。开发者需要注意跨浏览器兼容性。

4. **误解滚动条部分的层叠关系:**  开发者可能不清楚滚动条各个部分的层叠顺序，导致样式覆盖问题。例如，想要设置轨道背景色，但被滑块的样式覆盖了。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问一个包含可滚动内容的网页。** 例如，一个 `div` 元素设置了 `overflow: auto` 并且内容超出其大小。

2. **浏览器渲染页面时，发现需要显示滚动条。** Blink 引擎会根据元素的样式和内容布局来决定是否以及如何显示滚动条。

3. **Blink 引擎决定使用自定义滚动条主题。**  这通常是默认行为，或者可以通过特定的配置选项来指定。

4. **当滚动条需要被绘制时 (例如，页面初次加载、滚动事件发生、样式更新)，以下方法可能会被调用：**
   - **`PaintScrollCorner()`** (如果需要绘制角落)。
   - **`PaintTrackBackgroundAndButtons()`**。
   -  在 `PaintTrackBackgroundAndButtons()` 内部，会调用 **`PaintButton()`** (绘制按钮) 和 **`PaintThumb()`** (绘制滑块)。
   - **`PaintPart()`** 作为更通用的绘制入口会被调用，并最终调用 **`PaintIntoRect()`** 来进行实际的绘制。

5. **当用户与滚动条交互时 (例如，点击按钮，拖动滑块)：**
   - **`HitTest()`** 会被调用，以确定用户点击了滚动条的哪个部分。
   - 如果点击了按钮，相关的滚动逻辑会被触发，并可能导致 `PaintTrackBackgroundAndButtons()` 等方法被再次调用以更新滚动条的显示。
   - 如果拖动滑块，滚动位置会更新，`PaintThumb()` 会被调用以重新绘制滑块到新的位置。

**作为调试线索：**

- 如果滚动条没有按预期显示，可以通过 Chromium 的开发者工具中的 "Rendering" 标签来查看绘制事件，确认相关的 `Paint*` 方法是否被调用，以及调用的参数是否正确。
- 可以通过断点调试 `custom_scrollbar_theme.cc` 中的方法，例如在 `PaintThumb()` 中设置断点，查看在绘制滑块时的具体参数和状态，以定位样式或逻辑问题。
- 检查相关的 `LayoutCustomScrollbarPart` 对象，确认其属性是否正确，因为 `PaintIntoRect()` 依赖于这些信息进行绘制。
- 如果怀疑是 CSS 样式问题，可以逐步注释掉 CSS 样式，观察滚动条的变化，找出导致问题的 CSS 规则。

总而言之，`custom_scrollbar_theme.cc` 文件是 Blink 引擎中实现自定义滚动条外观和行为的关键部分，它与 CSS 样式紧密相关，并为用户的滚动操作提供视觉反馈。理解这个文件的功能有助于深入了解浏览器如何渲染和处理滚动条。

### 提示词
```
这是目录为blink/renderer/core/paint/custom_scrollbar_theme.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/paint/custom_scrollbar_theme.h"

#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/paint/object_painter.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_info.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

CustomScrollbarTheme* CustomScrollbarTheme::GetCustomScrollbarTheme() {
  DEFINE_STATIC_LOCAL(CustomScrollbarTheme, theme, ());
  return &theme;
}

ScrollbarPart CustomScrollbarTheme::HitTest(
    const Scrollbar& scrollbar,
    const gfx::Point& test_position) const {
  auto result = ScrollbarTheme::HitTest(scrollbar, test_position);
  if (result == kScrollbarBGPart) {
    // The ScrollbarTheme knows nothing about the double buttons.
    if (ButtonRect(scrollbar, kBackButtonEndPart).Contains(test_position))
      return kBackButtonEndPart;
    if (ButtonRect(scrollbar, kForwardButtonStartPart).Contains(test_position))
      return kForwardButtonStartPart;
  }
  return result;
}

void CustomScrollbarTheme::ButtonSizesAlongTrackAxis(const Scrollbar& scrollbar,
                                                     int& before_size,
                                                     int& after_size) const {
  gfx::Rect first_button = ButtonRect(scrollbar, kBackButtonStartPart);
  gfx::Rect second_button = ButtonRect(scrollbar, kForwardButtonStartPart);
  gfx::Rect third_button = ButtonRect(scrollbar, kBackButtonEndPart);
  gfx::Rect fourth_button = ButtonRect(scrollbar, kForwardButtonEndPart);
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    before_size = first_button.width() + second_button.width();
    after_size = third_button.width() + fourth_button.width();
  } else {
    before_size = first_button.height() + second_button.height();
    after_size = third_button.height() + fourth_button.height();
  }
}

bool CustomScrollbarTheme::HasButtons(const Scrollbar& scrollbar) const {
  int start_size;
  int end_size;
  ButtonSizesAlongTrackAxis(scrollbar, start_size, end_size);
  return (start_size + end_size) <=
         (scrollbar.Orientation() == kHorizontalScrollbar ? scrollbar.Width()
                                                          : scrollbar.Height());
}

bool CustomScrollbarTheme::HasThumb(const Scrollbar& scrollbar) const {
  return TrackLength(scrollbar) - ThumbLength(scrollbar) >= 0;
}

int CustomScrollbarTheme::MinimumThumbLength(const Scrollbar& scrollbar) const {
  return To<CustomScrollbar>(scrollbar).MinimumThumbLength();
}

gfx::Rect CustomScrollbarTheme::ButtonRect(const Scrollbar& scrollbar,
                                           ScrollbarPart part_type) const {
  return To<CustomScrollbar>(scrollbar).ButtonRect(part_type);
}

gfx::Rect CustomScrollbarTheme::BackButtonRect(
    const Scrollbar& scrollbar) const {
  return ButtonRect(scrollbar, kBackButtonStartPart);
}

gfx::Rect CustomScrollbarTheme::ForwardButtonRect(
    const Scrollbar& scrollbar) const {
  return ButtonRect(scrollbar, kForwardButtonEndPart);
}

gfx::Rect CustomScrollbarTheme::TrackRect(const Scrollbar& scrollbar) const {
  if (!HasButtons(scrollbar))
    return scrollbar.FrameRect();

  int start_length;
  int end_length;
  ButtonSizesAlongTrackAxis(scrollbar, start_length, end_length);

  return To<CustomScrollbar>(scrollbar).TrackRect(start_length, end_length);
}

gfx::Rect CustomScrollbarTheme::ConstrainTrackRectToTrackPieces(
    const Scrollbar& scrollbar,
    const gfx::Rect& rect) const {
  gfx::Rect back_rect =
      To<CustomScrollbar>(scrollbar).TrackPieceRectWithMargins(kBackTrackPart,
                                                               rect);
  gfx::Rect forward_rect =
      To<CustomScrollbar>(scrollbar).TrackPieceRectWithMargins(
          kForwardTrackPart, rect);
  gfx::Rect result = rect;
  if (scrollbar.Orientation() == kHorizontalScrollbar) {
    result.set_x(back_rect.x());
    result.set_width(forward_rect.right() - back_rect.x());
  } else {
    result.set_y(back_rect.y());
    result.set_height(forward_rect.bottom() - back_rect.y());
  }
  return result;
}

void CustomScrollbarTheme::PaintScrollCorner(
    GraphicsContext& context,
    const ScrollableArea&,
    const DisplayItemClient& display_item_client,
    const gfx::Rect& corner_rect) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, display_item_client,
                                                  DisplayItem::kScrollCorner))
    return;

  DrawingRecorder recorder(context, display_item_client,
                           DisplayItem::kScrollCorner, corner_rect);
  // FIXME: Implement.
  context.FillRect(corner_rect, Color::kWhite, AutoDarkMode::Disabled());
}

void CustomScrollbarTheme::PaintTrackBackgroundAndButtons(
    GraphicsContext& context,
    const Scrollbar& scrollbar,
    const gfx::Rect& rect) {
  PaintPart(context, scrollbar, rect, kScrollbarBGPart);

  if (HasButtons(scrollbar)) {
    PaintButton(context, scrollbar, ButtonRect(scrollbar, kBackButtonStartPart),
                kBackButtonStartPart);
    PaintButton(context, scrollbar, ButtonRect(scrollbar, kBackButtonEndPart),
                kBackButtonEndPart);
    PaintButton(context, scrollbar,
                ButtonRect(scrollbar, kForwardButtonStartPart),
                kForwardButtonStartPart);
    PaintButton(context, scrollbar,
                ButtonRect(scrollbar, kForwardButtonEndPart),
                kForwardButtonEndPart);
  }

  gfx::Rect track_rect = TrackRect(scrollbar);
  PaintPart(context, scrollbar, track_rect, kTrackBGPart);

  if (HasThumb(scrollbar)) {
    gfx::Rect start_track_rect;
    gfx::Rect thumb_rect;
    gfx::Rect end_track_rect;
    SplitTrack(scrollbar, track_rect, start_track_rect, thumb_rect,
               end_track_rect);
    PaintPart(context, scrollbar, start_track_rect, kBackTrackPart);
    PaintPart(context, scrollbar, end_track_rect, kForwardTrackPart);
  }
}

void CustomScrollbarTheme::PaintButton(GraphicsContext& context,
                                       const Scrollbar& scrollbar,
                                       const gfx::Rect& rect,
                                       ScrollbarPart part) {
  PaintPart(context, scrollbar, rect, part);
}

void CustomScrollbarTheme::PaintThumb(GraphicsContext& context,
                                      const Scrollbar& scrollbar,
                                      const gfx::Rect& rect) {
  PaintPart(context, scrollbar, rect, kThumbPart);
}

void CustomScrollbarTheme::PaintTickmarks(GraphicsContext& context,
                                          const Scrollbar& scrollbar,
                                          const gfx::Rect& rect) {
  GetTheme().PaintTickmarks(context, scrollbar, rect);
}

void CustomScrollbarTheme::PaintIntoRect(
    const LayoutCustomScrollbarPart& layout_custom_scrollbar_part,
    GraphicsContext& graphics_context,
    const PhysicalRect& rect) {
  PaintInfo paint_info(
      graphics_context, CullRect(ToPixelSnappedRect(rect)),
      PaintPhase::kForeground,
      layout_custom_scrollbar_part.ChildPaintBlockedByDisplayLock());
  ObjectPainter(layout_custom_scrollbar_part)
      .PaintAllPhasesAtomically(paint_info);
}

void CustomScrollbarTheme::PaintPart(GraphicsContext& context,
                                     const Scrollbar& scrollbar,
                                     const gfx::Rect& rect,
                                     ScrollbarPart part) {
  const auto& custom_scrollbar = To<CustomScrollbar>(scrollbar);
  const auto* part_layout_object = custom_scrollbar.GetPart(part);
  if (!part_layout_object)
    return;
  PaintIntoRect(*part_layout_object, context, PhysicalRect(rect));
}

}  // namespace blink
```