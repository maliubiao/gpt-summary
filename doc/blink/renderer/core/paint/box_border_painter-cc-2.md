Response:
My thinking process for analyzing the provided code snippet and generating the answer involved these steps:

1. **Understand the Goal:** The primary goal is to analyze a specific C++ source file (`box_border_painter.cc`) within the Chromium Blink rendering engine and explain its functionality, relationships to web technologies, potential errors, debugging, and summarize its overall purpose.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code, looking for recurring keywords and patterns. Keywords like `BoxSide`, `inner_`, `outer_`, `edge_quad`, `inner_points`, `outer_points`, `FindIntersection`, `ClipPolygon`, `DrawLineForBoxSide`, `GetRadii`, `IsZero`, `BorderStyle`, and function names like `Paint` and `DrawBoxSide` stood out. These provided initial clues about the code's domain and operations.

3. **Focus on the `Paint` Function:** The code snippet is primarily within the `Paint` function. This immediately signals that the core responsibility of this code is *drawing* or *painting* something. The context clues (box, border) suggest it's related to rendering the borders of HTML elements.

4. **Dissect the `Paint` Function Logic (Iterative Approach):** I started breaking down the `Paint` function step-by-step:
    * **Input Parameters:**  I noted the inputs: `context_` (likely a graphics rendering context), `box_rect` (the rectangle of the element), `border_data` (containing border styles, widths, colors), and `box_sides` (indicating which sides to paint).
    * **Early Exits:**  The initial checks for empty `box_sides` and non-renderable inner box suggest optimization and handling of edge cases.
    * **Corner Handling:** The code explicitly deals with corners, indicating that corner rendering is a specific concern. The `PaintCorner` function call confirms this.
    * **Side Iteration:** The loop iterating through `BoxSide` enum values suggests the code handles each border side independently.
    * **Point Calculation:**  The calculation of `outer_points` and `inner_points` is crucial for defining the border's geometry. These points likely represent the corners of the outer and inner bounds of the border.
    * **`switch` Statement for `BoxSide`:**  This is a key part. It indicates that the rendering logic differs based on which side (top, right, bottom, left) is being processed.
    * **Quadrilateral (`edge_quad`) Definition:**  For each side, a quadrilateral (`edge_quad`) is defined. This represents the basic shape of the border segment.
    * **Rounded Corner Handling (Radii):** The `inner_.GetRadii()` and `IsZero()` checks clearly indicate how rounded corners are handled. The `FindIntersection` function is likely used to calculate the intersection points for the rounded edges.
    * **Miter Handling:**  The `first_miter` and `second_miter` variables and the subsequent `if` conditions are responsible for handling how adjacent borders meet at corners (mitered, beveled, etc.). The `ClipPolygon` function is used to clip the border area based on the miter style.
    * **`DrawBoxSide` function:** This function is responsible for the actual drawing of a straight border segment.

5. **Infer Relationships to Web Technologies:** Based on the code's operations (drawing borders, handling rounded corners, different border styles), I connected it to:
    * **CSS:** Border properties (`border-width`, `border-style`, `border-color`, `border-radius`).
    * **HTML:** The visual representation of HTML elements is directly affected by how their borders are rendered.
    * **JavaScript:** While this specific code is C++, JavaScript can indirectly trigger this code by manipulating the CSS styles of elements.

6. **Consider Potential Errors and User Actions:**  I thought about common mistakes users or developers might make that could lead to this code being executed in interesting or problematic ways:
    * **Zero or Negative Border Width:**  This might lead to no border being drawn.
    * **Conflicting Border Styles:**  While CSS resolves conflicts, understanding how different styles interact in the rendering engine is important.
    * **Large Border Radii:** Extremely large radii could cause unexpected intersections or rendering artifacts.
    * **Debugging Scenarios:** I considered how a developer might step through this code while investigating border rendering issues.

7. **Hypothesize Inputs and Outputs (Conceptual):** While not strictly numerical input/output, I considered:
    * **Input:** CSS border properties, element dimensions.
    * **Output:** The visual representation of the border on the screen (pixels being painted).

8. **Synthesize the Summary:** Finally, I condensed my understanding into a concise summary of the `box_border_painter.cc` file's purpose.

**Self-Correction/Refinement during the process:**

* **Initial Overwhelm:**  The code can seem complex at first glance. Breaking it down into smaller, logical blocks (handling each side, then corners, then miters) made it more manageable.
* **Function Name Meaning:** I paid close attention to function names like `FindIntersection` and `ClipPolygon`, as they provide strong hints about the underlying algorithms.
* **DCHECK Statements:** The `DCHECK` statements are assertions, indicating assumptions the developers made about the state of the program at certain points. These can be helpful in understanding the expected behavior.
* **Contextual Clues:** The file path (`blink/renderer/core/paint`) strongly suggests that this code is part of the rendering process.

By following this iterative and analytical approach, I was able to understand the core functionality of the provided code snippet and relate it to web technologies and potential usage scenarios.
这是第3部分，对 `blink/renderer/core/paint/box_border_painter.cc` 文件的功能进行归纳总结：

**blink/renderer/core/paint/box_border_painter.cc 的核心功能是负责绘制HTML元素的边框。**

更具体地说，它做了以下事情：

* **接收边框信息：** 从Blink渲染引擎的其他部分接收关于元素边框的各种属性，例如边框的宽度、样式（实线、虚线等）、颜色、圆角半径等。
* **计算边框的几何形状：** 根据元素的尺寸、边框宽度和圆角半径，计算出边框各个部分的精确坐标和形状，包括直线边缘和圆角。
* **处理不同的边框样式：**  针对不同的 `border-style` CSS属性（如 `solid`, `dashed`, `dotted`, `double` 等），采取不同的绘制策略。
* **处理圆角：**  根据 `border-radius` CSS属性，计算并绘制圆滑的边框角。代码片段中大量 `FindIntersection` 的调用就是为了计算圆角弧线与直线边缘的交点。
* **处理边框交汇处的连接方式：**  根据 `border-miter-limit` 和边框样式，处理相邻边框的连接方式，例如斜接（miter）、斜角（bevel）、圆角（round）。 代码片段中的 `first_miter` 和 `second_miter` 变量以及相关的 `ClipPolygon` 调用就负责处理这些情况。
* **考虑抗锯齿：**  `ClipPolygon` 函数的第二个参数与抗锯齿有关，表明在绘制过程中会考虑提高边框的视觉质量。
* **与图形上下文交互：**  使用 `GraphicsContext` 对象将计算出的边框形状实际绘制到屏幕上。 `context_` 变量就是指向这个图形上下文的指针。
* **处理双边框：** `DoubleStripeOutsets` 函数表明支持绘制双线边框。
* **处理深色模式：** `AutoDarkMode` 参数表明该代码也考虑了在深色模式下的边框渲染。
* **优化绘制：**  代码中存在一些优化的逻辑，例如判断边框是否可渲染，以及对不同边框连接方式的分别处理。

**与 Javascript, HTML, CSS 的关系：**

* **CSS：**  `box_border_painter.cc` 的核心功能就是实现 CSS 中与边框相关的属性，例如 `border-width`, `border-style`, `border-color`, `border-radius`, `border-top`, `border-right` 等等。  CSS 样式定义了边框的外观，而这个文件负责将其转化为屏幕上的像素。
* **HTML：** HTML 元素是应用 CSS 样式的载体。 `box_border_painter.cc` 绘制的是 HTML 元素的边框。
* **Javascript：** Javascript 可以动态地修改 HTML 元素的 CSS 样式，包括边框属性。当 Javascript 修改了边框样式后，会触发 Blink 渲染引擎重新布局和绘制，最终会调用到 `box_border_painter.cc` 来绘制更新后的边框。

**逻辑推理的假设输入与输出：**

假设输入：

* `box_rect`: 一个表示元素矩形区域的 `gfx::Rect` 对象，例如 `{0, 0, 100, 50}` (x=0, y=0, width=100, height=50)。
* `border_data`: 包含边框样式信息的对象，例如：
    * 上边框：宽度 2px，样式 `solid`，颜色红色
    * 右边框：宽度 4px，样式 `dashed`，颜色蓝色
    * 下边框：宽度 2px，样式 `solid`，颜色红色
    * 左边框：宽度 4px，样式 `dashed`，颜色蓝色
    * 圆角半径：左上角 10px，右上角 5px，右下角 0px，左下角 0px
* `box_sides`: 一个枚举集合，指定要绘制哪些边框，例如 `{kTop, kRight, kBottom, kLeft}`。

输出：

* 在图形上下文中绘制出具有指定宽度、样式、颜色和圆角的矩形边框。 代码片段中的 `edge_quad` 和 `edge_pentagon` 变量会存储计算出的边框形状的顶点坐标。 例如，对于上边框，`edge_quad` 可能会计算出四个顶点坐标，形成一个矩形（如果不是圆角）。 如果是圆角，则可能需要计算更多的顶点（例如 `edge_pentagon`）。

**用户或编程常见的使用错误：**

* **边框宽度设置为负数或零：**  虽然 CSS 允许边框宽度为 0，但负数通常会导致未定义的行为或者被浏览器忽略。  如果边框宽度为 0，`ShouldRender()` 方法会返回 false，导致边框不被绘制。
* **边框颜色未设置或设置为透明：**  如果边框颜色未设置或者设置为 `transparent`，边框将不可见。
* **圆角半径过大导致重叠：**  如果圆角半径设置得非常大，可能会导致相邻的圆角重叠，产生不期望的视觉效果。 代码中的 `FindIntersection` 函数在处理圆角时可能会遇到精度问题或者性能问题。
* **错误的边框样式组合：**  某些边框样式的组合可能不会产生预期的效果。 例如，在非常窄的边框上使用 `dashed` 或 `dotted` 样式可能难以看清。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 和 CSS 被 Blink 引擎解析。**
3. **Blink 的布局引擎计算出页面上各个元素的尺寸和位置，包括需要绘制边框的元素。**
4. **当需要绘制某个元素的边框时，Blink 的绘制引擎会创建一个 `BoxBorderPainter` 对象。**
5. **绘制引擎将元素的边框样式信息（来自 CSS）、元素矩形区域等数据传递给 `BoxBorderPainter` 对象的 `Paint` 方法。**
6. **`Paint` 方法内部会根据边框的属性，逐步计算出边框的几何形状，并调用图形上下文的方法进行绘制。**
7. **如果在调试过程中，你发现某个元素的边框没有正确显示，你可以通过以下步骤来跟踪问题：**
    * **使用浏览器的开发者工具检查元素的 CSS 属性，确认边框相关的属性是否正确设置。**
    * **在开发者工具的 "Rendering" 选项卡中，可以查看元素的布局信息，确认元素的尺寸和位置是否正确。**
    * **如果怀疑是边框绘制代码的问题，可以在 `blink/renderer/core/paint/box_border_painter.cc` 相关的代码中设置断点。**
    * **重新加载页面或触发导致元素重绘的操作。**
    * **当代码执行到断点时，你可以逐步查看 `Paint` 方法的参数值，例如 `box_rect`、`border_data` 等，以及中间变量的值，例如 `outer_points`、`inner_points`、`edge_quad` 等，来分析边框的计算过程是否正确。**
    * **特别关注 `FindIntersection` 和 `ClipPolygon` 这些涉及到几何计算的函数，查看它们的输入和输出是否符合预期。**

总而言之，`blink/renderer/core/paint/box_border_painter.cc` 是 Blink 渲染引擎中负责将 CSS 边框样式转化为屏幕上可见像素的关键组件。 理解其工作原理有助于理解浏览器如何渲染网页，并为调试边框相关的渲染问题提供重要的线索。

### 提示词
```
这是目录为blink/renderer/core/paint/box_border_painter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
f (edge_quad[1].y() > inner_points[2].y()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[3],
                           inner_points[2], edge_quad[1]);
        }
        if (edge_quad[1].x() > inner_points[2].x()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[1],
                           inner_points[2], edge_quad[1]);
        }
        if (edge_quad[2].y() < edge_quad[1].y() &&
            edge_quad[2].x() > edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[2].x(), edge_quad[1].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }

      if (!inner_.GetRadii().TopRight().IsZero()) {
        FindIntersection(
            edge_quad[3], edge_quad[2],
            gfx::PointF(edge_quad[2].x() - inner_.GetRadii().TopRight().width(),
                        edge_quad[2].y()),
            gfx::PointF(
                edge_quad[2].x(),
                edge_quad[2].y() + inner_.GetRadii().TopRight().height()),
            edge_quad[2]);
        if (bound_quad1.y() < edge_quad[2].y()) {
          bound_quad1.set_y(edge_quad[2].y());
          bound_quad2.set_y(edge_quad[2].y());
        }

        if (edge_quad[2].y() > inner_points[3].y()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[3],
                           inner_points[2], edge_quad[2]);
        }
        if (edge_quad[2].x() < inner_points[3].x()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[0],
                           inner_points[3], edge_quad[2]);
        }
        if (edge_quad[2].y() > edge_quad[1].y() &&
            edge_quad[2].x() > edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[1].x(), edge_quad[2].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }
      break;

    case BoxSide::kLeft:
      // Swap the order of adjacent edges to allow common code
      std::swap(first_miter, second_miter);
      edge_quad[0] = outer_points[3];
      edge_quad[1] = inner_points[3];
      edge_quad[2] = inner_points[0];
      edge_quad[3] = outer_points[0];

      DCHECK(edge_quad[0].x() == edge_quad[3].x());
      DCHECK(edge_quad[1].x() == edge_quad[2].x());

      bound_quad1 = gfx::PointF(edge_quad[1].x(), edge_quad[0].y());
      bound_quad2 = gfx::PointF(edge_quad[2].x(), edge_quad[3].y());

      extension_offset.set_x(0);
      extension_offset.set_y(kExtensionLength);

      if (!inner_.GetRadii().TopLeft().IsZero()) {
        FindIntersection(
            edge_quad[3], edge_quad[2],
            gfx::PointF(edge_quad[2].x() + inner_.GetRadii().TopLeft().width(),
                        edge_quad[2].y()),
            gfx::PointF(
                edge_quad[2].x(),
                edge_quad[2].y() + inner_.GetRadii().TopLeft().height()),
            edge_quad[2]);
        DCHECK(bound_quad2.x() <= edge_quad[2].x());
        bound_quad1.set_x(edge_quad[2].x());
        bound_quad2.set_x(edge_quad[2].x());

        if (edge_quad[2].y() > inner_points[2].y()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[3],
                           inner_points[2], edge_quad[2]);
        }
        if (edge_quad[2].x() > inner_points[2].x()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[1],
                           inner_points[2], edge_quad[2]);
        }
        if (edge_quad[2].y() < edge_quad[1].y() &&
            edge_quad[2].x() > edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[2].x(), edge_quad[1].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }

      if (!inner_.GetRadii().BottomLeft().IsZero()) {
        FindIntersection(
            edge_quad[0], edge_quad[1],
            gfx::PointF(
                edge_quad[1].x() + inner_.GetRadii().BottomLeft().width(),
                edge_quad[1].y()),
            gfx::PointF(
                edge_quad[1].x(),
                edge_quad[1].y() - inner_.GetRadii().BottomLeft().height()),
            edge_quad[1]);
        if (bound_quad1.x() < edge_quad[1].x()) {
          bound_quad1.set_x(edge_quad[1].x());
          bound_quad2.set_x(edge_quad[1].x());
        }

        if (edge_quad[1].y() < inner_points[1].y()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[0],
                           inner_points[1], edge_quad[1]);
        }
        if (edge_quad[1].x() > inner_points[1].x()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[1],
                           inner_points[2], edge_quad[1]);
        }
        if (edge_quad[2].y() < edge_quad[1].y() &&
            edge_quad[2].x() < edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[1].x(), edge_quad[2].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }
      break;

    case BoxSide::kBottom:
      // Swap the order of adjacent edges to allow common code
      std::swap(first_miter, second_miter);
      edge_quad[0] = outer_points[2];
      edge_quad[1] = inner_points[2];
      edge_quad[2] = inner_points[3];
      edge_quad[3] = outer_points[3];

      DCHECK(edge_quad[0].y() == edge_quad[3].y());
      DCHECK(edge_quad[1].y() == edge_quad[2].y());

      bound_quad1 = gfx::PointF(edge_quad[0].x(), edge_quad[1].y());
      bound_quad2 = gfx::PointF(edge_quad[3].x(), edge_quad[2].y());

      extension_offset.set_x(kExtensionLength);
      extension_offset.set_y(0);

      if (!inner_.GetRadii().BottomLeft().IsZero()) {
        FindIntersection(
            edge_quad[3], edge_quad[2],
            gfx::PointF(
                edge_quad[2].x() + inner_.GetRadii().BottomLeft().width(),
                edge_quad[2].y()),
            gfx::PointF(
                edge_quad[2].x(),
                edge_quad[2].y() - inner_.GetRadii().BottomLeft().height()),
            edge_quad[2]);
        DCHECK(bound_quad2.y() >= edge_quad[2].y());
        bound_quad1.set_y(edge_quad[2].y());
        bound_quad2.set_y(edge_quad[2].y());

        if (edge_quad[2].y() < inner_points[1].y()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[0],
                           inner_points[1], edge_quad[2]);
        }
        if (edge_quad[2].x() > inner_points[1].x()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[1],
                           inner_points[2], edge_quad[2]);
        }
        if (edge_quad[2].y() < edge_quad[1].y() &&
            edge_quad[2].x() < edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[1].x(), edge_quad[2].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }

      if (!inner_.GetRadii().BottomRight().IsZero()) {
        FindIntersection(
            edge_quad[0], edge_quad[1],
            gfx::PointF(
                edge_quad[1].x() - inner_.GetRadii().BottomRight().width(),
                edge_quad[1].y()),
            gfx::PointF(
                edge_quad[1].x(),
                edge_quad[1].y() - inner_.GetRadii().BottomRight().height()),
            edge_quad[1]);
        if (bound_quad1.y() > edge_quad[1].y()) {
          bound_quad1.set_y(edge_quad[1].y());
          bound_quad2.set_y(edge_quad[1].y());
        }

        if (edge_quad[1].y() < inner_points[0].y()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[0],
                           inner_points[1], edge_quad[1]);
        }
        if (edge_quad[1].x() < inner_points[0].x()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[0],
                           inner_points[3], edge_quad[1]);
        }
        if (edge_quad[2].x() < edge_quad[1].x() &&
            edge_quad[2].y() > edge_quad[1].y()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[2].x(), edge_quad[1].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }
      break;

    case BoxSide::kRight:
      edge_quad[0] = outer_points[1];
      edge_quad[1] = inner_points[1];
      edge_quad[2] = inner_points[2];
      edge_quad[3] = outer_points[2];

      DCHECK(edge_quad[0].x() == edge_quad[3].x());
      DCHECK(edge_quad[1].x() == edge_quad[2].x());

      bound_quad1 = gfx::PointF(edge_quad[1].x(), edge_quad[0].y());
      bound_quad2 = gfx::PointF(edge_quad[2].x(), edge_quad[3].y());

      extension_offset.set_x(0);
      extension_offset.set_y(-kExtensionLength);

      if (!inner_.GetRadii().TopRight().IsZero()) {
        FindIntersection(
            edge_quad[0], edge_quad[1],
            gfx::PointF(edge_quad[1].x() - inner_.GetRadii().TopRight().width(),
                        edge_quad[1].y()),
            gfx::PointF(
                edge_quad[1].x(),
                edge_quad[1].y() + inner_.GetRadii().TopRight().height()),
            edge_quad[1]);
        DCHECK(bound_quad1.x() >= edge_quad[1].x());
        bound_quad1.set_x(edge_quad[1].x());
        bound_quad2.set_x(edge_quad[1].x());

        if (edge_quad[1].y() > inner_points[3].y()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[3],
                           inner_points[2], edge_quad[1]);
        }
        if (edge_quad[1].x() < inner_points[3].x()) {
          FindIntersection(edge_quad[0], edge_quad[1], inner_points[0],
                           inner_points[3], edge_quad[1]);
        }
        if (edge_quad[2].y() > edge_quad[1].y() &&
            edge_quad[2].x() > edge_quad[1].x()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[1].x(), edge_quad[2].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }

      if (!inner_.GetRadii().BottomRight().IsZero()) {
        FindIntersection(
            edge_quad[3], edge_quad[2],
            gfx::PointF(
                edge_quad[2].x() - inner_.GetRadii().BottomRight().width(),
                edge_quad[2].y()),
            gfx::PointF(
                edge_quad[2].x(),
                edge_quad[2].y() - inner_.GetRadii().BottomRight().height()),
            edge_quad[2]);
        if (bound_quad1.x() > edge_quad[2].x()) {
          bound_quad1.set_x(edge_quad[2].x());
          bound_quad2.set_x(edge_quad[2].x());
        }

        if (edge_quad[2].y() < inner_points[0].y()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[0],
                           inner_points[1], edge_quad[2]);
        }
        if (edge_quad[2].x() < inner_points[0].x()) {
          FindIntersection(edge_quad[3], edge_quad[2], inner_points[0],
                           inner_points[3], edge_quad[2]);
        }
        if (edge_quad[2].x() < edge_quad[1].x() &&
            edge_quad[2].y() > edge_quad[1].y()) {
          edge_pentagon = {edge_quad[0], edge_quad[1],
                           gfx::PointF(edge_quad[2].x(), edge_quad[1].y()),
                           edge_quad[2], edge_quad[3]};
        }
      }
      break;
  }

  if (first_miter == second_miter) {
    if (!edge_pentagon.empty() && !inner_.IsRenderable()) {
      DCHECK_EQ(edge_pentagon.size(), 5u);

      ClipPolygon(context_, edge_pentagon, first_miter == kSoftMiter);
      return;
    }

    ClipPolygon(context_, edge_quad, first_miter == kSoftMiter);
    return;
  }

  // If antialiasing settings for the first edge and second edge are different,
  // they have to be addressed separately. We do this by applying 2 clips, one
  // for each miter, with the appropriate anti-aliasing setting. Each clip uses
  // 3 sides of the quad rectilinear bounding box and a 4th side aligned with
  // the miter edge. We extend the clip in the miter direction to ensure overlap
  // as each edge is drawn.
  if (first_miter != kNoMiter) {
    gfx::PointF clipping_quad[4];

    clipping_quad[0] = edge_quad[0] + extension_offset;
    FindIntersection(edge_quad[0], edge_quad[1], bound_quad1, bound_quad2,
                     clipping_quad[1]);
    clipping_quad[1] += extension_offset;
    clipping_quad[2] = bound_quad2;
    clipping_quad[3] = edge_quad[3];

    ClipPolygon(context_, clipping_quad, first_miter == kSoftMiter);
  }

  if (second_miter != kNoMiter) {
    gfx::PointF clipping_quad[4];

    clipping_quad[0] = edge_quad[0];
    clipping_quad[1] = bound_quad1;
    FindIntersection(edge_quad[2], edge_quad[3], bound_quad1, bound_quad2,
                     clipping_quad[2]);
    clipping_quad[2] -= extension_offset;
    clipping_quad[3] = edge_quad[3] - extension_offset;

    ClipPolygon(context_, clipping_quad, second_miter == kSoftMiter);
  }
}

PhysicalBoxStrut BoxBorderPainter::DoubleStripeOutsets(
    BorderEdge::DoubleBorderStripe stripe) const {
  return outer_outsets_ -
         PhysicalBoxStrut(
             Edge(BoxSide::kTop).GetDoubleBorderStripeWidth(stripe),
             Edge(BoxSide::kRight).GetDoubleBorderStripeWidth(stripe),
             Edge(BoxSide::kBottom).GetDoubleBorderStripeWidth(stripe),
             Edge(BoxSide::kLeft).GetDoubleBorderStripeWidth(stripe));
}

PhysicalBoxStrut BoxBorderPainter::CenterOutsets() const {
  return outer_outsets_ -
         PhysicalBoxStrut(Edge(BoxSide::kTop).UsedWidth() * 0.5,
                          Edge(BoxSide::kRight).UsedWidth() * 0.5,
                          Edge(BoxSide::kBottom).UsedWidth() * 0.5,
                          Edge(BoxSide::kLeft).UsedWidth() * 0.5);
}

bool BoxBorderPainter::ColorsMatchAtCorner(BoxSide side,
                                           BoxSide adjacent_side) const {
  if (!Edge(adjacent_side).ShouldRender())
    return false;

  if (!Edge(side).SharesColorWith(Edge(adjacent_side)))
    return false;

  return !BorderStyleHasUnmatchedColorsAtCorner(Edge(side).BorderStyle(), side,
                                                adjacent_side);
}

void BoxBorderPainter::DrawBoxSide(GraphicsContext& context,
                                   const gfx::Rect& snapped_edge_rect,
                                   BoxSide side,
                                   Color color,
                                   EBorderStyle style,
                                   const AutoDarkMode& auto_dark_mode) {
  DrawLineForBoxSide(context, snapped_edge_rect.x(), snapped_edge_rect.y(),
                     snapped_edge_rect.right(), snapped_edge_rect.bottom(),
                     side, color, style, 0, 0, true, auto_dark_mode);
}

}  // namespace blink
```