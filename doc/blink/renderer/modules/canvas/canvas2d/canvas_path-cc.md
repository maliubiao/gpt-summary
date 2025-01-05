Response:
Let's break down the thought process for analyzing the provided C++ code for `CanvasPath`.

1. **Initial Skim for Keywords and Structure:** The first step is to quickly read through the code, looking for familiar keywords and structural elements related to graphics and paths. Keywords like `Path`, `MoveTo`, `LineTo`, `Arc`, `BezierCurveTo`, `Rect`, `RoundRect`, `ClosePath`, `Transform`, and `BoundingRect` immediately stand out. The `#include` directives at the top also give hints about dependencies. The overall structure of a class with methods is apparent.

2. **Identify Core Functionality:**  Based on the keywords, it's clear that this class is responsible for building and manipulating paths, a fundamental concept in 2D graphics. The methods correspond to common path operations in drawing APIs.

3. **Relate to Web Technologies (JavaScript, HTML, CSS):**  The directory name "blink/renderer/modules/canvas/canvas2d" is a strong indicator that this code is part of the HTML `<canvas>` element implementation. The methods in `CanvasPath` directly map to the methods of the Canvas 2D API in JavaScript. This is the crucial link to web technologies.

4. **Map C++ Methods to JavaScript Canvas API:**  Go through the C++ methods and mentally (or literally) map them to their JavaScript equivalents:
    * `closePath()` -> `ctx.closePath()`
    * `moveTo(x, y)` -> `ctx.moveTo(x, y)`
    * `lineTo(x, y)` -> `ctx.lineTo(x, y)`
    * `quadraticCurveTo(cpx, cpy, x, y)` -> `ctx.quadraticCurveTo(cpx, cpy, x, y)`
    * `bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y)` -> `ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y)`
    * `arcTo(x1, y1, x2, y2, r)` -> `ctx.arcTo(x1, y1, x2, y2, r)`
    * `arc(x, y, radius, startAngle, endAngle, anticlockwise)` -> `ctx.arc(x, y, radius, startAngle, endAngle, anticlockwise)`
    * `ellipse(x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise)` -> `ctx.ellipse(x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise)`
    * `rect(x, y, width, height)` -> `ctx.rect(x, y, width, height)`
    * `roundRect(...)` -> `ctx.roundRect(...)`

5. **Consider Input and Output:** For each method, think about the expected inputs (coordinates, radii, angles, etc.) and the output (modifying the internal path representation). This leads to understanding the method's purpose and how it affects the path.

6. **Identify Potential User Errors:** Based on the method parameters and the nature of drawing, common errors come to mind:
    * Incorrect number of arguments.
    * Negative radii (handled by exception throwing).
    * Unrealistic or out-of-bounds coordinates (though the code handles `NaN` and `Infinity`).
    * Misunderstanding the order of control points for curves.
    * Incorrectly specifying angles for arcs (leading to unexpected shapes).

7. **Infer Logic and Edge Cases:** Some methods have more complex logic. For example, `AdjustEndAngle` handles wrapping angles for arcs. The code also deals with "degenerate" ellipses (where one or both radii are zero). The `roundRect` implementation needs to handle different numbers of radius arguments. The code also includes checks for `IsTransformInvertible()`, suggesting transformations play a role.

8. **Trace User Operations:**  Imagine a user interacting with a web page. How do their actions translate to these C++ calls?  Any drawing on a `<canvas>` using the 2D context will ultimately trigger these methods. For example, drawing a rectangle involves calling `rect()`, which in turn calls the C++ `CanvasPath::rect()`.

9. **Look for Hints about Internal Implementation:** The code reveals some internal details, such as the use of `blink::Path` for storing the final path and separate `LineBuilder` and `ArcBuilder` for optimized handling of simple lines and arcs. The `identifiability_study_helper_` suggests some internal tracking or debugging mechanism.

10. **Focus on the "Why":** Why is this code needed?  It's the core of the path-building functionality for the Canvas 2D API, enabling web developers to create complex vector graphics.

11. **Organize and Explain:** Finally, structure the findings into logical sections as requested in the prompt: functionality, relationship to web technologies, input/output, user errors, and debugging. Use examples to illustrate the connections and concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just draws shapes."  **Correction:** It *builds* the *description* of the shapes. The actual drawing happens later in the rendering pipeline.
* **Realization:** The `LineBuilder` and `ArcBuilder` suggest an optimization. Simple line segments and basic arcs might be handled more efficiently before being merged into a full `Path` object.
* **Understanding the `Transform` interaction:** The `IsTransformInvertible()` checks and `GetTransform().MapPoint()` calls indicate that transformations applied to the canvas context are being applied at the path-building stage.
* **Importance of `ExceptionState`:** The `ExceptionState&` parameters highlight the error-handling mechanism, ensuring that invalid inputs from JavaScript are caught and reported.

By following these steps, moving from a general understanding to specific details and connecting the C++ code to the higher-level web technologies, a comprehensive analysis of the `CanvasPath.cc` file can be achieved.
This C++ source code file, `canvas_path.cc`, located within the Chromium Blink rendering engine, implements the functionality for creating and manipulating paths in the HTML Canvas 2D API. Essentially, it's the engine that powers the path-drawing commands you use in JavaScript with a `<canvas>` element.

Here's a breakdown of its functionalities:

**Core Functionality: Building and Modifying Paths**

This file defines the `CanvasPath` class, which manages the construction of geometric paths. It provides methods that directly correspond to the path manipulation methods available in the JavaScript Canvas 2D API:

* **`closePath()`:** Closes the current sub-path by drawing a straight line back to the starting point of the sub-path.
* **`moveTo(x, y)`:** Begins a new sub-path at the specified coordinates.
* **`lineTo(x, y)`:** Adds a straight line segment from the current point to the specified coordinates.
* **`quadraticCurveTo(cpx, cpy, x, y)`:** Adds a quadratic Bézier curve to the path.
* **`bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y)`:** Adds a cubic Bézier curve to the path.
* **`arcTo(x1, y1, x2, y2, r)`:** Adds an arc to the path, connecting the last point in the current sub-path to the given point (x2, y2) using an arc with the given radius (r).
* **`arc(x, y, radius, startAngle, endAngle, anticlockwise)`:** Adds a circular arc centered at (x, y) with the given radius.
* **`ellipse(x, y, radiusX, radiusY, rotation, startAngle, endAngle, anticlockwise)`:** Adds an elliptical arc.
* **`rect(x, y, width, height)`:** Creates a new closed rectangular sub-path.
* **`roundRect(...)`:** Creates a new closed rounded rectangular sub-path. There are overloaded versions to handle different ways of specifying the corner radii.

**Relationship to JavaScript, HTML, and CSS**

This C++ code directly implements the behavior exposed by the JavaScript Canvas 2D API.

* **JavaScript:**  When you use the Canvas 2D API in JavaScript, for example:

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');

   ctx.beginPath();
   ctx.moveTo(50, 50);
   ctx.lineTo(150, 50);
   ctx.lineTo(100, 150);
   ctx.closePath();
   ctx.stroke();
   ```

   Each of the `ctx.*` methods you call (like `moveTo`, `lineTo`, `closePath`) corresponds to a method call within the `CanvasPath` class in this C++ file. The JavaScript engine (V8 in Chromium) marshals the arguments from JavaScript to the corresponding C++ function.

* **HTML:** The `<canvas>` element in HTML provides the drawing surface. When JavaScript interacts with the canvas through its 2D rendering context, the underlying path operations are handled by this C++ code.

   ```html
   <canvas id="myCanvas" width="200" height="200"></canvas>
   ```

* **CSS:** While CSS itself doesn't directly interact with the path building process defined in this file, CSS styles (like `strokeStyle`, `fillStyle`, `lineWidth`) are used *later* in the rendering pipeline to determine how the paths built by this code are actually drawn on the canvas. The `CanvasPath` class is responsible for defining the *geometry* of the shape, not its appearance.

**Examples:**

* **`moveTo` and `lineTo`:**
    * **JavaScript:** `ctx.moveTo(10, 10); ctx.lineTo(100, 100);`
    * **C++ (Hypothetical):** This would result in calls to `CanvasPath::moveTo(10, 10)` and `CanvasPath::lineTo(100, 100)`. The internal `path_` object would be updated to store a line segment from (10, 10) to (100, 100).

* **`arc`:**
    * **JavaScript:** `ctx.arc(100, 75, 50, 0, Math.PI * 2);` (draws a full circle)
    * **C++ (Hypothetical):**  `CanvasPath::arc(100, 75, 50, 0, 6.283185307179586, false, exceptionState)`. The `path_` object would be updated to represent a circular arc.

* **`roundRect`:**
    * **JavaScript:** `ctx.roundRect(10, 10, 100, 100, 10);` (draws a rectangle with rounded corners of radius 10)
    * **C++ (Hypothetical):** `CanvasPath::roundRect(10, 10, 100, 100, {10}, exceptionState)`. The `path_` object would be updated to represent the rounded rectangle.

**Logical Inference (Hypothetical Input and Output)**

Let's consider the `lineTo` function:

* **Hypothetical Input:**  A `CanvasPath` object in a state where `moveTo(50, 50)` has been called, and then `lineTo(100, 100)` is called.
* **Logical Processing:**
    1. The function receives `double_x = 100`, `double_y = 100`.
    2. These are cast to `float x = 100`, `float y = 100`.
    3. Checks for `std::isfinite(x)` and `std::isfinite(y)` are performed (to handle NaN or Infinity).
    4. If a transformation is applied to the canvas context and it's invertible, the point (100, 100) is transformed.
    5. If the path is currently empty (unlikely in this scenario because of the `moveTo`), a `line_builder_` might be used initially.
    6. Otherwise, the `UpdatePathFromLineOrArcIfNecessaryForMutation()` function ensures the internal `path_` object is up-to-date.
    7. Finally, `path_.AddLineTo(gfx::PointF(x, y))` is called, adding the line segment to the internal path representation.
* **Hypothetical Output:** The internal `path_` object of the `CanvasPath` instance now contains a line segment from (50, 50) to (100, 100).

**User or Programming Common Usage Errors**

* **Negative Radius in `arc` or `ellipse`:**
    * **Error:** Providing a negative value for the `radius` in `ctx.arc()` or `radiusX`/`radiusY` in `ctx.ellipse()`.
    * **C++ Handling:** The code explicitly checks for `radius < 0` and throws a `DOMExceptionCode::kIndexSizeError`.
    * **Example:** `ctx.arc(100, 100, -50, 0, Math.PI);` will result in a JavaScript error.

* **Incorrect Number of Arguments in `roundRect`:**
    * **Error:** Providing fewer than 1 or more than 4 radius values to the `ctx.roundRect()` method when using the array-like syntax for radii.
    * **C++ Handling:** The code checks `num_radii` and throws a `RangeError` if the count is incorrect.
    * **Example:** `ctx.roundRect(10, 10, 100, 100, [10, 20, 30, 40, 50]);` will result in a JavaScript error.

* **Using `lineTo` without a preceding `moveTo`:**
    * **Behavior:** While not strictly an "error" that throws an exception, if you call `lineTo` without first calling `moveTo`, the "current point" is implicitly assumed to be (0, 0). This can lead to unexpected lines drawn from the origin.

* **Non-finite numbers (NaN or Infinity) as coordinates or dimensions:**
    * **C++ Handling:** The code includes checks using `std::isfinite()` to prevent processing of `NaN` or `Infinity` values, effectively ignoring these invalid inputs.

**User Operations as Debugging Clues**

To understand how a user's action leads to this code being executed, consider these steps as a debugging path:

1. **User Interaction:** A user interacts with a web page containing a `<canvas>` element. This interaction could be triggering a JavaScript function (e.g., by clicking a button, through an animation loop, or in response to mouse movements).

2. **JavaScript Canvas API Calls:** The JavaScript function manipulates the Canvas 2D rendering context (`ctx`). For example, it might call `ctx.beginPath()`, `ctx.moveTo(x, y)`, `ctx.lineTo(x1, y1)`, `ctx.stroke()`.

3. **JavaScript Engine (V8) Bridge:** The V8 JavaScript engine interprets these JavaScript calls. When a Canvas 2D API method is called, V8 knows that it needs to invoke the corresponding C++ implementation within the Blink rendering engine.

4. **Argument Marshaling:** V8 marshals the JavaScript arguments (numbers, booleans, etc.) into a format that can be passed to the C++ function.

5. **`CanvasPath` Method Invocation:** The corresponding method in the `CanvasPath` class (e.g., `CanvasPath::moveTo`, `CanvasPath::lineTo`) is called with the marshaled arguments.

6. **Path Modification:** The C++ method updates the internal representation of the path within the `CanvasPath` object (likely using the `path_` member variable, which is a `blink::Path` object).

7. **Rendering Pipeline:** Later, when the canvas needs to be painted to the screen (e.g., after calling `ctx.stroke()` or `ctx.fill()`), the information stored in the `CanvasPath` object is used by the graphics rendering pipeline to draw the actual shapes on the canvas.

**Debugging Example:**

Imagine a user reports that a line is not being drawn correctly on their canvas. Here's how a developer might trace it back to this file:

1. **Inspect JavaScript:** The developer would first examine the JavaScript code responsible for drawing the line, looking at the calls to `moveTo` and `lineTo`. They might use `console.log` to verify the coordinates being passed.

2. **Browser Developer Tools:** Using the browser's developer tools, the "Sources" tab allows setting breakpoints in the JavaScript code to step through the execution and inspect variable values.

3. **Chromium Source Code:** If the JavaScript seems correct, the issue might be in the underlying implementation. The developer might then look at the Chromium source code, specifically `canvas_path.cc`, to understand how `moveTo` and `lineTo` are implemented.

4. **Potential Issues in C++:**  The developer might look for potential bugs like:
    * Incorrect handling of transformations.
    * Precision issues with floating-point numbers.
    * Errors in the logic for adding line segments to the internal path representation.

5. **Logging/Debugging in C++ (Advanced):**  For deeper debugging, developers might need to add logging statements within the C++ code itself (using `DLOG` or similar mechanisms) and rebuild Chromium to observe the internal state of the `CanvasPath` object.

In summary, `blink/renderer/modules/canvas/canvas2d/canvas_path.cc` is a crucial file that forms the foundation for drawing paths on HTML canvases. It directly translates JavaScript API calls into concrete path manipulation operations within the Blink rendering engine. Understanding its functionality is essential for anyone working on the implementation or debugging of canvas-related features in Chromium.

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_path.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2008, 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008 Dirk Schulze <krit@webkit.org>
 * Copyright (C) 2010 Torch Mobile (Beijing) Co. Ltd. All rights reserved.
 * Copyright (C) 2012, 2013 Intel Corporation. All rights reserved.
 * Copyright (C) 2012, 2013 Adobe Systems Incorporated. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_path.h"

#include <cmath>
#include <ostream>  // IWYU pragma: keep (needed by String::Number(int), https://github.com/clangd/clangd/issues/2053)
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_dompointinit_unrestricteddouble.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/identifiability_study_helper.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/geometry/float_rounded_rect.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/visitor.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/transforms/affine_transform.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

void CanvasPath::closePath() {
  if (IsEmpty()) [[unlikely]] {
    return;
  }
  // If the current path is a zero lengthed path (ex: moveTo p1 and lineTo p1),
  // then closePath is no op.
  if (path_.BoundingRect().height() == 0 && path_.BoundingRect().width() == 0 &&
      (IsLine() && line_builder_.BoundingRect().height() == 0 &&
       line_builder_.BoundingRect().width() == 0)) [[unlikely]] {
    if (!path_.HasCurrentPoint()) {
      Clear();
      return;
    }
    auto p = path_.CurrentPoint();
    Clear();
    moveTo(p.x(), p.y());
    return;
  }

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kClosePath);
  }
  if (IsArc()) {
    // Only the first close does something.
    if (!arc_builder_.IsClosed()) {
      path_.Clear();
      arc_builder_.Close();
    }
  } else {
    UpdatePathFromLineOrArcIfNecessaryForMutation();
    path_.CloseSubpath();
  }
}

void CanvasPath::moveTo(double double_x, double double_y) {
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  if (!std::isfinite(x) || !std::isfinite(y)) [[unlikely]] {
    return;
  }
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kMoveTo, double_x,
                                                double_y);
  }
  gfx::PointF point(x, y);
  if (!IsTransformInvertible()) [[unlikely]] {
    point = GetTransform().MapPoint(point);
  }
  if (IsEmpty()) {
    line_builder_.MoveTo(point);
  } else {
    UpdatePathFromLineOrArcIfNecessaryForMutation();
    path_.MoveTo(point);
  }
}

void CanvasPath::lineTo(double double_x, double double_y) {
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  if (!std::isfinite(x) || !std::isfinite(y)) [[unlikely]] {
    return;
  }
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kLineTo, double_x,
                                                double_y);
  }
  gfx::PointF p1(x, y);

  if (!IsTransformInvertible()) [[unlikely]] {
    p1 = GetTransform().MapPoint(p1);
  }

  if (IsEmpty()) [[unlikely]] {
    line_builder_.MoveTo(p1);
  }

  if (line_builder_.CanCreateLineTo()) {
    // `path_` may contain the move to, reset it so that if `path_` is needed
    // it will be updated.
    path_.Clear();
    line_builder_.LineTo(p1);
    DCHECK(IsLine());
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  path_.AddLineTo(p1);
}

void CanvasPath::quadraticCurveTo(double double_cpx,
                                  double double_cpy,
                                  double double_x,
                                  double double_y) {
  float cpx = base::saturated_cast<float>(double_cpx);
  float cpy = base::saturated_cast<float>(double_cpy);
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);

  if (!std::isfinite(cpx) || !std::isfinite(cpy) || !std::isfinite(x) ||
      !std::isfinite(y)) [[unlikely]] {
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kQuadradicCurveTo,
                                                double_cpx, double_cpy,
                                                double_x, double_y);
  }
  gfx::PointF p1(x, y);
  gfx::PointF cp(cpx, cpy);

  if (!IsTransformInvertible()) [[unlikely]] {
    p1 = GetTransform().MapPoint(p1);
    cp = GetTransform().MapPoint(cp);
  }

  if (!path_.HasCurrentPoint()) [[unlikely]] {
    path_.MoveTo(gfx::PointF(cpx, cpy));
  }

  path_.AddQuadCurveTo(cp, p1);
}

void CanvasPath::bezierCurveTo(double double_cp1x,
                               double double_cp1y,
                               double double_cp2x,
                               double double_cp2y,
                               double double_x,
                               double double_y) {
  float cp1x = base::saturated_cast<float>(double_cp1x);
  float cp1y = base::saturated_cast<float>(double_cp1y);
  float cp2x = base::saturated_cast<float>(double_cp2x);
  float cp2y = base::saturated_cast<float>(double_cp2y);
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  if (!std::isfinite(cp1x) || !std::isfinite(cp1y) || !std::isfinite(cp2x) ||
      !std::isfinite(cp2y) || !std::isfinite(x) || !std::isfinite(y))
      [[unlikely]] {
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kBezierCurveTo, double_cp1x, double_cp1y, double_cp2x,
        double_cp2y, double_x, double_y);
  }

  gfx::PointF p1(x, y);
  gfx::PointF cp1(cp1x, cp1y);
  gfx::PointF cp2(cp2x, cp2y);

  if (!IsTransformInvertible()) [[unlikely]] {
    p1 = GetTransform().MapPoint(p1);
    cp1 = GetTransform().MapPoint(cp1);
    cp2 = GetTransform().MapPoint(cp2);
  }
  if (!path_.HasCurrentPoint()) [[unlikely]] {
    path_.MoveTo(gfx::PointF(cp1x, cp1y));
  }

  path_.AddBezierCurveTo(cp1, cp2, p1);
}

void CanvasPath::arcTo(double double_x1,
                       double double_y1,
                       double double_x2,
                       double double_y2,
                       double double_r,
                       ExceptionState& exception_state) {
  float x1 = base::saturated_cast<float>(double_x1);
  float y1 = base::saturated_cast<float>(double_y1);
  float x2 = base::saturated_cast<float>(double_x2);
  float y2 = base::saturated_cast<float>(double_y2);
  float r = base::saturated_cast<float>(double_r);
  if (!std::isfinite(x1) || !std::isfinite(y1) || !std::isfinite(x2) ||
      !std::isfinite(y2) || !std::isfinite(r)) [[unlikely]] {
    return;
  }

  if (r < 0) [[unlikely]] {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The radius provided (" + String::Number(r) + ") is negative.");
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kArcTo, double_x1,
                                                double_y1, double_x2, double_y2,
                                                double_r);
  }

  gfx::PointF p1(x1, y1);
  gfx::PointF p2(x2, y2);

  if (!IsTransformInvertible()) [[unlikely]] {
    p1 = GetTransform().MapPoint(p1);
    p2 = GetTransform().MapPoint(p2);
  }

  if (!path_.HasCurrentPoint()) [[unlikely]] {
    path_.MoveTo(p1);
  } else if (p1 == path_.CurrentPoint() || p1 == p2 || !r) [[unlikely]] {
    lineTo(x1, y1);
  } else {
    path_.AddArcTo(p1, p2, r);
  }
}

namespace {

float AdjustEndAngle(float start_angle, float end_angle, bool anticlockwise) {
  float new_end_angle = end_angle;
  /* http://www.whatwg.org/specs/web-apps/current-work/multipage/the-canvas-element.html#dom-context-2d-arc
   * If the anticlockwise argument is false and endAngle-startAngle is equal
   * to or greater than 2pi, or,
   * if the anticlockwise argument is true and startAngle-endAngle is equal to
   * or greater than 2pi,
   * then the arc is the whole circumference of this ellipse, and the point at
   * startAngle along this circle's circumference, measured in radians clockwise
   * from the ellipse's semi-major axis, acts as both the start point and the
   * end point.
   */
  if (!anticlockwise && end_angle - start_angle >= kTwoPiFloat) {
    new_end_angle = start_angle + kTwoPiFloat;
  } else if (anticlockwise && start_angle - end_angle >= kTwoPiFloat) {
    new_end_angle = start_angle - kTwoPiFloat;

    /*
     * Otherwise, the arc is the path along the circumference of this ellipse
     * from the start point to the end point, going anti-clockwise if the
     * anticlockwise argument is true, and clockwise otherwise.
     * Since the points are on the ellipse, as opposed to being simply angles
     * from zero, the arc can never cover an angle greater than 2pi radians.
     */
    /* NOTE: When startAngle = 0, endAngle = 2Pi and anticlockwise = true, the
     * spec does not indicate clearly.
     * We draw the entire circle, because some web sites use arc(x, y, r, 0,
     * 2*Math.PI, true) to draw circle.
     * We preserve backward-compatibility.
     */
  } else if (!anticlockwise && start_angle > end_angle) {
    new_end_angle = start_angle +
                    (kTwoPiFloat - fmodf(start_angle - end_angle, kTwoPiFloat));
  } else if (anticlockwise && start_angle < end_angle) {
    new_end_angle = start_angle -
                    (kTwoPiFloat - fmodf(end_angle - start_angle, kTwoPiFloat));
  }

  DCHECK(EllipseIsRenderable(start_angle, new_end_angle));
  DCHECK((anticlockwise && (start_angle >= new_end_angle)) ||
         (!anticlockwise && (new_end_angle >= start_angle)));
  return new_end_angle;
}

inline void LineTo(CanvasPath* path, const gfx::PointF& p) {
  path->lineTo(p.x(), p.y());
}

inline gfx::PointF GetPointOnEllipse(float radius_x,
                                     float radius_y,
                                     float theta) {
  return gfx::PointF(radius_x * cosf(theta), radius_y * sinf(theta));
}

void CanonicalizeAngle(float* start_angle, float* end_angle) {
  // Make 0 <= startAngle < 2*PI
  float new_start_angle = fmodf(*start_angle, kTwoPiFloat);

  if (new_start_angle < 0) {
    new_start_angle += kTwoPiFloat;
    // Check for possible catastrophic cancellation in cases where
    // newStartAngle was a tiny negative number (c.f. crbug.com/503422)
    if (new_start_angle >= kTwoPiFloat)
      new_start_angle -= kTwoPiFloat;
  }

  float delta = new_start_angle - *start_angle;
  *start_angle = new_start_angle;
  *end_angle = *end_angle + delta;

  DCHECK_GE(new_start_angle, 0);
  DCHECK_LT(new_start_angle, kTwoPiFloat);
}

/*
 * degenerateEllipse() handles a degenerated ellipse using several lines.
 *
 * Let's see a following example: line to ellipse to line.
 *        _--^\
 *       (     )
 * -----(      )
 *            )
 *           /--------
 *
 * If radiusX becomes zero, the ellipse of the example is degenerated.
 *         _
 *        // P
 *       //
 * -----//
 *      /
 *     /--------
 *
 * To draw the above example, need to get P that is a local maximum point.
 * Angles for P are 0.5Pi and 1.5Pi in the ellipse coordinates.
 *
 * If radiusY becomes zero, the result is as follows.
 * -----__
 *        --_
 *          ----------
 *            ``P
 * Angles for P are 0 and Pi in the ellipse coordinates.
 *
 * To handle both cases, degenerateEllipse() lines to start angle, local maximum
 * points(every 0.5Pi), and end angle.
 * NOTE: Before ellipse() calls this function, adjustEndAngle() is called, so
 * endAngle - startAngle must be equal to or less than 2Pi.
 */
void DegenerateEllipse(CanvasPath* path,
                       float x,
                       float y,
                       float radius_x,
                       float radius_y,
                       float rotation,
                       float start_angle,
                       float end_angle,
                       bool anticlockwise) {
  DCHECK(EllipseIsRenderable(start_angle, end_angle));
  DCHECK_GE(start_angle, 0);
  DCHECK_LT(start_angle, kTwoPiFloat);
  DCHECK((anticlockwise && (start_angle - end_angle) >= 0) ||
         (!anticlockwise && (end_angle - start_angle) >= 0));

  gfx::PointF center(x, y);
  AffineTransform rotation_matrix;
  rotation_matrix.RotateRadians(rotation);
  // First, if the object's path has any subpaths, then the method must add a
  // straight line from the last point in the subpath to the start point of the
  // arc.
  LineTo(path, center + rotation_matrix
                            .MapPoint(GetPointOnEllipse(radius_x, radius_y,
                                                        start_angle))
                            .OffsetFromOrigin());
  if ((!radius_x && !radius_y) || start_angle == end_angle) [[unlikely]] {
    return;
  }

  if (!anticlockwise) {
    // start_angle - fmodf(start_angle, kPiOverTwoFloat) + kPiOverTwoFloat is
    // the one of (0, 0.5Pi, Pi, 1.5Pi, 2Pi) that is the closest to start_angle
    // on the clockwise direction.
    for (float angle = start_angle - fmodf(start_angle, kPiOverTwoFloat) +
                       kPiOverTwoFloat;
         angle < end_angle; angle += kPiOverTwoFloat) {
      LineTo(path, center + rotation_matrix
                                .MapPoint(GetPointOnEllipse(radius_x, radius_y,
                                                            angle))
                                .OffsetFromOrigin());
    }
  } else {
    for (float angle = start_angle - fmodf(start_angle, kPiOverTwoFloat);
         angle > end_angle; angle -= kPiOverTwoFloat) {
      LineTo(path, center + rotation_matrix
                                .MapPoint(GetPointOnEllipse(radius_x, radius_y,
                                                            angle))
                                .OffsetFromOrigin());
    }
  }

  LineTo(path, center + rotation_matrix
                            .MapPoint(GetPointOnEllipse(radius_x, radius_y,
                                                        end_angle))
                            .OffsetFromOrigin());
}

}  // namespace

void CanvasPath::arc(double double_x,
                     double double_y,
                     double double_radius,
                     double double_start_angle,
                     double double_end_angle,
                     bool anticlockwise,
                     ExceptionState& exception_state) {
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  float radius = base::saturated_cast<float>(double_radius);
  float start_angle = base::saturated_cast<float>(double_start_angle);
  float end_angle = base::saturated_cast<float>(double_end_angle);
  if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(radius) ||
      !std::isfinite(start_angle) || !std::isfinite(end_angle)) [[unlikely]] {
    return;
  }

  if (radius < 0) [[unlikely]] {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        "The radius provided (" + String::Number(radius) + ") is negative.");
    return;
  }

  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kArc, double_x, double_y, double_radius, double_start_angle,
        double_end_angle, anticlockwise);
  }

  if (!radius || start_angle == end_angle) [[unlikely]] {
    // The arc is empty but we still need to draw the connecting line.
    lineTo(x + radius * cosf(start_angle), y + radius * sinf(start_angle));
    return;
  }

  CanonicalizeAngle(&start_angle, &end_angle);
  end_angle = AdjustEndAngle(start_angle, end_angle, anticlockwise);

  // TODO(348683485): small arcs don't render as well with ganesh. Use
  // old code path in this case.
  if (IsEmpty() && RuntimeEnabledFeatures::CanvasUsesArcPaintOpEnabled() &&
      radius >= 1) {
    const float sweep_angle = end_angle - start_angle;
    arc_builder_.ArcTo(x, y, radius, start_angle, sweep_angle);
    DCHECK(IsArc());
    return;
  }

  path_.AddArc(gfx::PointF(x, y), radius, start_angle, end_angle);
}

void CanvasPath::ellipse(double double_x,
                         double double_y,
                         double double_radius_x,
                         double double_radius_y,
                         double double_rotation,
                         double double_start_angle,
                         double double_end_angle,
                         bool anticlockwise,
                         ExceptionState& exception_state) {
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  float radius_x = base::saturated_cast<float>(double_radius_x);
  float radius_y = base::saturated_cast<float>(double_radius_y);
  float rotation = base::saturated_cast<float>(double_rotation);
  float start_angle = base::saturated_cast<float>(double_start_angle);
  float end_angle = base::saturated_cast<float>(double_end_angle);
  if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(radius_x) ||
      !std::isfinite(radius_y) || !std::isfinite(rotation) ||
      !std::isfinite(start_angle) || !std::isfinite(end_angle)) [[unlikely]] {
    return;
  }

  if (radius_x < 0) [[unlikely]] {
    exception_state.ThrowDOMException(DOMExceptionCode::kIndexSizeError,
                                      "The major-axis radius provided (" +
                                          String::Number(radius_x) +
                                          ") is negative.");
    return;
  }
  if (radius_y < 0) [[unlikely]] {
    exception_state.ThrowDOMException(DOMExceptionCode::kIndexSizeError,
                                      "The minor-axis radius provided (" +
                                          String::Number(radius_y) +
                                          ") is negative.");
    return;
  }

  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kEllipse, double_x, double_y, double_radius_x,
        double_radius_y, double_rotation, double_start_angle, double_end_angle,
        anticlockwise);
  }

  CanonicalizeAngle(&start_angle, &end_angle);
  float adjusted_end_angle =
      AdjustEndAngle(start_angle, end_angle, anticlockwise);
  if (!radius_x || !radius_y || start_angle == adjusted_end_angle)
      [[unlikely]] {
    // The ellipse is empty but we still need to draw the connecting line to
    // start point.
    DegenerateEllipse(this, x, y, radius_x, radius_y, rotation, start_angle,
                      adjusted_end_angle, anticlockwise);
    return;
  }

  path_.AddEllipse(gfx::PointF(x, y), radius_x, radius_y, rotation, start_angle,
                   adjusted_end_angle);
}

void CanvasPath::rect(double double_x,
                      double double_y,
                      double double_width,
                      double double_height) {
  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  float width = base::saturated_cast<float>(double_width);
  float height = base::saturated_cast<float>(double_height);
  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(width) ||
      !std::isfinite(height)) [[unlikely]] {
    return;
  }

  if (width == 0 && height == 0) {
    moveTo(x, y);
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kRect, double_x, double_y, double_width, double_height);
  }

  path_.AddRect(gfx::PointF(x, y), gfx::PointF(x + width, y + height));
}

void CanvasPath::roundRect(
    double double_x,
    double double_y,
    double double_width,
    double double_height,
    const HeapVector<Member<V8UnionDOMPointInitOrUnrestrictedDouble>>& radii,
    ExceptionState& exception_state) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DRoundRect);
  constexpr int kMaxRadii = 4;
  const int num_radii = radii.size();
  if (num_radii < 1 || num_radii > kMaxRadii) [[unlikely]] {
    exception_state.ThrowRangeError(
        String::Number(num_radii) +
        " radii provided. Between one and four radii are necessary.");
    return;
  }

  float x = base::saturated_cast<float>(double_x);
  float y = base::saturated_cast<float>(double_y);
  float width = base::saturated_cast<float>(double_width);
  float height = base::saturated_cast<float>(double_height);
  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(width) ||
      !std::isfinite(height)) [[unlikely]] {
    return;
  }
  UpdatePathFromLineOrArcIfNecessaryForMutation();
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();

  gfx::SizeF r[kMaxRadii];
  for (int i = 0; i < num_radii; ++i) {
    switch (radii[i]->GetContentType()) {
      case V8UnionDOMPointInitOrUnrestrictedDouble::ContentType::
          kDOMPointInit: {
        DOMPointInit* p = radii[i]->GetAsDOMPointInit();
        float r_x = base::saturated_cast<float>(p->x());
        float r_y = base::saturated_cast<float>(p->y());
        if (!std::isfinite(r_x) || !std::isfinite(r_y)) [[unlikely]] {
          return;
        }
        if (r_x < 0.0f) [[unlikely]] {
          exception_state.ThrowRangeError(
              "X-radius value " + String::Number(r_x) + " is negative.");
          return;
        }
        if (r_y < 0.0f) [[unlikely]] {
          exception_state.ThrowRangeError(
              "Y-radius value " + String::Number(r_y) + " is negative.");
          return;
        }
        r[i] = gfx::SizeF(base::saturated_cast<float>(p->x()),
                          base::saturated_cast<float>(p->y()));
        break;
      }
      case V8UnionDOMPointInitOrUnrestrictedDouble::ContentType::
          kUnrestrictedDouble: {
        float a =
            base::saturated_cast<float>(radii[i]->GetAsUnrestrictedDouble());
        if (!std::isfinite(a)) [[unlikely]] {
          return;
        }
        if (a < 0.0f) [[unlikely]] {
          exception_state.ThrowRangeError("Radius value " + String::Number(a) +
                                          " is negative.");
          return;
        }
        r[i] = gfx::SizeF(a, a);
        break;
      }
    }
  }

  if (width == 0 || height == 0) [[unlikely]] {
    // AddRoundRect does not handle flat rects, correctly.  But since there are
    // no rounded corners on a flat rect, we can just use AddRect.
    path_.AddRect(gfx::PointF(x, y), gfx::PointF(x + width, y + height));
    return;
  }

  gfx::SizeF corner_radii[4];  // row-wise ordering
  switch (num_radii) {
    case 1:
      corner_radii[0] = corner_radii[1] = corner_radii[2] = corner_radii[3] =
          r[0];
      break;
    case 2:
      corner_radii[0] = corner_radii[3] = r[0];
      corner_radii[1] = corner_radii[2] = r[1];
      break;
    case 3:
      corner_radii[0] = r[0];
      corner_radii[1] = corner_radii[2] = r[1];
      corner_radii[3] = r[2];
      break;
    case 4:
      corner_radii[0] = r[0];
      corner_radii[1] = r[1];
      corner_radii[2] = r[3];
      corner_radii[3] = r[2];
  }

  bool clockwise = true;
  if (width < 0) [[unlikely]] {
    // Horizontal flip
    clockwise = false;
    x += width;
    width = -width;
    using std::swap;
    swap(corner_radii[0], corner_radii[1]);
    swap(corner_radii[2], corner_radii[3]);
  }

  if (height < 0) [[unlikely]] {
    // Vertical flip
    clockwise = !clockwise;
    y += height;
    height = -height;
    using std::swap;
    swap(corner_radii[0], corner_radii[2]);
    swap(corner_radii[1], corner_radii[3]);
  }

  gfx::RectF rect(x, y, width, height);
  path_.AddRoundedRect(FloatRoundedRect(rect, corner_radii[0], corner_radii[1],
                                        corner_radii[2], corner_radii[3]),
                       clockwise);
  path_.MoveTo(gfx::PointF(x, y));
}

void CanvasPath::roundRect(
    double double_x,
    double double_y,
    double double_width,
    double double_height,
    const Member<V8UnionDOMPointInitOrUnrestrictedDouble>& radius,
    ExceptionState& exception_state) {
  const auto radii =
      HeapVector<Member<V8UnionDOMPointInitOrUnrestrictedDouble>>(1, radius);
  roundRect(double_x, double_y, double_width, double_height, radii,
            exception_state);
}

gfx::RectF CanvasPath::BoundingRect() const {
  if (!line_builder_.IsEmpty()) {
    return line_builder_.BoundingRect();
  } else if (IsArc()) {
    return arc_builder_.BoundingRect();
  }
  return path_.BoundingRect();
}

void CanvasPath::Trace(Visitor* visitor) const {
  visitor->Trace(identifiability_study_helper_);
}

ALWAYS_INLINE gfx::RectF CanvasPath::LineBuilder::BoundingRect() const {
  DCHECK_NE(state_, State::kEmpty);
  if (state_ == State::kStartingPoint) {
    return gfx::BoundingRect(line_.start, line_.start);
  }
  return gfx::BoundingRect(line_.start, line_.end);
}

ALWAYS_INLINE gfx::RectF CanvasPath::ArcBuilder::BoundingRect() const {
  DCHECK_NE(state_, State::kEmpty);
  return gfx::BoundingRect(
      gfx::PointF(arc_.x - arc_.radius, arc_.y - arc_.radius),
      gfx::PointF(arc_.x + arc_.radius, arc_.y + arc_.radius));
}

ALWAYS_INLINE void CanvasPath::ArcBuilder::UpdatePath(Path& path) const {
  DCHECK_NE(state_, State::kEmpty);
  path.AddArc(gfx::PointF(arc_.x, arc_.y), arc_.radius,
              arc_.start_angle_radians,
              arc_.start_angle_radians + arc_.sweep_angle_radians);
  if (state_ == State::kClosed) {
    path.CloseSubpath();
  }
}

void CanvasPath::UpdatePathFromLineOrArcIfNecessary() const {
  if (!DoesPathNeedUpdatingFromLineOrArc()) {
    return;
  }
  DCHECK(path_.IsEmpty());
  if (!line_builder_.IsEmpty()) {
    // There is a starting point, but possibly no ending point.
    path_.MoveTo(line_builder_.starting_point());
    if (IsLine()) {
      path_.AddLineTo(line_builder_.ending_point());
    }
  } else {
    DCHECK(!arc_builder_.IsEmpty());
    arc_builder_.UpdatePath(path_);
  }
}

void CanvasPath::UpdatePathFromLineOrArcIfNecessaryForMutation() {
  UpdatePathFromLineOrArcIfNecessary();
  line_builder_.Clear();
  arc_builder_.Clear();
}

}  // namespace blink

"""

```