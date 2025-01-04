Response:
Let's break down the thought process for analyzing the `logging_canvas.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies, logical reasoning examples, and potential user/programming errors.

2. **Initial Scan for Keywords:**  Immediately look for terms that hint at the file's purpose. Keywords like "logging," "canvas," "JSON," and graphics-related terms like "Skia," "Paint," "Rect," "Path," etc., jump out. The namespace `blink` also confirms it's part of the Chromium rendering engine.

3. **Infer Primary Function:**  The name `LoggingCanvas` strongly suggests this class is a specialized `SkCanvas` that *records* or *logs* the drawing operations performed on it. The inclusion of JSON-related code points towards structured logging.

4. **Identify Key Classes and Data Structures:**
    * `LoggingCanvas`: The core class, inheriting from `InterceptingCanvasBase`. This indicates it intercepts standard canvas drawing calls.
    * `AutoLogger`: A helper class used within each drawing method to automate the logging process. Its constructor/destructor behavior is key to understanding how each log entry is created.
    * `JSONArray`, `JSONObject`:  These are used to build the structured log output in JSON format.
    * Skia types (`SkPaint`, `SkRect`, `SkPath`, `SkImage`, etc.):  These represent the fundamental drawing primitives.

5. **Analyze Individual Methods (and the `AutoLogger` interaction):**  Go through the `LoggingCanvas` methods like `onDrawRect`, `onDrawPath`, `onDrawImage`, etc. Notice the consistent pattern:
    * An `AutoLogger` instance is created at the beginning of each method.
    * `logger.LogItemWithParams("methodName")` is called to create a JSON object with the method name.
    * Parameters of the drawing call are converted into JSON objects (using helper functions like `ObjectForSkRect`, `ObjectForSkPaint`, etc.) and added to the "params" object.
    * The original `SkCanvas` method is then called (e.g., `SkCanvas::onDrawRect(...)`).
    * The `AutoLogger`'s destructor is called, which pushes the completed JSON object onto the `log_`.

6. **Examine Helper Functions:**  The numerous `ObjectFor...` functions are crucial. They demonstrate how Skia objects are translated into JSON representations. Pay attention to the details:
    * Extracting individual properties (left, top, width, height for rectangles).
    * Handling different types within Skia (e.g., different `SkPath::Verb` types).
    * Converting enums to string representations (e.g., `PointModeName`, `FillTypeName`).

7. **Connect to Web Technologies:** Now, think about how these drawing operations relate to the web:
    * **`<canvas>` element:** The most direct connection. JavaScript drawing commands on a `<canvas>` ultimately translate into Skia calls. The `LoggingCanvas` acts as an intermediary, capturing those calls.
    * **CSS:**  CSS can influence the rendering on a canvas, for example, through transformations applied to the canvas element or parent elements. This translates to matrix operations (`didSetM44`, `didConcat44`, `didScale`, `didTranslate`). CSS styling also impacts paint properties (color, stroke, etc.).
    * **HTML:** The `<canvas>` element itself is part of the HTML structure. Images drawn onto the canvas originate from HTML `<img>` tags or other sources. Text drawn on the canvas reflects content that might originate from HTML.
    * **JavaScript:** JavaScript is the primary way to interact with the `<canvas>` API. JavaScript functions like `fillRect()`, `beginPath()`, `drawImage()`, etc., directly correspond to the logged methods.

8. **Formulate Examples:**  Based on the connections, construct concrete examples:
    * JavaScript drawing a rectangle leads to a `drawRect` log entry.
    * CSS scaling leads to a `scale` log entry.
    * Drawing an image from an `<img>` tag results in a `drawImage` log entry with image dimensions.

9. **Consider Logical Reasoning:** The core logic is the interception and structured logging. Think about a sequence of operations and the resulting log output. A simple sequence like drawing a rectangle, then a circle, then translating the canvas would produce a predictable JSON array of log entries.

10. **Identify Potential Errors:** Think about common mistakes when working with the Canvas API or debugging rendering:
    * Incorrect coordinates: Leads to misaligned drawings, which the log can help diagnose.
    * Wrong paint settings: Incorrect colors, stroke widths, etc., will be reflected in the paint object within the log.
    * Missing `save()`/`restore()` calls: Can lead to unexpected transformations being applied, and the `save` and `restore` log entries can help pinpoint this.

11. **Structure the Answer:** Organize the findings into the requested categories: functionality, relationship to web technologies, logical reasoning, and common errors. Use clear and concise language, providing specific examples where possible.

12. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have just said "logs canvas operations," but refining it to "records canvas drawing operations as structured JSON objects" is more precise. Also, ensuring the examples clearly illustrate the connection to web technologies is important.
`blink/renderer/platform/graphics/logging_canvas.cc` 文件定义了一个名为 `LoggingCanvas` 的类，这个类继承自 `InterceptingCanvasBase`，它的主要功能是**记录（log）所有在其上执行的绘图操作及其参数，并将这些记录以结构化的 JSON 格式输出**。  它的主要目的是用于调试、测试和分析 Canvas 的绘图过程。

以下是 `LoggingCanvas` 的具体功能及其与 JavaScript、HTML、CSS 关系的说明：

**主要功能:**

1. **拦截 Canvas 绘图调用:**  `LoggingCanvas` 重写了 `SkCanvas` 的许多绘图方法（例如 `drawRect`, `drawPath`, `drawImage` 等）。当在 `LoggingCanvas` 实例上执行绘图操作时，实际上是调用了 `LoggingCanvas` 中重写的方法。
2. **记录方法名和参数:**  在每个被重写的绘图方法中，`LoggingCanvas` 会记录被调用的方法名以及该方法接收到的所有参数。这些参数包括几何形状（例如矩形的坐标、路径的点）、画笔属性（颜色、线条粗细、样式）、图像数据、变换矩阵等。
3. **将记录转换为 JSON 格式:**  `LoggingCanvas` 使用 JSON 对象来存储记录。每个绘图操作被记录为一个 JSON 对象，其中包含一个 "method" 字段表示方法名，以及一个 "params" 字段，其值为一个包含所有参数的 JSON 对象。
4. **提供获取日志的方法:**  `LoggingCanvas` 提供了 `Log()` 方法，用于返回一个包含所有记录的 JSON 数组。
5. **辅助函数用于将 Skia 对象转换为 JSON:** 文件中包含许多辅助函数（例如 `ObjectForSkRect`, `ObjectForSkPaint`, `ObjectForSkPath` 等），用于将 Skia 库中的图形对象转换为易于理解和存储的 JSON 格式。

**与 JavaScript, HTML, CSS 的关系:**

`LoggingCanvas` 位于 Blink 渲染引擎的底层图形处理部分，它与前端技术通过以下方式相关联：

* **JavaScript `<canvas>` API:**  JavaScript 代码通过 `<canvas>` 元素的 2D 渲染上下文（`CanvasRenderingContext2D`）或 WebGL 渲染上下文执行绘图操作。  当使用 2D 上下文时，JavaScript 调用如 `fillRect()`, `beginPath()`, `drawImage()` 等最终会转化为对底层图形库（Skia，`LoggingCanvas` 就是基于 Skia 的）的调用。 `LoggingCanvas` 正是拦截和记录这些底层 Skia 调用。

   **举例说明:**

   ```javascript
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   ctx.fillStyle = 'red';
   ctx.fillRect(10, 10, 100, 50);
   ```

   当这段 JavaScript 代码执行时，如果渲染引擎内部使用了 `LoggingCanvas`，那么 `fillRect` 的调用会被拦截，并在日志中产生类似以下的 JSON 记录：

   ```json
   {
     "method": "drawRect",
     "params": {
       "rect": {
         "left": 10,
         "top": 10,
         "right": 110,
         "bottom": 60
       },
       "paint": {
         "color": "#FFFF0000", // Red的十六进制表示
         "styleName": "Fill"
         // ... 其他 paint 属性
       }
     }
   }
   ```

* **HTML `<canvas>` 元素:** `LoggingCanvas` 作用于 `<canvas>` 元素上绘制的内容。HTML 定义了 `<canvas>` 元素，JavaScript 则控制在这个元素上的绘制。`LoggingCanvas` 记录的是由 JavaScript 在 `<canvas>` 上产生的绘图指令。

* **CSS 影响 Canvas 的渲染:** CSS 可以通过变换（transform）、透明度（opacity）、裁剪（clip-path）等属性影响 `<canvas>` 元素的渲染结果。这些 CSS 属性最终会转化为图形操作。  例如，当 CSS 对 `<canvas>` 应用了 `transform: scale(2)` 时，`LoggingCanvas` 会记录相应的缩放操作。

   **举例说明:**

   ```html
   <canvas id="myCanvas" style="transform: scale(2);"></canvas>
   ```

   如果 JavaScript 在此 canvas 上绘制，`LoggingCanvas` 可能会记录类似于以下的变换操作：

   ```json
   {
     "method": "scale",
     "params": {
       "scaleX": 2,
       "scaleY": 2
     }
   }
   ```

**逻辑推理的例子 (假设输入与输出):**

假设 JavaScript 代码在 Canvas 上绘制一个红色圆和一个蓝色矩形：

**假设输入 (JavaScript):**

```javascript
const canvas = document.getElementById('myCanvas');
const ctx = canvas.getContext('2d');

// 绘制红色圆
ctx.fillStyle = 'red';
ctx.beginPath();
ctx.arc(50, 50, 30, 0, 2 * Math.PI);
ctx.fill();

// 绘制蓝色矩形
ctx.fillStyle = 'blue';
ctx.fillRect(100, 10, 80, 40);
```

**逻辑推理:**  `LoggingCanvas` 会拦截 `arc` 和 `fillRect` 的调用，并记录其参数。

**预期输出 (JSON):**

```json
[
  {
    "method": "drawPath",
    "params": {
      "path": {
        "fillType": "Winding",
        "convex": true,
        "isRect": false,
        "pathPoints": [
          {
            "verb": "Move",
            "points": [
              { "x": 80, "y": 50 }
            ]
          },
          {
            "verb": "Arc", // 注意：这里实际会更复杂，表示圆弧的控制点
            "points": [
              { "x": 50, "y": 20 },
              { "x": 20, "y": 50 }
            ]
          },
          // ... 其他构成圆弧的点
          {
            "verb": "Close",
            "points": []
          }
        ],
        "bounds": { "left": 20, "top": 20, "right": 80, "bottom": 80 }
      },
      "paint": {
        "color": "#FFFF0000", // Red
        "styleName": "Fill"
        // ...
      }
    }
  },
  {
    "method": "drawRect",
    "params": {
      "rect": {
        "left": 100,
        "top": 10,
        "right": 180,
        "bottom": 50
      },
      "paint": {
        "color": "#FF0000FF", // Blue
        "styleName": "Fill"
        // ...
      }
    }
  }
]
```

**用户或编程常见的使用错误 (导致日志不准确或无法记录):**

1. **没有将 `LoggingCanvas` 注入到渲染流程:** `LoggingCanvas` 本身不会自动生效。需要将其作为实际执行绘图操作的 `SkCanvas` 的替代品注入到 Blink 的渲染管线中。如果开发者没有正确配置，那么实际执行的仍然是默认的 `SkCanvas`，不会产生任何日志。
2. **假设日志会包含高级 Canvas API 信息:**  `LoggingCanvas` 记录的是底层的 Skia 调用。  例如，JavaScript 的 `arc()` 方法在底层会被分解成一系列的曲线绘制指令。日志中不会直接显示 `arc()` 调用，而是显示构成圆弧的 `Move`, `Cubic` 等 Skia Path 的动词。 用户可能会期望看到更高级别的 API 调用，但实际看到的是更底层的操作。
3. **误解日志输出的格式:**  日志输出是结构化的 JSON。如果用户期望的是简单的文本输出，或者不理解 JSON 格式，可能会难以解析和使用日志信息。
4. **性能开销:**  记录所有的绘图操作会带来一定的性能开销。如果在生产环境中错误地启用了 `LoggingCanvas`，可能会影响页面性能。这更像是一个部署错误，而不是 `LoggingCanvas` 本身的使用错误。
5. **日志信息过于冗余:** 对于复杂的 Canvas 动画或图形，`LoggingCanvas` 可能会产生大量的日志信息，使得分析变得困难。用户可能需要使用工具或编写脚本来过滤和分析这些日志。

总之，`blink/renderer/platform/graphics/logging_canvas.cc` 提供了一个强大的工具，用于深入了解 Blink 渲染引擎如何执行 Canvas 绘图操作，这对于调试渲染问题、理解图形性能瓶颈以及进行自动化测试非常有价值。但是，正确配置和理解其输出是有效使用它的关键。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/logging_canvas.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/logging_canvas.h"

#include <unicode/unistr.h>

#include "base/logging.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/image-encoders/image_encoder.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkPaint.h"
#include "third_party/skia/include/core/SkPath.h"
#include "third_party/skia/include/core/SkRRect.h"
#include "third_party/skia/include/core/SkRect.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

struct VerbParams {
  STACK_ALLOCATED();

 public:
  String name;
  unsigned point_count;
  unsigned point_offset;

  VerbParams(const String& name, unsigned point_count, unsigned point_offset)
      : name(name), point_count(point_count), point_offset(point_offset) {}
};

std::unique_ptr<JSONObject> ObjectForSkRect(const SkRect& rect) {
  auto rect_item = std::make_unique<JSONObject>();
  rect_item->SetDouble("left", rect.left());
  rect_item->SetDouble("top", rect.top());
  rect_item->SetDouble("right", rect.right());
  rect_item->SetDouble("bottom", rect.bottom());
  return rect_item;
}

String PointModeName(SkCanvas::PointMode mode) {
  switch (mode) {
    case SkCanvas::kPoints_PointMode:
      return "Points";
    case SkCanvas::kLines_PointMode:
      return "Lines";
    case SkCanvas::kPolygon_PointMode:
      return "Polygon";
    default:
      NOTREACHED();
  };
}

std::unique_ptr<JSONObject> ObjectForSkPoint(const SkPoint& point) {
  auto point_item = std::make_unique<JSONObject>();
  point_item->SetDouble("x", point.x());
  point_item->SetDouble("y", point.y());
  return point_item;
}

std::unique_ptr<JSONArray> ArrayForSkPoints(size_t count,
                                            const SkPoint points[]) {
  auto points_array_item = std::make_unique<JSONArray>();
  for (size_t i = 0; i < count; ++i)
    points_array_item->PushObject(ObjectForSkPoint(points[i]));
  return points_array_item;
}

std::unique_ptr<JSONObject> ObjectForRadius(const SkRRect& rrect,
                                            SkRRect::Corner corner) {
  auto radius_item = std::make_unique<JSONObject>();
  SkVector radius = rrect.radii(corner);
  radius_item->SetDouble("xRadius", radius.x());
  radius_item->SetDouble("yRadius", radius.y());
  return radius_item;
}

String RrectTypeName(SkRRect::Type type) {
  switch (type) {
    case SkRRect::kEmpty_Type:
      return "Empty";
    case SkRRect::kRect_Type:
      return "Rect";
    case SkRRect::kOval_Type:
      return "Oval";
    case SkRRect::kSimple_Type:
      return "Simple";
    case SkRRect::kNinePatch_Type:
      return "Nine-patch";
    case SkRRect::kComplex_Type:
      return "Complex";
    default:
      NOTREACHED();
  };
}

String RadiusName(SkRRect::Corner corner) {
  switch (corner) {
    case SkRRect::kUpperLeft_Corner:
      return "upperLeftRadius";
    case SkRRect::kUpperRight_Corner:
      return "upperRightRadius";
    case SkRRect::kLowerRight_Corner:
      return "lowerRightRadius";
    case SkRRect::kLowerLeft_Corner:
      return "lowerLeftRadius";
    default:
      NOTREACHED();
  }
}

std::unique_ptr<JSONObject> ObjectForSkRRect(const SkRRect& rrect) {
  auto rrect_item = std::make_unique<JSONObject>();
  rrect_item->SetString("type", RrectTypeName(rrect.type()));
  rrect_item->SetDouble("left", rrect.rect().left());
  rrect_item->SetDouble("top", rrect.rect().top());
  rrect_item->SetDouble("right", rrect.rect().right());
  rrect_item->SetDouble("bottom", rrect.rect().bottom());
  for (int i = 0; i < 4; ++i)
    rrect_item->SetObject(RadiusName((SkRRect::Corner)i),
                          ObjectForRadius(rrect, (SkRRect::Corner)i));
  return rrect_item;
}

String FillTypeName(SkPathFillType type) {
  switch (type) {
    case SkPathFillType::kWinding:
      return "Winding";
    case SkPathFillType::kEvenOdd:
      return "EvenOdd";
    case SkPathFillType::kInverseWinding:
      return "InverseWinding";
    case SkPathFillType::kInverseEvenOdd:
      return "InverseEvenOdd";
    default:
      NOTREACHED();
  };
}

VerbParams SegmentParams(SkPath::Verb verb) {
  switch (verb) {
    case SkPath::kMove_Verb:
      return VerbParams("Move", 1, 0);
    case SkPath::kLine_Verb:
      return VerbParams("Line", 1, 1);
    case SkPath::kQuad_Verb:
      return VerbParams("Quad", 2, 1);
    case SkPath::kConic_Verb:
      return VerbParams("Conic", 2, 1);
    case SkPath::kCubic_Verb:
      return VerbParams("Cubic", 3, 1);
    case SkPath::kClose_Verb:
      return VerbParams("Close", 0, 0);
    case SkPath::kDone_Verb:
      return VerbParams("Done", 0, 0);
    default:
      NOTREACHED();
  };
}

std::unique_ptr<JSONObject> ObjectForSkPath(const SkPath& path) {
  auto path_item = std::make_unique<JSONObject>();
  path_item->SetString("fillType", FillTypeName(path.getFillType()));
  path_item->SetBoolean("convex", path.isConvex());
  path_item->SetBoolean("isRect", path.isRect(nullptr));
  SkPath::RawIter iter(path);
  SkPoint points[4];
  auto path_points_array = std::make_unique<JSONArray>();
  for (SkPath::Verb verb = iter.next(points); verb != SkPath::kDone_Verb;
       verb = iter.next(points)) {
    VerbParams verb_params = SegmentParams(verb);
    auto path_point_item = std::make_unique<JSONObject>();
    path_point_item->SetString("verb", verb_params.name);
    DCHECK_LE(verb_params.point_count + verb_params.point_offset,
              std::size(points));
    path_point_item->SetArray(
        "points", ArrayForSkPoints(verb_params.point_count,
                                   points + verb_params.point_offset));
    if (SkPath::kConic_Verb == verb)
      path_point_item->SetDouble("conicWeight", iter.conicWeight());
    path_points_array->PushObject(std::move(path_point_item));
  }
  path_item->SetArray("pathPoints", std::move(path_points_array));
  path_item->SetObject("bounds", ObjectForSkRect(path.getBounds()));
  return path_item;
}

std::unique_ptr<JSONObject> ObjectForSkImage(const SkImage* image) {
  auto image_item = std::make_unique<JSONObject>();
  image_item->SetInteger("width", image->width());
  image_item->SetInteger("height", image->height());
  image_item->SetBoolean("opaque", image->isOpaque());
  image_item->SetInteger("uniqueID", image->uniqueID());
  return image_item;
}

std::unique_ptr<JSONArray> ArrayForSkScalars(size_t count,
                                             const SkScalar array[]) {
  auto points_array_item = std::make_unique<JSONArray>();
  for (size_t i = 0; i < count; ++i)
    points_array_item->PushDouble(array[i]);
  return points_array_item;
}

std::unique_ptr<JSONObject> ObjectForSkShader(const SkShader& shader) {
  return std::make_unique<JSONObject>();
}

String StringForSkColor(SkColor color) {
  // #AARRGGBB.
  return String::Format("#%08X", color);
}

void AppendFlagToString(StringBuilder* flags_string,
                        bool is_set,
                        const StringView& name) {
  if (!is_set)
    return;
  if (flags_string->length())
    flags_string->Append("|");
  flags_string->Append(name);
}

String StringForSkPaintFlags(const SkPaint& paint) {
  if (!paint.isAntiAlias() && !paint.isDither())
    return "none";
  StringBuilder flags_string;
  AppendFlagToString(&flags_string, paint.isAntiAlias(), "AntiAlias");
  AppendFlagToString(&flags_string, paint.isDither(), "Dither");
  return flags_string.ToString();
}

String StrokeCapName(SkPaint::Cap cap) {
  switch (cap) {
    case SkPaint::kButt_Cap:
      return "Butt";
    case SkPaint::kRound_Cap:
      return "Round";
    case SkPaint::kSquare_Cap:
      return "Square";
    default:
      NOTREACHED();
  };
}

String StrokeJoinName(SkPaint::Join join) {
  switch (join) {
    case SkPaint::kMiter_Join:
      return "Miter";
    case SkPaint::kRound_Join:
      return "Round";
    case SkPaint::kBevel_Join:
      return "Bevel";
    default:
      NOTREACHED();
  };
}

String StyleName(SkPaint::Style style) {
  switch (style) {
    case SkPaint::kFill_Style:
      return "Fill";
    case SkPaint::kStroke_Style:
      return "Stroke";
    default:
      NOTREACHED();
  };
}

std::unique_ptr<JSONObject> ObjectForSkPaint(const SkPaint& paint) {
  auto paint_item = std::make_unique<JSONObject>();
  if (SkShader* shader = paint.getShader())
    paint_item->SetObject("shader", ObjectForSkShader(*shader));
  paint_item->SetString("color", StringForSkColor(paint.getColor()));
  paint_item->SetDouble("strokeWidth", paint.getStrokeWidth());
  paint_item->SetDouble("strokeMiter", paint.getStrokeMiter());
  paint_item->SetString("flags", StringForSkPaintFlags(paint));
  paint_item->SetString("strokeCap", StrokeCapName(paint.getStrokeCap()));
  paint_item->SetString("strokeJoin", StrokeJoinName(paint.getStrokeJoin()));
  paint_item->SetString("styleName", StyleName(paint.getStyle()));
  const auto bm = paint.asBlendMode();
  if (bm != SkBlendMode::kSrcOver) {
    paint_item->SetString("blendMode",
                          bm ? SkBlendMode_Name(bm.value()) : "custom");
  }
  if (paint.getImageFilter())
    paint_item->SetString("imageFilter", "SkImageFilter");
  return paint_item;
}

String ClipOpName(SkClipOp op) {
  switch (op) {
    case SkClipOp::kDifference:
      return "kDifference_Op";
    case SkClipOp::kIntersect:
      return "kIntersect_Op";
    default:
      return "Unknown type";
  };
}

String FilterModeName(SkFilterMode fm) {
  switch (fm) {
    case SkFilterMode::kNearest:
      return "kNearest";
    case SkFilterMode::kLinear:
      return "kLinear";
  }
  return "not reachable";
}

String MipmapModeName(SkMipmapMode mm) {
  switch (mm) {
    case SkMipmapMode::kNone:
      return "kNone";
    case SkMipmapMode::kNearest:
      return "kNearest";
    case SkMipmapMode::kLinear:
      return "kLinear";
  }
  return "not reachable";
}

std::unique_ptr<JSONObject> ObjectForSkSamplingOptions(
    const SkSamplingOptions& sampling) {
  auto sampling_item = std::make_unique<JSONObject>();
  if (sampling.useCubic) {
    sampling_item->SetDouble("B", sampling.cubic.B);
    sampling_item->SetDouble("C", sampling.cubic.C);
  } else {
    sampling_item->SetString("filter", FilterModeName(sampling.filter));
    sampling_item->SetString("mipmap", MipmapModeName(sampling.mipmap));
  }
  return sampling_item;
}

}  // namespace

class AutoLogger
    : InterceptingCanvasBase::CanvasInterceptorBase<LoggingCanvas> {
 public:
  explicit AutoLogger(LoggingCanvas* canvas)
      : InterceptingCanvasBase::CanvasInterceptorBase<LoggingCanvas>(canvas) {}

  JSONObject* LogItem(const String& name);
  JSONObject* LogItemWithParams(const String& name);
  ~AutoLogger() {
    if (TopLevelCall())
      Canvas()->log_->PushObject(std::move(log_item_));
  }

 private:
  std::unique_ptr<JSONObject> log_item_;
};

JSONObject* AutoLogger::LogItem(const String& name) {
  auto item = std::make_unique<JSONObject>();
  item->SetString("method", name);
  log_item_ = std::move(item);
  return log_item_.get();
}

JSONObject* AutoLogger::LogItemWithParams(const String& name) {
  JSONObject* item = LogItem(name);
  auto params = std::make_unique<JSONObject>();
  item->SetObject("params", std::move(params));
  return item->GetJSONObject("params");
}

LoggingCanvas::LoggingCanvas()
    : InterceptingCanvasBase(999999, 999999),
      log_(std::make_unique<JSONArray>()) {}

void LoggingCanvas::onDrawPaint(const SkPaint& paint) {
  AutoLogger logger(this);
  logger.LogItemWithParams("drawPaint")
      ->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawPaint(paint);
}

void LoggingCanvas::onDrawPoints(PointMode mode,
                                 size_t count,
                                 const SkPoint pts[],
                                 const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawPoints");
  params->SetString("pointMode", PointModeName(mode));
  params->SetArray("points", ArrayForSkPoints(count, pts));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawPoints(mode, count, pts, paint);
}

void LoggingCanvas::onDrawRect(const SkRect& rect, const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawRect");
  params->SetObject("rect", ObjectForSkRect(rect));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawRect(rect, paint);
}

void LoggingCanvas::onDrawOval(const SkRect& oval, const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawOval");
  params->SetObject("oval", ObjectForSkRect(oval));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawOval(oval, paint);
}

void LoggingCanvas::onDrawRRect(const SkRRect& rrect, const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawRRect");
  params->SetObject("rrect", ObjectForSkRRect(rrect));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawRRect(rrect, paint);
}

void LoggingCanvas::onDrawPath(const SkPath& path, const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawPath");
  params->SetObject("path", ObjectForSkPath(path));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawPath(path, paint);
}

void LoggingCanvas::onDrawImage2(const SkImage* image,
                                 SkScalar left,
                                 SkScalar top,
                                 const SkSamplingOptions& sampling,
                                 const SkPaint* paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawImage");
  params->SetDouble("left", left);
  params->SetDouble("top", top);
  params->SetObject("sampling", ObjectForSkSamplingOptions(sampling));
  params->SetObject("image", ObjectForSkImage(image));
  if (paint)
    params->SetObject("paint", ObjectForSkPaint(*paint));
  SkCanvas::onDrawImage2(image, left, top, sampling, paint);
}

void LoggingCanvas::onDrawImageRect2(const SkImage* image,
                                     const SkRect& src,
                                     const SkRect& dst,
                                     const SkSamplingOptions& sampling,
                                     const SkPaint* paint,
                                     SrcRectConstraint constraint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawImageRect");
  params->SetObject("image", ObjectForSkImage(image));
  params->SetObject("src", ObjectForSkRect(src));
  params->SetObject("dst", ObjectForSkRect(dst));
  params->SetObject("sampling", ObjectForSkSamplingOptions(sampling));
  if (paint)
    params->SetObject("paint", ObjectForSkPaint(*paint));
  SkCanvas::onDrawImageRect2(image, src, dst, sampling, paint, constraint);
}

void LoggingCanvas::onDrawVerticesObject(const SkVertices* vertices,
                                         SkBlendMode bmode,
                                         const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawVertices");
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawVerticesObject(vertices, bmode, paint);
}

void LoggingCanvas::onDrawDRRect(const SkRRect& outer,
                                 const SkRRect& inner,
                                 const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawDRRect");
  params->SetObject("outer", ObjectForSkRRect(outer));
  params->SetObject("inner", ObjectForSkRRect(inner));
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawDRRect(outer, inner, paint);
}

void LoggingCanvas::onDrawTextBlob(const SkTextBlob* blob,
                                   SkScalar x,
                                   SkScalar y,
                                   const SkPaint& paint) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("drawTextBlob");
  params->SetDouble("x", x);
  params->SetDouble("y", y);
  params->SetObject("paint", ObjectForSkPaint(paint));
  SkCanvas::onDrawTextBlob(blob, x, y, paint);
}

void LoggingCanvas::onClipRect(const SkRect& rect,
                               SkClipOp op,
                               ClipEdgeStyle style) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("clipRect");
  params->SetObject("rect", ObjectForSkRect(rect));
  params->SetString("SkRegion::Op", ClipOpName(op));
  params->SetBoolean("softClipEdgeStyle", kSoft_ClipEdgeStyle == style);
  SkCanvas::onClipRect(rect, op, style);
}

void LoggingCanvas::onClipRRect(const SkRRect& rrect,
                                SkClipOp op,
                                ClipEdgeStyle style) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("clipRRect");
  params->SetObject("rrect", ObjectForSkRRect(rrect));
  params->SetString("SkRegion::Op", ClipOpName(op));
  params->SetBoolean("softClipEdgeStyle", kSoft_ClipEdgeStyle == style);
  SkCanvas::onClipRRect(rrect, op, style);
}

void LoggingCanvas::onClipPath(const SkPath& path,
                               SkClipOp op,
                               ClipEdgeStyle style) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("clipPath");
  params->SetObject("path", ObjectForSkPath(path));
  params->SetString("SkRegion::Op", ClipOpName(op));
  params->SetBoolean("softClipEdgeStyle", kSoft_ClipEdgeStyle == style);
  SkCanvas::onClipPath(path, op, style);
}

void LoggingCanvas::onClipRegion(const SkRegion& region, SkClipOp op) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("clipRegion");
  params->SetString("op", ClipOpName(op));
  SkCanvas::onClipRegion(region, op);
}

void LoggingCanvas::onDrawPicture(const SkPicture* picture,
                                  const SkMatrix* matrix,
                                  const SkPaint* paint) {
  UnrollDrawPicture(picture, matrix, paint, nullptr);
}

void LoggingCanvas::didSetM44(const SkM44& matrix) {
  SkScalar m[16];
  matrix.getColMajor(m);
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("setMatrix");
  params->SetArray("matrix44", ArrayForSkScalars(16, m));
}

void LoggingCanvas::didConcat44(const SkM44& matrix) {
  SkScalar m[16];
  matrix.getColMajor(m);
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("concat44");
  params->SetArray("matrix44", ArrayForSkScalars(16, m));
}

void LoggingCanvas::didScale(SkScalar x, SkScalar y) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("scale");
  params->SetDouble("scaleX", x);
  params->SetDouble("scaleY", y);
}

void LoggingCanvas::didTranslate(SkScalar x, SkScalar y) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("translate");
  params->SetDouble("dx", x);
  params->SetDouble("dy", y);
}

void LoggingCanvas::willSave() {
  AutoLogger logger(this);
  logger.LogItem("save");
  SkCanvas::willSave();
}

SkCanvas::SaveLayerStrategy LoggingCanvas::getSaveLayerStrategy(
    const SaveLayerRec& rec) {
  AutoLogger logger(this);
  JSONObject* params = logger.LogItemWithParams("saveLayer");
  if (rec.fBounds)
    params->SetObject("bounds", ObjectForSkRect(*rec.fBounds));
  if (rec.fPaint)
    params->SetObject("paint", ObjectForSkPaint(*rec.fPaint));
  params->SetInteger("saveFlags", static_cast<int>(rec.fSaveLayerFlags));
  return SkCanvas::getSaveLayerStrategy(rec);
}

void LoggingCanvas::willRestore() {
  AutoLogger logger(this);
  logger.LogItem("restore");
  SkCanvas::willRestore();
}

std::unique_ptr<JSONArray> LoggingCanvas::Log() {
  return JSONArray::From(log_->Clone());
}

std::unique_ptr<JSONArray> RecordAsJSON(const PaintRecord& record) {
  LoggingCanvas canvas;
  record.Playback(&canvas);
  return canvas.Log();
}

String RecordAsDebugString(const PaintRecord& record) {
  return RecordAsJSON(record)->ToPrettyJSONString();
}

void ShowPaintRecord(const PaintRecord& record) {
  DLOG(INFO) << RecordAsDebugString(record).Utf8();
}

std::unique_ptr<JSONArray> SkPictureAsJSON(const SkPicture& picture) {
  LoggingCanvas canvas;
  picture.playback(&canvas);
  return canvas.Log();
}

String SkPictureAsDebugString(const SkPicture& picture) {
  return SkPictureAsJSON(picture)->ToPrettyJSONString();
}

void ShowSkPicture(const SkPicture& picture) {
  DLOG(INFO) << SkPictureAsDebugString(picture).Utf8();
}

}  // namespace blink

"""

```