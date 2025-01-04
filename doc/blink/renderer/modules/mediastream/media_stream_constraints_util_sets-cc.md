Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The primary goal is to understand the functionality of `media_stream_constraints_util_sets.cc` within the Chromium Blink engine and relate it to web technologies (JavaScript, HTML, CSS) where applicable. We also need to address debugging aspects and common errors.

2. **Initial Code Scan (High-Level):**
   - Notice the `#include` directives. This tells us the file depends on other modules, particularly `media_constraints.h` and `media_stream_constraints_util.h`. This hints at the file's purpose: dealing with constraints related to media streams.
   - See the namespace `blink::media_constraints`. This confirms the area of focus.
   - Observe the `ResolutionSet` and `Point` classes. These seem central to the file's functionality, likely representing video resolution parameters.
   - Spot functions like `MinDimensionFromConstraint`, `MaxAspectRatioFromConstraint`, `ComputeVertices`, and `SelectClosestPointToIdeal`. These suggest the file is about processing and manipulating media stream constraints.

3. **Focus on Key Classes and Functions:**

   - **`Point` Class:**
     - Represents a single resolution (height and width).
     - Has basic arithmetic operators (+, -, *).
     - Includes methods for calculating dot product, Euclidean distance, and finding the closest point on a segment. This strongly suggests geometric calculations related to resolution spaces.

   - **`ResolutionSet` Class:**
     - Represents a *range* of acceptable resolutions, defined by minimum and maximum height, width, and aspect ratio.
     - Has methods for checking if the set is empty, if it contains a specific point, finding the intersection with another `ResolutionSet`, and crucially, selecting the "best" resolution based on ideal values.
     - The `ComputeVertices` method is interesting. It suggests the `ResolutionSet` can be visualized as a polygon in the resolution space.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**

   - **JavaScript:** The most direct connection is the `getUserMedia` API. This is the standard way for web pages to request access to the user's camera and microphone. The *constraints* passed to `getUserMedia` are the user-facing representation of what this C++ code processes. We need to connect the C++ concepts (like `ResolutionSet`) to the JavaScript constraint structure.
   - **HTML:**  While this code doesn't directly manipulate the DOM, the *effects* of these constraints will be visible in `<video>` elements where the media stream is rendered. The chosen resolution impacts how the video looks.
   - **CSS:**  CSS can influence the *display* size of the `<video>` element, but it doesn't directly control the *resolution* of the underlying media stream. The connection is less direct but still present. For instance, if the browser chooses a low resolution due to constraints, and CSS stretches it, the video might appear pixelated.

5. **Logic and Examples (Hypothetical Inputs and Outputs):**

   - **`ResolutionSet::Intersection`:**  Imagine two constraint sets: one allowing heights 100-200 and widths 200-300, and another allowing heights 150-250 and widths 250-350. The intersection would be heights 150-200 and widths 250-300.
   - **`ResolutionSet::SelectClosestPointToIdeal`:**  If the ideal height is 480, but the allowed range is 360-720, and the ideal width is 640, this function would find the closest valid resolution point to (480, 640) within the defined `ResolutionSet`.

6. **User/Programming Errors:**

   - **Incorrect Constraints in JavaScript:** Providing contradictory or impossible constraints (e.g., `minWidth > maxWidth`) will lead to empty `ResolutionSet`s in the C++ code, potentially causing the `getUserMedia` call to fail or select an unexpected resolution.
   - **Typos in Constraint Names:**  JavaScript developers might misspell constraint names (`minWdith` instead of `minWidth`), which would be ignored by the browser.

7. **Debugging Workflow:**

   - **JavaScript Console Logging:**  Log the constraints being passed to `getUserMedia`.
   - **Browser Developer Tools (Internals):** Chromium often exposes internal pages (like `chrome://webrtc-internals/`) that show detailed information about WebRTC calls, including the negotiated media capabilities. This is a crucial tool.
   - **C++ Debugging (Advanced):** For developers working on the Chromium source, standard C++ debugging tools (like GDB or LLDB) can be used to step through the `media_stream_constraints_util_sets.cc` code, inspect variables, and understand how constraints are being processed. Setting breakpoints within this file would be a key step.

8. **Structure the Answer:** Organize the information logically:

   - Start with a concise summary of the file's purpose.
   - Detail the functionalities of the key classes.
   - Explain the relationship to web technologies with concrete examples.
   - Provide hypothetical input/output examples for key functions.
   - Describe common user/programming errors.
   - Outline the debugging process.

9. **Refine and Elaborate:**  Review the initial draft and add more detail and clarity. For example, explain *why* the `ResolutionSet` is treated as a polygon (to handle complex constraint combinations). Clarify the meaning of "ideal" constraints.

By following these steps, we can arrive at a comprehensive and accurate explanation of the `media_stream_constraints_util_sets.cc` file and its role in the Chromium Blink engine. The process involves a combination of code reading, conceptual understanding of WebRTC, and thinking like both a web developer and a Chromium developer.
这个C++源代码文件 `media_stream_constraints_util_sets.cc` 的主要功能是**处理和操作媒体流的约束集合**，特别是关于视频分辨率（高度、宽度）和宽高比的约束。它定义了一些工具类和函数，用于将 JavaScript 中 `getUserMedia` 等 API 传递的约束转换为内部表示，并进行逻辑运算，最终选择最符合要求的媒体轨道设置。

以下是其功能的详细列举：

**核心功能：**

1. **定义数据结构:**
   - **`Point` 类:**  表示一个二维点，用于表示视频分辨率的高度和宽度。提供了一些基本的数学运算，例如加减、点积、欧几里得距离，以及计算点到线段的最近点。
   - **`ResolutionSet` 类:** 表示允许的视频分辨率的集合。它由最小和最大高度、最小和最大宽度，以及最小和最大宽高比定义。可以将其理解为一个在分辨率空间中的矩形或多边形区域。

2. **约束解析与转换:**
   - **`FromConstraintSet` 函数:**  将 `MediaTrackConstraintSetPlatform` 类型的约束（通常是从 JavaScript 传递过来的）转换为 `ResolutionSet` 对象。这包括提取 `height`、`width` 和 `aspectRatio` 约束的最小值和最大值。
   - **`StringSetFromConstraint`、`BoolSetFromConstraint`、`RescaleSetFromConstraint` 函数:**  处理字符串、布尔值类型的约束，例如设备 ID、是否允许调整大小等。虽然这些函数不直接操作分辨率，但它们是处理媒体轨道约束的辅助工具。

3. **集合运算:**
   - **`Intersection` 函数:** 计算两个 `ResolutionSet` 的交集，返回一个新的 `ResolutionSet`，其中包含同时满足两个集合约束的范围。

4. **最佳分辨率选择:**
   - **`ContainsPoint` 函数:**  检查给定的分辨率 `Point` 是否在 `ResolutionSet` 定义的允许范围内。
   - **`SelectClosestPointToIdeal` 函数:**  核心函数，用于从 `ResolutionSet` 中选择最接近理想分辨率的 `Point`。理想分辨率可能由 `ideal` 约束指定。该函数会考虑各种情况，包括只有部分理想值的情况（例如，只有理想高度，或者只有理想宽高比）。
   - **`SelectClosestPointToIdealAspectRatio` 函数:**  辅助函数，当主要理想约束是宽高比时，选择最接近理想宽高比的分辨率。
   - **`ClosestPointTo` 函数:**  在 `ResolutionSet` 边界上或内部找到最接近给定目标分辨率的 `Point`。
   - **`ComputeVertices` 函数:**  计算 `ResolutionSet` 表示的多边形的顶点。这用于在 `ClosestPointTo` 等函数中寻找边界点。

**与 JavaScript, HTML, CSS 的关系：**

这个文件位于 Blink 渲染引擎中，直接参与处理 WebRTC 规范中定义的媒体约束。它与 JavaScript, HTML, CSS 的关系如下：

* **JavaScript:**
    - 当 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` API 请求访问用户的摄像头或麦克风时，可以传递一个 `constraints` 对象来指定需要的媒体轨道属性，例如期望的分辨率、帧率等。
    - `media_stream_constraints_util_sets.cc` 的代码负责接收并解析这些 JavaScript 传递的约束。
    - **举例：** JavaScript 代码可能包含如下约束：
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: { width: { min: 640, ideal: 1280 }, height: { min: 480, ideal: 720 } } })
      ```
      这里的 `width` 和 `height` 的 `min` 和 `ideal` 属性会被转换成 `ResolutionSet` 对象，用于指导浏览器选择合适的摄像头分辨率。

* **HTML:**
    - HTML 的 `<video>` 元素用于显示媒体流。`media_stream_constraints_util_sets.cc` 的目标是帮助浏览器选择合适的媒体流设置，这最终会影响 `<video>` 元素中显示的内容。
    - **举例：** 如果 JavaScript 约束要求高分辨率，并且 `media_stream_constraints_util_sets.cc` 成功地选择了一个高分辨率的摄像头设置，那么最终在 HTML 的 `<video>` 元素中呈现的视频会更清晰。

* **CSS:**
    - CSS 主要负责控制 HTML 元素的样式和布局，它可以改变 `<video>` 元素的显示尺寸，但**不能直接控制媒体流本身的属性，例如分辨率**。
    - **举例：** 即使 CSS 设置了 `<video>` 元素的宽度和高度，如果底层媒体流的分辨率很低，那么即使拉伸显示，视频质量仍然会很差。`media_stream_constraints_util_sets.cc` 的工作是在媒体流层面选择合适的设置，这为 CSS 的渲染提供了基础。

**逻辑推理与假设输入输出：**

假设 JavaScript 传递的约束如下：

```javascript
const constraints = {
  video: {
    width: { min: 640, max: 1920, ideal: 1280 },
    height: { min: 480, max: 1080, ideal: 720 },
    aspectRatio: { ideal: 16/9 }
  }
};
```

`ResolutionSet::FromConstraintSet` 函数接收到这些约束后，会创建一个 `ResolutionSet` 对象，其内部属性大致为：

* `min_width_ = 640`
* `max_width_ = 1920`
* `min_height_ = 480`
* `max_height_ = 1080`
* `min_aspect_ratio_` 会根据精度计算，接近 `480/1920`
* `max_aspect_ratio_` 会根据精度计算，接近 `1080/640`

然后，`SelectClosestPointToIdeal` 函数会根据 `ideal` 约束（宽度 1280，高度 720，宽高比 16/9）在这个 `ResolutionSet` 定义的范围内找到最接近的有效分辨率。

**假设输入:** `ResolutionSet` 对象如上所述，`default_height = 480`, `default_width = 640`。

**可能的输出:**  如果实际的摄像头支持 1280x720 分辨率，并且在该 `ResolutionSet` 的范围内，那么 `SelectClosestPointToIdeal` 可能会返回一个 `Point` 对象，其 `height_` 为 720，`width_` 为 1280。

**用户或编程常见的使用错误：**

1. **约束冲突:**  在 JavaScript 中设置了相互冲突的约束，例如 `minWidth: 1000` 和 `maxWidth: 500`。这会导致 `ResolutionSet` 为空，从而可能导致 `getUserMedia` 调用失败或选择到非预期的分辨率。
    - **例子：**
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: { width: { min: 1000, max: 500 } } }); // 错误：min 比 max 大
      ```

2. **类型错误:**  传递了错误类型的约束值。
    - **例子：**
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: { width: { min: "large" } } }); // 错误：min 应该是数字
      ```

3. **误解 `ideal` 约束:**  `ideal` 只是一个提示，浏览器会尽力满足，但不保证一定能选择到理想的分辨率。用户可能会期望设置了 `ideal` 就一定会得到那个分辨率。

4. **忘记处理 `getUserMedia` 的 Promise 失败:** 如果约束无法满足，`getUserMedia` 的 Promise 会 reject，开发者需要正确处理这种情况。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户打开一个网页，该网页使用了 WebRTC 技术 (例如，一个视频会议应用)。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 请求访问摄像头。**
3. **在 `getUserMedia()` 调用中，JavaScript 代码传递了一个包含视频约束的对象。**
4. **浏览器接收到这个请求，并将约束传递给 Blink 渲染引擎进行处理。**
5. **Blink 引擎内部，`MediaStreamDevice::EnumerateVideoCaptureFormats()` 或类似函数会收集可用的摄像头能力。**
6. **`media_stream_constraints_util_sets.cc` 中的 `FromConstraintSet` 函数被调用，将 JavaScript 的约束转换为内部的 `ResolutionSet` 对象。**
7. **`SelectClosestPointToIdeal` 等函数被调用，根据 `ResolutionSet` 和可用的摄像头能力，选择最佳的视频格式 (分辨率)。**
8. **浏览器最终使用选定的视频格式启动摄像头，并将媒体流返回给 JavaScript 代码。**
9. **JavaScript 代码将这个媒体流设置到 HTML 的 `<video>` 元素上进行显示。**

**调试线索：**

* **检查 JavaScript 代码中传递给 `getUserMedia()` 的约束对象是否正确。** 使用 `console.log()` 打印约束对象。
* **使用浏览器的开发者工具 (例如 Chrome 的 `chrome://webrtc-internals/`) 查看 WebRTC 的内部日志，特别是 "PeerConnection" 部分，可以查看约束处理和协商的详细信息。**
* **如果怀疑是 C++ 代码的问题，可能需要在 Blink 引擎的源代码中添加日志输出，例如在 `FromConstraintSet` 和 `SelectClosestPointToIdeal` 函数中打印变量的值，来跟踪约束的处理过程。** 这需要 Chromium 的开发环境。
* **检查实际的摄像头设备支持哪些分辨率。**  浏览器的 WebRTC 内部页面或操作系统提供的工具可能能查看摄像头的能力信息。

总而言之，`media_stream_constraints_util_sets.cc` 是 Blink 引擎中处理媒体流约束的关键组件，它负责将用户在 JavaScript 中定义的期望转化为浏览器内部可以理解和执行的指令，最终影响用户看到的媒体流效果。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_sets.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"

#include <cmath>

#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"

namespace blink {
namespace media_constraints {

using Point = ResolutionSet::Point;

namespace {

constexpr double kTolerance = 1e-5;

// Not perfect, but good enough for this application.
bool AreApproximatelyEqual(double d1, double d2) {
  if (std::fabs((d1 - d2)) <= kTolerance)
    return true;

  return d1 == d2 || (std::fabs((d1 - d2) / d1) <= kTolerance &&
                      std::fabs((d1 - d2) / d2) <= kTolerance);
}

bool IsLess(double d1, double d2) {
  return d1 < d2 && !AreApproximatelyEqual(d1, d2);
}

bool IsLessOrEqual(double d1, double d2) {
  return d1 < d2 || AreApproximatelyEqual(d1, d2);
}

bool IsGreater(double d1, double d2) {
  return d1 > d2 && !AreApproximatelyEqual(d1, d2);
}

bool IsGreaterOrEqual(double d1, double d2) {
  return d1 > d2 || AreApproximatelyEqual(d1, d2);
}

int ToValidDimension(int dimension) {
  if (dimension > ResolutionSet::kMaxDimension)
    return ResolutionSet::kMaxDimension;
  if (dimension < 0)
    return 0;

  return static_cast<int>(dimension);
}

int MinDimensionFromConstraint(const LongConstraint& constraint) {
  if (!ConstraintHasMin(constraint))
    return 0;

  return ToValidDimension(ConstraintMin(constraint));
}

int MaxDimensionFromConstraint(const LongConstraint& constraint) {
  if (!ConstraintHasMax(constraint))
    return ResolutionSet::kMaxDimension;

  return ToValidDimension(ConstraintMax(constraint));
}

double ToValidAspectRatio(double aspect_ratio) {
  return aspect_ratio < 0.0 ? 0.0 : aspect_ratio;
}

double MinAspectRatioFromConstraint(const DoubleConstraint& constraint) {
  if (!ConstraintHasMin(constraint))
    return 0.0;

  return ToValidAspectRatio(ConstraintMin(constraint));
}

double MaxAspectRatioFromConstraint(const DoubleConstraint& constraint) {
  if (!ConstraintHasMax(constraint))
    return HUGE_VAL;

  return ToValidAspectRatio(ConstraintMax(constraint));
}

bool IsPositiveFiniteAspectRatio(double aspect_ratio) {
  return std::isfinite(aspect_ratio) && aspect_ratio > 0.0;
}

// If |vertices| has a single element, return |vertices[0]|.
// If |vertices| has two elements, returns the point in the segment defined by
// |vertices| that is closest to |point|.
// |vertices| must have 1 or 2 elements. Otherwise, behavior is undefined.
// This function is called when |point| has already been determined to be
// outside a polygon and |vertices| is the vertex or side closest to |point|.
Point GetClosestPointToVertexOrSide(const Vector<Point>& vertices,
                                    const Point& point) {
  DCHECK(!vertices.empty());
  // If only a single vertex closest to |point|, return that vertex.
  if (vertices.size() == 1U)
    return vertices[0];

  DCHECK_EQ(vertices.size(), 2U);
  // If a polygon side is closest to the ideal height, return the
  // point with aspect ratio closest to the default.
  return Point::ClosestPointInSegment(point, vertices[0], vertices[1]);
}

Point SelectPointWithLargestArea(const Point& p1, const Point& p2) {
  return p1.width() * p1.height() > p2.width() * p2.height() ? p1 : p2;
}

}  // namespace

Point::Point(double height, double width) : height_(height), width_(width) {
  DCHECK(!std::isnan(height_));
  DCHECK(!std::isnan(width_));
}
Point::Point(const Point& other) = default;
Point& Point::operator=(const Point& other) = default;

bool Point::operator==(const Point& other) const {
  return height_ == other.height_ && width_ == other.width_;
}

bool Point::operator!=(const Point& other) const {
  return !(*this == other);
}

bool Point::IsApproximatelyEqualTo(const Point& other) const {
  return AreApproximatelyEqual(height_, other.height_) &&
         AreApproximatelyEqual(width_, other.width_);
}

Point Point::operator+(const Point& other) const {
  return Point(height_ + other.height_, width_ + other.width_);
}

Point Point::operator-(const Point& other) const {
  return Point(height_ - other.height_, width_ - other.width_);
}

Point operator*(double d, const Point& p) {
  return Point(d * p.height(), d * p.width());
}

// Returns the dot product between |p1| and |p2|.
// static
double Point::Dot(const Point& p1, const Point& p2) {
  return p1.height_ * p2.height_ + p1.width_ * p2.width_;
}

// static
double Point::SquareEuclideanDistance(const Point& p1, const Point& p2) {
  Point diff = p1 - p2;
  return Dot(diff, diff);
}

// static
Point Point::ClosestPointInSegment(const Point& p,
                                   const Point& s1,
                                   const Point& s2) {
  // If |s1| and |s2| are the same, it is not really a segment. The closest
  // point to |p| is |s1|=|s2|.
  if (s1 == s2)
    return s1;

  // Translate coordinates to a system where the origin is |s1|.
  Point p_trans = p - s1;
  Point s2_trans = s2 - s1;

  // On this system, we are interested in the projection of |p_trans| on
  // |s2_trans|. The projection is m * |s2_trans|, where
  //       m = Dot(|s2_trans|, |p_trans|) / Dot(|s2_trans|, |s2_trans|).
  // If 0 <= m <= 1, the projection falls within the segment, and the closest
  // point is the projection itself.
  // If m < 0, the closest point is S1.
  // If m > 1, the closest point is S2.
  double m = Dot(s2_trans, p_trans) / Dot(s2_trans, s2_trans);
  if (m < 0)
    return s1;
  if (m > 1)
    return s2;

  // Return the projection in the original coordinate system.
  return s1 + m * s2_trans;
}

ResolutionSet::ResolutionSet(int min_height,
                             int max_height,
                             int min_width,
                             int max_width,
                             double min_aspect_ratio,
                             double max_aspect_ratio)
    : min_height_(min_height),
      max_height_(max_height),
      min_width_(min_width),
      max_width_(max_width),
      min_aspect_ratio_(min_aspect_ratio),
      max_aspect_ratio_(max_aspect_ratio) {
  DCHECK_GE(min_height_, 0);
  DCHECK_GE(max_height_, 0);
  DCHECK_LE(max_height_, kMaxDimension);
  DCHECK_GE(min_width_, 0);
  DCHECK_GE(max_width_, 0);
  DCHECK_LE(max_width_, kMaxDimension);
  DCHECK_GE(min_aspect_ratio_, 0.0);
  DCHECK_GE(max_aspect_ratio_, 0.0);
  DCHECK(!std::isnan(min_aspect_ratio_));
  DCHECK(!std::isnan(max_aspect_ratio_));
}

ResolutionSet::ResolutionSet()
    : ResolutionSet(0, kMaxDimension, 0, kMaxDimension, 0.0, HUGE_VAL) {}

ResolutionSet::ResolutionSet(const ResolutionSet& other) = default;

ResolutionSet& ResolutionSet::operator=(const ResolutionSet& other) = default;

bool ResolutionSet::IsHeightEmpty() const {
  return min_height_ > max_height_ || min_height_ >= kMaxDimension ||
         max_height_ <= 0;
}

bool ResolutionSet::IsWidthEmpty() const {
  return min_width_ > max_width_ || min_width_ >= kMaxDimension ||
         max_width_ <= 0;
}

bool ResolutionSet::IsAspectRatioEmpty() const {
  double max_resolution_aspect_ratio =
      static_cast<double>(max_width_) / static_cast<double>(min_height_);
  double min_resolution_aspect_ratio =
      static_cast<double>(min_width_) / static_cast<double>(max_height_);

  return IsGreater(min_aspect_ratio_, max_aspect_ratio_) ||
         IsLess(max_resolution_aspect_ratio, min_aspect_ratio_) ||
         IsGreater(min_resolution_aspect_ratio, max_aspect_ratio_) ||
         !std::isfinite(min_aspect_ratio_) || max_aspect_ratio_ <= 0.0;
}

bool ResolutionSet::IsEmpty() const {
  return IsHeightEmpty() || IsWidthEmpty() || IsAspectRatioEmpty();
}

bool ResolutionSet::ContainsPoint(const Point& point) const {
  double ratio = point.AspectRatio();
  return point.height() >= min_height_ && point.height() <= max_height_ &&
         point.width() >= min_width_ && point.width() <= max_width_ &&
         ((IsGreaterOrEqual(ratio, min_aspect_ratio_) &&
           IsLessOrEqual(ratio, max_aspect_ratio_)) ||
          // (0.0, 0.0) is always included in the aspect-ratio range.
          (point.width() == 0.0 && point.height() == 0.0));
}

bool ResolutionSet::ContainsPoint(int height, int width) const {
  return ContainsPoint(Point(height, width));
}

ResolutionSet ResolutionSet::Intersection(const ResolutionSet& other) const {
  return ResolutionSet(std::max(min_height_, other.min_height_),
                       std::min(max_height_, other.max_height_),
                       std::max(min_width_, other.min_width_),
                       std::min(max_width_, other.max_width_),
                       std::max(min_aspect_ratio_, other.min_aspect_ratio_),
                       std::min(max_aspect_ratio_, other.max_aspect_ratio_));
}

Point ResolutionSet::SelectClosestPointToIdeal(
    const MediaTrackConstraintSetPlatform& constraint_set,
    int default_height,
    int default_width) const {
  DCHECK_GE(default_height, 1);
  DCHECK_GE(default_width, 1);
  double default_aspect_ratio =
      static_cast<double>(default_width) / static_cast<double>(default_height);

  DCHECK(!IsEmpty());
  int num_ideals = 0;
  if (constraint_set.height.HasIdeal())
    ++num_ideals;
  if (constraint_set.width.HasIdeal())
    ++num_ideals;
  if (constraint_set.aspect_ratio.HasIdeal())
    ++num_ideals;

  switch (num_ideals) {
    case 0:
      return SelectClosestPointToIdealAspectRatio(
          default_aspect_ratio, default_height, default_width);

    case 1:
      // This case requires a point closest to a line.
      // In all variants, if the ideal line intersects the polygon, select the
      // point in the intersection that is closest to preserving the default
      // aspect ratio or a default dimension.
      // If the ideal line is outside the polygon, there is either a single
      // vertex or a polygon side closest to the ideal line. If a single vertex,
      // select that vertex. If a polygon side, select the point on that side
      // that is closest to preserving the default aspect ratio or a default
      // dimension.
      if (constraint_set.height.HasIdeal()) {
        int ideal_height = ToValidDimension(constraint_set.height.Ideal());
        ResolutionSet ideal_line = ResolutionSet::FromExactHeight(ideal_height);
        ResolutionSet intersection = Intersection(ideal_line);
        if (!intersection.IsEmpty()) {
          return intersection.ClosestPointTo(
              Point(ideal_height, ideal_height * default_aspect_ratio));
        }
        Vector<Point> closest_vertices =
            GetClosestVertices(&Point::height, ideal_height);
        Point ideal_point(closest_vertices[0].height(),
                          closest_vertices[0].height() * default_aspect_ratio);
        return GetClosestPointToVertexOrSide(closest_vertices, ideal_point);
      }
      if (constraint_set.width.HasIdeal()) {
        int ideal_width = ToValidDimension(constraint_set.width.Ideal());
        ResolutionSet ideal_line = ResolutionSet::FromExactWidth(ideal_width);
        ResolutionSet intersection = Intersection(ideal_line);
        if (!intersection.IsEmpty()) {
          return intersection.ClosestPointTo(
              Point(ideal_width / default_aspect_ratio, ideal_width));
        }
        Vector<Point> closest_vertices =
            GetClosestVertices(&Point::width, ideal_width);
        Point ideal_point(closest_vertices[0].width() / default_aspect_ratio,
                          closest_vertices[0].width());
        return GetClosestPointToVertexOrSide(closest_vertices, ideal_point);
      }
      {
        DCHECK(constraint_set.aspect_ratio.HasIdeal());
        double ideal_aspect_ratio =
            ToValidAspectRatio(constraint_set.aspect_ratio.Ideal());
        return SelectClosestPointToIdealAspectRatio(
            ideal_aspect_ratio, default_height, default_width);
      }

    case 2:
    case 3:
      double ideal_height;
      double ideal_width;
      if (constraint_set.height.HasIdeal()) {
        ideal_height = ToValidDimension(constraint_set.height.Ideal());
        ideal_width =
            constraint_set.width.HasIdeal()
                ? ToValidDimension(constraint_set.width.Ideal())
                : ideal_height *
                      ToValidAspectRatio(constraint_set.aspect_ratio.Ideal());
      } else {
        DCHECK(constraint_set.width.HasIdeal());
        DCHECK(constraint_set.aspect_ratio.HasIdeal());
        ideal_width = ToValidDimension(constraint_set.width.Ideal());
        ideal_height = ideal_width /
                       ToValidAspectRatio(constraint_set.aspect_ratio.Ideal());
      }
      return ClosestPointTo(Point(ideal_height, ideal_width));

    default:
      NOTREACHED();
  }
}

Point ResolutionSet::SelectClosestPointToIdealAspectRatio(
    double ideal_aspect_ratio,
    int default_height,
    int default_width) const {
  ResolutionSet intersection =
      Intersection(ResolutionSet::FromExactAspectRatio(ideal_aspect_ratio));
  if (!intersection.IsEmpty()) {
    Point default_height_point(default_height,
                               default_height * ideal_aspect_ratio);
    Point default_width_point(default_width / ideal_aspect_ratio,
                              default_width);
    return SelectPointWithLargestArea(
        intersection.ClosestPointTo(default_height_point),
        intersection.ClosestPointTo(default_width_point));
  }
  Vector<Point> closest_vertices =
      GetClosestVertices(&Point::AspectRatio, ideal_aspect_ratio);
  double actual_aspect_ratio = closest_vertices[0].AspectRatio();
  Point default_height_point(default_height,
                             default_height * actual_aspect_ratio);
  Point default_width_point(default_width / actual_aspect_ratio, default_width);
  return SelectPointWithLargestArea(
      GetClosestPointToVertexOrSide(closest_vertices, default_height_point),
      GetClosestPointToVertexOrSide(closest_vertices, default_width_point));
}

Point ResolutionSet::ClosestPointTo(const Point& point) const {
  DCHECK(std::numeric_limits<double>::has_infinity);
  DCHECK(std::isfinite(point.height()));
  DCHECK(std::isfinite(point.width()));

  if (ContainsPoint(point))
    return point;

  auto vertices = ComputeVertices();
  DCHECK_GE(vertices.size(), 1U);
  Point best_candidate(0, 0);
  double best_distance = HUGE_VAL;
  for (WTF::wtf_size_t i = 0; i < vertices.size(); ++i) {
    Point candidate = Point::ClosestPointInSegment(
        point, vertices[i], vertices[(i + 1) % vertices.size()]);
    double distance = Point::SquareEuclideanDistance(point, candidate);
    if (distance < best_distance) {
      best_candidate = candidate;
      best_distance = distance;
    }
  }

  DCHECK(std::isfinite(best_distance));
  return best_candidate;
}

Vector<Point> ResolutionSet::GetClosestVertices(double (Point::*accessor)()
                                                    const,
                                                double value) const {
  DCHECK(!IsEmpty());
  Vector<Point> vertices = ComputeVertices();
  Vector<Point> closest_vertices;
  double best_diff = HUGE_VAL;
  for (const auto& vertex : vertices) {
    double diff;
    if (std::isfinite(value))
      diff = std::fabs((vertex.*accessor)() - value);
    else
      diff = (vertex.*accessor)() == value ? 0.0 : HUGE_VAL;
    if (diff <= best_diff) {
      if (diff < best_diff) {
        best_diff = diff;
        closest_vertices.clear();
      }
      closest_vertices.push_back(vertex);
    }
  }
  DCHECK(!closest_vertices.empty());
  DCHECK_LE(closest_vertices.size(), 2U);
  return closest_vertices;
}

// static
ResolutionSet ResolutionSet::FromHeight(int min, int max) {
  return ResolutionSet(min, max, 0, kMaxDimension, 0.0, HUGE_VAL);
}

// static
ResolutionSet ResolutionSet::FromExactHeight(int value) {
  return ResolutionSet(value, value, 0, kMaxDimension, 0.0, HUGE_VAL);
}

// static
ResolutionSet ResolutionSet::FromWidth(int min, int max) {
  return ResolutionSet(0, kMaxDimension, min, max, 0.0, HUGE_VAL);
}

// static
ResolutionSet ResolutionSet::FromExactWidth(int value) {
  return ResolutionSet(0, kMaxDimension, value, value, 0.0, HUGE_VAL);
}

// static
ResolutionSet ResolutionSet::FromAspectRatio(double min, double max) {
  return ResolutionSet(0, kMaxDimension, 0, kMaxDimension, min, max);
}

// static
ResolutionSet ResolutionSet::FromExactAspectRatio(double value) {
  return ResolutionSet(0, kMaxDimension, 0, kMaxDimension, value, value);
}

// static
ResolutionSet ResolutionSet::FromExactResolution(int width, int height) {
  double aspect_ratio = ToValidAspectRatio(static_cast<double>(width) / height);
  return ResolutionSet(ToValidDimension(height), ToValidDimension(height),
                       ToValidDimension(width), ToValidDimension(width),
                       std::isnan(aspect_ratio) ? 0.0 : aspect_ratio,
                       std::isnan(aspect_ratio) ? HUGE_VAL : aspect_ratio);
}

Vector<Point> ResolutionSet::ComputeVertices() const {
  Vector<Point> vertices;
  // Add vertices in counterclockwise order
  // Start with (min_height, min_width) and continue along min_width.
  TryAddVertex(&vertices, Point(min_height_, min_width_));
  if (IsPositiveFiniteAspectRatio(max_aspect_ratio_))
    TryAddVertex(&vertices, Point(min_width_ / max_aspect_ratio_, min_width_));
  if (IsPositiveFiniteAspectRatio(min_aspect_ratio_))
    TryAddVertex(&vertices, Point(min_width_ / min_aspect_ratio_, min_width_));
  TryAddVertex(&vertices, Point(max_height_, min_width_));
  // Continue along max_height.
  if (IsPositiveFiniteAspectRatio(min_aspect_ratio_)) {
    TryAddVertex(&vertices,
                 Point(max_height_, max_height_ * min_aspect_ratio_));
  }
  if (IsPositiveFiniteAspectRatio(max_aspect_ratio_)) {
    TryAddVertex(&vertices,
                 Point(max_height_, max_height_ * max_aspect_ratio_));
  }
  TryAddVertex(&vertices, Point(max_height_, max_width_));
  // Continue along max_width.
  if (IsPositiveFiniteAspectRatio(min_aspect_ratio_))
    TryAddVertex(&vertices, Point(max_width_ / min_aspect_ratio_, max_width_));
  if (IsPositiveFiniteAspectRatio(max_aspect_ratio_))
    TryAddVertex(&vertices, Point(max_width_ / max_aspect_ratio_, max_width_));
  TryAddVertex(&vertices, Point(min_height_, max_width_));
  // Finish along min_height.
  if (IsPositiveFiniteAspectRatio(max_aspect_ratio_)) {
    TryAddVertex(&vertices,
                 Point(min_height_, min_height_ * max_aspect_ratio_));
  }
  if (IsPositiveFiniteAspectRatio(min_aspect_ratio_)) {
    TryAddVertex(&vertices,
                 Point(min_height_, min_height_ * min_aspect_ratio_));
  }

  DCHECK_LE(vertices.size(), 6U);
  return vertices;
}

void ResolutionSet::TryAddVertex(Vector<Point>* vertices,
                                 const Point& point) const {
  if (!ContainsPoint(point))
    return;

  // Add the point to the |vertices| if not already added.
  // This is to prevent duplicates in case an aspect ratio intersects a width
  // or height right on a vertex.
  if (vertices->empty() ||
      (*(vertices->end() - 1) != point && *vertices->begin() != point)) {
    vertices->push_back(point);
  }
}

ResolutionSet ResolutionSet::FromConstraintSet(
    const MediaTrackConstraintSetPlatform& constraint_set) {
  return ResolutionSet(
      MinDimensionFromConstraint(constraint_set.height),
      MaxDimensionFromConstraint(constraint_set.height),
      MinDimensionFromConstraint(constraint_set.width),
      MaxDimensionFromConstraint(constraint_set.width),
      MinAspectRatioFromConstraint(constraint_set.aspect_ratio),
      MaxAspectRatioFromConstraint(constraint_set.aspect_ratio));
}

DiscreteSet<std::string> StringSetFromConstraint(
    const StringConstraint& constraint) {
  if (!constraint.HasExact())
    return DiscreteSet<std::string>::UniversalSet();

  Vector<std::string> elements;
  for (const auto& entry : constraint.Exact())
    elements.push_back(entry.Ascii());

  return DiscreteSet<std::string>(std::move(elements));
}

DiscreteSet<bool> BoolSetFromConstraint(const BooleanConstraint& constraint) {
  if (!constraint.HasExact())
    return DiscreteSet<bool>::UniversalSet();

  return DiscreteSet<bool>({constraint.Exact()});
}

DiscreteSet<bool> RescaleSetFromConstraint(
    const StringConstraint& resize_mode_constraint) {
  DCHECK_EQ(resize_mode_constraint.GetName(),
            MediaTrackConstraintSetPlatform().resize_mode.GetName());
  bool contains_none = resize_mode_constraint.Matches(
      WebString::FromASCII(WebMediaStreamTrack::kResizeModeNone));
  bool contains_rescale = resize_mode_constraint.Matches(
      WebString::FromASCII(WebMediaStreamTrack::kResizeModeRescale));
  if (resize_mode_constraint.Exact().empty() ||
      (contains_none && contains_rescale)) {
    return DiscreteSet<bool>::UniversalSet();
  }

  if (contains_none)
    return DiscreteSet<bool>({false});

  if (contains_rescale)
    return DiscreteSet<bool>({true});

  return DiscreteSet<bool>::EmptySet();
}

}  // namespace media_constraints
}  // namespace blink

"""

```