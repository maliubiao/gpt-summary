Response:
The user wants a summary of the functionality of the C++ code provided. I need to analyze the code and identify its main purpose. The filename `media_stream_constraints_util_sets_test.cc` strongly suggests it's a unit test file. It includes headers related to media streams and constraints. The presence of `gtest` confirms it's using the Google Test framework.

Therefore, the main function of this file is to **test the functionality of the `media_constraints` namespace, specifically focusing on the `ResolutionSet` class and its related utility functions**.

To elaborate on this, I need to identify what aspects of `ResolutionSet` are being tested. The test cases cover:
- Basic operations on `Point` objects (addition, subtraction, dot product, distance, closest point on a segment).
- Creation and manipulation of `ResolutionSet` objects (from height, width, aspect ratio, exact values).
- Checking if a `ResolutionSet` contains a given point.
- Determining if a `ResolutionSet` is empty under various conditions.
- Intersection of `ResolutionSet` objects.
- Finding the closest point in a `ResolutionSet` to a given point or ideal constraints.
- Computing the vertices of a `ResolutionSet`.

Regarding connections to web technologies:
- **JavaScript:**  The `MediaStream` API in JavaScript allows web applications to access the user's camera and microphone. The constraints used in JavaScript's `getUserMedia()` to specify desired media track settings (like resolution) are related to the logic being tested here.
- **HTML:** HTML elements like `<video>` and `<audio>` are used to display media streams obtained through the `MediaStream` API. The constraints tested here ultimately affect what kind of media stream can be successfully created and displayed.
- **CSS:** While CSS doesn't directly control media stream constraints, it's used to style the HTML elements displaying the media. The resolution of the media stream (which is influenced by constraints) can impact how the media is rendered within the styled elements.

For logical reasoning, I can look at some test cases and infer input/output. For example, a test checking if a point is contained in a `ResolutionSet` with specific height and width ranges.

For common errors, consider how developers might incorrectly specify constraints in JavaScript or how the underlying C++ logic could have flaws.

Finally, I need to think about how a user's actions might lead to this code being executed. This involves tracing back from user interaction in a web browser to the underlying Blink engine.
这是名为 `media_stream_constraints_util_sets_test.cc` 的 Chromium Blink 引擎源代码文件，其主要功能是 **对与媒体流约束相关的集合工具类进行单元测试**。更具体地说，它专注于测试 `blink::media_constraints::ResolutionSet` 类的各种功能。

**功能归纳:**

1. **测试 `Point` 类的基本操作:**  该文件测试了表示分辨率的 `Point` 类的基本算术运算（加法、减法）、点积、距离计算以及计算点到线段最近点的功能。
2. **测试 `ResolutionSet` 类的创建和属性:**  它测试了如何创建 `ResolutionSet` 对象，包括从特定的高度、宽度、宽高比范围创建，以及从确切的高度、宽度或宽高比创建。同时测试了 `ResolutionSet` 的属性，例如是否包含某个点、是否为空、高度/宽度/宽高比维度是否为空。
3. **测试 `ResolutionSet` 的集合运算:** 文件测试了 `ResolutionSet` 对象的交集运算 (`Intersection`)，验证了在不同约束条件下交集的结果是否符合预期。
4. **测试 `ResolutionSet` 查找最近点的功能:**  它测试了 `ClosestPointTo` 方法，该方法用于找到 `ResolutionSet` 中最接近给定点的点。
5. **测试 `ResolutionSet` 根据理想约束选择最佳点的功能:**  测试了 `SelectClosestPointToIdeal` 方法，模拟了在给定理想高度、宽度和宽高比约束的情况下，从 `ResolutionSet` 中选择最合适的点。
6. **测试 `ResolutionSet` 计算顶点集合的功能:** 测试了 `ComputeVertices` 方法，用于计算 `ResolutionSet` 所代表的几何形状的顶点。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件中测试的功能直接影响了 Web 开发者在使用 JavaScript 的 `getUserMedia()` API 时所设置的媒体约束。

* **JavaScript:**  当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: { width: { min: 640, ideal: 1280 }, height: { min: 480, ideal: 720 } } })` 时，这些约束会被传递到浏览器底层引擎（Blink）。 `media_stream_constraints_util_sets_test.cc` 中测试的 `ResolutionSet` 类及其方法，正是用来解析和处理这些 JavaScript 传递过来的约束，并最终决定应该使用哪种分辨率的视频流。例如，测试用例 `ResolutionIdealIntersects` 和 `ResolutionIdealOutsideSinglePoint` 就模拟了在不同的理想约束下，`ResolutionSet` 如何选择最合适的点。
* **HTML:** HTML 的 `<video>` 元素用于展示媒体流。 `ResolutionSet` 的测试确保了当 JavaScript 请求特定分辨率的媒体流时，底层能够正确处理约束，从而提供符合要求的视频流，以便在 `<video>` 元素中正常显示。
* **CSS:** CSS 可以用来调整 `<video>` 元素的大小和布局，但 CSS 本身并不影响媒体流的实际分辨率。然而，`ResolutionSet` 保证了选择的媒体流分辨率与用户或应用要求的约束相符，这间接地影响了 CSS 布局的效果。例如，如果 CSS 设定了特定的宽高比，而 `ResolutionSet` 能够找到符合该宽高比约束的媒体流，那么在 `<video>` 元素中显示时就能更好地适应布局。

**逻辑推理举例：**

**假设输入:**

* 创建一个 `ResolutionSet` 对象，其最小高度为 100，最大高度为 200，最小宽度为 100，最大宽度为 200。
* 调用 `ContainsPoint(150, 150)` 方法。
* 调用 `ContainsPoint(50, 50)` 方法。

**预期输出:**

* `ContainsPoint(150, 150)` 返回 `true`，因为点 (150, 150) 在指定的高度和宽度范围内。
* `ContainsPoint(50, 50)` 返回 `false`，因为点 (50, 50) 的高度和宽度都小于最小值。

**用户或编程常见的使用错误举例：**

1. **约束冲突:** 用户在 JavaScript 中设置了相互冲突的约束，例如 `width: { min: 1000, max: 500 }`。`ResolutionSet` 的测试确保了在遇到这种冲突时，能够正确处理（例如，返回一个空集）。测试用例 `ResolutionTrivialEmptiness` 和 `ResolutionLineConstraintsEmptiness` 覆盖了这方面的情况。
2. **理想值超出范围:** 用户设置了理想的高度或宽度，但该值超出了设备能力或硬性约束范围。例如，请求一个 8K 分辨率的摄像头，但设备不支持。`ResolutionIdealOutsideSinglePoint` 和 `ResolutionIdealOutsideMultiplePoints` 等测试用例模拟了这种情况，验证了 `SelectClosestPointToIdeal` 方法在理想值不可达时如何选择最接近的有效点。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户打开一个网页或 Web 应用。**
2. **网页中的 JavaScript 代码调用了 `navigator.mediaDevices.getUserMedia()` 方法，请求访问摄像头或麦克风。**
3. **在 `getUserMedia()` 的参数中，JavaScript 代码指定了 `video` 或 `audio` 的约束，例如期望的分辨率、帧率等。**
4. **浏览器接收到这个请求，并将约束传递给 Blink 引擎的媒体流模块。**
5. **Blink 引擎会创建 `blink::media_constraints::ResolutionSet` 对象，并使用传递过来的约束来初始化它。**  `media_stream_constraints_util_sets_test.cc` 中测试的各种 `ResolutionSet::From...` 方法会被调用。
6. **Blink 引擎会使用 `ResolutionSet` 的方法（例如 `ContainsPoint`, `Intersection`, `SelectClosestPointToIdeal`）来确定最符合用户约束的媒体流配置。** 例如，如果用户设置了理想分辨率，`SelectClosestPointToIdeal` 方法会被调用。
7. **如果需要调试与分辨率约束相关的问题，开发者可能会查看 Blink 引擎中处理这些约束的代码，`media_stream_constraints_util_sets_test.cc` 文件以及其测试的 `media_stream_constraints_util_sets.h` 文件就是关键的入口点。** 开发者可以分析 `ResolutionSet` 的状态，检查其包含的点、边界、以及在不同约束下的行为，从而定位问题所在。

**功能归纳 (针对第 1 部分):**

这个代码文件的第 1 部分主要集中在以下几个方面：

* **`Point` 类的基础功能测试:** 验证了表示分辨率点的基本数学运算的正确性。
* **`ResolutionSet` 类的基本创建和属性测试:**  测试了 `ResolutionSet` 对象的创建方式，以及判断其基本属性（是否包含点，是否为空）的功能。
* **`ResolutionSet` 集合运算和查找最近点功能的初步测试:**  涵盖了 `Intersection` 和 `ClosestPointTo` 方法的一些基本测试用例。

总而言之，`media_stream_constraints_util_sets_test.cc` 的第 1 部分为 `ResolutionSet` 类的核心功能提供了坚实的单元测试基础，确保了媒体流约束在 Blink 引擎中能够被正确地解析和处理。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_sets_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_sets.h"

#include <cmath>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace media_constraints {

using media_constraints::ResolutionSet;
using Point = ResolutionSet::Point;
using BoolSet = media_constraints::DiscreteSet<bool>;

namespace {

const int kDefaultWidth = 640;
const int kDefaultHeight = 480;
constexpr double kDefaultAspectRatio =
    static_cast<double>(kDefaultWidth) / static_cast<double>(kDefaultHeight);

// Defined as macro in order to get more informative line-number information
// when a test fails.
#define EXPECT_POINT_EQ(p1, p2)                     \
  do {                                              \
    EXPECT_DOUBLE_EQ((p1).height(), (p2).height()); \
    EXPECT_DOUBLE_EQ((p1).width(), (p2).width());   \
  } while (0)

// Checks if |point| is an element of |vertices| using
// Point::IsApproximatelyEqualTo() to test for equality.
void VerticesContain(const Vector<Point>& vertices, const Point& point) {
  bool result = false;
  for (const auto& vertex : vertices) {
    if (point.IsApproximatelyEqualTo(vertex)) {
      result = true;
      break;
    }
  }
  EXPECT_TRUE(result);
}

bool AreCounterclockwise(const Vector<Point>& vertices) {
  // Single point or segment are trivial cases.
  if (vertices.size() <= 2)
    return true;
  else if (vertices.size() > 6)  // Polygons of more than 6 sides are not valid.
    return false;

  // The polygon defined by a resolution set is always convex and has at most 6
  // sides. When producing a list of the vertices for such a polygon, it is
  // important that they are returned in counterclockwise (or clockwise) order,
  // to make sure that any consecutive pair of vertices (modulo the number of
  // vertices) corresponds to a polygon side. Our implementation uses
  // counterclockwise order.
  // Compute orientation using the determinant of each diagonal in the
  // polygon, using the first vertex as reference.
  Point prev_diagonal = vertices[1] - vertices[0];
  for (auto vertex = vertices.begin() + 2; vertex != vertices.end(); ++vertex) {
    Point current_diagonal = *vertex - vertices[0];
    // The determinant of the two diagonals returns the signed area of the
    // parallelogram they generate. The area is positive if the diagonals are in
    // counterclockwise order, zero if the diagonals have the same direction and
    // negative if the diagonals are in clockwise order.
    // See https://en.wikipedia.org/wiki/Determinant#2_.C3.97_2_matrices.
    double det = prev_diagonal.height() * current_diagonal.width() -
                 current_diagonal.height() * prev_diagonal.width();
    if (det <= 0)
      return false;
    prev_diagonal = current_diagonal;
  }
  return true;
}

// Determines if |vertices| is valid according to the contract for
// ResolutionCandidateSet::ComputeVertices().
bool AreValidVertices(const ResolutionSet& set, const Vector<Point>& vertices) {
  // Verify that every vertex is included in |set|.
  for (const auto& vertex : vertices) {
    if (!set.ContainsPoint(vertex))
      return false;
  }

  return AreCounterclockwise(vertices);
}

// This function provides an alternative method for computing the projection
// of |point| on the line of segment |s1||s2| to be used to compare the results
// provided by Point::ClosestPointInSegment(). Since it relies on library
// functions, it has larger error in practice than
// Point::ClosestPointInSegment(), so results must be compared with
// Point::IsApproximatelyEqualTo().
// This function only computes projections. The result may be outside the
// segment |s1||s2|.
Point ProjectionOnSegmentLine(const Point& point,
                              const Point& s1,
                              const Point& s2) {
  double segment_slope =
      (s2.width() - s1.width()) / (s2.height() - s1.height());
  double segment_angle = std::atan(segment_slope);
  double norm = std::sqrt(Point::Dot(point, point));
  double angle =
      (point.height() == 0 && point.width() == 0)
          ? 0.0
          : std::atan(point.width() / point.height()) - segment_angle;
  double projection_length = norm * std::cos(angle);
  double projection_height = projection_length * std::cos(segment_angle);
  double projection_width = projection_length * std::sin(segment_angle);
  return Point(projection_height, projection_width);
}

}  // namespace

class MediaStreamConstraintsUtilSetsTest : public testing::Test {
 protected:
  using P = Point;

  Point SelectClosestPointToIdeal(const ResolutionSet& set) {
    return set.SelectClosestPointToIdeal(
        factory_.CreateMediaConstraints().Basic(), kDefaultHeight,
        kDefaultWidth);
  }

  test::TaskEnvironment task_environment_;
  MockConstraintFactory factory_;
};

// This test tests the test-harness function AreValidVertices.
TEST_F(MediaStreamConstraintsUtilSetsTest, VertexListValidity) {
  EXPECT_TRUE(AreCounterclockwise({P(1, 1)}));
  EXPECT_TRUE(AreCounterclockwise({P(1, 1)}));
  EXPECT_TRUE(AreCounterclockwise({P(1, 0), P(0, 1)}));
  EXPECT_TRUE(AreCounterclockwise({P(1, 1), P(0, 0), P(1, 0)}));

  // Not in counterclockwise order.
  EXPECT_FALSE(AreCounterclockwise({P(1, 0), P(0, 0), P(1, 1)}));

  // Final vertex aligned with the previous two vertices.
  EXPECT_FALSE(AreCounterclockwise({P(1, 0), P(1, 1), P(1, 1.5), P(1, 0.1)}));

  // Not in counterclockwise order.
  EXPECT_FALSE(
      AreCounterclockwise({P(1, 0), P(3, 0), P(2, 2), P(3.1, 1), P(0, 1)}));

  EXPECT_TRUE(AreCounterclockwise(
      {P(1, 0), P(3, 0), P(3.1, 1), P(3, 2), P(1, 2), P(0.9, 1)}));

  // Not in counterclockwise order.
  EXPECT_FALSE(AreCounterclockwise(
      {P(1, 0), P(3, 0), P(3.1, 1), P(1, 2), P(3, 2), P(0.9, 1)}));

  // Counterclockwise, but more than 6 vertices.
  EXPECT_FALSE(AreCounterclockwise(
      {P(1, 0), P(3, 0), P(3.1, 1), P(3, 2), P(2, 2.1), P(1, 2), P(0.9, 1)}));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, PointOperations) {
  const Point kZero(0, 0);

  // Basic equality and inequality
  EXPECT_EQ(P(0, 0), kZero);
  EXPECT_EQ(P(50, 50), P(50, 50));
  EXPECT_NE(kZero, P(50, 50));
  EXPECT_NE(P(50, 50), P(100, 100));
  EXPECT_NE(P(50, 50), P(100, 50));

  // Operations with zero.
  EXPECT_EQ(kZero, kZero + kZero);
  EXPECT_EQ(kZero, kZero - kZero);
  EXPECT_EQ(kZero, 0.0 * kZero);
  EXPECT_EQ(0.0, P::Dot(kZero, kZero));
  EXPECT_EQ(0.0, P::SquareEuclideanDistance(kZero, kZero));
  EXPECT_EQ(kZero, P::ClosestPointInSegment(kZero, kZero, kZero));

  // Operations with zero and nonzero values.
  EXPECT_EQ(P(50, 50), kZero + P(50, 50));
  EXPECT_EQ(P(50, 50) + kZero, kZero + P(50, 50));
  EXPECT_EQ(P(50, 50), P(50, 50) - kZero);
  EXPECT_EQ(kZero, P(50, 50) - P(50, 50));
  EXPECT_EQ(kZero, 0.0 * P(50, 50));
  EXPECT_EQ(0.0, P::Dot(kZero, P(50, 50)));
  EXPECT_EQ(0.0, P::Dot(P(50, 50), kZero));
  EXPECT_EQ(5000, P::SquareEuclideanDistance(kZero, P(50, 50)));
  EXPECT_EQ(P::SquareEuclideanDistance(P(50, 50), kZero),
            P::SquareEuclideanDistance(kZero, P(50, 50)));
  EXPECT_EQ(kZero, P::ClosestPointInSegment(kZero, kZero, P(50, 50)));
  EXPECT_EQ(kZero, P::ClosestPointInSegment(kZero, P(50, 50), kZero));
  EXPECT_EQ(P(50, 50),
            P::ClosestPointInSegment(P(50, 50), P(50, 50), P(50, 50)));

  // Operations with nonzero values.
  // Additions.
  EXPECT_EQ(P(100, 50), P(50, 50) + P(50, 0));
  EXPECT_EQ(P(100, 50), P(50, 0) + P(50, 50));

  // Substractions.
  EXPECT_EQ(P(50, 50), P(100, 100) - P(50, 50));
  EXPECT_EQ(P(50, 50), P(100, 50) - P(50, 0));
  EXPECT_EQ(P(50, 0), P(100, 50) - P(50, 50));

  // Scalar-vector products.
  EXPECT_EQ(P(50, 50), 1.0 * P(50, 50));
  EXPECT_EQ(P(75, 75), 1.5 * P(50, 50));
  EXPECT_EQ(P(200, 100), 2.0 * P(100, 50));
  EXPECT_EQ(2.0 * (P(100, 100) + P(100, 50)),
            2.0 * P(100, 100) + 2.0 * P(100, 50));

  // Dot products.
  EXPECT_EQ(2 * 50 * 100, P::Dot(P(50, 50), P(100, 100)));
  EXPECT_EQ(P::Dot(P(100, 100), P(50, 50)), P::Dot(P(50, 50), P(100, 100)));
  EXPECT_EQ(0, P::Dot(P(100, 0), P(0, 100)));

  // Distances.
  EXPECT_EQ(25, P::SquareEuclideanDistance(P(4, 0), P(0, 3)));
  EXPECT_EQ(75 * 75, P::SquareEuclideanDistance(P(100, 0), P(25, 0)));
  EXPECT_EQ(75 * 75, P::SquareEuclideanDistance(P(0, 100), P(0, 25)));
  EXPECT_EQ(5 * 5 + 9 * 9, P::SquareEuclideanDistance(P(5, 1), P(10, 10)));

  // Closest point to segment from (10,0) to (50,0).
  EXPECT_EQ(P(25, 0), P::ClosestPointInSegment(P(25, 25), P(10, 0), P(50, 0)));
  EXPECT_EQ(P(50, 0),
            P::ClosestPointInSegment(P(100, 100), P(10, 0), P(50, 0)));
  EXPECT_EQ(P(10, 0), P::ClosestPointInSegment(P(0, 100), P(10, 0), P(50, 0)));

  // Closest point to segment from (0,10) to (0,50).
  EXPECT_EQ(P(0, 25), P::ClosestPointInSegment(P(25, 25), P(0, 10), P(0, 50)));
  EXPECT_EQ(P(0, 50),
            P::ClosestPointInSegment(P(100, 100), P(0, 10), P(0, 50)));
  EXPECT_EQ(P(0, 10), P::ClosestPointInSegment(P(100, 0), P(0, 10), P(0, 50)));

  // Closest point to segment from (0,10) to (10,0).
  EXPECT_EQ(P(5, 5), P::ClosestPointInSegment(P(25, 25), P(0, 10), P(10, 0)));
  EXPECT_EQ(P(5, 5), P::ClosestPointInSegment(P(100, 100), P(0, 10), P(10, 0)));
  EXPECT_EQ(P(10, 0), P::ClosestPointInSegment(P(100, 0), P(0, 10), P(10, 0)));
  EXPECT_EQ(P(0, 10), P::ClosestPointInSegment(P(0, 100), P(0, 10), P(10, 0)));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionUnconstrained) {
  ResolutionSet set;
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(1, 1));
  EXPECT_TRUE(set.ContainsPoint(2000, 2000));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionConstrained) {
  ResolutionSet set = ResolutionSet::FromHeight(10, 100);
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_FALSE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromHeight(0, 100);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_FALSE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromHeight(100, ResolutionSet::kMaxDimension);
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_FALSE(set.ContainsPoint(10, 10));
  EXPECT_FALSE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_TRUE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromWidth(10, 100);
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_FALSE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromWidth(0, 100);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_FALSE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromWidth(100, ResolutionSet::kMaxDimension);
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_FALSE(set.ContainsPoint(10, 10));
  EXPECT_FALSE(set.ContainsPoint(50, 50));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_TRUE(set.ContainsPoint(500, 500));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromAspectRatio(1.0, 2.0);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(10, 20));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_TRUE(set.ContainsPoint(2000, 4000));
  EXPECT_FALSE(set.ContainsPoint(1, 50));
  EXPECT_FALSE(set.ContainsPoint(50, 1));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromAspectRatio(0.0, 2.0);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(10, 20));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_TRUE(set.ContainsPoint(2000, 4000));
  EXPECT_FALSE(set.ContainsPoint(1, 50));
  EXPECT_TRUE(set.ContainsPoint(50, 1));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromAspectRatio(1.0, HUGE_VAL);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(10, 10));
  EXPECT_TRUE(set.ContainsPoint(10, 20));
  EXPECT_TRUE(set.ContainsPoint(100, 100));
  EXPECT_TRUE(set.ContainsPoint(2000, 4000));
  EXPECT_TRUE(set.ContainsPoint(1, 50));
  EXPECT_FALSE(set.ContainsPoint(50, 1));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionTrivialEmptiness) {
  ResolutionSet set = ResolutionSet::FromHeight(100, 10);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_TRUE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromWidth(100, 10);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_TRUE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());

  set = ResolutionSet::FromAspectRatio(100.0, 10.0);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_TRUE(set.IsAspectRatioEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionLineConstraintsEmptiness) {
  ResolutionSet set(1, 1, 1, 1, 1, 1);
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_TRUE(set.ContainsPoint(1, 1));
  EXPECT_FALSE(set.ContainsPoint(1, 0));
  EXPECT_FALSE(set.ContainsPoint(0, 1));

  // Three lines that do not intersect in the same point is empty.
  set = ResolutionSet(1, 1, 1, 1, 0.5, 0.5);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_TRUE(set.IsAspectRatioEmpty());
  EXPECT_FALSE(set.ContainsPoint(0, 0));
  EXPECT_FALSE(set.ContainsPoint(1, 1));
  EXPECT_FALSE(set.ContainsPoint(1, 0));
  EXPECT_FALSE(set.ContainsPoint(0, 1));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionBoxEmptiness) {
  const int kMin = 100;
  const int kMax = 200;
  // Max aspect ratio below box.
  ResolutionSet set(kMin, kMax, kMin, kMax, 0.4, 0.4);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_TRUE(set.IsAspectRatioEmpty());

  // Min aspect ratio above box.
  set = ResolutionSet(kMin, kMax, kMin, kMax, 3.0, HUGE_VAL);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_TRUE(set.IsAspectRatioEmpty());

  // Min aspect ratio crosses box.
  set = ResolutionSet(kMin, kMax, kMin, kMax, 1.0, HUGE_VAL);
  EXPECT_FALSE(set.IsEmpty());

  // Max aspect ratio crosses box.
  set = ResolutionSet(kMin, kMax, kMin, kMax, 0.0, 1.0);
  EXPECT_FALSE(set.IsEmpty());

  // Min and max aspect ratios cross box.
  set = ResolutionSet(kMin, kMax, kMin, kMax, 0.9, 1.1);
  EXPECT_FALSE(set.IsEmpty());

  // Min and max aspect ratios cover box.
  set = ResolutionSet(kMin, kMax, kMin, kMax, 0.2, 100);
  EXPECT_FALSE(set.IsEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionPointIntersection) {
  ResolutionSet set1(1, 2, 1, 2, 0.0, HUGE_VAL);
  ResolutionSet set2 = ResolutionSet::FromExactAspectRatio(0.5);
  auto intersection = set1.Intersection(set2);

  // The intersection should contain only the point (h=2, w=1)
  EXPECT_TRUE(intersection.ContainsPoint(2, 1));

  // It should not contain any point in the vicinity of the included point
  // (integer version).
  EXPECT_FALSE(intersection.ContainsPoint(1, 0));
  EXPECT_FALSE(intersection.ContainsPoint(2, 0));
  EXPECT_FALSE(intersection.ContainsPoint(3, 0));
  EXPECT_FALSE(intersection.ContainsPoint(1, 1));
  EXPECT_FALSE(intersection.ContainsPoint(3, 1));
  EXPECT_FALSE(intersection.ContainsPoint(1, 2));
  EXPECT_FALSE(intersection.ContainsPoint(2, 2));
  EXPECT_FALSE(intersection.ContainsPoint(3, 2));

  // It should not contain any point in the vicinity of the included point
  // (floating-point version).
  EXPECT_FALSE(intersection.ContainsPoint(P(2.0001, 1.0001)));
  EXPECT_FALSE(intersection.ContainsPoint(P(2.0001, 1.0)));
  EXPECT_FALSE(intersection.ContainsPoint(P(2.0001, 0.9999)));
  EXPECT_FALSE(intersection.ContainsPoint(P(2.0, 1.0001)));
  EXPECT_FALSE(intersection.ContainsPoint(P(2.0, 0.9999)));
  EXPECT_FALSE(intersection.ContainsPoint(P(1.9999, 1.0001)));
  EXPECT_FALSE(intersection.ContainsPoint(P(1.9999, 1.0)));
  EXPECT_FALSE(intersection.ContainsPoint(P(1.9999, 0.9999)));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionLineIntersection) {
  ResolutionSet set1(1, 2, 1, 2, 0.0, HUGE_VAL);
  ResolutionSet set2 = ResolutionSet::FromExactAspectRatio(1.0);

  // The intersection should contain (1,1) and (2,2)
  auto intersection = set1.Intersection(set2);
  EXPECT_TRUE(intersection.ContainsPoint(1, 1));
  EXPECT_TRUE(intersection.ContainsPoint(2, 2));

  // It should not contain the other points in the bounding box.
  EXPECT_FALSE(intersection.ContainsPoint(1, 2));
  EXPECT_FALSE(intersection.ContainsPoint(2, 1));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionBoxIntersection) {
  const int kMin1 = 0;
  const int kMax1 = 2;
  ResolutionSet set1(kMin1, kMax1, kMin1, kMax1, 0.0, HUGE_VAL);

  const int kMin2 = 1;
  const int kMax2 = 3;
  ResolutionSet set2(kMin2, kMax2, kMin2, kMax2, 0.0, HUGE_VAL);

  auto intersection = set1.Intersection(set2);
  for (int i = kMin1; i <= kMax2; ++i) {
    for (int j = kMin1; j <= kMax2; ++j) {
      if (i >= kMin2 && j >= kMin2 && i <= kMax1 && j <= kMax1)
        EXPECT_TRUE(intersection.ContainsPoint(i, j));
      else
        EXPECT_FALSE(intersection.ContainsPoint(i, j));
    }
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionPointSetClosestPoint) {
  const int kHeight = 10;
  const int kWidth = 10;
  const double kAspectRatio = 1.0;
  ResolutionSet set(kHeight, kHeight, kWidth, kWidth, kAspectRatio,
                    kAspectRatio);

  for (int height = 0; height < 100; height += 10) {
    for (int width = 0; width < 100; width += 10) {
      EXPECT_EQ(P(kHeight, kWidth), set.ClosestPointTo(P(height, width)));
    }
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionLineSetClosestPoint) {
  {
    const int kHeight = 10;
    auto set = ResolutionSet::FromExactHeight(kHeight);
    for (int height = 0; height < 100; height += 10) {
      for (int width = 0; width < 100; width += 10) {
        EXPECT_EQ(P(kHeight, width), set.ClosestPointTo(P(height, width)));
      }
    }
    const int kWidth = 10;
    set = ResolutionSet::FromExactWidth(kWidth);
    for (int height = 0; height < 100; height += 10) {
      for (int width = 0; width < 100; width += 10) {
        EXPECT_EQ(P(height, kWidth), set.ClosestPointTo(P(height, width)));
      }
    }
  }

  {
    const double kAspectRatios[] = {0.0, 0.1, 0.2, 0.5,
                                    1.0, 2.0, 5.0, HUGE_VAL};
    for (double aspect_ratio : kAspectRatios) {
      auto set = ResolutionSet::FromExactAspectRatio(aspect_ratio);
      for (int height = 0; height < 100; height += 10) {
        for (int width = 0; width < 100; width += 10) {
          Point point(height, width);
          Point expected =
              ProjectionOnSegmentLine(point, P(0, 0), P(1, aspect_ratio));
          Point actual = set.ClosestPointTo(point);
          // This requires higher tolerance than ExpectPointEx due to the larger
          // error of the alternative projection method.
          EXPECT_TRUE(expected.IsApproximatelyEqualTo(actual));
        }
      }
    }
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionGeneralSetClosestPoint) {
  // This set contains the following vertices:
  // (10, 10), (20, 10), (100, 50), (100, 100), (100/1.5, 100), (10, 15)
  ResolutionSet set(10, 100, 10, 100, 0.5, 1.5);

  // Check that vertices are the closest points to themselves.
  auto vertices = set.ComputeVertices();
  for (auto& vertex : vertices)
    EXPECT_EQ(vertex, set.ClosestPointTo(vertex));

  // Point inside the set.
  EXPECT_EQ(P(11, 11), set.ClosestPointTo(P(11, 11)));

  // Close to horizontal segment (10, 10) (20, 10).
  EXPECT_EQ(P(15, 10), set.ClosestPointTo(P(15, 9)));

  // Close to horizontal segment (100, 100) (100/1.5, 100).
  EXPECT_EQ(P(99, 100), set.ClosestPointTo(P(99, 200)));

  // Close to vertical segment (10, 15) (10, 10).
  EXPECT_EQ(P(10, 12.5), set.ClosestPointTo(P(2, 12.5)));

  // Close to vertical segment (100, 50) (100, 100).
  EXPECT_EQ(P(100, 75), set.ClosestPointTo(P(120, 75)));

  // Close to oblique segment (20, 10) (100, 50)
  {
    Point point(70, 15);
    Point expected = ProjectionOnSegmentLine(point, P(20, 10), P(100, 50));
    Point actual = set.ClosestPointTo(point);
    EXPECT_POINT_EQ(expected, actual);
  }

  // Close to oblique segment (100/1.5, 100) (10, 15)
  {
    Point point(12, 70);
    Point expected =
        ProjectionOnSegmentLine(point, P(100 / 1.5, 100), P(10, 15));
    Point actual = set.ClosestPointTo(point);
    EXPECT_POINT_EQ(expected, actual);
  }

  // Points close to vertices.
  EXPECT_EQ(P(10, 10), set.ClosestPointTo(P(9, 9)));
  EXPECT_EQ(P(20, 10), set.ClosestPointTo(P(20, 9)));
  EXPECT_EQ(P(100, 50), set.ClosestPointTo(P(101, 50)));
  EXPECT_EQ(P(100, 100), set.ClosestPointTo(P(101, 101)));
  EXPECT_EQ(P(100 / 1.5, 100), set.ClosestPointTo(P(100 / 1.5, 101)));
  EXPECT_EQ(P(10, 15), set.ClosestPointTo(P(9, 15)));
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionIdealIntersects) {
  ResolutionSet set(100, 1000, 100, 1000, 0.5, 2.0);

  const int kIdealHeight = 500;
  const int kIdealWidth = 1000;
  const double kIdealAspectRatio = 1.5;

  // Ideal height.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(kIdealHeight, kIdealHeight * kDefaultAspectRatio),
                    point);
  }

  // Ideal width.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(kIdealWidth);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(kIdealWidth / kDefaultAspectRatio, kIdealWidth),
                    point);
  }

  // Ideal aspect ratio.
  {
    factory_.Reset();
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_DOUBLE_EQ(kDefaultHeight, point.height());
    EXPECT_DOUBLE_EQ(kDefaultHeight * kIdealAspectRatio, point.width());
  }

  // Ideal height and width.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().width.SetIdeal(kIdealWidth);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(kIdealHeight, kIdealWidth), point);
  }

  // Ideal height and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(kIdealHeight, kIdealHeight * kIdealAspectRatio),
                    point);
  }

  // Ideal width and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(kIdealWidth);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(kIdealWidth / kIdealAspectRatio, kIdealWidth), point);
  }

  // Ideal height, width and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().width.SetIdeal(kIdealWidth);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    // Ideal aspect ratio should be ignored.
    EXPECT_POINT_EQ(Point(kIdealHeight, kIdealWidth), point);
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionIdealOutsideSinglePoint) {
  // This set is a triangle with vertices (100,100), (1000,100) and (1000,1000).
  ResolutionSet set(100, 1000, 100, 1000, 0.0, 1.0);

  const int kIdealHeight = 50;
  const int kIdealWidth = 1100;
  const double kIdealAspectRatio = 0.09;
  const Point kVertex1(100, 100);
  const Point kVertex2(1000, 100);
  const Point kVertex3(1000, 1000);

  // Ideal height.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(kVertex1, point);
  }

  // Ideal width.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(kIdealWidth);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(kVertex3, point);
  }

  // Ideal aspect ratio.
  {
    factory_.Reset();
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(kVertex2, point);
  }

  // Ideal height and width.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().width.SetIdeal(kIdealWidth);
    Point point = SelectClosestPointToIdeal(set);
    Point expected = set.ClosestPointTo(Point(kIdealHeight, kIdealWidth));
    EXPECT_POINT_EQ(expected, point);
  }

  // Ideal height and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    Point expected = set.ClosestPointTo(
        Point(kIdealHeight, kIdealHeight * kIdealAspectRatio));
    EXPECT_POINT_EQ(expected, point);
  }

  // Ideal width and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(kIdealWidth);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    Point expected =
        set.ClosestPointTo(Point(kIdealWidth / kIdealAspectRatio, kIdealWidth));
    EXPECT_POINT_EQ(expected, point);
  }

  // Ideal height, width and aspect-ratio.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    factory_.basic().width.SetIdeal(kIdealWidth);
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    // kIdealAspectRatio is ignored if all three ideals are given.
    Point expected = set.ClosestPointTo(Point(kIdealHeight, kIdealWidth));
    EXPECT_POINT_EQ(expected, point);
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest,
       ResolutionIdealOutsideMultiplePoints) {
  // This set is a triangle with vertices (100,100), (1000,100) and (1000,1000).
  ResolutionSet set(100, 1000, 100, 1000, 0.0, 1.0);

  const int kIdealHeight = 1100;
  const int kIdealWidth = 50;
  const double kIdealAspectRatio = 11.0;
  const Point kVertex1(100, 100);
  const Point kVertex2(1000, 100);
  const Point kVertex3(1000, 1000);

  // Ideal height.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(kIdealHeight);
    Point point = SelectClosestPointToIdeal(set);
    // Parallel to the side between kVertex2 and kVertex3. Point closest to
    // default aspect ratio is kVertex3.
    EXPECT_POINT_EQ(kVertex3, point);
  }

  // Ideal width.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(kIdealWidth);
    Point point = SelectClosestPointToIdeal(set);
    // Parallel to the side between kVertex1 and kVertex2. Point closest to
    // default aspect ratio is kVertex1.
    EXPECT_POINT_EQ(kVertex1, point);
  }

  // Ideal aspect ratio.
  {
    factory_.Reset();
    factory_.basic().aspect_ratio.SetIdeal(kIdealAspectRatio);
    Point point = SelectClosestPointToIdeal(set);
    // The side between kVertex1 and kVertex3 is closest. The points closest to
    // default dimensions are (kDefaultHeight, kDefaultHeight * AR)
    // and (kDefaultWidth / AR, kDefaultWidth). Since the aspect ratio of the
    // polygon side is less than the default, the algorithm preserves the
    // default width.
    Point expected(kDefaultWidth / kVertex1.AspectRatio(), kDefaultWidth);
    EXPECT_POINT_EQ(expected, point);
    EXPECT_TRUE(set.ContainsPoint(expected));
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest,
       ResolutionUnconstrainedExtremeIdeal) {
  ResolutionSet set;

  // Ideal height.
  {
    factory_.Reset();
    factory_.basic().height.SetIdeal(std::numeric_limits<int32_t>::max());
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(
        Point(ResolutionSet::kMaxDimension, ResolutionSet::kMaxDimension),
        point);
    factory_.basic().height.SetIdeal(0);
    point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(0, 0), point);
  }

  // Ideal width.
  {
    factory_.Reset();
    factory_.basic().width.SetIdeal(std::numeric_limits<int32_t>::max());
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(ResolutionSet::kMaxDimension / kDefaultAspectRatio,
                          ResolutionSet::kMaxDimension),
                    point);
    factory_.basic().width.SetIdeal(0);
    point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(0, 0), point);
  }

  // Ideal Aspect Ratio.
  {
    factory_.Reset();
    factory_.basic().aspect_ratio.SetIdeal(HUGE_VAL);
    Point point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(0, ResolutionSet::kMaxDimension), point);
    factory_.basic().aspect_ratio.SetIdeal(0.0);
    point = SelectClosestPointToIdeal(set);
    EXPECT_POINT_EQ(Point(ResolutionSet::kMaxDimension, 0), point);
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ResolutionVertices) {
  // Empty set.
  {
    ResolutionSet set(1000, 100, 1000, 100, 0.5, 1.5);
    ASSERT_TRUE(set.IsEmpty());
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(0U, vertices.size());
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Three lines that intersect at the same point.
  {
    ResolutionSet set(1, 1, 1, 1, 1, 1);
    EXPECT_FALSE(set.IsEmpty());
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(1U, vertices.size());
    VerticesContain(vertices, Point(1, 1));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // A line segment with the lower-left and upper-right corner of the box.
  {
    ResolutionSet set(0, 100, 0, 100, 1.0, 1.0);
    EXPECT_FALSE(set.IsEmpty());
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(0, 0));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(0, 100, 0, 100, 1.0, HUGE_VAL);
    EXPECT_FALSE(set.IsEmpty());
    vertices = set.ComputeVertices();
    EXPECT_EQ(3U, vertices.size());
    VerticesContain(vertices, Point(0, 0));
    VerticesContain(vertices, Point(100, 100));
    VerticesContain(vertices, Point(0, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(0, 100, 0, 100, 0, 1.0);
    EXPECT_FALSE(set.IsEmpty());
    vertices = set.ComputeVertices();
    EXPECT_EQ(3U, vertices.size());
    VerticesContain(vertices, Point(0, 0));
    VerticesContain(vertices, Point(100, 100));
    VerticesContain(vertices, Point(100, 0));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // A line segment that crosses the bottom and right sides of the box.
  {
    const double kAspectRatio = 50.0 / 75.0;
    ResolutionSet set(50, 100, 50, 100, kAspectRatio, kAspectRatio);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, P
```