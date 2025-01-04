Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is a part of a test file (`media_stream_constraints_util_sets_test.cc`) within the Chromium Blink engine. It appears to be testing the behavior of classes related to media stream constraints, specifically how different constraints (like resolution and aspect ratio) are represented and how they interact.

Here's a breakdown of the likely functionalities:

1. **`ResolutionSet` Class Testing:**  The code extensively tests a class named `ResolutionSet`. This class likely represents a set of valid resolutions based on various constraints. The tests focus on:
    - **Geometric Interpretation:** It seems to calculate and verify the vertices of a polygon representing the valid resolution space defined by min/max width, height, and aspect ratio.
    - **Edge Cases:** It covers scenarios where aspect ratio lines intersect the boundaries of the resolution space in different ways.
    - **Exact Resolution:** Tests the case where only a specific resolution is allowed.
    - **Zero Resolution:** Tests the specific case of an exact resolution of 0x0.

2. **`NumericRangeSet` Class Testing:**  The code tests a template class `NumericRangeSet`, which appears to represent a range of numeric values. The tests cover:
    - **Open and Closed Ranges:** Testing sets with minimum, maximum, or no bounds.
    - **Empty Ranges:** Explicitly testing empty sets and those resulting from invalid bounds.
    - **Intersection:** Testing the intersection of different ranges.
    - **Conversion from Constraints:** Testing how `NumericRangeSet` is created from `LongConstraint` objects (which likely represent user-defined constraints).

3. **`DiscreteSet` Class Testing:** The code tests a template class `DiscreteSet`, which represents a set of discrete values (strings and booleans in these tests). The tests cover:
    - **Universal Set:** A set containing all possible values.
    - **Constrained Sets:** Sets with explicitly listed allowed values.
    - **Empty Set:** A set containing no values.
    - **Intersection:** Testing the intersection of different discrete sets.

4. **`RescaleSetFromConstraint` Function Testing:**  This function seems to translate a `resize_mode` constraint (likely a string) into a `BoolSet` indicating whether rescaling is allowed.

**Relationship to JavaScript, HTML, and CSS:**

These C++ classes and tests are part of the underlying implementation of the WebRTC API, which is exposed to JavaScript.

- **JavaScript:**  JavaScript code uses the `getUserMedia()` API to request access to the user's camera or microphone. The constraints passed to `getUserMedia()` (e.g., `width`, `height`, `aspectRatio`, `resizeMode`) are processed by the browser's engine, eventually leading to the kind of logic being tested in this file.
- **HTML:**  HTML elements like `<video>` are used to display the media stream obtained via `getUserMedia()`. The constraints influence which camera resolutions and capabilities are negotiated and used.
- **CSS:**  While CSS doesn't directly influence the *constraints* themselves, it's used to style the `<video>` element and how the video is displayed on the page. If the negotiated video resolution doesn't match the CSS layout, the browser might need to perform scaling, which could relate to the `resizeMode` constraint.

**Hypothetical Input and Output for `ResolutionSet::ComputeVertices()`:**

- **Input:** `ResolutionSet` object configured with `minWidth=50`, `maxWidth=100`, `minHeight=50`, `maxHeight=100`, `minAspectRatio=1.0`, `maxAspectRatio=1.0`.
- **Output:** A vector of `Point` objects representing the vertices of the valid resolution space. In this case, since the aspect ratio is fixed at 1.0, the output would be `{(50, 50), (100, 100)}`.

**Common User/Programming Errors:**

- **Inconsistent Constraints:** Specifying minimum values greater than maximum values (e.g., `minWidth=100`, `maxWidth=50`). This would lead to an empty set of valid resolutions. The `NumericRangeSet` tests specifically check for this.
- **Invalid Aspect Ratio:** Providing non-positive values for `minAspectRatio` or `maxAspectRatio`.
- **Incorrect String Values for `resizeMode`:**  Providing values other than "none" or "rescale" when setting the `resizeMode` constraint. The `RescaleSetFromConstraint` tests handle this.

**User Operations to Reach This Code (Debugging Clues):**

1. **Webpage using `getUserMedia()`:** A user visits a webpage that uses JavaScript to access their camera.
2. **JavaScript `getUserMedia()` call:** The webpage's JavaScript code calls `navigator.mediaDevices.getUserMedia()` with specific constraints. For example:
   ```javascript
   navigator.mediaDevices.getUserMedia({
       video: {
           width: { min: 640, ideal: 1280, max: 1920 },
           height: { min: 480, ideal: 720, max: 1080 },
           aspectRatio: 1.777 // 16:9
       }
   })
   .then(stream => { /* ... */ })
   .catch(error => { /* ... */ });
   ```
3. **Browser processes constraints:** The browser's rendering engine (Blink, in this case) receives these constraints.
4. **Constraint processing logic:**  The code in files like `media_stream_constraints_util_sets_test.cc` is part of the unit tests for the code that *interprets and processes* these constraints. During development and testing, engineers would run these tests to ensure the constraint handling logic is correct. If a bug is found related to how resolution or aspect ratio constraints are handled, this test file would likely be modified or new tests added to cover the problematic scenario.

**Summary of Functionality (Part 2):**

This part of the test file continues to verify the functionality of the `ResolutionSet` class, specifically focusing on:

- **More Complex Intersections:** Testing scenarios where the aspect ratio constraints intersect the resolution boundaries in various ways, creating polygons with different numbers of vertices (triangles, quadrilaterals, pentagons, hexagons).
- **Edge Cases with Aspect Ratio:** Testing extreme aspect ratio values (0.0 and infinity) to ensure the code handles them correctly.
- **`ExactResolution` Test:**  Confirms that a `ResolutionSet` created with an exact resolution contains only that specific resolution and no others.
- **`ZeroExactResolution` Test:** Specifically tests the behavior when the exact resolution is 0x0.
- **`NumericRangeSet` Tests (Continued):** Tests the creation and manipulation of numeric ranges using the `NumericRangeSet` class, including:
    - Creation with double values.
    - Conversion from `LongConstraint` objects.
    - Creation with explicit bounds.
    - Creation from a single value.
- **`DiscreteSet` Tests (Continued):** Tests the creation and manipulation of discrete sets using the `DiscreteSet` class for both string and boolean values, including:
    - Universal sets.
    - Constrained sets with explicit elements.
    - Empty sets.
    - Intersection of sets.
- **`RescaleSetFromConstraints` Test:** Tests the function that determines the allowed "rescale" modes based on the provided constraints.

In essence, this part of the test file provides more in-depth and varied test cases to ensure the robustness and correctness of the classes responsible for representing and manipulating media stream constraints related to resolution, aspect ratio, and discrete values like resize modes.

这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_sets_test.cc的chromium blink引擎源代码文件的第二部分，与第一部分共同构成了对媒体流约束工具集中集合类（例如 ResolutionSet, NumericRangeSet, DiscreteSet）功能的单元测试。

**归纳一下它的功能：**

这部分测试用例主要集中在验证以下几个方面：

1. **`ResolutionSet` 类的复杂几何情况测试:**
   - 延续第一部分的测试，这部分着重测试了当宽高限制和宽高比限制组合在一起时，`ResolutionSet::ComputeVertices()` 方法计算出的有效分辨率区域的顶点是否正确。
   - 测试了各种复杂的相交情况，例如：
     - 宽高比约束线与矩形边界的左边和上边相交。
     - 宽高比约束线与矩形边界的底部和顶部相交。
     - 宽高比约束线与矩形边界的左边和右边相交。
     - 宽高比约束线恰好触及矩形的角。
     - 形成六边形、五边形等复杂形状的有效分辨率区域的情况。
   - 测试了两个宽高比约束都与矩形边界的同一侧相交的情况。
   - 测试了极端宽高比的情况（0.0 和 HUGE_VAL）。

2. **`ResolutionSet` 类的精确分辨率测试:**
   - **`ExactResolution` 测试:** 验证了通过 `ResolutionSet::FromExactResolution()` 创建的 `ResolutionSet` 对象是否只包含指定的精确分辨率，而不包含其周围的任何分辨率。
   - **`ZeroExactResolution` 测试:** 验证了当精确分辨率为 0x0 时，`ResolutionSet` 的行为是否符合预期，例如包含点 (0, 0)，并且宽高比的最小值为 0.0，最大值为无穷大。

3. **`NumericRangeSet` 类的测试 (double 类型):**
   - **`NumericRangeSetDouble` 测试:** 针对 `double` 类型的 `NumericRangeSet` 进行了更全面的测试，包括：
     - 测试了开放集合（没有最小值或最大值）。
     - 测试了受限集合（有明确的最小值和最大值）。
     - 测试了下界大于上界时集合为空的情况。
     - 测试了显式创建空集合的情况。
     - 测试了集合的交集运算，包括与部分开放集合和空集合的交集。

4. **`NumericRangeSet` 类从约束创建的测试:**
   - **`NumericRangeSetFromConstraint` 测试:** 验证了如何从 `LongConstraint` 对象创建 `NumericRangeSet` 对象，包括：
     - 精确值约束。
     - 最小值和最大值约束。
     - 只有最小值或只有最大值约束。
     - 没有指定任何值的约束。
   - **`NumericRangeSetFromConstraintWithBounds` 测试:** 验证了在指定了外部边界（lower_bound 和 upper_bound）的情况下，如何从 `LongConstraint` 对象创建 `NumericRangeSet` 对象，并确保生成的范围不会超出这些边界。
   - **`NumericRangeSetFromValue` 测试:** 验证了从单个数值创建 `NumericRangeSet` 对象时，生成的范围的最小值和最大值都等于该数值。

5. **`DiscreteSet` 类的测试 (string 和 bool 类型):**
   - **`DiscreteSetString` 测试:** 针对 `String` 类型的 `DiscreteSet` 进行了测试，包括：
     - 全集。
     - 受限集合（包含明确的字符串元素）。
     - 空集。
     - 集合的交集运算。
   - **`DiscreteSetBool` 测试:** 针对 `bool` 类型的 `DiscreteSet` 进行了测试，包括：
     - 全集。
     - 只包含 `true` 或 `false` 的集合。
     - 空集。
     - 集合的交集运算。
     - 测试了显式包含 `true` 和 `false` 的全集，并验证其 `FirstElement()` 的行为。

6. **`RescaleSetFromConstraints` 函数的测试:**
   - **`RescaleSetFromConstraints` 测试:** 验证了 `RescaleSetFromConstraint` 函数如何根据 `MediaTrackConstraintSet` 中的 `resize_mode` 约束生成 `BoolSet` 对象，以表示是否允许调整大小。
   - 测试了各种 `resize_mode` 的值，包括：
     - 没有设置 `resize_mode`。
     - 无效的 `resize_mode` 值。
     - `"none"`（不允许调整大小）。
     - `"rescale"`（允许调整大小）。
     - 同时指定 `"none"` 和 `"rescale"`。

总而言之，这部分测试用例继续深入地测试了媒体流约束工具集中集合类的各种功能，覆盖了更复杂的场景和边界情况，确保这些类能够正确地表示和处理各种媒体流约束。这些测试对于保证 Chromium 浏览器在处理 WebRTC 媒体流约束时的正确性和稳定性至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_constraints_util_sets_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
oint(100, 100.0 * kAspectRatio));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 50, 100, kAspectRatio, HUGE_VAL);
    vertices = set.ComputeVertices();
    EXPECT_EQ(5U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, Point(100, 100.0 * kAspectRatio));
    VerticesContain(vertices, Point(50, 50));
    VerticesContain(vertices, Point(50, 100));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 50, 100, 0.0, kAspectRatio);
    vertices = set.ComputeVertices();
    EXPECT_EQ(3U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, Point(100, 100.0 * kAspectRatio));
    VerticesContain(vertices, Point(100, 50));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // A line segment that crosses the left and top sides of the box.
  {
    const double kAspectRatio = 75.0 / 50.0;
    ResolutionSet set(50, 100, 50, 100, kAspectRatio, kAspectRatio);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 50, 100, kAspectRatio, HUGE_VAL);
    vertices = set.ComputeVertices();
    EXPECT_EQ(3U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    VerticesContain(vertices, Point(50, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 50, 100, 0.0, kAspectRatio);
    vertices = set.ComputeVertices();
    EXPECT_EQ(5U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    VerticesContain(vertices, Point(50, 50));
    VerticesContain(vertices, Point(100, 100));
    VerticesContain(vertices, Point(100, 50));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // An aspect ratio constraint crosses the bottom and top sides of the box.
  {
    const double kAspectRatio = 75.0 / 50.0;
    ResolutionSet set(0, 100, 50, 100, kAspectRatio, kAspectRatio);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(0, 100, 50, 100, kAspectRatio, HUGE_VAL);
    vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    VerticesContain(vertices, Point(0, 50));
    VerticesContain(vertices, Point(0, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(0, 100, 50, 100, 0.0, kAspectRatio);
    vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50 / kAspectRatio, 50));
    VerticesContain(vertices, Point(100 / kAspectRatio, 100));
    VerticesContain(vertices, Point(100, 50));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // An aspect-ratio constraint crosses the left and right sides of the box.
  {
    const double kAspectRatio = 75.0 / 50.0;
    ResolutionSet set(50, 100, 0, 200, kAspectRatio, kAspectRatio);
    auto vertices = set.ComputeVertices();
    // This one fails if floating-point precision is too high.
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100, 100 * kAspectRatio));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 0, 200, kAspectRatio, HUGE_VAL);
    vertices = set.ComputeVertices();
    // This one fails if floating-point precision is too high.
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100, 100 * kAspectRatio));
    VerticesContain(vertices, Point(50, 200));
    VerticesContain(vertices, Point(100, 200));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 0, 200, 0.0, kAspectRatio);
    vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * kAspectRatio));
    VerticesContain(vertices, Point(100, 100 * kAspectRatio));
    VerticesContain(vertices, Point(50, 0));
    VerticesContain(vertices, Point(100, 0));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Aspect-ratio lines touch the corners of the box.
  {
    ResolutionSet set(50, 100, 50, 100, 0.5, 2.0);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50, 50));
    VerticesContain(vertices, Point(100, 50));
    VerticesContain(vertices, Point(50, 100));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Hexagons.
  {
    ResolutionSet set(10, 100, 10, 100, 0.5, 1.5);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(6U, vertices.size());
    VerticesContain(vertices, Point(10, 10));
    VerticesContain(vertices, Point(100, 100));
    VerticesContain(vertices, Point(10, 10 * 1.5));
    VerticesContain(vertices, Point(100 / 1.5, 100));
    VerticesContain(vertices, Point(10 / 0.5, 10));
    VerticesContain(vertices, Point(100, 100 * 0.5));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 50, 100, 50.0 / 75.0, 75.0 / 50.0);
    vertices = set.ComputeVertices();
    EXPECT_EQ(6U, vertices.size());
    VerticesContain(vertices, Point(50, 50));
    VerticesContain(vertices, Point(100, 100));
    VerticesContain(vertices, Point(75, 50));
    VerticesContain(vertices, Point(50, 75));
    VerticesContain(vertices, Point(100, 100.0 * 50.0 / 75.0));
    VerticesContain(vertices, Point(100 * 50.0 / 75.0, 100.0));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Both aspect-ratio constraints cross the left and top sides of the box.
  {
    ResolutionSet set(10, 100, 10, 100, 1.5, 1.7);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(10, 10 * 1.5));
    VerticesContain(vertices, Point(10, 10 * 1.7));
    VerticesContain(vertices, Point(100 / 1.5, 100));
    VerticesContain(vertices, Point(100 / 1.7, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Both aspect-ratio constraints cross the left and right sides of the box.
  {
    ResolutionSet set(10, 100, 10, ResolutionSet::kMaxDimension, 1.5, 1.7);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(10, 10 * 1.5));
    VerticesContain(vertices, Point(10, 10 * 1.7));
    VerticesContain(vertices, Point(100, 100 * 1.5));
    VerticesContain(vertices, Point(100, 100 * 1.7));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Both aspect-ratio constraints cross the bottom and top sides of the box.
  {
    ResolutionSet set(10, 100, 50, 100, 2.0, 4.0);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50 / 2.0, 50));
    VerticesContain(vertices, Point(100 / 2.0, 100));
    VerticesContain(vertices, Point(50 / 4.0, 50));
    VerticesContain(vertices, Point(100 / 4.0, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Both aspect-ratio constraints cross the bottom and right sides of the box.
  {
    ResolutionSet set(10, 100, 50, 100, 0.7, 0.9);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(4U, vertices.size());
    VerticesContain(vertices, Point(50 / 0.7, 50));
    VerticesContain(vertices, Point(50 / 0.9, 50));
    VerticesContain(vertices, Point(100, 100 * 0.7));
    VerticesContain(vertices, Point(100, 100 * 0.9));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Pentagons.
  {
    ResolutionSet set(10, 100, 50, 100, 0.7, 4.0);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(5U, vertices.size());
    VerticesContain(vertices, Point(50 / 0.7, 50));
    VerticesContain(vertices, Point(100, 100 * 0.7));
    VerticesContain(vertices, Point(50 / 4.0, 50));
    VerticesContain(vertices, Point(100 / 4.0, 100));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(50, 100, 10, 100, 0.7, 1.5);
    vertices = set.ComputeVertices();
    EXPECT_EQ(5U, vertices.size());
    VerticesContain(vertices, Point(50, 50 * 0.7));
    VerticesContain(vertices, Point(100, 100 * 0.7));
    VerticesContain(vertices, Point(50, 50 * 1.5));
    VerticesContain(vertices, Point(100 / 1.5, 100));
    VerticesContain(vertices, Point(100, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }

  // Extreme aspect ratios, for completeness.
  {
    ResolutionSet set(0, 100, 0, ResolutionSet::kMaxDimension, 0.0, 0.0);
    auto vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(0, 0));
    VerticesContain(vertices, Point(100, 0));
    EXPECT_TRUE(AreValidVertices(set, vertices));

    set = ResolutionSet(0, ResolutionSet::kMaxDimension, 0, 100, HUGE_VAL,
                        HUGE_VAL);
    vertices = set.ComputeVertices();
    EXPECT_EQ(2U, vertices.size());
    VerticesContain(vertices, Point(0, 0));
    VerticesContain(vertices, Point(0, 100));
    EXPECT_TRUE(AreValidVertices(set, vertices));
  }
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ExactResolution) {
  const int kExactWidth = 640;
  const int kExactHeight = 480;
  ResolutionSet set =
      ResolutionSet::FromExactResolution(kExactWidth, kExactHeight);
  EXPECT_TRUE(set.ContainsPoint(kExactHeight, kExactWidth));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight - 1, kExactWidth - 1));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight - 1, kExactWidth));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight - 1, kExactWidth + 1));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight, kExactWidth - 1));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight, kExactWidth + 1));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight + 1, kExactWidth - 1));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight + 1, kExactWidth));
  EXPECT_FALSE(set.ContainsPoint(kExactHeight + 1, kExactWidth + 1));
  EXPECT_FALSE(set.ContainsPoint(1, 1));
  EXPECT_FALSE(set.ContainsPoint(2000, 2000));
  EXPECT_FALSE(set.IsHeightEmpty());
  EXPECT_FALSE(set.IsWidthEmpty());
  EXPECT_FALSE(set.IsAspectRatioEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, ZeroExactResolution) {
  ResolutionSet set = ResolutionSet::FromExactResolution(0, 0);
  EXPECT_TRUE(set.ContainsPoint(0, 0));
  EXPECT_EQ(set.min_aspect_ratio(), 0.0);
  EXPECT_EQ(set.max_aspect_ratio(), HUGE_VAL);
}

TEST_F(MediaStreamConstraintsUtilSetsTest, NumericRangeSetDouble) {
  using DoubleRangeSet = media_constraints::NumericRangeSet<double>;
  // Open set.
  DoubleRangeSet set;
  EXPECT_FALSE(set.Min().has_value());
  EXPECT_FALSE(set.Max().has_value());
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_TRUE(set.Contains(0.0));
  EXPECT_TRUE(set.Contains(1.0));
  EXPECT_TRUE(set.Contains(HUGE_VAL));
  EXPECT_TRUE(set.Contains(-1.0));

  // Constrained set.
  const double kMin = 1.0;
  const double kMax = 10.0;
  set = DoubleRangeSet(kMin, kMax);
  EXPECT_EQ(kMin, *set.Min());
  EXPECT_EQ(kMax, *set.Max());
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_FALSE(set.Contains(0.0));
  EXPECT_TRUE(set.Contains(1.0));
  EXPECT_TRUE(set.Contains(10.0));
  EXPECT_FALSE(set.Contains(HUGE_VAL));
  EXPECT_FALSE(set.Contains(-1.0));

  // If the lower bound is greater than the upper bound, the set is empty.
  set = DoubleRangeSet(kMax, kMin);
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.Contains(0.0));
  EXPECT_FALSE(set.Contains(1.0));
  EXPECT_FALSE(set.Contains(HUGE_VAL));
  EXPECT_FALSE(set.Contains(-1.0));

  // An explicit empty set is empty.
  set = DoubleRangeSet::EmptySet();
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.Contains(0.0));
  EXPECT_FALSE(set.Contains(1.0));
  EXPECT_FALSE(set.Contains(HUGE_VAL));
  EXPECT_FALSE(set.Contains(-1.0));

  // Intersection.
  set = DoubleRangeSet(kMin, kMax);
  const double kMin2 = 5.0;
  const double kMax2 = 20.0;
  auto intersection = set.Intersection(DoubleRangeSet(kMin2, kMax2));
  EXPECT_EQ(kMin2, intersection.Min());
  EXPECT_EQ(kMax, intersection.Max());
  EXPECT_FALSE(intersection.IsEmpty());

  // Intersection with partially open sets.
  set = DoubleRangeSet(std::nullopt, kMax);
  intersection = set.Intersection(DoubleRangeSet(kMin2, std::nullopt));
  EXPECT_EQ(kMin2, *intersection.Min());
  EXPECT_EQ(kMax, *intersection.Max());
  EXPECT_FALSE(intersection.IsEmpty());

  // Empty intersection.
  intersection = set.Intersection(DoubleRangeSet(kMax + 1, HUGE_VAL));
  EXPECT_TRUE(intersection.IsEmpty());

  // Intersection with empty set.
  intersection = set.Intersection(DoubleRangeSet::EmptySet());
  EXPECT_TRUE(intersection.IsEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, NumericRangeSetFromConstraint) {
  // Exact value translates in a range with a single value.
  LongConstraint constraint = LongConstraint("aConstraint");
  constraint.SetExact(10);
  media_constraints::NumericRangeSet<int> range =
      media_constraints::NumericRangeSet<int>::FromConstraint(constraint);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 10);
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 10);

  // A constraint with min and max translates to range with same min and same
  // max.
  constraint = LongConstraint("aConstraint");
  constraint.SetMin(0);
  constraint.SetMax(100);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(constraint);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 0);
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 100);

  // A constraint with only a min or a max value translates to a half-bounded
  // set in both cases.
  constraint = LongConstraint("aConstraint");
  constraint.SetMin(0);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(constraint);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 0);
  EXPECT_FALSE(range.Max());

  constraint = LongConstraint("aConstraint");
  constraint.SetMax(100);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(constraint);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 100);
  EXPECT_FALSE(range.Min());

  // A constraint with no values specified maps to an unbounded range.
  constraint = LongConstraint("aConstraint");
  range = media_constraints::NumericRangeSet<int>::FromConstraint(constraint);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_FALSE(range.Min());
  EXPECT_FALSE(range.Max());
}

TEST_F(MediaStreamConstraintsUtilSetsTest,
       NumericRangeSetFromConstraintWithBounds) {
  int upper_bound = 25;
  int lower_bound = 5;
  // Exact value translates in a range with a single value.
  LongConstraint constraint = LongConstraint("aConstraint");
  constraint.SetExact(10);
  media_constraints::NumericRangeSet<int> range =
      media_constraints::NumericRangeSet<int>::FromConstraint(
          constraint, lower_bound, upper_bound);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 10);
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 10);

  // A constraint with min and max translates to range with same min and same
  // max. If lower and upper bound do not permit that, will have unspecified
  // min and max respectively.
  constraint = LongConstraint("aConstraint");
  constraint.SetMin(0);
  constraint.SetMax(100);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(constraint, 0,
                                                                  100);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 0);
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 100);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_FALSE(range.Min());
  EXPECT_FALSE(range.Max());

  // A constraint with only a min or a max value translates to a half-bounded
  // or unbounded range depending on the whether the lower and the upper bounds
  // allow for it.
  constraint = LongConstraint("aConstraint");
  constraint.SetMin(0);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_FALSE(range.Min());
  EXPECT_FALSE(range.Max());

  constraint = LongConstraint("aConstraint");
  constraint.SetMax(100);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_FALSE(range.Min());
  EXPECT_FALSE(range.Max());

  // A constraint with no values specified maps to an unbounded range
  // independently of upper and lower bounds.
  constraint = LongConstraint("aConstraint");
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_FALSE(range.Min());
  EXPECT_FALSE(range.Max());

  // If the constraint specifies a range that does not overlap with lower and
  // upper bounds, the resulting range will be empty.
  constraint = LongConstraint("aConstraint");
  constraint.SetMin(-5);
  constraint.SetMax(0);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_TRUE(range.IsEmpty());

  constraint = LongConstraint("aConstraint");
  constraint.SetMin(105);
  constraint.SetMax(110);
  range = media_constraints::NumericRangeSet<int>::FromConstraint(
      constraint, lower_bound, upper_bound);
  EXPECT_TRUE(range.IsEmpty());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, NumericRangeSetFromValue) {
  // Getting a range from a single value, will return a range with a single
  // value set as both max and min.
  auto range = media_constraints::NumericRangeSet<int>::FromValue(0);
  EXPECT_FALSE(range.IsEmpty());
  EXPECT_TRUE(range.Min());
  EXPECT_EQ(*range.Min(), 0);
  EXPECT_TRUE(range.Max());
  EXPECT_EQ(*range.Max(), 0);
}

TEST_F(MediaStreamConstraintsUtilSetsTest, DiscreteSetString) {
  // Universal set.
  using StringSet = media_constraints::DiscreteSet<String>;
  StringSet set = StringSet::UniversalSet();
  EXPECT_TRUE(set.Contains("arbitrary"));
  EXPECT_TRUE(set.Contains("strings"));
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_TRUE(set.is_universal());
  EXPECT_FALSE(set.HasExplicitElements());

  // Constrained set.
  set = StringSet(Vector<String>({"a", "b", "c"}));
  EXPECT_TRUE(set.Contains("a"));
  EXPECT_TRUE(set.Contains("b"));
  EXPECT_TRUE(set.Contains("c"));
  EXPECT_FALSE(set.Contains("d"));
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_FALSE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_EQ(String("a"), set.FirstElement());

  // Empty set.
  set = StringSet::EmptySet();
  EXPECT_FALSE(set.Contains("a"));
  EXPECT_FALSE(set.Contains("b"));
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.is_universal());
  EXPECT_FALSE(set.HasExplicitElements());

  // Intersection.
  set = StringSet(Vector<String>({"a", "b", "c"}));
  StringSet set2 = StringSet(Vector<String>({"b", "c", "d"}));
  auto intersection = set.Intersection(set2);
  EXPECT_FALSE(intersection.Contains("a"));
  EXPECT_TRUE(intersection.Contains("b"));
  EXPECT_TRUE(intersection.Contains("c"));
  EXPECT_FALSE(intersection.Contains("d"));
  EXPECT_FALSE(intersection.IsEmpty());
  EXPECT_FALSE(intersection.is_universal());
  EXPECT_TRUE(intersection.HasExplicitElements());
  EXPECT_EQ(String("b"), intersection.FirstElement());

  // Empty intersection.
  set2 = StringSet(Vector<String>({"d", "e", "f"}));
  intersection = set.Intersection(set2);
  EXPECT_FALSE(intersection.Contains("a"));
  EXPECT_FALSE(intersection.Contains("b"));
  EXPECT_FALSE(intersection.Contains("c"));
  EXPECT_FALSE(intersection.Contains("d"));
  EXPECT_TRUE(intersection.IsEmpty());
  EXPECT_FALSE(intersection.is_universal());
  EXPECT_FALSE(intersection.HasExplicitElements());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, DiscreteSetBool) {
  // Universal set.
  BoolSet set = BoolSet::UniversalSet();
  EXPECT_TRUE(set.Contains(true));
  EXPECT_TRUE(set.Contains(false));
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_TRUE(set.is_universal());
  EXPECT_FALSE(set.HasExplicitElements());

  // Constrained set.
  set = BoolSet({true});
  EXPECT_TRUE(set.Contains(true));
  EXPECT_FALSE(set.Contains(false));
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_FALSE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_TRUE(set.FirstElement());

  set = BoolSet({false});
  EXPECT_FALSE(set.Contains(true));
  EXPECT_TRUE(set.Contains(false));
  EXPECT_FALSE(set.IsEmpty());
  EXPECT_FALSE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_FALSE(set.FirstElement());

  // Empty set.
  set = BoolSet::EmptySet();
  EXPECT_FALSE(set.Contains(true));
  EXPECT_FALSE(set.Contains(false));
  EXPECT_TRUE(set.IsEmpty());
  EXPECT_FALSE(set.is_universal());
  EXPECT_FALSE(set.HasExplicitElements());

  // Intersection.
  set = BoolSet::UniversalSet();
  auto intersection = set.Intersection(BoolSet({true}));
  EXPECT_TRUE(intersection.Contains(true));
  EXPECT_FALSE(intersection.Contains(false));
  intersection = set.Intersection(set);
  EXPECT_TRUE(intersection.Contains(true));
  EXPECT_TRUE(intersection.Contains(true));

  // Empty intersection.
  set = BoolSet({true});
  intersection = set.Intersection(BoolSet({false}));
  EXPECT_TRUE(intersection.IsEmpty());

  // Explicit universal set with true as the first element.
  // This cannot result from a boolean constraint because they can only specify
  // one exact value.
  set = BoolSet({true, false});
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_TRUE(set.FirstElement());
  intersection = set.Intersection(BoolSet());
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_TRUE(set.FirstElement());
  intersection = BoolSet().Intersection(set);
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_TRUE(set.FirstElement());

  // Explicit universal set with false as the first element.
  // This cannot result from a boolean constraint because they can only specify
  // one exact value.
  set = BoolSet({false, true});
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_FALSE(set.FirstElement());
  intersection = set.Intersection(BoolSet());
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_FALSE(set.FirstElement());
  intersection = BoolSet().Intersection(set);
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_FALSE(set.FirstElement());

  // Intersection of explicit universal sets with different first elements.
  // This cannot result from boolean constraints because they can only specify
  // one exact value. The first element of the left-hand side is selected as the
  // first element of the intersection.
  set = BoolSet({true, false}).Intersection(BoolSet({false, true}));
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_TRUE(set.FirstElement());
  set = BoolSet({false, true}).Intersection(BoolSet({true, false}));
  EXPECT_TRUE(set.is_universal());
  EXPECT_TRUE(set.HasExplicitElements());
  EXPECT_FALSE(set.FirstElement());
}

TEST_F(MediaStreamConstraintsUtilSetsTest, RescaleSetFromConstraints) {
  factory_.Reset();
  factory_.CreateMediaConstraints();
  BoolSet set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_TRUE(set.is_universal());
  EXPECT_FALSE(set.HasExplicitElements());

  // Invalid exact value.
  factory_.basic().resize_mode.SetExact("invalid");
  set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_TRUE(set.IsEmpty());

  // No rescaling
  factory_.basic().resize_mode.SetExact(WebMediaStreamTrack::kResizeModeNone);
  set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_TRUE(set.Contains(false));
  EXPECT_FALSE(set.Contains(true));

  // Rescaling
  factory_.basic().resize_mode.SetExact(
      WebMediaStreamTrack::kResizeModeRescale);
  set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_TRUE(set.Contains(true));
  EXPECT_FALSE(set.Contains(false));

  // Both explicit
  Vector<String> rescale_modes = {WebMediaStreamTrack::kResizeModeRescale,
                                  WebMediaStreamTrack::kResizeModeNone};
  factory_.basic().resize_mode.SetExact(rescale_modes);
  set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_TRUE(set.Contains(true));
  EXPECT_TRUE(set.Contains(false));

  // Invalid and no rescaling.
  rescale_modes[0] = "invalid";
  factory_.basic().resize_mode.SetExact(Vector<String>(rescale_modes));
  set =
      media_constraints::RescaleSetFromConstraint(factory_.basic().resize_mode);
  EXPECT_FALSE(set.Contains(true));
  EXPECT_TRUE(set.Contains(false));
}

}  // namespace media_constraints
}  // namespace blink

"""


```