Response:
Let's break down the request and analyze the provided C++ code for `canvas_path_test.cc`.

**1. Understanding the Core Request:**

The request asks for a breakdown of the functionality of the `canvas_path_test.cc` file within the Chromium Blink engine. It specifically probes for connections to web technologies (JavaScript, HTML, CSS), asks for logical reasoning with input/output examples, common usage errors, and a debugging path leading to this code.

**2. Initial Code Analysis:**

* **Includes:** The `#include` directives tell us this is a C++ test file using the Google Test framework (`gtest/gtest.h`). It also includes Blink-specific headers related to canvas (`canvas_path.h`), execution context, graphics paths, and testing utilities.
* **Namespace:** The code is within the `blink` namespace, confirming its place within the Blink rendering engine.
* **`CanvasPathTest` Class:** This class inherits from `testing::Test`, making it a standard Google Test fixture. It sets up a test environment with a `NullExecutionContext`. The destructor ensures proper cleanup.
* **`TestCanvasPath` Class:** This is a custom class inheriting from `CanvasPath`. It's likely used to provide a concrete implementation or a simplified version of `CanvasPath` for testing purposes. It holds an `ExecutionContext`.
* **`TEST_F` Macros:** These macros define individual test cases within the `CanvasPathTest` fixture. Each test focuses on a specific aspect of the `CanvasPath` functionality.

**3. Deconstructing the Test Cases:**

I'll go through each `TEST_F` to understand what it's testing:

* **`Line`:** Tests the `moveTo` and `lineTo` methods. Verifies the `IsLine()` and `IsEmpty()` flags. Checks the start and end points of the line.
* **`LineBoundingRect`:**  Tests the calculation of the bounding rectangle for a line. It compares the bounding rectangle calculated by `CanvasPath` with one calculated from a `Path` created directly with Skia (the underlying graphics library).
* **`LineEquality` and `LineEquality2`:** Test whether two `CanvasPath` objects (or a `CanvasPath` and a `Path`) are considered equal after adding the same line segments.
* **`MultipleMoveTos`:** Checks how multiple `moveTo` calls affect the path.
* **`RectMoveToLineTo` and `MoveToLineToRect`:** Test the order of operations when adding a rectangle and then a line segment (and vice-versa).
* **`OnlyLineTo`:** Tests the behavior of `lineTo` when called on an empty path (it should implicitly do a `moveTo`).
* **`LineToLineTo`:** Tests consecutive `lineTo` calls.
* **`MoveToLineToMoveTo` and `MoveToMoveToLineTo`:** Test combinations of `moveTo` and `lineTo` calls.
* **`MoveToLineClosePath`:** Tests the `closePath()` method after drawing a line.
* **`Arc`:** Tests the `arc()` method and checks the `IsArc()` flag.
* **`ArcThenLine`:** Tests drawing an arc followed by a line segment.

**4. Connecting to Web Technologies:**

The `CanvasPath` class directly corresponds to the path operations defined in the HTML Canvas 2D API. The test cases are essentially verifying the correct implementation of these API methods.

**5. Logical Reasoning and Examples:**

For each test case, I can infer the expected input (the method calls on `CanvasPath`) and the expected output (the state of the `CanvasPath` object and comparisons with `Path`).

**6. Common User Errors:**

Based on the test cases, I can identify potential user errors, such as forgetting to `moveTo` before `lineTo`, or misunderstanding the behavior of `closePath`.

**7. Debugging Path:**

I need to think about how a developer might end up looking at this test file. This likely involves investigating issues related to canvas rendering or path manipulation in a web page.

**Planning Complete. Proceeding with Response Generation.**
## 功能列举

`blink/renderer/modules/canvas/canvas2d/canvas_path_test.cc` 文件是 Chromium Blink 引擎中，专门用于测试 `CanvasPath` 类的单元测试文件。  它的主要功能是：

1. **验证 `CanvasPath` 类的各种方法的功能是否正确**:  `CanvasPath` 类用于在 Canvas 2D API 中表示路径。这个测试文件会针对 `CanvasPath` 类的 `moveTo`, `lineTo`, `rect`, `closePath`, `arc` 等方法进行测试，确保它们按照规范工作。
2. **检查路径的状态**:  测试用例会检查路径是否为空 (`IsEmpty()`), 是否是一条直线 (`IsLine()`), 是否是一个弧线 (`IsArc()`).
3. **比较 `CanvasPath` 对象与其他路径表示**:  测试用例会将 `CanvasPath` 对象生成的路径与使用 `blink::Path` 类（Blink 内部的路径表示）生成的路径进行比较，以验证其正确性。
4. **测试路径的边界**:  测试用例会检查由 `CanvasPath` 生成的路径的边界矩形 (`BoundingRect()`) 是否正确。
5. **作为开发和调试的辅助**:  当 `CanvasPath` 类的代码被修改或添加新功能时，可以通过运行这些测试用例来快速验证修改是否引入了错误。

## 与 JavaScript, HTML, CSS 的关系

这个 C++ 测试文件直接测试的是 Blink 引擎内部的实现，但它所测试的功能是 Web 标准中 Canvas 2D API 的一部分，因此与 JavaScript, HTML, CSS 有着密切的关系。

**JavaScript 方面的举例说明:**

开发者在 JavaScript 中使用 Canvas 2D API 的路径操作方法，最终会调用到 Blink 引擎中 `CanvasPath` 类的相应方法。

* **`moveTo(x, y)`**:  JavaScript 中 `CanvasRenderingContext2D.moveTo(x, y)` 方法会在 Blink 内部调用 `CanvasPath::moveTo(x, y)`。`canvas_path_test.cc` 中的 `TEST_F(CanvasPathTest, Line)` 和 `TEST_F(CanvasPathTest, MultipleMoveTos)` 等测试用例就是为了验证这个方法的行为。
    * **假设输入 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.moveTo(10, 10);
    ctx.lineTo(50, 50);
    ```
    * **对应的 `CanvasPath` 操作:**  `CanvasPath` 对象会先执行 `moveTo(10, 10)`, 然后执行 `lineTo(50, 50)`。`TEST_F(CanvasPathTest, Line)` 就模拟了这种场景，并验证 `IsLine()` 返回 `true`，且起点和终点坐标正确。

* **`lineTo(x, y)`**: JavaScript 中 `CanvasRenderingContext2D.lineTo(x, y)` 方法对应 `CanvasPath::lineTo(x, y)`。`TEST_F(CanvasPathTest, Line)`, `TEST_F(CanvasPathTest, OnlyLineTo)` 等测试用例覆盖了不同场景下的 `lineTo` 方法。
    * **假设输入 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.lineTo(50, 50); // 在没有 moveTo 的情况下
    ```
    * **对应的 `CanvasPath` 操作:** `TEST_F(CanvasPathTest, OnlyLineTo)` 测试了这种情况，验证了即使没有先调用 `moveTo`, `lineTo` 也会隐式地执行 `moveTo` 到 `(50, 50)`。

* **`rect(x, y, width, height)`**: JavaScript 中的 `CanvasRenderingContext2D.rect(x, y, width, height)` 会在 Blink 内部转化为一系列 `CanvasPath` 的操作（通常是 `moveTo` 和多个 `lineTo`）。`TEST_F(CanvasPathTest, RectMoveToLineTo)` 和 `TEST_F(CanvasPathTest, MoveToLineToRect)` 测试了 `rect` 方法与其他路径方法结合使用的场景。
    * **假设输入 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.rect(10, 20, 30, 40);
    ctx.moveTo(0, 0);
    ctx.lineTo(100, 100);
    ```
    * **对应的 `CanvasPath` 操作:** `TEST_F(CanvasPathTest, RectMoveToLineTo)` 模拟了先调用 `rect` 再调用 `moveTo` 和 `lineTo` 的情况，并验证最终的路径是否与预期一致。

* **`closePath()`**: JavaScript 中的 `CanvasRenderingContext2D.closePath()` 对应 `CanvasPath::closePath()`。`TEST_F(CanvasPathTest, MoveToLineClosePath)` 验证了 `closePath` 的行为。
    * **假设输入 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.moveTo(10, 10);
    ctx.lineTo(50, 10);
    ctx.lineTo(50, 50);
    ctx.closePath();
    ```
    * **对应的 `CanvasPath` 操作:** `TEST_F(CanvasPathTest, MoveToLineClosePath)` 验证了调用 `closePath` 后，路径会闭合，并且 `IsLine()` 返回 `false`，因为路径不再仅仅是一条直线。

* **`arc(x, y, radius, startAngle, endAngle, anticlockwise)`**: JavaScript 中的 `CanvasRenderingContext2D.arc()` 对应 `CanvasPath::arc()`。`TEST_F(CanvasPathTest, Arc)` 和 `TEST_F(CanvasPathTest, ArcThenLine)` 验证了 `arc` 方法及其与其他方法的组合使用。
    * **假设输入 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.arc(100, 75, 50, 0, 1.5 * Math.PI);
    ```
    * **对应的 `CanvasPath` 操作:** `TEST_F(CanvasPathTest, Arc)` 验证了调用 `arc` 后，`IsArc()` 返回 `true`，并且生成的路径与预期一致。

**HTML 和 CSS 方面:**

HTML 中的 `<canvas>` 元素为 Canvas 2D API 提供了渲染的表面。JavaScript 代码操作 Canvas API 来绘制图形。CSS 可以用于设置 `<canvas>` 元素的样式，但这不直接影响 `CanvasPath` 的逻辑，`CanvasPath` 专注于路径的构建。

## 逻辑推理和假设输入输出

以下是一些测试用例的逻辑推理和假设输入输出示例：

**`TEST_F(CanvasPathTest, Line)`**

* **假设输入:**  先调用 `moveTo(0, 1)`，然后调用 `lineTo(2, 3)`。
* **逻辑推理:**  调用 `moveTo` 会将路径的起始点设置为 (0, 1)。调用 `lineTo` 会从当前点 (0, 1) 画一条直线到 (2, 3)。此时路径应该被认为是一条直线。
* **预期输出:** `IsLine()` 返回 `true`，`IsEmpty()` 返回 `false`，`path->line().start` 等于 `(0, 1)`，`path->line().end` 等于 `(2, 3)`。

**`TEST_F(CanvasPathTest, OnlyLineTo)`**

* **假设输入:**  直接调用 `lineTo(2, 3)`，没有先调用 `moveTo`。
* **逻辑推理:**  Canvas 2D API 规范规定，在没有当前路径的情况下调用 `lineTo` 会隐式地将路径的起始点设置为 `lineTo` 的终点。因此，相当于先执行了 `moveTo(2, 3)`，然后执行了 `lineTo(2, 3)`。
* **预期输出:** `IsEmpty()` 返回 `false`，`IsLine()` 返回 `true`，并且生成的路径等同于先 `moveTo(2, 3)` 再 `lineTo(2, 3)` 的路径。

**`TEST_F(CanvasPathTest, MoveToLineClosePath)`**

* **假设输入:**  调用 `moveTo(1, -1)`，然后调用 `lineTo(2, 3)`，最后调用 `closePath()`。
* **逻辑推理:**  `closePath()` 会将当前路径的最后一个点连接到起始点，形成一个闭合的子路径。虽然之前画了一条线段，但调用 `closePath` 后，路径不再仅仅是一条直线，而是一个闭合的形状。
* **预期输出:** `IsEmpty()` 返回 `false`，`IsLine()` 返回 `false`，并且生成的路径等同于先 `moveTo(1, -1)`，再 `lineTo(2, 3)`，最后 `closeSubpath()` (Blink 内部的路径闭合操作)。

## 用户或编程常见的使用错误

基于测试用例，可以推断出一些用户或编程常见的错误：

1. **忘记 `moveTo`**:  在开始绘制线条或形状之前，忘记调用 `moveTo` 来设置起始点。这可能导致意外的连接线或图形绘制在错误的位置。
    * **示例代码 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.lineTo(100, 100); // 忘记了 ctx.moveTo()
    ctx.stroke();
    ```
    * **调试线索:**  如果在调试时发现绘制的线段起点不在预期位置，或者出现意外的连接线，可以检查是否忘记了 `moveTo` 调用。`TEST_F(CanvasPathTest, OnlyLineTo)` 验证了这种情况下 `lineTo` 的隐式 `moveTo` 行为。

2. **错误地认为 `closePath` 总是会闭合路径到最初的 `moveTo` 点**:  如果中间有多次 `moveTo` 调用，`closePath` 只会闭合到当前子路径的起始点，而不是整个路径的起始点。
    * **示例代码 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.moveTo(10, 10);
    ctx.lineTo(50, 10);
    ctx.moveTo(10, 50);
    ctx.lineTo(50, 50);
    ctx.closePath(); // 只会闭合 (10, 50) 到 (50, 50)
    ctx.stroke();
    ```
    * **调试线索:**  如果期望闭合整个形状，但发现只闭合了部分，需要检查是否有多余的 `moveTo` 调用中断了当前的子路径。

3. **误解 `lineTo` 在空路径时的行为**:  初学者可能不清楚在没有 `moveTo` 的情况下调用 `lineTo` 会隐式地执行 `moveTo` 到 `lineTo` 的终点。
    * **示例代码 (JavaScript):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ctx.lineTo(100, 100);
    ctx.stroke();
    ```
    * **调试线索:**  如果期望绘制一条从原点开始的线段，但发现起点在 (100, 100)，可能是因为没有显式调用 `moveTo(0, 0)`。

## 用户操作如何一步步到达这里 (作为调试线索)

一个开发者在调试 Canvas 相关问题时，可能会按照以下步骤到达 `canvas_path_test.cc`：

1. **用户报告 Canvas 绘制错误:**  用户可能在网页上看到 Canvas 绘制的图形与预期不符，例如线条连接错误、形状不闭合、弧线绘制异常等。
2. **开发者尝试复现错误:**  开发者会尝试在本地环境中复现用户报告的问题，查看 JavaScript 代码中是否有明显的逻辑错误。
3. **怀疑是浏览器引擎的 Bug:**  如果 JavaScript 代码看起来没有问题，或者错误行为在不同浏览器中表现不一致，开发者可能会怀疑是浏览器引擎（例如 Blink）的实现存在 Bug。
4. **查找 Blink 相关的 Canvas 代码:**  开发者可能会开始搜索 Blink 引擎中与 Canvas 相关的代码。关键词可能包括 "Blink Canvas", "Canvas 2D", "Path API" 等。
5. **定位到 `CanvasPath` 类:**  通过代码搜索或浏览 Blink 的代码结构，开发者可能会找到 `blink/renderer/modules/canvas/canvas2d/canvas_path.h` 和 `canvas_path.cc`，了解到 `CanvasPath` 类负责管理 Canvas 的路径信息。
6. **查找 `CanvasPath` 的测试用例:**  为了验证 `CanvasPath` 的实现是否正确，开发者会查找相关的测试文件，通常测试文件会放在与被测试代码相同的或相邻的目录下，并且文件名中会包含 "test"。因此，开发者会找到 `blink/renderer/modules/canvas/canvas2d/canvas_path_test.cc`。
7. **阅读测试用例:**  开发者会阅读 `canvas_path_test.cc` 中的各个 `TEST_F`，了解 `CanvasPath` 的各种方法是如何被测试的，以及预期的行为是什么。这有助于开发者判断用户报告的错误是否是 Blink 引擎的 Bug，或者是否是用户代码使用不当。
8. **运行或修改测试用例:**  开发者可能会尝试运行这些测试用例，确保在他们的环境下这些测试都是通过的。如果怀疑是某个特定功能的 Bug，可能会修改现有的测试用例或者添加新的测试用例来复现和验证 Bug。
9. **调试 `CanvasPath` 的实现:**  如果确认是 Blink 的 Bug，开发者可能会使用调试器逐步执行 `CanvasPath` 的代码，查找错误的原因。

总而言之，`canvas_path_test.cc` 文件是 Blink 引擎保证 Canvas 2D API 实现正确性的重要组成部分，对于开发者理解 Canvas 的工作原理和排查相关问题非常有帮助。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_path_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_path.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/path.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/skia/include/core/SkPath.h"
#include "ui/gfx/geometry/skia_conversions.h"

// GoogleTest macros trigger a bug in IWYU:
// https://github.com/include-what-you-use/include-what-you-use/issues/1546
// IWYU pragma: no_include <string>

namespace blink {

class CanvasPathTest : public testing::Test {
 public:
  CanvasPathTest() = default;
  ~CanvasPathTest() override { context_->NotifyContextDestroyed(); }

 protected:
  test::TaskEnvironment task_environment_;
  Persistent<ExecutionContext> context_ =
      MakeGarbageCollected<NullExecutionContext>();
};

class TestCanvasPath : public GarbageCollected<TestCanvasPath>,
                       public CanvasPath {
 public:
  explicit TestCanvasPath(ExecutionContext* context)
      : execution_context_(context) {}

  ExecutionContext* GetTopExecutionContext() const override {
    return execution_context_.Get();
  }

  void Trace(Visitor* v) const override {
    CanvasPath::Trace(v);
    v->Trace(execution_context_);
  }

 private:
  Member<ExecutionContext> execution_context_;
};

TEST_F(CanvasPathTest, Line) {
  CanvasPath* path = MakeGarbageCollected<TestCanvasPath>(context_);
  EXPECT_FALSE(path->IsLine());
  EXPECT_TRUE(path->IsEmpty());
  const gfx::PointF start(0, 1);
  path->moveTo(start.x(), start.y());
  EXPECT_FALSE(path->IsEmpty());
  EXPECT_FALSE(path->IsLine());
  const gfx::PointF end(2, 3);
  path->lineTo(end.x(), end.y());
  EXPECT_TRUE(path->IsLine());
  EXPECT_EQ(path->line().start, start);
  EXPECT_EQ(path->line().end, end);
}

TEST_F(CanvasPathTest, LineBoundingRect) {
  CanvasPath* path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF start(0, 1);
  path->moveTo(start.x(), start.y());
  const gfx::PointF end(2, 3);
  path->lineTo(end.x(), end.y());
  EXPECT_TRUE(path->IsLine());

  SkPath sk_path;
  sk_path.moveTo(gfx::PointFToSkPoint(start));
  sk_path.lineTo(gfx::PointFToSkPoint(end));
  Path path_from_sk_path(sk_path);

  EXPECT_EQ(path->BoundingRect(), path_from_sk_path.BoundingRect());
}

TEST_F(CanvasPathTest, LineEquality) {
  CanvasPath* path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF start(0, 1);
  path->moveTo(start.x(), start.y());
  const gfx::PointF end(2, 3);
  path->lineTo(end.x(), end.y());
  EXPECT_TRUE(path->IsLine());

  Path path2;
  path2.MoveTo(start);
  path2.AddLineTo(end);

  EXPECT_EQ(path->GetPath(), path2);
}

TEST_F(CanvasPathTest, LineEquality2) {
  CanvasPath* path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF start(0, 1);
  path->moveTo(start.x(), start.y());
  Path path2;
  path2.MoveTo(start);
  EXPECT_EQ(path->GetPath(), path2);

  const gfx::PointF end(2, 3);
  path->lineTo(end.x(), end.y());
  EXPECT_TRUE(path->IsLine());

  path2.AddLineTo(end);

  EXPECT_EQ(path->GetPath(), path2);
}

TEST_F(CanvasPathTest, MultipleMoveTos) {
  CanvasPath* path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF start(0, 1);
  path->moveTo(start.x(), start.y());
  const gfx::PointF next(2, 3);
  path->moveTo(next.x(), next.y());

  SkPath sk_path;
  sk_path.moveTo(gfx::PointFToSkPoint(start));
  sk_path.moveTo(gfx::PointFToSkPoint(next));
  Path path_from_sk_path(sk_path);

  EXPECT_EQ(path->GetPath(), path_from_sk_path);
}

TEST_F(CanvasPathTest, RectMoveToLineTo) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::RectF rect(1, 2, 3, 4);
  const gfx::PointF start(0, 1);
  const gfx::PointF end(2, 3);
  canvas_path->rect(rect.x(), rect.y(), rect.width(), rect.height());
  canvas_path->moveTo(start.x(), start.y());
  canvas_path->lineTo(end.x(), end.y());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_FALSE(canvas_path->IsLine());
  Path path;
  path.AddRect(rect);
  path.MoveTo(start);
  path.AddLineTo(end);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, MoveToLineToRect) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::RectF rect(1, 2, 3, 4);
  const gfx::PointF start(0, 1);
  const gfx::PointF end(2, 3);
  canvas_path->moveTo(start.x(), start.y());
  canvas_path->lineTo(end.x(), end.y());
  canvas_path->rect(rect.x(), rect.y(), rect.width(), rect.height());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_FALSE(canvas_path->IsLine());
  Path path;
  path.MoveTo(start);
  path.AddLineTo(end);
  path.AddRect(rect);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, OnlyLineTo) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF end(2, 3);
  canvas_path->lineTo(end.x(), end.y());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_TRUE(canvas_path->IsLine());
  // CanvasPath::lineTo() when empty implicitly does a moveto.
  Path path;
  path.MoveTo(end);
  path.AddLineTo(end);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, LineToLineTo) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF start(1, -1);
  const gfx::PointF end(2, 3);
  canvas_path->lineTo(start.x(), start.y());
  canvas_path->lineTo(end.x(), end.y());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_FALSE(canvas_path->IsLine());
  // CanvasPath::lineTo() when empty implicitly does a moveto.
  Path path;
  path.MoveTo(start);
  path.AddLineTo(start);
  path.AddLineTo(end);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, MoveToLineToMoveTo) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF p1(1, -1);
  const gfx::PointF p2(2, 3);
  const gfx::PointF p3(2, 3);
  canvas_path->moveTo(p1.x(), p1.y());
  canvas_path->lineTo(p2.x(), p2.y());
  canvas_path->moveTo(p3.x(), p3.y());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_FALSE(canvas_path->IsLine());
  Path path;
  path.MoveTo(p1);
  path.AddLineTo(p2);
  path.MoveTo(p3);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, MoveToMoveToLineTo) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF p1(1, -1);
  const gfx::PointF p2(2, 3);
  const gfx::PointF p3(2, 3);
  canvas_path->moveTo(p1.x(), p1.y());
  canvas_path->moveTo(p2.x(), p2.y());
  canvas_path->lineTo(p3.x(), p3.y());
  EXPECT_FALSE(canvas_path->IsEmpty());
  EXPECT_FALSE(canvas_path->IsLine());
  Path path;
  path.MoveTo(p1);
  path.MoveTo(p2);
  path.AddLineTo(p3);
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, MoveToLineClosePath) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  const gfx::PointF p1(1, -1);
  const gfx::PointF p2(2, 3);
  canvas_path->moveTo(p1.x(), p1.y());
  canvas_path->lineTo(p2.x(), p2.y());
  canvas_path->closePath();
  EXPECT_FALSE(canvas_path->IsEmpty());
  // closePath() cancels the line.
  EXPECT_FALSE(canvas_path->IsLine());

  Path path;
  path.MoveTo(p1);
  path.AddLineTo(p2);
  path.CloseSubpath();
  EXPECT_EQ(canvas_path->GetPath(), path);
}

TEST_F(CanvasPathTest, Arc) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  NonThrowableExceptionState exception_state;
  canvas_path->arc(0, 1, 5, 2, 3, false, exception_state);
  EXPECT_TRUE(canvas_path->IsArc());

  Path path;
  path.AddArc(gfx::PointF(0, 1), 5, 2, 3);
  EXPECT_EQ(canvas_path->GetPath(), path);
  EXPECT_TRUE(canvas_path->IsArc());

  canvas_path->closePath();
  path.CloseSubpath();
  EXPECT_EQ(canvas_path->GetPath(), path);
  EXPECT_TRUE(canvas_path->IsArc());
}

TEST_F(CanvasPathTest, ArcThenLine) {
  CanvasPath* canvas_path = MakeGarbageCollected<TestCanvasPath>(context_);
  NonThrowableExceptionState exception_state;
  canvas_path->arc(0, 1, 5, 2, 3, false, exception_state);
  EXPECT_TRUE(canvas_path->IsArc());
  canvas_path->lineTo(8, 9);
  EXPECT_FALSE(canvas_path->IsArc());
  EXPECT_FALSE(canvas_path->IsLine());

  Path path;
  path.AddArc(gfx::PointF(0, 1), 5, 2, 3);
  path.AddLineTo(gfx::PointF(8, 9));
  EXPECT_EQ(canvas_path->GetPath(), path);
}

}  // namespace blink
```