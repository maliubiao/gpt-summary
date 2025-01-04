Response:
My thought process for analyzing the code and generating the summary goes like this:

1. **Understand the Core Purpose:** The filename `display_item_raster_invalidator_test.cc` immediately suggests this is a *test file*. The presence of `Invalidator` and `Raster` hints at its function: testing the mechanism for invalidating (marking as needing redraw) parts of the rendered output (rasters) based on changes to display items.

2. **Identify Key Classes:** I scan the code for the main classes involved. `DisplayItemRasterInvalidator` and `RasterInvalidator` are central. The `PaintControllerTestBase`, `PaintTestConfigurations`, and `TestPaintArtifact` point to the testing framework. `FakeDisplayItemClient` is clearly a mock object used for setting up test scenarios.

3. **Analyze the Test Structure:**  The code uses the Google Test framework (evident by `TEST_P`, `EXPECT_THAT`, and the general structure). Each `TEST_P` function represents a specific test case. The setup within each test typically involves:
    * Creating `FakeDisplayItemClient` instances to represent different elements on the page.
    * Using `RasterInvalidationPaintController` and `GraphicsContext` to simulate the painting process and create display items.
    * Performing some action (e.g., invalidating an item, changing its geometry, reordering).
    * Using `invalidator_->SetTracksRasterInvalidations(true)` to activate the invalidation tracking.
    * Repeating the painting process *after* the action.
    * Using `EXPECT_THAT(GetRasterInvalidations(), ...)` to assert the expected invalidation regions and reasons.

4. **Deconstruct Test Cases:** I go through each `TEST_P` function and try to understand what specific scenario it's testing:
    * **`FullInvalidationWithoutLayoutChange`**: A basic invalidation without any changes to the size or position of the element.
    * **`FullInvalidationWithGeometryChange`**: An invalidation where the element's position changes.
    * **`RemoveItemInMiddle`**: Testing what happens when an element is removed from the display list.
    * **`SwapOrder`**: Testing the impact of changing the order of elements (z-index change).
    * **`SwapOrderAndInvalidateFirst/Second`**: Combining reordering with explicit invalidation of one of the swapped elements.
    * **`SwapOrderWithIncrementalInvalidation`**: Checking if incremental invalidation is handled correctly during reordering.
    * **`NewItemInMiddle`**:  Testing the case where a new element is added.
    * **`Incremental`**: Focused on testing *partial* invalidation (only the changed parts of an element).
    * **`AddRemoveFirstAndInvalidateSecond` / `InvalidateFirstAndAddRemoveSecond`**:  Testing combinations of adding/removing elements and invalidating others.
    * **`SwapOrderWithChildren` / `SwapOrderWithChildrenAndInvalidation`**:  Testing how reordering and invalidation propagate through parent-child relationships.
    * **`SwapOrderCrossingChunks`**:  (The provided snippet ends mid-test, but the name suggests it's testing reordering across different paint chunks, which are optimization units.)

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  I think about how the tested scenarios correspond to common web development actions:
    * **JavaScript**: Modifying element styles (size, position, visibility), adding or removing elements from the DOM, changing z-index.
    * **HTML**: The structure of the DOM creates the initial display list.
    * **CSS**: Styles determine the visual appearance and layout of elements, influencing the paint process.

6. **Identify Potential User/Programming Errors:** I consider common mistakes developers might make that these tests implicitly check for, such as:
    * Forgetting to invalidate an element after changing its properties.
    * Incorrectly assuming that changing an element's order won't trigger a repaint.
    * Not understanding how incremental invalidation works.

7. **Formulate the Summary:** Based on the above analysis, I synthesize a concise summary highlighting the file's core purpose and its relationship to web technologies. I focus on the key functionality being tested: tracking invalidations due to layout changes, geometry changes, element removal/addition, and reordering. I also connect these scenarios to how they manifest in JavaScript, HTML, and CSS.

8. **Refine and Organize:** I organize the information logically, starting with the primary function and then elaborating on specific aspects and their relation to web technologies. I ensure the language is clear and avoids overly technical jargon where possible. I explicitly mention that it's a test file to provide context.这是 Chromium Blink 引擎源代码文件 `display_item_raster_invalidator_test.cc` 的第一部分，它的主要功能是 **测试 `DisplayItemRasterInvalidator` 类，该类负责跟踪并记录由于各种原因（例如布局变化、属性变化、元素出现或消失、元素重新排序）导致的渲染区域失效（raster invalidation）**。

简单来说，这个文件就像一个单元测试套件，用来验证 `DisplayItemRasterInvalidator` 是否能够正确地识别出哪些屏幕区域需要重新绘制，以及为什么需要重新绘制。

以下是更详细的功能分解和与 JavaScript, HTML, CSS 的关系，以及逻辑推理、用户/编程常见错误举例：

**功能归纳:**

1. **测试渲染失效跟踪:**  核心功能是测试 `DisplayItemRasterInvalidator` 是否能准确跟踪由于各种操作引起的渲染失效。
2. **模拟不同的渲染场景:**  通过创建 `FakeDisplayItemClient` 模拟不同的渲染对象，并在不同的渲染周期中进行操作（例如，移动、添加、删除、改变层叠顺序）。
3. **验证失效信息:**  使用 `EXPECT_THAT` 等断言宏，验证 `DisplayItemRasterInvalidator` 记录的失效信息（例如，失效的元素 ID、元素名称、失效区域、失效原因）是否与预期一致。
4. **覆盖多种失效原因:** 测试了包括布局变化 (`kLayout`)、元素消失 (`kDisappeared`)、元素重新排序 (`kReordered`)、元素出现 (`kAppeared`) 以及增量失效 (`kIncremental`) 等多种失效原因。
5. **使用 PaintController 进行渲染模拟:** 利用 `RasterInvalidationPaintController` 和 `GraphicsContext` 来模拟 Blink 引擎的渲染流程，并生成 Display Items。

**与 JavaScript, HTML, CSS 的关系及举例:**

`DisplayItemRasterInvalidator` 的工作直接关系到浏览器如何响应 JavaScript, HTML, CSS 的变化并更新屏幕显示。

* **JavaScript:** 当 JavaScript 代码修改 DOM 结构或元素样式时，可能会触发渲染失效。
    * **例 1 (修改样式):**  假设 JavaScript 代码通过 `element.style.left = '200px'` 移动了一个 HTML 元素的位置。`DisplayItemRasterInvalidator` 应该能够跟踪到这个元素的几何位置发生了变化，并记录相应的失效区域和失效原因 (`kLayout`)。
    * **例 2 (添加/删除元素):** 如果 JavaScript 使用 `appendChild` 添加了一个新的 HTML 元素，或者使用 `removeChild` 删除了一个元素，`DisplayItemRasterInvalidator` 应该能够记录新元素的出现 (`kAppeared`) 或者旧元素的消失 (`kDisappeared`)，并标记相关的渲染区域失效。

* **HTML:** HTML 结构定义了页面的初始渲染内容。当 HTML 结构发生变化（通过 JavaScript 操作 DOM），会影响渲染失效。

* **CSS:** CSS 样式规则决定了元素的视觉呈现。CSS 属性的修改，例如 `width`, `height`, `top`, `left`, `z-index`, `visibility` 等，都可能导致渲染失效。
    * **例 3 (修改 z-index):**  如果 CSS 规则改变了元素的 `z-index`，导致元素的层叠顺序发生变化，`DisplayItemRasterInvalidator` 应该能够检测到这种重新排序 (`kReordered`) 并记录失效信息。

**逻辑推理与假设输入/输出:**

例如，在 `TEST_P(DisplayItemRasterInvalidatorTest, SwapOrder)` 测试中：

* **假设输入 (初始状态):**
    * 两个 `FakeDisplayItemClient` 实例 `first` 和 `second`，以及一个 `unaffected` 实例。
    * 绘制顺序为 `first` 在前，`second` 在中间，`unaffected` 在最后。
* **操作:** 交换 `first` 和 `second` 的绘制顺序。
* **预期输出:** `GetRasterInvalidations()` 应该包含一个 `RasterInvalidationInfo` 对象，指示 `first` 元素由于重新排序 (`kReordered`) 而失效，并包含其对应的失效区域。 `unaffected` 元素不应该有失效记录。

**用户或编程常见的使用错误举例:**

虽然 `DisplayItemRasterInvalidator` 本身是引擎内部的组件，用户或开发者不会直接使用它，但理解其工作原理可以帮助避免一些与性能相关的错误：

* **过度 DOM 操作:**  频繁且不必要的 DOM 操作（例如，在循环中修改元素的样式）会导致大量的渲染失效，从而降低页面性能。`DisplayItemRasterInvalidator` 的测试正是为了确保引擎能够有效地处理这些失效。
* **不理解 CSS 属性的影响:**  某些 CSS 属性的修改会触发更广泛的渲染失效。例如，修改影响布局的属性（如 `width`, `height`）通常比修改仅影响绘制的属性（如 `background-color`）代价更高。理解这些影响可以帮助开发者编写更高效的 CSS。
* **假设渲染是廉价的:**  一些开发者可能会忽略小的视觉变化对渲染性能的影响。`DisplayItemRasterInvalidator` 的测试有助于确保即使是小的变化也能被正确跟踪和处理，避免不必要的重绘。

**总结 (第 1 部分的功能):**

这部分代码的核心功能是 **对 `DisplayItemRasterInvalidator` 类进行全面的单元测试，以确保它能够正确地跟踪和记录各种场景下发生的渲染失效。** 这些测试覆盖了布局变化、元素增删、层叠顺序改变以及增量更新等多种情况，验证了该类在识别需要重新绘制的区域和原因方面的准确性。这对于保证浏览器的渲染效率和用户体验至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/paint/display_item_raster_invalidator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/graphics/paint/display_item_raster_invalidator.h"

#include "base/functional/callback_helpers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_artifact.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_controller_test.h"
#include "third_party/blink/renderer/platform/testing/paint_property_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/test_paint_artifact.h"
#include "ui/gfx/geometry/point_f.h"

namespace blink {

using ::testing::UnorderedElementsAre;

class DisplayItemRasterInvalidatorTest : public PaintControllerTestBase,
                                         public PaintTestConfigurations,
                                         public RasterInvalidator::Callback {
 protected:
  DisplayItemRasterInvalidatorTest() = default;

  Vector<RasterInvalidationInfo> GetRasterInvalidations() {
    if (invalidator_->GetTracking()) {
      return invalidator_->GetTracking()->Invalidations();
    }
    return Vector<RasterInvalidationInfo>();
  }

  void InvalidateRect(const gfx::Rect&) override {}

  // In this file, DisplayItemRasterInvalidator is tested through
  // RasterInvalidator.
  Persistent<RasterInvalidator> invalidator_ =
      MakeGarbageCollected<RasterInvalidator>(*this);
};

class RasterInvalidationPaintController : public PaintControllerForTest {
  STACK_ALLOCATED();

 public:
  RasterInvalidationPaintController(
      PaintControllerPersistentData& persistent_data,
      RasterInvalidator& invalidator)
      : PaintControllerForTest(persistent_data), invalidator_(invalidator) {}
  ~RasterInvalidationPaintController() {
    ++sequence_number_;
    const auto& paint_artifact = CommitNewDisplayItems();
    invalidator_.Generate(PaintChunkSubset(paint_artifact),
                          // The layer bounds are big enough not to clip display
                          // item raster invalidation rects in the tests.
                          gfx::Vector2dF(), gfx::Size(20000, 20000),
                          PropertyTreeState::Root());
    for (auto& chunk : paint_artifact.GetPaintChunks()) {
      chunk.properties.ClearChangedToRoot(sequence_number_);
    }
  }

 private:
  RasterInvalidator& invalidator_;
  static int sequence_number_;
};

int RasterInvalidationPaintController::sequence_number_ = 1;

INSTANTIATE_PAINT_TEST_SUITE_P(DisplayItemRasterInvalidatorTest);

TEST_P(DisplayItemRasterInvalidatorTest, FullInvalidationWithoutLayoutChange) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 150, 300, 300));
  }

  first.Invalidate();
  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 150, 300, 300));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  first.Id(), "first", gfx::Rect(100, 100, 300, 350),
                  PaintInvalidationReason::kLayout}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, FullInvalidationWithGeometryChange) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 150, 300, 300));
  }

  first.Invalidate();
  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(200, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, first, kForegroundType, gfx::Rect(200, 150, 300, 300));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{first.Id(), "first",
                                         gfx::Rect(100, 100, 300, 350),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{first.Id(), "first",
                                         gfx::Rect(200, 100, 300, 350),
                                         PaintInvalidationReason::kLayout}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, RemoveItemInMiddle) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 300, 300));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 300, 300));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  second.Id(), "second", gfx::Rect(100, 100, 200, 200),
                  PaintInvalidationReason::kDisappeared}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrder) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, second, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
    DrawRect(context, unaffected, kForegroundType, gfx::Rect(300, 300, 10, 10));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, second, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
    DrawRect(context, unaffected, kForegroundType, gfx::Rect(300, 300, 10, 10));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  first.Id(), "first", gfx::Rect(100, 100, 100, 100),
                  PaintInvalidationReason::kReordered}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderAndInvalidateFirst) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate(PaintInvalidationReason::kOutline);
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  first.Id(), "first", gfx::Rect(100, 100, 100, 100),
                  PaintInvalidationReason::kOutline}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderAndInvalidateSecond) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    second.Invalidate(PaintInvalidationReason::kOutline);
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  second.Id(), "second", gfx::Rect(100, 100, 50, 200),
                  PaintInvalidationReason::kOutline}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderWithIncrementalInvalidation) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate(PaintInvalidationReason::kIncremental);
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, unaffected, kBackgroundType, gfx::Rect(300, 300, 10, 10));
  }

  // Incremental invalidation is not applicable when the item is reordered.
  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  first.Id(), "first", gfx::Rect(100, 100, 100, 100),
                  PaintInvalidationReason::kReordered}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, NewItemInMiddle) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& third =
      *MakeGarbageCollected<FakeDisplayItemClient>("third");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, third, kBackgroundType, gfx::Rect(125, 100, 200, 50));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  third.Id(), "third", gfx::Rect(125, 100, 200, 50),
                  PaintInvalidationReason::kAppeared}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, Incremental) {
  gfx::Rect initial_rect(100, 100, 100, 100);
  Persistent<FakeDisplayItemClient> clients[6];
  for (size_t i = 0; i < std::size(clients); i++) {
    clients[i] =
        MakeGarbageCollected<FakeDisplayItemClient>(String::Format("%zu", i));
  }
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    for (auto& client : clients)
      DrawRect(context, *client, kBackgroundType, gfx::Rect(initial_rect));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    gfx::Rect visual_rects[] = {
        gfx::Rect(100, 100, 150, 100), gfx::Rect(100, 100, 100, 150),
        gfx::Rect(100, 100, 150, 80),  gfx::Rect(100, 100, 80, 150),
        gfx::Rect(100, 100, 150, 150), gfx::Rect(100, 100, 80, 80)};
    for (size_t i = 0; i < std::size(clients); i++) {
      clients[i]->Invalidate(PaintInvalidationReason::kIncremental);
      DrawRect(context, *clients[i], kBackgroundType,
               gfx::Rect(visual_rects[i]));
    }
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{clients[0]->Id(), "0",
                                         gfx::Rect(200, 100, 50, 100),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[1]->Id(), "1",
                                         gfx::Rect(100, 200, 100, 50),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[2]->Id(), "2",
                                         gfx::Rect(200, 100, 50, 80),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[2]->Id(), "2",
                                         gfx::Rect(100, 180, 100, 20),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[3]->Id(), "3",
                                         gfx::Rect(180, 100, 20, 100),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[3]->Id(), "3",
                                         gfx::Rect(100, 200, 80, 50),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[4]->Id(), "4",
                                         gfx::Rect(200, 100, 50, 150),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[4]->Id(), "4",
                                         gfx::Rect(100, 200, 150, 50),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{clients[5]->Id(), "5",
                                         gfx::Rect(180, 100, 20, 100),
                                         PaintInvalidationReason::kIncremental},
                  RasterInvalidationInfo{
                      clients[5]->Id(), "5", gfx::Rect(100, 180, 100, 20),
                      PaintInvalidationReason::kIncremental}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, AddRemoveFirstAndInvalidateSecond) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, second, kBackgroundType, gfx::Rect(200, 200, 50, 50));
    DrawRect(context, second, kForegroundType, gfx::Rect(200, 200, 50, 50));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate();
    second.Invalidate();
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, second, kBackgroundType, gfx::Rect(150, 250, 100, 100));
    DrawRect(context, second, kForegroundType, gfx::Rect(150, 250, 100, 100));
    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{first.Id(), "first",
                                         gfx::Rect(100, 100, 150, 150),
                                         PaintInvalidationReason::kAppeared},
                  RasterInvalidationInfo{second.Id(), "second",
                                         gfx::Rect(200, 200, 50, 50),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{second.Id(), "second",
                                         gfx::Rect(150, 250, 100, 100),
                                         PaintInvalidationReason::kLayout}));
  invalidator_->SetTracksRasterInvalidations(false);

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, second, kBackgroundType, gfx::Rect(150, 250, 100, 100));
    DrawRect(context, second, kForegroundType, gfx::Rect(150, 250, 100, 100));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(RasterInvalidationInfo{
                  first.Id(), "first", gfx::Rect(100, 100, 150, 150),
                  PaintInvalidationReason::kDisappeared}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, InvalidateFirstAndAddRemoveSecond) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 150, 150));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate();
    second.Invalidate();
    DrawRect(context, first, kBackgroundType, gfx::Rect(150, 150, 100, 100));
    DrawRect(context, first, kForegroundType, gfx::Rect(150, 150, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(200, 200, 50, 50));
    DrawRect(context, second, kForegroundType, gfx::Rect(200, 200, 50, 50));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{first.Id(), "first",
                                         gfx::Rect(100, 100, 150, 150),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{second.Id(), "second",
                                         gfx::Rect(200, 200, 50, 50),
                                         PaintInvalidationReason::kAppeared}));
  invalidator_->SetTracksRasterInvalidations(false);

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate();
    second.Invalidate();
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 150, 150));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{first.Id(), "first",
                                         gfx::Rect(100, 100, 150, 150),
                                         PaintInvalidationReason::kLayout},
                  RasterInvalidationInfo{
                      second.Id(), "second", gfx::Rect(200, 200, 50, 50),
                      PaintInvalidationReason::kDisappeared}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderWithChildren) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, container1, kBackgroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, content1, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, container1, kForegroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, container2, kBackgroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, content2, kBackgroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, content2, kForegroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, container2, kForegroundType,
             gfx::Rect(100, 200, 100, 100));
  }

  // Simulate the situation when |container1| gets a z-index that is greater
  // than that of |container2|.
  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, container2, kBackgroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, content2, kBackgroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, content2, kForegroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, container2, kForegroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, container1, kBackgroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, content1, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, container1, kForegroundType,
             gfx::Rect(100, 100, 100, 100));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{container1.Id(), "container1",
                                         gfx::Rect(100, 100, 100, 100),
                                         PaintInvalidationReason::kReordered},
                  RasterInvalidationInfo{content1.Id(), "content1",
                                         gfx::Rect(100, 100, 50, 200),
                                         PaintInvalidationReason::kReordered}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderWithChildrenAndInvalidation) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, container1, kBackgroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, content1, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, container1, kForegroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, container2, kBackgroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, content2, kBackgroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, content2, kForegroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, container2, kForegroundType,
             gfx::Rect(100, 200, 100, 100));
  }

  invalidator_->SetTracksRasterInvalidations(true);
  {
    RasterInvalidationPaintController paint_controller(GetPersistentData(),
                                                       *invalidator_);
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Simulate the situation when |container1| gets a z-index that is greater
    // than that of |container2|, and |container1| is invalidated.
    container2.Invalidate();
    DrawRect(context, container2, kBackgroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, content2, kBackgroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, content2, kForegroundType, gfx::Rect(100, 200, 50, 200));
    DrawRect(context, container2, kForegroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, container1, kBackgroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, content1, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, container1, kForegroundType,
             gfx::Rect(100, 100, 100, 100));
  }

  EXPECT_THAT(GetRasterInvalidations(),
              UnorderedElementsAre(
                  RasterInvalidationInfo{container1.Id(), "container1",
                                         gfx::Rect(100, 100, 100, 100),
                                         PaintInvalidationReason::kReordered},
                  RasterInvalidationInfo{content1.Id(), "content1",
                                         gfx::Rect(100, 100, 50, 200),
                                         PaintInvalidationReason::kReordered},
                  RasterInvalidationInfo{container2.Id(), "container2",
                                         gfx::Rect(100, 200, 100, 100),
                                         PaintInvalidationReason::kLayout}));
  invalidator_->SetTracksRasterInvalidations(false);
}

TEST_P(DisplayItemRasterInvalidatorTest, SwapOrderCrossingChunks) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollec
"""


```