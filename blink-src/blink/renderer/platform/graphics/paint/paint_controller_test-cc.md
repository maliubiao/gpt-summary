Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine.
Specifically, they want to understand the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with inputs and outputs, common usage errors, and a general summary of its purpose for this first part of the file.

**Plan:**

1. **Identify the main purpose of the file:** Based on the file name `paint_controller_test.cc`, it's clear that this file contains tests for the `PaintController` class.
2. **Analyze the code structure:**  Look for test fixtures, test cases, and helper functions to understand what aspects of `PaintController` are being tested.
3. **Identify connections to web technologies:**  Consider how painting and display items relate to the rendering of HTML elements and their styles defined by CSS. JavaScript interactions might trigger repainting, but the test file itself won't directly use JavaScript.
4. **Infer logical reasoning and provide examples:**  Analyze the test cases to understand the inputs (e.g., drawing commands, invalidations) and expected outputs (e.g., whether items are cached or repainted).
5. **Identify potential usage errors:** Think about common mistakes developers might make when interacting with the painting system.
6. **Summarize the functionality:** Concisely describe the role of this file within the Blink rendering engine.
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/paint_controller_test.h"

#include "base/dcheck_is_on.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_cache_skipper.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/paint/subsequence_recorder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

using testing::ElementsAre;

namespace blink {

PaintControllerTestBase::DrawResult PaintControllerTestBase::Draw(
    GraphicsContext& context,
    const DisplayItemClient& client,
    DisplayItem::Type type,
    base::FunctionRef<void()> draw_function) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, client, type)) {
    return kCached;
  }

  auto& paint_controller = context.GetPaintController();
  auto* matching_cached_item =
      paint_controller.MatchingCachedItemToBeRepainted();
  PaintRecord old_record;
  if (matching_cached_item) {
    EXPECT_EQ(
        matching_cached_item->GetId(),
        DisplayItem::Id(client.Id(), type, paint_controller.CurrentFragment()));
    old_record = To<DrawingDisplayItem>(matching_cached_item)->GetPaintRecord();
  }

  bool would_be_cached =
      paint_controller.IsCheckingUnderInvalidationForTesting();

  draw_function();

  if (would_be_cached) {
    DCHECK(!matching_cached_item);
    return kCached;
  }

  if (matching_cached_item) {
    // We should reused the cached paint record and paint into it.
    PaintRecord new_record =
        To<DrawingDisplayItem>(
            GetNewPaintArtifact(paint_controller).GetDisplayItemList().back())
            .GetPaintRecord();
    EXPECT_NE(&old_record.GetFirstOp(), &new_record.GetFirstOp());
    EXPECT_EQ(old_record.bytes_used(), new_record.bytes_used());
    return kRepaintedCachedItem;
  }
  return kPaintedNew;
}

// Tests using this class will be tested with under-invalidation-checking
// enabled and disabled.
class PaintControllerTest : public PaintTestConfigurations,
                            public PaintControllerTestBase {
};

#define EXPECT_DEFAULT_ROOT_CHUNK(size)                               \
  EXPECT_THAT(GetPersistentData().GetPaintChunks(),                   \
              ElementsAre(IsPaintChunk(0, size, DefaultRootChunkId(), \
                                       DefaultPaintChunkProperties())))

INSTANTIATE_TEST_SUITE_P(All,
                         PaintControllerTest,
                         testing::Values(0, kUnderInvalidationChecking));
TEST_P(PaintControllerTest, NestedRecorders) {
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, client, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(client.Id(), kBackgroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(1);
}

TEST_P(PaintControllerTest, UpdateBasic) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 300, 300)));

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kCached, DrawRect(context, first, kForegroundType,
                                gfx::Rect(100, 100, 300, 300)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(1u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(2);
}
```

### 功能列举

这个C++源代码文件 (`paint_controller_test.cc`) 的主要功能是：

1. **为 `PaintController` 组件编写单元测试:**  `PaintController` 负责管理 Blink 渲染引擎中的绘制操作。这个测试文件验证了 `PaintController` 的各种功能是否按预期工作。

2. **测试绘制操作的缓存和重用:**  通过模拟不同的绘制场景和状态变化，测试 `PaintController` 是否能够有效地缓存绘制指令并避免不必要的重复绘制，以提高渲染性能。

3. **测试失效 (Invalidation) 机制:** 模拟元素失效的情况，并验证 `PaintController` 是否能正确地标记需要重绘的区域和对象。

4. **测试绘制指令的顺序和组织:**  验证在绘制过程中，指令的顺序是否被正确维护，以及是否能够处理绘制顺序的变化。

5. **提供用于测试绘制功能的基类:**  定义了 `PaintControllerTestBase` 类，其中包含用于执行绘制操作和断言结果的辅助函数 `Draw`。

### 与 JavaScript, HTML, CSS 的关系及举例说明

`PaintController` 及其测试直接关系到浏览器如何将 HTML、CSS 和 JavaScript 的渲染指令转化为屏幕上的像素。

* **HTML:**  HTML 定义了网页的结构，每个 HTML 元素最终都需要被绘制出来。`PaintController` 负责管理这些元素的绘制过程。例如，测试用例中 `FakeDisplayItemClient` 可以模拟一个 HTML 元素，而 `DrawRect` 操作模拟绘制这个元素的背景或前景。
    * **举例:** 当一个 `<div>` 元素在 HTML 中定义时，`PaintController` 将负责记录绘制这个 `<div>` 的背景颜色、边框等属性的操作。

* **CSS:** CSS 决定了 HTML 元素的样式，包括颜色、大小、位置等。`PaintController` 需要根据 CSS 提供的样式信息来生成绘制指令。
    * **举例:**  `DrawRect(context, client, kBackgroundType, gfx::Rect(100, 100, 200, 200))`  这个操作可能对应于一个 CSS 规则设置了某个元素的背景颜色，并指定了该元素的尺寸和位置。`kBackgroundType` 就可能代表了绘制背景相关的操作。

* **JavaScript:** JavaScript 可以动态地修改 HTML 结构和 CSS 样式，这些修改会触发页面的重绘。`PaintController` 需要能够处理这些动态变化，并有效地更新渲染结果。
    * **举例:**  当 JavaScript 修改一个元素的 `style.backgroundColor` 时，会触发该元素的失效，`PaintController` 会根据新的样式信息重新绘制该元素。测试用例中的 `Invalidate()` 方法模拟了这种失效的情况。

**测试用例中的对应关系：**

* `FakeDisplayItemClient`:  模拟需要绘制的 HTML 元素。
* `kBackgroundType`, `kForegroundType`:  可以对应于 CSS 中设置的背景或前景属性。
* `DrawRect`: 模拟根据 CSS 样式绘制矩形的操作，例如元素的背景或边框。
* `Invalidate()`: 模拟 JavaScript 引起的元素样式或布局变化，导致需要重新绘制。
* `kCached`, `kRepaintedCachedItem`, `kPaintedNew`:  测试 `PaintController` 是否正确地处理了缓存和重绘逻辑，这直接影响到 JavaScript 动态修改页面时的性能。

### 逻辑推理及假设输入与输出

测试用例中存在逻辑推理，主要体现在断言 (Expect) 语句中，它验证了在特定操作序列后，`PaintController` 的行为是否符合预期。

**示例 (来自 `TEST_P(PaintControllerTest, UpdateBasic)`):**

**假设输入:**

1. 首次绘制 `first` 元素背景 (矩形)。
2. 首次绘制 `second` 元素背景 (矩形)。
3. 首次绘制 `first` 元素前景 (矩形)。
4. 第二次绘制 `first` 元素背景 (相同的属性)。
5. 第二次绘制 `first` 元素前景 (相同的属性)。

**逻辑推理:**

`PaintController` 应该能够识别出第二次绘制 `first` 元素的背景和前景与之前的绘制相同，因此应该使用缓存的绘制指令，而不是重新绘制。

**预期输出:**

* 首次绘制时，`DrawRect` 返回 `kPaintedNew`。
* 第二次绘制时，`DrawRect` 返回 `kCached`。
* 显示列表在第一次绘制后包含三个绘制项。
* 显示列表在第二次绘制后仍然只包含两个绘制项 (因为使用了缓存)。

**代码中的体现:**

```cpp
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 300, 300)));

  // ... (断言显示列表)

    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kCached, DrawRect(context, first, kForegroundType,
                                gfx::Rect(100, 100, 300, 300)));

  // ... (断言显示列表)
```

### 涉及用户或者编程常见的使用错误及举例说明

虽然这个文件是测试代码，但它反映了 `PaintController` 的设计和预期用法。了解这些测试可以帮助避免在使用相关 API 时的错误。

**常见误用 (由测试用例揭示):**

1. **不必要的强制重绘:**  开发者可能错误地认为某些操作需要完全重绘，而实际上 `PaintController` 可以通过缓存进行优化。测试用例验证了在相同绘制操作下能够正确使用缓存。
    * **举例:**  如果开发者在 JavaScript 中频繁修改一个元素的某个样式，但该样式变化实际上不会影响元素的绘制结果 (例如，修改了一个未使用的 CSS 变量)，`PaintController` 的缓存机制可以避免不必要的重绘。

2. **错误地判断缓存是否有效:**  开发者可能不清楚何时应该失效 (invalidate) 绘制缓存。测试用例中 `Invalidate()` 方法的调用模拟了需要失效缓存的场景。
    * **举例:**  如果一个元素的几何属性 (如大小或位置) 发生了变化，或者其依赖的绘制状态改变了，那么与该元素相关的缓存就需要失效。忘记调用 `Invalidate()` 可能导致渲染结果不正确。

3. **对绘制顺序的错误假设:**  在复杂的场景中，绘制指令的顺序很重要。测试用例 (`UpdateSwapOrder`) 验证了 `PaintController` 是否能够处理绘制顺序的变化。
    * **举例:**  当使用 `z-index` 改变元素的堆叠顺序时，`PaintController` 需要确保绘制指令的顺序与新的堆叠顺序一致。错误地更新绘制顺序可能导致元素遮挡关系错误。

### 功能归纳

这个源代码文件的主要功能是 **作为 Chromium Blink 引擎中 `PaintController` 组件的单元测试集**。它通过模拟各种绘制场景和状态变化，验证了 `PaintController` 的核心功能，包括绘制操作的缓存和重用、失效机制、以及处理绘制指令顺序的能力。这些测试对于确保渲染引擎的正确性和性能至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/paint/paint_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/paint/paint_controller_test.h"

#include "base/dcheck_is_on.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/display_item_cache_skipper.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_display_item.h"
#include "third_party/blink/renderer/platform/graphics/paint/drawing_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_display_item_fragment.h"
#include "third_party/blink/renderer/platform/graphics/paint/scoped_paint_chunk_properties.h"
#include "third_party/blink/renderer/platform/graphics/paint/subsequence_recorder.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

using testing::ElementsAre;

namespace blink {

PaintControllerTestBase::DrawResult PaintControllerTestBase::Draw(
    GraphicsContext& context,
    const DisplayItemClient& client,
    DisplayItem::Type type,
    base::FunctionRef<void()> draw_function) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, client, type)) {
    return kCached;
  }

  auto& paint_controller = context.GetPaintController();
  auto* matching_cached_item =
      paint_controller.MatchingCachedItemToBeRepainted();
  PaintRecord old_record;
  if (matching_cached_item) {
    EXPECT_EQ(
        matching_cached_item->GetId(),
        DisplayItem::Id(client.Id(), type, paint_controller.CurrentFragment()));
    old_record = To<DrawingDisplayItem>(matching_cached_item)->GetPaintRecord();
  }

  bool would_be_cached =
      paint_controller.IsCheckingUnderInvalidationForTesting();

  draw_function();

  if (would_be_cached) {
    DCHECK(!matching_cached_item);
    return kCached;
  }

  if (matching_cached_item) {
    // We should reused the cached paint record and paint into it.
    PaintRecord new_record =
        To<DrawingDisplayItem>(
            GetNewPaintArtifact(paint_controller).GetDisplayItemList().back())
            .GetPaintRecord();
    EXPECT_NE(&old_record.GetFirstOp(), &new_record.GetFirstOp());
    EXPECT_EQ(old_record.bytes_used(), new_record.bytes_used());
    return kRepaintedCachedItem;
  }
  return kPaintedNew;
}

// Tests using this class will be tested with under-invalidation-checking
// enabled and disabled.
class PaintControllerTest : public PaintTestConfigurations,
                            public PaintControllerTestBase {
};

#define EXPECT_DEFAULT_ROOT_CHUNK(size)                               \
  EXPECT_THAT(GetPersistentData().GetPaintChunks(),                   \
              ElementsAre(IsPaintChunk(0, size, DefaultRootChunkId(), \
                                       DefaultPaintChunkProperties())))

INSTANTIATE_TEST_SUITE_P(All,
                         PaintControllerTest,
                         testing::Values(0, kUnderInvalidationChecking));
TEST_P(PaintControllerTest, NestedRecorders) {
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, client, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(client.Id(), kBackgroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(1);
}

TEST_P(PaintControllerTest, UpdateBasic) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 300, 300)));

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kCached, DrawRect(context, first, kForegroundType,
                                gfx::Rect(100, 100, 300, 300)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(1u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(2);
}

TEST_P(PaintControllerTest, UpdateSwapOrder) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kForegroundType,
                                    gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, unaffected, kBackgroundType,
                                    gfx::Rect(300, 300, 10, 10)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, unaffected, kForegroundType,
                                    gfx::Rect(300, 300, 10, 10)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(unaffected.Id(), kBackgroundType),
                          IsSameId(unaffected.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached, DrawRect(context, second, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, second, kForegroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, first, kForegroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, unaffected, kBackgroundType,
                                gfx::Rect(300, 300, 10, 10)));
    EXPECT_EQ(kCached, DrawRect(context, unaffected, kForegroundType,
                                gfx::Rect(300, 300, 10, 10)));

    EXPECT_EQ(6u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(2u, NumIndexedItems(paint_controller));  // first
    EXPECT_EQ(5u,
              NumSequentialMatches(
                  paint_controller));  // second, first foreground, unaffected
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));  // first
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(unaffected.Id(), kBackgroundType),
                          IsSameId(unaffected.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(6);
}

TEST_P(PaintControllerTest, UpdateSwapOrderWithInvalidation) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& unaffected =
      *MakeGarbageCollected<FakeDisplayItemClient>("unaffected");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kForegroundType,
                                    gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, unaffected, kBackgroundType,
                                    gfx::Rect(300, 300, 10, 10)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, unaffected, kForegroundType,
                                    gfx::Rect(300, 300, 10, 10)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(unaffected.Id(), kBackgroundType),
                          IsSameId(unaffected.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate();
    EXPECT_EQ(kCached, DrawRect(context, second, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, second, kForegroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kBackgroundType,
                                             gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kForegroundType,
                                             gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, unaffected, kBackgroundType,
                                gfx::Rect(300, 300, 10, 10)));
    EXPECT_EQ(kCached, DrawRect(context, unaffected, kForegroundType,
                                gfx::Rect(300, 300, 10, 10)));

    EXPECT_EQ(4u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(2u, NumIndexedItems(paint_controller));
    EXPECT_EQ(5u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(unaffected.Id(), kBackgroundType),
                          IsSameId(unaffected.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(6);
}

TEST_P(PaintControllerTest, UpdateNewItemInMiddle) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& third =
      *MakeGarbageCollected<FakeDisplayItemClient>("third");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, third, kBackgroundType,
                                    gfx::Rect(125, 100, 200, 50)));
    EXPECT_EQ(kCached, DrawRect(context, second, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));  // first, second
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(third.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);
}

TEST_P(PaintControllerTest, UpdateInvalidationWithPhases) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& third =
      *MakeGarbageCollected<FakeDisplayItemClient>("third");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, third, kBackgroundType, gfx::Rect(300, 100, 50, 50));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, second, kForegroundType, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, third, kForegroundType, gfx::Rect(300, 100, 50, 50));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(third.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(third.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    second.Invalidate();
    EXPECT_EQ(kCached, DrawRect(context, first, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, second, kBackgroundType,
                                             gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, third, kBackgroundType,
                                gfx::Rect(300, 100, 50, 50)));
    EXPECT_EQ(kCached, DrawRect(context, first, kForegroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, second, kForegroundType,
                                             gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, third, kForegroundType,
                                gfx::Rect(300, 100, 50, 50)));

    EXPECT_EQ(4u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(6u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(third.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kForegroundType),
                          IsSameId(third.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(6);
}

TEST_P(PaintControllerTest, UpdateAddFirstOverlap) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, second, kBackgroundType, gfx::Rect(200, 200, 50, 50));
    DrawRect(context, second, kForegroundType, gfx::Rect(200, 200, 50, 50));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    first.Invalidate();
    second.Invalidate();
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 150, 150)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kForegroundType,
                                    gfx::Rect(100, 100, 150, 150)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, second, kBackgroundType,
                                             gfx::Rect(150, 250, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, second, kForegroundType,
                                             gfx::Rect(150, 250, 100, 100)));
    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(4);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached, DrawRect(context, second, kBackgroundType,
                                gfx::Rect(150, 250, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, second, kForegroundType,
                                gfx::Rect(150, 250, 100, 100)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(2u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(2);
}

TEST_P(PaintControllerTest, UpdateAddLastOverlap) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, first, kForegroundType, gfx::Rect(100, 100, 150, 150));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    first.Invalidate();
    second.Invalidate();
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kBackgroundType,
                                             gfx::Rect(150, 150, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kForegroundType,
                                             gfx::Rect(150, 150, 100, 100)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(200, 200, 50, 50)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kForegroundType,
                                    gfx::Rect(200, 200, 50, 50)));
    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(second.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(4);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    first.Invalidate();
    second.Invalidate();
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kBackgroundType,
                                             gfx::Rect(100, 100, 150, 150)));
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kForegroundType,
                                             gfx::Rect(100, 100, 150, 150)));
    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(first.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(2);
}

TEST_P(PaintControllerTest, CachedDisplayItems) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 150, 150));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 150, 150));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType)));
  EXPECT_TRUE(ClientCacheIsValid(first));
  EXPECT_TRUE(ClientCacheIsValid(second));

  first.Invalidate();
  EXPECT_FALSE(ClientCacheIsValid(first));
  EXPECT_TRUE(ClientCacheIsValid(second));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, first, kBackgroundType,
                                             gfx::Rect(100, 100, 150, 150)));
    EXPECT_EQ(kCached, DrawRect(context, second, kBackgroundType,
                                gfx::Rect(100, 100, 150, 150)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType)));
  EXPECT_TRUE(ClientCacheIsValid(first));
  EXPECT_TRUE(ClientCacheIsValid(second));

  InvalidateAll();
  EXPECT_FALSE(ClientCacheIsValid(first));
  EXPECT_FALSE(ClientCacheIsValid(second));
}

TEST_P(PaintControllerTest, UpdateSwapOrderWithChildren) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
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

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kForegroundType),
                          IsSameId(container2.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    // Simulate the situation when |container1| gets a z-index that is greater
    // than that of |container2|.
    EXPECT_EQ(kCached, DrawRect(context, container2, kBackgroundType,
                                gfx::Rect(100, 200, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, content2, kBackgroundType,
                                gfx::Rect(100, 200, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, content2, kForegroundType,
                                gfx::Rect(100, 200, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, container2, kForegroundType,
                                gfx::Rect(100, 200, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, container1, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, container1, kForegroundType,
                                gfx::Rect(100, 100, 100, 100)));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kForegroundType),
                          IsSameId(container2.Id(), kForegroundType),
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(8);
}

TEST_P(PaintControllerTest, UpdateSwapOrderWithChildrenAndInvalidation) {
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
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

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kForegroundType),
                          IsSameId(container2.Id(), kForegroundType)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    // Simulate the situation when |container1| gets a z-index that is greater
    // than that of |container2|, and |container1| is invalidated.
    container1.Invalidate();
    EXPECT_EQ(kCached, DrawRect(context, container2, kBackgroundType,
                                gfx::Rect(100, 200, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, content2, kBackgroundTyp
"""


```