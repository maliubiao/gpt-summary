Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code snippet seems to be a part of unit tests for the `PaintController` in the Chromium Blink engine.

Here's a plan to summarize the functionality:

1. **Identify the core purpose:** The code tests the caching and reuse mechanisms of the `PaintController`, specifically focusing on subsequences (groups of drawing operations).
2. **Break down the tests:**  Analyze each `TEST_P` function and understand what specific aspect of caching it is verifying.
3. **Look for relationships with web technologies:** Determine if the tested features relate to how JavaScript, HTML, or CSS are rendered.
4. **Analyze logical reasoning:**  Examine tests that involve conditional logic or state changes to infer input and output.
5. **Identify potential user errors:**  See if the tests highlight common mistakes in how rendering might be approached.
6. **Synthesize the findings:** Combine the analysis of individual tests into a concise summary of the overall functionality.
这是 `blink/renderer/platform/graphics/paint/paint_controller_test.cc` 文件第 2 部分，主要功能是**测试 `PaintController` 中缓存子序列（Cached Subsequence）和显示项（Display Item）的各种场景，特别是关于它们的缓存、重用以及顺序变化时的行为**。

以下是针对代码片段中各个测试用例的功能归纳，并解释了与 JavaScript、HTML、CSS 的关系，以及逻辑推理和可能的用户错误：

**功能归纳:**

* **`CachedSubsequenceBasic`:**  测试基本的缓存子序列功能。验证在没有属性变化的情况下，子序列和其中的显示项是否能被成功缓存和重用。
* **`CachedSubsequenceWithPropertyChange`:** 测试当子序列相关的绘制属性（例如，paint chunk properties）发生变化时，缓存的失效和重新绘制行为。
* **`CachedSubsequenceForcePaintChunk`:** 测试即使绘制属性匹配，但由于创建了子序列，是否会强制创建一个新的 `PaintChunk`。
* **`CachedSubsequenceSwapOrder`:**  测试缓存的子序列在绘制顺序发生变化时的行为。模拟了由于 z-index 等原因导致的元素层叠顺序变化，验证 `PaintController` 是否能正确处理缓存和重用。
* **`CachedSubsequenceAndDisplayItemsSwapOrder`:** 测试缓存的子序列和单独的显示项在绘制顺序发生变化时的相互影响和 `PaintController` 的处理。
* **`DisplayItemSwapOrderBeforeCachedSubsequence`:**  测试当独立的显示项的顺序在包含缓存子序列的绘制中发生变化时，`PaintController` 的行为。
* **`CachedSubsequenceContainingFragments`:**  测试包含 Display Item Fragments 的子序列的缓存和重用。
* **`UpdateSwapOrderCrossingChunks`:** 测试在不同的 `PaintChunk` 之间移动显示项时，缓存机制的运作情况。
* **`OutOfOrderNoCrash`:**  一个健壮性测试，验证当以非预期的顺序请求绘制操作时，`PaintController` 不会崩溃。
* **`CachedNestedSubsequenceUpdate`:** 测试嵌套子序列的缓存和更新行为。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML 结构:**  `FakeDisplayItemClient` 可以模拟 HTML 元素（例如 `<div>`, `<span>`）。测试中创建的 `container` 和 `content` 可以理解为嵌套的 HTML 元素。
* **CSS 样式:** `DefaultPaintChunkProperties()` 可以理解为元素的默认 CSS 样式。`CreateOpacityEffect()` 模拟 CSS 的 `opacity` 属性。当 CSS 属性发生变化时（例如，通过 JavaScript 修改元素的 style），`PaintController` 需要重新绘制，这正是 `CachedSubsequenceWithPropertyChange` 测试的场景。
    * **举例:** HTML 中有一个 `<div>` 元素，CSS 中设置了 `opacity: 0.5`。当 JavaScript 修改这个元素的 `opacity` 为 `0.8` 时，`PaintController` 应该检测到属性变化，失效之前的缓存并重新绘制。
* **JavaScript 动画和 DOM 操作:**  JavaScript 可以动态地改变元素的属性和层叠顺序。`CachedSubsequenceSwapOrder` 和 `CachedSubsequenceAndDisplayItemsSwapOrder` 测试模拟了由于 JavaScript 操作（例如修改元素的 z-index）导致的绘制顺序变化。
    * **举例:** 两个 `<div>` 元素初始时按照 HTML 结构顺序绘制。JavaScript 通过修改 CSS 的 `z-index` 属性，改变了它们的层叠顺序。`PaintController` 需要正确地处理这种顺序变化，可能需要重新排序绘制指令。

**逻辑推理 - 假设输入与输出:**

以 `CachedSubsequenceBasic` 为例：

* **假设输入:**
    1. 首次绘制：绘制 `container1` 和 `content1`，它们具有相同的绘制属性。
    2. 第二次绘制：尝试使用相同的 `container1` 和 `content1` 进行绘制。
* **预期输出:**
    1. 首次绘制：`DrawRect` 返回 `kNew`，表示创建了新的显示项。`GetPersistentData().GetDisplayItemList()` 中包含 `container1` 和 `content1` 的绘制指令。
    2. 第二次绘制：`DrawRect` 返回 `kCached`，表示使用了缓存的显示项。`GetPersistentData().GetDisplayItemList()` 的内容应该与第一次绘制相同。

以 `CachedSubsequenceSwapOrder` 为例：

* **假设输入:**
    1. 首次绘制：先绘制 `container1` 和其内容，再绘制 `container2` 和其内容。
    2. 第二次绘制：尝试先绘制 `container2` 和其内容，再绘制 `container1` 和其内容（模拟 z-index 变化）。
* **预期输出:**
    1. 首次绘制：`GetPersistentData().GetDisplayItemList()` 的顺序是 `container1` 的内容在前，`container2` 的内容在后。`GetPersistentData().GetPaintChunks()` 中包含两个 `PaintChunk`，分别对应 `container1` 和 `container2`。
    2. 第二次绘制（未开启 `PaintUnderInvalidationCheckingEnabled`）：`UseCachedSubsequenceIfPossible` 返回 `true`，表示尽可能使用了缓存。`GetPersistentData().GetDisplayItemList()` 的顺序是 `container2` 的内容在前，`container1` 的内容在后。`GetPersistentData().GetPaintChunks()` 中 `PaintChunk` 的顺序也可能发生变化，以反映新的绘制顺序。

**用户或编程常见的使用错误举例:**

* **不必要的强制重绘:**  开发者可能会在没有必要的情况下触发元素的重绘，例如频繁地修改不会影响渲染输出的属性。`PaintController` 的缓存机制旨在避免这种不必要的重绘，提高性能。
* **过度细粒度的样式修改:**  频繁地修改元素的细微样式属性可能会导致缓存失效和性能下降。`PaintController` 的测试可以帮助理解哪些类型的样式修改会触发重绘。
* **不理解层叠上下文的影响:**  开发者可能不清楚 CSS 的层叠上下文规则，导致元素的绘制顺序与预期不符。`CachedSubsequenceSwapOrder` 这样的测试帮助验证 `PaintController` 在处理层叠顺序时的正确性。
* **假设缓存总是有效:**  开发者可能会错误地假设一旦内容被缓存，它就永远有效。实际上，属性变化、视口变化等都可能导致缓存失效。测试用例如 `CachedSubsequenceWithPropertyChange` 强调了缓存失效的情况。

**归纳一下它的功能 (第2部分):**

这部分代码主要针对 `PaintController` 的子序列缓存功能进行全面的单元测试。它验证了在各种场景下，包括基本缓存、属性变化、绘制顺序变化、包含 fragments 以及跨越 `PaintChunk` 等情况，`PaintController` 是否能正确地缓存和重用绘制指令，从而优化渲染性能。 这些测试覆盖了在实际网页渲染中可能遇到的各种复杂情况，确保了渲染引擎的稳定性和效率。

### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/paint_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
e,
                                gfx::Rect(100, 200, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, content2, kForegroundType,
                                gfx::Rect(100, 200, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, container2, kForegroundType,
                                gfx::Rect(100, 200, 100, 100)));
    EXPECT_EQ(kRepaintedCachedItem,
              DrawRect(context, container1, kBackgroundType,
                       gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kRepaintedCachedItem,
              DrawRect(context, container1, kForegroundType,
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

TEST_P(PaintControllerTest, CachedSubsequenceForcePaintChunk) {
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled())
    return;

  FakeDisplayItemClient& root =
      *MakeGarbageCollected<FakeDisplayItemClient>("root");
  auto root_properties = DefaultPaintChunkProperties();
  PaintChunk::Id root_id(root.Id(), DisplayItem::kCaret);
  FakeDisplayItemClient& container =
      *MakeGarbageCollected<FakeDisplayItemClient>("container");
  auto container_properties = DefaultPaintChunkProperties();
  PaintChunk::Id container_id(container.Id(), DisplayItem::kCaret);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);

    paint_controller.UpdateCurrentPaintChunkProperties(root_id, root,
                                                       root_properties);
    DrawRect(context, root, kBackgroundType, gfx::Rect(100, 100, 100, 100));

    {
      SubsequenceRecorder r(context, container);
      paint_controller.UpdateCurrentPaintChunkProperties(
          container_id, container, container_properties);
      DrawRect(context, container, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));
      DrawRect(context, container, kForegroundType,
               gfx::Rect(100, 100, 100, 100));
    }

    DrawRect(context, root, kForegroundType, gfx::Rect(100, 100, 100, 100));
  }

  // Even though the paint properties match, |container| should receive its
  // own PaintChunk because it created a subsequence.
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 1, root_id, root_properties),
                  IsPaintChunk(1, 3, container_id, container_properties),
                  IsPaintChunk(3, 4, PaintChunk::Id(root.Id(), kForegroundType),
                               root_properties)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(root_id, root,
                                                       root_properties);
    EXPECT_EQ(kCached, DrawRect(context, root, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_TRUE(paint_controller.UseCachedSubsequenceIfPossible(container));
    EXPECT_EQ(kCached, DrawRect(context, root, kForegroundType,
                                gfx::Rect(100, 100, 100, 100)));
  }

  // |container| should still receive its own PaintChunk because it is a cached
  // subsequence.
  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 1, root_id, root_properties),
                  IsPaintChunk(1, 3, container_id, container_properties),
                  IsPaintChunk(3, 4, PaintChunk::Id(root.Id(), kForegroundType),
                               container_properties)));
}

TEST_P(PaintControllerTest, CachedSubsequenceSwapOrder) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");

  PaintChunk::Id container1_id(container1.Id(), kBackgroundType);
  auto* container1_effect = CreateOpacityEffect(e0(), 0.5);
  auto container1_properties = DefaultPaintChunkProperties();
  container1_properties.SetEffect(*container1_effect);

  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  auto* container2_effect = CreateOpacityEffect(e0(), 0.5);
  auto container2_properties = DefaultPaintChunkProperties();
  container2_properties.SetEffect(*container2_effect);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);

    {
      paint_controller.UpdateCurrentPaintChunkProperties(
          container1_id, container1, container1_properties);

      SubsequenceRecorder r(context, container1);
      DrawRect(context, container1, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));
      DrawRect(context, content1, kBackgroundType,
               gfx::Rect(100, 100, 50, 200));
      DrawRect(context, content1, kForegroundType,
               gfx::Rect(100, 100, 50, 200));
      DrawRect(context, container1, kForegroundType,
               gfx::Rect(100, 100, 100, 100));
    }
    {
      paint_controller.UpdateCurrentPaintChunkProperties(
          container2_id, container2, container2_properties);

      SubsequenceRecorder r(context, container2);
      DrawRect(context, container2, kBackgroundType,
               gfx::Rect(100, 200, 100, 100));
      DrawRect(context, content2, kBackgroundType,
               gfx::Rect(100, 200, 50, 200));
      DrawRect(context, content2, kForegroundType,
               gfx::Rect(100, 200, 50, 200));
      DrawRect(context, container2, kForegroundType,
               gfx::Rect(100, 200, 100, 100));
    }
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

  EXPECT_SUBSEQUENCE(container1, 0, 1);
  EXPECT_NO_SUBSEQUENCE(content1);
  EXPECT_SUBSEQUENCE(container2, 1, 2);
  EXPECT_NO_SUBSEQUENCE(content2);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 4, container1_id, container1_properties),
                  IsPaintChunk(4, 8, container2_id, container2_properties)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    // Simulate the situation when |container1| gets a z-index that is greater
    // than that of |container2|.
    if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
      // When under-invalidation-checking is enabled,
      // UseCachedSubsequenceIfPossible is forced off, and the client is
      // expected to create the same painting as in the previous paint.
      EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container2));
      {
        paint_controller.UpdateCurrentPaintChunkProperties(
            container2_id, container2, container2_properties);

        SubsequenceRecorder r(context, container2);
        EXPECT_EQ(kCached, DrawRect(context, container2, kBackgroundType,
                                    gfx::Rect(100, 200, 100, 100)));
        EXPECT_EQ(kCached, DrawRect(context, content2, kBackgroundType,
                                    gfx::Rect(100, 200, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, content2, kForegroundType,
                                    gfx::Rect(100, 200, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, container2, kForegroundType,
                                    gfx::Rect(100, 200, 100, 100)));
      }
      EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container1));
      {
        paint_controller.UpdateCurrentPaintChunkProperties(
            container1_id, container1, container1_properties);

        SubsequenceRecorder r(context, container1);
        EXPECT_EQ(kCached, DrawRect(context, container1, kBackgroundType,
                                    gfx::Rect(100, 100, 100, 100)));
        EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                    gfx::Rect(100, 100, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, container1, kForegroundType,
                                    gfx::Rect(100, 100, 100, 100)));
      }
    } else {
      EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container2));
      EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container1));
    }

    EXPECT_EQ(8u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(2u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(0u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
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

  EXPECT_SUBSEQUENCE(container1, 1, 2);
  EXPECT_NO_SUBSEQUENCE(content1);
  EXPECT_SUBSEQUENCE(container2, 0, 1);
  EXPECT_NO_SUBSEQUENCE(content2);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 4, container2_id, container2_properties),
                  IsPaintChunk(4, 8, container1_id, container1_properties)));
}

TEST_P(PaintControllerTest, CachedSubsequenceAndDisplayItemsSwapOrder) {
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");

  PaintChunk::Id content1_id(content1.Id(), kBackgroundType);
  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  PaintChunk::Id content2_id(content2.Id(), kBackgroundType);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    {
      SubsequenceRecorder r(context, container2);
      DrawRect(context, container2, kBackgroundType,
               gfx::Rect(100, 200, 100, 100));
      DrawRect(context, content2, kBackgroundType,
               gfx::Rect(100, 200, 50, 200));
      DrawRect(context, content2, kForegroundType,
               gfx::Rect(100, 200, 50, 200));
      DrawRect(context, container2, kForegroundType,
               gfx::Rect(100, 200, 100, 100));
    }
    DrawRect(context, content1, kForegroundType, gfx::Rect(100, 100, 50, 200));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kForegroundType),
                          IsSameId(container2.Id(), kForegroundType),
                          IsSameId(content1.Id(), kForegroundType)));

  EXPECT_NO_SUBSEQUENCE(content1);
  EXPECT_SUBSEQUENCE(container2, 1, 2);
  EXPECT_NO_SUBSEQUENCE(content2);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(
          IsPaintChunk(0, 1, DefaultRootChunkId(),
                       DefaultPaintChunkProperties()),
          IsPaintChunk(1, 5, PaintChunk::Id(container2.Id(), kBackgroundType),
                       DefaultPaintChunkProperties()),
          IsPaintChunk(5, 6, PaintChunk::Id(content1.Id(), kForegroundType),
                       DefaultPaintChunkProperties())));

  // Simulate the situation when |container2| gets a z-index that is smaller
  // than that of |content1|.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
      // When under-invalidation-checking is enabled,
      // UseCachedSubsequenceIfPossible is forced off, and the client is
      // expected to create the same painting as in the previous paint.
      EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container2));
      {
        SubsequenceRecorder r(context, container2);
        EXPECT_EQ(kCached, DrawRect(context, container2, kBackgroundType,
                                    gfx::Rect(100, 200, 100, 100)));
        EXPECT_EQ(kCached, DrawRect(context, content2, kBackgroundType,
                                    gfx::Rect(100, 200, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, content2, kForegroundType,
                                    gfx::Rect(100, 200, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, container2, kForegroundType,
                                    gfx::Rect(100, 200, 100, 100)));
      }
      EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                  gfx::Rect(100, 100, 50, 200)));
      EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                  gfx::Rect(100, 100, 50, 200)));
    } else {
      EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container2));
      EXPECT_TRUE(DrawingRecorder::UseCachedDrawingIfPossible(context, content1,
                                                              kBackgroundType));
      EXPECT_TRUE(DrawingRecorder::UseCachedDrawingIfPossible(context, content1,
                                                              kForegroundType));
    }

    EXPECT_EQ(6u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(1u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kForegroundType),
                          IsSameId(container2.Id(), kForegroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType)));

  EXPECT_NO_SUBSEQUENCE(content1);
  EXPECT_SUBSEQUENCE(container2, 0, 1);
  EXPECT_NO_SUBSEQUENCE(content2);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(
          IsPaintChunk(0, 4, PaintChunk::Id(container2.Id(), kBackgroundType),
                       DefaultPaintChunkProperties()),
          IsPaintChunk(4, 6, PaintChunk::Id(content1.Id(), kBackgroundType),
                       DefaultPaintChunkProperties())));
}

TEST_P(PaintControllerTest, DisplayItemSwapOrderBeforeCachedSubsequence) {
  FakeDisplayItemClient& content1a =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1a");
  FakeDisplayItemClient& content1b =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1b");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content3 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content3");

  PaintChunk::Id content1a_id(content1a.Id(), kBackgroundType);
  PaintChunk::Id content1b_id(content1b.Id(), kBackgroundType);
  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  PaintChunk::Id content3_id(content3.Id(), kBackgroundType);
  gfx::Rect rect(100, 100, 50, 200);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, content1a, kBackgroundType, rect);
    DrawRect(context, content1b, kBackgroundType, rect);
    {
      SubsequenceRecorder r(context, container2);
      DrawRect(context, container2, kBackgroundType, rect);
    }
    DrawRect(context, content3, kBackgroundType, rect);
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content3.Id(), kBackgroundType)));

  // New paint order:
  // Subsequence(container1): container1, content1b(cached), content1a(cached).
  // Subsequence(container2): cached
  // Subsequence(contaienr3): container3, content3
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
      EXPECT_FALSE(DrawingRecorder::UseCachedDrawingIfPossible(
          context, content1b, kBackgroundType));
      EXPECT_EQ(kCached, DrawRect(context, content1b, kBackgroundType, rect));
      EXPECT_FALSE(DrawingRecorder::UseCachedDrawingIfPossible(
          context, content1a, kBackgroundType));
      EXPECT_EQ(kCached, DrawRect(context, content1a, kBackgroundType, rect));
      {
        EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
            context, container2));
        SubsequenceRecorder r(context, container2);
        EXPECT_EQ(kCached,
                  DrawRect(context, container2, kBackgroundType, rect));
      }
      EXPECT_FALSE(DrawingRecorder::UseCachedDrawingIfPossible(
          context, content3, kBackgroundType));
      EXPECT_EQ(kCached, DrawRect(context, content3, kBackgroundType, rect));
    } else {
      EXPECT_TRUE(DrawingRecorder::UseCachedDrawingIfPossible(
          context, content1b, kBackgroundType));
      EXPECT_TRUE(DrawingRecorder::UseCachedDrawingIfPossible(
          context, content1a, kBackgroundType));
      EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container2));
      EXPECT_TRUE(DrawingRecorder::UseCachedDrawingIfPossible(context, content3,
                                                              kBackgroundType));
    }

    EXPECT_EQ(4u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(1u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(1u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content1b.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content3.Id(), kBackgroundType)));
}

TEST_P(PaintControllerTest, CachedSubsequenceContainingFragments) {
  FakeDisplayItemClient& root =
      *MakeGarbageCollected<FakeDisplayItemClient>("root");
  constexpr wtf_size_t kFragmentCount = 3;
  FakeDisplayItemClient& container =
      *MakeGarbageCollected<FakeDisplayItemClient>("container");

  auto paint_container = [&container](GraphicsContext& context) {
    SubsequenceRecorder r(context, container);
    for (wtf_size_t i = 0; i < kFragmentCount; ++i) {
      ScopedDisplayItemFragment scoped_fragment(context, i);
      ScopedPaintChunkProperties content_chunk_properties(
          context.GetPaintController(), DefaultPaintChunkProperties(),
          container, kBackgroundType);
      DrawRect(context, container, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));
    }
  };

  // The first paint.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    ScopedPaintChunkProperties root_chunk_properties(
        paint_controller, DefaultPaintChunkProperties(), root, kBackgroundType);
    DrawRect(context, root, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    paint_container(context);
    DrawRect(context, root, kForegroundType, gfx::Rect(100, 100, 100, 100));
  }

  auto check_paint_results = [this, &root, &container]() {
    EXPECT_THAT(
        GetPersistentData().GetPaintChunks(),
        ElementsAre(
            IsPaintChunk(0, 1, PaintChunk::Id(root.Id(), kBackgroundType),
                         DefaultPaintChunkProperties()),
            // One chunk for all of the fragments because they have the
            // same properties.
            IsPaintChunk(1, 4, PaintChunk::Id(container.Id(), kBackgroundType),
                         DefaultPaintChunkProperties()),
            IsPaintChunk(4, 5, PaintChunk::Id(root.Id(), kForegroundType),
                         DefaultPaintChunkProperties())));
  };
  // Check results of the first paint.
  check_paint_results();

  // The second paint.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    ScopedPaintChunkProperties root_chunk_properties(
        paint_controller, DefaultPaintChunkProperties(), root, kBackgroundType);
    EXPECT_EQ(kCached, DrawRect(context, root, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));

    if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
      EXPECT_FALSE(paint_controller.UseCachedSubsequenceIfPossible(container));
      paint_container(context);
    } else {
      EXPECT_TRUE(paint_controller.UseCachedSubsequenceIfPossible(container));
    }
    EXPECT_EQ(kCached, DrawRect(context, root, kForegroundType,
                                gfx::Rect(100, 100, 100, 100)));
  }

  // The second paint should produce the exactly same results.
  check_paint_results();
}

TEST_P(PaintControllerTest, UpdateSwapOrderCrossingChunks) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");

  PaintChunk::Id container1_id(container1.Id(), kBackgroundType);
  auto* container1_effect = CreateOpacityEffect(e0(), 0.5);
  auto container1_properties = DefaultPaintChunkProperties();
  container1_properties.SetEffect(*container1_effect);

  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  auto* container2_effect = CreateOpacityEffect(e0(), 0.5);
  auto container2_properties = DefaultPaintChunkProperties();
  container2_properties.SetEffect(*container2_effect);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(
        container1_id, container1, container1_properties);
    DrawRect(context, container1, kBackgroundType,
             gfx::Rect(100, 100, 100, 100));
    DrawRect(context, content1, kBackgroundType, gfx::Rect(100, 100, 50, 200));
    paint_controller.UpdateCurrentPaintChunkProperties(
        container2_id, container2, container2_properties);
    DrawRect(context, container2, kBackgroundType,
             gfx::Rect(100, 200, 100, 100));
    DrawRect(context, content2, kBackgroundType, gfx::Rect(100, 200, 50, 200));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 2, container1_id, container1_properties),
                  IsPaintChunk(2, 4, container2_id, container2_properties)));

  // Move content2 into container1, without invalidation.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(
        container1_id, container1, container1_properties);
    EXPECT_EQ(kCached, DrawRect(context, container1, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached, DrawRect(context, content2, kBackgroundType,
                                gfx::Rect(100, 200, 50, 200)));
    paint_controller.UpdateCurrentPaintChunkProperties(
        container2_id, container2, container2_properties);
    EXPECT_EQ(kCached, DrawRect(context, container2, kBackgroundType,
                                gfx::Rect(100, 200, 100, 100)));

    EXPECT_EQ(4u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(1u, NumIndexedItems(paint_controller));
    EXPECT_EQ(3u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType),
                          IsSameId(container2.Id(), kBackgroundType)));

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 3, container1_id, container1_properties),
                  IsPaintChunk(3, 4, container2_id, container2_properties)));
}

TEST_P(PaintControllerTest, OutOfOrderNoCrash) {
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");

  const DisplayItem::Type kType1 = DisplayItem::kDrawingFirst;
  const DisplayItem::Type kType2 =
      static_cast<DisplayItem::Type>(DisplayItem::kDrawingFirst + 1);
  const DisplayItem::Type kType3 =
      static_cast<DisplayItem::Type>(DisplayItem::kDrawingFirst + 2);
  const DisplayItem::Type kType4 =
      static_cast<DisplayItem::Type>(DisplayItem::kDrawingFirst + 3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, client, kType1, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, client, kType2, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, client, kType3, gfx::Rect(100, 100, 50, 200));
    DrawRect(context, client, kType4, gfx::Rect(100, 100, 100, 100));
  }

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached,
              DrawRect(context, client, kType2, gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached,
              DrawRect(context, client, kType3, gfx::Rect(100, 100, 50, 200)));
    EXPECT_EQ(kCached,
              DrawRect(context, client, kType1, gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached,
              DrawRect(context, client, kType4, gfx::Rect(100, 100, 100, 100)));
  }
}

TEST_P(PaintControllerTest, CachedNestedSubsequenceUpdate) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");

  PaintChunk::Id container1_background_id(container1.Id(), kBackgroundType);
  auto* container1_effect = CreateOpacityEffect(e0(), 0.5);
  auto container1_background_properties = DefaultPaintChunkProperties();
  container1_background_properties.SetEffect(*container1_effect);
  PaintChunk::Id container1_foreground_id(container1.Id(), kForegroundType);
  auto container1_foreground_properties = DefaultPaintChunkProperties();
  container1_foreground_properties.SetEffect(*container1_effect);

  PaintChunk::Id content1_id(content1.Id(), kBackgroundType);
  auto* content1_effect = CreateOpacityEffect(e0(), 0.6);
  auto content1_properties = DefaultPaintChunkProperties();
  content1_properties.SetEffect(*content1_effect);

  PaintChunk::Id container2_background_id(container2.Id(), kBackgroundType);
  auto* container2_effect = CreateOpacityEffect(e0(), 0.7);
  auto container2_background_properties = DefaultPaintChunkProperties();
  container2_background_properties.SetEffect(*container2_effect);

  PaintChunk::Id content2_id(content2.Id(), kBackgroundType);
  auto* content2_effect = CreateOpacityEffect(e0(), 0.8);
  auto content2_properties = DefaultPaintChunkProperties();
  content2_properties.SetEffect(*content2_effect);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    {
      SubsequenceRecorder r(context, container1);
      paint_controller.UpdateCurrentPaintChunkProperties(
          container1_background_id, container1,
          container1_background_properties);
      DrawRect(context, container1, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));

      {
        SubsequenceRecorder inner_r(context, content1);
        paint_controller.UpdateCurrentPaintChunkProperties(
            content1_id, content1, content1_properties);
        DrawRect(context, content1, kBackgroundType,
                 gfx::Rect(100, 100, 50, 200));
        DrawRect(context, content1, kForegroundType,
                 gfx::Rect(100, 100, 50, 200));
      }
      paint_controller.UpdateCurrentPaintChunkProperties(
          container1_foreground_id, container1,
          container1_foreground_properties);
      DrawRect(context, container1, kForegroundType,
               gfx::Rect(100, 100, 100, 100));
    }
    {
      SubsequenceRecorder r(context, container2);
      paint_controller.UpdateCurrentPaintChunkProperties(
          container2_background_id, container2,
          container2_background_properties);
      DrawRect(context, container2, kBackgroundType,
               gfx::Rect(100, 200, 100, 100));
      {
        SubsequenceRecorder inner_r(context, content2);
        paint_controller.UpdateCurrentPaintChunkProperties(
            co
```