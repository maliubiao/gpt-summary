Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine.
Specifically, it's the `paint_controller_test.cc` file located in `blink/renderer/platform/graphics/paint/`.

I need to:
1. **List the functionalities** of this test file.
2. **Explain its relationship with JavaScript, HTML, and CSS** and provide examples if any.
3. **Describe any logical reasoning** with example inputs and outputs.
4. **Point out common usage errors** related to the tested functionalities.
5. **Summarize its functionalities** as it's the third part of a four-part analysis.

Based on the code, this file seems to contain unit tests for the `PaintController` class in the Blink rendering engine. The `PaintController` is responsible for managing the painting process, including recording and caching drawing operations.

Here's a breakdown of the functionalities tested in this specific part of the code:

*   **Caching and replaying paint subsequences:** Tests related to `SubsequenceRecorder` and `UseCachedSubsequenceIfPossible` to verify how painting operations can be cached and reused in subsequent paints.
*   **Handling invalidations:** Checks how the paint controller behaves when parts of the painted content are invalidated. It verifies if the correct parts are repainted and if cached data is used appropriately.
*   **Skipping the cache:** Tests the `BeginSkippingCache` and `EndSkippingCache` methods, which allow temporarily disabling the paint cache.
*   **Partial skipping of cache:** Verifies the behavior when some parts of the painting are done with the cache disabled.
*   **Handling duplicated IDs:** Tests how the paint controller deals with potential duplicate IDs for display items and paint chunks, especially when the cache is skipped or for transient paint controllers.
*   **Managing paint chunks:** Checks if paint chunks are correctly created and associated with display items.
*   **Frame lifecycle management:** Tests the `BeginFrame` and `EndFrame` methods of the `PaintController`, which manage the painting process for individual frames.
*   **Inserting items in front:** Simulates scenarios where items are added to the display list in front of existing items.
*   **Transient paint controllers:** Tests the behavior of temporary `PaintController` instances.
*   **Region capture data:** Verifies the functionality for recording region capture data associated with painted elements.

Now, let's address the relationship with web technologies:

*   **JavaScript:** JavaScript can trigger changes to the DOM and CSS styles, leading to repaints. The `PaintController` is responsible for efficiently updating the rendered output based on these changes. For example, a JavaScript animation that modifies an element's position or appearance would trigger repainting handled by the `PaintController`.
*   **HTML:** The structure of the HTML document directly influences the painting order and the hierarchy of paint artifacts. The tests demonstrate how the `PaintController` handles nested elements and their respective painting operations. For instance, the `SubsequenceRecorder` is used to group paint operations for specific HTML elements.
*   **CSS:** CSS properties determine the visual appearance of elements, such as colors, sizes, and positions. Changes in CSS styles often lead to repainting. The tests involve drawing rectangles with different properties, simulating how the `PaintController` records and potentially caches these drawing operations based on CSS styles.

Let's create some examples for logical reasoning:

**Scenario 1: Caching and Invalidation**

*   **Hypothetical Input:** An HTML `div` element with a red background is initially painted. Then, a JavaScript function changes the background color to blue.
*   **Expected Output:** The initial paint operation (drawing a red rectangle) is cached. When the color changes, the cached operation might be invalidated, and a new paint operation (drawing a blue rectangle) is recorded. The test `TEST_P(PaintControllerTest, CachedSubsequenceInvalidation)` demonstrates similar logic.

**Scenario 2: Skipping the Cache**

*   **Hypothetical Input:** A JavaScript function repeatedly draws a complex shape on a canvas element. To ensure the latest version is always displayed, the paint operations are performed within `BeginSkippingCache()` and `EndSkippingCache()`.
*   **Expected Output:** The drawing operations within the skipped cache block are not cached. Each time the function is called, the shape is redrawn from scratch. The test `TEST_P(PaintControllerTest, SkipCache)` covers this.

Common usage errors and potential issues:

*   **Incorrectly assuming caching:** Developers might assume that every paint operation is automatically cached. However, factors like invalidation or explicitly skipping the cache can prevent caching. The tests with `Invalidate()` demonstrate this.
*   **Unexpected repaint behavior after invalidation:**  Failing to understand which parts of the screen are invalidated can lead to unexpected repainting and performance issues. The tests with nested subsequences and invalidations highlight how changes in one part of the hierarchy can affect others.
*   **Overuse of `BeginSkippingCache()`:** Disabling the cache too often can negatively impact performance, as it prevents the reuse of previous drawing operations.

**Summary of Functionalities (Part 3):**

This part of the `paint_controller_test.cc` file focuses on testing the advanced caching mechanisms within the `PaintController`. It verifies how paint operations are grouped into subsequences, how these subsequences are cached and reused, and how invalidations affect the caching process. Additionally, it tests the ability to temporarily bypass the cache and the handling of potential issues like duplicate IDs during painting. It also covers the basic lifecycle of frame painting and management of paint items.

```cpp
TEST_P(PaintControllerTest, CachedSubsequenceInvalidation) {
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  PaintChunk::Id container1_background_id(container1.Id(), kBackgroundType);
  PaintChunkProperties container1_background_properties;
  PaintChunk::Id container1_foreground_id(container1.Id(), kForegroundType);
  PaintChunkProperties container1_foreground_properties;
  FakeDisplayItemClient& content1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1");
  PaintChunk::Id content1_id(content1.Id(), kBackgroundType);
  PaintChunkProperties content1_properties;
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  PaintChunk::Id container2_background_id(container2.Id(), kBackgroundType);
  PaintChunkProperties container2_background_properties;
  FakeDisplayItemClient& content2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2");
  PaintChunk::Id content2_id(content2.Id(), kBackgroundType);
  PaintChunkProperties content2_properties;
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
        paint_controller.UpdateCurrentPaintChunkProperties(content1_id, content1,
                                                           content1_properties);
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
            content2_id, content2, content2_properties);
        DrawRect(context, content2, kBackgroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
    }
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 3);
  EXPECT_SUBSEQUENCE(content1, 1, 2);
  EXPECT_SUBSEQUENCE(container2, 3, 5);
  EXPECT_SUBSEQUENCE(content2, 4, 5);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 1, container1_background_id,
                               container1_background_properties),
                  IsPaintChunk(1, 3, content1_id, content1_properties),
                  IsPaintChunk(3, 4, container1_foreground_id,
                               container1_foreground_properties),
                  IsPaintChunk(4, 5, container2_background_id,
                               container2_background_properties),
                  IsPaintChunk(5, 6, content2_id, content2_properties)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    // Invalidate container1 but not content1.
    container1.Invalidate();
    // Container2 itself now becomes empty (but still has the 'content2' child),
    // and chooses not to output subsequence info.
    container2.Invalidate();
    content2.Invalidate();
    EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));
    EXPECT_FALSE(
        SubsequenceRecorder::UseCachedSubsequenceIfPossible(context, content2));
    // Content2 now outputs foreground only.
    {
      SubsequenceRecorder r(context, content2);
      paint_controller.UpdateCurrentPaintChunkProperties(content2_id, content2,
                                                         content2_properties);
      EXPECT_EQ(kPaintedNew, DrawRect(context, content2, kForegroundType,
                                      gfx::Rect(100, 200, 50, 200)));
    }
    // Repaint container1 with foreground only.
    {
      SubsequenceRecorder r(context, container1);
      EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container1));
      // Use cached subsequence of content1.
      if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
        // When under-invalidation-checking is enabled,
        // UseCachedSubsequenceIfPossible is forced off, and the client is
        // expected to create the same painting as in the previous paint.
        EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
            context, content1));
        SubsequenceRecorder inner_r(context, content1);
        paint_controller.UpdateCurrentPaintChunkProperties(
            content1_id, content1, content1_properties);
        EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                    gfx::Rect(100, 100, 50, 200)));
      } else {
        EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
            context, content1));
      }
      paint_controller.UpdateCurrentPaintChunkProperties(
          container1_foreground_id, container1,
          container1_foreground_properties);
      EXPECT_EQ(kRepaintedCachedItem,
                DrawRect(context, container1, kForegroundType,
                         gfx::Rect(100, 100, 100, 100)));
    }

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(1u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(6u, NumIndexedItems(paint_controller));
    EXPECT_EQ(0u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content2.Id(), kForegroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType)));

  EXPECT_NO_SUBSEQUENCE(container2);
  EXPECT_SUBSEQUENCE(content2, 0, 1);
  EXPECT_SUBSEQUENCE(container1, 1, 3);
  EXPECT_SUBSEQUENCE(content1, 1, 2);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, content2_id, content2_properties),
                          IsPaintChunk(1, 3, content1_id, content1_properties),
                          IsPaintChunk(3, 4, container1_foreground_id,
                                       container1_foreground_properties)));
}

TEST_P(PaintControllerTest, CachedNestedSubsequenceKeepingDescendants) {
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled())
    return;

  FakeDisplayItemClient& root =
      *MakeGarbageCollected<FakeDisplayItemClient>("root");
  auto properties = DefaultPaintChunkProperties();
  PaintChunk::Id root_id(root.Id(), DisplayItem::kLayerChunk);
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  PaintChunk::Id container1_bg_id(container1.Id(), kBackgroundType);
  PaintChunk::Id container1_fg_id(container1.Id(), kForegroundType);
  FakeDisplayItemClient& content1a =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1a");
  PaintChunk::Id content1a_id(content1a.Id(), kBackgroundType);
  FakeDisplayItemClient& content1b =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1b");
  PaintChunk::Id content1b_id(content1b.Id(), kForegroundType);
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  FakeDisplayItemClient& content2a =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2a");
  PaintChunk::Id content2a_id(content2a.Id(), kBackgroundType);
  FakeDisplayItemClient& content2b =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2b");
  PaintChunk::Id content2b_id(content2b.Id(), kForegroundType);
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(root_id, root,
                                                       properties);

    {
      SubsequenceRecorder r(context, container1);
      DrawRect(context, container1, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));
      {
        SubsequenceRecorder inner_r(context, content1a);
        DrawRect(context, content1a, kBackgroundType,
                 gfx::Rect(100, 100, 50, 200));
      }
      {
        SubsequenceRecorder inner_r(context, content1b);
        DrawRect(context, content1b, kForegroundType,
                 gfx::Rect(100, 100, 50, 200));
      }
      DrawRect(context, container1, kForegroundType,
               gfx::Rect(100, 100, 100, 100));
    }
    {
      SubsequenceRecorder r(context, container2);
      DrawRect(context, container2, kBackgroundType,
               gfx::Rect(100, 200, 100, 100));
      {
        SubsequenceRecorder inner_r(context, content2a);
        DrawRect(context, content2a, kBackgroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
      {
        SubsequenceRecorder inner_r(context, content2b);
        DrawRect(context, content2b, kForegroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
    }

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 4);
  EXPECT_SUBSEQUENCE(content1a, 1, 2);
  EXPECT_SUBSEQUENCE(content1b, 2, 3);
  EXPECT_SUBSEQUENCE(container2, 4, 7);
  EXPECT_SUBSEQUENCE(content2a, 5, 6);
  EXPECT_SUBSEQUENCE(content2b, 6, 7);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container1_bg_id, properties),
                          IsPaintChunk(1, 2, content1a_id, properties),
                          IsPaintChunk(2, 3, content1b_id, properties),
                          IsPaintChunk(3, 4, container1_fg_id, properties),
                          IsPaintChunk(4, 5, container2_id, properties),
                          IsPaintChunk(5, 6, content2a_id, properties),
                          IsPaintChunk(6, 7, content2b_id, properties)));

  // Nothing invalidated. Should keep all subsequences.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container1));
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));

    EXPECT_EQ(7u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(6u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 4);
  EXPECT_SUBSEQUENCE(content1a, 1, 2);
  EXPECT_SUBSEQUENCE(content1b, 2, 3);
  EXPECT_SUBSEQUENCE(container2, 4, 7);
  EXPECT_SUBSEQUENCE(content2a, 5, 6);
  EXPECT_SUBSEQUENCE(content2b, 6, 7);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container1_bg_id, properties),
                          IsPaintChunk(1, 2, content1a_id, properties),
                          IsPaintChunk(2, 3, content1b_id, properties),
                          IsPaintChunk(3, 4, container1_fg_id, properties),
                          IsPaintChunk(4, 5, container2_id, properties),
                          IsPaintChunk(5, 6, content2a_id, properties),
                          IsPaintChunk(6, 7, content2b_id, properties)));

  // Swap order of the subsequences of container1 and container2.
  // Nothing invalidated. Should keep all subsequences.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container1));

    EXPECT_EQ(7u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(6u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container2, 0, 3);
  EXPECT_SUBSEQUENCE(content2a, 1, 2);
  EXPECT_SUBSEQUENCE(content2b, 2, 3);
  EXPECT_SUBSEQUENCE(container1, 3, 7);
  EXPECT_SUBSEQUENCE(content1a, 4, 5);
  EXPECT_SUBSEQUENCE(content1b, 5, 6);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container2_id, properties),
                          IsPaintChunk(1, 2, content2a_id, properties),
                          IsPaintChunk(2, 3, content2b_id, properties),
                          IsPaintChunk(3, 4, container1_bg_id, properties),
                          IsPaintChunk(4, 5, content1a_id, properties),
                          IsPaintChunk(5, 6, content1b_id, properties),
                          IsPaintChunk(6, 7, container1_fg_id, properties)));
}

TEST_P(PaintControllerTest, SkipCache) {
  FakeDisplayItemClient& multicol =
      *MakeGarbageCollected<FakeDisplayItemClient>("multicol");
  FakeDisplayItemClient& content =
      *MakeGarbageCollected<FakeDisplayItemClient>("content");
  gfx::Rect rect1(100, 100, 50, 50);
  gfx::Rect rect2(150, 100, 50, 50);
  gfx::Rect rect3(200, 100, 50, 50);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, multicol, kBackgroundType, gfx::Rect(100, 200, 100, 100));

    paint_controller.BeginSkippingCache();
    DrawRect(context, content, kForegroundType, rect1);
    DrawRect(context, content, kForegroundType, rect2);
    paint_controller.EndSkippingCache();
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Draw again with nothing invalidated.
    EXPECT_TRUE(ClientCacheIsValid(multicol));
    EXPECT_EQ(kCached, DrawRect(context, multicol, kBackgroundType,
                                gfx::Rect(100, 200, 100, 100)));

    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect1));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    paint_controller.EndSkippingCache();

    EXPECT_EQ(1u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(1u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Now the multicol becomes 3 columns and repaints.
    multicol.Invalidate();
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, multicol, kBackgroundType,
                                             gfx::Rect(100, 100, 100, 100)));

    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect1));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect3));
    paint_controller.EndSkippingCache();

    // We should repaint everything on invalidation of the scope container.
    const auto& display_item_list =
        GetNewPaintArtifact(paint_controller).GetDisplayItemList();
    EXPECT_THAT(display_item_list,
                ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                            IsSameId(content.Id(), kForegroundType),
                            IsSameId(content.Id(), kForegroundType),
                            IsSameId(content.Id(), kForegroundType)));
  }
  EXPECT_DEFAULT_ROOT_CHUNK(4);
}

TEST_P(PaintControllerTest, PartialSkipCache) {
  FakeDisplayItemClient& content =
      *MakeGarbageCollected<FakeDisplayItemClient>("content");

  gfx::Rect rect1(100, 100, 50, 50);
  gfx::Rect rect2(150, 100, 50, 50);
  gfx::Rect rect3(200, 100, 50, 50);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, content, kBackgroundType, rect1);
    paint_controller.BeginSkippingCache();
    DrawRect(context, content, kForegroundType, rect2);
    paint_controller.EndSkippingCache();
    DrawRect(context, content, kForegroundType, rect3);
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));

  // Content's cache is invalid because it has display items skipped cache.
  EXPECT_FALSE(ClientCacheIsValid(content));
  EXPECT_EQ(PaintInvalidationReason::kUncacheable,
            content.GetPaintInvalidationReason());

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Draw again with nothing invalidated.
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kBackgroundType, rect1));
    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    paint_controller.EndSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect3));

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(0u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
}

TEST_P(PaintControllerTest, SkipCacheDuplicatedItemAndChunkIds) {
  FakeDisplayItemClient& chunk_client =
      *MakeGarbageCollected<FakeDisplayItemClient>("chunk client");
  FakeDisplayItemClient& item_client =
      *MakeGarbageCollected<FakeDisplayItemClient>("item client");
  auto properties = DefaultPaintChunkProperties();
  PaintChunk::Id chunk_id(chunk_client.Id(), DisplayItem::kLayerChunk);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.BeginSkippingCache();
    {
      SubsequenceRecorder r(context, chunk_client);
      paint_controller.UpdateCurrentPaintChunkProperties(chunk_id, chunk_client,
                                                         properties);
      DrawRect(context, item_client, kBackgroundType,
               gfx::Rect(0, 0, 100, 100));
    }
    paint_controller.UpdateCurrentPaintChunkProperties(chunk_id, chunk_client,
                                                       properties);
    DrawRect(context, item_client, kBackgroundType, gfx::Rect(0, 0, 100, 100));
    paint_controller.EndSkippingCache();
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(item_client.Id(), kBackgroundType),
                          IsSameId(item_client.Id(), kBackgroundType)));
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[0].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[1].IsCacheable());

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, chunk_id, properties),
                          IsPaintChunk(1, 2, chunk_id, properties)));
  EXPECT_FALSE(GetPersistentData().GetPaintChunks()[0].is_cacheable);
  EXPECT_FALSE(GetPersistentData().GetPaintChunks()[1].is_cacheable);
}

TEST_P(PaintControllerTest, SmallPaintControllerHasOnePaintChunk) {
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("test client");

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, client, kBackgroundType, gfx::Rect(0, 0, 100, 100));
  }
  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1)));
}
void DrawPath(GraphicsContext& context,
              DisplayItemClient& client,
              DisplayItem::Type type,
              unsigned count) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, client, type))
    return;

  DrawingRecorder recorder(context, client, type, gfx::Rect(0, 0, 100, 100));
  SkPath path;
  path.moveTo(0, 0);
  path.lineTo(0, 100);
  path.lineTo(50, 50);
  path.lineTo(100, 100);
  path.lineTo(100, 0);
  path.close();
  cc::PaintFlags flags;
  flags.setAntiAlias(true);
  for (unsigned i = 0; i < count; i++)
    context.DrawPath(path, flags, AutoDarkMode::Disabled());
}

TEST_P(PaintControllerTest, BeginAndEndFrame) {
  class FakeFrame {};

  PaintController paint_controller;
  // PaintController should have one null frame in the stack since beginning.
  paint_controller.SetFirstPainted();
  FrameFirstPaint result = paint_controller.EndFrame(nullptr);
  EXPECT_TRUE(result.first_painted);
  EXPECT_FALSE(result.text_painted);
  EXPECT_FALSE(result.image_painted);
  // Readd the null frame.
  paint_controller.BeginFrame(nullptr);

  std::unique
### 提示词
```
这是目录为blink/renderer/platform/graphics/paint/paint_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ntent2_id, content2, content2_properties);
        DrawRect(context, content2, kBackgroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
    }
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2.Id(), kBackgroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 3);
  EXPECT_SUBSEQUENCE(content1, 1, 2);
  EXPECT_SUBSEQUENCE(container2, 3, 5);
  EXPECT_SUBSEQUENCE(content2, 4, 5);

  EXPECT_THAT(
      GetPersistentData().GetPaintChunks(),
      ElementsAre(IsPaintChunk(0, 1, container1_background_id,
                               container1_background_properties),
                  IsPaintChunk(1, 3, content1_id, content1_properties),
                  IsPaintChunk(3, 4, container1_foreground_id,
                               container1_foreground_properties),
                  IsPaintChunk(4, 5, container2_background_id,
                               container2_background_properties),
                  IsPaintChunk(5, 6, content2_id, content2_properties)));

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    // Invalidate container1 but not content1.
    container1.Invalidate();
    // Container2 itself now becomes empty (but still has the 'content2' child),
    // and chooses not to output subsequence info.
    container2.Invalidate();
    content2.Invalidate();
    EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));
    EXPECT_FALSE(
        SubsequenceRecorder::UseCachedSubsequenceIfPossible(context, content2));
    // Content2 now outputs foreground only.
    {
      SubsequenceRecorder r(context, content2);
      paint_controller.UpdateCurrentPaintChunkProperties(content2_id, content2,
                                                         content2_properties);
      EXPECT_EQ(kPaintedNew, DrawRect(context, content2, kForegroundType,
                                      gfx::Rect(100, 200, 50, 200)));
    }
    // Repaint container1 with foreground only.
    {
      SubsequenceRecorder r(context, container1);
      EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
          context, container1));
      // Use cached subsequence of content1.
      if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled()) {
        // When under-invalidation-checking is enabled,
        // UseCachedSubsequenceIfPossible is forced off, and the client is
        // expected to create the same painting as in the previous paint.
        EXPECT_FALSE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
            context, content1));
        SubsequenceRecorder inner_r(context, content1);
        paint_controller.UpdateCurrentPaintChunkProperties(
            content1_id, content1, content1_properties);
        EXPECT_EQ(kCached, DrawRect(context, content1, kBackgroundType,
                                    gfx::Rect(100, 100, 50, 200)));
        EXPECT_EQ(kCached, DrawRect(context, content1, kForegroundType,
                                    gfx::Rect(100, 100, 50, 200)));
      } else {
        EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
            context, content1));
      }
      paint_controller.UpdateCurrentPaintChunkProperties(
          container1_foreground_id, container1,
          container1_foreground_properties);
      EXPECT_EQ(kRepaintedCachedItem,
                DrawRect(context, container1, kForegroundType,
                         gfx::Rect(100, 100, 100, 100)));
    }

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(1u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(6u, NumIndexedItems(paint_controller));
    EXPECT_EQ(0u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(1u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content2.Id(), kForegroundType),
                          IsSameId(content1.Id(), kBackgroundType),
                          IsSameId(content1.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType)));

  EXPECT_NO_SUBSEQUENCE(container2);
  EXPECT_SUBSEQUENCE(content2, 0, 1);
  EXPECT_SUBSEQUENCE(container1, 1, 3);
  EXPECT_SUBSEQUENCE(content1, 1, 2);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, content2_id, content2_properties),
                          IsPaintChunk(1, 3, content1_id, content1_properties),
                          IsPaintChunk(3, 4, container1_foreground_id,
                                       container1_foreground_properties)));
}

TEST_P(PaintControllerTest, CachedNestedSubsequenceKeepingDescendants) {
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled())
    return;

  FakeDisplayItemClient& root =
      *MakeGarbageCollected<FakeDisplayItemClient>("root");
  auto properties = DefaultPaintChunkProperties();
  PaintChunk::Id root_id(root.Id(), DisplayItem::kLayerChunk);
  FakeDisplayItemClient& container1 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container1");
  PaintChunk::Id container1_bg_id(container1.Id(), kBackgroundType);
  PaintChunk::Id container1_fg_id(container1.Id(), kForegroundType);
  FakeDisplayItemClient& content1a =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1a");
  PaintChunk::Id content1a_id(content1a.Id(), kBackgroundType);
  FakeDisplayItemClient& content1b =
      *MakeGarbageCollected<FakeDisplayItemClient>("content1b");
  PaintChunk::Id content1b_id(content1b.Id(), kForegroundType);
  FakeDisplayItemClient& container2 =
      *MakeGarbageCollected<FakeDisplayItemClient>("container2");
  PaintChunk::Id container2_id(container2.Id(), kBackgroundType);
  FakeDisplayItemClient& content2a =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2a");
  PaintChunk::Id content2a_id(content2a.Id(), kBackgroundType);
  FakeDisplayItemClient& content2b =
      *MakeGarbageCollected<FakeDisplayItemClient>("content2b");
  PaintChunk::Id content2b_id(content2b.Id(), kForegroundType);
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.UpdateCurrentPaintChunkProperties(root_id, root,
                                                       properties);

    {
      SubsequenceRecorder r(context, container1);
      DrawRect(context, container1, kBackgroundType,
               gfx::Rect(100, 100, 100, 100));
      {
        SubsequenceRecorder inner_r(context, content1a);
        DrawRect(context, content1a, kBackgroundType,
                 gfx::Rect(100, 100, 50, 200));
      }
      {
        SubsequenceRecorder inner_r(context, content1b);
        DrawRect(context, content1b, kForegroundType,
                 gfx::Rect(100, 100, 50, 200));
      }
      DrawRect(context, container1, kForegroundType,
               gfx::Rect(100, 100, 100, 100));
    }
    {
      SubsequenceRecorder r(context, container2);
      DrawRect(context, container2, kBackgroundType,
               gfx::Rect(100, 200, 100, 100));
      {
        SubsequenceRecorder inner_r(context, content2a);
        DrawRect(context, content2a, kBackgroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
      {
        SubsequenceRecorder inner_r(context, content2b);
        DrawRect(context, content2b, kForegroundType,
                 gfx::Rect(100, 200, 50, 200));
      }
    }

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 4);
  EXPECT_SUBSEQUENCE(content1a, 1, 2);
  EXPECT_SUBSEQUENCE(content1b, 2, 3);
  EXPECT_SUBSEQUENCE(container2, 4, 7);
  EXPECT_SUBSEQUENCE(content2a, 5, 6);
  EXPECT_SUBSEQUENCE(content2b, 6, 7);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container1_bg_id, properties),
                          IsPaintChunk(1, 2, content1a_id, properties),
                          IsPaintChunk(2, 3, content1b_id, properties),
                          IsPaintChunk(3, 4, container1_fg_id, properties),
                          IsPaintChunk(4, 5, container2_id, properties),
                          IsPaintChunk(5, 6, content2a_id, properties),
                          IsPaintChunk(6, 7, content2b_id, properties)));

  // Nothing invalidated. Should keep all subsequences.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container1));
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));

    EXPECT_EQ(7u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(6u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType),
                          IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container1, 0, 4);
  EXPECT_SUBSEQUENCE(content1a, 1, 2);
  EXPECT_SUBSEQUENCE(content1b, 2, 3);
  EXPECT_SUBSEQUENCE(container2, 4, 7);
  EXPECT_SUBSEQUENCE(content2a, 5, 6);
  EXPECT_SUBSEQUENCE(content2b, 6, 7);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container1_bg_id, properties),
                          IsPaintChunk(1, 2, content1a_id, properties),
                          IsPaintChunk(2, 3, content1b_id, properties),
                          IsPaintChunk(3, 4, container1_fg_id, properties),
                          IsPaintChunk(4, 5, container2_id, properties),
                          IsPaintChunk(5, 6, content2a_id, properties),
                          IsPaintChunk(6, 7, content2b_id, properties)));

  // Swap order of the subsequences of container1 and container2.
  // Nothing invalidated. Should keep all subsequences.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container2));
    EXPECT_TRUE(SubsequenceRecorder::UseCachedSubsequenceIfPossible(
        context, container1));

    EXPECT_EQ(7u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(6u, NumCachedNewSubsequences(paint_controller));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(container2.Id(), kBackgroundType),
                          IsSameId(content2a.Id(), kBackgroundType),
                          IsSameId(content2b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kBackgroundType),
                          IsSameId(content1a.Id(), kBackgroundType),
                          IsSameId(content1b.Id(), kForegroundType),
                          IsSameId(container1.Id(), kForegroundType)));

  EXPECT_SUBSEQUENCE(container2, 0, 3);
  EXPECT_SUBSEQUENCE(content2a, 1, 2);
  EXPECT_SUBSEQUENCE(content2b, 2, 3);
  EXPECT_SUBSEQUENCE(container1, 3, 7);
  EXPECT_SUBSEQUENCE(content1a, 4, 5);
  EXPECT_SUBSEQUENCE(content1b, 5, 6);

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, container2_id, properties),
                          IsPaintChunk(1, 2, content2a_id, properties),
                          IsPaintChunk(2, 3, content2b_id, properties),
                          IsPaintChunk(3, 4, container1_bg_id, properties),
                          IsPaintChunk(4, 5, content1a_id, properties),
                          IsPaintChunk(5, 6, content1b_id, properties),
                          IsPaintChunk(6, 7, container1_fg_id, properties)));
}

TEST_P(PaintControllerTest, SkipCache) {
  FakeDisplayItemClient& multicol =
      *MakeGarbageCollected<FakeDisplayItemClient>("multicol");
  FakeDisplayItemClient& content =
      *MakeGarbageCollected<FakeDisplayItemClient>("content");
  gfx::Rect rect1(100, 100, 50, 50);
  gfx::Rect rect2(150, 100, 50, 50);
  gfx::Rect rect3(200, 100, 50, 50);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

    DrawRect(context, multicol, kBackgroundType, gfx::Rect(100, 200, 100, 100));

    paint_controller.BeginSkippingCache();
    DrawRect(context, content, kForegroundType, rect1);
    DrawRect(context, content, kForegroundType, rect2);
    paint_controller.EndSkippingCache();
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Draw again with nothing invalidated.
    EXPECT_TRUE(ClientCacheIsValid(multicol));
    EXPECT_EQ(kCached, DrawRect(context, multicol, kBackgroundType,
                                gfx::Rect(100, 200, 100, 100)));

    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect1));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    paint_controller.EndSkippingCache();

    EXPECT_EQ(1u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(1u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(3);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Now the multicol becomes 3 columns and repaints.
    multicol.Invalidate();
    EXPECT_EQ(kRepaintedCachedItem, DrawRect(context, multicol, kBackgroundType,
                                             gfx::Rect(100, 100, 100, 100)));

    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect1));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect3));
    paint_controller.EndSkippingCache();

    // We should repaint everything on invalidation of the scope container.
    const auto& display_item_list =
        GetNewPaintArtifact(paint_controller).GetDisplayItemList();
    EXPECT_THAT(display_item_list,
                ElementsAre(IsSameId(multicol.Id(), kBackgroundType),
                            IsSameId(content.Id(), kForegroundType),
                            IsSameId(content.Id(), kForegroundType),
                            IsSameId(content.Id(), kForegroundType)));
  }
  EXPECT_DEFAULT_ROOT_CHUNK(4);
}

TEST_P(PaintControllerTest, PartialSkipCache) {
  FakeDisplayItemClient& content =
      *MakeGarbageCollected<FakeDisplayItemClient>("content");

  gfx::Rect rect1(100, 100, 50, 50);
  gfx::Rect rect2(150, 100, 50, 50);
  gfx::Rect rect3(200, 100, 50, 50);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, content, kBackgroundType, rect1);
    paint_controller.BeginSkippingCache();
    DrawRect(context, content, kForegroundType, rect2);
    paint_controller.EndSkippingCache();
    DrawRect(context, content, kForegroundType, rect3);
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));

  // Content's cache is invalid because it has display items skipped cache.
  EXPECT_FALSE(ClientCacheIsValid(content));
  EXPECT_EQ(PaintInvalidationReason::kUncacheable,
            content.GetPaintInvalidationReason());

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    // Draw again with nothing invalidated.
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kBackgroundType, rect1));
    paint_controller.BeginSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect2));
    paint_controller.EndSkippingCache();
    EXPECT_EQ(kPaintedNew, DrawRect(context, content, kForegroundType, rect3));

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    EXPECT_EQ(0u, NumIndexedItems(paint_controller));
    EXPECT_EQ(0u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(content.Id(), kBackgroundType),
                          IsSameId(content.Id(), kForegroundType),
                          IsSameId(content.Id(), kForegroundType)));
}

TEST_P(PaintControllerTest, SkipCacheDuplicatedItemAndChunkIds) {
  FakeDisplayItemClient& chunk_client =
      *MakeGarbageCollected<FakeDisplayItemClient>("chunk client");
  FakeDisplayItemClient& item_client =
      *MakeGarbageCollected<FakeDisplayItemClient>("item client");
  auto properties = DefaultPaintChunkProperties();
  PaintChunk::Id chunk_id(chunk_client.Id(), DisplayItem::kLayerChunk);

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    paint_controller.BeginSkippingCache();
    {
      SubsequenceRecorder r(context, chunk_client);
      paint_controller.UpdateCurrentPaintChunkProperties(chunk_id, chunk_client,
                                                         properties);
      DrawRect(context, item_client, kBackgroundType,
               gfx::Rect(0, 0, 100, 100));
    }
    paint_controller.UpdateCurrentPaintChunkProperties(chunk_id, chunk_client,
                                                       properties);
    DrawRect(context, item_client, kBackgroundType, gfx::Rect(0, 0, 100, 100));
    paint_controller.EndSkippingCache();
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(item_client.Id(), kBackgroundType),
                          IsSameId(item_client.Id(), kBackgroundType)));
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[0].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[1].IsCacheable());

  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1, chunk_id, properties),
                          IsPaintChunk(1, 2, chunk_id, properties)));
  EXPECT_FALSE(GetPersistentData().GetPaintChunks()[0].is_cacheable);
  EXPECT_FALSE(GetPersistentData().GetPaintChunks()[1].is_cacheable);
}

TEST_P(PaintControllerTest, SmallPaintControllerHasOnePaintChunk) {
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("test client");

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, client, kBackgroundType, gfx::Rect(0, 0, 100, 100));
  }
  EXPECT_THAT(GetPersistentData().GetPaintChunks(),
              ElementsAre(IsPaintChunk(0, 1)));
}
void DrawPath(GraphicsContext& context,
              DisplayItemClient& client,
              DisplayItem::Type type,
              unsigned count) {
  if (DrawingRecorder::UseCachedDrawingIfPossible(context, client, type))
    return;

  DrawingRecorder recorder(context, client, type, gfx::Rect(0, 0, 100, 100));
  SkPath path;
  path.moveTo(0, 0);
  path.lineTo(0, 100);
  path.lineTo(50, 50);
  path.lineTo(100, 100);
  path.lineTo(100, 0);
  path.close();
  cc::PaintFlags flags;
  flags.setAntiAlias(true);
  for (unsigned i = 0; i < count; i++)
    context.DrawPath(path, flags, AutoDarkMode::Disabled());
}

TEST_P(PaintControllerTest, BeginAndEndFrame) {
  class FakeFrame {};

  PaintController paint_controller;
  // PaintController should have one null frame in the stack since beginning.
  paint_controller.SetFirstPainted();
  FrameFirstPaint result = paint_controller.EndFrame(nullptr);
  EXPECT_TRUE(result.first_painted);
  EXPECT_FALSE(result.text_painted);
  EXPECT_FALSE(result.image_painted);
  // Readd the null frame.
  paint_controller.BeginFrame(nullptr);

  std::unique_ptr<FakeFrame> frame1(new FakeFrame);
  paint_controller.BeginFrame(frame1.get());
  paint_controller.SetFirstPainted();
  paint_controller.SetTextPainted();
  paint_controller.SetImagePainted();

  result = paint_controller.EndFrame(frame1.get());
  EXPECT_TRUE(result.first_painted);
  EXPECT_TRUE(result.text_painted);
  EXPECT_TRUE(result.image_painted);

  std::unique_ptr<FakeFrame> frame2(new FakeFrame);
  paint_controller.BeginFrame(frame2.get());
  paint_controller.SetFirstPainted();

  std::unique_ptr<FakeFrame> frame3(new FakeFrame);
  paint_controller.BeginFrame(frame3.get());
  paint_controller.SetTextPainted();
  paint_controller.SetImagePainted();

  result = paint_controller.EndFrame(frame3.get());
  EXPECT_FALSE(result.first_painted);
  EXPECT_TRUE(result.text_painted);
  EXPECT_TRUE(result.image_painted);

  result = paint_controller.EndFrame(frame2.get());
  EXPECT_TRUE(result.first_painted);
  EXPECT_FALSE(result.text_painted);
  EXPECT_FALSE(result.image_painted);
}

TEST_P(PaintControllerTest, InsertValidItemInFront) {
  FakeDisplayItemClient& first =
      *MakeGarbageCollected<FakeDisplayItemClient>("first");
  FakeDisplayItemClient& second =
      *MakeGarbageCollected<FakeDisplayItemClient>("second");
  FakeDisplayItemClient& third =
      *MakeGarbageCollected<FakeDisplayItemClient>("third");
  FakeDisplayItemClient& fourth =
      *MakeGarbageCollected<FakeDisplayItemClient>("fourth");

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    DrawRect(context, first, kBackgroundType, gfx::Rect(100, 100, 300, 300));
    DrawRect(context, second, kBackgroundType, gfx::Rect(100, 100, 200, 200));
    DrawRect(context, third, kBackgroundType, gfx::Rect(100, 100, 100, 100));
    DrawRect(context, fourth, kBackgroundType, gfx::Rect(100, 100, 50, 50));

    EXPECT_EQ(0u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
  }
  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(third.Id(), kBackgroundType),
                          IsSameId(fourth.Id(), kBackgroundType)));
  EXPECT_TRUE(first.IsValid());
  EXPECT_TRUE(second.IsValid());
  EXPECT_TRUE(third.IsValid());
  EXPECT_TRUE(fourth.IsValid());

  // Simulate that a composited scrolling element is scrolled down, and "first"
  // and "second" are scrolled out of the interest rect.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kCached, DrawRect(context, third, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, fourth, kBackgroundType,
                                gfx::Rect(100, 100, 50, 50)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    // We indexed "first" and "second" when finding the cached item for "third".
    EXPECT_EQ(2u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }
  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(third.Id(), kBackgroundType),
                          IsSameId(fourth.Id(), kBackgroundType)));
  EXPECT_TRUE(first.IsValid());
  EXPECT_TRUE(second.IsValid());
  EXPECT_TRUE(third.IsValid());
  EXPECT_TRUE(fourth.IsValid());

  // Simulate "first" and "second" are scrolled back into the interest rect.
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_EQ(kPaintedNew, DrawRect(context, first, kBackgroundType,
                                    gfx::Rect(100, 100, 300, 300)));
    EXPECT_EQ(kPaintedNew, DrawRect(context, second, kBackgroundType,
                                    gfx::Rect(100, 100, 200, 200)));
    EXPECT_EQ(kCached, DrawRect(context, third, kBackgroundType,
                                gfx::Rect(100, 100, 100, 100)));
    EXPECT_EQ(kCached, DrawRect(context, fourth, kBackgroundType,
                                gfx::Rect(100, 100, 50, 50)));

    EXPECT_EQ(2u, NumCachedNewItems(paint_controller));
    EXPECT_EQ(0u, NumCachedNewSubsequences(paint_controller));
#if DCHECK_IS_ON()
    // We indexed "third" and "fourth" when finding the cached item for "first".
    EXPECT_EQ(2u, NumIndexedItems(paint_controller));
    EXPECT_EQ(2u, NumSequentialMatches(paint_controller));
    EXPECT_EQ(0u, NumOutOfOrderMatches(paint_controller));
#endif
  }
  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(first.Id(), kBackgroundType),
                          IsSameId(second.Id(), kBackgroundType),
                          IsSameId(third.Id(), kBackgroundType),
                          IsSameId(fourth.Id(), kBackgroundType)));
  EXPECT_TRUE(first.IsValid());
  EXPECT_TRUE(second.IsValid());
  EXPECT_TRUE(third.IsValid());
  EXPECT_TRUE(fourth.IsValid());
}

TEST_P(PaintControllerTest, TransientPaintControllerIncompleteCycle) {
  PaintController paint_controller;
  GraphicsContext context(paint_controller);
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");
  InitRootChunk(paint_controller);
  DrawRect(context, client, kBackgroundType, gfx::Rect(100, 100, 50, 50));
  // The client of a transient paint controller can abort without
  // CommintNewDisplayItems() and FinishCycle(). This should not crash.
}

TEST_P(PaintControllerTest, AllowDuplicatedIdForTransientPaintController) {
  PaintController paint_controller;
  GraphicsContext context(paint_controller);
  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");

  InitRootChunk(paint_controller);
  {
    SubsequenceRecorder r(context, client);
    ScopedPaintChunkProperties p(paint_controller,
                                 DefaultPaintChunkProperties(), client,
                                 kBackgroundType);
    DrawRect(context, client, kBackgroundType, gfx::Rect(100, 100, 50, 50));
  }
  {
    ScopedPaintChunkProperties p(paint_controller,
                                 DefaultPaintChunkProperties(), client,
                                 kBackgroundType);
    DrawRect(context, client, kBackgroundType, gfx::Rect(100, 100, 50, 50));
  }

  auto& paint_artifact = paint_controller.CommitNewDisplayItems();
  EXPECT_EQ(2u, paint_artifact.GetDisplayItemList().size());
  EXPECT_EQ(2u, paint_artifact.GetPaintChunks().size());
}

TEST_P(PaintControllerTest, AllowDuplicatedIdForUncacheableItem) {
  if (RuntimeEnabledFeatures::PaintUnderInvalidationCheckingEnabled())
    return;

  gfx::Rect r(100, 100, 300, 300);
  FakeDisplayItemClient& cacheable =
      *MakeGarbageCollected<FakeDisplayItemClient>("cacheable");
  FakeDisplayItemClient& uncacheable =
      *MakeGarbageCollected<FakeDisplayItemClient>("uncacheable");

  uncacheable.Invalidate(PaintInvalidationReason::kUncacheable);
  EXPECT_TRUE(cacheable.IsCacheable());
  EXPECT_FALSE(uncacheable.IsCacheable());

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    {
      SubsequenceRecorder recorder(context, cacheable);
      DrawRect(context, cacheable, kBackgroundType, gfx::Rect(r));
      DrawRect(context, uncacheable, kBackgroundType, gfx::Rect(r));
      // This should not trigger the duplicated id assert.
      DrawRect(context, uncacheable, kBackgroundType, gfx::Rect(r));
    }
  }
  EXPECT_TRUE(GetPersistentData().GetDisplayItemList()[0].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[1].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[2].IsCacheable());
  EXPECT_TRUE(cacheable.IsCacheable());
  EXPECT_FALSE(uncacheable.IsCacheable());

  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    EXPECT_TRUE(paint_controller.UseCachedSubsequenceIfPossible(cacheable));
  }
  EXPECT_TRUE(GetPersistentData().GetDisplayItemList()[0].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[1].IsCacheable());
  EXPECT_FALSE(GetPersistentData().GetDisplayItemList()[2].IsCacheable());
  EXPECT_TRUE(cacheable.IsCacheable());
  EXPECT_FALSE(uncacheable.IsCacheable());
}

TEST_P(PaintControllerTest, RecordRegionCaptureDataValidData) {
  static const auto kCropId = RegionCaptureCropId(base::Token::CreateRandom());
  static const gfx::Rect kBounds(1, 2, 640, 480);

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);
    paint_controller.RecordRegionCaptureData(client, kCropId, kBounds);

    DrawRect(context, client, kBackgroundType, gfx::Rect(100, 100, 200, 200));
  }

  EXPECT_THAT(GetPersistentData().GetDisplayItemList(),
              ElementsAre(IsSameId(client.Id(), kBackgroundType)));
  EXPECT_DEFAULT_ROOT_CHUNK(1);
  const PaintChunks& chunks = GetPersistentData().GetPaintChunks();
  EXPECT_EQ(1u, chunks.size());
  EXPECT_EQ(kBounds, chunks[0].region_capture_data->map.find(kCropId)->second);
}

// Death tests don't work properly on Android.
#if defined(GTEST_HAS_DEATH_TEST) && !BUILDFLAG(IS_ANDROID)

TEST_P(PaintControllerTest, RecordRegionCaptureDataEmptyToken) {
  static const auto kCropId = RegionCaptureCropId(base::Token{});
  static const gfx::Rect kBounds(1, 2, 640, 480);

  FakeDisplayItemClient& client =
      *MakeGarbageCollected<FakeDisplayItemClient>("client");
  {
    AutoCommitPaintController paint_controller(GetPersistentData());
    GraphicsContext context(paint_controller);
    InitRootChunk(paint_controller);

#if DCHECK_IS_ON
```