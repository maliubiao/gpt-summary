Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `notification_resources_loader_test.cc` immediately suggests this file tests something related to loading resources for notifications. The inclusion of `<gtest/gtest.h>` confirms it's a unit test.

2. **Examine the Includes:**  The `#include` directives provide clues about the functionalities being tested:
    * `notification_resources_loader.h`: This is the primary class being tested.
    * `notification_constants.h`, `notification.mojom-blink.h`: Indicate interaction with notification data structures. `mojom` suggests inter-process communication (likely with the browser process).
    * `LocalDOMWindow.h`, `LocalFrame.h`:  Show the context is within a web page.
    * `PageTestBase.h`:  Indicates this is a Blink test using a testing framework.
    * `MemoryCache.h`, `fetch/fetch.h` (implied by `URLLoaderMockFactory`): Hints at network resource loading.
    * `testing/`: Confirms testing utilities are being used.
    * `weborigin/kurl.h`:  Indicates URL handling.

3. **Analyze the Test Fixture:** The `NotificationResourcesLoaderTest` class inherits from `PageTestBase`. This tells us:
    * It sets up a minimal web page environment for testing.
    * It has access to a `LocalFrame` and `LocalDOMWindow`.
    * It uses a `NotificationResourcesLoader` instance (`loader_`).

4. **Understand the Test Setup:** The `SetUp` method confirms the page environment initialization. The constructor and destructor of the test fixture handle the lifecycle of the `NotificationResourcesLoader` and the mocked URL loader. The `DidFetchResources` method and `resources_loaded_closure_` suggest asynchronous resource loading and waiting mechanisms.

5. **Focus on the Test Methods (TEST_F):**  Each `TEST_F` macro defines an individual test case. Analyze what each test aims to verify:
    * `LoadMultipleResources`: Checks loading of image, icon, badge, and action icons. Verifies dimensions.
    * `LargeIconsAreScaledDown`: Checks if large images are scaled down to the maximum allowed sizes.
    * `DownscalingPreserves3_1AspectRatio`, `DownscalingPreserves3_2AspectRatio`: Checks aspect ratio preservation during downscaling.
    * `EmptyDataYieldsEmptyResources`: Tests the case where no resource URLs are provided.
    * `EmptyResourcesIfAllImagesFailToLoad`: Tests handling of failed resource loads.
    * `OneImageFailsToLoad`: Tests handling of a single failed resource load amidst successful ones.
    * `StopYieldsNoResources`: Checks if stopping the loader cancels ongoing requests.

6. **Identify Key Helper Methods:**
    * `RegisterMockedURL`:  Simulates successful resource loading by providing local test data. This is crucial for isolated testing.
    * `RegisterMockedErrorURL`: Simulates failed resource loading (e.g., 404 errors).
    * `StartAndWaitForResources`: Encapsulates the asynchronous loading process and waits for completion.

7. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `Notification` API in JavaScript is what triggers the creation of notifications. This test implicitly verifies the backend behavior when JavaScript requests resources. Example: `new Notification('Title', { icon: 'image.png', badge: 'badge.png', actions: [{ icon: 'action.png' }] });`
    * **HTML:** While not directly interacting with HTML *parsing*, the test operates within a web page environment provided by `PageTestBase`. The URLs provided in the notification data could come from `<img>` tags or other sources within the HTML.
    * **CSS:** CSS can influence how notifications are displayed, but this test focuses on *loading* the resources, not their rendering. However, the constraints on image sizes (max width/height) could be related to how the browser eventually renders these notifications, potentially involving CSS.

8. **Infer Logic and Assumptions:**
    * **Assumption:** The `NotificationResourcesLoader` fetches images asynchronously.
    * **Assumption:** There are maximum size limits for notification icons and images.
    * **Logic:** The tests verify that the loader correctly fetches, scales, and handles both successful and failed resource loads. The `StartAndWaitForResources` pattern indicates a need to synchronize with asynchronous operations.

9. **Consider User/Developer Errors:**
    * **User:** Providing invalid or non-existent URLs for notification resources. The test with `RegisterMockedErrorURL` simulates this.
    * **Developer:** Incorrectly constructing the `NotificationData` object in JavaScript, leading to missing or invalid resource URLs. Relying on unvalidated user-provided URLs could also be an error.

10. **Trace User Actions (Debugging Clues):**  Imagine a user interacting with a website:
    1. **User visits a website.**
    2. **Website requests permission to send notifications.**
    3. **User grants permission.**
    4. **JavaScript on the website creates a new `Notification` object, specifying image URLs.**
    5. **The browser's notification system (which includes `NotificationResourcesLoader`) receives this request.**
    6. **`NotificationResourcesLoader` starts fetching the specified resources.**
    7. **(This is where the tests come in): The tests simulate different scenarios of successful and failed fetches.**
    8. **Once resources are loaded (or failed), the notification is displayed to the user.**

By following these steps, systematically analyzing the code structure, purpose, and interactions, we can arrive at a comprehensive understanding of the test file's functionality and its relation to web technologies and potential error scenarios.
This C++ source code file, `notification_resources_loader_test.cc`, is a **unit test** for the `NotificationResourcesLoader` class within the Chromium Blink rendering engine. Its primary function is to **verify the correct behavior of the `NotificationResourcesLoader` in fetching and processing resources (like images) associated with web notifications.**

Here's a breakdown of its functionality and connections to web technologies:

**Core Functionality:**

1. **Resource Loading:** The tests simulate the loading of various resources (images for icons, badges, and action icons) specified in a `NotificationData` object.
2. **Success and Failure Handling:**  It tests scenarios where resource loading succeeds, fails (e.g., 404 errors), and where some resources load while others fail.
3. **Image Resizing:** It verifies that large images are correctly scaled down to predefined maximum sizes (e.g., `kNotificationMaxIconSizePx`, `kNotificationMaxImageWidthPx`) while preserving aspect ratios.
4. **Empty Resource Handling:** It checks how the loader behaves when no resources are specified or when all resource loading attempts fail.
5. **Loader Cancellation:** It tests the `Stop()` method to ensure that ongoing resource loading is cancelled when the loader is stopped.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This test directly relates to the **JavaScript Notifications API**. When a web page uses JavaScript to create a notification (using the `Notification` constructor), it can specify URLs for icons, badges, and action icons. The `NotificationResourcesLoader` is the Blink component responsible for fetching these resources behind the scenes.

   **Example:** A JavaScript code snippet might look like this:

   ```javascript
   new Notification('My Notification', {
       icon: 'images/my-icon.png',
       badge: 'images/my-badge.png',
       image: 'images/my-large-image.png',
       actions: [
           { action: 'like', title: 'Like', icon: 'images/like-icon.png' },
           { action: 'dislike', title: 'Dislike', icon: 'images/dislike-icon.png' }
       ]
   });
   ```

   The `NotificationResourcesLoaderTest` verifies how Blink handles the loading of `images/my-icon.png`, `images/my-badge.png`, `images/my-large-image.png`, `images/like-icon.png`, and `images/dislike-icon.png`.

* **HTML:** While this test doesn't directly parse HTML, the URLs provided for the notification resources are often hosted on web servers and accessed via standard HTTP requests. The HTML page might contain the logic that triggers the notification and thus indirectly provides the context for resource loading.

* **CSS:**  CSS is used to style the appearance of notifications. While this test focuses on the *loading* of the resources, the size constraints and aspect ratio preservation logic within `NotificationResourcesLoader` might be related to how the notification UI will eventually render these images, potentially involving CSS properties like `max-width`, `max-height`, and `object-fit`. For instance, the constants like `kNotificationMaxIconSizePx` could be aligned with CSS rules for notification icon display.

**Logic and Assumptions (Hypothetical Input and Output):**

**Assumption:** The test environment can mock network requests.

**Test Case Example: `LoadMultipleResources`**

* **Input (Simulated `NotificationData`):**
    * `notification_data->image`: `http://test.com/notifications/500x500.png` (successful load)
    * `notification_data->icon`: `http://test.com/notifications/100x100.png` (successful load)
    * `notification_data->badge`: `http://test.com/notifications/48x48.png` (successful load)
    * `notification_data->actions[0]->icon`: `http://test.com/notifications/110x110.png` (successful load)
    * `notification_data->actions[1]->icon`: `http://test.com/notifications/120x120.png` (successful load)

* **Output (Expected `NotificationResources`):**
    * `Resources()->image`: An `Image` object with width 500 and height 500.
    * `Resources()->icon`: An `Image` object with width 100.
    * `Resources()->badge`: An `Image` object with width 48.
    * `Resources()->action_icons[0]`: An `Image` object with width 110.
    * `Resources()->action_icons[1]`: An `Image` object with width 120.

**Test Case Example: `LargeIconsAreScaledDown`**

* **Input (Simulated `NotificationData`):**
    * `notification_data->icon`: `http://test.com/notifications/500x500.png` (successful load)
    * `notification_data->badge`: Same as icon.
    * `notification_data->actions[0]->icon`: Same as icon.

* **Output (Expected `NotificationResources`):**
    * `Resources()->icon`: An `Image` object with width `kNotificationMaxIconSizePx` and height `kNotificationMaxIconSizePx`.
    * `Resources()->badge`: An `Image` object with width `kNotificationMaxBadgeSizePx` and height `kNotificationMaxBadgeSizePx`.
    * `Resources()->action_icons[0]`: An `Image` object with width `kNotificationMaxActionIconSizePx` and height `kNotificationMaxActionIconSizePx`.

**User or Programming Common Usage Errors (and how the test relates):**

* **Providing Invalid URLs:** A web developer might accidentally provide a broken or non-existent URL for a notification icon. The tests like `EmptyResourcesIfAllImagesFailToLoad` and `OneImageFailsToLoad` simulate this scenario and verify that the notification system gracefully handles these errors (e.g., by showing a notification without the broken image).

* **Using Very Large Images:** A developer might use excessively large images for notification icons, which can consume unnecessary bandwidth and memory. The `LargeIconsAreScaledDown` test verifies that Blink prevents this by automatically scaling down these images to reasonable sizes.

* **Incorrectly Constructing `NotificationData`:** A bug in the JavaScript code generating the notification might lead to missing or incorrectly formatted resource URLs. The `EmptyDataYieldsEmptyResources` test covers the case where no URLs are provided.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User visits a website that uses the Notifications API.**
2. **The website requests permission to show notifications (e.g., using `Notification.requestPermission()`).**
3. **The user grants the website permission to show notifications.**
4. **At some point, the website's JavaScript code creates a new `Notification` object, specifying URLs for icons or other resources.**
5. **The browser's rendering engine (Blink) receives this notification request.**
6. **The `NotificationResourcesLoader` component within Blink is invoked to fetch the resources specified in the notification data.**
7. **If you were debugging this process, you might set breakpoints or trace execution within the `NotificationResourcesLoader::Start()` method or related functions to observe the resource loading process.**
8. **The `notification_resources_loader_test.cc` file serves as a low-level verification that this resource loading process works correctly under various conditions.**  If a bug is found in notification resource loading, a developer might write or modify a test in this file to reproduce and then fix the issue.

In essence, `notification_resources_loader_test.cc` is a crucial part of ensuring the robustness and correctness of web notifications in Chromium. It rigorously tests the resource loading mechanism, anticipating various scenarios, including success, failure, and edge cases.

### 提示词
```
这是目录为blink/renderer/modules/notifications/notification_resources_loader_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/notifications/notification_resources_loader.h"

#include <memory>

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/notifications/notification_constants.h"
#include "third_party/blink/public/mojom/notifications/notification.mojom-blink.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_loader_mock_factory.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
namespace {

constexpr char kResourcesLoaderBaseUrl[] = "http://test.com/";
constexpr char kResourcesLoaderBaseDir[] = "notifications/";
constexpr char kResourcesLoaderIcon48x48[] = "48x48.png";
constexpr char kResourcesLoaderIcon100x100[] = "100x100.png";
constexpr char kResourcesLoaderIcon110x110[] = "110x110.png";
constexpr char kResourcesLoaderIcon120x120[] = "120x120.png";
constexpr char kResourcesLoaderIcon500x500[] = "500x500.png";
constexpr char kResourcesLoaderIcon3000x1000[] = "3000x1000.png";
constexpr char kResourcesLoaderIcon3000x2000[] = "3000x2000.png";

class NotificationResourcesLoaderTest : public PageTestBase {
 public:
  NotificationResourcesLoaderTest()
      : loader_(MakeGarbageCollected<NotificationResourcesLoader>(
            WTF::BindOnce(&NotificationResourcesLoaderTest::DidFetchResources,
                          WTF::Unretained(this)))) {}

  ~NotificationResourcesLoaderTest() override {
    loader_->Stop();
    URLLoaderMockFactory::GetSingletonInstance()
        ->UnregisterAllURLsAndClearMemoryCache();
  }

  void SetUp() override { PageTestBase::SetUp(gfx::Size()); }

 protected:
  ExecutionContext* GetExecutionContext() const {
    return GetFrame().DomWindow();
  }

  NotificationResourcesLoader* Loader() const { return loader_.Get(); }

  const mojom::blink::NotificationResources* Resources() const {
    return resources_.get();
  }

  void DidFetchResources(NotificationResourcesLoader* loader) {
    resources_ = loader->GetResources();
    std::move(resources_loaded_closure_).Run();
  }

  void StartAndWaitForResources(
      const mojom::blink::NotificationData& notification_data) {
    base::RunLoop run_loop;
    resources_loaded_closure_ = run_loop.QuitClosure();
    Loader()->Start(GetExecutionContext(), notification_data);
    URLLoaderMockFactory::GetSingletonInstance()->ServeAsynchronousRequests();
    run_loop.Run();
  }

  // Registers a mocked url. When fetched, |fileName| will be loaded from the
  // test data directory.
  KURL RegisterMockedURL(const String& file_name) {
    KURL registered_url = url_test_helpers::RegisterMockedURLLoadFromBase(
        kResourcesLoaderBaseUrl,
        test::CoreTestDataPath(kResourcesLoaderBaseDir), file_name,
        "image/png");
    return registered_url;
  }

  // Registers a mocked url that will fail to be fetched, with a 404 error.
  KURL RegisterMockedErrorURL(const String& file_name) {
    KURL url(kResourcesLoaderBaseUrl + file_name);
    url_test_helpers::RegisterMockedErrorURLLoad(url);
    return url;
  }

  ScopedTestingPlatformSupport<TestingPlatformSupport> platform_;

 private:
  base::OnceClosure resources_loaded_closure_;
  Persistent<NotificationResourcesLoader> loader_;
  mojom::blink::NotificationResourcesPtr resources_;
};

TEST_F(NotificationResourcesLoaderTest, LoadMultipleResources) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->image = RegisterMockedURL(kResourcesLoaderIcon500x500);
  notification_data->icon = RegisterMockedURL(kResourcesLoaderIcon100x100);
  notification_data->badge = RegisterMockedURL(kResourcesLoaderIcon48x48);
  notification_data->actions = Vector<mojom::blink::NotificationActionPtr>();
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[0]->icon =
      RegisterMockedURL(kResourcesLoaderIcon110x110);
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[1]->icon =
      RegisterMockedURL(kResourcesLoaderIcon120x120);

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  ASSERT_FALSE(Resources()->image.drawsNothing());
  ASSERT_EQ(500, Resources()->image.width());
  ASSERT_EQ(500, Resources()->image.height());

  ASSERT_FALSE(Resources()->icon.drawsNothing());
  ASSERT_EQ(100, Resources()->icon.width());

  ASSERT_FALSE(Resources()->badge.drawsNothing());
  ASSERT_EQ(48, Resources()->badge.width());

  ASSERT_TRUE(Resources()->action_icons.has_value());
  auto& action_icons = Resources()->action_icons.value();
  ASSERT_EQ(2u, action_icons.size());
  ASSERT_FALSE(action_icons[0].drawsNothing());
  ASSERT_EQ(110, action_icons[0].width());
  ASSERT_FALSE(action_icons[1].drawsNothing());
  ASSERT_EQ(120, action_icons[1].width());
}

TEST_F(NotificationResourcesLoaderTest, LargeIconsAreScaledDown) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->icon = RegisterMockedURL(kResourcesLoaderIcon500x500);
  notification_data->badge = notification_data->icon;
  notification_data->actions = Vector<mojom::blink::NotificationActionPtr>();
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[0]->icon = notification_data->icon;

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  ASSERT_FALSE(Resources()->icon.drawsNothing());
  ASSERT_EQ(kNotificationMaxIconSizePx, Resources()->icon.width());
  ASSERT_EQ(kNotificationMaxIconSizePx, Resources()->icon.height());

  ASSERT_FALSE(Resources()->badge.drawsNothing());
  ASSERT_EQ(kNotificationMaxBadgeSizePx, Resources()->badge.width());
  ASSERT_EQ(kNotificationMaxBadgeSizePx, Resources()->badge.height());

  ASSERT_TRUE(Resources()->action_icons.has_value());
  auto& action_icons = Resources()->action_icons.value();
  ASSERT_EQ(1u, action_icons.size());
  ASSERT_FALSE(action_icons[0].drawsNothing());
  ASSERT_EQ(kNotificationMaxActionIconSizePx, action_icons[0].width());
  ASSERT_EQ(kNotificationMaxActionIconSizePx, action_icons[0].height());
}

TEST_F(NotificationResourcesLoaderTest, DownscalingPreserves3_1AspectRatio) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->image = RegisterMockedURL(kResourcesLoaderIcon3000x1000);

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  ASSERT_FALSE(Resources()->image.drawsNothing());
  ASSERT_EQ(kNotificationMaxImageWidthPx, Resources()->image.width());
  ASSERT_EQ(kNotificationMaxImageWidthPx / 3, Resources()->image.height());
}

TEST_F(NotificationResourcesLoaderTest, DownscalingPreserves3_2AspectRatio) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->image = RegisterMockedURL(kResourcesLoaderIcon3000x2000);

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  ASSERT_FALSE(Resources()->image.drawsNothing());
  ASSERT_EQ(kNotificationMaxImageHeightPx * 3 / 2, Resources()->image.width());
  ASSERT_EQ(kNotificationMaxImageHeightPx, Resources()->image.height());
}

TEST_F(NotificationResourcesLoaderTest, EmptyDataYieldsEmptyResources) {
  auto notification_data = mojom::blink::NotificationData::New();

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  ASSERT_TRUE(Resources()->image.drawsNothing());
  ASSERT_TRUE(Resources()->icon.drawsNothing());
  ASSERT_TRUE(Resources()->badge.drawsNothing());
  ASSERT_EQ(0u, Resources()->action_icons.value().size());
}

TEST_F(NotificationResourcesLoaderTest, EmptyResourcesIfAllImagesFailToLoad) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->icon = RegisterMockedErrorURL(kResourcesLoaderIcon100x100);
  notification_data->image = notification_data->icon;
  notification_data->badge = notification_data->icon;
  notification_data->actions = Vector<mojom::blink::NotificationActionPtr>();
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[0]->icon = notification_data->icon;

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  // The test received resources but they are all empty. This ensures that a
  // notification can still be shown even if the images fail to load.
  ASSERT_TRUE(Resources()->image.drawsNothing());
  ASSERT_TRUE(Resources()->icon.drawsNothing());
  ASSERT_TRUE(Resources()->badge.drawsNothing());
  ASSERT_EQ(1u, Resources()->action_icons.value().size());
  ASSERT_TRUE(Resources()->action_icons.value()[0].drawsNothing());
}

TEST_F(NotificationResourcesLoaderTest, OneImageFailsToLoad) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->icon = RegisterMockedURL(kResourcesLoaderIcon100x100);
  notification_data->badge = RegisterMockedErrorURL(kResourcesLoaderIcon48x48);

  ASSERT_FALSE(Resources());

  StartAndWaitForResources(*notification_data);
  ASSERT_TRUE(Resources());

  // The test received resources even though one image failed to load. This
  // ensures that a notification can still be shown, though slightly degraded.
  ASSERT_TRUE(Resources()->image.drawsNothing());
  ASSERT_FALSE(Resources()->icon.drawsNothing());
  ASSERT_EQ(100, Resources()->icon.width());
  ASSERT_TRUE(Resources()->badge.drawsNothing());
  ASSERT_EQ(0u, Resources()->action_icons.value().size());
}

TEST_F(NotificationResourcesLoaderTest, StopYieldsNoResources) {
  auto notification_data = mojom::blink::NotificationData::New();
  notification_data->image = RegisterMockedURL(kResourcesLoaderIcon500x500);
  notification_data->icon = RegisterMockedURL(kResourcesLoaderIcon100x100);
  notification_data->badge = RegisterMockedURL(kResourcesLoaderIcon48x48);
  notification_data->actions = Vector<mojom::blink::NotificationActionPtr>();
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[0]->icon =
      RegisterMockedURL(kResourcesLoaderIcon110x110);
  notification_data->actions->push_back(
      mojom::blink::NotificationAction::New());
  notification_data->actions.value()[1]->icon =
      RegisterMockedURL(kResourcesLoaderIcon120x120);

  ASSERT_FALSE(Resources());

  Loader()->Start(GetExecutionContext(), *notification_data);

  // Check that starting the loader did not synchronously fail, providing
  // empty resources. The requests should be pending now.
  ASSERT_FALSE(Resources());

  // The loader would stop e.g. when the execution context is destroyed or
  // when the loader is about to be destroyed, as a pre-finalizer.
  Loader()->Stop();
  URLLoaderMockFactory::GetSingletonInstance()->ServeAsynchronousRequests();

  // Loading should have been cancelled when |stop| was called so no resources
  // should have been received by the test even though
  // |serveAsynchronousRequests| was called.
  ASSERT_FALSE(Resources());
}

}  // namespace
}  // namespace blink
```