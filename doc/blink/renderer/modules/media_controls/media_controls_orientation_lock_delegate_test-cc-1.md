Response:
The user wants to understand the functionality of the provided C++ test file.
The file seems to be testing the `MediaControlsOrientationLockDelegate` in the Chromium Blink engine.
This delegate likely manages screen orientation locking when media controls are involved, especially during fullscreen transitions.

I need to:
1. **Summarize the file's purpose:** It tests the logic of locking and unlocking screen orientation in response to user actions and device orientation changes when media controls are active.
2. **Identify relationships with web technologies:** This involves understanding how screen orientation and fullscreen APIs in JavaScript, HTML, and CSS interact with the underlying browser implementation.
3. **Illustrate logic through examples:**  Show how different device orientations and user interactions lead to specific orientation lock states.
4. **Highlight potential user/developer errors:**  Point out common mistakes related to orientation locking.
5. **Explain the user journey:** Describe the steps a user might take to trigger the code being tested.
6. **Summarize the functionality based on the provided code snippet.**

**Breakdown of the code:**

The code defines several test cases within the `MediaControlsOrientationLockAndRotateToFullscreenDelegateTest` class. Each test case simulates different scenarios involving:

* **Device natural orientation:** Whether the device is naturally portrait or landscape.
* **Initial screen orientation:** The orientation of the screen before any interaction.
* **Video dimensions:** Whether the video is portrait or landscape.
* **User auto-rotate setting:** Whether the user has enabled or disabled automatic screen rotation.
* **User actions:**  Clicking the fullscreen button or rotating the device.
* **Expected outcomes:** The expected screen orientation lock state and whether the video enters or exits fullscreen.

The tests use functions like `RotateScreenTo`, `RotateDeviceTo`, `SimulateEnterFullscreen`, `SimulateExitFullscreen` to mimic user interactions and device state changes. Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_FALSE`) are used to verify the behavior of the `MediaControlsOrientationLockDelegate`.

**Key functionalities being tested (from the provided snippet):**

* **Locking to natural orientation on rotation:** When a device is rotated to its natural orientation while a video is inline, it should go to fullscreen and lock to that orientation.
* **Locking to video orientation on fullscreen button press:**  When the fullscreen button is pressed, the orientation should lock to the video's orientation.
* **Unlocking after a delay:**  After the device orientation matches the locked orientation, it should unlock to "any" orientation.
* **Handling auto-rotate disabled scenarios:** The tests explore how the orientation lock behaves when the user has disabled auto-rotate.
这个C++源代码文件 `blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate_test.cc` 的功能是**测试 `MediaControlsOrientationLockDelegate` 组件在 Chromium Blink 引擎中的行为**。

具体来说，它主要测试了在不同的场景下，媒体控件的 `MediaControlsOrientationLockDelegate` 如何管理屏幕方向锁定，尤其是在视频进入和退出全屏模式时。

由于这是第2部分，是对前一部分的补充，我们可以归纳出它的主要功能是：**针对各种复杂的屏幕旋转、设备方向变化以及用户手动锁定/解锁屏幕旋转的场景，测试媒体控件的方向锁定委托是否能够正确地锁定和解锁屏幕方向，以及是否能与全屏状态的变化协调工作。**

**与 JavaScript, HTML, CSS 的功能关系：**

虽然这个文件是 C++ 代码，但它直接关联着用户在网页上与媒体元素交互时的体验，而这些交互通常涉及到 JavaScript, HTML 和 CSS。

* **JavaScript:**  网页中的 JavaScript 代码可以使用 `requestFullscreen()` API 来请求全屏，或者监听 `orientationchange` 事件来获取屏幕方向的变化。`MediaControlsOrientationLockDelegate` 的行为会影响这些 API 的表现。例如，如果 `MediaControlsOrientationLockDelegate` 锁定了屏幕方向，即使 JavaScript 代码尝试改变方向，也可能不会立即生效。
* **HTML:** HTML 的 `<video>` 元素是媒体控件所作用的对象。全屏按钮通常是媒体控件的一部分，用户点击这个按钮会触发全屏状态的改变，从而影响 `MediaControlsOrientationLockDelegate` 的行为。
* **CSS:** CSS 可以用于控制媒体控件的样式和布局，包括全屏时的样式。`MediaControlsOrientationLockDelegate` 确保在全屏状态下，屏幕方向与视频内容或用户的期望一致。

**举例说明：**

假设一个用户在一个竖屏的手机上观看一个横屏的视频。

1. **用户点击全屏按钮 (JavaScript 发起 `requestFullscreen()`):**  `MediaControlsOrientationLockDelegate` 可能会锁定屏幕方向为横屏，即使用户的设备仍然是竖屏方向。这确保了视频在全屏时能够以正确的方向显示。
2. **用户旋转设备到横屏 (触发 `orientationchange` 事件):**  如果 `MediaControlsOrientationLockDelegate` 之前锁定了横屏，当用户将设备旋转到横屏时，`MediaControlsOrientationLockDelegate` 可能会解锁屏幕方向，允许设备自由旋转。
3. **用户在全屏模式下禁用了屏幕自动旋转:**  在这种情况下，即使设备方向发生变化，`MediaControlsOrientationLockDelegate` 也可能继续保持锁定的方向，以遵守用户的设置。

**逻辑推理、假设输入与输出：**

以下是一些基于代码片段的逻辑推理和假设输入输出：

**假设输入 1:** 用户在一个自然方向为竖屏的设备上，观看一个横屏视频，初始屏幕方向为竖屏，启用了自动旋转。用户点击全屏按钮。

**预期输出 1:** `MediaControlsOrientationLockDelegate` 会锁定屏幕方向为横屏 (`device::mojom::ScreenOrientationLockType::LANDSCAPE`)，视频进入全屏模式。

**假设输入 2:** 在上述场景下，用户在全屏模式下将设备旋转到横屏。

**预期输出 2:**  一段时间后，`MediaControlsOrientationLockDelegate` 会将屏幕方向锁定更改为 `ANY` (`device::mojom::ScreenOrientationLockType::ANY`)，允许设备自由旋转，但视频仍然保持全屏。

**涉及用户或者编程常见的使用错误：**

* **用户在使用全屏视频时禁用了屏幕自动旋转：**  用户可能期望在全屏模式下，即使旋转设备也能保持视频的方向。但是，如果用户禁用了自动旋转，`MediaControlsOrientationLockDelegate` 需要处理这种情况，避免与用户的系统设置冲突，同时确保视频的最佳观看体验。代码中的 `AutoRotateDisabled...` 开头的测试用例就覆盖了这种情况。
* **开发者没有正确处理屏幕方向变化的事件：**  开发者可能依赖于浏览器的默认行为，而忽略了在媒体控件的生命周期中，屏幕方向锁定可能会被 `MediaControlsOrientationLockDelegate` 修改。这可能导致在某些状态下，网页的布局或功能出现异常。
* **开发者假设全屏后屏幕方向会立即改变：**  屏幕方向的改变可能不是瞬时的，`MediaControlsOrientationLockDelegate` 的测试用例中也考虑到了这种延迟 (`test::RunDelayedTasks(GetUnlockDelay())`)。开发者需要考虑到这种异步性。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含 `<video>` 元素的网页。**
2. **视频加载并开始播放（可选）。**
3. **用户点击视频播放器上的全屏按钮。**  这个操作会触发 JavaScript 调用 `requestFullscreen()`。
4. **浏览器接收到全屏请求，并调用 Blink 引擎的相关代码。**
5. **Blink 引擎中的媒体控件组件被激活。**
6. **`MediaControlsOrientationLockDelegate` 组件根据当前的设备方向、视频尺寸、用户设置等信息，决定是否需要锁定屏幕方向。**
7. **如果需要锁定，`MediaControlsOrientationLockDelegate` 会请求操作系统锁定屏幕方向。**
8. **如果用户在全屏模式下旋转设备，或者点击退出全屏按钮，`MediaControlsOrientationLockDelegate` 可能会解锁屏幕方向。**

在调试相关问题时，可以关注以下步骤：

* **检查 JavaScript 代码中是否正确处理了全屏事件和屏幕方向变化事件。**
* **使用浏览器的开发者工具查看设备的屏幕方向和全屏状态。**
* **在 Chromium 源码中，可以断点调试 `MediaControlsOrientationLockDelegate` 的相关方法，例如 `LockOrientation`, `UnlockOrientation` 等，来追踪其行为。**
* **查看设备的系统日志，可能会有关于屏幕方向锁定的信息。**

**归纳其功能 (基于提供的代码片段)：**

这个代码片段主要测试了在自然方向为竖屏的设备上，当视频进入和退出全屏时，`MediaControlsOrientationLockDelegate` 如何处理屏幕方向锁定，并且考虑了用户禁用自动旋转的情况。

具体来说，测试用例涵盖了以下场景：

* **竖屏设备，横屏视频，从内联状态旋转到横屏进入全屏并锁定。**
* **竖屏设备，横屏视频，点击全屏按钮进入全屏并锁定为横屏。**
* **竖屏设备，锁定为横屏的全屏状态，旋转设备到横屏后解锁为任意方向。**
* **竖屏设备，锁定为横屏的全屏状态，点击退出全屏按钮回到内联状态。**
* **横屏设备，横屏视频，点击全屏按钮进入全屏并锁定为横屏。**
* **横屏设备，全屏状态，旋转设备到竖屏后退出全屏。**
* **用户禁用自动旋转时，全屏状态下的方向锁定行为。**
* **测试了在屏幕方向变化和设备方向变化之间可能存在的竞态条件。**

总而言之，这部分测试着重于验证 `MediaControlsOrientationLockDelegate` 在各种复杂的旋转和全屏切换场景下，能够正确地管理屏幕方向锁定，以提供良好的用户体验，并考虑到用户的系统设置。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/media_controls_orientation_lock_delegate_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
tationData::Create(
                    alpha, -90. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -90. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -85. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -85. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -95. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -95. /* beta */, -90. /* gamma */, absolute)));

      // These beta and gamma values should all map to r == 1 and
      // device_orientation_angle == 270, hence orientation == kLandscape.
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 0. /* beta */, 90. /* gamma */, absolute)));
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, 180. /* beta */, -90. /* gamma */, absolute)));
      EXPECT_EQ(perpendicular_to_natural_orientation,
                ComputeDeviceOrientation(DeviceOrientationData::Create(
                    alpha, -180. /* beta */, -90. /* gamma */, absolute)));
    }
  }
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       PortraitInlineRotateToLandscapeFullscreen) {
  // Naturally portrait device, initially portrait, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);
  PlayVideo();
  UpdateVisibilityObserver();

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user rotating their device to landscape triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));

  // MediaControlsRotateToFullscreenDelegate should enter fullscreen, so
  // MediaControlsOrientationLockDelegate should lock orientation to landscape
  // (even though the screen is already landscape).
  EXPECT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Device orientation events received by MediaControlsOrientationLockDelegate
  // will confirm that the device is already landscape.
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should lock to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       PortraitInlineButtonToPortraitLockedLandscapeFullscreen) {
  // Naturally portrait device, initially portrait, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user clicking on media controls fullscreen button.
  SimulateEnterFullscreen();
  EXPECT_TRUE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should lock to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // This will trigger a screen orientation change to landscape.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));

  // Even though the device is still held in portrait.
  RotateDeviceTo(0 /* portrait primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should remain locked to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       PortraitLockedLandscapeFullscreenRotateToLandscapeFullscreen) {
  // Naturally portrait device, initially portrait device orientation but locked
  // to landscape screen orientation, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user rotating their device to landscape (matching the screen
  // orientation lock).
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should lock to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
  EXPECT_TRUE(Video().IsFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       PortraitLockedLandscapeFullscreenBackToPortraitInline) {
  // Naturally portrait device, initially portrait device orientation but locked
  // to landscape screen orientation, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user clicking on media controls exit fullscreen button.
  SimulateExitFullscreen();
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());

  // Play the video and make it visible, just to make sure
  // MediaControlsRotateToFullscreenDelegate doesn't react to the
  // orientationchange event.
  PlayVideo();
  UpdateVisibilityObserver();

  // Unlocking the orientation earlier will trigger a screen orientation change
  // to portrait (since the device orientation was already portrait, even though
  // the screen was locked to landscape).
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));

  // Video should remain inline, unlocked.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  EXPECT_FALSE(Video().IsFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       LandscapeInlineRotateToPortraitInline) {
  // Naturally portrait device, initially landscape, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);
  PlayVideo();
  UpdateVisibilityObserver();

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user rotating their device to portrait triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  test::RunDelayedTasks(GetUnlockDelay());

  // Video should remain inline, unlocked.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  EXPECT_FALSE(Video().IsFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       LandscapeInlineButtonToLandscapeFullscreen) {
  // Naturally portrait device, initially landscape, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user clicking on media controls fullscreen button.
  SimulateEnterFullscreen();
  EXPECT_TRUE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should lock to landscape (even though
  // the screen is already landscape).
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Device orientation events received by MediaControlsOrientationLockDelegate
  // will confirm that the device is already landscape.
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should lock to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       LandscapeFullscreenRotateToPortraitInline) {
  // Naturally portrait device, initially landscape, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially fullscreen, locked to "any" orientation.
  SimulateEnterFullscreen();
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());

  // Simulate user rotating their device to portrait triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsRotateToFullscreenDelegate should exit fullscreen.
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock screen orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       LandscapeFullscreenBackToLandscapeInline) {
  // Naturally portrait device, initially landscape, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially fullscreen, locked to "any" orientation.
  SimulateEnterFullscreen();
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());

  // Simulate user clicking on media controls exit fullscreen button.
  SimulateExitFullscreen();
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock screen orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
}

TEST_F(
    MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
    AutoRotateDisabledPortraitInlineButtonToPortraitLockedLandscapeFullscreen) {
  // Naturally portrait device, initially portrait, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  InitVideo(640, 480);
  // But this time the user has disabled auto rotate, e.g. locked to portrait.
  SetIsAutoRotateEnabledByUser(false);

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user clicking on media controls fullscreen button.
  SimulateEnterFullscreen();
  EXPECT_TRUE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should lock to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // This will trigger a screen orientation change to landscape, since the app's
  // lock overrides the user's orientation lock (at least on Android).
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));

  // Even though the device is still held in portrait.
  RotateDeviceTo(0 /* portrait primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should remain locked to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());
}

TEST_F(
    MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
    AutoRotateDisabledPortraitLockedLandscapeFullscreenRotateToLandscapeLockedLandscapeFullscreen) {
  // Naturally portrait device, initially portrait device orientation but locked
  // to landscape screen orientation, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  // But this time the user has disabled auto rotate, e.g. locked to portrait
  // (even though the app's landscape screen orientation lock overrides it).
  SetIsAutoRotateEnabledByUser(false);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user rotating their device to landscape (matching the screen
  // orientation lock).
  RotateDeviceTo(90 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should remain locked to landscape even
  // though the screen orientation is now landscape, since the user has disabled
  // auto rotate, so unlocking now would cause the device to return to the
  // portrait orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());
  EXPECT_TRUE(Video().IsFullscreen());
}

TEST_F(
    MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
    AutoRotateDisabledPortraitLockedLandscapeFullscreenBackToPortraitInline) {
  // Naturally portrait device, initially portrait device orientation but locked
  // to landscape screen orientation, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  // But this time the user has disabled auto rotate, e.g. locked to portrait
  // (even though the app's landscape screen orientation lock overrides it).
  SetIsAutoRotateEnabledByUser(false);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user clicking on media controls exit fullscreen button.
  SimulateExitFullscreen();
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());

  // Play the video and make it visible, just to make sure
  // MediaControlsRotateToFullscreenDelegate doesn't react to the
  // orientationchange event.
  PlayVideo();
  UpdateVisibilityObserver();

  // Unlocking the orientation earlier will trigger a screen orientation change
  // to portrait, since the user had locked the screen orientation to portrait,
  // (which happens to also match the device orientation) and
  // MediaControlsOrientationLockDelegate is no longer overriding that lock.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));

  // Video should remain inline, unlocked.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  EXPECT_FALSE(Video().IsFullscreen());
}

TEST_F(
    MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
    AutoRotateDisabledLandscapeLockedLandscapeFullscreenRotateToPortraitLockedLandscapeFullscreen) {
  // Naturally portrait device, initially landscape device orientation yet also
  // locked to landscape screen orientation since the user had disabled auto
  // rotate, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  // The user has disabled auto rotate, e.g. locked to portrait (even though the
  // app's landscape screen orientation lock overrides it).
  SetIsAutoRotateEnabledByUser(false);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user rotating their device to portrait (matching the user's
  // rotation lock, but perpendicular to MediaControlsOrientationLockDelegate's
  // screen orientation lock which overrides it).
  RotateDeviceTo(0 /* portrait primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // Video should remain locked and fullscreen. This may disappoint users who
  // expect MediaControlsRotateToFullscreenDelegate to let them always leave
  // fullscreen by rotating perpendicular to the video's orientation (i.e.
  // rotating to portrait for a landscape video), however in this specific case,
  // since the user disabled auto rotate at the OS level, it's likely that they
  // wish to be able to use their phone whilst their head is lying sideways on a
  // pillow (or similar), in which case it's essential to keep the fullscreen
  // orientation lock.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());
  EXPECT_TRUE(Video().IsFullscreen());
}

TEST_F(
    MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
    AutoRotateDisabledLandscapeLockedLandscapeFullscreenBackToPortraitInline) {
  // Naturally portrait device, initially landscape device orientation yet also
  // locked to landscape screen orientation since the user had disabled auto
  // rotate, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(640, 480);
  // The user has disabled auto rotate, e.g. locked to portrait (even though the
  // app's landscape screen orientation lock overrides it).
  SetIsAutoRotateEnabledByUser(false);

  // Initially fullscreen, locked orientation.
  SimulateEnterFullscreen();
  ASSERT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate user clicking on media controls exit fullscreen button.
  SimulateExitFullscreen();
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());

  // Play the video and make it visible, just to make sure
  // MediaControlsRotateToFullscreenDelegate doesn't react to the
  // orientationchange event.
  PlayVideo();
  UpdateVisibilityObserver();

  // Unlocking the orientation earlier will trigger a screen orientation change
  // to portrait even though the device orientation is landscape, since the user
  // had locked the screen orientation to portrait, and
  // MediaControlsOrientationLockDelegate is no longer overriding that.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));

  // Video should remain inline, unlocked.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
  EXPECT_FALSE(Video().IsFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       PortraitVideoRotateEnterExit) {
  // Naturally portrait device, initially landscape, with *portrait* video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));
  InitVideo(480, 640);
  SetIsAutoRotateEnabledByUser(true);
  PlayVideo();
  UpdateVisibilityObserver();

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user rotating their device to portrait triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));

  // MediaControlsRotateToFullscreenDelegate should enter fullscreen, so
  // MediaControlsOrientationLockDelegate should lock orientation to portrait
  // (even though the screen is already portrait).
  EXPECT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::PORTRAIT,
            DelegateOrientationLock());

  // Device orientation events received by MediaControlsOrientationLockDelegate
  // will confirm that the device is already portrait.
  RotateDeviceTo(0 /* portrait primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should lock to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
  EXPECT_TRUE(Video().IsFullscreen());

  // Simulate user rotating their device to landscape triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));

  // MediaControlsRotateToFullscreenDelegate should exit fullscreen.
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock screen orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       LandscapeDeviceRotateEnterExit) {
  // Naturally *landscape* device, initially portrait, with landscape video.
  natural_orientation_is_portrait_ = false;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 270));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);
  PlayVideo();
  UpdateVisibilityObserver();

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user rotating their device to landscape triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 0));

  // MediaControlsRotateToFullscreenDelegate should enter fullscreen, so
  // MediaControlsOrientationLockDelegate should lock orientation to landscape
  // (even though the screen is already landscape).
  EXPECT_TRUE(Video().IsFullscreen());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Device orientation events received by MediaControlsOrientationLockDelegate
  // will confirm that the device is already landscape.
  RotateDeviceTo(0 /* landscape primary */);
  test::RunDelayedTasks(GetUnlockDelay());

  // MediaControlsOrientationLockDelegate should lock to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
  EXPECT_TRUE(Video().IsFullscreen());

  // Simulate user rotating their device to portrait triggering a screen
  // orientation change.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 270));

  // MediaControlsRotateToFullscreenDelegate should exit fullscreen.
  EXPECT_FALSE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should unlock screen orientation.
  CheckStatePendingFullscreen();
  EXPECT_FALSE(DelegateWillUnlockFullscreen());
}

TEST_F(MediaControlsOrientationLockAndRotateToFullscreenDelegateTest,
       ScreenOrientationRaceCondition) {
  // Naturally portrait device, initially portrait, with landscape video.
  natural_orientation_is_portrait_ = true;
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kPortraitPrimary, 0));
  InitVideo(640, 480);
  SetIsAutoRotateEnabledByUser(true);

  // Initially inline, unlocked orientation.
  ASSERT_FALSE(Video().IsFullscreen());
  CheckStatePendingFullscreen();
  ASSERT_FALSE(DelegateWillUnlockFullscreen());

  // Simulate user clicking on media controls fullscreen button.
  SimulateEnterFullscreen();
  EXPECT_TRUE(Video().IsFullscreen());

  // MediaControlsOrientationLockDelegate should lock to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // This will trigger a screen orientation change to landscape.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapePrimary, 90));

  // Even though the device is still held in portrait.
  RotateDeviceTo(0 /* portrait primary */);

  // MediaControlsOrientationLockDelegate should remain locked to landscape
  // indefinitely.
  test::RunDelayedTasks(GetUnlockDelay());
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Now suppose the user actually rotates from portrait-primary to landscape-
  // secondary, despite the screen currently being landscape-primary.
  RotateDeviceTo(270 /* landscape secondary */);

  // There can be a significant delay, between the device orientation changing
  // and the OS updating the screen orientation to match the new device
  // orientation. Manual testing showed that it could take longer than 200ms,
  // but less than 250ms, on common Android devices. Partly this is because OSes
  // often low-pass filter the device orientation to ignore high frequency
  // noise.
  //
  // During this period, MediaControlsOrientationLockDelegate should
  // remain locked to landscape. This prevents a race condition where the
  // delegate unlocks the screen orientation, so Android changes the screen
  // orientation back to portrait because it hasn't yet processed the device
  // orientation change to landscape.
  constexpr base::TimeDelta kMinUnlockDelay = base::Milliseconds(249);
  static_assert(GetUnlockDelay() > kMinUnlockDelay,
                "GetUnlockDelay() should significantly exceed kMinUnlockDelay");
  test::RunDelayedTasks(kMinUnlockDelay);
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Simulate the OS processing the device orientation change after a delay of
  // `kMinUnlockDelay` and hence changing the screen orientation.
  ASSERT_NO_FATAL_FAILURE(RotateScreenTo(
      display::mojom::blink::ScreenOrientation::kLandscapeSecondary, 270));

  // MediaControlsOrientationLockDelegate should remain locked to landscape.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::LANDSCAPE,
            DelegateOrientationLock());

  // Wait for the rest of the unlock delay.
  test::RunDelayedTasks(GetUnlockDelay() - kMinUnlockDelay);

  // MediaControlsOrientationLockDelegate should've locked to "any" orientation.
  CheckStateMaybeLockedFullscreen();
  EXPECT_EQ(device::mojom::ScreenOrientationLockType::ANY,
            DelegateOrientationLock());
  EXPECT_TRUE(DelegateWillUnlockFullscreen());
}

}  // namespace blink

"""


```