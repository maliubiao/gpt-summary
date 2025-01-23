Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Scan and Identification of Key Elements:**

First, I'd quickly scan the file for recognizable keywords and patterns:

* `#include`:  Indicates this is a C++ file and lists dependencies. I'd note the presence of `gtest/gtest.h` (testing framework), blink-specific headers (like `notification_data.h`, `notification.h`, bindings headers), and platform-level headers. This immediately tells me it's a test file for a Blink component related to notifications.
* `namespace blink { namespace {`: Standard C++ namespace usage, indicating the code is within the Blink rendering engine. The inner unnamed namespace suggests test-specific helpers.
* `TEST(...)`:  This is the core of Google Test. Each `TEST` macro defines an individual test case. I'd immediately recognize this as the primary way the file functions.
* Variable declarations with `k`:  The convention of using `k` prefixes for constants is common in Chromium. I'd note these as input data for the tests.
* `NotificationOptions`, `NotificationAction`, `TimestampTrigger`, `NotificationData`: These are key classes/structures being tested.
* `CreateNotificationData(...)`:  This function seems crucial as it's likely the function under test.
* `EXPECT_EQ`, `ASSERT_EQ`, `ASSERT_THAT`, `HadNoException`, `HadException`: These are Google Test assertion macros used to verify the behavior of the code.
* URLs, strings, booleans, arrays: These are the types of data being manipulated in the tests.

**2. Understanding the File's Purpose:**

Based on the included headers and the test names (like "ReflectProperties," "SilentNotificationWithVibration," "InvalidIconUrls"), it's clear that `notification_data_test.cc` is designed to test the functionality of the `NotificationData` class and the process of creating it from `NotificationOptions`. The tests aim to verify:

* **Correct mapping of properties:**  That properties set in `NotificationOptions` are correctly reflected in the created `NotificationData` object.
* **Validation and error handling:** That invalid or conflicting combinations of options (like vibration in silent notifications) are correctly detected and result in errors.
* **Data normalization/processing:** That data like vibration patterns and URLs are processed correctly.
* **Default values:**  That default values are applied when certain options are not specified.
* **Limits and constraints:** That limits like the maximum number of actions are enforced.

**3. Analyzing Individual Tests (Example: `ReflectProperties`):**

I'd go through each test case and understand what it's specifically testing:

* **Setup:** The `ReflectProperties` test sets up a base URL, creates various `NotificationOptions` with different properties (direction, language, body, tag, image, icon, badge, vibration, timestamp, renotify, silent, require interaction, actions, showTrigger).
* **Execution:** It calls `CreateNotificationData` to create a `NotificationData` object.
* **Assertions:** It then uses `EXPECT_EQ` to compare the values in the created `notification_data` with the values set in the `options`. Crucially, it verifies URL resolution against the base URL.

**4. Identifying Relationships to Web Technologies:**

Now, connect the dots to web technologies:

* **JavaScript:** The names of the classes (`Notification`, `NotificationOptions`, `NotificationAction`) directly correspond to the JavaScript Notification API. The tests are essentially validating the backend implementation of this API.
* **HTML:**  Notifications are a visual element presented by the browser. While this test doesn't directly manipulate HTML, the data being tested (title, body, icon, actions) are the *content* of those HTML notifications.
* **CSS:**  While not directly tested, the `dir` property ("rtl", "ltr") relates to text directionality, which is a CSS concern. The icon and badge URLs point to image resources, which are styled through CSS in the broader web context.

**5. Logical Inference and Examples:**

For logical inferences, consider a test like `SilentNotificationWithVibration`:

* **Assumption:**  The user (developer) tries to create a silent notification with a vibration pattern specified.
* **Input:** `options->setVibrate(...)`, `options->setSilent(true)`.
* **Expected Output:** An error (exception) is thrown. The `ASSERT_THAT(exception_state, HadException(...))` verifies this.

**6. Common User Errors:**

Think about what developers might do wrong when using the Notification API:

* Providing invalid URLs for icons or badges.
* Trying to set a vibration pattern for a silent notification.
* Using the "button" action type with a placeholder.
* Setting `renotify` to `true` without providing a tag.
* Providing a trigger timestamp too far in the future.

The test cases directly highlight these potential errors.

**7. Tracing User Operations (Debugging Clues):**

Imagine a developer reporting a bug with notifications. How might they reach this code?

* **JavaScript `new Notification(...)` call:** The user's JavaScript code calls the `Notification` constructor, passing in title and options.
* **Blink's JavaScript binding layer:** This call is intercepted by Blink's JavaScript bindings.
* **`CreateNotificationData` function:** The binding layer calls the `CreateNotificationData` function (the one being tested) to create the underlying `NotificationData` object from the provided options.
* **These tests as validation:** The tests in this file ensure that `CreateNotificationData` correctly handles the input from the JavaScript API. If a test fails, it might indicate a bug in the `CreateNotificationData` logic, the JavaScript bindings, or even the user's incorrect usage.

By systematically analyzing the code, its structure, and its purpose, we can arrive at a comprehensive understanding of the functionality of `notification_data_test.cc` and its connections to web technologies and potential user errors.
这个文件 `notification_data_test.cc` 是 Chromium Blink 引擎中用于测试 `NotificationData` 类的功能和行为的单元测试文件。 `NotificationData` 类是用于存储和传递通知相关数据的核心结构。

**主要功能:**

1. **测试 `NotificationOptions` 中的属性是否正确地反映到 `NotificationData` 中:**  这个文件通过创建 `NotificationOptions` 对象并设置不同的属性值，然后调用 `CreateNotificationData` 函数来生成 `NotificationData` 对象，并断言 `NotificationData` 中的属性值与设置的 `NotificationOptions` 中的值是否一致。

2. **测试对非法或不合法的 `NotificationOptions` 配置的处理:**  测试用例会故意设置一些不符合规范的选项组合，例如在静默通知中设置震动模式，或者为 "button" 类型的 action 设置 placeholder，验证 `CreateNotificationData` 函数是否会抛出预期的错误。

3. **测试 URL 的解析和处理:**  测试用例会设置各种类型的 URL（有效、无效、相对路径等）作为通知的图标、图片、徽章以及 action 的图标，验证 `CreateNotificationData` 函数是否能正确解析和处理这些 URL。

4. **测试数据规范化和默认值:**  例如，测试震动模式的规范化（将大的震动值限制在合理范围内），以及在没有设置时间戳时是否会使用默认的当前时间。

5. **测试通知 action 的数量限制:**  验证当提供的 action 数量超过最大允许值时，`CreateNotificationData` 函数是否会截断 actions 列表。

6. **测试 `showTrigger` (显示触发器) 的时间限制:** 验证当设置的触发时间超过允许的最大延迟时，是否会抛出错误。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接测试的是 Blink 引擎内部的 C++ 代码，它与 JavaScript, HTML, CSS 的功能有着密切的关系，因为它是 Web Notifications API 的底层实现的一部分。

* **JavaScript:**
    * **功能关系:**  JavaScript 的 `Notification` 接口允许网页开发者创建和管理系统通知。`NotificationData` 类存储了从 JavaScript 传递到 Blink 引擎的通知数据。
    * **举例:** 当 JavaScript 代码调用 `new Notification('标题', { body: '内容', icon: 'icon.png' })` 时，这些参数（'标题'，'内容'，'icon.png'）最终会被传递到 Blink 引擎，并被存储在 `NotificationData` 对象的相应属性中。这个测试文件中的 `TEST(NotificationDataTest, ReflectProperties)` 测试就验证了这种映射关系。

* **HTML:**
    * **功能关系:** 通知最终会在用户的操作系统或浏览器中以可视化的形式呈现，这涉及到 HTML 的渲染。虽然 `NotificationData` 本身不直接操作 HTML，但它存储的数据会被用来生成最终的通知 UI。
    * **举例:** `NotificationData` 中的 `title` 和 `body` 属性的值会显示在通知的标题和内容区域。`icon` 属性指向的图片会作为通知的图标显示。

* **CSS:**
    * **功能关系:** 通知的样式（例如文字方向）可能受到 CSS 的影响。 `NotificationOptions` 中的 `dir` 属性（表示文字方向，如 "ltr" 或 "rtl"）会影响通知内容的呈现方式。
    * **举例:** 测试文件中的 `TEST(NotificationDataTest, DirectionValues)` 测试了 `dir` 属性的值如何映射到 `NotificationData` 中的 `direction` 属性，而这个 `direction` 属性在后续渲染通知时会影响文本的显示方向，这与 CSS 的 `direction` 属性的功能类似。

**逻辑推理 (假设输入与输出):**

假设输入一个 `NotificationOptions` 对象，其中设置了 `silent` 为 `true` 并且设置了 `vibrate` 数组：

* **假设输入:**
    ```cpp
    NotificationOptions* options = NotificationOptions::Create(scope.GetIsolate());
    Vector<unsigned> vibration_pattern = {100, 200, 100};
    auto* vibration_sequence =
        MakeGarbageCollected<V8UnionUnsignedLongOrUnsignedLongSequence>(
            std::move(vibration_pattern));
    options->setSilent(true);
    options->setVibrate(vibration_sequence);
    ```
* **预期输出:** `CreateNotificationData` 函数会抛出一个类型错误 (TypeError)，因为规范规定静默通知不能指定震动模式。这在 `TEST(NotificationDataTest, SilentNotificationWithVibration)` 测试中进行了验证。

**用户或编程常见的使用错误及举例说明:**

1. **在静默通知中设置震动模式:** 用户（开发者）可能会错误地认为即使是静默通知也可以有震动反馈，从而在 `NotificationOptions` 中同时设置 `silent: true` 和 `vibrate: [...]`。`TEST(NotificationDataTest, SilentNotificationWithVibration)` 测试就模拟了这种情况，并验证了 Blink 引擎会阻止这种不合法的配置。

2. **为 "button" 类型的 action 设置 placeholder:**  早期的通知规范可能允许为所有类型的 action 设置 placeholder，但后来规范进行了修改，只有 "text" 类型的 action 才能设置 placeholder。如果用户尝试为 "button" 类型的 action 设置 placeholder，`TEST(NotificationDataTest, ActionTypeButtonWithPlaceholder)` 测试会验证是否会抛出错误。

3. **设置 `renotify: true` 但没有设置 `tag`:**  如果用户希望相同的通知只显示一次，除非它的内容发生变化，他们可能会设置 `renotify: true`。然而，为了让浏览器识别是同一个通知，需要设置一个唯一的 `tag`。如果用户忘记设置 `tag`，`TEST(NotificationDataTest, RenotifyWithEmptyTag)` 测试会验证是否会抛出错误。

4. **提供无效的 URL 作为图标或徽章:** 用户可能会错误地提供格式错误的 URL 或者无法访问的 URL 作为通知的图标、图片或徽章。`TEST(NotificationDataTest, InvalidIconUrls)` 测试验证了在这种情况下，`NotificationData` 会将这些 URL 设置为空，而不是抛出错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个网页:** 用户在浏览器中打开一个包含 Web Notifications API 的网页。

2. **网页 JavaScript 代码请求显示通知:** 网页的 JavaScript 代码调用 `new Notification('Title', options)` 来请求显示一个通知。这个 `options` 对象包含了通知的各种属性，例如 `body`, `icon`, `actions` 等。

3. **浏览器处理 JavaScript 通知请求:** 浏览器接收到 JavaScript 的通知请求，并将这些参数传递给 Blink 引擎的渲染进程。

4. **Blink 引擎创建 `NotificationOptions` 对象:** Blink 引擎会根据 JavaScript 传递的 `options` 创建一个对应的 C++ `NotificationOptions` 对象。

5. **调用 `CreateNotificationData` 函数:** Blink 引擎会调用 `CreateNotificationData` 函数，将 `NotificationOptions` 对象作为输入，来创建一个 `NotificationData` 对象。这个函数会进行各种校验和数据转换。

6. **`notification_data_test.cc` 中测试的逻辑被执行:**  `notification_data_test.cc` 中的测试用例模拟了上述步骤，通过创建不同的 `NotificationOptions` 对象，然后调用 `CreateNotificationData` 函数，并断言输出的 `NotificationData` 对象的状态是否符合预期。

**作为调试线索:**

如果一个 Web Notification 功能出现问题，例如通知显示不正确、行为异常或者抛出错误，开发者可能会检查以下内容：

* **JavaScript 代码:** 检查 JavaScript 代码中传递给 `Notification` 构造函数的参数是否正确。
* **浏览器控制台错误信息:** 检查浏览器控制台是否有与通知相关的错误信息。
* **Blink 引擎日志:** 如果需要深入调试，可以查看 Blink 引擎的日志，了解 `CreateNotificationData` 函数的执行过程和输出结果。
* **参考 `notification_data_test.cc` 中的测试用例:**  `notification_data_test.cc` 中的测试用例覆盖了各种正常和异常情况，可以帮助开发者理解 Blink 引擎对通知参数的预期，从而定位问题所在。例如，如果用户发现他们的静默通知仍然有震动，他们可以参考 `SilentNotificationWithVibration` 测试用例，了解这种配置是被 Blink 引擎禁止的。

总而言之，`notification_data_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎能够正确地处理和验证 Web Notifications API 传递的数据，保证了通知功能的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/modules/notifications/notification_data_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/notifications/notification_data.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/notifications/notification_constants.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_unsignedlong_unsignedlongsequence.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_action.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_notification_options.h"
#include "third_party/blink/renderer/modules/notifications/notification.h"
#include "third_party/blink/renderer/modules/notifications/timestamp_trigger.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/testing/exception_state_matchers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

const char kNotificationBaseUrl[] = "https://example.com/directory/";
const char kNotificationTitle[] = "My Notification";

const char kNotificationDir[] = "rtl";
const char kNotificationLang[] = "nl";
const char kNotificationBody[] = "Hello, world";
const char kNotificationTag[] = "my_tag";
const char kNotificationEmptyTag[] = "";
const char kNotificationImage[] = "https://example.com/image.jpg";
const char kNotificationIcon[] = "/icon.png";
const char kNotificationIconInvalid[] = "https://invalid:icon:url";
const char kNotificationBadge[] = "badge.png";
const std::array<unsigned, 5> kNotificationVibration = {42, 10, 20, 30, 40};
const uint64_t kNotificationTimestamp = 621046800ull;
const bool kNotificationRenotify = true;
const bool kNotificationSilent = false;
const bool kNotificationRequireInteraction = true;

const mojom::blink::NotificationActionType kBlinkNotificationActionType =
    mojom::blink::NotificationActionType::TEXT;
const char kNotificationActionType[] = "text";
const char kNotificationActionAction[] = "my_action";
const char kNotificationActionTitle[] = "My Action";
const char kNotificationActionIcon[] = "https://example.com/action_icon.png";
const char kNotificationActionPlaceholder[] = "Placeholder...";

const std::array<unsigned, 4> kNotificationVibrationUnnormalized = {10, 1000000,
                                                                    50, 42};
const std::array<int, 3> kNotificationVibrationNormalized = {10, 10000, 50};

TEST(NotificationDataTest, ReflectProperties) {
  test::TaskEnvironment task_environment;
  const KURL base_url(kNotificationBaseUrl);
  V8TestingScope scope(base_url);

  Vector<unsigned> vibration_pattern(kNotificationVibration);

  auto* vibration_sequence =
      MakeGarbageCollected<V8UnionUnsignedLongOrUnsignedLongSequence>(
          vibration_pattern);

  HeapVector<Member<NotificationAction>> actions;
  for (size_t i = 0; i < Notification::maxActions(); ++i) {
    NotificationAction* action = NotificationAction::Create(scope.GetIsolate());
    action->setType(kNotificationActionType);
    action->setAction(kNotificationActionAction);
    action->setTitle(kNotificationActionTitle);
    action->setIcon(kNotificationActionIcon);
    action->setPlaceholder(kNotificationActionPlaceholder);

    actions.push_back(action);
  }

  const DOMTimeStamp show_timestamp =
      base::Time::Now().InMillisecondsSinceUnixEpoch();
  TimestampTrigger* showTrigger = TimestampTrigger::Create(show_timestamp);

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setDir(kNotificationDir);
  options->setLang(kNotificationLang);
  options->setBody(kNotificationBody);
  options->setTag(kNotificationTag);
  options->setImage(kNotificationImage);
  options->setIcon(kNotificationIcon);
  options->setBadge(kNotificationBadge);
  options->setVibrate(vibration_sequence);
  options->setTimestamp(kNotificationTimestamp);
  options->setRenotify(kNotificationRenotify);
  options->setSilent(kNotificationSilent);
  options->setRequireInteraction(kNotificationRequireInteraction);
  options->setActions(actions);
  options->setShowTrigger(showTrigger);

  // TODO(peter): Test |options.data| and |notificationData.data|.

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(exception_state, HadNoException());

  EXPECT_EQ(kNotificationTitle, notification_data->title);

  EXPECT_EQ(mojom::blink::NotificationDirection::RIGHT_TO_LEFT,
            notification_data->direction);
  EXPECT_EQ(kNotificationLang, notification_data->lang);
  EXPECT_EQ(kNotificationBody, notification_data->body);
  EXPECT_EQ(kNotificationTag, notification_data->tag);
  EXPECT_EQ(base::Time::FromMillisecondsSinceUnixEpoch(
                static_cast<int64_t>(show_timestamp)),
            notification_data->show_trigger_timestamp);

  // URLs should be resolved against the base URL of the execution context.
  EXPECT_EQ(KURL(base_url, kNotificationImage), notification_data->image);
  EXPECT_EQ(KURL(base_url, kNotificationIcon), notification_data->icon);
  EXPECT_EQ(KURL(base_url, kNotificationBadge), notification_data->badge);

  ASSERT_EQ(vibration_pattern.size(),
            notification_data->vibration_pattern->size());
  for (wtf_size_t i = 0; i < vibration_pattern.size(); ++i) {
    EXPECT_EQ(
        vibration_pattern[i],
        static_cast<unsigned>(notification_data->vibration_pattern.value()[i]));
  }

  EXPECT_EQ(kNotificationTimestamp, notification_data->timestamp);
  EXPECT_EQ(kNotificationRenotify, notification_data->renotify);
  EXPECT_EQ(kNotificationSilent, notification_data->silent);
  EXPECT_EQ(kNotificationRequireInteraction,
            notification_data->require_interaction);
  EXPECT_EQ(actions.size(), notification_data->actions->size());
  for (const auto& action : notification_data->actions.value()) {
    EXPECT_EQ(kBlinkNotificationActionType, action->type);
    EXPECT_EQ(kNotificationActionAction, action->action);
    EXPECT_EQ(kNotificationActionTitle, action->title);
    EXPECT_EQ(kNotificationActionPlaceholder, action->placeholder);
  }
}

TEST(NotificationDataTest, SilentNotificationWithVibration) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  Vector<unsigned> vibration_pattern(kNotificationVibration);

  auto* vibration_sequence =
      MakeGarbageCollected<V8UnionUnsignedLongOrUnsignedLongSequence>(
          std::move(vibration_pattern));

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setVibrate(vibration_sequence);
  options->setSilent(true);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(exception_state,
              HadException(
                  ESErrorType::kTypeError,
                  "Silent notifications must not specify vibration patterns."));
}

TEST(NotificationDataTest, ActionTypeButtonWithPlaceholder) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  HeapVector<Member<NotificationAction>> actions;
  NotificationAction* action = NotificationAction::Create();
  action->setType("button");
  action->setPlaceholder("I'm afraid I can't do that...");
  actions.push_back(action);

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setActions(actions);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(
      exception_state,
      HadException(
          ESErrorType::kTypeError,
          "Notifications of type \"button\" cannot specify a placeholder."));
}

TEST(NotificationDataTest, RenotifyWithEmptyTag) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setTag(kNotificationEmptyTag);
  options->setRenotify(true);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(exception_state,
              HadException(ESErrorType::kTypeError,
                           "Notifications which set the renotify flag must "
                           "specify a non-empty tag."));
}

TEST(NotificationDataTest, InvalidIconUrls) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  HeapVector<Member<NotificationAction>> actions;
  for (size_t i = 0; i < Notification::maxActions(); ++i) {
    NotificationAction* action = NotificationAction::Create();
    action->setAction(kNotificationActionAction);
    action->setTitle(kNotificationActionTitle);
    action->setIcon(kNotificationIconInvalid);
    actions.push_back(action);
  }

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setImage(kNotificationIconInvalid);
  options->setIcon(kNotificationIconInvalid);
  options->setBadge(kNotificationIconInvalid);
  options->setActions(actions);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(exception_state, HadNoException());

  EXPECT_TRUE(notification_data->image.IsEmpty());
  EXPECT_TRUE(notification_data->icon.IsEmpty());
  EXPECT_TRUE(notification_data->badge.IsEmpty());
  for (const auto& action : notification_data->actions.value())
    EXPECT_TRUE(action->icon.IsEmpty());
}

TEST(NotificationDataTest, VibrationNormalization) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  Vector<unsigned> unnormalized_pattern(kNotificationVibrationUnnormalized);

  auto* vibration_sequence =
      MakeGarbageCollected<V8UnionUnsignedLongOrUnsignedLongSequence>(
          unnormalized_pattern);

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setVibrate(vibration_sequence);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  EXPECT_THAT(exception_state, HadNoException());

  Vector<int> normalized_pattern(kNotificationVibrationNormalized);

  ASSERT_EQ(normalized_pattern.size(),
            notification_data->vibration_pattern->size());
  for (wtf_size_t i = 0; i < normalized_pattern.size(); ++i) {
    EXPECT_EQ(normalized_pattern[i],
              notification_data->vibration_pattern.value()[i]);
  }
}

TEST(NotificationDataTest, DefaultTimestampValue) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  EXPECT_THAT(exception_state, HadNoException());

  // The timestamp should be set to the current time since the epoch if it
  // wasn't supplied by the developer. "32" has no significance, but an equal
  // comparison of the value could lead to flaky failures.
  EXPECT_NEAR(notification_data->timestamp,
              base::Time::Now().InMillisecondsFSinceUnixEpoch(), 32);
}

TEST(NotificationDataTest, DirectionValues) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  WTF::HashMap<String, mojom::blink::NotificationDirection> mappings;
  mappings.insert("ltr", mojom::blink::NotificationDirection::LEFT_TO_RIGHT);
  mappings.insert("rtl", mojom::blink::NotificationDirection::RIGHT_TO_LEFT);
  mappings.insert("auto", mojom::blink::NotificationDirection::AUTO);

  for (const String& direction : mappings.Keys()) {
    NotificationOptions* options =
        NotificationOptions::Create(scope.GetIsolate());
    options->setDir(direction);

    auto& exception_state = scope.GetExceptionState();
    mojom::blink::NotificationDataPtr notification_data =
        CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                               options, exception_state);
    ASSERT_THAT(exception_state, HadNoException());

    EXPECT_EQ(mappings.at(direction), notification_data->direction);
  }
}

TEST(NotificationDataTest, MaximumActionCount) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  HeapVector<Member<NotificationAction>> actions;
  for (size_t i = 0; i < Notification::maxActions() + 2; ++i) {
    NotificationAction* action = NotificationAction::Create();
    action->setAction(String::Number(i));
    action->setTitle(kNotificationActionTitle);

    actions.push_back(action);
  }

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setActions(actions);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(exception_state, HadNoException());

  // The stored actions will be capped to |maxActions| entries.
  ASSERT_EQ(Notification::maxActions(), notification_data->actions->size());

  for (wtf_size_t i = 0; i < Notification::maxActions(); ++i) {
    String expected_action = String::Number(i);
    EXPECT_EQ(expected_action, notification_data->actions.value()[i]->action);
  }
}

TEST(NotificationDataTest, RejectsTriggerTimestampOverAYear) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  base::Time show_timestamp =
      base::Time::Now() + kMaxNotificationShowTriggerDelay + base::Days(1);
  TimestampTrigger* show_trigger =
      TimestampTrigger::Create(show_timestamp.InMillisecondsFSinceUnixEpoch());

  NotificationOptions* options =
      NotificationOptions::Create(scope.GetIsolate());
  options->setShowTrigger(show_trigger);

  auto& exception_state = scope.GetExceptionState();
  mojom::blink::NotificationDataPtr notification_data =
      CreateNotificationData(scope.GetExecutionContext(), kNotificationTitle,
                             options, exception_state);
  ASSERT_THAT(
      exception_state,
      HadException(
          ESErrorType::kTypeError,
          "Notification trigger timestamp too far ahead in the future."));
}

}  // namespace
}  // namespace blink
```