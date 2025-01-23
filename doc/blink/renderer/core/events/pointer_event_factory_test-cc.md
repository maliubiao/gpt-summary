Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine and describe its functionality.
I need to identify the purpose of the code, explain its relation to web technologies like JavaScript, HTML, and CSS (if any), provide examples of input and output, highlight potential user/programming errors, and finally, summarize the overall function of the provided code snippet.

**Plan:**
1. **Identify the core class:** The filename `pointer_event_factory_test.cc` and the class name `PointerEventFactoryTest` strongly suggest that this file contains unit tests for a class named `PointerEventFactory`.
2. **Analyze test methods:**  Examine the different `TEST_F` methods to understand what aspects of `PointerEventFactory` are being tested. Look for patterns in the setup and assertions.
3. **Infer `PointerEventFactory`'s functionality:** Based on the tests, deduce the responsibilities of the `PointerEventFactory` class. It likely involves creating and managing `PointerEvent` objects.
4. **Relate to web technologies:** Consider how pointer events interact with JavaScript (event handling), HTML (elements that receive events), and CSS (styling based on pointer interactions).
5. **Provide input/output examples:**  Based on the test methods, create hypothetical scenarios and the expected outcomes.
6. **Identify potential errors:** Think about common mistakes developers might make when working with pointer events or using the `PointerEventFactory`.
7. **Summarize the functionality:** Condense the findings into a concise description of the code's purpose.
这是对 `blink/renderer/core/events/pointer_event_factory_test.cc` 文件部分代码的功能归纳：

**功能归纳：**

这段代码是 Chromium Blink 引擎中 `PointerEventFactory` 类的单元测试。它的主要功能是测试 `PointerEventFactory` 类在创建和管理 `PointerEvent` 对象时的各种场景和行为是否正确。

**具体来说，测试涵盖了以下方面：**

*   **创建不同类型的 `PointerEvent`：**  测试能够为不同类型的指针设备（鼠标、触摸、笔）创建正确的 `PointerEvent` 对象。
*   **管理指针 ID：**  测试 `PointerEventFactory` 如何分配和管理唯一的指针 ID，包括鼠标的固定 ID 和其他类型指针的动态分配 ID。
*   **跟踪活跃指针：** 测试 `PointerEventFactory` 如何跟踪当前活跃的指针以及它们的状态（例如，是否有按键按下）。
*   **处理指针事件的生命周期：** 测试 `PointerEventFactory` 如何处理指针的添加、移动、抬起、取消等事件，以及 primary 属性的正确设置。
*   **生成 pointerenter 和 pointerleave 事件：** 测试如何基于现有的 `PointerEvent` 创建 pointerenter 和 pointerleave 等边界事件。
*   **处理非悬停指针：** 测试如何追踪当前没有悬停在任何元素上的指针。
*   **处理鼠标按键状态：** 测试如何正确跟踪鼠标按键的按下状态。
*   **处理触摸事件的按下和释放：** 测试触摸事件的开始和结束，以及可能的拖拽场景。
*   **处理多种类型的指针同时存在的情况：** 测试鼠标、触摸和笔等多种指针设备同时操作时的事件处理。
*   **处理超出范围的指针类型：**  测试对于未知或超出预期的指针类型的处理。
*   **记录和获取最后一次指针位置：** 测试如何记录和获取特定指针的最后位置。
*   **处理合并 (coalesced) 和预测 (predicted) 的事件：** 测试对于 `pointermove` 事件，如何处理合并和预测的事件队列。
*   **处理键盘修饰键状态：** 测试在创建 `PointerEvent` 时如何正确设置 `ctrlKey`、`shiftKey`、`altKey` 和 `metaKey` 属性。
*   **测试设备 ID 特性：**  （在 `PointerEventFactoryDeviceIdTest` 中）测试是否正确处理与指针事件关联的设备 ID。

**与 JavaScript, HTML, CSS 的关系：**

`PointerEvent` 是 Web API 中的一个接口，用于表示由指点设备触发的硬件无关的事件。`PointerEventFactory` 的作用是在 Blink 渲染引擎的 C++ 代码中创建与这些 Web API 对象相对应的内部表示。

*   **JavaScript:**  当用户与网页交互（例如，点击、触摸屏幕、使用手写笔）时，浏览器会生成底层的输入事件。`PointerEventFactory` 负责将这些底层的输入事件转换为 `PointerEvent` 对象，这些对象最终会被传递到 JavaScript 中，供网页的 JavaScript 代码通过事件监听器进行处理。例如：

    ```javascript
    document.addEventListener('pointerdown', (event) => {
      console.log('Pointer ID:', event.pointerId);
      console.log('Pointer Type:', event.pointerType);
      console.log('Client X:', event.clientX);
      console.log('Client Y:', event.clientY);
    });
    ```

*   **HTML:** HTML 元素是接收和触发指针事件的目标。例如，一个 `<div>` 元素可以添加 `pointerdown` 事件监听器。`PointerEventFactory` 创建的事件对象会与触发事件的 HTML 元素关联起来。

    ```html
    <div id="myDiv" style="width: 100px; height: 100px; background-color: red;"></div>
    ```

*   **CSS:** CSS 可以使用伪类（例如 `:hover`, `:active`) 来响应指针事件引起的状态变化。虽然 `PointerEventFactory` 本身不直接操作 CSS，但它创建的 `PointerEvent` 对象会触发浏览器内部的状态变化，从而影响 CSS 伪类的应用。

    ```css
    #myDiv:hover {
      background-color: blue;
    }
    ```

**逻辑推理的假设输入与输出：**

假设输入一个 `WebPointerEvent` 对象，表示一个鼠标左键按下事件：

```c++
WebPointerEvent web_pointer_event;
web_pointer_event.pointer_type = WebPointerProperties::PointerType::kMouse;
web_pointer_event.id = 0; // 鼠标的原始 ID
web_pointer_event.SetType(WebInputEvent::Type::kPointerDown);
web_pointer_event.SetPositionInScreen(50, 60);
web_pointer_event.button = WebPointerProperties::Button::kLeftButton;
```

`PointerEventFactory::Create()` 方法接收到这个 `WebPointerEvent` 对象后，会进行以下处理（简化）：

*   **分配或查找指针 ID：**  对于鼠标，通常会使用预定义的 ID（例如 `expected_mouse_id_`，测试中为 1）。
*   **创建 `PointerEvent` 对象：**  创建一个 `PointerEvent` 实例，并填充相应的信息。
*   **设置属性：** 将 `web_pointer_event` 中的信息映射到 `PointerEvent` 对象的属性，例如 `pointerId`、`pointerType`、`clientX`、`clientY`、`buttons` 等。
*   **输出 `PointerEvent` 对象：** 返回创建的 `PointerEvent` 对象。

假设输出的 `PointerEvent` 对象（在 JavaScript 中访问）可能具有以下属性：

```javascript
{
  pointerId: 1,
  pointerType: "mouse",
  clientX: 50,
  clientY: 60,
  buttons: 1, // 表示鼠标左键按下
  isPrimary: true,
  // ... 其他属性
}
```

**涉及用户或编程常见的使用错误：**

虽然 `PointerEventFactory` 是 Blink 引擎内部的类，普通用户不会直接使用。但开发者在处理指针事件时可能遇到以下错误，这些错误与 `PointerEventFactory` 试图正确处理的场景相关：

*   **假设所有指针都是鼠标：**  错误地只监听鼠标事件（`mousedown`, `mouseup`, `mousemove`），而忽略了触摸和笔等其他类型的输入。`PointerEvent` 统一了这些输入方式。
*   **混淆指针 ID：**  对于多点触摸或多个笔同时输入的情况，错误地假设所有事件都来自同一个指针，而忽略了 `pointerId` 的区分。
*   **没有正确处理 `pointercancel` 事件：**  在某些情况下（例如，触摸操作被浏览器取消），会触发 `pointercancel` 事件。如果开发者没有正确处理这个事件，可能会导致应用程序状态不一致。
*   **错误地处理 `isPrimary` 属性：**  对于触摸事件，只有一个触点是 primary。如果开发者错误地假设所有触点都是 primary，可能会导致逻辑错误。
*   **在不需要时阻止默认行为：**  过度使用 `preventDefault()` 可能会阻止浏览器的默认行为，例如滚动或缩放。

**这段代码是第 1 部分，共 2 部分，其功能可以概括为：**

这段代码是 `PointerEventFactory` 类的单元测试的第一部分，主要关注于测试创建和管理各种基本类型的 `PointerEvent` 对象，以及跟踪活跃指针和处理简单的事件生命周期。它验证了 `PointerEventFactory` 能够正确地将底层的输入事件转化为符合 Web 标准的 `PointerEvent` 对象，为后续的事件分发和 JavaScript 处理奠定基础。

### 提示词
```
这是目录为blink/renderer/core/events/pointer_event_factory_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/events/pointer_event_factory.h"

#include <gtest/gtest.h>

#include <limits>

#include "base/containers/contains.h"
#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"

namespace {
const int32_t kBrowserDeviceId0 = 0;
const int32_t kBrowserDeviceId1 = 1;
}  // namespace

namespace blink {

class PointerEventFactoryTest : public testing::Test {
 protected:
  void SetUp() override;
  PointerEvent* CreateAndCheckPointerCancel(WebPointerProperties::PointerType,
                                            int raw_id,
                                            int unique_id,
                                            bool is_primary);
  PointerEvent* CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType pointer_type,
      int raw_id,
      int unique_id,
      bool is_primary,
      bool hovering,
      WebInputEvent::Modifiers modifiers = WebInputEvent::kNoModifiers,
      WebInputEvent::Type type = WebInputEvent::Type::kPointerDown,
      WebPointerProperties::Button button =
          WebPointerProperties::Button::kNoButton,
      wtf_size_t coalesced_event_count = 0,
      wtf_size_t predicted_event_count = 0) {
    WebPointerEvent web_pointer_event;
    web_pointer_event.pointer_type = pointer_type;
    web_pointer_event.id = raw_id;
    web_pointer_event.SetType(type);
    web_pointer_event.SetTimeStamp(WebInputEvent::GetStaticTimeStampForTests());
    web_pointer_event.SetModifiers(modifiers);
    web_pointer_event.force = 1.0;
    web_pointer_event.hovering = hovering;
    web_pointer_event.button = button;
    web_pointer_event.tilt_x = 1.5;
    web_pointer_event.tilt_y = 0.5;
    web_pointer_event.SetPositionInScreen(100, 100);
    Vector<WebPointerEvent> coalesced_events;
    for (wtf_size_t i = 0; i < coalesced_event_count; i++) {
      coalesced_events.push_back(web_pointer_event);
    }
    Vector<WebPointerEvent> predicted_events;
    for (wtf_size_t i = 0; i < predicted_event_count; i++) {
      predicted_events.push_back(web_pointer_event);
    }
    PointerEvent* pointer_event = pointer_event_factory_.Create(
        web_pointer_event, coalesced_events, predicted_events, nullptr);
    EXPECT_EQ(unique_id, pointer_event->pointerId());
    EXPECT_EQ(is_primary, pointer_event->isPrimary());
    EXPECT_EQ(WebInputEvent::GetStaticTimeStampForTests(),
              pointer_event->PlatformTimeStamp());
    const String& expected_pointer_type =
        PointerEventFactory::PointerTypeNameForWebPointPointerType(
            pointer_type);
    EXPECT_EQ(expected_pointer_type, pointer_event->pointerType());

    EXPECT_EQ(!!(modifiers & WebInputEvent::kControlKey),
              pointer_event->ctrlKey());
    EXPECT_EQ(!!(modifiers & WebInputEvent::kShiftKey),
              pointer_event->shiftKey());
    EXPECT_EQ(!!(modifiers & WebInputEvent::kAltKey), pointer_event->altKey());
    EXPECT_EQ(!!(modifiers & WebInputEvent::kMetaKey),
              pointer_event->metaKey());

    EXPECT_EQ(pointer_event->tiltX(), 2);
    EXPECT_EQ(pointer_event->tiltY(), 1);
    EXPECT_EQ(pointer_event->altitudeAngle(), 1.5432015087805078);
    EXPECT_EQ(pointer_event->azimuthAngle(), 0.3216896250354046);

    if (type == WebInputEvent::Type::kPointerMove) {
      EXPECT_EQ(coalesced_event_count,
                pointer_event->getCoalescedEvents().size());
      EXPECT_EQ(predicted_event_count,
                pointer_event->getPredictedEvents().size());
      for (wtf_size_t i = 0; i < coalesced_event_count; i++) {
        EXPECT_EQ(unique_id,
                  pointer_event->getCoalescedEvents()[i]->pointerId());
        EXPECT_EQ(is_primary,
                  pointer_event->getCoalescedEvents()[i]->isPrimary());
        EXPECT_EQ(expected_pointer_type, pointer_event->pointerType());
        EXPECT_EQ(WebInputEvent::GetStaticTimeStampForTests(),
                  pointer_event->PlatformTimeStamp());
      }
      for (wtf_size_t i = 0; i < predicted_event_count; i++) {
        EXPECT_EQ(unique_id,
                  pointer_event->getPredictedEvents()[i]->pointerId());
        EXPECT_EQ(is_primary,
                  pointer_event->getPredictedEvents()[i]->isPrimary());
        EXPECT_EQ(expected_pointer_type, pointer_event->pointerType());
        EXPECT_EQ(WebInputEvent::GetStaticTimeStampForTests(),
                  pointer_event->PlatformTimeStamp());
      }
    } else {
      EXPECT_EQ(0u, pointer_event->getCoalescedEvents().size());
      EXPECT_EQ(0u, pointer_event->getPredictedEvents().size());
    }
    EXPECT_EQ(
        pointer_event_factory_.GetLastPointerPosition(
            pointer_event->pointerId(),
            WebPointerProperties(1, WebPointerProperties::PointerType::kUnknown,
                                 WebPointerProperties::Button::kNoButton,
                                 gfx::PointF(50, 50), gfx::PointF(20, 20)),
            type),
        gfx::PointF(100, 100));
    return pointer_event;
  }
  void CreateAndCheckPointerTransitionEvent(PointerEvent*, const AtomicString&);
  void CheckNonHoveringPointers(const HashSet<int>& expected);

  PointerEventFactory pointer_event_factory_;
  int expected_mouse_id_;
  int mapped_id_start_;
};

void PointerEventFactoryTest::SetUp() {
  expected_mouse_id_ = 1;
  mapped_id_start_ = 2;
}

PointerEvent* PointerEventFactoryTest::CreateAndCheckPointerCancel(
    WebPointerProperties::PointerType pointer_type,
    int raw_id,
    int unique_id,
    bool is_primary) {
  PointerEvent* pointer_event = pointer_event_factory_.CreatePointerCancelEvent(
      unique_id, WebInputEvent::GetStaticTimeStampForTests(),
      /* deviceId */ -1);
  EXPECT_EQ("pointercancel", pointer_event->type());
  EXPECT_EQ(unique_id, pointer_event->pointerId());
  EXPECT_EQ(is_primary, pointer_event->isPrimary());
  EXPECT_EQ(
      PointerEventFactory::PointerTypeNameForWebPointPointerType(pointer_type),
      pointer_event->pointerType());
  EXPECT_EQ(WebInputEvent::GetStaticTimeStampForTests(),
            pointer_event->PlatformTimeStamp());

  return pointer_event;
}

void PointerEventFactoryTest::CreateAndCheckPointerTransitionEvent(
    PointerEvent* pointer_event,
    const AtomicString& type) {
  PointerEvent* clone_pointer_event =
      pointer_event_factory_.CreatePointerBoundaryEvent(pointer_event, type,
                                                        nullptr);
  EXPECT_EQ(clone_pointer_event->pointerType(), pointer_event->pointerType());
  EXPECT_EQ(clone_pointer_event->pointerId(), pointer_event->pointerId());
  EXPECT_EQ(clone_pointer_event->isPrimary(), pointer_event->isPrimary());
  EXPECT_EQ(clone_pointer_event->type(), type);

  EXPECT_EQ(clone_pointer_event->ctrlKey(), pointer_event->ctrlKey());
  EXPECT_EQ(clone_pointer_event->shiftKey(), pointer_event->shiftKey());
  EXPECT_EQ(clone_pointer_event->altKey(), pointer_event->altKey());
  EXPECT_EQ(clone_pointer_event->metaKey(), pointer_event->metaKey());
}

void PointerEventFactoryTest::CheckNonHoveringPointers(
    const HashSet<int>& expected_pointers) {
  Vector<int> pointers =
      pointer_event_factory_.GetPointerIdsOfNonHoveringPointers();
  EXPECT_EQ(pointers.size(), expected_pointers.size());
  for (int p : pointers) {
    EXPECT_TRUE(base::Contains(expected_pointers, p));
  }
}

TEST_F(PointerEventFactoryTest, MousePointer) {
  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));

  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */);
  PointerEvent* pointer_event2 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */,
      WebInputEvent::kLeftButtonDown);

  CreateAndCheckPointerTransitionEvent(pointer_event1,
                                       event_type_names::kPointerout);

  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_TRUE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));

  pointer_event_factory_.Remove(pointer_event1->pointerId());

  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_TRUE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 0,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);

  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));

  pointer_event_factory_.Remove(pointer_event1->pointerId());
  pointer_event_factory_.Remove(pointer_event2->pointerId());

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 1,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 20,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 0,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */,
                                WebInputEvent::kLeftButtonDown);

  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_TRUE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));

  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kMouse, 0,
                              expected_mouse_id_, true);

  EXPECT_TRUE(pointer_event_factory_.IsActive(expected_mouse_id_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(expected_mouse_id_));
}

TEST_F(PointerEventFactoryTest, TouchPointerPrimaryRemovedWhileAnotherIsThere) {
  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Remove(pointer_event1->pointerId());

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 2,
                                mapped_id_start_ + 2, false /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                false /* hovering */);
}

TEST_F(PointerEventFactoryTest, TouchPointerReleasedAndPressedAgain) {
  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));
  EXPECT_FALSE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */);
  PointerEvent* pointer_event2 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 1, mapped_id_start_ + 1,
      false /* isprimary */, false /* hovering */);

  CreateAndCheckPointerTransitionEvent(pointer_event1,
                                       event_type_names::kPointerleave);
  CreateAndCheckPointerTransitionEvent(pointer_event2,
                                       event_type_names::kPointerenter);

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_TRUE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));
  EXPECT_TRUE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  pointer_event_factory_.Remove(pointer_event1->pointerId());
  pointer_event_factory_.Remove(pointer_event2->pointerId());

  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));
  EXPECT_FALSE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 1,
                                mapped_id_start_ + 2, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 3, false /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Clear();

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 10,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
}

TEST_F(PointerEventFactoryTest, TouchAndDrag) {
  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));

  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */);
  PointerEvent* pointer_event2 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */);

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_TRUE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));

  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerUp);

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));

  pointer_event_factory_.Remove(pointer_event1->pointerId());
  pointer_event_factory_.Remove(pointer_event2->pointerId());

  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_));
  EXPECT_FALSE(pointer_event_factory_.IsActiveButtonsState(mapped_id_start_));

  EXPECT_FALSE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_FALSE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);

  // Remove an obsolete (i.e. already removed) pointer event which should have
  // no effect.
  pointer_event_factory_.Remove(pointer_event1->pointerId());

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_TRUE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kTouch, 0,
                              mapped_id_start_ + 1, true);

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_FALSE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);

  EXPECT_TRUE(pointer_event_factory_.IsActive(mapped_id_start_ + 1));
  EXPECT_TRUE(
      pointer_event_factory_.IsActiveButtonsState(mapped_id_start_ + 1));
}

TEST_F(PointerEventFactoryTest, MouseAndTouchAndPen) {
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 0,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);
  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);

  PointerEvent* pointer_event2 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 1, mapped_id_start_ + 2,
      false /* isprimary */, false /* hovering */);
  PointerEvent* pointer_event3 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 2, mapped_id_start_ + 3,
      false /* isprimary */, false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 47213,
                                mapped_id_start_ + 4, false /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Remove(pointer_event1->pointerId());
  pointer_event_factory_.Remove(pointer_event2->pointerId());
  pointer_event_factory_.Remove(pointer_event3->pointerId());

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 100,
                                mapped_id_start_ + 5, true /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Clear();

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 0,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);
}

TEST_F(PointerEventFactoryTest, NonHoveringPointers) {
  CheckNonHoveringPointers({});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, 0,
                                expected_mouse_id_, true /* isprimary */,
                                true /* hovering */);
  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kPen, 0, mapped_id_start_,
      true /* isprimary */, true /* hovering */);
  CheckNonHoveringPointers({});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
  CheckNonHoveringPointers({mapped_id_start_});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 0,
                                mapped_id_start_ + 1, true /* isprimary */,
                                false /* hovering */);
  CheckNonHoveringPointers({mapped_id_start_, mapped_id_start_ + 1});

  pointer_event_factory_.Remove(pointer_event1->pointerId());
  CheckNonHoveringPointers({mapped_id_start_ + 1});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 1,
                                mapped_id_start_ + 2, false /* isprimary */,
                                false /* hovering */);

  CheckNonHoveringPointers({mapped_id_start_ + 1, mapped_id_start_ + 2});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, 1,
                                mapped_id_start_ + 2, false /* isprimary */,
                                true /* hovering */);

  CheckNonHoveringPointers({mapped_id_start_ + 1});

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 3, true /* isprimary */,
                                false /* hovering */);

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_ + 4, false /* isprimary */,
                                false /* hovering */);

  CheckNonHoveringPointers(
      {mapped_id_start_ + 1, mapped_id_start_ + 3, mapped_id_start_ + 4});

  pointer_event_factory_.Clear();
  CheckNonHoveringPointers({});
}

TEST_F(PointerEventFactoryTest, PenAsTouchAndMouseEvent) {
  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kPen, 0, mapped_id_start_,
      true /* isprimary */, true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 2,
                                mapped_id_start_ + 2, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_, true /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Remove(pointer_event1->pointerId());

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 3, false /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 3, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kPen, 0,
                              mapped_id_start_ + 3, false);

  pointer_event_factory_.Clear();

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 1, false /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 1,
                                mapped_id_start_, true /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kPen, 0,
                                mapped_id_start_ + 1, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kPen, 1,
                              mapped_id_start_, true);
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kPen, 0,
                              mapped_id_start_ + 1, false);
}

TEST_F(PointerEventFactoryTest, OutOfRange) {
  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kUnknown, 0, mapped_id_start_,
      true /* isprimary */, true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 1,
                                mapped_id_start_ + 1, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 2,
                                mapped_id_start_ + 2, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 0,
                                mapped_id_start_, true /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 3,
                                mapped_id_start_ + 3, false /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 2,
                                mapped_id_start_ + 2, false /* isprimary */,
                                true /* hovering */);
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kUnknown, 3,
                              mapped_id_start_ + 3, false);

  pointer_event_factory_.Remove(pointer_event1->pointerId());

  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown, 0,
                                mapped_id_start_ + 4, false /* isprimary */,
                                false /* hovering */);
  CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kUnknown,
                                std::numeric_limits<int>::max(),
                                mapped_id_start_ + 5, false /* isprimary */,
                                false /* hovering */);

  pointer_event_factory_.Clear();

  for (int i = 0; i < 100; ++i) {
    CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kTouch, i,
                                  mapped_id_start_ + i, i == 0 /* isprimary */,
                                  true /* hovering */);
  }

  for (int i = 0; i < 100; ++i) {
    CreateAndCheckWebPointerEvent(WebPointerProperties::PointerType::kMouse, i,
                                  expected_mouse_id_, true /* isprimary */,
                                  false /* hovering */);
  }
  CreateAndCheckPointerCancel(WebPointerProperties::PointerType::kMouse, 0,
                              expected_mouse_id_, true);

  EXPECT_EQ(pointer_event_factory_.IsActive(0), false);
  EXPECT_EQ(pointer_event_factory_.IsActive(-1), false);
  EXPECT_EQ(
      pointer_event_factory_.IsActive(std::numeric_limits<PointerId>::max()),
      false);
}

TEST_F(PointerEventFactoryTest, LastPointerPosition) {
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerMove,
      WebPointerProperties::Button::kNoButton, 4);
  pointer_event_factory_.RemoveLastPosition(expected_mouse_id_);
  EXPECT_EQ(
      pointer_event_factory_.GetLastPointerPosition(
          expected_mouse_id_,
          WebPointerProperties(1, WebPointerProperties::PointerType::kUnknown,
                               WebPointerProperties::Button::kNoButton,
                               gfx::PointF(50, 50), gfx::PointF(20, 20)),
          WebInputEvent::Type::kPointerMove),
      gfx::PointF(20, 20));
}

TEST_F(PointerEventFactoryTest, CoalescedEvents) {
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerMove,
      WebPointerProperties::Button::kNoButton, 4);
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerMove,
      WebPointerProperties::Button::kNoButton, 3);
}

TEST_F(PointerEventFactoryTest, PredictedEvents) {
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerMove,
      WebPointerProperties::Button::kNoButton, 0 /* coalesced_count */,
      4 /* predicted_count */);
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerMove,
      WebPointerProperties::Button::kNoButton, 0 /* coalesced_count */,
      3 /* predicted_count */);

  // Check predicted_event_count when type != kPointerMove
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerDown,
      WebPointerProperties::Button::kNoButton, 0 /* coalesced_count */,
      4 /* predicted_count */);
  CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kTouch, 0, mapped_id_start_,
      true /* isprimary */, false /* hovering */, WebInputEvent::kNoModifiers,
      WebInputEvent::Type::kPointerUp, WebPointerProperties::Button::kNoButton,
      0 /* coalesced_count */, 3 /* predicted_count */);
}

TEST_F(PointerEventFactoryTest, MousePointerKeyStates) {
  WebInputEvent::Modifiers modifiers = static_cast<WebInputEvent::Modifiers>(
      WebInputEvent::kControlKey | WebInputEvent::kMetaKey);

  PointerEvent* pointer_event1 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, modifiers,
      WebInputEvent::Type::kPointerMove);

  CreateAndCheckPointerTransitionEvent(pointer_event1,
                                       event_type_names::kPointerout);

  modifiers = static_cast<WebInputEvent::Modifiers>(WebInputEvent::kAltKey |
                                                    WebInputEvent::kShiftKey);
  PointerEvent* pointer_event2 = CreateAndCheckWebPointerEvent(
      WebPointerProperties::PointerType::kMouse, 0, expected_mouse_id_,
      true /* isprimary */, true /* hovering */, modifiers,
      WebInputEvent::Type::kPointerMove);

  CreateAndCheckPointerTransitionEvent(pointer_event2,
                                       event_type_names::kPointerover);
}

class PointerEventFactoryDeviceIdTest : public SimTest {
 protected:
  PointerEventFactoryDeviceIdTest() {
    feature_list_.InitAndEnableFeature(features::kPointerEventDeviceId);
  }
  PointerEvent* CreatePointerEvent(
      WebPointerProperties::PointerType pointer_type,
      int raw_id,
      int32_t device_id) {
    WebPointerEvent web_pointer_event;
    web_pointer_event.pointer_type = pointer_type;
    web_pointer_event.id = raw_id;
    web_pointer_event.SetType(WebInputEvent::Type::kPointerDown);
    web_pointer_event.SetTimeStamp(WebInputEvent::GetStaticTimeStampForTests());
    web_pointer_event.SetModifiers(WebInputEvent::kNoModifiers);
    web_pointer_event.force = 1.0;
    web_pointer_event.hovering = false;
    web_pointer_event.button = WebPointerProperties::Button::kNoButton;
    web_pointer_event.SetPositionInScreen(100, 100);
    web_pointer_event.device_id = device_id;
    Vector<WebPointerEvent> coalesced_events;
    Vector<WebPointerEvent> predicted_events;

    LocalDOMWindow* window = GetDocument().domWindow();
    return pointer_event_factory_.Create(web_poin
```