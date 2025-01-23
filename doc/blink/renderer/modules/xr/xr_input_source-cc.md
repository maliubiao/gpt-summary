Response:
Let's break down the thought process for analyzing this C++ code and generating the summary.

**1. Initial Skim and Keyword Recognition:**

The first step is a quick scan of the code, looking for familiar keywords and structures. Things like `#include`, `namespace`, `class`, `public`, `private`, `static`, `const`, and the names of the included headers jump out. This gives an initial sense of the code's structure and purpose. The inclusion of headers like `<v8_xr_handedness.h>`, `<v8_xr_target_ray_mode.h>`, `XRHand.h`, `XRInputSourceEvent.h`, `XRSession.h`, and `XRSpace.h` strongly suggests this code is related to WebXR and handling input devices.

**2. Identifying the Core Class:**

The name of the file, `xr_input_source.cc`, and the presence of the `XRInputSource` class declaration make it clear that this is the central component. The goal is to understand what this class *does*.

**3. Analyzing Public Methods (the Interface):**

The public methods define how other parts of the Chromium engine interact with `XRInputSource`. Focusing on these provides a high-level understanding of its capabilities:

* `CreateOrUpdateFrom`:  This suggests the class manages the creation and modification of `XRInputSource` objects based on external data.
* Constructors:  How are `XRInputSource` objects created?  The different constructors indicate different initialization scenarios.
* `handedness()`, `targetRayMode()`, `targetRaySpace()`, `gripSpace()`: These are clearly accessors for properties related to the input source's tracking and interaction. The return types (`V8XRHandedness`, `V8XRTargetRayMode`, `XRSpace*`) link this code to the JavaScript WebXR API.
* `InvalidatesSameObject()`:  This is crucial for optimization and object reuse. It determines if an existing object can be updated or if a new one needs to be created.
* `SetInputFromPointer()`, `SetGamepadConnected()`, `UpdateGamepad()`, `UpdateHand()`: These methods indicate the class receives and processes data about the input device's state (position, buttons, hand tracking).
* `OnSelectStart()`, `OnSelectEnd()`, `OnSelect()`, `OnSqueezeStart()`, `OnSqueezeEnd()`, `OnSqueeze()`: These are event handlers, indicating that `XRInputSource` is responsible for dispatching events related to user interaction with the input source.
* `UpdateButtonStates()`, `ProcessOverlayHitTest()`:  These methods deal with more complex logic related to handling input events, especially in the context of DOM overlays.
* `OnRemoved()`: What happens when an input source is no longer active?

**4. Examining Private Members (Implementation Details):**

The private members reveal the internal state and dependencies of the `XRInputSource` class:

* `InternalState`:  A nested struct holding basic identification and state information.
* Pointers to `XRSession`, `XRTargetRaySpace`, `XRGripSpace`, `Gamepad`, `XRHand`:  These represent relationships with other key WebXR components.
* `mojo_from_input_`, `input_from_pointer_`:  Transforms likely related to coordinate systems.
* `profiles_`:  Information about the input device's capabilities.

**5. Tracing Data Flow and Logic:**

Once the methods and members are identified, the next step is to understand how data flows through the class and what logic is applied:

* **Creation/Update:** `CreateOrUpdateFrom` takes a `device::mojom::blink::XRInputSourceStatePtr` as input. This is likely data coming from the browser process or the underlying XR hardware. The method updates the internal state of the `XRInputSource` based on this data.
* **Space Management:**  The `targetRaySpace()` and `gripSpace()` methods return `XRSpace` objects, which are fundamental to positioning and orientation in WebXR. The logic within `gripSpace()` shows conditional return based on `targetRayMode`.
* **Event Dispatching:** The `OnSelect*` and `OnSqueeze*` methods create `XRInputSourceEvent` objects and dispatch them using the `session_->DispatchEvent()` mechanism. This is the core mechanism for informing web pages about user input.
* **Overlay Handling:** `ProcessOverlayHitTest` has specific logic for dealing with DOM overlays and potential interactions with cross-origin iframes. This involves hit testing and potentially suppressing events.

**6. Connecting to Web Technologies (JavaScript, HTML, CSS):**

With a solid understanding of the C++ code, the next step is to connect it to the web developer's perspective:

* **JavaScript API:**  The return types of methods like `handedness()` and `targetRayMode()` directly correspond to the properties of the `XRInputSource` object in the WebXR Device API in JavaScript. The dispatched events (`selectstart`, `selectend`, `select`, `squeezestart`, `squeezeend`, `squeeze`) are the events that web developers listen for.
* **HTML:** The `ProcessOverlayHitTest` method directly interacts with the DOM (Document Object Model), specifically `Element` and `HTMLFrameElementBase`. This shows how the input processing interacts with the structure of the web page.
* **CSS:** While not directly manipulated in this code, the positioning and rendering of 3D content influenced by the input source's transformations and events could be styled with CSS.

**7. Identifying Potential Issues (User/Programming Errors):**

Consider common mistakes developers might make when working with WebXR input:

* **Assuming Input Source Availability:**  Not checking if an input source exists before trying to access its properties.
* **Incorrect Event Handling:**  Not properly listening for and handling the various input events.
* **Misunderstanding Coordinate Systems:**  Not correctly converting between different coordinate spaces.
* **Overlay Interaction Issues:**  Not accounting for the behavior of DOM overlays and potential event suppression.

**8. Tracing User Actions (Debugging):**

Think about the sequence of user actions that would lead to this code being executed:

1. The user enters a WebXR session.
2. The XR hardware detects an input source (e.g., a controller).
3. The browser receives information about the input source's state (position, button presses).
4. This information is passed to the `XRInputSource::CreateOrUpdateFrom` method.
5. User interaction (e.g., pressing a button) triggers calls to `OnSelect*` or `OnSqueeze*`.
6. If a DOM overlay is present, `ProcessOverlayHitTest` might be called.

**9. Structuring the Output:**

Finally, organize the gathered information into a clear and understandable summary, using headings, bullet points, and examples to illustrate the key points. Include the requested sections on functionality, relationships with web technologies, logical reasoning (with examples), common errors, and debugging. Use clear and concise language, avoiding excessive technical jargon where possible. The goal is to make the information accessible to someone who might not be deeply familiar with the Chromium codebase.
好的，我们来详细分析一下 `blink/renderer/modules/xr/xr_input_source.cc` 这个 Chromium Blink 引擎的源代码文件。

**文件功能概述:**

`xr_input_source.cc` 文件定义了 `XRInputSource` 类，该类是 WebXR API 中 `XRInputSource` 接口在 Blink 渲染引擎中的实现。 `XRInputSource` 代表一个 XR 输入设备，例如 VR 控制器或手部，它允许用户与沉浸式环境进行交互。

该文件的主要功能包括：

1. **管理 XR 输入源的状态:**  维护输入源的各种状态信息，例如：
   -  `handedness` (左手、右手或无)
   -  `targetRayMode` (注视、指向或屏幕)
   -  是否可见 (`is_visible`)
   -  按钮状态 (例如，主按钮是否按下)
   -  相关的 `Gamepad` 对象 (如果存在)
   -  相关的 `XRHand` 对象 (如果存在，用于手部追踪)
   -  变换矩阵 (例如，输入源到 Mojo 坐标系的变换)

2. **创建和更新 XR 输入源:**  提供了静态方法 `CreateOrUpdateFrom`，用于基于从浏览器进程接收到的 `XRInputSourceStatePtr` 数据来创建或更新 `XRInputSource` 对象。

3. **处理输入事件:**  包含处理用户与输入源交互的逻辑，例如：
   -  `OnSelectStart`, `OnSelectEnd`, `OnSelect`: 处理选择 (通常是按钮点击) 事件。
   -  `OnSqueezeStart`, `OnSqueezeEnd`, `OnSqueeze`: 处理挤压 (通常是手柄上的握持按钮) 事件。
   -  `UpdateButtonStates`:  根据新的输入状态更新按钮状态并触发相应的事件。

4. **管理坐标空间:**  关联并提供访问与输入源相关的坐标空间：
   -  `targetRaySpace()`:  返回 `XRTargetRaySpace` 对象，表示从输入源发出的用于瞄准的光线的空间。
   -  `gripSpace()`: 返回 `XRGripSpace` 对象，表示输入设备的物理握持位置和方向的空间。

5. **处理 DOM 覆盖层 (Overlay) 的交互:**  `ProcessOverlayHitTest` 方法处理当 XR 内容覆盖在 HTML 内容之上时，输入源与覆盖层的交互。它涉及到点击测试，以确定输入是否与跨域的 iframe 交互，并根据情况抑制事件。

6. **与 JavaScript API 的桥梁:**  `XRInputSource` 类的设计和方法与 WebXR API 中的 `XRInputSource` 接口紧密对应，使得 JavaScript 代码可以通过该接口与底层的 XR 输入设备进行交互。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`XRInputSource` 类是 WebXR API 在 Blink 引擎中的核心实现之一，它直接关联到 JavaScript 中使用的 `XRInputSource` 对象。

**JavaScript:**

- 当 WebXR 会话开始时，JavaScript 代码可以通过 `XRSession.inputSources` 属性访问到一个 `XRInputSource` 对象的列表。
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.addEventListener('inputsourceschange', (event) => {
      event.added.forEach(inputSource => {
        console.log('New input source added:', inputSource);
        console.log('Handedness:', inputSource.handedness);
        console.log('Target ray mode:', inputSource.targetRayMode);
      });
    });
  });
  ```
- JavaScript 代码可以监听 `XRInputSource` 上触发的事件，例如 `selectstart`, `selectend`, `select`, `squeezestart`, `squeezeend`, `squeeze`。这些事件的处理逻辑在 `xr_input_source.cc` 中的 `OnSelect*` 和 `OnSqueeze*` 方法中实现。
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.addEventListener('inputsourceschange', (event) => {
      event.added.forEach(inputSource => {
        inputSource.addEventListener('selectstart', (event) => {
          console.log('Select start on input source:', inputSource);
        });
      });
    });
  });
  ```
- JavaScript 代码可以使用 `XRInputSource` 的 `targetRaySpace` 和 `gripSpace` 属性来获取对应的 `XRSpace` 对象，并使用 `XRSession.requestFrame()` 来获取这些空间的姿势 (位置和方向)。这允许开发者在 3D 场景中渲染与输入设备相关联的元素。
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.requestAnimationFrame(function animate(time, frame) {
      const pose = frame.getPose(inputSource.gripSpace, session.frameOfReference);
      if (pose) {
        // 使用 pose.transform 来渲染控制器模型
      }
      session.requestAnimationFrame(animate);
    });
  });
  ```

**HTML:**

- `xr_input_source.cc` 中的 `ProcessOverlayHitTest` 方法涉及到与 HTML 内容的交互。当 XR 体验与 HTML 覆盖层同时存在时，该方法会进行点击测试，判断用户的输入是否落在了 HTML 元素上。这允许 WebXR 应用与传统的 HTML UI 元素进行交互。
  - 假设有一个全屏的 WebXR 体验，并在其上覆盖了一个包含按钮的 HTML `div` 元素。当用户使用 VR 控制器点击覆盖层上的按钮时，`ProcessOverlayHitTest` 会确定点击位置是否在按钮的范围内，并将事件传递给 HTML。

**CSS:**

- 虽然 `xr_input_source.cc` 本身不直接操作 CSS，但它提供的输入信息 (例如控制器姿势、按钮状态) 可以被 JavaScript 代码用来动态地修改 CSS 样式，从而影响页面的视觉呈现。
  - 例如，当用户按下 VR 控制器上的某个按钮时，JavaScript 代码可以根据 `XRInputSource` 触发的事件，添加或移除某个 CSS 类到 HTML 元素上，从而改变元素的外观。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **`CreateOrUpdateFrom` 的输入:** 一个 `device::mojom::blink::XRInputSourceStatePtr` 对象，其中包含以下信息：
   - `source_id`: 123
   - `target_ray_mode`: `device::mojom::XRTargetRayMode::POINTING`
   - `handedness`: `device::mojom::XRHandedness::LEFT`
   - `primary_input_pressed`: true
   - `mojo_from_input`: 一个表示输入源到 Mojo 坐标系变换的 `gfx::Transform` 对象。

2. **`OnSelect` 的触发:**  用户按下了与 `XRInputSource` 关联的控制器的主要选择按钮。

3. **`ProcessOverlayHitTest` 的输入:**
   - 一个指向 HTML `Element` 的指针，代表覆盖层元素。
   - 一个 `device::mojom::blink::XRInputSourceStatePtr` 对象，包含覆盖层上的指针位置 `overlay_pointer_position`。

**假设输出:**

1. **`CreateOrUpdateFrom` 的输出:**  如果之前不存在 `source_id` 为 123 的 `XRInputSource` 对象，则创建一个新的 `XRInputSource` 对象，其 `targetRayMode` 为 `POINTING`，`handedness` 为 `LEFT`，并且内部状态 `primary_input_pressed` 为 `true`。如果已存在，则更新其状态。

2. **`OnSelect` 的输出:**
   - 触发一个类型为 `selectstart` 的 `XRInputSourceEvent`，并分发到相关的 `XRSession` 对象。
   - 如果 `selectstart` 事件没有被阻止默认行为，则触发一个类型为 `select` 的 `XRInputSourceEvent` 并分发。
   - 最后，触发一个类型为 `selectend` 的 `XRInputSourceEvent` 并分发。

3. **`ProcessOverlayHitTest` 的输出:**
   - 如果 `overlay_pointer_position` 指向的屏幕坐标经过点击测试后，命中了覆盖层中的一个非跨域 iframe 的 HTML 元素，则可能触发 `beforexrselect` 事件，并且输入源的 `is_visible` 保持为 `true`。
   - 如果命中了跨域 iframe，则输入源的 `is_visible` 可能被设置为 `false`，并且可能抑制后续的 `select` 事件。

**用户或编程常见的使用错误及举例说明:**

1. **未检查输入源是否存在:**  在 WebXR 会话中，输入源可能会动态地添加或移除。如果开发者没有正确监听 `inputsourceschange` 事件并检查输入源是否存在就直接访问其属性，可能会导致错误。
   ```javascript
   // 错误示例：假设只存在一个输入源
   navigator.xr.requestSession('immersive-vr').then(session => {
     session.requestAnimationFrame(function animate(time, frame) {
       const inputSource = session.inputSources[0]; // 如果没有输入源，这里会出错
       if (inputSource) {
         const pose = frame.getPose(inputSource.gripSpace, session.frameOfReference);
         // ...
       }
       session.requestAnimationFrame(animate);
     });
   });
   ```

2. **错误地理解事件顺序或阻止默认行为:**  WebXR 的 `select` 事件通常由 `selectstart` 和 `selectend` 包围。如果错误地阻止了 `selectstart` 的默认行为，可能会导致 `select` 事件不会触发。
   ```javascript
   navigator.xr.requestSession('immersive-vr').then(session => {
     session.addEventListener('inputsourceschange', (event) => {
       event.added.forEach(inputSource => {
         inputSource.addEventListener('selectstart', (event) => {
           event.preventDefault(); // 错误地阻止了 selectstart
         });
         inputSource.addEventListener('select', (event) => {
           console.log('Select event triggered'); // 可能不会触发
         });
       });
     });
   });
   ```

3. **在 DOM 覆盖层场景下，没有考虑跨域 iframe 的影响:**  开发者可能没有意识到当输入与跨域 iframe 交互时，WebXR 的输入事件可能会被抑制，导致交互行为不符合预期。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户正在使用一个支持 WebXR 的浏览器和一个 VR 头显和控制器。以下步骤可能导致代码执行到 `xr_input_source.cc`:

1. **用户访问一个 WebXR 页面:** 用户在浏览器中打开一个启用了 WebXR 功能的网页。
2. **页面请求 WebXR 会话:** 网页 JavaScript 代码调用 `navigator.xr.requestSession('immersive-vr')` 等方法请求一个沉浸式 VR 会话。
3. **浏览器请求 XR 设备:** 浏览器进程与底层的 XR 设备进行通信，请求开始会话。
4. **XR 设备报告输入源:**  VR 控制器被激活并被 XR 设备识别为输入源。设备将输入源的信息 (ID、类型、手部等) 发送给浏览器进程。
5. **浏览器进程传递输入源状态:** 浏览器进程将接收到的输入源状态信息封装成 `device::mojom::blink::XRInputSourceStatePtr` 对象，并通过 IPC 传递给渲染器进程。
6. **`XRInputSource::CreateOrUpdateFrom` 被调用:** 在渲染器进程中，Blink 引擎接收到输入源状态更新，并调用 `XRInputSource::CreateOrUpdateFrom` 方法来创建或更新对应的 `XRInputSource` 对象。
7. **用户与输入源交互:** 用户按下 VR 控制器上的一个按钮。
8. **XR 设备报告按钮事件:**  XR 设备检测到按钮按下，并将事件信息发送给浏览器进程。
9. **浏览器进程传递按钮状态:** 浏览器进程将更新后的输入源状态 (包括按钮状态) 传递给渲染器进程。
10. **`XRInputSource::UpdateButtonStates` 被调用:** 渲染器进程接收到更新，`UpdateButtonStates` 方法被调用，根据按钮状态的变化，可能会调用 `OnSelectStart` 或 `OnSelect` 等方法。
11. **事件分发:**  `OnSelect*` 方法会创建并分发 `XRInputSourceEvent`，这些事件会被 JavaScript 代码监听和处理。
12. **如果存在 DOM 覆盖层:** 当 XR 内容覆盖在 HTML 上时，用户使用控制器进行点击操作，可能会触发 `ProcessOverlayHitTest` 来判断点击位置和是否与跨域内容交互。

**调试线索:**

- **日志输出:**  查看 `xr_input_source.cc` 中 `DVLOG` 宏输出的日志信息，可以了解输入源状态的变化、事件的触发以及 `ProcessOverlayHitTest` 的点击测试结果。
- **断点调试:**  在 `XRInputSource` 的关键方法 (例如 `CreateOrUpdateFrom`, `OnSelect`, `ProcessOverlayHitTest`) 设置断点，可以跟踪代码执行流程，查看变量的值，理解输入事件的处理过程。
- **WebXR Device API 的事件监听:**  在 JavaScript 代码中监听 `inputsourceschange`、`selectstart`、`selectend` 等事件，可以了解输入源的添加和移除，以及用户交互事件的触发情况。
- **检查 `XRFrame` 获取的姿势信息:**  在 `requestAnimationFrame` 回调中，检查通过 `frame.getPose()` 获取的 `XRInputSource` 姿势信息，可以帮助理解输入源的跟踪是否正常。
- **分析 IPC 消息:**  使用 Chromium 的调试工具 (例如 `chrome://inspect/#devices`) 可以查看浏览器进程和渲染器进程之间的 IPC 消息，了解输入源状态是如何传递的。

希望以上分析能够帮助你理解 `blink/renderer/modules/xr/xr_input_source.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_input_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_input_source.h"

#include "base/time/time.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_handedness.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_target_ray_mode.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/modules/xr/xr_grip_space.h"
#include "third_party/blink/renderer/modules/xr/xr_hand.h"
#include "third_party/blink/renderer/modules/xr/xr_input_source_event.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_session_event.h"
#include "third_party/blink/renderer/modules/xr/xr_space.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/modules/xr/xr_target_ray_space.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"

namespace blink {

namespace {
std::unique_ptr<gfx::Transform> TryGetTransform(
    const std::optional<gfx::Transform>& transform) {
  if (transform) {
    return std::make_unique<gfx::Transform>(*transform);
  }

  return nullptr;
}

std::unique_ptr<gfx::Transform> TryGetTransform(const gfx::Transform* other) {
  if (other) {
    return std::make_unique<gfx::Transform>(*other);
  }

  return nullptr;
}
}  // namespace

XRInputSource::InternalState::InternalState(
    uint32_t source_id,
    device::mojom::XRTargetRayMode target_ray_mode,
    base::TimeTicks base_timestamp)
    : source_id(source_id),
      target_ray_mode(target_ray_mode),
      base_timestamp(base_timestamp) {}

XRInputSource::InternalState::InternalState(const InternalState& other) =
    default;

XRInputSource::InternalState::~InternalState() = default;

// static
XRInputSource* XRInputSource::CreateOrUpdateFrom(
    XRInputSource* other,
    XRSession* session,
    const device::mojom::blink::XRInputSourceStatePtr& state) {
  if (!state)
    return other;

  XRInputSource* updated_source = other;

  // Check if we have an existing object, and if we do, if it can be re-used.
  if (!other) {
    auto source_id = state->source_id;
    updated_source = MakeGarbageCollected<XRInputSource>(session, source_id);
  } else if (other->InvalidatesSameObject(state)) {
    // Something in the state has changed which requires us to re-create the
    // object.  Create a copy now, and we will blindly update any state later,
    // knowing that we now have a new object if needed.
    updated_source = MakeGarbageCollected<XRInputSource>(*other);
  }

  if (updated_source->state_.is_visible) {
    updated_source->UpdateGamepad(state->gamepad);
  }

  // Update the input source's description if this state update includes them.
  if (state->description) {
    const device::mojom::blink::XRInputSourceDescriptionPtr& desc =
        state->description;

    updated_source->state_.target_ray_mode = desc->target_ray_mode;
    updated_source->state_.handedness = desc->handedness;

    if (updated_source->state_.is_visible) {
      updated_source->input_from_pointer_ =
          TryGetTransform(desc->input_from_pointer);
    }

    updated_source->profiles_ = MakeGarbageCollected<FrozenArray<IDLString>>(
        state->description->profiles);
  }

  if (updated_source->state_.is_visible) {
    updated_source->mojo_from_input_ = TryGetTransform(state->mojo_from_input);
  }

  if (updated_source->state_.is_visible) {
    updated_source->UpdateHand(state->hand_tracking_data.get());
  }

  updated_source->state_.emulated_position = state->emulated_position;

  return updated_source;
}

XRInputSource::XRInputSource(XRSession* session,
                             uint32_t source_id,
                             device::mojom::XRTargetRayMode target_ray_mode)
    : state_(source_id, target_ray_mode, session->xr()->NavigationStart()),
      session_(session),
      target_ray_space_(MakeGarbageCollected<XRTargetRaySpace>(session, this)),
      grip_space_(MakeGarbageCollected<XRGripSpace>(session, this)),
      profiles_(MakeGarbageCollected<FrozenArray<IDLString>>()) {}

// Must make new target_ray_space_ and grip_space_ to ensure that they point to
// the correct XRInputSource object. Otherwise, the controller position gets
// stuck when an XRInputSource gets re-created. Also need to make a deep copy of
// the matrices since they use unique_ptrs.
XRInputSource::XRInputSource(const XRInputSource& other)
    : state_(other.state_),
      session_(other.session_),
      target_ray_space_(
          MakeGarbageCollected<XRTargetRaySpace>(other.session_, this)),
      grip_space_(MakeGarbageCollected<XRGripSpace>(other.session_, this)),
      gamepad_(other.gamepad_),
      hand_(other.hand_),
      profiles_(MakeGarbageCollected<FrozenArray<IDLString>>(
          other.profiles_->AsVector())),
      mojo_from_input_(TryGetTransform(other.mojo_from_input_.get())),
      input_from_pointer_(TryGetTransform(other.input_from_pointer_.get())) {}

V8XRHandedness XRInputSource::handedness() const {
  switch (state_.handedness) {
    case device::mojom::XRHandedness::NONE:
      return V8XRHandedness(V8XRHandedness::Enum::kNone);
    case device::mojom::XRHandedness::LEFT:
      return V8XRHandedness(V8XRHandedness::Enum::kLeft);
    case device::mojom::XRHandedness::RIGHT:
      return V8XRHandedness(V8XRHandedness::Enum::kRight);
  }

  NOTREACHED();
}

V8XRTargetRayMode XRInputSource::targetRayMode() const {
  switch (state_.target_ray_mode) {
    case device::mojom::XRTargetRayMode::GAZING:
      return V8XRTargetRayMode(V8XRTargetRayMode::Enum::kGaze);
    case device::mojom::XRTargetRayMode::POINTING:
      return V8XRTargetRayMode(V8XRTargetRayMode::Enum::kTrackedPointer);
    case device::mojom::XRTargetRayMode::TAPPING:
      return V8XRTargetRayMode(V8XRTargetRayMode::Enum::kScreen);
  }
  NOTREACHED();
}

XRSpace* XRInputSource::targetRaySpace() const {
  return target_ray_space_.Get();
}

XRSpace* XRInputSource::gripSpace() const {
  if (!state_.is_visible)
    return nullptr;

  if (state_.target_ray_mode == device::mojom::XRTargetRayMode::POINTING) {
    return grip_space_.Get();
  }

  return nullptr;
}

bool XRInputSource::InvalidatesSameObject(
    const device::mojom::blink::XRInputSourceStatePtr& state) {
  if ((state->gamepad && !gamepad_) || (!state->gamepad && gamepad_)) {
    return true;
  }

  if (state->description) {
    if (state->description->handedness != state_.handedness) {
      return true;
    }

    if (state->description->target_ray_mode != state_.target_ray_mode) {
      return true;
    }

    if (state->description->profiles.size() != profiles_->size()) {
      return true;
    }

    for (wtf_size_t i = 0; i < profiles_->size(); ++i) {
      if (state->description->profiles[i] != (*profiles_)[i]) {
        return true;
      }
    }
  }

  if ((state->hand_tracking_data.get() && !hand_) ||
      (!state->hand_tracking_data.get() && hand_)) {
    return true;
  }

  return false;
}

void XRInputSource::SetInputFromPointer(
    const gfx::Transform* input_from_pointer) {
  if (state_.is_visible) {
    input_from_pointer_ = TryGetTransform(input_from_pointer);
  }
}

void XRInputSource::SetGamepadConnected(bool state) {
  if (gamepad_)
    gamepad_->SetConnected(state);
}

void XRInputSource::UpdateGamepad(
    const std::optional<device::Gamepad>& gamepad) {
  if (gamepad) {
    if (!gamepad_) {
      gamepad_ = MakeGarbageCollected<Gamepad>(this, -1, state_.base_timestamp,
                                               base::TimeTicks::Now());
    }

    LocalDOMWindow* window = session_->xr()->DomWindow();
    bool cross_origin_isolated_capability =
        window ? window->CrossOriginIsolatedCapability() : false;
    gamepad_->UpdateFromDeviceState(*gamepad, cross_origin_isolated_capability);
  } else {
    gamepad_ = nullptr;
  }
}

void XRInputSource::UpdateHand(
    const device::mojom::blink::XRHandTrackingData* hand_tracking_data) {
  if (hand_tracking_data) {
    if (!hand_) {
      hand_ = MakeGarbageCollected<XRHand>(hand_tracking_data, this);
    } else {
      hand_->updateFromHandTrackingData(hand_tracking_data, this);
    }
  } else {
    hand_ = nullptr;
  }
}

std::optional<gfx::Transform> XRInputSource::MojoFromInput() const {
  if (!mojo_from_input_.get()) {
    return std::nullopt;
  }
  return *(mojo_from_input_.get());
}

std::optional<gfx::Transform> XRInputSource::InputFromPointer() const {
  if (!input_from_pointer_.get()) {
    return std::nullopt;
  }
  return *(input_from_pointer_.get());
}

void XRInputSource::OnSelectStart() {
  DVLOG(3) << __func__;
  // Discard duplicate events and ones after the session has ended.
  if (state_.primary_input_pressed || session_->ended())
    return;

  state_.primary_input_pressed = true;
  state_.selection_cancelled = false;

  DVLOG(3) << __func__ << ": dispatch selectstart event";
  XRInputSourceEvent* event =
      CreateInputSourceEvent(event_type_names::kSelectstart);
  session_->DispatchEvent(*event);

  if (event->defaultPrevented())
    state_.selection_cancelled = true;

  // Ensure the frame cannot be used outside of the event handler.
  event->frame()->Deactivate();
}

void XRInputSource::OnSelectEnd() {
  DVLOG(3) << __func__;
  // Discard duplicate events and ones after the session has ended.
  if (!state_.primary_input_pressed || session_->ended())
    return;

  state_.primary_input_pressed = false;

  if (!session_->xr()->DomWindow())
    return;

  DVLOG(3) << __func__ << ": dispatch selectend event";
  XRInputSourceEvent* event =
      CreateInputSourceEvent(event_type_names::kSelectend);
  session_->DispatchEvent(*event);

  if (event->defaultPrevented())
    state_.selection_cancelled = true;

  // Ensure the frame cannot be used outside of the event handler.
  event->frame()->Deactivate();
}

void XRInputSource::OnSelect() {
  DVLOG(3) << __func__;
  // If a select was fired but we had not previously started the selection it
  // indicates a sub-frame or instantaneous select event, and we should fire a
  // selectstart prior to the selectend.
  if (!state_.primary_input_pressed) {
    OnSelectStart();
  }

  // If SelectStart caused the session to end, we shouldn't try to fire the
  // select event.
  LocalDOMWindow* window = session_->xr()->DomWindow();
  if (!window)
    return;
  LocalFrame::NotifyUserActivation(
      window->GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);

  if (!state_.selection_cancelled && !session_->ended()) {
    DVLOG(3) << __func__ << ": dispatch select event";
    XRInputSourceEvent* event =
        CreateInputSourceEvent(event_type_names::kSelect);
    session_->DispatchEvent(*event);

    // Ensure the frame cannot be used outside of the event handler.
    event->frame()->Deactivate();
  }

  OnSelectEnd();
}

void XRInputSource::OnSqueezeStart() {
  DVLOG(3) << __func__;
  // Discard duplicate events and ones after the session has ended.
  if (state_.primary_squeeze_pressed || session_->ended())
    return;

  state_.primary_squeeze_pressed = true;
  state_.squeezing_cancelled = false;

  XRInputSourceEvent* event =
      CreateInputSourceEvent(event_type_names::kSqueezestart);
  session_->DispatchEvent(*event);

  if (event->defaultPrevented())
    state_.squeezing_cancelled = true;

  // Ensure the frame cannot be used outside of the event handler.
  event->frame()->Deactivate();
}

void XRInputSource::OnSqueezeEnd() {
  DVLOG(3) << __func__;
  // Discard duplicate events and ones after the session has ended.
  if (!state_.primary_squeeze_pressed || session_->ended())
    return;

  state_.primary_squeeze_pressed = false;

  if (!session_->xr()->DomWindow())
    return;

  DVLOG(3) << __func__ << ": dispatch squeezeend event";
  XRInputSourceEvent* event =
      CreateInputSourceEvent(event_type_names::kSqueezeend);
  session_->DispatchEvent(*event);

  if (event->defaultPrevented())
    state_.squeezing_cancelled = true;

  // Ensure the frame cannot be used outside of the event handler.
  event->frame()->Deactivate();
}

void XRInputSource::OnSqueeze() {
  DVLOG(3) << __func__;
  // If a squeeze was fired but we had not previously started the squeezing it
  // indicates a sub-frame or instantaneous squeeze event, and we should fire a
  // squeezestart prior to the squeezeend.
  if (!state_.primary_squeeze_pressed) {
    OnSqueezeStart();
  }

  // If SelectStart caused the session to end, we shouldn't try to fire the
  // select event.
  LocalDOMWindow* window = session_->xr()->DomWindow();
  if (!window)
    return;
  LocalFrame::NotifyUserActivation(
      window->GetFrame(),
      mojom::blink::UserActivationNotificationType::kInteraction);

  // If SelectStart caused the session to end, we shouldn't try to fire the
  // select event.
  if (!state_.squeezing_cancelled && !session_->ended()) {
    DVLOG(3) << __func__ << ": dispatch squeeze event";
    XRInputSourceEvent* event =
        CreateInputSourceEvent(event_type_names::kSqueeze);
    session_->DispatchEvent(*event);

    // Ensure the frame cannot be used outside of the event handler.
    event->frame()->Deactivate();
  }

  OnSqueezeEnd();
}

void XRInputSource::UpdateButtonStates(
    const device::mojom::blink::XRInputSourceStatePtr& new_state) {
  if (!new_state)
    return;

  DVLOG(3) << __func__ << ": state_.is_visible=" << state_.is_visible
           << ", state_.xr_select_events_suppressed="
           << state_.xr_select_events_suppressed
           << ", new_state->primary_input_clicked="
           << new_state->primary_input_clicked;

  if (!state_.is_visible) {
    DVLOG(3) << __func__ << ": input NOT VISIBLE";
    if (new_state->primary_input_clicked) {
      DVLOG(3) << __func__ << ": got click while invisible, SUPPRESS end";
      state_.xr_select_events_suppressed = false;
    }
    return;
  }
  if (state_.xr_select_events_suppressed) {
    if (new_state->primary_input_clicked) {
      DVLOG(3) << __func__ << ": got click, SUPPRESS end";
      state_.xr_select_events_suppressed = false;
    }
    DVLOG(3) << __func__ << ": overlay input select SUPPRESSED";
    return;
  }

  DCHECK(!state_.xr_select_events_suppressed);

  // Handle state change of the primary input, which may fire events
  if (new_state->primary_input_clicked)
    OnSelect();

  if (new_state->primary_input_pressed) {
    OnSelectStart();
  } else if (state_.primary_input_pressed) {
    // May get here if the input source was previously pressed but now isn't,
    // but the input source did not set primary_input_clicked to true. We will
    // treat this as a cancelled selection, firing the selectend event so the
    // page stays in sync with the controller state but won't fire the
    // usual select event.
    OnSelectEnd();
  }

  // Handle state change of the primary input, which may fire events
  if (new_state->primary_squeeze_clicked)
    OnSqueeze();

  if (new_state->primary_squeeze_pressed) {
    OnSqueezeStart();
  } else if (state_.primary_squeeze_pressed) {
    // May get here if the input source was previously pressed but now isn't,
    // but the input source did not set primary_squeeze_clicked to true. We will
    // treat this as a cancelled squeezeing, firing the squeezeend event so the
    // page stays in sync with the controller state but won't fire the
    // usual squeeze event.
    OnSqueezeEnd();
  }
}

void XRInputSource::ProcessOverlayHitTest(
    Element* overlay_element,
    const device::mojom::blink::XRInputSourceStatePtr& new_state) {
  DVLOG(3) << __func__ << ": state_.xr_select_events_suppressed="
           << state_.xr_select_events_suppressed;

  DCHECK(overlay_element);
  DCHECK(new_state->overlay_pointer_position);

  // Do a hit test at the overlay pointer position to see if the pointer
  // intersects a cross origin iframe. If yes, set the visibility to false which
  // causes targetRaySpace and gripSpace to return null poses.
  gfx::PointF point(new_state->overlay_pointer_position->x(),
                    new_state->overlay_pointer_position->y());
  DVLOG(3) << __func__ << ": hit test point=" << point.ToString();

  HitTestRequest::HitTestRequestType hit_type = HitTestRequest::kTouchEvent |
                                                HitTestRequest::kReadOnly |
                                                HitTestRequest::kActive;

  HitTestResult result = event_handling_util::HitTestResultInFrame(
      overlay_element->GetDocument().GetFrame(), HitTestLocation(point),
      hit_type);
  DVLOG(3) << __func__ << ": hit test InnerElement=" << result.InnerElement();

  Element* hit_element = result.InnerElement();
  if (!hit_element) {
    return;
  }

  // Check if the hit element is cross-origin content. In addition to an iframe,
  // this could potentially be an old-style frame in a frameset, so check for
  // the common base class to cover both. (There's no intention to actively
  // support framesets for DOM Overlay, but this helps prevent them from
  // being used as a mechanism for information leaks.)
  HTMLFrameElementBase* frame = DynamicTo<HTMLFrameElementBase>(hit_element);
  if (frame) {
    Document* hit_document = frame->contentDocument();
    if (hit_document) {
      Frame* hit_frame = hit_document->GetFrame();
      DCHECK(hit_frame);
      if (hit_frame->IsCrossOriginToOutermostMainFrame()) {
        // Mark the input source as invisible until the primary button is
        // released.
        state_.is_visible = false;

        // If this is the first touch, also suppress events, even if it
        // ends up being released outside the frame later.
        if (!state_.primary_input_pressed) {
          state_.xr_select_events_suppressed = true;
        }

        DVLOG(3)
            << __func__
            << ": input source overlaps with cross origin content, is_visible="
            << state_.is_visible << ", xr_select_events_suppressed="
            << state_.xr_select_events_suppressed;
        return;
      }
    }
  }

  // If we get here, the touch didn't hit a cross origin frame. Set the
  // controller spaces visible.
  state_.is_visible = true;

  // Now that the visibility check has finished, mark non-primary input sources
  // as suppressed.
  if (new_state->is_auxiliary) {
    state_.xr_select_events_suppressed = true;
  }

  // Now check if this is a new primary button press. If yes, send a
  // beforexrselect event to give the application an opportunity to cancel the
  // XR input "select" sequence that would normally be caused by this.

  if (state_.xr_select_events_suppressed) {
    DVLOG(3) << __func__ << ": using overlay input provider: SUPPRESS ongoing";
    return;
  }

  if (state_.primary_input_pressed) {
    DVLOG(3) << __func__ << ": ongoing press, not checking again";
    return;
  }

  bool is_primary_press =
      new_state->primary_input_pressed || new_state->primary_input_clicked;
  if (!is_primary_press) {
    DVLOG(3) << __func__ << ": no button press, ignoring";
    return;
  }

  // The event needs to be cancelable (obviously), bubble (so that parent
  // elements can handle it), and composed (so that it crosses shadow DOM
  // boundaries, including UA-added shadow DOM).
  Event* event = MakeGarbageCollected<XRSessionEvent>(
      event_type_names::kBeforexrselect, session_, Event::Bubbles::kYes,
      Event::Cancelable::kYes, Event::ComposedMode::kComposed);

  hit_element->DispatchEvent(*event);
  bool default_prevented = event->defaultPrevented();

  // Keep the input source visible, so it's exposed in the input sources array,
  // but don't generate XR select events for the current button sequence.
  state_.xr_select_events_suppressed = default_prevented;
  DVLOG(3) << __func__ << ": state_.xr_select_events_suppressed="
           << state_.xr_select_events_suppressed;
}

void XRInputSource::OnRemoved() {
  if (state_.primary_input_pressed) {
    state_.primary_input_pressed = false;

    XRInputSourceEvent* event =
        CreateInputSourceEvent(event_type_names::kSelectend);
    session_->DispatchEvent(*event);

    if (event->defaultPrevented())
      state_.selection_cancelled = true;

    // Ensure the frame cannot be used outside of the event handler.
    event->frame()->Deactivate();
  }

  if (state_.primary_squeeze_pressed) {
    state_.primary_squeeze_pressed = false;

    XRInputSourceEvent* event =
        CreateInputSourceEvent(event_type_names::kSqueezeend);
    session_->DispatchEvent(*event);

    if (event->defaultPrevented())
      state_.squeezing_cancelled = true;

    // Ensure the frame cannot be used outside of the event handler.
    event->frame()->Deactivate();
  }

  SetGamepadConnected(false);
}

XRInputSourceEvent* XRInputSource::CreateInputSourceEvent(
    const AtomicString& type) {
  XRFrame* presentation_frame = session_->CreatePresentationFrame();
  return XRInputSourceEvent::Create(type, presentation_frame, this);
}

void XRInputSource::Trace(Visitor* visitor) const {
  visitor->Trace(session_);
  visitor->Trace(target_ray_space_);
  visitor->Trace(grip_space_);
  visitor->Trace(gamepad_);
  visitor->Trace(hand_);
  visitor->Trace(profiles_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```