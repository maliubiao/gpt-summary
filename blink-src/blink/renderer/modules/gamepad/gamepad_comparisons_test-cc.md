Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `gamepad_comparisons_test.cc` and the inclusion of `gamepad_comparisons.h` immediately suggest the file is testing the functionality of gamepad comparisons within the Blink rendering engine. The `testing::Test` inheritance confirms this is a unit test.

2. **Examine the Includes:**
    * `third_party/blink/renderer/modules/gamepad/gamepad_comparisons.h`:  This is the target of the test – the code being validated.
    * `base/test/task_environment.h`: Indicates the tests might involve asynchronous operations or need a simulated environment.
    * `device/gamepad/public/cpp/gamepad.h`: Shows the test interacts with the underlying device-level gamepad representation.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms the use of the Google Test framework.
    * `third_party/blink/renderer/modules/gamepad/gamepad.h`:  Suggests interaction with the Blink's `Gamepad` object.
    * `third_party/blink/renderer/platform/testing/main_thread_isolate.h`:  Implies the tests might need to be aware of the main thread context in Blink.

3. **Analyze the `GamepadComparisonsTest` Class:**
    * **Setup Methods (`InitGamepadQuaternion`, `InitGamepadVector`):** These initialize internal `device::GamepadQuaternion` and `device::GamepadVector` structs, likely for setting up specific test conditions related to device input. They are not directly involved in the *comparison* logic but provide data for the `Gamepad` objects being compared.
    * **`CreateGamepad()`:**  This is a factory method for creating `Gamepad` objects. The arguments (`nullptr`, `0`, `dummy_time_origin`, `dummy_time_floor`) are important for understanding how test gamepads are constructed (though the specific values here aren't the core focus of *comparison*). The use of `MakeGarbageCollected` hints at Blink's memory management.
    * **`CreateEmptyGamepadList()`, `CreateGamepadListWith...()` methods:** These are crucial for setting up different test scenarios. They create `HeapVector<Member<Gamepad>>` objects, representing different gamepad states (neutral, tilted axis, button pressed, touch events, etc.). The specific values assigned to `axes`, `buttons`, and `touch` members within these methods are the *inputs* for the comparison logic being tested.
    * **Private Members (`task_environment_`, `isolate_`):**  These are standard boilerplate for Blink tests, as hinted at by the includes. They're necessary for setting up the testing environment.

4. **Examine the `TEST_F` Functions:** Each `TEST_F` is an individual test case. The naming convention is highly informative:
    * **Focus on Functionality:** Test names clearly describe what aspect of `GamepadComparisons` is being tested (e.g., `EmptyListCausesNoActivation`, `CompareNeutrals`, `CompareNeutralWithAxisTilt`).
    * **Input Variations:**  Different `CreateGamepadListWith...()` methods are used to provide varied input states to the `GamepadComparisons::Compare()` function.
    * **Assertions:** `EXPECT_TRUE` and `EXPECT_FALSE` are used to verify the *outputs* of the `GamepadComparisons::Compare()` function based on the input states. The specific assertions (`IsDifferent()`, `IsGamepadConnected()`, `IsAxisChanged()`, etc.) tell us what aspects of the comparison result are being checked.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `Gamepad` API in JavaScript allows web pages to access gamepad data. This C++ code *implements the underlying logic* that the JavaScript API interacts with. The tests verify how changes in gamepad state are detected and reported, which directly impacts how a JavaScript application would receive and interpret gamepad input.
    * **HTML:**  HTML provides the structure for web pages. Gamepad input might trigger actions on HTML elements (e.g., moving focus, triggering buttons). The accuracy of the gamepad comparison logic ensures that these interactions are correctly triggered.
    * **CSS:** While less directly related, CSS might be used to visually represent the state of gamepad-controlled elements (e.g., highlighting a button when pressed). The reliability of gamepad input, tested by this code, underpins the responsiveness of such visual feedback.

6. **Infer Logic and Assumptions:**
    * **Comparison Logic:** The tests implicitly reveal the core logic of `GamepadComparisons::Compare()`. It compares two lists of `Gamepad` objects and determines if there are differences in connection status, axis values, button states, and touch events.
    * **Activation:** The `HasUserActivation()` test suggests a concept of gamepad input contributing to "user activation" within the browser, which is relevant for security and preventing unwanted actions.
    * **Thresholds:** The `kDefaultButtonPressedThreshold` constant hints at the existence of thresholds for analog button presses.

7. **Consider User/Programming Errors:**
    * **Incorrect Comparison Flags:** The tests with `compare_all_axes=false` and `compare_all_buttons=false` highlight a potential error where a developer might not enable the necessary flags to detect specific changes.
    * **Misinterpreting Comparison Results:** A programmer might incorrectly assume a gamepad event occurred if `IsDifferent()` is true without checking the specific `IsAxisChanged()`, `IsButtonDown()`, etc., flags.
    * **Relying on Specific Order:** While not explicitly tested here,  the order of gamepads in the list might be significant, and misunderstanding this could lead to errors.

8. **Trace User Operations:**  This requires thinking about how gamepad events are generated and processed in a browser:
    1. **User Connects Gamepad:** The operating system detects the gamepad.
    2. **Browser Receives Event:** The browser's gamepad API (at the OS level) receives notification of the connection.
    3. **Blink Updates Gamepad State:** Blink's gamepad module updates its internal representation of connected gamepads.
    4. **Web Page Polls for Gamepad State:** JavaScript code on a web page uses the `navigator.getGamepads()` method.
    5. **Blink Provides Gamepad Data:** Blink provides the current gamepad state to the JavaScript code. The `GamepadComparisons` class is involved in determining if the state has *changed* since the last poll.
    6. **User Input:** The user presses a button, moves an axis, or touches the gamepad.
    7. **OS Reports Input:** The operating system reports the input event.
    8. **Blink Updates Internal State:** Blink updates the `axes`, `buttons`, or `touch` information for the corresponding `Gamepad` object.
    9. **`GamepadComparisons::Compare()` is Used:** When the web page polls again, `GamepadComparisons::Compare()` is likely used to determine if the gamepad state has changed since the last poll, allowing the browser to notify the JavaScript code of the changes.

By following these steps, a comprehensive understanding of the test file's purpose, its relation to web technologies, its underlying logic, potential errors, and the user journey can be achieved.这个C++源代码文件 `gamepad_comparisons_test.cc` 的主要功能是**测试 `blink::GamepadComparisons` 类的功能**。`GamepadComparisons` 类很可能负责比较两个 `Gamepad` 对象或列表，以确定它们之间的差异，例如：

* **连接状态的变化：**  判断手柄是否连接或断开。
* **按键状态的变化：** 判断按键是否被按下或释放。
* **轴状态的变化：** 判断摇杆或扳机的状态是否发生变化。
* **触摸事件的变化：** 判断触摸板上的触摸事件是否发生变化。
* **用户激活状态：** 判断是否存在导致用户激活的Gamepad事件。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件位于 Blink 引擎中，Blink 是 Chrome 浏览器的渲染引擎，负责将 HTML、CSS 和 JavaScript 代码转换为用户可见的网页。因此，它与这三种技术有直接关系：

1. **JavaScript:**
   * **关系：** JavaScript 通过 `Navigator.getGamepads()` API 获取连接到系统的游戏手柄信息。这个 C++ 代码中测试的 `GamepadComparisons` 类，正是为 JavaScript 提供准确的 gamepad 状态变化信息的底层实现。当 JavaScript 代码调用 `getGamepads()` 时，Blink 引擎会使用类似这里测试的逻辑来判断 gamepad 的状态是否发生了变化。
   * **举例说明：**  假设一个网页使用 JavaScript 监听 gamepad 的按键事件。
      ```javascript
      window.addEventListener("gamepadconnected", (event) => {
        console.log("Gamepad connected.");
      });

      window.addEventListener("gamepaddisconnected", (event) => {
        console.log("Gamepad disconnected.");
      });

      window.addEventListener("gamepadbuttondown", (event) => {
        console.log("Button pressed:", event.detail.index);
      });
      ```
      `gamepadconnected` 和 `gamepaddisconnected` 事件的触发，以及 `gamepadbuttondown` 事件中按键状态的判断，都依赖于 Blink 引擎中对 gamepad 状态变化的检测，而 `gamepad_comparisons_test.cc` 正是在测试这部分逻辑。

2. **HTML:**
   * **关系：** HTML 结构定义了网页的内容。游戏手柄的输入可以用来与 HTML 元素进行交互，例如控制游戏角色移动、选择菜单项等。这个 C++ 代码保证了手柄输入被正确地识别和传递，从而使得基于手柄控制的 HTML 交互能够正常工作。
   * **举例说明：** 一个简单的 HTML 按钮，可以通过 JavaScript 和 gamepad 输入进行点击：
      ```html
      <button id="myButton">Click Me</button>
      <script>
        window.addEventListener("gamepadbuttondown", (event) => {
          if (event.detail.index === 0) { // 假设按钮 0 是 "A" 键
            document.getElementById("myButton").click();
          }
        });
      </script>
      ```
      `GamepadComparisons` 的测试确保了当用户按下手柄的特定按钮时，`gamepadbuttondown` 事件能够被触发，从而使 JavaScript 代码能够执行 `myButton.click()` 操作。

3. **CSS:**
   * **关系：** CSS 负责网页的样式。游戏手柄的输入可以用来改变元素的 CSS 样式，例如当按钮被按下时改变其颜色或添加动画效果。
   * **举例说明：**  一个 CSS 样式，当按钮被按下时改变背景颜色：
      ```html
      <style>
        .button {
          background-color: lightblue;
        }
        .button.pressed {
          background-color: darkblue;
          color: white;
        }
      </style>
      <button id="myButton" class="button">Press Me</button>
      <script>
        window.addEventListener("gamepadbuttondown", (event) => {
          if (event.detail.index === 0) {
            document.getElementById("myButton").classList.add("pressed");
          }
        });

        window.addEventListener("gamepadbuttonup", (event) => {
          if (event.detail.index === 0) {
            document.getElementById("myButton").classList.remove("pressed");
          }
        });
      </script>
      ```
      `GamepadComparisons` 的正确性保证了 `gamepadbuttondown` 和 `gamepadbuttonup` 事件能够准确地反映手柄按键的状态，从而使 CSS 样式的动态改变能够正常工作。

**逻辑推理与假设输入输出：**

这个测试文件主要通过各种 `TEST_F` 函数来验证 `GamepadComparisons` 类的 `Compare` 和 `HasUserActivation` 方法。

**`HasUserActivation` 测试：**

* **假设输入：**  一个空的 gamepad 列表。
* **预期输出：** `HasUserActivation` 返回 `false`，因为没有 gamepad 事件发生。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, EmptyListCausesNoActivation) {
    auto list = CreateEmptyGamepadList();
    EXPECT_FALSE(GamepadComparisons::HasUserActivation(list));
  }
  ```

* **假设输入：**  一个 gamepad 列表，其中一个 gamepad 的摇杆有倾斜。
* **预期输出：** `HasUserActivation` 返回 `false`，因为摇杆倾斜通常不被认为是用户激活事件。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, AxisTiltCausesNoActivation) {
    auto list = CreateGamepadListWithAxisTilt();
    EXPECT_FALSE(GamepadComparisons::HasUserActivation(list));
  }
  ```

* **假设输入：**  一个 gamepad 列表，其中一个 gamepad 的按钮被按下。
* **预期输出：** `HasUserActivation` 返回 `true`，因为按下按钮通常被认为是用户激活事件。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, ButtonDownCausesActivation) {
    auto list = CreateGamepadListWithButtonDown();
    EXPECT_TRUE(GamepadComparisons::HasUserActivation(list));
  }
  ```

**`Compare` 测试：**

* **假设输入：** 两个空的 gamepad 列表。
* **预期输出：** `IsDifferent()` 返回 `false` (没有差异)，`IsGamepadConnected(0)` 返回 `false`，`IsGamepadDisconnected(0)` 返回 `false`，`IsAxisChanged(0, 0)` 返回 `false`，`IsButtonChanged(0, 0)` 返回 `false`，`IsButtonDown(0, 0)` 返回 `false`，`IsButtonUp(0, 0)` 返回 `false`。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, CompareEmptyLists) {
    // ...
    EXPECT_FALSE(compareResult.IsDifferent());
    EXPECT_FALSE(compareResult.IsGamepadConnected(0));
    // ...
  }
  ```

* **假设输入：** 第一个列表包含一个中性状态的 gamepad，第二个列表包含一个摇杆有倾斜的 gamepad。
* **预期输出：** `IsDifferent()` 返回 `true` (有差异)，`IsAxisChanged(0, 0)` 返回 `true` (轴 0 发生了变化)。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, CompareNeutralWithAxisTilt) {
    // ...
    EXPECT_TRUE(compareResult.IsDifferent());
    EXPECT_TRUE(compareResult.IsAxisChanged(0, 0));
    // ...
  }
  ```

* **假设输入：** 第一个列表包含一个中性状态的 gamepad，第二个列表包含一个按钮被按下的 gamepad。
* **预期输出：** `IsDifferent()` 返回 `true`，`IsButtonChanged(0, 0)` 返回 `true`，`IsButtonDown(0, 0)` 返回 `true`。
* **实际代码：**
  ```c++
  TEST_F(GamepadComparisonsTest, CompareNeutralWithButtonDown) {
    // ...
    EXPECT_TRUE(compareResult.IsDifferent());
    EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
    EXPECT_TRUE(compareResult.IsButtonDown(0, 0));
    // ...
  }
  ```

**用户或编程常见的使用错误：**

1. **没有正确处理 gamepad 连接和断开事件：** 开发者可能没有监听 `gamepadconnected` 和 `gamepaddisconnected` 事件，导致在 gamepad 连接或断开时，网页无法正确更新状态。
   * **用户操作：** 用户连接或断开一个游戏手柄。
   * **错误结果：** 网页上的游戏手柄相关功能可能无法正常工作，或者仍然显示旧的 gamepad 信息。

2. **没有轮询 gamepad 状态：** 开发者可能没有定期调用 `navigator.getGamepads()` 来获取最新的 gamepad 状态。
   * **用户操作：** 用户按下或释放一个按钮，或者移动摇杆。
   * **错误结果：** 网页上的游戏或应用可能无法及时响应用户的输入。

3. **误解 `GamepadButton` 对象的 `pressed` 和 `touched` 属性：** 开发者可能只检查 `pressed` 属性，而忽略了 `touched` 属性，导致无法处理模拟按键的按下过程（`touched` 为 true 但 `pressed` 可能为 false）。
   * **用户操作：** 用户轻轻按下一个模拟扳机键。
   * **错误结果：** 网页可能没有识别到用户的操作，直到扳机被完全按下。

4. **在比较 gamepad 状态时没有考虑时间戳：** 虽然这个测试文件没有直接涉及时间戳，但在实际应用中，比较 gamepad 事件发生的时间顺序可能很重要。如果开发者没有正确处理时间戳，可能会导致事件处理顺序错误。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户连接游戏手柄到电脑或设备上。** 操作系统会检测到新的游戏手柄。
2. **用户打开 Chrome 浏览器，并访问一个使用了 Gamepad API 的网页。**
3. **网页的 JavaScript 代码调用 `navigator.getGamepads()`。**
4. **Blink 引擎的 Gamepad 模块会获取当前连接的游戏手柄信息。**  这个过程会涉及到操作系统提供的接口。
5. **当 JavaScript 代码再次调用 `navigator.getGamepads()` 时，Blink 引擎需要判断 gamepad 的状态是否发生了变化。**  `blink::GamepadComparisons::Compare` 方法就是在这个时候被调用，比较当前和之前的 gamepad 状态。
6. **如果状态发生变化，Blink 引擎会触发相应的事件（例如 `gamepadbuttondown`），并将新的 gamepad 信息返回给 JavaScript 代码。**
7. **如果开发者在处理 gamepad 输入时遇到问题，例如按键没有响应，他们可能会查看浏览器的开发者工具，并查看相关的错误信息或事件监听器。**
8. **如果问题怀疑是 Blink 引擎的 gamepad 实现有问题，开发者（通常是 Chromium 的贡献者）可能会查看 Blink 引擎的源代码，包括 `gamepad_comparisons_test.cc`，来理解 gamepad 状态比较的逻辑，并可能运行这些测试来验证代码的正确性。**
9. **在开发或调试 Blink 引擎的过程中，修改 `blink::GamepadComparisons` 类的代码后，开发者会运行 `gamepad_comparisons_test.cc` 中的测试用例，以确保修改没有引入新的错误，并且现有的功能仍然正常工作。**

总而言之，`gamepad_comparisons_test.cc` 是 Blink 引擎中用于保证 gamepad 功能正确性的重要组成部分，它通过各种测试用例验证了 gamepad 状态比较逻辑的准确性，从而为基于 JavaScript 的 Web 游戏和应用提供了可靠的底层支持。

Prompt: 
```
这是目录为blink/renderer/modules/gamepad/gamepad_comparisons_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/gamepad/gamepad_comparisons.h"

#include "base/test/task_environment.h"
#include "device/gamepad/public/cpp/gamepad.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad.h"
#include "third_party/blink/renderer/platform/testing/main_thread_isolate.h"

namespace blink {

class GamepadComparisonsTest : public testing::Test {
 public:
  GamepadComparisonsTest() = default;

  GamepadComparisonsTest(const GamepadComparisonsTest&) = delete;
  GamepadComparisonsTest& operator=(const GamepadComparisonsTest&) = delete;

 protected:
  void InitGamepadQuaternion(device::GamepadQuaternion& q) {
    q.not_null = true;
    q.x = 0.f;
    q.y = 0.f;
    q.z = 0.f;
    q.w = 0.f;
  }

  void InitGamepadVector(device::GamepadVector& v) {
    v.not_null = true;
    v.x = 0.f;
    v.y = 0.f;
    v.z = 0.f;
  }

  Gamepad* CreateGamepad() {
    base::TimeTicks dummy_time_origin =
        base::TimeTicks() + base::Microseconds(1000);
    base::TimeTicks dummy_time_floor =
        base::TimeTicks() + base::Microseconds(2000);
    return MakeGarbageCollected<Gamepad>(nullptr, 0, dummy_time_origin,
                                         dummy_time_floor);
  }

  using GamepadList = HeapVector<Member<Gamepad>>;

  HeapVector<Member<Gamepad>> CreateEmptyGamepadList() {
    return HeapVector<Member<Gamepad>>(device::Gamepads::kItemsLengthCap);
  }

  HeapVector<Member<Gamepad>> CreateGamepadListWithNeutralGamepad() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    list[0] = gamepad;
    return list;
  }

  HeapVector<Member<Gamepad>> CreateGamepadListWithAxisTilt() {
    double axes[1] = {0.95};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};

    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    list[0] = gamepad;
    return list;
  }

  HeapVector<Member<Gamepad>> CreateGamepadListWithButtonDown() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{true, true, 1.0}};

    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    list[0] = gamepad;
    return list;
  }

  HeapVector<Member<Gamepad>> CreateGamepadListWithButtonTouched() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{
        false,
        true,
        // Just before the "pressed" threshold.
        device::GamepadButton::kDefaultButtonPressedThreshold - 0.01,
    }};

    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    list[0] = gamepad;
    return list;
  }

  HeapVector<Member<Gamepad>> CreateGamepadListWithButtonJustDown() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{
        true,
        true,
        // Just beyond the "pressed" threshold.
        device::GamepadButton::kDefaultButtonPressedThreshold + 0.01,
    }};

    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    list[0] = gamepad;
    return list;
  }

  void initTouch(float x,
                 float y,
                 uint8_t surface_id,
                 uint32_t touch_id,
                 bool has_surface_dimensions,
                 uint32_t surface_width,
                 uint32_t surface_height,
                 device::GamepadTouch& touch) {
    touch.x = x;
    touch.y = y;
    touch.surface_id = surface_id;
    touch.touch_id = touch_id;
    touch.has_surface_dimensions = has_surface_dimensions;
    touch.surface_width = surface_width;
    touch.surface_height = surface_height;
  }

  GamepadList CreateGamepadListWithTopLeftTouch() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch;
    initTouch(0.0f, 0.0f, 0, 0, false, 0, 0, touch);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(base::span_from_ref(touch));
    list[0] = gamepad;
    return list;
  }

  GamepadList CreateGamepadListWithTopLeftTouchesTouchId1() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch[2];
    initTouch(0.0f, 0.0f, 0, 0, false, 0, 0, touch[0]);
    initTouch(0.0f, 0.0f, 0, 1, false, 0, 0, touch[1]);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(touch);
    list[0] = gamepad;
    return list;
  }

  GamepadList CreateGamepadListWithTopLeftTouchesTouchId3() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch[2];
    initTouch(0.0f, 0.0f, 0, 0, false, 0, 0, touch[0]);
    initTouch(0.0f, 0.0f, 0, 3, false, 0, 0, touch[1]);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(touch);
    list[0] = gamepad;
    return list;
  }

  GamepadList CreateGamepadListWithTopLeftTouchSurface1() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch;
    initTouch(0.0f, 0.0f, 0, 1, true, 1280, 720, touch);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(base::span_from_ref(touch));
    list[0] = gamepad;
    return list;
  }

  GamepadList CreateGamepadListWithTopLeftTouchSurface2() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch;
    initTouch(0.0f, 0.0f, 0, 1, true, 1920, 1080, touch);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(base::span_from_ref(touch));
    list[0] = gamepad;
    return list;
  }

  GamepadList CreateGamepadListWithCenterTouch() {
    double axes[1] = {0.0};
    device::GamepadButton buttons[1] = {{false, false, 0.0}};
    device::GamepadTouch touch;
    initTouch(0.5f, 0.5f, 0, 1, true, 1280, 720, touch);
    auto list = CreateEmptyGamepadList();
    auto* gamepad = CreateGamepad();
    gamepad->SetId("gamepad");
    gamepad->SetAxes(axes);
    gamepad->SetButtons(buttons);
    gamepad->SetConnected(true);
    gamepad->SetTouchEvents(base::span_from_ref(touch));
    list[0] = gamepad;
    return list;
  }

 private:
  // Needed so we can do v8::Isolate::GetCurrent().
  base::test::TaskEnvironment task_environment_;
  blink::test::MainThreadIsolate isolate_;
};

TEST_F(GamepadComparisonsTest, EmptyListCausesNoActivation) {
  auto list = CreateEmptyGamepadList();
  EXPECT_FALSE(GamepadComparisons::HasUserActivation(list));
}

TEST_F(GamepadComparisonsTest, NeutralGamepadCausesNoActivation) {
  auto list = CreateGamepadListWithNeutralGamepad();
  EXPECT_FALSE(GamepadComparisons::HasUserActivation(list));
}

TEST_F(GamepadComparisonsTest, AxisTiltCausesNoActivation) {
  auto list = CreateGamepadListWithAxisTilt();
  EXPECT_FALSE(GamepadComparisons::HasUserActivation(list));
}

TEST_F(GamepadComparisonsTest, ButtonDownCausesActivation) {
  auto list = CreateGamepadListWithButtonDown();
  EXPECT_TRUE(GamepadComparisons::HasUserActivation(list));
}

TEST_F(GamepadComparisonsTest, CompareEmptyLists) {
  // Simulate no connected gamepads.
  auto list1 = CreateEmptyGamepadList();
  auto list2 = CreateEmptyGamepadList();
  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_FALSE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareNeutrals) {
  // Simulate a neutral gamepad with no input changes.
  auto list1 = CreateGamepadListWithNeutralGamepad();
  auto list2 = CreateGamepadListWithNeutralGamepad();
  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_FALSE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareEmptyListWithNeutral) {
  // Simulate a connection.
  auto list1 = CreateEmptyGamepadList();
  auto list2 = CreateGamepadListWithNeutralGamepad();
  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_TRUE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareNeutralWithEmptyList) {
  // Simulate a disconnection.
  auto list1 = CreateGamepadListWithNeutralGamepad();
  auto list2 = CreateEmptyGamepadList();
  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_TRUE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareNeutralWithAxisTilt) {
  // Simulate tilting an axis away from neutral.
  auto list1 = CreateGamepadListWithNeutralGamepad();
  auto list2 = CreateGamepadListWithAxisTilt();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_TRUE(compareResult.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));

  // Using compare_all_axes=false, comparison flags are not set for individual
  // axes.
  auto compareResult2 = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes*/ false, /*compare_all_buttons*/ true);
  EXPECT_TRUE(compareResult2.IsDifferent());
  EXPECT_FALSE(compareResult2.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult2.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult2.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareNeutralWithButtonDown) {
  // Simulate pressing a digital (on/off) button.
  auto list1 = CreateGamepadListWithNeutralGamepad();
  auto list2 = CreateGamepadListWithButtonDown();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));

  // Using compare_all_buttons=false, comparison flags are not set for
  // individual buttons.
  auto compareResult2 = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes*/ true, /*compare_all_buttons*/ false);
  EXPECT_TRUE(compareResult2.IsDifferent());
  EXPECT_FALSE(compareResult2.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult2.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult2.IsAxisChanged(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult2.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonDownWithNeutral) {
  // Simulate releasing a digital (on/off) button.
  auto list1 = CreateGamepadListWithButtonDown();
  auto list2 = CreateGamepadListWithNeutralGamepad();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_TRUE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareNeutralWithButtonTouched) {
  // Simulate touching an analog button or trigger.
  auto list1 = CreateGamepadListWithNeutralGamepad();
  auto list2 = CreateGamepadListWithButtonTouched();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonTouchedWithButtonJustDown) {
  // Simulate pressing an analog button or trigger enough to register a button
  // press.
  auto list1 = CreateGamepadListWithButtonTouched();
  auto list2 = CreateGamepadListWithButtonJustDown();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonJustDownWithButtonDown) {
  // Simulate continuing to press an analog button or trigger until it reaches
  // the maximum value.
  auto list1 = CreateGamepadListWithButtonJustDown();
  auto list2 = CreateGamepadListWithButtonDown();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonDownWithButtonJustDown) {
  // Simulate releasing an analog button or trigger until it is just barely
  // pressed.
  auto list1 = CreateGamepadListWithButtonDown();
  auto list2 = CreateGamepadListWithButtonJustDown();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonJustDownWithButtonTouched) {
  // Simulate releasing an analog button or trigger until it is no longer
  // pressed.
  auto list1 = CreateGamepadListWithButtonJustDown();
  auto list2 = CreateGamepadListWithButtonTouched();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_TRUE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareButtonTouchedWithNeutral) {
  // Simulate releasing an analog button or trigger until it is neutral.
  auto list1 = CreateGamepadListWithButtonTouched();
  auto list2 = CreateGamepadListWithNeutralGamepad();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/true, /*compare_all_buttons=*/true);
  EXPECT_TRUE(compareResult.IsDifferent());
  EXPECT_FALSE(compareResult.IsGamepadConnected(0));
  EXPECT_FALSE(compareResult.IsGamepadDisconnected(0));
  EXPECT_FALSE(compareResult.IsAxisChanged(0, 0));
  EXPECT_TRUE(compareResult.IsButtonChanged(0, 0));
  EXPECT_FALSE(compareResult.IsButtonDown(0, 0));
  EXPECT_FALSE(compareResult.IsButtonUp(0, 0));
}

TEST_F(GamepadComparisonsTest, CompareDifferentTouch) {
  auto list1 = CreateGamepadListWithTopLeftTouch();
  auto list2 = CreateGamepadListWithCenterTouch();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_TRUE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareDifferentSurface) {
  auto list1 = CreateGamepadListWithTopLeftTouch();
  auto list2 = CreateGamepadListWithTopLeftTouchSurface1();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_TRUE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareDifferentTouchId) {
  auto list1 = CreateGamepadListWithTopLeftTouchesTouchId1();
  auto list2 = CreateGamepadListWithTopLeftTouchesTouchId3();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);

  EXPECT_TRUE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareSameTouch1) {
  auto list1 = CreateGamepadListWithTopLeftTouch();

  auto compareResult = GamepadComparisons::Compare(
      list1, list1, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_FALSE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareSameTouch2) {
  auto list1 = CreateGamepadListWithTopLeftTouchesTouchId3();

  auto compareResult = GamepadComparisons::Compare(
      list1, list1, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_FALSE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareSurfaceNoSurfaceTouch) {
  auto list1 = CreateGamepadListWithTopLeftTouchSurface1();
  auto list2 = CreateGamepadListWithTopLeftTouch();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_TRUE(compareResult.IsDifferent());
}

TEST_F(GamepadComparisonsTest, CompareDifferentSurfaceTouch) {
  auto list1 = CreateGamepadListWithTopLeftTouchSurface1();
  auto list2 = CreateGamepadListWithTopLeftTouchSurface2();

  auto compareResult = GamepadComparisons::Compare(
      list1, list2, /*compare_all_axes=*/false, /*compare_all_buttons=*/false);
  EXPECT_TRUE(compareResult.IsDifferent());
}

}  // namespace blink

"""

```