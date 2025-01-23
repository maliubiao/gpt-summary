Response:
Let's break down the thought process to analyze the given C++ code for `gamepad_haptic_actuator.cc`.

1. **Understand the Goal:** The request asks for a functional analysis of a Chromium Blink engine source file related to gamepad haptics. This includes identifying its purpose, its connection to web technologies (JavaScript, HTML, CSS), providing examples, explaining logic, highlighting potential user errors, and outlining the user journey to reach this code.

2. **Initial Code Scan & High-Level Understanding:**
   - Keywords like "haptic," "vibration," "rumble," "playEffect," and "reset" immediately suggest the file handles gamepad vibration functionality.
   - `#include` directives point to interactions with lower-level components (`device/gamepad/public/cpp/gamepad.h`) and Blink's internal structures (`third_party/blink/...`).
   - The `namespace blink` and file path `blink/renderer/modules/gamepad/` confirm it's part of the gamepad module within the Blink rendering engine.
   - The presence of `ScriptPromise`, `ScriptPromiseResolver`, and V8-related includes strongly indicates interaction with JavaScript.

3. **Deconstructing the Code - Key Components and Functions:**

   - **Constructor (`GamepadHapticActuator::GamepadHapticActuator`)**: Initializes the actuator with the gamepad index and dispatcher. The `SetType` method is called here, hinting at different types of haptic actuators.

   - **`SetType`**:  Determines the supported haptic effects based on the `device::GamepadHapticActuatorType`. It distinguishes between `kVibration`, `kTriggerRumble`, and `kDualRumble`. The `supported_effects_` vector stores the supported effect types.

   - **`playEffect`**: This is the core function for triggering haptic feedback.
     - It takes `ScriptState`, `V8GamepadHapticEffectType`, and `GamepadEffectParameters` as input. These clearly map to JavaScript API elements.
     - It performs input validation on the parameters (duration, magnitudes, trigger values).
     - It uses `gamepad_dispatcher_->PlayVibrationEffectOnce` to send the command to the lower-level gamepad system.
     - It uses `ScriptPromise` to handle asynchronous operations and return results to JavaScript.
     - The `OnPlayEffectCompleted` callback handles the result of the vibration command.

   - **`OnPlayEffectCompleted`**:  Deals with the outcome of `PlayVibrationEffectOnce`.
     - Handles success (`GamepadHapticsResultComplete`), error (`GamepadHapticsResultError`), and preemption (`GamepadHapticsResultPreempted`).
     - Introduces the `should_reset_` flag and the `ResetVibrationIfNotPreempted` mechanism to stop vibrations after a successful effect, unless another effect is chained.

   - **`ResetVibrationIfNotPreempted`**:  Actually stops the vibration if the `should_reset_` flag is true. It calls `gamepad_dispatcher_->ResetVibrationActuator`.

   - **`reset`**: Provides a way to explicitly stop all ongoing haptic effects. It also uses a `ScriptPromise`.

   - **`OnResetCompleted`**:  Handles the result of the `ResetVibrationActuator` call.

   - **Helper Functions (`EffectTypeFromEnum`, `ResultToV8`)**: These convert between internal C++ enums and the enums exposed to JavaScript (V8).

4. **Connecting to Web Technologies:**

   - **JavaScript:** The `GamepadHapticActuator` class directly implements the functionality exposed by the JavaScript `GamepadHapticActuator` interface. The `playEffect` and `reset` methods correspond to JavaScript methods. The parameters and return types (`ScriptPromise` wrapping `V8GamepadHapticsResult`) are the bridge between C++ and JavaScript.

   - **HTML:**  HTML provides the structure for web pages where JavaScript can be executed. The gamepad API, and thus this C++ code, is accessed through JavaScript within an HTML page.

   - **CSS:** While CSS doesn't directly interact with the gamepad API, it can influence the user interface that triggers gamepad interactions (e.g., a button press that initiates a vibration).

5. **Examples, Logic, and Error Handling:**

   - **Examples:**  Illustrate how the JavaScript API maps to the C++ functions.
   - **Logic:** Focus on the `playEffect` function's validation, the asynchronous nature of the operations using promises, and the delayed reset mechanism.
   - **Errors:** Highlight common JavaScript usage mistakes, like providing invalid parameter values or exceeding the maximum duration. Also, mention the possibility of the underlying hardware not supporting certain features.

6. **User Journey and Debugging:**

   - Trace the steps a user takes to trigger the haptic actuator, starting from the user interaction (e.g., button press) to the JavaScript event handler and finally to the C++ code.
   - Mention debugging techniques, like using the browser's developer tools to inspect the `Gamepad` object and set breakpoints in the JavaScript code. Also, mention the role of console messages (although this file doesn't directly create them, it interacts with the console).

7. **Refinement and Organization:**

   - Structure the explanation logically, starting with the overall function and then delving into specifics.
   - Use clear and concise language.
   - Provide code snippets where necessary to illustrate points.
   - Ensure all aspects of the original request are addressed.

**Self-Correction/Refinement During the Process:**

- **Initial thought:**  Might have focused too much on the low-level details of the gamepad driver interaction. **Correction:** Shifted focus to the interaction with the JavaScript API and the role of this C++ code in that context.
- **Realization:** The `should_reset_` mechanism is a subtle but important optimization. **Correction:**  Made sure to explain its purpose clearly.
- **Consideration:** How deep to go into the `GamepadDispatcher`. **Correction:** Acknowledge its role but avoid getting bogged down in its implementation details, as the request is specifically about `gamepad_haptic_actuator.cc`.
- **Clarity:** Ensuring the connection between the C++ code and the JavaScript API is crystal clear. **Correction:** Used phrases like "This C++ file implements the backend logic for..." to emphasize the connection.

By following these steps and refining the analysis along the way, we arrive at a comprehensive and informative explanation of the `gamepad_haptic_actuator.cc` file.
好的，让我们详细分析一下 `blink/renderer/modules/gamepad/gamepad_haptic_actuator.cc` 这个文件。

**功能概要**

该 C++ 文件 `gamepad_haptic_actuator.cc` 实现了 Chromium Blink 引擎中用于控制游戏手柄（Gamepad）触觉反馈（Haptic Feedback）的功能。 它的主要职责是：

1. **管理游戏手柄的触觉执行器（Haptic Actuator）：**  它代表了游戏手柄上的一个可以产生震动或其他触觉效果的硬件单元。
2. **提供 JavaScript 接口的底层实现：** 它响应 JavaScript 代码发起的请求，例如播放特定的震动效果或停止震动。
3. **与设备层的 Gamepad API 交互：** 它通过 `GamepadDispatcher` 与更底层的设备层 Gamepad API 进行通信，实际控制手柄硬件。
4. **处理不同类型的触觉效果：** 它支持不同类型的触觉效果，例如双震动（Dual Rumble）和扳机震动（Trigger Rumble）。
5. **处理异步操作：** 播放触觉效果是异步的，该文件使用 `ScriptPromise` 来管理这些异步操作，并将结果返回给 JavaScript。
6. **处理错误情况：**  它会检查参数的有效性，并处理来自底层硬件的错误。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件是 Web API `GamepadHapticActuator` 在 Blink 渲染引擎中的底层实现。

* **JavaScript:**
    * **API 暴露：** JavaScript 代码可以通过 `navigator.getGamepads()` 获取 `Gamepad` 对象，然后访问其 `hapticActuators` 属性来获得 `GamepadHapticActuator` 对象。
    * **方法调用：** JavaScript 代码调用 `GamepadHapticActuator` 对象的方法，如 `playEffect()` 和 `reset()`，这些调用最终会触发此 C++ 文件中的相应函数。

    ```javascript
    // 获取第一个连接的游戏手柄
    const gamepad = navigator.getGamepads()[0];

    if (gamepad && gamepad.hapticActuators.length > 0) {
      const actuator = gamepad.hapticActuators[0];

      // 播放一个双震动效果
      actuator.playEffect('dual-rumble', {
        duration: 1000, // 持续 1 秒
        strongMagnitude: 1.0, // 强烈震动
        weakMagnitude: 0.5  // 较弱震动
      }).then(result => {
        console.log('震动效果播放完成:', result);
      }).catch(error => {
        console.error('播放震动效果失败:', error);
      });

      // 停止所有震动
      actuator.reset().then(result => {
        console.log('停止震动:', result);
      });
    }
    ```

* **HTML:** HTML 提供了网页的结构，JavaScript 代码通常嵌入在 HTML 中或由 HTML 加载，从而能够访问 Gamepad API 并触发触觉反馈。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gamepad Haptics Example</title>
    </head>
    <body>
      <button id="vibrateButton">震动</button>
      <script>
        const vibrateButton = document.getElementById('vibrateButton');

        vibrateButton.addEventListener('click', () => {
          const gamepad = navigator.getGamepads()[0];
          if (gamepad && gamepad.hapticActuators.length > 0) {
            const actuator = gamepad.hapticActuators[0];
            actuator.playEffect('dual-rumble', {
              duration: 500,
              strongMagnitude: 0.8,
              weakMagnitude: 0.2
            });
          }
        });
      </script>
    </body>
    </html>
    ```

* **CSS:** CSS 负责网页的样式，与 `GamepadHapticActuator` 的功能没有直接关系。但是，CSS 可以用于创建用户界面元素（例如按钮），用户与这些元素交互后可能会触发 JavaScript 代码，从而间接地触发触觉反馈。

**逻辑推理 (假设输入与输出)**

**假设输入（`playEffect` 方法）:**

* `script_state`: 当前的 JavaScript 执行状态。
* `type`:  `V8GamepadHapticEffectType` 对象，例如 `dual-rumble`。
* `params`: `GamepadEffectParameters` 对象，包含以下属性：
    * `duration`: 1000 (毫秒)
    * `startDelay`: 0 (毫秒)
    * `strongMagnitude`: 0.9
    * `weakMagnitude`: 0.3
    * `leftTrigger`: 0.0
    * `rightTrigger`: 0.0

**逻辑推理过程:**

1. **参数验证:** `playEffect` 函数首先会检查 `params` 中的值是否在有效范围内（例如，duration 和 startDelay >= 0，magnitude 在 0.0 到 1.0 之间）。
2. **效果类型转换:**  `EffectTypeFromEnum` 函数将 JavaScript 传递的 `dual-rumble` 转换为底层的 `GamepadHapticEffectType::GamepadHapticEffectTypeDualRumble` 枚举值。
3. **调用 GamepadDispatcher:**  `gamepad_dispatcher_->PlayVibrationEffectOnce` 被调用，并将以下信息传递给底层：
    * `pad_index_`:  游戏手柄的索引。
    *  底层的效果类型枚举值。
    *  一个包含效果参数的 `device::mojom::blink::GamepadEffectParameters` 对象。
    *  一个在操作完成时调用的回调函数 `OnPlayEffectCompleted`。
4. **异步处理:**  `playEffect` 返回一个 `ScriptPromise` 对象，JavaScript 可以使用 `.then()` 和 `.catch()` 来处理操作的成功或失败。

**可能输出 (Promise 的 resolve 或 reject):**

* **成功 (resolve):**  `V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kComplete)`，表示触觉效果已成功播放完成。
* **被抢占 (resolve):** `V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kPreempted)`，表示当前的触觉效果被另一个新的效果打断。
* **参数无效 (resolve):** `V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kInvalidParameter)`，如果输入参数超出有效范围。
* **不支持 (resolve):** `V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kNotSupported)`，如果手柄不支持请求的触觉效果类型。
* **错误 (reject):** 如果底层 Gamepad API 返回错误。

**假设输入（`reset` 方法）:**

* `script_state`: 当前的 JavaScript 执行状态。

**逻辑推理过程:**

1. **调用 GamepadDispatcher:** `gamepad_dispatcher_->ResetVibrationActuator` 被调用，并将 `pad_index_` 和一个回调函数 `OnResetCompleted` 传递给底层。
2. **异步处理:** `reset` 返回一个 `ScriptPromise` 对象。

**可能输出 (Promise 的 resolve 或 reject):**

* **成功 (resolve):** `V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kComplete)`，表示成功停止所有震动。
* **错误 (reject):** 如果底层 Gamepad API 返回错误。

**用户或编程常见的使用错误**

1. **无效的参数值:**  在调用 `playEffect` 时传递无效的参数，例如负的 `duration` 或 `startDelay`，超出 0.0 到 1.0 范围的 `strongMagnitude` 或 `weakMagnitude`。

   ```javascript
   // 错误示例：duration 为负数
   actuator.playEffect('dual-rumble', { duration: -100 });
   ```

2. **超出最大效果持续时间:** 尝试播放持续时间过长的效果。`device::GamepadHapticActuator::kMaxEffectDurationMillis` 定义了最大允许的持续时间。

   ```javascript
   // 错误示例：duration 过长
   actuator.playEffect('dual-rumble', { duration: 10000 }); // 假设 kMaxEffectDurationMillis 小于 10000
   ```

3. **未检查 `hapticActuators` 的存在:**  在访问 `hapticActuators` 之前，没有检查 `gamepad` 对象是否存在且 `hapticActuators` 数组不为空。

   ```javascript
   const gamepad = navigator.getGamepads()[0];
   // 错误示例：未检查 gamepad 是否存在
   gamepad.hapticActuators[0].playEffect(...);

   // 正确示例：
   if (gamepad && gamepad.hapticActuators.length > 0) {
     gamepad.hapticActuators[0].playEffect(...);
   }
   ```

4. **假设所有手柄都支持所有效果类型:**  不同的游戏手柄可能支持不同的触觉效果类型。应该查阅手柄的文档或通过特征检测来确定支持哪些效果。

5. **在 Promise 的回调中忘记处理错误:** 没有使用 `.catch()` 来处理 `playEffect()` 或 `reset()` 返回的 Promise 可能出现的错误。

   ```javascript
   actuator.playEffect(...).then(result => {
     // 处理成功情况
   }); // 错误示例：缺少 .catch()
   ```

**用户操作是如何一步步的到达这里 (调试线索)**

1. **用户交互:** 用户在网页上进行操作，例如点击一个按钮或在游戏中触发某个事件。
2. **JavaScript 事件处理:**  与该操作相关的 JavaScript 事件监听器被触发。
3. **调用 Gamepad API:**  事件处理函数中，JavaScript 代码获取 `Gamepad` 对象，并调用其 `hapticActuators` 上的 `playEffect()` 或 `reset()` 方法。
4. **Blink 引擎处理 JavaScript 调用:**  Blink 引擎接收到 JavaScript 的调用请求。
5. **V8 绑定:**  V8 引擎（JavaScript 引擎）将 JavaScript 的调用桥接到 C++ 代码。 这涉及到 `third_party/blink/renderer/bindings/modules/v8/` 目录下的一些绑定代码。
6. **调用 `GamepadHapticActuator` 的方法:**  JavaScript 的 `playEffect()` 或 `reset()` 调用最终会映射到 `gamepad_haptic_actuator.cc` 文件中相应的 C++ 方法 (`GamepadHapticActuator::playEffect` 或 `GamepadHapticActuator::reset`)。
7. **与 `GamepadDispatcher` 交互:**  `GamepadHapticActuator` 调用 `gamepad_dispatcher_` 的方法，例如 `PlayVibrationEffectOnce` 或 `ResetVibrationActuator`。
8. **设备层通信:** `GamepadDispatcher` 负责与更底层的设备层 Gamepad API 进行通信，这可能涉及到操作系统提供的 API 或驱动程序。
9. **硬件操作:**  底层 API 指令被发送到游戏手柄硬件，导致手柄产生震动或其他触觉效果。
10. **回调:** 当硬件操作完成时，设备层 API 会通知 Blink 引擎，最终会触发之前在 `playEffect` 或 `reset` 中设置的回调函数 (`OnPlayEffectCompleted` 或 `OnResetCompleted`)。
11. **Promise 的 resolve/reject:**  回调函数会根据操作结果 resolve 或 reject 相应的 `ScriptPromise`，并将结果返回给 JavaScript。
12. **JavaScript Promise 处理:** JavaScript 代码中的 `.then()` 或 `.catch()` 方法被执行，处理触觉反馈操作的结果。

**调试线索:**

* **浏览器开发者工具:** 使用浏览器的开发者工具（特别是 Console 和 Sources 面板）来查看 JavaScript 代码的执行流程、变量的值以及可能出现的错误。
* **断点调试:** 在 JavaScript 代码中设置断点，逐步执行代码，查看 `Gamepad` 对象和 `GamepadHapticActuator` 对象的状态。
* **Blink 渲染引擎调试:** 如果需要深入了解 Blink 引擎的内部工作原理，可以使用 Chromium 的调试工具（例如 gdb）来调试 C++ 代码。可以在 `gamepad_haptic_actuator.cc` 文件中设置断点，查看参数传递和函数调用过程。
* **日志输出:**  在 C++ 代码中添加日志输出（例如使用 `DLOG` 或 `DVLOG`），以便在控制台中查看关键操作的执行情况。
* **Gamepad API 事件监听:**  监听 `gamepadconnected` 和 `gamepaddisconnected` 事件，确保手柄已正确连接。

希望以上分析能够帮助你理解 `blink/renderer/modules/gamepad/gamepad_haptic_actuator.cc` 文件的功能和它在 Web 技术栈中的作用。

### 提示词
```
这是目录为blink/renderer/modules/gamepad/gamepad_haptic_actuator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/gamepad/gamepad_haptic_actuator.h"

#include "base/functional/callback_helpers.h"
#include "device/gamepad/public/cpp/gamepad.h"
#include "third_party/blink/public/mojom/devtools/console_message.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gamepad_effect_parameters.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gamepad_haptic_effect_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_gamepad_haptics_result.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/gamepad/gamepad_dispatcher.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

namespace {

using device::mojom::GamepadHapticsResult;
using device::mojom::GamepadHapticEffectType;

GamepadHapticEffectType EffectTypeFromEnum(
    V8GamepadHapticEffectType::Enum type) {
  switch (type) {
    case V8GamepadHapticEffectType::Enum::kDualRumble:
      return GamepadHapticEffectType::GamepadHapticEffectTypeDualRumble;
    case V8GamepadHapticEffectType::Enum::kTriggerRumble:
      return GamepadHapticEffectType::GamepadHapticEffectTypeTriggerRumble;
  }
  NOTREACHED();
}

V8GamepadHapticsResult ResultToV8(GamepadHapticsResult result) {
  switch (result) {
    case GamepadHapticsResult::GamepadHapticsResultComplete:
      return V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kComplete);
    case GamepadHapticsResult::GamepadHapticsResultPreempted:
      return V8GamepadHapticsResult(V8GamepadHapticsResult::Enum::kPreempted);
    case GamepadHapticsResult::GamepadHapticsResultInvalidParameter:
      return V8GamepadHapticsResult(
          V8GamepadHapticsResult::Enum::kInvalidParameter);
    case GamepadHapticsResult::GamepadHapticsResultNotSupported:
      return V8GamepadHapticsResult(
          V8GamepadHapticsResult::Enum::kNotSupported);
    default:
      NOTREACHED();
  }
}

}  // namespace

GamepadHapticActuator::GamepadHapticActuator(
    ExecutionContext& context,
    int pad_index,
    device::GamepadHapticActuatorType type)
    : ExecutionContextClient(&context),
      pad_index_(pad_index),
      gamepad_dispatcher_(MakeGarbageCollected<GamepadDispatcher>(context)) {
  SetType(type);
}

GamepadHapticActuator::~GamepadHapticActuator() = default;

void GamepadHapticActuator::SetType(device::GamepadHapticActuatorType type) {
  supported_effects_.clear();
  switch (type) {
    case device::GamepadHapticActuatorType::kVibration:
      type_ = V8GamepadHapticActuatorType::Enum::kVibration;
      break;
    // Currently devices that have trigger rumble support, also have dual-rumble
    // support.
    case device::GamepadHapticActuatorType::kTriggerRumble:
      supported_effects_.push_back(V8GamepadHapticEffectType(
          V8GamepadHapticEffectType::Enum::kTriggerRumble));
      [[fallthrough]];
    case device::GamepadHapticActuatorType::kDualRumble:
      supported_effects_.push_back(V8GamepadHapticEffectType(
          V8GamepadHapticEffectType::Enum::kDualRumble));
      type_ = V8GamepadHapticActuatorType::Enum::kDualRumble;
      break;
  }
}

ScriptPromise<V8GamepadHapticsResult> GamepadHapticActuator::playEffect(
    ScriptState* script_state,
    const V8GamepadHapticEffectType& type,
    const GamepadEffectParameters* params) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8GamepadHapticsResult>>(
          script_state);
  auto promise = resolver->Promise();

  if (params->duration() < 0.0 || params->startDelay() < 0.0 ||
      params->strongMagnitude() < 0.0 || params->strongMagnitude() > 1.0 ||
      params->weakMagnitude() < 0.0 || params->weakMagnitude() > 1.0 ||
      params->leftTrigger() < 0.0 || params->leftTrigger() > 1.0 ||
      params->rightTrigger() < 0.0 || params->rightTrigger() > 1.0) {
    resolver->Resolve(
        ResultToV8(GamepadHapticsResult::GamepadHapticsResultInvalidParameter));
    return promise;
  }

  // Limit the total effect duration.
  double effect_duration = params->duration() + params->startDelay();
  if (effect_duration >
      device::GamepadHapticActuator::kMaxEffectDurationMillis) {
    resolver->Resolve(
        ResultToV8(GamepadHapticsResult::GamepadHapticsResultInvalidParameter));
    return promise;
  }

  // Avoid resetting vibration for a preempted effect.
  should_reset_ = false;

  auto callback = WTF::BindOnce(&GamepadHapticActuator::OnPlayEffectCompleted,
                                WrapPersistent(this), WrapPersistent(resolver));

  gamepad_dispatcher_->PlayVibrationEffectOnce(
      pad_index_, EffectTypeFromEnum(type.AsEnum()),
      device::mojom::blink::GamepadEffectParameters::New(
          params->duration(), params->startDelay(), params->strongMagnitude(),
          params->weakMagnitude(), params->leftTrigger(),
          params->rightTrigger()),
      std::move(callback));

  return promise;
}

void GamepadHapticActuator::OnPlayEffectCompleted(
    ScriptPromiseResolver<V8GamepadHapticsResult>* resolver,
    device::mojom::GamepadHapticsResult result) {
  if (result == GamepadHapticsResult::GamepadHapticsResultError) {
    resolver->Reject();
    return;
  } else if (result == GamepadHapticsResult::GamepadHapticsResultComplete) {
    should_reset_ = true;
    ExecutionContext* context = GetExecutionContext();
    if (context) {
      // Post a delayed task to stop vibration. The task will be run after all
      // callbacks have run for the effect Promise, and may be ignored by
      // setting |should_reset_| to false. The intention is to only stop
      // vibration if the user did not chain another vibration effect in the
      // Promise callback.
      context->GetTaskRunner(TaskType::kMiscPlatformAPI)
          ->PostTask(FROM_HERE,
                     WTF::BindOnce(
                         &GamepadHapticActuator::ResetVibrationIfNotPreempted,
                         WrapPersistent(this)));
    } else {
      // The execution context is gone, meaning no new effects can be issued by
      // the page. Stop vibration without waiting for Promise callbacks.
      ResetVibrationIfNotPreempted();
    }
  }
  resolver->Resolve(ResultToV8(result));
}

void GamepadHapticActuator::ResetVibrationIfNotPreempted() {
  if (should_reset_) {
    should_reset_ = false;
    gamepad_dispatcher_->ResetVibrationActuator(pad_index_, base::DoNothing());
  }
}

ScriptPromise<V8GamepadHapticsResult> GamepadHapticActuator::reset(
    ScriptState* script_state) {
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<V8GamepadHapticsResult>>(
          script_state);

  auto callback = WTF::BindOnce(&GamepadHapticActuator::OnResetCompleted,
                                WrapPersistent(this), WrapPersistent(resolver));

  gamepad_dispatcher_->ResetVibrationActuator(pad_index_, std::move(callback));

  return resolver->Promise();
}

void GamepadHapticActuator::OnResetCompleted(
    ScriptPromiseResolver<V8GamepadHapticsResult>* resolver,
    device::mojom::GamepadHapticsResult result) {
  if (result == GamepadHapticsResult::GamepadHapticsResultError) {
    resolver->Reject();
    return;
  }
  resolver->Resolve(ResultToV8(result));
}

void GamepadHapticActuator::Trace(Visitor* visitor) const {
  visitor->Trace(gamepad_dispatcher_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink
```