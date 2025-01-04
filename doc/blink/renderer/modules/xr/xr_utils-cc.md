Response:
Let's break down the thought process for analyzing the `xr_utils.cc` file.

1. **Understand the Goal:** The primary goal is to understand the functionality of this specific C++ file within the Chromium/Blink rendering engine, especially its relationship to WebXR features (JavaScript, HTML, CSS). I also need to identify potential usage errors, demonstrate a debugging path, and perform logical inference.

2. **Initial Scan & Keyword Recognition:**  I'll quickly scan the code looking for keywords and patterns:
    * `#include`:  Indicates dependencies and the types of data the file manipulates (e.g., `gfx::Transform`, `DOMFloat32Array`, `WebGLRenderingContext`, `device::Pose`, `device::mojom::blink::XRHandJoint`).
    * Function names:  These are the primary actions the file performs (e.g., `transformationMatrixToDOMFloat32Array`, `DOMFloat32ArrayToTransform`, `makeNormalizedQuaternion`, `StringToMojomHandJoint`, `StringToXRSessionFeature`, `IsFeatureEnabledForContext`).
    * Namespaces:  The file is within the `blink` namespace, and interacts with `gfx` and `device`. This tells us about the scope and context.
    * `DCHECK`, `NOTREACHED`: These are debugging and error handling mechanisms. They can point to potential assumptions and error conditions.
    * `switch` statements: These are used for mapping between different representations of data (e.g., strings to enums).

3. **Categorize Functions by Functionality:** I'll group the functions based on what they seem to be doing:
    * **Matrix/Transformation Handling:**  `transformationMatrixToDOMFloat32Array`, `DOMFloat32ArrayToTransform`, `WTFFloatVectorToTransform`, `CreatePose`. These deal with converting between different matrix representations.
    * **Quaternion Normalization:** `makeNormalizedQuaternion`. This is a specific mathematical operation related to rotations in 3D space.
    * **WebGL Context Handling:** `webglRenderingContextBaseFromUnion`. This seems to handle different types of WebGL contexts.
    * **Hand Joint Mapping:** `StringToMojomHandJoint`, `MojomHandJointToV8Enum`. These functions convert between string representations of hand joints and their internal enum representations.
    * **XR Session Feature Mapping & Checking:** `StringToXRSessionFeature`, `XRSessionFeatureToString`, `IsFeatureEnabledForContext`. These functions handle the strings representing optional WebXR features and check if those features are enabled.

4. **Analyze Relationships to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The conversions to/from `DOMFloat32Array` are a direct link to JavaScript's `Float32Array`, which is used to pass numerical data between JavaScript and WebGL/WebXR. The hand joint and session feature mapping also relates to how these concepts are exposed in the WebXR JavaScript API.
    * **WebGL:** The `webglRenderingContextBaseFromUnion` function explicitly deals with WebGL contexts, indicating that this utility file is involved in how WebXR interacts with rendering via WebGL.
    * **HTML:** While not directly manipulating HTML, the "dom-overlay" feature mentioned in `StringToXRSessionFeature` implies interaction with the HTML DOM. This feature allows embedding HTML content within the XR scene.
    * **CSS:**  Less direct, but transformations (handled by the matrix functions) can influence how elements are rendered, including those in a DOM overlay.

5. **Logical Inference (Assumptions and Outputs):** For each function, I'll consider a typical input and what the expected output would be. This helps clarify the function's purpose. For example, for `transformationMatrixToDOMFloat32Array`, a `gfx::Transform` representing a translation will result in a `DOMFloat32Array` with specific values.

6. **Identify Potential Usage Errors:**  I'll look for areas where incorrect usage could lead to problems:
    * Incorrect array lengths in matrix conversions.
    * Invalid hand joint or session feature strings.
    * Passing a null or invalid WebGL context.
    * Assuming a feature is enabled without checking.

7. **Construct a Debugging Scenario:**  I need to illustrate how a user action might lead to this code being executed. A good scenario involves a user trying to use a WebXR feature, and how the browser might process that request, potentially involving these utility functions.

8. **Structure the Response:**  I'll organize the information logically:
    * Start with a general overview of the file's purpose.
    * Detail the functionality of each group of functions.
    * Explain the relationship to JavaScript, HTML, and CSS with concrete examples.
    * Provide examples of logical inference (input/output).
    * List common usage errors.
    * Describe a step-by-step user interaction that could lead to this code being executed.

9. **Refine and Review:** After drafting the initial response, I'll review it for clarity, accuracy, and completeness. I'll ensure that the examples are relevant and easy to understand. I'll also double-check that I've addressed all the prompt's requirements.

By following these steps, I can systematically analyze the provided code and produce a comprehensive and informative response. The key is to break down the problem into smaller, manageable parts and to focus on understanding the purpose and interactions of the different code elements.
这个文件 `xr_utils.cc` 是 Chromium Blink 渲染引擎中 `modules/xr` 目录下的一个实用工具文件。它的主要功能是提供与 WebXR API 相关的各种辅助函数，用于处理数据转换、枚举映射以及特征检测等操作。

下面详细列举其功能，并说明与 JavaScript, HTML, CSS 的关系：

**功能列表:**

1. **变换矩阵转换:**
   - `transformationMatrixToDOMFloat32Array(const gfx::Transform& matrix)`: 将 Chromium 内部使用的 `gfx::Transform` 类型的变换矩阵转换为 JavaScript 可直接使用的 `DOMFloat32Array` 对象。
   - `DOMFloat32ArrayToTransform(DOMFloat32Array* m)`: 将 JavaScript 传递过来的 `DOMFloat32Array` 对象（表示变换矩阵）转换回 Chromium 内部使用的 `gfx::Transform` 类型。
   - `WTFFloatVectorToTransform(const Vector<float>& m)`: 将 `WTF::Vector<float>` 类型的浮点数向量（通常是 4x4 矩阵数据）转换为 `gfx::Transform`。

   **与 JavaScript 的关系:** WebXR API 中，涉及到物体位置、方向等变换信息时，经常会使用 `Float32Array` 来表示 4x4 的变换矩阵。这两个转换函数就是为了在 C++ 和 JavaScript 之间传递这些变换数据。

2. **四元数归一化:**
   - `makeNormalizedQuaternion(double x, double y, double z, double w)`:  接收四元数的四个分量，并对其进行归一化处理，确保其长度为 1。返回一个只读的 `DOMPointReadOnly` 对象来表示归一化后的四元数。

   **与 JavaScript 的关系:** WebXR API 中，旋转信息有时会用四元数表示。虽然这里返回的是 `DOMPointReadOnly`，但它用于表示四元数 (x, y, z, w)。 归一化是四元数操作中常见的步骤，确保其代表有效的旋转。

3. **WebGL 上下文处理:**
   - `webglRenderingContextBaseFromUnion(const V8XRWebGLRenderingContext* context)`: 接收一个可以指向 `WebGLRenderingContext` 或 `WebGL2RenderingContext` 的联合类型指针，并根据实际类型返回对应的基类 `WebGLRenderingContextBase` 指针。

   **与 JavaScript 的关系:** WebXR 内容经常会渲染到 WebGL 上下文中。这个函数允许代码处理不同版本的 WebGL 上下文，使得 WebXR 可以与 WebGL 或 WebGL 2 一起工作。  在 JavaScript 中，开发者会获取 `WebGLRenderingContext` 或 `WebGL2RenderingContext` 对象，并将其传递给 WebXR 相关的 API。

4. **手部关节枚举映射:**
   - `StringToMojomHandJoint(const String& hand_joint_string)`: 将表示手部关节名称的字符串（例如 "wrist", "thumb-tip"）转换为 Chromium 内部使用的 `device::mojom::blink::XRHandJoint` 枚举值。
   - `MojomHandJointToV8Enum(device::mojom::blink::XRHandJoint hand_joint)`: 将 Chromium 内部的手部关节枚举值转换为 V8 中定义的 `V8XRHandJoint::Enum` 枚举值，以便在 JavaScript 中使用。

   **与 JavaScript 的关系:** WebXR Hand Input API 允许访问追踪到的手部关节信息。JavaScript 中会使用字符串来表示不同的手部关节，而 Chromium 内部使用枚举值。这两个函数用于在这两种表示方式之间进行转换。

5. **WebXR Session Feature 枚举映射和检测:**
   - `StringToXRSessionFeature(const String& feature_string)`: 将表示 WebXR Session Feature 名称的字符串（例如 "hit-test", "dom-overlay"）转换为 Chromium 内部使用的 `device::mojom::XRSessionFeature` 枚举值。
   - `XRSessionFeatureToString(device::mojom::XRSessionFeature feature)`: 将 Chromium 内部的 WebXR Session Feature 枚举值转换为其对应的字符串表示。
   - `IsFeatureEnabledForContext(device::mojom::XRSessionFeature feature, const ExecutionContext* context)`:  检查特定的 WebXR Session Feature 是否在给定的执行上下文中启用。这通常涉及到检查 RuntimeEnabledFeatures。

   **与 JavaScript, HTML 的关系:**
     - **JavaScript:** 当 Web 开发者在 JavaScript 中请求创建一个 WebXR Session 时，会指定 `requiredFeatures` 或 `optionalFeatures` 列表，其中包含了表示各种 WebXR 功能的字符串（例如 `navigator.xr.requestSession('immersive-vr', { optionalFeatures: ['dom-overlay'] })`）。`StringToXRSessionFeature` 就用于解析这些字符串。
     - **HTML:**  `dom-overlay` feature 允许将 HTML 内容渲染到 XR 场景中，这直接关联到 HTML。`IsFeatureEnabledForContext` 确保了只有在浏览器支持并启用了 `dom-overlay` 功能时，相关的 WebXR API 才能正常工作。

6. **创建 Pose 对象:**
   - `std::optional<device::Pose> CreatePose(const gfx::Transform& matrix)`:  根据给定的变换矩阵创建一个 `device::Pose` 对象。`Pose` 对象用于表示 3D 空间中的位置和方向。

   **与 JavaScript 的关系:** WebXR API 中的 `XRPose` 接口用于表示物体或视点的姿态（位置和方向）。`CreatePose` 函数是 Chromium 内部创建 `Pose` 对象的辅助方法，这些 `Pose` 对象最终会映射到 JavaScript 中的 `XRPose`。

**逻辑推理 (假设输入与输出):**

* **假设输入 (transformationMatrixToDOMFloat32Array):** 一个代表平移的 `gfx::Transform` 对象，例如将物体沿 X 轴移动 5 个单位。
  ```
  gfx::Transform matrix;
  matrix.Translate(5, 0, 0);
  ```
* **输出:**  `DOMFloat32Array` 的数据应该是 `[1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 5, 0, 0, 1]` (列主序)。

* **假设输入 (StringToMojomHandJoint):**  JavaScript 中表示左手食指指尖的字符串 `"index-finger-tip"`.
* **输出:** `device::mojom::blink::XRHandJoint::kIndexFingerTip` 枚举值。

* **假设输入 (IsFeatureEnabledForContext):**  `feature` 为 `device::mojom::XRSessionFeature::DOM_OVERLAY`，且当前的 `ExecutionContext` 对应的文档启用了 WebXR DOM Overlay 功能。
* **输出:** `true`。

**用户或编程常见的使用错误:**

1. **矩阵转换时数组长度不匹配:**  在 JavaScript 中创建 `Float32Array` 并传递给 WebXR API 时，如果数组的长度不是 16（4x4 矩阵），`DOMFloat32ArrayToTransform` 函数中的 `DCHECK_EQ(m->length(), 16u);` 会触发断言失败，导致程序崩溃。
   * **用户操作:** 开发者在 JavaScript 中错误地创建了一个长度不是 16 的 `Float32Array` 并将其用于设置 WebXR 物体的变换。
   * **代码示例 (JavaScript 错误用法):**
     ```javascript
     const invalidMatrix = new Float32Array(9); // 错误的长度
     // 假设存在某个 WebXR API 接收变换矩阵
     xrFrame.getPose(xrReferenceSpace).transformMatrix = invalidMatrix;
     ```

2. **传递无效的手部关节字符串:**  在使用 WebXR Hand Input API 时，如果传递给相关函数的字符串不是预定义的有效手部关节名称，`StringToMojomHandJoint` 函数会执行到 `NOTREACHED()`，表明这是一个不应该发生的情况，通常意味着编程错误。
   * **用户操作:** 开发者在 JavaScript 中使用了错误的字符串来表示手部关节。
   * **代码示例 (JavaScript 错误用法):**
     ```javascript
     const invalidJointName = "not-a-real-joint";
     // 假设存在某个 WebXR API 接收手部关节名称
     xrFrame.getJointPose(invalidJointName, xrReferenceSpace);
     ```

3. **假设未启用的 Feature 可用:** 开发者可能会在 JavaScript 中使用某个 WebXR Feature 的 API，但该 Feature 并未在浏览器中启用或未在 `requestSession` 中请求。`IsFeatureEnabledForContext` 可以用来避免这种情况，但在实际开发中，开发者可能忘记进行检查。
   * **用户操作:** 用户尝试访问依赖于未启用 Feature 的 WebXR 内容。
   * **代码示例 (JavaScript 错误用法，假设 "plane-detection" 未启用):**
     ```javascript
     navigator.xr.requestSession('immersive-ar')
       .then(session => {
         // ...
         session.requestHitTest(...); // 如果 "hit-test" 需要 "plane-detection" 且未启用，则会出错
       });
     ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户正在浏览一个使用了 WebXR 手部追踪功能的网页，并且该网页正在使用 `requestAnimationFrame` 循环来更新场景。

1. **用户打开支持 WebXR 的浏览器，并访问了该网页。**
2. **网页的 JavaScript 代码调用 `navigator.xr.requestSession('immersive-vr', { optionalFeatures: ['hand-tracking'] })` 请求一个 WebXR 会话，并请求了 `hand-tracking` 功能。**  这里，`StringToXRSessionFeature` 会被调用来解析 `"hand-tracking"` 字符串。
3. **如果用户同意授权 WebXR 会话，会话开始。**
4. **在每个渲染帧中，网页的 JavaScript 代码会请求当前的 XRFrame。**
5. **通过 `XRFrame.getJointPose(jointName, xrReferenceSpace)` 或类似的方法，网页尝试获取特定手部关节的姿态。**
6. **在 Blink 渲染引擎内部，当处理 `getJointPose` 请求时，会接收到 JavaScript 传递的关节名称字符串（例如 "thumb-tip"）。**
7. **`StringToMojomHandJoint("thumb-tip")` 函数会被调用，将 JavaScript 的字符串表示转换为内部的枚举值 `device::mojom::blink::XRHandJoint::kThumbTip`。**
8. **引擎会从底层 XR 设备或模拟器获取该关节的变换矩阵（`gfx::Transform`）。**
9. **为了将这个变换矩阵传递回 JavaScript，`transformationMatrixToDOMFloat32Array` 函数会被调用，将 `gfx::Transform` 转换为 `DOMFloat32Array`。**
10. **JavaScript 代码接收到 `DOMFloat32Array`，并可能用于更新场景中手的渲染模型。**

如果在上述任何步骤中出现错误，例如传递了错误的关节名称，或者底层的变换矩阵数据异常，都可能导致 `xr_utils.cc` 中的断言失败或逻辑错误，从而成为调试的线索。 开发者可以通过查看 Chromium 的日志、设置断点等方式，追踪到这些工具函数被调用的过程，从而定位问题。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_utils.h"

#include <cmath>

#include "third_party/blink/renderer/bindings/modules/v8/v8_union_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/core/geometry/dom_point_read_only.h"
#include "third_party/blink/renderer/modules/webgl/webgl2_rendering_context.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

DOMFloat32Array* transformationMatrixToDOMFloat32Array(
    const gfx::Transform& matrix) {
  float array[16];
  matrix.GetColMajorF(array);
  return DOMFloat32Array::Create(array);
}

gfx::Transform DOMFloat32ArrayToTransform(DOMFloat32Array* m) {
  DCHECK_EQ(m->length(), 16u);
  return gfx::Transform::ColMajorF(m->Data());
}

gfx::Transform WTFFloatVectorToTransform(const Vector<float>& m) {
  DCHECK_EQ(m.size(), 16u);
  return gfx::Transform::ColMajorF(m.data());
}

// Normalize to have length = 1.0
DOMPointReadOnly* makeNormalizedQuaternion(double x,
                                           double y,
                                           double z,
                                           double w) {
  double length = std::sqrt((x * x) + (y * y) + (z * z) + (w * w));
  if (length == 0.0) {
    // Return a default value instead of crashing.
    return DOMPointReadOnly::Create(0.0, 0.0, 0.0, 1.0);
  }
  return DOMPointReadOnly::Create(x / length, y / length, z / length,
                                  w / length);
}

WebGLRenderingContextBase* webglRenderingContextBaseFromUnion(
    const V8XRWebGLRenderingContext* context) {
  DCHECK(context);
  switch (context->GetContentType()) {
    case V8XRWebGLRenderingContext::ContentType::kWebGL2RenderingContext:
      return context->GetAsWebGL2RenderingContext();
    case V8XRWebGLRenderingContext::ContentType::kWebGLRenderingContext:
      return context->GetAsWebGLRenderingContext();
  }
  NOTREACHED();
}

std::optional<device::Pose> CreatePose(const gfx::Transform& matrix) {
  return device::Pose::Create(matrix);
}

device::mojom::blink::XRHandJoint StringToMojomHandJoint(
    const String& hand_joint_string) {
  if (hand_joint_string == "wrist") {
    return device::mojom::blink::XRHandJoint::kWrist;
  } else if (hand_joint_string == "thumb-metacarpal") {
    return device::mojom::blink::XRHandJoint::kThumbMetacarpal;
  } else if (hand_joint_string == "thumb-phalanx-proximal") {
    return device::mojom::blink::XRHandJoint::kThumbPhalanxProximal;
  } else if (hand_joint_string == "thumb-phalanx-distal") {
    return device::mojom::blink::XRHandJoint::kThumbPhalanxDistal;
  } else if (hand_joint_string == "thumb-tip") {
    return device::mojom::blink::XRHandJoint::kThumbTip;
  } else if (hand_joint_string == "index-finger-metacarpal") {
    return device::mojom::blink::XRHandJoint::kIndexFingerMetacarpal;
  } else if (hand_joint_string == "index-finger-phalanx-proximal") {
    return device::mojom::blink::XRHandJoint::kIndexFingerPhalanxProximal;
  } else if (hand_joint_string == "index-finger-phalanx-intermediate") {
    return device::mojom::blink::XRHandJoint::kIndexFingerPhalanxIntermediate;
  } else if (hand_joint_string == "index-finger-phalanx-distal") {
    return device::mojom::blink::XRHandJoint::kIndexFingerPhalanxDistal;
  } else if (hand_joint_string == "index-finger-tip") {
    return device::mojom::blink::XRHandJoint::kIndexFingerTip;
  } else if (hand_joint_string == "middle-finger-metacarpal") {
    return device::mojom::blink::XRHandJoint::kMiddleFingerMetacarpal;
  } else if (hand_joint_string == "middle-finger-phalanx-proximal") {
    return device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxProximal;
  } else if (hand_joint_string == "middle-finger-phalanx-intermediate") {
    return device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxIntermediate;
  } else if (hand_joint_string == "middle-finger-phalanx-distal") {
    return device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxDistal;
  } else if (hand_joint_string == "middle-finger-tip") {
    return device::mojom::blink::XRHandJoint::kMiddleFingerTip;
  } else if (hand_joint_string == "ring-finger-metacarpal") {
    return device::mojom::blink::XRHandJoint::kRingFingerMetacarpal;
  } else if (hand_joint_string == "ring-finger-phalanx-proximal") {
    return device::mojom::blink::XRHandJoint::kRingFingerPhalanxProximal;
  } else if (hand_joint_string == "ring-finger-phalanx-intermediate") {
    return device::mojom::blink::XRHandJoint::kRingFingerPhalanxIntermediate;
  } else if (hand_joint_string == "ring-finger-phalanx-distal") {
    return device::mojom::blink::XRHandJoint::kRingFingerPhalanxDistal;
  } else if (hand_joint_string == "ring-finger-tip") {
    return device::mojom::blink::XRHandJoint::kRingFingerTip;
  } else if (hand_joint_string == "pinky-finger-metacarpal") {
    return device::mojom::blink::XRHandJoint::kPinkyFingerMetacarpal;
  } else if (hand_joint_string == "pinky-finger-phalanx-proximal") {
    return device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxProximal;
  } else if (hand_joint_string == "pinky-finger-phalanx-intermediate") {
    return device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxIntermediate;
  } else if (hand_joint_string == "pinky-finger-phalanx-distal") {
    return device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxDistal;
  } else if (hand_joint_string == "pinky-finger-tip") {
    return device::mojom::blink::XRHandJoint::kPinkyFingerTip;
  }

  NOTREACHED();
}

V8XRHandJoint::Enum MojomHandJointToV8Enum(
    device::mojom::blink::XRHandJoint hand_joint) {
  switch (hand_joint) {
    case device::mojom::blink::XRHandJoint::kWrist:
      return V8XRHandJoint::Enum::kWrist;
    case device::mojom::blink::XRHandJoint::kThumbMetacarpal:
      return V8XRHandJoint::Enum::kThumbMetacarpal;
    case device::mojom::blink::XRHandJoint::kThumbPhalanxProximal:
      return V8XRHandJoint::Enum::kThumbPhalanxProximal;
    case device::mojom::blink::XRHandJoint::kThumbPhalanxDistal:
      return V8XRHandJoint::Enum::kThumbPhalanxDistal;
    case device::mojom::blink::XRHandJoint::kThumbTip:
      return V8XRHandJoint::Enum::kThumbTip;
    case device::mojom::blink::XRHandJoint::kIndexFingerMetacarpal:
      return V8XRHandJoint::Enum::kIndexFingerMetacarpal;
    case device::mojom::blink::XRHandJoint::kIndexFingerPhalanxProximal:
      return V8XRHandJoint::Enum::kIndexFingerPhalanxProximal;
    case device::mojom::blink::XRHandJoint::kIndexFingerPhalanxIntermediate:
      return V8XRHandJoint::Enum::kIndexFingerPhalanxIntermediate;
    case device::mojom::blink::XRHandJoint::kIndexFingerPhalanxDistal:
      return V8XRHandJoint::Enum::kIndexFingerPhalanxDistal;
    case device::mojom::blink::XRHandJoint::kIndexFingerTip:
      return V8XRHandJoint::Enum::kIndexFingerTip;
    case device::mojom::blink::XRHandJoint::kMiddleFingerMetacarpal:
      return V8XRHandJoint::Enum::kMiddleFingerMetacarpal;
    case device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxProximal:
      return V8XRHandJoint::Enum::kMiddleFingerPhalanxProximal;
    case device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxIntermediate:
      return V8XRHandJoint::Enum::kMiddleFingerPhalanxIntermediate;
    case device::mojom::blink::XRHandJoint::kMiddleFingerPhalanxDistal:
      return V8XRHandJoint::Enum::kMiddleFingerPhalanxDistal;
    case device::mojom::blink::XRHandJoint::kMiddleFingerTip:
      return V8XRHandJoint::Enum::kMiddleFingerTip;
    case device::mojom::blink::XRHandJoint::kRingFingerMetacarpal:
      return V8XRHandJoint::Enum::kRingFingerMetacarpal;
    case device::mojom::blink::XRHandJoint::kRingFingerPhalanxProximal:
      return V8XRHandJoint::Enum::kRingFingerPhalanxProximal;
    case device::mojom::blink::XRHandJoint::kRingFingerPhalanxIntermediate:
      return V8XRHandJoint::Enum::kRingFingerPhalanxIntermediate;
    case device::mojom::blink::XRHandJoint::kRingFingerPhalanxDistal:
      return V8XRHandJoint::Enum::kRingFingerPhalanxDistal;
    case device::mojom::blink::XRHandJoint::kRingFingerTip:
      return V8XRHandJoint::Enum::kRingFingerTip;
    case device::mojom::blink::XRHandJoint::kPinkyFingerMetacarpal:
      return V8XRHandJoint::Enum::kPinkyFingerMetacarpal;
    case device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxProximal:
      return V8XRHandJoint::Enum::kPinkyFingerPhalanxProximal;
    case device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxIntermediate:
      return V8XRHandJoint::Enum::kPinkyFingerPhalanxIntermediate;
    case device::mojom::blink::XRHandJoint::kPinkyFingerPhalanxDistal:
      return V8XRHandJoint::Enum::kPinkyFingerPhalanxDistal;
    case device::mojom::blink::XRHandJoint::kPinkyFingerTip:
      return V8XRHandJoint::Enum::kPinkyFingerTip;
  }
  NOTREACHED();
}

std::optional<device::mojom::XRSessionFeature> StringToXRSessionFeature(
    const String& feature_string) {
  if (feature_string == "viewer") {
    return device::mojom::XRSessionFeature::REF_SPACE_VIEWER;
  } else if (feature_string == "local") {
    return device::mojom::XRSessionFeature::REF_SPACE_LOCAL;
  } else if (feature_string == "local-floor") {
    return device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR;
  } else if (feature_string == "bounded-floor") {
    return device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR;
  } else if (feature_string == "unbounded") {
    return device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED;
  } else if (feature_string == "hit-test") {
    return device::mojom::XRSessionFeature::HIT_TEST;
  } else if (feature_string == "anchors") {
    return device::mojom::XRSessionFeature::ANCHORS;
  } else if (feature_string == "dom-overlay") {
    return device::mojom::XRSessionFeature::DOM_OVERLAY;
  } else if (feature_string == "light-estimation") {
    return device::mojom::XRSessionFeature::LIGHT_ESTIMATION;
  } else if (feature_string == "camera-access") {
    return device::mojom::XRSessionFeature::CAMERA_ACCESS;
  } else if (feature_string == "plane-detection") {
    return device::mojom::XRSessionFeature::PLANE_DETECTION;
  } else if (feature_string == "depth-sensing") {
    return device::mojom::XRSessionFeature::DEPTH;
  } else if (feature_string == "image-tracking") {
    return device::mojom::XRSessionFeature::IMAGE_TRACKING;
  } else if (feature_string == "hand-tracking") {
    return device::mojom::XRSessionFeature::HAND_INPUT;
  } else if (feature_string == "secondary-views") {
    return device::mojom::XRSessionFeature::SECONDARY_VIEWS;
  } else if (feature_string == "layers") {
    return device::mojom::XRSessionFeature::LAYERS;
  } else if (feature_string == "front-facing") {
    return device::mojom::XRSessionFeature::FRONT_FACING;
  } else if (feature_string == "webgpu") {
    return device::mojom::XRSessionFeature::WEBGPU;
  }

  return std::nullopt;
}

String XRSessionFeatureToString(device::mojom::XRSessionFeature feature) {
  switch (feature) {
    case device::mojom::XRSessionFeature::REF_SPACE_VIEWER:
      return "viewer";
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL:
      return "local";
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR:
      return "local-floor";
    case device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR:
      return "bounded-floor";
    case device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED:
      return "unbounded";
    case device::mojom::XRSessionFeature::DOM_OVERLAY:
      return "dom-overlay";
    case device::mojom::XRSessionFeature::HIT_TEST:
      return "hit-test";
    case device::mojom::XRSessionFeature::LIGHT_ESTIMATION:
      return "light-estimation";
    case device::mojom::XRSessionFeature::ANCHORS:
      return "anchors";
    case device::mojom::XRSessionFeature::CAMERA_ACCESS:
      return "camera-access";
    case device::mojom::XRSessionFeature::PLANE_DETECTION:
      return "plane-detection";
    case device::mojom::XRSessionFeature::DEPTH:
      return "depth-sensing";
    case device::mojom::XRSessionFeature::IMAGE_TRACKING:
      return "image-tracking";
    case device::mojom::XRSessionFeature::HAND_INPUT:
      return "hand-tracking";
    case device::mojom::XRSessionFeature::SECONDARY_VIEWS:
      return "secondary-views";
    case device::mojom::XRSessionFeature::LAYERS:
      return "layers";
    case device::mojom::XRSessionFeature::FRONT_FACING:
      return "front-facing";
    case device::mojom::XRSessionFeature::WEBGPU:
      return "webgpu";
  }

  return "";
}

bool IsFeatureEnabledForContext(device::mojom::XRSessionFeature feature,
                                const ExecutionContext* context) {
  switch (feature) {
    case device::mojom::XRSessionFeature::PLANE_DETECTION:
      return RuntimeEnabledFeatures::WebXRPlaneDetectionEnabled(context);
    case device::mojom::XRSessionFeature::IMAGE_TRACKING:
      return RuntimeEnabledFeatures::WebXRImageTrackingEnabled(context);
    case device::mojom::XRSessionFeature::HAND_INPUT:
      return RuntimeEnabledFeatures::WebXRHandInputEnabled(context);
    case device::mojom::XRSessionFeature::LAYERS:
      return RuntimeEnabledFeatures::WebXRLayersEnabled(context);
    case device::mojom::XRSessionFeature::WEBGPU:
      return RuntimeEnabledFeatures::WebXRGPUBindingEnabled(context);
    case device::mojom::XRSessionFeature::FRONT_FACING:
      return RuntimeEnabledFeatures::WebXRFrontFacingEnabled(context);
    case device::mojom::XRSessionFeature::HIT_TEST:
    case device::mojom::XRSessionFeature::LIGHT_ESTIMATION:
    case device::mojom::XRSessionFeature::ANCHORS:
    case device::mojom::XRSessionFeature::CAMERA_ACCESS:
    case device::mojom::XRSessionFeature::DEPTH:
    case device::mojom::XRSessionFeature::REF_SPACE_VIEWER:
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL:
    case device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR:
    case device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR:
    case device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED:
    case device::mojom::XRSessionFeature::DOM_OVERLAY:
    case device::mojom::XRSessionFeature::SECONDARY_VIEWS:
      return true;
  }
}

}  // namespace blink

"""

```