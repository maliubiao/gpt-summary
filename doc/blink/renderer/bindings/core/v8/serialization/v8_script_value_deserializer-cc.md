Response:
My thinking process to answer the request about `v8_script_value_deserializer.cc` goes like this:

1. **Understand the Core Function:** The filename itself is a huge clue. "deserializer" strongly suggests it's about taking serialized data and turning it back into usable objects. The "v8_script_value" part indicates it's dealing with JavaScript values within the V8 engine (the JavaScript engine used by Chromium). The path `blink/renderer/bindings/core/v8/serialization/` reinforces this – it's about the interface between Blink's rendering engine and V8, specifically during the process of converting data to and from a serialized format.

2. **Scan for Key Includes and Classes:**  I quickly scan the included headers. They reveal the types of data and operations the deserializer handles:
    * **Serialization:** `serialization_tag.h`, `trailer_reader.h`, `unpacked_serialized_script_value.h` point to the mechanics of serialization.
    * **V8 Integration:**  Headers like `v8.h`, `to_v8_traits.h`, and the `v8_` prefixed headers for various DOM objects (like `v8_blob.h`, `v8_dom_exception.h`, etc.) confirm it's about converting serialized data into V8 JavaScript objects.
    * **DOM Objects:** The long list of `v8_` prefixed headers for DOM types (Blob, DOMMatrix, DOMPoint, File, ImageBitmap, etc.) shows this deserializer is responsible for reconstructing these specific types of web platform objects.
    * **Blink Internals:** Headers like `dom_exception.h`, `blob.h`, `file.h`, and others in the `core` directory confirm that this code lives within the Blink rendering engine.
    * **Streams API:** `v8_readable_stream.h`, `v8_writable_stream.h`, `v8_transform_stream.h` and their corresponding core headers indicate handling of the Streams API.
    * **Utility/Base:**  `base/feature_list.h`, `base/time/time.h`, and `base/numerics/checked_math.h` suggest the use of common Chromium utilities.

3. **Identify the Primary Class and its Role:**  The core class is `V8ScriptValueDeserializer`. Its constructor and the `Deserialize()` method are the main entry points. The constructor takes serialized data and configuration, while `Deserialize()` performs the actual conversion.

4. **Connect Deserialization to Web Platform Features:**  Now I link the identified DOM object headers to their corresponding JavaScript/HTML/CSS features:
    * **`Blob` and `File`:**  Related to file uploads, `FileReader`, `URL.createObjectURL()`, `<input type="file">`.
    * **`ImageBitmap` and `ImageData`:** Canvas API (`<canvas>`), image manipulation.
    * **`DOMPoint`, `DOMRect`, `DOMMatrix`:** Geometry manipulation, potentially related to CSS transforms, SVG, or the Geometry APIs.
    * **`MessagePort`:** The Channel Messaging API (`postMessage`).
    * **Streams API (`ReadableStream`, `WritableStream`, `TransformStream`):**  Asynchronous data processing, piping, backpressure handling.
    * **`DOMException`:** Represents errors that occur during web API usage.
    * **`OffscreenCanvas`:** Rendering graphics in a worker thread or outside the main document.
    * **`FencedFrameConfig`:**  Related to the Privacy Sandbox and Fenced Frames, allowing for isolated content rendering.

5. **Consider the "Why":**  Why is deserialization needed?  The key use cases are:
    * **`postMessage()`:**  Sending complex data between different browsing contexts (iframes, workers).
    * **`structuredClone()`:**  Creating deep copies of JavaScript objects.
    * **Navigation:**  Passing state during navigation.
    * **Service Workers:**  Storing and retrieving data.
    * **Cache API:**  Storing responses.

6. **Infer Logic and Potential Issues:** Based on the class name and the types being deserialized, I can infer some logical steps:
    * **Reading a Version Header:**  The code explicitly mentions versioning to handle changes in the serialization format over time.
    * **Handling Different Data Types:** The `switch` statement in `ReadDOMObject` shows how the deserializer dispatches based on the `SerializationTag` to create the correct object type.
    * **Transferring Resources:** The `Transfer()` method suggests handling transferable objects (like `ArrayBuffer`, `MessagePort`, `ImageBitmap`), avoiding unnecessary copying.
    * **Error Handling:**  The use of `ExceptionState` indicates that errors can occur during deserialization.

7. **Think About User/Developer Errors:** Common mistakes when dealing with serialization/deserialization include:
    * **Mismatched Serialization/Deserialization:**  Trying to deserialize data serialized with an incompatible version.
    * **Transferring Already-Transferred Objects:**  Attempting to reuse a transferable object after it has been transferred.
    * **Incorrect Data Types:**  The serialized data doesn't match the expected structure.
    * **Security Issues:**  Potentially malicious serialized data could exploit vulnerabilities (though Blink likely has measures to mitigate this).

8. **Construct a Hypothetical Scenario (Debugging Clue):** To illustrate how one might end up debugging this code, I imagine a simple `postMessage` scenario where a complex object with transferable resources is sent between an iframe and its parent. If the deserialization fails in the iframe, the developer might step through the code and land in this deserializer.

9. **Summarize the Functionality:** Finally, I synthesize the information into a concise summary highlighting the core purpose, relationships to web features, potential issues, and debugging context. I pay attention to the specific request to summarize the functionality for the *first part* of the file.

By following these steps, I can break down the code's purpose and relate it to broader web development concepts, leading to a comprehensive and informative answer.
## 归纳 blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.cc 的功能 (第 1 部分)

这个文件的主要功能是**反序列化** (deserialization) 通过 Chromium Blink 引擎的 V8 JavaScript 引擎序列化后的 JavaScript 值。 换句话说，它负责将之前被转换为字节流的 JavaScript 数据重新构建成可以在 JavaScript 环境中使用的对象。

**具体来说，第 1 部分代码涵盖了以下关键方面：**

1. **头文件和命名空间:** 引入了必要的头文件，包括 V8 相关的头文件、Blink 内部的 DOM 对象定义、以及用于序列化和反序列化的特定头文件。定义了 `blink` 命名空间。

2. **版本控制:** 引入了“Blink-side”序列化版本控制的概念，允许 Blink 在 V8 提供的序列化机制之外添加自己的版本控制。这使得 Blink 能够在不破坏 V8 序列化兼容性的前提下，对序列化格式进行独立演进。
   - 定义了 `kMinVersionForSeparateEnvelope`，标志着 Blink 开始使用独立的版本信封的最低版本。
   - 提供了 `ReadVersionEnvelope` 函数，用于读取并解析 Blink 版本的信封信息。

3. **反序列化器类 `V8ScriptValueDeserializer` 的定义和初始化:**
   - 定义了主要的 `V8ScriptValueDeserializer` 类，负责执行反序列化操作。
   - 提供了多个构造函数，用于处理不同形式的序列化数据输入，包括 `SerializedScriptValue` 和 `UnpackedSerializedScriptValue`。
   - 初始化了内部的 V8 反序列化器 `deserializer_`。
   - 存储了传递过来的 transferable 对象，如 `message_ports` 和 `blob_info`。

4. **主要的 `Deserialize()` 方法:**
   - 这是反序列化的入口点。
   - 使用 V8 的 `EscapableHandleScope` 和 `TryCatch` 进行 V8 对象管理和异常处理。
   - 调用 `ReadVersionEnvelope` 读取 Blink 版本信息。
   - 调用 V8 反序列化器的 `ReadHeader()` 方法读取 V8 序列化头信息。
   - 如果没有读取到 Blink 版本信息，则使用 V8 头的版本信息。
   - 调用 `Transfer()` 方法处理 transferable 对象的转移。
   - 调用 V8 反序列化器的 `ReadValue()` 方法实际读取并反序列化 JavaScript 值。
   - 返回反序列化后的 V8 `Local<v8::Value>` 对象。

5. **处理 transferable 对象 (`Transfer()` 方法):**
   -  负责处理在序列化过程中被标记为 "transferable" 的对象，例如 `ArrayBuffer` 和 `MessagePort`。
   -  对于 `ArrayBuffer` (包括 `SharedArrayBuffer`)，将其包装成 V8 对象并告知 V8 反序列化器进行转移，避免数据拷贝。
   -  特殊处理了 `serialized_script_value_->GetStreams()`，可能用于处理 Streams API 相关的 transferable 对象。

6. **读取基本类型和字符串:**
   - 提供了 `ReadUnguessableToken()` 用于读取 `base::UnguessableToken` 类型。
   - 提供了 `ReadUTF8String()` 用于读取 UTF-8 编码的字符串。

7. **读取 DOM 对象 (`ReadDOMObject()` 方法):**
   -  这是一个核心方法，负责反序列化各种 Blink 特定的 DOM 对象。
   -  通过 `SerializationTag` 来识别要反序列化的对象类型。
   -  包含了 `switch` 语句，针对不同的 `SerializationTag` 执行不同的反序列化逻辑。
   -  目前第 1 部分代码中，`ReadDOMObject()` 方法已经涵盖了对以下 DOM 对象的反序列化逻辑：
     - `Blob`
     - `File` (部分)
     - `FileList`
     - `ImageBitmap`
     - `ImageData`
     - `DOMPoint`
     - `DOMPointReadOnly`
     - `DOMRect`
     - `DOMRectReadOnly` (仅调用 `ReadDOMRectReadOnly()`)
     - `DOMQuad`
     - `DOMMatrix` (2D 和 3D)
     - `DOMMatrixReadOnly` (2D 和 3D)
     - `MessagePort`
     - `MojoHandle`
     - `OffscreenCanvas`
     - `ReadableStream`
     - `WritableStream`
     - `TransformStream`
     - `DOMException`
     - `FencedFrameConfig`

**与 Javascript, HTML, CSS 功能的关系举例说明:**

* **Javascript 和 `postMessage`:**  当使用 `window.postMessage()` 在不同的 browsing contexts (例如 iframe 或 worker) 之间传递复杂数据时，这些数据需要被序列化和反序列化。 `V8ScriptValueDeserializer` 就负责在接收端将序列化的数据重新构建成 JavaScript 对象。
    * **假设输入:**  一个包含 `File` 对象和 `ArrayBuffer` 的序列化数据。
    * **输出:**  反序列化后的 JavaScript 对象，其中包含了 `File` 对象和 `ArrayBuffer` 的实例。

* **Javascript 和 `structuredClone`:** `structuredClone()` 函数允许创建 JavaScript 对象的深拷贝。这个过程内部也依赖于序列化和反序列化机制。
    * **假设输入:**  一个包含循环引用的 JavaScript 对象的序列化数据。
    * **输出:**  反序列化后的 JavaScript 对象，循环引用被正确重建。

* **Javascript 和 Streams API:**  当通过 `postMessage` 传递 `ReadableStream` 或 `WritableStream` 时，这些 stream 的状态和管道连接需要被序列化和反序列化。
    * **假设输入:**  一个 `ReadableStream` 的序列化数据，其中包含了 stream 的内部状态和管道连接信息。
    * **输出:**  反序列化后的 `ReadableStream` 对象，可以继续从其中读取数据。

* **HTML 和 `<input type="file">`:** 当用户通过 `<input type="file">` 选择文件后，可以通过 JavaScript 获取到 `File` 对象。当需要将这个 `File` 对象传递给 Web Worker 或进行持久化存储时，就需要进行序列化和反序列化。 `V8ScriptValueDeserializer` 负责重建这个 `File` 对象。

* **CSS 和 Geometry API (例如 `DOMMatrix`)**:  CSS Transforms 可以创建矩阵，JavaScript 可以通过 Geometry API (例如 `DOMMatrix`) 来操作这些矩阵。当需要存储或传递这些矩阵信息时，就需要序列化和反序列化。

**逻辑推理的假设输入与输出 (以 `ReadDOMPointTag` 为例):**

* **假设输入 (序列化数据):**  包含 `kDOMPointTag` 标签以及四个 double 类型的值，分别代表 x, y, z, w 坐标。 例如： `[... kDOMPointTag, 1.0, 2.5, 0.0, 1.0 ...]`
* **输出 (反序列化后的对象):**  一个 `DOMPoint` 对象的实例，其 x 属性为 1.0，y 属性为 2.5，z 属性为 0.0，w 属性为 1.0。

**涉及用户或者编程常见的使用错误举例说明:**

* **尝试反序列化不兼容版本的数据:** 如果发送端使用的 Blink 版本与接收端使用的 Blink 版本不兼容，导致序列化格式不一致，反序列化可能会失败。
    * **用户操作:**  用户在旧版本的浏览器标签页中创建了一些数据，并通过 `postMessage` 发送给新版本浏览器标签页。
    * **错误:**  `V8ScriptValueDeserializer` 可能会因为无法识别旧版本的序列化格式而抛出错误或返回 `nullptr`。

* **在 transferable 对象被转移后尝试访问它:**  一旦一个 transferable 对象 (如 `ArrayBuffer` 或 `MessagePort`) 被转移，它在原始上下文中的状态就会失效。如果在反序列化后，原始上下文仍然尝试访问这个对象，就会导致错误。
    * **用户操作:**  用户通过 `postMessage` 发送一个 `ArrayBuffer`，并在发送后尝试修改这个 `ArrayBuffer` 的内容。
    * **错误:**  修改操作不会影响接收端反序列化后的 `ArrayBuffer`，并且在某些情况下可能会导致程序崩溃或未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索 (以 `postMessage` 传递 `File` 对象为例):**

1. **用户在网页上操作，例如点击 `<input type="file">` 元素选择了一个文件。**
2. **JavaScript 代码获取到用户选择的 `File` 对象。**
3. **JavaScript 代码调用 `window.postMessage(fileObject, targetOrigin)` 将 `File` 对象发送到另一个 browsing context (例如 iframe)。**
4. **在发送端，`File` 对象会被 Blink 的序列化机制处理，转换为字节流。**  这个过程可能涉及到 `blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.cc` 文件。
5. **在接收端的 browsing context 中，接收到 `message` 事件。**
6. **Blink 引擎开始处理接收到的消息，并尝试反序列化 `data` 属性中的内容。**
7. **`V8ScriptValueDeserializer` 被创建并调用，负责将接收到的字节流还原成 JavaScript 对象。**
8. **`Deserialize()` 方法被调用，开始读取版本信息和数据。**
9. **当读取到 `kFileTag` 时，`ReadDOMObject()` 方法会被调用。**
10. **`ReadFile()` 方法会被调用，根据序列化数据重建 `File` 对象。**

如果在第 10 步 `ReadFile()` 过程中出现问题，例如读取到的数据不完整或格式错误，开发者可能会在此处设置断点进行调试，查看序列化数据的内容以及 `V8ScriptValueDeserializer` 的状态，从而定位问题原因。

**总结 (针对第 1 部分):**

总而言之，`v8_script_value_deserializer.cc` 的第 1 部分主要负责**初始化反序列化过程，读取基本的序列化信息 (如版本号)，并开始反序列化各种内置的 DOM 对象**。 它建立了反序列化的基础框架，并处理了大量核心的 Web 平台对象类型的重建工作。 这部分代码是连接序列化数据和可用的 JavaScript 对象之间的关键桥梁。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.h"

#include <limits>
#include <optional>

#include "base/feature_list.h"
#include "base/numerics/checked_math.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/fenced_frame/fenced_frame_utils.h"
#include "third_party/blink/public/platform/web_blob_info.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/trailer_reader.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/unpacked_serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_blob.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_matrix_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_init.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_point_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_quad.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_fenced_frame_config.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_file_list.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_data.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_message_port.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_mojo_handle.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_offscreen_canvas.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_readable_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_transform_stream.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_writable_stream.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/fileapi/file_list.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix.h"
#include "third_party/blink/renderer/core/geometry/dom_matrix_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_point.h"
#include "third_party/blink/renderer/core/geometry/dom_point_read_only.h"
#include "third_party/blink/renderer/core/geometry/dom_quad.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/geometry/dom_rect_read_only.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/inspector/inspector_audits_issue.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/mojo/mojo_handle.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/readable_stream_transferring_optimizer.h"
#include "third_party/blink/renderer/core/streams/transform_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_shared_array_buffer.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/file_metadata.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"

namespace blink {

namespace {

// The "Blink-side" serialization version, which defines how Blink will behave
// during the serialization process. The serialization format has two
// "envelopes": an outer one controlled by Blink and an inner one by V8.
//
// They are formatted as follows:
// [version tag] [Blink version] [version tag] [v8 version] ...
//
// Before version 16, there was only a single envelope and the version number
// for both parts was always equal.
//
// See also V8ScriptValueDeserializer.cpp.
const uint32_t kMinVersionForSeparateEnvelope = 16;

// Returns the number of bytes consumed reading the Blink version envelope, and
// sets |*version| to the version. If no Blink envelope was detected, zero is
// returned.
size_t ReadVersionEnvelope(SerializedScriptValue* serialized_script_value,
                           uint32_t* out_version) {
  const uint8_t* raw_data = serialized_script_value->Data();
  const size_t length = serialized_script_value->DataLengthInBytes();
  if (!length || raw_data[0] != kVersionTag)
    return 0;

  // Read a 32-bit unsigned integer from varint encoding.
  uint32_t version = 0;
  size_t i = 1;
  unsigned shift = 0;
  bool has_another_byte;
  do {
    if (i >= length)
      return 0;
    uint8_t byte = raw_data[i];
    if (shift < 32) [[likely]] {
      version |= static_cast<uint32_t>(byte & 0x7f) << shift;
      shift += 7;
    }
    has_another_byte = byte & 0x80;
    i++;
  } while (has_another_byte);

  // If the version in the envelope is too low, this was not a Blink version
  // envelope.
  if (version < kMinVersionForSeparateEnvelope)
    return 0;

  // These versions expect a trailer offset in the envelope.
  if (version >= TrailerReader::kMinWireFormatVersion) {
    static constexpr size_t kTrailerOffsetDataSize =
        1 + sizeof(uint64_t) + sizeof(uint32_t);
    DCHECK_LT(i, std::numeric_limits<size_t>::max() - kTrailerOffsetDataSize);
    i += kTrailerOffsetDataSize;
    if (i >= length)
      return 0;
  }

  // Otherwise, we did read the envelope. Hurray!
  *out_version = version;
  return i;
}

MessagePort* CreateEntangledPort(ScriptState* script_state,
                                 const MessagePortChannel& channel) {
  MessagePort* const port =
      MakeGarbageCollected<MessagePort>(*ExecutionContext::From(script_state));
  port->Entangle(channel);
  return port;
}

}  // namespace

V8ScriptValueDeserializer::V8ScriptValueDeserializer(
    ScriptState* script_state,
    UnpackedSerializedScriptValue* unpacked_value,
    const Options& options)
    : V8ScriptValueDeserializer(script_state,
                                unpacked_value,
                                unpacked_value->Value(),
                                options) {}

V8ScriptValueDeserializer::V8ScriptValueDeserializer(
    ScriptState* script_state,
    scoped_refptr<SerializedScriptValue> value,
    const Options& options)
    : V8ScriptValueDeserializer(script_state,
                                nullptr,
                                std::move(value),
                                options) {
  DCHECK(!serialized_script_value_->HasPackedContents())
      << "If the provided SerializedScriptValue could contain packed contents "
         "due to transfer, then it must be unpacked before deserialization. "
         "See SerializedScriptValue::Unpack.";
}

V8ScriptValueDeserializer::V8ScriptValueDeserializer(
    ScriptState* script_state,
    UnpackedSerializedScriptValue* unpacked_value,
    scoped_refptr<SerializedScriptValue> value,
    const Options& options)
    : script_state_(script_state),
      unpacked_value_(unpacked_value),
      serialized_script_value_(value),
      deserializer_(script_state_->GetIsolate(),
                    serialized_script_value_->Data(),
                    serialized_script_value_->DataLengthInBytes(),
                    this),
      transferred_message_ports_(options.message_ports),
      blob_info_array_(options.blob_info) {
  deserializer_.SetSupportsLegacyWireFormat(true);
}

v8::Local<v8::Value> V8ScriptValueDeserializer::Deserialize() {
#if DCHECK_IS_ON()
  DCHECK(!deserialize_invoked_);
  deserialize_invoked_ = true;
#endif

  v8::Isolate* isolate = script_state_->GetIsolate();
  v8::EscapableHandleScope scope(isolate);
  v8::TryCatch try_catch(isolate);
  v8::Local<v8::Context> context = script_state_->GetContext();

  size_t version_envelope_size =
      ReadVersionEnvelope(serialized_script_value_.get(), &version_);
  if (version_envelope_size) {
    const void* blink_envelope;
    bool read_envelope = ReadRawBytes(version_envelope_size, &blink_envelope);
    DCHECK(read_envelope);
    DCHECK_GE(version_, kMinVersionForSeparateEnvelope);
  } else {
    DCHECK_EQ(version_, 0u);
  }

  bool read_header;
  if (!deserializer_.ReadHeader(context).To(&read_header))
    return v8::Null(isolate);
  DCHECK(read_header);

  // If there was no Blink envelope earlier, Blink shares the wire format
  // version from the V8 header.
  if (!version_)
    version_ = deserializer_.GetWireFormatVersion();

  // Prepare to transfer the provided transferables.
  Transfer();

  v8::Local<v8::Value> value;
  if (!deserializer_.ReadValue(context).ToLocal(&value))
    return v8::Null(isolate);
  return scope.Escape(value);
}

void V8ScriptValueDeserializer::Transfer() {
  // TODO(ricea): Make ExtendableMessageEvent store an
  // UnpackedSerializedScriptValue like MessageEvent does, and then this
  // special case won't be necessary.
  streams_ = std::move(serialized_script_value_->GetStreams());

  // There's nothing else to transfer if the deserializer was not given an
  // unpacked value.
  if (!unpacked_value_)
    return;

  // Transfer array buffers.
  const auto& array_buffers = unpacked_value_->ArrayBuffers();
  for (unsigned i = 0; i < array_buffers.size(); i++) {
    DOMArrayBufferBase* array_buffer = array_buffers.at(i);
    v8::Local<v8::Value> wrapper =
        ToV8Traits<DOMArrayBufferBase>::ToV8(script_state_, array_buffer);
    if (array_buffer->IsShared()) {
      // Crash if we are receiving a SharedArrayBuffer and this isn't allowed.
      auto* execution_context = ExecutionContext::From(script_state_);
      CHECK(execution_context->SharedArrayBufferTransferAllowed());

      DCHECK(wrapper->IsSharedArrayBuffer());
      deserializer_.TransferSharedArrayBuffer(
          i, v8::Local<v8::SharedArrayBuffer>::Cast(wrapper));
    } else {
      DCHECK(wrapper->IsArrayBuffer());
      deserializer_.TransferArrayBuffer(
          i, v8::Local<v8::ArrayBuffer>::Cast(wrapper));
    }
  }
}

bool V8ScriptValueDeserializer::ReadUnguessableToken(
    base::UnguessableToken* token_out) {
  uint64_t high;
  uint64_t low;
  if (!ReadUint64(&high) || !ReadUint64(&low))
    return false;
  std::optional<base::UnguessableToken> token =
      base::UnguessableToken::Deserialize(high, low);
  if (!token.has_value()) {
    return false;
  }
  *token_out = token.value();
  return true;
}

bool V8ScriptValueDeserializer::ReadUTF8String(String* string) {
  uint32_t utf8_length = 0;
  const void* utf8_data = nullptr;
  if (!ReadUint32(&utf8_length) || !ReadRawBytes(utf8_length, &utf8_data))
    return false;
  // SAFETY: ReadRawBytes() guarantees `utf8_data` and `utf8_length` are safe.
  *string = String::FromUTF8(UNSAFE_BUFFERS(
      base::span(reinterpret_cast<const LChar*>(utf8_data), utf8_length)));

  // Decoding must have failed; this encoding does not distinguish between null
  // and empty strings.
  return !string->IsNull();
}

ScriptWrappable* V8ScriptValueDeserializer::ReadDOMObject(
    SerializationTag tag,
    ExceptionState& exception_state) {
  if (!ExecutionContextExposesInterface(
          ExecutionContext::From(GetScriptState()), tag)) {
    return nullptr;
  }
  switch (tag) {
    case kBlobTag: {
      if (Version() < 3)
        return nullptr;
      String uuid, type;
      uint64_t size;
      if (!ReadUTF8String(&uuid) || !ReadUTF8String(&type) ||
          !ReadUint64(&size))
        return nullptr;
      auto blob_handle = GetBlobDataHandle(uuid);
      if (!blob_handle)
        return nullptr;
      return MakeGarbageCollected<Blob>(std::move(blob_handle));
    }
    case kBlobIndexTag: {
      if (Version() < 6 || !blob_info_array_)
        return nullptr;
      uint32_t index = 0;
      if (!ReadUint32(&index) || index >= blob_info_array_->size())
        return nullptr;
      const WebBlobInfo& info = (*blob_info_array_)[index];
      auto blob_handle = info.GetBlobHandle();
      if (!blob_handle)
        return nullptr;
      return MakeGarbageCollected<Blob>(std::move(blob_handle));
    }
    case kFileTag:
      return ReadFile();
    case kFileIndexTag:
      return ReadFileIndex();
    case kFileListTag:
    case kFileListIndexTag: {
      // This does not presently deduplicate a File object and its entry in a
      // FileList, which is non-standard behavior.
      uint32_t length;
      if (!ReadUint32(&length))
        return nullptr;
      auto* file_list = MakeGarbageCollected<FileList>();
      for (uint32_t i = 0; i < length; i++) {
        if (File* file = (tag == kFileListTag ? ReadFile() : ReadFileIndex())) {
          file_list->Append(file);
        } else {
          return nullptr;
        }
      }
      return file_list;
    }
    case kImageBitmapTag: {
      SerializedPredefinedColorSpace predefined_color_space =
          SerializedPredefinedColorSpace::kSRGB;
      Vector<double> sk_color_space;
      SerializedPixelFormat canvas_pixel_format =
          SerializedPixelFormat::kNative8_LegacyObsolete;
      SerializedOpacityMode canvas_opacity_mode =
          SerializedOpacityMode::kOpaque;
      SerializedImageOrientation image_orientation =
          SerializedImageOrientation::kTopLeft;
      uint32_t origin_clean = 0, is_premultiplied = 0, width = 0, height = 0,
               byte_length = 0;
      const void* pixels = nullptr;
      if (Version() >= 18) {
        // read the list of key pair values for color settings, etc.
        bool is_done = false;
        do {
          ImageSerializationTag image_tag;
          if (!ReadUint32Enum<ImageSerializationTag>(&image_tag))
            return nullptr;
          switch (image_tag) {
            case ImageSerializationTag::kEndTag:
              is_done = true;
              break;
            case ImageSerializationTag::kPredefinedColorSpaceTag:
              if (!ReadUint32Enum<SerializedPredefinedColorSpace>(
                      &predefined_color_space)) {
                return nullptr;
              }
              break;
            case ImageSerializationTag::kParametricColorSpaceTag:
              sk_color_space.resize(kSerializedParametricColorSpaceLength);
              for (double& value : sk_color_space) {
                if (!ReadDouble(&value))
                  return nullptr;
              }
              break;
            case ImageSerializationTag::kCanvasPixelFormatTag:
              if (!ReadUint32Enum<SerializedPixelFormat>(&canvas_pixel_format))
                return nullptr;
              break;
            case ImageSerializationTag::kCanvasOpacityModeTag:
              if (!ReadUint32Enum<SerializedOpacityMode>(&canvas_opacity_mode))
                return nullptr;
              break;
            case ImageSerializationTag::kOriginCleanTag:
              if (!ReadUint32(&origin_clean) || origin_clean > 1)
                return nullptr;
              break;
            case ImageSerializationTag::kIsPremultipliedTag:
              if (!ReadUint32(&is_premultiplied) || is_premultiplied > 1)
                return nullptr;
              break;
            case ImageSerializationTag::kImageOrientationTag:
              if (!ReadUint32Enum<SerializedImageOrientation>(
                      &image_orientation))
                return nullptr;
              break;
            case ImageSerializationTag::kImageDataStorageFormatTag:
              // Does not apply to ImageBitmap.
              return nullptr;
          }
        } while (!is_done);
      } else if (!ReadUint32(&origin_clean) || origin_clean > 1 ||
                 !ReadUint32(&is_premultiplied) || is_premultiplied > 1) {
        return nullptr;
      }
      if (!ReadUint32(&width) || !ReadUint32(&height) ||
          !ReadUint32(&byte_length) || !ReadRawBytes(byte_length, &pixels))
        return nullptr;
      SerializedImageBitmapSettings settings(
          predefined_color_space, sk_color_space, canvas_pixel_format,
          canvas_opacity_mode, is_premultiplied, image_orientation);
      SkImageInfo info = settings.GetSkImageInfo(width, height);
      base::CheckedNumeric<uint32_t> computed_byte_length =
          info.computeMinByteSize();
      if (!computed_byte_length.IsValid() ||
          computed_byte_length.ValueOrDie() != byte_length)
        return nullptr;
      if (!origin_clean) {
        // Non-origin-clean ImageBitmap serialization/deserialization have
        // been deprecated.
        return nullptr;
      }
      SkPixmap pixmap(info, pixels, info.minRowBytes());
      return MakeGarbageCollected<ImageBitmap>(pixmap, origin_clean,
                                               settings.GetImageOrientation());
    }
    case kImageBitmapTransferTag: {
      uint32_t index = 0;
      if (!unpacked_value_)
        return nullptr;
      const auto& transferred_image_bitmaps = unpacked_value_->ImageBitmaps();
      if (!ReadUint32(&index) || index >= transferred_image_bitmaps.size())
        return nullptr;
      return transferred_image_bitmaps[index].Get();
    }
    case kImageDataTag: {
      SerializedPredefinedColorSpace predefined_color_space =
          SerializedPredefinedColorSpace::kSRGB;
      SerializedImageDataStorageFormat image_data_storage_format =
          SerializedImageDataStorageFormat::kUint8Clamped;
      uint32_t width = 0, height = 0;
      const void* pixels = nullptr;
      if (Version() >= 18) {
        bool is_done = false;
        do {
          ImageSerializationTag image_tag;
          if (!ReadUint32Enum<ImageSerializationTag>(&image_tag))
            return nullptr;
          switch (image_tag) {
            case ImageSerializationTag::kEndTag:
              is_done = true;
              break;
            case ImageSerializationTag::kPredefinedColorSpaceTag:
              if (!ReadUint32Enum<SerializedPredefinedColorSpace>(
                      &predefined_color_space))
                return nullptr;
              break;
            case ImageSerializationTag::kImageDataStorageFormatTag:
              if (!ReadUint32Enum<SerializedImageDataStorageFormat>(
                      &image_data_storage_format))
                return nullptr;
              break;
            case ImageSerializationTag::kCanvasPixelFormatTag:
            case ImageSerializationTag::kOriginCleanTag:
            case ImageSerializationTag::kIsPremultipliedTag:
            case ImageSerializationTag::kCanvasOpacityModeTag:
            case ImageSerializationTag::kParametricColorSpaceTag:
            case ImageSerializationTag::kImageOrientationTag:
              // Does not apply to ImageData.
              return nullptr;
          }
        } while (!is_done);
      }

      uint64_t byte_length_64 = 0;
      size_t byte_length = 0;
      if (!ReadUint32(&width) || !ReadUint32(&height) ||
          !ReadUint64(&byte_length_64) ||
          !base::MakeCheckedNum(byte_length_64).AssignIfValid(&byte_length) ||
          !ReadRawBytes(byte_length, &pixels)) {
        return nullptr;
      }

      SerializedImageDataSettings settings(predefined_color_space,
                                           image_data_storage_format);
      ImageData* image_data = ImageData::ValidateAndCreate(
          width, height, std::nullopt, settings.GetImageDataSettings(),
          ImageData::ValidateAndCreateParams(), exception_state);
      if (!image_data)
        return nullptr;
      SkPixmap image_data_pixmap = image_data->GetSkPixmap();
      if (image_data_pixmap.computeByteSize() != byte_length)
        return nullptr;
      memcpy(image_data_pixmap.writable_addr(), pixels, byte_length);
      return image_data;
    }
    case kDOMPointTag: {
      double x = 0, y = 0, z = 0, w = 1;
      if (!ReadDouble(&x) || !ReadDouble(&y) || !ReadDouble(&z) ||
          !ReadDouble(&w))
        return nullptr;
      return DOMPoint::Create(x, y, z, w);
    }
    case kDOMPointReadOnlyTag: {
      double x = 0, y = 0, z = 0, w = 1;
      if (!ReadDouble(&x) || !ReadDouble(&y) || !ReadDouble(&z) ||
          !ReadDouble(&w))
        return nullptr;
      return DOMPointReadOnly::Create(x, y, z, w);
    }
    case kDOMRectTag: {
      double x = 0, y = 0, width = 0, height = 0;
      if (!ReadDouble(&x) || !ReadDouble(&y) || !ReadDouble(&width) ||
          !ReadDouble(&height))
        return nullptr;
      return DOMRect::Create(x, y, width, height);
    }
    case kDOMRectReadOnlyTag: {
      return ReadDOMRectReadOnly();
    }
    case kDOMQuadTag: {
      DOMPointInit* point_inits[4];
      for (int i = 0; i < 4; ++i) {
        auto* init = DOMPointInit::Create();
        double x = 0, y = 0, z = 0, w = 0;
        if (!ReadDouble(&x) || !ReadDouble(&y) || !ReadDouble(&z) ||
            !ReadDouble(&w))
          return nullptr;
        init->setX(x);
        init->setY(y);
        init->setZ(z);
        init->setW(w);
        point_inits[i] = init;
      }
      return DOMQuad::Create(point_inits[0], point_inits[1], point_inits[2],
                             point_inits[3]);
    }
    case kDOMMatrix2DTag: {
      double values[6];
      for (double& d : values) {
        if (!ReadDouble(&d))
          return nullptr;
      }
      return DOMMatrix::CreateForSerialization(values);
    }
    case kDOMMatrix2DReadOnlyTag: {
      double values[6];
      for (double& d : values) {
        if (!ReadDouble(&d))
          return nullptr;
      }
      return DOMMatrixReadOnly::CreateForSerialization(values);
    }
    case kDOMMatrixTag: {
      double values[16];
      for (double& d : values) {
        if (!ReadDouble(&d))
          return nullptr;
      }
      return DOMMatrix::CreateForSerialization(values);
    }
    case kDOMMatrixReadOnlyTag: {
      double values[16];
      for (double& d : values) {
        if (!ReadDouble(&d))
          return nullptr;
      }
      return DOMMatrixReadOnly::CreateForSerialization(values);
    }
    case kMessagePortTag: {
      uint32_t index = 0;
      if (!ReadUint32(&index) || !transferred_message_ports_ ||
          index >= transferred_message_ports_->size())
        return nullptr;
      return (*transferred_message_ports_)[index].Get();
    }
    case kMojoHandleTag: {
      uint32_t index = 0;
      if (!RuntimeEnabledFeatures::MojoJSEnabled() || !ReadUint32(&index) ||
          index >= serialized_script_value_->MojoHandles().size()) {
        return nullptr;
      }
      return MakeGarbageCollected<MojoHandle>(
          std::move(serialized_script_value_->MojoHandles()[index]));
    }
    case kOffscreenCanvasTransferTag: {
      uint32_t width = 0, height = 0, canvas_id = 0, client_id = 0, sink_id = 0,
               filter_quality = 0;
      if (!ReadUint32(&width) || !ReadUint32(&height) ||
          !ReadUint32(&canvas_id) || !ReadUint32(&client_id) ||
          !ReadUint32(&sink_id) || !ReadUint32(&filter_quality))
        return nullptr;
      OffscreenCanvas* canvas =
          OffscreenCanvas::Create(GetScriptState(), width, height);
      canvas->SetPlaceholderCanvasId(canvas_id);
      canvas->SetFrameSinkId(client_id, sink_id);
      if (filter_quality == 0)
        canvas->SetFilterQuality(cc::PaintFlags::FilterQuality::kNone);
      else
        canvas->SetFilterQuality(cc::PaintFlags::FilterQuality::kLow);
      return canvas;
    }
    case kReadableStreamTransferTag: {
      uint32_t index = 0;
      if (!ReadUint32(&index) || index >= streams_.size()) {
        return nullptr;
      }
      return ReadableStream::Deserialize(
          script_state_,
          CreateEntangledPort(GetScriptState(), streams_[index].channel),
          std::move(streams_[index].readable_optimizer), exception_state);
    }
    case kWritableStreamTransferTag: {
      uint32_t index = 0;
      if (!ReadUint32(&index) || index >= streams_.size()) {
        return nullptr;
      }
      return WritableStream::Deserialize(
          script_state_,
          CreateEntangledPort(GetScriptState(), streams_[index].channel),
          std::move(streams_[index].writable_optimizer), exception_state);
    }
    case kTransformStreamTransferTag: {
      uint32_t index = 0;
      if (!ReadUint32(&index) ||
          index == std::numeric_limits<decltype(index)>::max() ||
          index + 1 >= streams_.size()) {
        return nullptr;
      }
      MessagePort* const port_for_readable =
          CreateEntangledPort(GetScriptState(), streams_[index].channel);
      MessagePort* const port_for_writable =
          CreateEntangledPort(GetScriptState(), streams_[index + 1].channel);

      // https://streams.spec.whatwg.org/#ts-transfer
      // 1. Let readableRecord be !
      //    StructuredDeserializeWithTransfer(dataHolder.[[readable]], the
      //    current Realm).
      ReadableStream* readable =
          ReadableStream::Deserialize(script_state_, port_for_readable,
                                      /*optimizer=*/nullptr, exception_state);
      if (!readable)
        return nullptr;

      // 2. Let writableRecord be !
      //    StructuredDeserializeWithTransfer(dataHolder.[[writable]], the
      //    current Realm).
      WritableStream* writable =
          WritableStream::Deserialize(script_state_, port_for_writable,
                                      /*optimizer=*/nullptr, exception_state);
      if (!writable)
        return nullptr;

      // 3. Set value.[[readable]] to readableRecord.[[Deserialized]].
      // 4. Set value.[[writable]] to writableRecord.[[Deserialized]].
      // 5. Set value.[[backpressure]], value.[[backpressureChangePromise]], and
      //    value.[[controller]] to undefined.
      return MakeGarbageCollected<TransformStream>(readable, writable);
    }
    case kDOMExceptionTag: {
      // See the serialization side for |stack_unused|.
      String name, message, stack_unused;
      if (!ReadUTF8String(&name) || !ReadUTF8String(&message) ||
          !ReadUTF8String(&stack_unused)) {
        return nullptr;
      }
      // DOMException::Create takes its arguments in the opposite order.
      return DOMException::Create(message, name);
    }
    case kFencedFrameConfigTag: {
      String url_string, shared_storage_context, urn_uuid_string;
      uint32_t has_shared_storage_context, has_container_size, container_width,
          container_height, has_content_size, content_width, content_height,
          freeze_initial_size;
      KURL url;
      std::optional<KURL> urn_uuid;
      FencedFrameConfig::AttributeVisibility url_visibility;
      std::optional<gfx::Size> container_size, content_size;

      if (!ReadUTF8String(&url_string) ||
          !ReadUint32Enum<FencedFrameConfig::AttributeVisibility>(
              &url_visibility) ||
          !ReadUint32(&freeze_initial_size) ||
          !ReadUTF8String(&urn_uuid_string)) {
        return nullptr;
      }

      // `ReadUTF8String` does not distinguish between null and empty strings.
      // Adding the `has_shared_storage_context` bit allows us to get this
      // functionality back, which is needed for Shared Storage.
      if (!ReadUint32(&has_shared_storage_context)) {
        return nullptr;
      }
      if (has_shared_storage_context &&
          !ReadUTF8String(&shared_storage_context)) {
        return nullptr;
      }

      if (!ReadUint32(&has_container_size)) {
        return nullptr;
      }
      if (has_container_size) {
        if (!ReadUint32(&container_width) || !ReadUint32(&container_height)) {
          return nullptr;
        }
        container_size = gfx::Size(container_width, container_height);
      }

      if (!ReadUint32(&has_content_size)) {
        return nullptr;
      }
      if (has_content_size) {
        if (!ReadUint32(&content_width) || !ReadUint32(&content_height)) {
          return nullptr;
        }
        content_size = gfx::Size(content_width, content_height);
      }

      // Validate the URL and URN values.
      url = KURL(url_string);
      if (!url.IsEmpty() && !url.IsValid()) {
        return nullptr;
      }
      if (blink::IsValidUrnUuidURL(GURL(urn_uuid_string.Utf8()))) {
        urn_uuid = KURL(urn_uuid_string);
      } else if (!urn_uuid_string.empty()) {
        return nullptr;
      }

      return FencedFrameConfig::Create(url, shared_storage_context, urn_uuid,
                                       container_size, content_size,
                                       url_visibility, freeze_initial_size);
    }
    default:
      break;
  }
  return nullptr;
}

File* V8ScriptValueDeserializer::ReadFile() {
  if (Version() < 3)
    return nullptr;
  String path, name, relative_path, uuid, type;
  uint32_t has_snapshot = 0;
  uint64_t size = 0;
  double last_modified_ms = 0;
  if (!ReadUTF8String(&path) || (Version() >= 4 && !ReadUTF8String(&name)) ||
      (Version() >= 4 && !ReadUTF8String(&relative_path)) ||
      !ReadUTF8String(&uuid) || !ReadUTF8String(&type) ||
      (Version() >= 4 && !ReadUint32(&has_snapshot)))
    return nullptr;
  if (has_snapshot) {
    if (!ReadUint64(&size) || !ReadDouble(&last_modified_ms))
      return nullptr;
    if (Version() < 8)
      last_modified_ms *= kMsPerSecond;
  }
  uint32_t is_user_visible = 1;
  if (Version() >= 7 && !ReadUint32(&is_user_visible))
    return nullptr;
  const File::UserVisibility user_visibility =
      is_user_visible ? File::kIsUserVisible : File::kIsNotUserVisible;
  auto blob_handle = GetBlobDataHandle(uuid);
  if (!blob_handle)
    return nullptr;
  std::optional<base::Time> last_modified;
  if (has_snapshot && std::isfinite(last_modified_ms)) {
    last_modified =
        base::Time::FromMillisecondsSinceUnixEpoch(last_modified_ms);
  }
  return File::CreateFromSerialization(path, name, relative_path,
                                       user_visibility, has_snapshot, size,
                                       last_modified, std::move(blob_handle));
}

File* V8ScriptValueDeserializer::ReadFileIndex() {
  if (Version() < 6 || !blob_info_array_)
    return nullptr;
  uint32_t index;
  if (!ReadUint32(&index) || index >= blob_info_array_->size())
    return nullptr;
  const WebBlobInfo& info = (*blob_info_array_)[index];
  auto blob_handle = info.GetBlobHandle();
  if (!blob_handle)
    return nullptr;
  return File::CreateFromIndexedSerialization(info.FileName(), info.size(),
                                              info.LastModified(), blob_handle);
}

DOMRectReadOnly* V8ScriptValueDeserializer::ReadDOMRectReadOnly() {
  double x = 0, y = 0, width = 0, height = 0;
  if (!ReadDouble(&x) || !ReadDouble(&y) || !ReadDouble(&width) ||
      !ReadDouble(&height))
    return nullptr;
  return DOMRectReadOnly::Create(x, y, width, height);
}

scoped_refptr<BlobDataHandle> V8ScriptValueDeserializer::GetBlobDataHandle(
    const String& uuid) {
  BlobDataHandleMap& handles = serialized_script_value_->BlobDataHandles();
  BlobDataHandleMap::const_iterator it = handles.find(uuid);
  if (it != handles.end())
    return it->value;

  return nullptr;
}

v8::MaybeLocal<v8::Object> V8ScriptValueDeserializer::ReadHostObject(
    v8::Isolate* isolate) {
  DCHECK_EQ(isolate, script_state_->GetIsolate());
  ExceptionState exception_state(isolate, v8::ExceptionContext::kUnknown,
                                 nullptr, nullptr);
  ScriptWrappable* wrappable = nullptr;
  SerializationTag tag = kVersionTag;
  if (ReadTag(&tag)) {
    wrappable = ReadDOMObject(tag, exception_state);
    if (exception_state.HadException())
      return v8::MaybeLocal<v8::Object>();
  }
  i
"""


```