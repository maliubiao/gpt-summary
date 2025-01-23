Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Core Purpose:** The filename `v8_script_value_serializer_for_modules.cc` and the `#include` of `v8_script_value_serializer_for_modules.h` immediately suggest this file is about *serializing* JavaScript values, specifically for *modules* within the Chromium/Blink rendering engine. Serialization means converting in-memory data structures into a format suitable for storage or transmission. The "modules" part indicates it handles types specific to web modules and related APIs.

2. **Identify Key Dependencies:** The `#include` directives are crucial. They reveal the major areas this code interacts with:
    * `platform/`:  Indicates interaction with platform-level abstractions, particularly `WebCrypto`.
    * `web/modules/mediastream/`:  Points to handling of media streams.
    * `bindings/core/v8/serialization/`: Shows this class *extends* or *uses* core serialization logic.
    * `bindings/core/v8/`:  General V8 binding infrastructure.
    * `bindings/modules/v8/`:  Bindings for module-specific JavaScript APIs.
    * Specific module APIs like `v8_audio_data.h`, `v8_crypto_key.h`, `v8_file_system_directory_handle.h`, etc. These are the *types* being serialized.
    * `core/dom/`: Interaction with core DOM concepts.
    * `modules/`: The various module implementations themselves (e.g., `modules/crypto/crypto_key.h`, `modules/mediastream/media_stream_track.h`).

3. **Analyze Key Functions:**  Focus on the primary methods:
    * `ExtractTransferable`: This strongly suggests handling the "transferable objects" concept in JavaScript (e.g., using the `transfer` argument in `postMessage`). It determines if an object can be moved rather than cloned during serialization.
    * `WriteDOMObject`: This is the core serialization logic for DOM objects and module-specific types. It decides *how* to represent each type in the serialized format.
    * Helper functions like `WriteCryptoKey`, `WriteFileSystemHandle`, `WriteRTCEncodedAudioFrame`, etc. These handle the serialization of specific complex types.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** Based on the identified dependencies and function names, infer the connections to web technologies:
    * **JavaScript:** Serialization is essential for `postMessage`, `structuredClone`, and potentially storage APIs like IndexedDB. The file directly deals with V8, JavaScript's engine in Chrome. The "modules" aspect ties it to JavaScript modules (`<script type="module">`).
    * **HTML:**  HTML elements often interact with the module APIs being serialized (e.g., `<video>` with `MediaStream`, `<input type="file">` with File System Access API).
    * **CSS:** While less direct, features like CSS Houdini (which can involve custom data structures) might eventually leverage this kind of serialization. However, in this specific file, the connection is weaker compared to JavaScript and HTML.

5. **Infer Logic and Assumptions:**
    * **Transferable Objects:**  The `ExtractTransferable` function checks for specific types (`VideoFrame`, `AudioData`, `RTCDataChannel`, `MediaStreamTrack`, `MediaSourceHandle`). The logic prevents duplicate transferable objects to avoid data corruption or unexpected behavior. It also enforces constraints (e.g., a `MediaSourceHandle` cannot be transferred if it's already been used).
    * **Serialization Format:**  The `WriteDOMObject` and its helpers use tags (like `kCryptoKeyTag`, `kDOMFileSystemTag`) to identify the type being serialized. They then write type-specific data. The code uses a binary format (writing bytes, integers, strings).
    * **Error Handling:** The `ExceptionState& exception_state` parameter is present in many functions, indicating error handling during the serialization process (e.g., `DOMExceptionCode::kDataCloneError`).
    * **Feature Flags:**  The code checks for runtime enabled features (e.g., `RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled`). This shows that some of the serialization logic is dependent on whether certain browser features are enabled.

6. **Construct Examples and Scenarios:**  Based on the function names and types, create concrete examples:
    * **`postMessage` with Transferables:** Demonstrate how transferring a `VideoFrame` works.
    * **IndexedDB:**  Illustrate storing and retrieving objects that use the serialized types.
    * **WebRTC:**  Show the transfer of `RTCDataChannel` and `MediaStreamTrack` objects.
    * **File System Access API:** Explain how `FileSystemFileHandle` and `FileSystemDirectoryHandle` are serialized.
    * **Media Source Extensions (MSE):**  Explain how `MediaSourceHandle` is handled.

7. **Consider User/Programming Errors:** Think about what could go wrong:
    * **Transferring non-transferable objects:** What happens if you try to transfer a regular object? (It gets cloned).
    * **Duplicate transferables:** The code explicitly prevents this and throws an error.
    * **Transferring used resources:** The `MediaSourceHandle` example illustrates this error.
    * **Serialization limitations:** Not all types can be serialized (e.g., functions, some complex objects).

8. **Trace User Actions (Debugging):**  Think about how a user's actions in a web page could lead to this code being executed:
    * **`postMessage`:** A common scenario.
    * **Saving data to IndexedDB:** The browser uses serialization internally.
    * **WebRTC interactions:**  Transferring data channels or media tracks.
    * **Using the File System Access API:**  Saving file handles.
    * **Working with Media Source Extensions:** Creating and transferring media sources.

9. **Structure the Explanation:** Organize the findings into logical sections (Functionality, Relationship to Web Technologies, Logic and Assumptions, User Errors, Debugging). Use clear language and provide specific examples.

10. **Refine and Iterate:** Review the explanation for clarity, accuracy, and completeness. Ensure that the examples are relevant and easy to understand. For instance, initially, I might have just said "handles media," but refining that to "handles the serialization of various media-related objects" is more precise. Similarly, going from "related to crypto" to explaining *which* crypto APIs are involved is important.

By following these steps, one can systematically analyze the provided C++ code and generate a comprehensive and informative explanation.
这个C++源代码文件 `v8_script_value_serializer_for_modules.cc` 是 Chromium Blink 引擎中负责**序列化（Serialization）和反序列化（Deserialization）特定JavaScript对象**的关键组件，尤其关注那些与**Web 模块（Web Modules）**相关的数据类型。它扩展了核心的序列化机制，以支持模块特有的对象。

以下是它的主要功能：

**1. 扩展核心序列化机制：**

   - 该文件定义了 `V8ScriptValueSerializerForModules` 类，它继承自 `V8ScriptValueSerializer`。核心序列化器处理基础的 JavaScript 类型（如数字、字符串、数组、普通对象）。这个模块的序列化器则添加了对更复杂、特定于模块的对象的支持。

**2. 处理可转移对象（Transferable Objects）：**

   - **`ExtractTransferable` 函数** 负责识别哪些 JavaScript 对象可以被“转移”（transfer）而不是被“克隆”（clone）。转移意味着原始对象的所有权被移动到新的上下文，而克隆则创建原始对象的副本。这对于性能至关重要，尤其是处理大型数据（例如，`VideoFrame`）。
   - **与 JavaScript 关系：** 当你使用 `postMessage` API 在不同的 JavaScript 执行上下文（例如，Web Worker，iframe）之间传递数据时，可以指定一个可选的 `transfer` 数组。`ExtractTransferable` 的作用就是判断数组中的哪些对象可以被高效地转移。

     **例子：**
     ```javascript
     const videoFrame = ...; // 获取一个 VideoFrame 对象
     worker.postMessage({ frame: videoFrame }, [videoFrame]); // videoFrame 将被转移
     ```
     在这个例子中，`V8ScriptValueSerializerForModules::ExtractTransferable` 会识别出 `videoFrame` 是一个 `VideoFrame` 对象，并将其标记为可转移。

   - **假设输入与输出：**
     - **假设输入：** 一个 V8 的 `v8::Value` 对象，代表 JavaScript 中的一个 `VideoFrame` 实例。
     - **假设输出：** `true`，并且将该 `VideoFrame` 对象添加到 `transferables` 容器中。

**3. 写入 DOM 对象（Writing DOM Objects）：**

   - **`WriteDOMObject` 函数** 负责将特定的 DOM 对象或模块相关的对象序列化为可以存储或传输的格式。它会根据对象的类型选择合适的序列化方式。
   - **与 JavaScript、HTML、CSS 关系：**
     - **JavaScript：**  这个函数处理各种 JavaScript 中可访问的 Web API 对象，例如 `CryptoKey` (Web Crypto API), `DOMFileSystem` (废弃的 File System API), `FileSystemFileHandle` 和 `FileSystemDirectoryHandle` (File System Access API), `RTCCertificate`, `RTCDataChannel` (WebRTC API), `MediaStreamTrack` (Media Streams API), `VideoFrame` 和 `AudioData` (WebCodecs API)。
     - **HTML：**  当 JavaScript 代码操作 HTML 元素或与其相关的 API 时，这些 API 的对象可能需要被序列化。例如，当你使用 File System Access API 选择一个文件，`FileSystemFileHandle` 对象就可能被序列化。
     - **CSS：**  与 CSS 的关系相对间接。但如果 JavaScript 代码创建或操作与 CSS 相关的对象（例如，通过 Houdini API 创建的自定义属性或值），这些对象如果需要跨上下文传递，也可能需要通过类似的序列化机制。

     **例子：**
     - **Crypto API:**
       ```javascript
       crypto.subtle.generateKey("AES-CBC", { name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"])
         .then(key => {
           // 当你需要存储或通过 postMessage 传递 key 时
           // V8ScriptValueSerializerForModules::WriteCryptoKey 会被调用
         });
       ```
     - **File System Access API:**
       ```javascript
       const fileHandle = await window.showOpenFilePicker();
       // 当你需要通过 postMessage 传递 fileHandle 时
       // V8ScriptValueSerializerForModules::WriteFileSystemHandle 会被调用
       ```
     - **WebRTC:**
       ```javascript
       const dataChannel = peerConnection.createDataChannel("my-channel");
       // 当 dataChannel 需要被转移时
       // V8ScriptValueSerializerForModules::WriteRTCDataChannel 会被调用
       ```
     - **WebCodecs API:**
       ```javascript
       const videoFrame = new VideoFrame(videoData, { ... });
       // 当 videoFrame 需要被转移时
       // V8ScriptValueSerializerForModules::WriteVideoFrameHandle 会被调用
       ```

   - **假设输入与输出：**
     - **假设输入：** 一个指向 `CryptoKey` 对象的指针。
     - **假设输出：**  将 `kCryptoKeyTag` 写入序列化流，然后写入密钥的算法信息、用途、是否可提取以及实际的密钥数据。

**4. 处理特定的模块类型：**

   - 文件中包含了针对各种模块特定类型的序列化逻辑，例如：
     - `CryptoKey` 的序列化 (`WriteCryptoKey`)，包括算法、用途等信息。
     - `DOMFileSystem` 的序列化，包括类型、名称和根 URL。
     - File System Access API 中 `FileSystemFileHandle` 和 `FileSystemDirectoryHandle` 的序列化 (`WriteFileSystemHandle`)，涉及到传递 `FileSystemAccessTransferToken`。
     - WebRTC 相关对象的序列化，如 `RTCCertificate` (`WriteRTCCertificate`)，`RTCEncodedAudioFrame` 和 `RTCEncodedVideoFrame` (`WriteRTCEncodedAudioFrame`, `WriteRTCEncodedVideoFrame`)，以及 `RTCDataChannel` (`WriteRTCDataChannel`)。
     - WebCodecs API 中 `VideoFrame` (`WriteVideoFrameHandle`) 和 `AudioData` (`WriteMediaAudioBuffer`) 的序列化。
     - Media Streams API 中 `MediaStreamTrack` 的序列化 (`WriteMediaStreamTrack`)，包括设备信息、标签、状态等。
     - Media Source Extensions (MSE) API 中 `MediaSourceHandleImpl` 的序列化 (`WriteMediaSourceHandle`).
     - Screen Capture API 中 `CropTarget` 和 `RestrictionTarget` 的序列化 (`WriteCropTarget`, `WriteRestrictionTarget`).

**5. 处理 Web Crypto API 对象：**

   - `WriteCryptoKey` 函数负责序列化 `WebCryptoKey` 对象，包括其算法信息（例如，AES、RSA）、密钥类型（public、private、secret）、用途（encrypt、decrypt、sign 等）以及实际的密钥数据。

**6. 处理 File System Access API 对象：**

   - `WriteFileSystemHandle` 函数用于序列化 `FileSystemFileHandle` 和 `FileSystemDirectoryHandle`。它不直接序列化文件的内容，而是序列化一个 `FileSystemAccessTransferToken`，这个 token 可以用来在不同的上下文（例如，Web Worker）中重新获取对文件系统条目的访问权限。

**7. 处理 WebRTC API 对象：**

   - 针对 `RTCCertificate`，它序列化证书的 PEM 编码。
   - 针对 `RTCEncodedAudioFrame` 和 `RTCEncodedVideoFrame`，它不直接序列化帧数据，而是序列化一个索引，指向存储在 `SerializedScriptValue` 中的附件（attachments）中的帧数据。这是为了避免在序列化过程中复制大量的媒体数据。
   - 针对 `RTCDataChannel`，它序列化一个指向底层 `webrtc::DataChannelInterface` 的引用，以便在目标上下文中重新建立连接。

**8. 处理 WebCodecs API 对象：**

   - 针对 `VideoFrame` 和 `AudioData`，它序列化指向其底层数据缓冲区的引用，同样使用附件机制来避免数据复制。
   - 针对 `EncodedAudioChunk` 和 `EncodedVideoChunk`，它序列化指向其解码器缓冲区的引用。

**9. 处理 Media Streams API 对象：**

   - 针对 `MediaStreamTrack`，它序列化各种属性，如 `kind`、`id`、`label`、`enabled` 状态等，以及与底层媒体设备相关的信息。

**10. 处理 Media Source Extensions (MSE) API 对象：**

    - 针对 `MediaSourceHandleImpl`，它序列化一个索引，指向存储在附件中的 `MediaSourceAttachmentProvider` 和内部 Blob URL。

**11. 处理 Screen Capture API 对象：**

    - 针对 `CropTarget` 和 `RestrictionTarget`，它序列化其唯一的 ID。

**涉及用户或编程常见的使用错误：**

1. **尝试转移不可转移的对象：**
   - **错误：** 尝试将一个普通 JavaScript 对象或一个不可转移的 DOM 对象（例如，一个普通的 `HTMLElement`）放入 `postMessage` 的 `transfer` 数组中。
   - **结果：** 该对象会被克隆而不是转移，可能导致性能下降，尤其是在处理大型对象时。
   - **调试线索：** 在开发者工具的网络面板或性能面板中观察到消息传递过程中存在大量的数据复制。

2. **重复转移同一个可转移对象：**
   - **错误：** 在 `postMessage` 的 `transfer` 数组中多次包含同一个可转移对象实例。
   - **结果：**  `V8ScriptValueSerializerForModules::ExtractTransferable` 会抛出一个 `DOMException`，错误消息类似于 "VideoFrame at index X is a duplicate of an earlier VideoFrame."
   - **假设输入：**  一个 `v8::Value` 数组，其中包含同一个 `VideoFrame` 对象的两个引用。
   - **用户操作：**
     ```javascript
     const videoFrame = ...;
     worker.postMessage({ frame1: videoFrame, frame2: videoFrame }, [videoFrame, videoFrame]);
     ```

3. **在不应该序列化存储时尝试序列化某些类型：**
   - **错误：**  尝试将某些只能用于临时传输的对象（例如，`RTCEncodedAudioFrame`，`RTCEncodedVideoFrame`，`VideoFrame`，`AudioData`）用于存储目的，比如通过 IndexedDB。
   - **结果：** `WriteDOMObject` 或相关的写入函数会抛出一个 `DOMException`，错误消息类似于 "An RTCEncodedAudioFrame cannot be serialized for storage."
   - **用户操作：**
     ```javascript
     const encodedFrame = ...;
     const request = indexedDB.open("myDB", 1);
     request.onsuccess = function(event) {
       const db = event.target.result;
       const transaction = db.transaction(["frames"], "readwrite");
       const store = transaction.objectStore("frames");
       store.add(encodedFrame); // 尝试存储 RTCEncodedAudioFrame
     };
     ```

4. **在 `RTCDataChannel` 发送数据后尝试转移：**
   - **错误：**  在已经通过 `RTCDataChannel.send()` 发送过数据后，尝试将其作为可转移对象传递。
   - **结果：** `V8ScriptValueSerializerForModules::WriteRTCDataChannel` 会抛出一个 `DOMException`，错误消息类似于 "RTCDataChannel at index is no longer transferable. Transfers must occur on creation, and before any calls to send()."
   - **用户操作：**
     ```javascript
     const dataChannel = peerConnection.createDataChannel("my-channel");
     dataChannel.send("Hello");
     worker.postMessage({ channel: dataChannel }, [dataChannel]); // 尝试转移已使用的 dataChannel
     ```

5. **尝试转移已使用或已分离的 `MediaSourceHandle`：**
   - **错误：** 尝试转移一个已经作为 `<video>` 或 `<audio>` 元素的 `srcObject` 使用过的 `MediaSourceHandle`，或者一个已经被 `detach()` 的 `MediaSourceHandle`。
   - **结果：** `V8ScriptValueSerializerForModules::WriteMediaSourceHandle` 会抛出一个 `DOMException`，错误消息会指示该 `MediaSourceHandle` 已经被使用或者已经分离。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **使用 `postMessage` API 传递数据：**
   - 用户在网页的 JavaScript 代码中调用 `window.postMessage()` 或 `worker.postMessage()`。
   - 浏览器会检查传递的消息和可选的 `transfer` 数组。
   - 对于 `transfer` 数组中的每个对象，Blink 引擎会调用 `V8ScriptValueSerializerForModules::ExtractTransferable` 来判断是否可以转移。
   - 如果对象可以转移，它会被标记，并在序列化过程中以特殊的方式处理。
   - 最终，Blink 会调用 `V8ScriptValueSerializerForModules::WriteDOMObject` 来将消息内容（包括转移的对象）序列化为可以发送到目标上下文的格式。

2. **使用 Structured Cloning (例如，IndexedDB, Cache API)：**
   - 当 JavaScript 代码尝试将对象存储到 IndexedDB 或 Cache API 中时，浏览器会使用结构化克隆算法来序列化这些对象。
   - Blink 引擎会调用 `V8ScriptValueSerializerForModules::WriteDOMObject` 来处理需要特殊序列化逻辑的对象类型。

3. **使用 WebRTC API 进行数据传输：**
   - 当通过 `RTCDataChannel` 发送或接收消息时，浏览器会使用结构化克隆来序列化要发送的数据。
   - 如果尝试转移 `RTCDataChannel` 或与其相关的对象，`V8ScriptValueSerializerForModules` 的相关函数会被调用。

4. **使用 File System Access API 获取文件句柄并传递：**
   - 当用户通过 `showOpenFilePicker` 或 `showSaveFilePicker` 获取 `FileSystemFileHandle` 或 `FileSystemDirectoryHandle` 后，如果尝试通过 `postMessage` 传递这些句柄，`V8ScriptValueSerializerForModules::WriteFileSystemHandle` 会被调用。

5. **使用 Media Streams API 或 WebCodecs API 处理媒体数据：**
   - 当 JavaScript 代码创建或操作 `MediaStreamTrack`、`VideoFrame`、`AudioData` 等对象，并尝试通过 `postMessage` 传递它们时，`V8ScriptValueSerializerForModules` 中相应的序列化函数会被调用。

**调试线索：**

- **断点：** 在 `V8ScriptValueSerializerForModules::ExtractTransferable` 和 `V8ScriptValueSerializerForModules::WriteDOMObject` 以及相关的写入函数中设置断点，可以观察哪些对象正在被序列化以及是否被识别为可转移。
- **日志输出：** 在这些函数中添加日志输出，记录正在处理的对象类型和状态。
- **开发者工具：**
    - **Console 面板：** 查看是否有 `DOMException` 抛出，这些异常通常包含关于序列化错误的详细信息。
    - **Network 面板/Performance 面板：** 观察 `postMessage` 的消息大小和传输时间，异常大的消息可能表明没有正确进行转移。
    - **Memory 面板：** 监控内存使用情况，如果本应转移的对象被克隆，可能会看到不必要的内存增加。
- **Blink 内部调试工具：** Chromium 提供了内部调试工具（例如，`chrome://tracing`），可以用来跟踪消息传递和序列化的过程。

总之，`v8_script_value_serializer_for_modules.cc` 是 Blink 引擎中一个至关重要的组件，它确保了 Web 模块相关的复杂 JavaScript 对象能够被正确地序列化和反序列化，从而支持跨上下文的数据传递和存储，这对于构建现代 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/bindings/modules/v8/serialization/v8_script_value_serializer_for_modules.h"

#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_crypto.h"
#include "third_party/blink/public/platform/web_crypto_key.h"
#include "third_party/blink/public/platform/web_crypto_key_algorithm.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_rect_read_only.h"
#include "third_party/blink/renderer/bindings/modules/v8/serialization/serialized_track_params.h"
#include "third_party/blink/renderer/bindings/modules/v8/serialization/web_crypto_sub_tags.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crop_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_crypto_key.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_dom_file_system.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_audio_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_directory_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_file_system_file_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_landmark.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_source_handle.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_stream_track.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_point_2d.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_restriction_target.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_certificate.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_data_channel.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_rtc_encoded_video_frame.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/modules/crypto/crypto_key.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_directory_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_file_handle.h"
#include "third_party/blink/renderer/modules/file_system_access/file_system_handle.h"
#include "third_party/blink/renderer/modules/filesystem/dom_file_system.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_attachment_supplement.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_attachment.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_impl.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_handle_transfer_list.h"
#include "third_party/blink/renderer/modules/mediastream/crop_target.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_utils.h"
#include "third_party/blink/renderer/modules/mediastream/restriction_target.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_certificate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel_attachment.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_data_channel_transfer_list.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_audio_frame_delegate.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_encoded_video_frame_delegate.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data_attachment.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_data_transfer_list.h"
#include "third_party/blink/renderer/modules/webcodecs/decoder_buffer_attachment.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_audio_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_attachment.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame_transfer_list.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"

namespace blink {

// static
bool V8ScriptValueSerializerForModules::ExtractTransferable(
    v8::Isolate* isolate,
    v8::Local<v8::Value> object,
    wtf_size_t object_index,
    Transferables& transferables,
    ExceptionState& exception_state) {
  // Give the core/ implementation a chance to try first.
  // If it didn't recognize the kind of object, try the modules types.
  if (V8ScriptValueSerializer::ExtractTransferable(
          isolate, object, object_index, transferables, exception_state)) {
    return true;
  }
  if (exception_state.HadException())
    return false;

  if (VideoFrame* video_frame = V8VideoFrame::ToWrappable(isolate, object)) {
    VideoFrameTransferList* transfer_list =
        transferables.GetOrCreateTransferList<VideoFrameTransferList>();
    if (transfer_list->video_frames.Contains(video_frame)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "VideoFrame at index " + String::Number(object_index) +
              " is a duplicate of an earlier VideoFrame.");
      return false;
    }
    transfer_list->video_frames.push_back(video_frame);
    return true;
  }

  if (AudioData* audio_data = V8AudioData::ToWrappable(isolate, object)) {
    AudioDataTransferList* transfer_list =
        transferables.GetOrCreateTransferList<AudioDataTransferList>();
    if (transfer_list->audio_data_collection.Contains(audio_data)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "AudioData at index " + String::Number(object_index) +
              " is a duplicate of an earlier AudioData.");
      return false;
    }
    transfer_list->audio_data_collection.push_back(audio_data);
    return true;
  }

  if (RTCDataChannel* channel =
          V8RTCDataChannel::ToWrappable(isolate, object)) {
    if (RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled(
            CurrentExecutionContext(isolate))) {
      RTCDataChannelTransferList* transfer_list =
          transferables.GetOrCreateTransferList<RTCDataChannelTransferList>();

      if (transfer_list->data_channel_collection.Contains(channel)) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "RTCDataChannel at index " + String::Number(object_index) +
                " is a duplicate of an earlier RTCDataChannel.");
        return false;
      }

      transfer_list->data_channel_collection.push_back(channel);
      return true;
    }
  }

  if (MediaStreamTrack* track =
          V8MediaStreamTrack::ToWrappable(isolate, object)) {
    if (RuntimeEnabledFeatures::MediaStreamTrackTransferEnabled(
            CurrentExecutionContext(isolate))) {
      if (transferables.media_stream_tracks.Contains(track)) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "MediaStreamTrack at index " + String::Number(object_index) +
                " is a duplicate of an earlier MediaStreamTrack.");
        return false;
      }
      transferables.media_stream_tracks.push_back(track);
      return true;
    }
  }

  if (MediaSourceHandleImpl* media_source_handle =
          V8MediaSourceHandle::ToWrappable(isolate, object)) {
    MediaSourceHandleTransferList* transfer_list =
        transferables.GetOrCreateTransferList<MediaSourceHandleTransferList>();
    if (transfer_list->media_source_handles.Contains(media_source_handle)) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "MediaSourceHandle at index " + String::Number(object_index) +
              " is a duplicate of an earlier MediaSourceHandle.");
      return false;
    }
    if (media_source_handle->is_detached()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "MediaSourceHandle at index " + String::Number(object_index) +
              " is detached and cannot be transferred.");
      return false;
    }
    if (media_source_handle->is_used()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "MediaSourceHandle at index " + String::Number(object_index) +
              " has been used as srcObject of media element already, and "
              "cannot be transferred.");
      return false;
    }
    transfer_list->media_source_handles.push_back(media_source_handle);
    return true;
  }

  return false;
}

bool V8ScriptValueSerializerForModules::WriteDOMObject(
    ScriptWrappable* wrappable,
    ExceptionState& exception_state) {
  // Give the core/ implementation a chance to try first.
  // If it didn't recognize the kind of wrapper, try the modules types.
  if (V8ScriptValueSerializer::WriteDOMObject(wrappable, exception_state))
    return true;
  if (exception_state.HadException())
    return false;

  ScriptWrappable::TypeDispatcher dispatcher(wrappable);
  if (auto* crypto_key = dispatcher.ToMostDerived<CryptoKey>()) {
    return WriteCryptoKey(crypto_key->Key(), exception_state);
  }
  if (auto* fs = dispatcher.ToMostDerived<DOMFileSystem>()) {
    if (!fs->Clonable()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A FileSystem object could not be cloned.");
      return false;
    }
    WriteAndRequireInterfaceTag(kDOMFileSystemTag);
    // This locks in the values of the FileSystemType enumerators.
    WriteUint32(static_cast<uint32_t>(fs->GetType()));
    WriteUTF8String(fs->name());
    WriteUTF8String(fs->RootURL().GetString());
    return true;
  }
  if (auto* file_handle = dispatcher.ToMostDerived<FileSystemFileHandle>()) {
    if (!RuntimeEnabledFeatures::FileSystemAccessEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    return WriteFileSystemHandle(kFileSystemFileHandleTag, file_handle);
  }
  if (auto* dir_handle =
          dispatcher.ToMostDerived<FileSystemDirectoryHandle>()) {
    if (!RuntimeEnabledFeatures::FileSystemAccessEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    return WriteFileSystemHandle(kFileSystemDirectoryHandleTag, dir_handle);
  }
  if (auto* certificate = dispatcher.ToMostDerived<RTCCertificate>()) {
    rtc::RTCCertificatePEM pem = certificate->Certificate()->ToPEM();
    WriteAndRequireInterfaceTag(kRTCCertificateTag);
    WriteUTF8String(pem.private_key().c_str());
    WriteUTF8String(pem.certificate().c_str());
    return true;
  }
  if (auto* audio_frame = dispatcher.ToMostDerived<RTCEncodedAudioFrame>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "An RTCEncodedAudioFrame cannot be "
                                        "serialized for storage.");
      return false;
    }
    return WriteRTCEncodedAudioFrame(audio_frame);
  }
  if (auto* video_frame = dispatcher.ToMostDerived<RTCEncodedVideoFrame>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "An RTCEncodedVideoFrame cannot be "
                                        "serialized for storage.");
      return false;
    }
    return WriteRTCEncodedVideoFrame(video_frame);
  }
  if (auto* video_frame = dispatcher.ToMostDerived<VideoFrame>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "A VideoFrame cannot be serialized for "
                                        "storage.");
      return false;
    }
    scoped_refptr<VideoFrameHandle> handle = video_frame->handle()->Clone();
    if (!handle) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "A VideoFrame could not be cloned "
                                        "because it was closed.");
      return false;
    }
    return WriteVideoFrameHandle(std::move(handle));
  }
  if (auto* audio_data = dispatcher.ToMostDerived<AudioData>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "AudioData cannot be serialized for "
                                        "storage.");
      return false;
    }
    scoped_refptr<media::AudioBuffer> data = audio_data->data();
    if (!data) {
      exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                        "AudioData could not be cloned "
                                        "because it was closed.");
      return false;
    }
    return WriteMediaAudioBuffer(std::move(data));
  }
  if (auto* audio_chunk = dispatcher.ToMostDerived<EncodedAudioChunk>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Encoded chunks cannot be serialized for storage.");
      return false;
    }
    return WriteDecoderBuffer(audio_chunk->buffer(), /*for_audio=*/true);
  }
  if (auto* video_chunk = dispatcher.ToMostDerived<EncodedVideoChunk>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "Encoded chunks cannot be serialized for storage.");
      return false;
    }
    return WriteDecoderBuffer(video_chunk->buffer(), /*for_audio=*/false);
  }
  if (auto* track = dispatcher.DowncastTo<MediaStreamTrack>()) {
    if (!RuntimeEnabledFeatures::MediaStreamTrackTransferEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A MediaStreamTrack cannot be serialized for storage.");
      return false;
    }
    return WriteMediaStreamTrack(track, dispatcher, exception_state);
  }
  if (auto* channel = dispatcher.DowncastTo<RTCDataChannel>()) {
    if (!RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "An RTCDataChannel cannot be serialized for storage.");
      return false;
    }
    if (!channel->IsTransferable()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "RTCDataChannel at index is no longer transferable. Transfers must "
          "occur on creation, and before any calls to send().");
      return false;
    }
    return WriteRTCDataChannel(channel);
  }
  if (auto* crop_target = dispatcher.ToMostDerived<CropTarget>()) {
    if (!RuntimeEnabledFeatures::RegionCaptureEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A CropTarget cannot be serialized for storage.");
      return false;
    }
    return WriteCropTarget(crop_target);
  }
  if (auto* restriction_target =
          dispatcher.ToMostDerived<RestrictionTarget>()) {
    if (!RuntimeEnabledFeatures::ElementCaptureEnabled(
            ExecutionContext::From(GetScriptState()))) {
      return false;
    }
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A RestrictionTarget cannot be serialized for storage.");
      return false;
    }
    return WriteRestrictionTarget(restriction_target);
  }
  if (auto* media_source_handle =
          dispatcher.ToMostDerived<MediaSourceHandleImpl>()) {
    if (IsForStorage()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kDataCloneError,
          "A MediaSourceHandle cannot be serialized for storage.");
      return false;
    }
    if (const Transferables* transferables = GetTransferables()) {
      if (const MediaSourceHandleTransferList* transfer_list =
              transferables
                  ->GetTransferListIfExists<MediaSourceHandleTransferList>()) {
        if (transfer_list->media_source_handles.Find(media_source_handle) !=
            kNotFound) {
          return WriteMediaSourceHandle(media_source_handle, exception_state);
        }
      }
    }
    exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                      "A MediaSourceHandle could not be cloned "
                                      "because it was not transferred.");
    return false;
  }

  return false;
}

namespace {

uint32_t AlgorithmIdForWireFormat(WebCryptoAlgorithmId id) {
  switch (id) {
    case kWebCryptoAlgorithmIdAesCbc:
      return kAesCbcTag;
    case kWebCryptoAlgorithmIdHmac:
      return kHmacTag;
    case kWebCryptoAlgorithmIdRsaSsaPkcs1v1_5:
      return kRsaSsaPkcs1v1_5Tag;
    case kWebCryptoAlgorithmIdSha1:
      return kSha1Tag;
    case kWebCryptoAlgorithmIdSha256:
      return kSha256Tag;
    case kWebCryptoAlgorithmIdSha384:
      return kSha384Tag;
    case kWebCryptoAlgorithmIdSha512:
      return kSha512Tag;
    case kWebCryptoAlgorithmIdAesGcm:
      return kAesGcmTag;
    case kWebCryptoAlgorithmIdRsaOaep:
      return kRsaOaepTag;
    case kWebCryptoAlgorithmIdAesCtr:
      return kAesCtrTag;
    case kWebCryptoAlgorithmIdAesKw:
      return kAesKwTag;
    case kWebCryptoAlgorithmIdRsaPss:
      return kRsaPssTag;
    case kWebCryptoAlgorithmIdEcdsa:
      return kEcdsaTag;
    case kWebCryptoAlgorithmIdEcdh:
      return kEcdhTag;
    case kWebCryptoAlgorithmIdHkdf:
      return kHkdfTag;
    case kWebCryptoAlgorithmIdPbkdf2:
      return kPbkdf2Tag;
    case kWebCryptoAlgorithmIdEd25519:
      return kEd25519Tag;
    case kWebCryptoAlgorithmIdX25519:
      return kX25519Tag;
  }
  NOTREACHED() << "Unknown algorithm ID " << id;
}

uint32_t AsymmetricKeyTypeForWireFormat(WebCryptoKeyType key_type) {
  switch (key_type) {
    case kWebCryptoKeyTypePublic:
      return kPublicKeyType;
    case kWebCryptoKeyTypePrivate:
      return kPrivateKeyType;
    case kWebCryptoKeyTypeSecret:
      break;
  }
  NOTREACHED() << "Unknown asymmetric key type " << key_type;
}

uint32_t NamedCurveForWireFormat(WebCryptoNamedCurve named_curve) {
  switch (named_curve) {
    case kWebCryptoNamedCurveP256:
      return kP256Tag;
    case kWebCryptoNamedCurveP384:
      return kP384Tag;
    case kWebCryptoNamedCurveP521:
      return kP521Tag;
  }
  NOTREACHED() << "Unknown named curve " << named_curve;
}

uint32_t KeyUsagesForWireFormat(WebCryptoKeyUsageMask usages,
                                bool extractable) {
  // Reminder to update this when adding new key usages.
  static_assert(kEndOfWebCryptoKeyUsage == (1 << 7) + 1,
                "update required when adding new key usages");
  uint32_t value = 0;
  if (extractable)
    value |= kExtractableUsage;
  if (usages & kWebCryptoKeyUsageEncrypt)
    value |= kEncryptUsage;
  if (usages & kWebCryptoKeyUsageDecrypt)
    value |= kDecryptUsage;
  if (usages & kWebCryptoKeyUsageSign)
    value |= kSignUsage;
  if (usages & kWebCryptoKeyUsageVerify)
    value |= kVerifyUsage;
  if (usages & kWebCryptoKeyUsageDeriveKey)
    value |= kDeriveKeyUsage;
  if (usages & kWebCryptoKeyUsageWrapKey)
    value |= kWrapKeyUsage;
  if (usages & kWebCryptoKeyUsageUnwrapKey)
    value |= kUnwrapKeyUsage;
  if (usages & kWebCryptoKeyUsageDeriveBits)
    value |= kDeriveBitsUsage;
  return value;
}

}  // namespace

bool V8ScriptValueSerializerForModules::WriteCryptoKey(
    const WebCryptoKey& key,
    ExceptionState& exception_state) {
  WriteAndRequireInterfaceTag(kCryptoKeyTag);

  // Write params.
  const WebCryptoKeyAlgorithm& algorithm = key.Algorithm();
  switch (algorithm.ParamsType()) {
    case kWebCryptoKeyAlgorithmParamsTypeAes: {
      const auto& params = *algorithm.AesParams();
      WriteOneByte(kAesKeyTag);
      WriteUint32(AlgorithmIdForWireFormat(algorithm.Id()));
      DCHECK_EQ(0, params.LengthBits() % 8);
      WriteUint32(params.LengthBits() / 8);
      break;
    }
    case kWebCryptoKeyAlgorithmParamsTypeHmac: {
      const auto& params = *algorithm.HmacParams();
      WriteOneByte(kHmacKeyTag);
      DCHECK_EQ(0u, params.LengthBits() % 8);
      WriteUint32(params.LengthBits() / 8);
      WriteUint32(AlgorithmIdForWireFormat(params.GetHash().Id()));
      break;
    }
    case kWebCryptoKeyAlgorithmParamsTypeRsaHashed: {
      const auto& params = *algorithm.RsaHashedParams();
      WriteOneByte(kRsaHashedKeyTag);
      WriteUint32(AlgorithmIdForWireFormat(algorithm.Id()));
      WriteUint32(AsymmetricKeyTypeForWireFormat(key.GetType()));
      WriteUint32(params.ModulusLengthBits());

      if (params.PublicExponent().size() >
          std::numeric_limits<uint32_t>::max()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kDataCloneError,
            "A CryptoKey object could not be cloned.");
        return false;
      }
      WriteUint32(static_cast<uint32_t>(params.PublicExponent().size()));
      WriteRawBytes(params.PublicExponent().data(),
                    params.PublicExponent().size());
      WriteUint32(AlgorithmIdForWireFormat(params.GetHash().Id()));
      break;
    }
    case kWebCryptoKeyAlgorithmParamsTypeEc: {
      const auto& params = *algorithm.EcParams();
      WriteOneByte(kEcKeyTag);
      WriteUint32(AlgorithmIdForWireFormat(algorithm.Id()));
      WriteUint32(AsymmetricKeyTypeForWireFormat(key.GetType()));
      WriteUint32(NamedCurveForWireFormat(params.NamedCurve()));
      break;
    }
    case kWebCryptoKeyAlgorithmParamsTypeNone:
      switch (algorithm.Id()) {
        case kWebCryptoAlgorithmIdEd25519:
        case kWebCryptoAlgorithmIdX25519: {
          CryptoKeySubTag tag = algorithm.Id() == kWebCryptoAlgorithmIdEd25519
                                    ? kEd25519KeyTag
                                    : kX25519KeyTag;
          WriteOneByte(tag);
          WriteUint32(AlgorithmIdForWireFormat(algorithm.Id()));
          WriteUint32(AsymmetricKeyTypeForWireFormat(key.GetType()));
          break;
        }
        default:
          DCHECK(WebCryptoAlgorithm::IsKdf(algorithm.Id()));
          WriteOneByte(kNoParamsKeyTag);
          WriteUint32(AlgorithmIdForWireFormat(algorithm.Id()));
      }
      break;
  }

  // Write key usages.
  WriteUint32(KeyUsagesForWireFormat(key.Usages(), key.Extractable()));

  // Write key data.
  WebVector<uint8_t> key_data;
  if (!Platform::Current()->Crypto()->SerializeKeyForClone(key, key_data) ||
      key_data.size() > std::numeric_limits<uint32_t>::max()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataCloneError,
        "A CryptoKey object could not be cloned.");
    return false;
  }
  WriteUint32(static_cast<uint32_t>(key_data.size()));
  WriteRawBytes(key_data.data(), key_data.size());

  return true;
}

bool V8ScriptValueSerializerForModules::WriteFileSystemHandle(
    SerializationTag tag,
    FileSystemHandle* file_system_handle) {
  mojo::PendingRemote<mojom::blink::FileSystemAccessTransferToken> token =
      file_system_handle->Transfer();

  SerializedScriptValue::FileSystemAccessTokensArray& tokens_array =
      GetSerializedScriptValue()->FileSystemAccessTokens();

  tokens_array.push_back(std::move(token));
  const uint32_t token_index = static_cast<uint32_t>(tokens_array.size() - 1);

  WriteAndRequireInterfaceTag(tag);
  WriteUTF8String(file_system_handle->name());
  WriteUint32(token_index);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteRTCEncodedAudioFrame(
    RTCEncodedAudioFrame* audio_frame) {
  auto* attachment =
      GetSerializedScriptValue()
          ->GetOrCreateAttachment<RTCEncodedAudioFramesAttachment>();
  auto& frames = attachment->EncodedAudioFrames();
  frames.push_back(audio_frame->Delegate());
  const uint32_t index = static_cast<uint32_t>(frames.size() - 1);

  WriteAndRequireInterfaceTag(kRTCEncodedAudioFrameTag);
  WriteUint32(index);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteRTCEncodedVideoFrame(
    RTCEncodedVideoFrame* video_frame) {
  auto* attachment =
      GetSerializedScriptValue()
          ->GetOrCreateAttachment<RTCEncodedVideoFramesAttachment>();
  auto& frames = attachment->EncodedVideoFrames();
  frames.push_back(video_frame->Delegate());
  const uint32_t index = static_cast<uint32_t>(frames.size() - 1);

  WriteAndRequireInterfaceTag(kRTCEncodedVideoFrameTag);
  WriteUint32(index);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteVideoFrameHandle(
    scoped_refptr<VideoFrameHandle> handle) {
  auto* attachment =
      GetSerializedScriptValue()->GetOrCreateAttachment<VideoFrameAttachment>();
  auto& frames = attachment->Handles();
  frames.push_back(std::move(handle));
  const uint32_t index = static_cast<uint32_t>(frames.size() - 1);

  WriteAndRequireInterfaceTag(kVideoFrameTag);
  WriteUint32(index);

  return true;
}

bool V8ScriptValueSerializerForModules::WriteMediaAudioBuffer(
    scoped_refptr<media::AudioBuffer> audio_data) {
  auto* attachment =
      GetSerializedScriptValue()->GetOrCreateAttachment<AudioDataAttachment>();
  auto& audio_buffers = attachment->AudioBuffers();
  audio_buffers.push_back(std::move(audio_data));
  const uint32_t index = static_cast<uint32_t>(audio_buffers.size() - 1);

  WriteAndRequireInterfaceTag(kAudioDataTag);
  WriteUint32(index);

  return true;
}

bool V8ScriptValueSerializerForModules::WriteDecoderBuffer(
    scoped_refptr<media::DecoderBuffer> data,
    bool for_audio) {
  auto* attachment = GetSerializedScriptValue()
                         ->GetOrCreateAttachment<DecoderBufferAttachment>();
  auto& buffers = attachment->Buffers();
  buffers.push_back(std::move(data));
  const uint32_t index = static_cast<uint32_t>(buffers.size() - 1);

  WriteAndRequireInterfaceTag(for_audio ? kEncodedAudioChunkTag
                                        : kEncodedVideoChunkTag);
  WriteUint32(index);

  return true;
}

bool V8ScriptValueSerializerForModules::WriteMediaStreamTrack(
    MediaStreamTrack* track,
    ScriptWrappable::TypeDispatcher& dispatcher,
    ExceptionState& exception_state) {
  String message;
  if (!track->TransferAllowed(message)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                      message);
    return false;
  }
  std::optional<const MediaStreamDevice> device = track->device();
  // TODO(crbug.com/1352414): Replace this UnguessableToken with a mojo
  // interface.
  auto transfer_id = base::UnguessableToken::Create();

  WriteAndRequireInterfaceTag(kMediaStreamTrack);
  auto track_impl_subtype = SerializeTrackImplSubtype(dispatcher);
  WriteUint32Enum(track_impl_subtype);
  WriteUnguessableToken(*device->serializable_session_id());
  WriteUnguessableToken(transfer_id);
  WriteUTF8String(track->kind());
  WriteUTF8String(track->id());
  WriteUTF8String(track->label());
  WriteOneByte(track->enabled());
  WriteOneByte(track->muted());
  WriteUint32Enum(SerializeContentHint(track->Component()->ContentHint()));
  WriteUint32Enum(SerializeReadyState(track->Component()->GetReadyState()));
  // Using `switch` to ensure new enum values are handled.
  switch (track_impl_subtype) {
    case SerializedTrackImplSubtype::kTrackImplSubtypeBase:
      // No additional data needs to be serialized.
      break;
    case SerializedTrackImplSubtype::kTrackImplSubtypeCanvasCapture:
    case SerializedTrackImplSubtype::kTrackImplSubtypeGenerator:
      NOTREACHED() << "device type is " << device->type
                   << " but track impl subtype is "
                   << static_cast<uint32_t>(track_impl_subtype);
    case SerializedTrackImplSubtype::kTrackImplSubtypeBrowserCapture:
      MediaStreamSource* const source = track->Component()->Source();
      DCHECK(source);
      DCHECK_EQ(source->GetType(), MediaStreamSource::kTypeVideo);
      MediaStreamVideoSource* const native_source =
          MediaStreamVideoSource::GetVideoSource(source);
      DCHECK(native_source);
      WriteUint32(native_source->GetSubCaptureTargetVersion());
      break;
  }
  // TODO(crbug.com/1288839): Needs to move to FinalizeTransfer?
  track->BeingTransferred(transfer_id);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteRTCDataChannel(
    RTCDataChannel* channel) {
  if (!RuntimeEnabledFeatures::TransferableRTCDataChannelEnabled()) {
    return false;
  }

  auto* attachment = GetSerializedScriptValue()
                         ->GetOrCreateAttachment<RTCDataChannelAttachment>();
  using NativeDataChannelVector =
      Vector<rtc::scoped_refptr<webrtc::DataChannelInterface>>;
  NativeDataChannelVector& channels = attachment->DataChannels();
  channels.push_back(channel->TransferUnderlyingChannel());
  const uint32_t index = static_cast<uint32_t>(channels.size() - 1);

  WriteAndRequireInterfaceTag(kRTCDataChannel);
  WriteUint32(index);

  return true;
}

bool V8ScriptValueSerializerForModules::WriteCropTarget(
    CropTarget* crop_target) {
  CHECK(crop_target);
  const String& id = crop_target->GetId();
  CHECK(!id.empty());
  WriteAndRequireInterfaceTag(kCropTargetTag);
  WriteUTF8String(id);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteRestrictionTarget(
    RestrictionTarget* restriction_target) {
  CHECK(restriction_target);
  const String& id = restriction_target->GetId();
  CHECK(!id.empty());
  WriteAndRequireInterfaceTag(kRestrictionTargetTag);
  WriteUTF8String(id);
  return true;
}

bool V8ScriptValueSerializerForModules::WriteMediaSourceHandle(
    MediaSourceHandleImpl* handle,
    ExceptionState& exception_state) {
  if (handle->is_serialized()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kDataCloneError,
        "MediaSourceHandle is already serialized.");
    return false;
  }

  if (handle->is_used()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kDataCloneError,
                                      "MediaSourceHandle has been used as "
                                      "srcObject of media element already.");
    return false;
  }

  // The collection of handle-attachment involved in serialization.
  auto* attachment = GetSerializedScriptValue()
                         ->GetOrCreateAttachment<MediaSourceHandleAttachment>();

  // The collection of underlying scoped_refptr<MediaSourceAttachmentProvider>
  // and internal object URLs involved in serialization. Each is the internal
  // state of a MediaSourceHandleImpl. Add the internal state of |handle| to it
  // and serialize it using the index of that state in the vector.
  auto& attachments = attachment->Attachments();

  scoped_refptr<HandleAttachmentProvider> media_source_attachment_provider =
      handle->TakeAttachmentProvider();
  // The two handle checks, above, (!is_serialized() and !is_used()) should
  // prevent us from ever having a missing |media_source_attachment_provider|
  // here.
  DCHECK(media_source_attachment_provider);

  attachments.push_back(MediaSourceHandleAttachment::HandleInternals{
      .attachment_provider = std::move(media_source_attachment_provider),
      .internal_blob_url = handle->GetInternalBlobURL()});
  handle->mark_serialized();
  const uint32_t index = static_cast<uint32_t>(attachments.size() - 1);

  WriteAndRequireInterfaceTag(kMediaSourceHandleTag);
  WriteUint32(index);

  return true;
}

}  // namespace blink
```