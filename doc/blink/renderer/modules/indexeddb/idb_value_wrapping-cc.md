Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of `idb_value_wrapping.cc` within the Chromium Blink engine, specifically related to IndexedDB. The request also asks for connections to JavaScript/HTML/CSS, common usage errors, debugging tips, and logical reasoning (with input/output examples).

2. **Initial Scan for Key Terms:**  A quick read reveals important keywords: `IndexedDB`, `wrapping`, `SerializedScriptValue`, `Blob`, `compression`, `Snappy`, `V8`. These terms immediately give context: this code is about how IndexedDB stores and retrieves JavaScript values, potentially optimizing storage through wrapping (using Blobs) and compression.

3. **Identify the Core Classes:** The code defines two primary classes: `IDBValueWrapper` and `IDBValueUnwrapper`. This strongly suggests a two-part process:
    * **Wrapper:** Takes a JavaScript value and prepares it for storage in IndexedDB.
    * **Unwrapper:** Takes data from IndexedDB and converts it back to a usable form.

4. **Analyze `IDBValueWrapper`:**
    * **Constructor:**  Takes a V8 value (a JavaScript value), serializes it using `SerializedScriptValue`, and stores the serialized data and associated Blob information. This confirms the role of serialization.
    * **`Clone`:**  Deserializes the stored data back into a JavaScript value. This is crucial for getting the data back out.
    * **`WriteVarInt`:**  A utility function for writing variable-length integers. This is a common technique for efficient storage of numbers of varying sizes.
    * **`DoneCloning`:**  The crucial step before actual storage. It handles compression (`MaybeCompress`) and potentially moving the data to a Blob (`MaybeStoreInBlob`).
    * **`ShouldCompress`:** Determines if compression should be attempted based on size and feature flags.
    * **`MaybeCompress`:**  Implements Snappy compression if appropriate, adding a specific header to identify compressed data. It also handles cases where compression isn't effective.
    * **`MaybeStoreInBlob`:** If the serialized data is too large (above a threshold), it's moved into a separate `BlobData`, and the main data is replaced with a "wrapping" structure that references the Blob. This is the core of the "wrapping" concept.
    * **`TakeWireBytes`:**  Returns the final byte representation ready for storage in IndexedDB. This might be the original serialized data, compressed data, or the wrapping structure pointing to a Blob.

5. **Analyze `IDBValueUnwrapper`:**
    * **`IsWrapped` (static):**  Checks if an `IDBValue` contains the wrapping header, indicating that the actual data is in a separate Blob.
    * **`IsWrapped` (for a vector):**  Checks a collection of `IDBValue`s for wrapping.
    * **`Unwrap` (static):**  Takes the content of the wrapper Blob and replaces the data in the `IDBValue`. This is the final step in retrieving the full data.
    * **`Decompress` (static):** Checks for the compression header and uses Snappy to decompress the data.
    * **`Parse`:**  Parses the wrapping structure to extract the size and offset of the external Blob.
    * **`WrapperBlobHandle`:** Returns a handle to the external Blob containing the actual data.
    * **`ReadVarInt` and `ReadBytes`:** Utility functions for reading variable-length integers and byte sequences from the wrapped data.
    * **`Reset`:** Resets the unwrapper state.

6. **Connect to JavaScript/HTML/CSS:**
    * **JavaScript:** IndexedDB is a JavaScript API. The `IDBValueWrapper` takes a JavaScript value (`v8::Local<v8::Value>`). The unwrapping process ultimately results in a JavaScript value being available to the script. Examples would involve storing complex objects, arrays, or large strings.
    * **HTML:** While not directly interacting, IndexedDB is used by web pages. The data stored can be associated with the HTML content of the page. For example, storing user preferences or cached data.
    * **CSS:** No direct relationship in terms of functionality here.

7. **Identify Common User/Programming Errors:**
    * **Data Corruption:**  Manually altering data in the IndexedDB storage can lead to parsing errors in the unwrapper.
    * **Incorrect Blob Handling:**  If the Blobs referenced by the wrapping structure are lost or modified, data retrieval will fail.
    * **Version Mismatches:** If the serialization format or wrapping scheme changes significantly, older data might become unreadable.

8. **Provide Debugging Clues:** The code provides clues for debugging:
    * **Check for the wrapping header:** `IsWrapped` is a good starting point.
    * **Examine Blob information:** If wrapped, check if the expected Blobs exist and have the correct size.
    * **Inspect the wire bytes:**  See if the data looks like a valid serialized value, a compressed value, or a wrapping structure.

9. **Construct Logical Reasoning with Input/Output:** This requires creating scenarios:
    * **Scenario 1 (No wrapping/compression):** A small JavaScript string gets serialized and stored directly.
    * **Scenario 2 (Compression):** A moderately sized string gets compressed before storage.
    * **Scenario 3 (Wrapping):** A large JavaScript object gets its data moved to a Blob, and a small wrapping structure is stored.

10. **Refine and Organize:**  Structure the analysis logically, starting with a summary of the file's purpose, then detailing the functionality of each class, explaining the connections to web technologies, outlining potential errors, and providing debugging guidance. The input/output examples help solidify understanding.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this about encryption?"  A closer look reveals terms like "compression" and "wrapping," which are related but distinct from encryption.
* **Realization:** The `kRequiresProcessingSSVPseudoVersion` and associated constants are a clever trick to distinguish wrapped/compressed data from regular serialized data. This needs to be clearly explained.
* **Emphasis:**  Highlight the importance of the header bytes in identifying wrapped and compressed data.
* **Clarity:** Use clear and concise language, avoiding jargon where possible, or explaining it when necessary. For instance, explain what "varint" means.

By following this step-by-step analysis, breaking down the code into manageable parts, and connecting the technical details to the broader context of web development, we can arrive at a comprehensive understanding of the `idb_value_wrapping.cc` file.
这个文件 `blink/renderer/modules/indexeddb/idb_value_wrapping.cc` 的主要功能是**处理 IndexedDB 中存储的 JavaScript 值的序列化、压缩和“包装”过程，以及反向的解包和解压缩过程。**  它旨在优化 IndexedDB 的存储效率和性能。

以下是该文件的详细功能分解：

**1. 值序列化和反序列化:**

*   **功能:** 使用 `SerializedScriptValue` 类将 JavaScript 值转换为字节流进行存储，以及将字节流转换回 JavaScript 值。
*   **与 JavaScript 的关系:**  这是 IndexedDB 如何持久化 JavaScript 对象的核心机制。当你在 JavaScript 中使用 `IDBObjectStore.add()` 或 `IDBObjectStore.put()` 存储数据时，这个文件中的代码会参与将你的 JavaScript 值转换为可以存储在磁盘上的格式。
*   **假设输入与输出:**
    *   **假设输入 (JavaScript):**  `{ name: "Alice", age: 30 }`
    *   **输出 (序列化后):**  一段表示该对象的字节流 (具体格式由 `SerializedScriptValue` 决定，但会包含类型信息和数据)。

**2. 值压缩:**

*   **功能:**  使用 Snappy 算法对序列化后的值进行压缩，以减少存储空间占用。
*   **条件:**  压缩只会在满足特定条件时进行，例如开启了相应的特性标志 (`features::kIndexedDBCompressValuesWithSnappy`)，并且值的未压缩大小超过一定的阈值 (`mojom::blink::kIDBWrapThreshold`)。压缩效果也会被评估，如果压缩比不高或解压后体积过大，则不会保留压缩。
*   **与 JavaScript 的关系:**  压缩过程对 JavaScript 代码是透明的。当 JavaScript 代码尝试读取数据时，会先进行解压缩。
*   **假设输入与输出:**
    *   **假设输入 (序列化后的字节流):**  一段较长的表示字符串的字节流。
    *   **输出 (压缩后):**  一段更短的字节流，开头包含指示压缩类型的特定标识 (`kCompressedWithSnappy`)。

**3. 值“包装” (Wrapping):**

*   **功能:**  对于体积较大的值（超过一定的阈值 `mojom::blink::kIDBWrapThreshold`），将其内容存储在单独的 `Blob` 对象中，然后在 IndexedDB 中存储一个指向该 `Blob` 的小“包装器”。
*   **目的:**  避免将过大的数据直接加载到内存中，提高 IndexedDB 操作的性能和内存使用效率。
*   **与 JavaScript 和 HTML 的关系:**
    *   **JavaScript:**  当 JavaScript 代码请求一个被“包装”的值时，IndexedDB 需要先获取 `Blob` 对象，然后从中读取实际的数据。这涉及到异步操作。
    *   **HTML:**  `Blob` 对象本身是 Web API 的一部分，常用于处理文件上传下载等场景。这里将其用于 IndexedDB 的内部优化。
*   **假设输入与输出:**
    *   **假设输入 (序列化后的字节流):**  一段非常长的表示大型 JavaScript 数组的字节流。
    *   **输出 (包装后):**
        *   IndexedDB 中存储一小段字节流，包含特定的标识 (`kReplaceWithBlob`)、`Blob` 的大小以及 `Blob` 在内部 `blob_info_` 列表中的索引。
        *   实际的数据存储在一个单独的 `Blob` 对象中。

**4. 值解包和解压缩:**

*   **功能:**  `IDBValueUnwrapper` 类负责识别和处理被压缩或被“包装”的值，将其恢复为原始的序列化后的字节流。
*   **与 JavaScript 的关系:**  这是将 IndexedDB 中存储的数据转换回 JavaScript 值的第一步。在反序列化之前，需要先进行解包和解压缩。

**5. 错误处理和调试:**

*   **功能:**  代码中包含了一些断言 (`DCHECK`)，用于在开发和调试阶段检查代码的正确性。
*   **调试线索:**  如果 IndexedDB 中存储的数据出现问题，例如无法反序列化，可以检查以下几点：
    *   **是否被“包装”了:**  `IDBValueUnwrapper::IsWrapped()` 可以判断一个 `IDBValue` 是否被包装。
    *   **是否被压缩了:**  `IDBValueUnwrapper::Decompress()` 可以尝试解压缩数据。
    *   **`Blob` 对象是否存在且完整:** 如果被包装了，需要确保对应的 `Blob` 对象存在且大小正确。

**用户操作如何一步步地到达这里（作为调试线索）:**

1. **用户在网页上执行 JavaScript 代码，使用 IndexedDB API 存储数据:**
    ```javascript
    const request = indexedDB.open("myDatabase", 1);
    request.onsuccess = function(event) {
      const db = event.target.result;
      const transaction = db.transaction(["myStore"], "readwrite");
      const store = transaction.objectStore("myStore");
      const data = { name: "Very Long String Here ...", moreData: [...] }; // 或者一个很大的 Blob 对象
      store.put(data, "myKey");
    };
    ```
2. **Blink 渲染引擎接收到存储数据的请求。**
3. **`IDBValueWrapper` 被创建，传入要存储的 JavaScript 值 (`data`)。**
4. **`SerializedScriptValue::Serialize()` 被调用，将 JavaScript 值序列化为字节流。**
5. **`IDBValueWrapper::DoneCloning()` 被调用，判断是否需要压缩或包装。**
    *   **如果 `data` 很小且未启用压缩，则直接返回序列化后的字节流。**
    *   **如果 `data` 较大且启用了压缩，则使用 Snappy 压缩，并添加压缩头。**
    *   **如果 `data` 非常大，则将其放入 `Blob` 对象中，并在 `IDBValueWrapper` 中存储指向 `Blob` 的信息。**
6. **最终生成的字节流（可能被压缩或包装过）被传递给 IndexedDB 后端进行持久化存储。**

**用户或编程常见的使用错误举例说明:**

1. **尝试存储无法被序列化的 JavaScript 值:**  某些 JavaScript 对象（例如包含循环引用的对象）无法被 `SerializedScriptValue` 正确序列化，会导致异常。
    ```javascript
    const obj = {};
    obj.circular = obj;
    store.put(obj, "circularKey"); // 可能抛出错误
    ```
2. **在读取被包装的值之前，`Blob` 对象被意外删除或修改:**  这会导致在解包时找不到对应的 `Blob` 数据，导致数据丢失或损坏。这通常发生在底层存储机制出现问题时，而不是用户的直接操作。
3. **假设数据始终是未压缩的或未包装的进行处理:**  如果代码直接假设从 IndexedDB 读取的数据是原始的序列化格式，而没有考虑到压缩和包装的可能性，则可能无法正确解析数据。应该使用 `IDBValueUnwrapper` 来处理读取到的数据。

**逻辑推理的假设输入与输出:**

**假设输入 1 (未压缩，未包装):**

*   **JavaScript 值:**  `123` (一个简单的数字)
*   **`SerializedScriptValue::Serialize()` 输出:**  `[0xFF, 0x11, 0xFF, 0x0D, ... (表示数字 123 的序列化数据)]` (这是一个简化的例子，实际的字节会更复杂)
*   **`IDBValueWrapper::MaybeCompress()` 输出:**  不压缩，返回原始的序列化数据。
*   **`IDBValueWrapper::MaybeStoreInBlob()` 输出:**  不包装，返回原始的序列化数据。
*   **`IDBValueWrapper::TakeWireBytes()` 输出:**  `[0xFF, 0x11, 0xFF, 0x0D, ... (表示数字 123 的序列化数据)]`

**假设输入 2 (压缩，未包装):**

*   **JavaScript 值:**  `"This is a long string to test compression."`
*   **`SerializedScriptValue::Serialize()` 输出:**  `[0xFF, 0x11, 0xFF, 0x0D, ... (表示该字符串的序列化数据)]` (假设大小超过压缩阈值)
*   **`IDBValueWrapper::MaybeCompress()` 输出:**  `[0xFF, 0x11, 0x02, ... (Snappy 压缩后的数据)]`
*   **`IDBValueWrapper::MaybeStoreInBlob()` 输出:**  不包装，返回压缩后的数据。
*   **`IDBValueWrapper::TakeWireBytes()` 输出:**  `[0xFF, 0x11, 0x02, ... (Snappy 压缩后的数据)]`

**假设输入 3 (未压缩，包装):**

*   **JavaScript 值:**  一个非常大的 JavaScript 对象。
*   **`SerializedScriptValue::Serialize()` 输出:**  `[0xFF, 0x11, 0xFF, 0x0D, ... (表示该大型对象的序列化数据)]` (假设大小超过包装阈值)
*   **`IDBValueWrapper::MaybeCompress()` 输出:**  不压缩，因为包装通常在压缩之后进行，或者大对象可能不适合压缩。
*   **`IDBValueWrapper::MaybeStoreInBlob()` 输出:**  `Blob` 对象被创建，包含原始序列化数据。`TakeWireBytes()` 返回 `[0xFF, 0x11, 0x01, <Blob 大小>, <Blob 索引>]`。
*   **`IDBValueWrapper::TakeWireBytes()` 输出:**  `[0xFF, 0x11, 0x01, <Blob 大小>, <Blob 索引>]`

总而言之，`idb_value_wrapping.cc` 是 Chromium Blink 引擎中 IndexedDB 模块的关键组成部分，它负责高效地存储和检索 JavaScript 数据，并通过压缩和包装等技术来优化性能和资源利用。 理解这个文件的功能有助于开发者更好地理解 IndexedDB 的内部工作原理，并能更好地进行调试和错误排查。

Prompt: 
```
这是目录为blink/renderer/modules/indexeddb/idb_value_wrapping.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/metrics/field_trial_params.h"
#include "base/numerics/safe_conversions.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/indexeddb/indexeddb.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialization_tag.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_binding_for_modules.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_request.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_value.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/snappy/src/snappy.h"

namespace blink {

namespace {

// V8 values are stored on disk by IndexedDB using the format implemented in
// SerializedScriptValue (SSV). The wrapping detection logic in
// IDBValueUnwrapper::IsWrapped() must be able to distinguish between SSV byte
// sequences produced and byte sequences expressing the fact that an IDBValue
// has been wrapped and requires post-processing.
//
// The detection logic takes advantage of the highly regular structure around
// SerializedScriptValue. A version 17 byte sequence always starts with the
// following four bytes:
//
// 1) 0xFF - kVersionTag
// 2) 0x11 - Blink wrapper version, 17
// 3) 0xFF - kVersionTag
// 4) 0x0D - V8 serialization version, currently 13, doesn't matter
//
// It follows that SSV will never produce byte sequences starting with 0xFF,
// 0x11, and any value except for 0xFF. If the SSV format changes, the version
// will have to be bumped.

// The SSV format version whose encoding hole is (ab)used for wrapping.
static const uint8_t kRequiresProcessingSSVPseudoVersion = 17;

// SSV processing command replacing the SSV data bytes with a Blob's contents.
//
// 1) 0xFF - kVersionTag
// 2) 0x11 - kRequiresProcessingSSVPseudoVersion
// 3) 0x01 - kReplaceWithBlob
// 4) varint - Blob size
// 5) varint - the offset of the SSV-wrapping Blob in the IDBValue list of Blobs
//             (should always be the last Blob)
static const uint8_t kReplaceWithBlob = 1;

// A similar approach is used to notate compressed data.
// 1) 0xFF - kVersionTag
// 2) 0x11 - kRequiresProcessingSSVPseudoVersion
// 3) 0x02 - kCompressedWithSnappy
// 4) the compressed data

// Data is compressed using Snappy in a single chunk (i.e. without framing).
static const uint8_t kCompressedWithSnappy = 2;

// The number of header bytes in the above scheme.
static const size_t kHeaderSize = 3u;

// Evaluates whether to transmit and store a payload in its compressed form
// based on the compression achieved. Decompressing has a cost in terms of both
// CPU and memory usage, so we skip it for less compressible or jumbo data.
bool ShouldTransmitCompressed(size_t uncompressed_length,
                              size_t compressed_length) {
  // Don't keep compressed if compression ratio is poor.
  if (compressed_length > uncompressed_length * 0.9) {
    return false;
  }

  // Don't keep compressed if decompressed size is large. Snappy doesn't have
  // native support for streamed decoding, so decompressing requires
  // O(uncompressed_length) memory more than handling an uncompressed value
  // would.
  // TODO(estade): implement framing as described in
  // https://github.com/google/snappy/blob/main/framing_format.txt
  if (compressed_length > 256000U) {
    return false;
  }

  return true;
}

}  // namespace

IDBValueWrapper::IDBValueWrapper(
    v8::Isolate* isolate,
    v8::Local<v8::Value> value,
    SerializedScriptValue::SerializeOptions::WasmSerializationPolicy
        wasm_policy,
    ExceptionState& exception_state) {
  SerializedScriptValue::SerializeOptions options;
  options.blob_info = &blob_info_;
  options.for_storage = SerializedScriptValue::kForStorage;
  options.wasm_policy = wasm_policy;

  serialized_value_ = SerializedScriptValue::Serialize(isolate, value, options,
                                                       exception_state);
  if (serialized_value_) {
    original_data_length_ = serialized_value_->DataLengthInBytes();
  }
#if DCHECK_IS_ON()
  if (exception_state.HadException())
    had_exception_ = true;
#endif  // DCHECK_IS_ON()
}

// Explicit destructor in the .cpp file, to move the dependency on the
// BlobDataHandle definition away from the header file.
IDBValueWrapper::~IDBValueWrapper() = default;

void IDBValueWrapper::Clone(ScriptState* script_state, ScriptValue* clone) {
#if DCHECK_IS_ON()
  DCHECK(!had_exception_) << __func__
                          << " called on wrapper with serialization exception";
  DCHECK(!done_cloning_) << __func__ << " called after DoneCloning()";
#endif  // DCHECK_IS_ON()

  *clone = DeserializeScriptValue(script_state, serialized_value_.get(),
                                  &blob_info_);
}

// static
void IDBValueWrapper::WriteVarInt(unsigned value, Vector<char>& output) {
  // Writes an unsigned integer as a base-128 varint.
  // The number is written, 7 bits at a time, from the least significant to
  // the most significant 7 bits. Each byte, except the last, has the MSB set.
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  do {
    output.push_back((value & 0x7F) | 0x80);
    value >>= 7;
  } while (value);
  output.back() &= 0x7F;
}

void IDBValueWrapper::DoneCloning() {
#if DCHECK_IS_ON()
  DCHECK(!had_exception_) << __func__
                          << " called on wrapper with serialization exception";
  DCHECK(!done_cloning_) << __func__ << " called twice";
  done_cloning_ = true;
  DCHECK(owns_blob_info_) << __func__ << " called after TakeBlobInfo()";
  DCHECK(owns_wire_bytes_) << __func__ << " called after TakeWireBytes()";
#endif  // DCHECK_IS_ON()

  wire_data_ = serialized_value_->GetWireData();
  MaybeCompress();
  MaybeStoreInBlob();
}

bool IDBValueWrapper::ShouldCompress(size_t uncompressed_length) const {
  static int field_trial_threshold =
      features::kIndexedDBCompressValuesWithSnappyCompressionThreshold.Get();
  return base::FeatureList::IsEnabled(
             features::kIndexedDBCompressValuesWithSnappy) &&
         uncompressed_length >=
             compression_threshold_override_.value_or(static_cast<size_t>(
                 field_trial_threshold < 0 ? mojom::blink::kIDBWrapThreshold
                                           : field_trial_threshold));
}

void IDBValueWrapper::MaybeCompress() {
  if (!base::FeatureList::IsEnabled(
          features::kIndexedDBCompressValuesWithSnappy)) {
    return;
  }

  DCHECK(wire_data_buffer_.empty());
  const size_t wire_data_size = wire_data_.size();

  if (!ShouldCompress(wire_data_size)) {
    return;
  }

  wire_data_buffer_.resize(
      kHeaderSize +
      static_cast<wtf_size_t>(snappy::MaxCompressedLength(wire_data_size)));
  wire_data_buffer_[0] = static_cast<uint8_t>(kVersionTag);
  wire_data_buffer_[1] = kRequiresProcessingSSVPseudoVersion;
  wire_data_buffer_[2] = kCompressedWithSnappy;
  size_t compressed_length;
  snappy::RawCompress(
      reinterpret_cast<const char*>(wire_data_.data()), wire_data_size,
      reinterpret_cast<char*>(wire_data_buffer_.data() + kHeaderSize),
      &compressed_length);
  if (ShouldTransmitCompressed(wire_data_size, compressed_length)) {
    // Truncate the excess space that was previously allocated.
    wire_data_buffer_.resize(kHeaderSize +
                             static_cast<wtf_size_t>(compressed_length));
  } else {
    CHECK_GE(wire_data_buffer_.size(), wire_data_size);
    // Compression wasn't very successful, but we still allocated a large chunk
    // of memory, so we can repurpose it. This copy saves us from making another
    // allocation later on in `MaybeStoreInBlob()` or `TakeWireBytes()`.
    memcpy(wire_data_buffer_.data(), wire_data_.data(), wire_data_size);
    wire_data_buffer_.resize(static_cast<wtf_size_t>(wire_data_size));
  }

  wire_data_ = base::make_span(
      reinterpret_cast<const uint8_t*>(wire_data_buffer_.data()),
      wire_data_buffer_.size());
}

void IDBValueWrapper::MaybeStoreInBlob() {
  const unsigned wrapping_threshold =
      wrapping_threshold_override_.value_or(mojom::blink::kIDBWrapThreshold);
  if (wire_data_.size() <= wrapping_threshold) {
    return;
  }

  // TODO(pwnall): The MIME type should probably be an atomic string.
  String mime_type(kWrapMimeType);
  auto wrapper_blob_data = std::make_unique<BlobData>();
  wrapper_blob_data->SetContentType(String(kWrapMimeType));

  if (wire_data_buffer_.empty()) {
    DCHECK(!ShouldCompress(wire_data_.size()));
    wrapper_blob_data->AppendBytes(wire_data_);
  } else {
    scoped_refptr<RawData> raw_data = RawData::Create();
    raw_data->MutableData()->swap(wire_data_buffer_);
    wrapper_blob_data->AppendData(std::move(raw_data));
  }
  const size_t wire_data_size = wire_data_.size();
  blob_info_.emplace_back(
      BlobDataHandle::Create(std::move(wrapper_blob_data), wire_data_size));

  DCHECK(wire_data_buffer_.empty());
  wire_data_buffer_.push_back(kVersionTag);
  wire_data_buffer_.push_back(kRequiresProcessingSSVPseudoVersion);
  wire_data_buffer_.push_back(kReplaceWithBlob);
  IDBValueWrapper::WriteVarInt(base::checked_cast<unsigned>(wire_data_size),
                               wire_data_buffer_);
  IDBValueWrapper::WriteVarInt(blob_info_.size() - 1, wire_data_buffer_);

  wire_data_ = base::make_span(
      reinterpret_cast<const uint8_t*>(wire_data_buffer_.data()),
      wire_data_buffer_.size());
  DCHECK(!wire_data_buffer_.empty());
}

Vector<char> IDBValueWrapper::TakeWireBytes() {
#if DCHECK_IS_ON()
  DCHECK(done_cloning_) << __func__ << " called before DoneCloning()";
  DCHECK(owns_wire_bytes_) << __func__ << " called twice";
  owns_wire_bytes_ = false;
#endif  // DCHECK_IS_ON()

  if (wire_data_buffer_.empty()) {
    DCHECK(!ShouldCompress(wire_data_.size()));
    // The wire bytes are coming directly from the SSV's GetWireData() call.
    DCHECK_EQ(wire_data_.data(), serialized_value_->GetWireData().data());
    DCHECK_EQ(wire_data_.size(), serialized_value_->GetWireData().size());
    return Vector<char>(wire_data_);
  }

  // The wire bytes are coming from wire_data_buffer_, so we can avoid a copy.
  DCHECK_EQ(wire_data_buffer_.data(),
            reinterpret_cast<const char*>(wire_data_.data()));
  DCHECK_EQ(wire_data_buffer_.size(), wire_data_.size());
  return std::move(wire_data_buffer_);
}

IDBValueUnwrapper::IDBValueUnwrapper() {
  Reset();
}

// static
bool IDBValueUnwrapper::IsWrapped(IDBValue* value) {
  DCHECK(value);

  if (value->DataSize() < kHeaderSize) {
    return false;
  }
  base::span<const uint8_t> data_span = base::as_byte_span(value->Data());
  return data_span[0] == kVersionTag &&
         data_span[1] == kRequiresProcessingSSVPseudoVersion &&
         data_span[2] == kReplaceWithBlob;
}

// static
bool IDBValueUnwrapper::IsWrapped(
    const Vector<std::unique_ptr<IDBValue>>& values) {
  for (const auto& value : values) {
    if (IsWrapped(value.get()))
      return true;
  }
  return false;
}

// static
void IDBValueUnwrapper::Unwrap(Vector<char>&& wrapper_blob_content,
                               IDBValue& wrapped_value) {
  wrapped_value.SetData(std::move(wrapper_blob_content));
  wrapped_value.TakeLastBlob();
}

// static
bool IDBValueUnwrapper::Decompress(const Vector<char>& buffer,
                                   Vector<char>* out_buffer) {
  if (buffer.size() < kHeaderSize) {
    return false;
  }
  base::span<const uint8_t> data_span = base::as_byte_span(buffer);

  if (data_span[0] != kVersionTag ||
      data_span[1] != kRequiresProcessingSSVPseudoVersion ||
      data_span[2] != kCompressedWithSnappy) {
    return false;
  }

  base::span<const char> compressed(
      base::as_chars(data_span.subspan(kHeaderSize)));

  Vector<char> decompressed_data;
  size_t decompressed_length;
  if (!snappy::GetUncompressedLength(compressed.data(), compressed.size(),
                                     &decompressed_length)) {
    return false;
  }

  decompressed_data.resize(static_cast<wtf_size_t>(decompressed_length));
  snappy::RawUncompress(compressed.data(), compressed.size(),
                        decompressed_data.data());
  *out_buffer = std::move(decompressed_data);
  return true;
}

bool IDBValueUnwrapper::Parse(IDBValue* value) {
  // Fast path that avoids unnecessary dynamic allocations.
  if (!IDBValueUnwrapper::IsWrapped(value))
    return false;

  const uint8_t* data = reinterpret_cast<const uint8_t*>(value->Data().data());
  end_ = data + value->DataSize();
  current_ = data + kHeaderSize;

  if (!ReadVarInt(blob_size_))
    return Reset();

  unsigned blob_offset;
  if (!ReadVarInt(blob_offset))
    return Reset();

  size_t value_blob_count = value->blob_info_.size();
  if (!value_blob_count || blob_offset != value_blob_count - 1)
    return Reset();

  blob_handle_ = value->blob_info_.back().GetBlobHandle();
  if (blob_handle_->size() != blob_size_)
    return Reset();

  return true;
}

scoped_refptr<BlobDataHandle> IDBValueUnwrapper::WrapperBlobHandle() {
  DCHECK(blob_handle_);

  return std::move(blob_handle_);
}

bool IDBValueUnwrapper::ReadVarInt(unsigned& value) {
  value = 0;
  unsigned shift = 0;
  bool has_another_byte;
  do {
    if (current_ >= end_)
      return false;

    if (shift >= sizeof(unsigned) * 8)
      return false;
    uint8_t byte = *current_;
    ++current_;
    value |= static_cast<unsigned>(byte & 0x7F) << shift;
    shift += 7;

    has_another_byte = byte & 0x80;
  } while (has_another_byte);
  return true;
}

bool IDBValueUnwrapper::ReadBytes(Vector<uint8_t>& value) {
  unsigned length;
  if (!ReadVarInt(length))
    return false;

  DCHECK_LE(current_, end_);
  if (end_ - current_ < static_cast<ptrdiff_t>(length))
    return false;
  Vector<uint8_t> result;
  result.ReserveInitialCapacity(length);
  result.Append(current_, length);
  value = std::move(result);
  current_ += length;
  return true;
}

bool IDBValueUnwrapper::Reset() {
#if DCHECK_IS_ON()
  blob_handle_ = nullptr;
  current_ = nullptr;
  end_ = nullptr;
#endif  // DCHECK_IS_ON()
  return false;
}

}  // namespace blink

"""

```