Response:
The user wants a summary of the functionality of the provided C++ code snippet.
The code is located in `v8/src/objects/value-serializer.cc` and appears to be related to serializing JavaScript values.

Here's a breakdown of the code's features and considerations:

1. **File Location and Naming:** The user correctly identified the file path. The prompt also asks about a `.tq` extension, which is relevant for Torque files but not applicable here.

2. **Core Functionality:** The code defines a `ValueSerializer` class. Based on the includes and the code itself, the primary function is to convert JavaScript values into a byte stream for storage or transmission.

3. **Serialization Format:** The comments highlight the importance of backward compatibility for the serialization format. This is crucial for persistent storage like IndexedDB. The code also defines `SerializationTag` enum, which lists the different types of JavaScript values that can be serialized.

4. **Versioning:** The code maintains a `kLatestVersion` constant to handle changes in the serialization format. This is essential for backward compatibility.

5. **Data Types Support:** The `SerializationTag` enum and the `Write...` methods indicate support for serializing various JavaScript data types, including:
    - Primitive values (undefined, null, boolean, numbers, strings, BigInt)
    - Objects (plain objects, arrays, dates, primitive wrappers, regular expressions, Maps, Sets)
    - ArrayBuffers and Typed Arrays
    - SharedArrayBuffers
    - Errors
    - Potentially WebAssembly-related objects (if `V8_ENABLE_WEBASSEMBLY` is defined)

6. **Serialization Strategies:** The code seems to employ different strategies for different data types:
    - Varint encoding for integers.
    - Direct byte representation for doubles (with a note about endianness).
    - Tag-based identification of object types.
    - Handling of sparse and dense arrays.
    - Object references to avoid redundant serialization of the same object.

7. **Delegation:** The `ValueSerializer` constructor takes a `v8::ValueSerializer::Delegate*`, suggesting a mechanism for customizing the serialization process, particularly for host objects.

8. **Error Handling:** The code includes checks for `out_of_memory_` and has a `ThrowDataCloneError` function, indicating awareness of potential serialization failures.

9. **Potential User Errors:**  Given the complexity, common errors might involve:
    - Trying to serialize non-serializable types (functions, symbols).
    - Issues with the serialization format version if custom serialization is involved.

**Plan for the response:**

- State that the file is a C++ source file, not Torque.
- Confirm its main function is serializing JavaScript values.
- List the supported data types.
- Explain the importance of backward compatibility and versioning.
- Mention the use of tags and different encoding schemes.
- Point out the delegation mechanism.
这个C++源代码文件 `v8/src/objects/value-serializer.cc` 的主要功能是**将 JavaScript 的值序列化成字节流**，以便存储或传输。这个过程也被称为**数据克隆**或者**序列化**。

以下是更详细的功能点：

1. **定义了序列化格式:**  代码中定义了 `SerializationTag` 枚举，它列出了所有可以被序列化的 JavaScript 数据类型，并为每种类型分配了一个唯一的标签。这个标签用于在反序列化时识别数据的类型。

2. **实现了多种数据类型的序列化:**  文件中包含了针对不同 JavaScript 数据类型的序列化逻辑，例如：
    - **基本类型:** `undefined`, `null`, 布尔值 (`true`, `false`)，数字 (整数和浮点数)，字符串。
    - **对象:** 普通 JavaScript 对象，数组，Date 对象，布尔值对象，数字对象，字符串对象，正则表达式对象，Map 和 Set 对象。
    - **缓冲区:** ArrayBuffer 和 TypedArray (例如 Int8Array, Uint32Array 等)。
    - **共享缓冲区:** SharedArrayBuffer。
    - **BigInt:**  用于表示任意精度的整数。
    - **错误对象:** EvalError, RangeError, ReferenceError 等。
    - **宿主对象 (Host Objects):**  允许外部代码自定义序列化逻辑。
    - **WebAssembly 相关对象:** (如果 `V8_ENABLE_WEBASSEMBLY` 宏定义被启用)  例如 WasmModuleObject 和 WasmMemoryObject。

3. **保证向后兼容性:**  代码注释中强调了保持序列化格式向后兼容的重要性。这是因为这个格式被 API 用于持久化数据到磁盘，例如 IndexedDB。 为了做到这一点，引入了版本控制 (`kLatestVersion`)。当序列化格式发生不兼容的改变时，版本号会被增加，反序列化器需要能够处理旧版本的格式。

4. **使用不同的编码方式:**  为了优化存储空间，代码使用了不同的编码方式：
    - **Varint 编码:**  用于编码无符号整数，可以有效地表示较小的数字。
    - **ZigZag 编码:** 用于编码有符号整数，可以有效地表示接近零的数字。
    - **直接字节写入:** 对于浮点数和原始字节数据。

5. **处理对象引用:**  为了避免重复序列化相同的对象，序列化器会跟踪已经序列化的对象，并在后续遇到相同的对象时，写入一个引用 (`kObjectReference`) 而不是完整的数据。

6. **处理循环引用:**  虽然代码没有显式地展示循环引用的处理逻辑，但通过对象引用的机制，理论上可以避免因循环引用导致的无限递归。

7. **支持 ArrayBuffer 的传输:**  `TransferArrayBuffer` 函数表明了序列化器可以处理 ArrayBuffer 的传输，这通常用于 Web Workers 或 Message Channels 之间的通信，避免数据的复制。

8. **委托机制 (Delegate):**  `ValueSerializer` 构造函数接受一个 `v8::ValueSerializer::Delegate*` 参数，这允许外部代码提供自定义的序列化逻辑，特别是对于宿主对象 (`kHostObject`)。

9. **错误处理:**  代码中包含了错误处理机制，例如当尝试序列化无法克隆的数据类型时，会抛出 `DataCloneError`。

**如果 `v8/src/objects/value-serializer.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码**

这是不正确的。当前的文件名是 `value-serializer.cc`，以 `.cc` 结尾，表明它是一个 **C++ 源代码文件**。 如果文件名为 `value-serializer.tq`，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种 V8 内部使用的类型安全的高级语言，用于生成高效的机器码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明**

`ValueSerializer` 的功能直接对应了 JavaScript 中的 `structuredClone()` 函数以及 `postMessage()` 方法在处理复杂对象时的内部机制。

**JavaScript 示例：**

```javascript
// 使用 structuredClone 进行克隆
const originalObject = { a: 1, b: 'hello', c: [1, 2, 3] };
const clonedObject = structuredClone(originalObject);
console.log(clonedObject); // 输出: { a: 1, b: 'hello', c: [1, 2, 3] }
console.log(originalObject === clonedObject); // 输出: false (是深拷贝)

// 使用 postMessage 在 Web Worker 中传输数据 (内部使用了类似的序列化机制)
const worker = new Worker('worker.js');
const dataToSend = { message: 'Hello from main thread!' };
worker.postMessage(dataToSend);

// 在 worker.js 中
onmessage = function(e) {
  console.log('Worker received:', e.data);
}
```

在上面的例子中，`structuredClone()` 函数和 `postMessage()` 方法的幕后工作原理就涉及到类似于 `v8/src/objects/value-serializer.cc` 中实现的序列化过程。它们需要将 JavaScript 对象转换为可以存储或传输的格式，并且在另一端能够正确地重建对象。

**如果有代码逻辑推理，请给出假设输入与输出**

假设我们要序列化一个简单的 JavaScript 对象：

**假设输入 (JavaScript 对象):**

```javascript
const input = { key: "value", count: 42 };
```

**可能的序列化输出 (字节流 - 简化表示):**

```
o  // kBeginJSObject 标签
S  // kUtf8String 标签 (表示接下来的字符串是 UTF-8 编码)
5  // 字符串 "key" 的长度 (Varint 编码)
k e y  // 字符串 "key" 的内容
S  // kUtf8String 标签
5  // 字符串 "value" 的长度
v a l u e // 字符串 "value" 的内容
S  // kUtf8String 标签
5  // 字符串 "count" 的长度
c o u n t // 字符串 "count" 的内容
I  // kInt32 标签 (表示接下来的数字是 32 位整数)
84 // 数字 42 的 ZigZag 编码 (假设)
{  // kEndJSObject 标签
2  // 属性数量 (Varint 编码)
```

**解释:**

- `o` 表示开始一个 JavaScript 对象。
- `S` 表示接下来的数据是一个 UTF-8 编码的字符串。
- 紧随 `S` 后的数字是字符串的长度，使用 Varint 编码。
- 之后是字符串的实际内容。
- `I` 表示接下来的数据是一个 32 位有符号整数，使用 ZigZag 编码。
- `{` 表示 JavaScript 对象结束。
- 最后的 `2` 表示这个对象有 2 个属性。

**注意:** 这只是一个简化的表示。实际的字节流会包含更多的细节，例如版本信息等，并且编码方式可能更复杂。

**如果涉及用户常见的编程错误，请举例说明**

用户在使用涉及到序列化的 API (例如 `structuredClone`, `postMessage`) 时，常见的编程错误包括：

1. **尝试克隆不可序列化的值:**  某些 JavaScript 值是不可序列化的，例如 `Symbol`，函数，包含循环引用的对象（如果序列化器没有正确处理）。

   ```javascript
   const obj = {
     a: 1,
     b: function() { console.log('hello'); } // 尝试克隆函数
   };
   try {
     structuredClone(obj); // 会抛出 DataCloneError
   } catch (e) {
     console.error(e); // 输出 DataCloneError
   }
   ```

2. **在 `postMessage` 中传递不可序列化的值:** 类似于 `structuredClone`，`postMessage` 也有其可以传输的数据类型限制。

   ```javascript
   const worker = new Worker('worker.js');
   const nonSerializable = new WeakMap(); // WeakMap 不可序列化
   try {
     worker.postMessage(nonSerializable); // 可能会抛出错误，具体取决于浏览器实现
   } catch (e) {
     console.error(e);
   }
   ```

3. **假设克隆是绝对独立的:**  虽然 `structuredClone` 进行的是深拷贝，但某些类型的对象 (例如 `ArrayBuffer`) 在传输后可能会被 "转移" (transferable)，这意味着原始对象将变得不可用或状态被改变。

   ```javascript
   const buffer = new ArrayBuffer(10);
   const clonedBuffer = structuredClone(buffer);
   console.log(buffer === clonedBuffer); // 输出 false

   const worker = new Worker('worker.js');
   worker.postMessage(buffer, [buffer]); // 将 buffer 转移到 worker
   console.log(buffer.byteLength); // 在某些浏览器中，这里可能为 0，因为 buffer 已被转移
   ```

**这是第1部分，共4部分，请归纳一下它的功能**

总而言之，`v8/src/objects/value-serializer.cc` 的主要功能是 **实现 JavaScript 值的序列化**。它定义了序列化格式，支持多种数据类型，并考虑了向后兼容性、性能优化和错误处理。这个模块是 V8 引擎中用于数据克隆和跨上下文通信等功能的核心组件。

Prompt: 
```
这是目录为v8/src/objects/value-serializer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/value-serializer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/value-serializer.h"

#include <type_traits>

#include "include/v8-maybe.h"
#include "include/v8-value-serializer-version.h"
#include "include/v8-value-serializer.h"
#include "include/v8-wasm.h"
#include "src/api/api-inl.h"
#include "src/base/logging.h"
#include "src/base/platform/memory.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/handles/global-handles-inl.h"
#include "src/handles/handles-inl.h"
#include "src/handles/maybe-handles-inl.h"
#include "src/handles/shared-object-conveyor-handles.h"
#include "src/heap/factory.h"
#include "src/numbers/conversions.h"
#include "src/objects/heap-number-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-buffer.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/js-collection-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/js-shared-array-inl.h"
#include "src/objects/js-struct-inl.h"
#include "src/objects/map-updater.h"
#include "src/objects/objects-inl.h"
#include "src/objects/objects.h"
#include "src/objects/oddball-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/property-details.h"
#include "src/objects/smi.h"
#include "src/objects/transitions-inl.h"
#include "src/regexp/regexp.h"
#include "src/snapshot/code-serializer.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-objects-inl.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

// WARNING: This serialization format MUST remain backward compatible!
//
// This format is used by APIs to persist values to disk, e.g. IndexedDB.
//
// Backward compatibility means that when the format changes, deserializing
// valid values in the older format must behave identically as before the
// change. To maintain compatibility, either a format change does not affect the
// deserializing behavior of valid values in the older format, or the
// kLatestVersion constant is bumped.
//
// Adding a new tag is backwards compatible because no valid serialized value in
// older formats would contain the new object tag.
//
// On the other hand, changing the format of a particular tag is backwards
// incompatible and the version must be bumped. For example, a JSArrayBufferView
// tag prior to version 14 was followed by the sub-tag, the byte offset, and the
// byte length. Starting with version 14, a JSArrayBufferView tag is followed by
// the sub-tag, the byte offset, the byte length, and flags. Due the addition of
// flags, older valid serialized values for JSArrayBufferViews would be
// misinterpreted by newer deserializers. This requires the version to be bumped
// and the deserializer to handle both the old and new formats depending on the
// version.

// Version 9: (imported from Blink)
// Version 10: one-byte (Latin-1) strings
// Version 11: properly separate undefined from the hole in arrays
// Version 12: regexp and string objects share normal string encoding
// Version 13: host objects have an explicit tag (rather than handling all
//             unknown tags)
// Version 14: flags for JSArrayBufferViews
// Version 15: support for shared objects with an explicit tag
//
// WARNING: Increasing this value is a change which cannot safely be rolled
// back without breaking compatibility with data stored on disk. It is
// strongly recommended that you do not make such changes near a release
// milestone branch point.
//
// Recent changes are routinely reverted in preparation for branch, and this
// has been the cause of at least one bug in the past.
static const uint32_t kLatestVersion = 15;
static_assert(kLatestVersion == v8::CurrentValueSerializerFormatVersion(),
              "Exported format version must match latest version.");

namespace {
// For serializing JSArrayBufferView flags. Instead of serializing /
// deserializing the flags directly, we serialize them bit by bit. This is for
// ensuring backwards compatibility in the case where the representation
// changes. Note that the ValueSerializer data can be stored on disk.
using JSArrayBufferViewIsLengthTracking = base::BitField<bool, 0, 1>;
using JSArrayBufferViewIsBackedByRab =
    JSArrayBufferViewIsLengthTracking::Next<bool, 1>;

}  // namespace

template <typename T>
static size_t BytesNeededForVarint(T value) {
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be written as varints.");
  size_t result = 0;
  do {
    result++;
    value >>= 7;
  } while (value);
  return result;
}

enum class SerializationTag : uint8_t {
  // version:uint32_t (if at beginning of data, sets version > 0)
  kVersion = 0xFF,
  // ignore
  kPadding = '\0',
  // refTableSize:uint32_t (previously used for sanity checks; safe to ignore)
  kVerifyObjectCount = '?',
  // Oddballs (no data).
  kTheHole = '-',
  kUndefined = '_',
  kNull = '0',
  kTrue = 'T',
  kFalse = 'F',
  // Number represented as 32-bit integer, ZigZag-encoded
  // (like sint32 in protobuf)
  kInt32 = 'I',
  // Number represented as 32-bit unsigned integer, varint-encoded
  // (like uint32 in protobuf)
  kUint32 = 'U',
  // Number represented as a 64-bit double.
  // Host byte order is used (N.B. this makes the format non-portable).
  kDouble = 'N',
  // BigInt. Bitfield:uint32_t, then raw digits storage.
  kBigInt = 'Z',
  // byteLength:uint32_t, then raw data
  kUtf8String = 'S',
  kOneByteString = '"',
  kTwoByteString = 'c',
  // Reference to a serialized object. objectID:uint32_t
  kObjectReference = '^',
  // Beginning of a JS object.
  kBeginJSObject = 'o',
  // End of a JS object. numProperties:uint32_t
  kEndJSObject = '{',
  // Beginning of a sparse JS array. length:uint32_t
  // Elements and properties are written as key/value pairs, like objects.
  kBeginSparseJSArray = 'a',
  // End of a sparse JS array. numProperties:uint32_t length:uint32_t
  kEndSparseJSArray = '@',
  // Beginning of a dense JS array. length:uint32_t
  // |length| elements, followed by properties as key/value pairs
  kBeginDenseJSArray = 'A',
  // End of a dense JS array. numProperties:uint32_t length:uint32_t
  kEndDenseJSArray = '$',
  // Date. millisSinceEpoch:double
  kDate = 'D',
  // Boolean object. No data.
  kTrueObject = 'y',
  kFalseObject = 'x',
  // Number object. value:double
  kNumberObject = 'n',
  // BigInt object. Bitfield:uint32_t, then raw digits storage.
  kBigIntObject = 'z',
  // String object, UTF-8 encoding. byteLength:uint32_t, then raw data.
  kStringObject = 's',
  // Regular expression, UTF-8 encoding. byteLength:uint32_t, raw data,
  // flags:uint32_t.
  kRegExp = 'R',
  // Beginning of a JS map.
  kBeginJSMap = ';',
  // End of a JS map. length:uint32_t.
  kEndJSMap = ':',
  // Beginning of a JS set.
  kBeginJSSet = '\'',
  // End of a JS set. length:uint32_t.
  kEndJSSet = ',',
  // Array buffer. byteLength:uint32_t, then raw data.
  kArrayBuffer = 'B',
  // Resizable ArrayBuffer.
  kResizableArrayBuffer = '~',
  // Array buffer (transferred). transferID:uint32_t
  kArrayBufferTransfer = 't',
  // View into an array buffer.
  // subtag:ArrayBufferViewTag, byteOffset:uint32_t, byteLength:uint32_t
  // For typed arrays, byteOffset and byteLength must be divisible by the size
  // of the element.
  // Note: kArrayBufferView is special, and should have an ArrayBuffer (or an
  // ObjectReference to one) serialized just before it. This is a quirk arising
  // from the previous stack-based implementation.
  kArrayBufferView = 'V',
  // Shared array buffer. transferID:uint32_t
  kSharedArrayBuffer = 'u',
  // A HeapObject shared across Isolates. sharedValueID:uint32_t
  kSharedObject = 'p',
  // A wasm module object transfer. next value is its index.
  kWasmModuleTransfer = 'w',
  // The delegate is responsible for processing all following data.
  // This "escapes" to whatever wire format the delegate chooses.
  kHostObject = '\\',
  // A transferred WebAssembly.Memory object. maximumPages:int32_t, then by
  // SharedArrayBuffer tag and its data.
  kWasmMemoryTransfer = 'm',
  // A list of (subtag: ErrorTag, [subtag dependent data]). See ErrorTag for
  // details.
  kError = 'r',

  // The following tags are reserved because they were in use in Chromium before
  // the kHostObject tag was introduced in format version 13, at
  //   v8           refs/heads/master@{#43466}
  //   chromium/src refs/heads/master@{#453568}
  //
  // They must not be reused without a version check to prevent old values from
  // starting to deserialize incorrectly. For simplicity, it's recommended to
  // avoid them altogether.
  //
  // This is the set of tags that existed in SerializationTag.h at that time and
  // still exist at the time of this writing (i.e., excluding those that were
  // removed on the Chromium side because there should be no real user data
  // containing them).
  //
  // It might be possible to also free up other tags which were never persisted
  // (e.g. because they were used only for transfer) in the future.
  kLegacyReservedMessagePort = 'M',
  kLegacyReservedBlob = 'b',
  kLegacyReservedBlobIndex = 'i',
  kLegacyReservedFile = 'f',
  kLegacyReservedFileIndex = 'e',
  kLegacyReservedDOMFileSystem = 'd',
  kLegacyReservedFileList = 'l',
  kLegacyReservedFileListIndex = 'L',
  kLegacyReservedImageData = '#',
  kLegacyReservedImageBitmap = 'g',
  kLegacyReservedImageBitmapTransfer = 'G',
  kLegacyReservedOffscreenCanvas = 'H',
  kLegacyReservedCryptoKey = 'K',
  kLegacyReservedRTCCertificate = 'k',
};

namespace {

enum class ArrayBufferViewTag : uint8_t {
  kInt8Array = 'b',
  kUint8Array = 'B',
  kUint8ClampedArray = 'C',
  kInt16Array = 'w',
  kUint16Array = 'W',
  kInt32Array = 'd',
  kUint32Array = 'D',
  kFloat16Array = 'h',
  kFloat32Array = 'f',
  kFloat64Array = 'F',
  kBigInt64Array = 'q',
  kBigUint64Array = 'Q',
  kDataView = '?',
};

// Sub-tags only meaningful for error serialization.
enum class ErrorTag : uint8_t {
  // The error is an EvalError. No accompanying data.
  kEvalErrorPrototype = 'E',
  // The error is a RangeError. No accompanying data.
  kRangeErrorPrototype = 'R',
  // The error is a ReferenceError. No accompanying data.
  kReferenceErrorPrototype = 'F',
  // The error is a SyntaxError. No accompanying data.
  kSyntaxErrorPrototype = 'S',
  // The error is a TypeError. No accompanying data.
  kTypeErrorPrototype = 'T',
  // The error is a URIError. No accompanying data.
  kUriErrorPrototype = 'U',
  // Followed by message: string.
  kMessage = 'm',
  // Followed by a JS object: cause.
  kCause = 'c',
  // Followed by stack: string.
  kStack = 's',
  // The end of this error information.
  kEnd = '.',
};

}  // namespace

ValueSerializer::ValueSerializer(Isolate* isolate,
                                 v8::ValueSerializer::Delegate* delegate)
    : isolate_(isolate),
      delegate_(delegate),
      zone_(isolate->allocator(), ZONE_NAME),
      id_map_(isolate->heap(), ZoneAllocationPolicy(&zone_)),
      array_buffer_transfer_map_(isolate->heap(),
                                 ZoneAllocationPolicy(&zone_)) {
  if (delegate_) {
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate_);
    has_custom_host_objects_ = delegate_->HasCustomHostObject(v8_isolate);
  }
}

ValueSerializer::~ValueSerializer() {
  if (buffer_) {
    if (delegate_) {
      delegate_->FreeBufferMemory(buffer_);
    } else {
      base::Free(buffer_);
    }
  }
}

void ValueSerializer::WriteHeader() {
  WriteTag(SerializationTag::kVersion);
  WriteVarint(kLatestVersion);
}

void ValueSerializer::SetTreatArrayBufferViewsAsHostObjects(bool mode) {
  treat_array_buffer_views_as_host_objects_ = mode;
}

void ValueSerializer::WriteTag(SerializationTag tag) {
  uint8_t raw_tag = static_cast<uint8_t>(tag);
  WriteRawBytes(&raw_tag, sizeof(raw_tag));
}

template <typename T>
void ValueSerializer::WriteVarint(T value) {
  // Writes an unsigned integer as a base-128 varint.
  // The number is written, 7 bits at a time, from the least significant to the
  // most significant 7 bits. Each byte, except the last, has the MSB set.
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  static_assert(std::is_integral<T>::value && std::is_unsigned<T>::value,
                "Only unsigned integer types can be written as varints.");
  uint8_t stack_buffer[sizeof(T) * 8 / 7 + 1];
  uint8_t* next_byte = &stack_buffer[0];
  do {
    *next_byte = (value & 0x7F) | 0x80;
    next_byte++;
    value >>= 7;
  } while (value);
  *(next_byte - 1) &= 0x7F;
  WriteRawBytes(stack_buffer, next_byte - stack_buffer);
}

template <typename T>
void ValueSerializer::WriteZigZag(T value) {
  // Writes a signed integer as a varint using ZigZag encoding (i.e. 0 is
  // encoded as 0, -1 as 1, 1 as 2, -2 as 3, and so on).
  // See also https://developers.google.com/protocol-buffers/docs/encoding
  // Note that this implementation relies on the right shift being arithmetic.
  static_assert(std::is_integral<T>::value && std::is_signed<T>::value,
                "Only signed integer types can be written as zigzag.");
  using UnsignedT = typename std::make_unsigned<T>::type;
  WriteVarint((static_cast<UnsignedT>(value) << 1) ^
              (value >> (8 * sizeof(T) - 1)));
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void ValueSerializer::WriteZigZag(int32_t value);

void ValueSerializer::WriteDouble(double value) {
  // Warning: this uses host endianness.
  WriteRawBytes(&value, sizeof(value));
}

void ValueSerializer::WriteOneByteString(base::Vector<const uint8_t> chars) {
  WriteVarint<uint32_t>(chars.length());
  WriteRawBytes(chars.begin(), chars.length() * sizeof(uint8_t));
}

void ValueSerializer::WriteTwoByteString(base::Vector<const base::uc16> chars) {
  // Warning: this uses host endianness.
  WriteVarint<uint32_t>(chars.length() * sizeof(base::uc16));
  WriteRawBytes(chars.begin(), chars.length() * sizeof(base::uc16));
}

void ValueSerializer::WriteBigIntContents(Tagged<BigInt> bigint) {
  uint32_t bitfield = bigint->GetBitfieldForSerialization();
  size_t bytelength = BigInt::DigitsByteLengthForBitfield(bitfield);
  WriteVarint<uint32_t>(bitfield);
  uint8_t* dest;
  if (ReserveRawBytes(bytelength).To(&dest)) {
    bigint->SerializeDigits(dest, bytelength);
  }
}

void ValueSerializer::WriteRawBytes(const void* source, size_t length) {
  uint8_t* dest;
  if (ReserveRawBytes(length).To(&dest) && length > 0) {
    memcpy(dest, source, length);
  }
}

Maybe<uint8_t*> ValueSerializer::ReserveRawBytes(size_t bytes) {
  size_t old_size = buffer_size_;
  size_t new_size = old_size + bytes;
  if (V8_UNLIKELY(new_size > buffer_capacity_)) {
    bool ok;
    if (!ExpandBuffer(new_size).To(&ok)) {
      return Nothing<uint8_t*>();
    }
  }
  buffer_size_ = new_size;
  return Just(&buffer_[old_size]);
}

Maybe<bool> ValueSerializer::ExpandBuffer(size_t required_capacity) {
  DCHECK_GT(required_capacity, buffer_capacity_);
  size_t requested_capacity =
      std::max(required_capacity, buffer_capacity_ * 2) + 64;
  size_t provided_capacity = 0;
  void* new_buffer = nullptr;
  if (delegate_) {
    new_buffer = delegate_->ReallocateBufferMemory(buffer_, requested_capacity,
                                                   &provided_capacity);
  } else {
    new_buffer = base::Realloc(buffer_, requested_capacity);
    provided_capacity = requested_capacity;
  }
  if (new_buffer) {
    DCHECK(provided_capacity >= requested_capacity);
    buffer_ = reinterpret_cast<uint8_t*>(new_buffer);
    buffer_capacity_ = provided_capacity;
    return Just(true);
  } else {
    out_of_memory_ = true;
    return Nothing<bool>();
  }
}

void ValueSerializer::WriteByte(uint8_t value) {
  uint8_t* dest;
  if (ReserveRawBytes(sizeof(uint8_t)).To(&dest)) {
    *dest = value;
  }
}

void ValueSerializer::WriteUint32(uint32_t value) {
  WriteVarint<uint32_t>(value);
}

void ValueSerializer::WriteUint64(uint64_t value) {
  WriteVarint<uint64_t>(value);
}

std::pair<uint8_t*, size_t> ValueSerializer::Release() {
  auto result = std::make_pair(buffer_, buffer_size_);
  buffer_ = nullptr;
  buffer_size_ = 0;
  buffer_capacity_ = 0;
  return result;
}

void ValueSerializer::TransferArrayBuffer(
    uint32_t transfer_id, DirectHandle<JSArrayBuffer> array_buffer) {
  DCHECK(!array_buffer_transfer_map_.Find(array_buffer));
  DCHECK(!array_buffer->is_shared());
  array_buffer_transfer_map_.Insert(array_buffer, transfer_id);
}

Maybe<bool> ValueSerializer::WriteObject(Handle<Object> object) {
  // There is no sense in trying to proceed if we've previously run out of
  // memory. Bail immediately, as this likely implies that some write has
  // previously failed and so the buffer is corrupt.
  if (V8_UNLIKELY(out_of_memory_)) return ThrowIfOutOfMemory();

  if (IsSmi(*object)) {
    WriteSmi(Cast<Smi>(*object));
    return ThrowIfOutOfMemory();
  }

  DCHECK(IsHeapObject(*object));
  InstanceType instance_type =
      Cast<HeapObject>(*object)->map(isolate_)->instance_type();
  switch (instance_type) {
    case ODDBALL_TYPE:
      WriteOddball(Cast<Oddball>(*object));
      return ThrowIfOutOfMemory();
    case HEAP_NUMBER_TYPE:
      WriteHeapNumber(Cast<HeapNumber>(*object));
      return ThrowIfOutOfMemory();
    case BIGINT_TYPE:
      WriteBigInt(Cast<BigInt>(*object));
      return ThrowIfOutOfMemory();
    case JS_TYPED_ARRAY_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE: {
      // Despite being JSReceivers, these have their wrapped buffer serialized
      // first. That makes this logic a little quirky, because it needs to
      // happen before we assign object IDs.
      // TODO(jbroman): It may be possible to avoid materializing a typed
      // array's buffer here.
      Handle<JSArrayBufferView> view = Cast<JSArrayBufferView>(object);
      if (!id_map_.Find(view) && !treat_array_buffer_views_as_host_objects_) {
        Handle<JSArrayBuffer> buffer(
            InstanceTypeChecker::IsJSTypedArray(instance_type)
                ? Cast<JSTypedArray>(view)->GetBuffer()
                : handle(Cast<JSArrayBuffer>(view->buffer()), isolate_));
        if (!WriteJSReceiver(buffer).FromMaybe(false)) return Nothing<bool>();
      }
      return WriteJSReceiver(view);
    }
    default:
      if (InstanceTypeChecker::IsString(instance_type)) {
        WriteString(Cast<String>(object));
        return ThrowIfOutOfMemory();
      } else if (InstanceTypeChecker::IsJSReceiver(instance_type)) {
        return WriteJSReceiver(Cast<JSReceiver>(object));
      } else {
        return ThrowDataCloneError(MessageTemplate::kDataCloneError, object);
      }
  }
}

void ValueSerializer::WriteOddball(Tagged<Oddball> oddball) {
  SerializationTag tag = SerializationTag::kUndefined;
  switch (oddball->kind()) {
    case Oddball::kUndefined:
      tag = SerializationTag::kUndefined;
      break;
    case Oddball::kFalse:
      tag = SerializationTag::kFalse;
      break;
    case Oddball::kTrue:
      tag = SerializationTag::kTrue;
      break;
    case Oddball::kNull:
      tag = SerializationTag::kNull;
      break;
    default:
      UNREACHABLE();
  }
  WriteTag(tag);
}

void ValueSerializer::WriteSmi(Tagged<Smi> smi) {
  static_assert(kSmiValueSize <= 32, "Expected SMI <= 32 bits.");
  WriteTag(SerializationTag::kInt32);
  WriteZigZag<int32_t>(smi.value());
}

void ValueSerializer::WriteHeapNumber(Tagged<HeapNumber> number) {
  WriteTag(SerializationTag::kDouble);
  WriteDouble(number->value());
}

void ValueSerializer::WriteBigInt(Tagged<BigInt> bigint) {
  WriteTag(SerializationTag::kBigInt);
  WriteBigIntContents(bigint);
}

void ValueSerializer::WriteString(Handle<String> string) {
  string = String::Flatten(isolate_, string);
  DisallowGarbageCollection no_gc;
  String::FlatContent flat = string->GetFlatContent(no_gc);
  DCHECK(flat.IsFlat());
  if (flat.IsOneByte()) {
    base::Vector<const uint8_t> chars = flat.ToOneByteVector();
    WriteTag(SerializationTag::kOneByteString);
    WriteOneByteString(chars);
  } else if (flat.IsTwoByte()) {
    base::Vector<const base::uc16> chars = flat.ToUC16Vector();
    uint32_t byte_length = chars.length() * sizeof(base::uc16);
    // The existing reading code expects 16-byte strings to be aligned.
    if ((buffer_size_ + 1 + BytesNeededForVarint(byte_length)) & 1)
      WriteTag(SerializationTag::kPadding);
    WriteTag(SerializationTag::kTwoByteString);
    WriteTwoByteString(chars);
  } else {
    UNREACHABLE();
  }
}

Maybe<bool> ValueSerializer::WriteJSReceiver(Handle<JSReceiver> receiver) {
  // If the object has already been serialized, just write its ID.
  auto find_result = id_map_.FindOrInsert(receiver);
  if (find_result.already_exists) {
    WriteTag(SerializationTag::kObjectReference);
    WriteVarint(*find_result.entry - 1);
    return ThrowIfOutOfMemory();
  }

  // Otherwise, allocate an ID for it.
  uint32_t id = next_id_++;
  *find_result.entry = id + 1;

  // Eliminate callable and exotic objects, which should not be serialized.
  InstanceType instance_type = receiver->map()->instance_type();
  if (IsCallable(*receiver) || (IsSpecialReceiverInstanceType(instance_type) &&
                                instance_type != JS_SPECIAL_API_OBJECT_TYPE)) {
    return ThrowDataCloneError(MessageTemplate::kDataCloneError, receiver);
  }

  // If we are at the end of the stack, abort. This function may recurse.
  STACK_CHECK(isolate_, Nothing<bool>());

  HandleScope scope(isolate_);
  switch (instance_type) {
    case JS_ARRAY_TYPE:
      return WriteJSArray(Cast<JSArray>(receiver));
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_OBJECT_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    case JS_API_OBJECT_TYPE: {
      Handle<JSObject> js_object = Cast<JSObject>(receiver);
      Maybe<bool> is_host_object = IsHostObject(js_object);
      if (is_host_object.IsNothing()) {
        return is_host_object;
      }
      if (is_host_object.FromJust()) {
        return WriteHostObject(js_object);
      } else {
        return WriteJSObject(js_object);
      }
    }
    case JS_SPECIAL_API_OBJECT_TYPE:
      return WriteHostObject(Cast<JSObject>(receiver));
    case JS_DATE_TYPE:
      WriteJSDate(Cast<JSDate>(*receiver));
      return ThrowIfOutOfMemory();
    case JS_PRIMITIVE_WRAPPER_TYPE:
      return WriteJSPrimitiveWrapper(Cast<JSPrimitiveWrapper>(receiver));
    case JS_REG_EXP_TYPE:
      WriteJSRegExp(Cast<JSRegExp>(receiver));
      return ThrowIfOutOfMemory();
    case JS_MAP_TYPE:
      return WriteJSMap(Cast<JSMap>(receiver));
    case JS_SET_TYPE:
      return WriteJSSet(Cast<JSSet>(receiver));
    case JS_ARRAY_BUFFER_TYPE:
      return WriteJSArrayBuffer(Cast<JSArrayBuffer>(receiver));
    case JS_TYPED_ARRAY_TYPE:
    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return WriteJSArrayBufferView(Cast<JSArrayBufferView>(*receiver));
    case JS_ERROR_TYPE:
      return WriteJSError(Cast<JSObject>(receiver));
    case JS_SHARED_ARRAY_TYPE:
      return WriteJSSharedArray(Cast<JSSharedArray>(receiver));
    case JS_SHARED_STRUCT_TYPE:
      return WriteJSSharedStruct(Cast<JSSharedStruct>(receiver));
    case JS_ATOMICS_MUTEX_TYPE:
    case JS_ATOMICS_CONDITION_TYPE:
      return WriteSharedObject(receiver);
#if V8_ENABLE_WEBASSEMBLY
    case WASM_MODULE_OBJECT_TYPE:
      return WriteWasmModule(Cast<WasmModuleObject>(receiver));
    case WASM_MEMORY_OBJECT_TYPE:
      return WriteWasmMemory(Cast<WasmMemoryObject>(receiver));
#endif  // V8_ENABLE_WEBASSEMBLY
    default:
      break;
  }

  return ThrowDataCloneError(MessageTemplate::kDataCloneError, receiver);
}

Maybe<bool> ValueSerializer::WriteJSObject(Handle<JSObject> object) {
  DCHECK(!IsCustomElementsReceiverMap(object->map()));
  const bool can_serialize_fast =
      object->HasFastProperties(isolate_) && object->elements()->length() == 0;
  if (!can_serialize_fast) return WriteJSObjectSlow(object);

  DirectHandle<Map> map(object->map(), isolate_);
  WriteTag(SerializationTag::kBeginJSObject);

  // Write out fast properties as long as they are only data properties and the
  // map doesn't change.
  uint32_t properties_written = 0;
  bool map_changed = false;
  for (InternalIndex i : map->IterateOwnDescriptors()) {
    Handle<Name> key(map->instance_descriptors(isolate_)->GetKey(i), isolate_);
    if (!IsString(*key, isolate_)) continue;
    PropertyDetails details =
        map->instance_descriptors(isolate_)->GetDetails(i);
    if (details.IsDontEnum()) continue;

    Handle<Object> value;
    if (V8_LIKELY(!map_changed)) map_changed = *map != object->map();
    if (V8_LIKELY(!map_changed &&
                  details.location() == PropertyLocation::kField)) {
      DCHECK_EQ(PropertyKind::kData, details.kind());
      FieldIndex field_index = FieldIndex::ForDetails(*map, details);
      value = handle(object->RawFastPropertyAt(field_index), isolate_);
    } else {
      // This logic should essentially match WriteJSObjectPropertiesSlow.
      // If the property is no longer found, do not serialize it.
      // This could happen if a getter deleted the property.
      LookupIterator it(isolate_, object, key, LookupIterator::OWN);
      if (!it.IsFound()) continue;
      if (!Object::GetProperty(&it).ToHandle(&value)) return Nothing<bool>();
    }

    if (!WriteObject(key).FromMaybe(false) ||
        !WriteObject(value).FromMaybe(false)) {
      return Nothing<bool>();
    }
    properties_written++;
  }

  WriteTag(SerializationTag::kEndJSObject);
  WriteVarint<uint32_t>(properties_written);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSObjectSlow(Handle<JSObject> object) {
  WriteTag(SerializationTag::kBeginJSObject);
  Handle<FixedArray> keys;
  uint32_t properties_written = 0;
  if (!KeyAccumulator::GetKeys(isolate_, object, KeyCollectionMode::kOwnOnly,
                               ENUMERABLE_STRINGS)
           .ToHandle(&keys) ||
      !WriteJSObjectPropertiesSlow(object, keys).To(&properties_written)) {
    return Nothing<bool>();
  }
  WriteTag(SerializationTag::kEndJSObject);
  WriteVarint<uint32_t>(properties_written);
  return ThrowIfOutOfMemory();
}

Maybe<bool> ValueSerializer::WriteJSArray(Handle<JSArray> array) {
  PtrComprCageBase cage_base(isolate_);
  uint32_t length = 0;
  bool valid_length = Object::ToArrayLength(array->length(), &length);
  DCHECK(valid_length);
  USE(valid_length);

  // To keep things simple, for now we decide between dense and sparse
  // serialization based on elements kind. A more principled heuristic could
  // count the elements, but would need to take care to note which indices
  // existed (as only indices which were enumerable own properties at this point
  // should be serialized).
  const bool should_serialize_densely =
      array->HasFastElements(cage_base) && !array->HasHoleyElements(cage_base);

  if (should_serialize_densely) {
    DCHECK_LE(length, static_cast<uint32_t>(FixedArray::kMaxLength));
    WriteTag(SerializationTag::kBeginDenseJSArray);
    WriteVarint<uint32_t>(length);
    uint32_t i = 0;

    // Fast paths. Note that PACKED_ELEMENTS in particular can bail due to the
    // structure of the elements changing.
    switch (array->GetElementsKind(cage_base)) {
      case PACKED_SMI_ELEMENTS: {
        DisallowGarbageCollection no_gc;
        Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
        for (i = 0; i < length; i++) {
          WriteSmi(Cast<Smi>(elements->get(i)));
        }
        break;
      }
      case PACKED_DOUBLE_ELEMENTS: {
        // Elements are empty_fixed_array, not a FixedDoubleArray, if the array
        // is empty. No elements to encode in this case anyhow.
        if (length == 0) break;
        DisallowGarbageCollection no_gc;
        Tagged<FixedDoubleArray> elements =
            Cast<FixedDoubleArray>(array->elements());
        for (i = 0; i < length; i++) {
          WriteTag(SerializationTag::kDouble);
          WriteDouble(elements->get_scalar(i));
        }
        break;
      }
      case PACKED_ELEMENTS: {
        DirectHandle<Object> old_length(array->length(cage_base), isolate_);
        for (; i < length; i++) {
          if (array->length(cage_base) != *old_length ||
              array->GetElementsKind(cage_base) != PACKED_ELEMENTS) {
            // Fall back to slow path.
            break;
          }
          Handle<Object> element(Cast<FixedArray>(array->elements())->get(i),
                                 isolate_);
          if (!WriteObject(element).FromMaybe(false)) return Nothing<bool>();
        }
        break;
      }
      default:
        break;
    }

    // If there are elements remaining, serialize them slowly.
    for (; i < length; i++) {
      // Serializing the array's elements can have arbitrary side effects, so we
      // cannot rely on still having fast elements, even if it did to begin
      // with.
      Handle<Object> element;
      LookupIterator it(isolate_, array, i, array, LookupIterator::OWN);
      if (!it.IsFound()) {
        // This can happen in the case where an array that was originally dense
        // became sparse during serialization. It's too late to switch to the
        // sparse format, but we can mark the elements as absent.
        WriteTag(SerializationTag::kTheHole);
        continue;
      }
      if (!Object::GetProperty(&it).ToHandle(&element) ||
          !WriteObject(element).FromMaybe(false)) {
        return Nothing<bool>();
      }
    }

    Handle<FixedArray> keys;
    if (!KeyAccumulator::GetKeys(isolate_, array, KeyCollectionMode::kOwnOnly,
                                 ENUMERABLE_STRINGS,
                                 GetKeysConversion::kKeepNumbers, false, true)
             .ToHandle(&keys)) {
      return Nothing<bool>();
    }

    uint32_t properties_written;
    if (!WriteJSObjectPropertiesSlow(array, keys).To(&properties_written)) {
      return Nothing<bool>();
    }
    WriteTag(SerializationTag::kEndDenseJSArray);
    WriteVarint<uint32_t>(properties_written);
    WriteVarint<uint32_t>(length);
  } else {
    WriteTag(SerializationTag::kBeginSparseJSArray);
    WriteVarint<uint32_t>(length);
    Handle<FixedArray> keys;
    uint32_t properties_written = 0;
    if (!KeyAccumulator::GetKeys(isolate_, array, KeyCollectionMode::kOwnOnly,
                                 ENUMERABLE_STRINGS)
             .ToHandle(&keys) ||
        !WriteJSObjectPropertiesSlow(array, keys).To(&properties_written)) {
      return Nothing<bool>();
    }
    WriteTag(SerializationTag::kEndSparseJSArray);
    WriteVarint<uint32_t>(properties_written);
    WriteVarint<uint32_t>(length);
  }
  return ThrowIfOutOfMemory();
}

void ValueSerializer::WriteJSDate(Tagged<JSDate> date) {
  WriteTag(SerializationTag::kDate);
  WriteDouble(date->value());
}

Maybe<bool> ValueSerializer::WriteJSPrimitiveWrapper(
    DirectHandle<JSPrimitiveWrapper> value) {
  PtrComprCageBase cage_base(isolate_);
  {
    DisallowGarbageCollection no_gc;
    Tagged<Object> inner_value = value->value();
    if (IsTrue(inner_value, isolate_)) {
      WriteTag(SerializationTag::kTrueObject);
    } else if (IsFalse(inner_value, isolate_)) {
      WriteTag(SerializationTag::kFalseObject);
    } else if (IsNumber(inner_value, cage_base)) {
      WriteTag(SerializationTag::kNumberObject);
      WriteDouble(Object::NumberValue(inner_value));
    } else if (IsBigInt(inner_value, cage_base)) {
      WriteTag(SerializationTag::kBigIntObject);
      WriteBigIntContents(Cast<BigInt>(inner_value));
    } else if (IsString(inner_value, cage_base)) {
      WriteTag(SerializationTag::kStringObject);
      WriteString(handle(Cast<String>(inner_value), isolate_));
    } else {
      AllowGarbageCollection allow_gc;
      DCHECK(IsSymbol(inner_value));
      return ThrowDataCloneError(MessageTemplate::kDataCloneError, value);
    }
  }
  return ThrowIfOutOfMemory();
}

void ValueSerializer::WriteJSRegExp(DirectHandle<JSRegExp> regexp) {
  WriteTag(SerializationTag::kRegExp);
  WriteString(handle(regexp->source(), isolate_));
  WriteVarint(static_cast<uint32_t>(regexp->flags()));
}

Maybe<bool> ValueSerializer::WriteJSMap(DirectHandle<JSMap> js_map) {
  // First copy the key-value pairs, since getters could mut
"""


```