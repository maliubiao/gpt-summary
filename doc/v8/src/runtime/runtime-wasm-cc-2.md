Response:
Let's break down the thought process for analyzing this V8 source code snippet.

1. **Understanding the Context:** The first crucial step is to recognize the file path: `v8/src/runtime/runtime-wasm.cc`. This immediately tells us we're dealing with runtime functions specifically for WebAssembly within the V8 JavaScript engine. Runtime functions are the bridge between compiled (or in this case, interpreted) code and the V8 engine's internal functionalities. The `.cc` extension confirms it's C++ code.

2. **Scanning for Key Concepts:** Next, I'd quickly scan the code for recurring keywords and function names. Words like `String`, `Wasm`, `Utf8`, `Wtf8`, `Memory`, `Array`, `Trap`, `ThrowWasmError`, `Measure`, `Encode`, `NewString`, etc., stand out. This provides a high-level overview of the functionality. The repeated use of `ClearThreadInWasmScope` and `HandleScope` further reinforces that these are runtime functions operating within a specific context.

3. **Analyzing Individual Functions (Iterative Process):**  I would then go through each `RUNTIME_FUNCTION` definition one by one, trying to understand its purpose. Here's a potential breakdown of the thinking for a few representative functions:

    * **`Runtime_WasmStringNew`:**
        * **Input:** `WasmTrustedInstanceData`, memory index, offset, size.
        * **Action:** Reads raw bytes from WebAssembly memory and creates a JavaScript string.
        * **Checks:** Boundary checks on `offset` and `size`, alignment check.
        * **Key functions:** `trusted_instance_data->memory_base()`, `isolate->factory()->NewStringFromOneByte`.
        * **Inference:** Creates one-byte strings from WASM memory. Potential for out-of-bounds and unaligned access errors.

    * **`Runtime_WasmStringNewUtf16`:** Similar to the above, but handles two-byte (UTF-16) characters. The `& 1` check is a giveaway for alignment.

    * **`Runtime_WasmSubstring`:**
        * **Input:** JavaScript `String`, start index, length.
        * **Action:** Creates a substring.
        * **Key functions:** `String::Flatten`, `isolate->factory()->NewCopiedSubstring`.
        * **Inference:**  Standard string manipulation, likely related to JavaScript's `substring()` method.

    * **`Runtime_WasmStringConst`:**
        * **Input:** `WasmTrustedInstanceData`, index.
        * **Action:** Retrieves a pre-defined string literal from the WASM module.
        * **Key data structure:** `trusted_instance_data->module()->stringref_literals`.
        * **Inference:** Optimization for constant strings defined within the WASM module.

    * **`Runtime_WasmStringMeasureUtf8` and `Runtime_WasmStringMeasureWtf8`:**
        * **Input:** JavaScript `String`.
        * **Action:** Calculates the length of the string when encoded as UTF-8 or WTF-8.
        * **Key function:** `MeasureWtf8`.
        * **Inference:** Important for determining buffer sizes when converting strings to byte arrays. The `Utf8` version checks for isolated surrogates, while `Wtf8` does not (hence the 'T' for "Transformed").

    * **`Runtime_WasmStringEncodeWtf8` and `Runtime_WasmStringEncodeWtf8Array`:**
        * **Input:** JavaScript `String`, WASM memory or array, offset, encoding variant.
        * **Action:** Encodes a JavaScript string into a WASM memory region or array.
        * **Key function:** `EncodeWtf8`.
        * **Inference:**  Handles the conversion from JavaScript strings to byte representations in WASM, with options for different UTF-8 variants (WTF-8, strict UTF-8, lossy UTF-8).

4. **Identifying Common Patterns and Themes:**  As I analyze more functions, patterns emerge:

    * **Memory Access:** Many functions deal with reading from or writing to WebAssembly memory. This involves boundary checks to prevent security vulnerabilities.
    * **String Encodings:**  The code heavily involves different UTF-8 variants (UTF-8 and WTF-8) and UTF-16, highlighting the need to handle various character encodings when interoperating between JavaScript and WebAssembly.
    * **Error Handling:** The `ThrowWasmError` function is used consistently for reporting errors that occur during WebAssembly execution.
    * **JavaScript Interoperability:**  Functions often take JavaScript `String` objects as input or create them as output, showcasing the interaction between the two environments.

5. **Connecting to JavaScript:**  Once I understand the purpose of a function, I think about how it might be used from JavaScript. For example, the `Runtime_WasmSubstring` function is clearly related to the JavaScript `substring()` method. Functions dealing with UTF-8 encoding are relevant when JavaScript interacts with WASM memory buffers.

6. **Considering Edge Cases and Errors:** I look for checks that prevent common errors, like out-of-bounds memory access, unaligned access, and invalid UTF-8 sequences.

7. **Addressing Specific Instructions:**

    * **`.tq` extension:** The prompt mentions `.tq`. Since this file is `.cc`, the statement is false. Torque is a different language used for V8's built-in functions, often generating C++.
    * **JavaScript Relationship:**  The analysis of individual functions and the identification of patterns directly addresses this.
    * **Code Logic Inference:** This involves providing example inputs and outputs, which I've done for a few key functions in the thought process.
    * **Common Programming Errors:**  The boundary and alignment checks directly point to potential programming errors.

8. **Summarization (the final step):**  Based on the detailed analysis, I would then synthesize a concise summary that captures the main functionalities of the code, as demonstrated in the provided good answer. This involves grouping related functions and highlighting the core purpose of the file.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:**  Seeing a large chunk of code can be daunting. The key is to break it down into smaller, manageable parts (individual functions).
* **Unfamiliar APIs:** If I encounter unfamiliar V8 APIs (like `WasmTrustedInstanceData`), I would make a note to look them up or infer their purpose from the context. The naming is often descriptive.
* **Assumptions:** I might make initial assumptions about a function's purpose, but I'd refine them as I read the code more carefully and see how it interacts with other functions. For example, initially, I might think all string functions are about JavaScript strings, but then realize some are about manipulating byte arrays in WASM memory.

By following this iterative and analytical process, I can effectively understand the functionality of even a moderately complex piece of V8 source code.
好的，让我们来归纳一下这段 `v8/src/runtime/runtime-wasm.cc` 代码的功能。

**核心功能总结:**

这段代码定义了一系列 V8 运行时函数 (runtime functions)，专门用于支持 WebAssembly (Wasm) 中与字符串 (String) 和内存 (Memory) 操作相关的特性。它主要处理以下几个方面：

1. **创建 Wasm 字符串:**
   - 从 Wasm 模块的内存中读取字节序列，并将其转换为 JavaScript 的 `String` 对象。支持单字节 (Latin-1) 和双字节 (UTF-16) 编码。
   - 从 `WasmArray` 中创建字符串。
   - 创建 Wasm 字符串常量，这些常量在 Wasm 模块中预定义。
   - 从 Wasm 数据段中创建字符串片段。

2. **Wasm 字符串操作:**
   - 获取字符串的子串。
   - 测量 Wasm 字符串以 UTF-8 或 WTF-8 编码时的字节长度。
   - 将 JavaScript `String` 对象编码为 UTF-8 或 WTF-8 格式，并写入到 Wasm 模块的内存或 `WasmArray` 中。支持不同的 UTF-8 变体 (严格 UTF-8, WTF-8, 容错 UTF-8)。
   - 将 JavaScript `String` 对象编码为 UTF-16 格式，并写入到 Wasm 模块的内存中 (小端字节序)。
   - 将 JavaScript `String` 对象转换为 UTF-8 字节数组 (`ByteArray`)。
   - 从 `ByteArray` 中截取片段并创建 Wasm 字符串。

3. **与其他 Wasm 数据类型的交互:**
   - 从 `WasmArray` 创建字符串。
   - 将字符串编码到 `WasmArray` 中。

4. **其他辅助功能:**
   - 将 Unicode 码点转换为 JavaScript 字符串。
   - 计算 JavaScript 字符串的哈希值。
   - (在启用 `V8_ENABLE_DRUMBRAKE` 时) 提供用于追踪 Wasm 代码执行时间的函数。

**关于 .tq 结尾：**

正如代码注释中提到的，如果 `v8/src/runtime/runtime-wasm.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它可以生成 C++ 代码。然而，由于该文件以 `.cc` 结尾，所以它是一个直接编写的 C++ 源代码文件。

**与 JavaScript 的关系和示例:**

这段 C++ 代码的功能是为 WebAssembly 提供与 JavaScript 互操作的能力，特别是针对字符串的处理。在 JavaScript 中，当调用 Wasm 模块中导入或导出的涉及字符串的操作时，V8 引擎会调用这些运行时函数来完成实际的工作。

**示例：**

假设有一个 Wasm 模块导出了一个函数，该函数返回一个字符串。在 JavaScript 中调用该函数时：

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const wasmString = instance.exports.getStringFromWasm();
console.log(wasmString);
```

在 Wasm 模块的 `getStringFromWasm` 函数内部，可能会调用一个导入的函数，该函数最终会触发 `Runtime_WasmStringNew` 或 `Runtime_WasmStringConst` 等运行时函数，将 Wasm 内存中的字符串数据转换为 JavaScript 的 `String` 对象，然后返回给 JavaScript。

再例如，如果 Wasm 模块需要将 JavaScript 传递给它的字符串进行处理：

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
instance.exports.processString("Hello from JavaScript");
```

Wasm 模块的 `processString` 函数可能会调用一个导入的函数，该函数最终会触发 `Runtime_WasmStringEncodeWtf8` 等运行时函数，将 JavaScript 的 `String` 对象编码成 UTF-8 字节序列，并写入到 Wasm 模块的线性内存中，以便 Wasm 代码进行处理。

**代码逻辑推理（假设输入与输出）：**

**假设输入 `Runtime_WasmStringNew`:**

* `trusted_instance_data`: 指向当前 Wasm 实例数据的指针。
* `memory`:  Wasm 内存的索引，假设为 `0`。
* `offset`:  从 Wasm 内存开始读取的偏移量，假设为 `100`。
* `size_in_bytes`: 要读取的字节数，假设为 `10`。

**可能输出:**

如果从 Wasm 实例的第 0 个内存的偏移量 100 处读取的 10 个字节是 ASCII 字符 "abcdefghij"，那么该运行时函数将返回一个 JavaScript 的 `String` 对象，其值为 "abcdefghij"。

**假设输入 `Runtime_WasmStringEncodeWtf8`:**

* `trusted_instance_data`: 指向当前 Wasm 实例数据的指针。
* `memory`: Wasm 内存的索引，假设为 `0`。
* `utf8_variant_value`: UTF-8 编码变体的枚举值，假设为 `0` (表示 WTF-8)。
* `string`: 要编码的 JavaScript 字符串，假设为 "你好"。
* `offset_double`: 写入 Wasm 内存的偏移量，假设为 `200`。

**可能输出:**

该运行时函数会将字符串 "你好" 编码为 WTF-8 字节序列 (例如：`\xE4\xBD\xA0\xE5\xA5\xBD`)，并将这些字节写入到 Wasm 实例的第 0 个内存的偏移量 200 处。函数本身可能会返回写入的字节数（在这个例子中是 6）。

**用户常见的编程错误:**

1. **内存越界访问:**  在调用 `Runtime_WasmStringNew` 或 `Runtime_WasmStringEncodeWtf8` 等函数时，如果提供的 `offset` 和 `size` 超出了 Wasm 模块的内存边界，会导致运行时错误或崩溃。

   ```javascript
   // 假设 wasmMemory 是一个 ArrayBuffer，大小为 100 字节
   const wasmMemory = new Uint8Array(100);
   const offset = 95;
   const size = 10;
   // 尝试读取超出边界的数据
   // 这在 Wasm 模块内部调用运行时函数时可能会触发错误
   ```

2. **非对齐访问:**  对于 `Runtime_WasmStringNewUtf16` 和 `Runtime_WasmStringEncodeWtf16`，如果提供的 `offset` 是奇数，会导致非对齐访问错误，因为 UTF-16 字符通常需要 2 字节对齐。

   ```javascript
   // 尝试在奇数偏移量写入 UTF-16 数据
   const offset = 1;
   // ... 在 Wasm 模块内部调用 Runtime_WasmStringEncodeWtf16 时可能会触发错误
   ```

3. **UTF-8 编码错误:**  在使用 `Runtime_WasmStringEncodeWtf8` 时，如果选择了严格的 UTF-8 变体，并且 JavaScript 字符串包含无效的 UTF-8 序列 (例如，孤立的代理对)，则会抛出错误。

   ```javascript
   // 包含孤立代理对的字符串
   const str = String.fromCharCode(0xD800);
   // 如果使用严格 UTF-8 编码，这可能会导致错误
   ```

**总结:**

总而言之，`v8/src/runtime/runtime-wasm.cc` 的这部分代码是 V8 引擎中处理 WebAssembly 字符串和内存操作的关键组成部分。它定义了允许 Wasm 代码与 JavaScript 字符串进行高效交互的底层运行时函数，并包含了必要的错误检查和类型转换逻辑，以确保安全和正确的执行。它处理了从 Wasm 内存创建字符串、将 JavaScript 字符串编码到 Wasm 内存、以及进行各种字符串操作等核心任务。

Prompt: 
```
这是目录为v8/src/runtime/runtime-wasm.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/runtime/runtime-wasm.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
deunits * 2, mem_size)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapMemOutOfBounds);
  }
  if (offset & 1) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapUnalignedAccess);
  }

  const uint8_t* bytes = trusted_instance_data->memory_base(memory) + offset;
  const base::uc16* codeunits = reinterpret_cast<const base::uc16*>(bytes);
  RETURN_RESULT_OR_TRAP(isolate->factory()->NewStringFromTwoByteLittleEndian(
      {codeunits, size_in_codeunits}));
}

RUNTIME_FUNCTION(Runtime_WasmStringNewWtf16Array) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(3, args.length());
  HandleScope scope(isolate);
  DirectHandle<WasmArray> array(Cast<WasmArray>(args[0]), isolate);
  uint32_t start = NumberToUint32(args[1]);
  uint32_t end = NumberToUint32(args[2]);

  RETURN_RESULT_OR_TRAP(
      isolate->factory()->NewStringFromUtf16(array, start, end));
}

RUNTIME_FUNCTION(Runtime_WasmSubstring) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(3, args.length());
  HandleScope scope(isolate);
  Handle<String> string(Cast<String>(args[0]), isolate);
  int start = args.positive_smi_value_at(1);
  int length = args.positive_smi_value_at(2);

  string = String::Flatten(isolate, string);
  return *isolate->factory()->NewCopiedSubstring(string, start, length);
}

// Returns the new string if the operation succeeds.  Otherwise traps.
RUNTIME_FUNCTION(Runtime_WasmStringConst) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(2, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  static_assert(
      base::IsInRange(wasm::kV8MaxWasmStringLiterals, 0, Smi::kMaxValue));
  uint32_t index = args.positive_smi_value_at(1);

  DCHECK_LT(index, trusted_instance_data->module()->stringref_literals.size());

  const wasm::WasmStringRefLiteral& literal =
      trusted_instance_data->module()->stringref_literals[index];
  const base::Vector<const uint8_t> module_bytes =
      trusted_instance_data->native_module()->wire_bytes();
  const base::Vector<const uint8_t> string_bytes = module_bytes.SubVector(
      literal.source.offset(), literal.source.end_offset());
  // TODO(12868): No need to re-validate WTF-8.  Also, result should be cached.
  return *isolate->factory()
              ->NewStringFromUtf8(string_bytes, unibrow::Utf8Variant::kWtf8)
              .ToHandleChecked();
}

RUNTIME_FUNCTION(Runtime_WasmStringNewSegmentWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(5, args.length());
  HandleScope scope(isolate);
  DirectHandle<WasmTrustedInstanceData> trusted_instance_data(
      Cast<WasmTrustedInstanceData>(args[0]), isolate);
  uint32_t segment_index = args.positive_smi_value_at(1);
  uint32_t offset = args.positive_smi_value_at(2);
  uint32_t length = args.positive_smi_value_at(3);
  unibrow::Utf8Variant variant =
      static_cast<unibrow::Utf8Variant>(args.positive_smi_value_at(4));

  if (!base::IsInBounds<uint32_t>(
          offset, length,
          trusted_instance_data->data_segment_sizes()->get(segment_index))) {
    return ThrowWasmError(isolate,
                          MessageTemplate::kWasmTrapDataSegmentOutOfBounds);
  }

  Address source =
      trusted_instance_data->data_segment_starts()->get(segment_index) + offset;
  MaybeHandle<String> result = isolate->factory()->NewStringFromUtf8(
      {reinterpret_cast<const uint8_t*>(source), length}, variant);
  if (variant == unibrow::Utf8Variant::kUtf8NoTrap) {
    DCHECK(!isolate->has_exception());
    // Only instructions from the stringref proposal can set variant
    // kUtf8NoTrap, so WasmNull is appropriate here.
    if (result.is_null()) return *isolate->factory()->wasm_null();
    return *result.ToHandleChecked();
  }
  RETURN_RESULT_OR_FAILURE(isolate, result);
}

namespace {
// TODO(12868): Consider unifying with api.cc:String::Utf8Length.
template <typename T>
int MeasureWtf8(base::Vector<const T> wtf16) {
  int previous = unibrow::Utf16::kNoPreviousCharacter;
  int length = 0;
  DCHECK(wtf16.size() <= String::kMaxLength);
  static_assert(String::kMaxLength <=
                (kMaxInt / unibrow::Utf8::kMaxEncodedSize));
  for (size_t i = 0; i < wtf16.size(); i++) {
    int current = wtf16[i];
    length += unibrow::Utf8::Length(current, previous);
    previous = current;
  }
  return length;
}
int MeasureWtf8(Isolate* isolate, Handle<String> string) {
  string = String::Flatten(isolate, string);
  DisallowGarbageCollection no_gc;
  String::FlatContent content = string->GetFlatContent(no_gc);
  DCHECK(content.IsFlat());
  return content.IsOneByte() ? MeasureWtf8(content.ToOneByteVector())
                             : MeasureWtf8(content.ToUC16Vector());
}
size_t MaxEncodedSize(base::Vector<const uint8_t> wtf16) {
  DCHECK(wtf16.size() < std::numeric_limits<size_t>::max() /
                            unibrow::Utf8::kMax8BitCodeUnitSize);
  return wtf16.size() * unibrow::Utf8::kMax8BitCodeUnitSize;
}
size_t MaxEncodedSize(base::Vector<const base::uc16> wtf16) {
  DCHECK(wtf16.size() < std::numeric_limits<size_t>::max() /
                            unibrow::Utf8::kMax16BitCodeUnitSize);
  return wtf16.size() * unibrow::Utf8::kMax16BitCodeUnitSize;
}
bool HasUnpairedSurrogate(base::Vector<const uint8_t> wtf16) { return false; }
bool HasUnpairedSurrogate(base::Vector<const base::uc16> wtf16) {
  return unibrow::Utf16::HasUnpairedSurrogate(wtf16.begin(), wtf16.size());
}
// TODO(12868): Consider unifying with api.cc:String::WriteUtf8.
template <typename T>
int EncodeWtf8(base::Vector<char> bytes, size_t offset,
               base::Vector<const T> wtf16, unibrow::Utf8Variant variant,
               MessageTemplate* message, MessageTemplate out_of_bounds) {
  // The first check is a quick estimate to decide whether the second check
  // is worth the computation.
  if (!base::IsInBounds<size_t>(offset, MaxEncodedSize(wtf16), bytes.size()) &&
      !base::IsInBounds<size_t>(offset, MeasureWtf8(wtf16), bytes.size())) {
    *message = out_of_bounds;
    return -1;
  }

  bool replace_invalid = false;
  switch (variant) {
    case unibrow::Utf8Variant::kWtf8:
      break;
    case unibrow::Utf8Variant::kUtf8:
      if (HasUnpairedSurrogate(wtf16)) {
        *message = MessageTemplate::kWasmTrapStringIsolatedSurrogate;
        return -1;
      }
      break;
    case unibrow::Utf8Variant::kLossyUtf8:
      replace_invalid = true;
      break;
    default:
      UNREACHABLE();
  }

  char* dst_start = bytes.begin() + offset;
  char* dst = dst_start;
  int previous = unibrow::Utf16::kNoPreviousCharacter;
  for (auto code_unit : wtf16) {
    dst += unibrow::Utf8::Encode(dst, code_unit, previous, replace_invalid);
    previous = code_unit;
  }
  DCHECK_LE(dst - dst_start, static_cast<ptrdiff_t>(kMaxInt));
  return static_cast<int>(dst - dst_start);
}
template <typename GetWritableBytes>
Tagged<Object> EncodeWtf8(Isolate* isolate, unibrow::Utf8Variant variant,
                          Handle<String> string,
                          GetWritableBytes get_writable_bytes, size_t offset,
                          MessageTemplate out_of_bounds_message) {
  string = String::Flatten(isolate, string);
  MessageTemplate message;
  int written;
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent content = string->GetFlatContent(no_gc);
    base::Vector<char> dst = get_writable_bytes(no_gc);
    written = content.IsOneByte()
                  ? EncodeWtf8(dst, offset, content.ToOneByteVector(), variant,
                               &message, out_of_bounds_message)
                  : EncodeWtf8(dst, offset, content.ToUC16Vector(), variant,
                               &message, out_of_bounds_message);
  }
  if (written < 0) {
    DCHECK_NE(message, MessageTemplate::kNone);
    return ThrowWasmError(isolate, message);
  }
  return *isolate->factory()->NewNumberFromInt(written);
}
}  // namespace

// Used for storing the name of a string-constants imports module off the heap.
// Defined here to be able to make use of the helper functions above.
void ToUtf8Lossy(Isolate* isolate, Handle<String> string, std::string& out) {
  int utf8_length = MeasureWtf8(isolate, string);
  DisallowGarbageCollection no_gc;
  out.resize(utf8_length);
  String::FlatContent content = string->GetFlatContent(no_gc);
  DCHECK(content.IsFlat());
  static constexpr unibrow::Utf8Variant variant =
      unibrow::Utf8Variant::kLossyUtf8;
  MessageTemplate* error_cant_happen = nullptr;
  MessageTemplate oob_cant_happen = MessageTemplate::kInvalid;
  if (content.IsOneByte()) {
    EncodeWtf8({out.data(), out.size()}, 0, content.ToOneByteVector(), variant,
               error_cant_happen, oob_cant_happen);
  } else {
    EncodeWtf8({out.data(), out.size()}, 0, content.ToUC16Vector(), variant,
               error_cant_happen, oob_cant_happen);
  }
}

RUNTIME_FUNCTION(Runtime_WasmStringMeasureUtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);
  Handle<String> string(Cast<String>(args[0]), isolate);

  string = String::Flatten(isolate, string);
  int length;
  {
    DisallowGarbageCollection no_gc;
    String::FlatContent content = string->GetFlatContent(no_gc);
    DCHECK(content.IsFlat());
    if (content.IsOneByte()) {
      length = MeasureWtf8(content.ToOneByteVector());
    } else {
      base::Vector<const base::uc16> code_units = content.ToUC16Vector();
      if (unibrow::Utf16::HasUnpairedSurrogate(code_units.begin(),
                                               code_units.size())) {
        length = -1;
      } else {
        length = MeasureWtf8(code_units);
      }
    }
  }
  return *isolate->factory()->NewNumberFromInt(length);
}

RUNTIME_FUNCTION(Runtime_WasmStringMeasureWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);
  Handle<String> string(Cast<String>(args[0]), isolate);

  int length = MeasureWtf8(isolate, string);
  return *isolate->factory()->NewNumberFromInt(length);
}

RUNTIME_FUNCTION(Runtime_WasmStringEncodeWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(5, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  uint32_t utf8_variant_value = args.positive_smi_value_at(2);
  Handle<String> string(Cast<String>(args[3]), isolate);
  double offset_double = args.number_value_at(4);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));

  char* memory_start =
      reinterpret_cast<char*>(trusted_instance_data->memory_base(memory));
  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);
  auto get_writable_bytes =
      [&](const DisallowGarbageCollection&) -> base::Vector<char> {
    return {memory_start, trusted_instance_data->memory_size(memory)};
  };
  return EncodeWtf8(isolate, utf8_variant, string, get_writable_bytes, offset,
                    MessageTemplate::kWasmTrapMemOutOfBounds);
}

RUNTIME_FUNCTION(Runtime_WasmStringEncodeWtf8Array) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(4, args.length());
  HandleScope scope(isolate);
  uint32_t utf8_variant_value = args.positive_smi_value_at(0);
  Handle<String> string(Cast<String>(args[1]), isolate);
  Handle<WasmArray> array(Cast<WasmArray>(args[2]), isolate);
  uint32_t start = NumberToUint32(args[3]);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));
  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);
  auto get_writable_bytes =
      [&](const DisallowGarbageCollection&) -> base::Vector<char> {
    return {reinterpret_cast<char*>(array->ElementAddress(0)), array->length()};
  };
  return EncodeWtf8(isolate, utf8_variant, string, get_writable_bytes, start,
                    MessageTemplate::kWasmTrapArrayOutOfBounds);
}

RUNTIME_FUNCTION(Runtime_WasmStringToUtf8Array) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);
  Handle<String> string(Cast<String>(args[0]), isolate);
  uint32_t length = MeasureWtf8(isolate, string);
  wasm::WasmValue initial_value(int8_t{0});
  Tagged<WeakFixedArray> rtts = isolate->heap()->wasm_canonical_rtts();
  // This function can only get called from Wasm code, so we can safely assume
  // that the canonical RTT is still around.
  DirectHandle<Map> map(
      Cast<Map>(
          rtts->get(wasm::TypeCanonicalizer::kPredefinedArrayI8Index.index)
              .GetHeapObjectAssumeWeak()),
      isolate);
  Handle<WasmArray> array = isolate->factory()->NewWasmArray(
      wasm::kWasmI8, length, initial_value, map);
  auto get_writable_bytes =
      [&](const DisallowGarbageCollection&) -> base::Vector<char> {
    return {reinterpret_cast<char*>(array->ElementAddress(0)), length};
  };
  Tagged<Object> write_result =
      EncodeWtf8(isolate, unibrow::Utf8Variant::kLossyUtf8, string,
                 get_writable_bytes, 0, MessageTemplate::kNone);
  DCHECK(IsNumber(write_result) && Object::NumberValue(write_result) == length);
  USE(write_result);
  return *array;
}

RUNTIME_FUNCTION(Runtime_WasmStringEncodeWtf16) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(6, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t memory = args.positive_smi_value_at(1);
  Tagged<String> string = Cast<String>(args[2]);
  double offset_double = args.number_value_at(3);
  uintptr_t offset = static_cast<uintptr_t>(offset_double);
  uint32_t start = args.positive_smi_value_at(4);
  uint32_t length = args.positive_smi_value_at(5);

  DCHECK(base::IsInBounds<uint32_t>(start, length, string->length()));

  size_t mem_size = trusted_instance_data->memory_size(memory);
  static_assert(String::kMaxLength <=
                (std::numeric_limits<size_t>::max() / sizeof(base::uc16)));
  if (!base::IsInBounds<size_t>(offset, length * sizeof(base::uc16),
                                mem_size)) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapMemOutOfBounds);
  }
  if (offset & 1) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapUnalignedAccess);
  }

#if defined(V8_TARGET_LITTLE_ENDIAN)
  uint16_t* dst = reinterpret_cast<uint16_t*>(
      trusted_instance_data->memory_base(memory) + offset);
  String::WriteToFlat(string, dst, start, length);
#elif defined(V8_TARGET_BIG_ENDIAN)
  // TODO(12868): The host is big-endian but we need to write the string
  // contents as little-endian.
  USE(string);
  USE(start);
  UNIMPLEMENTED();
#else
#error Unknown endianness
#endif

  return Smi::zero();  // Unused.
}

RUNTIME_FUNCTION(Runtime_WasmStringAsWtf8) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);
  Handle<String> string(Cast<String>(args[0]), isolate);
  int wtf8_length = MeasureWtf8(isolate, string);
  Handle<ByteArray> array = isolate->factory()->NewByteArray(wtf8_length);

  auto utf8_variant = unibrow::Utf8Variant::kWtf8;
  auto get_writable_bytes =
      [&](const DisallowGarbageCollection&) -> base::Vector<char> {
    return {reinterpret_cast<char*>(array->begin()),
            static_cast<size_t>(wtf8_length)};
  };
  EncodeWtf8(isolate, utf8_variant, string, get_writable_bytes, 0,
             MessageTemplate::kWasmTrapArrayOutOfBounds);
  return *array;
}

RUNTIME_FUNCTION(Runtime_WasmStringViewWtf8Encode) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(7, args.length());
  HandleScope scope(isolate);
  Tagged<WasmTrustedInstanceData> trusted_instance_data =
      Cast<WasmTrustedInstanceData>(args[0]);
  uint32_t utf8_variant_value = args.positive_smi_value_at(1);
  DirectHandle<ByteArray> array(Cast<ByteArray>(args[2]), isolate);
  double addr_double = args.number_value_at(3);
  uintptr_t addr = static_cast<uintptr_t>(addr_double);
  uint32_t start = NumberToUint32(args[4]);
  uint32_t end = NumberToUint32(args[5]);
  uint32_t memory = args.positive_smi_value_at(6);

  DCHECK(utf8_variant_value <=
         static_cast<uint32_t>(unibrow::Utf8Variant::kLastUtf8Variant));
  DCHECK_LE(start, end);
  DCHECK(base::IsInBounds<size_t>(start, end - start, array->length()));

  auto utf8_variant = static_cast<unibrow::Utf8Variant>(utf8_variant_value);
  size_t length = end - start;

  if (!base::IsInBounds<size_t>(addr, length,
                                trusted_instance_data->memory_size(memory))) {
    return ThrowWasmError(isolate, MessageTemplate::kWasmTrapMemOutOfBounds);
  }

  uint8_t* memory_start = trusted_instance_data->memory_base(memory);
  const uint8_t* src = reinterpret_cast<const uint8_t*>(array->begin() + start);
  uint8_t* dst = memory_start + addr;

  std::vector<size_t> surrogates;
  if (utf8_variant != unibrow::Utf8Variant::kWtf8) {
    unibrow::Wtf8::ScanForSurrogates({src, length}, &surrogates);
    if (utf8_variant == unibrow::Utf8Variant::kUtf8 && !surrogates.empty()) {
      return ThrowWasmError(isolate,
                            MessageTemplate::kWasmTrapStringIsolatedSurrogate);
    }
  }

  MemCopy(dst, src, length);

  for (size_t surrogate : surrogates) {
    DCHECK_LT(surrogate, length);
    DCHECK_EQ(utf8_variant, unibrow::Utf8Variant::kLossyUtf8);
    unibrow::Utf8::Encode(reinterpret_cast<char*>(dst + surrogate),
                          unibrow::Utf8::kBadChar, 0, false);
  }

  // Unused.
  return Tagged<Smi>(0);
}

RUNTIME_FUNCTION(Runtime_WasmStringViewWtf8Slice) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(3, args.length());
  HandleScope scope(isolate);
  DirectHandle<ByteArray> array(Cast<ByteArray>(args[0]), isolate);
  uint32_t start = NumberToUint32(args[1]);
  uint32_t end = NumberToUint32(args[2]);

  DCHECK_LT(start, end);
  DCHECK(base::IsInBounds<size_t>(start, end - start, array->length()));

  // This can't throw because the result can't be too long if the input wasn't,
  // and encoding failures are ruled out too because {start}/{end} are aligned.
  return *isolate->factory()
              ->NewStringFromUtf8(array, start, end,
                                  unibrow::Utf8Variant::kWtf8)
              .ToHandleChecked();
}

#ifdef V8_ENABLE_DRUMBRAKE
RUNTIME_FUNCTION(Runtime_WasmTraceBeginExecution) {
  DCHECK(v8_flags.slow_histograms && !v8_flags.wasm_jitless &&
         v8_flags.wasm_enable_exec_time_histograms);
  DCHECK_EQ(0, args.length());
  HandleScope scope(isolate);

  wasm::WasmExecutionTimer* timer = isolate->wasm_execution_timer();
  timer->Start();

  return ReadOnlyRoots(isolate).undefined_value();
}

RUNTIME_FUNCTION(Runtime_WasmTraceEndExecution) {
  DCHECK(v8_flags.slow_histograms && !v8_flags.wasm_jitless &&
         v8_flags.wasm_enable_exec_time_histograms);
  DCHECK_EQ(0, args.length());
  HandleScope scope(isolate);

  wasm::WasmExecutionTimer* timer = isolate->wasm_execution_timer();
  timer->Stop();

  return ReadOnlyRoots(isolate).undefined_value();
}
#endif  // V8_ENABLE_DRUMBRAKE

RUNTIME_FUNCTION(Runtime_WasmStringFromCodePoint) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  HandleScope scope(isolate);

  uint32_t code_point = NumberToUint32(args[0]);
  if (code_point <= unibrow::Utf16::kMaxNonSurrogateCharCode) {
    return *isolate->factory()->LookupSingleCharacterStringFromCode(code_point);
  }
  if (code_point > 0x10FFFF) {
    // Allocate a new number to preserve the to-uint conversion (e.g. if
    // args[0] == -1, we want the error message to report 4294967295).
    return ThrowWasmError(isolate, MessageTemplate::kInvalidCodePoint,
                          {isolate->factory()->NewNumberFromUint(code_point)});
  }

  base::uc16 char_buffer[] = {
      unibrow::Utf16::LeadSurrogate(code_point),
      unibrow::Utf16::TrailSurrogate(code_point),
  };
  DirectHandle<SeqTwoByteString> result =
      isolate->factory()
          ->NewRawTwoByteString(arraysize(char_buffer))
          .ToHandleChecked();
  DisallowGarbageCollection no_gc;
  CopyChars(result->GetChars(no_gc), char_buffer, arraysize(char_buffer));
  return *result;
}

RUNTIME_FUNCTION(Runtime_WasmStringHash) {
  ClearThreadInWasmScope flag_scope(isolate);
  DCHECK_EQ(1, args.length());
  Tagged<String> string(Cast<String>(args[0]));
  uint32_t hash = string->EnsureHash();
  return Smi::FromInt(static_cast<int>(hash));
}

}  // namespace v8::internal

"""


```