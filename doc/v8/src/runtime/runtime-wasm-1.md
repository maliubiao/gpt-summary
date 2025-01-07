Response: The user wants to understand the functionality of the C++ code in `v8/src/runtime/runtime-wasm.cc`, specifically the second part of the file.

The goal is to:
1. **Summarize the functionality** of this code snippet.
2. **Identify its relation to JavaScript**.
3. **Provide JavaScript examples** to illustrate the connection.

Based on the function names and operations, this part of the code seems to handle **string manipulation** within the WebAssembly runtime in V8. It includes functionalities like:

- Creating new strings from different sources (memory, arrays, constants).
- Creating substrings.
- Measuring the length of strings in UTF-8.
- Encoding strings to UTF-8 and UTF-16.
- Converting strings to UTF-8 byte arrays.
- Hashing strings.
- Handling single Unicode code points.

The connection to JavaScript is through the **WebAssembly API**, where JavaScript can interact with WebAssembly modules and their memory. String operations in WebAssembly often involve transferring data between WebAssembly memory and JavaScript strings.
这是 `v8/src/runtime/runtime-wasm.cc` 文件的第二部分，主要负责 WebAssembly 中 **字符串 (string)** 相关的运行时功能。这些运行时函数（`RUNTIME_FUNCTION`）会被 V8 的 WebAssembly 引擎在执行 WebAssembly 代码时调用，用来处理 WebAssembly 模块内部的字符串操作以及与 JavaScript 字符串的交互。

**主要功能归纳：**

1. **创建 WebAssembly 字符串:**
   - 从 WebAssembly 内存中的 UTF-16 数据创建 JavaScript 字符串 (`Runtime_WasmStringNewUtf16`, `Runtime_WasmStringNewUtf16Array`).
   - 创建 WebAssembly 模块中定义的字符串常量 (`Runtime_WasmStringConst`).
   - 从 WebAssembly 数据段创建 UTF-8 字符串片段 (`Runtime_WasmStringNewSegmentWtf8`).
   - 从 Unicode 码点创建 JavaScript 字符串 (`Runtime_WasmStringFromCodePoint`).

2. **字符串操作:**
   - 创建子字符串 (`Runtime_WasmSubstring`).

3. **测量字符串长度:**
   - 测量 JavaScript 字符串以 UTF-8 编码后的长度 (`Runtime_WasmStringMeasureUtf8`, `Runtime_WasmStringMeasureWtf8`).

4. **编码字符串:**
   - 将 JavaScript 字符串编码为 UTF-8 并写入 WebAssembly 内存 (`Runtime_WasmStringEncodeWtf8`).
   - 将 JavaScript 字符串编码为 UTF-8 并写入 WebAssembly 数组 (`Runtime_WasmStringEncodeWtf8Array`).
   - 将 JavaScript 字符串编码为 UTF-16 并写入 WebAssembly 内存 (`Runtime_WasmStringEncodeWtf16`).
   - 将 JavaScript 字符串转换为 UTF-8 字节数组 (`Runtime_WasmStringToUtf8Array`, `Runtime_WasmStringAsWtf8`).
   - 将字节数组的片段解释为 UTF-8 字符串 (`Runtime_WasmStringViewWtf8Slice`).
   - 将字节数组的片段编码到 WebAssembly 内存中，可以进行有损的 UTF-8 转换 (`Runtime_WasmStringViewWtf8Encode`).

5. **获取字符串哈希值:**
   - 计算 JavaScript 字符串的哈希值 (`Runtime_WasmStringHash`).

6. **性能追踪 (在 `V8_ENABLE_DRUMBRAKE` 宏定义下):**
   - 用于标记 WebAssembly 代码执行的开始和结束，可能用于性能分析 (`Runtime_WasmTraceBeginExecution`, `Runtime_WasmTraceEndExecution`).

**与 JavaScript 的关系及示例:**

这些运行时函数是 WebAssembly 与 JavaScript 交互中处理字符串的关键。当 WebAssembly 代码需要创建、操作或与 JavaScript 传递字符串时，会调用这些函数。

**JavaScript 示例：**

假设我们有一个 WebAssembly 模块，其中定义了一个导出的函数 `getStringFromMemory` 和一个导出的内存对象 `memory`。

```javascript
// 加载 WebAssembly 模块
const wasmModule = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
const wasmInstance = wasmModule.instance;

// 获取导出的函数和内存
const getStringFromMemory = wasmInstance.exports.getStringFromMemory;
const memory = wasmInstance.exports.memory;

// 假设 WebAssembly 内存的偏移量 100 开始存储了一个 UTF-16 字符串 "Hello" (长度为 5)
const offset = 100;
const length = 5;

// WebAssembly 代码会调用 Runtime_WasmStringNewUtf16 来创建字符串
const jsString = getStringFromMemory(offset, length);
console.log(jsString); // 输出 "Hello"

// 假设 WebAssembly 有一个函数 encodeString，它接收一个 JavaScript 字符串并将其 UTF-8 编码写入内存
const encodeString = wasmInstance.exports.encodeString;
const jsStringToEncode = "你好";
const encodeOffset = 200;

// WebAssembly 代码会调用 Runtime_WasmStringEncodeWtf8 来完成编码
encodeString(jsStringToEncode, encodeOffset);

// 现在 WebAssembly 内存的偏移量 200 开始存储了 "你好" 的 UTF-8 编码

// 假设 WebAssembly 有一个函数 getStringLength，它测量一个 JavaScript 字符串的 UTF-8 长度
const getStringLength = wasmInstance.exports.getStringLength;
const lengthInUtf8 = getStringLength("你好"); // WebAssembly 代码会调用 Runtime_WasmStringMeasureUtf8
console.log(lengthInUtf8); // 输出 6 (因为 "你好" UTF-8 编码占 6 个字节)
```

**更具体的 JavaScript API 的关联：**

- **`WebAssembly.Memory`:**  `Runtime_WasmStringNewUtf16` 和 `Runtime_WasmStringEncodeWtf8` 等函数直接操作 `WebAssembly.Memory` 实例的底层 ArrayBuffer。
- **WebAssembly 导入/导出字符串相关的函数:** 当 WebAssembly 模块导出或导入需要处理字符串的函数时，V8 内部会使用这些运行时函数来桥接 WebAssembly 的字符串表示和 JavaScript 的字符串表示。

总而言之，这部分 `runtime-wasm.cc` 代码是 V8 WebAssembly 引擎处理字符串的核心，它使得 WebAssembly 代码能够高效地创建、操作字符串并与 JavaScript 环境中的字符串进行互操作。

Prompt: 
```
这是目录为v8/src/runtime/runtime-wasm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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