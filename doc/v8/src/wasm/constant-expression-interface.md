Response: Let's break down the thought process for analyzing this C++ code and relating it to JavaScript.

1. **Understand the Goal:** The request asks for the functionality of the C++ code and how it relates to JavaScript. This immediately suggests focusing on what the code *does* rather than low-level implementation details. The connection to JavaScript means we need to identify concepts and operations that are mirrored or have equivalents in JavaScript.

2. **Initial Scan and Keywords:**  A quick read reveals keywords and patterns related to WebAssembly: `wasm`, `FullDecoder`, `Value`, `WasmValue`, `WasmOpcode`, `module`, `GlobalGet`, `StructNew`, `ArrayNew`, `RefNull`, `RefFunc`, etc. This strongly indicates the code is involved in processing WebAssembly instructions. The presence of "ConstantExpressionInterface" in the class name is a crucial clue.

3. **Identify the Core Purpose:** The class name "ConstantExpressionInterface" suggests this code is responsible for handling *constant expressions* within WebAssembly. Constant expressions are a specific subset of WebAssembly instructions that can be evaluated at compile time (or instantiation time) rather than during runtime. This is a key distinction.

4. **Analyze Individual Methods:** Go through the methods one by one and determine their function:
    * **`I32Const`, `I64Const`, `F32Const`, `F64Const`, `S128Const`:** These clearly deal with creating constant values of different WebAssembly numeric types (integers, floats, SIMD vectors). The `WasmValue` being assigned in each case confirms this.
    * **`UnOp`:** This handles unary operations. The cases `kExprExternConvertAny` and `kExprAnyConvertExtern` are significant. They involve converting between WebAssembly references and JavaScript objects (`WasmToJSObject`, `JSToWasmObject`). This is a direct link to JavaScript interaction.
    * **`BinOp`:** Deals with binary operations (addition, subtraction, multiplication) on integer types. The `base::AddWithWraparound`, `base::SubWithWraparound`, `base::MulWithWraparound` indicate operations that handle potential overflows by wrapping around.
    * **`RefNull`:**  Creates a null reference of a specific type. The distinction between `wasm_null` and `null_value` likely relates to different kinds of nulls within WebAssembly's type system.
    * **`RefFunc`:** Creates a reference to a WebAssembly function. This is essential for calling WebAssembly functions from other WebAssembly code or from JavaScript.
    * **`GlobalGet`:** Retrieves the value of a constant global variable. The code differentiates between numeric and reference types, handling their storage differently.
    * **`StructNew`:**  Creates a new instance of a WebAssembly struct. It takes the field values as input.
    * **`StringConst`:** Creates a WebAssembly string literal. It fetches the string data from the module's bytecode.
    * **`StructNewDefault`:** Creates a new struct with default values for its fields.
    * **`ArrayNew`:** Creates a new WebAssembly array with a given length and initial value.
    * **`ArrayNewDefault`:** Creates a new array with default initial values.
    * **`ArrayNewFixed`:** Creates an array with specific initial elements.
    * **`ArrayNewSegment`:** Creates an array by copying data from a data or element segment within the WebAssembly module. This is more complex and might not always be constant. The code comments hint at future potential for this to become constant.
    * **`RefI31`:** Creates a reference to a 31-bit integer. This is a special WebAssembly type.
    * **`DoReturn`:**  Indicates the end of a constant expression.

5. **Identify the JavaScript Connection:** The key JavaScript link is in the `UnOp` method, specifically the `kExprExternConvertAny` and `kExprAnyConvertExtern` cases. These methods explicitly handle the conversion between WebAssembly and JavaScript values. This is where the boundaries of the two systems meet.

6. **Construct the Explanation:**  Now, organize the findings into a coherent explanation:
    * **Summarize the core function:** Start by stating that the file deals with evaluating constant expressions in WebAssembly.
    * **Explain the role:**  Clarify that it's used during compilation/instantiation, not runtime.
    * **Categorize the operations:** Group the methods by the type of constant expression they handle (constants, unary ops, binary ops, references, structs, arrays, etc.). This provides structure.
    * **Highlight the JavaScript connection:** Focus on the `UnOp` method and the conversion between WebAssembly references and JavaScript objects. Explain *why* this is important (interoperability).
    * **Provide JavaScript examples:** Create clear and simple JavaScript code snippets that demonstrate the WebAssembly concepts handled by the C++ code (creating instances, accessing globals, calling functions). This makes the connection concrete.

7. **Refine and Review:** Read through the explanation and examples. Ensure the language is clear and accurate. Check for any jargon that might need further explanation. Make sure the JavaScript examples are correct and illustrate the intended points. For example, initially, one might forget to mention the need for `WebAssembly.instantiate` and focus solely on the object creation. Reviewing helps catch such omissions. Also, consider if the explanation balances technical accuracy with clarity for someone who may not be deeply familiar with V8 internals.

This detailed thought process, starting with a high-level understanding and then drilling down into the specifics of each function, is crucial for accurately summarizing complex code and connecting it to related concepts in other languages like JavaScript.
这个C++源代码文件 `constant-expression-interface.cc`  定义了一个接口，用于在 V8 JavaScript 引擎的 WebAssembly (Wasm) 模块编译过程中处理 **常量表达式**。

**核心功能归纳:**

该接口 (`ConstantExpressionInterface`) 提供了一系列方法，用于解析和计算 WebAssembly 常量表达式的值。常量表达式是 WebAssembly 规范的一部分，它允许在模块的某些地方（例如全局变量的初始化器、元素的偏移量等）使用在编译时就能确定值的表达式。

具体来说，这个接口定义了如何处理以下类型的常量表达式：

* **常量值:**
    * `I32Const`:  32位整数常量
    * `I64Const`:  64位整数常量
    * `F32Const`:  32位浮点数常量
    * `F64Const`:  64位浮点数常量
    * `S128Const`: 128位 SIMD 常量
    * `StringConst`: 字符串常量

* **一元操作:**
    * `UnOp`:  处理一元操作，目前主要处理 WebAssembly 引用类型和 JavaScript 对象之间的转换：
        * `kExprExternConvertAny`: 将 WebAssembly 引用转换为 JavaScript 对象。
        * `kExprAnyConvertExtern`: 将 JavaScript 对象转换为 WebAssembly 外部引用。

* **二元操作:**
    * `BinOp`: 处理二元操作，目前只支持整数的加减乘：
        * `kExprI32Add`, `kExprI32Sub`, `kExprI32Mul`: 32位整数的加减乘。
        * `kExprI64Add`, `kExprI64Sub`, `kExprI64Mul`: 64位整数的加减乘。

* **引用相关:**
    * `RefNull`: 创建一个空引用。
    * `RefFunc`: 创建一个对 WebAssembly 函数的引用。
    * `RefI31`: 创建一个 i31 类型的引用。

* **全局变量:**
    * `GlobalGet`: 获取常量全局变量的值。

* **结构体 (Struct) 相关:**
    * `StructNew`: 创建一个新的结构体实例。
    * `StructNewDefault`: 创建一个新的结构体实例，字段使用默认值。

* **数组 (Array) 相关:**
    * `ArrayNew`: 创建一个新的数组实例。
    * `ArrayNewDefault`: 创建一个新的数组实例，元素使用默认值。
    * `ArrayNewFixed`: 创建一个新的数组实例，并使用给定的元素进行初始化。
    * `ArrayNewSegment`:  从数据段或元素段创建数组（目前被认为是**非常量**，但保留了基础设施，未来可能支持常量）。

* **控制流:**
    * `DoReturn`:  表示常量表达式的结束。

**与 JavaScript 的关系 (通过 `UnOp` 方法体现):**

这个文件通过 `UnOp` 方法中的 `kExprExternConvertAny` 和 `kExprAnyConvertExtern` 操作，直接关联到 JavaScript 的功能。WebAssembly 允许与 JavaScript 进行互操作，这意味着 WebAssembly 模块可以调用 JavaScript 函数，JavaScript 也可以调用 WebAssembly 函数。

* **`kExprExternConvertAny` (WebAssembly to JavaScript):**  当 WebAssembly 代码中有一个常量表达式需要将 WebAssembly 的引用类型（例如 `externref`）转换为 JavaScript 对象时，就会调用这个方法。

* **`kExprAnyConvertExtern` (JavaScript to WebAssembly):**  当 WebAssembly 代码中有一个常量表达式需要将 JavaScript 对象转换为 WebAssembly 的外部引用类型 (`externref`) 时，就会调用这个方法。

**JavaScript 示例:**

假设我们有一个 WebAssembly 模块，它定义了一个常量全局变量，其初始值是一个对 JavaScript 对象的引用。为了初始化这个全局变量，WebAssembly 编译器需要能够将 JavaScript 对象转换为 WebAssembly 的引用。

**WebAssembly 代码 (示意):**

```wasm
(module
  (global (export "myGlobal") (mut i32) (i32.const 0)) ; 先声明一个可变的 i32 全局变量
  (global (export "jsObjectRef") (ref extern) (global.get 0)) ; 尝试用一个 i32 来初始化一个 ref extern，这在实际场景中需要通过 JS 注入
)
```

**对应的 JavaScript 代码:**

```javascript
const wasmCode = // ... 编译后的 WebAssembly 字节码
const wasmModule = new WebAssembly.Module(wasmCode);
const jsObject = { value: 42 };

// 导入 JavaScript 对象
const importObject = {
  env: {
    // 假设 WebAssembly 代码中会通过某种方式访问或转换这个 jsObject
  },
  //  这里可能需要更复杂的导入来建立关联，上面的 wasm 示例简化了概念
};

const wasmInstance = new WebAssembly.Instance(wasmModule, importObject);

//  在 V8 引擎的编译过程中，当遇到需要将 JavaScript 对象转换为 wasm 的 externref 时，
//  `ConstantExpressionInterface::UnOp` 中的 `kExprAnyConvertExtern` 方法会被调用。

// 类似地，如果 wasm 中有一个常量表达式需要将 externref 转换回 JS 对象，
// `ConstantExpressionInterface::UnOp` 中的 `kExprExternConvertAny` 方法会被调用。

//  以下是一个假设的场景，展示了从 wasm 获取一个对 JS 对象的引用：
//  (假设 wasm 模块中存在这样的逻辑)
// const jsRefFromWasm = wasmInstance.exports.jsObjectRef;
// console.log(jsRefFromWasm.value); // 访问来自 wasm 的 JS 对象

```

**更具体的 JavaScript 示例 (假设 WebAssembly 模块需要一个 JavaScript 对象作为常量):**

虽然 WebAssembly 本身不能直接定义 JavaScript 对象作为常量，但可以通过导入的方式实现类似的效果。  考虑一个更贴近实际的场景，WebAssembly 模块期望在初始化时接收一个来自 JavaScript 的常量引用。

**WebAssembly 代码 (示意):**

```wasm
(module
  (import "env" "getJSObject" (global $js_object_global (ref extern)))
  (global (export "myConstantObject") (ref extern) (global.get $js_object_global))
)
```

**JavaScript 代码:**

```javascript
const wasmCode = // ... 编译后的 WebAssembly 字节码
const wasmModule = new WebAssembly.Module(wasmCode);
const jsObject = { data: "hello from js" };

const importObject = {
  env: {
    getJSObject: jsObject // 将 JavaScript 对象作为导入的全局变量
  }
};

const wasmInstance = new WebAssembly.Instance(wasmModule, importObject);

const constantObjectFromWasm = wasmInstance.exports.myConstantObject;
console.log(constantObjectFromWasm.data); // 输出 "hello from js"

// 在 V8 编译这个 WebAssembly 模块时，当处理 `(global (export "myConstantObject") (ref extern) (global.get $js_object_global))` 时，
// 因为 `$js_object_global` 是一个导入的全局变量，其初始值来自 JavaScript，
// V8 引擎内部会涉及到将 JavaScript 对象转换为 WebAssembly 的 `externref` 的过程，
// 这与 `ConstantExpressionInterface` 中处理常量表达式的逻辑有关。
```

**总结:**

`constant-expression-interface.cc` 文件是 V8 引擎中处理 WebAssembly 常量表达式的关键部分，它负责在编译时计算这些表达式的值。它通过特定的方法处理不同类型的常量、操作以及与 JavaScript 的互操作。  与 JavaScript 的主要联系在于处理 WebAssembly 引用类型和 JavaScript 对象之间的转换，这对于实现 WebAssembly 和 JavaScript 的无缝集成至关重要。

### 提示词
```
这是目录为v8/src/wasm/constant-expression-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/constant-expression-interface.h"

#include "src/base/overflowing-math.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/oddball.h"
#include "src/wasm/decoder.h"
#include "src/wasm/wasm-objects.h"

namespace v8 {
namespace internal {
namespace wasm {

void ConstantExpressionInterface::I32Const(FullDecoder* decoder, Value* result,
                                           int32_t value) {
  if (generate_value()) result->runtime_value = WasmValue(value);
}

void ConstantExpressionInterface::I64Const(FullDecoder* decoder, Value* result,
                                           int64_t value) {
  if (generate_value()) result->runtime_value = WasmValue(value);
}

void ConstantExpressionInterface::F32Const(FullDecoder* decoder, Value* result,
                                           float value) {
  if (generate_value()) result->runtime_value = WasmValue(value);
}

void ConstantExpressionInterface::F64Const(FullDecoder* decoder, Value* result,
                                           double value) {
  if (generate_value()) result->runtime_value = WasmValue(value);
}

void ConstantExpressionInterface::S128Const(FullDecoder* decoder,
                                            const Simd128Immediate& imm,
                                            Value* result) {
  if (!generate_value()) return;
  result->runtime_value = WasmValue(imm.value, kWasmS128);
}

void ConstantExpressionInterface::UnOp(FullDecoder* decoder, WasmOpcode opcode,
                                       const Value& input, Value* result) {
  if (!generate_value()) return;
  switch (opcode) {
    case kExprExternConvertAny: {
      result->runtime_value = WasmValue(
          WasmToJSObject(isolate_, input.runtime_value.to_ref()),
          ValueType::RefMaybeNull(HeapType::kExtern, input.type.nullability()),
          decoder->module_);
      break;
    }
    case kExprAnyConvertExtern: {
      const char* error_message = nullptr;
      result->runtime_value = WasmValue(
          JSToWasmObject(isolate_, input.runtime_value.to_ref(),
                         kCanonicalAnyRef, &error_message)
              .ToHandleChecked(),
          ValueType::RefMaybeNull(HeapType::kAny, input.type.nullability()),
          decoder->module_);
      break;
    }
    default:
      UNREACHABLE();
  }
}

void ConstantExpressionInterface::BinOp(FullDecoder* decoder, WasmOpcode opcode,
                                        const Value& lhs, const Value& rhs,
                                        Value* result) {
  if (!generate_value()) return;
  switch (opcode) {
    case kExprI32Add:
      result->runtime_value = WasmValue(base::AddWithWraparound(
          lhs.runtime_value.to_i32(), rhs.runtime_value.to_i32()));
      break;
    case kExprI32Sub:
      result->runtime_value = WasmValue(base::SubWithWraparound(
          lhs.runtime_value.to_i32(), rhs.runtime_value.to_i32()));
      break;
    case kExprI32Mul:
      result->runtime_value = WasmValue(base::MulWithWraparound(
          lhs.runtime_value.to_i32(), rhs.runtime_value.to_i32()));
      break;
    case kExprI64Add:
      result->runtime_value = WasmValue(base::AddWithWraparound(
          lhs.runtime_value.to_i64(), rhs.runtime_value.to_i64()));
      break;
    case kExprI64Sub:
      result->runtime_value = WasmValue(base::SubWithWraparound(
          lhs.runtime_value.to_i64(), rhs.runtime_value.to_i64()));
      break;
    case kExprI64Mul:
      result->runtime_value = WasmValue(base::MulWithWraparound(
          lhs.runtime_value.to_i64(), rhs.runtime_value.to_i64()));
      break;
    default:
      UNREACHABLE();
  }
}

void ConstantExpressionInterface::RefNull(FullDecoder* decoder, ValueType type,
                                          Value* result) {
  if (!generate_value()) return;
  result->runtime_value = WasmValue(
      type.use_wasm_null() ? Cast<Object>(isolate_->factory()->wasm_null())
                           : Cast<Object>(isolate_->factory()->null_value()),
      type, decoder->module_);
}

void ConstantExpressionInterface::RefFunc(FullDecoder* decoder,
                                          uint32_t function_index,
                                          Value* result) {
  if (isolate_ == nullptr) {
    outer_module_->functions[function_index].declared = true;
    return;
  }
  if (!generate_value()) return;
  ModuleTypeIndex sig_index = module_->functions[function_index].sig_index;
  bool function_is_shared = module_->type(sig_index).is_shared;
  ValueType type = ValueType::Ref(module_->functions[function_index].sig_index);
  Handle<WasmFuncRef> func_ref = WasmTrustedInstanceData::GetOrCreateFuncRef(
      isolate_,
      function_is_shared ? shared_trusted_instance_data_
                         : trusted_instance_data_,
      function_index);
  result->runtime_value = WasmValue(func_ref, type, decoder->module_);
}

void ConstantExpressionInterface::GlobalGet(FullDecoder* decoder, Value* result,
                                            const GlobalIndexImmediate& imm) {
  if (!generate_value()) return;
  const WasmGlobal& global = module_->globals[imm.index];
  DCHECK(!global.mutability);
  DirectHandle<WasmTrustedInstanceData> data =
      global.shared ? shared_trusted_instance_data_ : trusted_instance_data_;
  result->runtime_value =
      global.type.is_numeric()
          ? WasmValue(reinterpret_cast<uint8_t*>(
                          data->untagged_globals_buffer()->backing_store()) +
                          global.offset,
                      global.type)
          : WasmValue(handle(data->tagged_globals_buffer()->get(global.offset),
                             isolate_),
                      global.type, decoder->module_);
}

void ConstantExpressionInterface::StructNew(FullDecoder* decoder,
                                            const StructIndexImmediate& imm,
                                            const Value args[], Value* result) {
  if (!generate_value()) return;
  DirectHandle<WasmTrustedInstanceData> data =
      GetTrustedInstanceDataForTypeIndex(imm.index);
  DirectHandle<Map> rtt{
      Cast<Map>(data->managed_object_maps()->get(imm.index.index)), isolate_};
  WasmValue* field_values =
      decoder->zone_->AllocateArray<WasmValue>(imm.struct_type->field_count());
  for (size_t i = 0; i < imm.struct_type->field_count(); i++) {
    field_values[i] = args[i].runtime_value;
  }
  result->runtime_value = WasmValue(
      isolate_->factory()->NewWasmStruct(imm.struct_type, field_values, rtt),
      ValueType::Ref(HeapType(imm.index)), decoder->module_);
}

void ConstantExpressionInterface::StringConst(FullDecoder* decoder,
                                              const StringConstImmediate& imm,
                                              Value* result) {
  if (!generate_value()) return;
  static_assert(base::IsInRange(kV8MaxWasmStringLiterals, 0, Smi::kMaxValue));

  DCHECK_LT(imm.index, module_->stringref_literals.size());

  const wasm::WasmStringRefLiteral& literal =
      module_->stringref_literals[imm.index];
  const base::Vector<const uint8_t> module_bytes =
      trusted_instance_data_->native_module()->wire_bytes();
  const base::Vector<const uint8_t> string_bytes = module_bytes.SubVector(
      literal.source.offset(), literal.source.end_offset());
  Handle<String> string =
      isolate_->factory()
          ->NewStringFromUtf8(string_bytes, unibrow::Utf8Variant::kWtf8)
          .ToHandleChecked();
  result->runtime_value =
      WasmValue(string, kWasmStringRef.AsNonNull(), decoder->module_);
}

namespace {
WasmValue DefaultValueForType(ValueType type, Isolate* isolate,
                              const WasmModule* module) {
  switch (type.kind()) {
    case kI32:
    case kI8:
    case kI16:
      return WasmValue(0);
    case kI64:
      return WasmValue(int64_t{0});
    case kF16:
    case kF32:
      return WasmValue(0.0f);
    case kF64:
      return WasmValue(0.0);
    case kS128:
      return WasmValue(Simd128());
    case kRefNull:
      return WasmValue(type.use_wasm_null()
                           ? Cast<Object>(isolate->factory()->wasm_null())
                           : Cast<Object>(isolate->factory()->null_value()),
                       type, module);
    case kVoid:
    case kRtt:
    case kRef:
    case kTop:
    case kBottom:
      UNREACHABLE();
  }
}
}  // namespace

void ConstantExpressionInterface::StructNewDefault(
    FullDecoder* decoder, const StructIndexImmediate& imm, Value* result) {
  if (!generate_value()) return;
  DirectHandle<WasmTrustedInstanceData> data =
      GetTrustedInstanceDataForTypeIndex(imm.index);
  DirectHandle<Map> rtt{
      Cast<Map>(data->managed_object_maps()->get(imm.index.index)), isolate_};
  WasmValue* field_values =
      decoder->zone_->AllocateArray<WasmValue>(imm.struct_type->field_count());
  for (uint32_t i = 0; i < imm.struct_type->field_count(); i++) {
    field_values[i] = DefaultValueForType(imm.struct_type->field(i), isolate_,
                                          decoder->module_);
  }
  result->runtime_value = WasmValue(
      isolate_->factory()->NewWasmStruct(imm.struct_type, field_values, rtt),
      ValueType::Ref(imm.index), decoder->module_);
}

void ConstantExpressionInterface::ArrayNew(FullDecoder* decoder,
                                           const ArrayIndexImmediate& imm,
                                           const Value& length,
                                           const Value& initial_value,
                                           Value* result) {
  if (!generate_value()) return;
  DirectHandle<WasmTrustedInstanceData> data =
      GetTrustedInstanceDataForTypeIndex(imm.index);
  DirectHandle<Map> rtt{
      Cast<Map>(data->managed_object_maps()->get(imm.index.index)), isolate_};
  if (length.runtime_value.to_u32() >
      static_cast<uint32_t>(WasmArray::MaxLength(imm.array_type))) {
    error_ = MessageTemplate::kWasmTrapArrayTooLarge;
    return;
  }
  result->runtime_value = WasmValue(
      isolate_->factory()->NewWasmArray(imm.array_type->element_type(),
                                        length.runtime_value.to_u32(),
                                        initial_value.runtime_value, rtt),
      ValueType::Ref(imm.index), decoder->module_);
}

void ConstantExpressionInterface::ArrayNewDefault(
    FullDecoder* decoder, const ArrayIndexImmediate& imm, const Value& length,
    Value* result) {
  if (!generate_value()) return;
  Value initial_value(decoder->pc(), imm.array_type->element_type());
  initial_value.runtime_value = DefaultValueForType(
      imm.array_type->element_type(), isolate_, decoder->module_);
  return ArrayNew(decoder, imm, length, initial_value, result);
}

void ConstantExpressionInterface::ArrayNewFixed(
    FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
    const IndexImmediate& length_imm, const Value elements[], Value* result) {
  if (!generate_value()) return;
  DirectHandle<WasmTrustedInstanceData> data =
      GetTrustedInstanceDataForTypeIndex(array_imm.index);
  DirectHandle<Map> rtt{
      Cast<Map>(data->managed_object_maps()->get(array_imm.index.index)),
      isolate_};
  base::Vector<WasmValue> element_values =
      decoder->zone_->AllocateVector<WasmValue>(length_imm.index);
  for (size_t i = 0; i < length_imm.index; i++) {
    element_values[i] = elements[i].runtime_value;
  }
  result->runtime_value =
      WasmValue(isolate_->factory()->NewWasmArrayFromElements(
                    array_imm.array_type, element_values, rtt),
                ValueType::Ref(HeapType(array_imm.index)), decoder->module_);
}

// TODO(14034): These expressions are non-constant for now. There are plans to
// make them constant in the future, so we retain the required infrastructure
// here.
void ConstantExpressionInterface::ArrayNewSegment(
    FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
    const IndexImmediate& segment_imm, const Value& offset_value,
    const Value& length_value, Value* result) {
  if (!generate_value()) return;

  DirectHandle<WasmTrustedInstanceData> data =
      GetTrustedInstanceDataForTypeIndex(array_imm.index);

  DirectHandle<Map> rtt{
      Cast<Map>(data->managed_object_maps()->get(array_imm.index.index)),
      isolate_};

  uint32_t length = length_value.runtime_value.to_u32();
  uint32_t offset = offset_value.runtime_value.to_u32();
  if (length >
      static_cast<uint32_t>(WasmArray::MaxLength(array_imm.array_type))) {
    error_ = MessageTemplate::kWasmTrapArrayTooLarge;
    return;
  }
  ValueType element_type = array_imm.array_type->element_type();
  ValueType result_type = ValueType::Ref(HeapType(array_imm.index));
  if (element_type.is_numeric()) {
    const WasmDataSegment& data_segment =
        module_->data_segments[segment_imm.index];
    uint32_t length_in_bytes =
        length * array_imm.array_type->element_type().value_kind_size();

    if (!base::IsInBounds<uint32_t>(offset, length_in_bytes,
                                    data_segment.source.length())) {
      error_ = MessageTemplate::kWasmTrapDataSegmentOutOfBounds;
      return;
    }

    Address source =
        data->data_segment_starts()->get(segment_imm.index) + offset;
    Handle<WasmArray> array_value =
        isolate_->factory()->NewWasmArrayFromMemory(length, rtt, source);
    result->runtime_value =
        WasmValue(array_value, result_type, decoder->module_);
  } else {
    const wasm::WasmElemSegment* elem_segment =
        &decoder->module_->elem_segments[segment_imm.index];
    // A constant expression should not observe if a passive segment is dropped.
    // However, it should consider active and declarative segments as empty.
    if (!base::IsInBounds<size_t>(
            offset, length,
            elem_segment->status == WasmElemSegment::kStatusPassive
                ? elem_segment->element_count
                : 0)) {
      error_ = MessageTemplate::kWasmTrapElementSegmentOutOfBounds;
      return;
    }

    Handle<Object> array_object =
        isolate_->factory()->NewWasmArrayFromElementSegment(
            trusted_instance_data_, shared_trusted_instance_data_,
            segment_imm.index, offset, length, rtt);
    if (IsSmi(*array_object)) {
      // A smi result stands for an error code.
      error_ = static_cast<MessageTemplate>(Cast<Smi>(*array_object).value());
    } else {
      result->runtime_value =
          WasmValue(array_object, result_type, decoder->module_);
    }
  }
}

void ConstantExpressionInterface::RefI31(FullDecoder* decoder,
                                         const Value& input, Value* result) {
  if (!generate_value()) return;
  Address raw = input.runtime_value.to_i32();
  // We have to craft the Smi manually because we accept out-of-bounds inputs.
  // For 32-bit Smi builds, set the topmost bit to sign-extend the second bit.
  // This way, interpretation in JS (if this value escapes there) will be the
  // same as i31.get_s.
  static_assert((SmiValuesAre31Bits() ^ SmiValuesAre32Bits()) == 1);
  intptr_t shifted;
  if constexpr (SmiValuesAre31Bits()) {
    shifted = raw << (kSmiTagSize + kSmiShiftSize);
  } else {
    shifted =
        static_cast<intptr_t>(raw << (kSmiTagSize + kSmiShiftSize + 1)) >> 1;
  }
  result->runtime_value =
      WasmValue(handle(Tagged<Smi>(shifted), isolate_),
                wasm::kWasmI31Ref.AsNonNull(), decoder->module_);
}

void ConstantExpressionInterface::DoReturn(FullDecoder* decoder,
                                           uint32_t /*drop_values*/) {
  end_found_ = true;
  // End decoding on "end". Note: We need this because we do not know the length
  // of a constant expression while decoding it.
  decoder->set_end(decoder->pc() + 1);
  if (generate_value()) {
    computed_value_ = decoder->stack_value(1)->runtime_value;
  }
}

Handle<WasmTrustedInstanceData>
ConstantExpressionInterface::GetTrustedInstanceDataForTypeIndex(
    ModuleTypeIndex index) {
  bool type_is_shared = module_->type(index).is_shared;
  return type_is_shared ? shared_trusted_instance_data_
                        : trusted_instance_data_;
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```