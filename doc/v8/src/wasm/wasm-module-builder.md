Response: The user wants a summary of the C++ source code file `v8/src/wasm/wasm-module-builder.cc`.
This file seems to be related to building WebAssembly modules programmatically within the V8 JavaScript engine.

Here's a plan:
1. **Identify the main class:**  `WasmModuleBuilder` seems central.
2. **Summarize the purpose of `WasmModuleBuilder`:** It's likely responsible for constructing the binary representation of a WebAssembly module.
3. **Identify key helper classes:** `WasmFunctionBuilder` appears important for building individual functions.
4. **List the main functionalities:**  Adding functions, globals, tables, memories, imports, exports, etc.
5. **Explain how it relates to JavaScript:** This builder is used internally by V8 when compiling or creating WebAssembly modules, including those loaded from JavaScript. Provide a JavaScript example of loading and potentially creating a Wasm module.

Let's break down the functionalities by examining the methods of `WasmModuleBuilder` and `WasmFunctionBuilder`.
这个C++源代码文件 `v8/src/wasm/wasm-module-builder.cc` 的主要功能是提供一个**构建 WebAssembly 模块**的工具。它允许在 C++ 代码中程序化地创建 WebAssembly 模块的各个部分，例如类型定义、导入、函数、表、内存、全局变量、导出和数据段等。

**核心功能归纳：**

1. **模块构建核心类 `WasmModuleBuilder`:**
   - 负责管理整个 WebAssembly 模块的结构和数据。
   - 提供了添加各种模块组成部分的方法，例如：
     - `AddFunction`: 添加函数。
     - `AddSignature`: 添加函数签名（类型）。
     - `AddTag`: 添加异常标签。
     - `AddStructType`, `AddArrayType`: 添加结构体和数组类型。
     - `AddTable`: 添加表。
     - `AddMemory`: 添加内存。
     - `AddGlobal`: 添加全局变量。
     - `AddImport`: 添加导入（函数或全局变量）。
     - `AddExport`: 添加导出。
     - `AddDataSegment`: 添加数据段。
     - `AddElementSegment`: 添加元素段。
     - `MarkStartFunction`: 设置启动函数。
   - 提供了将构建好的模块写入二进制格式的方法 `WriteTo`。

2. **函数构建辅助类 `WasmFunctionBuilder`:**
   - 用于构建单个 WebAssembly 函数的内部结构和代码。
   - 提供了设置函数签名、添加局部变量和发射 WebAssembly 指令的方法，例如：
     - `SetSignature`: 设置函数签名。
     - `AddLocal`: 添加局部变量。
     - `EmitByte`, `EmitI32V`, `EmitU32V`, `EmitU64V`: 发射原始字节或 LEB128 编码的值。
     - `Emit`, `EmitWithPrefix`, `EmitWithU8`, `EmitWithI32V`, `EmitWithU32V`: 发射 WebAssembly 操作码及其操作数。
     - `EmitGetLocal`, `EmitSetLocal`, `EmitTeeLocal`:  发射局部变量访问指令。
     - `EmitI32Const`, `EmitI64Const`, `EmitF32Const`, `EmitF64Const`: 发射常量指令。
     - `EmitDirectCallIndex`: 发射直接函数调用指令。
     - `EmitFromInitializerExpression`: 发射初始化表达式。
     - `SetName`: 设置函数名称（用于调试信息）。
   - 提供了获取函数体二进制数据的方法 `WriteBody`。

3. **初始化表达式处理:**
   - 代码中包含对 `WasmInitExpr` 的处理，用于初始化全局变量、表和内存等。
   - 函数 `WriteInitializerExpression` 将 `WasmInitExpr` 转换为 WebAssembly 的初始化表达式字节码。

4. **辅助函数:**
   - `EmitSection` 和 `FixupSection` 用于处理 WebAssembly 模块中各个段的结构，包括写入段的头部（段代码和长度）。
   - `FromInitExprOperator` 将 `WasmInitExpr` 的操作符转换为对应的 WebAssembly 操作码。

**与 JavaScript 的关系（以及 JavaScript 示例）：**

`v8/src/wasm/wasm-module-builder.cc` 是 V8 引擎内部用来创建 WebAssembly 模块的工具。虽然开发者不能直接在 JavaScript 中使用这个 C++ 类，但 V8 引擎在以下场景会使用它：

- **编译 WebAssembly 代码:** 当 JavaScript 代码加载 `.wasm` 文件或使用 `WebAssembly.compile` 或 `WebAssembly.instantiate` 方法时，V8 会解析 WebAssembly 的二进制格式。如果需要进一步操作或生成模块，可能会用到 `WasmModuleBuilder`。
- **创建 WebAssembly 模块 (JS API):**  虽然没有直接的 JavaScript API 对应于 `WasmModuleBuilder` 的所有功能，但一些 JavaScript API 可以间接地触发 V8 内部使用它。 例如，未来可能会有更底层的 API 允许开发者更精细地构建 Wasm 模块。
- **测试和工具:** V8 的测试套件和内部工具可能会使用 `WasmModuleBuilder` 来生成特定的 WebAssembly 模块用于测试编译、优化和执行等功能。

**JavaScript 示例 (间接关联):**

```javascript
// 1. 加载现有的 WebAssembly 模块
fetch('my_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    // 可以调用导出的函数
    results.instance.exports.exported_function();
  });

// 2. 创建 WebAssembly 模块 (Text format - V8 内部会将其转换为二进制)
const wasmSource = `
  (module
    (func $add (param $p1 i32) (param $p2 i32) (result i32)
      local.get $p1
      local.get $p2
      i32.add
    )
    (export "add" (func $add))
  )
`;

// 注意：直接从文本格式创建模块在浏览器中通常需要通过编译步骤
// 这里只是演示概念，实际使用需要编译 API
WebAssembly.compileStreaming(new Response(wasmSource, { headers: { 'content-type': 'application/wasm' } }))
  .then(module => WebAssembly.instantiate(module))
  .then(instance => {
    console.log(instance.exports.add(5, 3)); // 输出 8
  });

// 3. 未来可能的更底层的创建 API (这是一个假设的例子，目前 JS API 不支持这样精细的控制)
// 假设未来有类似这样的 API 可以让开发者更底层地构建 Wasm 模块
/*
const moduleBuilder = new WebAssembly.ModuleBuilder();
const sig = moduleBuilder.addSignature({ params: ['i32', 'i32'], returns: ['i32'] });
const func = moduleBuilder.addFunction(sig);
func.emitGetLocal(0);
func.emitGetLocal(1);
func.emit(WebAssembly.Opcodes.i32_add);
func.emitEnd();
moduleBuilder.addExport("add", func);
const wasmModule = moduleBuilder.toModule();
const instance = await WebAssembly.instantiate(wasmModule);
console.log(instance.exports.add(10, 2));
*/
```

在上述 JavaScript 示例中，虽然我们没有直接操作 `WasmModuleBuilder`，但 V8 引擎在处理 `WebAssembly.instantiate` 或 `WebAssembly.compileStreaming` 时，会将 WebAssembly 的二进制表示（或者文本格式，然后编译成二进制）加载到其内部的数据结构中。如果需要程序化地生成 WebAssembly 模块（例如，在某些高级工具或代码生成场景中），V8 内部就会使用像 `WasmModuleBuilder` 这样的类来构建模块的二进制表示。

总而言之，`v8/src/wasm/wasm-module-builder.cc` 是 V8 引擎中一个关键的内部组件，负责在 C++ 层面构建 WebAssembly 模块，为 JavaScript 中加载和使用 WebAssembly 提供了基础。

### 提示词
```
这是目录为v8/src/wasm/wasm-module-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/wasm-module-builder.h"

#include "src/codegen/signature.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/leb-helper.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-module.h"
#include "src/zone/zone-containers.h"

namespace v8 {
namespace internal {
namespace wasm {

namespace {

// Emit a section code and the size as a padded varint that can be patched
// later.
size_t EmitSection(SectionCode code, ZoneBuffer* buffer) {
  // Emit the section code.
  buffer->write_u8(code);

  // Emit a placeholder for the length.
  return buffer->reserve_u32v();
}

// Patch the size of a section after it's finished.
void FixupSection(ZoneBuffer* buffer, size_t start) {
  buffer->patch_u32v(start, static_cast<uint32_t>(buffer->offset() - start -
                                                  kPaddedVarInt32Size));
}

WasmOpcode FromInitExprOperator(WasmInitExpr::Operator op) {
  switch (op) {
    case WasmInitExpr::kGlobalGet:
      return kExprGlobalGet;
    case WasmInitExpr::kI32Const:
      return kExprI32Const;
    case WasmInitExpr::kI64Const:
      return kExprI64Const;
    case WasmInitExpr::kF32Const:
      return kExprF32Const;
    case WasmInitExpr::kF64Const:
      return kExprF64Const;
    case WasmInitExpr::kS128Const:
      return kExprS128Const;
    case WasmInitExpr::kI32Add:
      return kExprI32Add;
    case WasmInitExpr::kI32Sub:
      return kExprI32Sub;
    case WasmInitExpr::kI32Mul:
      return kExprI32Mul;
    case WasmInitExpr::kI64Add:
      return kExprI64Add;
    case WasmInitExpr::kI64Sub:
      return kExprI64Sub;
    case WasmInitExpr::kI64Mul:
      return kExprI64Mul;
    case WasmInitExpr::kRefNullConst:
      return kExprRefNull;
    case WasmInitExpr::kRefFuncConst:
      return kExprRefFunc;
    case WasmInitExpr::kStructNew:
      return kExprStructNew;
    case WasmInitExpr::kStructNewDefault:
      return kExprStructNewDefault;
    case WasmInitExpr::kArrayNew:
      return kExprArrayNew;
    case WasmInitExpr::kArrayNewDefault:
      return kExprArrayNewDefault;
    case WasmInitExpr::kArrayNewFixed:
      return kExprArrayNewFixed;
    case WasmInitExpr::kRefI31:
      return kExprRefI31;
    case WasmInitExpr::kStringConst:
      return kExprStringConst;
    case WasmInitExpr::kAnyConvertExtern:
      return kExprAnyConvertExtern;
    case WasmInitExpr::kExternConvertAny:
      return kExprExternConvertAny;
  }
}

void WriteInitializerExpressionWithoutEnd(ZoneBuffer* buffer,
                                          const WasmInitExpr& init) {
  switch (init.kind()) {
    case WasmInitExpr::kI32Const:
      buffer->write_u8(kExprI32Const);
      buffer->write_i32v(init.immediate().i32_const);
      break;
    case WasmInitExpr::kI64Const:
      buffer->write_u8(kExprI64Const);
      buffer->write_i64v(init.immediate().i64_const);
      break;
    case WasmInitExpr::kF32Const:
      buffer->write_u8(kExprF32Const);
      buffer->write_f32(init.immediate().f32_const);
      break;
    case WasmInitExpr::kF64Const:
      buffer->write_u8(kExprF64Const);
      buffer->write_f64(init.immediate().f64_const);
      break;
    case WasmInitExpr::kS128Const:
      buffer->write_u8(kSimdPrefix);
      buffer->write_u8(kExprS128Const & 0xFF);
      buffer->write(init.immediate().s128_const.data(), kSimd128Size);
      break;
    case WasmInitExpr::kI32Add:
    case WasmInitExpr::kI32Sub:
    case WasmInitExpr::kI32Mul:
    case WasmInitExpr::kI64Add:
    case WasmInitExpr::kI64Sub:
    case WasmInitExpr::kI64Mul:
      WriteInitializerExpressionWithoutEnd(buffer, (*init.operands())[0]);
      WriteInitializerExpressionWithoutEnd(buffer, (*init.operands())[1]);
      buffer->write_u8(FromInitExprOperator(init.kind()));
      break;
    case WasmInitExpr::kGlobalGet:
      buffer->write_u8(kExprGlobalGet);
      buffer->write_u32v(init.immediate().index);
      break;
    case WasmInitExpr::kRefNullConst:
      buffer->write_u8(kExprRefNull);
      buffer->write_i32v(HeapType(init.immediate().heap_type).code());
      break;
    case WasmInitExpr::kRefFuncConst:
      buffer->write_u8(kExprRefFunc);
      buffer->write_u32v(init.immediate().index);
      break;
    case WasmInitExpr::kStructNew:
    case WasmInitExpr::kStructNewDefault:
    case WasmInitExpr::kArrayNew:
    case WasmInitExpr::kArrayNewDefault: {
      if (init.operands() != nullptr) {
        for (const WasmInitExpr& operand : *init.operands()) {
          WriteInitializerExpressionWithoutEnd(buffer, operand);
        }
      }
      WasmOpcode opcode = FromInitExprOperator(init.kind());
      DCHECK_EQ(opcode >> 8, kGCPrefix);
      DCHECK_EQ(opcode & 0x80, 0);
      buffer->write_u8(kGCPrefix);
      buffer->write_u8(static_cast<uint8_t>(opcode));
      buffer->write_u32v(init.immediate().index);
      break;
    }
    case WasmInitExpr::kArrayNewFixed: {
      static_assert((kExprArrayNewFixed >> 8) == kGCPrefix);
      static_assert((kExprArrayNewFixed & 0x80) == 0);
      for (const WasmInitExpr& operand : *init.operands()) {
        WriteInitializerExpressionWithoutEnd(buffer, operand);
      }
      buffer->write_u8(kGCPrefix);
      buffer->write_u8(static_cast<uint8_t>(kExprArrayNewFixed));
      buffer->write_u32v(init.immediate().index);
      buffer->write_u32v(static_cast<uint32_t>(init.operands()->size()));
      break;
    }
    case WasmInitExpr::kRefI31:
    case WasmInitExpr::kAnyConvertExtern:
    case WasmInitExpr::kExternConvertAny: {
      WriteInitializerExpressionWithoutEnd(buffer, (*init.operands())[0]);
      WasmOpcode opcode = FromInitExprOperator(init.kind());
      DCHECK_EQ(opcode >> 8, kGCPrefix);
      DCHECK_EQ(opcode & 0x80, 0);
      buffer->write_u8(kGCPrefix);
      buffer->write_u8(opcode);
      break;
    }
    case WasmInitExpr::kStringConst:
      buffer->write_u8(kGCPrefix);
      buffer->write_u32v(kExprStringConst & 0xFF);
      buffer->write_u32v(init.immediate().index);
      break;
  }
}

void WriteInitializerExpression(ZoneBuffer* buffer, const WasmInitExpr& init) {
  WriteInitializerExpressionWithoutEnd(buffer, init);
  buffer->write_u8(kExprEnd);
}
}  // namespace

WasmFunctionBuilder::WasmFunctionBuilder(WasmModuleBuilder* builder)
    : builder_(builder),
      locals_(builder->zone()),
      signature_index_{0},
      func_index_(static_cast<uint32_t>(builder->functions_.size())),
      body_(builder->zone(), 256),
      i32_temps_(builder->zone()),
      i64_temps_(builder->zone()),
      f32_temps_(builder->zone()),
      f64_temps_(builder->zone()),
      direct_calls_(builder->zone()),
      asm_offsets_(builder->zone(), 8) {}

void WasmFunctionBuilder::EmitByte(uint8_t val) { body_.write_u8(val); }

void WasmFunctionBuilder::EmitI32V(int32_t val) { body_.write_i32v(val); }

void WasmFunctionBuilder::EmitU32V(uint32_t val) { body_.write_u32v(val); }

void WasmFunctionBuilder::EmitU64V(uint64_t val) { body_.write_u64v(val); }

void WasmFunctionBuilder::SetSignature(const FunctionSig* sig) {
  DCHECK(!locals_.has_sig());
  locals_.set_sig(sig);
  signature_index_ = builder_->AddSignature(sig, true);
}

void WasmFunctionBuilder::SetSignature(ModuleTypeIndex sig_index) {
  DCHECK(!locals_.has_sig());
  DCHECK_EQ(builder_->types_[sig_index.index].kind, TypeDefinition::kFunction);
  signature_index_ = sig_index;
  locals_.set_sig(builder_->types_[sig_index.index].function_sig);
}

uint32_t WasmFunctionBuilder::AddLocal(ValueType type) {
  DCHECK(locals_.has_sig());
  return locals_.AddLocals(1, type);
}

void WasmFunctionBuilder::EmitGetLocal(uint32_t local_index) {
  EmitWithU32V(kExprLocalGet, local_index);
}

void WasmFunctionBuilder::EmitSetLocal(uint32_t local_index) {
  EmitWithU32V(kExprLocalSet, local_index);
}

void WasmFunctionBuilder::EmitTeeLocal(uint32_t local_index) {
  EmitWithU32V(kExprLocalTee, local_index);
}

void WasmFunctionBuilder::EmitCode(const uint8_t* code, uint32_t code_size) {
  body_.write(code, code_size);
}

void WasmFunctionBuilder::EmitCode(std::initializer_list<const uint8_t> code) {
  body_.write(code.begin(), code.size());
}

void WasmFunctionBuilder::Emit(WasmOpcode opcode) {
  DCHECK_LE(opcode, 0xFF);
  body_.write_u8(opcode);
}

void WasmFunctionBuilder::EmitWithPrefix(WasmOpcode opcode) {
  DCHECK_GT(opcode, 0xFF);
  if (opcode > 0xFFFF) {
    DCHECK_EQ(kSimdPrefix, opcode >> 12);
    body_.write_u8(kSimdPrefix);
    body_.write_u32v(opcode & 0xFFF);
  } else {
    body_.write_u8(opcode >> 8);      // Prefix.
    body_.write_u32v(opcode & 0xff);  // LEB encoded tail.
  }
}

void WasmFunctionBuilder::EmitWithU8(WasmOpcode opcode,
                                     const uint8_t immediate) {
  body_.write_u8(opcode);
  body_.write_u8(immediate);
}

void WasmFunctionBuilder::EmitWithU8U8(WasmOpcode opcode, const uint8_t imm1,
                                       const uint8_t imm2) {
  body_.write_u8(opcode);
  body_.write_u8(imm1);
  body_.write_u8(imm2);
}

void WasmFunctionBuilder::EmitWithI32V(WasmOpcode opcode, int32_t immediate) {
  body_.write_u8(opcode);
  body_.write_i32v(immediate);
}

void WasmFunctionBuilder::EmitWithU32V(WasmOpcode opcode, uint32_t immediate) {
  body_.write_u8(opcode);
  body_.write_u32v(immediate);
}

namespace {
void WriteValueType(ZoneBuffer* buffer, const ValueType& type) {
  buffer->write_u8(type.value_type_code());
  if (type.encoding_needs_shared()) {
    buffer->write_u8(kSharedFlagCode);
  }
  if (type.encoding_needs_heap_type()) {
    buffer->write_i32v(type.heap_type().code());
  }
  if (type.is_rtt()) {
    buffer->write_u32v(type.ref_index());
  }
}
}  // namespace

void WasmFunctionBuilder::EmitValueType(ValueType type) {
  WriteValueType(&body_, type);
}

void WasmFunctionBuilder::EmitI32Const(int32_t value) {
  EmitWithI32V(kExprI32Const, value);
}

void WasmFunctionBuilder::EmitI64Const(int64_t value) {
  body_.write_u8(kExprI64Const);
  body_.write_i64v(value);
}

void WasmFunctionBuilder::EmitF32Const(float value) {
  body_.write_u8(kExprF32Const);
  body_.write_f32(value);
}

void WasmFunctionBuilder::EmitF64Const(double value) {
  body_.write_u8(kExprF64Const);
  body_.write_f64(value);
}

void WasmFunctionBuilder::EmitDirectCallIndex(uint32_t index) {
  DirectCallIndex call;
  call.offset = body_.size();
  call.direct_index = index;
  direct_calls_.push_back(call);
  uint8_t placeholder_bytes[kMaxVarInt32Size] = {0};
  EmitCode(placeholder_bytes, arraysize(placeholder_bytes));
}

void WasmFunctionBuilder::EmitFromInitializerExpression(
    const WasmInitExpr& init_expr) {
  WriteInitializerExpression(&body_, init_expr);
}

void WasmFunctionBuilder::SetName(base::Vector<const char> name) {
  name_ = name;
}

void WasmFunctionBuilder::AddAsmWasmOffset(size_t call_position,
                                           size_t to_number_position) {
  // We only want to emit one mapping per byte offset.
  DCHECK(asm_offsets_.size() == 0 || body_.size() > last_asm_byte_offset_);

  DCHECK_LE(body_.size(), kMaxUInt32);
  uint32_t byte_offset = static_cast<uint32_t>(body_.size());
  asm_offsets_.write_u32v(byte_offset - last_asm_byte_offset_);
  last_asm_byte_offset_ = byte_offset;

  DCHECK_GE(std::numeric_limits<uint32_t>::max(), call_position);
  uint32_t call_position_u32 = static_cast<uint32_t>(call_position);
  asm_offsets_.write_i32v(call_position_u32 - last_asm_source_position_);

  DCHECK_GE(std::numeric_limits<uint32_t>::max(), to_number_position);
  uint32_t to_number_position_u32 = static_cast<uint32_t>(to_number_position);
  asm_offsets_.write_i32v(to_number_position_u32 - call_position_u32);
  last_asm_source_position_ = to_number_position_u32;
}

void WasmFunctionBuilder::SetAsmFunctionStartPosition(
    size_t function_position) {
  DCHECK_EQ(0, asm_func_start_source_position_);
  DCHECK_GE(std::numeric_limits<uint32_t>::max(), function_position);
  uint32_t function_position_u32 = static_cast<uint32_t>(function_position);
  // Must be called before emitting any asm.js source position.
  DCHECK_EQ(0, asm_offsets_.size());
  asm_func_start_source_position_ = function_position_u32;
  last_asm_source_position_ = function_position_u32;
}

void WasmFunctionBuilder::SetCompilationHint(
    WasmCompilationHintStrategy strategy, WasmCompilationHintTier baseline,
    WasmCompilationHintTier top_tier) {
  uint8_t hint_byte = static_cast<uint8_t>(strategy) |
                      static_cast<uint8_t>(baseline) << 2 |
                      static_cast<uint8_t>(top_tier) << 4;
  DCHECK_NE(hint_byte, kNoCompilationHint);
  hint_ = hint_byte;
}

void WasmFunctionBuilder::DeleteCodeAfter(size_t position) {
  DCHECK_LE(position, body_.size());
  body_.Truncate(position);
}

void WasmFunctionBuilder::WriteSignature(ZoneBuffer* buffer) const {
  buffer->write_u32v(signature_index_);
}

void WasmFunctionBuilder::WriteBody(ZoneBuffer* buffer) const {
  size_t locals_size = locals_.Size();
  buffer->write_size(locals_size + body_.size());
  buffer->EnsureSpace(locals_size);
  uint8_t** ptr = buffer->pos_ptr();
  locals_.Emit(*ptr);
  (*ptr) += locals_size;  // UGLY: manual bump of position pointer
  if (body_.size() > 0) {
    size_t base = buffer->offset();
    buffer->write(body_.begin(), body_.size());
    for (DirectCallIndex call : direct_calls_) {
      buffer->patch_u32v(
          base + call.offset,
          call.direct_index +
              static_cast<uint32_t>(builder_->function_imports_.size()));
    }
  }
}

void WasmFunctionBuilder::WriteAsmWasmOffsetTable(ZoneBuffer* buffer) const {
  if (asm_func_start_source_position_ == 0 && asm_offsets_.size() == 0) {
    buffer->write_size(0);
    return;
  }
  size_t locals_enc_size = LEBHelper::sizeof_u32v(locals_.Size());
  size_t func_start_size =
      LEBHelper::sizeof_u32v(asm_func_start_source_position_);
  buffer->write_size(asm_offsets_.size() + locals_enc_size + func_start_size);
  // Offset of the recorded byte offsets.
  DCHECK_GE(kMaxUInt32, locals_.Size());
  buffer->write_u32v(static_cast<uint32_t>(locals_.Size()));
  // Start position of the function.
  buffer->write_u32v(asm_func_start_source_position_);
  buffer->write(asm_offsets_.begin(), asm_offsets_.size());
}

WasmModuleBuilder::WasmModuleBuilder(Zone* zone)
    : zone_(zone),
      types_(zone),
      function_imports_(zone),
      global_imports_(zone),
      exports_(zone),
      functions_(zone),
      tables_(zone),
      memories_(zone),
      data_segments_(zone),
      element_segments_(zone),
      globals_(zone),
      tags_(zone),
      signature_map_(zone),
      current_recursive_group_start_(-1),
      recursive_groups_(zone),
      start_function_index_(-1) {}

WasmFunctionBuilder* WasmModuleBuilder::AddFunction(const FunctionSig* sig) {
  functions_.push_back(zone_->New<WasmFunctionBuilder>(this));
  // Add the signature if one was provided here.
  if (sig) functions_.back()->SetSignature(sig);
  return functions_.back();
}

WasmFunctionBuilder* WasmModuleBuilder::AddFunction(ModuleTypeIndex sig_index) {
  functions_.push_back(zone_->New<WasmFunctionBuilder>(this));
  functions_.back()->SetSignature(sig_index);
  return functions_.back();
}

void WasmModuleBuilder::AddDataSegment(const uint8_t* data, uint32_t size,
                                       uint32_t dest) {
  data_segments_.push_back({.data = ZoneVector<uint8_t>(zone()), .dest = dest});
  ZoneVector<uint8_t>& vec = data_segments_.back().data;
  for (uint32_t i = 0; i < size; i++) {
    vec.push_back(data[i]);
  }
}

void WasmModuleBuilder::AddPassiveDataSegment(const uint8_t* data,
                                              uint32_t size) {
  data_segments_.push_back(
      {.data = ZoneVector<uint8_t>(zone()), .dest = 0, .is_active = false});
  ZoneVector<uint8_t>& vec = data_segments_.back().data;
  for (uint32_t i = 0; i < size; i++) {
    vec.push_back(data[i]);
  }
}

ModuleTypeIndex WasmModuleBuilder::ForceAddSignature(
    const FunctionSig* sig, bool is_final, ModuleTypeIndex supertype) {
  ModuleTypeIndex index{static_cast<uint32_t>(types_.size())};
  signature_map_.emplace(*sig, index);
  types_.emplace_back(sig, supertype, is_final, false);
  return index;
}

ModuleTypeIndex WasmModuleBuilder::AddSignature(const FunctionSig* sig,
                                                bool is_final,
                                                ModuleTypeIndex supertype) {
  auto sig_entry = signature_map_.find(*sig);
  if (sig_entry != signature_map_.end()) return sig_entry->second;
  return ForceAddSignature(sig, is_final, supertype);
}

uint32_t WasmModuleBuilder::AddTag(const FunctionSig* type) {
  DCHECK_EQ(0, type->return_count());
  ModuleTypeIndex type_index = AddSignature(type, true);
  uint32_t except_index = static_cast<uint32_t>(tags_.size());
  tags_.push_back(type_index);
  return except_index;
}

ModuleTypeIndex WasmModuleBuilder::AddStructType(StructType* type,
                                                 bool is_final,
                                                 ModuleTypeIndex supertype) {
  uint32_t index = static_cast<uint32_t>(types_.size());
  types_.emplace_back(type, supertype, is_final, false);
  return ModuleTypeIndex{index};
}

ModuleTypeIndex WasmModuleBuilder::AddArrayType(ArrayType* type, bool is_final,
                                                ModuleTypeIndex supertype) {
  uint32_t index = static_cast<uint32_t>(types_.size());
  types_.emplace_back(type, supertype, is_final, false);
  return ModuleTypeIndex{index};
}

uint32_t WasmModuleBuilder::IncreaseTableMinSize(uint32_t table_index,
                                                 uint32_t count) {
  DCHECK_LT(table_index, tables_.size());
  uint32_t old_min_size = tables_[table_index].min_size;
  if (count > v8_flags.wasm_max_table_size - old_min_size) {
    return std::numeric_limits<uint32_t>::max();
  }
  tables_[table_index].min_size = old_min_size + count;
  tables_[table_index].max_size =
      std::max(old_min_size + count, tables_[table_index].max_size);
  return old_min_size;
}

uint32_t WasmModuleBuilder::AddTable(ValueType type, uint32_t min_size) {
  tables_.push_back({.type = type, .min_size = min_size});
  return static_cast<uint32_t>(tables_.size() - 1);
}

uint32_t WasmModuleBuilder::AddTable(ValueType type, uint32_t min_size,
                                     uint32_t max_size,
                                     AddressType address_type) {
  tables_.push_back({.type = type,
                     .min_size = min_size,
                     .max_size = max_size,
                     .has_maximum = true,
                     .address_type = address_type});
  return static_cast<uint32_t>(tables_.size() - 1);
}

uint32_t WasmModuleBuilder::AddTable(ValueType type, uint32_t min_size,
                                     uint32_t max_size, WasmInitExpr init,
                                     AddressType address_type) {
  tables_.push_back({.type = type,
                     .min_size = min_size,
                     .max_size = max_size,
                     .has_maximum = true,
                     .address_type = address_type,
                     .init = {init}});
  return static_cast<uint32_t>(tables_.size() - 1);
}

uint32_t WasmModuleBuilder::AddMemory(uint32_t min_pages) {
  memories_.push_back({.min_pages = min_pages});
  return static_cast<uint32_t>(memories_.size() - 1);
}

uint32_t WasmModuleBuilder::AddMemory(uint32_t min_pages, uint32_t max_pages) {
  memories_.push_back(
      {.min_pages = min_pages, .max_pages = max_pages, .has_max_pages = true});
  return static_cast<uint32_t>(memories_.size() - 1);
}

uint32_t WasmModuleBuilder::AddMemory64(uint32_t min_pages) {
  memories_.push_back(
      {.min_pages = min_pages, .address_type = AddressType::kI64});
  return static_cast<uint32_t>(memories_.size() - 1);
}

uint32_t WasmModuleBuilder::AddMemory64(uint32_t min_pages,
                                        uint32_t max_pages) {
  memories_.push_back({.min_pages = min_pages,
                       .max_pages = max_pages,
                       .has_max_pages = true,
                       .address_type = AddressType::kI64});
  return static_cast<uint32_t>(memories_.size() - 1);
}

uint32_t WasmModuleBuilder::AddElementSegment(WasmElemSegment segment) {
  element_segments_.push_back(std::move(segment));
  return static_cast<uint32_t>(element_segments_.size() - 1);
}

void WasmModuleBuilder::SetIndirectFunction(
    uint32_t table_index, uint32_t index_in_table,
    uint32_t direct_function_index,
    WasmElemSegment::FunctionIndexingMode indexing_mode) {
  WasmElemSegment segment(zone_, kWasmFuncRef, table_index,
                          WasmInitExpr(static_cast<int>(index_in_table)));
  segment.indexing_mode = indexing_mode;
  segment.entries.emplace_back(WasmElemSegment::Entry::kRefFuncEntry,
                               direct_function_index);
  AddElementSegment(std::move(segment));
}

uint32_t WasmModuleBuilder::AddImport(base::Vector<const char> name,
                                      const FunctionSig* sig,
                                      base::Vector<const char> module) {
  DCHECK(adding_imports_allowed_);
  function_imports_.push_back(
      {.module = module, .name = name, .sig_index = AddSignature(sig, true)});
  return static_cast<uint32_t>(function_imports_.size() - 1);
}

uint32_t WasmModuleBuilder::AddGlobalImport(base::Vector<const char> name,
                                            ValueType type, bool mutability,
                                            base::Vector<const char> module) {
  global_imports_.push_back({.module = module,
                             .name = name,
                             .type_code = type.value_type_code(),
                             .mutability = mutability});
  return static_cast<uint32_t>(global_imports_.size() - 1);
}

void WasmModuleBuilder::MarkStartFunction(WasmFunctionBuilder* function) {
  start_function_index_ = function->func_index();
}

void WasmModuleBuilder::AddExport(base::Vector<const char> name,
                                  ImportExportKindCode kind, uint32_t index) {
  DCHECK_LE(index, std::numeric_limits<int>::max());
  exports_.push_back(
      {.name = name, .kind = kind, .index = static_cast<int>(index)});
}

uint32_t WasmModuleBuilder::AddExportedGlobal(ValueType type, bool mutability,
                                              WasmInitExpr init,
                                              base::Vector<const char> name) {
  uint32_t index = AddGlobal(type, mutability, init);
  AddExport(name, kExternalGlobal, index);
  return index;
}

void WasmModuleBuilder::ExportImportedFunction(base::Vector<const char> name,
                                               int import_index) {
#if DEBUG
  // The size of function_imports_ must not change any more.
  adding_imports_allowed_ = false;
#endif
  exports_.push_back(
      {.name = name,
       .kind = kExternalFunction,
       .index = import_index - static_cast<int>(function_imports_.size())});
}

uint32_t WasmModuleBuilder::AddGlobal(ValueType type, bool mutability,
                                      WasmInitExpr init) {
  globals_.push_back({.type = type, .mutability = mutability, .init = init});
  return static_cast<uint32_t>(globals_.size() - 1);
}

void WasmModuleBuilder::WriteTo(ZoneBuffer* buffer) const {
  // == Emit magic =============================================================
  buffer->write_u32(kWasmMagic);
  buffer->write_u32(kWasmVersion);

  // == Emit types =============================================================
  if (!types_.empty()) {
    size_t start = EmitSection(kTypeSectionCode, buffer);
    size_t type_count = types_.size();
    for (auto pair : recursive_groups_) {
      // Every rec. group counts as one type entry.
      type_count -= pair.second - 1;
    }

    buffer->write_size(type_count);

    for (uint32_t i = 0; i < types_.size(); i++) {
      auto recursive_group = recursive_groups_.find(i);

      if (recursive_group != recursive_groups_.end()) {
        buffer->write_u8(kWasmRecursiveTypeGroupCode);
        buffer->write_u32v(recursive_group->second);
      }

      const TypeDefinition& type = types_[i];

      if (type.supertype.valid()) {
        buffer->write_u8(type.is_final ? kWasmSubtypeFinalCode
                                       : kWasmSubtypeCode);
        buffer->write_u8(1);
        buffer->write_u32v(type.supertype);
      } else if (!type.is_final) {
        buffer->write_u8(kWasmSubtypeCode);
        buffer->write_u8(0);
      }
      switch (type.kind) {
        case TypeDefinition::kFunction: {
          const FunctionSig* sig = type.function_sig;
          buffer->write_u8(kWasmFunctionTypeCode);
          buffer->write_size(sig->parameter_count());
          for (auto param : sig->parameters()) {
            WriteValueType(buffer, param);
          }
          buffer->write_size(sig->return_count());
          for (auto ret : sig->returns()) {
            WriteValueType(buffer, ret);
          }
          break;
        }
        case TypeDefinition::kStruct: {
          const StructType* struct_type = type.struct_type;
          buffer->write_u8(kWasmStructTypeCode);
          buffer->write_size(struct_type->field_count());
          for (uint32_t i = 0; i < struct_type->field_count(); i++) {
            WriteValueType(buffer, struct_type->field(i));
            buffer->write_u8(struct_type->mutability(i) ? 1 : 0);
          }
          break;
        }
        case TypeDefinition::kArray: {
          const ArrayType* array_type = type.array_type;
          buffer->write_u8(kWasmArrayTypeCode);
          WriteValueType(buffer, array_type->element_type());
          buffer->write_u8(array_type->mutability() ? 1 : 0);
          break;
        }
      }
    }
    FixupSection(buffer, start);
  }

  // == Emit imports ===========================================================
  if (global_imports_.size() + function_imports_.size() > 0) {
    size_t start = EmitSection(kImportSectionCode, buffer);
    buffer->write_size(global_imports_.size() + function_imports_.size());
    for (auto import : global_imports_) {
      buffer->write_string(import.module);  // module name
      buffer->write_string(import.name);    // field name
      buffer->write_u8(kExternalGlobal);
      buffer->write_u8(import.type_code);
      buffer->write_u8(import.mutability ? 1 : 0);
    }
    for (auto import : function_imports_) {
      buffer->write_string(import.module);  // module name
      buffer->write_string(import.name);    // field name
      buffer->write_u8(kExternalFunction);
      buffer->write_u32v(import.sig_index);
    }
    FixupSection(buffer, start);
  }

  // == Emit function signatures ===============================================
  uint32_t num_function_names = 0;
  if (!functions_.empty()) {
    size_t start = EmitSection(kFunctionSectionCode, buffer);
    buffer->write_size(functions_.size());
    for (auto* function : functions_) {
      function->WriteSignature(buffer);
      if (!function->name_.empty()) ++num_function_names;
    }
    FixupSection(buffer, start);
  }

  // == Emit tables ============================================================
  if (!tables_.empty()) {
    size_t start = EmitSection(kTableSectionCode, buffer);
    buffer->write_size(tables_.size());
    for (const WasmTable& table : tables_) {
      if (table.init) {
        buffer->write_u8(0x40);  // table-with-initializer
        buffer->write_u8(0x00);  // reserved byte
      }
      WriteValueType(buffer, table.type);
      uint8_t limits_byte = (table.is_table64() ? 4 : 0) |
                            (table.is_shared ? 2 : 0) |
                            (table.has_maximum ? 1 : 0);
      buffer->write_u8(limits_byte);
      auto WriteValToBuffer = [&](uint32_t val) {
        table.is_table64() ? buffer->write_u64v(val) : buffer->write_u32v(val);
      };
      WriteValToBuffer(table.min_size);
      if (table.has_maximum) {
        WriteValToBuffer(table.max_size);
      }
      if (table.init) {
        WriteInitializerExpression(buffer, *table.init);
      }
    }
    FixupSection(buffer, start);
  }

  // == Emit memory declaration ================================================
  if (!memories_.empty()) {
    size_t start = EmitSection(kMemorySectionCode, buffer);
    buffer->write_size(memories_.size());
    for (const WasmMemory& memory : memories_) {
      uint8_t limits_byte = (memory.is_memory64() ? 4 : 0) |
                            (memory.is_shared ? 2 : 0) |
                            (memory.has_max_pages ? 1 : 0);
      buffer->write_u8(limits_byte);
      auto WriteValToBuffer = [&](uint32_t val) {
        memory.is_memory64() ? buffer->write_u64v(val)
                             : buffer->write_u32v(val);
      };
      WriteValToBuffer(memory.min_pages);
      if (memory.has_max_pages) {
        WriteValToBuffer(memory.max_pages);
      }
    }
    FixupSection(buffer, start);
  }

  // == Emit event section =====================================================
  if (!tags_.empty()) {
    size_t start = EmitSection(kTagSectionCode, buffer);
    buffer->write_size(tags_.size());
    for (ModuleTypeIndex type : tags_) {
      buffer->write_u32v(kExceptionAttribute);
      buffer->write_u32v(type);
    }
    FixupSection(buffer, start);
  }

  // == Emit globals ===========================================================
  if (!globals_.empty()) {
    size_t start = EmitSection(kGlobalSectionCode, buffer);
    buffer->write_size(globals_.size());

    for (const WasmGlobal& global : globals_) {
      WriteValueType(buffer, global.type);
      buffer->write_u8(global.mutability ? 1 : 0);
      WriteInitializerExpression(buffer, global.init);
    }
    FixupSection(buffer, start);
  }

  // == Emit exports ===========================================================
  if (!exports_.empty()) {
    size_t start = EmitSection(kExportSectionCode, buffer);
    buffer->write_size(exports_.size());
    for (auto ex : exports_) {
      buffer->write_string(ex.name);
      buffer->write_u8(ex.kind);
      switch (ex.kind) {
        case kExternalFunction:
          buffer->write_size(ex.index + function_imports_.size());
          break;
        case kExternalGlobal:
          buffer->write_size(ex.index + global_imports_.size());
          break;
        case kExternalMemory:
        case kExternalTable:
          // The WasmModuleBuilder doesn't support importing tables or memories
          // yet, so there is no index offset to add.
          buffer->write_size(ex.index);
          break;
        case kExternalTag:
          UNREACHABLE();
      }
    }
    FixupSection(buffer, start);
  }

  // == Emit start function index ==============================================
  if (start_function_index_ >= 0) {
    size_t start = EmitSection(kStartSectionCode, buffer);
    buffer->write_size(start_function_index_ + function_imports_.size());
    FixupSection(buffer, start);
  }

  // == Emit element segments ==================================================
  if (!element_segments_.empty()) {
    size_t start = EmitSection(kElementSectionCode, buffer);
    buffer->write_size(element_segments_.size());
    for (const WasmElemSegment& segment : element_segments_) {
      bool is_active = segment.status == WasmElemSegment::kStatusActive;
      // We pick the most general syntax, i.e., we always explicitly emit the
      // table index and the type, and use the expressions-as-elements syntax.
      // The initial byte is one of 0x05, 0x06, and 0x07.
      uint8_t kind_mask =
          segment.status == WasmElemSegment::kStatusActive
              ? 0b10
              : segment.status == WasmElemSegment::kStatusDeclarative ? 0b11
                                                                      : 0b01;
      uint8_t expressions_as_elements_mask = 0b100;
      buffer->write_u8(kind_mask | expressions_as_elements_mask);
      if (is_active) {
        buffer->write_u32v(segment.table_index);
        WriteInitializerExpression(buffer, segment.offset);
      }
      WriteValueType(buffer, segment.type);
      buffer->write_size(segment.entries.size());
      for (const WasmElemSegment::Entry entry : segment.entries) {
        uint8_t opcode =
            entry.kind == WasmElemSegment::Entry::kGlobalGetEntry
                ? kExprGlobalGet
                : entry.kind == WasmElemSegment::Entry::kRefFuncEntry
                      ? kExprRefFunc
                      : kExprRefNull;
        bool needs_function_offset =
            segment.indexing_mode ==
                WasmElemSegment::kRelativeToDeclaredFunctions &&
            entry.kind == WasmElemSegment::Entry::kRefFuncEntry;
        uint32_t index =
            entry.index + (needs_function_offset
                               ? static_cast<uint32_t>(function_imports_.size())
                               : 0);
        buffer->write_u8(opcode);
        buffer->write_u32v(index);
        buffer->write_u8(kExprEnd);
      }
    }
    FixupSection(buffer, start);
  }

  // == Emit data segment count section ========================================
  if (std::any_of(
          data_segments_.begin(), data_segments_.end(),
          [](const WasmDataSegment& segment) { return !segment.is_active; })) {
    buffer->write_u8(kDataCountSectionCode);
    buffer->write_u32v(1);  // section length
    buffer->write_u32v(static_cast<uint32_t>(data_segments_.size()));
  }

  // == Emit compilation hints section =========================================
  bool emit_compilation_hints = false;
  for (auto* fn : functions_) {
    if (fn->hint_ != kNoCompilationHint) {
      emit_compilation_hints = true;
      break;
    }
  }
  if (emit_compilation_hints) {
    // Emit the section code.
    buffer->write_u8(kUnknownSectionCode);
    // Emit a placeholder for section length.
    size_t start = buffer->reserve_u32v();
    // Emit custom section name.
    buffer->write_string(base::CStrVector("compilationHints"));
    // Emit hint count.
    buffer->write_size(functions_.size());
    // Emit hint bytes.
    for (auto* fn : functions_) {
      uint8_t hint_byte =
          fn->hint_ != kNoCompilationHint ? fn->hint_ : kDefaultCompilationHint;
      buffer->write_u8(hint_byte);
    }
    FixupSection(buffer, start);
  }

  // == Emit code ==============================================================
  if (!functions_.empty()) {
    size_t start = EmitSection(kCodeSectionCode, buffer);
    buffer->write_size(functions_.size());
    for (auto* function : functions_) {
      function->WriteBody(buffer);
    }
    FixupSection(buffer, start);
  }

  // == Emit data segments =====================================================
  if (!data_segments_.empty()) {
    size_t start = EmitSection(kDataSectionCode, buffer);
    buffer->write_size(data_segments_.size());

    for (auto segment : data_segments_) {
      if (segment.is_active) {
        buffer->write_u8(0);              // linear memory segment
        buffer->write_u8(kExprI32Const);  // constant expression for dest
        buffer->write_u32v(segment.dest);
        buffer->write_u8(kExprEnd);
      } else {
        buffer->write_u8(kPassive);
      }
      buffer->write_u32v(static_cast<uint32_t>(segment.data.size()));
      buffer->write(segment.data.data(), segment.data.size());
    }
    FixupSection(buffer, start);
  }

  // == Emit names =============================================================
  if (num_function_names > 0 || !function_imports_.empty()) {
    // Emit the section code.
    buffer->write_u8(kUnknownSectionCode);
    // Emit a placeholder for the length.
    size_t start = buffer->reserve_u32v();
    // Emit the section string.
    buffer->write_string(base::CStrVector("name"));
    // Emit a subsection for the function names.
    buffer->write_u8(NameSectionKindCode::kFunctionCode);
    // Emit a placeholder for the subsection length.
    size_t functions_start = buffer->reserve_u32v();
    // Emit the function names.
    // Imports are always named.
    uint32_t num_imports = static_cast<uint32_t>(function_imports_.size());
    buffer->write_size(num_imports + num_function_names);
    uint32_t function_index = 0;
    for (; function_index < num_imports; ++function_index) {
      const WasmFunctionImport* import = &function_imports_[function_index];
      DCHECK(!import->name.empty());
      buffer->write_u32v(function_index);
      buffer->write_string(import->name);
    }
    if (num_function_names > 0) {
      for (auto* function : functions_) {
        DCHECK_EQ(function_index,
                  function->func_index() + function_imports_.size());
        if (!function->name_.empty()) {
          buffer->write_u32v(function_index);
          buffer->write_string(function->name_);
        }
        ++function_index;
      }
    }
    FixupSection(buffer, functions_start);
    FixupSection(buffer, start);
  }
}

void WasmModuleBuilder::WriteAsmJsOffsetTable(ZoneBuffer* buffer) const {
  // == Emit asm.js offset table ===============================================
  buffer->write_size(functions_.size());
  // Emit the offset table per function.
  for (auto* function : functions_) {
    function->WriteAsmWasmOffsetTable(buffer);
  }
}
}  // namespace wasm
}  // namespace internal
}  // namespace v8
```