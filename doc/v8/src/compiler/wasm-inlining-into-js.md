Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality and relation to JavaScript.

**1. Initial Skim and Keyword Identification:**

The first step is a quick skim of the code, looking for recognizable keywords and structures. I see:

* `#include`:  This tells me it's C++ and includes other files. The included files (`wasm-inlining-into-js.h`, `wasm-compiler-definitions.h`, etc.) immediately suggest a connection to WebAssembly and compilation. The `into-js` part of the filename and the first include strongly hint at the core function: inlining WebAssembly code into JavaScript execution.
* `namespace v8::internal::compiler`: This confirms it's part of the V8 JavaScript engine's compilation pipeline.
* `class WasmIntoJSInlinerImpl`:  This is a core component. "Inliner" reinforces the idea of inlining. "Impl" often indicates an implementation detail.
* `TryInlining()`: This function name is very descriptive. It suggests an attempt to inline.
* `wasm::`:  This namespace is heavily used, confirming the WebAssembly focus. Types like `WasmModule`, `FunctionBody`, `ValueType`, and opcodes like `kExprAnyConvertExtern` appear frequently.
* `MachineGraph`, `Graph`, `Node`, `WasmGraphAssembler`: These are components of the V8 Turbofan compiler, the optimizing compiler for JavaScript (and apparently for inlined WebAssembly as well).
* `SourcePositionTable`:  Indicates handling of source code locations, important for debugging and error reporting.
* `// Copyright 2023 the V8 project authors`:  Standard V8 copyright header.

**2. Understanding the `WasmIntoJSInlinerImpl` Class:**

This class seems to be the heart of the inlining logic. I'll look at its members and methods:

* **Constructor:** It takes various parameters related to the WebAssembly module, function body, the compilation graph, and source position information. This tells me it's initialized with the context necessary for inlining a specific WebAssembly function.
* **`Param()`:**  This appears to handle getting parameters for the WebAssembly function within the compilation graph. The type guarding is interesting, suggesting type safety is being maintained during inlining.
* **`TryInlining()`:** This is the main driver. It checks for unsupported features (like multi-return) and then seems to process the WebAssembly bytecode instruction by instruction. The `switch` statement on `opcode` is a clear indicator of bytecode interpretation. The `stack` variable suggests a stack-based execution model, like WebAssembly's.
* **Private methods (like `ParseAnyConvertExtern`, `ParseLocalGet`, `ParseStructGet`, etc.):** These handle specific WebAssembly opcodes. The names are descriptive of the operations they perform. They manipulate the `stack` and use the `gasm_` (WasmGraphAssembler) to build the compilation graph nodes.
* **`ReadOpcode()`:** Responsible for reading and decoding WebAssembly opcodes from the bytecode.
* **`TypeNode()`:** Associates a V8 compilation graph node with its WebAssembly type.
* **`SetSourcePosition()`:**  Records the source code location for the generated graph nodes.

**3. Identifying the Core Functionality:**

Based on the class structure and method names, the core functionality is:

* **Decoding WebAssembly Bytecode:**  The `Decoder` base class and the `ReadOpcode()` method handle this.
* **Building a V8 Compilation Graph:** The `WasmGraphAssembler` (`gasm_`) is used to create nodes in the `MachineGraph`. Each parsed WebAssembly instruction leads to the creation of corresponding graph nodes.
* **Type Handling:**  The code explicitly manages WebAssembly types and converts them to V8's internal type system (`compiler::Type`).
* **Handling Specific WebAssembly Features:** The `switch` statement and the `Parse...` methods indicate support for various WebAssembly instructions like memory access, struct/array operations, and type conversions.
* **Inlining Limitations:** The `TryInlining()` method has early exits (`return false`) for unsupported features.

**4. Connecting to JavaScript:**

The key connection to JavaScript is the purpose of this inlining:

* **Optimizing JavaScript Performance:** By inlining WebAssembly functions directly into the JavaScript execution graph, V8 can potentially eliminate the overhead of calling into and out of the WebAssembly boundary. This can lead to significant performance improvements when JavaScript code frequently interacts with WebAssembly.
* **Seamless Interoperability:** The type conversions and handling of externrefs (`AnyConvertExtern`, `ExternConvertAny`) are crucial for making WebAssembly objects and JavaScript objects interact correctly.

**5. Constructing the JavaScript Example:**

To illustrate the connection, I need a simple JavaScript scenario that would benefit from this kind of inlining. The example should involve calling a WebAssembly function from JavaScript:

```javascript
// Assume we have a WebAssembly module instance 'wasmInstance'
// with an exported function 'add'.

const result = wasmInstance.exports.add(5, 3);
console.log(result);
```

Now, explain how the C++ code *could* optimize this. Imagine the `add` function in WebAssembly is very simple. The inliner might detect this and instead of a function call, directly insert the WebAssembly `add` logic into the JavaScript's execution flow. This is the core idea of inlining.

**6. Refining the Explanation:**

Review the drafted explanation to ensure clarity and accuracy. Use concise language and explain technical terms where necessary. Emphasize the "why" behind the code – the performance benefits of inlining.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this code is about *generating* WebAssembly from JavaScript.
* **Correction:** The filename "wasm-inlining-into-js.cc" strongly suggests the opposite direction: integrating WebAssembly into JavaScript execution. The presence of `MachineGraph` and compiler-related terms confirms this is about optimization within V8.
* **Initial thought:** Focus heavily on the specific WebAssembly opcodes.
* **Refinement:** While mentioning some opcodes is important, the higher-level goal of inlining and its benefits for JavaScript performance are more crucial for a general understanding. Don't get bogged down in the minutiae of every opcode unless specifically asked.
* **Initial thought:** The JavaScript example should be complex.
* **Refinement:** A simple example clearly demonstrates the basic interaction between JavaScript and WebAssembly, which is sufficient to illustrate the purpose of the inliner. Complexity can obscure the core point.

By following these steps, moving from a high-level understanding to examining details, and then connecting the code back to its purpose in the JavaScript environment, a comprehensive and accurate explanation can be constructed.
这个C++源代码文件 `v8/src/compiler/wasm-inlining-into-js.cc` 的主要功能是 **尝试将简单的 WebAssembly 函数内联到 V8 JavaScript 引擎的 Turbofan 编译器生成的 JavaScript 代码中**。

更具体地说，它实现了一个内联器，这个内联器会检查 WebAssembly 函数的字节码，并尝试将其中的某些操作直接转换为 Turbofan 图中的节点。如果 WebAssembly 函数足够简单且只包含支持的操作，内联器就能成功将其逻辑嵌入到调用它的 JavaScript 代码的执行流程中。

**以下是其功能的详细归纳：**

1. **WebAssembly 函数的解码和分析:**
   - 它使用 `wasm::Decoder` 来读取和解析 WebAssembly 函数的字节码。
   - 它检查函数是否符合内联的条件，例如，不支持多返回值或包含本地变量的函数。

2. **Turbofan 图的构建:**
   - 如果 WebAssembly 函数可以内联，它会使用 `WasmGraphAssembler` 来创建 Turbofan 图中的节点，这些节点对应于 WebAssembly 函数中的操作。
   - 它处理各种 WebAssembly 操作码，例如：
     - 类型转换 (`kExprAnyConvertExtern`, `kExprExternConvertAny`)
     - 引用操作 (`kExprRefCast`, `kExprRefCastNull`)
     - 数组操作 (`kExprArrayLen`, `kExprArrayGet`, `kExprArraySet`)
     - 结构体操作 (`kExprStructGet`, `kExprStructSet`)
     - 局部变量访问 (`kExprLocalGet`)
     - 控制流 (`kExprDrop`, `kExprEnd`)
   - 它会为生成的节点设置源位置信息，以便进行调试。

3. **类型信息的维护:**
   - 它会跟踪 WebAssembly 值的类型，并将其转换为 Turbofan 的类型系统 (`compiler::Type::Wasm`)。
   - 它会添加类型保护 (`gasm_.TypeGuard`) 以确保类型安全。

4. **错误处理和限制:**
   - 如果遇到不支持的 WebAssembly 操作码或结构，内联器会立即停止并返回 `false`，表示无法内联。
   - 它对可以内联的 WebAssembly 函数施加了许多限制，例如不支持本地变量和多返回值。

**与 JavaScript 功能的关系和示例：**

这个文件的核心目的是提升 JavaScript 代码中调用 WebAssembly 函数的性能。当 JavaScript 代码调用一个可以被内联的 WebAssembly 函数时，V8 引擎不是执行一个传统的函数调用，而是直接将 WebAssembly 函数的指令嵌入到 JavaScript 代码的执行路径中。这可以减少函数调用的开销，并允许 Turbofan 进一步优化组合后的代码。

**JavaScript 示例：**

假设我们有一个简单的 WebAssembly 模块，其中包含一个将两个数字相加的函数 `add`:

```wat
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

在 JavaScript 中调用这个函数：

```javascript
const wasmCode = await fetch('my_module.wasm'); // 假设 'my_module.wasm' 包含上面的 WASM 代码
const wasmInstance = await WebAssembly.instantiateStreaming(wasmCode);
const add = wasmInstance.instance.exports.add;

const result = add(5, 3);
console.log(result); // 输出 8
```

**`wasm-inlining-into-js.cc` 的作用：**

当 V8 引擎执行 `add(5, 3)` 时，`WasmIntoJSInliner` 会尝试将 `add` 函数内联。因为它是一个非常简单的函数，只包含受支持的操作 (`local.get`, `i32.add`)，内联器可能会成功地将 `add` 函数的逻辑嵌入到 JavaScript 的执行流程中。

**内联后的概念性执行流程 (简化):**

原本的执行流程是 JavaScript 调用 WebAssembly 函数，然后 WebAssembly 函数执行并返回。

内联后的概念性执行流程可能更接近这样：

```javascript
// ... 前面的代码

const result = 5 + 3; // 内联器将 WebAssembly 的加法操作直接插入到 JavaScript 中
console.log(result);
```

**好处：**

- **减少函数调用开销:**  消除了跨越 JavaScript 和 WebAssembly 边界的函数调用的开销。
- **更好的优化机会:**  Turbofan 可以对内联后的代码进行更全面的优化，因为它现在可以将 WebAssembly 的操作视为 JavaScript 代码的一部分。

**总结:**

`v8/src/compiler/wasm-inlining-into-js.cc` 是 V8 引擎中一个重要的优化组件，它通过将简单的 WebAssembly 函数内联到 JavaScript 代码中来提高性能，从而实现更高效的 JavaScript 和 WebAssembly 互操作。它通过解码 WebAssembly 字节码、构建 Turbofan 图节点以及处理类型信息来实现这一目标，但受到可以内联的 WebAssembly 函数的复杂性限制。

Prompt: 
```
这是目录为v8/src/compiler/wasm-inlining-into-js.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-inlining-into-js.h"

#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/compiler/wasm-compiler.h"
#include "src/compiler/wasm-graph-assembler.h"
#include "src/wasm/decoder.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler {

namespace {

using wasm::WasmOpcode;
using wasm::WasmOpcodes;

class WasmIntoJSInlinerImpl : private wasm::Decoder {
  using ValidationTag = NoValidationTag;

  struct Value {
    Node* node = nullptr;
    wasm::ValueType type = wasm::kWasmBottom;
  };

 public:
  WasmIntoJSInlinerImpl(Zone* zone, const wasm::WasmModule* module,
                        MachineGraph* mcgraph, const wasm::FunctionBody& body,
                        base::Vector<const uint8_t> bytes,
                        SourcePositionTable* source_position_table,
                        int inlining_id)
      : wasm::Decoder(bytes.begin(), bytes.end()),
        module_(module),
        mcgraph_(mcgraph),
        body_(body),
        graph_(mcgraph->graph()),
        gasm_(mcgraph, zone),
        source_position_table_(source_position_table),
        inlining_id_(inlining_id) {
    // +1 for instance node.
    size_t params = body.sig->parameter_count() + 1;
    Node* start =
        graph_->NewNode(mcgraph->common()->Start(static_cast<int>(params)));
    graph_->SetStart(start);
    graph_->SetEnd(graph_->NewNode(mcgraph->common()->End(0)));
    gasm_.InitializeEffectControl(start, start);

    // Initialize parameter nodes.
    // We have to add another +1 as the minimum parameter index is actually
    // -1, not 0...
    size_t params_extended = params + 1;
    parameters_ = zone->AllocateArray<Node*>(params_extended);
    for (unsigned i = 0; i < params_extended; i++) {
      parameters_[i] = nullptr;
    }
    // Instance node at parameter 0.
    trusted_data_node_ = Param(wasm::kWasmInstanceDataParameterIndex);
  }

  Node* Param(int index, const char* debug_name = nullptr) {
    DCHECK_NOT_NULL(graph_->start());
    // Turbofan allows negative parameter indices.
    DCHECK_GE(index, kMinParameterIndex);
    int array_index = index - kMinParameterIndex;
    if (parameters_[array_index] == nullptr) {
      Node* param = graph_->NewNode(
          mcgraph_->common()->Parameter(index, debug_name), graph_->start());
      if (index > wasm::kWasmInstanceDataParameterIndex) {
        // Add a type guard to keep type information based on the inlinee's
        // signature.
        wasm::ValueType type = body_.sig->GetParam(index - 1);
        Type tf_type = compiler::Type::Wasm(type, module_, graph_->zone());
        param = gasm_.TypeGuard(tf_type, param);
      }
      parameters_[array_index] = param;
    }
    return parameters_[array_index];
  }

  bool TryInlining() {
    if (body_.sig->return_count() > 1) {
      return false;  // Multi-return is not supported.
    }
    // Parse locals.
    if (consume_u32v() != 0) {
      // Functions with locals are not supported.
      return false;
    }
    // Parse body.
    base::SmallVector<Value, 4> stack;
    while (is_inlineable_) {
      WasmOpcode opcode = ReadOpcode();
      switch (opcode) {
        case wasm::kExprAnyConvertExtern:
          DCHECK(!stack.empty());
          stack.back() = ParseAnyConvertExtern(stack.back());
          continue;
        case wasm::kExprExternConvertAny:
          DCHECK(!stack.empty());
          stack.back() = ParseExternConvertAny(stack.back());
          continue;
        case wasm::kExprRefCast:
        case wasm::kExprRefCastNull:
          DCHECK(!stack.empty());
          stack.back() =
              ParseRefCast(stack.back(), opcode == wasm::kExprRefCastNull);
          continue;
        case wasm::kExprArrayLen:
          DCHECK(!stack.empty());
          stack.back() = ParseArrayLen(stack.back());
          continue;
        case wasm::kExprArrayGet:
        case wasm::kExprArrayGetS:
        case wasm::kExprArrayGetU: {
          DCHECK_GE(stack.size(), 2);
          Value index = stack.back();
          stack.pop_back();
          Value array = stack.back();
          stack.back() = ParseArrayGet(array, index, opcode);
          continue;
        }
        case wasm::kExprArraySet: {
          DCHECK_GE(stack.size(), 3);
          Value value = stack.back();
          stack.pop_back();
          Value index = stack.back();
          stack.pop_back();
          Value array = stack.back();
          stack.pop_back();
          ParseArraySet(array, index, value);
          continue;
        }
        case wasm::kExprStructGet:
        case wasm::kExprStructGetS:
        case wasm::kExprStructGetU:
          DCHECK(!stack.empty());
          stack.back() = ParseStructGet(stack.back(), opcode);
          continue;
        case wasm::kExprStructSet: {
          DCHECK_GE(stack.size(), 2);
          Value value = stack.back();
          stack.pop_back();
          Value wasm_struct = stack.back();
          stack.pop_back();
          ParseStructSet(wasm_struct, value);
          continue;
        }
        case wasm::kExprLocalGet:
          stack.push_back(ParseLocalGet());
          continue;
        case wasm::kExprDrop:
          DCHECK(!stack.empty());
          stack.pop_back();
          continue;
        case wasm::kExprEnd: {
          DCHECK_LT(stack.size(), 2);
          int return_count = static_cast<int>(stack.size());
          base::SmallVector<Node*, 8> buf(return_count + 3);
          buf[0] = mcgraph_->Int32Constant(0);
          if (return_count) {
            buf[1] = stack.back().node;
          }
          buf[return_count + 1] = gasm_.effect();
          buf[return_count + 2] = gasm_.control();
          Node* ret = graph_->NewNode(mcgraph_->common()->Return(return_count),
                                      return_count + 3, buf.data());

          gasm_.MergeControlToEnd(ret);
          return true;
        }
        default:
          // Instruction not supported for inlining.
          return false;
      }
    }
    // The decoder found an instruction it couldn't inline successfully.
    return false;
  }

 private:
  Value ParseAnyConvertExtern(Value input) {
    DCHECK(input.type.is_reference_to(wasm::HeapType::kExtern) ||
           input.type.is_reference_to(wasm::HeapType::kNoExtern));
    wasm::ValueType result_type = wasm::ValueType::RefMaybeNull(
        wasm::HeapType::kAny, input.type.is_nullable()
                                  ? wasm::Nullability::kNullable
                                  : wasm::Nullability::kNonNullable);
    Node* internalized = gasm_.WasmAnyConvertExtern(input.node);
    return TypeNode(internalized, result_type);
  }

  Value ParseExternConvertAny(Value input) {
    DCHECK(input.type.is_reference());
    wasm::ValueType result_type = wasm::ValueType::RefMaybeNull(
        wasm::HeapType::kExtern, input.type.is_nullable()
                                     ? wasm::Nullability::kNullable
                                     : wasm::Nullability::kNonNullable);
    Node* internalized = gasm_.WasmExternConvertAny(input.node);
    return TypeNode(internalized, result_type);
  }

  Value ParseLocalGet() {
    uint32_t index = consume_u32v();
    DCHECK_LT(index, body_.sig->parameter_count());
    return TypeNode(Param(index + 1), body_.sig->GetParam(index));
  }

  Value ParseStructGet(Value struct_val, WasmOpcode opcode) {
    wasm::ModuleTypeIndex struct_index{consume_u32v()};
    DCHECK(module_->has_struct(struct_index));
    const wasm::StructType* struct_type = module_->struct_type(struct_index);
    uint32_t field_index = consume_u32v();
    DCHECK_GT(struct_type->field_count(), field_index);
    const bool is_signed = opcode == wasm::kExprStructGetS;
    const CheckForNull null_check =
        struct_val.type.is_nullable() ? kWithNullCheck : kWithoutNullCheck;
    Node* member = gasm_.StructGet(struct_val.node, struct_type, field_index,
                                   is_signed, null_check);
    SetSourcePosition(member);
    return TypeNode(member, struct_type->field(field_index).Unpacked());
  }

  void ParseStructSet(Value wasm_struct, Value value) {
    wasm::ModuleTypeIndex struct_index{consume_u32v()};
    DCHECK(module_->has_struct(struct_index));
    const wasm::StructType* struct_type = module_->struct_type(struct_index);
    uint32_t field_index = consume_u32v();
    DCHECK_GT(struct_type->field_count(), field_index);
    const CheckForNull null_check =
        wasm_struct.type.is_nullable() ? kWithNullCheck : kWithoutNullCheck;
    gasm_.StructSet(wasm_struct.node, value.node, struct_type, field_index,
                    null_check);
    SetSourcePosition(gasm_.effect());
  }

  Value ParseRefCast(Value input, bool null_succeeds) {
    auto [heap_index, length] = read_i33v<ValidationTag>(pc_);
    pc_ += length;
    if (heap_index < 0) {
      if ((heap_index & 0x7f) != wasm::kArrayRefCode) {
        // Abstract casts for non array type are not supported.
        is_inlineable_ = false;
        return {};
      }
      auto done = gasm_.MakeLabel();
      // Abstract cast to array.
      if (input.type.is_nullable() && null_succeeds) {
        gasm_.GotoIf(gasm_.IsNull(input.node, input.type), &done);
      }
      gasm_.TrapIf(gasm_.IsSmi(input.node), TrapId::kTrapIllegalCast);
      gasm_.TrapUnless(gasm_.HasInstanceType(input.node, WASM_ARRAY_TYPE),
                       TrapId::kTrapIllegalCast);
      SetSourcePosition(gasm_.effect());
      gasm_.Goto(&done);
      gasm_.Bind(&done);
      // Add TypeGuard for graph typing.
      Graph* graph = mcgraph_->graph();
      wasm::ValueType result_type = wasm::ValueType::RefMaybeNull(
          wasm::HeapType::kArray,
          null_succeeds ? wasm::kNullable : wasm::kNonNullable);
      Node* type_guard =
          graph->NewNode(mcgraph_->common()->TypeGuard(
                             Type::Wasm(result_type, module_, graph->zone())),
                         input.node, gasm_.effect(), gasm_.control());
      gasm_.InitializeEffectControl(type_guard, gasm_.control());
      return TypeNode(type_guard, result_type);
    }
    if (module_->has_signature(
            wasm::ModuleTypeIndex{static_cast<uint32_t>(heap_index)})) {
      is_inlineable_ = false;
      return {};
    }
    wasm::ValueType target_type = wasm::ValueType::RefMaybeNull(
        wasm::ModuleTypeIndex{static_cast<uint32_t>(heap_index)},
        null_succeeds ? wasm::kNullable : wasm::kNonNullable);
    Node* rtt = mcgraph_->graph()->NewNode(
        gasm_.simplified()->RttCanon(target_type.ref_index()),
        trusted_data_node_);
    TypeNode(rtt, wasm::ValueType::Rtt(target_type.ref_index()));
    Node* cast = gasm_.WasmTypeCast(input.node, rtt, {input.type, target_type});
    SetSourcePosition(cast);
    return TypeNode(cast, target_type);
  }

  Value ParseArrayLen(Value input) {
    DCHECK(wasm::IsHeapSubtypeOf(input.type.heap_type(),
                                 wasm::HeapType(wasm::HeapType::kArray),
                                 module_));
    const CheckForNull null_check =
        input.type.is_nullable() ? kWithNullCheck : kWithoutNullCheck;
    Node* len = gasm_.ArrayLength(input.node, null_check);
    SetSourcePosition(len);
    return TypeNode(len, wasm::kWasmI32);
  }

  Value ParseArrayGet(Value array, Value index, WasmOpcode opcode) {
    wasm::ModuleTypeIndex array_index{consume_u32v()};
    DCHECK(module_->has_array(array_index));
    const wasm::ArrayType* array_type = module_->array_type(array_index);
    const bool is_signed = opcode == WasmOpcode::kExprArrayGetS;
    const CheckForNull null_check =
        array.type.is_nullable() ? kWithNullCheck : kWithoutNullCheck;
    // Perform bounds check.
    Node* length = gasm_.ArrayLength(array.node, null_check);
    SetSourcePosition(length);
    gasm_.TrapUnless(gasm_.Uint32LessThan(index.node, length),
                     TrapId::kTrapArrayOutOfBounds);
    SetSourcePosition(gasm_.effect());
    // Perform array.get.
    Node* element =
        gasm_.ArrayGet(array.node, index.node, array_type, is_signed);
    return TypeNode(element, array_type->element_type().Unpacked());
  }

  void ParseArraySet(Value array, Value index, Value value) {
    wasm::ModuleTypeIndex array_index{consume_u32v()};
    DCHECK(module_->has_array(array_index));
    const wasm::ArrayType* array_type = module_->array_type(array_index);
    const CheckForNull null_check =
        array.type.is_nullable() ? kWithNullCheck : kWithoutNullCheck;
    // Perform bounds check.
    Node* length = gasm_.ArrayLength(array.node, null_check);
    SetSourcePosition(length);
    gasm_.TrapUnless(gasm_.Uint32LessThan(index.node, length),
                     TrapId::kTrapArrayOutOfBounds);
    SetSourcePosition(gasm_.effect());
    // Perform array.set.
    gasm_.ArraySet(array.node, index.node, value.node, array_type);
  }

  WasmOpcode ReadOpcode() {
    DCHECK_LT(pc_, end_);
    instruction_start_ = pc();
    WasmOpcode opcode = static_cast<WasmOpcode>(*pc_);
    if (!WasmOpcodes::IsPrefixOpcode(opcode)) {
      ++pc_;
      return opcode;
    }
    auto [opcode_with_prefix, length] =
        read_prefixed_opcode<ValidationTag>(pc_);
    pc_ += length;
    return opcode_with_prefix;
  }

  Value TypeNode(Node* node, wasm::ValueType type) {
    compiler::NodeProperties::SetType(
        node, compiler::Type::Wasm(type, module_, graph_->zone()));
    return {node, type};
  }

  void SetSourcePosition(Node* node) {
    if (!source_position_table_->IsEnabled()) return;
    int offset = static_cast<int>(instruction_start_ - start());
    source_position_table_->SetSourcePosition(
        node, SourcePosition(offset, inlining_id_));
  }

  const wasm::WasmModule* module_;
  MachineGraph* mcgraph_;
  const wasm::FunctionBody& body_;
  Node** parameters_;
  Graph* graph_;
  Node* trusted_data_node_;
  WasmGraphAssembler gasm_;
  SourcePositionTable* source_position_table_ = nullptr;
  const uint8_t* instruction_start_ = pc_;
  int inlining_id_;
  bool is_inlineable_ = true;
};

}  // anonymous namespace

bool WasmIntoJSInliner::TryInlining(Zone* zone, const wasm::WasmModule* module,
                                    MachineGraph* mcgraph,
                                    const wasm::FunctionBody& body,
                                    base::Vector<const uint8_t> bytes,
                                    SourcePositionTable* source_position_table,
                                    int inlining_id) {
  WasmIntoJSInlinerImpl inliner(zone, module, mcgraph, body, bytes,
                                source_position_table, inlining_id);
  return inliner.TryInlining();
}

}  // namespace v8::internal::compiler

"""

```