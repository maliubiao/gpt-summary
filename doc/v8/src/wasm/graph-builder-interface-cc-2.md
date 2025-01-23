Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `v8/src/wasm/graph-builder-interface.cc` file.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:**  I need to identify the distinct operations the code performs. Each function within the class likely represents a specific functionality related to building a graph for WebAssembly.

2. **Check for `.tq` extension:** The prompt explicitly asks about the `.tq` extension, indicating a check for Torque-related code. I can confirm this is C++ and not Torque.

3. **Relationship with JavaScript and examples:** If the code interacts with JavaScript concepts, I should provide illustrative JavaScript examples. This involves understanding the connection between WebAssembly and JavaScript in V8.

4. **Code logic and examples:**  For functions with clear logic, I need to provide hypothetical inputs and their corresponding outputs, demonstrating the function's behavior.

5. **Common programming errors:** I should identify potential programming errors that developers might encounter when interacting with the functionalities exposed by this code.

6. **Overall functionality (Part 3 of 4):**  The prompt indicates this is part of a larger context. I need to summarize the role of this specific code section within the broader graph building process.

**Mental Walkthrough of the Code:**

- The code defines a class `WasmGraphBuildingInterface`.
- It seems to provide an interface to a `WasmGraphBuilder`.
- The methods in this class correspond to various WebAssembly operations like:
    - Struct manipulation (`StructNew`, `StructGet`, `StructSet`)
    - Array manipulation (`ArrayNew`, `ArrayGet`, `ArraySet`, `ArrayLen`, `ArrayCopy`, `ArrayFill`, etc.)
    - Reference operations (`RefI31`, `I31GetS`, `I31GetU`, `RefTest`, `RefCast`, `BrOnCast`, etc.)
    - String manipulation (`StringNewWtf8`, `StringNewWtf16`, `StringMeasureWtf8`, `StringEncodeWtf8`, `StringConcat`, `StringEq`, etc.)
    - Control flow related operations (`Forward`, and likely the `BrOn*` family of functions).
- The class maintains internal state like `locals_allocator_`, `ssa_env_`, `loop_infos_`, etc., suggesting it manages the context of graph construction.
- The presence of `FullDecoder* decoder` arguments in many methods indicates it interacts with the decoding process of WebAssembly bytecode.

**Constraint Checklist & Confidence Score:**

1. 列举一下它的功能: Yes
2. 如果v8/src/wasm/graph-builder-interface.cc以.tq结尾，那它是个v8 torque源代码: Yes
3. 如果它与javascript的功能有关系，请用javascript举例说明: Yes
4. 如果有代码逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户常见的编程错误，请举例说明: Yes
6. 这是第3部分，共4部分，请归纳一下它的功能: Yes

Confidence Score: 5/5  I have a good understanding of what the code does and can address all the constraints.

**Strategizing the Response:**

I will structure the response as follows:

1. **Primary Functionality:**  A concise summary of the core responsibility of `graph-builder-interface.cc`.
2. **Detailed Functionalities:** A bulleted list of the key operations exposed by the class, grouping related functions (structs, arrays, references, strings, control flow).
3. **Torque Check:** Explicitly state that the file is C++ and not a Torque file.
4. **JavaScript Relationship and Examples:** Explain how the WebAssembly graph building process relates to JavaScript execution and provide a simple JavaScript example that might trigger some of these underlying operations.
5. **Code Logic and Examples:**  Choose a few representative functions (e.g., `StructGet`, `ArraySet`, `BrOnCast`) and illustrate their behavior with hypothetical inputs and outputs in a simplified manner.
6. **Common Programming Errors:**  Discuss potential issues a WebAssembly developer might face that would relate to the kinds of operations this code handles (e.g., type mismatches, null references, out-of-bounds access).
7. **Overall Functionality (Part 3):**  Contextualize the provided code as an interface layer between the WebAssembly decoder and the graph builder, responsible for translating WebAssembly operations into graph nodes.

By following this plan, I can provide a comprehensive and well-organized answer that addresses all aspects of the user's request.
好的，根据你提供的代码片段，以下是 `v8/src/wasm/graph-builder-interface.cc` 文件中部分代码的功能归纳：

**主要功能归纳：**

这段代码定义了 `WasmGraphBuildingInterface` 类的一部分，这个类是 WebAssembly 编译过程中，将解码后的 WebAssembly 指令转换成 V8 内部图表示（通常是 TurboFan 的图）的接口。它提供了一系列方法，用于构建代表各种 WebAssembly 操作的图节点。

**更详细的功能列表：**

这段代码片段主要涉及以下 WebAssembly 特性的图节点构建：

* **结构体 (Struct) 操作:**
    * `StructNew`: 创建一个新的结构体实例。
    * `StructGet`: 获取结构体字段的值。
    * `StructSet`: 设置结构体字段的值。

* **数组 (Array) 操作:**
    * `ArrayNew`: 创建一个新的数组实例，可以指定初始值。
    * `ArrayNewDefault`: 创建一个新的数组实例，使用默认初始值。
    * `ArrayGet`: 获取数组元素的值。
    * `ArraySet`: 设置数组元素的值。
    * `ArrayLen`: 获取数组的长度。
    * `ArrayCopy`: 复制数组的一部分到另一个数组。
    * `ArrayFill`: 使用一个值填充数组的一部分。
    * `ArrayNewFixed`: 创建一个具有固定初始元素的数组。
    * `ArrayNewSegment`: 基于内存段创建一个数组。
    * `ArrayInitSegment`: 使用内存段的数据初始化数组。

* **i31 类型操作:**
    * `RefI31`: 将一个 i32 值转换为 i31 引用。
    * `I31GetS`: 从 i31 引用中获取有符号 i32 值。
    * `I31GetU`: 从 i31 引用中获取无符号 i32 值。

* **引用 (Reference) 类型操作:**
    * `RefTest`: 检查一个对象是否是指定引用类型的实例。
    * `RefTestAbstract`: 检查一个对象是否是指定的抽象堆类型的实例。
    * `RefCast`: 将一个对象转换为指定的引用类型，如果转换失败会抛出异常。
    * `RefCastAbstract`: 将一个对象转换为指定的抽象堆类型，如果转换失败会抛出异常。
    * `BrOnCast`: 如果对象是指定引用类型的实例，则跳转到指定的分支。
    * `BrOnCastFail`: 如果对象不是指定引用类型的实例，则跳转到指定的分支。
    * `BrOnCastAbstract`:  如果对象是指定的抽象堆类型的实例，则跳转到指定的分支。
    * `BrOnCastFailAbstract`: 如果对象不是指定的抽象堆类型的实例，则跳转到指定的分支。
    * `BrOnEq`, `BrOnNonEq`, `BrOnStruct`, `BrOnNonStruct`, `BrOnArray`, `BrOnNonArray`, `BrOnI31`, `BrOnNonI31`, `BrOnString`, `BrOnNonString`:  基于对象类型的特定断言进行分支跳转。

* **字符串 (String) 操作:**
    * `StringNewWtf8`, `StringNewWtf8Array`, `StringNewWtf16`, `StringNewWtf16Array`: 创建新的字符串。
    * `StringConst`: 创建一个常量字符串。
    * `StringMeasureWtf8`, `StringMeasureWtf16`: 测量字符串的长度。
    * `StringEncodeWtf8`, `StringEncodeWtf8Array`, `StringEncodeWtf16`, `StringEncodeWtf16Array`: 将字符串编码到内存或数组中。
    * `StringConcat`: 连接两个字符串。
    * `StringEq`: 比较两个字符串是否相等。
    * `StringIsUSVSequence`: 检查字符串是否是 USV 序列。
    * `StringAsWtf8`, `StringAsWtf16`, `StringAsIter`: 将字符串转换为不同的表示形式。
    * `StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`, `StringViewWtf16GetCodeUnit`, `StringViewWtf16Encode`, `StringViewWtf16Slice`, `StringViewIterNext`, `StringViewIterAdvance`, `StringViewIterRewind`, `StringViewIterSlice`:  操作字符串视图。
    * `StringCompare`: 比较两个字符串。
    * `StringFromCodePoint`: 从代码点创建字符串。
    * `StringHash`: 计算字符串的哈希值。

* **其他操作:**
    * `Forward`:  在 SSA 环境中传递值，可能需要进行类型保护。

**关于 `.tq` 结尾：**

你说的对，如果 `v8/src/wasm/graph-builder-interface.cc` 以 `.tq` 结尾，那它将是 V8 的 Torque 源代码。但实际上，根据你提供的文件名，它是 `.cc` 结尾，所以这是一个 **C++ 源代码文件**，而不是 Torque 文件。 Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码。

**与 JavaScript 的关系及示例：**

这段代码的功能直接关系到 WebAssembly 在 JavaScript 虚拟机中的执行。当 JavaScript 代码加载并执行 WebAssembly 模块时，V8 会将 WebAssembly 的字节码编译成机器码。 `graph-builder-interface.cc` 中定义的接口正是用于将 WebAssembly 的操作转换成 V8 内部的图表示，这是编译过程中的关键一步。

例如，一个简单的 JavaScript 代码调用 WebAssembly 导出的函数，该函数操作数组，可能会触发这段代码中的 `ArrayNew`、`ArrayGet` 或 `ArraySet` 等方法：

```javascript
// 假设已经加载了一个 WebAssembly 模块 'wasmModule'
const wasmArray = wasmModule.exports.create_array(10); // 可能会触发 ArrayNew
wasmModule.exports.set_array_element(wasmArray, 5, 123); // 可能会触发 ArraySet
const element = wasmModule.exports.get_array_element(wasmArray, 5); // 可能会触发 ArrayGet
console.log(element);
```

在这个例子中，`wasmModule.exports.create_array`、`wasmModule.exports.set_array_element` 和 `wasmModule.exports.get_array_element` 是 WebAssembly 模块导出的函数，它们的内部实现会对应到 `graph-builder-interface.cc` 中的相关方法调用，以便在 V8 的 TurboFan 编译器中构建相应的图节点。

**代码逻辑推理及假设输入输出：**

以 `StructGet` 为例：

**假设输入：**

* `decoder`: 指向当前解码器的指针，用于获取当前位置等信息。
* `struct_object`: 一个表示结构体对象的 `Value`，假设其内部 `node` 指向代表该结构体的图节点，`type` 描述了结构体的类型。
* `field`: 一个 `FieldImmediate` 结构，包含了要访问的字段的结构体类型和索引信息。假设 `field.struct_imm.struct_type` 是结构体类型 A，`field.field_imm.index` 是字段在结构体中的索引 1。
* `is_signed`: `true`，表示要获取的字段是有符号的。
* `result`: 一个指向 `Value` 的指针，用于存储获取到的字段值。

**代码逻辑：**

`StructGet` 方法会调用 `builder_->StructGet`，将结构体对象节点、结构体类型、字段索引等信息传递给图构建器，以创建一个表示获取结构体字段操作的图节点。然后，`SetAndTypeNode` 会将新创建的图节点和其类型信息设置到 `result` 中。

**假设输出：**

`result` 指向的 `Value` 对象的 `node` 成员将指向新创建的表示结构体字段获取操作的图节点，其 `type` 成员将描述获取到的字段的类型。

**用户常见的编程错误举例：**

与这段代码相关的用户常见编程错误通常发生在编写 WebAssembly 代码时，例如：

* **类型不匹配:** 尝试将错误类型的值赋值给结构体字段或数组元素，这可能导致在 `StructSet` 或 `ArraySet` 操作时类型检查失败。
  ```wasm
  (module
    (type $struct_type (struct (field i32)))
    (func (export "set_field") (param $s (ref $struct_type)) (param $val f32)
      (struct.set $struct_type 0 (local.get $s) (local.get $val))) ;; 错误：尝试将 f32 写入 i32 字段
  )
  ```

* **空引用 (Null Reference) 错误:**  在没有进行空值检查的情况下尝试访问结构体或数组的字段或元素，可能导致 `NullCheckFor` 触发错误。
  ```wasm
  (module
    (type $array_type (array i32))
    (func (export "get_element") (param $arr (ref null $array_type)) (param $index i32) (result i32)
      (array.get $array_type (local.get $arr) (local.get $index))) ;; 错误：如果 $arr 为空，则会出错
  )
  ```

* **数组越界访问:**  尝试访问数组边界之外的元素，这会在 `ArrayGet` 或 `ArraySet` 操作时导致错误。
  ```wasm
  (module
    (type $array_type (array i32))
    (func (export "access_out_of_bounds") (param $arr (ref $array_type))
      (array.get $array_type (local.get $arr) (i32.const 100))) ;; 错误：假设数组长度小于 100
  )
  ```

* **类型转换错误:** 在使用 `ref.cast` 等指令时，如果对象的实际类型与目标类型不兼容，会导致类型转换失败。

**这是第3部分，共4部分，请归纳一下它的功能**

考虑到这是第 3 部分，并且结合前面列举的功能，可以推断出 `v8/src/wasm/graph-builder-interface.cc` 的主要职责是：

**作为 WebAssembly 解码器和图构建器之间的桥梁，将解码后的 WebAssembly 指令转换为可以直接被 V8 的 TurboFan 编译器理解和优化的图节点。**

这段代码片段集中展示了如何处理与 **复合类型（结构体和数组）、引用类型、以及字符串操作** 相关的 WebAssembly 指令，并将其转化为图构建器可以操作的节点。这部分功能是构建完整 WebAssembly 执行图的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/graph-builder-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
mmediate& field, bool is_signed, Value* result) {
    SetAndTypeNode(result, builder_->StructGet(struct_object.node,
                                               field.struct_imm.struct_type,
                                               field.field_imm.index,
                                               NullCheckFor(struct_object.type),
                                               is_signed, decoder->position()));
  }

  void StructSet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, const Value& field_value) {
    builder_->StructSet(struct_object.node, field.struct_imm.struct_type,
                        field.field_imm.index, field_value.node,
                        NullCheckFor(struct_object.type), decoder->position());
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length, const Value& initial_value,
                Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    SetAndTypeNode(result, builder_->ArrayNew(imm.index, imm.array_type,
                                              length.node, initial_value.node,
                                              rtt, decoder->position()));
    // array.new(_default) introduces a loop. Therefore, we have to mark the
    // immediately nesting loop (if any) as non-innermost.
    if (!loop_infos_.empty()) loop_infos_.back().can_be_innermost = false;
  }

  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    // This will be set in {builder_}.
    TFNode* initial_value = nullptr;
    SetAndTypeNode(result,
                   builder_->ArrayNew(imm.index, imm.array_type, length.node,
                                      initial_value, rtt, decoder->position()));
    // array.new(_default) introduces a loop. Therefore, we have to mark the
    // immediately nesting loop (if any) as non-innermost.
    if (!loop_infos_.empty()) loop_infos_.back().can_be_innermost = false;
  }

  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                bool is_signed, Value* result) {
    SetAndTypeNode(
        result, builder_->ArrayGet(array_obj.node, imm.array_type, index.node,
                                   NullCheckFor(array_obj.type), is_signed,
                                   decoder->position()));
  }

  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                const Value& value) {
    builder_->ArraySet(array_obj.node, imm.array_type, index.node, value.node,
                       NullCheckFor(array_obj.type), decoder->position());
  }

  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    SetAndTypeNode(
        result, builder_->ArrayLen(array_obj.node, NullCheckFor(array_obj.type),
                                   decoder->position()));
  }

  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    builder_->ArrayCopy(dst.node, dst_index.node, NullCheckFor(dst.type),
                        src.node, src_index.node, NullCheckFor(src.type),
                        length.node, src_imm.array_type, decoder->position());
  }

  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& index, const Value& value,
                 const Value& length) {
    builder_->ArrayFill(array.node, index.node, value.node, length.node,
                        imm.array_type, NullCheckFor(array.type),
                        decoder->position());
    // array.fill introduces a loop. Therefore, we have to mark the immediately
    // nesting loop (if any) as non-innermost.
    if (!loop_infos_.empty()) loop_infos_.back().can_be_innermost = false;
  }

  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm, const Value elements[],
                     Value* result) {
    TFNode* rtt = builder_->RttCanon(array_imm.index);
    NodeVector element_nodes(length_imm.index);
    GetNodes(element_nodes.data(), elements, length_imm.index);
    SetAndTypeNode(result, builder_->ArrayNewFixed(array_imm.array_type, rtt,
                                                   VectorOf(element_nodes)));
  }

  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm, const Value& offset,
                       const Value& length, Value* result) {
    TFNode* rtt = builder_->RttCanon(array_imm.index);
    SetAndTypeNode(result,
                   builder_->ArrayNewSegment(
                       segment_imm.index, offset.node, length.node, rtt,
                       array_imm.array_type->element_type().is_reference(),
                       decoder->position()));
  }

  void ArrayInitSegment(FullDecoder* decoder,
                        const ArrayIndexImmediate& array_imm,
                        const IndexImmediate& segment_imm, const Value& array,
                        const Value& array_index, const Value& segment_offset,
                        const Value& length) {
    builder_->ArrayInitSegment(
        segment_imm.index, array.node, array_index.node, segment_offset.node,
        length.node, array_imm.array_type->element_type().is_reference(),
        decoder->position());
  }

  void RefI31(FullDecoder* decoder, const Value& input, Value* result) {
    SetAndTypeNode(result, builder_->RefI31(input.node));
  }

  void I31GetS(FullDecoder* decoder, const Value& input, Value* result) {
    SetAndTypeNode(result,
                   builder_->I31GetS(input.node, NullCheckFor(input.type),
                                     decoder->position()));
  }

  void I31GetU(FullDecoder* decoder, const Value& input, Value* result) {
    SetAndTypeNode(result,
                   builder_->I31GetU(input.node, NullCheckFor(input.type),
                                     decoder->position()));
  }

  using WasmTypeCheckConfig = v8::internal::compiler::WasmTypeCheckConfig;

  void RefTest(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    TFNode* rtt = builder_->RttCanon(ref_index);
    WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         ref_index, null_succeeds ? kNullable : kNonNullable)};
    SetAndTypeNode(result, builder_->RefTest(object.node, rtt, config));
  }

  void RefTestAbstract(FullDecoder* decoder, const Value& object,
                       wasm::HeapType type, Value* result, bool null_succeeds) {
    WasmTypeCheckConfig config{
        object.type, ValueType::RefMaybeNull(
                         type, null_succeeds ? kNullable : kNonNullable)};
    SetAndTypeNode(result, builder_->RefTestAbstract(object.node, config));
  }

  void RefCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    TFNode* node = object.node;
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      node = builder_->TypeGuard(node, result->type);
    } else {
      TFNode* rtt = builder_->RttCanon(ref_index);
      WasmTypeCheckConfig config{object.type, result->type};
      node = builder_->RefCast(object.node, rtt, config, decoder->position());
    }
    SetAndTypeNode(result, node);
  }

  // TODO(jkummerow): {type} is redundant.
  void RefCastAbstract(FullDecoder* decoder, const Value& object,
                       wasm::HeapType type, Value* result, bool null_succeeds) {
    TFNode* node = object.node;
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) {
      node = builder_->TypeGuard(node, result->type);
    } else {
      WasmTypeCheckConfig config{object.type, result->type};
      node =
          builder_->RefCastAbstract(object.node, config, decoder->position());
    }
    SetAndTypeNode(result, node);
  }

  template <compiler::WasmGraphBuilder::ResultNodesOfBr (
      compiler::WasmGraphBuilder::*branch_function)(TFNode*, TFNode*,
                                                    WasmTypeCheckConfig)>
  void BrOnCastAbs(FullDecoder* decoder, HeapType type, const Value& object,
                   Value* forwarding_value, uint32_t br_depth,
                   bool branch_on_match, bool null_succeeds) {
    TFNode* rtt =
        type.is_bottom() ? nullptr : builder_->RttCanon(type.ref_index());
    // If the type is bottom (used for abstract types), set HeapType to None.
    // The heap type is not read but the null information is needed for the
    // cast.
    Nullability nullable = null_succeeds ? kNullable : kNonNullable;
    ValueType to_type =
        type.is_bottom() ? ValueType::RefMaybeNull(HeapType::kNone, nullable)
                         : ValueType::RefMaybeNull(type.ref_index(), nullable);
    WasmTypeCheckConfig config{object.type, to_type};
    SsaEnv* branch_env = Split(decoder->zone(), ssa_env_);
    // TODO(choongwoo): Clear locals of `no_branch_env` after use.
    SsaEnv* no_branch_env = Steal(decoder->zone(), ssa_env_);
    no_branch_env->SetNotMerged();
    auto nodes_after_br =
        (builder_->*branch_function)(object.node, rtt, config);

    SsaEnv* match_env = branch_on_match ? branch_env : no_branch_env;
    SsaEnv* no_match_env = branch_on_match ? no_branch_env : branch_env;
    match_env->control = nodes_after_br.control_on_match;
    match_env->effect = nodes_after_br.effect_on_match;
    no_match_env->control = nodes_after_br.control_on_no_match;
    no_match_env->effect = nodes_after_br.effect_on_no_match;

    builder_->SetControl(no_branch_env->control);

    if (branch_on_match) {
      ScopedSsaEnv scoped_env(this, branch_env, no_branch_env);
      // Narrow type for the successful cast target branch.
      Forward(decoder, object, forwarding_value);
      // Currently, br_on_* instructions modify the value stack before calling
      // the interface function, so we don't need to drop any values here.
      BrOrRet(decoder, br_depth);
      // Note: Differently to below for !{branch_on_match}, we do not Forward
      // the value here to perform a TypeGuard. It can't be done here due to
      // asymmetric decoder code. A Forward here would be poped from the stack
      // and ignored by the decoder. Therefore the decoder has to call Forward
      // itself.
    } else {
      {
        ScopedSsaEnv scoped_env(this, branch_env, no_branch_env);
        // It is necessary in case of {null_succeeds} to forward the value.
        // This will add a TypeGuard to the non-null type (as in this case the
        // object is non-nullable).
        Forward(decoder, object, decoder->stack_value(1));
        BrOrRet(decoder, br_depth);
      }
      // Narrow type for the successful cast fallthrough branch.
      Forward(decoder, object, forwarding_value);
    }
  }

  void BrOnCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
                const Value& object, Value* value_on_branch, uint32_t br_depth,
                bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnCast>(
        decoder, HeapType{ref_index}, object, value_on_branch, br_depth, true,
        null_succeeds);
  }

  void BrOnCastFail(FullDecoder* decoder, ModuleTypeIndex ref_index,
                    const Value& object, Value* value_on_fallthrough,
                    uint32_t br_depth, bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnCast>(
        decoder, HeapType{ref_index}, object, value_on_fallthrough, br_depth,
        false, null_succeeds);
  }

  void BrOnCastAbstract(FullDecoder* decoder, const Value& object,
                        HeapType type, Value* value_on_branch,
                        uint32_t br_depth, bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return BrOnEq(decoder, object, value_on_branch, br_depth,
                      null_succeeds);
      case HeapType::kI31:
        return BrOnI31(decoder, object, value_on_branch, br_depth,
                       null_succeeds);
      case HeapType::kStruct:
        return BrOnStruct(decoder, object, value_on_branch, br_depth,
                          null_succeeds);
      case HeapType::kArray:
        return BrOnArray(decoder, object, value_on_branch, br_depth,
                         null_succeeds);
      case HeapType::kString:
        return BrOnString(decoder, object, value_on_branch, br_depth,
                          null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn: {
        DCHECK(null_succeeds);
        SsaEnv* false_env = ssa_env_;
        SsaEnv* true_env = Split(decoder->zone(), false_env);
        false_env->SetNotMerged();
        std::tie(true_env->control, false_env->control) =
            builder_->BrOnNull(object.node, object.type);
        builder_->SetControl(false_env->control);
        {
          ScopedSsaEnv scoped_env(this, true_env);
          // Narrow type for the successful cast target branch.
          Forward(decoder, object, value_on_branch);
          int drop_values = 0;
          BrOrRet(decoder, br_depth, drop_values);
        }
      } break;
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  void BrOnCastFailAbstract(FullDecoder* decoder, const Value& object,
                            HeapType type, Value* value_on_fallthrough,
                            uint32_t br_depth, bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return BrOnNonEq(decoder, object, value_on_fallthrough, br_depth,
                         null_succeeds);
      case HeapType::kI31:
        return BrOnNonI31(decoder, object, value_on_fallthrough, br_depth,
                          null_succeeds);
      case HeapType::kStruct:
        return BrOnNonStruct(decoder, object, value_on_fallthrough, br_depth,
                             null_succeeds);
      case HeapType::kArray:
        return BrOnNonArray(decoder, object, value_on_fallthrough, br_depth,
                            null_succeeds);
      case HeapType::kString:
        return BrOnNonString(decoder, object, value_on_fallthrough, br_depth,
                             null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn:
        DCHECK(null_succeeds);
        // We need to store a node in the stack where the decoder so far only
        // pushed a value and expects the `BrOnCastFailAbstract` to set it.
        // TODO(14034): The compiler shouldn't have to access the stack used by
        // the decoder ideally.
        Forward(decoder, object, decoder->stack_value(1));
        return BrOnNonNull(decoder, object, value_on_fallthrough, br_depth,
                           true);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  void BrOnEq(FullDecoder* decoder, const Value& object, Value* value_on_branch,
              uint32_t br_depth, bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnEq>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_branch, br_depth,
        true, null_succeeds);
  }

  void BrOnNonEq(FullDecoder* decoder, const Value& object,
                 Value* value_on_fallthrough, uint32_t br_depth,
                 bool null_succeeds) {
    // TODO(14034): Merge BrOn* and BrOnNon* instructions as their only
    // difference is a boolean flag passed to BrOnCastAbs. This could also be
    // leveraged to merge BrOnCastFailAbstract and BrOnCastAbstract.
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnEq>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_fallthrough,
        br_depth, false, null_succeeds);
  }

  void BrOnStruct(FullDecoder* decoder, const Value& object,
                  Value* value_on_branch, uint32_t br_depth,
                  bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnStruct>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_branch, br_depth,
        true, null_succeeds);
  }

  void BrOnNonStruct(FullDecoder* decoder, const Value& object,
                     Value* value_on_fallthrough, uint32_t br_depth,
                     bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnStruct>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_fallthrough,
        br_depth, false, null_succeeds);
  }

  void BrOnArray(FullDecoder* decoder, const Value& object,
                 Value* value_on_branch, uint32_t br_depth,
                 bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnArray>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_branch, br_depth,
        true, null_succeeds);
  }

  void BrOnNonArray(FullDecoder* decoder, const Value& object,
                    Value* value_on_fallthrough, uint32_t br_depth,
                    bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnArray>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_fallthrough,
        br_depth, false, null_succeeds);
  }

  void BrOnI31(FullDecoder* decoder, const Value& object,
               Value* value_on_branch, uint32_t br_depth, bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnI31>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_branch, br_depth,
        true, null_succeeds);
  }

  void BrOnNonI31(FullDecoder* decoder, const Value& object,
                  Value* value_on_fallthrough, uint32_t br_depth,
                  bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnI31>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_fallthrough,
        br_depth, false, null_succeeds);
  }

  void BrOnString(FullDecoder* decoder, const Value& object,
                  Value* value_on_branch, uint32_t br_depth,
                  bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnString>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_branch, br_depth,
        true, null_succeeds);
  }

  void BrOnNonString(FullDecoder* decoder, const Value& object,
                     Value* value_on_fallthrough, uint32_t br_depth,
                     bool null_succeeds) {
    BrOnCastAbs<&compiler::WasmGraphBuilder::BrOnString>(
        decoder, HeapType{HeapType::kBottom}, object, value_on_fallthrough,
        br_depth, false, null_succeeds);
  }

  void StringNewWtf8(FullDecoder* decoder, const MemoryIndexImmediate& memory,
                     const unibrow::Utf8Variant variant, const Value& offset,
                     const Value& size, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringNewWtf8(memory.memory, variant, offset.node,
                                           size.node, decoder->position()));
  }

  void StringNewWtf8Array(FullDecoder* decoder,
                          const unibrow::Utf8Variant variant,
                          const Value& array, const Value& start,
                          const Value& end, Value* result) {
    SetAndTypeNode(result, builder_->StringNewWtf8Array(
                               variant, array.node, NullCheckFor(array.type),
                               start.node, end.node, decoder->position()));
  }

  void StringNewWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                      const Value& offset, const Value& size, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringNewWtf16(imm.memory, offset.node, size.node,
                                            decoder->position()));
  }

  void StringNewWtf16Array(FullDecoder* decoder, const Value& array,
                           const Value& start, const Value& end,
                           Value* result) {
    SetAndTypeNode(result, builder_->StringNewWtf16Array(
                               array.node, NullCheckFor(array.type), start.node,
                               end.node, decoder->position()));
  }

  void StringConst(FullDecoder* decoder, const StringConstImmediate& imm,
                   Value* result) {
    SetAndTypeNode(result, builder_->StringConst(imm.index));
  }

  void StringMeasureWtf8(FullDecoder* decoder,
                         const unibrow::Utf8Variant variant, const Value& str,
                         Value* result) {
    switch (variant) {
      case unibrow::Utf8Variant::kUtf8:
        SetAndTypeNode(
            result, builder_->StringMeasureUtf8(
                        str.node, NullCheckFor(str.type), decoder->position()));
        break;
      case unibrow::Utf8Variant::kLossyUtf8:
      case unibrow::Utf8Variant::kWtf8:
        SetAndTypeNode(
            result, builder_->StringMeasureWtf8(
                        str.node, NullCheckFor(str.type), decoder->position()));
        break;
      case unibrow::Utf8Variant::kUtf8NoTrap:
        UNREACHABLE();
    }
  }

  void StringMeasureWtf16(FullDecoder* decoder, const Value& str,
                          Value* result) {
    SetAndTypeNode(
        result, builder_->StringMeasureWtf16(str.node, NullCheckFor(str.type),
                                             decoder->position()));
  }

  void StringEncodeWtf8(FullDecoder* decoder,
                        const MemoryIndexImmediate& memory,
                        const unibrow::Utf8Variant variant, const Value& str,
                        const Value& offset, Value* result) {
    SetAndTypeNode(
        result, builder_->StringEncodeWtf8(memory.memory, variant, str.node,
                                           NullCheckFor(str.type), offset.node,
                                           decoder->position()));
  }

  void StringEncodeWtf8Array(FullDecoder* decoder,
                             const unibrow::Utf8Variant variant,
                             const Value& str, const Value& array,
                             const Value& start, Value* result) {
    SetAndTypeNode(
        result, builder_->StringEncodeWtf8Array(
                    variant, str.node, NullCheckFor(str.type), array.node,
                    NullCheckFor(array.type), start.node, decoder->position()));
  }

  void StringEncodeWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                         const Value& str, const Value& offset, Value* result) {
    SetAndTypeNode(result, builder_->StringEncodeWtf16(
                               imm.memory, str.node, NullCheckFor(str.type),
                               offset.node, decoder->position()));
  }

  void StringEncodeWtf16Array(FullDecoder* decoder, const Value& str,
                              const Value& array, const Value& start,
                              Value* result) {
    SetAndTypeNode(
        result, builder_->StringEncodeWtf16Array(
                    str.node, NullCheckFor(str.type), array.node,
                    NullCheckFor(array.type), start.node, decoder->position()));
  }

  void StringConcat(FullDecoder* decoder, const Value& head, const Value& tail,
                    Value* result) {
    SetAndTypeNode(result, builder_->StringConcat(
                               head.node, NullCheckFor(head.type), tail.node,
                               NullCheckFor(tail.type), decoder->position()));
  }

  void StringEq(FullDecoder* decoder, const Value& a, const Value& b,
                Value* result) {
    SetAndTypeNode(result, builder_->StringEqual(a.node, a.type, b.node, b.type,
                                                 decoder->position()));
  }

  void StringIsUSVSequence(FullDecoder* decoder, const Value& str,
                           Value* result) {
    SetAndTypeNode(
        result, builder_->StringIsUSVSequence(str.node, NullCheckFor(str.type),
                                              decoder->position()));
  }

  void StringAsWtf8(FullDecoder* decoder, const Value& str, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringAsWtf8(str.node, NullCheckFor(str.type),
                                          decoder->position()));
  }

  void StringViewWtf8Advance(FullDecoder* decoder, const Value& view,
                             const Value& pos, const Value& bytes,
                             Value* result) {
    SetAndTypeNode(result, builder_->StringViewWtf8Advance(
                               view.node, NullCheckFor(view.type), pos.node,
                               bytes.node, decoder->position()));
  }

  void StringViewWtf8Encode(FullDecoder* decoder,
                            const MemoryIndexImmediate& memory,
                            const unibrow::Utf8Variant variant,
                            const Value& view, const Value& addr,
                            const Value& pos, const Value& bytes,
                            Value* next_pos, Value* bytes_written) {
    builder_->StringViewWtf8Encode(memory.memory, variant, view.node,
                                   NullCheckFor(view.type), addr.node, pos.node,
                                   bytes.node, &next_pos->node,
                                   &bytes_written->node, decoder->position());
    builder_->SetType(next_pos->node, next_pos->type);
    builder_->SetType(bytes_written->node, bytes_written->type);
  }

  void StringViewWtf8Slice(FullDecoder* decoder, const Value& view,
                           const Value& start, const Value& end,
                           Value* result) {
    SetAndTypeNode(result, builder_->StringViewWtf8Slice(
                               view.node, NullCheckFor(view.type), start.node,
                               end.node, decoder->position()));
  }

  void StringAsWtf16(FullDecoder* decoder, const Value& str, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringAsWtf16(str.node, NullCheckFor(str.type),
                                           decoder->position()));
  }

  void StringViewWtf16GetCodeUnit(FullDecoder* decoder, const Value& view,
                                  const Value& pos, Value* result) {
    SetAndTypeNode(result, builder_->StringViewWtf16GetCodeUnit(
                               view.node, NullCheckFor(view.type), pos.node,
                               decoder->position()));
  }

  void StringViewWtf16Encode(FullDecoder* decoder,
                             const MemoryIndexImmediate& imm, const Value& view,
                             const Value& offset, const Value& pos,
                             const Value& codeunits, Value* result) {
    SetAndTypeNode(
        result, builder_->StringViewWtf16Encode(
                    imm.memory, view.node, NullCheckFor(view.type), offset.node,
                    pos.node, codeunits.node, decoder->position()));
  }

  void StringViewWtf16Slice(FullDecoder* decoder, const Value& view,
                            const Value& start, const Value& end,
                            Value* result) {
    SetAndTypeNode(result, builder_->StringViewWtf16Slice(
                               view.node, NullCheckFor(view.type), start.node,
                               end.node, decoder->position()));
  }

  void StringAsIter(FullDecoder* decoder, const Value& str, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringAsIter(str.node, NullCheckFor(str.type),
                                          decoder->position()));
  }

  void StringViewIterNext(FullDecoder* decoder, const Value& view,
                          Value* result) {
    SetAndTypeNode(
        result, builder_->StringViewIterNext(view.node, NullCheckFor(view.type),
                                             decoder->position()));
  }

  void StringViewIterAdvance(FullDecoder* decoder, const Value& view,
                             const Value& codepoints, Value* result) {
    SetAndTypeNode(result, builder_->StringViewIterAdvance(
                               view.node, NullCheckFor(view.type),
                               codepoints.node, decoder->position()));
  }

  void StringViewIterRewind(FullDecoder* decoder, const Value& view,
                            const Value& codepoints, Value* result) {
    SetAndTypeNode(result, builder_->StringViewIterRewind(
                               view.node, NullCheckFor(view.type),
                               codepoints.node, decoder->position()));
  }

  void StringViewIterSlice(FullDecoder* decoder, const Value& view,
                           const Value& codepoints, Value* result) {
    SetAndTypeNode(result, builder_->StringViewIterSlice(
                               view.node, NullCheckFor(view.type),
                               codepoints.node, decoder->position()));
  }

  void StringCompare(FullDecoder* decoder, const Value& lhs, const Value& rhs,
                     Value* result) {
    SetAndTypeNode(result, builder_->StringCompare(
                               lhs.node, NullCheckFor(lhs.type), rhs.node,
                               NullCheckFor(rhs.type), decoder->position()));
  }

  void StringFromCodePoint(FullDecoder* decoder, const Value& code_point,
                           Value* result) {
    SetAndTypeNode(result, builder_->StringFromCodePoint(code_point.node));
  }

  void StringHash(FullDecoder* decoder, const Value& string, Value* result) {
    SetAndTypeNode(result,
                   builder_->StringHash(string.node, NullCheckFor(string.type),
                                        decoder->position()));
  }

  void Forward(FullDecoder* decoder, const Value& from, Value* to) {
    if (from.type == to->type) {
      to->node = from.node;
    } else {
      SetAndTypeNode(to, builder_->TypeGuard(from.node, to->type));
    }
  }

  std::vector<compiler::WasmLoopInfo>& loop_infos() { return loop_infos_; }
  DanglingExceptions& dangling_exceptions() { return dangling_exceptions_; }

 private:
  LocalsAllocator locals_allocator_;
  SsaEnv* ssa_env_ = nullptr;
  compiler::WasmGraphBuilder* builder_;
  int func_index_;
  const BranchHintMap* branch_hints_ = nullptr;
  // Tracks loop data for loop unrolling.
  std::vector<compiler::WasmLoopInfo> loop_infos_;
  // When inlining, tracks exception handlers that are left dangling and must be
  // handled by the callee.
  DanglingExceptions dangling_exceptions_;
  AssumptionsJournal* assumptions_;
  InlinedStatus inlined_status_;
  // The entries in {type_feedback_} are indexed by the position of feedback-
  // consuming instructions (currently only calls).
  int feedback_instruction_index_ = 0;
  std::vector<CallSiteFeedback> type_feedback_;

  class V8_NODISCARD ScopedSsaEnv {
   public:
    ScopedSsaEnv(WasmGraphBuildingInterface* interface, SsaEnv* env,
                 SsaEnv* next_env = nullptr)
        : interface_(interface),
          next_env_(next_env ? next_env : interface->ssa_env_) {
      interface_->SetEnv(env);
    }
    ~ScopedSsaEnv() {
      interface_->ssa_env_->Kill();
      interface_->SetEnv(next_env_);
    }

   private:
    WasmGraphBuildingInterface* interface_;
    SsaEnv* next_env_;
  };

  TFNode* effect() { return builder_->effect(); }

  TFNode* control() { return builder_->control(); }

  TryInfo* current_try_info(FullDecoder* decoder) {
    DCHECK_LT(decoder->current_catch(), decoder->control_depth());
    return decoder->control_at(decoder->control_depth_of_current_catch())
        ->try_info;
  }

  // If {emit_loop_exits()} returns true, we need to emit LoopExit,
  // LoopExitEffect, and LoopExit nodes whenever a control resp. effect resp.
  // value escapes a loop. We emit loop exits in the following cases:
  // - When popping the control of a loop.
  // - At some nodes which connect to the graph's end. We do not always need to
  //   emit loop exits for such nodes, since the wasm loop analysis algorithm
  //   can handle a loop body which connects directly to the graph's end.
  //   However, we need to emit them anyway for nodes that may be rewired to
  //   different nodes during inlining. The
```