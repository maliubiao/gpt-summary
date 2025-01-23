Response: The user is asking for a summary of the C++ source code file `v8/src/wasm/graph-builder-interface.cc`, specifically the second part of it. The prompt also indicates that the first part has already been provided. I need to identify the functionalities implemented in this second part and relate them to JavaScript where applicable.

**Plan:**

1. **Identify the primary class/structure:** The code snippet is part of the `WasmGraphBuildingInterface` class.
2. **Analyze the methods:** Go through each method defined in this part of the file and understand its purpose. Focus on what operations it performs in the context of building a graph for WebAssembly.
3. **Look for connections to JavaScript:** Identify any methods that directly correspond to or facilitate interactions with JavaScript functionality.
4. **Provide JavaScript examples:** For the identified connections, create illustrative JavaScript code snippets to demonstrate the relationship.
5. **Synthesize a summary:** Combine the analysis into a concise description of the file's functionality.
这个C++源代码文件（`v8/src/wasm/graph-builder-interface.cc`的第二部分）定义了 `WasmGraphBuildingInterface` 类的一部分。这个接口是 WebAssembly 代码解码器 (`FullDecoder`) 和 TurboFan 图构建器 (`WasmGraphBuilder`) 之间的桥梁。它提供了一系列方法，让解码器能够指示图构建器创建表示各种 WebAssembly 操作的节点。

具体来说，这部分代码主要负责处理以下 WebAssembly 的**引用类型 (Reference Types)** 和 **字符串 (String Types)** 相关的操作：

**引用类型操作:**

* **`RefI31`**:  创建一个 `i31ref` 类型的值，它是一个包含两个有符号 31 位整数的引用。
* **`I31GetS` 和 `I31GetU`**: 从 `i31ref` 中提取有符号或无符号的 31 位整数。
* **`RefTest` 和 `RefTestAbstract`**:  检查一个引用是否是指定类型或抽象类型的实例。
* **`RefCast` 和 `RefCastAbstract`**: 将一个引用转换为指定的类型或抽象类型。如果转换失败，则会抛出异常。
* **`BrOnCast`，`BrOnCastFail`，`BrOnCastAbstract`，`BrOnCastFailAbstract`**:  带有类型转换的条件分支指令。如果类型转换成功/失败，则跳转到指定的分支目标。这些方法涵盖了各种具体的引用类型（如 `eqref`, `i31ref`, `structref`, `arrayref`, `stringref`）以及抽象类型。
* **`BrOnEq`，`BrOnNonEq`，`BrOnStruct`，`BrOnNonStruct`，`BrOnArray`，`BrOnNonArray`，`BrOnI31`，`BrOnNonI31`，`BrOnString`，`BrOnNonString`**:  基于引用类型的条件分支指令，用于判断引用的具体类型。

**字符串类型操作:**

* **`StringNewWtf8` 和 `StringNewWtf8Array`**:  从 UTF-8 编码的内存或数组中创建字符串。
* **`StringNewWtf16` 和 `StringNewWtf16Array`**: 从 UTF-16 编码的内存或数组中创建字符串。
* **`StringConst`**:  创建一个常量字符串。
* **`StringMeasureWtf8` 和 `StringMeasureWtf16`**:  测量 UTF-8 或 UTF-16 字符串的长度（以字节或代码单元计）。
* **`StringEncodeWtf8` 和 `StringEncodeWtf8Array`**: 将字符串编码为 UTF-8 并写入内存或数组。
* **`StringEncodeWtf16` 和 `StringEncodeWtf16Array`**: 将字符串编码为 UTF-16 并写入内存或数组。
* **`StringConcat`**: 连接两个字符串。
* **`StringEq`**:  比较两个字符串是否相等。
* **`StringIsUSVSequence`**: 检查字符串是否是 USV 序列 (Unicode Scalar Value)。
* **`StringAsWtf8` 和 `StringAsWtf16`**: 将字符串转换为 UTF-8 或 UTF-16 视图。
* **字符串视图 (String View) 相关操作 (`StringViewWtf8Advance`, `StringViewWtf8Encode`, `StringViewWtf8Slice`, `StringViewWtf16GetCodeUnit`, `StringViewWtf16Encode`, `StringViewWtf16Slice`):**  用于操作字符串的视图，允许高效地访问和处理字符串的部分内容。
* **字符串迭代器 (String Iterator) 相关操作 (`StringAsIter`, `StringViewIterNext`, `StringViewIterAdvance`, `StringViewIterRewind`, `StringViewIterSlice`):**  用于迭代字符串中的代码点。
* **`StringCompare`**: 比较两个字符串的大小。
* **`StringFromCodePoint`**: 从 Unicode 代码点创建字符串。
* **`StringHash`**: 计算字符串的哈希值。

**其他辅助方法:**

* **`Forward`**: 将一个值从一个位置传递到另一个位置，并在必要时插入类型保护节点。
* **`loop_infos()` 和 `dangling_exceptions()`**: 提供对循环信息和悬挂异常信息的访问。
* **`ScopedSsaEnv`**: 一个辅助类，用于管理 SSA 环境的生命周期。
* **`SetEnv`**: 设置当前的 SSA 环境。
* **`CheckForException`**:  检查操作是否可能抛出异常，并根据情况处理异常控制流。
* **`MergeValuesInto` 和 `Goto`**: 用于合并控制流和 SSA 状态。
* **`Split` 和 `Steal`**: 用于创建 SSA 环境的副本。
* **`CallInfo`**:  一个辅助类，用于封装函数调用的信息。
* **`DoCall` 和 `DoReturnCall`**:  执行函数调用和尾调用。
* **`BuildLoopExits` 和 `WrapLocalsAtLoopExit`**:  处理循环的退出。
* **`BuildNestedLoopExits`**: 处理嵌套循环的退出。
* **`NullCheckFor`**:  根据值类型确定是否需要进行空值检查。
* **`SetAndTypeNode`**:  设置值节点的类型。
* **`FindFirstUsedMemoryIndex`**: 尝试找到函数中第一个被使用的内存索引。
* **`ThrowRef`**: 抛出一个引用类型的异常。

**与 JavaScript 的关系及示例:**

这些 C++ 代码最终会被编译成 V8 引擎的一部分，用于执行 WebAssembly 代码。  许多这里定义的操作对应着 WebAssembly 规范中的指令，而这些指令可以通过 JavaScript 来调用和操作。

**引用类型的例子:**

```javascript
// 假设有一个 WebAssembly 模块导出了一个接受 i31ref 并返回其第一个元素的函数
const wasmInstance = // ... 加载和实例化 WebAssembly 模块 ...
const getFirstI31 = wasmInstance.exports.getFirstI31;

// 在 JavaScript 中创建一个 i31ref (这通常需要 WebAssembly 的辅助函数或特定的 API)
const i31RefValue = // ... 创建 i31ref 的逻辑 ...

// 调用 WebAssembly 函数
const firstValue = getFirstI31(i31RefValue);

console.log(firstValue);
```

**字符串类型的例子:**

```javascript
// 假设有一个 WebAssembly 模块导出了一个接受字符串并返回其长度的函数
const wasmInstance = // ... 加载和实例化 WebAssembly 模块 ...
const getStringLength = wasmInstance.exports.getStringLength;

const jsString = "Hello, WebAssembly!";

// 将 JavaScript 字符串传递给 WebAssembly (可能需要编码成 WebAssembly 的字符串表示)
// 具体如何传递取决于 WebAssembly 模块的接口定义
const wasmString = // ... 将 jsString 转换为 WebAssembly 可用的字符串 ...

const length = getStringLength(wasmString);
console.log(`字符串长度: ${length}`);

// 假设 WebAssembly 模块导出了一个创建字符串的函数
const createWasmString = wasmInstance.exports.createString;
const newWasmString = createWasmString("A new string from WebAssembly");

// 假设 WebAssembly 模块导出了一个返回字符串内容的函数
const getStringContent = wasmInstance.exports.getStringContent;
const content = getStringContent(newWasmString);
console.log(content); // 输出可能需要将 WebAssembly 的字符串表示转换回 JavaScript 字符串
```

**总结:**

这部分 `graph-builder-interface.cc` 文件定义了用于在 TurboFan 编译器中构建 WebAssembly 引用类型和字符串类型操作图的接口。它通过提供一系列方法，使得 WebAssembly 解码器能够有效地将 WebAssembly 指令转换为 TurboFan 图节点。这些操作直接对应于 WebAssembly 规范中的特性，并且在 JavaScript 中执行 WebAssembly 代码时会被间接地使用。JavaScript 代码通过 WebAssembly 的 API 与这些底层操作进行交互。

### 提示词
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
  //   different nodes during inlining. These are Return and TailCall nodes.
  // - After IfFailure nodes.
  // - When exiting a loop through Delegate.
  bool emit_loop_exits() {
    return v8_flags.wasm_loop_unrolling || v8_flags.wasm_loop_peeling;
  }

  void GetNodes(TFNode** nodes, const Value* values, size_t count) {
    for (size_t i = 0; i < count; ++i) {
      nodes[i] = values[i].node;
    }
  }

  void GetNodes(TFNode** nodes, base::Vector<const Value> values) {
    GetNodes(nodes, values.begin(), values.size());
  }

  void SetEnv(SsaEnv* env) {
    if (v8_flags.trace_wasm_decoder) {
      char state = 'X';
      if (env) {
        switch (env->state) {
          case SsaEnv::kReached:
            state = 'R';
            break;
          case SsaEnv::kUnreachable:
            state = 'U';
            break;
          case SsaEnv::kMerged:
            state = 'M';
            break;
        }
      }
      PrintF("{set_env = %p, state = %c", env, state);
      if (env && env->control) {
        PrintF(", control = ");
        compiler::WasmGraphBuilder::PrintDebugName(env->control);
      }
      PrintF("}\n");
    }
    if (ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    ssa_env_ = env;
    builder_->SetEffectControl(env->effect, env->control);
    builder_->set_instance_cache(&env->instance_cache);
  }

  TFNode* CheckForException(FullDecoder* decoder, TFNode* node,
                            bool may_modify_instance_cache) {
    DCHECK_NOT_NULL(node);

    // We need to emit IfSuccess/IfException nodes if this node throws and has
    // an exception handler. An exception handler can either be a try-scope
    // around this node, or if this function is being inlined, the IfException
    // output of the inlined Call node.
    const bool inside_try_scope = decoder->current_catch() != -1;
    if (inlined_status_ != kInlinedHandledCall && !inside_try_scope) {
      return node;
    }

    TFNode* if_success = nullptr;
    TFNode* if_exception = nullptr;
    if (!builder_->ThrowsException(node, &if_success, &if_exception)) {
      return node;
    }

    // TODO(choongwoo): Clear locals of `success_env` after use.
    SsaEnv* success_env = Steal(decoder->zone(), ssa_env_);
    success_env->control = if_success;

    SsaEnv* exception_env = Split(decoder->zone(), success_env);
    exception_env->control = if_exception;
    exception_env->effect = if_exception;

    ScopedSsaEnv scoped_env(this, exception_env, success_env);

    // The exceptional operation could have modified memory size; we need to
    // reload the memory context into the exceptional control path.
    if (may_modify_instance_cache) {
      ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);
    }

    if (emit_loop_exits()) {
      ValueVector values;
      BuildNestedLoopExits(decoder,
                           inside_try_scope
                               ? decoder->control_depth_of_current_catch()
                               : decoder->control_depth() - 1,
                           true, values, &if_exception);
    }
    if (inside_try_scope) {
      TryInfo* try_info = current_try_info(decoder);
      Goto(decoder, try_info->catch_env);
      if (try_info->exception == nullptr) {
        DCHECK_EQ(SsaEnv::kReached, try_info->catch_env->state);
        try_info->exception = if_exception;
      } else {
        DCHECK_EQ(SsaEnv::kMerged, try_info->catch_env->state);
        try_info->exception = builder_->CreateOrMergeIntoPhi(
            MachineRepresentation::kTaggedPointer, try_info->catch_env->control,
            try_info->exception, if_exception);
      }
    } else {
      DCHECK_EQ(inlined_status_, kInlinedHandledCall);
      // We leave the IfException/LoopExit node dangling, and record the
      // exception/effect/control here. We will connect them to the handler of
      // the inlined call during inlining.
      // Note: We have to generate the handler now since we have no way of
      // generating a LoopExit if needed in the inlining code.
      dangling_exceptions_.Add(if_exception, effect(), control());
    }
    return node;
  }

  void MergeValuesInto(FullDecoder* decoder, Control* c, Merge<Value>* merge,
                       Value* values) {
    DCHECK(merge == &c->start_merge || merge == &c->end_merge);

    SsaEnv* target = c->merge_env;
    // This has to be computed before calling Goto().
    const bool first = target->state == SsaEnv::kUnreachable;

    Goto(decoder, target);

    if (merge->arity == 0) return;

    for (uint32_t i = 0; i < merge->arity; ++i) {
      Value& val = values[i];
      Value& old = (*merge)[i];
      DCHECK_NOT_NULL(val.node);
      DCHECK(val.type == kWasmBottom || val.type.machine_representation() ==
                                            old.type.machine_representation());
      old.node = first ? val.node
                       : builder_->CreateOrMergeIntoPhi(
                             old.type.machine_representation(), target->control,
                             old.node, val.node);
    }
  }

  void MergeValuesInto(FullDecoder* decoder, Control* c, Merge<Value>* merge,
                       uint32_t drop_values = 0) {
#ifdef DEBUG
    uint32_t avail = decoder->stack_size() -
                     decoder->control_at(0)->stack_depth - drop_values;
    DCHECK_GE(avail, merge->arity);
#endif
    Value* stack_values = merge->arity > 0
                              ? decoder->stack_value(merge->arity + drop_values)
                              : nullptr;
    MergeValuesInto(decoder, c, merge, stack_values);
  }

  void Goto(FullDecoder* decoder, SsaEnv* to) {
    DCHECK_NOT_NULL(to);
    switch (to->state) {
      case SsaEnv::kUnreachable: {  // Overwrite destination.
        to->state = SsaEnv::kReached;
        DCHECK_EQ(ssa_env_->locals.size(), decoder->num_locals());
        to->locals = ssa_env_->locals;
        to->control = control();
        to->effect = effect();
        to->instance_cache = ssa_env_->instance_cache;
        break;
      }
      case SsaEnv::kReached: {  // Create a new merge.
        to->state = SsaEnv::kMerged;
        // Merge control.
        TFNode* controls[] = {to->control, control()};
        TFNode* merge = builder_->Merge(2, controls);
        to->control = merge;
        // Merge effects.
        TFNode* old_effect = effect();
        if (old_effect != to->effect) {
          TFNode* inputs[] = {to->effect, old_effect, merge};
          to->effect = builder_->EffectPhi(2, inputs);
        }
        // Merge locals.
        DCHECK_EQ(ssa_env_->locals.size(), decoder->num_locals());
        for (uint32_t i = 0; i < to->locals.size(); i++) {
          TFNode* a = to->locals[i];
          TFNode* b = ssa_env_->locals[i];
          if (a != b) {
            TFNode* inputs[] = {a, b, merge};
            to->locals[i] = builder_->Phi(decoder->local_type(i), 2, inputs);
          }
        }
        // Start a new merge from the instance cache.
        builder_->NewInstanceCacheMerge(&to->instance_cache,
                                        &ssa_env_->instance_cache, merge);
        break;
      }
      case SsaEnv::kMerged: {
        TFNode* merge = to->control;
        // Extend the existing merge control node.
        builder_->AppendToMerge(merge, control());
        // Merge effects.
        to->effect =
            builder_->CreateOrMergeIntoEffectPhi(merge, to->effect, effect());
        // Merge locals.
        for (uint32_t i = 0; i < to->locals.size(); i++) {
          to->locals[i] = builder_->CreateOrMergeIntoPhi(
              decoder->local_type(i).machine_representation(), merge,
              to->locals[i], ssa_env_->locals[i]);
        }
        // Merge the instance caches.
        builder_->MergeInstanceCacheInto(&to->instance_cache,
                                         &ssa_env_->instance_cache, merge);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  // Create a complete copy of {from}.
  SsaEnv* Split(Zone* zone, SsaEnv* from) {
    DCHECK_NOT_NULL(from);
    if (from == ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    SsaEnv* result = zone->New<SsaEnv>(*from);
    result->state = SsaEnv::kReached;
    return result;
  }

  // Create a copy of {from} that steals its state and leaves {from}
  // unreachable.
  SsaEnv* Steal(Zone* zone, SsaEnv* from) {
    DCHECK_NOT_NULL(from);
    if (from == ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    SsaEnv* result = zone->New<SsaEnv>(std::move(*from));
    result->state = SsaEnv::kReached;
    return result;
  }

  class CallInfo {
   public:
    enum CallMode { kCallDirect, kCallIndirect, kCallRef };

    static CallInfo CallDirect(uint32_t callee_index, int call_count) {
      return {kCallDirect, callee_index, nullptr,
              static_cast<uint32_t>(call_count),
              CheckForNull::kWithoutNullCheck};
    }

    static CallInfo CallIndirect(const Value& index_value, uint32_t table_index,
                                 ModuleTypeIndex sig_index) {
      return {kCallIndirect, sig_index.index, &index_value, table_index,
              CheckForNull::kWithoutNullCheck};
    }

    static CallInfo CallRef(const Value& funcref_value,
                            CheckForNull null_check) {
      return {kCallRef, 0, &funcref_value, 0, null_check};
    }

    CallMode call_mode() { return call_mode_; }

    ModuleTypeIndex sig_index() {
      DCHECK_EQ(call_mode_, kCallIndirect);
      return ModuleTypeIndex{callee_or_sig_index_};
    }

    uint32_t callee_index() {
      DCHECK_EQ(call_mode_, kCallDirect);
      return callee_or_sig_index_;
    }

    int call_count() {
      DCHECK_EQ(call_mode_, kCallDirect);
      return static_cast<int>(table_index_or_call_count_);
    }

    CheckForNull null_check() {
      DCHECK_EQ(call_mode_, kCallRef);
      return null_check_;
    }

    const Value* index_or_callee_value() {
      DCHECK_NE(call_mode_, kCallDirect);
      return index_or_callee_value_;
    }

    uint32_t table_index() {
      DCHECK_EQ(call_mode_, kCallIndirect);
      return table_index_or_call_count_;
    }

   private:
    CallInfo(CallMode call_mode, uint32_t callee_or_sig_index,
             const Value* index_or_callee_value,
             uint32_t table_index_or_call_count, CheckForNull null_check)
        : call_mode_(call_mode),
          callee_or_sig_index_(callee_or_sig_index),
          index_or_callee_value_(index_or_callee_value),
          table_index_or_call_count_(table_index_or_call_count),
          null_check_(null_check) {}
    CallMode call_mode_;
    uint32_t callee_or_sig_index_;
    const Value* index_or_callee_value_;
    uint32_t table_index_or_call_count_;
    CheckForNull null_check_;
  };

  void DoCall(FullDecoder* decoder, CallInfo call_info, const FunctionSig* sig,
              const Value args[], Value returns[]) {
    size_t param_count = sig->parameter_count();
    size_t return_count = sig->return_count();
    NodeVector arg_nodes(param_count + 1);
    base::SmallVector<TFNode*, 1> return_nodes(return_count);
    arg_nodes[0] = (call_info.call_mode() == CallInfo::kCallDirect)
                       ? nullptr
                       : call_info.index_or_callee_value()->node;

    for (size_t i = 0; i < param_count; ++i) {
      arg_nodes[i + 1] = args[i].node;
    }
    switch (call_info.call_mode()) {
      case CallInfo::kCallIndirect: {
        TFNode* call = builder_->CallIndirect(
            call_info.table_index(), call_info.sig_index(),
            base::VectorOf(arg_nodes), base::VectorOf(return_nodes),
            decoder->position());
        CheckForException(decoder, call, true);
        break;
      }
      case CallInfo::kCallDirect: {
        TFNode* call = builder_->CallDirect(
            call_info.callee_index(), base::VectorOf(arg_nodes),
            base::VectorOf(return_nodes), decoder->position());
        builder_->StoreCallCount(call, call_info.call_count());
        CheckForException(decoder, call, true);
        break;
      }
      case CallInfo::kCallRef: {
        TFNode* call = builder_->CallRef(
            sig, base::VectorOf(arg_nodes), base::VectorOf(return_nodes),
            call_info.null_check(), decoder->position());
        CheckForException(decoder, call, true);
        break;
      }
    }
    for (size_t i = 0; i < return_count; ++i) {
      SetAndTypeNode(&returns[i], return_nodes[i]);
    }
    // The invoked function could have used grow_memory, so we need to
    // reload memory information.
    ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);
  }

  void DoReturnCall(FullDecoder* decoder, CallInfo call_info,
                    const FunctionSig* sig, const Value args[]) {
    size_t arg_count = sig->parameter_count();

    ValueVector arg_values(arg_count + 1);
    if (call_info.call_mode() == CallInfo::kCallDirect) {
      arg_values[0].node = nullptr;
    } else {
      arg_values[0] = *call_info.index_or_callee_value();
      // This is not done by copy assignment.
      arg_values[0].node = call_info.index_or_callee_value()->node;
    }
    if (arg_count > 0) {
      std::memcpy(arg_values.data() + 1, args, arg_count * sizeof(Value));
    }

    if (emit_loop_exits()) {
      BuildNestedLoopExits(decoder, decoder->control_depth(), false,
                           arg_values);
    }

    NodeVector arg_nodes(arg_count + 1);
    GetNodes(arg_nodes.data(), base::VectorOf(arg_values));

    switch (call_info.call_mode()) {
      case CallInfo::kCallIndirect:
        builder_->ReturnCallIndirect(
            call_info.table_index(), call_info.sig_index(),
            base::VectorOf(arg_nodes), decoder->position());
        break;
      case CallInfo::kCallDirect: {
        TFNode* call = builder_->ReturnCall(call_info.callee_index(),
                                            base::VectorOf(arg_nodes),
                                            decoder->position());
        builder_->StoreCallCount(call, call_info.call_count());
        break;
      }
      case CallInfo::kCallRef:
        builder_->ReturnCallRef(sig, base::VectorOf(arg_nodes),
                                call_info.null_check(), decoder->position());
        break;
    }
  }

  const CallSiteFeedback& next_call_feedback() {
    DCHECK_LT(feedback_instruction_index_, type_feedback_.size());
    return type_feedback_[feedback_instruction_index_++];
  }

  void BuildLoopExits(FullDecoder* decoder, Control* loop) {
    builder_->LoopExit(loop->loop_node);
    ssa_env_->control = control();
    ssa_env_->effect = effect();
  }

  void WrapLocalsAtLoopExit(FullDecoder* decoder, Control* loop) {
    for (uint32_t index = 0; index < decoder->num_locals(); index++) {
      if (loop->loop_assignments->Contains(static_cast<int>(index))) {
        ssa_env_->locals[index] = builder_->LoopExitValue(
            ssa_env_->locals[index],
            decoder->local_type(index).machine_representation());
      }
    }
    if (loop->loop_assignments->Contains(decoder->num_locals())) {
      for (auto field : compiler::WasmInstanceCacheNodes::kFields) {
        if (ssa_env_->instance_cache.*field == nullptr) continue;
        ssa_env_->instance_cache.*field =
            builder_->LoopExitValue(ssa_env_->instance_cache.*field,
                                    MachineType::PointerRepresentation());
      }
    }
  }

  void BuildNestedLoopExits(FullDecoder* decoder, uint32_t depth_limit,
                            bool wrap_exit_values, ValueVector& stack_values,
                            TFNode** exception_value = nullptr) {
    DCHECK(emit_loop_exits());
    Control* control = nullptr;
    // We are only interested in exits from the innermost loop.
    for (uint32_t i = 0; i < depth_limit; i++) {
      Control* c = decoder->control_at(i);
      if (c->is_loop()) {
        control = c;
        break;
      }
    }
    if (control != nullptr && control->loop_innermost) {
      BuildLoopExits(decoder, control);
      for (Value& value : stack_values) {
        if (value.node != nullptr) {
          value.node = builder_->SetType(
              builder_->LoopExitValue(value.node,
                                      value.type.machine_representation()),
              value.type);
        }
      }
      if (exception_value != nullptr) {
        *exception_value = builder_->LoopExitValue(
            *exception_value, MachineRepresentation::kTaggedPointer);
      }
      if (wrap_exit_values) {
        WrapLocalsAtLoopExit(decoder, control);
      }
    }
  }

  CheckForNull NullCheckFor(ValueType type) {
    DCHECK(type.is_object_reference());
    return type.is_nullable() ? CheckForNull::kWithNullCheck
                              : CheckForNull::kWithoutNullCheck;
  }

  void SetAndTypeNode(Value* value, TFNode* node) {
    // This DCHECK will help us catch uninitialized values.
    DCHECK_LT(value->type.kind(), kBottom);
    value->node = builder_->SetType(node, value->type);
  }

  // In order to determine the memory index to cache in an SSA value, we try to
  // determine the first memory index that will be accessed in the function. If
  // we do not find a memory access this method returns -1.
  // This is a best-effort implementation: It ignores potential control flow and
  // only looks for basic memory load and store operations.
  int FindFirstUsedMemoryIndex(base::Vector<const uint8_t> body, Zone* zone) {
    BodyLocalDecls locals;
    for (BytecodeIterator it{body.begin(), body.end(), &locals, zone};
         it.has_next(); it.next()) {
      WasmOpcode opcode = it.current();
      constexpr bool kConservativelyAssumeMemory64 = true;
      switch (opcode) {
        default:
          break;
#define CASE(name, ...) case kExpr##name:
          FOREACH_LOAD_MEM_OPCODE(CASE)
          FOREACH_STORE_MEM_OPCODE(CASE)
#undef CASE
          MemoryAccessImmediate imm(&it, it.pc() + 1, UINT32_MAX,
                                    kConservativelyAssumeMemory64,
                                    Decoder::kNoValidation);
          return imm.mem_index;
      }
    }
    return -1;
  }

  void ThrowRef(FullDecoder* decoder, TFNode* exception) {
    DCHECK_NOT_NULL(exception);
    CheckForException(decoder, builder_->ThrowRef(exception), false);
    builder_->TerminateThrow(effect(), control());
  }
};

}  // namespace

void BuildTFGraph(AccountingAllocator* allocator, WasmEnabledFeatures enabled,
                  const WasmModule* module, compiler::WasmGraphBuilder* builder,
                  WasmDetectedFeatures* detected, const FunctionBody& body,
                  std::vector<compiler::WasmLoopInfo>* loop_infos,
                  DanglingExceptions* dangling_exceptions,
                  compiler::NodeOriginTable* node_origins, int func_index,
                  AssumptionsJournal* assumptions,
                  InlinedStatus inlined_status) {
  Zone zone(allocator, ZONE_NAME);
  WasmFullDecoder<Decoder::NoValidationTag, WasmGraphBuildingInterface> decoder(
      &zone, module, enabled, detected, body, builder, func_index, assumptions,
      inlined_status, &zone);
  if (node_origins) {
    builder->AddBytecodePositionDecorator(node_origins, &decoder);
  }
  decoder.Decode();
  if (node_origins) {
    builder->RemoveBytecodePositionDecorator();
  }
  *loop_infos = std::move(decoder.interface().loop_infos());
  if (dangling_exceptions != nullptr) {
    *dangling_exceptions = std::move(decoder.interface().dangling_exceptions());
  }
  // TurboFan does not run with validation, so graph building must always
  // succeed.
  CHECK(decoder.ok());
}

}  // namespace v8::internal::wasm
```