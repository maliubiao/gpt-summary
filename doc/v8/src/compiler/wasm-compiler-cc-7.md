Response:
My thinking process to answer the request about `v8/src/compiler/wasm-compiler.cc` went something like this:

1. **Understand the Core Request:** The user wants a summary of the functionality of this C++ file within the V8 JavaScript engine. Key aspects to cover include general purpose, relationships to JavaScript, code logic (with examples), potential programming errors, and a concise summary. The prompt also includes constraints like mentioning `.tq` files and indicating this is part 8 of 12.

2. **Identify the File's Role:** The file path itself, `v8/src/compiler/wasm-compiler.cc`, is highly indicative. "compiler" suggests it's involved in the compilation process. "wasm-compiler" strongly suggests it's specifically responsible for compiling WebAssembly code within V8. This becomes the central theme of the answer.

3. **Analyze the Provided Code Snippet:** The code snippet is full of calls to `gasm_->...` and `graph()->NewNode(...)`. These are hallmarks of V8's compiler infrastructure, specifically the GraphAssembler and the intermediate representation (IR) graph. Keywords like `ArrayNewFixed`, `ArraySet`, `StructGet`, `RefTest`, `StringNewWtf8`, etc., directly relate to WebAssembly features: arrays, structs, references, and strings. This confirms the initial hypothesis about the file's role.

4. **Break Down Functionality into Key Areas:**  Based on the code, I identified several distinct areas of functionality:
    * **Memory Allocation:**  Functions like `ArrayNewFixed` clearly deal with allocating memory for WebAssembly objects.
    * **Array Operations:**  A significant portion deals with creating, initializing, accessing (`ArrayGet`), and modifying (`ArraySet`) WebAssembly arrays, including bounds checking.
    * **Struct Operations:**  Similar to arrays, the code handles getting and setting fields of WebAssembly structs.
    * **Reference Types:**  Functions like `RefTest`, `RefCast`, `BrOnCast`, and `BrOnEq` are about handling WebAssembly's reference types (including casting and type checking).
    * **String Handling:**  Functions like `StringNewWtf8`, `StringMeasureUtf8`, and `StringEncodeWtf8` are dedicated to creating, measuring, and encoding WebAssembly strings.
    * **Type Checking and Guards:**  The code uses `WasmTypeCheck`, `TypeGuard`, and various `BrOn...` functions to ensure type safety.
    * **Builtin Calls:**  The frequent calls to `gasm_->CallBuiltin` indicate the use of pre-compiled, optimized V8 functions for certain operations.
    * **Control Flow:**  The `BrOnCastAbs` and other branching logic show how WebAssembly control flow constructs are translated into the compiler's IR.

5. **Address Specific Instructions:**
    * **`.tq` Files:** I know that `.tq` files in V8 are related to Torque, V8's internal language for implementing built-in functions. The code provided is C++, so it's not a Torque file.
    * **JavaScript Relationship:**  WebAssembly's primary purpose is to run alongside JavaScript. I considered scenarios where JavaScript interacts with WebAssembly features, such as creating WebAssembly instances, calling WebAssembly functions that might return or manipulate arrays and strings. I also thought about how JavaScript might receive data from WebAssembly arrays or pass strings to WebAssembly.
    * **Code Logic/Examples:** For each functional area, I tried to create simple, illustrative examples. For instance, demonstrating array creation and access in both C++ (the compiler's perspective) and equivalent JavaScript. For branching, I formulated a scenario where a WebAssembly function might return different values based on a type check.
    * **Common Programming Errors:**  I focused on errors that arise from interacting with WebAssembly features, like out-of-bounds array accesses, invalid casts, and null pointer dereferences.
    * **Concise Summary:**  I distilled the identified functionalities into a brief concluding paragraph.

6. **Structure and Refine the Answer:** I organized the information logically, starting with the file's purpose, then detailing its functionalities, addressing the specific instructions, and finally providing the summary. I used clear headings and bullet points to improve readability. I double-checked that all parts of the prompt were addressed.

7. **Consider the "Part 8 of 12" Context:**  While the provided snippet doesn't directly reveal information about the other parts, knowing it's part of a larger compilation process helps frame its significance. It's a crucial stage where WebAssembly semantics are translated into V8's internal representation.

By following this structured approach, I could generate a comprehensive and accurate answer that addressed all aspects of the user's request. The key was to leverage my understanding of V8's architecture, WebAssembly concepts, and compiler principles, combined with careful analysis of the provided code.
好的，让我们来分析一下 `v8/src/compiler/wasm-compiler.cc` 这个 V8 源代码文件的功能。

**核心功能：WebAssembly 的编译**

根据文件名和代码内容，`v8/src/compiler/wasm-compiler.cc` 的核心功能是 **将 WebAssembly 代码编译成 V8 可以执行的机器码**。  它负责将 WebAssembly 的抽象语法树（AST）转换为 V8 内部的中间表示（IR），最终生成优化的机器码。

**具体功能分解：**

从提供的代码片段中，我们可以看到它涉及以下具体的 WebAssembly 功能的编译：

1. **数组操作：**
   - `ArrayNewFixed`: 创建具有固定大小和初始元素的数组。
   - `ArrayNew`: 创建具有初始长度和可选初始值的数组。
   - `ArrayNewSegment`: 基于数据段创建数组。
   - `ArrayInitSegment`: 将数据段的内容复制到数组中。
   - `ArrayGet`: 获取数组中的元素。
   - `ArraySet`: 设置数组中的元素。
   - `ArrayLen`: 获取数组的长度。
   - `ArrayCopy`: 复制数组的一部分到另一个数组。
   - `ArrayFill`: 用指定的值填充数组。
   - `BoundsCheckArray`, `BoundsCheckArrayWithLength`: 进行数组越界检查。

2. **结构体操作：**
   - `StructGet`: 获取结构体中的字段值。
   - `StructSet`: 设置结构体中的字段值。

3. **RTT (运行时类型信息) 操作：**
   - `RttCanon`: 获取类型的规范 RTT。
   - `RefTest`: 检查对象是否是指定类型的实例。
   - `RefCast`: 将对象转换为指定类型，如果类型不匹配则抛出异常。
   - `RefCastAbstract`: 抽象的类型转换。
   - `BrOnCast`, `BrOnCastAbs`, `BrOnEq`, `BrOnStruct`, `BrOnArray`, `BrOnI31`, `BrOnString`: 基于类型检查进行条件分支。

4. **字符串操作：**
   - `StringNewWtf8`, `StringNewWtf8Array`: 从 UTF-8 编码的数据创建字符串。
   - `StringNewWtf16`, `StringNewWtf16Array`: 从 UTF-16 编码的数据创建字符串。
   - `StringConst`: 创建常量字符串。
   - `StringMeasureUtf8`, `StringMeasureWtf8`, `StringMeasureWtf16`: 测量字符串的长度。
   - `StringEncodeWtf8`, `StringEncodeWtf8Array`: 将字符串编码为 UTF-8 数据。

5. **类型守卫：**
   - `TypeGuard`: 强制指定值的类型，用于类型优化。

6. **内存操作 (间接体现)：**
   - 通过 `ArrayNewSegment`, `ArrayInitSegment`, `StringNewWtf8` 等函数可以推断出涉及对 WebAssembly 线性内存的访问。

7. **错误处理：**
   - `TrapIfTrue`, `TrapIfFalse`:  在编译时插入运行时陷阱 (trap)，用于处理错误情况，例如类型转换失败、数组越界等。

**关于 .tq 文件：**

你提到如果文件以 `.tq` 结尾，那它是个 V8 Torque 源代码。 **`v8/src/compiler/wasm-compiler.cc` 不是以 `.tq` 结尾，所以它是一个 C++ 源代码文件。**  Torque 文件通常用于定义 V8 的内置函数和类型系统。

**与 JavaScript 的关系：**

`v8/src/compiler/wasm-compiler.cc` 的工作是使得 V8 能够理解和执行 WebAssembly 代码。当 JavaScript 代码加载并实例化一个 WebAssembly 模块时，V8 会调用这个文件中的代码来编译 WebAssembly 模块中的函数。

**JavaScript 示例：**

```javascript
// 假设我们有一个名为 'module.wasm' 的 WebAssembly 文件
fetch('module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const instance = results.instance;
    // 调用 WebAssembly 导出的函数
    const result = instance.exports.add(5, 10);
    console.log(result); // 输出 WebAssembly 函数的返回值
  });
```

在这个例子中，当 `WebAssembly.instantiate(bytes)` 被调用时，V8 内部就会使用 `v8/src/compiler/wasm-compiler.cc` 中的代码来编译 `module.wasm` 中的 WebAssembly 代码，包括 `add` 函数。

**代码逻辑推理 (假设输入与输出)：**

假设有以下简单的 WebAssembly 指令要编译：

```wasm
(module
  (func (export "get_array_element") (param $array i32) (param $index i32) (result i32)
    local.get $array
    local.get $index
    i32.load_mem8_s // 从数组中加载一个 i8 类型的值并符号扩展为 i32
  )
)
```

**假设输入：**

- WebAssembly 抽象语法树 (AST) 表示了上面的代码。
- `$array` 参数对应一个表示 WebAssembly 数组的 V8 内部节点。
- `$index` 参数对应一个表示索引的 V8 内部节点。

**可能的输出 (V8 内部 IR 节点)：**

编译器可能会生成类似以下的 V8 内部 IR 节点序列：

1. **`Load` 节点:**  表示从内存中加载数据。
   - **操作类型:** `kLoad`
   - **内存地址:**  由 `$array` 节点（数组基地址）和 `$index` 节点（索引）计算得到。可能需要进行一些偏移计算和类型转换。
   - **加载大小:** 1 字节 (因为是 `i32.load_mem8_s`)。
   - **符号扩展:**  指示需要进行符号扩展。

2. **可能的边界检查节点:** 在 `Load` 节点之前，可能会有用于数组边界检查的节点 (`TrapIfFalse` 节点)，以确保 `$index` 在数组的有效范围内。

**用户常见的编程错误 (与此文件功能相关)：**

1. **WebAssembly 数组越界访问：**  在 WebAssembly 代码中访问数组时，如果索引超出数组的边界，会导致运行时错误。`v8/src/compiler/wasm-compiler.cc` 会插入边界检查，但错误的索引值仍然是 WebAssembly 代码中的逻辑错误。

   **JavaScript 示例 (模拟 WebAssembly 错误):**

   ```javascript
   const arr = new Uint8Array(10);
   console.log(arr[10]); // 访问越界，虽然 JavaScript 不会立即报错，但 WebAssembly 会
   ```

2. **类型转换错误：**  在 WebAssembly 中进行类型转换时，如果类型不兼容，会导致运行时错误。例如，尝试将一个 `i32` 类型的引用强制转换为一个 `f64` 类型的引用。

   **WebAssembly 示例 (会导致类型转换错误):**

   ```wasm
   (module
     (type $sig_i32_i32 (func (param i32) (result i32)))
     (func (export "type_error") (param $p i32) (result i32)
       local.get $p
       ref.cast (ref i64)  // 尝试将 i32 类型的引用转换为 i64 类型的引用 (假设有这样的指令)
       return
     )
   )
   ```

**归纳功能 (第 8 部分，共 12 部分):**

作为编译过程的第 8 部分，`v8/src/compiler/wasm-compiler.cc` 的主要功能是 **将 WebAssembly 的高级抽象操作（例如数组访问、结构体访问、类型转换、字符串操作等）转换为 V8 内部的、更底层的中间表示**。 它是连接 WebAssembly 前端解析和后端机器码生成的关键桥梁，确保了 WebAssembly 代码能够被 V8 正确且高效地执行。 它的工作依赖于之前阶段（例如解析和验证），并为后续的优化和代码生成阶段提供输入。

总而言之，`v8/src/compiler/wasm-compiler.cc` 是 V8 中负责 WebAssembly 代码编译的核心组件之一，它实现了将 WebAssembly 特性转化为 V8 可执行代码的关键逻辑。

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
Barrier), a,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  gasm_->ArrayInitializeLength(a, length);

  ArrayFillImpl(a, gasm_->Int32Constant(0),
                initial_value != nullptr
                    ? initial_value
                    : SetType(DefaultValue(element_type),
                              type->element_type().Unpacked()),
                length, type, false);

  return a;
}

Node* WasmGraphBuilder::ArrayNewFixed(const wasm::ArrayType* type, Node* rtt,
                                      base::Vector<Node*> elements) {
  wasm::ValueType element_type = type->element_type();
  Node* array = gasm_->Allocate(RoundUp(element_type.value_kind_size() *
                                            static_cast<int>(elements.size()),
                                        kObjectAlignment) +
                                WasmArray::kHeaderSize);
  gasm_->StoreMap(array, rtt);
  gasm_->InitializeImmutableInObject(
      ObjectAccess(MachineType::TaggedPointer(), kNoWriteBarrier), array,
      wasm::ObjectAccess::ToTagged(JSReceiver::kPropertiesOrHashOffset),
      LOAD_ROOT(EmptyFixedArray, empty_fixed_array));
  gasm_->ArrayInitializeLength(
      array, SetType(Int32Constant(static_cast<int>(elements.size())),
                     wasm::kWasmI32));
  for (int i = 0; i < static_cast<int>(elements.size()); i++) {
    gasm_->ArraySet(array, gasm_->Int32Constant(i), elements[i], type);
  }
  return array;
}

Node* WasmGraphBuilder::ArrayNewSegment(uint32_t segment_index, Node* offset,
                                        Node* length, Node* rtt,
                                        bool is_element,
                                        wasm::WasmCodePosition position) {
  // This call cannot be marked as eliminatable because it performs an array
  // maximum size check.
  Node* array = gasm_->CallBuiltin(
      Builtin::kWasmArrayNewSegment, Operator::kNoProperties,
      gasm_->Uint32Constant(segment_index), offset, length,
      gasm_->SmiConstant(is_element ? 1 : 0), gasm_->SmiConstant(0), rtt);
  SetSourcePosition(array, position);
  return array;
}

// TODO(jkummerow): This check would be more elegant if we made
// {ArrayNewSegment} a high-level node that's lowered later.
bool IsArrayNewSegment(Node* node) {
  if (node->opcode() != IrOpcode::kCall) return false;
  Node* callee = NodeProperties::GetValueInput(node, 0);
  if (callee->opcode() != IrOpcode::kNumberConstant) return false;
  double target = OpParameter<double>(callee->op());
  return target == static_cast<double>(Builtin::kWasmArrayNewSegment);
}

void WasmGraphBuilder::ArrayInitSegment(uint32_t segment_index, Node* array,
                                        Node* array_index, Node* segment_offset,
                                        Node* length, bool is_element,
                                        wasm::WasmCodePosition position) {
  gasm_->CallBuiltin(
      Builtin::kWasmArrayInitSegment, Operator::kNoProperties, array_index,
      segment_offset, length, gasm_->SmiConstant(segment_index),
      gasm_->SmiConstant(is_element ? 1 : 0), gasm_->SmiConstant(0), array);
  SetSourcePosition(control(), position);
}

Node* WasmGraphBuilder::RttCanon(wasm::ModuleTypeIndex type_index) {
  Node* rtt = graph()->NewNode(gasm_->simplified()->RttCanon(type_index),
                               GetInstanceData());
  return SetType(rtt, wasm::ValueType::Rtt(type_index));
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::TestCallbacks(
    GraphAssemblerLabel<1>* label) {
  return {// succeed_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint, Int32Constant(1));
          },
          // fail_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint, Int32Constant(0));
          },
          // fail_if_not
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIfNot(condition, label, hint, Int32Constant(0));
          }};
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::CastCallbacks(
    GraphAssemblerLabel<0>* label, wasm::WasmCodePosition position) {
  return {// succeed_if
          [this, label](Node* condition, BranchHint hint) -> void {
            gasm_->GotoIf(condition, label, hint);
          },
          // fail_if
          [this, position](Node* condition, BranchHint hint) -> void {
            TrapIfTrue(wasm::kTrapIllegalCast, condition, position);
          },
          // fail_if_not
          [this, position](Node* condition, BranchHint hint) -> void {
            TrapIfFalse(wasm::kTrapIllegalCast, condition, position);
          }};
}

WasmGraphBuilder::Callbacks WasmGraphBuilder::BranchCallbacks(
    SmallNodeVector& no_match_controls, SmallNodeVector& no_match_effects,
    SmallNodeVector& match_controls, SmallNodeVector& match_effects) {
  return {
      // succeed_if
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
        match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
      },
      // fail_if
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        no_match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
        no_match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
      },
      // fail_if_not
      [&](Node* condition, BranchHint hint) -> void {
        Node* branch = graph()->NewNode(mcgraph()->common()->Branch(hint),
                                        condition, control());
        no_match_controls.emplace_back(
            graph()->NewNode(mcgraph()->common()->IfFalse(), branch));
        no_match_effects.emplace_back(effect());
        SetControl(graph()->NewNode(mcgraph()->common()->IfTrue(), branch));
      }};
}

void WasmGraphBuilder::EqCheck(Node* object, bool object_can_be_null,
                               Callbacks callbacks, bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.succeed_if(gasm_->IsSmi(object), BranchHint::kFalse);
  Node* map = gasm_->LoadMap(object);
  callbacks.fail_if_not(gasm_->IsDataRefMap(map), BranchHint::kTrue);
}

void WasmGraphBuilder::ManagedObjectInstanceCheck(Node* object,
                                                  bool object_can_be_null,
                                                  InstanceType instance_type,
                                                  Callbacks callbacks,
                                                  bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.fail_if(gasm_->IsSmi(object), BranchHint::kFalse);
  callbacks.fail_if_not(gasm_->HasInstanceType(object, instance_type),
                        BranchHint::kTrue);
}

void WasmGraphBuilder::StringCheck(Node* object, bool object_can_be_null,
                                   Callbacks callbacks, bool null_succeeds) {
  if (object_can_be_null) {
    if (null_succeeds) {
      callbacks.succeed_if(IsNull(object, wasm::kWasmAnyRef),
                           BranchHint::kFalse);
    } else {
      // The {IsDataRefMap} check below will fail for {null} anyway.
    }
  }
  callbacks.fail_if(gasm_->IsSmi(object), BranchHint::kFalse);
  Node* map = gasm_->LoadMap(object);
  Node* instance_type = gasm_->LoadInstanceType(map);
  Node* check = gasm_->Uint32LessThan(
      instance_type, gasm_->Uint32Constant(FIRST_NONSTRING_TYPE));
  callbacks.fail_if_not(check, BranchHint::kTrue);
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnCastAbs(
    std::function<void(Callbacks)> type_checker) {
  SmallNodeVector no_match_controls, no_match_effects, match_controls,
      match_effects;
  Node *match_control, *match_effect, *no_match_control, *no_match_effect;

  type_checker(BranchCallbacks(no_match_controls, no_match_effects,
                               match_controls, match_effects));

  match_controls.emplace_back(control());
  match_effects.emplace_back(effect());

  // Wire up the control/effect nodes.
  DCHECK_EQ(match_controls.size(), match_effects.size());
  unsigned match_count = static_cast<unsigned>(match_controls.size());
  if (match_count == 1) {
    match_control = match_controls[0];
    match_effect = match_effects[0];
  } else {
    match_control = Merge(match_count, match_controls.data());
    // EffectPhis need their control dependency as an additional input.
    match_effects.emplace_back(match_control);
    match_effect = EffectPhi(match_count, match_effects.data());
  }

  DCHECK_EQ(no_match_controls.size(), no_match_effects.size());
  unsigned no_match_count = static_cast<unsigned>(no_match_controls.size());
  if (no_match_count == 1) {
    no_match_control = no_match_controls[0];
    no_match_effect = no_match_effects[0];
  } else {
    // Range is 2..4, so casting to unsigned is safe.
    no_match_control = Merge(no_match_count, no_match_controls.data());
    // EffectPhis need their control dependency as an additional input.
    no_match_effects.emplace_back(no_match_control);
    no_match_effect = EffectPhi(no_match_count, no_match_effects.data());
  }

  return {match_control, match_effect, no_match_control, no_match_effect};
}

Node* WasmGraphBuilder::RefTest(Node* object, Node* rtt,
                                WasmTypeCheckConfig config) {
  return gasm_->WasmTypeCheck(object, rtt, config);
}

Node* WasmGraphBuilder::RefTestAbstract(Node* object,
                                        WasmTypeCheckConfig config) {
  DCHECK(!config.to.has_index());
  return gasm_->WasmTypeCheckAbstract(object, config);
}

Node* WasmGraphBuilder::RefCast(Node* object, Node* rtt,
                                WasmTypeCheckConfig config,
                                wasm::WasmCodePosition position) {
  Node* cast = gasm_->WasmTypeCast(object, rtt, config);
  SetSourcePosition(cast, position);
  return cast;
}

Node* WasmGraphBuilder::RefCastAbstract(Node* object,
                                        WasmTypeCheckConfig config,
                                        wasm::WasmCodePosition position) {
  DCHECK(!config.to.has_index());
  Node* cast = gasm_->WasmTypeCastAbstract(object, config);
  SetSourcePosition(cast, position);
  return cast;
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnCast(
    Node* object, Node* rtt, WasmTypeCheckConfig config) {
  auto [true_node, false_node] =
      BranchNoHint(gasm_->WasmTypeCheck(object, rtt, config));

  return {true_node,   // control on match
          effect(),    // effect on match
          false_node,  // control on no match
          effect()};   // effect on no match
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnEq(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  return BrOnCastAbs([this, config, object](Callbacks callbacks) -> void {
    if (config.from.is_nullable()) {
      if (config.to.is_nullable()) {
        callbacks.succeed_if(gasm_->IsNull(object, config.from),
                             BranchHint::kFalse);
      } else {
        // The {IsDataRefMap} check below will fail for {null}.
      }
    }
    callbacks.succeed_if(gasm_->IsSmi(object), BranchHint::kFalse);
    Node* map = gasm_->LoadMap(object);
    callbacks.fail_if_not(gasm_->IsDataRefMap(map), BranchHint::kTrue);
  });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnStruct(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, object, config, null_succeeds](Callbacks callbacks) -> void {
        return ManagedObjectInstanceCheck(object, config.from.is_nullable(),
                                          WASM_STRUCT_TYPE, callbacks,
                                          null_succeeds);
      });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnArray(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, config, object, null_succeeds](Callbacks callbacks) -> void {
        return ManagedObjectInstanceCheck(object, config.from.is_nullable(),
                                          WASM_ARRAY_TYPE, callbacks,
                                          null_succeeds);
      });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnI31(
    Node* object, Node* /* rtt */, WasmTypeCheckConfig config) {
  return BrOnCastAbs([this, object, config](Callbacks callbacks) -> void {
    if (config.from.is_nullable()) {
      if (config.to.is_nullable()) {
        callbacks.succeed_if(gasm_->IsNull(object, config.from),
                             BranchHint::kFalse);
      } else {
        // Covered by the {IsSmi} check below.
      }
    }
    callbacks.fail_if_not(gasm_->IsSmi(object), BranchHint::kTrue);
  });
}

WasmGraphBuilder::ResultNodesOfBr WasmGraphBuilder::BrOnString(
    Node* object, Node* /*rtt*/, WasmTypeCheckConfig config) {
  bool null_succeeds = config.to.is_nullable();
  return BrOnCastAbs(
      [this, config, object, null_succeeds](Callbacks callbacks) -> void {
        return StringCheck(object, config.from.is_nullable(), callbacks,
                           null_succeeds);
      });
}

Node* WasmGraphBuilder::TypeGuard(Node* value, wasm::ValueType type) {
  DCHECK_NOT_NULL(env_);
  return SetEffect(graph()->NewNode(mcgraph()->common()->TypeGuard(Type::Wasm(
                                        type, env_->module, graph()->zone())),
                                    value, effect(), control()));
}

Node* WasmGraphBuilder::StructGet(Node* struct_object,
                                  const wasm::StructType* struct_type,
                                  uint32_t field_index, CheckForNull null_check,
                                  bool is_signed,
                                  wasm::WasmCodePosition position) {
  Node* result = gasm_->StructGet(struct_object, struct_type, field_index,
                                  is_signed, null_check);
  SetSourcePosition(result, position);
  return result;
}

void WasmGraphBuilder::StructSet(Node* struct_object,
                                 const wasm::StructType* struct_type,
                                 uint32_t field_index, Node* field_value,
                                 CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  gasm_->StructSet(struct_object, field_value, struct_type, field_index,
                   null_check);
  SetSourcePosition(effect(), position);
}

void WasmGraphBuilder::BoundsCheckArray(Node* array, Node* index,
                                        CheckForNull null_check,
                                        wasm::WasmCodePosition position) {
  if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) {
    if (null_check == kWithNullCheck) {
      AssertNotNull(array, wasm::kWasmArrayRef, position);
    }
  } else {
    Node* length = gasm_->ArrayLength(array, null_check);
    SetSourcePosition(length, position);
    TrapIfFalse(wasm::kTrapArrayOutOfBounds,
                gasm_->Uint32LessThan(index, length), position);
  }
}

void WasmGraphBuilder::BoundsCheckArrayWithLength(
    Node* array, Node* index, Node* length, CheckForNull null_check,
    wasm::WasmCodePosition position) {
  if (V8_UNLIKELY(v8_flags.experimental_wasm_skip_bounds_checks)) return;
  Node* array_length = gasm_->ArrayLength(array, null_check);
  SetSourcePosition(array_length, position);
  Node* range_end = gasm_->Int32Add(index, length);
  Node* range_valid = gasm_->Word32And(
      // OOB if (index + length > array.len).
      gasm_->Uint32LessThanOrEqual(range_end, array_length),
      // OOB if (index + length) overflows.
      gasm_->Uint32LessThanOrEqual(index, range_end));
  TrapIfFalse(wasm::kTrapArrayOutOfBounds, range_valid, position);
}

Node* WasmGraphBuilder::ArrayGet(Node* array_object,
                                 const wasm::ArrayType* type, Node* index,
                                 CheckForNull null_check, bool is_signed,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArray(array_object, index, null_check, position);
  return gasm_->ArrayGet(array_object, index, type, is_signed);
}

void WasmGraphBuilder::ArraySet(Node* array_object, const wasm::ArrayType* type,
                                Node* index, Node* value,
                                CheckForNull null_check,
                                wasm::WasmCodePosition position) {
  BoundsCheckArray(array_object, index, null_check, position);
  gasm_->ArraySet(array_object, index, value, type);
}

Node* WasmGraphBuilder::ArrayLen(Node* array_object, CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  Node* result = gasm_->ArrayLength(array_object, null_check);
  SetSourcePosition(result, position);
  return result;
}

void WasmGraphBuilder::ArrayCopy(Node* dst_array, Node* dst_index,
                                 CheckForNull dst_null_check, Node* src_array,
                                 Node* src_index, CheckForNull src_null_check,
                                 Node* length,
                                 const wasm::ArrayType* array_type,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArrayWithLength(dst_array, dst_index, length, dst_null_check,
                             position);
  BoundsCheckArrayWithLength(src_array, src_index, length, src_null_check,
                             position);

  auto end = gasm_->MakeLabel();

  gasm_->GotoIf(gasm_->Word32Equal(length, Int32Constant(0)), &end);

  auto builtin = gasm_->MakeLabel();

  // Values determined by test/mjsunit/wasm/array-copy-benchmark.js on x64.
  int array_copy_max_loop_length;
  switch (array_type->element_type().kind()) {
    case wasm::kI32:
    case wasm::kI64:
    case wasm::kI8:
    case wasm::kI16:
      array_copy_max_loop_length = 20;
      break;
    case wasm::kF16:
    case wasm::kF32:
    case wasm::kF64:
      array_copy_max_loop_length = 35;
      break;
    case wasm::kS128:
      array_copy_max_loop_length = 100;
      break;
    case wasm::kRtt:
    case wasm::kRef:
    case wasm::kRefNull:
      array_copy_max_loop_length = 15;
      break;
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }

  gasm_->GotoIf(
      gasm_->Uint32LessThan(Int32Constant(array_copy_max_loop_length), length),
      &builtin);

  auto reverse = gasm_->MakeLabel();

  gasm_->GotoIf(gasm_->Uint32LessThan(src_index, dst_index), &reverse);

  Node* src_end_index = gasm_->Int32Sub(gasm_->Int32Add(src_index, length),
                                        gasm_->Int32Constant(1));
  Node* dst_end_index = gasm_->Int32Sub(gasm_->Int32Add(dst_index, length),
                                        gasm_->Int32Constant(1));

  {
    auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32,
                                     MachineRepresentation::kWord32);

    gasm_->Goto(&loop, src_index, dst_index);
    gasm_->Bind(&loop);

    Node* value = gasm_->ArrayGet(src_array, loop.PhiAt(0), array_type, false);
    gasm_->ArraySet(dst_array, loop.PhiAt(1), value, array_type);

    Node* condition = gasm_->Uint32LessThan(loop.PhiAt(0), src_end_index);
    gasm_->GotoIfNot(condition, &end);
    gasm_->Goto(&loop, gasm_->Int32Add(loop.PhiAt(0), Int32Constant(1)),
                gasm_->Int32Add(loop.PhiAt(1), Int32Constant(1)));
  }

  {
    gasm_->Bind(&reverse);
    auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32,
                                     MachineRepresentation::kWord32);

    gasm_->Goto(&loop, src_end_index, dst_end_index);
    gasm_->Bind(&loop);

    Node* value = gasm_->ArrayGet(src_array, loop.PhiAt(0), array_type, false);
    gasm_->ArraySet(dst_array, loop.PhiAt(1), value, array_type);

    Node* condition = gasm_->Uint32LessThan(src_index, loop.PhiAt(0));
    gasm_->GotoIfNot(condition, &end);
    gasm_->Goto(&loop, gasm_->Int32Sub(loop.PhiAt(0), Int32Constant(1)),
                gasm_->Int32Sub(loop.PhiAt(1), Int32Constant(1)));
  }

  {
    gasm_->Bind(&builtin);
    Node* function =
        gasm_->ExternalConstant(ExternalReference::wasm_array_copy());
    MachineType arg_types[]{MachineType::TaggedPointer(), MachineType::Uint32(),
                            MachineType::TaggedPointer(), MachineType::Uint32(),
                            MachineType::Uint32()};
    MachineSignature sig(0, 5, arg_types);
    BuildCCall(&sig, function, dst_array, dst_index, src_array, src_index,
               length);
    gasm_->Goto(&end);
  }

  gasm_->Bind(&end);
}

Node* WasmGraphBuilder::StoreInInt64StackSlot(Node* value,
                                              wasm::ValueType type) {
  Node* value_int64;
  switch (type.kind()) {
    case wasm::kI32:
    case wasm::kI8:
    case wasm::kI16:
      value_int64 =
          graph()->NewNode(mcgraph()->machine()->ChangeInt32ToInt64(), value);
      break;
    case wasm::kI64:
      value_int64 = value;
      break;
    case wasm::kS128:
      // We can only get here if {value} is the constant 0.
      DCHECK_EQ(value->opcode(), IrOpcode::kS128Zero);
      value_int64 = Int64Constant(0);
      break;
    case wasm::kF32:
      value_int64 = graph()->NewNode(
          mcgraph()->machine()->ChangeInt32ToInt64(),
          graph()->NewNode(mcgraph()->machine()->BitcastFloat32ToInt32(),
                           value));
      break;
    case wasm::kF64:
      value_int64 = graph()->NewNode(
          mcgraph()->machine()->BitcastFloat64ToInt64(), value);
      break;
    case wasm::kRefNull:
    case wasm::kRef:
      value_int64 = kSystemPointerSize == 4
                        ? graph()->NewNode(
                              mcgraph()->machine()->ChangeInt32ToInt64(), value)
                        : value;
      break;
    case wasm::kF16:
      UNIMPLEMENTED();
    case wasm::kRtt:
    case wasm::kVoid:
    case wasm::kTop:
    case wasm::kBottom:
      UNREACHABLE();
  }

  return StoreArgsInStackSlot({{MachineRepresentation::kWord64, value_int64}});
}

void WasmGraphBuilder::ArrayFill(Node* array, Node* index, Node* value,
                                 Node* length, const wasm::ArrayType* type,
                                 CheckForNull null_check,
                                 wasm::WasmCodePosition position) {
  BoundsCheckArrayWithLength(array, index, length, null_check, position);
  ArrayFillImpl(array, index, value, length, type,
                type->element_type().is_reference());
}

void WasmGraphBuilder::ArrayFillImpl(Node* array, Node* index, Node* value,
                                     Node* length, const wasm::ArrayType* type,
                                     bool emit_write_barrier) {
  DCHECK_NOT_NULL(value);
  wasm::ValueType element_type = type->element_type();

  // Initialize the array. Use an external function for large arrays with
  // null/number initializer. Use a loop for small arrays and reference arrays
  // with a non-null initial value.
  auto done = gasm_->MakeLabel();
  // TODO(manoskouk): If the loop is ever removed here, we have to update
  // ArrayNew(), ArrayNewDefault(), and ArrayFill() in
  // graph-builder-interface.cc to not mark the current loop as non-innermost.
  auto loop = gasm_->MakeLoopLabel(MachineRepresentation::kWord32);

  // The builtin cannot handle s128 values other than 0.
  if (!(element_type == wasm::kWasmS128 &&
        value->opcode() != IrOpcode::kS128Zero)) {
    constexpr uint32_t kArrayNewMinimumSizeForMemSet = 16;
    gasm_->GotoIf(gasm_->Uint32LessThan(
                      length, Int32Constant(kArrayNewMinimumSizeForMemSet)),
                  &loop, BranchHint::kNone, index);
    Node* function =
        gasm_->ExternalConstant(ExternalReference::wasm_array_fill());

    Node* stack_slot = StoreInInt64StackSlot(value, element_type);

    MachineType arg_types[]{
        MachineType::TaggedPointer(), MachineType::Uint32(),
        MachineType::Uint32(),        MachineType::Uint32(),
        MachineType::Uint32(),        MachineType::Pointer()};
    MachineSignature sig(0, 6, arg_types);
    BuildCCall(&sig, function, array, index, length,
               Int32Constant(emit_write_barrier ? 1 : 0),
               Int32Constant(element_type.raw_bit_field()), stack_slot);
    gasm_->Goto(&done);
  } else {
    gasm_->Goto(&loop, index);
  }
  gasm_->Bind(&loop);
  {
    Node* current_index = loop.PhiAt(0);
    Node* check =
        gasm_->UintLessThan(current_index, gasm_->Int32Add(index, length));
    gasm_->GotoIfNot(check, &done);
    gasm_->ArraySet(array, current_index, value, type);
    current_index = gasm_->Int32Add(current_index, Int32Constant(1));
    gasm_->Goto(&loop, current_index);
  }
  gasm_->Bind(&done);
}

// General rules for operator properties for builtin calls:
// - Use kEliminatable if it can neither throw a catchable exception nor trap.
// - Use kNoDeopt | kNoThrow if it can trap (because in that case, eliminating
//   it would avoid the trap and thereby observably change the code's behavior
//   compared to its unoptimized version).
// - If you don't use kNoThrow (nor kEliminatable which implies it), then you
//   must also set up control nodes for the throwing case, e.g. by using
//   WasmGraphBuildingInterface::CheckForException().

Node* WasmGraphBuilder::StringNewWtf8(const wasm::WasmMemory* memory,
                                      unibrow::Utf8Variant variant,
                                      Node* offset, Node* size,
                                      wasm::WasmCodePosition position) {
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf8,
                            Operator::kNoDeopt | Operator::kNoThrow, offset,
                            size, gasm_->Int32Constant(memory->index),
                            gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringNewWtf8Array(unibrow::Utf8Variant variant,
                                           Node* array, CheckForNull null_check,
                                           Node* start, Node* end,
                                           wasm::WasmCodePosition position) {
  // Special case: shortcut a sequence "array from data segment" + "string from
  // wtf8 array" to directly create a string from the segment.
  if (IsArrayNewSegment(array)) {
    // We can only pass 3 untagged parameters to the builtin (on 32-bit
    // platforms). The segment index is easy to tag: if it validated, it must
    // be in Smi range.
    Node* segment_index = NodeProperties::GetValueInput(array, 1);
    Uint32Matcher index_matcher(segment_index);
    DCHECK(index_matcher.HasResolvedValue());
    Node* segment_index_smi = gasm_->SmiConstant(index_matcher.ResolvedValue());
    // Arbitrary choice for the second tagged parameter: the segment offset.
    Node* segment_offset = NodeProperties::GetValueInput(array, 2);
    TrapIfFalse(wasm::kTrapDataSegmentOutOfBounds,
                gasm_->Uint32LessThan(segment_offset,
                                      gasm_->Uint32Constant(Smi::kMaxValue)),
                position);
    Node* segment_offset_smi = gasm_->BuildChangeInt32ToSmi(segment_offset);
    Node* segment_length = NodeProperties::GetValueInput(array, 3);
    Node* variant_smi = gasm_->SmiConstant(static_cast<int32_t>(variant));
    return gasm_->CallBuiltin(Builtin::kWasmStringFromDataSegment,
                              Operator::Operator::kNoDeopt | Operator::kNoThrow,
                              segment_length, start, end, segment_index_smi,
                              segment_offset_smi, variant_smi);
  }

  // Regular path if the shortcut wasn't taken.
  if (null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(
      Builtin::kWasmStringNewWtf8Array, Operator::kNoDeopt | Operator::kNoThrow,
      start, end, array, gasm_->SmiConstant(static_cast<int32_t>(variant)));
}

Node* WasmGraphBuilder::StringNewWtf16(const wasm::WasmMemory* memory,
                                       Node* offset, Node* size,
                                       wasm::WasmCodePosition position) {
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf16,
                            Operator::kNoDeopt | Operator::kNoThrow,
                            gasm_->Uint32Constant(memory->index), offset, size);
}

Node* WasmGraphBuilder::StringNewWtf16Array(Node* array,
                                            CheckForNull null_check,
                                            Node* start, Node* end,
                                            wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringNewWtf16Array,
                            Operator::kNoDeopt | Operator::kNoThrow, array,
                            start, end);
}

Node* WasmGraphBuilder::StringConst(uint32_t index) {
  return gasm_->CallBuiltin(Builtin::kWasmStringConst,
                            Operator::kNoDeopt | Operator::kNoThrow,
                            gasm_->Uint32Constant(index));
}

Node* WasmGraphBuilder::StringMeasureUtf8(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringMeasureUtf8,
                            Operator::kEliminatable, string);
}

Node* WasmGraphBuilder::StringMeasureWtf8(Node* string, CheckForNull null_check,
                                          wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->CallBuiltin(Builtin::kWasmStringMeasureWtf8,
                            Operator::kEliminatable, string);
}

Node* WasmGraphBuilder::StringMeasureWtf16(Node* string,
                                           CheckForNull null_check,
                                           wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  return gasm_->LoadStringLength(string);
}

Node* WasmGraphBuilder::StringEncodeWtf8(const wasm::WasmMemory* memory,
                                         unibrow::Utf8Variant variant,
                                         Node* string, CheckForNull null_check,
                                         Node* offset,
                                         wasm::WasmCodePosition position) {
  if (null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  MemTypeToUintPtrOrOOBTrap(memory->address_type, {&offset}, position);
  return gasm_->CallBuiltin(
      Builtin::kWasmStringEncodeWtf8, Operator::kNoDeopt | Operator::kNoThrow,
      offset, gasm_->Int32Constant(memory->index),
      gasm_->Int32Constant(static_cast<int32_t>(variant)), string);
}

Node* WasmGraphBuilder::StringEncodeWtf8Array(
    unibrow::Utf8Variant variant, Node* string, CheckForNull string_null_check,
    Node* array, CheckForNull array_null_check, Node* start,
    wasm::WasmCodePosition position) {
  if (string_null_check == kWithNullCheck) {
    string = AssertNotNull(string, wasm::kWasmStringRef, position);
  }
  if (array_null_check == kWithNullCheck) {
    array = AssertNotNull(array, wasm::kWasmArrayRef, p
```