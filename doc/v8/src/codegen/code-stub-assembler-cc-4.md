Response:
My thinking process to analyze the provided V8 code snippet went something like this:

1. **Identify the Core Functionality:** The code is part of `v8/src/codegen/code-stub-assembler.cc`. The name "CodeStubAssembler" immediately suggests it's a low-level code generation tool within V8. The methods inside are manipulating V8's internal object representation (maps, functions, arrays, etc.) and generating low-level instructions or manipulating existing code structures.

2. **Break Down into Functional Groups:**  I started categorizing the methods based on their names and what they appear to be doing. Common themes emerged:
    * **Loading Object Properties:**  Methods like `LoadSlowObjectWithNullPrototypeMap`, `LoadJSArrayElementsMap`, `LoadFunctionKind`, `LoadJSFunctionPrototype`, etc., are clearly focused on retrieving specific fields or metadata from V8 objects.
    * **Checking Object Properties/States:**  Functions like `IsGeneratorFunction`, `IsJSFunctionWithPrototypeSlot`, `SharedFunctionInfoHasBaselineCode` perform boolean checks based on object state.
    * **Conditional Control Flow:** Methods like `BranchIfHasPrototypeProperty`, `GotoIfPrototypeRequiresRuntimeLookup` indicate the code is branching based on object properties.
    * **Loading Code Objects:** `LoadJSFunctionCode`, `LoadSharedFunctionInfoBytecodeArray` are fetching executable code related to functions.
    * **Storing Object Properties:**  A large group of `Store...` methods are responsible for writing data back into V8 objects. The variations (e.g., `NoWriteBarrier`, `Unsafe`) hint at different levels of write barrier handling for performance optimization.
    * **Array Manipulation:** Methods like `EnsureArrayPushable`, `PossiblyGrowElementsCapacity`, `BuildAppendJSArray`, `TryStoreArrayElement` deal with dynamically sizing and adding elements to JavaScript arrays.
    * **Object Allocation:**  `AllocateCellWithValue`, `AllocateHeapNumber`, `AllocateBigInt`, `AllocateByteArray` are involved in creating new V8 objects.
    * **Helper Functions:** Some functions like `CloneIfMutablePrimitive` perform specific utility tasks.

3. **Infer Purpose from Method Names and Signatures:** I paid close attention to the naming conventions and parameter types. For instance, methods taking `TNode<JSFunction>` clearly operate on JavaScript function objects. Methods with `TNode<Map>` deal with object maps. The `TNode` prefix suggests these are nodes within the assembler's internal representation.

4. **Look for Direct JavaScript Relevance:**  Several methods have direct counterparts in JavaScript behavior. Array manipulation methods clearly relate to `Array.prototype.push`. The prototype checks relate to how JavaScript inheritance works. The function kind checks relate to different types of JavaScript functions (regular, generator, async).

5. **Identify Potential Torque (.tq) Relationship:** The prompt explicitly mentioned `.tq` files. Given the low-level nature of the code, it's highly likely this `.cc` file is *generated* from a higher-level `.tq` file (Torque). Torque is V8's DSL for writing performance-critical code. This part of the prompt helps confirm the low-level interpretation.

6. **Consider Error Scenarios:** The prompt asked about common programming errors. The code's focus on object layout and memory management suggests potential errors related to type mismatches, accessing non-existent properties, or incorrect assumptions about object structure. The `bailout` labels and checks indicate error handling within the generated code.

7. **Hypothesize Inputs and Outputs (Code Logic Reasoning):**  For simple functions, I tried to imagine what input values would lead to specific outputs. For example, `IsGeneratorFunction` would return `true` if the input `JSFunction` was indeed a generator function. `LoadJSArrayElementsMap` takes an `ElementsKind` and would return the appropriate map for that array type.

8. **Synthesize and Summarize:**  Finally, I combined my observations into a concise summary, highlighting the core functionalities, the likely relationship to Torque, connections to JavaScript, potential error scenarios, and the overall role of the code within V8's code generation pipeline. I also structured the answer into the requested format (features, Torque relationship, JavaScript examples, input/output, common errors, and a summary).

Essentially, my process was a combination of code reading, pattern recognition, leveraging my understanding of JavaScript and compiler concepts, and paying close attention to the hints provided in the prompt. The iterative nature of examining individual methods and then grouping them into higher-level functionalities was key to understanding the overall purpose of the code.
好的，让我们来分析一下提供的 V8 源代码片段 `v8/src/codegen/code-stub-assembler.cc` 的功能。

**功能列举:**

这段代码是 V8 引擎中 `CodeStubAssembler` 类的一部分，它提供了用于在编译时生成机器码的低级接口。其主要功能可以归纳为以下几点：

1. **加载 V8 内部对象属性:**
   - `LoadSlowObjectWithNullPrototypeMap`: 加载具有 `null` 原型的慢速对象的 Map。
   - `LoadJSArrayElementsMap`: 加载不同类型的 JavaScript 数组元素的 Map (例如，Packed, Holey 等)。
   - `LoadFunctionKind`:  从 `JSFunction` 对象中加载函数类型信息。
   - `LoadJSFunctionPrototype`: 加载 `JSFunction` 的原型对象。
   - `LoadJSFunctionCode`: 加载 `JSFunction` 关联的代码对象。
   - `LoadSharedFunctionInfoTrustedData`/`LoadSharedFunctionInfoUntrustedData`: 加载 `SharedFunctionInfo` 中存储的受信任和不受信任的数据。
   - `LoadSharedFunctionInfoBytecodeArray`: 加载 `SharedFunctionInfo` 关联的字节码数组。
   - `LoadBytecodeArrayParameterCount`: 加载字节码数组的参数数量。
   - `LoadCellValue`: 加载 Cell 对象中存储的值。
   - `LoadHeapNumberValue`: 加载 HeapNumber 对象中存储的数值。
   - `LoadBigIntBitfield`/`LoadBigIntDigit`: 加载 BigInt 对象的内部数据。

2. **检查 V8 内部对象状态:**
   - `IsGeneratorFunction`: 检查一个 `JSFunction` 是否为生成器函数。
   - `IsJSFunctionWithPrototypeSlot`: 检查一个对象是否是具有原型槽的 `JSFunction`。
   - `SharedFunctionInfoHasBaselineCode`: 检查 `SharedFunctionInfo` 是否具有基线代码。

3. **基于对象状态进行分支控制:**
   - `BranchIfHasPrototypeProperty`: 根据函数是否具有原型属性进行条件跳转。
   - `GotoIfPrototypeRequiresRuntimeLookup`: 如果需要运行时查找原型则跳转。

4. **存储 V8 内部对象属性:**
   - `StoreObjectByteNoWriteBarrier`:  存储对象的字节，不使用写屏障。
   - `StoreHeapNumberValue`: 存储 HeapNumber 对象的数值。
   - `StoreObjectField`: 存储对象的字段 (支持写屏障和无写屏障版本)。
   - `StoreIndirectPointerField`/`StoreTrustedPointerField`: 存储间接指针或受信任指针字段。
   - `StoreMap`: 存储对象的 Map。
   - `StoreFixedArrayOrPropertyArrayElement`: 存储固定数组或属性数组的元素。
   - `StoreFixedDoubleArrayElement`: 存储固定双精度浮点数数组的元素。
   - `StoreFeedbackVectorSlot`: 存储反馈向量的槽位。
   - `StoreCellValue`: 存储 Cell 对象的值。
   - `StoreBigIntBitfield`/`StoreBigIntDigit`: 存储 BigInt 对象的内部数据。

5. **操作 JavaScript 数组:**
   - `EnsureArrayPushable`: 确保可以向数组中推送元素。
   - `PossiblyGrowElementsCapacity`:  根据需要增加数组的容量。
   - `BuildAppendJSArray`:  将多个参数追加到 JavaScript 数组。
   - `TryStoreArrayElement`: 尝试存储数组元素，并根据元素类型进行检查。

6. **分配 V8 内部对象:**
   - `AllocateCellWithValue`: 分配并初始化一个 Cell 对象。
   - `AllocateHeapNumber`/`AllocateHeapNumberWithValue`: 分配并初始化一个 HeapNumber 对象。
   - `AllocateBigInt`/`AllocateRawBigInt`: 分配 BigInt 对象。
   - `AllocateByteArray`/`AllocateNonEmptyByteArray`: 分配字节数组。

7. **其他辅助功能:**
   - `CloneIfMutablePrimitive`: 如果是可变的基本类型，则克隆它。

**关于 `.tq` 结尾的源代码:**

如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它的确是 V8 的 **Torque** 源代码。 Torque 是 V8 开发的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时代码。  当前的 `.cc` 文件很可能是由 `.tq` 文件编译生成的。

**与 JavaScript 功能的关系及示例:**

`CodeStubAssembler` 中提供的功能与很多 JavaScript 的底层实现息息相关。以下是一些例子：

1. **数组 `push` 操作:** `EnsureArrayPushable`, `PossiblyGrowElementsCapacity`, `BuildAppendJSArray`, `TryStoreArrayElement` 这些方法直接参与了 `Array.prototype.push` 等数组操作的底层实现。

   ```javascript
   const arr = [1, 2, 3];
   arr.push(4); // 底层可能涉及到上述的 CodeStubAssembler 方法
   ```

2. **对象原型链查找:** `LoadSlowObjectWithNullPrototypeMap`, `LoadJSFunctionPrototype`, `BranchIfHasPrototypeProperty`, `GotoIfPrototypeRequiresRuntimeLookup` 这些方法与 JavaScript 的原型继承机制密切相关。当访问对象的属性时，V8 需要遍历原型链来查找属性，这些方法就是用于操作原型链上的对象。

   ```javascript
   function Animal(name) {
     this.name = name;
   }
   Animal.prototype.sayHello = function() {
     console.log(`Hello, I'm ${this.name}`);
   };

   const dog = new Animal("Dog");
   dog.sayHello(); // 访问原型链上的方法，底层可能涉及到原型链的查找
   ```

3. **函数调用:** `LoadJSFunctionCode`, `LoadFunctionKind` 等方法用于获取函数的相关信息，这在函数调用过程中是必不可少的。V8 需要知道函数的代码在哪里，以及函数的类型 (普通函数、生成器函数等)。

   ```javascript
   function add(a, b) {
     return a + b;
   }
   add(5, 3); // 函数调用，底层需要加载函数代码等信息
   ```

4. **BigInt 操作:** `AllocateBigInt`, `StoreBigIntDigit`, `LoadBigIntDigit` 等方法用于支持 JavaScript 的 `BigInt` 数据类型。

   ```javascript
   const largeNumber = 9007199254740991n;
   const anotherLargeNumber = largeNumber + 1n;
   console.log(anotherLargeNumber);
   ```

**代码逻辑推理 (假设输入与输出):**

假设我们有以下输入：

* `function`: 一个 `JSFunction` 对象，代表一个 JavaScript 生成器函数。

调用 `IsGeneratorFunction(function)`:

* **假设输入:**  `function` 是一个生成器函数，例如：
  ```javascript
  function* myGenerator() {
    yield 1;
    yield 2;
  }
  ```
* **输出:** `true`

调用 `LoadJSArrayElementsMap(kind, native_context)`:

* **假设输入:**
    * `kind`: 一个 `Int32T`，其值为 `PACKED_SMI_ELEMENTS` (表示只包含小整数的数组)。
    * `native_context`: 当前的 NativeContext 对象。
* **输出:**  指向 `PACKED_SMI_ELEMENTS` 数组 Map 的 `TNode<Map>`。

**用户常见的编程错误 (举例说明):**

这段代码主要在 V8 内部使用，普通 JavaScript 开发者不会直接操作它。但是，理解其背后的原理可以帮助理解一些常见的编程错误：

1. **原型链污染:**  如果错误地修改了内置对象的原型，可能会导致程序行为异常，甚至安全漏洞。 例如，修改 `Object.prototype`：

   ```javascript
   Object.prototype.foo = 'bar';
   const obj = {};
   console.log(obj.foo); // "bar" -  这可能不是期望的行为，破坏了封装性。
   ```
   `CodeStubAssembler` 中与原型相关的代码（如 `LoadJSFunctionPrototype`）在原型链查找时会受到这种污染的影响。

2. **类型假设错误:**  在编写高性能的 JavaScript 代码时，开发者可能会不当地假设数组元素的类型。例如，假设一个数组只包含数字，但实际上可能包含其他类型的值，这会导致 V8 内部进行类型转换，降低性能。  `TryStoreArrayElement` 方法会根据 `ElementsKind` 进行类型检查，如果类型不匹配，可能需要进行转换或抛出错误。

   ```javascript
   const arr = [1, 2, 'a']; // 混合类型的数组可能导致性能下降
   ```

**功能归纳 (第 5 部分，共 23 部分):**

作为 `CodeStubAssembler` 的一部分，这部分代码主要负责提供 **加载和存储 V8 内部对象属性** 以及 **进行基本的对象状态检查和条件分支** 的功能。它构建了操作 V8 内部数据结构的基础设施，为更高级别的代码生成和优化奠定了基础。  在整个 `CodeStubAssembler` 中，不同的部分会专注于不同的操作，例如函数调用、对象创建、属性访问等。这部分代码更侧重于基础的数据访问和操作。

希望这个分析能够帮助你理解这段 V8 源代码的功能！

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共23部分，请归纳一下它的功能

"""
eapObjectAssumeWeak(value, runtime));
  return result;
}

TNode<Map> CodeStubAssembler::LoadSlowObjectWithNullPrototypeMap(
    TNode<NativeContext> native_context) {
  TNode<Map> map = CAST(LoadContextElement(
      native_context, Context::SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP));
  return map;
}

TNode<Map> CodeStubAssembler::LoadJSArrayElementsMap(
    TNode<Int32T> kind, TNode<NativeContext> native_context) {
  CSA_DCHECK(this, IsFastElementsKind(kind));
  TNode<IntPtrT> offset =
      IntPtrAdd(IntPtrConstant(Context::FIRST_JS_ARRAY_MAP_SLOT),
                ChangeInt32ToIntPtr(kind));
  return UncheckedCast<Map>(LoadContextElement(native_context, offset));
}

TNode<Map> CodeStubAssembler::LoadJSArrayElementsMap(
    ElementsKind kind, TNode<NativeContext> native_context) {
  return UncheckedCast<Map>(
      LoadContextElement(native_context, Context::ArrayMapIndex(kind)));
}

TNode<Uint32T> CodeStubAssembler::LoadFunctionKind(TNode<JSFunction> function) {
  const TNode<SharedFunctionInfo> shared_function_info =
      LoadObjectField<SharedFunctionInfo>(
          function, JSFunction::kSharedFunctionInfoOffset);

  const TNode<Uint32T> function_kind =
      DecodeWord32<SharedFunctionInfo::FunctionKindBits>(
          LoadObjectField<Uint32T>(shared_function_info,
                                   SharedFunctionInfo::kFlagsOffset));
  return function_kind;
}

TNode<BoolT> CodeStubAssembler::IsGeneratorFunction(
    TNode<JSFunction> function) {
  const TNode<Uint32T> function_kind = LoadFunctionKind(function);

  // See IsGeneratorFunction(FunctionKind kind).
  return IsInRange(
      function_kind,
      static_cast<uint32_t>(FunctionKind::kAsyncConciseGeneratorMethod),
      static_cast<uint32_t>(FunctionKind::kConciseGeneratorMethod));
}

TNode<BoolT> CodeStubAssembler::IsJSFunctionWithPrototypeSlot(
    TNode<HeapObject> object) {
  // Only JSFunction maps may have HasPrototypeSlotBit set.
  return IsSetWord32<Map::Bits1::HasPrototypeSlotBit>(
      LoadMapBitField(LoadMap(object)));
}

void CodeStubAssembler::BranchIfHasPrototypeProperty(
    TNode<JSFunction> function, TNode<Int32T> function_map_bit_field,
    Label* if_true, Label* if_false) {
  // (has_prototype_slot() && IsConstructor()) ||
  // IsGeneratorFunction(shared()->kind())
  uint32_t mask = Map::Bits1::HasPrototypeSlotBit::kMask |
                  Map::Bits1::IsConstructorBit::kMask;

  GotoIf(IsAllSetWord32(function_map_bit_field, mask), if_true);
  Branch(IsGeneratorFunction(function), if_true, if_false);
}

void CodeStubAssembler::GotoIfPrototypeRequiresRuntimeLookup(
    TNode<JSFunction> function, TNode<Map> map, Label* runtime) {
  // !has_prototype_property() || has_non_instance_prototype()
  TNode<Int32T> map_bit_field = LoadMapBitField(map);
  Label next_check(this);
  BranchIfHasPrototypeProperty(function, map_bit_field, &next_check, runtime);
  BIND(&next_check);
  GotoIf(IsSetWord32<Map::Bits1::HasNonInstancePrototypeBit>(map_bit_field),
         runtime);
}

TNode<HeapObject> CodeStubAssembler::LoadJSFunctionPrototype(
    TNode<JSFunction> function, Label* if_bailout) {
  CSA_DCHECK(this, IsFunctionWithPrototypeSlotMap(LoadMap(function)));
  CSA_DCHECK(this, IsClearWord32<Map::Bits1::HasNonInstancePrototypeBit>(
                       LoadMapBitField(LoadMap(function))));
  TNode<HeapObject> proto_or_map = LoadObjectField<HeapObject>(
      function, JSFunction::kPrototypeOrInitialMapOffset);
  GotoIf(IsTheHole(proto_or_map), if_bailout);

  TVARIABLE(HeapObject, var_result, proto_or_map);
  Label done(this, &var_result);
  GotoIfNot(IsMap(proto_or_map), &done);

  var_result = LoadMapPrototype(CAST(proto_or_map));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<Code> CodeStubAssembler::LoadJSFunctionCode(TNode<JSFunction> function) {
#ifdef V8_ENABLE_LEAPTIERING
  TNode<JSDispatchHandleT> dispatch_handle = LoadObjectField<JSDispatchHandleT>(
      function, JSFunction::kDispatchHandleOffset);
  return LoadCodeObjectFromJSDispatchTable(dispatch_handle);
#else
  return LoadCodePointerFromObject(function, JSFunction::kCodeOffset);
#endif  // V8_ENABLE_LEAPTIERING
}

TNode<Object> CodeStubAssembler::LoadSharedFunctionInfoTrustedData(
    TNode<SharedFunctionInfo> sfi) {
#ifdef V8_ENABLE_SANDBOX
  TNode<IndirectPointerHandleT> trusted_data_handle =
      LoadObjectField<IndirectPointerHandleT>(
          sfi, SharedFunctionInfo::kTrustedFunctionDataOffset);

  return Select<Object>(
      Word32Equal(trusted_data_handle,
                  Int32Constant(kNullIndirectPointerHandle)),
      [=, this] { return SmiConstant(0); },
      [=, this] {
        return ResolveIndirectPointerHandle(trusted_data_handle,
                                            kUnknownIndirectPointerTag);
      });
#else
  return LoadObjectField<Object>(
      sfi, SharedFunctionInfo::kTrustedFunctionDataOffset);
#endif
}

TNode<Object> CodeStubAssembler::LoadSharedFunctionInfoUntrustedData(
    TNode<SharedFunctionInfo> sfi) {
  return LoadObjectField<Object>(
      sfi, SharedFunctionInfo::kUntrustedFunctionDataOffset);
}

TNode<BoolT> CodeStubAssembler::SharedFunctionInfoHasBaselineCode(
    TNode<SharedFunctionInfo> sfi) {
  TNode<Object> data = LoadSharedFunctionInfoTrustedData(sfi);
  return TaggedIsCode(data);
}

TNode<Smi> CodeStubAssembler::LoadSharedFunctionInfoBuiltinId(
    TNode<SharedFunctionInfo> sfi) {
  return LoadObjectField<Smi>(sfi,
                              SharedFunctionInfo::kUntrustedFunctionDataOffset);
}

TNode<BytecodeArray> CodeStubAssembler::LoadSharedFunctionInfoBytecodeArray(
    TNode<SharedFunctionInfo> sfi) {
  TNode<HeapObject> function_data = LoadTrustedPointerFromObject(
      sfi, SharedFunctionInfo::kTrustedFunctionDataOffset,
      kUnknownIndirectPointerTag);

  TVARIABLE(HeapObject, var_result, function_data);

  Label check_for_interpreter_data(this, &var_result);
  Label done(this, &var_result);

  GotoIfNot(HasInstanceType(var_result.value(), CODE_TYPE),
            &check_for_interpreter_data);
  {
    TNode<Code> code = CAST(var_result.value());
#ifdef DEBUG
    TNode<Int32T> code_flags =
        LoadObjectField<Int32T>(code, Code::kFlagsOffset);
    CSA_DCHECK(
        this, Word32Equal(DecodeWord32<Code::KindField>(code_flags),
                          Int32Constant(static_cast<int>(CodeKind::BASELINE))));
#endif  // DEBUG
    TNode<HeapObject> baseline_data = CAST(LoadProtectedPointerField(
        code, Code::kDeoptimizationDataOrInterpreterDataOffset));
    var_result = baseline_data;
  }
  Goto(&check_for_interpreter_data);

  BIND(&check_for_interpreter_data);

  GotoIfNot(HasInstanceType(var_result.value(), INTERPRETER_DATA_TYPE), &done);
  TNode<BytecodeArray> bytecode_array = CAST(LoadProtectedPointerField(
      CAST(var_result.value()), InterpreterData::kBytecodeArrayOffset));
  var_result = bytecode_array;
  Goto(&done);

  BIND(&done);
  // We need an explicit check here since we use the
  // kUnknownIndirectPointerTag above and so don't have any type guarantees.
  CSA_SBXCHECK(this, HasInstanceType(var_result.value(), BYTECODE_ARRAY_TYPE));
  return CAST(var_result.value());
}

#ifdef V8_ENABLE_WEBASSEMBLY
TNode<WasmFunctionData>
CodeStubAssembler::LoadSharedFunctionInfoWasmFunctionData(
    TNode<SharedFunctionInfo> sfi) {
  return CAST(LoadTrustedPointerFromObject(
      sfi, SharedFunctionInfo::kTrustedFunctionDataOffset,
      kWasmFunctionDataIndirectPointerTag));
}

TNode<WasmExportedFunctionData>
CodeStubAssembler::LoadSharedFunctionInfoWasmExportedFunctionData(
    TNode<SharedFunctionInfo> sfi) {
  TNode<WasmFunctionData> function_data =
      LoadSharedFunctionInfoWasmFunctionData(sfi);
  // TODO(saelo): it would be nice if we could use LoadTrustedPointerFromObject
  // with a kWasmExportedFunctionDataIndirectPointerTag to avoid the SBXCHECK,
  // but for that our tagging scheme first needs to support type hierarchies.
  CSA_SBXCHECK(
      this, HasInstanceType(function_data, WASM_EXPORTED_FUNCTION_DATA_TYPE));
  return CAST(function_data);
}

TNode<WasmJSFunctionData>
CodeStubAssembler::LoadSharedFunctionInfoWasmJSFunctionData(
    TNode<SharedFunctionInfo> sfi) {
  TNode<WasmFunctionData> function_data =
      LoadSharedFunctionInfoWasmFunctionData(sfi);
  // TODO(saelo): it would be nice if we could use LoadTrustedPointerFromObject
  // with a kWasmJSFunctionDataIndirectPointerTag to avoid the SBXCHECK, but
  // for that our tagging scheme first needs to support type hierarchies.
  CSA_SBXCHECK(this,
               HasInstanceType(function_data, WASM_JS_FUNCTION_DATA_TYPE));
  return CAST(function_data);
}
#endif  // V8_ENABLE_WEBASSEMBLY

TNode<Int32T> CodeStubAssembler::LoadBytecodeArrayParameterCount(
    TNode<BytecodeArray> bytecode_array) {
  return LoadObjectField<Uint16T>(bytecode_array,
                                  BytecodeArray::kParameterSizeOffset);
}

TNode<Int32T> CodeStubAssembler::LoadBytecodeArrayParameterCountWithoutReceiver(
    TNode<BytecodeArray> bytecode_array) {
  return Int32Sub(LoadBytecodeArrayParameterCount(bytecode_array),
                  Int32Constant(kJSArgcReceiverSlots));
}

void CodeStubAssembler::StoreObjectByteNoWriteBarrier(TNode<HeapObject> object,
                                                      int offset,
                                                      TNode<Word32T> value) {
  StoreNoWriteBarrier(MachineRepresentation::kWord8, object,
                      IntPtrConstant(offset - kHeapObjectTag), value);
}

void CodeStubAssembler::StoreHeapNumberValue(TNode<HeapNumber> object,
                                             TNode<Float64T> value) {
  StoreObjectFieldNoWriteBarrier(object, offsetof(HeapNumber, value_), value);
}

void CodeStubAssembler::StoreObjectField(TNode<HeapObject> object, int offset,
                                         TNode<Smi> value) {
  StoreObjectFieldNoWriteBarrier(object, offset, value);
}

void CodeStubAssembler::StoreObjectField(TNode<HeapObject> object,
                                         TNode<IntPtrT> offset,
                                         TNode<Smi> value) {
  StoreObjectFieldNoWriteBarrier(object, offset, value);
}

void CodeStubAssembler::StoreObjectField(TNode<HeapObject> object, int offset,
                                         TNode<Object> value) {
  DCHECK_NE(HeapObject::kMapOffset, offset);  // Use StoreMap instead.
  OptimizedStoreField(MachineRepresentation::kTagged,
                      UncheckedCast<HeapObject>(object), offset, value);
}

void CodeStubAssembler::StoreObjectField(TNode<HeapObject> object,
                                         TNode<IntPtrT> offset,
                                         TNode<Object> value) {
  int const_offset;
  if (TryToInt32Constant(offset, &const_offset)) {
    StoreObjectField(object, const_offset, value);
  } else {
    Store(object, IntPtrSub(offset, IntPtrConstant(kHeapObjectTag)), value);
  }
}

void CodeStubAssembler::StoreIndirectPointerField(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag,
    TNode<ExposedTrustedObject> value) {
  DCHECK(V8_ENABLE_SANDBOX_BOOL);
  OptimizedStoreIndirectPointerField(object, offset, tag, value);
}

void CodeStubAssembler::StoreIndirectPointerFieldNoWriteBarrier(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag,
    TNode<ExposedTrustedObject> value) {
  DCHECK(V8_ENABLE_SANDBOX_BOOL);
  OptimizedStoreIndirectPointerFieldNoWriteBarrier(object, offset, tag, value);
}

void CodeStubAssembler::StoreTrustedPointerField(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag,
    TNode<ExposedTrustedObject> value) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerField(object, offset, tag, value);
#else
  StoreObjectField(object, offset, value);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreTrustedPointerFieldNoWriteBarrier(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag,
    TNode<ExposedTrustedObject> value) {
#ifdef V8_ENABLE_SANDBOX
  StoreIndirectPointerFieldNoWriteBarrier(object, offset, tag, value);
#else
  StoreObjectFieldNoWriteBarrier(object, offset, value);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::ClearTrustedPointerField(TNode<HeapObject> object,
                                                 int offset) {
#ifdef V8_ENABLE_SANDBOX
  StoreObjectFieldNoWriteBarrier(object, offset,
                                 Uint32Constant(kNullTrustedPointerHandle));
#else
  StoreObjectFieldNoWriteBarrier(object, offset, SmiConstant(0));
#endif
}

void CodeStubAssembler::UnsafeStoreObjectFieldNoWriteBarrier(
    TNode<HeapObject> object, int offset, TNode<Object> value) {
  DCHECK_NE(HeapObject::kMapOffset, offset);  // Use StoreMap instead.
  OptimizedStoreFieldUnsafeNoWriteBarrier(MachineRepresentation::kTagged,
                                          object, offset, value);
}

void CodeStubAssembler::StoreSharedObjectField(TNode<HeapObject> object,
                                               TNode<IntPtrT> offset,
                                               TNode<Object> value) {
  CSA_DCHECK(this,
             WordNotEqual(
                 WordAnd(LoadMemoryChunkFlags(object),
                         IntPtrConstant(MemoryChunk::IN_WRITABLE_SHARED_SPACE)),
                 IntPtrConstant(0)));
  int const_offset;
  if (TryToInt32Constant(offset, &const_offset)) {
    StoreObjectField(object, const_offset, value);
  } else {
    Store(object, IntPtrSub(offset, IntPtrConstant(kHeapObjectTag)), value);
  }
}

void CodeStubAssembler::StoreMap(TNode<HeapObject> object, TNode<Map> map) {
  OptimizedStoreMap(object, map);
  DcheckHasValidMap(object);
}

void CodeStubAssembler::StoreMapNoWriteBarrier(TNode<HeapObject> object,
                                               RootIndex map_root_index) {
  StoreMapNoWriteBarrier(object, CAST(LoadRoot(map_root_index)));
}

void CodeStubAssembler::StoreMapNoWriteBarrier(TNode<HeapObject> object,
                                               TNode<Map> map) {
  OptimizedStoreMap(object, map);
  DcheckHasValidMap(object);
}

void CodeStubAssembler::StoreObjectFieldRoot(TNode<HeapObject> object,
                                             int offset, RootIndex root_index) {
  TNode<Object> root = LoadRoot(root_index);
  if (offset == HeapObject::kMapOffset) {
    StoreMap(object, CAST(root));
  } else if (RootsTable::IsImmortalImmovable(root_index)) {
    StoreObjectFieldNoWriteBarrier(object, offset, root);
  } else {
    StoreObjectField(object, offset, root);
  }
}

template <typename TIndex>
void CodeStubAssembler::StoreFixedArrayOrPropertyArrayElement(
    TNode<UnionOf<FixedArray, PropertyArray>> object, TNode<TIndex> index_node,
    TNode<Object> value, WriteBarrierMode barrier_mode, int additional_offset) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT index is allowed");
  DCHECK(barrier_mode == SKIP_WRITE_BARRIER ||
         barrier_mode == UNSAFE_SKIP_WRITE_BARRIER ||
         barrier_mode == UPDATE_WRITE_BARRIER ||
         barrier_mode == UPDATE_EPHEMERON_KEY_WRITE_BARRIER);
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  static_assert(static_cast<int>(OFFSET_OF_DATA_START(FixedArray)) ==
                static_cast<int>(PropertyArray::kHeaderSize));
  int header_size =
      OFFSET_OF_DATA_START(FixedArray) + additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index_node, HOLEY_ELEMENTS, header_size);
  static_assert(static_cast<int>(offsetof(FixedArray, length_)) ==
                static_cast<int>(offsetof(FixedDoubleArray, length_)));
  static_assert(static_cast<int>(offsetof(FixedArray, length_)) ==
                static_cast<int>(offsetof(WeakFixedArray, length_)));
  static_assert(static_cast<int>(offsetof(FixedArray, length_)) ==
                static_cast<int>(PropertyArray::kLengthAndHashOffset));
  // Check that index_node + additional_offset <= object.length.
  // TODO(cbruni): Use proper LoadXXLength helpers
  CSA_DCHECK(
      this,
      IsOffsetInBounds(
          offset,
          Select<IntPtrT>(
              IsPropertyArray(object),
              [=, this] {
                TNode<Int32T> length_and_hash = LoadAndUntagToWord32ObjectField(
                    object, PropertyArray::kLengthAndHashOffset);
                return Signed(ChangeUint32ToWord(
                    DecodeWord32<PropertyArray::LengthField>(length_and_hash)));
              },
              [=, this] {
                return LoadAndUntagPositiveSmiObjectField(
                    object, FixedArrayBase::kLengthOffset);
              }),
          OFFSET_OF_DATA_START(FixedArray)));
  if (barrier_mode == SKIP_WRITE_BARRIER) {
    StoreNoWriteBarrier(MachineRepresentation::kTagged, object, offset, value);
  } else if (barrier_mode == UNSAFE_SKIP_WRITE_BARRIER) {
    UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged, object, offset,
                              value);
  } else if (barrier_mode == UPDATE_EPHEMERON_KEY_WRITE_BARRIER) {
    StoreEphemeronKey(object, offset, value);
  } else {
    Store(object, offset, value);
  }
}

template V8_EXPORT_PRIVATE void
CodeStubAssembler::StoreFixedArrayOrPropertyArrayElement<Smi>(
    TNode<UnionOf<FixedArray, PropertyArray>>, TNode<Smi>, TNode<Object>,
    WriteBarrierMode, int);

template V8_EXPORT_PRIVATE void
CodeStubAssembler::StoreFixedArrayOrPropertyArrayElement<IntPtrT>(
    TNode<UnionOf<FixedArray, PropertyArray>>, TNode<IntPtrT>, TNode<Object>,
    WriteBarrierMode, int);

template V8_EXPORT_PRIVATE void
CodeStubAssembler::StoreFixedArrayOrPropertyArrayElement<UintPtrT>(
    TNode<UnionOf<FixedArray, PropertyArray>>, TNode<UintPtrT>, TNode<Object>,
    WriteBarrierMode, int);

template <typename TIndex>
void CodeStubAssembler::StoreFixedDoubleArrayElement(
    TNode<FixedDoubleArray> object, TNode<TIndex> index, TNode<Float64T> value,
    CheckBounds check_bounds) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(std::is_same<TIndex, Smi>::value ||
                    std::is_same<TIndex, UintPtrT>::value ||
                    std::is_same<TIndex, IntPtrT>::value,
                "Only Smi, UintPtrT or IntPtrT index is allowed");
  if (NeedsBoundsCheck(check_bounds)) {
    FixedArrayBoundsCheck(object, index, 0);
  }
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS,
                             OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag);
  MachineRepresentation rep = MachineRepresentation::kFloat64;
  // Make sure we do not store signalling NaNs into double arrays.
  TNode<Float64T> value_silenced = Float64SilenceNaN(value);
  StoreNoWriteBarrier(rep, object, offset, value_silenced);
}

// Export the Smi version which is used outside of code-stub-assembler.
template V8_EXPORT_PRIVATE void CodeStubAssembler::StoreFixedDoubleArrayElement<
    Smi>(TNode<FixedDoubleArray>, TNode<Smi>, TNode<Float64T>, CheckBounds);

void CodeStubAssembler::StoreFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
    TNode<AnyTaggedT> value, WriteBarrierMode barrier_mode,
    int additional_offset) {
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  DCHECK(barrier_mode == SKIP_WRITE_BARRIER ||
         barrier_mode == UNSAFE_SKIP_WRITE_BARRIER ||
         barrier_mode == UPDATE_WRITE_BARRIER);
  int header_size = FeedbackVector::kRawFeedbackSlotsOffset +
                    additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(Signed(slot), HOLEY_ELEMENTS, header_size);
  // Check that slot <= feedback_vector.length.
  CSA_DCHECK(this,
             IsOffsetInBounds(offset, LoadFeedbackVectorLength(feedback_vector),
                              FeedbackVector::kHeaderSize),
             SmiFromIntPtr(offset), feedback_vector);
  if (barrier_mode == SKIP_WRITE_BARRIER) {
    StoreNoWriteBarrier(MachineRepresentation::kTagged, feedback_vector, offset,
                        value);
  } else if (barrier_mode == UNSAFE_SKIP_WRITE_BARRIER) {
    UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged, feedback_vector,
                              offset, value);
  } else {
    Store(feedback_vector, offset, value);
  }
}

TNode<Int32T> CodeStubAssembler::EnsureArrayPushable(TNode<Context> context,
                                                     TNode<Map> map,
                                                     Label* bailout) {
  // Disallow pushing onto prototypes. It might be the JSArray prototype.
  // Disallow pushing onto non-extensible objects.
  Comment("Disallow pushing onto prototypes");
  GotoIfNot(IsExtensibleNonPrototypeMap(map), bailout);

  EnsureArrayLengthWritable(context, map, bailout);

  TNode<Uint32T> kind =
      DecodeWord32<Map::Bits2::ElementsKindBits>(LoadMapBitField2(map));
  return Signed(kind);
}

void CodeStubAssembler::PossiblyGrowElementsCapacity(
    ElementsKind kind, TNode<HeapObject> array, TNode<BInt> length,
    TVariable<FixedArrayBase>* var_elements, TNode<BInt> growth,
    Label* bailout) {
  Label fits(this, var_elements);
  TNode<BInt> capacity =
      TaggedToParameter<BInt>(LoadFixedArrayBaseLength(var_elements->value()));

  TNode<BInt> new_length = IntPtrOrSmiAdd(growth, length);
  GotoIfNot(IntPtrOrSmiGreaterThan(new_length, capacity), &fits);
  TNode<BInt> new_capacity = CalculateNewElementsCapacity(new_length);
  *var_elements = GrowElementsCapacity(array, var_elements->value(), kind, kind,
                                       capacity, new_capacity, bailout);
  Goto(&fits);
  BIND(&fits);
}

TNode<Smi> CodeStubAssembler::BuildAppendJSArray(ElementsKind kind,
                                                 TNode<JSArray> array,
                                                 CodeStubArguments* args,
                                                 TVariable<IntPtrT>* arg_index,
                                                 Label* bailout) {
  Comment("BuildAppendJSArray: ", ElementsKindToString(kind));
  Label pre_bailout(this);
  Label success(this);
  TVARIABLE(Smi, var_tagged_length, LoadFastJSArrayLength(array));
  TVARIABLE(BInt, var_length, SmiToBInt(var_tagged_length.value()));
  TVARIABLE(FixedArrayBase, var_elements, LoadElements(array));

  // Trivial case: no values are being appended.
  // We have this special case here so that callers of this function can assume
  // that there is at least one argument if this function bails out. This may
  // otherwise not be the case if, due to another bug or in-sandbox memory
  // corruption, the JSArray's length is larger than that of its backing
  // FixedArray. In that case, PossiblyGrowElementsCapacity can fail even if no
  // element are to be appended.
  GotoIf(IntPtrEqual(args->GetLengthWithoutReceiver(), IntPtrConstant(0)),
         &success);

  // Resize the capacity of the fixed array if it doesn't fit.
  TNode<IntPtrT> first = arg_index->value();
  TNode<BInt> growth =
      IntPtrToBInt(IntPtrSub(args->GetLengthWithoutReceiver(), first));
  PossiblyGrowElementsCapacity(kind, array, var_length.value(), &var_elements,
                               growth, &pre_bailout);

  // Push each argument onto the end of the array now that there is enough
  // capacity.
  CodeStubAssembler::VariableList push_vars({&var_length}, zone());
  TNode<FixedArrayBase> elements = var_elements.value();
  args->ForEach(
      push_vars,
      [&](TNode<Object> arg) {
        TryStoreArrayElement(kind, &pre_bailout, elements, var_length.value(),
                             arg);
        Increment(&var_length);
      },
      first);
  {
    TNode<Smi> length = BIntToSmi(var_length.value());
    var_tagged_length = length;
    StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
    Goto(&success);
  }

  BIND(&pre_bailout);
  {
    TNode<Smi> length = ParameterToTagged(var_length.value());
    var_tagged_length = length;
    TNode<Smi> diff = SmiSub(length, LoadFastJSArrayLength(array));
    StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
    *arg_index = IntPtrAdd(arg_index->value(), SmiUntag(diff));
    Goto(bailout);
  }

  BIND(&success);
  return var_tagged_length.value();
}

void CodeStubAssembler::TryStoreArrayElement(ElementsKind kind, Label* bailout,
                                             TNode<FixedArrayBase> elements,
                                             TNode<BInt> index,
                                             TNode<Object> value) {
  if (IsSmiElementsKind(kind)) {
    GotoIf(TaggedIsNotSmi(value), bailout);
  } else if (IsDoubleElementsKind(kind)) {
    GotoIfNotNumber(value, bailout);
  }

  if (IsDoubleElementsKind(kind)) {
    StoreElement(elements, kind, index, ChangeNumberToFloat64(CAST(value)));
  } else {
    StoreElement(elements, kind, index, value);
  }
}

void CodeStubAssembler::BuildAppendJSArray(ElementsKind kind,
                                           TNode<JSArray> array,
                                           TNode<Object> value,
                                           Label* bailout) {
  Comment("BuildAppendJSArray: ", ElementsKindToString(kind));
  TVARIABLE(BInt, var_length, SmiToBInt(LoadFastJSArrayLength(array)));
  TVARIABLE(FixedArrayBase, var_elements, LoadElements(array));

  // Resize the capacity of the fixed array if it doesn't fit.
  TNode<BInt> growth = IntPtrOrSmiConstant<BInt>(1);
  PossiblyGrowElementsCapacity(kind, array, var_length.value(), &var_elements,
                               growth, bailout);

  // Push each argument onto the end of the array now that there is enough
  // capacity.
  TryStoreArrayElement(kind, bailout, var_elements.value(), var_length.value(),
                       value);
  Increment(&var_length);

  TNode<Smi> length = BIntToSmi(var_length.value());
  StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
}

TNode<Cell> CodeStubAssembler::AllocateCellWithValue(TNode<Object> value,
                                                     WriteBarrierMode mode) {
  TNode<HeapObject> result = Allocate(Cell::kSize, AllocationFlag::kNone);
  StoreMapNoWriteBarrier(result, RootIndex::kCellMap);
  TNode<Cell> cell = CAST(result);
  StoreCellValue(cell, value, mode);
  return cell;
}

TNode<Object> CodeStubAssembler::LoadCellValue(TNode<Cell> cell) {
  return LoadObjectField(cell, Cell::kValueOffset);
}

void CodeStubAssembler::StoreCellValue(TNode<Cell> cell, TNode<Object> value,
                                       WriteBarrierMode mode) {
  DCHECK(mode == SKIP_WRITE_BARRIER || mode == UPDATE_WRITE_BARRIER);

  if (mode == UPDATE_WRITE_BARRIER) {
    StoreObjectField(cell, Cell::kValueOffset, value);
  } else {
    StoreObjectFieldNoWriteBarrier(cell, Cell::kValueOffset, value);
  }
}

TNode<HeapNumber> CodeStubAssembler::AllocateHeapNumber() {
  TNode<HeapObject> result =
      Allocate(sizeof(HeapNumber), AllocationFlag::kNone);
  RootIndex heap_map_index = RootIndex::kHeapNumberMap;
  StoreMapNoWriteBarrier(result, heap_map_index);
  return UncheckedCast<HeapNumber>(result);
}

TNode<HeapNumber> CodeStubAssembler::AllocateHeapNumberWithValue(
    TNode<Float64T> value) {
  TNode<HeapNumber> result = AllocateHeapNumber();
  StoreHeapNumberValue(result, value);
  return result;
}

TNode<Object> CodeStubAssembler::CloneIfMutablePrimitive(TNode<Object> object) {
  TVARIABLE(Object, result, object);
  Label done(this);

  GotoIf(TaggedIsSmi(object), &done);
  // TODO(leszeks): Read the field descriptor to decide if this heap number is
  // mutable or not.
  GotoIfNot(IsHeapNumber(UncheckedCast<HeapObject>(object)), &done);
  {
    // Mutable heap number found --- allocate a clone.
    TNode<Float64T> value =
        LoadHeapNumberValue(UncheckedCast<HeapNumber>(object));
    result = AllocateHeapNumberWithValue(value);
    Goto(&done);
  }

  BIND(&done);
  return result.value();
}

TNode<BigInt> CodeStubAssembler::AllocateBigInt(TNode<IntPtrT> length) {
  TNode<BigInt> result = AllocateRawBigInt(length);
  StoreBigIntBitfield(result,
                      Word32Shl(TruncateIntPtrToInt32(length),
                                Int32Constant(BigInt::LengthBits::kShift)));
  return result;
}

TNode<BigInt> CodeStubAssembler::AllocateRawBigInt(TNode<IntPtrT> length) {
  TNode<IntPtrT> size =
      IntPtrAdd(IntPtrConstant(sizeof(BigInt)),
                Signed(WordShl(length, kSystemPointerSizeLog2)));
  TNode<HeapObject> raw_result = Allocate(size);
  StoreMapNoWriteBarrier(raw_result, RootIndex::kBigIntMap);
#ifdef BIGINT_NEEDS_PADDING
  static_assert(arraysize(BigInt::padding_) == sizeof(int32_t));
  StoreObjectFieldNoWriteBarrier(raw_result, offsetof(BigInt, padding_),
                                 Int32Constant(0));
#endif
  return UncheckedCast<BigInt>(raw_result);
}

void CodeStubAssembler::StoreBigIntBitfield(TNode<BigInt> bigint,
                                            TNode<Word32T> bitfield) {
  StoreObjectFieldNoWriteBarrier(bigint, offsetof(BigInt, bitfield_), bitfield);
}

void CodeStubAssembler::StoreBigIntDigit(TNode<BigInt> bigint,
                                         intptr_t digit_index,
                                         TNode<UintPtrT> digit) {
  CHECK_LE(0, digit_index);
  CHECK_LT(digit_index, BigInt::kMaxLength);
  StoreObjectFieldNoWriteBarrier(
      bigint,
      OFFSET_OF_DATA_START(BigInt) +
          static_cast<int>(digit_index) * kSystemPointerSize,
      digit);
}

void CodeStubAssembler::StoreBigIntDigit(TNode<BigInt> bigint,
                                         TNode<IntPtrT> digit_index,
                                         TNode<UintPtrT> digit) {
  TNode<IntPtrT> offset =
      IntPtrAdd(IntPtrConstant(OFFSET_OF_DATA_START(BigInt)),
                IntPtrMul(digit_index, IntPtrConstant(kSystemPointerSize)));
  StoreObjectFieldNoWriteBarrier(bigint, offset, digit);
}

TNode<Word32T> CodeStubAssembler::LoadBigIntBitfield(TNode<BigInt> bigint) {
  return UncheckedCast<Word32T>(
      LoadObjectField<Uint32T>(bigint, offsetof(BigInt, bitfield_)));
}

TNode<UintPtrT> CodeStubAssembler::LoadBigIntDigit(TNode<BigInt> bigint,
                                                   intptr_t digit_index) {
  CHECK_LE(0, digit_index);
  CHECK_LT(digit_index, BigInt::kMaxLength);
  return LoadObjectField<UintPtrT>(
      bigint, OFFSET_OF_DATA_START(BigInt) +
                  static_cast<int>(digit_index) * kSystemPointerSize);
}

TNode<UintPtrT> CodeStubAssembler::LoadBigIntDigit(TNode<BigInt> bigint,
                                                   TNode<IntPtrT> digit_index) {
  TNode<IntPtrT> offset =
      IntPtrAdd(IntPtrConstant(OFFSET_OF_DATA_START(BigInt)),
                IntPtrMul(digit_index, IntPtrConstant(kSystemPointerSize)));
  return LoadObjectField<UintPtrT>(bigint, offset);
}

TNode<ByteArray> CodeStubAssembler::AllocateNonEmptyByteArray(
    TNode<UintPtrT> length, AllocationFlags flags) {
  CSA_DCHECK(this, WordNotEqual(length, IntPtrConstant(0)));

  Comment("AllocateNonEmptyByteArray");
  TVARIABLE(Object, var_result);

  TNode<IntPtrT> raw_size = GetArrayAllocationSize(
      Signed(length), UINT8_ELEMENTS,
      OFFSET_OF_DATA_START(ByteArray) + kObjectAlignmentMask);
  TNode<IntPtrT> size =
      WordAnd(raw_size, IntPtrConstant(~kObjectAlignmentMask));

  TNode<HeapObject> result = Allocate(size, flags);

  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kByteArrayMap));
  StoreMapNoWriteBarrier(result, RootIndex::kByteArrayMap);
  StoreObjectFieldNoWriteBarrier(result, offsetof(ByteArray, length_),
                                 SmiTag(Signed(length)));

  return CAST(result);
}

TNode<ByteArray> CodeStubAssembler::AllocateByteArray(TNode<UintPtrT> length,
                                                      AllocationFlags flags) {
  // TODO(ishell): unify with AllocateNonEmptyByteArray().

  Comment("AllocateByteArray");
  TVARIABLE(Object, var_result);

  // Compute the ByteArray size and check if it fits into new space.
  Label if_lengthiszero(this), if_sizeissmall(this),
      if_notsizeissmall(this, Label::kDeferred), if_join(this);
  GotoIf(WordEqual(length, UintPtrConstant(0)), &if_lengthiszero);

  TNode<IntPtrT> raw_size = GetArrayAllocationSize(
      Signed(length), UINT8_ELEMENTS,
      OFFSET_OF_DATA_START(ByteArray) + kObjectAlignmentMask);
  TNode<IntPtrT> size =
      WordAnd(raw_size, IntPtrConstant(~kObjectAlignmentMask));
  Branch(IntPtrLessThanOrEqual(size, IntPtrConstant(kMaxRegularHeapOb
"""


```