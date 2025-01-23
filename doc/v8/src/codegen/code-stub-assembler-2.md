Response: The user wants me to summarize the functionality of the C++ code provided, which is a part of the `code-stub-assembler.cc` file in the V8 JavaScript engine. I need to identify the main purpose of the code snippets and if it relates to any JavaScript functionality, provide a JavaScript example. This is the third part of a 12-part summary.

Based on the code, it seems this part focuses on:

1. **Loading and Checking Object Properties:** Functions to load maps, function kinds, prototype information, and shared function info data.
2. **Memory Operations:**  Functions for storing and loading object fields, including handling write barriers and different data types (Smi, Object, HeapNumber, BigInt).
3. **Array Operations:** Functions for allocating and manipulating arrays (JSArray, FixedArray, ByteArray), including growing capacity, appending elements, and storing elements with different element kinds.
4. **Object Allocation:** Functions for allocating various heap objects like Cell, HeapNumber, BigInt, String (SeqOneByteString, SeqTwoByteString, SlicedString), Dictionary (NameDictionary, PropertyDictionary, OrderedNameDictionary, OrderedHashSet, OrderedHashMap), and JSObject.
5. **Helper Functions:** Functions for aligning memory, checking array capacity, and initializing object fields.

The code heavily involves accessing and manipulating the internal structure of JavaScript objects in memory. This is core to how the V8 engine executes JavaScript.
这个C++代码片段主要提供了在V8的CodeStubAssembler中用于**加载对象属性**、**存储对象属性**和**分配各种V8堆对象**的功能。它直接操作V8的内部表示，与JavaScript的底层执行息息相关。

以下是更具体的归纳：

**功能归纳：**

1. **加载对象信息 (Loading Object Information):**
    *   加载对象的Map (类型信息)。
    *   加载JSArray的不同类型的Map。
    *   加载JSFunction的类型 (例如是否为Generator函数)。
    *   检查JSFunction是否拥有prototype属性。
    *   加载JSFunction的prototype。
    *   加载JSFunction的Code (执行的代码)。
    *   加载SharedFunctionInfo中的可信和不可信数据 (包含编译后的代码或字节码)。
    *   检查SharedFunctionInfo是否有基线代码。
    *   加载SharedFunctionInfo的Builtin ID。
    *   加载SharedFunctionInfo的BytecodeArray (字节码)。
    *   加载SharedFunctionInfo的Wasm相关数据。
    *   加载BytecodeArray的参数数量。

2. **存储对象信息 (Storing Object Information):**
    *   存储对象的字节数据，并可以控制是否使用写屏障。
    *   存储HeapNumber的值。
    *   存储对象的字段，包括Smi和Object类型，并处理写屏障。
    *   存储IndirectPointerField和TrustedPointerField (用于沙箱环境)。
    *   清除TrustedPointerField。
    *   不安全地存储对象字段 (不使用写屏障)。
    *   存储共享对象的字段。
    *   存储对象的Map。
    *   存储FixedArray或PropertyArray的元素。
    *   存储FixedDoubleArray的元素。
    *   存储FeedbackVector的槽位。

3. **数组操作 (Array Operations):**
    *   确保数组可以进行push操作 (检查可扩展性和原型)。
    *   可能地增长数组的容量。
    *   构建并追加元素到JSArray。
    *   尝试存储数组元素，并根据元素类型进行检查。

4. **分配堆对象 (Heap Object Allocation):**
    *   分配Cell对象并设置值。
    *   分配HeapNumber对象并设置值。
    *   如果原始值是可变的原始类型，则克隆它。
    *   分配BigInt对象。
    *   分配ByteArray对象。
    *   分配SeqOneByteString和SeqTwoByteString对象。
    *   分配SlicedString对象。
    *   分配NameDictionary和PropertyDictionary (用于存储对象属性)。
    *   复制NameDictionary。
    *   分配OrderedHashTable (OrderedNameDictionary, OrderedHashSet, OrderedHashMap)。
    *   分配JSObject对象。
    *   初始化JSObject对象。
    *   不使用SlackTracking和使用SlackTracking两种方式初始化JSObject的body。
    *   不使用写屏障存储多个字段。
    *   将FixedArray标记为COW (Copy-on-Write)。

5. **辅助函数 (Helper Functions):**
    *   检查是否是零或者Context对象。
    *   检查是否是有效的快速JSArray容量。
    *   分配JSArray对象，可以指定元素、长度和分配位点。
    *   分配未初始化的JSArray对象。
    *   分配JSArray并填充初始值。
    *   从JSArray中提取子数组。
    *   克隆快速JSArray。

**与JavaScript的关系及举例：**

这些C++代码是V8引擎执行JavaScript代码的基础。 每当JavaScript引擎需要创建对象、访问对象属性、操作数组时，底层的C++代码就会被调用。

**JavaScript 示例：**

```javascript
// 1. 创建一个普通对象
const obj = {};

// 底层可能涉及到 AllocateJSObjectFromMap 和 StoreMap 等函数

// 2. 给对象添加属性
obj.name = "example";

// 底层可能涉及到 AllocateNameDictionary 或 AllocatePropertyDictionary,
// 以及 StoreObjectField 等函数

// 3. 创建一个数组并添加元素
const arr = [1, 2, 3];

// 底层可能涉及到 AllocateJSArray, AllocateFixedArray, 和 BuildAppendJSArray 等函数

// 4. 获取数组的长度
const length = arr.length;

// 底层可能涉及到 LoadFastJSArrayLength 等函数

// 5. 定义一个函数
function myFunction() {
  return 10;
}

// 底层可能涉及到 AllocateJSFunction, LoadJSFunctionCode,
// LoadSharedFunctionInfo 等函数

// 6. 调用函数
myFunction();

// 底层会使用加载的 Code 执行函数
```

**更具体的例子：**

当执行 `const arr = [1, 2, 3];` 时，V8可能会调用类似 `AllocateJSArray` 来分配 `JSArray` 对象本身，然后根据数组元素的类型（在这个例子中是Smi），可能会调用 `AllocateFixedArray` 来分配存储元素的 `FixedArray`。 接着，在初始化数组元素时，可能会调用 `StoreFixedArrayElement` 将 `1`, `2`, `3` 存储到 `FixedArray` 中。

当执行 `arr.push(4);` 时，V8可能会调用 `EnsureArrayPushable` 来检查数组是否可以扩展，然后调用 `PossiblyGrowElementsCapacity` 来检查并可能增加底层 `FixedArray` 的容量，最后调用 `BuildAppendJSArray` 将新元素 `4` 添加到数组中。

总之，这段C++代码是V8引擎中负责对象和数组的内存管理和属性操作的核心部分，是理解JavaScript底层运行机制的关键。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共12部分，请归纳一下它的功能
```

### 源代码
```
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
  Branch(IntPtrLessThanOrEqual(size, IntPtrConstant(kMaxRegularHeapObjectSize)),
         &if_sizeissmall, &if_notsizeissmall);

  BIND(&if_sizeissmall);
  {
    // Just allocate the ByteArray in new space.
    TNode<HeapObject> result =
        AllocateInNewSpace(UncheckedCast<IntPtrT>(size), flags);
    DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kByteArrayMap));
    StoreMapNoWriteBarrier(result, RootIndex::kByteArrayMap);
    StoreObjectFieldNoWriteBarrier(result, offsetof(ByteArray, length_),
                                   SmiTag(Signed(length)));
    var_result = result;
    Goto(&if_join);
  }

  BIND(&if_notsizeissmall);
  {
    // We might need to allocate in large object space, go to the runtime.
    TNode<Object> result =
        CallRuntime(Runtime::kAllocateByteArray, NoContextConstant(),
                    ChangeUintPtrToTagged(length));
    var_result = result;
    Goto(&if_join);
  }

  BIND(&if_lengthiszero);
  {
    var_result = EmptyByteArrayConstant();
    Goto(&if_join);
  }

  BIND(&if_join);
  return CAST(var_result.value());
}

TNode<String> CodeStubAssembler::AllocateSeqOneByteString(
    uint32_t length, AllocationFlags flags) {
  Comment("AllocateSeqOneByteString");
  if (length == 0) {
    return EmptyStringConstant();
  }
  TNode<HeapObject> result = Allocate(SeqOneByteString::SizeFor(length), flags);
  StoreNoWriteBarrier(MachineRepresentation::kTaggedSigned, result,
                      IntPtrConstant(SeqOneByteString::SizeFor(length) -
                                     kObjectAlignment - kHeapObjectTag),
                      SmiConstant(0));
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kSeqOneByteStringMap));
  StoreMapNoWriteBarrier(result, RootIndex::kSeqOneByteStringMap);
  StoreObjectFieldNoWriteBarrier(result, offsetof(SeqOneByteString, length_),
                                 Uint32Constant(length));
  StoreObjectFieldNoWriteBarrier(result,
                                 offsetof(SeqOneByteString, raw_hash_field_),
                                 Int32Constant(String::kEmptyHashField));
  return CAST(result);
}

TNode<BoolT> CodeStubAssembler::IsZeroOrContext(TNode<Object> object) {
  return Select<BoolT>(
      TaggedEqual(object, SmiConstant(0)),
      [=, this] { return Int32TrueConstant(); },
      [=, this] { return IsContext(CAST(object)); });
}

TNode<String> CodeStubAssembler::AllocateSeqTwoByteString(
    uint32_t length, AllocationFlags flags) {
  Comment("AllocateSeqTwoByteString");
  if (length == 0) {
    return EmptyStringConstant();
  }
  TNode<HeapObject> result = Allocate(SeqTwoByteString::SizeFor(length), flags);
  StoreNoWriteBarrier(MachineRepresentation::kTaggedSigned, result,
                      IntPtrConstant(SeqTwoByteString::SizeFor(length) -
                                     kObjectAlignment - kHeapObjectTag),
                      SmiConstant(0));
  DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kSeqTwoByteStringMap));
  StoreMapNoWriteBarrier(result, RootIndex::kSeqTwoByteStringMap);
  StoreObjectFieldNoWriteBarrier(result, offsetof(SeqTwoByteString, length_),
                                 Uint32Constant(length));
  StoreObjectFieldNoWriteBarrier(result,
                                 offsetof(SeqTwoByteString, raw_hash_field_),
                                 Int32Constant(String::kEmptyHashField));
  return CAST(result);
}

TNode<String> CodeStubAssembler::AllocateSlicedString(RootIndex map_root_index,
                                                      TNode<Uint32T> length,
                                                      TNode<String> parent,
                                                      TNode<Smi> offset) {
  DCHECK(map_root_index == RootIndex::kSlicedOneByteStringMap ||
         map_root_index == RootIndex::kSlicedTwoByteStringMap);
  TNode<HeapObject> result = Allocate(sizeof(SlicedString));
  DCHECK(RootsTable::IsImmortalImmovable(map_root_index));
  StoreMapNoWriteBarrier(result, map_root_index);
  StoreObjectFieldNoWriteBarrier(result,
                                 offsetof(SlicedString, raw_hash_field_),
                                 Int32Constant(String::kEmptyHashField));
  StoreObjectFieldNoWriteBarrier(result, offsetof(SlicedString, length_),
                                 length);
  StoreObjectFieldNoWriteBarrier(result, offsetof(SlicedString, parent_),
                                 parent);
  StoreObjectFieldNoWriteBarrier(result, offsetof(SlicedString, offset_),
                                 offset);
  return CAST(result);
}

TNode<String> CodeStubAssembler::AllocateSlicedOneByteString(
    TNode<Uint32T> length, TNode<String> parent, TNode<Smi> offset) {
  return AllocateSlicedString(RootIndex::kSlicedOneByteStringMap, length,
                              parent, offset);
}

TNode<String> CodeStubAssembler::AllocateSlicedTwoByteString(
    TNode<Uint32T> length, TNode<String> parent, TNode<Smi> offset) {
  return AllocateSlicedString(RootIndex::kSlicedTwoByteStringMap, length,
                              parent, offset);
}

TNode<NameDictionary> CodeStubAssembler::AllocateNameDictionary(
    int at_least_space_for) {
  return AllocateNameDictionary(IntPtrConstant(at_least_space_for));
}

TNode<NameDictionary> CodeStubAssembler::AllocateNameDictionary(
    TNode<IntPtrT> at_least_space_for, AllocationFlags flags) {
  CSA_DCHECK(this, UintPtrLessThanOrEqual(
                       at_least_space_for,
                       IntPtrConstant(NameDictionary::kMaxCapacity)));
  TNode<IntPtrT> capacity = HashTableComputeCapacity(at_least_space_for);
  return AllocateNameDictionaryWithCapacity(capacity, flags);
}

TNode<NameDictionary> CodeStubAssembler::AllocateNameDictionaryWithCapacity(
    TNode<IntPtrT> capacity, AllocationFlags flags) {
  CSA_DCHECK(this, WordIsPowerOfTwo(capacity));
  CSA_DCHECK(this, IntPtrGreaterThan(capacity, IntPtrConstant(0)));
  TNode<IntPtrT> length = EntryToIndex<NameDictionary>(capacity);
  TNode<IntPtrT> store_size =
      IntPtrAdd(TimesTaggedSize(length),
                IntPtrConstant(OFFSET_OF_DATA_START(NameDictionary)));

  TNode<NameDictionary> result =
      UncheckedCast<NameDictionary>(Allocate(store_size, flags));

  // Initialize FixedArray fields.
  {
    DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kNameDictionaryMap));
    StoreMapNoWriteBarrier(result, RootIndex::kNameDictionaryMap);
    StoreObjectFieldNoWriteBarrier(result, offsetof(NameDictionary, length_),
                                   SmiFromIntPtr(length));
  }

  // Initialized HashTable fields.
  {
    TNode<Smi> zero = SmiConstant(0);
    StoreFixedArrayElement(result, NameDictionary::kNumberOfElementsIndex, zero,
                           SKIP_WRITE_BARRIER);
    StoreFixedArrayElement(result,
                           NameDictionary::kNumberOfDeletedElementsIndex, zero,
                           SKIP_WRITE_BARRIER);
    StoreFixedArrayElement(result, NameDictionary::kCapacityIndex,
                           SmiTag(capacity), SKIP_WRITE_BARRIER);
    // Initialize Dictionary fields.
    StoreFixedArrayElement(result, NameDictionary::kNextEnumerationIndexIndex,
                           SmiConstant(PropertyDetails::kInitialIndex),
                           SKIP_WRITE_BARRIER);
    StoreFixedArrayElement(result, NameDictionary::kObjectHashIndex,
                           SmiConstant(PropertyArray::kNoHashSentinel),
                           SKIP_WRITE_BARRIER);
    StoreFixedArrayElement(result, NameDictionary::kFlagsIndex,
                           SmiConstant(NameDictionary::kFlagsDefault),
                           SKIP_WRITE_BARRIER);
  }

  // Initialize NameDictionary elements.
  {
    TNode<IntPtrT> result_word = BitcastTaggedToWord(result);
    TNode<IntPtrT> start_address = IntPtrAdd(
        result_word, IntPtrConstant(NameDictionary::OffsetOfElementAt(
                                        NameDictionary::kElementsStartIndex) -
                                    kHeapObjectTag));
    TNode<IntPtrT> end_address = IntPtrAdd(
        result_word, IntPtrSub(store_size, IntPtrConstant(kHeapObjectTag)));

    TNode<Undefined> filler = UndefinedConstant();
    DCHECK(RootsTable::IsImmortalImmovable(RootIndex::kUndefinedValue));

    StoreFieldsNoWriteBarrier(start_address, end_address, filler);
  }

  return result;
}

TNode<PropertyDictionary> CodeStubAssembler::AllocatePropertyDictionary(
    int at_least_space_for) {
  TNode<HeapObject> dict;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    dict = AllocateSwissNameDictionary(at_least_space_for);
  } else {
    dict = AllocateNameDictionary(at_least_space_for);
  }
  return TNode<PropertyDictionary>::UncheckedCast(dict);
}

TNode<PropertyDictionary> CodeStubAssembler::AllocatePropertyDictionary(
    TNode<IntPtrT> at_least_space_for, AllocationFlags flags) {
  TNode<HeapObject> dict;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    dict = AllocateSwissNameDictionary(at_least_space_for);
  } else {
    dict = AllocateNameDictionary(at_least_space_for, flags);
  }
  return TNode<PropertyDictionary>::UncheckedCast(dict);
}

TNode<PropertyDictionary>
CodeStubAssembler::AllocatePropertyDictionaryWithCapacity(
    TNode<IntPtrT> capacity, AllocationFlags flags) {
  TNode<HeapObject> dict;
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    dict = AllocateSwissNameDictionaryWithCapacity(capacity);
  } else {
    dict = AllocateNameDictionaryWithCapacity(capacity, flags);
  }
  return TNode<PropertyDictionary>::UncheckedCast(dict);
}

TNode<NameDictionary> CodeStubAssembler::CopyNameDictionary(
    TNode<NameDictionary> dictionary, Label* large_object_fallback) {
  Comment("Copy boilerplate property dict");
  TNode<IntPtrT> capacity =
      PositiveSmiUntag(GetCapacity<NameDictionary>(dictionary));
  CSA_DCHECK(this, IntPtrGreaterThanOrEqual(capacity, IntPtrConstant(0)));
  GotoIf(UintPtrGreaterThan(
             capacity, IntPtrConstant(NameDictionary::kMaxRegularCapacity)),
         large_object_fallback);
  TNode<NameDictionary> properties =
      AllocateNameDictionaryWithCapacity(capacity);
  TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(dictionary);
  CopyFixedArrayElements(PACKED_ELEMENTS, dictionary, properties, length,
                         SKIP_WRITE_BARRIER);
  return properties;
}

template <typename CollectionType>
TNode<CollectionType> CodeStubAssembler::AllocateOrderedHashTable(
    TNode<IntPtrT> capacity) {
  capacity = IntPtrRoundUpToPowerOfTwo32(capacity);
  capacity =
      IntPtrMax(capacity, IntPtrConstant(CollectionType::kInitialCapacity));
  return AllocateOrderedHashTableWithCapacity<CollectionType>(capacity);
}

template <typename CollectionType>
TNode<CollectionType> CodeStubAssembler::AllocateOrderedHashTableWithCapacity(
    TNode<IntPtrT> capacity) {
  CSA_DCHECK(this, WordIsPowerOfTwo(capacity));
  CSA_DCHECK(this,
             IntPtrGreaterThanOrEqual(
                 capacity, IntPtrConstant(CollectionType::kInitialCapacity)));
  CSA_DCHECK(this,
             IntPtrLessThanOrEqual(
                 capacity, IntPtrConstant(CollectionType::MaxCapacity())));

  static_assert(CollectionType::kLoadFactor == 2);
  TNode<IntPtrT> bucket_count = Signed(WordShr(capacity, IntPtrConstant(1)));
  TNode<IntPtrT> data_table_length =
      IntPtrMul(capacity, IntPtrConstant(CollectionType::kEntrySize));

  TNode<IntPtrT> data_table_start_index = IntPtrAdd(
      IntPtrConstant(CollectionType::HashTableStartIndex()), bucket_count);
  TNode<IntPtrT> fixed_array_length =
      IntPtrAdd(data_table_start_index, data_table_length);

  // Allocate the table and add the proper map.
  const ElementsKind elements_kind = HOLEY_ELEMENTS;
  TNode<Map> fixed_array_map =
      HeapConstantNoHole(CollectionType::GetMap(ReadOnlyRoots(isolate())));
  TNode<CollectionType> table =
      CAST(AllocateFixedArray(elements_kind, fixed_array_length,
                              AllocationFlag::kNone, fixed_array_map));

  Comment("Initialize the OrderedHashTable fields.");
  const WriteBarrierMode barrier_mode = SKIP_WRITE_BARRIER;
  UnsafeStoreFixedArrayElement(table, CollectionType::NumberOfElementsIndex(),
                               SmiConstant(0), barrier_mode);
  UnsafeStoreFixedArrayElement(table,
                               CollectionType::NumberOfDeletedElementsIndex(),
                               SmiConstant(0), barrier_mode);
  UnsafeStoreFixedArrayElement(table, CollectionType::NumberOfBucketsIndex(),
                               SmiFromIntPtr(bucket_count), barrier_mode);

  TNode<IntPtrT> object_address = BitcastTaggedToWord(table);

  static_assert(CollectionType::HashTableStartIndex() ==
                CollectionType::NumberOfBucketsIndex() + 1);

  TNode<Smi> not_found_sentinel = SmiConstant(CollectionType::kNotFound);

  intptr_t const_capacity;
  if (TryToIntPtrConstant(capacity, &const_capacity) &&
      const_capacity == CollectionType::kInitialCapacity) {
    int const_bucket_count =
        static_cast<int>(const_capacity / CollectionType::kLoadFactor);
    int const_data_table_length =
        static_cast<int>(const_capacity * CollectionType::kEntrySize);
    int const_data_table_start_index = static_cast<int>(
        CollectionType::HashTableStartIndex() + const_bucket_count);

    Comment("Fill the buckets with kNotFound (constant capacity).");
    for (int i = 0; i < const_bucket_count; i++) {
      UnsafeStoreFixedArrayElement(table,
                                   CollectionType::HashTableStartIndex() + i,
                                   not_found_sentinel, barrier_mode);
    }

    Comment("Fill the data table with undefined (constant capacity).");
    for (int i = 0; i < const_data_table_length; i++) {
      UnsafeStoreFixedArrayElement(table, const_data_table_start_index + i,
                                   UndefinedConstant(), barrier_mode);
    }
  } else {
    Comment("Fill the buckets with kNotFound.");
    TNode<IntPtrT> buckets_start_address =
        IntPtrAdd(object_address,
                  IntPtrConstant(FixedArray::OffsetOfElementAt(
                                     CollectionType::HashTableStartIndex()) -
                                 kHeapObjectTag));
    TNode<IntPtrT> buckets_end_address =
        IntPtrAdd(buckets_start_address, TimesTaggedSize(bucket_count));

    StoreFieldsNoWriteBarrier(buckets_start_address, buckets_end_address,
                              not_found_sentinel);

    Comment("Fill the data table with undefined.");
    TNode<IntPtrT> data_start_address = buckets_end_address;
    TNode<IntPtrT> data_end_address = IntPtrAdd(
        object_address,
        IntPtrAdd(
            IntPtrConstant(OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag),
            TimesTaggedSize(fixed_array_length)));

    StoreFieldsNoWriteBarrier(data_start_address, data_end_address,
                              UndefinedConstant());

#ifdef DEBUG
    TNode<IntPtrT> ptr_diff =
        IntPtrSub(data_end_address, buckets_start_address);
    TNode<IntPtrT> array_length = LoadAndUntagFixedArrayBaseLength(table);
    TNode<IntPtrT> array_data_fields = IntPtrSub(
        array_length, IntPtrConstant(CollectionType::HashTableStartIndex()));
    TNode<IntPtrT> expected_end =
        IntPtrAdd(data_start_address,
                  TimesTaggedSize(IntPtrMul(
                      capacity, IntPtrConstant(CollectionType::kEntrySize))));

    CSA_DCHECK(this, IntPtrEqual(ptr_diff, TimesTaggedSize(array_data_fields)));
    CSA_DCHECK(this, IntPtrEqual(expected_end, data_end_address));
#endif
  }

  return table;
}

TNode<OrderedNameDictionary> CodeStubAssembler::AllocateOrderedNameDictionary(
    TNode<IntPtrT> capacity) {
  TNode<OrderedNameDictionary> table =
      AllocateOrderedHashTable<OrderedNameDictionary>(capacity);
  StoreFixedArrayElement(table, OrderedNameDictionary::PrefixIndex(),
                         SmiConstant(PropertyArray::kNoHashSentinel),
                         SKIP_WRITE_BARRIER);
  return table;
}

TNode<OrderedNameDictionary> CodeStubAssembler::AllocateOrderedNameDictionary(
    int capacity) {
  return AllocateOrderedNameDictionary(IntPtrConstant(capacity));
}

TNode<OrderedHashSet> CodeStubAssembler::AllocateOrderedHashSet() {
  return AllocateOrderedHashTableWithCapacity<OrderedHashSet>(
      IntPtrConstant(OrderedHashSet::kInitialCapacity));
}

TNode<OrderedHashSet> CodeStubAssembler::AllocateOrderedHashSet(
    TNode<IntPtrT> capacity) {
  return AllocateOrderedHashTableWithCapacity<OrderedHashSet>(capacity);
}

TNode<OrderedHashMap> CodeStubAssembler::AllocateOrderedHashMap() {
  return AllocateOrderedHashTableWithCapacity<OrderedHashMap>(
      IntPtrConstant(OrderedHashMap::kInitialCapacity));
}

TNode<JSObject> CodeStubAssembler::AllocateJSObjectFromMap(
    TNode<Map> map, std::optional<TNode<HeapObject>> properties,
    std::optional<TNode<FixedArray>> elements, AllocationFlags flags,
    SlackTrackingMode slack_tracking_mode) {
  CSA_DCHECK(this, Word32BinaryNot(IsJSFunctionMap(map)));
  CSA_DCHECK(this, Word32BinaryNot(InstanceTypeEqual(LoadMapInstanceType(map),
                                                     JS_GLOBAL_OBJECT_TYPE)));
  TNode<IntPtrT> instance_size =
      TimesTaggedSize(LoadMapInstanceSizeInWords(map));
  TNode<HeapObject> object = AllocateInNewSpace(instance_size, flags);
  StoreMapNoWriteBarrier(object, map);
  InitializeJSObjectFromMap(object, map, instance_size, properties, elements,
                            slack_tracking_mode);
  return CAST(object);
}

void CodeStubAssembler::InitializeJSObjectFromMap(
    TNode<HeapObject> object, TNode<Map> map, TNode<IntPtrT> instance_size,
    std::optional<TNode<HeapObject>> properties,
    std::optional<TNode<FixedArray>> elements,
    SlackTrackingMode slack_tracking_mode) {
  // This helper assumes that the object is in new-space, as guarded by the
  // check in AllocatedJSObjectFromMap.
  if (!properties) {
    CSA_DCHECK(this, Word32BinaryNot(IsDictionaryMap((map))));
    StoreObjectFieldRoot(object, JSObject::kPropertiesOrHashOffset,
                         RootIndex::kEmptyFixedArray);
  } else {
    CSA_DCHECK(this, Word32Or(Word32Or(IsPropertyArray(*properties),
                                       IsPropertyDictionary(*properties)),
                              IsEmptyFixedArray(*properties)));
    StoreObjectFieldNoWriteBarrier(object, JSObject::kPropertiesOrHashOffset,
                                   *properties);
  }
  if (!elements) {
    StoreObjectFieldRoot(object, JSObject::kElementsOffset,
                         RootIndex::kEmptyFixedArray);
  } else {
    StoreObjectFieldNoWriteBarrier(object, JSObject::kElementsOffset,
                                   *elements);
  }
  switch (slack_tracking_mode) {
    case SlackTrackingMode::kDontInitializeInObjectProperties:
      return;
    case kNoSlackTracking:
      return InitializeJSObjectBodyNoSlackTracking(object, map, instance_size);
    case kWithSlackTracking:
      return InitializeJSObjectBodyWithSlackTracking(object, map,
                                                     instance_size);
  }
}

void CodeStubAssembler::InitializeJSObjectBodyNoSlackTracking(
    TNode<HeapObject> object, TNode<Map> map, TNode<IntPtrT> instance_size,
    int start_offset) {
  static_assert(Map::kNoSlackTracking == 0);
  CSA_DCHECK(this, IsClearWord32<Map::Bits3::ConstructionCounterBits>(
                       LoadMapBitField3(map)));
  InitializeFieldsWithRoot(object, IntPtrConstant(start_offset), instance_size,
                           RootIndex::kUndefinedValue);
}

void CodeStubAssembler::InitializeJSObjectBodyWithSlackTracking(
    TNode<HeapObject> object, TNode<Map> map, TNode<IntPtrT> instance_size) {
  Comment("InitializeJSObjectBodyNoSlackTracking");

  // Perform in-object slack tracking if requested.
  int start_offset = JSObject::kHeaderSize;
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  Label end(this), slack_tracking(this), complete(this, Label::kDeferred);
  static_assert(Map::kNoSlackTracking == 0);
  GotoIf(IsSetWord32<Map::Bits3::ConstructionCounterBits>(bit_field3),
         &slack_tracking);
  Comment("No slack tracking");
  InitializeJSObjectBodyNoSlackTracking(object, map, instance_size);
  Goto(&end);

  BIND(&slack_tracking);
  {
    Comment("Decrease construction counter");
    // Slack tracking is only done on initial maps.
    CSA_DCHECK(this, IsUndefined(LoadMapBackPointer(map)));
    static_assert(Map::Bits3::ConstructionCounterBits::kLastUsedBit == 31);
    TNode<Word32T> new_bit_field3 = Int32Sub(
        bit_field3,
        Int32Constant(1 << Map::Bits3::ConstructionCounterBits::kShift));

    // The object still has in-object slack therefore the |unsed_or_unused|
    // field contain the "used" value.
    TNode<IntPtrT> used_size =
        Signed(TimesTaggedSize(ChangeUint32ToWord(LoadObjectField<Uint8T>(
            map, Map::kUsedOrUnusedInstanceSizeInWordsOffset))));

    Comment("Initialize filler fields");
    InitializeFieldsWithRoot(object, used_size, instance_size,
                             RootIndex::kOnePointerFillerMap);

    Comment("Initialize undefined fields");
    InitializeFieldsWithRoot(object, IntPtrConstant(start_offset), used_size,
                             RootIndex::kUndefinedValue);

    static_assert(Map::kNoSlackTracking == 0);
    GotoIf(IsClearWord32<Map::Bits3::ConstructionCounterBits>(new_bit_field3),
           &complete);

    // Setting ConstructionCounterBits to 0 requires taking the
    // map_updater_access mutex, which we can't do from CSA, so we only manually
    // update ConstructionCounterBits when its result is non-zero; otherwise we
    // let the runtime do it (with the GotoIf right above this comment).
    StoreObjectFieldNoWriteBarrier(map, Map::kBitField3Offset, new_bit_field3);
    static_assert(Map::kSlackTrackingCounterEnd == 1);

    Goto(&end);
  }

  // Finalize the instance size.
  BIND(&complete);
  {
    // ComplextInobjectSlackTracking doesn't allocate and thus doesn't need a
    // context.
    CallRuntime(Runtime::kCompleteInobjectSlackTrackingForMap,
                NoContextConstant(), map);
    Goto(&end);
  }

  BIND(&end);
}

void CodeStubAssembler::StoreFieldsNoWriteBarrier(TNode<IntPtrT> start_address,
                                                  TNode<IntPtrT> end_address,
                                                  TNode<Object> value) {
  Comment("StoreFieldsNoWriteBarrier");
  CSA_DCHECK(this, WordIsAligned(start_address, kTaggedSize));
  CSA_DCHECK(this, WordIsAligned(end_address, kTaggedSize));
  BuildFastLoop<IntPtrT>(
      start_address, end_address,
      [=, this](TNode<IntPtrT> current) {
        UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged, current,
                                  value);
      },
      kTaggedSize, LoopUnrollingMode::kYes, IndexAdvanceMode::kPost);
}

void CodeStubAssembler::MakeFixedArrayCOW(TNode<FixedArray> array) {
  CSA_DCHECK(this, IsFixedArrayMap(LoadMap(array)));
  Label done(this);
  // The empty fixed array is not modifiable anyway. And we shouldn't change its
  // Map.
  GotoIf(TaggedEqual(array, EmptyFixedArrayConstant()), &done);
  StoreMap(array, FixedCOWArrayMapConstant());
  Goto(&done);
  BIND(&done);
}

TNode<BoolT> CodeStubAssembler::IsValidFastJSArrayCapacity(
    TNode<IntPtrT> capacity) {
  return UintPtrLessThanOrEqual(capacity,
                                UintPtrConstant(JSArray::kMaxFastArrayLength));
}

TNode<JSArray> CodeStubAssembler::AllocateJSArray(
    TNode<Map> array_map, TNode<FixedArrayBase> elements, TNode<Smi> length,
    std::optional<TNode<AllocationSite>> allocation_site,
    int array_header_size) {
  Comment("begin allocation of JSArray passing in elements");
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));

  int base_size = array_header_size;
  if (allocation_site) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    base_size += ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
  }

  TNode<IntPtrT> size = IntPtrConstant(base_size);
  TNode<JSArray> result =
      AllocateUninitializedJSArray(array_map, length, allocation_site, size);
  StoreObjectFieldNoWriteBarrier(result, JSArray::kElementsOffset, elements);
  return result;
}

namespace {

// To prevent GC between the array and elements allocation, the elements
// object allocation is folded together with the js-array allocation.
TNode<FixedArrayBase> InnerAllocateElements(CodeStubAssembler* csa,
                                            TNode<JSArray> js_array,
                                            int offset) {
  return csa->UncheckedCast<FixedArrayBase>(
      csa->BitcastWordToTagged(csa->IntPtrAdd(
          csa->BitcastTaggedToWord(js_array), csa->IntPtrConstant(offset))));
}

}  // namespace

TNode<IntPtrT> CodeStubAssembler::AlignToAllocationAlignment(
    TNode<IntPtrT> value) {
  if (!V8_COMPRESS_POINTERS_8GB_BOOL) return value;

  Label not_aligned(this), is_aligned(this);
  TVARIABLE(IntPtrT, result, value);

  Branch(WordIsAligned(value, kObjectAlignment8GbHeap), &is_aligned,
         &not_aligned);

  BIND(&not_aligned);
  {
    if (kObjectAlignment8GbHeap == 2 * kTaggedSize) {
      result = IntPtrAdd(value, IntPtrConstant(kTaggedSize));
    } else {
      result =
          WordAnd(IntPtrAdd(value, IntPtrConstant(kObjectAlignment8GbHeapMask)),
                  IntPtrConstant(~kObjectAlignment8GbHeapMask));
    }
    Goto(&is_aligned);
  }

  BIND(&is_aligned);
  return result.value();
}

std::pair<TNode<JSArray>, TNode<FixedArrayBase>>
CodeStubAssembler::AllocateUninitializedJSArrayWithElements(
    ElementsKind kind, TNode<Map> array_map, TNode<Smi> length,
    std::optional<TNode<AllocationSite>> allocation_site,
    TNode<IntPtrT> capacity, AllocationFlags allocation_flags,
    int array_header_size) {
  Comment("begin allocation of JSArray with elements");
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));

  TVARIABLE(JSArray, array);
  TVARIABLE(FixedArrayBase, elements);

  Label out(this), empty(this), nonempty(this);

  int capacity_int;
  if (TryToInt32Constant(capacity, &capacity_int)) {
    if (capacity_int == 0) {
      TNode<FixedArray> empty_array = EmptyFixedArrayConstant();
      array = AllocateJSArray(array_map, empty_array, length, allocation_site,
                              array_header_size);
      return {array.value(), empty_array};
    } else {
      Goto(&nonempty);
    }
  } else {
    Branch(WordEqual(capacity, IntPtrConstant(0)), &empty, &nonempty);

    BIND(&empty);
    {
      TNode<FixedArray> empty_array = EmptyFixedArrayConstant();
      array = AllocateJSArray(array_map, empty_array, length, allocation_site,
                              array_header_size);
      elements = empty_array;
      Goto(&out);
    }
  }

  BIND(&nonempty);
  {
    int base_size = ALIGN_TO_ALLOCATION_ALIGNMENT(array_header_size);
    if (allocation_site) {
      DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
      base_size += ALIGN_TO_ALLOCATION_ALIGNMENT(AllocationMemento::kSize);
    }

    const int elements_offset = base_size;

    // Compute space for elements
    base_size += OFFSET_OF_DATA_START(FixedArray);
    TNode<IntPtrT> size = AlignToAllocationAlignment(
        ElementOffsetFromIndex(capacity, kind, base_size));

    // For very large arrays in which the requested allocation exceeds the
    // maximal size of a regular heap object, we cannot use the allocation
    // folding trick. Instead, we first allocate the elements in large object
    // space, and then allocate the JSArray (and possibly the allocation
    // memento) in new space.
    Label next(this);
    GotoIf(IsRegularHeapObjectSize(size), &next);

    CSA_CHECK(this, IsValidFastJSArrayCapacity(capacity));

    // Allocate and initialize the elements first. Full initialization is
    // needed because the upcoming JSArray allocation could trigger GC.
    elements = AllocateFixedArray(kind, capacity, allocation_flags);

    if (IsDoubleElementsKind(kind)) {
      FillEntireFixedDoubleArrayWithZero(CAST(elements.value()), capacity);
    } else {
      FillEntireFixedArrayWithSmiZero(kind, CAST(elements.value()), capacity);
    }

    // The JSArray and possibly allocation memento next. Note that
    // allocation_flags are *not* passed on here and the resulting JSArray
    // will always be in new space.
    array = AllocateJSArray(array_map, elements.value(), length,
                            allocation_site, array_header_size);

    Goto(&out);

    BIND(&next);

    // Fold all objects into a single new space allocation.
    array =
        AllocateUninitializedJSArray(array_map, length, allocation_site, size);
    elements = InnerAllocateElements(this, array.value(), elements_offset);

    StoreObjectFieldNoWriteBarrier(array.value(), JSObject::kElementsOffset,
                                   elements.value());

    // Setup elements object.
    static_assert(FixedArrayBase::kHeaderSize == 2 * kTaggedSize);
    RootIndex elements_map_index = IsDoubleElementsKind(kind)
                                       ? RootIndex::kFixedDoubleArrayMap
                                       : RootIndex::kFixedArrayMap;
    DCHECK(RootsTable::IsImmortalImmovable(elements_map_index));
    StoreMapNoWriteBarrier(elements.value(), elements_map_index);

    CSA_DCHECK(this, WordNotEqual(capacity, IntPtrConstant(0)));
    TNode<Smi> capacity_smi = SmiTag(capacity);
    StoreObjectFieldNoWriteBarrier(elements.value(),
                                   offsetof(FixedArray, length_), capacity_smi);
    Goto(&out);
  }

  BIND(&out);
  return {array.value(), elements.value()};
}

TNode<JSArray> CodeStubAssembler::AllocateUninitializedJSArray(
    TNode<Map> array_map, TNode<Smi> length,
    std::optional<TNode<AllocationSite>> allocation_site,
    TNode<IntPtrT> size_in_bytes) {
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));

  // Allocate space for the JSArray and the elements FixedArray in one go.
  TNode<HeapObject> array = AllocateInNewSpace(size_in_bytes);

  StoreMapNoWriteBarrier(array, array_map);
  StoreObjectFieldNoWriteBarrier(array, JSArray::kLengthOffset, length);
  StoreObjectFieldRoot(array, JSArray::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);

  if (allocation_site) {
    DCHECK(V8_ALLOCATION_SITE_TRACKING_BOOL);
    InitializeAllocationMemento(
        array,
        IntPtrConstant(ALIGN_TO_ALLOCATION_ALIGNMENT(JSArray::kHeaderSize)),
        *allocation_site);
  }

  return CAST(array);
}

TNode<JSArray> CodeStubAssembler::AllocateJSArray(
    ElementsKind kind, TNode<Map> array_map, TNode<IntPtrT> capacity,
    TNode<Smi> length, std::optional<TNode<AllocationSite>> allocation_site,
    AllocationFlags allocation_flags) {
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));

  TNode<JSArray> array;
  TNode<FixedArrayBase> elements;

  std::tie(array, elements) = AllocateUninitializedJSArrayWithElements(
      kind, array_map, length, allocation_site, capacity, allocation_flags);

  Label out(this), nonempty(this);

  Branch(WordEqual(capacity, IntPtrConstant(0)), &out, &nonempty);

  BIND(&nonempty);
  {
    FillFixedArrayWithValue(kind, elements, IntPtrConstant(0), capacity,
                            RootIndex::kTheHoleValue);
    Goto(&out);
  }

  BIND(&out);
  return array;
}

TNode<JSArray> CodeStubAssembler::ExtractFastJSArray(TNode<Context> context,
                                                     TNode<JSArray> array,
                                                     TNode<BInt> begin,
                                                     TNode<BInt> count) {
  TNode<Map> original_array_map = LoadMap(array);
  TNode<Int32T> elements_kind = LoadMapElementsKind(original_array_map);

  // Use the canonical map for the Array's ElementsKind
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> array_map = LoadJSArrayElementsMap(elements_kind, native_context);

  TNode<FixedArrayBase> new_elements = ExtractFixedArray(
      LoadElements(array), std::optional<TNode<BInt>>(begin),
      std::optional<TNode<BInt>>(count),
      std::optional<TNode<BInt>>(std::nullopt),
      ExtractFixedArrayFlag::kAllFixedArrays, nullptr, elements_kind);

  TNode<JSArray> result = AllocateJSArray(
      array_map, new_elements, ParameterToTagged(count), std::nullopt);
  return result;
}

TNode<JSArray> CodeStubAssembler::CloneFastJSArray(
    TNode<Context> context, TNode<JSArray> array,
    std::optional<TNode<AllocationSite>> allocation_site,
    HoleConversionMode convert_holes) {
  // TODO(dhai): we should be able to assert IsFastJSArray(array) here, but this
  // function is also used to copy boilerplates even when the no-elemen
```