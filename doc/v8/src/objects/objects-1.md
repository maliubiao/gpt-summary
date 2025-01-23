Response: The user wants to understand the functionality of the C++ code in `v8/src/objects/objects.cc`, specifically the second part of the file.

The code deals with various aspects of JavaScript object behavior, including:
- **Species Constructor**: Determining the constructor to use for derived objects.
- **Iteration Effects**: Checking if iterating over an object has observable side effects.
- **Code-like Objects**: Identifying objects that can be treated as code.
- **Object Representation**: Printing short representations of objects for debugging.
- **Object Size**: Calculating the size of various heap objects.
- **Object Rehashing**: Managing the internal hash tables of objects.
- **Property Access**: Implementing the `SetProperty` and `SetSuperProperty` operations.
- **Property Definition**: Handling the `AddDataProperty` and `TransitionAndWriteDataProperty` logic.
- **Read-Only Properties**:  Managing attempts to write to read-only properties.
- **Shared Objects**:  Handling the creation of shared objects for inter-isolate communication.
- **Accessor Information**: Managing accessor properties.
- **JSProxy**: Implementing the behavior of JavaScript Proxy objects, including `Revoke`, `IsArray`, `HasProperty`, `SetProperty`, `DeletePropertyOrElement`, and `DefineOwnProperty`.
- **JSArray**: Implementing the `DefineOwnProperty` and `ArraySetLength` operations for arrays.

I will summarize these functionalities, highlighting their connection to JavaScript features and providing relevant JavaScript examples.
这是 `v8/src/objects/objects.cc` 文件第二部分的代码，主要负责实现 JavaScript 对象的各种核心操作和行为。以下是其功能的归纳：

**主要功能归纳:**

1. **`SpeciesConstructor`**:  这个函数用于确定一个对象在进行某些操作（例如 `Array.prototype.slice`）时应该使用的构造函数。它遵循 ES6 规范中定义的 "Species" 模式。

2. **`IterationHasObservableEffects`**:  这个函数判断对一个对象进行迭代是否会产生可观察的副作用。这在 V8 优化迭代过程时非常重要。例如，对于普通的 `Array`，如果其原型链没有被修改，并且其元素是紧凑排列的，那么迭代可以被优化为简单的顺序访问。

3. **`IsCodeLike`**:  判断一个对象是否可以被当作代码来执行。这通常用于判断是否是函数或者其他可调用的对象。

4. **对象打印辅助函数 (`ShortPrint`, `Brief`)**:  提供了一系列用于打印对象简洁表示形式的函数，主要用于调试和日志输出。

5. **`HeapObject::SizeFromMap`**:  计算各种 V8 堆对象的实际大小。由于 V8 中存在多种类型的对象，并且有些对象的大小是动态的（例如数组），这个函数根据对象的 `Map` 信息来确定其大小。

6. **对象哈希管理 (`NeedsRehashing`, `CanBeRehashed`, `RehashBasedOnMap`)**:  V8 使用哈希表来存储对象的属性。这些函数用于判断对象是否需要重新哈希（例如，当哈希表过于拥挤时），以及执行实际的重新哈希操作。

7. **属性设置核心逻辑 (`SetPropertyInternal`)**:  这是设置对象属性的核心实现，处理各种情况，包括访问器属性、拦截器、代理等。

8. **`SetProperty` 和 `SetSuperProperty`**:  实现了 JavaScript 中设置对象属性的操作。`SetProperty` 用于普通的对象属性设置，而 `SetSuperProperty` 用于设置原型链上的属性。

9. **`AddDataProperty` 和 `TransitionAndWriteDataProperty`**:  实现了向对象添加新的数据属性的逻辑。`TransitionAndWriteDataProperty` 涉及到对象的形状（`Map`）转换，以适应新属性的添加。

10. **只读属性处理 (`WriteToReadOnlyProperty`)**:  处理尝试写入只读属性的情况，根据严格模式与否抛出错误或静默失败。

11. **共享对象 (`ShareSlow`)**:  用于创建可以在不同 Isolate 之间共享的对象。

12. **访问器信息管理 (`AccessorInfo::AppendUnique`)**:  用于管理访问器属性的信息，确保不会重复添加相同的访问器。

13. **`JSProxy` 实现**:  实现了 JavaScript `Proxy` 对象的各种行为，包括：
    - `Revoke`: 撤销代理。
    - `IsArray`: 检查代理是否表现得像一个数组。
    - `HasProperty`:  实现 `in` 操作符的代理行为。
    - `SetProperty`: 实现属性赋值的代理行为。
    - `DeletePropertyOrElement`: 实现 `delete` 操作符的代理行为。
    - `DefineOwnProperty`: 实现 `Object.defineProperty` 的代理行为。
    - `New`: 创建新的 `JSProxy` 对象。
    - `GetPropertyAttributes`: 获取代理属性的属性描述符。
    - `SetPrivateSymbol`: 设置代理对象的私有 Symbol 属性。

14. **`JSArray` 的 `DefineOwnProperty` 和 `ArraySetLength`**:  实现了数组的 `Object.defineProperty` 操作以及设置数组 `length` 属性的特殊逻辑。

**与 JavaScript 功能的关联及 JavaScript 示例:**

**1. `SpeciesConstructor`**

```javascript
class MyArray extends Array {
  static get [Symbol.species]() { return Array; }
}

const myArray = new MyArray(1, 2, 3);
const slicedArray = myArray.slice(1); // slicedArray 是 Array 的实例，而不是 MyArray
console.log(slicedArray instanceof Array); // true
console.log(slicedArray instanceof MyArray); // false
```
这个例子展示了 `Symbol.species` 如何影响 `slice` 方法返回的对象类型。`SpeciesConstructor` 在 V8 内部负责查找和使用 `Symbol.species` 指定的构造函数。

**2. `IterationHasObservableEffects`**

```javascript
const arr = [1, 2, 3];
for (const element of arr) {
  console.log(element);
}

// 如果 arr 的原型被修改，例如：
Array.prototype.customProperty = 'test';
for (const element of arr) {
  console.log(element); // 现在可能会访问到 customProperty，产生了不同的效果
}
```
`IterationHasObservableEffects` 帮助 V8 判断第一种情况的迭代可以进行优化，而第二种情况则不能。

**3. `IsCodeLike`**

```javascript
function myFunction() {}
const obj = {};

console.log(typeof myFunction); // "function"
console.log(typeof obj);        // "object"
```
`IsCodeLike` 用于 V8 内部区分函数（可以执行的代码）和其他类型的对象。

**4. 对象打印辅助函数**

这些函数主要用于 V8 内部的调试，在 JavaScript 中没有直接对应的功能，但开发者可以通过 `console.log` 等方法间接观察到 V8 使用的类似输出。

**5. `HeapObject::SizeFromMap`**

在 JavaScript 中无法直接获取对象在内存中的大小，但 V8 内部使用此函数来管理内存分配和垃圾回收。

**6. 对象哈希管理**

JavaScript 对象底层的属性存储依赖于哈希表。当对象属性数量增加或键的分布不均匀时，V8 会进行重新哈希以提高性能。这个过程对 JavaScript 开发者是透明的。

**7. `SetProperty` 和 `SetSuperProperty`**

```javascript
const obj = {};
obj.name = 'John'; // 使用 SetProperty

class Parent {
  constructor() {
    this.parentProperty = 'parent';
  }
}

class Child extends Parent {
  constructor() {
    super();
  }
  set parentProperty(value) {
    super.parentProperty = value; // 使用 SetSuperProperty
  }
}

const child = new Child();
child.parentProperty = 'newParent';
```
这两个函数对应 JavaScript 中直接赋值属性和在派生类中通过 `super` 关键字设置父类属性的操作。

**8. `AddDataProperty` 和 `TransitionAndWriteDataProperty`**

```javascript
const obj = {};
obj.age = 30; // V8 可能会进行 Map 的转换来添加新的属性

Object.defineProperty(obj, 'city', { value: 'New York' }); // 也会触发类似的内部过程
```
当向对象添加新属性时，V8 内部会使用这些函数来更新对象的内部结构。

**9. 只读属性处理**

```javascript
const obj = {};
Object.defineProperty(obj, 'constant', { value: 100, writable: false });

obj.constant = 200; // 在非严格模式下静默失败
'use strict';
obj.constant = 300; // 在严格模式下抛出 TypeError
```
`WriteToReadOnlyProperty` 负责实现这种行为。

**10. `JSProxy` 实现**

```javascript
const target = { name: 'original' };
const handler = {
  get(target, prop) {
    console.log(`读取属性: ${prop}`);
    return target[prop];
  },
  set(target, prop, value) {
    console.log(`设置属性: ${prop} 为 ${value}`);
    target[prop] = value;
    return true;
  }
};

const proxy = new Proxy(target, handler);
console.log(proxy.name);
proxy.name = 'proxy';
```
这段代码展示了 `Proxy` 的基本用法。`JSProxy` 的各个方法在 V8 内部实现了 `Proxy` 的拦截行为。

**11. `JSArray` 的 `DefineOwnProperty` 和 `ArraySetLength`**

```javascript
const arr = [1, 2, 3];
Object.defineProperty(arr, 'length', { value: 5 }); // 使用 DefineOwnProperty 设置 length
console.log(arr); // 输出 [ 1, 2, 3, <2 empty items> ]

arr.length = 2; // 使用 ArraySetLength 改变 length
console.log(arr); // 输出 [ 1, 2 ]
```
这些函数处理了数组 `length` 属性的特殊行为，包括截断数组和扩展数组。

总而言之，`v8/src/objects/objects.cc` 的这部分代码是 V8 引擎中实现 JavaScript 对象核心特性的关键组成部分，它直接影响着 JavaScript 代码的执行和行为。理解这些内部机制有助于更深入地理解 JavaScript 的运行原理和 V8 的优化策略。

### 提示词
```
这是目录为v8/src/objects/objects.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```
te)) {
        constructor = isolate->factory()->undefined_value();
      }
    }
  }
  if (IsUndefined(*constructor, isolate)) {
    return default_species;
  } else {
    if (!IsConstructor(*constructor)) {
      THROW_NEW_ERROR(isolate,
                      NewTypeError(MessageTemplate::kSpeciesNotConstructor));
    }
    return constructor;
  }
}

// ES6 section 7.3.20 SpeciesConstructor ( O, defaultConstructor )
V8_WARN_UNUSED_RESULT MaybeHandle<Object> Object::SpeciesConstructor(
    Isolate* isolate, Handle<JSReceiver> recv,
    Handle<JSFunction> default_ctor) {
  Handle<Object> ctor_obj;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, ctor_obj,
      JSObject::GetProperty(isolate, recv,
                            isolate->factory()->constructor_string()));

  if (IsUndefined(*ctor_obj, isolate)) return default_ctor;

  if (!IsJSReceiver(*ctor_obj)) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kConstructorNotReceiver));
  }

  Handle<JSReceiver> ctor = Cast<JSReceiver>(ctor_obj);

  Handle<Object> species;
  ASSIGN_RETURN_ON_EXCEPTION(
      isolate, species,
      JSObject::GetProperty(isolate, ctor,
                            isolate->factory()->species_symbol()));

  if (IsNullOrUndefined(*species, isolate)) {
    return default_ctor;
  }

  if (IsConstructor(*species)) return species;

  THROW_NEW_ERROR(isolate,
                  NewTypeError(MessageTemplate::kSpeciesNotConstructor));
}

// static
bool Object::IterationHasObservableEffects(Tagged<Object> obj) {
  DisallowGarbageCollection no_gc;
  // Check that this object is an array.
  if (!IsJSArray(obj)) return true;
  Tagged<JSArray> array = Cast<JSArray>(obj);

  // Check that we have the original ArrayPrototype.
  Tagged<Object> array_proto = array->map()->prototype();
  if (!IsJSObject(array_proto)) return true;
  Tagged<NativeContext> native_context = array->GetCreationContext().value();
  auto initial_array_prototype = native_context->initial_array_prototype();
  if (initial_array_prototype != array_proto) return true;

  Isolate* isolate = array->GetIsolate();
  // Check that the ArrayPrototype hasn't been modified in a way that would
  // affect iteration.
  if (!Protectors::IsArrayIteratorLookupChainIntact(isolate)) return true;

  // For FastPacked kinds, iteration will have the same effect as simply
  // accessing each property in order.
  ElementsKind array_kind = array->GetElementsKind();
  if (IsFastPackedElementsKind(array_kind)) return false;

  // For FastHoley kinds, an element access on a hole would cause a lookup on
  // the prototype. This could have different results if the prototype has been
  // changed.
  if (IsHoleyElementsKind(array_kind) &&
      Protectors::IsNoElementsIntact(isolate)) {
    return false;
  }
  return true;
}

// static
bool Object::IsCodeLike(Tagged<Object> obj, Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  return IsJSReceiver(obj) && Cast<JSReceiver>(obj)->IsCodeLike(isolate);
}

void ShortPrint(Tagged<Object> obj, FILE* out) {
  OFStream os(out);
  os << Brief(obj);
}

void ShortPrint(Tagged<Object> obj, StringStream* accumulator) {
  std::ostringstream os;
  os << Brief(obj);
  accumulator->Add(os.str().c_str());
}

void ShortPrint(Tagged<Object> obj, std::ostream& os) { os << Brief(obj); }

std::ostream& operator<<(std::ostream& os, Tagged<Object> obj) {
  ShortPrint(obj, os);
  return os;
}

std::ostream& operator<<(std::ostream& os, Object::Conversion kind) {
  switch (kind) {
    case Object::Conversion::kToNumber:
      return os << "ToNumber";
    case Object::Conversion::kToNumeric:
      return os << "ToNumeric";
  }
  UNREACHABLE();
}

std::ostream& operator<<(std::ostream& os, const Brief& v) {
  Tagged<MaybeObject> maybe_object(v.value);
  Tagged<Smi> smi;
  Tagged<HeapObject> heap_object;
  if (maybe_object.ToSmi(&smi)) {
    Smi::SmiPrint(smi, os);
  } else if (maybe_object.IsCleared()) {
    os << "[cleared]";
  } else if (maybe_object.GetHeapObjectIfWeak(&heap_object)) {
    os << "[weak] ";
    heap_object->HeapObjectShortPrint(os);
  } else if (maybe_object.GetHeapObjectIfStrong(&heap_object)) {
    heap_object->HeapObjectShortPrint(os);
  } else {
    UNREACHABLE();
  }
  return os;
}

// static
void Smi::SmiPrint(Tagged<Smi> smi, std::ostream& os) { os << smi.value(); }

void Struct::BriefPrintDetails(std::ostream& os) {}

void Tuple2::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(value1()) << ", " << Brief(value2());
}

void MegaDomHandler::BriefPrintDetails(std::ostream& os) {
  os << " " << Brief(accessor(kAcquireLoad)) << ", " << Brief(context());
}

void ClassPositions::BriefPrintDetails(std::ostream& os) {
  os << " " << start() << ", " << end();
}

void CallableTask::BriefPrintDetails(std::ostream& os) {
  os << " callable=" << Brief(callable());
}

int HeapObjectLayout::SizeFromMap(Tagged<Map> map) const {
  return Tagged<HeapObject>(this)->SizeFromMap(map);
}

int HeapObject::SizeFromMap(Tagged<Map> map) const {
  int instance_size = map->instance_size();
  if (instance_size != kVariableSizeSentinel) return instance_size;
  // Only inline the most frequent cases.
  InstanceType instance_type = map->instance_type();
  if (base::IsInRange(instance_type, FIRST_FIXED_ARRAY_TYPE,
                      LAST_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<FixedArray>(*this)->AllocatedSize();
  }
#define CASE(TypeCamelCase, TYPE_UPPER_CASE)                     \
  if (instance_type == TYPE_UPPER_CASE##_TYPE) {                 \
    return UncheckedCast<TypeCamelCase>(*this)->AllocatedSize(); \
  }
  SIMPLE_HEAP_OBJECT_LIST2(CASE)
#undef CASE
  if (instance_type == SLOPPY_ARGUMENTS_ELEMENTS_TYPE) {
    return UncheckedCast<SloppyArgumentsElements>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_CONTEXT_TYPE, LAST_CONTEXT_TYPE)) {
    if (instance_type == NATIVE_CONTEXT_TYPE) return NativeContext::kSize;
    return Context::SizeFor(UncheckedCast<Context>(*this)->length());
  }
  if (instance_type == SEQ_ONE_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_ONE_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_ONE_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqOneByteString::SizeFor(
        UncheckedCast<SeqOneByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == BYTECODE_ARRAY_TYPE) {
    return BytecodeArray::SizeFor(
        UncheckedCast<BytecodeArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FREE_SPACE_TYPE) {
    return UncheckedCast<FreeSpace>(*this)->size(kRelaxedLoad);
  }
  if (instance_type == SEQ_TWO_BYTE_STRING_TYPE ||
      instance_type == INTERNALIZED_TWO_BYTE_STRING_TYPE ||
      instance_type == SHARED_SEQ_TWO_BYTE_STRING_TYPE) {
    // Strings may get concurrently truncated, hence we have to access its
    // length synchronized.
    return SeqTwoByteString::SizeFor(
        UncheckedCast<SeqTwoByteString>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FIXED_DOUBLE_ARRAY_TYPE) {
    return UncheckedCast<FixedDoubleArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == PROTECTED_FIXED_ARRAY_TYPE) {
    return UncheckedCast<ProtectedFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_WEAK_FIXED_ARRAY_TYPE) {
    return UncheckedCast<TrustedWeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == TRUSTED_BYTE_ARRAY_TYPE) {
    return UncheckedCast<TrustedByteArray>(*this)->AllocatedSize();
  }
  if (instance_type == FEEDBACK_METADATA_TYPE) {
    return UncheckedCast<FeedbackMetadata>(*this)->AllocatedSize();
  }
  if (base::IsInRange(instance_type, FIRST_DESCRIPTOR_ARRAY_TYPE,
                      LAST_DESCRIPTOR_ARRAY_TYPE)) {
    return DescriptorArray::SizeFor(
        UncheckedCast<DescriptorArray>(*this)->number_of_all_descriptors());
  }
  if (base::IsInRange(instance_type, FIRST_WEAK_FIXED_ARRAY_TYPE,
                      LAST_WEAK_FIXED_ARRAY_TYPE)) {
    return UncheckedCast<WeakFixedArray>(*this)->AllocatedSize();
  }
  if (instance_type == WEAK_ARRAY_LIST_TYPE) {
    return WeakArrayList::SizeForCapacity(
        UncheckedCast<WeakArrayList>(*this)->capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_SET_TYPE) {
    return SmallOrderedHashSet::SizeFor(
        UncheckedCast<SmallOrderedHashSet>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_HASH_MAP_TYPE) {
    return SmallOrderedHashMap::SizeFor(
        UncheckedCast<SmallOrderedHashMap>(*this)->Capacity());
  }
  if (instance_type == SMALL_ORDERED_NAME_DICTIONARY_TYPE) {
    return SmallOrderedNameDictionary::SizeFor(
        UncheckedCast<SmallOrderedNameDictionary>(*this)->Capacity());
  }
  if (instance_type == SWISS_NAME_DICTIONARY_TYPE) {
    return SwissNameDictionary::SizeFor(
        UncheckedCast<SwissNameDictionary>(*this)->Capacity());
  }
  if (instance_type == PROPERTY_ARRAY_TYPE) {
    return PropertyArray::SizeFor(
        UncheckedCast<PropertyArray>(*this)->length(kAcquireLoad));
  }
  if (instance_type == FEEDBACK_VECTOR_TYPE) {
    return FeedbackVector::SizeFor(
        UncheckedCast<FeedbackVector>(*this)->length());
  }
  if (instance_type == BIGINT_TYPE) {
    return BigInt::SizeFor(UncheckedCast<BigInt>(*this)->length());
  }
  if (instance_type == PREPARSE_DATA_TYPE) {
    Tagged<PreparseData> data = UncheckedCast<PreparseData>(*this);
    return PreparseData::SizeFor(data->data_length(), data->children_length());
  }
#define MAKE_TORQUE_SIZE_FOR(TYPE, TypeName)                \
  if (instance_type == TYPE) {                              \
    return UncheckedCast<TypeName>(*this)->AllocatedSize(); \
  }
  TORQUE_INSTANCE_TYPE_TO_BODY_DESCRIPTOR_LIST(MAKE_TORQUE_SIZE_FOR)
#undef MAKE_TORQUE_SIZE_FOR

  if (instance_type == INSTRUCTION_STREAM_TYPE) {
    return UncheckedCast<InstructionStream>(*this)->Size();
  }
  if (instance_type == COVERAGE_INFO_TYPE) {
    return CoverageInfo::SizeFor(
        UncheckedCast<CoverageInfo>(*this)->slot_count());
  }
#if V8_ENABLE_WEBASSEMBLY
  if (instance_type == WASM_TYPE_INFO_TYPE) {
    return WasmTypeInfo::SizeFor(
        UncheckedCast<WasmTypeInfo>(*this)->supertypes_length());
  }
  if (instance_type == WASM_STRUCT_TYPE) {
    return WasmStruct::GcSafeSize(map);
  }
  if (instance_type == WASM_ARRAY_TYPE) {
    return WasmArray::SizeFor(map, UncheckedCast<WasmArray>(*this)->length());
  }
  if (instance_type == WASM_NULL_TYPE) {
    return WasmNull::kSize;
  }
  if (instance_type == WASM_DISPATCH_TABLE_TYPE) {
    return WasmDispatchTable::SizeFor(
        UncheckedCast<WasmDispatchTable>(*this)->capacity());
  }
#endif  // V8_ENABLE_WEBASSEMBLY
  DCHECK_EQ(instance_type, EMBEDDER_DATA_ARRAY_TYPE);
  return EmbedderDataArray::SizeFor(
      UncheckedCast<EmbedderDataArray>(*this)->length());
}

bool HeapObject::NeedsRehashing(PtrComprCageBase cage_base) const {
  return NeedsRehashing(map(cage_base)->instance_type());
}

bool HeapObject::NeedsRehashing(InstanceType instance_type) const {
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    // Use map() only when it's guaranteed that it's not an InstructionStream
    // object.
    DCHECK_IMPLIES(instance_type != INSTRUCTION_STREAM_TYPE,
                   instance_type == map()->instance_type());
  } else {
    DCHECK_EQ(instance_type, map()->instance_type());
  }
  switch (instance_type) {
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return Cast<DescriptorArray>(*this)->number_of_descriptors() > 1;
    case TRANSITION_ARRAY_TYPE:
      return Cast<TransitionArray>(*this)->number_of_transitions() > 1;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      return false;  // We'll rehash from the JSMap or JSSet referencing them.
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case HASH_TABLE_TYPE:
    case SMALL_ORDERED_HASH_MAP_TYPE:
    case SMALL_ORDERED_HASH_SET_TYPE:
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

bool HeapObject::CanBeRehashed(PtrComprCageBase cage_base) const {
  DCHECK(NeedsRehashing(cage_base));
  switch (map(cage_base)->instance_type()) {
    case JS_MAP_TYPE:
    case JS_SET_TYPE:
      return true;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case ORDERED_NAME_DICTIONARY_TYPE:
      return false;
    case NAME_DICTIONARY_TYPE:
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
    case SWISS_NAME_DICTIONARY_TYPE:
      return true;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      return true;
    case TRANSITION_ARRAY_TYPE:
      return true;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_HASH_SET_TYPE:
      return Cast<SmallOrderedHashMap>(*this)->NumberOfElements() == 0;
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      return Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements() == 0;
    default:
      return false;
  }
  UNREACHABLE();
}

template <typename IsolateT>
void HeapObject::RehashBasedOnMap(IsolateT* isolate) {
  switch (map(isolate)->instance_type()) {
    case HASH_TABLE_TYPE:
      Cast<ObjectHashTable>(*this)->Rehash(isolate);
      break;
    case NAME_DICTIONARY_TYPE:
      Cast<NameDictionary>(*this)->Rehash(isolate);
      break;
    case NAME_TO_INDEX_HASH_TABLE_TYPE:
      Cast<NameToIndexHashTable>(*this)->Rehash(isolate);
      break;
    case REGISTERED_SYMBOL_TABLE_TYPE:
      Cast<RegisteredSymbolTable>(*this)->Rehash(isolate);
      break;
    case SWISS_NAME_DICTIONARY_TYPE:
      Cast<SwissNameDictionary>(*this)->Rehash(isolate);
      break;
    case GLOBAL_DICTIONARY_TYPE:
      Cast<GlobalDictionary>(*this)->Rehash(isolate);
      break;
    case NUMBER_DICTIONARY_TYPE:
      Cast<NumberDictionary>(*this)->Rehash(isolate);
      break;
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      Cast<SimpleNumberDictionary>(*this)->Rehash(isolate);
      break;
    case DESCRIPTOR_ARRAY_TYPE:
    case STRONG_DESCRIPTOR_ARRAY_TYPE:
      DCHECK_LE(1, Cast<DescriptorArray>(*this)->number_of_descriptors());
      Cast<DescriptorArray>(*this)->Sort();
      break;
    case TRANSITION_ARRAY_TYPE:
      Cast<TransitionArray>(*this)->Sort();
      break;
    case SMALL_ORDERED_HASH_MAP_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashMap>(*this)->NumberOfElements());
      break;
    case SMALL_ORDERED_HASH_SET_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedHashSet>(*this)->NumberOfElements());
      break;
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
      UNREACHABLE();  // We'll rehash from the JSMap or JSSet referencing them.
    case JS_MAP_TYPE: {
      Cast<JSMap>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case JS_SET_TYPE: {
      Cast<JSSet>(*this)->Rehash(isolate->AsIsolate());
      break;
    }
    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      DCHECK_EQ(0, Cast<SmallOrderedNameDictionary>(*this)->NumberOfElements());
      break;
    case INTERNALIZED_ONE_BYTE_STRING_TYPE:
    case INTERNALIZED_TWO_BYTE_STRING_TYPE:
      // Rare case, rehash read-only space strings before they are sealed.
      DCHECK(ReadOnlyHeap::Contains(*this));
      Cast<String>(*this)->EnsureHash();
      break;
    default:
      // TODO(ishell): remove once b/326043780 is no longer an issue.
      isolate->AsIsolate()->PushParamsAndDie(
          reinterpret_cast<void*>(ptr()), reinterpret_cast<void*>(map().ptr()),
          reinterpret_cast<void*>(
              static_cast<uintptr_t>(map()->instance_type())));
      UNREACHABLE();
  }
}
template void HeapObject::RehashBasedOnMap(Isolate* isolate);
template void HeapObject::RehashBasedOnMap(LocalIsolate* isolate);

void DescriptorArray::GeneralizeAllFields(bool clear_constness) {
  int length = number_of_descriptors();
  for (InternalIndex i : InternalIndex::Range(length)) {
    PropertyDetails details = GetDetails(i);
    details = details.CopyWithRepresentation(Representation::Tagged());
    if (details.location() == PropertyLocation::kField) {
      // Since constness is not propagated across proto transitions we must
      // clear the flag here.
      if (clear_constness) {
        details = details.CopyWithConstness(PropertyConstness::kMutable);
      }
      DCHECK_EQ(PropertyKind::kData, details.kind());
      SetValue(i, FieldType::Any());
    }
    SetDetails(i, details);
  }
}

MaybeHandle<Object> Object::SetProperty(Isolate* isolate, Handle<JSAny> object,
                                        Handle<Name> name, Handle<Object> value,
                                        StoreOrigin store_origin,
                                        Maybe<ShouldThrow> should_throw) {
  LookupIterator it(isolate, object, name);
  MAYBE_RETURN_NULL(SetProperty(&it, value, store_origin, should_throw));
  return value;
}

Maybe<bool> Object::SetPropertyInternal(LookupIterator* it,
                                        Handle<Object> value,
                                        Maybe<ShouldThrow> should_throw,
                                        StoreOrigin store_origin, bool* found) {
  it->UpdateProtector();
  DCHECK(it->IsFound());

  // Make sure that the top context does not change when doing callbacks or
  // interceptor calls.
  AssertNoContextChange ncc(it->isolate());

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::ACCESS_CHECK:
        if (it->HasAccess()) continue;
        // Check whether it makes sense to reuse the lookup iterator. Here it
        // might still call into setters up the prototype chain.
        return JSObject::SetPropertyWithFailedAccessCheck(it, value,
                                                          should_throw);

      case LookupIterator::JSPROXY: {
        Handle<JSAny> receiver = it->GetReceiver();
        // In case of global IC, the receiver is the global object. Replace by
        // the global proxy.
        if (IsJSGlobalObject(*receiver)) {
          receiver = handle(Cast<JSGlobalObject>(*receiver)->global_proxy(),
                            it->isolate());
        }
        return JSProxy::SetProperty(it->GetHolder<JSProxy>(), it->GetName(),
                                    value, receiver, should_throw);
      }

      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(it->isolate(), kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));

      case LookupIterator::INTERCEPTOR: {
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          InterceptorResult result;
          if (!JSObject::SetPropertyWithInterceptor(it, should_throw, value)
                   .To(&result)) {
            // An exception was thrown in the interceptor. Propagate.
            return Nothing<bool>();
          }
          switch (result) {
            case InterceptorResult::kFalse:
              return Just(false);
            case InterceptorResult::kTrue:
              return Just(true);
            case InterceptorResult::kNotIntercepted:
              // Proceed lookup.
              break;
          }
          // Assuming that the callback has side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          // Proceed lookup from the next state.
          it->Next();
        } else {
          Maybe<PropertyAttributes> maybe_attributes =
              JSObject::GetPropertyAttributesWithInterceptor(it);
          if (maybe_attributes.IsNothing()) return Nothing<bool>();
          if ((maybe_attributes.FromJust() & READ_ONLY) != 0) {
            return WriteToReadOnlyProperty(it, value, should_throw);
          }
          // At this point we might have called interceptor's query or getter
          // callback. Assuming that the callbacks have side effects, we use
          // Object::SetSuperProperty() which works properly regardless on
          // whether the property was present on the receiver or not when
          // storing to the receiver.
          if (maybe_attributes.FromJust() == ABSENT) {
            // Proceed lookup from the next state.
            it->Next();
          } else {
            // Finish lookup in order to make Object::SetSuperProperty() store
            // property to the receiver.
            it->NotFound();
          }
        }
        return Object::SetSuperProperty(it, value, store_origin, should_throw);
      }

      case LookupIterator::ACCESSOR: {
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        DirectHandle<Object> accessors = it->GetAccessors();
        if (IsAccessorInfo(*accessors) &&
            !it->HolderIsReceiverOrHiddenPrototype()) {
          *found = false;
          return Nothing<bool>();
        }
        return SetPropertyWithAccessor(it, value, should_throw);
      }
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND: {
        // IntegerIndexedElementSet converts value to a Number/BigInt prior to
        // the bounds check. The bounds check has already happened here, but
        // perform the possibly effectful ToNumber (or ToBigInt) operation
        // anyways.
        DirectHandle<JSTypedArray> holder = it->GetHolder<JSTypedArray>();
        Handle<Object> converted_value;
        if (holder->type() == kExternalBigInt64Array ||
            holder->type() == kExternalBigUint64Array) {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              BigInt::FromObject(it->isolate(), value), Nothing<bool>());
        } else {
          ASSIGN_RETURN_ON_EXCEPTION_VALUE(
              it->isolate(), converted_value,
              Object::ToNumber(it->isolate(), value), Nothing<bool>());
        }

        // For RAB/GSABs, the above conversion might grow the buffer so that the
        // index is no longer out of bounds. Redo the bounds check and try
        // again.
        it->RecheckTypedArrayBounds();
        if (it->state() != LookupIterator::DATA) {
          // Still out of bounds.
          DCHECK_EQ(it->state(), LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND);

          // FIXME: Throw a TypeError if the holder is detached here
          // (IntegerIndexedElementSet step 5).

          // TODO(verwaest): Per spec, we should return false here (steps 6-9
          // in IntegerIndexedElementSet), resulting in an exception being
          // thrown on OOB accesses in strict code. Historically, v8 has not
          // done made this change due to uncertainty about web compat.
          // (v8:4901)
          return Just(true);
        }
        value = converted_value;
        [[fallthrough]];
      }

      case LookupIterator::DATA:
        if (it->IsReadOnly()) {
          return WriteToReadOnlyProperty(it, value, should_throw);
        }
        if (it->HolderIsReceiverOrHiddenPrototype()) {
          return SetDataProperty(it, value);
        }
        [[fallthrough]];
      case LookupIterator::NOT_FOUND:
      case LookupIterator::TRANSITION:
        *found = false;
        return Nothing<bool>();
    }
    UNREACHABLE();
  }
}

bool Object::CheckContextualStoreToJSGlobalObject(
    LookupIterator* it, Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();

  if (IsJSGlobalObject(*it->GetReceiver(), isolate) &&
      (GetShouldThrow(isolate, should_throw) == ShouldThrow::kThrowOnError)) {
    if (it->state() == LookupIterator::TRANSITION) {
      // The property cell that we have created is garbage because we are going
      // to throw now instead of putting it into the global dictionary. However,
      // the cell might already have been stored into the feedback vector, so
      // we must invalidate it nevertheless.
      it->transition_cell()->ClearAndInvalidate(ReadOnlyRoots(isolate));
    }
    isolate->Throw(*isolate->factory()->NewReferenceError(
        MessageTemplate::kNotDefined, it->GetName()));
    return false;
  }
  return true;
}

Maybe<bool> Object::SetProperty(LookupIterator* it, Handle<Object> value,
                                StoreOrigin store_origin,
                                Maybe<ShouldThrow> should_throw) {
  if (it->IsFound()) {
    bool found = true;
    Maybe<bool> result =
        SetPropertyInternal(it, value, should_throw, store_origin, &found);
    if (found) return result;
  }

  if (!CheckContextualStoreToJSGlobalObject(it, should_throw)) {
    return Nothing<bool>();
  }
  return AddDataProperty(it, value, NONE, should_throw, store_origin);
}

Maybe<bool> Object::SetSuperProperty(LookupIterator* it, Handle<Object> value,
                                     StoreOrigin store_origin,
                                     Maybe<ShouldThrow> should_throw) {
  Isolate* isolate = it->isolate();

  if (it->IsFound()) {
    bool found = true;
    Maybe<bool> result =
        SetPropertyInternal(it, value, should_throw, store_origin, &found);
    if (found) return result;
  }

  it->UpdateProtector();

  // The property either doesn't exist on the holder or exists there as a data
  // property.

  if (!IsJSReceiver(*it->GetReceiver())) {
    return WriteToReadOnlyProperty(it, value, should_throw);
  }
  Handle<JSReceiver> receiver = Cast<JSReceiver>(it->GetReceiver());

  // Note, the callers rely on the fact that this code is redoing the full own
  // lookup from scratch.
  LookupIterator own_lookup(isolate, receiver, it->GetKey(),
                            LookupIterator::OWN);
  for (;; own_lookup.Next()) {
    switch (own_lookup.state()) {
      case LookupIterator::ACCESS_CHECK:
        if (!own_lookup.HasAccess()) {
          return JSObject::SetPropertyWithFailedAccessCheck(&own_lookup, value,
                                                            should_throw);
        }
        continue;

      case LookupIterator::ACCESSOR:
        if (IsAccessorInfo(*own_lookup.GetAccessors())) {
          if (own_lookup.IsReadOnly()) {
            return WriteToReadOnlyProperty(&own_lookup, value, should_throw);
          }
          return Object::SetPropertyWithAccessor(&own_lookup, value,
                                                 should_throw);
        }
        [[fallthrough]];
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return RedefineIncompatibleProperty(isolate, it->GetName(), value,
                                            should_throw);

      case LookupIterator::DATA: {
        if (own_lookup.IsReadOnly()) {
          return WriteToReadOnlyProperty(&own_lookup, value, should_throw);
        }
        return SetDataProperty(&own_lookup, value);
      }

      case LookupIterator::INTERCEPTOR:
      case LookupIterator::JSPROXY: {
        PropertyDescriptor desc;
        Maybe<bool> owned =
            JSReceiver::GetOwnPropertyDescriptor(&own_lookup, &desc);
        MAYBE_RETURN(owned, Nothing<bool>());
        if (!owned.FromJust()) {
          // |own_lookup| might become outdated at this point anyway.
          // TODO(leszeks): Remove this restart since we don't really use the
          // lookup iterator after this.
          own_lookup.Restart();
          if (!CheckContextualStoreToJSGlobalObject(&own_lookup,
                                                    should_throw)) {
            return Nothing<bool>();
          }
          return JSReceiver::CreateDataProperty(isolate, receiver, it->GetKey(),
                                                value, should_throw);
        }
        if (PropertyDescriptor::IsAccessorDescriptor(&desc) ||
            !desc.writable()) {
          return RedefineIncompatibleProperty(isolate, it->GetName(), value,
                                              should_throw);
        }

        PropertyDescriptor value_desc;
        value_desc.set_value(Cast<JSAny>(value));
        return JSReceiver::DefineOwnProperty(isolate, receiver, it->GetName(),
                                             &value_desc, should_throw);
      }

      case LookupIterator::NOT_FOUND:
        if (!CheckContextualStoreToJSGlobalObject(&own_lookup, should_throw)) {
          return Nothing<bool>();
        }
        return AddDataProperty(&own_lookup, value, NONE, should_throw,
                               store_origin);

      case LookupIterator::WASM_OBJECT:
        RETURN_FAILURE(it->isolate(), kThrowOnError,
                       NewTypeError(MessageTemplate::kWasmObjectsAreOpaque));

      case LookupIterator::TRANSITION:
        UNREACHABLE();
    }
    UNREACHABLE();
  }
}

Maybe<bool> Object::CannotCreateProperty(Isolate* isolate,
                                         Handle<JSAny> receiver,
                                         Handle<Object> name,
                                         DirectHandle<Object> value,
                                         Maybe<ShouldThrow> should_throw) {
  RETURN_FAILURE(
      isolate, GetShouldThrow(isolate, should_throw),
      NewTypeError(MessageTemplate::kStrictCannotCreateProperty, name,
                   Object::TypeOf(isolate, receiver), receiver));
}

Maybe<bool> Object::WriteToReadOnlyProperty(
    LookupIterator* it, DirectHandle<Object> value,
    Maybe<ShouldThrow> maybe_should_throw) {
  ShouldThrow should_throw = GetShouldThrow(it->isolate(), maybe_should_throw);
  if (it->IsFound() && !it->HolderIsReceiver()) {
    // "Override mistake" attempted, record a use count to track this per
    // v8:8175
    v8::Isolate::UseCounterFeature feature =
        should_throw == kThrowOnError
            ? v8::Isolate::kAttemptOverrideReadOnlyOnPrototypeStrict
            : v8::Isolate::kAttemptOverrideReadOnlyOnPrototypeSloppy;
    it->isolate()->CountUsage(feature);
  }
  return WriteToReadOnlyProperty(it->isolate(), it->GetReceiver(),
                                 it->GetName(), value, should_throw);
}

Maybe<bool> Object::WriteToReadOnlyProperty(Isolate* isolate,
                                            Handle<JSAny> receiver,
                                            Handle<Object> name,
                                            DirectHandle<Object> value,
                                            ShouldThrow should_throw) {
  RETURN_FAILURE(isolate, should_throw,
                 NewTypeError(MessageTemplate::kStrictReadOnlyProperty, name,
                              Object::TypeOf(isolate, receiver), receiver));
}

Maybe<bool> Object::RedefineIncompatibleProperty(
    Isolate* isolate, Handle<Object> name, DirectHandle<Object> value,
    Maybe<ShouldThrow> should_throw) {
  RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                 NewTypeError(MessageTemplate::kRedefineDisallowed, name));
}

Maybe<bool> Object::SetDataProperty(LookupIterator* it, Handle<Object> value) {
  Isolate* isolate = it->isolate();
  DCHECK_IMPLIES(IsJSProxy(*it->GetReceiver(), isolate),
                 it->GetName()->IsPrivateName());
  DCHECK_IMPLIES(!it->IsElement() && it->GetName()->IsPrivateName(),
                 it->state() == LookupIterator::DATA);
  Handle<JSReceiver> receiver = Cast<JSReceiver>(it->GetReceiver());

  // Store on the holder which may be hidden behind the receiver.
  DCHECK(it->HolderIsReceiverOrHiddenPrototype());

  Handle<Object> to_assign = value;
  // Convert the incoming value to a number for storing into typed arrays.
  if (it->IsElement() && IsJSObject(*receiver, isolate) &&
      Cast<JSObject>(*receiver)->HasTypedArrayOrRabGsabTypedArrayElements(
          isolate)) {
    auto receiver_ta = Cast<JSTypedArray>(receiver);
    ElementsKind elements_kind = Cast<JSObject>(*receiver)->GetElementsKind();
    if (IsBigIntTypedArrayElementsKind(elements_kind)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, to_assign,
                                       BigInt::FromObject(isolate, value),
                                       Nothing<bool>());
      if (V8_UNLIKELY(receiver_ta->IsDetachedOrOutOfBounds() ||
                      it->index() >= receiver_ta->GetLength())) {
        return Just(true);
      }
    } else if (!IsNumber(*value) && !IsUndefined(*value, isolate)) {
      ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, to_assign,
                                       Object::ToNumber(isolate, value),
                                       Nothing<bool>());
      if (V8_UNLIKELY(receiver_ta->IsDetachedOrOutOfBounds() ||
                      it->index() >= receiver_ta->GetLength())) {
        return Just(true);
      }
    }
  }

  DCHECK(!IsWasmObject(*receiver, isolate));
  if (V8_UNLIKELY(IsJSSharedStruct(*receiver, isolate) ||
                  IsJSSharedArray(*receiver, isolate))) {
    // Shared structs can only point to primitives or shared values.
    ASSIGN_RETURN_ON_EXCEPTION_VALUE(
        isolate, to_assign, Object::Share(isolate, to_assign, kThrowOnError),
        Nothing<bool>());
    it->WriteDataValue(to_assign, false);
  } else {
    // Possibly migrate to the most up-to-date map that will be able to store
    // |value| under it->name().
    it->PrepareForDataProperty(to_assign);

    // Write the property value.
    it->WriteDataValue(to_assign, false);
  }

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->HeapObjectVerify(isolate);
  }
#endif
  return Just(true);
}

Maybe<bool> Object::AddDataProperty(LookupIterator* it,
                                    DirectHandle<Object> value,
                                    PropertyAttributes attributes,
                                    Maybe<ShouldThrow> should_throw,
                                    StoreOrigin store_origin,
                                    EnforceDefineSemantics semantics) {
  if (!IsJSReceiver(*it->GetReceiver())) {
    return CannotCreateProperty(it->isolate(), it->GetReceiver(), it->GetName(),
                                value, should_throw);
  }

  // Private symbols should be installed on JSProxy using
  // JSProxy::SetPrivateSymbol.
  if (IsJSProxy(*it->GetReceiver()) && it->GetName()->IsPrivate() &&
      !it->GetName()->IsPrivateName()) {
    RETURN_FAILURE(it->isolate(), GetShouldThrow(it->isolate(), should_throw),
                   NewTypeError(MessageTemplate::kProxyPrivate));
  }

  DCHECK_NE(LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND, it->state());

  Handle<JSReceiver> receiver = it->GetStoreTarget<JSReceiver>();
  DCHECK_IMPLIES(IsJSProxy(*receiver), it->GetName()->IsPrivateName());
  DCHECK_IMPLIES(IsJSProxy(*receiver),
                 it->state() == LookupIterator::NOT_FOUND);

  // If the receiver is a JSGlobalProxy, store on the prototype (JSGlobalObject)
  // instead. If the prototype is Null, the proxy is detached.
  if (IsJSGlobalProxy(*receiver)) return Just(true);

  Isolate* isolate = it->isolate();

  if (it->ExtendingNonExtensible(receiver)) {
    bool is_shared_object = IsAlwaysSharedSpaceJSObject(*receiver);
    RETURN_FAILURE(
        isolate, GetShouldThrow(it->isolate(), should_throw),
        NewTypeError(
            semantics == EnforceDefineSemantics::kDefine
                ? (is_shared_object
                       ? MessageTemplate::kDefineDisallowedFixedLayout
                       : MessageTemplate::kDefineDisallowed)
                : (is_shared_object ? MessageTemplate::kObjectFixedLayout
                                    : MessageTemplate::kObjectNotExtensible),
            it->GetName()));
  }

  if (it->IsElement(*receiver)) {
    if (IsJSArray(*receiver)) {
      Handle<JSArray> array = Cast<JSArray>(receiver);
      if (JSArray::WouldChangeReadOnlyLength(array, it->array_index())) {
        RETURN_FAILURE(isolate, GetShouldThrow(it->isolate(), should_throw),
                       NewTypeError(MessageTemplate::kStrictReadOnlyProperty,
                                    isolate->factory()->length_string(),
                                    Object::TypeOf(isolate, array), array));
      }
    }

    Handle<JSObject> receiver_obj = Cast<JSObject>(receiver);
    MAYBE_RETURN(JSObject::AddDataElement(receiver_obj, it->array_index(),
                                          value, attributes),
                 Nothing<bool>());
    JSObject::ValidateElements(*receiver_obj);
    return Just(true);
  }

  return Object::TransitionAndWriteDataProperty(it, value, attributes,
                                                should_throw, store_origin);
}

// static
Maybe<bool> Object::TransitionAndWriteDataProperty(
    LookupIterator* it, DirectHandle<Object> value,
    PropertyAttributes attributes, Maybe<ShouldThrow> should_throw,
    StoreOrigin store_origin) {
  Handle<JSReceiver> receiver = it->GetStoreTarget<JSReceiver>();
  it->UpdateProtector();
  // Migrate to the most up-to-date map that will be able to store |value|
  // under it->name() with |attributes|.
  it->PrepareTransitionToDataProperty(receiver, value, attributes,
                                      store_origin);
  DCHECK_EQ(LookupIterator::TRANSITION, it->state());
  it->ApplyTransitionToDataProperty(receiver);

  // Write the property value.
  it->WriteDataValue(value, true);

#if VERIFY_HEAP
  if (v8_flags.verify_heap) {
    receiver->HeapObjectVerify(it->isolate());
  }
#endif

  return Just(true);
}
// static
MaybeHandle<Object> Object::ShareSlow(Isolate* isolate,
                                      Handle<HeapObject> value,
                                      ShouldThrow throw_if_cannot_be_shared) {
  // Use Object::Share() if value might already be shared.
  DCHECK(!IsShared(*value));

  SharedObjectSafePublishGuard publish_guard;

  if (IsString(*value)) {
    return String::Share(isolate, Cast<String>(value));
  }

  if (IsHeapNumber(*value)) {
    uint64_t bits = Cast<HeapNumber>(*value)->value_as_bits();
    return isolate->factory()
        ->NewHeapNumberFromBits<AllocationType::kSharedOld>(bits);
  }

  if (throw_if_cannot_be_shared == kThrowOnError) {
    THROW_NEW_ERROR(isolate,
                    NewTypeError(MessageTemplate::kCannotBeShared, value));
  }
  return MaybeHandle<Object>();
}

namespace {

template <class T>
int AppendUniqueCallbacks(Isolate* isolate, DirectHandle<ArrayList> callbacks,
                          Handle<typename T::Array> array,
                          int valid_descriptors) {
  int nof_callbacks = callbacks->length();

  // Fill in new callback descriptors.  Process the callbacks from
  // back to front so that the last callback with a given name takes
  // precedence over previously added callbacks with that name.
  for (int i = nof_callbacks - 1; i >= 0; i--) {
    Handle<AccessorInfo> entry(Cast<AccessorInfo>(callbacks->get(i)), isolate);
    Handle<Name> key(Cast<Name>(entry->name()), isolate);
    DCHECK(IsUniqueName(*key));
    // Check if a descriptor with this name already exists before writing.
    if (!T::Contains(key, entry, valid_descriptors, array)) {
      T::Insert(key, entry, valid_descriptors, array);
      valid_descriptors++;
    }
  }

  return valid_descriptors;
}

struct FixedArrayAppender {
  using Array = FixedArray;
  static bool Contains(DirectHandle<Name> key, DirectHandle<AccessorInfo> entry,
                       int valid_descriptors, DirectHandle<FixedArray> array) {
    for (int i = 0; i < valid_descriptors; i++) {
      if (*key == Cast<AccessorInfo>(array->get(i))->name()) return true;
    }
    return false;
  }
  static void Insert(DirectHandle<Name> key, DirectHandle<AccessorInfo> entry,
                     int valid_descriptors, DirectHandle<FixedArray> array) {
    DisallowGarbageCollection no_gc;
    array->set(valid_descriptors, *entry);
  }
};

}  // namespace

int AccessorInfo::AppendUnique(Isolate* isolate, Handle<Object> descriptors,
                               Handle<FixedArray> array,
                               int valid_descriptors) {
  auto callbacks = Cast<ArrayList>(descriptors);
  DCHECK_GE(array->length(), callbacks->length() + valid_descriptors);
  return AppendUniqueCallbacks<FixedArrayAppender>(isolate, callbacks, array,
                                                   valid_descriptors);
}

void JSProxy::Revoke(DirectHandle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  // ES#sec-proxy-revocation-functions
  if (!proxy->IsRevoked()) {
    // 5. Set p.[[ProxyTarget]] to null.
    proxy->set_target(ReadOnlyRoots(isolate).null_value());
    // 6. Set p.[[ProxyHandler]] to null.
    proxy->set_handler(ReadOnlyRoots(isolate).null_value());
  }
  DCHECK(proxy->IsRevoked());
}

// static
Maybe<bool> JSProxy::IsArray(Handle<JSProxy> proxy) {
  Isolate* isolate = proxy->GetIsolate();
  Handle<JSReceiver> object = Cast<JSReceiver>(proxy);
  for (int i = 0; i < JSProxy::kMaxIterationLimit; i++) {
    proxy = Cast<JSProxy>(object);
    if (proxy->IsRevoked()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyRevoked,
          isolate->factory()->NewStringFromAsciiChecked("IsArray")));
      return Nothing<bool>();
    }
    object = handle(Cast<JSReceiver>(proxy->target()), isolate);
    if (IsJSArray(*object)) return Just(true);
    if (!IsJSProxy(*object)) return Just(false);
  }

  // Too deep recursion, throw a RangeError.
  isolate->StackOverflow();
  return Nothing<bool>();
}

Maybe<bool> JSProxy::HasProperty(Isolate* isolate, DirectHandle<JSProxy> proxy,
                                 Handle<Name> name) {
  DCHECK(!name->IsPrivate());
  STACK_CHECK(isolate, Nothing<bool>());
  // 1. (Assert)
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, isolate->factory()->has_string()));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "has").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler),
                        isolate->factory()->has_string()),
      Nothing<bool>());
  // 7. If trap is undefined, then
  if (IsUndefined(*trap, isolate)) {
    // 7a. Return target.[[HasProperty]](P).
    return JSReceiver::HasProperty(isolate, target, name);
  }
  // 8. Let booleanTrapResult be ToBoolean(? Call(trap, handler, «target, P»)).
  Handle<Object> trap_result_obj;
  Handle<Object> args[] = {target, name};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result_obj,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  bool boolean_trap_result = Object::BooleanValue(*trap_result_obj, isolate);
  // 9. If booleanTrapResult is false, then:
  if (!boolean_trap_result) {
    MAYBE_RETURN(JSProxy::CheckHasTrap(isolate, name, target), Nothing<bool>());
  }
  // 10. Return booleanTrapResult.
  return Just(boolean_trap_result);
}

Maybe<bool> JSProxy::CheckHasTrap(Isolate* isolate, Handle<Name> name,
                                  Handle<JSReceiver> target) {
  // 9a. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 9b. If targetDesc is not undefined, then:
  if (target_found.FromJust()) {
    // 9b i. If targetDesc.[[Configurable]] is false, throw a TypeError
    //       exception.
    if (!target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyHasNonConfigurable, name));
      return Nothing<bool>();
    }
    // 9b ii. Let extensibleTarget be ? IsExtensible(target).
    Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
    MAYBE_RETURN(extensible_target, Nothing<bool>());
    // 9b iii. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyHasNonExtensible, name));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

Maybe<bool> JSProxy::SetProperty(DirectHandle<JSProxy> proxy, Handle<Name> name,
                                 Handle<Object> value, Handle<JSAny> receiver,
                                 Maybe<ShouldThrow> should_throw) {
  DCHECK(!name->IsPrivate());
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->set_string();

  if (proxy->IsRevoked()) {
    isolate->Throw(
        *factory->NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap, Object::GetMethod(isolate, handler, trap_name),
      Nothing<bool>());
  if (IsUndefined(*trap, isolate)) {
    PropertyKey key(isolate, name);
    LookupIterator it(isolate, receiver, key, target);

    return Object::SetSuperProperty(&it, value, StoreOrigin::kMaybeKeyed,
                                    should_throw);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name, value, receiver};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  if (!Object::BooleanValue(*trap_result, isolate)) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, name));
  }

  MaybeHandle<Object> result =
      JSProxy::CheckGetSetTrapResult(isolate, name, target, value, kSet);

  if (result.is_null()) {
    return Nothing<bool>();
  }
  return Just(true);
}

Maybe<bool> JSProxy::DeletePropertyOrElement(DirectHandle<JSProxy> proxy,
                                             Handle<Name> name,
                                             LanguageMode language_mode) {
  DCHECK(!name->IsPrivate());
  ShouldThrow should_throw =
      is_sloppy(language_mode) ? kDontThrow : kThrowOnError;
  Isolate* isolate = proxy->GetIsolate();
  STACK_CHECK(isolate, Nothing<bool>());
  Factory* factory = isolate->factory();
  Handle<String> trap_name = factory->deleteProperty_string();

  if (proxy->IsRevoked()) {
    isolate->Throw(
        *factory->NewTypeError(MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  Handle<JSReceiver> handler(Cast<JSReceiver>(proxy->handler()), isolate);

  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap, Object::GetMethod(isolate, handler, trap_name),
      Nothing<bool>());
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::DeletePropertyOrElement(isolate, target, name,
                                               language_mode);
  }

  Handle<Object> trap_result;
  Handle<Object> args[] = {target, name};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  if (!Object::BooleanValue(*trap_result, isolate)) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, name));
  }

  // Enforce the invariant.
  return JSProxy::CheckDeleteTrap(isolate, name, target);
}

Maybe<bool> JSProxy::CheckDeleteTrap(Isolate* isolate, Handle<Name> name,
                                     Handle<JSReceiver> target) {
  // 10. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, name, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 11. If targetDesc is undefined, return true.
  if (target_found.FromJust()) {
    // 12. If targetDesc.[[Configurable]] is false, throw a TypeError exception.
    if (!target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDeletePropertyNonConfigurable, name));
      return Nothing<bool>();
    }
    // 13. Let extensibleTarget be ? IsExtensible(target).
    Maybe<bool> extensible_target = JSReceiver::IsExtensible(isolate, target);
    MAYBE_RETURN(extensible_target, Nothing<bool>());
    // 14. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDeletePropertyNonExtensible, name));
      return Nothing<bool>();
    }
  }
  return Just(true);
}

// static
MaybeHandle<JSProxy> JSProxy::New(Isolate* isolate, Handle<Object> target,
                                  Handle<Object> handler) {
  if (!IsJSReceiver(*target)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kProxyNonObject));
  }
  if (!IsJSReceiver(*handler)) {
    THROW_NEW_ERROR(isolate, NewTypeError(MessageTemplate::kProxyNonObject));
  }
  return isolate->factory()->NewJSProxy(Cast<JSReceiver>(target),
                                        Cast<JSReceiver>(handler));
}

Maybe<PropertyAttributes> JSProxy::GetPropertyAttributes(LookupIterator* it) {
  PropertyDescriptor desc;
  Maybe<bool> found = JSProxy::GetOwnPropertyDescriptor(
      it->isolate(), it->GetHolder<JSProxy>(), it->GetName(), &desc);
  MAYBE_RETURN(found, Nothing<PropertyAttributes>());
  if (!found.FromJust()) return Just(ABSENT);
  return Just(desc.ToAttributes());
}

// TODO(jkummerow): Consider unification with FastAsArrayLength() in
// accessors.cc.
bool PropertyKeyToArrayLength(DirectHandle<Object> value, uint32_t* length) {
  DCHECK(IsNumber(*value) || IsName(*value));
  if (Object::ToArrayLength(*value, length)) return true;
  if (IsString(*value)) return Cast<String>(*value)->AsArrayIndex(length);
  return false;
}

bool PropertyKeyToArrayIndex(DirectHandle<Object> index_obj, uint32_t* output) {
  return PropertyKeyToArrayLength(index_obj, output) && *output != kMaxUInt32;
}

// ES6 9.4.2.1
// static
Maybe<bool> JSArray::DefineOwnProperty(Isolate* isolate, Handle<JSArray> o,
                                       Handle<Object> name,
                                       PropertyDescriptor* desc,
                                       Maybe<ShouldThrow> should_throw) {
  if (IsName(*name)) {
    name = isolate->factory()->InternalizeName(Cast<Name>(name));
  }

  // 1. Assert: IsPropertyKey(P) is true. ("P" is |name|.)
  // 2. If P is "length", then:
  if (*name == ReadOnlyRoots(isolate).length_string()) {
    // 2a. Return ArraySetLength(A, Desc).
    return ArraySetLength(isolate, o, desc, should_throw);
  }
  // 3. Else if P is an array index, then:
  uint32_t index = 0;
  if (PropertyKeyToArrayIndex(name, &index)) {
    // 3a. Let oldLenDesc be OrdinaryGetOwnProperty(A, "length").
    PropertyDescriptor old_len_desc;
    Maybe<bool> success = GetOwnPropertyDescriptor(
        isolate, o, isolate->factory()->length_string(), &old_len_desc);
    // 3b. (Assert)
    DCHECK(success.FromJust());
    USE(success);
    // 3c. Let oldLen be oldLenDesc.[[Value]].
    uint32_t old_len = 0;
    CHECK(Object::ToArrayLength(*old_len_desc.value(), &old_len));
    // 3d. Let index be ToUint32(P).
    // (Already done above.)
    // 3e. (Assert)
    // 3f. If index >= oldLen and oldLenDesc.[[Writable]] is false,
    //     return false.
    if (index >= old_len && old_len_desc.has_writable() &&
        !old_len_desc.writable()) {
      RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                     NewTypeError(MessageTemplate::kDefineDisallowed, name));
    }
    // 3g. Let succeeded be OrdinaryDefineOwnProperty(A, P, Desc).
    Maybe<bool> succeeded =
        OrdinaryDefineOwnProperty(isolate, o, name, desc, should_throw);
    // 3h. Assert: succeeded is not an abrupt completion.
    //     In our case, if should_throw == kThrowOnError, it can be!
    // 3i. If succeeded is false, return false.
    if (succeeded.IsNothing() || !succeeded.FromJust()) return succeeded;
    // 3j. If index >= oldLen, then:
    if (index >= old_len) {
      // 3j i. Set oldLenDesc.[[Value]] to index + 1.
      old_len_desc.set_value(isolate->factory()->NewNumberFromUint(index + 1));
      // 3j ii. Let succeeded be
      //        OrdinaryDefineOwnProperty(A, "length", oldLenDesc).
      succeeded = OrdinaryDefineOwnProperty(isolate, o,
                                            isolate->factory()->length_string(),
                                            &old_len_desc, should_throw);
      // 3j iii. Assert: succeeded is true.
      DCHECK(succeeded.FromJust());
      USE(succeeded);
    }
    // 3k. Return true.
    return Just(true);
  }

  // 4. Return OrdinaryDefineOwnProperty(A, P, Desc).
  return OrdinaryDefineOwnProperty(isolate, o, name, desc, should_throw);
}

// Part of ES6 9.4.2.4 ArraySetLength.
// static
bool JSArray::AnythingToArrayLength(Isolate* isolate,
                                    Handle<Object> length_object,
                                    uint32_t* output) {
  // Fast path: check numbers and strings that can be converted directly
  // and unobservably.
  if (Object::ToArrayLength(*length_object, output)) return true;
  if (IsString(*length_object) &&
      Cast<String>(length_object)->AsArrayIndex(output)) {
    return true;
  }
  // Slow path: follow steps in ES6 9.4.2.4 "ArraySetLength".
  // 3. Let newLen be ToUint32(Desc.[[Value]]).
  Handle<Number> uint32_v;
  if (!Object::ToUint32(isolate, length_object).ToHandle(&uint32_v)) {
    // 4. ReturnIfAbrupt(newLen).
    return false;
  }
  // 5. Let numberLen be ToNumber(Desc.[[Value]]).
  Handle<Number> number_v;
  if (!Object::ToNumber(isolate, length_object).ToHandle(&number_v)) {
    // 6. ReturnIfAbrupt(newLen).
    return false;
  }
  // 7. If newLen != numberLen, throw a RangeError exception.
  if (Object::NumberValue(*uint32_v) != Object::NumberValue(*number_v)) {
    DirectHandle<Object> exception =
        isolate->factory()->NewRangeError(MessageTemplate::kInvalidArrayLength);
    isolate->Throw(*exception);
    return false;
  }
  CHECK(Object::ToArrayLength(*uint32_v, output));
  return true;
}

// ES6 9.4.2.4
// static
Maybe<bool> JSArray::ArraySetLength(Isolate* isolate, Handle<JSArray> a,
                                    PropertyDescriptor* desc,
                                    Maybe<ShouldThrow> should_throw) {
  // 1. If the [[Value]] field of Desc is absent, then
  if (!desc->has_value()) {
    // 1a. Return OrdinaryDefineOwnProperty(A, "length", Desc).
    return OrdinaryDefineOwnProperty(
        isolate, a, isolate->factory()->length_string(), desc, should_throw);
  }
  // 2. Let newLenDesc be a copy of Desc.
  // (Actual copying is not necessary.)
  PropertyDescriptor* new_len_desc = desc;
  // 3. - 7. Convert Desc.[[Value]] to newLen.
  uint32_t new_len = 0;
  if (!AnythingToArrayLength(isolate, desc->value(), &new_len)) {
    DCHECK(isolate->has_exception());
    return Nothing<bool>();
  }
  // 8. Set newLenDesc.[[Value]] to newLen.
  // (Done below, if needed.)
  // 9. Let oldLenDesc be OrdinaryGetOwnProperty(A, "length").
  PropertyDescriptor old_len_desc;
  Maybe<bool> success = GetOwnPropertyDescriptor(
      isolate, a, isolate->factory()->length_string(), &old_len_desc);
  // 10. (Assert)
  DCHECK(success.FromJust());
  USE(success);
  // 11. Let oldLen be oldLenDesc.[[Value]].
  uint32_t old_len = 0;
  CHECK(Object::ToArrayLength(*old_len_desc.value(), &old_len));
  // 12. If newLen >= oldLen, then
  if (new_len >= old_len) {
    // 8. Set newLenDesc.[[Value]] to newLen.
    // 12a. Return OrdinaryDefineOwnProperty(A, "length", newLenDesc).
    new_len_desc->set_value(isolate->factory()->NewNumberFromUint(new_len));
    return OrdinaryDefineOwnProperty(isolate, a,
                                     isolate->factory()->length_string(),
                                     new_len_desc, should_throw);
  }
  // 13. If oldLenDesc.[[Writable]] is false, return false.
  if (!old_len_desc.writable() ||
      // Also handle the {configurable: true} and enumerable changes
      // since we later use JSArray::SetLength instead of
      // OrdinaryDefineOwnProperty to change the length,
      // and it doesn't have access to the descriptor anymore.
      new_len_desc->configurable() ||
      (new_len_desc->has_enumerable() &&
       (old_len_desc.enumerable() != new_len_desc->enumerable()))) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kRedefineDisallowed,
                                isolate->factory()->length_string()));
  }
  // 14. If newLenDesc.[[Writable]] is absent or has the value true,
  // let newWritable be true.
  bool new_writable = false;
  if (!new_len_desc->has_writable() || new_len_desc->writable()) {
    new_writable = true;
  } else {
    // 15. Else,
    // 15a. Need to defer setting the [[Writable]] attribute to false in case
    //      any elements cannot be deleted.
    // 15b. Let newWritable be false. (It's initialized as "false" anyway.)
    // 15c. Set newLenDesc.[[Writable]] to true.
    // (Not needed.)
  }
  // Most of steps 16 through 19 is implemented by JSArray::SetLength.
  MAYBE_RETURN(JSArray::SetLength(a, new_len), Nothing<bool>());
  // Steps 19d-ii, 20.
  if (!new_writable) {
    PropertyDescriptor readonly;
    readonly.set_writable(false);
    success = OrdinaryDefineOwnProperty(isolate, a,
                                        isolate->factory()->length_string(),
                                        &readonly, should_throw);
    DCHECK(success.FromJust());
    USE(success);
  }
  uint32_t actual_new_len = 0;
  CHECK(Object::ToArrayLength(a->length(), &actual_new_len));
  // Steps 19d-v, 21. Return false if there were non-deletable elements.
  bool result = actual_new_len == new_len;
  if (!result) {
    RETURN_FAILURE(
        isolate, GetShouldThrow(isolate, should_throw),
        NewTypeError(MessageTemplate::kStrictDeleteProperty,
                     isolate->factory()->NewNumberFromUint(actual_new_len - 1),
                     a));
  }
  return Just(result);
}

// ES6 9.5.6
// static
Maybe<bool> JSProxy::DefineOwnProperty(Isolate* isolate, Handle<JSProxy> proxy,
                                       Handle<Object> key,
                                       PropertyDescriptor* desc,
                                       Maybe<ShouldThrow> should_throw) {
  STACK_CHECK(isolate, Nothing<bool>());
  if (IsSymbol(*key) && Cast<Symbol>(key)->IsPrivate()) {
    DCHECK(!Cast<Symbol>(key)->IsPrivateName());
    return JSProxy::SetPrivateSymbol(isolate, proxy, Cast<Symbol>(key), desc,
                                     should_throw);
  }
  Handle<String> trap_name = isolate->factory()->defineProperty_string();
  // 1. Assert: IsPropertyKey(P) is true.
  DCHECK(IsName(*key) || IsNumber(*key));
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "defineProperty").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then:
  if (IsUndefined(*trap, isolate)) {
    // 7a. Return target.[[DefineOwnProperty]](P, Desc).
    return JSReceiver::DefineOwnProperty(isolate, target, key, desc,
                                         should_throw);
  }
  // 8. Let descObj be FromPropertyDescriptor(Desc).
  Handle<Object> desc_obj = desc->ToObject(isolate);
  // 9. Let booleanTrapResult be
  //    ToBoolean(? Call(trap, handler, «target, P, descObj»)).
  Handle<Name> property_name =
      IsName(*key) ? Cast<Name>(key)
                   : Cast<Name>(isolate->factory()->NumberToString(key));
  // Do not leak private property names.
  DCHECK(!property_name->IsPrivate());
  Handle<Object> trap_result_obj;
  Handle<Object> args[] = {target, property_name, desc_obj};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result_obj,
      Execution::Call(isolate, trap, handler, arraysize(args), args),
      Nothing<bool>());
  // 10. If booleanTrapResult is false, return false.
  if (!Object::BooleanValue(*trap_result_obj, isolate)) {
    RETURN_FAILURE(isolate, GetShouldThrow(isolate, should_throw),
                   NewTypeError(MessageTemplate::kProxyTrapReturnedFalsishFor,
                                trap_name, property_name));
  }
  // 11. Let targetDesc be ? target.[[GetOwnProperty]](P).
  PropertyDescriptor target_desc;
  Maybe<bool> target_found =
      JSReceiver::GetOwnPropertyDescriptor(isolate, target, key, &target_desc);
  MAYBE_RETURN(target_found, Nothing<bool>());
  // 12. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> maybe_extensible = JSReceiver::IsExtensible(isolate, target);
  MAYBE_RETURN(maybe_extensible, Nothing<bool>());
  bool extensible_target = maybe_extensible.FromJust();
  // 13. If Desc has a [[Configurable]] field and if Desc.[[Configurable]]
  //     is false, then:
  // 13a. Let settingConfigFalse be true.
  // 14. Else let settingConfigFalse be false.
  bool setting_config_false = desc->has_configurable() && !desc->configurable();
  // 15. If targetDesc is undefined, then
  if (!target_found.FromJust()) {
    // 15a. If extensibleTarget is false, throw a TypeError exception.
    if (!extensible_target) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonExtensible, property_name));
      return Nothing<bool>();
    }
    // 15b. If settingConfigFalse is true, throw a TypeError exception.
    if (setting_config_false) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonConfigurable, property_name));
      return Nothing<bool>();
    }
  } else {
    // 16. Else targetDesc is not undefined,
    // 16a. If IsCompatiblePropertyDescriptor(extensibleTarget, Desc,
    //      targetDesc) is false, throw a TypeError exception.
    Maybe<bool> valid = IsCompatiblePropertyDescriptor(
        isolate, extensible_target, desc, &target_desc, property_name,
        Just(kDontThrow));
    MAYBE_RETURN(valid, Nothing<bool>());
    if (!valid.FromJust()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyIncompatible, property_name));
      return Nothing<bool>();
    }
    // 16b. If settingConfigFalse is true and targetDesc.[[Configurable]] is
    //      true, throw a TypeError exception.
    if (setting_config_false && target_desc.configurable()) {
      isolate->Throw(*isolate->factory()->NewTypeError(
          MessageTemplate::kProxyDefinePropertyNonConfigurable, property_name));
      return Nothing<bool>();
    }
    // 16c. If IsDataDescriptor(targetDesc) is true,
    // targetDesc.[[Configurable]] is
    //       false, and targetDesc.[[Writable]] is true, then
    if (PropertyDescriptor::IsDataDescriptor(&target_desc) &&
        !target_desc.configurable() && target_desc.writable()) {
      // 16c i. If Desc has a [[Writable]] field and Desc.[[Writable]] is false,
      // throw a TypeError exception.
      if (desc->has_writable() && !desc->writable()) {
        isolate->Throw(*isolate->factory()->NewTypeError(
            MessageTemplate::kProxyDefinePropertyNonConfigurableWritable,
            property_name));
        return Nothing<bool>();
      }
    }
  }
  // 17. Return true.
  return Just(true);
}

// static
Maybe<bool> JSProxy::SetPrivateSymbol(Isolate* isolate, Handle<JSProxy> proxy,
                                      Handle<Symbol> private_name,
                                      PropertyDescriptor* desc,
                                      Maybe<ShouldThrow> should_throw) {
  // Despite the g
```