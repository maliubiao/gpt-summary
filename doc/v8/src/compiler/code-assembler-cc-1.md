Response:
My thinking process for summarizing the provided C++ code snippet goes like this:

1. **Identify the Core Functionality:** The code primarily deals with storing data in memory, specifically within the V8 JavaScript engine. Keywords like "Store," "OptimizedStoreField," "AtomicStore," and "WriteBarrier" immediately stand out. This points towards operations that write values to memory locations, often with specific considerations for garbage collection and concurrency.

2. **Categorize the Store Operations:** I notice various "Store" functions with different prefixes and suffixes:
    * `StoreToObject`:  General-purpose store with write barrier options.
    * `OptimizedStoreField`: Optimized store for object fields.
    * `OptimizedStoreIndirectPointerField`:  Stores to memory locations pointed to by other memory locations.
    * `OptimizedStoreMap`: Specifically for updating the "map" of an object (important for V8's object model).
    * `Store`: Basic store with a full write barrier.
    * `StoreEphemeronKey`:  Specialized store for ephemeron keys (related to weak references).
    * `StoreNoWriteBarrier`: Stores without triggering write barriers.
    * `UnsafeStoreNoWriteBarrier`:  Similar to `StoreNoWriteBarrier`, potentially with fewer checks.
    * `StoreFullTaggedNoWriteBarrier`: Stores tagged values without write barriers.
    * `AtomicStore`:  Atomic store operations for concurrent programming.

3. **Understand Write Barriers:** The concept of "WriteBarrier" appears frequently. I recall that write barriers are crucial for garbage collectors to track object references and prevent premature collection. The different types (kFull, kMap, kNone, kAssertNoWriteBarrier, kNoWriteBarrier, kIndirectPointerWriteBarrier, kEphemeronKeyWriteBarrier) indicate varying levels of strictness and purpose related to garbage collection.

4. **Focus on "Optimized":** The "Optimized" prefix suggests that these store operations are designed for performance. They likely take advantage of knowledge about the object's layout or type.

5. **Recognize Atomic Operations:** The "AtomicStore," "AtomicAdd," "AtomicSub," etc., functions clearly relate to atomic operations, used for thread-safe data manipulation.

6. **Identify Potential User Errors:** The comments within the code, like "Please use OptimizedStoreMap(base, value) instead," point to common mistakes developers might make when using these low-level functions. Using a general `Store` when a more specific and optimized version exists is a likely error. Incorrectly handling write barriers (or not handling them when necessary) is another significant potential error.

7. **Connect to JavaScript (If Applicable):** I consider how these low-level store operations relate to JavaScript behavior. While JavaScript itself doesn't have direct equivalents to these functions, they are the *underlying mechanisms* by which JavaScript object properties are set and updated. For example, when you do `object.property = value;` in JavaScript, V8 internally uses one of these store operations. The concept of "map" is also directly related to how V8 manages object structure. Atomic operations relate to the `SharedArrayBuffer` and `Atomics` API in JavaScript.

8. **Infer Code Logic (Hypothetical Inputs and Outputs):**  For functions like `AtomicAdd`, I can easily imagine a scenario where multiple threads are trying to increment a shared counter. I can define hypothetical inputs (the memory location, the value to add) and the expected output (the updated value and potentially the previous value).

9. **Structure the Summary:** I organize my findings into logical categories: core functionality, detailed breakdown of store operations, the role of write barriers, atomic operations, potential errors, and connections to JavaScript.

10. **Address the `.tq` Question:**  The prompt specifically asks about the `.tq` extension. I explicitly note that this file is `.cc` and thus C++, not Torque.

11. **Address the "Part 2" Instruction:**  The prompt mentions "Part 2". I focus the summary on the provided code snippet and avoid making assumptions about what might be in Part 1 or Part 3. I explicitly state that the summary is based on the given code.

By following these steps, I can generate a comprehensive and accurate summary of the provided V8 C++ code. The process involves understanding the technical terms, recognizing patterns, and making logical connections to higher-level concepts like garbage collection and JavaScript semantics.
好的，我们来归纳一下 `v8/src/compiler/code-assembler.cc` 代码片段的功能。

**功能归纳：**

这段代码主要提供了 `CodeAssembler` 类中用于在 V8 内部进行**内存存储操作**的一系列方法。这些方法是对更底层的 `RawMachineAssembler` 的封装，并针对不同的场景和需求提供了更高级别的抽象和优化。

**具体功能点：**

1. **通用存储 (Store)：**
   - 提供了基本的 `Store` 方法，用于将值存储到指定的内存地址。
   - 区分了是否需要写屏障 (Write Barrier)，写屏障是垃圾回收机制中用于追踪对象引用的重要手段。

2. **优化的字段存储 (OptimizedStoreField)：**
   - 提供了针对 HeapObject 字段存储的优化方法。
   - 允许指定不同的写屏障策略，例如：
     - `kFullWriteBarrier`:  执行完整的写屏障，确保垃圾回收器能正确追踪对象图。
     - `kMapWriteBarrier`: 仅针对 Map 字段的写屏障。
     - `kNone`:  不执行写屏障。
     - `kAssertNoWriteBarrier`:  断言此处不需要写屏障，用于优化。
   - `OptimizedStoreIndirectPointerField`:  用于存储间接指针字段。
   - `OptimizedStoreMap`:  专门用于更新对象的 Map (V8 中用于描述对象结构和类型的关键信息)。

3. **无写屏障存储 (StoreNoWriteBarrier, UnsafeStoreNoWriteBarrier)：**
   - 提供了显式地禁止写屏障的存储方法。
   - `UnsafeStoreNoWriteBarrier` 可能表示更底层的、没有安全检查的操作，需要谨慎使用。
   - 提供了存储完整的 Tagged 值且不带写屏障的版本 (`StoreFullTaggedNoWriteBarrier`).

4. **原子操作 (AtomicStore, AtomicAdd, AtomicSub 等)：**
   - 提供了原子存储操作，用于在多线程环境下安全地更新内存。
   - 支持多种原子操作，如加、减、与、或、异或、交换以及比较并交换。
   - 需要指定内存顺序 (`AtomicMemoryOrder`)，控制操作的可见性。

5. **根表存储 (StoreRoot)：**
   - 提供了存储到根表 (Roots Table) 的方法。根表存储了 V8 运行时的一些重要全局对象。
   - 限制了只能存储到可变的根 (non-immortal immovable roots)。

**与 JavaScript 的关系：**

虽然这段代码是 C++ 实现，但它直接关系到 JavaScript 的对象模型和内存管理。当你执行 JavaScript 代码，例如：

```javascript
const obj = {};
obj.property = 42;
```

V8 引擎在底层会使用类似于 `OptimizedStoreField` 或 `Store` 的操作，将值 `42` 存储到 `obj` 对象相应的内存位置。  `obj` 的结构信息（例如 `property` 的偏移量）会存储在其 `Map` 中，而 `OptimizedStoreMap` 就用于更新这个 `Map`。

垃圾回收器依赖于写屏障来追踪对象的引用，因此在修改对象属性时，V8 会根据情况插入相应的写屏障指令。

原子操作则与 JavaScript 的 `SharedArrayBuffer` 和 `Atomics` API 相关。当你使用 `Atomics.store()` 等方法时，V8 底层可能会调用 `AtomicStore` 这样的函数。

**代码逻辑推理 (假设输入与输出)：**

假设我们有以下代码：

```c++
TNode<HeapObject> my_object = ...; // 假设已经有一个 HeapObject
TNode<Int32T> value_to_store = Int32Constant(100);
int offset = 16; // 假设要存储的字段偏移量是 16

// 使用优化的字段存储
assembler->OptimizedStoreField(MachineRepresentation::kWord32, my_object, offset, value_to_store);
```

**假设输入：**

- `my_object`: 指向一个 V8 堆对象的指针。
- `value_to_store`:  表示整数值 100 的 Node。
- `offset`:  整数 16，表示要存储的字段在对象中的偏移量。
- `MachineRepresentation::kWord32`:  表示要存储的值是 32 位整数。

**预期输出：**

- `my_object` 指向的堆对象的偏移量为 16 的内存位置将被写入值 100。
- 由于使用的是 `OptimizedStoreField` 且默认带有 `kFullWriteBarrier`，垃圾回收器会记录这次修改，以便后续进行垃圾回收时能正确处理。

**用户常见的编程错误举例：**

1. **忘记写屏障或使用了错误的写屏障策略：**

   ```c++
   TNode<HeapObject> parent = ...;
   TNode<HeapObject> child = ...;

   // 错误地使用了无写屏障的存储，可能导致垃圾回收器过早回收 child
   assembler->UnsafeStoreNoWriteBarrier(MachineRepresentation::kTagged, parent, offset_of_child, child);
   ```

   如果 `child` 对象只被 `parent` 对象引用，并且这里没有执行写屏障，那么垃圾回收器可能认为 `child` 没有被引用，从而错误地回收它。

2. **在需要原子操作的场景下使用了非原子操作：**

   ```c++
   TNode<RawPtrT> shared_counter_ptr = ...; // 指向共享内存中的计数器
   TNode<Word32T> current_value = Load<Word32T>(shared_counter_ptr);
   TNode<Word32T> new_value = Int32Add(current_value, Int32Constant(1));
   // 在多线程环境下，这可能导致数据竞争
   Store<Word32T>(shared_counter_ptr, new_value);
   ```

   在多线程环境下，多个线程可能同时读取 `current_value`，然后都进行加一操作并存储，导致计数器最终的值小于预期。应该使用 `AtomicAdd` 来保证操作的原子性。

3. **错误地使用了 `Store` 而不是更优化的版本：**

   ```c++
   TNode<HeapObject> obj = ...;
   TNode<Map> new_map = ...;

   // 应该使用 OptimizedStoreMap
   assembler->Store(obj, offset_of_map, new_map);
   ```

   直接使用 `Store` 可能会遗漏一些针对特定字段的优化。

**总结这段代码的功能：**

这段 `v8/src/compiler/code-assembler.cc` 的代码片段是 `CodeAssembler` 类中用于执行各种内存存储操作的核心部分。它提供了不同级别的存储方法，包括通用存储、优化的字段存储、无写屏障存储以及原子操作。这些方法是 V8 引擎在执行 JavaScript 代码时操作对象和内存的关键底层机制。开发者在使用这些方法时需要理解写屏障和原子操作的重要性，以避免潜在的内存管理和并发问题。

**关于 `.tq` 扩展名：**

根据描述，如果 `v8/src/compiler/code-assembler.cc` 以 `.tq` 结尾，那么它才是 V8 Torque 源代码。由于它以 `.cc` 结尾，所以它是 **C++ 源代码**。Torque 是一种 V8 自研的类型化的中间语言，用于生成高效的汇编代码。

Prompt: 
```
这是目录为v8/src/compiler/code-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/code-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
er_kind;
  switch (write_barrier) {
    case StoreToObjectWriteBarrier::kFull:
      write_barrier_kind = WriteBarrierKind::kFullWriteBarrier;
      break;
    case StoreToObjectWriteBarrier::kMap:
      write_barrier_kind = WriteBarrierKind::kMapWriteBarrier;
      break;
    case StoreToObjectWriteBarrier::kNone:
      if (CanBeTaggedPointer(rep)) {
        write_barrier_kind = WriteBarrierKind::kAssertNoWriteBarrier;
      } else {
        write_barrier_kind = WriteBarrierKind::kNoWriteBarrier;
      }
      break;
  }
  raw_assembler()->StoreToObject(rep, object, offset, value,
                                 write_barrier_kind);
}

void CodeAssembler::OptimizedStoreField(MachineRepresentation rep,
                                        TNode<HeapObject> object, int offset,
                                        Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kFullWriteBarrier);
}

void CodeAssembler::OptimizedStoreIndirectPointerField(TNode<HeapObject> object,
                                                       int offset,
                                                       IndirectPointerTag tag,
                                                       Node* value) {
  raw_assembler()->OptimizedStoreIndirectPointerField(
      object, offset, tag, value,
      WriteBarrierKind::kIndirectPointerWriteBarrier);
}

void CodeAssembler::OptimizedStoreIndirectPointerFieldNoWriteBarrier(
    TNode<HeapObject> object, int offset, IndirectPointerTag tag, Node* value) {
  raw_assembler()->OptimizedStoreIndirectPointerField(
      object, offset, tag, value, WriteBarrierKind::kNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreFieldAssertNoWriteBarrier(
    MachineRepresentation rep, TNode<HeapObject> object, int offset,
    Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kAssertNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreFieldUnsafeNoWriteBarrier(
    MachineRepresentation rep, TNode<HeapObject> object, int offset,
    Node* value) {
  raw_assembler()->OptimizedStoreField(rep, object, offset, value,
                                       WriteBarrierKind::kNoWriteBarrier);
}

void CodeAssembler::OptimizedStoreMap(TNode<HeapObject> object,
                                      TNode<Map> map) {
  raw_assembler()->OptimizedStoreMap(object, map);
}

void CodeAssembler::Store(Node* base, Node* offset, Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(MachineRepresentation::kTagged, base, offset, value,
                         kFullWriteBarrier);
}

void CodeAssembler::StoreEphemeronKey(Node* base, Node* offset, Node* value) {
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(MachineRepresentation::kTagged, base, offset, value,
                         kEphemeronKeyWriteBarrier);
}

void CodeAssembler::StoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                        Node* value) {
  raw_assembler()->Store(
      rep, base, value,
      CanBeTaggedPointer(rep) ? kAssertNoWriteBarrier : kNoWriteBarrier);
}

void CodeAssembler::StoreNoWriteBarrier(MachineRepresentation rep, Node* base,
                                        Node* offset, Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(
      rep, base, offset, value,
      CanBeTaggedPointer(rep) ? kAssertNoWriteBarrier : kNoWriteBarrier);
}

void CodeAssembler::UnsafeStoreNoWriteBarrier(MachineRepresentation rep,
                                              Node* base, Node* value) {
  raw_assembler()->Store(rep, base, value, kNoWriteBarrier);
}

void CodeAssembler::UnsafeStoreNoWriteBarrier(MachineRepresentation rep,
                                              Node* base, Node* offset,
                                              Node* value) {
  // Please use OptimizedStoreMap(base, value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->Store(rep, base, offset, value, kNoWriteBarrier);
}

void CodeAssembler::StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base,
                                                  TNode<Object> tagged_value) {
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), base,
                      BitcastTaggedToWord(tagged_value));
}

void CodeAssembler::StoreFullTaggedNoWriteBarrier(TNode<RawPtrT> base,
                                                  TNode<IntPtrT> offset,
                                                  TNode<Object> tagged_value) {
  // Please use OptimizedStoreMap(base, tagged_value) instead.
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), base, offset,
                      BitcastTaggedToWord(tagged_value));
}

void CodeAssembler::AtomicStore(MachineRepresentation rep,
                                AtomicMemoryOrder order, TNode<RawPtrT> base,
                                TNode<WordT> offset, TNode<Word32T> value) {
  DCHECK(!raw_assembler()->IsMapOffsetConstantMinusTag(offset));
  raw_assembler()->AtomicStore(
      AtomicStoreParameters(rep, WriteBarrierKind::kNoWriteBarrier, order),
      base, offset, value);
}

void CodeAssembler::AtomicStore64(AtomicMemoryOrder order, TNode<RawPtrT> base,
                                  TNode<WordT> offset, TNode<UintPtrT> value,
                                  TNode<UintPtrT> value_high) {
  raw_assembler()->AtomicStore64(
      AtomicStoreParameters(MachineRepresentation::kWord64,
                            WriteBarrierKind::kNoWriteBarrier, order),
      base, offset, value, value_high);
}

#define ATOMIC_FUNCTION(name)                                                 \
  TNode<Word32T> CodeAssembler::Atomic##name(                                 \
      MachineType type, TNode<RawPtrT> base, TNode<UintPtrT> offset,          \
      TNode<Word32T> value) {                                                 \
    return UncheckedCast<Word32T>(                                            \
        raw_assembler()->Atomic##name(type, base, offset, value));            \
  }                                                                           \
  template <class Type>                                                       \
  TNode<Type> CodeAssembler::Atomic##name##64(                                \
      TNode<RawPtrT> base, TNode<UintPtrT> offset, TNode<UintPtrT> value,     \
      TNode<UintPtrT> value_high) {                                           \
    return UncheckedCast<Type>(                                               \
        raw_assembler()->Atomic##name##64(base, offset, value, value_high));  \
  }                                                                           \
  template TNode<AtomicInt64> CodeAssembler::Atomic##name##64 < AtomicInt64 > \
      (TNode<RawPtrT> base, TNode<UintPtrT> offset, TNode<UintPtrT> value,    \
       TNode<UintPtrT> value_high);                                           \
  template TNode<AtomicUint64> CodeAssembler::Atomic##name##64 <              \
      AtomicUint64 > (TNode<RawPtrT> base, TNode<UintPtrT> offset,            \
                      TNode<UintPtrT> value, TNode<UintPtrT> value_high);
ATOMIC_FUNCTION(Add)
ATOMIC_FUNCTION(Sub)
ATOMIC_FUNCTION(And)
ATOMIC_FUNCTION(Or)
ATOMIC_FUNCTION(Xor)
ATOMIC_FUNCTION(Exchange)
#undef ATOMIC_FUNCTION

TNode<Word32T> CodeAssembler::AtomicCompareExchange(MachineType type,
                                                    TNode<RawPtrT> base,
                                                    TNode<WordT> offset,
                                                    TNode<Word32T> old_value,
                                                    TNode<Word32T> new_value) {
  return UncheckedCast<Word32T>(raw_assembler()->AtomicCompareExchange(
      type, base, offset, old_value, new_value));
}

template <class Type>
TNode<Type> CodeAssembler::AtomicCompareExchange64(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high) {
  // This uses Uint64() intentionally: AtomicCompareExchange is not implemented
  // for Int64(), which is fine because the machine instruction only cares
  // about words.
  return UncheckedCast<Type>(raw_assembler()->AtomicCompareExchange64(
      base, offset, old_value, old_value_high, new_value, new_value_high));
}

template TNode<AtomicInt64> CodeAssembler::AtomicCompareExchange64<AtomicInt64>(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high);
template TNode<AtomicUint64>
CodeAssembler::AtomicCompareExchange64<AtomicUint64>(
    TNode<RawPtrT> base, TNode<WordT> offset, TNode<UintPtrT> old_value,
    TNode<UintPtrT> new_value, TNode<UintPtrT> old_value_high,
    TNode<UintPtrT> new_value_high);

void CodeAssembler::MemoryBarrier(AtomicMemoryOrder order) {
  raw_assembler()->MemoryBarrier(order);
}

void CodeAssembler::StoreRoot(RootIndex root_index, TNode<Object> value) {
  DCHECK(!RootsTable::IsImmortalImmovable(root_index));
  TNode<ExternalReference> isolate_root =
      ExternalConstant(ExternalReference::isolate_root(isolate()));
  int offset = IsolateData::root_slot_offset(root_index);
  StoreFullTaggedNoWriteBarrier(isolate_root, IntPtrConstant(offset), value);
}

Node* CodeAssembler::Projection(int index, Node* value) {
  DCHECK_LT(index, value->op()->ValueOutputCount());
  return raw_assembler()->Projection(index, value);
}

TNode<HeapObject> CodeAssembler::OptimizedAllocate(TNode<IntPtrT> size,
                                                   AllocationType allocation) {
  return UncheckedCast<HeapObject>(
      raw_assembler()->OptimizedAllocate(size, allocation));
}

void CodeAssembler::HandleException(Node* node) {
  if (state_->exception_handler_labels_.empty()) return;
  CodeAssemblerExceptionHandlerLabel* label =
      state_->exception_handler_labels_.back();

  if (node->op()->HasProperty(Operator::kNoThrow)) {
    return;
  }

  Label success(this), exception(this, Label::kDeferred);
  success.MergeVariables();
  exception.MergeVariables();

  raw_assembler()->Continuations(node, success.label_, exception.label_);

  Bind(&exception);
  const Operator* op = raw_assembler()->common()->IfException();
  Node* exception_value = raw_assembler()->AddNode(op, node, node);
  label->AddInputs({UncheckedCast<Object>(exception_value)});
  Goto(label->plain_label());

  Bind(&success);
  raw_assembler()->AddNode(raw_assembler()->common()->IfSuccess(), node);
}

namespace {
template <size_t kMaxSize>
class NodeArray {
 public:
  void Add(Node* node) {
    DCHECK_GT(kMaxSize, size());
    *ptr_++ = node;
  }

  Node* const* data() const { return arr_; }
  int size() const { return static_cast<int>(ptr_ - arr_); }

 private:
  Node* arr_[kMaxSize];
  Node** ptr_ = arr_;
};

#ifdef DEBUG
bool IsValidArgumentCountFor(const CallInterfaceDescriptor& descriptor,
                             size_t argument_count) {
  size_t parameter_count = descriptor.GetParameterCount();
  if (descriptor.AllowVarArgs()) {
    return argument_count >= parameter_count;
  } else {
    return argument_count == parameter_count;
  }
}
#endif  // DEBUG
}  // namespace

Node* CodeAssembler::CallRuntimeImpl(
    Runtime::FunctionId function, TNode<Object> context,
    std::initializer_list<TNode<Object>> args) {
  int result_size = Runtime::FunctionForId(function)->result_size;
#if V8_ENABLE_WEBASSEMBLY
  bool switch_to_the_central_stack =
      state_->kind_ == CodeKind::WASM_FUNCTION ||
      state_->kind_ == CodeKind::WASM_TO_JS_FUNCTION ||
      state_->kind_ == CodeKind::JS_TO_WASM_FUNCTION ||
      state_->builtin_ == Builtin::kJSToWasmWrapper ||
      state_->builtin_ == Builtin::kJSToWasmHandleReturns ||
      state_->builtin_ == Builtin::kWasmToJsWrapperCSA ||
      wasm::BuiltinLookup::IsWasmBuiltinId(state_->builtin_);
#else
  bool switch_to_the_central_stack = false;
#endif
  Builtin centry =
      Builtins::RuntimeCEntry(result_size, switch_to_the_central_stack);
  TNode<Code> centry_code =
      HeapConstantNoHole(isolate()->builtins()->code_handle(centry));
  constexpr size_t kMaxNumArgs = 7;
  DCHECK_GE(kMaxNumArgs, args.size());
  int argc = static_cast<int>(args.size());
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      zone(), function, argc, Operator::kNoProperties,
      Runtime::MayAllocate(function) ? CallDescriptor::kNoFlags
                                     : CallDescriptor::kNoAllocate);

  TNode<ExternalReference> ref =
      ExternalConstant(ExternalReference::Create(function));
  TNode<Int32T> arity = Int32Constant(argc);

  NodeArray<kMaxNumArgs + 4> inputs;
  inputs.Add(centry_code);
  for (const auto& arg : args) inputs.Add(arg);
  inputs.Add(ref);
  inputs.Add(arity);
  inputs.Add(context);

  CallPrologue();
  Node* return_value =
      raw_assembler()->CallN(call_descriptor, inputs.size(), inputs.data());
  HandleException(return_value);
  CallEpilogue();
  return return_value;
}

Builtin CodeAssembler::builtin() { return state()->builtin_; }

#if V8_ENABLE_WEBASSEMBLY
TNode<RawPtrT> CodeAssembler::SwitchToTheCentralStack() {
  TNode<ExternalReference> do_switch = ExternalConstant(
      ExternalReference::wasm_switch_to_the_central_stack_for_js());
  TNode<RawPtrT> central_stack_sp = TNode<RawPtrT>::UncheckedCast(CallCFunction(
      do_switch, MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(),
                     ExternalConstant(ExternalReference::isolate_address())),
      std::make_pair(MachineType::Pointer(), LoadFramePointer())));

  TNode<RawPtrT> old_sp = LoadStackPointer();
  SetStackPointer(central_stack_sp);
  return old_sp;
}

void CodeAssembler::SwitchFromTheCentralStack(TNode<RawPtrT> old_sp) {
  TNode<ExternalReference> do_switch = ExternalConstant(
      ExternalReference::wasm_switch_from_the_central_stack_for_js());
  CodeAssemblerLabel skip(this);
  GotoIf(IntPtrEqual(old_sp, UintPtrConstant(0)), &skip);
  CallCFunction(
      do_switch, MachineType::Pointer(),
      std::make_pair(MachineType::Pointer(),
                     ExternalConstant(ExternalReference::isolate_address())));
  SetStackPointer(old_sp);
  Goto(&skip);
  Bind(&skip);
}

TNode<RawPtrT> CodeAssembler::SwitchToTheCentralStackIfNeeded() {
  TVariable<RawPtrT> old_sp(PointerConstant(nullptr), this);
  Label no_switch(this);
  Label end(this);  // -> return value of the call (kTaggedPointer)
  TNode<Uint8T> is_on_central_stack_flag = LoadUint8FromRootRegister(
      IntPtrConstant(IsolateData::is_on_central_stack_flag_offset()));
  GotoIf(is_on_central_stack_flag, &no_switch);
  old_sp = SwitchToTheCentralStack();
  Goto(&no_switch);
  Bind(&no_switch);
  return old_sp.value();
}
#endif

void CodeAssembler::TailCallRuntimeImpl(
    Runtime::FunctionId function, TNode<Int32T> arity, TNode<Object> context,
    std::initializer_list<TNode<Object>> args) {
  int result_size = Runtime::FunctionForId(function)->result_size;
#if V8_ENABLE_WEBASSEMBLY
  bool switch_to_the_central_stack =
      state_->kind_ == CodeKind::WASM_FUNCTION ||
      state_->kind_ == CodeKind::WASM_TO_JS_FUNCTION ||
      state_->kind_ == CodeKind::JS_TO_WASM_FUNCTION ||
      state_->builtin_ == Builtin::kJSToWasmWrapper ||
      state_->builtin_ == Builtin::kJSToWasmHandleReturns ||
      state_->builtin_ == Builtin::kWasmToJsWrapperCSA ||
      wasm::BuiltinLookup::IsWasmBuiltinId(state_->builtin_);
#else
  bool switch_to_the_central_stack = false;
#endif
  Builtin centry =
      Builtins::RuntimeCEntry(result_size, switch_to_the_central_stack);
  TNode<Code> centry_code =
      HeapConstantNoHole(isolate()->builtins()->code_handle(centry));

  constexpr size_t kMaxNumArgs = 6;
  DCHECK_GE(kMaxNumArgs, args.size());
  int argc = static_cast<int>(args.size());
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      zone(), function, argc, Operator::kNoProperties,
      CallDescriptor::kNoFlags);

  TNode<ExternalReference> ref =
      ExternalConstant(ExternalReference::Create(function));

  NodeArray<kMaxNumArgs + 4> inputs;
  inputs.Add(centry_code);
  for (const auto& arg : args) inputs.Add(arg);
  inputs.Add(ref);
  inputs.Add(arity);
  inputs.Add(context);

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallStubN(StubCallMode call_mode,
                               const CallInterfaceDescriptor& descriptor,
                               int input_count, Node* const* inputs) {
  DCHECK(call_mode == StubCallMode::kCallCodeObject ||
         call_mode == StubCallMode::kCallBuiltinPointer);

  // implicit nodes are target and optionally context.
  int implicit_nodes = descriptor.HasContextParameter() ? 2 : 1;
  DCHECK_LE(implicit_nodes, input_count);
  int argc = input_count - implicit_nodes;
  DCHECK(IsValidArgumentCountFor(descriptor, argc));
  // Extra arguments not mentioned in the descriptor are passed on the stack.
  int stack_parameter_count = argc - descriptor.GetRegisterParameterCount();
  DCHECK_LE(descriptor.GetStackParameterCount(), stack_parameter_count);

  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, stack_parameter_count, CallDescriptor::kNoFlags,
      Operator::kNoProperties, call_mode);

  CallPrologue();
  Node* return_value =
      raw_assembler()->CallN(call_descriptor, input_count, inputs);
  HandleException(return_value);
  CallEpilogue();
  return return_value;
}

void CodeAssembler::TailCallStubImpl(const CallInterfaceDescriptor& descriptor,
                                     TNode<Code> target, TNode<Object> context,
                                     std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 11;
  DCHECK_GE(kMaxNumArgs, args.size());
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount(),
      CallDescriptor::kNoFlags, Operator::kNoProperties);

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallStubRImpl(StubCallMode call_mode,
                                   const CallInterfaceDescriptor& descriptor,
                                   TNode<Object> target, TNode<Object> context,
                                   std::initializer_list<Node*> args) {
  DCHECK(call_mode == StubCallMode::kCallCodeObject ||
         call_mode == StubCallMode::kCallBuiltinPointer);
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));

  constexpr size_t kMaxNumArgs = 10;
  DCHECK_GE(kMaxNumArgs, args.size());

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  return CallStubN(call_mode, descriptor, inputs.size(), inputs.data());
}

Node* CodeAssembler::CallJSStubImpl(
    const CallInterfaceDescriptor& descriptor, TNode<Object> target,
    TNode<Object> context, TNode<Object> function,
    std::optional<TNode<Object>> new_target, TNode<Int32T> arity,
    std::optional<TNode<JSDispatchHandleT>> dispatch_handle,
    std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 10;
  DCHECK_GE(kMaxNumArgs, args.size());
  NodeArray<kMaxNumArgs + 6> inputs;

  inputs.Add(target);
  inputs.Add(function);
  if (new_target) {
    inputs.Add(*new_target);
  }
  inputs.Add(arity);
#ifdef V8_ENABLE_LEAPTIERING
  if (dispatch_handle) {
    inputs.Add(*dispatch_handle);
  }
#endif
  for (auto arg : args) inputs.Add(arg);
  // Context argument is implicit so isn't counted.
  DCHECK(IsValidArgumentCountFor(descriptor, inputs.size()));
  if (descriptor.HasContextParameter()) {
    inputs.Add(context);
  }

  return CallStubN(StubCallMode::kCallCodeObject, descriptor, inputs.size(),
                   inputs.data());
}

void CodeAssembler::TailCallStubThenBytecodeDispatchImpl(
    const CallInterfaceDescriptor& descriptor, Node* target, Node* context,
    std::initializer_list<Node*> args) {
  constexpr size_t kMaxNumArgs = 6;
  DCHECK_GE(kMaxNumArgs, args.size());
  DCHECK(IsValidArgumentCountFor(descriptor, args.size()));

  int argc = static_cast<int>(args.size());
  // Extra arguments not mentioned in the descriptor are passed on the stack.
  int stack_parameter_count = argc - descriptor.GetRegisterParameterCount();
  DCHECK_LE(descriptor.GetStackParameterCount(), stack_parameter_count);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, stack_parameter_count, CallDescriptor::kNoFlags,
      Operator::kNoProperties);

  NodeArray<kMaxNumArgs + 2> inputs;
  inputs.Add(target);
  for (auto arg : args) inputs.Add(arg);
  inputs.Add(context);

  raw_assembler()->TailCallN(call_descriptor, inputs.size(), inputs.data());
}

template <class... TArgs>
void CodeAssembler::TailCallBytecodeDispatch(
    const CallInterfaceDescriptor& descriptor, TNode<RawPtrT> target,
    TArgs... args) {
  DCHECK_EQ(descriptor.GetParameterCount(), sizeof...(args));
  auto call_descriptor = Linkage::GetBytecodeDispatchCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount());

  Node* nodes[] = {target, args...};
  CHECK_EQ(descriptor.GetParameterCount() + 1, arraysize(nodes));
  raw_assembler()->TailCallN(call_descriptor, arraysize(nodes), nodes);
}

// Instantiate TailCallBytecodeDispatch() for argument counts used by
// CSA-generated code
template V8_EXPORT_PRIVATE void CodeAssembler::TailCallBytecodeDispatch(
    const CallInterfaceDescriptor& descriptor, TNode<RawPtrT> target,
    TNode<Object>, TNode<IntPtrT>, TNode<BytecodeArray>,
    TNode<ExternalReference>);

void CodeAssembler::TailCallJSCode(TNode<Code> code, TNode<Context> context,
                                   TNode<JSFunction> function,
                                   TNode<Object> new_target,
                                   TNode<Int32T> arg_count,
                                   TNode<JSDispatchHandleT> dispatch_handle) {
  JSTrampolineDescriptor descriptor;
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      zone(), descriptor, descriptor.GetStackParameterCount(),
      CallDescriptor::kFixedTargetRegister, Operator::kNoProperties,
      StubCallMode::kCallCodeObject);

#ifdef V8_ENABLE_LEAPTIERING
  Node* nodes[] = {code,      function,        new_target,
                   arg_count, dispatch_handle, context};
#else
  Node* nodes[] = {code, function, new_target, arg_count, context};
#endif
  // + 2 for code and context.
  CHECK_EQ(descriptor.GetParameterCount() + 2, arraysize(nodes));
  raw_assembler()->TailCallN(call_descriptor, arraysize(nodes), nodes);
}

Node* CodeAssembler::CallCFunctionN(Signature<MachineType>* signature,
                                    int input_count, Node* const* inputs) {
  auto call_descriptor = Linkage::GetSimplifiedCDescriptor(zone(), signature);
  return raw_assembler()->CallN(call_descriptor, input_count, inputs);
}

Node* CodeAssembler::CallCFunction(
    Node* function, std::optional<MachineType> return_type,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  return raw_assembler()->CallCFunction(function, return_type, args);
}

Node* CodeAssembler::CallCFunctionWithoutFunctionDescriptor(
    Node* function, MachineType return_type,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  return raw_assembler()->CallCFunctionWithoutFunctionDescriptor(
      function, return_type, args);
}

Node* CodeAssembler::CallCFunctionWithCallerSavedRegisters(
    Node* function, MachineType return_type, SaveFPRegsMode mode,
    std::initializer_list<CodeAssembler::CFunctionArg> args) {
  DCHECK(return_type.LessThanOrEqualPointerSize());
  return raw_assembler()->CallCFunctionWithCallerSavedRegisters(
      function, return_type, mode, args);
}

void CodeAssembler::Goto(Label* label) {
  label->MergeVariables();
  raw_assembler()->Goto(label->label_);
}

void CodeAssembler::GotoIf(TNode<IntegralT> condition, Label* true_label) {
  Label false_label(this);
  Branch(condition, true_label, &false_label);
  Bind(&false_label);
}

void CodeAssembler::GotoIfNot(TNode<IntegralT> condition, Label* false_label) {
  Label true_label(this);
  Branch(condition, &true_label, false_label);
  Bind(&true_label);
}

void CodeAssembler::Branch(TNode<IntegralT> condition, Label* true_label,
                           Label* false_label) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    if ((true_label->is_used() || true_label->is_bound()) &&
        (false_label->is_used() || false_label->is_bound())) {
      return Goto(constant ? true_label : false_label);
    }
  }
  true_label->MergeVariables();
  false_label->MergeVariables();
  return raw_assembler()->Branch(condition, true_label->label_,
                                 false_label->label_);
}

void CodeAssembler::Branch(TNode<BoolT> condition,
                           const std::function<void()>& true_body,
                           const std::function<void()>& false_body) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? true_body() : false_body();
  }

  Label vtrue(this), vfalse(this);
  Branch(condition, &vtrue, &vfalse);

  Bind(&vtrue);
  true_body();

  Bind(&vfalse);
  false_body();
}

void CodeAssembler::Branch(TNode<BoolT> condition, Label* true_label,
                           const std::function<void()>& false_body) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? Goto(true_label) : false_body();
  }

  Label vfalse(this);
  Branch(condition, true_label, &vfalse);
  Bind(&vfalse);
  false_body();
}

void CodeAssembler::Branch(TNode<BoolT> condition,
                           const std::function<void()>& true_body,
                           Label* false_label) {
  int32_t constant;
  if (TryToInt32Constant(condition, &constant)) {
    return constant ? true_body() : Goto(false_label);
  }

  Label vtrue(this);
  Branch(condition, &vtrue, false_label);
  Bind(&vtrue);
  true_body();
}

void CodeAssembler::Switch(Node* index, Label* default_label,
                           const int32_t* case_values, Label** case_labels,
                           size_t case_count) {
  RawMachineLabel** labels =
      zone()->AllocateArray<RawMachineLabel*>(case_count);
  for (size_t i = 0; i < case_count; ++i) {
    labels[i] = case_labels[i]->label_;
    case_labels[i]->MergeVariables();
  }
  default_label->MergeVariables();
  return raw_assembler()->Switch(index, default_label->label_, case_values,
                                 labels, case_count);
}

bool CodeAssembler::UnalignedLoadSupported(MachineRepresentation rep) const {
  return raw_assembler()->machine()->UnalignedLoadSupported(rep);
}
bool CodeAssembler::UnalignedStoreSupported(MachineRepresentation rep) const {
  return raw_assembler()->machine()->UnalignedStoreSupported(rep);
}

// RawMachineAssembler delegate helpers:
Isolate* CodeAssembler::isolate() const { return raw_assembler()->isolate(); }

Factory* CodeAssembler::factory() const { return isolate()->factory(); }

Zone* CodeAssembler::zone() const { return raw_assembler()->zone(); }

bool CodeAssembler::IsExceptionHandlerActive() const {
  return !state_->exception_handler_labels_.empty();
}

RawMachineAssembler* CodeAssembler::raw_assembler() const {
  return state_->raw_assembler_.get();
}

JSGraph* CodeAssembler::jsgraph() const { return state_->jsgraph_; }

// The core implementation of Variable is stored through an indirection so
// that it can outlive the often block-scoped Variable declarations. This is
// needed to ensure that variable binding and merging through phis can
// properly be verified.
class CodeAssemblerVariable::Impl : public ZoneObject {
 public:
  explicit Impl(MachineRepresentation rep, CodeAssemblerState::VariableId id)
      :
#if DEBUG
        debug_info_(AssemblerDebugInfo(nullptr, nullptr, -1)),
#endif
        value_(nullptr),
        rep_(rep),
        var_id_(id) {
  }

#if DEBUG
  AssemblerDebugInfo debug_info() const { return debug_info_; }
  void set_debug_info(AssemblerDebugInfo debug_info) {
    debug_info_ = debug_info;
  }

  AssemblerDebugInfo debug_info_;
#endif  // DEBUG
  bool operator<(const CodeAssemblerVariable::Impl& other) const {
    return var_id_ < other.var_id_;
  }
  Node* value_;
  MachineRepresentation rep_;
  CodeAssemblerState::VariableId var_id_;
};

bool CodeAssemblerVariable::ImplComparator::operator()(
    const CodeAssemblerVariable::Impl* a,
    const CodeAssemblerVariable::Impl* b) const {
  return *a < *b;
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             MachineRepresentation rep)
    : impl_(assembler->zone()->New<Impl>(rep,
                                         assembler->state()->NextVariableId())),
      state_(assembler->state()) {
  state_->variables_.insert(impl_);
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             MachineRepresentation rep,
                                             Node* initial_value)
    : CodeAssemblerVariable(assembler, rep) {
  Bind(initial_value);
}

#if DEBUG
CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             AssemblerDebugInfo debug_info,
                                             MachineRepresentation rep)
    : impl_(assembler->zone()->New<Impl>(rep,
                                         assembler->state()->NextVariableId())),
      state_(assembler->state()) {
  impl_->set_debug_info(debug_info);
  state_->variables_.insert(impl_);
}

CodeAssemblerVariable::CodeAssemblerVariable(CodeAssembler* assembler,
                                             AssemblerDebugInfo debug_info,
                                             MachineRepresentation rep,
                                             Node* initial_value)
    : CodeAssemblerVariable(assembler, debug_info, rep) {
  impl_->set_debug_info(debug_info);
  Bind(initial_value);
}
#endif  // DEBUG

CodeAssemblerVariable::~CodeAssemblerVariable() {
  state_->variables_.erase(impl_);
}

void CodeAssemblerVariable::Bind(Node* value) { impl_->value_ = value; }

Node* CodeAssemblerVariable::value() const {
#if DEBUG
  if (!IsBound()) {
    std::stringstream str;
    str << "#Use of unbound variable:"
        << "#\n    Variable:      " << *this << "#\n    Current Block: ";
    state_->PrintCurrentBlock(str);
    FATAL("%s", str.str().c_str());
  }
  if (!state_->InsideBlock()) {
    std::stringstream str;
    str << "#Accessing variable value outside a block:"
        << "#\n    Variable:      " << *this;
    FATAL("%s", str.str().c_str());
  }
#endif  // DEBUG
  return impl_->value_;
}

MachineRepresentation CodeAssemblerVariable::rep() const { return impl_->rep_; }

bool CodeAssemblerVariable::IsBound() const { return impl_->value_ != nullptr; }

std::ostream& operator<<(std::ostream& os,
                         const CodeAssemblerVariable::Impl& impl) {
#if DEBUG
  AssemblerDebugInfo info = impl.debug_info();
  if (info.name) os << "V" << info;
#endif  // DEBUG
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const CodeAssemblerVariable& variable) {
  os << *variable.impl_;
  return os;
}

CodeAssemblerLabel::CodeAssemblerLabel(CodeAssembler* assembler,
                                       size_t vars_count,
                                       CodeAssemblerVariable* const* vars,
                                       CodeAssemblerLabel::Type type)
    : bound_(false),
      merge_count_(0),
      state_(assembler->state()),
      label_(nullptr) {
  label_ = assembler->zone()->New<RawMachineLabel>(
      type == kDeferred ? RawMachineLabel::kDeferred
                        : RawMachineLabel::kNonDeferred);
  for (size_t i = 0; i < vars_count; ++i) {
    variable_phis_[vars[i]->impl_] = nullptr;
  }
}

CodeAssemblerLabel::~CodeAssemblerLabel() { label_->~R
"""


```