Response:
The user wants to understand the functionality of the V8 source code file `v8/src/builtins/builtins-collections-gen.cc`. I need to analyze the provided C++ code and address the specific questions:

1. **List its functionalities**: I need to identify the primary purpose and the different operations implemented in this file. Based on the includes and the code, it seems related to the implementation of built-in JavaScript collection objects like Map and Set.
2. **Torque source code**: Check if the filename ends with `.tq`. If not, it's not a Torque file.
3. **Relationship with Javascript**: Explain how the C++ code relates to the behavior of JavaScript `Map` and `Set` objects. Provide JavaScript examples.
4. **Code logic inference**: Identify code segments that perform logical operations and provide example inputs and outputs.
5. **Common programming errors**: Point out potential pitfalls or mistakes developers might make when using these collections in JavaScript.
6. **Overall summary**:  Provide a concise summary of the file's purpose.

**Analysis of the code:**

- **Includes**: The included headers suggest this file deals with:
    - Constructor built-ins (`builtins-constructor-gen.h`)
    - Iterator built-ins (`builtins-iterator-gen.h`)
    - Utility built-ins (`builtins-utils-gen.h`)
    - Code generation (`code-stub-assembler-inl.h`)
    - Execution context and protectors (`execution/protectors.h`)
    - Heap management (`heap/factory-inl.h`, `heap/heap-inl.h`)
    - Hash table implementation (`objects/hash-table-inl.h`, `objects/ordered-hash-table.h`)
    - JS collection objects (`objects/js-collection.h`)
    - Root objects (`roots/roots.h`)
- **Namespaces**: The code is within the `v8::internal` namespace.
- **`BaseCollectionsAssembler`**: This class seems to provide common functionalities for different collection types. Methods like `AddConstructorEntry`, `AddConstructorEntries`, `GenerateConstructor`, `GetAddFunction` are present.
- **`CollectionsBuiltinsAssembler`**: This class appears to implement specific built-in functions for collections like `MapConstructor` and `SetConstructor`.
- **Key operations**: The code contains logic for:
    - Adding entries to collections during construction.
    - Handling different types of initializers (iterables, arrays).
    - Implementing fast paths for common scenarios.
    - Allocating and managing the underlying hash tables.
    - Implementing iterators for collections.
    - Handling weak collections.
- **Torque**: The instruction states that if the filename ends with `.tq`, it's a Torque file. This file ends with `.cc`, so it's not a Torque file.

**Plan:**

1. State that the file is a C++ source file for V8 built-ins.
2. List the main functionalities based on the code analysis (constructor, adding elements, iterators, etc.).
3. Confirm that it's not a Torque file because of the `.cc` extension.
4. Explain the connection to JavaScript `Map` and `Set` by showing how the C++ code implements their behavior. Provide JavaScript examples of creating and adding elements to `Map` and `Set`.
5. Select a simple code segment (e.g., `AddConstructorEntry`) and provide hypothetical input and output to illustrate its logic.
6. Give examples of common JavaScript errors when working with `Map` and `Set` (e.g., using non-object keys in `WeakMap`).
7. Summarize the file's role in implementing the core behavior of JavaScript collections within V8.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-collections-gen.h"

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-iterator-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/protectors.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-collection.h"
#include "src/objects/ordered-hash-table.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

template <class T>
using TVariable = compiler::TypedCodeAssemblerVariable<T>;

void BaseCollectionsAssembler::AddConstructorEntry(
    Variant variant, TNode<Context> context, TNode<Object> collection,
    TNode<Object> add_function, TNode<Object> key_value,
    Label* if_may_have_side_effects, Label* if_exception,
    TVariable<Object>* var_exception) {
  compiler::ScopedExceptionHandler handler(this, if_exception, var_exception);
  CSA_DCHECK(this, Word32BinaryNot(IsHashTableHole(key_value)));
  if (variant == kMap || variant == kWeakMap) {
    TorqueStructKeyValuePair pair =
        if_may_have_side_effects != nullptr
            ? LoadKeyValuePairNoSideEffects(context, key_value,
                                            if_may_have_side_effects)
            : LoadKeyValuePair(context, key_value);
    TNode<Object> key_n = pair.key;
    TNode<Object> value_n = pair.value;
    Call(context, add_function, collection, key_n, value_n);
  } else {
    DCHECK(variant == kSet || variant == kWeakSet);
    Call(context, add_function, collection, key_value);
  }
}

void BaseCollectionsAssembler::AddConstructorEntries(
    Variant variant, TNode<Context> context,
    TNode<NativeContext> native_context, TNode<HeapObject> collection,
    TNode<Object> initial_entries) {
  CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(initial_entries)));

  enum Mode { kSlow, kFastJSArray, kFastCollection };
  TVARIABLE(IntPtrT, var_at_least_space_for, IntPtrConstant(0));
  TVARIABLE(HeapObject, var_entries_table, UndefinedConstant());
  TVARIABLE(Int32T, var_mode, Int32Constant(kSlow));
  Label if_fast_js_array(this), allocate_table(this);

  // The slow path is taken if the initial add function is modified. This check
  // must precede the kSet fast path below, which has the side effect of
  // exhausting {initial_entries} if it is a JSSetIterator.
  GotoIfInitialAddFunctionModified(variant, native_context, collection,
                                   &allocate_table);

  GotoIf(IsFastJSArrayWithNoCustomIteration(context, initial_entries),
         &if_fast_js_array);
  if (variant == Variant::kSet) {
    GetEntriesIfFastCollectionOrIterable(
        variant, initial_entries, context, &var_entries_table,
        &var_at_least_space_for, &allocate_table);
    var_mode = Int32Constant(kFastCollection);
    Goto(&allocate_table);
  } else {
    Goto(&allocate_table);
  }
  BIND(&if_fast_js_array);
  {
    var_mode = Int32Constant(kFastJSArray);
    if (variant == kWeakSet || variant == kWeakMap) {
      var_at_least_space_for =
          PositiveSmiUntag(LoadFastJSArrayLength(CAST(initial_entries)));
    } else {
      // TODO(ishell): consider using array length for all collections
      static_assert(OrderedHashSet::kInitialCapacity ==
                    OrderedHashMap::kInitialCapacity);
      var_at_least_space_for = IntPtrConstant(OrderedHashSet::kInitialCapacity);
    }
    Goto(&allocate_table);
  }
  TVARIABLE(JSReceiver, var_iterator_object);
  TVARIABLE(Object, var_exception);
  Label exit(this), from_fast_jsarray(this), from_fast_collection(this),
      slow_loop(this, Label::kDeferred), if_exception(this, Label::kDeferred);
  BIND(&allocate_table);
  {
    TNode<HeapObject> table =
        AllocateTable(variant, var_at_least_space_for.value());
    StoreObjectField(collection, GetTableOffset(variant), table);
    if (variant == Variant::kSet) {
      GotoIf(Word32Equal(var_mode.value(), Int32Constant(kFastCollection)),
             &from_fast_collection);
    }
    Branch(Word32Equal(var_mode.value(), Int32Constant(kFastJSArray)),
           &from_fast_jsarray, &slow_loop);
  }
  BIND(&from_fast_jsarray);
  {
    Label if_exception_during_fast_iteration(this, Label::kDeferred);
    TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
    TNode<JSArray> initial_entries_jsarray =
        UncheckedCast<JSArray>(initial_entries);
#if DEBUG
    CSA_DCHECK(this, IsFastJSArrayWithNoCustomIteration(
                         context, initial_entries_jsarray));
    TNode<Map> original_initial_entries_map = LoadMap(initial_entries_jsarray);
#endif

    Label if_may_have_side_effects(this, Label::kDeferred);
    {
      compiler::ScopedExceptionHandler handler(
          this, &if_exception_during_fast_iteration, &var_exception);
      AddConstructorEntriesFromFastJSArray(
          variant, context, native_context, collection, initial_entries_jsarray,
          &if_may_have_side_effects, var_index);
    }
    Goto(&exit);

    if (variant == kMap || variant == kWeakMap) {
      BIND(&if_may_have_side_effects);
#if DEBUG
      {
        // Check that add/set function has not been modified.
        Label if_not_modified(this), if_modified(this);
        GotoIfInitialAddFunctionModified(variant, native_context, collection,
                                         &if_modified);
        Goto(&if_not_modified);
        BIND(&if_modified);
        Unreachable();
        BIND(&if_not_modified);
      }
      CSA_DCHECK(this, TaggedEqual(original_initial_entries_map,
                                   LoadMap(initial_entries_jsarray)));
#endif
      var_mode = Int32Constant(kSlow);
      Goto(&allocate_table);
    }
    BIND(&if_exception_during_fast_iteration);
    {
      // In case exception is thrown during collection population, materialize
      // the iteator and execute iterator closing protocol. It might be
      // non-trivial in case "return" callback is added somewhere in the
      // iterator's prototype chain.
      TNode<NativeContext> native_context = LoadNativeContext(context);
      TNode<IntPtrT> next_index =
          IntPtrAdd(var_index.value(), IntPtrConstant(1));
      var_iterator_object = CreateArrayIterator(
          native_context, UncheckedCast<JSArray>(initial_entries),
          IterationKind::kValues, SmiTag(next_index));
      Goto(&if_exception);
    }
  }
  if (variant == Variant::kSet) {
    BIND(&from_fast_collection);
    {
      AddConstructorEntriesFromFastCollection(variant, collection,
                                              var_entries_table.value());
      Goto(&exit);
    }
  }
  BIND(&slow_loop);
  {
    AddConstructorEntriesFromIterable(
        variant, context, native_context, collection, initial_entries,
        &if_exception, &var_iterator_object, &var_exception);
    Goto(&exit);
  }
  BIND(&if_exception);
  {
    TNode<HeapObject> message = GetPendingMessage();
    SetPendingMessage(TheHoleConstant());
    // iterator.next field is not used by IteratorCloseOnException.
    TorqueStructIteratorRecord iterator = {var_iterator_object.value(), {}};
    IteratorCloseOnException(context, iterator);
    CallRuntime(Runtime::kReThrowWithMessage, context, var_exception.value(),
                message);
    Unreachable();
  }
  BIND(&exit);
}

void BaseCollectionsAssembler::AddConstructorEntriesFromFastJSArray(
    Variant variant, TNode<Context> context, TNode<Context> native_context,
    TNode<Object> collection, TNode<JSArray> fast_jsarray,
    Label* if_may_have_side_effects, TVariable<IntPtrT>& var_current_index) {
  TNode<FixedArrayBase> elements = LoadElements(fast_jsarray);
  TNode<Int32T> elements_kind = LoadElementsKind(fast_jsarray);
  TNode<JSFunction> add_func = GetInitialAddFunction(variant, native_context);
  CSA_DCHECK(this,
             TaggedEqual(GetAddFunction(variant, native_context, collection),
                         add_func));
  CSA_DCHECK(this, IsFastJSArrayWithNoCustomIteration(context, fast_jsarray));
  TNode<IntPtrT> length = PositiveSmiUntag(LoadFastJSArrayLength(fast_jsarray));
  CSA_DCHECK(
      this, HasInitialCollectionPrototype(variant, native_context, collection));

#if DEBUG
  TNode<Map> original_collection_map = LoadMap(CAST(collection));
  TNode<Map> original_fast_js_array_map = LoadMap(fast_jsarray);
#endif
  Label exit(this), if_doubles(this), if_smiorobjects(this);
  GotoIf(IntPtrEqual(length, IntPtrConstant(0)), &exit);
  Branch(IsFastSmiOrTaggedElementsKind(elements_kind), &if_smiorobjects,
         &if_doubles);
  BIND(&if_smiorobjects);
  {
    auto set_entry = [&](TNode<IntPtrT> index) {
      TNode<Object> element =
          LoadAndNormalizeFixedArrayElement(CAST(elements), index);
      AddConstructorEntry(variant, context, collection, add_func, element,
                          if_may_have_side_effects);
    };

    // Instead of using the slower iteration protocol to iterate over the
    // elements, a fast loop is used. This assumes that adding an element
    // to the collection does not call user code that could mutate the elements
    // or collection.
    BuildFastLoop<IntPtrT>(var_current_index, IntPtrConstant(0), length,
                           set_entry, 1, LoopUnrollingMode::kNo,
                           IndexAdvanceMode::kPost);
    Goto(&exit);
  }
  BIND(&if_doubles);
  {
    // A Map constructor requires entries to be arrays (ex. [key, value]),
    // so a FixedDoubleArray can never succeed.
    if (variant == kMap || variant == kWeakMap) {
      CSA_DCHECK(this, IntPtrGreaterThan(length, IntPtrConstant(0)));
      TNode<Object> element =
          LoadAndNormalizeFixedDoubleArrayElement(elements, IntPtrConstant(0));
      ThrowTypeError(context, MessageTemplate::kIteratorValueNotAnObject,
                     element);
    } else {
      DCHECK(variant == kSet || variant == kWeakSet);
      auto set_entry = [&](TNode<IntPtrT> index) {
        TNode<Object> entry = LoadAndNormalizeFixedDoubleArrayElement(
            elements, UncheckedCast<IntPtrT>(index));
        AddConstructorEntry(variant, context, collection, add_func, entry);
      };
      BuildFastLoop<IntPtrT>(var_current_index, IntPtrConstant(0), length,
                             set_entry, 1, LoopUnrollingMode::kNo,
                             IndexAdvanceMode::kPost);
      Goto(&exit);
    }
  }
  BIND(&exit);
#if DEBUG
  CSA_DCHECK(this,
             TaggedEqual(original_collection_map, LoadMap(CAST(collection))));
  CSA_DCHECK(this,
             TaggedEqual(original_fast_js_array_map, LoadMap(fast_jsarray)));
#endif
}

void BaseCollectionsAssembler::AddConstructorEntriesFromIterable(
    Variant variant, TNode<Context> context, TNode<Context> native_context,
    TNode<Object> collection, TNode<Object> iterable, Label* if_exception,
    TVariable<JSReceiver>* var_iterator_object,
    TVariable<Object>* var_exception) {
  Label exit(this), loop(this);
  CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(iterable)));
  TNode<Object> add_func = GetAddFunction(variant, context, collection);
  IteratorBuiltinsAssembler iterator_assembler(this->state());
  TorqueStructIteratorRecord iterator =
      iterator_assembler.GetIterator(context, iterable);
  *var_iterator_object = iterator.object;

  CSA_DCHECK(this, Word32BinaryNot(IsUndefined(iterator.object)));

  TNode<Map> fast_iterator_result_map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));

  Goto(&loop);
  BIND(&loop);
  {
    TNode<JSReceiver> next = iterator_assembler.IteratorStep(
        context, iterator, &exit, fast_iterator_result_map);
    TNode<Object> next_value = iterator_assembler.IteratorValue(
        context, next, fast_iterator_result_map);
    AddConstructorEntry(variant, context, collection, add_func, next_value,
                        nullptr, if_exception, var_exception);
    Goto(&loop);
  }
  BIND(&exit);
}

RootIndex BaseCollectionsAssembler::GetAddFunctionNameIndex(Variant variant) {
  switch (variant) {
    case kMap:
    case kWeakMap:
      return RootIndex::kset_string;
    case kSet:
    case kWeakSet:
      return RootIndex::kadd_string;
  }
  UNREACHABLE();
}

void BaseCollectionsAssembler::GotoIfInitialAddFunctionModified(
    Variant variant, TNode<NativeContext> native_context,
    TNode<HeapObject> collection, Label* if_modified) {
  static_assert(JSCollection::kAddFunctionDescriptorIndex ==
                JSWeakCollection::kAddFunctionDescriptorIndex);

  // TODO(jgruber): Investigate if this should also fall back to full prototype
  // verification.
  static constexpr PrototypeCheckAssembler::Flags flags{
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness};

  static constexpr int kNoContextIndex = -1;
  static_assert(
      (flags & PrototypeCheckAssembler::kCheckPrototypePropertyIdentity) == 0);

  using DescriptorIndexNameValue =
      PrototypeCheckAssembler::DescriptorIndexNameValue;

  DescriptorIndexNameValue property_to_check{
      JSCollection::kAddFunctionDescriptorIndex,
      GetAddFunctionNameIndex(variant), kNoContextIndex};

  PrototypeCheckAssembler prototype_check_assembler(
      state(), flags, native_context,
      GetInitialCollectionPrototype(variant, native_context),
      base::Vector<DescriptorIndexNameValue>(&property_to_check, 1));

  TNode<HeapObject> prototype = LoadMapPrototype(LoadMap(collection));
  Label if_unmodified(this);
  prototype_check_assembler.CheckAndBranch(prototype, &if_unmodified,
                                           if_modified);

  BIND(&if_unmodified);
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollection(
    TNode<Context> context, TNode<JSFunction> constructor,
    TNode<JSReceiver> new_target) {
  TNode<BoolT> is_target_unmodified = TaggedEqual(constructor, new_target);

  return Select<JSObject>(
      is_target_unmodified,
      [=, this] { return AllocateJSCollectionFast(constructor); },
      [=, this] {
        return AllocateJSCollectionSlow(context, constructor, new_target);
      });
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollectionFast(
    TNode<JSFunction> constructor) {
  CSA_DCHECK(this, IsConstructorMap(LoadMap(constructor)));
  TNode<Map> initial_map =
      CAST(LoadJSFunctionPrototypeOrInitialMap(constructor));
  return AllocateJSObjectFromMap(initial_map);
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollectionSlow(
    TNode<Context> context, TNode<JSFunction> constructor,
    TNode<JSReceiver> new_target) {
  ConstructorBuiltinsAssembler constructor_assembler(this->state());
  return constructor_assembler.FastNewObject(context, constructor, new_target);
}

void BaseCollectionsAssembler::GenerateConstructor(
    Variant variant, Handle<String> constructor_function_name,
    TNode<Object> new_target, TNode<IntPtrT> argc, TNode<Context> context) {
  const int kIterableArg = 0;
  CodeStubArguments args(this, argc);
  TNode<Object> iterable = args.GetOptionalArgumentValue(kIterableArg);

  Label if_undefined(this, Label::kDeferred);
  GotoIf(IsUndefined(new_target), &if_undefined);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSObject> collection = AllocateJSCollection(
      context, GetConstructor(variant, native_context), CAST(new_target));

  Label add_constructor_entries(this);

  // The empty case.
  //
  // This is handled specially to simplify AddConstructorEntries, which is
  // complex and contains multiple fast paths.
  GotoIfNot(IsNullOrUndefined(iterable), &add_constructor_entries);
  TNode<HeapObject> table = AllocateTable(variant, IntPtrConstant(0));
  StoreObjectField(collection, GetTableOffset(variant), table);
  Return(collection);

  BIND(&add_constructor_entries);
  AddConstructorEntries(variant, context, native_context, collection, iterable);
  Return(collection);

  BIND(&if_undefined);
  ThrowTypeError(context, MessageTemplate::kConstructorNotFunction,
                 HeapConstantNoHole(constructor_function_name));
}

TNode<Object> BaseCollectionsAssembler::GetAddFunction(
    Variant variant, TNode<Context> context, TNode<Object> collection) {
  Handle<String> add_func_name = (variant == kMap || variant == kWeakMap)
                                     ? isolate()->factory()->set_string()
                                     : isolate()->factory()->add_string();
  TNode<Object> add_func = GetProperty(context, collection, add_func_name);

  Label exit(this), if_notcallable(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(add_func), &if_notcallable);
  GotoIfNot(IsCallable(CAST(add_func)), &if_notcallable);
  Goto(&exit);

  BIND(&if_notcallable);
  ThrowTypeError(context, MessageTemplate::kPropertyNotFunction, add_func,
                 HeapConstantNoHole(add_func_name), collection);

  BIND(&exit);
  return add_func;
}

TNode<JSFunction> BaseCollectionsAssembler::GetConstructor(
    Variant variant, TNode<Context> native_context) {
  int index;
  switch (variant) {
    case kMap:
      index = Context::JS_MAP_FUN_INDEX;
      break;
    case kSet:
      index = Context::JS_SET_FUN_INDEX;
      break;
    case kWeakMap:
      index = Context::JS_WEAK_MAP_FUN_INDEX;
      break;
    case kWeakSet:
      index = Context::JS_WEAK_SET_FUN_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, index));
}

TNode<JSFunction> BaseCollectionsAssembler::GetInitialAddFunction(
    Variant variant, TNode<Context> native_context) {
  int index;
  switch (variant) {
    case kMap:
      index = Context::MAP_SET_INDEX;
      break;
    case kSet:
      index = Context::SET_ADD_INDEX;
      break;
    case kWeakMap:
      index = Context::WEAKMAP_SET_INDEX;
      break;
    case kWeakSet:
      index = Context::WEAKSET_ADD_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, index));
}

int BaseCollectionsAssembler::GetTableOffset(Variant variant) {
  switch (variant) {
    case kMap:
      return JSMap::kTableOffset;
    case kSet:
      return JSSet::kTableOffset;
    case kWeakMap:
      return JSWeakMap::kTableOffset;
    case kWeakSet:
      return JSWeakSet::kTableOffset;
  }
  UNREACHABLE();
}

// https://tc39.es/ecma262/#sec-canbeheldweakly
void BaseCollectionsAssembler::GotoIfCannotBeHeldWeakly(
    const TNode<Object> obj, Label* if_cannot_be_held_weakly) {
  Label check_symbol_key(this);
  Label end(this);
  GotoIf(TaggedIsSmi(obj), if_cannot_be_held_weakly);
  TNode<Uint16T> instance_type = LoadMapInstanceType(LoadMap(CAST(obj)));
  GotoIfNot(IsJSReceiverInstanceType(instance_type), &check_symbol_key);
  // TODO(v8:12547) Shared structs and arrays should only be able to point
  // to shared values in weak collections. For now, disallow them as weak
  // collection keys.
  GotoIf(IsAlwaysSharedSpaceJSObjectInstanceType(instance_type),
         if_cannot_be_held_weakly);
  Goto(&end);
  Bind(&check_symbol_key);
  GotoIfNot(IsSymbolInstanceType(instance_type), if_cannot_be_held_weakly);
  TNode<Uint32T> flags = LoadSymbolFlags(CAST(obj));
  GotoIf(Word32And(flags, Symbol::IsInPublicSymbolTableBit::kMask),
         if_cannot_be_held_weakly);
  Goto(&end);
  Bind(&end);
}

TNode<Map> BaseCollectionsAssembler::GetInitialCollectionPrototype(
    Variant variant, TNode<Context> native_context) {
  int initial_prototype_index;
  switch (variant) {
    case kMap:
      initial_prototype_index = Context::INITIAL_MAP_PROTOTYPE_MAP_INDEX;
      break;
    case kSet:
      initial_prototype_index = Context::INITIAL_SET_PROTOTYPE_MAP_INDEX;
      break;
    case kWeakMap:
      initial_prototype_index = Context::INITIAL_WEAKMAP_PROTOTYPE_MAP_INDEX;
      break;
    case kWeakSet:
      initial_prototype_index = Context::INITIAL_WEAKSET_PROTOTYPE_MAP_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, initial_prototype_index));
}

TNode<BoolT> BaseCollectionsAssembler::HasInitialCollectionPrototype(
    Variant variant, TNode<Context> native_context, TNode<Object> collection) {
  TNode<Map> collection_proto_map =
      LoadMap(LoadMapPrototype(LoadMap(CAST(collection))));

  return TaggedEqual(collection_proto_map,
                     GetInitialCollectionPrototype(variant, native_context));
}

TNode<Object> BaseCollectionsAssembler::LoadAndNormalizeFixedArrayElement(
    TNode<FixedArray> elements, TNode<IntPtrT> index) {
  TNode<Object> element = UnsafeLoadFixedArrayElement(elements, index);
  return Select<Object>(
      IsTheHole(element), [=, this] { return UndefinedConstant(); },
      [=] { return element; });
}

TNode<Object> BaseCollectionsAssembler::LoadAndNormalizeFixedDoubleArrayElement(
    TNode<HeapObject> elements, TNode<IntPtrT> index) {
  TVARIABLE(Object, entry);
  Label if_hole(this, Label::kDeferred), next(this);
  TNode<Float64T> element =
      LoadFixedDoubleArrayElement(CAST(elements), index, &if_hole);
  {  // not hole
    entry = AllocateHeapNumberWithValue(element);
    Goto(&next);
  }
  BIND(&if_hole);
  {
    entry = UndefinedConstant();
    Goto(&next);
  }
  BIND(&next);
  return entry.value();
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntry(
    const TNode<CollectionType> table, const TNode<Uint32T> hash,
    const std::function<void(TNode<Object>, Label*, Label*)>& key_compare,
    TVariable<IntPtrT>* entry_start_position, Label* entry_found,
    Label* not_found) {
  // Get the index of the bucket.
  const TNode<Uint32T> number_of_buckets =
      PositiveSmiToUint32(CAST(UnsafeLoadFixedArrayElement(
          table, CollectionType::NumberOfBucketsIndex())));
  const TNode<Uint32T> bucket =
      Word32And(hash, Uint32Sub(number_of_buckets, Uint32Constant(1)));
  const TNode<IntPtrT> first_entry = SmiUntag(CAST(UnsafeLoadFixedArrayElement(
      table, Signed(ChangeUint32ToWord(bucket)),
      CollectionType::HashTableStartIndex() * kTaggedSize)));
  const TNode<IntPtrT> number_of_buckets_intptr =
      Signed(ChangeUint32ToWord(number_of_buckets));

  // Walk the bucket chain.
  TNode<IntPtrT> entry_start;
  Label if_key_found(this);
  {
    TVARIABLE(IntPtrT, var_entry, first_entry);
    Label loop(this, {&var_entry, entry_start_position}),
        continue_next_entry(this);
    Goto(&loop);
    BIND(&loop);

    // If the entry index is the not-found sentinel, we are done.
    GotoIf(IntPtrEqual(var_entry.value(),
                       IntPtrConstant(CollectionType::kNotFound)),
           not_found);

    // Make sure the entry index is within range.
    CSA_DCHECK(
        this,
        UintPtrLessThan(
            var_entry.value(),
            PositiveSmiUntag(SmiAdd(
                CAST(UnsafeLoadFixedArrayElement(
                    table, CollectionType::NumberOfElementsIndex())),
                CAST(UnsafeLoadFixedArrayElement(
                    table, CollectionType::NumberOfDeletedElementsIndex()))))));

    // Compute the index of the entry relative to kHashTableStartIndex.
    entry_start =
        IntPtrAdd(IntPtrMul(var_entry.value(),
                            IntPtrConstant(CollectionType::kEntrySize)),
                  number_of_buckets_intptr);

    // Load the key from the entry.
    const TNode<Object> candidate_key =
        UnsafeLoadKeyFromOrderedHashTableEntry(table, entry_start);

    key_compare(candidate_key, &if_key_found, &continue_next_entry);

    BIND(&continue_next_entry);
    // Load the index of the next entry in the bucket chain.
    var_entry = SmiUntag(CAST(UnsafeLoadFixedArrayElement(
        table, entry_start,
        (CollectionType::HashTableStartIndex() + CollectionType::kChainOffset) *
            kTaggedSize)));

    Goto(&loop);
  }

  BIND(&if_key_found);
  *entry_start_position = entry_start;
  Goto(entry_found);
}

// a helper function to unwrap a fast js collection and load its length.
// var_entries_table is a variable meant to store the unwrapped collection.
// var_number_of_elements is a variable meant to store the length of the
// unwrapped collection. the function jumps to if_not_fast_collection if the
// collection is not a fast js collection.
void CollectionsBuiltinsAssembler::GetEntriesIfFastCollectionOrIterable(
    Variant variant, TNode<Object> initial_entries, TNode<Context> context,
    TVariable<HeapObject>* var_entries_table,
    TVariable<IntPtrT>* var_number_of_elements, Label* if_not_fast_collection) {
  Label if_fast_js_set(this), exit(this);
  DCHECK_EQ(variant, kSet);
  BranchIfIterableWithOriginalValueSetIterator(
      initial_entries, context, &if_fast_js_set, if_not_fast_collection);
  BIND(&if_fast_js_set);
  {
    *var_entries_table = SetOrSetIteratorToSet(initial_entries);
    TNode<Smi> size_smi = LoadObjectField<Smi>(
        var_entries_table->value(), OrderedHashMap::NumberOfElementsOffset());
    *var_number_of_elements = PositiveSmiUntag(size_smi);
    Goto(&exit);
  }
  BIND(&exit);
}

void CollectionsBuiltinsAssembler::AddConstructorEntriesFromSet(
    TNode<JSSet> collection, TNode<OrderedHashSet> table) {
  TNode<OrderedHashSet> entry_table = LoadObjectField<OrderedHashSet>(
      collection, GetTableOffset(Variant::kSet));

  TNode<IntPtrT> number_of_buckets =
      PositiveSmiUnt
Prompt: 
```
这是目录为v8/src/builtins/builtins-collections-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-collections-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-collections-gen.h"

#include "src/builtins/builtins-constructor-gen.h"
#include "src/builtins/builtins-iterator-gen.h"
#include "src/builtins/builtins-utils-gen.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/execution/protectors.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/js-collection.h"
#include "src/objects/ordered-hash-table.h"
#include "src/roots/roots.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

template <class T>
using TVariable = compiler::TypedCodeAssemblerVariable<T>;

void BaseCollectionsAssembler::AddConstructorEntry(
    Variant variant, TNode<Context> context, TNode<Object> collection,
    TNode<Object> add_function, TNode<Object> key_value,
    Label* if_may_have_side_effects, Label* if_exception,
    TVariable<Object>* var_exception) {
  compiler::ScopedExceptionHandler handler(this, if_exception, var_exception);
  CSA_DCHECK(this, Word32BinaryNot(IsHashTableHole(key_value)));
  if (variant == kMap || variant == kWeakMap) {
    TorqueStructKeyValuePair pair =
        if_may_have_side_effects != nullptr
            ? LoadKeyValuePairNoSideEffects(context, key_value,
                                            if_may_have_side_effects)
            : LoadKeyValuePair(context, key_value);
    TNode<Object> key_n = pair.key;
    TNode<Object> value_n = pair.value;
    Call(context, add_function, collection, key_n, value_n);
  } else {
    DCHECK(variant == kSet || variant == kWeakSet);
    Call(context, add_function, collection, key_value);
  }
}

void BaseCollectionsAssembler::AddConstructorEntries(
    Variant variant, TNode<Context> context,
    TNode<NativeContext> native_context, TNode<HeapObject> collection,
    TNode<Object> initial_entries) {
  CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(initial_entries)));

  enum Mode { kSlow, kFastJSArray, kFastCollection };
  TVARIABLE(IntPtrT, var_at_least_space_for, IntPtrConstant(0));
  TVARIABLE(HeapObject, var_entries_table, UndefinedConstant());
  TVARIABLE(Int32T, var_mode, Int32Constant(kSlow));
  Label if_fast_js_array(this), allocate_table(this);

  // The slow path is taken if the initial add function is modified. This check
  // must precede the kSet fast path below, which has the side effect of
  // exhausting {initial_entries} if it is a JSSetIterator.
  GotoIfInitialAddFunctionModified(variant, native_context, collection,
                                   &allocate_table);

  GotoIf(IsFastJSArrayWithNoCustomIteration(context, initial_entries),
         &if_fast_js_array);
  if (variant == Variant::kSet) {
    GetEntriesIfFastCollectionOrIterable(
        variant, initial_entries, context, &var_entries_table,
        &var_at_least_space_for, &allocate_table);
    var_mode = Int32Constant(kFastCollection);
    Goto(&allocate_table);
  } else {
    Goto(&allocate_table);
  }
  BIND(&if_fast_js_array);
  {
    var_mode = Int32Constant(kFastJSArray);
    if (variant == kWeakSet || variant == kWeakMap) {
      var_at_least_space_for =
          PositiveSmiUntag(LoadFastJSArrayLength(CAST(initial_entries)));
    } else {
      // TODO(ishell): consider using array length for all collections
      static_assert(OrderedHashSet::kInitialCapacity ==
                    OrderedHashMap::kInitialCapacity);
      var_at_least_space_for = IntPtrConstant(OrderedHashSet::kInitialCapacity);
    }
    Goto(&allocate_table);
  }
  TVARIABLE(JSReceiver, var_iterator_object);
  TVARIABLE(Object, var_exception);
  Label exit(this), from_fast_jsarray(this), from_fast_collection(this),
      slow_loop(this, Label::kDeferred), if_exception(this, Label::kDeferred);
  BIND(&allocate_table);
  {
    TNode<HeapObject> table =
        AllocateTable(variant, var_at_least_space_for.value());
    StoreObjectField(collection, GetTableOffset(variant), table);
    if (variant == Variant::kSet) {
      GotoIf(Word32Equal(var_mode.value(), Int32Constant(kFastCollection)),
             &from_fast_collection);
    }
    Branch(Word32Equal(var_mode.value(), Int32Constant(kFastJSArray)),
           &from_fast_jsarray, &slow_loop);
  }
  BIND(&from_fast_jsarray);
  {
    Label if_exception_during_fast_iteration(this, Label::kDeferred);
    TVARIABLE(IntPtrT, var_index, IntPtrConstant(0));
    TNode<JSArray> initial_entries_jsarray =
        UncheckedCast<JSArray>(initial_entries);
#if DEBUG
    CSA_DCHECK(this, IsFastJSArrayWithNoCustomIteration(
                         context, initial_entries_jsarray));
    TNode<Map> original_initial_entries_map = LoadMap(initial_entries_jsarray);
#endif

    Label if_may_have_side_effects(this, Label::kDeferred);
    {
      compiler::ScopedExceptionHandler handler(
          this, &if_exception_during_fast_iteration, &var_exception);
      AddConstructorEntriesFromFastJSArray(
          variant, context, native_context, collection, initial_entries_jsarray,
          &if_may_have_side_effects, var_index);
    }
    Goto(&exit);

    if (variant == kMap || variant == kWeakMap) {
      BIND(&if_may_have_side_effects);
#if DEBUG
      {
        // Check that add/set function has not been modified.
        Label if_not_modified(this), if_modified(this);
        GotoIfInitialAddFunctionModified(variant, native_context, collection,
                                         &if_modified);
        Goto(&if_not_modified);
        BIND(&if_modified);
        Unreachable();
        BIND(&if_not_modified);
      }
      CSA_DCHECK(this, TaggedEqual(original_initial_entries_map,
                                   LoadMap(initial_entries_jsarray)));
#endif
      var_mode = Int32Constant(kSlow);
      Goto(&allocate_table);
    }
    BIND(&if_exception_during_fast_iteration);
    {
      // In case exception is thrown during collection population, materialize
      // the iteator and execute iterator closing protocol. It might be
      // non-trivial in case "return" callback is added somewhere in the
      // iterator's prototype chain.
      TNode<NativeContext> native_context = LoadNativeContext(context);
      TNode<IntPtrT> next_index =
          IntPtrAdd(var_index.value(), IntPtrConstant(1));
      var_iterator_object = CreateArrayIterator(
          native_context, UncheckedCast<JSArray>(initial_entries),
          IterationKind::kValues, SmiTag(next_index));
      Goto(&if_exception);
    }
  }
  if (variant == Variant::kSet) {
    BIND(&from_fast_collection);
    {
      AddConstructorEntriesFromFastCollection(variant, collection,
                                              var_entries_table.value());
      Goto(&exit);
    }
  }
  BIND(&slow_loop);
  {
    AddConstructorEntriesFromIterable(
        variant, context, native_context, collection, initial_entries,
        &if_exception, &var_iterator_object, &var_exception);
    Goto(&exit);
  }
  BIND(&if_exception);
  {
    TNode<HeapObject> message = GetPendingMessage();
    SetPendingMessage(TheHoleConstant());
    // iterator.next field is not used by IteratorCloseOnException.
    TorqueStructIteratorRecord iterator = {var_iterator_object.value(), {}};
    IteratorCloseOnException(context, iterator);
    CallRuntime(Runtime::kReThrowWithMessage, context, var_exception.value(),
                message);
    Unreachable();
  }
  BIND(&exit);
}

void BaseCollectionsAssembler::AddConstructorEntriesFromFastJSArray(
    Variant variant, TNode<Context> context, TNode<Context> native_context,
    TNode<Object> collection, TNode<JSArray> fast_jsarray,
    Label* if_may_have_side_effects, TVariable<IntPtrT>& var_current_index) {
  TNode<FixedArrayBase> elements = LoadElements(fast_jsarray);
  TNode<Int32T> elements_kind = LoadElementsKind(fast_jsarray);
  TNode<JSFunction> add_func = GetInitialAddFunction(variant, native_context);
  CSA_DCHECK(this,
             TaggedEqual(GetAddFunction(variant, native_context, collection),
                         add_func));
  CSA_DCHECK(this, IsFastJSArrayWithNoCustomIteration(context, fast_jsarray));
  TNode<IntPtrT> length = PositiveSmiUntag(LoadFastJSArrayLength(fast_jsarray));
  CSA_DCHECK(
      this, HasInitialCollectionPrototype(variant, native_context, collection));

#if DEBUG
  TNode<Map> original_collection_map = LoadMap(CAST(collection));
  TNode<Map> original_fast_js_array_map = LoadMap(fast_jsarray);
#endif
  Label exit(this), if_doubles(this), if_smiorobjects(this);
  GotoIf(IntPtrEqual(length, IntPtrConstant(0)), &exit);
  Branch(IsFastSmiOrTaggedElementsKind(elements_kind), &if_smiorobjects,
         &if_doubles);
  BIND(&if_smiorobjects);
  {
    auto set_entry = [&](TNode<IntPtrT> index) {
      TNode<Object> element =
          LoadAndNormalizeFixedArrayElement(CAST(elements), index);
      AddConstructorEntry(variant, context, collection, add_func, element,
                          if_may_have_side_effects);
    };

    // Instead of using the slower iteration protocol to iterate over the
    // elements, a fast loop is used.  This assumes that adding an element
    // to the collection does not call user code that could mutate the elements
    // or collection.
    BuildFastLoop<IntPtrT>(var_current_index, IntPtrConstant(0), length,
                           set_entry, 1, LoopUnrollingMode::kNo,
                           IndexAdvanceMode::kPost);
    Goto(&exit);
  }
  BIND(&if_doubles);
  {
    // A Map constructor requires entries to be arrays (ex. [key, value]),
    // so a FixedDoubleArray can never succeed.
    if (variant == kMap || variant == kWeakMap) {
      CSA_DCHECK(this, IntPtrGreaterThan(length, IntPtrConstant(0)));
      TNode<Object> element =
          LoadAndNormalizeFixedDoubleArrayElement(elements, IntPtrConstant(0));
      ThrowTypeError(context, MessageTemplate::kIteratorValueNotAnObject,
                     element);
    } else {
      DCHECK(variant == kSet || variant == kWeakSet);
      auto set_entry = [&](TNode<IntPtrT> index) {
        TNode<Object> entry = LoadAndNormalizeFixedDoubleArrayElement(
            elements, UncheckedCast<IntPtrT>(index));
        AddConstructorEntry(variant, context, collection, add_func, entry);
      };
      BuildFastLoop<IntPtrT>(var_current_index, IntPtrConstant(0), length,
                             set_entry, 1, LoopUnrollingMode::kNo,
                             IndexAdvanceMode::kPost);
      Goto(&exit);
    }
  }
  BIND(&exit);
#if DEBUG
  CSA_DCHECK(this,
             TaggedEqual(original_collection_map, LoadMap(CAST(collection))));
  CSA_DCHECK(this,
             TaggedEqual(original_fast_js_array_map, LoadMap(fast_jsarray)));
#endif
}

void BaseCollectionsAssembler::AddConstructorEntriesFromIterable(
    Variant variant, TNode<Context> context, TNode<Context> native_context,
    TNode<Object> collection, TNode<Object> iterable, Label* if_exception,
    TVariable<JSReceiver>* var_iterator_object,
    TVariable<Object>* var_exception) {
  Label exit(this), loop(this);
  CSA_DCHECK(this, Word32BinaryNot(IsNullOrUndefined(iterable)));
  TNode<Object> add_func = GetAddFunction(variant, context, collection);
  IteratorBuiltinsAssembler iterator_assembler(this->state());
  TorqueStructIteratorRecord iterator =
      iterator_assembler.GetIterator(context, iterable);
  *var_iterator_object = iterator.object;

  CSA_DCHECK(this, Word32BinaryNot(IsUndefined(iterator.object)));

  TNode<Map> fast_iterator_result_map = CAST(
      LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX));

  Goto(&loop);
  BIND(&loop);
  {
    TNode<JSReceiver> next = iterator_assembler.IteratorStep(
        context, iterator, &exit, fast_iterator_result_map);
    TNode<Object> next_value = iterator_assembler.IteratorValue(
        context, next, fast_iterator_result_map);
    AddConstructorEntry(variant, context, collection, add_func, next_value,
                        nullptr, if_exception, var_exception);
    Goto(&loop);
  }
  BIND(&exit);
}

RootIndex BaseCollectionsAssembler::GetAddFunctionNameIndex(Variant variant) {
  switch (variant) {
    case kMap:
    case kWeakMap:
      return RootIndex::kset_string;
    case kSet:
    case kWeakSet:
      return RootIndex::kadd_string;
  }
  UNREACHABLE();
}

void BaseCollectionsAssembler::GotoIfInitialAddFunctionModified(
    Variant variant, TNode<NativeContext> native_context,
    TNode<HeapObject> collection, Label* if_modified) {
  static_assert(JSCollection::kAddFunctionDescriptorIndex ==
                JSWeakCollection::kAddFunctionDescriptorIndex);

  // TODO(jgruber): Investigate if this should also fall back to full prototype
  // verification.
  static constexpr PrototypeCheckAssembler::Flags flags{
      PrototypeCheckAssembler::kCheckPrototypePropertyConstness};

  static constexpr int kNoContextIndex = -1;
  static_assert(
      (flags & PrototypeCheckAssembler::kCheckPrototypePropertyIdentity) == 0);

  using DescriptorIndexNameValue =
      PrototypeCheckAssembler::DescriptorIndexNameValue;

  DescriptorIndexNameValue property_to_check{
      JSCollection::kAddFunctionDescriptorIndex,
      GetAddFunctionNameIndex(variant), kNoContextIndex};

  PrototypeCheckAssembler prototype_check_assembler(
      state(), flags, native_context,
      GetInitialCollectionPrototype(variant, native_context),
      base::Vector<DescriptorIndexNameValue>(&property_to_check, 1));

  TNode<HeapObject> prototype = LoadMapPrototype(LoadMap(collection));
  Label if_unmodified(this);
  prototype_check_assembler.CheckAndBranch(prototype, &if_unmodified,
                                           if_modified);

  BIND(&if_unmodified);
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollection(
    TNode<Context> context, TNode<JSFunction> constructor,
    TNode<JSReceiver> new_target) {
  TNode<BoolT> is_target_unmodified = TaggedEqual(constructor, new_target);

  return Select<JSObject>(
      is_target_unmodified,
      [=, this] { return AllocateJSCollectionFast(constructor); },
      [=, this] {
        return AllocateJSCollectionSlow(context, constructor, new_target);
      });
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollectionFast(
    TNode<JSFunction> constructor) {
  CSA_DCHECK(this, IsConstructorMap(LoadMap(constructor)));
  TNode<Map> initial_map =
      CAST(LoadJSFunctionPrototypeOrInitialMap(constructor));
  return AllocateJSObjectFromMap(initial_map);
}

TNode<JSObject> BaseCollectionsAssembler::AllocateJSCollectionSlow(
    TNode<Context> context, TNode<JSFunction> constructor,
    TNode<JSReceiver> new_target) {
  ConstructorBuiltinsAssembler constructor_assembler(this->state());
  return constructor_assembler.FastNewObject(context, constructor, new_target);
}

void BaseCollectionsAssembler::GenerateConstructor(
    Variant variant, Handle<String> constructor_function_name,
    TNode<Object> new_target, TNode<IntPtrT> argc, TNode<Context> context) {
  const int kIterableArg = 0;
  CodeStubArguments args(this, argc);
  TNode<Object> iterable = args.GetOptionalArgumentValue(kIterableArg);

  Label if_undefined(this, Label::kDeferred);
  GotoIf(IsUndefined(new_target), &if_undefined);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSObject> collection = AllocateJSCollection(
      context, GetConstructor(variant, native_context), CAST(new_target));

  Label add_constructor_entries(this);

  // The empty case.
  //
  // This is handled specially to simplify AddConstructorEntries, which is
  // complex and contains multiple fast paths.
  GotoIfNot(IsNullOrUndefined(iterable), &add_constructor_entries);
  TNode<HeapObject> table = AllocateTable(variant, IntPtrConstant(0));
  StoreObjectField(collection, GetTableOffset(variant), table);
  Return(collection);

  BIND(&add_constructor_entries);
  AddConstructorEntries(variant, context, native_context, collection, iterable);
  Return(collection);

  BIND(&if_undefined);
  ThrowTypeError(context, MessageTemplate::kConstructorNotFunction,
                 HeapConstantNoHole(constructor_function_name));
}

TNode<Object> BaseCollectionsAssembler::GetAddFunction(
    Variant variant, TNode<Context> context, TNode<Object> collection) {
  Handle<String> add_func_name = (variant == kMap || variant == kWeakMap)
                                     ? isolate()->factory()->set_string()
                                     : isolate()->factory()->add_string();
  TNode<Object> add_func = GetProperty(context, collection, add_func_name);

  Label exit(this), if_notcallable(this, Label::kDeferred);
  GotoIf(TaggedIsSmi(add_func), &if_notcallable);
  GotoIfNot(IsCallable(CAST(add_func)), &if_notcallable);
  Goto(&exit);

  BIND(&if_notcallable);
  ThrowTypeError(context, MessageTemplate::kPropertyNotFunction, add_func,
                 HeapConstantNoHole(add_func_name), collection);

  BIND(&exit);
  return add_func;
}

TNode<JSFunction> BaseCollectionsAssembler::GetConstructor(
    Variant variant, TNode<Context> native_context) {
  int index;
  switch (variant) {
    case kMap:
      index = Context::JS_MAP_FUN_INDEX;
      break;
    case kSet:
      index = Context::JS_SET_FUN_INDEX;
      break;
    case kWeakMap:
      index = Context::JS_WEAK_MAP_FUN_INDEX;
      break;
    case kWeakSet:
      index = Context::JS_WEAK_SET_FUN_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, index));
}

TNode<JSFunction> BaseCollectionsAssembler::GetInitialAddFunction(
    Variant variant, TNode<Context> native_context) {
  int index;
  switch (variant) {
    case kMap:
      index = Context::MAP_SET_INDEX;
      break;
    case kSet:
      index = Context::SET_ADD_INDEX;
      break;
    case kWeakMap:
      index = Context::WEAKMAP_SET_INDEX;
      break;
    case kWeakSet:
      index = Context::WEAKSET_ADD_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, index));
}

int BaseCollectionsAssembler::GetTableOffset(Variant variant) {
  switch (variant) {
    case kMap:
      return JSMap::kTableOffset;
    case kSet:
      return JSSet::kTableOffset;
    case kWeakMap:
      return JSWeakMap::kTableOffset;
    case kWeakSet:
      return JSWeakSet::kTableOffset;
  }
  UNREACHABLE();
}

// https://tc39.es/ecma262/#sec-canbeheldweakly
void BaseCollectionsAssembler::GotoIfCannotBeHeldWeakly(
    const TNode<Object> obj, Label* if_cannot_be_held_weakly) {
  Label check_symbol_key(this);
  Label end(this);
  GotoIf(TaggedIsSmi(obj), if_cannot_be_held_weakly);
  TNode<Uint16T> instance_type = LoadMapInstanceType(LoadMap(CAST(obj)));
  GotoIfNot(IsJSReceiverInstanceType(instance_type), &check_symbol_key);
  // TODO(v8:12547) Shared structs and arrays should only be able to point
  // to shared values in weak collections. For now, disallow them as weak
  // collection keys.
  GotoIf(IsAlwaysSharedSpaceJSObjectInstanceType(instance_type),
         if_cannot_be_held_weakly);
  Goto(&end);
  Bind(&check_symbol_key);
  GotoIfNot(IsSymbolInstanceType(instance_type), if_cannot_be_held_weakly);
  TNode<Uint32T> flags = LoadSymbolFlags(CAST(obj));
  GotoIf(Word32And(flags, Symbol::IsInPublicSymbolTableBit::kMask),
         if_cannot_be_held_weakly);
  Goto(&end);
  Bind(&end);
}

TNode<Map> BaseCollectionsAssembler::GetInitialCollectionPrototype(
    Variant variant, TNode<Context> native_context) {
  int initial_prototype_index;
  switch (variant) {
    case kMap:
      initial_prototype_index = Context::INITIAL_MAP_PROTOTYPE_MAP_INDEX;
      break;
    case kSet:
      initial_prototype_index = Context::INITIAL_SET_PROTOTYPE_MAP_INDEX;
      break;
    case kWeakMap:
      initial_prototype_index = Context::INITIAL_WEAKMAP_PROTOTYPE_MAP_INDEX;
      break;
    case kWeakSet:
      initial_prototype_index = Context::INITIAL_WEAKSET_PROTOTYPE_MAP_INDEX;
      break;
  }
  return CAST(LoadContextElement(native_context, initial_prototype_index));
}

TNode<BoolT> BaseCollectionsAssembler::HasInitialCollectionPrototype(
    Variant variant, TNode<Context> native_context, TNode<Object> collection) {
  TNode<Map> collection_proto_map =
      LoadMap(LoadMapPrototype(LoadMap(CAST(collection))));

  return TaggedEqual(collection_proto_map,
                     GetInitialCollectionPrototype(variant, native_context));
}

TNode<Object> BaseCollectionsAssembler::LoadAndNormalizeFixedArrayElement(
    TNode<FixedArray> elements, TNode<IntPtrT> index) {
  TNode<Object> element = UnsafeLoadFixedArrayElement(elements, index);
  return Select<Object>(
      IsTheHole(element), [=, this] { return UndefinedConstant(); },
      [=] { return element; });
}

TNode<Object> BaseCollectionsAssembler::LoadAndNormalizeFixedDoubleArrayElement(
    TNode<HeapObject> elements, TNode<IntPtrT> index) {
  TVARIABLE(Object, entry);
  Label if_hole(this, Label::kDeferred), next(this);
  TNode<Float64T> element =
      LoadFixedDoubleArrayElement(CAST(elements), index, &if_hole);
  {  // not hole
    entry = AllocateHeapNumberWithValue(element);
    Goto(&next);
  }
  BIND(&if_hole);
  {
    entry = UndefinedConstant();
    Goto(&next);
  }
  BIND(&next);
  return entry.value();
}

template <typename CollectionType>
void CollectionsBuiltinsAssembler::FindOrderedHashTableEntry(
    const TNode<CollectionType> table, const TNode<Uint32T> hash,
    const std::function<void(TNode<Object>, Label*, Label*)>& key_compare,
    TVariable<IntPtrT>* entry_start_position, Label* entry_found,
    Label* not_found) {
  // Get the index of the bucket.
  const TNode<Uint32T> number_of_buckets =
      PositiveSmiToUint32(CAST(UnsafeLoadFixedArrayElement(
          table, CollectionType::NumberOfBucketsIndex())));
  const TNode<Uint32T> bucket =
      Word32And(hash, Uint32Sub(number_of_buckets, Uint32Constant(1)));
  const TNode<IntPtrT> first_entry = SmiUntag(CAST(UnsafeLoadFixedArrayElement(
      table, Signed(ChangeUint32ToWord(bucket)),
      CollectionType::HashTableStartIndex() * kTaggedSize)));
  const TNode<IntPtrT> number_of_buckets_intptr =
      Signed(ChangeUint32ToWord(number_of_buckets));

  // Walk the bucket chain.
  TNode<IntPtrT> entry_start;
  Label if_key_found(this);
  {
    TVARIABLE(IntPtrT, var_entry, first_entry);
    Label loop(this, {&var_entry, entry_start_position}),
        continue_next_entry(this);
    Goto(&loop);
    BIND(&loop);

    // If the entry index is the not-found sentinel, we are done.
    GotoIf(IntPtrEqual(var_entry.value(),
                       IntPtrConstant(CollectionType::kNotFound)),
           not_found);

    // Make sure the entry index is within range.
    CSA_DCHECK(
        this,
        UintPtrLessThan(
            var_entry.value(),
            PositiveSmiUntag(SmiAdd(
                CAST(UnsafeLoadFixedArrayElement(
                    table, CollectionType::NumberOfElementsIndex())),
                CAST(UnsafeLoadFixedArrayElement(
                    table, CollectionType::NumberOfDeletedElementsIndex()))))));

    // Compute the index of the entry relative to kHashTableStartIndex.
    entry_start =
        IntPtrAdd(IntPtrMul(var_entry.value(),
                            IntPtrConstant(CollectionType::kEntrySize)),
                  number_of_buckets_intptr);

    // Load the key from the entry.
    const TNode<Object> candidate_key =
        UnsafeLoadKeyFromOrderedHashTableEntry(table, entry_start);

    key_compare(candidate_key, &if_key_found, &continue_next_entry);

    BIND(&continue_next_entry);
    // Load the index of the next entry in the bucket chain.
    var_entry = SmiUntag(CAST(UnsafeLoadFixedArrayElement(
        table, entry_start,
        (CollectionType::HashTableStartIndex() + CollectionType::kChainOffset) *
            kTaggedSize)));

    Goto(&loop);
  }

  BIND(&if_key_found);
  *entry_start_position = entry_start;
  Goto(entry_found);
}

// a helper function to unwrap a fast js collection and load its length.
// var_entries_table is a variable meant to store the unwrapped collection.
// var_number_of_elements is a variable meant to store the length of the
// unwrapped collection. the function jumps to if_not_fast_collection if the
// collection is not a fast js collection.
void CollectionsBuiltinsAssembler::GetEntriesIfFastCollectionOrIterable(
    Variant variant, TNode<Object> initial_entries, TNode<Context> context,
    TVariable<HeapObject>* var_entries_table,
    TVariable<IntPtrT>* var_number_of_elements, Label* if_not_fast_collection) {
  Label if_fast_js_set(this), exit(this);
  DCHECK_EQ(variant, kSet);
  BranchIfIterableWithOriginalValueSetIterator(
      initial_entries, context, &if_fast_js_set, if_not_fast_collection);
  BIND(&if_fast_js_set);
  {
    *var_entries_table = SetOrSetIteratorToSet(initial_entries);
    TNode<Smi> size_smi = LoadObjectField<Smi>(
        var_entries_table->value(), OrderedHashMap::NumberOfElementsOffset());
    *var_number_of_elements = PositiveSmiUntag(size_smi);
    Goto(&exit);
  }
  BIND(&exit);
}

void CollectionsBuiltinsAssembler::AddConstructorEntriesFromSet(
    TNode<JSSet> collection, TNode<OrderedHashSet> table) {
  TNode<OrderedHashSet> entry_table = LoadObjectField<OrderedHashSet>(
      collection, GetTableOffset(Variant::kSet));

  TNode<IntPtrT> number_of_buckets =
      PositiveSmiUntag(CAST(UnsafeLoadFixedArrayElement(
          table, OrderedHashSet::NumberOfBucketsIndex())));
  TNode<IntPtrT> number_of_elements = LoadAndUntagPositiveSmiObjectField(
      table, OrderedHashSet::NumberOfElementsOffset());
  TNode<IntPtrT> number_of_deleted_elements = PositiveSmiUntag(CAST(
      LoadObjectField(table, OrderedHashSet::NumberOfDeletedElementsOffset())));
  TNode<IntPtrT> used_capacity =
      IntPtrAdd(number_of_elements, number_of_deleted_elements);
  TNode<IntPtrT> loop_bound = IntPtrAdd(
      IntPtrMul(used_capacity, IntPtrConstant(OrderedHashSet::kEntrySize)),
      number_of_buckets);

  TNode<IntPtrT> number_of_buckets_entry_table =
      PositiveSmiUntag(CAST(UnsafeLoadFixedArrayElement(
          entry_table, OrderedHashSet::NumberOfBucketsIndex())));

  TVARIABLE(Object, entry_key);
  TVARIABLE(IntPtrT, var_entry_table_occupancy, IntPtrConstant(0));
  VariableList loop_vars({&var_entry_table_occupancy}, zone());
  Label exit(this);

  auto set_entry = [&](TNode<IntPtrT> index) {
    entry_key = UnsafeLoadKeyFromOrderedHashTableEntry(table, index);
    Label if_key_is_not_hole(this), continue_loop(this);
    Branch(IsHashTableHole(entry_key.value()), &continue_loop,
           &if_key_is_not_hole);
    BIND(&if_key_is_not_hole);
    {
      AddNewToOrderedHashSet(entry_table, entry_key.value(),
                             number_of_buckets_entry_table,
                             var_entry_table_occupancy.value());
      Increment(&var_entry_table_occupancy, 1);
      Goto(&continue_loop);
    }
    BIND(&continue_loop);
    return;
  };

  // Instead of using the slower iteration protocol to iterate over the
  // elements, a fast loop is used.  This assumes that adding an element
  // to the collection does not call user code that could mutate the elements
  // or collection. The iteration is based on the layout of the ordered hash
  // table.
  BuildFastLoop<IntPtrT>(loop_vars, number_of_buckets, loop_bound, set_entry,
                         OrderedHashSet::kEntrySize, LoopUnrollingMode::kNo,
                         IndexAdvanceMode::kPost);
  Goto(&exit);
  BIND(&exit);
}

void CollectionsBuiltinsAssembler::AddConstructorEntriesFromFastCollection(
    Variant variant, TNode<HeapObject> collection,
    TNode<HeapObject> source_table) {
  if (variant == kSet) {
    AddConstructorEntriesFromSet(CAST(collection), CAST(source_table));
    return;
  }
}

template <typename IteratorType>
TNode<HeapObject> CollectionsBuiltinsAssembler::AllocateJSCollectionIterator(
    const TNode<Context> context, int map_index,
    const TNode<HeapObject> collection) {
  const TNode<Object> table =
      LoadObjectField(collection, JSCollection::kTableOffset);
  const TNode<NativeContext> native_context = LoadNativeContext(context);
  const TNode<Map> iterator_map =
      CAST(LoadContextElement(native_context, map_index));
  const TNode<HeapObject> iterator =
      AllocateInNewSpace(IteratorType::kHeaderSize);
  StoreMapNoWriteBarrier(iterator, iterator_map);
  StoreObjectFieldRoot(iterator, IteratorType::kPropertiesOrHashOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldRoot(iterator, IteratorType::kElementsOffset,
                       RootIndex::kEmptyFixedArray);
  StoreObjectFieldNoWriteBarrier(iterator, IteratorType::kTableOffset, table);
  StoreObjectFieldNoWriteBarrier(iterator, IteratorType::kIndexOffset,
                                 SmiConstant(0));
  return iterator;
}

TNode<HeapObject> CollectionsBuiltinsAssembler::AllocateTable(
    Variant variant, TNode<IntPtrT> at_least_space_for) {
  if (variant == kMap) {
    return AllocateOrderedHashMap();
  } else {
    DCHECK_EQ(variant, kSet);
    TNode<IntPtrT> capacity = HashTableComputeCapacity(at_least_space_for);
    return AllocateOrderedHashSet(capacity);
  }
}

TF_BUILTIN(MapConstructor, CollectionsBuiltinsAssembler) {
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  GenerateConstructor(kMap, isolate()->factory()->Map_string(), new_target,
                      argc, context);
}

TF_BUILTIN(SetConstructor, CollectionsBuiltinsAssembler) {
  auto new_target = Parameter<Object>(Descriptor::kJSNewTarget);
  TNode<IntPtrT> argc = ChangeInt32ToIntPtr(
      UncheckedParameter<Int32T>(Descriptor::kJSActualArgumentsCount));
  auto context = Parameter<Context>(Descriptor::kContext);

  GenerateConstructor(kSet, isolate()->factory()->Set_string(), new_target,
                      argc, context);
}

TNode<Smi> CollectionsBuiltinsAssembler::CallGetOrCreateHashRaw(
    const TNode<HeapObject> key) {
  const TNode<ExternalReference> function_addr =
      ExternalConstant(ExternalReference::get_or_create_hash_raw());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_tagged = MachineType::AnyTagged();

  TNode<Smi> result = CAST(CallCFunction(function_addr, type_tagged,
                                         std::make_pair(type_ptr, isolate_ptr),
                                         std::make_pair(type_tagged, key)));

  return result;
}

TNode<Uint32T> CollectionsBuiltinsAssembler::CallGetHashRaw(
    const TNode<HeapObject> key) {
  const TNode<ExternalReference> function_addr =
      ExternalConstant(ExternalReference::orderedhashmap_gethash_raw());
  const TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());

  MachineType type_ptr = MachineType::Pointer();
  MachineType type_tagged = MachineType::AnyTagged();

  TNode<Smi> result = CAST(CallCFunction(function_addr, type_tagged,
                                         std::make_pair(type_ptr, isolate_ptr),
                                         std::make_pair(type_tagged, key)));
  return PositiveSmiToUint32(result);
}

TNode<Uint32T> CollectionsBuiltinsAssembler::GetHash(
    const TNode<HeapObject> key) {
  TVARIABLE(Uint32T, var_hash);
  Label if_receiver(this), if_other(this), done(this);
  Branch(IsJSReceiver(key), &if_receiver, &if_other);

  BIND(&if_receiver);
  {
    var_hash = LoadJSReceiverIdentityHash(CAST(key));
    Goto(&done);
  }

  BIND(&if_other);
  {
    var_hash = CallGetHashRaw(key);
    Goto(&done);
  }

  BIND(&done);
  return var_hash.value();
}

void CollectionsBuiltinsAssembler::SameValueZeroSmi(TNode<Smi> key_smi,
                                                    TNode<Object> candidate_key,
                                                    Label* if_same,
                                                    Label* if_not_same) {
  // If the key is the same, we are done.
  GotoIf(TaggedEqual(candidate_key, key_smi), if_same);

  // If the candidate key is smi, then it must be different (because
  // we already checked for equality above).
  GotoIf(TaggedIsSmi(candidate_key), if_not_same);

  // If the candidate key is not smi, we still have to check if it is a
  // heap number with the same value.
  GotoIfNot(IsHeapNumber(CAST(candidate_key)), if_not_same);

  const TNode<Float64T> candidate_key_number =
      LoadHeapNumberValue(CAST(candidate_key));
  const 
"""


```